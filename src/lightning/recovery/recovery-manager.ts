/**
 * RecoveryManager: the single choke point for safety-critical persistence
 * (docs/RECOVERY-PROTOCOL.md sections 5.1 and 5.2).
 *
 * Every safety transition commits as ONE SQLite transaction covering both the
 * state mutations and the outbox rows for the wire messages those mutations
 * authorize. Messages are released to the caller only after that transaction
 * returns, which is what turns "persist before send" from an ordering
 * convention spread across call sites into a structural property of the
 * commit path.
 */

import { SUPERSEDES_OWN_KIND_MESSAGE_TYPES } from '../channel/channel-actions';
import { IStorageBackend } from '../storage/types';
import { withStorageTransaction } from '../storage/transaction';
import {
	IRecoveryCommitResult,
	IRecoveryJournalSink,
	IRecoveryOutboxRow,
	RecoveryCriticality,
	RecoveryMutation,
	RecoveryOutboundMessage,
	SafetyTransition
} from './types';

/** Optional hooks, kept narrow so the node can log without owning the class. */
export interface IRecoveryManagerOptions {
	/**
	 * Called when a transition fails to commit. The caller has ALREADY been
	 * told (commit returns committed: false with no released messages); this
	 * is for logging and telemetry only.
	 */
	onError?: (
		error: Error,
		context: {
			criticality: RecoveryCriticality;
			/** True when the caller reports this failure itself. */
			reportedByCaller: boolean;
		}
	) => void;
	/**
	 * Per-channel cap on retained outbox rows. A peer that never reconnects
	 * would otherwise let the table grow without bound. Exceeding the cap
	 * prunes the OLDEST rows, degrading that channel to reconstruct-from-state
	 * retransmission, which is exactly today's behavior.
	 */
	maxOutboxRowsPerChannel?: number;
	/**
	 * Phase 2 recovery journal (docs/RECOVERY-PROTOCOL.md 5.3). When set,
	 * every Important and SafetyCritical transition appends a frame INSIDE
	 * its own transaction; a journal failure rolls the transition back, since
	 * journaled durability is part of the commit, not a best-effort tail.
	 * Reconstructable transitions are never journaled.
	 */
	journal?: IRecoveryJournalSink;
	/**
	 * Called after a transition COMMITS with a journal frame (never for
	 * Reconstructable or journal-less commits). Runs outside the transaction;
	 * a throw is swallowed. The capsule refresh hangs off this (spec 5.4).
	 */
	onCommitted?: () => void;
}

/** Rows retained per channel before the oldest are pruned. */
const DEFAULT_MAX_OUTBOX_ROWS_PER_CHANNEL = 512;

export class RecoveryManager {
	private readonly storage: IStorageBackend;
	private readonly options: IRecoveryManagerOptions;
	private readonly maxOutboxRows: number;
	/** Lazily seeded row counts per channel, to avoid a COUNT per commit. */
	private readonly outboxCounts = new Map<string, number>();

	constructor(storage: IStorageBackend, options: IRecoveryManagerOptions = {}) {
		this.storage = storage;
		this.options = options;
		this.maxOutboxRows =
			options.maxOutboxRowsPerChannel ?? DEFAULT_MAX_OUTBOX_ROWS_PER_CHANNEL;
	}

	/** True when the backend can persist outbox rows (all methods present). */
	get outboxSupported(): boolean {
		return (
			typeof this.storage.saveOutboxMessage === 'function' &&
			typeof this.storage.loadOutboxMessages === 'function'
		);
	}

	/**
	 * Apply a transition atomically, then release its outbound messages.
	 *
	 * On ANY failure the SQLite transaction rolls back and NO message is
	 * released: a wire message whose justifying state did not reach disk must
	 * never reach the peer. This is the deliberate behavior change over the
	 * previous persistChannel, which swallowed persistence errors and let the
	 * caller send anyway.
	 */
	commit(transition: SafetyTransition): IRecoveryCommitResult {
		const { mutations, outboundMessages } = transition;
		if (mutations.length === 0 && outboundMessages.length === 0) {
			return { committed: true, released: [], frameSequence: null };
		}

		const outboxIds: Array<number | null> = [];
		let journaled = false;
		let frameSequence: bigint | null = null;
		try {
			// Joins an outer transaction when one is active (reconstruction
			// replays commits inside a single install transaction); opens
			// its own otherwise. See withStorageTransaction.
			withStorageTransaction(this.storage, () => {
				for (const mutation of mutations) {
					this.applyMutation(mutation);
				}
				for (const message of outboundMessages) {
					outboxIds.push(this.insertOutboxRow(message));
				}
				// Journal the transition INSIDE its own transaction (spec 5.3):
				// frame and transition commit or roll back as one unit. The rows
				// this commit inserted are stamped with the frame that carries
				// them (the frame_sequence Phase 1 left null), and stamped
				// BEFORE the append: a snapshot captured during the append
				// (bootstrap, or an interval snapshot right behind this delta)
				// must already see the stamps, or reconstruction from that
				// snapshot would resurrect the rows unstamped.
				if (
					this.options.journal &&
					transition.criticality !== RecoveryCriticality.Reconstructable
				) {
					const sequence = this.options.journal.nextSequence();
					const ids = outboxIds.filter((id): id is number => id != null);
					if (ids.length && this.storage.setOutboxFrameSequence) {
						this.storage.setOutboxFrameSequence(ids, Number(sequence));
					}
					// appendFrame reports the sequence it actually used, which is
					// what a Phase 6 barrier waits on. nextSequence agrees with it
					// in all three append branches, but the barrier is a fund
					// safety gate: it takes the value the frame was written under,
					// not a prediction of it.
					frameSequence = this.options.journal.appendFrame(
						mutations,
						outboundMessages
					);
					journaled = true;
				}
			});
		} catch (error) {
			this.options.journal?.onCommitRollback?.();
			this.options.onError?.(error as Error, {
				criticality: transition.criticality,
				reportedByCaller: transition.reportedByCaller === true
			});
			// The transaction rolled back, so any counter we bumped for rows that
			// no longer exist has to come back down; drop the cached counts for
			// the touched channels and let them re-seed from storage. An
			// outbox_supersede also touched the cache mid-transaction (its
			// deletes re-seeded the count), so its channel drops too.
			for (const message of outboundMessages) {
				if (message.channelId) this.outboxCounts.delete(message.channelId);
			}
			for (const mutation of mutations) {
				if (
					mutation.type === 'outbox_supersede' ||
					mutation.type === 'channel_closed'
				) {
					this.outboxCounts.delete(mutation.channelId);
				}
			}
			return {
				committed: false,
				released: [],
				error: error as Error,
				frameSequence: null
			};
		}

		// channel_closed deleted the channel's outbox rows with it (the storage
		// layer cascades); a stale cached count would survive the row deletion.
		for (const mutation of mutations) {
			if (mutation.type === 'channel_closed') {
				this.outboxCounts.delete(mutation.channelId);
			}
		}

		// A frame was durably appended: let the owner refresh derived replicas
		// (the peer_storage capsule, spec 5.4). Outside the transaction, after
		// commit, and never allowed to fail the transition it observed.
		if (journaled && this.options.onCommitted) {
			try {
				this.options.onCommitted();
			} catch {
				/* observer only */
			}
		}

		return {
			committed: true,
			released: outboundMessages.map((message, index) => ({
				id: outboxIds[index] ?? null,
				message
			})),
			frameSequence
		};
	}

	/**
	 * Mark released rows as written to the socket. Best-effort: a row still
	 * reading `pending_send` after a real send only means reestablish may offer
	 * it again, which peers treat idempotently.
	 */
	markSent(ids: Array<number | null>): void {
		if (!this.storage.setOutboxDisposition) return;
		for (const id of ids) {
			if (id == null) continue;
			try {
				this.storage.setOutboxDisposition(id, 'sent_unacked');
			} catch {
				// Diagnostic state only; never fail a completed send over it.
			}
		}
	}

	/**
	 * Drop the rows a peer has proven it holds. Called when the reestablish
	 * exchange shows the peer is caught up, per spec 5.2.
	 *
	 * Superseded rows are DELETED rather than kept in a terminal disposition:
	 * their only consumer is retransmission, which by definition no longer
	 * needs them, and retaining them would reintroduce the unbounded-growth
	 * problem the row cap exists to prevent.
	 */
	supersedeChannelOutbox(channelId: string, messageTypes?: number[]): void {
		if (!this.storage.deleteOutboxMessages) return;
		try {
			this.storage.deleteOutboxMessages(channelId, messageTypes);
			this.outboxCounts.delete(channelId);
		} catch (error) {
			this.options.onError?.(error as Error, {
				criticality: RecoveryCriticality.Important,
				reportedByCaller: false
			});
		}
	}

	/** Every retained outbox row, oldest first. */
	getOutbox(channelId?: string): IRecoveryOutboxRow[] {
		if (!this.storage.loadOutboxMessages) return [];
		try {
			return this.storage.loadOutboxMessages(channelId);
		} catch {
			return [];
		}
	}

	/** Forget a closed channel's rows entirely. */
	clearChannelOutbox(channelId: string): void {
		this.supersedeChannelOutbox(channelId);
	}

	// ─────────────── internals ───────────────

	private insertOutboxRow(message: RecoveryOutboundMessage): number | null {
		if (!this.storage.saveOutboxMessage) return null;
		const channelId = message.channelId;

		// Types where only the newest row is ever retransmitted retire the
		// channel's older rows of the same type as they are written. This runs
		// INSIDE the caller's transaction, so the replacement is atomic: a
		// crash cannot leave the channel with neither the old row nor the new.
		if (
			channelId &&
			this.storage.deleteOutboxMessages &&
			SUPERSEDES_OWN_KIND_MESSAGE_TYPES.includes(message.messageType)
		) {
			this.storage.deleteOutboxMessages(channelId, [message.messageType]);
			this.outboxCounts.delete(channelId);
		}

		// Counted BEFORE the insert: seeding from storage afterwards would count
		// the new row and then add one for it again.
		const before = channelId ? this.countFor(channelId) : 0;
		const id = this.storage.saveOutboxMessage(message);
		if (channelId) {
			const count = before + 1;
			this.outboxCounts.set(channelId, count);
			if (count > this.maxOutboxRows && this.storage.pruneOutboxMessages) {
				this.storage.pruneOutboxMessages(channelId, this.maxOutboxRows);
				this.outboxCounts.set(channelId, this.maxOutboxRows);
			}
		}
		return id;
	}

	private countFor(channelId: string): number {
		const cached = this.outboxCounts.get(channelId);
		if (cached !== undefined) return cached;
		// Prefer the dedicated count: the cache goes cold on every same-kind
		// supersede (once per commitment round on a busy channel), and seeding
		// through loadOutboxMessages would decrypt every retained row just to
		// take .length of the result.
		const seeded = this.storage.countOutboxMessages
			? this.storage.countOutboxMessages(channelId)
			: this.storage.loadOutboxMessages
			? this.storage.loadOutboxMessages(channelId).length
			: 0;
		this.outboxCounts.set(channelId, seeded);
		return seeded;
	}

	private applyMutation(mutation: RecoveryMutation): void {
		switch (mutation.type) {
			case 'channel_state':
				this.storage.saveChannel(
					mutation.channelId,
					mutation.state,
					mutation.peerPubkey
				);
				break;
			case 'channel_key_index':
				this.storage.saveChannelKeyIndex(
					mutation.channelId,
					mutation.channelIndex
				);
				break;
			case 'chain_monitor':
				this.storage.saveChainMonitor(mutation.channelId, mutation.state);
				break;
			case 'payment_preimage':
				this.storage.savePreimage(mutation.paymentHash, mutation.preimage);
				break;
			case 'htlc_payment_mapping':
				this.storage.saveHtlcPaymentMapping(
					mutation.htlcKey,
					mutation.paymentHash
				);
				break;
			case 'delete_htlc_payment_mapping':
				this.storage.deleteHtlcPaymentMapping(mutation.htlcKey);
				break;
			case 'htlc_shared_secret':
				this.storage.saveHtlcSharedSecret(mutation.key, mutation.secret);
				break;
			case 'delete_htlc_shared_secret':
				this.storage.deleteHtlcSharedSecret(mutation.key);
				break;
			case 'forwarded_htlc':
				this.storage.saveForwardedHtlc(
					mutation.outKey,
					mutation.inChannelId,
					mutation.inHtlcId
				);
				break;
			case 'delete_forwarded_htlc':
				this.storage.deleteForwardedHtlc(mutation.outKey);
				break;
			case 'payment_state':
				this.storage.savePayment(mutation.paymentHash, mutation.payment);
				break;
			case 'payment_secret':
				this.storage.savePaymentSecret(mutation.paymentHash, mutation.secret);
				break;
			case 'delete_payment_secret':
				this.storage.deletePaymentSecret(mutation.paymentHash);
				break;
			case 'delete_payment':
				this.storage.deletePayment(mutation.paymentHash);
				break;
			case 'delete_preimage':
				this.storage.deletePreimage(mutation.paymentHash);
				break;
			case 'invoice_state':
				this.storage.saveInvoice(mutation.paymentHash, mutation.invoice);
				break;
			case 'delete_invoice':
				this.storage.deleteInvoice(mutation.paymentHash);
				break;
			case 'invoice_path_id':
				this.storage.saveInvoicePathId?.(mutation.paymentHash, mutation.pathId);
				break;
			case 'delete_invoice_path_id':
				this.storage.deleteInvoicePathId(mutation.paymentHash);
				break;
			case 'forwarding_event':
				this.storage.saveForwardingEvent?.(mutation.event);
				break;
			case 'channel_closed':
				this.storage.deleteChannel(mutation.channelId);
				break;
			case 'outbox_supersede':
				// Runs INSIDE the caller's transaction: the peer-proven row
				// deletions commit with the state that processed the proof, or
				// roll back with it. The cache drops so any insert later in
				// this same transaction re-seeds against the post-delete table.
				if (this.storage.deleteOutboxMessages) {
					this.storage.deleteOutboxMessages(
						mutation.channelId,
						mutation.messageTypes
					);
					this.outboxCounts.delete(mutation.channelId);
				}
				break;
		}
	}
}
