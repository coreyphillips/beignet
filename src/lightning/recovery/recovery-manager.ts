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

import { IStorageBackend } from '../storage/types';
import {
	IRecoveryCommitResult,
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
		context: { criticality: RecoveryCriticality }
	) => void;
	/**
	 * Per-channel cap on retained outbox rows. A peer that never reconnects
	 * would otherwise let the table grow without bound. Exceeding the cap
	 * prunes the OLDEST rows, degrading that channel to reconstruct-from-state
	 * retransmission, which is exactly today's behavior.
	 */
	maxOutboxRowsPerChannel?: number;
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
			return { committed: true, released: [] };
		}

		const outboxIds: Array<number | null> = [];
		try {
			this.storage.transaction(() => {
				for (const mutation of mutations) {
					this.applyMutation(mutation);
				}
				for (const message of outboundMessages) {
					outboxIds.push(this.insertOutboxRow(message));
				}
			});
		} catch (error) {
			this.options.onError?.(error as Error, {
				criticality: transition.criticality
			});
			// The transaction rolled back, so any counter we bumped for rows that
			// no longer exist has to come back down; drop the cached counts for
			// the touched channels and let them re-seed from storage.
			for (const message of outboundMessages) {
				if (message.channelId) this.outboxCounts.delete(message.channelId);
			}
			return { committed: false, released: [], error: error as Error };
		}

		return {
			committed: true,
			released: outboundMessages.map((message, index) => ({
				id: outboxIds[index] ?? null,
				message
			}))
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
				criticality: RecoveryCriticality.Important
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
		const id = this.storage.saveOutboxMessage(message);
		const channelId = message.channelId;
		if (channelId) {
			const count = (this.countFor(channelId) ?? 0) + 1;
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
		const seeded = this.storage.loadOutboxMessages
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
			case 'channel_closed':
				this.storage.deleteChannel(mutation.channelId);
				break;
		}
	}
}
