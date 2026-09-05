/**
 * Async payments: AsyncPaymentManager.
 *
 * Two roles, wired through onion messages:
 *  - LSP: parks a forward destined for an offline receiver in the durable
 *    held-forward ledger, tells the receiver what is parked (HELD_HTLC_NOTICE)
 *    and releases parts when a valid release capability arrives.
 *  - Receiver: learns what is parked from a notice (or asks with a query),
 *    signs a release capability with its node key and sends it; on a wake
 *    message, emits so the host reconnects to the LSP.
 *
 * The manager owns the ledger's state machine. The node supplies, per hold,
 * a driver that can place the onward add or fail the inbound HTLC; drivers
 * are process memory and are re-armed by the restart redispatch, while the
 * ledger row is the durable truth every driver action is judged against.
 *
 * Authorization (issue #708): a release names hold ids, is signed by the
 * receiver's node key over a domain-separated digest (release-capability.ts),
 * must arrive from the peer it names as receiver, and that peer must be the
 * one the HOLD recorded as the outgoing channel's peer. The payment hash is
 * never an input to authorization.
 */

import crypto from 'crypto';
import { EventEmitter } from 'events';
import { OnionMessageManager } from '../onion-message/manager';
import {
	RELEASE_HELD_HTLC_TLV_TYPE,
	ASYNC_WAKE_TLV_TYPE,
	HELD_HTLC_NOTICE_TLV_TYPE,
	HELD_HTLC_QUERY_TLV_TYPE,
	IHeldForwardNotice,
	IHeldForwardNoticeEntry,
	encodeHeldForwardNotice,
	decodeHeldForwardNotice
} from './types';
import { HeldForwardLedger, IHeldForwardRecord } from './held-forward-ledger';
import {
	IReleaseCapability,
	decodeReleaseCapability,
	deriveHoldRegistrationId,
	encodeReleaseCapability,
	signReleaseCapability,
	verifyReleaseCapability
} from './release-capability';

/** How the node acts on one hold, armed at dispatch (and re-dispatch). */
export interface IHeldForwardDriver {
	/**
	 * Place the onward add. `forwarded` once the outgoing leg exists,
	 * `deferred` when the outgoing channel cannot take an add right now
	 * (reestablishing, quiescing), `refused` when the add was refused and
	 * the refusal path has already resolved the inbound HTLC.
	 */
	forward: () => 'forwarded' | 'deferred' | 'refused';
	/** Fail the inbound HTLC upstream; false when it cannot be carried now. */
	fail: () => boolean;
}

export interface IAsyncPaymentManagerDeps {
	nodePrivkey: Buffer;
	nodeId: Buffer;
	chainHash: Buffer;
	currentHeight: () => number;
	/** Durable fact: the forward linkage row for this hold's inbound HTLC exists. */
	hasOutgoingLeg: (record: IHeldForwardRecord) => boolean;
	/** Durable fact: the inbound HTLC is still committed and unresolved. */
	incomingUnresolved: (record: IHeldForwardRecord) => boolean;
	/**
	 * All-or-nothing at the channel (issue #708 review): can every one of
	 * these unplaced parts be placed right now, judged together? True when
	 * the outgoing channel cannot take adds at all yet (the driver defers
	 * then); false only when the channel can, and the set does not fit.
	 */
	canForwardSet?: (records: IHeldForwardRecord[]) => boolean;
	/** Unix milliseconds; injectable for expiry tests. */
	now?: () => number;
	/**
	 * Receiver role (issue #709): the registration id a release of these
	 * holds at this LSP must name: the one the LSP's notice reported for
	 * them (a hold resolves under the registration it was parked under,
	 * expired or superseded since or not), else the live grant's. Undefined
	 * falls back to the derived placeholder id (pre-#709 LSPs).
	 */
	registrationIdFor?: (
		lspNodeIdHex: string,
		holdIds: Buffer[]
	) => Buffer | undefined;
}

/** How registerHold judges a NEW hold before writing its row (issue #709). */
export type HoldAdmissionJudge = () =>
	| { ok: true; patch?: Partial<IHeldForwardRecord> }
	| { ok: false; reason: string };

export type RegisterHoldOutcome =
	| { record: IHeldForwardRecord; created: boolean }
	| { refused: string }
	| { storageFailed: true };

export type ReleaseRefusalReason =
	| 'not_rehydrated'
	| 'malformed'
	| 'wrong_network'
	| 'wrong_lsp'
	| 'sender_mismatch'
	| 'bad_signature'
	| 'expired'
	| 'unknown_hold'
	| 'registration_mismatch'
	| 'past_cutoff'
	| 'amount_mismatch'
	| 'stale'
	| 'storage_failed';

export interface IReleaseOutcome {
	ok: boolean;
	/** A valid capability the ledger had already honoured (replay). */
	duplicate?: boolean;
	reason?: ReleaseRefusalReason;
	holdIds?: string[];
}

/** Default lifetime of a receiver-issued capability. */
const DEFAULT_CAPABILITY_TTL_SEC = 600;

export class AsyncPaymentManager extends EventEmitter {
	private onionManager: OnionMessageManager | null = null;
	private drivers = new Map<string, IHeldForwardDriver>();

	constructor(
		private readonly ledger: HeldForwardLedger,
		private readonly deps: IAsyncPaymentManagerDeps
	) {
		super();
	}

	/** The ledger, for inspection and operator tooling. */
	getLedger(): HeldForwardLedger {
		return this.ledger;
	}

	/**
	 * Attach the onion message manager and register handlers for the async
	 * TLVs. Every handler is self-contained: a malformed message is refused,
	 * never thrown.
	 */
	attachOnionMessageManager(onionManager: OnionMessageManager): void {
		this.onionManager = onionManager;
		onionManager.registerTlvHandler(
			RELEASE_HELD_HTLC_TLV_TYPE,
			(fromPeer, _type, data) => {
				this.handleRelease(fromPeer, data);
			}
		);
		onionManager.registerTlvHandler(
			ASYNC_WAKE_TLV_TYPE,
			(_fromPeer, _type, data) => {
				// data is the payment hash the sender wants paid.
				this.emit('wake', data.length === 32 ? data : undefined);
			}
		);
		onionManager.registerTlvHandler(
			HELD_HTLC_NOTICE_TLV_TYPE,
			(fromPeer, _type, data) => {
				const notice = decodeHeldForwardNotice(data);
				if (!notice) return;
				this.emit('held-notice', {
					lspNodeId: Buffer.from(fromPeer, 'hex'),
					notice
				});
			}
		);
		onionManager.registerTlvHandler(HELD_HTLC_QUERY_TLV_TYPE, (fromPeer) => {
			this.sendNotice(fromPeer);
		});
	}

	// ─────────────── LSP role ───────────────

	/**
	 * Park a forward. Idempotent on the inbound HTLC's canonical identity: a
	 * redispatch after restart (or a replayed add) re-arms the driver on the
	 * existing record and, if that record is mid-transition, drives it.
	 * Returns null when the durable write failed; the caller must then not
	 * treat the HTLC as held.
	 */
	registerHold(
		fields: Parameters<HeldForwardLedger['register']>[0],
		driver: IHeldForwardDriver,
		judge?: HoldAdmissionJudge
	): RegisterHoldOutcome {
		// An inbound HTLC that already has a row is a redispatch: its
		// resources were reserved when the row was written, so admission is
		// not judged again (a restart must never refuse what it still owes).
		const existing = this.ledger.byIncoming(
			fields.inChannelIdHex,
			BigInt(fields.inHtlcId)
		);
		let toRegister = fields;
		if (!existing && judge) {
			// Verdict and durable write in one synchronous step: nothing can
			// interleave a second admission between them.
			const verdict = judge();
			if (!verdict.ok) return { refused: verdict.reason };
			if (verdict.patch) toRegister = { ...fields, ...verdict.patch };
		}
		const result = this.ledger.register(toRegister);
		if (!result) return { storageFailed: true };
		const { record, created } = result;
		if (!created && record.state !== 'HELD') {
			if (record.state === 'RELEASED' || record.state === 'FAILED') {
				// Terminal already: nothing to arm. The caller decides what a
				// redispatch of a resolved hold means (it should not happen:
				// a resolved inbound HTLC is not redispatched).
				return { record, created };
			}
			this.drivers.set(record.id, driver);
			this.driveHold(record.id);
			return { record: this.ledger.get(record.id) ?? record, created };
		}
		this.drivers.set(record.id, driver);
		if (created) this.emit('held', record);
		return { record, created };
	}

	/**
	 * LSP: judge a release capability from `fromPeer` and, when it is valid,
	 * move the named set HELD -> RELEASING atomically and drive each part.
	 */
	handleRelease(fromPeer: string, data: Buffer): IReleaseOutcome {
		const refuse = (reason: ReleaseRefusalReason): IReleaseOutcome => {
			this.emit('release-refused', { fromPeer, reason });
			return { ok: false, reason };
		};
		if (!this.ledger.isRehydrated()) return refuse('not_rehydrated');
		const cap = decodeReleaseCapability(data);
		if (!cap) return refuse('malformed');
		if (!cap.chainHash.equals(this.deps.chainHash)) {
			return refuse('wrong_network');
		}
		if (!cap.lspNodeId.equals(this.deps.nodeId)) return refuse('wrong_lsp');
		const receiverHex = cap.receiverNodeId.toString('hex');
		// The transport-authenticated sender must be the identity the
		// capability names; a relayed or spoofed release fails here before
		// any signature work.
		if (receiverHex !== fromPeer) return refuse('sender_mismatch');
		if (!verifyReleaseCapability(cap)) return refuse('bad_signature');
		const nowSec = BigInt(Math.floor((this.deps.now ?? Date.now)() / 1000));
		if (nowSec > cap.expiresAt) return refuse('expired');

		const ids = cap.holdIds.map((h) => h.toString('hex'));
		const nonceHex = cap.nonce.toString('hex');
		const records: IHeldForwardRecord[] = [];
		for (const id of ids) {
			const r = this.ledger.get(id);
			// A hold that exists for someone else is reported exactly like one
			// that does not exist: a caller never learns another receiver's
			// hold ids through this handler.
			if (!r || r.receiverNodeIdHex !== receiverHex) {
				return refuse('unknown_hold');
			}
			if (r.registrationIdHex !== cap.registrationId.toString('hex')) {
				return refuse('registration_mismatch');
			}
			records.push(r);
		}
		// Replay of a capability the ledger already honoured: every member
		// left HELD under this very nonce. Idempotent success, no action.
		if (
			records.every((r) => r.state !== 'HELD' && r.releaseNonceHex === nonceHex)
		) {
			return { ok: true, duplicate: true, holdIds: ids };
		}
		let sum = 0n;
		for (const r of records) sum += BigInt(r.forwardAmountMsat);
		if (sum !== cap.amountMsat) return refuse('amount_mismatch');
		const height = this.deps.currentHeight();
		if (height > 0 && records.some((r) => height >= r.cutoffHeight)) {
			return refuse('past_cutoff');
		}
		const result = this.ledger.beginRelease(ids, nonceHex);
		if (result.outcome !== 'applied') {
			if (result.outcome === 'storage_failed') return refuse('storage_failed');
			if (result.outcome === 'not_rehydrated') return refuse('not_rehydrated');
			// stale/missing: another transition (the cutoff, a fail, an
			// earlier release) already moved a member. Idempotent no-op.
			return refuse('stale');
		}
		this.emit('release-accepted', {
			holdIds: ids,
			receiverNodeIdHex: receiverHex
		});
		for (const id of ids) this.driveHold(id);
		return { ok: true, holdIds: ids };
	}

	/** Operator: fail a hold now (HELD, or RELEASING with no add placed). */
	failHeldForward(holdIdHex: string, reason = 'operator'): boolean {
		const r = this.ledger.get(holdIdHex);
		if (!r) return false;
		let result;
		if (r.state === 'HELD') {
			result = this.ledger.beginFail(holdIdHex, reason);
		} else if (r.state === 'RELEASING' && !this.deps.hasOutgoingLeg(r)) {
			result = this.ledger.abandonRelease(holdIdHex, reason);
		} else {
			return false;
		}
		if (result.outcome !== 'applied') return false;
		this.driveHold(holdIdHex);
		return true;
	}

	/**
	 * Act on a hold's durable state with its armed driver. Every action is
	 * gated on the row: a RELEASING row forwards, a FAILING row fails, and
	 * both settle to their terminal state only after the action is real
	 * (the outgoing leg exists / the failure was accepted by the channel).
	 */
	driveHold(holdIdHex: string): void {
		const r = this.ledger.get(holdIdHex);
		if (!r) return;
		const driver = this.drivers.get(holdIdHex);
		if (r.state === 'RELEASING') {
			if (this.deps.hasOutgoingLeg(r)) {
				this.finish(this.ledger.markReleased(holdIdHex), 'released');
				return;
			}
			if (!driver) return;
			// A set of more than one part is placed whole or not at all: the
			// ledger transition was atomic, and the channel must be too. Every
			// unplaced member is judged together before this add leaves; a set
			// that does not fit is failed back whole, never delivered half.
			// A single part needs no such check: there is no half of one, and
			// the add's own verdict is exact.
			const set = this.unplacedReleaseSet(r);
			if (
				set.length > 1 &&
				this.deps.canForwardSet &&
				!this.deps.canForwardSet(set)
			) {
				for (const member of set) {
					this.ledger.abandonRelease(member.id, 'set_capacity');
				}
				this.emit('release-set-failed', {
					holdIds: set.map((m) => m.id),
					reason: 'set_capacity'
				});
				for (const member of set) this.driveHold(member.id);
				return;
			}
			const outcome = driver.forward();
			if (outcome === 'forwarded') {
				this.finish(this.ledger.markReleased(holdIdHex), 'released');
			} else if (outcome === 'refused') {
				this.finish(
					this.ledger.markReleaseRefused(holdIdHex, 'forward_refused'),
					'failed'
				);
			}
			// deferred: the row stays RELEASING and a later channel event or
			// block re-drives it.
			return;
		}
		if (r.state === 'FAILING') {
			if (!this.deps.incomingUnresolved(r)) {
				this.finish(this.ledger.markFailed(holdIdHex), 'failed');
				return;
			}
			if (!driver) return;
			if (driver.fail()) {
				this.finish(this.ledger.markFailed(holdIdHex), 'failed');
			}
		}
	}

	/**
	 * The members of `r`'s release set (the rows that left HELD under the
	 * same capability) that are still RELEASING with no outgoing leg.
	 */
	private unplacedReleaseSet(r: IHeldForwardRecord): IHeldForwardRecord[] {
		if (!r.releaseNonceHex) return [r];
		return this.ledger
			.list()
			.filter(
				(x) =>
					x.state === 'RELEASING' &&
					x.releaseNonceHex === r.releaseNonceHex &&
					!this.deps.hasOutgoingLeg(x)
			);
	}

	private finish(
		result: ReturnType<HeldForwardLedger['markReleased']>,
		event: 'released' | 'failed'
	): void {
		if (result.outcome !== 'applied' || !result.record) return;
		this.drivers.delete(result.record.id);
		this.emit(event, result.record);
	}

	/**
	 * Repair from durable facts alone (safe on every run): a RELEASING row
	 * whose outgoing leg exists is RELEASED; any unresolved row whose inbound
	 * HTLC is gone (settled, failed, or its channel closed) is FAILED.
	 */
	reconcile(): void {
		for (const r of this.ledger.unresolved()) {
			if (r.state === 'RELEASING' && this.deps.hasOutgoingLeg(r)) {
				this.finish(this.ledger.markReleased(r.id), 'released');
				continue;
			}
			if (!this.deps.incomingUnresolved(r)) {
				if (r.state === 'HELD') {
					this.ledger.beginFail(r.id, 'incoming_resolved');
				} else if (r.state === 'RELEASING') {
					this.ledger.abandonRelease(r.id, 'incoming_resolved');
				}
				this.finish(this.ledger.markFailed(r.id), 'failed');
			}
		}
	}

	/**
	 * Per-block work: the CLTV cutoff. At `cutoffHeight` a HELD row moves to
	 * FAILING (the transition a racing release loses against), an unplaced
	 * RELEASING row too, and every pending transition is re-driven.
	 */
	scan(height: number): void {
		if (height <= 0) return;
		this.reconcile();
		for (const r of this.ledger.unresolved()) {
			if (r.state === 'HELD') {
				if (height >= r.cutoffHeight) {
					if (this.ledger.beginFail(r.id, 'cutoff').outcome === 'applied') {
						this.driveHold(r.id);
					}
				}
				continue;
			}
			if (
				r.state === 'RELEASING' &&
				height >= r.cutoffHeight &&
				!this.deps.hasOutgoingLeg(r)
			) {
				this.ledger.abandonRelease(r.id, 'cutoff_unplaced');
			}
			this.driveHold(r.id);
		}
	}

	/** A channel can carry updates again: re-drive what waited on it. */
	onChannelUsable(channelIdHex: string): void {
		for (const r of this.ledger.unresolved()) {
			if (
				r.inChannelIdHex === channelIdHex ||
				r.outChannelIdHex === channelIdHex
			) {
				this.driveHold(r.id);
			}
		}
	}

	/** Every record, for operators and tests. */
	listHeldForwards(): IHeldForwardRecord[] {
		return this.ledger.list();
	}

	/** Records still owed an action. */
	listUnresolved(): IHeldForwardRecord[] {
		return this.ledger.unresolved();
	}

	/** The notice for one receiver: its HELD parts. */
	noticeFor(receiverNodeIdHex: string): IHeldForwardNotice {
		const entries: IHeldForwardNoticeEntry[] = this.ledger
			.forReceiver(receiverNodeIdHex)
			.filter((r) => r.state === 'HELD')
			.map((r) => ({
				holdId: Buffer.from(r.id, 'hex'),
				paymentHash: Buffer.from(r.paymentHashHex, 'hex'),
				forwardAmountMsat: BigInt(r.forwardAmountMsat),
				forwardCltv: r.forwardCltv,
				cutoffHeight: r.cutoffHeight,
				registrationId: Buffer.from(r.registrationIdHex, 'hex')
			}));
		return { entries };
	}

	/**
	 * LSP: tell a receiver what is parked for it. False when nothing is, or
	 * when no transport is attached (an embedded node without networking).
	 */
	sendNotice(receiverNodeIdHex: string): boolean {
		const notice = this.noticeFor(receiverNodeIdHex);
		if (notice.entries.length === 0 || !this.onionManager) return false;
		try {
			this.onionManager.sendOnionMessage(
				Buffer.from(receiverNodeIdHex, 'hex'),
				new Map([[HELD_HTLC_NOTICE_TLV_TYPE, encodeHeldForwardNotice(notice)]])
			);
			return true;
		} catch {
			return false;
		}
	}

	// ─────────────── Receiver role ───────────────

	/**
	 * Receiver: build a capability over `holdIds` for the LSP and send it.
	 * `amountMsat` must equal the sum of the parts' forward amounts as the
	 * notice reported them. Returns the capability sent (tests inspect it).
	 */
	sendRelease(
		lspNodeId: Buffer,
		holdIds: Buffer[],
		amountMsat: bigint,
		options?: { ttlSec?: number; registrationId?: Buffer }
	): IReleaseCapability {
		if (!this.onionManager) throw new Error('onion manager not attached');
		const cap = this.buildRelease(lspNodeId, holdIds, amountMsat, options);
		this.onionManager.sendOnionMessage(
			lspNodeId,
			new Map([[RELEASE_HELD_HTLC_TLV_TYPE, encodeReleaseCapability(cap)]])
		);
		return cap;
	}

	/** Receiver: sign a capability without sending it. */
	buildRelease(
		lspNodeId: Buffer,
		holdIds: Buffer[],
		amountMsat: bigint,
		options?: { ttlSec?: number; registrationId?: Buffer }
	): IReleaseCapability {
		const nowSec = Math.floor((this.deps.now ?? Date.now)() / 1000);
		return signReleaseCapability(
			{
				chainHash: this.deps.chainHash,
				receiverNodeId: this.deps.nodeId,
				lspNodeId,
				registrationId:
					options?.registrationId ??
					this.deps.registrationIdFor?.(lspNodeId.toString('hex'), holdIds) ??
					deriveHoldRegistrationId(this.deps.nodeId, lspNodeId),
				amountMsat,
				expiresAt: BigInt(
					nowSec + (options?.ttlSec ?? DEFAULT_CAPABILITY_TTL_SEC)
				),
				nonce: crypto.randomBytes(32),
				holdIds
			},
			this.deps.nodePrivkey
		);
	}

	/** Receiver: ask the LSP for a notice of everything parked for us. */
	sendQuery(lspNodeId: Buffer): void {
		if (!this.onionManager) throw new Error('onion manager not attached');
		this.onionManager.sendOnionMessage(
			lspNodeId,
			new Map([[HELD_HTLC_QUERY_TLV_TYPE, Buffer.alloc(0)]])
		);
	}

	/** Sender: nudge an offline receiver to come online for a payment hash. */
	sendWake(receiverNodeId: Buffer, paymentHash: Buffer): void {
		if (!this.onionManager) throw new Error('onion manager not attached');
		this.onionManager.sendOnionMessage(
			receiverNodeId,
			new Map([[ASYNC_WAKE_TLV_TYPE, paymentHash]])
		);
	}
}
