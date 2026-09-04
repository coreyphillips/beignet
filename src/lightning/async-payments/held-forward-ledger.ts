/**
 * Held-forward ledger (issue #708): the durable record of every inbound HTLC
 * an LSP has parked for an offline receiver, with its lifecycle.
 *
 * Identity. Every held incoming HTLC gets a random 32-byte `hold_id` and
 * keeps its canonical (incoming_channel_id, incoming_htlc_id) identity. The
 * payment hash is an INDEX (parts of one payment share it), never a key:
 * two MPP parts, a retry, or a duplicate add each get their own record.
 *
 * Lifecycle, every arrow a compare-and-swap on the durable row:
 *
 *   HELD -> RELEASING -> RELEASED      (capability accepted, forward placed)
 *   HELD -> FAILING   -> FAILED        (cutoff reached, or operator fail)
 *   RELEASING -> FAILING               (release won, but the forward could
 *                                       not be placed before the cutoff)
 *   RELEASING -> FAILED                (the forward was refused outright and
 *                                       the refusal already failed upstream)
 *
 * The CLTV cutoff. A hold's `cutoffHeight` is fixed when it is parked:
 *
 *   cutoffHeight = min(forwardCltv - DEFAULT_MIN_FINAL_CLTV_EXPIRY,
 *                      incomingCltvExpiry - heldExpiryMargin)
 *
 * The first term is the last height at which the outgoing HTLC still gives
 * the receiver the final-hop headroom it advertises (a beignet receiver
 * refuses anything shorter as expiry-too-soon); the second is the LSP's own
 * margin before its inbound leg would have to be resolved on-chain. A
 * release is accepted only while height < cutoffHeight; at cutoffHeight the
 * per-block scan moves the hold to FAILING. Both are CAS transitions on the
 * same row from HELD, so a release racing the cutoff has exactly one durable
 * winner: whichever write lands first, and the loser sees `stale`.
 *
 * MPP policy. Atomic payment-set release is the default: the receiver, who
 * alone knows the payment's total, signs one capability naming the complete
 * set of hold ids, and `beginRelease` moves the whole set HELD -> RELEASING
 * in one store transaction or not at all. Independent part release is the
 * same call with a set of one, which a receiver uses for amount-less
 * invoices where no total is known. The LSP never guesses a total: it
 * cannot see total_msat inside a blinded final payload.
 */

import crypto from 'crypto';
import {
	DurableLedger,
	IDurableLedgerStore,
	ILedgerCodec,
	ILedgerRecord,
	ILedgerTransitionResult
} from '../storage/durable-ledger';

export type HeldForwardState =
	| 'HELD'
	| 'RELEASING'
	| 'RELEASED'
	| 'FAILING'
	| 'FAILED';

export interface IHeldForwardRecord extends ILedgerRecord {
	/** hold_id, 32 random bytes as hex. */
	id: string;
	state: HeldForwardState;
	/** Canonical identity of the parked inbound HTLC. */
	inChannelIdHex: string;
	inHtlcId: string;
	/** Index only. */
	paymentHashHex: string;
	outChannelIdHex: string;
	/** Peer on the outgoing channel: the only identity that may release. */
	receiverNodeIdHex: string;
	registrationIdHex: string;
	incomingAmountMsat: string;
	forwardAmountMsat: string;
	forwardCltv: number;
	incomingCltvExpiry: number;
	cutoffHeight: number;
	createdAt: number;
	/** Nonce of the capability that moved the record to RELEASING. */
	releaseNonceHex?: string;
	/** Why the record left HELD/RELEASING for the fail path. */
	failReason?: string;
	resolvedAt?: number;
}

export const HELD_FORWARD_LEDGER_PREFIX = 'held_forward';

const STATES: HeldForwardState[] = [
	'HELD',
	'RELEASING',
	'RELEASED',
	'FAILING',
	'FAILED'
];

export const heldForwardCodec: ILedgerCodec<IHeldForwardRecord> = {
	encode: (record) => JSON.stringify(record),
	decode: (raw) => {
		try {
			const parsed = JSON.parse(raw) as Partial<IHeldForwardRecord>;
			if (
				typeof parsed.id !== 'string' ||
				!STATES.includes(parsed.state as HeldForwardState) ||
				typeof parsed.inChannelIdHex !== 'string' ||
				typeof parsed.inHtlcId !== 'string' ||
				typeof parsed.paymentHashHex !== 'string' ||
				typeof parsed.outChannelIdHex !== 'string' ||
				typeof parsed.receiverNodeIdHex !== 'string' ||
				typeof parsed.cutoffHeight !== 'number'
			) {
				return null;
			}
			return parsed as IHeldForwardRecord;
		} catch {
			return null;
		}
	}
};

export function isUnresolvedHeldForward(state: HeldForwardState): boolean {
	return state === 'HELD' || state === 'RELEASING' || state === 'FAILING';
}

export type HeldForwardTransition = ILedgerTransitionResult<IHeldForwardRecord>;

export class HeldForwardLedger {
	private readonly ledger: DurableLedger<IHeldForwardRecord>;

	constructor(store: IDurableLedgerStore<IHeldForwardRecord>) {
		this.ledger = new DurableLedger(store);
	}

	rehydrate(): number {
		return this.ledger.rehydrate();
	}

	isRehydrated(): boolean {
		return this.ledger.isRehydrated();
	}

	get(holdIdHex: string): IHeldForwardRecord | undefined {
		return this.ledger.get(holdIdHex);
	}

	list(): IHeldForwardRecord[] {
		return this.ledger.list();
	}

	unresolved(): IHeldForwardRecord[] {
		return this.ledger.find((r) => isUnresolvedHeldForward(r.state));
	}

	/** The record for an inbound HTLC, by its canonical identity. */
	byIncoming(
		inChannelIdHex: string,
		inHtlcId: bigint
	): IHeldForwardRecord | undefined {
		const id = inHtlcId.toString();
		return this.ledger.find(
			(r) => r.inChannelIdHex === inChannelIdHex && r.inHtlcId === id
		)[0];
	}

	/** Payment-level index: every part parked under one hash. */
	partsForPaymentHash(paymentHashHex: string): IHeldForwardRecord[] {
		return this.ledger.find((r) => r.paymentHashHex === paymentHashHex);
	}

	/** Unresolved holds whose outgoing peer is this receiver. */
	forReceiver(receiverNodeIdHex: string): IHeldForwardRecord[] {
		return this.ledger.find(
			(r) =>
				r.receiverNodeIdHex === receiverNodeIdHex &&
				isUnresolvedHeldForward(r.state)
		);
	}

	/**
	 * Park a new hold. Idempotent on the canonical identity: an inbound HTLC
	 * that already has a record (a restart's redispatch, a replayed add)
	 * gets that record back, keeping the hold_id any capability already
	 * names.
	 */
	register(
		fields: Omit<
			IHeldForwardRecord,
			'id' | 'state' | 'createdAt' | 'releaseNonceHex' | 'failReason'
		>
	): { record: IHeldForwardRecord; created: boolean } | null {
		const existing = this.byIncoming(
			fields.inChannelIdHex,
			BigInt(fields.inHtlcId)
		);
		if (existing) return { record: existing, created: false };
		const record: IHeldForwardRecord = {
			...fields,
			id: crypto.randomBytes(32).toString('hex'),
			state: 'HELD',
			createdAt: Date.now()
		};
		const result = this.ledger.insert(record);
		if (result.outcome !== 'applied' || !result.record) return null;
		return { record: result.record, created: true };
	}

	/**
	 * Atomic set release: every named hold moves HELD -> RELEASING in one
	 * transaction, or none does.
	 */
	beginRelease(holdIdHexes: string[], nonceHex: string): HeldForwardTransition {
		return this.ledger.transitionSet(holdIdHexes, ['HELD'], 'RELEASING', {
			releaseNonceHex: nonceHex
		});
	}

	markReleased(holdIdHex: string): HeldForwardTransition {
		return this.ledger.transition(holdIdHex, ['RELEASING'], 'RELEASED', {
			resolvedAt: Date.now()
		});
	}

	/**
	 * The cutoff (or an operator) fails a HELD row. From HELD only: a release
	 * that already won the race is never undone by this transition, which is
	 * what makes the race have exactly one winner.
	 */
	beginFail(holdIdHex: string, reason: string): HeldForwardTransition {
		return this.ledger.transition(holdIdHex, ['HELD'], 'FAILING', {
			failReason: reason
		});
	}

	/**
	 * A RELEASING row whose forward was never placed (no outgoing leg exists)
	 * and can no longer be: the cutoff arrived, or its inbound leg is gone.
	 * The caller must have checked the leg is absent; a placed add is owned
	 * by the forward machinery from then on.
	 */
	abandonRelease(holdIdHex: string, reason: string): HeldForwardTransition {
		return this.ledger.transition(holdIdHex, ['RELEASING'], 'FAILING', {
			failReason: reason
		});
	}

	markFailed(holdIdHex: string): HeldForwardTransition {
		return this.ledger.transition(holdIdHex, ['FAILING'], 'FAILED', {
			resolvedAt: Date.now()
		});
	}

	/**
	 * A RELEASING hold whose forward was refused outright: the refusal path
	 * already failed the inbound HTLC (or handed it to another engine), so
	 * the record is terminal without a FAILING pass of its own.
	 */
	markReleaseRefused(holdIdHex: string, reason: string): HeldForwardTransition {
		return this.ledger.transition(holdIdHex, ['RELEASING'], 'FAILED', {
			failReason: reason,
			resolvedAt: Date.now()
		});
	}

	/** Drop a terminal record (housekeeping; never an unresolved one). */
	forget(holdIdHex: string): boolean {
		const r = this.ledger.get(holdIdHex);
		if (!r || isUnresolvedHeldForward(r.state)) return false;
		return this.ledger.remove(holdIdHex);
	}
}
