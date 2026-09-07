/**
 * Swap ledger (issue #737, phase 2): the durable record of every swap a
 * provider has quoted, funded, paid, claimed or refunded, with its lifecycle
 * as compare-and-swap transitions on a DurableLedger row.
 *
 * Identity. A swap id is derived from the requesting peer and the payment
 * hash (keys.ts); the hash is an index, never the key.
 *
 * Reverse swap lifecycle (client pays Lightning, provider funds the chain):
 *
 *   CREATED -> HELD -> FUNDING -> FUNDING_BROADCAST -> FUNDED -> CLAIMED -> SETTLED
 *   FUNDED -> REFUND_PENDING -> REFUNDED          (nobody claimed; hold cancelled
 *                                                  only after REFUNDED)
 *   FUNDING_BROADCAST | REFUND_PENDING -> CLAIMED  (a claim at any depth wins)
 *   CREATED | HELD -> CANCELLED                    (nothing left the wallet)
 *   FUNDING -> FAILED                              (no transaction could be built,
 *                                                  or the hold went before broadcast)
 *   FUNDING_BROADCAST | FUNDED | REFUND_PENDING | CLAIMED -> EXPOSED
 *                                                  (the Lightning side was cancelled
 *                                                  under us; funds are on chain)
 *
 * Submarine swap lifecycle (client funds the chain, provider pays Lightning),
 * reserved here for the later engine:
 *
 *   CREATED -> FUNDING_SEEN -> FUNDED -> PAYING -> PREIMAGE_KNOWN
 *           -> CLAIM_BROADCAST -> CLAIM_CONFIRMED
 *   PAYING -> PAYMENT_UNRESOLVED -> PREIMAGE_KNOWN | PAYMENT_FAILED
 *   PAYING -> PAYMENT_FAILED
 *   FUNDING_SEEN | FUNDED -> FUNDING_LOST -> FUNDING_SEEN
 *   CREATED -> CANCELLED | FAILED
 *
 * Rules inherited from the held-forward ledger: durable write before memory,
 * every arrow a CAS, rehydrate before serve. Two rules of this ledger's own:
 * a preimage, once recorded, is never removed by any transition, and no
 * private key is ever stored (keys.ts re-derives them).
 */

import {
	DurableLedger,
	IDurableLedgerStore,
	ILedgerCodec,
	ILedgerRecord,
	ILedgerTransitionResult
} from '../storage/durable-ledger';

export type SwapDirection = 'reverse' | 'submarine';

export type ReverseSwapState =
	| 'CREATED'
	| 'HELD'
	| 'FUNDING'
	| 'FUNDING_BROADCAST'
	| 'FUNDED'
	| 'CLAIMED'
	| 'SETTLED'
	| 'REFUND_PENDING'
	| 'REFUNDED'
	| 'EXPOSED'
	| 'CANCELLED'
	| 'FAILED';

export type SubmarineSwapState =
	| 'CREATED'
	| 'FUNDING_SEEN'
	| 'FUNDED'
	| 'FUNDING_LOST'
	| 'PAYING'
	| 'PAYMENT_UNRESOLVED'
	| 'PREIMAGE_KNOWN'
	| 'CLAIM_BROADCAST'
	| 'CLAIM_CONFIRMED'
	| 'PAYMENT_FAILED'
	| 'CANCELLED'
	| 'FAILED';

export type SwapState = ReverseSwapState | SubmarineSwapState;

export type SwapResolutionKind = 'claim' | 'refund' | 'unknown';
export type SwapPreimageSource =
	| 'onchain-claim'
	| 'lightning'
	| 'peer'
	| 'other';

/** A recorded spend of the swap output, with what the chain last said about it. */
export interface ISwapResolutionRecord {
	kind: SwapResolutionKind;
	txid: string;
	/** Raw transaction, when we built it ourselves. */
	txHex?: string;
	/** Confirmation height; absent while in the mempool. */
	height?: number;
	confirmations: number;
	/** False until the chain has been asked about it since the last restart. */
	verifiedThisSession: boolean;
}

/**
 * One swap. Bigints travel as decimal strings and buffers as hex so the row
 * is plain JSON. Fields are grouped by the phase that writes them; a phase
 * never rewrites an earlier phase's facts.
 */
export interface ISwapRecord extends ILedgerRecord {
	/** Swap id hex (keys.ts deriveSwapId). */
	id: string;
	state: SwapState;
	direction: SwapDirection;
	peerNodeIdHex: string;
	/** Index only: parts of one payment share it. */
	paymentHashHex: string;
	/** Contract terms; the on-chain roles are independent of direction. */
	claimPubkeyHex: string;
	refundPubkeyHex: string;
	refundHeight: number;
	outputScriptHex: string;
	address: string;
	network: 'bitcoin' | 'testnet' | 'regtest' | 'signet';
	/** Amounts, decimal strings. */
	onchainSat: string;
	invoiceMsat: string;
	totalFeeSat: string;
	minerFeeSat: string;
	createdAt: number;
	createdHeight: number;
	updatedAt: number;
	/** Invoice facts (reverse: ours; submarine: the client's). */
	bolt11?: string;
	invoiceExpiresAt?: number;
	/** Reverse: the admitted held set. */
	heldAt?: number;
	heldHeight?: number;
	/** The earliest height the node's own sweeper may cancel the hold at. */
	cancellationHeight?: number;
	/** Funding, once known. `fundingTxHex` only when we built it. */
	fundingAttempts: number;
	fundingTxHex?: string;
	fundingTxid?: string;
	fundingVout?: number;
	fundingValueSat?: string;
	/**
	 * Set BEFORE the first broadcast is attempted. Absent on a row with
	 * bytes, the bytes never left this process: a hold cancel may fail the
	 * swap and release the inputs. Present, they may be out (a broadcast
	 * that threw can have relayed), so the row is exposed and watched.
	 */
	fundingBroadcastAttemptedAt?: number;
	fundingBroadcastAt?: number;
	fundingHeight?: number;
	/** Refund (reverse: ours) bookkeeping. */
	refundTxHex?: string;
	refundTxid?: string;
	refundFeeSat?: string;
	refundBroadcastHeight?: number;
	refundBumps: number;
	/** The winning spend as last observed. */
	resolution?: ISwapResolutionRecord;
	/** Any hash-matching preimage from any source; retained forever. */
	preimageHex?: string;
	preimageSource?: SwapPreimageSource;
	settledAt?: number;
	holdCancelledAt?: number;
	holdCancelReason?: string;
	failureReason?: string;
	lastError?: string;
}

export const SWAP_LEDGER_PREFIX = 'swap';

const REVERSE_STATES: readonly ReverseSwapState[] = [
	'CREATED',
	'HELD',
	'FUNDING',
	'FUNDING_BROADCAST',
	'FUNDED',
	'CLAIMED',
	'SETTLED',
	'REFUND_PENDING',
	'REFUNDED',
	'EXPOSED',
	'CANCELLED',
	'FAILED'
];

const SUBMARINE_STATES: readonly SubmarineSwapState[] = [
	'CREATED',
	'FUNDING_SEEN',
	'FUNDED',
	'FUNDING_LOST',
	'PAYING',
	'PAYMENT_UNRESOLVED',
	'PREIMAGE_KNOWN',
	'CLAIM_BROADCAST',
	'CLAIM_CONFIRMED',
	'PAYMENT_FAILED',
	'CANCELLED',
	'FAILED'
];

const TERMINAL_STATES: ReadonlySet<SwapState> = new Set<SwapState>([
	'SETTLED',
	'REFUNDED',
	'CANCELLED',
	'FAILED',
	'CLAIM_CONFIRMED',
	'PAYMENT_FAILED'
]);

/** Legal arrows per direction: from -> the states it may move to. */
const REVERSE_TRANSITIONS: Readonly<
	Record<ReverseSwapState, readonly ReverseSwapState[]>
> = {
	CREATED: ['HELD', 'CANCELLED', 'FAILED'],
	HELD: ['FUNDING', 'CANCELLED', 'FAILED'],
	FUNDING: ['FUNDING_BROADCAST', 'FAILED'],
	FUNDING_BROADCAST: ['FUNDED', 'CLAIMED', 'EXPOSED'],
	FUNDED: ['CLAIMED', 'REFUND_PENDING', 'EXPOSED'],
	CLAIMED: ['SETTLED', 'EXPOSED'],
	REFUND_PENDING: ['CLAIMED', 'REFUNDED', 'EXPOSED'],
	EXPOSED: [],
	SETTLED: [],
	REFUNDED: [],
	CANCELLED: [],
	FAILED: []
};

const SUBMARINE_TRANSITIONS: Readonly<
	Record<SubmarineSwapState, readonly SubmarineSwapState[]>
> = {
	CREATED: ['FUNDING_SEEN', 'CANCELLED', 'FAILED'],
	FUNDING_SEEN: ['FUNDED', 'FUNDING_LOST', 'CANCELLED'],
	FUNDED: ['PAYING', 'FUNDING_LOST'],
	FUNDING_LOST: ['FUNDING_SEEN', 'CANCELLED'],
	PAYING: ['PREIMAGE_KNOWN', 'PAYMENT_UNRESOLVED', 'PAYMENT_FAILED'],
	PAYMENT_UNRESOLVED: ['PREIMAGE_KNOWN', 'PAYMENT_FAILED'],
	PREIMAGE_KNOWN: ['CLAIM_BROADCAST'],
	CLAIM_BROADCAST: ['CLAIM_CONFIRMED'],
	CLAIM_CONFIRMED: [],
	PAYMENT_FAILED: [],
	CANCELLED: [],
	FAILED: []
};

export function isTerminalSwapState(state: SwapState): boolean {
	return TERMINAL_STATES.has(state);
}

export function swapStatesFor(direction: SwapDirection): readonly SwapState[] {
	return direction === 'reverse' ? REVERSE_STATES : SUBMARINE_STATES;
}

/** The states a swap of this direction may move to `to` from. */
export function swapSourcesFor(
	direction: SwapDirection,
	to: SwapState
): SwapState[] {
	const table: Readonly<Record<string, readonly SwapState[]>> =
		direction === 'reverse' ? REVERSE_TRANSITIONS : SUBMARINE_TRANSITIONS;
	return Object.keys(table).filter((from) =>
		table[from].includes(to)
	) as SwapState[];
}

/**
 * Whether a swap's principal is at risk right now: reverse rows from HELD
 * onward (our coins are or will be locked) until a resolution has met
 * policy, submarine rows from PAYING onward (a Lightning payment is out).
 */
export function isSwapExposure(
	record: ISwapRecord,
	resolutionConfirmations = 1
): boolean {
	if (isTerminalSwapState(record.state)) return false;
	if (record.direction === 'reverse') {
		if (record.state === 'CREATED') return false;
		if (record.state === 'EXPOSED') {
			// Only a resolution verified in THIS process, at the configured
			// depth, takes the principal off the books: a reloaded flag is
			// history, and one confirmation is not policy depth.
			return !(
				record.resolution &&
				record.resolution.verifiedThisSession &&
				record.resolution.confirmations >= Math.max(1, resolutionConfirmations)
			);
		}
		return true;
	}
	return (
		record.state === 'PAYING' ||
		record.state === 'PAYMENT_UNRESOLVED' ||
		record.state === 'PREIMAGE_KNOWN' ||
		record.state === 'CLAIM_BROADCAST'
	);
}

const HEX64 = /^[0-9a-f]{64}$/;

function isDecimal(value: unknown): boolean {
	return typeof value === 'string' && /^[0-9]+$/.test(value);
}

export const swapCodec: ILedgerCodec<ISwapRecord> = {
	encode: (record) => JSON.stringify(record),
	decode: (raw) => {
		try {
			const parsed = JSON.parse(raw) as Partial<ISwapRecord>;
			if (
				typeof parsed.id !== 'string' ||
				!parsed.id ||
				(parsed.direction !== 'reverse' && parsed.direction !== 'submarine') ||
				!swapStatesFor(parsed.direction).includes(parsed.state as SwapState) ||
				typeof parsed.peerNodeIdHex !== 'string' ||
				typeof parsed.paymentHashHex !== 'string' ||
				!HEX64.test(parsed.paymentHashHex) ||
				typeof parsed.claimPubkeyHex !== 'string' ||
				typeof parsed.refundPubkeyHex !== 'string' ||
				!Number.isSafeInteger(parsed.refundHeight) ||
				typeof parsed.outputScriptHex !== 'string' ||
				typeof parsed.address !== 'string' ||
				typeof parsed.network !== 'string' ||
				!isDecimal(parsed.onchainSat) ||
				!isDecimal(parsed.invoiceMsat) ||
				!isDecimal(parsed.totalFeeSat) ||
				!isDecimal(parsed.minerFeeSat) ||
				typeof parsed.createdAt !== 'number' ||
				typeof parsed.createdHeight !== 'number' ||
				typeof parsed.fundingAttempts !== 'number' ||
				typeof parsed.refundBumps !== 'number'
			) {
				return null;
			}
			if (
				parsed.preimageHex !== undefined &&
				(typeof parsed.preimageHex !== 'string' ||
					!HEX64.test(parsed.preimageHex))
			) {
				return null;
			}
			// A resolution read back from storage was verified by an earlier
			// process against a chain that may have moved: it counts again
			// only once this one has observed it.
			if (parsed.resolution) {
				parsed.resolution = {
					...parsed.resolution,
					verifiedThisSession: false
				};
			}
			return parsed as ISwapRecord;
		} catch {
			return null;
		}
	}
};

export type SwapTransition = ILedgerTransitionResult<ISwapRecord>;

/** Fields a caller supplies to open a record; the ledger fills the rest. */
export type ISwapRecordInput = Omit<
	ISwapRecord,
	'state' | 'updatedAt' | 'fundingAttempts' | 'refundBumps'
> &
	Partial<Pick<ISwapRecord, 'fundingAttempts' | 'refundBumps'>>;

/** Live exposure over a set of records. */
export interface ISwapExposureSummary {
	/** Unresolved rows of any state. */
	count: number;
	/** Rows whose principal is at risk (isSwapExposure). */
	exposedCount: number;
	/** Sum of onchainSat over exposed rows. */
	exposedSat: bigint;
}

export class SwapLedger {
	private readonly ledger: DurableLedger<ISwapRecord>;

	constructor(store: IDurableLedgerStore<ISwapRecord>) {
		this.ledger = new DurableLedger(store);
	}

	rehydrate(): number {
		return this.ledger.rehydrate();
	}

	isRehydrated(): boolean {
		return this.ledger.isRehydrated();
	}

	get(swapIdHex: string): ISwapRecord | undefined {
		return this.ledger.get(swapIdHex);
	}

	list(): ISwapRecord[] {
		return this.ledger.list();
	}

	unresolved(): ISwapRecord[] {
		return this.ledger.find((r) => !isTerminalSwapState(r.state));
	}

	byPaymentHash(paymentHashHex: string): ISwapRecord[] {
		return this.ledger.find((r) => r.paymentHashHex === paymentHashHex);
	}

	byFundingOutpoint(txid: string, vout: number): ISwapRecord | undefined {
		return this.ledger.find(
			(r) => r.fundingTxid === txid && r.fundingVout === vout
		)[0];
	}

	static exposure(
		records: readonly ISwapRecord[],
		resolutionConfirmations = 1
	): ISwapExposureSummary {
		let count = 0;
		let exposedCount = 0;
		let exposedSat = 0n;
		for (const r of records) {
			if (isTerminalSwapState(r.state)) continue;
			count++;
			if (isSwapExposure(r, resolutionConfirmations)) {
				exposedCount++;
				exposedSat += BigInt(r.onchainSat);
			}
		}
		return { count, exposedCount, exposedSat };
	}

	/**
	 * Open a record in CREATED. Idempotent on the id: a repeat is `stale`
	 * with the existing row, never an overwrite.
	 */
	insert(input: ISwapRecordInput): SwapTransition {
		const now = Date.now();
		return this.ledger.insert({
			...input,
			state: 'CREATED',
			fundingAttempts: input.fundingAttempts ?? 0,
			refundBumps: input.refundBumps ?? 0,
			updatedAt: now
		});
	}

	/**
	 * Move a record to `to` along a legal arrow for its direction. The CAS
	 * runs against every state that may reach `to`; a record anywhere else
	 * is `stale`, which is how a late worker learns it lost.
	 */
	move(
		swapIdHex: string,
		to: SwapState,
		patch: Partial<ISwapRecord> = {}
	): SwapTransition {
		if (!this.ledger.isRehydrated()) return { outcome: 'not_rehydrated' };
		const current = this.ledger.get(swapIdHex);
		if (!current) return { outcome: 'missing' };
		const from = swapSourcesFor(current.direction, to);
		if (from.length === 0) {
			return { outcome: 'stale', record: current, actualState: current.state };
		}
		return this.ledger.transition(swapIdHex, from, to, {
			...this.withoutPreimageRemoval(current, patch),
			updatedAt: Date.now()
		});
	}

	/**
	 * Update bookkeeping without changing state: invoice details, funding
	 * transaction bytes, refund bumps, resolution observations.
	 */
	patch(swapIdHex: string, patch: Partial<ISwapRecord>): SwapTransition {
		if (!this.ledger.isRehydrated()) return { outcome: 'not_rehydrated' };
		const current = this.ledger.get(swapIdHex);
		if (!current) return { outcome: 'missing' };
		return this.ledger.transition(swapIdHex, [current.state], current.state, {
			...this.withoutPreimageRemoval(current, patch),
			updatedAt: Date.now()
		});
	}

	/**
	 * Record a hash-matching preimage from any source, in any non-terminal
	 * state (and, deliberately, in EXPOSED). Write once: a later source never
	 * replaces an earlier one, though the call still reports `applied`.
	 */
	recordPreimage(
		swapIdHex: string,
		preimageHex: string,
		source: SwapPreimageSource
	): SwapTransition {
		if (!this.ledger.isRehydrated()) return { outcome: 'not_rehydrated' };
		const current = this.ledger.get(swapIdHex);
		if (!current) return { outcome: 'missing' };
		if (isTerminalSwapState(current.state)) {
			return { outcome: 'stale', record: current, actualState: current.state };
		}
		if (current.preimageHex) return { outcome: 'applied', record: current };
		return this.ledger.transition(swapIdHex, [current.state], current.state, {
			preimageHex,
			preimageSource: source,
			updatedAt: Date.now()
		});
	}

	/** Drop a terminal record. Refuses anything still unresolved. */
	forget(swapIdHex: string): boolean {
		const current = this.ledger.get(swapIdHex);
		if (!current || !isTerminalSwapState(current.state)) return false;
		return this.ledger.remove(swapIdHex);
	}

	private withoutPreimageRemoval(
		current: ISwapRecord,
		patch: Partial<ISwapRecord>
	): Partial<ISwapRecord> {
		if (!current.preimageHex) return patch;
		const { preimageHex: _p, preimageSource: _s, ...rest } = patch;
		return rest;
	}
}
