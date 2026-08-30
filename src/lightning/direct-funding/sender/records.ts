/**
 * The payer's durable payment records (issue #613).
 *
 * `docs/RECOVERY-PROTOCOL.md` 5.10 requires new transient state to carry one of
 * four dispositions. This is **D1, persist before emit**: the record reaches
 * storage before the witness reaches the lane, in the same ordering discipline
 * as everything else that lets a commitment out. The fork had none of this, so
 * a crash between the witness send and the HTTP response lost every trace of a
 * payment that may already be on chain (defect D7), which is precisely the
 * scenario the never-reject contract exists to prevent.
 *
 * It lives OUTSIDE the recovery journal, the way `jit:*` does. `RecoveryMutation`
 * has no `metadata` variant, and inventing one would put a payer's private
 * bookkeeping under the guardian quorum's barrier: a record that cannot be
 * written must fail the send, not fence the node. Storage is the encrypted
 * wallet-data store, the same place 4A's request records live.
 */

import {
	DF_POST_WITNESS_STATES,
	DfPaymentStatus,
	IDfPaymentRecord
} from './types';

/** Wallet-data key holding every payment record. */
export const DF_PAYMENTS_STORAGE_KEY = 'df:payments';

/**
 * How long a settled record is kept. Long enough that a payer coming back to
 * ask "did this request go through" after a week still gets the truth, and long
 * enough to outlive the longest request TTL by a wide margin.
 */
export const DF_PAYMENT_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;

/**
 * Records held at once. A settled record is small, but the set is written whole
 * on every change, so it needs a ceiling; the oldest SETTLED records go first
 * and a live one is never evicted.
 */
export const DF_MAX_PAYMENT_RECORDS = 512;

export interface IDfPaymentStoreDeps {
	storage?: {
		saveWalletData(key: string, value: string): void;
		loadWalletData(key: string): string | null;
	};
	now?: () => number;
}

export class DirectFundingPaymentStore {
	private byRequest = new Map<string, IDfPaymentRecord>();

	constructor(private readonly deps: IDfPaymentStoreDeps) {}

	private now(): number {
		return this.deps.now ? this.deps.now() : Date.now();
	}

	// ─────────────── Lifecycle ───────────────

	/** Reload every record. Returns how many came back. */
	restore(): number {
		this.byRequest.clear();
		const raw = this.deps.storage?.loadWalletData(DF_PAYMENTS_STORAGE_KEY);
		if (!raw) return 0;
		let parsed: unknown;
		try {
			parsed = JSON.parse(raw);
		} catch {
			// Corrupt state runs from nothing rather than taking the node down.
			// What is lost is the payer's own bookkeeping, not money: the coin is
			// spent or it is not, and the chain says which.
			return 0;
		}
		if (!Array.isArray(parsed)) return 0;
		for (const entry of parsed as IDfPaymentRecord[]) {
			if (!isWellFormedRecord(entry)) continue;
			this.byRequest.set(entry.requestId, entry);
		}
		return this.byRequest.size;
	}

	get(requestIdHex: string): IDfPaymentRecord | null {
		return this.byRequest.get(requestIdHex) ?? null;
	}

	list(): IDfPaymentRecord[] {
		return [...this.byRequest.values()];
	}

	size(): number {
		return this.byRequest.size;
	}

	/** Records whose funding may be on chain and is not settled yet. */
	pending(): IDfPaymentRecord[] {
		return this.list().filter(
			(r) => r.status === 'SIGNED_PENDING' || r.status === 'MEMPOOL_SEEN'
		);
	}

	// ─────────────── Writes ───────────────

	/**
	 * Open a record for a request that has none, pinning the coin and the offer
	 * to it. Returns false when the write failed: the caller must refuse rather
	 * than offer a coin nothing would remember offering.
	 */
	open(record: IDfPaymentRecord): boolean {
		this.evict();
		this.byRequest.set(record.requestId, record);
		if (this.persist()) return true;
		this.byRequest.delete(record.requestId);
		return false;
	}

	/**
	 * Move a record forward. Returns false when the write failed.
	 *
	 * The in-memory record is updated either way: a caller that retries writes
	 * the whole set again rather than losing the transition, and the states this
	 * carries are ones the process must not forget while it is still running.
	 */
	update(
		requestIdHex: string,
		patch: Partial<Omit<IDfPaymentRecord, 'requestId'>>
	): boolean {
		const record = this.byRequest.get(requestIdHex);
		if (!record) return false;
		Object.assign(record, patch, { updatedAt: this.now() });
		return this.persist();
	}

	/**
	 * The persist-before-emit step: everything rev 2 requires a payer to hold
	 * about a witness it is ABOUT to release, written before it is released.
	 *
	 * A false return is a refusal, and it is the last moment one is allowed: the
	 * caller has not emitted the witness yet, so refusing here still leaves
	 * nothing spent. After this returns true the send can only resolve.
	 */
	commitWitness(
		requestIdHex: string,
		commit: {
			attestation: IDfPaymentRecord['attestation'];
			negotiatedTx: string;
			witness: string[];
			fundingTxid: string;
			frozen: boolean;
		}
	): boolean {
		return this.update(requestIdHex, { ...commit, status: 'SIGNED_PENDING' });
	}

	/**
	 * Undo a commit whose witness never reached the wire.
	 *
	 * A lane throws from `send` only when it could not carry the frame at all,
	 * so nothing can have answered it and the record must stop describing a
	 * spend: the commitment is dropped, the coin comes free, and the request
	 * goes back to the offer it was. Leaving SIGNED_PENDING behind would pin the
	 * coin to a payment that never happened.
	 */
	rollbackWitness(requestIdHex: string): boolean {
		const record = this.byRequest.get(requestIdHex);
		if (!record) return false;
		delete record.attestation;
		delete record.negotiatedTx;
		delete record.witness;
		delete record.fundingTxid;
		delete record.witnessSent;
		return this.update(requestIdHex, { status: 'OFFERED', frozen: false });
	}

	/** Drop a record outright. Only ever a record no witness was built for. */
	forget(requestIdHex: string): void {
		const record = this.byRequest.get(requestIdHex);
		if (!record) return;
		if (DF_POST_WITNESS_STATES.has(record.status)) return;
		this.byRequest.delete(requestIdHex);
		this.persist();
	}

	// ─────────────── Internals ───────────────

	/**
	 * Make room by dropping the oldest SETTLED records, and only those. A record
	 * whose witness is out and whose funding has not settled is never evicted:
	 * it is the only thing that says a coin may be spent.
	 */
	private evict(): void {
		const now = this.now();
		const settled = (r: IDfPaymentRecord): boolean =>
			r.status === 'CONFIRMED' ||
			r.status === 'FAILED' ||
			r.status === 'ABORTED';
		for (const record of [...this.byRequest.values()]) {
			if (settled(record) && now - record.updatedAt > DF_PAYMENT_RETENTION_MS) {
				this.byRequest.delete(record.requestId);
			}
		}
		if (this.byRequest.size < DF_MAX_PAYMENT_RECORDS) return;
		const evictable = [...this.byRequest.values()]
			.filter(settled)
			.sort((a, b) => a.updatedAt - b.updatedAt);
		for (const record of evictable) {
			if (this.byRequest.size < DF_MAX_PAYMENT_RECORDS) break;
			this.byRequest.delete(record.requestId);
		}
	}

	/** Write the whole set. Reports whether it landed. */
	private persist(): boolean {
		if (!this.deps.storage) return true;
		try {
			this.deps.storage.saveWalletData(
				DF_PAYMENTS_STORAGE_KEY,
				JSON.stringify([...this.byRequest.values()])
			);
			return true;
		} catch {
			return false;
		}
	}
}

const STATUSES: ReadonlySet<string> = new Set<DfPaymentStatus>([
	'CREATED',
	'OFFERED',
	'SIGNED_PENDING',
	'MEMPOOL_SEEN',
	'CONFIRMED',
	'ABORTED',
	'FAILED'
]);

function isHex(value: unknown, bytes?: number): boolean {
	return (
		typeof value === 'string' &&
		value.length % 2 === 0 &&
		(bytes === undefined || value.length === bytes * 2) &&
		/^[0-9a-f]*$/i.test(value)
	);
}

function isDecimal(value: unknown): boolean {
	return typeof value === 'string' && /^(0|[1-9][0-9]{0,18})$/.test(value);
}

/**
 * A restored row is only usable if the fields an idempotent retry reads came
 * back intact. A record with a truncated outpoint would answer "this request
 * already has an attempt" while naming a coin that cannot be re-offered, which
 * is worse than having no record: it would wedge the request permanently.
 */
export function isWellFormedRecord(entry: unknown): entry is IDfPaymentRecord {
	const r = entry as IDfPaymentRecord | null;
	return (
		!!r &&
		isHex(r.requestId, 16) &&
		isHex(r.receiptHash, 32) &&
		isHex(r.receiverNodeId, 33) &&
		isHex(r.offerId, 16) &&
		isHex(r.offerBody) &&
		r.offerBody.length > 0 &&
		isHex(r.spentTxid, 32) &&
		Number.isInteger(r.spentVout) &&
		r.spentVout >= 0 &&
		isDecimal(r.spentValueSat) &&
		isDecimal(r.amountSat) &&
		isDecimal(r.maxTotalFeeSat) &&
		isHex(r.changeScript) &&
		r.changeScript.length > 0 &&
		STATUSES.has(r.status) &&
		Number.isFinite(r.createdAt) &&
		Number.isFinite(r.updatedAt)
	);
}
