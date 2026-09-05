/**
 * The receipt witness's durable state (spec section 9.6, Appendix F.5): a
 * second instance of the durable-ledger infrastructure of issue #716, with
 * its own two record kinds and state machines, never a held-forward variant.
 *
 *   mailbox:  PROVISIONED -> CLOSED -> EXPIRED
 *   record:   RECORDED -> RECEIPTED
 *
 * A mailbox is one witness's store for one epoch, named by a random id that
 * links to nothing. A record is the witness's signed, receiver-encrypted
 * statement that it saw t_k. Both survive a restart with R offline
 * (rehydrate-before-serve), and neither is ever deleted before
 * `retention_until`.
 */

import {
	DurableLedger,
	IDurableLedgerStore,
	ILedgerCodec,
	ILedgerRecord,
	ILedgerTransitionResult
} from '../storage/durable-ledger';

export const FF_WITNESS_MAILBOX_LEDGER_PREFIX = 'ffor_witness_mailbox';
export const FF_WITNESS_RECORD_LEDGER_PREFIX = 'ffor_witness_record';

export type FforWitnessMailboxState = 'PROVISIONED' | 'CLOSED' | 'EXPIRED';
export type FforWitnessRecordState = 'RECORDED' | 'RECEIPTED';

/** One book entry as the witness needs it, hex and decimal for the codec. */
export interface IFforWitnessEntry {
	k: number;
	hashHex: string;
	amountMsat: string;
	tExp: number;
	d: number;
	sHtlcId: string;
	termsHashHex: string;
}

export interface IFforWitnessMailboxRecord extends ILedgerRecord {
	/** mailbox_id as hex. */
	id: string;
	state: FforWitnessMailboxState;
	/** The manifest bytes as received, signature included (audit). */
	manifestHex: string;
	hActHex: string;
	hBookHex: string;
	tSetupHex: string;
	hCommitHex: string;
	epochStartHeight: number;
	fetchPubkeyHex: string;
	encPubkeyHex: string;
	retentionUntil: number;
	minReceipts: number;
	entries: IFforWitnessEntry[];
	/** Fetch and close nonces already accepted (F.1 replay rule), capped. */
	acceptedNonces: string[];
	settledBitmapHex?: string;
	provisionedAt: number;
	closedAt?: number;
	/** Bytes reserved at provisioning, released at EXPIRED (section 9.6.7). */
	reservedBytes: number;
}

export interface IFforWitnessRecordRow extends ILedgerRecord {
	/** record_id as hex. */
	id: string;
	state: FforWitnessRecordState;
	mailboxIdHex: string;
	k: number;
	/** The full Appendix F.2 encoding, receipts included. */
	recordHex: string;
	unbarriered: boolean;
	/** The outgoing HTLC key the fulfil answered ("channelIdHex:offered-id"). */
	outKey: string;
	recordedHeight: number;
	/** The journal frame that carried the write, when journaled. */
	frameSequence?: string;
	receiptsPending: boolean;
	propagatedAt?: number;
}

const MAILBOX_STATES: FforWitnessMailboxState[] = [
	'PROVISIONED',
	'CLOSED',
	'EXPIRED'
];
const RECORD_STATES: FforWitnessRecordState[] = ['RECORDED', 'RECEIPTED'];
const MAX_ACCEPTED_NONCES = 1024;
/** Section 9.6.7: a record without receipts is well under 1 KB. */
export const FF_WITNESS_RECORD_RESERVE_BYTES = 1024;

export const fforWitnessMailboxCodec: ILedgerCodec<IFforWitnessMailboxRecord> =
	{
		encode: (record) => JSON.stringify(record),
		decode: (raw) => {
			try {
				const p = JSON.parse(raw) as Partial<IFforWitnessMailboxRecord>;
				if (
					typeof p.id !== 'string' ||
					!MAILBOX_STATES.includes(p.state as FforWitnessMailboxState) ||
					typeof p.manifestHex !== 'string' ||
					typeof p.hActHex !== 'string' ||
					typeof p.fetchPubkeyHex !== 'string' ||
					typeof p.encPubkeyHex !== 'string' ||
					typeof p.retentionUntil !== 'number' ||
					!Array.isArray(p.entries)
				) {
					return null;
				}
				return {
					...(p as IFforWitnessMailboxRecord),
					acceptedNonces: Array.isArray(p.acceptedNonces)
						? p.acceptedNonces
						: []
				};
			} catch {
				return null;
			}
		}
	};

export const fforWitnessRecordCodec: ILedgerCodec<IFforWitnessRecordRow> = {
	encode: (record) => JSON.stringify(record),
	decode: (raw) => {
		try {
			const p = JSON.parse(raw) as Partial<IFforWitnessRecordRow>;
			if (
				typeof p.id !== 'string' ||
				!RECORD_STATES.includes(p.state as FforWitnessRecordState) ||
				typeof p.mailboxIdHex !== 'string' ||
				typeof p.k !== 'number' ||
				typeof p.recordHex !== 'string'
			) {
				return null;
			}
			return p as IFforWitnessRecordRow;
		} catch {
			return null;
		}
	}
};

export type FforWitnessMailboxTransition =
	ILedgerTransitionResult<IFforWitnessMailboxRecord>;
export type FforWitnessRecordTransition =
	ILedgerTransitionResult<IFforWitnessRecordRow>;

/** What the ledger holds, for the capacity gate. */
export interface IFforWitnessOccupancy {
	mailboxes: number;
	records: number;
	reservedBytes: number;
}

export class FforWitnessLedger {
	private readonly mailboxes: DurableLedger<IFforWitnessMailboxRecord>;
	private readonly records: DurableLedger<IFforWitnessRecordRow>;
	/** hash hex -> the live mailbox and slot naming it. */
	private byHashIndex = new Map<string, { mailboxIdHex: string; k: number }>();

	constructor(
		mailboxStore: IDurableLedgerStore<IFforWitnessMailboxRecord>,
		recordStore: IDurableLedgerStore<IFforWitnessRecordRow>
	) {
		this.mailboxes = new DurableLedger(mailboxStore);
		this.records = new DurableLedger(recordStore);
	}

	/** Rehydrate both ledgers and rebuild the hash index; serve nothing before. */
	rehydrate(): number {
		const n = this.mailboxes.rehydrate() + this.records.rehydrate();
		this.byHashIndex.clear();
		for (const m of this.mailboxes.list()) this.indexMailbox(m);
		return n;
	}

	isRehydrated(): boolean {
		return this.mailboxes.isRehydrated() && this.records.isRehydrated();
	}

	private indexMailbox(m: IFforWitnessMailboxRecord): void {
		if (m.state === 'EXPIRED') return;
		for (const e of m.entries) {
			this.byHashIndex.set(e.hashHex, { mailboxIdHex: m.id, k: e.k });
		}
	}

	private unindexMailbox(m: IFforWitnessMailboxRecord): void {
		for (const e of m.entries) {
			const at = this.byHashIndex.get(e.hashHex);
			if (at && at.mailboxIdHex === m.id) this.byHashIndex.delete(e.hashHex);
		}
	}

	mailbox(mailboxIdHex: string): IFforWitnessMailboxRecord | undefined {
		return this.mailboxes.get(mailboxIdHex);
	}

	listMailboxes(): IFforWitnessMailboxRecord[] {
		return this.mailboxes.list();
	}

	/** The live mailbox and slot a payment hash names, if any. */
	byHash(
		hashHex: string
	): { mailbox: IFforWitnessMailboxRecord; k: number } | null {
		const at = this.byHashIndex.get(hashHex);
		if (!at) return null;
		const mailbox = this.mailboxes.get(at.mailboxIdHex);
		if (!mailbox || mailbox.state === 'EXPIRED') return null;
		return { mailbox, k: at.k };
	}

	occupancy(): IFforWitnessOccupancy {
		let mailboxes = 0;
		let reservedBytes = 0;
		for (const m of this.mailboxes.list()) {
			if (m.state === 'EXPIRED') continue;
			mailboxes++;
			reservedBytes += m.reservedBytes;
		}
		return { mailboxes, records: this.records.list().length, reservedBytes };
	}

	/** Insert a mailbox; `stale` when the id already exists. */
	provision(
		fields: Omit<
			IFforWitnessMailboxRecord,
			'state' | 'acceptedNonces' | 'provisionedAt'
		>
	): FforWitnessMailboxTransition {
		const record: IFforWitnessMailboxRecord = {
			...fields,
			state: 'PROVISIONED',
			acceptedNonces: [],
			provisionedAt: Date.now()
		};
		const result = this.mailboxes.insert(record);
		if (result.outcome === 'applied' && result.record) {
			this.indexMailbox(result.record);
		}
		return result;
	}

	/**
	 * Accept a fetch or close nonce exactly once per mailbox (F.1). The
	 * durable write lands before the caller acts, so a nonce replayed after
	 * a restart is still refused.
	 */
	acceptNonce(
		mailboxIdHex: string,
		nonceHex: string
	): 'accepted' | 'replayed' | 'missing' | 'failed' {
		const m = this.mailboxes.get(mailboxIdHex);
		if (!m) return 'missing';
		if (m.acceptedNonces.includes(nonceHex)) return 'replayed';
		const kept = [...m.acceptedNonces, nonceHex].slice(-MAX_ACCEPTED_NONCES);
		const result = this.mailboxes.transition(mailboxIdHex, [m.state], m.state, {
			acceptedNonces: kept
		});
		return result.outcome === 'applied' ? 'accepted' : 'failed';
	}

	/** Section 9.6.6: stop creating records; keep the existing ones. */
	close(
		mailboxIdHex: string,
		settledBitmapHex: string
	): FforWitnessMailboxTransition {
		return this.mailboxes.transition(
			mailboxIdHex,
			['PROVISIONED', 'CLOSED'],
			'CLOSED',
			{
				settledBitmapHex,
				closedAt: Date.now()
			}
		);
	}

	/** Past retention_until: the reservation is released and the records go. */
	expire(mailboxIdHex: string): FforWitnessMailboxTransition {
		const m = this.mailboxes.get(mailboxIdHex);
		const result = this.mailboxes.transition(
			mailboxIdHex,
			['PROVISIONED', 'CLOSED'],
			'EXPIRED',
			{ reservedBytes: 0 }
		);
		if (result.outcome === 'applied' && m) {
			this.unindexMailbox(m);
			for (const r of this.records.find(
				(x) => x.mailboxIdHex === mailboxIdHex
			)) {
				this.records.remove(r.id);
			}
		}
		return result;
	}

	record(mailboxIdHex: string, k: number): IFforWitnessRecordRow | undefined {
		return this.records.find(
			(r) => r.mailboxIdHex === mailboxIdHex && r.k === k
		)[0];
	}

	listRecords(mailboxIdHex: string): IFforWitnessRecordRow[] {
		return this.records
			.find((r) => r.mailboxIdHex === mailboxIdHex)
			.sort((a, b) => a.k - b.k);
	}

	/** Step 3 of section 9.6.5: one record per slot, append-only. */
	insertRecord(
		fields: Omit<IFforWitnessRecordRow, 'state'>
	): FforWitnessRecordTransition {
		if (this.record(fields.mailboxIdHex, fields.k)) {
			return {
				outcome: 'stale',
				record: this.record(fields.mailboxIdHex, fields.k)
			};
		}
		return this.records.insert({ ...fields, state: 'RECORDED' });
	}

	markReceipted(
		recordIdHex: string,
		recordHex: string
	): FforWitnessRecordTransition {
		return this.records.transition(recordIdHex, ['RECORDED'], 'RECEIPTED', {
			recordHex,
			receiptsPending: false
		});
	}

	markPropagated(recordIdHex: string): FforWitnessRecordTransition {
		const r = this.records.get(recordIdHex);
		if (!r) return { outcome: 'missing' };
		return this.records.transition(recordIdHex, [r.state], r.state, {
			propagatedAt: Date.now()
		});
	}
}
