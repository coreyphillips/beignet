/**
 * The issuer's durable state (spec section 9.7.3, 9.7.7, Appendix F.5): the
 * manifests it holds and one row per slot whose issuance is a
 * compare-and-swap, so a slot is issued once and a crash between the mark
 * and the send re-answers identical metadata with the same invoice.
 */

import {
	DurableLedger,
	IDurableLedgerStore,
	ILedgerCodec,
	ILedgerRecord,
	ILedgerTransitionResult
} from '../storage/durable-ledger';

export const FF_ISSUER_MANIFEST_LEDGER_PREFIX = 'ffor_issuer_manifest';
export const FF_ISSUER_SLOT_LEDGER_PREFIX = 'ffor_issuer_slot';

export type FforIssuerManifestState = 'ISSUING' | 'RETIRED';
export type FforIssuerSlotState = 'UNISSUED' | 'ISSUED';

export interface IFforIssuerHopRow {
	nodeIdHex: string;
	scidHex: string;
	feeBaseMsat: number;
	feeProportionalMillionths: number;
	cltvExpiryDelta: number;
	htlcMinimumMsat: string;
	htlcMaximumMsat: string;
}

export interface IFforIssuerManifestRecord extends ILedgerRecord {
	/** mailbox_id hex. */
	id: string;
	state: FforIssuerManifestState;
	manifestHex: string;
	offerHex: string;
	offerIdHex: string;
	hops: IFforIssuerHopRow[];
	issueUntil: number;
	rAttestationHex: string;
	rNodeIdHex: string;
	hActHex: string;
	hBookHex: string;
	confirmedBlindedIds: string[];
	numSlots: number;
	retiredReason?: string;
}

export interface IFforIssuerSlotRecord extends ILedgerRecord {
	/** `<mailbox hex>:<k>`. */
	id: string;
	state: FforIssuerSlotState;
	mailboxIdHex: string;
	k: number;
	amountMsat: string;
	hashHex: string;
	payerIdHex?: string;
	metadataHashHex?: string;
	issuedUnixTime?: number;
	/** The signed invoice bytes, stored before they are sent. */
	invoiceHex?: string;
}

const MANIFEST_STATES: FforIssuerManifestState[] = ['ISSUING', 'RETIRED'];
const SLOT_STATES: FforIssuerSlotState[] = ['UNISSUED', 'ISSUED'];

export const fforIssuerManifestCodec: ILedgerCodec<IFforIssuerManifestRecord> =
	{
		encode: (r) => JSON.stringify(r),
		decode: (raw) => {
			try {
				const p = JSON.parse(raw) as Partial<IFforIssuerManifestRecord>;
				if (
					typeof p.id !== 'string' ||
					!MANIFEST_STATES.includes(p.state as FforIssuerManifestState) ||
					typeof p.offerHex !== 'string' ||
					typeof p.offerIdHex !== 'string' ||
					!Array.isArray(p.hops) ||
					typeof p.issueUntil !== 'number'
				) {
					return null;
				}
				return p as IFforIssuerManifestRecord;
			} catch {
				return null;
			}
		}
	};

export const fforIssuerSlotCodec: ILedgerCodec<IFforIssuerSlotRecord> = {
	encode: (r) => JSON.stringify(r),
	decode: (raw) => {
		try {
			const p = JSON.parse(raw) as Partial<IFforIssuerSlotRecord>;
			if (
				typeof p.id !== 'string' ||
				!SLOT_STATES.includes(p.state as FforIssuerSlotState) ||
				typeof p.mailboxIdHex !== 'string' ||
				typeof p.k !== 'number' ||
				typeof p.amountMsat !== 'string' ||
				typeof p.hashHex !== 'string'
			) {
				return null;
			}
			return p as IFforIssuerSlotRecord;
		} catch {
			return null;
		}
	}
};

export type FforIssuerSlotTransition =
	ILedgerTransitionResult<IFforIssuerSlotRecord>;

export function slotId(mailboxIdHex: string, k: number): string {
	return `${mailboxIdHex}:${k}`;
}

export class FforIssuerLedger {
	private readonly manifests: DurableLedger<IFforIssuerManifestRecord>;
	private readonly slots: DurableLedger<IFforIssuerSlotRecord>;

	constructor(
		manifestStore: IDurableLedgerStore<IFforIssuerManifestRecord>,
		slotStore: IDurableLedgerStore<IFforIssuerSlotRecord>
	) {
		this.manifests = new DurableLedger(manifestStore);
		this.slots = new DurableLedger(slotStore);
	}

	rehydrate(): number {
		return this.manifests.rehydrate() + this.slots.rehydrate();
	}

	manifest(mailboxIdHex: string): IFforIssuerManifestRecord | undefined {
		return this.manifests.get(mailboxIdHex);
	}

	listManifests(): IFforIssuerManifestRecord[] {
		return this.manifests.list();
	}

	byOffer(offerIdHex: string): IFforIssuerManifestRecord | undefined {
		return this.manifests.find((m) => m.offerIdHex === offerIdHex)[0];
	}

	/** Insert the manifest and its K UNISSUED slots. */
	provision(
		manifest: Omit<IFforIssuerManifestRecord, 'state'>,
		slots: { k: number; amountMsat: bigint; hashHex: string }[]
	): 'applied' | 'stale' | 'failed' {
		const m = this.manifests.insert({ ...manifest, state: 'ISSUING' });
		if (m.outcome === 'stale') return 'stale';
		if (m.outcome !== 'applied') return 'failed';
		for (const s of slots) {
			const r = this.slots.insert({
				id: slotId(manifest.id, s.k),
				state: 'UNISSUED',
				mailboxIdHex: manifest.id,
				k: s.k,
				amountMsat: s.amountMsat.toString(),
				hashHex: s.hashHex
			});
			if (r.outcome !== 'applied' && r.outcome !== 'stale') {
				this.manifests.remove(manifest.id);
				return 'failed';
			}
		}
		return 'applied';
	}

	slotsOf(mailboxIdHex: string): IFforIssuerSlotRecord[] {
		return this.slots
			.find((s) => s.mailboxIdHex === mailboxIdHex)
			.sort((a, b) => a.k - b.k);
	}

	/** The slot already issued to this payer for this request metadata, if any. */
	issuedFor(
		mailboxIdHex: string,
		payerIdHex: string,
		metadataHashHex: string
	): IFforIssuerSlotRecord | undefined {
		return this.slots.find(
			(s) =>
				s.mailboxIdHex === mailboxIdHex &&
				s.state === 'ISSUED' &&
				s.payerIdHex === payerIdHex &&
				s.metadataHashHex === metadataHashHex
		)[0];
	}

	/** The lowest unissued slot of exactly this amount (section 9.7.3 step 2). */
	firstUnissued(
		mailboxIdHex: string,
		amountMsat: bigint
	): IFforIssuerSlotRecord | undefined {
		return this.slotsOf(mailboxIdHex).find(
			(s) => s.state === 'UNISSUED' && BigInt(s.amountMsat) === amountMsat
		);
	}

	/** Step 3: mark issued, durably, by compare-and-swap. */
	issue(
		id: string,
		payerIdHex: string,
		metadataHashHex: string
	): FforIssuerSlotTransition {
		return this.slots.transition(id, ['UNISSUED'], 'ISSUED', {
			payerIdHex,
			metadataHashHex,
			issuedUnixTime: Date.now()
		});
	}

	/** The invoice bytes for a slot, stored before they are sent. */
	storeInvoice(id: string, invoiceHex: string): FforIssuerSlotTransition {
		return this.slots.transition(id, ['ISSUED'], 'ISSUED', { invoiceHex });
	}

	retire(
		mailboxIdHex: string,
		reason: string
	): ILedgerTransitionResult<IFforIssuerManifestRecord> {
		return this.manifests.transition(mailboxIdHex, ['ISSUING'], 'RETIRED', {
			retiredReason: reason
		});
	}
}
