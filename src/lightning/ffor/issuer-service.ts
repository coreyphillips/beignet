/**
 * The BOLT 12 issuer I (spec section 9.7): answers invoice_requests for
 * an offer R delegated to it by a path-terminal offer, one fixed-amount
 * slot per invoice, issued once by compare-and-swap before any invoice
 * leaves, signed under the blinded key the request's path names. Co-hosted
 * with the first receipt witness, whose mailbox holds the book.
 *
 * Every refusal is the one fixed string of section 9.7.3, so a payer learns
 * nothing about the book: not how many slots remain, not which amounts
 * exist, not whether issuance has ended.
 */

import crypto from 'crypto';
import { getPublicKey } from '../crypto/ecdh';
import { deriveBlindedPrivkey } from '../onion/blinded-path';
import { decodeOfferTlv, getTlvRecords } from '../offer/tlv';
import { computeOfferId } from '../offer/merkle';
import { IOffer } from '../offer/types';
import {
	IIssuanceContext,
	IssuanceAnswer,
	IssuancePolicy
} from '../offer/offer-manager';
import { FforWitnessLedger } from './witness-ledger';
import {
	FF_ISSUER_ACK_TYPE,
	FF_ISSUER_PROVISION_TYPE,
	FF_ISSUER_STATUS_RESP_TYPE,
	FF_ISSUER_STATUS_TYPE,
	FF_WITNESS_REQUEST_ID_LEN
} from './witness-types';
import {
	FF_ISSUER_ATTESTATION_TLV,
	FF_ISSUER_MANIFEST_VERSION,
	FF_ISSUER_REFUSAL,
	IFforIssuerHop,
	decodeIssuerProvision,
	decodeIssuerStatus,
	encodeAttestationTlvValue,
	encodeIssuerAck,
	encodeIssuerStatusResp,
	verifyAttestation,
	verifyIssuerStatus
} from './issuer-messages';
import {
	FforIssuerLedger,
	IFforIssuerHopRow,
	IFforIssuerManifestRecord,
	slotId
} from './issuer-ledger';
import {
	buildIssuerPaymentPath,
	conservativeExpirySeconds
} from './issuer-paths';
import { bitmapSet } from './messages';

export interface IFforIssuerConfig {
	enabled: boolean;
}

export interface IFforIssuerDeps {
	ledger: FforIssuerLedger;
	witnessLedger: FforWitnessLedger;
	nodePrivkey: Buffer;
	nodeId: Buffer;
	currentHeight: () => number;
	send: (peer: string, type: number, payload: Buffer) => void;
	log: (action: string, data: Record<string, unknown>) => void;
	emit: (event: string, data: unknown) => void;
	offers: {
		registerDelegatedOffer(offer: IOffer, policy: IssuancePolicy): string;
		unregisterDelegatedOffer(offerIdHex: string): void;
	};
}

function hopFromRow(r: IFforIssuerHopRow): IFforIssuerHop {
	return {
		nodeId: Buffer.from(r.nodeIdHex, 'hex'),
		shortChannelId: Buffer.from(r.scidHex, 'hex'),
		feeBaseMsat: r.feeBaseMsat,
		feeProportionalMillionths: r.feeProportionalMillionths,
		cltvExpiryDelta: r.cltvExpiryDelta,
		htlcMinimumMsat: BigInt(r.htlcMinimumMsat),
		htlcMaximumMsat: BigInt(r.htlcMaximumMsat)
	};
}

export class FforIssuerService {
	constructor(
		_cfg: IFforIssuerConfig,
		private readonly deps: IFforIssuerDeps
	) {}

	get ledger(): FforIssuerLedger {
		return this.deps.ledger;
	}

	/** Re-register every live manifest's offer after a restart (F.5). */
	rehydrate(): number {
		let n = 0;
		for (const m of this.deps.ledger.listManifests()) {
			// Retired manifests stay registered too: their refusals must not
			// differ from a live manifest's.
			this.registerOffer(m);
			n++;
		}
		return n;
	}

	private registerOffer(m: IFforIssuerManifestRecord): void {
		const { offer } = decodeOfferTlv(Buffer.from(m.offerHex, 'hex'));
		this.deps.offers.registerDelegatedOffer(
			{ ...offer, offerId: Buffer.from(m.offerIdHex, 'hex') },
			this.policyFor(m.id)
		);
	}

	handleMessage(peer: string, type: number, payload: Buffer): boolean {
		switch (type) {
			case FF_ISSUER_PROVISION_TYPE:
				this.handleProvision(peer, payload);
				return true;
			case FF_ISSUER_STATUS_TYPE:
				this.handleStatus(peer, payload);
				return true;
			default:
				return false;
		}
	}

	// ── Provisioning (section 9.7.2) ──────────────────────────────────

	private handleProvision(peer: string, payload: Buffer): void {
		if (payload.length < FF_WITNESS_REQUEST_ID_LEN) return;
		const requestId = Buffer.from(
			payload.subarray(0, FF_WITNESS_REQUEST_ID_LEN)
		);
		const refuse = (error: string): void => {
			this.deps.log('ffor_issuer_provision_refused', { peer, error });
			this.deps.send(
				peer,
				FF_ISSUER_ACK_TYPE,
				encodeIssuerAck({ requestId, ok: false, blindedNodeIds: [], error })
			);
		};
		let decoded: ReturnType<typeof decodeIssuerProvision>;
		try {
			decoded = decodeIssuerProvision(payload);
		} catch (err) {
			refuse(`undecodable manifest: ${(err as Error).message}`);
			return;
		}
		const { manifest, manifestWire } = decoded;
		if (manifest.version !== FF_ISSUER_MANIFEST_VERSION) {
			refuse(`manifest version ${manifest.version} not supported`);
			return;
		}
		const mailboxIdHex = manifest.mailboxId.toString('hex');
		const mailbox = this.deps.witnessLedger.mailbox(mailboxIdHex);
		if (!mailbox || mailbox.state === 'EXPIRED') {
			refuse('no such mailbox on this witness');
			return;
		}
		if (manifest.hops.length < 2) {
			refuse('template needs S and R at least');
			return;
		}
		const rNodeId = manifest.hops[manifest.hops.length - 1].nodeId;
		let offer: Omit<IOffer, 'offerId'>;
		let offerId: Buffer;
		try {
			offer = decodeOfferTlv(manifest.offer).offer;
			offerId = computeOfferId(getTlvRecords(manifest.offer));
		} catch (err) {
			refuse(`undecodable offer: ${(err as Error).message}`);
			return;
		}
		const hAct = Buffer.from(mailbox.hActHex, 'hex');
		const hBook = Buffer.from(mailbox.hBookHex, 'hex');
		if (
			!verifyAttestation(offerId, hAct, hBook, rNodeId, manifest.rAttestation)
		) {
			refuse('attestation does not verify under the template terminal');
			return;
		}
		if (offer.issuerId) {
			refuse('offer names an issuer id: not path-terminal');
			return;
		}
		// The offer paths this node terminates: as introduction node it holds
		// the path key and can derive the blinded key each path names it by.
		const confirmed: Buffer[] = [];
		for (const p of offer.paths ?? []) {
			if (!p.introductionNodeId.equals(this.deps.nodeId)) continue;
			if (p.blindedHops.length !== 1) continue;
			const mine = getPublicKey(
				deriveBlindedPrivkey(p.blindingPoint, this.deps.nodePrivkey)
			);
			if (mine.equals(p.blindedHops[0].blindedNodeId)) confirmed.push(mine);
		}
		if (confirmed.length === 0) {
			refuse('no offer path terminates at this node');
			return;
		}
		const d = mailbox.entries[0]?.d ?? 0;
		const height = this.deps.currentHeight();
		if (manifest.issueUntil > d) {
			refuse('issue_until is past the settlement deadline');
			return;
		}
		if (manifest.issueUntil <= height) {
			refuse('issue_until is not in the future');
			return;
		}
		if (offer.absoluteExpiry !== undefined) {
			const latest =
				BigInt(Math.floor(Date.now() / 1000)) +
				BigInt(conservativeExpirySeconds(manifest.issueUntil - height));
			if (offer.absoluteExpiry > latest) {
				refuse('offer expiry is later than the conservative issue_until');
				return;
			}
		}
		const existing = this.deps.ledger.manifest(mailboxIdHex);
		if (existing) {
			if (existing.manifestHex === manifestWire.toString('hex')) {
				this.ack(
					peer,
					requestId,
					existing.confirmedBlindedIds.map((h) => Buffer.from(h, 'hex'))
				);
				return;
			}
			refuse('mailbox already has an issuer manifest');
			return;
		}
		const record: Omit<IFforIssuerManifestRecord, 'state'> = {
			id: mailboxIdHex,
			manifestHex: manifestWire.toString('hex'),
			offerHex: manifest.offer.toString('hex'),
			offerIdHex: offerId.toString('hex'),
			hops: manifest.hops.map((h) => ({
				nodeIdHex: h.nodeId.toString('hex'),
				scidHex: h.shortChannelId.toString('hex'),
				feeBaseMsat: h.feeBaseMsat,
				feeProportionalMillionths: h.feeProportionalMillionths,
				cltvExpiryDelta: h.cltvExpiryDelta,
				htlcMinimumMsat: h.htlcMinimumMsat.toString(),
				htlcMaximumMsat: h.htlcMaximumMsat.toString()
			})),
			issueUntil: manifest.issueUntil,
			rAttestationHex: manifest.rAttestation.toString('hex'),
			rNodeIdHex: rNodeId.toString('hex'),
			hActHex: mailbox.hActHex,
			hBookHex: mailbox.hBookHex,
			confirmedBlindedIds: confirmed.map((c) => c.toString('hex')),
			numSlots: mailbox.entries.length
		};
		const outcome = this.deps.ledger.provision(
			record,
			mailbox.entries.map((e) => ({
				k: e.k,
				amountMsat: BigInt(e.amountMsat),
				hashHex: e.hashHex
			}))
		);
		if (outcome !== 'applied') {
			refuse(`cannot store the manifest: ${outcome}`);
			return;
		}
		this.registerOffer({ ...record, state: 'ISSUING' });
		this.deps.log('ffor_issuer_provisioned', {
			mailboxId: mailboxIdHex,
			offerId: record.offerIdHex,
			slots: record.numSlots,
			issueUntil: manifest.issueUntil
		});
		this.deps.emit('ffor:issuer-provisioned', {
			mailboxId: manifest.mailboxId,
			offerId,
			slots: record.numSlots
		});
		this.ack(peer, requestId, confirmed);
	}

	private ack(peer: string, requestId: Buffer, blindedNodeIds: Buffer[]): void {
		this.deps.send(
			peer,
			FF_ISSUER_ACK_TYPE,
			encodeIssuerAck({ requestId, ok: true, blindedNodeIds })
		);
	}

	// ── Answering an invoice_request (section 9.7.3) ─────────────────

	private policyFor(mailboxIdHex: string): IssuancePolicy {
		return (ctx: IIssuanceContext): IssuanceAnswer =>
			this.answer(mailboxIdHex, ctx);
	}

	private answer(mailboxIdHex: string, ctx: IIssuanceContext): IssuanceAnswer {
		const refusal: IssuanceAnswer = { error: FF_ISSUER_REFUSAL };
		const m = this.deps.ledger.manifest(mailboxIdHex);
		const mailbox = this.deps.witnessLedger.mailbox(mailboxIdHex);
		if (
			!m ||
			m.state !== 'ISSUING' ||
			!mailbox ||
			mailbox.state !== 'PROVISIONED'
		) {
			return refusal;
		}
		const height = this.deps.currentHeight();
		if (height >= m.issueUntil) {
			this.retire(mailboxIdHex, 'issue_until');
			return refusal;
		}
		// Section 9.7.3 step 1: the requested amount, exactly.
		const quantity = ctx.request.quantity ?? 1n;
		const requested =
			ctx.request.amount ??
			(ctx.offer.amount !== undefined
				? ctx.offer.amount * quantity
				: undefined);
		if (requested === undefined || requested <= 0n) return refusal;
		if (!ctx.blindingPoint) return refusal; // not over a signed path
		const payerIdHex = ctx.request.payerKey.toString('hex');
		const metadataHashHex = crypto
			.createHash('sha256')
			.update(ctx.request.metadata ?? Buffer.alloc(0))
			.digest('hex');
		// Identical metadata from the same payer: the same invoice, byte for
		// byte, or the same slot again when the crash came before the store.
		let slot = this.deps.ledger.issuedFor(
			mailboxIdHex,
			payerIdHex,
			metadataHashHex
		);
		if (slot?.invoiceHex)
			return { resend: Buffer.from(slot.invoiceHex, 'hex') };
		if (!slot) {
			// Step 2: an unissued slot of exactly this amount, never rounded,
			// never a larger one.
			const candidate = this.deps.ledger.firstUnissued(mailboxIdHex, requested);
			if (!candidate) return refusal;
			// Step 3: durable, compare-and-swap, before any invoice exists.
			const marked = this.deps.ledger.issue(
				candidate.id,
				payerIdHex,
				metadataHashHex
			);
			if (marked.outcome !== 'applied' || !marked.record) return refusal;
			slot = marked.record;
		}
		const issued = slot;
		const hops = m.hops.map(hopFromRow);
		const d = mailbox.entries[0]?.d ?? m.issueUntil;
		const remaining = Math.min(m.issueUntil, d) - height;
		const built = buildIssuerPaymentPath(hops, height + 2016);
		const signingPrivkey = deriveBlindedPrivkey(
			ctx.blindingPoint,
			this.deps.nodePrivkey
		);
		this.deps.log('ffor_issuer_issued', {
			mailboxId: mailboxIdHex,
			k: issued.k,
			payer: payerIdHex
		});
		this.deps.emit('ffor:issuer-issued', {
			mailboxId: Buffer.from(mailboxIdHex, 'hex'),
			k: issued.k,
			payerId: ctx.request.payerKey
		});
		return {
			decision: {
				paymentHash: Buffer.from(issued.hashHex, 'hex'),
				amountMsat: BigInt(issued.amountMsat),
				paths: [built.path],
				payInfo: [built.payInfo],
				relativeExpiry: conservativeExpirySeconds(remaining),
				signingPrivkey,
				nodeId: getPublicKey(signingPrivkey),
				features: Buffer.alloc(0),
				extraRecords: [
					{
						type: FF_ISSUER_ATTESTATION_TLV,
						value: encodeAttestationTlvValue(
							Buffer.from(m.hActHex, 'hex'),
							Buffer.from(m.hBookHex, 'hex'),
							Buffer.from(m.rAttestationHex, 'hex')
						)
					}
				],
				onIssued: (invoiceTlv): void => {
					this.deps.ledger.storeInvoice(issued.id, invoiceTlv.toString('hex'));
				}
			}
		};
	}

	// ── Status (section 9.7.7) ────────────────────────────────────────

	private handleStatus(peer: string, payload: Buffer): void {
		if (payload.length < FF_WITNESS_REQUEST_ID_LEN) return;
		const requestId = Buffer.from(
			payload.subarray(0, FF_WITNESS_REQUEST_ID_LEN)
		);
		const refuse = (): void => {
			this.deps.send(
				peer,
				FF_ISSUER_STATUS_RESP_TYPE,
				encodeIssuerStatusResp({
					requestId,
					ok: false,
					numSlots: 0,
					issued: Buffer.alloc(0),
					slots: [],
					error: 'unknown mailbox'
				})
			);
		};
		let msg: ReturnType<typeof decodeIssuerStatus>;
		try {
			msg = decodeIssuerStatus(payload);
		} catch {
			refuse();
			return;
		}
		const mailboxIdHex = msg.mailboxId.toString('hex');
		const mailbox = this.deps.witnessLedger.mailbox(mailboxIdHex);
		const m = this.deps.ledger.manifest(mailboxIdHex);
		if (
			!mailbox ||
			!m ||
			!verifyIssuerStatus(msg, Buffer.from(mailbox.fetchPubkeyHex, 'hex')) ||
			this.deps.witnessLedger.acceptNonce(
				mailboxIdHex,
				msg.nonce.toString('hex')
			) !== 'accepted'
		) {
			refuse();
			return;
		}
		const slots = this.deps.ledger.slotsOf(mailboxIdHex);
		const issued = Buffer.alloc(Math.ceil(m.numSlots / 8));
		const tuples = [];
		for (const s of slots) {
			if (s.state !== 'ISSUED') continue;
			bitmapSet(issued, s.k);
			tuples.push({
				k: s.k,
				payerId: Buffer.from(s.payerIdHex!, 'hex'),
				metadataHash: Buffer.from(s.metadataHashHex!, 'hex'),
				issuedUnixTime: BigInt(s.issuedUnixTime ?? 0)
			});
		}
		this.deps.send(
			peer,
			FF_ISSUER_STATUS_RESP_TYPE,
			encodeIssuerStatusResp({
				requestId,
				ok: true,
				numSlots: m.numSlots,
				issued,
				slots: tuples
			})
		);
	}

	// ── Retirement (section 9.7.7) ────────────────────────────────────

	private retire(mailboxIdHex: string, reason: string): void {
		const m = this.deps.ledger.manifest(mailboxIdHex);
		if (!m || m.state !== 'ISSUING') return;
		if (this.deps.ledger.retire(mailboxIdHex, reason).outcome === 'applied') {
			// The offer stays registered: a request after retirement gets the
			// one fixed refusal (section 9.7.3), never "unknown offer", which
			// would tell the payer that issuance ended.
			this.deps.log('ffor_issuer_retired', { mailboxId: mailboxIdHex, reason });
			this.deps.emit('ffor:issuer-retired', {
				mailboxId: Buffer.from(mailboxIdHex, 'hex'),
				reason
			});
		}
	}

	onBlock(height: number): void {
		for (const m of this.deps.ledger.listManifests()) {
			if (m.state !== 'ISSUING') continue;
			if (height >= m.issueUntil) this.retire(m.id, 'issue_until');
		}
	}

	/** Slots this issuer has issued for a mailbox (operators, tests). */
	issuedSlots(mailboxIdHex: string): number[] {
		return this.deps.ledger
			.slotsOf(mailboxIdHex)
			.filter((s) => s.state === 'ISSUED')
			.map((s) => s.k);
	}

	static slotId = slotId;
}
