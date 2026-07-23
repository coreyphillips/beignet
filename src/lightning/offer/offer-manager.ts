/**
 * BOLT 12: Offer Manager.
 *
 * High-level manager for creating offers, handling invoice requests,
 * and managing the BOLT 12 offer-to-payment flow.
 *
 * Events:
 * - 'offer:created' (offer: IOffer, encoded: string)
 * - 'invoice:requested' (request: IInvoiceRequest)
 * - 'invoice:received' (invoice: IBolt12Invoice)
 * - 'invoice:error' (error: IInvoiceError)
 */

import { EventEmitter } from 'events';
import crypto from 'crypto';
import {
	IOffer,
	IInvoiceRequest,
	IBolt12Invoice,
	IInvoiceError
} from './types';
import {
	encodeOfferTlv,
	encodeInvoiceRequestTlv,
	decodeInvoiceRequestTlv,
	encodeInvoiceTlv,
	decodeInvoiceTlv,
	encodeInvoiceErrorTlv,
	decodeInvoiceErrorTlv,
	getTlvRecords,
	getTlvRecordsForSigning
} from './tlv';
import {
	computeOfferId,
	computeSignatureHash,
	computeMerkleRootFromRecords
} from './merkle';
import { schnorrSign, schnorrVerify, toXOnlyPubkey } from './schnorr';
import { encodeOffer } from './encode';
import { ITlvRecord } from '../message/tlv';
import { IBlindedPath, constructBlindedPath } from '../onion/blinded-path';
import { OnionMessageManager } from '../onion-message/manager';
import { getPublicKey } from '../crypto/ecdh';

/** TLV type for BOLT 12 invoice request in onion messages */
export const TLV_INVOICE_REQUEST = 64;
/** TLV type for BOLT 12 invoice in onion messages */
export const TLV_INVOICE = 66;
/** TLV type for BOLT 12 invoice error in onion messages */
export const TLV_INVOICE_ERROR = 68;

// BOLT 12 signature tags are "lightning" || messagename || fieldname (the field
// is always the "signature" field, type 240). A bare "lightning" tag made every
// signature incompatible with CLN/eclair/LDK in both directions.
/** Signature tag for BOLT 12 invoices. */
const INVOICE_SIGNATURE_TAG = 'lightninginvoicesignature';
/** Signature tag for BOLT 12 invoice requests. */
const INVOICE_REQUEST_SIGNATURE_TAG = 'lightninginvoice_requestsignature';

export interface ICreateOfferOptions {
	/** Amount in millisatoshis (optional for "any amount" offers) */
	amount?: bigint;
	/** Human-readable description */
	description: string;
	/** Optional issuer name */
	issuer?: string;
	/** Optional features */
	features?: Buffer;
	/** Optional blinded paths for reaching the issuer */
	paths?: IBlindedPath[];
	/** Maximum quantity */
	quantityMax?: bigint;
	/** Absolute expiry (seconds since epoch) */
	absoluteExpiry?: bigint;
	/** Supported chains (each 32 bytes) */
	chains?: Buffer[];
	/** Optional metadata */
	metadata?: Buffer;
	/**
	 * BOLT 4 path_id embedded in the final hop of `paths`. When set, an
	 * incoming invoice_request for this offer MUST have arrived over one of
	 * those paths (its decrypted recipient data carries this path_id) or it is
	 * rejected. Omit for externally built paths without one.
	 */
	pathId?: Buffer;
}

export interface IRequestInvoiceOptions {
	/** Amount to pay in millisatoshis (required if offer has no amount) */
	amount?: bigint;
	/** Quantity to request */
	quantity?: bigint;
	/** Payer note */
	payerNote?: string;
	/** Chain hash (32 bytes) */
	chain?: Buffer;
}

export class OfferManager extends EventEmitter {
	private nodePrivkey: Buffer;
	private nodeId: Buffer;
	private offers: Map<
		string,
		{ offer: IOffer; encoded: string; tlvData: Buffer; pathId?: Buffer }
	> = new Map();
	private onionMessageManager: OnionMessageManager | null = null;
	private pendingInvoiceRequests: Map<
		string,
		{
			resolve: (invoice: IBolt12Invoice) => void;
			reject: (err: Error) => void;
			timer: ReturnType<typeof setTimeout>;
			/**
			 * The signed invreq records we sent, retained so the invoice's
			 * mirrored fields can be checked (BOLT 12: the reader MUST reject an
			 * invoice whose invreq-range fields differ from the request).
			 */
			sentRecords?: ITlvRecord[];
			/**
			 * The path_id we embedded in the blinded reply path sent with the
			 * invreq. When set, only an invoice delivered over that path (its
			 * decrypted recipient data surfaces this path_id) may resolve this
			 * request.
			 */
			replyPathId?: Buffer;
		}
	> = new Map();
	/**
	 * Payment preimages for BOLT 12 invoices WE issued (offer-issuer side), keyed
	 * by payment_hash hex. The preimage is secret and never goes on the wire, but
	 * the node must register it so an incoming HTLC for this hash can be fulfilled.
	 * Surfaced via the `invoice:issued` event and {@link getInvoicePreimage}.
	 */
	private invoicePreimages: Map<string, Buffer> = new Map();
	private invoiceRequestTimeoutMs: number;

	constructor(
		nodePrivkey: Buffer,
		options?: {
			onionMessageManager?: OnionMessageManager;
			invoiceRequestTimeoutMs?: number;
		}
	) {
		super();
		this.nodePrivkey = nodePrivkey;
		this.nodeId = getPublicKey(nodePrivkey);
		this.invoiceRequestTimeoutMs = options?.invoiceRequestTimeoutMs ?? 30_000;

		if (options?.onionMessageManager) {
			this.attachOnionMessageManager(options.onionMessageManager);
		}
	}

	/**
	 * Attach an OnionMessageManager for sending/receiving BOLT 12 messages.
	 */
	attachOnionMessageManager(mgr: OnionMessageManager): void {
		this.onionMessageManager = mgr;

		// Register TLV handlers for BOLT 12 message types
		mgr.registerTlvHandler(
			TLV_INVOICE_REQUEST,
			(_fromPeer, _tlvType, data, replyPath, pathId) => {
				this.handleIncomingInvoiceRequest(data, replyPath, pathId);
			}
		);

		mgr.registerTlvHandler(
			TLV_INVOICE,
			(_fromPeer, _tlvType, data, _replyPath, pathId) => {
				this.handleIncomingInvoice(data, pathId);
			}
		);

		mgr.registerTlvHandler(TLV_INVOICE_ERROR, (_fromPeer, _tlvType, data) => {
			this.handleIncomingInvoiceError(data);
		});
	}

	/**
	 * Create a new offer.
	 *
	 * @param options - Offer parameters
	 * @returns The offer and its bech32m-encoded string
	 */
	createOffer(options: ICreateOfferOptions): {
		offer: IOffer;
		encoded: string;
	} {
		const offer: IOffer = {
			offerId: Buffer.alloc(32), // Placeholder — computed below
			description: options.description,
			issuerId: this.nodeId
		};

		if (options.amount !== undefined) offer.amount = options.amount;
		if (options.issuer) offer.issuer = options.issuer;
		if (options.features) offer.features = options.features;
		if (options.paths) offer.paths = options.paths;
		if (options.quantityMax !== undefined)
			offer.quantityMax = options.quantityMax;
		if (options.absoluteExpiry !== undefined)
			offer.absoluteExpiry = options.absoluteExpiry;
		if (options.chains) offer.chains = options.chains;
		if (options.metadata) offer.metadata = options.metadata;

		// Encode TLV and compute offer ID
		const tlvData = encodeOfferTlv(offer);
		const records = getTlvRecords(tlvData);
		const offerId = computeOfferId(records);
		offer.offerId = offerId;

		const encoded = encodeOffer(offer);

		// Store offer (with the expected path_id when its paths carry one)
		this.offers.set(offerId.toString('hex'), {
			offer,
			encoded,
			tlvData,
			pathId: options.pathId
		});

		this.emit('offer:created', offer, encoded);
		return { offer, encoded };
	}

	/**
	 * Get a stored offer by its ID.
	 */
	getOffer(offerId: Buffer): IOffer | undefined {
		const entry = this.offers.get(offerId.toString('hex'));
		return entry?.offer;
	}

	/**
	 * List all stored offers.
	 */
	listOffers(): IOffer[] {
		return Array.from(this.offers.values()).map((e) => e.offer);
	}

	/**
	 * Remove a stored offer.
	 */
	removeOffer(offerId: Buffer): boolean {
		return this.offers.delete(offerId.toString('hex'));
	}

	/**
	 * Request an invoice for an offer.
	 * Sends an invoice_request via onion message and waits for the invoice reply.
	 *
	 * @param offer - The offer to request an invoice for
	 * @param options - Request options (amount, quantity, etc.)
	 * @returns Promise that resolves with the received BOLT 12 invoice
	 */
	async requestInvoice(
		offer: IOffer,
		options?: IRequestInvoiceOptions
	): Promise<IBolt12Invoice> {
		// Validate offer
		if (offer.absoluteExpiry !== undefined) {
			const now = BigInt(Math.floor(Date.now() / 1000));
			if (now >= offer.absoluteExpiry) {
				throw new Error('Offer has expired');
			}
		}

		// Generate ephemeral payer key
		const payerPrivkey = crypto.randomBytes(32);
		const payerPubkey = getPublicKey(payerPrivkey);

		// Build invoice request. invreq_metadata (type 0) is a payer-generated
		// nonce that BOLT 12 requires and that the signature commits to; it must be
		// set before we encode + sign.
		const request: IInvoiceRequest = {
			payerKey: payerPubkey,
			offerId: offer.offerId,
			amount: options?.amount ?? offer.amount,
			metadata: crypto.randomBytes(32)
		};

		if (options?.quantity !== undefined) request.quantity = options.quantity;
		if (options?.payerNote) request.payerNote = options.payerNote;
		// BOLT 12: invreq_chain MUST name the chain unless it is bitcoin
		// mainnet. Default it from the offer's own chains — omitting it on
		// regtest/testnet makes the issuer reject with "Wrong chain".
		const chain = options?.chain ?? offer.chains?.[0];
		if (chain) request.chain = chain;

		// Encode the invoice request TLV (includes offer fields)
		const offerTlvData = encodeOfferTlv(offer);
		const requestTlvData = encodeInvoiceRequestTlv(request, offerTlvData);

		// Sign the invoice request with the payer key
		const requestRecords = getTlvRecords(requestTlvData);
		const merkleRoot = computeMerkleRootFromRecords(requestRecords);
		const sigHash = computeSignatureHash(
			INVOICE_REQUEST_SIGNATURE_TAG,
			merkleRoot
		);
		request.signature = schnorrSign(sigHash, payerPrivkey);

		// The exact signed records we send: retained so the invoice's mirrored
		// invreq-range fields can be verified on receipt (BOLT 12 reader MUST).
		const signedRequestTlv = encodeInvoiceRequestTlv(request, offerTlvData);
		const sentRecords = getTlvRecords(signedRequestTlv);

		// If we have an onion message manager and the offer has paths or issuer_id, send via onion
		let replyPathId: Buffer | undefined;
		if (this.onionMessageManager && (offer.paths || offer.issuerId)) {
			const messageData = new Map<number, Buffer>();
			messageData.set(TLV_INVOICE_REQUEST, signedRequestTlv);

			// BOLT 12: the issuer sends its invoice back over OUR reply path, so
			// the invoice_request MUST carry one — without it a conformant
			// issuer (CLN) silently drops the request and the payer times out.
			// A 1-hop path to ourselves: the issuer routes to our real node id
			// (the introduction node IS the recipient) and only WE ever decrypt
			// the hop blob, so it also carries a path_id we verify on the reply
			// (stored on the pending request below).
			replyPathId = crypto.randomBytes(32);
			const replyPath = constructBlindedPath(
				crypto.randomBytes(32),
				[this.nodeId],
				[{ pathId: replyPathId }]
			);

			// Send along the offer's first blinded path, or — for a pathless
			// offer — along a 1-hop blinded path we build to the issuer: BOLT 4
			// onion messages are ALWAYS blinded (every hop payload carries
			// encrypted_data and the sphinx layer is addressed to blinded node
			// ids), so a raw unblinded send is silently dropped by CLN/LND.
			if (offer.paths && offer.paths.length > 0) {
				this.onionMessageManager.sendReply(offer.paths[0], messageData, {
					replyPath
				});
			} else if (offer.issuerId) {
				const issuerPath = constructBlindedPath(
					crypto.randomBytes(32),
					[offer.issuerId],
					[{}]
				);
				this.onionMessageManager.sendReply(issuerPath, messageData, {
					replyPath
				});
			}
		}

		this.emit('invoice:requested', request);

		// Wait for invoice response
		return new Promise<IBolt12Invoice>((resolve, reject) => {
			const offerIdHex = offer.offerId.toString('hex');
			const timer = setTimeout(() => {
				this.pendingInvoiceRequests.delete(offerIdHex);
				reject(new Error('Invoice request timed out'));
			}, this.invoiceRequestTimeoutMs);

			this.pendingInvoiceRequests.set(offerIdHex, {
				resolve,
				reject,
				timer,
				sentRecords,
				replyPathId
			});
		});
	}

	/**
	 * Handle an incoming invoice request (as the offer issuer).
	 * Validates against local offers, creates a BOLT 12 invoice, and sends via reply path.
	 */
	handleInvoiceRequest(
		requestData: Buffer,
		replyPath?: IBlindedPath,
		pathId?: Buffer
	): IBolt12Invoice | null {
		const { request, records } = decodeInvoiceRequestTlv(requestData);

		// BOLT 12: a valid invoice_request MUST carry invreq_metadata (type 0) and
		// a signature (type 240) by the payer key. Reject an unsigned or forged
		// request rather than issuing an invoice against it.
		if (
			!request.metadata ||
			!request.signature ||
			!this.verifyInvoiceRequestSignature(
				records,
				request.payerKey,
				request.signature
			)
		) {
			const error: IInvoiceError = { error: 'Invalid invoice request' };
			if (replyPath && this.onionMessageManager) {
				const errData = encodeInvoiceErrorTlv(error);
				const messageData = new Map<number, Buffer>();
				messageData.set(TLV_INVOICE_ERROR, errData);
				this.onionMessageManager.sendReply(replyPath, messageData);
			}
			this.emit('invoice:error', error);
			return null;
		}

		// Match against local offers by the offerId the decoder computed from the
		// offer TLV records mirrored into the request (zero when none present).
		let matchedOffer: IOffer | undefined;
		let matchedOfferIdHex: string | undefined;

		if (!request.offerId.equals(Buffer.alloc(32))) {
			matchedOfferIdHex = request.offerId.toString('hex');
			matchedOffer = this.offers.get(matchedOfferIdHex)?.offer;
		}

		if (!matchedOffer) {
			// Send error
			const error: IInvoiceError = { error: 'Unknown offer' };
			if (replyPath && this.onionMessageManager) {
				const errData = encodeInvoiceErrorTlv(error);
				const messageData = new Map<number, Buffer>();
				messageData.set(TLV_INVOICE_ERROR, errData);
				this.onionMessageManager.sendReply(replyPath, messageData);
			}
			this.emit('invoice:error', error);
			return null;
		}

		// BOLT 4: when we embedded a path_id in this offer's blinded paths, the
		// invoice_request MUST have arrived over one of them — its decrypted
		// recipient data surfaces that path_id. A request addressed to us
		// directly (or over a forged path) is rejected.
		const expectedPathId = this.offers.get(matchedOfferIdHex!)?.pathId;
		if (expectedPathId && (!pathId || !pathId.equals(expectedPathId))) {
			const error: IInvoiceError = { error: 'Invalid path_id' };
			if (replyPath && this.onionMessageManager) {
				const errData = encodeInvoiceErrorTlv(error);
				const messageData = new Map<number, Buffer>();
				messageData.set(TLV_INVOICE_ERROR, errData);
				this.onionMessageManager.sendReply(replyPath, messageData);
			}
			this.emit('invoice:error', error);
			return null;
		}

		// Validate expiry
		if (matchedOffer.absoluteExpiry !== undefined) {
			const now = BigInt(Math.floor(Date.now() / 1000));
			if (now >= matchedOffer.absoluteExpiry) {
				const error: IInvoiceError = { error: 'Offer has expired' };
				if (replyPath && this.onionMessageManager) {
					const errData = encodeInvoiceErrorTlv(error);
					const messageData = new Map<number, Buffer>();
					messageData.set(TLV_INVOICE_ERROR, errData);
					this.onionMessageManager.sendReply(replyPath, messageData);
				}
				this.emit('invoice:error', error);
				return null;
			}
		}

		// Validate amount
		const amount = request.amount ?? matchedOffer.amount;
		if (amount === undefined) {
			const error: IInvoiceError = {
				error: 'Amount required but not specified'
			};
			if (replyPath && this.onionMessageManager) {
				const errData = encodeInvoiceErrorTlv(error);
				const messageData = new Map<number, Buffer>();
				messageData.set(TLV_INVOICE_ERROR, errData);
				this.onionMessageManager.sendReply(replyPath, messageData);
			}
			this.emit('invoice:error', error);
			return null;
		}

		// Create invoice
		const preimage = crypto.randomBytes(32);
		const paymentHash = crypto.createHash('sha256').update(preimage).digest();
		const paymentSecret = crypto.randomBytes(32);

		// Retain the preimage so the node can fulfill the incoming HTLC for this
		// invoice (it never leaves the issuer — not part of the BOLT 12 invoice).
		this.invoicePreimages.set(paymentHash.toString('hex'), preimage);

		// BOLT 12: the invoice MUST include invoice_paths (one or more blinded
		// paths to us) with exactly one blinded_payinfo per path. Reuse the
		// offer's paths when it has them; a direct (announced-node) offer gets a
		// minimal 1-hop path terminating at us — the payer treats the
		// introduction node as the destination.
		const invoicePaths =
			matchedOffer.paths && matchedOffer.paths.length > 0
				? matchedOffer.paths
				: [
						{
							introductionNodeId: this.nodeId,
							blindingPoint: getPublicKey(crypto.randomBytes(32)),
							blindedHops: [
								{ blindedNodeId: this.nodeId, encryptedData: Buffer.alloc(0) }
							]
						}
				  ];
		const invoicePayInfo = invoicePaths.map(() => ({
			feeBaseMsat: 0,
			feeProportionalMillionths: 0,
			cltvExpiryDelta: 18,
			htlcMinimumMsat: 1n,
			htlcMaximumMsat: 21_000_000n * 100_000_000n * 1000n
		}));

		const invoice: IBolt12Invoice = {
			paymentHash,
			amount,
			description: matchedOffer.description,
			createdAt: BigInt(Math.floor(Date.now() / 1000)),
			relativeExpiry: 7200, // 2 hours
			paymentSecret,
			nodeId: this.nodeId,
			paths: invoicePaths,
			blindedPayInfo: invoicePayInfo
		};

		// Sign the invoice. BOLT 12: the invoice MUST copy all non-signature
		// fields from the invoice_request (mirrored via `records`), and the
		// signature commits to the FULL record set — mirrored fields included.
		const invoiceTlvData = encodeInvoiceTlv(invoice, records);
		const invoiceRecords = getTlvRecordsForSigning(invoiceTlvData);
		const merkleRoot = computeMerkleRootFromRecords(invoiceRecords);
		const sigHash = computeSignatureHash(INVOICE_SIGNATURE_TAG, merkleRoot);
		invoice.signature = schnorrSign(sigHash, this.nodePrivkey);
		// Retain the full signed wire records (mirrored fields included):
		// signature verification and any re-encode must use these, never a
		// structural re-encode that would drop the mirror.
		invoice.records = getTlvRecords(encodeInvoiceTlv(invoice, records));

		// Send via reply path if available
		if (replyPath && this.onionMessageManager) {
			const signedInvoiceTlv = encodeInvoiceTlv(invoice, records);
			const messageData = new Map<number, Buffer>();
			messageData.set(TLV_INVOICE, signedInvoiceTlv);
			this.onionMessageManager.sendReply(replyPath, messageData);
		}

		// `invoice:issued` carries the preimage so the node can register it for
		// settlement (the issuer side — we will RECEIVE this payment). Distinct from
		// `invoice:received`, which also fires when we are the PAYER and hold no
		// preimage.
		this.emit('invoice:issued', invoice, preimage);
		this.emit('invoice:received', invoice);
		return invoice;
	}

	/**
	 * The payment preimage for a BOLT 12 invoice WE issued, or undefined if this
	 * payment_hash was not issued by us (e.g. we are the payer). Used by the node
	 * to fulfill an incoming HTLC matching a BOLT 12 invoice.
	 */
	getInvoicePreimage(paymentHash: Buffer): Buffer | undefined {
		return this.invoicePreimages.get(paymentHash.toString('hex'));
	}

	/**
	 * Validate a BOLT 12 invoice signature.
	 *
	 * When the raw decoded `records` are available (any invoice received off
	 * the wire) they MUST be used: the signature commits to every record —
	 * including invreq fields mirrored per BOLT 12 and unknown TLVs — which a
	 * structural re-encode would drop, wrongly failing every spec invoice.
	 */
	verifyInvoiceSignature(
		invoice: IBolt12Invoice,
		rawRecords?: ITlvRecord[]
	): boolean {
		if (!invoice.signature) return false;

		const raw = rawRecords ?? invoice.records;
		const records = raw
			? raw.filter((r) => r.type !== 240n)
			: getTlvRecords(
					encodeInvoiceTlv({
						...invoice,
						signature: undefined
					})
			  );
		const merkleRoot = computeMerkleRootFromRecords(records);
		const sigHash = computeSignatureHash(INVOICE_SIGNATURE_TAG, merkleRoot);

		const xOnlyNodeId = toXOnlyPubkey(invoice.nodeId);
		return schnorrVerify(sigHash, xOnlyNodeId, invoice.signature);
	}

	/**
	 * Verify an invoice_request's payer signature (BOLT 12): the signature covers
	 * the merkle root of all request TLVs except the signature itself, and is made
	 * by the invreq_payer_id key.
	 */
	verifyInvoiceRequestSignature(
		records: ITlvRecord[],
		payerKey: Buffer,
		signature: Buffer
	): boolean {
		const merkleRoot = computeMerkleRootFromRecords(records);
		const sigHash = computeSignatureHash(
			INVOICE_REQUEST_SIGNATURE_TAG,
			merkleRoot
		);
		return schnorrVerify(sigHash, toXOnlyPubkey(payerKey), signature);
	}

	/**
	 * Validate that an invoice is consistent with its source offer.
	 */
	validateInvoiceForOffer(invoice: IBolt12Invoice, offer: IOffer): boolean {
		// Amount must match or exceed offer amount
		if (offer.amount !== undefined && invoice.amount < offer.amount) {
			return false;
		}

		// Description must match
		if (invoice.description !== offer.description) {
			return false;
		}

		// Node ID should match offer issuer ID
		if (offer.issuerId && !invoice.nodeId.equals(offer.issuerId)) {
			return false;
		}

		return true;
	}

	/**
	 * Destroy the manager, cleaning up all state.
	 */
	destroy(): void {
		// Clear pending requests
		for (const [, pending] of this.pendingInvoiceRequests) {
			clearTimeout(pending.timer);
			pending.reject(new Error('OfferManager destroyed'));
		}
		this.pendingInvoiceRequests.clear();
		this.offers.clear();
		this.invoicePreimages.clear();
		this.onionMessageManager = null;
		this.removeAllListeners();
	}

	// ─────────────── Private ───────────────

	private handleIncomingInvoiceRequest(
		data: Buffer,
		replyPath?: IBlindedPath,
		pathId?: Buffer
	): void {
		this.handleInvoiceRequest(data, replyPath, pathId);
	}

	private handleIncomingInvoice(data: Buffer, pathId?: Buffer): void {
		const { invoice, records } = decodeInvoiceTlv(data);

		// BOLT 12 reader checks (S-4.H3): the signature commits to the FULL
		// record set (mirrored + unknown fields included), the invoice MUST
		// carry blinded payment paths with exactly one payinfo per path, and
		// its invreq-range fields MUST byte-match the request we sent.
		const validateAgainstSent = (sentRecords?: ITlvRecord[]): string | null => {
			if (!this.verifyInvoiceSignature(invoice, records)) {
				return 'invalid invoice signature';
			}
			if (!invoice.paths || invoice.paths.length === 0) {
				return 'invoice_paths missing or empty';
			}
			if (
				!invoice.blindedPayInfo ||
				invoice.blindedPayInfo.length !== invoice.paths.length
			) {
				return 'invoice_blindedpay must carry one payinfo per path';
			}
			if (sentRecords) {
				for (const sent of sentRecords) {
					if (sent.type === 240n) continue; // signature not mirrored
					const mirrored = records.find((r) => r.type === sent.type);
					if (!mirrored || !mirrored.value.equals(sent.value)) {
						return `invoice does not mirror invreq field ${sent.type}`;
					}
				}
			}
			return null;
		};

		const settle = (
			offerIdHex: string,
			pending: NonNullable<
				ReturnType<(typeof this.pendingInvoiceRequests)['get']>
			>
		): void => {
			const reason = validateAgainstSent(pending.sentRecords);
			clearTimeout(pending.timer);
			this.pendingInvoiceRequests.delete(offerIdHex);
			if (reason) {
				pending.reject(new Error(`Rejected BOLT 12 invoice: ${reason}`));
				this.emit('invoice:error', { error: reason });
				return;
			}
			pending.resolve(invoice);
			this.emit('invoice:received', invoice);
		};

		// BOLT 4: an invoice delivered over one of OUR blinded reply paths
		// surfaces the path_id we embedded — the strongest possible binding to
		// the request that issued it. Match on it first; a path_id that matches
		// no pending request means the message did not come over a path we
		// issued for a live request, so ignore it entirely.
		if (pathId) {
			for (const [offerIdHex, pending] of this.pendingInvoiceRequests) {
				if (pending.replyPathId && pending.replyPathId.equals(pathId)) {
					settle(offerIdHex, pending);
					return;
				}
			}
			this.emit('invoice:error', {
				error: 'invoice path_id matches no pending invoice_request'
			});
			return;
		}

		// No path_id: the invoice did NOT arrive over a blinded reply path we
		// issued. A pending request that sent one (replyPathId set) must only be
		// resolved via that path, so it is skipped here; legacy pendings created
		// without an onion send (no reply path) keep the description/issuer match.
		for (const [offerIdHex, pending] of this.pendingInvoiceRequests) {
			if (pending.replyPathId) continue;
			const offerEntry = this.offers.get(offerIdHex);
			if (offerEntry) {
				// Match by description and issuer
				const descMatch = offerEntry.offer.description === invoice.description;
				const issuerMatch =
					!offerEntry.offer.issuerId ||
					invoice.nodeId.equals(offerEntry.offer.issuerId);
				if (descMatch && issuerMatch) {
					settle(offerIdHex, pending);
					return;
				}
			}
		}

		// Fallback: if only one pending request (without a reply-path binding),
		// resolve it (backward compat)
		if (this.pendingInvoiceRequests.size === 1) {
			const [offerIdHex, pending] = this.pendingInvoiceRequests.entries().next()
				.value!;
			if (!pending.replyPathId) {
				settle(offerIdHex, pending);
				return;
			}
			this.emit('invoice:error', {
				error: 'invoice lacks the path_id of its pending invoice_request'
			});
			return;
		}

		// No pending request — emit as unsolicited invoice
		this.emit('invoice:received', invoice);
	}

	private handleIncomingInvoiceError(data: Buffer): void {
		const error = decodeInvoiceErrorTlv(data);

		// Reject the first pending request
		for (const [offerIdHex, pending] of this.pendingInvoiceRequests) {
			clearTimeout(pending.timer);
			this.pendingInvoiceRequests.delete(offerIdHex);
			pending.reject(new Error(`Invoice error: ${error.error}`));
			break;
		}

		this.emit('invoice:error', error);
	}
}
