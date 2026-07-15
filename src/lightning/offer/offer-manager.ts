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
import { IBlindedPath } from '../onion/blinded-path';
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
		{ offer: IOffer; encoded: string; tlvData: Buffer }
	> = new Map();
	private onionMessageManager: OnionMessageManager | null = null;
	private pendingInvoiceRequests: Map<
		string,
		{
			resolve: (invoice: IBolt12Invoice) => void;
			reject: (err: Error) => void;
			timer: ReturnType<typeof setTimeout>;
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
			(_fromPeer, _tlvType, data, replyPath) => {
				this.handleIncomingInvoiceRequest(data, replyPath);
			}
		);

		mgr.registerTlvHandler(TLV_INVOICE, (_fromPeer, _tlvType, data) => {
			this.handleIncomingInvoice(data);
		});

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

		// Store offer
		this.offers.set(offerId.toString('hex'), { offer, encoded, tlvData });

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
		if (options?.chain) request.chain = options.chain;

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

		// If we have an onion message manager and the offer has paths or issuer_id, send via onion
		if (this.onionMessageManager && (offer.paths || offer.issuerId)) {
			const messageData = new Map<number, Buffer>();
			const signedRequestTlv = encodeInvoiceRequestTlv(request, offerTlvData);
			messageData.set(TLV_INVOICE_REQUEST, signedRequestTlv);

			// Send to the first blinded path, or directly to issuer_id
			if (offer.paths && offer.paths.length > 0) {
				this.onionMessageManager.sendReply(offer.paths[0], messageData);
			} else if (offer.issuerId) {
				this.onionMessageManager.sendOnionMessage(offer.issuerId, messageData);
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

			this.pendingInvoiceRequests.set(offerIdHex, { resolve, reject, timer });
		});
	}

	/**
	 * Handle an incoming invoice request (as the offer issuer).
	 * Validates against local offers, creates a BOLT 12 invoice, and sends via reply path.
	 */
	handleInvoiceRequest(
		requestData: Buffer,
		replyPath?: IBlindedPath
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

		const invoice: IBolt12Invoice = {
			paymentHash,
			amount,
			description: matchedOffer.description,
			createdAt: BigInt(Math.floor(Date.now() / 1000)),
			relativeExpiry: 7200, // 2 hours
			paymentSecret,
			nodeId: this.nodeId,
			paths: matchedOffer.paths
		};

		// Sign the invoice
		const invoiceTlvData = encodeInvoiceTlv(invoice);
		const invoiceRecords = getTlvRecordsForSigning(invoiceTlvData);
		const merkleRoot = computeMerkleRootFromRecords(invoiceRecords);
		const sigHash = computeSignatureHash(INVOICE_SIGNATURE_TAG, merkleRoot);
		invoice.signature = schnorrSign(sigHash, this.nodePrivkey);

		// Send via reply path if available
		if (replyPath && this.onionMessageManager) {
			const signedInvoiceTlv = encodeInvoiceTlv(invoice);
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
	 */
	verifyInvoiceSignature(invoice: IBolt12Invoice): boolean {
		if (!invoice.signature) return false;

		const invoiceTlvData = encodeInvoiceTlv({
			...invoice,
			signature: undefined
		});
		const records = getTlvRecords(invoiceTlvData);
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
		replyPath?: IBlindedPath
	): void {
		this.handleInvoiceRequest(data, replyPath);
	}

	private handleIncomingInvoice(data: Buffer): void {
		const { invoice } = decodeInvoiceTlv(data);

		// Try to match by offer description + node ID (offer-aware matching)
		for (const [offerIdHex, pending] of this.pendingInvoiceRequests) {
			const offerEntry = this.offers.get(offerIdHex);
			if (offerEntry) {
				// Match by description and issuer
				const descMatch = offerEntry.offer.description === invoice.description;
				const issuerMatch =
					!offerEntry.offer.issuerId ||
					invoice.nodeId.equals(offerEntry.offer.issuerId);
				if (descMatch && issuerMatch) {
					clearTimeout(pending.timer);
					this.pendingInvoiceRequests.delete(offerIdHex);
					pending.resolve(invoice);
					this.emit('invoice:received', invoice);
					return;
				}
			}
		}

		// Fallback: if only one pending request, resolve it (backward compat)
		if (this.pendingInvoiceRequests.size === 1) {
			const [offerIdHex, pending] = this.pendingInvoiceRequests.entries().next()
				.value!;
			clearTimeout(pending.timer);
			this.pendingInvoiceRequests.delete(offerIdHex);
			pending.resolve(invoice);
			this.emit('invoice:received', invoice);
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
