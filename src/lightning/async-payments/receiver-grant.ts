/**
 * Receiver registration grant for the async receive service (issue #709).
 *
 * A receiver asks a holding LSP for a registration (ASYNC_REGISTRATION_REQUEST
 * onion message); the LSP, when its service is enabled and it admits the
 * receiver, answers with a GRANT signed by its node key. The grant is the
 * receiver's proof that this LSP will park hold_htlc forwards for it, and
 * the terms it registered under. Its `registration_id` is the value the
 * receiver stamps into the hold_htlc marker of its blinded payment paths
 * (issue #708 reserved that slot for exactly this), and the LSP admits a
 * hold only when the marker names an ACTIVE registration whose receiver is
 * the peer on the outgoing channel and whose permitted SCID is the channel
 * the path forwards onto.
 *
 * Request (all integers big-endian):
 *
 *   version            u8   (1)
 *   chain_hash         32
 *   receiver_node_id   33   must be the onion message's authenticated sender
 *   lsp_node_id        33   the node being asked
 *   scid               8    the LSP -> receiver channel the receiver will
 *                           name in its paths (its intercept identifier)
 *   requested_blocks   u16  hold window wanted; 0 = the service default
 *   nonce              32   random; the replay domain of the request AND
 *                           of the grant it produces (see below)
 *
 * Grant body:
 *
 *   version            u8   (1)
 *   feature_bit        u16  the BOLT 9 bit the service was negotiated under
 *                           (Feature.ASYNC_RECEIVE_SERVICE + 1, the odd bit)
 *   service_flags      u32  reserved, zero
 *   chain_hash         32
 *   receiver_node_id   33
 *   lsp_node_id        33
 *   registration_id    32   random, LSP-minted; the hold_htlc marker value
 *   scid               8    the only outgoing channel holds may target
 *   max_part_msat      u64  largest single held part
 *   max_payment_msat   u64  largest sum of parts under one payment hash
 *   max_parts          u16  concurrent unresolved holds
 *   max_held_msat      u64  aggregate unresolved held value
 *   max_hold_blocks    u16  longest hold window (cutoff is clamped to it)
 *   min_remaining_cltv u16  shortest window a hold is admitted with
 *   admission_fee_msat u64  non-refundable, per part, from prepaid credit
 *   holding_fee_msat_per_block u64  paid by the sender in the LSP hop's
 *                           payment_relay fee, for the whole max_hold_blocks
 *                           window, kept by the LSP at release
 *   fee_collection     u8   1 = the scheme above (the only defined value)
 *   credit_msat        u64  prepaid credit at issuance
 *   issued_at          u64  unix seconds
 *   expires_at         u64  unix seconds; holds are not admitted after it
 *   nonce              32   the request nonce, echoed: the LSP refuses a
 *                           second request carrying a nonce it has seen from
 *                           the same receiver, so a captured request cannot
 *                           mint a second registration, and the receiver
 *                           matches the reply to its own request by it
 *   witness_profile    32   receipt-witness profile id (ffor#24); zeros =
 *                           none. Reserved, unused for now.
 *
 *   digest    = SHA256(SHA256(tag) || SHA256(tag) || body)
 *               tag = "beignet/async-payments/receiver-grant/v1"
 *   signature = ECDSA(LSP node key, digest), 64-byte compact
 *   wire      = body || signature
 *
 * Reply: status u8 (1 = granted, followed by the grant wire; 0 = refused,
 * followed by the request nonce and a UTF-8 reason).
 */

import crypto from 'crypto';
import { sign, verify } from '../crypto/ecdh';

export const RECEIVER_GRANT_VERSION = 1;
export const REGISTRATION_REQUEST_VERSION = 1;
const GRANT_TAG = 'beignet/async-payments/receiver-grant/v1';

/** The only defined fee-collection scheme (see the module comment). */
export const FEE_COLLECTION_PREPAID_ADMISSION_SENDER_HOLDING = 1;

const REQUEST_LEN = 1 + 32 + 33 + 33 + 8 + 2 + 32;
const GRANT_BODY_LEN =
	1 +
	2 +
	4 +
	32 +
	33 +
	33 +
	32 +
	8 +
	8 +
	8 +
	2 +
	8 +
	2 +
	2 +
	8 +
	8 +
	1 +
	8 +
	8 +
	8 +
	32 +
	32;
const SIGNATURE_LEN = 64;

export interface IRegistrationRequest {
	version: number;
	chainHash: Buffer;
	receiverNodeId: Buffer;
	lspNodeId: Buffer;
	scid: Buffer;
	requestedHoldBlocks: number;
	nonce: Buffer;
}

export interface IReceiverGrant {
	version: number;
	featureBit: number;
	serviceFlags: number;
	chainHash: Buffer;
	receiverNodeId: Buffer;
	lspNodeId: Buffer;
	registrationId: Buffer;
	scid: Buffer;
	maxPartMsat: bigint;
	maxPaymentMsat: bigint;
	maxParts: number;
	maxHeldMsat: bigint;
	maxHoldBlocks: number;
	minRemainingCltv: number;
	admissionFeeMsat: bigint;
	holdingFeeMsatPerBlock: bigint;
	feeCollection: number;
	creditMsat: bigint;
	/** Unix seconds. */
	issuedAt: bigint;
	/** Unix seconds. */
	expiresAt: bigint;
	nonce: Buffer;
	witnessProfile: Buffer;
	signature: Buffer;
}

export type IUnsignedReceiverGrant = Omit<IReceiverGrant, 'signature'>;

export type IRegistrationReply =
	| { granted: true; grant: IReceiverGrant }
	| { granted: false; nonce: Buffer; reason: string };

/** BIP340-style tagged hash. */
function taggedHash(tag: string, data: Buffer): Buffer {
	const tagHash = crypto.createHash('sha256').update(tag).digest();
	return crypto
		.createHash('sha256')
		.update(tagHash)
		.update(tagHash)
		.update(data)
		.digest();
}

function expectLen(buf: Buffer, len: number, what: string): void {
	if (buf.length !== len) throw new Error(`${what} must be ${len} bytes`);
}

// ─────────────── Request ───────────────

export function encodeRegistrationRequest(req: IRegistrationRequest): Buffer {
	expectLen(req.chainHash, 32, 'chain hash');
	expectLen(req.receiverNodeId, 33, 'receiver node id');
	expectLen(req.lspNodeId, 33, 'lsp node id');
	expectLen(req.scid, 8, 'scid');
	expectLen(req.nonce, 32, 'nonce');
	const buf = Buffer.alloc(REQUEST_LEN);
	let off = 0;
	buf.writeUInt8(req.version, off);
	off += 1;
	req.chainHash.copy(buf, off);
	off += 32;
	req.receiverNodeId.copy(buf, off);
	off += 33;
	req.lspNodeId.copy(buf, off);
	off += 33;
	req.scid.copy(buf, off);
	off += 8;
	buf.writeUInt16BE(req.requestedHoldBlocks, off);
	off += 2;
	req.nonce.copy(buf, off);
	return buf;
}

export function decodeRegistrationRequest(
	buf: Buffer
): IRegistrationRequest | null {
	if (buf.length !== REQUEST_LEN) return null;
	let off = 0;
	const version = buf.readUInt8(off);
	off += 1;
	if (version !== REGISTRATION_REQUEST_VERSION) return null;
	const chainHash = Buffer.from(buf.subarray(off, off + 32));
	off += 32;
	const receiverNodeId = Buffer.from(buf.subarray(off, off + 33));
	off += 33;
	const lspNodeId = Buffer.from(buf.subarray(off, off + 33));
	off += 33;
	const scid = Buffer.from(buf.subarray(off, off + 8));
	off += 8;
	const requestedHoldBlocks = buf.readUInt16BE(off);
	off += 2;
	const nonce = Buffer.from(buf.subarray(off, off + 32));
	return {
		version,
		chainHash,
		receiverNodeId,
		lspNodeId,
		scid,
		requestedHoldBlocks,
		nonce
	};
}

// ─────────────── Grant ───────────────

function encodeGrantBody(g: IUnsignedReceiverGrant): Buffer {
	expectLen(g.chainHash, 32, 'chain hash');
	expectLen(g.receiverNodeId, 33, 'receiver node id');
	expectLen(g.lspNodeId, 33, 'lsp node id');
	expectLen(g.registrationId, 32, 'registration id');
	expectLen(g.scid, 8, 'scid');
	expectLen(g.nonce, 32, 'nonce');
	expectLen(g.witnessProfile, 32, 'witness profile');
	const buf = Buffer.alloc(GRANT_BODY_LEN);
	let off = 0;
	buf.writeUInt8(g.version, off);
	off += 1;
	buf.writeUInt16BE(g.featureBit, off);
	off += 2;
	buf.writeUInt32BE(g.serviceFlags, off);
	off += 4;
	g.chainHash.copy(buf, off);
	off += 32;
	g.receiverNodeId.copy(buf, off);
	off += 33;
	g.lspNodeId.copy(buf, off);
	off += 33;
	g.registrationId.copy(buf, off);
	off += 32;
	g.scid.copy(buf, off);
	off += 8;
	buf.writeBigUInt64BE(g.maxPartMsat, off);
	off += 8;
	buf.writeBigUInt64BE(g.maxPaymentMsat, off);
	off += 8;
	buf.writeUInt16BE(g.maxParts, off);
	off += 2;
	buf.writeBigUInt64BE(g.maxHeldMsat, off);
	off += 8;
	buf.writeUInt16BE(g.maxHoldBlocks, off);
	off += 2;
	buf.writeUInt16BE(g.minRemainingCltv, off);
	off += 2;
	buf.writeBigUInt64BE(g.admissionFeeMsat, off);
	off += 8;
	buf.writeBigUInt64BE(g.holdingFeeMsatPerBlock, off);
	off += 8;
	buf.writeUInt8(g.feeCollection, off);
	off += 1;
	buf.writeBigUInt64BE(g.creditMsat, off);
	off += 8;
	buf.writeBigUInt64BE(g.issuedAt, off);
	off += 8;
	buf.writeBigUInt64BE(g.expiresAt, off);
	off += 8;
	g.nonce.copy(buf, off);
	off += 32;
	g.witnessProfile.copy(buf, off);
	return buf;
}

/** The digest the LSP signs. */
export function receiverGrantDigest(g: IUnsignedReceiverGrant): Buffer {
	return taggedHash(GRANT_TAG, encodeGrantBody(g));
}

/** Build and sign a grant with the LSP's node private key. */
export function signReceiverGrant(
	fields: Omit<IUnsignedReceiverGrant, 'version'>,
	lspNodePrivkey: Buffer
): IReceiverGrant {
	const unsigned: IUnsignedReceiverGrant = {
		...fields,
		version: RECEIVER_GRANT_VERSION
	};
	const signature = sign(receiverGrantDigest(unsigned), lspNodePrivkey);
	return { ...unsigned, signature };
}

/** Serialize for the wire (body || signature). */
export function encodeReceiverGrant(g: IReceiverGrant): Buffer {
	expectLen(g.signature, SIGNATURE_LEN, 'signature');
	return Buffer.concat([encodeGrantBody(g), g.signature]);
}

/** Parse wire bytes; null when malformed. Does NOT verify the signature. */
export function decodeReceiverGrant(buf: Buffer): IReceiverGrant | null {
	if (buf.length !== GRANT_BODY_LEN + SIGNATURE_LEN) return null;
	let off = 0;
	const version = buf.readUInt8(off);
	off += 1;
	if (version !== RECEIVER_GRANT_VERSION) return null;
	const featureBit = buf.readUInt16BE(off);
	off += 2;
	const serviceFlags = buf.readUInt32BE(off);
	off += 4;
	const chainHash = Buffer.from(buf.subarray(off, off + 32));
	off += 32;
	const receiverNodeId = Buffer.from(buf.subarray(off, off + 33));
	off += 33;
	const lspNodeId = Buffer.from(buf.subarray(off, off + 33));
	off += 33;
	const registrationId = Buffer.from(buf.subarray(off, off + 32));
	off += 32;
	const scid = Buffer.from(buf.subarray(off, off + 8));
	off += 8;
	const maxPartMsat = buf.readBigUInt64BE(off);
	off += 8;
	const maxPaymentMsat = buf.readBigUInt64BE(off);
	off += 8;
	const maxParts = buf.readUInt16BE(off);
	off += 2;
	const maxHeldMsat = buf.readBigUInt64BE(off);
	off += 8;
	const maxHoldBlocks = buf.readUInt16BE(off);
	off += 2;
	const minRemainingCltv = buf.readUInt16BE(off);
	off += 2;
	const admissionFeeMsat = buf.readBigUInt64BE(off);
	off += 8;
	const holdingFeeMsatPerBlock = buf.readBigUInt64BE(off);
	off += 8;
	const feeCollection = buf.readUInt8(off);
	off += 1;
	const creditMsat = buf.readBigUInt64BE(off);
	off += 8;
	const issuedAt = buf.readBigUInt64BE(off);
	off += 8;
	const expiresAt = buf.readBigUInt64BE(off);
	off += 8;
	const nonce = Buffer.from(buf.subarray(off, off + 32));
	off += 32;
	const witnessProfile = Buffer.from(buf.subarray(off, off + 32));
	off += 32;
	const signature = Buffer.from(buf.subarray(off, off + SIGNATURE_LEN));
	return {
		version,
		featureBit,
		serviceFlags,
		chainHash,
		receiverNodeId,
		lspNodeId,
		registrationId,
		scid,
		maxPartMsat,
		maxPaymentMsat,
		maxParts,
		maxHeldMsat,
		maxHoldBlocks,
		minRemainingCltv,
		admissionFeeMsat,
		holdingFeeMsatPerBlock,
		feeCollection,
		creditMsat,
		issuedAt,
		expiresAt,
		nonce,
		witnessProfile,
		signature
	};
}

/**
 * Verify the signature against the LSP identity the grant names. The caller
 * still has to check that identity is the LSP it asked (and the message's
 * authenticated sender); this only proves the named key signed.
 */
export function verifyReceiverGrant(g: IReceiverGrant): boolean {
	if (g.signature.length !== SIGNATURE_LEN) return false;
	try {
		return verify(receiverGrantDigest(g), g.lspNodeId, g.signature);
	} catch {
		return false;
	}
}

/** The holding fee the sender pays for a hold's whole reserved window. */
export function holdingFeeForWindowMsat(g: {
	holdingFeeMsatPerBlock: bigint;
	maxHoldBlocks: number;
}): bigint {
	return g.holdingFeeMsatPerBlock * BigInt(g.maxHoldBlocks);
}

// ─────────────── Reply ───────────────

export function encodeRegistrationReply(reply: IRegistrationReply): Buffer {
	if (reply.granted) {
		return Buffer.concat([Buffer.from([1]), encodeReceiverGrant(reply.grant)]);
	}
	expectLen(reply.nonce, 32, 'nonce');
	const reason = Buffer.from(reply.reason, 'utf8').subarray(0, 200);
	return Buffer.concat([Buffer.from([0]), reply.nonce, reason]);
}

export function decodeRegistrationReply(
	buf: Buffer
): IRegistrationReply | null {
	if (buf.length < 1) return null;
	const status = buf.readUInt8(0);
	if (status === 1) {
		const grant = decodeReceiverGrant(buf.subarray(1));
		return grant ? { granted: true, grant } : null;
	}
	if (status !== 0 || buf.length < 33) return null;
	return {
		granted: false,
		nonce: Buffer.from(buf.subarray(1, 33)),
		reason: buf.subarray(33).toString('utf8')
	};
}
