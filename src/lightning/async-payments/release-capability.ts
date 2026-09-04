/**
 * Release capability for LSP-held async forwards (issue #708).
 *
 * The receiver authorizes the release of parked HTLCs by signing, with its
 * node key, a domain-separated digest over everything the authorization
 * must be bound to. The holding LSP verifies the signature against the
 * receiver identity the HOLD recorded (the peer on the outgoing channel),
 * and additionally checks that the onion message carrying the capability
 * arrived from that same peer.
 *
 * Construction (all integers big-endian):
 *
 *   body =
 *     version           u8   (1)
 *     chain_hash        32   network domain
 *     receiver_node_id  33   who signs, and who the hold is for
 *     lsp_node_id       33   the holding LSP; a capability for one LSP is
 *                            meaningless at another
 *     registration_id   32   the blinded-path / service registration the
 *                            hold was parked under (blinded-path marker)
 *     amount_msat       u64  exact sum of the named parts' forward amounts
 *     expires_at        u64  unix seconds after which the LSP refuses it
 *     nonce             32   random; the replay domain together with the
 *                            hold ids (a hold moves once, so a replayed
 *                            capability is a no-op, and a capability for
 *                            other holds names other ids)
 *     count             u16  number of hold ids
 *     hold_ids          count * 32, sorted ascending (canonical order)
 *
 *   digest = SHA256(SHA256(tag) || SHA256(tag) || body)
 *            tag = "beignet/async-payments/release-capability/v1"
 *   signature = ECDSA(receiver node key, digest), 64-byte compact
 *   wire = body || signature
 *
 * The hold ids are the complete set this capability releases. The LSP
 * releases them atomically (all in HELD, or nothing moves), which is the
 * atomic payment-set policy; a set of one is an independent part release.
 */

import crypto from 'crypto';
import { sign, verify } from '../crypto/ecdh';

export const RELEASE_CAPABILITY_VERSION = 1;
const CAPABILITY_TAG = 'beignet/async-payments/release-capability/v1';
const REGISTRATION_TAG = 'beignet/async-payments/hold-registration/v1';

const FIXED_BODY_LEN = 1 + 32 + 33 + 33 + 32 + 8 + 8 + 32 + 2;
const SIGNATURE_LEN = 64;

export interface IReleaseCapability {
	version: number;
	chainHash: Buffer;
	receiverNodeId: Buffer;
	lspNodeId: Buffer;
	registrationId: Buffer;
	amountMsat: bigint;
	/** Unix seconds. */
	expiresAt: bigint;
	nonce: Buffer;
	/** Sorted ascending; the complete set the capability releases. */
	holdIds: Buffer[];
	signature: Buffer;
}

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

/**
 * The registration identifier a receiver stamps into the hold_htlc marker
 * of its blinded payment paths, and that the LSP records on every hold it
 * parks. Derived, not stored, so a receiver can recompute it when it signs:
 * it binds a hold to the (receiver, LSP) pair the path was built for. A
 * later service registration (issue #709) replaces this derivation with the
 * registered identifier; the capability layout does not change.
 */
export function deriveHoldRegistrationId(
	receiverNodeId: Buffer,
	lspNodeId: Buffer
): Buffer {
	return taggedHash(
		REGISTRATION_TAG,
		Buffer.concat([receiverNodeId, lspNodeId])
	);
}

function sortHoldIds(holdIds: Buffer[]): Buffer[] {
	return [...holdIds].sort((a, b) => Buffer.compare(a, b));
}

function encodeBody(cap: Omit<IReleaseCapability, 'signature'>): Buffer {
	if (cap.chainHash.length !== 32)
		throw new Error('chain hash must be 32 bytes');
	if (cap.receiverNodeId.length !== 33) {
		throw new Error('receiver node id must be 33 bytes');
	}
	if (cap.lspNodeId.length !== 33)
		throw new Error('lsp node id must be 33 bytes');
	if (cap.registrationId.length !== 32) {
		throw new Error('registration id must be 32 bytes');
	}
	if (cap.nonce.length !== 32) throw new Error('nonce must be 32 bytes');
	if (cap.holdIds.length === 0 || cap.holdIds.length > 0xffff) {
		throw new Error('capability must name between 1 and 65535 holds');
	}
	const head = Buffer.alloc(FIXED_BODY_LEN);
	let off = 0;
	head.writeUInt8(cap.version, off);
	off += 1;
	cap.chainHash.copy(head, off);
	off += 32;
	cap.receiverNodeId.copy(head, off);
	off += 33;
	cap.lspNodeId.copy(head, off);
	off += 33;
	cap.registrationId.copy(head, off);
	off += 32;
	head.writeBigUInt64BE(cap.amountMsat, off);
	off += 8;
	head.writeBigUInt64BE(cap.expiresAt, off);
	off += 8;
	cap.nonce.copy(head, off);
	off += 32;
	head.writeUInt16BE(cap.holdIds.length, off);
	const ids = sortHoldIds(cap.holdIds);
	for (const id of ids) {
		if (id.length !== 32) throw new Error('hold id must be 32 bytes');
	}
	return Buffer.concat([head, ...ids]);
}

/** The digest the receiver signs. */
export function releaseCapabilityDigest(
	cap: Omit<IReleaseCapability, 'signature'>
): Buffer {
	return taggedHash(CAPABILITY_TAG, encodeBody(cap));
}

/** Build and sign a capability with the receiver's node private key. */
export function signReleaseCapability(
	fields: Omit<IReleaseCapability, 'signature' | 'version' | 'holdIds'> & {
		holdIds: Buffer[];
	},
	receiverNodePrivkey: Buffer
): IReleaseCapability {
	const unsigned = {
		...fields,
		version: RELEASE_CAPABILITY_VERSION,
		holdIds: sortHoldIds(fields.holdIds)
	};
	const signature = sign(
		releaseCapabilityDigest(unsigned),
		receiverNodePrivkey
	);
	return { ...unsigned, signature };
}

/** Serialize for the wire (body || signature). */
export function encodeReleaseCapability(cap: IReleaseCapability): Buffer {
	if (cap.signature.length !== SIGNATURE_LEN) {
		throw new Error('signature must be 64 bytes');
	}
	return Buffer.concat([encodeBody(cap), cap.signature]);
}

/** Parse wire bytes; null when malformed. Does NOT verify the signature. */
export function decodeReleaseCapability(
	buf: Buffer
): IReleaseCapability | null {
	if (buf.length < FIXED_BODY_LEN + SIGNATURE_LEN) return null;
	let off = 0;
	const version = buf.readUInt8(off);
	off += 1;
	if (version !== RELEASE_CAPABILITY_VERSION) return null;
	const chainHash = Buffer.from(buf.subarray(off, off + 32));
	off += 32;
	const receiverNodeId = Buffer.from(buf.subarray(off, off + 33));
	off += 33;
	const lspNodeId = Buffer.from(buf.subarray(off, off + 33));
	off += 33;
	const registrationId = Buffer.from(buf.subarray(off, off + 32));
	off += 32;
	const amountMsat = buf.readBigUInt64BE(off);
	off += 8;
	const expiresAt = buf.readBigUInt64BE(off);
	off += 8;
	const nonce = Buffer.from(buf.subarray(off, off + 32));
	off += 32;
	const count = buf.readUInt16BE(off);
	off += 2;
	if (count === 0) return null;
	if (buf.length !== off + count * 32 + SIGNATURE_LEN) return null;
	const holdIds: Buffer[] = [];
	for (let i = 0; i < count; i++) {
		holdIds.push(Buffer.from(buf.subarray(off, off + 32)));
		off += 32;
	}
	// Canonical order is part of what was signed; an unsorted or duplicated
	// list is a different message and does not decode.
	for (let i = 1; i < holdIds.length; i++) {
		if (Buffer.compare(holdIds[i - 1], holdIds[i]) >= 0) return null;
	}
	const signature = Buffer.from(buf.subarray(off, off + SIGNATURE_LEN));
	return {
		version,
		chainHash,
		receiverNodeId,
		lspNodeId,
		registrationId,
		amountMsat,
		expiresAt,
		nonce,
		holdIds,
		signature
	};
}

/**
 * Verify the signature against the receiver identity the capability names.
 * The caller still has to check that identity is the one the HOLD recorded
 * and the one the message came from; this only proves the named key signed.
 */
export function verifyReleaseCapability(cap: IReleaseCapability): boolean {
	if (cap.signature.length !== SIGNATURE_LEN) return false;
	try {
		return verify(
			releaseCapabilityDigest(cap),
			cap.receiverNodeId,
			cap.signature
		);
	} catch {
		return false;
	}
}
