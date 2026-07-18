/**
 * BOLT 4: Blinded Path Construction and Processing
 *
 * A blinded path consists of:
 *   - introduction_node_id: the first node in the blinded path (known to sender)
 *   - blinding_point: the initial ephemeral blinding key
 *   - blinded_hops: array of { blinded_node_id, encrypted_recipient_data }
 *
 * Each hop's encrypted_recipient_data contains the real next_node_id and
 * (for payment paths) the short_channel_id + fee/cltv parameters.
 */

import {
	deriveBlindingKeyChain,
	computeBlindedNodeId,
	deriveBlindedNodeIdTweak,
	deriveBlindingEncryptionKey,
	encryptBlindedData,
	decryptBlindedData,
	deriveBlindingSharedSecret,
	deriveNextBlindingKey
} from './blinding';
import { privateMultiply, isValidPublicKey } from '../crypto/ecdh';
import { encodeTlvStream, decodeTlvStream } from '../message/tlv';

export interface IBlindedHop {
	/** The blinded (tweaked) node ID */
	blindedNodeId: Buffer;
	/** Encrypted data for this hop */
	encryptedData: Buffer;
}

export interface IBlindedPath {
	/** First node in the blinded portion (public, known to sender) */
	introductionNodeId: Buffer;
	/** Initial blinding point (ephemeral public key) */
	blindingPoint: Buffer;
	/** Blinded hops after the introduction node */
	blindedHops: IBlindedHop[];
}

/** Plaintext content of encrypted_recipient_data for an intermediate blinded hop */
export interface IBlindedHopData {
	/** Next node to forward to (absent for final hop) */
	nextNodeId?: Buffer;
	/** Short channel ID for forwarding */
	shortChannelId?: Buffer;
	/** Fee and CLTV parameters for payment forwarding */
	paymentRelay?: {
		cltvExpiryDelta: number;
		feeProportionalMillionths: number;
		feeBaseMsat: number;
	};
	/** Payment constraints */
	paymentConstraints?: {
		maxCltvExpiry: number;
		htlcMinimumMsat: bigint;
	};
	/**
	 * Async payments: when set on the LSP (introduction) hop, the LSP parks the
	 * HTLC instead of forwarding it to the (offline) recipient, and waits for a
	 * release_held_htlc onion message before forwarding.
	 */
	holdHtlc?: boolean;
	/**
	 * path_id (BOLT 4 encrypted_recipient_data type 6): a private, recipient-
	 * chosen identifier placed in the FINAL hop of a blinded path. The
	 * recipient checks the decrypted path_id matches one it published, proving
	 * the message arrived via the intended path (and not a probe/replay).
	 */
	pathId?: Buffer;
	/** Padding for uniform hop sizes */
	padding?: Buffer;
}

// ── encrypted_recipient_data TLV types (BOLT 4) ─────────────────────
const ERD_PADDING = 1n;
const ERD_SHORT_CHANNEL_ID = 2n;
const ERD_NEXT_NODE_ID = 4n;
const ERD_PATH_ID = 6n;
const ERD_PAYMENT_RELAY = 10n;
const ERD_PAYMENT_CONSTRAINTS = 12n;
/**
 * beignet-custom async-payments hold_htlc marker. Odd, so spec nodes that don't
 * understand it ignore it (async receive only matters when a beignet LSP is the
 * introduction node).
 */
const ERD_HOLD_HTLC = 65537n;

/** Minimal big-endian encoding of a uint (BOLT 1 tu32/tu64); 0 → empty. */
function encodeTruncatedUint(value: bigint): Buffer {
	if (value < 0n) throw new Error('truncated uint must be non-negative');
	if (value === 0n) return Buffer.alloc(0);
	const bytes: number[] = [];
	let v = value;
	while (v > 0n) {
		bytes.unshift(Number(v & 0xffn));
		v >>= 8n;
	}
	return Buffer.from(bytes);
}

/** Decode a minimal big-endian uint (possibly empty → 0). */
function decodeTruncatedUint(buf: Buffer): bigint {
	let v = 0n;
	for (const b of buf) v = (v << 8n) | BigInt(b);
	return v;
}

/**
 * Encode blinded hop data as BOLT 4 encrypted_recipient_data — a TLV stream so
 * LND/CLN can act as the introduction node. Payment paths use short_channel_id
 * (type 2) + payment_relay (10) + payment_constraints (12); onion-message paths
 * use next_node_id (type 4). Records are emitted in strictly increasing order.
 */
export function encodeBlindedHopData(data: IBlindedHopData): Buffer {
	const records: { type: bigint; value: Buffer }[] = [];

	if (data.padding) {
		records.push({ type: ERD_PADDING, value: data.padding });
	}
	if (data.shortChannelId) {
		records.push({ type: ERD_SHORT_CHANNEL_ID, value: data.shortChannelId });
	}
	if (data.nextNodeId) {
		records.push({ type: ERD_NEXT_NODE_ID, value: data.nextNodeId });
	}
	if (data.pathId) {
		records.push({ type: ERD_PATH_ID, value: data.pathId });
	}
	if (data.paymentRelay) {
		const head = Buffer.alloc(6);
		head.writeUInt16BE(data.paymentRelay.cltvExpiryDelta, 0);
		head.writeUInt32BE(data.paymentRelay.feeProportionalMillionths, 2);
		records.push({
			type: ERD_PAYMENT_RELAY,
			value: Buffer.concat([
				head,
				encodeTruncatedUint(BigInt(data.paymentRelay.feeBaseMsat))
			])
		});
	}
	if (data.paymentConstraints) {
		const head = Buffer.alloc(4);
		head.writeUInt32BE(data.paymentConstraints.maxCltvExpiry, 0);
		records.push({
			type: ERD_PAYMENT_CONSTRAINTS,
			value: Buffer.concat([
				head,
				encodeTruncatedUint(data.paymentConstraints.htlcMinimumMsat)
			])
		});
	}
	if (data.holdHtlc) {
		records.push({ type: ERD_HOLD_HTLC, value: Buffer.alloc(0) });
	}

	return encodeTlvStream(records);
}

/**
 * Decode BOLT 4 encrypted_recipient_data. Unknown TLV records are ignored
 * (forward-compatible), as the TLV stream decoder tolerates odd unknown types.
 */
export function decodeBlindedHopData(buf: Buffer): IBlindedHopData {
	const data: IBlindedHopData = {};
	if (buf.length === 0) return data;
	const { records } = decodeTlvStream(buf);

	for (const r of records) {
		if (r.type === ERD_PADDING) {
			data.padding = Buffer.from(r.value);
		} else if (r.type === ERD_SHORT_CHANNEL_ID) {
			data.shortChannelId = Buffer.from(r.value);
		} else if (r.type === ERD_NEXT_NODE_ID) {
			data.nextNodeId = Buffer.from(r.value);
		} else if (r.type === ERD_PATH_ID) {
			data.pathId = Buffer.from(r.value);
		} else if (r.type === ERD_PAYMENT_RELAY) {
			data.paymentRelay = {
				cltvExpiryDelta: r.value.readUInt16BE(0),
				feeProportionalMillionths: r.value.readUInt32BE(2),
				feeBaseMsat: Number(decodeTruncatedUint(r.value.subarray(6)))
			};
		} else if (r.type === ERD_PAYMENT_CONSTRAINTS) {
			data.paymentConstraints = {
				maxCltvExpiry: r.value.readUInt32BE(0),
				htlcMinimumMsat: decodeTruncatedUint(r.value.subarray(4))
			};
		} else if (r.type === ERD_HOLD_HTLC) {
			data.holdHtlc = true;
		}
	}

	return data;
}

/**
 * Construct a blinded path from a sequence of node public keys.
 *
 * @param blindingSecret - 32-byte random secret for the blinding key chain
 * @param nodePubkeys - Array of node public keys in the path (first is introduction node)
 * @param hopDataList - Plaintext data for each hop (same length as nodePubkeys)
 * @returns The blinded path
 */
export function constructBlindedPath(
	blindingSecret: Buffer,
	nodePubkeys: Buffer[],
	hopDataList: IBlindedHopData[]
): IBlindedPath {
	if (nodePubkeys.length === 0) {
		throw new Error('Path must have at least one node');
	}
	if (nodePubkeys.length !== hopDataList.length) {
		throw new Error('Must have same number of nodes and hop data');
	}

	const { blindingKeys, sharedSecrets } = deriveBlindingKeyChain(
		blindingSecret,
		nodePubkeys
	);

	// BOLT 4: pad every hop's encrypted_data to the same length (padding TLV
	// type 1) so the blobs don't leak each hop's role by size. Some
	// implementations (LND) treat unequal lengths as a validation failure.
	// With target = maxLen + 2 every hop fits: the padding TLV costs 2 bytes
	// of overhead plus (target - 2 - baseLen) pad bytes (0 for the largest).
	const basePlaintexts = hopDataList.map((d) => encodeBlindedHopData(d));
	const maxLen = Math.max(...basePlaintexts.map((p) => p.length));
	const paddedPlaintexts = hopDataList.map((d, i) =>
		encodeBlindedHopData({
			...d,
			padding: Buffer.alloc(maxLen - basePlaintexts[i].length)
		})
	);

	const blindedHops: IBlindedHop[] = [];

	for (let i = 0; i < nodePubkeys.length; i++) {
		// Compute blinded node ID
		const blindedNodeId = computeBlindedNodeId(
			nodePubkeys[i],
			sharedSecrets[i]
		);

		// Encrypt hop data
		const encKey = deriveBlindingEncryptionKey(sharedSecrets[i]);
		const encryptedData = encryptBlindedData(encKey, paddedPlaintexts[i]);

		blindedHops.push({ blindedNodeId, encryptedData });
	}

	return {
		introductionNodeId: nodePubkeys[0],
		blindingPoint: blindingKeys[0],
		blindedHops
	};
}

// ── Shared wire serialization ───────────────────────────────────────
//
// These serializers are the single source of truth for putting blinded
// paths on the wire. They are reused by BOLT 12 (offer/tlv.ts) and BOLT 11
// (invoice blinded-paths tagged field) so the byte layout cannot drift
// between the two surfaces.
//
// NOTE: the encrypted_recipient_data blobs themselves use beignet's compact
// encodeBlindedHopData format (above), NOT the BOLT 4 TLV format, so this is
// currently a beignet-to-beignet wire — full LND/CLN interop requires swapping
// encodeBlindedHopData for real BOLT 4 TLVs (tracked as a follow-up).

/** Pay parameters advertised for a blinded payment path (BOLT 4 §payinfo). */
export interface IBlindedPayInfo {
	feeBaseMsat: number;
	feeProportionalMillionths: number;
	cltvExpiryDelta: number;
	htlcMinimumMsat: bigint;
	htlcMaximumMsat: bigint;
	features?: Buffer;
}

/** A blinded path together with the pay parameters to reach the recipient. */
export interface IBlindedPaymentPath {
	path: IBlindedPath;
	payInfo: IBlindedPayInfo;
}

/**
 * Encode a single blinded path (BOLT 4 `blinded_path` subtype):
 *   sciddir_or_pubkey:first_node_id || point(33):first_path_key ||
 *   byte:num_hops || num_hops * [ point(33) || u16:enclen || enc_data ]
 *
 * `introductionNodeId` is a `sciddir_or_pubkey`: 33 bytes when the leading
 * byte is 0x02/0x03 (a node pubkey), 9 bytes when it is 0x00/0x01 (a
 * direction byte + 8-byte short_channel_id referencing node_1/node_2).
 */
export function encodeBlindedPath(path: IBlindedPath): Buffer {
	const first = path.introductionNodeId;
	if (
		!(
			(first.length === 33 && (first[0] === 0x02 || first[0] === 0x03)) ||
			(first.length === 9 && (first[0] === 0x00 || first[0] === 0x01))
		)
	) {
		throw new Error(
			`blinded_path first_node_id is not a valid sciddir_or_pubkey (len=${first.length}, first byte=${first[0]})`
		);
	}
	const parts: Buffer[] = [first, path.blindingPoint];
	const numHops = Buffer.alloc(1);
	numHops[0] = path.blindedHops.length;
	parts.push(numHops);
	for (const hop of path.blindedHops) {
		parts.push(hop.blindedNodeId);
		const lenBuf = Buffer.alloc(2);
		lenBuf.writeUInt16BE(hop.encryptedData.length);
		parts.push(lenBuf);
		parts.push(hop.encryptedData);
	}
	return Buffer.concat(parts);
}

/** Decode a single blinded path starting at `offset`; returns the new offset. */
export function decodeBlindedPath(
	buf: Buffer,
	offset: number
): { path: IBlindedPath; offset: number } {
	// sciddir_or_pubkey: 0x00/0x01 -> 9 bytes (scid+direction), 0x02/0x03 ->
	// 33-byte point. Assuming 33 bytes unconditionally mis-parsed every
	// spec-built path using the scid-dir form (S-4.H4).
	const disc = buf[offset];
	let firstLen: number;
	if (disc === 0x02 || disc === 0x03) {
		firstLen = 33;
	} else if (disc === 0x00 || disc === 0x01) {
		firstLen = 9;
	} else {
		throw new Error(
			`blinded_path first_node_id has invalid sciddir_or_pubkey discriminator ${disc}`
		);
	}
	if (offset + firstLen + 33 + 1 > buf.length) {
		throw new Error('blinded_path truncated');
	}
	const introductionNodeId = Buffer.from(
		buf.subarray(offset, offset + firstLen)
	);
	// BOLT 12: a reader MUST reject invalid points; a 33-byte first_node_id is
	// a pubkey (the 9-byte form is scid+direction, no point to validate).
	if (firstLen === 33 && !isValidPublicKey(introductionNodeId)) {
		throw new Error('blinded_path first_node_id is not a valid point');
	}
	offset += firstLen;
	const blindingPoint = Buffer.from(buf.subarray(offset, offset + 33));
	if (!isValidPublicKey(blindingPoint)) {
		throw new Error('blinded_path path_key is not a valid point');
	}
	offset += 33;
	const numHops = buf[offset++];
	// A path with no hops routes nowhere; BOLT 12 rejects it outright.
	if (numHops === 0) {
		throw new Error('blinded_path has zero hops');
	}
	const blindedHops: IBlindedHop[] = [];
	for (let j = 0; j < numHops; j++) {
		if (offset + 33 + 2 > buf.length) {
			throw new Error('blinded_path truncated at hop');
		}
		const blindedNodeId = Buffer.from(buf.subarray(offset, offset + 33));
		if (!isValidPublicKey(blindedNodeId)) {
			throw new Error('blinded_path blinded_node_id is not a valid point');
		}
		offset += 33;
		const encLen = buf.readUInt16BE(offset);
		offset += 2;
		if (offset + encLen > buf.length) {
			throw new Error('blinded_path truncated at hop encrypted data');
		}
		const encryptedData = Buffer.from(buf.subarray(offset, offset + encLen));
		offset += encLen;
		blindedHops.push({ blindedNodeId, encryptedData });
	}
	return { path: { introductionNodeId, blindingPoint, blindedHops }, offset };
}

/**
 * Encode an array of blinded paths (BOLT 12 `[...*blinded_path]`): the paths
 * are concatenated with NO count prefix — the array fills the TLV length.
 * (The 1-byte count beignet used to add made every offer/invreq/invoice path
 * field unreadable by spec decoders, S-4.H4.)
 */
export function encodeBlindedPaths(paths: IBlindedPath[]): Buffer {
	return Buffer.concat(paths.map(encodeBlindedPath));
}

/** Decode a `[...*blinded_path]` array: paths until the buffer is consumed. */
export function decodeBlindedPaths(buf: Buffer): IBlindedPath[] {
	let offset = 0;
	const paths: IBlindedPath[] = [];
	while (offset < buf.length) {
		const decoded = decodeBlindedPath(buf, offset);
		paths.push(decoded.path);
		offset = decoded.offset;
	}
	return paths;
}

/**
 * Encode one pay-info record (BOLT 12 `blinded_payinfo` subtype):
 *   u32:fee_base_msat || u32:fee_proportional_millionths ||
 *   u16:cltv_expiry_delta || u64:htlc_minimum_msat || u64:htlc_maximum_msat ||
 *   u16:flen || flen*byte:features
 * (beignet used to put the u16 length between htlc_minimum and htlc_maximum
 * and never serialized features — unreadable by spec decoders, S-4.H4.)
 */
export function encodeBlindedPayInfo(info: IBlindedPayInfo): Buffer {
	const features = info.features ?? Buffer.alloc(0);
	const buf = Buffer.alloc(28 + features.length);
	buf.writeUInt32BE(info.feeBaseMsat, 0);
	buf.writeUInt32BE(info.feeProportionalMillionths, 4);
	buf.writeUInt16BE(info.cltvExpiryDelta, 8);
	buf.writeBigUInt64BE(info.htlcMinimumMsat, 10);
	buf.writeBigUInt64BE(info.htlcMaximumMsat, 18);
	buf.writeUInt16BE(features.length, 26);
	features.copy(buf, 28);
	return buf;
}

/** Decode one pay-info record starting at `offset`; returns the new offset. */
export function decodeBlindedPayInfo(
	buf: Buffer,
	offset: number
): { info: IBlindedPayInfo; offset: number } {
	if (offset + 28 > buf.length) {
		throw new Error('blinded_payinfo truncated');
	}
	const feeBaseMsat = buf.readUInt32BE(offset);
	const feeProportionalMillionths = buf.readUInt32BE(offset + 4);
	const cltvExpiryDelta = buf.readUInt16BE(offset + 8);
	const htlcMinimumMsat = buf.readBigUInt64BE(offset + 10);
	const htlcMaximumMsat = buf.readBigUInt64BE(offset + 18);
	const flen = buf.readUInt16BE(offset + 26);
	if (offset + 28 + flen > buf.length) {
		throw new Error('blinded_payinfo truncated at features');
	}
	const features = Buffer.from(buf.subarray(offset + 28, offset + 28 + flen));
	const info: IBlindedPayInfo = {
		feeBaseMsat,
		feeProportionalMillionths,
		cltvExpiryDelta,
		htlcMinimumMsat,
		htlcMaximumMsat
	};
	if (flen > 0) info.features = features;
	return { info, offset: offset + 28 + flen };
}

/**
 * Encode a `[...*blinded_payinfo]` array: records concatenated with NO count
 * prefix — the array fills the TLV length (BOLT 12).
 */
export function encodeBlindedPayInfos(infos: IBlindedPayInfo[]): Buffer {
	return Buffer.concat(infos.map(encodeBlindedPayInfo));
}

/** Decode a `[...*blinded_payinfo]` array: records until the buffer ends. */
export function decodeBlindedPayInfos(buf: Buffer): IBlindedPayInfo[] {
	let offset = 0;
	const infos: IBlindedPayInfo[] = [];
	while (offset < buf.length) {
		const decoded = decodeBlindedPayInfo(buf, offset);
		infos.push(decoded.info);
		offset = decoded.offset;
	}
	return infos;
}

/**
 * Encode blinded payment paths for a BOLT 11 invoice tagged field (a
 * beignet-specific tag-25 extension, NOT a spec format): each entry is a
 * self-delimiting blinded path immediately followed by its (variable-length)
 * pay info, prefixed by the entry count.
 *   num(1) || [ blinded_path || pay_info ] ...
 */
export function encodeInvoiceBlindedPaymentPaths(
	entries: IBlindedPaymentPath[]
): Buffer {
	const num = Buffer.alloc(1);
	num[0] = entries.length;
	const parts: Buffer[] = [num];
	for (const entry of entries) {
		parts.push(encodeBlindedPath(entry.path));
		parts.push(encodeBlindedPayInfo(entry.payInfo));
	}
	return Buffer.concat(parts);
}

/** Decode blinded payment paths produced by encodeInvoiceBlindedPaymentPaths. */
export function decodeInvoiceBlindedPaymentPaths(
	buf: Buffer
): IBlindedPaymentPath[] {
	let offset = 0;
	const num = buf[offset++];
	const entries: IBlindedPaymentPath[] = [];
	for (let i = 0; i < num; i++) {
		const p = decodeBlindedPath(buf, offset);
		offset = p.offset;
		const info = decodeBlindedPayInfo(buf, offset);
		offset = info.offset;
		entries.push({ path: p.path, payInfo: info.info });
	}
	return entries;
}

/**
 * Process a blinded hop: decrypt the encrypted data and derive the next blinding key.
 *
 * @param blindingKey - The current blinding point (ephemeral pubkey)
 * @param nodePrivkey - This node's private key
 * @param encryptedData - The encrypted recipient data for this hop
 * @returns Decrypted hop data and next blinding key
 */
export function processBlindedHop(
	blindingKey: Buffer,
	nodePrivkey: Buffer,
	encryptedData: Buffer
): { hopData: IBlindedHopData; nextBlindingKey: Buffer } {
	// Derive shared secret
	const sharedSecret = deriveBlindingSharedSecret(blindingKey, nodePrivkey);

	// Derive encryption key and decrypt
	const encKey = deriveBlindingEncryptionKey(sharedSecret);
	const plaintext = decryptBlindedData(encKey, encryptedData);

	// Decode hop data
	const hopData = decodeBlindedHopData(plaintext);

	// Derive next blinding key
	const nextBlindingKey = deriveNextBlindingKey(blindingKey, sharedSecret);

	return { hopData, nextBlindingKey };
}

/**
 * Derive a blinded hop's blinded private key, given the blinding point it
 * received. The sender encrypted this hop's onion layer to its blinded node id
 * (node_pubkey * tweak), so the hop must peel the onion with the matching
 * blinded private key (node_privkey * tweak), where tweak = HMAC-SHA256(
 * "blinded_node_id", ECDH(blinding_point, node_privkey)).
 */
export function deriveBlindedPrivkey(
	blindingPoint: Buffer,
	nodePrivkey: Buffer
): Buffer {
	const sharedSecret = deriveBlindingSharedSecret(blindingPoint, nodePrivkey);
	// Same tweak as computeBlindedNodeId (HMAC "blinded_node_id"), NOT the rho
	// encryption key — so getPublicKey(blindedPrivkey) == the blinded node id.
	const tweak = deriveBlindedNodeIdTweak(sharedSecret);
	return privateMultiply(nodePrivkey, tweak);
}
