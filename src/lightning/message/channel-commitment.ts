/**
 * BOLT 2: `commitment_signed` and `revoke_and_ack` message encoding/decoding.
 *
 * commitment_signed (type 132):
 *   [32: channel_id]
 *   [64: signature]
 *   [2: num_htlcs]
 *   [num_htlcs * 64: htlc_signature]
 *   commitment_signed_tlvs:
 *     type 1 (splice_info): [32: funding_txid]
 *
 * Splicing (lightning/bolts #1160, CLN-compatible): during a splice the sender
 * MUST set the `funding_txid` (TLV type 1) to the funding transaction the
 * commitment spends, so the receiver can route it to the right (old vs spliced)
 * funding output. txid is internal byte order (tx.getHash(), CLN
 * `towire_bitcoin_txid`).
 *
 * revoke_and_ack (type 133):
 *   [32: channel_id]
 *   [32: per_commitment_secret]
 *   [33: next_per_commitment_point]
 */

import { encodeTlvStream, decodeTlvStream, ITlvRecord } from './tlv';

export interface ICommitmentSignedMessage {
	channelId: Buffer;
	signature: Buffer;
	htlcSignatures: Buffer[];
	/** Splice: the funding txid this commitment spends (TLV type 1, internal order). */
	fundingTxid?: Buffer;
	/**
	 * option_taproot: the signer's 98-byte partial_signature_with_nonce (32-byte
	 * MuSig2 partial signature || 66-byte public nonce) over the recipient's
	 * commitment. Replaces the ECDSA `signature` field for taproot channels (which
	 * is then all-zero). TLV type 2 (LND convention; pin at interop).
	 */
	partialSignatureWithNonce?: Buffer;
}

const TLV_SPLICE_INFO = 1n;
const TLV_PARTIAL_SIG_WITH_NONCE = 2n;
/** option_taproot: next per-commitment verification nonce in revoke_and_ack. */
const TLV_NEXT_LOCAL_NONCE = 4n;

export interface IRevokeAndAckMessage {
	channelId: Buffer;
	perCommitmentSecret: Buffer;
	nextPerCommitmentPoint: Buffer;
	/**
	 * option_taproot: our 66-byte MuSig2 public nonce for the NEXT commitment
	 * (rotate-on-revoke). The previous nonce is now spent. TLV type 4.
	 */
	nextLocalNonce?: Buffer;
}

const COMMITMENT_SIGNED_FIXED_LENGTH = 98; // 32 + 64 + 2
const REVOKE_AND_ACK_LENGTH = 97; // 32 + 32 + 33

/**
 * Encode a `commitment_signed` message payload.
 */
export function encodeCommitmentSignedMessage(
	msg: ICommitmentSignedMessage
): Buffer {
	const numHtlcs = msg.htlcSignatures.length;
	const buf = Buffer.alloc(COMMITMENT_SIGNED_FIXED_LENGTH + numHtlcs * 64);
	let offset = 0;

	msg.channelId.copy(buf, offset);
	offset += 32;
	msg.signature.copy(buf, offset);
	offset += 64;
	buf.writeUInt16BE(numHtlcs, offset);
	offset += 2;

	for (const sig of msg.htlcSignatures) {
		sig.copy(buf, offset);
		offset += 64;
	}

	// Append optional TLVs (splice funding_txid type 1; taproot partial sig type 2).
	const records: ITlvRecord[] = [];
	if (msg.fundingTxid) {
		if (msg.fundingTxid.length !== 32) {
			throw new Error(
				`commitment_signed funding_txid must be 32 bytes, got ${msg.fundingTxid.length}`
			);
		}
		records.push({ type: TLV_SPLICE_INFO, value: msg.fundingTxid });
	}
	if (msg.partialSignatureWithNonce) {
		if (msg.partialSignatureWithNonce.length !== 98) {
			throw new Error(
				`partial_signature_with_nonce must be 98 bytes, got ${msg.partialSignatureWithNonce.length}`
			);
		}
		records.push({
			type: TLV_PARTIAL_SIG_WITH_NONCE,
			value: msg.partialSignatureWithNonce
		});
	}
	if (records.length > 0) {
		// TLV records must be in ascending type order.
		records.sort((a, b) => (a.type < b.type ? -1 : 1));
		return Buffer.concat([buf, encodeTlvStream(records)]);
	}

	return buf;
}

/**
 * Decode a `commitment_signed` message payload.
 */
export function decodeCommitmentSignedMessage(
	payload: Buffer
): ICommitmentSignedMessage {
	if (payload.length < COMMITMENT_SIGNED_FIXED_LENGTH) {
		throw new Error(
			`commitment_signed too short: need ${COMMITMENT_SIGNED_FIXED_LENGTH} bytes, got ${payload.length}`
		);
	}

	let offset = 0;

	const channelId = Buffer.from(payload.subarray(offset, offset + 32));
	offset += 32;
	const signature = Buffer.from(payload.subarray(offset, offset + 64));
	offset += 64;
	const numHtlcs = payload.readUInt16BE(offset);
	offset += 2;

	const expectedLength = COMMITMENT_SIGNED_FIXED_LENGTH + numHtlcs * 64;
	if (payload.length < expectedLength) {
		throw new Error(
			`commitment_signed too short for ${numHtlcs} HTLCs: need ${expectedLength} bytes, got ${payload.length}`
		);
	}

	const htlcSignatures: Buffer[] = [];
	for (let i = 0; i < numHtlcs; i++) {
		htlcSignatures.push(Buffer.from(payload.subarray(offset, offset + 64)));
		offset += 64;
	}

	// Parse optional TLVs: splice funding_txid (1), taproot partial sig (2).
	let fundingTxid: Buffer | undefined;
	let partialSignatureWithNonce: Buffer | undefined;
	if (offset < payload.length) {
		const { records } = decodeTlvStream(payload, offset);
		for (const record of records) {
			if (record.type === TLV_SPLICE_INFO && record.value.length === 32) {
				fundingTxid = Buffer.from(record.value);
			} else if (
				record.type === TLV_PARTIAL_SIG_WITH_NONCE &&
				record.value.length === 98
			) {
				partialSignatureWithNonce = Buffer.from(record.value);
			}
		}
	}

	return {
		channelId,
		signature,
		htlcSignatures,
		fundingTxid,
		partialSignatureWithNonce
	};
}

/**
 * Encode a `revoke_and_ack` message payload.
 */
export function encodeRevokeAndAckMessage(msg: IRevokeAndAckMessage): Buffer {
	const buf = Buffer.alloc(REVOKE_AND_ACK_LENGTH);
	msg.channelId.copy(buf, 0);
	msg.perCommitmentSecret.copy(buf, 32);
	msg.nextPerCommitmentPoint.copy(buf, 64);

	// option_taproot: append the next verification nonce (TLV type 4).
	if (msg.nextLocalNonce) {
		if (msg.nextLocalNonce.length !== 66) {
			throw new Error(
				`revoke_and_ack next_local_nonce must be 66 bytes, got ${msg.nextLocalNonce.length}`
			);
		}
		return Buffer.concat([
			buf,
			encodeTlvStream([
				{ type: TLV_NEXT_LOCAL_NONCE, value: msg.nextLocalNonce }
			])
		]);
	}
	return buf;
}

/**
 * Decode a `revoke_and_ack` message payload.
 */
export function decodeRevokeAndAckMessage(
	payload: Buffer
): IRevokeAndAckMessage {
	if (payload.length < REVOKE_AND_ACK_LENGTH) {
		throw new Error(
			`revoke_and_ack too short: need ${REVOKE_AND_ACK_LENGTH} bytes, got ${payload.length}`
		);
	}

	const channelId = Buffer.from(payload.subarray(0, 32));
	const perCommitmentSecret = Buffer.from(payload.subarray(32, 64));
	const nextPerCommitmentPoint = Buffer.from(payload.subarray(64, 97));

	// option_taproot: parse the optional next_local_nonce TLV (type 4).
	let nextLocalNonce: Buffer | undefined;
	if (payload.length > REVOKE_AND_ACK_LENGTH) {
		const { records } = decodeTlvStream(payload, REVOKE_AND_ACK_LENGTH);
		for (const record of records) {
			if (record.type === TLV_NEXT_LOCAL_NONCE && record.value.length === 66) {
				nextLocalNonce = Buffer.from(record.value);
			}
		}
	}

	return {
		channelId,
		perCommitmentSecret,
		nextPerCommitmentPoint,
		nextLocalNonce
	};
}
