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

import {
	type ICommitmentNonceDecodeOptions,
	type IFundingVerificationNonce,
	decodeNextLocalNonces,
	encodeNextLocalNonces,
	TLV_NEXT_LOCAL_NONCES
} from './commitment-nonces';
import type { ITlvRecord } from './tlv';
import type { CustomRecords } from './custom-records';
import {
	boundedLightningPayload,
	customRecordEntries,
	decodeWithCustomRecords
} from './custom-records';
import { encodeTlvStream, decodeTlvStream } from './tlv';

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
	/**
	 * Asset channels only: the provider's signatures over the asset side of
	 * the commitment, as custom records (types at or above 65536).
	 */
	customRecords?: CustomRecords;
}

/** How to read a commitment_signed. */
export interface ICommitmentSignedDecodeOptions {
	/**
	 * Read custom records instead of rejecting an unknown even type at or
	 * above 65536. Set only for a channel with asset state; the default is
	 * the standard reading.
	 */
	customRecords?: boolean;
}

const TLV_SPLICE_INFO = 1n;
const TLV_PARTIAL_SIG_WITH_NONCE = 2n;
/** option_taproot: next per-commitment verification nonce in revoke_and_ack. */
const TLV_NEXT_LOCAL_NONCE = 4n;
const COMMITMENT_SIGNED_TLV_TYPES = new Set<bigint>([
	TLV_SPLICE_INFO,
	TLV_PARTIAL_SIG_WITH_NONCE
]);
const FINAL_REVOKE_AND_ACK_TLV_TYPES = new Set([TLV_NEXT_LOCAL_NONCES]);
const REVOKE_AND_ACK_TLV_TYPES = new Set<bigint>([TLV_NEXT_LOCAL_NONCE]);

export interface IRevokeAndAckMessage {
	channelId: Buffer;
	perCommitmentSecret: Buffer;
	nextPerCommitmentPoint: Buffer;
	/**
	 * option_taproot: our 66-byte MuSig2 public nonce for the NEXT commitment
	 * (rotate-on-revoke). The previous nonce is now spent. TLV type 4.
	 */
	nextLocalNonce?: Buffer;
	/** Final Taproot verification nonces keyed by funding txid (TLV 22). */
	nextLocalNonces?: IFundingVerificationNonce[];
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
	const records: ITlvRecord[] = customRecordEntries(msg.customRecords);
	const hasCustomRecords = records.length > 0;
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
		const payload = Buffer.concat([buf, encodeTlvStream(records)]);
		// Custom records are the one part of this message with no fixed size.
		return hasCustomRecords ? boundedLightningPayload(payload) : payload;
	}

	return buf;
}

/**
 * Decode a `commitment_signed` message payload.
 */
export function decodeCommitmentSignedMessage(
	payload: Buffer,
	options: ICommitmentSignedDecodeOptions = {}
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
	const customRecords = new Map<bigint, Buffer>();
	if (offset < payload.length) {
		const records = options.customRecords
			? decodeWithCustomRecords(payload, offset, COMMITMENT_SIGNED_TLV_TYPES)
			: decodeTlvStream(payload, offset, COMMITMENT_SIGNED_TLV_TYPES).records;
		for (const record of records) {
			if (record.type === TLV_SPLICE_INFO && record.value.length === 32) {
				fundingTxid = Buffer.from(record.value);
			} else if (
				record.type === TLV_PARTIAL_SIG_WITH_NONCE &&
				record.value.length === 98
			) {
				partialSignatureWithNonce = Buffer.from(record.value);
			} else if (options.customRecords && record.type >= 65536n) {
				customRecords.set(record.type, Buffer.from(record.value));
			}
		}
	}

	return {
		channelId,
		signature,
		htlcSignatures,
		fundingTxid,
		partialSignatureWithNonce,
		...(customRecords.size > 0 ? { customRecords } : {})
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

	if (msg.nextLocalNonces !== undefined) {
		if (msg.nextLocalNonce !== undefined)
			throw new Error('Cannot mix staging and final Taproot nonce records');
		const nonces = encodeNextLocalNonces(msg.nextLocalNonces);
		return boundedLightningPayload(
			Buffer.concat([buf, encodeTlvStream([nonces])])
		);
	}

	// Staging uses one verification nonce (TLV type 4).
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
	payload: Buffer,
	options: ICommitmentNonceDecodeOptions = {}
): IRevokeAndAckMessage {
	if (options.finalTaproot) boundedLightningPayload(payload);
	if (payload.length < REVOKE_AND_ACK_LENGTH) {
		throw new Error(
			`revoke_and_ack too short: need ${REVOKE_AND_ACK_LENGTH} bytes, got ${payload.length}`
		);
	}

	const channelId = Buffer.from(payload.subarray(0, 32));
	const perCommitmentSecret = Buffer.from(payload.subarray(32, 64));
	const nextPerCommitmentPoint = Buffer.from(payload.subarray(64, 97));

	let nextLocalNonces: IFundingVerificationNonce[] | undefined;
	let nextLocalNonce: Buffer | undefined;
	if (payload.length > REVOKE_AND_ACK_LENGTH) {
		const { records } = decodeTlvStream(
			payload,
			REVOKE_AND_ACK_LENGTH,
			options.finalTaproot
				? FINAL_REVOKE_AND_ACK_TLV_TYPES
				: REVOKE_AND_ACK_TLV_TYPES
		);
		for (const record of records) {
			if (record.type === TLV_NEXT_LOCAL_NONCE && record.value.length === 66) {
				nextLocalNonce = Buffer.from(record.value);
			} else if (record.type === TLV_NEXT_LOCAL_NONCES) {
				nextLocalNonces = decodeNextLocalNonces(record.value);
			}
		}
	}

	if (options.finalTaproot && !nextLocalNonces) {
		throw new Error('Final revoke_and_ack requires next_local_nonces');
	}

	return {
		channelId,
		perCommitmentSecret,
		nextPerCommitmentPoint,
		nextLocalNonce,
		...(nextLocalNonces && { nextLocalNonces })
	};
}
