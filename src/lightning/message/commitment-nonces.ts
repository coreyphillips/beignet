import { MAX_LIGHTNING_PAYLOAD } from './custom-records';
import type { ITlvRecord } from './tlv';

/** Verification nonce for a commitment spending a specific funding transaction. */
export interface IFundingVerificationNonce {
	/** 32-byte funding txid in wire order (tx.getHash()). */
	fundingTxid: Buffer;
	/** 66-byte MuSig2 public nonce. */
	nonce: Buffer;
}

export interface ICommitmentNonceDecodeOptions {
	/** Read the final Taproot nonce records for a channel using that format. */
	finalTaproot?: boolean;
}

export const TLV_NEXT_LOCAL_NONCES = 22n;
const ENTRY_LENGTH = 32 + 66;

function checkFundingTxid(seen: Set<string>, fundingTxid: Buffer): void {
	const key = fundingTxid.toString('hex');
	if (seen.has(key))
		throw new Error('Duplicate funding txid in next_local_nonces');
	seen.add(key);
}

export function encodeNextLocalNonces(
	entries: IFundingVerificationNonce[]
): ITlvRecord {
	if (
		entries.length === 0 ||
		entries.length * ENTRY_LENGTH > MAX_LIGHTNING_PAYLOAD
	) {
		throw new Error('Invalid next_local_nonces entry count');
	}
	const seen = new Set<string>();
	const value = Buffer.alloc(entries.length * ENTRY_LENGTH);
	for (const [index, { fundingTxid, nonce }] of entries.entries()) {
		if (
			!Buffer.isBuffer(fundingTxid) ||
			fundingTxid.length !== 32 ||
			!Buffer.isBuffer(nonce) ||
			nonce.length !== 66
		) {
			throw new Error(
				'next_local_nonces requires a 32-byte funding txid and a 66-byte nonce'
			);
		}
		checkFundingTxid(seen, fundingTxid);
		fundingTxid.copy(value, index * ENTRY_LENGTH);
		nonce.copy(value, index * ENTRY_LENGTH + 32);
	}
	return { type: TLV_NEXT_LOCAL_NONCES, value };
}

export function decodeNextLocalNonces(
	value: Buffer
): IFundingVerificationNonce[] {
	if (!value.length || value.length % ENTRY_LENGTH !== 0)
		throw new Error(
			'next_local_nonces must contain complete funding txid and nonce pairs'
		);
	const seen = new Set<string>();
	const entries: IFundingVerificationNonce[] = [];
	for (let offset = 0; offset < value.length; offset += ENTRY_LENGTH) {
		const fundingTxid = value.subarray(offset, offset + 32);
		checkFundingTxid(seen, fundingTxid);
		entries.push({
			fundingTxid,
			nonce: value.subarray(offset + 32, offset + ENTRY_LENGTH)
		});
	}
	return entries;
}
