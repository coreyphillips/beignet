/**
 * BOLT 3: Channel signing operations.
 *
 * Signs commitment transactions, HTLC transactions, and closing
 * transactions for Lightning channels.
 */

import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { sign, verify, getPublicKey } from '../crypto/ecdh';
import { partialSign, type SessionKey } from '../crypto/musig';

bitcoin.initEccLib(ecc);

/**
 * Encode a 64-byte compact signature to DER format.
 */
function toDer(sig: Buffer): Buffer {
	if (sig.length !== 64) {
		throw new Error(`Signature must be 64 bytes, got ${sig.length}`);
	}

	const r = sig.subarray(0, 32);
	const s = sig.subarray(32, 64);

	function encodeInt(val: Buffer): Buffer {
		let v = val;
		let start = 0;
		while (start < v.length - 1 && v[start] === 0) start++;
		v = v.subarray(start);
		if (v[0] & 0x80) {
			v = Buffer.concat([Buffer.from([0x00]), v]);
		}
		return Buffer.concat([Buffer.from([0x02, v.length]), v]);
	}

	const rDer = encodeInt(r);
	const sDer = encodeInt(s);

	return Buffer.concat([
		Buffer.from([0x30, rDer.length + sDer.length]),
		rDer,
		sDer
	]);
}

/**
 * Handles signing operations for a Lightning channel.
 */
export class ChannelSigner {
	private fundingPrivkey: Buffer;
	readonly fundingPubkey: Buffer;
	private _htlcBasepointSecret: Buffer | undefined;

	constructor(fundingPrivkey: Buffer, htlcBasepointSecret?: Buffer) {
		if (fundingPrivkey.length !== 32) {
			throw new Error(
				`Funding private key must be 32 bytes, got ${fundingPrivkey.length}`
			);
		}
		if (
			htlcBasepointSecret !== undefined &&
			htlcBasepointSecret.length !== 32
		) {
			throw new Error(
				`HTLC basepoint secret must be 32 bytes, got ${htlcBasepointSecret.length}`
			);
		}
		this.fundingPrivkey = fundingPrivkey;
		this.fundingPubkey = getPublicKey(fundingPrivkey);
		this._htlcBasepointSecret = htlcBasepointSecret;
	}

	get htlcBasepointSecret(): Buffer | undefined {
		return this._htlcBasepointSecret;
	}

	/**
	 * Sign an arbitrary 32-byte digest with the funding private key.
	 *
	 * Used for the splice shared (2-of-2 funding) input, whose sighash is
	 * computed by the caller. Returns a 64-byte compact signature.
	 */
	signFundingDigest(digest: Buffer): Buffer {
		if (digest.length !== 32) {
			throw new Error(`Digest must be 32 bytes, got ${digest.length}`);
		}
		return sign(digest, this.fundingPrivkey);
	}

	/**
	 * option_taproot: produce a MuSig2 partial signature over a commitment (or
	 * closing) transaction with the funding key, for a signing session already
	 * derived by the caller. The funding private key never leaves the signer.
	 *
	 * NONCE SAFETY (catastrophic if violated): `ourPublicNonce` MUST be the exact
	 * single-use object returned by generateNonce for this session and must never
	 * be reused for another sighash — the caller (channel state machine) owns that
	 * lifecycle. Returns a 32-byte partial signature.
	 */
	signCommitmentPartial(
		session: SessionKey,
		ourPublicNonce: Uint8Array
	): Buffer {
		return partialSign({
			secretKey: this.fundingPrivkey,
			publicNonce: ourPublicNonce,
			sessionKey: session
		});
	}

	/**
	 * Sign a commitment transaction.
	 * Signs the funding input with the funding key for the 2-of-2 multisig.
	 *
	 * @param tx - The commitment transaction
	 * @param fundingWitnessScript - The 2-of-2 multisig witness script
	 * @param fundingAmount - The funding output value in satoshis
	 * @returns 64-byte compact signature
	 */
	signCommitmentTx(
		tx: bitcoin.Transaction,
		fundingWitnessScript: Buffer,
		fundingAmount: number
	): Buffer {
		const sigHash = tx.hashForWitnessV0(
			0,
			fundingWitnessScript,
			fundingAmount,
			bitcoin.Transaction.SIGHASH_ALL
		);
		return sign(sigHash, this.fundingPrivkey);
	}

	/**
	 * Sign an HTLC transaction (HTLC-success or HTLC-timeout).
	 *
	 * @param tx - The HTLC transaction
	 * @param htlcWitnessScript - The HTLC witness script
	 * @param htlcAmount - The HTLC output value in satoshis
	 * @param htlcPrivkey - The HTLC private key for this commitment
	 * @param useAnchorSighash - If true, use SIGHASH_SINGLE|SIGHASH_ANYONECANPAY (BOLT 3 anchors)
	 * @returns 64-byte compact signature
	 */
	signHtlcTx(
		tx: bitcoin.Transaction,
		htlcWitnessScript: Buffer,
		htlcAmount: number,
		htlcPrivkey: Buffer,
		useAnchorSighash?: boolean
	): Buffer {
		const sighashType = useAnchorSighash
			? bitcoin.Transaction.SIGHASH_SINGLE |
			  bitcoin.Transaction.SIGHASH_ANYONECANPAY
			: bitcoin.Transaction.SIGHASH_ALL;
		const sigHash = tx.hashForWitnessV0(
			0,
			htlcWitnessScript,
			htlcAmount,
			sighashType
		);
		return sign(sigHash, htlcPrivkey);
	}

	/**
	 * Sign a cooperative closing transaction.
	 *
	 * @param tx - The closing transaction
	 * @param fundingWitnessScript - The 2-of-2 multisig witness script
	 * @param fundingAmount - The funding output value in satoshis
	 * @returns 64-byte compact signature
	 */
	signClosingTx(
		tx: bitcoin.Transaction,
		fundingWitnessScript: Buffer,
		fundingAmount: number
	): Buffer {
		return this.signCommitmentTx(tx, fundingWitnessScript, fundingAmount);
	}

	/**
	 * Verify a remote party's signature on a commitment transaction.
	 *
	 * @param tx - The commitment transaction
	 * @param signature - 64-byte compact signature from remote
	 * @param remoteFundingPubkey - Remote's funding public key
	 * @param fundingWitnessScript - The 2-of-2 multisig witness script
	 * @param fundingAmount - The funding output value in satoshis
	 * @returns true if signature is valid
	 */
	verifyCommitmentSig(
		tx: bitcoin.Transaction,
		signature: Buffer,
		remoteFundingPubkey: Buffer,
		fundingWitnessScript: Buffer,
		fundingAmount: number
	): boolean {
		const sigHash = tx.hashForWitnessV0(
			0,
			fundingWitnessScript,
			fundingAmount,
			bitcoin.Transaction.SIGHASH_ALL
		);
		// strict (low-S): this signature goes into the funding 2-of-2 witness of a
		// commitment/closing tx we broadcast. A high-S signature verifies but makes
		// that tx non-standard/non-relayable, so reject it here rather than accept an
		// unbroadcastable commitment (BIP146).
		return verify(sigHash, remoteFundingPubkey, signature, true);
	}

	/**
	 * Build the witness for a commitment transaction input (2-of-2 multisig).
	 * Per BIP 147, the dummy OP_0 is required for OP_CHECKMULTISIG.
	 *
	 * @param localSig - Local signature (64-byte compact)
	 * @param remoteSig - Remote signature (64-byte compact)
	 * @param localFundingPubkey - Local funding public key
	 * @param remoteFundingPubkey - Remote funding public key
	 * @param fundingWitnessScript - The 2-of-2 multisig witness script
	 * @returns Witness stack
	 */
	static buildFundingWitness(
		localSig: Buffer,
		remoteSig: Buffer,
		localFundingPubkey: Buffer,
		remoteFundingPubkey: Buffer,
		fundingWitnessScript: Buffer
	): Buffer[] {
		// Signatures must be in the same order as pubkeys in the script.
		// Script has keys sorted lexicographically.
		const localDer = Buffer.concat([toDer(localSig), Buffer.from([0x01])]);
		const remoteDer = Buffer.concat([toDer(remoteSig), Buffer.from([0x01])]);

		const cmp = Buffer.compare(localFundingPubkey, remoteFundingPubkey);
		const [sig1, sig2] =
			cmp < 0 ? [localDer, remoteDer] : [remoteDer, localDer];

		return [
			Buffer.alloc(0), // OP_0 dummy for CHECKMULTISIG bug
			sig1,
			sig2,
			fundingWitnessScript
		];
	}
}
