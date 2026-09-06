import * as bitcoin from 'bitcoinjs-lib';
import { isValidPublicKey } from '../crypto/ecdh';
import { assertBlockHeight } from './validation';

/** Roles are on-chain roles, independent of the direction of the swap. */
export interface ISwapHtlc {
	paymentHash: Buffer;
	claimPublicKey: Buffer;
	refundPublicKey: Buffer;
	/** Refund nLockTime in blocks. The preimage branch remains valid afterward. */
	refundHeight: number;
}

export interface ISwapHtlcOutput {
	witnessScript: Buffer;
	outputScript: Buffer;
	address: string;
}

/**
 * Canonical P2WSH swap contract. Claim witness: [sig, preimage, 01, script].
 * Refund witness: [sig, empty, script]. A claim requires exactly 32 bytes.
 */
export function buildSwapHtlc(
	htlc: ISwapHtlc,
	network: bitcoin.Network = bitcoin.networks.bitcoin
): ISwapHtlcOutput {
	if (!Buffer.isBuffer(htlc.paymentHash) || htlc.paymentHash.length !== 32) {
		throw new Error('Payment hash must be 32 bytes');
	}
	for (const [name, key] of [
		['Claim', htlc.claimPublicKey],
		['Refund', htlc.refundPublicKey]
	] as const) {
		if (!Buffer.isBuffer(key) || !isValidPublicKey(key)) {
			throw new Error(
				`${name} public key must be a valid compressed public key`
			);
		}
	}
	assertBlockHeight(htlc.refundHeight, 'Refund height');
	const op = bitcoin.opcodes;
	const witnessScript = bitcoin.script.compile([
		op.OP_IF,
		op.OP_SIZE,
		bitcoin.script.number.encode(32),
		op.OP_EQUALVERIFY,
		op.OP_SHA256,
		htlc.paymentHash,
		op.OP_EQUALVERIFY,
		htlc.claimPublicKey,
		op.OP_CHECKSIG,
		op.OP_ELSE,
		bitcoin.script.number.encode(htlc.refundHeight),
		op.OP_CHECKLOCKTIMEVERIFY,
		op.OP_DROP,
		htlc.refundPublicKey,
		op.OP_CHECKSIG,
		op.OP_ENDIF
	]);
	const payment = bitcoin.payments.p2wsh({
		redeem: { output: witnessScript },
		network
	});
	return {
		witnessScript,
		outputScript: payment.output!,
		address: payment.address!
	};
}
