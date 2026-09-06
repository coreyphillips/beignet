import * as bitcoin from 'bitcoinjs-lib';
import { getPublicKey, isValidPrivateKey, sign, verify } from '../crypto/ecdh';
import { buildSwapHtlc, ISwapHtlc } from './htlc';
import { assertSatoshis } from './validation';

export interface ISwapFunding {
	htlc: ISwapHtlc;
	/** Caller must establish this transaction's chain status and spendability. */
	fundingTransaction: bitcoin.Transaction;
	outputIndex: number;
}

export interface ISwapSpend extends ISwapFunding {
	/** Native P2WPKH, P2WSH or P2TR destination scriptPubKey. */
	destinationScript: Buffer;
	/** Absolute transaction fee, not a fee rate. */
	feeSatoshis: bigint;
	privateKey: Buffer;
}

function validatedFunding(funding: ISwapFunding): {
	witnessScript: Buffer;
	value: number;
} {
	const { witnessScript, outputScript } = buildSwapHtlc(funding.htlc);
	const { outputIndex, fundingTransaction } = funding;
	if (
		!Number.isInteger(outputIndex) ||
		outputIndex < 0 ||
		outputIndex >= fundingTransaction.outs.length
	) {
		throw new Error('Funding output index is out of range');
	}
	const output = fundingTransaction.outs[outputIndex];
	if (!output.script.equals(outputScript)) {
		throw new Error('Funding output does not match the swap contract');
	}
	if (!Number.isSafeInteger(output.value)) {
		throw new Error('Funding value must be an integer number of satoshis');
	}
	assertSatoshis(BigInt(output.value), 'Funding value');
	return { witnessScript, value: output.value };
}

function destinationDust(script: Buffer): bigint {
	if (
		Buffer.isBuffer(script) &&
		script.length === 22 &&
		script[0] === bitcoin.opcodes.OP_0 &&
		script[1] === 20
	) {
		return 294n;
	}
	if (
		Buffer.isBuffer(script) &&
		script.length === 34 &&
		(script[0] === bitcoin.opcodes.OP_0 ||
			script[0] === bitcoin.opcodes.OP_1) &&
		script[1] === 32
	) {
		return 330n;
	}
	throw new Error('Destination must be a native P2WPKH, P2WSH or P2TR script');
}

function buildSpend(
	params: ISwapSpend,
	claim: boolean,
	preimage?: Buffer
): bitcoin.Transaction {
	const { witnessScript, value } = validatedFunding(params);
	const { privateKey, destinationScript, feeSatoshis, htlc } = params;
	if (!Buffer.isBuffer(privateKey) || !isValidPrivateKey(privateKey)) {
		throw new Error('Private key must be a valid 32-byte scalar');
	}
	const expectedKey = claim ? htlc.claimPublicKey : htlc.refundPublicKey;
	if (!getPublicKey(privateKey).equals(expectedKey)) {
		throw new Error('Private key does not match the selected swap branch');
	}
	assertSatoshis(feeSatoshis, 'Fee');
	const outputValue = BigInt(value) - feeSatoshis;
	if (outputValue < destinationDust(destinationScript)) {
		throw new Error('Fee leaves an insufficient or dust output');
	}
	if (
		claim &&
		(!Buffer.isBuffer(preimage) ||
			preimage.length !== 32 ||
			!bitcoin.crypto.sha256(preimage).equals(htlc.paymentHash))
	) {
		throw new Error(
			'Claim preimage must be 32 bytes and match the payment hash'
		);
	}

	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.locktime = claim ? 0 : htlc.refundHeight;
	// Enable CLTV and opt in to fee replacement without a relative timelock.
	tx.addInput(
		params.fundingTransaction.getHash(),
		params.outputIndex,
		0xfffffffd
	);
	tx.addOutput(Buffer.from(destinationScript), Number(outputValue));
	const digest = tx.hashForWitnessV0(
		0,
		witnessScript,
		value,
		bitcoin.Transaction.SIGHASH_ALL
	);
	const signature = bitcoin.script.signature.encode(
		sign(digest, privateKey),
		bitcoin.Transaction.SIGHASH_ALL
	);
	tx.setWitness(
		0,
		claim
			? [signature, Buffer.from(preimage!), Buffer.from([1]), witnessScript]
			: [signature, Buffer.alloc(0), witnessScript]
	);
	return tx;
}

/** Signed, single-input/single-output preimage claim with SIGHASH_ALL. */
export function buildSwapClaimTx(
	params: ISwapSpend & { preimage: Buffer }
): bitcoin.Transaction {
	return buildSpend(params, true, params.preimage);
}

/**
 * Signed CLTV refund, suitable for saving before funding is broadcast.
 * nLockTime = refundHeight permits inclusion starting at refundHeight + 1.
 * Creating or broadcasting it does not make cancelling a held payment safe.
 */
export function buildSwapRefundTx(params: ISwapSpend): bitcoin.Transaction {
	return buildSpend(params, false);
}

/**
 * Return a copy of a preimage from a canonical claim of the exact
 * funded output. Check the script, hash, branch, amount-bound signature and
 * outpoint. Returns undefined for a refund, malformed or unrelated spend.
 * Supports ALL, NONE and SINGLE, each optionally combined with ANYONECANPAY.
 * Undefined is not evidence that the preimage has never been revealed.
 * This is not transaction consensus validation or confirmation/reorg evidence.
 * Invalid expected funding data throws instead of being treated as no claim.
 */
export function extractSwapPreimage(
	transaction: bitcoin.Transaction,
	funding: ISwapFunding
): Buffer | undefined {
	const { witnessScript, value } = validatedFunding(funding);
	const fundingHash = funding.fundingTransaction.getHash();
	const matches = transaction.ins
		.map((input, index) => ({ input, index }))
		.filter(
			({ input }) =>
				input.hash.equals(fundingHash) && input.index === funding.outputIndex
		);
	if (matches.length !== 1) return undefined;
	const { input, index } = matches[0];
	const witness = input.witness;
	if (
		input.script.length !== 0 ||
		witness.length !== 4 ||
		!witness[3].equals(witnessScript) ||
		!witness[2].equals(Buffer.from([1])) ||
		witness[1].length !== 32 ||
		!bitcoin.crypto.sha256(witness[1]).equals(funding.htlc.paymentHash)
	)
		return undefined;
	try {
		const { signature, hashType } = bitcoin.script.signature.decode(witness[0]);
		const digest = transaction.hashForWitnessV0(
			index,
			witnessScript,
			value,
			hashType
		);
		if (!verify(digest, funding.htlc.claimPublicKey, signature, true))
			return undefined;
		return Buffer.from(witness[1]);
	} catch {
		return undefined;
	}
}
