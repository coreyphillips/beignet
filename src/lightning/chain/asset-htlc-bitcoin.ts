import { Transaction } from 'bitcoinjs-lib';
import { getPublicKey } from '../crypto/ecdh';
import type { ITaprootLeafSpend } from '../script/commitment-taproot';
import {
	signTaprootHtlcLeaf,
	tapleafHash,
	verifyTaprootHtlcLeaf
} from '../script/htlc-taproot';

/** A fee wallet may append inputs and outputs. SIGHASH_SINGLE preserves the original pair. */
export function checkSponsoredHtlc(
	template: Transaction,
	sponsored?: Transaction
): void {
	const first = template.ins[0],
		input = sponsored?.ins[0];
	if (
		!sponsored ||
		!input ||
		sponsored.version !== template.version ||
		sponsored.locktime !== template.locktime ||
		!input.hash.equals(first.hash) ||
		input.index !== first.index ||
		input.sequence !== first.sequence ||
		!input.script.equals(first.script) ||
		!sponsored.outs[0]?.script.equals(template.outs[0].script) ||
		sponsored.outs[0].value !== template.outs[0].value ||
		input.witness.length !== first.witness.length ||
		input.witness.some((v, n) => !v.equals(first.witness[n]))
	)
		throw Error('Fee-sponsored asset HTLC changed its signed input or output');
}

/** Local signatures bind one measured value and a P2TR output. Verify an
 * already signed wallet receipt after interruption before the engine journal. */
export function assetHtlcSweepSigner(
	template: Transaction,
	coin: Transaction['outs'][number],
	secret: Buffer,
	leaf?: ITaprootLeafSpend
) {
	const first = template.ins[0],
		authorizedTail = first.witness.slice(1);
	let signedId: string | undefined;
	const matches = (tx: Transaction) =>
		tx.version === template.version &&
		tx.locktime === template.locktime &&
		tx.ins.length === 1 &&
		tx.outs.length === 1 &&
		tx.ins[0].hash.equals(first.hash) &&
		tx.ins[0].index === first.index &&
		tx.ins[0].sequence === first.sequence &&
		!tx.ins[0].script.length &&
		tx.outs[0].script.length === 34 &&
		tx.outs[0].script.subarray(0, 2).equals(Buffer.of(0x51, 32)) &&
		(!signedId || tx.getId() === signedId);
	const digest = (tx: Transaction) =>
		tx.hashForWitnessV1(
			0,
			[coin.script],
			[coin.value],
			Transaction.SIGHASH_DEFAULT,
			leaf && tapleafHash(leaf.script, leaf.leafVersion)
		);
	return {
		sign(tx: Transaction): Buffer[] {
			if (!matches(tx) || tx.outs[0].value !== template.outs[0].value)
				throw Error('Invalid Bitcoin asset HTLC payout template');
			signedId = tx.getId();
			return [
				signTaprootHtlcLeaf(digest(tx), secret),
				...authorizedTail.map((v) => Buffer.from(v))
			];
		},
		accepts(tx: Transaction): boolean {
			if (
				!matches(tx) ||
				tx.outs[0].value < 330 ||
				tx.outs[0].value >= coin.value
			)
				return false;
			const stack = tx.ins[0].witness;
			return (
				stack.length === authorizedTail.length + 1 &&
				stack[0].length === 64 &&
				authorizedTail.every((b, i) => b.equals(stack[i + 1])) &&
				verifyTaprootHtlcLeaf(digest(tx), getPublicKey(secret), stack[0])
			);
		}
	};
}
