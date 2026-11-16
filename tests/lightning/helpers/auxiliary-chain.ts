/**
 * A chain small enough to read, for the asset channel tests (issue #2093).
 *
 * It keeps the set of unspent outputs and judges a transaction the way a
 * node's mempool would for the spends these tests make: every input spends
 * an output that exists and is unspent, the outputs do not exceed the
 * inputs, the fee meets the minimum relay rate, no output is dust, and a
 * taproot key spend carries a BIP 340 signature of the key that is in the
 * spent output's script on this chain. That key is read from the chain,
 * never from a channel's state, so a transaction signed under another key
 * than the one its funding committed to is refused here as it would be by
 * the network.
 */

import * as bitcoin from 'bitcoinjs-lib';
import { ecc } from '../../../src/utils/ecc';

bitcoin.initEccLib(ecc);

export interface IChainOutput {
	script: Buffer;
	value: number;
}

/** The smallest value a node relays for an output of this script. */
export function relayDustLimit(script: Buffer): number {
	if (script.length > 0 && script[0] === 0x6a) return 0;
	if (script.length === 22 && script[0] === 0x00) return 294;
	if (script.length === 34 && (script[0] === 0x00 || script[0] === 0x51)) {
		return 330;
	}
	if (script.length === 23) return 540;
	return 546;
}

const isTaprootOutput = (script: Buffer): boolean =>
	script.length === 34 && script[0] === 0x51 && script[1] === 0x20;

/** How a spend this chain does not judge by itself is judged, by input. */
export type SpendJudge = (
	tx: bitcoin.Transaction,
	inputIndex: number,
	spent: IChainOutput[]
) => void;

export class TestChain {
	private readonly unspent = new Map<string, IChainOutput>();
	private readonly spentBy = new Map<string, string>();
	/** Every transaction this chain confirmed, by id, with its height. */
	readonly confirmed = new Map<
		string,
		{ tx: bitcoin.Transaction; height: number }
	>();
	height = 100;

	private static key(txid: string, vout: number): string {
		return `${txid}:${vout}`;
	}

	private static outpoint(input: { hash: Buffer; index: number }): string {
		return TestChain.key(
			Buffer.from(input.hash).reverse().toString('hex'),
			input.index
		);
	}

	/**
	 * Put a transaction's outputs on the chain without judging its inputs:
	 * a funding transaction, whose inputs a test invents.
	 */
	seed(tx: bitcoin.Transaction): void {
		const txid = tx.getId();
		tx.outs.forEach((out, vout) => {
			this.unspent.set(TestChain.key(txid, vout), {
				script: Buffer.from(out.script),
				value: out.value
			});
		});
		this.confirmed.set(txid, { tx, height: this.height });
	}

	/** The unspent output at an outpoint, or undefined. */
	output(txid: string, vout: number): IChainOutput | undefined {
		return this.unspent.get(TestChain.key(txid, vout));
	}

	/** The id of the confirmed transaction that spent an outpoint, or undefined. */
	spender(txid: string, vout: number): string | undefined {
		return this.spentBy.get(TestChain.key(txid, vout));
	}

	/**
	 * Judge a transaction and say what it pays. Throws with the reason it
	 * would not be relayed or mined. `judge` is asked about every input that
	 * is not a taproot key spend.
	 */
	accept(
		tx: bitcoin.Transaction,
		judge?: SpendJudge
	): { fee: number; vsize: number } {
		if (tx.ins.length === 0) throw new Error('a transaction needs an input');
		const spent = tx.ins.map((input) => {
			const point = TestChain.outpoint(input);
			const output = this.unspent.get(point);
			if (!output) {
				throw new Error(
					this.spentBy.has(point)
						? `input ${point} is already spent by ${this.spentBy.get(point)}`
						: `input ${point} does not exist`
				);
			}
			return output;
		});
		if (
			new Set(tx.ins.map((input) => TestChain.outpoint(input))).size !==
			tx.ins.length
		) {
			throw new Error('a transaction spends an outpoint twice');
		}
		const paidIn = spent.reduce((sum, output) => sum + output.value, 0);
		const paidOut = tx.outs.reduce((sum, output) => sum + output.value, 0);
		if (paidOut > paidIn) throw new Error('outputs exceed inputs');
		const fee = paidIn - paidOut;
		const vsize = Math.ceil(tx.weight() / 4);
		if (fee < vsize) {
			throw new Error(
				`fee ${fee} is below the minimum relay fee for ${vsize} vB`
			);
		}
		for (const [index, out] of tx.outs.entries()) {
			if (out.value < relayDustLimit(out.script)) {
				throw new Error(`output ${index} of ${out.value} sat is dust`);
			}
		}
		tx.ins.forEach((input, index) => {
			const output = spent[index];
			const keySpend =
				isTaprootOutput(output.script) && input.witness.length === 1;
			if (!keySpend) {
				if (!judge) {
					throw new Error(`input ${index} is a spend this chain cannot judge`);
				}
				judge(tx, index, spent);
				return;
			}
			const signature = input.witness[0];
			if (signature.length !== 64 && signature.length !== 65) {
				throw new Error(`input ${index} carries no schnorr signature`);
			}
			const hashType =
				signature.length === 65
					? signature[64]
					: bitcoin.Transaction.SIGHASH_DEFAULT;
			const sighash = tx.hashForWitnessV1(
				index,
				spent.map((each) => each.script),
				spent.map((each) => each.value),
				hashType
			);
			if (
				!ecc.verifySchnorr(
					sighash,
					output.script.subarray(2),
					signature.subarray(0, 64)
				)
			) {
				throw new Error(
					`input ${index} is not signed by the key of the output it spends`
				);
			}
		});
		return { fee, vsize };
	}

	/** Judge a transaction, confirm it in a new block and return that height. */
	mine(tx: bitcoin.Transaction, judge?: SpendJudge): number {
		this.accept(tx, judge);
		const txid = tx.getId();
		this.height += 1;
		for (const input of tx.ins) {
			const point = TestChain.outpoint(input);
			this.unspent.delete(point);
			this.spentBy.set(point, txid);
		}
		tx.outs.forEach((out, vout) => {
			this.unspent.set(TestChain.key(txid, vout), {
				script: Buffer.from(out.script),
				value: out.value
			});
		});
		this.confirmed.set(txid, { tx, height: this.height });
		return this.height;
	}
}
