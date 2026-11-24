import type { Transaction } from 'bitcoinjs-lib';
import { ecc } from '../../utils/ecc';
import { taprootKeySpendSighash } from '../script/funding-taproot';
import type {
	IFinalSpliceCandidate,
	IFinalSpliceTerms
} from './final-splice-candidate';

export interface ISpliceLocalExit {
	/** Reconstructed from the local ledger and its key locators. */
	expected: Transaction;
	signed: Transaction;
}

export function validateFinalSpliceExit(
	view: ISpliceLocalExit,
	source: Transaction,
	index: number
): void {
	const tx = view.signed;
	if (
		tx.ins.length !== 1 ||
		!tx.ins[0].hash.equals(source.getHash()) ||
		tx.ins[0].index !== index ||
		!view.expected.getHash().equals(tx.getHash())
	)
		throw new Error('Splice exit does not match the local commitment');
	const prev = source.outs[index],
		w = tx.ins[0].witness;
	if (
		w.length !== 1 ||
		w[0].length !== 64 ||
		!ecc.verifySchnorr(
			taprootKeySpendSighash(tx, 0, [prev.script], [prev.value]),
			prev.script.subarray(2),
			w[0]
		)
	)
		throw new Error('Invalid splice commitment exit signature');
}

/** Both funding generations require a locally verified, fully signed unilateral spend. */
export function validateFinalSpliceExits(
	exits: { parent: ISpliceLocalExit; candidate: ISpliceLocalExit },
	c: IFinalSpliceCandidate,
	terms: IFinalSpliceTerms
): void {
	validateFinalSpliceExit(exits.parent, terms.parent, terms.parentIndex);
	validateFinalSpliceExit(exits.candidate, c.tx, c.fundingIndex);
}
