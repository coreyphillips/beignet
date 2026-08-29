/**
 * What the payer checks in the exact bytes it is asked to sign (issue #613).
 *
 * Rev 2 lists seven obligations, and every one of them fails CLOSED, before any
 * signature exists. The payer is signing a transaction a stranger built: the
 * only thing standing between it and a coin spent into someone else's output is
 * that these run first and none of them is skippable.
 *
 * Kept out of the engine so each can be exercised on its own, the way 4C's
 * `receiver/verify.ts` is. Nothing here throws on peer bytes: every refusal is
 * a returned string, and the two signature verifications go through the repo's
 * own wrappers, which already turn a library throw into `false`.
 */

import * as bitcoin from 'bitcoinjs-lib';
import {
	zbase32Encode,
	verifyMessageSignature
} from '../../crypto/message-signing';
import { createFundingScript } from '../../script/funding';
import { attestationMessage, IDfPrevout, IDfSignRequest } from '../messages';
import { DF_MAX_PREVOUTS, DF_MAX_TX_OUTPUTS } from '../types';

/** Rev 2: height-based locktimes only, so the transaction is final on a block. */
export const DF_MAX_LOCKTIME = 500_000_000;

export interface IDfSignRequestCheck {
	request: IDfSignRequest;
	/** Parsed from `request.rawTx`; the exact bytes that would be signed. */
	tx: bitcoin.Transaction;
	/** The offer id we sent. */
	offerId: Buffer;
	/** Our outpoint, prev txid in INTERNAL byte order. */
	payerPrevTxid: Buffer;
	payerVout: number;
	payerValueSat: bigint;
	/** The sequence our offer committed to. */
	sequence: number;
	changeScript: Buffer;
	amountSat: bigint;
	maxTotalFeeSat: bigint;
	/** The node the payment request named; the attestation MUST recover to it. */
	receiverNodeId: Buffer;
	/** Does this wallet control the outpoint? */
	ownsOutpoint(txidDisplayHex: string, vout: number): boolean;
}

export interface IDfSignRequestVerdict {
	/** The index of our input, once check 1 has located it. */
	inputIndex: number;
	/** The 2-of-2 the attestation named, for the caller to record. */
	fundingScript: Buffer;
	fundingTxidDisplay: string;
}

/**
 * Run every check rev 2 makes a payer's MUST. Returns the refusal, or the facts
 * the caller needs to sign.
 */
export function signRequestProblem(
	c: IDfSignRequestCheck
): { problem: string } | { verdict: IDfSignRequestVerdict } {
	if (!c.request.offerId.equals(c.offerId)) {
		return { problem: 'sign request names a different offer' };
	}

	// ── 2. Shape. Cheapest, and it bounds every loop below. ──
	if (c.tx.version !== 2) {
		return { problem: `funding transaction version is ${c.tx.version}, not 2` };
	}
	if (c.tx.locktime >= DF_MAX_LOCKTIME) {
		// A time-based locktime cannot be reasoned about against a block height,
		// and rev 2 refuses it rather than leave the payer guessing when the coin
		// becomes spendable by this transaction.
		return { problem: 'funding transaction uses a time-based locktime' };
	}
	if (c.tx.ins.length > DF_MAX_PREVOUTS) {
		return {
			problem: `funding transaction has ${c.tx.ins.length} inputs, above the ${DF_MAX_PREVOUTS} direct funding allows`
		};
	}
	if (c.tx.outs.length > DF_MAX_TX_OUTPUTS) {
		return {
			problem: `funding transaction has ${c.tx.outs.length} outputs, above the ${DF_MAX_TX_OUTPUTS} direct funding allows`
		};
	}
	if (c.request.prevouts.length !== c.tx.ins.length) {
		// BIP 341 needs one prevout per input, and a short list would make the
		// taproot sighash silently wrong rather than refused.
		return {
			problem: `sign request carries ${c.request.prevouts.length} prevouts for ${c.tx.ins.length} inputs`
		};
	}

	// ── 1. Input. Ours exactly once, at the sequence we committed to, and no
	// other input in the transaction is ours. ──
	const ours: number[] = [];
	for (let i = 0; i < c.tx.ins.length; i++) {
		if (
			Buffer.from(c.tx.ins[i].hash).equals(c.payerPrevTxid) &&
			c.tx.ins[i].index === c.payerVout
		) {
			ours.push(i);
		}
	}
	if (ours.length !== 1) {
		return {
			problem: `funding transaction spends the offered coin ${ours.length} times`
		};
	}
	const inputIndex = ours[0];
	if (c.tx.ins[inputIndex].sequence !== c.sequence) {
		return {
			problem: 'funding transaction changed the offered input sequence'
		};
	}
	for (let i = 0; i < c.tx.ins.length; i++) {
		if (i === inputIndex) continue;
		const txid = Buffer.from(c.tx.ins[i].hash).reverse().toString('hex');
		if (c.ownsOutpoint(txid, c.tx.ins[i].index)) {
			// We agreed to spend one coin. A second one of ours in the same
			// transaction is money leaving that no ceiling in this exchange bounds,
			// and the fee arithmetic below would not see it at all.
			return {
				problem: `funding transaction spends a second coin of ours at input ${i}`
			};
		}
	}

	// ── 3. Change and fee. payer_cost is what leaves this wallet: our input,
	// less everything that comes back to our change script. ──
	let changeSat = 0n;
	for (const out of c.tx.outs) {
		if (Buffer.from(out.script).equals(c.changeScript)) {
			changeSat += BigInt(out.value);
		}
	}
	const payerCost = c.payerValueSat - changeSat;
	if (payerCost < c.amountSat) {
		// The receiver paid us back more than the coin was worth, so the amount it
		// actually receives is below what we agreed to pay.
		return {
			problem: `funding transaction returns ${changeSat} sat of a ${c.payerValueSat} sat coin, leaving less than the ${c.amountSat} sat payment`
		};
	}
	const payerFee = payerCost - c.amountSat;
	if (payerFee > c.maxTotalFeeSat) {
		// No change output at all is legitimate: honest change below dust becomes
		// fee. Either way it lands here, and the ceiling is what bounds it.
		return {
			problem: `funding transaction costs us ${payerFee} sat in fees, above the ${c.maxTotalFeeSat} sat allowed`
		};
	}

	// ── 4/5. The funding output IS the receiver's channel: the exact 2-of-2
	// built from the attested funding pubkeys, and the node the payment request
	// named is what attested to it. Without both, "delivery" is a claim. ──
	const att = c.request.attestation;
	const funding = createFundingScript(
		att.localFundingPubkey,
		att.remoteFundingPubkey
	).p2wshOutput;
	const fundingOut = c.tx.outs[att.fundingOutputIndex];
	if (!fundingOut) {
		return {
			problem: 'funding output index is not an output of the transaction'
		};
	}
	if (!Buffer.from(fundingOut.script).equals(funding)) {
		return { problem: 'funding output does not match the attested 2-of-2' };
	}
	const fundingValue = BigInt(fundingOut.value);

	if (c.request.sharedInputIndex !== undefined) {
		// Splice extension: our payment goes into a channel that already holds
		// value, so both halves have to be verified. The shared input must BE the
		// attested channel funding (the same 2-of-2 we just checked the output
		// against), and the new output must carry the old capacity as well.
		const shared = c.request.sharedInputIndex;
		if (shared === inputIndex) {
			return {
				problem: 'sign request names our own input as the shared input'
			};
		}
		if (shared >= c.tx.ins.length) {
			return {
				problem: 'shared input index is not an input of the transaction'
			};
		}
		const sharedPrevout: IDfPrevout | undefined = c.request.prevouts[shared];
		if (!sharedPrevout || !sharedPrevout.script.equals(funding)) {
			return { problem: 'shared input is not the attested channel funding' };
		}
		const floor = sharedPrevout.valueSat + c.amountSat - c.maxTotalFeeSat;
		if (fundingValue < floor) {
			return {
				problem: `spliced funding output holds ${fundingValue} sat, below the ${floor} sat the old channel plus our payment requires`
			};
		}
	} else if (fundingValue < c.amountSat) {
		// 7. And this is where a request that fixed an amount is honored: the
		// offer carried that amount, and the output has to hold it.
		return {
			problem: `funding output holds ${fundingValue} sat, less than the ${c.amountSat} sat we are paying`
		};
	}

	// ── 5. Attestation. Recovery alone authenticates nothing (a tampered
	// message still recovers SOME key), so the recovered key must BE the
	// receiver the request named. ──
	const verdict = verifyMessageSignature(
		attestationMessage(
			c.offerId,
			c.request.rawTx,
			att.fundingOutputIndex,
			att.localFundingPubkey
		),
		zbase32Encode(att.signature)
	);
	if (!verdict.valid || !verdict.pubkey) {
		return { problem: 'attestation signature is invalid' };
	}
	if (!verdict.pubkey.equals(c.receiverNodeId)) {
		return {
			problem:
				'attestation was signed by a different node than the payment request named'
		};
	}

	return {
		verdict: {
			inputIndex,
			fundingScript: funding,
			fundingTxidDisplay: c.tx.getId()
		}
	};
}

/**
 * Check 6: every supplied prevout is chain truth.
 *
 * BIP 341 commits to the amount and script of EVERY input, so for a taproot
 * spend a lying prevout is signing input rather than metadata. It cannot steal
 * anything (a wrong commitment only makes the signature invalid), but it turns
 * a payment into a broadcast that fails, and the failure surfaces long after
 * the witness left. So it fails closed and early instead.
 *
 * Our own entry is checked whatever the kind: a P2WPKH sighash commits to our
 * value, and a wrong one there is the same denial of service for one input.
 * Everything else is only fetched when we are actually signing over it.
 */
export async function prevoutProblem(
	tx: bitcoin.Transaction,
	prevouts: IDfPrevout[],
	inputIndex: number,
	payerScript: Buffer,
	payerValueSat: bigint,
	commitsToAllPrevouts: boolean,
	getTransaction: (txidHex: string) => Promise<Buffer>
): Promise<string | null> {
	const mine = prevouts[inputIndex];
	if (!mine) return 'sign request has no prevout for our input';
	if (!mine.script.equals(payerScript) || mine.valueSat !== payerValueSat) {
		return 'sign request prevouts do not match our own input';
	}
	if (!commitsToAllPrevouts) return null;
	for (let i = 0; i < tx.ins.length; i++) {
		if (i === inputIndex) continue;
		const txidHex = Buffer.from(tx.ins[i].hash).reverse().toString('hex');
		let prevTx: bitcoin.Transaction;
		try {
			prevTx = bitcoin.Transaction.fromBuffer(await getTransaction(txidHex));
		} catch {
			return `could not verify input ${i} against the chain`;
		}
		if (prevTx.getId() !== txidHex) {
			return `could not verify input ${i} against the chain`;
		}
		const out = prevTx.outs[tx.ins[i].index];
		const claimed = prevouts[i];
		if (
			!out ||
			!claimed ||
			!Buffer.from(out.script).equals(claimed.script) ||
			BigInt(out.value) !== claimed.valueSat
		) {
			return `sign request prevout ${i} does not match chain truth`;
		}
	}
	return null;
}
