/**
 * Everything the receiver checks before, and about, the transaction it
 * attests to (issue #612).
 *
 * Three jobs, kept out of the engine so each can be tested on its own: the
 * offer's own fields, the payer's proof that it controls the coin, and the
 * negotiated transaction the receiver is about to put its node signature over.
 *
 * Nothing here throws on peer bytes. The fork called the secp256k1 bindings
 * bare, and those throw on a malformed scalar or a non-point pubkey, so four
 * malformed offers took direct funding off the node for an hour (defect D1);
 * every verification below goes through the repo's own wrappers, which already
 * turn a library throw into `false`, behind explicit length checks.
 */

import * as bitcoin from 'bitcoinjs-lib';
import { computeScriptHash } from '../../chain/chain-watcher';
import { verify as ecdsaVerify } from '../../crypto/ecdh';
import { MAX_INTERACTIVE_TX_SEQUENCE } from '../../interactive-tx/validation';
import { schnorrVerify } from '../../offer/schnorr';
import { isValidShutdownScript } from '../../channel/validation';
import { scriptKind } from '../../wallet/wallet-funding-provider';
import { deriveOfferId, IDfOffer, ownershipDigest } from '../messages';
import {
	DF_MAX_PREVOUTS,
	DF_MAX_SCRIPT_BYTES,
	DF_MAX_TX_OUTPUTS,
	DF_NODE_ID_BYTES
} from '../types';
import {
	DF_HARD_MIN_OFFER_AMOUNT_SAT,
	IDfChainSource,
	IDfReceiverConfig
} from './types';

const XONLY_PUBKEY_BYTES = 32;

// ─────────────── The offer's own fields ───────────────

/**
 * Refuse an offer whose fields we could not serve whatever the chain says.
 * Returns the decline reason, or null.
 *
 * The fork checked only a floor on the amount (defect D10) and nothing at all
 * on the sequence (D9) or the change script (D8), so a non-integral amount
 * threw inside `BigInt()` after a session had been spent, and an oversized or
 * non-standard change script became an output of a funding transaction nobody
 * could ever broadcast. The TLV codec (4A) already fixes every field's width,
 * which is what removes the fork's third class of these (D11); what is left is
 * range and kind.
 */
export function offerFieldProblem(
	offer: IDfOffer,
	config: IDfReceiverConfig
): string | null {
	// Identity first: the id is SHA256 over txid, vout and amount, and the
	// whole idempotency story assumes it. A payer-chosen id would let one coin
	// wear many identities, or two payments share one.
	const expectedId = deriveOfferId(offer.txid, offer.vout, offer.amountSat);
	if (!expectedId.equals(offer.offerId)) {
		return 'offer id is not derived from the offered outpoint and amount';
	}
	const floor =
		config.minAmountSat !== undefined &&
		config.minAmountSat > DF_HARD_MIN_OFFER_AMOUNT_SAT
			? config.minAmountSat
			: DF_HARD_MIN_OFFER_AMOUNT_SAT;
	if (offer.amountSat < floor) {
		return `amount below this receiver's ${floor} sat direct funding minimum`;
	}
	if (
		config.maxAmountSat !== undefined &&
		offer.amountSat > config.maxAmountSat
	) {
		return `amount above this receiver's ${config.maxAmountSat} sat direct funding maximum`;
	}
	// The coin has to cover the payment before anything else is worth doing;
	// the fee headroom is judged later, against the negotiated transaction.
	if (offer.amountSat > offer.valueSat) {
		return 'offered amount exceeds the value of the offered coin';
	}
	if (offer.sequence > MAX_INTERACTIVE_TX_SEQUENCE) {
		// The interactive-tx builder refuses this, but only once the session is
		// already open and the peer is already talking.
		return `sequence must be at most ${MAX_INTERACTIVE_TX_SEQUENCE} (BOLT 2 interactive tx)`;
	}
	if (
		config.requiredSequence !== undefined &&
		offer.sequence !== config.requiredSequence
	) {
		return `sequence must be ${config.requiredSequence}`;
	}
	if (
		offer.changeScript.length === 0 ||
		offer.changeScript.length > DF_MAX_SCRIPT_BYTES ||
		!isValidShutdownScript(offer.changeScript, true, false)
	) {
		// Any witness program is fine, an OP_RETURN is not: change is money the
		// payer gets back, and a burn output would be a funding transaction we
		// negotiated and the payer can never recover from.
		return 'change script is not a standard payable output';
	}
	return null;
}

// ─────────────── Ownership proof ───────────────

/**
 * Verify that the key controlling the offered coin signed this offer. Returns
 * the decline reason, or null.
 *
 * Note what this does NOT buy: a proof prices nothing by itself, since one
 * UTXO can sign for arbitrarily many offers at zero cost. The admission caps
 * bound the work; this bounds the waste, by refusing before a whole channel
 * session is spent on a coin the payer cannot spend.
 *
 * Rev 2 notes a final specification may adopt BIP 322 wholesale. We do not,
 * and only the two script kinds `scriptKind` classifies are admitted, because
 * they are exactly the two whose witnesses the channel can verify later.
 */
export function ownershipProblem(
	offer: IDfOffer,
	prevOutScript: Buffer
): string | null {
	const kind = scriptKind(prevOutScript);
	if (!kind) return 'unsupported input script';
	const digest = ownershipDigest(
		offer.offerId,
		offer.txid,
		offer.vout,
		offer.amountSat
	);
	if (kind === 'p2tr') {
		// The x-only key comes out of the scriptPubKey, never from the proof:
		// lifting it here means the taproot tweak is validated by construction
		// instead of being trusted from a pubkey the payer chose.
		const outputKey = prevOutScript.subarray(2, 2 + XONLY_PUBKEY_BYTES);
		return schnorrVerify(digest, outputKey, offer.ownership.signature)
			? null
			: 'invalid taproot ownership signature';
	}
	if (offer.ownership.pubkey.length !== DF_NODE_ID_BYTES) {
		return 'ownership pubkey must be a 33-byte compressed key for a P2WPKH input';
	}
	const program = prevOutScript.subarray(2, 22);
	if (!bitcoin.crypto.hash160(offer.ownership.pubkey).equals(program)) {
		return 'ownership pubkey does not control the offered coin';
	}
	return ecdsaVerify(digest, offer.ownership.pubkey, offer.ownership.signature)
		? null
		: 'invalid ownership signature';
}

// ─────────────── Chain facts about the coin ───────────────

/**
 * What our own chain source says about the offered outpoint: whether it is
 * provably gone, and whether it is confirmed.
 *
 * The rules are `classifyRemoteFundingInput`'s (issue #311) and fail open for
 * the same reasons: absence from an unspent set proves nothing about an
 * unconfirmed coin, and a server that cannot answer must not refuse an honest
 * payer. Answered here rather than there because the engine needs the
 * confirmation status as well: the fork asserted `confirmed: true`
 * unconditionally (defect D13), which would have satisfied a peer's
 * `require_confirmed_inputs` over a coin still in the mempool.
 *
 * `confirmed` is left undefined when nothing conclusive came back, which the
 * channel treats as unknown rather than as a claim.
 */
export async function classifyOfferedCoin(
	chain: IDfChainSource,
	outpoint: { txidDisplayHex: string; vout: number; script: Buffer }
): Promise<{ spent: boolean; confirmed?: boolean }> {
	if (!chain.listUnspent) return { spent: false };
	const scriptHash = computeScriptHash(outpoint.script);
	const unspent = await chain.listUnspent(scriptHash).catch(() => null);
	if (!unspent) return { spent: false };
	const entry = unspent.find(
		(u) => u.txid === outpoint.txidDisplayHex && u.outputIndex === outpoint.vout
	);
	if (entry) return { spent: false, confirmed: entry.height > 0 };
	// Absent from the unspent set. Only a CONFIRMED parent makes that positive
	// evidence of a spend; anything else is a server that has not indexed it.
	if (!chain.getScriptHashHistory) return { spent: false };
	const history = await chain
		.getScriptHashHistory(scriptHash)
		.catch(() => null);
	const seen = history?.find((h) => h.txid === outpoint.txidDisplayHex);
	if (!seen || seen.height <= 0) return { spent: false };
	return { spent: true, confirmed: true };
}

// ─────────────── The transaction we are about to attest to ───────────────

export interface IDfFundingCheck {
	tx: bitcoin.Transaction;
	fundingOutputIndex: number;
	/** Smallest funding output value this transaction may carry. */
	minFundingValueSat: bigint;
	/** The payer's outpoint, prev txid in INTERNAL byte order. */
	payerPrevTxid: Buffer;
	payerVout: number;
	/** Input indices whose witnesses the channel is still owed. */
	owedExternalIndices: number[];
	offer: IDfOffer;
}

/**
 * Check the negotiated transaction before signing an attestation over it.
 * Returns the problem, or null.
 *
 * The fork signed whatever the session produced (defect D14). The payer checks
 * these too, but an attestation is a statement by this node's identity key
 * about bytes it has read, and the fork's had not read them: nothing verified
 * that the funding output held the offered amount, that the payer's change was
 * present and correctly valued, or that the coin being spent was the one
 * offered.
 */
export function fundingTransactionProblem(c: IDfFundingCheck): string | null {
	// Rev 2's shape cap, before the attestation rather than after it. A payer
	// that enforces the cap refuses to sign anything past it, so attesting here
	// would put this node's identity key over bytes the exchange cannot use;
	// the sign request's own prevout list would not encode past the input cap
	// either, and that throw comes after the signature is already made.
	if (c.tx.ins.length > DF_MAX_PREVOUTS) {
		return `negotiated transaction has ${c.tx.ins.length} inputs, above the ${DF_MAX_PREVOUTS} direct funding allows`;
	}
	if (c.tx.outs.length > DF_MAX_TX_OUTPUTS) {
		return `negotiated transaction has ${c.tx.outs.length} outputs, above the ${DF_MAX_TX_OUTPUTS} direct funding allows`;
	}
	const spending: number[] = [];
	for (let i = 0; i < c.tx.ins.length; i++) {
		if (
			Buffer.from(c.tx.ins[i].hash).equals(c.payerPrevTxid) &&
			c.tx.ins[i].index === c.payerVout
		) {
			spending.push(i);
		}
	}
	if (spending.length !== 1) {
		return `negotiated transaction spends the offered coin ${spending.length} times`;
	}
	const payerIndex = spending[0];
	if (!c.owedExternalIndices.includes(payerIndex)) {
		// The channel does not consider this input a third party's, so it is not
		// holding its tx_signatures for it: asking the payer to sign would be
		// asking for a witness nothing is waiting on.
		return 'the offered coin is not the input the channel is owed a witness for';
	}
	if (c.tx.ins[payerIndex].sequence !== c.offer.sequence) {
		// The payer signs the sequence it offered; anything else makes its
		// witness invalid over the transaction it is being handed.
		return 'negotiated transaction changed the offered input sequence';
	}
	const fundingOut = c.tx.outs[c.fundingOutputIndex];
	if (!fundingOut)
		return 'funding output index is not an output of the transaction';
	if (BigInt(fundingOut.value) < c.minFundingValueSat) {
		return `funding output holds ${fundingOut.value} sat, below the offered ${c.minFundingValueSat} sat`;
	}
	const changeOuts = c.tx.outs.filter((o) =>
		Buffer.from(o.script).equals(c.offer.changeScript)
	);
	if (changeOuts.length > 1) {
		return 'negotiated transaction pays the change script more than once';
	}
	// No change output is legitimate: the remainder was below dust and became
	// fee. Either way the payer's cost is what it agreed to bound.
	const changeSat = changeOuts.length === 1 ? BigInt(changeOuts[0].value) : 0n;
	const payerCost = c.offer.valueSat - changeSat;
	if (payerCost < c.offer.amountSat) {
		return 'negotiated transaction returns the payer more than its coin was worth';
	}
	const payerFee = payerCost - c.offer.amountSat;
	if (payerFee > c.offer.maxTotalFeeSat) {
		return `payer would pay ${payerFee} sat in fees, above the ${c.offer.maxTotalFeeSat} sat it allowed`;
	}
	return null;
}
