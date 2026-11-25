import { Transaction } from 'bitcoinjs-lib';
import type {
	IInteractiveTxInput,
	IInteractiveTxOutput
} from '../interactive-tx/types';
import {
	MAX_INTERACTIVE_TX_SEQUENCE,
	MAX_MONEY_SATS,
	MAX_PEER_PREVTX_BYTES_PER_SESSION,
	checkFeeSufficiency,
	MAX_STANDARD_TX_WEIGHT,
	validateInteractiveTx,
	validatePeerInputPrevTx
} from '../interactive-tx/validation';
import {
	createTaprootFundingScript,
	taprootKeySpendSighash
} from '../script/funding-taproot';
import { isValidPublicKey } from '../crypto/ecdh';
import { buildSpliceTx } from './splice-tx';
import { MAX_SPLICE_FEERATE_PERKW } from './splice-weight';

export interface IFinalFundingReference {
	fundingTxHex: string;
	fundingOutputIndex: number;
	localFundingPubkey: string;
	remoteFundingPubkey: string;
	localFundingKeyIndex: number;
}

export interface IFinalSpliceTerms {
	/** Roots verified against the retained parent and the completed candidate asset proofs. */
	assetFundingRoots?: { parent: Buffer; candidate: Buffer };
	parent: Transaction;
	parentIndex: number;
	oldLocalKey: Buffer;
	oldPeerKey: Buffer;
	newLocalKey: Buffer;
	newPeerKey: Buffer;
	localIsSpliceInitiator: boolean;
	localDelta: bigint;
	peerDelta: bigint;
	localFeeBudget: bigint;
	feerate: number;
	dust: bigint;
	locktime: number;
}

export interface IFinalSpliceCandidate {
	tx: Transaction;
	fundingIndex: number;
	sharedIndex: number;
	scripts: Buffer[];
	values: number[];
	localInputs: number[];
	peerInputs: number[];
	/** Owners of surviving non-funding outputs, local then peer. */
	outputOwners: [boolean, boolean];
	digest: Buffer;
}

/** Eclair 0.14.0 prices a peer-funded withdrawal using the unsigned common
 * fields and the 230 WU shared input. Its quote omits the 2 WU marker/flag.
 * Accept that exact quote only when our wallet contributes neither funds nor
 * an input. Keep the relay floor and every local spending limit intact.
 */
export function finalSpliceFeeError(
	fee: bigint,
	weight: number,
	t: IFinalSpliceTerms,
	singleShared: boolean
): string | null {
	const strict = checkFeeSufficiency(fee, weight, t.feerate);
	if (
		!strict ||
		t.assetFundingRoots !== undefined ||
		t.localIsSpliceInitiator ||
		!singleShared ||
		t.localDelta !== 0n ||
		t.localFeeBudget !== 0n ||
		t.peerDelta >= 0n
	)
		return strict;
	const referenceFee = BigInt(Math.floor(((weight - 2) * t.feerate) / 1000));
	return fee === referenceFee && fee >= BigInt(Math.ceil(weight / 4))
		? null
		: strict;
}

function ordered<T extends { serialId: bigint }>(
	items: T[],
	ids: Set<bigint>
): T[] {
	for (const { serialId } of items) {
		if (serialId < 0n || serialId > 0xffffffffffffffffn || ids.has(serialId))
			throw new Error('Invalid or repeated splice serial id');
		ids.add(serialId);
	}
	return [...items].sort((a, b) => (a.serialId < b.serialId ? -1 : 1));
}

/** Audit the agreed interactive transaction against the old funding and both signed contributions. */
export function buildFinalSpliceCandidate(
	terms: IFinalSpliceTerms,
	unorderedInputs: IInteractiveTxInput[],
	unorderedOutputs: IInteractiveTxOutput[]
): IFinalSpliceCandidate {
	if (unorderedInputs.length > 252 || unorderedOutputs.length > 252)
		throw new Error('Too many splice inputs or outputs');
	const failure = validateInteractiveTx(
		unorderedInputs,
		unorderedOutputs,
		terms.dust
	);
	if (failure) throw new Error(failure);
	if (
		!Number.isSafeInteger(terms.locktime) ||
		terms.locktime < 0 ||
		terms.locktime > 0xffffffff ||
		!Number.isSafeInteger(terms.feerate) ||
		terms.feerate < 1 ||
		terms.feerate > MAX_SPLICE_FEERATE_PERKW ||
		terms.localFeeBudget < 0n ||
		terms.dust < 1n ||
		terms.oldLocalKey.equals(terms.oldPeerKey) ||
		terms.newLocalKey.equals(terms.newPeerKey) ||
		![
			terms.oldLocalKey,
			terms.oldPeerKey,
			terms.newLocalKey,
			terms.newPeerKey
		].every(isValidPublicKey)
	)
		throw new Error('Invalid final splice terms');
	const roots = terms.assetFundingRoots;
	if (
		roots !== undefined &&
		(!Buffer.isBuffer(roots?.parent) ||
			roots.parent.length !== 32 ||
			!Buffer.isBuffer(roots.candidate) ||
			roots.candidate.length !== 32)
	)
		throw new Error('Asset splicing requires both verified funding roots');
	const parentOutput = terms.parent.outs[terms.parentIndex];
	if (
		!parentOutput ||
		!createTaprootFundingScript(
			terms.oldLocalKey,
			terms.oldPeerKey,
			undefined,
			roots?.parent
		).p2trOutput.equals(parentOutput.script)
	)
		throw new Error('Shared input does not match the active funding keys');
	const newScript = createTaprootFundingScript(
		terms.newLocalKey,
		terms.newPeerKey,
		undefined,
		roots?.candidate
	).p2trOutput;
	const capacity =
		BigInt(parentOutput.value) + terms.localDelta + terms.peerDelta;
	if (capacity < terms.dust || capacity > MAX_MONEY_SATS)
		throw new Error('Invalid spliced capacity');
	const ids = new Set<bigint>();
	const inputs = ordered(unorderedInputs, ids);
	const outputs = ordered(unorderedOutputs, ids);
	const tx = buildSpliceTx(
		inputs,
		outputs.map((o) => ({
			serialId: o.serialId,
			script: o.scriptPubkey,
			valueSats: o.amountSats
		})),
		terms.locktime
	);
	const scripts: Buffer[] = [],
		values: number[] = [],
		localInputs: number[] = [],
		peerInputs: number[] = [];
	const outputOwners: [boolean, boolean] = [false, false];
	const fees = [-terms.localDelta, -terms.peerDelta],
		prevBytes = [0, 0];
	let weight = tx.weight() + 2,
		sharedIndex = -1,
		fundingIndex = -1;
	const parentHash = terms.parent.getHash();
	function side(serial: bigint): number {
		return (serial % 2n === 0n) === terms.localIsSpliceInitiator ? 0 : 1;
	}
	for (const [i, input] of inputs.entries()) {
		if (
			!Number.isInteger(input.sequence) ||
			input.sequence < 0 ||
			input.sequence > MAX_INTERACTIVE_TX_SEQUENCE
		)
			throw new Error('Invalid splice sequence');
		let prevout;
		if (input.isShared) {
			if (
				sharedIndex !== -1 ||
				input.serialId % 2n !== 0n ||
				(input.prevTx?.length ?? 0) > 0 ||
				!input.prevTxid.equals(parentHash) ||
				input.prevOutputIndex !== terms.parentIndex
			)
				throw new Error('Wrong splice shared input');
			sharedIndex = i;
			prevout = parentOutput;
			weight += 66;
		} else {
			const error = validatePeerInputPrevTx(
				input.prevTx,
				input.prevOutputIndex
			);
			if (error) throw new Error(error);
			const owner = side(input.serialId);
			prevBytes[owner] += input.prevTx!.length;
			if (
				input.prevTx!.length > 65535 ||
				prevBytes[owner] > MAX_PEER_PREVTX_BYTES_PER_SESSION
			)
				throw new Error('Splice previous transactions exceed budget');
			const prev = Transaction.fromBuffer(input.prevTx!);
			if (!prev.getHash().equals(input.prevTxid))
				throw new Error('Wrong splice input transaction');
			prevout = prev.outs[input.prevOutputIndex];
			const p2tr =
				prevout.script.length === 34 &&
				prevout.script[0] === 0x51 &&
				prevout.script[1] === 32;
			const p2wpkh =
				prevout.script.length === 22 &&
				prevout.script[0] === 0 &&
				prevout.script[1] === 20;
			if (!p2tr && !p2wpkh) throw new Error('Unsupported splice wallet input');
			fees[owner] += BigInt(prevout.value);
			(owner === 0 ? localInputs : peerInputs).push(i);
			weight += p2tr ? 66 : 107;
		}
		values.push(prevout.value);
		scripts.push(prevout.script);
	}
	for (const [i, out] of outputs.entries()) {
		if (out.scriptPubkey.equals(newScript)) {
			if (
				fundingIndex !== -1 ||
				out.serialId % 2n !== 0n ||
				out.amountSats !== capacity
			)
				throw new Error('Invalid new splice funding output');
			fundingIndex = i;
		} else {
			const owner = side(out.serialId);
			outputOwners[owner] = true;
			fees[owner] -= out.amountSats;
		}
	}
	if (
		sharedIndex < 0 ||
		fundingIndex < 0 ||
		fees.some((f) => f < 0n) ||
		fees[0] > terms.localFeeBudget ||
		values.reduce((a, v) => a + BigInt(v), 0n) > MAX_MONEY_SATS
	)
		throw new Error(
			'Final splice is missing shared funding or exceeds the approved contribution'
		);
	if (weight > MAX_STANDARD_TX_WEIGHT)
		throw new Error('Splice exceeds standard transaction weight');
	const feeError = finalSpliceFeeError(
		fees[0] + fees[1],
		weight,
		terms,
		inputs.length === 1
	);
	if (feeError) throw new Error(feeError);
	return {
		tx,
		sharedIndex,
		fundingIndex,
		scripts,
		values,
		localInputs,
		peerInputs,
		outputOwners,
		digest: taprootKeySpendSighash(tx, sharedIndex, scripts, values)
	};
}
