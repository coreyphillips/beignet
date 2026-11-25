import { Transaction } from 'bitcoinjs-lib';
import { REGTEST_CHAIN_HASH } from '../chain/hashes';
import {
	assetSpliceCommitmentBytes,
	type IAssetSpliceWireRecordLimit
} from '../features/asset-splice';
import { isValidPublicKey } from '../crypto/ecdh';
import { sha256 } from '../crypto/provider';
import type { IInteractiveTxInput } from '../interactive-tx/types';
import {
	DUST_LIMIT_SATS,
	MAX_INTERACTIVE_TX_INPUTS,
	MAX_INTERACTIVE_TX_OUTPUTS,
	MAX_INTERACTIVE_TX_SEQUENCE,
	MAX_MONEY_SATS,
	MAX_PEER_PREVTX_BYTES_PER_SESSION,
	validatePeerInputPrevTx
} from '../interactive-tx/validation';
import { MAX_INDEX } from '../keys/shachain';
import {
	decodeSpliceMessage,
	decodeSpliceAckMessage,
	encodeSpliceMessage,
	encodeSpliceAckMessage,
	SPLICE_LOCK_DEPTH_ACCEPT_MAX
} from '../message/splice';
import { createTaprootFundingScript } from '../script/funding-taproot';
import {
	planAssetSpliceBalances,
	type IAssetSpliceBalanceState,
	type IAssetSpliceUnitMovement
} from './asset-splice-balances';
import {
	buildFinalSpliceCandidate,
	type IFinalSpliceTerms
} from './final-splice-candidate';
import { MAX_SPLICE_FEERATE_PERKW } from './splice-weight';

type Pair<T> = readonly [initiator: T, acceptor: T];

export interface IAssetSpliceLayout {
	attempt: Buffer;
	chainHash: Buffer;
	channelId: Buffer;
	init: Buffer;
	ack: Buffer;
	parent: Transaction;
	parentIndex: number;
	parentKeys: Pair<Buffer>;
	parentRoot: Buffer;
	stateNumber: bigint;
	priorDigest?: Buffer;
	feeBudgets: Pair<bigint>;
	maxAcceptedHtlcs: Pair<number>;
	commitmentRecordLimits: Pair<readonly IAssetSpliceWireRecordLimit[]>;
	dust: bigint;
	parentBalances: IAssetSpliceBalanceState;
	movements: readonly IAssetSpliceUnitMovement[];
	proposalDigests: Pair<Buffer>;
	inputs: readonly IInteractiveTxInput[];
	outputs: readonly {
		serialId: bigint;
		role: 'funding' | 'change' | 'withdrawal';
		amountSats: bigint;
		/** Authenticated provider descriptor, including recipients, keys, tree and per-issuance amounts. */
		descriptorHash: Buffer;
	}[];
}

function hashHex(value: Buffer): string {
	if (!Buffer.isBuffer(value) || value.length !== 32)
		throw new Error('Invalid asset splice digest');
	return value.toString('hex');
}

function hashPair(values: Pair<Buffer>): string[] {
	if (values.length !== 2)
		throw new Error('Asset splice requires both peer digests');
	return [hashHex(values[0]), hashHex(values[1])];
}

function inRange(value: bigint, min: bigint, max: bigint): boolean {
	return typeof value === 'bigint' && value >= min && value <= max;
}

function digest(fields: unknown[], stage: 'layout' | 'final'): Buffer {
	// Fixed-position arrays of ASCII strings and bounded integers. All large integers are decimal strings.
	return sha256(
		Buffer.from(
			'beignet/asset-splice/' + stage + '/v1\0' + JSON.stringify(fields),
			'utf8'
		)
	);
}

function checkSerials(
	items: readonly { serialId: bigint }[],
	max: number,
	serials: Set<bigint>
): void {
	if (!Array.isArray(items) || items.length < 1 || items.length > max)
		throw new Error('Invalid asset splice item count');
	let previous = -1n;
	for (const { serialId } of items) {
		if (
			!inRange(serialId, 0n, 0xffffffffffffffffn) ||
			serialId <= previous ||
			serials.has(serialId)
		)
			throw new Error('Invalid asset splice serial order or reuse');
		serials.add(serialId);
		previous = serialId;
	}
}

function checkLayout(layout: IAssetSpliceLayout) {
	const init = decodeSpliceMessage(layout.init);
	const ack = decodeSpliceAckMessage(layout.ack);
	if (
		!encodeSpliceMessage(init).equals(layout.init) ||
		!encodeSpliceAckMessage(ack).equals(layout.ack) ||
		!layout.chainHash.equals(REGTEST_CHAIN_HASH) ||
		!init.channelId.equals(layout.channelId) ||
		!ack.channelId.equals(layout.channelId) ||
		init.requireConfirmedInputs ||
		ack.requireConfirmedInputs ||
		!init.lockDepth ||
		init.lockDepth > SPLICE_LOCK_DEPTH_ACCEPT_MAX ||
		ack.lockDepth !== init.lockDepth ||
		init.fundingFeeratePerkw < 1 ||
		init.fundingFeeratePerkw > MAX_SPLICE_FEERATE_PERKW ||
		!inRange(layout.stateNumber, 0n, MAX_INDEX) ||
		layout.stateNumber > 0n !== (layout.priorDigest !== undefined) ||
		!inRange(layout.dust, 1n, MAX_MONEY_SATS) ||
		layout.feeBudgets.length !== 2 ||
		!layout.feeBudgets.every((cap) => inRange(cap, 0n, MAX_MONEY_SATS)) ||
		layout.parentKeys.length !== 2
	)
		throw new Error('Invalid asset splice negotiation terms');
	const parent = layout.parent.outs[layout.parentIndex];
	const keys = [...layout.parentKeys, init.fundingPubkey, ack.fundingPubkey];
	if (
		!Number.isInteger(layout.parentIndex) ||
		!parent ||
		!keys.every((key) => Buffer.isBuffer(key) && isValidPublicKey(key)) ||
		new Set(keys.map((key) => key.subarray(1).toString('hex'))).size !== 4 ||
		!parent.script.equals(
			createTaprootFundingScript(
				...layout.parentKeys,
				undefined,
				layout.parentRoot
			).p2trOutput
		)
	)
		throw new Error('Invalid asset splice parent or funding keys');
	const serials = new Set<bigint>();
	checkSerials(layout.inputs, MAX_INTERACTIVE_TX_INPUTS, serials);
	checkSerials(layout.outputs, MAX_INTERACTIVE_TX_OUTPUTS, serials);
	const parentHash = layout.parent.getHash();
	const prevouts = new Set<string>();
	const fees = [-init.relativeSatoshis, -ack.relativeSatoshis];
	const prevTxBytes = [0, 0];
	let sharedInputs = 0;
	const inputs = layout.inputs.map((input) => {
		const { serialId, prevTxid, prevOutputIndex, sequence, prevTx } = input;
		const txid = hashHex(prevTxid);
		const outpoint = txid + ':' + prevOutputIndex;
		if (
			!Number.isInteger(prevOutputIndex) ||
			prevOutputIndex < 0 ||
			prevOutputIndex > 0xffffffff ||
			!Number.isInteger(sequence) ||
			sequence < 0 ||
			sequence > MAX_INTERACTIVE_TX_SEQUENCE ||
			prevouts.has(outpoint) ||
			(input.prevTxVout !== undefined && input.prevTxVout !== prevOutputIndex)
		)
			throw new Error('Invalid asset splice input');
		prevouts.add(outpoint);
		const owner = Number(serialId & 1n);
		if (input.isShared === true) {
			if (
				++sharedInputs !== 1 ||
				owner !== 0 ||
				!parentHash.equals(prevTxid) ||
				layout.parentIndex !== prevOutputIndex ||
				prevTx?.length
			)
				throw new Error('Incorrect shared asset splice input');
		} else {
			if (
				(input.isShared !== undefined && input.isShared !== false) ||
				!Buffer.isBuffer(prevTx) ||
				prevTx.length > 65535 ||
				(prevTxBytes[owner] += prevTx.length) >
					MAX_PEER_PREVTX_BYTES_PER_SESSION ||
				validatePeerInputPrevTx(prevTx, prevOutputIndex)
			)
				throw new Error('Invalid external asset splice input');
			const previous = Transaction.fromBuffer(prevTx);
			if (
				!previous.getHash().equals(prevTxid) ||
				!previous.toBuffer().equals(prevTx)
			)
				throw new Error('External asset splice transaction mismatch');
			fees[owner] += BigInt(previous.outs[prevOutputIndex].value);
		}
		return [
			serialId.toString(),
			txid,
			prevOutputIndex,
			sequence,
			input.isShared === true,
			prevTx?.length ? hashHex(sha256(prevTx)) : null
		];
	});
	const capacity =
		BigInt(parent.value) + init.relativeSatoshis + ack.relativeSatoshis;
	let fundingIndex = -1;
	let total = 0n;
	const outputs = layout.outputs.map((o, i) => {
		const owner = Number(o.serialId & 1n);
		if (
			!inRange(
				o.amountSats,
				layout.dust > DUST_LIMIT_SATS ? layout.dust : DUST_LIMIT_SATS,
				MAX_MONEY_SATS
			) ||
			(total += o.amountSats) > MAX_MONEY_SATS
		)
			throw new Error('Invalid asset splice output amount');
		if (o.role === 'funding') {
			if (fundingIndex !== -1 || owner !== 0 || o.amountSats !== capacity)
				throw new Error('Incorrect asset splice funding output');
			fundingIndex = i;
		} else {
			if (o.role !== 'withdrawal' && o.role !== 'change')
				throw new Error('Unknown asset splice output role');
			fees[owner] -= o.amountSats;
		}
		return [
			o.serialId.toString(),
			o.role,
			o.amountSats.toString(),
			hashHex(o.descriptorHash)
		];
	});
	if (
		sharedInputs !== 1 ||
		fundingIndex < 0 ||
		fees.some((fee, i) => !inRange(fee, 0n, layout.feeBudgets[i]))
	)
		throw new Error(
			'Missing shared funding or asset splice exceeds fee consent'
		);
	const balances = planAssetSpliceBalances(
		layout.parentBalances,
		layout.movements
	);
	const issues = balances.parent.issuances.map((v) => [
		v.assetId,
		v.funding.toString(),
		v.initiator.toString(),
		v.acceptor.toString()
	]);
	const htlcs = [...balances.parent.htlcs]
		.sort((a, b) => {
			if (a.offeredBy !== b.offeredBy)
				return a.offeredBy === 'initiator' ? -1 : 1;
			return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
		})
		.map((v) => [
			v.offeredBy,
			v.id.toString(),
			v.paymentHash,
			v.cltvExpiry,
			v.amountMsat.toString(),
			v.allocations.map((a) => [a.assetId, a.units.toString()])
		]);
	const moves = [...layout.movements]
		.sort((a, b) =>
			a.assetId < b.assetId
				? -1
				: a.assetId > b.assetId
				? 1
				: Number(a.owner === 'acceptor') - Number(b.owner === 'acceptor')
		)
		.map((v) => [
			v.assetId,
			v.owner,
			v.inputs.toString(),
			v.change.toString(),
			v.withdrawals.toString(),
			v.delta.toString()
		]);
	if (layout.commitmentRecordLimits.length !== 2)
		throw new Error(
			'Asset splice requires commitment wire budgets for both holders'
		);
	const signatureLimits = layout.commitmentRecordLimits.map((records) => {
		assetSpliceCommitmentBytes(layout.maxAcceptedHtlcs, records);
		return [...records]
			.sort((a, b) => (a.type < b.type ? -1 : 1))
			.map((r) => [r.type.toString(), r.maxBytes]);
	});
	const layoutDigest = digest(
		[
			hashHex(layout.attempt),
			hashHex(layout.chainHash),
			hashHex(layout.channelId),
			layout.init.toString('hex'),
			layout.ack.toString('hex'),
			hashHex(parentHash),
			layout.parentIndex,
			layout.parentKeys.map((k) => k.toString('hex')),
			hashHex(layout.parentRoot),
			layout.stateNumber.toString(),
			...(layout.priorDigest ? [hashHex(layout.priorDigest)] : []),
			layout.feeBudgets.map((x) => x.toString()),
			layout.maxAcceptedHtlcs,
			signatureLimits,
			layout.dust.toString(),
			issues,
			htlcs,
			moves,
			hashPair(layout.proposalDigests),
			inputs,
			outputs
		],
		'layout'
	);
	return { init, ack, balances, fundingIndex, layoutDigest };
}

/** Both parties use initiator order for roles, serials and authenticated proposals. */
export function assetSpliceLayoutDigest(layout: IAssetSpliceLayout): Buffer {
	return checkLayout(layout).layoutDigest;
}

/** The host independently verifies all virtual signatures, receivers, histories and output exclusions for this layout. */
export function verifyAssetSpliceCandidate(
	layout: IAssetSpliceLayout,
	acknowledged: Buffer,
	isInitiator: boolean,
	frozen: Transaction,
	verified: {
		/** Engine layout attached to the provider's verified virtual transfers. */
		layoutDigest: Buffer;
		transaction: Buffer;
		fundingRoot: Buffer;
		proofDigest: Buffer;
		fundingProofs?: Buffer;
	},
	authorizations: Pair<Buffer>
) {
	const { init, ack, balances, fundingIndex, layoutDigest } =
		checkLayout(layout);
	if (
		!layoutDigest.equals(acknowledged) ||
		!Buffer.isBuffer(verified.layoutDigest) ||
		!layoutDigest.equals(verified.layoutDigest) ||
		!frozen.toBuffer().equals(verified.transaction) ||
		frozen.outs.length !== layout.outputs.length ||
		typeof isInitiator !== 'boolean'
	)
		throw new Error(
			'Frozen asset splice disagrees with the acknowledged transaction or layout'
		);
	const local = isInitiator ? init : ack;
	const peer = isInitiator ? ack : init;
	// bitcoinjs keeps its input and output buffers by reference. Give the signer an owned snapshot.
	const terms: IFinalSpliceTerms = {
		parent: Transaction.fromBuffer(layout.parent.toBuffer()),
		parentIndex: layout.parentIndex,
		oldLocalKey: Buffer.from(layout.parentKeys[isInitiator ? 0 : 1]),
		oldPeerKey: Buffer.from(layout.parentKeys[isInitiator ? 1 : 0]),
		newLocalKey: Buffer.from(local.fundingPubkey),
		newPeerKey: Buffer.from(peer.fundingPubkey),
		localIsSpliceInitiator: isInitiator,
		localDelta: local.relativeSatoshis,
		peerDelta: peer.relativeSatoshis,
		localFeeBudget: layout.feeBudgets[isInitiator ? 0 : 1],
		feerate: init.fundingFeeratePerkw,
		dust: layout.dust,
		locktime: init.locktime,
		assetFundingRoots: {
			parent: Buffer.from(layout.parentRoot),
			candidate: Buffer.from(verified.fundingRoot)
		}
	};
	const outputs = layout.outputs.map((o, i) => ({
		serialId: o.serialId,
		amountSats: o.amountSats,
		scriptPubkey: Buffer.from(frozen.outs[i].script)
	}));
	const inputs = layout.inputs.map((i) => ({
		...i,
		prevTxid: Buffer.from(i.prevTxid),
		prevTx: i.prevTx && Buffer.from(i.prevTx)
	}));
	const candidate = buildFinalSpliceCandidate(terms, inputs, outputs);
	if (
		candidate.fundingIndex !== fundingIndex ||
		!candidate.tx.toBuffer().equals(verified.transaction)
	)
		throw new Error('Final asset splice disagrees with the approved layout');
	const result = {
		terms,
		candidate,
		balances,
		layoutDigest: Buffer.from(layoutDigest),
		digest: digest(
			[
				hashHex(layoutDigest),
				hashHex(candidate.tx.getHash()),
				hashHex(verified.fundingRoot),
				hashPair(authorizations),
				hashHex(verified.proofDigest)
			],
			'final'
		)
	};
	constructionViews.set(result, {
		transaction: candidate.tx.toHex(),
		layoutDigest: hashHex(layoutDigest),
		finalDigest: hashHex(result.digest),
		fundingProofHash: verified.fundingProofs?.length
			? sha256(verified.fundingProofs).toString('hex')
			: undefined,
		minimumDepth: init.lockDepth!,
		terms: copyConstructionTerms(terms)
	});
	return result;
}

function copyConstructionTerms(terms: IFinalSpliceTerms): IFinalSpliceTerms {
	const roots = terms.assetFundingRoots!;
	return {
		...terms,
		parent: Transaction.fromBuffer(terms.parent.toBuffer()),
		oldLocalKey: Buffer.from(terms.oldLocalKey),
		oldPeerKey: Buffer.from(terms.oldPeerKey),
		newLocalKey: Buffer.from(terms.newLocalKey),
		newPeerKey: Buffer.from(terms.newPeerKey),
		assetFundingRoots: {
			parent: Buffer.from(roots.parent),
			candidate: Buffer.from(roots.candidate)
		}
	};
}
const constructionViews = new WeakMap<
	object,
	{
		transaction: string;
		layoutDigest: string;
		finalDigest: string;
		fundingProofHash: string | undefined;
		minimumDepth: number;
		terms: IFinalSpliceTerms;
	}
>();

/** Pin construction to the exact provider-verified transaction even if a caller mutates its returned buffers. */
export function assetSpliceConstructionView(
	layout: IAssetSpliceLayout,
	verified: ReturnType<typeof verifyAssetSpliceCandidate>
) {
	const view = constructionViews.get(verified);
	if (
		!view ||
		view.layoutDigest !== hashHex(assetSpliceLayoutDigest(layout)) ||
		view.layoutDigest !== hashHex(verified.layoutDigest) ||
		view.finalDigest !== hashHex(verified.digest) ||
		view.transaction !== verified.candidate.tx.toHex()
	)
		throw new Error(
			'Asset splice construction differs from the verified manifest'
		);
	return { ...view, terms: copyConstructionTerms(view.terms) };
}
