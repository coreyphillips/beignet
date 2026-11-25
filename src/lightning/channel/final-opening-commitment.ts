import type { IFinalFundingReference } from './final-splice-candidate';
import { createTaprootFundingScript } from '../script/funding-taproot';
import { Transaction } from 'bitcoinjs-lib';
import { MAX_INDEX } from '../keys/shachain';
import type { ICommitmentTxResult } from '../script/commitment';
import type { ICommitmentKeys } from './commitment-builder';
import {
	buildTaprootHtlcSuccessTx,
	buildTaprootHtlcTimeoutTx,
	taprootHtlcLeafSighash
} from '../script/htlc-taproot';
import { isValidPublicKey } from '../crypto/ecdh';
import type { IChannelBasepoints } from '../keys/derivation';
import { ANCHOR_TOTAL_COST } from '../script/anchor';
import {
	buildCommitmentTx,
	calculateObscuredCommitmentNumber
} from '../script/commitment';
import {
	buildTaprootToLocalOutput,
	buildTaprootToRemoteOutput,
	buildTaprootAnchorOutput,
	buildTaprootOfferedHtlcOutput,
	buildTaprootReceivedHtlcOutput,
	assertFinalTaprootHtlcExpiry,
	type ITaprootAuxLeaf,
	type ITaprootHtlcOutput,
	type ITaprootLeafSpend
} from '../script/commitment-taproot';
import {
	type IFinalOpeningCandidate,
	validateAssetOpening,
	validateFinalOpening
} from '../storage/final-opening-candidate';
import {
	calculateCommitmentFee,
	deriveCommitmentKeys
} from './commitment-builder';
import { MIN_DUST_LIMIT_SATOSHIS, MAX_DUST_LIMIT_SATOSHIS } from './types';
import { deriveV2ChannelId } from './validation';

type OpeningBasepoints = Record<keyof IChannelBasepoints, string>;

export interface IFinalOpeningTerms {
	localBasepoints: OpeningBasepoints;
	remoteBasepoints: OpeningBasepoints;
	localToSelfDelay: number;
	remoteToSelfDelay: number;
	localDustLimitSatoshis: number;
	remoteDustLimitSatoshis: number;
	commitmentFeeratePerKw: number;
}

function readPoint(hex: string): Buffer {
	if (typeof hex !== 'string' || !/^(02|03)[0-9a-f]{64}$/.test(hex))
		throw new Error('Invalid opening basepoint encoding');
	const key = Buffer.from(hex, 'hex');
	if (!isValidPublicKey(key)) throw new Error('Invalid opening basepoint');
	return key;
}

function readBasepoints(points: OpeningBasepoints): IChannelBasepoints {
	if (
		Object.keys(points).length !== 6 ||
		![
			'fundingPubkey',
			'revocationBasepoint',
			'paymentBasepoint',
			'delayedPaymentBasepoint',
			'htlcBasepoint',
			'firstPerCommitmentPoint'
		].every((key) => Object.prototype.hasOwnProperty.call(points, key))
	)
		throw new Error('Unexpected opening basepoints');
	return {
		fundingPubkey: readPoint(points.fundingPubkey),
		revocationBasepoint: readPoint(points.revocationBasepoint),
		paymentBasepoint: readPoint(points.paymentBasepoint),
		delayedPaymentBasepoint: readPoint(points.delayedPaymentBasepoint),
		htlcBasepoint: readPoint(points.htlcBasepoint),
		firstPerCommitmentPoint: readPoint(points.firstPerCommitmentPoint)
	};
}

function requireRange(value: number, min: number, max: number): void {
	if (!Number.isSafeInteger(value) || value < min || value > max)
		throw new Error('Opening commitment terms out of range');
}

export interface IFinalCommitmentHtlc {
	id: bigint;
	offeredBy: 'local' | 'peer';
	amountMsat: bigint;
	paymentHash: Buffer;
	cltvExpiry: number;
}

export interface IFinalBalances {
	localBalanceMsat: bigint;
	remoteBalanceMsat: bigint;
}

export interface IFinalCommitmentView {
	tx: Transaction;
	outputMap: ICommitmentTxResult['outputMap'];
	keys: ICommitmentKeys;
	toSelfDelay: number;
	htlcs: Array<{
		htlc: IFinalCommitmentHtlc;
		offered: boolean;
		outputIndex: number;
		tree: ITaprootHtlcOutput;
		leaf: ITaprootLeafSpend;
		secondLevelTx: Transaction;
		digest: Buffer;
	}>;
}

/** The first Bitcoin-only commitment has no HTLCs, push or lease. */
export function buildFinalOpeningCommitment(
	candidate: IFinalOpeningCandidate,
	terms: IFinalOpeningTerms,
	owner: 'local' | 'remote'
): Transaction {
	const point = (
		owner === 'local' ? terms.localBasepoints : terms.remoteBasepoints
	).firstPerCommitmentPoint;
	return buildFinalCommitmentView(
		candidate,
		terms,
		owner,
		readPoint(point),
		0n,
		{
			localBalanceMsat: BigInt(candidate.localContributionSats) * 1000n,
			remoteBalanceMsat: BigInt(candidate.remoteContributionSats) * 1000n
		},
		[]
	).tx;
}

/** Balances exclude pending HTLCs and include the opener's commitment fee and anchors. */
export function buildFinalCommitmentView(
	candidate: IFinalOpeningCandidate,
	terms: IFinalOpeningTerms,
	owner: 'local' | 'remote',
	point: Buffer,
	height: bigint,
	balances: IFinalBalances,
	htlcs: readonly IFinalCommitmentHtlc[],
	fundingRef?: IFinalFundingReference
): IFinalCommitmentView {
	validateFinalOpening(candidate);
	return buildValidatedView(
		candidate,
		terms,
		owner,
		point,
		height,
		balances,
		htlcs,
		fundingRef
	);
}

/** Leaves are named for the holder of this commitment, on either peer. */
export interface IAssetOpeningLeaves {
	fundingRoot: Buffer;
	toLocal?: ITaprootAuxLeaf;
	toRemote?: ITaprootAuxLeaf;
}

export interface IAssetSpliceLeaves extends IAssetOpeningLeaves {
	htlcs?: readonly {
		offeredBy: IFinalCommitmentHtlc['offeredBy'];
		id: bigint;
		output: ITaprootAuxLeaf;
		secondLevel: ITaprootAuxLeaf;
	}[];
}

export function buildAssetSpliceCommitment(
	opening: IFinalOpeningCandidate,
	terms: IFinalOpeningTerms,
	holder: 'local' | 'remote',
	point: Buffer,
	height: bigint,
	balances: IFinalBalances,
	htlcs: readonly IFinalCommitmentHtlc[],
	funding: IFinalFundingReference,
	openingRoot: Buffer,
	assets: IAssetSpliceLeaves
): IFinalCommitmentView {
	validateAssetOpening(opening, openingRoot);
	if (
		!funding ||
		!Number.isSafeInteger(funding.fundingOutputIndex) ||
		funding.fundingOutputIndex < 0
	)
		throw new Error('Missing selected asset funding outpoint');
	const validateLeaf = (leaf: ITaprootAuxLeaf) => {
		if (!leaf || !Buffer.isBuffer(leaf.script) || leaf.script.length === 0)
			throw new Error('Missing asset commitment leaf script');
	};
	if (assets.toLocal !== undefined) validateLeaf(assets.toLocal);
	if (assets.toRemote !== undefined) validateLeaf(assets.toRemote);
	for (const h of assets.htlcs ?? []) {
		if (
			(h.offeredBy !== 'local' && h.offeredBy !== 'peer') ||
			typeof h.id !== 'bigint' ||
			h.id < 0n ||
			h.id > 0xffffffffffffffffn
		)
			throw new Error('Invalid asset HTLC identity');
		validateLeaf(h.output);
		validateLeaf(h.secondLevel);
	}
	if (!Buffer.isBuffer(assets.fundingRoot) || assets.fundingRoot.length !== 32)
		throw new Error(
			'Asset splice commitment requires its selected funding root'
		);
	return buildValidatedView(
		opening,
		terms,
		holder,
		point,
		height,
		balances,
		htlcs,
		funding,
		assets
	);
}

export function buildAssetOpeningCommitment(
	candidate: IFinalOpeningCandidate,
	terms: IFinalOpeningTerms,
	owner: 'local' | 'remote',
	assets: IAssetOpeningLeaves
): IFinalCommitmentView {
	validateAssetOpening(candidate, assets.fundingRoot);
	const holder =
		owner === 'local' ? terms.localBasepoints : terms.remoteBasepoints;
	return buildValidatedView(
		candidate,
		terms,
		owner,
		readPoint(holder.firstPerCommitmentPoint),
		0n,
		{
			localBalanceMsat: BigInt(candidate.localContributionSats) * 1000n,
			remoteBalanceMsat: BigInt(candidate.remoteContributionSats) * 1000n
		},
		[],
		undefined,
		assets
	);
}

function buildValidatedView(
	candidate: IFinalOpeningCandidate,
	terms: IFinalOpeningTerms,
	owner: 'local' | 'remote',
	point: Buffer,
	height: bigint,
	balances: IFinalBalances,
	htlcs: readonly IFinalCommitmentHtlc[],
	fundingRef?: IFinalFundingReference,
	assets?: IAssetSpliceLeaves
): IFinalCommitmentView {
	if (
		Object.keys(terms).length !== 7 ||
		![
			'localBasepoints',
			'remoteBasepoints',
			'localToSelfDelay',
			'remoteToSelfDelay',
			'localDustLimitSatoshis',
			'remoteDustLimitSatoshis',
			'commitmentFeeratePerKw'
		].every((key) => Object.prototype.hasOwnProperty.call(terms, key))
	)
		throw new Error('Unexpected opening commitment terms');
	if (owner !== 'local' && owner !== 'remote')
		throw new Error('Invalid opening commitment owner');
	const local = readBasepoints(terms.localBasepoints);
	const remote = readBasepoints(terms.remoteBasepoints);
	if (
		terms.localBasepoints.fundingPubkey !== candidate.localFundingPubkey ||
		terms.remoteBasepoints.fundingPubkey !== candidate.remoteFundingPubkey ||
		local.revocationBasepoint.equals(remote.revocationBasepoint) ||
		deriveV2ChannelId(
			local.revocationBasepoint,
			remote.revocationBasepoint
		).toString('hex') !== candidate.channelId
	)
		throw new Error('Opening basepoints do not match the funding candidate');

	requireRange(terms.commitmentFeeratePerKw, 1, 0xffffffff);
	for (const dust of [
		terms.localDustLimitSatoshis,
		terms.remoteDustLimitSatoshis
	])
		requireRange(
			dust,
			Number(MIN_DUST_LIMIT_SATOSHIS),
			Number(MAX_DUST_LIMIT_SATOSHIS)
		);
	for (const delay of [terms.localToSelfDelay, terms.remoteToSelfDelay])
		requireRange(delay, 1, 2016);

	const selected = fundingRef ?? candidate;
	const funding = Transaction.fromHex(selected.fundingTxHex);
	const fundingIndex = selected.fundingOutputIndex;
	if (fundingRef) {
		local.fundingPubkey = readPoint(fundingRef.localFundingPubkey);
		remote.fundingPubkey = readPoint(fundingRef.remoteFundingPubkey);
		const actual = funding.outs[fundingIndex]?.script;
		if (
			!actual ||
			local.fundingPubkey.equals(remote.fundingPubkey) ||
			!createTaprootFundingScript(
				local.fundingPubkey,
				remote.fundingPubkey,
				undefined,
				assets?.fundingRoot
			).p2trOutput.equals(actual)
		)
			throw new Error(
				'Commitment funding output disagrees with the agreed keys'
			);
	}
	const localOwner = owner === 'local';
	const holder = localOwner ? local : remote;
	const peer = localOwner ? remote : local;
	const opener = candidate.isInitiator ? local : remote;
	const acceptor = candidate.isInitiator ? remote : local;
	const keys = deriveCommitmentKeys(local, remote, point, localOwner);
	if (
		!Buffer.isBuffer(point) ||
		point.length !== 33 ||
		!isValidPublicKey(point) ||
		height < 0n ||
		height > MAX_INDEX
	)
		throw new Error('Invalid commitment height or per-commitment point');
	const dust = BigInt(
		localOwner ? terms.localDustLimitSatoshis : terms.remoteDustLimitSatoshis
	);
	let total = balances.localBalanceMsat + balances.remoteBalanceMsat;
	const seen = new Set<string>();
	const prepared: {
		htlc: IFinalCommitmentHtlc;
		offered: boolean;
		tree: ITaprootHtlcOutput;
		amount: bigint;
	}[] = [];
	for (const htlc of htlcs) {
		const { id, offeredBy, amountMsat, paymentHash, cltvExpiry } = htlc;
		const htlcKey = offeredBy + '/' + id;
		if (
			typeof id !== 'bigint' ||
			typeof amountMsat !== 'bigint' ||
			id < 0n ||
			id > 0xffffffffffffffffn ||
			amountMsat <= 0n ||
			(offeredBy !== 'local' && offeredBy !== 'peer') ||
			!Buffer.isBuffer(paymentHash) ||
			paymentHash.length !== 32 ||
			seen.has(htlcKey)
		)
			throw new Error('Invalid commitment HTLC');
		assertFinalTaprootHtlcExpiry(cltvExpiry);
		seen.add(htlcKey);
		total += amountMsat;
		const amount = amountMsat / 1000n;
		if (amount < dust) continue;
		const offered = localOwner === (offeredBy === 'local');
		const args = [
			keys.revocationPubkey,
			keys.localHtlcPubkey,
			keys.remoteHtlcPubkey,
			paymentHash
		] as const;
		const tree = offered
			? buildTaprootOfferedHtlcOutput(...args, undefined, 'final')
			: buildTaprootReceivedHtlcOutput(...args, cltvExpiry, undefined, 'final');
		prepared.push({ htlc, offered, tree, amount });
	}
	if (total !== BigInt(funding.outs[fundingIndex].value) * 1000n)
		throw new Error(
			'Commitment balances and HTLCs do not conserve channel capacity'
		);
	const cost =
		calculateCommitmentFee(
			terms.commitmentFeeratePerKw,
			prepared.length,
			true,
			true
		) + ANCHOR_TOTAL_COST;
	const localBalance =
		balances.localBalanceMsat / 1000n - (candidate.isInitiator ? cost : 0n);
	const remoteBalance =
		balances.remoteBalanceMsat / 1000n - (candidate.isInitiator ? 0n : cost);
	if (
		balances.localBalanceMsat < 0n ||
		balances.remoteBalanceMsat < 0n ||
		localBalance < 0n ||
		remoteBalance < 0n
	)
		throw new Error('Opener cannot fund the commitment fee and anchors');
	if (localBalance < dust && remoteBalance < dust && !prepared.length)
		throw new Error('Commitment has no spendable balance');
	const toSelfDelay = localOwner
		? terms.remoteToSelfDelay
		: terms.localToSelfDelay;
	const { tx, outputMap } = buildCommitmentTx({
		fundingTxid: funding.getHash().toString('hex'),
		fundingOutputIndex: fundingIndex,
		fundingAmount: BigInt(funding.outs[fundingIndex].value),
		obscuredCommitmentNumber: calculateObscuredCommitmentNumber(
			opener.paymentBasepoint,
			acceptor.paymentBasepoint,
			height
		),
		localAmount: localOwner ? localBalance : remoteBalance,
		remoteAmount: localOwner ? remoteBalance : localBalance,
		revocationPubkey: keys.revocationPubkey,
		localDelayedPubkey: keys.localDelayedPubkey,
		remotePaymentPubkey: peer.paymentBasepoint,
		toSelfDelay,
		dustLimitSatoshis: dust,
		useAnchors: true,
		htlcOutputs: prepared.map(({ htlc, tree, amount }) => ({
			htlcId: htlc.id,
			script: Buffer.alloc(0),
			amount,
			cltvExpiry: htlc.cltvExpiry,
			paymentHash: htlc.paymentHash,
			taprootScript: tree.output
		})),
		localFundingPubkey: holder.fundingPubkey,
		remoteFundingPubkey: peer.fundingPubkey,
		taprootToLocalScript: buildTaprootToLocalOutput(
			keys.revocationPubkey,
			keys.localDelayedPubkey,
			toSelfDelay,
			undefined,
			'final'
		).output,
		taprootToRemoteScript: buildTaprootToRemoteOutput(
			peer.paymentBasepoint,
			undefined,
			'final'
		).output,
		taprootAnchorLocalScript: buildTaprootAnchorOutput(keys.localDelayedPubkey)
			.output,
		taprootAnchorRemoteScript: buildTaprootAnchorOutput(peer.paymentBasepoint)
			.output
	});
	// A virtual transfer commits to output indexes. Both peers first sort the
	// ordinary outputs, then attach the signed leaves at those fixed indexes.
	if (assets?.toLocal) {
		const index = outputMap.toLocal;
		if (index === undefined)
			throw new Error('Missing carrier for local asset payout');
		tx.outs[index].script = buildTaprootToLocalOutput(
			keys.revocationPubkey,
			keys.localDelayedPubkey,
			toSelfDelay,
			undefined,
			{ finalLeaf: assets.toLocal }
		).output;
	}
	if (assets?.toRemote) {
		const index = outputMap.toRemote;
		if (index === undefined)
			throw new Error('Missing carrier for remote asset payout');
		tx.outs[index].script = buildTaprootToRemoteOutput(
			peer.paymentBasepoint,
			undefined,
			{ finalLeaf: assets.toRemote }
		).output;
	}
	const byHtlc = new Map<
		string,
		NonNullable<IAssetSpliceLeaves['htlcs']>[number]
	>();
	for (const leaves of assets?.htlcs ?? []) {
		const key = leaves.offeredBy + '/' + leaves.id;
		if (byHtlc.has(key) || !leaves.output || !leaves.secondLevel)
			throw new Error('Incomplete or duplicate asset HTLC leaves');
		byHtlc.set(key, leaves);
	}
	// Every child spends the final parent txid, including children with no asset leaves.
	let attached = 0;
	for (const [i, index] of outputMap.htlcs.entries()) {
		const item = prepared[outputMap.htlcOriginalIndices[i]];
		const h = item.htlc;
		const leaves = byHtlc.get(h.offeredBy + '/' + h.id);
		if (!leaves) continue;
		const args = [
			keys.revocationPubkey,
			keys.localHtlcPubkey,
			keys.remoteHtlcPubkey,
			h.paymentHash
		] as const;
		const format = { finalLeaf: leaves.output };
		item.tree = item.offered
			? buildTaprootOfferedHtlcOutput(...args, undefined, format)
			: buildTaprootReceivedHtlcOutput(
					...args,
					h.cltvExpiry,
					undefined,
					format
			  );
		tx.outs[index].script = item.tree.output;
		attached++;
	}
	if (attached !== byHtlc.size)
		throw new Error(
			'Asset HTLC requires a matching untrimmed commitment output'
		);
	const signedHtlcs = outputMap.htlcs.map((outputIndex, i) => {
		const { htlc, offered, tree, amount } =
			prepared[outputMap.htlcOriginalIndices[i]];
		const leaves = byHtlc.get(htlc.offeredBy + '/' + htlc.id);
		const childFormat = leaves ? { finalLeaf: leaves.secondLevel } : 'final';
		const childKeys = [
			keys.revocationPubkey,
			keys.localDelayedPubkey,
			toSelfDelay
		] as const;
		const secondLevelTx = offered
			? buildTaprootHtlcTimeoutTx(
					tx.getId(),
					outputIndex,
					amount,
					htlc.cltvExpiry,
					...childKeys,
					undefined,
					childFormat
			  )
			: buildTaprootHtlcSuccessTx(
					tx.getId(),
					outputIndex,
					amount,
					...childKeys,
					undefined,
					childFormat
			  );
		const leaf = offered ? tree.timeout : tree.success;
		return {
			htlc,
			offered,
			outputIndex,
			tree,
			leaf,
			secondLevelTx,
			digest: taprootHtlcLeafSighash(
				secondLevelTx,
				tree.output,
				Number(amount),
				leaf.script
			)
		};
	});
	return { tx, outputMap, keys, toSelfDelay, htlcs: signedHtlcs };
}
