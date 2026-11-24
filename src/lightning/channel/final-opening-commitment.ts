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
	type ITaprootHtlcOutput,
	type ITaprootLeafSpend
} from '../script/commitment-taproot';
import {
	type IFinalOpeningCandidate,
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
				remote.fundingPubkey
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
	const signedHtlcs = outputMap.htlcs.map((outputIndex, i) => {
		const { htlc, offered, tree, amount } =
			prepared[outputMap.htlcOriginalIndices[i]];
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
					'final'
			  )
			: buildTaprootHtlcSuccessTx(
					tx.getId(),
					outputIndex,
					amount,
					...childKeys,
					undefined,
					'final'
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
