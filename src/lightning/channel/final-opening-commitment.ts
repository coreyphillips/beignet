import { Transaction } from 'bitcoinjs-lib';
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
	buildTaprootAnchorOutput
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

/** The first Bitcoin-only commitment has no HTLCs, push or lease. */
export function buildFinalOpeningCommitment(
	candidate: IFinalOpeningCandidate,
	terms: IFinalOpeningTerms,
	owner: 'local' | 'remote'
): Transaction {
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

	const localOwner = owner === 'local';
	const holder = localOwner ? local : remote;
	const peer = localOwner ? remote : local;
	const opener = candidate.isInitiator ? local : remote;
	const acceptor = candidate.isInitiator ? remote : local;
	const keys = deriveCommitmentKeys(
		local,
		remote,
		holder.firstPerCommitmentPoint,
		localOwner
	);
	const cost =
		calculateCommitmentFee(terms.commitmentFeeratePerKw, 0, true, true) +
		ANCHOR_TOTAL_COST;
	const localBalance =
		BigInt(candidate.localContributionSats) -
		(candidate.isInitiator ? cost : 0n);
	const remoteBalance =
		BigInt(candidate.remoteContributionSats) -
		(candidate.isInitiator ? 0n : cost);
	if (localBalance < 0n || remoteBalance < 0n)
		throw new Error(
			'Opener cannot fund the opening commitment fee and anchors'
		);
	const dust = BigInt(
		localOwner ? terms.localDustLimitSatoshis : terms.remoteDustLimitSatoshis
	);
	if (localBalance < dust && remoteBalance < dust)
		throw new Error('Opening commitment has no spendable balance');
	const toSelfDelay = localOwner
		? terms.remoteToSelfDelay
		: terms.localToSelfDelay;
	const funding = Transaction.fromHex(candidate.fundingTxHex);
	return buildCommitmentTx({
		fundingTxid: funding.getHash().toString('hex'),
		fundingOutputIndex: candidate.fundingOutputIndex,
		fundingAmount: BigInt(funding.outs[candidate.fundingOutputIndex].value),
		obscuredCommitmentNumber: calculateObscuredCommitmentNumber(
			opener.paymentBasepoint,
			acceptor.paymentBasepoint,
			0n
		),
		localAmount: localOwner ? localBalance : remoteBalance,
		remoteAmount: localOwner ? remoteBalance : localBalance,
		revocationPubkey: keys.revocationPubkey,
		localDelayedPubkey: keys.localDelayedPubkey,
		remotePaymentPubkey: peer.paymentBasepoint,
		toSelfDelay,
		dustLimitSatoshis: dust,
		useAnchors: true,
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
	}).tx;
}
