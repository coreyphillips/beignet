import { Transaction } from 'bitcoinjs-lib';
import {
	buildAssetSpliceCommitment,
	type IFinalOpeningTerms
} from '../channel/final-opening-commitment';
import type { IFinalFundingReference } from '../channel/final-splice-candidate';
import type { IFinalOpeningCandidate } from './final-opening-candidate';
import type { IAssetSpliceExitBranch } from './asset-splice-exit-proofs';
import { validateFundingWitness } from '../interactive-tx/funding-witness';

export interface IStoredSpliceLeaf {
	script: string;
	leafVersion?: number;
}
export interface IStoredSpliceHtlc {
	id: string;
	offeredBy: 'local' | 'peer';
	amountMsat: string;
	paymentHash: string;
	cltvExpiry: number;
	outputIndex: number | null;
	outputLeaf: IStoredSpliceLeaf | null;
	secondLevelLeaf: IStoredSpliceLeaf | null;
}
export interface IAssetSpliceHolderRecovery {
	point: string;
	localBalanceMsat: string;
	remoteBalanceMsat: string;
	ownedOutputIndex: number | null;
	toLocal: IStoredSpliceLeaf | null;
	toRemote: IStoredSpliceLeaf | null;
	htlcs: IStoredSpliceHtlc[];
}

function hex(value: string, min: number, max = min): string {
	if (
		typeof value !== 'string' ||
		value.length < min * 2 ||
		value.length > max * 2 ||
		value.length % 2 ||
		!/^[a-f0-9]+$/.test(value)
	)
		throw new Error('Invalid asset recovery bytes');
	return value;
}
function index(value: number, max = 0xffffffff): number {
	if (!Number.isSafeInteger(value) || value < 0 || value > max)
		throw new Error('Invalid asset recovery index');
	return value;
}
function decimal(value: string): string {
	if (
		typeof value !== 'string' ||
		value.length > 20 ||
		!/^(0|[1-9][0-9]*)$/.test(value) ||
		BigInt(value) > 0xffffffffffffffffn
	)
		throw new Error('Invalid asset recovery amount');
	return value;
}
function leaf(v: IStoredSpliceLeaf | null): IStoredSpliceLeaf | null {
	if (v === null) return null;
	const script = hex(v.script, 1, 10000);
	if (v.leafVersion === undefined) return { script };
	if (index(v.leafVersion, 254) % 2)
		throw new Error('Invalid asset recovery leaf version');
	return { script, leafVersion: v.leafVersion };
}
export function canonicalSpliceFunding(
	v: IFinalFundingReference
): IFinalFundingReference {
	return {
		fundingTxHex: hex(v.fundingTxHex, 10, 400000),
		fundingOutputIndex: index(v.fundingOutputIndex),
		localFundingPubkey: hex(v.localFundingPubkey, 33),
		remoteFundingPubkey: hex(v.remoteFundingPubkey, 33),
		localFundingKeyIndex: index(v.localFundingKeyIndex, 0x7fffffff)
	};
}
export function canonicalSpliceHolder(
	v: IAssetSpliceHolderRecovery
): IAssetSpliceHolderRecovery {
	if (!Array.isArray(v.htlcs) || v.htlcs.length > 966)
		throw new Error('Invalid asset recovery HTLC set');
	return {
		point: hex(v.point, 33),
		localBalanceMsat: decimal(v.localBalanceMsat),
		remoteBalanceMsat: decimal(v.remoteBalanceMsat),
		ownedOutputIndex:
			v.ownedOutputIndex === null ? null : index(v.ownedOutputIndex),
		toLocal: leaf(v.toLocal),
		toRemote: leaf(v.toRemote),
		htlcs: v.htlcs.map((h) => {
			if (
				(h.offeredBy !== 'local' && h.offeredBy !== 'peer') ||
				(h.outputLeaf === null) !== (h.secondLevelLeaf === null)
			)
				throw new Error('Invalid asset recovery HTLC leaves');
			return {
				id: decimal(h.id),
				offeredBy: h.offeredBy,
				amountMsat: decimal(h.amountMsat),
				paymentHash: hex(h.paymentHash, 32),
				cltvExpiry: index(h.cltvExpiry),
				outputIndex: h.outputIndex === null ? null : index(h.outputIndex),
				outputLeaf: leaf(h.outputLeaf),
				secondLevelLeaf: leaf(h.secondLevelLeaf)
			};
		})
	};
}
function decoded(v: IStoredSpliceLeaf) {
	return { script: Buffer.from(v.script, 'hex'), leafVersion: v.leafVersion };
}

/** Reconstruct the exact funding output, signed transaction and each named balance/HTLC output before recovery. */
export function spliceRecoveryView(
	opening: IFinalOpeningCandidate,
	terms: IFinalOpeningTerms,
	openingRoot: string,
	branch: IAssetSpliceExitBranch,
	holder: 'local' | 'remote',
	stateNumber: string
) {
	const h = holder === 'local' ? branch.localRecovery : branch.remoteRecovery;
	const { funding } = branch;
	const tx = Transaction.fromHex(funding.fundingTxHex);
	if (
		tx.hasWitnesses() ||
		tx.toHex() !== funding.fundingTxHex ||
		tx.getId() !== branch.fundingTxid ||
		funding.fundingOutputIndex !== branch.outputIndex
	)
		throw new Error('Splice recovery uses a different funding output');
	if (
		stateNumber === '0' &&
		h.point !==
			(holder === 'local' ? terms.localBasepoints : terms.remoteBasepoints)
				.firstPerCommitmentPoint
	)
		throw new Error(
			'Splice recovery uses a different opening commitment point'
		);
	const assets = {
		fundingRoot: Buffer.from(branch.fundingRoot, 'hex'),
		toLocal: h.toLocal ? decoded(h.toLocal) : undefined,
		toRemote: h.toRemote ? decoded(h.toRemote) : undefined,
		htlcs: h.htlcs.flatMap((v) =>
			v.outputLeaf && v.secondLevelLeaf
				? [
						{
							offeredBy: v.offeredBy,
							id: BigInt(v.id),
							output: decoded(v.outputLeaf),
							secondLevel: decoded(v.secondLevelLeaf)
						}
				  ]
				: []
		)
	};
	const view = buildAssetSpliceCommitment(
		opening,
		terms,
		holder,
		Buffer.from(h.point, 'hex'),
		BigInt(stateNumber),
		{
			localBalanceMsat: BigInt(h.localBalanceMsat),
			remoteBalanceMsat: BigInt(h.remoteBalanceMsat)
		},
		h.htlcs.map((v) => ({
			id: BigInt(v.id),
			offeredBy: v.offeredBy,
			amountMsat: BigInt(v.amountMsat),
			paymentHash: Buffer.from(v.paymentHash, 'hex'),
			cltvExpiry: v.cltvExpiry
		})),
		funding,
		Buffer.from(openingRoot, 'hex'),
		assets
	);
	const commitment = Transaction.fromHex(
		holder === 'local' ? branch.localCommitment : branch.remoteCommitment
	);
	const local = holder === 'local';
	const coin = tx.outs[funding.fundingOutputIndex];
	if (
		commitment.getId() !== view.tx.getId() ||
		(local &&
			validateFundingWitness(commitment, 0, commitment.ins[0].witness, {
				scripts: [coin.script],
				values: [BigInt(coin.value)]
			}))
	)
		throw new Error(
			'Retained splice commitment differs from the reconstructed transaction'
		);
	if (
		(local ? view.outputMap.toLocal : view.outputMap.toRemote) !==
		(h.ownedOutputIndex ?? undefined)
	)
		throw new Error(
			'Asset recovery balance output differs from the reconstructed commitment'
		);
	for (const item of h.htlcs) {
		const found = view.htlcs.find(
			(v) =>
				v.htlc.id === BigInt(item.id) && v.htlc.offeredBy === item.offeredBy
		);
		if (found?.outputIndex !== (item.outputIndex ?? undefined))
			throw new Error(
				'Asset recovery HTLC output differs from the reconstructed commitment'
			);
	}
	return { view, assets, point: Buffer.from(h.point, 'hex') };
}
