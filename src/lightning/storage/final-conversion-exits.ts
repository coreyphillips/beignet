/**
 * A pending conversion's exits (#2151 step 2b): the parent branch, of the
 * channel's current type, and the candidate branch, of the other type, each
 * the commitments at the conversion's state number on its own funding
 * output. They live in the device-journal scope `conversion`, which nothing
 * that reads `asset-splice` sees. Step 4 writes them while signing a
 * conversion; Step 5 adopts the candidate with a `channel-type` record.
 */
import { Transaction } from 'bitcoinjs-lib';
import { isFinalTaprootTypeHex } from '../channel/commitment-profile';
import {
	buildFinalCommitmentView,
	type IFinalCommitmentType,
	type IFinalCommitmentView,
	type IFinalOpeningTerms
} from '../channel/final-opening-commitment';
import type { IFinalFundingReference } from '../channel/final-splice-candidate';
import { ASSET_SPLICE_RECOVERY_TYPE_HEX as ASSET_BRANCH_TYPE } from '../features/asset-opening';
import { validateFundingWitness } from '../interactive-tx/funding-witness';
import {
	validateAssetExitBranch,
	type IAssetSpliceExitBranch
} from './asset-splice-exit-proofs';
import {
	canonicalSpliceFunding,
	spliceRecoveryView
} from './asset-splice-recovery';
import type { IFinalOpeningCandidate } from './final-opening-candidate';

/** One holder's view of a plain branch's commitment at the conversion's height. */
export interface IPlainHolderRecovery {
	point: string;
	localBalanceMsat: string;
	remoteBalanceMsat: string;
	feeratePerKw: number;
	htlcs: [];
}
export interface IPlainExitBranch {
	type: 'plain';
	channelType: string;
	minimumDepth: number;
	funding: IFinalFundingReference;
	fundingTxid: string;
	outputIndex: number;
	localCommitment: string;
	remoteCommitment: string;
	localRecovery: IPlainHolderRecovery;
	remoteRecovery: IPlainHolderRecovery;
}
/**
 * A conversion's asset branch: the exit proofs' branch, which stays
 * unchanged, with the feerate its commitments were signed at, since the
 * branch alone does not carry it.
 */
export type IAssetExitBranch = {
	type: 'asset';
	feeratePerKw: number;
} & IAssetSpliceExitBranch;
export type IFinalExitBranch = IAssetExitBranch | IPlainExitBranch;

/** The `conversion-exits` event: the parent has the current type and the candidate the other one. */
export interface IFinalConversionExits {
	stateNumber: string;
	digest: string;
	parent: IFinalExitBranch;
	candidate: IFinalExitBranch;
}
export type FinalConversionEvent =
	| ({ kind: 'conversion-exits' } & IFinalConversionExits)
	| { kind: 'conversion-released'; digest: string };

function invalid(): never {
	throw new Error('Invalid conversion exits');
}
function hex(v: unknown, bytes?: number): string {
	if (
		typeof v !== 'string' ||
		!v.length ||
		v.length % 2 ||
		!/^[0-9a-f]+$/.test(v) ||
		(bytes !== undefined && v.length !== bytes * 2)
	)
		invalid();
	return v;
}
function decimal(v: unknown): string {
	if (typeof v !== 'string' || !/^(0|[1-9][0-9]*)$/.test(v)) invalid();
	return v;
}
function plainHolder(v: IPlainHolderRecovery): IPlainHolderRecovery {
	if (
		!v ||
		typeof v !== 'object' ||
		!Number.isSafeInteger(v.feeratePerKw) ||
		v.feeratePerKw < 0 ||
		!Array.isArray(v.htlcs) ||
		v.htlcs.length
	)
		invalid();
	return {
		point: hex(v.point, 33),
		localBalanceMsat: decimal(v.localBalanceMsat),
		remoteBalanceMsat: decimal(v.remoteBalanceMsat),
		feeratePerKw: v.feeratePerKw,
		htlcs: []
	};
}
function plainBranch(v: IPlainExitBranch): IPlainExitBranch {
	if (
		!isFinalTaprootTypeHex(v.channelType) ||
		!Number.isSafeInteger(v.minimumDepth) ||
		v.minimumDepth < 1 ||
		!Number.isSafeInteger(v.outputIndex) ||
		v.outputIndex < 0
	)
		invalid();
	const fundingTxid = hex(v.fundingTxid, 32);
	const commitment = (raw: string, local: boolean): string => {
		let tx: Transaction;
		try {
			tx = Transaction.fromHex(hex(raw));
		} catch {
			invalid();
		}
		if (
			tx.toHex() !== raw ||
			tx.ins.length !== 1 ||
			tx.ins[0].index !== v.outputIndex ||
			!tx.ins[0].hash.equals(Buffer.from(fundingTxid, 'hex').reverse()) ||
			(local ? !tx.hasWitnesses() : tx.hasWitnesses())
		)
			invalid();
		return raw;
	};
	return {
		type: 'plain',
		channelType: v.channelType,
		minimumDepth: v.minimumDepth,
		funding: canonicalSpliceFunding(v.funding),
		fundingTxid,
		outputIndex: v.outputIndex,
		localCommitment: commitment(v.localCommitment, true),
		remoteCommitment: commitment(v.remoteCommitment, false),
		localRecovery: plainHolder(v.localRecovery),
		remoteRecovery: plainHolder(v.remoteRecovery)
	};
}

/** The canonical form of a branch: the asset branch checks of the exit proofs, or the plain shape. */
export function canonicalFinalExitBranch(
	v: IFinalExitBranch
): IFinalExitBranch {
	if (!v || typeof v !== 'object') invalid();
	if (v.type === 'plain') return plainBranch(v);
	if (v.type !== 'asset') invalid();
	const { type: _type, feeratePerKw, ...rest } = v;
	if (!Number.isSafeInteger(feeratePerKw) || feeratePerKw < 0) invalid();
	return { type: 'asset', feeratePerKw, ...validateAssetExitBranch(rest) };
}

/** The canonical form of a `conversion-exits` input. */
export function canonicalFinalConversionExits(
	v: IFinalConversionExits
): IFinalConversionExits {
	if (!v || typeof v !== 'object') invalid();
	return {
		stateNumber: decimal(v.stateNumber),
		digest: hex(v.digest, 32),
		parent: canonicalFinalExitBranch(v.parent),
		candidate: canonicalFinalExitBranch(v.candidate)
	};
}

/** What a branch's recovery view is built against: the opening, its terms and its own root. */
export interface IConversionViewContext {
	candidate: IFinalOpeningCandidate;
	terms: IFinalOpeningTerms;
	/** The opening's own asset root, absent for a plain opening. */
	openingRoot?: Buffer;
}

/** The context a conversion's branches are rebuilt against: the opening, its terms and its own root. */
export function conversionViewContext(
	candidate: IFinalOpeningCandidate,
	terms: IFinalOpeningTerms,
	openingRoot: string | undefined
): IConversionViewContext {
	return {
		candidate,
		terms,
		...(openingRoot && { openingRoot: Buffer.from(openingRoot, 'hex') })
	};
}

export type IConversionRecoveryView =
	| {
			type: 'plain';
			view: IFinalCommitmentView;
			recovery: IPlainHolderRecovery;
	  }
	| ({ type: 'asset' } & ReturnType<typeof spliceRecoveryView>);

/** The commitment type a branch's builder passes, with the opening's own root. */
export function branchCommitmentType(
	channelType: string,
	openingRoot?: Buffer
): IFinalCommitmentType {
	return { channelType, ...(openingRoot && { openingRoot }) };
}

/**
 * Rebuild one holder's commitment of a branch: a plain branch with the plain
 * builder and its own type, an asset branch through spliceRecoveryView with
 * the opening's own root and the branch's root in its assets. Throws when the
 * branch's bytes are not what its builder builds.
 */
export function conversionRecoveryView(
	ctx: IConversionViewContext,
	branch: IFinalExitBranch,
	holder: 'local' | 'remote',
	stateNumber: string
): IConversionRecoveryView {
	const local = holder === 'local';
	if (branch.type === 'plain') {
		const recovery = local ? branch.localRecovery : branch.remoteRecovery;
		const view = buildFinalCommitmentView(
			ctx.candidate,
			{ ...ctx.terms, commitmentFeeratePerKw: recovery.feeratePerKw },
			holder,
			Buffer.from(recovery.point, 'hex'),
			BigInt(stateNumber),
			{
				localBalanceMsat: BigInt(recovery.localBalanceMsat),
				remoteBalanceMsat: BigInt(recovery.remoteBalanceMsat)
			},
			[],
			branch.funding,
			branchCommitmentType(branch.channelType, ctx.openingRoot)
		);
		const signed = Transaction.fromHex(
			local ? branch.localCommitment : branch.remoteCommitment
		);
		if (view.tx.getId() !== signed.getId())
			throw new Error(
				'Conversion commitment differs from the reconstructed transaction'
			);
		return { type: 'plain', view, recovery };
	}
	// An asset branch is rebuilt at its own feerate.
	const { type: _type, feeratePerKw, ...member } = branch;
	return {
		type: 'asset',
		...spliceRecoveryView(
			ctx.candidate,
			{ ...ctx.terms, commitmentFeeratePerKw: feeratePerKw },
			ctx.openingRoot ? ctx.openingRoot.toString('hex') : '',
			member,
			holder,
			stateNumber,
			branchCommitmentType(
				// An asset branch runs the recoverable asset type.
				ASSET_BRANCH_TYPE,
				ctx.openingRoot
			)
		)
	};
}

/** A plain branch's local commitment carries a witness that spends its funding output. */
export function verifyPlainBranchWitness(branch: IPlainExitBranch): void {
	const commitment = Transaction.fromHex(branch.localCommitment);
	const funding = Transaction.fromHex(branch.funding.fundingTxHex);
	const coin = funding.outs[branch.outputIndex];
	if (
		!coin ||
		funding.getId() !== branch.fundingTxid ||
		branch.funding.fundingOutputIndex !== branch.outputIndex ||
		validateFundingWitness(commitment, 0, commitment.ins[0].witness, {
			scripts: [coin.script],
			values: [BigInt(coin.value)]
		})
	)
		throw new Error('Conversion commitment witness does not verify');
}
