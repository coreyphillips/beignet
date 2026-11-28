import type { Transaction } from 'bitcoinjs-lib';
import type {
	IOpenChannel2Message,
	IAcceptChannel2Message
} from '../message/dual-funding';
import type { IFinalOpeningCandidate } from '../storage/final-opening-candidate';
import type {
	IFinalOpeningTerms,
	IFinalCommitmentView
} from './final-opening-commitment';
import type { IAssetConversionTerms } from './asset-conversion-terms';
import type { IAssetOpenLayout } from './asset-opening-manifest';
import type { IAssetSpliceDescription } from './asset-splice-agreement';
import type { IAssetSpliceWireRecordLimit } from '../features/asset-splice';
import type { IFinalExitBranch } from '../storage/final-conversion-exits';
import type { IAssetSpliceHostHolder } from './asset-splice-signature-round';
import type { IFinalFundingReference } from './final-splice-candidate';

export interface IAssetOpenContext {
	/** Local original-device enrollment. Never sourced from the peer. */
	walletGeneration?: 4 | 5;
	peer: string;
	isInitiator: boolean;
	channelId: Buffer;
	attempt: Buffer;
	open: IOpenChannel2Message;
	accept: IAcceptChannel2Message;
}

export type AssetOpenPair<T> = readonly [initiator: T, acceptor: T];

export interface IAssetOpenDescription {
	inputs: (IAssetOpenLayout['inputs'][number] & { prevTx: Buffer })[];
	outputs: IAssetOpenLayout['outputs'];
}

export interface IAssetOpenPlan {
	/** Covers the engine layout, each per-issuance allocation and the unsigned transfers. */
	digest: Buffer;
	consent(): Promise<Buffer>;
	authorize(consents: AssetOpenPair<Buffer>): Promise<Buffer>;
	finalize(
		consents: AssetOpenPair<Buffer>,
		authorizations: AssetOpenPair<Buffer>
	): Promise<IAssetOpenFunding>;
}

export interface IAssetOpenFunding {
	transaction: Buffer;
	fundingRoot: Buffer;
	/** Digest independently reconstructed from both parties' finished funding proofs. */
	proofDigest: Buffer;
	fundingProofs: Buffer;
}

export interface IAssetOpenExitContext {
	opening: IAssetOpenContext;
	funding: IAssetOpenFunding;
	candidate: IFinalOpeningCandidate;
	terms: IFinalOpeningTerms;
	/** Bitcoin views before asset leaves are attached, in local and remote holder order. */
	local: IFinalCommitmentView;
	remote: IFinalCommitmentView;
}

export interface IAssetOpenExit {
	toLocal?: { script: string; leafVersion?: number };
	toRemote?: { script: string; leafVersion?: number };
	proofs: string;
}

/** One device-authorized splice linking the original opening to a confirmed payout. */
export interface IAssetFundingLineageEntry {
	parentTxid: string;
	parentOutputIndex: number;
	fundingTxid: string;
	fundingOutputIndex: number;
	fundingTxHex: string;
}

export interface IAssetOpeningPayout {
	fundingLineage?: readonly IAssetFundingLineageEntry[];
	walletGeneration?: 5;
	virtualPayout?: import('./asset-payout-revocation').IAssetPayoutScope;
	revocation?: { signVirtual(assetId: string, digest: Buffer): Buffer };
	update?: {
		roundDigest: string;
		stateNumber: string;
		fundingTxid: string;
		fundingOutputIndex: number;
	};
	/** Present when the observed commitment matches a retained splice generation. */
	splice?: {
		finalDigest: string;
		stateNumber: string;
		generation: 'parent' | 'candidate';
		fundingTxid: string;
		fundingOutputIndex: number;
	};
	candidate: IFinalOpeningCandidate;
	fundingProofs: Buffer;
	exitProofs: Buffer;
	holder: 'local' | 'remote';
	parent: Transaction;
	outputIndex: number;
	delay: number;
	feeRate: number;
	/** Signs only this output, for its verified script tree and exact transaction. */
	signSweep(unsigned: Transaction, prevTxs: readonly Transaction[]): Buffer[];
}

export interface IAssetHtlcVirtualSpend {
	assetId: string;
	stage: 'commitment' | 'second-level';
	inputRoot: Buffer;
	outputRoot: Buffer;
	lockTime: number;
	sequence: number;
}

export interface IAssetOpeningHtlcPayout {
	fundingLineage?: readonly IAssetFundingLineageEntry[];
	walletGeneration: 5;
	candidate: IFinalOpeningCandidate;
	virtualPayout: import('./asset-payout-revocation').IAssetPayoutScope;
	fundingProofs: Buffer;
	exitProofs: Buffer;
	commitment: Transaction;
	parent: Transaction;
	holder: 'local' | 'remote';
	commitmentOutputIndex: number;
	outputIndex: number;
	kind: Exclude<
		import('./auxiliary').AuxiliarySpendKind,
		'to_local_delayed' | 'to_local_revocation' | 'to_remote'
	>;
	htlc: import('./asset-splice-update-provider').IAssetUpdateHtlc;
	keys: IFinalCommitmentView['keys'];
	toSelfDelay: number;
	preimage?: Buffer;
	peerHtlcSignatures?: Buffer;
	childSignatureIndex: number;
	secondLevelTemplate: Transaction;
	transaction: Transaction;
	signSweep(tx: Transaction): Buffer[];
	signVirtual(spend: IAssetHtlcVirtualSpend): Buffer;
}

/** The attempt a conversion host call concerns (#2151). */
export interface IAssetConversionContext {
	channelId: string;
	peer: string;
	/** The attempt id, from the channel, the parent outpoint, the terms digest and the initiator's role. */
	attempt: Buffer;
	isInitiator: boolean;
	/** Whether this side opened the channel: the role the terms name it by. */
	isOpener: boolean;
	parent: {
		txid: string;
		outputIndex: number;
		stateNumber: string;
		type: 'plain' | 'asset';
		channelType: string;
	};
	direction: 'to-plain' | 'to-asset';
}

/** What the engine knows of a conversion's bitcoin side, initiator first where paired (#2151). */
export interface IAssetConversionBitcoin {
	/** The candidate funding keys, initiator first. */
	fundingKeys: AssetOpenPair<Buffer>;
	/** `splice_init.locktime`. */
	lockTime: number;
	/** The terms' lock depth. */
	minimumDepth: number;
	/** The terms' funding feerate. */
	feeratePerKw: number;
	parent: {
		type: 'plain' | 'asset';
		channelType: string;
		/** The live funding output's value. */
		valueSats: bigint;
		/** The parent funding keys, initiator first. */
		fundingKeys: AssetOpenPair<Buffer>;
		/** An asset parent's funding root, and only there. */
		root?: Buffer;
	};
	candidate: {
		type: 'plain' | 'asset';
		channelType: string;
		maxAcceptedHtlcs: AssetOpenPair<number>;
		dustLimitSats: AssetOpenPair<bigint>;
	};
}

/** Units of one issuance that move in a conversion. */
export interface IAssetConversionMovement {
	/** 64 lowercase hex characters. */
	assetId: string;
	/** The side whose units move: from its channel balance (to bitcoin) or its own inputs (to an asset). */
	from: 'initiator' | 'acceptor';
	/** The output that receives them. */
	outputSerial: bigint;
	units: bigint;
}

/** The host's description of a conversion's layout, initiator first where paired. */
export interface IAssetConversionDescription {
	inputs: IAssetSpliceDescription['inputs'];
	outputs: IAssetSpliceDescription['outputs'];
	movements: readonly IAssetConversionMovement[];
	/** To bitcoin: the parent's funded issuances by holder. To an asset: empty. */
	parentUnits: readonly {
		assetId: string;
		initiator: bigint;
		acceptor: bigint;
	}[];
	/** Two, initiator first. */
	feeBudgets: readonly bigint[];
	/** Two, initiator first. */
	relativeSatoshis: readonly bigint[];
	/** To an asset only: each holder's commitment record limits, initiator first. Absent to bitcoin. */
	commitmentRecordLimits?: readonly (readonly IAssetSpliceWireRecordLimit[])[];
}

/**
 * Both hosts derive `digest` from the proposals and the layout digest, so it
 * is equal on both sides. Since Step 4b the plan also consents, authorizes
 * the assets and freezes the funding transaction.
 */
export interface IAssetConversionPlan {
	/** 32 bytes. */
	digest: Buffer;
	/** This side's 64-byte consent to the agreement. */
	consent(): Promise<Buffer>;
	/** This side's asset authorizations, 1 byte to 4 MiB, given both consents in initiator order. */
	authorize(consents: AssetOpenPair<Buffer>): Promise<Buffer>;
	/** The unsigned funding transaction both hosts build from the layout and both authorizations. */
	finalize(
		consents: AssetOpenPair<Buffer>,
		authorizations: AssetOpenPair<Buffer>
	): Promise<IAssetConversionFunding>;
}

/** The plan's frozen funding (#2151 Step 4b). */
export interface IAssetConversionFunding {
	layoutDigest: Buffer;
	transaction: Buffer;
	/** To an asset: the transfer proofs into the candidate's funding. To bitcoin: those of the withdrawals. 32 bytes. */
	proofDigest: Buffer;
	/** To an asset only: the candidate's funding root, 32 bytes. */
	fundingRoot?: Buffer;
	/** To an asset only: the candidate's funding proofs, 1 byte to 4 MiB. */
	fundingProofs?: Buffer;
}

/** One branch of a conversion's exits as the host sees it: its type, funding and both holders' views, built without leaves. */
export type IAssetConversionHostBranch =
	| {
			type: 'plain';
			channelType: string;
			funding: IFinalFundingReference;
			local: IAssetSpliceHostHolder;
			remote: IAssetSpliceHostHolder;
	  }
	| {
			type: 'asset';
			channelType: string;
			funding: IFinalFundingReference;
			fundingRoot: Buffer;
			local: IAssetSpliceHostHolder;
			remote: IAssetSpliceHostHolder;
	  };

/** To bitcoin: one withdrawal movement of the layout, at its output in the frozen funding. */
export interface IAssetConversionWithdrawal {
	assetId: string;
	/** The side whose units move. */
	from: 'initiator' | 'acceptor';
	outputSerial: bigint;
	/** The output's index in the frozen funding transaction. */
	outputIndex: number;
	units: bigint;
	/** The output's owner by serial parity: the buyer. */
	owner: 'local' | 'remote';
}

/** What both hosts sign and verify a conversion's exits against. */
export interface IAssetConversionHostExitViews {
	/** The candidate's commitment terms: the channel's, at the terms' commitment feerate. */
	terms: IFinalOpeningTerms;
	originalInitiator: boolean;
	finalDigest: Buffer;
	layoutDigest: Buffer;
	fundingFeeratePerkw: number;
	/** Initiator first. */
	paymentBasepoints: AssetOpenPair<Buffer>;
	/** The current type at N on the live funding. */
	parent: IAssetConversionHostBranch;
	/** The target type at N on the candidate's funding. */
	candidate: IAssetConversionHostBranch;
	/** To bitcoin: the layout's withdrawal movements. Absent to an asset. */
	withdrawals?: readonly IAssetConversionWithdrawal[];
}

/** The host's verified exit evidence: an asset branch's holder leaves and proofs; null for a plain branch. */
export interface IAssetConversionExitEvidence {
	parent: Record<'local' | 'remote', IAssetOpenExit> | null;
	candidate: Record<'local' | 'remote', IAssetOpenExit> | null;
}

/** To bitcoin on the buyer's side: one withdrawal's signed transfer and proof as the host persisted them. */
export interface IAssetConversionWithdrawalReceipt {
	outputIndex: number;
	assetId: string;
	/** Decimal. */
	units: string;
	/** Lowercase hex, 1 byte to 4 MiB. */
	proof: string;
}

/** What the host retained for a conversion's exits. */
export interface IAssetConversionExitReceipt {
	channelId: string;
	/** Lowercase hex. */
	finalDigest: string;
	/** Decimal. */
	stateNumber: string;
	parent: IFinalExitBranch;
	candidate: IFinalExitBranch;
	/** To bitcoin on the buyer's side: one receipt per withdrawal it owns. Otherwise empty. */
	withdrawals: readonly IAssetConversionWithdrawalReceipt[];
}

/**
 * The conversion surface of a host (#2151): the terms calls, the planner
 * calls and, since Step 4b, the exit calls. This build signs the
 * candidate's exits and first commitments, and no funding.
 */
export interface IAssetConversionHost {
	assetConversionVersion: 1;
	/** The engine's floor is its own estimate less this margin, in sat/kw, so that two engines whose estimates differ do not deadlock. */
	conversionFeerateMarginPerKw: number;
	/** The initiator's terms of a conversion under the host's agreement `reference`. */
	conversionTerms(
		ctx: Omit<IAssetConversionContext, 'attempt'>,
		request: { reference: Buffer }
	): Promise<IAssetConversionTerms>;
	/** Confirm the exact canonical terms and their digest. Only `true` confirms. */
	verifyConversionTerms(
		ctx: IAssetConversionContext,
		terms: IAssetConversionTerms,
		digest: Buffer
	): Promise<boolean>;
	/** Called once for an attempt this host verified, with the end's text: when the attempt ends, or, for an attempt that sends its own tx_abort, as soon as its withdrawal is on disk, with the tx_abort's text. The channel can then stay held for up to 30 seconds, until the peer echoes the tx_abort or its bound expires, so a new conversion or update of the channel may be refused with the in-progress text until then. After a restart it may also be called for an attempt from before it, which this process never saw, and may then repeat a call made before the restart; it must be idempotent. It is final, even while a planner call is pending. Since Step 4b it also releases what the host retained for the attempt's candidate, its exits and, to bitcoin, the withdrawal receipts: the candidate was dropped and can never confirm, and a retain that finishes after this call is released too. The attempt id can repeat; the final digest names the candidate. */
	abandonConversion(
		ctx: IAssetConversionContext,
		reason: string
	): void | Promise<void>;
	/** This side's proposal, 1 byte to 4 MiB, sent to the peer as its layout. */
	proposeConversion(
		ctx: IAssetConversionContext,
		terms: IAssetConversionTerms
	): Promise<Buffer>;
	/** The layout both proposals describe. */
	describeConversion(
		ctx: IAssetConversionContext,
		proposals: AssetOpenPair<Buffer>,
		bitcoin: IAssetConversionBitcoin
	): Promise<IAssetConversionDescription>;
	/** The plan for the layout the engine checked and hashed. */
	prepareConversion(
		ctx: IAssetConversionContext,
		proposals: AssetOpenPair<Buffer>,
		bitcoin: IAssetConversionBitcoin,
		layoutDigest: Buffer
	): Promise<IAssetConversionPlan>;
	/**
	 * This side's exit share, 1 byte to 4 MiB. It signs only the candidate's
	 * exits and, to bitcoin, a seller's withdrawal transfers and proofs for
	 * the buyer. It must never sign a new transfer over the parent's
	 * commitment outputs at N, which stay broadcastable until N is revoked.
	 */
	signConversionExits(
		ctx: IAssetConversionContext,
		views: IAssetConversionHostExitViews
	): Promise<Buffer>;
	/** Verify both shares, in initiator order, against the views. */
	verifyConversionExits(
		ctx: IAssetConversionContext,
		views: IAssetConversionHostExitViews,
		shares: AssetOpenPair<Buffer>
	): Promise<IAssetConversionExitEvidence>;
	/** Persist this side's exits and, to bitcoin on the buyer's side, each withdrawal's signed transfer and proof, then return them. */
	retainConversionExits(
		ctx: IAssetConversionContext,
		views: IAssetConversionHostExitViews,
		exact: Record<
			'parent' | 'candidate',
			Record<'local' | 'remote', Transaction>
		>
	): Promise<IAssetConversionExitReceipt>;
}

/** Explicit host support for private dual-funded asset openings on regtest. */
export interface IAuxiliaryDualFunding
	extends Partial<import('./asset-splice-transport').AssetSpliceHost>,
		Partial<import('./asset-splice-update-provider').IAssetSpliceUpdateHost> {
	version: 1;
	assetSpliceRecoveryVersion?: 1;
	/** Synchronous local policy. An absent answer declines before a key is allocated. */
	contribution(
		peer: string,
		isInitiator: boolean,
		openerSats: bigint
	): bigint | undefined;
	/** Release the local reservations of a durably abandoned unsigned opening. Idempotent. */
	abandon(ctx: IAssetOpenContext): Promise<void>;
	propose(ctx: IAssetOpenContext): Promise<Buffer>;
	describe(
		ctx: IAssetOpenContext,
		proposals: AssetOpenPair<Buffer>
	): Promise<IAssetOpenDescription>;
	prepare(
		ctx: IAssetOpenContext,
		proposals: AssetOpenPair<Buffer>,
		layoutDigest: Buffer
	): Promise<IAssetOpenPlan>;
	signExits(ctx: IAssetOpenExitContext): Promise<Buffer>;
	verifyExits(
		ctx: IAssetOpenExitContext,
		signatures: AssetOpenPair<Buffer>
	): Promise<{ local: IAssetOpenExit; remote: IAssetOpenExit }>;
	signFunding(
		candidate: IFinalOpeningCandidate,
		fundingProofs: Buffer,
		tx: Transaction,
		indices: readonly number[],
		prevouts: { scripts: Buffer[]; values: bigint[] }
	): Promise<Buffer[][]>;
	/** Verify the accepted-chain anchor and import its proofs idempotently before channel_ready. */
	confirmFunding(
		candidate: IFinalOpeningCandidate,
		fundingProofs: Buffer
	): Promise<void>;
	retractFunding(candidate: IFinalOpeningCandidate): Promise<void>;
	/** Retain the sweep's proof material before returning its broadcastable transaction. */
	recoverOutput(ctx: IAssetOpeningPayout): Promise<Transaction | null>;
	/** Preserve a confirmed HTLC's asset proofs while resolving its selected spend branch. */
	recoverHtlc?(ctx: IAssetOpeningHtlcPayout): Promise<Transaction | null>;
	/** Locators and proofs for the completed terminal sweep, exported before broadcast. */
	outputRecoveryReceipt?(
		channelId: string,
		parentTxid: string,
		outputIndex: number,
		payout: Transaction
	): Buffer | undefined;
	/** Verify the accepted-chain spend and import its outputs into the current wallet before resolving. */
	restoreOutputReceipt?(
		channelId: string,
		parentTxid: string,
		outputIndex: number,
		payout: Transaction,
		receipt: Buffer
	): Promise<void>;
	/** The initiator's terms of a conversion under the host's agreement `reference` (#2151). */
	conversionTerms?(
		ctx: Omit<IAssetConversionContext, 'attempt'>,
		request: { reference: Buffer }
	): Promise<IAssetConversionTerms>;
	/** Confirm the exact canonical terms and their digest. Only `true` confirms. */
	verifyConversionTerms?(
		ctx: IAssetConversionContext,
		terms: IAssetConversionTerms,
		digest: Buffer
	): Promise<boolean>;
	/** Called once for an attempt this host verified, with the end's text: when the attempt ends, or, for an attempt that sends its own tx_abort, as soon as its withdrawal is on disk, with the tx_abort's text. The channel can then stay held for up to 30 seconds, until the peer echoes the tx_abort or its bound expires, so a new conversion or update of the channel may be refused with the in-progress text until then. After a restart it may also be called for an attempt from before it, which this process never saw, and may then repeat a call made before the restart; it must be idempotent. Since Step 4b it also releases what the host retained for the attempt's candidate, its exits and, to bitcoin, the withdrawal receipts: the candidate was dropped and can never confirm, and a retain that finishes after this call is released too. The attempt id can repeat; the final digest names the candidate. */
	abandonConversion?(
		ctx: IAssetConversionContext,
		reason: string
	): void | Promise<void>;
	/** The conversion surface's version (#2151 step 3b). */
	assetConversionVersion?: 1;
	/** See `IAssetConversionHost.conversionFeerateMarginPerKw`. */
	conversionFeerateMarginPerKw?: number;
	/** See `IAssetConversionHost.proposeConversion`. */
	proposeConversion?(
		ctx: IAssetConversionContext,
		terms: IAssetConversionTerms
	): Promise<Buffer>;
	/** See `IAssetConversionHost.describeConversion`. */
	describeConversion?(
		ctx: IAssetConversionContext,
		proposals: AssetOpenPair<Buffer>,
		bitcoin: IAssetConversionBitcoin
	): Promise<IAssetConversionDescription>;
	/** See `IAssetConversionHost.prepareConversion`. */
	prepareConversion?(
		ctx: IAssetConversionContext,
		proposals: AssetOpenPair<Buffer>,
		bitcoin: IAssetConversionBitcoin,
		layoutDigest: Buffer
	): Promise<IAssetConversionPlan>;
	/** See `IAssetConversionHost.signConversionExits` (#2151 Step 4b). */
	signConversionExits?(
		ctx: IAssetConversionContext,
		views: IAssetConversionHostExitViews
	): Promise<Buffer>;
	/** See `IAssetConversionHost.verifyConversionExits`. */
	verifyConversionExits?(
		ctx: IAssetConversionContext,
		views: IAssetConversionHostExitViews,
		shares: AssetOpenPair<Buffer>
	): Promise<IAssetConversionExitEvidence>;
	/** See `IAssetConversionHost.retainConversionExits`. */
	retainConversionExits?(
		ctx: IAssetConversionContext,
		views: IAssetConversionHostExitViews,
		exact: Record<
			'parent' | 'candidate',
			Record<'local' | 'remote', Transaction>
		>
	): Promise<IAssetConversionExitReceipt>;
}
