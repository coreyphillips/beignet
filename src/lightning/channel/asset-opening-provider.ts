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
import type { IAssetOpenLayout } from './asset-opening-manifest';

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
}
