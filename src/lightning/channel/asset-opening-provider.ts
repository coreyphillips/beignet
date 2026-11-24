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
	walletGeneration?: 4;
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

export interface IAssetOpeningPayout {
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

/** Explicit host support for private dual-funded asset openings on regtest. */
export interface IAuxiliaryDualFunding {
	version: 1;
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
}
