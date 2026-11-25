import type { Transaction } from 'bitcoinjs-lib';
import type { ITaprootAuxLeaf } from '../script/commitment-taproot';
import type { AssetOpenPair } from './asset-opening-provider';
import type { IFinalFundingReference } from './final-splice-candidate';
import type {
	IFinalBalances,
	IFinalCommitmentHtlc,
	IFinalCommitmentView,
	IFinalOpeningTerms
} from './final-opening-commitment';

export interface IAssetUpdateAmount {
	assetId: string;
	units: bigint;
}
export interface IAssetUpdateHtlc extends IFinalCommitmentHtlc {
	allocations: readonly IAssetUpdateAmount[];
}
type Offerer = IAssetUpdateHtlc['offeredBy'];
export type AssetUpdateChange =
	| { kind: 'add'; htlc: IAssetUpdateHtlc }
	| { kind: 'fulfill'; offeredBy: Offerer; id: bigint; preimage: Buffer }
	| { kind: 'fail'; offeredBy: Offerer; id: bigint; reason: Buffer }
	| { kind: 'fee'; feeratePerKw: number };

export interface IAssetUpdateHolderView extends IFinalBalances {
	point: Buffer;
	tx: Transaction;
	keys: IFinalCommitmentView['keys'];
	toSelfDelay: number;
	outputMap: IFinalCommitmentView['outputMap'];
	htlcs: readonly IAssetUpdateHtlc[];
	/** Bitcoin-only input transactions, output indexes and spend leaves before adding the host's asset roots. */
	htlcOutputs: IFinalCommitmentView['htlcs'];
}
export interface IAssetUpdateMemberView {
	/** Canonical display txid:vout. */
	outpoint: string;
	funding: IFinalFundingReference;
	fundingRoot: Buffer;
	fundingProofs: Buffer;
	local: IAssetUpdateHolderView;
	remote: IAssetUpdateHolderView;
}
export interface IAssetUpdateRound {
	walletGeneration?: 5;
	channelId: string;
	localIsInitiator: boolean;
	stateNumber: bigint;
	digest: Buffer;
	priorDigest?: Buffer;
	changes: readonly AssetUpdateChange[];
	terms: IFinalOpeningTerms;
	members: readonly IAssetUpdateMemberView[];
}
export interface IAssetUpdateHolderEvidence {
	toLocal?: ITaprootAuxLeaf;
	toRemote?: ITaprootAuxLeaf;
	htlcs: readonly {
		id: bigint;
		offeredBy: Offerer;
		output: ITaprootAuxLeaf;
		secondLevel: ITaprootAuxLeaf;
	}[];
	/** Proofs for the balances and each enforceable HTLC and second-level spend. */
	proofs: Buffer;
	/** Exact auxiliary commitment_signed TLV 65537 from the counterparty of this holder. */
	htlcSignatures: Buffer;
}
export interface IAssetUpdateMemberEvidence {
	outpoint: string;
	local: IAssetUpdateHolderEvidence;
	remote: IAssetUpdateHolderEvidence;
}
export interface IAssetUpdateSignedMember {
	outpoint: string;
	local: Transaction;
	remote: Transaction;
	localEvidence: IAssetUpdateHolderEvidence;
	remoteEvidence: IAssetUpdateHolderEvidence;
}
export interface IAssetUpdateHtlcSigner {
	signHtlc(
		hash: Buffer,
		point: Buffer,
		htlcBasepoint: Buffer,
		outpoint: string,
		offeredBy: IAssetUpdateHtlc['offeredBy'],
		htlcId: bigint,
		assetId: string
	): Buffer;
}
export interface IAssetSpliceUpdateHost {
	signAssetUpdateViews(round: IAssetUpdateRound): Promise<Buffer>;
	signAssetUpdateHtlcs(
		round: IAssetUpdateRound,
		jointShares: AssetOpenPair<Buffer>,
		signer: IAssetUpdateHtlcSigner
	): Promise<Buffer>;
	verifyAssetUpdateViews(
		round: IAssetUpdateRound,
		jointShares: AssetOpenPair<Buffer>,
		htlcShares: AssetOpenPair<Buffer>
	): Promise<readonly IAssetUpdateMemberEvidence[]>;
	retainAssetUpdateViews(
		round: IAssetUpdateRound,
		members: readonly IAssetUpdateSignedMember[]
	): Promise<void>;
}
