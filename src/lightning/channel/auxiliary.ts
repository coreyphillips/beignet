/**
 * Auxiliary channels: the contract between the channel state machine and a
 * host-supplied provider that commits a second asset to a taproot channel
 * (Taproot Assets, as LND and tapd deploy them).
 *
 * The engine knows nothing of the asset itself. It keeps the Bitcoin
 * channel, asks the provider for one extra tapscript leaf per commitment
 * output, carries the provider's opaque bytes through storage and the wire,
 * and never hands the provider a private key. Everything here is a type; a
 * node without `INodeConfig.auxiliaryChannels` runs none of it.
 */

import type * as bitcoin from 'bitcoinjs-lib';
import type { ISigner } from '../keys/signer';
import type { CustomRecords } from '../message/custom-records';
import type { ITaprootAuxLeaf } from '../script/commitment-taproot';
import type { IChannelState } from './channel-state';
import type {
	IBuiltCommitment,
	ICommitmentKeys,
	IHtlcOutputWithMeta
} from './commitment-builder';
import type { HtlcDirection, IHtlcEntry } from './types';

export type { ITaprootAuxLeaf } from '../script/commitment-taproot';

/** One output of a commitment transaction, as the provider sees it. */
export interface IAuxiliaryOutput {
	outputIndex: number;
	role:
		| 'to_local'
		| 'to_remote'
		| 'offered_htlc'
		| 'received_htlc'
		| 'anchor_local'
		| 'anchor_remote';
	bitcoinValue: bigint;
	script: Buffer;
	/** Compressed public key, preserving the parity required by asset scripts. */
	internalKey: Buffer;
	/** Ordinary Bitcoin leaves before adding the auxiliary asset leaf. */
	leaves: ITaprootAuxLeaf[];
	htlcId?: bigint;
	direction?: HtlcDirection;
	cltvExpiry?: number;
}

/** What the provider is given to build the asset side of one commitment. */
export interface IAuxiliaryCommitmentContext {
	/** Resolve against the completed first-level transaction; absent for unsigned local previews. */
	resolveSecondLevelRevocationKey?(
		transaction: bitcoin.Transaction
	): Buffer | undefined;
	state: IChannelState;
	side: 'local' | 'remote';
	commitmentNumber: bigint;
	/** Asset balances from the node perspective for this exact commitment view. */
	localAssetBalance: bigint;
	remoteAssetBalance: bigint;
	signedLocal: boolean;
	perCommitmentPoint: Buffer;
	keys: ICommitmentKeys;
	baseTransaction: bitcoin.Transaction;
	outputs: IAuxiliaryOutput[];
	htlcs: IHtlcOutputWithMeta[];
}

/** The asset side of one commitment, kept with the channel row. */
export interface IAuxiliaryCommitmentData {
	secondLevelRevocationKey?: Buffer;
	secondLevelRevocationBasepoint?: Buffer;
	secondLevelCommitmentTxid?: string;
	/** Complete opaque asset commitment/provenance data used to recover this view. */
	customData: Buffer;
	/** Keyed by the already sorted Bitcoin output index. */
	outputLeaves: Map<number, ITaprootAuxLeaf>;
	/** Keyed by `${node-local direction}:${htlc ID}`. */
	secondLevelLeaves: Map<string, ITaprootAuxLeaf>;
	htlcOutputIndexes?: Map<string, number>;
	/** Peer auxiliary signatures, if this is a signed local view. */
	peerSignatures?: Map<bigint, Buffer>;
}

/** The terminal outcome of one asset HTLC, reported to the host until acknowledged. */
export interface IAuxiliaryHtlcResolution {
	htlcId: bigint;
	direction: HtlcDirection;
	paymentHash: Buffer;
	auxiliaryAmount: bigint;
	customRecords?: CustomRecords;
	outcome: 'fulfilled' | 'failed';
}

/** Optional peer-specific compatibility using standard BOLT 2 CSV fields. */
export interface IAuxiliaryOpeningCsvPolicy {
	mode: 'symmetric';
	/** Defaults to configured toSelfDelay and cannot reduce that protection. */
	minimumDelay?: number;
	/** Maximum mirrored peer delay, at most 2016 blocks. Defaults to 2016. */
	maximumDelay?: number;
	/** Outgoing request, within the bounds. Defaults to minimumDelay. */
	preferredDelay?: number;
}

/** Effective opening policy, retained across restart. */
export interface IAuxiliaryOpeningCsvState {
	mode: 'symmetric';
	minimumDelay: number;
	maximumDelay: number;
	localDelay: number;
}

/**
 * The asset state of one channel. Journaled with the Bitcoin commitment and
 * revocation state, in the same channel row.
 */
export interface IChannelAuxiliaryState {
	/** Chosen before open/accept; absent on existing unrestricted channels. */
	openingCsvPolicy?: IAuxiliaryOpeningCsvState;
	/** Source-bound peer public points received with commitment_signed. */
	childRevocationBasepoints?: Map<string, Buffer>;
	/** Opaque funding asset state. The provider owns its schema and validation. */
	channelData: Buffer;
	/** Durable terminal notifications retained until the host acknowledges them. */
	resolvedHtlcs?: Map<string, IAuxiliaryHtlcResolution>;
	localBalance: bigint;
	remoteBalance: bigint;
	localShutdownRecords?: Map<bigint, Buffer>;
	remoteShutdownRecords?: Map<bigint, Buffer>;
	closeTransactions?: Map<string, Buffer>;
	/** Exact authenticated closing_signed accepted before the signed close was saved. */
	acceptedClosingSigned?: Buffer;
	/** Signed views retained for force-close and revoked-commitment recovery. */
	localCommitments: Map<bigint, IAuxiliaryCommitmentData>;
	remoteCommitments: Map<bigint, IAuxiliaryCommitmentData>;
}

/** What the provider is given to sign or verify the asset HTLC signatures. */
export interface IAuxiliarySigningContext {
	state: IChannelState;
	side: 'local' | 'remote';
	commitmentNumber: bigint;
	perCommitmentPoint: Buffer;
	commitment: IBuiltCommitment;
}

/** The Bitcoin witness branch an asset-bearing output is spent through. */
export type AuxiliarySpendKind =
	| 'to_local_delayed'
	| 'to_local_revocation'
	| 'to_remote'
	| 'htlc_timeout'
	| 'htlc_success'
	| 'htlc_second_level_timeout'
	| 'htlc_second_level_success'
	| 'htlc_revocation'
	| 'second_level_delayed'
	| 'second_level_revocation';

/** One asset-bearing input of a sweep. */
export interface IAuxiliarySweepInput {
	transactionInputIndex: number;
	commitmentOutputIndex: number;
	kind: AuxiliarySpendKind;
	/** Untweaked key for this selected Bitcoin witness branch. */
	publicKey: Buffer;
	htlcId?: bigint;
	direction?: HtlcDirection;
	paymentHash?: Buffer;
	cltvExpiry?: number;
	leafScript?: Buffer;
	leafVersion?: number;
	controlBlock?: Buffer;
	preimage?: Buffer;
	/** Actual parent transaction when resolving a second-level HTLC output. */
	sourceTransaction?: bitcoin.Transaction;
	/** Signed virtual parent transition retained from the first-level resolver. */
	previousAuxiliaryData?: Buffer;
}

/** A signature the provider asks the host to make for one sweep input. */
export interface IAuxiliarySweepSigningRequest {
	transactionInputIndex: number;
	/** Must match the branch key from the corresponding input descriptor. */
	publicKey: Buffer;
	sigHash: Buffer;
	/** HTLC internal-key index tweak, before the optional Taproot key tweak. */
	singleTweak?: Buffer;
	/** Present only for an asset key-path spend. */
	taprootMerkleRoot?: Buffer;
}

/** What the provider is given to prepare the asset side of a sweep. */
export interface IAuxiliarySweepContext {
	/** Scoped child key differs from the original first-level revocation key. */
	secondLevelRevocationKey?: Buffer;
	state: IChannelState;
	side: 'local' | 'remote';
	commitmentNumber: bigint;
	/** Complete Bitcoin template before signatures; only output scripts may change. */
	transaction: bitcoin.Transaction;
	inputs: IAuxiliarySweepInput[];
	destinationScript: Buffer;
	/** Host-owned keys are never given to the auxiliary provider. */
	sign(request: IAuxiliarySweepSigningRequest): Buffer;
}

/** The asset side of a sweep. */
export interface IAuxiliarySweepResult {
	outputScripts: ReadonlyMap<number, Buffer>;
	/** Signed asset packets and provenance persisted with the Bitcoin sweep. */
	customData: Buffer;
}

/** What the provider is given to pre-sign the child of a revoked asset HTLC. */
export interface IAuxiliaryRevokedChildContext {
	state: IChannelState;
	commitmentNumber: bigint;
	commitmentTransaction: bitcoin.Transaction;
	commitmentData: Buffer;
	sourceOutputIndex: number;
	htlcId: bigint;
	direction: HtlcDirection;
	paymentHash: Buffer;
	cltvExpiry: number;
	childTemplate: bitcoin.Transaction;
	htlcLeafScript: Buffer;
	htlcControlBlock: Buffer;
	firstLevelRevocationKey: Buffer;
	secondLevelRevocationKey: Buffer;
	sign(request: IAuxiliarySweepSigningRequest): Buffer;
}

/** What the provider is given to build the asset side of a cooperative close. */
export interface IAuxiliaryCloseContext {
	state: IChannelState;
	transaction: bitcoin.Transaction;
	localOutputIndex?: number;
	remoteOutputIndex?: number;
	feeSatoshis: bigint;
	localAmount: bigint;
	remoteAmount: bigint;
	localDustLimit: bigint;
	remoteDustLimit: bigint;
}

/** The asset side of a cooperative close. */
export interface IAuxiliaryCloseResult {
	/** Complete, deterministically ordered payout layout, when assets use separate anchors. */
	outputs?: readonly {
		value: bigint;
		script: Buffer;
		side: 'local' | 'remote';
		asset: boolean;
	}[];
	outputScripts: Map<number, Buffer>;
	customData: Buffer;
}

/** A shutdown script with the asset records that travel beside it. */
export interface IAuxiliaryShutdown {
	scriptPubkey: Buffer;
	customRecords: CustomRecords;
}

/**
 * Deterministic synchronous asset extension to the channel state machine.
 * It must use only the supplied durable state. Host callbacks are reattached on
 * restore; no callback is serialized. Exceptions stop the signing transition.
 */
export interface IChannelAuxiliaryProvider {
	buildCommitment(
		context: IAuxiliaryCommitmentContext
	): IAuxiliaryCommitmentData;
	signHtlcs(context: IAuxiliarySigningContext, signer: ISigner): CustomRecords;
	verifyHtlcs(
		context: IAuxiliarySigningContext,
		customRecords: CustomRecords
	): boolean;
	/** Reject invalid asset metadata before admitting an HTLC into channel state. */
	validateHtlc(state: IChannelState, entry: IHtlcEntry): void;
	getHtlcAmount(state: IChannelState, entry: IHtlcEntry): bigint;
	prepareShutdown(
		state: IChannelState,
		destinationScript: Buffer,
		signer: ISigner
	): IAuxiliaryShutdown;
	verifyShutdown(state: IChannelState, shutdown: IAuxiliaryShutdown): boolean;
	/** Fee-independent output sizes added beyond the ordinary Bitcoin payouts. */
	extraCloseOutputScriptLengths?(
		state: Readonly<IChannelState>
	): readonly number[];
	buildClose(context: IAuxiliaryCloseContext): IAuxiliaryCloseResult;
	/** Required before spending any output carrying an auxiliary asset leaf. */
	prepareSweep?(context: IAuxiliarySweepContext): IAuxiliarySweepResult;
	/** Pre-sign only the first-level virtual transition before delegating a revoked child. */
	prepareRevokedChild?(context: IAuxiliaryRevokedChildContext): Buffer;
}
