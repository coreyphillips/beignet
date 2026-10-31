import { Feature, FeatureFlags } from '../features/flags';
import { isOverlayChannel } from './types';
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

/** Pinned Taproot Assets bound keeping commitment signatures within one frame. */
export const MAX_AUXILIARY_HTLCS_PER_PARTY = 83;
/** Dust policy preserving the upstream 354-satoshi asset HTLC carrier. */
export const AUXILIARY_CHANNEL_DUST_LIMIT = 354n;

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

export interface IAuxiliaryCommitmentContext {
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

export interface IAuxiliaryCommitmentData {
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

export interface IAuxiliaryHtlcResolution {
	htlcId: bigint;
	direction: HtlcDirection;
	paymentHash: Buffer;
	auxiliaryAmount: bigint;
	customRecords?: CustomRecords;
	outcome: 'fulfilled' | 'failed';
}

export interface IChannelAuxiliaryState {
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

export interface IAuxiliarySigningContext {
	state: IChannelState;
	side: 'local' | 'remote';
	commitmentNumber: bigint;
	perCommitmentPoint: Buffer;
	commitment: IBuiltCommitment;
}

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

export interface IAuxiliarySweepContext {
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

export interface IAuxiliarySweepResult {
	outputScripts: ReadonlyMap<number, Buffer>;
	/** Signed asset packets and provenance persisted with the Bitcoin sweep. */
	customData: Buffer;
}

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
	/** Authenticate the immutable asset identity and every slot's exact asset records. */
	validateFforAssetTerms?(
		state: Readonly<IChannelState>,
		terms: import('../ffor/assets').IFforAssetTerms
	): void;
	buildFunding?: import('./interactive-funding').AuxiliaryFundingBuilder;
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
}

export function copyAuxiliaryCommitment(
	data: IAuxiliaryCommitmentData
): IAuxiliaryCommitmentData {
	const copyLeaf = (leaf: ITaprootAuxLeaf): ITaprootAuxLeaf => ({
		script: Buffer.from(leaf.script),
		...(leaf.leafVersion !== undefined ? { leafVersion: leaf.leafVersion } : {})
	});
	return {
		customData: Buffer.from(data.customData),
		htlcOutputIndexes: data.htlcOutputIndexes
			? new Map(data.htlcOutputIndexes)
			: undefined,
		outputLeaves: new Map(
			[...data.outputLeaves].map(([index, leaf]) => [index, copyLeaf(leaf)])
		),
		secondLevelLeaves: new Map(
			[...data.secondLevelLeaves].map(([id, leaf]) => [id, copyLeaf(leaf)])
		),
		...(data.peerSignatures
			? {
					peerSignatures: new Map(
						[...data.peerSignatures].map(([type, bytes]) => [
							type,
							Buffer.from(bytes)
						])
					)
			  }
			: {})
	};
}

export function requireAuxiliaryProvider(
	state: IChannelState
): IChannelAuxiliaryProvider {
	if (
		!state.auxiliaryState ||
		!state.auxiliaryProvider ||
		!state.fundingTaprootMerkleRoot ||
		state.fundingTaprootMerkleRoot.length !== 32
	) {
		throw new Error('Asset channel state or auxiliary provider is unavailable');
	}
	return state.auxiliaryProvider;
}

/** Enforce the exact overlay type and the prearranged asset funding descriptor. */
export function validateAuxiliaryChannelType(
	state: IChannelState,
	channelType: Buffer | null | undefined
): string | null {
	const overlay = isOverlayChannel(channelType);
	if (!overlay && !state.auxiliaryState && !state.fundingTaprootMerkleRoot)
		return null;
	if (!overlay || !channelType || channelType[0] === 0)
		return 'Asset channel requires the Taproot overlay channel type';
	const allowed = new Set<number>([
		Feature.OPTION_TAPROOT_OVERLAY,
		Feature.SCID_ALIAS,
		Feature.ZERO_CONF
	]);
	const flags = FeatureFlags.fromBuffer(channelType);
	if (
		!flags.hasBit(Feature.OPTION_TAPROOT_OVERLAY) ||
		flags.listSetBits().some((bit) => !allowed.has(bit))
	)
		return 'Invalid Taproot overlay channel type';
	try {
		requireAuxiliaryProvider(state);
	} catch {
		return 'Asset channel funding context or provider is unavailable';
	}
	return null;
}
