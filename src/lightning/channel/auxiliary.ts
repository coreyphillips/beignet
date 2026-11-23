/**
 * Auxiliary channels: the contract between the channel state machine and a
 * host-supplied provider that commits a second asset to a taproot channel
 * (Taproot Assets, as LND and tapd deploy them).
 *
 * The engine knows nothing of the asset itself. It keeps the Bitcoin
 * channel, asks the provider for one extra tapscript leaf per commitment
 * output, carries the provider's opaque bytes through storage and the wire,
 * and never hands the provider a private key. A node without
 * `INodeConfig.auxiliaryChannels` runs none of it.
 */

import { CodedError } from '../../utils/errors';
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
	/** This node's units in this commitment view, summed across the channel's asset IDs. */
	localAssetBalance: bigint;
	/** The peer's units in this commitment view, summed across the channel's asset IDs. */
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
	/**
	 * Only on a failed outcome of an HTLC this node received: the node had
	 * decided to settle it and its preimage left the node, in a fulfil made
	 * in the channel or in a claim it signed for the chain, and the payer
	 * took the output back all the same. The payer may hold the preimage,
	 * and the HTLC was not received. An ordinary failure does not carry
	 * it.
	 */
	preimageRevealed?: true;
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
 * What the node decided for one HTLC it received on an asset channel: to
 * settle it, with the preimage it settles with, or to fail it. A claim by
 * preimage on the chain is made for an HTLC with a decision to settle and
 * for no other; a preimage that is merely stored for the payment hash
 * decides nothing.
 */
export type IAuxiliaryHtlcDecision =
	| { outcome: 'settle'; preimage: Buffer }
	| { outcome: 'fail' };

/** What the node decided for an HTLC it received, by the HTLC's id. */
export function auxiliaryHtlcDecisionOf(
	state: { auxiliaryState?: IChannelAuxiliaryState },
	htlcId: bigint | undefined
): IAuxiliaryHtlcDecision | undefined {
	return htlcId === undefined
		? undefined
		: state.auxiliaryState?.htlcDecisions?.get(htlcId.toString());
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
	/**
	 * What the node decided for each HTLC it received, by the id of the
	 * HTLC in decimal. Written when the node decides (a fulfil or a fail it
	 * makes in the channel, a hold settled or cancelled while no message
	 * can carry it) and kept for as long as a commitment the node holds
	 * carries the HTLC, and from then on once the channel is on chain. Two
	 * HTLCs of one payment hash have a decision each.
	 */
	htlcDecisions?: Map<string, IAuxiliaryHtlcDecision>;
	/** This node's balance summed across the channel's asset IDs. */
	localBalance: bigint;
	/** The peer's balance summed across the channel's asset IDs. */
	remoteBalance: bigint;
	localShutdownRecords?: Map<bigint, Buffer>;
	remoteShutdownRecords?: Map<bigint, Buffer>;
	closeTransactions?: Map<string, Buffer>;
	/** Exact authenticated closing_signed accepted before the signed close was saved. */
	acceptedClosingSigned?: Buffer;
	/**
	 * The txid of a spend of the funding output that this node took for the
	 * cooperative close while it holds no close payload for it: the
	 * transaction is in no entry of closeTransactions, so the node cannot
	 * say where the units went. Set when the spend is seen, kept with the
	 * row, and told to the host with the close ('channel:closed'), once.
	 * Absent for a close the node signed.
	 */
	unrecordedCloseTxid?: string;
	/**
	 * The opener's host has been told that the peer signed the first
	 * commitment: onFundingSigned returned without throwing. Absent until
	 * then, so the news is delivered again after a restart or a throw.
	 */
	fundingSignedDelivered?: true;
	/** Signed views retained for force-close and revoked-commitment recovery. */
	localCommitments: Map<bigint, IAuxiliaryCommitmentData>;
	remoteCommitments: Map<bigint, IAuxiliaryCommitmentData>;
	/**
	 * Views of commitments of the peer that are revoked, held here until a
	 * store of revoked views has them (channel/auxiliary-revoked.ts). With
	 * such a store only the last few are here, and the one of a revoked
	 * commitment seen on the chain. Without one they all stay, in the row.
	 */
	revokedCommitments?: Map<bigint, IAuxiliaryCommitmentData>;
	/**
	 * The revoked commitment of the peer that is on the chain, whose view
	 * stays in `revokedCommitments`. Set while the node runs; never stored.
	 */
	revokedCommitmentHeld?: bigint;
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
	/**
	 * Reject invalid asset metadata before admitting an HTLC into channel
	 * state. Asked about every HTLC of an asset channel, with or without
	 * custom records.
	 */
	validateHtlc(state: IChannelState, entry: IHtlcEntry): void;
	/**
	 * The sum of the units this HTLC carries across the channel's asset IDs.
	 * Zero for a plain bitcoin HTLC, which an asset channel takes from its
	 * peer and never offers.
	 */
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

/** An independent deep copy of the asset side of one commitment. */
export function copyAuxiliaryCommitment(
	data: IAuxiliaryCommitmentData
): IAuxiliaryCommitmentData {
	const copyLeaf = (leaf: ITaprootAuxLeaf): ITaprootAuxLeaf => ({
		script: Buffer.from(leaf.script),
		...(leaf.leafVersion !== undefined ? { leafVersion: leaf.leafVersion } : {})
	});
	return {
		customData: Buffer.from(data.customData),
		...(data.secondLevelRevocationKey
			? {
					secondLevelRevocationKey: Buffer.from(data.secondLevelRevocationKey)
			  }
			: {}),
		...(data.secondLevelRevocationBasepoint
			? {
					secondLevelRevocationBasepoint: Buffer.from(
						data.secondLevelRevocationBasepoint
					)
			  }
			: {}),
		...(data.secondLevelCommitmentTxid !== undefined
			? { secondLevelCommitmentTxid: data.secondLevelCommitmentTxid }
			: {}),
		...(data.htlcOutputIndexes
			? { htlcOutputIndexes: new Map(data.htlcOutputIndexes) }
			: {}),
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

/**
 * The provider of an asset channel, or a throw. A channel is run as an asset
 * channel only with all three: its asset state, the provider that reads it,
 * and the 32-byte root its funding key commits to. Anything less stops the
 * transition that asked, so an asset channel is never signed for as an
 * ordinary one.
 */
export function requireAuxiliaryProvider(
	state: IChannelState
): IChannelAuxiliaryProvider {
	if (
		!state.auxiliaryState ||
		!state.auxiliaryProvider ||
		!state.fundingTaprootMerkleRoot ||
		state.fundingTaprootMerkleRoot.length !== 32
	) {
		const id = (state.channelId ?? state.temporaryChannelId).toString('hex');
		throw new Error(
			`Asset channel state or auxiliary provider is unavailable (channel ${id})`
		);
	}
	return state.auxiliaryProvider;
}

/**
 * The most HTLCs either side of an asset channel may hold open. Every asset
 * HTLC adds its proofs to what a commitment carries, and this is the count
 * LND holds its asset channels to.
 */
export const MAX_AUXILIARY_HTLCS_PER_PARTY = 83;

/**
 * The most HTLCs a node holds open at once on an asset channel, each way,
 * when its host sets no other number (`IAuxiliaryChannelConfig.maxHtlcs`).
 *
 * Every HTLC that is open when a channel goes to the chain is an output
 * the node has to spend in time, each with a fee input of its own from the
 * fee pool, which makes a few fee coins per preparation and a block each.
 * A commitment could carry far more HTLC outputs than a pool can pay for
 * before they expire. A node with asset channels is an endpoint that makes
 * and receives single payments, so it announces this number as its
 * max_accepted_htlcs and offers no more than the same number at once.
 */
export const DEFAULT_AUXILIARY_MAX_HTLCS = 8;

/**
 * The number a host set for the HTLCs its asset channels hold at once, or
 * the default. Throws for a number that cannot be one: it has to be whole,
 * at least 1 and no more than an asset channel may carry at all.
 */
export function auxiliaryMaxHtlcs(configured: number | undefined): number {
	if (configured === undefined) return DEFAULT_AUXILIARY_MAX_HTLCS;
	if (
		!Number.isInteger(configured) ||
		configured < 1 ||
		configured > MAX_AUXILIARY_HTLCS_PER_PARTY
	) {
		throw new Error(
			`The most HTLCs an asset channel holds at once (maxHtlcs) has to be a whole number from 1 to ${MAX_AUXILIARY_HTLCS_PER_PARTY}`
		);
	}
	return configured;
}
/** The dust limit of an asset channel: the 354 satoshi carrier of an asset HTLC. */
export const AUXILIARY_CHANNEL_DUST_LIMIT = 354n;

/**
 * Why `channelType` cannot be the type of this channel's asset opening, or
 * null when it can. Only for a channel that holds asset funding: the type
 * has to be the overlay, with nothing beside it but the asset HTLC modes,
 * scid_alias and zero_conf, and the channel has to be runnable as an asset
 * channel. A channel without asset funding is not this function's to judge.
 */
export function validateAuxiliaryChannelType(
	state: IChannelState,
	channelType: Buffer | null | undefined
): string | null {
	if (!state.auxiliaryState && !state.fundingTaprootMerkleRoot) return null;
	if (
		!channelType ||
		channelType.length === 0 ||
		channelType[0] === 0 ||
		!isOverlayChannel(channelType)
	) {
		return 'Asset channel requires the Taproot overlay channel type';
	}
	const allowed = new Set<number>([
		Feature.OPTION_TAPROOT_OVERLAY,
		Feature.OPTION_ASSET_FIXED_HTLC_OUTPUTS,
		Feature.OPTION_ASSET_CHILD_CUSTODY,
		Feature.SCID_ALIAS,
		Feature.ZERO_CONF
	]);
	const flags = FeatureFlags.fromBuffer(channelType);
	if (flags.listSetBits().some((bit) => !allowed.has(bit))) {
		return 'Invalid Taproot overlay channel type';
	}
	if (
		flags.hasBit(Feature.OPTION_ASSET_CHILD_CUSTODY) &&
		!flags.hasBit(Feature.OPTION_ASSET_FIXED_HTLC_OUTPUTS)
	) {
		return 'Child custody requires fixed asset HTLC outputs';
	}
	try {
		requireAuxiliaryProvider(state);
	} catch {
		return 'Asset channel funding context or provider is unavailable';
	}
	return null;
}

/**
 * The asset provider, or the commitment builder on its behalf, could not
 * answer for a commitment of an asset channel. Whatever asked is refused
 * with this, before anything it would have sent or stored.
 */
export class AuxiliaryProviderError extends CodedError<'ASSET_PROVIDER_REFUSED'> {
	/** The channel id, or the temporary id of a channel that has none yet, hex. */
	readonly channelId: string;
	/** What was being done, in a few words. */
	readonly operation: string;

	constructor(channelId: string, operation: string, cause: unknown) {
		super(
			'ASSET_PROVIDER_REFUSED',
			`The asset provider refused ${operation} (channel ${channelId}): ${
				cause instanceof Error ? cause.message : String(cause)
			}`,
			{ cause }
		);
		this.name = 'AuxiliaryProviderError';
		this.channelId = channelId;
		this.operation = operation;
	}
}

/** The typed refusal of `operation` on the channel `state` describes. */
export function auxiliaryProviderError(
	state: Pick<IChannelState, 'channelId' | 'temporaryChannelId'>,
	operation: string,
	cause: unknown
): AuxiliaryProviderError {
	return cause instanceof AuxiliaryProviderError
		? cause
		: new AuxiliaryProviderError(
				(state.channelId ?? state.temporaryChannelId).toString('hex'),
				operation,
				cause
		  );
}
