/**
 * Auxiliary channels: what a host configures to run them
 * (`INodeConfig.auxiliaryChannels`) and the values that pass between the
 * node and the host while an asset channel is funded and used, with the
 * one function that turns a new channel into an asset channel.
 */

import { Feature, FeatureFlags } from '../features/flags';
import { funderCommitmentCostSats } from './commitment-builder';
import type { CustomRecords } from '../message/custom-records';
import type { IHopPayload } from '../onion/types';
import type { IInvoiceInfo } from '../storage/types';
import type { Channel } from './channel';
import type { IChannelState } from './channel-state';
import type {
	IAuxiliaryHtlcResolution,
	IAuxiliaryOpeningCsvPolicy,
	IChannelAuxiliaryProvider
} from './auxiliary';
import type { ChannelState } from './types';
import {
	AUXILIARY_CHANNEL_DUST_LIMIT,
	MAX_AUXILIARY_HTLCS_PER_PARTY
} from './auxiliary';

/** Validated by the asset protocol before standard channel negotiation starts. */
export interface IAuxiliaryFundingDescriptor {
	temporaryChannelId: Buffer;
	fundingTaprootMerkleRoot: Buffer;
	channelData: Buffer;
	localBalance: bigint;
	remoteBalance: bigint;
}

/** Public asset balances and routing identity of one channel, without key material. */
export interface IAuxiliaryChannelInfo {
	channelId: Buffer;
	temporaryChannelId: Buffer;
	peerPubkey: string;
	state: ChannelState;
	channelData: Buffer;
	localAssetBalance: bigint;
	remoteAssetBalance: bigint;
	nextLocalHtlcId: bigint;
	localBalanceMsat: bigint;
	remoteBalanceMsat: bigint;
	dustLimitSatoshis: bigint;
	shortChannelId?: Buffer;
}

/** The asset side of one outgoing HTLC. */
export interface IAuxiliaryPayment {
	/** Exact circuit whose quote was reserved before native admission. */
	expectedHtlcId?: bigint;
	channelId: Buffer;
	wireAmountMsat: bigint;
	customRecords: CustomRecords;
}

/** An incoming asset HTLC, for the host to value against its quote. */
export interface IAuxiliaryIncomingHtlc {
	state: IChannelState;
	peerPubkey: string;
	channelId: Buffer;
	htlcId: bigint;
	paymentHash: Buffer;
	wireAmountMsat: bigint;
	customRecords: CustomRecords;
	hopPayload: IHopPayload;
	isFinalHop: boolean;
	/** Previously accepted live circuits and their credited quoted value. */
	acceptedHtlcs: readonly {
		channelId: Buffer;
		htlcId: bigint;
		amountMsat: bigint;
	}[];
	invoice?: IInvoiceInfo;
}

/** A forward whose outgoing channel the host may resolve from a quote alias. */
export interface IAuxiliaryForwardContext {
	shortChannelId: Buffer;
	paymentHash: Buffer;
	amountToForwardMsat: bigint;
	outgoingCltvExpiry: number;
	incomingChannelId: Buffer;
	incomingHtlcId: bigint;
}

/** A forward placed on its outgoing channel, before the add is sent. */
export interface IAuxiliaryForwardPlacement extends IAuxiliaryForwardContext {
	state: IChannelState;
	outgoingChannelId: Buffer;
	outgoingHtlcId: bigint;
	peerPubkey: string;
}

/**
 * Asset channel support, set as `INodeConfig.auxiliaryChannels`. The
 * provider extends the channel state machine; the callbacks tie funding,
 * payment and forwarding to the host's asset protocol.
 */
export interface IAuxiliaryChannelConfig {
	/** Standard-wire CSV compatibility for new channels only. Does not authorize legacy signatures. */
	openingCsvPolicy?(peerPubkey: string): IAuxiliaryOpeningCsvPolicy | undefined;
	/** Explicitly permit delegated Bitcoin and asset custody for independently scoped revoked HTLC children. */
	allowRevokedChildCustody?: boolean;
	/** Explicit new-channel compatibility for peers lacking native fixed-output HTLCs. */
	allowLegacyHtlcSignatures?(peerPubkey: string): boolean;
	provider: IChannelAuxiliaryProvider;
	/** Return the quoted Bitcoin value of the admitted asset amount, or throw. */
	valueIncomingHtlc?(context: IAuxiliaryIncomingHtlc): bigint;
	/** Read-only lookup of a peer-bound RFQ alias before Bitcoin forwarding checks. */
	resolveForwardChannel?(
		context: IAuxiliaryForwardContext
	): { channelId: Buffer; peerPubkey: string } | undefined;
	/** Durably reserve a quote using the exact outgoing circuit before the add. */
	prepareForwardHtlc?(context: IAuxiliaryForwardPlacement): IAuxiliaryPayment;
	/** Called only when admission did not consume the outgoing HTLC ID. */
	onForwardAdmissionFailed?(
		context: IAuxiliaryForwardPlacement & { customRecords?: CustomRecords }
	): void;
	/** Idempotent durable callback, delivered again after a crash until acknowledged. */
	onHtlcResolved?(
		context: IAuxiliaryHtlcResolution & {
			state: IChannelState;
			peerPubkey: string;
			channelId: Buffer;
		}
	): void;
	/** Complete local asset negotiation durably before accept_channel is sent. */
	beforeAccept?(channel: Channel, peerPubkey: string): Promise<void>;
	/** Wait for validation of custom funding proofs before the initial signature. */
	beforeFundingCreated?(channel: Channel, peerPubkey: string): Promise<void>;
	/** Custom records (types at or above 65536) sent in this node's init. */
	initCustomRecords?: CustomRecords;
	/** Look up a durable, peer-bound incoming asset funding negotiation. */
	resolveIncoming(
		peerPubkey: string,
		temporaryChannelId: Buffer
	): IAuxiliaryFundingDescriptor | undefined;
	/** Takes over anchor assembly after the peer accepts the Bitcoin parameters. */
	onAccepted?(channel: Channel, peerPubkey: string): void;
}

/** The most asset funding data a channel carries: 64 MiB. */
export const MAX_AUXILIARY_FUNDING_DATA_BYTES = 64 * 1024 * 1024;

/**
 * Throw unless a funding descriptor can open an asset channel: a temporary
 * channel id a peer can answer to, a 32-byte funding root, balances that
 * are not negative, not both zero and together within a u64, and funding
 * data within its limit. Pure, so an opening can be refused before a key
 * index is spent on it.
 */
export function validateAuxiliaryFunding(
	descriptor: IAuxiliaryFundingDescriptor
): void {
	if (
		!descriptor ||
		!Buffer.isBuffer(descriptor.temporaryChannelId) ||
		descriptor.temporaryChannelId.length !== 32 ||
		descriptor.temporaryChannelId.every((byte) => byte === 0) ||
		!Buffer.isBuffer(descriptor.fundingTaprootMerkleRoot) ||
		descriptor.fundingTaprootMerkleRoot.length !== 32
	) {
		throw new Error('Invalid asset funding identity');
	}
	if (
		typeof descriptor.localBalance !== 'bigint' ||
		typeof descriptor.remoteBalance !== 'bigint' ||
		descriptor.localBalance < 0n ||
		descriptor.remoteBalance < 0n ||
		descriptor.localBalance + descriptor.remoteBalance <= 0n ||
		descriptor.localBalance + descriptor.remoteBalance > 0xffffffffffffffffn
	) {
		throw new Error('Invalid asset funding balances');
	}
	if (
		!Buffer.isBuffer(descriptor.channelData) ||
		descriptor.channelData.length > MAX_AUXILIARY_FUNDING_DATA_BYTES
	) {
		throw new Error('Asset funding data exceeds limit');
	}
}

/** The dust limit an asset channel runs with, given the configured one. */
export function auxiliaryDustLimit(configured: bigint): bigint {
	return configured > AUXILIARY_CHANNEL_DUST_LIMIT
		? AUXILIARY_CHANNEL_DUST_LIMIT
		: configured;
}

/** The type every asset channel has at least: the overlay bit alone. */
const OVERLAY_CHANNEL_TYPE = ((): Buffer => {
	const flags = FeatureFlags.empty();
	flags.setCompulsory(Feature.OPTION_TAPROOT_OVERLAY);
	return flags.toBuffer();
})();

/** The bitcoin side of an opening, as far as it decides who gets an output. */
export interface IAuxiliaryCarrier {
	fundingSatoshis: bigint;
	pushMsat: bigint;
	/** The feerate of the opening's first commitments. */
	feeratePerKw: number;
	openerAssetBalance: bigint;
	acceptorAssetBalance: bigint;
	/**
	 * The larger of the two sides' dust limits, as far as they are known:
	 * each commitment is trimmed with its holder's, and a side that holds
	 * asset units needs its output on both.
	 */
	dustLimitSatoshis: bigint;
}

/**
 * Why the bitcoin of an opening cannot carry its asset balances, or
 * undefined. A side that holds asset units needs an output of its own on
 * both first commitments. This is the commitment builder's own arithmetic
 * for a commitment without HTLCs: the acceptor has what it is pushed,
 * rounded down to a satoshi, and the opener has the rest, rounded down,
 * less the commitment fee and the two anchors, which it pays. Either is an
 * output when it reaches the dust limit.
 */
export function auxiliaryCarrierError(
	opening: IAuxiliaryCarrier
): string | undefined {
	const cost = funderCommitmentCostSats(
		opening.feeratePerKw,
		0,
		OVERLAY_CHANNEL_TYPE
	);
	const acceptor = opening.pushMsat / 1000n;
	const opener =
		(opening.fundingSatoshis * 1000n - opening.pushMsat) / 1000n - cost;
	const dust = opening.dustLimitSatoshis;
	if (opening.acceptorAssetBalance > 0n && acceptor < dust) {
		return `The acceptor of an asset channel holds asset units and has to be pushed at least ${dust} satoshis to carry them`;
	}
	if (opening.openerAssetBalance > 0n && opener < dust) {
		return `The opener of an asset channel holds asset units and has to keep at least ${dust} satoshis, after the ${cost} of the commitment fee and anchors, to carry them`;
	}
	return undefined;
}

/**
 * Make a channel that has not said anything to its peer yet an asset
 * channel: the root its funding key commits to, the asset balances, and the
 * dust limit and HTLC count of an asset channel where the configured ones
 * are looser. The descriptor has to be for this channel's temporary id.
 */
export function applyAuxiliaryFunding(
	state: IChannelState,
	descriptor: IAuxiliaryFundingDescriptor
): void {
	validateAuxiliaryFunding(descriptor);
	if (!descriptor.temporaryChannelId.equals(state.temporaryChannelId)) {
		throw new Error('Invalid asset funding identity');
	}
	state.localConfig = {
		...state.localConfig,
		dustLimitSatoshis: auxiliaryDustLimit(state.localConfig.dustLimitSatoshis),
		maxAcceptedHtlcs: Math.min(
			state.localConfig.maxAcceptedHtlcs,
			MAX_AUXILIARY_HTLCS_PER_PARTY
		)
	};
	state.fundingTaprootMerkleRoot = Buffer.from(
		descriptor.fundingTaprootMerkleRoot
	);
	state.auxiliaryState = {
		channelData: Buffer.from(descriptor.channelData),
		localBalance: descriptor.localBalance,
		remoteBalance: descriptor.remoteBalance,
		localCommitments: new Map(),
		remoteCommitments: new Map()
	};
}
