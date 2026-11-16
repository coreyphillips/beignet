/**
 * Auxiliary channels: what a host configures to run them
 * (`INodeConfig.auxiliaryChannels`) and the values that pass between the
 * node and the host while an asset channel is funded and used. Everything
 * here is a type.
 */

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
