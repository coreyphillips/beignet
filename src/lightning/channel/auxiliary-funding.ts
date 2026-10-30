import type { CustomRecords } from '../message/custom-records';
import type { IHopPayload } from '../onion/types';
import type { IInvoiceInfo } from '../storage/types';
import type { IChannelState } from './channel-state';
import type {
	IAuxiliaryHtlcResolution,
	IChannelAuxiliaryProvider
} from './auxiliary';

/** Validated by the asset protocol before standard channel negotiation starts. */
export interface IAuxiliaryFundingDescriptor {
	temporaryChannelId: Buffer;
	fundingTaprootMerkleRoot: Buffer;
	channelData: Buffer;
	localBalance: bigint;
	remoteBalance: bigint;
}

export interface IAuxiliaryChannelInfo {
	channelId: Buffer;
	temporaryChannelId: Buffer;
	peerPubkey: string;
	state: import('./types').ChannelState;
	channelData: Buffer;
	localAssetBalance: bigint;
	remoteAssetBalance: bigint;
	nextLocalHtlcId: bigint;
	localBalanceMsat: bigint;
	remoteBalanceMsat: bigint;
	dustLimitSatoshis: bigint;
	shortChannelId?: Buffer;
}

export interface IAuxiliaryPayment {
	/** Exact circuit whose quote was reserved before native admission. */
	expectedHtlcId?: bigint;
	channelId: Buffer;
	wireAmountMsat: bigint;
	customRecords: CustomRecords;
}
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

export interface IAuxiliaryForwardContext {
	shortChannelId: Buffer;
	paymentHash: Buffer;
	amountToForwardMsat: bigint;
	outgoingCltvExpiry: number;
	incomingChannelId: Buffer;
	incomingHtlcId: bigint;
}
export interface IAuxiliaryForwardPlacement extends IAuxiliaryForwardContext {
	state: IChannelState;
	outgoingChannelId: Buffer;
	outgoingHtlcId: bigint;
	peerPubkey: string;
}

export interface IAuxiliaryChannelConfig {
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
	beforeAccept?(
		channel: import('./channel').Channel,
		peerPubkey: string
	): Promise<void>;
	/** Wait for validation of custom funding proofs before the initial signature. */
	beforeFundingCreated?(
		channel: import('./channel').Channel,
		peerPubkey: string
	): Promise<void>;
	initCustomRecords?: import('../message/custom-records').CustomRecords;
	/** Look up a durable, peer-bound incoming asset funding negotiation. */
	resolveIncoming(
		peerPubkey: string,
		temporaryChannelId: Buffer
	): IAuxiliaryFundingDescriptor | undefined;
	/** Takes over anchor assembly after the peer accepts the Bitcoin parameters. */
	onAccepted?(channel: import('./channel').Channel, peerPubkey: string): void;
}

export function applyAuxiliaryFunding(
	state: IChannelState,
	descriptor: IAuxiliaryFundingDescriptor
): void {
	if (
		descriptor.temporaryChannelId.length !== 32 ||
		!descriptor.temporaryChannelId.equals(state.temporaryChannelId) ||
		descriptor.fundingTaprootMerkleRoot.length !== 32
	)
		throw new Error('Invalid asset funding identity');
	const max = (1n << 64n) - 1n;
	if (
		descriptor.localBalance < 0n ||
		descriptor.remoteBalance < 0n ||
		descriptor.localBalance + descriptor.remoteBalance <= 0n ||
		descriptor.localBalance + descriptor.remoteBalance > max
	)
		throw new Error('Invalid asset funding balances');
	if (descriptor.channelData.length > 64 * 1024 * 1024)
		throw new Error('Asset funding data exceeds limit');
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
