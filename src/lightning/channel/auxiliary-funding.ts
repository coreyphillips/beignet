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
import type {
	IAuxiliaryForwardLegResolution,
	IAuxiliaryForwardRequest,
	IAuxiliaryForwardTerms
} from './auxiliary-forward';
import type { ChannelState } from './types';
import {
	AUXILIARY_CHANNEL_DUST_LIMIT,
	DEFAULT_AUXILIARY_MAX_HTLCS,
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
	/**
	 * The asset units on this node's side that no HTLC holds. An HTLC this
	 * node offered leaves this balance when it is added and comes back only
	 * if it fails; one in flight is in neither balance, it is in `htlcs`.
	 */
	localAssetBalance: bigint;
	/**
	 * The asset units on the peer's side that no HTLC holds: an HTLC the
	 * peer offered left this balance when it arrived.
	 */
	remoteAssetBalance: bigint;
	nextLocalHtlcId: bigint;
	localBalanceMsat: bigint;
	remoteBalanceMsat: bigint;
	dustLimitSatoshis: bigint;
	shortChannelId?: Buffer;
	/**
	 * How many outcomes of the channel's asset HTLCs the host has not taken
	 * yet (onHtlcResolved has not returned for them). Present only when
	 * there are some. Above ChannelManager.AUXILIARY_MAX_UNDELIVERED_OUTCOMES
	 * the channel takes no further asset HTLC.
	 */
	undeliveredOutcomes?: number;
	/**
	 * How large the store of revoked views of the channel is: `rows`, one
	 * for each commitment of the peer whose asset side the node keeps so
	 * that it can punish that commitment, and `bytes`, what their values
	 * take in the database. It grows by a row with every commitment the
	 * peer revokes (two for a payment that settles) and is not trimmed
	 * while the channel lives; it is dropped with the channel. Present when
	 * the node's storage keeps that store, which the SQLite backend does.
	 */
	revokedViews?: { rows: number; bytes: number };
	/** The HTLCs in flight on the channel, each side's, with what they carry. */
	htlcs: IAuxiliaryChannelHtlc[];
}

/** One HTLC in flight on an asset channel. */
export interface IAuxiliaryChannelHtlc {
	htlcId: bigint;
	/** Offered by this node, or received from the peer. */
	direction: 'offered' | 'received';
	paymentHash: Buffer;
	/** The bitcoin the HTLC carries on the wire. */
	wireAmountMsat: bigint;
	cltvExpiry: number;
	/** The asset units the HTLC carries. Absent for a plain bitcoin HTLC. */
	auxiliaryAmount?: bigint;
	/** The custom records the HTLC was added with. Empty for a plain HTLC. */
	customRecords: CustomRecords;
}

/** One HTLC an asset payment went out as. */
export interface IAuxiliaryPaymentHtlc {
	channelId: Buffer;
	htlcId: bigint;
	/** What the HTLC is worth to the payment, as the route carries it. */
	amountMsat: bigint;
	/** The HTLC as its channel holds it, while it is in flight there. */
	htlc?: IAuxiliaryChannelHtlc;
}

/** How fundAuxiliaryChannel is given the funding transaction. */
export interface IAuxiliaryFundingOptions {
	/**
	 * The script each input of the transaction spends, in input order. Given,
	 * the transaction is unsigned: the node keeps and broadcasts nothing of
	 * it, and the host signs and publishes it after `onFundingSigned`.
	 */
	prevoutScripts?: Buffer[];
}

/** An asset opening at its point of no return. */
export interface IAuxiliaryFundingSigned {
	channelId: Buffer;
	temporaryChannelId: Buffer;
	peerPubkey: string;
	/** The funding transaction's id, in the byte order of the wire. */
	fundingTxid: Buffer;
	fundingOutputIndex: number;
}

/** The asset side of one outgoing HTLC. */
export interface IAuxiliaryPayment {
	/** Exact circuit whose quote was reserved before native admission. */
	expectedHtlcId?: bigint;
	channelId: Buffer;
	wireAmountMsat: bigint;
	customRecords: CustomRecords;
}

/**
 * An incoming HTLC, for the host to claim and value or to leave alone. It
 * need not be an asset HTLC, nor have arrived on an asset channel.
 */
export interface IAuxiliaryIncomingHtlc {
	state: IChannelState;
	peerPubkey: string;
	channelId: Buffer;
	htlcId: bigint;
	paymentHash: Buffer;
	wireAmountMsat: bigint;
	/** The asset units the HTLC carries. Absent for a plain bitcoin HTLC. */
	auxiliaryAmount?: bigint;
	/** Empty for a plain bitcoin HTLC. */
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

/** An asset channel a restore is about to bring back. */
export interface IAuxiliaryRestoredChannel {
	channelId: Buffer;
	peerPubkey: string;
	/**
	 * Where the channel comes from: the recovery journal, which carries the
	 * node's rows for it as they were at its head, or a static channel
	 * backup, which carries no asset state at all and can only ask the peer
	 * to close.
	 */
	source: 'journal' | 'static-backup';
	/** The asset funding data the journal holds for it. */
	channelData?: Buffer;
}

/**
 * Asset channel support, set as `INodeConfig.auxiliaryChannels`. The
 * provider extends the channel state machine; the callbacks tie funding
 * and payment to the host's asset protocol. A node with asset channels is
 * only ever an endpoint of an asset payment: nothing that arrives on an
 * asset channel is forwarded, and nothing is forwarded out over one. The
 * hooks of a forward with an asset leg (`prepareForward`,
 * `onForwardLegResolved`) are declared and not called yet.
 */
export interface IAuxiliaryChannelConfig {
	/** Standard-wire CSV compatibility for new channels only. Does not authorize legacy signatures. */
	openingCsvPolicy?(peerPubkey: string): IAuxiliaryOpeningCsvPolicy | undefined;
	/** Explicitly permit delegated Bitcoin and asset custody for independently scoped revoked HTLC children. */
	allowRevokedChildCustody?: boolean;
	/** Explicit new-channel compatibility for peers lacking native fixed-output HTLCs. */
	allowLegacyHtlcSignatures?(peerPubkey: string): boolean;
	/**
	 * The most HTLCs this node holds open at once on an asset channel, each
	 * way: a whole number from 1 to 83, 8 when not set. The node announces
	 * it as its max_accepted_htlcs on every asset channel it opens or
	 * accepts from then on, and offers no more than this many asset HTLCs
	 * at once on any asset channel, whatever the peer would accept and
	 * whatever the channel announced when it was opened: the next asset
	 * payment is refused with `ASSET_HTLC_LIMIT_REACHED` before anything is
	 * sent. Each open HTLC is an output the node must spend in time, with a
	 * fee input of its own, if the channel goes to the chain, so keep it
	 * within what the fee pool can pay for. Ordinary channels are not
	 * touched.
	 */
	maxHtlcs?: number;
	provider: IChannelAuxiliaryProvider;
	/**
	 * Asked, before the node settles it and outside any storage
	 * transaction, about every incoming HTLC that ends at this node, whatever
	 * channel it arrived on. Only the host knows that a payment hash belongs
	 * to an asset invoice, so it sees each of them and can refuse. An HTLC
	 * that arrived on an asset channel or carries asset units and does not
	 * end at this node is failed back without asking. One of three answers:
	 *
	 * - A value in millisatoshis, above zero and within a u64: the HTLC is
	 *   the host's and is worth that much. The node goes on with that value
	 *   in place of the bitcoin amount on the wire: an invoice is judged paid
	 *   against it.
	 * - `undefined`: the HTLC is not the host's. It carries no asset units
	 *   and its payment hash is not one the host issued an asset invoice or
	 *   holds a quote for. The node goes on exactly as a node without asset
	 *   channels would, on the bitcoin amount the HTLC carries. Given for an
	 *   HTLC that carries asset units or arrived on an asset channel it is a
	 *   refusal, because such an HTLC is always the host's to value.
	 * - A throw: the HTLC is failed back. It is never settled, and the
	 *   node's own invoice logic never sees it. This is the answer for a
	 *   plain HTLC whose payment hash belongs to an invoice issued for asset
	 *   units: between two wallets such an invoice's face in satoshis is
	 *   nominal, and settling it for that many satoshis would give a receipt
	 *   for the units away.
	 *
	 * Anything else returned (null, zero, a negative, not a bigint) refuses
	 * as a throw does. Without this hook an HTLC that carries asset units or
	 * arrives on an asset channel is failed back, and no other is asked
	 * about.
	 */
	valueIncomingHtlc?(context: IAuxiliaryIncomingHtlc): bigint | undefined;
	/**
	 * Declared and not called by this build: every forward with an asset leg
	 * is refused before anything is offered, whatever this would answer. The
	 * contract it will be called under is in docs/EXTENSIONS.md ("Forwards
	 * with an asset leg"), and `AUXILIARY_CHANNELS_API` lists it in
	 * `surfaces` from the build that calls it.
	 *
	 * Asked about an HTLC the node is to forward when either leg is an asset
	 * leg, or when its next hop is a short channel id the node has no channel
	 * for, once the incoming HTLC is irrevocably committed. Asked once for
	 * each incoming HTLC, synchronously, outside any storage transaction and
	 * before anything is offered; the answer is kept with the forward and is
	 * not asked again on a reestablish or after a restart, except when the
	 * node stopped before it was kept, so the host answers a second ask about
	 * an HTLC as it answered the first. When the forward no longer passes the
	 * checks made before the ask, or the incoming channel can no longer settle
	 * the HTLC, the node does not ask again and tells `onForwardLegResolved`
	 * the outgoing leg was never offered. One of three answers:
	 *
	 * - The host's terms: the forward goes on if every check of the node's
	 *   own passes, and is failed back otherwise.
	 * - `undefined`: not the host's. Only for a forward without an asset leg,
	 *   which goes on as on a node without asset channels; for one with an
	 *   asset leg it refuses.
	 * - A throw: the incoming HTLC is failed back and nothing is offered.
	 *
	 * Anything else refuses as a throw does. Without this hook every forward
	 * with an asset leg is refused, and no other forward is asked about.
	 * `valueIncomingHtlc` is never asked about a forward.
	 */
	prepareForward?(
		request: IAuxiliaryForwardRequest
	): IAuxiliaryForwardTerms | undefined;
	/**
	 * Declared and not called by this build. The end of each leg of a
	 * forward the host took on, in its channel or on the chain, told once
	 * the leg's HTLC has left its channel for good or the chain has resolved
	 * it. Idempotent durable callback, delivered again after a crash until it
	 * returns without throwing, outside any storage transaction. A promise
	 * it returns is not awaited: the leg counts as delivered when the call
	 * returns, and a later rejection does not deliver it again.
	 * `onHtlcResolved` keeps its own rules for asset HTLCs, a leg of a
	 * forward or not.
	 */
	onForwardLegResolved?(resolution: IAuxiliaryForwardLegResolution): void;
	/**
	 * Idempotent durable callback, delivered again after a crash until
	 * acknowledged.
	 *
	 * The outcome 'never-sent' is for a part of an outgoing asset payment
	 * that was recorded and whose HTLC never entered its channel, because
	 * the node stopped between the two. It is delivered when the node is
	 * restored, with the HTLC id the part was prepared for, no units
	 * (auxiliaryAmount is 0) and no custom records: nothing left the
	 * channel, which gives that id to its next HTLC.
	 */
	onHtlcResolved?(
		context: Omit<IAuxiliaryHtlcResolution, 'outcome'> & {
			outcome: IAuxiliaryHtlcResolution['outcome'] | 'never-sent';
			state: IChannelState;
			peerPubkey: string;
			channelId: Buffer;
		}
	): void;
	/**
	 * The point of no return of an asset opening this node began: the peer's
	 * funding_signed is verified and the channel's row is written. Called
	 * outside any storage transaction, before the node broadcasts a funding
	 * transaction it was given signed, and never before that moment. Until
	 * it is called the host can abandon the opening
	 * (`abandonAuxiliaryOpen`); from it on the opening is irrevocable and the
	 * funding transaction may be signed and published. Idempotent by
	 * contract: it is called for the same channel again, when the channel
	 * is restored and after the next write of it that commits, until one
	 * call has returned without throwing and the channel's row says so. A
	 * throw is reported and changes nothing else: the opening is irrevocable
	 * all the same. "Irrevocable" follows the written row: a funding_signed
	 * that was verified while the row could not be written has told the
	 * host nothing, and that opening can still be abandoned.
	 */
	onFundingSigned?(context: IAuxiliaryFundingSigned): void;
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
	/**
	 * Whether the host can run these asset channels once a restore has
	 * brought the node's rows for them back. A restore brings nothing of
	 * what the host keeps beside those rows, so one that holds asset
	 * channels is refused, with nothing installed, unless this returns
	 * `true`: absent, `false`, a throw and anything else all refuse
	 * (`AuxiliaryRestoreRefusedError`). Synchronous.
	 */
	canRestore?(channels: readonly IAuxiliaryRestoredChannel[]): boolean;
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
 * `maxHtlcs` is the most HTLCs this node accepts at once on the channel,
 * which it announces to its peer: the host's number, or the default.
 */
export function applyAuxiliaryFunding(
	state: IChannelState,
	descriptor: IAuxiliaryFundingDescriptor,
	maxHtlcs: number = DEFAULT_AUXILIARY_MAX_HTLCS
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
			MAX_AUXILIARY_HTLCS_PER_PARTY,
			maxHtlcs
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
