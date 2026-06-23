/**
 * BOLT 2: Channel data types, enums, and configuration.
 */

import { FeatureFlags, Feature } from '../features/flags';

/**
 * Check whether a negotiated channel_type includes option_anchors_zero_fee_htlc_tx.
 * Returns true if bit 22 (ANCHOR_ZERO_FEE_HTLC) is set.
 */
export function isAnchorChannel(channelType: Buffer | null): boolean {
	if (!channelType || channelType.length === 0) return false;
	return FeatureFlags.fromBuffer(channelType).hasFeature(
		Feature.ANCHOR_ZERO_FEE_HTLC
	);
}

export enum ChannelState {
	NONE = 'NONE',
	SENT_OPEN = 'SENT_OPEN',
	SENT_ACCEPT = 'SENT_ACCEPT',
	SENT_FUNDING_CREATED = 'SENT_FUNDING_CREATED',
	SENT_FUNDING_SIGNED = 'SENT_FUNDING_SIGNED',
	AWAITING_FUNDING_CONFIRMED = 'AWAITING_FUNDING_CONFIRMED',
	AWAITING_CHANNEL_READY = 'AWAITING_CHANNEL_READY',
	NORMAL = 'NORMAL',
	SHUTTING_DOWN = 'SHUTTING_DOWN',
	NEGOTIATING_CLOSING = 'NEGOTIATING_CLOSING',
	AWAITING_REESTABLISH = 'AWAITING_REESTABLISH',
	DUAL_FUNDING_V2 = 'DUAL_FUNDING_V2',
	AWAITING_TX_SIGNATURES = 'AWAITING_TX_SIGNATURES',
	SPLICING = 'SPLICING',
	CLOSED = 'CLOSED',
	FORCE_CLOSED = 'FORCE_CLOSED',
	ERRORED = 'ERRORED'
}

export enum ChannelRole {
	OPENER = 'OPENER',
	ACCEPTOR = 'ACCEPTOR'
}

export enum HtlcDirection {
	OFFERED = 'OFFERED',
	RECEIVED = 'RECEIVED'
}

export enum HtlcState {
	PENDING = 'PENDING',
	COMMITTED = 'COMMITTED',
	FULFILLED = 'FULFILLED',
	FAILED = 'FAILED'
}

export interface IHtlcEntry {
	id: bigint;
	amountMsat: bigint;
	paymentHash: Buffer;
	cltvExpiry: number;
	onionRoutingPacket: Buffer;
	direction: HtlcDirection;
	state: HtlcState;
}

export interface IChannelConfig {
	dustLimitSatoshis: bigint;
	maxHtlcValueInFlightMsat: bigint;
	channelReserveSatoshis: bigint;
	htlcMinimumMsat: bigint;
	toSelfDelay: number;
	maxAcceptedHtlcs: number;
	feeratePerKw: number;
}

/** BOLT 2: Maximum allowed number of pending HTLCs per direction */
export const MAX_ACCEPTED_HTLCS = 483;

/** BOLT 2: Maximum channel funding size (2^24 satoshis without wumbo) */
export const MAX_FUNDING_SATOSHIS = 16777216n;

/** Dust limit matching LND's DustLimitForSize(UnknownWitnessSize) = 354 sat.
 *  LND requires: 354 <= dustLimit <= 1062, and
 *  min(ourReserve, theirReserve) >= max(ourDust, theirDust).
 *  Using 354 ensures compatibility with LND's own 354 dust limit. */
export const MIN_DUST_LIMIT_SATOSHIS = 354n;

/** Default channel configuration */
export const DEFAULT_CHANNEL_CONFIG: IChannelConfig = {
	dustLimitSatoshis: 354n,
	maxHtlcValueInFlightMsat: 500_000_000n,
	channelReserveSatoshis: 10_000n,
	htlcMinimumMsat: 1_000n,
	toSelfDelay: 144,
	maxAcceptedHtlcs: 483,
	feeratePerKw: 253
};

/** Result type for ChannelManager operations that may fail. */
export interface ChannelResult {
	ok: boolean;
	actions: import('./channel-actions').ChannelAction[];
	error?: string;
}

/** Bitcoin mainnet chain hash */
export const BITCOIN_CHAIN_HASH = Buffer.from(
	'6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000',
	'hex'
);

/** Bitcoin regtest chain hash */
export const REGTEST_CHAIN_HASH = Buffer.from(
	'06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f',
	'hex'
);
