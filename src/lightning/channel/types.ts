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
	const flags = FeatureFlags.fromBuffer(channelType);
	// Simple taproot channels are always anchor-style commitments. LND's taproot
	// channel_type contains ONLY the taproot bit (not the anchor bit), so treat
	// taproot as implying anchors here — every internal anchor branch (to_remote
	// 1-CSV, anchor outputs, zero-fee HTLC, CSV sweep sequence) must still fire.
	return (
		flags.hasFeature(Feature.ANCHOR_ZERO_FEE_HTLC) ||
		flags.hasFeature(Feature.OPTION_TAPROOT)
	);
}

/**
 * Check whether a negotiated channel_type includes option_taproot (simple
 * taproot channels). Returns true if bit 80/81 (OPTION_TAPROOT) is set.
 */
export function isTaprootChannel(channelType: Buffer | null): boolean {
	if (!channelType || channelType.length === 0) return false;
	return FeatureFlags.fromBuffer(channelType).hasFeature(
		Feature.OPTION_TAPROOT
	);
}

/**
 * Check whether a negotiated channel_type includes option_scid_alias.
 *
 * BOLT 2 conditions the "MUST NOT allow incoming HTLCs using the real
 * short_channel_id" rule on the CHANNEL TYPE, not on announce_channel. A private
 * channel that did not negotiate option_scid_alias may still be addressed by its
 * real SCID, and peers routinely do so via invoice route hints.
 */
export function hasScidAliasChannelType(channelType: Buffer | null): boolean {
	if (!channelType || channelType.length === 0) return false;
	return FeatureFlags.fromBuffer(channelType).hasFeature(Feature.SCID_ALIAS);
}

/**
 * Refuse a proposed dual-funded (v2) channel_type before ANY state exists
 * for it, or return null when it is acceptable.
 *
 * BOLT 2 defines channel types as explicit even-bit combinations, so this
 * is an allow-list, not a bit filter: static_remotekey, optionally with
 * anchors_zero_fee_htlc_tx, optionally with scid_alias (+zero_conf, which
 * BOLT 9 makes dependent on scid_alias). Everything else is refused,
 * including option_taproot: taproot v2 signing is unimplemented (the
 * commitment stage fails closed), and a negotiation that is guaranteed to
 * die later must be refused at admission, before keys are derived, state
 * is retained or an ACCEPT_CHANNEL2 is sent.
 *
 * BOLT 2 makes channel_type REQUIRED on open_channel2 (unlike the legacy
 * open, where it is optional), so an absent or empty value is refused
 * outright, as is a non-minimal encoding (leading zero bytes): two
 * different byte strings for one type would let the echo check be
 * satisfied by a value the commitment dispatch reads differently.
 *
 * Every bit is additionally held to BOTH feature vectors when the caller
 * supplies them, per BOLT 2's rule that a channel_type must not carry
 * un-negotiated features (the default vector advertises scid_alias and
 * zero_conf, so this costs nothing between our own nodes; zero-conf
 * ACCEPTANCE stays separately gated on the trusted set where the type is
 * adopted). A vector the caller does not have (raw Channel harnesses,
 * manager-less drivers) skips only its own half of that check.
 */
export function validateV2ChannelType(
	channelType: Buffer | null | undefined,
	localFeatures?: FeatureFlags | null,
	remoteFeatures?: FeatureFlags | null
): string | null {
	if (!channelType || channelType.length === 0) {
		return 'open_channel2 requires a channel_type';
	}
	if (channelType[0] === 0) {
		return 'channel_type must use a minimal encoding';
	}
	const flags = FeatureFlags.fromBuffer(channelType);
	if (flags.hasFeature(Feature.OPTION_TAPROOT)) {
		return 'channel_type option_taproot is not supported for dual-funded (v2) channels';
	}
	// Only the even (compulsory) bits of the known combinations may appear;
	// any other bit, odd bits included, is an unknown type.
	const allowed = FeatureFlags.empty();
	allowed.setCompulsory(Feature.STATIC_REMOTE_KEY);
	allowed.setCompulsory(Feature.ANCHOR_ZERO_FEE_HTLC);
	allowed.setCompulsory(Feature.SCID_ALIAS);
	allowed.setCompulsory(Feature.ZERO_CONF);
	const mask = allowed.toBuffer();
	for (let i = 0; i < channelType.length; i++) {
		const bits = channelType[channelType.length - 1 - i];
		const permitted = i < mask.length ? mask[mask.length - 1 - i] : 0;
		if ((bits & ~permitted) !== 0) {
			return 'channel_type is not a recognized dual-funded (v2) combination';
		}
	}
	if (!flags.hasFeature(Feature.STATIC_REMOTE_KEY)) {
		return 'channel_type must include static_remotekey';
	}
	if (
		flags.hasFeature(Feature.ZERO_CONF) &&
		!flags.hasFeature(Feature.SCID_ALIAS)
	) {
		return 'channel_type zero_conf requires option_scid_alias';
	}
	if (flags.hasFeature(Feature.ANCHOR_ZERO_FEE_HTLC)) {
		if (
			localFeatures != null &&
			!localFeatures.hasFeature(Feature.ANCHOR_ZERO_FEE_HTLC)
		) {
			return 'channel_type anchors_zero_fee_htlc_tx was not negotiated: this node does not advertise it';
		}
		if (
			remoteFeatures != null &&
			!remoteFeatures.hasFeature(Feature.ANCHOR_ZERO_FEE_HTLC)
		) {
			return 'channel_type anchors_zero_fee_htlc_tx was not negotiated: the peer does not advertise it';
		}
	}
	if (
		localFeatures != null &&
		!localFeatures.hasFeature(Feature.STATIC_REMOTE_KEY)
	) {
		return 'channel_type static_remotekey was not negotiated: this node does not advertise it';
	}
	if (
		remoteFeatures != null &&
		!remoteFeatures.hasFeature(Feature.STATIC_REMOTE_KEY)
	) {
		return 'channel_type static_remotekey was not negotiated: the peer does not advertise it';
	}
	if (flags.hasFeature(Feature.SCID_ALIAS)) {
		if (
			localFeatures != null &&
			!localFeatures.hasFeature(Feature.SCID_ALIAS)
		) {
			return 'channel_type scid_alias was not negotiated: this node does not advertise it';
		}
		if (
			remoteFeatures != null &&
			!remoteFeatures.hasFeature(Feature.SCID_ALIAS)
		) {
			return 'channel_type scid_alias was not negotiated: the peer does not advertise it';
		}
	}
	if (flags.hasFeature(Feature.ZERO_CONF)) {
		if (localFeatures != null && !localFeatures.hasFeature(Feature.ZERO_CONF)) {
			return 'channel_type zero_conf was not negotiated: this node does not advertise it';
		}
		if (
			remoteFeatures != null &&
			!remoteFeatures.hasFeature(Feature.ZERO_CONF)
		) {
			return 'channel_type zero_conf was not negotiated: the peer does not advertise it';
		}
	}
	return null;
}

/**
 * BOLT 2: a channel whose type carries option_scid_alias MUST NOT be
 * announced. Returns the refusal, or null when the pairing is legal.
 * Callers with a channel_flags byte pass its announce bit (0x01).
 */
export function scidAliasAnnounceRefusal(
	channelType: Buffer | null | undefined,
	announceChannel: boolean
): string | null {
	if (!announceChannel) return null;
	if (!channelType || channelType.length === 0) return null;
	if (!FeatureFlags.fromBuffer(channelType).hasFeature(Feature.SCID_ALIAS)) {
		return null;
	}
	return 'a channel_type carrying option_scid_alias cannot be announced';
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
	/**
	 * Route blinding (BOLT 2/4): blinding_point received in (or sent with) the
	 * update_add_htlc. Present when this HTLC enters a blinded path; a downstream
	 * blinded hop uses it to derive its blinded node key for onion processing.
	 */
	blindingPoint?: Buffer;

	/**
	 * BOLT 2 two-phase updates — OUR side of an update the PEER has not yet
	 * irrevocably committed. The peer only bakes an update of ours into its
	 * signatures over OUR commitment after it has revoked a commitment of its
	 * own covering the update; until then, commitments the peer signs (and
	 * that we verify with buildLocalCommitment) legitimately EXCLUDE it.
	 *
	 * addRemoteCommitted (OFFERED entries we added): false from addHtlc until
	 * the peer's revoke_and_ack for our commitment_signed covering the add.
	 * While false, buildLocalCommitment omits the HTLC output and returns the
	 * provisionally-deducted amount to our balance.
	 *
	 * removalRemoteCommitted (FULFILLED/FAILED entries): false from OUR
	 * update_fulfill/fail (RECEIVED direction) or from receiving the peer's
	 * (OFFERED direction) until the peer's revoke_and_ack for our
	 * commitment_signed covering the removal. While false on a RECEIVED entry,
	 * buildLocalCommitment still includes the HTLC (the peer's signatures do).
	 * The removal's balance movement is finalized (and the entry deleted) only
	 * once it is no longer false.
	 *
	 * commitCoverPending: stamp set by signCommitment on every entry whose
	 * phase the in-flight commitment advances; the answering revoke_and_ack
	 * promotes the flags above and clears it.
	 *
	 * MIRROR SIDE — the PEER's updates that WE have not revoked for yet. We may
	 * only bake a peer update into commitments WE sign (buildRemoteCommitment)
	 * after we have revoked our own prior commitment in response to the peer's
	 * commitment_signed covering that update; the peer builds its own local
	 * commitment WITHOUT the update until it holds our revoke_and_ack, so
	 * signing it in early produces "Bad commit_sig" at the peer (observed live
	 * vs CLN when its update_fail interleaved with its revoke_and_ack).
	 *
	 * addLocallyRevoked (RECEIVED entries the peer added): false from
	 * handleUpdateAddHtlc until we revoke for the peer's covering
	 * commitment_signed. While false, buildRemoteCommitment omits the HTLC and
	 * returns the peer's provisionally-deducted amount.
	 *
	 * removalLocallyRevoked (OFFERED entries the peer fulfilled/failed): false
	 * from handleUpdateFulfill/FailHtlc until we revoke for the covering
	 * commitment_signed. While false, buildRemoteCommitment still includes the
	 * HTLC.
	 *
	 * All are optional: absent (legacy persisted states and hand-built
	 * fixtures) means "already committed/revoked" — the pre-two-phase behavior.
	 */
	addRemoteCommitted?: boolean;
	removalRemoteCommitted?: boolean;
	commitCoverPending?: boolean;
	addLocallyRevoked?: boolean;
	removalLocallyRevoked?: boolean;

	/**
	 * RECEIVED entries: set once handleRevokeAndAck has handed this HTLC to the
	 * node layer with an HTLC_FORWARDED action. The dispatch is edge-triggered
	 * (once per HTLC), not level-triggered: an entry stays COMMITTED for as long
	 * as the forward is in flight downstream, so without this marker every later
	 * revoke_and_ack on the channel re-dispatches it and the node layer offers a
	 * duplicate outgoing HTLC for one inbound payment.
	 *
	 * Persisted, because the node layer has no dedup of its own: an unpersisted
	 * marker would re-dispatch every in-flight HTLC on each restart and offer a
	 * duplicate outgoing one. The cost is that the marker reaches disk before the
	 * node layer has acted, so a restart in that window would strand the HTLC.
	 * LightningNode.redispatchUnresolvedReceivedHtlcs closes that window on
	 * startup by re-dispatching committed received HTLCs that have no durable
	 * resolution in flight.
	 *
	 * Optional: absent (legacy persisted states and hand-built fixtures) means
	 * "not yet dispatched", so an entry written before this field existed is
	 * dispatched by the next revoke_and_ack rather than being skipped forever.
	 */
	forwardEmitted?: boolean;
	/**
	 * Admission-time classification (issue 410): this received HTLC was dust
	 * and pushed total dust exposure past MAX_DUST_HTLC_EXPOSURE_MSAT when it
	 * was admitted, so the node fails it back once committed (BOLT 2: SHOULD
	 * fail such an HTLC once it's committed, SHOULD NOT reveal a preimage).
	 * Stamped at admission because the exposure total is order-dependent:
	 * within a synchronously dispatched batch, earlier entries settle before
	 * later ones are checked, so a dispatch-time recomputation would let the
	 * HTLC that crossed the ceiling slip under it. Persisted so a restart
	 * replay answers identically.
	 */
	dustExposureFailback?: boolean;
	/**
	 * Admission-time provenance (issue #469): this received HTLC entered the
	 * channel while its capsule-restore hold (restoreRecencyUnproven) was
	 * already standing, so the node fails it back once committed rather than
	 * settling it. Stamped at admission because that is the fact the policy
	 * turns on: an HTLC already committed in the capsule predates the hold,
	 * still settles off chain, and must not be mistaken for a new one when
	 * redispatchUnresolvedReceivedHtlcs replays it after a restart. Persisted
	 * so the refusal survives a crash between the commit and the fail-back.
	 */
	addedWhileRestoreUnproven?: boolean;
}

/**
 * Minimal record of one HTLC as it appeared in a specific (now potentially
 * revoked) remote commitment — enough to reconstruct its output witness script
 * for a penalty sweep after the live HTLC has been settled and forgotten.
 */
export interface IHtlcSnapshotEntry {
	paymentHash: Buffer;
	amountMsat: bigint;
	cltvExpiry: number;
	direction: HtlcDirection;
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

/** BOLT 2: maximum channel funding without wumbo. The spec bound is
 *  funding_satoshis < 2^24, so the largest VALID value is 2^24 - 1. */
export const MAX_FUNDING_SATOSHIS = 16777215n;

/** Funding ceiling when option_wumbo (large_channels, bit 18) is negotiated:
 *  10 BTC. Wumbo lifts the 2^24 cap, but an unbounded channel is a fat-finger
 *  and fund-concentration hazard, so a sane absolute ceiling remains. */
export const MAX_WUMBO_FUNDING_SATOSHIS = 1_000_000_000n;

/** Dust limit matching LND's DustLimitForSize(UnknownWitnessSize) = 354 sat.
 *  LND requires: 354 <= dustLimit <= 1062, and
 *  min(ourReserve, theirReserve) >= max(ourDust, theirDust).
 *  Using 354 ensures compatibility with LND's own 354 dust limit. */
export const MIN_DUST_LIMIT_SATOSHIS = 354n;

/** Upper bound on a peer-proposed dust limit, matching LND's own cap
 *  (354 <= dustLimit <= 1062). A dust limit above this is not a genuine
 *  "too-small-to-create" threshold: an unbounded value lets an acceptor trim
 *  our to_remote output out of every commitment we sign (see FS-1). */
export const MAX_DUST_LIMIT_SATOSHIS = 1062n;

/** Largest value encodable in a wire u64 field. */
export const U64_MAX = 0xffffffffffffffffn;

/** Default channel configuration */
export const DEFAULT_CHANNEL_CONFIG: IChannelConfig = {
	dustLimitSatoshis: 354n,
	// "No artificial limit" (CLN advertises the same U64 max). The value is
	// advertised as configured on every open/accept path, v1 and v2, and is
	// never clamped to capacity: the advertisement is immutable for the life
	// of the channel while capacity is not (splice), so clamping at open
	// would bake the initial capacity in as a permanent ceiling. Peers take
	// min(capacity, value) as the effective limit, balance/reserve rules
	// bound what can actually be in flight, and the gossip htlc_maximum_msat
	// is clamped to current capacity at channel_update build time. A fixed
	// default here (formerly 500k sat) capped the usable in-flight amount of
	// every larger channel: CLN and LDK compute effective capacity as
	// min(capacity, this value), so a wumbo channel was treated as a 500k-sat
	// one and peers with a min-capacity policy above it rejected our opens at
	// any funding size.
	maxHtlcValueInFlightMsat: U64_MAX,
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

/** Bitcoin signet chain hash (genesis hash, internal byte order) */
export const SIGNET_CHAIN_HASH = Buffer.from(
	'f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000',
	'hex'
);

/** Bitcoin testnet3 chain hash (genesis hash, internal byte order) */
export const TESTNET_CHAIN_HASH = Buffer.from(
	'43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000',
	'hex'
);
