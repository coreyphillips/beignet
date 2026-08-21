/**
 * BOLT 7: Gossip types, constants, and Short Channel ID utilities.
 */

// ── Interfaces ──────────────────────────────────────────────────────

export interface IShortChannelId {
	block: number;
	txIndex: number;
	outputIndex: number;
}

export interface INodeAddress {
	type: number;
	host: string;
	port: number;
}

export interface IChannelAnnouncementMessage {
	nodeSignature1: Buffer;
	nodeSignature2: Buffer;
	bitcoinSignature1: Buffer;
	bitcoinSignature2: Buffer;
	features: Buffer;
	chainHash: Buffer;
	shortChannelId: Buffer;
	nodeId1: Buffer;
	nodeId2: Buffer;
	bitcoinKey1: Buffer;
	bitcoinKey2: Buffer;
}

/**
 * Liquidity-ads lease rates (bLIP-0051 option_will_fund), advertised in a
 * node_announcement trailing TLV. Lets a buyer compute the lease fee a seller
 * charges to fund inbound liquidity, and bounds the routing fees the seller may
 * charge over the lease.
 */
export interface ILeaseRates {
	/** Seller's per-input funding weight, used to charge mining-fee share (u16). */
	fundingWeightWitness: number;
	/** Proportional lease fee in 1/10_000 of the leased amount (u16). */
	leaseFeeBasis: number;
	/** Flat lease fee in satoshis (u32). */
	leaseFeeBaseSat: number;
	/** Max routing base fee (msat) the seller may charge over the lease (u32). */
	channelFeeMaxBaseMsat: number;
	/** Max routing proportional fee in 1/1000 the seller may charge (u16). */
	channelFeeMaxProportionalThousandths: number;
}

export interface INodeAnnouncementMessage {
	signature: Buffer;
	features: Buffer;
	timestamp: number;
	nodeId: Buffer;
	rgbColor: Buffer;
	alias: Buffer;
	addresses: INodeAddress[];
	/** Liquidity-ads lease rates (node_ann_tlvs type 1, option_will_fund). */
	leaseRates?: ILeaseRates;
}

/** node_ann_tlvs TLV type for the option_will_fund lease-rates record. */
export const NODE_ANN_TLV_LEASE_RATES = 1n;

/**
 * Fixed prefix length of the lease-rates record. The full record is this
 * 10-byte prefix followed by channel_fee_max_base_msat as a tu32 (0-4 bytes),
 * so the total is variable. CLN/spec field order:
 *   funding_weight(u16) || lease_fee_basis(u16)
 *   || channel_fee_max_proportional_thousandths(u16) || lease_fee_base_sat(u32)
 *   || channel_fee_max_base_msat(tu32)
 */
export const LEASE_RATES_FIXED_LEN = 10;

/** Minimal big-endian encoding of a u32 (tu32): no leading zero bytes. */
function encodeTu32(val: number): Buffer {
	if (val === 0) return Buffer.alloc(0);
	const full = Buffer.alloc(4);
	full.writeUInt32BE(val >>> 0);
	let start = 0;
	while (start < 3 && full[start] === 0) start++;
	return full.subarray(start);
}

/** Decode a tu32 (rejects a non-minimal leading zero byte or >4 bytes). */
function decodeTu32(buf: Buffer): number {
	if (buf.length === 0) return 0;
	if (buf.length > 4) throw new Error('lease_rates tu32 exceeds 4 bytes');
	if (buf[0] === 0) throw new Error('lease_rates tu32 is not minimal');
	const padded = Buffer.alloc(4);
	buf.copy(padded, 4 - buf.length);
	return padded.readUInt32BE();
}

/** Encode lease rates into the option_will_fund record (spec/CLN byte order). */
export function encodeLeaseRates(rates: ILeaseRates): Buffer {
	const fixed = Buffer.alloc(LEASE_RATES_FIXED_LEN);
	fixed.writeUInt16BE(rates.fundingWeightWitness, 0);
	fixed.writeUInt16BE(rates.leaseFeeBasis, 2);
	fixed.writeUInt16BE(rates.channelFeeMaxProportionalThousandths, 4);
	fixed.writeUInt32BE(rates.leaseFeeBaseSat, 6);
	return Buffer.concat([fixed, encodeTu32(rates.channelFeeMaxBaseMsat)]);
}

/**
 * Decode an option_will_fund lease-rates record. `buf` must be exactly the
 * lease_rates bytes (the TLV value, or the will_fund tail after the signature),
 * since channel_fee_max_base_msat (tu32) consumes the remainder.
 */
export function decodeLeaseRates(buf: Buffer): ILeaseRates {
	if (buf.length < LEASE_RATES_FIXED_LEN) {
		throw new Error(
			`lease_rates too short: need >= ${LEASE_RATES_FIXED_LEN} bytes, got ${buf.length}`
		);
	}
	return {
		fundingWeightWitness: buf.readUInt16BE(0),
		leaseFeeBasis: buf.readUInt16BE(2),
		channelFeeMaxProportionalThousandths: buf.readUInt16BE(4),
		leaseFeeBaseSat: buf.readUInt32BE(6),
		channelFeeMaxBaseMsat: decodeTu32(buf.subarray(LEASE_RATES_FIXED_LEN))
	};
}

export interface IChannelUpdateMessage {
	signature: Buffer;
	chainHash: Buffer;
	shortChannelId: Buffer;
	timestamp: number;
	messageFlags: number;
	channelFlags: number;
	cltvExpiryDelta: number;
	htlcMinimumMsat: bigint;
	feeBaseMsat: number;
	feeProportionalMillionths: number;
	htlcMaximumMsat?: bigint;
}

export interface IAnnouncementSignaturesMessage {
	channelId: Buffer;
	shortChannelId: Buffer;
	nodeSignature: Buffer;
	bitcoinSignature: Buffer;
}

// ── Gossip Query Interfaces (BOLT 7 §4) ────────────────────────────

export interface IQueryChannelRangeMessage {
	chainHash: Buffer; // 32 bytes
	firstBlocknum: number; // uint32
	numberOfBlocks: number; // uint32
}

export interface IReplyChannelRangeMessage {
	chainHash: Buffer; // 32 bytes
	firstBlocknum: number; // uint32
	numberOfBlocks: number; // uint32
	syncComplete: boolean;
	encodedShortIds: Buffer; // encoding_type(1) + compressed/raw SCIDs
}

export interface IQueryShortChannelIdsMessage {
	chainHash: Buffer; // 32 bytes
	encodedShortIds: Buffer; // encoding_type(1) + compressed/raw SCIDs
}

export interface IReplyShortChannelIdsEndMessage {
	chainHash: Buffer; // 32 bytes
	complete: boolean;
}

export interface IGossipTimestampFilterMessage {
	chainHash: Buffer; // 32 bytes
	firstTimestamp: number; // uint32
	timestampRange: number; // uint32
}

/**
 * Provenance a caller can claim for a gossip message applied to the graph.
 * `true` = signature-verified AND the codec reproduces the signed bytes, so
 * the entry may be served to gossip queries. `'deferred'` = carries
 * signatures that have not been checked yet; verification is postponed until
 * a consumer needs the trust (a gossip query, a dial-address read), per
 * issue #443. Anything else stores as explicit false: never served, never
 * re-checked. This is an input type; stored entries keep boolean flags plus
 * separate *VerifyDeferred markers (see IGraphChannel).
 */
export type TGossipVerified = boolean | 'deferred';

export interface IGraphChannel {
	shortChannelId: Buffer;
	nodeId1: Buffer;
	nodeId2: Buffer;
	features: Buffer;
	announcement: IChannelAnnouncementMessage;
	update1?: IChannelUpdateMessage;
	update2?: IChannelUpdateMessage;
	// BOLT 7: a node MUST NOT relay announcements it has not validated. These
	// booleans record signature-verified (servable) provenance per stored
	// message; only entries whose flag is exactly true are included in
	// reply_channel_range data / query_short_channel_ids responses. All
	// states stay routable locally. Absent (undefined) means a legacy row
	// from before provenance tracking (resolved at the restore boundary), or
	// a deferred entry when the matching marker below is set.
	announcementVerified?: boolean;
	update1Verified?: boolean;
	update2Verified?: boolean;
	// Deferred-verification markers (issue #443): the message carries
	// signatures that have not been checked yet. While a marker is true the
	// matching *Verified flag stays undefined, so both truthiness checks and
	// the === true serve filters treat the entry as unverified; resolution
	// settles the boolean and clears the marker. Kept separate from the
	// booleans so downstream `if (x.announcementVerified)` code never sees a
	// truthy unverified value.
	announcementVerifyDeferred?: boolean;
	update1VerifyDeferred?: boolean;
	update2VerifyDeferred?: boolean;
}

export interface IGraphNode {
	nodeId: Buffer;
	announcement?: INodeAnnouncementMessage;
	channels: Set<string>;
	// Same provenance rule as IGraphChannel: unverified node_announcements are
	// never served to gossip queries.
	announcementVerified?: boolean;
	announcementVerifyDeferred?: boolean;
}

export interface IRouteHop {
	pubkey: Buffer;
	shortChannelId: Buffer;
	amountToForwardMsat: bigint;
	outgoingCltvValue: number;
	feeBaseMsat: number;
	feeProportionalMillionths: number;
	cltvExpiryDelta: number;
	/**
	 * Route blinding (BOLT 4): encrypted_recipient_data destined for THIS hop
	 * (onion TLV 10). Present on the introduction node and every blinded hop.
	 */
	encryptedRecipientData?: Buffer;
	/**
	 * Route blinding (BOLT 4): blinding_point (onion TLV 12). Present only on the
	 * introduction node — downstream blinded hops derive their own.
	 */
	blindingPoint?: Buffer;
}

export interface IRoute {
	hops: IRouteHop[];
	totalAmountMsat: bigint;
	totalCltvDelta: number;
	totalFeeMsat: bigint;
}

// ── Constants ───────────────────────────────────────────────────────

export const ADDRESS_TYPE_IPV4 = 1;
export const ADDRESS_TYPE_IPV6 = 2;
export const ADDRESS_TYPE_TORV2 = 3;
export const ADDRESS_TYPE_TORV3 = 4;
export const ADDRESS_TYPE_DNS = 5;

export const CHANNEL_FLAG_DIRECTION = 0x01;
export const CHANNEL_FLAG_DISABLED = 0x02;

export const MESSAGE_FLAG_HTLC_MAX = 0x01;

export const ANNOUNCEMENT_SIGNATURES_LENGTH = 168;

/** BOLT 7: Maximum age for channel updates before pruning (2 weeks). */
export const DEFAULT_PRUNE_MAX_AGE = 1_209_600;

/**
 * BOLT 7: ignore gossip timestamped unreasonably far in the future. One hour
 * of forward skew is generous (gossip propagates in seconds; RGS snapshots
 * are stamped in the past) while capping how long a garbage timestamp can
 * camp a slot against the strictly-newer freshness rule: without a bound, a
 * max-u32 timestamp holds its slot until 2106 (issue #446).
 */
export const MAX_GOSSIP_TIMESTAMP_SKEW = 3_600;

// ── Short Channel ID ────────────────────────────────────────────────

/**
 * Encode an IShortChannelId into an 8-byte Buffer.
 * Layout: block(24b) | txIndex(24b) | outputIndex(16b)
 */
export function encodeShortChannelId(scid: IShortChannelId): Buffer {
	if (scid.block < 0 || scid.block > 0xffffff) {
		throw new Error(`Block out of range: ${scid.block}`);
	}
	if (scid.txIndex < 0 || scid.txIndex > 0xffffff) {
		throw new Error(`txIndex out of range: ${scid.txIndex}`);
	}
	if (scid.outputIndex < 0 || scid.outputIndex > 0xffff) {
		throw new Error(`outputIndex out of range: ${scid.outputIndex}`);
	}
	const val =
		(BigInt(scid.block) << 40n) |
		(BigInt(scid.txIndex) << 16n) |
		BigInt(scid.outputIndex);
	const buf = Buffer.alloc(8);
	buf.writeBigUInt64BE(val);
	return buf;
}

/**
 * Decode an 8-byte Buffer into an IShortChannelId.
 */
export function decodeShortChannelId(buf: Buffer): IShortChannelId {
	if (buf.length !== 8) {
		throw new Error(`Short channel ID must be 8 bytes, got ${buf.length}`);
	}
	const val = buf.readBigUInt64BE();
	return {
		block: Number((val >> 40n) & 0xffffffn),
		txIndex: Number((val >> 16n) & 0xffffffn),
		outputIndex: Number(val & 0xffffn)
	};
}

/**
 * Convert an 8-byte SCID buffer to "block:txIndex:outputIndex" string.
 */
export function shortChannelIdToString(buf: Buffer): string {
	const scid = decodeShortChannelId(buf);
	return `${scid.block}:${scid.txIndex}:${scid.outputIndex}`;
}

/**
 * Parse a "block:txIndex:outputIndex" string into an 8-byte Buffer.
 */
export function stringToShortChannelId(str: string): Buffer {
	const parts = str.split(':');
	if (parts.length !== 3) {
		throw new Error(`Invalid SCID string format: "${str}"`);
	}
	const block = parseInt(parts[0], 10);
	const txIndex = parseInt(parts[1], 10);
	const outputIndex = parseInt(parts[2], 10);
	if (isNaN(block) || isNaN(txIndex) || isNaN(outputIndex)) {
		throw new Error(`Invalid SCID string: "${str}"`);
	}
	return encodeShortChannelId({ block, txIndex, outputIndex });
}
