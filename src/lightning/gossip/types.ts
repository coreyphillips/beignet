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

/** Serialized length of the lease-rates record (2+2+4+4+2). */
export const LEASE_RATES_LENGTH = 14;

/** Encode lease rates into the 14-byte option_will_fund record. */
export function encodeLeaseRates(rates: ILeaseRates): Buffer {
	const buf = Buffer.alloc(LEASE_RATES_LENGTH);
	buf.writeUInt16BE(rates.fundingWeightWitness, 0);
	buf.writeUInt16BE(rates.leaseFeeBasis, 2);
	buf.writeUInt32BE(rates.leaseFeeBaseSat, 4);
	buf.writeUInt32BE(rates.channelFeeMaxBaseMsat, 8);
	buf.writeUInt16BE(rates.channelFeeMaxProportionalThousandths, 12);
	return buf;
}

/** Decode the 14-byte option_will_fund lease-rates record. */
export function decodeLeaseRates(buf: Buffer): ILeaseRates {
	if (buf.length < LEASE_RATES_LENGTH) {
		throw new Error(
			`lease_rates too short: need ${LEASE_RATES_LENGTH} bytes, got ${buf.length}`
		);
	}
	return {
		fundingWeightWitness: buf.readUInt16BE(0),
		leaseFeeBasis: buf.readUInt16BE(2),
		leaseFeeBaseSat: buf.readUInt32BE(4),
		channelFeeMaxBaseMsat: buf.readUInt32BE(8),
		channelFeeMaxProportionalThousandths: buf.readUInt16BE(12)
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

export interface IGraphChannel {
	shortChannelId: Buffer;
	nodeId1: Buffer;
	nodeId2: Buffer;
	features: Buffer;
	announcement: IChannelAnnouncementMessage;
	update1?: IChannelUpdateMessage;
	update2?: IChannelUpdateMessage;
}

export interface IGraphNode {
	nodeId: Buffer;
	announcement?: INodeAnnouncementMessage;
	channels: Set<string>;
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
