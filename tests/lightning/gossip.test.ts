/**
 * BOLT 7: Gossip & Routing — Tests
 *
 * Tests for SCID utilities, gossip message encode/decode, signature validation,
 * network graph, pathfinding, and barrel exports.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	// Types & constants
	IShortChannelId,
	INodeAddress,
	IChannelAnnouncementMessage,
	INodeAnnouncementMessage,
	IChannelUpdateMessage,
	IAnnouncementSignaturesMessage,
	ADDRESS_TYPE_IPV4,
	ADDRESS_TYPE_IPV6,
	ADDRESS_TYPE_TORV3,
	CHANNEL_FLAG_DIRECTION,
	CHANNEL_FLAG_DISABLED,
	MESSAGE_FLAG_HTLC_MAX,
	ANNOUNCEMENT_SIGNATURES_LENGTH,
	DEFAULT_PRUNE_MAX_AGE,
	// SCID utilities
	encodeShortChannelId,
	decodeShortChannelId,
	shortChannelIdToString,
	stringToShortChannelId,
	// Messages
	encodeChannelAnnouncementMessage,
	decodeChannelAnnouncementMessage,
	encodeNodeAnnouncementMessage,
	decodeNodeAnnouncementMessage,
	encodeChannelUpdateMessage,
	decodeChannelUpdateMessage,
	encodeAnnouncementSignaturesMessage,
	decodeAnnouncementSignaturesMessage,
	encodeNodeAddress,
	decodeNodeAddress,
	// Validation
	computeGossipSignatureHash,
	getChannelAnnouncementSignedData,
	getNodeAnnouncementSignedData,
	getChannelUpdateSignedData,
	verifyChannelAnnouncement,
	verifyNodeAnnouncement,
	verifyChannelUpdate,
	signChannelAnnouncement,
	signNodeAnnouncement,
	signChannelUpdate,
	// Network Graph
	NetworkGraph,
	// Pathfinding
	calculateFee,
	findRoute
} from '../../src/lightning/gossip';
import { getPublicKey, sign } from '../../src/lightning/crypto/ecdh';
import { BITCOIN_CHAIN_HASH } from '../../src/lightning/channel/types';

// ── Helpers ─────────────────────────────────────────────────────────

/** Generate a random private/public keypair, ensuring lexicographic ordering can be controlled. */
function makeKeypair(): { privateKey: Buffer; publicKey: Buffer } {
	let privKey: Buffer;
	do {
		privKey = crypto.randomBytes(32);
	} while (privKey[0] === 0);
	return { privateKey: privKey, publicKey: getPublicKey(privKey) };
}

/** Create two keypairs with pubkey1 < pubkey2 lexicographically. */
function makeOrderedKeypairs(): {
	key1: { privateKey: Buffer; publicKey: Buffer };
	key2: { privateKey: Buffer; publicKey: Buffer };
} {
	const a = makeKeypair();
	const b = makeKeypair();
	if (Buffer.compare(a.publicKey, b.publicKey) < 0) {
		return { key1: a, key2: b };
	}
	return { key1: b, key2: a };
}

/** Create a dummy SCID buffer. */
function makeScid(block: number, txIndex: number, outputIndex: number): Buffer {
	return encodeShortChannelId({ block, txIndex, outputIndex });
}

/** Build a minimal valid channel_announcement. */
function buildChannelAnnouncement(
	nodeKey1: { privateKey: Buffer; publicKey: Buffer },
	nodeKey2: { privateKey: Buffer; publicKey: Buffer },
	bitcoinKey1: { privateKey: Buffer; publicKey: Buffer },
	bitcoinKey2: { privateKey: Buffer; publicKey: Buffer },
	scid: Buffer,
	features: Buffer = Buffer.alloc(0)
): { msg: IChannelAnnouncementMessage; payload: Buffer } {
	// Create a placeholder message with zero sigs first
	const placeholder: IChannelAnnouncementMessage = {
		nodeSignature1: Buffer.alloc(64),
		nodeSignature2: Buffer.alloc(64),
		bitcoinSignature1: Buffer.alloc(64),
		bitcoinSignature2: Buffer.alloc(64),
		features,
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		nodeId1: nodeKey1.publicKey,
		nodeId2: nodeKey2.publicKey,
		bitcoinKey1: bitcoinKey1.publicKey,
		bitcoinKey2: bitcoinKey2.publicKey
	};
	const placeholderPayload = encodeChannelAnnouncementMessage(placeholder);

	// Sign it
	const sig1 = signChannelAnnouncement(
		placeholderPayload,
		nodeKey1.privateKey,
		bitcoinKey1.privateKey
	);
	const sig2 = signChannelAnnouncement(
		placeholderPayload,
		nodeKey2.privateKey,
		bitcoinKey2.privateKey
	);

	const msg: IChannelAnnouncementMessage = {
		...placeholder,
		nodeSignature1: sig1.nodeSignature,
		nodeSignature2: sig2.nodeSignature,
		bitcoinSignature1: sig1.bitcoinSignature,
		bitcoinSignature2: sig2.bitcoinSignature
	};

	const payload = encodeChannelAnnouncementMessage(msg);
	return { msg, payload };
}

/** Build a channel_update message. */
function buildChannelUpdate(
	nodePrivkey: Buffer,
	scid: Buffer,
	timestamp: number,
	direction: number,
	opts: {
		disabled?: boolean;
		cltvExpiryDelta?: number;
		htlcMinimumMsat?: bigint;
		feeBaseMsat?: number;
		feeProportionalMillionths?: number;
		htlcMaximumMsat?: bigint;
	} = {}
): { msg: IChannelUpdateMessage; payload: Buffer } {
	const channelFlags =
		(direction & CHANNEL_FLAG_DIRECTION) |
		(opts.disabled ? CHANNEL_FLAG_DISABLED : 0);
	const hasMax = opts.htlcMaximumMsat !== undefined;
	const messageFlags = hasMax ? MESSAGE_FLAG_HTLC_MAX : 0;

	const placeholder: IChannelUpdateMessage = {
		signature: Buffer.alloc(64),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		timestamp,
		messageFlags,
		channelFlags,
		cltvExpiryDelta: opts.cltvExpiryDelta ?? 40,
		htlcMinimumMsat: opts.htlcMinimumMsat ?? 1000n,
		feeBaseMsat: opts.feeBaseMsat ?? 1000,
		feeProportionalMillionths: opts.feeProportionalMillionths ?? 1,
		htlcMaximumMsat: opts.htlcMaximumMsat
	};

	const placeholderPayload = encodeChannelUpdateMessage(placeholder);
	const sig = signChannelUpdate(placeholderPayload, nodePrivkey);

	const msg: IChannelUpdateMessage = { ...placeholder, signature: sig };
	const payload = encodeChannelUpdateMessage(msg);
	return { msg, payload };
}

/** Build a node_announcement message. */
function buildNodeAnnouncement(
	nodePrivkey: Buffer,
	timestamp: number,
	alias = 'test-node',
	addresses: INodeAddress[] = []
): { msg: INodeAnnouncementMessage; payload: Buffer } {
	const aliasBuf = Buffer.alloc(32);
	Buffer.from(alias, 'utf8').copy(aliasBuf);

	const placeholder: INodeAnnouncementMessage = {
		signature: Buffer.alloc(64),
		features: Buffer.alloc(0),
		timestamp,
		nodeId: getPublicKey(nodePrivkey),
		rgbColor: Buffer.from([255, 128, 0]),
		alias: aliasBuf,
		addresses
	};

	const placeholderPayload = encodeNodeAnnouncementMessage(placeholder);
	const sig = signNodeAnnouncement(placeholderPayload, nodePrivkey);

	const msg: INodeAnnouncementMessage = { ...placeholder, signature: sig };
	const payload = encodeNodeAnnouncementMessage(msg);
	return { msg, payload };
}

// ═══════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════

describe('BOLT 7: Gossip & Routing', () => {
	// ── Short Channel ID ────────────────────────────────────────────

	describe('Short Channel ID', () => {
		it('should encode and decode a normal SCID', () => {
			const scid: IShortChannelId = {
				block: 700000,
				txIndex: 42,
				outputIndex: 1
			};
			const encoded = encodeShortChannelId(scid);
			expect(encoded.length).to.equal(8);
			const decoded = decodeShortChannelId(encoded);
			expect(decoded).to.deep.equal(scid);
		});

		it('should encode and decode minimum values (all zeros)', () => {
			const scid: IShortChannelId = { block: 0, txIndex: 0, outputIndex: 0 };
			const encoded = encodeShortChannelId(scid);
			expect(encoded).to.deep.equal(Buffer.alloc(8));
			expect(decodeShortChannelId(encoded)).to.deep.equal(scid);
		});

		it('should encode and decode maximum values', () => {
			const scid: IShortChannelId = {
				block: 0xffffff,
				txIndex: 0xffffff,
				outputIndex: 0xffff
			};
			const encoded = encodeShortChannelId(scid);
			const decoded = decodeShortChannelId(encoded);
			expect(decoded).to.deep.equal(scid);
		});

		it('should reject block number out of range', () => {
			expect(() =>
				encodeShortChannelId({ block: 0x1000000, txIndex: 0, outputIndex: 0 })
			).to.throw('Block out of range');
		});

		it('should reject txIndex out of range', () => {
			expect(() =>
				encodeShortChannelId({ block: 0, txIndex: 0x1000000, outputIndex: 0 })
			).to.throw('txIndex out of range');
		});

		it('should reject outputIndex out of range', () => {
			expect(() =>
				encodeShortChannelId({ block: 0, txIndex: 0, outputIndex: 0x10000 })
			).to.throw('outputIndex out of range');
		});

		it('should reject wrong buffer length for decode', () => {
			expect(() => decodeShortChannelId(Buffer.alloc(7))).to.throw(
				'must be 8 bytes'
			);
			expect(() => decodeShortChannelId(Buffer.alloc(9))).to.throw(
				'must be 8 bytes'
			);
		});

		it('should convert to string format', () => {
			const scid: IShortChannelId = {
				block: 700000,
				txIndex: 42,
				outputIndex: 1
			};
			const encoded = encodeShortChannelId(scid);
			expect(shortChannelIdToString(encoded)).to.equal('700000:42:1');
		});

		it('should parse from string format', () => {
			const buf = stringToShortChannelId('700000:42:1');
			const decoded = decodeShortChannelId(buf);
			expect(decoded).to.deep.equal({
				block: 700000,
				txIndex: 42,
				outputIndex: 1
			});
		});

		it('should round-trip string format', () => {
			const str = '123456:789:5';
			expect(shortChannelIdToString(stringToShortChannelId(str))).to.equal(str);
		});

		it('should reject malformed string format', () => {
			expect(() => stringToShortChannelId('123:456')).to.throw(
				'Invalid SCID string format'
			);
			expect(() => stringToShortChannelId('a:b:c')).to.throw(
				'Invalid SCID string'
			);
		});

		it('should reject negative values', () => {
			expect(() =>
				encodeShortChannelId({ block: -1, txIndex: 0, outputIndex: 0 })
			).to.throw('Block out of range');
		});
	});

	// ── Channel Announcement Messages ───────────────────────────────

	describe('channel_announcement encode/decode', () => {
		it('should round-trip with zero-length features', () => {
			const msg: IChannelAnnouncementMessage = {
				nodeSignature1: crypto.randomBytes(64),
				nodeSignature2: crypto.randomBytes(64),
				bitcoinSignature1: crypto.randomBytes(64),
				bitcoinSignature2: crypto.randomBytes(64),
				features: Buffer.alloc(0),
				chainHash: BITCOIN_CHAIN_HASH,
				shortChannelId: makeScid(700000, 1, 0),
				nodeId1: crypto.randomBytes(33),
				nodeId2: crypto.randomBytes(33),
				bitcoinKey1: crypto.randomBytes(33),
				bitcoinKey2: crypto.randomBytes(33)
			};
			const payload = encodeChannelAnnouncementMessage(msg);
			const decoded = decodeChannelAnnouncementMessage(payload);

			expect(decoded.nodeSignature1).to.deep.equal(msg.nodeSignature1);
			expect(decoded.nodeSignature2).to.deep.equal(msg.nodeSignature2);
			expect(decoded.bitcoinSignature1).to.deep.equal(msg.bitcoinSignature1);
			expect(decoded.bitcoinSignature2).to.deep.equal(msg.bitcoinSignature2);
			expect(decoded.features).to.deep.equal(msg.features);
			expect(decoded.chainHash).to.deep.equal(msg.chainHash);
			expect(decoded.shortChannelId).to.deep.equal(msg.shortChannelId);
			expect(decoded.nodeId1).to.deep.equal(msg.nodeId1);
			expect(decoded.nodeId2).to.deep.equal(msg.nodeId2);
			expect(decoded.bitcoinKey1).to.deep.equal(msg.bitcoinKey1);
			expect(decoded.bitcoinKey2).to.deep.equal(msg.bitcoinKey2);
		});

		it('should round-trip with non-empty features', () => {
			const features = Buffer.from([0x01, 0x02, 0x03]);
			const msg: IChannelAnnouncementMessage = {
				nodeSignature1: crypto.randomBytes(64),
				nodeSignature2: crypto.randomBytes(64),
				bitcoinSignature1: crypto.randomBytes(64),
				bitcoinSignature2: crypto.randomBytes(64),
				features,
				chainHash: BITCOIN_CHAIN_HASH,
				shortChannelId: makeScid(1, 2, 3),
				nodeId1: crypto.randomBytes(33),
				nodeId2: crypto.randomBytes(33),
				bitcoinKey1: crypto.randomBytes(33),
				bitcoinKey2: crypto.randomBytes(33)
			};
			const payload = encodeChannelAnnouncementMessage(msg);
			expect(payload.length).to.equal(430 + 3); // min + feature length
			const decoded = decodeChannelAnnouncementMessage(payload);
			expect(decoded.features).to.deep.equal(features);
		});

		it('should have minimum payload size of 430 bytes', () => {
			const msg: IChannelAnnouncementMessage = {
				nodeSignature1: Buffer.alloc(64),
				nodeSignature2: Buffer.alloc(64),
				bitcoinSignature1: Buffer.alloc(64),
				bitcoinSignature2: Buffer.alloc(64),
				features: Buffer.alloc(0),
				chainHash: Buffer.alloc(32),
				shortChannelId: Buffer.alloc(8),
				nodeId1: Buffer.alloc(33),
				nodeId2: Buffer.alloc(33),
				bitcoinKey1: Buffer.alloc(33),
				bitcoinKey2: Buffer.alloc(33)
			};
			const payload = encodeChannelAnnouncementMessage(msg);
			expect(payload.length).to.equal(430);
		});

		it('should reject payload too short', () => {
			expect(() =>
				decodeChannelAnnouncementMessage(Buffer.alloc(429))
			).to.throw('too short');
		});

		it('should preserve all 4 signatures independently', () => {
			const sigs = [
				crypto.randomBytes(64),
				crypto.randomBytes(64),
				crypto.randomBytes(64),
				crypto.randomBytes(64)
			];
			const msg: IChannelAnnouncementMessage = {
				nodeSignature1: sigs[0],
				nodeSignature2: sigs[1],
				bitcoinSignature1: sigs[2],
				bitcoinSignature2: sigs[3],
				features: Buffer.alloc(0),
				chainHash: Buffer.alloc(32),
				shortChannelId: Buffer.alloc(8),
				nodeId1: Buffer.alloc(33),
				nodeId2: Buffer.alloc(33),
				bitcoinKey1: Buffer.alloc(33),
				bitcoinKey2: Buffer.alloc(33)
			};
			const decoded = decodeChannelAnnouncementMessage(
				encodeChannelAnnouncementMessage(msg)
			);
			expect(decoded.nodeSignature1).to.deep.equal(sigs[0]);
			expect(decoded.nodeSignature2).to.deep.equal(sigs[1]);
			expect(decoded.bitcoinSignature1).to.deep.equal(sigs[2]);
			expect(decoded.bitcoinSignature2).to.deep.equal(sigs[3]);
		});

		it('should preserve all 4 pubkeys independently', () => {
			const keys = Array.from({ length: 4 }, () => crypto.randomBytes(33));
			const msg: IChannelAnnouncementMessage = {
				nodeSignature1: Buffer.alloc(64),
				nodeSignature2: Buffer.alloc(64),
				bitcoinSignature1: Buffer.alloc(64),
				bitcoinSignature2: Buffer.alloc(64),
				features: Buffer.alloc(0),
				chainHash: Buffer.alloc(32),
				shortChannelId: Buffer.alloc(8),
				nodeId1: keys[0],
				nodeId2: keys[1],
				bitcoinKey1: keys[2],
				bitcoinKey2: keys[3]
			};
			const decoded = decodeChannelAnnouncementMessage(
				encodeChannelAnnouncementMessage(msg)
			);
			expect(decoded.nodeId1).to.deep.equal(keys[0]);
			expect(decoded.nodeId2).to.deep.equal(keys[1]);
			expect(decoded.bitcoinKey1).to.deep.equal(keys[2]);
			expect(decoded.bitcoinKey2).to.deep.equal(keys[3]);
		});

		it('should preserve chain hash and SCID', () => {
			const chainHash = crypto.randomBytes(32);
			const scid = makeScid(800000, 100, 2);
			const msg: IChannelAnnouncementMessage = {
				nodeSignature1: Buffer.alloc(64),
				nodeSignature2: Buffer.alloc(64),
				bitcoinSignature1: Buffer.alloc(64),
				bitcoinSignature2: Buffer.alloc(64),
				features: Buffer.alloc(0),
				chainHash,
				shortChannelId: scid,
				nodeId1: Buffer.alloc(33),
				nodeId2: Buffer.alloc(33),
				bitcoinKey1: Buffer.alloc(33),
				bitcoinKey2: Buffer.alloc(33)
			};
			const decoded = decodeChannelAnnouncementMessage(
				encodeChannelAnnouncementMessage(msg)
			);
			expect(decoded.chainHash).to.deep.equal(chainHash);
			expect(decoded.shortChannelId).to.deep.equal(scid);
		});

		it('should handle large feature vectors', () => {
			const features = crypto.randomBytes(100);
			const msg: IChannelAnnouncementMessage = {
				nodeSignature1: Buffer.alloc(64),
				nodeSignature2: Buffer.alloc(64),
				bitcoinSignature1: Buffer.alloc(64),
				bitcoinSignature2: Buffer.alloc(64),
				features,
				chainHash: Buffer.alloc(32),
				shortChannelId: Buffer.alloc(8),
				nodeId1: Buffer.alloc(33),
				nodeId2: Buffer.alloc(33),
				bitcoinKey1: Buffer.alloc(33),
				bitcoinKey2: Buffer.alloc(33)
			};
			const decoded = decodeChannelAnnouncementMessage(
				encodeChannelAnnouncementMessage(msg)
			);
			expect(decoded.features).to.deep.equal(features);
		});
	});

	// ── Node Announcement Messages ──────────────────────────────────

	describe('node_announcement encode/decode', () => {
		it('should round-trip with no addresses', () => {
			const alias = Buffer.alloc(32);
			Buffer.from('my-node', 'utf8').copy(alias);
			const msg: INodeAnnouncementMessage = {
				signature: crypto.randomBytes(64),
				features: Buffer.alloc(0),
				timestamp: 1700000000,
				nodeId: crypto.randomBytes(33),
				rgbColor: Buffer.from([255, 128, 0]),
				alias,
				addresses: []
			};
			const payload = encodeNodeAnnouncementMessage(msg);
			const decoded = decodeNodeAnnouncementMessage(payload);

			expect(decoded.signature).to.deep.equal(msg.signature);
			expect(decoded.timestamp).to.equal(msg.timestamp);
			expect(decoded.nodeId).to.deep.equal(msg.nodeId);
			expect(decoded.rgbColor).to.deep.equal(msg.rgbColor);
			expect(decoded.alias).to.deep.equal(msg.alias);
			expect(decoded.addresses).to.deep.equal([]);
		});

		it('should round-trip with IPv4 address', () => {
			const alias = Buffer.alloc(32);
			const msg: INodeAnnouncementMessage = {
				signature: Buffer.alloc(64),
				features: Buffer.alloc(0),
				timestamp: 1700000000,
				nodeId: Buffer.alloc(33),
				rgbColor: Buffer.from([0, 0, 0]),
				alias,
				addresses: [
					{ type: ADDRESS_TYPE_IPV4, host: '192.168.1.1', port: 9735 }
				]
			};
			const decoded = decodeNodeAnnouncementMessage(
				encodeNodeAnnouncementMessage(msg)
			);
			expect(decoded.addresses).to.have.length(1);
			expect(decoded.addresses[0].type).to.equal(ADDRESS_TYPE_IPV4);
			expect(decoded.addresses[0].host).to.equal('192.168.1.1');
			expect(decoded.addresses[0].port).to.equal(9735);
		});

		it('should round-trip with IPv6 address', () => {
			const alias = Buffer.alloc(32);
			const msg: INodeAnnouncementMessage = {
				signature: Buffer.alloc(64),
				features: Buffer.alloc(0),
				timestamp: 1700000000,
				nodeId: Buffer.alloc(33),
				rgbColor: Buffer.from([0, 0, 0]),
				alias,
				addresses: [
					{
						type: ADDRESS_TYPE_IPV6,
						host: '2001:0db8:0000:0000:0000:0000:0000:0001',
						port: 9735
					}
				]
			};
			const decoded = decodeNodeAnnouncementMessage(
				encodeNodeAnnouncementMessage(msg)
			);
			expect(decoded.addresses).to.have.length(1);
			expect(decoded.addresses[0].type).to.equal(ADDRESS_TYPE_IPV6);
			expect(decoded.addresses[0].host).to.equal(
				'2001:0db8:0000:0000:0000:0000:0000:0001'
			);
			expect(decoded.addresses[0].port).to.equal(9735);
		});

		it('should round-trip with multiple addresses', () => {
			const alias = Buffer.alloc(32);
			const msg: INodeAnnouncementMessage = {
				signature: Buffer.alloc(64),
				features: Buffer.alloc(0),
				timestamp: 1700000000,
				nodeId: Buffer.alloc(33),
				rgbColor: Buffer.from([0, 0, 0]),
				alias,
				addresses: [
					{ type: ADDRESS_TYPE_IPV4, host: '10.0.0.1', port: 9735 },
					{ type: ADDRESS_TYPE_IPV4, host: '10.0.0.2', port: 9736 }
				]
			};
			const decoded = decodeNodeAnnouncementMessage(
				encodeNodeAnnouncementMessage(msg)
			);
			expect(decoded.addresses).to.have.length(2);
			expect(decoded.addresses[0].host).to.equal('10.0.0.1');
			expect(decoded.addresses[1].host).to.equal('10.0.0.2');
		});

		it('should preserve alias padding', () => {
			const alias = Buffer.alloc(32);
			Buffer.from('short', 'utf8').copy(alias);
			const msg: INodeAnnouncementMessage = {
				signature: Buffer.alloc(64),
				features: Buffer.alloc(0),
				timestamp: 1,
				nodeId: Buffer.alloc(33),
				rgbColor: Buffer.from([0, 0, 0]),
				alias,
				addresses: []
			};
			const decoded = decodeNodeAnnouncementMessage(
				encodeNodeAnnouncementMessage(msg)
			);
			expect(decoded.alias.length).to.equal(32);
			expect(decoded.alias.subarray(0, 5).toString('utf8')).to.equal('short');
			expect(decoded.alias.subarray(5)).to.deep.equal(Buffer.alloc(27));
		});

		it('should preserve RGB color', () => {
			const alias = Buffer.alloc(32);
			const msg: INodeAnnouncementMessage = {
				signature: Buffer.alloc(64),
				features: Buffer.alloc(0),
				timestamp: 1,
				nodeId: Buffer.alloc(33),
				rgbColor: Buffer.from([0xab, 0xcd, 0xef]),
				alias,
				addresses: []
			};
			const decoded = decodeNodeAnnouncementMessage(
				encodeNodeAnnouncementMessage(msg)
			);
			expect(decoded.rgbColor).to.deep.equal(Buffer.from([0xab, 0xcd, 0xef]));
		});

		it('should have minimum payload of 140 bytes', () => {
			const msg: INodeAnnouncementMessage = {
				signature: Buffer.alloc(64),
				features: Buffer.alloc(0),
				timestamp: 0,
				nodeId: Buffer.alloc(33),
				rgbColor: Buffer.alloc(3),
				alias: Buffer.alloc(32),
				addresses: []
			};
			const payload = encodeNodeAnnouncementMessage(msg);
			expect(payload.length).to.equal(140);
		});

		it('should reject payload too short', () => {
			expect(() => decodeNodeAnnouncementMessage(Buffer.alloc(139))).to.throw(
				'too short'
			);
		});

		it('should reject a zero timestamp (gossip DoS guard)', () => {
			const msg: INodeAnnouncementMessage = {
				signature: Buffer.alloc(64),
				features: Buffer.alloc(0),
				timestamp: 1,
				nodeId: Buffer.alloc(33),
				rgbColor: Buffer.alloc(3),
				alias: Buffer.alloc(32),
				addresses: []
			};
			const payload = encodeNodeAnnouncementMessage(msg);
			// Zero out the 4-byte timestamp (offset 64 sig + 2 flen + 0 features).
			payload.writeUInt32BE(0, 66);
			expect(() => decodeNodeAnnouncementMessage(payload)).to.throw(
				'greater than zero'
			);
		});

		it('should round-trip with features', () => {
			const features = Buffer.from([0x01, 0x02]);
			const msg: INodeAnnouncementMessage = {
				signature: Buffer.alloc(64),
				features,
				timestamp: 1000,
				nodeId: Buffer.alloc(33),
				rgbColor: Buffer.alloc(3),
				alias: Buffer.alloc(32),
				addresses: []
			};
			const decoded = decodeNodeAnnouncementMessage(
				encodeNodeAnnouncementMessage(msg)
			);
			expect(decoded.features).to.deep.equal(features);
		});
	});

	// ── Channel Update Messages ─────────────────────────────────────

	describe('channel_update encode/decode', () => {
		it('should round-trip without htlc_maximum_msat', () => {
			const msg: IChannelUpdateMessage = {
				signature: crypto.randomBytes(64),
				chainHash: BITCOIN_CHAIN_HASH,
				shortChannelId: makeScid(700000, 1, 0),
				timestamp: 1700000000,
				messageFlags: 0,
				channelFlags: 0,
				cltvExpiryDelta: 40,
				htlcMinimumMsat: 1000n,
				feeBaseMsat: 1000,
				feeProportionalMillionths: 1
			};
			const payload = encodeChannelUpdateMessage(msg);
			expect(payload.length).to.equal(128);
			const decoded = decodeChannelUpdateMessage(payload);

			expect(decoded.signature).to.deep.equal(msg.signature);
			expect(decoded.chainHash).to.deep.equal(msg.chainHash);
			expect(decoded.shortChannelId).to.deep.equal(msg.shortChannelId);
			expect(decoded.timestamp).to.equal(msg.timestamp);
			expect(decoded.messageFlags).to.equal(0);
			expect(decoded.channelFlags).to.equal(0);
			expect(decoded.cltvExpiryDelta).to.equal(40);
			expect(decoded.htlcMinimumMsat).to.equal(1000n);
			expect(decoded.feeBaseMsat).to.equal(1000);
			expect(decoded.feeProportionalMillionths).to.equal(1);
			expect(decoded.htlcMaximumMsat).to.be.undefined;
		});

		it('should round-trip with htlc_maximum_msat', () => {
			const msg: IChannelUpdateMessage = {
				signature: crypto.randomBytes(64),
				chainHash: BITCOIN_CHAIN_HASH,
				shortChannelId: makeScid(700000, 1, 0),
				timestamp: 1700000000,
				messageFlags: MESSAGE_FLAG_HTLC_MAX,
				channelFlags: 0,
				cltvExpiryDelta: 144,
				htlcMinimumMsat: 1000n,
				feeBaseMsat: 500,
				feeProportionalMillionths: 100,
				htlcMaximumMsat: 1_000_000_000n
			};
			const payload = encodeChannelUpdateMessage(msg);
			expect(payload.length).to.equal(136);
			const decoded = decodeChannelUpdateMessage(payload);

			expect(decoded.htlcMaximumMsat).to.equal(1_000_000_000n);
			expect(decoded.messageFlags).to.equal(MESSAGE_FLAG_HTLC_MAX);
		});

		it('should preserve direction bit in channelFlags', () => {
			const msg: IChannelUpdateMessage = {
				signature: Buffer.alloc(64),
				chainHash: Buffer.alloc(32),
				shortChannelId: Buffer.alloc(8),
				timestamp: 1,
				messageFlags: 0,
				channelFlags: CHANNEL_FLAG_DIRECTION,
				cltvExpiryDelta: 0,
				htlcMinimumMsat: 0n,
				feeBaseMsat: 0,
				feeProportionalMillionths: 0
			};
			const decoded = decodeChannelUpdateMessage(
				encodeChannelUpdateMessage(msg)
			);
			expect(decoded.channelFlags & CHANNEL_FLAG_DIRECTION).to.equal(
				CHANNEL_FLAG_DIRECTION
			);
		});

		it('should preserve disabled bit in channelFlags', () => {
			const msg: IChannelUpdateMessage = {
				signature: Buffer.alloc(64),
				chainHash: Buffer.alloc(32),
				shortChannelId: Buffer.alloc(8),
				timestamp: 1,
				messageFlags: 0,
				channelFlags: CHANNEL_FLAG_DISABLED,
				cltvExpiryDelta: 0,
				htlcMinimumMsat: 0n,
				feeBaseMsat: 0,
				feeProportionalMillionths: 0
			};
			const decoded = decodeChannelUpdateMessage(
				encodeChannelUpdateMessage(msg)
			);
			expect(decoded.channelFlags & CHANNEL_FLAG_DISABLED).to.equal(
				CHANNEL_FLAG_DISABLED
			);
		});

		it('should preserve both direction and disabled bits', () => {
			const flags = CHANNEL_FLAG_DIRECTION | CHANNEL_FLAG_DISABLED;
			const msg: IChannelUpdateMessage = {
				signature: Buffer.alloc(64),
				chainHash: Buffer.alloc(32),
				shortChannelId: Buffer.alloc(8),
				timestamp: 1,
				messageFlags: 0,
				channelFlags: flags,
				cltvExpiryDelta: 0,
				htlcMinimumMsat: 0n,
				feeBaseMsat: 0,
				feeProportionalMillionths: 0
			};
			const decoded = decodeChannelUpdateMessage(
				encodeChannelUpdateMessage(msg)
			);
			expect(decoded.channelFlags).to.equal(flags);
		});

		it('should preserve all fee fields', () => {
			const msg: IChannelUpdateMessage = {
				signature: Buffer.alloc(64),
				chainHash: Buffer.alloc(32),
				shortChannelId: Buffer.alloc(8),
				timestamp: 1,
				messageFlags: MESSAGE_FLAG_HTLC_MAX,
				channelFlags: 0,
				cltvExpiryDelta: 65535,
				htlcMinimumMsat: 999_999n,
				feeBaseMsat: 4294967295,
				feeProportionalMillionths: 1000000,
				htlcMaximumMsat: 16_777_215_000_000_000n
			};
			const decoded = decodeChannelUpdateMessage(
				encodeChannelUpdateMessage(msg)
			);
			expect(decoded.cltvExpiryDelta).to.equal(65535);
			expect(decoded.htlcMinimumMsat).to.equal(999_999n);
			expect(decoded.feeBaseMsat).to.equal(4294967295);
			expect(decoded.feeProportionalMillionths).to.equal(1000000);
			expect(decoded.htlcMaximumMsat).to.equal(16_777_215_000_000_000n);
		});

		it('should reject payload too short', () => {
			expect(() => decodeChannelUpdateMessage(Buffer.alloc(127))).to.throw(
				'too short'
			);
		});

		it('should reject a zero timestamp (gossip DoS guard)', () => {
			const msg: IChannelUpdateMessage = {
				signature: Buffer.alloc(64),
				chainHash: Buffer.alloc(32),
				shortChannelId: Buffer.alloc(8),
				timestamp: 1,
				messageFlags: 0,
				channelFlags: 0,
				cltvExpiryDelta: 0,
				htlcMinimumMsat: 0n,
				feeBaseMsat: 0,
				feeProportionalMillionths: 0
			};
			const payload = encodeChannelUpdateMessage(msg);
			// Zero out the 4-byte timestamp (offset 64 sig + 32 chain + 8 scid).
			payload.writeUInt32BE(0, 104);
			expect(() => decodeChannelUpdateMessage(payload)).to.throw(
				'greater than zero'
			);
		});

		it('should have fixed length of 128 without htlc_max', () => {
			const msg: IChannelUpdateMessage = {
				signature: Buffer.alloc(64),
				chainHash: Buffer.alloc(32),
				shortChannelId: Buffer.alloc(8),
				timestamp: 0,
				messageFlags: 0,
				channelFlags: 0,
				cltvExpiryDelta: 0,
				htlcMinimumMsat: 0n,
				feeBaseMsat: 0,
				feeProportionalMillionths: 0
			};
			expect(encodeChannelUpdateMessage(msg).length).to.equal(128);
		});
	});

	// ── Announcement Signatures Messages ────────────────────────────

	describe('announcement_signatures encode/decode', () => {
		it('should round-trip all fields', () => {
			const msg: IAnnouncementSignaturesMessage = {
				channelId: crypto.randomBytes(32),
				shortChannelId: makeScid(500000, 10, 0),
				nodeSignature: crypto.randomBytes(64),
				bitcoinSignature: crypto.randomBytes(64)
			};
			const payload = encodeAnnouncementSignaturesMessage(msg);
			const decoded = decodeAnnouncementSignaturesMessage(payload);

			expect(decoded.channelId).to.deep.equal(msg.channelId);
			expect(decoded.shortChannelId).to.deep.equal(msg.shortChannelId);
			expect(decoded.nodeSignature).to.deep.equal(msg.nodeSignature);
			expect(decoded.bitcoinSignature).to.deep.equal(msg.bitcoinSignature);
		});

		it('should have fixed length of 168 bytes', () => {
			const msg: IAnnouncementSignaturesMessage = {
				channelId: Buffer.alloc(32),
				shortChannelId: Buffer.alloc(8),
				nodeSignature: Buffer.alloc(64),
				bitcoinSignature: Buffer.alloc(64)
			};
			const payload = encodeAnnouncementSignaturesMessage(msg);
			expect(payload.length).to.equal(ANNOUNCEMENT_SIGNATURES_LENGTH);
		});

		it('should reject payload too short', () => {
			expect(() =>
				decodeAnnouncementSignaturesMessage(Buffer.alloc(167))
			).to.throw('too short');
		});

		it('should preserve both signatures independently', () => {
			const nodeSig = crypto.randomBytes(64);
			const btcSig = crypto.randomBytes(64);
			const msg: IAnnouncementSignaturesMessage = {
				channelId: Buffer.alloc(32),
				shortChannelId: Buffer.alloc(8),
				nodeSignature: nodeSig,
				bitcoinSignature: btcSig
			};
			const decoded = decodeAnnouncementSignaturesMessage(
				encodeAnnouncementSignaturesMessage(msg)
			);
			expect(decoded.nodeSignature).to.deep.equal(nodeSig);
			expect(decoded.bitcoinSignature).to.deep.equal(btcSig);
			expect(decoded.nodeSignature).to.not.deep.equal(decoded.bitcoinSignature);
		});
	});

	// ── Node Address encode/decode ──────────────────────────────────

	describe('Node Address encode/decode', () => {
		it('should encode/decode IPv4 address', () => {
			const addr: INodeAddress = {
				type: ADDRESS_TYPE_IPV4,
				host: '192.168.1.100',
				port: 9735
			};
			const encoded = encodeNodeAddress(addr);
			expect(encoded.length).to.equal(7);
			const { address, bytesRead } = decodeNodeAddress(encoded, 0);
			expect(bytesRead).to.equal(7);
			expect(address.type).to.equal(ADDRESS_TYPE_IPV4);
			expect(address.host).to.equal('192.168.1.100');
			expect(address.port).to.equal(9735);
		});

		it('should encode/decode IPv6 address', () => {
			const addr: INodeAddress = {
				type: ADDRESS_TYPE_IPV6,
				host: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
				port: 9735
			};
			const encoded = encodeNodeAddress(addr);
			expect(encoded.length).to.equal(19);
			const { address, bytesRead } = decodeNodeAddress(encoded, 0);
			expect(bytesRead).to.equal(19);
			expect(address.host).to.equal('2001:0db8:85a3:0000:0000:8a2e:0370:7334');
			expect(address.port).to.equal(9735);
		});

		it('should encode/decode TorV3 address', () => {
			const hostHex = crypto.randomBytes(35).toString('hex');
			const addr: INodeAddress = {
				type: ADDRESS_TYPE_TORV3,
				host: hostHex,
				port: 9735
			};
			const encoded = encodeNodeAddress(addr);
			expect(encoded.length).to.equal(38);
			const { address, bytesRead } = decodeNodeAddress(encoded, 0);
			expect(bytesRead).to.equal(38);
			expect(address.host).to.equal(hostHex);
			expect(address.port).to.equal(9735);
		});

		it('should reject unknown address type on encode', () => {
			expect(() => encodeNodeAddress({ type: 99, host: '', port: 0 })).to.throw(
				'Unknown address type'
			);
		});
	});

	// ── Signature Validation ────────────────────────────────────────

	describe('Signature Validation', () => {
		it('should produce deterministic hash for same input', () => {
			const data = Buffer.from('hello gossip');
			const hash1 = computeGossipSignatureHash(data);
			const hash2 = computeGossipSignatureHash(data);
			expect(hash1).to.deep.equal(hash2);
		});

		it('should produce unique hashes for different inputs', () => {
			const hash1 = computeGossipSignatureHash(Buffer.from('data1'));
			const hash2 = computeGossipSignatureHash(Buffer.from('data2'));
			expect(hash1).to.not.deep.equal(hash2);
		});

		it('should extract signed data from correct offset in channel_announcement', () => {
			const payload = crypto.randomBytes(500);
			const signedData = getChannelAnnouncementSignedData(payload);
			expect(signedData.length).to.equal(500 - 256);
			expect(signedData).to.deep.equal(payload.subarray(256));
		});

		it('should extract signed data from correct offset in node_announcement', () => {
			const payload = crypto.randomBytes(200);
			const signedData = getNodeAnnouncementSignedData(payload);
			expect(signedData.length).to.equal(200 - 64);
			expect(signedData).to.deep.equal(payload.subarray(64));
		});

		it('should extract signed data from correct offset in channel_update', () => {
			const payload = crypto.randomBytes(136);
			const signedData = getChannelUpdateSignedData(payload);
			expect(signedData.length).to.equal(136 - 64);
			expect(signedData).to.deep.equal(payload.subarray(64));
		});

		describe('channel_announcement sign/verify round-trip', () => {
			it('should sign and verify successfully', () => {
				const { key1: nodeKey1, key2: nodeKey2 } = makeOrderedKeypairs();
				const btcKey1 = makeKeypair();
				const btcKey2 = makeKeypair();
				const scid = makeScid(700000, 1, 0);

				const { msg, payload } = buildChannelAnnouncement(
					nodeKey1,
					nodeKey2,
					btcKey1,
					btcKey2,
					scid
				);

				expect(verifyChannelAnnouncement(msg, payload)).to.be.true;
			});

			it('should reject with wrong signing key', () => {
				const { key1: nodeKey1, key2: nodeKey2 } = makeOrderedKeypairs();
				const btcKey1 = makeKeypair();
				const btcKey2 = makeKeypair();
				const wrongKey = makeKeypair();
				const scid = makeScid(700000, 1, 0);

				const { payload } = buildChannelAnnouncement(
					nodeKey1,
					nodeKey2,
					btcKey1,
					btcKey2,
					scid
				);

				// Tamper: replace nodeSignature1 with a signature from the wrong key
				const signedData = getChannelAnnouncementSignedData(payload);
				const hash = computeGossipSignatureHash(signedData);
				const badSig = sign(hash, wrongKey.privateKey);

				const tamperedMsg = decodeChannelAnnouncementMessage(payload);
				tamperedMsg.nodeSignature1 = badSig;

				expect(verifyChannelAnnouncement(tamperedMsg, payload)).to.be.false;
			});
		});

		describe('node_announcement sign/verify round-trip', () => {
			it('should sign and verify successfully', () => {
				const nodeKey = makeKeypair();
				const { msg, payload } = buildNodeAnnouncement(
					nodeKey.privateKey,
					1700000000,
					'test-alias'
				);
				expect(verifyNodeAnnouncement(msg, payload)).to.be.true;
			});

			it('should reject with wrong key', () => {
				const nodeKey = makeKeypair();
				const wrongKey = makeKeypair();
				const { payload } = buildNodeAnnouncement(
					nodeKey.privateKey,
					1700000000
				);

				const msg = decodeNodeAnnouncementMessage(payload);
				// Replace nodeId with wrong key's pubkey
				msg.nodeId = wrongKey.publicKey;

				expect(verifyNodeAnnouncement(msg, payload)).to.be.false;
			});
		});

		describe('channel_update sign/verify round-trip', () => {
			it('should sign and verify for direction 0', () => {
				const { key1, key2 } = makeOrderedKeypairs();
				const scid = makeScid(700000, 1, 0);
				const { msg, payload } = buildChannelUpdate(
					key1.privateKey,
					scid,
					1700000000,
					0
				);
				expect(
					verifyChannelUpdate(msg, payload, key1.publicKey, key2.publicKey)
				).to.be.true;
			});

			it('should sign and verify for direction 1', () => {
				const { key1, key2 } = makeOrderedKeypairs();
				const scid = makeScid(700000, 1, 0);
				const { msg, payload } = buildChannelUpdate(
					key2.privateKey,
					scid,
					1700000000,
					1
				);
				expect(
					verifyChannelUpdate(msg, payload, key1.publicKey, key2.publicKey)
				).to.be.true;
			});

			it('should reject wrong direction verification', () => {
				const { key1, key2 } = makeOrderedKeypairs();
				const scid = makeScid(700000, 1, 0);
				// Signed by key1 (direction 0) but we claim direction 1
				const { payload } = buildChannelUpdate(
					key1.privateKey,
					scid,
					1700000000,
					0
				);
				const msg = decodeChannelUpdateMessage(payload);
				// Modify channelFlags to claim direction 1
				const tamperedMsg: IChannelUpdateMessage = {
					...msg,
					channelFlags: msg.channelFlags | CHANNEL_FLAG_DIRECTION
				};
				// This should fail because key2 didn't sign it
				expect(
					verifyChannelUpdate(
						tamperedMsg,
						payload,
						key1.publicKey,
						key2.publicKey
					)
				).to.be.false;
			});
		});
	});

	// ── Network Graph ───────────────────────────────────────────────

	describe('NetworkGraph', () => {
		let graph: NetworkGraph;

		beforeEach(() => {
			graph = new NetworkGraph();
		});

		it('should start empty', () => {
			expect(graph.getChannelCount()).to.equal(0);
			expect(graph.getNodeCount()).to.equal(0);
		});

		it('should add a channel announcement', () => {
			const { key1, key2 } = makeOrderedKeypairs();
			const btcKey1 = makeKeypair();
			const btcKey2 = makeKeypair();
			const scid = makeScid(700000, 1, 0);
			const { msg } = buildChannelAnnouncement(
				key1,
				key2,
				btcKey1,
				btcKey2,
				scid
			);

			expect(graph.addChannelAnnouncement(msg)).to.be.true;
			expect(graph.getChannelCount()).to.equal(1);
			expect(graph.getNodeCount()).to.equal(2);
		});

		it('should reject duplicate channel', () => {
			const { key1, key2 } = makeOrderedKeypairs();
			const btcKey1 = makeKeypair();
			const btcKey2 = makeKeypair();
			const scid = makeScid(700000, 1, 0);
			const { msg } = buildChannelAnnouncement(
				key1,
				key2,
				btcKey1,
				btcKey2,
				scid
			);

			expect(graph.addChannelAnnouncement(msg)).to.be.true;
			expect(graph.addChannelAnnouncement(msg)).to.be.false;
			expect(graph.getChannelCount()).to.equal(1);
		});

		it('should reject wrong chain hash', () => {
			const { key1, key2 } = makeOrderedKeypairs();
			const btcKey1 = makeKeypair();
			const btcKey2 = makeKeypair();
			const scid = makeScid(700000, 1, 0);
			const { msg } = buildChannelAnnouncement(
				key1,
				key2,
				btcKey1,
				btcKey2,
				scid
			);
			msg.chainHash = crypto.randomBytes(32);

			expect(graph.addChannelAnnouncement(msg)).to.be.false;
		});

		it('should reject nodeId1 >= nodeId2', () => {
			const { key1, key2 } = makeOrderedKeypairs();
			const btcKey1 = makeKeypair();
			const btcKey2 = makeKeypair();
			const scid = makeScid(700000, 1, 0);
			// Swap node1 and node2 so order is wrong
			const { msg } = buildChannelAnnouncement(
				key1,
				key2,
				btcKey1,
				btcKey2,
				scid
			);
			const temp = msg.nodeId1;
			msg.nodeId1 = msg.nodeId2;
			msg.nodeId2 = temp;

			expect(graph.addChannelAnnouncement(msg)).to.be.false;
		});

		it('should look up channel by SCID', () => {
			const { key1, key2 } = makeOrderedKeypairs();
			const btcKey1 = makeKeypair();
			const btcKey2 = makeKeypair();
			const scid = makeScid(700000, 1, 0);
			const { msg } = buildChannelAnnouncement(
				key1,
				key2,
				btcKey1,
				btcKey2,
				scid
			);

			graph.addChannelAnnouncement(msg);
			const ch = graph.getChannel(scid);
			expect(ch).to.not.be.undefined;
			expect(ch!.nodeId1).to.deep.equal(key1.publicKey);
			expect(ch!.nodeId2).to.deep.equal(key2.publicKey);
		});

		it('should look up node by ID', () => {
			const { key1, key2 } = makeOrderedKeypairs();
			const btcKey1 = makeKeypair();
			const btcKey2 = makeKeypair();
			const scid = makeScid(700000, 1, 0);
			const { msg } = buildChannelAnnouncement(
				key1,
				key2,
				btcKey1,
				btcKey2,
				scid
			);

			graph.addChannelAnnouncement(msg);
			const node = graph.getNode(key1.publicKey);
			expect(node).to.not.be.undefined;
			expect(node!.channels.size).to.equal(1);
		});

		it('should return undefined for unknown channel', () => {
			expect(graph.getChannel(makeScid(1, 1, 1))).to.be.undefined;
		});

		it('should return undefined for unknown node', () => {
			expect(graph.getNode(crypto.randomBytes(33))).to.be.undefined;
		});

		it('should get node channels', () => {
			const { key1, key2 } = makeOrderedKeypairs();
			const btcKey1 = makeKeypair();
			const btcKey2 = makeKeypair();
			const btcKey3 = makeKeypair();
			const btcKey4 = makeKeypair();
			const key3 = makeKeypair();

			// Ensure key1 < key3 for second channel
			let channelKey1: typeof key1, channelKey2: typeof key3;
			if (Buffer.compare(key1.publicKey, key3.publicKey) < 0) {
				channelKey1 = key1;
				channelKey2 = key3;
			} else {
				channelKey1 = key3;
				channelKey2 = key1;
			}

			const scid1 = makeScid(700000, 1, 0);
			const scid2 = makeScid(700000, 2, 0);
			const { msg: msg1 } = buildChannelAnnouncement(
				key1,
				key2,
				btcKey1,
				btcKey2,
				scid1
			);
			const { msg: msg2 } = buildChannelAnnouncement(
				channelKey1,
				channelKey2,
				btcKey3,
				btcKey4,
				scid2
			);

			graph.addChannelAnnouncement(msg1);
			graph.addChannelAnnouncement(msg2);

			// key1 should be in both channels
			const channels = graph.getNodeChannels(key1.publicKey);
			expect(channels.length).to.equal(2);
		});

		it('should apply channel update to direction 0', () => {
			const { key1, key2 } = makeOrderedKeypairs();
			const btcKey1 = makeKeypair();
			const btcKey2 = makeKeypair();
			const scid = makeScid(700000, 1, 0);
			const { msg: annMsg } = buildChannelAnnouncement(
				key1,
				key2,
				btcKey1,
				btcKey2,
				scid
			);
			graph.addChannelAnnouncement(annMsg);

			const { msg: updateMsg } = buildChannelUpdate(
				key1.privateKey,
				scid,
				1700000000,
				0
			);
			expect(graph.applyChannelUpdate(updateMsg)).to.be.true;

			const ch = graph.getChannel(scid)!;
			expect(ch.update1).to.not.be.undefined;
			expect(ch.update1!.timestamp).to.equal(1700000000);
			expect(ch.update2).to.be.undefined;
		});

		it('should apply channel update to direction 1', () => {
			const { key1, key2 } = makeOrderedKeypairs();
			const btcKey1 = makeKeypair();
			const btcKey2 = makeKeypair();
			const scid = makeScid(700000, 1, 0);
			const { msg: annMsg } = buildChannelAnnouncement(
				key1,
				key2,
				btcKey1,
				btcKey2,
				scid
			);
			graph.addChannelAnnouncement(annMsg);

			const { msg: updateMsg } = buildChannelUpdate(
				key2.privateKey,
				scid,
				1700000000,
				1
			);
			expect(graph.applyChannelUpdate(updateMsg)).to.be.true;

			const ch = graph.getChannel(scid)!;
			expect(ch.update2).to.not.be.undefined;
			expect(ch.update1).to.be.undefined;
		});

		it('should reject update for unknown channel', () => {
			const key = makeKeypair();
			const scid = makeScid(700000, 1, 0);
			const { msg } = buildChannelUpdate(key.privateKey, scid, 1700000000, 0);
			expect(graph.applyChannelUpdate(msg)).to.be.false;
		});

		it('should reject update with older timestamp', () => {
			const { key1, key2 } = makeOrderedKeypairs();
			const btcKey1 = makeKeypair();
			const btcKey2 = makeKeypair();
			const scid = makeScid(700000, 1, 0);
			const { msg: annMsg } = buildChannelAnnouncement(
				key1,
				key2,
				btcKey1,
				btcKey2,
				scid
			);
			graph.addChannelAnnouncement(annMsg);

			const { msg: update1 } = buildChannelUpdate(
				key1.privateKey,
				scid,
				2000,
				0
			);
			const { msg: update2 } = buildChannelUpdate(
				key1.privateKey,
				scid,
				1000,
				0
			);
			const { msg: update3 } = buildChannelUpdate(
				key1.privateKey,
				scid,
				2000,
				0
			); // same timestamp

			expect(graph.applyChannelUpdate(update1)).to.be.true;
			expect(graph.applyChannelUpdate(update2)).to.be.false; // older
			expect(graph.applyChannelUpdate(update3)).to.be.false; // same
		});

		it('should apply node announcement to node with channels', () => {
			const { key1, key2 } = makeOrderedKeypairs();
			const btcKey1 = makeKeypair();
			const btcKey2 = makeKeypair();
			const scid = makeScid(700000, 1, 0);
			const { msg: annMsg } = buildChannelAnnouncement(
				key1,
				key2,
				btcKey1,
				btcKey2,
				scid
			);
			graph.addChannelAnnouncement(annMsg);

			const { msg: nodeAnn } = buildNodeAnnouncement(
				key1.privateKey,
				1700000000,
				'alice'
			);
			expect(graph.applyNodeAnnouncement(nodeAnn)).to.be.true;

			const node = graph.getNode(key1.publicKey)!;
			expect(node.announcement).to.not.be.undefined;
			expect(node.announcement!.timestamp).to.equal(1700000000);
		});

		it('should reject node announcement for node without channels', () => {
			const key = makeKeypair();
			const { msg } = buildNodeAnnouncement(key.privateKey, 1700000000);
			expect(graph.applyNodeAnnouncement(msg)).to.be.false;
		});

		it('should reject node announcement with older timestamp', () => {
			const { key1, key2 } = makeOrderedKeypairs();
			const btcKey1 = makeKeypair();
			const btcKey2 = makeKeypair();
			const scid = makeScid(700000, 1, 0);
			const { msg: annMsg } = buildChannelAnnouncement(
				key1,
				key2,
				btcKey1,
				btcKey2,
				scid
			);
			graph.addChannelAnnouncement(annMsg);

			const { msg: nodeAnn1 } = buildNodeAnnouncement(key1.privateKey, 2000);
			const { msg: nodeAnn2 } = buildNodeAnnouncement(key1.privateKey, 1000);

			expect(graph.applyNodeAnnouncement(nodeAnn1)).to.be.true;
			expect(graph.applyNodeAnnouncement(nodeAnn2)).to.be.false;
		});

		it('should remove channel and clean up orphan nodes', () => {
			const { key1, key2 } = makeOrderedKeypairs();
			const btcKey1 = makeKeypair();
			const btcKey2 = makeKeypair();
			const scid = makeScid(700000, 1, 0);
			const { msg } = buildChannelAnnouncement(
				key1,
				key2,
				btcKey1,
				btcKey2,
				scid
			);
			graph.addChannelAnnouncement(msg);

			expect(graph.getChannelCount()).to.equal(1);
			expect(graph.getNodeCount()).to.equal(2);

			expect(graph.removeChannel(scid)).to.be.true;
			expect(graph.getChannelCount()).to.equal(0);
			expect(graph.getNodeCount()).to.equal(0);
		});

		it('should not remove node with other channels', () => {
			const { key1, key2 } = makeOrderedKeypairs();
			const btcKey1 = makeKeypair();
			const btcKey2 = makeKeypair();
			const btcKey3 = makeKeypair();
			const btcKey4 = makeKeypair();
			const key3 = makeKeypair();

			let channelKey1: typeof key1, channelKey2: typeof key3;
			if (Buffer.compare(key1.publicKey, key3.publicKey) < 0) {
				channelKey1 = key1;
				channelKey2 = key3;
			} else {
				channelKey1 = key3;
				channelKey2 = key1;
			}

			const scid1 = makeScid(700000, 1, 0);
			const scid2 = makeScid(700000, 2, 0);
			const { msg: msg1 } = buildChannelAnnouncement(
				key1,
				key2,
				btcKey1,
				btcKey2,
				scid1
			);
			const { msg: msg2 } = buildChannelAnnouncement(
				channelKey1,
				channelKey2,
				btcKey3,
				btcKey4,
				scid2
			);

			graph.addChannelAnnouncement(msg1);
			graph.addChannelAnnouncement(msg2);

			graph.removeChannel(scid1);
			expect(graph.getChannelCount()).to.equal(1);
			// key1 still has scid2, key2 has no channels
			expect(graph.getNode(key1.publicKey)).to.not.be.undefined;
		});

		it('should return false for removing non-existent channel', () => {
			expect(graph.removeChannel(makeScid(1, 1, 1))).to.be.false;
		});

		it('should prune stale channels', () => {
			const { key1, key2 } = makeOrderedKeypairs();
			const btcKey1 = makeKeypair();
			const btcKey2 = makeKeypair();
			const scid = makeScid(700000, 1, 0);
			const { msg: annMsg } = buildChannelAnnouncement(
				key1,
				key2,
				btcKey1,
				btcKey2,
				scid
			);
			graph.addChannelAnnouncement(annMsg);

			// Add old update
			const { msg: updateMsg } = buildChannelUpdate(
				key1.privateKey,
				scid,
				1000,
				0
			);
			graph.applyChannelUpdate(updateMsg);

			// Prune with current time far in the future
			const pruned = graph.pruneStaleChannels(1000 + DEFAULT_PRUNE_MAX_AGE + 1);
			expect(pruned).to.equal(1);
			expect(graph.getChannelCount()).to.equal(0);
		});

		it('should not prune fresh channels', () => {
			const { key1, key2 } = makeOrderedKeypairs();
			const btcKey1 = makeKeypair();
			const btcKey2 = makeKeypair();
			const scid = makeScid(700000, 1, 0);
			const { msg: annMsg } = buildChannelAnnouncement(
				key1,
				key2,
				btcKey1,
				btcKey2,
				scid
			);
			graph.addChannelAnnouncement(annMsg);

			const { msg: updateMsg } = buildChannelUpdate(
				key1.privateKey,
				scid,
				1700000000,
				0
			);
			graph.applyChannelUpdate(updateMsg);

			const pruned = graph.pruneStaleChannels(1700000000);
			expect(pruned).to.equal(0);
			expect(graph.getChannelCount()).to.equal(1);
		});

		it('should prune channels with no updates', () => {
			const { key1, key2 } = makeOrderedKeypairs();
			const btcKey1 = makeKeypair();
			const btcKey2 = makeKeypair();
			const scid = makeScid(700000, 1, 0);
			const { msg } = buildChannelAnnouncement(
				key1,
				key2,
				btcKey1,
				btcKey2,
				scid
			);
			graph.addChannelAnnouncement(msg);

			// No updates added — latest timestamp is 0
			const pruned = graph.pruneStaleChannels(DEFAULT_PRUNE_MAX_AGE + 1);
			expect(pruned).to.equal(1);
		});

		it('should return all channel IDs', () => {
			const { key1, key2 } = makeOrderedKeypairs();
			const btcKey1 = makeKeypair();
			const btcKey2 = makeKeypair();
			const scid1 = makeScid(700000, 1, 0);
			const scid2 = makeScid(700000, 2, 0);
			const { key1: key3, key2: key4 } = makeOrderedKeypairs();
			const btcKey3 = makeKeypair();
			const btcKey4 = makeKeypair();

			const { msg: msg1 } = buildChannelAnnouncement(
				key1,
				key2,
				btcKey1,
				btcKey2,
				scid1
			);
			const { msg: msg2 } = buildChannelAnnouncement(
				key3,
				key4,
				btcKey3,
				btcKey4,
				scid2
			);

			graph.addChannelAnnouncement(msg1);
			graph.addChannelAnnouncement(msg2);

			const ids = graph.getAllChannelIds();
			expect(ids).to.have.length(2);
		});

		it('should return all node IDs', () => {
			const { key1, key2 } = makeOrderedKeypairs();
			const btcKey1 = makeKeypair();
			const btcKey2 = makeKeypair();
			const scid = makeScid(700000, 1, 0);
			const { msg } = buildChannelAnnouncement(
				key1,
				key2,
				btcKey1,
				btcKey2,
				scid
			);
			graph.addChannelAnnouncement(msg);

			const ids = graph.getAllNodeIds();
			expect(ids).to.have.length(2);
		});
	});

	// ── Pathfinding ─────────────────────────────────────────────────

	describe('Pathfinding', () => {
		describe('calculateFee', () => {
			it('should return zero for zero fees', () => {
				expect(calculateFee(1_000_000n, 0, 0)).to.equal(0n);
			});

			it('should calculate base-only fee', () => {
				expect(calculateFee(1_000_000n, 1000, 0)).to.equal(1000n);
			});

			it('should calculate proportional-only fee', () => {
				// 1_000_000 * 1000 / 1_000_000 = 1000
				expect(calculateFee(1_000_000n, 0, 1000)).to.equal(1000n);
			});

			it('should calculate combined fee', () => {
				// base=1000 + 1_000_000 * 500 / 1_000_000 = 1000 + 500 = 1500
				expect(calculateFee(1_000_000n, 1000, 500)).to.equal(1500n);
			});

			it('should handle large amounts', () => {
				const amount = 100_000_000_000n; // 100 BTC in msat
				const fee = calculateFee(amount, 1000, 1);
				// base=1000 + 100_000_000_000 * 1 / 1_000_000 = 1000 + 100_000 = 101_000
				expect(fee).to.equal(101_000n);
			});
		});

		describe('findRoute', () => {
			/** Helper to set up a simple graph with channels and updates. */
			function setupGraph(): {
				graph: NetworkGraph;
				keys: Array<{ privateKey: Buffer; publicKey: Buffer }>;
			} {
				// Create 4 nodes: A -> B -> C -> D
				// We need them in lexicographic order for channel announcements
				const rawKeys = Array.from({ length: 4 }, () => makeKeypair());
				// Sort by pubkey
				rawKeys.sort((a, b) => Buffer.compare(a.publicKey, b.publicKey));

				const graph = new NetworkGraph();

				// Channel A-B
				const btcAB1 = makeKeypair(),
					btcAB2 = makeKeypair();
				const scidAB = makeScid(100, 1, 0);
				const { msg: annAB } = buildChannelAnnouncement(
					rawKeys[0],
					rawKeys[1],
					btcAB1,
					btcAB2,
					scidAB
				);
				graph.addChannelAnnouncement(annAB);

				// Channel B-C
				const btcBC1 = makeKeypair(),
					btcBC2 = makeKeypair();
				const scidBC = makeScid(100, 2, 0);
				const { msg: annBC } = buildChannelAnnouncement(
					rawKeys[1],
					rawKeys[2],
					btcBC1,
					btcBC2,
					scidBC
				);
				graph.addChannelAnnouncement(annBC);

				// Channel C-D
				const btcCD1 = makeKeypair(),
					btcCD2 = makeKeypair();
				const scidCD = makeScid(100, 3, 0);
				const { msg: annCD } = buildChannelAnnouncement(
					rawKeys[2],
					rawKeys[3],
					btcCD1,
					btcCD2,
					scidCD
				);
				graph.addChannelAnnouncement(annCD);

				// Add bidirectional updates for all channels
				const addUpdates = (
					nodeKeys: typeof rawKeys,
					idx1: number,
					idx2: number,
					scid: Buffer
				) => {
					// Direction 0 (from lower-key node)
					const { msg: u0 } = buildChannelUpdate(
						nodeKeys[idx1].privateKey,
						scid,
						1700000000,
						0,
						{
							cltvExpiryDelta: 40,
							htlcMinimumMsat: 1000n,
							feeBaseMsat: 1000,
							feeProportionalMillionths: 1,
							htlcMaximumMsat: 1_000_000_000_000n
						}
					);
					graph.applyChannelUpdate(u0);

					// Direction 1 (from higher-key node)
					const { msg: u1 } = buildChannelUpdate(
						nodeKeys[idx2].privateKey,
						scid,
						1700000000,
						1,
						{
							cltvExpiryDelta: 40,
							htlcMinimumMsat: 1000n,
							feeBaseMsat: 1000,
							feeProportionalMillionths: 1,
							htlcMaximumMsat: 1_000_000_000_000n
						}
					);
					graph.applyChannelUpdate(u1);
				};

				addUpdates(rawKeys, 0, 1, scidAB);
				addUpdates(rawKeys, 1, 2, scidBC);
				addUpdates(rawKeys, 2, 3, scidCD);

				return { graph, keys: rawKeys };
			}

			it('should find a direct (1-hop) route', () => {
				const { graph, keys } = setupGraph();
				const route = findRoute(
					graph,
					keys[0].publicKey,
					keys[1].publicKey,
					100_000n,
					144
				);

				expect(route).to.not.be.null;
				expect(route!.hops).to.have.length(1);
				expect(route!.hops[0].amountToForwardMsat).to.equal(100_000n);
				expect(route!.hops[0].outgoingCltvValue).to.equal(144);
				expect(route!.hops[0].pubkey).to.deep.equal(keys[1].publicKey);
			});

			it('prefers a shorter route over a longer zero-fee route (hop penalty)', () => {
				// Pure fee-minimization would pick a long zero-fee path, which is
				// far more likely to stall (each extra hop is a failure point). The
				// per-hop reliability penalty must make a cheaper-to-route shorter
				// path win even when a longer path has strictly lower fees.
				const graph = new NetworkGraph();
				const [S, D, M, P, Q] = Array.from({ length: 5 }, () => makeKeypair());

				let scidCounter = 1;
				const announce = (
					a: { privateKey: Buffer; publicKey: Buffer },
					b: { privateKey: Buffer; publicKey: Buffer },
					feeBaseMsat: number
				) => {
					const scid = makeScid(100, scidCounter++, 0);
					const [n1, n2] =
						Buffer.compare(a.publicKey, b.publicKey) < 0 ? [a, b] : [b, a];
					const { msg: ann } = buildChannelAnnouncement(
						n1,
						n2,
						makeKeypair(),
						makeKeypair(),
						scid
					);
					graph.addChannelAnnouncement(ann);
					for (const direction of [0, 1]) {
						const signer = direction === 0 ? n1 : n2;
						const { msg: upd } = buildChannelUpdate(
							signer.privateKey,
							scid,
							1700000000,
							direction,
							{
								cltvExpiryDelta: 40,
								htlcMinimumMsat: 1000n,
								feeBaseMsat,
								feeProportionalMillionths: 0,
								htlcMaximumMsat: 1_000_000_000_000n
							}
						);
						graph.applyChannelUpdate(upd);
					}
				};

				// Short path S -> M -> D: M charges a small 500 msat forwarding fee.
				announce(S, M, 0);
				announce(M, D, 500);
				// Long path S -> P -> Q -> D: entirely fee-free.
				announce(S, P, 0);
				announce(P, Q, 0);
				announce(Q, D, 0);

				const route = findRoute(graph, S.publicKey, D.publicKey, 100_000n, 144);
				expect(route).to.not.be.null;
				expect(route!.hops).to.have.length(2);
				expect(route!.hops[0].pubkey).to.deep.equal(M.publicKey);
			});

			it('should find a 2-hop route', () => {
				const { graph, keys } = setupGraph();
				const route = findRoute(
					graph,
					keys[0].publicKey,
					keys[2].publicKey,
					100_000n,
					144
				);

				expect(route).to.not.be.null;
				expect(route!.hops).to.have.length(2);
				// Last hop delivers exact amount
				expect(route!.hops[1].amountToForwardMsat).to.equal(100_000n);
				expect(route!.hops[1].outgoingCltvValue).to.equal(144);
				// First hop includes fee
				expect(Number(route!.hops[0].amountToForwardMsat)).to.be.greaterThan(
					100_000
				);
			});

			it('should find a 3-hop route', () => {
				const { graph, keys } = setupGraph();
				const route = findRoute(
					graph,
					keys[0].publicKey,
					keys[3].publicKey,
					100_000n,
					144
				);

				expect(route).to.not.be.null;
				expect(route!.hops).to.have.length(3);
				expect(route!.hops[2].amountToForwardMsat).to.equal(100_000n);
			});

			it('should return null for same source and destination', () => {
				const { graph, keys } = setupGraph();
				const route = findRoute(
					graph,
					keys[0].publicKey,
					keys[0].publicKey,
					100_000n,
					144
				);
				expect(route).to.be.null;
			});

			it('should return null for unreachable destination', () => {
				const { graph, keys } = setupGraph();
				const isolatedKey = makeKeypair();
				const route = findRoute(
					graph,
					keys[0].publicKey,
					isolatedKey.publicKey,
					100_000n,
					144
				);
				expect(route).to.be.null;
			});

			// Local channels: route over our own channels even when unannounced
			// (matches LND/CLN/LDK — a direct payment to a channel peer must work
			// regardless of gossip).
			it('routes a direct payment to a channel peer not in the gossip graph', () => {
				const graph = new NetworkGraph(); // nothing announced
				const me = makeKeypair();
				const peer = makeKeypair();
				const scid = makeScid(200, 1, 0);

				// Without local channels the peer is unreachable.
				expect(findRoute(graph, me.publicKey, peer.publicKey, 50_000n, 144)).to
					.be.null;

				// With a local channel to the peer: direct 1-hop route, zero fee.
				const route = findRoute(
					graph,
					me.publicKey,
					peer.publicKey,
					50_000n,
					144,
					undefined,
					undefined,
					undefined,
					undefined,
					undefined,
					undefined,
					[
						{
							shortChannelId: scid,
							peer: peer.publicKey,
							outboundMsat: 1_000_000n
						}
					]
				);
				expect(route).to.not.be.null;
				expect(route!.hops).to.have.length(1);
				expect(route!.hops[0].pubkey).to.deep.equal(peer.publicKey);
				expect(route!.hops[0].amountToForwardMsat).to.equal(50_000n);
				expect(route!.totalFeeMsat).to.equal(0n);
			});

			it('respects the local channel outbound capacity', () => {
				const graph = new NetworkGraph();
				const me = makeKeypair();
				const peer = makeKeypair();
				const local = [
					{
						shortChannelId: makeScid(200, 2, 0),
						peer: peer.publicKey,
						outboundMsat: 40_000n
					}
				];

				expect(
					findRoute(
						graph,
						me.publicKey,
						peer.publicKey,
						40_000n,
						144,
						undefined,
						undefined,
						undefined,
						undefined,
						undefined,
						undefined,
						local
					)
				).to.not.be.null;
				expect(
					findRoute(
						graph,
						me.publicKey,
						peer.publicKey,
						40_001n,
						144,
						undefined,
						undefined,
						undefined,
						undefined,
						undefined,
						undefined,
						local
					)
				).to.be.null;
			});

			it('uses a local channel as the first hop into the announced graph', () => {
				const { graph, keys } = setupGraph(); // keys[1]→keys[2]→keys[3] announced
				const me = makeKeypair(); // not present in the graph

				// No announced path from `me` into the graph.
				expect(findRoute(graph, me.publicKey, keys[3].publicKey, 100_000n, 144))
					.to.be.null;

				// A local channel me→keys[1] lets us reach keys[3] via the graph.
				const route = findRoute(
					graph,
					me.publicKey,
					keys[3].publicKey,
					100_000n,
					144,
					undefined,
					undefined,
					undefined,
					undefined,
					undefined,
					undefined,
					[
						{
							shortChannelId: makeScid(200, 3, 0),
							peer: keys[1].publicKey,
							outboundMsat: 10_000_000n
						}
					]
				);
				expect(route).to.not.be.null;
				expect(route!.hops).to.have.length(3);
				expect(route!.hops[0].pubkey).to.deep.equal(keys[1].publicKey);
				expect(route!.hops[2].pubkey).to.deep.equal(keys[3].publicKey);
			});

			it('should return null when amount exceeds htlc maximum', () => {
				const graph = new NetworkGraph();
				const { key1, key2 } = makeOrderedKeypairs();
				const btcKey1 = makeKeypair(),
					btcKey2 = makeKeypair();
				const scid = makeScid(100, 1, 0);
				const { msg: ann } = buildChannelAnnouncement(
					key1,
					key2,
					btcKey1,
					btcKey2,
					scid
				);
				graph.addChannelAnnouncement(ann);

				// Set htlcMaximumMsat to small value
				const { msg: u0 } = buildChannelUpdate(
					key1.privateKey,
					scid,
					1700000000,
					0,
					{
						htlcMaximumMsat: 50_000n,
						htlcMinimumMsat: 1000n,
						feeBaseMsat: 1000,
						feeProportionalMillionths: 1
					}
				);
				const { msg: u1 } = buildChannelUpdate(
					key2.privateKey,
					scid,
					1700000000,
					1,
					{
						htlcMaximumMsat: 50_000n,
						htlcMinimumMsat: 1000n,
						feeBaseMsat: 1000,
						feeProportionalMillionths: 1
					}
				);
				graph.applyChannelUpdate(u0);
				graph.applyChannelUpdate(u1);

				const route = findRoute(
					graph,
					key1.publicKey,
					key2.publicKey,
					100_000n,
					144
				);
				expect(route).to.be.null;
			});

			it('should return null when amount below htlc minimum', () => {
				const graph = new NetworkGraph();
				const { key1, key2 } = makeOrderedKeypairs();
				const btcKey1 = makeKeypair(),
					btcKey2 = makeKeypair();
				const scid = makeScid(100, 1, 0);
				const { msg: ann } = buildChannelAnnouncement(
					key1,
					key2,
					btcKey1,
					btcKey2,
					scid
				);
				graph.addChannelAnnouncement(ann);

				const { msg: u0 } = buildChannelUpdate(
					key1.privateKey,
					scid,
					1700000000,
					0,
					{
						htlcMinimumMsat: 10_000n,
						feeBaseMsat: 1000,
						feeProportionalMillionths: 1,
						htlcMaximumMsat: 1_000_000_000n
					}
				);
				const { msg: u1 } = buildChannelUpdate(
					key2.privateKey,
					scid,
					1700000000,
					1,
					{
						htlcMinimumMsat: 10_000n,
						feeBaseMsat: 1000,
						feeProportionalMillionths: 1,
						htlcMaximumMsat: 1_000_000_000n
					}
				);
				graph.applyChannelUpdate(u0);
				graph.applyChannelUpdate(u1);

				const route = findRoute(
					graph,
					key1.publicKey,
					key2.publicKey,
					5_000n,
					144
				);
				expect(route).to.be.null;
			});

			it('should skip disabled channels', () => {
				const graph = new NetworkGraph();
				const { key1, key2 } = makeOrderedKeypairs();
				const btcKey1 = makeKeypair(),
					btcKey2 = makeKeypair();
				const scid = makeScid(100, 1, 0);
				const { msg: ann } = buildChannelAnnouncement(
					key1,
					key2,
					btcKey1,
					btcKey2,
					scid
				);
				graph.addChannelAnnouncement(ann);

				// Both directions disabled
				const { msg: u0 } = buildChannelUpdate(
					key1.privateKey,
					scid,
					1700000000,
					0,
					{
						disabled: true,
						feeBaseMsat: 1000,
						feeProportionalMillionths: 1,
						htlcMaximumMsat: 1_000_000_000n
					}
				);
				const { msg: u1 } = buildChannelUpdate(
					key2.privateKey,
					scid,
					1700000000,
					1,
					{
						disabled: true,
						feeBaseMsat: 1000,
						feeProportionalMillionths: 1,
						htlcMaximumMsat: 1_000_000_000n
					}
				);
				graph.applyChannelUpdate(u0);
				graph.applyChannelUpdate(u1);

				const route = findRoute(
					graph,
					key1.publicKey,
					key2.publicKey,
					100_000n,
					144
				);
				expect(route).to.be.null;
			});

			it('should verify fee accumulation in multi-hop route', () => {
				const { graph, keys } = setupGraph();
				const paymentAmount = 1_000_000n;
				const route = findRoute(
					graph,
					keys[0].publicKey,
					keys[3].publicKey,
					paymentAmount,
					144
				);

				expect(route).to.not.be.null;

				// Last hop delivers exact amount
				const lastHop = route!.hops[route!.hops.length - 1];
				expect(lastHop.amountToForwardMsat).to.equal(paymentAmount);

				// Each preceding hop must include fee for the next
				for (let i = route!.hops.length - 2; i >= 0; i--) {
					const hop = route!.hops[i];
					const nextHop = route!.hops[i + 1];
					const expectedFee = calculateFee(
						nextHop.amountToForwardMsat,
						hop.feeBaseMsat,
						hop.feeProportionalMillionths
					);
					expect(hop.amountToForwardMsat).to.equal(
						nextHop.amountToForwardMsat + expectedFee
					);
				}

				// Total fee should match
				expect(route!.totalFeeMsat).to.equal(
					route!.hops[0].amountToForwardMsat - paymentAmount
				);
				expect(route!.totalAmountMsat).to.equal(
					route!.hops[0].amountToForwardMsat
				);
			});

			it('should verify CLTV accumulation in multi-hop route', () => {
				const { graph, keys } = setupGraph();
				const finalCltv = 144;
				const route = findRoute(
					graph,
					keys[0].publicKey,
					keys[3].publicKey,
					100_000n,
					finalCltv
				);

				expect(route).to.not.be.null;

				// Last hop has final CLTV
				const lastHop = route!.hops[route!.hops.length - 1];
				expect(lastHop.outgoingCltvValue).to.equal(finalCltv);

				// Each preceding hop adds cltvExpiryDelta
				for (let i = route!.hops.length - 2; i >= 0; i--) {
					const hop = route!.hops[i];
					const nextHop = route!.hops[i + 1];
					expect(hop.outgoingCltvValue).to.equal(
						nextHop.outgoingCltvValue + nextHop.cltvExpiryDelta
					);
				}

				// Total CLTV delta
				expect(route!.totalCltvDelta).to.be.greaterThan(0);
			});

			it('should enforce maxHops', () => {
				const { graph, keys } = setupGraph();
				// 3-hop route but max 2 hops
				const route = findRoute(
					graph,
					keys[0].publicKey,
					keys[3].publicKey,
					100_000n,
					144,
					2
				);
				expect(route).to.be.null;
			});

			it('should prefer lower-cost route', () => {
				// Create a diamond: A -> B -> D and A -> C -> D
				// Make A-C-D cheaper than A-B-D
				const rawKeys = Array.from({ length: 4 }, () => makeKeypair());
				rawKeys.sort((a, b) => Buffer.compare(a.publicKey, b.publicKey));

				const graph = new NetworkGraph();

				// Channel 0-1 (A-B): high fee
				const btc01a = makeKeypair(),
					btc01b = makeKeypair();
				const scid01 = makeScid(100, 1, 0);
				const { msg: ann01 } = buildChannelAnnouncement(
					rawKeys[0],
					rawKeys[1],
					btc01a,
					btc01b,
					scid01
				);
				graph.addChannelAnnouncement(ann01);

				// Channel 0-2 (A-C): low fee
				const btc02a = makeKeypair(),
					btc02b = makeKeypair();
				const scid02 = makeScid(100, 2, 0);
				const { msg: ann02 } = buildChannelAnnouncement(
					rawKeys[0],
					rawKeys[2],
					btc02a,
					btc02b,
					scid02
				);
				graph.addChannelAnnouncement(ann02);

				// Channel 1-3 (B-D): high fee
				const btc13a = makeKeypair(),
					btc13b = makeKeypair();
				const scid13 = makeScid(100, 3, 0);
				const { msg: ann13 } = buildChannelAnnouncement(
					rawKeys[1],
					rawKeys[3],
					btc13a,
					btc13b,
					scid13
				);
				graph.addChannelAnnouncement(ann13);

				// Channel 2-3 (C-D): low fee
				const btc23a = makeKeypair(),
					btc23b = makeKeypair();
				const scid23 = makeScid(100, 4, 0);
				const { msg: ann23 } = buildChannelAnnouncement(
					rawKeys[2],
					rawKeys[3],
					btc23a,
					btc23b,
					scid23
				);
				graph.addChannelAnnouncement(ann23);

				// High fee updates for A-B and B-D (10000 base)
				const addExpensiveUpdates = (
					privKey1: Buffer,
					privKey2: Buffer,
					scid: Buffer
				) => {
					const { msg: u0 } = buildChannelUpdate(
						privKey1,
						scid,
						1700000000,
						0,
						{
							feeBaseMsat: 10000,
							feeProportionalMillionths: 100,
							htlcMinimumMsat: 1000n,
							htlcMaximumMsat: 1_000_000_000_000n
						}
					);
					const { msg: u1 } = buildChannelUpdate(
						privKey2,
						scid,
						1700000000,
						1,
						{
							feeBaseMsat: 10000,
							feeProportionalMillionths: 100,
							htlcMinimumMsat: 1000n,
							htlcMaximumMsat: 1_000_000_000_000n
						}
					);
					graph.applyChannelUpdate(u0);
					graph.applyChannelUpdate(u1);
				};

				// Low fee updates for A-C and C-D (100 base)
				const addCheapUpdates = (
					privKey1: Buffer,
					privKey2: Buffer,
					scid: Buffer
				) => {
					const { msg: u0 } = buildChannelUpdate(
						privKey1,
						scid,
						1700000000,
						0,
						{
							feeBaseMsat: 100,
							feeProportionalMillionths: 1,
							htlcMinimumMsat: 1000n,
							htlcMaximumMsat: 1_000_000_000_000n
						}
					);
					const { msg: u1 } = buildChannelUpdate(
						privKey2,
						scid,
						1700000000,
						1,
						{
							feeBaseMsat: 100,
							feeProportionalMillionths: 1,
							htlcMinimumMsat: 1000n,
							htlcMaximumMsat: 1_000_000_000_000n
						}
					);
					graph.applyChannelUpdate(u0);
					graph.applyChannelUpdate(u1);
				};

				addExpensiveUpdates(
					rawKeys[0].privateKey,
					rawKeys[1].privateKey,
					scid01
				);
				addCheapUpdates(rawKeys[0].privateKey, rawKeys[2].privateKey, scid02);
				addExpensiveUpdates(
					rawKeys[1].privateKey,
					rawKeys[3].privateKey,
					scid13
				);
				addCheapUpdates(rawKeys[2].privateKey, rawKeys[3].privateKey, scid23);

				const route = findRoute(
					graph,
					rawKeys[0].publicKey,
					rawKeys[3].publicKey,
					1_000_000n,
					144
				);

				expect(route).to.not.be.null;
				expect(route!.hops).to.have.length(2);
				// Should go through C (rawKeys[2]), not B (rawKeys[1])
				expect(route!.hops[0].pubkey).to.deep.equal(rawKeys[2].publicKey);
				expect(route!.hops[1].pubkey).to.deep.equal(rawKeys[3].publicKey);
			});
		});
	});

	// ── Integration ─────────────────────────────────────────────────

	describe('Integration', () => {
		it('should export all types through barrel', async () => {
			const gossip = await import('../../src/lightning/gossip');
			expect(gossip.encodeShortChannelId).to.be.a('function');
			expect(gossip.decodeShortChannelId).to.be.a('function');
			expect(gossip.encodeChannelAnnouncementMessage).to.be.a('function');
			expect(gossip.decodeChannelAnnouncementMessage).to.be.a('function');
			expect(gossip.encodeNodeAnnouncementMessage).to.be.a('function');
			expect(gossip.decodeNodeAnnouncementMessage).to.be.a('function');
			expect(gossip.encodeChannelUpdateMessage).to.be.a('function');
			expect(gossip.decodeChannelUpdateMessage).to.be.a('function');
			expect(gossip.computeGossipSignatureHash).to.be.a('function');
			expect(gossip.verifyChannelAnnouncement).to.be.a('function');
			expect(gossip.NetworkGraph).to.be.a('function');
			expect(gossip.calculateFee).to.be.a('function');
			expect(gossip.findRoute).to.be.a('function');
		});

		it('should be accessible via lightning.gossip', async () => {
			const lightning = await import('../../src/lightning');
			expect(lightning.gossip).to.not.be.undefined;
			expect(lightning.gossip.NetworkGraph).to.be.a('function');
			expect(lightning.gossip.findRoute).to.be.a('function');
		});

		it('should build graph, find route, and verify hop amounts end-to-end', () => {
			// Create 3 nodes: A -> B -> C
			const rawKeys = Array.from({ length: 3 }, () => makeKeypair());
			rawKeys.sort((a, b) => Buffer.compare(a.publicKey, b.publicKey));

			const graph = new NetworkGraph();

			// Channel A-B
			const btcAB1 = makeKeypair(),
				btcAB2 = makeKeypair();
			const scidAB = makeScid(500, 1, 0);
			const { msg: annAB } = buildChannelAnnouncement(
				rawKeys[0],
				rawKeys[1],
				btcAB1,
				btcAB2,
				scidAB
			);
			graph.addChannelAnnouncement(annAB);

			// Channel B-C
			const btcBC1 = makeKeypair(),
				btcBC2 = makeKeypair();
			const scidBC = makeScid(500, 2, 0);
			const { msg: annBC } = buildChannelAnnouncement(
				rawKeys[1],
				rawKeys[2],
				btcBC1,
				btcBC2,
				scidBC
			);
			graph.addChannelAnnouncement(annBC);

			// Updates with specific fees
			const { msg: uAB0 } = buildChannelUpdate(
				rawKeys[0].privateKey,
				scidAB,
				1700000000,
				0,
				{
					feeBaseMsat: 500,
					feeProportionalMillionths: 10,
					cltvExpiryDelta: 40,
					htlcMinimumMsat: 100n,
					htlcMaximumMsat: 10_000_000_000n
				}
			);
			const { msg: uAB1 } = buildChannelUpdate(
				rawKeys[1].privateKey,
				scidAB,
				1700000000,
				1,
				{
					feeBaseMsat: 500,
					feeProportionalMillionths: 10,
					cltvExpiryDelta: 40,
					htlcMinimumMsat: 100n,
					htlcMaximumMsat: 10_000_000_000n
				}
			);
			const { msg: uBC0 } = buildChannelUpdate(
				rawKeys[1].privateKey,
				scidBC,
				1700000000,
				0,
				{
					feeBaseMsat: 200,
					feeProportionalMillionths: 5,
					cltvExpiryDelta: 30,
					htlcMinimumMsat: 100n,
					htlcMaximumMsat: 10_000_000_000n
				}
			);
			const { msg: uBC1 } = buildChannelUpdate(
				rawKeys[2].privateKey,
				scidBC,
				1700000000,
				1,
				{
					feeBaseMsat: 200,
					feeProportionalMillionths: 5,
					cltvExpiryDelta: 30,
					htlcMinimumMsat: 100n,
					htlcMaximumMsat: 10_000_000_000n
				}
			);
			graph.applyChannelUpdate(uAB0);
			graph.applyChannelUpdate(uAB1);
			graph.applyChannelUpdate(uBC0);
			graph.applyChannelUpdate(uBC1);

			const paymentAmount = 1_000_000n;
			const finalCltv = 144;
			const route = findRoute(
				graph,
				rawKeys[0].publicKey,
				rawKeys[2].publicKey,
				paymentAmount,
				finalCltv
			);

			expect(route).to.not.be.null;
			expect(route!.hops).to.have.length(2);

			// Verify last hop delivers exact amount
			expect(route!.hops[1].amountToForwardMsat).to.equal(paymentAmount);
			expect(route!.hops[1].outgoingCltvValue).to.equal(finalCltv);

			// Verify first hop fee calculation
			// The first hop (B→C) charges: base=200 + 1_000_000 * 5 / 1_000_000 = 200 + 5 = 205
			// But wait — the fee in the first hop is what the hop B charges to forward
			// Actually the hop info in route is about what B needs to receive
			const expectedFee = calculateFee(
				paymentAmount,
				route!.hops[0].feeBaseMsat,
				route!.hops[0].feeProportionalMillionths
			);
			expect(route!.hops[0].amountToForwardMsat).to.equal(
				paymentAmount + expectedFee
			);

			// Verify CLTV
			expect(route!.hops[0].outgoingCltvValue).to.equal(
				finalCltv + route!.hops[1].cltvExpiryDelta
			);

			// Verify totals
			expect(route!.totalAmountMsat).to.equal(
				route!.hops[0].amountToForwardMsat
			);
			expect(route!.totalFeeMsat).to.equal(
				route!.totalAmountMsat - paymentAmount
			);
		});

		it('should handle bidirectional routing', () => {
			// Verify routing works in both directions
			const rawKeys = Array.from({ length: 2 }, () => makeKeypair());
			rawKeys.sort((a, b) => Buffer.compare(a.publicKey, b.publicKey));

			const graph = new NetworkGraph();
			const btc1 = makeKeypair(),
				btc2 = makeKeypair();
			const scid = makeScid(100, 1, 0);
			const { msg: ann } = buildChannelAnnouncement(
				rawKeys[0],
				rawKeys[1],
				btc1,
				btc2,
				scid
			);
			graph.addChannelAnnouncement(ann);

			// Add updates in both directions
			const { msg: u0 } = buildChannelUpdate(
				rawKeys[0].privateKey,
				scid,
				1700000000,
				0,
				{
					feeBaseMsat: 1000,
					feeProportionalMillionths: 1,
					htlcMinimumMsat: 100n,
					htlcMaximumMsat: 10_000_000_000n
				}
			);
			const { msg: u1 } = buildChannelUpdate(
				rawKeys[1].privateKey,
				scid,
				1700000000,
				1,
				{
					feeBaseMsat: 2000,
					feeProportionalMillionths: 2,
					htlcMinimumMsat: 100n,
					htlcMaximumMsat: 10_000_000_000n
				}
			);
			graph.applyChannelUpdate(u0);
			graph.applyChannelUpdate(u1);

			// Route A -> B
			const routeAB = findRoute(
				graph,
				rawKeys[0].publicKey,
				rawKeys[1].publicKey,
				100_000n,
				144
			);
			expect(routeAB).to.not.be.null;
			expect(routeAB!.hops).to.have.length(1);

			// Route B -> A
			const routeBA = findRoute(
				graph,
				rawKeys[1].publicKey,
				rawKeys[0].publicKey,
				100_000n,
				144
			);
			expect(routeBA).to.not.be.null;
			expect(routeBA!.hops).to.have.length(1);
		});

		it('should handle channel with only one direction update', () => {
			const rawKeys = Array.from({ length: 2 }, () => makeKeypair());
			rawKeys.sort((a, b) => Buffer.compare(a.publicKey, b.publicKey));

			const graph = new NetworkGraph();
			const btc1 = makeKeypair(),
				btc2 = makeKeypair();
			const scid = makeScid(100, 1, 0);
			const { msg: ann } = buildChannelAnnouncement(
				rawKeys[0],
				rawKeys[1],
				btc1,
				btc2,
				scid
			);
			graph.addChannelAnnouncement(ann);

			// Only add direction 0 update (from node0 to node1)
			const { msg: u0 } = buildChannelUpdate(
				rawKeys[0].privateKey,
				scid,
				1700000000,
				0,
				{
					feeBaseMsat: 1000,
					feeProportionalMillionths: 1,
					htlcMinimumMsat: 100n,
					htlcMaximumMsat: 10_000_000_000n
				}
			);
			graph.applyChannelUpdate(u0);

			// Route 0->1 should work (uses update from direction 0 = node0's policy)
			const route01 = findRoute(
				graph,
				rawKeys[0].publicKey,
				rawKeys[1].publicKey,
				100_000n,
				144
			);
			expect(route01).to.not.be.null;

			// Route 1->0 should fail (no update for direction 1)
			const route10 = findRoute(
				graph,
				rawKeys[1].publicKey,
				rawKeys[0].publicKey,
				100_000n,
				144
			);
			expect(route10).to.be.null;
		});
	});
});
