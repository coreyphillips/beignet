/**
 * Gossip intake liveness and pre-verification gates (issue #437).
 *
 * A peer re-serving a full mainnet graph carries hundreds of thousands of
 * pure-JS signature verifications; handled inline on the message path they
 * pinned the event loop for the whole dump, starving every HTTP route, ping
 * and signal handler, and the resulting pong timeouts made peers reconnect
 * and restart the dump: a livelock observed in the field. Two defenses are
 * pinned here: the graph's pre-verification gates (a message that cannot
 * change the graph never pays for its signatures) and the bounded, yielding
 * intake queue (a dump costs throughput, never liveness).
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
	IChannelAnnouncementMessage,
	NetworkGraph,
	encodeChannelAnnouncementMessage,
	encodeChannelUpdateMessage,
	encodeNodeAnnouncementMessage,
	encodeShortChannelId,
	signChannelAnnouncement,
	signChannelUpdate,
	CHANNEL_FLAG_DIRECTION
} from '../../src/lightning/gossip';
import { makeSignedNodeAnnouncement } from './helpers/signed-gossip';
import { IChannelUpdateMessage } from '../../src/lightning/gossip/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { MessageType } from '../../src/lightning/message/types';
import { Network } from '../../src/lightning/invoice/types';
import { INodeConfig } from '../../src/lightning/node/types';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	DEFAULT_CHANNEL_CONFIG,
	REGTEST_CHAIN_HASH
} from '../../src/lightning/channel/types';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';

function makeKeypair(): { privateKey: Buffer; publicKey: Buffer } {
	let privKey: Buffer;
	do {
		privKey = crypto.randomBytes(32);
	} while (privKey[0] === 0);
	return { privateKey: privKey, publicKey: getPublicKey(privKey) };
}

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

/** A fully signed channel_announcement on the given chain. */
function buildAnnouncement(
	scidBlock: number,
	chainHash: Buffer
): {
	msg: IChannelAnnouncementMessage;
	payload: Buffer;
	key1: { privateKey: Buffer; publicKey: Buffer };
	key2: { privateKey: Buffer; publicKey: Buffer };
} {
	const { key1, key2 } = makeOrderedKeypairs();
	const btc1 = makeKeypair();
	const btc2 = makeKeypair();
	const placeholder: IChannelAnnouncementMessage = {
		nodeSignature1: Buffer.alloc(64),
		nodeSignature2: Buffer.alloc(64),
		bitcoinSignature1: Buffer.alloc(64),
		bitcoinSignature2: Buffer.alloc(64),
		features: Buffer.alloc(0),
		chainHash,
		shortChannelId: encodeShortChannelId({
			block: scidBlock,
			txIndex: 1,
			outputIndex: 0
		}),
		nodeId1: key1.publicKey,
		nodeId2: key2.publicKey,
		bitcoinKey1: btc1.publicKey,
		bitcoinKey2: btc2.publicKey
	};
	const placeholderPayload = encodeChannelAnnouncementMessage(placeholder);
	const sig1 = signChannelAnnouncement(
		placeholderPayload,
		key1.privateKey,
		btc1.privateKey
	);
	const sig2 = signChannelAnnouncement(
		placeholderPayload,
		key2.privateKey,
		btc2.privateKey
	);
	const msg = {
		...placeholder,
		nodeSignature1: sig1.nodeSignature,
		nodeSignature2: sig2.nodeSignature,
		bitcoinSignature1: sig1.bitcoinSignature,
		bitcoinSignature2: sig2.bitcoinSignature
	};
	return { msg, payload: encodeChannelAnnouncementMessage(msg), key1, key2 };
}

/** A signed channel_update for one direction of an announced channel. */
function buildUpdate(
	ann: ReturnType<typeof buildAnnouncement>,
	timestamp: number,
	direction: 0 | 1,
	chainHash: Buffer
): { msg: IChannelUpdateMessage; payload: Buffer } {
	const signer = direction === 0 ? ann.key1 : ann.key2;
	const placeholder: IChannelUpdateMessage = {
		signature: Buffer.alloc(64),
		chainHash,
		shortChannelId: ann.msg.shortChannelId,
		timestamp,
		messageFlags: 1,
		channelFlags: direction,
		cltvExpiryDelta: 40,
		htlcMinimumMsat: 1000n,
		feeBaseMsat: 1000,
		feeProportionalMillionths: 100,
		htlcMaximumMsat: 100_000_000n
	};
	const placeholderPayload = encodeChannelUpdateMessage(placeholder);
	const signature = signChannelUpdate(placeholderPayload, signer.privateKey);
	const msg = { ...placeholder, signature };
	return { msg, payload: encodeChannelUpdateMessage(msg) };
}

describe('Gossip pre-verification gates (NetworkGraph)', () => {
	it('gate false always implies apply refuses, even claiming verified', () => {
		const graph = new NetworkGraph(REGTEST_CHAIN_HASH);
		const ann = buildAnnouncement(100, REGTEST_CHAIN_HASH);

		// Unknown channel: update gate refuses, apply refuses.
		const early = buildUpdate(ann, 1000, 0, REGTEST_CHAIN_HASH);
		expect(graph.wouldAcceptChannelUpdate(early.msg)).to.equal(false);
		expect(graph.applyChannelUpdate(early.msg, { verified: true })).to.equal(
			false
		);

		// Fresh announcement passes the gate, then lands verified.
		expect(graph.wouldAcceptChannelAnnouncement(ann.msg)).to.equal(true);
		expect(graph.addChannelAnnouncement(ann.msg, { verified: true })).to.equal(
			true
		);

		// Re-served verified announcement: gate false, apply false.
		expect(graph.wouldAcceptChannelAnnouncement(ann.msg)).to.equal(false);
		expect(graph.addChannelAnnouncement(ann.msg, { verified: true })).to.equal(
			false
		);

		// Verified update, then a stale re-send: gate false, apply false.
		const update = buildUpdate(ann, 2000, 0, REGTEST_CHAIN_HASH);
		expect(graph.wouldAcceptChannelUpdate(update.msg)).to.equal(true);
		expect(graph.applyChannelUpdate(update.msg, { verified: true })).to.equal(
			true
		);
		const stale = buildUpdate(ann, 2000, 0, REGTEST_CHAIN_HASH);
		expect(graph.wouldAcceptChannelUpdate(stale.msg)).to.equal(false);
		expect(graph.applyChannelUpdate(stale.msg, { verified: true })).to.equal(
			false
		);
	});

	it('an unverified (RGS-primed) entry keeps its upgrade path open', () => {
		const graph = new NetworkGraph(REGTEST_CHAIN_HASH);
		const ann = buildAnnouncement(101, REGTEST_CHAIN_HASH);
		expect(graph.addChannelAnnouncement(ann.msg, { verified: false })).to.equal(
			true
		);
		// The gate must NOT shortcut the unverified-to-verified upgrade.
		expect(graph.wouldAcceptChannelAnnouncement(ann.msg)).to.equal(true);
		expect(graph.addChannelAnnouncement(ann.msg, { verified: true })).to.equal(
			true
		);
		// Same for a stale update sitting in an unverified slot.
		const rgsUpdate = buildUpdate(ann, 5000, 1, REGTEST_CHAIN_HASH);
		expect(
			graph.applyChannelUpdate(rgsUpdate.msg, { verified: false })
		).to.equal(true);
		const signedNotNewer = buildUpdate(ann, 5000, 1, REGTEST_CHAIN_HASH);
		expect(graph.wouldAcceptChannelUpdate(signedNotNewer.msg)).to.equal(true);
	});

	it('wrong chain and disordered node ids never reach verification', () => {
		const graph = new NetworkGraph(REGTEST_CHAIN_HASH);
		const wrongChain = buildAnnouncement(102, Buffer.alloc(32, 7));
		expect(graph.wouldAcceptChannelAnnouncement(wrongChain.msg)).to.equal(
			false
		);
		const ann = buildAnnouncement(103, REGTEST_CHAIN_HASH);
		const disordered = {
			...ann.msg,
			nodeId1: ann.msg.nodeId2,
			nodeId2: ann.msg.nodeId1
		};
		expect(graph.wouldAcceptChannelAnnouncement(disordered)).to.equal(false);
	});
});

describe('Gossip intake queue (LightningNode)', () => {
	let storage: SqliteStorage;
	let dbPath: string;
	let node: LightningNode;

	function makeConfig(eagerGossipVerify = false): INodeConfig {
		const seed = crypto.randomBytes(32);
		const keys: Buffer[] = [];
		for (let i = 0; i < 5; i++) {
			keys.push(
				crypto
					.createHash('sha256')
					.update(seed)
					.update(Buffer.from([i]))
					.digest()
			);
		}
		return {
			nodePrivateKey: crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from('node-identity'))
				.digest(),
			network: Network.REGTEST as Network,
			channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
			channelBasepoints: {
				fundingPubkey: getPublicKey(keys[0]),
				revocationBasepoint: getPublicKey(keys[1]),
				paymentBasepoint: getPublicKey(keys[2]),
				delayedPaymentBasepoint: getPublicKey(keys[3]),
				htlcBasepoint: getPublicKey(keys[4]),
				firstPerCommitmentPoint: Buffer.alloc(33)
			},
			perCommitmentSeed: crypto.randomBytes(32),
			fundingPrivkey: keys[0],
			storage,
			enableNetworking: false,
			eagerGossipVerify
		};
	}

	beforeEach(() => {
		dbPath = path.join(
			os.tmpdir(),
			`beignet-test-gossip-intake-${Date.now()}-${Math.random()
				.toString(36)
				.slice(2)}.db`
		);
		storage = new SqliteStorage(dbPath);
		storage.open();
		node = new LightningNode(makeConfig());
	});

	afterEach(() => {
		node.destroy();
		storage.close();
		try {
			fs.unlinkSync(dbPath);
		} catch {
			/* ignore */
		}
	});

	const feed = (type: number, payload: Buffer): void => {
		(
			node as unknown as {
				handleGossipMessage(p: string, t: number, b: Buffer): void;
			}
		).handleGossipMessage('aa'.repeat(33), type, payload);
	};
	const graphOf = (n: LightningNode): NetworkGraph =>
		(n as unknown as { graph: NetworkGraph }).graph;

	it('broadcast gossip is queued, not applied inline, and lands on flush', async () => {
		const ann = buildAnnouncement(200, REGTEST_CHAIN_HASH);
		feed(MessageType.CHANNEL_ANNOUNCEMENT, ann.payload);
		expect(graphOf(node).getChannelCount()).to.equal(0);
		await node.flushGossip();
		expect(graphOf(node).getChannelCount()).to.equal(1);
	});

	it('an update queued behind its announcement applies in order', async () => {
		const ann = buildAnnouncement(201, REGTEST_CHAIN_HASH);
		const update = buildUpdate(ann, 9999, 0, REGTEST_CHAIN_HASH);
		feed(MessageType.CHANNEL_ANNOUNCEMENT, ann.payload);
		feed(MessageType.CHANNEL_UPDATE, update.payload);
		await node.flushGossip();
		const ch = graphOf(node).getChannel(ann.msg.shortChannelId);
		expect(ch).to.not.equal(undefined);
		expect(ch!.update1?.timestamp).to.equal(9999);
		expect((ch!.update1!.channelFlags & CHANNEL_FLAG_DIRECTION) === 0).to.equal(
			true
		);
	});

	it('a re-served dump changes nothing and costs no reprocessing', async () => {
		const ann = buildAnnouncement(202, REGTEST_CHAIN_HASH);
		feed(MessageType.CHANNEL_ANNOUNCEMENT, ann.payload);
		await node.flushGossip();
		feed(MessageType.CHANNEL_ANNOUNCEMENT, ann.payload);
		feed(MessageType.CHANNEL_ANNOUNCEMENT, ann.payload);
		await node.flushGossip();
		expect(graphOf(node).getChannelCount()).to.equal(1);
	});

	it('the intake is bounded: a flood beyond the cap is dropped, not stored', async () => {
		const statics = LightningNode as unknown as { GOSSIP_INTAKE_MAX: number };
		const saved = statics.GOSSIP_INTAKE_MAX;
		statics.GOSSIP_INTAKE_MAX = 3;
		try {
			for (let i = 0; i < 6; i++) {
				const ann = buildAnnouncement(300 + i, REGTEST_CHAIN_HASH);
				feed(MessageType.CHANNEL_ANNOUNCEMENT, ann.payload);
			}
			await node.flushGossip();
			// The first slice may begin draining before the flood ends, so the
			// floor is the cap and the ceiling is cap plus one drained slice's
			// worth; what must never happen is all six being stored.
			expect(graphOf(node).getChannelCount()).to.be.at.least(3);
			expect(graphOf(node).getChannelCount()).to.be.below(6);
		} finally {
			statics.GOSSIP_INTAKE_MAX = saved;
		}
	});

	it('the event loop keeps ticking while a dump drains', async () => {
		// The tick floor below only exists when intake verifies (issue #437's
		// contract); the lazy default admits a 40-message dump in one slice.
		// destroy() closes the storage handle, so build a fresh one.
		node.destroy();
		storage = new SqliteStorage(dbPath);
		storage.open();
		node = new LightningNode(makeConfig(true));
		for (let i = 0; i < 40; i++) {
			const ann = buildAnnouncement(400 + i, REGTEST_CHAIN_HASH);
			feed(MessageType.CHANNEL_ANNOUNCEMENT, ann.payload);
		}
		let ticks = 0;
		let counting = true;
		const tick = (): void => {
			if (!counting) return;
			ticks++;
			setImmediate(tick);
		};
		setImmediate(tick);
		await node.flushGossip();
		counting = false;
		expect(graphOf(node).getChannelCount()).to.equal(40);
		// 160 pure-JS signature verifications cannot have run in one slice;
		// the loop must have turned between slices.
		expect(ticks).to.be.at.least(5);
	});

	it('lazy intake (default) admits a dump as deferred without paying for signatures', async () => {
		const ann = buildAnnouncement(500, REGTEST_CHAIN_HASH);
		const update = buildUpdate(ann, 1000, 0, REGTEST_CHAIN_HASH);
		feed(MessageType.CHANNEL_ANNOUNCEMENT, ann.payload);
		feed(MessageType.CHANNEL_UPDATE, update.payload);
		await node.flushGossip();
		const ch = graphOf(node).getChannel(ann.msg.shortChannelId)!;
		expect(ch.announcementVerified).to.equal(undefined);
		expect(ch.announcementVerifyDeferred).to.equal(true);
		expect(ch.update1VerifyDeferred).to.equal(true);
	});

	it('lazy intake admits a garbage-signature announcement as deferred; eager drops it', async () => {
		const ann = buildAnnouncement(501, REGTEST_CHAIN_HASH);
		const garbage = {
			...ann.msg,
			nodeSignature1: crypto.randomBytes(64)
		};
		const garbagePayload = encodeChannelAnnouncementMessage(garbage);
		feed(MessageType.CHANNEL_ANNOUNCEMENT, garbagePayload);
		await node.flushGossip();
		expect(
			graphOf(node).getChannel(ann.msg.shortChannelId)!
				.announcementVerifyDeferred
		).to.equal(true);

		node.destroy();
		storage = new SqliteStorage(dbPath);
		storage.open();
		node = new LightningNode(makeConfig(true));
		feed(MessageType.CHANNEL_ANNOUNCEMENT, garbagePayload);
		await node.flushGossip();
		expect(graphOf(node).getChannel(ann.msg.shortChannelId)).to.equal(
			undefined
		);
	});

	it('a re-served dump in lazy mode causes no graph change and no storage writes', async () => {
		const ann = buildAnnouncement(502, REGTEST_CHAIN_HASH);
		const update = buildUpdate(ann, 1000, 0, REGTEST_CHAIN_HASH);
		feed(MessageType.CHANNEL_ANNOUNCEMENT, ann.payload);
		feed(MessageType.CHANNEL_UPDATE, update.payload);
		await node.flushGossip();

		// A deferred slot holding real signatures must refuse its own re-serve
		// at apply, or every re-served dump would rewrite the whole gossip
		// table (the #437 failure class relocated to disk).
		let writes = 0;
		const original = storage.saveGossipChannel.bind(storage);
		storage.saveGossipChannel = (scidHex, channel): void => {
			writes++;
			original(scidHex, channel);
		};
		feed(MessageType.CHANNEL_ANNOUNCEMENT, ann.payload);
		feed(MessageType.CHANNEL_UPDATE, update.payload);
		await node.flushGossip();
		expect(writes).to.equal(0);
		const ch = graphOf(node).getChannel(ann.msg.shortChannelId)!;
		expect(ch.announcementVerifyDeferred).to.equal(true);
		expect(ch.update1?.timestamp).to.equal(1000);
	});

	it('our-channel updates keep eager verification in lazy mode', async () => {
		const ann = buildAnnouncement(600, REGTEST_CHAIN_HASH);
		feed(MessageType.CHANNEL_ANNOUNCEMENT, ann.payload);
		await node.flushGossip();
		// Pretend the SCID names one of our channels: this is the synchronous
		// intake fork whose graph slot backs invoice route hints.
		(
			node as unknown as {
				channelUpdateTargetsOurChannel(m: unknown): boolean;
			}
		).channelUpdateTargetsOurChannel = () => true;

		const update = buildUpdate(ann, 1000, 0, REGTEST_CHAIN_HASH);
		feed(MessageType.CHANNEL_UPDATE, update.payload);
		const ch = graphOf(node).getChannel(ann.msg.shortChannelId)!;
		// Verified at intake: a boolean, never 'deferred'.
		expect(ch.update1Verified).to.be.true;

		// A garbage signature is dropped outright, not admitted deferred.
		const garbage = {
			...buildUpdate(ann, 2000, 0, REGTEST_CHAIN_HASH).msg,
			signature: crypto.randomBytes(64)
		};
		feed(MessageType.CHANNEL_UPDATE, encodeChannelUpdateMessage(garbage));
		expect(ch.update1?.timestamp).to.equal(1000);
		expect(ch.update1Verified).to.be.true;
	});

	it('capture-worthy node announcements keep eager verification in lazy mode', async () => {
		const ann = buildAnnouncement(601, REGTEST_CHAIN_HASH);
		feed(MessageType.CHANNEL_ANNOUNCEMENT, ann.payload);
		await node.flushGossip();

		// Baseline: a crowd node announcement is admitted deferred.
		const first = makeSignedNodeAnnouncement(ann.key1.privateKey, 1000);
		feed(MessageType.NODE_ANNOUNCEMENT, first.payload);
		await node.flushGossip();
		expect(
			graphOf(node).getNode(first.msg.nodeId)!.announcementVerifyDeferred
		).to.equal(true);

		// A capture-worthy one (reconnect-address source for a channel peer)
		// verifies at intake even in lazy mode: addresses must never be
		// captured from an unproven claim.
		(
			node as unknown as {
				nodeAnnouncementCaptureWorthwhile(m: unknown): boolean;
			}
		).nodeAnnouncementCaptureWorthwhile = () => true;
		const second = makeSignedNodeAnnouncement(ann.key1.privateKey, 2000);
		feed(MessageType.NODE_ANNOUNCEMENT, second.payload);
		await node.flushGossip();
		const stored = graphOf(node).getNode(second.msg.nodeId)!;
		expect(stored.announcementVerified).to.be.true;

		// And a garbage signature is dropped outright, never admitted.
		const garbage = {
			...makeSignedNodeAnnouncement(ann.key1.privateKey, 3000).msg,
			signature: crypto.randomBytes(64)
		};
		feed(MessageType.NODE_ANNOUNCEMENT, encodeNodeAnnouncementMessage(garbage));
		await node.flushGossip();
		expect(stored.announcement!.timestamp).to.equal(2000);
		expect(stored.announcementVerified).to.be.true;
	});
});
