/**
 * Gossip intake liveness, pre-verification gates and admission hardening
 * (issues #437, #446).
 *
 * A peer re-serving a full mainnet graph carries hundreds of thousands of
 * pure-JS signature verifications; handled inline on the message path they
 * pinned the event loop for the whole dump, starving every HTTP route, ping
 * and signal handler, and the resulting pong timeouts made peers reconnect
 * and restart the dump: a livelock observed in the field. Two defenses are
 * pinned here: the graph's pre-verification gates (a message that cannot
 * change the graph never pays for its signatures) and the bounded, yielding
 * intake queue (a dump costs throughput, never liveness).
 *
 * Lazy verification (issue #443) then made admission itself nearly free, so
 * two admission bounds are pinned here as well (issue #446): far-future
 * timestamps are refused before they can camp a slot against the
 * strictly-newer freshness rule, and the graph holds a hard channel ceiling
 * under which verified admissions evict unverified entries but garbage
 * displaces nothing.
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
import {
	IChannelUpdateMessage,
	IGraphChannel,
	DEFAULT_PRUNE_MAX_AGE,
	MAX_GOSSIP_TIMESTAMP_SKEW
} from '../../src/lightning/gossip/types';
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

describe('Gossip far-future timestamps (NetworkGraph, issue #446)', () => {
	const FAR_FUTURE = 4294967295; // max u32, the cheapest permanent camp

	it('a far-future channel_update is refused whatever its provenance', () => {
		const graph = new NetworkGraph(REGTEST_CHAIN_HASH);
		const ann = buildAnnouncement(700, REGTEST_CHAIN_HASH);
		expect(graph.addChannelAnnouncement(ann.msg, { verified: true })).to.equal(
			true
		);

		const camped = buildUpdate(ann, FAR_FUTURE, 0, REGTEST_CHAIN_HASH);
		expect(graph.wouldAcceptChannelUpdate(camped.msg)).to.equal(false);
		expect(graph.applyChannelUpdate(camped.msg, { verified: true })).to.equal(
			false
		);
		expect(graph.getChannel(ann.msg.shortChannelId)!.update1).to.equal(
			undefined
		);

		// The slot stays open: a legitimate update is not camped out.
		const real = buildUpdate(ann, 1000, 0, REGTEST_CHAIN_HASH);
		expect(graph.wouldAcceptChannelUpdate(real.msg)).to.equal(true);
		expect(graph.applyChannelUpdate(real.msg, { verified: true })).to.equal(
			true
		);
		expect(
			graph.getChannel(ann.msg.shortChannelId)!.update1?.timestamp
		).to.equal(1000);
	});

	it('a far-future node_announcement is refused whatever its provenance', () => {
		const graph = new NetworkGraph(REGTEST_CHAIN_HASH);
		const ann = buildAnnouncement(701, REGTEST_CHAIN_HASH);
		expect(graph.addChannelAnnouncement(ann.msg, { verified: true })).to.equal(
			true
		);

		const camped = makeSignedNodeAnnouncement(ann.key1.privateKey, FAR_FUTURE);
		expect(graph.wouldAcceptNodeAnnouncement(camped.msg)).to.equal(false);
		expect(
			graph.applyNodeAnnouncement(camped.msg, { verified: true })
		).to.equal(false);
		expect(graph.getNode(camped.msg.nodeId)!.announcement).to.equal(undefined);

		const real = makeSignedNodeAnnouncement(ann.key1.privateKey, 1000);
		expect(graph.wouldAcceptNodeAnnouncement(real.msg)).to.equal(true);
		expect(graph.applyNodeAnnouncement(real.msg, { verified: true })).to.equal(
			true
		);
	});

	it('ordinary clock skew stays admissible; beyond the bound is not', () => {
		const graph = new NetworkGraph(REGTEST_CHAIN_HASH);
		const ann = buildAnnouncement(702, REGTEST_CHAIN_HASH);
		expect(graph.addChannelAnnouncement(ann.msg, { verified: true })).to.equal(
			true
		);

		const now = Math.floor(Date.now() / 1000);
		const skewed = buildUpdate(ann, now + 60, 0, REGTEST_CHAIN_HASH);
		expect(graph.wouldAcceptChannelUpdate(skewed.msg)).to.equal(true);
		expect(graph.applyChannelUpdate(skewed.msg, { verified: true })).to.equal(
			true
		);

		const beyond = buildUpdate(
			ann,
			now + MAX_GOSSIP_TIMESTAMP_SKEW + 86_400,
			1,
			REGTEST_CHAIN_HASH
		);
		expect(graph.wouldAcceptChannelUpdate(beyond.msg)).to.equal(false);
		expect(graph.applyChannelUpdate(beyond.msg, { verified: true })).to.equal(
			false
		);
	});

	it('a poisoned pre-bound row is repaired at the restore boundary', () => {
		// A max-u32 update persisted BEFORE the bound existed restores with
		// verified flags, so no takeover can displace it and pruning (keyed
		// off the same timestamp) never reclaims it. The restore boundary
		// must drop the slot or upgrading cannot repair a poisoned database.
		const graph = new NetworkGraph(REGTEST_CHAIN_HASH);
		const ann = buildAnnouncement(703, REGTEST_CHAIN_HASH);
		const poison = buildUpdate(ann, FAR_FUTURE, 0, REGTEST_CHAIN_HASH);
		graph.restoreChannel({
			shortChannelId: ann.msg.shortChannelId,
			nodeId1: ann.msg.nodeId1,
			nodeId2: ann.msg.nodeId2,
			features: Buffer.alloc(0),
			announcement: ann.msg,
			announcementVerified: true,
			update1: poison.msg,
			update1Verified: true
		});
		const ch = graph.getChannel(ann.msg.shortChannelId)!;
		expect(ch.update1).to.equal(undefined);
		expect(ch.update1Verified).to.equal(undefined);

		// The freed slot takes the next real update instead of refusing it.
		const real = buildUpdate(ann, 1000, 0, REGTEST_CHAIN_HASH);
		expect(graph.applyChannelUpdate(real.msg, { verified: true })).to.equal(
			true
		);
		expect(ch.update1?.timestamp).to.equal(1000);

		// Same repair for a poisoned node announcement row.
		const poisonAnn = makeSignedNodeAnnouncement(
			ann.key1.privateKey,
			FAR_FUTURE
		);
		graph.restoreNode({
			nodeId: poisonAnn.msg.nodeId,
			announcement: poisonAnn.msg,
			announcementVerified: true,
			channels: new Set([ann.msg.shortChannelId.toString('hex')])
		});
		expect(graph.getNode(poisonAnn.msg.nodeId)!.announcement).to.equal(
			undefined
		);
		const realAnn = makeSignedNodeAnnouncement(ann.key1.privateKey, 1000);
		expect(
			graph.applyNodeAnnouncement(realAnn.msg, { verified: true })
		).to.equal(true);
	});
});

describe('Gossip channel ceiling (NetworkGraph, issue #446)', () => {
	const savedCap = NetworkGraph.MAX_CHANNELS;
	afterEach(() => {
		NetworkGraph.MAX_CHANNELS = savedCap;
	});

	/** An IGraphChannel row as a storage backend would hand to restoreChannel. */
	const makeRow = (
		ann: ReturnType<typeof buildAnnouncement>,
		extra: Partial<IGraphChannel> = {}
	): IGraphChannel => ({
		shortChannelId: ann.msg.shortChannelId,
		nodeId1: ann.msg.nodeId1,
		nodeId2: ann.msg.nodeId2,
		features: Buffer.alloc(0),
		announcement: ann.msg,
		...extra
	});

	it('at the ceiling, unverified admissions are refused and displace nothing', () => {
		NetworkGraph.MAX_CHANNELS = 2;
		const evicted: string[] = [];
		const graph = new NetworkGraph(REGTEST_CHAIN_HASH, {
			onChannelEvicted: (scidHex): void => {
				evicted.push(scidHex);
			}
		});
		const ann1 = buildAnnouncement(710, REGTEST_CHAIN_HASH);
		const ann2 = buildAnnouncement(711, REGTEST_CHAIN_HASH);
		const ann3 = buildAnnouncement(712, REGTEST_CHAIN_HASH);
		expect(
			graph.addChannelAnnouncement(ann1.msg, { verified: 'deferred' })
		).to.equal(true);
		expect(
			graph.addChannelAnnouncement(ann2.msg, { verified: 'deferred' })
		).to.equal(true);
		expect(
			graph.addChannelAnnouncement(ann3.msg, { verified: 'deferred' })
		).to.equal(false);
		expect(
			graph.addChannelAnnouncement(ann3.msg, { verified: false })
		).to.equal(false);
		expect(graph.getChannelCount()).to.equal(2);
		expect(evicted).to.deep.equal([]);
	});

	it('at the ceiling, a verified admission evicts the oldest unverified entry', () => {
		NetworkGraph.MAX_CHANNELS = 2;
		const evicted: string[] = [];
		const graph = new NetworkGraph(REGTEST_CHAIN_HASH, {
			onChannelEvicted: (scidHex): void => {
				evicted.push(scidHex);
			}
		});
		const ann1 = buildAnnouncement(713, REGTEST_CHAIN_HASH);
		const ann2 = buildAnnouncement(714, REGTEST_CHAIN_HASH);
		const ann3 = buildAnnouncement(715, REGTEST_CHAIN_HASH);
		graph.addChannelAnnouncement(ann1.msg, { verified: 'deferred' });
		graph.addChannelAnnouncement(ann2.msg, { verified: 'deferred' });
		expect(graph.addChannelAnnouncement(ann3.msg, { verified: true })).to.equal(
			true
		);
		expect(graph.getChannelCount()).to.equal(2);
		expect(graph.getChannel(ann1.msg.shortChannelId)).to.equal(undefined);
		expect(graph.getChannel(ann3.msg.shortChannelId)).to.not.equal(undefined);
		expect(evicted).to.deep.equal([ann1.msg.shortChannelId.toString('hex')]);
	});

	it('a full graph of verified entries refuses even verified admissions', () => {
		NetworkGraph.MAX_CHANNELS = 2;
		const evicted: string[] = [];
		const graph = new NetworkGraph(REGTEST_CHAIN_HASH, {
			onChannelEvicted: (scidHex): void => {
				evicted.push(scidHex);
			}
		});
		const ann1 = buildAnnouncement(716, REGTEST_CHAIN_HASH);
		const ann2 = buildAnnouncement(717, REGTEST_CHAIN_HASH);
		const ann3 = buildAnnouncement(718, REGTEST_CHAIN_HASH);
		graph.addChannelAnnouncement(ann1.msg, { verified: true });
		graph.addChannelAnnouncement(ann2.msg, { verified: true });
		expect(graph.wouldAcceptChannelAnnouncement(ann3.msg)).to.equal(false);
		expect(graph.addChannelAnnouncement(ann3.msg, { verified: true })).to.equal(
			false
		);
		expect(graph.getChannelCount()).to.equal(2);
		expect(evicted).to.deep.equal([]);
	});

	it('an in-place upgrade at the ceiling is not growth and evicts nothing', () => {
		NetworkGraph.MAX_CHANNELS = 2;
		const evicted: string[] = [];
		const graph = new NetworkGraph(REGTEST_CHAIN_HASH, {
			onChannelEvicted: (scidHex): void => {
				evicted.push(scidHex);
			}
		});
		const ann1 = buildAnnouncement(719, REGTEST_CHAIN_HASH);
		const ann2 = buildAnnouncement(720, REGTEST_CHAIN_HASH);
		graph.addChannelAnnouncement(ann1.msg, { verified: 'deferred' });
		graph.addChannelAnnouncement(ann2.msg, { verified: 'deferred' });
		expect(graph.addChannelAnnouncement(ann1.msg, { verified: true })).to.equal(
			true
		);
		expect(graph.getChannelCount()).to.equal(2);
		expect(evicted).to.deep.equal([]);
		expect(
			graph.getChannel(ann1.msg.shortChannelId)!.announcementVerified
		).to.equal(true);

		// The upgraded entry left the evictable pool: a verified admission at
		// the ceiling now takes the remaining deferred one.
		const ann3 = buildAnnouncement(721, REGTEST_CHAIN_HASH);
		expect(graph.addChannelAnnouncement(ann3.msg, { verified: true })).to.equal(
			true
		);
		expect(evicted).to.deep.equal([ann2.msg.shortChannelId.toString('hex')]);
	});

	it('serve-time resolution moves an entry out of the evictable pool', () => {
		NetworkGraph.MAX_CHANNELS = 1;
		const evicted: string[] = [];
		const graph = new NetworkGraph(REGTEST_CHAIN_HASH, {
			onChannelEvicted: (scidHex): void => {
				evicted.push(scidHex);
			}
		});
		const ann1 = buildAnnouncement(722, REGTEST_CHAIN_HASH);
		expect(
			graph.addChannelAnnouncement(ann1.msg, { verified: 'deferred' })
		).to.equal(true);

		// A gossip query resolves the deferred announcement (real signatures,
		// so it settles verified) and the eviction index must follow.
		const served = graph.getGossipMessagesForChannels([
			ann1.msg.shortChannelId
		]);
		expect(served.announcements).to.have.length(1);
		expect(
			graph.getChannel(ann1.msg.shortChannelId)!.announcementVerified
		).to.equal(true);

		const ann2 = buildAnnouncement(723, REGTEST_CHAIN_HASH);
		expect(graph.addChannelAnnouncement(ann2.msg, { verified: true })).to.equal(
			false
		);
		expect(graph.getChannel(ann1.msg.shortChannelId)).to.not.equal(undefined);
		expect(evicted).to.deep.equal([]);
	});

	it('restoreChannel enforces the ceiling with the same preference', () => {
		NetworkGraph.MAX_CHANNELS = 1;
		const evicted: string[] = [];
		const graph = new NetworkGraph(REGTEST_CHAIN_HASH, {
			onChannelEvicted: (scidHex): void => {
				evicted.push(scidHex);
			}
		});
		const ann1 = buildAnnouncement(724, REGTEST_CHAIN_HASH);
		const ann2 = buildAnnouncement(725, REGTEST_CHAIN_HASH);
		const ann3 = buildAnnouncement(726, REGTEST_CHAIN_HASH);
		const ann4 = buildAnnouncement(727, REGTEST_CHAIN_HASH);

		// An unverified row under the ceiling restores normally.
		graph.restoreChannel(makeRow(ann1));
		expect(graph.getChannelCount()).to.equal(1);

		// An unverified row at the ceiling is dropped AND reported, so the
		// poisoned store shrinks instead of re-inflating every boot.
		graph.restoreChannel(makeRow(ann2));
		expect(graph.getChannelCount()).to.equal(1);
		expect(graph.getChannel(ann2.msg.shortChannelId)).to.equal(undefined);
		expect(evicted).to.deep.equal([ann2.msg.shortChannelId.toString('hex')]);

		// A verified row at the ceiling evicts an unverified in-graph entry.
		graph.restoreChannel(makeRow(ann3, { announcementVerified: true }));
		expect(graph.getChannelCount()).to.equal(1);
		expect(graph.getChannel(ann3.msg.shortChannelId)).to.not.equal(undefined);
		expect(evicted).to.deep.equal([
			ann2.msg.shortChannelId.toString('hex'),
			ann1.msg.shortChannelId.toString('hex')
		]);

		// A verified row against a ceiling full of verified entries is skipped
		// WITHOUT the report: provably-signed data stays on disk.
		graph.restoreChannel(makeRow(ann4, { announcementVerified: true }));
		expect(graph.getChannelCount()).to.equal(1);
		expect(graph.getChannel(ann4.msg.shortChannelId)).to.equal(undefined);
		expect(evicted).to.have.length(2);
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

	it('far-future gossip dies at the gate: no graph change, no storage write', async () => {
		const ann = buildAnnouncement(800, REGTEST_CHAIN_HASH);
		feed(MessageType.CHANNEL_ANNOUNCEMENT, ann.payload);
		await node.flushGossip();

		let writes = 0;
		const original = storage.saveGossipChannel.bind(storage);
		storage.saveGossipChannel = (scidHex, channel): void => {
			writes++;
			original(scidHex, channel);
		};
		const camped = buildUpdate(ann, 4294967295, 0, REGTEST_CHAIN_HASH);
		feed(MessageType.CHANNEL_UPDATE, camped.payload);
		await node.flushGossip();
		const ch = graphOf(node).getChannel(ann.msg.shortChannelId)!;
		expect(ch.update1).to.equal(undefined);
		expect(writes).to.equal(0);

		// The slot it tried to camp still takes the legitimate update.
		const real = buildUpdate(ann, 1000, 0, REGTEST_CHAIN_HASH);
		feed(MessageType.CHANNEL_UPDATE, real.payload);
		await node.flushGossip();
		expect(ch.update1?.timestamp).to.equal(1000);
		expect(writes).to.equal(1);
	});

	it('a poisoned store is trimmed to the ceiling on restore, preferring verified rows', async () => {
		// Rows land in storage before the node boots; destroy() closed the
		// beforeEach handle, so reopen one.
		node.destroy();
		storage = new SqliteStorage(dbPath);
		storage.open();

		const recent = Math.floor(Date.now() / 1000) - 60;
		const annVer = buildAnnouncement(801, REGTEST_CHAIN_HASH);
		const upd = buildUpdate(annVer, recent, 0, REGTEST_CHAIN_HASH);
		const verifiedRow: IGraphChannel = {
			shortChannelId: annVer.msg.shortChannelId,
			nodeId1: annVer.msg.nodeId1,
			nodeId2: annVer.msg.nodeId2,
			features: Buffer.alloc(0),
			announcement: annVer.msg,
			announcementVerified: true,
			update1: upd.msg,
			update1Verified: true
		};
		storage.saveGossipChannel(
			annVer.msg.shortChannelId.toString('hex'),
			verifiedRow
		);
		for (const block of [802, 803]) {
			const ann = buildAnnouncement(block, REGTEST_CHAIN_HASH);
			const garbageUpd = buildUpdate(ann, recent, 0, REGTEST_CHAIN_HASH);
			storage.saveGossipChannel(ann.msg.shortChannelId.toString('hex'), {
				shortChannelId: ann.msg.shortChannelId,
				nodeId1: ann.msg.nodeId1,
				nodeId2: ann.msg.nodeId2,
				features: Buffer.alloc(0),
				announcement: ann.msg,
				update1: garbageUpd.msg
			});
		}
		expect(storage.loadAllGossipChannels()).to.have.length(3);

		const savedCap = NetworkGraph.MAX_CHANNELS;
		NetworkGraph.MAX_CHANNELS = 1;
		try {
			node = new LightningNode(makeConfig());
		} finally {
			NetworkGraph.MAX_CHANNELS = savedCap;
		}

		// Whatever order the rows restored in, the verified one holds the
		// single slot and the unverified rows are gone from disk too.
		expect(graphOf(node).getChannelCount()).to.equal(1);
		expect(graphOf(node).getChannel(annVer.msg.shortChannelId)).to.not.equal(
			undefined
		);
		expect(storage.loadAllGossipChannels()).to.have.length(1);
	});

	it('a stale verified row cannot displace a fresh deferred row at the restore ceiling', async () => {
		// Startup pruning would remove the stale row moments after restore, so
		// letting it win a ceiling slot first (evicting and DELETING the fresh
		// row it will not outlive) would leave the graph empty. The restore
		// filter must keep stale rows out of ceiling contention entirely.
		node.destroy();
		storage = new SqliteStorage(dbPath);
		storage.open();

		const now = Math.floor(Date.now() / 1000);
		const annStale = buildAnnouncement(810, REGTEST_CHAIN_HASH);
		const staleUpd = buildUpdate(
			annStale,
			now - DEFAULT_PRUNE_MAX_AGE - 3600,
			0,
			REGTEST_CHAIN_HASH
		);
		storage.saveGossipChannel(annStale.msg.shortChannelId.toString('hex'), {
			shortChannelId: annStale.msg.shortChannelId,
			nodeId1: annStale.msg.nodeId1,
			nodeId2: annStale.msg.nodeId2,
			features: Buffer.alloc(0),
			announcement: annStale.msg,
			announcementVerified: true,
			update1: staleUpd.msg,
			update1Verified: true
		});
		const annFresh = buildAnnouncement(811, REGTEST_CHAIN_HASH);
		const freshUpd = buildUpdate(annFresh, now - 60, 0, REGTEST_CHAIN_HASH);
		storage.saveGossipChannel(annFresh.msg.shortChannelId.toString('hex'), {
			shortChannelId: annFresh.msg.shortChannelId,
			nodeId1: annFresh.msg.nodeId1,
			nodeId2: annFresh.msg.nodeId2,
			features: Buffer.alloc(0),
			announcement: annFresh.msg,
			update1: freshUpd.msg
		});

		const savedCap = NetworkGraph.MAX_CHANNELS;
		NetworkGraph.MAX_CHANNELS = 1;
		try {
			node = new LightningNode(makeConfig());
		} finally {
			NetworkGraph.MAX_CHANNELS = savedCap;
		}

		expect(graphOf(node).getChannelCount()).to.equal(1);
		expect(graphOf(node).getChannel(annFresh.msg.shortChannelId)).to.not.equal(
			undefined
		);
		expect(storage.loadAllGossipChannels()).to.have.length(1);
	});

	it('a far-future update never reaches peer policy adoption', async () => {
		// The adoption path runs before the graph gate and keys its own
		// freshness off the update timestamp: adopted once, a max-u32 update
		// would pin our route-hint policy against every later real update.
		let adoptions = 0;
		(
			node as unknown as {
				maybeAdoptPeerChannelPolicy(m: unknown, p: unknown): void;
			}
		).maybeAdoptPeerChannelPolicy = (): void => {
			adoptions++;
		};
		const ann = buildAnnouncement(812, REGTEST_CHAIN_HASH);
		feed(MessageType.CHANNEL_ANNOUNCEMENT, ann.payload);
		await node.flushGossip();

		const camped = buildUpdate(ann, 4294967295, 0, REGTEST_CHAIN_HASH);
		feed(MessageType.CHANNEL_UPDATE, camped.payload);
		await node.flushGossip();
		expect(adoptions).to.equal(0);

		// Sanity: an in-range update does reach the adoption path.
		const real = buildUpdate(ann, 1000, 0, REGTEST_CHAIN_HASH);
		feed(MessageType.CHANNEL_UPDATE, real.payload);
		await node.flushGossip();
		expect(adoptions).to.equal(1);
	});

	it('a far-future node announcement never reaches address capture', async () => {
		// The capture path's private freshness map would otherwise let a
		// validly signed max-u32 announcement pin the peer's reconnect
		// fallback address against every later real announcement.
		const ann = buildAnnouncement(813, REGTEST_CHAIN_HASH);
		feed(MessageType.CHANNEL_ANNOUNCEMENT, ann.payload);
		await node.flushGossip();

		(
			node as unknown as {
				nodeAnnouncementCaptureWorthwhile(m: unknown): boolean;
			}
		).nodeAnnouncementCaptureWorthwhile = (): boolean => true;
		let captures = 0;
		(
			node as unknown as {
				captureChannelPeerAddresses(m: unknown): void;
			}
		).captureChannelPeerAddresses = (): void => {
			captures++;
		};

		const camped = makeSignedNodeAnnouncement(ann.key1.privateKey, 4294967295);
		feed(MessageType.NODE_ANNOUNCEMENT, camped.payload);
		await node.flushGossip();
		expect(captures).to.equal(0);
		expect(graphOf(node).getNode(camped.msg.nodeId)!.announcement).to.equal(
			undefined
		);

		// Sanity: an in-range verified announcement does reach capture.
		const real = makeSignedNodeAnnouncement(ann.key1.privateKey, 2000);
		feed(MessageType.NODE_ANNOUNCEMENT, real.payload);
		await node.flushGossip();
		expect(captures).to.equal(1);
	});
});
