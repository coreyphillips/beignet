/**
 * Forwarding history and fee accounting (M3).
 *
 * Covers the settled-forward ledger: a record written when a forwarded HTLC's
 * downstream fulfill settles both legs (fee arithmetic included), listForwards
 * filtering/ordering, summary totals, the retention cap, persistence across a
 * storage reopen, the schema migration, and the BeignetNode wrapper's
 * msat-as-string JSON mapping.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import {
	DEFAULT_CHANNEL_CONFIG,
	BITCOIN_CHAIN_HASH
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { encodeShortChannelId } from '../../src/lightning/gossip/types';
import { decode as decodeInvoice } from '../../src/lightning/invoice/decode';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { IForwardingEvent } from '../../src/lightning/storage/types';
import { BeignetNode } from '../../src/cli/beignet-node';

// ─────────────── Helpers (mirrors tests/lightning/channel-policy.test.ts) ───────────────

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`fwd-history-seed-${id}`))
		.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		const privkey = crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([i]))
			.digest();
		keys.push(privkey);
	}
	return {
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

function makeNodeConfig(seedId: number): INodeConfig {
	const seed = makeSeed(seedId);
	const nodePrivateKey = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from('node-identity'))
		.digest();
	const fundingPrivkey = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([0]))
		.digest();
	// Secret behind makeBasepoints' htlcBasepoint (keys[4]), needed for HTLC
	// second-level signatures during commitment_signed.
	const htlcBasepointSecret = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([4]))
		.digest();
	return {
		nodePrivateKey,
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey,
		htlcBasepointSecret
	};
}

function createNode(seedId: number, storage?: SqliteStorage): LightningNode {
	const config = storage
		? { ...makeNodeConfig(seedId), storage }
		: makeNodeConfig(seedId);
	const node = new LightningNode(config);
	node.on('node:error', () => {});
	return node;
}

function connectNodes(nodeA: LightningNode, nodeB: LightningNode): void {
	nodeA.on(
		'message:outbound',
		(pubkey: string, type: number, payload: Buffer) => {
			if (pubkey === nodeB.getNodeId()) {
				nodeB.handlePeerMessage(nodeA.getNodeId(), type, payload);
			}
		}
	);
	nodeB.on(
		'message:outbound',
		(pubkey: string, type: number, payload: Buffer) => {
			if (pubkey === nodeA.getNodeId()) {
				nodeA.handlePeerMessage(nodeB.getNodeId(), type, payload);
			}
		}
	);
}

function openReadyChannel(
	alice: LightningNode,
	bob: LightningNode,
	fundingSatoshis = 1_000_000n
): Buffer {
	const channel = alice.openChannel(bob.getNodeId(), fundingSatoshis);
	const fundingTxid = crypto.randomBytes(32);
	const channelId = alice.createFunding(
		channel,
		fundingTxid,
		0,
		crypto.randomBytes(64)
	)!;
	alice.handleFundingConfirmed(channelId);
	bob.handleFundingConfirmed(channelId);
	return channelId;
}

/** Add an announced channel + both-direction updates to a node's graph. */
function addGraphChannel(
	node: LightningNode,
	scid: Buffer,
	pubA: Buffer,
	pubB: Buffer
): void {
	const aIs1 = Buffer.compare(pubA, pubB) < 0;
	node.getGraph().addChannelAnnouncement({
		nodeSignature1: Buffer.alloc(64),
		nodeSignature2: Buffer.alloc(64),
		bitcoinSignature1: Buffer.alloc(64),
		bitcoinSignature2: Buffer.alloc(64),
		features: Buffer.alloc(0),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		nodeId1: aIs1 ? pubA : pubB,
		nodeId2: aIs1 ? pubB : pubA,
		bitcoinKey1: Buffer.alloc(33, 2),
		bitcoinKey2: Buffer.alloc(33, 3)
	});
	for (const dir of [0, 1]) {
		node.getGraph().applyChannelUpdate({
			signature: Buffer.alloc(64),
			chainHash: BITCOIN_CHAIN_HASH,
			shortChannelId: scid,
			timestamp: Math.floor(Date.now() / 1000),
			messageFlags: 1,
			channelFlags: dir,
			cltvExpiryDelta: 40,
			htlcMinimumMsat: 1000n,
			feeBaseMsat: 1000,
			feeProportionalMillionths: 1,
			htlcMaximumMsat: 1_000_000_000n
		});
	}
}

function nodePubkey(seedId: number): Buffer {
	return getPublicKey(makeNodeConfig(seedId).nodePrivateKey);
}

interface IForwardSetup {
	alice: LightningNode;
	bob: LightningNode;
	charlie: LightningNode;
	abChannelId: Buffer;
	bcChannelId: Buffer;
}

// Alice -> Bob -> Charlie with a known fee: Bob's policy is base 5000 / ppm 0,
// propagated to Charlie's invoice hint so the payer attaches the exact fee.
function setupForwarding(bobStorage?: SqliteStorage): IForwardSetup {
	const alice = createNode(1);
	const bob = createNode(2, bobStorage);
	const charlie = createNode(3);
	connectNodes(alice, bob);
	connectNodes(bob, charlie);

	const abChannelId = openReadyChannel(alice, bob, 1_000_000n);
	const bcChannelId = openReadyChannel(bob, charlie, 1_000_000n);

	const scidAB = encodeShortChannelId({
		block: 830,
		txIndex: 1,
		outputIndex: 0
	});
	const scidBC = encodeShortChannelId({
		block: 830,
		txIndex: 2,
		outputIndex: 0
	});
	bob.registerChannelScid(abChannelId, scidAB);
	bob.registerChannelScid(bcChannelId, scidBC);
	alice.registerChannelScid(abChannelId, scidAB);
	// SCID aliases on both BC sides so Bob's policy update reaches Charlie and
	// the invoice hint names the channel Bob forwards over. Both are
	// remoteScidAlias: BOLT 7 has Bob address his direct channel_update with an
	// alias RECEIVED from the peer, and BOLT 2 has Charlie's invoice hint name the
	// alias Bob generated. Bob resolves scidBC via the registerChannelScid above.
	bob
		.getChannelManager()
		.getChannel(bcChannelId)!
		.getFullState().remoteScidAlias = scidBC;
	charlie
		.getChannelManager()
		.getChannel(bcChannelId)!
		.getFullState().remoteScidAlias = scidBC;

	addGraphChannel(alice, scidAB, nodePubkey(1), nodePubkey(2));

	bob.setChannelPolicy(bcChannelId, {
		feeBaseMsat: 5000,
		feeProportionalMillionths: 0
	});

	return { alice, bob, charlie, abChannelId, bcChannelId };
}

function makeEvent(
	overrides: Partial<Omit<IForwardingEvent, 'id'>> = {}
): Omit<IForwardingEvent, 'id'> {
	return {
		settledAt: 1000,
		inChannelId: 'aa'.repeat(32),
		outChannelId: 'bb'.repeat(32),
		amountInMsat: 1_005_000n,
		amountOutMsat: 1_000_000n,
		feeMsat: 5000n,
		...overrides
	};
}

// ─────────────── Tests ───────────────

describe('Forwarding History (M3)', function () {
	describe('settled-forward recording (A -> B -> C)', function () {
		it('writes one ledger record with correct fee arithmetic when the forward settles', function () {
			const storage = new SqliteStorage(':memory:');
			storage.open();
			const { alice, bob, charlie, abChannelId, bcChannelId } =
				setupForwarding(storage);
			try {
				const before = Date.now();
				const invoice = charlie.createInvoice({
					amountMsat: 5_000_000n,
					description: 'fwd-ledger'
				});
				alice.sendPayment(invoice.bolt11);

				const decoded = decodeInvoice(invoice.bolt11);
				expect(charlie.getPayment(decoded.paymentHash)!.status).to.equal(
					'COMPLETED'
				);

				const forwards = bob.listForwards();
				expect(forwards).to.have.length(1);
				const fwd = forwards[0];
				expect(fwd.inChannelId).to.equal(abChannelId.toString('hex'));
				expect(fwd.outChannelId).to.equal(bcChannelId.toString('hex'));
				expect(Number(fwd.amountInMsat)).to.equal(5_005_000);
				expect(Number(fwd.amountOutMsat)).to.equal(5_000_000);
				expect(Number(fwd.feeMsat)).to.equal(5000);
				expect(fwd.settledAt).to.be.at.least(before);
				expect(fwd.settledAt).to.be.at.most(Date.now());

				const summary = bob.getForwardingSummary();
				expect(summary.count).to.equal(1);
				expect(Number(summary.volumeOutMsat)).to.equal(5_000_000);
				expect(Number(summary.feesEarnedMsat)).to.equal(5000);

				// Endpoints record nothing: only the forwarding node earns the entry
				expect(alice.listForwards()).to.have.length(0);
				expect(charlie.listForwards()).to.have.length(0);
			} finally {
				alice.destroy();
				bob.destroy();
				charlie.destroy();
			}
		});

		it('records one entry per settled forward across repeated payments', function () {
			const storage = new SqliteStorage(':memory:');
			storage.open();
			const { alice, bob, charlie } = setupForwarding(storage);
			try {
				for (let i = 0; i < 3; i++) {
					const invoice = charlie.createInvoice({
						amountMsat: 1_000_000n,
						description: `fwd-${i}`
					});
					alice.sendPayment(invoice.bolt11);
				}
				const forwards = bob.listForwards();
				expect(forwards).to.have.length(3);
				const summary = bob.getForwardingSummary();
				expect(summary.count).to.equal(3);
				expect(Number(summary.volumeOutMsat)).to.equal(3_000_000);
				expect(Number(summary.feesEarnedMsat)).to.equal(15_000);
			} finally {
				alice.destroy();
				bob.destroy();
				charlie.destroy();
			}
		});

		it('returns empty results without a storage backend', function () {
			const node = createNode(9);
			try {
				expect(node.listForwards()).to.deep.equal([]);
				const summary = node.getForwardingSummary();
				expect(summary.count).to.equal(0);
				expect(Number(summary.volumeOutMsat)).to.equal(0);
				expect(Number(summary.feesEarnedMsat)).to.equal(0);
			} finally {
				node.destroy();
			}
		});
	});

	describe('listForwardingEvents filters and ordering', function () {
		let storage: SqliteStorage;

		beforeEach(function () {
			storage = new SqliteStorage(':memory:');
			storage.open();
			const chanA = '11'.repeat(32);
			const chanB = '22'.repeat(32);
			const chanC = '33'.repeat(32);
			storage.saveForwardingEvent(
				makeEvent({ settledAt: 100, inChannelId: chanA, outChannelId: chanB })
			);
			storage.saveForwardingEvent(
				makeEvent({ settledAt: 200, inChannelId: chanB, outChannelId: chanC })
			);
			storage.saveForwardingEvent(
				makeEvent({ settledAt: 300, inChannelId: chanC, outChannelId: chanA })
			);
			storage.saveForwardingEvent(
				makeEvent({ settledAt: 400, inChannelId: chanA, outChannelId: chanC })
			);
		});

		afterEach(function () {
			storage.close();
		});

		it('orders newest first and breaks ties by id descending', function () {
			const events = storage.listForwardingEvents();
			expect(events.map((e) => e.settledAt)).to.deep.equal([
				400, 300, 200, 100
			]);
			// Same-timestamp tie: later insert (higher id) first
			storage.saveForwardingEvent(makeEvent({ settledAt: 400 }));
			const tied = storage.listForwardingEvents();
			expect(tied[0].settledAt).to.equal(400);
			expect(tied[0].id).to.be.greaterThan(tied[1].id);
		});

		it('filters by since and until', function () {
			const since = storage.listForwardingEvents({ since: 200 });
			expect(since.map((e) => e.settledAt)).to.deep.equal([400, 300, 200]);
			const until = storage.listForwardingEvents({ until: 200 });
			expect(until.map((e) => e.settledAt)).to.deep.equal([200, 100]);
			const window = storage.listForwardingEvents({ since: 150, until: 350 });
			expect(window.map((e) => e.settledAt)).to.deep.equal([300, 200]);
		});

		it('applies limit and offset', function () {
			const limited = storage.listForwardingEvents({ limit: 2 });
			expect(limited.map((e) => e.settledAt)).to.deep.equal([400, 300]);
			const paged = storage.listForwardingEvents({ limit: 2, offset: 2 });
			expect(paged.map((e) => e.settledAt)).to.deep.equal([200, 100]);
		});

		it('matches channelId against either leg', function () {
			const chanA = '11'.repeat(32);
			const events = storage.listForwardingEvents({ channelId: chanA });
			// chanA appears as inbound (100, 400) and outbound (300)
			expect(events.map((e) => e.settledAt)).to.deep.equal([400, 300, 100]);
		});

		it('preserves bigint msat values through the round-trip', function () {
			storage.saveForwardingEvent(
				makeEvent({
					settledAt: 500,
					// Above 2^53: exercises the TEXT column + BigInt() path
					amountInMsat: 9_007_199_254_741_993n,
					amountOutMsat: 9_007_199_254_740_993n,
					feeMsat: 1000n
				})
			);
			const [event] = storage.listForwardingEvents({ since: 500 });
			expect(event.amountInMsat === 9_007_199_254_741_993n).to.equal(true);
			expect(event.amountOutMsat === 9_007_199_254_740_993n).to.equal(true);
			expect(event.feeMsat === 1000n).to.equal(true);
		});
	});

	describe('getForwardingSummary', function () {
		it('sums count, outbound volume and fees, honoring since', function () {
			const storage = new SqliteStorage(':memory:');
			storage.open();
			try {
				storage.saveForwardingEvent(
					makeEvent({
						settledAt: 100,
						amountOutMsat: 1_000_000n,
						feeMsat: 100n
					})
				);
				storage.saveForwardingEvent(
					makeEvent({
						settledAt: 200,
						amountOutMsat: 2_000_000n,
						feeMsat: 200n
					})
				);
				storage.saveForwardingEvent(
					makeEvent({
						settledAt: 300,
						amountOutMsat: 3_000_000n,
						feeMsat: 300n
					})
				);
				const all = storage.getForwardingSummary();
				expect(all.count).to.equal(3);
				expect(Number(all.volumeOutMsat)).to.equal(6_000_000);
				expect(Number(all.feesEarnedMsat)).to.equal(600);
				const recent = storage.getForwardingSummary({ since: 200 });
				expect(recent.count).to.equal(2);
				expect(Number(recent.volumeOutMsat)).to.equal(5_000_000);
				expect(Number(recent.feesEarnedMsat)).to.equal(500);
				const none = storage.getForwardingSummary({ since: 301 });
				expect(none.count).to.equal(0);
				expect(Number(none.volumeOutMsat)).to.equal(0);
				expect(Number(none.feesEarnedMsat)).to.equal(0);
			} finally {
				storage.close();
			}
		});
	});

	describe('retention cap', function () {
		it('prunes oldest rows on insert past the cap (default 100k, test cap 5)', function () {
			const storage = new SqliteStorage(':memory:');
			storage.open();
			try {
				expect(storage.forwardingEventsMaxRows).to.equal(100_000);
				storage.forwardingEventsMaxRows = 5;
				for (let i = 1; i <= 8; i++) {
					storage.saveForwardingEvent(makeEvent({ settledAt: i * 100 }));
				}
				const events = storage.listForwardingEvents();
				expect(events).to.have.length(5);
				// Oldest three (100..300) pruned, newest five kept
				expect(events.map((e) => e.settledAt)).to.deep.equal([
					800, 700, 600, 500, 400
				]);
			} finally {
				storage.close();
			}
		});
	});

	describe('persistence and schema', function () {
		let tmpDir: string;

		beforeEach(function () {
			tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-fwd-'));
		});

		afterEach(function () {
			fs.rmSync(tmpDir, { recursive: true, force: true });
		});

		it('events survive a storage close and reopen', function () {
			const dbPath = path.join(tmpDir, 'node.db');
			const storage = new SqliteStorage(dbPath);
			storage.open();
			storage.saveForwardingEvent(makeEvent({ settledAt: 111 }));
			storage.saveForwardingEvent(makeEvent({ settledAt: 222 }));
			storage.close();

			const storage2 = new SqliteStorage(dbPath);
			storage2.open();
			try {
				const events = storage2.listForwardingEvents();
				expect(events).to.have.length(2);
				expect(events.map((e) => e.settledAt)).to.deep.equal([222, 111]);
				expect(Number(events[0].feeMsat)).to.equal(5000);
			} finally {
				storage2.close();
			}
		});

		it('schema includes the forwarding_events migration (v6+)', function () {
			const storage = new SqliteStorage(':memory:');
			storage.open();
			try {
				expect(SqliteStorage.CURRENT_SCHEMA_VERSION).to.be.at.least(6);
				expect(storage.getSchemaVersion()).to.equal(
					SqliteStorage.CURRENT_SCHEMA_VERSION
				);
			} finally {
				storage.close();
			}
		});
	});

	describe('BeignetNode wrapper', function () {
		const MNEMONIC =
			'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
		let tmpDir: string;

		beforeEach(function () {
			tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-fwd-cli-'));
		});

		afterEach(function () {
			fs.rmSync(tmpDir, { recursive: true, force: true });
		});

		it('listForwards/getForwardingSummary return msat values as strings', async function () {
			this.timeout(60_000);
			const node = await BeignetNode.create({
				mnemonic: MNEMONIC,
				network: 'regtest',
				dataDir: tmpDir,
				logLevel: 'silent',
				rapidGossipSync: false,
				autoGossipSync: false
			});
			try {
				// Inject a ledger row directly into the node's storage backend so
				// the wrapper's bigint -> string mapping is exercised with data
				const storage = (
					node as unknown as { node: { storage: SqliteStorage } }
				).node.storage;
				storage.saveForwardingEvent(makeEvent({ settledAt: 123 }));

				const forwards = node.listForwards();
				expect(forwards).to.have.length(1);
				expect(forwards[0].amountInMsat).to.equal('1005000');
				expect(forwards[0].amountOutMsat).to.equal('1000000');
				expect(forwards[0].feeMsat).to.equal('5000');
				expect(forwards[0].settledAt).to.equal(123);

				const summary = node.getForwardingSummary();
				expect(summary.count).to.equal(1);
				expect(summary.volumeOutMsat).to.equal('1000000');
				expect(summary.feesEarnedMsat).to.equal('5000');

				// since past the event filters it out
				const empty = node.getForwardingSummary(124);
				expect(empty.count).to.equal(0);
				expect(empty.volumeOutMsat).to.equal('0');
			} finally {
				await node.destroy();
			}
		});
	});
});
