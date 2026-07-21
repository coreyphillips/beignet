/**
 * Per-channel routing fee-policy control (M3).
 *
 * Covers setChannelPolicy validation, override-over-default precedence via
 * getChannelPolicy, the 'all' target, persistence through SqliteStorage,
 * channel_update regeneration for announced channels, the direct
 * channel_update sent to the peer for unannounced channels (adopted via
 * maybeAdoptPeerChannelPolicy), forwarding fee/CLTV enforcement of the
 * override, effective policy in channel listings, and the BeignetNode
 * wrapper.
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
import {
	encodeChannelUpdateMessage,
	decodeChannelUpdateMessage
} from '../../src/lightning/gossip/messages';
import { decode as decodeInvoice } from '../../src/lightning/invoice/decode';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { BeignetNode } from '../../src/cli/beignet-node';

// ─────────────── Helpers (mirrors tests/lightning/node.test.ts) ───────────────

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`policy-seed-${id}`))
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

function createNode(seedId: number): LightningNode {
	const node = new LightningNode(makeNodeConfig(seedId));
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

// ─────────────── Tests ───────────────

describe('Channel Routing Policy (M3)', function () {
	this.timeout(30_000);

	describe('setChannelPolicy validation', function () {
		let alice: LightningNode;
		let bob: LightningNode;
		let channelId: Buffer;

		beforeEach(function () {
			alice = createNode(1);
			bob = createNode(2);
			connectNodes(alice, bob);
			channelId = openReadyChannel(alice, bob);
		});

		afterEach(function () {
			alice.destroy();
			bob.destroy();
		});

		it('rejects an empty policy', function () {
			expect(() => alice.setChannelPolicy(channelId, {})).to.throw(
				'at least one field'
			);
		});

		it('rejects negative and non-integer feeBaseMsat', function () {
			expect(() =>
				alice.setChannelPolicy(channelId, { feeBaseMsat: -1 })
			).to.throw('feeBaseMsat');
			expect(() =>
				alice.setChannelPolicy(channelId, { feeBaseMsat: 1.5 })
			).to.throw('feeBaseMsat');
		});

		it('rejects feeProportionalMillionths above u32', function () {
			expect(() =>
				alice.setChannelPolicy(channelId, {
					feeProportionalMillionths: 0x1_0000_0000
				})
			).to.throw('feeProportionalMillionths');
		});

		it('rejects cltvExpiryDelta of 0 and above u16', function () {
			expect(() =>
				alice.setChannelPolicy(channelId, { cltvExpiryDelta: 0 })
			).to.throw('cltvExpiryDelta');
			expect(() =>
				alice.setChannelPolicy(channelId, { cltvExpiryDelta: 65536 })
			).to.throw('cltvExpiryDelta');
		});

		it('rejects negative htlc bounds', function () {
			expect(() =>
				alice.setChannelPolicy(channelId, { htlcMinimumMsat: -1n })
			).to.throw('htlcMinimumMsat');
			expect(() =>
				alice.setChannelPolicy(channelId, { htlcMaximumMsat: -1n })
			).to.throw('htlcMaximumMsat');
		});

		it('rejects htlcMinimumMsat above htlcMaximumMsat', function () {
			expect(() =>
				alice.setChannelPolicy(channelId, {
					htlcMinimumMsat: 10n,
					htlcMaximumMsat: 5n
				})
			).to.throw('exceeds htlcMaximumMsat');
		});

		it('rejects a partial update that would invert an existing min/max pair', function () {
			alice.setChannelPolicy(channelId, { htlcMaximumMsat: 100n });
			expect(() =>
				alice.setChannelPolicy(channelId, { htlcMinimumMsat: 200n })
			).to.throw('exceeds htlcMaximumMsat');
		});

		it('rejects an unknown channelId', function () {
			expect(() =>
				alice.setChannelPolicy(crypto.randomBytes(32), { feeBaseMsat: 1 })
			).to.throw('Channel not found');
		});

		it('validates fields even before channel lookup', function () {
			expect(() =>
				alice.setChannelPolicy(crypto.randomBytes(32), { cltvExpiryDelta: 0 })
			).to.throw('cltvExpiryDelta');
		});
	});

	describe('getChannelPolicy effective values', function () {
		let alice: LightningNode;
		let bob: LightningNode;
		let channelId: Buffer;

		beforeEach(function () {
			alice = createNode(1);
			bob = createNode(2);
			connectNodes(alice, bob);
			channelId = openReadyChannel(alice, bob);
		});

		afterEach(function () {
			alice.destroy();
			bob.destroy();
		});

		it('returns node defaults with source=default when no override is set', function () {
			const policy = alice.getChannelPolicy(channelId)!;
			expect(policy.source).to.equal('default');
			expect(policy.feeBaseMsat).to.equal(1000);
			expect(policy.feeProportionalMillionths).to.equal(1);
			expect(policy.cltvExpiryDelta).to.equal(40);
			// Channel-level defaults: negotiated htlc_minimum_msat and the
			// capacity-capped max_htlc_value_in_flight_msat
			expect(policy.htlcMinimumMsat).to.equal(
				DEFAULT_CHANNEL_CONFIG.htlcMinimumMsat
			);
			// Capacity of the 1M sat test channel: the default in-flight limit
			// is clamped to capacity at open/accept.
			expect(policy.htlcMaximumMsat).to.equal(1_000_000_000n);
		});

		it('override takes precedence, unset fields fall back to defaults', function () {
			alice.setChannelPolicy(channelId, {
				feeBaseMsat: 2500,
				cltvExpiryDelta: 144
			});
			const policy = alice.getChannelPolicy(channelId)!;
			expect(policy.source).to.equal('override');
			expect(policy.feeBaseMsat).to.equal(2500);
			expect(policy.cltvExpiryDelta).to.equal(144);
			// Untouched fields keep the defaults
			expect(policy.feeProportionalMillionths).to.equal(1);
			expect(policy.htlcMinimumMsat).to.equal(
				DEFAULT_CHANNEL_CONFIG.htlcMinimumMsat
			);
		});

		it('merges consecutive partial updates', function () {
			alice.setChannelPolicy(channelId, { feeBaseMsat: 2500 });
			alice.setChannelPolicy(channelId, { feeProportionalMillionths: 300 });
			const policy = alice.getChannelPolicy(channelId)!;
			expect(policy.feeBaseMsat).to.equal(2500);
			expect(policy.feeProportionalMillionths).to.equal(300);
		});

		it('returns null for an unknown channel', function () {
			expect(alice.getChannelPolicy(crypto.randomBytes(32))).to.be.null;
		});

		it('respects custom node-wide defaults from INodeConfig', function () {
			const carol = new LightningNode({
				...makeNodeConfig(3),
				forwardingFeeBaseMsat: 5000,
				forwardingFeePropMillionths: 200,
				forwardingCltvDelta: 80
			});
			carol.on('node:error', () => {});
			const dave = createNode(4);
			connectNodes(carol, dave);
			try {
				const cdChannelId = openReadyChannel(carol, dave);
				const policy = carol.getChannelPolicy(cdChannelId)!;
				expect(policy.source).to.equal('default');
				expect(policy.feeBaseMsat).to.equal(5000);
				expect(policy.feeProportionalMillionths).to.equal(200);
				expect(policy.cltvExpiryDelta).to.equal(80);
			} finally {
				carol.destroy();
				dave.destroy();
			}
		});
	});

	describe("'all' target", function () {
		it('applies the policy to every channel', function () {
			const alice = createNode(1);
			const bob = createNode(2);
			const carol = createNode(3);
			connectNodes(alice, bob);
			connectNodes(alice, carol);
			try {
				const abChannelId = openReadyChannel(alice, bob);
				const acChannelId = openReadyChannel(alice, carol);

				alice.setChannelPolicy('all', { feeProportionalMillionths: 250 });

				for (const id of [abChannelId, acChannelId]) {
					const policy = alice.getChannelPolicy(id)!;
					expect(policy.source).to.equal('override');
					expect(policy.feeProportionalMillionths).to.equal(250);
					// Unset fields keep node defaults
					expect(policy.feeBaseMsat).to.equal(1000);
				}
			} finally {
				alice.destroy();
				bob.destroy();
				carol.destroy();
			}
		});

		it("'all' with invalid fields throws even when there are no channels", function () {
			const alice = createNode(1);
			try {
				expect(() =>
					alice.setChannelPolicy('all', { cltvExpiryDelta: 0 })
				).to.throw('cltvExpiryDelta');
			} finally {
				alice.destroy();
			}
		});
	});

	describe('persistence (SqliteStorage round-trip)', function () {
		let tmpDir: string;

		beforeEach(function () {
			tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-policy-'));
		});

		afterEach(function () {
			fs.rmSync(tmpDir, { recursive: true, force: true });
		});

		it('storage saves, loads and deletes channel policies', function () {
			const storage = new SqliteStorage(':memory:');
			storage.open();
			try {
				// At least v4: the channel_policies migration this test depends on
				expect(storage.getSchemaVersion()).to.be.at.least(4);
				expect(storage.getSchemaVersion()).to.equal(
					SqliteStorage.CURRENT_SCHEMA_VERSION
				);
				storage.saveChannelPolicy('aa'.repeat(32), {
					feeBaseMsat: 123,
					htlcMinimumMsat: '999'
				});
				const rows = storage.loadAllChannelPolicies();
				expect(rows).to.have.length(1);
				expect(rows[0].channelId).to.equal('aa'.repeat(32));
				expect(rows[0].policy.feeBaseMsat).to.equal(123);
				expect(rows[0].policy.htlcMinimumMsat).to.equal('999');
				storage.deleteChannelPolicy('aa'.repeat(32));
				expect(storage.loadAllChannelPolicies()).to.have.length(0);
			} finally {
				storage.close();
			}
		});

		it('overrides survive a node restart and stay effective', function () {
			const dbPath = path.join(tmpDir, 'node.db');
			const storage = new SqliteStorage(dbPath);
			storage.open();
			const alice = new LightningNode({ ...makeNodeConfig(1), storage });
			alice.on('node:error', () => {});
			const bob = createNode(2);
			connectNodes(alice, bob);
			const channelId = openReadyChannel(alice, bob);
			alice.setChannelPolicy(channelId, {
				feeBaseMsat: 7500,
				htlcMinimumMsat: 10n
			});
			// destroy() closes the storage handle too
			alice.destroy();
			bob.destroy();

			const storage2 = new SqliteStorage(dbPath);
			storage2.open();
			const alice2 = new LightningNode({
				...makeNodeConfig(1),
				storage: storage2
			});
			alice2.on('node:error', () => {});
			try {
				const policy = alice2.getChannelPolicy(channelId)!;
				expect(policy, 'channel restored with policy').to.not.be.null;
				expect(policy.source).to.equal('override');
				expect(policy.feeBaseMsat).to.equal(7500);
				expect(policy.htlcMinimumMsat).to.equal(10n);
				// Unset fields still fall back to defaults after reload
				expect(policy.feeProportionalMillionths).to.equal(1);
			} finally {
				alice2.destroy();
			}
		});
	});

	describe('channel_update regeneration (announced channel)', function () {
		it('initial signed update carries the effective policy; setChannelPolicy rewrites and re-signs it', function () {
			const alice = createNode(1);
			const bob = createNode(2);
			connectNodes(alice, bob);
			try {
				const channelId = openReadyChannel(alice, bob);
				const scid = encodeShortChannelId({
					block: 800,
					txIndex: 5,
					outputIndex: 0
				});
				// Simulate the announcement flow: Channel emits announcement:ready
				// with a placeholder-policy channel_update (as buildFullAnnouncement
				// does); the node must stamp the effective policy before signing.
				const placeholderUpdate = encodeChannelUpdateMessage({
					signature: Buffer.alloc(64),
					chainHash: BITCOIN_CHAIN_HASH,
					shortChannelId: scid,
					timestamp: 1000,
					messageFlags: 1,
					channelFlags: 0,
					cltvExpiryDelta: 144,
					htlcMinimumMsat: 1n,
					feeBaseMsat: 0,
					feeProportionalMillionths: 0,
					htlcMaximumMsat: 123n
				});
				alice
					.getChannelManager()
					.emit(
						'announcement:ready',
						channelId,
						Buffer.alloc(430),
						placeholderUpdate
					);

				const gossip = (
					alice as unknown as {
						_ownChannelGossip: Map<string, { update: Buffer }>;
					}
				)._ownChannelGossip;
				const cached1 = gossip.get(channelId.toString('hex'))!.update;
				const dec1 = decodeChannelUpdateMessage(cached1);
				// Node defaults + channel-level htlc bounds, not the placeholders
				expect(dec1.feeBaseMsat).to.equal(1000);
				expect(dec1.feeProportionalMillionths).to.equal(1);
				expect(dec1.cltvExpiryDelta).to.equal(40);
				expect(dec1.htlcMinimumMsat).to.equal(
					DEFAULT_CHANNEL_CONFIG.htlcMinimumMsat
				);
				// Capacity of the 1M sat test channel: the default in-flight limit
				// is clamped to capacity at open/accept.
				expect(dec1.htlcMaximumMsat).to.equal(1_000_000_000n);
				expect(dec1.signature.equals(Buffer.alloc(64)), 'signed').to.be.false;

				alice.setChannelPolicy(channelId, {
					feeBaseMsat: 4321,
					feeProportionalMillionths: 555,
					cltvExpiryDelta: 99,
					htlcMinimumMsat: 5n,
					htlcMaximumMsat: 2_000_000_000_000n
				});

				const cached2 = gossip.get(channelId.toString('hex'))!.update;
				const dec2 = decodeChannelUpdateMessage(cached2);
				expect(dec2.feeBaseMsat).to.equal(4321);
				expect(dec2.feeProportionalMillionths).to.equal(555);
				expect(dec2.cltvExpiryDelta).to.equal(99);
				expect(dec2.htlcMinimumMsat).to.equal(5n);
				// BOLT 7: htlc_maximum_msat clamped to channel capacity (1M sats)
				expect(dec2.htlcMaximumMsat).to.equal(1_000_000_000n);
				// Strictly newer timestamp so peers do not dedupe the new policy
				expect(dec2.timestamp).to.be.greaterThan(dec1.timestamp);
				expect(dec2.signature.equals(Buffer.alloc(64)), 're-signed').to.be
					.false;
			} finally {
				alice.destroy();
				bob.destroy();
			}
		});
	});

	describe('direct channel_update to peer (unannounced channel)', function () {
		it('peer adopts the new policy via maybeAdoptPeerChannelPolicy', function () {
			const bob = createNode(2);
			const carol = createNode(3);
			connectNodes(bob, carol);
			try {
				const bcChannelId = openReadyChannel(bob, carol);
				const scidBC = encodeShortChannelId({
					block: 810,
					txIndex: 2,
					outputIndex: 0
				});
				// Models carol generating scidBC and sending it in channel_ready:
				// carol keeps it as her own scidAlias, bob stores it as
				// remoteScidAlias. BOLT 7 says bob's direct channel_update must name
				// an alias RECEIVED from the peer, so bob addresses it with
				// remoteScidAlias and carol matches it against her own.
				bob
					.getChannelManager()
					.getChannel(bcChannelId)!
					.getFullState().remoteScidAlias = scidBC;
				carol
					.getChannelManager()
					.getChannel(bcChannelId)!
					.getFullState().scidAlias = scidBC;

				bob.setChannelPolicy(bcChannelId, {
					feeBaseMsat: 7777,
					feeProportionalMillionths: 21,
					cltvExpiryDelta: 66
				});

				const adopted = carol
					.getChannelManager()
					.getChannel(bcChannelId)!
					.getFullState().remoteForwardingPolicy;
				expect(adopted, 'carol adopted the direct update').to.exist;
				expect(adopted!.feeBaseMsat).to.equal(7777);
				expect(adopted!.feeProportionalMillionths).to.equal(21);
				expect(adopted!.cltvExpiryDelta).to.equal(66);
			} finally {
				bob.destroy();
				carol.destroy();
			}
		});
	});

	describe('forwarding enforcement', function () {
		interface IForwardSetup {
			alice: LightningNode;
			bob: LightningNode;
			charlie: LightningNode;
			bcChannelId: Buffer;
		}

		// Alice -> Bob -> Charlie. AB is in Alice's graph; BC reaches Alice
		// only via Charlie's invoice routing hints (the wallet-node pattern).
		function setupForwarding(): IForwardSetup {
			const alice = createNode(1);
			const bob = createNode(2);
			const charlie = createNode(3);
			connectNodes(alice, bob);
			connectNodes(bob, charlie);

			const abChannelId = openReadyChannel(alice, bob, 1_000_000n);
			const bcChannelId = openReadyChannel(bob, charlie, 1_000_000n);

			const scidAB = encodeShortChannelId({
				block: 820,
				txIndex: 1,
				outputIndex: 0
			});
			const scidBC = encodeShortChannelId({
				block: 820,
				txIndex: 2,
				outputIndex: 0
			});
			bob.registerChannelScid(abChannelId, scidAB);
			bob.registerChannelScid(bcChannelId, scidBC);
			alice.registerChannelScid(abChannelId, scidAB);
			// Charlie's hint names the SCID Bob forwards over, which per BOLT 2 is
			// the alias BOB generated and sent charlie, stored as remoteScidAlias.
			charlie
				.getChannelManager()
				.getChannel(bcChannelId)!
				.getFullState().remoteScidAlias = scidBC;

			addGraphChannel(alice, scidAB, nodePubkey(1), nodePubkey(2));
			return { alice, bob, charlie, bcChannelId };
		}

		it('rejects a forward that does not cover the overridden base fee', function () {
			const { alice, bob, charlie, bcChannelId } = setupForwarding();
			try {
				let bobForwarded = false;
				bob.on('htlc:forward', () => {
					bobForwarded = true;
				});
				// Invoice issued BEFORE the policy change: its routing hint still
				// advertises the old default fee, so Alice underpays Bob's new fee.
				const invoice = charlie.createInvoice({
					amountMsat: 5_000_000n,
					description: 'fee-too-low'
				});
				bob.setChannelPolicy(bcChannelId, { feeBaseMsat: 50_000 });
				try {
					alice.sendPayment(invoice.bolt11);
				} catch {
					// Retries may exhaust routes and throw; the assertion below is
					// what matters.
				}

				expect(bobForwarded, 'bob must not forward').to.be.false;
				const decoded = decodeInvoice(invoice.bolt11);
				const received = charlie.getPayment(decoded.paymentHash);
				expect(received?.status).to.not.equal('COMPLETED');
			} finally {
				alice.destroy();
				bob.destroy();
				charlie.destroy();
			}
		});

		it('rejects a forward whose CLTV margin is below the overridden delta', function () {
			const { alice, bob, charlie, bcChannelId } = setupForwarding();
			try {
				let bobForwarded = false;
				bob.on('htlc:forward', () => {
					bobForwarded = true;
				});
				// Invoice hint frozen at delta 40; Bob then starts requiring 200.
				const invoice = charlie.createInvoice({
					amountMsat: 5_000_000n,
					description: 'cltv-too-low'
				});
				bob.setChannelPolicy(bcChannelId, { cltvExpiryDelta: 200 });
				try {
					alice.sendPayment(invoice.bolt11);
				} catch {
					// Expected: no viable route after the rejection.
				}

				expect(bobForwarded, 'bob must not forward').to.be.false;
			} finally {
				alice.destroy();
				bob.destroy();
				charlie.destroy();
			}
		});

		it('forwards when the payer honors the propagated override (end to end)', function () {
			const { alice, bob, charlie, bcChannelId } = setupForwarding();
			try {
				// With SCID aliases on both sides Bob's setChannelPolicy sends the
				// direct channel_update, Charlie adopts it, and the invoice hint
				// advertises the REAL fee, so Alice attaches enough.
				const scidBC = encodeShortChannelId({
					block: 820,
					txIndex: 2,
					outputIndex: 0
				});
				// Bob's direct channel_update names an alias received from the peer.
				bob
					.getChannelManager()
					.getChannel(bcChannelId)!
					.getFullState().remoteScidAlias = scidBC;

				bob.setChannelPolicy(bcChannelId, {
					feeBaseMsat: 5000,
					feeProportionalMillionths: 0
				});
				const adopted = charlie
					.getChannelManager()
					.getChannel(bcChannelId)!
					.getFullState().remoteForwardingPolicy;
				expect(adopted?.feeBaseMsat, 'charlie learned the fee').to.equal(5000);

				let bobForwarded = false;
				bob.on('htlc:forward', () => {
					bobForwarded = true;
				});
				const invoice = charlie.createInvoice({
					amountMsat: 5_000_000n,
					description: 'fee-honored'
				});
				alice.sendPayment(invoice.bolt11);

				expect(bobForwarded, 'bob forwarded').to.be.true;
				const decoded = decodeInvoice(invoice.bolt11);
				expect(charlie.getPayment(decoded.paymentHash)!.status).to.equal(
					'COMPLETED'
				);
				expect(alice.getPayment(decoded.paymentHash)!.status).to.equal(
					'COMPLETED'
				);
			} finally {
				alice.destroy();
				bob.destroy();
				charlie.destroy();
			}
		});
	});

	describe('channel info exposure', function () {
		it('getChannel/listChannels expose the effective policy', function () {
			const alice = createNode(1);
			const bob = createNode(2);
			connectNodes(alice, bob);
			try {
				const channelId = openReadyChannel(alice, bob);

				const before = alice.getChannel(channelId)!;
				expect(before.feeBaseMsat).to.equal(1000);
				expect(before.feeProportionalMillionths).to.equal(1);
				expect(before.cltvExpiryDelta).to.equal(40);
				expect(before.htlcMinimumMsat).to.equal(
					DEFAULT_CHANNEL_CONFIG.htlcMinimumMsat
				);
				// Capacity of the 1M sat test channel: the default in-flight limit
				// is clamped to capacity at open/accept.
				expect(before.htlcMaximumMsat).to.equal(1_000_000_000n);

				alice.setChannelPolicy(channelId, {
					feeBaseMsat: 42,
					htlcMaximumMsat: 250_000_000n
				});
				const after = alice.listChannels()[0];
				expect(after.feeBaseMsat).to.equal(42);
				expect(after.htlcMaximumMsat).to.equal(250_000_000n);
				// Unset fields still reflect defaults
				expect(after.cltvExpiryDelta).to.equal(40);
			} finally {
				alice.destroy();
				bob.destroy();
			}
		});
	});

	describe('BeignetNode wrapper', function () {
		const MNEMONIC =
			'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
		let tmpDir: string;

		beforeEach(function () {
			tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-policy-cli-'));
		});

		afterEach(function () {
			fs.rmSync(tmpDir, { recursive: true, force: true });
		});

		it('updateChannelPolicy/getChannelPolicy round through the wrapper', async function () {
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
				// No channels yet: 'all' is a no-op but must still validate fields
				const result = node.updateChannelPolicy('all', { feeBaseMsat: 100 });
				expect(result.updated).to.equal(0);
				expect(result.policies).to.deep.equal([]);
				expect(() =>
					node.updateChannelPolicy('all', { cltvExpiryDelta: 0 })
				).to.throw('cltvExpiryDelta');
				// Unknown channel: policy lookup is null, update throws
				expect(node.getChannelPolicy('bb'.repeat(32))).to.be.null;
				expect(() =>
					node.updateChannelPolicy('bb'.repeat(32), { feeBaseMsat: 1 })
				).to.throw('Channel not found');
			} finally {
				await node.destroy();
			}
		});
	});
});
