/**
 * Recovery Protocol phase 3: the Recovery Capsule over BOLT 1 peer_storage
 * (docs/RECOVERY-PROTOCOL.md 5.4 and 9).
 *
 * Tests cover:
 * 1. Capsule encrypt/decode round trip; foreign, tampered and wrong-key
 *    blobs are rejected as null (restore scans candidates, it must not crash)
 * 2. Best-capsule selection: highest (writerEpoch, latestSequence)
 * 3. Composition: SCB-only locator without a journal; tip and base-snapshot
 *    binding with one; graceful degradation to SCB + locator when the inline
 *    journal exceeds the peer-storage budget; loud failure when even the
 *    SCB-only capsule is oversized
 * 4. Restore fails closed: tampered inline frames, a capsule head that does
 *    not match its inline journal, and dirty targets all throw
 * 5. Acceptance (section 9 phase 3): a node restored from the capsule alone
 *    is byte-identical, resumes its channel via reestablish, and pays over it
 */

import { expect } from 'chai';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { Network } from '../../src/lightning/invoice/types';
import { INodeConfig } from '../../src/lightning/node/types';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { IStorageBackend } from '../../src/lightning/storage/types';
import {
	RecoveryCriticality,
	RecoveryManager,
	RecoveryJournal,
	RecoveryCapsule,
	RecoveryMutation,
	RecoveryOutboundMessage,
	CAPSULE_MAX_BYTES,
	PROBE_MUTATION_COVERAGE,
	PROBE_SNAPSHOT_COVERAGE,
	composeRecoveryCapsule,
	decodeRecoveryCapsuleBlob,
	encryptRecoveryCapsule,
	knownGoodProbeFrames,
	reconstructFromFrames,
	restoreFromRecoveryCapsule,
	restoreBestRecoveryCapsule,
	selectRecoveryCapsule,
	deriveRecoveryMasterKey,
	deriveRecoveryRoot,
	deriveFrameIv,
	deriveFrameKey,
	decodeFrame,
	decryptFrame,
	encodeFrame,
	encryptFrame,
	frameAad,
	hashFrame
} from '../../src/lightning/recovery';
import { withStorageTransaction } from '../../src/lightning/storage/transaction';
import { createOpenerState } from '../../src/lightning/channel/channel-state';
import { MonitorState } from '../../src/lightning/chain/types';
import { PaymentDirection } from '../../src/lightning/node/types';
import { MessageType } from '../../src/lightning/message/types';
import { decodePeerStorageMessage } from '../../src/lightning/message/peer-storage';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';
import {
	encodeScb,
	IStaticChannelBackup
} from '../../src/lightning/backup/scb';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import {
	DEFAULT_CHANNEL_CONFIG,
	BITCOIN_CHAIN_HASH,
	ChannelState
} from '../../src/lightning/channel/types';
import {
	serializeChannelState,
	serializePaymentInfo
} from '../../src/lightning/storage/serialization';
import {
	IChannelAnnouncementMessage,
	IChannelUpdateMessage,
	encodeShortChannelId
} from '../../src/lightning/gossip/types';
import { PaymentStatus } from '../../src/lightning/node/types';

// ─────────────── Fixtures (harness modeled on recovery-phase1) ───────────────

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(`recovery-phase3-seed-${id}`)
		.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
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
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

function makeNodeConfig(
	seedId: number,
	storage?: IStorageBackend,
	recovery = false
): INodeConfig {
	const seed = makeSeed(seedId);
	return {
		nodePrivateKey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from('node-identity'))
			.digest(),
		network: Network.REGTEST as Network,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([0]))
			.digest(),
		htlcBasepointSecret: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([4]))
			.digest(),
		storage,
		recovery: recovery ? { enabled: true } : undefined
	};
}

function createNode(
	seedId: number,
	storage?: IStorageBackend,
	recovery = false
): LightningNode {
	const node = new LightningNode(makeNodeConfig(seedId, storage, recovery));
	node.on('error', () => {});
	node.on('node:error', () => {});
	return node;
}

function connectNodes(nodeA: LightningNode, nodeB: LightningNode): void {
	nodeA.on('message:outbound', (pubkey: string, type: number, p: Buffer) => {
		if (pubkey === nodeB.getNodeId()) {
			nodeB.handlePeerMessage(nodeA.getNodeId(), type, p);
		}
	});
	nodeB.on('message:outbound', (pubkey: string, type: number, p: Buffer) => {
		if (pubkey === nodeA.getNodeId()) {
			nodeA.handlePeerMessage(nodeB.getNodeId(), type, p);
		}
	});
}

function openReadyChannel(alice: LightningNode, bob: LightningNode): Buffer {
	const channel = alice.openChannel(bob.getNodeId(), 1_000_000n);
	const channelId = alice.createFunding(
		channel,
		crypto.randomBytes(32),
		0,
		crypto.randomBytes(64)
	)!;
	alice.handleFundingConfirmed(channelId);
	bob.handleFundingConfirmed(channelId);
	return channelId;
}

/** Direct alice->bob graph so the restored node can route a payment. */
function buildDirectGraph(alice: LightningNode): void {
	const alicePubkey = getPublicKey(makeNodeConfig(1).nodePrivateKey);
	const bobPubkey = getPublicKey(makeNodeConfig(2).nodePrivateKey);
	const scid = encodeShortChannelId({ block: 500, txIndex: 1, outputIndex: 0 });
	const aliceIsNode1 = Buffer.compare(alicePubkey, bobPubkey) < 0;
	const announcement: IChannelAnnouncementMessage = {
		nodeSignature1: Buffer.alloc(64),
		nodeSignature2: Buffer.alloc(64),
		bitcoinSignature1: Buffer.alloc(64),
		bitcoinSignature2: Buffer.alloc(64),
		features: Buffer.alloc(0),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		nodeId1: aliceIsNode1 ? alicePubkey : bobPubkey,
		nodeId2: aliceIsNode1 ? bobPubkey : alicePubkey,
		bitcoinKey1: Buffer.alloc(33, 2),
		bitcoinKey2: Buffer.alloc(33, 3)
	};
	alice.getGraph().addChannelAnnouncement(announcement);
	const update: IChannelUpdateMessage = {
		signature: Buffer.alloc(64),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		timestamp: Math.floor(Date.now() / 1000),
		messageFlags: 1,
		channelFlags: 0,
		cltvExpiryDelta: 40,
		htlcMinimumMsat: 1000n,
		feeBaseMsat: 1000,
		feeProportionalMillionths: 1,
		htlcMaximumMsat: 1_000_000_000n
	};
	alice.getGraph().applyChannelUpdate(update);
	alice.getGraph().applyChannelUpdate({ ...update, channelFlags: 1 });
	alice.registerChannelScid(
		alice.getChannelManager().listChannels()[0].getChannelId()!,
		scid
	);
}

const NODE_SECRET = makeNodeConfig(1).nodePrivateKey;

/** The capsule dry-run scratch: a fresh in-memory backend per candidate. */
const scratchStorage = (): SqliteStorage => {
	const scratch = new SqliteStorage(':memory:');
	scratch.open();
	return scratch;
};

function openStorage(): SqliteStorage {
	const storage = new SqliteStorage(':memory:');
	storage.open();
	return storage;
}

function makeScb(): string {
	const backup: IStaticChannelBackup = {
		version: 1,
		network: 'regtest',
		createdAt: 1_700_000_000_000,
		channels: []
	};
	return encodeScb(backup, NODE_SECRET);
}

/**
 * A journaled storage with a few committed transitions. `salt` varies the
 * committed content, so two storages with the same salt produce identical
 * chains and different salts produce different frame hashes at the same
 * heights (the conflicting-heads case).
 */
function journaledStorage(
	transitions = 3,
	salt = 0
): {
	storage: SqliteStorage;
	journal: RecoveryJournal;
	manager: RecoveryManager;
} {
	const storage = openStorage();
	const journal = new RecoveryJournal(
		storage,
		deriveRecoveryMasterKey(NODE_SECRET),
		getPublicKey(NODE_SECRET),
		deriveRecoveryRoot(NODE_SECRET).recoveryId
	);
	const manager = new RecoveryManager(storage, { journal });
	for (let i = 0; i < transitions; i++) {
		const result = manager.commit({
			criticality: RecoveryCriticality.SafetyCritical,
			mutations: [
				{
					type: 'payment_preimage',
					paymentHash: Buffer.alloc(32, i + 1 + salt).toString('hex'),
					preimage: Buffer.alloc(32, i + 1 + salt)
				}
			],
			outboundMessages: []
		});
		expect(result.committed).to.equal(true);
	}
	return { storage, journal, manager };
}

/**
 * Deterministic dump of every safety-critical table (slimmed copy of the
 * phase 2 helper; keep the two in sync). frame_sequence stamps compare;
 * row ids and created_at are nonsemantic.
 */
function dumpTables(storage: IStorageBackend): string {
	const sortByFirst = <T extends { 0: string }>(rows: T[]): T[] =>
		rows.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
	const bigintSafe = (_key: string, value: unknown): unknown =>
		typeof value === 'bigint' ? `${value.toString()}n` : value;
	const dump = {
		channels: sortByFirst(
			storage
				.loadAllChannels()
				.map(
					(c) =>
						[
							c.channelId,
							JSON.stringify(serializeChannelState(c.state)),
							c.peerPubkey,
							String(storage.loadChannelKeyIndex(c.channelId))
						] as [string, string, string, string]
				)
		),
		monitors: sortByFirst(
			storage
				.loadAllChainMonitors()
				.map(
					(m) =>
						[m.channelId, JSON.stringify(m.state, bigintSafe)] as [
							string,
							string
						]
				)
		),
		preimages: sortByFirst(
			storage
				.loadAllPreimages()
				.map(
					(p) => [p.paymentHash, p.preimage.toString('hex')] as [string, string]
				)
		),
		payments: sortByFirst(
			storage
				.loadAllPayments()
				.map(
					(p) =>
						[
							p.paymentHash,
							JSON.stringify(serializePaymentInfo(p.payment))
						] as [string, string]
				)
		),
		paymentSecrets: sortByFirst(
			storage
				.loadAllPaymentSecrets()
				.map(
					(s) =>
						[s.paymentHashHex, s.secret.toString('hex')] as [string, string]
				)
		),
		htlcPaymentMappings: sortByFirst(
			storage
				.loadAllHtlcPaymentMappings()
				.map((m) => [m.key, m.paymentHashHex] as [string, string])
		),
		invoices: sortByFirst(
			storage
				.loadAllInvoices()
				.map(
					(i) =>
						[i.paymentHashHex, JSON.stringify(i.invoice, bigintSafe)] as [
							string,
							string
						]
				)
		),
		outbox: (storage.loadOutboxMessages?.() ?? []).map((row) => [
			row.peerId,
			row.channelId ?? '',
			String(row.messageType),
			row.wireMessage.toString('hex'),
			row.disposition,
			String(row.frameSequence)
		])
	};
	return JSON.stringify(dump);
}

// ─────────────── 1. Capsule crypto and codec ───────────────

describe('Recovery phase 3: capsule crypto', () => {
	function sampleCapsule(): RecoveryCapsule {
		return {
			version: 1,
			encryptedScb: makeScb(),
			writerEpoch: 3n,
			latestSequence: 41n,
			frameHash: Buffer.alloc(32, 7),
			snapshotHash: Buffer.alloc(32, 9),
			guardians: [
				{
					guardianId: 'ab'.repeat(33),
					transports: [
						{ type: 'onion-http', url: 'http://guardianexample.onion' },
						{ type: 'https', url: 'https://guardian.example.com' }
					]
				}
			],
			inlineRecoveryState: Buffer.from('{"meta":{},"frames":[]}', 'utf8')
		};
	}

	it('round trips through encrypt and decode', () => {
		const capsule = sampleCapsule();
		const blob = encryptRecoveryCapsule(capsule, NODE_SECRET);
		const decoded = decodeRecoveryCapsuleBlob(blob, NODE_SECRET);
		expect(decoded).to.not.equal(null);
		expect(decoded!.writerEpoch).to.equal(3n);
		expect(decoded!.latestSequence).to.equal(41n);
		expect(decoded!.frameHash.equals(capsule.frameHash)).to.equal(true);
		expect(decoded!.snapshotHash.equals(capsule.snapshotHash)).to.equal(true);
		expect(decoded!.guardians).to.deep.equal(capsule.guardians);
		expect(
			decoded!.inlineRecoveryState!.equals(capsule.inlineRecoveryState!)
		).to.equal(true);
		expect(decoded!.encryptedScb).to.equal(capsule.encryptedScb);
	});

	it('carries optional guardian auth credentials through the encrypted capsule', () => {
		// Wire 2.4: non-local transports REQUIRE authentication, so the
		// credential must survive catastrophic restoration inside the
		// seed-encrypted capsule. Optional and additive: descriptors without
		// it (every Phase 3 capsule) stay valid.
		const capsule = sampleCapsule();
		capsule.guardians = [
			{
				guardianId: 'ab'.repeat(32),
				transports: [{ type: 'https', url: 'https://guardian.example.com' }],
				auth: { type: 'bearer', token: 'restore-me-with-the-seed' }
			},
			{
				guardianId: 'cd'.repeat(32),
				transports: [{ type: 'onion-http', url: 'http://guardianx.onion' }],
				auth: {
					type: 'tor-v3-client-auth',
					privateKey: 'descriptor-x25519-private'
				}
			},
			{
				guardianId: 'ef'.repeat(32),
				transports: [{ type: 'local-http', url: 'http://127.0.0.1:9911' }]
			}
		];
		const decoded = decodeRecoveryCapsuleBlob(
			encryptRecoveryCapsule(capsule, NODE_SECRET),
			NODE_SECRET
		);
		expect(decoded).to.not.equal(null);
		expect(decoded!.guardians).to.deep.equal(capsule.guardians);
		expect(decoded!.guardians[0].auth).to.deep.equal({
			type: 'bearer',
			token: 'restore-me-with-the-seed'
		});
		expect(decoded!.guardians[2].auth).to.equal(undefined);
	});

	it('returns null for foreign, tampered and wrong-key blobs', () => {
		const blob = encryptRecoveryCapsule(sampleCapsule(), NODE_SECRET);
		// Foreign blob: not our magic.
		expect(
			decodeRecoveryCapsuleBlob(crypto.randomBytes(200), NODE_SECRET)
		).to.equal(null);
		// Tampered ciphertext.
		const tampered = Buffer.from(blob);
		tampered[tampered.length - 1] ^= 0x01;
		expect(decodeRecoveryCapsuleBlob(tampered, NODE_SECRET)).to.equal(null);
		// Wrong key: another node's secret.
		expect(
			decodeRecoveryCapsuleBlob(blob, makeNodeConfig(2).nodePrivateKey)
		).to.equal(null);
	});

	it('selects the highest (writerEpoch, latestSequence) capsule', () => {
		const base = sampleCapsule();
		const older: RecoveryCapsule = {
			...base,
			writerEpoch: 2n,
			latestSequence: 90n
		};
		const newerEpoch: RecoveryCapsule = {
			...base,
			writerEpoch: 3n,
			latestSequence: 10n
		};
		const newest: RecoveryCapsule = {
			...base,
			writerEpoch: 3n,
			latestSequence: 41n
		};
		// Epoch dominates sequence: a superseded writer's higher sequence loses.
		expect(selectRecoveryCapsule([older, newest, newerEpoch])).to.equal(newest);
		expect(selectRecoveryCapsule([])).to.equal(null);
	});
});

// ─────────────── 3. Composition ───────────────

describe('Recovery phase 3: capsule composition', () => {
	it('composes an SCB-only locator capsule without a journal', () => {
		const storage = openStorage();
		const { blob, capsule, inline } = composeRecoveryCapsule({
			storage,
			encryptedScb: makeScb(),
			nodeSecret: NODE_SECRET
		});
		expect(inline).to.equal(false);
		expect(capsule.latestSequence).to.equal(0n);
		expect(capsule.frameHash.equals(Buffer.alloc(32))).to.equal(true);
		expect(blob.length).to.be.at.most(CAPSULE_MAX_BYTES);
		const decoded = decodeRecoveryCapsuleBlob(blob, NODE_SECRET);
		expect(decoded!.inlineRecoveryState).to.equal(undefined);
		storage.close();
	});

	it('binds the journal tip and base snapshot, and inlines the journal', () => {
		const { storage, journal } = journaledStorage();
		const { capsule, inline } = composeRecoveryCapsule({
			storage,
			encryptedScb: makeScb(),
			nodeSecret: NODE_SECRET
		});
		expect(inline).to.equal(true);
		const tip = journal.getTip()!;
		expect(capsule.latestSequence).to.equal(tip.sequence);
		expect(capsule.frameHash.equals(tip.frameHash)).to.equal(true);
		// The base snapshot is frame 1 (bootstrap): its stored hash binds.
		const base = storage.loadRecoveryFrames()[0];
		expect(base.sequence).to.equal(1);
		expect(capsule.snapshotHash.equals(base.frameHash)).to.equal(true);
		storage.close();
	});

	it('degrades to SCB + locator when the inline journal exceeds the budget', () => {
		const { storage, journal } = journaledStorage(5);
		const { blob, capsule, inline } = composeRecoveryCapsule({
			storage,
			encryptedScb: makeScb(),
			nodeSecret: NODE_SECRET,
			// Big enough for SCB + locator, far too small for the journal.
			maxBytes: 1500
		});
		expect(inline).to.equal(false);
		expect(capsule.inlineRecoveryState).to.equal(undefined);
		// The locator still points at the real head.
		expect(capsule.latestSequence).to.equal(journal.getTip()!.sequence);
		expect(blob.length).to.be.at.most(1500);
		storage.close();
	});

	it('throws when even the SCB-only capsule is oversized', () => {
		const storage = openStorage();
		expect(() =>
			composeRecoveryCapsule({
				storage,
				encryptedScb: makeScb(),
				nodeSecret: NODE_SECRET,
				maxBytes: 64
			})
		).to.throw(/oversized/);
		storage.close();
	});
});

// ─────────────── 4. Restore fails closed ───────────────

describe('Recovery phase 3: capsule restore', () => {
	function composedCapsule(): {
		storage: SqliteStorage;
		capsule: RecoveryCapsule;
	} {
		const { storage } = journaledStorage();
		const { capsule } = composeRecoveryCapsule({
			storage,
			encryptedScb: makeScb(),
			nodeSecret: NODE_SECRET
		});
		return { storage, capsule };
	}

	it('rebuilds byte-identical tables from the inline journal (tier 2)', () => {
		const { storage, capsule } = composedCapsule();
		const target = openStorage();
		const result = restoreFromRecoveryCapsule(capsule, target, NODE_SECRET);
		expect(result.tier).to.equal(2);
		expect(result.framesApplied).to.be.greaterThan(0);
		expect(dumpTables(target)).to.equal(dumpTables(storage));
		storage.close();
		target.close();
	});

	it('falls back to tier 1 when the capsule has no inline state', () => {
		const { storage } = journaledStorage();
		const { capsule } = composeRecoveryCapsule({
			storage,
			encryptedScb: makeScb(),
			nodeSecret: NODE_SECRET,
			maxBytes: 1500
		});
		const target = openStorage();
		const result = restoreFromRecoveryCapsule(capsule, target, NODE_SECRET);
		expect(result.tier).to.equal(1);
		expect(result.scb.version).to.equal(1);
		expect(target.loadAllPreimages()).to.have.length(0);
		storage.close();
		target.close();
	});

	it('rejects a tampered inline frame', () => {
		const { storage, capsule } = composedCapsule();
		const inline = JSON.parse(capsule.inlineRecoveryState!.toString('utf8'));
		const ct = Buffer.from(inline.frames[0].ciphertext, 'base64');
		ct[ct.length - 1] ^= 0x01;
		inline.frames[0].ciphertext = ct.toString('base64');
		capsule.inlineRecoveryState = Buffer.from(JSON.stringify(inline), 'utf8');
		const target = openStorage();
		expect(() =>
			restoreFromRecoveryCapsule(capsule, target, NODE_SECRET)
		).to.throw(/failed authentication/);
		storage.close();
		target.close();
	});

	it('rejects an inline journal that does not end at the capsule head', () => {
		const { storage, capsule } = composedCapsule();
		// A lying head: the capsule claims a NEWER sequence than the payload.
		// A stale-payload splice must not restore silently behind the anchor.
		capsule.latestSequence += 1n;
		const target = openStorage();
		expect(() =>
			restoreFromRecoveryCapsule(capsule, target, NODE_SECRET)
		).to.throw(/truncated|head does not match/);
		storage.close();
		target.close();
	});

	it('rejects a dirty restore target', () => {
		const { storage, capsule } = composedCapsule();
		const target = openStorage();
		target.savePreimage('ee'.repeat(32), Buffer.alloc(32, 9));
		expect(() =>
			restoreFromRecoveryCapsule(capsule, target, NODE_SECRET)
		).to.throw(/EMPTY target/);
		storage.close();
		target.close();
	});
});

// ─────────────── 5. Acceptance: restore + reestablish + pay ───────────────

describe('Recovery phase 3: end to end restore from the capsule alone', () => {
	it('restores a small node, resumes the channel via reestablish, and pays', function () {
		this.timeout(30_000);

		// A journaled node with one live channel and an invoice.
		const liveStorage = openStorage();
		const alice = createNode(1, liveStorage, true);
		const bob = createNode(2, undefined, false);
		connectNodes(alice, bob);
		openReadyChannel(alice, bob);
		alice.createInvoice({ amountMsat: 25_000n, description: 'pre-restore' });

		// The node composed an initial capsule at startup and throttles the
		// rest; a manual refresh gives us the current one, exactly the blob
		// distributePeerStorage pushes and remembers.
		expect(alice.refreshRecoveryCapsule()).to.be.at.least(0);
		const blob = (alice as unknown as { ourPeerStorageBlob: Buffer | null })
			.ourPeerStorageBlob;
		expect(blob, 'capsule blob composed and remembered').to.not.equal(null);

		// Restore side: ONE validated operation over the raw candidate blobs
		// (spec 5.4); the foreign garbage blob is ignored, ours validates,
		// wins, and rebuilds byte-identically into a fresh database.
		const restoredStorage = openStorage();
		const result = restoreBestRecoveryCapsule(
			[crypto.randomBytes(300), blob!],
			restoredStorage,
			makeNodeConfig(1).nodePrivateKey,
			{ scratchStorage }
		);
		expect(result.tier).to.equal(2);
		expect(
			result.capsule.inlineRecoveryState,
			'small wallet fits inline'
		).to.not.equal(undefined);
		expect(result.rejectedCandidates).to.equal(0);
		expect(dumpTables(restoredStorage)).to.equal(dumpTables(liveStorage));
		// The Tier 1 material is present and lists the channel too.
		expect(result.scb.channels).to.have.length(1);

		// The old device is gone; bob notices the disconnect. Drop bob's
		// loopback wiring to the destroyed node, or its dead listener runs
		// first and breaks the emit chain to the restored one.
		alice.destroy();
		bob.removeAllListeners('message:outbound');
		bob
			.getChannelManager()
			.handlePeerDisconnected(
				getPublicKey(makeNodeConfig(1).nodePrivateKey).toString('hex')
			);

		// The restored node comes up from the reconstructed database and
		// resumes the channel via reestablish: exact resumption, no force
		// close, and a payment flows over the resumed channel. A real
		// connection delivers BOTH reestablish messages before any responses
		// they trigger, so hold a FIFO until both sides have sent theirs
		// (wire model from reestablish-update-retransmission.test.ts).
		const restored = createNode(1, restoredStorage, true);
		const queue: Array<{
			to: LightningNode;
			from: string;
			type: number;
			payload: Buffer;
		}> = [];
		let hold = true;
		const wire = (from: LightningNode, to: LightningNode): void => {
			from.on('message:outbound', (pk: string, t: number, p: Buffer) => {
				if (pk !== to.getNodeId()) return;
				if (hold) {
					queue.push({ to, from: from.getNodeId(), type: t, payload: p });
				} else {
					to.handlePeerMessage(from.getNodeId(), t, p);
				}
			});
		};
		wire(restored, bob);
		wire(bob, restored);
		restored.getChannelManager().handlePeerReconnected(bob.getNodeId());
		bob.getChannelManager().handlePeerReconnected(restored.getNodeId());
		// FIFO drain; nested emissions keep queueing in order behind it.
		while (queue.length > 0) {
			const m = queue.shift()!;
			m.to.handlePeerMessage(m.from, m.type, m.payload);
		}
		hold = false;

		const restoredChannel = restored.getChannelManager().listChannels()[0];
		const bobChannel = bob.getChannelManager().listChannels()[0];
		expect(restoredChannel.getState()).to.equal(ChannelState.NORMAL);
		expect(bobChannel.getState()).to.equal(ChannelState.NORMAL);

		buildDirectGraph(restored);
		const invoice = bob.createInvoice({
			amountMsat: 50_000n,
			description: 'post-restore'
		});
		const payment = restored.sendPayment(invoice.bolt11);
		expect(payment.status).to.equal(PaymentStatus.COMPLETED);

		restored.destroy();
		bob.destroy();
		liveStorage.close();
		restoredStorage.close();
	});

	it('does not compose capsules when the journal is off', () => {
		const storage = openStorage();
		const node = createNode(3, storage, false);
		expect(node.refreshRecoveryCapsule()).to.equal(0);
		expect(
			(node as unknown as { ourPeerStorageBlob: Buffer | null })
				.ourPeerStorageBlob
		).to.equal(null);
		node.destroy();
		storage.close();
	});
});

// ─────────────── Review regressions: stale startup, validated selection,
// new-provider freshness ───────────────

describe('Recovery phase 3: review regressions', () => {
	it('startup capsule re-bases a journal left stale by a disabled period', () => {
		// node.destroy() closes its storage, so the three runs share a
		// file-backed database instead of one ':memory:' handle.
		const dbPath = path.join(
			fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-p3-stale-')),
			'stale.db'
		);
		const openFile = (): SqliteStorage => {
			const s = new SqliteStorage(dbPath);
			s.open();
			return s;
		};

		// Run 1: recovery enabled; state A journaled.
		const run1 = createNode(4, openFile(), true);
		run1.createInvoice({ amountMsat: 1_000n, description: 'state-a' });
		run1.destroy();

		// Run 2: recovery disabled; state advances to B, journal stays at A.
		const run2 = createNode(4, openFile(), false);
		run2.createInvoice({ amountMsat: 2_000n, description: 'state-b' });
		run2.destroy();

		// Run 3: recovery enabled again. The INITIAL capsule, captured before
		// any new transition, must already describe state B: the constructor
		// re-bases the journal before composing. A capsule whose SCB and
		// inline Tier 2 journal describe different points in time is exactly
		// the stale-restore bug.
		const run3Storage = openFile();
		const run3 = createNode(4, run3Storage, true);
		const blob = (run3 as unknown as { ourPeerStorageBlob: Buffer | null })
			.ourPeerStorageBlob;
		expect(blob, 'initial capsule composed').to.not.equal(null);
		const capsule = decodeRecoveryCapsuleBlob(
			blob!,
			makeNodeConfig(4).nodePrivateKey
		)!;
		expect(capsule.inlineRecoveryState).to.not.equal(undefined);

		const restored = openStorage();
		const result = restoreFromRecoveryCapsule(
			capsule,
			restored,
			makeNodeConfig(4).nodePrivateKey
		);
		expect(result.tier).to.equal(2);
		// BOTH invoices are present: state B, not the stale state A.
		expect(restored.loadAllInvoices()).to.have.length(2);
		expect(dumpTables(restored)).to.equal(dumpTables(run3Storage));
		run3.destroy();
		restored.close();
	});

	/** Tamper one inline frame of a composed capsule and re-encrypt it. */
	function tamperInline(capsule: RecoveryCapsule, nodeSecret: Buffer): Buffer {
		const inline = JSON.parse(
			capsule.inlineRecoveryState!.toString('utf8')
		) as { frames: Array<{ ciphertext: string }> };
		const ct = Buffer.from(inline.frames[0].ciphertext, 'base64');
		ct[ct.length - 1] ^= 0x01;
		inline.frames[0].ciphertext = ct.toString('base64');
		return encryptRecoveryCapsule(
			{
				...capsule,
				inlineRecoveryState: Buffer.from(JSON.stringify(inline), 'utf8')
			},
			nodeSecret
		);
	}

	it('restores the highest candidate WHOSE CHAIN VALIDATES, not the raw highest', () => {
		const { storage, manager } = journaledStorage(2);
		const older = composeRecoveryCapsule({
			storage,
			encryptedScb: makeScb(),
			nodeSecret: NODE_SECRET
		});
		const olderState = dumpTables(storage);

		// The journal advances, and the NEWER capsule's inline is corrupted.
		expect(
			manager.commit({
				criticality: RecoveryCriticality.SafetyCritical,
				mutations: [
					{
						type: 'payment_preimage',
						paymentHash: Buffer.alloc(32, 9).toString('hex'),
						preimage: Buffer.alloc(32, 9)
					}
				],
				outboundMessages: []
			}).committed
		).to.equal(true);
		const newer = composeRecoveryCapsule({
			storage,
			encryptedScb: makeScb(),
			nodeSecret: NODE_SECRET
		});
		const tamperedNewer = tamperInline(newer.capsule, NODE_SECRET);

		const target = openStorage();
		const result = restoreBestRecoveryCapsule(
			[tamperedNewer, older.blob],
			target,
			NODE_SECRET,
			{ scratchStorage }
		);
		// The raw-highest candidate is invalid; the validated lower one wins.
		expect(result.tier).to.equal(2);
		expect(result.capsule.latestSequence).to.equal(
			older.capsule.latestSequence
		);
		expect(dumpTables(target)).to.equal(olderState);
		// And the newer, unvalidatable head is surfaced, not hidden.
		expect(result.newestSeenHead.latestSequence).to.equal(
			newer.capsule.latestSequence
		);
		storage.close();
		target.close();
	});

	it('fails closed on equal heads with conflicting hashes', () => {
		// Two seed-identical writers advanced independently to the same
		// height: same (epoch, sequence), different frame hashes.
		const a = journaledStorage(2, 0);
		const b = journaledStorage(2, 100);
		const blobA = composeRecoveryCapsule({
			storage: a.storage,
			encryptedScb: makeScb(),
			nodeSecret: NODE_SECRET
		}).blob;
		const blobB = composeRecoveryCapsule({
			storage: b.storage,
			encryptedScb: makeScb(),
			nodeSecret: NODE_SECRET
		}).blob;
		const target = openStorage();
		expect(() =>
			restoreBestRecoveryCapsule([blobA, blobB], target, NODE_SECRET, {
				scratchStorage
			})
		).to.throw(/conflicting/);
		a.storage.close();
		b.storage.close();
		target.close();
	});

	it('falls back to Tier 1 when no inline journal validates', () => {
		const { storage } = journaledStorage(2);
		const composed = composeRecoveryCapsule({
			storage,
			encryptedScb: makeScb(),
			nodeSecret: NODE_SECRET
		});
		const tampered = tamperInline(composed.capsule, NODE_SECRET);
		const target = openStorage();
		const result = restoreBestRecoveryCapsule([tampered], target, NODE_SECRET, {
			scratchStorage
		});
		expect(result.tier).to.equal(1);
		expect(result.scb.version).to.equal(1);
		// Nothing touched the target on the failed Tier 2 attempt.
		expect(target.loadAllPreimages()).to.have.length(0);
		expect(target.loadRecoveryFrames()).to.have.length(0);
		storage.close();
		target.close();
	});

	it('never inlines a journal that fails verification at compose time', () => {
		const { storage } = journaledStorage(3);
		// Corrupt one stored frame on disk.
		const db = (
			storage as unknown as {
				db: {
					prepare: (sql: string) => {
						run: (...args: unknown[]) => unknown;
						get: (...args: unknown[]) => unknown;
					};
				};
			}
		).db;
		// The storage layer refuses UPDATEs on frame rows (append-only
		// trigger), so simulated corruption replaces the row wholesale.
		const full = db
			.prepare('SELECT * FROM recovery_frames WHERE sequence = 2')
			.get() as Record<string, unknown>;
		db.prepare('DELETE FROM recovery_frames WHERE sequence = 2').run();
		db.prepare(
			'INSERT INTO recovery_frames (sequence, writer_epoch, frame_hash, previous_hash, ciphertext, created_at) VALUES (?, ?, ?, ?, ?, ?)'
		).run(
			full.sequence,
			full.writer_epoch,
			full.frame_hash,
			full.previous_hash,
			Buffer.alloc(64),
			full.created_at
		);
		const { capsule, inline, inlineError } = composeRecoveryCapsule({
			storage,
			encryptedScb: makeScb(),
			nodeSecret: NODE_SECRET
		});
		// SCB + locator go out; the broken chain does not.
		expect(inline).to.equal(false);
		expect(capsule.inlineRecoveryState).to.equal(undefined);
		expect(inlineError).to.match(/failed authentication|truncated/);
		storage.close();
	});

	it('a provider connecting inside the throttle window gets a FRESH capsule', () => {
		const storage = openStorage();
		const node = createNode(5, storage, true);
		const nodeKey = makeNodeConfig(5).nodePrivateKey;
		// Startup composed and consumed the throttle window; this commit
		// lands inside it, so the cached blob stays at the startup head.
		node.createInvoice({ amountMsat: 3_000n, description: 'inside-window' });
		const cached = decodeRecoveryCapsuleBlob(
			(node as unknown as { ourPeerStorageBlob: Buffer | null })
				.ourPeerStorageBlob!,
			nodeKey
		)!;

		const capablePk = '03'.repeat(33);
		const capableFeatures = FeatureFlags.empty();
		capableFeatures.setOptional(Feature.PROVIDE_STORAGE);
		const sent: Array<{ pubkey: string; type: number; payload: Buffer }> = [];
		(node as unknown as { peerManager: unknown }).peerManager = {
			listPeers: (): unknown[] => [{ pubkey: capablePk }],
			getPeer: (): unknown => ({
				getRemoteInit: (): unknown => ({ features: capableFeatures })
			}),
			sendToPeer: (pubkey: string, type: number, payload: Buffer): void => {
				sent.push({ pubkey, type, payload });
			},
			destroy: (): void => {}
		};
		(
			node as unknown as { sendPeerStorageOnConnect: (pk: string) => void }
		).sendPeerStorageOnConnect(capablePk);

		const push = sent.find((m) => m.type === MessageType.PEER_STORAGE);
		expect(push, 'capsule pushed on connect').to.not.equal(undefined);
		const framed = decodePeerStorageMessage(push!.payload).blob;
		// Unwrap the bPS1 privacy framing to the raw capsule blob.
		expect(framed.toString('ascii', 0, 4)).to.equal('bPS1');
		const blob = framed.subarray(8, 8 + framed.readUInt32BE(4));
		const fresh = decodeRecoveryCapsuleBlob(Buffer.from(blob), nodeKey)!;
		// The new provider got the post-commit head, not the throttled cache.
		expect(fresh.latestSequence > cached.latestSequence).to.equal(true);
		node.destroy();
		storage.close();
	});

	it('never inlines a stale journal when the startup re-base fails', () => {
		const dbPath = path.join(
			fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-p3-rebase-')),
			'rebase.db'
		);
		const openFile = (): SqliteStorage => {
			const s = new SqliteStorage(dbPath);
			s.open();
			return s;
		};

		// Run 1: recovery enabled; state A journaled.
		const run1 = createNode(6, openFile(), true);
		run1.createInvoice({ amountMsat: 1_000n, description: 'state-a' });
		run1.destroy();
		// Run 2: recovery disabled; state advances to B, journal stays at A.
		const run2 = createNode(6, openFile(), false);
		run2.createInvoice({ amountMsat: 2_000n, description: 'state-b' });
		run2.destroy();

		// Run 3: the re-base snapshot write fails (disk full). The retained
		// journal is internally VALID but stale, which chain verification
		// cannot see, so a failed re-base must prohibit inlining outright.
		const run3Storage = openFile();
		const failing = new Proxy(run3Storage, {
			get(target, prop, receiver): unknown {
				if (prop === 'saveRecoveryFrame') {
					return (): never => {
						throw new Error('disk full');
					};
				}
				const value = Reflect.get(target, prop, receiver);
				return typeof value === 'function' ? value.bind(target) : value;
			}
		}) as IStorageBackend;
		const run3 = createNode(6, failing, true);
		const blob = (run3 as unknown as { ourPeerStorageBlob: Buffer | null })
			.ourPeerStorageBlob;
		expect(blob, 'SCB + locator capsule still composed').to.not.equal(null);
		const capsule = decodeRecoveryCapsuleBlob(
			blob!,
			makeNodeConfig(6).nodePrivateKey
		)!;
		// The stale-but-valid journal must NOT ride; the locator still
		// reports the stale head honestly instead of pretending none exists.
		expect(capsule.inlineRecoveryState).to.equal(undefined);
		expect(capsule.latestSequence > 0n).to.equal(true);
		// And a restore of this capsule is Tier 1 only.
		const target = openStorage();
		const result = restoreFromRecoveryCapsule(
			capsule,
			target,
			makeNodeConfig(6).nodePrivateKey
		);
		expect(result.tier).to.equal(1);
		// The failure arms a self-healing retry: the capsule stays dirty for
		// connecting providers, and a deferred refresh is scheduled so
		// Tier 2 coverage returns without new Lightning activity.
		expect(
			(run3 as unknown as { capsuleDirty: boolean }).capsuleDirty
		).to.equal(true);
		expect(
			(run3 as unknown as { capsuleRefreshTimer: unknown }).capsuleRefreshTimer
		).to.not.equal(null);
		run3.destroy();
		target.close();
	});

	it('tries every replica of a nonconflicting head before dropping lower', () => {
		const { storage } = journaledStorage(2);
		const good = composeRecoveryCapsule({
			storage,
			encryptedScb: makeScb(),
			nodeSecret: NODE_SECRET
		});
		// Two damaged replicas of the SAME head: one with a mangled inline
		// payload, one with a broken SCB but a valid chain. Neither may stop
		// the intact third replica from restoring this head, whatever the
		// arrival order.
		const badInline = encryptRecoveryCapsule(
			{
				...good.capsule,
				inlineRecoveryState: Buffer.from('not even json', 'utf8')
			},
			NODE_SECRET
		);
		const badScb = encryptRecoveryCapsule(
			{ ...good.capsule, encryptedScb: 'beignet-scb-v1:AAAA' },
			NODE_SECRET
		);
		const target = openStorage();
		const result = restoreBestRecoveryCapsule(
			[badInline, badScb, good.blob],
			target,
			NODE_SECRET,
			{ scratchStorage }
		);
		expect(result.tier).to.equal(2);
		expect(result.capsule.latestSequence).to.equal(good.capsule.latestSequence);
		expect(dumpTables(target)).to.equal(dumpTables(storage));
		storage.close();
		target.close();
	});
});

describe('Recovery phase 3: capsule schema prevalidation', () => {
	it('rejects a future-schema capsule BEFORE writing the target and falls back to Tier 1', () => {
		// A single-frame journal whose base snapshot is rewritten, with a
		// valid AEAD seal and matching tip hash, to declare schema '3':
		// what a capsule composed by a future release looks like.
		const { storage } = journaledStorage(1);
		const row = storage.loadRecoveryFrames!(0)[0];
		const epoch = BigInt(row.writerEpoch);
		const masterKey = deriveRecoveryMasterKey(NODE_SECRET);
		const nodeId = getPublicKey(NODE_SECRET);
		const key = deriveFrameKey(masterKey, nodeId, epoch);
		const aad = frameAad(
			nodeId,
			epoch,
			BigInt(row.sequence),
			row.previousFrameHash
		);
		const frame = decodeFrame(decryptFrame(key, row.ciphertext, aad));
		frame.snapshot!.schemaVersion = '3';
		const plaintext = encodeFrame(frame);
		const frameHash = hashFrame(plaintext);
		const iv = deriveFrameIv(
			deriveRecoveryRoot(NODE_SECRET).recoveryId,
			epoch,
			BigInt(row.sequence),
			frameHash
		);
		(
			storage as unknown as {
				db: { prepare(sql: string): { run(...args: unknown[]): unknown } };
			}
		).db
			.prepare('DELETE FROM recovery_frames WHERE sequence = ?')
			.run(row.sequence);
		storage.saveRecoveryFrame!({
			sequence: row.sequence,
			writerEpoch: row.writerEpoch,
			frameHash,
			previousFrameHash: row.previousFrameHash,
			ciphertext: encryptFrame(key, plaintext, aad, iv),
			createdAt: row.createdAt
		});
		storage.setRecoveryMeta!('journal_tip_hash', frameHash.toString('hex'));

		const { blob } = composeRecoveryCapsule({
			storage,
			encryptedScb: makeScb(),
			nodeSecret: NODE_SECRET
		});

		// Direct restore: the schema refusal lands during candidate
		// validation, BEFORE the first write to the target.
		const capsule = decodeRecoveryCapsuleBlob(blob, NODE_SECRET)!;
		const target1 = openStorage();
		expect(() =>
			restoreFromRecoveryCapsule(capsule, target1, NODE_SECRET)
		).to.throw(/cannot restore/);
		expect(
			target1.loadRecoveryFrames!(0),
			'no frames written to the target'
		).to.have.length(0);
		expect(
			target1.getRecoveryMeta!('journal_tip_sequence') ?? null,
			'no journal metadata written either'
		).to.equal(null);
		target1.close();

		// Selection: the incompatible inline journal is a CANDIDATE defect,
		// so the valid Tier 1 SCB is still returned and the target stays
		// clean, instead of an exception over a half-written database.
		const target2 = openStorage();
		const best = restoreBestRecoveryCapsule([blob], target2, NODE_SECRET, {
			scratchStorage
		});
		expect(best.tier, 'the SCB tier survives').to.equal(1);
		expect(best.framesApplied).to.equal(0);
		expect(target2.loadRecoveryFrames!(0)).to.have.length(0);
		target2.close();
		storage.close();
	});
});

describe('Recovery phase 3: capsule replay failures roll back', () => {
	it('a replay-invalid capsule leaves the target untouched and falls back to Tier 1', () => {
		// An AUTHENTICATED, current-schema capsule whose snapshot content
		// cannot actually replay (an outbox row with a null peerId hits the
		// NOT NULL constraint): chain verification cannot see this, so the
		// install transaction must roll the frames and metadata back and
		// selection must degrade to the valid Tier 1 SCB.
		const { storage } = journaledStorage(1);
		const row = storage.loadRecoveryFrames!(0)[0];
		const epoch = BigInt(row.writerEpoch);
		const masterKey = deriveRecoveryMasterKey(NODE_SECRET);
		const nodeId = getPublicKey(NODE_SECRET);
		const key = deriveFrameKey(masterKey, nodeId, epoch);
		const aad = frameAad(
			nodeId,
			epoch,
			BigInt(row.sequence),
			row.previousFrameHash
		);
		const frame = decodeFrame(decryptFrame(key, row.ciphertext, aad));
		frame.snapshot!.outbox = [
			{
				peerId: null as unknown as string,
				channelId: undefined,
				messageType: 1,
				wireMessage: Buffer.alloc(2),
				disposition: 'pending_send',
				frameSequence: null
			}
		];
		const plaintext = encodeFrame(frame);
		const frameHash = hashFrame(plaintext);
		const iv = deriveFrameIv(
			deriveRecoveryRoot(NODE_SECRET).recoveryId,
			epoch,
			BigInt(row.sequence),
			frameHash
		);
		(
			storage as unknown as {
				db: { prepare(sql: string): { run(...args: unknown[]): unknown } };
			}
		).db
			.prepare('DELETE FROM recovery_frames WHERE sequence = ?')
			.run(row.sequence);
		storage.saveRecoveryFrame!({
			sequence: row.sequence,
			writerEpoch: row.writerEpoch,
			frameHash,
			previousFrameHash: row.previousFrameHash,
			ciphertext: encryptFrame(key, plaintext, aad, iv),
			createdAt: row.createdAt
		});
		storage.setRecoveryMeta!('journal_tip_hash', frameHash.toString('hex'));

		const { blob } = composeRecoveryCapsule({
			storage,
			encryptedScb: makeScb(),
			nodeSecret: NODE_SECRET
		});

		// Direct restore: the throw leaves the target EXACTLY as it was,
		// because frames, metadata and replay share one transaction.
		const capsule = decodeRecoveryCapsuleBlob(blob, NODE_SECRET)!;
		const target1 = openStorage();
		expect(() =>
			restoreFromRecoveryCapsule(capsule, target1, NODE_SECRET, {
				scratchStorage
			})
		).to.throw(/failed to replay/);
		expect(
			target1.loadRecoveryFrames!(0),
			'the dry-run refused before any target write'
		).to.have.length(0);
		expect(
			target1.getRecoveryMeta!('journal_tip_sequence') ?? null,
			'and the metadata'
		).to.equal(null);
		target1.close();

		// Selection: a candidate defect, so the Tier 1 SCB still restores.
		const target2 = openStorage();
		const best = restoreBestRecoveryCapsule([blob], target2, NODE_SECRET, {
			scratchStorage
		});
		expect(best.tier, 'Tier 1 fallback survives').to.equal(1);
		expect(target2.loadRecoveryFrames!(0)).to.have.length(0);
		target2.close();
		storage.close();
	});

	it('a dirty target is refused loudly before any candidate is tried', () => {
		const { storage } = journaledStorage(1);
		const { blob } = composeRecoveryCapsule({
			storage,
			encryptedScb: makeScb(),
			nodeSecret: NODE_SECRET
		});
		const dirty = openStorage();
		dirty.savePreimage('bb'.repeat(32), Buffer.alloc(32, 7));
		expect(() =>
			restoreBestRecoveryCapsule([blob], dirty, NODE_SECRET, {
				scratchStorage
			})
		).to.throw(/EMPTY target/);
		dirty.close();
		storage.close();
	});
});

describe('Recovery phase 3: restore target and backend contracts', () => {
	it('refuses a target carrying recovery metadata or frames, not just tables', () => {
		const { storage } = journaledStorage(1);
		const { blob } = composeRecoveryCapsule({
			storage,
			encryptedScb: makeScb(),
			nodeSecret: NODE_SECRET
		});
		const capsule = decodeRecoveryCapsuleBlob(blob, NODE_SECRET)!;

		// Metadata-only residue: application tables empty, but journal
		// metadata present. Overwriting it would silently orphan another
		// journal's identity.
		const metaDirty = openStorage();
		metaDirty.setRecoveryMeta!('journal_tip_sequence', '7');
		expect(() =>
			restoreBestRecoveryCapsule([blob], metaDirty, NODE_SECRET, {
				scratchStorage
			})
		).to.throw(/recovery metadata/);
		expect(() =>
			restoreFromRecoveryCapsule(capsule, metaDirty, NODE_SECRET)
		).to.throw(/recovery metadata/);
		expect(
			metaDirty.getRecoveryMeta!('journal_tip_sequence'),
			'the residue was not overwritten'
		).to.equal('7');
		metaDirty.close();

		// Frame residue: a stray stored frame with no tip metadata.
		const frameDirty = openStorage();
		const row = storage.loadRecoveryFrames!(0)[0];
		frameDirty.saveRecoveryFrame!(row);
		frameDirty.deleteRecoveryMeta?.('journal_tip_sequence');
		expect(() =>
			restoreBestRecoveryCapsule([blob], frameDirty, NODE_SECRET, {
				scratchStorage
			})
		).to.throw(/recovery frames/);
		frameDirty.close();
		storage.close();
	});

	it('restores Tier 2 through a backend that refuses nested transactions', () => {
		// IStorageBackend does not promise reentrant transactions. Emulate
		// a strictly non-reentrant backend: the whole install (frames,
		// metadata, replay) must share ONE transaction instead of nesting.
		const { storage } = journaledStorage(2);
		const { blob } = composeRecoveryCapsule({
			storage,
			encryptedScb: makeScb(),
			nodeSecret: NODE_SECRET
		});
		const capsule = decodeRecoveryCapsuleBlob(blob, NODE_SECRET)!;
		const real = openStorage();
		let inTransaction = false;
		const strict = new Proxy(real, {
			get(target, prop, receiver): unknown {
				if (prop === 'transaction') {
					return <T>(fn: () => T): T => {
						if (inTransaction) {
							throw new Error('nested transaction refused');
						}
						inTransaction = true;
						try {
							return target.transaction(fn);
						} finally {
							inTransaction = false;
						}
					};
				}
				const value = Reflect.get(target, prop, receiver);
				return typeof value === 'function' ? value.bind(target) : value;
			}
		}) as unknown as IStorageBackend;

		const result = restoreFromRecoveryCapsule(capsule, strict, NODE_SECRET);
		expect(result.tier, 'the valid capsule restores Tier 2').to.equal(2);
		expect(real.loadRecoveryFrames!(0).length).to.be.greaterThan(0);
		expect(real.loadAllPreimages().length).to.be.greaterThan(0);
		real.close();
		storage.close();
	});

	it('propagates a broken target instead of degrading it to Tier 1', () => {
		// A valid capsule over a target whose frame store fails is a TARGET
		// problem: returning Tier 1 would mask the broken database.
		const { storage } = journaledStorage(1);
		const { blob } = composeRecoveryCapsule({
			storage,
			encryptedScb: makeScb(),
			nodeSecret: NODE_SECRET
		});
		const broken = openStorage();
		broken.saveRecoveryFrame = (): void => {
			throw new Error('disk write failed');
		};
		expect(() =>
			restoreBestRecoveryCapsule([blob], broken, NODE_SECRET, {
				scratchStorage
			})
		).to.throw(/disk write failed/);
		broken.close();
		storage.close();
	});
});

describe('Recovery phase 3: round-13 boundary hardening', () => {
	it('propagates a replay-time target failure instead of Tier 1', () => {
		// A VALID capsule over a target whose preimage table fails during
		// the replay: with the dry-run proving the content on a scratch,
		// the install-time failure is a TARGET problem and must propagate,
		// never degrade to Tier 1.
		const { storage } = journaledStorage(2);
		const { blob } = composeRecoveryCapsule({
			storage,
			encryptedScb: makeScb(),
			nodeSecret: NODE_SECRET
		});
		const broken = openStorage();
		broken.savePreimage = (): void => {
			throw new Error('preimage disk write failed');
		};
		expect(() =>
			restoreBestRecoveryCapsule([blob], broken, NODE_SECRET, {
				scratchStorage
			})
		).to.throw(/preimage disk write failed/);
		// The shared install transaction rolled everything back.
		expect(broken.loadRecoveryFrames!()).to.have.length(0);
		expect(broken.getRecoveryMeta!('journal_tip_sequence') ?? null).to.equal(
			null
		);
		broken.close();
		storage.close();
	});

	it('refuses residue the old empty-target check missed', () => {
		const { storage } = journaledStorage(1);
		const { blob } = composeRecoveryCapsule({
			storage,
			encryptedScb: makeScb(),
			nodeSecret: NODE_SECRET
		});
		const row = storage.loadRecoveryFrames!(0)[0];

		// (a) A sequence-0 frame: loadRecoveryFrames(0) reads strictly
		// above, so the old check missed it; the restored journal would be
		// immediately unverifiable.
		const seqZero = openStorage();
		seqZero.saveRecoveryFrame!({ ...row, sequence: 0 });
		expect(() =>
			restoreBestRecoveryCapsule([blob], seqZero, NODE_SECRET, {
				scratchStorage
			})
		).to.throw(/recovery frames/);
		seqZero.close();

		// (b) Recovery-control metadata beyond the journal's own keys.
		const leased = openStorage();
		leased.setRecoveryMeta!('writer_lease_v1', 'aa'.repeat(16));
		expect(() =>
			restoreBestRecoveryCapsule([blob], leased, NODE_SECRET, {
				scratchStorage
			})
		).to.throw(/recovery metadata/);
		leased.close();

		// (c) An orphaned key-index row: it would shift the next
		// derivation index of the restored node.
		const indexed = openStorage();
		indexed.saveChannelKeyIndex('cc'.repeat(32), 7);
		expect(() =>
			restoreBestRecoveryCapsule([blob], indexed, NODE_SECRET, {
				scratchStorage
			})
		).to.throw(/EMPTY target/);
		indexed.close();
		storage.close();
	});
});

describe('Recovery phase 3: round-14 validator and residue hardening', () => {
	it('selection REQUIRES the scratch and a broken validator propagates', () => {
		const { storage } = journaledStorage(1);
		const { blob } = composeRecoveryCapsule({
			storage,
			encryptedScb: makeScb(),
			nodeSecret: NODE_SECRET
		});

		// (a) Mandatory: without a scratch the candidate/Tier-1 contract
		// cannot be honored, so selection refuses to run at all.
		const t1 = openStorage();
		expect(() => restoreBestRecoveryCapsule([blob], t1, NODE_SECRET)).to.throw(
			/requires options\.scratchStorage/
		);
		t1.close();

		// (b) A validator whose own storage cannot pass the probe is
		// INFRASTRUCTURE failure: it must propagate raw, never downgrade a
		// valid capsule to another candidate or Tier 1.
		const t2 = openStorage();
		const brokenScratch = (): SqliteStorage => {
			const scratch = new SqliteStorage(':memory:');
			scratch.open();
			scratch.transaction = (): never => {
				throw new Error('scratch backend exploded');
			};
			return scratch;
		};
		expect(() =>
			restoreBestRecoveryCapsule([blob], t2, NODE_SECRET, {
				scratchStorage: brokenScratch
			})
		).to.throw(/scratch backend exploded/);
		expect(t2.loadRecoveryFrames!()).to.have.length(0);
		t2.close();
		storage.close();
	});

	it('a scratch that mutates its inputs cannot alter the target replay', () => {
		// The dry-run hands decoded frames to FOREIGN code; a hostile or
		// buggy adapter mutating a Buffer argument must not change what the
		// target reconstructs, because the install re-decodes from the
		// authenticated rows.
		const { storage } = journaledStorage(1);
		const original = storage.loadAllPreimages()[0].preimage.toString('hex');
		const { blob } = composeRecoveryCapsule({
			storage,
			encryptedScb: makeScb(),
			nodeSecret: NODE_SECRET
		});
		const mutatingScratch = (): SqliteStorage => {
			const scratch = new SqliteStorage(':memory:');
			scratch.open();
			const realSave = scratch.savePreimage.bind(scratch);
			scratch.savePreimage = (hash: string, preimage: Buffer): void => {
				realSave(hash, preimage);
				preimage.fill(0); // hostile: mutate the shared buffer
			};
			return scratch;
		};
		const target = openStorage();
		const capsule = decodeRecoveryCapsuleBlob(blob, NODE_SECRET)!;
		const result = restoreFromRecoveryCapsule(capsule, target, NODE_SECRET, {
			scratchStorage: mutatingScratch
		});
		expect(result.tier).to.equal(2);
		expect(
			target.loadAllPreimages()[0].preimage.toString('hex'),
			'the target replay used a fresh decode, not the mutated buffers'
		).to.equal(original);
		target.close();
		storage.close();
	});

	it('a non-enumerating backend is refused Tier 2 outright', () => {
		// A backend that cannot enumerate its recovery metadata cannot
		// prove a restore target clean of unknown residue, so it does not
		// get a journal (journalSupported) and a capsule restore degrades
		// to Tier 1 BY CONTRACT instead of installing over unseen state.
		const { storage } = journaledStorage(1);
		const { blob } = composeRecoveryCapsule({
			storage,
			encryptedScb: makeScb(),
			nodeSecret: NODE_SECRET
		});
		const base = openStorage();
		base.setRecoveryMeta!('guardian_replicated_through', '5');
		const nonEnumerating = new Proxy(base, {
			get(target, prop, receiver): unknown {
				if (prop === 'listRecoveryMetaKeys') return undefined;
				const value = Reflect.get(target, prop, receiver);
				return typeof value === 'function' ? value.bind(target) : value;
			}
		}) as unknown as IStorageBackend;
		const result = restoreBestRecoveryCapsule(
			[blob],
			nonEnumerating,
			NODE_SECRET,
			{ scratchStorage }
		);
		expect(result.tier, 'Tier 1 only').to.equal(1);
		expect(base.loadRecoveryFrames!(), 'no frames installed').to.have.length(0);
		base.close();
		storage.close();
	});
});

describe('Recovery phase 3: validator failures are never capsule defects', () => {
	it('a validator that cannot replay KNOWN-GOOD content propagates raw', () => {
		// The probe replays a synthetic known-good frame set exercising the
		// same reads, table writes and transaction completion a real replay
		// needs. A scratch backend failing THAT is broken infrastructure:
		// it must propagate raw, never silently discard a valid Tier-2
		// candidate into Tier 1.
		const { storage } = journaledStorage(1);
		const { blob } = composeRecoveryCapsule({
			storage,
			encryptedScb: makeScb(),
			nodeSecret: NODE_SECRET
		});
		const target = openStorage();
		const failingReplayScratch = (): SqliteStorage => {
			const scratch = new SqliteStorage(':memory:');
			scratch.open();
			scratch.savePreimage = (): void => {
				throw new Error('scratch preimage table broken');
			};
			return scratch;
		};
		expect(() =>
			restoreBestRecoveryCapsule([blob], target, NODE_SECRET, {
				scratchStorage: failingReplayScratch
			})
		).to.throw(/scratch preimage table broken/);
		expect(
			target.loadRecoveryFrames!(),
			'the target was never touched'
		).to.have.length(0);
		target.close();
		storage.close();
	});
});

describe('Recovery phase 3: round-16 validator provenance', () => {
	it('a backend failing a table the probe covers propagates raw', () => {
		// savePaymentSecret failures were previously laundered into capsule
		// defects; the known-good probe now writes that table on the SAME
		// instance whose candidate failure is being classified, so a broken
		// validator propagates instead of discarding valid Tier-2 state.
		const { storage, manager } = journaledStorage(1);
		// The candidate itself carries a payment secret, so its replay hits
		// the broken table.
		expect(
			manager.commit({
				criticality: RecoveryCriticality.SafetyCritical,
				mutations: [
					{
						type: 'payment_secret',
						paymentHash: 'ee'.repeat(32),
						secret: Buffer.alloc(32, 9)
					}
				],
				outboundMessages: []
			}).committed
		).to.equal(true);
		const { blob } = composeRecoveryCapsule({
			storage,
			encryptedScb: makeScb(),
			nodeSecret: NODE_SECRET
		});
		const target = openStorage();
		const broken = (): SqliteStorage => {
			const scratch = new SqliteStorage(':memory:');
			scratch.open();
			scratch.savePaymentSecret = (): void => {
				throw new Error('scratch payment_secrets broken');
			};
			return scratch;
		};
		expect(() =>
			restoreBestRecoveryCapsule([blob], target, NODE_SECRET, {
				scratchStorage: broken
			})
		).to.throw(/scratch payment_secrets broken/);
		expect(target.loadRecoveryFrames!()).to.have.length(0);
		target.close();
		storage.close();
	});
});

describe('Recovery phase 3: round-17 probe coverage and transient discrimination', () => {
	function probeChannelMutation(): RecoveryMutation {
		const point = getPublicKey(Buffer.alloc(32, 21));
		const state = createOpenerState({
			temporaryChannelId: Buffer.alloc(32, 22),
			fundingSatoshis: 1_000n,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: {
				fundingPubkey: point,
				revocationBasepoint: point,
				paymentBasepoint: point,
				delayedPaymentBasepoint: point,
				htlcBasepoint: point,
				firstPerCommitmentPoint: point
			},
			localPerCommitmentSeed: Buffer.alloc(32, 23)
		});
		state.channelId = Buffer.alloc(32, 0xdc);
		return {
			type: 'channel_state',
			channelId: 'dc'.repeat(32),
			state,
			peerPubkey: point.toString('hex')
		};
	}

	/** Every storage method a candidate replay can reach on the scratch. */
	const REPLAY_SURFACE = [
		'saveChannel',
		'saveChannelKeyIndex',
		'saveChainMonitor',
		'savePreimage',
		'savePayment',
		'savePaymentSecret',
		'saveHtlcPaymentMapping',
		'saveForwardedHtlc',
		'saveHtlcSharedSecret',
		'saveInvoice',
		'saveInvoicePathId',
		'saveForwardingEvent',
		'saveOutboxMessage',
		'setOutboxFrameSequence',
		'deleteHtlcPaymentMapping',
		'deleteHtlcSharedSecret',
		'deleteForwardedHtlc',
		'deletePaymentSecret',
		'deletePayment',
		'deletePreimage',
		'deleteInvoice',
		'deleteInvoicePathId',
		'deleteOutboxMessages',
		'deleteChannel'
	] as const;

	it('the probe replays cleanly and invokes EVERY replay-surface operation', () => {
		const scratch = scratchStorage();
		const called = new Set<string>();
		const outboxDeletions: Array<number[] | undefined> = [];
		const spy = new Proxy(scratch, {
			get(target, prop, receiver): unknown {
				const value = Reflect.get(target, prop, receiver);
				if (typeof value !== 'function') return value;
				return (...args: unknown[]): unknown => {
					called.add(String(prop));
					if (String(prop) === 'deleteOutboxMessages') {
						outboxDeletions.push(args[1] as number[] | undefined);
					}
					return (value as (...a: unknown[]) => unknown).apply(target, args);
				};
			}
		}) as unknown as IStorageBackend;
		withStorageTransaction(spy, () => {
			reconstructFromFrames(spy, knownGoodProbeFrames());
		});
		for (const method of REPLAY_SURFACE) {
			expect(called.has(method), `probe exercises ${method}`).to.equal(true);
		}
		// BOTH outbox deletion shapes ran: the filtered path (a message-type
		// list) is a distinct storage path from the unfiltered sweep.
		expect(
			outboxDeletions.some((types) => Array.isArray(types)),
			'the FILTERED outbox deletion ran'
		).to.equal(true);
		expect(
			outboxDeletions.some((types) => types == null),
			'the unfiltered outbox deletion ran'
		).to.equal(true);
		scratch.close();
	});

	it('the probe frames carry every mutation variant and populate every snapshot table', () => {
		const frames = knownGoodProbeFrames();
		const carried = new Set<string>();
		for (const frame of frames) {
			for (const mutation of frame.mutations) carried.add(mutation.type);
		}
		expect([...carried].sort()).to.deep.equal(
			Object.keys(PROBE_MUTATION_COVERAGE).sort()
		);
		const snapshot = frames.find((f) => f.snapshot)!.snapshot!;
		for (const field of Object.keys(PROBE_SNAPSHOT_COVERAGE)) {
			const rows = snapshot[field as keyof typeof snapshot] as unknown[];
			expect(Array.isArray(rows), `${field} is an array`).to.equal(true);
			expect(rows.length, `${field} is populated`).to.be.greaterThan(0);
		}
		expect(
			frames.some((f) => f.outboundMessages.length > 0),
			'the outbox insert path is exercised by a delta'
		).to.equal(true);
	});

	// One broken scratch method per case, with a candidate whose replay
	// genuinely touches it: every failure must propagate RAW (validator
	// infrastructure), never launder into a Tier-1 downgrade of valid
	// Tier-2 content. Before round 17 the probe left these tables
	// unexercised, so a backend broken on them misclassified the capsule.
	const faultMatrix: Array<{
		method: string;
		mutations: RecoveryMutation[];
		outbound?: RecoveryOutboundMessage[];
	}> = [
		{ method: 'saveChannel', mutations: [probeChannelMutation()] },
		{
			method: 'saveChainMonitor',
			mutations: [
				{
					type: 'chain_monitor',
					channelId: 'dc'.repeat(32),
					state: {
						monitorState: MonitorState.WATCHING,
						commitmentBroadcast: null,
						trackedOutputs: [],
						currentBlockHeight: 0
					}
				}
			]
		},
		{
			method: 'savePayment',
			mutations: [
				{
					type: 'payment_state',
					paymentHash: 'ee'.repeat(32),
					payment: {
						paymentHash: Buffer.alloc(32, 0xee),
						amountMsat: 1n,
						status: PaymentStatus.COMPLETED,
						direction: PaymentDirection.OUTGOING,
						createdAt: 0
					}
				}
			]
		},
		{
			method: 'saveInvoice',
			mutations: [
				{
					type: 'invoice_state',
					paymentHash: 'ee'.repeat(32),
					invoice: {
						paymentHash: 'ee'.repeat(32),
						bolt11: 'lnbcrt1round17',
						expiry: 3600,
						createdAt: 0
					}
				}
			]
		},
		{
			method: 'saveForwardingEvent',
			mutations: [
				{
					type: 'forwarding_event',
					event: {
						settledAt: 3,
						inChannelId: 'dc'.repeat(32),
						outChannelId: 'dc'.repeat(32),
						amountInMsat: 2n,
						amountOutMsat: 1n,
						feeMsat: 1n
					}
				}
			]
		},
		{
			method: 'saveOutboxMessage',
			mutations: [],
			outbound: [
				{
					peerId: getPublicKey(Buffer.alloc(32, 21)).toString('hex'),
					channelId: 'dc'.repeat(32),
					messageType: 136,
					wireMessage: Buffer.from([0]),
					disposition: 'pending_send'
				}
			]
		},
		{
			method: 'deleteChannel',
			mutations: [
				probeChannelMutation(),
				{ type: 'channel_closed', channelId: 'dc'.repeat(32) }
			]
		}
	];

	for (const entry of faultMatrix) {
		it(`a backend broken on ${entry.method} propagates raw`, () => {
			const { storage, manager } = journaledStorage(1, 40);
			expect(
				manager.commit({
					criticality: RecoveryCriticality.SafetyCritical,
					mutations: entry.mutations,
					outboundMessages: entry.outbound ?? []
				}).committed
			).to.equal(true);
			const { blob } = composeRecoveryCapsule({
				storage,
				encryptedScb: makeScb(),
				nodeSecret: NODE_SECRET
			});
			const target = openStorage();
			const broken = (): SqliteStorage => {
				const scratch = scratchStorage();
				(scratch as unknown as Record<string, unknown>)[entry.method] =
					(): void => {
						throw new Error(`scratch ${entry.method} broken`);
					};
				return scratch;
			};
			expect(() =>
				restoreBestRecoveryCapsule([blob], target, NODE_SECRET, {
					scratchStorage: broken
				})
			).to.throw(new RegExp(`scratch ${entry.method} broken`));
			expect(
				target.loadRecoveryFrames!(),
				'the target was never touched'
			).to.have.length(0);
			target.close();
			storage.close();
		});
	}

	it('a transient scratch failure is retried, not misread as a content defect', () => {
		// The FIRST scratch instance fails a table write; every later one is
		// healthy. The candidate must reproduce its failure on a fresh,
		// probe-proven instance before it may be classified as content, so a
		// one-shot hiccup restores Tier 2 instead of silently degrading.
		const { storage, manager } = journaledStorage(1, 50);
		expect(
			manager.commit({
				criticality: RecoveryCriticality.SafetyCritical,
				mutations: [probeChannelMutation()],
				outboundMessages: []
			}).committed
		).to.equal(true);
		const { blob } = composeRecoveryCapsule({
			storage,
			encryptedScb: makeScb(),
			nodeSecret: NODE_SECRET
		});
		const target = openStorage();
		let scratchInstances = 0;
		const flaky = (): SqliteStorage => {
			const scratch = scratchStorage();
			scratchInstances++;
			if (scratchInstances === 1) {
				scratch.saveChannel = (): void => {
					throw new Error('transient scratch hiccup');
				};
			}
			return scratch;
		};
		const result = restoreBestRecoveryCapsule([blob], target, NODE_SECRET, {
			scratchStorage: flaky
		});
		expect(result.tier, 'restored at Tier 2 despite the hiccup').to.equal(2);
		expect(scratchInstances, 'a fresh instance decided').to.be.greaterThan(1);
		expect(
			target.loadAllChannels().map((c) => c.channelId),
			'the candidate channel restored'
		).to.include('dc'.repeat(32));
		target.close();
		storage.close();
	});

	it('a capsule carrying forwarding and outbox rows restores them at Tier 2', () => {
		const { storage, manager } = journaledStorage(1, 60);
		expect(
			manager.commit({
				criticality: RecoveryCriticality.SafetyCritical,
				mutations: [
					{
						type: 'forwarding_event',
						event: {
							settledAt: 4,
							inChannelId: 'dc'.repeat(32),
							outChannelId: 'dc'.repeat(32),
							amountInMsat: 5n,
							amountOutMsat: 4n,
							feeMsat: 1n
						}
					}
				],
				outboundMessages: [
					{
						peerId: getPublicKey(Buffer.alloc(32, 21)).toString('hex'),
						channelId: 'dc'.repeat(32),
						messageType: 136,
						wireMessage: Buffer.from([0]),
						disposition: 'pending_send'
					}
				]
			}).committed
		).to.equal(true);
		const { blob } = composeRecoveryCapsule({
			storage,
			encryptedScb: makeScb(),
			nodeSecret: NODE_SECRET
		});
		const target = openStorage();
		const result = restoreBestRecoveryCapsule([blob], target, NODE_SECRET, {
			scratchStorage
		});
		expect(result.tier).to.equal(2);
		expect(
			(target.listForwardingEvents?.() ?? []).length,
			'the forwarding ledger survived the round trip'
		).to.be.greaterThan(0);
		target.close();
		storage.close();
	});
});

describe('Recovery phase 3: round-18 validator hardening', () => {
	it('a scratch that MUTATES the frames and fails cannot poison the retry', () => {
		// The first scratch instance corrupts a decoded object (foreign
		// adapter code holds real references) and then fails. The retry
		// must decode a FRESH authenticated frame graph: reusing the
		// mutated one made the reproduction fail for the scratch's own
		// reasons and downgraded a valid capsule to Tier 1.
		const { storage, manager } = journaledStorage(1, 70);
		expect(
			manager.commit({
				criticality: RecoveryCriticality.SafetyCritical,
				mutations: [
					{
						type: 'invoice_state',
						paymentHash: 'ef'.repeat(32),
						invoice: {
							paymentHash: 'ef'.repeat(32),
							bolt11: 'lnbcrt1round18',
							expiry: 3600,
							createdAt: 0
						}
					}
				],
				outboundMessages: []
			}).committed
		).to.equal(true);
		const { blob } = composeRecoveryCapsule({
			storage,
			encryptedScb: makeScb(),
			nodeSecret: NODE_SECRET
		});
		const target = openStorage();
		let scratchInstances = 0;
		const mutating = (): SqliteStorage => {
			const scratch = scratchStorage();
			scratchInstances++;
			if (scratchInstances === 1) {
				scratch.saveInvoice = (_hash, invoice): void => {
					// Corrupt the DECODED object the replay handed us, then
					// fail: a reused graph would now violate NOT NULL on the
					// retry and read as a content defect.
					(invoice as { paymentHash?: string }).paymentHash = undefined;
					throw new Error('transient mutating hiccup');
				};
			}
			return scratch;
		};
		const result = restoreBestRecoveryCapsule([blob], target, NODE_SECRET, {
			scratchStorage: mutating
		});
		expect(result.tier, 'restored at Tier 2 despite the mutation').to.equal(2);
		expect(
			target.loadAllInvoices().map((row) => row.paymentHashHex),
			'the invoice restored from an UNMUTATED decode'
		).to.include('ef'.repeat(32));
		target.close();
		storage.close();
	});

	it('a backend whose transaction COMMIT is broken propagates raw', () => {
		// The rolled-back health probe never exercises successful commit
		// completion, so a backend failing exactly at commit used to fail
		// the candidate twice and read as a content defect. The deciding
		// instance must also COMPLETE a probe commit before a reproduced
		// candidate failure may be typed as content.
		const { storage } = journaledStorage(2, 80);
		const { blob } = composeRecoveryCapsule({
			storage,
			encryptedScb: makeScb(),
			nodeSecret: NODE_SECRET
		});
		const target = openStorage();
		const commitBroken = (): SqliteStorage => {
			const scratch = scratchStorage();
			const real = scratch.transaction.bind(scratch);
			(scratch as unknown as Record<string, unknown>).transaction = (
				fn: () => unknown
			): unknown => {
				const value = real(fn);
				// The work succeeded; the COMMIT boundary is what fails.
				throw new Error('scratch commit broken');
				return value;
			};
			return scratch;
		};
		expect(() =>
			restoreBestRecoveryCapsule([blob], target, NODE_SECRET, {
				scratchStorage: commitBroken
			})
		).to.throw(/scratch commit broken/);
		expect(
			target.loadRecoveryFrames!(),
			'the target was never touched'
		).to.have.length(0);
		target.close();
		storage.close();
	});

	it('a backend broken on FILTERED outbox deletion propagates raw', () => {
		// deleteOutboxMessages with a message-type list reaches a different
		// storage path than the unfiltered sweep; the probe must exercise
		// both, or a backend broken on the filtered shape misclassifies a
		// capsule whose deltas carry a filtered supersede.
		const { storage, manager } = journaledStorage(1, 90);
		expect(
			manager.commit({
				criticality: RecoveryCriticality.SafetyCritical,
				mutations: [
					{
						type: 'outbox_supersede',
						channelId: 'dc'.repeat(32),
						messageTypes: [133]
					}
				],
				outboundMessages: []
			}).committed
		).to.equal(true);
		const { blob } = composeRecoveryCapsule({
			storage,
			encryptedScb: makeScb(),
			nodeSecret: NODE_SECRET
		});
		const target = openStorage();
		const broken = (): SqliteStorage => {
			const scratch = scratchStorage();
			const real = scratch.deleteOutboxMessages!.bind(scratch);
			scratch.deleteOutboxMessages = (
				channelId: string,
				messageTypes?: number[]
			): void => {
				if (messageTypes != null) {
					throw new Error('scratch filtered outbox deletion broken');
				}
				real(channelId, messageTypes);
			};
			return scratch;
		};
		expect(() =>
			restoreBestRecoveryCapsule([blob], target, NODE_SECRET, {
				scratchStorage: broken
			})
		).to.throw(/scratch filtered outbox deletion broken/);
		expect(target.loadRecoveryFrames!()).to.have.length(0);
		target.close();
		storage.close();
	});
});
