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
	CAPSULE_MAX_BYTES,
	composeRecoveryCapsule,
	decodeRecoveryCapsuleBlob,
	encryptRecoveryCapsule,
	restoreFromRecoveryCapsule,
	selectRecoveryCapsule,
	deriveRecoveryMasterKey
} from '../../src/lightning/recovery';
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

/** A journaled storage with a few committed transitions. */
function journaledStorage(transitions = 3): {
	storage: SqliteStorage;
	journal: RecoveryJournal;
} {
	const storage = openStorage();
	const journal = new RecoveryJournal(
		storage,
		deriveRecoveryMasterKey(NODE_SECRET),
		getPublicKey(NODE_SECRET)
	);
	const manager = new RecoveryManager(storage, { journal });
	for (let i = 0; i < transitions; i++) {
		const result = manager.commit({
			criticality: RecoveryCriticality.SafetyCritical,
			mutations: [
				{
					type: 'payment_preimage',
					paymentHash: Buffer.alloc(32, i + 1).toString('hex'),
					preimage: Buffer.alloc(32, i + 1)
				}
			],
			outboundMessages: []
		});
		expect(result.committed).to.equal(true);
	}
	return { storage, journal };
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

		// Restore side: scan candidates like a real restore would; the foreign
		// garbage blob is ignored, ours decodes.
		const candidates = [crypto.randomBytes(300), blob!]
			.map((b) =>
				decodeRecoveryCapsuleBlob(b, makeNodeConfig(1).nodePrivateKey)
			)
			.filter((c): c is RecoveryCapsule => c !== null);
		expect(candidates).to.have.length(1);
		const capsule = selectRecoveryCapsule(candidates)!;
		expect(
			capsule.inlineRecoveryState,
			'small wallet fits inline'
		).to.not.equal(undefined);

		// Tier 2: byte-identical restore into a fresh database.
		const restoredStorage = openStorage();
		const result = restoreFromRecoveryCapsule(
			capsule,
			restoredStorage,
			makeNodeConfig(1).nodePrivateKey
		);
		expect(result.tier).to.equal(2);
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
