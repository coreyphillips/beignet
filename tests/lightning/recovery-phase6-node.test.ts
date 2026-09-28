/**
 * Recovery Protocol phase 6, part 5: the barrier as the node wires it
 * (docs/RECOVERY-PROTOCOL.md 5.8, section 8 and 9).
 *
 * The invariants under test:
 *
 * 1. A journal in quorum mode with no enforcing barrier REFUSES to start.
 *    Continuing would put revoke_and_ack on the wire unbarriered beneath a
 *    certified head that still reads 'quorum', and a later restore of that
 *    chain would claim an exactness it does not have.
 * 2. Every journaled commit hands its frame to replication without waiting,
 *    which is what makes the node a driver of durability rather than a
 *    consumer of it.
 * 3. An advancing watermark releases the compaction the journal held back
 *    for a lagging replica.
 * 4. getRecoveryStatus answers the section 8 questions: the mode, how far
 *    replication provably got, and which channels are waiting.
 * 5. Shutting the node down refuses what is held rather than leaving it
 *    parked on a timer.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import {
	INodeConfig,
	IPaymentInfo,
	InvalidRequestError,
	LightningErrorCode,
	LightningPaymentError,
	PaymentDirection,
	PaymentStatus
} from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import { encode as encodeInvoice } from '../../src/lightning/invoice/encode';
import {
	DEFAULT_CHANNEL_CONFIG,
	REGTEST_CHAIN_HASH
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { IStorageBackend } from '../../src/lightning/storage/types';
import {
	CRASH_V1_PROFILE,
	DurabilityBarrier,
	GuardianClient,
	GuardianHttpServer,
	GuardianReplicator,
	GuardianStartupGate,
	IBoundGuardianClient,
	IWriterLeaseKeys,
	JOURNAL_META_KEYS,
	RecoveryCriticality,
	RecoveryJournal,
	RecoveryManager,
	ReferenceGuardian,
	computeGuardianSetId,
	deriveRecoveryMasterKey,
	deriveRecoveryRoot,
	xOnlyFromSecret
} from '../../src/lightning/recovery';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	IChannelAnnouncementMessage,
	IChannelUpdateMessage,
	encodeShortChannelId
} from '../../src/lightning/gossip/types';
import {
	connectNodes,
	createNode as createLoopbackNode,
	openReadyChannel
} from './helpers/loopback-nodes';

const sha = (s: string): Buffer =>
	crypto.createHash('sha256').update(s).digest();

const GUARDIAN_SECRETS = [1, 2, 3].map((i) => sha(`p6-node-guardian-${i}`));
const GUARDIAN_IDS = GUARDIAN_SECRETS.map((s) => xOnlyFromSecret(s));
const SET_ID = computeGuardianSetId({
	...CRASH_V1_PROFILE,
	guardianIds: GUARDIAN_IDS
});
const CONTEXT = { guardianSetId: SET_ID, members: GUARDIAN_IDS };

let now = 2_220_000_000_000n;
const clock = (): bigint => ++now;

interface IServed {
	guardian: ReferenceGuardian;
	server: GuardianHttpServer;
	client: GuardianClient;
	id: Buffer;
}

async function serve(index: number): Promise<IServed> {
	const guardian = new ReferenceGuardian({
		path: ':memory:',
		guardianSecret: GUARDIAN_SECRETS[index],
		members: GUARDIAN_IDS,
		clock
	});
	const server = new GuardianHttpServer({ guardian });
	const port = await server.listen(0);
	const client = new GuardianClient({
		url: `http://127.0.0.1:${port}`,
		guardianSetId: SET_ID
	});
	return { guardian, server, client, id: GUARDIAN_IDS[index] };
}

function bind(served: IServed[]): IBoundGuardianClient[] {
	return served.map((entry) => ({
		client: entry.client,
		expectedGuardianId: entry.id
	}));
}

async function shutdown(served: IServed[]): Promise<void> {
	for (const entry of served) {
		try {
			await entry.server.close();
			entry.guardian.close();
		} catch {
			// Already closed by the test.
		}
	}
}

function makeSeed(id: number): Buffer {
	return sha(`p6-node-seed-${id}`);
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

const NODE_SEED = makeSeed(1);
const NODE_SECRET = crypto
	.createHash('sha256')
	.update(NODE_SEED)
	.update(Buffer.from('node-identity'))
	.digest();
const ROOT = deriveRecoveryRoot(NODE_SECRET);
const NODE_ID = getPublicKey(NODE_SECRET);

function makeNodeConfig(
	storage: IStorageBackend,
	recovery: INodeConfig['recovery']
): INodeConfig {
	return {
		nodePrivateKey: NODE_SECRET,
		network: Network.REGTEST as Network,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(NODE_SEED),
		perCommitmentSeed: makeSeed(101),
		fundingPrivkey: crypto
			.createHash('sha256')
			.update(NODE_SEED)
			.update(Buffer.from([0]))
			.digest(),
		htlcBasepointSecret: crypto
			.createHash('sha256')
			.update(NODE_SEED)
			.update(Buffer.from([4]))
			.digest(),
		storage,
		recovery
	};
}

function createNode(
	storage: IStorageBackend,
	recovery: INodeConfig['recovery']
): LightningNode {
	const node = new LightningNode(makeNodeConfig(storage, recovery));
	node.on('error', () => {});
	node.on('node:error', () => {});
	return node;
}

function openStorage(): SqliteStorage {
	const storage = new SqliteStorage(':memory:');
	storage.open();
	return storage;
}

function addTenHopRoute(
	payer: LightningNode,
	firstHop: LightningNode,
	channelId: Buffer
): Buffer {
	const nodes = [
		Buffer.from(payer.getNodeId(), 'hex'),
		Buffer.from(firstHop.getNodeId(), 'hex')
	];
	for (let i = 2; i <= 10; i++) {
		nodes.push(getPublicKey(sha(`keysend-route-${i}`)));
	}

	for (let i = 0; i < 10; i++) {
		const shortChannelId = encodeShortChannelId({
			block: 700,
			txIndex: i + 1,
			outputIndex: 0
		});
		const [nodeId1, nodeId2] =
			Buffer.compare(nodes[i], nodes[i + 1]) < 0
				? [nodes[i], nodes[i + 1]]
				: [nodes[i + 1], nodes[i]];
		const announcement: IChannelAnnouncementMessage = {
			nodeSignature1: Buffer.alloc(64),
			nodeSignature2: Buffer.alloc(64),
			bitcoinSignature1: Buffer.alloc(64),
			bitcoinSignature2: Buffer.alloc(64),
			features: Buffer.alloc(0),
			chainHash: REGTEST_CHAIN_HASH,
			shortChannelId,
			nodeId1,
			nodeId2,
			bitcoinKey1: Buffer.alloc(33, 2),
			bitcoinKey2: Buffer.alloc(33, 3)
		};
		payer.getGraph().addChannelAnnouncement(announcement);
		const update: IChannelUpdateMessage = {
			signature: Buffer.alloc(64),
			chainHash: REGTEST_CHAIN_HASH,
			shortChannelId,
			timestamp: Math.floor(Date.now() / 1000),
			messageFlags: 1,
			channelFlags: 0,
			cltvExpiryDelta: 40,
			htlcMinimumMsat: 1_000n,
			feeBaseMsat: 1_000,
			feeProportionalMillionths: 1,
			htlcMaximumMsat: 1_000_000_000n
		};
		payer.getGraph().applyChannelUpdate(update);
		payer.getGraph().applyChannelUpdate({ ...update, channelFlags: 1 });
		if (i === 0) payer.registerChannelScid(channelId, shortChannelId);
	}
	return nodes[10];
}

function replicatorFor(
	storage: IStorageBackend,
	guardians: IBoundGuardianClient[]
): GuardianReplicator {
	return new GuardianReplicator({
		storage,
		guardians,
		context: CONTEXT,
		required: CRASH_V1_PROFILE.required,
		recoveryRoot: ROOT,
		clock
	});
}

function barrierFor(
	replicator: GuardianReplicator,
	lease: () => IWriterLeaseKeys | null,
	durability: 'local' | 'async-remote' | 'quorum'
): DurabilityBarrier {
	return new DurabilityBarrier({
		durability,
		replicator,
		lease,
		timeoutMs: 2_000,
		retryDelayMs: 50
	});
}

async function waitFor(
	condition: () => boolean,
	timeoutMs = 8_000
): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (!condition()) {
		if (Date.now() > deadline) throw new Error('waitFor timed out');
		await new Promise((resolve) => setTimeout(resolve, 25));
	}
}

// ─────────────── Tests ───────────────

describe('Recovery phase 6: a quorum chain will not run unbarriered', () => {
	it('a node REFUSES to start when its journal promised quorum and nothing enforces it', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storage = openStorage();

		// A first run in quorum mode leaves quorum frames and the meta floor.
		const journal = new RecoveryJournal(
			storage,
			deriveRecoveryMasterKey(NODE_SECRET),
			NODE_ID,
			ROOT.recoveryId,
			{ durability: 'quorum' }
		);
		new RecoveryManager(storage, { journal }).commit({
			criticality: RecoveryCriticality.SafetyCritical,
			mutations: [
				{
					type: 'payment_preimage',
					paymentHash: sha('promised').toString('hex'),
					preimage: sha('promised-preimage')
				}
			],
			outboundMessages: []
		});
		expect(storage.getRecoveryMeta(JOURNAL_META_KEYS.durabilityFloor)).to.equal(
			'quorum'
		);

		// A second run with the guardians dropped from config. Starting would
		// send revoke_and_ack unbarriered under a certified head that reads
		// 'quorum', and a later restore would trust it.
		expect(() =>
			createNode(storage, { enabled: true, durability: 'async-remote' })
		).to.throw(/quorum/);

		await shutdown(served);
		storage.close();
	});

	it('removing the recovery block ENTIRELY is refused too', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storage = openStorage();
		const journal = new RecoveryJournal(
			storage,
			deriveRecoveryMasterKey(NODE_SECRET),
			NODE_ID,
			ROOT.recoveryId,
			{ durability: 'quorum' }
		);
		new RecoveryManager(storage, { journal }).commit({
			criticality: RecoveryCriticality.SafetyCritical,
			mutations: [
				{
					type: 'payment_preimage',
					paymentHash: sha('whole-block').toString('hex'),
					preimage: sha('whole-block-preimage')
				}
			],
			outboundMessages: []
		});

		// The quadrant a guard keyed on the JOURNAL OBJECT cannot see, and the
		// most natural way an operator turns recovery off: dropping the block
		// removes the journal and the barrier together, so a check on either
		// one alone short-circuits. The node would then advance its channels
		// while appending nothing, leaving the certified head reading 'quorum'
		// but describing state the peers have long since moved past, and a
		// later restore would resume on a commitment the peer can punish.
		// The check is therefore on the DATABASE.
		expect(() => createNode(storage, undefined)).to.throw(/quorum/);
		expect(() => createNode(storage, { enabled: false })).to.throw(/quorum/);

		await shutdown(served);
		storage.close();
	});

	it('an enforcing barrier with NO JOURNAL is refused, not silently inert', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storage = openStorage();
		const replicator = replicatorFor(storage, bind(served));
		const barrier = barrierFor(replicator, () => null, 'quorum');

		// The mirror image of the case above, and worse because it looks like
		// it is working: with no journal every batch reports frameSequence
		// null, every barrier answers yes, and quorum mode would hold nothing
		// at all while claiming to.
		expect(() =>
			createNode(storage, { enabled: false, durability: 'quorum', barrier })
		).to.throw(/journal/);

		await shutdown(served);
		storage.close();
	});

	it('the same chain starts fine once the barrier is back', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storage = openStorage();
		const journal = new RecoveryJournal(
			storage,
			deriveRecoveryMasterKey(NODE_SECRET),
			NODE_ID,
			ROOT.recoveryId,
			{ durability: 'quorum' }
		);
		new RecoveryManager(storage, { journal }).commit({
			criticality: RecoveryCriticality.SafetyCritical,
			mutations: [
				{
					type: 'payment_preimage',
					paymentHash: sha('restored').toString('hex'),
					preimage: sha('restored-preimage')
				}
			],
			outboundMessages: []
		});

		const replicator = replicatorFor(storage, bind(served));
		const barrier = barrierFor(replicator, () => null, 'quorum');
		const node = createNode(storage, {
			enabled: true,
			durability: 'quorum',
			barrier
		});
		expect(node.getRecoveryStatus().durability).to.equal('quorum');
		node.destroy();
		await shutdown(served);
	});
});

describe('Recovery phase 6: the node drives durability', () => {
	it('a journaled commit replicates WITHOUT the caller waiting for it', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storage = openStorage();
		const replicator = replicatorFor(storage, bind(served));
		let lease: IWriterLeaseKeys | null = null;
		const barrier = barrierFor(replicator, () => lease, 'async-remote');
		const node = createNode(storage, {
			enabled: true,
			durability: 'async-remote',
			barrier
		});
		lease = (
			(await replicator.ensureNamespace()) as { lease: IWriterLeaseKeys }
		).lease;

		// Any journaled write will do; the point is that the node kicked the
		// pump and nothing in the write path blocked on the answer.
		(
			node as unknown as {
				recovery: RecoveryManager;
			}
		).recovery.commit({
			criticality: RecoveryCriticality.SafetyCritical,
			mutations: [
				{
					type: 'payment_preimage',
					paymentHash: sha('driven').toString('hex'),
					preimage: sha('driven-preimage')
				}
			],
			outboundMessages: []
		});

		await waitFor(() => replicator.replicatedThrough() > 0n);
		expect(node.getRecoveryStatus().lastDurableSequence).to.not.equal('0');
		node.destroy();
		await shutdown(served);
		storage.close();
	});

	it('an advancing watermark releases the compaction a lagging replica held back', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storage = openStorage();
		const replicator = replicatorFor(storage, bind(served));
		let lease: IWriterLeaseKeys | null = null;
		const barrier = barrierFor(replicator, () => lease, 'async-remote');
		const node = createNode(storage, {
			enabled: true,
			durability: 'async-remote',
			barrier,
			snapshotIntervalFrames: 2
		});
		const recovery = (node as unknown as { recovery: RecoveryManager })
			.recovery;

		// Commit while replication cannot run: the writer lease does not exist
		// yet, so snapshots pile up unpruned rather than deleting frames the
		// guardians have never seen.
		for (let i = 0; i < 6; i++) {
			recovery.commit({
				criticality: RecoveryCriticality.SafetyCritical,
				mutations: [
					{
						type: 'payment_preimage',
						paymentHash: Buffer.alloc(32, 40 + i).toString('hex'),
						preimage: Buffer.alloc(32, 40 + i)
					}
				],
				outboundMessages: []
			});
		}
		const heldBack = storage.loadRecoveryFrames().length;
		expect(storage.loadRecoveryFrames()[0].sequence).to.equal(1);

		lease = (
			(await replicator.ensureNamespace()) as { lease: IWriterLeaseKeys }
		).lease;
		barrier.kickReplication();
		await waitFor(() => storage.loadRecoveryFrames().length < heldBack);
		// The chain still verifies from its new base.
		expect(storage.loadRecoveryFrames()[0].sequence).to.equal(
			Number(storage.getRecoveryMeta(JOURNAL_META_KEYS.lastSnapshot))
		);

		node.destroy();
		await shutdown(served);
		storage.close();
	});

	it('holds snapshots under the record limit the guardian set advertises (issue #1014)', async function (): Promise<void> {
		const storage = openStorage();
		for (let i = 0; i < 20; i++) {
			storage.saveForwardingEvent({
				settledAt: 1_700_000_000_000 + i,
				inChannelId: Buffer.alloc(32, 1).toString('hex'),
				outChannelId: Buffer.alloc(32, 2).toString('hex'),
				amountInMsat: 1_001_000n,
				amountOutMsat: 1_000_000n,
				feeMsat: 1_000n
			});
		}
		// No lease, so nothing is ever sent to these endpoints.
		const replicator = replicatorFor(
			storage,
			GUARDIAN_IDS.map((id) => ({
				client: new GuardianClient({
					url: 'http://127.0.0.1:9',
					guardianSetId: SET_ID
				}),
				expectedGuardianId: id
			}))
		);
		replicator.maxRecordBytes = (): number => 64;
		const barrier = barrierFor(replicator, () => null, 'async-remote');
		const node = createNode(storage, {
			enabled: true,
			durability: 'async-remote',
			barrier
		});
		const actions: string[] = [];
		node.on('log', (log: { action: string }) => actions.push(log.action));

		expect(
			(node as unknown as { recovery: RecoveryManager }).recovery.commit({
				criticality: RecoveryCriticality.SafetyCritical,
				mutations: [
					{
						type: 'payment_preimage',
						paymentHash: sha('limited').toString('hex'),
						preimage: sha('limited-preimage')
					}
				],
				outboundMessages: []
			}).committed
		).to.equal(true);
		await waitFor(() => actions.includes('recovery_frame_oversized'));
		expect(actions).to.include('recovery_snapshot_trimmed');

		const journal = new RecoveryJournal(
			storage,
			deriveRecoveryMasterKey(NODE_SECRET),
			NODE_ID,
			ROOT.recoveryId
		);
		const [snapshot] = journal.loadVerifiedFrames();
		expect(snapshot.snapshot!.forwardingEvents).to.have.length(0);
		node.destroy();
		storage.close();
	});

	it('refuses oversized payment metadata and routed keysend state (issue #1134)', async function (): Promise<void> {
		const CEILING = 5_000;
		const storage = openStorage();
		// No lease, so nothing is ever sent to these endpoints.
		const replicator = replicatorFor(
			storage,
			GUARDIAN_IDS.map((id) => ({
				client: new GuardianClient({
					url: 'http://127.0.0.1:9',
					guardianSetId: SET_ID
				}),
				expectedGuardianId: id
			}))
		);
		replicator.maxRecordBytes = (): number => CEILING;
		const barrier = barrierFor(replicator, () => null, 'async-remote');
		const node = createNode(storage, {
			enabled: true,
			durability: 'async-remote',
			barrier
		});
		const actions: string[] = [];
		node.on('log', (log: { action: string }) => actions.push(log.action));

		const hash = sha('labelled');
		const payment: IPaymentInfo = {
			paymentHash: hash,
			preimage: sha('labelled-preimage'),
			amountMsat: 1_000_000n,
			status: PaymentStatus.COMPLETED,
			direction: PaymentDirection.OUTGOING,
			createdAt: 1_700_000_000_000,
			completedAt: 1_700_000_001_000
		};
		storage.savePayment(hash.toString('hex'), payment);
		(node as unknown as { payments: Map<string, IPaymentInfo> }).payments.set(
			hash.toString('hex'),
			payment
		);

		// Larger than an empty page on its own: before, it was saved, and the
		// bootstrap snapshot's page carrying it was refused by every guardian.
		expect(() =>
			node.setPaymentMetadata(hash, { note: 'x'.repeat(10_000) })
		).to.throw(InvalidRequestError, /too large/);
		// Would fit a frame today, but leaves no room for the row to grow.
		expect(() =>
			node.setPaymentMetadata(hash, { note: 'x'.repeat(3_000) })
		).to.throw(InvalidRequestError, /too large/);
		expect(node.getPayment(hash)!.metadata).to.equal(undefined);
		expect(storage.loadPayment(hash.toString('hex'))!.metadata).to.equal(
			undefined
		);
		expect(storage.loadRecoveryFrames()).to.have.length(0);

		// Keysend takes caller metadata into its row too.
		expect(() =>
			node.sendKeysend({
				destination: getPublicKey(sha('keysend-payee')),
				amountMsat: 1_000n,
				metadata: { note: 'x'.repeat(10_000) }
			})
		)
			.to.throw(LightningPaymentError, /too large/)
			.with.property('code', LightningErrorCode.INVALID_KEYSEND);

		// A label that fits lands, and the bootstrap snapshot it triggers stays
		// under the limit.
		node.setPaymentMetadata(hash, { note: 'coffee' });
		const frames = storage.loadRecoveryFrames();
		expect(frames).to.not.have.length(0);
		for (const frame of frames) {
			expect(frame.ciphertext.length).to.be.at.most(CEILING);
		}
		expect(storage.loadPayment(hash.toString('hex'))!.metadata).to.deep.equal({
			note: 'coffee'
		});
		await new Promise((resolve) => setImmediate(resolve));
		expect(actions).to.not.include('recovery_frame_oversized');
		const firstHop = createLoopbackNode('keysend-frame-limit', 2);
		connectNodes(node, firstHop);
		const channelId = openReadyChannel(node, firstHop);
		const destination = addTenHopRoute(node, firstHop, channelId);
		const beforeCounter = node
			.getChannelManager()
			.getChannel(channelId)!
			.getFullState().localHtlcCounter;
		const beforeFrames = storage.loadRecoveryFrames().length;
		const internals = node as unknown as {
			paymentRetryContexts: Map<string, unknown>;
			htlcPaymentMap: Map<string, string>;
		};
		const beforePayments = node.listPayments().length;

		expect(() =>
			node.sendKeysend({
				destination,
				amountMsat: 1_000n,
				metadata: { note: 'x'.repeat(2_000) }
			})
		)
			.to.throw(LightningPaymentError, /too large/)
			.with.property('code', LightningErrorCode.INVALID_KEYSEND);
		expect(node.listPayments()).to.have.length(beforePayments);
		expect(internals.paymentRetryContexts.size).to.equal(0);
		expect(internals.htlcPaymentMap.size).to.equal(0);
		expect(
			node.getChannelManager().getChannel(channelId)!.getFullState()
				.localHtlcCounter
		).to.equal(beforeCounter);
		expect(storage.loadRecoveryFrames()).to.have.length(beforeFrames);

		firstHop.destroy();
		node.destroy();
		storage.close();
	});

	it('labels, stores and journals a first invoice payment, and refuses metadata over the ceiling (issue #1152)', async function (): Promise<void> {
		const CEILING = 5_000;
		const storage = openStorage();
		// No lease, so nothing is ever sent to these endpoints.
		const replicator = replicatorFor(
			storage,
			GUARDIAN_IDS.map((id) => ({
				client: new GuardianClient({
					url: 'http://127.0.0.1:9',
					guardianSetId: SET_ID
				}),
				expectedGuardianId: id
			}))
		);
		replicator.maxRecordBytes = (): number => CEILING;
		const barrier = barrierFor(replicator, () => null, 'async-remote');
		const node = createNode(storage, {
			enabled: true,
			durability: 'async-remote',
			barrier
		});
		const payee = createLoopbackNode('first-invoice-metadata', 2);
		connectNodes(node, payee);
		node.handleNewBlock(1000);
		payee.handleNewBlock(1000);
		const channelId = openReadyChannel(node, payee);
		const farPayee = addTenHopRoute(node, payee, channelId);

		// A hash with no record yet: the send creates it, labels and all.
		const invoice = payee.createInvoice({
			amountMsat: 5_000_000n,
			description: 'first'
		});
		const hashHex = invoice.paymentHash.toString('hex');
		expect(node.getPayment(invoice.paymentHash)).to.equal(undefined);
		node.sendPaymentWithOptions(invoice.bolt11, {
			metadata: { requestId: 'req-1' }
		});
		const resolution = await node.awaitPaymentResolution(
			invoice.paymentHash,
			5_000
		);
		expect(resolution.status).to.equal(PaymentStatus.COMPLETED);
		expect(node.getPayment(invoice.paymentHash)!.metadata).to.include({
			requestId: 'req-1'
		});
		expect(storage.loadPayment(hashHex)!.metadata).to.include({
			requestId: 'req-1'
		});
		const journal = new RecoveryJournal(
			storage,
			deriveRecoveryMasterKey(NODE_SECRET),
			NODE_ID,
			ROOT.recoveryId
		);
		const journaled: IPaymentInfo[] = [];
		for (const frame of journal.loadVerifiedFrames()) {
			for (const mutation of frame.mutations) {
				if (
					mutation.type === 'payment_state' &&
					mutation.paymentHash === hashHex
				) {
					journaled.push(mutation.payment);
				}
			}
			for (const row of frame.snapshot?.payments ?? []) {
				if (row.paymentHash === hashHex) journaled.push(row.payment);
			}
		}
		// From the PENDING row written before the HTLC left, on.
		expect(journaled.map((p) => p.status)).to.include(PaymentStatus.PENDING);
		for (const payment of journaled) {
			expect(payment.metadata).to.include({ requestId: 'req-1' });
		}

		const htlcCounter = (): bigint =>
			node.getChannelManager().getChannel(channelId)!.getFullState()
				.localHtlcCounter;
		const beforeCounter = htlcCounter();
		const beforeFrames = storage.loadRecoveryFrames().length;
		const beforePayments = node.listPayments().length;

		// Too large for any row: refused before a record or an HTLC exists.
		const second = payee.createInvoice({
			amountMsat: 5_000_000n,
			description: 'second'
		});
		expect(() =>
			node.sendPaymentWithOptions(second.bolt11, {
				metadata: { note: 'x'.repeat(10_000) }
			})
		).to.throw(InvalidRequestError, /too large/);

		// Fits the metadata half of a frame, but not beside a ten-hop route.
		const room = (
			node as unknown as {
				recoveryJournal: { mutationRoom(): number };
			}
		).recoveryJournal.mutationRoom();
		const farHash = sha('far-invoice-preimage');
		const farInvoice = encodeInvoice({
			network: Network.REGTEST,
			amountMsat: 1_000n,
			paymentHash: farHash,
			paymentSecret: sha('far-invoice-secret'),
			description: 'far',
			privateKey: sha('keysend-route-10')
		});
		expect(getPublicKey(sha('keysend-route-10'))).to.deep.equal(farPayee);
		expect(() =>
			node.sendPaymentWithOptions(farInvoice, {
				metadata: { note: 'x'.repeat(Math.floor(room / 2) - 20) }
			})
		).to.throw(InvalidRequestError, /too large/);
		// A later send of the hash must not retry with the refused labels.
		expect(
			(
				node as unknown as { paymentRetryContexts: Map<string, unknown> }
			).paymentRetryContexts.has(farHash.toString('hex'))
		).to.equal(false);

		// The same labels over ten-hop MPP parts, refused before a part leaves.
		const part = {
			hops: Array.from({ length: 10 }, () => ({
				pubkey: farPayee,
				shortChannelId: Buffer.alloc(8),
				amountToForwardMsat: 500n,
				outgoingCltvValue: 400,
				cltvExpiryDelta: 40,
				feeBaseMsat: 1_000,
				feeProportionalMillionths: 1
			})),
			totalAmountMsat: 500n,
			totalCltvDelta: 400,
			totalFeeMsat: 0n
		};
		expect(() =>
			(
				node as unknown as {
					sendPaymentMpp(...args: unknown[]): IPaymentInfo;
				}
			).sendPaymentMpp(
				farInvoice,
				{
					paymentHash: farHash,
					paymentSecret: sha('far-invoice-secret'),
					amountMsat: 1_000n
				},
				{ parts: [part, part], totalAmountMsat: 1_000n, totalFeeMsat: 0n },
				40,
				undefined,
				undefined,
				{ note: 'x'.repeat(Math.floor(room / 2) - 20) }
			)
		).to.throw(InvalidRequestError, /too large/);

		expect(node.getPayment(second.paymentHash)).to.equal(undefined);
		expect(node.getPayment(farHash)).to.equal(undefined);
		expect(node.listPayments()).to.have.length(beforePayments);
		expect(htlcCounter()).to.equal(beforeCounter);
		expect(storage.loadRecoveryFrames()).to.have.length(beforeFrames);

		payee.destroy();
		node.destroy();
		storage.close();
	});

	it('refuses metadata that pushes an expired invoice payment row over the ceiling (issue #1152)', async function (): Promise<void> {
		const storage = openStorage();
		// No lease, so nothing is ever sent to these endpoints.
		const replicator = replicatorFor(
			storage,
			GUARDIAN_IDS.map((id) => ({
				client: new GuardianClient({
					url: 'http://127.0.0.1:9',
					guardianSetId: SET_ID
				}),
				expectedGuardianId: id
			}))
		);
		replicator.maxRecordBytes = (): number => 700;
		const barrier = barrierFor(replicator, () => null, 'async-remote');
		const node = createNode(storage, {
			enabled: true,
			durability: 'async-remote',
			barrier
		});
		const room = (
			node as unknown as {
				recoveryJournal: { mutationRoom(): number };
			}
		).recoveryJournal.mutationRoom();
		const hash = sha('expired-invoice-preimage');
		const expired = encodeInvoice({
			network: Network.REGTEST,
			amountMsat: 1_000n,
			paymentHash: hash,
			paymentSecret: sha('expired-invoice-secret'),
			description: 'expired',
			timestamp: Math.floor(Date.now() / 1000) - 7_200,
			expiry: 60,
			privateKey: sha('expired-invoice-payee')
		});

		// Fits the metadata half of a frame, but not beside the FAILED row.
		expect(() =>
			node.sendPaymentWithOptions(expired, {
				metadata: { note: 'x'.repeat(Math.floor(room / 2) - 20) }
			})
		).to.throw(InvalidRequestError, /too large/);
		expect(node.getPayment(hash)).to.equal(undefined);
		expect(storage.loadRecoveryFrames()).to.have.length(0);

		node.destroy();
		storage.close();
	});
});

describe('Recovery phase 6: the status surface', () => {
	it('reports the mode, the durable head and nothing waiting on a quiet node', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storage = openStorage();
		const replicator = replicatorFor(storage, bind(served));
		const barrier = barrierFor(replicator, () => null, 'quorum');
		const node = createNode(storage, {
			enabled: true,
			durability: 'quorum',
			barrier
		});

		const status = node.getRecoveryStatus();
		expect(status.durability).to.equal('quorum');
		expect(status.lastDurableSequence).to.equal('0');
		expect(status.awaitingDurabilityCount).to.equal(0);
		expect(status.fenced).to.equal(false);
		expect(status.channels).to.deep.equal([]);

		node.destroy();
		await shutdown(served);
		storage.close();
	});

	it('a node with no recovery config reports local and stays out of the way', () => {
		const storage = openStorage();
		const node = createNode(storage, undefined);
		const status = node.getRecoveryStatus();
		expect(status.durability).to.equal('local');
		expect(status.gate).to.equal('disabled');
		expect(status.awaitingDurabilityCount).to.equal(0);
		node.destroy();
		storage.close();
	});

	it('destroy REFUSES what is held instead of leaving it parked', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storage = openStorage();
		const replicator = replicatorFor(storage, bind(served));
		const barrier = barrierFor(replicator, () => null, 'quorum');
		const node = createNode(storage, {
			enabled: true,
			durability: 'quorum',
			barrier
		});

		const held = barrier.whenReleased(99n);
		node.destroy();
		const outcome = await held;
		expect(outcome.released).to.equal(false);
		expect((outcome as { reason: string }).reason).to.equal('stopped');

		await shutdown(served);
		storage.close();
	});
});

describe('Recovery phase 6: ownership settling starts replication', () => {
	it('a frame committed before the lease replicates when the gate opens', async function (): Promise<void> {
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storage = openStorage();
		const replicator = replicatorFor(storage, bind(served));
		let lease: IWriterLeaseKeys | null = null;
		const barrier = barrierFor(replicator, () => lease, 'async-remote');
		const gate = new GuardianStartupGate({
			storage,
			replicator,
			required: CRASH_V1_PROFILE.required,
			clock
		});
		const node = createNode(storage, {
			enabled: true,
			durability: 'async-remote',
			barrier,
			startupGate: gate
		});

		// Committed while ownership is still unsettled. The pump runs, finds no
		// lease and nobody waiting, and gives up: that is deliberate, since
		// spinning a timer on an absent lease would never end.
		const commit = (
			node as unknown as { recovery: RecoveryManager }
		).recovery.commit({
			criticality: RecoveryCriticality.SafetyCritical,
			mutations: [
				{
					type: 'payment_preimage',
					paymentHash: sha('pre-lease').toString('hex'),
					preimage: sha('pre-lease-secret')
				}
			],
			outboundMessages: []
		});
		expect(commit.committed).to.equal(true);
		await new Promise((resolve) => setTimeout(resolve, 200));
		expect(replicator.replicatedThrough()).to.equal(0n);

		// The lease is installed BEFORE confirm, because the gate runs its open
		// listeners synchronously inside it.
		lease = (
			(await replicator.ensureNamespace()) as {
				lease: IWriterLeaseKeys;
			}
		).lease;
		expect((await gate.confirm(lease)).state).to.equal('confirmed');

		// No further commit. Without the wakeup this frame would sit
		// unreplicated for as long as the node stayed quiet.
		await waitFor(() => replicator.replicatedThrough() >= 1n);
		expect(node.getRecoveryStatus().lastDurableSequence).to.not.equal('0');

		node.destroy();
		await shutdown(served);
		storage.close();
	});
});

describe('Recovery phase 6: a finished namespace is reported, not guessed', () => {
	it('survives the restart that discovered it and refuses a new channel', async function (): Promise<void> {
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storage = openStorage();

		// A previous run pruned past a configured ceiling. The fact is in the
		// journal metadata, so this run inherits it: without that, a dead
		// namespace and an unreachable guardian set look identical, and only
		// one of them is ever coming back.
		const journal = new RecoveryJournal(
			storage,
			deriveRecoveryMasterKey(NODE_SECRET),
			NODE_ID,
			ROOT.recoveryId,
			{ durability: 'quorum' }
		);
		new RecoveryManager(storage, { journal }).commit({
			criticality: RecoveryCriticality.SafetyCritical,
			mutations: [
				{
					type: 'payment_preimage',
					paymentHash: sha('finished').toString('hex'),
					preimage: sha('finished-preimage')
				}
			],
			outboundMessages: []
		});
		storage.setRecoveryMeta(
			JOURNAL_META_KEYS.backfillLost,
			'a previous run pruned frames the quorum never received'
		);

		const replicator = replicatorFor(storage, bind(served));
		const barrier = barrierFor(replicator, () => null, 'quorum');
		// It still STARTS. An operator whose namespace is finished still has to
		// be able to close the channels it already has, so refusing to boot
		// would take away the only exit.
		const node = createNode(storage, {
			enabled: true,
			durability: 'quorum',
			barrier
		});

		const status = node.getRecoveryStatus();
		expect(status.backfillLost).to.equal(true);
		expect(status.fenced).to.equal(false);
		expect(status.durability).to.equal('quorum');

		// Opening is the one irreversible step the barrier does not otherwise
		// gate: funding_created, funding_signed and channel_ready are not
		// barrier-class, so an open would run to completion into a namespace
		// that can never record it.
		expect(() => node.openChannel('02'.repeat(33), 100_000n)).to.throw(
			/lost its guardian backfill/
		);

		// EVERY entry point, not only the one the node wrapper happens to use.
		// ChannelManager is published, and its low-level primitives are
		// reachable by an embedder driving the negotiation itself.
		const manager = (node as unknown as { channelManager: ChannelManager })
			.channelManager;
		const peer = '02'.repeat(33);
		const errors: string[] = [];
		manager.on('error', (_id: Buffer | null, message: string) => {
			errors.push(message);
		});
		const indexBeforeRefusals = manager.nextChannelIndex;

		expect(() => manager.openChannel(peer, 100_000n)).to.throw(
			/lost its guardian backfill/
		);
		// The v2 entry point answers to the same namespace check as v1 now
		// that quorum starts dual-funded opens: a namespace that lost its
		// backfill refuses BOTH open flavours at the pre-allocation boundary.
		expect(() =>
			manager.createDualFundedChannel(peer, {
				fundingSatoshis: 100_000n,
				fundingFeeratePerkw: 500
			} as unknown as Parameters<typeof manager.createDualFundedChannel>[1])
		).to.throw(/lost its guardian backfill/);

		// The zero-conf primitive refuses with a null, matching its own
		// disposition. Trust the peer FIRST, or the untrusted-peer branch above
		// the guard satisfies this on its own and the assertion would pass with
		// the guard reverted.
		manager.addTrustedPeer(peer);
		expect(manager.openZeroConfChannel(peer, 100_000n)).to.equal(null);
		expect(errors.join(' ')).to.contain('lost its guardian backfill');

		// And nothing was allocated on the way to any refusal: a refused open
		// must not burn a per-channel key index. This is the assertion that
		// pins the guard AHEAD of deriveKeysForNewChannel rather than behind
		// it, so it has to be a before/after comparison on a manager whose
		// deriver actually advances the index.
		expect(manager.listChannels()).to.have.length(0);
		expect(manager.nextChannelIndex).to.equal(indexBeforeRefusals);

		node.destroy();
		await shutdown(served);
		storage.close();
	});
});

describe('Recovery phase 6: a truncated wire stream drops the connection', () => {
	it('reports its own code rather than reusing the barrier timeout', async function (): Promise<void> {
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storage = openStorage();
		const replicator = replicatorFor(storage, bind(served));
		const barrier = barrierFor(replicator, () => null, 'quorum');
		const node = createNode(storage, {
			enabled: true,
			durability: 'quorum',
			barrier
		});

		const errors: Array<{ code: string; message: string }> = [];
		node.on('node:error', (error: { code: string; message: string }) => {
			errors.push(error);
		});

		const channelId = crypto.randomBytes(32);
		(
			node as unknown as { channelManager: { emit: (...a: unknown[]) => void } }
		).channelManager.emit(
			'transition:dispatch-failed',
			'02'.repeat(33),
			channelId.toString('hex'),
			'observer exploded',
			2
		);

		// A distinct code from DURABILITY_BARRIER_TIMEOUT, because the remedy
		// differs: a freeze exempts a fenced writer from the disconnect, and
		// here nothing else is tearing the transport down.
		const failure = errors.find((e) => e.code === 'BARRIER_DISPATCH_FAILED');
		expect(failure, 'a dispatch failure must be reported').to.not.equal(
			undefined
		);
		expect(failure!.message).to.contain('observer exploded');
		expect(
			errors.some((e) => e.code === 'DURABILITY_BARRIER_TIMEOUT')
		).to.equal(false);

		node.destroy();
		await shutdown(served);
		storage.close();
	});
});

// Issue 432: the barrier handlers' remedy is a disconnect, but in
// message:outbound mode there is no PeerManager to drop a socket. The node
// must then apply the protocol side itself (handlePeerDisconnected, marking
// the channels for reestablish) and ask the HOST to sever the connection via
// 'peer:disconnect-requested', the pattern the quiescence watchdog already
// uses. Without both halves the peer waits forever on a withheld batch and
// the reestablish backstop never sees the channel.
describe('Recovery phase 6: barrier disconnects reach the host on external transports', () => {
	const PEER = '02'.repeat(33);

	function spyOnResets(node: LightningNode): string[] {
		const resets: string[] = [];
		const cm = (node as unknown as { channelManager: ChannelManager })
			.channelManager;
		const original = cm.handlePeerDisconnected.bind(cm);
		cm.handlePeerDisconnected = (pubkey: string): void => {
			resets.push(pubkey);
			original(pubkey);
		};
		return resets;
	}

	function collectRequests(node: LightningNode): string[] {
		const requests: string[] = [];
		node.on('peer:disconnect-requested', (pubkey: string) => {
			requests.push(pubkey);
		});
		return requests;
	}

	function emitOnManager(node: LightningNode, ...args: unknown[]): void {
		(
			node as unknown as { channelManager: { emit: (...a: unknown[]) => void } }
		).channelManager.emit(...args);
	}

	// The handlers defer their remedy with setImmediate; two rounds cover a
	// deferral scheduled from inside the first.
	async function flush(): Promise<void> {
		await new Promise<void>((resolve) => setImmediate(resolve));
		await new Promise<void>((resolve) => setImmediate(resolve));
	}

	it('transition:blocked resets the channels and asks the host to disconnect', async function (): Promise<void> {
		const storage = openStorage();
		const node = createNode(storage, undefined);
		const resets = spyOnResets(node);
		const requests = collectRequests(node);

		emitOnManager(node, 'transition:blocked', PEER, null);
		await flush();

		expect(requests).to.deep.equal([PEER]);
		expect(resets).to.deep.equal([PEER]);

		node.destroy();
		storage.close();
	});

	it('transition:frozen does the same and still reports the barrier timeout', async function (): Promise<void> {
		const storage = openStorage();
		const node = createNode(storage, undefined);
		const resets = spyOnResets(node);
		const requests = collectRequests(node);
		const codes: string[] = [];
		node.on('node:error', (error: { code: string }) => {
			codes.push(error.code);
		});

		emitOnManager(
			node,
			'transition:frozen',
			PEER,
			'aa'.repeat(32),
			'timeout',
			1
		);
		await flush();

		expect(requests).to.deep.equal([PEER]);
		expect(resets).to.deep.equal([PEER]);
		expect(codes).to.include('DURABILITY_BARRIER_TIMEOUT');

		node.destroy();
		storage.close();
	});

	it('a fenced freeze stays exempt from the disconnect', async function (): Promise<void> {
		const storage = openStorage();
		const node = createNode(storage, undefined);
		const resets = spyOnResets(node);
		const requests = collectRequests(node);

		emitOnManager(
			node,
			'transition:frozen',
			PEER,
			'aa'.repeat(32),
			'fenced',
			1
		);
		await flush();

		expect(requests).to.have.length(0);
		expect(resets).to.have.length(0);

		node.destroy();
		storage.close();
	});

	it('transition:dispatch-failed resets the channels and asks the host to disconnect', async function (): Promise<void> {
		const storage = openStorage();
		const node = createNode(storage, undefined);
		const resets = spyOnResets(node);
		const requests = collectRequests(node);

		emitOnManager(
			node,
			'transition:dispatch-failed',
			PEER,
			'bb'.repeat(32),
			'observer exploded',
			2
		);
		await flush();

		expect(requests).to.deep.equal([PEER]);
		expect(resets).to.deep.equal([PEER]);

		node.destroy();
		storage.close();
	});

	it('with networking a HELD peer gets the socket drop and no host request', async function (): Promise<void> {
		const storage = openStorage();
		const config = makeNodeConfig(storage, undefined);
		config.enableNetworking = true;
		const node = new LightningNode(config);
		node.on('error', () => {});
		node.on('node:error', () => {});
		const resets = spyOnResets(node);
		const requests = collectRequests(node);
		const dropped: string[] = [];
		const pm = (
			node as unknown as {
				peerManager: {
					disconnectPeer: (pubkey: string) => void;
					getPeer: (pubkey: string) => unknown;
				};
			}
		).peerManager;
		pm.getPeer = (): unknown => ({});
		pm.disconnectPeer = (pubkey: string): void => {
			dropped.push(pubkey);
		};

		emitOnManager(node, 'transition:blocked', PEER, null);
		emitOnManager(
			node,
			'transition:frozen',
			PEER,
			'aa'.repeat(32),
			'timeout',
			1
		);
		emitOnManager(
			node,
			'transition:dispatch-failed',
			PEER,
			'bb'.repeat(32),
			'observer exploded',
			2
		);
		await flush();

		expect(dropped).to.deep.equal([PEER, PEER, PEER]);
		expect(requests).to.have.length(0);
		expect(resets).to.have.length(0);

		node.destroy();
		storage.close();
	});

	it('with networking an UNHELD peer still gets the reset and the host request', async function (): Promise<void> {
		// The remedy is chosen per peer, not per node: a peer the PeerManager
		// does not hold talks over the event transport, and disconnectPeer
		// would find nothing to drop.
		const storage = openStorage();
		const config = makeNodeConfig(storage, undefined);
		config.enableNetworking = true;
		const node = new LightningNode(config);
		node.on('error', () => {});
		node.on('node:error', () => {});
		const resets = spyOnResets(node);
		const requests = collectRequests(node);

		emitOnManager(
			node,
			'transition:dispatch-failed',
			PEER,
			'bb'.repeat(32),
			'observer exploded',
			2
		);
		await flush();

		expect(requests).to.deep.equal([PEER]);
		expect(resets).to.deep.equal([PEER]);

		node.destroy();
		storage.close();
	});

	it('a barrier fence silences the event transport and asks the host to disconnect', async function (): Promise<void> {
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storage = openStorage();
		const replicator = replicatorFor(storage, bind(served));
		const barrier = barrierFor(replicator, () => null, 'quorum');
		const node = createNode(storage, {
			enabled: true,
			durability: 'quorum',
			barrier
		});
		const resets = spyOnResets(node);
		const requests = collectRequests(node);
		const cm = (
			node as unknown as {
				channelManager: { listChannelPeers: () => string[] };
			}
		).channelManager;
		cm.listChannelPeers = (): string[] => [PEER];
		const outbound: number[] = [];
		node.on('message:outbound', (_pubkey: string, type: number) => {
			outbound.push(type);
		});
		const send = (
			node as unknown as {
				emitOutbound: (pubkey: string, type: number, payload: Buffer) => void;
			}
		).emitOutbound.bind(node);

		// Before the fence the event transport carries traffic.
		send(PEER, 18, Buffer.alloc(0));
		expect(outbound).to.have.length(1);

		(barrier as unknown as { fence: () => void }).fence();

		// The fence asks the host to sever every channel peer's transport and
		// applies the protocol side, the same remedy the socket side gets
		// from freezeConnections.
		expect(requests).to.deep.equal([PEER]);
		expect(resets).to.deep.equal([PEER]);
		// And the chokepoint goes silent: a superseded writer must not put
		// another wire message on ANY transport.
		send(PEER, 18, Buffer.alloc(0));
		expect(outbound).to.have.length(1);
		expect(node.getRecoveryStatus().fenced).to.equal(true);

		node.destroy();
		await shutdown(served);
		storage.close();
	});
});
