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
import { INodeConfig } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
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
