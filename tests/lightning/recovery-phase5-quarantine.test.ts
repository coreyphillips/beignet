/**
 * Recovery Protocol phase 5: startup quarantine
 * (docs/RECOVERY-PROTOCOL.md 5.6 startup rule).
 *
 * The rule: channels may not leave quarantine, and the node may not even
 * connect to channel peers, until a guardian quorum confirms this device
 * still owns its writer lease. A stale device must therefore learn it was
 * superseded BEFORE it can touch the Lightning protocol.
 *
 * These tests instrument the TRANSPORT BOUNDARY rather than a status flag:
 * the assertion that matters is that a quarantined or fenced node emits
 * zero wire messages, so nothing escapes before the gate opens.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	CRASH_V1_PROFILE,
	GuardianClient,
	GuardianHttpServer,
	GuardianReplicator,
	GuardianStartupGate,
	GuardianState,
	GuardianStatus,
	IBoundGuardianClient,
	IStartupGateEvent,
	IWriterLeaseKeys,
	RecoveryCriticality,
	RecoveryJournal,
	RecoveryManager,
	ReferenceGuardian,
	computeGuardianSetId,
	deriveRecoveryMasterKey,
	deriveRecoveryRoot,
	generateWriterKey,
	loadWriterLease,
	signAcquisition,
	xOnlyFromSecret
} from '../../src/lightning/recovery';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

const sha = (s: string): Buffer =>
	crypto.createHash('sha256').update(s).digest();

const GUARDIAN_SECRETS = [1, 2, 3].map((i) => sha(`p5-gate-guardian-${i}`));
const GUARDIAN_IDS = GUARDIAN_SECRETS.map((s) => xOnlyFromSecret(s));
const SET_ID = computeGuardianSetId({
	...CRASH_V1_PROFILE,
	guardianIds: GUARDIAN_IDS
});
const CONTEXT = { guardianSetId: SET_ID, members: GUARDIAN_IDS };

let now = 2_100_000_000_000n;
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
	return {
		guardian,
		server,
		id: GUARDIAN_IDS[index],
		client: new GuardianClient({
			url: `http://127.0.0.1:${port}`,
			guardianSetId: SET_ID
		})
	};
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
		} catch {
			// already closed
		}
		entry.guardian.close();
	}
}

function makeSeed(id: number): Buffer {
	return crypto.createHash('sha256').update(`p5-gate-seed-${id}`).digest();
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

function makeNodeConfig(seedId: number, storage: SqliteStorage): INodeConfig {
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
		recovery: { enabled: true }
	};
}

function openStorage(): SqliteStorage {
	const storage = new SqliteStorage(':memory:');
	storage.open();
	return storage;
}

function nodeSecretOf(seedId: number): Buffer {
	return makeNodeConfig(seedId, openStorage()).nodePrivateKey;
}

function replicatorFor(
	storage: SqliteStorage,
	served: IServed[],
	nodeSecret: Buffer
): GuardianReplicator {
	return new GuardianReplicator({
		storage,
		guardians: bind(served),
		context: CONTEXT,
		required: CRASH_V1_PROFILE.required,
		recoveryRoot: deriveRecoveryRoot(nodeSecret),
		clock
	});
}

function gateFor(
	storage: SqliteStorage,
	replicator: GuardianReplicator,
	events: IStartupGateEvent[] = []
): GuardianStartupGate {
	return new GuardianStartupGate({
		storage,
		replicator,
		required: CRASH_V1_PROFILE.required,
		clock,
		onEvent: (event): void => {
			events.push(event);
		}
	});
}

describe('Recovery phase 5: startup quarantine', () => {
	it('confirms a current lease and only then permits peer traffic', async () => {
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storage = openStorage();
		const secret = nodeSecretOf(1);
		const journal = new RecoveryJournal(
			storage,
			deriveRecoveryMasterKey(secret),
			getPublicKey(secret),
			deriveRecoveryRoot(secret).recoveryId
		);
		const manager = new RecoveryManager(storage, { journal });
		manager.commit({
			criticality: RecoveryCriticality.SafetyCritical,
			mutations: [
				{
					type: 'payment_preimage',
					paymentHash: Buffer.alloc(32, 1).toString('hex'),
					preimage: Buffer.alloc(32, 1)
				}
			],
			outboundMessages: []
		});
		const rep = replicatorFor(storage, served, secret);
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;

		const events: IStartupGateEvent[] = [];
		const gate = gateFor(storage, rep, events);
		// The gate starts CLOSED, before anything is asked.
		expect(gate.getState()).to.equal('quarantined');
		expect(gate.permitsPeerTraffic()).to.equal(false);

		const outcome = await gate.confirm(lease);
		expect(outcome.state).to.equal('confirmed');
		expect(outcome.confirming).to.equal(3);
		expect(gate.permitsPeerTraffic()).to.equal(true);
		expect(events.some((e) => e.type === 'gate:confirmed')).to.equal(true);
		// The confirmation is recorded against THIS identity.
		const stored = loadWriterLease(storage);
		expect(
			(stored as { state: 'present'; lease: IWriterLeaseKeys }).lease
				.confirmedAt
		).to.not.equal(null);
		await shutdown(served);
		storage.close();
	});

	it('stays quarantined without a confirming quorum', async () => {
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storage = openStorage();
		const secret = nodeSecretOf(2);
		const rep = replicatorFor(storage, served, secret);
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;

		// Two guardians go dark: one confirmation is not a quorum, and
		// silence is not evidence of ownership.
		await served[1].server.close();
		await served[2].server.close();
		const events: IStartupGateEvent[] = [];
		const gate = gateFor(storage, rep, events);
		const outcome = await gate.confirm(lease);
		expect(outcome.state).to.equal('quarantined');
		expect(outcome.confirming).to.be.lessThan(CRASH_V1_PROFILE.required);
		expect(gate.permitsPeerTraffic()).to.equal(false);
		expect(events.some((e) => e.type === 'gate:quarantined')).to.equal(true);
		await shutdown(served);
		storage.close();
	});

	it('fences permanently once a newer epoch is proven', async () => {
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storage = openStorage();
		const secret = nodeSecretOf(3);
		const rep = replicatorFor(storage, served, secret);
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;
		const root = deriveRecoveryRoot(secret);

		// Another device takes the epoch.
		const head = (await served[0].client.getHead(root.recoveryId))
			.state as GuardianState;
		const newWriter = generateWriterKey();
		for (const entry of served) {
			expect(
				(
					await entry.client.acquireEpoch({
						protocolVersion: 1,
						guardianSetId: SET_ID,
						expectedState: head,
						newEpoch: head.lease.epoch + 1n,
						newWriterPublicKey: newWriter.publicKey,
						...signAcquisition(
							SET_ID,
							head,
							head.lease.epoch + 1n,
							newWriter,
							root.rootSecret
						)
					})
				).status
			).to.equal(GuardianStatus.OK);
		}

		const events: IStartupGateEvent[] = [];
		const gate = gateFor(storage, rep, events);
		const outcome = await gate.confirm(lease);
		expect(outcome.state).to.equal('fenced');
		expect(outcome.supersededBy?.lease.epoch).to.equal(lease.epoch + 1n);
		expect(gate.permitsPeerTraffic()).to.equal(false);
		expect(events.some((e) => e.type === 'gate:fenced')).to.equal(true);

		// Fencing is PERMANENT: even a later confirmation attempt cannot
		// reopen the gate for this lease.
		const again = await gate.confirm(lease);
		expect(again.state).to.equal('fenced');
		expect(gate.permitsPeerTraffic()).to.equal(false);
		// The stale lease was never marked confirmed.
		const stored = loadWriterLease(storage);
		expect(
			(stored as { state: 'present'; lease: IWriterLeaseKeys }).lease
				.confirmedAt
		).to.equal(lease.confirmedAt);
		await shutdown(served);
		storage.close();
	});

	it('a superseded device emits ZERO wire messages after restart', async () => {
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storageA = openStorage();
		const secret = nodeSecretOf(4);
		const root = deriveRecoveryRoot(secret);
		const rep = replicatorFor(storageA, served, secret);
		const decision = await rep.ensureNamespace();
		const leaseA = (decision as { lease: IWriterLeaseKeys }).lease;

		// Device B takes epoch E+1 while A is down.
		const head = (await served[0].client.getHead(root.recoveryId))
			.state as GuardianState;
		const writerB = generateWriterKey();
		for (const entry of served) {
			await entry.client.acquireEpoch({
				protocolVersion: 1,
				guardianSetId: SET_ID,
				expectedState: head,
				newEpoch: head.lease.epoch + 1n,
				newWriterPublicKey: writerB.publicKey,
				...signAcquisition(
					SET_ID,
					head,
					head.lease.epoch + 1n,
					writerB,
					root.rootSecret
				)
			});
		}

		// Device A restarts, attaches the gate, and instruments its own
		// transport boundary: every outbound message and peer event is
		// counted, so nothing can slip out unnoticed.
		const nodeA = new LightningNode(makeNodeConfig(4, storageA));
		nodeA.on('error', () => {});
		nodeA.on('node:error', () => {});
		const wireMessages: Array<{ peer: string; type: number }> = [];
		nodeA.on('message:outbound', (peer: string, type: number) => {
			wireMessages.push({ peer, type });
		});
		const gateEvents: IStartupGateEvent[] = [];
		const gate = gateFor(storageA, rep, gateEvents);
		nodeA.attachRecoveryGate(gate);
		expect(nodeA.getRecoveryGateState()).to.equal('quarantined');

		// Even before confirmation, a peer that connects must not draw a
		// single message out of this node.
		const peerKey = getPublicKey(makeSeed(99)).toString('hex');
		nodeA.getChannelManager().handlePeerReconnected(peerKey);
		expect(wireMessages).to.have.length(0);

		const outcome = await gate.confirm(leaseA);
		expect(outcome.state).to.equal('fenced');
		expect(nodeA.getRecoveryGateState()).to.equal('fenced');
		// A obtained SIGNED evidence of the newer epoch.
		expect(outcome.supersededBy?.lease.epoch).to.equal(leaseA.epoch + 1n);

		// And still, after learning it is fenced, nothing reaches the wire.
		nodeA.getChannelManager().handlePeerReconnected(peerKey);
		expect(wireMessages).to.have.length(0);
		expect(nodeA.getRecoveryGateState()).to.equal('fenced');
		// The old lease was never marked confirmed.
		const stored = loadWriterLease(storageA);
		expect(
			(stored as { state: 'present'; lease: IWriterLeaseKeys }).lease
				.confirmedAt
		).to.equal(leaseA.confirmedAt);

		nodeA.destroy();
		await shutdown(served);
	});

	it('runs ungated when no gate is attached', async () => {
		// The spec allows running without guardians; that mode must not be
		// silently quarantined.
		const storage = openStorage();
		const node = new LightningNode(makeNodeConfig(5, storage));
		node.on('error', () => {});
		node.on('node:error', () => {});
		expect(node.getRecoveryGateState()).to.equal('disabled');
		node.destroy();
	});
});
