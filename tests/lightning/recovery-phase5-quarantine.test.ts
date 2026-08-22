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
 * a quarantined or fenced node establishes no connections in either
 * direction, emits zero wire messages, and dispatches zero inbound
 * messages to its handlers, so nothing escapes OR enters before the gate
 * opens. The gate arrives via config.recovery.startupGate at construction;
 * there is deliberately no post-construction attach.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import net from 'net';
import { EventEmitter } from 'events';
import { MessageType } from '../../src/lightning/message/types';
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
import { PeerManager } from '../../src/lightning/transport/peer-manager';
import { Peer } from '../../src/lightning/transport/peer';
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
	port: number;
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
		port,
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

async function waitFor(cond: () => boolean, timeoutMs = 8_000): Promise<void> {
	const start = Date.now();
	while (!cond()) {
		if (Date.now() - start > timeoutMs) {
			throw new Error('waitFor timed out');
		}
		await new Promise((r) => setTimeout(r, 25));
	}
}

/**
 * Minimal IDuplexTransport that records every write and destroy, so the
 * mid-handshake fencing tests can assert EXACTLY what left the node.
 */
class FakeTransport extends EventEmitter {
	writes: Buffer[] = [];
	destroyed = false;
	readonly writableLength = 0;
	readonly remoteAddress = '127.0.0.1';
	readonly remotePort = 1;
	write(data: Uint8Array | string, cb?: (err?: Error) => void): boolean {
		this.writes.push(Buffer.from(data as Uint8Array));
		cb?.();
		return true;
	}
	setTimeout(_timeout: number, _callback?: () => void): this {
		return this;
	}
	setKeepAlive(_enable?: boolean, _initialDelay?: number): this {
		return this;
	}
	destroy(error?: Error): this {
		if (this.destroyed) return this;
		this.destroyed = true;
		if (error && this.listenerCount('error') > 0) this.emit('error', error);
		this.emit('close', Boolean(error));
		return this;
	}
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
	it('confirms a current lease and only then permits peer traffic', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
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

	it('stays quarantined without a confirming quorum', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
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

	it('fences permanently once a newer epoch is proven', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
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

	it('recheck keeps a confirmed gate open through an outage and fences on a proven takeover', async function (): Promise<void> {
		// Issue #455: the idle re-check must be asymmetric. Guardians going
		// dark is not evidence of anything (confirm would re-quarantine; the
		// re-check must not), while one signed higher-epoch state is the
		// same proof the barrier fences on.
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storage = openStorage();
		const secret = nodeSecretOf(12);
		const rep = replicatorFor(storage, served, secret);
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;
		const root = deriveRecoveryRoot(secret);

		const events: IStartupGateEvent[] = [];
		const gate = gateFor(storage, rep, events);
		let fencedListenerRuns = 0;
		gate.onFenced(() => {
			fencedListenerRuns++;
		});
		expect((await gate.confirm(lease)).state).to.equal('confirmed');

		// Still current: the re-check confirms and changes nothing.
		const still = await gate.recheck(lease);
		expect(still.state).to.equal('confirmed');
		expect(still.confirming).to.equal(3);
		expect(gate.permitsPeerTraffic()).to.equal(true);

		// Every guardian dark: whether the fan-out surfaces as an error or
		// as zero confirmations, the gate stays OPEN (confirm would have
		// re-quarantined here).
		const ports = served.map((entry) => entry.port);
		for (const entry of served) await entry.server.close();
		try {
			const dark = await gate.recheck(lease);
			expect(dark.state).to.equal('confirmed');
			expect(dark.confirming).to.equal(0);
		} catch {
			// An error is the other acceptable answer; the assertions below
			// prove it changed nothing.
		}
		expect(gate.getState()).to.equal('confirmed');
		expect(gate.permitsPeerTraffic()).to.equal(true);
		expect(events.some((e) => e.type === 'gate:quarantined')).to.equal(false);
		expect(fencedListenerRuns).to.equal(0);

		// Guardians return on the SAME ports (the replicator's clients are
		// bound to them) and another device takes the epoch.
		for (const [i, entry] of served.entries()) {
			entry.server = new GuardianHttpServer({ guardian: entry.guardian });
			await entry.server.listen(ports[i]);
		}
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

		const fenced = await gate.recheck(lease);
		expect(fenced.state).to.equal('fenced');
		expect(fenced.supersededBy?.lease.epoch).to.equal(lease.epoch + 1n);
		expect(gate.permitsPeerTraffic()).to.equal(false);
		expect(events.some((e) => e.type === 'gate:fenced')).to.equal(true);
		expect(fencedListenerRuns, 'hard-freeze hook ran once').to.equal(1);
		// Permanent, and idempotent: a later re-check reports fenced without
		// re-running the freeze.
		const again = await gate.recheck(lease);
		expect(again.state).to.equal('fenced');
		expect(fencedListenerRuns).to.equal(1);
		await shutdown(served);
		storage.close();
	});

	it('a superseded device emits ZERO wire messages after restart', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
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

		// Device A restarts with the gate in its CONSTRUCTION config (the
		// only way to install one) and instruments its own transport
		// boundary: every outbound message and peer event is counted, so
		// nothing can slip out unnoticed.
		const gateEvents: IStartupGateEvent[] = [];
		const gate = gateFor(storageA, rep, gateEvents);
		const configA = makeNodeConfig(4, storageA);
		configA.recovery = { enabled: true, startupGate: gate };
		const nodeA = new LightningNode(configA);
		nodeA.on('error', () => {});
		nodeA.on('node:error', () => {});
		const wireMessages: Array<{ peer: string; type: number }> = [];
		nodeA.on('message:outbound', (peer: string, type: number) => {
			wireMessages.push({ peer, type });
		});
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

	it('runs ungated when no gate is configured', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		// The spec allows running without guardians; that mode must not be
		// silently quarantined.
		const storage = openStorage();
		const node = new LightningNode(makeNodeConfig(5, storage));
		node.on('error', () => {});
		node.on('node:error', () => {});
		expect(node.getRecoveryGateState()).to.equal('disabled');
		node.destroy();
	});

	it('gates the CONNECTION lifecycle over TCP: no peer contact while quarantined, networking on confirmation, hard-freeze on fence', async function () {
		// The spec rule is "may not even connect", not "connect but stay
		// quiet": while quarantined the node refuses to listen and to dial,
		// and the constructor's dial pass is deferred behind the gate.
		// Confirmation starts real networking; a proven newer epoch then
		// drops every connection and closes the listener. Two real nodes
		// over TCP, with the RECEIVER instrumented, so no internal claim is
		// trusted.
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storageA = openStorage();
		const secret = nodeSecretOf(6);
		const root = deriveRecoveryRoot(secret);
		const rep = replicatorFor(storageA, served, secret);
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;

		const gateEvents: IStartupGateEvent[] = [];
		const gate = gateFor(storageA, rep, gateEvents);
		const configA = { ...makeNodeConfig(6, storageA), enableNetworking: true };
		configA.recovery = { enabled: true, startupGate: gate };
		const a = new LightningNode(configA);
		a.on('error', () => {});
		a.on('node:error', () => {});

		const storageB = openStorage();
		const configB = { ...makeNodeConfig(7, storageB), enableNetworking: true };
		const b = new LightningNode(configB);
		b.on('error', () => {});
		b.on('node:error', () => {});

		try {
			const aPub = getPublicKey(configA.nodePrivateKey).toString('hex');
			const bPub = getPublicKey(configB.nodePrivateKey).toString('hex');

			// QUARANTINED: no listener, no dial, no deferred dial timers.
			let listenErr: unknown;
			try {
				await a.listen(0);
			} catch (err) {
				listenErr = err;
			}
			expect(String(listenErr)).to.match(/quarantine/i);
			let dialErr: unknown;
			try {
				await a.connectPeer(bPub, '127.0.0.1', 1);
			} catch (err) {
				dialErr = err;
			}
			expect(String(dialErr)).to.match(/quarantine/i);
			expect((a as any).peerManager.isListening()).to.equal(false);
			expect((a as any)._reconnectTimers.size).to.equal(0);
			expect(
				gateEvents.filter((e) => e.type === 'gate:blocked').length
			).to.be.greaterThan(0);

			// CONFIRMED: networking is permitted and actually works.
			const outcome = await gate.confirm(lease);
			expect(outcome.state).to.equal('confirmed');
			expect(a.getRecoveryGateState()).to.equal('confirmed');
			await a.listen(0);
			const port = (a as any).peerManager.server.address().port as number;

			// Count every Lightning message B receives from A at B's own
			// transport, excluding connection-level liveness (init/ping/pong).
			const received: number[] = [];
			(b as any).peerManager.on('message', (pubkey: string, type: number) => {
				if (pubkey !== aPub) return;
				if (
					type === MessageType.INIT ||
					type === MessageType.PING ||
					type === MessageType.PONG
				) {
					return;
				}
				received.push(type);
			});

			await b.connectPeer(aPub, '127.0.0.1', port);
			await waitFor(() => (a as any).peerManager.listPeers().length === 1);
			// The socket path passes traffic, observed at the receiver.
			expect(a.distributePeerStorage(Buffer.from('capsule-bytes'))).to.equal(1);
			await waitFor(() =>
				received.some((type) => type === MessageType.PEER_STORAGE)
			);

			// FENCED: another device takes the epoch; the moment a later
			// confirmation proves it, the node hard-freezes: every
			// connection drops, the listener closes, dials refuse.
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
			const fenced = await gate.confirm(lease);
			expect(fenced.state).to.equal('fenced');
			expect((a as any).peerManager.isListening()).to.equal(false);
			await waitFor(() => (a as any).peerManager.listPeers().length === 0);
			await waitFor(() => (b as any).peerManager.listPeers().length === 0);
			const receivedBeforeFreeze = received.length;
			expect(a.distributePeerStorage(Buffer.from('capsule-bytes'))).to.equal(0);
			let fencedDial: unknown;
			try {
				await a.connectPeer(bPub, '127.0.0.1', port);
			} catch (err) {
				fencedDial = err;
			}
			expect(String(fencedDial)).to.match(/quarantine/i);
			let fencedListen: unknown;
			try {
				await a.listen(0);
			} catch (err) {
				fencedListen = err;
			}
			expect(String(fencedListen)).to.match(/quarantine/i);
			await new Promise((r) => setTimeout(r, 200));
			expect(received.length).to.equal(receivedBeforeFreeze);
		} finally {
			a.destroy();
			b.destroy();
			await shutdown(served);
		}
	});

	it('suppresses gossip sync messages while quarantined', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		// Gossip sync and query responses emit at the NODE level, not through
		// the ChannelManager relay; they must answer to the same gate. An
		// ungated twin proves the probe would have spoken.
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const peerKey = getPublicKey(makeSeed(98)).toString('hex');

		const plain = new LightningNode(makeNodeConfig(88, openStorage()));
		plain.on('error', () => {});
		plain.on('node:error', () => {});
		let plainEmitted = 0;
		plain.on('message:outbound', () => {
			plainEmitted++;
		});
		plain.initiateGossipSync(peerKey);
		expect(plainEmitted).to.be.greaterThan(0);
		plain.destroy();

		const storage = openStorage();
		const secret = nodeSecretOf(8);
		const rep = replicatorFor(storage, served, secret);
		const events: IStartupGateEvent[] = [];
		const config = makeNodeConfig(8, storage);
		config.recovery = {
			enabled: true,
			startupGate: gateFor(storage, rep, events)
		};
		const gated = new LightningNode(config);
		gated.on('error', () => {});
		gated.on('node:error', () => {});
		let emitted = 0;
		gated.on('message:outbound', () => {
			emitted++;
		});
		gated.initiateGossipSync(peerKey);
		expect(emitted).to.equal(0);
		expect(events.some((e) => e.type === 'gate:blocked')).to.equal(true);
		gated.destroy();
		await shutdown(served);
	});

	it('drops inbound messages while quarantined, before any handler', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		// The event-transport inbound boundary: an inbound error message
		// must not reach the channel manager on an unconfirmed device, where
		// it could force-close and broadcast state the device may not own.
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const peerKey = getPublicKey(makeSeed(97)).toString('hex');
		// 32-byte channel id plus a zero-length error payload.
		const errorPayload = Buffer.alloc(34);

		const plain = new LightningNode(makeNodeConfig(89, openStorage()));
		plain.on('error', () => {});
		plain.on('node:error', () => {});
		let plainHandled = 0;
		const plainCm = plain.getChannelManager() as any;
		const plainOriginal = plainCm.handleMessage.bind(plainCm);
		plainCm.handleMessage = (pk: string, t: number, p: Buffer): void => {
			plainHandled++;
			plainOriginal(pk, t, p);
		};
		plain.handlePeerMessage(peerKey, MessageType.ERROR, errorPayload);
		expect(plainHandled).to.equal(1);
		plain.destroy();

		const storage = openStorage();
		const secret = nodeSecretOf(10);
		const rep = replicatorFor(storage, served, secret);
		const events: IStartupGateEvent[] = [];
		const config = makeNodeConfig(10, storage);
		config.recovery = {
			enabled: true,
			startupGate: gateFor(storage, rep, events)
		};
		const gated = new LightningNode(config);
		gated.on('error', () => {});
		gated.on('node:error', () => {});
		let handled = 0;
		const cm = gated.getChannelManager() as any;
		const original = cm.handleMessage.bind(cm);
		cm.handleMessage = (pk: string, t: number, p: Buffer): void => {
			handled++;
			original(pk, t, p);
		};
		gated.handlePeerMessage(peerKey, MessageType.ERROR, errorPayload);
		expect(handled).to.equal(0);
		expect(events.some((e) => e.type === 'gate:blocked')).to.equal(true);
		gated.destroy();
		await shutdown(served);
	});

	it('defers the startup dial pass until ownership confirmation', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		// The constructor schedules auto-reconnect dials; with a gate in the
		// config they are withheld entirely (no timers armed) and run only
		// from the gate's open hook.
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storage = openStorage();
		const secret = nodeSecretOf(11);
		const rep = replicatorFor(storage, served, secret);
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;

		const gate = gateFor(storage, rep);
		const config = { ...makeNodeConfig(11, storage), enableNetworking: true };
		config.recovery = { enabled: true, startupGate: gate };
		const node = new LightningNode(config);
		node.on('error', () => {});
		node.on('node:error', () => {});
		expect((node as any)._autoReconnectDeferred).to.equal(true);
		expect((node as any)._reconnectTimers.size).to.equal(0);

		const outcome = await gate.confirm(lease);
		expect(outcome.state).to.equal('confirmed');
		// The deferred pass ran on the open transition.
		expect((node as any)._autoReconnectDeferred).to.equal(false);
		node.destroy();
		await shutdown(served);
	});

	it('PeerManager gates hold at the transport itself', async function () {
		// Unit-level proof for each of the three transport gates, so the
		// node-level tests do not carry the whole burden: connections refuse
		// in BOTH directions pre-handshake, a gated send throws, and a gated
		// inbound message never reaches a registered handler.
		this.timeout(20_000);
		const keyA = sha('pm-gate-a');
		const keyB = sha('pm-gate-b');
		const pmA = new PeerManager({ localPrivateKey: keyA });
		const pmB = new PeerManager({ localPrivateKey: keyB });
		const aPub = getPublicKey(keyA).toString('hex');
		const bPub = getPublicKey(keyB).toString('hex');
		let open = false;
		pmA.setConnectionGate(() => open);
		try {
			await pmA.listen(0);
			const port = (pmA as any).server.address().port as number;

			// Outbound dial refused at dialPeer, the one chokepoint.
			let dialErr: unknown;
			try {
				await pmA.connectPeer(bPub, '127.0.0.1', 1);
			} catch (err) {
				dialErr = err;
			}
			expect(String(dialErr)).to.match(/Connection gate refused/);

			// Inbound socket destroyed BEFORE the BOLT 8 handshake: the
			// dialer fails and neither side registers a peer.
			let inboundErr: unknown;
			try {
				await pmB.connectPeer(aPub, '127.0.0.1', port);
			} catch (err) {
				inboundErr = err;
			}
			expect(inboundErr).to.not.equal(undefined);
			expect(pmA.listPeers()).to.have.length(0);
			expect(pmB.listPeers()).to.have.length(0);

			// Open the gate: the same dial completes.
			open = true;
			await pmB.connectPeer(aPub, '127.0.0.1', port);
			await waitFor(() => pmA.listPeers().length === 1);

			// Outbound send gate throws like an unconnected peer.
			pmA.setOutboundGate(() => false);
			expect(() =>
				pmA.sendToPeer(bPub, MessageType.PING, Buffer.alloc(4))
			).to.throw(/Outbound gate refused/);
			pmA.setOutboundGate(null);

			// Inbound dispatch gate: a registered handler never fires.
			let handled = 0;
			pmA.onMessage(MessageType.CHANNEL_REESTABLISH, () => {
				handled++;
			});
			pmA.setInboundGate(() => false);
			pmB.sendToPeer(aPub, MessageType.CHANNEL_REESTABLISH, Buffer.alloc(80));
			await new Promise((r) => setTimeout(r, 200));
			expect(handled).to.equal(0);
			pmA.setInboundGate(null);
			pmB.sendToPeer(aPub, MessageType.CHANNEL_REESTABLISH, Buffer.alloc(80));
			await waitFor(() => handled === 1);
		} finally {
			pmA.destroy();
			pmB.destroy();
		}
	});

	it('freezeConnections aborts an OUTBOUND connection mid-handshake', async function () {
		// The race: a dial passes the gate, then the freeze lands while the
		// socket/Noise/init sequence is still in flight. Such a connection is
		// invisible to listPeers(), so the freeze must reach into the pending
		// set, or the handshake completes and registers AFTER the fence. A
		// silent TCP server stalls the dial deterministically between act 1
		// and act 2.
		this.timeout(20_000);
		const pm = new PeerManager({ localPrivateKey: sha('freeze-out-local') });
		const peerPub = getPublicKey(sha('freeze-out-remote')).toString('hex');
		const accepted: net.Socket[] = [];
		let bytesFromDialer = 0;
		const silent = net.createServer((sock) => {
			accepted.push(sock);
			sock.on('data', (chunk) => {
				bytesFromDialer += chunk.length;
			});
		});
		await new Promise<void>((resolve) => silent.listen(0, resolve));
		const port = (silent.address() as net.AddressInfo).port;
		let connected = 0;
		pm.on('peer:connect', () => {
			connected++;
		});
		try {
			const dial = pm.connectPeer(peerPub, '127.0.0.1', port);
			dial.catch(() => {});
			// The dial is mid-handshake: act 1 written, act 2 never coming.
			await waitFor(() => accepted.length === 1 && bytesFromDialer > 0);
			const bytesBeforeFreeze = bytesFromDialer;
			expect((pm as any).pendingPeers.size).to.equal(1);

			pm.freezeConnections();

			let dialErr: unknown;
			try {
				await dial;
			} catch (err) {
				dialErr = err;
			}
			expect(dialErr).to.not.equal(undefined);
			expect(pm.listPeers()).to.have.length(0);
			expect((pm as any).pendingPeers.size).to.equal(0);
			expect(connected).to.equal(0);
			// Not one byte after the freeze.
			await new Promise((r) => setTimeout(r, 200));
			expect(bytesFromDialer).to.equal(bytesBeforeFreeze);
			// And a frozen manager refuses everything, permanently.
			let refrozen: unknown;
			try {
				await pm.connectPeer(peerPub, '127.0.0.1', port);
			} catch (err) {
				refrozen = err;
			}
			expect(String(refrozen)).to.match(/permanently frozen/);
			let listenErr: unknown;
			try {
				await pm.listen(0);
			} catch (err) {
				listenErr = err;
			}
			expect(String(listenErr)).to.match(/permanently frozen/);
		} finally {
			pm.destroy();
			await new Promise<void>((resolve) => silent.close(() => resolve()));
			for (const sock of accepted) sock.destroy();
		}
	});

	it('freezeConnections aborts an INBOUND connection mid-handshake', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		// Inbound variant: the socket was accepted and the responder is
		// waiting for act 1 when the freeze lands. The fake transport records
		// every write and destroy, so the assertion is exact: destroyed, no
		// registration, and not a single byte written by the responder.
		const pm = new PeerManager({ localPrivateKey: sha('freeze-in-local') });
		const fake = new FakeTransport();
		try {
			(pm as any).handleInboundConnection(fake);
			expect((pm as any).pendingPeers.size).to.equal(1);
			expect(fake.destroyed).to.equal(false);

			pm.freezeConnections();

			expect(fake.destroyed).to.equal(true);
			expect((pm as any).pendingPeers.size).to.equal(0);
			expect(pm.listPeers()).to.have.length(0);
			// Release the stall: bytes arriving now draw no response.
			fake.emit('data', Buffer.alloc(50, 7));
			await new Promise((r) => setTimeout(r, 100));
			expect(fake.writes).to.have.length(0);
			expect(pm.listPeers()).to.have.length(0);
		} finally {
			pm.destroy();
		}
	});

	it('a socket factory resolving after disconnect is destroyed before any byte', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		// The sharpest late case (Tor/SOCKS/WebSocket): disconnect() lands
		// while the factory is still pending, so there is no socket to
		// destroy yet. The factory's socket must die the moment it exists,
		// before act 1 is written.
		let resolveFactory: (socket: FakeTransport) => void = () => {};
		const peer = new Peer({
			localPrivateKey: sha('late-factory-local'),
			remotePublicKey: getPublicKey(sha('late-factory-remote')),
			host: 'example.invalid',
			port: 9735,
			createSocket: () =>
				new Promise<FakeTransport>((resolve) => {
					resolveFactory = resolve;
				})
		});
		const attempt = peer.connect();
		attempt.catch(() => {});
		peer.disconnect();
		const fake = new FakeTransport();
		resolveFactory(fake);
		let err: unknown;
		try {
			await attempt;
		} catch (e) {
			err = e;
		}
		expect(String(err)).to.match(/aborted/i);
		expect(fake.destroyed).to.equal(true);
		expect(fake.writes).to.have.length(0);
	});

	it('freezeConnections closes a TCP listener that is still binding', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		// this.server is only assigned after the asynchronous bind, so a
		// freeze landing mid-bind saw no listener to close and left a fenced
		// node externally bound. The freeze fires synchronously after
		// listen() starts, which is deterministically inside the bind.
		const pm = new PeerManager({ localPrivateKey: sha('freeze-bind-tcp') });
		try {
			const listening = pm.listen(0);
			listening.catch(() => {});
			pm.freezeConnections();
			let err: unknown;
			try {
				await listening;
			} catch (e) {
				err = e;
			}
			expect(String(err)).to.match(/invalidated|frozen|aborted/i);
			expect(pm.isListening()).to.equal(false);
		} finally {
			pm.destroy();
		}
	});

	it('freezeConnections closes a WebSocket listener that is still binding', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		// Same race as the TCP variant, across listenWebSocket's await.
		const pm = new PeerManager({ localPrivateKey: sha('freeze-bind-ws') });
		try {
			const listening = pm.listenWebSocket(0);
			listening.catch(() => {});
			pm.freezeConnections();
			let err: unknown;
			try {
				await listening;
			} catch (e) {
				err = e;
			}
			expect(String(err)).to.match(/invalidated|frozen|aborted/i);
			expect(pm.isListening()).to.equal(false);
		} finally {
			pm.destroy();
		}
	});

	it('freezeConnections clears reconnect timers for DISCONNECTED peers and disables rescheduling', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		// disconnectPeer clears timers per pubkey, but reconnect timers also
		// exist for peers that are currently disconnected, which no
		// listPeers() sweep reaches; a fenced node must not wake and redial
		// forever.
		const pm = new PeerManager({
			localPrivateKey: sha('freeze-timers'),
			autoReconnect: true
		});
		const peerPub = getPublicKey(sha('freeze-timers-remote')).toString('hex');
		// A port that refuses immediately: bind then close.
		const probe = net.createServer();
		await new Promise<void>((resolve) => probe.listen(0, resolve));
		const deadPort = (probe.address() as net.AddressInfo).port;
		await new Promise<void>((resolve) => probe.close(() => resolve()));
		try {
			let dialErr: unknown;
			try {
				await pm.connectPeer(peerPub, '127.0.0.1', deadPort);
			} catch (err) {
				dialErr = err;
			}
			expect(dialErr).to.not.equal(undefined);
			// The failed dial armed a reconnect timer for a peer that is NOT
			// in listPeers().
			expect((pm as any).reconnectTimers.size).to.equal(1);
			expect(pm.listPeers()).to.have.length(0);

			pm.freezeConnections();
			expect((pm as any).reconnectTimers.size).to.equal(0);
			// Rescheduling is permanently disabled, not merely cleared once.
			(pm as any).scheduleReconnect(peerPub);
			expect((pm as any).reconnectTimers.size).to.equal(0);
		} finally {
			pm.destroy();
		}
	});

	it('destroy() during a stalled establishment arms no reconnect timer', async function () {
		// Ordinary shutdown, not fencing: destroy() aborts the in-flight
		// connectPeer, whose catch path would schedule a reconnect because
		// autoReconnect is on. The destroyed flag must refuse it, or a
		// destroyed manager wakes up and redials.
		this.timeout(20_000);
		const pm = new PeerManager({
			localPrivateKey: sha('destroy-stall-local'),
			autoReconnect: true
		});
		const peerPub = getPublicKey(sha('destroy-stall-remote')).toString('hex');
		const accepted: net.Socket[] = [];
		const silent = net.createServer((sock) => {
			accepted.push(sock);
			// A paused socket never reads the client's FIN, so 'end' never
			// fires and server.close() in the cleanup would wait forever.
			sock.resume();
		});
		await new Promise<void>((resolve) => silent.listen(0, resolve));
		const port = (silent.address() as net.AddressInfo).port;
		try {
			const dial = pm.connectPeer(peerPub, '127.0.0.1', port);
			dial.catch(() => {});
			await waitFor(() => accepted.length === 1);

			pm.destroy();

			let err: unknown;
			try {
				await dial;
			} catch (e) {
				err = e;
			}
			expect(err).to.not.equal(undefined);
			expect((pm as any).reconnectTimers.size).to.equal(0);
			// And rescheduling stays refused after destroy, permanently.
			(pm as any).scheduleReconnect(peerPub);
			expect((pm as any).reconnectTimers.size).to.equal(0);
		} finally {
			pm.destroy();
			await new Promise<void>((resolve) => silent.close(() => resolve()));
			for (const sock of accepted) sock.destroy();
		}
	});

	it('a fence landing during an in-flight confirmation is never overwritten', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		// The race: confirmation A reads a healthy quorum, then stalls in
		// flight; a takeover is proven and the gate fences; A's stale answer
		// finally arrives still naming the old lease current. Fencing is
		// permanent, so the slow answer must not reopen the gate or mark the
		// stale lease confirmed.
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storage = openStorage();
		const secret = nodeSecretOf(9);
		const rep = replicatorFor(storage, served, secret);
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;
		const root = deriveRecoveryRoot(secret);

		let releaseFirst: () => void = () => {};
		let firstAnswered = false;
		let hold: Promise<void> | null = new Promise<void>((resolve) => {
			releaseFirst = resolve;
		});
		const delayed = {
			confirmOwnership: async (asked: IWriterLeaseKeys) => {
				const answer = await rep.confirmOwnership(asked);
				const pending = hold;
				hold = null;
				if (pending) {
					firstAnswered = true;
					await pending;
				}
				return answer;
			}
		} as unknown as GuardianReplicator;

		const events: IStartupGateEvent[] = [];
		const gate = gateFor(storage, delayed, events);
		// Confirmation A departs while the lease is still current, and its
		// healthy answer stalls in flight.
		const slow = gate.confirm(lease);
		await waitFor(() => firstAnswered);

		// The takeover happens while A is in flight.
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

		// Confirmation B proves the newer epoch: the gate fences.
		const fenced = await gate.confirm(lease);
		expect(fenced.state).to.equal('fenced');

		// A's stale answer lands. It must change nothing.
		releaseFirst();
		const stale = await slow;
		expect(stale.state).to.equal('fenced');
		expect(gate.getState()).to.equal('fenced');
		expect(gate.permitsPeerTraffic()).to.equal(false);
		const stored = loadWriterLease(storage);
		expect(
			(stored as { state: 'present'; lease: IWriterLeaseKeys }).lease
				.confirmedAt
		).to.equal(lease.confirmedAt);
		await shutdown(served);
		storage.close();
	});
});
