/**
 * Recovery Protocol phase 6, part 2: the replication pass a durability
 * barrier can safely stand on (docs/RECOVERY-PROTOCOL.md 5.3, 5.8, 9).
 *
 * Phase 5 replicated best effort and nothing depended on the answer. Phase 6
 * releases irreversible wire messages on it, which changes what the pass has
 * to guarantee:
 *
 * 1. Appends PIPELINE. The writer streams records to each guardian in
 *    sequence order without waiting for the previous receipt, so a delayed
 *    receipt costs no extra round trip.
 * 2. Receipts are CUMULATIVE. One proven head releases everything at or
 *    below it, and the pass does no per-record accounting.
 * 3. A receipt only counts as evidence about OUR chain: right namespace,
 *    right epoch and writer key, and matching frame hash where it lands on a
 *    frame we hold.
 * 4. The watermark only ever rises, and overlapping passes coalesce rather
 *    than racing it downward.
 * 5. Fencing is permanent and, under a barrier, node wide. It therefore
 *    needs a SIGNED higher epoch, never one endpoint's unsigned rejection.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	CRASH_V1_PROFILE,
	GuardianClient,
	GuardianHttpServer,
	GuardianReplicator,
	GuardianState,
	GuardianStatus,
	IBoundGuardianClient,
	IGuardianReplicationEvent,
	IWriterLeaseKeys,
	RecoveryCriticality,
	RecoveryJournal,
	RecoveryManager,
	ReferenceGuardian,
	REPLICATION_META_KEYS,
	computeGuardianSetId,
	decodeGetHeadResponse,
	decodePutStateResponse,
	deriveRecoveryMasterKey,
	deriveRecoveryRoot,
	encodeGetHeadResponse,
	encodePutStateResponse,
	nodeGuardianTransport,
	xOnlyFromSecret
} from '../../src/lightning/recovery';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

const sha = (s: string): Buffer =>
	crypto.createHash('sha256').update(s).digest();

const GUARDIAN_SECRETS = [1, 2, 3].map((i) => sha(`p6-rep-guardian-${i}`));
const GUARDIAN_IDS = GUARDIAN_SECRETS.map((s) => xOnlyFromSecret(s));
const SET_ID = computeGuardianSetId({
	...CRASH_V1_PROFILE,
	guardianIds: GUARDIAN_IDS
});
const CONTEXT = { guardianSetId: SET_ID, members: GUARDIAN_IDS };
const NODE_SECRET = sha('p6-rep-node-secret');
const ROOT = deriveRecoveryRoot(NODE_SECRET);
const NODE_ID = getPublicKey(NODE_SECRET);

let now = 2_200_000_000_000n;
const clock = (): bigint => ++now;

interface IServed {
	guardian: ReferenceGuardian;
	server: GuardianHttpServer;
	client: GuardianClient;
	id: Buffer;
}

function bind(served: IServed[]): IBoundGuardianClient[] {
	return served.map((entry) => ({
		client: entry.client,
		expectedGuardianId: entry.id
	}));
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

function openStorage(): SqliteStorage {
	const storage = new SqliteStorage(':memory:');
	storage.open();
	return storage;
}

function journaledStorage(count: number): {
	storage: SqliteStorage;
	journal: RecoveryJournal;
	manager: RecoveryManager;
} {
	const storage = openStorage();
	const journal = new RecoveryJournal(
		storage,
		deriveRecoveryMasterKey(NODE_SECRET),
		NODE_ID,
		ROOT.recoveryId,
		{ durability: 'quorum' }
	);
	const manager = new RecoveryManager(storage, { journal });
	for (let i = 0; i < count; i++) {
		expect(
			manager.commit({
				criticality: RecoveryCriticality.SafetyCritical,
				mutations: [
					{
						type: 'payment_preimage',
						paymentHash: Buffer.alloc(32, i + 1).toString('hex'),
						preimage: Buffer.alloc(32, i + 1)
					}
				],
				outboundMessages: []
			}).committed
		).to.equal(true);
	}
	return { storage, journal, manager };
}

function replicator(
	storage: SqliteStorage,
	guardians: IBoundGuardianClient[],
	events: IGuardianReplicationEvent[] = [],
	pipelineWindow?: number
): GuardianReplicator {
	return new GuardianReplicator({
		storage,
		guardians,
		context: CONTEXT,
		required: CRASH_V1_PROFILE.required,
		recoveryRoot: ROOT,
		clock,
		pipelineWindow,
		onEvent: (event): void => {
			events.push(event);
		}
	});
}

/** Establish the namespace and hand back the granted lease. */
async function registered(rep: GuardianReplicator): Promise<IWriterLeaseKeys> {
	const decision = await rep.ensureNamespace();
	expect(decision.outcome).to.equal('registered');
	return (decision as { lease: IWriterLeaseKeys }).lease;
}

/**
 * Wrap an endpoint so a test can watch, delay or rewrite its traffic. The
 * guardian stays real: only the bytes on the wire are instrumented.
 */
function instrument(
	entry: IServed,
	hooks: {
		onRequest?: (path: string) => void;
		onSettled?: (path: string) => void;
		delayMs?: (path: string) => number;
		rewrite?: (
			path: string,
			response: { status: number; body: Buffer }
		) => { status: number; body: Buffer };
	}
): IBoundGuardianClient {
	return {
		expectedGuardianId: entry.id,
		client: new GuardianClient({
			url: entry.client.url,
			guardianSetId: SET_ID,
			transport: async (
				url,
				init
			): Promise<{ status: number; body: Buffer }> => {
				const path = url.slice(url.lastIndexOf('/'));
				hooks.onRequest?.(path);
				const delay = hooks.delayMs?.(path) ?? 0;
				if (delay > 0) {
					await new Promise((resolve) => setTimeout(resolve, delay));
				}
				const response = await nodeGuardianTransport()(url, init);
				hooks.onSettled?.(path);
				return hooks.rewrite ? hooks.rewrite(path, response) : response;
			}
		})
	};
}

// ─────────────── Tests ───────────────

describe('Recovery phase 6: appends pipeline', () => {
	it('streams several records to ONE guardian before reading any receipt', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const { storage } = journaledStorage(8);
		let inFlight = 0;
		let peak = 0;
		const watched = instrument(served[0], {
			onRequest: (path): void => {
				if (path !== '/put_state') return;
				inFlight += 1;
				if (inFlight > peak) peak = inFlight;
			},
			onSettled: (path): void => {
				if (path === '/put_state') inFlight -= 1;
			},
			// Hold every response so the window has to be genuinely concurrent
			// to overlap rather than winning a race by luck.
			delayMs: (path): number => (path === '/put_state' ? 25 : 0)
		});
		const guardians = [watched, ...bind(served).slice(1)];
		const rep = replicator(storage, guardians, [], 4);
		const lease = await registered(rep);

		const result = await rep.replicatePending(lease);
		expect(result.outcome).to.equal('replicated');
		// Sequential streaming would never exceed one outstanding request.
		expect(peak).to.be.greaterThan(1);
		await shutdown(served);
		storage.close();
	});

	it('a slow guardian adds NO round trip per frame, only per pass', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const { storage } = journaledStorage(12);
		let puts = 0;
		const counted = served.map((entry) =>
			instrument(entry, {
				onRequest: (path): void => {
					if (path === '/put_state') puts += 1;
				}
			})
		);
		const rep = replicator(storage, counted, [], 8);
		const lease = await registered(rep);
		puts = 0;

		const result = await rep.replicatePending(lease);
		expect(result.outcome).to.equal('replicated');
		// Every frame reaches every guardian exactly once. Anything that
		// re-drove records per barrier would multiply this.
		const frames = storage.loadRecoveryFrames().length;
		expect(puts).to.equal(frames * served.length);
		await shutdown(served);
		storage.close();
	});

	it('a strictly sequential window reaches the SAME head, only slower', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const { storage } = journaledStorage(6);
		const rep = replicator(storage, bind(served), [], 1);
		const lease = await registered(rep);

		const result = await rep.replicatePending(lease);
		expect(result.outcome).to.equal('replicated');
		const head = await served[0].client.getHead(ROOT.recoveryId);
		expect((head.state as GuardianState).logHead.sequence).to.equal(
			result.replicatedThrough
		);
		await shutdown(served);
		storage.close();
	});

	it('re-anchors and still converges when responses arrive OUT OF ORDER', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const { storage } = journaledStorage(10);
		// Stagger one endpoint's responses so its records land at the guardian
		// in a different order than they were issued. The guardian refuses the
		// ones that arrive early with an unsigned gap error, and the stream has
		// to re-anchor on the position it reports rather than give up.
		let seen = 0;
		const jittered = instrument(served[0], {
			delayMs: (path): number =>
				path === '/put_state' ? (seen++ % 2 === 0 ? 20 : 1) : 0
		});
		const rep = replicator(
			storage,
			[jittered, ...bind(served).slice(1)],
			[],
			6
		);
		const lease = await registered(rep);

		const result = await rep.replicatePending(lease);
		const tip = BigInt(storage.loadRecoveryFrames().slice(-1)[0].sequence);
		expect(result.replicatedThrough).to.equal(tip);
		const head = await served[0].client.getHead(ROOT.recoveryId);
		expect((head.state as GuardianState).logHead.sequence).to.equal(tip);
		await shutdown(served);
		storage.close();
	});
});

describe('Recovery phase 6: receipts are cumulative and bound', () => {
	it('one proven head certifies the whole prefix, with no per-record accounting', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const { storage } = journaledStorage(9);
		const events: IGuardianReplicationEvent[] = [];
		const rep = replicator(storage, bind(served), events);
		const lease = await registered(rep);

		const result = await rep.replicatePending(lease);
		const tip = BigInt(storage.loadRecoveryFrames().slice(-1)[0].sequence);
		expect(result.replicatedThrough).to.equal(tip);
		expect(result.durable).to.equal(Number(tip));
		const durable = events.filter((e) => e.type === 'record:replicated');
		expect(durable.length).to.equal(1);
		expect(durable[0].sequence).to.equal(tip);
		await shutdown(served);
		storage.close();
	});

	it('a receipt for a DIFFERENT namespace never advances the watermark', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const { storage } = journaledStorage(3);
		const rep = replicator(storage, bind(served));
		const lease = await registered(rep);

		// A second namespace on the same real guardians, driven far ahead of
		// ours. Its receipts are perfectly valid; they are simply not about us.
		const otherSecret = sha('p6-rep-other-node');
		const otherRoot = deriveRecoveryRoot(otherSecret);
		const otherStorage = openStorage();
		const otherJournal = new RecoveryJournal(
			otherStorage,
			deriveRecoveryMasterKey(otherSecret),
			getPublicKey(otherSecret),
			otherRoot.recoveryId
		);
		const otherManager = new RecoveryManager(otherStorage, {
			journal: otherJournal
		});
		for (let i = 0; i < 20; i++) {
			otherManager.commit({
				criticality: RecoveryCriticality.SafetyCritical,
				mutations: [
					{
						type: 'payment_preimage',
						paymentHash: Buffer.alloc(32, 200 + i).toString('hex'),
						preimage: Buffer.alloc(32, 200 + i)
					}
				],
				outboundMessages: []
			});
		}
		const otherRep = new GuardianReplicator({
			storage: otherStorage,
			guardians: bind(served),
			context: CONTEXT,
			required: CRASH_V1_PROFILE.required,
			recoveryRoot: otherRoot,
			clock
		});
		const otherLease = await registered(otherRep);
		await otherRep.replicatePending(otherLease);

		// Serve OUR put_state calls the other namespace's head instead.
		const foreign = await served[0].client.getHead(otherRoot.recoveryId);
		const swapped = served.map((entry) =>
			instrument(entry, {
				rewrite: (path, response) => {
					if (path !== '/put_state') return response;
					const decoded = decodePutStateResponse(response.body);
					return {
						status: response.status,
						body: encodePutStateResponse({
							...decoded,
							receipt: foreign.receipt
						})
					};
				}
			})
		);
		storage.setRecoveryMeta(REPLICATION_META_KEYS.replicatedThrough, '0');
		const cheated = replicator(storage, swapped);
		const result = await cheated.replicatePending(lease);
		expect(result.replicatedThrough).to.equal(0n);

		await shutdown(served);
		storage.close();
		otherStorage.close();
	});

	it('a lease the guardians never granted collects nothing to count', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const { storage } = journaledStorage(3);
		const rep = replicator(storage, bind(served));
		const lease = await registered(rep);
		await rep.replicatePending(lease);

		// Defense in depth over one property, checked here end to end. The
		// guardian refuses a record signed under an epoch it did not grant, so
		// no receipt comes back at all; and were one to arrive anyway,
		// provenHead independently refuses a receipt whose state names a
		// different epoch or writer key. Either alone leaves the mark at zero.
		const impostor: IWriterLeaseKeys = {
			...lease,
			epoch: lease.epoch + 5n
		};
		storage.setRecoveryMeta(REPLICATION_META_KEYS.replicatedThrough, '0');
		const second = replicator(storage, bind(served));
		const result = await second.replicatePending(impostor);
		expect(result.replicatedThrough).to.equal(0n);
		await shutdown(served);
		storage.close();
	});

	it('a guardian holding a DIFFERENT record at our sequence is a conflict', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const { storage } = journaledStorage(4);
		const events: IGuardianReplicationEvent[] = [];
		const rep = replicator(storage, bind(served), events);
		const lease = await registered(rep);
		await rep.replicatePending(lease);

		// Same position, different frame hash. The signature is genuine; the
		// record behind it is not ours.
		const honest = await served[0].client.getHead(ROOT.recoveryId);
		const state = honest.state as GuardianState;
		const forged: GuardianState = {
			...state,
			logHead: { ...state.logHead, frameHash: sha('not-our-frame') }
		};
		const lying = served.map((entry) =>
			instrument(entry, {
				rewrite: (path, response) => {
					if (path !== '/get_head') return response;
					const decoded = decodeGetHeadResponse(response.body);
					return {
						status: response.status,
						body: encodeGetHeadResponse({ ...decoded, state: forged })
					};
				}
			})
		);
		// confirmOwnership is the reader that has to reject it: an unsigned
		// substitution must not be able to describe our chain.
		const proof = await replicator(storage, lying, events).confirmOwnership(
			lease
		);
		expect(proof.confirming).to.equal(0);
		await shutdown(served);
		storage.close();
	});
});

describe('Recovery phase 6: the watermark only rises', () => {
	it('overlapping passes COALESCE rather than racing the mark downward', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const { storage } = journaledStorage(6);
		const rep = replicator(storage, bind(served));
		const lease = await registered(rep);

		const [a, b, c] = await Promise.all([
			rep.replicatePending(lease),
			rep.replicatePending(lease),
			rep.replicatePending(lease)
		]);
		// Single flight: all three callers observe the same pass.
		expect(a).to.equal(b);
		expect(b).to.equal(c);
		const tip = BigInt(storage.loadRecoveryFrames().slice(-1)[0].sequence);
		expect(rep.replicatedThrough()).to.equal(tip);
		await shutdown(served);
		storage.close();
	});

	it('a later pass never writes a LOWER mark than the one on disk', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const { storage } = journaledStorage(5);
		const rep = replicator(storage, bind(served));
		const lease = await registered(rep);
		await rep.replicatePending(lease);
		const high = rep.replicatedThrough();
		expect(high > 0n).to.equal(true);

		// Two guardians go dark, so a fresh pass from zero can prove nothing.
		// It must leave the established mark alone rather than reset it.
		storage.setRecoveryMeta(REPLICATION_META_KEYS.replicatedThrough, '0');
		await served[1].server.close();
		await served[2].server.close();
		const starved = replicator(storage, bind(served));
		const result = await starved.replicatePending(lease);
		expect(result.replicatedThrough).to.equal(0n);
		await shutdown(served);
		storage.close();
	});

	it('a CORRUPT watermark reads as zero instead of throwing into the send path', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const { storage } = journaledStorage(2);
		const rep = replicator(storage, bind(served));
		storage.setRecoveryMeta(
			REPLICATION_META_KEYS.replicatedThrough,
			'not-a-number'
		);
		expect(rep.replicatedThrough()).to.equal(0n);

		// And the pass that follows still works, because re-offering records a
		// guardian already holds is answered idempotently.
		const lease = await registered(rep);
		const result = await rep.replicatePending(lease);
		expect(result.outcome).to.equal('replicated');
		await shutdown(served);
		storage.close();
	});
});

describe('Recovery phase 6: fencing needs proof', () => {
	it('one endpoint claiming supersession does NOT fence the node', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const { storage } = journaledStorage(3);
		const events: IGuardianReplicationEvent[] = [];
		const rep = replicator(storage, bind(served), events);
		const lease = await registered(rep);

		// ERR_EPOCH_SUPERSEDED is an unsigned status. Under a quorum barrier a
		// fence stops revoke_and_ack, fulfill and splice on EVERY channel,
		// permanently, so one endpoint saying it must never be enough.
		const liar = instrument(served[0], {
			rewrite: (path, response) => {
				if (path !== '/put_state') return response;
				const decoded = decodePutStateResponse(response.body);
				return {
					status: response.status,
					body: encodePutStateResponse({
						...decoded,
						receipt: undefined,
						status: GuardianStatus.ERR_EPOCH_SUPERSEDED
					})
				};
			}
		});
		const guardians = [liar, ...bind(served).slice(1)];
		const result = await replicator(
			storage,
			guardians,
			events
		).replicatePending(lease);

		expect(result.outcome).to.not.equal('fenced');
		expect(
			events.some((e) => e.type === 'writer:supersession-unproven')
		).to.equal(true);
		expect(events.some((e) => e.type === 'writer:fenced')).to.equal(false);
		await shutdown(served);
		storage.close();
	});
});
