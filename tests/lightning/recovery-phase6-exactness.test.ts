/**
 * Recovery Protocol phase 6, part 6: the wire-safety proof
 * (docs/RECOVERY-PROTOCOL.md 5.6, 5.8, section 6).
 *
 * This is the payoff of the whole phase. Phase 5 marked EVERY restored
 * channel StateUncertain, permanently, and deliberately left no way to skip
 * it: a compatible channel_reestablish proves nothing about exactness, and
 * the earlier attempt at an escape hatch, a caller-supplied
 * wireSafeThroughSequence scalar, was removed because a bare number bound to
 * nothing could launder a stale restore into a broadcastable one.
 *
 * The invariants under test:
 *
 * 1. A restore whose CERTIFIED HEAD declares quorum durability comes back
 *    resumable, with a proof naming the namespace, the superseded epoch and
 *    the head it was derived at.
 * 2. Any other restore keeps the DLP fallback. Absence of proof is the
 *    ordinary outcome, not an error.
 * 3. The proof is evidence, not configuration. It is derived from the
 *    verified chain, and a proof whose fields do not match the restore it
 *    claims to describe fails the same predicate the driver applies.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	CRASH_V1_PROFILE,
	GuardianClient,
	GuardianHttpServer,
	GuardianReplicator,
	GuardianState,
	IBoundGuardianClient,
	IWireSafetyProof,
	IWriterLeaseKeys,
	RecoveryCriticality,
	RecoveryFrame,
	RecoveryJournal,
	RecoveryManager,
	ReferenceGuardian,
	RestoreDriver,
	computeGuardianSetId,
	deriveRecoveryMasterKey,
	deriveRecoveryRoot,
	deriveWireSafetyProof,
	verifyWireSafetyProof,
	xOnlyFromSecret
} from '../../src/lightning/recovery';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { IStorageBackend } from '../../src/lightning/storage/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { createOpenerState } from '../../src/lightning/channel/channel-state';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';

const sha = (s: string): Buffer =>
	crypto.createHash('sha256').update(s).digest();

const GUARDIAN_SECRETS = [1, 2, 3].map((i) => sha(`p6-exact-guardian-${i}`));
const GUARDIAN_IDS = GUARDIAN_SECRETS.map((s) => xOnlyFromSecret(s));
const SET_ID = computeGuardianSetId({
	...CRASH_V1_PROFILE,
	guardianIds: GUARDIAN_IDS
});
const CONTEXT = { guardianSetId: SET_ID, members: GUARDIAN_IDS };
const NODE_SECRET = sha('p6-exact-node-secret');
const ROOT = deriveRecoveryRoot(NODE_SECRET);
const NODE_ID = getPublicKey(NODE_SECRET);

let now = 2_230_000_000_000n;
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

function driverFor(
	target: IStorageBackend,
	guardians: IBoundGuardianClient[]
): RestoreDriver {
	return new RestoreDriver({
		target,
		guardians,
		context: CONTEXT,
		required: CRASH_V1_PROFILE.required,
		recoveryRoot: ROOT,
		nodeSecret: NODE_SECRET,
		nodeId: NODE_ID,
		clock
	});
}

const CHANNEL_ID = Buffer.alloc(32, 0xd6).toString('hex');

/** Seed a database with one channel, a journal, and a replicated chain. */
async function sourceNode(
	served: IServed[],
	durability: 'quorum' | 'async-remote' | undefined
): Promise<SqliteStorage> {
	const storage = openStorage();
	const chanSeed = sha('p6-exact-channel');
	const keys = Array.from({ length: 6 }, (_, i) =>
		crypto
			.createHash('sha256')
			.update(chanSeed)
			.update(Buffer.from([i]))
			.digest()
	);
	const channelState = createOpenerState({
		temporaryChannelId: Buffer.alloc(32, 0xd6),
		fundingSatoshis: 500_000n,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: {
			fundingPubkey: getPublicKey(keys[0]),
			revocationBasepoint: getPublicKey(keys[1]),
			paymentBasepoint: getPublicKey(keys[2]),
			delayedPaymentBasepoint: getPublicKey(keys[3]),
			htlcBasepoint: getPublicKey(keys[4]),
			firstPerCommitmentPoint: getPublicKey(keys[5])
		},
		localPerCommitmentSeed: sha('p6-exact-seed')
	});
	expect(channelState.stateUncertain).to.equal(undefined);
	storage.saveChannel(CHANNEL_ID, channelState, '02'.padEnd(66, 'ab'));

	const journal = new RecoveryJournal(
		storage,
		deriveRecoveryMasterKey(NODE_SECRET),
		NODE_ID,
		ROOT.recoveryId,
		{ durability }
	);
	const manager = new RecoveryManager(storage, { journal });
	manager.commit({
		criticality: RecoveryCriticality.SafetyCritical,
		mutations: [
			{
				type: 'payment_preimage',
				paymentHash: Buffer.alloc(32, 0xa1).toString('hex'),
				preimage: Buffer.alloc(32, 0xa1)
			}
		],
		outboundMessages: []
	});
	const rep = replicatorFor(storage, bind(served));
	const decision = await rep.ensureNamespace();
	await rep.replicatePending((decision as { lease: IWriterLeaseKeys }).lease);
	return storage;
}

// ─────────────── Tests ───────────────

describe('Recovery phase 6: a proven-exact restore resumes', () => {
	it('a certified head declaring QUORUM brings the channel back resumable', async () => {
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storage = await sourceNode(served, 'quorum');

		const target = openStorage();
		const result = await driverFor(target, bind(served)).restore();

		// This is the phase 5 behaviour being lifted, and only by evidence.
		const restored = target.loadChannel(CHANNEL_ID);
		expect(restored).to.not.equal(null);
		expect(restored!.state.stateUncertain).to.equal(undefined);

		const proof = result.wireSafetyProof as IWireSafetyProof;
		expect(proof).to.not.equal(undefined);
		expect(proof.durability).to.equal('quorum');
		expect(proof.recoveryId.equals(ROOT.recoveryId)).to.equal(true);
		expect(proof.headSequence).to.equal(result.certifiedState.logHead.sequence);
		expect(
			proof.headFrameHash.equals(result.certifiedState.logHead.frameHash)
		).to.equal(true);
		expect(proof.supersededEpoch).to.equal(result.certifiedState.lease.epoch);

		await shutdown(served);
		storage.close();
		target.close();
	});

	it('an ASYNC-REMOTE head keeps the DLP fallback, with no proof', async () => {
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storage = await sourceNode(served, 'async-remote');

		const target = openStorage();
		const result = await driverFor(target, bind(served)).restore();

		// Nothing barriered those messages, so the certified head may trail
		// what the lost device already told its peers.
		expect(target.loadChannel(CHANNEL_ID)!.state.stateUncertain).to.equal(true);
		expect(result.wireSafetyProof).to.equal(undefined);

		await shutdown(served);
		storage.close();
		target.close();
	});

	it('a head with NO declaration at all is treated as unproven', async () => {
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storage = await sourceNode(served, undefined);

		const target = openStorage();
		const result = await driverFor(target, bind(served)).restore();

		expect(target.loadChannel(CHANNEL_ID)!.state.stateUncertain).to.equal(true);
		expect(result.wireSafetyProof).to.equal(undefined);

		await shutdown(served);
		storage.close();
		target.close();
	});

	it('the driver REPORTS which way it went, either way', async () => {
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storage = await sourceNode(served, 'quorum');
		const target = openStorage();
		const details: string[] = [];
		const driver = new RestoreDriver({
			target,
			guardians: bind(served),
			context: CONTEXT,
			required: CRASH_V1_PROFILE.required,
			recoveryRoot: ROOT,
			nodeSecret: NODE_SECRET,
			nodeId: NODE_ID,
			clock,
			onEvent: (event): void => {
				if (event.type === 'restore:exactness') details.push(event.detail);
			}
		});
		await driver.restore();

		expect(details).to.have.length(1);
		expect(details[0]).to.contain('quorum');

		await shutdown(served);
		storage.close();
		target.close();
	});
});

describe('Recovery phase 6: the proof is evidence, not configuration', () => {
	const head: RecoveryFrame = {
		version: 1,
		writerEpoch: 1n,
		sequence: 12n,
		previousFrameHash: Buffer.alloc(32),
		timestamp: 0,
		mutations: [],
		outboundMessages: [],
		durability: 'quorum'
	};
	const certified: GuardianState = {
		recoveryId: ROOT.recoveryId,
		lease: { epoch: 3n, writerPublicKey: Buffer.alloc(32, 7) },
		origin: { firstSequence: 1n, previousHash: Buffer.alloc(32) },
		logHead: {
			sequence: 12n,
			frameHash: sha('exact-head'),
			ciphertextHash: sha('exact-ciphertext'),
			recordEpoch: 1n
		}
	};

	function derived(): IWireSafetyProof {
		const result = deriveWireSafetyProof(certified, [head], ROOT.recoveryId);
		expect(result.proven).to.equal(true);
		return (result as { proof: IWireSafetyProof }).proof;
	}

	it('a proof derived from this restore verifies against it', () => {
		expect(
			verifyWireSafetyProof(derived(), {
				certified,
				recoveryId: ROOT.recoveryId,
				head
			})
		).to.equal(true);
	});

	it('a proof naming another NAMESPACE does not verify', () => {
		const forged = { ...derived(), recoveryId: sha('someone-else') };
		expect(
			verifyWireSafetyProof(forged, {
				certified,
				recoveryId: ROOT.recoveryId,
				head
			})
		).to.equal(false);
	});

	it('a proof naming another EPOCH does not verify', () => {
		const forged = { ...derived(), supersededEpoch: 99n };
		expect(
			verifyWireSafetyProof(forged, {
				certified,
				recoveryId: ROOT.recoveryId,
				head
			})
		).to.equal(false);
	});

	it('a proof pointing at another HEAD does not verify, sequence or hash', () => {
		expect(
			verifyWireSafetyProof(
				{ ...derived(), headSequence: 13n },
				{ certified, recoveryId: ROOT.recoveryId, head }
			)
		).to.equal(false);
		// A sequence alone names a position; the hash is what names a chain.
		expect(
			verifyWireSafetyProof(
				{ ...derived(), headFrameHash: sha('different-chain') },
				{ certified, recoveryId: ROOT.recoveryId, head }
			)
		).to.equal(false);
	});

	it('a proof over a head that does not declare quorum does not verify', () => {
		const weakHead: RecoveryFrame = { ...head, durability: 'async-remote' };
		expect(
			verifyWireSafetyProof(derived(), {
				certified,
				recoveryId: ROOT.recoveryId,
				head: weakHead
			})
		).to.equal(false);
	});

	it('derivation refuses a chain that does not END at the certified head', () => {
		const short: RecoveryFrame = { ...head, sequence: 11n };
		const result = deriveWireSafetyProof(certified, [short], ROOT.recoveryId);
		expect(result.proven).to.equal(false);
		expect((result as { reason: string }).reason).to.equal('head-mismatch');
	});

	it('derivation refuses an empty restore rather than calling it exact', () => {
		const result = deriveWireSafetyProof(certified, [], ROOT.recoveryId);
		expect(result.proven).to.equal(false);
		expect((result as { reason: string }).reason).to.equal('no-frames');
	});
});
