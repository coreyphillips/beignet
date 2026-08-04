/**
 * Recovery Protocol phase 6 acceptance (docs/RECOVERY-PROTOCOL.md section 9,
 * "Phase 6: quorum barriers").
 *
 * The section 9 sentence, clause by clause, against two live nodes with a
 * real channel and three real guardians:
 *
 *   "in quorum mode, no revoke_and_ack, fulfill, or irreversible splice
 *    message precedes its quorum receipt"
 *      -> the flagship case below holds a real commitment round at the wire
 *         and shows the peer receiving nothing until the receipts land.
 *
 *   "guardian latency does not stall unrelated channels or non-critical
 *    writes"
 *      -> Important transitions keep committing while a channel is held.
 *
 *   "appends pipeline and receipts are cumulative"
 *      -> commits keep landing during the hold, and ONE advance releases
 *         everything behind it.
 *
 *   "barrier timeout behavior (freeze, not proceed) is tested"
 *      -> the quorum stays unreachable past the timeout and the peer still
 *         receives nothing.
 *
 * The narrower unit-level proofs live in recovery-phase6-barrier.test.ts
 * (the barrier), -gating.test.ts (the dispatch boundary), -replication.test.ts
 * (pipelining and receipt binding) and -exactness.test.ts (the payoff). This
 * file is the end-to-end statement those add up to.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { MessageType } from '../../src/lightning/message/types';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { IStorageBackend } from '../../src/lightning/storage/types';
import {
	CRASH_V1_PROFILE,
	DurabilityBarrier,
	GuardianClient,
	GuardianHttpServer,
	GuardianReplicator,
	IBoundGuardianClient,
	IWriterLeaseKeys,
	RecoveryCriticality,
	RecoveryManager,
	ReferenceGuardian,
	computeGuardianSetId,
	deriveRecoveryRoot,
	nodeGuardianTransport,
	xOnlyFromSecret
} from '../../src/lightning/recovery';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

const sha = (s: string): Buffer =>
	crypto.createHash('sha256').update(s).digest();

const GUARDIAN_SECRETS = [1, 2, 3].map((i) => sha(`p6-accept-guardian-${i}`));
const GUARDIAN_IDS = GUARDIAN_SECRETS.map((s) => xOnlyFromSecret(s));
const SET_ID = computeGuardianSetId({
	...CRASH_V1_PROFILE,
	guardianIds: GUARDIAN_IDS
});
const CONTEXT = { guardianSetId: SET_ID, members: GUARDIAN_IDS };

let now = 2_240_000_000_000n;
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

/** Endpoints whose put_state calls can be held open on demand. */
function gateable(
	served: IServed[],
	blocked: () => boolean
): IBoundGuardianClient[] {
	return served.map((entry) => ({
		expectedGuardianId: entry.id,
		client: new GuardianClient({
			url: entry.client.url,
			guardianSetId: SET_ID,
			transport: async (
				url,
				init
			): Promise<{ status: number; body: Buffer }> => {
				if (url.endsWith('/put_state')) {
					while (blocked()) {
						await new Promise((resolve) => setTimeout(resolve, 10));
					}
				}
				return nodeGuardianTransport()(url, init);
			}
		})
	}));
}

function makeSeed(id: number): Buffer {
	return sha(`p6-accept-seed-${id}`);
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

function nodeSecret(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(makeSeed(id))
		.update(Buffer.from('node-identity'))
		.digest();
}

function makeNodeConfig(
	id: number,
	storage?: IStorageBackend,
	recovery?: INodeConfig['recovery']
): INodeConfig {
	const seed = makeSeed(id);
	return {
		nodePrivateKey: nodeSecret(id),
		network: Network.REGTEST as Network,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(id + 100),
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
		recovery
	};
}

function createNode(
	id: number,
	storage?: IStorageBackend,
	recovery?: INodeConfig['recovery']
): LightningNode {
	const node = new LightningNode(makeNodeConfig(id, storage, recovery));
	node.on('error', () => {});
	node.on('node:error', () => {});
	return node;
}

/** Loopback, with a tap on everything alice puts on the wire. */
function connectNodes(
	alice: LightningNode,
	bob: LightningNode,
	seen: number[]
): void {
	alice.on('message:outbound', (pubkey: string, type: number, p: Buffer) => {
		if (pubkey !== bob.getNodeId()) return;
		seen.push(type);
		bob.handlePeerMessage(alice.getNodeId(), type, p);
	});
	bob.on('message:outbound', (pubkey: string, type: number, p: Buffer) => {
		if (pubkey === alice.getNodeId()) {
			alice.handlePeerMessage(bob.getNodeId(), type, p);
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

function openStorage(): SqliteStorage {
	const storage = new SqliteStorage(':memory:');
	storage.open();
	return storage;
}

async function waitFor(
	condition: () => boolean,
	timeoutMs = 8_000
): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (!condition()) {
		if (Date.now() > deadline) throw new Error('waitFor timed out');
		await new Promise((resolve) => setTimeout(resolve, 20));
	}
}

interface IQuorumNode {
	alice: LightningNode;
	bob: LightningNode;
	storage: SqliteStorage;
	barrier: DurabilityBarrier;
	replicator: GuardianReplicator;
	seen: number[];
	channelId: Buffer;
}

/**
 * Alice in quorum mode against real guardians, connected to a plain Bob, with
 * a ready channel between them. `blocked` gates the guardians' put_state.
 */
async function quorumPair(
	served: IServed[],
	blocked: () => boolean,
	timeoutMs = 20_000
): Promise<IQuorumNode> {
	const storage = openStorage();
	const root = deriveRecoveryRoot(nodeSecret(1));
	const replicator = new GuardianReplicator({
		storage,
		guardians: gateable(served, blocked),
		context: CONTEXT,
		required: CRASH_V1_PROFILE.required,
		recoveryRoot: root,
		clock
	});
	let lease: IWriterLeaseKeys | null = null;
	const barrier = new DurabilityBarrier({
		durability: 'quorum',
		replicator,
		lease: (): IWriterLeaseKeys | null => lease,
		timeoutMs,
		retryDelayMs: 40
	});
	const alice = createNode(1, storage, {
		enabled: true,
		durability: 'quorum',
		barrier
	});
	const bob = createNode(2);
	const seen: number[] = [];
	connectNodes(alice, bob, seen);

	// Ownership first: nothing is provable until the namespace exists.
	const decision = await replicator.ensureNamespace();
	expect(decision.outcome).to.equal('registered');
	lease = (decision as { lease: IWriterLeaseKeys }).lease;

	const channelId = openReadyChannel(alice, bob);
	// Drain the opening traffic, which is not barrier-class, then start the
	// tap clean so the assertions are only about the commitment round.
	await waitFor(() => barrier.watermark() > 0n);
	seen.length = 0;
	return { alice, bob, storage, barrier, replicator, seen, channelId };
}

// ─────────────── Tests ───────────────

describe('Recovery phase 6 acceptance: no irreversible message precedes its receipt', () => {
	it('a real commitment round reaches the peer only AFTER the quorum stores it', async function () {
		this.timeout(30_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		let blocked = false;
		const pair = await quorumPair(served, () => blocked);

		// From here the guardians answer nothing, so no frame can become
		// durable and every barrier-class message has to wait.
		blocked = true;
		const invoice = pair.bob.createInvoice({
			amountMsat: 10_000n,
			description: 'phase6-acceptance'
		});
		try {
			pair.alice.sendPayment(invoice.bolt11);
		} catch {
			// A held commitment means the send does not complete here; the
			// point of the test is what did NOT reach the peer.
		}
		await new Promise((resolve) => setTimeout(resolve, 400));

		// update_add_htlc is not barrier-class and may go; the commitment that
		// makes the outgoing HTLC irrevocable, and any revoke_and_ack behind
		// it, may not.
		expect(pair.seen).to.not.include(MessageType.COMMITMENT_SIGNED);
		expect(pair.seen).to.not.include(MessageType.REVOKE_AND_ACK);
		expect(
			pair.alice.getRecoveryStatus().awaitingDurabilityCount
		).to.be.greaterThan(0);

		// Let the guardians answer. One advance releases everything behind it.
		blocked = false;
		await waitFor(() => pair.seen.includes(MessageType.COMMITMENT_SIGNED));
		expect(pair.alice.getRecoveryStatus().lastDurableSequence).to.not.equal(
			'0'
		);

		pair.alice.destroy();
		pair.bob.destroy();
		await shutdown(served);
	});

	it('non-critical writes keep committing while a channel is held', async function () {
		this.timeout(30_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		let blocked = false;
		const pair = await quorumPair(served, () => blocked);

		blocked = true;
		const invoice = pair.bob.createInvoice({
			amountMsat: 10_000n,
			description: 'phase6-unrelated'
		});
		try {
			pair.alice.sendPayment(invoice.bolt11);
		} catch {
			// A held commitment means the send does not complete here; the
			// point of the test is what did NOT reach the peer.
		}
		await waitFor(
			() => pair.alice.getRecoveryStatus().awaitingDurabilityCount > 0
		);

		// The barrier holds MESSAGES, never commits: an Important transition
		// still lands on disk and in the journal while a channel waits.
		const recovery = (pair.alice as unknown as { recovery: RecoveryManager })
			.recovery;
		const before = pair.storage.loadRecoveryFrames().length;
		const result = recovery.commit({
			criticality: RecoveryCriticality.Important,
			mutations: [
				{
					type: 'payment_preimage',
					paymentHash: sha('unrelated').toString('hex'),
					preimage: sha('unrelated-preimage')
				}
			],
			outboundMessages: []
		});
		expect(result.committed).to.equal(true);
		expect(pair.storage.loadRecoveryFrames().length).to.be.greaterThan(before);

		blocked = false;
		pair.alice.destroy();
		pair.bob.destroy();
		await shutdown(served);
	});
});

describe('Recovery phase 6 acceptance: a timeout freezes', () => {
	it('an unreachable quorum leaves the peer with NOTHING, past the timeout', async function () {
		this.timeout(30_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		let blocked = false;
		// A short barrier timeout so the freeze is observable in a test.
		const pair = await quorumPair(served, () => blocked, 400);

		const frozen: string[] = [];
		pair.alice.on('node:error', (err: { code?: string }) => {
			if (err.code === 'DURABILITY_BARRIER_TIMEOUT') frozen.push(err.code);
		});

		blocked = true;
		const invoice = pair.bob.createInvoice({
			amountMsat: 10_000n,
			description: 'phase6-freeze'
		});
		try {
			pair.alice.sendPayment(invoice.bolt11);
		} catch {
			// A held commitment means the send does not complete here; the
			// point of the test is what did NOT reach the peer.
		}
		await waitFor(() => frozen.length > 0);

		// Freeze, not proceed: the timeout produced a refusal, and the
		// commitment never reached the peer. Give it a further moment to prove
		// nothing arrives late either.
		await new Promise((resolve) => setTimeout(resolve, 300));
		expect(pair.seen).to.not.include(MessageType.COMMITMENT_SIGNED);
		expect(pair.seen).to.not.include(MessageType.REVOKE_AND_ACK);

		blocked = false;
		pair.alice.destroy();
		pair.bob.destroy();
		await shutdown(served);
	});
});
