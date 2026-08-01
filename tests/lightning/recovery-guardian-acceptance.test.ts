/**
 * Phase 4 acceptance (docs/RECOVERY-PROTOCOL.md section 9, wire spec 5):
 * the guardian pipeline proven end to end, mechanically.
 *
 * 1. REAL SIGKILL child-process durability at the receipt boundary: a
 *    guardian killed after acknowledging holds everything it acknowledged;
 *    one killed before the response leaves stays atomic either way.
 * 2. A restore device reconciling divergent heads over HTTP: backfilling a
 *    laggard through SYNC_RECORD, defeating silent truncation with its own
 *    retained receipt, and re-entering writability only on quorum evidence.
 * 3. A missed takeover repaired through SYNC_EPOCH, with the minority tail
 *    truncated to the orphan archive and re-filled under the new epoch.
 * 4. The flagship: a node whose device is LOST replicates its journal to
 *    three guardians, restores from their records alone into a fresh
 *    database byte-identically, resumes its channel via reestablish, and
 *    pays.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import readline from 'readline';
import { spawn } from 'child_process';
import Database from 'better-sqlite3';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { Network } from '../../src/lightning/invoice/types';
import { INodeConfig, PaymentStatus } from '../../src/lightning/node/types';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { IStorageBackend } from '../../src/lightning/storage/types';
import {
	GuardianClient,
	GuardianHttpServer,
	GuardianState,
	GuardianStatus,
	IGuardianAlarm,
	IGuardianReceipt,
	IGuardianRecord,
	IGuardianTakeoverCertificate,
	JOURNAL_META_KEYS,
	ReferenceGuardian,
	acquireTranscriptHash,
	countReceiptQuorum,
	deriveRecoveryMasterKey,
	deriveRecoveryRoot,
	guardianFanOut,
	reconstructFromFrames,
	signTranscript,
	statesEqual,
	u64be,
	verifyFrameChain,
	verifyGuardianReceipt
} from '../../src/lightning/recovery';
import {
	ACCEPT_GUARDIAN_IDS,
	ACCEPT_GUARDIAN_SECRETS,
	ACCEPT_ROOT,
	ACCEPT_SET_ID,
	ACCEPT_WRITER,
	ITestWriter,
	acceptChain,
	buildRegistrationFor,
	makeTestWriter,
	sha,
	signRecordFor
} from './helpers/guardian-accept-fixture';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import {
	BITCOIN_CHAIN_HASH,
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
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

const CHILD_PATH = path.join(__dirname, 'helpers', 'guardian-crash-child.ts');
const REPO_ROOT = path.resolve(__dirname, '..', '..');
const sha256buf = (b: Buffer): Buffer =>
	crypto.createHash('sha256').update(b).digest();

// ─────────────── crash-child harness ───────────────

interface IChildRun {
	lastAcknowledged: bigint;
	sawDone: boolean;
}

/**
 * Spawn the crash child against a database file and SIGKILL it the moment
 * `killLine` appears on its stdout. Resolves with the highest receipt the
 * PARENT observed before death: the acknowledged set, by definition.
 */
function runChildAndKillOn(
	dbPath: string,
	killLine: string
): Promise<IChildRun> {
	return new Promise((resolve, reject) => {
		const child = spawn(
			process.execPath,
			['-r', 'ts-node/register', CHILD_PATH, dbPath],
			{
				cwd: REPO_ROOT,
				env: { ...process.env, TS_NODE_TRANSPILE_ONLY: '1' },
				stdio: ['ignore', 'pipe', 'inherit']
			}
		);
		const lines = readline.createInterface({ input: child.stdout });
		let lastAcknowledged = 0n;
		let sawDone = false;
		let exited = false;
		let closed = false;
		let failed: Error | null = null;
		const timer = setTimeout(() => {
			child.kill('SIGKILL');
			reject(new Error('crash child timed out'));
		}, 110_000);
		const settle = (): void => {
			if (!exited || !closed) return;
			clearTimeout(timer);
			if (failed) reject(failed);
			else resolve({ lastAcknowledged, sawDone });
		};
		lines.on('line', (line) => {
			if (line.startsWith('receipt:')) {
				lastAcknowledged = BigInt(line.slice('receipt:'.length));
			} else if (line === 'done') {
				sawDone = true;
			} else if (line.startsWith('error:')) {
				failed = new Error(`crash child protocol error: ${line}`);
				child.kill('SIGKILL');
			}
			if (line === killLine) {
				child.kill('SIGKILL');
			}
		});
		lines.on('close', () => {
			closed = true;
			settle();
		});
		child.on('exit', () => {
			exited = true;
			settle();
		});
		child.on('error', (error) => {
			clearTimeout(timer);
			reject(error);
		});
	});
}

/**
 * Reopen the killed guardian's store in-process and prove the receipt
 * boundary held: open-time verification passes with NO rollback (SQLite
 * atomicity means the interrupted append either committed whole or vanished
 * whole), the head covers every acknowledged sequence, every surviving
 * record byte-matches what the writer sent, and the writer resumes by
 * replaying the remainder.
 */
function verifyIntactAfterCrash(
	dbPath: string,
	lastAcknowledged: bigint
): void {
	const alarms: IGuardianAlarm[] = [];
	const guardian = new ReferenceGuardian({
		path: dbPath,
		guardianSecret: ACCEPT_GUARDIAN_SECRETS[0],
		members: ACCEPT_GUARDIAN_IDS,
		onAlarm: (alarm): void => {
			alarms.push(alarm);
		}
	});
	expect(alarms.length, 'no rollback on reopen').to.equal(0);
	const headRequest = {
		protocolVersion: 1,
		guardianSetId: ACCEPT_SET_ID,
		recoveryId: ACCEPT_ROOT.recoveryId
	};
	const head = guardian.getHead(headRequest);
	expect(head.status).to.equal(GuardianStatus.OK);
	expect(head.possiblyStale).to.equal(false);
	const sequence = (head.state as GuardianState).logHead.sequence;
	expect(
		sequence >= lastAcknowledged,
		`head ${sequence} covers acknowledged ${lastAcknowledged}`
	).to.equal(true);

	const chain = acceptChain();
	const page = guardian.getState({
		protocolVersion: 1,
		guardianSetId: ACCEPT_SET_ID,
		recoveryId: ACCEPT_ROOT.recoveryId,
		fromSequence: 0n,
		maxRecords: 0
	});
	const records = page.records as IGuardianRecord[];
	expect(BigInt(records.length)).to.equal(sequence);
	records.forEach((record, i) => {
		expect(record.sequence).to.equal(chain[i].sequence);
		expect(record.frameHash.equals(chain[i].frameHash)).to.equal(true);
		expect(record.ciphertext.equals(chain[i].ciphertext)).to.equal(true);
	});

	for (let i = Number(sequence); i < chain.length; i++) {
		expect(guardian.syncRecord({ record: chain[i] }).status).to.equal(
			GuardianStatus.OK
		);
	}
	const finalHead = guardian.getHead(headRequest);
	expect((finalHead.state as GuardianState).logHead.sequence).to.equal(
		BigInt(chain.length)
	);
	guardian.close();
}

// ─────────────── HTTP guardian trio harness ───────────────

interface IServedGuardian {
	guardian: ReferenceGuardian;
	server: GuardianHttpServer;
	client: GuardianClient;
}

async function serveGuardian(
	index: number,
	dbPath = ':memory:',
	onAlarm?: (alarm: IGuardianAlarm) => void
): Promise<IServedGuardian> {
	const guardian = new ReferenceGuardian({
		path: dbPath,
		guardianSecret: ACCEPT_GUARDIAN_SECRETS[index],
		members: ACCEPT_GUARDIAN_IDS,
		onAlarm
	});
	const server = new GuardianHttpServer({ guardian });
	const port = await server.listen(0);
	const client = new GuardianClient({
		url: `http://127.0.0.1:${port}`,
		guardianSetId: ACCEPT_SET_ID
	});
	return { guardian, server, client };
}

function buildAcquireFor(
	root: { rootSecret: Buffer; recoveryId: Buffer },
	expectedState: GuardianState,
	newWriter: ITestWriter
): {
	protocolVersion: number;
	guardianSetId: Buffer;
	expectedState: GuardianState;
	newEpoch: bigint;
	newWriterPublicKey: Buffer;
	rootSignature: Buffer;
	newWriterSignature: Buffer;
} {
	const newEpoch = expectedState.lease.epoch + 1n;
	const hash = acquireTranscriptHash(
		ACCEPT_SET_ID,
		expectedState,
		newEpoch,
		newWriter.pub
	);
	return {
		protocolVersion: 1,
		guardianSetId: ACCEPT_SET_ID,
		expectedState,
		newEpoch,
		newWriterPublicKey: newWriter.pub,
		rootSignature: signTranscript(hash, root.rootSecret),
		newWriterSignature: signTranscript(hash, newWriter.secret)
	};
}

describe('Guardian acceptance: SIGKILL at the receipt boundary', () => {
	let dir: string;
	before(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-guardian-kill-'));
	});
	after(() => {
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it('killed AFTER acknowledging, the guardian holds everything acknowledged', async function () {
		this.timeout(120_000);
		const dbPath = path.join(dir, 'kill-after-receipt.sqlite');
		const run = await runChildAndKillOn(dbPath, 'receipt:5');
		expect(run.sawDone, 'child was killed mid-chain').to.equal(false);
		expect(run.lastAcknowledged >= 5n).to.equal(true);
		verifyIntactAfterCrash(dbPath, run.lastAcknowledged);
	});

	it('killed BEFORE the response leaves, the interrupted append is atomic', async function () {
		this.timeout(120_000);
		const dbPath = path.join(dir, 'kill-before-receipt.sqlite');
		// The kill fires on the attempt marker, so the signal lands while the
		// append (and its fsync) is still in flight.
		const run = await runChildAndKillOn(dbPath, 'attempting:4');
		expect(run.sawDone).to.equal(false);
		verifyIntactAfterCrash(dbPath, run.lastAcknowledged);
	});
});

describe('Guardian acceptance: restore-device repair over HTTP', () => {
	let dir: string;
	before(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-guardian-repair-'));
	});
	after(() => {
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it('backfills a laggard, defeats silent truncation, and re-enters on quorum evidence', async function () {
		this.timeout(30_000);
		const fileA = path.join(dir, 'guardian-a.sqlite');
		const a = await serveGuardian(0, fileA);
		const b = await serveGuardian(1);
		const c = await serveGuardian(2);
		const clients = [a.client, b.client, c.client];
		const context = {
			guardianSetId: ACCEPT_SET_ID,
			members: ACCEPT_GUARDIAN_IDS
		};
		const registration = buildRegistrationFor(
			ACCEPT_ROOT,
			ACCEPT_SET_ID,
			ACCEPT_WRITER.pub
		);
		const chain = acceptChain(4);

		await guardianFanOut(clients, (client) => client.register(registration));
		// C lags: the writer reached only A and B for records 1..3.
		const writerReceipts: IGuardianReceipt[] = [];
		for (const record of chain.slice(0, 3)) {
			const results = await guardianFanOut([a.client, b.client], (client) =>
				client.putState(record)
			);
			expect(
				countReceiptQuorum(
					results,
					context,
					(s) => s.logHead.sequence >= record.sequence
				)
			).to.equal(2);
			for (const r of results)
				writerReceipts.push(r.result?.receipt as IGuardianReceipt);
		}

		// A restore device reconciles: C is behind, records are
		// self-authenticating, SYNC_RECORD repairs it (wire 5.6).
		const cHead = await c.client.getHead(ACCEPT_ROOT.recoveryId);
		expect((cHead.state as GuardianState).logHead.sequence).to.equal(0n);
		for (const record of chain.slice(0, 3)) {
			const synced = await c.client.syncRecord(record);
			expect(synced.status).to.equal(GuardianStatus.OK);
		}
		const caughtUp = await c.client.getHead(ACCEPT_ROOT.recoveryId);
		expect(
			statesEqual(
				caughtUp.state as GuardianState,
				(await a.client.getHead(ACCEPT_ROOT.recoveryId)).state as GuardianState
			)
		).to.equal(true);

		// Silent truncation: A loses its tail on disk. The reopened guardian
		// confesses (possibly_stale, shorter head) because the declared head
		// no longer verifies; the writer's own retained receipt proves the
		// truncation regardless of what the guardian claims.
		await a.server.close();
		a.guardian.close();
		const raw = new Database(fileA);
		raw
			.prepare('DELETE FROM guardian_records WHERE sequence > ?')
			.run(u64be(2n));
		raw.close();
		const alarms: IGuardianAlarm[] = [];
		const reopened = await serveGuardian(0, fileA, (alarm) =>
			alarms.push(alarm)
		);
		expect(
			alarms.some((x) => x.status === GuardianStatus.ERR_STORE_UNCERTAIN)
		).to.equal(true);
		const truncatedHead = await reopened.client.getHead(ACCEPT_ROOT.recoveryId);
		expect(truncatedHead.possiblyStale).to.equal(true);
		expect((truncatedHead.state as GuardianState).logHead.sequence).to.equal(
			2n
		);
		const retained = writerReceipts.find(
			(r) =>
				r &&
				r.guardianId.equals(ACCEPT_GUARDIAN_IDS[0]) &&
				r.state.logHead.sequence === 3n
		) as IGuardianReceipt;
		expect(verifyGuardianReceipt(retained, context)).to.equal(true);
		expect(
			retained.state.logHead.sequence >
				(truncatedHead.state as GuardianState).logHead.sequence
		).to.equal(true);

		// Ordinary writes refuse until repaired; SYNC_RECORD replays the
		// missing record; quorum evidence from the OTHER guardians' current
		// receipts lifts writability at the byte-exact target (wire 5.10).
		const refused = await reopened.client.putState(chain[3]);
		expect(refused.status).to.equal(GuardianStatus.ERR_STORE_UNCERTAIN);
		expect((await reopened.client.syncRecord(chain[2])).status).to.equal(
			GuardianStatus.OK
		);
		const target = (await b.client.getHead(ACCEPT_ROOT.recoveryId))
			.state as GuardianState;
		const evidence = [
			(await b.client.getHead(ACCEPT_ROOT.recoveryId))
				.receipt as IGuardianReceipt,
			(await c.client.getHead(ACCEPT_ROOT.recoveryId))
				.receipt as IGuardianReceipt
		];
		const lifted = reopened.guardian.submitRepairEvidence({
			recoveryId: ACCEPT_ROOT.recoveryId,
			target,
			receipts: evidence,
			certificates: []
		});
		expect(lifted.status).to.equal(GuardianStatus.OK);
		const healthy = await reopened.client.getHead(ACCEPT_ROOT.recoveryId);
		expect(healthy.possiblyStale).to.equal(false);

		// The writer continues on the repaired guardian.
		const resumed = await reopened.client.putState(chain[3]);
		expect(resumed.status).to.equal(GuardianStatus.OK);

		await reopened.server.close();
		reopened.guardian.close();
		await b.server.close();
		b.guardian.close();
		await c.server.close();
		c.guardian.close();
	});

	it('repairs a missed takeover through SYNC_EPOCH and reconciles the minority tail', async function () {
		this.timeout(30_000);
		const a = await serveGuardian(0);
		const b = await serveGuardian(1);
		const c = await serveGuardian(2);
		const registration = buildRegistrationFor(
			ACCEPT_ROOT,
			ACCEPT_SET_ID,
			ACCEPT_WRITER.pub
		);
		const chain = acceptChain(3);
		await guardianFanOut([a.client, b.client, c.client], (client) =>
			client.register(registration)
		);
		for (const record of chain.slice(0, 2)) {
			await guardianFanOut([a.client, b.client, c.client], (client) =>
				client.putState(record)
			);
		}
		// The dying device lands record 3 on C alone: a sub-threshold tail.
		expect((await c.client.putState(chain[2])).status).to.equal(
			GuardianStatus.OK
		);

		// The restore device reads every head and finds the divergence.
		const heads = await guardianFanOut(
			[a.client, b.client, c.client],
			(client) => client.getHead(ACCEPT_ROOT.recoveryId)
		);
		const headSeqs = heads.map(
			(h) => (h.result?.state as GuardianState).logHead.sequence
		);
		expect(headSeqs).to.deep.equal([2n, 2n, 3n]);

		// Takeover against the QUORUM head (2): CAS succeeds on A and B with
		// the same dual-signed request; C never sees it.
		const quorumState = heads[0].result?.state as GuardianState;
		const newWriter = makeTestWriter('accept-writer-2');
		const acquire = buildAcquireFor(ACCEPT_ROOT, quorumState, newWriter);
		const certA = (await a.client.acquireEpoch(acquire))
			.certificate as IGuardianTakeoverCertificate;
		const certB = (await b.client.acquireEpoch(acquire))
			.certificate as IGuardianTakeoverCertificate;
		expect(certA && certB).to.not.equal(undefined);

		// C missed the takeover: the certificate bundle repairs it, fixing
		// the superseded final head at 2 and truncating its minority tail
		// into the orphan archive (wire 5.7).
		const synced = await c.client.syncEpoch([certA, certB]);
		expect(synced.status).to.equal(GuardianStatus.OK);
		const cState = (await c.client.getHead(ACCEPT_ROOT.recoveryId))
			.state as GuardianState;
		expect(cState.lease.epoch).to.equal(2n);
		expect(cState.logHead.sequence).to.equal(2n);
		const orphans = c.guardian.listOrphanedRecords(ACCEPT_ROOT.recoveryId);
		expect(orphans.length).to.equal(1);
		expect(orphans[0].reason).to.equal('sync-epoch-truncation');
		expect(orphans[0].frameHash.equals(chain[2].frameHash)).to.equal(true);

		// The new writer re-fills sequence 3 under epoch 2 everywhere; the
		// discarded tail never resurfaces in GET_STATE.
		const refill = signRecordFor(
			ACCEPT_SET_ID,
			ACCEPT_ROOT.recoveryId,
			newWriter.secret,
			{
				epoch: 2n,
				sequence: 3n,
				previousHash: chain[1].frameHash,
				frameHash: sha('accept-refill-frame-3'),
				ciphertext: sha('accept-refill-ct-3')
			}
		);
		const refills = await guardianFanOut(
			[a.client, b.client, c.client],
			(client) => client.putState(refill)
		);
		expect(
			refills.filter((r) => r.result?.status === GuardianStatus.OK).length
		).to.equal(3);
		const finalHeads = await guardianFanOut(
			[a.client, b.client, c.client],
			(client) => client.getHead(ACCEPT_ROOT.recoveryId)
		);
		for (const h of finalHeads) {
			expect(
				statesEqual(
					h.result?.state as GuardianState,
					finalHeads[0].result?.state as GuardianState
				)
			).to.equal(true);
		}
		const served = await c.client.getState(ACCEPT_ROOT.recoveryId, 2n);
		const servedRecords = served.records as IGuardianRecord[];
		expect(servedRecords.length).to.equal(1);
		expect(servedRecords[0].frameHash.equals(refill.frameHash)).to.equal(true);

		await a.server.close();
		a.guardian.close();
		await b.server.close();
		b.guardian.close();
		await c.server.close();
		c.guardian.close();
	});
});

// ─────────────── flagship: restore from guardian replicas ───────────────

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(`guardian-acceptance-seed-${id}`)
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

/**
 * Deterministic dump of every safety-critical table (slimmed copy of the
 * phase 2 helper; keep them in sync). Row ids and created_at nonsemantic.
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

function openStorage(): SqliteStorage {
	const storage = new SqliteStorage(':memory:');
	storage.open();
	return storage;
}

describe('Guardian acceptance: restore from guardian replicas end to end', () => {
	it('replicates the journal, loses the device, restores from guardians, reestablishes, pays', async function () {
		this.timeout(60_000);

		// A journaled node with one live channel and an invoice.
		const liveStorage = openStorage();
		const alice = createNode(1, liveStorage, true);
		const bob = createNode(2, undefined, false);
		connectNodes(alice, bob);
		openReadyChannel(alice, bob);
		alice.createInvoice({ amountMsat: 25_000n, description: 'pre-restore' });

		// The writer replicates every journal frame as a signed guardian
		// record. Wire 4.1: the root-committed origin is the retained base
		// position; for this fresh journal that is sequence 1 with a zero
		// previous hash, and the frames all sit under writer epoch 1.
		const aliceKey = makeNodeConfig(1).nodePrivateKey;
		const root = deriveRecoveryRoot(aliceKey);
		const writer = makeTestWriter('accept-flagship-writer');
		const rows = liveStorage.loadRecoveryFrames();
		expect(rows.length).to.be.greaterThan(0);
		expect(rows[0].sequence).to.equal(1);
		expect(rows.every((r) => r.writerEpoch === 1)).to.equal(true);

		const a = await serveGuardian(0);
		const b = await serveGuardian(1);
		const c = await serveGuardian(2);
		const clients = [a.client, b.client, c.client];
		const context = {
			guardianSetId: ACCEPT_SET_ID,
			members: ACCEPT_GUARDIAN_IDS
		};
		const registration = buildRegistrationFor(root, ACCEPT_SET_ID, writer.pub);
		const registered = await guardianFanOut(clients, (client) =>
			client.register(registration)
		);
		expect(
			registered.filter((r) => r.result?.status === GuardianStatus.OK).length
		).to.equal(3);
		for (const row of rows) {
			const record = signRecordFor(
				ACCEPT_SET_ID,
				root.recoveryId,
				writer.secret,
				{
					epoch: BigInt(row.writerEpoch),
					sequence: BigInt(row.sequence),
					previousHash: row.previousFrameHash,
					frameHash: row.frameHash,
					ciphertext: row.ciphertext
				}
			);
			const results = await guardianFanOut(clients, (client) =>
				client.putState(record)
			);
			// The barrier discipline counts the record durable at 2 distinct
			// receipts; all three guardians are up here.
			expect(
				countReceiptQuorum(
					results,
					context,
					(s) => s.logHead.sequence >= BigInt(row.sequence)
				)
			).to.equal(3);
		}

		// Total device loss. Everything alice had dies with the process; the
		// dump taken here is what the guardians must reproduce.
		const preDump = dumpTables(liveStorage);
		alice.destroy();
		bob.removeAllListeners('message:outbound');
		bob
			.getChannelManager()
			.handlePeerDisconnected(getPublicKey(aliceKey).toString('hex'));

		// The restore device fetches the head bundle, cross-checks it, and
		// pages the records back (deliberately small pages to walk has_more).
		const headBundle = await a.client.getHead(root.recoveryId);
		expect(headBundle.status).to.equal(GuardianStatus.OK);
		const head = headBundle.state as GuardianState;
		expect(
			verifyGuardianReceipt(headBundle.receipt as IGuardianReceipt, context)
		).to.equal(true);
		const fetched: IGuardianRecord[] = [];
		let cursor = 0n;
		for (;;) {
			const page = await a.client.getState(root.recoveryId, cursor, 2);
			for (const record of page.records as IGuardianRecord[]) {
				fetched.push(record);
				cursor = record.sequence;
			}
			if (!page.hasMore) break;
		}
		expect(BigInt(fetched.length)).to.equal(head.logHead.sequence);
		const last = fetched[fetched.length - 1];
		expect(last.frameHash.equals(head.logHead.frameHash)).to.equal(true);
		expect(
			sha256buf(last.ciphertext).equals(head.logHead.ciphertextHash)
		).to.equal(true);

		// Rebuild a fresh database from the fetched records alone: store the
		// frames, recreate the journal meta the chain verification needs, and
		// replay. The result must be byte-identical to the lost device.
		const restoredStorage = openStorage();
		const frameRows = fetched.map((record) => ({
			sequence: Number(record.sequence),
			writerEpoch: Number(record.epoch),
			frameHash: record.frameHash,
			previousFrameHash: record.previousHash,
			ciphertext: record.ciphertext,
			createdAt: Date.now()
		}));
		const frames = verifyFrameChain(
			frameRows,
			{
				tipSequence: String(last.sequence),
				tipHash: last.frameHash.toString('hex'),
				lastSnapshotSequence: String(frameRows[0].sequence)
			},
			deriveRecoveryMasterKey(aliceKey),
			getPublicKey(aliceKey)
		);
		restoredStorage.transaction(() => {
			for (const row of frameRows) restoredStorage.saveRecoveryFrame!(row);
			restoredStorage.setRecoveryMeta!(
				JOURNAL_META_KEYS.tipSequence,
				String(last.sequence)
			);
			restoredStorage.setRecoveryMeta!(
				JOURNAL_META_KEYS.tipHash,
				last.frameHash.toString('hex')
			);
			restoredStorage.setRecoveryMeta!(JOURNAL_META_KEYS.writerEpoch, '1');
			restoredStorage.setRecoveryMeta!(
				JOURNAL_META_KEYS.lastSnapshot,
				String(frameRows[0].sequence)
			);
		});
		reconstructFromFrames(restoredStorage, frames);
		expect(dumpTables(restoredStorage)).to.equal(preDump);

		// The restored node resumes the channel via reestablish. A real
		// connection delivers BOTH reestablish messages before any responses
		// they trigger, so hold a FIFO until both sides have sent theirs.
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
		while (queue.length > 0) {
			const m = queue.shift()!;
			m.to.handlePeerMessage(m.from, m.type, m.payload);
		}
		hold = false;

		expect(restored.getChannelManager().listChannels()[0].getState()).to.equal(
			ChannelState.NORMAL
		);
		expect(bob.getChannelManager().listChannels()[0].getState()).to.equal(
			ChannelState.NORMAL
		);

		buildDirectGraph(restored);
		const invoice = bob.createInvoice({
			amountMsat: 50_000n,
			description: 'post-restore'
		});
		const payment = restored.sendPayment(invoice.bolt11);
		expect(payment.status).to.equal(PaymentStatus.COMPLETED);

		restored.destroy();
		bob.destroy();
		await a.server.close();
		a.guardian.close();
		await b.server.close();
		b.guardian.close();
		await c.server.close();
		c.guardian.close();
	});
});
