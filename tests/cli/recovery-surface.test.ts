/**
 * The daemon Recovery Protocol surface (docs/RECOVERY-PROTOCOL.md section 8,
 * issue #435): env-shaped config validation, GET /recovery/status as the
 * capability probe, the restore-pending hold, and the REST-driven guardian
 * restore that resumes a node on a fresh database.
 *
 * Boots offline (unreachable Electrum, the auth-scopes pattern); the
 * guardians are in-process reference guardians over real TCP.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import { IStartedDaemon, startDaemon } from '../../src/cli/daemon';
import { resolveConfig } from '../../src/cli/config';
import { BeignetError } from '../../src/cli/errors';
import {
	GuardianHttpServer,
	ReferenceGuardian,
	composeRecoveryCapsule,
	decodeRecoveryCapsuleBlob,
	encryptRecoveryCapsule,
	xOnlyFromSecret
} from '../../src/lightning/recovery';
import { decodeScb, encodeScb } from '../../src/lightning/backup/scb';
import {
	LnCoinType,
	deriveLightningKeysFromMnemonic
} from '../../src/lightning/keys/wallet-keys';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import * as bip39 from 'bip39';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const sha = (s: string): Buffer =>
	crypto.createHash('sha256').update(s).digest();

const NODE_SECRET = deriveLightningKeysFromMnemonic(
	MNEMONIC,
	undefined,
	LnCoinType.REGTEST
).nodePrivateKey;
const GUARDIAN_SECRETS = [1, 2, 3].map((i) => sha(`surface-guardian-${i}`));
const GUARDIAN_IDS = GUARDIAN_SECRETS.map((s) => xOnlyFromSecret(s));

const OFFLINE = {
	electrumHost: '127.0.0.1',
	electrumPort: 65529,
	electrumTls: false,
	rapidGossipSync: false,
	autoGossipSync: false,
	logLevel: 'silent' as const,
	network: 'regtest' as const,
	mnemonic: MNEMONIC,
	daemonPort: 0
};

interface IServed {
	guardian: ReferenceGuardian;
	server: GuardianHttpServer;
	uri: string;
}

async function serve(index: number): Promise<IServed> {
	const guardian = new ReferenceGuardian({
		path: ':memory:',
		guardianSecret: GUARDIAN_SECRETS[index],
		members: GUARDIAN_IDS
	});
	const server = new GuardianHttpServer({ guardian });
	const port = await server.listen(0);
	return {
		guardian,
		server,
		uri: `${GUARDIAN_IDS[index].toString('hex')}@http://127.0.0.1:${port}`
	};
}

async function shutdown(served: IServed[]): Promise<void> {
	for (const entry of served) {
		try {
			await entry.server.close();
			entry.guardian.close();
		} catch {
			// Already closed.
		}
	}
}

function tmpDir(tag: string): string {
	return fs.mkdtempSync(path.join(os.tmpdir(), `beignet-recovery-${tag}-`));
}

function portOf(daemon: IStartedDaemon): number {
	return (daemon.server.address() as AddressInfo).port;
}

function request(
	port: number,
	method: string,
	urlPath: string,
	body?: Record<string, unknown>,
	token?: string
): Promise<{ status: number; body: Record<string, unknown> }> {
	return new Promise((resolve, reject) => {
		const payload = body ? JSON.stringify(body) : undefined;
		const headers: Record<string, string | number> = {};
		if (token) headers['Authorization'] = `Bearer ${token}`;
		if (payload) {
			headers['Content-Type'] = 'application/json';
			headers['Content-Length'] = Buffer.byteLength(payload);
		}
		const req = http.request(
			{ hostname: '127.0.0.1', port, path: urlPath, method, headers },
			(res) => {
				const chunks: Buffer[] = [];
				res.on('data', (chunk: Buffer) => chunks.push(chunk));
				res.on('end', () => {
					try {
						resolve({
							status: res.statusCode!,
							body: JSON.parse(Buffer.concat(chunks).toString())
						});
					} catch {
						resolve({ status: res.statusCode!, body: {} });
					}
				});
			}
		);
		req.on('error', reject);
		if (payload) req.write(payload);
		req.end();
	});
}

async function waitFor(
	predicate: () => boolean | Promise<boolean>,
	timeoutMs = 20_000
): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	for (;;) {
		if (await predicate()) return;
		if (Date.now() > deadline) throw new Error('waitFor timed out');
		await new Promise((resolve) => setTimeout(resolve, 50));
	}
}

function readinessCheck(
	body: Record<string, unknown>,
	name: string
): { status: string; severity: string; message: string } {
	const checks = (
		body.result as {
			checks: Array<{
				name: string;
				status: string;
				severity: string;
				message: string;
			}>;
		}
	).checks;
	const check = checks.find((c) => c.name === name);
	expect(check, `readiness check ${name} present`).to.not.equal(undefined);
	return check!;
}

async function expectStartRefused(
	opts: Record<string, unknown>,
	message: RegExp
): Promise<void> {
	let error: unknown = null;
	try {
		const daemon = await startDaemon({ ...OFFLINE, ...opts });
		await daemon.stop();
	} catch (e) {
		error = e;
	}
	expect(error, 'expected startDaemon to refuse').to.be.instanceOf(
		BeignetError
	);
	expect((error as BeignetError).code).to.equal('INVALID_PARAMS');
	expect((error as BeignetError).message).to.match(message);
}

describe('Recovery surface: configuration validation (pre-boot)', () => {
	const dir = tmpDir('validate');
	after(() => fs.rmSync(dir, { recursive: true, force: true }));

	it('refuses a guardian mode without exactly three guardians', async () => {
		await expectStartRefused(
			{ dataDir: dir, recoveryMode: 'quorum' },
			/needs exactly 3 guardians/
		);
		await expectStartRefused(
			{
				dataDir: dir,
				recoveryMode: 'async-remote',
				recoveryGuardians: [
					`${GUARDIAN_IDS[0].toString('hex')}@http://127.0.0.1:1`
				]
			},
			/needs exactly 3 guardians/
		);
	});

	it('refuses malformed guardian URIs with the parser message', async () => {
		await expectStartRefused(
			{
				dataDir: dir,
				recoveryMode: 'quorum',
				recoveryGuardians: [
					'http://127.0.0.1:1',
					`${GUARDIAN_IDS[1].toString('hex')}@http://127.0.0.1:2`,
					`${GUARDIAN_IDS[2].toString('hex')}@http://127.0.0.1:3`
				]
			},
			/missing the pubkey@url separator/
		);
	});

	it('refuses a credential inside a guardian URL and a malformed structured entry', async () => {
		const ids = GUARDIAN_IDS.map((id) => id.toString('hex'));
		await expectStartRefused(
			{
				recoveryMode: 'quorum',
				recoveryGuardians: [
					`${ids[0]}@https://alice:secret@g1.example`,
					`${ids[1]}@https://g2.example`,
					`${ids[2]}@https://g3.example`
				]
			},
			/credentials in the URL/
		);
		await expectStartRefused(
			{
				recoveryMode: 'quorum',
				recoveryGuardians: [
					{
						guardianId: ids[0],
						url: 'https://g1.example',
						auth: { type: 'nope' }
					},
					{ guardianId: ids[1], url: 'https://g2.example' },
					{ guardianId: ids[2], url: 'https://g3.example' }
				]
			},
			/not a known credential shape/
		);
	});

	it('refuses guardians configured without a guardian mode, typos included', async () => {
		const guardians = GUARDIAN_IDS.map(
			(id, i) => `${id.toString('hex')}@http://127.0.0.1:${i + 1}`
		);
		// A typo in the mode resolves to off; guardians beside it refuse
		// startup instead of silently running unprotected.
		await expectStartRefused(
			{
				dataDir: dir,
				recoveryMode: 'quorumm',
				recoveryGuardians: guardians
			},
			/guardians need async-remote or quorum/
		);
		await expectStartRefused(
			{ dataDir: dir, recoveryGuardians: guardians },
			/guardians need async-remote or quorum/
		);
	});

	it('refuses a lease check interval Node would turn into a 1 ms poll', async () => {
		// NaN (an unparseable env value) and anything past 2^31-1 ms both
		// become a 1 ms timer in Node, which would hammer the guardian set.
		process.env.BEIGNET_RECOVERY_LEASE_CHECK_MS = 'soon';
		try {
			expect(
				Number.isNaN(resolveConfig({}).recoveryLeaseCheckIntervalMs)
			).to.equal(true);
		} finally {
			delete process.env.BEIGNET_RECOVERY_LEASE_CHECK_MS;
		}
		await expectStartRefused(
			{ dataDir: dir, recoveryLeaseCheckIntervalMs: Number.NaN },
			/BEIGNET_RECOVERY_LEASE_CHECK_MS must be an integer/
		);
		await expectStartRefused(
			{ dataDir: dir, recoveryLeaseCheckIntervalMs: 2 ** 31 },
			/BEIGNET_RECOVERY_LEASE_CHECK_MS must be an integer/
		);
		await expectStartRefused(
			{ dataDir: dir, recoveryLeaseCheckIntervalMs: 1.5 },
			/BEIGNET_RECOVERY_LEASE_CHECK_MS must be an integer/
		);
	});

	it('refuses an unknown recovery profile', async () => {
		await expectStartRefused(
			{ dataDir: dir, recoveryProfile: 'byzantine-v9' },
			/crash-v1 is the only accepted value/
		);
	});
});

describe('Recovery surface: status and refusals on a running daemon', () => {
	let daemon: IStartedDaemon;
	let dir: string;

	before(async function (): Promise<void> {
		this.timeout(30_000);
		dir = tmpDir('off');
		daemon = await startDaemon({ ...OFFLINE, dataDir: dir });
	});

	after(async function (): Promise<void> {
		this.timeout(30_000);
		await daemon.stop();
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it('GET /recovery/status answers 200 with state disabled when off', async () => {
		const res = await request(portOf(daemon), 'GET', '/recovery/status');
		expect(res.status).to.equal(200);
		expect(res.body.ok).to.equal(true);
		const result = res.body.result as Record<string, unknown>;
		expect(result.mode).to.equal('off');
		expect(result.state).to.equal('disabled');
		expect(result.profile).to.equal(null);
		expect(result.guardians).to.deep.equal([]);
		expect(result.node).to.equal(null);
	});

	it('GET /readiness warns on CHANNEL_BACKUP when recovery is off', async () => {
		const res = await request(portOf(daemon), 'GET', '/readiness');
		expect(res.status).to.equal(200);
		const check = readinessCheck(res.body, 'CHANNEL_BACKUP');
		expect(check.status).to.equal('WARN');
		expect(check.severity).to.equal('WARNING');
		expect(check.message).to.match(/force-close/);
	});

	it('POST /recovery/restore without confirm is refused', async () => {
		const res = await request(portOf(daemon), 'POST', '/recovery/restore', {});
		expect(res.status).to.equal(400);
		expect((res.body.error as { code: string }).code).to.equal(
			'INVALID_PARAMS'
		);
	});

	it('POST /recovery/restore-capsule with recovery off is unsupported', async () => {
		const res = await request(
			portOf(daemon),
			'POST',
			'/recovery/restore-capsule',
			{
				confirm: true
			}
		);
		expect(res.status).to.equal(409);
		expect((res.body.error as { code: string }).code).to.equal(
			'CAPSULE_RESTORE_UNSUPPORTED'
		);
	});

	it('POST /recovery/restore on a running node answers RESTORE_NOT_PENDING', async () => {
		const res = await request(portOf(daemon), 'POST', '/recovery/restore', {
			confirm: true
		});
		expect(res.status).to.equal(409);
		expect((res.body.error as { code: string }).code).to.equal(
			'RESTORE_NOT_PENDING'
		);
	});
});

describe('Recovery surface: peer-storage mode', () => {
	it('runs with the journal on and reports durability local', async function (): Promise<void> {
		this.timeout(30_000);
		const dir = tmpDir('peer-storage');
		const daemon = await startDaemon({
			...OFFLINE,
			dataDir: dir,
			recoveryMode: 'peer-storage'
		});
		try {
			const res = await request(portOf(daemon), 'GET', '/recovery/status');
			expect(res.status).to.equal(200);
			const result = res.body.result as {
				mode: string;
				state: string;
				node: { durability: string; gate: string } | null;
			};
			expect(result.mode).to.equal('peer-storage');
			expect(result.state).to.equal('running');
			expect(result.node?.durability).to.equal('local');
			expect(result.node?.gate).to.equal('disabled');
			const readiness = await request(portOf(daemon), 'GET', '/readiness');
			const check = readinessCheck(readiness.body, 'CHANNEL_BACKUP');
			expect(check.status).to.equal('WARN');
			expect(check.message).to.match(/storage peers/);
		} finally {
			await daemon.stop();
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});
});

describe('Recovery surface: capsule restore in peer-storage mode', () => {
	const PEER_A = '02' + 'a1'.repeat(32);
	const PEER_B = '02' + 'b2'.repeat(32);
	const ADMIN_KEY = 'a'.repeat(64);
	const MONITOR_KEY = 'b'.repeat(64);
	const emptyScb = (network: string): string =>
		encodeScb(
			{ version: 1, network, createdAt: Date.now(), channels: [] },
			NODE_SECRET
		);

	/** Feed a blob in as if a storage peer had returned it on reconnect. */
	function retrieved(daemon: IStartedDaemon, peer: string, blob: Buffer): void {
		daemon.node.getNode().emit('peer_storage:retrieved', peer, blob);
	}

	async function statusOf(
		port: number,
		token?: string
	): Promise<{
		state: string;
		capsules: {
			candidates: number;
			best: { inline: boolean; latestSequence: string } | null;
		};
	}> {
		const res = await request(
			port,
			'GET',
			'/recovery/status',
			undefined,
			token
		);
		expect(res.status).to.equal(200);
		return res.body.result as {
			state: string;
			capsules: {
				candidates: number;
				best: { inline: boolean; latestSequence: string } | null;
			};
		};
	}

	it('recognizes capsules, surfaces the embedded SCB, and restores Tier 2 across a restart', async function (): Promise<void> {
		this.timeout(180_000);
		const dirA = tmpDir('capsule-a');
		const dirB = tmpDir('capsule-b');
		try {
			// Device A: one journaled commit (an invoice), which composes the
			// capsule the library would push to storage peers. A second
			// candidate is the SCB-only twin of the same head (the degraded
			// compose), to prove the restore picks the replica that validates
			// inline rather than the first one that arrived.
			const deviceA = await startDaemon({
				...OFFLINE,
				dataDir: dirA,
				recoveryMode: 'peer-storage'
			});
			const portA = portOf(deviceA);
			const invoice = await request(portA, 'POST', '/invoice/create', {
				amountSats: 2100,
				description: 'capsule restore probe'
			});
			expect(invoice.body.ok, JSON.stringify(invoice.body)).to.equal(true);
			const paymentHash = (invoice.body.result as { paymentHash: string })
				.paymentHash;
			const inlineBlob = (
				deviceA.node.getNode() as unknown as {
					ourPeerStorageBlob: Buffer | null;
				}
			).ourPeerStorageBlob;
			expect(
				inlineBlob,
				'a node holding state composes a capsule'
			).to.not.equal(null);
			const storageA = (deviceA.node as unknown as { storage: SqliteStorage })
				.storage;
			const scbOnlyBlob = composeRecoveryCapsule({
				storage: storageA,
				encryptedScb: emptyScb('bcrt'),
				nodeSecret: NODE_SECRET,
				allowInline: false
			}).blob;
			// A capsule this seed's node composed on ANOTHER network: testnet,
			// regtest and signet share a coin type, so it authenticates here.
			const foreignNetworkBlob = composeRecoveryCapsule({
				storage: storageA,
				encryptedScb: emptyScb('tb'),
				nodeSecret: NODE_SECRET
			}).blob;
			await deviceA.stop();

			// Device B: same seed, fresh database, peer-storage mode. It boots
			// normally (there is no guardian set to ask), and pushes nothing
			// while empty, so the peers keep the capsule for it. It carries
			// API keys so the restore can prove a revocation survives.
			const bootB = (): Promise<IStartedDaemon> =>
				startDaemon({
					...OFFLINE,
					dataDir: dirB,
					recoveryMode: 'peer-storage',
					apiToken: ADMIN_KEY,
					apiKeys: [{ name: 'monitor', key: MONITOR_KEY, scopes: ['readonly'] }]
				});
			const get = (
				port: number,
				urlPath: string,
				token = ADMIN_KEY
			): Promise<{ status: number; body: Record<string, unknown> }> =>
				request(port, 'GET', urlPath, undefined, token);
			const post = (
				port: number,
				urlPath: string,
				body: Record<string, unknown>
			): Promise<{ status: number; body: Record<string, unknown> }> =>
				request(port, 'POST', urlPath, body, ADMIN_KEY);
			let deviceB = await bootB();
			let portB = portOf(deviceB);
			let report: { head: { writerEpoch: string; latestSequence: string } };
			try {
				// A revoked key must stay dead across the restore: the override
				// lives in the database the swap replaces. So must a webhook.
				expect((await get(portB, '/info', MONITOR_KEY)).status).to.equal(200);
				const revoke = await post(portB, '/auth/keys/revoke', {
					name: 'monitor'
				});
				expect(revoke.status).to.equal(200);
				expect((await get(portB, '/info', MONITOR_KEY)).status).to.equal(401);
				const hook = await post(portB, '/webhooks/register', {
					url: 'http://127.0.0.1:9/hook',
					events: ['payment:received']
				});
				expect(hook.status, JSON.stringify(hook.body)).to.equal(200);

				expect(
					(
						deviceB.node.getNode() as unknown as {
							ourPeerStorageBlob: Buffer | null;
						}
					).ourPeerStorageBlob,
					'an empty node pushes no capsule'
				).to.equal(null);
				expect((await statusOf(portB, ADMIN_KEY)).capsules).to.deep.equal({
					candidates: 0,
					best: null
				});
				expect((await get(portB, '/backup/peer-retrieved')).status).to.equal(
					404
				);
				const early = await post(portB, '/recovery/restore-capsule', {
					confirm: true
				});
				expect(early.status).to.equal(404);
				expect((early.body.error as { code: string }).code).to.equal(
					'CAPSULE_RESTORE_NO_CANDIDATES'
				);
				const unconfirmed = await post(portB, '/recovery/restore-capsule', {});
				expect(unconfirmed.status).to.equal(400);

				// Garbage is still ignored, so is the other-network capsule
				// (left in, its newer head would win the selection and fail the
				// whole restore); the capsules are recognized.
				retrieved(deviceB, PEER_A, crypto.randomBytes(200));
				retrieved(deviceB, PEER_A, foreignNetworkBlob);
				expect((await statusOf(portB, ADMIN_KEY)).capsules.candidates).to.equal(
					0
				);
				expect((await get(portB, '/backup/peer-retrieved')).status).to.equal(
					404
				);
				retrieved(deviceB, PEER_A, scbOnlyBlob);
				let status = await statusOf(portB, ADMIN_KEY);
				expect(status.capsules.candidates).to.equal(1);
				expect(status.capsules.best?.inline).to.equal(false);
				retrieved(deviceB, PEER_B, inlineBlob!);
				status = await statusOf(portB, ADMIN_KEY);
				expect(status.capsules.candidates).to.equal(2);
				expect(status.capsules.best?.inline).to.equal(true);
				// The same peer returning the SCB-only twin of the SAME head on
				// a later reconnect must not displace the inline replica.
				retrieved(deviceB, PEER_B, scbOnlyBlob);
				status = await statusOf(portB, ADMIN_KEY);
				expect(status.capsules.candidates).to.equal(2);
				expect(status.capsules.best?.inline).to.equal(true);

				// Tier 1 never regresses: the embedded SCB is surfaced under the
				// wallet seed, the key POST /restore/scb decodes with.
				const surfaced = await get(portB, '/backup/peer-retrieved');
				expect(surfaced.status).to.equal(200);
				const scb = surfaced.body.result as {
					encoded: string;
					source: string;
					channelCount: number;
				};
				expect(scb.source).to.equal('capsule');
				expect(scb.channelCount).to.equal(0);
				const decoded = decodeScb(
					scb.encoded,
					bip39.mnemonicToSeedSync(MNEMONIC)
				);
				expect(decoded.network).to.equal('bcrt');

				const progress: string[] = [];
				const restored: Array<Record<string, unknown>> = [];
				deviceB.node.on('recovery:restore-progress', (data) =>
					progress.push((data as { type: string }).type)
				);
				deviceB.node.on('recovery:restored', (data) =>
					restored.push(data as Record<string, unknown>)
				);
				const res = await post(portB, '/recovery/restore-capsule', {
					confirm: true
				});
				expect(res.body.ok, JSON.stringify(res.body)).to.equal(true);
				const result = res.body.result as {
					tier: number;
					framesApplied: number;
					rejectedCandidates: number;
					restartRequired: boolean;
					head: { writerEpoch: string; latestSequence: string };
				};
				report = result;
				expect(result.tier).to.equal(2);
				expect(result.framesApplied).to.be.at.least(1);
				expect(result.rejectedCandidates).to.equal(1);
				expect(result.restartRequired).to.equal(true);
				expect(progress).to.include('capsule:installed');
				expect(progress).to.include('restore:complete');
				expect(restored).to.have.length(1);
				expect(restored[0].tier).to.equal(2);

				// The daemon holds for a restart: nothing but the recovery
				// surface answers, and the status says why.
				const held = await get(portB, '/info');
				expect(held.status).to.equal(503);
				expect((held.body.error as { code: string }).code).to.equal(
					'NODE_RESTART_REQUIRED'
				);
				const heldStatus = await statusOf(portB, ADMIN_KEY);
				expect(heldStatus.state).to.equal('restart-required');
				expect(heldStatus.capsules.candidates).to.equal(2);
			} finally {
				await deviceB.stop();
			}

			// The previous database is kept beside the restored one; the swap
			// marker cleared.
			const files = fs.readdirSync(dirB);
			expect(files).to.include('regtest.db');
			const kept = files.find((f) =>
				f.startsWith('regtest.db.pre-capsule-restore-')
			);
			expect(kept).to.not.equal(undefined);
			expect(files.some((f) => f.endsWith('.capsule-restore'))).to.equal(false);
			expect(files).to.not.include('regtest.capsule-restore.json');

			const expectRestoredState = async (port: number): Promise<void> => {
				const after = await statusOf(port, ADMIN_KEY);
				expect(after.state).to.equal('running');
				expect(after.capsules.candidates).to.equal(0);
				const found = await get(port, `/invoice?paymentHash=${paymentHash}`);
				expect(found.status, JSON.stringify(found.body)).to.equal(200);
				expect(
					(found.body.result as { description: string }).description
				).to.equal('capsule restore probe');
				// Daemon state followed the operator: the revoked key is still
				// dead and the webhook is still registered.
				expect((await get(port, '/info', MONITOR_KEY)).status).to.equal(401);
				const hooks = await get(port, '/webhooks');
				expect(hooks.status).to.equal(200);
				expect(
					(hooks.body.result as Array<{ url: string }>).map((h) => h.url)
				).to.deep.equal(['http://127.0.0.1:9/hook']);
			};

			// Restart: the node runs on A's exact state.
			deviceB = await bootB();
			portB = portOf(deviceB);
			try {
				await expectRestoredState(portB);
			} finally {
				await deviceB.stop();
			}

			// Kill points inside the swap. The marker makes the two renames
			// durable: a boot that finds it finishes whatever a crash left,
			// from either side of the window, and never opens an empty
			// database instead.
			const dbPath = path.join(dirB, 'regtest.db');
			const stagedPath = path.join(dirB, 'regtest.db.capsule-restore');
			const markerPath = path.join(dirB, 'regtest.capsule-restore.json');
			const marker = JSON.stringify({
				version: 1,
				stagedAt: Date.now(),
				staged: 'regtest.db.capsule-restore',
				keep: 'regtest.db.pre-capsule-restore-replay',
				head: report.head,
				tier: 2
			});
			// (1) Crash between the renames: the canonical database was moved
			// aside and the staged one not yet installed.
			fs.renameSync(dbPath, stagedPath);
			fs.writeFileSync(markerPath, marker);
			deviceB = await bootB();
			portB = portOf(deviceB);
			try {
				await expectRestoredState(portB);
			} finally {
				await deviceB.stop();
			}
			expect(fs.existsSync(markerPath)).to.equal(false);
			expect(fs.existsSync(stagedPath)).to.equal(false);
			// (2) Crash before the first rename: the empty pre-restore database
			// is still canonical beside the fully staged one.
			fs.renameSync(dbPath, stagedPath);
			fs.copyFileSync(path.join(dirB, kept!), dbPath);
			fs.writeFileSync(markerPath, marker);
			deviceB = await bootB();
			portB = portOf(deviceB);
			try {
				await expectRestoredState(portB);
			} finally {
				await deviceB.stop();
			}
			expect(fs.existsSync(markerPath)).to.equal(false);
			expect(
				fs.existsSync(path.join(dirB, 'regtest.db.pre-capsule-restore-replay'))
			).to.equal(true);
		} finally {
			fs.rmSync(dirA, { recursive: true, force: true });
			fs.rmSync(dirB, { recursive: true, force: true });
		}
	});

	it('falls back to Tier 1 on the live node, and refuses a database holding state', async function (): Promise<void> {
		this.timeout(60_000);
		const dir = tmpDir('capsule-tier1');
		const dirDirty = tmpDir('capsule-dirty');
		try {
			const daemon = await startDaemon({
				...OFFLINE,
				dataDir: dir,
				recoveryMode: 'peer-storage'
			});
			const port = portOf(daemon);
			try {
				// An SCB-only capsule (no inline journal): Tier 1 is the whole
				// answer and needs no restart.
				const scratch = new SqliteStorage(':memory:');
				scratch.open();
				const blob = composeRecoveryCapsule({
					storage: scratch,
					encryptedScb: emptyScb('bcrt'),
					nodeSecret: NODE_SECRET
				}).blob;
				scratch.close();
				retrieved(daemon, PEER_A, blob);
				const res = await request(port, 'POST', '/recovery/restore-capsule', {
					confirm: true
				});
				expect(res.body.ok, JSON.stringify(res.body)).to.equal(true);
				const report = res.body.result as {
					tier: number;
					restartRequired: boolean;
					recovering: string[];
				};
				expect(report.tier).to.equal(1);
				expect(report.restartRequired).to.equal(false);
				expect(report.recovering).to.deep.equal([]);
				const info = await request(port, 'GET', '/info');
				expect(info.status).to.equal(200);
				expect((await statusOf(port)).state).to.equal('running');

				// A staged file that cannot be written is an operational
				// failure, not a candidate defect: 500, and the daemon keeps
				// serving. (A directory squatting on the staged path makes the
				// open fail.)
				fs.mkdirSync(path.join(dir, 'regtest.db.capsule-restore'));
				const broken = await request(
					port,
					'POST',
					'/recovery/restore-capsule',
					{ confirm: true }
				);
				expect(broken.status).to.equal(500);
				expect((broken.body.error as { code: string }).code).to.equal(
					'CAPSULE_RESTORE_INSTALL_FAILED'
				);
				fs.rmdirSync(path.join(dir, 'regtest.db.capsule-restore'));
				expect((await statusOf(port)).state).to.equal('running');
				expect((await request(port, 'GET', '/info')).status).to.equal(200);
			} finally {
				await daemon.stop();
			}

			// A database that already holds state is refused, not discarded.
			const dirty = await startDaemon({
				...OFFLINE,
				dataDir: dirDirty,
				recoveryMode: 'peer-storage'
			});
			try {
				const portDirty = portOf(dirty);
				const own = await request(portDirty, 'POST', '/invoice/create', {
					amountSats: 1,
					description: 'local state'
				});
				expect(own.body.ok).to.equal(true);
				const ownBlob = (
					dirty.node.getNode() as unknown as {
						ourPeerStorageBlob: Buffer | null;
					}
				).ourPeerStorageBlob;
				retrieved(dirty, PEER_B, ownBlob!);
				const res = await request(
					portDirty,
					'POST',
					'/recovery/restore-capsule',
					{ confirm: true }
				);
				expect(res.status).to.equal(409);
				expect((res.body.error as { code: string }).code).to.equal(
					'CAPSULE_RESTORE_TARGET_DIRTY'
				);
				expect((await statusOf(portDirty)).state).to.equal('running');
			} finally {
				await dirty.stop();
			}
		} finally {
			fs.rmSync(dir, { recursive: true, force: true });
			fs.rmSync(dirDirty, { recursive: true, force: true });
		}
	});
	it('refuses a capsule that names guardians before either tier acts, and hands the set back on the admin route', async function (): Promise<void> {
		this.timeout(60_000);
		const dir = tmpDir('capsule-guardian-backed');
		const dirSrc = tmpDir('capsule-guardian-src');
		const GUARDIAN_ID = '44'.repeat(32);
		const guardians = [
			{
				guardianId: GUARDIAN_ID,
				transports: [
					{ type: 'https' as const, url: 'https://alice:secret@g1.example' }
				],
				auth: { type: 'bearer' as const, token: 'bearer-secret' }
			}
		];
		try {
			// An inline (Tier 2) candidate naming guardians, composed from a
			// node that holds state.
			const source = await startDaemon({
				...OFFLINE,
				dataDir: dirSrc,
				recoveryMode: 'peer-storage'
			});
			let inlineBlob: Buffer;
			let scbOnlyBlob: Buffer;
			try {
				const own = await request(portOf(source), 'POST', '/invoice/create', {
					amountSats: 1,
					description: 'guardian-backed state'
				});
				expect(own.body.ok).to.equal(true);
				const storageSrc = (
					source.node as unknown as { storage: SqliteStorage }
				).storage;
				inlineBlob = composeRecoveryCapsule({
					storage: storageSrc,
					encryptedScb: emptyScb('bcrt'),
					nodeSecret: NODE_SECRET,
					guardians
				}).blob;
				scbOnlyBlob = composeRecoveryCapsule({
					storage: storageSrc,
					encryptedScb: emptyScb('bcrt'),
					nodeSecret: NODE_SECRET,
					guardians,
					allowInline: false
				}).blob;
			} finally {
				await source.stop();
			}

			const daemon = await startDaemon({
				...OFFLINE,
				dataDir: dir,
				recoveryMode: 'peer-storage',
				apiToken: ADMIN_KEY,
				apiKeys: [{ name: 'monitor', key: MONITOR_KEY, scopes: ['readonly'] }]
			});
			const port = portOf(daemon);
			try {
				const expectUntouched = async (): Promise<void> => {
					expect((await statusOf(port, ADMIN_KEY)).state).to.equal('running');
					expect(
						(await request(port, 'GET', '/info', undefined, ADMIN_KEY)).status
					).to.equal(200);
					expect(
						fs.existsSync(path.join(dir, 'regtest.db.capsule-restore'))
					).to.equal(false);
					expect(
						fs.existsSync(path.join(dir, 'regtest.capsule-restore.json'))
					).to.equal(false);
				};
				const restore = (): Promise<{
					status: number;
					body: Record<string, unknown>;
				}> =>
					request(
						port,
						'POST',
						'/recovery/restore-capsule',
						{ confirm: true },
						ADMIN_KEY
					);

				// Tier 1 shape first: the refusal lands before the SCB path
				// persists DLP recovery or asks a peer to force-close.
				retrieved(daemon, PEER_A, scbOnlyBlob);
				const tier1 = await restore();
				expect(tier1.status).to.equal(409);
				expect((tier1.body.error as { code: string }).code).to.equal(
					'CAPSULE_RESTORE_GUARDIAN_BACKED'
				);
				await expectUntouched();

				// Tier 2 shape: the inline replica displaces the SCB-only twin
				// at the same head, and the refusal lands before the swap.
				retrieved(daemon, PEER_A, inlineBlob);
				const status = await statusOf(port, ADMIN_KEY);
				expect(status.capsules.best?.inline).to.equal(true);
				const tier2 = await restore();
				expect(tier2.status).to.equal(409);
				expect((tier2.body.error as { code: string }).code).to.equal(
					'CAPSULE_RESTORE_GUARDIAN_BACKED'
				);
				await expectUntouched();

				// The readonly status route reports the locators with every
				// credential gone: the structured auth AND the URL userinfo.
				const reported = (
					await request(port, 'GET', '/recovery/status', undefined, MONITOR_KEY)
				).body.result as {
					capsules: { best: { guardians: Array<Record<string, unknown>> } };
				};
				expect(reported.capsules.best.guardians).to.deep.equal([
					{
						guardianId: GUARDIAN_ID,
						transports: [{ type: 'https', url: 'https://g1.example/' }]
					}
				]);

				// The admin handoff is the one place they come back, behind
				// admin scope and an explicit confirm.
				const noConfirm = await request(
					port,
					'POST',
					'/recovery/capsule-guardians',
					{},
					ADMIN_KEY
				);
				expect(noConfirm.status).to.equal(400);
				const readonly = await request(
					port,
					'POST',
					'/recovery/capsule-guardians',
					{ confirm: true },
					MONITOR_KEY
				);
				expect(readonly.status).to.equal(403);
				const handoff = await request(
					port,
					'POST',
					'/recovery/capsule-guardians',
					{ confirm: true },
					ADMIN_KEY
				);
				expect(handoff.status, JSON.stringify(handoff.body)).to.equal(200);
				const revealed = handoff.body.result as {
					fromPeer: string;
					guardians: unknown[];
					entries: unknown[];
				};
				expect(revealed.fromPeer).to.equal(PEER_A);
				expect(revealed.guardians).to.deep.equal(guardians);
				expect(revealed.entries).to.deep.equal([
					{
						guardianId: GUARDIAN_ID,
						url: 'https://alice:secret@g1.example',
						auth: { type: 'bearer', token: 'bearer-secret' }
					}
				]);

				// The escape hatch (issue #459): unfenced restores the
				// guardian-backed capsule anyway. The source chain is local
				// durability, so Tier 2 installs, and the report says what
				// was not fenced. A non-boolean flag is a parameter error.
				const badFlag = await request(
					port,
					'POST',
					'/recovery/restore-capsule',
					{ confirm: true, unfenced: 'yes' },
					ADMIN_KEY
				);
				expect(badFlag.status).to.equal(400);
				// The library API is as strict as the route: a truthy string
				// is not authorization.
				let libraryError: unknown = null;
				try {
					await daemon.node.restoreFromCapsules({
						unfenced: 'false' as unknown as boolean
					});
				} catch (err) {
					libraryError = err;
				}
				expect((libraryError as { code?: string } | null)?.code).to.equal(
					'INVALID_PARAMS'
				);
				await expectUntouched();
				const progress: string[] = [];
				daemon.node.on('recovery:restore-progress', (data) =>
					progress.push((data as { type: string }).type)
				);
				const hatch = await request(
					port,
					'POST',
					'/recovery/restore-capsule',
					{ confirm: true, unfenced: true },
					ADMIN_KEY
				);
				expect(hatch.status, JSON.stringify(hatch.body)).to.equal(200);
				const report = hatch.body.result as {
					tier: number;
					restartRequired: boolean;
					unfenced?: { guardians: Array<Record<string, unknown>> };
				};
				expect(report.tier).to.equal(2);
				expect(report.restartRequired).to.equal(true);
				expect(report.unfenced?.guardians).to.deep.equal([
					{
						guardianId: GUARDIAN_ID,
						transports: [{ type: 'https', url: 'https://g1.example/' }]
					}
				]);
				expect(progress).to.include('capsule:unfenced');
				expect((await statusOf(port, ADMIN_KEY)).state).to.equal(
					'restart-required'
				);
			} finally {
				await daemon.stop();
			}

			// The Tier 1 shape under the hatch recovers on the live node like
			// any SCB restore, and reports the unfenced guardians too.
			const tier1Dir = tmpDir('capsule-guardian-tier1');
			const tier1Daemon = await startDaemon({
				...OFFLINE,
				dataDir: tier1Dir,
				recoveryMode: 'peer-storage'
			});
			try {
				const tier1Port = portOf(tier1Daemon);
				retrieved(tier1Daemon, PEER_A, scbOnlyBlob);
				const hatch = await request(
					tier1Port,
					'POST',
					'/recovery/restore-capsule',
					{ confirm: true, unfenced: true }
				);
				expect(hatch.status, JSON.stringify(hatch.body)).to.equal(200);
				const report = hatch.body.result as {
					tier: number;
					restartRequired: boolean;
					recovering: string[];
					unfenced?: { guardians: unknown[] };
				};
				expect(report.tier).to.equal(1);
				expect(report.restartRequired).to.equal(false);
				expect(report.recovering).to.deep.equal([]);
				expect(report.unfenced?.guardians).to.have.length(1);
				expect((await statusOf(tier1Port)).state).to.equal('running');
			} finally {
				await tier1Daemon.stop();
				fs.rmSync(tier1Dir, { recursive: true, force: true });
			}
		} finally {
			fs.rmSync(dir, { recursive: true, force: true });
			fs.rmSync(dirSrc, { recursive: true, force: true });
		}
	});
});

describe('Recovery surface: guardian quorum lifecycle over REST', () => {
	it('registers, journals, then restores a fresh database through POST /recovery/restore', async function (): Promise<void> {
		this.timeout(120_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const guardianUris = served.map((entry) => entry.uri);
		const dirA = tmpDir('device-a');
		const dirB = tmpDir('device-b');
		try {
			// Device A: register the namespace and make one journaled commit
			// durable on the quorum (an invoice persists its payment secret
			// through the safety-transition layer).
			// Device A stays RUNNING and idle through the takeover below: the
			// periodic lease check (issue #455) is what must notice it.
			const deviceA = await startDaemon({
				...OFFLINE,
				dataDir: dirA,
				recoveryMode: 'quorum',
				recoveryGuardians: guardianUris,
				recoveryLeaseCheckIntervalMs: 200
			});
			const portA = portOf(deviceA);
			const fencedOnA: Array<Record<string, unknown>> = [];
			deviceA.node.on('recovery:fenced', (data) =>
				fencedOnA.push(data as Record<string, unknown>)
			);
			const statusA = await request(portA, 'GET', '/recovery/status');
			expect(statusA.status).to.equal(200);
			const resultA = statusA.body.result as {
				mode: string;
				profile: string;
				guardians: Array<{ guardianId: string; url: string }>;
			};
			expect(resultA.mode).to.equal('quorum');
			expect(resultA.profile).to.equal('crash-v1');
			expect(resultA.guardians).to.have.length(3);

			const invoice = await request(portA, 'POST', '/invoice/create', {
				amountSats: 1000,
				description: 'recovery surface probe'
			});
			expect(invoice.body.ok, JSON.stringify(invoice.body)).to.equal(true);
			await waitFor(async () => {
				const res = await request(portA, 'GET', '/recovery/status');
				const node = (
					res.body.result as { node: { lastDurableSequence: string } }
				).node;
				return node !== null && BigInt(node.lastDurableSequence) >= 1n;
			});
			const confirmedA = await request(portA, 'GET', '/recovery/status');
			expect(
				(confirmedA.body.result as { node: { gate: string } }).node.gate
			).to.equal('confirmed');
			const readyA = await request(portA, 'GET', '/readiness');
			const backupA = readinessCheck(readyA.body, 'CHANNEL_BACKUP');
			expect(backupA.status).to.equal('PASS');
			expect(backupA.message).to.match(/guardian quorum \(quorum/);

			// The capsule A pushes to storage peers names its guardian set
			// (issue #457): one local-http descriptor per configured entry,
			// and no credential key because the URI format carries none.
			const capsuleBlob = (
				deviceA.node.getNode() as unknown as {
					ourPeerStorageBlob: Buffer | null;
				}
			).ourPeerStorageBlob;
			expect(
				capsuleBlob,
				'a guardian-mode node composes a capsule'
			).to.not.equal(null);
			const capsuleA = decodeRecoveryCapsuleBlob(capsuleBlob!, NODE_SECRET);
			expect(capsuleA).to.not.equal(null);
			expect(capsuleA!.guardians).to.deep.equal(
				served.map((entry) => ({
					guardianId: entry.guardian.guardianId.toString('hex'),
					transports: [
						{
							type: 'local-http',
							url: entry.uri.slice(entry.uri.indexOf('@') + 1)
						}
					]
				}))
			);

			// A capsule naming a DIFFERENT set is reported under capsules.best
			// and never adopted: the configured set stays at the top level.
			const foreignIds = [4, 5, 6].map((i) =>
				xOnlyFromSecret(sha(`foreign-guardian-${i}`)).toString('hex')
			);
			const foreignBlob = composeRecoveryCapsule({
				storage: (deviceA.node as unknown as { storage: SqliteStorage })
					.storage,
				encryptedScb: capsuleA!.encryptedScb,
				nodeSecret: NODE_SECRET,
				guardians: foreignIds.map((guardianId, i) => ({
					guardianId,
					transports: [{ type: 'https', url: `https://g${i}.example` }],
					auth: { type: 'bearer', token: `foreign-${i}` }
				}))
			}).blob;
			deviceA.node
				.getNode()
				.emit('peer_storage:retrieved', '02' + 'c3'.repeat(32), foreignBlob);
			const foreignStatus = await request(portA, 'GET', '/recovery/status');
			const foreignResult = foreignStatus.body.result as {
				guardians: Array<{ guardianId: string }>;
				capsules: {
					best: {
						guardians: Array<Record<string, unknown>>;
					} | null;
				};
			};
			expect(foreignResult.guardians.map((g) => g.guardianId)).to.deep.equal(
				GUARDIAN_IDS.map((id) => id.toString('hex'))
			);
			expect(
				foreignResult.capsules.best?.guardians.map((g) => g.guardianId)
			).to.deep.equal(foreignIds);
			for (const reported of foreignResult.capsules.best!.guardians) {
				expect(
					reported,
					'credentials never leave the capsule'
				).to.not.have.property('auth');
			}

			// Device B: same seed, fresh data dir, and NO guardian configuration
			// at all. Booted in peer-storage mode it pushes nothing while empty,
			// and the capsule a storage peer returns names the set to restore
			// with; a restart in quorum mode with that set is then the ordinary
			// restore-from-nothing flow.
			const deviceBProbe = await startDaemon({
				...OFFLINE,
				dataDir: dirB,
				recoveryMode: 'peer-storage'
			});
			let recoveredEntries: Array<{ guardianId: string; url: string }>;
			try {
				const portProbe = portOf(deviceBProbe);
				deviceBProbe.node
					.getNode()
					.emit('peer_storage:retrieved', '02' + 'a1'.repeat(32), capsuleBlob!);
				const probe = await request(portProbe, 'GET', '/recovery/status');
				expect(probe.status).to.equal(200);
				const probeResult = probe.body.result as {
					mode: string;
					guardians: unknown[];
					capsules: {
						candidates: number;
						best: {
							guardians: Array<{
								guardianId: string;
								transports: Array<{ type: string; url: string }>;
							}>;
						} | null;
					};
				};
				expect(probeResult.mode).to.equal('peer-storage');
				expect(probeResult.guardians).to.deep.equal([]);
				expect(probeResult.capsules.candidates).to.equal(1);
				const locators = probeResult.capsules.best!.guardians;
				expect(locators).to.have.length(3);
				// A quorum chain has no escape hatch: the install could never
				// boot unbarriered, so even unfenced is refused (issue #459).
				const hatch = await request(
					portProbe,
					'POST',
					'/recovery/restore-capsule',
					{ confirm: true, unfenced: true }
				);
				expect(hatch.status).to.equal(409);
				expect((hatch.body.error as { code: string }).code).to.equal(
					'CAPSULE_RESTORE_QUORUM_NAMESPACE'
				);
				expect(
					fs.existsSync(path.join(dirB, 'regtest.db.capsule-restore'))
				).to.equal(false);
				const recoveredUris = locators.map(
					(g) => `${g.guardianId}@${g.transports[0].url}`
				);
				expect([...recoveredUris].sort()).to.deep.equal(
					[...guardianUris].sort()
				);
				// The admin handoff returns the same set as structured config
				// entries (no auth key: the daemon URI form carries none).
				const handoff = await request(
					portProbe,
					'POST',
					'/recovery/capsule-guardians',
					{ confirm: true }
				);
				expect(handoff.status, JSON.stringify(handoff.body)).to.equal(200);
				recoveredEntries = (
					handoff.body.result as {
						entries: Array<{ guardianId: string; url: string }>;
					}
				).entries;
				expect(recoveredEntries).to.have.length(3);
				for (const entry of recoveredEntries) {
					expect(entry).to.not.have.property('auth');
				}

				// A capsule from before locators existed names no guardians
				// but can still carry a quorum journal; the quorum refusal
				// does not depend on the locators, hatch or no hatch.
				const legacyBlob = encryptRecoveryCapsule(
					{ ...capsuleA!, guardians: [] },
					NODE_SECRET
				);
				deviceBProbe.node
					.getNode()
					.emit('peer_storage:retrieved', '02' + 'a1'.repeat(32), legacyBlob);
				const legacyStatus = await request(
					portProbe,
					'GET',
					'/recovery/status'
				);
				expect(
					(
						legacyStatus.body.result as {
							capsules: { best: { guardians: unknown[] } };
						}
					).capsules.best.guardians
				).to.deep.equal([]);
				for (const body of [
					{ confirm: true },
					{ confirm: true, unfenced: true }
				]) {
					const legacy = await request(
						portProbe,
						'POST',
						'/recovery/restore-capsule',
						body
					);
					expect(legacy.status, JSON.stringify(body)).to.equal(409);
					expect((legacy.body.error as { code: string }).code).to.equal(
						'CAPSULE_RESTORE_QUORUM_NAMESPACE'
					);
				}
				expect(
					fs.existsSync(path.join(dirB, 'regtest.db.capsule-restore'))
				).to.equal(false);
				expect((await request(portProbe, 'GET', '/info')).status).to.equal(200);
			} finally {
				await deviceBProbe.stop();
			}

			// Device B again, now in quorum mode with the set the capsule
			// named, in the structured form the handoff returned. The boot
			// decision must refuse to register a second genesis and hold for
			// restore.
			const deviceB = await startDaemon({
				...OFFLINE,
				dataDir: dirB,
				recoveryMode: 'quorum',
				recoveryGuardians: recoveredEntries
			});
			const portB = portOf(deviceB);
			try {
				const held = await request(portB, 'GET', '/info');
				expect(held.status).to.equal(503);
				expect((held.body.error as { code: string }).code).to.equal(
					'NODE_RESTORE_PENDING'
				);

				const pending = await request(portB, 'GET', '/recovery/status');
				expect(pending.status).to.equal(200);
				const pendingResult = pending.body.result as {
					state: string;
					node: unknown;
					restore: { inProgress: boolean };
				};
				expect(pendingResult.state).to.equal('restore-required');
				expect(pendingResult.node).to.equal(null);
				expect(pendingResult.restore.inProgress).to.equal(false);

				const progress: string[] = [];
				const restored: Array<Record<string, unknown>> = [];
				deviceB.node.on('recovery:restore-progress', (data) =>
					progress.push((data as { type: string }).type)
				);
				deviceB.node.on('recovery:restored', (data) =>
					restored.push(data as Record<string, unknown>)
				);

				// Two simultaneous restores: exactly one runs, the other is
				// told one is in progress (the in-flight flag is set before
				// the first await, so whichever handler runs second sees it).
				// The winner blocks until the node is up.
				const [first, second] = await Promise.all([
					request(portB, 'POST', '/recovery/restore', { confirm: true }),
					request(portB, 'POST', '/recovery/restore', { confirm: true })
				]);
				const outcomes = [first, second];
				const winner = outcomes.find((r) => r.body.ok === true);
				const loser = outcomes.find((r) => r.body.ok !== true);
				expect(winner, 'one restore must succeed').to.not.equal(undefined);
				expect(loser, 'one restore must be refused').to.not.equal(undefined);
				expect((loser!.body.error as { code: string }).code).to.equal(
					'RESTORE_IN_PROGRESS'
				);
				const report = winner!.body.result as {
					exact: boolean;
					framesApplied: number;
					epoch: string;
				};
				expect(report.framesApplied).to.be.at.least(1);
				expect(report.epoch).to.equal('2');
				expect(progress).to.include('epoch:acquired');
				expect(progress).to.include('restore:complete');
				expect(restored).to.have.length(1);

				// The daemon now serves normally on the restored state.
				const info = await request(portB, 'GET', '/info');
				expect(info.status).to.equal(200);
				const after = await request(portB, 'GET', '/recovery/status');
				const afterResult = after.body.result as {
					state: string;
					node: { durability: string } | null;
				};
				expect(afterResult.state).to.equal('running');
				expect(afterResult.node?.durability).to.equal('quorum');

				// The idle old writer learns it was superseded from the lease
				// check alone: no commit, no restart. Same event and payload
				// as the barrier and startup-gate fences.
				await waitFor(async () => {
					const res = await request(portA, 'GET', '/recovery/status');
					return (res.body.result as { state: string }).state === 'fenced';
				});
				const fencedA = await request(portA, 'GET', '/recovery/status');
				expect(
					(fencedA.body.result as { node: { gate: string } }).node.gate
				).to.equal('fenced');
				expect(fencedOnA).to.have.length(1);
				expect((fencedOnA[0].supersededBy as { epoch: string }).epoch).to.equal(
					'2'
				);
				// The barrier noticing the same takeover on A's next commit must
				// not relay a second recovery:fenced: one fence, one event.
				const late = await request(portA, 'POST', '/invoice/create', {
					amountSats: 5,
					description: 'after the takeover'
				});
				expect(late.status, JSON.stringify(late.body)).to.equal(200);
				await waitFor(async () => {
					const res = await request(portA, 'GET', '/recovery/status');
					return (res.body.result as { node: { fenced: boolean } }).node.fenced;
				});
				expect(fencedOnA).to.have.length(1);

				// A fenced node is not mainnet ready, whatever else passes.
				const fencedReady = await request(portA, 'GET', '/readiness');
				const fencedCheck = readinessCheck(fencedReady.body, 'CHANNEL_BACKUP');
				expect(fencedCheck.status).to.equal('FAIL');
				expect(fencedCheck.severity).to.equal('CRITICAL');
				expect((fencedReady.body.result as { ready: boolean }).ready).to.equal(
					false
				);
			} finally {
				await deviceB.stop();
				await deviceA.stop();
			}
		} finally {
			await shutdown(served);
			fs.rmSync(dirA, { recursive: true, force: true });
			fs.rmSync(dirB, { recursive: true, force: true });
		}
	});
});
