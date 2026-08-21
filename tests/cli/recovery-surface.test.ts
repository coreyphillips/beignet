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
import { BeignetError } from '../../src/cli/errors';
import {
	GuardianHttpServer,
	ReferenceGuardian,
	xOnlyFromSecret
} from '../../src/lightning/recovery';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const sha = (s: string): Buffer =>
	crypto.createHash('sha256').update(s).digest();

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
	body?: Record<string, unknown>
): Promise<{ status: number; body: Record<string, unknown> }> {
	return new Promise((resolve, reject) => {
		const payload = body ? JSON.stringify(body) : undefined;
		const headers: Record<string, string | number> = {};
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

	it('POST /recovery/restore without confirm is refused', async () => {
		const res = await request(portOf(daemon), 'POST', '/recovery/restore', {});
		expect(res.status).to.equal(400);
		expect((res.body.error as { code: string }).code).to.equal(
			'INVALID_PARAMS'
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
		} finally {
			await daemon.stop();
			fs.rmSync(dir, { recursive: true, force: true });
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
			const deviceA = await startDaemon({
				...OFFLINE,
				dataDir: dirA,
				recoveryMode: 'quorum',
				recoveryGuardians: guardianUris
			});
			const portA = portOf(deviceA);
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
			await deviceA.stop();

			// Device B: same seed, fresh database. The boot decision must
			// refuse to register a second genesis and hold for restore.
			const deviceB = await startDaemon({
				...OFFLINE,
				dataDir: dirB,
				recoveryMode: 'quorum',
				recoveryGuardians: guardianUris
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
			} finally {
				await deviceB.stop();
			}
		} finally {
			await shutdown(served);
			fs.rmSync(dirA, { recursive: true, force: true });
			fs.rmSync(dirB, { recursive: true, force: true });
		}
	});
});
