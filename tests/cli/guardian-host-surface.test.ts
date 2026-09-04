/**
 * Node-hosted guardians end to end over the daemon (issue #699 phases B and
 * C): three daemons serve the reference guardian at their Lightning
 * addresses, a fourth resolves their URIs to guardian entries, pins them in
 * quorum mode, registers over bolt8 sessions and journals durably; the
 * hosts report the set. Then the guardian-only lane (D6): a host whose own
 * writer lease is quarantined, because its guardians are down, still
 * answers guardian traffic.
 *
 * Boots offline (unreachable Electrum, the recovery-surface pattern).
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as http from 'http';
import * as net from 'net';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import { IStartedDaemon, startDaemon } from '../../src/cli/daemon';
import { BeignetError } from '../../src/cli/errors';
import {
	GuardianClient,
	bolt8GuardianTransport,
	decodeRecoveryCapsuleBlob,
	CRASH_V1_PROFILE,
	GuardianStatus,
	computeGuardianSetId,
	deriveRecoveryRoot,
	encryptRecoveryCapsule
} from '../../src/lightning/recovery';
import {
	LnCoinType,
	deriveLightningKeysFromMnemonic
} from '../../src/lightning/keys/wallet-keys';

const MNEMONICS = [
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
	'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong',
	'legal winner thank year wave sausage worth useful legal winner thank yellow',
	'letter advice cage absurd amount doctor acoustic avoid letter advice cage above'
];

const OFFLINE = {
	electrumHost: '127.0.0.1',
	electrumPort: 65529,
	electrumTls: false,
	rapidGossipSync: false,
	autoGossipSync: false,
	logLevel: 'silent' as const,
	network: 'regtest' as const,
	daemonPort: 0
};

function tmpDir(tag: string): string {
	return fs.mkdtempSync(
		path.join(os.tmpdir(), `beignet-guardian-host-${tag}-`)
	);
}

function portOf(daemon: IStartedDaemon): number {
	return (daemon.server.address() as AddressInfo).port;
}

async function freePort(): Promise<number> {
	return new Promise((resolve) => {
		const probe = net.createServer();
		probe.listen(0, '127.0.0.1', () => {
			const port = (probe.address() as AddressInfo).port;
			probe.close(() => resolve(port));
		});
	});
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
	timeoutMs = 30_000
): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	for (;;) {
		if (await predicate()) return;
		if (Date.now() > deadline) throw new Error('waitFor timed out');
		await new Promise((resolve) => setTimeout(resolve, 100));
	}
}

interface IHost {
	daemon: IStartedDaemon;
	dir: string;
	listenPort: number;
	uri: string;
}

async function startHost(
	index: number,
	extra: Record<string, unknown> = {}
): Promise<IHost> {
	const dir = tmpDir(`host-${index}`);
	const listenPort = await freePort();
	const daemon = await startDaemon({
		...OFFLINE,
		mnemonic: MNEMONICS[index],
		dataDir: dir,
		listenPort,
		guardianServe: true,
		...extra
	});
	const info = await request(portOf(daemon), 'GET', '/info');
	const nodeId = (info.body.result as { nodeId: string }).nodeId;
	return { daemon, dir, listenPort, uri: `${nodeId}@127.0.0.1:${listenPort}` };
}

async function stopAll(hosts: Array<IHost | null>): Promise<void> {
	for (const host of hosts) {
		if (!host) continue;
		try {
			await host.daemon.stop();
		} catch {
			// Already stopped.
		}
		fs.rmSync(host.dir, { recursive: true, force: true });
	}
}

describe('Guardian host surface: config', () => {
	it('refuses guardianServe without a listen port and validates the limits', async function (): Promise<void> {
		this.timeout(60_000);
		const dir = tmpDir('config');
		const refused = async (
			opts: Record<string, unknown>,
			pattern: RegExp
		): Promise<void> => {
			let error: unknown;
			try {
				const daemon = await startDaemon({
					...OFFLINE,
					mnemonic: MNEMONICS[0],
					dataDir: dir,
					...opts
				});
				await daemon.stop();
			} catch (e) {
				error = e;
			}
			expect(error, 'expected startDaemon to refuse').to.be.instanceOf(
				BeignetError
			);
			expect((error as Error).message).to.match(pattern);
		};
		try {
			await refused({ guardianServe: true }, /needs listenPort/);
			await refused(
				{
					guardianServe: true,
					listenPort: await freePort(),
					guardianMaxSets: 0
				},
				/guardianMaxSets/
			);
			await refused(
				{
					guardianServe: true,
					listenPort: await freePort(),
					guardianMaxCiphertextBytes: 17 * 1024 * 1024
				},
				/guardianMaxCiphertextBytes/
			);
		} finally {
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});
});

describe('Guardian host surface: a wallet guarded by three beignet nodes', () => {
	const hosts: Array<IHost | null> = [];
	let wallet: IStartedDaemon | null = null;
	let walletDir: string | null = null;
	let pinned: string[] = [];
	let restored: IStartedDaemon | null = null;
	let restoredDir: string | null = null;

	after(async function (): Promise<void> {
		this.timeout(60_000);
		if (restored) {
			try {
				await restored.stop();
			} catch {
				// Already stopped.
			}
		}
		if (restoredDir) fs.rmSync(restoredDir, { recursive: true, force: true });
		if (wallet) {
			try {
				await wallet.stop();
			} catch {
				// Already stopped.
			}
		}
		if (walletDir) fs.rmSync(walletDir, { recursive: true, force: true });
		await stopAll(hosts.splice(0));
	});

	it('resolves Lightning URIs to guardian entries, registers over bolt8 and journals durably', async function (): Promise<void> {
		this.timeout(180_000);
		hosts.push(await startHost(0), await startHost(1), await startHost(2));
		const [a, b, c] = hosts as IHost[];

		// Hosting reports itself, with nothing served yet.
		const hostStatus = await request(
			portOf(a.daemon),
			'GET',
			'/guardian/status'
		);
		expect(hostStatus.status).to.equal(200);
		const before = hostStatus.body.result as {
			serving: boolean;
			guardianId: string;
			sets: unknown[];
		};
		expect(before.serving).to.equal(true);
		expect(before.guardianId).to.match(/^[0-9a-f]{64}$/);
		expect(before.sets).to.have.length(0);

		// One host resolves the others' URIs (and its own) to entries.
		const entries: string[] = [];
		for (const host of [a, b, c]) {
			const resolved = await request(
				portOf(a.daemon),
				'POST',
				'/recovery/resolve-guardian',
				{
					uri: host.uri
				}
			);
			expect(resolved.status, JSON.stringify(resolved.body)).to.equal(200);
			const result = resolved.body.result as {
				guardianId: string;
				url: string;
				entry: string;
				guardianSetIds: string[];
			};
			expect(result.url).to.equal(
				`bolt8://${host.uri.split('@')[0]}@127.0.0.1:${host.listenPort}`
			);
			expect(result.entry).to.equal(`${result.guardianId}@${result.url}`);
			expect(result.guardianSetIds).to.have.length(0);
			entries.push(result.entry);
		}
		expect(new Set(entries.map((e) => e.slice(0, 64))).size).to.equal(3);
		// A dead address is reported, not hung on.
		const dead = await request(
			portOf(a.daemon),
			'POST',
			'/recovery/resolve-guardian',
			{
				uri: `${a.uri.split('@')[0]}@127.0.0.1:1`
			}
		);
		expect(dead.status).to.not.equal(200);
		expect(JSON.stringify(dead.body)).to.match(/GUARDIAN_UNREACHABLE/);
		// Garbage is a 400.
		const junk = await request(
			portOf(a.daemon),
			'POST',
			'/recovery/resolve-guardian',
			{
				uri: 'not a uri'
			}
		);
		expect(junk.status).to.equal(400);

		// The wallet pins the three and boots in quorum mode over bolt8.
		walletDir = tmpDir('wallet');
		pinned = entries;
		wallet = await startDaemon({
			...OFFLINE,
			mnemonic: MNEMONICS[3],
			dataDir: walletDir,
			recoveryMode: 'quorum',
			recoveryGuardians: entries,
			recoveryLeaseCheckIntervalMs: 200
		});
		const walletPort = portOf(wallet);
		const status = await request(walletPort, 'GET', '/recovery/status');
		expect(status.status).to.equal(200);
		const surface = status.body.result as {
			mode: string;
			state: string;
			guardians: Array<{ guardianId: string; url: string }>;
			node: { gate: string; lastDurableSequence: string } | null;
		};
		expect(surface.mode).to.equal('quorum');
		expect(surface.state).to.equal('running');
		expect(surface.guardians).to.have.length(3);
		expect(
			surface.guardians.every((g) => g.url.startsWith('bolt8://'))
		).to.equal(true);
		await waitFor(async () => {
			const s = await request(walletPort, 'GET', '/recovery/status');
			return (
				(s.body.result as { node: { gate: string } | null }).node?.gate ===
				'confirmed'
			);
		});

		// A journaled commit goes durable on the quorum over the sessions.
		const durableBefore = BigInt(
			(
				(await request(walletPort, 'GET', '/recovery/status')).body.result as {
					node: { lastDurableSequence: string };
				}
			).node.lastDurableSequence
		);
		const invoice = await request(walletPort, 'POST', '/invoice/create', {
			amountSats: 1000,
			description: 'guarded by three beignet nodes'
		});
		expect(invoice.body.ok, JSON.stringify(invoice.body)).to.equal(true);
		await waitFor(async () => {
			const s = await request(walletPort, 'GET', '/recovery/status');
			const now = BigInt(
				(s.body.result as { node: { lastDurableSequence: string } }).node
					.lastDurableSequence
			);
			return now > durableBefore;
		});

		// Every host now serves the wallet's set, with one namespace in it.
		for (const host of [a, b, c]) {
			const served = await request(
				portOf(host.daemon),
				'GET',
				'/guardian/status'
			);
			const result = served.body.result as {
				sets: Array<{
					setId: string;
					members: string[];
					namespaces: number;
					bytes: number;
				}>;
				sessions: number;
			};
			expect(result.sets).to.have.length(1);
			expect(result.sets[0].namespaces).to.equal(1);
			expect(result.sets[0].members.sort()).to.deep.equal(
				entries.map((e) => e.slice(0, 64)).sort()
			);
			expect(result.sets[0].bytes).to.be.greaterThan(0);
			expect(result.sessions).to.equal(1);
			expect(
				fs.existsSync(path.join(host.dir, 'guardian', 'sets.json'))
			).to.equal(true);
		}
		// The host never saw the wallet as a peer: the session key was fresh.
		const peersOnA = await request(portOf(a.daemon), 'GET', '/peers');
		const walletInfo = await request(walletPort, 'GET', '/info');
		const walletNodeId = (walletInfo.body.result as { nodeId: string }).nodeId;
		const listed =
			(peersOnA.body.result as Array<{ pubkey: string }> | undefined) ?? [];
		expect(listed.some((p) => p.pubkey === walletNodeId)).to.equal(false);
	});
	it('restores the same seed on a fresh device through the node-hosted guardians and fences the old one', async function (): Promise<void> {
		this.timeout(180_000);
		expect(wallet, 'the previous test booted the wallet').to.not.equal(null);
		const walletPort = portOf(wallet!);

		// The capsule the wallet pushes to storage peers names the three hosts
		// as bolt8 locators (spec 5.4): a seed restore with no configuration
		// would read them back from a peer.
		const nodeSecret = deriveLightningKeysFromMnemonic(
			MNEMONICS[3],
			undefined,
			LnCoinType.REGTEST
		).nodePrivateKey;
		const blob = (
			wallet!.node.getNode() as unknown as { ourPeerStorageBlob: Buffer | null }
		).ourPeerStorageBlob;
		expect(blob, 'a guardian-mode node composes a capsule').to.not.equal(null);
		const capsule = decodeRecoveryCapsuleBlob(blob!, nodeSecret);
		expect(capsule).to.not.equal(null);
		expect(capsule!.guardians.map((g) => g.transports[0].type)).to.deep.equal([
			'bolt8',
			'bolt8',
			'bolt8'
		]);
		expect(
			capsule!.guardians
				.map((g) => `${g.guardianId}@${g.transports[0].url}`)
				.sort()
		).to.deep.equal([...pinned].sort());

		// Device B: same seed, empty database, the same three entries. The
		// hosts hold the namespace, so it boots restore-pending.
		restoredDir = tmpDir('restored');
		restored = await startDaemon({
			...OFFLINE,
			mnemonic: MNEMONICS[3],
			dataDir: restoredDir,
			recoveryMode: 'quorum',
			recoveryGuardians: pinned
		});
		const portB = portOf(restored);
		const held = await request(portB, 'GET', '/info');
		expect(held.status).to.equal(503);
		expect((held.body.error as { code: string }).code).to.equal(
			'NODE_RESTORE_PENDING'
		);
		const pending = await request(portB, 'GET', '/recovery/status');
		expect((pending.body.result as { state: string }).state).to.equal(
			'restore-required'
		);

		const fencedOnA: unknown[] = [];
		wallet!.node.on('recovery:fenced', (data) => fencedOnA.push(data));
		const progress: string[] = [];
		restored.node.on('recovery:restore-progress', (data) =>
			progress.push((data as { type: string }).type)
		);

		const outcome = await request(portB, 'POST', '/recovery/restore', {
			confirm: true
		});
		expect(outcome.body.ok, JSON.stringify(outcome.body)).to.equal(true);
		const report = outcome.body.result as {
			framesApplied: number;
			epoch: string;
		};
		expect(report.framesApplied).to.be.at.least(1);
		expect(report.epoch).to.equal('2');
		expect(progress).to.include('epoch:acquired');
		expect(progress).to.include('restore:complete');
		expect((await request(portB, 'GET', '/info')).status).to.equal(200);
		await waitFor(async () => {
			const s = await request(portB, 'GET', '/recovery/status');
			return (
				(s.body.result as { node: { gate: string } | null }).node?.gate ===
				'confirmed'
			);
		});

		// The takeover fenced the old device through the same hosts.
		await waitFor(async () => {
			const s = await request(walletPort, 'GET', '/recovery/status');
			const result = s.body.result as {
				state: string;
				node: { fenced: boolean } | null;
			};
			return (
				result.state === 'fenced' ||
				result.node?.fenced === true ||
				fencedOnA.length > 0
			);
		}, 60_000);

		// Every host now holds the takeover: the set is still one set, with
		// one namespace, at epoch 2.
		for (const host of hosts as IHost[]) {
			const served = await request(
				portOf(host.daemon),
				'GET',
				'/guardian/status'
			);
			const result = served.body.result as {
				sets: Array<{ namespaces: number }>;
			};
			expect(result.sets).to.have.length(1);
			expect(result.sets[0].namespaces).to.equal(1);
		}
	});
});

describe('Guardian host surface: the guardian-only lane', () => {
	const hosts: Array<IHost | null> = [];

	after(async function (): Promise<void> {
		this.timeout(60_000);
		await stopAll(hosts.splice(0));
	});

	it('keeps serving guardian traffic while its own writer lease is quarantined', async function (): Promise<void> {
		this.timeout(240_000);
		// B and C guard A (with a third guardian that never answers). A holds
		// its lease with two of three, so it confirms; then B and C go away,
		// A restarts quarantined, and must still answer INFO over the lane.
		const b = await startHost(1);
		const c = await startHost(2);
		hosts.push(b, c);
		const resolve = async (uri: string): Promise<string> => {
			const resolved = await request(
				portOf(b.daemon),
				'POST',
				'/recovery/resolve-guardian',
				{ uri }
			);
			expect(resolved.status, JSON.stringify(resolved.body)).to.equal(200);
			return (resolved.body.result as { entry: string }).entry;
		};
		const entryB = await resolve(b.uri);
		const entryC = await resolve(c.uri);
		// A never-answering third member: a valid x-only key at a dead port.
		const deadMember =
			'79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
		const entryDead = `${deadMember}@bolt8://${
			b.uri.split('@')[0]
		}@127.0.0.1:1`;

		const dirA = tmpDir('host-a');
		const listenA = await freePort();
		let a = await startDaemon({
			...OFFLINE,
			mnemonic: MNEMONICS[0],
			dataDir: dirA,
			listenPort: listenA,
			guardianServe: true,
			recoveryMode: 'quorum',
			recoveryGuardians: [entryB, entryC, entryDead],
			recoveryLeaseCheckIntervalMs: 200
		});
		const nodeIdA = (
			(await request(portOf(a), 'GET', '/info')).body.result as {
				nodeId: string;
			}
		).nodeId;
		await waitFor(async () => {
			const s = await request(portOf(a), 'GET', '/recovery/status');
			return (
				(s.body.result as { node: { gate: string } | null }).node?.gate ===
				'confirmed'
			);
		});

		// Stop everything, then bring A back alone: its persisted lease boots
		// the node quarantined, because no quorum can confirm it.
		await a.stop();
		await b.daemon.stop();
		await c.daemon.stop();
		a = await startDaemon({
			...OFFLINE,
			mnemonic: MNEMONICS[0],
			dataDir: dirA,
			listenPort: listenA,
			guardianServe: true,
			recoveryMode: 'quorum',
			recoveryGuardians: [entryB, entryC, entryDead],
			recoveryLeaseCheckIntervalMs: 200
		});
		try {
			const quarantined = await request(portOf(a), 'GET', '/recovery/status');
			const view = quarantined.body.result as {
				state: string;
				node: { gate: string } | null;
			};
			expect(view.state).to.equal('running');
			expect(view.node?.gate).to.equal('quarantined');

			// The lane: a stranger's guardian session gets INFO answered.
			const transport = bolt8GuardianTransport();
			try {
				const client = new GuardianClient({
					url: `bolt8://${nodeIdA}@127.0.0.1:${listenA}`,
					guardianSetId: Buffer.alloc(32),
					transport,
					timeoutMs: 10_000
				});
				const info = await client.info();
				expect(info.guardianId.toString('hex')).to.match(/^[0-9a-f]{64}$/);
				const hostView = (await request(portOf(a), 'GET', '/guardian/status'))
					.body.result as {
					serving: boolean;
					sessions: number;
				};
				expect(hostView.serving).to.equal(true);
				expect(hostView.sessions).to.equal(1);
			} finally {
				transport.close();
			}
			// Still quarantined: the lane changed nothing about A's own lease.
			const still = await request(portOf(a), 'GET', '/recovery/status');
			expect(
				(still.body.result as { node: { gate: string } }).node.gate
			).to.equal('quarantined');
		} finally {
			await a.stop();
			fs.rmSync(dirA, { recursive: true, force: true });
		}
	});
});

describe('Guardian rotation surface: a wallet moves to a new set with the channels running', () => {
	const hosts: Array<IHost | null> = [];
	let wallet: IStartedDaemon | null = null;
	let walletDir: string | null = null;
	let restored: IStartedDaemon | null = null;
	let restoredDir: string | null = null;

	after(async function (): Promise<void> {
		this.timeout(60_000);
		for (const daemon of [restored, wallet]) {
			if (!daemon) continue;
			try {
				await daemon.stop();
			} catch {
				// Already stopped.
			}
		}
		for (const dir of [restoredDir, walletDir]) {
			if (dir) fs.rmSync(dir, { recursive: true, force: true });
		}
		await stopAll(hosts.splice(0));
	});

	it('rotates one member, keeps journaling, retires the old set, and a restore with the old entries follows the rotation', async function (): Promise<void> {
		this.timeout(240_000);
		hosts.push(
			await startHost(0),
			await startHost(1),
			await startHost(2),
			await startHost(3)
		);
		const [a, b, c, d] = hosts as IHost[];
		const resolve = async (uri: string): Promise<string> => {
			const r = await request(
				portOf(a.daemon),
				'POST',
				'/recovery/resolve-guardian',
				{ uri }
			);
			expect(r.status, JSON.stringify(r.body)).to.equal(200);
			return (r.body.result as { entry: string }).entry;
		};
		const entryA = await resolve(a.uri);
		const entryB = await resolve(b.uri);
		const entryC = await resolve(c.uri);
		const entryD = await resolve(d.uri);
		const oldEntries = [entryA, entryB, entryC];
		const newEntries = [entryB, entryC, entryD];

		walletDir = tmpDir('rotating-wallet');
		wallet = await startDaemon({
			...OFFLINE,
			mnemonic: MNEMONICS[3],
			dataDir: walletDir,
			recoveryMode: 'quorum',
			recoveryGuardians: oldEntries,
			recoveryLeaseCheckIntervalMs: 200
		});
		const walletPort = portOf(wallet);
		const status = async (port: number): Promise<Record<string, unknown>> =>
			(await request(port, 'GET', '/recovery/status')).body.result as Record<
				string,
				unknown
			>;
		await waitFor(
			async () =>
				(await status(walletPort)).node !== null &&
				((await status(walletPort)).node as { gate: string }).gate ===
					'confirmed'
		);
		const before = await status(walletPort);
		expect(before.generation).to.equal('1');
		expect(before.configuredSetStale).to.equal(false);
		const invoice1 = await request(walletPort, 'POST', '/invoice/create', {
			amountSats: 1000,
			description: 'before rotation'
		});
		expect(invoice1.body.ok).to.equal(true);
		await waitFor(
			async () =>
				BigInt(
					((await status(walletPort)).node as { lastDurableSequence: string })
						.lastDurableSequence
				) >= 1n
		);
		const durableBefore = BigInt(
			((await status(walletPort)).node as { lastDurableSequence: string })
				.lastDurableSequence
		);

		// Refusals first: no confirm, wrong count, the same set.
		const unconfirmed = await request(
			walletPort,
			'POST',
			'/recovery/rotate-guardians',
			{ guardians: newEntries }
		);
		expect(unconfirmed.status).to.equal(400);
		const sameSet = await request(
			walletPort,
			'POST',
			'/recovery/rotate-guardians',
			{ guardians: oldEntries, confirm: true }
		);
		expect(sameSet.status, JSON.stringify(sameSet.body)).to.equal(400);

		// The rotation: A out, D in.
		const progress: string[] = [];
		wallet.node.on('recovery:rotation-progress', (data) =>
			progress.push((data as { type: string }).type)
		);
		const rotatedEvents: unknown[] = [];
		wallet.node.on('recovery:rotated', (data) => rotatedEvents.push(data));
		const rotated = await request(
			walletPort,
			'POST',
			'/recovery/rotate-guardians',
			{ guardians: newEntries, confirm: true }
		);
		expect(rotated.status, JSON.stringify(rotated.body)).to.equal(200);
		const result = rotated.body.result as {
			generation: string;
			guardians: Array<{ guardianId: string }>;
			retired: number;
		};
		expect(result.generation).to.equal('2');
		expect(result.guardians.map((g) => g.guardianId).sort()).to.deep.equal(
			newEntries.map((e) => e.slice(0, 64)).sort()
		);
		expect(result.retired).to.be.greaterThan(0);
		expect(progress).to.include('rotation:registered');
		expect(progress).to.include('rotation:switched');
		expect(progress).to.include('rotation:retired');
		expect(rotatedEvents).to.have.length(1);

		const after = await status(walletPort);
		expect(after.generation).to.equal('2');
		expect(after.configuredSetStale).to.equal(true);
		expect(
			(after.guardians as Array<{ guardianId: string }>)
				.map((g) => g.guardianId)
				.sort()
		).to.deep.equal(newEntries.map((e) => e.slice(0, 64)).sort());
		expect(
			(
				after.rotation as {
					inProgress: boolean;
					pending: boolean;
					retirePending: boolean;
				}
			).inProgress
		).to.equal(false);
		expect((after.rotation as { pending: boolean }).pending).to.equal(false);
		expect(
			(after.rotation as { retirePending: boolean }).retirePending
		).to.equal(false);
		expect((after.node as { gate: string }).gate).to.equal('confirmed');

		// Journaling continues on the new set: a commit goes durable there.
		const invoice2 = await request(walletPort, 'POST', '/invoice/create', {
			amountSats: 2000,
			description: 'after rotation'
		});
		expect(invoice2.body.ok).to.equal(true);
		await waitFor(
			async () =>
				BigInt(
					((await status(walletPort)).node as { lastDurableSequence: string })
						.lastDurableSequence
				) > durableBefore
		);

		// D serves the set now; A's namespace is retired with the rotation attached.
		const dView = (await request(portOf(d.daemon), 'GET', '/guardian/status'))
			.body.result as { sets: Array<{ namespaces: number }> };
		expect(dView.sets).to.have.length(1);
		expect(dView.sets[0].namespaces).to.equal(1);
		const oldIds = oldEntries.map((e) => Buffer.from(e.slice(0, 64), 'hex'));
		const oldSetId = computeGuardianSetId({
			...CRASH_V1_PROFILE,
			guardianIds: oldIds
		});
		const probe = bolt8GuardianTransport();
		try {
			const client = new GuardianClient({
				url: entryA.slice(65),
				guardianSetId: oldSetId,
				transport: probe,
				timeoutMs: 10_000
			});
			const recoveryId = deriveRecoveryRoot(
				deriveLightningKeysFromMnemonic(
					MNEMONICS[3],
					undefined,
					LnCoinType.REGTEST
				).nodePrivateKey
			).recoveryId;
			const head = await client.getHead(recoveryId);
			expect(head.status).to.equal(GuardianStatus.OK);
			expect(head.rotation, 'A holds the rotation').to.not.equal(undefined);
			expect(head.rotation!.generation).to.equal(2n);
		} finally {
			probe.close();
		}

		// A fresh device with the OLD entries follows the rotation to the live set and restores there.
		restoredDir = tmpDir('rotated-restore');
		restored = await startDaemon({
			...OFFLINE,
			mnemonic: MNEMONICS[3],
			dataDir: restoredDir,
			recoveryMode: 'quorum',
			recoveryGuardians: oldEntries
		});
		const restoredPort = portOf(restored);
		const pending = await status(restoredPort);
		expect(pending.state).to.equal('restore-required');
		expect(
			(pending.rotation as { followed: { generation: string } | null }).followed
				?.generation
		).to.equal('2');
		expect(
			(pending.guardians as Array<{ guardianId: string }>)
				.map((g) => g.guardianId)
				.sort()
		).to.deep.equal(newEntries.map((e) => e.slice(0, 64)).sort());
		const outcome = await request(restoredPort, 'POST', '/recovery/restore', {
			confirm: true
		});
		expect(outcome.body.ok, JSON.stringify(outcome.body)).to.equal(true);
		expect((outcome.body.result as { epoch: string }).epoch).to.equal('2');
		await waitFor(
			async () =>
				((await status(restoredPort)).node as { gate: string } | null)?.gate ===
				'confirmed'
		);
		expect((await status(restoredPort)).generation).to.equal('2');

		// The rotated wallet is the old device now: the takeover fences it.
		await waitFor(async () => {
			const s = await status(walletPort);
			return (
				s.state === 'fenced' ||
				(s.node as { fenced: boolean } | null)?.fenced === true
			);
		}, 60_000);

		// And a capsule from a LATER generation fences the restored device too
		// (wire 5.9): another device rotated the namespace away from it.
		const nodeSecret = deriveLightningKeysFromMnemonic(
			MNEMONICS[3],
			undefined,
			LnCoinType.REGTEST
		).nodePrivateKey;
		const blob = (
			restored.node.getNode() as unknown as {
				ourPeerStorageBlob: Buffer | null;
			}
		).ourPeerStorageBlob;
		expect(blob).to.not.equal(null);
		const capsule = decodeRecoveryCapsuleBlob(blob!, nodeSecret);
		expect(capsule!.generation).to.equal(2n);
		const later = encryptRecoveryCapsule(
			{ ...capsule!, generation: 3n },
			nodeSecret
		);
		restored.node
			.getNode()
			.emit('peer_storage:retrieved', '02' + 'a1'.repeat(32), later);
		await waitFor(async () => {
			const s = await status(restoredPort);
			return (
				s.state === 'fenced' ||
				(s.node as { fenced: boolean } | null)?.fenced === true
			);
		});
	});
});
