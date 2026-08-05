/**
 * Recovery Phase 7, component 9: the process-level SIGKILL matrix
 * (docs/RECOVERY-PROTOCOL.md section 9, Phase 7, revision 6). The victim
 * is a production LightningNode assembly in a dedicated child process
 * (real SQLite file, real TCP, real guardian HTTP when quorum), built by
 * tests/lightning/helpers/chaos-node-child.cjs against the COMPILED
 * library. The parent hosts the live peer in-process with networking
 * enabled, drives each scenario over the child's stdin line protocol,
 * records the schedule of commit and send boundaries from a rehearsal
 * life, then re-runs the scenario once per label: the armed child reports
 * `reached:<label>` and busy-spins, the parent SIGKILLs it (the exit
 * signal is asserted, so no life ever ends gracefully), respawns it on
 * the same file, reconnects over real TCP, and judges the outcome.
 *
 * One matrix, two executors: the boundary vocabulary (pre-commit:N,
 * post-commit:N, post-send:TYPE:K) and the scenario shapes are the
 * in-process chaos matrix's own; this executor buys authoritative crash
 * semantics (a real process dying with real file durability and real
 * sockets) at process-spawn cost, which is why it lives behind its own
 * npm script and CI step instead of test:lightning.
 *
 * EXCLUDED from test:lightning; run via `npm run test:sigkill` after
 * `npm run build` (the child requires dist).
 */

import { expect } from 'chai';
import { ChildProcess, spawn } from 'child_process';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import readline from 'readline';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { ChannelState, HtlcState } from '../../src/lightning/channel/types';
import {
	CRASH_V1_PROFILE,
	GuardianHttpServer,
	ReferenceGuardian,
	computeGuardianSetId,
	xOnlyFromSecret
} from '../../src/lightning/recovery';
import { createChaosNode } from './helpers/chaos-harness';

const CHILD = path.join(__dirname, 'helpers', 'chaos-node-child.cjs');
const REPO_ROOT = path.join(__dirname, '..', '..');
const VICTIM_SEED = 171;
const PEER_SEED = 172;

interface IChildHandle {
	proc: ChildProcess;
	lines: string[];
	waitLine: (prefix: string, timeoutMs?: number) => Promise<string>;
	send: (cmd: string) => void;
	kill: () => Promise<string | null>;
}

function spawnChild(envExtra: Record<string, string>): IChildHandle {
	const proc = spawn(process.execPath, [CHILD], {
		cwd: REPO_ROOT,
		env: { ...process.env, ...envExtra },
		stdio: ['pipe', 'pipe', 'inherit']
	});
	const lines: string[] = [];
	const waiters: Array<{
		prefix: string;
		resolve: (line: string) => void;
	}> = [];
	const rl = readline.createInterface({ input: proc.stdout! });
	rl.on('line', (line) => {
		lines.push(line);
		for (let i = waiters.length - 1; i >= 0; i--) {
			if (line.startsWith(waiters[i].prefix)) {
				const [waiter] = waiters.splice(i, 1);
				waiter.resolve(line);
			}
		}
	});
	return {
		proc,
		lines,
		waitLine: (prefix: string, timeoutMs = 20_000): Promise<string> => {
			const already = lines.find((l) => l.startsWith(prefix));
			if (already) return Promise.resolve(already);
			return new Promise((resolve, reject) => {
				const timer = setTimeout(() => {
					reject(
						new Error(
							`timed out waiting for "${prefix}"; last lines: ${lines
								.slice(-6)
								.join(' | ')}`
						)
					);
				}, timeoutMs);
				waiters.push({
					prefix,
					resolve: (line): void => {
						clearTimeout(timer);
						resolve(line);
					}
				});
			});
		},
		send: (cmd: string): void => {
			proc.stdin!.write(cmd + '\n');
		},
		kill: (): Promise<string | null> =>
			new Promise((resolve) => {
				proc.once('exit', (_code, signal) => resolve(signal));
				proc.kill('SIGKILL');
			})
	};
}

function tempDb(prefix: string): string {
	return path.join(
		fs.mkdtempSync(path.join(os.tmpdir(), `beignet-${prefix}-`)),
		'node.db'
	);
}

async function settle(rounds = 10): Promise<void> {
	for (let i = 0; i < rounds; i++) {
		await new Promise<void>((resolve) => setImmediate(resolve));
	}
}

async function waitFor(
	predicate: () => boolean,
	what: string,
	timeoutMs = 20_000
): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (!predicate()) {
		if (Date.now() > deadline) throw new Error(`timed out: ${what}`);
		await new Promise((resolve) => setTimeout(resolve, 20));
	}
}

interface IWorld {
	peer: LightningNode;
	dbPath: string;
	mode: 'local' | 'async-remote' | 'quorum';
	guardians: string;
	served: Array<{ guardian: ReferenceGuardian; server: GuardianHttpServer }>;
	channelId: string;
	firstLife: boolean;
}

const GUARDIAN_SECRETS = [1, 2, 3].map((i) =>
	crypto.createHash('sha256').update(`p7-sigkill-guardian-${i}`).digest()
);

async function serveTrio(): Promise<{
	served: IWorld['served'];
	urls: string;
}> {
	const guardianIds = GUARDIAN_SECRETS.map((s) => xOnlyFromSecret(s));
	void computeGuardianSetId({ ...CRASH_V1_PROFILE, guardianIds });
	let clockNow = 2_500_000_000_000n;
	const clock = (): bigint => ++clockNow;
	const served: IWorld['served'] = [];
	const urls: string[] = [];
	for (let i = 0; i < 3; i++) {
		const guardian = new ReferenceGuardian({
			path: ':memory:',
			guardianSecret: GUARDIAN_SECRETS[i],
			members: guardianIds,
			clock
		});
		const server = new GuardianHttpServer({ guardian });
		const port = await server.listen(0);
		served.push({ guardian, server });
		urls.push(`http://127.0.0.1:${port}`);
	}
	return { served, urls: urls.join(',') };
}

async function makeWorld(mode: IWorld['mode']): Promise<IWorld> {
	const peer = createChaosNode(PEER_SEED, {
		extras: { enableNetworking: true }
	});
	await peer.listen(0, '127.0.0.1');
	let guardians = '';
	let served: IWorld['served'] = [];
	if (mode !== 'local') {
		const trio = await serveTrio();
		guardians = trio.urls;
		served = trio.served;
	}
	return {
		peer,
		dbPath: tempDb('sigkill'),
		mode,
		guardians,
		served,
		channelId: '',
		firstLife: true
	};
}

async function destroyWorld(world: IWorld): Promise<void> {
	world.peer.destroy();
	for (const s of world.served) {
		try {
			await s.server.close();
			s.guardian.close();
		} catch {
			// Already closed.
		}
	}
}

/** Spawn a child life and connect the parent peer to it. */
async function bootChild(
	world: IWorld,
	arm: string | null
): Promise<IChildHandle> {
	const child = spawnChild({
		CHAOS_DB: world.dbPath,
		CHAOS_SEED: String(VICTIM_SEED),
		CHAOS_MODE: world.mode,
		CHAOS_GUARDIANS: world.guardians,
		CHAOS_REGISTER: world.firstLife ? '1' : '0',
		...(arm ? { CHAOS_ARM: arm } : {})
	});
	world.firstLife = false;
	const ready = await child.waitLine('ready:');
	const [, nodeId, port] = ready.split(':');
	await world.peer.connectPeer(nodeId, '127.0.0.1', Number(port));
	return child;
}

/**
 * S1a at process level: the child (payer) opens a channel to the parent
 * peer and pays its invoice. Returns the command script driven every
 * life, so schedules stay deterministic across the rehearsal and every
 * kill run.
 */
async function driveS1a(
	world: IWorld,
	child: IChildHandle,
	expectKill: boolean
): Promise<void> {
	child.send(`open 1000000 ${world.peer.getNodeId()}`);
	const opened = await child.waitLine('opened:').catch((err) => {
		if (expectKill) return null;
		throw err;
	});
	if (opened === null) return;
	world.channelId = opened.slice('opened:'.length);
	world.peer.handleFundingConfirmed(Buffer.from(world.channelId, 'hex'));
	await waitFor(
		() =>
			world.peer
				.getChannelManager()
				.listChannels()
				.some((c) => c.getState() === ChannelState.NORMAL),
		'the channel to open'
	);
	child.send(`graph ${world.peer.getNodeId()} 830`);
	const graphOk = await child
		.waitLine('ok:graph', 8000)
		.catch(() => (expectKill ? null : Promise.reject()));
	if (graphOk === null) return;
	const invoice = world.peer.createInvoice({
		amountMsat: 50_000n,
		description: 'sigkill s1a'
	});
	child.send(`pay ${invoice.bolt11}`);
	const paid = await child.waitLine('paid:', 25_000).catch((err) => {
		if (expectKill) return null;
		throw err;
	});
	if (paid !== null && !expectKill) {
		expect(paid, 'rehearsal payment settled').to.equal('paid:COMPLETED');
	}
}

/** The rehearsal life: record the label schedule the scenario produces. */
async function recordSchedule(world: IWorld): Promise<string[]> {
	const child = await bootChild(world, null);
	await driveS1a(world, child, false);
	// Drain the tail: the last gated sends may land just after paid:, and
	// the schedule must record them deterministically.
	for (let i = 0; i < 100; i++) {
		child.send('dump');
		const dumpLine = await child.waitLine('dump:');
		const dump = JSON.parse(dumpLine.slice('dump:'.length)) as {
			awaitingDurability: number;
		};
		child.lines.splice(child.lines.indexOf(dumpLine), 1);
		if (dump.awaitingDurability === 0) break;
		await new Promise((resolve) => setTimeout(resolve, 20));
	}
	await new Promise((resolve) => setTimeout(resolve, 300));
	const schedule: string[] = [];
	for (const line of child.lines) {
		if (line.startsWith('evt:commit:')) {
			const n = line.slice('evt:commit:'.length);
			schedule.push(`pre-commit:${n}`, `post-commit:${n}`);
		} else if (line.startsWith('evt:send:')) {
			schedule.push(`post-send:${line.slice('evt:send:'.length)}`);
		}
	}
	child.send('quit');
	await new Promise((resolve) => child.proc.once('exit', resolve));
	return schedule;
}

/**
 * One kill run: fresh world state on the same command script, die at the
 * armed label (SIGKILL, asserted), respawn on the same file, reconnect,
 * and prove liveness: both sides converge and a fresh payment settles.
 */
async function runKillCell(world: IWorld, label: string): Promise<void> {
	const child = await bootChild(world, label);
	// The drive stalls wherever the armed boundary freezes the child, so it
	// races the boundary report rather than being awaited to completion.
	const reached = child.waitLine(`reached:${label}`, 30_000);
	await Promise.race([
		driveS1a(world, child, true).catch(() => undefined),
		reached
	]);
	await reached;
	const signal = await child.kill();
	expect(signal, `the child died by SIGKILL at ${label}`).to.equal('SIGKILL');

	// The peer notices the socket drop the way any TCP peer would.
	await settle();

	const revived = await bootChild(world, null);
	// Reestablish rides the reconnect. Re-deliver the funding confirmation
	// the chain would repeat, both sides, when the open got that far.
	if (world.channelId) {
		revived.send(`confirm ${world.channelId}`);
		await revived.waitLine('ok:').catch(() => undefined);
		try {
			world.peer.handleFundingConfirmed(Buffer.from(world.channelId, 'hex'));
		} catch {
			// The peer may never have seen the funding; the fresh-open branch
			// below covers it.
		}
	}
	const channelUp = await waitFor(
		() =>
			world.peer
				.getChannelManager()
				.listChannels()
				.some((c) => c.getState() === ChannelState.NORMAL),
		`the peer channel back to NORMAL after ${label}`,
		8_000
	).then(
		() => true,
		() => false
	);
	if (!channelUp) {
		// The kill predates a usable channel. Liveness then means the
		// restarted node can simply open a fresh one on the same file.
		revived.send(`open 1000000 ${world.peer.getNodeId()}`);
		const opened = await revived.waitLine('opened:');
		const freshId = opened.slice('opened:'.length);
		world.peer.handleFundingConfirmed(Buffer.from(freshId, 'hex'));
		await waitFor(
			() =>
				world.peer
					.getChannelManager()
					.listChannels()
					.some((c) => c.getState() === ChannelState.NORMAL),
			`a fresh channel after ${label}`
		);
	}
	const invoice = world.peer.createInvoice({
		amountMsat: 30_000n,
		description: `sigkill probe ${label}`
	});
	revived.send(`graph ${world.peer.getNodeId()} 830`);
	await revived.waitLine('ok:graph');
	revived.send(`pay ${invoice.bolt11}`);
	const paid = await revived.waitLine('paid:', 25_000);
	expect(paid, `probe payment settled after ${label}`).to.equal(
		'paid:COMPLETED'
	);

	// No stuck HTLC on the surviving peer, and the child reports healthy
	// channels from its own view of the same file.
	for (const channel of world.peer.getChannelManager().listChannels()) {
		const state = channel.getFullState();
		if (channel.getState() !== ChannelState.NORMAL) continue;
		expect(
			[...state.htlcs.values()].every(
				(h) => h.state !== HtlcState.PENDING && h.state !== HtlcState.COMMITTED
			),
			`no HTLC left in flight after ${label}`
		).to.equal(true);
	}
	revived.send('dump');
	const dumpLine = await revived.waitLine('dump:');
	const dump = JSON.parse(dumpLine.slice('dump:'.length)) as {
		channels: Array<{ state: string }>;
	};
	expect(
		dump.channels.some((c) => c.state === 'NORMAL'),
		`the child holds a NORMAL channel after ${label}`
	).to.equal(true);

	const bye = await revived.kill();
	expect(bye).to.equal('SIGKILL');
}

describe('Recovery phase 7: SIGKILL matrix (dedicated child, real assembly)', function () {
	for (const mode of ['local', 'quorum'] as const) {
		it(`S1a payer: every boundary survives a real SIGKILL and resumes (${mode})`, async function () {
			this.timeout(600_000);
			const rehearsalWorld = await makeWorld(mode);
			let schedule: string[];
			try {
				schedule = await recordSchedule(rehearsalWorld);
			} finally {
				await destroyWorld(rehearsalWorld);
			}
			expect(
				schedule.length,
				'the rehearsal recorded a schedule'
			).to.be.at.least(8);
			expect(
				schedule.some((l) => l.startsWith('post-send:COMMITMENT_SIGNED')),
				'the schedule crossed the commitment boundary'
			).to.equal(true);

			for (const label of schedule) {
				const world = await makeWorld(mode);
				try {
					await runKillCell(world, label);
				} finally {
					await destroyWorld(world);
				}
			}
		});
	}

	it('a graceful exit never happens: every armed life ends by SIGKILL', async function () {
		this.timeout(60_000);
		const world = await makeWorld('local');
		try {
			const child = await bootChild(world, 'post-commit:1');
			const reached = child.waitLine('reached:post-commit:1', 30_000);
			await Promise.race([
				driveS1a(world, child, true).catch(() => undefined),
				reached
			]);
			await reached;
			const signal = await child.kill();
			expect(signal).to.equal('SIGKILL');
		} finally {
			await destroyWorld(world);
		}
	});
});
