/**
 * `beignet channel forceclose <id> --offline` (issue #2024): the node options
 * it boots with, the close sequence, and what reaches Electrum.
 *
 * The sequence runs against a fake node on a fake clock. The Electrum cases
 * boot a real node on the mapped options against a local TCP stand-in that
 * records the first bytes of each connection and hangs up: a TLS ClientHello
 * starts with 0x16, a plaintext Electrum request with '{'.
 */

import { expect } from 'chai';
import { spawn } from 'child_process';
import * as fs from 'fs';
import * as net from 'net';
import * as os from 'os';
import * as path from 'path';
import { BeignetNode } from '../../src/cli/beignet-node';
import {
	acquireInstanceLock,
	releaseInstanceLock
} from '../../src/cli/instance-lock';
import { noopLogger } from '../../src/logger';
import { assertDistCliFresh, DIST_CLI } from './helpers/dist-cli';
import {
	IOfflineForceCloseNode,
	IOfflineForceCloseOptions,
	offlineForceCloseOptions,
	runOfflineForceClose
} from '../../src/cli/offline-force-close';
import type { BeignetConfig, ChannelInfo } from '../../src/cli/types';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const CHANNEL = 'cd'.repeat(32);
const TXID = 'ef'.repeat(32);

describe('offlineForceCloseOptions', () => {
	const config: BeignetConfig = {
		mnemonic: MNEMONIC,
		network: 'signet',
		dataDir: '/tmp/wallet',
		electrumHost: 'electrum.example',
		electrumPort: 50002,
		electrumTls: true,
		electrumTlsVerify: true,
		electrumTlsFingerprints: ['AB'.repeat(32)],
		electrumServers: [{ host: 'backup.example', port: 50002, tls: true }],
		feeEstimationSource: 'electrum',
		listenPort: 9735,
		websocketPort: 9736,
		iroh: true,
		porchRelays: ['wss://relay.example'],
		guardianServe: true,
		autoBootstrap: true,
		autoReconnect: true,
		backupPath: '/tmp/backups',
		watchtowers: ['02' + 'aa'.repeat(32) + '@tower.example:9911'],
		recoveryMode: 'off',
		logLevel: 'debug'
	};
	const opts = offlineForceCloseOptions(config, noopLogger);

	it('opens the configured wallet on the configured network', () => {
		expect(opts.mnemonic).to.equal(MNEMONIC);
		expect(opts.network).to.equal('signet');
		expect(opts.dataDir).to.equal('/tmp/wallet');
	});

	it('dials Electrum with the configured server and TLS settings', () => {
		expect(opts.electrumHost).to.equal('electrum.example');
		expect(opts.electrumPort).to.equal(50002);
		expect(opts.electrumTls).to.equal(true);
		expect(opts.electrumTlsVerify).to.equal(true);
		expect(opts.electrumTlsFingerprints).to.deep.equal(['AB'.repeat(32)]);
		expect(opts.electrumServers).to.deep.equal(config.electrumServers);
		expect(opts.feeEstimationSource).to.equal('electrum');
	});

	it('leaves TLS to the network default when the config does not set it', () => {
		const bare = offlineForceCloseOptions(
			{ mnemonic: MNEMONIC, network: 'mainnet' },
			noopLogger
		);
		expect(bare).to.have.property('electrumTls', undefined);
	});

	it('opens no listener and reaches no peer', () => {
		expect(opts.listenPort).to.equal(undefined);
		expect(opts.websocketPort).to.equal(undefined);
		expect(opts.iroh).to.equal(undefined);
		expect(opts.porchRelays).to.equal(undefined);
		expect(opts.guardianServe).to.equal(undefined);
		expect(opts.watchtowers).to.equal(undefined);
		expect(opts.backupPath).to.equal(undefined);
		expect(opts.autoReconnect).to.equal(false);
		expect(opts.autoBootstrap).to.equal(false);
		expect(opts.autoGossipSync).to.equal(false);
		expect(opts.rapidGossipSync).to.equal(false);
	});

	it('logs through the logger it is given, never the console', () => {
		expect(opts.logger).to.equal(noopLogger);
	});
});

interface IFake extends IOfflineForceCloseNode {
	closes: boolean[];
	rebroadcasts: number;
}

/**
 * A node on the fake clock. `connectAt` and `broadcastAt` are the times the
 * Electrum connection and the close broadcast land; `rebroadcastOk` is what a
 * manual rebroadcast reports.
 */
function fakeNode(
	clock: { t: number },
	setup: {
		state?: ChannelInfo['state'];
		closer?: 'local' | 'remote';
		connectAt?: number;
		broadcastAt?: number;
		rebroadcastOk?: boolean;
		refuse?: string;
		missing?: boolean;
	} = {}
): IFake {
	let state = setup.state ?? 'AWAITING_REESTABLISH';
	let closedAt: number | undefined =
		state === 'FORCE_CLOSED' ? clock.t : undefined;
	const fake: IFake = {
		closes: [],
		rebroadcasts: 0,
		getHealth: () => ({
			electrumConnected: clock.t >= (setup.connectAt ?? 0)
		}),
		getChannel: (id) => {
			if (setup.missing || id !== CHANNEL) return null;
			const info = { channelId: CHANNEL, state } as ChannelInfo;
			if (closedAt !== undefined) {
				info.closeStatus = {
					closer: setup.closer ?? 'local',
					closingTxid: TXID,
					broadcast:
						setup.broadcastAt !== undefined && clock.t >= setup.broadcastAt,
					confirmationHeight: 0,
					resolution: 'pending'
				} as ChannelInfo['closeStatus'];
			}
			return info;
		},
		forceCloseChannel: (_id, accept) => {
			fake.closes.push(accept === true);
			if (setup.refuse) return { ok: false, error: setup.refuse };
			state = 'FORCE_CLOSED';
			closedAt = clock.t;
			return { ok: true, commitmentTxid: TXID };
		},
		rebroadcastClose: async () => {
			fake.rebroadcasts++;
			return { ok: true, txid: TXID, broadcastOk: setup.rebroadcastOk };
		}
	};
	return fake;
}

describe('runOfflineForceClose', () => {
	let clock: { t: number };
	let timing: IOfflineForceCloseOptions;

	beforeEach(() => {
		clock = { t: 0 };
		timing = {
			acceptStaleStateRisk: false,
			connectTimeoutMs: 60_000,
			broadcastTimeoutMs: 60_000,
			pollMs: 500,
			rebroadcastMs: 10_000,
			now: (): number => clock.t,
			sleep: async (ms): Promise<void> => {
				clock.t += ms;
			}
		};
	});

	it('waits for Electrum, closes, and answers once the broadcast is seen', async () => {
		const node = fakeNode(clock, { connectAt: 3_000, broadcastAt: 4_000 });
		const result = await runOfflineForceClose(node, CHANNEL, timing);
		expect(result).to.deep.equal({
			ok: true,
			result: { forceClosed: true, commitmentTxid: TXID, broadcast: true }
		});
		expect(node.closes).to.deep.equal([false]);
		expect(node.rebroadcasts).to.equal(0);
	});

	it('closes nothing when Electrum never answers', async () => {
		const node = fakeNode(clock, { connectAt: Infinity });
		const result = await runOfflineForceClose(node, CHANNEL, timing);
		expect(result.ok).to.equal(false);
		expect(result.error?.code).to.equal('ELECTRUM_UNAVAILABLE');
		expect(result.error?.message).to.match(/nothing was closed/);
		expect(node.closes).to.deep.equal([]);
	});

	it('passes the stale state acknowledgement through', async () => {
		const node = fakeNode(clock, { broadcastAt: 0 });
		await runOfflineForceClose(node, CHANNEL, {
			...timing,
			acceptStaleStateRisk: true
		});
		expect(node.closes).to.deep.equal([true]);
	});

	it('reports a refused close under FORCE_CLOSE_FAILED', async () => {
		const node = fakeNode(clock, { refuse: 'Channel is in state CLOSED' });
		const result = await runOfflineForceClose(node, CHANNEL, timing);
		expect(result.error).to.deep.equal({
			code: 'FORCE_CLOSE_FAILED',
			message: 'Channel is in state CLOSED'
		});
	});

	it('reports an unknown channel', async () => {
		const node = fakeNode(clock, { missing: true });
		const result = await runOfflineForceClose(node, CHANNEL, timing);
		expect(result.error?.code).to.equal('CHANNEL_NOT_FOUND');
		expect(node.closes).to.deep.equal([]);
	});

	it('rebroadcasts when the queued broadcast is not seen', async () => {
		const node = fakeNode(clock, { rebroadcastOk: true });
		const result = await runOfflineForceClose(node, CHANNEL, timing);
		expect(result.ok).to.equal(true);
		expect(node.rebroadcasts).to.equal(1);
		expect(clock.t).to.equal(10_000);
	});

	it('rebroadcasts a channel already force closed at once, without closing again', async () => {
		const node = fakeNode(clock, {
			state: 'FORCE_CLOSED',
			rebroadcastOk: true
		});
		const result = await runOfflineForceClose(node, CHANNEL, timing);
		expect(result).to.deep.equal({
			ok: true,
			result: {
				forceClosed: true,
				commitmentTxid: TXID,
				broadcast: true,
				alreadyForceClosed: true
			}
		});
		expect(node.closes).to.deep.equal([]);
		expect(node.rebroadcasts).to.equal(1);
		expect(clock.t).to.equal(0);
	});

	it('on a re-run, does not take a sighting of our commitment from an earlier run as the broadcast', async () => {
		const node = fakeNode(clock, {
			state: 'FORCE_CLOSED',
			broadcastAt: 0,
			rebroadcastOk: false
		});
		const result = await runOfflineForceClose(node, CHANNEL, timing);
		expect(result.error?.code).to.equal('BROADCAST_FAILED');
		expect(node.rebroadcasts).to.equal(7);
	});

	it('on a re-run, takes a sighting of the peer close without rebroadcasting', async () => {
		const node = fakeNode(clock, {
			state: 'FORCE_CLOSED',
			closer: 'remote',
			broadcastAt: 0
		});
		const result = await runOfflineForceClose(node, CHANNEL, timing);
		expect(result.ok).to.equal(true);
		expect(node.rebroadcasts).to.equal(0);
	});

	it('fails with the txid and the last broadcast error when nothing lands', async () => {
		const node = fakeNode(clock, { rebroadcastOk: false });
		const result = await runOfflineForceClose(node, CHANNEL, {
			...timing,
			lastBroadcastError: () => 'min relay fee not met'
		});
		expect(result.error?.code).to.equal('BROADCAST_FAILED');
		expect(result.error?.message).to.include(TXID);
		expect(result.error?.message).to.include('min relay fee not met');
		expect(result.error?.message).to.include(`rebroadcast-close ${CHANNEL}`);
		expect(node.rebroadcasts).to.equal(6);
	});
});

describe('offline force close Electrum transport', function () {
	this.timeout(60_000);

	let dir: string;
	let server: net.Server;
	let port: number;
	let firstBytes: number[];

	beforeEach(async () => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-offline-close-'));
		firstBytes = [];
		server = net.createServer((socket) => {
			// Hang up after the first bytes: a held socket would make the
			// wallet's stop wait out its refresh bound.
			socket.once('data', (chunk: Buffer) => {
				firstBytes.push(chunk[0]);
				socket.destroy();
			});
			socket.on('error', () => undefined);
		});
		await new Promise<void>((resolve) =>
			server.listen(0, '127.0.0.1', resolve)
		);
		port = (server.address() as net.AddressInfo).port;
	});

	afterEach(async () => {
		await new Promise<void>((resolve) => server.close(() => resolve()));
		fs.rmSync(dir, { recursive: true, force: true });
	});

	const firstByteWith = async (
		electrumTls: boolean | undefined
	): Promise<number> => {
		const node = await BeignetNode.create(
			offlineForceCloseOptions(
				{
					mnemonic: MNEMONIC,
					network: 'regtest',
					dataDir: dir,
					electrumHost: '127.0.0.1',
					electrumPort: port,
					electrumTls
				},
				noopLogger
			)
		);
		try {
			const deadline = Date.now() + 15_000;
			while (firstBytes.length === 0 && Date.now() < deadline) {
				await new Promise((resolve) => setTimeout(resolve, 50));
			}
		} finally {
			await node.destroy();
		}
		expect(firstBytes, 'the node never dialed the stand-in').to.not.be.empty;
		return firstBytes[0];
	};

	it('speaks TLS when electrumTls is true', async () => {
		expect(await firstByteWith(true)).to.equal(0x16);
	});

	it('speaks plaintext when electrumTls is false', async () => {
		expect(await firstByteWith(false)).to.equal('{'.charCodeAt(0));
	});
});

describe('beignet channel forceclose --offline', function () {
	this.timeout(60_000);

	before(assertDistCliFresh);

	let home: string;
	let dataDir: string;
	let server: net.Server;
	let port: number;
	let firstBytes: number[];

	beforeEach(async () => {
		home = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-offline-cli-'));
		dataDir = path.join(home, 'data');
		firstBytes = [];
		server = net.createServer((socket) => {
			socket.once('data', (chunk: Buffer) => {
				firstBytes.push(chunk[0]);
				socket.destroy();
			});
			socket.on('error', () => undefined);
		});
		await new Promise<void>((resolve) =>
			server.listen(0, '127.0.0.1', resolve)
		);
		port = (server.address() as net.AddressInfo).port;
	});

	afterEach(async () => {
		await new Promise<void>((resolve) => server.close(() => resolve()));
		fs.rmSync(home, { recursive: true, force: true });
	});

	const writeConfig = (config: Record<string, unknown>): void => {
		fs.mkdirSync(path.join(home, '.beignet'), { recursive: true });
		fs.writeFileSync(
			path.join(home, '.beignet', 'config.json'),
			JSON.stringify(config)
		);
	};

	/**
	 * Run the built CLI under the temp HOME, with none of the caller's
	 * BEIGNET_* variables. `until` ends the child early once it returns true.
	 */
	const run = (
		args: string[],
		env: Record<string, string> = {},
		until?: () => boolean
	): Promise<{ code: number | null; stdout: string; stderr: string }> => {
		const childEnv: NodeJS.ProcessEnv = { HOME: home, PATH: process.env.PATH };
		const child = spawn(process.execPath, [DIST_CLI, ...args], {
			env: { ...childEnv, ...env },
			stdio: ['ignore', 'pipe', 'pipe']
		});
		let stdout = '';
		let stderr = '';
		child.stdout.on('data', (c: Buffer) => (stdout += c.toString()));
		child.stderr.on('data', (c: Buffer) => (stderr += c.toString()));
		const poll =
			until &&
			setInterval(() => {
				if (until()) child.kill('SIGKILL');
			}, 50);
		const killer = setTimeout(() => child.kill('SIGKILL'), 45_000);
		return new Promise((resolve) => {
			child.once('close', (code) => {
				if (poll) clearInterval(poll);
				clearTimeout(killer);
				resolve({ code, stdout, stderr });
			});
		});
	};

	const regtestConfig = (
		extra: Record<string, unknown> = {}
	): Record<string, unknown> => ({
		mnemonic: MNEMONIC,
		network: 'regtest',
		dataDir,
		electrumHost: '127.0.0.1',
		electrumPort: port,
		...extra
	});

	it('refuses while the daemon holds the wallet, with one JSON line on stdout', async () => {
		writeConfig(regtestConfig());
		fs.mkdirSync(dataDir, { recursive: true });
		const lockPath = path.join(dataDir, 'regtest.lock');
		acquireInstanceLock(lockPath);
		try {
			const { code, stdout, stderr } = await run([
				'channel',
				'forceclose',
				CHANNEL,
				'--offline'
			]);
			expect(code, stderr).to.equal(1);
			const lines = stdout.trim().split('\n');
			expect(lines, stdout).to.have.length(1);
			const out = JSON.parse(lines[0]);
			expect(out.ok).to.equal(false);
			expect(out.error.code).to.equal('INSTANCE_ALREADY_RUNNING');
			expect(out.error.message).to.include('drop --offline');
		} finally {
			releaseInstanceLock(lockPath);
		}
	});

	it('takes --network over the config file', async () => {
		// The lock is per network: holding signet's proves which one opened.
		writeConfig(regtestConfig());
		fs.mkdirSync(dataDir, { recursive: true });
		const lockPath = path.join(dataDir, 'signet.lock');
		acquireInstanceLock(lockPath);
		try {
			const { stdout } = await run([
				'channel',
				'forceclose',
				CHANNEL,
				'--offline',
				'--network',
				'signet'
			]);
			expect(JSON.parse(stdout).error.code).to.equal(
				'INSTANCE_ALREADY_RUNNING'
			);
		} finally {
			releaseInstanceLock(lockPath);
		}
	});

	it('refuses with no mnemonic in the config or the environment', async () => {
		const { code, stdout } = await run([
			'channel',
			'forceclose',
			CHANNEL,
			'--offline'
		]);
		expect(code).to.equal(1);
		expect(JSON.parse(stdout).error.code).to.equal('NO_MNEMONIC');
	});

	it('reads the mnemonic from BEIGNET_MNEMONIC and dials Electrum over TLS as configured', async () => {
		const config: Record<string, unknown> = regtestConfig({
			electrumTls: true
		});
		delete config.mnemonic;
		writeConfig(config);
		await run(
			['channel', 'forceclose', CHANNEL, '--offline'],
			{ BEIGNET_MNEMONIC: MNEMONIC },
			() => firstBytes.length > 0
		);
		expect(firstBytes[0]).to.equal(0x16);
	});

	it('dials Electrum in plaintext when the config turns TLS off', async () => {
		writeConfig(regtestConfig({ electrumTls: false }));
		await run(
			['channel', 'forceclose', CHANNEL, '--offline'],
			{},
			() => firstBytes.length > 0
		);
		expect(firstBytes[0]).to.equal('{'.charCodeAt(0));
	});
});
