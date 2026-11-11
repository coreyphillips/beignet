import { expect } from 'chai';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import {
	irohBooleanEnv,
	irohRelaysEnv,
	validateIrohConfig
} from '../../src/cli/iroh-config';
import { daemonOptions } from '../../src/cli/daemon-options';
import { startDaemon, IStartedDaemon } from '../../src/cli/daemon';
import { BeignetNode } from '../../src/cli/beignet-node';
import { BeignetConfig, NodeInfo, PeerInfo } from '../../src/cli/types';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	IFakeIrohBinding,
	fakeIrohBinding
} from '../lightning/helpers/fake-iroh';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

describe('Iroh daemon configuration', () => {
	it('allows an empty relay environment variable to disable relays', () => {
		const previous = process.env.BEIGNET_IROH_RELAYS;
		try {
			delete process.env.BEIGNET_IROH_RELAYS;
			expect(irohRelaysEnv()).to.equal(undefined);
			for (const value of ['', '  ,  ']) {
				process.env.BEIGNET_IROH_RELAYS = value;
				expect(irohRelaysEnv()).to.deep.equal([]);
			}
			process.env.BEIGNET_IROH_RELAYS = ' https://relay.example , ';
			expect(irohRelaysEnv()).to.deep.equal(['https://relay.example']);
		} finally {
			if (previous === undefined) delete process.env.BEIGNET_IROH_RELAYS;
			else process.env.BEIGNET_IROH_RELAYS = previous;
		}
	});
	it('carries Iroh and WebSocket peer settings into a capsule restore', () => {
		const source = new SqliteStorage(':memory:');
		const target = new SqliteStorage(':memory:');
		source.open();
		target.open();
		try {
			const pubkey = '02' + 'ab'.repeat(32);
			const id = 'cd'.repeat(32);
			source.savePeerAddress(pubkey, id, 0, {
				type: 'iroh',
				endpointId: id,
				relayUrl: 'https://relay.example/',
				fallbackOnion: { host: 'a'.repeat(56) + '.onion', port: 9735 }
			});
			source.savePeerAddress('03' + 'ab'.repeat(32), 'ws.example', 443, {
				type: 'ws',
				url: 'wss://ws.example/'
			});
			target.savePeerAddress(pubkey, id, 0, { type: 'iroh', endpointId: id });
			const node = Object.create(BeignetNode.prototype) as {
				storage: SqliteStorage;
				networkName: string;
				carryDaemonState: (from: SqliteStorage, to: SqliteStorage) => void;
			};
			node.storage = source;
			node.networkName = 'regtest';
			node.carryDaemonState(source, target);
			expect(target.loadAllPeerAddresses()).to.deep.equal(
				source.loadAllPeerAddresses()
			);
		} finally {
			source.close();
			target.close();
		}
	});
	it('requires an explicit boolean opt-in', () => {
		const previous = process.env.BEIGNET_IROH;
		try {
			delete process.env.BEIGNET_IROH;
			expect(irohBooleanEnv('BEIGNET_IROH')).to.equal(undefined);
			process.env.BEIGNET_IROH = 'true';
			expect(irohBooleanEnv('BEIGNET_IROH')).to.equal(true);
			process.env.BEIGNET_IROH = 'false';
			expect(irohBooleanEnv('BEIGNET_IROH')).to.equal(false);
			process.env.BEIGNET_IROH = 'treu';
			expect(() => irohBooleanEnv('BEIGNET_IROH')).to.throw(
				'exactly true or false'
			);
		} finally {
			if (previous === undefined) delete process.env.BEIGNET_IROH;
			else process.env.BEIGNET_IROH = previous;
		}
	});
	it('forwards the opt-in, discovery policy and custom relays to the daemon', () => {
		const config = {
			network: 'regtest',
			iroh: true,
			irohDiscovery: false,
			irohRelays: ['https://relay.example/']
		} as BeignetConfig;
		const options = daemonOptions(config, 0);
		expect(options.iroh).to.equal(true);
		expect(options.irohDiscovery).to.equal(false);
		expect(options.irohRelays).to.deep.equal(config.irohRelays);
	});
	it('reads relay-only from the environment and forwards it to the daemon', () => {
		const previous = process.env.BEIGNET_IROH_RELAY_ONLY;
		try {
			delete process.env.BEIGNET_IROH_RELAY_ONLY;
			expect(irohBooleanEnv('BEIGNET_IROH_RELAY_ONLY')).to.equal(undefined);
			process.env.BEIGNET_IROH_RELAY_ONLY = 'true';
			expect(irohBooleanEnv('BEIGNET_IROH_RELAY_ONLY')).to.equal(true);
			process.env.BEIGNET_IROH_RELAY_ONLY = '1';
			expect(() => irohBooleanEnv('BEIGNET_IROH_RELAY_ONLY')).to.throw(
				'exactly true or false'
			);
		} finally {
			if (previous === undefined) delete process.env.BEIGNET_IROH_RELAY_ONLY;
			else process.env.BEIGNET_IROH_RELAY_ONLY = previous;
		}
		const on = daemonOptions(
			{ network: 'regtest', iroh: true, irohRelayOnly: true } as BeignetConfig,
			0
		);
		expect(on.irohRelayOnly).to.equal(true);
		const off = daemonOptions(
			{ network: 'regtest', iroh: true } as BeignetConfig,
			0
		);
		expect(off.irohRelayOnly).to.equal(undefined);
	});
	it('refuses relay-only with relays disabled, and a non-boolean value', async () => {
		expect(() =>
			validateIrohConfig({ irohRelayOnly: 'true' as unknown as boolean })
		).to.throw('irohRelayOnly must be a boolean');
		expect(() =>
			validateIrohConfig({ iroh: true, irohRelayOnly: true, irohRelays: [] })
		).to.throw('needs a relay');
		// With Iroh off the switch has nothing to act on, and with relays left
		// at their default there is one to use.
		validateIrohConfig({ irohRelayOnly: true, irohRelays: [] });
		validateIrohConfig({ iroh: true, irohRelayOnly: true });
		const error = await BeignetNode.create({
			iroh: true,
			irohRelayOnly: true,
			irohRelays: []
		}).then(
			() => null,
			(err: Error) => err
		);
		expect(error?.message).to.contain('needs a relay');
	});
	it('rejects invalid settings before starting a node', async () => {
		expect(() =>
			validateIrohConfig({ irohRelays: ['file:///tmp/relay'] })
		).to.throw('relay');
		const error = await BeignetNode.create({
			iroh: 'true' as unknown as boolean
		}).then(
			() => null,
			(err: Error) => err
		);
		expect(error?.message).to.contain('iroh must be a boolean');
	});
});

describe('Iroh daemon surface', function () {
	this.timeout(20_000);
	let daemon: IStartedDaemon | undefined;
	let dir: string;
	before(function () {
		try {
			require('@number0/iroh/index.js');
		} catch {
			this.skip();
		}
	});
	beforeEach(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-iroh-api-'));
	});
	afterEach(async () => {
		await daemon?.stop();
		daemon = undefined;
		fs.rmSync(dir, { recursive: true, force: true });
	});
	async function boot(enabled: boolean): Promise<void> {
		daemon = await startDaemon({
			mnemonic: MNEMONIC,
			network: 'regtest',
			dataDir: dir,
			daemonPort: 0,
			electrumHost: '127.0.0.1',
			electrumPort: 65529,
			electrumTls: false,
			rapidGossipSync: false,
			autoGossipSync: false,
			autoBootstrap: false,
			autoReconnect: false,
			logLevel: 'silent',
			iroh: enabled,
			irohDiscovery: false,
			irohRelays: []
		});
	}
	async function request(
		route: string,
		body?: unknown
	): Promise<{
		status: number;
		body: { result: NodeInfo; error?: { code: string } };
	}> {
		const port = (daemon!.server.address() as AddressInfo).port;
		const response = await fetch(`http://127.0.0.1:${port}${route}`, {
			method: body === undefined ? 'GET' : 'POST',
			headers: { 'content-type': 'application/json' },
			...(body === undefined ? {} : { body: JSON.stringify(body) })
		});
		return {
			status: response.status,
			body: (await response.json()) as { result: NodeInfo }
		};
	}
	it('exposes capability without starting Iroh when disabled', async () => {
		await boot(false);
		const response = await request('/info');
		expect(response.body.result.irohAvailable).to.equal(true);
		expect(response.body.result.irohUri).to.equal(undefined);
	});
	it('rejects a disabled Iroh dial as a non-retryable configuration error', async () => {
		await boot(false);
		const info = await request('/info');
		const response = await request('/peer/connect', {
			pubkey: info.body.result.nodeId,
			transport: 'iroh',
			endpointId: 'ab'.repeat(32)
		});
		expect(response.status).to.equal(400);
		expect(response.body.error?.code).to.equal('INVALID_PARAMS');
	});
	it('waits for a relay hint with private discovery and accepts an Iroh API dial', async () => {
		await boot(true);
		const info = await request('/info');
		const address = { pubkey: info.body.result.nodeId, host: 'ab'.repeat(32) };
		expect(info.body.result.irohUri).to.equal(undefined);
		expect(info.body.result.listening).to.equal(true);
		const calls: unknown[][] = [];
		daemon!.node.connectPeer = async (...args): Promise<PeerInfo> => {
			calls.push(args);
			return {
				pubkey: args[0],
				host: address.host,
				port: 0,
				state: 'connected'
			};
		};
		const relayUrl = 'https://relay.example/';
		const fallbackOnion = { host: 'a'.repeat(56) + '.onion', port: 9735 };
		const response = await request('/peer/connect', {
			pubkey: address.pubkey,
			transport: 'iroh',
			endpointId: address.host,
			relayUrl,
			fallbackOnion
		});
		expect(response.status).to.equal(200);
		expect(calls[0][3]).to.deep.equal({
			type: 'iroh',
			endpointId: address.host,
			relayUrl,
			fallbackOnion
		});
		const invalid = await request('/peer/connect', {
			pubkey: address.pubkey,
			transport: 'iroh',
			endpointId: 'not-an-id'
		});
		expect(invalid.status).to.equal(400);
		expect(calls).to.have.length(1);
	});
});

describe('Iroh relay-only daemon surface', function () {
	this.timeout(20_000);
	const PUBLIC_ADDRESS = '203.0.113.9:4433';
	let daemon: IStartedDaemon | undefined;
	let fake: IFakeIrohBinding | undefined;
	let dir: string;
	before(function () {
		try {
			require('@number0/iroh/index.js');
		} catch {
			this.skip();
		}
	});
	beforeEach(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-iroh-relay-only-'));
	});
	afterEach(async () => {
		await daemon?.stop();
		daemon = undefined;
		fake?.restore();
		fake = undefined;
		fs.rmSync(dir, { recursive: true, force: true });
	});
	async function boot(
		extra: Partial<Parameters<typeof startDaemon>[0]> = {}
	): Promise<void> {
		daemon = await startDaemon({
			mnemonic: MNEMONIC,
			network: 'regtest',
			dataDir: dir,
			daemonPort: 0,
			electrumHost: '127.0.0.1',
			electrumPort: 65529,
			electrumTls: false,
			rapidGossipSync: false,
			autoGossipSync: false,
			autoBootstrap: false,
			autoReconnect: false,
			logLevel: 'silent',
			iroh: true,
			irohRelayOnly: true,
			irohDiscovery: false,
			irohRelays: ['https://relay.example/'],
			...extra
		});
	}
	async function info(): Promise<NodeInfo> {
		const port = (daemon!.server.address() as AddressInfo).port;
		const response = await fetch(`http://127.0.0.1:${port}/info`);
		return ((await response.json()) as { result: NodeInfo }).result;
	}
	async function until(check: () => Promise<boolean>): Promise<void> {
		const deadline = Date.now() + 5_000;
		while (!(await check())) {
			if (Date.now() > deadline) throw new Error('condition timed out');
			await new Promise((resolve) => setTimeout(resolve, 50));
		}
	}

	it('reports the mode, publishes the link once a relay is known, and takes it down on a violation', async () => {
		fake = fakeIrohBinding({ native: true });
		const errors: Array<{ code: string; message: string }> = [];
		await boot({ onError: (error) => errors.push(error) });
		const endpoint = fake.builders[0].endpoint;
		expect(fake.builders[0].calls).to.include('clearIpTransports');

		const bound = await info();
		expect(bound.irohRelayOnly).to.equal(true);
		expect(bound.irohRelayOnlyMode).to.equal('native');
		expect(bound.irohListenError).to.equal(undefined);
		expect(bound.irohUri).to.equal(undefined);
		expect(bound.listening).to.equal(true);

		endpoint.relayUrl = 'https://relay.example/';
		const linked = await info();
		expect(linked.irohUri).to.contain('?relay=https%3A%2F%2Frelay.example%2F');

		// The endpoint's own address list gains an address a peer could use.
		endpoint.addresses = [PUBLIC_ADDRESS];
		await until(async () => (await info()).irohListenError !== undefined);
		const down = await info();
		expect(down.irohListenError).to.deep.include({
			state: 'failed',
			errno: 'IROH_RELAY_ONLY_VIOLATED'
		});
		expect(down.irohListenError?.message).to.not.contain('203.0.113');
		expect(down.irohUri).to.equal(undefined);
		expect(down.irohRelayOnly).to.equal(true);
		expect(down.irohRelayOnlyMode).to.equal(undefined);
		expect(down.listening).to.equal(false);
		expect(endpoint.closed).to.equal(true);
		expect(errors.map((error) => error.code)).to.deep.equal([
			'IROH_RELAY_ONLY_VIOLATED'
		]);
		// Nothing binds a second endpoint.
		expect(fake.builders).to.have.length(1);
	});

	it('starts without the listener when relay-only cannot be kept at bind', async () => {
		fake = fakeIrohBinding({
			native: true,
			endpoint: () => ({ addresses: [PUBLIC_ADDRESS] })
		});
		await boot();
		const result = await info();
		expect(result.irohRelayOnly).to.equal(true);
		expect(result.irohRelayOnlyMode).to.equal(undefined);
		expect(result.irohUri).to.equal(undefined);
		expect(result.irohListenError).to.deep.include({
			state: 'failed',
			errno: 'IROH_RELAY_ONLY_VIOLATED'
		});
		expect(result.irohListenError?.message).to.not.contain('203.0.113');
		expect(fake.builders[0].endpoint.closed).to.equal(true);
	});

	it('leaves the relay-only fields off /info for an ordinary Iroh node', async () => {
		fake = fakeIrohBinding();
		await boot({ irohRelayOnly: false });
		const result = await info();
		expect(result).to.not.have.property('irohRelayOnly');
		expect(result).to.not.have.property('irohRelayOnlyMode');
		expect(fake.builders[0].bindAddrs).to.deep.equal([]);
	});

	it('warns when a clearnet address is announced beside relay-only', async () => {
		fake = fakeIrohBinding({ native: true });
		const warnings: string[] = [];
		const logger = {
			debug: (): void => undefined,
			info: (): void => undefined,
			warn: (message: string): void => {
				warnings.push(message);
			},
			error: (): void => undefined
		};
		await boot({
			logLevel: 'warn',
			logger,
			announceAddresses: [
				'203.0.113.7:9735',
				'vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion:9735'
			]
		});
		const about = warnings.filter((message) =>
			message.includes('irohRelayOnly')
		);
		expect(about).to.have.length(1);
		expect(about[0]).to.contain('1 clearnet address');
	});
});
