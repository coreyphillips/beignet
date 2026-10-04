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
				carryDaemonState: (from: SqliteStorage, to: SqliteStorage) => void;
			};
			node.storage = source;
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
