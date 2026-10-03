import Database from 'better-sqlite3';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { SocksClient } from 'socks';
const sinon = require('sinon');
import {
	createNode,
	makeNodeConfig,
	connectNodes,
	openReadyChannel
} from './helpers/loopback-nodes';
import { parseAnnouncedAddress } from '../../src/lightning/gossip/messages';
import { deriveLightningKeysFromMnemonic } from '../../src/lightning/keys/wallet-keys';
import { expect } from 'chai';
import { hkdfSync } from 'crypto';
import { once } from 'events';
import * as bip39 from 'bip39';
import {
	deriveIrohSecretKey,
	connectIrohWithFallback,
	formatIrohAddress,
	normalizeIrohEndpointId,
	parseIrohAddress,
	IrohTransport,
	IIrohStream,
	IIrohEndpoint
} from '../../src/lightning/transport/iroh';
import { parsePeerUri } from '../../src/lightning/transport/peer-uri';
import { parseScbAddress } from '../../src/lightning/backup/scb';
import { PeerManager } from '../../src/lightning/transport/peer-manager';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';

const ID = 'ab'.repeat(32);
const PK = '02' + 'ab'.repeat(32);
const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const tick = (): Promise<void> =>
	new Promise((resolve) => setImmediate(resolve));
function deferred<T>(): {
	promise: Promise<T>;
	resolve: (value: T) => void;
	reject: (error: Error) => void;
} {
	let resolve!: (value: T) => void;
	let reject!: (error: Error) => void;
	const promise = new Promise<T>((yes, no) => {
		resolve = yes;
		reject = no;
	});
	return { promise, resolve, reject };
}
function fakeStream(): IIrohStream & {
	readResult: ReturnType<typeof deferred<Uint8Array>>;
	closedResult: ReturnType<typeof deferred<void>>;
	writes: Uint8Array[];
	closeCount: number;
} {
	const readResult = deferred<Uint8Array>();
	const closedResult = deferred<void>();
	return {
		readResult,
		closedResult,
		writes: [],
		closeCount: 0,
		read: () => readResult.promise,
		async writeAll(bytes): Promise<void> {
			this.writes.push(bytes);
		},
		close(): void {
			this.closeCount++;
		},
		closed: () => closedResult.promise,
		diagnostics: () => ({ endpointId: ID, path: 'direct', rttMs: 2 })
	};
}

describe('Iroh addresses and identity', () => {
	it('parses hex and base32 ids without treating them as TCP hosts', () => {
		const uri = `${PK}@iroh:${ID}?relay=https%3A%2F%2Frelay.example%2F`;
		expect(parsePeerUri(uri)).to.deep.equal({
			pubkey: PK,
			host: ID,
			port: 0,
			transport: {
				type: 'iroh',
				endpointId: ID,
				relayUrl: 'https://relay.example/'
			}
		});
		expect(normalizeIrohEndpointId('a'.repeat(52))).to.equal('00'.repeat(32));
		expect(normalizeIrohEndpointId(ID.toUpperCase())).to.equal(ID);
		expect(formatIrohAddress(parseIrohAddress(uri.split('@')[1]))).to.equal(
			uri.split('@')[1]
		);
		expect(parseScbAddress(uri.split('@')[1])?.transport).to.deep.equal(
			parsePeerUri(uri).transport
		);
	});
	it('rejects malformed ids, unknown fields and ambiguous relay hints', () => {
		for (const address of [
			'iroh:short',
			`iroh:${ID}:9735`,
			`iroh:${ID}#fragment`,
			`iroh:${ID}?x=1`,
			`iroh:${ID}?relay=`,
			`iroh:${ID}?relay=ftp://relay.example`,
			`iroh:${ID}?relay=https://user:password@relay.example`,
			`iroh:${ID}?relay=https://one.example&relay=https://two.example`,
			'iroh:' + 'a'.repeat(51) + 'b'
		])
			expect(() => parseIrohAddress(address), address).to.throw();
	});
	it('derives a stable, domain-separated key from the BIP39 seed', () => {
		const seed = bip39.mnemonicToSeedSync(MNEMONIC);
		const expected = Buffer.from(
			hkdfSync('sha256', seed, Buffer.alloc(32), 'beignet/iroh/identity/v1', 32)
		);
		expect(deriveIrohSecretKey(seed)).to.deep.equal(expected);
		expect(deriveIrohSecretKey(seed)).to.deep.equal(
			deriveIrohSecretKey(bip39.mnemonicToSeedSync(MNEMONIC))
		);
		expect(
			deriveIrohSecretKey(bip39.mnemonicToSeedSync(MNEMONIC, 'passphrase'))
		).not.to.deep.equal(expected);
	});
	it('preserves transport options in storage, and clears them on a later TCP dial', () => {
		const db = new SqliteStorage(':memory:');
		db.open();
		try {
			const transport = parsePeerUri(
				`${PK}@iroh:${ID}?relay=https://relay.example`
			).transport;
			db.savePeerAddress(PK, ID, 0, transport);
			expect(db.loadAllPeerAddresses()).to.deep.equal([
				{ pubkey: PK, host: ID, port: 0, transport }
			]);
			db.savePeerAddress(PK, '127.0.0.1', 9735);
			expect(db.loadAllPeerAddresses()).to.deep.equal([
				{ pubkey: PK, host: '127.0.0.1', port: 9735 }
			]);
		} finally {
			db.close();
		}
	});
});

describe('Iroh duplex adapter', () => {
	it('serializes writes and accounts for in-flight bytes until flushed', async () => {
		const stream = fakeStream();
		const release = deferred<void>();
		stream.writeAll = async (bytes): Promise<void> => {
			stream.writes.push(bytes);
			await release.promise;
		};
		const socket = new IrohTransport(stream);
		const callbacks: number[] = [];
		const first = Buffer.alloc(1024 * 1024, 1);
		expect(socket.write(first, () => callbacks.push(1))).to.equal(false);
		socket.write('next', () => callbacks.push(2));
		first.fill(2);
		expect(socket.writableLength).to.equal(1024 * 1024 + 4);
		expect(stream.writes.length).to.equal(1);
		expect(stream.writes[0][0]).to.equal(1);
		release.resolve();
		await tick();
		expect(callbacks).to.deep.equal([1, 2]);
		expect(socket.writableLength).to.equal(0);
		socket.destroy();
	});
	it('buffers received data until a handshake reader attaches', async () => {
		const stream = fakeStream();
		let first = true;
		stream.read = async (): Promise<Uint8Array> => {
			if (first) {
				first = false;
				return Buffer.from('act1');
			}
			return stream.readResult.promise;
		};
		const socket = new IrohTransport(stream);
		await tick();
		const received: Buffer[] = [];
		socket.on('data', (bytes: Buffer) => received.push(bytes));
		expect(Buffer.concat(received).toString()).to.equal('act1');
		socket.destroy();
	});
	it('treats a half-close as a full close exactly once', async () => {
		const stream = fakeStream();
		const socket = new IrohTransport(stream);
		const closed = once(socket, 'close');
		let count = 0;
		socket.on('close', () => count++);
		stream.readResult.resolve(Buffer.alloc(0));
		await closed;
		stream.closedResult.resolve();
		socket.destroy();
		await tick();
		expect(count).to.equal(1);
		expect(stream.closeCount).to.equal(1);
	});
	it('propagates native write errors and fails every pending callback', async () => {
		const stream = fakeStream();
		const failure = new Error('stream reset');
		stream.writeAll = async (): Promise<void> => {
			throw failure;
		};
		const socket = new IrohTransport(stream);
		const events: string[] = [];
		socket.on('error', (err) => {
			expect(err).to.equal(failure);
			events.push('error');
		});
		const closed = new Promise<void>((resolve) =>
			socket.on('close', () => {
				events.push('close');
				resolve();
			})
		);
		const errors: Array<Error | undefined> = [];
		socket.write('one', (err) => errors.push(err));
		socket.write('two', (err) => errors.push(err));
		await closed;
		expect(errors).to.deep.equal([failure, failure]);
		expect(events).to.deep.equal(['error', 'close']);
		expect(socket.writableLength).to.equal(0);
	});
	it('emits timeout without closing and cancels a disarmed timer', async () => {
		const stream = fakeStream();
		const socket = new IrohTransport(stream);
		let expired = 0;
		socket.on('timeout', () => expired++);
		socket.setTimeout(1).setTimeout(0);
		await new Promise((resolve) => setTimeout(resolve, 5));
		expect(expired).to.equal(0);
		const timeout = once(socket, 'timeout');
		socket.setTimeout(1);
		await timeout;
		expect(stream.closeCount).to.equal(0);
		socket.destroy();
	});
	it('closes promptly when the QUIC connection dies without stream EOF', async () => {
		const stream = fakeStream();
		const socket = new IrohTransport(stream);
		const closed = once(socket, 'close');
		stream.closedResult.resolve();
		await closed;
		expect(stream.closeCount).to.equal(1);
	});
});

describe('Iroh endpoint lifecycle', () => {
	it('does not create an endpoint unless Iroh is requested', async () => {
		let calls = 0;
		const pm = new PeerManager({
			localPrivateKey: Buffer.alloc(32, 1),
			iroh: {
				secretKey: Buffer.alloc(32, 2),
				factory: async (): Promise<IIrohEndpoint> => {
					calls++;
					throw new Error('unexpected');
				}
			}
		});
		await tick();
		expect(calls).to.equal(0);
		pm.destroy();
	});
	it('closes an endpoint whose bind finishes after a freeze', async () => {
		const bound = deferred<IIrohEndpoint>();
		const pm = new PeerManager({
			localPrivateKey: Buffer.alloc(32, 1),
			iroh: {
				secretKey: Buffer.alloc(32, 2),
				factory: (): Promise<IIrohEndpoint> => bound.promise
			}
		});
		const listening = pm.listenIroh().then(
			() => 'success',
			(err: Error) => err.message
		);
		pm.freezeConnections();
		// The caller settles even if the platform bind never returns.
		expect(await listening).to.contain('Listener aborted');
		let closed = 0;
		bound.resolve({
			close: async () => {
				closed++;
			}
		} as IIrohEndpoint);
		await tick();
		expect(closed).to.equal(1);
		expect(pm.isListening()).to.equal(false);
		pm.destroy();
	});
	it('derives the same endpoint key on mnemonic restore and never reuses the node key', async () => {
		const keys: Buffer[] = [];
		for (let n = 0; n < 2; n++) {
			const node = LightningNode.fromMnemonic(MNEMONIC, {
				enableNetworking: true,
				iroh: {
					factory: async (options) => {
						keys.push(Buffer.from(options.secretKey));
						throw new Error('captured');
					}
				}
			});
			try {
				await node.listenIroh();
			} catch {
				/* Only capture the factory input. */
			}
			node.destroy();
		}
		expect(keys).to.have.length(2);
		expect(keys[0]).to.deep.equal(keys[1]);
		expect(keys[0]).not.to.deep.equal(
			deriveLightningKeysFromMnemonic(MNEMONIC).nodePrivateKey
		);
		expect(keys[0]).to.deep.equal(
			deriveIrohSecretKey(bip39.mnemonicToSeedSync(MNEMONIC))
		);
	});
	it('refuses an Iroh dial without an injected factory', async () => {
		const pm = new PeerManager({
			localPrivateKey: Buffer.alloc(32, 1),
			autoReconnect: true
		});
		const reconnect = sinon.spy(
			pm as unknown as { scheduleReconnect: () => void },
			'scheduleReconnect'
		);
		try {
			const message = await pm
				.connectPeer(PK, ID, 0, { type: 'iroh', endpointId: ID })
				.then(
					() => 'success',
					(err: Error) => err.message
				);
			expect(message).to.contain('Iroh is not enabled');
			expect(reconnect.called).to.equal(false);
			expect(pm.getPeerAddress(PK)).to.equal(undefined);
		} finally {
			pm.destroy();
		}
	});
});

describe('Iroh with an optional Tor fallback', () => {
	for (const phase of ['binding', 'connecting']) {
		it(`cancels fallback and late work after timing out during ${phase}`, async () => {
			const clock = sinon.useFakeTimers();
			const socks = sinon
				.stub(SocksClient, 'createConnection')
				.rejects(new Error('unexpected fallback'));
			const bound = deferred<IIrohEndpoint>();
			const connected = deferred<IrohTransport>();
			const connect = sinon.stub().returns(connected.promise);
			const endpoint = {
				connect,
				close: async () => undefined,
				stopListening: () => undefined
			} as unknown as IIrohEndpoint;
			const pm = new PeerManager({
				localPrivateKey: Buffer.alloc(32, 1),
				iroh: {
					secretKey: Buffer.alloc(32, 2),
					factory: (): Promise<IIrohEndpoint> =>
						phase === 'binding' ? bound.promise : Promise.resolve(endpoint)
				}
			});
			try {
				const result = pm
					.connectPeer(
						PK,
						ID,
						0,
						{
							type: 'iroh',
							endpointId: ID,
							fallbackOnion: { host: 'a'.repeat(56) + '.onion', port: 9735 }
						},
						{ timeoutMs: 100, reconnect: false }
					)
					.then(
						() => null,
						(error: Error) => error
					);
				await clock.tickAsync(100);
				expect((await result)?.message).to.equal('Connection timeout');
				await clock.tickAsync(2000);
				expect(socks.called).to.equal(false);
				bound.resolve(endpoint);
				await clock.tickAsync(1);
				expect(connect.callCount).to.equal(phase === 'binding' ? 0 : 1);
				const stream = fakeStream();
				connected.resolve(new IrohTransport(stream));
				await clock.tickAsync(1);
				if (phase === 'connecting') expect(stream.closeCount).to.equal(1);
			} finally {
				pm.destroy();
				socks.restore();
				clock.restore();
			}
		});
	}
	it('does not start Tor when Iroh connects promptly', async () => {
		const socket = new IrohTransport(fakeStream());
		let fallbackCalls = 0;
		const winner = await connectIrohWithFallback(
			async () => socket,
			async () => {
				fallbackCalls++;
				throw new Error('unexpected');
			},
			5
		);
		await new Promise((resolve) => setTimeout(resolve, 10));
		expect(winner).to.equal(socket);
		expect(fallbackCalls).to.equal(0);
		socket.destroy();
	});
	it('starts Tor after the delay and disposes of a late Iroh socket', async () => {
		const primary = deferred<IrohTransport>();
		const lateStream = fakeStream();
		const late = new IrohTransport(lateStream);
		const tor = new IrohTransport(fakeStream());
		const winner = await connectIrohWithFallback(
			() => primary.promise,
			async () => tor,
			1
		);
		expect(winner).to.equal(tor);
		primary.resolve(late);
		await tick();
		expect(lateStream.closeCount).to.equal(1);
		tor.destroy();
	});
	it('falls back immediately on failure and reports when both paths fail', async () => {
		const error = await connectIrohWithFallback(
			async () => {
				throw new Error('primary failed');
			},
			async () => {
				throw new Error('fallback failed');
			},
			60_000
		).then(
			() => null,
			(err: Error) => err
		);
		expect(error?.message)
			.to.contain('primary failed')
			.and.to.contain('fallback failed');
	});
});

describe('persisted Iroh peer addresses', () => {
	it('migrates legacy TCP rows and retains Iroh relay and fallback details after reopening', () => {
		const directory = fs.mkdtempSync(
			path.join(os.tmpdir(), 'beignet-iroh-storage-')
		);
		const filename = path.join(directory, 'node.db');
		try {
			const legacy = new Database(filename);
			legacy.exec(
				'CREATE TABLE schema_version (version INTEGER PRIMARY KEY); INSERT INTO schema_version VALUES (14); CREATE TABLE peer_addresses (pubkey TEXT PRIMARY KEY, host TEXT NOT NULL, port INTEGER NOT NULL, last_connected INTEGER NOT NULL DEFAULT 0)'
			);
			legacy
				.prepare(
					'INSERT INTO peer_addresses (pubkey, host, port) VALUES (?, ?, ?)'
				)
				.run(PK, '127.0.0.1', 9735);
			legacy.close();
			const storage = new SqliteStorage(filename);
			storage.open();
			expect(storage.getSchemaVersion()).to.equal(15);
			expect(storage.loadAllPeerAddresses()).to.deep.equal([
				{ pubkey: PK, host: '127.0.0.1', port: 9735 }
			]);
			const transport = {
				type: 'iroh' as const,
				endpointId: ID,
				relayUrl: 'https://relay.example/',
				fallbackOnion: { host: 'a'.repeat(56) + '.onion', port: 9735 }
			};
			storage.savePeerAddress(PK, ID, 0, transport);
			storage.close();
			const reopened = new SqliteStorage(filename);
			reopened.open();
			try {
				expect(reopened.loadAllPeerAddresses()).to.deep.equal([
					{ pubkey: PK, host: ID, port: 0, transport }
				]);
			} finally {
				reopened.close();
			}
		} finally {
			fs.rmSync(directory, { recursive: true, force: true });
		}
	});

	it('redials a restored channel with its Iroh transport and includes it in the backup', async () => {
		const directory = fs.mkdtempSync(
			path.join(os.tmpdir(), 'beignet-iroh-restart-')
		);
		const filename = path.join(directory, 'node.db');
		let alice: LightningNode | undefined;
		let bob: LightningNode | undefined;
		let restored: LightningNode | undefined;
		try {
			const storage = new SqliteStorage(filename);
			storage.open();
			alice = createNode('iroh-persistence', 1, storage);
			bob = createNode('iroh-persistence', 2);
			connectNodes(alice, bob);
			openReadyChannel(alice, bob);
			const pubkey = bob.getNodeId();
			const transport = {
				type: 'iroh' as const,
				endpointId: ID,
				relayUrl: 'https://relay.example/'
			};
			storage.savePeerAddress(pubkey, ID, 0, transport);
			const backup = alice.buildStaticChannelBackupData();
			expect(backup.channels[0].peerAddresses).to.deep.equal([
				formatIrohAddress(transport)
			]);
			alice.destroy();
			alice = undefined;
			bob.destroy();
			bob = undefined;
			const reopened = new SqliteStorage(filename);
			reopened.open();
			restored = new LightningNode({
				...makeNodeConfig('iroh-persistence', 1, reopened),
				enableNetworking: true,
				autoReconnect: true
			});
			const calls: unknown[][] = [];
			restored.getPeerManager()!.connectPeer = async (
				...args
			): Promise<void> => {
				calls.push(args);
			};
			await new Promise((resolve) => setTimeout(resolve, 20));
			expect(calls).to.have.length(1);
			expect(calls[0]).to.deep.equal([pubkey, ID, 0, transport]);
		} finally {
			alice?.destroy();
			bob?.destroy();
			restored?.destroy();
			fs.rmSync(directory, { recursive: true, force: true });
		}
	});

	it('does not encode an Iroh endpoint as a gossip address', () => {
		expect(() => parseAnnouncedAddress(`iroh:${ID}`)).to.throw();
	});
});
