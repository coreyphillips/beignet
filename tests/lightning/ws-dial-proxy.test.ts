/**
 * Outbound WebSocket peer dials and the SOCKS5 proxy (issue #1992).
 *
 * A peer reached by a ws:// or wss:// address used to be dialed directly
 * whatever the proxy settings said, so a node or wallet that hides behind
 * Tor showed its own address to that peer. A Porch link is such an address
 * (issue #1980). These dials are now routed as TCP dials are: by
 * selectOutboundProxy, on the host the WebSocket connects to.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import dns from 'dns';
import net from 'net';
import {
	DEFAULT_TOR_PROXY,
	PeerManager
} from '../../src/lightning/transport/peer-manager';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import type { WebSocketConstructor } from '../../src/lightning/transport/websocket';

const settle = (ms: number): Promise<void> =>
	new Promise((resolve) => setTimeout(resolve, ms));

const randomPubkey = (): string =>
	getPublicKey(crypto.randomBytes(32)).toString('hex');

const ONION = `${'a'.repeat(56)}.onion`;

/**
 * A SOCKS5 proxy that sends every CONNECT to one local port, whatever was
 * asked for, and records the host and port it was asked for.
 */
async function socksTo(targetPort: number): Promise<{
	port: number;
	requested: string[];
	close: () => Promise<void>;
}> {
	const requested: string[] = [];
	const sockets = new Set<net.Socket>();
	const server = net.createServer((client) => {
		sockets.add(client);
		client.on('error', () => undefined);
		client.on('close', () => sockets.delete(client));
		client.once('data', () => {
			client.write(Buffer.from([0x05, 0x00]));
			client.once('data', (request) => {
				// A name (type 3) is what a proxied dial must send: an address
				// (type 1) would mean the name was resolved on this side.
				const named = request[3] === 0x03;
				const end = named ? 5 + request[4] : 8;
				const host = named
					? request.subarray(5, end).toString()
					: `address ${Array.from(request.subarray(4, 8)).join('.')}`;
				requested.push(`${host}:${request.readUInt16BE(end)}`);
				const target = net.connect(targetPort, '127.0.0.1');
				sockets.add(target);
				target.on('error', () => client.destroy());
				target.on('close', () => sockets.delete(target));
				target.once('connect', () => {
					const reply = Buffer.alloc(10);
					reply[0] = 0x05;
					reply[3] = 0x01;
					client.write(reply);
					client.pipe(target);
					target.pipe(client);
				});
			});
		});
	});
	await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
	return {
		port: (server.address() as net.AddressInfo).port,
		requested,
		close: (): Promise<void> => {
			for (const socket of sockets) socket.destroy();
			return new Promise<void>((resolve) => server.close(() => resolve()));
		}
	};
}

/** A TCP server that keeps the first bytes each connection sends. */
async function recordingServer(): Promise<{
	port: number;
	first: Buffer[];
	close: () => Promise<void>;
}> {
	const first: Buffer[] = [];
	const sockets = new Set<net.Socket>();
	const server = net.createServer((socket) => {
		sockets.add(socket);
		socket.on('error', () => undefined);
		socket.on('close', () => sockets.delete(socket));
		socket.once('data', (chunk) => first.push(chunk));
	});
	await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
	return {
		port: (server.address() as net.AddressInfo).port,
		first,
		close: (): Promise<void> => {
			for (const socket of sockets) socket.destroy();
			return new Promise<void>((resolve) => server.close(() => resolve()));
		}
	};
}

/** A port on loopback that nothing listens on. */
async function closedPort(): Promise<number> {
	const server = net.createServer();
	await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
	const { port } = server.address() as net.AddressInfo;
	await new Promise<void>((resolve) => server.close(() => resolve()));
	return port;
}

/**
 * Every name this process asks its resolver for. A direct dial to a named
 * host resolves the name first; a dial through the proxy never does.
 */
function recordLookups(): { names: string[]; restore: () => void } {
	const names: string[] = [];
	const holder = dns as unknown as { lookup: (...args: unknown[]) => unknown };
	const original = holder.lookup;
	holder.lookup = function (this: unknown, ...args: unknown[]): unknown {
		names.push(String(args[0]));
		return original.apply(this, args);
	};
	return {
		names,
		restore: (): void => {
			holder.lookup = original;
		}
	};
}

/** A WebSocket constructor that records what it is asked to open and never opens it. */
function inertWebSocket(): { impl: WebSocketConstructor; urls: string[] } {
	const urls: string[] = [];
	class Inert {
		binaryType = 'blob';
		readyState = 0;
		bufferedAmount = 0;
		onopen: unknown = null;
		onmessage: unknown = null;
		onerror: unknown = null;
		onclose: unknown = null;
		constructor(url: string) {
			urls.push(url);
		}
		send(): void {
			// never open
		}
		close(): void {
			// never open
		}
	}
	return { impl: Inert as unknown as WebSocketConstructor, urls };
}

/**
 * Makes the runtime look like one that opens no sockets of its own (a
 * browser) until the returned function is called.
 */
function asBrowserRuntime(): () => void {
	const descriptor = Object.getOwnPropertyDescriptor(process.versions, 'node')!;
	Object.defineProperty(process.versions, 'node', {
		...descriptor,
		value: undefined
	});
	return (): void => {
		Object.defineProperty(process.versions, 'node', descriptor);
	};
}

/** The error a dial ends in, or undefined when it connected. */
async function outcome(dial: Promise<void>): Promise<Error | undefined> {
	try {
		await dial;
	} catch (err) {
		return err as Error;
	}
	return undefined;
}

describe('WebSocket peer dials and the SOCKS5 proxy (#1992)', function () {
	this.timeout(10_000);

	let lookups: ReturnType<typeof recordLookups>;
	const managers: PeerManager[] = [];
	const closers: Array<() => Promise<void>> = [];

	const manager = (
		options: Partial<ConstructorParameters<typeof PeerManager>[0]> = {}
	): PeerManager => {
		const pm = new PeerManager({
			localPrivateKey: crypto.randomBytes(32),
			socks5TimeoutMs: 1000,
			...options
		});
		managers.push(pm);
		return pm;
	};

	beforeEach(function () {
		lookups = recordLookups();
	});

	afterEach(async function () {
		lookups.restore();
		for (const pm of managers.splice(0)) pm.destroy();
		for (const close of closers.splice(0)) await close();
	});

	it('reaches a WebSocket peer at a public host through the proxy, its name unresolved', async function () {
		const listenerKey = crypto.randomBytes(32);
		const listenerPub = getPublicKey(listenerKey).toString('hex');
		const listener = manager({ localPrivateKey: listenerKey });
		await listener.listenWebSocket(0, '127.0.0.1');
		const proxy = await socksTo(listener.getWebSocketListenerPort()!);
		closers.push(proxy.close);

		const dialer = manager({
			socks5Proxy: { host: '127.0.0.1', port: proxy.port }
		});
		const seen = new Promise<string>((resolve) => {
			listener.once('peer:connect', resolve);
		});
		await dialer.connectPeer(listenerPub, 'relay.example', 8080, {
			type: 'ws',
			url: 'ws://relay.example:8080/v1/p/abc'
		});

		expect(await seen).to.be.a('string');
		expect(proxy.requested).to.deep.equal(['relay.example:8080']);
		expect(lookups.names).to.not.include('relay.example');
		expect(dialer.listPeers()[0].transport).to.equal('ws');
	});

	it('goes by the host in the URL, not by the peer host beside it', async function () {
		const listenerKey = crypto.randomBytes(32);
		const listenerPub = getPublicKey(listenerKey).toString('hex');
		const listener = manager({ localPrivateKey: listenerKey });
		await listener.listenWebSocket(0, '127.0.0.1');
		const port = listener.getWebSocketListenerPort()!;
		const proxy = await socksTo(port);
		closers.push(proxy.close);

		// A loopback host beside a public URL: the URL is what gets dialed.
		const proxied = manager({
			socks5Proxy: { host: '127.0.0.1', port: proxy.port }
		});
		await proxied.connectPeer(listenerPub, '127.0.0.1', port, {
			type: 'ws',
			url: 'ws://relay.example:8080'
		});
		expect(proxy.requested).to.deep.equal(['relay.example:8080']);

		// A public host beside a loopback URL: dialed directly, as a loopback
		// TCP peer is. Tor refuses loopback targets.
		const direct = manager({
			socks5Proxy: { host: '127.0.0.1', port: proxy.port }
		});
		await direct.connectPeer(listenerPub, 'relay.example', 8080, {
			type: 'ws',
			url: `ws://127.0.0.1:${port}`
		});
		expect(proxy.requested).to.have.length(1);
		expect(lookups.names).to.not.include('relay.example');
	});

	it('runs TLS for a wss:// peer inside the tunnel, for the host in the URL', async function () {
		const target = await recordingServer();
		const proxy = await socksTo(target.port);
		closers.push(proxy.close, target.close);

		const dialer = manager({
			socks5Proxy: { host: '127.0.0.1', port: proxy.port }
		});
		// A Porch link. The target never answers, so the dial times out.
		const err = await outcome(
			dialer.connectPeer(
				randomPubkey(),
				'relay.example',
				443,
				{ type: 'ws', url: 'wss://relay.example/v1/p/abc' },
				{ timeoutMs: 400, reconnect: false }
			)
		);

		expect(err).to.be.instanceOf(Error);
		expect(proxy.requested).to.deep.equal(['relay.example:443']);
		expect(target.first).to.have.length(1);
		// A TLS handshake record carrying the name it is for, and no HTTP
		// request in the clear.
		expect(target.first[0][0]).to.equal(0x16);
		expect(target.first[0].includes('relay.example')).to.equal(true);
		expect(target.first[0].includes('GET ')).to.equal(false);
		expect(lookups.names).to.not.include('relay.example');
	});

	it("keeps to the proxy's scope: an onion host through it, a public one directly", async function () {
		const target = await recordingServer();
		const proxy = await socksTo(target.port);
		closers.push(proxy.close, target.close);
		const inert = inertWebSocket();

		const dialer = manager({
			socks5Proxy: { host: '127.0.0.1', port: proxy.port },
			socks5ProxyScope: 'onion',
			webSocketImpl: inert.impl
		});
		await outcome(
			dialer.connectPeer(
				randomPubkey(),
				ONION,
				9735,
				{ type: 'ws' },
				{ timeoutMs: 300, reconnect: false }
			)
		);
		expect(proxy.requested).to.deep.equal([`${ONION}:9735`]);
		expect(inert.urls).to.deep.equal([]);

		await outcome(
			dialer.connectPeer(
				randomPubkey(),
				'relay.example',
				8080,
				{ type: 'ws', url: 'ws://relay.example:8080' },
				{ timeoutMs: 300, reconnect: false }
			)
		);
		expect(proxy.requested).to.have.length(1);
		expect(inert.urls).to.deep.equal(['ws://relay.example:8080']);
	});

	it("sends an onion host to Tor's default port when no proxy is set", async function () {
		const dialer = manager();
		const proxies: Array<{ host: string; port: number }> = [];
		(
			dialer as unknown as {
				buildSocks5Factory: (proxy: {
					host: string;
					port: number;
				}) => () => Promise<net.Socket>;
			}
		).buildSocks5Factory = (proxy) => {
			proxies.push(proxy);
			return async (): Promise<net.Socket> => {
				throw new Error('no Tor in this test');
			};
		};

		const err = await outcome(
			dialer.connectPeer(
				randomPubkey(),
				ONION,
				9735,
				{ type: 'ws', url: `ws://${ONION}:9735` },
				{ timeoutMs: 500, reconnect: false }
			)
		);

		expect(err).to.be.instanceOf(Error);
		expect(proxies).to.deep.equal([DEFAULT_TOR_PROXY]);
		expect(lookups.names).to.not.include(ONION);
	});

	it('leaves an onion host to the platform WebSocket where the engine opens no sockets and no proxy is set', async function () {
		const inert = inertWebSocket();
		const dialer = manager({ webSocketImpl: inert.impl });
		const proxies: unknown[] = [];
		(
			dialer as unknown as { buildSocks5Factory: (proxy: unknown) => unknown }
		).buildSocks5Factory = (proxy): unknown => {
			proxies.push(proxy);
			throw new Error('not expected');
		};

		const restore = asBrowserRuntime();
		try {
			await outcome(
				dialer.connectPeer(
					randomPubkey(),
					ONION,
					9735,
					{ type: 'ws' },
					{ timeoutMs: 200, reconnect: false }
				)
			);
		} finally {
			restore();
		}

		// As before the fix: only the platform can reach an onion host there.
		expect(inert.urls).to.deep.equal([`ws://${ONION}:9735`]);
		expect(proxies).to.deep.equal([]);
	});

	it('keeps a configured proxy in such a runtime: no dial without it', async function () {
		const target = await recordingServer();
		const proxy = await socksTo(target.port);
		closers.push(proxy.close, target.close);
		const inert = inertWebSocket();
		const dialer = manager({
			socks5Proxy: { host: '127.0.0.1', port: proxy.port },
			webSocketImpl: inert.impl
		});

		const restore = asBrowserRuntime();
		try {
			await outcome(
				dialer.connectPeer(
					randomPubkey(),
					'relay.example',
					8080,
					{ type: 'ws', url: 'ws://relay.example:8080' },
					{ timeoutMs: 300, reconnect: false }
				)
			);
		} finally {
			restore();
		}

		// The platform WebSocket would dial the peer directly, so it is not
		// used. (Under Node the in-repo client still runs and reaches the
		// proxy; in a browser it cannot, and the dial fails.)
		expect(inert.urls).to.deep.equal([]);
		expect(proxy.requested).to.deep.equal(['relay.example:8080']);
	});

	it('does not hand a proxied dial to an injected webSocketImpl', async function () {
		const target = await recordingServer();
		const proxy = await socksTo(target.port);
		closers.push(proxy.close, target.close);
		const inert = inertWebSocket();

		// An injected constructor takes a URL and nothing else: it could
		// only dial the peer directly.
		const dialer = manager({
			socks5Proxy: { host: '127.0.0.1', port: proxy.port },
			webSocketImpl: inert.impl
		});
		await outcome(
			dialer.connectPeer(
				randomPubkey(),
				'relay.example',
				8080,
				{ type: 'ws', url: 'ws://relay.example:8080' },
				{ timeoutMs: 300, reconnect: false }
			)
		);

		expect(inert.urls).to.deep.equal([]);
		expect(proxy.requested).to.deep.equal(['relay.example:8080']);
	});

	it('fails when the proxy is down, and dials nothing else', async function () {
		const dialer = manager({
			socks5Proxy: { host: '127.0.0.1', port: await closedPort() }
		});
		const err = await outcome(
			dialer.connectPeer(
				randomPubkey(),
				'relay.example',
				8080,
				{ type: 'ws', url: 'ws://relay.example:8080' },
				{ timeoutMs: 2000, reconnect: false }
			)
		);
		await settle(100);

		expect(err).to.be.instanceOf(Error);
		// The one thing a direct dial would have done first.
		expect(lookups.names).to.not.include('relay.example');
		expect(dialer.listPeers()).to.deep.equal([]);
	});

	it('dials directly, with the injected constructor, when no proxy is set', async function () {
		const inert = inertWebSocket();
		const dialer = manager({ webSocketImpl: inert.impl });
		await outcome(
			dialer.connectPeer(
				randomPubkey(),
				'relay.example',
				8080,
				{ type: 'ws', url: 'wss://relay.example/v1/p/abc' },
				{ timeoutMs: 200, reconnect: false }
			)
		);
		expect(inert.urls).to.deep.equal(['wss://relay.example/v1/p/abc']);
	});
});
