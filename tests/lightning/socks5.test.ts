import { expect } from 'chai';
import crypto from 'crypto';
import net from 'net';
import { Peer } from '../../src/lightning/transport/peer';
import {
	DEFAULT_TOR_PROXY,
	PeerManager,
	Socks5ProxyScope,
	isPrivateOrLoopbackHost,
	selectOutboundProxy
} from '../../src/lightning/transport/peer-manager';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

describe('SOCKS5 Proxy Support', function () {
	describe('Peer with createSocket factory', function () {
		it('Should use custom createSocket instead of net.connect', async function () {
			const localKey = crypto.randomBytes(32);
			const remoteKey = crypto.randomBytes(32);
			const remotePub = getPublicKey(remoteKey);

			let factoryCalled = false;
			let factoryHost = '';
			let factoryPort = 0;

			const createSocket = async (
				host: string,
				port: number
			): Promise<net.Socket> => {
				factoryCalled = true;
				factoryHost = host;
				factoryPort = port;
				// Fail before returning a socket — enough to verify the factory path
				throw new Error('factory was called');
			};

			const peer = new Peer({
				localPrivateKey: localKey,
				remotePublicKey: remotePub,
				host: 'test.onion',
				port: 9735,
				createSocket
			});

			try {
				await peer.connect();
			} catch {
				// Expected — factory throws
			}

			expect(factoryCalled).to.be.true;
			expect(factoryHost).to.equal('test.onion');
			expect(factoryPort).to.equal(9735);
		});

		it('Should propagate factory errors', async function () {
			const localKey = crypto.randomBytes(32);
			const remoteKey = crypto.randomBytes(32);
			const remotePub = getPublicKey(remoteKey);

			const createSocket = async (): Promise<net.Socket> => {
				throw new Error('SOCKS5 connection refused');
			};

			const peer = new Peer({
				localPrivateKey: localKey,
				remotePublicKey: remotePub,
				host: 'unreachable.onion',
				port: 9735,
				createSocket
			});

			try {
				await peer.connect();
				expect.fail('Should have thrown');
			} catch (err) {
				expect((err as Error).message).to.equal('SOCKS5 connection refused');
			}

			expect(peer.getState()).to.equal('disconnected');
		});

		it('Should reset to disconnected state after factory failure', async function () {
			const localKey = crypto.randomBytes(32);
			const remoteKey = crypto.randomBytes(32);
			const remotePub = getPublicKey(remoteKey);

			const createSocket = async (): Promise<net.Socket> => {
				throw new Error('proxy down');
			};

			const peer = new Peer({
				localPrivateKey: localKey,
				remotePublicKey: remotePub,
				host: 'test.onion',
				port: 9735,
				createSocket
			});

			try {
				await peer.connect();
			} catch {
				// expected
			}

			expect(peer.getState()).to.equal('disconnected');

			// Should be able to retry
			try {
				await peer.connect();
			} catch {
				// expected again
			}

			expect(peer.getState()).to.equal('disconnected');
		});
	});

	describe('isPrivateOrLoopbackHost', function () {
		it('Classifies loopback and localhost as private', function () {
			for (const h of ['localhost', '127.0.0.1', '127.5.6.7', '::1', '[::1]']) {
				expect(isPrivateOrLoopbackHost(h), h).to.be.true;
			}
		});

		it('Classifies RFC1918 and link-local ranges as private', function () {
			for (const h of [
				'10.0.0.1',
				'10.21.21.200',
				'172.16.0.1',
				'172.31.255.254',
				'192.168.4.20',
				'169.254.1.1',
				'0.0.0.0',
				'fe80::1',
				'fd00::1',
				'::ffff:192.168.1.2'
			]) {
				expect(isPrivateOrLoopbackHost(h), h).to.be.true;
			}
		});

		it('Classifies public addresses and hostnames as not private', function () {
			for (const h of [
				'8.8.8.8',
				'1.2.3.4',
				'84.21.100.4',
				'172.32.0.1', // just outside 172.16.0.0/12
				'172.15.0.1', // just below it
				'193.168.0.1', // not 192.168
				'ln.acinq.co',
				'clearnet.example.com',
				'abc123.onion',
				'2001:4860:4860::8888'
			]) {
				expect(isPrivateOrLoopbackHost(h), h).to.be.false;
			}
		});
	});

	describe('selectOutboundProxy', function () {
		// The one table every dial path (peer manager, watchtower) reads from
		// (issue #963): onion always rides a proxy (the configured one, else
		// Tor's default), private/loopback is always direct, and public
		// clearnet rides the configured proxy only under scope 'all'.
		const proxy = { host: '10.21.21.11', port: 9050 };
		const cases: Array<{
			host: string;
			scope: Socks5ProxyScope;
			proxy: { host: string; port: number } | undefined;
			expected: { host: string; port: number } | undefined;
		}> = [
			// .onion
			{ host: 'abc123.onion', scope: 'all', proxy, expected: proxy },
			{ host: 'abc123.onion', scope: 'onion', proxy, expected: proxy },
			{
				host: 'abc123.onion',
				scope: 'all',
				proxy: undefined,
				expected: DEFAULT_TOR_PROXY
			},
			{
				host: 'ABC123.ONION',
				scope: 'onion',
				proxy: undefined,
				expected: DEFAULT_TOR_PROXY
			},
			// private / loopback
			{ host: '127.0.0.1', scope: 'all', proxy, expected: undefined },
			{ host: '192.168.4.20', scope: 'onion', proxy, expected: undefined },
			{
				host: 'localhost',
				scope: 'all',
				proxy: undefined,
				expected: undefined
			},
			{ host: '[::1]', scope: 'onion', proxy: undefined, expected: undefined },
			// public clearnet
			{ host: '203.0.113.1', scope: 'all', proxy, expected: proxy },
			{ host: '203.0.113.1', scope: 'onion', proxy, expected: undefined },
			{ host: 'ln.acinq.co', scope: 'all', proxy, expected: proxy },
			{ host: 'ln.acinq.co', scope: 'onion', proxy, expected: undefined },
			{
				host: '203.0.113.1',
				scope: 'all',
				proxy: undefined,
				expected: undefined
			},
			{
				host: 'ln.acinq.co',
				scope: 'onion',
				proxy: undefined,
				expected: undefined
			}
		];

		for (const c of cases) {
			it(`${c.host} with proxy ${c.proxy ? 'set' : 'unset'} under scope ${
				c.scope
			} -> ${
				c.expected ? `${c.expected.host}:${c.expected.port}` : 'direct'
			}`, function () {
				expect(selectOutboundProxy(c.host, c.proxy, c.scope)).to.deep.equal(
					c.expected
				);
			});
		}

		it('defaults the scope to all, which is the pre-#963 behaviour', function () {
			expect(selectOutboundProxy('203.0.113.1', proxy)).to.deep.equal(proxy);
			expect(selectOutboundProxy('abc.onion', undefined)).to.deep.equal(
				DEFAULT_TOR_PROXY
			);
		});
	});

	describe('PeerManager with socks5ProxyScope onion', function () {
		// Hybrid mode (issue #963): the proxy is for .onion peers only. Same
		// flag-server pattern as the scope 'all' cases below: a TCP server that
		// records any contact stands in for the proxy.
		let proxy: net.Server;
		let proxyPort = 0;
		let proxyContacted = false;

		beforeEach(async function () {
			proxyContacted = false;
			proxy = net.createServer((s) => {
				proxyContacted = true;
				s.destroy();
			});
			await new Promise<void>((resolve) =>
				proxy.listen(0, '127.0.0.1', resolve)
			);
			proxyPort = (proxy.address() as net.AddressInfo).port;
		});

		afterEach(async function () {
			await new Promise<void>((resolve) => proxy.close(() => resolve()));
		});

		const manager = (): PeerManager =>
			new PeerManager({
				localPrivateKey: crypto.randomBytes(32),
				socks5Proxy: { host: '127.0.0.1', port: proxyPort },
				socks5ProxyScope: 'onion',
				socks5TimeoutMs: 500
			});

		it('Should dial public clearnet peers directly, never touching the proxy', async function () {
			this.timeout(5000);
			const pm = manager();
			// 203.0.113.1 is TEST-NET-3 (RFC 5737), never routed: the direct
			// dial either fails at once or sits in SYN until the 200 ms dial
			// bound. Either way the proxy must see nothing, which is what
			// distinguishes this from the scope 'all' case that proxies it.
			const dial = pm
				.connectPeer(
					getPublicKey(crypto.randomBytes(32)).toString('hex'),
					'203.0.113.1',
					9735,
					undefined,
					{ timeoutMs: 200, reconnect: false }
				)
				.catch(() => undefined);
			await new Promise((r) => setTimeout(r, 300));

			expect(proxyContacted, 'proxy should not be contacted for a public host')
				.to.be.false;

			pm.destroy();
			await Promise.race([dial, new Promise((r) => setTimeout(r, 1000))]);
		});

		it('Should still route .onion peers through the proxy', async function () {
			this.timeout(5000);
			const pm = manager();
			try {
				await pm.connectPeer(
					getPublicKey(crypto.randomBytes(32)).toString('hex'),
					'abc123.onion',
					9735
				);
			} catch {
				// The flag server speaks no SOCKS, so negotiation fails; the
				// point is that the dial was aimed at the proxy at all.
			}

			expect(proxyContacted, 'proxy should be contacted for an onion host').to
				.be.true;

			pm.destroy();
		});

		it('Should still dial private peers directly', async function () {
			this.timeout(5000);
			const pm = manager();
			try {
				// Port 1 is closed, so a direct dial fails fast with ECONNREFUSED.
				await pm.connectPeer(
					getPublicKey(crypto.randomBytes(32)).toString('hex'),
					'127.0.0.1',
					1
				);
				expect.fail('Should have thrown');
			} catch (err) {
				expect((err as Error).message).to.include('ECONNREFUSED');
			}

			expect(proxyContacted, 'proxy should not be contacted for a private host')
				.to.be.false;

			pm.destroy();
		});
	});

	describe('PeerManager with socks5Proxy', function () {
		it('Should use explicit socks5Proxy for all connections', async function () {
			// Fail fast and deterministically: this connects to a (normally absent)
			// proxy on 127.0.0.1:9050. If that port is occupied/filtered in the
			// environment, the SOCKS negotiation would otherwise hang past mocha's
			// default 2s timeout. A short socks5TimeoutMs + generous test timeout
			// makes the outcome (an error) deterministic regardless of the host.
			this.timeout(5000);
			const localKey = crypto.randomBytes(32);
			const remoteKey = crypto.randomBytes(32);
			const remotePub = getPublicKey(remoteKey);
			const remotePubHex = remotePub.toString('hex');

			const pm = new PeerManager({
				localPrivateKey: localKey,
				socks5Proxy: { host: '127.0.0.1', port: 9050 },
				socks5TimeoutMs: 500
			});

			// connectPeer will fail because there's no actual SOCKS5 proxy,
			// but the error should come from the SOCKS5 connection attempt
			try {
				await pm.connectPeer(remotePubHex, 'clearnet.example.com', 9735);
				expect.fail('Should have thrown');
			} catch (err) {
				// SocksClient tries 127.0.0.1:9050 — ECONNREFUSED
				expect(err).to.be.an('error');
			}

			pm.destroy();
		});

		it('Should dial private/LAN peers directly, bypassing the proxy', async function () {
			// A configured proxy must NOT be used for a private address: Tor rejects
			// those, so a LAN channel peer would otherwise be unreachable the moment
			// Tor is enabled. Prove it by pointing the proxy at a server that flags
			// any contact, then dialing a private target and asserting it was never
			// touched (the dial goes straight to the dead target port instead).
			this.timeout(5000);
			let proxyContacted = false;
			const proxy = net.createServer((s) => {
				proxyContacted = true;
				s.destroy();
			});
			await new Promise<void>((resolve) =>
				proxy.listen(0, '127.0.0.1', resolve)
			);
			const proxyPort = (proxy.address() as net.AddressInfo).port;

			const localKey = crypto.randomBytes(32);
			const remotePub = getPublicKey(crypto.randomBytes(32));
			const pm = new PeerManager({
				localPrivateKey: localKey,
				socks5Proxy: { host: '127.0.0.1', port: proxyPort },
				socks5TimeoutMs: 500
			});

			try {
				// Port 1 is closed, so a direct dial fails fast with ECONNREFUSED.
				await pm.connectPeer(remotePub.toString('hex'), '127.0.0.1', 1);
				expect.fail('Should have thrown');
			} catch (err) {
				expect((err as Error).message).to.include('ECONNREFUSED');
			}

			expect(proxyContacted, 'proxy should not be contacted for a private host')
				.to.be.false;

			pm.destroy();
			await new Promise<void>((resolve) => proxy.close(() => resolve()));
		});

		it('Should still route public clearnet peers through the proxy', async function () {
			// The privacy path stays intact: a public address with a proxy set goes
			// through it. Same flag server, but this time we expect it contacted.
			this.timeout(5000);
			let proxyContacted = false;
			const proxy = net.createServer((s) => {
				proxyContacted = true;
				s.destroy();
			});
			await new Promise<void>((resolve) =>
				proxy.listen(0, '127.0.0.1', resolve)
			);
			const proxyPort = (proxy.address() as net.AddressInfo).port;

			const localKey = crypto.randomBytes(32);
			const remotePub = getPublicKey(crypto.randomBytes(32));
			const pm = new PeerManager({
				localPrivateKey: localKey,
				socks5Proxy: { host: '127.0.0.1', port: proxyPort },
				socks5TimeoutMs: 500
			});

			try {
				await pm.connectPeer(remotePub.toString('hex'), '93.184.216.34', 9735);
			} catch {
				// The flag server speaks no SOCKS, so negotiation fails, which is fine.
				// The point is that the dial was aimed at the proxy at all.
			}

			expect(proxyContacted, 'proxy should be contacted for a public host').to
				.be.true;

			pm.destroy();
			await new Promise<void>((resolve) => proxy.close(() => resolve()));
		});

		it('Should auto-detect .onion and route through default Tor proxy', async function () {
			this.timeout(5000);
			const localKey = crypto.randomBytes(32);
			const remoteKey = crypto.randomBytes(32);
			const remotePub = getPublicKey(remoteKey);
			const remotePubHex = remotePub.toString('hex');

			const pm = new PeerManager({
				localPrivateKey: localKey,
				// no socks5Proxy — should auto-detect .onion → default Tor proxy.
				// Short timeout so the (absent) proxy attempt fails fast.
				socks5TimeoutMs: 500
			});

			try {
				await pm.connectPeer(remotePubHex, 'abc123.onion', 9735);
				expect.fail('Should have thrown');
			} catch (err) {
				// Should attempt SOCKS5 on 127.0.0.1:9050 (ECONNREFUSED),
				// NOT a DNS resolution failure for .onion
				const msg = (err as Error).message;
				expect(msg).to.not.include('ENOTFOUND');
				expect(msg).to.not.include('getaddrinfo');
			}

			pm.destroy();
		});

		it('Should use direct TCP for non-.onion when no socks5Proxy', async function () {
			this.timeout(5000);
			const localKey = crypto.randomBytes(32);
			const remoteKey = crypto.randomBytes(32);
			const remotePub = getPublicKey(remoteKey);
			const remotePubHex = remotePub.toString('hex');

			const pm = new PeerManager({
				localPrivateKey: localKey
				// no socks5Proxy
			});

			try {
				await pm.connectPeer(remotePubHex, '127.0.0.1', 1);
			} catch (err) {
				// Direct connection error (ECONNREFUSED on 127.0.0.1:1)
				expect((err as Error).message).to.include('ECONNREFUSED');
			}

			pm.destroy();
		});
	});

	describe('SOCKS5 mock server integration', function () {
		it('Should tunnel through a mock SOCKS5 proxy to reach target', async function () {
			this.timeout(5000);

			// Set up a target TCP server (simulates the Lightning peer's TCP endpoint)
			const targetServer = net.createServer((socket) => {
				// Echo back whatever is received
				socket.on('data', (data) => socket.write(data));
			});

			await new Promise<void>((resolve) => {
				targetServer.listen(0, '127.0.0.1', resolve);
			});
			const targetPort = (targetServer.address() as net.AddressInfo).port;

			// Set up a minimal SOCKS5 proxy server
			const proxyServer = net.createServer((clientSocket) => {
				// SOCKS5 greeting: client sends version + auth methods
				clientSocket.once('data', (greeting) => {
					// Verify SOCKS5 greeting
					expect(greeting[0]).to.equal(0x05); // version
					// Reply: no auth required
					clientSocket.write(Buffer.from([0x05, 0x00]));

					// SOCKS5 connect request
					clientSocket.once('data', (request) => {
						expect(request[0]).to.equal(0x05); // version
						expect(request[1]).to.equal(0x01); // connect command

						// Parse destination address
						const addrType = request[3];
						let destHost: string;
						let addrEnd: number;

						if (addrType === 0x01) {
							// IPv4
							destHost = `${request[4]}.${request[5]}.${request[6]}.${request[7]}`;
							addrEnd = 8;
						} else if (addrType === 0x03) {
							// Domain
							const domainLen = request[4];
							destHost = request.subarray(5, 5 + domainLen).toString();
							addrEnd = 5 + domainLen;
						} else {
							clientSocket.destroy();
							return;
						}
						const destPort = request.readUInt16BE(addrEnd);

						// Connect to the actual target
						const targetSocket = net.connect(
							destPort,
							destHost === 'localhost' ? '127.0.0.1' : destHost
						);

						targetSocket.once('connect', () => {
							// Send success reply
							const reply = Buffer.alloc(10);
							reply[0] = 0x05; // version
							reply[1] = 0x00; // success
							reply[2] = 0x00; // reserved
							reply[3] = 0x01; // IPv4
							// bound address 0.0.0.0:0
							clientSocket.write(reply);

							// Pipe bidirectionally
							clientSocket.pipe(targetSocket);
							targetSocket.pipe(clientSocket);
						});

						targetSocket.once('error', () => {
							clientSocket.destroy();
						});
					});
				});
			});

			await new Promise<void>((resolve) => {
				proxyServer.listen(0, '127.0.0.1', resolve);
			});
			const proxyPort = (proxyServer.address() as net.AddressInfo).port;

			// Now use our Peer's createSocket with SocksClient to tunnel through
			const { SocksClient } = await import('socks');

			const createSocket = async (
				host: string,
				port: number
			): Promise<net.Socket> => {
				const { socket } = await SocksClient.createConnection({
					proxy: { host: '127.0.0.1', port: proxyPort, type: 5 },
					command: 'connect',
					destination: { host, port }
				});
				return socket;
			};

			// Create the tunneled socket
			const socket = await createSocket('127.0.0.1', targetPort);

			// Verify data flows through the tunnel
			const echoData = Buffer.from('hello through socks5');
			const received = await new Promise<Buffer>((resolve) => {
				socket.once('data', resolve);
				socket.write(echoData);
			});

			expect(received.equals(echoData)).to.be.true;

			// Cleanup
			socket.destroy();
			await new Promise<void>((resolve) => targetServer.close(() => resolve()));
			await new Promise<void>((resolve) => proxyServer.close(() => resolve()));
		});
	});
});
