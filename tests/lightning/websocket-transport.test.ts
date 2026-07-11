/**
 * WebSocket peer transport: offline unit tests.
 *
 * - injectable WebSocket constructor resolution
 * - ws:// URL building/parsing + peer URI parsing (TCP forms unchanged)
 * - WS client transport semantics (data, close, error, backpressure mapping)
 * - in-repo RFC 6455 server: upgrade handshake, masking enforcement,
 *   fragmentation, ping auto-reply, close handshake, oversize frames,
 *   non-upgrade HTTP requests
 * - IDuplexTransport conformance for TCP (net.Socket) and WS loopbacks
 * - BOLT 8 Noise handshake + init between two Peers over WS
 * - PeerManager listenWebSocket + connectPeer({type:'ws'})
 * - two in-process LightningNodes: full handshake + channel to NORMAL +
 *   a payment over our WS server/client pair
 */

import { expect } from 'chai';
import crypto from 'crypto';
import net from 'net';
import {
	resolveWebSocketConstructor,
	buildWebSocketUrl,
	parseWebSocketUrl,
	connectWebSocket,
	WebSocketTransport,
	IWebSocketLike,
	WebSocketConstructor
} from '../../src/lightning/transport/websocket';
import {
	WebSocketServer,
	WebSocketServerTransport
} from '../../src/lightning/transport/websocket-server';
import {
	encodeWsFrame,
	WsOpcode,
	WsCloseCode,
	decodeWsClosePayload,
	WsFrameParser
} from '../../src/lightning/transport/websocket-frame';
import { parsePeerUri } from '../../src/lightning/transport/peer-uri';
import { NodeWebSocket } from '../../src/lightning/transport/websocket-node-client';
import { IDuplexTransport } from '../../src/lightning/transport/duplex-transport';
import { Peer } from '../../src/lightning/transport/peer';
import { PeerManager } from '../../src/lightning/transport/peer-manager';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	BITCOIN_CHAIN_HASH
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { Network } from '../../src/lightning/invoice/types';
import {
	encodeShortChannelId,
	IChannelAnnouncementMessage,
	IChannelUpdateMessage
} from '../../src/lightning/gossip/types';
import { PaymentStatus } from '../../src/lightning/node/types';

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitFor(
	cond: () => boolean,
	timeoutMs = 10_000,
	label = 'condition'
): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (!cond()) {
		if (Date.now() > deadline) {
			throw new Error(`Timed out waiting for ${label}`);
		}
		await sleep(25);
	}
}

/** Start a WS server and return it with its bound port. */
async function startWsServer(): Promise<{
	server: WebSocketServer;
	port: number;
}> {
	const server = new WebSocketServer();
	await server.listen(0, '127.0.0.1');
	const addr = server.address();
	if (!addr || typeof addr !== 'object') throw new Error('no address');
	return { server, port: addr.port };
}

/** Perform a raw WS upgrade over a TCP socket (for crafted-frame tests). */
function rawUpgrade(
	port: number
): Promise<{ socket: net.Socket; response: string }> {
	return new Promise((resolve, reject) => {
		const socket = net.connect(port, '127.0.0.1', () => {
			const key = crypto.randomBytes(16).toString('base64');
			socket.write(
				'GET / HTTP/1.1\r\n' +
					'Host: 127.0.0.1\r\n' +
					'Upgrade: websocket\r\n' +
					'Connection: Upgrade\r\n' +
					`Sec-WebSocket-Key: ${key}\r\n` +
					'Sec-WebSocket-Version: 13\r\n' +
					'\r\n'
			);
		});
		socket.once('error', reject);
		let buf = '';
		const onData = (d: Buffer): void => {
			buf += d.toString('latin1');
			if (buf.includes('\r\n\r\n')) {
				socket.removeListener('data', onData);
				resolve({ socket, response: buf });
			}
		};
		socket.on('data', onData);
	});
}

describe('WebSocket transport (offline)', function () {
	this.timeout(30_000);

	// ─── Injectable constructor resolution ────────────────────

	describe('resolveWebSocketConstructor', function () {
		it('prefers an injected implementation', function () {
			class Fake {}
			const resolved = resolveWebSocketConstructor(
				Fake as unknown as WebSocketConstructor
			);
			expect(resolved).to.equal(Fake);
		});

		it('falls back to globalThis.WebSocket when available', function () {
			const g = globalThis as { WebSocket?: unknown };
			expect(typeof g.WebSocket).to.equal('function'); // Node >= 22
			expect(resolveWebSocketConstructor()).to.equal(g.WebSocket);
		});

		it('throws a descriptive error when nothing is available', function () {
			const g = globalThis as { WebSocket?: unknown };
			const saved = g.WebSocket;
			try {
				delete g.WebSocket;
				expect(() => resolveWebSocketConstructor()).to.throw(
					/No WebSocket implementation/
				);
			} finally {
				g.WebSocket = saved;
			}
		});
	});

	// ─── URL / URI parsing ─────────────────────────────────────

	describe('URL and peer URI parsing', function () {
		it('builds ws:// URLs (bracketing IPv6)', function () {
			expect(buildWebSocketUrl('example.com', 9735)).to.equal(
				'ws://example.com:9735'
			);
			expect(buildWebSocketUrl('::1', 9735)).to.equal('ws://[::1]:9735');
		});

		it('parses ws:// and wss:// URLs with default ports', function () {
			expect(parseWebSocketUrl('ws://a.b:19847')).to.deep.equal({
				host: 'a.b',
				port: 19847,
				secure: false
			});
			expect(parseWebSocketUrl('wss://a.b/path')).to.deep.equal({
				host: 'a.b',
				port: 443,
				secure: true
			});
			expect(parseWebSocketUrl('ws://a.b')).to.deep.equal({
				host: 'a.b',
				port: 80,
				secure: false
			});
			expect(parseWebSocketUrl('ws://[::1]:9736').host).to.equal('::1');
		});

		it('rejects non-ws URLs', function () {
			expect(() => parseWebSocketUrl('http://a.b')).to.throw(/ws:\/\//);
			expect(() => parseWebSocketUrl('not a url')).to.throw(/Invalid/);
		});

		it('parses plain TCP peer URIs exactly as before', function () {
			const pk = '02'.repeat(33);
			const parsed = parsePeerUri(`${pk}@127.0.0.1:9735`);
			expect(parsed.pubkey).to.equal(pk);
			expect(parsed.host).to.equal('127.0.0.1');
			expect(parsed.port).to.equal(9735);
			expect(parsed.transport).to.equal(undefined);
		});

		it('parses bracketed IPv6 TCP peer URIs', function () {
			const pk = '02'.repeat(33);
			const parsed = parsePeerUri(`${pk}@[::1]:9735`);
			expect(parsed.host).to.equal('::1');
			expect(parsed.port).to.equal(9735);
		});

		it('parses ws:// and wss:// peer URIs', function () {
			const pk = '03'.repeat(33);
			const ws = parsePeerUri(`${pk}@ws://node.example:19847`);
			expect(ws.transport).to.deep.equal({
				type: 'ws',
				url: 'ws://node.example:19847'
			});
			expect(ws.host).to.equal('node.example');
			expect(ws.port).to.equal(19847);

			const wss = parsePeerUri(`${pk}@wss://node.example/ws`);
			expect(wss.port).to.equal(443);
			expect(wss.transport?.type).to.equal('ws');
		});

		it('rejects malformed peer URIs', function () {
			expect(() => parsePeerUri('nope')).to.throw(/missing @/);
			expect(() => parsePeerUri('zz@1.2.3.4:9735')).to.throw(/pubkey/);
			expect(() => parsePeerUri(`${'02'.repeat(33)}@1.2.3.4`)).to.throw(/port/);
			expect(() => parsePeerUri(`${'02'.repeat(33)}@1.2.3.4:99999`)).to.throw(
				/host\/port/
			);
		});
	});

	// ─── Client transport unit behavior (fake ws) ──────────────

	describe('WebSocketTransport (fake WebSocket)', function () {
		class FakeWs implements IWebSocketLike {
			binaryType = 'arraybuffer';
			bufferedAmount = 0;
			readyState = 1;
			sent: Uint8Array[] = [];
			closed: Array<number | undefined> = [];
			onopen: ((ev?: unknown) => void) | null = null;
			onmessage: ((ev: { data: unknown }) => void) | null = null;
			onclose:
				| ((ev?: {
						code?: number;
						reason?: string;
						wasClean?: boolean;
				  }) => void)
				| null = null;
			onerror: ((ev?: unknown) => void) | null = null;

			send(data: Uint8Array): void {
				this.sent.push(data);
				this.bufferedAmount += data.byteLength;
			}

			close(code?: number): void {
				this.closed.push(code);
			}
		}

		it('maps writableLength to bufferedAmount (backpressure)', function () {
			const ws = new FakeWs();
			const t = new WebSocketTransport(ws);
			expect(t.writableLength).to.equal(0);
			t.write(Buffer.alloc(1000));
			expect(t.writableLength).to.equal(1000);
			t.destroy();
		});

		it('invokes the write callback asynchronously', async function () {
			const ws = new FakeWs();
			const t = new WebSocketTransport(ws);
			let called = false;
			const returned = t.write(Buffer.from('abc'), () => {
				called = true;
			});
			expect(returned).to.equal(true);
			expect(called).to.equal(false); // async like net.Socket
			await sleep(1);
			expect(called).to.equal(true);
			t.destroy();
		});

		it('emits Buffer data for ArrayBuffer and view messages', function () {
			const ws = new FakeWs();
			const t = new WebSocketTransport(ws);
			const chunks: Buffer[] = [];
			t.on('data', (d: Buffer) => chunks.push(d));
			const bytes = crypto.randomBytes(20);
			ws.onmessage!({
				data: bytes.buffer.slice(
					bytes.byteOffset,
					bytes.byteOffset + bytes.byteLength
				)
			});
			ws.onmessage!({ data: new Uint8Array([1, 2, 3]) });
			expect(chunks.length).to.equal(2);
			expect(chunks[0].equals(bytes)).to.equal(true);
			expect([...chunks[1]]).to.deep.equal([1, 2, 3]);
			t.destroy();
		});

		it('destroys with an error on text messages (BOLT 8 is binary-only)', function () {
			const ws = new FakeWs();
			const t = new WebSocketTransport(ws);
			const errors: Error[] = [];
			let closed = false;
			let closeHadError = false;
			t.on('error', (e: Error) => errors.push(e));
			t.on('close', (hadError: boolean) => {
				closed = true;
				closeHadError = hadError;
			});
			ws.onmessage!({ data: 'text frame' });
			expect(errors.length).to.equal(1);
			expect(errors[0].message).to.match(/non-binary/);
			expect(closed).to.equal(true);
			expect(closeHadError).to.equal(true);
			expect(ws.closed.length).to.equal(1);
		});

		it('emits close(false) on remote close, exactly once', function () {
			const ws = new FakeWs();
			const t = new WebSocketTransport(ws);
			let closes = 0;
			let hadError = true;
			t.on('close', (e: boolean) => {
				closes++;
				hadError = e;
			});
			ws.onclose!({ code: 1000 });
			t.destroy(); // second teardown is a no-op
			expect(closes).to.equal(1);
			expect(hadError).to.equal(false);
		});

		it('destroy(err) emits error then close(true) and closes the ws', function () {
			const ws = new FakeWs();
			const t = new WebSocketTransport(ws);
			const events: string[] = [];
			t.on('error', () => events.push('error'));
			t.on('close', (hadError: boolean) => events.push(`close:${hadError}`));
			t.destroy(new Error('boom'));
			expect(events).to.deep.equal(['error', 'close:true']);
			expect(ws.closed).to.deep.equal([1000]);
		});

		it('setTimeout arms a deadline that emits timeout; 0 disarms', async function () {
			const ws = new FakeWs();
			const t = new WebSocketTransport(ws);
			let fired = 0;
			t.setTimeout(30, () => fired++);
			await sleep(80);
			expect(fired).to.equal(1);
			t.setTimeout(30);
			t.setTimeout(0); // disarm
			await sleep(80);
			expect(fired).to.equal(1);
			t.destroy();
		});

		it('write after destroy fails via callback', async function () {
			const ws = new FakeWs();
			const t = new WebSocketTransport(ws);
			t.destroy();
			let err: Error | undefined;
			t.write(Buffer.alloc(1), (e) => {
				err = e;
			});
			await sleep(1);
			expect(err).to.be.instanceOf(Error);
		});
	});

	// ─── In-repo server: upgrade + crafted frames ───────────────

	describe('WebSocketServer (RFC 6455)', function () {
		it('completes the upgrade with the correct Sec-WebSocket-Accept', async function () {
			const { server, port } = await startWsServer();
			try {
				const key = 'dGhlIHNhbXBsZSBub25jZQ==';
				const response = await new Promise<string>((resolve, reject) => {
					const socket = net.connect(port, '127.0.0.1', () => {
						socket.write(
							'GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n' +
								'Connection: Upgrade\r\n' +
								`Sec-WebSocket-Key: ${key}\r\n` +
								'Sec-WebSocket-Version: 13\r\n\r\n'
						);
					});
					socket.once('error', reject);
					socket.once('data', (d) => {
						resolve(d.toString());
						socket.destroy();
					});
				});
				expect(response).to.include('101 Switching Protocols');
				expect(response).to.include(
					'Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo='
				);
			} finally {
				server.close();
			}
		});

		it('rejects plain HTTP requests with 426', async function () {
			const { server, port } = await startWsServer();
			try {
				const response = await new Promise<string>((resolve, reject) => {
					const socket = net.connect(port, '127.0.0.1', () => {
						socket.write('GET / HTTP/1.1\r\nHost: x\r\n\r\n');
					});
					socket.once('error', reject);
					let buf = '';
					socket.on('data', (d) => {
						buf += d.toString();
						if (buf.includes('\r\n\r\n')) {
							resolve(buf);
							socket.destroy();
						}
					});
				});
				expect(response).to.include('426');
			} finally {
				server.close();
			}
		});

		it('rejects upgrades with a bad Sec-WebSocket-Version', async function () {
			const { server, port } = await startWsServer();
			try {
				const response = await new Promise<string>((resolve, reject) => {
					const socket = net.connect(port, '127.0.0.1', () => {
						socket.write(
							'GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n' +
								'Connection: Upgrade\r\n' +
								`Sec-WebSocket-Key: ${crypto
									.randomBytes(16)
									.toString('base64')}\r\n` +
								'Sec-WebSocket-Version: 8\r\n\r\n'
						);
					});
					socket.once('error', reject);
					socket.once('data', (d) => {
						resolve(d.toString());
						socket.destroy();
					});
				});
				expect(response).to.include('426');
				expect(response).to.include('Sec-WebSocket-Version: 13');
			} finally {
				server.close();
			}
		});

		it('streams masked binary frames (including fragmented) as data', async function () {
			const { server, port } = await startWsServer();
			try {
				const received: Buffer[] = [];
				server.on('connection', (t: WebSocketServerTransport) => {
					t.on('data', (d: Buffer) => received.push(d));
					t.on('error', () => {});
				});
				const { socket } = await rawUpgrade(port);
				const p1 = crypto.randomBytes(10);
				const p2 = crypto.randomBytes(200); // 16-bit length path
				const p3a = Buffer.from('frag-one|');
				const p3b = Buffer.from('frag-two');
				socket.write(
					Buffer.concat([
						encodeWsFrame({
							opcode: WsOpcode.BINARY,
							payload: p1,
							maskKey: crypto.randomBytes(4)
						}),
						encodeWsFrame({
							opcode: WsOpcode.BINARY,
							payload: p2,
							maskKey: crypto.randomBytes(4)
						}),
						encodeWsFrame({
							opcode: WsOpcode.BINARY,
							payload: p3a,
							fin: false,
							maskKey: crypto.randomBytes(4)
						}),
						encodeWsFrame({
							opcode: WsOpcode.CONTINUATION,
							payload: p3b,
							fin: true,
							maskKey: crypto.randomBytes(4)
						})
					])
				);
				await waitFor(
					() => Buffer.concat(received).length >= 10 + 200 + 17,
					5000,
					'all payload bytes'
				);
				expect(
					Buffer.concat(received).equals(Buffer.concat([p1, p2, p3a, p3b]))
				).to.equal(true);
				socket.destroy();
			} finally {
				server.close();
			}
		});

		it('closes 1002 on unmasked client frames', async function () {
			const { server, port } = await startWsServer();
			try {
				server.on('connection', (t: WebSocketServerTransport) => {
					t.on('error', () => {});
				});
				const { socket } = await rawUpgrade(port);
				const closeInfo = await new Promise<{ code: number }>(
					(resolve, reject) => {
						const parser = new WsFrameParser({ requireMasked: false });
						socket.on('data', (d) => {
							for (const f of parser.push(d)) {
								if (f.opcode === WsOpcode.CLOSE) {
									resolve(decodeWsClosePayload(f.payload));
								}
							}
						});
						socket.once('error', reject);
						// UNMASKED client frame — protocol violation
						socket.write(
							encodeWsFrame({
								opcode: WsOpcode.BINARY,
								payload: Buffer.alloc(3)
							})
						);
					}
				);
				expect(closeInfo.code).to.equal(WsCloseCode.PROTOCOL_ERROR);
				socket.destroy();
			} finally {
				server.close();
			}
		});

		it('closes 1003 on text frames', async function () {
			const { server, port } = await startWsServer();
			try {
				server.on('connection', (t: WebSocketServerTransport) => {
					t.on('error', () => {});
				});
				const { socket } = await rawUpgrade(port);
				const closeInfo = await new Promise<{ code: number }>(
					(resolve, reject) => {
						const parser = new WsFrameParser({ requireMasked: false });
						socket.on('data', (d) => {
							for (const f of parser.push(d)) {
								if (f.opcode === WsOpcode.CLOSE) {
									resolve(decodeWsClosePayload(f.payload));
								}
							}
						});
						socket.once('error', reject);
						socket.write(
							encodeWsFrame({
								opcode: WsOpcode.TEXT,
								payload: Buffer.from('hello'),
								maskKey: crypto.randomBytes(4)
							})
						);
					}
				);
				expect(closeInfo.code).to.equal(WsCloseCode.UNSUPPORTED_DATA);
				socket.destroy();
			} finally {
				server.close();
			}
		});

		it('closes 1002 on a continuation without a fragmented message', async function () {
			const { server, port } = await startWsServer();
			try {
				server.on('connection', (t: WebSocketServerTransport) => {
					t.on('error', () => {});
				});
				const { socket } = await rawUpgrade(port);
				const closeInfo = await new Promise<{ code: number }>(
					(resolve, reject) => {
						const parser = new WsFrameParser({ requireMasked: false });
						socket.on('data', (d) => {
							for (const f of parser.push(d)) {
								if (f.opcode === WsOpcode.CLOSE) {
									resolve(decodeWsClosePayload(f.payload));
								}
							}
						});
						socket.once('error', reject);
						socket.write(
							encodeWsFrame({
								opcode: WsOpcode.CONTINUATION,
								payload: Buffer.alloc(2),
								maskKey: crypto.randomBytes(4)
							})
						);
					}
				);
				expect(closeInfo.code).to.equal(WsCloseCode.PROTOCOL_ERROR);
				socket.destroy();
			} finally {
				server.close();
			}
		});

		it('auto-replies to pings with matching pong payloads', async function () {
			const { server, port } = await startWsServer();
			try {
				server.on('connection', (t: WebSocketServerTransport) => {
					t.on('error', () => {});
				});
				const { socket } = await rawUpgrade(port);
				const body = Buffer.from('are-you-there');
				const pong = await new Promise<Buffer>((resolve, reject) => {
					const parser = new WsFrameParser({ requireMasked: false });
					socket.on('data', (d) => {
						for (const f of parser.push(d)) {
							if (f.opcode === WsOpcode.PONG) resolve(f.payload);
						}
					});
					socket.once('error', reject);
					socket.write(
						encodeWsFrame({
							opcode: WsOpcode.PING,
							payload: body,
							maskKey: crypto.randomBytes(4)
						})
					);
				});
				expect(pong.equals(body)).to.equal(true);
				socket.destroy();
			} finally {
				server.close();
			}
		});

		it('echoes the close handshake and drops the connection', async function () {
			const { server, port } = await startWsServer();
			try {
				let transportClosed = false;
				server.on('connection', (t: WebSocketServerTransport) => {
					t.on('error', () => {});
					t.on('close', () => {
						transportClosed = true;
					});
				});
				const { socket } = await rawUpgrade(port);
				const gotClose = new Promise<{ code: number }>((resolve, reject) => {
					const parser = new WsFrameParser({ requireMasked: false });
					socket.on('data', (d) => {
						for (const f of parser.push(d)) {
							if (f.opcode === WsOpcode.CLOSE) {
								resolve(decodeWsClosePayload(f.payload));
							}
						}
					});
					socket.once('error', reject);
				});
				socket.write(
					encodeWsFrame({
						opcode: WsOpcode.CLOSE,
						payload: Buffer.from([0x03, 0xe8]), // 1000
						maskKey: crypto.randomBytes(4)
					})
				);
				const closeInfo = await gotClose;
				expect(closeInfo.code).to.equal(WsCloseCode.NORMAL);
				await waitFor(() => transportClosed, 5000, 'transport close');
				socket.destroy();
			} finally {
				server.close();
			}
		});

		it('closes 1009 when a frame exceeds the payload cap', async function () {
			const server = new WebSocketServer({ maxFramePayloadBytes: 1024 });
			await server.listen(0, '127.0.0.1');
			const addr = server.address();
			const port = (addr as net.AddressInfo).port;
			try {
				server.on('connection', (t: WebSocketServerTransport) => {
					t.on('error', () => {});
				});
				const { socket } = await rawUpgrade(port);
				const closeInfo = await new Promise<{ code: number }>(
					(resolve, reject) => {
						const parser = new WsFrameParser({ requireMasked: false });
						socket.on('data', (d) => {
							for (const f of parser.push(d)) {
								if (f.opcode === WsOpcode.CLOSE) {
									resolve(decodeWsClosePayload(f.payload));
								}
							}
						});
						socket.once('error', reject);
						socket.write(
							encodeWsFrame({
								opcode: WsOpcode.BINARY,
								payload: crypto.randomBytes(2048),
								maskKey: crypto.randomBytes(4)
							})
						);
					}
				);
				expect(closeInfo.code).to.equal(WsCloseCode.MESSAGE_TOO_BIG);
				socket.destroy();
			} finally {
				server.close();
			}
		});
	});

	// ─── In-repo Node WS client ─────────────────────────────────

	describe('NodeWebSocket (in-repo Node client)', function () {
		it('sends RFC-cased handshake headers (CLN requires exact casing)', async function () {
			const captured = await new Promise<string>((resolve, reject) => {
				const srv = net.createServer((socket) => {
					socket.once('data', (d) => {
						resolve(d.toString('latin1'));
						socket.destroy();
						srv.close();
					});
				});
				srv.once('error', reject);
				srv.listen(0, '127.0.0.1', () => {
					const port = (srv.address() as net.AddressInfo).port;
					const ws = new NodeWebSocket(`ws://127.0.0.1:${port}`);
					ws.onerror = (): void => {};
					ws.onclose = (): void => {};
				});
			});
			// CLN's handshake parser string-matches these EXACT spellings
			expect(captured).to.include('Connection: Upgrade\r\n');
			expect(captured).to.include('Upgrade: websocket\r\n');
			expect(captured).to.include('Sec-WebSocket-Version: 13\r\n');
			expect(captured).to.match(/Sec-WebSocket-Key: [A-Za-z0-9+/=]+\r\n/);
		});

		it('rejects a bad Sec-WebSocket-Accept', async function () {
			const result = await new Promise<string>((resolve, reject) => {
				const srv = net.createServer((socket) => {
					socket.once('data', () => {
						socket.write(
							'HTTP/1.1 101 Switching Protocols\r\n' +
								'Upgrade: websocket\r\n' +
								'Connection: Upgrade\r\n' +
								'Sec-WebSocket-Accept: bm90LXRoZS1yaWdodC1hY2NlcHQ=\r\n\r\n'
						);
					});
				});
				srv.once('error', reject);
				srv.listen(0, '127.0.0.1', () => {
					const port = (srv.address() as net.AddressInfo).port;
					const ws = new NodeWebSocket(`ws://127.0.0.1:${port}`);
					ws.onopen = (): void => resolve('open');
					ws.onerror = (e): void => resolve((e as Error).message || 'error');
					ws.onclose = (): void => {};
					setTimeout(() => srv.close(), 100);
				});
			});
			expect(result).to.match(/invalid upgrade response/);
		});

		it('reassembles fragmented server messages and auto-pongs pings', async function () {
			const { server, port } = await startWsServer();
			try {
				const rawConn = new Promise<WebSocketServerTransport>((resolve) => {
					server.once('connection', resolve);
				});
				const ws = new NodeWebSocket(`ws://127.0.0.1:${port}`);
				ws.binaryType = 'arraybuffer';
				const messages: Buffer[] = [];
				ws.onmessage = (ev): void => {
					messages.push(Buffer.from(ev.data as ArrayBuffer));
				};
				ws.onerror = (): void => {};
				await new Promise<void>((resolve) => {
					ws.onopen = (): void => resolve();
				});
				const serverTransport = await rawConn;
				// Reach the raw socket to send crafted fragments + ping
				const raw = (serverTransport as unknown as { socket: net.Socket })
					.socket;
				// Watch for the client's (masked) pong echo on the raw socket
				const pongPayload = new Promise<Buffer>((resolve) => {
					const parser = new WsFrameParser(); // client frames: masked
					raw.on('data', (d: Buffer) => {
						for (const f of parser.push(d)) {
							if (f.opcode === WsOpcode.PONG) resolve(f.payload);
						}
					});
				});
				raw.write(
					Buffer.concat([
						encodeWsFrame({
							opcode: WsOpcode.BINARY,
							payload: Buffer.from('part-1|'),
							fin: false
						}),
						encodeWsFrame({
							opcode: WsOpcode.PING,
							payload: Buffer.from('mid-message-ping')
						}),
						encodeWsFrame({
							opcode: WsOpcode.CONTINUATION,
							payload: Buffer.from('part-2'),
							fin: true
						})
					])
				);
				// One reassembled message despite the interleaved control frame
				await waitFor(() => messages.length === 1, 5000, 'message');
				expect(messages[0].toString()).to.equal('part-1|part-2');
				expect((await pongPayload).toString()).to.equal('mid-message-ping');
				ws.close();
			} finally {
				server.close();
			}
		});
	});

	// ─── Transport conformance (TCP and WS) ────────────────────

	describe('IDuplexTransport conformance', function () {
		interface ITransportPair {
			client: IDuplexTransport;
			server: IDuplexTransport;
			cleanup: () => void;
		}

		async function tcpPair(): Promise<ITransportPair> {
			return new Promise((resolve, reject) => {
				const srv = net.createServer((serverSocket) => {
					srv.close();
					resolve({
						client,
						server: serverSocket,
						cleanup: (): void => {
							client.destroy();
							serverSocket.destroy();
						}
					});
				});
				srv.once('error', reject);
				let client: net.Socket;
				srv.listen(0, '127.0.0.1', () => {
					const addr = srv.address() as net.AddressInfo;
					client = net.connect(addr.port, '127.0.0.1');
					client.once('error', reject);
				});
			});
		}

		async function wsPair(
			webSocketImpl?: WebSocketConstructor
		): Promise<ITransportPair> {
			const { server, port } = await startWsServer();
			const serverTransportPromise = new Promise<WebSocketServerTransport>(
				(resolve) => {
					server.once('connection', resolve);
				}
			);
			const client = await connectWebSocket(`ws://127.0.0.1:${port}`, {
				webSocketImpl
			});
			const serverTransport = await serverTransportPromise;
			return {
				client,
				server: serverTransport,
				cleanup: (): void => {
					client.destroy();
					serverTransport.destroy();
					server.close();
				}
			};
		}

		const variants: Array<{
			name: string;
			make: () => Promise<ITransportPair>;
		}> = [
			{ name: 'TCP (net.Socket)', make: tcpPair },
			{
				name: 'WebSocket (global undici client)',
				make: (): Promise<ITransportPair> => wsPair()
			},
			{
				name: 'WebSocket (in-repo Node client)',
				make: (): Promise<ITransportPair> => wsPair(NodeWebSocket)
			}
		];

		for (const variant of variants) {
			describe(variant.name, function () {
				it('delivers written bytes in order, both directions', async function () {
					const pair = await variant.make();
					try {
						const gotAtServer: Buffer[] = [];
						const gotAtClient: Buffer[] = [];
						pair.server.on('data', (d: Buffer) => gotAtServer.push(d));
						pair.client.on('data', (d: Buffer) => gotAtClient.push(d));
						const a = crypto.randomBytes(1000);
						const b = crypto.randomBytes(50);
						pair.client.write(a);
						pair.client.write(b);
						pair.server.write(b);
						pair.server.write(a);
						await waitFor(
							() =>
								Buffer.concat(gotAtServer).length === 1050 &&
								Buffer.concat(gotAtClient).length === 1050,
							5000,
							'bytes both ways'
						);
						expect(
							Buffer.concat(gotAtServer).equals(Buffer.concat([a, b]))
						).to.equal(true);
						expect(
							Buffer.concat(gotAtClient).equals(Buffer.concat([b, a]))
						).to.equal(true);
					} finally {
						pair.cleanup();
					}
				});

				it('write callback fires; writableLength is a number', async function () {
					const pair = await variant.make();
					try {
						expect(typeof pair.client.writableLength).to.equal('number');
						await new Promise<void>((resolve, reject) => {
							pair.client.write(Buffer.alloc(10), (err) =>
								err ? reject(err) : resolve()
							);
						});
					} finally {
						pair.cleanup();
					}
				});

				it('emits close on the far side when a side is destroyed', async function () {
					const pair = await variant.make();
					try {
						let serverClosed = false;
						pair.server.on('close', () => {
							serverClosed = true;
						});
						pair.server.on('error', () => {});
						pair.client.destroy();
						await waitFor(() => serverClosed, 5000, 'remote close');
					} finally {
						pair.cleanup();
					}
				});

				it('destroy(err) surfaces error then close(hadError=true)', async function () {
					const pair = await variant.make();
					try {
						const events: string[] = [];
						pair.client.on('error', () => events.push('error'));
						pair.client.on('close', (hadError: boolean) =>
							events.push(`close:${hadError}`)
						);
						pair.client.destroy(new Error('fatal'));
						await waitFor(
							() => events.includes('close:true'),
							5000,
							'close event'
						);
						expect(events[0]).to.equal('error');
					} finally {
						pair.cleanup();
					}
				});

				it('setTimeout emits timeout without closing the transport', async function () {
					const pair = await variant.make();
					try {
						let timedOut = false;
						let closed = false;
						pair.client.on('close', () => {
							closed = true;
						});
						pair.client.setTimeout(50, () => {
							timedOut = true;
						});
						await waitFor(() => timedOut, 5000, 'timeout event');
						pair.client.setTimeout(0);
						expect(closed).to.equal(false);
					} finally {
						pair.cleanup();
					}
				});

				it('setKeepAlive is callable and chainable', async function () {
					const pair = await variant.make();
					try {
						expect(pair.client.setKeepAlive(true, 1000)).to.equal(pair.client);
					} finally {
						pair.cleanup();
					}
				});
			});
		}
	});

	// ─── Peer over WS: Noise handshake + init ───────────────────

	describe('Peer over WebSocket (BOLT 8 Noise + BOLT 1 init)', function () {
		it('completes handshake + init and exchanges messages over WS', async function () {
			const initiatorKey = crypto.randomBytes(32);
			const responderKey = crypto.randomBytes(32);
			const responderPub = getPublicKey(responderKey);

			const { server, port } = await startWsServer();
			let responderPeer: Peer | null = null;
			const responderReady = new Promise<Peer>((resolve, reject) => {
				server.on('connection', (transport: WebSocketServerTransport) => {
					const peer = new Peer({
						localPrivateKey: responderKey,
						remotePublicKey: Buffer.alloc(33, 0), // learned in handshake
						host: transport.remoteAddress || 'unknown',
						port: transport.remotePort || 0
					});
					peer.on('error', () => {});
					responderPeer = peer;
					peer
						.acceptInbound(transport)
						.then(() => resolve(peer))
						.catch(reject);
				});
			});

			const initiator = new Peer({
				localPrivateKey: initiatorKey,
				remotePublicKey: responderPub,
				host: '127.0.0.1',
				port,
				createSocket: (host, p): Promise<WebSocketTransport> =>
					connectWebSocket(`ws://${host}:${p}`)
			});
			initiator.on('error', () => {});

			try {
				await initiator.connect();
				const responder = await responderReady;

				expect(initiator.getState()).to.equal('ready');
				expect(responder.getState()).to.equal('ready');
				// Responder learned the initiator's identity from Noise act 3
				expect(
					responder.remotePublicKey.equals(getPublicKey(initiatorKey))
				).to.equal(true);
				// Init exchanged
				expect(initiator.getRemoteInit()).to.not.equal(null);
				expect(responder.getRemoteInit()).to.not.equal(null);

				// Exchange an application message (odd/unknown type passes through)
				const payload = crypto.randomBytes(32);
				const got = new Promise<{ type: number; body: Buffer }>((resolve) => {
					responder.on('message', (type: number, body: Buffer) =>
						resolve({ type, body })
					);
				});
				initiator.sendMessage(40001, payload);
				const msg = await got;
				expect(msg.type).to.equal(40001);
				expect(msg.body.equals(payload)).to.equal(true);
			} finally {
				initiator.disconnect();
				if (responderPeer) (responderPeer as Peer).disconnect();
				server.close();
			}
		});
	});

	// ─── PeerManager over WS ───────────────────────────────────

	describe('PeerManager over WebSocket', function () {
		it('accepts inbound WS peers and dials outbound with {type: ws}', async function () {
			const aKey = crypto.randomBytes(32);
			const bKey = crypto.randomBytes(32);
			const aPub = getPublicKey(aKey).toString('hex');
			const bPub = getPublicKey(bKey).toString('hex');

			const a = new PeerManager({ localPrivateKey: aKey });
			const b = new PeerManager({ localPrivateKey: bKey });
			try {
				await a.listenWebSocket(0, '127.0.0.1');
				const port = a.getWebSocketListenerPort();
				expect(port).to.be.a('number');
				expect(a.isListeningWebSocket()).to.equal(true);
				expect(a.isListening()).to.equal(true);

				const aSawPeer = new Promise<string>((resolve) => {
					a.once('peer:connect', resolve);
				});
				await b.connectPeer(aPub, '127.0.0.1', port!, { type: 'ws' });
				expect(await aSawPeer).to.equal(bPub);

				// listPeers reports the transport
				const bPeers = b.listPeers();
				expect(bPeers.length).to.equal(1);
				expect(bPeers[0].transport).to.equal('ws');
				// Inbound side never reports ws dialing info (it accepted)
				expect(a.listPeers().length).to.equal(1);

				// Message routing works over the WS link
				const got = new Promise<Buffer>((resolve) => {
					a.onMessage(40001, (_pk, _type, payload) => resolve(payload));
				});
				const body = crypto.randomBytes(16);
				b.sendToPeer(aPub, 40001, body);
				expect((await got).equals(body)).to.equal(true);

				b.disconnectPeer(aPub);
			} finally {
				a.destroy();
				b.destroy();
			}
		});

		it('keeps TCP listeners and WS listeners coexisting', async function () {
			const key = crypto.randomBytes(32);
			const pm = new PeerManager({ localPrivateKey: key });
			try {
				await pm.listen(0, '127.0.0.1');
				await pm.listenWebSocket(0, '127.0.0.1');
				expect(pm.isListening()).to.equal(true);
				expect(pm.isListeningWebSocket()).to.equal(true);
				pm.stopListening();
				expect(pm.isListening()).to.equal(false);
				expect(pm.isListeningWebSocket()).to.equal(false);
			} finally {
				pm.destroy();
			}
		});
	});

	// ─── Two LightningNodes over WS: handshake + channel ───────

	describe('LightningNode channel over WebSocket (in-process)', function () {
		function makeSeed(id: number): Buffer {
			return crypto
				.createHash('sha256')
				.update(Buffer.from(`ws-node-seed-${id}`))
				.digest();
		}

		function makeBasepoints(seed: Buffer): {
			basepoints: IChannelBasepoints;
			secrets: Buffer[];
		} {
			const keys: Buffer[] = [];
			for (let i = 0; i < 5; i++) {
				keys.push(
					crypto
						.createHash('sha256')
						.update(seed)
						.update(Buffer.from([i]))
						.digest()
				);
			}
			return {
				basepoints: {
					fundingPubkey: getPublicKey(keys[0]),
					revocationBasepoint: getPublicKey(keys[1]),
					paymentBasepoint: getPublicKey(keys[2]),
					delayedPaymentBasepoint: getPublicKey(keys[3]),
					htlcBasepoint: getPublicKey(keys[4]),
					firstPerCommitmentPoint: Buffer.alloc(33)
				},
				secrets: keys
			};
		}

		function makeNode(seedId: number): LightningNode {
			const seed = makeSeed(seedId);
			const { basepoints, secrets } = makeBasepoints(seed);
			const config: INodeConfig = {
				nodePrivateKey: crypto
					.createHash('sha256')
					.update(seed)
					.update(Buffer.from('node-identity'))
					.digest(),
				network: Network.REGTEST,
				channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
				channelBasepoints: basepoints,
				perCommitmentSeed: makeSeed(seedId + 100),
				fundingPrivkey: secrets[0],
				htlcBasepointSecret: secrets[4],
				enableNetworking: true
			};
			const node = new LightningNode(config);
			node.on('error', () => {});
			node.on('node:error', () => {});
			return node;
		}

		/** Publish a synthetic direct channel into a node's graph for routing. */
		function buildDirectGraph(
			payer: LightningNode,
			payee: LightningNode,
			channelId: Buffer
		): void {
			const payerPub = Buffer.from(payer.getNodeId(), 'hex');
			const payeePub = Buffer.from(payee.getNodeId(), 'hex');
			const scid = encodeShortChannelId({
				block: 500,
				txIndex: 1,
				outputIndex: 0
			});
			const payerIsNode1 = Buffer.compare(payerPub, payeePub) < 0;
			const announcement: IChannelAnnouncementMessage = {
				nodeSignature1: Buffer.alloc(64),
				nodeSignature2: Buffer.alloc(64),
				bitcoinSignature1: Buffer.alloc(64),
				bitcoinSignature2: Buffer.alloc(64),
				features: Buffer.alloc(0),
				chainHash: BITCOIN_CHAIN_HASH,
				shortChannelId: scid,
				nodeId1: payerIsNode1 ? payerPub : payeePub,
				nodeId2: payerIsNode1 ? payeePub : payerPub,
				bitcoinKey1: Buffer.alloc(33, 2),
				bitcoinKey2: Buffer.alloc(33, 3)
			};
			payer.getGraph().addChannelAnnouncement(announcement);
			const update1: IChannelUpdateMessage = {
				signature: Buffer.alloc(64),
				chainHash: BITCOIN_CHAIN_HASH,
				shortChannelId: scid,
				timestamp: Math.floor(Date.now() / 1000),
				messageFlags: 1,
				channelFlags: 0,
				cltvExpiryDelta: 40,
				htlcMinimumMsat: 1000n,
				feeBaseMsat: 1000,
				feeProportionalMillionths: 1,
				htlcMaximumMsat: 1_000_000_000n
			};
			payer.getGraph().applyChannelUpdate(update1);
			payer.getGraph().applyChannelUpdate({ ...update1, channelFlags: 1 });
			payer.registerChannelScid(channelId, scid);
		}

		it('opens a channel to NORMAL and pays an invoice over WS', async function () {
			const alice = makeNode(1);
			const bob = makeNode(2);
			try {
				// Bob accepts inbound WS peers; Alice dials over WS
				await bob.listenWebSocket(0, '127.0.0.1');
				const pm = bob.getPeerManager();
				const port = pm!.getWebSocketListenerPort();
				expect(port).to.be.a('number');

				await alice.connectPeer(bob.getNodeId(), '127.0.0.1', port!, {
					type: 'ws'
				});
				expect(alice.listPeers()[0].state).to.equal('ready');
				expect(alice.listPeers()[0].transport).to.equal('ws');
				await waitFor(
					() => bob.listPeers().length === 1,
					10_000,
					'bob sees alice'
				);

				// Channel open over the WS link
				const accepted = new Promise<void>((resolve) => {
					alice.getChannelManager().once('channel:accepted', () => resolve());
				});
				const channel = alice.openChannel(bob.getNodeId(), 1_000_000n);
				await accepted;

				const fundingTxid = crypto.randomBytes(32);
				const channelId = alice.createFunding(
					channel,
					fundingTxid,
					0,
					crypto.randomBytes(64)
				);
				expect(channelId).to.not.equal(null);

				// funding_created/funding_signed complete over the wire
				await waitFor(
					() => {
						const chs = bob.getChannelManager().listChannels();
						return chs.length === 1 && chs[0].getChannelId() !== null;
					},
					10_000,
					'bob channel funded'
				);
				await waitFor(
					() =>
						alice.getChannel(channelId!)?.state ===
						ChannelState.AWAITING_FUNDING_CONFIRMED,
					10_000,
					'alice funding signed'
				);
				alice.handleFundingConfirmed(channelId!);
				bob.handleFundingConfirmed(
					bob.getChannelManager().listChannels()[0].getChannelId()!
				);

				await waitFor(
					() =>
						alice.getChannel(channelId!)?.state === ChannelState.NORMAL &&
						bob.getChannelManager().listChannels()[0].getState() === 'NORMAL',
					15_000,
					'channel NORMAL both sides'
				);

				// A payment across the WS channel
				buildDirectGraph(alice, bob, channelId!);
				const invoice = bob.createInvoice({
					amountMsat: 10_000_000n,
					description: 'ws in-process payment'
				});
				const payment = alice.sendPayment(invoice.bolt11);
				await waitFor(
					() =>
						alice.getPayment(payment.paymentHash)?.status ===
						PaymentStatus.COMPLETED,
					15_000,
					'payment completed'
				);
			} finally {
				alice.destroy();
				bob.destroy();
			}
		});
	});
});
