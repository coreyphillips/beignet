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
import { execSync } from 'child_process';
import crypto from 'crypto';
import fs from 'fs';
import http from 'http';
import https from 'https';
import net from 'net';
import os from 'os';
import path from 'path';
import sinon from 'sinon';
import tls from 'tls';
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
	WebSocketServerTransport,
	PRE_HANDSHAKE_MAX_WS_BYTES,
	checkWebSocketUpgrade,
	denyWebSocketUpgrade,
	acceptWebSocketUpgrade
} from '../../src/lightning/transport/websocket-server';
import {
	encodeWsFrame,
	WsOpcode,
	WsCloseCode,
	decodeWsClosePayload,
	WsFrameParser,
	DEFAULT_MAX_WS_PAYLOAD_BYTES
} from '../../src/lightning/transport/websocket-frame';
import { parsePeerUri } from '../../src/lightning/transport/peer-uri';
import {
	NodeWebSocket,
	nodeWebSocketVia
} from '../../src/lightning/transport/websocket-node-client';
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

/** Resolve with the server's close frame on a raw-upgraded socket. */
function nextClose(socket: net.Socket): Promise<{ code: number }> {
	return new Promise((resolve, reject) => {
		const parser = new WsFrameParser({ requireMasked: false });
		socket.on('data', (d) => {
			for (const f of parser.push(d)) {
				if (f.opcode === WsOpcode.CLOSE) {
					resolve(decodeWsClosePayload(f.payload));
				}
			}
		});
		socket.on('error', reject);
	});
}

interface IFrameServer {
	port: number;
	/** The request line and headers of each upgrade, as received. */
	requests: Array<{ url: string; host: string }>;
	/** Every data frame a client sent. */
	frames: Array<{ opcode: number; payload: string }>;
	/** Send a frame to the most recent client. */
	send(opcode: number, payload: Buffer, fin?: boolean): void;
	close(): Promise<void>;
}

/**
 * A WebSocket server built from the exported upgrade helpers, which records
 * what it is sent instead of treating it as BOLT 8 bytes. With `tlsOptions`
 * it serves wss://.
 */
async function startFrameServer(
	tlsOptions?: https.ServerOptions
): Promise<IFrameServer> {
	const requests: IFrameServer['requests'] = [];
	const frames: IFrameServer['frames'] = [];
	const sockets = new Set<net.Socket>();
	let latest: net.Socket | undefined;
	const server = tlsOptions
		? https.createServer(tlsOptions)
		: http.createServer();
	server.on('upgrade', (req: http.IncomingMessage, socket: net.Socket) => {
		const checked = checkWebSocketUpgrade(req);
		if ('deny' in checked) return denyWebSocketUpgrade(socket, checked.deny);
		requests.push({ url: req.url ?? '', host: req.headers.host ?? '' });
		acceptWebSocketUpgrade(socket, checked.key);
		latest = socket;
		sockets.add(socket);
		const parser = new WsFrameParser({ requireMasked: true });
		socket.on('data', (d: Buffer) => {
			for (const f of parser.push(d)) {
				if (f.opcode === WsOpcode.TEXT || f.opcode === WsOpcode.BINARY)
					frames.push({ opcode: f.opcode, payload: f.payload.toString() });
			}
		});
		socket.on('error', () => undefined);
		socket.on('close', () => sockets.delete(socket));
	});
	server.on('tlsClientError', () => undefined);
	await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
	return {
		port: (server.address() as net.AddressInfo).port,
		requests,
		frames,
		send: (opcode, payload, fin = true): void => {
			latest?.write(encodeWsFrame({ opcode, payload, fin }));
		},
		close: (): Promise<void> => {
			for (const socket of sockets) socket.destroy();
			return new Promise((resolve) => server.close(() => resolve()));
		}
	};
}

/** A connected TCP stream to a local port, as an injected dial returns. */
function dialLocal(port: number): Promise<net.Socket> {
	return new Promise((resolve, reject) => {
		const socket: net.Socket = net.createConnection(port, '127.0.0.1', () =>
			resolve(socket)
		);
		socket.once('error', reject);
	});
}

/** Resolve once a client WebSocket is open; reject if it fails first. */
function opened(ws: IWebSocketLike): Promise<void> {
	return new Promise((resolve, reject) => {
		ws.onopen = (): void => resolve();
		ws.onerror = (e): void => reject(e);
	});
}

function maskedBinary(payload: Buffer): Buffer {
	return encodeWsFrame({
		opcode: WsOpcode.BINARY,
		payload,
		maskKey: crypto.randomBytes(4)
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
			// globalThis.WebSocket only exists on Node >= 21 (CI runs 20);
			// on older Node the "throws when nothing available" case below
			// covers the resolution path instead.
			const g = globalThis as { WebSocket?: unknown };
			if (typeof g.WebSocket !== 'function') {
				this.skip();
				return;
			}
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

		it('closes 1009 on an incomplete frame too large for an unestablished peer', async function () {
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
				const closed = nextClose(socket);
				// Declares the full default cap, then sends only the start of it.
				const header = Buffer.alloc(14);
				header[0] = 0x80 | WsOpcode.BINARY;
				header[1] = 0x80 | 127;
				header.writeBigUInt64BE(BigInt(DEFAULT_MAX_WS_PAYLOAD_BYTES), 2);
				crypto.randomBytes(4).copy(header, 10);
				socket.write(Buffer.concat([header, crypto.randomBytes(64 * 1024)]));
				expect((await closed).code).to.equal(WsCloseCode.MESSAGE_TOO_BIG);
				await waitFor(() => transportClosed, 5000, 'transport close');
				socket.destroy();
			} finally {
				server.close();
			}
		});

		it('holds an unestablished peer to the cap for unread data', async function () {
			const { server, port } = await startWsServer();
			try {
				server.on('connection', (t: WebSocketServerTransport) => {
					t.on('error', () => {});
				});
				const { socket } = await rawUpgrade(port);
				const closed = nextClose(socket);
				// A frame at the cap is accepted; one more unread byte is not.
				socket.write(
					Buffer.concat([
						maskedBinary(crypto.randomBytes(PRE_HANDSHAKE_MAX_WS_BYTES)),
						maskedBinary(Buffer.alloc(1))
					])
				);
				expect((await closed).code).to.equal(WsCloseCode.INTERNAL_ERROR);
				socket.destroy();
			} finally {
				server.close();
			}
		});

		it('lifts both caps once the peer is established', async function () {
			const { server, port } = await startWsServer();
			try {
				let transport: WebSocketServerTransport | undefined;
				server.on('connection', (t: WebSocketServerTransport) => {
					t.on('error', () => {});
					t.markEstablished();
					transport = t;
				});
				const { socket } = await rawUpgrade(port);
				const big = crypto.randomBytes(1024 * 1024);
				const small = crypto.randomBytes(1);
				socket.write(Buffer.concat([maskedBinary(big), maskedBinary(small)]));
				await waitFor(
					() =>
						(transport as unknown as { pendingBytes: number } | undefined)
							?.pendingBytes ===
						big.length + small.length,
					5000,
					'unread frames buffered'
				);
				const received: Buffer[] = [];
				transport!.on('data', (d: Buffer) => received.push(d));
				expect(
					Buffer.concat(received).equals(Buffer.concat([big, small]))
				).to.equal(true);
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

		it('sends a string as a text message and bytes as a binary one', async function () {
			const server = await startFrameServer();
			try {
				const ws = new NodeWebSocket(`ws://127.0.0.1:${server.port}`);
				const received: unknown[] = [];
				ws.onmessage = (ev): void => {
					received.push(ev.data);
				};
				await opened(ws);
				ws.send('{"t":"héllo"}');
				ws.send(Buffer.from('bytes'));
				await waitFor(() => server.frames.length === 2, 5000, 'frames');
				expect(server.frames).to.deep.equal([
					{ opcode: WsOpcode.TEXT, payload: '{"t":"héllo"}' },
					{ opcode: WsOpcode.BINARY, payload: 'bytes' }
				]);
				// And the other way: text arrives as a string, bytes as a buffer.
				server.send(WsOpcode.TEXT, Buffer.from('{"t":"ready"}'));
				server.send(WsOpcode.BINARY, Buffer.from('raw'));
				await waitFor(() => received.length === 2, 5000, 'messages');
				expect(received[0]).to.equal('{"t":"ready"}');
				expect(Buffer.from(received[1] as ArrayBuffer).toString()).to.equal(
					'raw'
				);
				ws.close();
			} finally {
				await server.close();
			}
		});

		it('closes on a message over maxPayloadBytes, whole or in fragments', async function () {
			const server = await startFrameServer();
			try {
				for (const fragmented of [false, true]) {
					const ws = new NodeWebSocket(`ws://127.0.0.1:${server.port}`, {
						maxPayloadBytes: 1024
					});
					const messages: unknown[] = [];
					const errors: Error[] = [];
					let closed = false;
					ws.onmessage = (ev): void => {
						messages.push(ev.data);
					};
					await opened(ws);
					ws.onerror = (e): void => {
						errors.push(e as Error);
					};
					ws.onclose = (): void => {
						closed = true;
					};
					// At the cap is delivered.
					server.send(WsOpcode.BINARY, Buffer.alloc(1024, 1));
					await waitFor(() => messages.length === 1, 5000, 'message at cap');
					if (fragmented) {
						server.send(WsOpcode.BINARY, Buffer.alloc(600, 2), false);
						server.send(WsOpcode.CONTINUATION, Buffer.alloc(600, 3));
					} else {
						server.send(WsOpcode.BINARY, Buffer.alloc(1025, 2));
					}
					await waitFor(() => closed, 5000, 'close');
					expect(messages).to.have.length(1);
					expect(errors).to.have.length(1);
				}
			} finally {
				await server.close();
			}
		});

		it('keeps the 16 MiB default when no cap is given', function () {
			const ws = new NodeWebSocket('ws://127.0.0.1:1');
			ws.onerror = (): void => {};
			expect(
				(ws as unknown as { maxPayloadBytes: number }).maxPayloadBytes
			).to.equal(DEFAULT_MAX_WS_PAYLOAD_BYTES);
			ws.close();
		});

		describe('with an injected connect', function () {
			it('hands over the host as written and never dials it itself', async function () {
				const server = await startFrameServer();
				const dialed: Array<[string, number]> = [];
				const direct = sinon.spy(net, 'connect');
				try {
					// A name that does not resolve: only the injected dial can
					// reach the server.
					const ws = new NodeWebSocket(
						'ws://relay.example.invalid:4321/v1/host?x=1',
						{
							connect: (host, port): Promise<net.Socket> => {
								dialed.push([host, port]);
								return dialLocal(server.port);
							}
						}
					);
					await opened(ws);
					expect(dialed).to.deep.equal([['relay.example.invalid', 4321]]);
					expect(direct.called).to.equal(false);
					expect(server.requests).to.deep.equal([
						{ url: '/v1/host?x=1', host: 'relay.example.invalid:4321' }
					]);
					ws.send('hello');
					await waitFor(() => server.frames.length === 1, 5000, 'frame');
					ws.close();
				} finally {
					direct.restore();
					await server.close();
				}
			});

			it('accepts a stream returned without a promise', async function () {
				const server = await startFrameServer();
				try {
					const ws = new NodeWebSocket('ws://relay.example.invalid:1/', {
						connect: (): net.Socket =>
							net.createConnection(server.port, '127.0.0.1')
					});
					await opened(ws);
					ws.close();
				} finally {
					await server.close();
				}
			});

			it('fails the connection when the dial is refused', async function () {
				for (const connect of [
					(): Promise<net.Socket> => Promise.reject(new Error('no tunnel')),
					(): net.Socket => {
						throw new Error('no tunnel');
					}
				]) {
					const ws = new NodeWebSocket('ws://relay.example.invalid:1/', {
						connect
					});
					const outcome = await new Promise<string>((resolve) => {
						let error = '';
						ws.onopen = (): void => resolve('open');
						ws.onerror = (e): void => {
							error = (e as Error).message;
						};
						ws.onclose = (): void => resolve(error);
					});
					expect(outcome).to.equal('no tunnel');
					expect(ws.readyState).to.equal(3);
				}
			});

			it('destroys a stream that arrives after close()', async function () {
				const server = await startFrameServer();
				try {
					let release: (socket: net.Socket) => void = () => undefined;
					const ws = new NodeWebSocket('ws://relay.example.invalid:1/', {
						connect: (): Promise<net.Socket> =>
							new Promise<net.Socket>((resolve) => {
								release = resolve;
							})
					});
					let closes = 0;
					ws.onclose = (): void => {
						closes++;
					};
					await sleep(10);
					ws.close();
					expect(closes).to.equal(1);
					const socket = await dialLocal(server.port);
					release(socket);
					await waitFor(() => socket.destroyed, 5000, 'stream destroyed');
					expect(server.requests).to.have.length(0);
					expect(closes).to.equal(1);
				} finally {
					await server.close();
				}
			});

			describe('wss://', function () {
				let dir: string;
				let key: string;
				let cert: string;

				before(function () {
					dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-wss-'));
					const keyPath = path.join(dir, 'key.pem');
					const certPath = path.join(dir, 'cert.pem');
					key = crypto.generateKeyPairSync('rsa', {
						modulusLength: 2048,
						privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
						publicKeyEncoding: { type: 'spki', format: 'pem' }
					}).privateKey;
					fs.writeFileSync(keyPath, key);
					execSync(
						`openssl req -new -x509 -key ${keyPath} -out ${certPath} -days 1 -subj "/CN=localhost" -batch 2>/dev/null`
					);
					cert = fs.readFileSync(certPath, 'utf8');
				});

				after(function () {
					fs.rmSync(dir, { recursive: true, force: true });
				});

				const tunnelTo =
					(port: number, streams: net.Socket[]) =>
					async (): Promise<net.Socket> => {
						const socket = await dialLocal(port);
						streams.push(socket);
						return socket;
					};

				it('runs TLS inside the stream, for the host in the URL', async function () {
					const server = await startFrameServer({ key, cert });
					const streams: net.Socket[] = [];
					// The test certificate is its own authority: trust it for
					// this dial and change nothing else about the call.
					const original = tls.connect.bind(tls) as (
						options: tls.ConnectionOptions,
						listener?: () => void
					) => tls.TLSSocket;
					const calls: tls.ConnectionOptions[] = [];
					const stub = sinon.stub(tls, 'connect').callsFake(((
						options: tls.ConnectionOptions,
						listener?: () => void
					) => {
						calls.push(options);
						return original({ ...options, ca: cert }, listener);
					}) as unknown as typeof tls.connect);
					try {
						const ws = new NodeWebSocket(
							`wss://localhost:${server.port}/v1/host`,
							{ connect: tunnelTo(server.port, streams) }
						);
						await opened(ws);
						expect(calls).to.have.length(1);
						expect(calls[0].socket).to.equal(streams[0]);
						expect(calls[0].servername).to.equal('localhost');
						// No address of its own to dial, and verification left on.
						expect(calls[0]).to.not.have.property('host');
						expect(calls[0]).to.not.have.property('port');
						expect(calls[0]).to.not.have.property('rejectUnauthorized');
						ws.send('over tls');
						await waitFor(() => server.frames.length === 1, 5000, 'frame');
						expect(server.frames[0].payload).to.equal('over tls');
						ws.close();
					} finally {
						stub.restore();
						await server.close();
					}
				});

				it('refuses a certificate it cannot verify', async function () {
					const server = await startFrameServer({ key, cert });
					try {
						const ws = new NodeWebSocket(
							`wss://localhost:${server.port}/v1/host`,
							{ connect: tunnelTo(server.port, []) }
						);
						const outcome = await new Promise<string>((resolve) => {
							ws.onopen = (): void => resolve('open');
							ws.onerror = (e): void =>
								resolve((e as NodeJS.ErrnoException).code ?? 'error');
						});
						expect(outcome).to.match(/SELF_SIGNED/);
						expect(server.requests).to.have.length(0);
					} finally {
						await server.close();
					}
				});
			});
		});

		describe('nodeWebSocketVia', function () {
			it('builds a constructor whose every connection uses the given dial', async function () {
				const server = await startFrameServer();
				const dialed: string[] = [];
				try {
					const Via = nodeWebSocketVia(
						(host, port) => {
							dialed.push(`${host}:${port}`);
							return net.createConnection(server.port, '127.0.0.1');
						},
						{ maxPayloadBytes: 2048 }
					);
					const ws = new Via('ws://one.example.invalid:9735/');
					await opened(ws);
					expect(ws).to.be.instanceOf(NodeWebSocket);
					expect(
						(ws as unknown as { maxPayloadBytes: number }).maxPayloadBytes
					).to.equal(2048);
					// The standard second argument cannot replace the dial.
					const other = new Via('ws://two.example.invalid:9736/', ['x']);
					await opened(other);
					expect(dialed).to.deep.equal([
						'one.example.invalid:9735',
						'two.example.invalid:9736'
					]);
					ws.close();
					other.close();
				} finally {
					await server.close();
				}
			});

			it('carries a BOLT 8 transport through connectWebSocket', async function () {
				const { server, port } = await startWsServer();
				try {
					const inbound = new Promise<WebSocketServerTransport>((resolve) => {
						server.once('connection', resolve);
					});
					const dialed: string[] = [];
					const transport = await connectWebSocket(
						'ws://node.example.invalid:9735',
						{
							webSocketImpl: nodeWebSocketVia((host, p) => {
								dialed.push(`${host}:${p}`);
								return net.createConnection(port, '127.0.0.1');
							})
						}
					);
					const serverSide = await inbound;
					const got = new Promise<Buffer>((resolve) => {
						serverSide.on('data', resolve);
					});
					transport.write(Buffer.from('act one'));
					expect((await got).toString()).to.equal('act one');
					expect(dialed).to.deep.equal(['node.example.invalid:9735']);
					transport.destroy();
				} finally {
					server.close();
				}
			});
		});
	});

	describe('upgrade helpers', function () {
		const request = (
			headers: Record<string, string>,
			method = 'GET'
		): { method: string; headers: http.IncomingHttpHeaders } => ({
			method,
			headers
		});
		const good = {
			upgrade: 'websocket',
			'sec-websocket-version': '13',
			'sec-websocket-key': crypto.randomBytes(16).toString('base64')
		};

		it('returns the key of a well-formed request', function () {
			expect(checkWebSocketUpgrade(request(good))).to.deep.equal({
				key: good['sec-websocket-key']
			});
			expect(
				checkWebSocketUpgrade(request({ ...good, upgrade: 'WebSocket' }))
			).to.have.property('key');
		});

		it('names the denial for each malformed request', function () {
			const denied = (
				headers: Record<string, string>,
				method?: string
			): unknown => {
				const checked = checkWebSocketUpgrade(request(headers, method));
				return 'deny' in checked ? checked.deny : 'accepted';
			};
			expect(denied(good, 'POST')).to.deep.equal({
				status: 405,
				message: 'Method Not Allowed'
			});
			expect(denied({ ...good, upgrade: 'h2c' })).to.deep.equal({
				status: 400,
				message: 'Bad Request'
			});
			expect(denied({ ...good, 'sec-websocket-version': '8' })).to.deep.equal({
				status: 426,
				message: 'Upgrade Required',
				headers: 'Sec-WebSocket-Version: 13\r\n'
			});
			expect(
				denied({ ...good, 'sec-websocket-key': 'c2hvcnQ=' })
			).to.deep.equal({ status: 400, message: 'Bad Request' });
			const { 'sec-websocket-key': _key, ...keyless } = good;
			expect(denied(keyless)).to.deep.equal({
				status: 400,
				message: 'Bad Request'
			});
		});

		it('writes the denial and the acceptance a client expects', async function () {
			const server = await startFrameServer();
			try {
				const exchange = (lines: string[]): Promise<string> =>
					new Promise((resolve, reject) => {
						const socket = net.connect(server.port, '127.0.0.1', () => {
							socket.write(lines.join('\r\n') + '\r\n\r\n');
						});
						let got = '';
						socket.on('data', (d) => {
							got += d.toString('latin1');
							if (got.includes('\r\n\r\n')) {
								resolve(got);
								socket.destroy();
							}
						});
						socket.once('error', reject);
					});
				const base = [
					'GET / HTTP/1.1',
					'Host: 127.0.0.1',
					'Connection: Upgrade',
					'Upgrade: websocket',
					'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ=='
				];
				expect(await exchange([...base, 'Sec-WebSocket-Version: 12'])).to.equal(
					'HTTP/1.1 426 Upgrade Required\r\n' +
						'Connection: close\r\n' +
						'Sec-WebSocket-Version: 13\r\n' +
						'\r\n'
				);
				// The RFC 6455 section 1.3 example key and its accept value.
				expect(await exchange([...base, 'Sec-WebSocket-Version: 13'])).to.equal(
					'HTTP/1.1 101 Switching Protocols\r\n' +
						'Upgrade: websocket\r\n' +
						'Connection: Upgrade\r\n' +
						'Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n' +
						'\r\n'
				);
			} finally {
				await server.close();
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
				name: 'WebSocket (in-repo Node client)',
				make: (): Promise<ITransportPair> => wsPair(NodeWebSocket)
			}
		];
		// globalThis.WebSocket only exists on Node >= 21 (CI runs 20); the
		// in-repo client above covers the same conformance surface there.
		if (
			typeof (globalThis as { WebSocket?: unknown }).WebSocket === 'function'
		) {
			variants.push({
				name: 'WebSocket (global undici client)',
				make: (): Promise<ITransportPair> => wsPair()
			});
		}

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
			let establishedCalls = 0;
			const responderReady = new Promise<Peer>((resolve, reject) => {
				server.on('connection', (transport: WebSocketServerTransport) => {
					const markEstablished = transport.markEstablished.bind(transport);
					transport.markEstablished = (): void => {
						establishedCalls++;
						markEstablished();
					};
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
				// In-repo client explicitly: matches the PeerManager default
				// under Node and keeps this green on Node 20 (no global
				// WebSocket there).
				createSocket: (host, p): Promise<WebSocketTransport> =>
					connectWebSocket(`ws://${host}:${p}`, {
						webSocketImpl: NodeWebSocket
					})
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
				// ...so the server transport stops holding it to stranger caps
				expect(establishedCalls).to.equal(1);

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
			// This suite exercises the WS TRANSPORT over the manually-driven v1
			// funding flow (createFunding below). With default features on both
			// ends the peers would negotiate option_dual_fund and openChannel
			// would correctly route to the v2 interactive flow (issue #158),
			// which this harness does not drive. Pin features without dual fund
			// so the v1 open stays under test.
			const features = LightningNode.defaultFeatures();
			features.clearBit(28); // option_dual_fund, compulsory bit
			features.clearBit(29); // option_dual_fund, optional bit
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
				enableNetworking: true,
				localFeatures: features
			};
			const node = new LightningNode(config);
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
