/**
 * The Porch relay server (src/cli/porch-relay.ts, docs/PORCH-PROTOCOL.md):
 * registration, pairing, what it copies and what it refuses, its limits and
 * its bookkeeping. The clients here are the in-repo WebSocket client and raw
 * sockets; the node's own host side has its tests with the host.
 */

import { expect } from 'chai';
import { execSync } from 'child_process';
import crypto from 'crypto';
import fs from 'fs';
import http from 'http';
import net from 'net';
import os from 'os';
import nodePath from 'path';
import sinon from 'sinon';
import tls from 'tls';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { IPorchRelayOptions, PorchRelay } from '../../src/cli/porch-relay';
import {
	IPorchChallenge,
	IPorchRegister,
	PORCH_CLOSE_REFUSED,
	PORCH_CLOSE_TRY_LATER,
	PorchControlMessage,
	createPorchRegister,
	decodePorchControl,
	encodePorchControl,
	porchRouteId
} from '../../src/lightning/transport/porch';
import {
	WsCloseCode,
	WsFrameParser,
	WsOpcode,
	encodeWsFrame
} from '../../src/lightning/transport/websocket-frame';
import type { IWebSocketLike } from '../../src/lightning/transport/websocket';
import { NodeWebSocket } from '../../src/lightning/transport/websocket-node-client';

const AUTHORITY = 'relay.test';

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitFor(
	cond: () => boolean,
	label: string,
	timeoutMs = 10_000
): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (!cond()) {
		if (Date.now() > deadline)
			throw new Error(`Timed out waiting for ${label}`);
		await sleep(5);
	}
}

/** A WebSocket client that keeps what it is sent. */
class Client {
	readonly ws: NodeWebSocket;
	readonly texts: string[] = [];
	readonly binary: Buffer[] = [];
	/** Text and binary in arrival order, to check one against the other. */
	readonly order: Array<'text' | 'binary'> = [];
	closed?: { code?: number };
	error?: Error;
	/** Called for each text message as it arrives. */
	onText?: (text: string) => void;
	private opened = false;
	private read = 0;

	constructor(port: number, path: string, host = AUTHORITY, secure = false) {
		// The URL names the relay as a host would; the dial goes to loopback.
		this.ws = new NodeWebSocket(`${secure ? 'wss' : 'ws'}://${host}${path}`, {
			connect: (): net.Socket => net.createConnection(port, '127.0.0.1')
		});
		this.ws.onmessage = (ev): void => {
			if (typeof ev.data === 'string') {
				this.texts.push(ev.data);
				this.order.push('text');
				this.onText?.(ev.data);
			} else {
				this.binary.push(Buffer.from(ev.data as ArrayBuffer));
				this.order.push('binary');
			}
		};
		this.ws.onopen = (): void => {
			this.opened = true;
		};
		this.ws.onerror = (e): void => {
			this.error = e as Error;
		};
		this.ws.onclose = (ev): void => {
			this.closed = { code: ev?.code };
		};
	}

	async open(): Promise<this> {
		// The relay may accept and close in one breath (a 1013, say): that
		// connection opened.
		await waitFor(() => this.opened || this.closed !== undefined, 'open');
		if (!this.opened) throw this.error ?? new Error('closed before open');
		return this;
	}

	/** The next control message not yet handed out. */
	async control(): Promise<PorchControlMessage> {
		await waitFor(() => this.texts.length > this.read, 'a control message');
		const message = decodePorchControl(this.texts[this.read++]);
		if (!message) throw new Error('undecodable control message');
		return message;
	}

	sendControl(message: PorchControlMessage): void {
		this.ws.send(encodePorchControl(message));
	}

	received(): string {
		return Buffer.concat(this.binary).toString();
	}

	async closeCode(timeoutMs = 5_000): Promise<number | undefined> {
		await waitFor(() => this.closed !== undefined, 'close', timeoutMs);
		return this.closed?.code;
	}
}

interface IHostIdentity {
	secret: Buffer;
	key: Buffer;
	tags: Buffer[];
	routeIds: string[];
}

function identity(seed: number, links = 1): IHostIdentity {
	const secret = Buffer.alloc(32, seed);
	const key = getPublicKey(secret);
	const tags = Array.from({ length: links }, (_, i) =>
		Buffer.alloc(16, seed * 16 + i)
	);
	return {
		secret,
		key,
		tags,
		routeIds: tags.map((tag) => porchRouteId(key, tag))
	};
}

describe('Porch relay', function () {
	let relay: PorchRelay;
	let port: number;
	const clients: Client[] = [];
	const sockets: net.Socket[] = [];

	async function start(
		options: Partial<IPorchRelayOptions> = {}
	): Promise<void> {
		relay = new PorchRelay({ authorities: [AUTHORITY], ...options });
		await relay.listen(0, '127.0.0.1');
		port = (relay.address() as net.AddressInfo).port;
	}

	function client(path: string, host?: string): Client {
		const c = new Client(port, path, host);
		clients.push(c);
		return c;
	}

	/** Open a standby connection and answer the challenge. */
	async function register(
		host: IHostIdentity,
		change: {
			token?: string;
			authority?: string;
			tags?: Buffer[];
			message?: (m: IPorchRegister, c: IPorchChallenge) => PorchControlMessage;
		} = {}
	): Promise<{ standby: Client; challenge: IPorchChallenge }> {
		const standby = await client('/v1/host').open();
		const challenge = (await standby.control()) as IPorchChallenge;
		expect(challenge.t).to.equal('challenge');
		const message = createPorchRegister({
			hostSecret: host.secret,
			nonce: Buffer.from(challenge.nonce, 'hex'),
			authority: change.authority ?? AUTHORITY,
			tags: change.tags ?? host.tags,
			...(change.token !== undefined ? { token: change.token } : {})
		});
		standby.sendControl(
			change.message ? change.message(message, challenge) : message
		);
		return { standby, challenge };
	}

	/** A standby that the relay has accepted. */
	async function standbyFor(
		host: IHostIdentity,
		change: Parameters<typeof register>[1] = {}
	): Promise<Client> {
		const { standby } = await register(host, change);
		expect(await standby.control()).to.deep.equal({ t: 'ready' });
		return standby;
	}

	/** A raw upgraded socket, for what a WebSocket client will not send. */
	async function raw(
		path: string,
		options: { headers?: string[]; trailing?: Buffer } = {}
	): Promise<{
		socket: net.Socket;
		status: string;
		frames: Array<{ opcode: number; payload: Buffer; fin: boolean }>;
	}> {
		const socket = net.createConnection(port, '127.0.0.1');
		sockets.push(socket);
		socket.on('error', () => undefined);
		const frames: Array<{ opcode: number; payload: Buffer; fin: boolean }> = [];
		const parser = new WsFrameParser({ requireMasked: false });
		let head = Buffer.alloc(0);
		let status = '';
		const upgraded = new Promise<void>((resolve) => {
			socket.on('data', (chunk: Buffer) => {
				if (status) {
					frames.push(...parser.push(chunk));
					return;
				}
				head = Buffer.concat([head, chunk]);
				const end = head.indexOf('\r\n\r\n');
				if (end < 0) return;
				status = head.subarray(0, head.indexOf('\r\n')).toString();
				const rest = head.subarray(end + 4);
				if (rest.length > 0) frames.push(...parser.push(rest));
				resolve();
			});
			socket.on('close', () => resolve());
		});
		socket.write(
			Buffer.concat([
				Buffer.from(
					[
						`GET ${path} HTTP/1.1`,
						`Host: ${AUTHORITY}`,
						'Connection: Upgrade',
						'Upgrade: websocket',
						`Sec-WebSocket-Key: ${crypto.randomBytes(16).toString('base64')}`,
						'Sec-WebSocket-Version: 13',
						...(options.headers ?? [])
					].join('\r\n') + '\r\n\r\n'
				),
				options.trailing ?? Buffer.alloc(0)
			])
		);
		await upgraded;
		return { socket, status, frames };
	}

	const masked = (opcode: number, payload: Buffer, fin = true): Buffer =>
		encodeWsFrame({ opcode, payload, fin, maskKey: crypto.randomBytes(4) });

	afterEach(async function () {
		for (const c of clients.splice(0)) c.ws.close();
		for (const s of sockets.splice(0)) s.destroy();
		await relay?.close();
	});

	describe('configuration', function () {
		it('needs a public name and sane limits', function () {
			expect(() => new PorchRelay({ authorities: [] })).to.throw(/public name/);
			expect(() => new PorchRelay({ authorities: [''] })).to.throw(
				/public name/
			);
			expect(
				() => new PorchRelay({ authorities: [AUTHORITY], token: '' })
			).to.throw(/token is empty/);
			expect(
				() => new PorchRelay({ authorities: [AUTHORITY], limits: { hosts: 0 } })
			).to.throw(/hosts must be a positive integer/);
			expect(
				() =>
					new PorchRelay({
						authorities: [AUTHORITY],
						limits: { messageBytes: 1024 }
					})
			).to.throw(/messageBytes must be at least/);
		});

		it('answers /health and nothing else over plain HTTP', async function () {
			await start();
			const get = (path: string, method = 'GET'): Promise<[number, string]> =>
				new Promise((resolve, reject) => {
					const req = http.request(
						{ host: '127.0.0.1', port, path, method },
						(res) => {
							let body = '';
							res.on('data', (d) => (body += d));
							res.on('end', () => resolve([res.statusCode ?? 0, body]));
						}
					);
					req.on('error', reject);
					req.end();
				});
			expect(await get('/health')).to.deep.equal([200, '{"ok":true}']);
			expect((await get('/health', 'POST'))[0]).to.equal(404);
			expect((await get('/'))[0]).to.equal(404);
			expect((await get('/v1/host'))[0]).to.equal(404);
		});

		it('upgrades only the two paths it serves', async function () {
			await start();
			const host = identity(1);
			expect((await raw('/v1/host')).status).to.match(/ 101 /);
			expect((await raw(`/v1/p/${host.routeIds[0]}`)).status).to.match(/ 101 /);
			for (const path of [
				'/',
				'/v1/hosts',
				'/v1/p/',
				'/v1/p/short',
				`/v1/p/${host.routeIds[0].toUpperCase()}`,
				`/v1/p/${host.routeIds[0]}/more`
			]) {
				expect((await raw(path)).status, path).to.match(/ 404 /);
			}
		});
	});

	describe('registration', function () {
		it('challenges with a fresh nonce and its own name, and accepts a signed answer', async function () {
			await start();
			const host = identity(1, 2);
			const first = await register(host);
			expect(first.challenge).to.include({ v: 1, authority: AUTHORITY });
			expect(await first.standby.control()).to.deep.equal({ t: 'ready' });
			const second = await register(host);
			expect(second.challenge.nonce).to.not.equal(first.challenge.nonce);
			expect(await second.standby.control()).to.deep.equal({ t: 'ready' });
			expect(relay.stats()).to.include({ hosts: 1, standbys: 2, circuits: 0 });
		});

		it('names the configured authority the request asked for, and never one it was not given', async function () {
			await start({ authorities: [AUTHORITY, 'relayonion.onion'] });
			const named = async (host: string): Promise<string> => {
				const c = await client('/v1/host', host).open();
				return ((await c.control()) as IPorchChallenge).authority;
			};
			expect(await named('relayonion.onion')).to.equal('relayonion.onion');
			expect(await named('RELAYONION.onion')).to.equal('relayonion.onion');
			expect(await named(AUTHORITY)).to.equal(AUTHORITY);
			expect(await named('attacker.example')).to.equal(AUTHORITY);
			expect(await named(`${AUTHORITY}:8443`)).to.equal(AUTHORITY);
		});

		const refusals: Array<
			[string, Parameters<typeof register>[1], Partial<IPorchRelayOptions>?]
		> = [
			['signed for another relay', { authority: 'other.example' }],
			[
				'signed over another nonce',
				{
					message: (): IPorchRegister =>
						createPorchRegister({
							hostSecret: identity(1).secret,
							nonce: Buffer.alloc(32, 7),
							authority: AUTHORITY,
							tags: identity(1).tags
						})
				}
			],
			[
				'listing a tag that was not signed',
				{ message: (m): IPorchRegister => ({ ...m, tags: ['00'.repeat(16)] }) }
			],
			[
				'under a key that did not sign',
				{
					message: (m): IPorchRegister => ({
						...m,
						key: identity(2).key.toString('hex')
					})
				}
			],
			[
				'not a registration at all',
				{ message: (): PorchControlMessage => ({ t: 'pong' }) }
			],
			[
				'without the token a private relay asks for',
				{},
				{ token: 'open sesame' }
			],
			[
				'with the wrong token',
				{ token: 'open says me' },
				{ token: 'open sesame' }
			],
			[
				'listing more links than the relay takes',
				{ tags: identity(1, 2).tags },
				{ limits: { tagsPerRegistration: 1 } }
			]
		];
		for (const [name, change, options] of refusals) {
			it(`refuses a registration ${name}`, async function () {
				await start(options);
				const { standby } = await register(identity(1), change);
				expect(await standby.closeCode()).to.equal(PORCH_CLOSE_REFUSED);
				expect(relay.stats()).to.include({
					hosts: 0,
					standbys: 0,
					refusedRegistrations: 1
				});
			});
		}

		it('refuses a registration replayed on another connection', async function () {
			await start();
			const host = identity(1);
			let recorded: IPorchRegister | undefined;
			const first = await register(host, {
				message: (m): IPorchRegister => (recorded = m)
			});
			expect(await first.standby.control()).to.deep.equal({ t: 'ready' });
			const replay = await register(host, {
				message: (): IPorchRegister => recorded as IPorchRegister
			});
			expect(await replay.standby.closeCode()).to.equal(PORCH_CLOSE_REFUSED);
			expect(relay.stats()).to.include({ standbys: 1 });
		});

		it('accepts the token a private relay asks for', async function () {
			await start({ token: 'open sesame' });
			await standbyFor(identity(1), { token: 'open sesame' });
			expect(relay.stats()).to.include({ standbys: 1 });
		});

		it('drops a connection that does not register in time', async function () {
			await start({ limits: { registerTimeoutMs: 80 } });
			const silent = await client('/v1/host').open();
			await silent.control();
			expect(await silent.closeCode()).to.equal(PORCH_CLOSE_REFUSED);
		});

		it('drops a standby that sends anything but a pong', async function () {
			await start();
			const host = identity(1);
			const bytes = await standbyFor(host);
			bytes.ws.send(Buffer.from('act one'));
			expect(await bytes.closeCode()).to.equal(WsCloseCode.PROTOCOL_ERROR);
			const again = await standbyFor(host);
			again.sendControl({ t: 'ready' });
			expect(await again.closeCode()).to.equal(WsCloseCode.PROTOCOL_ERROR);
			const garbage = await standbyFor(host);
			garbage.ws.send('{"t":');
			expect(await garbage.closeCode()).to.equal(WsCloseCode.PROTOCOL_ERROR);
			expect(relay.stats()).to.include({ hosts: 0, standbys: 0 });
		});
	});

	describe('pairing', function () {
		it('tells the host which link was used, then copies bytes both ways', async function () {
			await start();
			const host = identity(1, 2);
			const standby = await standbyFor(host);
			const visitor = await client(`/v1/p/${host.routeIds[1]}`).open();
			expect(await standby.control()).to.deep.equal({
				t: 'paired',
				tag: host.tags[1].toString('hex')
			});
			visitor.ws.send(Buffer.from('act one'));
			await waitFor(() => standby.received() === 'act one', 'visitor bytes');
			standby.ws.send(Buffer.from('act two'));
			await waitFor(() => visitor.received() === 'act two', 'host bytes');
			const big = crypto.randomBytes(65_569);
			visitor.ws.send(big);
			await waitFor(
				() => Buffer.concat(standby.binary).length === 7 + big.length,
				'a full-size message'
			);
			expect(Buffer.concat(standby.binary).subarray(7)).to.deep.equal(big);
			// The visitor never sees a control message.
			expect(visitor.texts).to.deep.equal([]);
			expect(relay.stats()).to.include({
				hosts: 1,
				standbys: 0,
				circuits: 1,
				paired: 1
			});
		});

		it('delivers what a visitor sent before it was paired, after `paired` and in order', async function () {
			await start({ limits: { pairWaitMs: 2_000 } });
			const host = identity(1);
			// The first bytes ride in the same segment as the upgrade request.
			const visitor = await raw(`/v1/p/${host.routeIds[0]}`, {
				trailing: masked(WsOpcode.BINARY, Buffer.from('one|'))
			});
			visitor.socket.write(masked(WsOpcode.BINARY, Buffer.from('two|')));
			await waitFor(() => relay.stats().visitorsWaiting === 1, 'the visitor');
			const standby = await standbyFor(host);
			visitor.socket.write(masked(WsOpcode.BINARY, Buffer.from('three')));
			await waitFor(() => standby.received() === 'one|two|three', 'held bytes');
			// challenge, ready, paired, and only then the bytes.
			expect(standby.order.slice(0, 4)).to.deep.equal([
				'text',
				'text',
				'text',
				'binary'
			]);
			expect(standby.order.lastIndexOf('text')).to.equal(2);
			expect(await standby.control()).to.deep.equal({
				t: 'paired',
				tag: host.tags[0].toString('hex')
			});
		});

		it('passes fragments through as fragments and answers pings itself', async function () {
			await start();
			const host = identity(1);
			const standby = await standbyFor(host);
			const visitor = await raw(`/v1/p/${host.routeIds[0]}`);
			await standby.control();
			visitor.socket.write(
				Buffer.concat([
					masked(WsOpcode.BINARY, Buffer.from('frag-'), false),
					masked(WsOpcode.PING, Buffer.from('mid')),
					masked(WsOpcode.CONTINUATION, Buffer.from('ment'), true)
				])
			);
			// The client reassembles: one message, so the frames arrived whole.
			await waitFor(() => standby.binary.length === 1, 'the message');
			expect(standby.received()).to.equal('frag-ment');
			await waitFor(
				() => visitor.frames.some((f) => f.opcode === WsOpcode.PONG),
				'the pong'
			);
			expect(
				visitor.frames
					.find((f) => f.opcode === WsOpcode.PONG)
					?.payload.toString()
			).to.equal('mid');
		});

		it('turns a visitor away when no standby appears', async function () {
			await start({ limits: { pairWaitMs: 80 } });
			const started = Date.now();
			const visitor = await client(`/v1/p/${identity(1).routeIds[0]}`).open();
			expect(await visitor.closeCode()).to.equal(PORCH_CLOSE_TRY_LATER);
			// Held for the wait it was configured with, not the default 3 s.
			expect(Date.now() - started).to.be.within(75, 2_500);
			expect(relay.stats()).to.include({
				visitorsWaiting: 0,
				visitorsTurnedAway: 1
			});
		});

		it('uses one standby for one circuit, and the next visitor waits for the next standby', async function () {
			await start({ limits: { pairWaitMs: 2_000 } });
			const host = identity(1);
			const first = await standbyFor(host);
			const a = await client(`/v1/p/${host.routeIds[0]}`).open();
			await first.control();
			const b = await client(`/v1/p/${host.routeIds[0]}`).open();
			await waitFor(() => relay.stats().visitorsWaiting === 1, 'b waiting');
			b.ws.send(Buffer.from('from b'));
			const second = await standbyFor(host);
			expect((await second.control()).t).to.equal('paired');
			await waitFor(() => second.received() === 'from b', 'b through');
			a.ws.send(Buffer.from('from a'));
			await waitFor(() => first.received() === 'from a', 'a through');
			expect(relay.stats()).to.include({ circuits: 2, standbys: 0, paired: 2 });
		});

		it('routes each link to the host that registered it', async function () {
			await start();
			const one = identity(1);
			const two = identity(2);
			const standbyOne = await standbyFor(one);
			const standbyTwo = await standbyFor(two);
			const visitor = await client(`/v1/p/${two.routeIds[0]}`).open();
			expect((await standbyTwo.control()).t).to.equal('paired');
			visitor.ws.send(Buffer.from('for two'));
			await waitFor(() => standbyTwo.received() === 'for two', 'bytes');
			expect(standbyOne.texts).to.have.length(2);
			expect(standbyOne.binary).to.have.length(0);
		});

		it('ends a route when its last standby goes: a revoked link stops resolving', async function () {
			await start({ limits: { pairWaitMs: 80 } });
			const host = identity(1, 2);
			const both = await standbyFor(host);
			both.ws.close();
			await waitFor(() => relay.stats().standbys === 0, 'the old standby gone');
			// The host comes back listing one link fewer.
			await standbyFor(host, { tags: [host.tags[0]] });
			const revoked = await client(`/v1/p/${host.routeIds[1]}`).open();
			expect(await revoked.closeCode()).to.equal(PORCH_CLOSE_TRY_LATER);
			const kept = await client(`/v1/p/${host.routeIds[0]}`).open();
			kept.ws.send(Buffer.from('still here'));
			await sleep(150);
			expect(kept.closed).to.equal(undefined);
		});
	});

	describe('what a circuit carries', function () {
		async function circuit(): Promise<{ standby: Client; visitor: Client }> {
			const host = identity(1);
			const standby = await standbyFor(host);
			const visitor = await client(`/v1/p/${host.routeIds[0]}`).open();
			await standby.control();
			return { standby, visitor };
		}

		it('closes a visitor that sends text, before pairing or after', async function () {
			await start({ limits: { pairWaitMs: 2_000 } });
			const early = await client(`/v1/p/${identity(9).routeIds[0]}`).open();
			early.ws.send('{"t":"ready"}');
			expect(await early.closeCode()).to.equal(WsCloseCode.UNSUPPORTED_DATA);
			const { standby, visitor } = await circuit();
			visitor.ws.send('{"t":"paired"}');
			expect(await visitor.closeCode()).to.equal(WsCloseCode.UNSUPPORTED_DATA);
			// The host is told the circuit is over, and never sees the text.
			expect(await standby.closeCode()).to.equal(WsCloseCode.GOING_AWAY);
			expect(standby.texts).to.have.length(3);
		});

		it('closes a paired host that sends text', async function () {
			await start();
			const { standby, visitor } = await circuit();
			standby.sendControl({ t: 'pong' });
			expect(await standby.closeCode()).to.equal(WsCloseCode.UNSUPPORTED_DATA);
			expect(await visitor.closeCode()).to.equal(WsCloseCode.GOING_AWAY);
			expect(visitor.texts).to.deep.equal([]);
			expect(relay.stats()).to.include({ circuits: 0, hosts: 0 });
		});

		it('closes the other side when one side closes, cleanly or not', async function () {
			await start();
			const clean = await circuit();
			clean.visitor.ws.close(1000);
			expect(await clean.standby.closeCode()).to.equal(WsCloseCode.NORMAL);
			const coded = await circuit();
			// An application code, which the interface allows and the client sends.
			(coded.standby.ws as IWebSocketLike).close(4001);
			expect(await coded.visitor.closeCode()).to.equal(4001);
			const cut = await circuit();
			(cut.standby.ws as unknown as { socket: net.Socket }).socket.destroy();
			expect(await cut.visitor.closeCode()).to.equal(WsCloseCode.GOING_AWAY);
			await waitFor(() => relay.stats().circuits === 0, 'circuits gone');
			expect(relay.stats()).to.include({ hosts: 0, standbys: 0 });
		});

		it('closes a circuit that has carried nothing for circuitIdleMs', async function () {
			await start({ limits: { circuitIdleMs: 1_000 } });
			const { standby, visitor } = await circuit();
			// Traffic keeps it open well past the limit.
			for (let i = 0; i < 9; i++) {
				await sleep(200);
				visitor.ws.send(Buffer.from('.'));
			}
			expect(standby.closed).to.equal(undefined);
			expect(await standby.closeCode()).to.equal(WsCloseCode.GOING_AWAY);
			expect(await visitor.closeCode()).to.equal(WsCloseCode.GOING_AWAY);
		});

		it('refuses a frame over messageBytes', async function () {
			await start({ limits: { messageBytes: 64 * 1024 } });
			const { standby, visitor } = await circuit();
			visitor.ws.send(Buffer.alloc(64 * 1024));
			await waitFor(
				() => Buffer.concat(standby.binary).length === 64 * 1024,
				'the frame at the cap'
			);
			visitor.ws.send(Buffer.alloc(64 * 1024 + 1));
			expect(await visitor.closeCode()).to.equal(WsCloseCode.MESSAGE_TOO_BIG);
			expect(await standby.closeCode()).to.equal(WsCloseCode.GOING_AWAY);
		});

		it('does not stall a circuit whose queue limit is smaller than a socket buffer', async function () {
			// Nothing is owed a 'drain' below the socket's own high-water mark,
			// so a sender paused there would never be resumed.
			await start({ limits: { queueBytes: 1 } });
			const { standby, visitor } = await circuit();
			const total = 400 * 4096;
			for (let i = 0; i < 400; i++) visitor.ws.send(Buffer.alloc(4096, 5));
			await waitFor(
				() => Buffer.concat(standby.binary).length === total,
				'every byte'
			);
			for (let i = 0; i < 400; i++) standby.ws.send(Buffer.alloc(4096, 6));
			await waitFor(
				() => Buffer.concat(visitor.binary).length === total,
				'every byte back'
			);
		});

		it('pauses a fast sender while the other side is not reading, and loses nothing', async function () {
			this.timeout(120_000);
			const queueBytes = 256 * 1024;
			await start({ limits: { queueBytes } });
			const host = identity(1);
			const standby = await standbyFor(host);
			const visitor = await raw(`/v1/p/${host.routeIds[0]}`);
			await standby.control();
			const chunk = Buffer.alloc(32 * 1024, 7);
			const hostSocket = (standby.ws as unknown as { socket: net.Socket })
				.socket;
			const backedUp = (): boolean => hostSocket.writableLength > 1024 * 1024;
			let peak = 0;
			const sample = setInterval(() => {
				for (const relaySocket of (
					relay as unknown as { sockets: Set<net.Socket> }
				).sockets) {
					peak = Math.max(peak, relaySocket.writableLength);
				}
			}, 2);
			// The visitor stops reading and the host sends for as long as its
			// own socket takes it. Only the relay refusing to read can stop it.
			visitor.socket.pause();
			let sent = 0;
			let stop = false;
			const sending = (async (): Promise<void> => {
				while (!stop) {
					if (sent >= 128 * 1024 * 1024) {
						throw new Error('the relay took everything it was sent');
					}
					standby.ws.send(chunk);
					sent += chunk.length;
					if (backedUp()) {
						await new Promise<void>((resolve) =>
							hostSocket.once('drain', () => resolve())
						);
					} else if (sent % (1024 * 1024) === 0) {
						await sleep(0);
					}
				}
			})();
			try {
				// The sender has stalled once the relay holds more than its limit
				// for the visitor, the sender's own socket still holds bytes and
				// it has sent nothing for half a second. Its socket need not be
				// over the mark it waits at: a stall can leave it anywhere above
				// empty.
				let last = -1;
				let since = Date.now();
				const stalled = (): boolean => {
					if (sent !== last) {
						last = sent;
						since = Date.now();
					}
					return (
						peak > queueBytes &&
						hostSocket.writableLength > 0 &&
						Date.now() - since >= 500
					);
				};
				await Promise.race([
					sending,
					waitFor(stalled, 'the sender stalling', 40_000)
				]);
				// What the relay holds is its limit and the read that crossed it,
				// not the megabytes behind them.
				expect(peak).to.be.greaterThan(queueBytes);
				expect(peak).to.be.lessThan(queueBytes + 4 * 65_536);
				stop = true;
				visitor.socket.resume();
				await sending;
				const received = (): number =>
					visitor.frames.reduce((n, f) => n + f.payload.length, 0);
				await waitFor(() => received() === sent, 'every byte', 20_000);
				expect(visitor.frames.every((f) => f.payload.every((b) => b === 7))).to
					.be.true;
				expect(peak).to.be.lessThan(queueBytes + 4 * 65_536);
			} finally {
				stop = true;
				clearInterval(sample);
			}
		});
	});

	describe('limits', function () {
		it('replaces the oldest standby when a host is at its cap', async function () {
			await start({ limits: { standbysPerHost: 2 } });
			const host = identity(1);
			const oldest = await standbyFor(host);
			const middle = await standbyFor(host);
			const newest = await standbyFor(host);
			expect(await oldest.closeCode()).to.equal(WsCloseCode.GOING_AWAY);
			expect(relay.stats()).to.include({ hosts: 1, standbys: 2 });
			expect(middle.closed).to.equal(undefined);
			expect(newest.closed).to.equal(undefined);
		});

		it('keeps a host with a cap of one standby reachable across a replacement', async function () {
			await start({ limits: { standbysPerHost: 1 } });
			const host = identity(1);
			const old = await standbyFor(host);
			const fresh = await standbyFor(host);
			expect(await old.closeCode()).to.equal(WsCloseCode.GOING_AWAY);
			expect(relay.stats()).to.include({ hosts: 1, standbys: 1 });
			const visitor = await client(`/v1/p/${host.routeIds[0]}`).open();
			expect((await fresh.control()).t).to.equal('paired');
			visitor.ws.send(Buffer.from('hello'));
			await waitFor(() => fresh.received() === 'hello', 'bytes');
		});

		it('turns a visitor away at circuitsPerHost and leaves the standby for the next', async function () {
			await start({ limits: { circuitsPerHost: 1, pairWaitMs: 2_000 } });
			const host = identity(1);
			const first = await standbyFor(host);
			const a = await client(`/v1/p/${host.routeIds[0]}`).open();
			await first.control();
			const spare = await standbyFor(host);
			const b = await client(`/v1/p/${host.routeIds[0]}`).open();
			expect(await b.closeCode()).to.equal(PORCH_CLOSE_TRY_LATER);
			expect(relay.stats()).to.include({ circuits: 1, standbys: 1 });
			// When the first circuit ends, the spare serves the next visitor.
			a.ws.close();
			await waitFor(() => relay.stats().circuits === 0, 'the circuit ending');
			await client(`/v1/p/${host.routeIds[0]}`).open();
			expect((await spare.control()).t).to.equal('paired');
		});

		it('takes no new host key past the hosts cap, and takes one again when a host leaves', async function () {
			await start({ limits: { hosts: 1 } });
			const one = await standbyFor(identity(1));
			// A second standby of the same host is not a new host.
			await standbyFor(identity(1));
			const { standby: refused } = await register(identity(2));
			expect(await refused.closeCode()).to.equal(PORCH_CLOSE_TRY_LATER);
			one.ws.close();
			for (const c of clients) c.ws.close();
			await waitFor(() => relay.stats().hosts === 0, 'the host leaving');
			await standbyFor(identity(2));
			expect(relay.stats()).to.include({ hosts: 1 });
		});

		it('caps visitors and unpaired connections per source address', async function () {
			await start({
				addressKey: () => 'one-source',
				limits: {
					visitorsPerAddress: 2,
					pendingPerAddress: 3,
					pairWaitMs: 2_000
				}
			});
			const host = identity(1);
			const path = `/v1/p/${host.routeIds[0]}`;
			// Two visitors pair; they still count as visitors, not as pending.
			for (let i = 0; i < 2; i++) {
				const standby = await standbyFor(host);
				await client(path).open();
				await standby.control();
			}
			expect((await raw(path)).status).to.match(/ 429 /);
			expect(relay.stats().visitorsTurnedAway).to.equal(1);
			// Pending: three connections that have not registered.
			const pending = [];
			for (let i = 0; i < 3; i++) pending.push(await raw('/v1/host'));
			expect(pending.map((p) => p.status.includes(' 101 '))).to.deep.equal([
				true,
				true,
				true
			]);
			expect((await raw('/v1/host')).status).to.match(/ 429 /);
			// One of them goes away, and there is room for one again.
			pending[0].socket.destroy();
			await waitFor(
				() =>
					(
						relay as unknown as { pendingByAddress: Map<string, number> }
					).pendingByAddress.get('one-source') === 2,
				'the slot coming back'
			);
			expect((await raw('/v1/host')).status).to.match(/ 101 /);
		});

		it('caps idle standbys per source address, whatever keys they registered', async function () {
			await start({
				addressKey: () => 'one-source',
				limits: { standbysPerAddress: 2 }
			});
			const one = identity(1);
			const first = await standbyFor(one);
			const second = await standbyFor(identity(2));
			const refused = await register(identity(3));
			expect(await refused.standby.closeCode()).to.equal(PORCH_CLOSE_TRY_LATER);
			expect(relay.stats()).to.include({ hosts: 2, standbys: 2 });
			// A standby that leaves makes room for one.
			second.ws.close();
			await waitFor(() => relay.stats().standbys === 1, 'a standby leaving');
			await standbyFor(identity(3));
			expect(await (await register(identity(4))).standby.closeCode()).to.equal(
				PORCH_CLOSE_TRY_LATER
			);
			// So does one that is paired: it is a circuit now, not a standby.
			await client(`/v1/p/${one.routeIds[0]}`).open();
			expect((await first.control()).t).to.equal('paired');
			await standbyFor(identity(4));
			expect(relay.stats()).to.include({ hosts: 3, standbys: 2, circuits: 1 });
		});

		it('limits how fast one source address may start upgrades', async function () {
			await start({
				trustedProxies: ['127.0.0.1'],
				addressKey: (address) => address ?? null,
				limits: { upgradesPerMinute: 3 }
			});
			const from = async (source: string, path: string): Promise<string> => {
				const c = await raw(path, {
					headers: [`X-Forwarded-For: ${source}`]
				});
				c.socket.destroy();
				return c.status.split(' ')[1];
			};
			const visitorPath = `/v1/p/${identity(1).routeIds[0]}`;
			expect([
				await from('203.0.113.5', '/v1/host'),
				await from('203.0.113.5', visitorPath),
				await from('203.0.113.5', '/v1/host'),
				await from('203.0.113.5', '/v1/host'),
				await from('203.0.113.5', visitorPath)
			]).to.deep.equal(['101', '101', '101', '429', '429']);
			// Another source has its own allowance.
			expect(await from('198.51.100.7', '/v1/host')).to.equal('101');
		});

		it('does not limit a source the address rule leaves unlimited', async function () {
			await start({ limits: { pendingPerAddress: 1 } });
			// Loopback under the default rule.
			expect((await raw('/v1/host')).status).to.match(/ 101 /);
			expect((await raw('/v1/host')).status).to.match(/ 101 /);
		});

		it('counts a proxied connection under the address its own proxy saw', async function () {
			const seen: string[] = [];
			await start({
				trustedProxies: ['127.0.0.1'],
				addressKey: (address) => {
					seen.push(address ?? '');
					return address ?? null;
				},
				limits: { pendingPerAddress: 1 }
			});
			const from = (forwarded: string): Promise<{ status: string }> =>
				raw('/v1/host', { headers: [`X-Forwarded-For: ${forwarded}`] });
			expect((await from('203.0.113.5')).status).to.match(/ 101 /);
			expect((await from('203.0.113.5')).status).to.match(/ 429 /);
			// The left of the list is the client's own claim and is not believed.
			expect((await from('198.51.100.1, 203.0.113.5')).status).to.match(
				/ 429 /
			);
			expect((await from('203.0.113.5, 198.51.100.7')).status).to.match(
				/ 101 /
			);
			expect(seen).to.deep.equal([
				'203.0.113.5',
				'203.0.113.5',
				'203.0.113.5',
				'198.51.100.7'
			]);
		});

		it('ignores X-Forwarded-For from a peer it was not told to trust', async function () {
			const seen: string[] = [];
			await start({
				addressKey: (address) => {
					seen.push(address ?? '');
					return null;
				}
			});
			await raw('/v1/host', { headers: ['X-Forwarded-For: 203.0.113.5'] });
			expect(seen).to.deep.equal(['127.0.0.1']);
		});

		it('closes a visitor that sends more than it may hold before pairing', async function () {
			await start({ limits: { visitorHoldBytes: 1024, pairWaitMs: 2_000 } });
			const visitor = await client(`/v1/p/${identity(1).routeIds[0]}`).open();
			visitor.ws.send(Buffer.alloc(1024));
			await sleep(50);
			expect(visitor.closed).to.equal(undefined);
			visitor.ws.send(Buffer.alloc(1));
			expect(await visitor.closeCode()).to.equal(WsCloseCode.MESSAGE_TOO_BIG);
		});
	});

	describe('liveness', function () {
		it('pings idle standbys, keeps the ones that answer and drops the ones that do not', async function () {
			await start({ limits: { pingIntervalMs: 40, missedPings: 2 } });
			const host = identity(1);
			const live = await standbyFor(host);
			const dead = await standbyFor(identity(2));
			// Answered as each ping arrives, the way a host does.
			let answered = 0;
			live.onText = (text): void => {
				if (decodePorchControl(text)?.t !== 'ping') return;
				answered++;
				live.sendControl({ t: 'pong' });
			};
			expect(await dead.closeCode()).to.equal(WsCloseCode.GOING_AWAY);
			expect(dead.texts.slice(2)).to.deep.equal([
				'{"t":"ping"}',
				'{"t":"ping"}'
			]);
			await waitFor(() => answered > 6, 'more pings');
			expect(live.closed).to.equal(undefined);
			expect(relay.stats()).to.include({ hosts: 1, standbys: 1 });
		});

		it('does not ping a standby once it is paired', async function () {
			await start({ limits: { pingIntervalMs: 30, missedPings: 1 } });
			const host = identity(1);
			const standby = await standbyFor(host);
			await client(`/v1/p/${host.routeIds[0]}`).open();
			await waitFor(
				() => standby.texts.some((t) => t.includes('paired')),
				'paired'
			);
			const before = standby.texts.length;
			await sleep(150);
			expect(standby.texts.length).to.equal(before);
			expect(standby.closed).to.equal(undefined);
		});
	});

	describe('serving TLS itself', function () {
		let dir: string;
		let key: string;
		let cert: string;
		let stub: sinon.SinonStub;

		before(function () {
			dir = fs.mkdtempSync(nodePath.join(os.tmpdir(), 'beignet-porch-'));
			const keyPath = nodePath.join(dir, 'key.pem');
			const certPath = nodePath.join(dir, 'cert.pem');
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

		beforeEach(function () {
			// The test certificate is its own authority: trust it for these
			// dials and change nothing else about them.
			const original = tls.connect.bind(tls) as (
				options: tls.ConnectionOptions,
				listener?: () => void
			) => tls.TLSSocket;
			stub = sinon
				.stub(tls, 'connect')
				.callsFake(((options: tls.ConnectionOptions, listener?: () => void) =>
					original(
						{ ...options, ca: cert },
						listener
					)) as unknown as typeof tls.connect);
		});

		afterEach(function () {
			stub.restore();
		});

		it('registers, pairs and copies over wss://, and counts a connection once', async function () {
			await start({ authorities: ['localhost'], tls: { key, cert } });
			const secure = (path: string): Client => {
				const c = new Client(port, path, 'localhost', true);
				clients.push(c);
				return c;
			};
			const host = identity(1);
			const standby = await secure('/v1/host').open();
			const challenge = (await standby.control()) as IPorchChallenge;
			expect(challenge.authority).to.equal('localhost');
			standby.sendControl(
				createPorchRegister({
					hostSecret: host.secret,
					nonce: Buffer.from(challenge.nonce, 'hex'),
					authority: 'localhost',
					tags: host.tags
				})
			);
			expect(await standby.control()).to.deep.equal({ t: 'ready' });
			const visitor = await secure(`/v1/p/${host.routeIds[0]}`).open();
			expect((await standby.control()).t).to.equal('paired');
			visitor.ws.send(Buffer.from('over tls'));
			await waitFor(() => standby.received() === 'over tls', 'visitor bytes');
			standby.ws.send(Buffer.from('and back'));
			await waitFor(() => visitor.received() === 'and back', 'host bytes');
			expect(relay.stats()).to.include({ connections: 2, circuits: 1 });

			// A client that does not speak TLS gets nowhere.
			const plain = new Client(port, '/v1/host', 'localhost');
			clients.push(plain);
			await plain.closeCode();
			expect(plain.texts).to.deep.equal([]);

			await relay.close();
			await standby.closeCode();
			await visitor.closeCode();
			expect(relay.stats()).to.include({ connections: 0, circuits: 0 });
		});
	});

	describe('shutdown', function () {
		it('drops every connection and stops listening', async function () {
			await start({ limits: { pairWaitMs: 2_000 } });
			const host = identity(1);
			const standby = await standbyFor(host);
			const visitor = await client(`/v1/p/${host.routeIds[0]}`).open();
			await standby.control();
			const idle = await standbyFor(host);
			const waiting = await client(`/v1/p/${identity(3).routeIds[0]}`).open();
			await relay.close();
			for (const c of [standby, visitor, idle, waiting]) {
				await c.closeCode();
			}
			await new Promise<void>((resolve) => {
				const probe = net.createConnection(port, '127.0.0.1');
				probe.on('error', () => resolve());
				probe.on('connect', () => {
					throw new Error('still listening');
				});
			});
		});
	});
});
