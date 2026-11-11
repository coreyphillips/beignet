/**
 * The Porch host (src/lightning/transport/porch-host.ts) against a real
 * relay in the same process: standbys, pairing, what reaches the peer layer,
 * and how it behaves when the relay refuses, vanishes or goes quiet.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import net from 'net';
import { IPorchRelayOptions, PorchRelay } from '../../src/cli/porch-relay';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	PORCH_CLOSE_TRY_LATER,
	parsePorchRelayUrl,
	porchRouteId
} from '../../src/lightning/transport/porch';
import {
	IPorchHostOptions,
	IPorchHostStatus,
	MAX_PORCH_STANDBYS,
	PORCH_PRE_HANDSHAKE_MAX_BYTES,
	PorchCircuitTransport,
	PorchHost
} from '../../src/lightning/transport/porch-host';
import {
	WsFrameParser,
	WsOpcode,
	decodeWsClosePayload,
	encodeWsFrame
} from '../../src/lightning/transport/websocket-frame';
import {
	NodeWebSocket,
	nodeWebSocketVia
} from '../../src/lightning/transport/websocket-node-client';

const RELAY_URL = 'ws://relay.test';

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

describe('Porch host', function () {
	const secret = Buffer.alloc(32, 5);
	const key = getPublicKey(secret);
	const tagA = Buffer.alloc(16, 0xa1);
	const tagB = Buffer.alloc(16, 0xb2);
	const route = (tag: Buffer): string => porchRouteId(key, tag);

	let relay: PorchRelay | undefined;
	let port = 0;
	let dials = 0;
	const hosts: PorchHost[] = [];
	const sockets: net.Socket[] = [];
	const visitors: NodeWebSocket[] = [];

	async function startRelay(
		options: Partial<IPorchRelayOptions> = {},
		onPort = 0
	): Promise<PorchRelay> {
		relay = new PorchRelay({ authorities: ['relay.test'], ...options });
		await relay.listen(onPort, '127.0.0.1');
		port = (relay.address() as net.AddressInfo).port;
		return relay;
	}

	/** A host that dials whatever `port` is when the dial happens. */
	function host(
		options: Partial<IPorchHostOptions> = {},
		circuits: PorchCircuitTransport[] = []
	): PorchHost {
		const h = new PorchHost({
			relay: parsePorchRelayUrl(RELAY_URL),
			hostSecret: secret,
			tags: (): Buffer[] => [tagA],
			webSocket: nodeWebSocketVia((): net.Socket => {
				dials++;
				return net.createConnection(port, '127.0.0.1');
			}),
			onCircuit: (circuit): void => {
				circuits.push(circuit);
			},
			...options,
			timing: {
				backoffMs: 20,
				maxBackoffMs: 80,
				refusedBackoffMs: 60_000,
				dialRefillMs: 20,
				...options.timing
			}
		});
		hosts.push(h);
		return h;
	}

	function visit(tag: Buffer): NodeWebSocket {
		const ws = new NodeWebSocket(`${RELAY_URL}/v1/p/${route(tag)}`, {
			connect: (): net.Socket => net.createConnection(port, '127.0.0.1')
		});
		visitors.push(ws);
		return ws;
	}

	/** A visitor on a raw socket, whose first bytes ride with the upgrade. */
	async function rawVisitor(
		tag: Buffer,
		first: Buffer
	): Promise<{ socket: net.Socket; closeCode: () => number | undefined }> {
		const socket = net.createConnection(port, '127.0.0.1');
		sockets.push(socket);
		socket.on('error', () => undefined);
		const parser = new WsFrameParser({ requireMasked: false });
		let upgraded = false;
		let head = Buffer.alloc(0);
		let code: number | undefined;
		const read = (chunk: Buffer): void => {
			for (const frame of parser.push(chunk)) {
				if (frame.opcode === WsOpcode.CLOSE) {
					code = decodeWsClosePayload(frame.payload).code;
				}
			}
		};
		socket.on('data', (chunk: Buffer) => {
			if (upgraded) return read(chunk);
			head = Buffer.concat([head, chunk]);
			const end = head.indexOf('\r\n\r\n');
			if (end < 0) return;
			upgraded = true;
			read(head.subarray(end + 4));
		});
		socket.write(
			Buffer.concat([
				Buffer.from(
					[
						`GET /v1/p/${route(tag)} HTTP/1.1`,
						'Host: relay.test',
						'Connection: Upgrade',
						'Upgrade: websocket',
						`Sec-WebSocket-Key: ${crypto.randomBytes(16).toString('base64')}`,
						'Sec-WebSocket-Version: 13'
					].join('\r\n') + '\r\n\r\n'
				),
				first
			])
		);
		await waitFor(() => upgraded, 'the upgrade');
		return { socket, closeCode: () => code };
	}

	const masked = (payload: Buffer): Buffer =>
		encodeWsFrame({
			opcode: WsOpcode.BINARY,
			payload,
			maskKey: crypto.randomBytes(4)
		});

	const standbys = (): number => relay?.stats().standbys ?? 0;

	beforeEach(function () {
		dials = 0;
	});

	afterEach(async function () {
		for (const h of hosts.splice(0)) {
			h.stop();
			h.closeCircuits();
		}
		for (const ws of visitors.splice(0)) ws.close();
		for (const s of sockets.splice(0)) s.destroy();
		await relay?.close();
		relay = undefined;
	});

	it('keeps the standbys it was asked for, and says when the links work', async function () {
		await startRelay();
		const h = host({ standbys: 3 });
		const seen: IPorchHostStatus[] = [];
		h.on('status', (status: IPorchHostStatus) => seen.push(status));
		expect(h.status()).to.deep.equal({
			relay: RELAY_URL,
			state: 'stopped',
			idle: 0,
			circuits: 0
		});
		h.start();
		expect(h.status().state).to.equal('connecting');
		await waitFor(() => h.status().idle === 3, 'three standbys');
		expect(h.status()).to.deep.equal({
			relay: RELAY_URL,
			state: 'ready',
			idle: 3,
			circuits: 0
		});
		expect(relay?.stats()).to.include({ hosts: 1, standbys: 3 });
		expect(dials).to.equal(3);
		expect(seen[0].state).to.equal('connecting');
		expect(seen[seen.length - 1]).to.deep.equal(h.status());
		// start() twice is start() once.
		h.start();
		await sleep(60);
		expect(dials).to.equal(3);
	});

	it('is not disturbed by a status observer that throws', async function () {
		await startRelay();
		const circuits: PorchCircuitTransport[] = [];
		const h = host({}, circuits);
		let thrown = 0;
		h.on('status', () => {
			thrown++;
			throw new Error('observer');
		});
		h.start();
		await waitFor(() => h.status().idle === 2, 'standbys');
		visit(tagA);
		await waitFor(() => circuits.length === 1, 'the circuit');
		await waitFor(() => h.status().idle === 2, 'the replacement');
		expect(thrown).to.be.at.least(3);
		expect(relay?.stats()).to.include({ standbys: 2, circuits: 1 });
	});

	it('refuses a standby count the relay would not keep', function () {
		for (const count of [0, MAX_PORCH_STANDBYS + 1, 1.5, NaN]) {
			expect(() => host({ standbys: count })).to.throw(
				/whole number from 1 to 8/
			);
		}
	});

	it('does not connect at all while it has no link to serve', async function () {
		await startRelay();
		let tags: Buffer[] = [];
		const h = host({ tags: () => tags });
		h.start();
		await sleep(80);
		expect(dials).to.equal(0);
		expect(relay?.stats().connections).to.equal(0);
		tags = [tagA];
		h.refresh();
		await waitFor(() => h.status().idle === 2, 'standbys');
	});

	it('hands a paired visitor to the peer layer as a transport, and replaces the standby', async function () {
		await startRelay();
		const circuits: PorchCircuitTransport[] = [];
		const h = host({ tags: () => [tagA, tagB] }, circuits);
		h.start();
		await waitFor(() => standbys() === 2, 'standbys');

		const visitor = visit(tagB);
		const fromHost: Buffer[] = [];
		visitor.onmessage = (ev): void => {
			fromHost.push(Buffer.from(ev.data as ArrayBuffer));
		};
		await waitFor(() => circuits.length === 1, 'the circuit');
		const circuit = circuits[0];
		// All the node learns about where this came from is the relay's name.
		expect(circuit.remoteAddress).to.equal('porch:relay.test');
		expect(circuit.remotePort).to.equal(undefined);
		expect(circuit.transportType).to.equal('ws');
		expect(circuit.porch).to.deep.equal({
			relay: 'relay.test',
			tag: tagB.toString('hex')
		});

		const fromVisitor: Buffer[] = [];
		circuit.on('data', (chunk: Buffer) => fromVisitor.push(chunk));
		await waitFor(() => visitor.readyState === 1, 'the visitor opening');
		visitor.send(Buffer.from('act one'));
		await waitFor(
			() => Buffer.concat(fromVisitor).toString() === 'act one',
			'visitor bytes'
		);
		circuit.write(Buffer.from('act two'));
		await waitFor(
			() => Buffer.concat(fromHost).toString() === 'act two',
			'host bytes'
		);

		// The used standby is replaced, and the circuit is counted.
		await waitFor(() => standbys() === 2, 'the replacement');
		expect(h.status()).to.include({ state: 'ready', idle: 2, circuits: 1 });
		expect(dials).to.equal(3);

		// Either side ending it ends it for the host's count too.
		let closed = false;
		circuit.once('close', () => (closed = true));
		visitor.close();
		await waitFor(() => closed, 'the circuit closing');
		expect(h.status().circuits).to.equal(0);
	});

	it('counts a circuit out when the peer layer ends it, which removes every listener first', async function () {
		await startRelay();
		const circuits: PorchCircuitTransport[] = [];
		const h = host({}, circuits);
		const seen: IPorchHostStatus[] = [];
		h.on('status', (status: IPorchHostStatus) => seen.push(status));
		h.start();
		await waitFor(() => standbys() === 2, 'standbys');
		const visitor = visit(tagA);
		let visitorClosed = false;
		visitor.onclose = (): void => {
			visitorClosed = true;
		};
		await waitFor(() => circuits.length === 1, 'the circuit');
		await waitFor(() => standbys() === 2, 'the replacement');
		expect(h.status().circuits).to.equal(1);
		// What Peer does with a transport it is done with.
		circuits[0].removeAllListeners();
		circuits[0].destroy();
		expect(h.status().circuits).to.equal(0);
		expect(seen[seen.length - 1]).to.include({ circuits: 0, idle: 2 });
		await waitFor(() => visitorClosed, 'the visitor being closed');
		expect(relay?.stats().circuits).to.equal(0);
		// Destroying it again changes nothing.
		circuits[0].destroy();
		expect(h.status().circuits).to.equal(0);
	});

	it('keeps what the visitor sent before anything was listening, in order', async function () {
		await startRelay();
		const circuits: PorchCircuitTransport[] = [];
		host({}, circuits).start();
		await waitFor(() => standbys() === 2, 'standbys');
		// The first bytes reach the relay with the upgrade, so they follow
		// `paired` to the host in the same segment.
		const visitor = await rawVisitor(tagA, masked(Buffer.from('one|')));
		visitor.socket.write(masked(Buffer.from('two|')));
		visitor.socket.write(masked(Buffer.from('three')));
		await waitFor(() => circuits.length === 1, 'the circuit');
		// Nobody attaches for a while, as while a handshake write flushes.
		await sleep(50);
		const got: Buffer[] = [];
		circuits[0].on('data', (chunk: Buffer) => got.push(chunk));
		await waitFor(
			() => Buffer.concat(got).toString() === 'one|two|three',
			'the held bytes'
		);
	});

	it('holds a stranger to a small buffer until the handshake is done', async function () {
		await startRelay({ limits: { visitorHoldBytes: 1024 * 1024 } });
		const circuits: PorchCircuitTransport[] = [];
		host({}, circuits).start();
		await waitFor(() => standbys() === 2, 'standbys');

		const flood = async (): Promise<PorchCircuitTransport> => {
			const before = circuits.length;
			const visitor = visit(tagA);
			await waitFor(() => circuits.length === before + 1, 'the circuit');
			await waitFor(() => visitor.readyState === 1, 'the visitor opening');
			const circuit = circuits[before];
			circuit.on('error', () => undefined);
			return circuit;
		};
		const chunk = Buffer.alloc(64 * 1024);
		const sendTo = (circuit: PorchCircuitTransport, chunks: number): void => {
			const visitor = visitors[circuits.indexOf(circuit)];
			for (let i = 0; i < chunks; i++) visitor.send(chunk);
		};

		// Unread and unproven: closed once it passes the cap.
		const stranger = await flood();
		let strangerClosed = false;
		stranger.once('close', () => (strangerClosed = true));
		sendTo(stranger, PORCH_PRE_HANDSHAKE_MAX_BYTES / chunk.length);
		await sleep(50);
		expect(strangerClosed).to.equal(false);
		sendTo(stranger, 1);
		await waitFor(() => strangerClosed, 'the stranger closing');

		// Established: the same bytes are held.
		const peer = await flood();
		let peerClosed = false;
		peer.once('close', () => (peerClosed = true));
		peer.markEstablished();
		sendTo(peer, 4);
		await sleep(80);
		expect(peerClosed).to.equal(false);
		let held = 0;
		peer.on('data', (data: Buffer) => (held += data.length));
		await waitFor(() => held === 4 * chunk.length, 'the held bytes');
	});

	it('registers the links as they are, and refresh() applies a change', async function () {
		await startRelay({ limits: { pairWaitMs: 60 } });
		let tags = [tagA];
		const circuits: PorchCircuitTransport[] = [];
		const h = host({ tags: () => tags }, circuits);
		h.start();
		await waitFor(() => standbys() === 2, 'standbys');

		const closeCode = (ws: NodeWebSocket): Promise<number | undefined> =>
			new Promise((resolve) => {
				ws.onclose = (ev): void => resolve(ev?.code);
			});
		// A link that was never registered does not resolve.
		expect(await closeCode(visit(tagB))).to.equal(PORCH_CLOSE_TRY_LATER);

		// Added: resolves after refresh().
		tags = [tagA, tagB];
		h.refresh();
		await waitFor(() => h.status().idle === 2, 'fresh standbys');
		visit(tagB);
		await waitFor(() => circuits.length === 1, 'the new link working');

		// Revoked: stops resolving, and its circuit is the caller's to close.
		tags = [tagA];
		h.refresh();
		await waitFor(() => h.status().idle === 2, 'fresh standbys again');
		expect(await closeCode(visit(tagB))).to.equal(PORCH_CLOSE_TRY_LATER);
		expect(h.status().circuits).to.equal(1);
		let closed = false;
		circuits[0].once('close', () => (closed = true));
		h.closeCircuits(tagA.toString('hex'));
		expect(closed).to.equal(false);
		h.closeCircuits(tagB.toString('hex'));
		expect(closed).to.equal(true);
		expect(h.status().circuits).to.equal(0);
		// The link that stayed still works.
		visit(tagA);
		await waitFor(() => circuits.length === 2, 'the kept link working');
	});

	it('re-registers at once when the links change, whatever the visitors left of the allowance', async function () {
		await startRelay();
		let tags = [tagA];
		const circuits: PorchCircuitTransport[] = [];
		// Two dials to start with and the next a long way off.
		const h = host(
			{
				tags: (): Buffer[] => tags,
				timing: { dialBurst: 2, dialRefillMs: 60_000 }
			},
			circuits
		);
		h.start();
		await waitFor(() => h.status().idle === 2, 'standbys');
		expect(dials).to.equal(2);

		// The operator's change is not rationed: a full set, straight away.
		tags = [tagA, tagB];
		h.refresh();
		await waitFor(() => h.status().idle === 2, 'fresh standbys', 2_000);
		expect(dials).to.equal(4);

		// A visitor's is: the set was all the change granted.
		visit(tagB);
		await waitFor(() => circuits.length === 1, 'the circuit');
		await sleep(150);
		expect(dials).to.equal(4);
		expect(h.status()).to.include({ idle: 1, circuits: 1 });
	});

	it('will not register with a relay that answers under another name', async function () {
		await startRelay({ authorities: ['elsewhere.test'] });
		const h = host();
		h.start();
		await waitFor(() => h.status().state === 'unreachable', 'the refusal');
		expect(h.status().lastError).to.equal(
			'the relay answered under another name'
		);
		expect(relay?.stats()).to.include({ hosts: 0, standbys: 0 });
	});

	it('reports a refused registration and does not hammer the relay', async function () {
		await startRelay({ token: 'open sesame' });
		const refused = host({ token: 'open says me' });
		refused.start();
		await waitFor(() => refused.status().state === 'refused', 'the refusal');
		expect(refused.status()).to.deep.equal({
			relay: RELAY_URL,
			state: 'refused',
			idle: 0,
			circuits: 0,
			lastError: 'the relay refused the registration'
		});
		const after = dials;
		await sleep(200);
		// One answer was enough: the next try is refusedBackoffMs away.
		expect(dials).to.equal(after);
		expect(after).to.be.at.most(2);
		refused.stop();

		const welcome = host({ token: 'open sesame' });
		welcome.start();
		await waitFor(() => welcome.status().state === 'ready', 'the registration');
	});

	it('backs off while the relay is away and returns when it is back', async function () {
		// Find a free port, then leave it closed.
		await startRelay();
		const freePort = port;
		await relay?.close();
		relay = undefined;

		const h = host();
		h.start();
		await waitFor(() => h.status().state === 'unreachable', 'the failures');
		expect(h.status().lastError).to.be.a('string');
		const failing = dials;
		await sleep(300);
		// Backing off: a few more tries, not hundreds.
		expect(dials - failing).to.be.within(1, 12);

		await startRelay({}, freePort);
		await waitFor(() => h.status().state === 'ready', 'the return');
		await waitFor(() => h.status().idle === 2, 'both standbys');
		expect(h.status()).to.not.have.property('lastError');
	});

	it('comes back after the relay restarts under it', async function () {
		await startRelay();
		const h = host();
		h.start();
		await waitFor(() => h.status().idle === 2, 'standbys');
		const onPort = port;
		await relay?.close();
		await waitFor(() => h.status().idle === 0, 'the loss');
		await startRelay({}, onPort);
		await waitFor(() => h.status().idle === 2, 'the return');
		expect(relay?.stats()).to.include({ hosts: 1, standbys: 2 });
	});

	it('answers the relay, so its standbys are kept', async function () {
		await startRelay({ limits: { pingIntervalMs: 25, missedPings: 1 } });
		const h = host();
		h.start();
		await waitFor(() => h.status().idle === 2, 'standbys');
		await sleep(300);
		expect(relay?.stats()).to.include({ standbys: 2 });
		expect(dials).to.equal(2);
	});

	it('replaces a standby that hears nothing', async function () {
		// The relay's pings are a long way apart, so the host hears nothing.
		await startRelay({ limits: { pingIntervalMs: 60_000 } });
		const h = host({ standbys: 1, timing: { silenceMs: 80 } });
		h.start();
		await waitFor(() => h.status().idle === 1, 'the standby');
		expect(dials).to.equal(1);
		await waitFor(() => dials >= 3, 'two replacements');
		await waitFor(() => h.status().idle === 1, 'a standby again');
		expect(relay?.stats().standbys).to.be.at.most(1);
	});

	it('gives up on a relay that never completes the registration', async function () {
		// Accepts the connection and the upgrade, then says nothing.
		const silent = net.createServer((socket) => {
			sockets.push(socket);
			socket.on('error', () => undefined);
			socket.once('data', (request: Buffer) => {
				const keyLine = /sec-websocket-key: (.+)\r\n/i.exec(request.toString());
				const accept = crypto
					.createHash('sha1')
					.update((keyLine?.[1] ?? '') + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
					.digest('base64');
				socket.write(
					'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n' +
						`Connection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`
				);
			});
		});
		await new Promise<void>((resolve) =>
			silent.listen(0, '127.0.0.1', () => resolve())
		);
		port = (silent.address() as net.AddressInfo).port;
		try {
			const h = host({ standbys: 1, timing: { registerTimeoutMs: 60 } });
			h.start();
			await waitFor(() => h.status().state === 'unreachable', 'the timeouts');
			expect(h.status().lastError).to.equal(
				'the relay did not complete the registration in time'
			);
		} finally {
			silent.close();
		}
	});

	it('opens no more connections than its allowance when visitors flood a link', async function () {
		await startRelay({ limits: { pairWaitMs: 40 } });
		const circuits: PorchCircuitTransport[] = [];
		// Two to start with, one more in the allowance, and the next a long
		// way off.
		const h = host(
			{ timing: { dialBurst: 3, dialRefillMs: 60_000 } },
			circuits
		);
		h.start();
		await waitFor(() => standbys() === 2, 'standbys');
		for (let i = 0; i < 12; i++) visit(tagA);
		await waitFor(() => circuits.length === 3, 'the circuits it could serve');
		await sleep(200);
		expect(dials).to.equal(3);
		expect(circuits).to.have.length(3);
		expect(h.status()).to.include({
			idle: 0,
			circuits: 3,
			state: 'connecting'
		});
	});

	it('stop() closes the standbys, leaves the circuits and opens nothing more', async function () {
		await startRelay();
		const circuits: PorchCircuitTransport[] = [];
		const h = host({}, circuits);
		h.start();
		await waitFor(() => standbys() === 2, 'standbys');
		visit(tagA);
		await waitFor(() => circuits.length === 1, 'the circuit');
		await waitFor(() => standbys() === 2, 'the replacement');
		const before = dials;
		h.stop();
		expect(h.status()).to.deep.equal({
			relay: RELAY_URL,
			state: 'stopped',
			idle: 0,
			circuits: 1
		});
		await waitFor(() => standbys() === 0, 'the standbys closing');
		await sleep(100);
		expect(dials).to.equal(before);
		expect(relay?.stats().circuits).to.equal(1);
		h.closeCircuits();
		await waitFor(() => relay?.stats().circuits === 0, 'the circuit closing');
		// It can be started again.
		h.start();
		await waitFor(() => h.status().idle === 2, 'standbys again');
	});
});
