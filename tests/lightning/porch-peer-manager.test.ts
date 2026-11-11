/**
 * Porch in the peer manager (issue #1980): how a relay is dialed, what a bad
 * configuration is, and how visitors that arrive through a relay are
 * admitted, listed and let go.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import net from 'net';
import { IPorchRelayOptions, PorchRelay } from '../../src/cli/porch-relay';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	DEFAULT_TOR_PROXY,
	IPeerManagerOptions,
	PeerManager,
	selectPorchProxy
} from '../../src/lightning/transport/peer-manager';
import { parsePeerUri } from '../../src/lightning/transport/peer-uri';
import {
	PORCH_CLOSE_TRY_LATER,
	PORCH_MAX_TAGS,
	derivePorchHostSecret,
	porchRouteId
} from '../../src/lightning/transport/porch';
import type {
	IPorchConfig,
	IPorchHostStatus
} from '../../src/lightning/transport/porch-host';
import {
	WsOpcode,
	encodeWsFrame
} from '../../src/lightning/transport/websocket-frame';
import { NodeWebSocket } from '../../src/lightning/transport/websocket-node-client';

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
		await sleep(10);
	}
}

async function freePort(): Promise<number> {
	const server = net.createServer();
	await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
	const { port } = server.address() as net.AddressInfo;
	await new Promise<void>((resolve) => server.close(() => resolve()));
	return port;
}

describe('Porch in the peer manager', function () {
	this.timeout(20_000);

	const hostSecret = derivePorchHostSecret(Buffer.alloc(32, 9));
	const hostKey = getPublicKey(hostSecret);
	const tagA = Buffer.alloc(16, 0xa1);
	const tagB = Buffer.alloc(16, 0xb2);
	const tagC = Buffer.alloc(16, 0xc3);
	const proxy = { host: '127.0.0.1', port: 19050 };

	describe('how a relay is dialed', function () {
		const rows: Array<
			[
				string,
				'direct' | 'tor' | undefined,
				typeof proxy | undefined,
				'all' | 'onion',
				typeof proxy | undefined
			]
		> = [
			// Left alone, a relay is dialed as a peer at that host would be.
			['relay.example', undefined, undefined, 'all', undefined],
			['relay.example', undefined, proxy, 'all', proxy],
			['relay.example', undefined, proxy, 'onion', undefined],
			['127.0.0.1', undefined, proxy, 'all', undefined],
			['192.168.1.20', undefined, proxy, 'all', undefined],
			['relayaddress.onion', undefined, proxy, 'onion', proxy],
			['relayaddress.onion', undefined, undefined, 'all', DEFAULT_TOR_PROXY],
			// 'tor': always the proxy, whatever the scope says about peers.
			['relay.example', 'tor', proxy, 'all', proxy],
			['relay.example', 'tor', proxy, 'onion', proxy],
			['relay.example', 'tor', undefined, 'all', DEFAULT_TOR_PROXY],
			['relayaddress.onion', 'tor', undefined, 'all', DEFAULT_TOR_PROXY],
			// 'direct': never the proxy.
			['relay.example', 'direct', proxy, 'all', undefined],
			['127.0.0.1', 'direct', proxy, 'all', undefined]
		];
		for (const [host, via, given, scope, expected] of rows) {
			it(`${host}, via ${via ?? 'unset'}, proxy ${
				given ? 'set' : 'unset'
			}, scope ${scope}: ${
				expected ? `proxy :${expected.port}` : 'direct'
			}`, function () {
				expect(selectPorchProxy(host, via, given, scope)).to.deep.equal(
					expected
				);
			});
		}

		it('refuses the two combinations that could only fail or leak', function () {
			for (const host of [
				'127.0.0.1',
				'localhost',
				'10.0.0.4',
				'192.168.1.20'
			]) {
				expect(() => selectPorchProxy(host, 'tor', proxy, 'all')).to.throw(
					/private address: Tor cannot reach it/
				);
			}
			expect(() =>
				selectPorchProxy('relayaddress.onion', 'direct', proxy, 'all')
			).to.throw(/onion service: it cannot be dialed with via 'direct'/);
		});
	});

	describe('configuration', function () {
		const build = (porch: Partial<IPorchConfig>): PeerManager =>
			new PeerManager({
				localPrivateKey: crypto.randomBytes(32),
				porch: {
					relays: ['wss://relay.example'],
					hostSecret,
					tags: [tagA],
					...porch
				}
			});

		it('is refused when the node is built, not when it first dials', function () {
			const bad: Array<[Partial<IPorchConfig>, RegExp]> = [
				[{ relays: [] }, /at least one relay/],
				[{ relays: ['https://relay.example'] }, /ws:\/\/ or wss:\/\//],
				[
					// The same relay, once with its default port spelled out.
					{ relays: ['wss://relay.example', 'wss://RELAY.example:443'] },
					/relay\.example is listed twice/
				],
				[{ relays: ['ws://127.0.0.1:2114'], via: 'tor' }, /private address/],
				[
					{ relays: ['ws://relayaddress.onion'], via: 'direct' },
					/onion service/
				],
				[{ standbys: 9 }, /whole number from 1 to 8/],
				[{ standbys: 0 }, /whole number from 1 to 8/],
				[{ tags: [Buffer.alloc(15)] }, /must be 16 bytes/],
				[
					{
						tags: Array.from({ length: PORCH_MAX_TAGS + 1 }, () =>
							crypto.randomBytes(16)
						)
					},
					/at most 256 links/
				]
			];
			for (const [porch, message] of bad) {
				expect(() => build(porch), JSON.stringify(porch).slice(0, 80)).to.throw(
					message
				);
			}
		});

		it('takes a relay as a URL or with its token, and no links at all', function () {
			const pm = build({
				relays: [
					'wss://one.example',
					{ url: 'ws://two.example:8080', token: 'secret' }
				],
				tags: []
			});
			expect(pm.isPorchEnabled()).to.equal(true);
			expect(pm.getPorchStatus().map((status) => status.relay)).to.deep.equal([
				'wss://one.example',
				'ws://two.example:8080'
			]);
			expect(pm.getPorchLinks()).to.deep.equal([]);
			pm.destroy();
		});

		it('lists one link per tag and relay, each a peer URI for this node', function () {
			const key = crypto.randomBytes(32);
			const pm = new PeerManager({
				localPrivateKey: key,
				porch: {
					relays: ['wss://one.example', 'ws://two.example:8080'],
					hostSecret,
					// Out of order and with a repeat: listed once, sorted.
					tags: [tagB, tagA, tagB]
				}
			});
			const nodeId = getPublicKey(key).toString('hex');
			const routeA = porchRouteId(hostKey, tagA);
			const routeB = porchRouteId(hostKey, tagB);
			expect(pm.getPorchLinks()).to.deep.equal([
				{
					relay: 'wss://one.example',
					tag: tagA.toString('hex'),
					uri: `${nodeId}@wss://one.example/v1/p/${routeA}`
				},
				{
					relay: 'ws://two.example:8080',
					tag: tagA.toString('hex'),
					uri: `${nodeId}@ws://two.example:8080/v1/p/${routeA}`
				},
				{
					relay: 'wss://one.example',
					tag: tagB.toString('hex'),
					uri: `${nodeId}@wss://one.example/v1/p/${routeB}`
				},
				{
					relay: 'ws://two.example:8080',
					tag: tagB.toString('hex'),
					uri: `${nodeId}@ws://two.example:8080/v1/p/${routeB}`
				}
			]);
			// Every one of them is a URI the dialing side already understands.
			for (const link of pm.getPorchLinks()) {
				const parsed = parsePeerUri(link.uri);
				expect(parsed.pubkey).to.equal(nodeId);
				expect(parsed.transport?.type).to.equal('ws');
			}
			pm.destroy();
		});

		it('makes the node refuse addresses a peer chose, whatever else was asked', function () {
			const plain = new PeerManager({
				localPrivateKey: crypto.randomBytes(32)
			});
			expect(plain.canDialLearnedAddress('203.0.113.1')).to.equal(true);
			expect(plain.isPorchEnabled()).to.equal(false);
			expect(plain.getPorchStatus()).to.deep.equal([]);
			expect(plain.getPorchLinks()).to.deep.equal([]);
			expect(() => plain.listenPorch()).to.throw(/Porch is not enabled/);
			expect(() => plain.setPorchTags([tagA])).to.throw(/Porch is not enabled/);
			plain.destroy();

			const hidden = new PeerManager({
				localPrivateKey: crypto.randomBytes(32),
				learnedAddressDials: 'any',
				porch: { relays: ['wss://relay.example'], hostSecret, tags: [tagA] }
			});
			expect(hidden.canDialLearnedAddress('203.0.113.1')).to.equal(false);
			hidden.destroy();
		});
	});

	describe('with a relay', function () {
		let relay: PorchRelay;
		let relayName: string;
		const managers: PeerManager[] = [];
		const sockets: NodeWebSocket[] = [];

		async function startRelay(
			options: Partial<IPorchRelayOptions> = {}
		): Promise<void> {
			const port = await freePort();
			relayName = `127.0.0.1:${port}`;
			relay = new PorchRelay({ authorities: [relayName], ...options });
			await relay.listen(port, '127.0.0.1');
		}

		function manager(options: Partial<IPeerManagerOptions> = {}): PeerManager {
			const pm = new PeerManager({
				localPrivateKey: crypto.randomBytes(32),
				...options
			});
			pm.on('peer:error', () => undefined);
			managers.push(pm);
			return pm;
		}

		function home(
			options: Partial<IPeerManagerOptions> = {},
			porch: Partial<IPorchConfig> = {}
		): PeerManager {
			return manager({
				...options,
				porch: {
					relays: [`ws://${relayName}`],
					hostSecret,
					tags: [tagA],
					...porch
				}
			});
		}

		const linkFor = (pm: PeerManager, tag: Buffer): string => {
			const link = pm
				.getPorchLinks()
				.find((entry) => entry.tag === tag.toString('hex'));
			if (!link) throw new Error('no such link');
			return link.uri;
		};

		async function visit(
			pm: PeerManager,
			tag: Buffer,
			visitor = manager()
		): Promise<PeerManager> {
			const link = parsePeerUri(linkFor(pm, tag));
			await visitor.connectPeer(
				link.pubkey,
				link.host,
				link.port,
				link.transport,
				{ reconnect: false }
			);
			return visitor;
		}

		const id = (pm: PeerManager): string =>
			(pm as unknown as { localPubkeyHex: string }).localPubkeyHex;

		/** A visitor that connects through a link and then says nothing. */
		function mute(uri: string): NodeWebSocket & { closed: boolean } {
			const ws = new NodeWebSocket(
				uri.slice(uri.indexOf('@') + 1)
			) as NodeWebSocket & { closed: boolean };
			ws.closed = false;
			ws.onclose = (): void => {
				ws.closed = true;
			};
			ws.onerror = (): void => undefined;
			sockets.push(ws);
			return ws;
		}

		beforeEach(async function () {
			await startRelay();
		});

		afterEach(async function () {
			for (const pm of managers.splice(0)) pm.destroy();
			for (const ws of sockets.splice(0)) ws.close();
			await relay.close();
		});

		it('waits at the relay from listenPorch() until the listeners stop', async function () {
			const pm = home();
			const seen: IPorchHostStatus[] = [];
			pm.on('porch:status', (status: IPorchHostStatus) => seen.push(status));
			expect(pm.isListening()).to.equal(false);
			expect(pm.isListeningPorch()).to.equal(false);
			expect(pm.getPorchStatus()[0].state).to.equal('stopped');
			// Nothing is dialed until it is asked to listen.
			await sleep(60);
			expect(relay.stats().connections).to.equal(0);

			pm.listenPorch();
			expect(pm.isListening()).to.equal(true);
			expect(pm.isListeningPorch()).to.equal(true);
			await waitFor(() => relay.stats().standbys === 2, 'standbys');
			expect(pm.getPorchStatus()).to.deep.equal([
				{ relay: `ws://${relayName}`, state: 'ready', idle: 2, circuits: 0 }
			]);
			expect(seen[seen.length - 1]).to.deep.equal(pm.getPorchStatus()[0]);
			// Asking twice changes nothing.
			pm.listenPorch();
			await sleep(60);
			expect(relay.stats().standbys).to.equal(2);

			pm.stopListening();
			expect(pm.isListening()).to.equal(false);
			expect(pm.getPorchStatus()[0].state).to.equal('stopped');
			await waitFor(() => relay.stats().standbys === 0, 'standbys closing');

			pm.listenPorch();
			await waitFor(() => relay.stats().standbys === 2, 'standbys again');
		});

		it('leaves the relay when the manager is destroyed or frozen, for good', async function () {
			for (const end of ['destroy', 'freezeConnections'] as const) {
				const pm = home();
				pm.listenPorch();
				await waitFor(() => relay.stats().standbys === 2, 'standbys');
				const visitor = await visit(pm, tagA);
				await waitFor(() => pm.listPeers().length === 1, 'the visitor');
				pm[end]();
				await waitFor(
					() => relay.stats().connections === 0,
					`everything closing on ${end}`
				);
				expect(pm.isListening()).to.equal(false);
				expect(() => pm.listenPorch()).to.throw(/Connections are disabled/);
				await sleep(100);
				expect(relay.stats().connections).to.equal(0);
				visitor.destroy();
			}
		});

		it('admits a visitor as a peer and lists what little is known of it', async function () {
			const pm = home({}, { tags: [tagA, tagB] });
			pm.listenPorch();
			await waitFor(() => relay.stats().standbys === 2, 'standbys');

			const arrived = new Promise<string>((resolve) => {
				pm.once('peer:connect', resolve);
			});
			const visitor = await visit(pm, tagB);
			expect(await arrived).to.equal(id(visitor));
			expect(pm.listPeers()).to.have.length(1);
			const [peer] = pm.listPeers();
			expect(peer).to.include({
				pubkey: id(visitor),
				host: `porch:${relayName}`,
				port: 0,
				state: 'ready',
				transport: 'ws'
			});
			expect(peer.porch).to.deep.equal({
				relay: relayName,
				tag: tagB.toString('hex')
			});
			// Nothing is kept to dial the visitor back with.
			expect(pm.getPeerAddress(id(visitor))).to.equal(undefined);
			// A peer that was dialed has no such entry.
			expect(visitor.listPeers()[0]).to.not.have.property('porch');

			// Messages cross the relay in both directions.
			const body = crypto.randomBytes(24);
			const atHome = new Promise<Buffer>((resolve) => {
				pm.onMessage(40001, (_pubkey, _type, payload) => resolve(payload));
			});
			const atVisitor = new Promise<Buffer>((resolve) => {
				visitor.onMessage(40003, (_pubkey, _type, payload) => resolve(payload));
			});
			visitor.sendToPeer(id(pm), 40001, body);
			pm.sendToPeer(id(visitor), 40003, body);
			expect((await atHome).equals(body)).to.equal(true);
			expect((await atVisitor).equals(body)).to.equal(true);

			await waitFor(
				() => pm.getPorchStatus()[0].idle === 2,
				'the standby being replaced'
			);
			expect(pm.getPorchStatus()[0].circuits).to.equal(1);
			visitor.disconnectPeer(id(pm));
			await waitFor(() => pm.listPeers().length === 0, 'the visitor leaving');
			await waitFor(
				() => pm.getPorchStatus()[0].circuits === 0,
				'the circuit closing'
			);
		});

		it('changes the links served, and closes what came in through a revoked one', async function () {
			await relay.close();
			await startRelay({ limits: { pairWaitMs: 100 } });
			const pm = home({}, { tags: [tagA, tagB] });
			pm.listenPorch();
			await waitFor(() => relay.stats().standbys === 2, 'standbys');
			const linkB = linkFor(pm, tagB);

			const viaA = await visit(pm, tagA);
			await waitFor(() => relay.stats().standbys === 2, 'a fresh standby');
			const viaB = await visit(pm, tagB);
			await waitFor(() => pm.listPeers().length === 2, 'both visitors');
			await waitFor(() => relay.stats().standbys === 2, 'fresh standbys');

			const gone: string[] = [];
			pm.on('peer:disconnect', (pubkey: string) => gone.push(pubkey));
			pm.setPorchTags([tagA, tagC]);
			await waitFor(() => gone.length === 1, 'the revoked visitor closing');
			expect(gone).to.deep.equal([id(viaB)]);
			expect(pm.listPeers().map((peer) => peer.pubkey)).to.deep.equal([
				id(viaA)
			]);
			expect(pm.getPorchLinks().map((link) => link.tag)).to.deep.equal([
				tagA.toString('hex'),
				tagC.toString('hex')
			]);

			// The revoked link no longer resolves at the relay.
			await waitFor(
				() => pm.getPorchStatus()[0].idle === 2,
				'standbys for the new links'
			);
			const stale = mute(linkB);
			let code: number | undefined;
			stale.onclose = (ev): void => {
				code = ev?.code;
			};
			await waitFor(() => code !== undefined, 'the stale link closing');
			expect(code).to.equal(PORCH_CLOSE_TRY_LATER);

			// The kept link and the new one do.
			await visit(pm, tagC);
			await waitFor(() => relay.stats().standbys === 2, 'a fresh standby');
			await visit(pm, tagA);
			await waitFor(() => pm.listPeers().length === 3, 'the new visitors');
		});

		it('counts a relay as one source, so strangers there cannot hold every handshake slot', async function () {
			const pm = home(
				{ maxPendingInboundPerAddress: 2, inboundHandshakeTimeoutMs: 1_500 },
				{ standbys: 4 }
			);
			pm.listenPorch();
			await waitFor(() => relay.stats().standbys === 4, 'standbys');
			const uri = linkFor(pm, tagA);

			// Two visitors that never start a handshake hold the two slots.
			const first = mute(uri);
			const second = mute(uri);
			await waitFor(
				() => pm.getPorchStatus()[0].circuits === 2,
				'two circuits waiting'
			);
			// The third is let go at once: its circuit closes while the first
			// two are still inside their handshake deadline.
			const third = mute(uri);
			await waitFor(() => third.closed, 'the third closing', 1_000);
			expect(first.closed).to.equal(false);
			expect(second.closed).to.equal(false);
			// And the deadline frees the slots.
			await waitFor(
				() => first.closed && second.closed,
				'the handshake deadline',
				5_000
			);
			await waitFor(
				() => pm.getPorchStatus()[0].circuits === 0,
				'the circuits closing'
			);
			// A real visitor gets in afterwards.
			await visit(pm, tagA);
			await waitFor(() => pm.listPeers().length === 1, 'a real visitor');
		});

		it('will not put together a large message for a stranger', async function () {
			const pm = home();
			pm.listenPorch();
			await waitFor(() => relay.stats().standbys === 2, 'standbys');
			const route = linkFor(pm, tagA).split('/v1/p/')[1];
			const [, portText] = relayName.split(':');

			// A visitor on a raw socket, so it can send a message in pieces
			// and never finish it. Each piece is within the relay's frame
			// limit, so the relay passes them on.
			const socket = net.createConnection(Number(portText), '127.0.0.1');
			let closed = false;
			let upgraded = false;
			socket.on('error', () => undefined);
			socket.on('close', () => (closed = true));
			socket.on('data', () => (upgraded = true));
			socket.write(
				[
					`GET /v1/p/${route} HTTP/1.1`,
					`Host: ${relayName}`,
					'Connection: Upgrade',
					'Upgrade: websocket',
					`Sec-WebSocket-Key: ${crypto.randomBytes(16).toString('base64')}`,
					'Sec-WebSocket-Version: 13'
				].join('\r\n') + '\r\n\r\n'
			);
			try {
				await waitFor(() => upgraded, 'the upgrade');
				await waitFor(
					() => pm.getPorchStatus()[0].circuits === 1,
					'the circuit'
				);
				const piece = (opcode: number): Buffer =>
					encodeWsFrame({
						opcode,
						fin: false,
						payload: Buffer.alloc(60 * 1024),
						maskKey: crypto.randomBytes(4)
					});
				socket.write(piece(WsOpcode.BINARY));
				socket.write(piece(WsOpcode.CONTINUATION));
				await sleep(150);
				// 120 KiB of an unfinished message: held, within the limit.
				expect(closed).to.equal(false);
				expect(pm.getPorchStatus()[0].circuits).to.equal(1);
				socket.write(piece(WsOpcode.CONTINUATION));
				// 180 KiB: the node lets go long before its handshake deadline
				// (10 seconds) would have.
				await waitFor(() => closed, 'the circuit being dropped', 2_000);
				await waitFor(
					() => pm.getPorchStatus()[0].circuits === 0,
					'the circuit count'
				);
			} finally {
				socket.destroy();
			}
		});

		it('caps peers through one relay like peers from one address, channel peers aside', async function () {
			const known = new Set<string>();
			const pm = home({
				maxInboundPeersPerAddress: 1,
				isChannelPeer: (pubkey) => known.has(pubkey)
			});
			pm.listenPorch();
			await waitFor(() => relay.stats().standbys === 2, 'standbys');

			const first = await visit(pm, tagA);
			await waitFor(() => pm.listPeers().length === 1, 'the first visitor');
			await waitFor(() => relay.stats().standbys === 2, 'a fresh standby');

			// A second stranger completes the handshake and is then dropped.
			const stranger = manager();
			let strangerDropped = false;
			stranger.on('peer:disconnect', () => (strangerDropped = true));
			await visit(pm, tagA, stranger).catch(() => {
				strangerDropped = true;
			});
			await waitFor(() => strangerDropped, 'the stranger being dropped');
			expect(pm.listPeers().map((peer) => peer.pubkey)).to.deep.equal([
				id(first)
			]);

			// A channel peer is admitted past the cap.
			await waitFor(() => relay.stats().standbys === 2, 'a fresh standby');
			const partner = manager();
			known.add(id(partner));
			await visit(pm, tagA, partner);
			await waitFor(() => pm.listPeers().length === 2, 'the channel peer');
		});
	});
});
