/**
 * Inbound admission (issue #1021): handshakes still in flight are capped in
 * total and per public source address and die at a hard deadline, the
 * WebSocket listener bounds connections that have not upgraded yet, and
 * maxInboundPeers is applied once the peer's identity is known so a peer we
 * hold a channel with is admitted past it.
 */

import { expect } from 'chai';
import * as crypto from 'crypto';
import * as net from 'net';
import { Peer } from '../../src/lightning/transport/peer';
import {
	PeerManager,
	inboundAddressKey
} from '../../src/lightning/transport/peer-manager';
import {
	WebSocketServer,
	WebSocketServerTransport
} from '../../src/lightning/transport/websocket-server';
import {
	encodeWsFrame,
	WsOpcode
} from '../../src/lightning/transport/websocket-frame';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { LightningNode } from '../../src/lightning/node/lightning-node';

const HOST_SECRET = crypto.createHash('sha256').update('admission').digest();
const HOST_ID = getPublicKey(HOST_SECRET);

interface IPmInternal {
	pendingInbound: Map<Peer, string | null>;
	handleInboundConnection(socket: net.Socket): void;
}

const internal = (pm: PeerManager): IPmInternal => pm as unknown as IPmInternal;

async function settle(ms = 50): Promise<void> {
	await new Promise((resolve) => setTimeout(resolve, ms));
}

async function until(
	predicate: () => boolean,
	timeoutMs = 3_000
): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (!predicate()) {
		if (Date.now() > deadline) throw new Error('condition not met in time');
		await settle(10);
	}
}

function listenPort(pm: PeerManager): number {
	const server = (pm as unknown as { server: net.Server }).server;
	return (server.address() as net.AddressInfo).port;
}

async function listenLocal(pm: PeerManager): Promise<number> {
	await pm.listen(0, '127.0.0.1');
	return listenPort(pm);
}

/** A raw TCP client that says nothing, tracking when the far end drops it. */
function silentClient(port: number): { socket: net.Socket; closed: boolean } {
	const client = { socket: net.connect(port, '127.0.0.1'), closed: false };
	client.socket.on('error', () => undefined);
	client.socket.on('close', () => {
		client.closed = true;
	});
	return client;
}

function dialer(
	port: number,
	key = crypto.randomBytes(32),
	remotePublicKey = HOST_ID
): Peer {
	const peer = new Peer({
		localPrivateKey: key,
		remotePublicKey,
		host: '127.0.0.1',
		port,
		connectTimeout: 2_000,
		handshakeTimeout: 2_000
	});
	peer.on('error', () => undefined);
	return peer;
}

describe('inboundAddressKey', () => {
	it('keys public IPv4 on the address, unwrapping the IPv4-mapped form', () => {
		expect(inboundAddressKey('203.0.113.9')).to.equal('203.0.113.9');
		expect(inboundAddressKey('::ffff:203.0.113.9')).to.equal('203.0.113.9');
	});

	it('keys public IPv6 on its /64', () => {
		expect(inboundAddressKey('2001:db8:1:2:3:4:5:6')).to.equal(
			'2001:db8:1:2::/64'
		);
		expect(inboundAddressKey('2001:DB8:1:2::9')).to.equal('2001:db8:1:2::/64');
		expect(inboundAddressKey('2001:db8::1')).to.equal('2001:db8:0:0::/64');
	});

	it('leaves private, loopback and unknown sources unlimited', () => {
		for (const address of [
			'127.0.0.1',
			'10.21.21.11',
			'192.168.1.5',
			'::1',
			'::ffff:172.17.0.1',
			'fe80::1%eth0',
			'fd00::5',
			undefined
		]) {
			expect(inboundAddressKey(address), String(address)).to.equal(null);
		}
	});
});

describe('peer manager inbound admission', () => {
	let pm: PeerManager | undefined;
	const sockets: net.Socket[] = [];
	const peers: Peer[] = [];

	afterEach(() => {
		for (const socket of sockets.splice(0)) socket.destroy();
		for (const peer of peers.splice(0)) peer.disconnect();
		pm?.destroy();
		pm = undefined;
	});

	it('destroys sockets past maxPendingInbound while handshakes are in flight', async () => {
		pm = new PeerManager({
			localPrivateKey: HOST_SECRET,
			maxPendingInbound: 2
		});
		const port = await listenLocal(pm);
		const stalled = [silentClient(port), silentClient(port)];
		sockets.push(...stalled.map((c) => c.socket));
		await until(() => internal(pm!).pendingInbound.size === 2);

		const refused = silentClient(port);
		sockets.push(refused.socket);
		await until(() => refused.closed);
		expect(stalled.map((c) => c.closed)).to.deep.equal([false, false]);

		// Freed slots admit a real peer again.
		for (const c of stalled) c.socket.destroy();
		await until(() => internal(pm!).pendingInbound.size === 0);
		const peer = dialer(port);
		peers.push(peer);
		await peer.connect();
		await until(() => pm!.listPeers().length === 1);
	});

	it('ends an inbound handshake at its deadline even while bytes trickle in', async () => {
		pm = new PeerManager({
			localPrivateKey: HOST_SECRET,
			inboundHandshakeTimeoutMs: 300
		});
		const port = await listenLocal(pm);
		const client = silentClient(port);
		sockets.push(client.socket);
		// One act-one byte every 50 ms would reset an idle timer forever and
		// needs 2.5 s to deliver the 50 bytes.
		const trickle = setInterval(() => {
			if (!client.closed) client.socket.write(Buffer.alloc(1));
		}, 50);
		const started = Date.now();
		try {
			await until(() => client.closed, 2_000);
		} finally {
			clearInterval(trickle);
		}
		expect(Date.now() - started).to.be.lessThan(1_500);
		await until(() => internal(pm!).pendingInbound.size === 0);
	});

	it('caps handshakes in flight per public source address, not per private one', async () => {
		pm = new PeerManager({
			localPrivateKey: HOST_SECRET,
			maxPendingInboundPerAddress: 2
		});
		// Route real sockets into the admission path under a chosen source
		// address, since a test can only connect from loopback.
		let nextAddress = '';
		const relay = net.createServer((socket) => {
			Object.defineProperty(socket, 'remoteAddress', { value: nextAddress });
			internal(pm!).handleInboundConnection(socket);
		});
		await new Promise<void>((resolve) =>
			relay.listen(0, '127.0.0.1', () => resolve())
		);
		const port = (relay.address() as net.AddressInfo).port;
		const open = async (
			address: string
		): Promise<{ socket: net.Socket; closed: boolean }> => {
			nextAddress = address;
			const before = internal(pm!).pendingInbound.size;
			const client = silentClient(port);
			sockets.push(client.socket);
			await until(
				() => internal(pm!).pendingInbound.size > before || client.closed
			);
			return client;
		};
		try {
			const first = await open('203.0.113.9');
			const second = await open('::ffff:203.0.113.9');
			const third = await open('203.0.113.9');
			await until(() => third.closed);
			expect([first.closed, second.closed]).to.deep.equal([false, false]);

			const other = await open('198.51.100.7');
			await settle(100);
			expect(other.closed).to.equal(false);

			const privates = [
				await open('10.21.21.11'),
				await open('10.21.21.11'),
				await open('10.21.21.11')
			];
			await settle(100);
			expect(privates.map((c) => c.closed)).to.deep.equal([
				false,
				false,
				false
			]);
			expect(internal(pm).pendingInbound.size).to.equal(6);
		} finally {
			relay.close();
		}
	});

	it('refuses a stranger past maxInboundPeers after the handshake but admits a channel peer', async () => {
		const channelKey = crypto.randomBytes(32);
		const channelPubkey = getPublicKey(channelKey).toString('hex');
		pm = new PeerManager({
			localPrivateKey: HOST_SECRET,
			maxInboundPeers: 1,
			isChannelPeer: (pubkey): boolean => pubkey === channelPubkey
		});
		const port = await listenLocal(pm);

		const squatter = dialer(port);
		peers.push(squatter);
		await squatter.connect();
		await until(() => pm!.listPeers().length === 1);

		const stranger = dialer(port);
		peers.push(stranger);
		let strangerClosed = false;
		stranger.on('close', () => {
			strangerClosed = true;
		});
		await stranger.connect().catch(() => {
			strangerClosed = true;
		});
		await until(() => strangerClosed);
		expect(pm.listPeers()).to.have.length(1);

		const channelPeer = dialer(port, channelKey);
		peers.push(channelPeer);
		await channelPeer.connect();
		await until(() => pm!.listPeers().length === 2);
		expect(pm.getPeer(channelPubkey)).to.exist;
	});

	it('refuses a peer past maxInboundPeers when isChannelPeer throws', async () => {
		pm = new PeerManager({
			localPrivateKey: HOST_SECRET,
			maxInboundPeers: 0,
			isChannelPeer: (): boolean => {
				throw new Error('lookup failed');
			}
		});
		const port = await listenLocal(pm);
		const peer = dialer(port);
		peers.push(peer);
		let closed = false;
		peer.on('close', () => {
			closed = true;
		});
		await peer.connect().catch(() => {
			closed = true;
		});
		await until(() => closed);
		expect(pm.listPeers()).to.have.length(0);
	});
});

describe('websocket server upgrade admission', () => {
	let server: WebSocketServer | undefined;
	const sockets: net.Socket[] = [];

	afterEach(() => {
		for (const socket of sockets.splice(0)) socket.destroy();
		server?.close();
		server = undefined;
	});

	it('bounds connections that have not upgraded, in number and in time', async () => {
		server = new WebSocketServer({
			maxPendingUpgrades: 1,
			upgradeTimeoutMs: 500
		});
		await server.listen(0, '127.0.0.1');
		const port = (server.address() as net.AddressInfo).port;

		const silent = silentClient(port);
		sockets.push(silent.socket);
		await settle(50);
		const refused = silentClient(port);
		sockets.push(refused.socket);
		await until(() => refused.closed, 250);
		expect(silent.closed).to.equal(false);

		await until(() => silent.closed, 2_000);
	});

	it('bounds connections that have not upgraded per source address key', async () => {
		const keys: Array<string | null> = ['a', 'a', 'b', null, null];
		server = new WebSocketServer({
			maxPendingUpgradesPerAddress: 1,
			upgradeAddressKey: (): string | null => keys.shift() ?? null
		});
		await server.listen(0, '127.0.0.1');
		const port = (server.address() as net.AddressInfo).port;

		const clients: Array<{ socket: net.Socket; closed: boolean }> = [];
		for (let i = 0; i < 5; i++) {
			const client = silentClient(port);
			sockets.push(client.socket);
			clients.push(client);
			await settle(50);
		}
		expect(clients.map((c) => c.closed)).to.deep.equal([
			false,
			true,
			false,
			false,
			false
		]);
	});

	it('counts an upgraded connection it closes until it is gone, reading nothing more from it', async function () {
		this.timeout(5_000);
		server = new WebSocketServer({ maxPendingUpgrades: 1 });
		let transport: WebSocketServerTransport | undefined;
		server.on('connection', (t: WebSocketServerTransport) => {
			transport = t;
			t.destroy();
		});
		await server.listen(0, '127.0.0.1');
		const port = (server.address() as net.AddressInfo).port;

		// A client that never answers our close, so the socket lingers.
		const client = silentClient(port);
		sockets.push(client.socket);
		client.socket.write(
			'GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n' +
				'Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n' +
				`Sec-WebSocket-Key: ${crypto
					.randomBytes(16)
					.toString('base64')}\r\n\r\n`
		);
		await until(() => transport !== undefined);
		client.socket.write(
			encodeWsFrame({
				opcode: WsOpcode.BINARY,
				payload: Buffer.alloc(1024),
				maskKey: crypto.randomBytes(4)
			})
		);
		await settle(50);
		const received: Buffer[] = [];
		transport!.on('data', (chunk: Buffer) => received.push(chunk));
		expect(received).to.have.length(0);

		const refused = silentClient(port);
		sockets.push(refused.socket);
		await until(() => refused.closed, 250);

		const pending = (
			server as unknown as { pendingUpgrades: Map<unknown, unknown> }
		).pendingUpgrades;
		await until(() => pending.size === 0, 2_000);
		const admitted = silentClient(port);
		sockets.push(admitted.socket);
		await settle(100);
		expect(admitted.closed).to.equal(false);
	});
});

describe('LightningNode inbound cap', () => {
	it('hands maxInboundPeers to the peer manager, where a stranger is not a channel peer', async () => {
		const nodeKey = crypto.randomBytes(32);
		const node = new LightningNode({
			nodePrivateKey: nodeKey,
			perCommitmentSeed: crypto.randomBytes(32),
			channelBasepoints: {
				fundingPubkey: crypto.randomBytes(33),
				revocationBasepoint: crypto.randomBytes(33),
				paymentBasepoint: crypto.randomBytes(33),
				delayedPaymentBasepoint: crypto.randomBytes(33),
				htlcBasepoint: crypto.randomBytes(33),
				firstPerCommitmentPoint: crypto.randomBytes(33)
			},
			fundingPrivkey: crypto.randomBytes(32),
			enableNetworking: true,
			maxInboundPeers: 0
		});
		try {
			await node.listen(0, '127.0.0.1');
			const pm = (node as unknown as { peerManager: PeerManager }).peerManager;
			const port = await listenPort(pm);
			const peer = dialer(port, crypto.randomBytes(32), getPublicKey(nodeKey));
			let closed = false;
			peer.on('close', () => {
				closed = true;
			});
			await peer.connect().catch(() => {
				closed = true;
			});
			await until(() => closed);
			expect(pm.listPeers()).to.have.length(0);
			peer.disconnect();
		} finally {
			node.destroy();
		}
	});
});
