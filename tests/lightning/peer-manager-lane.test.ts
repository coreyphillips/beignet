/**
 * The guardian-only lane (recovery 5.6 exception, issue #699 D6): while the
 * connection gate is closed, an inbound session the lane gate admits
 * completes the handshake and may carry ONLY what the lane gate allows, in
 * both directions; everything else about it is refused. Ordinary inbound is
 * still destroyed before the handshake, the lane has its own cap, lane
 * peers are invisible to the ordinary peer surface, and teardown drops them.
 */

import { expect } from 'chai';
import * as crypto from 'crypto';
import * as net from 'net';
import { Peer } from '../../src/lightning/transport/peer';
import { PeerManager } from '../../src/lightning/transport/peer-manager';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	BEIGNET_CUSTOM_MESSAGE_TYPE,
	BeignetCustomSubtype,
	decodeCustomMessage,
	encodeCustomMessage
} from '../../src/lightning/message/custom';

const HOST_SECRET = crypto.createHash('sha256').update('lane-host').digest();
const HOST_ID = getPublicKey(HOST_SECRET);

const isGuardianFrame = (type: number, payload: Buffer): boolean => {
	if (type !== BEIGNET_CUSTOM_MESSAGE_TYPE) return false;
	try {
		const subtype = decodeCustomMessage(payload).subtype;
		return (
			subtype === BeignetCustomSubtype.GUARDIAN_REQUEST ||
			subtype === BeignetCustomSubtype.GUARDIAN_RESPONSE
		);
	} catch {
		return false;
	}
};

async function freePort(): Promise<number> {
	return new Promise((resolve) => {
		const probe = net.createServer();
		probe.listen(0, '127.0.0.1', () => {
			const port = (probe.address() as net.AddressInfo).port;
			probe.close(() => resolve(port));
		});
	});
}

interface IHost {
	pm: PeerManager;
	port: number;
	gateOpen: boolean;
	laneAdmits: boolean;
	laneMessages: Array<{ pubkey: string; type: number; payload: Buffer }>;
	laneConnects: string[];
	laneDisconnects: string[];
}

async function startHost(
	options: { maxLanePeers?: number; withLane?: boolean } = {}
): Promise<IHost> {
	const pm = new PeerManager({
		localPrivateKey: HOST_SECRET,
		maxLanePeers: options.maxLanePeers
	});
	const host: IHost = {
		pm,
		port: await freePort(),
		gateOpen: false,
		laneAdmits: true,
		laneMessages: [],
		laneConnects: [],
		laneDisconnects: []
	};
	pm.setConnectionGate(() => host.gateOpen);
	if (options.withLane !== false) {
		pm.setLaneGate({
			admits: (): boolean => host.laneAdmits,
			allows: isGuardianFrame
		});
	}
	pm.on('lane:connect', (pubkey: string) => host.laneConnects.push(pubkey));
	pm.on('lane:disconnect', (pubkey: string) =>
		host.laneDisconnects.push(pubkey)
	);
	pm.on('lane:message', (pubkey: string, type: number, payload: Buffer) => {
		host.laneMessages.push({ pubkey, type, payload });
	});
	await pm.listen(host.port, '127.0.0.1');
	return host;
}

/** A stranger dialing the host under a fresh key, as a guardian session does. */
function stranger(port: number): Peer {
	const peer = new Peer({
		localPrivateKey: crypto.randomBytes(32),
		remotePublicKey: HOST_ID,
		host: '127.0.0.1',
		port,
		connectTimeout: 2_000,
		handshakeTimeout: 2_000
	});
	peer.on('error', () => undefined);
	return peer;
}

const guardianRequest = (body: Buffer): Buffer =>
	encodeCustomMessage(BeignetCustomSubtype.GUARDIAN_REQUEST, body);

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

describe('peer manager guardian lane', () => {
	let host: IHost;
	const peers: Peer[] = [];

	afterEach(() => {
		for (const peer of peers.splice(0)) peer.disconnect();
		host?.pm.destroy();
	});

	it('destroys ordinary inbound before the handshake while the gate is closed and no lane exists', async () => {
		host = await startHost({ withLane: false });
		const peer = stranger(host.port);
		peers.push(peer);
		let failure: unknown;
		try {
			await peer.connect();
		} catch (error) {
			failure = error;
		}
		expect(failure).to.be.instanceOf(Error);
		expect(host.pm.lanePeerCount()).to.equal(0);
		expect(host.pm.listPeers()).to.have.length(0);
	});

	it('admits a lane session while gated, carries guardian frames both ways, hides it from listPeers', async () => {
		host = await startHost();
		const peer = stranger(host.port);
		peers.push(peer);
		const received: Buffer[] = [];
		peer.on('message', (type: number, payload: Buffer) => {
			if (type === BEIGNET_CUSTOM_MESSAGE_TYPE) received.push(payload);
		});
		await peer.connect();
		await until(() => host.laneConnects.length === 1);
		const pubkey = host.laneConnects[0];
		expect(host.pm.lanePeerCount()).to.equal(1);
		expect(host.pm.isLanePeer(pubkey)).to.equal(true);
		expect(host.pm.listPeers()).to.have.length(0);
		expect(host.pm.getPeer(pubkey)).to.equal(undefined);

		peer.sendMessage(
			BEIGNET_CUSTOM_MESSAGE_TYPE,
			guardianRequest(Buffer.from('hello'))
		);
		await until(() => host.laneMessages.length === 1);
		expect(host.laneMessages[0].pubkey).to.equal(pubkey);
		expect(
			decodeCustomMessage(host.laneMessages[0].payload).payload.toString()
		).to.equal('hello');

		// The host answers through sendToPeer, which routes to the lane.
		host.pm.sendToPeer(
			pubkey,
			BEIGNET_CUSTOM_MESSAGE_TYPE,
			encodeCustomMessage(
				BeignetCustomSubtype.GUARDIAN_RESPONSE,
				Buffer.from('world')
			)
		);
		await until(() => received.length === 1);
		expect(decodeCustomMessage(received[0]).payload.toString()).to.equal(
			'world'
		);

		// But it can send nothing else down the lane.
		expect(() =>
			host.pm.sendToPeer(
				pubkey,
				BEIGNET_CUSTOM_MESSAGE_TYPE,
				encodeCustomMessage(1, Buffer.alloc(0))
			)
		).to.throw(/Lane refused/);
		expect(() => host.pm.sendToPeer(pubkey, 32, Buffer.alloc(0))).to.throw(
			/Lane refused/
		);
	});

	it('disconnects a lane peer that sends anything but lane traffic', async () => {
		host = await startHost();
		const peer = stranger(host.port);
		peers.push(peer);
		const closed = new Promise<void>((resolve) =>
			peer.once('close', () => resolve())
		);
		await peer.connect();
		await until(() => host.laneConnects.length === 1);
		// A beignet custom message on a non-guardian subtype: refused.
		peer.sendMessage(
			BEIGNET_CUSTOM_MESSAGE_TYPE,
			encodeCustomMessage(1, Buffer.alloc(0))
		);
		await closed;
		await until(() => host.laneDisconnects.length === 1);
		expect(host.pm.lanePeerCount()).to.equal(0);
		expect(host.laneMessages).to.have.length(0);
	});

	it('caps lane sessions separately from inbound peers, and refuses when the lane gate says so', async () => {
		host = await startHost({ maxLanePeers: 1 });
		const first = stranger(host.port);
		peers.push(first);
		await first.connect();
		await until(() => host.laneConnects.length === 1);

		const second = stranger(host.port);
		peers.push(second);
		let failure: unknown;
		try {
			await second.connect();
		} catch (error) {
			failure = error;
		}
		expect(failure).to.be.instanceOf(Error);
		expect(host.pm.lanePeerCount()).to.equal(1);

		first.disconnect();
		await until(() => host.pm.lanePeerCount() === 0);
		host.laneAdmits = false;
		const third = stranger(host.port);
		peers.push(third);
		let refused: unknown;
		try {
			await third.connect();
		} catch (error) {
			refused = error;
		}
		expect(refused).to.be.instanceOf(Error);
	});

	it('keeps a lane session lane-restricted after the gate opens, while new inbound becomes ordinary', async () => {
		host = await startHost();
		const lanePeer = stranger(host.port);
		peers.push(lanePeer);
		await lanePeer.connect();
		await until(() => host.laneConnects.length === 1);

		host.gateOpen = true;
		const ordinary = stranger(host.port);
		peers.push(ordinary);
		await ordinary.connect();
		await until(() => host.pm.listPeers().length === 1);
		expect(host.pm.lanePeerCount()).to.equal(1);
		expect(host.pm.listPeers()[0].pubkey).to.not.equal(host.laneConnects[0]);
	});

	it('drops lane peers on destroy and reports each one', async () => {
		host = await startHost();
		const a = stranger(host.port);
		const b = stranger(host.port);
		peers.push(a, b);
		await a.connect();
		await b.connect();
		await until(() => host.laneConnects.length === 2);
		host.pm.destroy();
		expect(host.pm.lanePeerCount()).to.equal(0);
		expect(host.laneDisconnects.sort()).to.deep.equal(
			[...host.laneConnects].sort()
		);
	});

	it('disconnectPeer reaches a lane peer', async () => {
		host = await startHost();
		const peer = stranger(host.port);
		peers.push(peer);
		const closed = new Promise<void>((resolve) =>
			peer.once('close', () => resolve())
		);
		await peer.connect();
		await until(() => host.laneConnects.length === 1);
		host.pm.disconnectPeer(host.laneConnects[0]);
		await closed;
		expect(host.pm.lanePeerCount()).to.equal(0);
		expect(host.laneDisconnects).to.have.length(1);
	});
});
