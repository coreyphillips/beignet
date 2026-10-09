/**
 * Self-disconnect (issue #1437): a Peer that closes an established
 * connection itself (a protocol violation, a ping flood) must still report
 * 'close' once, or PeerManager keeps its registration and inbound slot.
 */

import { expect } from 'chai';
import * as crypto from 'crypto';
import { Peer } from '../../src/lightning/transport/peer';
import { PeerManager } from '../../src/lightning/transport/peer-manager';
import { IDuplexTransport } from '../../src/lightning/transport/duplex-transport';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

const HOST_SECRET = crypto
	.createHash('sha256')
	.update('self-disconnect')
	.digest();
const HOST_ID = getPublicKey(HOST_SECRET);
// Even, so BOLT 1 requires the receiver to close; not a known type.
const UNKNOWN_REQUIRED_TYPE = 20000;

async function settle(ms = 20): Promise<void> {
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

function dialer(port: number, key: Buffer): Peer {
	const peer = new Peer({
		localPrivateKey: key,
		remotePublicKey: HOST_ID,
		host: '127.0.0.1',
		port,
		connectTimeout: 2_000,
		handshakeTimeout: 2_000
	});
	peer.on('error', () => undefined);
	return peer;
}

describe('Peer self-disconnect close (issue #1437)', () => {
	it('reports close exactly once when it drops an established connection', async () => {
		const peer = new Peer({
			localPrivateKey: crypto.randomBytes(32),
			remotePublicKey: HOST_ID,
			host: '127.0.0.1',
			port: 1
		});
		(peer as unknown as { state: string }).state = 'ready';
		peer.on('error', () => undefined);
		let closes = 0;
		peer.on('close', () => closes++);

		(
			peer as unknown as { handleMessage(type: number, payload: Buffer): void }
		).handleMessage(UNKNOWN_REQUIRED_TYPE, Buffer.alloc(0));
		expect(peer.getState()).to.equal('disconnected');
		peer.disconnect();
		await settle();
		expect(closes).to.equal(1);
	});

	it('reports no close for an establishment it aborts', async () => {
		const peer = new Peer({
			localPrivateKey: crypto.randomBytes(32),
			remotePublicKey: HOST_ID,
			host: '127.0.0.1',
			port: 1,
			connectTimeout: 100,
			createSocket: (): Promise<IDuplexTransport> =>
				new Promise(() => undefined)
		});
		let closes = 0;
		peer.on('close', () => closes++);
		const connecting = peer.connect();
		peer.disconnect();
		let error: Error | undefined;
		await connecting.catch((err: Error) => {
			error = err;
		});
		await settle();
		expect(error?.message).to.equal('Peer aborted');
		expect(closes).to.equal(0);
	});
});

describe('PeerManager self-disconnect release (issue #1437)', () => {
	let pm: PeerManager | undefined;
	const peers: Peer[] = [];

	afterEach(() => {
		for (const peer of peers.splice(0)) peer.disconnect();
		pm?.destroy();
		pm = undefined;
	});

	it('frees the registration and inbound slot of a peer it drops itself', async () => {
		pm = new PeerManager({ localPrivateKey: HOST_SECRET, maxInboundPeers: 1 });
		pm.on('peer:error', () => undefined);
		const disconnects: string[] = [];
		pm.on('peer:disconnect', (pubkey: string) => disconnects.push(pubkey));
		await pm.listen(0, '127.0.0.1');
		const port = (
			pm as unknown as { server: { address(): { port: number } } }
		).server.address().port;

		const firstKey = crypto.randomBytes(32);
		const first = dialer(port, firstKey);
		peers.push(first);
		let firstClosed = false;
		first.on('close', () => {
			firstClosed = true;
		});
		await first.connect();
		await until(() => pm!.listPeers().length === 1);

		first.sendMessage(UNKNOWN_REQUIRED_TYPE, Buffer.alloc(0));
		await until(() => firstClosed);
		await settle();
		expect(pm.listPeers()).to.deep.equal([]);
		expect(disconnects).to.deep.equal([getPublicKey(firstKey).toString('hex')]);

		const secondKey = crypto.randomBytes(32);
		const second = dialer(port, secondKey);
		peers.push(second);
		await second.connect();
		await until(() => pm!.listPeers().length === 1);
		await settle(100);
		expect(second.getState()).to.equal('ready');
		expect(pm.getPeer(getPublicKey(secondKey).toString('hex'))).to.exist;
	});
});
