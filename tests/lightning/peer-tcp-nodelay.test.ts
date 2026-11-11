/**
 * A Lightning message is one small write, and the next one often follows
 * before the first is acknowledged. With Nagle's algorithm on, the second
 * waits for that acknowledgement. Every TCP socket a peer is carried by has
 * it turned off: the one a node dials, the one a socket factory (a SOCKS5
 * proxy, a native bridge) hands over, and the one a listener accepts.
 */

import { expect } from 'chai';
import * as crypto from 'crypto';
import * as net from 'net';
import { Peer } from '../../src/lightning/transport/peer';
import { PeerManager } from '../../src/lightning/transport/peer-manager';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

const key = (label: string): Buffer =>
	crypto.createHash('sha256').update(label).digest();

async function until(
	predicate: () => boolean,
	timeoutMs = 5_000
): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (!predicate()) {
		if (Date.now() > deadline) throw new Error('condition not met in time');
		await new Promise((resolve) => setTimeout(resolve, 10));
	}
}

async function freePort(): Promise<number> {
	const probe = net.createServer();
	await new Promise<void>((resolve) => probe.listen(0, '127.0.0.1', resolve));
	const { port } = probe.address() as net.AddressInfo;
	await new Promise<void>((resolve) => probe.close(() => resolve()));
	return port;
}

describe('TCP peer sockets send without delay', () => {
	const managers: PeerManager[] = [];
	const original = net.Socket.prototype.setNoDelay;
	/** Every socket told to send without delay while a test runs. */
	let withoutDelay: net.Socket[] = [];

	function manager(label: string): PeerManager {
		const pm = new PeerManager({
			localPrivateKey: key(label),
			autoReconnect: false
		});
		pm.on('error', () => undefined);
		managers.push(pm);
		return pm;
	}

	/** How many sockets on each side of `port` were told to send without delay. */
	function told(port: number): { dialed: number; accepted: number } {
		return {
			dialed: new Set(withoutDelay.filter((s) => s.remotePort === port)).size,
			accepted: new Set(withoutDelay.filter((s) => s.localPort === port)).size
		};
	}

	beforeEach(() => {
		withoutDelay = [];
		net.Socket.prototype.setNoDelay = function (
			this: net.Socket,
			noDelay?: boolean
		): net.Socket {
			if (noDelay === true) withoutDelay.push(this);
			return original.call(this, noDelay);
		};
	});

	afterEach(() => {
		net.Socket.prototype.setNoDelay = original;
		for (const pm of managers.splice(0)) pm.destroy();
	});

	it('on the socket it dials and on the socket the listener accepts', async () => {
		const port = await freePort();
		const host = manager('nodelay-host');
		await host.listen(port, '127.0.0.1');
		const guest = manager('nodelay-guest');

		await guest.connectPeer(
			getPublicKey(key('nodelay-host')).toString('hex'),
			'127.0.0.1',
			port
		);
		await until(() => host.listPeers().length === 1);

		expect(told(port)).to.deep.equal({ dialed: 1, accepted: 1 });
	});

	it('on a socket a factory hands over, as a SOCKS5 proxy does', async () => {
		const port = await freePort();
		const host = manager('nodelay-factory-host');
		await host.listen(port, '127.0.0.1');
		let made = 0;
		const guest = new Peer({
			localPrivateKey: key('nodelay-factory-guest'),
			remotePublicKey: getPublicKey(key('nodelay-factory-host')),
			host: '127.0.0.1',
			port,
			createSocket: async (
				address: string,
				to: number
			): Promise<net.Socket> => {
				made++;
				const socket = net.connect(to, address);
				await new Promise<void>((resolve, reject) => {
					socket.once('connect', () => resolve());
					socket.once('error', reject);
				});
				return socket;
			}
		});
		guest.on('error', () => undefined);

		try {
			await guest.connect();
			await until(() => host.listPeers().length === 1);

			expect(made).to.equal(1);
			expect(told(port)).to.deep.equal({ dialed: 1, accepted: 1 });
		} finally {
			guest.disconnect();
		}
	});
});
