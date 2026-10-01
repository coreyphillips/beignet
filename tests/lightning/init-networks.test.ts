/**
 * BOLT 1 init `networks`: a peer whose chains share none with ours is
 * disconnected during the init exchange, over a real localhost connection.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import net from 'net';
import { Peer } from '../../src/lightning/transport/peer';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	BITCOIN_CHAIN_HASH,
	REGTEST_CHAIN_HASH
} from '../../src/lightning/channel/types';

const HOST_SECRET = crypto.randomBytes(32);

interface IHost {
	port: number;
	/** Settles with the inbound side's accept outcome. */
	accepted: Promise<Error | null>;
	close(): Promise<void>;
}

async function startHost(networks?: Buffer[]): Promise<IHost> {
	const sessions: Peer[] = [];
	let settle: (outcome: Error | null) => void = () => undefined;
	const accepted = new Promise<Error | null>((resolve) => {
		settle = resolve;
	});
	const server = net.createServer((socket) => {
		const peer = new Peer({
			localPrivateKey: HOST_SECRET,
			remotePublicKey: Buffer.alloc(33, 0),
			host: '127.0.0.1',
			port: 0,
			networks
		});
		peer.on('error', () => undefined);
		sessions.push(peer);
		peer.acceptInbound(socket).then(
			() => settle(null),
			(err: Error) => {
				socket.destroy();
				settle(err);
			}
		);
	});
	const port = await new Promise<number>((resolve, reject) => {
		server.once('error', reject);
		server.listen(0, '127.0.0.1', () => {
			const address = server.address();
			if (address === null || typeof address === 'string') {
				reject(new Error('no address'));
				return;
			}
			resolve(address.port);
		});
	});
	return {
		port,
		accepted,
		close: (): Promise<void> =>
			new Promise((resolve) => {
				for (const peer of sessions) peer.disconnect();
				server.close(() => resolve());
			})
	};
}

function dial(port: number, networks?: Buffer[]): Peer {
	const peer = new Peer({
		localPrivateKey: crypto.randomBytes(32),
		remotePublicKey: getPublicKey(HOST_SECRET),
		host: '127.0.0.1',
		port,
		networks
	});
	peer.on('error', () => undefined);
	return peer;
}

describe('init networks (BOLT 1)', function () {
	let host: IHost | undefined;
	let peer: Peer | undefined;

	afterEach(async function () {
		peer?.disconnect();
		await host?.close();
		peer = undefined;
		host = undefined;
	});

	it('disconnects when the peer shares no chain with us', async function () {
		host = await startHost([BITCOIN_CHAIN_HASH]);
		peer = dial(host.port, [REGTEST_CHAIN_HASH]);

		const dialError = await peer.connect().then(
			() => null,
			(err: Error) => err
		);
		expect(dialError?.message).to.match(/share no chain/);
		expect((await host.accepted)?.message).to.match(/share no chain/);
	});

	it('connects when one chain is shared', async function () {
		host = await startHost([BITCOIN_CHAIN_HASH, REGTEST_CHAIN_HASH]);
		peer = dial(host.port, [REGTEST_CHAIN_HASH]);

		await peer.connect();
		expect(await host.accepted).to.equal(null);
	});

	it('connects when the peer advertises no networks', async function () {
		host = await startHost();
		peer = dial(host.port, [REGTEST_CHAIN_HASH]);

		await peer.connect();
		expect(await host.accepted).to.equal(null);
	});
});
