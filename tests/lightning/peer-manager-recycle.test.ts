/**
 * PeerManager.recyclePeer (issue #2111): close a peer's connection so that
 * it is made again.
 *
 * BOLT 2's lighter answer to an update a node cannot take is "send a
 * `warning` and close the connection": the reestablish of the next
 * connection drops what neither side committed. disconnectPeer cancels any
 * dial, so after it nothing brings the connection back from this side.
 * recyclePeer tears the connection down the same way and then dials the
 * peer again on the usual backoff. Real sockets on localhost.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { PeerManager } from '../../src/lightning/transport/peer-manager';

interface IPair {
	server: PeerManager;
	client: PeerManager;
	serverPub: string;
	clientPub: string;
	/** The reasons of the client's peer:disconnect events, in order. */
	reasons: string[];
}

const wait = (ms: number): Promise<void> =>
	new Promise((resolve) => setTimeout(resolve, ms));

/** Polls `done` every 10 ms until it holds or `ms` have passed. */
async function until(done: () => boolean, ms: number): Promise<boolean> {
	const deadline = Date.now() + ms;
	while (!done() && Date.now() < deadline) await wait(10);
	return done();
}

// The private fields a test reads to see what is scheduled.
const timers = (pm: PeerManager): Map<string, unknown> =>
	(pm as unknown as { reconnectTimers: Map<string, unknown> }).reconnectTimers;
const delays = (pm: PeerManager): Map<string, number> =>
	(pm as unknown as { reconnectDelays: Map<string, number> }).reconnectDelays;
/** The port a listening PeerManager took. */
const portOf = (pm: PeerManager): number =>
	(
		pm as unknown as { server: { address: () => { port: number } } }
	).server.address().port;

describe('PeerManager.recyclePeer: a connection closed to be made again (issue #2111)', function () {
	this.timeout(30_000);
	const made: PeerManager[] = [];
	afterEach(() => {
		for (const pm of made.splice(0)) pm.destroy();
	});

	/** The client dials the server, as a wallet dials the peer it opened a channel to. */
	async function pair(): Promise<IPair> {
		const serverKey = crypto.randomBytes(32);
		const clientKey = crypto.randomBytes(32);
		const server = new PeerManager({ localPrivateKey: serverKey });
		const client = new PeerManager({
			localPrivateKey: clientKey,
			autoReconnect: true
		});
		made.push(client, server);
		await server.listen(0, '127.0.0.1');
		const port = portOf(server);
		const serverPub = getPublicKey(serverKey).toString('hex');
		const clientPub = getPublicKey(clientKey).toString('hex');
		const reasons: string[] = [];
		client.on(
			'peer:disconnect',
			(_pubkey: string, info: { reason?: string }) => {
				reasons.push(info.reason ?? '');
			}
		);
		await client.connectPeer(serverPub, '127.0.0.1', port);
		expect(
			await until(() => server.listPeers().length === 1, 5000),
			'the server holds the client'
		).to.equal(true);
		return { server, client, serverPub, clientPub, reasons };
	}

	const holds = (pm: PeerManager, pubkey: string): boolean =>
		pm.listPeers().some((p) => p.pubkey === pubkey);

	it('closes the connection at once and dials the peer again', async () => {
		const p = await pair();
		p.client.recyclePeer(p.serverPub);

		expect(holds(p.client, p.serverPub), 'closed at once').to.equal(false);
		expect(p.reasons).to.deep.equal(['connection recycled']);
		expect(timers(p.client).has(p.serverPub), 'a dial is scheduled').to.equal(
			true
		);
		// The first dial comes after the initial backoff, 1 s with jitter.
		expect(
			await until(() => holds(p.client, p.serverPub), 5000),
			'connected again'
		).to.equal(true);
		expect(
			await until(() => holds(p.server, p.clientPub), 5000),
			'the server holds the new connection'
		).to.equal(true);
	});

	it('keeps the backoff growing over recycles that come before a connection proves stable', async () => {
		const p = await pair();
		p.client.recyclePeer(p.serverPub);
		const first = delays(p.client).get(p.serverPub);
		expect(await until(() => holds(p.client, p.serverPub), 5000)).to.equal(
			true
		);
		p.client.recyclePeer(p.serverPub);
		const second = delays(p.client).get(p.serverPub);
		expect(first).to.equal(2000);
		expect(second).to.equal(4000);
	});

	it('disconnectPeer, as before, dials nothing', async () => {
		const p = await pair();
		p.client.disconnectPeer(p.serverPub);
		expect(holds(p.client, p.serverPub)).to.equal(false);
		expect(p.reasons).to.deep.equal(['disconnect requested']);
		expect(timers(p.client).has(p.serverPub)).to.equal(false);
		await wait(1500);
		expect(holds(p.client, p.serverPub), 'still closed').to.equal(false);
	});

	it('a disconnectPeer after it cancels the dial', async () => {
		const p = await pair();
		p.client.recyclePeer(p.serverPub);
		expect(timers(p.client).has(p.serverPub)).to.equal(true);
		p.client.disconnectPeer(p.serverPub);
		expect(timers(p.client).has(p.serverPub)).to.equal(false);
		await wait(1500);
		expect(holds(p.client, p.serverPub), 'still closed').to.equal(false);
	});

	it('a peer:disconnect observer that cancels the peer leaves no dial behind', async () => {
		const p = await pair();
		p.client.on('peer:disconnect', (pubkey: string) => {
			p.client.disconnectPeer(pubkey);
		});
		p.client.recyclePeer(p.serverPub);
		expect(timers(p.client).has(p.serverPub)).to.equal(false);
		await wait(1500);
		expect(holds(p.client, p.serverPub), 'still closed').to.equal(false);
	});

	it('dials nothing without autoReconnect, and is a disconnect for a peer it does not hold', async () => {
		const p = await pair();
		const quiet = new PeerManager({ localPrivateKey: crypto.randomBytes(32) });
		made.push(quiet);
		const port = portOf(p.server);
		await quiet.connectPeer(p.serverPub, '127.0.0.1', port);
		quiet.recyclePeer(p.serverPub);
		expect(holds(quiet, p.serverPub)).to.equal(false);
		expect(timers(quiet).has(p.serverPub)).to.equal(false);

		// Not held: nothing to close, and nothing scheduled.
		const stranger = getPublicKey(crypto.randomBytes(32)).toString('hex');
		p.client.recyclePeer(stranger);
		expect(timers(p.client).has(stranger)).to.equal(false);
		expect(holds(p.client, p.serverPub), 'the other peer stays').to.equal(true);
	});
});
