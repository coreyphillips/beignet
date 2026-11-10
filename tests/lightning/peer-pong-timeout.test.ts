/**
 * The pong deadline runs from the oldest ping still unanswered. It used to
 * start again on every ping, and with pings every 30s and a 60s deadline it
 * never ran out, so a connection that went silent without a socket error (a
 * suspended phone, a dead Tor circuit) stayed listed as connected for good.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import sinon from 'sinon';
import { Peer } from '../../src/lightning/transport/peer';
import { MessageType } from '../../src/lightning/message/types';
import { encodePongMessage } from '../../src/lightning/message/ping';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

const key = (label: string): Buffer =>
	crypto.createHash('sha256').update(label).digest();

/** A ready Peer pinging on the default schedule, its transport never run. */
function pingingPeer(): { peer: Peer; pings: () => number; errors: Error[] } {
	const peer = new Peer({
		localPrivateKey: key('pong-timeout-local'),
		remotePublicKey: getPublicKey(key('pong-timeout-remote')),
		host: '127.0.0.1',
		port: 1
	});
	(peer as unknown as { state: string }).state = 'ready';
	let sent = 0;
	peer.sendMessage = (type: number): void => {
		if (type === MessageType.PING) sent += 1;
	};
	const errors: Error[] = [];
	peer.on('error', (err: Error) => errors.push(err));
	(peer as unknown as { startPingTimer(): void }).startPingTimer();
	return { peer, pings: () => sent, errors };
}

const pong = (peer: Peer): void =>
	(
		peer as unknown as {
			handleMessage(type: number, payload: Buffer): void;
		}
	).handleMessage(MessageType.PONG, encodePongMessage(1));

describe('Peer pong deadline', function () {
	let clock: sinon.SinonFakeTimers;

	beforeEach(function () {
		clock = sinon.useFakeTimers({
			now: Date.now(),
			toFake: [
				'setTimeout',
				'clearTimeout',
				'setInterval',
				'clearInterval',
				'Date'
			]
		});
	});

	afterEach(function () {
		clock.restore();
	});

	it('closes a silent peer 60s after the first unanswered ping, though pings go on', function () {
		const { peer, pings, errors } = pingingPeer();
		clock.tick(30_000);
		expect(pings()).to.equal(1);
		// The second ping, at 60s, does not move the first one's deadline.
		clock.tick(59_999);
		expect(pings()).to.equal(2);
		expect(errors).to.deep.equal([]);
		expect(peer.getState()).to.equal('ready');
		clock.tick(1);
		expect(errors.map((err) => err.message)).to.deep.equal(['Pong timeout']);
		expect(peer.getState()).to.equal('disconnected');
		// Disconnected, it pings no more and times out no more.
		const sent = pings();
		clock.tick(600_000);
		expect(pings()).to.equal(sent);
		expect(errors).to.have.length(1);
	});

	it('keeps a peer that answers inside the deadline', function () {
		const { peer, pings, errors } = pingingPeer();
		for (let i = 0; i < 20; i++) {
			clock.tick(30_000);
			// A slow answer, inside the deadline, as a stalled Tor circuit gives.
			clock.tick(25_000);
			pong(peer);
			clock.tick(5_000);
		}
		expect(pings()).to.equal(40);
		expect(errors).to.deep.equal([]);
		expect(peer.getState()).to.equal('ready');
	});

	it('gives a ping sent after an answer the full deadline again', function () {
		const { peer, errors } = pingingPeer();
		clock.tick(30_000);
		pong(peer);
		// The next ping, at 60s, goes unanswered: its deadline is 120s.
		clock.tick(30_000);
		clock.tick(59_999);
		expect(errors).to.deep.equal([]);
		expect(peer.getState()).to.equal('ready');
		clock.tick(1);
		expect(errors.map((err) => err.message)).to.deep.equal(['Pong timeout']);
		expect(peer.getState()).to.equal('disconnected');
	});
});
