/**
 * Ping flood (issue #1399): a ping of a few bytes may ask for a 65531-byte
 * pong, so the pong bytes a connection may request are metered and a peer
 * that runs past the allowance is closed instead of answered.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import sinon from 'sinon';
import { Peer } from '../../src/lightning/transport/peer';
import { MessageType } from '../../src/lightning/message/types';
import {
	encodePingMessage,
	decodePongMessage
} from '../../src/lightning/message/ping';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

const key = (label: string): Buffer =>
	crypto.createHash('sha256').update(label).digest();

/** A ready Peer whose transport never runs; sent pong sizes are recorded. */
function readyPeer(): { peer: Peer; pongs: number[]; errors: Error[] } {
	const peer = new Peer({
		localPrivateKey: key('ping-flood-local'),
		remotePublicKey: getPublicKey(key('ping-flood-remote')),
		host: '127.0.0.1',
		port: 1
	});
	(peer as unknown as { state: string }).state = 'ready';
	const pongs: number[] = [];
	const errors: Error[] = [];
	peer.sendMessage = (type: number, payload: Buffer): void => {
		if (type === MessageType.PONG) {
			pongs.push(decodePongMessage(payload).byteslen);
		}
	};
	peer.on('error', (err: Error) => errors.push(err));
	return { peer, pongs, errors };
}

const feedPing = (peer: Peer, payload: Buffer): void =>
	(
		peer as unknown as {
			handleMessage(type: number, payload: Buffer): void;
		}
	).handleMessage(MessageType.PING, payload);

const ping = (peer: Peer, numPongBytes: number): void =>
	feedPing(peer, encodePingMessage(numPongBytes));

describe('Peer ping flood (issue #1399)', function () {
	let clock: sinon.SinonFakeTimers;

	beforeEach(function () {
		clock = sinon.useFakeTimers({ now: Date.now(), toFake: ['Date'] });
	});

	afterEach(function () {
		clock.restore();
	});

	it('answers two maximum pongs, then closes the flooding peer', function () {
		const { peer, pongs, errors } = readyPeer();
		for (let i = 0; i < 1000; i++) ping(peer, 65531);
		expect(pongs).to.deep.equal([65531, 65531]);
		expect(errors).to.have.length(1);
		expect(errors[0].message).to.contain('Ping flood');
		expect(peer.getState()).to.equal('disconnected');
	});

	it('refills the allowance at one maximum pong per 30 seconds', function () {
		const { peer, pongs, errors } = readyPeer();
		ping(peer, 65531);
		ping(peer, 65531);
		clock.tick(30_000);
		ping(peer, 65531);
		expect(pongs).to.have.length(3);
		expect(errors).to.deep.equal([]);
		ping(peer, 65531);
		expect(pongs, 'the refill is not a fresh burst').to.have.length(3);
		expect(errors).to.have.length(1);
	});

	it('never meters zero-byte pongs, as LDK asks for during gossip', function () {
		const { peer, pongs, errors } = readyPeer();
		for (let i = 0; i < 10_000; i++) ping(peer, 0);
		expect(pongs).to.have.length(10_000);
		expect(errors).to.deep.equal([]);
		expect(peer.getState()).to.equal('ready');
	});

	it('keeps answering an LND-sized ping every minute', function () {
		const { peer, pongs, errors } = readyPeer();
		for (let i = 0; i < 120; i++) {
			ping(peer, 4096);
			clock.tick(60_000);
		}
		expect(pongs).to.have.length(120);
		expect(errors).to.deep.equal([]);
	});

	it('still ignores a ping asking for more than 65531 bytes', function () {
		const { peer, pongs, errors } = readyPeer();
		const payload = Buffer.alloc(4);
		payload.writeUInt16BE(65532, 0);
		for (let i = 0; i < 1000; i++) feedPing(peer, payload);
		expect(pongs).to.deep.equal([]);
		expect(errors).to.deep.equal([]);
		expect(peer.getState()).to.equal('ready');
	});
});
