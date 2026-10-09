/**
 * Write buffer ceiling (issue #1400): gossip and sync replies are dropped
 * under backpressure, but every other message is queued. A channel peer that
 * reads just enough to answer pings would otherwise grow the write buffer
 * without bound, so past a hard ceiling the peer is disconnected instead.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { Peer } from '../../src/lightning/transport/peer';
import { MessageType } from '../../src/lightning/message/types';
import { BEIGNET_CUSTOM_MESSAGE_TYPE } from '../../src/lightning/message/custom';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

const MB = 1024 * 1024;
const CEILING = 72 * MB;

const key = (label: string): Buffer =>
	crypto.createHash('sha256').update(label).digest();

/**
 * A ready Peer over a socket that never drains: every write adds to
 * writableLength, which starts at `buffered`.
 */
function stalledPeer(buffered: number): {
	peer: Peer;
	writes: number[];
	errors: Error[];
	destroyed: () => boolean;
} {
	const peer = new Peer({
		localPrivateKey: key('write-ceiling-local'),
		remotePublicKey: getPublicKey(key('write-ceiling-remote')),
		host: '127.0.0.1',
		port: 1
	});
	const writes: number[] = [];
	const errors: Error[] = [];
	let destroyed = false;
	const socket = {
		writableLength: buffered,
		write: (data: Buffer): boolean => {
			writes.push(data.readUInt16BE(0));
			socket.writableLength += data.length;
			return false;
		},
		removeAllListeners: (): void => undefined,
		destroy: (): void => {
			destroyed = true;
		}
	};
	Object.assign(peer, {
		state: 'ready',
		transport: { encryptPacket: (message: Buffer): Buffer => message },
		socket
	});
	peer.on('error', (err: Error) => errors.push(err));
	return { peer, writes, errors, destroyed: (): boolean => destroyed };
}

describe('Peer write buffer ceiling (issue #1400)', function () {
	it('still queues channel messages up to the ceiling', function () {
		const { peer, writes, errors } = stalledPeer(CEILING - 2000);
		peer.sendMessage(MessageType.UPDATE_ADD_HTLC, Buffer.alloc(1450));
		peer.sendMessage(MessageType.COMMITMENT_SIGNED, Buffer.alloc(98));

		expect(writes).to.eql([
			MessageType.UPDATE_ADD_HTLC,
			MessageType.COMMITMENT_SIGNED
		]);
		expect(errors).to.eql([]);
		expect(peer.getState()).to.equal('ready');
	});

	it('disconnects a peer whose buffer is past the ceiling', function () {
		const { peer, writes, errors, destroyed } = stalledPeer(CEILING + 1);
		let stateAtError = '';
		peer.on('error', () => {
			stateAtError = peer.getState();
		});
		peer.sendMessage(MessageType.COMMITMENT_SIGNED, Buffer.alloc(98));

		expect(writes).to.eql([]);
		expect(destroyed()).to.equal(true);
		expect(peer.getState()).to.equal('disconnected');
		expect(errors).to.have.length(1);
		expect(errors[0].message).to.contain('Write buffer overflow');
		// A send from an error observer must throw, not loop back in here.
		expect(stateAtError).to.equal('disconnected');
		expect(() =>
			peer.sendMessage(MessageType.UPDATE_ADD_HTLC, Buffer.alloc(1450))
		).to.throw('not ready');
	});

	it('writes a 64 MiB guardian response whole on an idle connection', function () {
		const { peer, writes, errors } = stalledPeer(0);
		const chunk = Buffer.alloc(65_000);
		const chunks = Math.ceil((64 * MB) / chunk.length);
		for (let i = 0; i < chunks; i++) {
			peer.sendMessage(BEIGNET_CUSTOM_MESSAGE_TYPE, chunk);
		}

		expect(writes).to.have.length(chunks);
		expect(errors).to.eql([]);
		expect(peer.getState()).to.equal('ready');
	});
});
