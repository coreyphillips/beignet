/**
 * Issue #1689: PeerManager.sendToPeer refuses with a coded PeerError, and
 * ChannelManager falls back to the host's transport only when the peer is not
 * connected. A gate's refusal is deliberate, so the message must not leave by
 * message:outbound either.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { MessageType } from '../../src/lightning/message/types';
import {
	PeerError,
	PeerErrorCode,
	PeerManager
} from '../../src/lightning/transport/peer-manager';

const PEER = getPublicKey(Buffer.alloc(32, 7)).toString('hex');

function key(label: string): Buffer {
	return crypto.createHash('sha256').update(label).digest();
}

function makeConfig(): IChannelManagerConfig {
	const point = (i: number): Buffer => getPublicKey(key(`basepoint-${i}`));
	return {
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: {
			fundingPubkey: point(0),
			revocationBasepoint: point(1),
			paymentBasepoint: point(2),
			delayedPaymentBasepoint: point(3),
			htlcBasepoint: point(4),
			firstPerCommitmentPoint: Buffer.alloc(33)
		},
		localPerCommitmentSeed: key('seed'),
		localFundingPrivkey: key('funding'),
		htlcBasepointSecret: key('htlc')
	};
}

/** What reaches message:outbound when sendToPeer throws `thrown`. */
function relayedAfter(thrown: Error): number {
	const manager = new ChannelManager(makeConfig());
	manager.on('error', () => undefined);
	let relayed = 0;
	manager.on('message:outbound', () => {
		relayed++;
	});
	(manager as unknown as { peerManager: unknown }).peerManager = {
		sendToPeer: (): never => {
			throw thrown;
		}
	};
	(
		manager as unknown as {
			sendMessage(peer: string, type: MessageType, payload: Buffer): void;
		}
	).sendMessage(PEER, MessageType.PING, Buffer.alloc(4));
	return relayed;
}

describe('Peer send refusal codes (issue #1689)', () => {
	it('refuses an unconnected peer with NOT_CONNECTED', () => {
		const pm = new PeerManager({ localPrivateKey: key('local') });
		try {
			let thrown: unknown;
			try {
				pm.sendToPeer(PEER, MessageType.PING, Buffer.alloc(4));
			} catch (err) {
				thrown = err;
			}
			expect(thrown).to.be.instanceOf(PeerError);
			expect((thrown as PeerError).code).to.equal(PeerErrorCode.NOT_CONNECTED);
			expect((thrown as PeerError).message).to.equal(
				`Not connected to peer ${PEER}`
			);
		} finally {
			pm.destroy();
		}
	});

	it('falls back to the host transport for a peer that is not connected', () => {
		expect(
			relayedAfter(new PeerError(PeerErrorCode.NOT_CONNECTED, 'not connected'))
		).to.equal(1);
	});

	it('falls back for a send that failed for another reason, as before', () => {
		expect(relayedAfter(new Error('socket closed'))).to.equal(1);
	});

	for (const code of [
		PeerErrorCode.OUTBOUND_GATE_REFUSED,
		PeerErrorCode.LANE_REFUSED
	]) {
		it(`does not relay a message refused with ${code}`, () => {
			expect(relayedAfter(new PeerError(code, 'refused'))).to.equal(0);
		});
	}
});
