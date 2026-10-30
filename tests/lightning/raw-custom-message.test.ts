import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { Network } from '../../src/lightning/invoice/types';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { Peer } from '../../src/lightning/transport/peer';
import { PeerErrorCode } from '../../src/lightning/transport/peer-manager';
import { MessageType } from '../../src/lightning/message/types';
import { BEIGNET_CUSTOM_MESSAGE_TYPE } from '../../src/lightning/message/custom';

const PEER = getPublicKey(Buffer.alloc(32, 11)).toString('hex');
const TYPES = [32768, 32769, 65535];

function makeNode(networking = false): LightningNode {
	const key = (): Buffer => getPublicKey(crypto.randomBytes(32));
	return new LightningNode({
		nodePrivateKey: crypto.randomBytes(32),
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: {
			fundingPubkey: key(),
			revocationBasepoint: key(),
			paymentBasepoint: key(),
			delayedPaymentBasepoint: key(),
			htlcBasepoint: key(),
			firstPerCommitmentPoint: key()
		},
		perCommitmentSeed: crypto.randomBytes(32),
		fundingPrivkey: crypto.randomBytes(32),
		enableNetworking: networking
	});
}

interface RawMessage {
	peerPubkey: string;
	type: number;
	payload: Buffer;
}

function nextMessage(node: LightningNode): Promise<RawMessage> {
	return new Promise((resolve, reject) => {
		const listener = (message: RawMessage): void => {
			clearTimeout(timer);
			resolve(message);
		};
		const timer = setTimeout(() => {
			node.removeListener('raw-custom-message', listener);
			reject(new Error('raw custom message timed out'));
		}, 3000);
		node.once('raw-custom-message', listener);
	});
}

describe('Raw custom peer messages', function () {
	this.timeout(10000);

	it('registers only unused experimental uint16 types atomically', () => {
		const node = makeNode();
		try {
			for (const invalid of [
				NaN,
				Infinity,
				-1,
				1.5,
				32767,
				65536,
				BEIGNET_CUSTOM_MESSAGE_TYPE,
				MessageType.FF_INIT
			]) {
				expect(() =>
					node.registerRawCustomMessageTypes([32768, invalid])
				).to.throw(/unused uint16/);
				expect(() =>
					node.sendRawCustomMessage(PEER, 32768, Buffer.alloc(0))
				).to.throw(/not registered/);
			}
		} finally {
			node.destroy();
		}
	});

	it('reference counts overlapping registrations and releases each once', () => {
		const node = makeNode();
		try {
			const seen: number[] = [];
			node.on('raw-custom-message', (msg) => seen.push(msg.type));
			const first = node.registerRawCustomMessageTypes([32768, 32768, 32769]);
			const second = node.registerRawCustomMessageTypes([32768]);
			first();
			first();
			node.handlePeerMessage(PEER, 32768, Buffer.alloc(0));
			node.handlePeerMessage(PEER, 32769, Buffer.alloc(0));
			expect(seen).deep.equal([32768]);
			second();
			expect(() =>
				node.sendRawCustomMessage(PEER, 32768, Buffer.alloc(0))
			).to.throw(/not registered/);
		} finally {
			node.destroy();
		}
	});

	it('isolates subscriber buffers and failures while respecting once listeners', () => {
		const node = makeNode();
		try {
			node.registerRawCustomMessageTypes(TYPES);
			const payload = Buffer.from('quote');
			const seen: RawMessage[] = [];
			let once = 0;
			node.on('raw-custom-message', (msg) => {
				msg.payload.fill(0);
				throw new Error('listener');
			});
			node.on('log', () => {
				throw new Error('log');
			});
			node.once('raw-custom-message', () => {
				once++;
			});
			node.on('raw-custom-message', (msg) => seen.push(msg));
			for (let i = 0; i < 2; i++)
				node.handlePeerMessage(PEER.toUpperCase(), 32768, payload);
			expect(once).equal(1);
			expect(seen).have.length(2);
			expect(seen[0].peerPubkey).equal(PEER);
			expect(seen[0].payload.equals(payload)).equal(true);
			expect(seen[1].payload.equals(Buffer.from('quote'))).equal(true);
		} finally {
			node.destroy();
		}
	});

	it('bounds inbound frames and validates external transport peer-key format', () => {
		const node = makeNode();
		try {
			node.registerRawCustomMessageTypes(TYPES);
			const lengths: number[] = [];
			node.on('raw-custom-message', (msg) => lengths.push(msg.payload.length));
			node.handlePeerMessage(PEER, 32768, Buffer.alloc(65533));
			node.handlePeerMessage(PEER, 32768, Buffer.alloc(65534));
			node.handlePeerMessage('invalid', 32768, Buffer.alloc(0));
			node.handlePeerMessage(PEER, 32768, new Uint8Array(1) as Buffer);
			expect(lengths).deep.equal([65533]);
		} finally {
			node.destroy();
		}
	});

	it('refuses unregistered, oversized, malformed and disconnected outbound requests', () => {
		const node = makeNode(true);
		try {
			node.registerRawCustomMessageTypes(TYPES);
			expect(() =>
				node.sendRawCustomMessage(PEER, 32770, Buffer.alloc(0))
			).to.throw(/not registered/);
			expect(() =>
				node.sendRawCustomMessage(PEER, 32768, Buffer.alloc(65534))
			).to.throw(/65533/);
			expect(() =>
				node.sendRawCustomMessage(PEER, 32768, new Uint8Array(1) as Buffer)
			).to.throw(/Buffer/);
			expect(() =>
				node.sendRawCustomMessage('invalid', 32768, Buffer.alloc(0))
			).to.throw();
			expect(() => node.sendRawCustomMessage(PEER, 32768, Buffer.alloc(0)))
				.to.throw()
				.property('code', PeerErrorCode.NOT_CONNECTED);
		} finally {
			node.destroy();
		}
	});

	it('keeps event-transport input behind the node recovery gate', () => {
		const node = makeNode();
		try {
			node.registerRawCustomMessageTypes(TYPES);
			(
				node as unknown as { recoveryPermitsPeerTraffic(): boolean }
			).recoveryPermitsPeerTraffic = (): boolean => false;
			let received = false;
			node.on('raw-custom-message', () => {
				received = true;
			});
			node.handlePeerMessage(PEER, 32768, Buffer.alloc(0));
			expect(received).equal(false);
		} finally {
			node.destroy();
		}
	});

	it('passes exact even and odd wire types over Noise with authenticated sender identity', async () => {
		const a = makeNode(true),
			b = makeNode(true);
		try {
			a.registerRawCustomMessageTypes(TYPES);
			b.registerRawCustomMessageTypes(TYPES);
			await b.listen(0, '127.0.0.1');
			const port = (
				b.getPeerManager() as unknown as {
					server: { address(): { port: number } };
				}
			).server.address().port;
			await a.connectPeer(b.getNodeId(), '127.0.0.1', port);
			for (const type of TYPES) {
				const payload =
					type === 65535
						? Buffer.alloc(65533, 13)
						: Buffer.from([0, 1, 2, 255]);
				const received = nextMessage(b);
				a.sendRawCustomMessage(b.getNodeId().toUpperCase(), type, payload);
				const message = await received;
				expect(message.peerPubkey).equal(a.getNodeId());
				expect(message.type).equal(type);
				expect(message.payload.equals(payload)).equal(true);
			}
			const reply = nextMessage(a);
			b.sendRawCustomMessage(a.getNodeId(), 32768, Buffer.from('reply'));
			expect((await reply).peerPubkey).equal(b.getNodeId());
			a.getPeerManager()!.setOutboundGate(() => false);
			expect(() =>
				a.sendRawCustomMessage(b.getNodeId(), 32768, Buffer.alloc(0))
			)
				.to.throw()
				.property('code', PeerErrorCode.OUTBOUND_GATE_REFUSED);
		} finally {
			a.destroy();
			b.destroy();
		}
	});

	it('still disconnects unknown required types and changes support on live peers', () => {
		const supported = new Set([32768]);
		const peer = new Peer({
			localPrivateKey: Buffer.alloc(32, 12),
			remotePublicKey: Buffer.from(PEER, 'hex'),
			host: '127.0.0.1',
			port: 1,
			isKnownCustomMessageType: (type): boolean => supported.has(type)
		});
		const received: number[] = [],
			errors: string[] = [];
		peer.on('message', (type) => received.push(type));
		peer.on('error', (error: Error) => errors.push(error.message));
		const input = peer as unknown as {
			state: string;
			handleMessage(type: number, payload: Buffer): void;
		};
		input.state = 'ready';
		input.handleMessage(32768, Buffer.alloc(0));
		supported.delete(32768);
		input.handleMessage(32768, Buffer.alloc(0));
		expect(received).deep.equal([32768]);
		expect(errors).deep.equal(['Unknown required message type 32768']);
		peer.disconnect();
	});
});
