/**
 * The peer-carried direct-funding lanes (issue #611, LFBW port #532 4B):
 * lane 1 over an authenticated peer connection, lane 3 blind-relayed through a
 * shared peer, and the relay server half.
 *
 * Every drop and refusal path is here, because the fork had all of them and
 * none of them were visible: seven distinct silent drops with no metric and no
 * log (defect D28), and a forwarder with no rate limit, no per-peer budget, no
 * size cap and no self-loop refusal, which made an opt-in relay an unmetered
 * message bus between any two connected peers (defect D29).
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { Network } from '../../src/lightning/invoice/types';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { GuardianStartupGate } from '../../src/lightning/recovery/startup-gate';
import {
	BEIGNET_CUSTOM_PROTOCOL_VERSION,
	BeignetCustomSubtype,
	encodeCustomMessage
} from '../../src/lightning/message/custom';
import {
	DF_MAX_FRAME_BYTES,
	DfDirectPeerLaneFactory,
	DfDropReason,
	DfRelayForwarder,
	DfRelayLaneFactory,
	IDfInboundFrame,
	IDfPeerMessaging,
	laneKeyFor
} from '../../src/lightning/direct-funding/transport';
import {
	IDfWireFrame,
	decodeSealedFrame,
	encodeSealedFrame,
	openFrame,
	sealFrame,
	senderLaneKeys
} from '../../src/lightning/direct-funding/frames';
import { encodeDfRelayFrame } from '../../src/lightning/direct-funding/messages';
import { DirectFundingRequestStore } from '../../src/lightning/direct-funding/requests';
import { DfTransportType } from '../../src/lightning/direct-funding/types';
import {
	FakeDfNetwork,
	FakeDfPeer,
	recordingLog
} from './helpers/df-transport';

const OFFER = BeignetCustomSubtype.DIRECT_FUNDING_OFFER;
const RECEIPT = BeignetCustomSubtype.DIRECT_FUNDING_RECEIPT;
const RELAY = BeignetCustomSubtype.DIRECT_FUNDING_RELAY;

/** An opening frame for `requestId` that nothing here needs to open. */
function openingFrame(requestId: Buffer): Buffer {
	return encodeSealedFrame(
		{ nonce: Buffer.alloc(12, 3), ciphertext: Buffer.alloc(32, 4) },
		{ requestId, ephemeralPublicKey: pubkeyFor('ephemeral') }
	);
}

function continuationFrame(): Buffer {
	return encodeSealedFrame({
		nonce: Buffer.alloc(12, 5),
		ciphertext: Buffer.alloc(32, 6)
	});
}

function pubkeyFor(label: string): Buffer {
	return getPublicKey(crypto.createHash('sha256').update(label).digest());
}

describe('Direct-funding lane 1: direct peer', () => {
	let net: FakeDfNetwork;
	let payer: FakeDfPeer;
	let receiver: FakeDfPeer;

	beforeEach(() => {
		net = new FakeDfNetwork();
		payer = net.add('payer');
		receiver = net.add('receiver');
	});

	const descriptor = {
		type: DfTransportType.DIRECT_PEER as const,
		host: 'receiver.example',
		port: 9735
	};

	it('carries a sealed 4A frame both ways between two nodes', async () => {
		const store = new DirectFundingRequestStore({});
		const record = store.mint();
		const requestId = Buffer.from(record.requestId, 'hex');

		const receiverFactory = new DfDirectPeerLaneFactory(receiver);
		const inbound: IDfInboundFrame[] = [];
		receiverFactory.attachInbound((f) => inbound.push(f));

		const payerFactory = new DfDirectPeerLaneFactory(payer);
		const lane = await payerFactory.open(descriptor, {
			requestId,
			receiverNodeId: Buffer.from(receiver.id, 'hex')
		});
		expect(lane).to.not.equal(null);

		const replies: Buffer[] = [];
		const sender = senderLaneKeys(
			getPublicKey(Buffer.from(record.encryptionPrivateKeyHex, 'hex')),
			requestId
		);
		lane!.onMessage((f) => {
			const body = openFrame(
				sender.keys.recvKey,
				requestId,
				f.subtype,
				decodeWire(f.payload)
			);
			if (body) replies.push(body);
		});

		const offer = sealFrame(
			sender.keys.sendKey,
			requestId,
			OFFER,
			Buffer.from('offer body')
		);
		lane!.send(
			OFFER,
			encodeSealedFrame(offer, {
				requestId,
				ephemeralPublicKey: sender.ephemeralPublicKey
			})
		);

		// The receiver derives its half from the frame alone, exactly as 4C will.
		expect(inbound.length).to.equal(1);
		expect(inbound[0].authenticatedPeer).to.equal(payer.id);
		const keys = store.laneKeysForFrame(decodeWire(inbound[0].payload));
		expect(keys).to.not.equal(null);
		const body = openFrame(
			keys!.keys.recvKey,
			requestId,
			OFFER,
			decodeWire(inbound[0].payload)
		);
		expect(body?.toString()).to.equal('offer body');

		const receipt = sealFrame(
			keys!.keys.sendKey,
			requestId,
			RECEIPT,
			Buffer.from('receipt body')
		);
		inbound[0].reply.send(RECEIPT, encodeSealedFrame(receipt));

		expect(replies.map((r) => r.toString())).to.deep.equal(['receipt body']);
		expect(lane!.framesExchanged()).to.equal(2);
		lane!.close();
		expect(payerFactory.openLaneCount).to.equal(0);
	});

	it('dials the receiver, and falls through when the dial fails', async () => {
		const factory = new DfDirectPeerLaneFactory(payer);
		net.undialable.add(receiver.id);
		const lane = await factory.open(descriptor, {
			requestId: Buffer.alloc(16, 1),
			receiverNodeId: Buffer.from(receiver.id, 'hex')
		});
		expect(lane).to.equal(null);
		expect(payer.dialAttempts).to.equal(1);
	});

	it('routes an offer for another request to the receiver sink, not the payer lane', async () => {
		// Both roles at once on one connection: the discriminator is the request
		// the opening frame names, not the peer.
		const paying = Buffer.alloc(16, 1);
		const offered = Buffer.alloc(16, 2);
		const factory = new DfDirectPeerLaneFactory(payer);
		const sunk: IDfInboundFrame[] = [];
		factory.attachInbound((f) => sunk.push(f));
		const lane = await factory.open(descriptor, {
			requestId: paying,
			receiverNodeId: Buffer.from(receiver.id, 'hex')
		});
		const claimed: IDfInboundFrame[] = [];
		lane!.onMessage((f) => claimed.push(f));

		payer.deliver({
			peerPubkey: receiver.id,
			subtype: OFFER,
			payload: openingFrame(offered)
		});
		expect(sunk.length).to.equal(1);
		expect(claimed.length).to.equal(0);

		// A continuation names no request, so the open lane AND the session the
		// offer just started both get a look; each drops what it cannot open.
		// Giving it to the payer lane alone starved the receiving session.
		payer.deliver({
			peerPubkey: receiver.id,
			subtype: RECEIPT,
			payload: continuationFrame()
		});
		expect(claimed.length).to.equal(1);
		expect(sunk.length).to.equal(2);
		lane!.close();
	});

	it('drops a frame in a protocol version it does not speak', () => {
		const recorder = recordingLog();
		const factory = new DfDirectPeerLaneFactory(payer, recorder.log);
		const seen: IDfInboundFrame[] = [];
		factory.attachInbound((f) => seen.push(f));
		payer.deliver({
			peerPubkey: receiver.id,
			version: BEIGNET_CUSTOM_PROTOCOL_VERSION + 1,
			subtype: OFFER,
			payload: openingFrame(Buffer.alloc(16, 1))
		});
		expect(seen).to.deep.equal([]);
		expect(recorder.reasons()).to.deep.equal([
			DfDropReason.UNSUPPORTED_VERSION
		]);
	});

	it('drops a frame nothing is listening for, and says so', () => {
		const recorder = recordingLog();
		const factory = new DfDirectPeerLaneFactory(payer, recorder.log);
		const detach = factory.attachInbound(() => undefined);
		detach();
		payer.deliver({
			peerPubkey: receiver.id,
			subtype: OFFER,
			payload: openingFrame(Buffer.alloc(16, 9))
		});
		expect(recorder.reasons()).to.deep.equal([DfDropReason.NO_LISTENER]);
	});

	it('drops a payload that is not a sealed frame at all', () => {
		const recorder = recordingLog();
		const factory = new DfDirectPeerLaneFactory(payer, recorder.log);
		factory.attachInbound(() => undefined);
		payer.deliver({
			peerPubkey: receiver.id,
			subtype: OFFER,
			payload: Buffer.from([0xff, 0x01])
		});
		expect(recorder.reasons()).to.deep.equal([DfDropReason.NOT_A_SEALED_FRAME]);
	});

	it('drops an oversized frame before decoding it', () => {
		const recorder = recordingLog();
		const factory = new DfDirectPeerLaneFactory(payer, recorder.log);
		factory.attachInbound(() => undefined);
		payer.deliver({
			peerPubkey: receiver.id,
			subtype: OFFER,
			payload: Buffer.alloc(DF_MAX_FRAME_BYTES + 1)
		});
		expect(recorder.reasons()).to.deep.equal([DfDropReason.FRAME_TOO_LARGE]);
	});

	it('reports the reserved abort subtype and ignores unrelated traffic', () => {
		const recorder = recordingLog();
		const factory = new DfDirectPeerLaneFactory(payer, recorder.log);
		factory.attachInbound(() => undefined);
		payer.deliver({
			peerPubkey: receiver.id,
			subtype: BeignetCustomSubtype.DIRECT_FUNDING_ABORT,
			payload: Buffer.alloc(4)
		});
		payer.deliver({
			peerPubkey: receiver.id,
			subtype: BeignetCustomSubtype.JIT_RECEIVE_ACK,
			payload: Buffer.alloc(4)
		});
		expect(recorder.reasons()).to.deep.equal([DfDropReason.UNHANDLED_SUBTYPE]);
	});

	it('never lets a throwing frame handler cost the peer its connection', () => {
		const recorder = recordingLog();
		const factory = new DfDirectPeerLaneFactory(payer, recorder.log);
		factory.attachInbound(() => {
			throw new Error('application observer bug');
		});
		const afterUs: number[] = [];
		payer.onCustomMessage((msg) => afterUs.push(msg.subtype));

		payer.deliver({
			peerPubkey: receiver.id,
			subtype: OFFER,
			payload: openingFrame(Buffer.alloc(16, 1))
		});

		// The node's dispatch would have swallowed the throw AND skipped every
		// later listener; neither happened.
		expect(payer.escapedErrors).to.deep.equal([]);
		expect(afterUs).to.deep.equal([OFFER]);
		expect(recorder.reasons()).to.include(DfDropReason.HANDLER_FAILED);
	});

	it('refuses an oversized send by name and reports it from trySend', async () => {
		const recorder = recordingLog();
		const factory = new DfDirectPeerLaneFactory(payer, recorder.log);
		net.connect(payer, receiver);
		const lane = await factory.open(descriptor, {
			requestId: Buffer.alloc(16, 1),
			receiverNodeId: Buffer.from(receiver.id, 'hex')
		});
		const huge = Buffer.alloc(DF_MAX_FRAME_BYTES + 1);
		expect(() => lane!.send(OFFER, huge)).to.throw(/max/);
		expect(lane!.trySend(OFFER, huge)).to.equal(false);
		expect(recorder.reasons()).to.include(DfDropReason.SEND_FAILED);
		expect(lane!.framesExchanged()).to.equal(0);
	});

	it('turns a send to a vanished peer into a logged no-op, not a throw', async () => {
		// The fork's offer resend fired from a bare setTimeout into a send that
		// throws `Not connected to peer`, which is an uncaughtException (D2).
		const recorder = recordingLog();
		const factory = new DfDirectPeerLaneFactory(payer, recorder.log);
		net.connect(payer, receiver);
		const lane = await factory.open(descriptor, {
			requestId: Buffer.alloc(16, 1),
			receiverNodeId: Buffer.from(receiver.id, 'hex')
		});
		payer.connections.delete(receiver.id);
		expect(lane!.trySend(OFFER, continuationFrame())).to.equal(false);
		expect(recorder.reasons()).to.include(DfDropReason.SEND_FAILED);
	});
});

describe('Direct-funding lane 1 and the recovery gates', () => {
	function makeNode(gate?: FakeGate): LightningNode {
		const seed = crypto.randomBytes(32);
		const k = (i: number): Buffer =>
			getPublicKey(
				crypto
					.createHash('sha256')
					.update(seed)
					.update(Buffer.from([i]))
					.digest()
			);
		const basepoints: IChannelBasepoints = {
			fundingPubkey: k(0),
			revocationBasepoint: k(1),
			paymentBasepoint: k(2),
			delayedPaymentBasepoint: k(3),
			htlcBasepoint: k(4),
			firstPerCommitmentPoint: Buffer.alloc(33)
		};
		return new LightningNode({
			nodePrivateKey: crypto.randomBytes(32),
			network: Network.REGTEST,
			channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
			channelBasepoints: basepoints,
			perCommitmentSeed: crypto.randomBytes(32),
			fundingPrivkey: crypto.randomBytes(32),
			...(gate
				? {
						recovery: {
							startupGate: gate as unknown as GuardianStartupGate
						}
				  }
				: {})
		});
	}

	/** Enough of the startup gate for the node's one question. */
	class FakeGate {
		state: 'confirmed' | 'quarantined' = 'quarantined';
		blocked: string[] = [];
		onOpen(listener: () => void): void {
			if (this.state === 'confirmed') listener();
		}
		onFenced(): void {
			return;
		}
		getState(): string {
			return this.state;
		}
		permitsPeerTraffic(): boolean {
			return this.state === 'confirmed';
		}
		reportBlocked(detail: string): void {
			this.blocked.push(detail);
		}
	}

	/** The real node surface a lane is allowed to touch, and nothing else. */
	function peerMessagingFor(node: LightningNode): IDfPeerMessaging {
		return {
			nodeIdHex: () => node.getNodeId(),
			sendCustomMessage: (peer, subtype, payload) =>
				node.sendCustomMessage(peer, subtype, payload),
			onCustomMessage: (cb): (() => void) => {
				node.on('custom-message', cb);
				return () => {
					node.removeListener('custom-message', cb);
				};
			},
			isPeerConnected: () => true,
			connectPeer: async () => undefined
		};
	}

	const peerHex = '02' + 'ab'.repeat(32);

	it('reaches the lane through the real custom-message dispatch', () => {
		const node = makeNode();
		const factory = new DfDirectPeerLaneFactory(peerMessagingFor(node));
		const seen: IDfInboundFrame[] = [];
		factory.attachInbound((f) => seen.push(f));

		node.handlePeerMessage(
			peerHex,
			44069,
			encodeCustomMessage(OFFER, openingFrame(Buffer.alloc(16, 1)))
		);

		expect(seen.length).to.equal(1);
		expect(seen[0].authenticatedPeer).to.equal(peerHex);
		node.destroy();
	});

	it('is unreachable while the recovery inbound gate is closed', () => {
		const gate = new FakeGate();
		const node = makeNode(gate);
		const factory = new DfDirectPeerLaneFactory(peerMessagingFor(node));
		const seen: IDfInboundFrame[] = [];
		factory.attachInbound((f) => seen.push(f));

		node.handlePeerMessage(
			peerHex,
			44069,
			encodeCustomMessage(OFFER, openingFrame(Buffer.alloc(16, 1)))
		);

		expect(seen.length).to.equal(0);
		expect(gate.blocked.length).to.be.greaterThan(0);
		node.destroy();
	});
});

describe('Direct-funding lane 3: blind relay', () => {
	let net: FakeDfNetwork;
	let payer: FakeDfPeer;
	let lsp: FakeDfPeer;
	let receiver: FakeDfPeer;

	beforeEach(() => {
		net = new FakeDfNetwork();
		payer = net.add('payer');
		lsp = net.add('lsp');
		receiver = net.add('receiver');
		net.connect(payer, lsp);
		net.connect(lsp, receiver);
	});

	function descriptor(): {
		type: DfTransportType.LSP_RELAY;
		relayNodeId: Buffer;
		host: string;
		port: number;
	} {
		return {
			type: DfTransportType.LSP_RELAY,
			relayNodeId: Buffer.from(lsp.id, 'hex'),
			host: 'lsp.example',
			port: 9735
		};
	}

	it('carries a sealed frame through the relay and back', async () => {
		const forwarder = new DfRelayForwarder(lsp);
		forwarder.start();

		const store = new DirectFundingRequestStore({});
		const record = store.mint();
		const requestId = Buffer.from(record.requestId, 'hex');

		const receiverFactory = new DfRelayLaneFactory(receiver);
		const inbound: IDfInboundFrame[] = [];
		receiverFactory.attachInbound((f) => inbound.push(f));

		const payerFactory = new DfRelayLaneFactory(payer);
		const lane = await payerFactory.open(descriptor(), {
			requestId,
			receiverNodeId: Buffer.from(receiver.id, 'hex')
		});
		const replies: Buffer[] = [];
		const sender = senderLaneKeys(
			getPublicKey(Buffer.from(record.encryptionPrivateKeyHex, 'hex')),
			requestId
		);
		lane!.onMessage((f) => {
			const body = openFrame(
				sender.keys.recvKey,
				requestId,
				f.subtype,
				decodeWire(f.payload)
			);
			if (body) replies.push(body);
		});

		const offer = sealFrame(
			sender.keys.sendKey,
			requestId,
			OFFER,
			Buffer.from('relayed offer')
		);
		lane!.send(
			OFFER,
			encodeSealedFrame(offer, {
				requestId,
				ephemeralPublicKey: sender.ephemeralPublicKey
			})
		);

		expect(inbound.length).to.equal(1);
		// The relay's stamp authenticates the RELAY, never the payer.
		expect(inbound[0].relayAssertedFrom).to.equal(payer.id);
		expect(inbound[0].authenticatedPeer).to.equal(undefined);
		expect(inbound[0].laneKey).to.equal(laneKeyFor(lsp.id, payer.id));

		const keys = store.laneKeysForFrame(decodeWire(inbound[0].payload));
		expect(
			openFrame(
				keys!.keys.recvKey,
				requestId,
				OFFER,
				decodeWire(inbound[0].payload)
			)?.toString()
		).to.equal('relayed offer');

		const receipt = sealFrame(
			keys!.keys.sendKey,
			requestId,
			RECEIPT,
			Buffer.from('relayed receipt')
		);
		inbound[0].reply.send(RECEIPT, encodeSealedFrame(receipt));
		expect(replies.map((r) => r.toString())).to.deep.equal(['relayed receipt']);

		lane!.close();
		expect(payerFactory.openLaneCount).to.equal(0);
		forwarder.stop();
	});

	it('refuses to open a lane whose relay IS the counterparty', async () => {
		const factory = new DfRelayLaneFactory(payer);
		const lane = await factory.open(descriptor(), {
			requestId: Buffer.alloc(16, 1),
			receiverNodeId: Buffer.from(lsp.id, 'hex')
		});
		expect(lane).to.equal(null);
	});

	it('refuses to relay for a peer when it is only a client', () => {
		const recorder = recordingLog();
		const factory = new DfRelayLaneFactory(receiver, recorder.log);
		factory.attachInbound(() => undefined);
		receiver.deliver({
			peerPubkey: lsp.id,
			subtype: RELAY,
			payload: encodeDfRelayFrame({
				to: Buffer.from(payer.id, 'hex'),
				subtype: OFFER,
				payload: openingFrame(Buffer.alloc(16, 1))
			})
		});
		expect(recorder.reasons()).to.deep.equal([DfDropReason.RELAY_NOT_A_SERVER]);
	});

	it('drops a malformed relay wrapper', () => {
		const recorder = recordingLog();
		const factory = new DfRelayLaneFactory(receiver, recorder.log);
		factory.attachInbound(() => undefined);
		receiver.deliver({
			peerPubkey: lsp.id,
			subtype: RELAY,
			payload: Buffer.from([0xff, 0xff, 0xff])
		});
		expect(recorder.reasons()).to.deep.equal([
			DfDropReason.MALFORMED_RELAY_FRAME
		]);
	});

	it('drops a wrapper in a protocol version it does not speak', () => {
		const recorder = recordingLog();
		const factory = new DfRelayLaneFactory(receiver, recorder.log);
		const seen: IDfInboundFrame[] = [];
		factory.attachInbound((f) => seen.push(f));
		receiver.deliver({
			peerPubkey: lsp.id,
			version: BEIGNET_CUSTOM_PROTOCOL_VERSION + 1,
			subtype: RELAY,
			payload: encodeDfRelayFrame({
				from: Buffer.from(payer.id, 'hex'),
				subtype: OFFER,
				payload: openingFrame(Buffer.alloc(16, 1))
			})
		});
		expect(seen).to.deep.equal([]);
		expect(recorder.reasons()).to.deep.equal([
			DfDropReason.UNSUPPORTED_VERSION
		]);
	});
});

describe('Direct-funding relay server (defect D29)', () => {
	let net: FakeDfNetwork;
	let payer: FakeDfPeer;
	let lsp: FakeDfPeer;
	let receiver: FakeDfPeer;
	let stranger: FakeDfPeer;

	beforeEach(() => {
		net = new FakeDfNetwork();
		payer = net.add('payer');
		lsp = net.add('lsp');
		receiver = net.add('receiver');
		stranger = net.add('stranger');
		net.connect(payer, lsp);
		net.connect(lsp, receiver);
	});

	function originator(
		to: FakeDfPeer,
		payload = openingFrame(Buffer.alloc(16, 1))
	): Buffer {
		return encodeDfRelayFrame({
			to: Buffer.from(to.id, 'hex'),
			subtype: OFFER,
			payload
		});
	}

	it('stamps `from` from the connection the frame arrived on', () => {
		const forwarder = new DfRelayForwarder(lsp);
		forwarder.start();
		lsp.deliver({
			peerPubkey: payer.id,
			subtype: RELAY,
			payload: originator(receiver)
		});
		expect(lsp.sent.length).to.equal(1);
		expect(lsp.sent[0].to).to.equal(receiver.id);
		expect(receiver.listeners.size).to.equal(0);
		forwarder.stop();
	});

	it('never re-forwards a frame that already carries `from`', () => {
		const recorder = recordingLog();
		const forwarder = new DfRelayForwarder(lsp, {}, recorder.log);
		forwarder.start();
		lsp.deliver({
			peerPubkey: payer.id,
			subtype: RELAY,
			payload: encodeDfRelayFrame({
				from: Buffer.from(stranger.id, 'hex'),
				subtype: OFFER,
				payload: openingFrame(Buffer.alloc(16, 1))
			})
		});
		expect(lsp.sent.length).to.equal(0);
		expect(recorder.reasons()).to.deep.equal([
			DfDropReason.RELAY_ALREADY_FORWARDED
		]);
		forwarder.stop();
	});

	it('refuses a frame addressed to the relay itself', () => {
		const recorder = recordingLog();
		const forwarder = new DfRelayForwarder(lsp, {}, recorder.log);
		forwarder.start();
		lsp.deliver({
			peerPubkey: payer.id,
			subtype: RELAY,
			payload: originator(lsp)
		});
		expect(lsp.sent.length).to.equal(0);
		expect(recorder.reasons()).to.deep.equal([
			DfDropReason.RELAY_SELF_ADDRESSED
		]);
		forwarder.stop();
	});

	it('refuses a frame addressed back at its own sender', () => {
		const recorder = recordingLog();
		const forwarder = new DfRelayForwarder(lsp, {}, recorder.log);
		forwarder.start();
		lsp.deliver({
			peerPubkey: payer.id,
			subtype: RELAY,
			payload: originator(payer)
		});
		expect(lsp.sent.length).to.equal(0);
		expect(recorder.reasons()).to.deep.equal([
			DfDropReason.RELAY_SELF_ADDRESSED
		]);
		forwarder.stop();
	});

	it('drops a frame for a peer it is not connected to', () => {
		const recorder = recordingLog();
		const forwarder = new DfRelayForwarder(lsp, {}, recorder.log);
		forwarder.start();
		lsp.deliver({
			peerPubkey: payer.id,
			subtype: RELAY,
			payload: originator(stranger)
		});
		expect(lsp.sent.length).to.equal(0);
		expect(recorder.reasons()).to.deep.equal([
			DfDropReason.RELAY_TARGET_NOT_CONNECTED
		]);
		forwarder.stop();
	});

	it('cuts an over-budget peer off, and only that peer', () => {
		const recorder = recordingLog();
		const forwarder = new DfRelayForwarder(
			lsp,
			{ maxFramesPerSecond: 1, burstMultiplier: 2 },
			recorder.log
		);
		forwarder.start();
		net.connect(stranger, lsp);
		for (let i = 0; i < 5; i++) {
			lsp.deliver({
				peerPubkey: payer.id,
				subtype: RELAY,
				payload: originator(receiver)
			});
		}
		expect(lsp.sent.length).to.equal(2);
		expect(
			recorder.reasons().filter((r) => r === DfDropReason.RELAY_OVER_BUDGET)
		).to.have.length(3);

		// A different peer still has its own budget.
		lsp.deliver({
			peerPubkey: stranger.id,
			subtype: RELAY,
			payload: originator(receiver)
		});
		expect(lsp.sent.length).to.equal(3);
		forwarder.stop();
	});

	it('spends the budget on a frame it drops, so junk is not free', () => {
		const recorder = recordingLog();
		const forwarder = new DfRelayForwarder(
			lsp,
			{ maxFramesPerSecond: 1, burstMultiplier: 2 },
			recorder.log
		);
		forwarder.start();
		for (let i = 0; i < 2; i++) {
			lsp.deliver({
				peerPubkey: payer.id,
				subtype: RELAY,
				payload: Buffer.from([0xff, 0xff])
			});
		}
		lsp.deliver({
			peerPubkey: payer.id,
			subtype: RELAY,
			payload: originator(receiver)
		});
		expect(lsp.sent.length).to.equal(0);
		expect(recorder.reasons()).to.deep.equal([
			DfDropReason.MALFORMED_RELAY_FRAME,
			DfDropReason.MALFORMED_RELAY_FRAME,
			DfDropReason.RELAY_OVER_BUDGET
		]);
		forwarder.stop();
	});

	it('refuses an oversized frame', () => {
		const recorder = recordingLog();
		const forwarder = new DfRelayForwarder(
			lsp,
			{ maxFrameBytes: 128 },
			recorder.log
		);
		forwarder.start();
		lsp.deliver({
			peerPubkey: payer.id,
			subtype: RELAY,
			payload: originator(receiver, Buffer.alloc(4096))
		});
		expect(lsp.sent.length).to.equal(0);
		expect(recorder.reasons()).to.deep.equal([DfDropReason.FRAME_TOO_LARGE]);
		forwarder.stop();
	});

	it('logs nothing at all on a successful forward, and never a target', () => {
		const recorder = recordingLog();
		const forwarder = new DfRelayForwarder(lsp, {}, recorder.log);
		forwarder.start();
		lsp.deliver({
			peerPubkey: payer.id,
			subtype: RELAY,
			payload: originator(receiver)
		});
		expect(recorder.lines).to.deep.equal([]);

		lsp.deliver({
			peerPubkey: payer.id,
			subtype: RELAY,
			payload: originator(stranger)
		});
		const written = JSON.stringify(recorder.lines);
		expect(written).to.not.include(stranger.id);
		expect(written).to.include(payer.id);
		forwarder.stop();
	});

	it('never writes the target into a failed forward', () => {
		// The connected check passes and the send still fails: a disconnect in
		// between, or the outbound recovery gate. Both errors name the target,
		// which would put one exchange's two endpoints on the same log line.
		const recorder = recordingLog();
		const racing: IDfPeerMessaging = {
			nodeIdHex: () => lsp.id,
			isPeerConnected: () => true,
			connectPeer: async () => undefined,
			onCustomMessage: (cb) => lsp.onCustomMessage(cb),
			sendCustomMessage: (to): void => {
				throw new Error(`Not connected to peer ${to}`);
			}
		};
		const forwarder = new DfRelayForwarder(racing, {}, recorder.log);
		forwarder.start();
		lsp.deliver({
			peerPubkey: payer.id,
			subtype: RELAY,
			payload: originator(receiver)
		});
		expect(recorder.reasons()).to.deep.equal([
			DfDropReason.RELAY_FORWARD_FAILED
		]);
		const written = JSON.stringify(recorder.lines);
		expect(written).to.not.include(receiver.id);
		expect(written).to.include(payer.id);
		forwarder.stop();
	});

	it('refuses to forward a wrapper in a version it cannot re-encode', () => {
		const recorder = recordingLog();
		const forwarder = new DfRelayForwarder(lsp, {}, recorder.log);
		forwarder.start();
		lsp.deliver({
			peerPubkey: payer.id,
			version: BEIGNET_CUSTOM_PROTOCOL_VERSION + 1,
			subtype: RELAY,
			payload: originator(receiver)
		});
		expect(lsp.sent.length).to.equal(0);
		expect(recorder.reasons()).to.deep.equal([
			DfDropReason.UNSUPPORTED_VERSION
		]);
		forwarder.stop();
	});

	it('ignores every subtype but the relay wrapper', () => {
		const recorder = recordingLog();
		const forwarder = new DfRelayForwarder(lsp, {}, recorder.log);
		forwarder.start();
		lsp.deliver({
			peerPubkey: payer.id,
			subtype: OFFER,
			payload: openingFrame(Buffer.alloc(16, 1))
		});
		expect(recorder.lines).to.deep.equal([]);
		expect(lsp.sent.length).to.equal(0);
		forwarder.stop();
	});
});

/** The 4A wire parse every consumer of a lane payload runs. */
function decodeWire(payload: Buffer): IDfWireFrame {
	const wire = decodeSealedFrame(payload);
	if (!wire) throw new Error('lane delivered something that is not a frame');
	return wire;
}
