/**
 * Direct-funding lane 2: onion messages over blinded paths (issue #611, LFBW
 * port #532 4B).
 *
 * Three real `OnionMessageManager`s wired to each other by node id: a payer, an
 * introduction node (the receiver's LSP) and a receiver. Every frame is really
 * sphinx-wrapped, forwarded and peeled, so the path_id these tests turn on is
 * the one BOLT 4 surfaces from decrypted recipient data and nothing else.
 *
 * What is pinned:
 *  - a frame with no path_id never reaches a handler;
 *  - a path_id must resolve to an outstanding request AND the sealed frame must
 *    name that same request, neither alone;
 *  - a receiver-role frame with no reply path is unanswerable and dropped;
 *  - a sign_request-sized frame selects the BOLT 4 large form and round trips;
 *  - the lane is anonymous: it never sets `authenticatedPeer`;
 *  - a lane leaves no registry entry behind, subscribed or not (defect D21).
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { OnionMessageManager } from '../../src/lightning/onion-message/manager';
import { LARGE_ONION_PACKET_LENGTH } from '../../src/lightning/onion/types';
import { IBlindedPath } from '../../src/lightning/onion/blinded-path';
import { BeignetCustomSubtype } from '../../src/lightning/message/custom';
import {
	DF_ONION_TLV,
	DfDropReason,
	DfOnionLaneFactory,
	IDfInboundFrame,
	IDfTransport,
	encodeDfOnionBody,
	mintDfBlindedPath
} from '../../src/lightning/direct-funding/transport';
import {
	decodeSealedFrame,
	encodeSealedFrame,
	openFrame,
	sealFrame,
	senderLaneKeys
} from '../../src/lightning/direct-funding/frames';
import { DirectFundingRequestStore } from '../../src/lightning/direct-funding/requests';
import {
	DfTransportType,
	IDfOnionTransport,
	IDfRequestRecord
} from '../../src/lightning/direct-funding/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	FakeDfNetwork,
	FakeDfPeer,
	recordingLog
} from './helpers/df-transport';

const OFFER = BeignetCustomSubtype.DIRECT_FUNDING_OFFER;
const RECEIPT = BeignetCustomSubtype.DIRECT_FUNDING_RECEIPT;

interface IOnionHarness {
	net: FakeDfNetwork;
	payer: FakeDfPeer;
	intro: FakeDfPeer;
	receiver: FakeDfPeer;
	managers: Map<string, OnionMessageManager>;
	wireSizes: number[];
	destroy(): void;
}

function harness(): IOnionHarness {
	const net = new FakeDfNetwork();
	const payer = net.add('onion-payer');
	const intro = net.add('onion-intro');
	const receiver = net.add('onion-receiver');
	net.connect(payer, intro);
	net.connect(intro, receiver);

	const managers = new Map<string, OnionMessageManager>();
	const wireSizes: number[] = [];
	for (const peer of [payer, intro, receiver]) {
		managers.set(peer.id, new OnionMessageManager(peer.privkey));
	}
	for (const peer of [payer, intro, receiver]) {
		managers.get(peer.id)!.setSendFunction((to, _type, payload) => {
			wireSizes.push(payload.length);
			managers.get(to)?.handleMessage(peer.id, payload);
		});
	}
	return {
		net,
		payer,
		intro,
		receiver,
		managers,
		wireSizes,
		destroy: (): void => {
			for (const m of managers.values()) m.destroy();
		}
	};
}

/** The blinded path a receiver would sign into its envelope. */
function receiverPath(
	h: IOnionHarness,
	record: IDfRequestRecord
): IBlindedPath {
	return mintDfBlindedPath(
		h.intro.pubkey,
		h.receiver.pubkey,
		Buffer.from(record.onionPathSecretHex, 'hex')
	);
}

function descriptorFor(path: IBlindedPath): IDfOnionTransport {
	return {
		type: DfTransportType.ONION_MESSAGE,
		host: 'lsp.example',
		port: 9735,
		introNodeId: path.introductionNodeId,
		pathKey: path.blindingPoint,
		hops: path.blindedHops
	};
}

function receiverFactory(
	h: IOnionHarness,
	store: DirectFundingRequestStore,
	log?: (a: string, d: Record<string, unknown>) => void
): DfOnionLaneFactory {
	return new DfOnionLaneFactory(
		{
			manager: h.managers.get(h.receiver.id)!,
			peers: h.receiver,
			nodeId: () => h.receiver.pubkey,
			resolvePathSecret: (hex) =>
				store.byOnionPathSecret(hex)?.requestId ?? null
		},
		log
	);
}

function payerFactory(
	h: IOnionHarness,
	log?: (a: string, d: Record<string, unknown>) => void
): DfOnionLaneFactory {
	return new DfOnionLaneFactory(
		{
			manager: h.managers.get(h.payer.id)!,
			peers: h.payer,
			nodeId: () => h.payer.pubkey,
			resolvePathSecret: () => null
		},
		log
	);
}

describe('Direct-funding lane 2: onion messages', () => {
	let h: IOnionHarness;

	beforeEach(() => {
		h = harness();
	});

	afterEach(() => {
		h.destroy();
	});

	it('carries a sealed frame to the receiver and answers on the reply path', async () => {
		const store = new DirectFundingRequestStore({});
		const record = store.mint();
		const requestId = Buffer.from(record.requestId, 'hex');
		const path = receiverPath(h, record);

		const inbound: IDfInboundFrame[] = [];
		const rx = receiverFactory(h, store);
		rx.attachInbound((f) => inbound.push(f));

		const tx = payerFactory(h);
		const lane = await tx.open(descriptorFor(path), {
			requestId,
			receiverNodeId: h.receiver.pubkey
		});
		expect(lane).to.not.equal(null);

		const sender = senderLaneKeys(
			getPublicKey(Buffer.from(record.encryptionPrivateKeyHex, 'hex')),
			requestId
		);
		const replies: string[] = [];
		lane!.onMessage((f) => {
			const body = openFrame(
				sender.keys.recvKey,
				requestId,
				f.subtype,
				decodeSealedFrame(f.payload)!
			);
			if (body) replies.push(body.toString());
		});

		lane!.send(
			OFFER,
			encodeSealedFrame(
				sealFrame(
					sender.keys.sendKey,
					requestId,
					OFFER,
					Buffer.from('onion offer')
				),
				{ requestId, ephemeralPublicKey: sender.ephemeralPublicKey }
			)
		);

		expect(inbound.length).to.equal(1);
		// Anonymous by construction: the receiver learns no node id at all.
		expect(inbound[0].authenticatedPeer).to.equal(undefined);
		expect(inbound[0].boundRequestId?.equals(requestId)).to.equal(true);

		const keys = store.laneKeysForFrame(decodeSealedFrame(inbound[0].payload)!);
		expect(
			openFrame(
				keys!.keys.recvKey,
				requestId,
				OFFER,
				decodeSealedFrame(inbound[0].payload)!
			)?.toString()
		).to.equal('onion offer');

		inbound[0].reply.send(
			RECEIPT,
			encodeSealedFrame(
				sealFrame(
					keys!.keys.sendKey,
					requestId,
					RECEIPT,
					Buffer.from('onion receipt')
				)
			)
		);
		expect(replies).to.deep.equal(['onion receipt']);

		lane!.close();
		expect(tx.openLaneCount).to.equal(0);
	});

	it('selects the BOLT 4 large form for a sign_request-sized frame', async () => {
		const store = new DirectFundingRequestStore({});
		const record = store.mint();
		const requestId = Buffer.from(record.requestId, 'hex');
		const path = receiverPath(h, record);

		const inbound: IDfInboundFrame[] = [];
		receiverFactory(h, store).attachInbound((f) => inbound.push(f));
		const lane = (await payerFactory(h).open(descriptorFor(path), {
			requestId,
			receiverNodeId: h.receiver.pubkey
		})) as IDfTransport;

		const sender = senderLaneKeys(
			getPublicKey(Buffer.from(record.encryptionPrivateKeyHex, 'hex')),
			requestId
		);
		// A signed 16-input transaction with its prevouts: the frame 2A exists for.
		const body = crypto.randomBytes(6000);
		h.wireSizes.length = 0;
		lane.send(
			BeignetCustomSubtype.DIRECT_FUNDING_SIGN_REQUEST,
			encodeSealedFrame(
				sealFrame(
					sender.keys.sendKey,
					requestId,
					BeignetCustomSubtype.DIRECT_FUNDING_SIGN_REQUEST,
					body
				),
				{ requestId, ephemeralPublicKey: sender.ephemeralPublicKey }
			)
		);

		// Both legs (payer emit, intro forward) at exactly the large wire size.
		expect(h.wireSizes).to.deep.equal([
			33 + 2 + LARGE_ONION_PACKET_LENGTH,
			33 + 2 + LARGE_ONION_PACKET_LENGTH
		]);
		expect(inbound.length).to.equal(1);
		const keys = store.laneKeysForFrame(decodeSealedFrame(inbound[0].payload)!);
		const opened = openFrame(
			keys!.keys.recvKey,
			requestId,
			BeignetCustomSubtype.DIRECT_FUNDING_SIGN_REQUEST,
			decodeSealedFrame(inbound[0].payload)!
		);
		expect(opened?.equals(body)).to.equal(true);
		lane.close();
	});

	it('keeps a small frame on the standard form', async () => {
		const store = new DirectFundingRequestStore({});
		const record = store.mint();
		const path = receiverPath(h, record);
		receiverFactory(h, store).attachInbound(() => undefined);
		const lane = (await payerFactory(h).open(descriptorFor(path), {
			requestId: Buffer.from(record.requestId, 'hex'),
			receiverNodeId: h.receiver.pubkey
		})) as IDfTransport;

		h.wireSizes.length = 0;
		lane.send(
			OFFER,
			encodeSealedFrame({
				nonce: Buffer.alloc(12, 1),
				ciphertext: Buffer.alloc(64, 2)
			})
		);
		expect(h.wireSizes.every((s) => s < LARGE_ONION_PACKET_LENGTH)).to.equal(
			true
		);
		lane.close();
	});

	describe('drops', () => {
		let store: DirectFundingRequestStore;
		let record: IDfRequestRecord;
		let recorder: ReturnType<typeof recordingLog>;
		let seen: IDfInboundFrame[];

		beforeEach(() => {
			store = new DirectFundingRequestStore({});
			record = store.mint();
			recorder = recordingLog();
			seen = [];
			receiverFactory(h, store, recorder.log).attachInbound((f) =>
				seen.push(f)
			);
		});

		/** Speak straight to the receiver with a path_id of our choosing. */
		function hostileSend(
			body: Buffer,
			opts: { pathId?: Buffer; replyPath?: IBlindedPath } = {}
		): void {
			h.managers
				.get(h.payer.id)!
				.sendOnionMessage(h.receiver.pubkey, new Map([[DF_ONION_TLV, body]]), {
					...(opts.pathId ? { pathId: opts.pathId } : {}),
					...(opts.replyPath ? { replyPath: opts.replyPath } : {})
				});
		}

		function frameFor(requestId: Buffer): Buffer {
			return encodeSealedFrame(
				{ nonce: Buffer.alloc(12, 1), ciphertext: Buffer.alloc(32, 2) },
				{ requestId, ephemeralPublicKey: h.payer.pubkey }
			);
		}

		function anyReplyPath(): IBlindedPath {
			return mintDfBlindedPath(
				h.intro.pubkey,
				h.payer.pubkey,
				crypto.randomBytes(32)
			);
		}

		it('drops a frame with no path_id at all', () => {
			hostileSend(
				encodeDfOnionBody(
					OFFER,
					frameFor(Buffer.from(record.requestId, 'hex'))
				),
				{ replyPath: anyReplyPath() }
			);
			expect(recorder.reasons()).to.deep.equal([DfDropReason.NO_PATH_ID]);
		});

		it('drops a path_id that resolves to no outstanding request', () => {
			hostileSend(
				encodeDfOnionBody(
					OFFER,
					frameFor(Buffer.from(record.requestId, 'hex'))
				),
				{ pathId: crypto.randomBytes(32), replyPath: anyReplyPath() }
			);
			expect(recorder.reasons()).to.deep.equal([DfDropReason.UNKNOWN_PATH_ID]);
		});

		it('drops when the path_id and the sealed request id disagree', () => {
			// The route was ours. The content was sealed to something else, which
			// is a holder of one request speaking on another request's path.
			hostileSend(encodeDfOnionBody(OFFER, frameFor(Buffer.alloc(16, 0xaa))), {
				pathId: Buffer.from(record.onionPathSecretHex, 'hex'),
				replyPath: anyReplyPath()
			});
			expect(recorder.reasons()).to.deep.equal([
				DfDropReason.REQUEST_ID_MISMATCH
			]);
		});

		it('drops a receiver-role frame with no reply path', () => {
			hostileSend(
				encodeDfOnionBody(
					OFFER,
					frameFor(Buffer.from(record.requestId, 'hex'))
				),
				{ pathId: Buffer.from(record.onionPathSecretHex, 'hex') }
			);
			expect(recorder.reasons()).to.deep.equal([DfDropReason.NO_REPLY_PATH]);
		});

		it('drops a subtype this lane does not carry', () => {
			hostileSend(
				encodeDfOnionBody(
					BeignetCustomSubtype.DIRECT_FUNDING_ABORT,
					frameFor(Buffer.from(record.requestId, 'hex'))
				),
				{
					pathId: Buffer.from(record.onionPathSecretHex, 'hex'),
					replyPath: anyReplyPath()
				}
			);
			expect(recorder.reasons()).to.deep.equal([
				DfDropReason.UNHANDLED_SUBTYPE
			]);
		});

		it('drops a body that is not a frame envelope', () => {
			hostileSend(Buffer.alloc(1), {
				pathId: Buffer.from(record.onionPathSecretHex, 'hex'),
				replyPath: anyReplyPath()
			});
			expect(recorder.reasons()).to.deep.equal([DfDropReason.MALFORMED_BODY]);
		});

		it('drops a body whose payload is not a sealed frame', () => {
			hostileSend(encodeDfOnionBody(OFFER, Buffer.from([0xff, 0x00])), {
				pathId: Buffer.from(record.onionPathSecretHex, 'hex'),
				replyPath: anyReplyPath()
			});
			expect(recorder.reasons()).to.deep.equal([
				DfDropReason.NOT_A_SEALED_FRAME
			]);
		});

		it('accepts a continuation frame, which declares no request id', () => {
			// The path_id alone proves the route was ours; the seal proves the
			// rest, and 4C refuses a frame it cannot open under boundRequestId.
			hostileSend(
				encodeDfOnionBody(
					OFFER,
					encodeSealedFrame({
						nonce: Buffer.alloc(12, 1),
						ciphertext: Buffer.alloc(32, 2)
					})
				),
				{
					pathId: Buffer.from(record.onionPathSecretHex, 'hex'),
					replyPath: anyReplyPath()
				}
			);
			expect(seen.length).to.equal(1);
			expect(seen[0].boundRequestId?.toString('hex')).to.equal(
				record.requestId
			);
		});
	});

	it('leaves no registry entry behind when a lane is opened and declined', async () => {
		// The fork inserted a lane entry unconditionally and removed it only when
		// the last subscriber left, so every decline path leaked one, keyed by
		// peer, growable by any peer that sent a declinable offer (defect D21).
		const store = new DirectFundingRequestStore({});
		const tx = payerFactory(h);
		for (let i = 0; i < 25; i++) {
			const record = store.mint();
			const lane = await tx.open(descriptorFor(receiverPath(h, record)), {
				requestId: Buffer.from(record.requestId, 'hex'),
				receiverNodeId: h.receiver.pubkey
			});
			// Declined without ever subscribing.
			lane!.close();
		}
		expect(tx.openLaneCount).to.equal(0);
	});

	it('falls through when the introduction node cannot be dialled', async () => {
		const store = new DirectFundingRequestStore({});
		const record = store.mint();
		h.payer.connections.delete(h.intro.id);
		h.net.undialable.add(h.intro.id);
		const lane = await payerFactory(h).open(
			descriptorFor(receiverPath(h, record)),
			{
				requestId: Buffer.from(record.requestId, 'hex'),
				receiverNodeId: h.receiver.pubkey
			}
		);
		expect(lane).to.equal(null);
	});

	it('falls through on a descriptor carrying no blinded hops', async () => {
		const lane = await payerFactory(h).open(
			{
				type: DfTransportType.ONION_MESSAGE,
				host: 'lsp.example',
				port: 9735,
				introNodeId: h.intro.pubkey,
				pathKey: h.intro.pubkey,
				hops: []
			},
			{ requestId: Buffer.alloc(16, 1), receiverNodeId: h.receiver.pubkey }
		);
		expect(lane).to.equal(null);
	});
});
