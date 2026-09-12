/**
 * Direct funding through the node's onion send hook (issue #790).
 *
 * `LightningNode.registerOnionMessageHandler` used to swallow every
 * `PeerManager.sendToPeer` throw. The direct-funding onion lane then counted a
 * frame that never left the process, the transport registry refused the relay
 * fall-through it otherwise supports, and the payer sat out the offer timeout
 * reporting EXCHANGE_TIMEOUT for a refusal that happened locally.
 *
 * These tests wire the PRODUCTION hook (the method itself, not a copy of its
 * try/catch) to a real OnionMessageManager, the real onion lane factory and
 * the real registry, and fault-inject only the peer write.
 *
 * What is pinned:
 *  - a definite pre-write refusal with a connected peer view throws out of the
 *    lane with the local reason, and counts nothing;
 *  - the registry then tries the next lane and names the reason in UNREACHABLE;
 *  - the whole sender reports UNREACHABLE, not EXCHANGE_TIMEOUT, and records it;
 *  - a peer manager that is gone at send time is a refusal too;
 *  - an accepted write is counted, addressed to the intro node as type 513;
 *  - once a write was accepted the registry never switches lanes.
 */

import { expect } from 'chai';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { OnionMessageManager } from '../../src/lightning/onion-message/manager';
import {
	DfOnionLaneFactory,
	DfTransportRegistry,
	IDfLaneFactory,
	IDfTransport,
	mintDfBlindedPath
} from '../../src/lightning/direct-funding/transport';
import {
	DfTransportType,
	DirectFundingError,
	DirectFundingErrorCode,
	chainHashForNetwork
} from '../../src/lightning/direct-funding/types';
import { DirectFundingSender } from '../../src/lightning/direct-funding/sender/engine';
import { DirectFundingPaymentStore } from '../../src/lightning/direct-funding/sender/records';
import { Network } from '../../src/lightning/invoice/types';
import { BeignetCustomSubtype } from '../../src/lightning/message/custom';
import { FakeDfNetwork, FakeDfPeer } from './helpers/df-transport';
import {
	FakeSenderWallet,
	makeCoin,
	memoryStorage,
	mintRequest
} from './helpers/df-sender';

const ONION_MESSAGE_TYPE = 513;
const OFFER = BeignetCustomSubtype.DIRECT_FUNDING_OFFER;

interface IPeerWrite {
	toPeer: string;
	type: number;
	payload: Buffer;
}

/** The slice of PeerManager the hook touches, with the write fault-injectable. */
class FakePeerManager {
	writes: IPeerWrite[] = [];
	registeredTypes: number[] = [];
	refuseWith: Error | null = null;

	onMessage(type: number): void {
		this.registeredTypes.push(type);
	}

	sendToPeer(toPeer: string, type: number, payload: Buffer): void {
		if (this.refuseWith) throw this.refuseWith;
		this.writes.push({ toPeer, type, payload });
	}
}

/** The node's private method, invoked on exactly the fields it reads. */
function wireProductionHook(host: {
	peerManager: FakePeerManager | null;
	onionMessageManager: OnionMessageManager;
}): void {
	(
		LightningNode.prototype as unknown as {
			registerOnionMessageHandler(this: unknown): void;
		}
	).registerOnionMessageHandler.call(host);
}

interface IHookHarness {
	payer: FakeDfPeer;
	intro: FakeDfPeer;
	receiver: FakeDfPeer;
	manager: OnionMessageManager;
	peerManager: FakePeerManager;
	host: {
		peerManager: FakePeerManager | null;
		onionMessageManager: OnionMessageManager;
	};
	factory: DfOnionLaneFactory;
	descriptor: () => {
		type: DfTransportType.ONION_MESSAGE;
		host: string;
		port: number;
		introNodeId: Buffer;
		pathKey: Buffer;
		hops: { blindedNodeId: Buffer; encryptedData: Buffer }[];
	};
	destroy(): void;
}

function harness(): IHookHarness {
	const net = new FakeDfNetwork();
	const payer = net.add('hook-payer');
	const intro = net.add('hook-intro');
	const receiver = net.add('hook-receiver');
	// The payer's peer view says the introduction node is connected. Whether
	// a write is accepted is the peer manager's call, not the view's.
	net.connect(payer, intro);

	const manager = new OnionMessageManager(payer.privkey);
	const peerManager = new FakePeerManager();
	const host = { peerManager, onionMessageManager: manager };
	wireProductionHook(host);

	const factory = new DfOnionLaneFactory({
		manager,
		peers: payer,
		nodeId: () => payer.pubkey,
		resolvePathSecret: () => null
	});
	const blinded = mintDfBlindedPath(
		intro.pubkey,
		receiver.pubkey,
		Buffer.alloc(32, 9)
	);
	return {
		payer,
		intro,
		receiver,
		manager,
		peerManager,
		host,
		factory,
		descriptor: () => ({
			type: DfTransportType.ONION_MESSAGE,
			host: 'lsp.example',
			port: 9735,
			introNodeId: blinded.introductionNodeId,
			pathKey: blinded.blindingPoint,
			hops: blinded.blindedHops
		}),
		destroy: (): void => {
			factory.destroy();
			manager.destroy();
		}
	};
}

async function openLane(h: IHookHarness): Promise<IDfTransport> {
	const lane = await h.factory.open(h.descriptor(), {
		requestId: Buffer.alloc(16, 1),
		receiverNodeId: h.receiver.pubkey
	});
	expect(lane).to.not.equal(null);
	return lane as IDfTransport;
}

/** A relay lane that only counts how often the registry reached for it. */
class CountingRelayFactory implements IDfLaneFactory {
	readonly type = DfTransportType.LSP_RELAY;
	opens = 0;
	async open(): Promise<IDfTransport | null> {
		this.opens++;
		return null;
	}
	attachInbound(): () => void {
		return () => undefined;
	}
}

function registryOver(
	h: IHookHarness,
	relay: CountingRelayFactory
): DfTransportRegistry {
	const registry = new DfTransportRegistry();
	registry.register({
		type: DfTransportType.ONION_MESSAGE,
		enabled: true,
		load: () => h.factory
	});
	registry.register({
		type: DfTransportType.LSP_RELAY,
		enabled: true,
		load: () => relay
	});
	return registry;
}

async function refusal(p: Promise<unknown>): Promise<DirectFundingError> {
	try {
		await p;
	} catch (err) {
		expect(err).to.be.instanceOf(DirectFundingError);
		return err as DirectFundingError;
	}
	throw new Error('expected a refusal');
}

describe('Direct funding through the node onion send hook (issue #790)', () => {
	let h: IHookHarness;

	beforeEach(() => {
		h = harness();
	});

	afterEach(() => {
		h.destroy();
	});

	it('registers the onion message type with the peer manager', () => {
		expect(h.peerManager.registeredTypes).to.deep.equal([ONION_MESSAGE_TYPE]);
	});

	it('counts an accepted write, addressed to the introduction node as type 513', async () => {
		const lane = await openLane(h);
		lane.send(OFFER, Buffer.alloc(40, 2));
		expect(h.peerManager.writes).to.have.length(1);
		expect(h.peerManager.writes[0].toPeer).to.equal(
			h.intro.pubkey.toString('hex')
		);
		expect(h.peerManager.writes[0].type).to.equal(ONION_MESSAGE_TYPE);
		expect(lane.framesExchanged()).to.equal(1);
		lane.close();
	});

	it('refuses a write the peer link rejects while the peer view says connected, and counts nothing', async () => {
		const lane = await openLane(h);
		h.peerManager.refuseWith = new Error('Peer is not ready for messaging');
		expect(h.payer.isPeerConnected(h.intro.pubkey.toString('hex'))).to.equal(
			true
		);

		let err: unknown;
		try {
			lane.send(OFFER, Buffer.alloc(40, 2));
		} catch (e) {
			err = e;
		}
		expect(err).to.be.instanceOf(DirectFundingError);
		expect((err as DirectFundingError).code).to.equal(
			DirectFundingErrorCode.UNREACHABLE
		);
		// The local reason survives: a payer reading its record should not be
		// told the receiver went quiet when its own link refused the frame.
		expect((err as DirectFundingError).message).to.match(
			/refused the frame: Peer is not ready for messaging/
		);
		expect(lane.trySend(OFFER, Buffer.alloc(40, 2))).to.equal(false);
		expect(lane.framesExchanged()).to.equal(0);
		expect(h.peerManager.writes).to.have.length(0);
		lane.close();
	});

	it('refuses when the peer manager is gone at send time', async () => {
		const lane = await openLane(h);
		h.host.peerManager = null;
		expect(() => lane.send(OFFER, Buffer.alloc(40, 2))).to.throw(
			/Networking is not enabled/
		);
		expect(lane.framesExchanged()).to.equal(0);
		lane.close();
	});

	it('lets the registry fall through to the relay after a refused write, naming the reason', async () => {
		h.peerManager.refuseWith = new Error(
			'Outbound gate refused message type 513'
		);
		const relay = new CountingRelayFactory();
		const registry = registryOver(h, relay);

		const err = await refusal(
			registry.run(
				[h.descriptor()],
				{ requestId: Buffer.alloc(16, 1), receiverNodeId: h.receiver.pubkey },
				async (lane) => {
					lane.send(OFFER, Buffer.alloc(40, 2));
					return lane.type;
				}
			)
		);
		expect(err.code).to.equal(DirectFundingErrorCode.UNREACHABLE);
		expect(err.message).to.match(/failed to carry a frame/);
		expect(err.message).to.match(
			/ONION_MESSAGE: the introduction node link refused the frame: Outbound gate refused message type 513/
		);
		// The synthesized relay through the introduction node was tried.
		expect(relay.opens).to.equal(1);
	});

	it('never switches lanes once a write was accepted', async () => {
		const relay = new CountingRelayFactory();
		const registry = registryOver(h, relay);

		let err: unknown;
		try {
			await registry.run(
				[h.descriptor()],
				{ requestId: Buffer.alloc(16, 1), receiverNodeId: h.receiver.pubkey },
				async (lane) => {
					lane.send(OFFER, Buffer.alloc(40, 2));
					throw new Error('receiver never answered');
				}
			);
		} catch (e) {
			err = e;
		}
		expect((err as Error).message).to.equal('receiver never answered');
		expect(h.peerManager.writes).to.have.length(1);
		expect(relay.opens).to.equal(0);
	});

	it('makes the sender report UNREACHABLE with the local reason, not EXCHANGE_TIMEOUT', async () => {
		h.peerManager.refuseWith = new Error(
			'injected transport refusal before write'
		);
		const relay = new CountingRelayFactory();
		const registry = registryOver(h, relay);
		const request = mintRequest({
			nodePrivkey: h.receiver.privkey,
			amountSat: 50_000n,
			transports: [h.descriptor()]
		});
		const wallet = new FakeSenderWallet([makeCoin(100_000)]);
		const payments = new DirectFundingPaymentStore({
			storage: memoryStorage()
		});
		const sender = new DirectFundingSender(
			{
				wallet,
				payments,
				registry,
				chainHash: (): Buffer => chainHashForNetwork(Network.REGTEST)
			},
			{ offerResendDelaysMs: [], offerTimeoutMs: 100, receiptTimeoutMs: 100 }
		);
		try {
			const err = await refusal(
				sender.send(request.encoded, { maxTotalFeeSat: 1_000n })
			);
			expect(err.code).to.equal(DirectFundingErrorCode.UNREACHABLE);
			expect(err.message).to.match(/injected transport refusal before write/);
			expect(relay.opens).to.equal(1);
			expect(h.peerManager.writes).to.have.length(0);

			const record = payments.get(request.requestId.toString('hex'));
			expect(record?.status).to.equal('ABORTED');
			expect(record?.reasonCode).to.equal(DirectFundingErrorCode.UNREACHABLE);
			expect(record?.reason).to.match(
				/injected transport refusal before write/
			);
		} finally {
			sender.stop();
		}
	});
});
