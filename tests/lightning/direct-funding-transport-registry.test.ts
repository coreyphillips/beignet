/**
 * The direct-funding transport registry (issue #611, LFBW port #532 4B).
 *
 * The registry is the deliverable: #532 defers the hyperswarm rendezvous
 * transport to #533 and asks 4B for "the seam the future swarm plugin registers
 * into, with no core changes". These pin what that seam promises.
 *
 *  - selection walks the RECEIVER's stated preference order;
 *  - a descriptor type nobody claims is skipped, never an error;
 *  - only connection-establishment failures fall through, and once a frame has
 *    been exchanged the lane owns the exchange;
 *  - a lane whose loader throws (its optional dependency is not installed)
 *    takes only itself out of service.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	DfLaneSkipReason,
	DfTransportRegistry,
	IDfInboundFrame,
	IDfLaneFactory,
	IDfOpenContext,
	IDfTransport,
	withSynthesizedRelay
} from '../../src/lightning/direct-funding/transport';
import {
	DfTransportDescriptor,
	DfTransportType,
	DirectFundingError,
	DirectFundingErrorCode,
	IDfOnionTransport,
	IDfRelayTransport
} from '../../src/lightning/direct-funding/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { recordingLog } from './helpers/df-transport';

const NODE_A = getPublicKey(crypto.createHash('sha256').update('a').digest());
const NODE_B = getPublicKey(crypto.createHash('sha256').update('b').digest());

const CTX: IDfOpenContext = {
	requestId: Buffer.alloc(16, 7),
	receiverNodeId: NODE_A
};

/** A lane that records what it was asked to do and never touches a wire. */
class StubLane implements IDfTransport {
	exchanged = 0;
	closed = 0;
	constructor(readonly type: number) {}
	send(): void {
		this.exchanged++;
	}
	trySend(): boolean {
		this.exchanged++;
		return true;
	}
	onMessage(): () => void {
		return () => undefined;
	}
	framesExchanged(): number {
		return this.exchanged;
	}
	close(): void {
		this.closed++;
	}
}

class StubFactory implements IDfLaneFactory {
	opens = 0;
	attaches = 0;
	lastLane: StubLane | null = null;

	constructor(
		readonly type: number,
		private readonly behaviour: 'ok' | 'null' | 'throw' = 'ok'
	) {}

	async open(
		_descriptor: DfTransportDescriptor,
		_ctx: IDfOpenContext
	): Promise<IDfTransport | null> {
		this.opens++;
		if (this.behaviour === 'null') return null;
		if (this.behaviour === 'throw') throw new Error('dial refused');
		this.lastLane = new StubLane(this.type);
		return this.lastLane;
	}

	attachInbound(_sink: (frame: IDfInboundFrame) => void): () => void {
		this.attaches++;
		return () => {
			this.attaches--;
		};
	}
}

function directPeer(host = 'a.example'): DfTransportDescriptor {
	return { type: DfTransportType.DIRECT_PEER, host, port: 9735 };
}

function onion(): IDfOnionTransport {
	return {
		type: DfTransportType.ONION_MESSAGE,
		host: 'lsp.example',
		port: 9735,
		introNodeId: NODE_B,
		pathKey: NODE_B,
		hops: [{ blindedNodeId: NODE_A, encryptedData: Buffer.alloc(4) }]
	};
}

function relay(): IDfRelayTransport {
	return {
		type: DfTransportType.LSP_RELAY,
		relayNodeId: NODE_B,
		host: 'lsp.example',
		port: 9735
	};
}

/** The reserved rendezvous type, as 4A's decoder hands it back today. */
function rendezvous(): DfTransportDescriptor {
	return { type: DfTransportType.RENDEZVOUS, value: Buffer.alloc(8, 1) };
}

describe('Direct-funding transport registry', () => {
	describe('selection order', () => {
		it("uses the receiver's first descriptor and never opens the rest", async () => {
			const first = new StubFactory(DfTransportType.ONION_MESSAGE);
			const second = new StubFactory(DfTransportType.DIRECT_PEER);
			const registry = new DfTransportRegistry();
			registry.register({
				type: DfTransportType.DIRECT_PEER,
				enabled: true,
				load: () => second
			});
			registry.register({
				type: DfTransportType.ONION_MESSAGE,
				enabled: true,
				load: () => first
			});

			const used = await registry.run(
				[onion(), directPeer()],
				CTX,
				async (lane) => lane.type
			);

			expect(used).to.equal(DfTransportType.ONION_MESSAGE);
			expect(first.opens).to.equal(1);
			expect(second.opens).to.equal(0);
		});

		it('honours a receiver that lists the direct peer first', async () => {
			const peerLane = new StubFactory(DfTransportType.DIRECT_PEER);
			const onionLane = new StubFactory(DfTransportType.ONION_MESSAGE);
			const registry = new DfTransportRegistry();
			registry.register({
				type: DfTransportType.DIRECT_PEER,
				enabled: true,
				load: () => peerLane
			});
			registry.register({
				type: DfTransportType.ONION_MESSAGE,
				enabled: true,
				load: () => onionLane
			});

			const used = await registry.run(
				[directPeer(), onion()],
				CTX,
				async (lane) => lane.type
			);

			expect(used).to.equal(DfTransportType.DIRECT_PEER);
			expect(onionLane.opens).to.equal(0);
		});
	});

	describe('an existing connection to the receiver', () => {
		// The beignet-umbrel case: a home node paying its own lightning-first
		// wallet, which published no address (an Umbrel publishes no ports)
		// and named that same node as its relay. The connection between them
		// already exists; dialing the relay meant the node dialing itself.
		it('tries the direct lane first when the payer is already connected, whatever the receiver listed', async () => {
			const peerLane = new StubFactory(DfTransportType.DIRECT_PEER);
			const relayLane = new StubFactory(DfTransportType.LSP_RELAY);
			const registry = new DfTransportRegistry(undefined, {
				isPeerConnected: (hex) => hex === NODE_A.toString('hex')
			});
			registry.register({
				type: DfTransportType.DIRECT_PEER,
				enabled: true,
				load: () => peerLane
			});
			registry.register({
				type: DfTransportType.LSP_RELAY,
				enabled: true,
				load: () => relayLane
			});

			const used = await registry.run(
				[relay()],
				CTX,
				async (lane) => lane.type
			);
			expect(used).to.equal(DfTransportType.DIRECT_PEER);
			expect(relayLane.opens).to.equal(0);
		});

		it("falls back to the receiver's descriptors when the direct lane does not establish", async () => {
			const peerLane = new StubFactory(DfTransportType.DIRECT_PEER, 'null');
			const relayLane = new StubFactory(DfTransportType.LSP_RELAY);
			const registry = new DfTransportRegistry(undefined, {
				isPeerConnected: () => true
			});
			registry.register({
				type: DfTransportType.DIRECT_PEER,
				enabled: true,
				load: () => peerLane
			});
			registry.register({
				type: DfTransportType.LSP_RELAY,
				enabled: true,
				load: () => relayLane
			});

			const used = await registry.run(
				[relay()],
				CTX,
				async (lane) => lane.type
			);
			expect(used).to.equal(DfTransportType.LSP_RELAY);
			expect(peerLane.opens).to.equal(1);
		});

		it('leaves the order alone when not connected, or when the receiver listed a direct address itself', async () => {
			const peerLane = new StubFactory(DfTransportType.DIRECT_PEER);
			const relayLane = new StubFactory(DfTransportType.LSP_RELAY);
			const registry = new DfTransportRegistry(undefined, {
				isPeerConnected: () => false
			});
			registry.register({
				type: DfTransportType.DIRECT_PEER,
				enabled: true,
				load: () => peerLane
			});
			registry.register({
				type: DfTransportType.LSP_RELAY,
				enabled: true,
				load: () => relayLane
			});
			expect(
				await registry.run([relay()], CTX, async (lane) => lane.type)
			).to.equal(DfTransportType.LSP_RELAY);
			expect(peerLane.opens).to.equal(0);

			const connected = new DfTransportRegistry(undefined, {
				isPeerConnected: () => true
			});
			const peer2 = new StubFactory(DfTransportType.DIRECT_PEER);
			const relay2 = new StubFactory(DfTransportType.LSP_RELAY);
			connected.register({
				type: DfTransportType.DIRECT_PEER,
				enabled: true,
				load: () => peer2
			});
			connected.register({
				type: DfTransportType.LSP_RELAY,
				enabled: true,
				load: () => relay2
			});
			expect(
				await connected.run(
					[relay(), directPeer()],
					CTX,
					async (lane) => lane.type
				)
			).to.equal(DfTransportType.LSP_RELAY);
		});

		it('skips a relay descriptor that names the payer itself', async () => {
			const relayLane = new StubFactory(DfTransportType.LSP_RELAY);
			const log = recordingLog();
			const registry = new DfTransportRegistry(log.log, {
				nodeId: () => NODE_B
			});
			registry.register({
				type: DfTransportType.LSP_RELAY,
				enabled: true,
				load: () => relayLane
			});
			let refused: unknown;
			try {
				await registry.run([relay()], CTX, async (lane) => lane.type);
			} catch (err) {
				refused = err;
			}
			expect(refused).to.be.instanceOf(DirectFundingError);
			expect((refused as DirectFundingError).code).to.equal(
				DirectFundingErrorCode.UNREACHABLE
			);
			expect(relayLane.opens).to.equal(0);
			expect(log.reasons()).to.include(DfLaneSkipReason.SELF_RELAY);
		});
	});

	describe('unknown and disabled descriptors', () => {
		it('skips a descriptor type nobody claims and keeps going', async () => {
			const peerLane = new StubFactory(DfTransportType.DIRECT_PEER);
			const recorder = recordingLog();
			const registry = new DfTransportRegistry(recorder.log);
			registry.register({
				type: DfTransportType.DIRECT_PEER,
				enabled: true,
				load: () => peerLane
			});

			const used = await registry.run(
				[rendezvous(), directPeer()],
				CTX,
				async (lane) => lane.type
			);

			expect(used).to.equal(DfTransportType.DIRECT_PEER);
			expect(recorder.reasons()).to.include(DfLaneSkipReason.UNKNOWN_TYPE);
		});

		it('skips a registered but disabled lane by name', async () => {
			const peerLane = new StubFactory(DfTransportType.DIRECT_PEER);
			const onionLane = new StubFactory(DfTransportType.ONION_MESSAGE);
			const recorder = recordingLog();
			const registry = new DfTransportRegistry(recorder.log);
			registry.register({
				type: DfTransportType.ONION_MESSAGE,
				enabled: false,
				load: () => onionLane
			});
			registry.register({
				type: DfTransportType.DIRECT_PEER,
				enabled: true,
				load: () => peerLane
			});

			await registry.run([onion(), directPeer()], CTX, async (l) => l.type);

			// A disabled lane is not loaded, let alone imported.
			expect(onionLane.opens).to.equal(0);
			expect(recorder.reasons()).to.include(DfLaneSkipReason.DISABLED);
			expect(registry.isEnabled(DfTransportType.ONION_MESSAGE)).to.equal(false);
		});

		it('refuses UNREACHABLE when nothing in the envelope is usable', async () => {
			const registry = new DfTransportRegistry();
			let err: unknown;
			try {
				await registry.run([rendezvous()], CTX, async () => 'never');
			} catch (e) {
				err = e;
			}
			expect(err).to.be.instanceOf(DirectFundingError);
			expect((err as DirectFundingError).code).to.equal(
				DirectFundingErrorCode.UNREACHABLE
			);
		});
	});

	describe('fall-through', () => {
		it('falls through when the lane never establishes', async () => {
			const dead = new StubFactory(DfTransportType.ONION_MESSAGE, 'null');
			const live = new StubFactory(DfTransportType.DIRECT_PEER);
			const recorder = recordingLog();
			const registry = new DfTransportRegistry(recorder.log);
			registry.register({
				type: DfTransportType.ONION_MESSAGE,
				enabled: true,
				load: () => dead
			});
			registry.register({
				type: DfTransportType.DIRECT_PEER,
				enabled: true,
				load: () => live
			});

			const used = await registry.run(
				[onion(), directPeer()],
				CTX,
				async (lane) => lane.type
			);

			expect(used).to.equal(DfTransportType.DIRECT_PEER);
			expect(recorder.reasons()).to.include(DfLaneSkipReason.NOT_ESTABLISHED);
		});

		it('treats a throwing open as an establishment failure', async () => {
			const dead = new StubFactory(DfTransportType.ONION_MESSAGE, 'throw');
			const live = new StubFactory(DfTransportType.DIRECT_PEER);
			const registry = new DfTransportRegistry();
			registry.register({
				type: DfTransportType.ONION_MESSAGE,
				enabled: true,
				load: () => dead
			});
			registry.register({
				type: DfTransportType.DIRECT_PEER,
				enabled: true,
				load: () => live
			});

			const used = await registry.run(
				[onion(), directPeer()],
				CTX,
				async (lane) => lane.type
			);
			expect(used).to.equal(DfTransportType.DIRECT_PEER);
		});

		it('falls through when the exchange dies before any frame', async () => {
			const first = new StubFactory(DfTransportType.ONION_MESSAGE);
			const second = new StubFactory(DfTransportType.DIRECT_PEER);
			const recorder = recordingLog();
			const registry = new DfTransportRegistry(recorder.log);
			registry.register({
				type: DfTransportType.ONION_MESSAGE,
				enabled: true,
				load: () => first
			});
			registry.register({
				type: DfTransportType.DIRECT_PEER,
				enabled: true,
				load: () => second
			});

			const used = await registry.run(
				[onion(), directPeer()],
				CTX,
				async (lane) => {
					if (lane.type === DfTransportType.ONION_MESSAGE) {
						throw new Error('peer vanished between dial and first send');
					}
					return lane.type;
				}
			);

			expect(used).to.equal(DfTransportType.DIRECT_PEER);
			expect(recorder.reasons()).to.include(
				DfLaneSkipReason.NO_FRAME_EXCHANGED
			);
		});

		it('NEVER falls through once a frame has been exchanged', async () => {
			const first = new StubFactory(DfTransportType.ONION_MESSAGE);
			const second = new StubFactory(DfTransportType.DIRECT_PEER);
			const registry = new DfTransportRegistry();
			registry.register({
				type: DfTransportType.ONION_MESSAGE,
				enabled: true,
				load: () => first
			});
			registry.register({
				type: DfTransportType.DIRECT_PEER,
				enabled: true,
				load: () => second
			});

			let err: unknown;
			try {
				await registry.run([onion(), directPeer()], CTX, async (lane) => {
					// The offer went out. Whatever happens next, this lane owns the
					// exchange: retrying elsewhere would offer the same coin twice.
					lane.send(16, Buffer.alloc(1));
					throw new Error('receiver never answered');
				});
			} catch (e) {
				err = e;
			}

			expect((err as Error).message).to.equal('receiver never answered');
			expect(second.opens).to.equal(0);
		});

		it('closes the lane whether the exchange succeeds or fails', async () => {
			const factory = new StubFactory(DfTransportType.DIRECT_PEER);
			const registry = new DfTransportRegistry();
			registry.register({
				type: DfTransportType.DIRECT_PEER,
				enabled: true,
				load: () => factory
			});

			await registry.run([directPeer()], CTX, async () => 'done');
			expect(factory.lastLane?.closed).to.equal(1);

			await registry
				.run([directPeer()], CTX, async (lane) => {
					lane.send(16, Buffer.alloc(1));
					throw new Error('boom');
				})
				.catch(() => undefined);
			expect(factory.lastLane?.closed).to.equal(1);
		});
	});

	describe('optional lanes', () => {
		it('serves every other lane when a loader throws', async () => {
			const live = new StubFactory(DfTransportType.DIRECT_PEER);
			const recorder = recordingLog();
			const registry = new DfTransportRegistry(recorder.log);
			let loads = 0;
			registry.register({
				type: DfTransportType.RENDEZVOUS,
				enabled: true,
				load: () => {
					loads++;
					throw new Error("Cannot find module 'hyperswarm'");
				}
			});
			registry.register({
				type: DfTransportType.DIRECT_PEER,
				enabled: true,
				load: () => live
			});

			const used = await registry.run(
				[rendezvous(), directPeer()],
				CTX,
				async (lane) => lane.type
			);

			expect(used).to.equal(DfTransportType.DIRECT_PEER);
			expect(recorder.reasons()).to.include(
				DfLaneSkipReason.MODULE_UNAVAILABLE
			);

			// A loader that failed once is never called again.
			await registry.run(
				[rendezvous(), directPeer()],
				CTX,
				async (lane) => lane.type
			);
			expect(loads).to.equal(1);
		});

		it('loads a lane once and only when a descriptor selects it', async () => {
			const peerLane = new StubFactory(DfTransportType.DIRECT_PEER);
			const onionLane = new StubFactory(DfTransportType.ONION_MESSAGE);
			let onionLoads = 0;
			const registry = new DfTransportRegistry();
			registry.register({
				type: DfTransportType.ONION_MESSAGE,
				enabled: true,
				load: () => {
					onionLoads++;
					return onionLane;
				}
			});
			registry.register({
				type: DfTransportType.DIRECT_PEER,
				enabled: true,
				load: () => peerLane
			});

			await registry.run([directPeer()], CTX, async (l) => l.type);
			expect(onionLoads).to.equal(0);

			await registry.run([onion()], CTX, async (l) => l.type);
			await registry.run([onion()], CTX, async (l) => l.type);
			expect(onionLoads).to.equal(1);
		});

		it('loads once when two first uses overlap', async () => {
			// A slow loader (a dynamic import is one) leaves a window between the
			// first call and the factory being recorded. Two loads there would
			// install two sets of listeners, and destroy() would reach one.
			const onionLane = new StubFactory(DfTransportType.ONION_MESSAGE);
			let onionLoads = 0;
			let release = (): void => undefined;
			const held = new Promise<void>((resolve) => {
				release = resolve;
			});
			const registry = new DfTransportRegistry();
			registry.register({
				type: DfTransportType.ONION_MESSAGE,
				enabled: true,
				load: async () => {
					onionLoads++;
					await held;
					return onionLane;
				}
			});

			const both = Promise.all([
				registry.run([onion()], CTX, async (l) => l.type),
				registry.attachInbound(() => undefined)
			]);
			release();
			await both;

			expect(onionLoads).to.equal(1);
			expect(onionLane.attaches).to.equal(1);
		});
	});

	describe('inbound attachment', () => {
		it('attaches every enabled lane and detaches them together', async () => {
			const peerLane = new StubFactory(DfTransportType.DIRECT_PEER);
			const onionLane = new StubFactory(DfTransportType.ONION_MESSAGE);
			const registry = new DfTransportRegistry();
			registry.register({
				type: DfTransportType.DIRECT_PEER,
				enabled: true,
				load: () => peerLane
			});
			registry.register({
				type: DfTransportType.ONION_MESSAGE,
				enabled: false,
				load: () => onionLane
			});

			const detach = await registry.attachInbound(() => undefined);
			expect(peerLane.attaches).to.equal(1);
			expect(onionLane.attaches).to.equal(0);

			detach();
			expect(peerLane.attaches).to.equal(0);
		});
	});

	describe('synthesized relay descriptor', () => {
		it('adds one from the onion intro node, last', () => {
			const ordered = withSynthesizedRelay([onion(), directPeer()]);
			expect(ordered.map((t) => t.type)).to.deep.equal([
				DfTransportType.ONION_MESSAGE,
				DfTransportType.DIRECT_PEER,
				DfTransportType.LSP_RELAY
			]);
			const synthesized = ordered[2] as IDfRelayTransport;
			expect(synthesized.relayNodeId.equals(NODE_B)).to.equal(true);
			expect(synthesized.host).to.equal('lsp.example');
		});

		it('adds none when the receiver published its own relay', () => {
			const ordered = withSynthesizedRelay([relay(), onion()]);
			expect(
				ordered.filter((t) => t.type === DfTransportType.LSP_RELAY).length
			).to.equal(1);
		});

		it('adds none without an onion descriptor', () => {
			expect(withSynthesizedRelay([directPeer()]).length).to.equal(1);
		});

		it('is reached by run() when the receiver published only an onion', async () => {
			const relayLane = new StubFactory(DfTransportType.LSP_RELAY);
			const registry = new DfTransportRegistry();
			registry.register({
				type: DfTransportType.LSP_RELAY,
				enabled: true,
				load: () => relayLane
			});

			const used = await registry.run([onion()], CTX, async (l) => l.type);
			expect(used).to.equal(DfTransportType.LSP_RELAY);
		});
	});
});
