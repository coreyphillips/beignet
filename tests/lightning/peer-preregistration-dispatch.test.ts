/**
 * Held post-handshake delivery (the coalescing window, closed at the source).
 *
 * The post-handshake drain can surface coalesced traffic (an init and an
 * open_channel2 in one TCP segment) before the consumer finishes bring-up.
 * For an inbound accept the drain can run before ANY listener is attached,
 * so a manager-level queue would lose those frames outright; and delivering
 * them before the peer:connect handlers ran would let a remote
 * channel_reestablish move a channel out of AWAITING_REESTABLISH before our
 * own reconnect hook sends the reestablish WE owe. The Peer therefore holds
 * post-init messages AT THE SOURCE (one ordered stream) and the manager
 * releases them only after registration, bookkeeping and peer:connect all
 * completed.
 *
 * The kernel-level coalescing cannot be forced deterministically over a
 * real socket, so the hold/release semantics are pinned white-box on the
 * Peer, and the release-after-bring-up wiring is pinned over a REAL
 * localhost connection via an instrumented release.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { Peer } from '../../src/lightning/transport/peer';
import { MessageType } from '../../src/lightning/message/types';
import {
	IChannelBasepoints,
	perCommitmentPointFromSecret
} from '../../src/lightning/keys/derivation';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

function makeSeed(id: number): Buffer {
	return crypto.createHash('sha256').update(`prereg-seed-${id}`).digest();
}

function makeBasepoints(seedId: number): IChannelBasepoints {
	const seed = makeSeed(seedId);
	const keys: Buffer[] = [];
	for (let i = 0; i < 6; i++) {
		keys.push(
			crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from([i]))
				.digest()
		);
	}
	return {
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: perCommitmentPointFromSecret(
			generateFromSeed(makeSeed(seedId + 100), MAX_INDEX)
		)
	};
}

function makeNodeConfig(seedId: number): INodeConfig {
	const seed = makeSeed(seedId);
	return {
		nodePrivateKey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from('node-identity'))
			.digest(),
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seedId),
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey: makeSeed(seedId + 200),
		htlcBasepointSecret: makeSeed(seedId + 300),
		enableNetworking: true
	};
}

/** A Peer whose transport never runs: white-box hold/release. */
function bareHeldPeer(): Peer {
	const peer = new Peer({
		localPrivateKey: makeSeed(1),
		remotePublicKey: getPublicKey(makeSeed(2)),
		host: '127.0.0.1',
		port: 1,
		holdMessagesUntilRelease: true
	});
	(peer as unknown as { state: string }).state = 'ready';
	return peer;
}

const feed = (peer: Peer, type: number, payload: Buffer): void =>
	(
		peer as unknown as {
			handleMessage(type: number, payload: Buffer): void;
		}
	).handleMessage(type, payload);

describe('Peer held post-handshake delivery', function () {
	this.timeout(10_000);

	it('holds post-init messages until released, then delivers in order', function () {
		const peer = bareHeldPeer();
		const seen: number[] = [];
		peer.on('message', (type: number) => seen.push(type));

		feed(peer, MessageType.OPEN_CHANNEL2, Buffer.from([1]));
		feed(peer, MessageType.TX_ADD_INPUT, Buffer.from([2]));
		expect(seen, 'nothing delivered while held').to.deep.equal([]);

		peer.releaseHeldMessages();
		expect(seen, 'delivered in arrival order').to.deep.equal([
			MessageType.OPEN_CHANNEL2,
			MessageType.TX_ADD_INPUT
		]);

		// Live from here on: no second hold.
		feed(peer, MessageType.TX_COMPLETE, Buffer.from([3]));
		expect(seen).to.have.length(3);
	});

	it('a throwing listener surfaces as a peer error and CLOSES the connection', function () {
		const peer = bareHeldPeer();
		const seen: number[] = [];
		const errors: Error[] = [];
		peer.on('error', (err: Error) => {
			errors.push(err);
			// HOSTILE error observer: it re-pokes the peer with a fresh
			// frame AND throws. The teardown already happened (terminal
			// first), so neither may have any effect.
			feed(peer, MessageType.TX_COMPLETE, Buffer.from([9]));
			throw new Error('error observer exploded too');
		});
		peer.on('message', (type: number) => {
			seen.push(type);
			throw new Error('handler exploded');
		});

		feed(peer, MessageType.OPEN_CHANNEL2, Buffer.from([1]));
		feed(peer, MessageType.TX_ADD_INPUT, Buffer.from([2]));
		peer.releaseHeldMessages();

		// The first delivery threw: torn down BEFORE the error observer ran,
		// so the reentrant feed dispatched nothing, the throwing observer
		// bypassed nothing, and later frames cannot run after the gap.
		expect(seen).to.deep.equal([MessageType.OPEN_CHANNEL2]);
		expect(errors).to.have.length(1);
		expect(errors[0].message).to.contain('handler exploded');
		expect(
			(peer as unknown as { state: string }).state,
			'the peer is no longer ready'
		).to.not.equal('ready');
	});

	it('a recursive release cannot interleave the drain', function () {
		const peer = bareHeldPeer();
		const seen: number[] = [];
		peer.on('message', (type: number) => {
			seen.push(type);
			// A hostile observer calls release again mid-drain: the
			// reentrancy guard must make it a no-op instead of starting a
			// second cursor over the same queue.
			peer.releaseHeldMessages();
		});
		feed(peer, MessageType.OPEN_CHANNEL2, Buffer.from([1]));
		feed(peer, MessageType.TX_ADD_INPUT, Buffer.from([2]));
		feed(peer, MessageType.TX_COMPLETE, Buffer.from([3]));
		peer.releaseHeldMessages();
		expect(seen).to.deep.equal([
			MessageType.OPEN_CHANNEL2,
			MessageType.TX_ADD_INPUT,
			MessageType.TX_COMPLETE
		]);
	});

	it('reentrant arrivals queue BEHIND the remaining held frames', function () {
		const peer = bareHeldPeer();
		const seen: number[] = [];
		peer.on('message', (type: number) => {
			seen.push(type);
			// A synchronous transport delivers a NEW frame while older held
			// frames are still draining: it must not overtake them.
			if (seen.length === 1) {
				feed(peer, MessageType.TX_COMPLETE, Buffer.from([9]));
			}
		});
		feed(peer, MessageType.OPEN_CHANNEL2, Buffer.from([1]));
		feed(peer, MessageType.TX_ADD_INPUT, Buffer.from([2]));
		peer.releaseHeldMessages();
		expect(seen).to.deep.equal([
			MessageType.OPEN_CHANNEL2,
			MessageType.TX_ADD_INPUT,
			MessageType.TX_COMPLETE
		]);
	});

	it('a held handler that fails mid-release FAILS the dial (no false success)', async function () {
		// A held frame is injected DETERMINISTICALLY during bring-up (after
		// registration, before release) and its handler explodes: the Peer
		// tears down mid-release, and connectPeer must REJECT instead of
		// resolving with an empty registry.
		const a = new LightningNode(makeNodeConfig(15));
		const b = new LightningNode(makeNodeConfig(16));
		a.on('node:error', () => {});
		b.on('node:error', () => {});
		a.on('peer:error', () => {});
		try {
			const pmA = (
				a as unknown as {
					peerManager: {
						on(e: string, l: (...args: unknown[]) => void): void;
						peers: Map<string, unknown>;
						getPeer(pk: string): Peer | undefined;
					};
				}
			).peerManager;
			// This listener runs during dialPeer's peer:connect emit, i.e.
			// after registration and strictly before releaseHeldMessages:
			// the injected frame is guaranteed to drain through the release.
			pmA.on('peer:connect', (pubkey: unknown) => {
				const peer = pmA.getPeer(pubkey as string);
				(
					peer as unknown as {
						heldMessages: Array<{ type: number; payload: Buffer }>;
					}
				).heldMessages.push({
					type: 50_001, // odd, unknown: dispatched, no builtin handler
					payload: Buffer.alloc(1)
				});
			});
			pmA.on('message', () => {
				throw new Error('held handler exploded');
			});
			await b.listen(0, '127.0.0.1');
			const port = (
				b as unknown as {
					peerManager: { server: { address(): { port: number } } };
				}
			).peerManager.server.address().port;
			let rejection: Error | null = null;
			await a.connectPeer(b.getNodeId(), '127.0.0.1', port).catch((err) => {
				rejection = err instanceof Error ? err : new Error(String(err));
			});
			expect(rejection, 'the dial rejected').to.be.instanceOf(Error);
			expect(String(rejection)).to.contain('held-message delivery');
			expect(pmA.peers.size, 'rejected dial leaves no peer').to.equal(0);
		} finally {
			a.destroy();
			b.destroy();
		}
	});

	it('an explicit disconnectPeer from a peer:connect observer is respected', async function () {
		// The observer deliberately drops the fresh connection. The dial
		// must NOT read the resulting non-ready peer as a held-delivery
		// failure: rejecting would schedule the auto-reconnect the
		// disconnect just cancelled, undoing an explicit operator decision.
		const a = new LightningNode(makeNodeConfig(17));
		const b = new LightningNode(makeNodeConfig(18));
		a.on('node:error', () => {});
		b.on('node:error', () => {});
		a.on('peer:connect', (pubkey: string) => {
			a.disconnectPeer(pubkey);
		});
		try {
			const pmA = (
				a as unknown as {
					peerManager: {
						peers: Map<string, unknown>;
						reconnectTimers: Map<string, unknown>;
					};
				}
			).peerManager;
			await b.listen(0, '127.0.0.1');
			const port = (
				b as unknown as {
					peerManager: { server: { address(): { port: number } } };
				}
			).peerManager.server.address().port;
			// Resolves: the connection was established, then explicitly
			// closed by the observer. That is not a dial failure.
			await a.connectPeer(b.getNodeId(), '127.0.0.1', port);
			expect(pmA.peers.size, 'the disconnect stands').to.equal(0);
			expect(
				pmA.reconnectTimers.size,
				'no auto-reconnect was scheduled against the explicit disconnect'
			).to.equal(0);
			await new Promise((resolve) => setTimeout(resolve, 200));
			expect(pmA.peers.size, 'no resurrection later either').to.equal(0);
			expect(pmA.reconnectTimers.size).to.equal(0);
		} finally {
			a.destroy();
			b.destroy();
		}
	});

	it('a failed bring-up TEARS DOWN instead of releasing held traffic', async function () {
		// The connect hook is the required bring-up (our channel_reestablish
		// rides it): if it fails, releasing the peer's held reestablish
		// would reopen the ordering hazard the hold exists to prevent, so
		// the connection dies and the dial fails visibly instead.
		const events: string[] = [];
		const realRelease = Peer.prototype.releaseHeldMessages;
		Peer.prototype.releaseHeldMessages = function (
			this: Peer,
			...args: []
		): void {
			events.push('release');
			return realRelease.apply(this, args);
		};
		const a = new LightningNode(makeNodeConfig(13));
		const b = new LightningNode(makeNodeConfig(14));
		a.on('node:error', () => {});
		b.on('node:error', () => {});
		try {
			const pmOf = (n: LightningNode): NodeJS.EventEmitter =>
				(n as unknown as { peerManager: NodeJS.EventEmitter }).peerManager;
			// Hostile hooks on BOTH sides; ours registered LAST so the
			// node's own bring-up runs first and the failure follows it.
			pmOf(a).on('peer:connect', () => {
				throw new Error('outbound hook exploded');
			});
			pmOf(b).on('peer:connect', () => {
				throw new Error('inbound hook exploded');
			});
			pmOf(a).on('peer:error', () => {});
			pmOf(b).on('peer:error', () => {});

			await b.listen(0, '127.0.0.1');
			const port = (
				b as unknown as {
					peerManager: { server: { address(): { port: number } } };
				}
			).peerManager.server.address().port;
			let rejected = false;
			try {
				await a.connectPeer(b.getNodeId(), '127.0.0.1', port);
			} catch {
				rejected = true;
			}
			await new Promise((resolve) => setTimeout(resolve, 500));

			expect(rejected, 'the dial failed visibly').to.equal(true);
			expect(
				events.filter((e) => e === 'release'),
				'no held traffic was released after a failed bring-up'
			).to.have.length(0);
			const peersOf = (n: LightningNode): Map<string, unknown> =>
				(
					n as unknown as {
						peerManager: { peers: Map<string, unknown> };
					}
				).peerManager.peers;
			expect(peersOf(a).size, 'outbound unregistered').to.equal(0);
			expect(peersOf(b).size, 'inbound unregistered').to.equal(0);
		} finally {
			Peer.prototype.releaseHeldMessages = realRelease;
			a.destroy();
			b.destroy();
		}
	});

	it('stops delivering the moment the connection leaves ready', function () {
		const peer = bareHeldPeer();
		const seen: number[] = [];
		peer.on('message', (type: number) => {
			seen.push(type);
			// The delivered message tears the connection down (a refusal
			// error, a disconnect): nothing further may deliver.
			(peer as unknown as { state: string }).state = 'closing';
		});

		feed(peer, MessageType.OPEN_CHANNEL2, Buffer.from([1]));
		feed(peer, MessageType.TX_ADD_INPUT, Buffer.from([2]));
		peer.releaseHeldMessages();
		expect(seen).to.deep.equal([MessageType.OPEN_CHANNEL2]);
	});

	it('a raw Peer without the flag keeps the emit-immediately behavior', function () {
		const peer = new Peer({
			localPrivateKey: makeSeed(3),
			remotePublicKey: getPublicKey(makeSeed(4)),
			host: '127.0.0.1',
			port: 1
		});
		(peer as unknown as { state: string }).state = 'ready';
		const seen: number[] = [];
		peer.on('message', (type: number) => seen.push(type));
		feed(peer, MessageType.OPEN_CHANNEL2, Buffer.from([1]));
		expect(seen).to.deep.equal([MessageType.OPEN_CHANNEL2]);
	});

	it('re-arms a fresh hold on each establishment (no stale replay, no bypass)', async function () {
		// A reused Peer must not replay the prior connection's held frames,
		// nor skip holding because the first release nulled the queue.
		const peer = new Peer({
			localPrivateKey: makeSeed(5),
			remotePublicKey: getPublicKey(makeSeed(6)),
			host: '127.0.0.1',
			port: 1,
			holdMessagesUntilRelease: true
		});
		const rearm = (): void =>
			(peer as unknown as { rearmHeldMessages(): void }).rearmHeldMessages();

		// Life 1: hold, receive, release.
		rearm();
		(peer as unknown as { state: string }).state = 'ready';
		const seen: number[] = [];
		peer.on('message', (type: number) => seen.push(type));
		feed(peer, MessageType.OPEN_CHANNEL2, Buffer.from([1]));
		peer.releaseHeldMessages();
		expect(seen).to.deep.equal([MessageType.OPEN_CHANNEL2]);

		// Teardown drops the (empty) queue; a stray late frame is ignored.
		peer.disconnect();
		feed(peer, MessageType.TX_ADD_INPUT, Buffer.from([2]));

		// Life 2: a fresh hold, NOT the nulled post-release state, and no
		// replay of life 1's frame.
		rearm();
		(peer as unknown as { state: string }).state = 'ready';
		feed(peer, MessageType.TX_COMPLETE, Buffer.from([3]));
		expect(seen, 'life-2 frame held until release').to.deep.equal([
			MessageType.OPEN_CHANNEL2
		]);
		peer.releaseHeldMessages();
		expect(seen, 'only life-2 frame delivered, no replay').to.deep.equal([
			MessageType.OPEN_CHANNEL2,
			MessageType.TX_COMPLETE
		]);
	});

	it('a rejected connect() on a live peer leaves its delivery state untouched', async function () {
		// connect() must validate the lifecycle transition BEFORE arming a
		// fresh hold: re-arming a live connection's queue would silently
		// hold its subsequent traffic forever.
		const peer = bareHeldPeer();
		const seen: number[] = [];
		peer.on('message', (type: number) => seen.push(type));
		feed(peer, MessageType.OPEN_CHANNEL2, Buffer.from([1]));

		let firstRejected = false;
		await peer.connect().catch(() => {
			firstRejected = true;
		});
		expect(firstRejected, 'connect() on a ready peer rejects').to.equal(true);
		// The held frame survived the rejected call and still delivers.
		peer.releaseHeldMessages();
		expect(seen).to.deep.equal([MessageType.OPEN_CHANNEL2]);

		// Live now. A second rejected connect() must not re-arm the hold:
		// traffic keeps flowing immediately.
		let secondRejected = false;
		await peer.connect().catch(() => {
			secondRejected = true;
		});
		expect(secondRejected).to.equal(true);
		feed(peer, MessageType.TX_COMPLETE, Buffer.from([2]));
		expect(seen, 'the live connection was not put back on hold').to.deep.equal([
			MessageType.OPEN_CHANNEL2,
			MessageType.TX_COMPLETE
		]);
	});

	it("an old drain never clears a newer lifecycle's fresh queue", function () {
		// A delivered message's observer tears the connection down and a
		// reconnect re-arms mid-drain: the old drain's cleanup must only
		// retire ITS OWN queue, or the new lifecycle silently loses its
		// hold and traffic bypasses the release ordering.
		const peer = bareHeldPeer();
		const rearm = (): void =>
			(peer as unknown as { rearmHeldMessages(): void }).rearmHeldMessages();
		const seen: number[] = [];
		peer.on('message', (type: number) => {
			seen.push(type);
			// Mid-drain teardown plus the start of a new establishment.
			peer.disconnect();
			rearm();
		});
		feed(peer, MessageType.OPEN_CHANNEL2, Buffer.from([1]));
		feed(peer, MessageType.TX_ADD_INPUT, Buffer.from([2]));
		peer.releaseHeldMessages();
		// First frame delivered; the teardown killed the old queue's tail.
		expect(seen).to.deep.equal([MessageType.OPEN_CHANNEL2]);

		// The NEW lifecycle's queue survived the old drain's cleanup: its
		// traffic is held until its own release, not delivered live.
		(peer as unknown as { state: string }).state = 'ready';
		feed(peer, MessageType.TX_COMPLETE, Buffer.from([3]));
		expect(seen, 'the new lifecycle still holds').to.deep.equal([
			MessageType.OPEN_CHANNEL2
		]);
		peer.releaseHeldMessages();
		expect(seen).to.deep.equal([
			MessageType.OPEN_CHANNEL2,
			MessageType.TX_COMPLETE
		]);
	});

	it('over a real connection, release happens exactly once per side, AFTER peer:connect', async function () {
		// Instrument the release so the real bring-up order is observable.
		const events: string[] = [];
		const realRelease = Peer.prototype.releaseHeldMessages;
		Peer.prototype.releaseHeldMessages = function (
			this: Peer,
			...args: []
		): void {
			events.push(
				`release:${this.remotePublicKey.toString('hex').slice(0, 8)}`
			);
			return realRelease.apply(this, args);
		};
		const a = new LightningNode(makeNodeConfig(11));
		const b = new LightningNode(makeNodeConfig(12));
		a.on('node:error', () => {});
		b.on('node:error', () => {});
		try {
			const pmOf = (n: LightningNode): NodeJS.EventEmitter =>
				(n as unknown as { peerManager: NodeJS.EventEmitter }).peerManager;
			pmOf(a).on('peer:connect', (pk: string) =>
				events.push(`connect:${pk.slice(0, 8)}`)
			);
			pmOf(b).on('peer:connect', (pk: string) =>
				events.push(`connect:${pk.slice(0, 8)}`)
			);

			await b.listen(0, '127.0.0.1');
			const port = (
				b as unknown as {
					peerManager: { server: { address(): { port: number } } };
				}
			).peerManager.server.address().port;
			await a.connectPeer(b.getNodeId(), '127.0.0.1', port);
			await new Promise((resolve) => setTimeout(resolve, 500));

			const releases = events.filter((e) => e.startsWith('release:'));
			expect(releases, 'one release per side').to.have.length(2);
			for (const side of [
				b.getNodeId().slice(0, 8),
				a.getNodeId().slice(0, 8)
			]) {
				const connectAt = events.indexOf(`connect:${side}`);
				const releaseAt = events.indexOf(`release:${side}`);
				expect(connectAt, `peer:connect for ${side} happened`).to.be.gte(0);
				expect(releaseAt, `release for ${side} happened`).to.be.gte(0);
				expect(
					releaseAt,
					`release for ${side} strictly after its peer:connect`
				).to.be.greaterThan(connectAt);
			}
		} finally {
			Peer.prototype.releaseHeldMessages = realRelease;
			a.destroy();
			b.destroy();
		}
	});
});
