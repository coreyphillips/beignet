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
import net from 'net';
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
			expect(
				(pmA as unknown as { reconnectTimers: Map<string, unknown> })
					.reconnectTimers.size,
				'a genuine failure still schedules the auto-reconnect retry'
			).to.equal(1);
		} finally {
			a.destroy();
			b.destroy();
		}
	});

	it('the release outcome is STICKY for the lifecycle', function () {
		// releaseHeldMessages() is public: an observer may drain (and fail)
		// before the manager's own call, and the manager must still see the
		// causal result instead of a fresh 'released' from a cleared queue.
		const peer = bareHeldPeer();
		peer.on('error', () => {});
		peer.on('message', () => {
			throw new Error('handler exploded');
		});
		feed(peer, MessageType.OPEN_CHANNEL2, Buffer.from([1]));
		expect(peer.releaseHeldMessages()).to.equal('failed');
		expect(
			peer.releaseHeldMessages(),
			'a later caller sees the same failure'
		).to.equal('failed');
	});

	it('an observer draining (and failing) before the manager still fails the dial', async function () {
		// A peer:connect observer calls the PUBLIC releaseHeldMessages
		// itself; the drain fails and the peer:error cleanup unregisters
		// the peer. The manager's own release call must see the sticky
		// failure: without it, the dial resolves with zero peers.
		const a = new LightningNode(makeNodeConfig(25));
		const b = new LightningNode(makeNodeConfig(26));
		a.on('node:error', () => {});
		b.on('node:error', () => {});
		a.on('peer:error', (pubkey: string) => {
			a.disconnectPeer(pubkey);
		});
		try {
			const pmA = (
				a as unknown as {
					peerManager: {
						on(e: string, l: (...args: unknown[]) => void): void;
						peers: Map<string, unknown>;
						reconnectTimers: Map<string, unknown>;
						getPeer(pk: string): Peer | undefined;
					};
				}
			).peerManager;
			pmA.on('peer:connect', (pubkey: unknown) => {
				const peer = pmA.getPeer(pubkey as string);
				(
					peer as unknown as {
						heldMessages: Array<{ type: number; payload: Buffer }>;
					}
				).heldMessages.push({
					type: 50_001,
					payload: Buffer.alloc(1)
				});
				// The observer's own early drain: it fails right here.
				peer?.releaseHeldMessages();
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
			expect(rejection, 'the dial still rejected').to.be.instanceOf(Error);
			expect(String(rejection)).to.contain('held-message delivery');
			expect(pmA.peers.size, 'no phantom registration').to.equal(0);
			expect(
				pmA.reconnectTimers.size,
				'the explicit cleanup disconnect was not resurrected'
			).to.equal(0);
		} finally {
			a.destroy();
			b.destroy();
		}
	});

	it('a peer:error cleanup disconnect does not turn delivery failure into success', async function () {
		// Same deterministic held-frame failure as above, but the app's
		// peer:error observer "cleans up" with an explicit disconnectPeer,
		// removing the registration before the dial's ownership check. The
		// dial must STILL reject: the causal outcome is a delivery failure,
		// and registry identity alone cannot distinguish this cleanup from
		// a deliberate cancellation.
		const a = new LightningNode(makeNodeConfig(21));
		const b = new LightningNode(makeNodeConfig(22));
		a.on('node:error', () => {});
		b.on('node:error', () => {});
		a.on('peer:error', (pubkey: string) => {
			a.disconnectPeer(pubkey);
		});
		try {
			const pmA = (
				a as unknown as {
					peerManager: {
						on(e: string, l: (...args: unknown[]) => void): void;
						peers: Map<string, unknown>;
						reconnectTimers: Map<string, unknown>;
						getPeer(pk: string): Peer | undefined;
					};
				}
			).peerManager;
			pmA.on('peer:connect', (pubkey: unknown) => {
				const peer = pmA.getPeer(pubkey as string);
				(
					peer as unknown as {
						heldMessages: Array<{ type: number; payload: Buffer }>;
					}
				).heldMessages.push({
					type: 50_001,
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
			expect(
				rejection,
				'the dial rejected despite the cleanup'
			).to.be.instanceOf(Error);
			expect(String(rejection)).to.contain('held-message delivery');
			expect(pmA.peers.size, 'no phantom registration').to.equal(0);
			expect(
				pmA.reconnectTimers.size,
				'the failure did not resurrect the explicitly cancelled peer'
			).to.equal(0);
		} finally {
			a.destroy();
			b.destroy();
		}
	});

	it('a throwing peer:connect observer costs neither the connection nor the dial', async function () {
		// The public notification is not part of the required bring-up: an
		// application observer that explodes, and even a log observer that
		// explodes while that failure is being reported, must both be
		// contained instead of reading as a failed bring-up and tearing
		// down a healthy connection.
		const a = new LightningNode(makeNodeConfig(23));
		const b = new LightningNode(makeNodeConfig(24));
		a.on('node:error', () => {});
		b.on('node:error', () => {});
		a.on('peer:connect', () => {
			throw new Error('app observer exploded');
		});
		a.on('log', (entry: { action?: string }) => {
			if (entry?.action === 'connect_observer_failed') {
				throw new Error('log observer exploded too');
			}
		});
		try {
			const pmA = (
				a as unknown as {
					peerManager: {
						peers: Map<string, unknown>;
						getPeer(pk: string): Peer | undefined;
					};
				}
			).peerManager;
			await b.listen(0, '127.0.0.1');
			const port = (
				b as unknown as {
					peerManager: { server: { address(): { port: number } } };
				}
			).peerManager.server.address().port;
			await a.connectPeer(b.getNodeId(), '127.0.0.1', port);
			expect(pmA.peers.size, 'the connection survived').to.equal(1);
			expect(pmA.getPeer(b.getNodeId())?.getState(), 'and it is live').to.equal(
				'ready'
			);
		} finally {
			a.destroy();
			b.destroy();
		}
	});

	it('a reentrant release reports pending, never a false terminal outcome', function () {
		// A recursive call during an active drain has no terminal outcome
		// to report yet: answering 'released' while the outer drain later
		// fails would hand the reentrant caller a false success.
		const peer = bareHeldPeer();
		peer.on('error', () => {});
		const reentrant: string[] = [];
		let first = true;
		peer.on('message', () => {
			if (first) {
				first = false;
				reentrant.push(peer.releaseHeldMessages());
				return;
			}
			throw new Error('second handler exploded');
		});
		feed(peer, MessageType.OPEN_CHANNEL2, Buffer.from([1]));
		feed(peer, MessageType.TX_ADD_INPUT, Buffer.from([2]));
		expect(peer.releaseHeldMessages()).to.equal('failed');
		expect(reentrant, 'the reentrant call saw pending').to.deep.equal([
			'pending'
		]);
		expect(peer.releaseHeldMessages(), 'sticky afterwards').to.equal('failed');
	});

	it('an explicit disconnectPeer DURING a pending dial wins over registration', async function () {
		// The cancellation lands after the handshake completed but before
		// the manager registers the connection: the dial must not
		// resurrect the peer the caller just removed, and must reject
		// without scheduling the auto-reconnect that was just cancelled.
		const a = new LightningNode(makeNodeConfig(27));
		const b = new LightningNode(makeNodeConfig(28));
		a.on('node:error', () => {});
		b.on('node:error', () => {});
		const realConnect = Peer.prototype.connect;
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
			Peer.prototype.connect = async function (this: Peer): Promise<void> {
				await realConnect.apply(this);
				a.disconnectPeer(b.getNodeId());
			};
			let rejection: Error | null = null;
			await a.connectPeer(b.getNodeId(), '127.0.0.1', port).catch((err) => {
				rejection = err instanceof Error ? err : new Error(String(err));
			});
			expect(rejection, 'the dial rejected').to.be.instanceOf(Error);
			expect(String(rejection)).to.contain('cancelled while establishing');
			expect(
				(rejection as unknown as Error).name,
				'and the rejection is TYPED so retry loops can stop'
			).to.equal('PeerDialCancelledError');
			expect(pmA.peers.size, 'nothing was registered').to.equal(0);
			expect(pmA.reconnectTimers.size, 'and nothing was rescheduled').to.equal(
				0
			);
		} finally {
			Peer.prototype.connect = realConnect;
			a.destroy();
			b.destroy();
		}
	});

	it('disconnectPeer aborts a stalled in-flight dial immediately', async function () {
		// A TCP server that accepts and never answers: the noise handshake
		// stalls. Explicit cancellation must abort the pending dial NOW
		// (typed rejection, no socket left live until the 30s timeout).
		const blackhole = net.createServer(() => undefined);
		await new Promise<void>((resolve) =>
			blackhole.listen(0, '127.0.0.1', resolve)
		);
		const port = (blackhole.address() as { port: number }).port;
		const a = new LightningNode(makeNodeConfig(31));
		a.on('node:error', () => {});
		try {
			const pmA = (
				a as unknown as {
					peerManager: {
						peers: Map<string, unknown>;
						reconnectTimers: Map<string, unknown>;
						pendingDialsByPubkey: Map<string, unknown>;
					};
				}
			).peerManager;
			const target = getPublicKey(makeSeed(997)).toString('hex');
			let rejection: Error | null = null;
			const dial = a.connectPeer(target, '127.0.0.1', port).catch((err) => {
				rejection = err instanceof Error ? err : new Error(String(err));
			});
			await new Promise((resolve) => setTimeout(resolve, 150));
			expect(
				pmA.pendingDialsByPubkey.size,
				'the stalled dial is indexed'
			).to.equal(1);
			a.disconnectPeer(target);
			await dial;
			expect(rejection, 'the dial settled promptly').to.be.instanceOf(Error);
			expect((rejection as unknown as Error).name).to.equal(
				'PeerDialCancelledError'
			);
			expect(pmA.pendingDialsByPubkey.size, 'nothing pending').to.equal(0);
			expect(pmA.peers.size).to.equal(0);
			expect(pmA.reconnectTimers.size, 'nothing rescheduled').to.equal(0);
		} finally {
			a.destroy();
			blackhole.close();
		}
	});

	it('connectPeerById stops on cancellation instead of trying the next address', async function () {
		// The cancellation covers the whole node-id operation: treating it
		// as one more failed address and dialing the next graph candidate
		// would reconnect the very peer the caller just removed.
		const a = new LightningNode(makeNodeConfig(32));
		a.on('node:error', () => {});
		try {
			const pubkey = getPublicKey(makeSeed(996)).toString('hex');
			(
				a as unknown as {
					graph: {
						getNode(id: Buffer): {
							announcement: {
								addresses: Array<{
									type: number;
									host: string;
									port: number;
								}>;
							};
						};
					};
				}
			).graph = {
				getNode: () => ({
					announcement: {
						addresses: [
							{ type: 1, host: '127.0.0.1', port: 1 },
							{ type: 1, host: '127.0.0.1', port: 2 }
						]
					}
				})
			};
			const pmA = (
				a as unknown as {
					peerManager: {
						connectPeer(pk: string, host: string, port: number): Promise<void>;
					};
				}
			).peerManager;
			const { PeerDialCancelledError } = await import(
				'../../src/lightning/transport/peer-manager'
			);
			let dials = 0;
			pmA.connectPeer = async (pk: string): Promise<void> => {
				dials++;
				throw new PeerDialCancelledError(pk);
			};
			let rejection: Error | null = null;
			await a.connectPeer(pubkey).catch((err) => {
				rejection = err instanceof Error ? err : new Error(String(err));
			});
			expect(rejection, 'the operation rejected').to.be.instanceOf(Error);
			expect((rejection as unknown as Error).name).to.equal(
				'PeerDialCancelledError'
			);
			expect(dials, 'the second address was never tried').to.equal(1);
		} finally {
			a.destroy();
		}
	});

	it('a peer:disconnect observer cancelling on natural close is respected', async function () {
		// The remote side drops the connection; a synchronous
		// peer:disconnect observer decides the peer is gone for good. The
		// close handler must not schedule a reconnect that adopts the
		// post-cancellation generation.
		const a = new LightningNode(makeNodeConfig(33));
		const b = new LightningNode(makeNodeConfig(34));
		a.on('node:error', () => {});
		b.on('node:error', () => {});
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
			await a.connectPeer(b.getNodeId(), '127.0.0.1', port);
			expect(pmA.peers.size).to.equal(1);
			a.on('peer:disconnect', (pubkey: string) => {
				a.disconnectPeer(pubkey);
			});
			// Natural close from the REMOTE side.
			b.disconnectPeer(a.getNodeId());
			await new Promise((resolve) => setTimeout(resolve, 300));
			expect(pmA.peers.size, 'the peer stayed gone').to.equal(0);
			expect(
				pmA.reconnectTimers.size,
				'the close handler honored the cancellation'
			).to.equal(0);
		} finally {
			a.destroy();
			b.destroy();
		}
	});

	it('a cancellation during DNS resolution stops the node-id operation', async function () {
		// While bootstrapPeers() is pending no dial exists to reject with
		// the typed error: the operation token captured up front must stop
		// the FIRST dns dial from ever starting.
		const a = new LightningNode(makeNodeConfig(35));
		a.on('node:error', () => {});
		try {
			const pubkey = getPublicKey(makeSeed(995)).toString('hex');
			(
				a as unknown as {
					graph: { getNode(id: Buffer): undefined };
				}
			).graph = { getNode: () => undefined };
			(
				a as unknown as {
					bootstrapPeers(): Promise<
						Array<{ pubkey: Buffer; host: string; port: number }>
					>;
				}
			).bootstrapPeers = async () => {
				// The explicit cancellation lands MID-resolution.
				a.disconnectPeer(pubkey);
				return [
					{
						pubkey: Buffer.from(pubkey, 'hex'),
						host: '127.0.0.1',
						port: 9
					}
				];
			};
			let dials = 0;
			(
				a as unknown as {
					peerManager: { connectPeer(): Promise<void> };
				}
			).peerManager.connectPeer = async (): Promise<void> => {
				dials++;
			};
			let rejection: Error | null = null;
			await a.connectPeer(pubkey).catch((err) => {
				rejection = err instanceof Error ? err : new Error(String(err));
			});
			expect(rejection, 'the operation rejected').to.be.instanceOf(Error);
			expect((rejection as unknown as Error).name).to.equal(
				'PeerDialCancelledError'
			);
			expect(dials, 'the resolved DNS address was never dialed').to.equal(0);
		} finally {
			a.destroy();
		}
	});

	it('an inbound replacement is discarded when a peer:disconnect observer cancels', async function () {
		// Newest-wins replacement emits peer:disconnect for the old
		// connection; a synchronous observer cancelling the peer must not
		// be reversed by registering the fresh inbound anyway.
		const a = new LightningNode(makeNodeConfig(36));
		const b = new LightningNode(makeNodeConfig(37));
		a.on('node:error', () => {});
		b.on('node:error', () => {});
		try {
			const pmA = (
				a as unknown as {
					peerManager: {
						peers: Map<string, unknown>;
						reconnectTimers: Map<string, unknown>;
					};
				}
			).peerManager;
			await a.listen(0, '127.0.0.1');
			const port = (
				a as unknown as {
					peerManager: { server: { address(): { port: number } } };
				}
			).peerManager.server.address().port;
			// First inbound registers normally.
			await b.connectPeer(a.getNodeId(), '127.0.0.1', port);
			await new Promise((resolve) => setTimeout(resolve, 100));
			expect(pmA.peers.size, 'the first inbound registered').to.equal(1);
			// The observer decides the peer is gone for good the moment the
			// replacement tears the old connection down.
			a.on('peer:disconnect', (pubkey: string) => {
				a.disconnectPeer(pubkey);
			});
			// A SECOND inbound from the same identity (a raw Peer dialing
			// a's listener) triggers newest-wins replacement.
			const raw = new Peer({
				localPrivateKey: crypto
					.createHash('sha256')
					.update(makeSeed(37))
					.update(Buffer.from('node-identity'))
					.digest(),
				remotePublicKey: Buffer.from(a.getNodeId(), 'hex'),
				host: '127.0.0.1',
				port
			});
			raw.on('error', () => {});
			await raw.connect().catch(() => undefined);
			await new Promise((resolve) => setTimeout(resolve, 300));
			expect(
				pmA.peers.size,
				'the replacement was discarded, not registered'
			).to.equal(0);
			expect(pmA.reconnectTimers.size).to.equal(0);
			raw.disconnect();
		} finally {
			a.destroy();
			b.destroy();
		}
	});

	it('an outbound collision replacement is discarded when the observer cancels', async function () {
		// The outbound twin of the inbound test: an inbound registers WHILE
		// our outbound handshake is in flight, our outbound wins the
		// cross-direction tie-break and tears the inbound down, and a
		// synchronous observer cancellation during that teardown must
		// discard OUR fresh connection too, rejecting the dial typed.
		const x = new LightningNode(makeNodeConfig(38));
		const y = new LightningNode(makeNodeConfig(39));
		x.on('node:error', () => {});
		y.on('node:error', () => {});
		const realConnect = Peer.prototype.connect;
		try {
			// The SMALLER pubkey side prefers its outbound in the tie-break.
			const [small, big] = x.getNodeId() < y.getNodeId() ? [x, y] : [y, x];
			const pmSmall = (
				small as unknown as {
					peerManager: {
						peers: Map<string, unknown>;
						reconnectTimers: Map<string, unknown>;
					};
				}
			).peerManager;
			await small.listen(0, '127.0.0.1');
			await big.listen(0, '127.0.0.1');
			const smallPort = (
				small as unknown as {
					peerManager: { server: { address(): { port: number } } };
				}
			).peerManager.server.address().port;
			const bigPort = (
				big as unknown as {
					peerManager: { server: { address(): { port: number } } };
				}
			).peerManager.server.address().port;
			small.on('peer:disconnect', (pubkey: string) => {
				small.disconnectPeer(pubkey);
			});
			// After small's outbound handshake completes but BEFORE the
			// manager registers it, an inbound bearing BIG'S identity (a raw
			// Peer: big's manager would refuse the dial as already-connected)
			// occupies the registration: the exact cross-dial window.
			const nodeKeyOf = (seedId: number): Buffer =>
				crypto
					.createHash('sha256')
					.update(makeSeed(seedId))
					.update(Buffer.from('node-identity'))
					.digest();
			const bigKey = [38, 39]
				.map(nodeKeyOf)
				.find((k) => getPublicKey(k).toString('hex') === big.getNodeId())!;
			const raw = new Peer({
				localPrivateKey: bigKey,
				remotePublicKey: Buffer.from(small.getNodeId(), 'hex'),
				host: '127.0.0.1',
				port: smallPort
			});
			raw.on('error', () => {});
			let armed = true;
			Peer.prototype.connect = async function (this: Peer): Promise<void> {
				await realConnect.apply(this);
				if (armed && this.remotePublicKey.toString('hex') === big.getNodeId()) {
					armed = false;
					await realConnect.apply(raw);
					await new Promise((resolve) => setTimeout(resolve, 100));
				}
			};
			let rejection: Error | null = null;
			await small
				.connectPeer(big.getNodeId(), '127.0.0.1', bigPort)
				.catch((err) => {
					rejection = err instanceof Error ? err : new Error(String(err));
				});
			expect(rejection, 'the dial rejected').to.be.instanceOf(Error);
			expect((rejection as unknown as Error).name).to.equal(
				'PeerDialCancelledError'
			);
			await new Promise((resolve) => setTimeout(resolve, 200));
			expect(
				pmSmall.peers.size,
				'neither the loser nor the replacement survived'
			).to.equal(0);
			expect(pmSmall.reconnectTimers.size).to.equal(0);
			raw.disconnect();
		} finally {
			Peer.prototype.connect = realConnect;
			x.destroy();
			y.destroy();
		}
	});

	it('a throwing peer:disconnect observer does not leak the inbound replacement', async function () {
		// Newest-wins replacement emits peer:disconnect for the old
		// connection synchronously. An observer that THROWS (rather than
		// cancels) must not unwind into the replacement path: the fresh
		// inbound would end up neither registered nor disconnected, with no
		// listeners attached, leaking until its ping timeout (issue #319).
		const a = new LightningNode(makeNodeConfig(93));
		const b = new LightningNode(makeNodeConfig(94));
		a.on('node:error', () => {});
		b.on('node:error', () => {});
		try {
			const pmA = (
				a as unknown as {
					peerManager: {
						peers: Map<string, unknown>;
					};
				}
			).peerManager;
			await a.listen(0, '127.0.0.1');
			const port = (
				a as unknown as {
					peerManager: { server: { address(): { port: number } } };
				}
			).peerManager.server.address().port;
			// First inbound registers normally.
			await b.connectPeer(a.getNodeId(), '127.0.0.1', port);
			await new Promise((resolve) => setTimeout(resolve, 100));
			expect(pmA.peers.size, 'the first inbound registered').to.equal(1);
			const observerErrors: string[] = [];
			a.on('peer:error', (_pubkey: string, err: Error) => {
				observerErrors.push(err.message);
			});
			a.on('peer:disconnect', () => {
				throw new Error('disconnect observer exploded');
			});
			// A SECOND inbound from the same identity triggers newest-wins.
			const raw = new Peer({
				localPrivateKey: crypto
					.createHash('sha256')
					.update(makeSeed(94))
					.update(Buffer.from('node-identity'))
					.digest(),
				remotePublicKey: Buffer.from(a.getNodeId(), 'hex'),
				host: '127.0.0.1',
				port
			});
			raw.on('error', () => {});
			await raw.connect().catch(() => undefined);
			await new Promise((resolve) => setTimeout(resolve, 300));
			expect(
				pmA.peers.size,
				'the replacement was registered despite the throwing observer'
			).to.equal(1);
			expect(
				observerErrors,
				'the observer failure surfaced as peer:error'
			).to.include('disconnect observer exploded');
			raw.disconnect();
		} finally {
			a.destroy();
			b.destroy();
		}
	});

	it('a throwing peer:disconnect observer does not leak the outbound race winner', async function () {
		// The outbound twin: an inbound registers WHILE our outbound
		// handshake is in flight, our outbound wins the cross-direction
		// tie-break and tears the inbound down. An observer throwing during
		// that teardown must not unwind before the registration at the end
		// of dialPeer: the dial would reject with the observer's error and
		// the fresh socket would leak un-registered (issue #319).
		const x = new LightningNode(makeNodeConfig(95));
		const y = new LightningNode(makeNodeConfig(96));
		x.on('node:error', () => {});
		y.on('node:error', () => {});
		const realConnect = Peer.prototype.connect;
		try {
			// The SMALLER pubkey side prefers its outbound in the tie-break.
			const [small, big] = x.getNodeId() < y.getNodeId() ? [x, y] : [y, x];
			const pmSmall = (
				small as unknown as {
					peerManager: {
						peers: Map<string, unknown>;
					};
				}
			).peerManager;
			await small.listen(0, '127.0.0.1');
			await big.listen(0, '127.0.0.1');
			const smallPort = (
				small as unknown as {
					peerManager: { server: { address(): { port: number } } };
				}
			).peerManager.server.address().port;
			const bigPort = (
				big as unknown as {
					peerManager: { server: { address(): { port: number } } };
				}
			).peerManager.server.address().port;
			small.on('peer:disconnect', () => {
				throw new Error('disconnect observer exploded');
			});
			// After small's outbound handshake completes but BEFORE the
			// manager registers it, an inbound bearing BIG'S identity
			// occupies the registration: the exact cross-dial window.
			const nodeKeyOf = (seedId: number): Buffer =>
				crypto
					.createHash('sha256')
					.update(makeSeed(seedId))
					.update(Buffer.from('node-identity'))
					.digest();
			const bigKey = [95, 96]
				.map(nodeKeyOf)
				.find((k) => getPublicKey(k).toString('hex') === big.getNodeId())!;
			const raw = new Peer({
				localPrivateKey: bigKey,
				remotePublicKey: Buffer.from(small.getNodeId(), 'hex'),
				host: '127.0.0.1',
				port: smallPort
			});
			raw.on('error', () => {});
			let armed = true;
			Peer.prototype.connect = async function (this: Peer): Promise<void> {
				await realConnect.apply(this);
				if (armed && this.remotePublicKey.toString('hex') === big.getNodeId()) {
					armed = false;
					await realConnect.apply(raw);
					await new Promise((resolve) => setTimeout(resolve, 100));
				}
			};
			let rejection: Error | null = null;
			await small
				.connectPeer(big.getNodeId(), '127.0.0.1', bigPort)
				.catch((err) => {
					rejection = err instanceof Error ? err : new Error(String(err));
				});
			expect(rejection, 'the dial resolved despite the throwing observer').to.be
				.null;
			await new Promise((resolve) => setTimeout(resolve, 200));
			expect(pmSmall.peers.size, 'the race winner was registered').to.equal(1);
			raw.disconnect();
		} finally {
			Peer.prototype.connect = realConnect;
			x.destroy();
			y.destroy();
		}
	});

	it('a throwing peer:disconnect observer does not cancel the reconnect on natural close', async function () {
		// The close handler schedules the auto-reconnect AFTER the
		// peer:disconnect emit. A throwing observer must not unwind past
		// that scheduling (silently cancelling the reconnect) or escape
		// uncaught into the socket event loop.
		const a = new LightningNode(makeNodeConfig(91));
		const b = new LightningNode(makeNodeConfig(92));
		a.on('node:error', () => {});
		b.on('node:error', () => {});
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
			await a.connectPeer(b.getNodeId(), '127.0.0.1', port);
			expect(pmA.peers.size).to.equal(1);
			a.on('peer:disconnect', () => {
				throw new Error('disconnect observer exploded');
			});
			// Natural close from the REMOTE side. The reconnect delay floor
			// (1s base, minus 25% jitter) keeps the timer pending well past
			// the assertion below.
			b.disconnectPeer(a.getNodeId());
			await new Promise((resolve) => setTimeout(resolve, 300));
			expect(pmA.peers.size, 'the close bookkeeping completed').to.equal(0);
			expect(
				pmA.reconnectTimers.size,
				'the reconnect was still scheduled'
			).to.equal(1);
		} finally {
			a.destroy();
			b.destroy();
		}
	});

	it('a reconnect round cancelled mid-round neither redials nor reschedules', async function () {
		// disconnectPeer clears the PENDING timer, but a round already past
		// that point keeps running: it must check the cancellation before
		// trying another address and before rescheduling itself.
		const a = new LightningNode(makeNodeConfig(29));
		a.on('node:error', () => {});
		try {
			const pubkey = getPublicKey(makeSeed(999)).toString('hex');
			const pmA = (
				a as unknown as {
					peerManager: {
						peerAddresses: Map<string, { host: string; port: number }>;
						reconnectDelays: Map<string, number>;
						reconnectTimers: Map<string, unknown>;
						dialPeer: (...args: unknown[]) => Promise<void>;
						scheduleReconnect(pk: string): void;
					};
				}
			).peerManager;
			pmA.peerAddresses.set(pubkey, { host: '127.0.0.1', port: 1 });
			pmA.reconnectDelays.set(pubkey, 80);
			let dialCount = 0;
			pmA.dialPeer = async (): Promise<void> => {
				dialCount++;
				// The explicit cancellation lands while the round is mid-dial.
				a.disconnectPeer(pubkey);
				throw new Error('dial failed');
			};
			pmA.scheduleReconnect(pubkey);
			expect(pmA.reconnectTimers.size).to.equal(1);
			await new Promise((resolve) => setTimeout(resolve, 500));
			expect(dialCount, 'exactly one dial ran').to.equal(1);
			expect(
				pmA.reconnectTimers.size,
				'the cancelled round did not reschedule itself'
			).to.equal(0);
		} finally {
			a.destroy();
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
		): ReturnType<Peer['releaseHeldMessages']> {
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
		// Life 1: hold (armed by the constructor), receive, release.
		(peer as unknown as { state: string }).state = 'ready';
		const seen: number[] = [];
		peer.on('message', (type: number) => seen.push(type));
		peer.on('error', () => {});
		feed(peer, MessageType.OPEN_CHANNEL2, Buffer.from([1]));
		peer.releaseHeldMessages();
		expect(seen).to.deep.equal([MessageType.OPEN_CHANNEL2]);

		// Teardown drops the (empty) queue; a stray late frame is ignored.
		peer.disconnect();
		feed(peer, MessageType.TX_ADD_INPUT, Buffer.from([2]));

		// Life 2 re-arms through the REAL call site: connect() itself (the
		// dial fails, port 1, but the fresh hold must already be armed).
		// A fresh hold, NOT the nulled post-release state, and no replay
		// of life 1's frame.
		await peer.connect().catch(() => undefined);
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

	it('teardown by the FINAL held frame reports aborted, not released', function () {
		// The drain loop only observes state at the top of an iteration, so
		// a disconnect from the last (or sole) handler used to fall out of
		// the loop into the success return. The outcome is the CAUSAL
		// record; 'released' for a torn-down connection is a false answer.
		const peer = bareHeldPeer();
		const seen: number[] = [];
		peer.on('message', (type: number) => {
			seen.push(type);
			(peer as unknown as { state: string }).state = 'closing';
		});
		feed(peer, MessageType.OPEN_CHANNEL2, Buffer.from([1]));
		expect(peer.releaseHeldMessages()).to.equal('aborted');
		expect(seen).to.deep.equal([MessageType.OPEN_CHANNEL2]);
		// Sticky for the lifecycle, like every other terminal outcome.
		expect(peer.releaseHeldMessages()).to.equal('aborted');
	});

	it('a handler that disconnects and THEN throws still records failed', function () {
		// disconnect() nulls the queue without starting a new lifecycle, so
		// a guard keyed on array identity would skip the sticky write here.
		// The lifecycle ID does not move until a re-establishment re-arms:
		// this is still the failing lifecycle and must answer 'failed'.
		const peer = bareHeldPeer();
		peer.on('message', () => {
			peer.disconnect();
			throw new Error('handler failed after its own teardown');
		});
		peer.on('error', () => {});
		feed(peer, MessageType.OPEN_CHANNEL2, Buffer.from([1]));
		expect(peer.releaseHeldMessages()).to.equal('failed');
		expect(peer.releaseHeldMessages(), 'sticky across queries').to.equal(
			'failed'
		);
	});

	it('a throwing handler that re-armed a fresh lifecycle cannot destroy it', function () {
		// The old drain's failure path used to clear this.heldMessages and
		// disconnect unconditionally: a handler that tore down, re-armed a
		// new establishment and THEN threw had the fresh queue erased and
		// its reset outcome clobbered by the stale drain. With the
		// lifecycle ID, the old drain reports its failure and touches
		// nothing that now belongs to the new lifecycle.
		const peer = bareHeldPeer();
		const rearm = (): void =>
			(peer as unknown as { rearmHeldMessages(): void }).rearmHeldMessages();
		const seen: number[] = [];
		let threw = false;
		peer.on('message', (type: number) => {
			seen.push(type);
			if (!threw) {
				threw = true;
				peer.disconnect();
				rearm();
				throw new Error('old lifecycle handler failed');
			}
		});
		const errors: Error[] = [];
		peer.on('error', (err: Error) => errors.push(err));
		feed(peer, MessageType.OPEN_CHANNEL2, Buffer.from([1]));
		expect(
			peer.releaseHeldMessages(),
			'the old drain still reports its failure'
		).to.equal('failed');
		// The failure is SURFACED even though the stale drain touches
		// nothing: a 'failed' outcome with zero error events is invisible
		// to every observer that only listens.
		expect(errors.length, 'the peer error was emitted').to.equal(1);
		expect(String(errors[0].message)).to.contain(
			'old lifecycle handler failed'
		);

		// The FRESH lifecycle is intact: its queue still holds (traffic is
		// not delivered live), and its outcome was not poisoned to 'failed'.
		(peer as unknown as { state: string }).state = 'ready';
		feed(peer, MessageType.TX_COMPLETE, Buffer.from([3]));
		expect(seen, 'the new lifecycle still holds').to.deep.equal([
			MessageType.OPEN_CHANNEL2
		]);
		expect(peer.releaseHeldMessages()).to.equal('released');
		expect(seen).to.deep.equal([
			MessageType.OPEN_CHANNEL2,
			MessageType.TX_COMPLETE
		]);
	});

	it('disconnectPeer during a first inbound handshake wins over registration', async function () {
		// Inbound peers are anonymous until Noise completes, so an explicit
		// disconnectPeer(pubkey) issued mid-handshake has nothing
		// pubkey-addressable to abort; the cancellation era must be
		// re-checked the moment identity is learned, or the peer registers
		// 'ready' right through the cancellation.
		const a = new LightningNode(makeNodeConfig(72));
		a.on('node:error', () => {});
		const dialerKey = crypto
			.createHash('sha256')
			.update(makeSeed(73))
			.update(Buffer.from('node-identity'))
			.digest();
		const dialerPubkey = getPublicKey(dialerKey).toString('hex');
		const originalAccept = Peer.prototype.acceptInbound;
		try {
			const pmA = (
				a as unknown as {
					peerManager: {
						peers: Map<string, unknown>;
						reconnectTimers: Map<string, unknown>;
					};
				}
			).peerManager;
			await a.listen(0, '127.0.0.1');
			const port = (
				a as unknown as {
					peerManager: { server: { address(): { port: number } } };
				}
			).peerManager.server.address().port;
			// Cancel WHILE the Noise handshake is in flight: the wrap runs
			// after the manager snapshotted its era for this socket and
			// before the handshake learns who is dialing.
			Peer.prototype.acceptInbound = async function (
				this: Peer,
				...args: Parameters<typeof originalAccept>
			): Promise<void> {
				a.disconnectPeer(dialerPubkey);
				return originalAccept.apply(this, args);
			};
			const raw = new Peer({
				localPrivateKey: dialerKey,
				remotePublicKey: Buffer.from(a.getNodeId(), 'hex'),
				host: '127.0.0.1',
				port
			});
			raw.on('error', () => {});
			await raw.connect().catch(() => undefined);
			await new Promise((resolve) => setTimeout(resolve, 300));
			expect(
				pmA.peers.size,
				'the cancelled handshake never registered'
			).to.equal(0);
			expect(pmA.reconnectTimers.size).to.equal(0);
			raw.disconnect();
		} finally {
			Peer.prototype.acceptInbound = originalAccept;
			a.destroy();
		}
	});

	it('over a real connection, release happens exactly once per side, AFTER peer:connect', async function () {
		// Instrument the release so the real bring-up order is observable.
		const events: string[] = [];
		const realRelease = Peer.prototype.releaseHeldMessages;
		Peer.prototype.releaseHeldMessages = function (
			this: Peer,
			...args: []
		): ReturnType<Peer['releaseHeldMessages']> {
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
