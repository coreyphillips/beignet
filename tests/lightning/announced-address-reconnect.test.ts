/**
 * Reconnecting to inbound channel peers via gossip-announced addresses.
 *
 * An inbound peer exposes no dialable address (its TCP source port is
 * ephemeral), so before this feature a channel with a peer that only ever
 * dialed us had no self-recovery path: after a drop, the channel sat in
 * AWAITING_REESTABLISH until a human forced a reconnect from the other side.
 * LND and CLN fall back to the addresses in the peer's signature-verified
 * node_announcement; these tests cover beignet doing the same.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { EventEmitter } from 'events';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { PeerManager } from '../../src/lightning/transport/peer-manager';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	encodeNodeAnnouncementMessage,
	announcedDialableAddresses
} from '../../src/lightning/gossip/messages';
import { signNodeAnnouncement } from '../../src/lightning/gossip/validation';
import {
	ADDRESS_TYPE_IPV4,
	ADDRESS_TYPE_TORV2,
	ADDRESS_TYPE_TORV3,
	ADDRESS_TYPE_DNS
} from '../../src/lightning/gossip/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { IStorageBackend } from '../../src/lightning/storage/types';

// ── Helpers ────────────────────────────────────────────────────────

function makeBasepoints(): IChannelBasepoints {
	return {
		fundingPubkey: crypto.randomBytes(33),
		revocationBasepoint: crypto.randomBytes(33),
		paymentBasepoint: crypto.randomBytes(33),
		delayedPaymentBasepoint: crypto.randomBytes(33),
		htlcBasepoint: crypto.randomBytes(33),
		firstPerCommitmentPoint: crypto.randomBytes(33)
	};
}

function makeNode(opts?: {
	privateKey?: Buffer;
	storage?: IStorageBackend;
}): LightningNode {
	return new LightningNode({
		nodePrivateKey: opts?.privateKey ?? crypto.randomBytes(32),
		perCommitmentSeed: crypto.randomBytes(32),
		channelBasepoints: makeBasepoints(),
		fundingPrivkey: crypto.randomBytes(32),
		enableNetworking: true,
		storage: opts?.storage
	});
}

/** A signed node_announcement advertising the given addresses. */
function makeAnnouncement(
	privkey: Buffer,
	addresses: Array<{ type: number; host: string; port: number }>,
	timestamp = Math.floor(Date.now() / 1000)
): Buffer {
	const payload = encodeNodeAnnouncementMessage({
		signature: Buffer.alloc(64),
		features: Buffer.alloc(0),
		timestamp,
		nodeId: getPublicKey(privkey),
		rgbColor: Buffer.from([0, 0, 0]),
		alias: Buffer.alloc(32),
		addresses
	});
	signNodeAnnouncement(payload, privkey).copy(payload, 0);
	return payload;
}

async function waitFor(cond: () => boolean, timeoutMs = 10_000): Promise<void> {
	const start = Date.now();
	while (!cond()) {
		if (Date.now() - start > timeoutMs) {
			throw new Error('waitFor timed out');
		}
		await new Promise((r) => setTimeout(r, 25));
	}
}

// ── announcedDialableAddresses ─────────────────────────────────────

describe('announcedDialableAddresses', function () {
	it('passes IPv4 and DNS descriptors through as host:port', function () {
		const out = announcedDialableAddresses([
			{ type: ADDRESS_TYPE_IPV4, host: '203.0.113.7', port: 9735 },
			{ type: ADDRESS_TYPE_DNS, host: 'node.example.com', port: 9736 }
		]);
		expect(out).to.deep.equal([
			{ host: '203.0.113.7', port: 9735 },
			{ host: 'node.example.com', port: 9736 }
		]);
	});

	it('re-encodes a Tor v3 descriptor to its .onion hostname', function () {
		const out = announcedDialableAddresses([
			{
				type: ADDRESS_TYPE_TORV3,
				host: crypto.randomBytes(35).toString('hex'),
				port: 9735
			}
		]);
		expect(out.length).to.equal(1);
		expect(out[0].host.endsWith('.onion')).to.equal(true);
		expect(out[0].port).to.equal(9735);
	});

	it('drops Tor v2, zero ports and unknown types', function () {
		const out = announcedDialableAddresses([
			{
				type: ADDRESS_TYPE_TORV2,
				host: crypto.randomBytes(10).toString('hex'),
				port: 9735
			},
			{ type: ADDRESS_TYPE_IPV4, host: '203.0.113.7', port: 0 },
			{ type: 99, host: 'whatever', port: 9735 }
		]);
		expect(out).to.deep.equal([]);
	});
});

// ── PeerManager: announced-address fallbacks ───────────────────────

describe('PeerManager: gossip-announced reconnect fallbacks', function () {
	it('caps stored announced addresses and clears on an empty list', function () {
		const pm = new PeerManager({ localPrivateKey: crypto.randomBytes(32) });
		const pubkey = crypto.randomBytes(33).toString('hex');
		const many = Array.from({ length: 8 }, (_, i) => ({
			host: `203.0.113.${i}`,
			port: 9735
		}));
		pm.setAnnouncedAddresses(pubkey, many);
		expect(pm.getAnnouncedAddresses(pubkey).length).to.equal(5);
		pm.setAnnouncedAddresses(pubkey, []);
		expect(pm.getAnnouncedAddresses(pubkey)).to.deep.equal([]);
		pm.destroy();
	});

	it('schedules a reconnect for a peer with only announced addresses', function () {
		const pm = new PeerManager({
			localPrivateKey: crypto.randomBytes(32),
			autoReconnect: true
		});
		const pubkey = crypto.randomBytes(33).toString('hex');
		const internal = pm as unknown as {
			scheduleReconnect(pubkey: string): void;
			reconnectTimers: Map<string, ReturnType<typeof setTimeout>>;
		};

		// No addresses at all: nothing to schedule (pre-existing behavior).
		internal.scheduleReconnect(pubkey);
		expect(internal.reconnectTimers.has(pubkey)).to.equal(false);

		// Announced addresses alone are enough now.
		pm.setAnnouncedAddresses(pubkey, [{ host: '203.0.113.7', port: 9735 }]);
		internal.scheduleReconnect(pubkey);
		expect(internal.reconnectTimers.has(pubkey)).to.equal(true);
		pm.destroy();
	});

	it('dials the last-known-good address first, then deduped announced ones', async function () {
		const pm = new PeerManager({ localPrivateKey: crypto.randomBytes(32) });
		const pubkey = crypto.randomBytes(33).toString('hex');
		try {
			await pm.connectPeer(pubkey, '127.0.0.1', 1);
		} catch {
			// expected: nothing listens on port 1; the address is still stored
		}
		pm.setAnnouncedAddresses(pubkey, [
			{ host: '127.0.0.1', port: 1 }, // duplicate of the stored address
			{ host: '203.0.113.7', port: 9735 }
		]);
		const internal = pm as unknown as {
			reconnectCandidates(
				pubkey: string
			): Array<{ host: string; port: number }>;
		};
		const candidates = internal.reconnectCandidates(pubkey);
		expect(
			candidates.map((c) => ({ host: c.host, port: c.port }))
		).to.deep.equal([
			{ host: '127.0.0.1', port: 1 },
			{ host: '203.0.113.7', port: 9735 }
		]);
		pm.destroy();
	});
});

// ── LightningNode: capture from node_announcement ──────────────────

describe('LightningNode: channel peer address capture', function () {
	interface IAnnouncedSave {
		pubkey: string;
		timestamp: number;
		addresses: Array<{ host: string; port: number }>;
	}

	function storageStub(recorded: {
		peerSaves: Array<{ pubkey: string; host: string; port: number }>;
		announcedSaves: IAnnouncedSave[];
	}): IStorageBackend {
		const stub: Partial<IStorageBackend> = {
			loadAllChannels: () => [],
			loadAllPayments: () => [],
			loadAllPreimages: () => [],
			loadAllScidMappings: () => [],
			loadAllHtlcPaymentMappings: () => [],
			loadAllForwardedHtlcs: () => [],
			loadAllPaymentSecrets: () => [],
			loadAllInvoices: () => [],
			loadMissionControl: () => null,
			loadAllChainMonitors: () => [],
			loadAllGossipChannels: () => [],
			loadAllGossipNodes: () => [],
			loadAllPeerAddresses: () => [...recorded.peerSaves],
			loadAllAnnouncedPeerAddresses: () => [...recorded.announcedSaves],
			loadMetadata: () => null,
			loadAllHtlcSharedSecrets: () => [],
			saveHtlcSharedSecret: () => {},
			deleteHtlcSharedSecret: () => {},
			savePeerAddress: (pubkey: string, host: string, port: number) => {
				recorded.peerSaves.push({ pubkey, host, port });
			},
			saveAnnouncedPeerAddresses: (
				pubkey: string,
				timestamp: number,
				addresses: Array<{ host: string; port: number }>
			) => {
				recorded.announcedSaves.push({ pubkey, timestamp, addresses });
			}
		};
		return stub as IStorageBackend;
	}

	interface ICaptureHarness {
		node: LightningNode;
		peerKey: Buffer;
		peerPub: string;
		recorded: {
			peerSaves: Array<{ pubkey: string; host: string; port: number }>;
			announcedSaves: IAnnouncedSave[];
		};
		announce(
			addresses: Array<{ type: number; host: string; port: number }>,
			timestamp: number
		): void;
		announced(): Array<{ host: string; port: number }>;
	}

	function makeCaptureHarness(): ICaptureHarness {
		const recorded = {
			peerSaves: [] as Array<{ pubkey: string; host: string; port: number }>,
			announcedSaves: [] as IAnnouncedSave[]
		};
		const node = makeNode({ storage: storageStub(recorded) });
		const peerKey = crypto.randomBytes(32);
		const peerPub = getPublicKey(peerKey).toString('hex');
		const internal = node as unknown as {
			channelPeerPubkeys(): Set<string>;
			handleNodeAnnouncement(payload: Buffer): void;
			peerManager: PeerManager;
		};
		internal.channelPeerPubkeys = (): Set<string> => new Set([peerPub]);
		return {
			node,
			peerKey,
			peerPub,
			recorded,
			announce: (addresses, timestamp): void =>
				internal.handleNodeAnnouncement(
					makeAnnouncement(peerKey, addresses, timestamp)
				),
			announced: (): Array<{ host: string; port: number }> =>
				internal.peerManager.getAnnouncedAddresses(peerPub)
		};
	}

	const ADDR_1 = { type: ADDRESS_TYPE_IPV4, host: '203.0.113.7', port: 9735 };
	const ADDR_2 = { type: ADDRESS_TYPE_IPV4, host: '203.0.113.8', port: 9735 };

	it('captures and persists a channel peer announcement the graph rejects', function () {
		const h = makeCaptureHarness();
		// The peer has no channels in the graph, so applyNodeAnnouncement
		// rejects this announcement; the capture path must still run.
		h.announce([ADDR_1], 1000);
		expect(h.announced()).to.deep.equal([{ host: '203.0.113.7', port: 9735 }]);
		// Persisted to the announced-address store with its timestamp, and
		// NEVER to peer_addresses: that store is reserved for addresses proven
		// by a successful outbound dial.
		expect(h.recorded.announcedSaves).to.deep.equal([
			{
				pubkey: h.peerPub,
				timestamp: 1000,
				addresses: [{ host: '203.0.113.7', port: 9735 }]
			}
		]);
		expect(h.recorded.peerSaves).to.deep.equal([]);

		// A newer announcement supersedes, in memory and in storage.
		h.announce([ADDR_2], 2000);
		expect(h.announced()).to.deep.equal([{ host: '203.0.113.8', port: 9735 }]);
		expect(h.recorded.announcedSaves.length).to.equal(2);
		expect(h.recorded.announcedSaves[1].timestamp).to.equal(2000);
		expect(h.recorded.peerSaves).to.deep.equal([]);
		h.node.destroy();
	});

	it('ignores an older valid node_announcement', function () {
		const h = makeCaptureHarness();
		h.announce([ADDR_2], 2000);
		// Validly signed but stale: a replay must not regress the addresses.
		h.announce([ADDR_1], 1000);
		expect(h.announced()).to.deep.equal([{ host: '203.0.113.8', port: 9735 }]);
		expect(h.recorded.announcedSaves.length).to.equal(1);
		h.node.destroy();
	});

	it('ignores a duplicate timestamp', function () {
		const h = makeCaptureHarness();
		h.announce([ADDR_1], 1000);
		h.announce([ADDR_2], 1000);
		expect(h.announced()).to.deep.equal([{ host: '203.0.113.7', port: 9735 }]);
		expect(h.recorded.announcedSaves.length).to.equal(1);
		h.node.destroy();
	});

	it('a newer announcement with no usable addresses clears the fallbacks', function () {
		const h = makeCaptureHarness();
		h.announce([ADDR_1], 1000);
		expect(h.announced().length).to.equal(1);
		// The peer withdraws its addresses: the newest signed announcement
		// supersedes down to an empty list.
		h.announce([], 2000);
		expect(h.announced()).to.deep.equal([]);
		expect(h.recorded.announcedSaves[1]).to.deep.equal({
			pubkey: h.peerPub,
			timestamp: 2000,
			addresses: []
		});
		h.node.destroy();
	});

	it('ignores announcements from nodes we have no channel with', function () {
		const recorded = {
			peerSaves: [] as Array<{ pubkey: string; host: string; port: number }>,
			announcedSaves: [] as IAnnouncedSave[]
		};
		const node = makeNode({ storage: storageStub(recorded) });
		const peerKey = crypto.randomBytes(32);
		const internal = node as unknown as {
			handleNodeAnnouncement(payload: Buffer): void;
			peerManager: PeerManager;
		};
		internal.handleNodeAnnouncement(makeAnnouncement(peerKey, [ADDR_1], 1000));
		expect(
			internal.peerManager.getAnnouncedAddresses(
				getPublicKey(peerKey).toString('hex')
			)
		).to.deep.equal([]);
		expect(recorded.announcedSaves).to.deep.equal([]);
		expect(recorded.peerSaves).to.deep.equal([]);
		node.destroy();
	});
});

// ── SqliteStorage: announced peer address round-trip ───────────────

describe('SqliteStorage: announced peer addresses', function () {
	it('round-trips announced address sets, newest write wins', function () {
		const storage = new SqliteStorage(':memory:');
		storage.open();
		const pubkey = crypto.randomBytes(33).toString('hex');
		storage.saveAnnouncedPeerAddresses(pubkey, 1000, [
			{ host: '203.0.113.7', port: 9735 }
		]);
		storage.saveAnnouncedPeerAddresses(pubkey, 2000, []);
		expect(storage.loadAllAnnouncedPeerAddresses()).to.deep.equal([
			{ pubkey, timestamp: 2000, addresses: [] }
		]);
	});
});

// ── PeerManager: cross-dial race safety ────────────────────────────

describe('PeerManager: simultaneous cross-dial handling', function () {
	it('a stale close does not tear down the live replacement connection', function () {
		const pm = new PeerManager({
			localPrivateKey: crypto.randomBytes(32),
			autoReconnect: true
		});
		const pubkey = crypto.randomBytes(33).toString('hex');
		const internal = pm as unknown as {
			setupPeerListeners(pubkey: string, peer: unknown): void;
			peers: Map<string, unknown>;
		};
		const stale = new EventEmitter();
		internal.setupPeerListeners(pubkey, stale);
		const live = { marker: 'live', disconnect: (): void => {} };
		internal.peers.set(pubkey, live);
		let disconnects = 0;
		pm.on('peer:disconnect', () => disconnects++);

		// The stale instance closes after losing a cross-dial race. It must
		// not delete the live connection's bookkeeping or emit a spurious
		// peer:disconnect (which would also schedule a needless reconnect).
		stale.emit('close');
		expect(internal.peers.get(pubkey)).to.equal(live);
		expect(disconnects).to.equal(0);
		pm.destroy();
	});

	it('an outbound dial that loses the race to an inbound connection is discarded', async function () {
		this.timeout(20_000);
		const aKey = crypto.randomBytes(32);
		const bKey = crypto.randomBytes(32);
		const bPub = getPublicKey(bKey).toString('hex');
		const pmA = new PeerManager({ localPrivateKey: aKey });
		const pmB = new PeerManager({ localPrivateKey: bKey });
		try {
			await pmB.listen(0);
			const bPort = (
				pmB as unknown as { server: { address(): { port: number } } }
			).server.address().port;

			const aInternal = pmA as unknown as {
				dialPeer(pubkey: string, host: string, port: number): Promise<void>;
				peers: Map<string, unknown>;
			};
			let connects = 0;
			pmA.on('peer:connect', () => connects++);

			// Start the outbound handshake, then let an "inbound" connection
			// register for the same pubkey while it is in flight.
			const dial = aInternal.dialPeer(bPub, '127.0.0.1', bPort);
			const inboundWinner = {
				marker: 'inbound-winner',
				disconnect: (): void => {}
			};
			aInternal.peers.set(bPub, inboundWinner);
			await dial;

			// The completed inbound connection keeps its registration; the
			// outbound loser is torn down without a peer:connect.
			expect(aInternal.peers.get(bPub)).to.equal(inboundWinner);
			expect(connects).to.equal(0);
			// B observes the discarded outbound connection close.
			await waitFor(() => pmB.listPeers().length === 0);
		} finally {
			pmA.destroy();
			pmB.destroy();
		}
	});
});

// ── End to end: inbound channel peer self-recovers over TCP ────────

describe('inbound channel peer reconnects via its announced address', function () {
	it('redials the peer after it drops, using the node_announcement address', async function () {
		this.timeout(20_000);
		const aKey = crypto.randomBytes(32);
		const bKey = crypto.randomBytes(32);
		const aPub = getPublicKey(aKey).toString('hex');
		const bPub = getPublicKey(bKey).toString('hex');
		const a = makeNode({ privateKey: aKey });
		const b = makeNode({ privateKey: bKey });
		try {
			await a.listen(0);
			await b.listen(0);
			const aInternal = a as unknown as {
				channelPeerPubkeys(): Set<string>;
				handleNodeAnnouncement(payload: Buffer): void;
				peerManager: PeerManager;
			};
			const listenPort = (node: LightningNode): number =>
				(
					node as unknown as {
						peerManager: { server: { address(): { port: number } } };
					}
				).peerManager.server.address().port;
			const aPort = listenPort(a);
			const bPort = listenPort(b);

			// B dials A: from A's side B is inbound, so A stores no address.
			await b.connectPeer(aPub, '127.0.0.1', aPort);
			await waitFor(() => aInternal.peerManager.listPeers().length === 1);
			expect(aInternal.peerManager.getPeerAddress(bPub)).to.equal(undefined);

			// A treats B as a channel peer and receives B's node_announcement.
			aInternal.channelPeerPubkeys = (): Set<string> => new Set([bPub]);
			aInternal.handleNodeAnnouncement(
				makeAnnouncement(bKey, [
					{ type: ADDRESS_TYPE_IPV4, host: '127.0.0.1', port: bPort }
				])
			);
			expect(aInternal.peerManager.getAnnouncedAddresses(bPub).length).to.equal(
				1
			);

			// B drops the connection. A must self-recover by dialing the
			// announced address (initial backoff ~1s).
			b.disconnectPeer(aPub);
			await waitFor(() => aInternal.peerManager.listPeers().length === 0);
			await waitFor(
				() =>
					aInternal.peerManager.listPeers().length === 1 &&
					aInternal.peerManager.getPeerAddress(bPub) !== undefined
			);
			// The successful dial promotes the announced address to
			// last-known-good, so it also persists across future drops.
			expect(aInternal.peerManager.getPeerAddress(bPub)).to.deep.include({
				host: '127.0.0.1',
				port: bPort
			});
		} finally {
			a.destroy();
			b.destroy();
		}
	});
});
