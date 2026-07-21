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
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { PeerManager } from '../../src/lightning/transport/peer-manager';
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
	function storageStub(
		saved: Array<{ pubkey: string; host: string; port: number }>
	): IStorageBackend {
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
			loadAllPeerAddresses: () => [...saved],
			loadMetadata: () => null,
			loadAllHtlcSharedSecrets: () => [],
			saveHtlcSharedSecret: () => {},
			deleteHtlcSharedSecret: () => {},
			savePeerAddress: (pubkey: string, host: string, port: number) => {
				saved.push({ pubkey, host, port });
			}
		};
		return stub as IStorageBackend;
	}

	it('captures and persists a channel peer announcement the graph rejects', function () {
		const saved: Array<{ pubkey: string; host: string; port: number }> = [];
		const node = makeNode({ storage: storageStub(saved) });
		const peerKey = crypto.randomBytes(32);
		const peerPub = getPublicKey(peerKey).toString('hex');
		const internal = node as unknown as {
			channelPeerPubkeys(): Set<string>;
			handleNodeAnnouncement(payload: Buffer): void;
			peerManager: PeerManager;
		};
		internal.channelPeerPubkeys = (): Set<string> => new Set([peerPub]);

		// The peer has no channels in the graph, so applyNodeAnnouncement
		// rejects this announcement; the capture path must still run.
		internal.handleNodeAnnouncement(
			makeAnnouncement(peerKey, [
				{ type: ADDRESS_TYPE_IPV4, host: '203.0.113.7', port: 9735 }
			])
		);

		expect(internal.peerManager.getAnnouncedAddresses(peerPub)).to.deep.equal([
			{ host: '203.0.113.7', port: 9735 }
		]);
		expect(saved).to.deep.equal([
			{ pubkey: peerPub, host: '203.0.113.7', port: 9735 }
		]);

		// A second announcement must not clobber the persisted address:
		// the stored entry now stands in for a last-known-good address.
		internal.handleNodeAnnouncement(
			makeAnnouncement(
				peerKey,
				[{ type: ADDRESS_TYPE_IPV4, host: '203.0.113.8', port: 9735 }],
				Math.floor(Date.now() / 1000) + 60
			)
		);
		expect(saved.length).to.equal(1);
		// ...but the in-memory fallbacks do follow the newest announcement.
		expect(internal.peerManager.getAnnouncedAddresses(peerPub)).to.deep.equal([
			{ host: '203.0.113.8', port: 9735 }
		]);
		node.destroy();
	});

	it('ignores announcements from nodes we have no channel with', function () {
		const saved: Array<{ pubkey: string; host: string; port: number }> = [];
		const node = makeNode({ storage: storageStub(saved) });
		const peerKey = crypto.randomBytes(32);
		const internal = node as unknown as {
			handleNodeAnnouncement(payload: Buffer): void;
			peerManager: PeerManager;
		};
		internal.handleNodeAnnouncement(
			makeAnnouncement(peerKey, [
				{ type: ADDRESS_TYPE_IPV4, host: '203.0.113.7', port: 9735 }
			])
		);
		expect(
			internal.peerManager.getAnnouncedAddresses(
				getPublicKey(peerKey).toString('hex')
			)
		).to.deep.equal([]);
		expect(saved).to.deep.equal([]);
		node.destroy();
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
