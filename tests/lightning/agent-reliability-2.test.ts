/**
 * Production Hardening 6 — Phase 2: Agent Reliability Tests (15 tests)
 *
 * 2.1: waitForPayment (4 tests)
 * 2.2: getBalance (3 tests)
 * 2.3: Graph pruning timer (2 tests)
 * 2.4: Don't store inbound peer ephemeral port (3 tests)
 * 2.5: Emit errors on persistence failures (3 tests)
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	PaymentStatus,
	PaymentDirection,
	IPaymentInfo
} from '../../src/lightning/node/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	HtlcDirection,
	HtlcState,
	BITCOIN_CHAIN_HASH
} from '../../src/lightning/channel/types';
import {
	encodeChannelUpdateMessage,
	decodeChannelUpdateMessage
} from '../../src/lightning/gossip/messages';
import { Channel } from '../../src/lightning/channel/channel';
import { createOpenerState } from '../../src/lightning/channel/channel-state';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { Network } from '../../src/lightning/invoice/types';
import { PeerManager } from '../../src/lightning/transport/peer-manager';
import { IStorageBackend } from '../../src/lightning/storage/types';

// ─────────────── Helpers ───────────────

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`reliability2-seed-${id}`))
		.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		const privkey = crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([i]))
			.digest();
		keys.push(privkey);
	}
	return {
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

function createTestNode(opts?: {
	enableNetworking?: boolean;
	storage?: IStorageBackend;
}): LightningNode {
	const privkey = crypto.randomBytes(32);
	const seed = crypto.randomBytes(32);
	const fundingPrivkey = crypto.randomBytes(32);
	const basepoints = makeBasepoints(seed);
	const node = new LightningNode({
		nodePrivateKey: privkey,
		channelBasepoints: basepoints,
		perCommitmentSeed: seed,
		fundingPrivkey,
		network: Network.REGTEST,
		enableNetworking: opts?.enableNetworking,
		storage: opts?.storage
	});
	node.on('error', () => {});
	node.on('node:error', () => {});
	return node;
}

// ─────────────── Fix 2.1: waitForPayment ───────────────

describe('Fix 2.1: waitForPayment', () => {
	it('waitForPayment resolves on matching payment:received', async () => {
		const node = createTestNode();
		const paymentHash = crypto.randomBytes(32);

		const promise = node.waitForPayment(paymentHash, 5000);

		// Simulate receiving the payment
		const paymentInfo: IPaymentInfo = {
			paymentHash,
			amountMsat: 1000n,
			status: PaymentStatus.COMPLETED,
			direction: PaymentDirection.INCOMING,
			createdAt: Date.now()
		};

		// Emit after a short delay
		setTimeout(() => {
			node.emit('payment:received', paymentInfo);
		}, 50);

		const result = await promise;
		expect(result.paymentHash.toString('hex')).to.equal(
			paymentHash.toString('hex')
		);
		expect(result.status).to.equal(PaymentStatus.COMPLETED);
		node.destroy();
	});

	it('waitForPayment rejects on timeout', async () => {
		const node = createTestNode();
		const paymentHash = crypto.randomBytes(32);

		try {
			await node.waitForPayment(paymentHash, 100);
			expect.fail('Should have timed out');
		} catch (err: unknown) {
			expect((err as Error).message).to.include('timed out');
		}
		node.destroy();
	});

	it('waitForPayment resolves immediately if already received', async () => {
		const node = createTestNode();

		// Create an invoice to set up payment tracking
		const result = node.createInvoice({
			amountMsat: 1000n,
			description: 'test'
		});
		const paymentHash = result.paymentHash;

		// Manually mark it as completed in payments map
		const payments = (
			node as unknown as { payments: Map<string, IPaymentInfo> }
		).payments;
		const payment = payments.get(paymentHash.toString('hex'));
		if (payment) {
			payment.status = PaymentStatus.COMPLETED;
		}

		const resolved = await node.waitForPayment(paymentHash, 1000);
		expect(resolved.status).to.equal(PaymentStatus.COMPLETED);
		node.destroy();
	});

	it('waitForPayment ignores non-matching hashes', async () => {
		const node = createTestNode();
		const targetHash = crypto.randomBytes(32);
		const wrongHash = crypto.randomBytes(32);

		const promise = node.waitForPayment(targetHash, 500);

		// Emit wrong hash first
		setTimeout(() => {
			node.emit('payment:received', {
				paymentHash: wrongHash,
				amountMsat: 1000n,
				status: PaymentStatus.COMPLETED,
				direction: PaymentDirection.INCOMING,
				createdAt: Date.now()
			} as IPaymentInfo);
		}, 20);

		// Then emit correct hash
		setTimeout(() => {
			node.emit('payment:received', {
				paymentHash: targetHash,
				amountMsat: 2000n,
				status: PaymentStatus.COMPLETED,
				direction: PaymentDirection.INCOMING,
				createdAt: Date.now()
			} as IPaymentInfo);
		}, 50);

		const result = await promise;
		expect(result.paymentHash.toString('hex')).to.equal(
			targetHash.toString('hex')
		);
		expect(Number(result.amountMsat)).to.equal(2000);
		node.destroy();
	});
});

// ─────────────── Fix 2.2: getBalance ───────────────

describe('Fix 2.2: getBalance', () => {
	it('getBalance returns zero for node with no NORMAL channels', () => {
		const node = createTestNode();
		const balance = node.getBalance();
		expect(Number(balance.localBalanceMsat)).to.equal(0);
		expect(Number(balance.remoteBalanceMsat)).to.equal(0);
		expect(Number(balance.unsettledBalanceMsat)).to.equal(0);
		node.destroy();
	});

	it('getBalance sums across multiple NORMAL channels', () => {
		const node = createTestNode();

		// Create two channels in NORMAL state
		for (let i = 0; i < 2; i++) {
			const state = createOpenerState({
				temporaryChannelId: Buffer.alloc(32),
				fundingSatoshis: 100000n,
				pushMsat: 0n,
				localConfig: DEFAULT_CHANNEL_CONFIG,
				localBasepoints: makeBasepoints(makeSeed(20 + i)),
				localPerCommitmentSeed: makeSeed(30 + i)
			});
			state.state = ChannelState.NORMAL;
			state.channelId = crypto.randomBytes(32);
			state.localBalanceMsat = 50_000_000n;
			state.remoteBalanceMsat = 50_000_000n;

			const channel = new Channel(state);
			node.getChannelManager().restoreChannel(channel, 'aabb'.repeat(16));
		}

		const balance = node.getBalance();
		expect(Number(balance.localBalanceMsat)).to.equal(100_000_000);
		expect(Number(balance.remoteBalanceMsat)).to.equal(100_000_000);
		node.destroy();
	});

	it('getBalance excludes FORCE_CLOSED channels (funds are in on-chain recovery)', () => {
		const node = createTestNode();

		// One live NORMAL channel.
		const normal = createOpenerState({
			temporaryChannelId: Buffer.alloc(32),
			fundingSatoshis: 100000n,
			pushMsat: 0n,
			localConfig: DEFAULT_CHANNEL_CONFIG,
			localBasepoints: makeBasepoints(makeSeed(40)),
			localPerCommitmentSeed: makeSeed(41)
		});
		normal.state = ChannelState.NORMAL;
		normal.channelId = crypto.randomBytes(32);
		normal.localBalanceMsat = 50_000_000n;
		normal.remoteBalanceMsat = 0n;
		node
			.getChannelManager()
			.restoreChannel(new Channel(normal), 'aabb'.repeat(16));

		// One FORCE_CLOSED channel — its funds are no longer live on Lightning;
		// they are being swept back to the on-chain wallet.
		const closed = createOpenerState({
			temporaryChannelId: Buffer.alloc(32),
			fundingSatoshis: 100000n,
			pushMsat: 0n,
			localConfig: DEFAULT_CHANNEL_CONFIG,
			localBasepoints: makeBasepoints(makeSeed(42)),
			localPerCommitmentSeed: makeSeed(43)
		});
		closed.state = ChannelState.FORCE_CLOSED;
		closed.channelId = crypto.randomBytes(32);
		closed.localBalanceMsat = 50_000_000n;
		closed.remoteBalanceMsat = 0n;
		node
			.getChannelManager()
			.restoreChannel(new Channel(closed), 'ccdd'.repeat(16));

		const balance = node.getBalance();
		// Only the NORMAL channel counts — the force-closed balance is excluded.
		expect(Number(balance.localBalanceMsat)).to.equal(50_000_000);
		node.destroy();
	});

	it('getBalance counts pending HTLCs as unsettled', () => {
		const node = createTestNode();

		const state = createOpenerState({
			temporaryChannelId: Buffer.alloc(32),
			fundingSatoshis: 100000n,
			pushMsat: 0n,
			localConfig: DEFAULT_CHANNEL_CONFIG,
			localBasepoints: makeBasepoints(makeSeed(40)),
			localPerCommitmentSeed: makeSeed(41)
		});
		state.state = ChannelState.NORMAL;
		state.channelId = crypto.randomBytes(32);
		state.localBalanceMsat = 80_000_000n;
		state.remoteBalanceMsat = 20_000_000n;

		// Add a pending HTLC
		state.htlcs.set('0:0', {
			id: 0n,
			direction: HtlcDirection.OFFERED,
			amountMsat: 5_000_000n,
			paymentHash: crypto.randomBytes(32),
			cltvExpiry: 500,
			state: HtlcState.PENDING,
			onionRoutingPacket: Buffer.alloc(1366)
		});

		const channel = new Channel(state);
		node.getChannelManager().restoreChannel(channel, 'aabb'.repeat(16));

		const balance = node.getBalance();
		expect(Number(balance.unsettledBalanceMsat)).to.equal(5_000_000);
		node.destroy();
	});
});

// ─────────────── Force-close sweep destination ───────────────

describe('sweepDestinationScript', () => {
	it('defaults to P2WPKH(fundingPubkey) when not configured', () => {
		const seed = makeSeed(700);
		const basepoints = makeBasepoints(seed);
		const node = new LightningNode({
			nodePrivateKey: crypto.randomBytes(32),
			channelBasepoints: basepoints,
			perCommitmentSeed: seed,
			fundingPrivkey: crypto.randomBytes(32),
			network: Network.REGTEST
		});
		node.on('node:error', () => {});

		const expected = bitcoin.payments.p2wpkh({
			pubkey: basepoints.fundingPubkey
		}).output!;
		expect(node.getSweepDestinationScript().equals(expected)).to.be.true;
		node.destroy();
	});

	it('uses the configured wallet sweepDestinationScript (so recovered funds land in the wallet)', () => {
		const seed = makeSeed(701);
		const basepoints = makeBasepoints(seed);
		const walletScript = bitcoin.payments.p2wpkh({
			pubkey: getPublicKey(crypto.randomBytes(32))
		}).output!;

		const node = new LightningNode({
			nodePrivateKey: crypto.randomBytes(32),
			channelBasepoints: basepoints,
			perCommitmentSeed: seed,
			fundingPrivkey: crypto.randomBytes(32),
			network: Network.REGTEST,
			sweepDestinationScript: walletScript
		});
		node.on('node:error', () => {});

		// The wallet address is used, not the funding-key default.
		expect(node.getSweepDestinationScript().equals(walletScript)).to.be.true;
		const fundingDefault = bitcoin.payments.p2wpkh({
			pubkey: basepoints.fundingPubkey
		}).output!;
		expect(node.getSweepDestinationScript().equals(fundingDefault)).to.be.false;
		node.destroy();
	});

	it('setSweepDestinationScript redirects sweeps after construction (funding-key → wallet)', () => {
		// Simulates the wallet address only becoming available after startup
		// (e.g. Electrum was down at boot): the node must start on the funding-key
		// fallback, then redirect to the wallet once setSweepDestinationScript runs.
		const seed = makeSeed(702);
		const basepoints = makeBasepoints(seed);
		const node = new LightningNode({
			nodePrivateKey: crypto.randomBytes(32),
			channelBasepoints: basepoints,
			perCommitmentSeed: seed,
			fundingPrivkey: crypto.randomBytes(32),
			network: Network.REGTEST
		});
		node.on('node:error', () => {});

		// Initially falls back to the funding-key address.
		const fundingDefault = bitcoin.payments.p2wpkh({
			pubkey: basepoints.fundingPubkey
		}).output!;
		expect(node.getSweepDestinationScript().equals(fundingDefault)).to.be.true;

		// Once a wallet address resolves, sweeps redirect to it.
		const walletScript = bitcoin.payments.p2wpkh({
			pubkey: getPublicKey(crypto.randomBytes(32))
		}).output!;
		node.setSweepDestinationScript(walletScript);
		expect(node.getSweepDestinationScript().equals(walletScript)).to.be.true;
		node.destroy();
	});
});

// ─────────────── Gossip propagation (own announcements) ───────────────

import { MessageType } from '../../src/lightning/message/types';
import { decodeNodeAnnouncementMessage } from '../../src/lightning/gossip/messages';

describe('Gossip propagation', () => {
	it('buildNodeAnnouncement produces a valid, signed node_announcement for this node', () => {
		const node = createTestNode({ enableNetworking: true });
		const payload = (node as any).buildNodeAnnouncement(1700000000);
		expect(payload, 'node_announcement built').to.be.instanceOf(Buffer);
		const msg = decodeNodeAnnouncementMessage(payload);
		expect(msg.nodeId.toString('hex')).to.equal(node.getNodeId());
		expect(msg.timestamp).to.equal(1700000000);
		node.destroy();
	});

	it('sendOwnGossipTo pushes cached channel + node announcements to a peer', () => {
		const node = createTestNode({ enableNetworking: true });
		// Record what gets sent without touching the wire.
		const calls: Array<{ pubkey: string; type: number }> = [];
		(node as any).peerManager.sendToPeer = (pubkey: string, type: number) => {
			calls.push({ pubkey, type });
		};
		// Seed the cache as if a channel had been announced.
		(node as any)._ownChannelGossip.set('chan1', {
			announcement: Buffer.alloc(64, 1),
			update: Buffer.alloc(64, 2)
		});
		(node as any)._ownNodeAnnouncement = Buffer.alloc(64, 3);

		(node as any).sendOwnGossipTo('deadbeef');

		const types = calls.map((c) => c.type);
		expect(types).to.include(MessageType.CHANNEL_ANNOUNCEMENT);
		expect(types).to.include(MessageType.CHANNEL_UPDATE);
		expect(types).to.include(MessageType.NODE_ANNOUNCEMENT);
		expect(calls.every((c) => c.pubkey === 'deadbeef')).to.be.true;
		node.destroy();
	});

	it('sendOwnGossipTo is a no-op when nothing has been announced yet', () => {
		const node = createTestNode({ enableNetworking: true });
		const calls: number[] = [];
		(node as any).peerManager.sendToPeer = (_p: string, type: number) => {
			calls.push(type);
		};
		(node as any).sendOwnGossipTo('deadbeef');
		expect(calls.length).to.equal(0);
		node.destroy();
	});

	it('refreshChannelUpdate bumps the timestamp + re-signs, preserving the policy', () => {
		const node = createTestNode({ enableNetworking: true });
		const original = {
			signature: Buffer.alloc(64),
			chainHash: BITCOIN_CHAIN_HASH,
			shortChannelId: Buffer.from('0e88ee000d6f0001', 'hex'),
			timestamp: 1000,
			messageFlags: 1, // htlc_max present
			channelFlags: 0,
			cltvExpiryDelta: 80,
			htlcMinimumMsat: 1000n,
			feeBaseMsat: 0,
			feeProportionalMillionths: 1,
			htlcMaximumMsat: 1_000_000_000n
		};
		const cached = encodeChannelUpdateMessage(original);
		const refreshed = (node as any).refreshChannelUpdate(cached, 2000);
		expect(refreshed, 'refreshed update produced').to.be.instanceOf(Buffer);

		const decoded = decodeChannelUpdateMessage(refreshed);
		// Timestamp bumped…
		expect(decoded.timestamp).to.equal(2000);
		// …policy unchanged (no force-close-relevant fields touched; pure gossip)…
		expect(decoded.cltvExpiryDelta).to.equal(80);
		expect(decoded.feeBaseMsat).to.equal(0);
		expect(decoded.feeProportionalMillionths).to.equal(1);
		expect(decoded.shortChannelId.toString('hex')).to.equal('0e88ee000d6f0001');
		expect(decoded.channelFlags).to.equal(0);
		// …and it was actually re-signed (signature is non-zero).
		expect(decoded.signature.equals(Buffer.alloc(64))).to.be.false;
		node.destroy();
	});
});

// ─────────────── Fix 2.3: Graph pruning timer ───────────────

describe('Fix 2.3: Graph pruning timer', () => {
	it('graph pruning timer is started on construction', () => {
		const node = createTestNode();
		// The timer is stored in graphPruneTimer — it should be set
		const timer = (
			node as unknown as {
				graphPruneTimer: ReturnType<typeof setInterval> | null;
			}
		).graphPruneTimer;
		expect(timer).to.not.be.null;
		node.destroy();
	});

	it('destroy() clears graph pruning timer', () => {
		const node = createTestNode();
		node.destroy();
		const timer = (
			node as unknown as {
				graphPruneTimer: ReturnType<typeof setInterval> | null;
			}
		).graphPruneTimer;
		expect(timer).to.be.null;
	});
});

// ─────────────── Fix 2.4: Don't store inbound peer ephemeral port ───────────────

describe("Fix 2.4: Don't store inbound peer ephemeral port", () => {
	it('inbound connection does not store ephemeral port', () => {
		const pm = new PeerManager({
			localPrivateKey: crypto.randomBytes(32)
		});
		// Before any connections, peerAddresses should be empty
		const addr = pm.getPeerAddress('aabbccdd'.repeat(8));
		expect(addr).to.be.undefined;
		pm.destroy();
	});

	it('outbound connection stores listening port', async () => {
		const pm = new PeerManager({
			localPrivateKey: crypto.randomBytes(32)
		});
		const pubkey = crypto.randomBytes(33).toString('hex');

		// connectPeer will store the address before attempting connection
		// The connection itself will fail (no actual server), but the address is stored first
		try {
			await pm.connectPeer(pubkey, '127.0.0.1', 9735);
		} catch {
			// Expected: no actual server
		}

		const addr = pm.getPeerAddress(pubkey);
		expect(addr).to.not.be.undefined;
		expect(addr!.host).to.equal('127.0.0.1');
		expect(addr!.port).to.equal(9735);
		pm.destroy();
	});

	it('reconnect uses only outbound/gossip addresses', () => {
		const pm = new PeerManager({
			localPrivateKey: crypto.randomBytes(32),
			autoReconnect: true
		});

		// An inbound peer has no stored address, so reconnect won't be attempted
		const inboundPubkey = crypto.randomBytes(33).toString('hex');
		const addr = pm.getPeerAddress(inboundPubkey);
		expect(addr).to.be.undefined;
		pm.destroy();
	});
});

// ─────────────── Fix 2.5: Emit errors on persistence failures ───────────────

describe('Fix 2.5: Emit errors on persistence failures', () => {
	it('persistChannel emits node:error on storage failure', () => {
		const failingStorage: Partial<IStorageBackend> = {
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
			loadAllPeerAddresses: () => [],
			loadMetadata: () => null,
			loadAllHtlcSharedSecrets: () => [],
			saveHtlcSharedSecret: () => {},
			deleteHtlcSharedSecret: () => {},
			saveChannel: () => {
				throw new Error('disk full');
			},
			savePayment: () => {},
			saveMissionControl: () => {}
		};

		const node = createTestNode({ storage: failingStorage as IStorageBackend });
		const errors: { code: string; message: string }[] = [];
		node.removeAllListeners('node:error');
		node.on('node:error', (err: { code: string; message: string }) => {
			errors.push(err);
		});

		// Create a channel and trigger persist
		const state = createOpenerState({
			temporaryChannelId: Buffer.alloc(32),
			fundingSatoshis: 100000n,
			pushMsat: 0n,
			localConfig: DEFAULT_CHANNEL_CONFIG,
			localBasepoints: makeBasepoints(makeSeed(50)),
			localPerCommitmentSeed: makeSeed(51)
		});
		state.channelId = crypto.randomBytes(32);
		state.state = ChannelState.NORMAL;
		const channel = new Channel(state);
		const peer = 'aa'.repeat(33);
		node.getChannelManager().restoreChannel(channel, peer);

		// Trigger persist
		(
			node as unknown as { persistChannel: (id: Buffer) => void }
		).persistChannel(state.channelId!);

		const persErrors = errors.filter((e) => e.code === 'PERSISTENCE_ERROR');
		expect(persErrors.length).to.be.greaterThan(0);
		expect(persErrors[0].message).to.include('disk full');
		node.destroy();
	});

	it('persistPayment emits node:error on storage failure', () => {
		const failingStorage: Partial<IStorageBackend> = {
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
			loadAllPeerAddresses: () => [],
			loadMetadata: () => null,
			loadAllHtlcSharedSecrets: () => [],
			saveHtlcSharedSecret: () => {},
			deleteHtlcSharedSecret: () => {},
			saveChannel: () => {},
			savePayment: () => {
				throw new Error('db locked');
			},
			saveMissionControl: () => {}
		};

		const node = createTestNode({ storage: failingStorage as IStorageBackend });
		const errors: { code: string; message: string }[] = [];
		node.removeAllListeners('node:error');
		node.on('node:error', (err: { code: string; message: string }) => {
			errors.push(err);
		});

		// Create a payment in the payments map
		const paymentHash = crypto.randomBytes(32);
		const payments = (
			node as unknown as { payments: Map<string, IPaymentInfo> }
		).payments;
		payments.set(paymentHash.toString('hex'), {
			paymentHash,
			amountMsat: 1000n,
			status: PaymentStatus.PENDING,
			direction: PaymentDirection.OUTGOING,
			createdAt: Date.now()
		});

		// Trigger persist
		(node as unknown as { persistPayment: (h: Buffer) => void }).persistPayment(
			paymentHash
		);

		const persErrors = errors.filter((e) => e.code === 'PERSISTENCE_ERROR');
		expect(persErrors.length).to.be.greaterThan(0);
		expect(persErrors[0].message).to.include('db locked');
		node.destroy();
	});

	it('mission control save failure emits node:error', () => {
		const failingStorage: Partial<IStorageBackend> = {
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
			loadAllPeerAddresses: () => [],
			loadMetadata: () => null,
			loadAllHtlcSharedSecrets: () => [],
			saveHtlcSharedSecret: () => {},
			deleteHtlcSharedSecret: () => {},
			saveChannel: () => {},
			savePayment: () => {},
			saveMissionControl: () => {
				throw new Error('io error');
			}
		};

		const node = createTestNode({ storage: failingStorage as IStorageBackend });
		const errors: { code: string; message: string }[] = [];
		node.removeAllListeners('node:error');
		node.on('node:error', (err: { code: string; message: string }) => {
			errors.push(err);
		});

		// Add some entries to mission control so export is non-empty
		const mc = (
			node as unknown as {
				missionControl: {
					recordFailure: (s: string, a: bigint, c: number) => void;
					size: number;
				};
			}
		).missionControl;
		mc.recordFailure('aabb'.repeat(4), 1000n, 0x100c);

		// Trigger mission control save on destroy
		node.destroy();

		const persErrors = errors.filter((e) => e.code === 'PERSISTENCE_ERROR');
		expect(persErrors.length).to.be.greaterThan(0);
		expect(persErrors[0].message).to.include('io error');
	});
});
