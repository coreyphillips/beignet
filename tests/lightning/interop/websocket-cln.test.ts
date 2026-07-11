/**
 * Interop Tests: Beignet ↔ CLN over WebSocket transport (regtest)
 *
 * CLN accepts BOLT 8 peers over RFC 6455 WebSocket when configured with
 * `bind-addr=ws:0.0.0.0:19847` (docker/docker-compose.yml cln service).
 * These tests prove beignet's WS client transport against a real CLN node:
 *
 * - WS-1: Noise handshake + BOLT 1 init exchange over ws://
 * - WS-2: BOLT 1 ping/pong keepalive over the WS link
 * - WS-3: channel open to NORMAL, then a payment in each direction
 * - WS-4: disconnect + reestablish over WS
 *
 * All tests auto-skip if Docker/CLN is not running.
 * Run: docker compose -f docker/docker-compose.yml up -d
 */

import { expect } from 'chai';
import { ClnRestClient } from './cln-client';
import {
	isClnAvailable,
	createClnClient,
	waitForClnSync,
	waitForClnPeerChannelNormal,
	mineBlocks,
	fundClnWallet,
	createInteropNode,
	setupRoutingForChannel,
	sleep,
	CLN_P2P_HOST
} from './cln-helpers';
import { LightningNode } from '../../../src/lightning/node/lightning-node';
import { Peer } from '../../../src/lightning/transport/peer';
import {
	connectWebSocket,
	WebSocketTransport
} from '../../../src/lightning/transport/websocket';
import { NodeWebSocket } from '../../../src/lightning/transport/websocket-node-client';
import { FeatureFlags, Feature } from '../../../src/lightning/features/flags';
import { REGTEST_CHAIN_HASH } from '../../../src/lightning/channel/types';
import { Network } from '../../../src/lightning/invoice/types';
import {
	deriveLightningKeysFromMnemonic,
	LnCoinType
} from '../../../src/lightning/keys/wallet-keys';
import {
	TEST_MNEMONIC,
	bitcoinRpc,
	ensureBitcoindFunds,
	BitcoindFundingProvider
} from './shared-helpers';
import { PaymentStatus } from '../../../src/lightning/node/types';

/** CLN WebSocket listener (bind-addr=ws:0.0.0.0:19847 in docker-compose). */
export const CLN_WS_PORT = 19847;

async function waitFor(
	cond: () => boolean | Promise<boolean>,
	timeoutMs: number,
	label: string
): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	for (;;) {
		if (await cond()) return;
		if (Date.now() > deadline) {
			throw new Error(`Timed out waiting for ${label}`);
		}
		await sleep(500);
	}
}

/**
 * Open a CLN-funded channel to a beignet node connected over WS and wait
 * for NORMAL on both sides. Mirrors setupClnChannel but dials ws://.
 */
async function setupClnChannelOverWs(
	cln: ClnRestClient,
	clnPubkey: string,
	seedId: number,
	fundingAmount: number,
	pushMsat: number
): Promise<{ node: LightningNode; channelId: Buffer }> {
	const node = createInteropNode(seedId);
	node.on('node:error', () => {
		/* absorb */
	});

	await fundClnWallet(cln);
	await node.connectPeer(clnPubkey, CLN_P2P_HOST, CLN_WS_PORT, {
		type: 'ws'
	});

	await cln.fundChannel(node.getNodeId(), fundingAmount, pushMsat);
	await mineBlocks(6);
	await sleep(3000);

	const channelManager = node.getChannelManager();
	await waitFor(
		() => channelManager.listChannels().length > 0,
		30_000,
		'beignet channel object'
	);
	const channelId = channelManager.listChannels()[0].getChannelId();
	if (!channelId) throw new Error('Channel has no channelId after open');
	node.handleFundingConfirmed(channelId);

	await waitForClnPeerChannelNormal(cln, node.getNodeId(), 60_000);
	await waitFor(
		() => channelManager.getChannel(channelId)?.getState() === 'NORMAL',
		30_000,
		'beignet channel NORMAL'
	);
	return { node, channelId };
}

/**
 * Beignet-funded channel to CLN over WS (mirrors
 * setupBeignetFundedClnChannel). Used for the bidirectional-payment tier:
 * with beignet as funder, CLN never sends update_fee, sidestepping a
 * pre-existing (transport-independent) commit_sig desync that hits
 * CLN-funded channels after CLN's update_fee — see the cln-interop Tier 4
 * comments; reproduced identically over plain TCP on master.
 */
async function setupBeignetFundedChannelOverWs(
	cln: ClnRestClient,
	clnPubkey: string,
	seedId: number,
	fundingAmount = 500_000n
): Promise<{ node: LightningNode; channelId: Buffer }> {
	await ensureBitcoindFunds(2.0);
	const keys = deriveLightningKeysFromMnemonic(
		TEST_MNEMONIC,
		`interop-seed-${seedId}`,
		LnCoinType.REGTEST
	);
	const features = FeatureFlags.empty();
	features.setOptional(Feature.DATA_LOSS_PROTECT);
	features.setOptional(Feature.STATIC_REMOTE_KEY);
	features.setOptional(Feature.PAYMENT_SECRET);
	features.setOptional(Feature.TLV_ONION);
	features.setOptional(Feature.CHANNEL_TYPE);
	features.setOptional(Feature.GOSSIP_QUERIES);
	features.setOptional(Feature.ANCHOR_ZERO_FEE_HTLC);
	const node = new LightningNode({
		nodePrivateKey: keys.nodePrivateKey,
		channelBasepoints: keys.channelBasepoints,
		perCommitmentSeed: keys.perCommitmentSeed,
		fundingPrivkey: keys.fundingPrivkey,
		htlcBasepointSecret: keys.htlcBasepointSecret,
		network: Network.REGTEST,
		enableNetworking: true,
		localFeatures: features,
		chainHashes: [REGTEST_CHAIN_HASH],
		preferAnchors: true,
		fundingProvider: new BitcoindFundingProvider()
	});
	node.on('node:error', () => {
		/* absorb */
	});

	await fundClnWallet(cln);
	await node.connectPeer(clnPubkey, CLN_P2P_HOST, CLN_WS_PORT, {
		type: 'ws'
	});
	await sleep(2000);

	node.openChannel(clnPubkey, fundingAmount);
	const channelManager = node.getChannelManager();
	await waitFor(
		() => channelManager.listChannels().length > 0,
		30_000,
		'beignet channel object (funded open)'
	);
	// Give the auto-funding flow a moment to broadcast before confirming
	await sleep(3000);
	await mineBlocks(6);
	await sleep(3000);
	const channelId = channelManager.listChannels()[0].getChannelId();
	if (!channelId) throw new Error('Channel has no channelId after open');
	node.handleFundingConfirmed(channelId);

	// CLN's lock-in detection under Docker is slow; keep nudging with blocks
	for (let i = 0; i < 12; i++) {
		try {
			await waitForClnPeerChannelNormal(cln, node.getNodeId(), 5_000);
			break;
		} catch {
			await mineBlocks(1);
		}
	}
	await waitForClnPeerChannelNormal(cln, node.getNodeId(), 30_000);
	await waitFor(
		() => channelManager.getChannel(channelId)?.getState() === 'NORMAL',
		30_000,
		'beignet channel NORMAL (funded open)'
	);
	return { node, channelId };
}

describe('Interop: Beignet ↔ CLN over WebSocket (regtest)', function () {
	this.timeout(180_000);

	let cln: ClnRestClient;
	let clnPubkey: string;
	let node: LightningNode;
	let skipAll = false;

	before(async function () {
		const available = await isClnAvailable();
		if (!available) {
			skipAll = true;
			console.log(
				'    ⚠ CLN not available — skipping WS interop tests. Start Docker: docker compose -f docker/docker-compose.yml up -d'
			);
			this.skip();
			return;
		}
		const client = await createClnClient();
		if (!client) {
			skipAll = true;
			this.skip();
			return;
		}
		cln = client;
		await waitForClnSync(cln);
		const info = await cln.getInfo();
		clnPubkey = info.id;
	});

	beforeEach(function () {
		if (skipAll) this.skip();
	});

	afterEach(function () {
		if (node) {
			node.destroy();
		}
	});

	// ═══════════════════════════════════════════════════════════
	// WS-1: Noise handshake + init over ws://
	// ═══════════════════════════════════════════════════════════

	describe('WS-1: Connection & Init over ws://', function () {
		it('should complete the BOLT 8 handshake + BOLT 1 init over WS', async function () {
			node = createInteropNode(601);
			node.on('node:error', () => {
				/* absorb */
			});

			await node.connectPeer(clnPubkey, CLN_P2P_HOST, CLN_WS_PORT, {
				type: 'ws'
			});

			const peers = node.listPeers();
			expect(peers.length).to.equal(1);
			expect(peers[0].pubkey).to.equal(clnPubkey);
			expect(peers[0].state).to.equal('ready');
			expect(peers[0].transport).to.equal('ws');

			// Init really exchanged: CLN's features are visible
			const remoteInit = node
				.getPeerManager()!
				.getPeer(clnPubkey)!
				.getRemoteInit();
			expect(remoteInit).to.not.equal(null);

			// CLN sees us as a connected peer
			await waitFor(
				async () => {
					const { peers: clnPeers } = await cln.listPeers();
					return (clnPeers || []).some(
						(p) => p.id === node.getNodeId() && p.connected
					);
				},
				15_000,
				'CLN to list the WS peer'
			);
		});

		it('should connect via an explicit ws:// url', async function () {
			node = createInteropNode(602);
			node.on('node:error', () => {
				/* absorb */
			});

			await node.connectPeer(clnPubkey, undefined, undefined, {
				type: 'ws',
				url: `ws://${CLN_P2P_HOST}:${CLN_WS_PORT}`
			});
			expect(node.listPeers()[0].state).to.equal('ready');
			expect(node.listPeers()[0].port).to.equal(CLN_WS_PORT);
		});
	});

	// ═══════════════════════════════════════════════════════════
	// WS-2: BOLT 1 ping/pong over the WS link
	// ═══════════════════════════════════════════════════════════

	describe('WS-2: ping/pong', function () {
		it('should keep the WS connection alive via BOLT 1 ping/pong', async function () {
			// Direct Peer with an aggressive ping schedule: if CLN's pongs did
			// not come back over WS, the pong timeout would disconnect us.
			const keys = deriveLightningKeysFromMnemonic(
				TEST_MNEMONIC,
				'interop-seed-603',
				LnCoinType.REGTEST
			);
			// CLN requires several feature bits in init; advertise the same
			// optional set the interop node uses so init succeeds.
			const features = FeatureFlags.empty();
			features.setOptional(Feature.DATA_LOSS_PROTECT);
			features.setOptional(Feature.STATIC_REMOTE_KEY);
			features.setOptional(Feature.PAYMENT_SECRET);
			features.setOptional(Feature.TLV_ONION);
			features.setOptional(Feature.CHANNEL_TYPE);
			features.setOptional(Feature.GOSSIP_QUERIES);
			features.setOptional(Feature.ANCHOR_ZERO_FEE_HTLC);
			const peer = new Peer({
				localPrivateKey: keys.nodePrivateKey,
				remotePublicKey: Buffer.from(clnPubkey, 'hex'),
				host: CLN_P2P_HOST,
				port: CLN_WS_PORT,
				localFeatures: features,
				pingInterval: 2_000,
				pongTimeout: 6_000,
				// NodeWebSocket: CLN's ws handshake parser requires RFC-cased
				// headers, which Node's built-in WebSocket lowercases.
				createSocket: (host, port): Promise<WebSocketTransport> =>
					connectWebSocket(`ws://${host}:${port}`, {
						webSocketImpl: NodeWebSocket
					})
			});
			const errors: Error[] = [];
			peer.on('error', (e: Error) => errors.push(e));

			await peer.connect();
			expect(peer.getState()).to.equal('ready');

			// Multiple ping cycles must round-trip (2s interval, 6s budget each)
			await sleep(9_000);
			expect(peer.getState()).to.equal('ready');
			expect(errors.map((e) => e.message)).to.not.include('Pong timeout');

			peer.disconnect();
		});
	});

	// ═══════════════════════════════════════════════════════════
	// WS-3: Channel to NORMAL + a payment in each direction
	// ═══════════════════════════════════════════════════════════

	describe('WS-3: channel + payments over WS', function () {
		it('should open a beignet-funded channel to NORMAL and pay in both directions', async function () {
			this.timeout(300_000);
			const setup = await setupBeignetFundedChannelOverWs(cln, clnPubkey, 604);
			node = setup.node;

			// Channel rides the WS transport
			expect(node.listPeers()[0].transport).to.equal('ws');

			// Routing + current chain height (no chain backend in-test; a stale
			// height of 0 makes the final CLTV look expired to CLN → 0x400f)
			setupRoutingForChannel(node, clnPubkey);
			const tip = (await bitcoinRpc('getblockcount')) as number;
			node.handleNewBlock(tip);
			await sleep(1000);

			// 1. Beignet pays CLN over the WS channel. 50k sats, so CLN ends up
			// comfortably above its channel reserve (1% of 500k = 5k sats) for
			// the return payment — at/below the reserve CLN's xpay stalls
			// retrying "cannot afford HTLC above channel reserve".
			const label = `ws-test-${Date.now()}-${Math.random()
				.toString(36)
				.slice(2)}`;
			const clnInvoice = await cln.createInvoice(
				50_000_000,
				label,
				'ws interop: beignet pays cln'
			);
			const payment = node.sendPayment(clnInvoice.bolt11);
			expect(payment).to.have.property('paymentHash');

			await waitFor(
				async () => {
					const { invoices } = await cln.listInvoices(label);
					return (invoices || []).some((i) => i.status === 'paid');
				},
				30_000,
				'CLN invoice to be paid over WS'
			);
			const info = node.getPayment(payment.paymentHash);
			expect(info?.status).to.equal(PaymentStatus.COMPLETED);

			// 2. CLN pays beignet back over the same WS channel
			const invoice = node.createInvoice({
				amountMsat: 10_000_000n,
				description: 'ws interop: cln pays beignet'
			});
			const payResult = await cln.pay(invoice.bolt11);
			expect(payResult.payment_preimage).to.be.a('string');
			expect(payResult.payment_preimage.length).to.be.greaterThan(0);
		});
	});

	// ═══════════════════════════════════════════════════════════
	// WS-4: Disconnect / reestablish over WS
	// ═══════════════════════════════════════════════════════════

	describe('WS-4: disconnect & reestablish over WS', function () {
		it('should reestablish the channel over WS and still route payments', async function () {
			const setup = await setupClnChannelOverWs(
				cln,
				clnPubkey,
				605,
				1_000_000,
				200_000_000
			);
			node = setup.node;
			const channelManager = node.getChannelManager();

			// Drop the WS connection
			node.disconnectPeer(clnPubkey);
			await sleep(3000);

			// Reconnect over WS (retry; CLN-side peer cleanup timing varies)
			const reconnectDeadline = Date.now() + 30_000;
			while (node.listPeers().length === 0 && Date.now() < reconnectDeadline) {
				try {
					await node.connectPeer(clnPubkey, CLN_P2P_HOST, CLN_WS_PORT, {
						type: 'ws'
					});
				} catch {
					// may already be connecting
				}
				await sleep(2000);
			}
			expect(node.listPeers().length).to.equal(1);
			expect(node.listPeers()[0].transport).to.equal('ws');

			// channel_reestablish completes and the channel returns to NORMAL
			await waitFor(
				() =>
					channelManager.getChannel(setup.channelId)?.getState() === 'NORMAL',
				60_000,
				'channel NORMAL after WS reestablish'
			);

			// CLN can still pay us over the reestablished WS channel
			const invoice = node.createInvoice({
				amountMsat: 1_000_000n,
				description: 'ws interop: post-reestablish payment'
			});
			const payResult = await cln.pay(invoice.bolt11);
			expect(payResult.payment_preimage).to.be.a('string');
			expect(payResult.payment_preimage.length).to.be.greaterThan(0);
		});
	});
});
