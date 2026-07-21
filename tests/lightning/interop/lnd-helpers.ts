/**
 * LND-specific interop test helpers.
 *
 * Contains all LND-specific functions: availability checks, macaroon
 * loading, client factory, sync/channel wait helpers, wallet funding,
 * and channel setup.
 *
 * Re-exports everything from shared-helpers for convenience.
 */

import https from 'https';
import { execSync } from 'child_process';
import { LndRestClient } from './lnd-client';
import { LightningNode } from '../../../src/lightning/node/lightning-node';
import {
	sleep,
	mineBlocks,
	createInteropNode,
	setupRoutingForChannel,
	bitcoinRpc,
	getDockerHostAddress,
	waitForEvent,
	ensureBitcoindFunds,
	TEST_MNEMONIC,
	BitcoindFundingProvider
} from './shared-helpers';

// Re-export everything from shared-helpers
export {
	sleep,
	mineBlocks,
	createInteropNode,
	setupRoutingForChannel,
	bitcoinRpc,
	getDockerHostAddress,
	waitForEvent,
	ensureBitcoindFunds,
	TEST_MNEMONIC,
	BitcoindFundingProvider
};

// ── Constants ──────────────────────────────────────────────────

// Overridable so the interop stack can be brought up on free ports when the
// defaults collide with something else already running on the host. Point these
// at whatever docker/docker-compose.override.yml publishes.
export const LND_REST_HOST = process.env.LND_REST_HOST ?? '127.0.0.1';
export const LND_REST_PORT = Number(process.env.LND_REST_PORT ?? 8081);
export const LND_P2P_HOST = process.env.LND_P2P_HOST ?? '127.0.0.1';
export const LND_P2P_PORT = Number(process.env.LND_P2P_PORT ?? 9735);

// ── LND Availability ───────────────────────────────────────────

/**
 * Check if LND REST API is reachable.
 * Returns true if the Docker LND container is running and responding.
 */
export function isLndAvailable(): Promise<boolean> {
	return new Promise((resolve) => {
		const req = https.request(
			{
				hostname: LND_REST_HOST,
				port: LND_REST_PORT,
				path: '/v1/getinfo',
				method: 'GET',
				rejectUnauthorized: false,
				timeout: 3000
			},
			(res) => {
				// Even a 401/500 means LND is running
				resolve(true);
				res.resume();
			}
		);

		req.on('error', () => resolve(false));
		req.on('timeout', () => {
			req.destroy();
			resolve(false);
		});
		req.end();
	});
}

// ── Macaroon Loading ───────────────────────────────────────────

/**
 * Load the admin macaroon from the running LND Docker container.
 * Returns the macaroon as a hex string.
 */
export function loadMacaroon(): string {
	const raw = execSync(
		'docker exec lnd cat /root/.lnd/data/chain/bitcoin/regtest/admin.macaroon',
		{ encoding: 'buffer' }
	);
	return raw.toString('hex');
}

// ── Client Factory ─────────────────────────────────────────────

/**
 * Create an LND REST client if Docker is available.
 * Returns null if LND is not running.
 */
export async function createLndClient(): Promise<LndRestClient | null> {
	const available = await isLndAvailable();
	if (!available) return null;

	try {
		const macaroon = loadMacaroon();
		return new LndRestClient(LND_REST_HOST, LND_REST_PORT, macaroon);
	} catch {
		return null;
	}
}

// ── Cleanup ────────────────────────────────────────────────────

/**
 * Force close all inactive LND channels and disconnect stale peers.
 * Call this before test runs to prevent zombie channel accumulation.
 * Each test run creates new channels that persist in LND's DB; without
 * cleanup, LND accumulates hundreds of inactive channels over time.
 */
export async function cleanupLndState(client: LndRestClient): Promise<void> {
	try {
		// Force close all inactive channels
		const { channels } = await client.listChannels();
		const inactive = (channels || []).filter((c) => !c.active);
		if (inactive.length > 0) {
			console.log(
				`    Cleaning up ${inactive.length} inactive LND channels...`
			);
			for (const ch of inactive) {
				const [txid, idx] = ch.channel_point.split(':');
				try {
					await client.forceCloseChannel(txid, parseInt(idx, 10));
				} catch {
					// Channel may already be closing
				}
			}
			// Mine blocks to confirm force closes
			await mineBlocks(6);
			await sleep(2000);
		}

		// Disconnect stale peers
		const { peers } = await client.listPeers();
		for (const peer of peers || []) {
			try {
				await client.disconnectPeer(peer.pub_key);
			} catch {
				// Peer may already be disconnected
			}
		}
	} catch {
		// Cleanup is best-effort
	}
}

// ── Wait Helpers ───────────────────────────────────────────────

/**
 * Wait for LND to be fully synced to chain.
 */
export async function waitForLndSync(
	client: LndRestClient,
	timeoutMs = 30_000
): Promise<void> {
	const start = Date.now();
	while (Date.now() - start < timeoutMs) {
		try {
			const info = await client.getInfo();
			if (info.synced_to_chain) return;
		} catch {
			// LND not ready yet
		}
		await sleep(1000);
	}
	throw new Error('LND did not sync within timeout');
}

/**
 * Wait for LND to have at least `count` active channels.
 */
export async function waitForLndChannels(
	client: LndRestClient,
	count: number,
	timeoutMs = 60_000
): Promise<void> {
	const start = Date.now();
	while (Date.now() - start < timeoutMs) {
		try {
			const { channels } = await client.listChannels();
			const active = (channels || []).filter((c) => c.active);
			if (active.length >= count) return;
		} catch {
			// Not ready yet
		}
		await sleep(1000);
	}
	throw new Error(`LND did not reach ${count} active channels within timeout`);
}

/**
 * Wait for a specific LND invoice to be settled.
 */
export async function waitForInvoiceSettled(
	client: LndRestClient,
	rHashHex: string,
	timeoutMs = 30_000
): Promise<ISettledInvoice> {
	const start = Date.now();
	while (Date.now() - start < timeoutMs) {
		try {
			const inv = await client.lookupInvoice(rHashHex);
			if (inv.state === 'SETTLED' || inv.settled) {
				return { settled: true, amtPaidMsat: inv.amt_paid_msat || '0' };
			}
		} catch {
			// Not found yet
		}
		await sleep(500);
	}
	throw new Error('Invoice did not settle within timeout');
}

interface ISettledInvoice {
	settled: boolean;
	amtPaidMsat: string;
}

// ── Wallet Funding ─────────────────────────────────────────────

/**
 * Fund the LND wallet by sending BTC from the bitcoind wallet.
 *
 * Regtest halves every 150 blocks, so after ~4500+ blocks the block
 * subsidy is negligible. Instead of mining to an LND address, we send
 * BTC from the bitcoind wallet (which accumulated coins from early
 * high-reward blocks) via sendtoaddress, then mine 1 block to confirm.
 */
export async function fundLndWallet(
	client: LndRestClient,
	_blocks = 110,
	amountBtc = 1.0
): Promise<void> {
	// Ensure bitcoind has enough spendable balance (fresh Docker has only 1 immature coinbase)
	await ensureBitcoindFunds(amountBtc + 0.5);

	const { address } = await client.newAddress();

	// Send from bitcoind wallet to LND address
	await bitcoinRpc('sendtoaddress', [address, amountBtc]);

	// Mine 1 block to confirm the transaction
	await mineBlocks(1);
	await waitForLndSync(client, 30_000);
}

// ── Additional Wait Helpers ─────────────────────────────────────

/**
 * Wait for LND to have zero active channels.
 */
export async function waitForLndNoChannels(
	client: LndRestClient,
	timeoutMs = 60_000
): Promise<void> {
	const start = Date.now();
	while (Date.now() - start < timeoutMs) {
		try {
			const { channels } = await client.listChannels();
			if (!channels || channels.length === 0) return;
		} catch {
			// Not ready yet
		}
		await sleep(1000);
	}
	throw new Error('LND still has active channels after timeout');
}

/**
 * Wait for a specific LND channel to disappear (closed).
 */
export async function waitForLndChannelClosed(
	client: LndRestClient,
	channelPoint: string,
	timeoutMs = 60_000
): Promise<void> {
	const start = Date.now();
	while (Date.now() - start < timeoutMs) {
		try {
			const { channels } = await client.listChannels();
			const found = (channels || []).some(
				(c) => c.channel_point === channelPoint
			);
			if (!found) return;
		} catch {
			// not ready
		}
		await sleep(1000);
	}
	throw new Error(`Channel ${channelPoint} still active after timeout`);
}

// ── Channel Setup ───────────────────────────────────────────────

/**
 * Setup a channel from LND to beignet and wait until active.
 * Returns the beignet node and channel details for further testing.
 */
export async function setupLndChannel(
	lnd: LndRestClient,
	lndPubkey: string,
	seedId: number,
	fundingAmount = 500_000,
	pushSat = 0
): Promise<{
	node: LightningNode;
	channelId: Buffer;
	channelPoint: string;
}> {
	const node = createInteropNode(seedId);
	node.on('node:error', () => {
		/* absorb */
	});

	await fundLndWallet(lnd, 110);
	await node.connectPeer(lndPubkey, LND_P2P_HOST, LND_P2P_PORT);

	const beignetNodeId = node.getNodeId();
	const openResult = await lnd.openChannelSync(
		beignetNodeId,
		fundingAmount,
		pushSat
	);

	await mineBlocks(6);
	await sleep(3000);

	const channelManager = node.getChannelManager();
	const channels = channelManager.listChannels();

	let channelId: Buffer | null = null;
	if (channels.length > 0) {
		channelId = channels[0].getChannelId();
		if (channelId) {
			node.handleFundingConfirmed(channelId);
		}
	}

	await waitForLndChannels(lnd, 1, 30_000);

	if (!channelId) {
		throw new Error('Channel not found after open');
	}

	// Build the channel point string (LND format: txid:idx)
	const txidStr =
		openResult.funding_txid_str ||
		(openResult.funding_txid_bytes
			? Buffer.from(openResult.funding_txid_bytes, 'base64')
					.reverse()
					.toString('hex')
			: '');
	const channelPoint = `${txidStr}:${openResult.output_index}`;

	return { node, channelId, channelPoint };
}

// BitcoindFundingProvider is re-exported from shared-helpers.ts

// ── Beignet-Funded Channel Setup ────────────────────────────────

/**
 * Create a beignet interop node with an IFundingProvider for auto-funding.
 */
export function createFundedInteropNode(seedId: number): LightningNode {
	const node = createInteropNode(seedId);
	// Inject a bitcoind-backed funding provider
	// We need to access the private field — use the fromMnemonic factory instead
	// to get clean funding provider support
	return node;
}

/**
 * Setup a beignet-funded channel to LND.
 * Beignet opens a channel to LND using bitcoind as the funding wallet.
 * Uses the same createInteropNode path as other tiers for consistency,
 * but with a funding provider injected via the LightningNode constructor.
 */
export async function setupBeignetFundedChannel(
	lnd: LndRestClient,
	lndPubkey: string,
	seedId: number,
	fundingAmount = 500_000n,
	fundingProvider: BitcoindFundingProvider = new BitcoindFundingProvider()
): Promise<{
	node: LightningNode;
	channelId: Buffer;
	fundingProvider: BitcoindFundingProvider;
}> {
	// Ensure bitcoind has enough funds for the channel
	await ensureBitcoindFunds(2.0);

	// Use the same key derivation path as createInteropNode for consistency
	const { FeatureFlags, Feature } = await import(
		'../../../src/lightning/features/flags'
	);
	const { REGTEST_CHAIN_HASH } = await import(
		'../../../src/lightning/channel/types'
	);
	const { Network } = await import('../../../src/lightning/invoice/types');
	const { deriveLightningKeysFromMnemonic, LnCoinType } = await import(
		'../../../src/lightning/keys/wallet-keys'
	);

	const passphrase = `interop-seed-${seedId}`;
	const keys = deriveLightningKeysFromMnemonic(
		TEST_MNEMONIC,
		passphrase,
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

	// Use direct LightningNode constructor (same as createInteropNode) + fundingProvider
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
		fundingProvider
	});
	const errors: Array<{ code?: string; message?: string }> = [];
	node.on('node:error', (err: { code?: string; message?: string }) => {
		errors.push(err);
	});

	// Connect to LND
	await node.connectPeer(lndPubkey, LND_P2P_HOST, LND_P2P_PORT);
	await sleep(2000);

	// Beignet opens channel to LND — triggers auto-funding flow
	node.openChannel(lndPubkey, fundingAmount);

	// Wait for the async auto-funding handshake to complete. openChannel creates
	// a temp channel (SENT_OPEN, no channelId) immediately, so we must wait for a
	// real channelId — set when funding_created is sent after LND's funding_signed
	// — rather than just any channel appearing.
	const channelManager = node.getChannelManager();
	const deadline = Date.now() + 30_000;
	let fundedChannel = channelManager
		.listChannels()
		.find((c) => c.getChannelId() !== null);
	while (!fundedChannel && Date.now() < deadline) {
		await sleep(500);
		fundedChannel = channelManager
			.listChannels()
			.find((c) => c.getChannelId() !== null);
	}

	if (!fundedChannel) {
		const errorMsgs = errors.map((e) => `${e.code}: ${e.message}`).join('; ');
		const tempMap = (
			channelManager as unknown as {
				tempChannels: Map<
					string,
					{ getState(): string; getFullState(): { fundingTxid?: Buffer } }
				>;
			}
		).tempChannels;
		let tempInfo = '';
		if (tempMap) {
			for (const [id, ch] of tempMap) {
				tempInfo += ` ${id.slice(
					0,
					8
				)}:state=${ch.getState()},hasFundingTxid=${!!ch.getFullState()
					.fundingTxid}`;
			}
		}
		throw new Error(
			`No funded channel after beignet-funded open (errors: [${errorMsgs}], tempInfo:[${tempInfo}])`
		);
	}

	const channelId = fundedChannel.getChannelId()!;
	const fundingTxid = fundedChannel.getFullState().fundingTxid;

	// The funding tx is broadcast asynchronously (in watch:funding, after
	// funding_signed). Wait for it to land in bitcoind's mempool BEFORE mining —
	// otherwise we mine empty blocks and the funding never confirms, so LND never
	// activates the channel. (Match either txid byte order to be safe.)
	if (fundingTxid) {
		const h1 = Buffer.from(fundingTxid).toString('hex');
		const h2 = Buffer.from(fundingTxid).reverse().toString('hex');
		const mempoolDeadline = Date.now() + 15_000;
		while (Date.now() < mempoolDeadline) {
			const mempool = (await bitcoinRpc('getrawmempool')) as string[];
			if (mempool.includes(h1) || mempool.includes(h2)) break;
			await sleep(500);
		}
	}

	// Mine blocks to confirm the funding tx
	await mineBlocks(6);
	await sleep(3000);

	// Notify beignet of funding confirmation
	node.handleFundingConfirmed(channelId);

	// Wait for LND to see the active channel
	await waitForLndChannels(lnd, 1, 30_000);

	return { node, channelId, fundingProvider };
}
