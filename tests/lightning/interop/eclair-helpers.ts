/**
 * Eclair-specific interop test helpers.
 *
 * Contains Eclair availability checks, client factory, sync/channel
 * wait helpers, wallet funding, payment polling, and channel setup.
 *
 * Re-exports everything from shared-helpers for convenience.
 *
 * NOTE: Eclair's ZMQ block notifications do not work reliably under
 * Docker on ARM Macs (amd64 image emulation). All sync helpers use
 * `docker restart eclair` to force chain-tip sync via RPC at startup.
 */

import http from 'http';
import { execSync } from 'child_process';
import { EclairRestClient } from './eclair-client';
import { LightningNode } from '../../../src/lightning/node/lightning-node';
import { FeatureFlags, Feature } from '../../../src/lightning/features/flags';
import { REGTEST_CHAIN_HASH } from '../../../src/lightning/channel/types';
import { Network } from '../../../src/lightning/invoice/types';
import {
	deriveLightningKeysFromMnemonic,
	LnCoinType
} from '../../../src/lightning/keys/wallet-keys';
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

export const ECLAIR_REST_HOST = '127.0.0.1';
export const ECLAIR_REST_PORT = 8082;
export const ECLAIR_P2P_HOST = '127.0.0.1';
export const ECLAIR_P2P_PORT = 9737;
export const ECLAIR_PASSWORD = 'eclairpassword';

// ── Eclair Availability ────────────────────────────────────────

/**
 * Check if Eclair REST API is reachable.
 * Returns true if the Docker Eclair container is running and responding.
 */
export function isEclairAvailable(): Promise<boolean> {
	return new Promise((resolve) => {
		const authHeader =
			'Basic ' + Buffer.from(`:${ECLAIR_PASSWORD}`).toString('base64');

		const req = http.request(
			{
				hostname: ECLAIR_REST_HOST,
				port: ECLAIR_REST_PORT,
				path: '/getinfo',
				method: 'POST',
				headers: {
					Authorization: authHeader,
					'Content-Type': 'application/x-www-form-urlencoded',
					'Content-Length': 0
				},
				timeout: 3000
			},
			(res) => {
				// Even a 401/500 means Eclair is running
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

// ── Client Factory ─────────────────────────────────────────────

/**
 * Create an Eclair REST client if Docker is available.
 * Returns null if Eclair is not running.
 */
export async function createEclairClient(): Promise<EclairRestClient | null> {
	const available = await isEclairAvailable();
	if (!available) return null;

	try {
		const client = new EclairRestClient(
			ECLAIR_REST_HOST,
			ECLAIR_REST_PORT,
			ECLAIR_PASSWORD
		);
		// Verify connection
		await client.getInfo();
		return client;
	} catch {
		return null;
	}
}

// ── Eclair Restart & Sync ─────────────────────────────────────

/**
 * Restart Eclair and wait for it to sync to bitcoind's chain tip.
 *
 * Eclair's ZMQ block notifications do not work reliably under Docker
 * on ARM Macs. Restarting forces Eclair to sync via RPC at startup.
 */
export async function restartEclairAndSync(
	client: EclairRestClient,
	timeoutMs = 120_000
): Promise<void> {
	const btcInfo = (await bitcoinRpc('getblockchaininfo')) as { blocks: number };
	const targetHeight = btcInfo.blocks;

	// Check if already synced (avoid unnecessary restart)
	try {
		const info = await client.getInfo();
		if (info.blockHeight >= targetHeight) return;
	} catch {
		/* not reachable, restart anyway */
	}

	// Eclair v0.14 refuses to start if it detects locked UTXOs.
	// Must stop Eclair first, then unlock, then start — otherwise Eclair
	// re-locks UTXOs between our unlock and its shutdown.
	try {
		execSync('docker stop eclair', { timeout: 30_000 });
	} catch {
		/* ignore */
	}
	try {
		await bitcoinRpc('lockunspent', [true]);
	} catch {
		/* ignore */
	}
	try {
		execSync('docker start eclair', { timeout: 30_000 });
	} catch {
		/* ignore */
	}

	// Wait for Eclair to come back up and sync
	const start = Date.now();
	let lastLog = 0;
	while (Date.now() - start < timeoutMs) {
		try {
			const info = await client.getInfo();
			const elapsed = Math.floor((Date.now() - start) / 1000);

			if (elapsed - lastLog >= 15) {
				console.log(
					`    Eclair restart sync: ${info.blockHeight}/${targetHeight} (${elapsed}s elapsed)`
				);
				lastLog = elapsed;
			}

			if (info.blockHeight >= targetHeight) return;
		} catch {
			// Eclair still starting up
		}
		await sleep(2000);
	}
	throw new Error('Eclair did not sync after restart within timeout');
}

// ── Wait Helpers ───────────────────────────────────────────────

/**
 * Wait for Eclair to be fully synced to chain.
 * Uses restart if Eclair falls behind (ZMQ unreliable on ARM Docker).
 */
export async function waitForEclairSync(
	client: EclairRestClient,
	timeoutMs = 180_000
): Promise<void> {
	const btcInfo = (await bitcoinRpc('getblockchaininfo')) as { blocks: number };
	const targetHeight = btcInfo.blocks;

	// Quick check — already synced?
	try {
		const info = await client.getInfo();
		if (info.blockHeight >= targetHeight) return;
	} catch {
		/* proceed */
	}

	// Not synced — restart to force RPC sync
	await restartEclairAndSync(client, timeoutMs);
}

/**
 * Wait for Eclair to have at least `count` active channels.
 */
export async function waitForEclairChannels(
	client: EclairRestClient,
	count: number,
	timeoutMs = 60_000
): Promise<void> {
	const start = Date.now();
	while (Date.now() - start < timeoutMs) {
		try {
			const channels = await client.channels();
			const active = (channels || []).filter((c) => c.state === 'NORMAL');
			if (active.length >= count) return;
		} catch {
			// Not ready yet
		}
		await sleep(1000);
	}
	throw new Error(
		`Eclair did not reach ${count} active channels within timeout`
	);
}

/**
 * Wait for Eclair to have zero active channels.
 */
export async function waitForEclairNoChannels(
	client: EclairRestClient,
	timeoutMs = 60_000
): Promise<void> {
	const start = Date.now();
	while (Date.now() - start < timeoutMs) {
		try {
			const channels = await client.channels();
			const active = (channels || []).filter(
				(c) => c.state === 'NORMAL' || c.state === 'WAIT_FOR_FUNDING_CONFIRMED'
			);
			if (active.length === 0) return;
		} catch {
			// Not ready yet
		}
		await sleep(1000);
	}
	throw new Error('Eclair still has active channels after timeout');
}

/**
 * Wait for a specific Eclair channel to close.
 */
export async function waitForEclairChannelClosed(
	client: EclairRestClient,
	channelId: string,
	timeoutMs = 60_000
): Promise<void> {
	const start = Date.now();
	while (Date.now() - start < timeoutMs) {
		try {
			const channels = await client.channels();
			const found = (channels || []).some(
				(c) =>
					c.channelId === channelId &&
					(c.state === 'NORMAL' || c.state === 'WAIT_FOR_FUNDING_CONFIRMED')
			);
			if (!found) return;
		} catch {
			// Not ready
		}
		await sleep(1000);
	}
	throw new Error(`Eclair channel ${channelId} still active after timeout`);
}

/**
 * Mine blocks and restart Eclair to ensure it sees them.
 * Use this instead of plain mineBlocks() when Eclair needs to be aware
 * of new blocks (e.g. channel confirmations, close confirmations).
 */
export async function mineBlocksAndSyncEclair(
	client: EclairRestClient,
	count: number
): Promise<string[]> {
	const hashes = await mineBlocks(count);
	await restartEclairAndSync(client, 60_000);
	return hashes;
}

/**
 * Wait for an Eclair payment to complete.
 * Eclair's payInvoice is async — returns UUID immediately.
 * Must poll getSentInfo to check completion.
 */
export async function waitForEclairPayment(
	client: EclairRestClient,
	paymentHash: string,
	timeoutMs = 30_000
): Promise<{ success: boolean; preimage?: string; error?: string }> {
	const start = Date.now();
	while (Date.now() - start < timeoutMs) {
		try {
			const sentInfos = await client.getSentInfo(paymentHash);
			if (sentInfos && sentInfos.length > 0) {
				const latest = sentInfos[sentInfos.length - 1];
				if (latest.status.type === 'sent') {
					return { success: true, preimage: latest.status.paymentPreimage };
				}
				if (latest.status.type === 'failed') {
					return {
						success: false,
						error: latest.status.failureMessage || 'Payment failed'
					};
				}
			}
		} catch {
			// Not ready yet
		}
		await sleep(500);
	}
	return { success: false, error: 'Payment timed out' };
}

// ── Wallet Funding ─────────────────────────────────────────────

/**
 * Fund the Eclair wallet by sending BTC from the bitcoind wallet.
 * Mines 1 block and restarts Eclair to sync.
 */
export async function fundEclairWallet(
	client: EclairRestClient,
	amountBtc = 1.0
): Promise<void> {
	// Ensure bitcoind has enough spendable balance (fresh Docker has only 1 immature coinbase)
	await ensureBitcoindFunds(amountBtc + 0.5);

	const address = await client.getNewAddress();

	// Send from bitcoind wallet to Eclair address
	await bitcoinRpc('sendtoaddress', [address, amountBtc]);

	// Mine 1 block to confirm the transaction
	await mineBlocks(1);

	// Restart Eclair to see the new block (ZMQ unreliable)
	await restartEclairAndSync(client, 60_000);
}

// ── Channel Setup ───────────────────────────────────────────────

/**
 * Setup a channel from Eclair to beignet and wait until active.
 *
 * Flow (restart-resilient, no ZMQ dependency):
 * 1. Fund Eclair wallet (mine + restart to sync)
 * 2. Connect beignet to Eclair
 * 3. Eclair opens channel to beignet
 * 4. Mine 6 blocks for channel confirmation
 * 5. Restart Eclair to see confirmations (kills P2P connection)
 * 6. Reconnect beignet to Eclair
 * 7. Wait for channel to become active on both sides
 */
export async function setupEclairChannel(
	eclair: EclairRestClient,
	eclairPubkey: string,
	seedId: number,
	fundingAmount = 500_000,
	pushMsat = 0
): Promise<{
	node: LightningNode;
	channelId: Buffer;
	eclairChannelId: string;
}> {
	const node = createInteropNode(seedId);
	node.on('node:error', () => {
		/* absorb */
	});

	// Step 1: Fund Eclair wallet (mines + restarts to sync)
	await fundEclairWallet(eclair);

	// Step 2: Connect beignet to Eclair
	await node.connectPeer(eclairPubkey, ECLAIR_P2P_HOST, ECLAIR_P2P_PORT);

	// Step 3: Eclair opens channel to beignet
	const beignetNodeId = node.getNodeId();
	const eclairChannelId = await eclair.open(
		beignetNodeId,
		fundingAmount,
		pushMsat > 0 ? pushMsat : undefined
	);

	// Wait for beignet to process the open_channel/accept_channel exchange
	await sleep(3000);

	// Step 4: Mine 6 blocks for channel confirmation
	await mineBlocks(6);
	await sleep(1000);

	// Step 5: Notify beignet about funding confirmation BEFORE restart.
	// This updates beignet's channel state so channel_reestablish works
	// correctly after the restart kills the P2P connection.
	const channelManager = node.getChannelManager();
	const channels = channelManager.listChannels();

	let channelId: Buffer | null = null;
	if (channels.length > 0) {
		channelId = channels[0].getChannelId();
		if (channelId) {
			node.handleFundingConfirmed(channelId);
		}
	}

	if (!channelId) {
		throw new Error('Channel not found after open');
	}

	await sleep(1000);

	// Step 6: Restart Eclair to see confirmations (ZMQ unreliable)
	// This kills the P2P connection, but Eclair persists channel state.
	await restartEclairAndSync(eclair, 60_000);

	// Step 7: Reconnect beignet to Eclair for channel_reestablish
	await node.connectPeer(eclairPubkey, ECLAIR_P2P_HOST, ECLAIR_P2P_PORT);
	await sleep(3000);

	await waitForEclairChannels(eclair, 1, 30_000);

	// Wait for beignet channel to reach NORMAL
	const deadline = Date.now() + 30_000;
	while (Date.now() < deadline) {
		const ch = channelManager.getChannel(channelId);
		if (ch && ch.getState() === 'NORMAL') break;
		await sleep(500);
	}

	return { node, channelId, eclairChannelId };
}

// ── Beignet-Funded Channel Setup ────────────────────────────────

/**
 * Setup a beignet-funded channel to Eclair.
 * Beignet opens a channel to Eclair using bitcoind as the funding wallet.
 */
export async function setupBeignetFundedEclairChannel(
	eclair: EclairRestClient,
	eclairPubkey: string,
	seedId: number,
	fundingAmount = 500_000n
): Promise<{
	node: LightningNode;
	channelId: Buffer;
}> {
	// Ensure bitcoind has enough funds for the channel
	await ensureBitcoindFunds(2.0);

	const fundingProvider = new BitcoindFundingProvider();

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
	node.on('node:error', () => {
		/* absorb */
	});

	// Connect to Eclair
	await node.connectPeer(eclairPubkey, ECLAIR_P2P_HOST, ECLAIR_P2P_PORT);
	await sleep(2000);

	// Beignet opens channel to Eclair — triggers auto-funding flow
	node.openChannel(eclairPubkey, fundingAmount);

	// Wait for the funding handshake to complete — the channel first appears as a
	// temp channel (no channelId), so wait for a real channelId rather than just
	// any channel.
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
		throw new Error('No funded channel after beignet-funded open to Eclair');
	}

	const channelId = fundedChannel.getChannelId()!;
	const fundingTxid = fundedChannel.getFullState().fundingTxid;

	// The funding tx is broadcast asynchronously (after funding_signed). Wait for
	// it in bitcoind's mempool BEFORE mining, else we mine empty blocks and the
	// funding never confirms.
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
	await sleep(1000);

	// Notify beignet of funding confirmation BEFORE restart
	node.handleFundingConfirmed(channelId);
	await sleep(1000);

	// Restart Eclair to see confirmations (ZMQ unreliable on this setup).
	await restartEclairAndSync(eclair, 60_000);

	// Reconnect beignet to Eclair for channel_reestablish (idempotent).
	try {
		await node.connectPeer(eclairPubkey, ECLAIR_P2P_HOST, ECLAIR_P2P_PORT);
	} catch {
		// may already be connected
	}
	await sleep(3000);

	// Wait for Eclair to see the active channel.
	await waitForEclairChannels(eclair, 1, 30_000);

	// Wait for beignet channel to reach NORMAL
	const normalDeadline = Date.now() + 30_000;
	while (Date.now() < normalDeadline) {
		const ch = channelManager.getChannel(channelId);
		if (ch && ch.getState() === 'NORMAL') break;
		await sleep(500);
	}

	return { node, channelId };
}
