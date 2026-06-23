/**
 * CLN-specific interop test helpers.
 *
 * Contains CLN availability checks, rune loading, client factory,
 * sync/channel wait helpers, wallet funding, and channel setup.
 *
 * Re-exports everything from shared-helpers for convenience.
 */

import https from 'https';
import { execSync } from 'child_process';
import { ClnRestClient } from './cln-client';
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

export const CLN_REST_HOST = '127.0.0.1';
export const CLN_REST_PORT = 3010;
export const CLN_P2P_HOST = '127.0.0.1';
export const CLN_P2P_PORT = 19846;

/**
 * Docker container name for CLN. Defaults to the compose service `cln`, but can
 * be overridden (e.g. `cln-splice`) when running a standalone CLN with
 * --experimental-splicing.
 */
export const CLN_CONTAINER = process.env.CLN_CONTAINER || 'cln';

// ── CLN Availability ───────────────────────────────────────────

/**
 * Check if CLN REST API is reachable.
 * Returns true if the Docker CLN container is running and responding.
 */
export function isClnAvailable(): Promise<boolean> {
	return new Promise((resolve) => {
		const req = https.request(
			{
				hostname: CLN_REST_HOST,
				port: CLN_REST_PORT,
				path: '/v1/getinfo',
				method: 'POST',
				rejectUnauthorized: false,
				timeout: 3000
			},
			(res) => {
				// Even a 401/403 means CLN is running
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

// ── Rune Loading ───────────────────────────────────────────────

/**
 * Load a CLN rune from the running Docker container.
 * Retries up to 5 times with 2s delay (CLN may still be starting).
 */
export async function loadClnRune(): Promise<string> {
	for (let attempt = 0; attempt < 5; attempt++) {
		try {
			const output = execSync(
				`docker exec ${CLN_CONTAINER} lightning-cli --network=regtest createrune`,
				{ encoding: 'utf-8', timeout: 10_000 }
			);
			const parsed = JSON.parse(output);
			return parsed.rune;
		} catch {
			if (attempt < 4) {
				await sleep(2000);
			}
		}
	}
	throw new Error('Failed to load CLN rune after 5 attempts');
}

// ── Client Factory ─────────────────────────────────────────────

/**
 * Create a CLN REST client if Docker is available.
 * Returns null if CLN is not running.
 */
export async function createClnClient(): Promise<ClnRestClient | null> {
	const available = await isClnAvailable();
	if (!available) return null;

	try {
		const rune = await loadClnRune();
		return new ClnRestClient(CLN_REST_HOST, CLN_REST_PORT, rune);
	} catch {
		return null;
	}
}

// ── Wait Helpers ───────────────────────────────────────────────

/**
 * Wait for CLN to be fully synced to chain.
 */
export async function waitForClnSync(
	client: ClnRestClient,
	timeoutMs = 60_000
): Promise<void> {
	// Snapshot target height ONCE so parallel mining doesn't create a moving target
	const btcInfo = (await bitcoinRpc('getblockchaininfo')) as { blocks: number };
	const targetHeight = btcInfo.blocks;

	const start = Date.now();
	while (Date.now() - start < timeoutMs) {
		try {
			const info = await client.getInfo();
			if (info.blockheight >= targetHeight) return;
		} catch {
			// CLN not ready yet
		}
		await sleep(1000);
	}
	throw new Error('CLN did not sync within timeout');
}

/**
 * Wait for CLN to have at least `count` active channels.
 */
export async function waitForClnChannels(
	client: ClnRestClient,
	count: number,
	timeoutMs = 60_000
): Promise<void> {
	const start = Date.now();
	while (Date.now() - start < timeoutMs) {
		try {
			const { channels } = await client.listChannels();
			const active = (channels || []).filter(
				(c) => c.state === 'CHANNELD_NORMAL'
			);
			if (active.length >= count) return;
		} catch {
			// Not ready yet
		}
		await sleep(1000);
	}
	throw new Error(`CLN did not reach ${count} active channels within timeout`);
}

/**
 * Wait for CLN to have zero active channels.
 */
export async function waitForClnNoChannels(
	client: ClnRestClient,
	timeoutMs = 60_000
): Promise<void> {
	const start = Date.now();
	while (Date.now() - start < timeoutMs) {
		try {
			const { channels } = await client.listChannels();
			const active = (channels || []).filter(
				(c) =>
					c.state === 'CHANNELD_NORMAL' ||
					c.state === 'CHANNELD_AWAITING_LOCKIN'
			);
			if (active.length === 0) return;
		} catch {
			// Not ready yet
		}
		await sleep(1000);
	}
	throw new Error('CLN still has active channels after timeout');
}

/**
 * Wait for a specific CLN channel to close.
 */
export async function waitForClnChannelClosed(
	client: ClnRestClient,
	peerId: string,
	timeoutMs = 60_000
): Promise<void> {
	const start = Date.now();
	while (Date.now() - start < timeoutMs) {
		try {
			const { channels } = await client.listChannels();
			const found = (channels || []).some(
				(c) =>
					c.peer_id === peerId &&
					(c.state === 'CHANNELD_NORMAL' ||
						c.state === 'CHANNELD_AWAITING_LOCKIN')
			);
			if (!found) return;
		} catch {
			// Not ready
		}
		await sleep(1000);
	}
	throw new Error(`CLN channel with ${peerId} still active after timeout`);
}

// ── Wallet Funding ─────────────────────────────────────────────

/**
 * Fund the CLN wallet by sending BTC from the bitcoind wallet.
 */
export async function fundClnWallet(
	client: ClnRestClient,
	amountBtc = 1.0
): Promise<void> {
	// Ensure bitcoind has enough spendable balance (fresh Docker has only 1 immature coinbase)
	await ensureBitcoindFunds(amountBtc + 0.5);

	const { bech32 } = await client.newAddr();

	// Send from bitcoind wallet to CLN address
	await bitcoinRpc('sendtoaddress', [bech32, amountBtc]);

	// Mine 1 block to confirm the transaction
	await mineBlocks(1);
	await waitForClnSync(client, 60_000);
}

// ── Channel Setup ───────────────────────────────────────────────

/**
 * Setup a channel from CLN to beignet and wait until active.
 * Returns the beignet node and channel details for further testing.
 */
export async function setupClnChannel(
	cln: ClnRestClient,
	clnPubkey: string,
	seedId: number,
	fundingAmount = 500_000,
	pushMsat = 0
): Promise<{
	node: LightningNode;
	channelId: Buffer;
	fundingTxid: string;
}> {
	const node = createInteropNode(seedId);
	node.on('node:error', () => {
		/* absorb */
	});

	await fundClnWallet(cln);
	await node.connectPeer(clnPubkey, CLN_P2P_HOST, CLN_P2P_PORT);

	const beignetNodeId = node.getNodeId();
	const openResult = await cln.fundChannel(
		beignetNodeId,
		fundingAmount,
		pushMsat > 0 ? pushMsat : undefined
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

	await waitForClnChannels(cln, 1, 30_000);

	if (!channelId) {
		throw new Error('Channel not found after open');
	}

	// Wait for beignet's channel to reach NORMAL (channel_ready exchange)
	const deadline = Date.now() + 30_000;
	while (Date.now() < deadline) {
		const ch = channelManager.getChannel(channelId);
		if (ch && ch.getState() === 'NORMAL') break;
		await sleep(500);
	}

	return { node, channelId, fundingTxid: openResult.txid };
}

// ── Beignet-Funded Channel Setup ────────────────────────────────

/**
 * Setup a beignet-funded channel to CLN.
 * Beignet opens a channel to CLN using bitcoind as the funding wallet.
 */
export async function setupBeignetFundedClnChannel(
	cln: ClnRestClient,
	clnPubkey: string,
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
	features.setOptional(Feature.QUIESCE);
	features.setOptional(Feature.SPLICE);

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
	node.on('node:error', (e: unknown) => {
		if (process.env.DEBUG_INTEROP) {
			// eslint-disable-next-line no-console
			console.log('    [node:error]', JSON.stringify(e));
		}
	});

	// Connect to CLN
	await node.connectPeer(clnPubkey, CLN_P2P_HOST, CLN_P2P_PORT);
	await sleep(2000);

	// Beignet opens channel to CLN — triggers auto-funding flow
	node.openChannel(clnPubkey, fundingAmount);

	// Wait for channel to appear
	const channelManager = node.getChannelManager();
	const deadline = Date.now() + 30_000;
	while (Date.now() < deadline) {
		const chs = channelManager.listChannels();
		if (chs.length > 0) break;
		await sleep(1000);
	}

	let channels = channelManager.listChannels();
	if (channels.length === 0) {
		throw new Error('No channel found after beignet-funded open to CLN');
	}

	// Mine blocks to confirm the funding tx
	await mineBlocks(6);
	await sleep(3000);

	channels = channelManager.listChannels();
	const channelId = channels[0].getChannelId();
	if (!channelId) {
		throw new Error('Channel has no channelId after open');
	}

	// Notify beignet of funding confirmation
	node.handleFundingConfirmed(channelId);

	// Wait for CLN to see the active channel
	await waitForClnChannels(cln, 1, 30_000);

	// Wait for beignet channel to reach NORMAL
	const normalDeadline = Date.now() + 30_000;
	while (Date.now() < normalDeadline) {
		const ch = channelManager.getChannel(channelId);
		if (ch && ch.getState() === 'NORMAL') break;
		await sleep(500);
	}

	return { node, channelId };
}
