/**
 * Helpers for the DEDICATED taproot LND container (`lnd-taproot`).
 *
 * This is a separate container from the shared `lnd` (which is NOT taproot
 * enabled). It runs lightninglabs/lnd v0.20 with --protocol.simple-taproot-chans
 * on the SAME shared regtest bitcoind. It advertises feature bit 181
 * (simple-taproot-chans-x, the LND staging assignment).
 *
 *   REST  127.0.0.1:8082
 *   p2p   127.0.0.1:9736
 *   macaroon: docker exec lnd-taproot cat .../regtest/admin.macaroon
 *
 * See memory taproot-channels-m4 "Stage E".
 */

import https from 'https';
import { execSync } from 'child_process';
import { LndRestClient } from './lnd-client';
import { LightningNode } from '../../../src/lightning/node/lightning-node';
import {
	TEST_MNEMONIC,
	ensureBitcoindFunds,
	sleep,
	mineBlocks,
	bitcoinRpc,
	BitcoindFundingProvider
} from './shared-helpers';
import { waitForLndChannels } from './lnd-helpers';

export const LND_TAPROOT_REST_HOST = '127.0.0.1';
export const LND_TAPROOT_REST_PORT = 8082;
export const LND_TAPROOT_P2P_HOST = '127.0.0.1';
export const LND_TAPROOT_P2P_PORT = 9736;
export const LND_TAPROOT_CONTAINER = 'lnd-taproot';

/** Check if the taproot LND REST API is reachable. */
export function isLndTaprootAvailable(): Promise<boolean> {
	return new Promise((resolve) => {
		const req = https.request(
			{
				hostname: LND_TAPROOT_REST_HOST,
				port: LND_TAPROOT_REST_PORT,
				path: '/v1/getinfo',
				method: 'GET',
				rejectUnauthorized: false,
				timeout: 3000
			},
			(res) => {
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

/** Load the admin macaroon from the taproot LND container as hex. */
export function loadTaprootMacaroon(): string {
	const raw = execSync(
		`docker exec ${LND_TAPROOT_CONTAINER} cat /root/.lnd/data/chain/bitcoin/regtest/admin.macaroon`,
		{ encoding: 'buffer' }
	);
	return raw.toString('hex');
}

/** Create a REST client for the taproot LND, or null if unavailable. */
export async function createLndTaprootClient(): Promise<LndRestClient | null> {
	const available = await isLndTaprootAvailable();
	if (!available) return null;
	try {
		const macaroon = loadTaprootMacaroon();
		return new LndRestClient(
			LND_TAPROOT_REST_HOST,
			LND_TAPROOT_REST_PORT,
			macaroon
		);
	} catch {
		return null;
	}
}

// ── Taproot beignet node + channel setup ───────────────────────

/**
 * Build a beignet LightningNode that advertises simple taproot channels
 * (Feature.OPTION_TAPROOT, staging bit 181) and prefers taproot on open.
 */
export async function buildTaprootBeignetNode(
	seedId: number,
	fundingProvider: BitcoindFundingProvider
): Promise<LightningNode> {
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

	const passphrase = `taproot-interop-${seedId}`;
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
	features.setOptional(Feature.OPTION_TAPROOT);

	return new LightningNode({
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
		preferTaproot: true,
		fundingProvider
	});
}

/**
 * Open a beignet→LND simple-taproot channel and drive it to active:
 * connect → openChannel(preferTaproot) → broadcast funding → confirm →
 * channel_ready → wait until LND lists the channel active.
 *
 * Returns the live beignet node (caller is responsible for node.destroy()).
 */
export async function setupTaprootLndChannel(
	lnd: LndRestClient,
	lndPubkey: string,
	seedId: number,
	fundingSats = 200_000n,
	pushMsat = 0n
): Promise<{ node: LightningNode; channelId: Buffer }> {
	await ensureBitcoindFunds(2.0);

	const fundingProvider = new BitcoindFundingProvider();
	const node = await buildTaprootBeignetNode(seedId, fundingProvider);
	node.on('node:error', () => {
		/* absorb */
	});

	await node.connectPeer(lndPubkey, LND_TAPROOT_P2P_HOST, LND_TAPROOT_P2P_PORT);
	await sleep(2000);

	// pushMsat seeds the LND side with outbound liquidity (needed to test the
	// LND→beignet direction).
	node.openChannel(lndPubkey, fundingSats, pushMsat || undefined);

	const cm = node.getChannelManager();
	const deadline = Date.now() + 30_000;
	let funded = cm.listChannels().find((c) => c.getChannelId() !== null);
	while (!funded && Date.now() < deadline) {
		await sleep(500);
		funded = cm.listChannels().find((c) => c.getChannelId() !== null);
	}
	if (!funded) throw new Error('No funded taproot channel after open');
	const channelId = funded.getChannelId()!;
	const fundingTxid = funded.getFullState().fundingTxid;

	if (fundingTxid) {
		const h1 = Buffer.from(fundingTxid).toString('hex');
		const h2 = Buffer.from(fundingTxid).reverse().toString('hex');
		const mp = Date.now() + 15_000;
		while (Date.now() < mp) {
			const mempool = (await bitcoinRpc('getrawmempool')) as string[];
			if (mempool.includes(h1) || mempool.includes(h2)) break;
			await sleep(500);
		}
	}

	await mineBlocks(6);
	await sleep(3000);
	node.handleFundingConfirmed(channelId);

	// Sync beignet's block height to the chain tip so outbound payments set a
	// final CLTV relative to the real height (else LND fails HTLCs "expiry too
	// soon"). currentBlockHeight defaults to 0 with no chain backend in-test.
	const tip = (await bitcoinRpc('getblockcount')) as number;
	node.handleNewBlock(tip);

	await waitForLndChannels(lnd, 1, 60_000);
	return { node, channelId };
}
