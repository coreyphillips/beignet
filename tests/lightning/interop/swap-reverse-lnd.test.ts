/**
 * Reverse swap with a real LND client (issue #737): LND opens a channel to
 * an in-process beignet provider, pays the provider's hold invoice, the
 * provider funds the P2WSH contract with Bitcoin Core's wallet, the test
 * claims to LND's own address and LND's payment completes with the preimage.
 * The second case lets nobody claim and proves the payer fails only once the
 * provider's refund has confirmed to policy depth.
 *
 * Needs the docker stack (bitcoind on 43782, LND REST on LND_REST_PORT).
 * Skips when it is absent unless REQUIRE_SWAP_REGTEST=1.
 */

import { expect } from 'chai';
import { LndRestClient } from './lnd-client';
import {
	requireLnd,
	cleanupLndState,
	fundLndWallet,
	waitForLndChannels,
	waitForLndSync,
	LND_P2P_HOST,
	LND_P2P_PORT
} from './lnd-helpers';
import {
	BitcoindFundingProvider,
	bitcoinRpc,
	ensureBitcoindFunds,
	mineBlocks,
	sleep
} from './shared-helpers';
import {
	CoreSwapChainSource,
	ISwapPayer,
	ISwapScene,
	SWAP_PROVIDER_CONFIG,
	freePort,
	makeSwapNode,
	runReverseSwapHappyPath,
	runReverseSwapRefundPath
} from './swap-helpers';

function lndPayer(lnd: LndRestClient): ISwapPayer {
	return {
		pay: async (bolt11) => {
			const res = await lnd.sendPaymentSync(bolt11);
			if (res.payment_error) throw new Error(res.payment_error);
			return {
				preimageHex: Buffer.from(res.payment_preimage, 'base64').toString('hex')
			};
		},
		status: async (hashHex) => {
			const { payments } = await lnd.listPayments();
			const p = payments.find((x) => x.payment_hash === hashHex);
			if (!p) return 'unknown';
			if (p.status === 'SUCCEEDED') return 'complete';
			if (p.status === 'FAILED') return 'failed';
			return 'pending';
		},
		newAddress: async () => (await lnd.newAddress()).address
	};
}

describe('Interop: reverse swap with LND (issue #737)', function () {
	this.timeout(600_000);

	let lnd: LndRestClient;
	let skipAll = false;
	let scene: ISwapScene | null = null;

	before(async function () {
		this.timeout(120_000);
		const required = process.env.REQUIRE_SWAP_REGTEST === '1';
		let chain: string;
		try {
			chain = ((await bitcoinRpc('getblockchaininfo')) as { chain: string })
				.chain;
		} catch {
			if (required)
				throw new Error('Required swap regtest node is unavailable');
			skipAll = true;
			this.skip();
			return;
		}
		expect(chain).to.equal('regtest');
		// REQUIRE_SWAP_REGTEST keeps its old meaning for this suite's LND leg;
		// INTEROP_REQUIRE_LND is read by the helper.
		lnd = await requireLnd(this, 'swap-reverse-lnd', { required });
		await ensureBitcoindFunds(3);
		await waitForLndSync(lnd);
		await cleanupLndState(lnd);
		const lndPubkey = (await lnd.getInfo()).identity_pubkey;

		const chainSource = new CoreSwapChainSource();
		await chainSource.refresh();
		const provider = makeSwapNode('swap-provider-lnd', {
			fundingProvider: new BitcoindFundingProvider(),
			feeEstimator: { estimateFee: async () => 2 },
			swaps: { ...SWAP_PROVIDER_CONFIG, chainSource }
		});
		const client2 = makeSwapNode('swap-client-lnd');
		const port = await freePort();
		await client2.listen(port);
		await provider.connectPeer(client2.getNodeId(), '127.0.0.1', port);
		await sleep(1_500);

		await fundLndWallet(lnd, 110);
		await provider.connectPeer(lndPubkey, LND_P2P_HOST, LND_P2P_PORT);
		await sleep(2_000);
		await lnd.openChannelSync(provider.getNodeId(), 1_000_000, 0);
		await mineBlocks(6);
		await sleep(3_000);
		const channels = provider.getChannelManager().listChannels();
		expect(channels.length, 'provider has the LND channel').to.be.greaterThan(
			0
		);
		provider.handleFundingConfirmed(channels[0].getChannelId()!);
		await waitForLndChannels(lnd, 1, 30_000);
		const tip = await chainSource.refresh();
		provider.handleNewBlock(tip);
		client2.handleNewBlock(tip);
		await provider.startSwapProvider();
		scene = {
			provider,
			client: client2,
			chain: chainSource,
			payer: lndPayer(lnd)
		};
	});

	beforeEach(function () {
		if (skipAll) this.skip();
	});

	after(function () {
		try {
			scene?.client.destroy();
			scene?.provider.destroy();
		} catch {
			/* ignore */
		}
	});

	it('LND pays, the provider funds, the claim settles the hold', async function () {
		const { swapIdHex } = await runReverseSwapHappyPath(scene!);
		expect(
			scene!.provider.listSwaps().find((r) => r.id === swapIdHex)!.state
		).to.equal('SETTLED');
	});

	it('nobody claims: the provider refunds and fails LND only after the refund confirmed', async function () {
		await runReverseSwapRefundPath(scene!);
	});
});
