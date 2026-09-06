/**
 * Reverse swap with a real Core Lightning client (issue #737): the CLN
 * twin of swap-reverse-lnd.test.ts. CLN opens the channel, pays the hold
 * invoice, the test claims to a CLN address, and the second case proves the
 * refund path releases the payer only at policy depth.
 *
 * Needs the docker stack (bitcoind on 43782, clnrest on 3010). Skips when it
 * is absent unless REQUIRE_SWAP_REGTEST=1.
 */

import { expect } from 'chai';
import { ClnRestClient } from './cln-client';
import {
	isClnAvailable,
	createClnClient,
	fundClnWallet,
	waitForClnSync,
	waitForClnPeerChannelNormal,
	CLN_P2P_HOST,
	CLN_P2P_PORT
} from './cln-helpers';
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

function clnPayer(cln: ClnRestClient): ISwapPayer {
	return {
		pay: async (bolt11) => {
			const res = await cln.pay(bolt11);
			if (res.status !== 'complete') throw new Error(`pay ${res.status}`);
			return { preimageHex: res.payment_preimage };
		},
		status: async (hashHex) => {
			const { pays } = await cln.listPays(hashHex);
			const p = pays.find((x) => x.payment_hash === hashHex);
			if (!p) return 'unknown';
			return p.status;
		},
		newAddress: async () => (await cln.newAddr()).bech32
	};
}

describe('Interop: reverse swap with CLN (issue #737)', function () {
	this.timeout(600_000);

	let cln: ClnRestClient;
	let skipAll = false;
	let scene: ISwapScene | null = null;

	before(async function () {
		this.timeout(120_000);
		const required = process.env.REQUIRE_SWAP_REGTEST === '1';
		try {
			const info = (await bitcoinRpc('getblockchaininfo')) as { chain: string };
			expect(info.chain).to.equal('regtest');
		} catch {
			if (required)
				throw new Error('Required swap regtest node is unavailable');
			skipAll = true;
			this.skip();
			return;
		}
		if (!(await isClnAvailable())) {
			if (required) throw new Error('Required CLN is unavailable');
			skipAll = true;
			console.log('    [skip] CLN container not reachable');
			this.skip();
			return;
		}
		const client = await createClnClient();
		if (!client) {
			if (required) throw new Error('Required CLN is unavailable');
			skipAll = true;
			this.skip();
			return;
		}
		cln = client;
		await ensureBitcoindFunds(3);
		await waitForClnSync(cln);
		const clnPubkey = (await cln.getInfo()).id;

		const chainSource = new CoreSwapChainSource();
		await chainSource.refresh();
		const provider = makeSwapNode('swap-provider-cln', {
			fundingProvider: new BitcoindFundingProvider(),
			feeEstimator: { estimateFee: async () => 2 },
			swaps: { ...SWAP_PROVIDER_CONFIG, chainSource }
		});
		const client2 = makeSwapNode('swap-client-cln');
		const port = await freePort();
		await client2.listen(port);
		await provider.connectPeer(client2.getNodeId(), '127.0.0.1', port);
		await sleep(1_500);

		await fundClnWallet(cln);
		await provider.connectPeer(clnPubkey, CLN_P2P_HOST, CLN_P2P_PORT);
		await sleep(2_000);
		await cln.fundChannel(provider.getNodeId(), 1_000_000);
		await mineBlocks(6);
		await sleep(3_000);
		const channels = provider.getChannelManager().listChannels();
		expect(channels.length, 'provider has the CLN channel').to.be.greaterThan(
			0
		);
		provider.handleFundingConfirmed(channels[0].getChannelId()!);
		await waitForClnPeerChannelNormal(cln, provider.getNodeId());
		const tip = await chainSource.refresh();
		provider.handleNewBlock(tip);
		client2.handleNewBlock(tip);
		await provider.startSwapProvider();
		scene = {
			provider,
			client: client2,
			chain: chainSource,
			payer: clnPayer(cln)
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

	it('CLN pays, the provider funds, the claim settles the hold', async function () {
		const { swapIdHex } = await runReverseSwapHappyPath(scene!);
		expect(
			scene!.provider.listSwaps().find((r) => r.id === swapIdHex)!.state
		).to.equal('SETTLED');
	});

	it('nobody claims: the provider refunds and fails CLN only after the refund confirmed', async function () {
		await runReverseSwapRefundPath(scene!);
	});
});
