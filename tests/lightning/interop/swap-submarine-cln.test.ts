/**
 * Submarine swap with a real CLN client (issue #743): an in-process beignet
 * provider opens a channel TO CLN, CLN mints the invoice, the test funds the
 * contract from Bitcoin Core's wallet, the provider pays CLN under the
 * ceiling, CLN settles, the provider claims and confirms. The second case
 * deletes CLN's unpaid invoice so the HTLC fails back on arrival: the swap
 * ends PAYMENT_FAILED with no claim and the test refunds after the height.
 *
 * Needs the docker stack (bitcoind on 43782, CLN REST on 3010). Skips when
 * it is absent unless REQUIRE_SWAP_REGTEST=1.
 */

import crypto from 'crypto';
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
	sleep
} from './shared-helpers';
import {
	CoreSwapChainSource,
	ISubmarineInvoicer,
	ISubmarineScene,
	SUBMARINE_PROVIDER_CONFIG,
	freePort,
	makeSwapNode,
	openBeignetFundedChannelTo,
	runSubmarineSwapHappyPath,
	runSubmarineSwapRefundPath
} from './swap-helpers';

function clnInvoicer(cln: ClnRestClient): ISubmarineInvoicer {
	return {
		createInvoice: async (amountMsat) => {
			const label = `submarine-${crypto.randomBytes(6).toString('hex')}`;
			const inv = await cln.createInvoice(
				amountMsat.toString(),
				label,
				'submarine swap'
			);
			return {
				bolt11: inv.bolt11,
				paymentHashHex: inv.payment_hash,
				handle: label
			};
		},
		failUnpaid: async (label) => {
			// CLN has no hold invoices: deleting the unpaid invoice makes it
			// fail the HTLC with an unknown-payment error on arrival.
			await cln.delInvoice(label, 'unpaid');
		},
		invoiceState: async (paymentHashHex) => {
			const { invoices } = await cln.listInvoices();
			const inv = invoices.find((i) => i.payment_hash === paymentHashHex);
			if (!inv) return 'unknown';
			if (inv.status === 'paid') return 'settled';
			if (inv.status === 'expired') return 'cancelled';
			return 'open';
		},
		newAddress: async () => (await cln.newAddr()).bech32
	};
}

describe('Interop: submarine swap with CLN (issue #743)', function () {
	this.timeout(900_000);

	let cln: ClnRestClient;
	let skipAll = false;
	let scene: ISubmarineScene | null = null;

	before(async function () {
		this.timeout(180_000);
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
		await fundClnWallet(cln);
		const clnPubkey = (await cln.getInfo()).id;

		const chainSource = new CoreSwapChainSource();
		await chainSource.refresh();
		const provider = makeSwapNode('submarine-provider-cln', {
			fundingProvider: new BitcoindFundingProvider(),
			feeEstimator: { estimateFee: async () => 2 },
			swaps: { ...SUBMARINE_PROVIDER_CONFIG, chainSource }
		});
		const client2 = makeSwapNode('submarine-client-cln');
		const port = await freePort();
		await client2.listen(port);
		await provider.connectPeer(client2.getNodeId(), '127.0.0.1', port);
		await sleep(1_500);

		await openBeignetFundedChannelTo(
			provider,
			clnPubkey,
			CLN_P2P_HOST,
			CLN_P2P_PORT,
			1_000_000n,
			() => waitForClnPeerChannelNormal(cln, provider.getNodeId())
		);
		const tip = await chainSource.refresh();
		provider.handleNewBlock(tip);
		client2.handleNewBlock(tip);
		await provider.startSwapProvider();
		scene = {
			provider,
			client: client2,
			chain: chainSource,
			invoicer: clnInvoicer(cln)
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

	it('CLN invoices, Core funds the contract, the provider pays under the ceiling and claims', async function () {
		const { swapIdHex } = await runSubmarineSwapHappyPath(scene!);
		expect(
			scene!.provider.listSwaps().find((r) => r.id === swapIdHex)!.state
		).to.equal('CLAIM_CONFIRMED');
	});

	it('CLN deletes the unpaid invoice: the swap fails with no claim and the client refunds after the height', async function () {
		await runSubmarineSwapRefundPath(scene!);
	});
});
