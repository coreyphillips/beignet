/**
 * Submarine swap with a real LND client (issue #743): an in-process beignet
 * provider opens a channel TO LND (it pays, so it needs outbound), LND mints
 * the invoice, the test funds the contract from Bitcoin Core's wallet, the
 * provider pays LND under the ceiling, LND settles, the preimage reaches the
 * provider through payment:preimage and the provider claims and confirms.
 * The second case has LND hold and then cancel the payment: the provider's
 * HTLC fails back, the swap ends PAYMENT_FAILED with no claim, and the test
 * refunds the contract after the refund height.
 *
 * Needs the docker stack (bitcoind on 43782, LND REST on LND_REST_PORT).
 * Skips when it is absent unless REQUIRE_SWAP_REGTEST=1.
 */

import crypto from 'crypto';
import { expect } from 'chai';
import { LndRestClient } from './lnd-client';
import {
	isLndAvailable,
	createLndClient,
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

function lndInvoicer(lnd: LndRestClient): ISubmarineInvoicer {
	return {
		createInvoice: async (amountMsat, options = {}) => {
			const valueSat = Number(amountMsat / 1000n);
			if (options.failable) {
				// A hold invoice on a hash the test knows: LND parks the HTLC
				// until the test cancels it.
				const preimage = crypto.randomBytes(32);
				const hashHex = crypto
					.createHash('sha256')
					.update(preimage)
					.digest('hex');
				const hold = await lnd.addHoldInvoice(hashHex, valueSat);
				return {
					bolt11: hold.payment_request,
					paymentHashHex: hashHex,
					handle: hashHex
				};
			}
			const inv = await lnd.addInvoice(valueSat, 'submarine swap');
			return {
				bolt11: inv.payment_request,
				paymentHashHex: Buffer.from(inv.r_hash, 'base64').toString('hex'),
				handle: ''
			};
		},
		failUnpaid: async (_handle, paymentHashHex) => {
			await lnd.cancelHoldInvoice(paymentHashHex);
		},
		invoiceState: async (paymentHashHex) => {
			try {
				const inv = await lnd.lookupInvoice(paymentHashHex);
				if (inv.state === 'SETTLED' || inv.settled) return 'settled';
				if (inv.state === 'CANCELED') return 'cancelled';
				if (inv.state === 'ACCEPTED') return 'accepted';
				return 'open';
			} catch {
				return 'unknown';
			}
		},
		newAddress: async () => (await lnd.newAddress()).address
	};
}

describe('Interop: submarine swap with LND (issue #743)', function () {
	this.timeout(900_000);

	let lnd: LndRestClient;
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
		if (!(await isLndAvailable())) {
			if (required) throw new Error('Required LND is unavailable');
			skipAll = true;
			console.log('    [skip] LND container not reachable');
			this.skip();
			return;
		}
		const client = await createLndClient();
		if (!client) {
			if (required) throw new Error('Required LND is unavailable');
			skipAll = true;
			this.skip();
			return;
		}
		lnd = client;
		await ensureBitcoindFunds(3);
		await waitForLndSync(lnd);
		await cleanupLndState(lnd);
		await fundLndWallet(lnd, 10);
		const lndPubkey = (await lnd.getInfo()).identity_pubkey;

		const chainSource = new CoreSwapChainSource();
		await chainSource.refresh();
		const provider = makeSwapNode('submarine-provider-lnd', {
			fundingProvider: new BitcoindFundingProvider(),
			feeEstimator: { estimateFee: async () => 2 },
			swaps: { ...SUBMARINE_PROVIDER_CONFIG, chainSource }
		});
		const client2 = makeSwapNode('submarine-client-lnd');
		const port = await freePort();
		await client2.listen(port);
		await provider.connectPeer(client2.getNodeId(), '127.0.0.1', port);
		await sleep(1_500);

		// The provider pays LND: it opens and funds the channel.
		await openBeignetFundedChannelTo(
			provider,
			lndPubkey,
			LND_P2P_HOST,
			LND_P2P_PORT,
			1_000_000n,
			() => waitForLndChannels(lnd, 1, 60_000)
		);
		const tip = await chainSource.refresh();
		provider.handleNewBlock(tip);
		client2.handleNewBlock(tip);
		await provider.startSwapProvider();
		scene = {
			provider,
			client: client2,
			chain: chainSource,
			invoicer: lndInvoicer(lnd)
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

	it('LND invoices, Core funds the contract, the provider pays under the ceiling and claims', async function () {
		const { swapIdHex } = await runSubmarineSwapHappyPath(scene!);
		expect(
			scene!.provider.listSwaps().find((r) => r.id === swapIdHex)!.state
		).to.equal('CLAIM_CONFIRMED');
	});

	it('LND holds then cancels: the swap fails with no claim and the client refunds after the height', async function () {
		await runSubmarineSwapRefundPath(scene!);
	});
});
