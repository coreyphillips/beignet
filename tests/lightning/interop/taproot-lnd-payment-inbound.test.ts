/**
 * STAGE E — LND→beignet payment over a LIVE simple-taproot channel.
 *
 * The mirror of taproot-lnd-payment.test.ts. The channel is opened with a push
 * so LND has outbound liquidity, then LND pays a beignet invoice. This exercises
 * the RECEIVE side of the taproot commitment-update flow: beignet must VERIFY
 * LND's commitment_signed (LND's MuSig2 partial over beignet's commitment + LND's
 * per-HTLC BIP340 second-level Schnorr sig), rotate its verification nonce, and
 * fulfill — the opposite of the beignet→LND test, which validated beignet
 * PRODUCING those signatures. Auto-skips when lnd-taproot is down.
 */

import { expect } from 'chai';
import {
	createLndTaprootClient,
	setupTaprootLndChannel
} from './lnd-taproot-helpers';
import { setupRoutingForChannel, sleep } from './shared-helpers';
import { LndRestClient } from './lnd-client';
import { LightningNode } from '../../../src/lightning/node/lightning-node';

describe('Stage E — LND→beignet simple-taproot payment (inbound HTLC)', function () {
	this.timeout(180_000);

	let lnd: LndRestClient | null = null;
	let lndPubkey = '';
	let node: LightningNode | null = null;

	before(async function () {
		lnd = await createLndTaprootClient();
		if (!lnd) {
			console.log('    [skip] lnd-taproot not reachable (REST 8082)');
			this.skip();
			return;
		}
		lndPubkey = (await lnd.getInfo()).identity_pubkey;
	});

	after(function () {
		if (node) {
			try {
				node.disconnectPeer(lndPubkey);
			} catch {
				/* ignore */
			}
			try {
				node.destroy();
			} catch {
				/* ignore */
			}
		}
	});

	it('LND pays a beignet invoice over the taproot channel (beignet verifies + fulfills)', async function () {
		if (!lnd) {
			this.skip();
			return;
		}

		// Open with a 100k-sat push so LND has outbound liquidity to spend.
		const setup = await setupTaprootLndChannel(
			lnd,
			lndPubkey,
			4,
			200_000n,
			100_000_000n
		);
		node = setup.node;

		// Register SCID + synthetic edges; the beignet invoice also carries a
		// private-channel routing hint so LND can route inbound to beignet.
		setupRoutingForChannel(node, lndPubkey);
		await sleep(2000);

		const amountMsat = 5_000_000n; // 5000 sat
		const invoice = node.createInvoice({
			amountMsat,
			description: 'LND→beignet taproot'
		});

		// LND pays beignet's invoice. Success means beignet verified LND's taproot
		// commitment + HTLC sigs, advanced the commitment, and returned the preimage.
		const payResult = await lnd.sendPaymentSync(invoice.bolt11);
		expect(
			payResult.payment_error,
			`LND payment failed: ${payResult.payment_error}`
		).to.be.oneOf(['', undefined]);
		expect(payResult.payment_preimage, 'LND must receive a preimage').to.have
			.length.greaterThan(0);

		// Cross-check: beignet recorded the payment as received/settled.
		await sleep(1000);
		const received = node.waitForPayment(invoice.paymentHash, 15_000);
		await received;
		console.log(
			`\n    ✓ inbound taproot payment settled: 5000 sat LND→beignet`
		);
	});
});
