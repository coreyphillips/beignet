/**
 * STAGE E — payment over a LIVE beignet→LND simple-taproot channel.
 *
 * Opens a real beignet→LND simple-taproot channel (capstone flow), then routes
 * a real HTLC payment beignet→LND and asserts it SETTLES on both sides. This is
 * the first validation of the taproot COMMITMENT-UPDATE wire format against live
 * LND: update_add_htlc → commitment_signed (MuSig2 partial sig over the funding
 * key-spend + per-HTLC BIP340 second-level Schnorr sigs) → revoke_and_ack (with
 * verification-nonce rotation) → update_fulfill_htlc → another commitment round.
 *
 * beignet is the funder (all outbound liquidity), so the testable direction is
 * beignet→LND — which is also the critical one: LND must VERIFY beignet's
 * taproot commitment + HTLC signatures. Auto-skips when lnd-taproot is down.
 */

import { expect } from 'chai';
import {
	createLndTaprootClient,
	setupTaprootLndChannel
} from './lnd-taproot-helpers';
import { setupRoutingForChannel, sleep } from './shared-helpers';
import { waitForInvoiceSettled } from './lnd-helpers';
import { LndRestClient } from './lnd-client';
import { LightningNode } from '../../../src/lightning/node/lightning-node';

describe('Stage E — beignet→LND simple-taproot payment (HTLC round)', function () {
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

	it('routes a real HTLC over the taproot channel and settles both sides', async function () {
		if (!lnd) {
			this.skip();
			return;
		}

		// Open + drive a beignet→LND simple-taproot channel to active.
		const setup = await setupTaprootLndChannel(lnd, lndPubkey, 3);
		node = setup.node;

		// Register the channel SCID + synthetic graph edges so beignet can route
		// directly to LND (the channel is private/unannounced for taproot).
		setupRoutingForChannel(node, lndPubkey);
		await sleep(2000);

		// LND creates an invoice; beignet pays it over the taproot channel.
		const amountSat = 5_000;
		const lndInvoice = await lnd.addInvoice(amountSat, 'beignet→LND taproot');
		const payment = node.sendPayment(lndInvoice.payment_request);
		expect(payment).to.have.property('paymentHash');

		// Strict: beignet's payment completes (preimage received from LND) — proves
		// LND accepted beignet's taproot commitment_signed + HTLC sigs, fulfilled,
		// and the second commitment round (with nonce rotation) succeeded.
		const result = await node.waitForPayment(payment.paymentHash, 90_000);
		expect(result, 'beignet payment must complete').to.exist;

		// Strict: LND reports the invoice SETTLED for the full amount.
		const rHashHex = payment.paymentHash.toString('hex');
		const settled = await waitForInvoiceSettled(lnd, rHashHex, 30_000);
		expect(settled.settled, 'LND invoice must be settled').to.be.true;
		expect(BigInt(settled.amtPaidMsat)).to.equal(BigInt(amountSat) * 1000n);
		console.log(
			`\n    ✓ taproot payment settled: ${amountSat} sat beignet→LND (amt_paid_msat=${settled.amtPaidMsat})`
		);
	});
});
