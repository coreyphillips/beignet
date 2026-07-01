/**
 * STAGE E — channel_reestablish (MuSig2 nonce re-exchange) over a LIVE
 * beignet→LND simple-taproot channel.
 *
 * Opens a real beignet→LND simple-taproot channel, settles a payment (advancing
 * the commitment past #0), then DISCONNECTS and RECONNECTS the peer. On
 * reconnect beignet sends channel_reestablish carrying its deterministically
 * re-derived MuSig2 verification nonce (next_local_nonce, TLV type 4) and adopts
 * LND's; the channel must resume to NORMAL without LND force-closing, and a
 * SECOND payment must settle over the resumed channel.
 *
 * This is the first validation of the taproot RECONNECT wire format against live
 * LND v0.20 — it pins next_local_nonce (TLV 4) and the post-reconnect nonce
 * semantics, exercising createReestablish → LND → handleReestablish → a fresh
 * commitment round (commitment_signed MuSig2 partial + revoke_and_ack nonce
 * rotation) all vs the live peer. Auto-skips when lnd-taproot is down.
 */

import { expect } from 'chai';
import {
	createLndTaprootClient,
	setupTaprootLndChannel,
	LND_TAPROOT_P2P_HOST,
	LND_TAPROOT_P2P_PORT
} from './lnd-taproot-helpers';
import { setupRoutingForChannel, sleep } from './shared-helpers';
import { waitForInvoiceSettled, waitForLndChannels } from './lnd-helpers';
import { LndRestClient } from './lnd-client';
import { LightningNode } from '../../../src/lightning/node/lightning-node';
import { ChannelState } from '../../../src/lightning/channel/types';

describe('Stage E — beignet→LND simple-taproot reestablish (nonce re-exchange)', function () {
	this.timeout(240_000);

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

	/** Pay an LND-issued invoice over the taproot channel and assert it settles. */
	async function payLnd(
		n: LightningNode,
		client: LndRestClient,
		amountSat: number,
		memo: string
	): Promise<void> {
		const invoice = await client.addInvoice(amountSat, memo);
		const payment = n.sendPayment(invoice.payment_request);
		expect(payment, `payment object (${memo})`).to.have.property('paymentHash');
		const result = await n.waitForPayment(payment.paymentHash, 90_000);
		expect(result, `beignet payment must complete (${memo})`).to.exist;
		const settled = await waitForInvoiceSettled(
			client,
			payment.paymentHash.toString('hex'),
			30_000
		);
		expect(settled.settled, `LND invoice settled (${memo})`).to.be.true;
		expect(BigInt(settled.amtPaidMsat)).to.equal(BigInt(amountSat) * 1000n);
	}

	/** Poll beignet's single channel until it reaches `target` (or throw). */
	async function waitForBeignetChannelState(
		n: LightningNode,
		target: ChannelState,
		timeoutMs: number
	): Promise<void> {
		const cm = n.getChannelManager();
		const deadline = Date.now() + timeoutMs;
		while (Date.now() < deadline) {
			const ch = cm.listChannels()[0];
			if (ch && ch.getState() === target) return;
			await sleep(500);
		}
		const got = cm.listChannels()[0]?.getState();
		throw new Error(
			`beignet channel did not reach ${
				ChannelState[target]
			} within ${timeoutMs}ms (state=${
				got === undefined ? 'none' : ChannelState[got]
			})`
		);
	}

	it('resumes a taproot channel across a reconnect and settles a payment afterward', async function () {
		if (!lnd) {
			this.skip();
			return;
		}

		// Open + drive a beignet→LND simple-taproot channel to active.
		const setup = await setupTaprootLndChannel(lnd, lndPubkey, 4);
		node = setup.node;
		setupRoutingForChannel(node, lndPubkey);
		await sleep(2000);

		// First payment — advances the commitment past #0 so there is real state to
		// preserve across the reconnect (and the verification nonces have rotated).
		await payLnd(node, lnd, 5_000, 'pre-reconnect taproot');
		const beforeNum = node
			.getChannelManager()
			.listChannels()[0]
			.getFullState().localCommitmentNumber;
		expect(beforeNum > 0n, 'commitment advanced before reconnect').to.be.true;

		// ── DISCONNECT ──────────────────────────────────────────────
		node.disconnectPeer(lndPubkey);
		// beignet marks the channel AWAITING_REESTABLISH on peer:disconnect.
		await waitForBeignetChannelState(
			node,
			ChannelState.AWAITING_REESTABLISH,
			15_000
		);

		// ── RECONNECT ───────────────────────────────────────────────
		// On peer:connect beignet sends channel_reestablish (with the
		// deterministically re-derived next_local_nonce TLV); LND replies with its
		// own; both adopt each other's verification nonce and the channel resumes.
		await node.connectPeer(
			lndPubkey,
			LND_TAPROOT_P2P_HOST,
			LND_TAPROOT_P2P_PORT
		);

		// beignet returns to NORMAL once it processes LND's channel_reestablish.
		await waitForBeignetChannelState(node, ChannelState.NORMAL, 30_000);
		// LND re-marks the channel active (peer back online + reestablished).
		await waitForLndChannels(lnd, 1, 60_000);

		// ── POST-RECONNECT PAYMENT ──────────────────────────────────
		// The decisive check: a fresh HTLC + commitment round (MuSig2 partial +
		// nonce rotation) succeeds over the resumed channel, proving the nonce
		// re-exchange in channel_reestablish was accepted by live LND.
		await sleep(2000);
		await payLnd(node, lnd, 4_000, 'post-reconnect taproot');

		const afterNum = node
			.getChannelManager()
			.listChannels()[0]
			.getFullState().localCommitmentNumber;
		expect(afterNum > beforeNum, 'commitment advanced after reconnect').to.be
			.true;
		console.log(
			`\n    ✓ taproot channel reestablished across reconnect; payment settled post-reconnect (commitment ${beforeNum}→${afterNum})`
		);
	});
});
