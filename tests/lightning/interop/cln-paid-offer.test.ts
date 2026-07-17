/**
 * Live paid-offer milestone: beignet PAYS a CLN BOLT 12 offer end to end over
 * a real regtest channel.
 *
 * Exercises the full payer flow the BOLT 12 work built up: decode the lno
 * string (checksum-less bech32, spec subtype layouts), send invoice_request
 * as an onion message, receive CLN's invoice reply over our reply path,
 * validate the mirrored invoice (paths + payinfo), route through the blinded
 * payment path, and settle so CLN marks the offer's invoice paid.
 *
 * Skips cleanly when the CLN container is not running.
 */

import { expect } from 'chai';
import { ClnRestClient } from './cln-client';
import {
	isClnAvailable,
	createClnClient,
	waitForClnSync,
	waitForClnPeerChannelNormal,
	setupBeignetFundedClnChannel,
	waitFor,
	sleep
} from './cln-helpers';
import { ChannelState } from '../../../src/lightning/channel/types';
import {
	setupRoutingForChannel,
	mineBlocks,
	bitcoinRpc
} from './shared-helpers';
import { LightningNode } from '../../../src/lightning/node/lightning-node';
import { decodeOffer } from '../../../src/lightning/offer/decode';
import { Feature } from '../../../src/lightning/features/flags';
import { PaymentStatus } from '../../../src/lightning/node/types';

describe('Interop: Beignet pays a CLN BOLT 12 offer (regtest)', function () {
	this.timeout(240_000);

	let cln: ClnRestClient;
	let clnPubkey: string;
	let node: LightningNode | undefined;
	let skipAll = false;

	before(async function () {
		const available = await isClnAvailable();
		if (!available) {
			skipAll = true;
			console.log('    ⚠ CLN not available — skipping paid-offer milestone.');
			this.skip();
			return;
		}
		const client = await createClnClient();
		if (!client) {
			skipAll = true;
			this.skip();
			return;
		}
		cln = client;
		await waitForClnSync(cln);
		const info = await cln.getInfo();
		clnPubkey = info.id;
	});

	afterEach(function () {
		if (node) {
			node.destroy();
			node = undefined;
		}
	});

	it('decodes the offer, fetches the invoice via onion message, and pays it', async function () {
		if (skipAll) this.skip();

		// A beignet-funded channel so we hold the outbound liquidity, with the
		// onion-message + route-blinding feature bits the offer flow needs.
		const setup = await setupBeignetFundedClnChannel(
			cln,
			clnPubkey,
			250,
			1_000_000n,
			[Feature.ONION_MESSAGES, Feature.ROUTE_BLINDING]
		);
		node = setup.node;

		// The funding broadcast is asynchronous and can land after the helper's
		// own mining; mine again so the funding tx confirms for sure.
		await mineBlocks(6);
		await sleep(2000);
		const chId = setup.channelId;
		node.handleFundingConfirmed(chId);

		// The payment leg needs the channel USABLE, not just opened: wait for
		// NORMAL on both sides before wiring routing (the scid lands then too).
		await waitForClnPeerChannelNormal(cln, node.getNodeId(), 90_000);
		const normal = await waitFor(() => {
			const ch = node!.getChannelManager().getChannel(setup.channelId);
			return ch && ch.getState() === ChannelState.NORMAL ? ch : null;
		}, 60_000);
		expect(normal, 'beignet channel NORMAL').to.not.equal(null);
		// Sync beignet's block height so the payment's absolute CLTV is relative
		// to the real tip (defaults to 0 with no chain backend in-test, which the
		// recipient rejects as incorrect_or_unknown_payment_details).
		const tip = (await bitcoinRpc('getblockcount')) as number;
		node.handleNewBlock(tip);
		setupRoutingForChannel(node, clnPubkey);

		// CLN publishes an offer with a fixed amount.
		const amountMsat = 25_000_000n;
		const offerResult = await cln.createOffer(
			`${amountMsat}msat`,
			`beignet paid-offer milestone ${Date.now()}`
		);
		expect(offerResult.bolt12.startsWith('lno')).to.equal(true);

		// beignet decodes the live lno string.
		const offer = decodeOffer(offerResult.bolt12);
		expect(offer.amount).to.equal(amountMsat);

		// invoice_request goes out as an onion message; CLN's offers subsystem
		// replies with a signed BOLT 12 invoice over our reply path.
		const invoice = await node.requestInvoice(offer, { timeoutMs: 60_000 });
		expect(invoice.paymentHash, 'invoice carries a payment hash').to.exist;
		expect(invoice.amount).to.equal(amountMsat);
		expect(
			invoice.paths && invoice.paths.length > 0,
			'invoice carries blinded payment paths'
		).to.equal(true);
		console.log(
			`    invoice: ${invoice.paths!.length} blinded path(s), intro ${invoice
				.paths![0].introductionNodeId.toString('hex')
				.slice(0, 16)}..., ${invoice.paths![0].blindedHops.length} hop(s)`
		);

		// Pay it through the blinded path and wait for settlement.
		const payment = node.payBolt12Invoice(invoice);
		expect(payment.paymentHash).to.exist;

		const hashHex = invoice.paymentHash!.toString('hex');
		const paidInvoice = await waitFor(async () => {
			const { invoices } = await cln.listInvoices();
			const inv = invoices.find((i) => i.payment_hash === hashHex);
			return inv && inv.status === 'paid' ? inv : null;
		}, 90_000);
		expect(paidInvoice, 'CLN invoice for the offer marked paid').to.not.equal(
			null
		);

		// Our own payment record settled too.
		const settled = await waitFor(() => {
			const p = node!
				.listPayments()
				.find((x) => x.paymentHash.toString('hex') === hashHex);
			return p && p.status === PaymentStatus.COMPLETED ? p : null;
		}, 30_000);
		expect(settled, 'beignet payment record SUCCEEDED').to.not.equal(null);

		await sleep(500);
	});
});
