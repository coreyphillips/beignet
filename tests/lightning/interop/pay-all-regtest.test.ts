import { expect } from 'chai';
import { LightningNode } from '../../../src/lightning/node/lightning-node';
import { PaymentStatus } from '../../../src/lightning/node/types';
import { ChannelState } from '../../../src/lightning/channel/types';
import {
	isClnAvailable,
	createClnClient,
	waitForClnSync,
	setupClnChannel,
	setupRoutingForChannel,
	waitFor
} from './cln-helpers';
import { bitcoinRpc } from './shared-helpers';

describe('Interop: pay-all to CLN (live)', function () {
	this.timeout(180_000);
	let node: LightningNode | undefined;
	afterEach(() => node?.destroy());

	it('settles the exact reviewed debit and retains the ordinary peer reserve', async function () {
		if (!(await isClnAvailable())) {
			this.skip();
			return;
		}
		const cln = await createClnClient();
		if (!cln) {
			this.skip();
			return;
		}
		await waitForClnSync(cln);
		const peer = (await cln.getInfo()).id;
		const setup = await setupClnChannel(
			cln,
			peer,
			Date.now(),
			1_000_000,
			300_000_001
		);
		node = setup.node;
		setupRoutingForChannel(node, peer);
		node.handleNewBlock((await bitcoinRpc('getblockcount')) as number);
		const channel = node.getChannelManager().getChannel(setup.channelId)!;
		await waitFor(
			() => {
				const state = channel.getFullState();
				return state.state === ChannelState.NORMAL &&
					state.pendingFeeratePerKw === undefined
					? true
					: null;
			},
			30_000,
			'settled opening commitment'
		);
		const reserve = channel.getFullState().remoteConfig.channelReserveSatoshis;
		expect(reserve > 0n).to.equal(true);
		const label = `pay-all-${Date.now()}`;
		const invoice = await cln.createInvoice(
			'any',
			label,
			'exact debit interoperability'
		);
		const before = channel.getFullState().localBalanceMsat;
		const quote = node.quotePayAll(invoice.bolt11, 0n);
		expect(quote.routeFound).to.equal(true);
		expect(quote.debitMsat % 1000n).to.equal(1n);
		node.sendPayAll(invoice.bolt11, quote.debitMsat, quote.maxFeeMsat);
		const payment = await node.waitForPayment(
			Buffer.from(invoice.payment_hash, 'hex'),
			60_000
		);
		expect(payment.status).to.equal(PaymentStatus.COMPLETED);
		expect(payment.payAll).to.deep.equal({
			debitMsat: quote.debitMsat,
			maxFeeMsat: 0n,
			deliveredMsat: quote.debitMsat,
			feeMsat: 0n,
			remainderMsat: 0n
		});
		const paid = await waitFor(
			async () => {
				const row = (await cln.listInvoices(label)).invoices[0];
				return row?.status === 'paid' ? row : null;
			},
			15_000,
			'CLN invoice settled'
		);
		expect(
			BigInt(String(paid.amount_received_msat).replace(/msat$/, ''))
		).to.equal(quote.debitMsat);
		expect(before - channel.getFullState().localBalanceMsat).to.equal(
			quote.debitMsat
		);
		expect(channel.getSpendableOutboundMsat()).to.equal(0n);
		expect(channel.getFullState().localBalanceMsat >= reserve * 1000n).to.equal(
			true
		);
		expect(channel.getState()).to.equal(ChannelState.NORMAL);
	});
});
