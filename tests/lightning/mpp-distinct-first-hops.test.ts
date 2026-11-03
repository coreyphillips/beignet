/**
 * MPP across distinct first-hop peers (issue #1922, step 3).
 *
 * A wallet W holds channels with several primaries, each of which has a
 * channel to the recipient D. An invoice from D larger than any one W channel's
 * spendable balance, but within their sum, must complete with one part per
 * primary. The splitter already walked every local channel; what failed was
 * its sizing (a halved part left later parts to run out before the amount
 * did) and the four-part default once a wallet holds more channels than that.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { PaymentStatus } from '../../src/lightning/node/types';
import { ChannelState } from '../../src/lightning/channel/types';
import { encodeShortChannelId } from '../../src/lightning/gossip/types';
import { MessageType } from '../../src/lightning/message/types';
import { encode as encodeInvoice } from '../../src/lightning/invoice/encode';
import { decode as decodeInvoice } from '../../src/lightning/invoice/decode';
import { Network } from '../../src/lightning/invoice/types';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	createNode,
	destroyAll,
	nodePrivkey,
	settle,
	waitFor,
	wire
} from './helpers/async-world';
import { writableState } from './helpers/writable-state';

interface IPrimary {
	node: LightningNode;
	/** W's channel with this primary. */
	wChannelId: Buffer;
	/** This primary's channel with D. */
	dChannelId: Buffer;
	/** Adds this primary forwarded to D. */
	forwards: number;
}

interface IWorld {
	w: LightningNode;
	d: LightningNode;
	primaries: IPrimary[];
	/** update_add_htlc messages W sent, one per part. */
	wAdds: number;
	spendable: bigint[];
	nodes: LightningNode[];
}

async function openChannelOf(
	opener: LightningNode,
	acceptor: LightningNode,
	fundingSatoshis: bigint
): Promise<Buffer> {
	const channel = opener.openChannel(acceptor.getNodeId(), fundingSatoshis);
	const channelId = opener.createFunding(
		channel,
		crypto.randomBytes(32),
		0,
		crypto.randomBytes(64)
	)!;
	await waitFor(
		() => channel.getState() !== ChannelState.SENT_FUNDING_CREATED,
		'funding_signed to arrive'
	);
	opener.handleFundingConfirmed(channelId);
	acceptor.handleFundingConfirmed(channelId);
	await waitFor(
		() => channel.getState() === ChannelState.NORMAL,
		'the opened channel to reach NORMAL'
	);
	return channelId;
}

/**
 * W opens one channel per entry of `wChannelSats` to a fresh primary, and each
 * primary opens a 1M-sat channel to D, so D has inbound on every primary and W
 * holds the balance on its side. The P-D channels are private: D's invoice
 * hints them by the alias the primary chose, which the primary forwards over
 * once registered, as the async-world setup does.
 */
async function buildWorld(
	seedBase: number,
	wChannelSats: bigint[]
): Promise<IWorld> {
	const w = createNode(seedBase);
	const d = createNode(seedBase + 1);
	const primaries: IPrimary[] = [];
	for (let i = 0; i < wChannelSats.length; i++) {
		const node = createNode(seedBase + 2 + i);
		wire(w, node, { val: false });
		wire(node, d, { val: false });
		const wChannelId = await openChannelOf(w, node, wChannelSats[i]);
		const dChannelId = await openChannelOf(node, d, 1_000_000n);
		const primary: IPrimary = { node, wChannelId, dChannelId, forwards: 0 };
		node.on('htlc:forward', () => {
			primary.forwards++;
		});
		primaries.push(primary);
	}
	const nodes = [w, d, ...primaries.map((p) => p.node)];
	await waitFor(
		() =>
			nodes.every((n) =>
				n
					.getChannelManager()
					.listChannels()
					.every((c) => c.getState() === ChannelState.NORMAL)
			),
		'every channel on every node to reach NORMAL'
	);
	primaries.forEach((p, i) => {
		const scid = encodeShortChannelId({
			block: 840,
			txIndex: i + 1,
			outputIndex: 0
		});
		p.node.registerChannelScid(p.dChannelId, scid);
		writableState(
			p.node.getChannelManager().getChannel(p.dChannelId)!
		).remoteScidAlias = scid;
		writableState(
			d.getChannelManager().getChannel(p.dChannelId)!
		).remoteScidAlias = scid;
	});
	const world: IWorld = {
		w,
		d,
		primaries,
		wAdds: 0,
		spendable: primaries.map((p) =>
			w.getChannelManager().getChannel(p.wChannelId)!.getSpendableOutboundMsat()
		),
		nodes
	};
	w.on('message:outbound', (_pk: string, type: number) => {
		if (type === MessageType.UPDATE_ADD_HTLC) world.wAdds++;
	});
	return world;
}

const sum = (values: bigint[]): bigint => values.reduce((a, b) => a + b, 0n);

/** Fees the parts pay their primaries, generously. */
const FEE_MARGIN_MSAT = 100_000n;

async function payAndSettle(
	world: IWorld,
	bolt11: string,
	paymentHash: Buffer
): Promise<void> {
	world.w.sendPayment(bolt11);
	await waitFor(
		() => world.w.getPayment(paymentHash)?.status === PaymentStatus.COMPLETED,
		'the payment to complete on W'
	);
	expect(world.d.getPayment(paymentHash)?.status).to.equal(
		PaymentStatus.COMPLETED
	);
}

describe('MPP across distinct first-hop peers (issue #1922)', function () {
	it('a payment larger than either channel completes with one part over each of two primaries', async function () {
		this.timeout(30_000);
		const world = await buildWorld(7100, [200_000n, 200_000n]);
		const { spendable } = world;
		const amountMsat = sum(spendable) - FEE_MARGIN_MSAT;
		expect(
			spendable.every((s) => amountMsat > s),
			'neither channel carries it alone'
		).to.equal(true);

		const invoice = world.d.createInvoice({
			amountMsat,
			description: 'two primaries'
		});
		await payAndSettle(world, invoice.bolt11, invoice.paymentHash);

		expect(world.wAdds, 'one part per primary').to.equal(2);
		expect(world.primaries.map((p) => p.forwards)).to.deep.equal([1, 1]);
		destroyAll(...world.nodes);
	});

	it('without basic_mpp on the invoice the payment is still not split', async function () {
		this.timeout(30_000);
		const seedBase = 7120;
		const world = await buildWorld(seedBase, [200_000n, 200_000n]);
		const amountMsat = sum(world.spendable) - FEE_MARGIN_MSAT;

		// D's own invoice, re-signed with its hints and secret but no basic_mpp.
		const template = decodeInvoice(
			world.d.createInvoice({ amountMsat, description: 'template' }).bolt11
		);
		const features = FeatureFlags.empty();
		features.setCompulsory(Feature.TLV_ONION);
		features.setCompulsory(Feature.PAYMENT_SECRET);
		const dKey = nodePrivkey(seedBase + 1);
		const bolt11 = encodeInvoice({
			network: Network.REGTEST,
			paymentHash: template.paymentHash,
			paymentSecret: template.paymentSecret,
			description: 'no basic_mpp',
			amountMsat,
			payeeNodeKey: getPublicKey(dKey),
			privateKey: dKey,
			featureBits: features,
			routingHints: template.routingHints
		});
		expect(template.routingHints?.length, 'a hint per primary').to.equal(2);

		expect(() => world.w.sendPayment(bolt11)).to.throw('No route found');
		expect(world.wAdds).to.equal(0);
		destroyAll(...world.nodes);
	});

	it('five primaries carry a payment that needs all five, past the four-part default', async function () {
		this.timeout(60_000);
		const world = await buildWorld(7140, [
			100_000n,
			100_000n,
			100_000n,
			100_000n,
			100_000n
		]);
		const { spendable } = world;
		const amountMsat = sum(spendable) - FEE_MARGIN_MSAT;
		const largestFour = sum(
			[...spendable].sort((a, b) => (a < b ? 1 : -1)).slice(0, 4)
		);
		expect(amountMsat > largestFour, 'four channels do not carry it').to.equal(
			true
		);

		const invoice = world.d.createInvoice({
			amountMsat,
			description: 'five primaries'
		});
		await payAndSettle(world, invoice.bolt11, invoice.paymentHash);

		expect(world.wAdds, 'one part per primary').to.equal(5);
		expect(world.primaries.map((p) => p.forwards)).to.deep.equal([
			1, 1, 1, 1, 1
		]);
		destroyAll(...world.nodes);
	});

	it('a 100k and a 20k channel pay their sum in two parts, not four halvings and a refusal', async function () {
		this.timeout(30_000);
		const world = await buildWorld(7160, [100_000n, 20_000n]);
		const { spendable } = world;
		const amountMsat = sum(spendable) - FEE_MARGIN_MSAT;
		expect(amountMsat > spendable[0]).to.equal(true);

		const invoice = world.d.createInvoice({
			amountMsat,
			description: 'uneven primaries'
		});
		await payAndSettle(world, invoice.bolt11, invoice.paymentHash);

		expect(world.wAdds, 'one part per primary').to.equal(2);
		expect(world.primaries.map((p) => p.forwards)).to.deep.equal([1, 1]);
		destroyAll(...world.nodes);
	});

	it('a primary channel voided between planning and dispatch fails the payment locally (#1941)', async function () {
		this.timeout(30_000);
		const world = await buildWorld(7180, [200_000n, 200_000n]);
		const amountMsat = sum(world.spendable) - FEE_MARGIN_MSAT;
		const invoice = world.d.createInvoice({
			amountMsat,
			description: 'primary gone'
		});

		// The first part's update_add_htlc is the moment after planning and
		// before the second part's dispatch: W's channel with the other
		// primary is voided there, as a close or void landing mid-send would.
		let voided: Buffer | undefined;
		world.w.on(
			'message:outbound',
			(_pk: string, type: number, payload: Buffer) => {
				if (type !== MessageType.UPDATE_ADD_HTLC || voided) return;
				const used = payload.subarray(0, 32);
				const other = world.primaries.find((p) => !p.wChannelId.equals(used))!;
				voided = other.wChannelId;
				world.w.getChannelManager().voidChannel(other.wChannelId);
			}
		);
		let failedEvents = 0;
		world.w.on('payment:failed', () => failedEvents++);

		const payment = world.w.sendPayment(invoice.bolt11);
		await settle();

		expect(voided, 'the first part left').to.exist;
		expect(world.wAdds, 'the second part never left').to.equal(1);
		expect(payment.status).to.equal(PaymentStatus.FAILED);
		expect(payment.failureReason).to.match(/first-hop channel is gone/);
		expect(failedEvents, 'payment:failed emitted once').to.equal(1);
		// The dispatched part's secrets stay until D fails it back.
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		expect((world.w as any).outboundMppPayments.size).to.equal(1);
		// D holds the lone part it was forwarded and credits nothing.
		expect(sum(world.primaries.map((p) => BigInt(p.forwards)))).to.equal(1n);
		expect(world.d.getPayment(invoice.paymentHash)!.status).to.equal(
			PaymentStatus.PENDING
		);
		destroyAll(...world.nodes);
	});

	it('a part fulfilled before a later part finds its channel gone leaves the payment COMPLETED (#1941)', async function () {
		this.timeout(30_000);
		const world = await buildWorld(7200, [200_000n, 200_000n]);
		const amountMsat = sum(world.spendable) - FEE_MARGIN_MSAT;
		const invoice = world.d.createInvoice({
			amountMsat,
			description: 'settled mid-dispatch',
			hold: true
		});

		// D settles the first part the moment it is held, as a hold-invoice
		// consumer may. This wire delivers inline, so W holds the preimage
		// before the second part's dispatch step, which then finds W's channel
		// with the other primary voided on the first part's update_add_htlc.
		world.d.on('hold:accepted', () => {
			world.d.settleHeldHtlc(invoice.paymentHash);
		});
		let voided: Buffer | undefined;
		world.w.on(
			'message:outbound',
			(_pk: string, type: number, payload: Buffer) => {
				if (type !== MessageType.UPDATE_ADD_HTLC || voided) return;
				const used = payload.subarray(0, 32);
				const other = world.primaries.find((p) => !p.wChannelId.equals(used))!;
				voided = other.wChannelId;
				world.w.getChannelManager().voidChannel(other.wChannelId);
			}
		);
		const events: string[] = [];
		world.w.on('payment:sent', () => events.push('sent'));
		world.w.on('payment:failed', () => events.push('failed'));

		const payment = world.w.sendPayment(invoice.bolt11);
		await settle();

		expect(voided, 'the first part left').to.exist;
		expect(world.wAdds, 'the second part never left').to.equal(1);
		expect(events, 'the preimage ended the payment').to.deep.equal(['sent']);
		expect(payment.status).to.equal(PaymentStatus.COMPLETED);
		expect(payment.preimage).to.exist;
		expect(payment.failureReason).to.equal(undefined);
		expect(world.w.getPayment(invoice.paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		expect((world.w as any).outboundMppPayments.size).to.equal(0);
		destroyAll(...world.nodes);
	});
});
