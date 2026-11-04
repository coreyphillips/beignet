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
import { INodeConfig, PaymentStatus } from '../../src/lightning/node/types';
import {
	FEE_INSUFFICIENT,
	MPP_TIMEOUT,
	TEMPORARY_CHANNEL_FAILURE
} from '../../src/lightning/onion/types';
import { createFailureMessage } from '../../src/lightning/onion/failures';
import {
	ChannelState,
	REGTEST_CHAIN_HASH
} from '../../src/lightning/channel/types';
import {
	IChannelUpdateMessage,
	encodeShortChannelId
} from '../../src/lightning/gossip/types';
import { encodeChannelUpdateMessage } from '../../src/lightning/gossip/messages';
import { signChannelUpdate } from '../../src/lightning/gossip/validation';
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
	/** What those adds carried to D. */
	forwardedMsat: bigint;
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

interface IWorldOptions {
	/** Each primary's channel to D, 1M sats unless given. */
	dChannelSats?: bigint[];
	wExtra?: Partial<INodeConfig>;
	dExtra?: Partial<INodeConfig>;
}

/**
 * W opens one channel per entry of `wChannelSats` to a fresh primary, and each
 * primary opens a 1M-sat channel to D (or its `dChannelSats` entry), so D has
 * inbound on every primary and W holds the balance on its side. The P-D
 * channels are private: D's invoice hints them by the alias the primary chose,
 * which the primary forwards over once registered, as the async-world setup
 * does.
 */
async function buildWorld(
	seedBase: number,
	wChannelSats: bigint[],
	options: IWorldOptions = {}
): Promise<IWorld> {
	const w = createNode(seedBase, undefined, options.wExtra);
	const d = createNode(seedBase + 1, undefined, options.dExtra);
	const primaries: IPrimary[] = [];
	for (let i = 0; i < wChannelSats.length; i++) {
		const node = createNode(seedBase + 2 + i);
		wire(w, node, { val: false });
		wire(node, d, { val: false });
		const wChannelId = await openChannelOf(w, node, wChannelSats[i]);
		const dChannelId = await openChannelOf(
			node,
			d,
			options.dChannelSats?.[i] ?? 1_000_000n
		);
		const primary: IPrimary = {
			node,
			wChannelId,
			dChannelId,
			forwards: 0,
			forwardedMsat: 0n
		};
		node.on(
			'htlc:forward',
			(_inChannel: Buffer, _outChannel: Buffer, amountMsat: bigint) => {
				primary.forwards++;
				primary.forwardedMsat += amountMsat;
			}
		);
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
		const scid = hintScidOf(i);
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

/** The alias primary `i` registers for its channel to D, which D's invoice hints. */
function hintScidOf(i: number): Buffer {
	return encodeShortChannelId({ block: 840, txIndex: i + 1, outputIndex: 0 });
}

/**
 * Make W's planner prefer the other primaries over primary `i` when more than
 * one can carry a part: a MissionControl penalty on the hinted channel adds a
 * cost, not an exclusion, so a replacement part can still take it.
 */
function penalise(world: IWorld, i: number): void {
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	(world.w as any).missionControl.recordFailure(hintScidOf(i).toString('hex'));
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

	/**
	 * Three primaries. W's channel with P1 carries most of the amount and the
	 * rest fits P2 or P3; P3 is penalised so the plan takes P2. P2's channel
	 * to D is far too small for its part, which a hint cannot show, so P2
	 * fails the part back with temporary_channel_failure once the siblings
	 * have left.
	 */
	const REMAINDER_MSAT = 50_000_000n;

	it('a part its primary fails is replaced over another primary under the same payment (#1942)', async function () {
		this.timeout(30_000);
		const world = await buildWorld(7220, [200_000n, 100_000n, 100_000n], {
			dChannelSats: [1_000_000n, 30_000n, 1_000_000n]
		});
		penalise(world, 2);
		const amountMsat = world.spendable[0] + REMAINDER_MSAT;
		const invoice = world.d.createInvoice({
			amountMsat,
			description: 'replaced part'
		});
		const events: string[] = [];
		world.w.on('payment:sent', () => events.push('sent'));
		world.w.on('payment:failed', () => events.push('failed'));

		await payAndSettle(world, invoice.bolt11, invoice.paymentHash);

		const payment = world.w.getPayment(invoice.paymentHash)!;
		expect(world.wAdds, 'two planned parts and one replacement').to.equal(3);
		expect(
			world.primaries.map((p) => p.forwards),
			'P2 forwarded nothing, P3 carried the replacement'
		).to.deep.equal([1, 0, 1]);
		expect(payment.retryCount, 'one part replaced').to.equal(1);
		expect(
			payment.failureCode,
			'the part failure stays on the record'
		).to.equal(TEMPORARY_CHANNEL_FAILURE);
		expect(events, 'one completion event').to.deep.equal(['sent']);
		expect(payment.sentMsat! >= amountMsat).to.equal(true);
		expect(payment.sentMsat! < amountMsat + FEE_MARGIN_MSAT).to.equal(true);
		// Everything D was ever sent is the invoice exactly: the replacement
		// took the failed part's place, it did not join it.
		expect(
			sum(world.primaries.map((p) => p.forwardedMsat)),
			'D received total_msat once'
		).to.equal(amountMsat);
		expect(world.d.getPayment(invoice.paymentHash)!.amountMsat).to.equal(
			amountMsat
		);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		expect((world.w as any).outboundMppPayments.size).to.equal(0);
		destroyAll(...world.nodes);
	});

	it('the failed first hop is excluded from the replacement and the payment fails once every alternative fails (#1942)', async function () {
		this.timeout(30_000);
		const world = await buildWorld(7240, [200_000n, 100_000n, 100_000n], {
			dChannelSats: [1_000_000n, 30_000n, 30_000n],
			dExtra: { mppTimeoutMs: 1 }
		});
		penalise(world, 2);
		const amountMsat = world.spendable[0] + REMAINDER_MSAT;
		const invoice = world.d.createInvoice({
			amountMsat,
			description: 'no alternative'
		});
		let failedEvents = 0;
		world.w.on('payment:failed', () => failedEvents++);

		const payment = world.w.sendPayment(invoice.bolt11);
		await waitFor(
			() => payment.status === PaymentStatus.FAILED,
			'the payment to fail on W'
		);
		await settle();

		expect(
			world.wAdds,
			'P2, then P3 as its replacement, then nothing'
		).to.equal(3);
		expect(world.primaries.map((p) => p.forwards)).to.deep.equal([1, 0, 0]);
		expect(payment.retryCount).to.equal(1);
		expect(payment.failureReason).to.match(
			/Replacement part not sent: no route/
		);
		expect(failedEvents, 'payment:failed emitted once').to.equal(1);
		// Both failed primaries' hinted channels and W's channels to them are
		// out; P1's channel stays in, it did its part.
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const wAny = world.w as any;
		const excluded: Set<string> | undefined = wAny.paymentRetryContexts.get(
			invoice.paymentHash.toString('hex')
		)?.excludedChannels;
		expect(excluded, 'the context went with the payment').to.equal(undefined);
		// D holds P1's part alone and releases it at its MPP timeout; the
		// record is already FAILED, so that failure changes nothing but the
		// code it records.
		await new Promise((r) => setTimeout(r, 5));
		world.d.failTimedOutMppPayments();
		await settle();
		expect(payment.failureCode).to.equal(MPP_TIMEOUT);
		expect(failedEvents).to.equal(1);
		expect(wAny.outboundMppPayments.size).to.equal(0);
		expect(world.d.getPayment(invoice.paymentHash)!.status).to.equal(
			PaymentStatus.PENDING
		);
		destroyAll(...world.nodes);
	});

	it('the retry bound ends the payment FAILED without a replacement (#1942)', async function () {
		this.timeout(30_000);
		const world = await buildWorld(7260, [200_000n, 100_000n, 100_000n], {
			dChannelSats: [1_000_000n, 30_000n, 1_000_000n],
			wExtra: { maxPaymentRetries: 0 }
		});
		penalise(world, 2);
		const amountMsat = world.spendable[0] + REMAINDER_MSAT;
		const invoice = world.d.createInvoice({
			amountMsat,
			description: 'no retries'
		});
		let failedEvents = 0;
		world.w.on('payment:failed', () => failedEvents++);

		const payment = world.w.sendPayment(invoice.bolt11);
		await waitFor(
			() => payment.status === PaymentStatus.FAILED,
			'the payment to fail on W'
		);
		await settle();

		expect(world.wAdds, 'the two planned parts only').to.equal(2);
		expect(world.primaries.map((p) => p.forwards)).to.deep.equal([1, 0, 0]);
		expect(payment.failureReason).to.match(/0 part retries used/);
		expect(payment.failureCode).to.equal(TEMPORARY_CHANNEL_FAILURE);
		expect(failedEvents).to.equal(1);
		destroyAll(...world.nodes);
	});

	it('a first hop that re-prices its channel to D carries its own replacement at the new price (#1942)', async function () {
		this.timeout(30_000);
		// W's channel with P3 cannot carry the remainder, so only P2 can
		// replace the part P2 fails. P2 fails it with fee_insufficient and a
		// signed channel_update for its channel to D at a higher base fee than
		// the hint carries: a price, not a fault, so neither that channel nor
		// W's channel to P2 is excluded from the replacement.
		const seedBase = 7280;
		const world = await buildWorld(seedBase, [200_000n, 100_000n, 20_000n]);
		const amountMsat = world.spendable[0] + REMAINDER_MSAT;
		const invoice = world.d.createInvoice({
			amountMsat,
			description: 'repriced first hop'
		});
		const hint = decodeInvoice(invoice.bolt11)
			.routingHints!.flat()
			.find((hop) => hop.shortChannelId.equals(hintScidOf(1)))!;
		const p2Key = nodePrivkey(seedBase + 3);
		const p2Pubkey = getPublicKey(p2Key);
		const dPubkey = getPublicKey(nodePrivkey(seedBase + 1));
		const update: IChannelUpdateMessage = {
			signature: Buffer.alloc(64),
			chainHash: REGTEST_CHAIN_HASH,
			shortChannelId: hintScidOf(1),
			timestamp: Math.floor(Date.now() / 1000),
			messageFlags: 0,
			channelFlags: Buffer.compare(p2Pubkey, dPubkey) < 0 ? 0 : 1,
			cltvExpiryDelta: hint.cltvExpiryDelta,
			htlcMinimumMsat: 1n,
			feeBaseMsat: hint.feeBaseMsat + 1_000,
			feeProportionalMillionths: hint.feeProportionalMillionths
		};
		const signed = encodeChannelUpdateMessage({
			...update,
			signature: signChannelUpdate(encodeChannelUpdateMessage(update), p2Key)
		});
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const p2 = world.primaries[1].node as any;
		const forward = p2.handleForwardHtlc.bind(p2);
		p2.handleForwardHtlc = (
			inChannelId: Buffer,
			inHtlcId: bigint,
			_paymentHash: Buffer,
			processed: { sharedSecret: Buffer },
			incomingAmountMsat: bigint
		): void => {
			p2.handleForwardHtlc = forward;
			// fee_insufficient: [u64 htlc_msat][u16 len][channel_update]
			const data = Buffer.alloc(10 + signed.length);
			data.writeBigUInt64BE(incomingAmountMsat, 0);
			data.writeUInt16BE(signed.length, 8);
			signed.copy(data, 10);
			p2.channelManager.failHtlc(
				inChannelId,
				inHtlcId,
				createFailureMessage(processed.sharedSecret, FEE_INSUFFICIENT, data)
			);
		};
		const actions: string[] = [];
		world.w.on('log', (log: { action: string }) => actions.push(log.action));

		await payAndSettle(world, invoice.bolt11, invoice.paymentHash);

		const payment = world.w.getPayment(invoice.paymentHash)!;
		expect(actions).to.include('retry_repriced');
		expect(world.wAdds, 'two planned parts and one replacement').to.equal(3);
		expect(
			world.primaries.map((p) => p.forwards),
			'P2 forwarded its own replacement'
		).to.deep.equal([1, 1, 0]);
		expect(payment.retryCount).to.equal(1);
		expect(sum(world.primaries.map((p) => p.forwardedMsat))).to.equal(
			amountMsat
		);
		destroyAll(...world.nodes);
	});
});
