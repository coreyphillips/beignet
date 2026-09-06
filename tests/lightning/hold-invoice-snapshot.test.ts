/**
 * getHeldInvoiceSnapshot and the 'hold:cancelled' event (issue #737, phase 2).
 *
 * A reverse swap provider funds an on-chain contract only against the FULL
 * committed MPP set of its hold invoice, with each part's absolute expiry and
 * the height at which the node's own CLTV sweeper would cancel the hash. The
 * snapshot re-derives `committed` from channel state on every call, and the
 * cancel event fires for every cancel path with its reason.
 */

import { expect } from 'chai';
import { PaymentStatus } from '../../src/lightning/node/types';
import {
	HELD_HTLC_EXPIRY_MARGIN,
	LightningNode
} from '../../src/lightning/node/lightning-node';
import { IHoldCancelledEvent } from '../../src/lightning/node/types';
import { validateReverseSwapAdmission } from '../../src/lightning/swaps';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	buildGraph,
	connectNodes,
	createNode,
	makeExternalHash,
	openReadyChannel,
	parkedCltvExpiry,
	scidForIndex
} from './helpers/loopback-nodes';

const TAG = 'hold-snapshot';

function cancelEvents(node: LightningNode): IHoldCancelledEvent[] {
	const out: IHoldCancelledEvent[] = [];
	node.on('hold:cancelled', (e: IHoldCancelledEvent) => out.push(e));
	return out;
}

describe('Hold invoice snapshot (issue #737 phase 2)', function () {
	it('exports the sweeper margin the snapshot reports', function () {
		expect(HELD_HTLC_EXPIRY_MARGIN).to.equal(18);
	});

	it('returns null for an unknown hash and an empty snapshot for an unpaid hold invoice', function () {
		const bob = createNode(TAG, 2);
		expect(bob.getHeldInvoiceSnapshot(Buffer.alloc(32, 7))).to.equal(null);
		const { hash } = makeExternalHash();
		bob.createInvoice({
			amountMsat: 1_000_000n,
			description: 'open',
			hold: true,
			paymentHash: hash
		});
		const snap = bob.getHeldInvoiceSnapshot(hash)!;
		expect(snap.state).to.equal('OPEN');
		expect(snap.parts).to.have.length(0);
		expect(snap.committedMsat).to.equal(0n);
		expect(snap.expectedAmountMsat).to.equal(1_000_000n);
		expect(snap.complete).to.equal(false);
		expect(snap.earliestExpiry).to.equal(null);
		expect(snap.cancelHeight).to.equal(null);
		// A plain (non-hold) invoice is not a hold invoice.
		const plain = bob.createInvoice({ amountMsat: 1n, description: 'p' });
		expect(bob.getHeldInvoiceSnapshot(plain.paymentHash)).to.equal(null);
	});

	it('reports one committed part with the channel identity and absolute expiry', function () {
		const alice = createNode(TAG, 3);
		const bob = createNode(TAG, 4);
		connectNodes(alice, bob);
		alice.handleNewBlock(1000);
		bob.handleNewBlock(1000);
		const channelId = openReadyChannel(alice, bob);
		buildGraph(alice, bob, [channelId]);

		const { hash } = makeExternalHash();
		const invoice = bob.createInvoice({
			amountMsat: 5_000_000n,
			description: 'one-part',
			hold: true,
			paymentHash: hash
		});
		alice.sendPayment(invoice.bolt11);

		const snap = bob.getHeldInvoiceSnapshot(hash)!;
		expect(snap.state).to.equal('ACCEPTED');
		expect(snap.currentHeight).to.equal(1000);
		expect(snap.parts).to.have.length(1);
		const part = snap.parts[0];
		expect(part.committed).to.equal(true);
		expect(part.channelId).to.deep.equal(channelId);
		expect(part.id).to.equal(
			`${channelId.toString('hex')}:${part.htlcId.toString()}`
		);
		expect(part.paymentHash).to.deep.equal(hash);
		expect(part.amountMsat).to.equal(5_000_000n);
		expect(part.cltvExpiry).to.equal(parkedCltvExpiry(bob, channelId));
		expect(snap.committedMsat).to.equal(5_000_000n);
		expect(snap.complete).to.equal(true);
		expect(snap.earliestExpiry).to.equal(part.cltvExpiry);
		expect(snap.cancelMarginBlocks).to.equal(HELD_HTLC_EXPIRY_MARGIN);
		expect(snap.cancelHeight).to.equal(
			part.cltvExpiry - HELD_HTLC_EXPIRY_MARGIN
		);
	});

	it('is incomplete after one MPP part and complete after both, and feeds the reverse admission check', function () {
		const alice = createNode(TAG, 5);
		const bob = createNode(TAG, 6);
		connectNodes(alice, bob);
		alice.handleNewBlock(1000);
		bob.handleNewBlock(1000);
		const ch1 = openReadyChannel(alice, bob, 100_000n);
		const ch2 = openReadyChannel(alice, bob, 100_000n);
		buildGraph(alice, bob, [ch1, ch2], 100_000_000n);

		const { hash } = makeExternalHash();
		const totalMsat = 90_000_000n;
		const invoice = bob.createInvoice({
			amountMsat: totalMsat,
			description: 'hold-mpp',
			hold: true,
			paymentHash: hash
		});
		const bobPubkey = Buffer.from(bob.getNodeId(), 'hex');
		const sendPart = (i: number, cltv: number): void => {
			alice.sendPaymentToRoute(
				{
					hops: [
						{
							pubkey: bobPubkey,
							shortChannelId: scidForIndex(i),
							amountToForwardMsat: totalMsat / 2n,
							outgoingCltvValue: cltv
						}
					]
				},
				hash,
				cltv,
				invoice.paymentSecret,
				totalMsat
			);
		};

		sendPart(0, 40);
		let snap = bob.getHeldInvoiceSnapshot(hash)!;
		expect(snap.parts).to.have.length(1);
		expect(snap.committedMsat).to.equal(totalMsat / 2n);
		expect(snap.complete).to.equal(false);
		// Partial set: the admission validator refuses it.
		expect(() =>
			validateReverseSwapAdmission({
				currentHeight: 1000,
				refundHeight: 1010,
				paymentHash: hash,
				expectedAmountMsat: totalMsat,
				committedHtlcs: snap.parts.filter((p) => p.committed),
				fundingSafetyBlocks: 1,
				resolutionSafetyBlocks: 1,
				holdCancelSafetyBlocks: snap.cancelMarginBlocks
			})
		).to.throw(/complete expected invoice amount/);

		sendPart(1, 60);
		snap = bob.getHeldInvoiceSnapshot(hash)!;
		expect(snap.parts).to.have.length(2);
		expect(snap.parts.every((p) => p.committed)).to.equal(true);
		expect(snap.committedMsat).to.equal(totalMsat);
		expect(snap.complete).to.equal(true);
		expect(snap.earliestExpiry).to.equal(1040);
		expect(snap.cancelHeight).to.equal(1040 - HELD_HTLC_EXPIRY_MARGIN);
		const ids = new Set(snap.parts.map((p) => p.id));
		expect(ids.size).to.equal(2);

		// The complete set passes with margins that fit under the cancel height,
		// and the validator's cancellation height matches the snapshot's.
		const cancellationHeight = validateReverseSwapAdmission({
			currentHeight: 1000,
			refundHeight: 1010,
			paymentHash: hash,
			expectedAmountMsat: totalMsat,
			committedHtlcs: snap.parts,
			fundingSafetyBlocks: 2,
			resolutionSafetyBlocks: 5,
			holdCancelSafetyBlocks: snap.cancelMarginBlocks
		});
		expect(cancellationHeight).to.equal(snap.cancelHeight);
		// Bumping the expected amount makes the same set incomplete.
		expect(() =>
			validateReverseSwapAdmission({
				currentHeight: 1000,
				refundHeight: 1010,
				paymentHash: hash,
				expectedAmountMsat: totalMsat + 1n,
				committedHtlcs: snap.parts,
				fundingSafetyBlocks: 2,
				resolutionSafetyBlocks: 5,
				holdCancelSafetyBlocks: snap.cancelMarginBlocks
			})
		).to.throw(/complete expected invoice amount/);
	});

	it('refuses a further part once the parked set covers the invoice', function () {
		const alice = createNode(TAG, 11);
		const bob = createNode(TAG, 12);
		connectNodes(alice, bob);
		alice.handleNewBlock(1000);
		bob.handleNewBlock(1000);
		const ch1 = openReadyChannel(alice, bob, 100_000n);
		const ch2 = openReadyChannel(alice, bob, 100_000n);
		buildGraph(alice, bob, [ch1, ch2], 100_000_000n);

		const { hash } = makeExternalHash();
		const totalMsat = 90_000_000n;
		const invoice = bob.createInvoice({
			amountMsat: totalMsat,
			description: 'hold-mpp-extra',
			hold: true,
			paymentHash: hash
		});
		const bobPubkey = Buffer.from(bob.getNodeId(), 'hex');
		const sendPart = (i: number, amountMsat: bigint, cltv: number): void => {
			alice.sendPaymentToRoute(
				{
					hops: [
						{
							pubkey: bobPubkey,
							shortChannelId: scidForIndex(i),
							amountToForwardMsat: amountMsat,
							outgoingCltvValue: cltv
						}
					]
				},
				hash,
				cltv,
				invoice.paymentSecret,
				totalMsat
			);
		};
		sendPart(0, totalMsat / 2n, 200);
		sendPart(1, totalMsat / 2n, 200);
		let snap = bob.getHeldInvoiceSnapshot(hash)!;
		expect(snap.complete).to.equal(true);
		expect(snap.parts).to.have.length(2);
		expect(snap.cancelHeight).to.equal(1200 - HELD_HTLC_EXPIRY_MARGIN);

		// A late 1 msat part with a short expiry would drag the whole set
		// into the sweeper's margin: it is failed back, never parked.
		sendPart(0, 1n, 40);
		snap = bob.getHeldInvoiceSnapshot(hash)!;
		expect(snap.parts).to.have.length(2);
		expect(snap.committedMsat).to.equal(totalMsat);
		expect(snap.cancelHeight).to.equal(1200 - HELD_HTLC_EXPIRY_MARGIN);
		const events = cancelEvents(bob);
		bob.handleNewBlock(1040 - HELD_HTLC_EXPIRY_MARGIN);
		expect(events).to.have.length(0);
		expect(bob.getHeldInvoiceSnapshot(hash)!.state).to.equal('ACCEPTED');
	});

	it('refuses an external hash the node already has a record for', function () {
		const alice = createNode(TAG, 13);
		const bob = createNode(TAG, 14);
		connectNodes(alice, bob);
		const channelId = openReadyChannel(alice, bob);
		buildGraph(alice, bob, [channelId]);

		// Bob issues a plain invoice; a hold invoice on its hash is refused.
		const plain = bob.createInvoice({ amountMsat: 1_000n, description: 'p' });
		expect(() =>
			bob.createInvoice({
				amountMsat: 1_000n,
				description: 'clash',
				hold: true,
				paymentHash: plain.paymentHash
			})
		).to.throw(/already in use/);
		expect(bob.paymentHashInUse(plain.paymentHash)).to.equal(true);

		// Alice is paying Bob's hold invoice: a hold invoice on the hash SHE
		// is sending against is refused on her side (her payment record
		// must not be overwritten by an incoming placeholder).
		const { hash } = makeExternalHash();
		const held = bob.createInvoice({
			amountMsat: 5_000_000n,
			description: 'hold',
			hold: true,
			paymentHash: hash
		});
		alice.sendPayment(held.bolt11);
		expect(alice.getPayment(hash)!.status).to.equal(PaymentStatus.PENDING);
		expect(() =>
			alice.createInvoice({
				amountMsat: 1n,
				description: 'clobber',
				hold: true,
				paymentHash: hash
			})
		).to.throw(/already in use/);
		expect(alice.getPayment(hash)!.status).to.equal(PaymentStatus.PENDING);
		expect(alice.paymentHashInUse(hash)).to.equal(true);
		expect(alice.paymentHashInUse(makeExternalHash().hash)).to.equal(false);
	});

	it('runs the expiry sweep only after the swap provider finished its look at the block', async function () {
		const alice = createNode(TAG, 15);
		const bob = createNode(TAG, 16);
		connectNodes(alice, bob);
		alice.handleNewBlock(1000);
		bob.handleNewBlock(1000);
		const channelId = openReadyChannel(alice, bob);
		buildGraph(alice, bob, [channelId]);
		const events = cancelEvents(bob);
		const { hash } = makeExternalHash();
		const invoice = bob.createInvoice({
			amountMsat: 5_000_000n,
			description: 'hold-order',
			hold: true,
			paymentHash: hash
		});
		alice.sendPayment(invoice.bolt11);
		const cancelHeight = parkedCltvExpiry(bob, channelId) - 18;

		// A provider whose chain look is still pending at the block.
		let finish: () => void = () => undefined;
		const looked: number[] = [];
		(bob as unknown as { swapProvider: unknown }).swapProvider = {
			onBlock: (height: number): Promise<void> => {
				looked.push(height);
				return new Promise<void>((resolve) => {
					finish = resolve;
				});
			}
		};
		bob.handleNewBlock(cancelHeight);
		expect(looked).to.deep.equal([cancelHeight]);
		await new Promise((r) => setImmediate(r));
		expect(events).to.have.length(0);
		expect(bob.getHeldInvoiceSnapshot(hash)!.state).to.equal('ACCEPTED');
		finish();
		await new Promise((r) => setImmediate(r));
		await new Promise((r) => setImmediate(r));
		expect(events).to.have.length(1);
		expect(events[0].reason).to.equal('expiry-scan');
	});

	it('emits hold:cancelled with reason api for explicit cancels, paid and unpaid', function () {
		const alice = createNode(TAG, 7);
		const bob = createNode(TAG, 8);
		connectNodes(alice, bob);
		const channelId = openReadyChannel(alice, bob);
		buildGraph(alice, bob, [channelId]);
		const events = cancelEvents(bob);

		const paid = makeExternalHash();
		const invoice = bob.createInvoice({
			amountMsat: 5_000_000n,
			description: 'paid',
			hold: true,
			paymentHash: paid.hash
		});
		alice.sendPayment(invoice.bolt11);
		expect(bob.cancelHoldInvoice(paid.hash)).to.deep.equal({ htlcsFailed: 1 });
		expect(events).to.have.length(1);
		expect(events[0].paymentHash).to.deep.equal(paid.hash);
		expect(events[0].reason).to.equal('api');
		expect(events[0].htlcsFailed).to.equal(1);
		const snap = bob.getHeldInvoiceSnapshot(paid.hash)!;
		expect(snap.state).to.equal('CANCELLED');
		expect(snap.parts).to.have.length(0);
		expect(alice.getPayment(paid.hash)!.status).to.equal(PaymentStatus.FAILED);

		const unpaid = makeExternalHash();
		bob.createInvoice({
			amountMsat: 1_000n,
			description: 'unpaid',
			hold: true,
			paymentHash: unpaid.hash
		});
		expect(bob.cancelHoldInvoice(unpaid.hash)).to.deep.equal({
			htlcsFailed: 0
		});
		expect(events).to.have.length(2);
		expect(events[1].reason).to.equal('api');
		expect(events[1].htlcsFailed).to.equal(0);
		// Cancelling a closed hash again emits nothing.
		expect(bob.cancelHoldInvoice(unpaid.hash)).to.equal(null);
		expect(events).to.have.length(2);
	});

	it('emits hold:cancelled with reason expiry-scan when the sweeper cancels at the margin', function () {
		const alice = createNode(TAG, 9);
		const bob = createNode(TAG, 10);
		connectNodes(alice, bob);
		alice.handleNewBlock(1000);
		bob.handleNewBlock(1000);
		const channelId = openReadyChannel(alice, bob);
		buildGraph(alice, bob, [channelId]);
		const events = cancelEvents(bob);

		const { hash } = makeExternalHash();
		const invoice = bob.createInvoice({
			amountMsat: 5_000_000n,
			description: 'hold-cltv',
			hold: true,
			paymentHash: hash
		});
		alice.sendPayment(invoice.bolt11);
		const snap = bob.getHeldInvoiceSnapshot(hash)!;
		const cancelHeight = snap.cancelHeight!;
		expect(cancelHeight).to.equal(parkedCltvExpiry(bob, channelId) - 18);

		bob.handleNewBlock(cancelHeight - 1);
		expect(events).to.have.length(0);
		expect(bob.getHeldInvoiceSnapshot(hash)!.state).to.equal('ACCEPTED');

		bob.handleNewBlock(cancelHeight);
		expect(events).to.have.length(1);
		expect(events[0].reason).to.equal('expiry-scan');
		expect(events[0].htlcsFailed).to.equal(1);
		expect(bob.getHeldInvoiceSnapshot(hash)!.state).to.equal('CANCELLED');
	});

	it('rebuilds the snapshot after a reload and re-verifies commitment against the restored channel', function () {
		const storage = new SqliteStorage(':memory:');
		storage.open();
		const alice = createNode(TAG, 11);
		const bob = createNode(TAG, 12, storage);
		connectNodes(alice, bob);
		alice.handleNewBlock(1000);
		bob.handleNewBlock(1000);
		const channelId = openReadyChannel(alice, bob);
		buildGraph(alice, bob, [channelId]);

		const { hash } = makeExternalHash();
		const invoice = bob.createInvoice({
			amountMsat: 5_000_000n,
			description: 'hold-restart',
			hold: true,
			paymentHash: hash
		});
		alice.sendPayment(invoice.bolt11);
		const before = bob.getHeldInvoiceSnapshot(hash)!;
		expect(before.complete).to.equal(true);

		const bob2 = createNode(TAG, 12, storage);
		const after = bob2.getHeldInvoiceSnapshot(hash)!;
		expect(after.state).to.equal('ACCEPTED');
		expect(after.parts).to.have.length(1);
		expect(after.parts[0].committed).to.equal(true);
		expect(after.parts[0].id).to.equal(before.parts[0].id);
		expect(after.parts[0].cltvExpiry).to.equal(before.parts[0].cltvExpiry);
		expect(after.complete).to.equal(true);
		storage.close();
	});
});
