/**
 * The outgoing payment record and the HTLC view it feeds must survive what
 * the #743 fund-safety audit found could erase or overwrite them while an
 * HTLC is still out: an incoming keysend on the same hash, an MPP dispatch
 * that never journaled its record, the completed-payment pruner, and the
 * plain loss of the record. A swap engine judges a payment by this view; a
 * paid payment reported as failed refunds the client the coins the preimage
 * already bought.
 */

import { expect } from 'chai';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	IPaymentHtlcResolvedEvent,
	IPaymentPreimageEvent,
	PaymentDirection,
	PaymentStatus
} from '../../src/lightning/node/types';
import {
	buildGraph,
	connectNodes,
	createNode,
	makeExternalHash,
	openReadyChannel
} from './helpers/loopback-nodes';

const TAG = 'outgoing-record-integrity';

describe('Outgoing payment record integrity (#743 audit)', function () {
	it('refuses an incoming keysend on a hash this node is paying, so the outgoing record survives', async function () {
		const alice = createNode(TAG, 1);
		const bob = createNode(TAG, 2);
		const carol = createNode(TAG, 9);
		connectNodes(alice, bob);
		connectNodes(alice, carol);
		alice.handleNewBlock(1000);
		bob.handleNewBlock(1000);
		carol.handleNewBlock(1000);
		const channelId = openReadyChannel(alice, bob);
		buildGraph(alice, bob, [channelId]);
		const toCarol = openReadyChannel(carol, alice);
		buildGraph(carol, alice, [toCarol]);

		const { preimage, hash } = makeExternalHash();
		const invoice = bob.createInvoice({
			amountMsat: 5_000_000n,
			description: 'held',
			hold: true,
			paymentHash: hash
		});
		alice.sendPayment(invoice.bolt11);
		expect(alice.getOutgoingHtlcs(hash).htlcs).to.have.length(1);

		// The payee knows the preimage; a keysend carrying it to alice from
		// any peer used to overwrite alice's OUTGOING record with an INCOMING
		// one (and alice's own payment then looked failed).
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const keysend = (carol as any).dispatchKeysend(
			{
				destination: Buffer.from(alice.getNodeId(), 'hex'),
				amountMsat: 1_000n
			},
			preimage
		);
		await new Promise((r) => setTimeout(r, 20));
		expect(carol.getPayment(keysend.paymentHash)!.status).to.equal(
			PaymentStatus.FAILED
		);
		const record = alice.getPayment(hash)!;
		expect(record.direction).to.equal(PaymentDirection.OUTGOING);
		expect(record.status).to.equal(PaymentStatus.PENDING);
		let view = alice.getOutgoingHtlcs(hash);
		expect(view.status).to.equal(PaymentStatus.PENDING);
		expect(view.resolved).to.equal(false);
		expect(view.preimage).to.equal(undefined);

		// Bob settles: the payment completes as it always did.
		const preimages: IPaymentPreimageEvent[] = [];
		alice.on('payment:preimage', (e: IPaymentPreimageEvent) =>
			preimages.push(e)
		);
		expect(bob.settleHeldHtlc(hash, preimage)).to.equal(true);
		const resolution = await alice.awaitPaymentResolution(hash, 5_000);
		expect(resolution.status).to.equal(PaymentStatus.COMPLETED);
		expect(resolution.preimage).to.deep.equal(preimage);
		expect(preimages).to.have.length(1);
		view = alice.getOutgoingHtlcs(hash);
		expect(view.resolved).to.equal(true);
		expect(view.preimage).to.deep.equal(preimage);
		expect(alice.getPayment(hash)!.direction).to.equal(
			PaymentDirection.OUTGOING
		);
	});

	it('a fulfilled HTLC whose record is gone still announces the preimage and shows it in the view', async function () {
		const alice = createNode(TAG, 3);
		const bob = createNode(TAG, 4);
		connectNodes(alice, bob);
		alice.handleNewBlock(1000);
		bob.handleNewBlock(1000);
		const channelId = openReadyChannel(alice, bob);
		buildGraph(alice, bob, [channelId]);

		const { preimage, hash } = makeExternalHash();
		const invoice = bob.createInvoice({
			amountMsat: 5_000_000n,
			description: 'held',
			hold: true,
			paymentHash: hash
		});
		alice.sendPayment(invoice.bolt11);
		// The record is lost (never journaled, pruned, whatever): the HTLC
		// alice offered is still out there.
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(alice as any).payments.delete(hash.toString('hex'));
		let view = alice.getOutgoingHtlcs(hash);
		expect(view.status).to.equal(null);
		expect(view.htlcs).to.have.length(1);
		expect(view.resolved).to.equal(false);

		const preimages: IPaymentPreimageEvent[] = [];
		const resolved: IPaymentHtlcResolvedEvent[] = [];
		alice.on('payment:preimage', (e: IPaymentPreimageEvent) =>
			preimages.push(e)
		);
		alice.on('payment:htlc-resolved', (e: IPaymentHtlcResolvedEvent) =>
			resolved.push(e)
		);
		expect(bob.settleHeldHtlc(hash, preimage)).to.equal(true);
		await new Promise((r) => setTimeout(r, 20));
		expect(preimages).to.have.length(1);
		expect(preimages[0].preimage).to.deep.equal(preimage);
		expect(resolved.some((e) => e.state === 'fulfilled')).to.equal(true);
		view = alice.getOutgoingHtlcs(hash);
		expect(view.status).to.equal(null);
		expect(view.preimage).to.deep.equal(preimage);
		expect(view.resolved).to.equal(true);
	});

	it('journals the MPP record before the first part leaves, so a restart mid-flight finds it', async function () {
		const storage = new SqliteStorage(':memory:');
		storage.open();
		const alice = createNode(TAG, 5, storage);
		const bob = createNode(TAG, 6);
		connectNodes(alice, bob);
		alice.handleNewBlock(1000);
		bob.handleNewBlock(1000);
		openReadyChannel(alice, bob, 200_000n);
		openReadyChannel(alice, bob, 200_000n);

		// Above either channel, within both: the hinted invoice splits.
		const { hash } = makeExternalHash();
		const invoice = bob.createInvoice({
			amountMsat: 250_000_000n,
			description: 'mpp held',
			hold: true,
			paymentHash: hash
		});
		const payment = alice.sendPayment(invoice.bolt11);
		expect(payment.status).to.equal(PaymentStatus.PENDING);
		const view = alice.getOutgoingHtlcs(hash);
		expect(view.htlcs.length, 'two parts out').to.equal(2);

		const journaled = storage
			.loadAllPayments()
			.find((p) => p.paymentHash === hash.toString('hex'));
		expect(journaled, 'the PENDING record is on disk').to.not.equal(undefined);
		expect(journaled!.payment.status).to.equal(PaymentStatus.PENDING);
		expect(journaled!.payment.direction).to.equal(PaymentDirection.OUTGOING);

		const alice2 = createNode(TAG, 5, storage);
		expect(alice2.getPayment(hash)!.status).to.equal(PaymentStatus.PENDING);
		storage.close();
	});

	it('the pruner keeps a FAILED record whose HTLC is still out, and drops it once resolved', async function () {
		const alice = createNode(TAG, 7, undefined, {
			resourceConfig: {
				completedPaymentTtlMs: 1,
				maxCompletedPayments: 1,
				cleanupIntervalMs: 0
			}
		});
		const bob = createNode(TAG, 8);
		connectNodes(alice, bob);
		alice.handleNewBlock(1000);
		bob.handleNewBlock(1000);
		const channelId = openReadyChannel(alice, bob);
		buildGraph(alice, bob, [channelId]);

		const { preimage, hash } = makeExternalHash();
		const invoice = bob.createInvoice({
			amountMsat: 5_000_000n,
			description: 'held',
			hold: true,
			paymentHash: hash
		});
		alice.sendPayment(invoice.bolt11);
		alice.failPayment(hash, 'timeout');
		expect(alice.getPayment(hash)!.status).to.equal(PaymentStatus.FAILED);
		await new Promise((r) => setTimeout(r, 5));
		// Past the TTL and over the size cap, yet the HTLC is live: kept.
		alice.pruneCompletedPayments();
		expect(alice.getPayment(hash), 'record kept').to.not.equal(undefined);
		expect(alice.getOutgoingHtlcs(hash).status).to.equal(PaymentStatus.FAILED);

		// The payee settles late: the record is promoted and the preimage
		// lands on it.
		expect(bob.settleHeldHtlc(hash, preimage)).to.equal(true);
		const resolution = await alice.awaitPaymentResolution(hash, 5_000);
		expect(resolution.status).to.equal(PaymentStatus.COMPLETED);
		expect(alice.getPayment(hash)!.preimage).to.deep.equal(preimage);
		await new Promise((r) => setTimeout(r, 5));
		// Resolved and expired: pruned now.
		expect(alice.pruneCompletedPayments()).to.be.greaterThan(0);
		expect(alice.getPayment(hash)).to.equal(undefined);
	});
});
