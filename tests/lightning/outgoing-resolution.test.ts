/**
 * Outgoing attempt resolution (issue #737, phase 2): getOutgoingHtlcs,
 * awaitPaymentResolution, the 'payment:htlc-resolved' and 'payment:preimage'
 * events, and reconciliation of a preimage learned on chain.
 *
 * A wall-clock payment timeout marks the record FAILED but retracts nothing:
 * the HTLC is still live and the payee may still settle it. A submarine swap
 * provider must be able to tell "timed out" from "every HTLC failed", and
 * must learn a late preimage however it arrives.
 */

import { expect } from 'chai';
import {
	IPaymentHtlcResolvedEvent,
	IPaymentInfo,
	IPaymentPreimageEvent,
	PaymentStatus
} from '../../src/lightning/node/types';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	buildGraph,
	connectNodes,
	createNode,
	makeExternalHash,
	openReadyChannel,
	parkedCltvExpiry
} from './helpers/loopback-nodes';

const TAG = 'outgoing-resolution';

describe('Outgoing payment resolution (issue #737 phase 2)', function () {
	it('reports an unknown hash as resolved with no HTLCs and no record', function () {
		const alice = createNode(TAG, 1);
		const view = alice.getOutgoingHtlcs(Buffer.alloc(32, 9));
		expect(view.status).to.equal(null);
		expect(view.htlcs).to.have.length(0);
		expect(view.resolved).to.equal(true);
		expect(view.latestOutstandingExpiry).to.equal(null);
		expect(view.preimage).to.equal(undefined);
	});

	it('a wall-clock failure leaves the HTLC live and the payment unresolved until the payee settles', async function () {
		const alice = createNode(TAG, 2);
		const bob = createNode(TAG, 3);
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

		let view = alice.getOutgoingHtlcs(hash);
		expect(view.status).to.equal(PaymentStatus.PENDING);
		expect(view.htlcs).to.have.length(1);
		expect(view.htlcs[0].state).to.equal('offered');
		expect(view.htlcs[0].terminal).to.equal(false);
		expect(view.htlcs[0].channelId).to.deep.equal(channelId);
		expect(view.htlcs[0].amountMsat).to.equal(5_000_000n);
		expect(view.htlcs[0].cltvExpiry).to.equal(parkedCltvExpiry(bob, channelId));
		expect(view.resolved).to.equal(false);
		expect(view.latestOutstandingExpiry).to.equal(view.htlcs[0].cltvExpiry);

		// The wall clock gives up: the record says FAILED, the HTLC says nothing.
		alice.failPayment(hash, 'timeout');
		expect(alice.getPayment(hash)!.status).to.equal(PaymentStatus.FAILED);
		view = alice.getOutgoingHtlcs(hash);
		expect(view.status).to.equal(PaymentStatus.FAILED);
		expect(view.resolved).to.equal(false);
		expect(view.latestOutstandingExpiry).to.equal(view.htlcs[0].cltvExpiry);

		let settled = false;
		const waiting = alice.awaitPaymentResolution(hash).then((r) => {
			settled = true;
			return r;
		});
		await new Promise((r) => setImmediate(r));
		expect(settled).to.equal(false);

		const sent: IPaymentInfo[] = [];
		const preimages: IPaymentPreimageEvent[] = [];
		const resolvedHtlcs: IPaymentHtlcResolvedEvent[] = [];
		alice.on('payment:sent', (p: IPaymentInfo) => sent.push(p));
		alice.on('payment:preimage', (e: IPaymentPreimageEvent) =>
			preimages.push(e)
		);
		alice.on('payment:htlc-resolved', (e: IPaymentHtlcResolvedEvent) =>
			resolvedHtlcs.push(e)
		);

		// The payee settles late: the record is promoted, the preimage is
		// announced with its source, and the wait resolves.
		expect(bob.settleHeldHtlc(hash, preimage)).to.equal(true);
		const resolution = await waiting;
		expect(resolution.resolved).to.equal(true);
		expect(resolution.status).to.equal(PaymentStatus.COMPLETED);
		expect(resolution.preimage).to.deep.equal(preimage);
		expect(resolution.htlcs.every((h) => h.terminal)).to.equal(true);
		expect(sent).to.have.length(1);
		expect(preimages).to.have.length(1);
		expect(preimages[0].source).to.equal('htlc');
		expect(preimages[0].preimage).to.deep.equal(preimage);
		expect(resolvedHtlcs.some((e) => e.state === 'fulfilled')).to.equal(true);
		expect(resolvedHtlcs[0].channelId).to.deep.equal(channelId);
	});

	it('a cancelled hold resolves the HTLC as failed', async function () {
		const alice = createNode(TAG, 4);
		const bob = createNode(TAG, 5);
		connectNodes(alice, bob);
		alice.handleNewBlock(1000);
		bob.handleNewBlock(1000);
		const channelId = openReadyChannel(alice, bob);
		buildGraph(alice, bob, [channelId]);

		const { hash } = makeExternalHash();
		const invoice = bob.createInvoice({
			amountMsat: 5_000_000n,
			description: 'cancel',
			hold: true,
			paymentHash: hash
		});
		alice.sendPayment(invoice.bolt11);
		const resolvedHtlcs: IPaymentHtlcResolvedEvent[] = [];
		alice.on('payment:htlc-resolved', (e: IPaymentHtlcResolvedEvent) =>
			resolvedHtlcs.push(e)
		);
		const waiting = alice.awaitPaymentResolution(hash, 5_000);

		bob.cancelHoldInvoice(hash);
		const resolution = await waiting;
		expect(resolution.resolved).to.equal(true);
		expect(resolution.status).to.equal(PaymentStatus.FAILED);
		expect(resolution.preimage).to.equal(undefined);
		expect(resolvedHtlcs).to.have.length(1);
		expect(resolvedHtlcs[0].state).to.equal('failed');
		expect(resolvedHtlcs[0].paymentHash).to.deep.equal(hash);
	});

	it('times out with the partial view attached and fails nothing', async function () {
		const alice = createNode(TAG, 6);
		const bob = createNode(TAG, 7);
		connectNodes(alice, bob);
		alice.handleNewBlock(1000);
		bob.handleNewBlock(1000);
		const channelId = openReadyChannel(alice, bob);
		buildGraph(alice, bob, [channelId]);
		const { hash } = makeExternalHash();
		const invoice = bob.createInvoice({
			amountMsat: 5_000_000n,
			description: 'timeout',
			hold: true,
			paymentHash: hash
		});
		alice.sendPayment(invoice.bolt11);
		try {
			await alice.awaitPaymentResolution(hash, 20);
			expect.fail('should have timed out');
		} catch (err) {
			const e = err as Error & { resolution?: { resolved: boolean } };
			expect(e.message).to.match(/timed out/);
			expect(e.resolution!.resolved).to.equal(false);
		}
		// Unlike sendPaymentAsync, the record is untouched.
		expect(alice.getPayment(hash)!.status).to.equal(PaymentStatus.PENDING);
		bob.cancelHoldInvoice(hash);
	});

	it('a preimage learned on chain completes a pending or failed outgoing record and survives a reload', async function () {
		const storage = new SqliteStorage(':memory:');
		storage.open();
		const alice = createNode(TAG, 8, storage);
		const bob = createNode(TAG, 9);
		connectNodes(alice, bob);
		alice.handleNewBlock(1000);
		bob.handleNewBlock(1000);
		const channelId = openReadyChannel(alice, bob);
		buildGraph(alice, bob, [channelId]);

		const { preimage, hash } = makeExternalHash();
		const invoice = bob.createInvoice({
			amountMsat: 5_000_000n,
			description: 'onchain',
			hold: true,
			paymentHash: hash
		});
		alice.sendPayment(invoice.bolt11);
		alice.failPayment(hash, 'timeout');
		expect(alice.getPayment(hash)!.status).to.equal(PaymentStatus.FAILED);

		const sent: IPaymentInfo[] = [];
		const preimages: IPaymentPreimageEvent[] = [];
		alice.on('payment:sent', (p: IPaymentInfo) => sent.push(p));
		alice.on('payment:preimage', (e: IPaymentPreimageEvent) =>
			preimages.push(e)
		);
		const waiting = alice.awaitPaymentResolution(hash, 5_000);

		// The same entry the channel manager's 'preimage:learned' reaches when
		// a downstream claim reveals the preimage on chain.
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(alice as any).handleOnChainPreimageLearned(hash, preimage);

		expect(alice.getPayment(hash)!.status).to.equal(PaymentStatus.COMPLETED);
		expect(alice.getPayment(hash)!.preimage).to.deep.equal(preimage);
		expect(sent).to.have.length(1);
		expect(preimages).to.have.length(1);
		expect(preimages[0].source).to.equal('onchain');
		// The off-chain HTLC is still parked at bob: the payment is known
		// paid, but the HTLC itself has not resolved yet.
		const view = alice.getOutgoingHtlcs(hash);
		expect(view.preimage).to.deep.equal(preimage);
		expect(view.status).to.equal(PaymentStatus.COMPLETED);
		expect(view.resolved).to.equal(false);

		// Bob's settle lands the same preimage again: no second promotion.
		bob.settleHeldHtlc(hash, preimage);
		const resolution = await waiting;
		expect(resolution.resolved).to.equal(true);
		expect(sent).to.have.length(1);
		expect(preimages).to.have.length(2);
		expect(preimages[1].source).to.equal('htlc');

		const alice2 = createNode(TAG, 8, storage);
		expect(alice2.getPayment(hash)!.status).to.equal(PaymentStatus.COMPLETED);
		expect(alice2.getPayment(hash)!.preimage).to.deep.equal(preimage);
		storage.close();
	});
});
