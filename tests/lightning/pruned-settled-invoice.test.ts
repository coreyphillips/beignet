/**
 * Issue #819: pruning a settled incoming payment from memory keeps the
 * invoice, and the invoice's hash must stay closed to a keysend carrying
 * the revealed preimage.
 */

import { expect } from 'chai';
import { INodeConfig, PaymentStatus } from '../../src/lightning/node/types';
import {
	buildGraph,
	connectNodes,
	createNode,
	openReadyChannel
} from './helpers/loopback-nodes';

const TAG = 'pruned-settled-invoice';

describe('Pruned settled invoice (#819)', function () {
	async function replayAfterPrune(
		resourceConfig: INodeConfig['resourceConfig'],
		seedId: number
	): Promise<void> {
		const alice = createNode(TAG, seedId);
		const bob = createNode(TAG, seedId + 1, undefined, { resourceConfig });
		const carol = createNode(TAG, seedId + 2);
		connectNodes(alice, bob);
		connectNodes(carol, bob);
		for (const node of [alice, bob, carol]) node.handleNewBlock(1000);
		buildGraph(alice, bob, [openReadyChannel(alice, bob)]);
		buildGraph(carol, bob, [openReadyChannel(carol, bob)]);

		const invoice = bob.createInvoice({
			amountMsat: 5_000_000n,
			description: 'settled-then-pruned'
		});
		alice.sendPayment(invoice.bolt11);
		const paid = alice.getPayment(invoice.paymentHash)!;
		expect(paid.status).to.equal(PaymentStatus.COMPLETED);
		const preimage = paid.preimage!;

		await new Promise((r) => setTimeout(r, 5));
		expect(bob.pruneCompletedPayments()).to.be.greaterThan(0);
		expect(bob.getPayment(invoice.paymentHash)).to.equal(undefined);

		let received = 0;
		let settled = 0;
		bob.on('payment:received', () => received++);
		bob.on('invoice:settled', () => settled++);

		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const keysend = (carol as any).dispatchKeysend(
			{
				destination: Buffer.from(bob.getNodeId(), 'hex'),
				amountMsat: 1_000n
			},
			preimage
		);
		await new Promise((r) => setTimeout(r, 20));

		expect(carol.getPayment(keysend.paymentHash)!.status).to.equal(
			PaymentStatus.FAILED
		);
		expect(received, 'no second payment:received').to.equal(0);
		expect(settled, 'no second invoice:settled').to.equal(0);
		expect(bob.getPayment(invoice.paymentHash), 'no new incoming record').to.be
			.undefined;
	}

	it('refuses a keysend on the hash after the TTL prunes the settled payment', async function () {
		await replayAfterPrune(
			{
				completedPaymentTtlMs: 1,
				maxCompletedPayments: 10_000,
				cleanupIntervalMs: 0
			},
			1
		);
	});

	it('refuses a keysend on the hash after the size cap prunes the settled payment', async function () {
		await replayAfterPrune(
			{
				completedPaymentTtlMs: 86_400_000,
				maxCompletedPayments: 0,
				cleanupIntervalMs: 0
			},
			10
		);
	});
});
