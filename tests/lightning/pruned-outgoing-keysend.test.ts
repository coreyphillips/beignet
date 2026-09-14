/**
 * Issue #840: pruning a settled outgoing payment from memory must not let the
 * payee (who knows the preimage) keysend it back over the outgoing row.
 */

import crypto from 'crypto';
import { expect } from 'chai';
import {
	INodeConfig,
	PaymentDirection,
	PaymentStatus
} from '../../src/lightning/node/types';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	buildGraph,
	connectNodes,
	createNode,
	openReadyChannel
} from './helpers/loopback-nodes';

const TAG = 'pruned-outgoing-keysend';

describe('Pruned outgoing keysend collision (#840)', function () {
	async function collideAfterPrune(
		resourceConfig: INodeConfig['resourceConfig'],
		seedId: number
	): Promise<void> {
		const storage = new SqliteStorage(':memory:');
		storage.open();
		const alice = createNode(TAG, seedId, storage, { resourceConfig });
		const bob = createNode(TAG, seedId + 1);
		const carol = createNode(TAG, seedId + 2);
		connectNodes(alice, bob);
		connectNodes(carol, alice);
		for (const node of [alice, bob, carol]) node.handleNewBlock(1000);
		buildGraph(alice, bob, [openReadyChannel(alice, bob)]);
		buildGraph(carol, alice, [openReadyChannel(carol, alice)]);

		const first = alice.sendKeysend({
			destination: Buffer.from(bob.getNodeId(), 'hex'),
			amountMsat: 5_000_000n
		});
		await new Promise((r) => setTimeout(r, 20));
		const hashHex = first.paymentHash.toString('hex');
		expect(alice.getPayment(first.paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
		const preimage = bob.getPayment(first.paymentHash)!.preimage!;

		await new Promise((r) => setTimeout(r, 5));
		expect(alice.pruneCompletedPayments()).to.be.greaterThan(0);
		expect(alice.getPayment(first.paymentHash)).to.equal(undefined);

		let received = 0;
		alice.on('payment:received', () => received++);

		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const collision = (carol as any).dispatchKeysend(
			{
				destination: Buffer.from(alice.getNodeId(), 'hex'),
				amountMsat: 1_000n
			},
			preimage
		);
		await new Promise((r) => setTimeout(r, 20));

		expect(carol.getPayment(collision.paymentHash)!.status).to.equal(
			PaymentStatus.FAILED
		);
		expect(received, 'no payment:received').to.equal(0);
		expect(alice.getPayment(first.paymentHash), 'no new incoming record').to.be
			.undefined;
		const row = storage.loadPayment(hashHex)!;
		expect(row.direction, 'durable outgoing row kept').to.equal(
			PaymentDirection.OUTGOING
		);
		expect(row.status).to.equal(PaymentStatus.COMPLETED);
		expect(row.amountMsat).to.equal(5_000_000n);
	}

	it('refuses the keysend after the TTL prunes the settled outgoing payment', async function () {
		await collideAfterPrune(
			{
				completedPaymentTtlMs: 1,
				maxCompletedPayments: 10_000,
				cleanupIntervalMs: 0
			},
			1
		);
	});

	it('refuses the keysend after the size cap prunes the settled outgoing payment', async function () {
		await collideAfterPrune(
			{
				completedPaymentTtlMs: 86_400_000,
				maxCompletedPayments: 0,
				cleanupIntervalMs: 0
			},
			10
		);
	});

	// Issue #847: nor may an invoice be created on the hash of any pruned
	// terminal outgoing payment.
	async function invoiceAfterPrune(
		resourceConfig: INodeConfig['resourceConfig'],
		seedId: number,
		outcome: PaymentStatus.COMPLETED | PaymentStatus.FAILED
	): Promise<void> {
		const storage = new SqliteStorage(':memory:');
		storage.open();
		const alice = createNode(TAG, seedId, storage, { resourceConfig });
		const bob = createNode(TAG, seedId + 1);
		connectNodes(alice, bob);
		for (const node of [alice, bob]) node.handleNewBlock(1000);
		buildGraph(alice, bob, [openReadyChannel(alice, bob)]);

		const preimage = crypto.randomBytes(32);
		const paymentHash = crypto.createHash('sha256').update(preimage).digest();
		if (outcome === PaymentStatus.FAILED) {
			// Bob refuses a keysend on a hash his own invoice owns.
			bob.createInvoice({
				amountMsat: 1_000n,
				description: 'owned',
				hold: true,
				paymentHash
			});
		}
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(alice as any).dispatchKeysend(
			{
				destination: Buffer.from(bob.getNodeId(), 'hex'),
				amountMsat: 5_000_000n
			},
			preimage
		);
		await new Promise((r) => setTimeout(r, 20));
		expect(alice.getPayment(paymentHash)!.status).to.equal(outcome);

		await new Promise((r) => setTimeout(r, 5));
		expect(alice.pruneCompletedPayments()).to.be.greaterThan(0);
		expect(alice.getPayment(paymentHash)).to.equal(undefined);
		expect(alice.paymentHashInUse(paymentHash)).to.equal(true);

		expect(() =>
			alice.createInvoice({
				amountMsat: 1_000n,
				description: 'reuse',
				hold: true,
				paymentHash
			})
		).to.throw('paymentHash is already in use by this node');
		const row = storage.loadPayment(paymentHash.toString('hex'))!;
		expect(row.direction, 'durable outgoing row kept').to.equal(
			PaymentDirection.OUTGOING
		);
		expect(row.status).to.equal(outcome);
		expect(row.amountMsat).to.equal(5_000_000n);
	}

	it('refuses an invoice after the TTL prunes the settled outgoing payment (#847)', async function () {
		await invoiceAfterPrune(
			{
				completedPaymentTtlMs: 1,
				maxCompletedPayments: 10_000,
				cleanupIntervalMs: 0
			},
			20,
			PaymentStatus.COMPLETED
		);
	});

	it('refuses an invoice after the size cap prunes the settled outgoing payment (#847)', async function () {
		await invoiceAfterPrune(
			{
				completedPaymentTtlMs: 86_400_000,
				maxCompletedPayments: 0,
				cleanupIntervalMs: 0
			},
			30,
			PaymentStatus.COMPLETED
		);
	});

	it('refuses an invoice after the TTL prunes the failed outgoing payment (#847)', async function () {
		await invoiceAfterPrune(
			{
				completedPaymentTtlMs: 1,
				maxCompletedPayments: 10_000,
				cleanupIntervalMs: 0
			},
			40,
			PaymentStatus.FAILED
		);
	});
});
