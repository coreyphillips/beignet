/**
 * Issue #829: a settled keysend has no invoice to keep its hash closed, so
 * pruning its payment from memory must not let a sender replay the preimage.
 * Issue #841: nor may a hold invoice be created on that hash.
 */

import { expect } from 'chai';
import { INodeConfig, PaymentStatus } from '../../src/lightning/node/types';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	buildGraph,
	connectNodes,
	createNode,
	openReadyChannel
} from './helpers/loopback-nodes';

const TAG = 'pruned-keysend-replay';

describe('Pruned keysend replay (#829)', function () {
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

		const destination = Buffer.from(bob.getNodeId(), 'hex');
		const first = alice.sendKeysend({ destination, amountMsat: 5_000_000n });
		await new Promise((r) => setTimeout(r, 20));
		const paid = alice.getPayment(first.paymentHash)!;
		expect(paid.status).to.equal(PaymentStatus.COMPLETED);
		expect(bob.getPayment(first.paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);

		await new Promise((r) => setTimeout(r, 5));
		expect(bob.pruneCompletedPayments()).to.be.greaterThan(0);
		expect(bob.getPayment(first.paymentHash)).to.equal(undefined);

		let received = 0;
		bob.on('payment:received', () => received++);

		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const replay = (carol as any).dispatchKeysend(
			{ destination, amountMsat: 1_000n },
			paid.preimage!
		);
		await new Promise((r) => setTimeout(r, 20));

		expect(carol.getPayment(replay.paymentHash)!.status).to.equal(
			PaymentStatus.FAILED
		);
		expect(received, 'no second payment:received').to.equal(0);
		expect(bob.getPayment(first.paymentHash), 'no new incoming record').to.be
			.undefined;
	}

	it('refuses a replayed keysend after the TTL prunes the settled payment', async function () {
		await replayAfterPrune(
			{
				completedPaymentTtlMs: 1,
				maxCompletedPayments: 10_000,
				cleanupIntervalMs: 0
			},
			1
		);
	});

	it('refuses a replayed keysend after the size cap prunes the settled payment', async function () {
		await replayAfterPrune(
			{
				completedPaymentTtlMs: 86_400_000,
				maxCompletedPayments: 0,
				cleanupIntervalMs: 0
			},
			10
		);
	});

	it('refuses a hold invoice on the hash of a pruned settled keysend (#841)', async function () {
		const storage = new SqliteStorage(':memory:');
		storage.open();
		const alice = createNode(TAG, 20);
		const bob = createNode(TAG, 21, storage, {
			resourceConfig: {
				completedPaymentTtlMs: 1,
				maxCompletedPayments: 10_000,
				cleanupIntervalMs: 0
			}
		});
		connectNodes(alice, bob);
		for (const node of [alice, bob]) node.handleNewBlock(1000);
		buildGraph(alice, bob, [openReadyChannel(alice, bob)]);

		const first = alice.sendKeysend({
			destination: Buffer.from(bob.getNodeId(), 'hex'),
			amountMsat: 5_000_000n
		});
		await new Promise((r) => setTimeout(r, 20));
		const hashHex = first.paymentHash.toString('hex');
		expect(bob.getPayment(first.paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);

		await new Promise((r) => setTimeout(r, 5));
		expect(bob.pruneCompletedPayments()).to.be.greaterThan(0);
		expect(bob.getPayment(first.paymentHash)).to.equal(undefined);
		expect(bob.paymentHashInUse(first.paymentHash)).to.equal(true);

		expect(() =>
			bob.createInvoice({
				amountMsat: 1_000n,
				description: 'reuse',
				hold: true,
				paymentHash: first.paymentHash
			})
		).to.throw('paymentHash is already in use by this node');
		const row = storage.loadPayment(hashHex)!;
		expect(row.status, 'durable keysend row kept').to.equal(
			PaymentStatus.COMPLETED
		);
		expect(row.metadata?._keysend).to.equal('true');
	});
});
