/**
 * The prune tick's liveness check (issue #1676). getOutgoingHtlcs walks
 * every channel and the whole HTLC map, so the pruner must not ask it about
 * every retained payment each minute: not at all under the cap, and over it
 * only for a hash that can still have an HTLC out. Which records go must not
 * change, and one with a live HTLC must never go.
 */

import { expect } from 'chai';
import { OutputStatus, OutputType } from '../../src/lightning/chain/types';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	IPaymentInfo,
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

const TAG = 'prune-liveness-scan';

interface INodeInternals {
	payments: Map<string, IPaymentInfo>;
	resourceConfig: { maxCompletedPayments: number };
}

function internals(node: LightningNode): INodeInternals {
	return node as unknown as INodeInternals;
}

function setup(
	aliceId: number,
	bobId: number,
	completedPaymentTtlMs: number,
	maxCompletedPayments: number
): { alice: LightningNode; bob: LightningNode; channelId: Buffer } {
	const alice = createNode(TAG, aliceId, undefined, {
		resourceConfig: {
			completedPaymentTtlMs,
			maxCompletedPayments,
			cleanupIntervalMs: 0
		}
	});
	const bob = createNode(TAG, bobId);
	connectNodes(alice, bob);
	alice.handleNewBlock(1000);
	bob.handleNewBlock(1000);
	const channelId = openReadyChannel(alice, bob);
	buildGraph(alice, bob, [channelId]);
	return { alice, bob, channelId };
}

/** Pay a hold invoice of bob's: the HTLC stays out until bob decides. */
function sendHeld(alice: LightningNode, bob: LightningNode): Buffer {
	const { hash } = makeExternalHash();
	const invoice = bob.createInvoice({
		amountMsat: 5_000_000n,
		description: 'held',
		hold: true,
		paymentHash: hash
	});
	alice.sendPayment(invoice.bolt11);
	return hash;
}

/** COMPLETED outgoing records with no HTLC anywhere, oldest first. */
function addCompleted(
	node: LightningNode,
	count: number,
	completedAt: number
): string[] {
	const hashes: string[] = [];
	for (let i = 0; i < count; i++) {
		const { hash } = makeExternalHash();
		internals(node).payments.set(hash.toString('hex'), {
			paymentHash: hash,
			amountMsat: 1_000n,
			status: PaymentStatus.COMPLETED,
			direction: PaymentDirection.OUTGOING,
			createdAt: completedAt + i,
			completedAt: completedAt + i
		});
		hashes.push(hash.toString('hex'));
	}
	return hashes;
}

function countViews(node: LightningNode): { calls: number } {
	const counter = { calls: 0 };
	const original = node.getOutgoingHtlcs.bind(node);
	node.getOutgoingHtlcs = (hash: Buffer) => {
		counter.calls++;
		return original(hash);
	};
	return counter;
}

describe('Prune tick liveness check (issue #1676)', function () {
	it('asks no record for its HTLCs under the cap, and over it none with no HTLC out', function () {
		const { alice, bob } = setup(1, 2, 86_400_000, 10_000);
		// A payment with its HTLC out, so the channels are not empty.
		const pending = sendHeld(alice, bob);
		const hashes = addCompleted(alice, 5_000, Date.now() - 1_000_000);
		const views = countViews(alice);

		expect(alice.pruneCompletedPayments()).to.equal(0);
		expect(views.calls, 'under the cap').to.equal(0);

		internals(alice).resourceConfig.maxCompletedPayments = 4_000;
		expect(alice.pruneCompletedPayments()).to.equal(1_000);
		expect(views.calls, 'over the cap, no HTLC out').to.equal(0);
		const payments = internals(alice).payments;
		expect(hashes.slice(0, 1_000).some((h) => payments.has(h))).to.equal(false);
		expect(hashes.slice(1_000).every((h) => payments.has(h))).to.equal(true);
		expect(alice.getPayment(pending)!.status).to.equal(PaymentStatus.PENDING);
	});

	it('over the cap a live record is checked, kept, and not counted toward the cap', function () {
		const { alice, bob } = setup(3, 4, 86_400_000, 3);
		const live = sendHeld(alice, bob);
		alice.failPayment(live, 'timeout');
		// The oldest record, so only its live HTLC keeps it.
		internals(alice).payments.get(live.toString('hex'))!.completedAt =
			Date.now() - 100_000;
		const hashes = addCompleted(alice, 3, Date.now() - 50_000);
		const views = countViews(alice);

		// Four terminal records, but only three can go: none over the cap.
		expect(alice.pruneCompletedPayments()).to.equal(0);
		expect(views.calls, 'only the hash with an HTLC out').to.equal(1);

		internals(alice).resourceConfig.maxCompletedPayments = 2;
		expect(alice.pruneCompletedPayments()).to.equal(1);
		expect(views.calls).to.equal(2);
		const payments = internals(alice).payments;
		expect(payments.has(hashes[0]), 'oldest prunable').to.equal(false);
		expect(payments.has(hashes[1])).to.equal(true);
		expect(payments.has(hashes[2])).to.equal(true);
		expect(alice.getPayment(live)!.status).to.equal(PaymentStatus.FAILED);
	});

	it('keeps a record whose mapped HTLC is gone from the channel but still tracked by its monitor', async function () {
		const { alice, bob, channelId } = setup(5, 6, 1, 0);
		const hash = sendHeld(alice, bob);
		alice.failPayment(hash, 'timeout');
		// The channel no longer carries the entry: only the HTLC map and the
		// monitor know the HTLC.
		const htlcs = alice
			.getChannelManager()
			.getChannel(channelId)!
			.getFullState().htlcs;
		const key = [...htlcs.keys()].find((k) => k.startsWith('offered-'))!;
		const htlcId = htlcs.get(key)!.id;
		htlcs.delete(key);
		let status = OutputStatus.SPEND_CONFIRMED;
		const manager = alice.getChannelManager() as unknown as {
			getMonitor(id: Buffer): unknown;
		};
		manager.getMonitor = (id: Buffer) =>
			id.equals(channelId)
				? {
						getTrackedOutputs: () => [
							{
								outputType: OutputType.OFFERED_HTLC,
								htlcId,
								paymentHash: hash,
								status,
								amount: 5_000n
							}
						]
				  }
				: undefined;
		await new Promise((r) => setTimeout(r, 5));

		expect(alice.pruneCompletedPayments()).to.equal(0);
		expect(alice.getPayment(hash)!.status).to.equal(PaymentStatus.FAILED);

		status = OutputStatus.IRREVOCABLY_RESOLVED;
		expect(alice.pruneCompletedPayments()).to.equal(1);
		expect(alice.getPayment(hash)).to.equal(undefined);
	});
});
