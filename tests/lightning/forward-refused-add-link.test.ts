/**
 * A forward whose outgoing add the channel refuses writes no link to its
 * incoming HTLC. The link is staged beside the add and commits with it; a
 * refused add takes it back before anything is written, so no stored row
 * ever maps an outgoing HTLC id the channel did not use, which a later
 * unrelated HTLC would take.
 */

import { expect } from 'chai';
import type { LightningNode } from '../../src/lightning/node/lightning-node';
import { PaymentStatus } from '../../src/lightning/node/types';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	connectNodes,
	createNode,
	openReadyChannel
} from './helpers/loopback-nodes';

const settle = async (): Promise<void> => {
	for (let i = 0; i < 60; i++) {
		await new Promise<void>((resolve) => setImmediate(resolve));
	}
};

describe('a forward refused at the outgoing add writes no link', function () {
	this.timeout(60_000);
	const nodes: LightningNode[] = [];
	const storages: SqliteStorage[] = [];
	afterEach(() => {
		for (const node of nodes.splice(0)) node.destroy();
		for (const storage of storages.splice(0)) storage.close();
	});

	it('commits no batch that holds the link, and leaves no link row, when the outgoing channel refuses the add', async () => {
		const tag = 'forward-refused-add-link';
		const storage = new SqliteStorage(':memory:');
		storage.open();
		storages.push(storage);
		const alice = createNode(tag, 1);
		const bob = createNode(tag, 2, storage);
		const carol = createNode(tag, 3);
		nodes.push(alice, bob, carol);
		connectNodes(alice, bob);
		connectNodes(bob, carol);
		const inChannel = openReadyChannel(alice, bob, 5_000_000n);
		const outChannel = openReadyChannel(bob, carol, 1_000_000n);
		await settle();
		const outAlias = bob
			.getChannelManager()
			.getChannel(outChannel)!
			.getFullState().scidAlias!;
		const inAlias = alice
			.getChannelManager()
			.getChannel(inChannel)!
			.getFullState().scidAlias!;

		// Every batch Bob commits, by the types of its mutations.
		const commits: string[][] = [];
		const recovery = (
			bob as unknown as {
				recovery: {
					commit: (input: { mutations: Array<{ type: string }> }) => unknown;
				};
			}
		).recovery;
		const commit = recovery.commit.bind(recovery);
		recovery.commit = (input): unknown => {
			commits.push(input.mutations.map((mutation) => mutation.type));
			return commit(input);
		};

		// 1,500,000 sat onward over a channel Bob funded with 1,000,000.
		const forwardMsat = 1_500_000_000n;
		const invoice = carol.createInvoice({
			amountMsat: forwardMsat,
			description: tag
		});
		alice.sendPaymentToRoute(
			{
				hops: [
					{
						pubkey: Buffer.from(bob.getNodeId(), 'hex'),
						shortChannelId: inAlias,
						amountToForwardMsat: forwardMsat + 10_000n,
						outgoingCltvValue: 240
					},
					{
						pubkey: Buffer.from(carol.getNodeId(), 'hex'),
						shortChannelId: outAlias,
						amountToForwardMsat: forwardMsat,
						outgoingCltvValue: 40
					}
				]
			},
			invoice.paymentHash,
			40,
			invoice.paymentSecret
		);
		await settle();
		await settle();

		expect(alice.getPayment(invoice.paymentHash)?.status).to.equal(
			PaymentStatus.FAILED
		);
		expect(
			bob.getChannelManager().getChannel(outChannel)!.getFullState()
				.localHtlcCounter
		).to.equal(0n);
		expect(
			commits.some((types) => types.includes('forwarded_htlc')),
			JSON.stringify(commits)
		).to.equal(false);
		expect(storage.loadAllForwardedHtlcs()).to.deep.equal([]);
	});
});
