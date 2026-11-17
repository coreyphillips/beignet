/**
 * A swap counts no asset channel as bitcoin the node could pay with
 * (issue #2093).
 *
 * The submarine swap service asks the node two things before it takes a
 * swap: how much it could send right now, and whether it has a channel
 * with the payee that can carry the payment. An asset channel takes HTLCs
 * and has bitcoin on our side, so both answers counted it. That bitcoin
 * only carries asset outputs and no ordinary payment goes over the channel,
 * so it is left out of both, and an ordinary channel is counted as it was.
 */

import { expect } from 'chai';
import {
	assetHost,
	connectHosts,
	openAssetChannel,
	withAssetOpens,
	type IAssetHost
} from './helpers/auxiliary-nodes';
import { openReadyChannel } from './helpers/loopback-nodes';

describe('A swap counts no asset channel as bitcoin the node could pay with (#2093)', function () {
	this.timeout(60_000);
	withAssetOpens();

	const hosts: IAssetHost[] = [];

	afterEach(() => {
		for (const host of hosts.splice(0)) {
			host.node.destroy();
			host.storage?.close();
		}
	});

	it('answers no outbound and no channel with the payee for an asset channel, and the ordinary channel alone once there is one', async () => {
		const alice = assetHost('audit swap figures', 1);
		const bob = assetHost('audit swap figures', 2);
		hosts.push(alice, bob);
		connectHosts(alice, bob);
		const channelId = await openAssetChannel(alice, bob, {
			tag: 'audit swap figures',
			openerUnits: 9000n,
			acceptorUnits: 1000n
		});
		const figures = alice.node as unknown as {
			swapSpendableOutboundMsat(): bigint;
			swapHasUsableChannelWith(nodeId: Buffer): boolean;
		};
		const payee = Buffer.from(bob.node.getNodeId(), 'hex');
		const manager = alice.node.getChannelManager();

		// The asset channel is one the unfiltered figures would count: it
		// takes HTLCs and has bitcoin on our side.
		const asset = manager.getChannel(channelId)!;
		expect(asset.acceptsNewHtlcs()).to.equal(true);
		expect(asset.getSpendableOutboundMsat() > 0n).to.equal(true);

		expect(figures.swapSpendableOutboundMsat()).to.equal(0n);
		expect(figures.swapHasUsableChannelWith(payee)).to.equal(false);

		const ordinary = manager.getChannel(
			openReadyChannel(alice.node, bob.node)
		)!;
		expect(ordinary.getSpendableOutboundMsat() > 0n).to.equal(true);
		expect(figures.swapSpendableOutboundMsat()).to.equal(
			ordinary.getSpendableOutboundMsat()
		);
		expect(figures.swapHasUsableChannelWith(payee)).to.equal(true);
	});
});
