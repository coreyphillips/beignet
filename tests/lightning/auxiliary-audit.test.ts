/**
 * An asset channel is never offered or rebalanced as if its sats were
 * bitcoin (issue #2093).
 *
 * The bitcoin in an asset channel only carries the channel's units. A
 * blinded payment path over it would invite an ordinary payment the channel
 * does not take, and a rebalance through it would move the carrier. Both
 * are kept from it, and a node without an asset channel builds the paths
 * and rebalances as it did.
 */

import { expect } from 'chai';
import { AuxiliaryPaymentError } from '../../src/lightning/node/types';
import {
	assetHost,
	connectHosts,
	openAssetChannel,
	withAssetOpens,
	type IAssetHost
} from './helpers/auxiliary-nodes';
import { openReadyChannel } from './helpers/loopback-nodes';

describe('An asset channel is never offered or rebalanced as if its sats were bitcoin (#2093)', function () {
	this.timeout(60_000);
	withAssetOpens();

	const hosts: IAssetHost[] = [];

	afterEach(() => {
		for (const host of hosts.splice(0)) {
			host.node.destroy();
			host.storage?.close();
		}
	});

	const pair = async (
		tag: string
	): Promise<{ alice: IAssetHost; bob: IAssetHost; channelId: Buffer }> => {
		const alice = assetHost(tag, 1);
		const bob = assetHost(tag, 2);
		hosts.push(alice, bob);
		connectHosts(alice, bob);
		const channelId = await openAssetChannel(alice, bob, {
			tag,
			openerUnits: 9000n,
			acceptorUnits: 1000n
		});
		return { alice, bob, channelId };
	};

	it('is not offered as a blinded payment path, alone or beside an ordinary channel', async () => {
		const { alice, bob } = await pair('audit blinded paths');
		const paths = (): unknown[] =>
			(
				bob.node as unknown as { buildBlindedPaymentPaths: () => unknown[] }
			).buildBlindedPaymentPaths();
		// Bob's only channel is the asset channel.
		expect(paths()).to.deep.equal([]);
		// With an ordinary channel beside it, that one alone is offered.
		openReadyChannel(alice.node, bob.node);
		expect(paths()).to.have.length(1);
	});

	it('is refused as either channel of a rebalance with a typed error, and nothing is sent', async () => {
		const { alice, bob, channelId } = await pair('audit rebalance');
		const ordinaryId = openReadyChannel(alice.node, bob.node);
		const id = channelId.toString('hex');
		for (const [fromChannelId, toChannelId, leg] of [
			[channelId, ordinaryId, 'from'],
			[ordinaryId, channelId, 'to']
		] as const) {
			const refusal = await alice.node
				.rebalanceChannel({
					fromChannelId,
					toChannelId,
					amountSats: 1000n,
					maxFeeSats: 10n
				})
				.then(
					() => undefined,
					(err: unknown) => err
				);
			expect(refusal, leg).to.be.instanceOf(AuxiliaryPaymentError);
			const error = refusal as AuxiliaryPaymentError;
			expect(error.code, leg).to.equal('ASSET_PAYMENT_UNSUPPORTED');
			expect(error.channelId, leg).to.equal(id);
			expect(error.message, leg).to.include(
				`the ${leg} channel of a rebalance`
			);
		}
		expect(alice.node.listPayments()).to.deep.equal([]);
		expect(bob.node.listPayments()).to.deep.equal([]);
	});
});
