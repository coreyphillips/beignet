/**
 * An asset channel is quoted no splice and takes part in no composite
 * splice (issue #2093).
 *
 * The channel itself refuses a splice, started here or by the peer. What
 * is checked here is what stands in front of that: a splice quote would
 * state how much bitcoin could be taken out of the channel or added to it,
 * and the composite planner would rank it among the channels to pay a
 * destination from. Both say that it is an asset channel, and an ordinary
 * channel beside it is quoted as it was.
 */

import { expect } from 'chai';
import { InvalidSpliceError } from '../../src/lightning/node/types';
import type { Channel } from '../../src/lightning/channel/channel';
import {
	assetHost,
	connectHosts,
	openAssetChannel,
	withAssetOpens,
	type IAssetHost
} from './helpers/auxiliary-nodes';
import { openReadyChannel } from './helpers/loopback-nodes';

const DESTINATION = Buffer.concat([
	Buffer.from('0014', 'hex'),
	Buffer.alloc(20, 9)
]);

describe('An asset channel is quoted no splice and joins no composite splice (#2093)', function () {
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

	it('refuses a splice quote in either direction with a typed error that names the channel', async () => {
		const { alice, bob, channelId } = await pair('audit splice quote');
		for (const direction of ['out', 'in'] as const) {
			let refusal: unknown;
			try {
				alice.node.spliceQuote(channelId, direction, 1000, DESTINATION);
			} catch (err) {
				refusal = err;
			}
			expect(refusal, direction).to.be.instanceOf(InvalidSpliceError);
			expect((refusal as Error).message, direction).to.equal(
				`An asset channel does not support a splice (channel ${channelId.toString(
					'hex'
				)})`
			);
		}
		// An ordinary channel beside it is quoted, and for its own bitcoin.
		const ordinaryId = openReadyChannel(alice.node, bob.node);
		const quote = alice.node.spliceQuote(ordinaryId, 'out', 1000, DESTINATION);
		expect(quote.direction).to.equal('out');
		expect(quote.spendableSats).to.be.greaterThan(0);
		expect(quote.spendableSats).to.be.lessThan(1_000_000);
	});

	it('is no channel of a composite splice: the planner says why before any other reason', async () => {
		const { alice, channelId } = await pair('audit composite splice');
		const engine = (
			alice.node as unknown as {
				compositeSplice(): {
					ineligible(
						channel: Channel,
						amountSats: bigint
					): Promise<string | null>;
				};
			}
		).compositeSplice();
		const channel = alice.node.getChannelManager().getChannel(channelId)!;
		expect(await engine.ineligible(channel, 100_000n)).to.equal(
			'an asset channel is not spliced'
		);
	});
});
