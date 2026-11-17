/**
 * An ending on the chain whose onHtlcResolved call throws (issue #2093
 * step 10).
 *
 * A delivery pass is started by a write of the channel, and a channel
 * that is on the chain has none: an outcome the host's callback threw for
 * once stayed held until the node was restarted. Each block now offers
 * the host what it has not taken, under the limit of the other retries of
 * an asset channel: three passes per channel per minute. The staging is
 * that of the review of step 10.
 */

import { expect } from 'chai';
import {
	IRREVOCABLE_DEPTH,
	OutputStatus,
	OutputType
} from '../../src/lightning/chain/types';
import type { ITrackedOutput } from '../../src/lightning/chain/types';
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import { withAssetOpens, type IAssetHost } from './helpers/auxiliary-nodes';
import {
	SWEEP_DESTINATION,
	assetChainWorld,
	errorsOf,
	holdUnits,
	settle,
	trackedOutputs,
	type IAssetChainPair
} from './helpers/auxiliary-on-chain';

describe('an outcome of an asset HTLC that the host did not take is offered again on each block (issue #2093 step 10)', function () {
	this.timeout(180000);
	withAssetOpens();
	const world = assetChainWorld();
	const now = Date.now;
	afterEach(() => {
		Date.now = now;
		world.dispose();
	});

	const htlcOf = (
		host: IAssetHost,
		pair: IAssetChainPair
	): ITrackedOutput | undefined =>
		trackedOutputs(host, pair.channelId).find(
			(output) =>
				!output.isSecondLevelHtlc &&
				(output.outputType === OutputType.OFFERED_HTLC ||
					output.outputType === OutputType.RECEIVED_HTLC)
		);
	const isSpent = (output: ITrackedOutput | undefined): boolean =>
		!!output &&
		[OutputStatus.SPEND_CONFIRMED, OutputStatus.IRREVOCABLY_RESOLVED].includes(
			output.status
		);
	/**
	 * Alice offers 5000 units for a hold nobody settles, Bob closes, her
	 * timeout takes the output back and is buried to one block short of
	 * the depth at which its ending is told. `refuses` says whether her
	 * callback throws on a call, by its number.
	 */
	const timedOut = async (
		tag: string,
		refuses: (call: number) => boolean
	): Promise<{
		pair: IAssetChainPair;
		seen: { calls: number; taken: string[] };
	}> => {
		const seen = { calls: 0, taken: [] as string[] };
		const pair = await world.open(tag, {
			feeWallet: { alice: true, bob: true },
			hooks: {
				alice: {
					onHtlcResolved: (context: {
						direction: string;
						outcome: string;
					}): void => {
						seen.calls++;
						if (refuses(seen.calls)) throw new Error('the host store is busy');
						seen.taken.push(`${context.direction}:${context.outcome}`);
					}
				},
				bob: {
					valueIncomingHtlc: (context: { auxiliaryAmount?: bigint }): bigint =>
						context.auxiliaryAmount! * 1000n
				}
			}
		});
		for (const wallet of [pair.wallets.alice!, pair.wallets.bob!]) {
			wallet.fund(100_000);
			wallet.fund(100_000);
		}
		await world.mine(pair, 1);
		const held = await holdUnits(pair, 5000n, tag);
		const closed = pair.bob.node.forceCloseChannel(
			pair.channelId,
			SWEEP_DESTINATION
		);
		expect(closed.ok, closed.error).to.equal(true);
		await settle();
		await world.mine(pair, 2);
		pair.chain.advance(held.cltvExpiry - 1 - pair.chain.height);
		await settle();
		for (let i = 0; i < 10 && !isSpent(htlcOf(pair.alice, pair)); i++) {
			await world.mine(pair, 1);
		}
		const spent = htlcOf(pair.alice, pair)!;
		expect(isSpent(spent)).to.equal(true);
		const spendHeight = pair.chain.confirmed.get(spent.resolutionTxid!)!.height;
		pair.chain.advance(spendHeight + IRREVOCABLE_DEPTH - 1 - pair.chain.height);
		await settle();
		expect(seen.calls).to.equal(0);
		// The block in which the ending is told: the first call.
		for (let i = 0; i < 3 && seen.calls === 0; i++) await world.mine(pair, 1);
		expect(seen.calls).to.equal(1);
		return { pair, seen };
	};
	const refusals = (pair: IAssetChainPair): string[] =>
		errorsOf(pair.alice).filter((e) =>
			e.includes('Asset resolution callback failed')
		);

	it('delivers on the next block an ending whose callback threw once', async () => {
		const { pair, seen } = await timedOut(
			'aux-redeliver-once',
			(call) => call === 1
		);
		expect(seen.taken).to.deep.equal([]);
		expect(refusals(pair)).to.have.length(1);
		expect(
			pair.alice.node.getAuxiliaryChannelInfo(pair.channelId)
				?.undeliveredOutcomes
		).to.equal(1);

		await world.mine(pair, 1);
		expect(seen.calls).to.equal(2);
		expect(seen.taken).to.deep.equal(['OFFERED:failed']);
		// Taken: nothing is held and nothing more is asked.
		for (let i = 0; i < 30; i++) await world.mine(pair, 1);
		expect(seen.calls).to.equal(2);
		expect(refusals(pair)).to.have.length(1);
	});

	it('asks a host that keeps throwing three times a minute for a channel and no more, and again in the next minute', async () => {
		const { pair, seen } = await timedOut('aux-redeliver-limit', () => true);
		for (let i = 0; i < 30; i++) await world.mine(pair, 1);
		expect(seen.calls).to.equal(
			1 + ChannelManager.AUXILIARY_RETRY_ATTEMPTS_PER_INTERVAL
		);
		expect(seen.taken).to.deep.equal([]);

		// A minute on, the next block asks again.
		Date.now = (): number =>
			now() + ChannelManager.AUXILIARY_RETRY_INTERVAL_MS + 1000;
		await world.mine(pair, 1);
		expect(seen.calls).to.equal(
			2 + ChannelManager.AUXILIARY_RETRY_ATTEMPTS_PER_INTERVAL
		);
		Date.now = now;
	});
});
