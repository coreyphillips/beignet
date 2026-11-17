/**
 * The daemon takes no on-chain send out of an asset channel (issue #2093).
 *
 * A send from channel funds is a splice out of the channel that can spare
 * the most. An asset channel is never spliced, and the bitcoin in it only
 * carries asset outputs, so it is not ranked: the send comes from an
 * ordinary channel, or from none.
 *
 * The node is faked here, at the one place the daemon reads it. The fake
 * quotes every channel, the asset channel too, so what keeps it out is the
 * daemon's own check.
 */

import { expect } from 'chai';
import { BeignetNode } from '../../src/cli/beignet-node';
import { ChannelState } from '../../src/lightning/channel/types';

const methods = BeignetNode.prototype as unknown as Record<
	string,
	(this: unknown, ...args: unknown[]) => unknown
>;

type Row = Record<string, unknown>;

const channel = (fill: number, spendableSats: number, asset: boolean): Row => ({
	spendableSats,
	getChannelId: (): Buffer => Buffer.alloc(32, fill),
	getState: (): ChannelState => ChannelState.NORMAL,
	spliceBusyReason: (): null => null,
	spliceInteractiveTxDustFloor: (): bigint => 546n,
	getFundingSatoshis: (): bigint => 2_000_000n,
	getFullState: (): Row => ({
		...(asset ? { auxiliaryState: { localBalance: 900n } } : {})
	})
});

const pick = (channels: Row[]): Row | null => {
	const quoted: string[] = [];
	const daemon = {
		node: {
			getChannelManager: (): unknown => ({
				listChannels: (): Row[] => channels,
				getPeerForChannel: (): string => '02' + 'aa'.repeat(32)
			}),
			peerSupportsSplicing: (): boolean => true,
			spliceQuote: (channelId: Buffer): Row => {
				quoted.push(channelId.toString('hex'));
				const spendableSats = channels.find((c) =>
					(c.getChannelId as () => Buffer)().equals(channelId)
				)!.spendableSats as number;
				return {
					direction: 'out',
					feeSats: 500,
					spendableSats,
					maxAmountSats: spendableSats
				};
			}
		}
	};
	const best = methods._singleChannelSend.call(
		daemon,
		100_000,
		1000,
		Buffer.alloc(22, 1)
	) as Row | null;
	return best ? { ...best, quoted } : null;
};

describe('The daemon and an asset channel: a send from channel funds (#2093)', () => {
	it('ranks ordinary channels as it did', () => {
		const best = pick([channel(1, 400_000, false), channel(2, 900_000, false)]);
		expect((best!.channelId as Buffer).toString('hex')).to.equal(
			'02'.repeat(32)
		);
		expect(best).to.include({
			feeSats: 500,
			oldCapacitySats: 2_000_000,
			spendableSats: 900_000
		});
		expect(best!.quoted).to.deep.equal(['01'.repeat(32), '02'.repeat(32)]);
	});

	it('takes the send from an ordinary channel though an asset channel holds more bitcoin, and asks no quote of the asset channel', () => {
		const best = pick([
			channel(7, 1_900_000, true),
			channel(1, 400_000, false)
		]);
		expect((best!.channelId as Buffer).toString('hex')).to.equal(
			'01'.repeat(32)
		);
		expect(best!.spendableSats).to.equal(400_000);
		expect(best!.quoted).to.deep.equal(['01'.repeat(32)]);
	});

	it('finds no channel to send from when the only channel is an asset channel', () => {
		expect(pick([channel(7, 1_900_000, true)])).to.equal(null);
	});
});
