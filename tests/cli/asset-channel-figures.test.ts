/**
 * The daemon's bitcoin figures leave an asset channel out (issue #2093).
 *
 * The bitcoin in an asset channel only carries asset outputs. It is not a
 * Lightning balance on its way back to the wallet when the channel closes,
 * and it is not a balance held with a primary that a bitcoin receive could
 * be weighed against. Each figure here is read with ordinary channels only,
 * where it is the figure it always was, and again with an asset channel
 * beside them, where it has not moved.
 *
 * The node is faked here, at the one place the daemon reads it.
 */

import { expect } from 'chai';
import { BeignetNode } from '../../src/cli/beignet-node';
import { ChannelState } from '../../src/lightning/channel/types';

const methods = BeignetNode.prototype as unknown as Record<
	string,
	(this: unknown, ...args: unknown[]) => unknown
>;

type Row = Record<string, unknown>;

describe('The daemon and an asset channel: bitcoin figures (#2093)', () => {
	it('leaves a closing asset channel out of the balance that is pending close', () => {
		const pending = (rows: Row[]): number =>
			methods.getPendingCloseBalanceSats.call({
				isForceCloseBalanceInWallet: (): boolean => false,
				node: {
					listChannels: (): Row[] => rows,
					getChannelManager: (): unknown => ({
						getChannel: (): undefined => undefined
					})
				}
			}) as number;
		const ordinary: Row[] = [
			{
				channelId: Buffer.alloc(32, 1),
				state: ChannelState.SHUTTING_DOWN,
				localBalanceMsat: 700_000_000n
			},
			{
				channelId: Buffer.alloc(32, 2),
				state: ChannelState.FORCE_CLOSED,
				localBalanceMsat: 300_000_000n
			},
			{
				channelId: Buffer.alloc(32, 3),
				state: ChannelState.NORMAL,
				localBalanceMsat: 9_000_000_000n
			}
		];
		expect(pending(ordinary)).to.equal(1_000_000);
		for (const state of [
			ChannelState.FORCE_CLOSED,
			ChannelState.SHUTTING_DOWN,
			ChannelState.NEGOTIATING_CLOSING
		]) {
			expect(
				pending([
					...ordinary,
					{
						channelId: Buffer.alloc(32, 7),
						state,
						localBalanceMsat: 1_500_000_000n,
						auxiliary: true
					}
				]),
				state
			).to.equal(1_000_000);
		}
	});

	it('counts no asset channel toward a primary, in its balance, its channels or the choice of who receives', () => {
		const first = '02' + 'aa'.repeat(32);
		const second = '03' + 'bb'.repeat(32);
		const channel = (
			fill: number,
			peer: string,
			localBalanceMsat: bigint,
			asset: boolean
		): Row => ({
			peer,
			acceptsNewHtlcs: (): boolean => true,
			getChannelId: (): Buffer => Buffer.alloc(32, fill),
			getFullState: (): Row => ({
				localBalanceMsat,
				...(asset ? { auxiliaryState: { localBalance: 900n } } : {})
			})
		});
		const primaries = (channels: Row[]): Row => {
			const daemon = {
				primaryBalances: methods.primaryBalances,
				primariesStore: (): unknown => ({
					get: (): unknown => ({
						fillThresholdSat: 100_000,
						primaries: [{ pubkey: first }, { pubkey: second }]
					})
				}),
				node: {
					getChannelManager: (): unknown => ({
						listChannels: (): Row[] => channels,
						getPeerForChannel: (id: Buffer): string | null =>
							(channels.find((c) =>
								(c.getChannelId as () => Buffer)().equals(id)
							)?.peer as string) ?? null
					})
				}
			};
			return methods.listPrimaries.call(daemon) as Row;
		};
		const row = (info: Row, at: number): Row => (info.primaries as Row[])[at];

		// Ordinary channels only: the first primary is full, so the second
		// receives. This is the answer the figure always gave.
		const full = primaries([
			channel(1, first, 1_500_000_000n, false),
			channel(2, second, 50_000_000n, false)
		]);
		expect(row(full, 0)).to.include({
			balanceSat: 1_500_000,
			channelCount: 1,
			belowThreshold: false,
			isReceiveTarget: false
		});
		expect(full.receiveTarget).to.equal(second);

		// The same bitcoin in an asset channel with the first primary is no
		// balance held there: it is still the one to fill.
		const asset = primaries([
			channel(7, first, 1_500_000_000n, true),
			channel(2, second, 50_000_000n, false)
		]);
		expect(row(asset, 0)).to.include({
			balanceSat: 0,
			channelCount: 0,
			belowThreshold: true,
			isReceiveTarget: true
		});
		expect(asset.receiveTarget).to.equal(first);

		// Beside an ordinary channel with the same primary, only the ordinary
		// one is counted.
		const both = primaries([
			channel(7, first, 1_500_000_000n, true),
			channel(1, first, 40_000_000n, false),
			channel(2, second, 50_000_000n, false)
		]);
		expect(row(both, 0)).to.include({ balanceSat: 40_000, channelCount: 1 });
		expect(row(both, 1)).to.include({ balanceSat: 50_000, channelCount: 1 });
	});
});
