/**
 * The daemon counts no asset channel as a channel for ordinary payments
 * (issue #2093).
 *
 * No ordinary payment goes over an asset channel. So it is not one of the
 * channels a minimum is filled with, not the channel a payment is checked
 * against, not the second channel that makes one a spare, not a balance to
 * read for depletion, and not the channel the payment queues wait for.
 * Each answer is read with ordinary channels only, where it is the answer
 * it always was, and with an asset channel in the list.
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

/** The BOLT 11 specification's 2500 micro-bitcoin invoice. */
const BOLT11 =
	'lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs' +
	'pp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7' +
	'enxv4jsxqzpu9qrsgquk0rl77nj30yxdy8j9vdx85fkpmdla2087ne0xh8nhedh8w27kyke' +
	'0lp53ut353s06fv3qfegext0eh0ymjpf39tuven09sam30g4vgpfna3rh';

const ready = (fill: number, extra: Row = {}): Row => ({
	channelId: fill.toString(16).padStart(2, '0').repeat(32),
	state: 'NORMAL',
	...extra
});

describe('The daemon and an asset channel: channels counted for ordinary payments (#2093)', () => {
	it('fills a minimum of channels with ordinary channels only', async () => {
		const ensure = async (
			rows: Row[]
		): Promise<{ channels: Row[]; asked: number[] }> => {
			const asked: number[] = [];
			const channels = (await methods.ensureMinimumChannels.call(
				{
					isGraphRestoring: (): boolean => false,
					getReadyChannels: (): Row[] => rows,
					getChannelSuggestions: (count: number): unknown[] => {
						asked.push(count);
						return [];
					}
				},
				2,
				100_000
			)) as Row[];
			return { channels, asked };
		};
		// Two ordinary channels meet a minimum of two: nothing is looked for.
		const two = [ready(1), ready(2)];
		expect(await ensure(two)).to.deep.equal({ channels: two, asked: [] });
		// One ordinary and one asset channel do not: one more is looked for,
		// and the asset channel is not among the channels answered.
		const mixed = await ensure([ready(1), ready(7, { auxiliary: true })]);
		expect(mixed.asked).to.deep.equal([2]);
		expect(mixed.channels).to.deep.equal([ready(1)]);
	});

	it('says an ordinary payment has no channel when the only ready channel is an asset channel', () => {
		const channelsCheck = (rows: Row[]): Row | undefined => {
			const result = methods.validatePayment.call(
				{
					decodeInvoice: (): Row => ({}),
					_maxPaymentSats: undefined,
					_dailySpendLimitSats: undefined,
					_draining: false,
					canSend: (): Row => ({ canSend: true, availableSats: 1_000_000 }),
					estimatePayment: (): null => null,
					getReadyChannels: (): Row[] => rows,
					_buildValidationResult: methods._buildValidationResult
				},
				BOLT11
			) as { checks: Row[] };
			return result.checks.find((check) => check.name === 'CHANNELS');
		};
		expect(channelsCheck([ready(1)])).to.equal(undefined);
		expect(channelsCheck([ready(1), ready(7, { auxiliary: true })])).to.equal(
			undefined
		);
		const none = channelsCheck([]);
		const assetOnly = channelsCheck([ready(7, { auxiliary: true })]);
		expect(none).to.include({ name: 'CHANNELS', status: 'FAIL' });
		expect(assetOnly).to.deep.equal(none);
	});

	it('scores mainnet readiness on ordinary channels: an asset channel is no spare and its bitcoin says nothing about depletion', () => {
		const readiness = (rows: Row[]): Record<string, Row> => {
			const result = methods.getMainnetReadiness.call({
				storage: {},
				backupPath: '/backups',
				electrumServerCount: 2,
				getHealth: (): Row => ({ electrumConnected: true }),
				getFeeSnapshot: (): Row => ({ sampleCount: 3 }),
				channelBackupReadiness: (): Row => ({
					name: 'CHANNEL_BACKUP',
					status: 'PASS',
					severity: 'WARNING',
					message: 'backed up'
				}),
				node: {
					getNodeInfo: (): Row => ({ networkingEnabled: true }),
					listChannels: (): Row[] => rows,
					getGraph: (): Row => ({
						getChannelCount: (): number => 5,
						getNodeCount: (): number => 4
					})
				}
			}) as { score: number; checks: Row[] };
			return {
				...Object.fromEntries(result.checks.map((c) => [c.name, c])),
				SCORE: { score: result.score }
			};
		};
		const channel = (localSats: bigint, extra: Row = {}): Row => ({
			state: 'NORMAL',
			channelType: null,
			fundingSatoshis: 1_000_000n,
			localBalanceMsat: localSats * 1000n,
			...extra
		});

		// Two ordinary channels, one of them balanced: a spare, and healthy.
		const two = readiness([channel(950_000n), channel(500_000n)]);
		expect(two.SUFFICIENT_CHANNELS.status).to.equal('PASS');
		expect(two.SUFFICIENT_CHANNELS.message).to.equal(
			'2 ready channels (redundancy OK)'
		);
		expect(two.CHANNEL_BALANCE_HEALTH.message).to.equal(
			'Channel balances are healthy'
		);
		expect(two.HAS_ACTIVE_CHANNEL.message).to.equal('2 active channel(s)');

		// The balanced one is an asset channel: the ordinary channel is the
		// only one, and it is depleted.
		const mixed = readiness([
			channel(950_000n),
			channel(500_000n, { auxiliary: true })
		]);
		expect(mixed.SUFFICIENT_CHANNELS.status).to.equal('WARN');
		expect(mixed.SUFFICIENT_CHANNELS.message).to.match(
			/^Only 1 ready channel /
		);
		expect(mixed.CHANNEL_BALANCE_HEALTH).to.include({
			status: 'WARN',
			message: 'All 1 channel(s) are >90% depleted in one direction'
		});
		expect(mixed.HAS_ACTIVE_CHANNEL.message).to.equal('1 active channel(s)');
		expect(mixed.SCORE.score).to.be.lessThan(two.SCORE.score as number);

		// An asset channel alone reads as a node with no channel yet.
		expect(readiness([channel(500_000n, { auxiliary: true })])).to.deep.equal(
			readiness([])
		);
	});

	it('holds the payment queues for an ordinary channel, and does not wait for an asset channel', () => {
		const channel = (
			state: ChannelState,
			accepts: boolean,
			asset = false
		): Row => ({
			acceptsNewHtlcs: (): boolean => accepts,
			getFullState: (): Row => ({
				state,
				...(state === ChannelState.AWAITING_REESTABLISH
					? { preReestablishState: ChannelState.NORMAL }
					: {}),
				...(asset ? { auxiliaryState: { localBalance: 900n } } : {})
			})
		});
		const canCarry = (channels: Row[]): boolean =>
			methods.canCarryHtlc.call({
				node: {
					getChannelManager: (): unknown => ({
						listChannels: (): Row[] => channels
					})
				}
			}) as boolean;
		const usable = channel(ChannelState.NORMAL, true);
		const coming = channel(ChannelState.AWAITING_REESTABLISH, false);
		const usableAsset = channel(ChannelState.NORMAL, true, true);
		const comingAsset = channel(ChannelState.AWAITING_REESTABLISH, false, true);

		// Ordinary channels only, as it always answered.
		expect(canCarry([])).to.equal(true);
		expect(canCarry([usable])).to.equal(true);
		expect(canCarry([coming])).to.equal(false);
		expect(canCarry([coming, usable])).to.equal(true);

		// A usable asset channel does not start the queues while the
		// ordinary channel is still coming back.
		expect(canCarry([coming, usableAsset])).to.equal(false);
		expect(canCarry([usable, comingAsset])).to.equal(true);
		// An asset channel alone is no channel to wait for: the payment is
		// tried and fails on its own terms, as with no channel at all.
		expect(canCarry([comingAsset])).to.equal(true);
		expect(canCarry([usableAsset])).to.equal(true);
	});
});
