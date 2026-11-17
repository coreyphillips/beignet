/**
 * Every asset channel that is not over is in exactly one of the two asset
 * figures of the daemon's balance (issue #2093).
 *
 * `assetChannelClosingSats` holds an asset channel that is shutting down,
 * negotiating its close, or force closed with the wallet's balance output
 * not yet spent in a block. `assetChannelSats` holds every other one that
 * is not over, whatever its state: still opening, from the moment its
 * funding transaction exists; open; waiting for its peer; failed and not
 * yet closed. A closed channel and one whose opening never had a funding
 * transaction are in neither, and so is every ordinary channel, whose
 * balance of a wallet without an asset channel is the keys it always was.
 *
 * The table below is a Record over the engine's state type, so a state
 * the engine gains does not compile until it has a row, and the cases run
 * over the values of that type. Two real nodes then show the two states
 * that were in no figure: an asset channel that is still opening, and one
 * that has failed.
 */

import { expect } from 'chai';
import { BeignetNode } from '../../src/cli/beignet-node';
import { ChannelState } from '../../src/lightning/channel/types';
import {
	assetHost,
	connectHosts,
	openAssetChannel,
	withAssetOpens,
	type IAssetHost
} from '../lightning/helpers/auxiliary-nodes';
import { writableState } from '../lightning/helpers/writable-state';

const methods = BeignetNode.prototype as unknown as Record<
	string,
	(this: unknown, ...args: unknown[]) => unknown
>;

type Row = Record<string, unknown>;
type Figure = 'assetChannelSats' | 'assetChannelClosingSats' | 'neither';

/**
 * The figure that holds the local balance of an asset channel whose
 * funding transaction exists, by the state the channel is in.
 */
const FUNDED: Record<ChannelState, Figure> = {
	[ChannelState.NONE]: 'assetChannelSats',
	[ChannelState.SENT_OPEN]: 'assetChannelSats',
	[ChannelState.SENT_ACCEPT]: 'assetChannelSats',
	[ChannelState.SENT_FUNDING_CREATED]: 'assetChannelSats',
	[ChannelState.SENT_FUNDING_SIGNED]: 'assetChannelSats',
	[ChannelState.AWAITING_FUNDING_CONFIRMED]: 'assetChannelSats',
	[ChannelState.AWAITING_CHANNEL_READY]: 'assetChannelSats',
	[ChannelState.NORMAL]: 'assetChannelSats',
	[ChannelState.SHUTTING_DOWN]: 'assetChannelClosingSats',
	[ChannelState.NEGOTIATING_CLOSING]: 'assetChannelClosingSats',
	[ChannelState.AWAITING_REESTABLISH]: 'assetChannelSats',
	[ChannelState.DUAL_FUNDING_V2]: 'assetChannelSats',
	[ChannelState.AWAITING_TX_SIGNATURES]: 'assetChannelSats',
	[ChannelState.SPLICING]: 'assetChannelSats',
	[ChannelState.CLOSED]: 'neither',
	[ChannelState.FORCE_CLOSED]: 'assetChannelClosingSats',
	[ChannelState.ERRORED]: 'assetChannelSats'
};

/** Every state the engine has, read from its type. */
const STATES = Object.values(ChannelState);

/** The balance of a wallet with no asset channel: the keys of master. */
const NOTHING = {
	onchain: 0,
	lightning: 0,
	total: 0,
	unsettledSats: 0,
	splicingSats: 0
};

const TXID = 'f0'.repeat(32);

/** A channel row as the node lists one, with 1,500,000 sats on this side. */
const row = (
	fill: number,
	state: ChannelState,
	given: { asset: boolean; funded: boolean; sats?: number }
): Row => ({
	channelId: Buffer.alloc(32, fill),
	state,
	localBalanceMsat: BigInt(given.sats ?? 1_500_000) * 1000n,
	...(given.asset ? { auxiliary: true } : {}),
	...(given.funded ? { fundingTxid: TXID, fundingOutputIndex: 0 } : {})
});

/**
 * What the daemon answers `GET /balance` over a node that lists `rows`.
 * `was` says, by the first byte of a channel id, the state a channel whose
 * peer is away was in.
 */
const balanceOver = (
	rows: Row[],
	was: Record<number, ChannelState> = {}
): Row =>
	methods.getBalance.call(
		Object.assign(Object.create(BeignetNode.prototype), {
			node: {
				// The engine's own figures: no ordinary channel is open.
				getBalance: (): Row => ({
					localBalanceMsat: 0n,
					remoteBalanceMsat: 0n,
					unsettledBalanceMsat: 0n
				}),
				listChannels: (): Row[] => rows,
				getChannelManager: (): unknown => ({
					getChannel: (channelId: Buffer): unknown =>
						was[channelId[0]]
							? {
									getFullState: (): Row => ({
										preReestablishState: was[channelId[0]]
									})
							  }
							: undefined,
					// No commitment of any of them is on the chain.
					getMonitor: (): undefined => undefined
				})
			},
			wallet: { getBalance: (): number => 0, transactions: {} }
		})
	) as Row;

/** The whole answer when `figure` holds 1,500,000 sats and nothing else is held. */
const holding = (figure: Figure): Row =>
	figure === 'neither' ? NOTHING : { ...NOTHING, [figure]: 1_500_000 };

/** What the daemon answers `GET /balance` over a host's own node. */
const balanceOf = (host: IAssetHost): Row =>
	methods.getBalance.call(
		Object.assign(Object.create(BeignetNode.prototype), {
			node: host.node,
			wallet: { getBalance: (): number => 0, transactions: {} }
		})
	) as Row;

describe('The daemon and an asset channel in each state: the two asset figures (#2093)', function () {
	this.timeout(60_000);
	withAssetOpens();
	const hosts: IAssetHost[] = [];
	afterEach(() => {
		for (const host of hosts.splice(0)) host.node.destroy();
	});

	it('has a row in its table for every state the engine has', () => {
		expect(STATES.length).to.be.greaterThan(10);
		expect(Object.keys(FUNDED).sort()).to.deep.equal([...STATES].sort());
		// The three that are closing, the one that is over, and the rest.
		expect(
			STATES.filter((s) => FUNDED[s] === 'assetChannelClosingSats')
		).to.have.members([
			ChannelState.SHUTTING_DOWN,
			ChannelState.NEGOTIATING_CLOSING,
			ChannelState.FORCE_CLOSED
		]);
		expect(STATES.filter((s) => FUNDED[s] === 'neither')).to.deep.equal([
			ChannelState.CLOSED
		]);
	});

	for (const state of STATES) {
		it(`${state}: an asset channel is in ${FUNDED[state]}, and an ordinary channel in neither`, () => {
			// The whole answer is compared: the figure named holds the
			// channel's local balance and the other is absent.
			expect(
				balanceOver([row(7, state, { asset: true, funded: true })])
			).to.deep.equal(holding(FUNDED[state]));
			// An ordinary channel in the same state, with its funding or
			// without: the keys of a wallet that never had an asset channel.
			for (const funded of [true, false]) {
				expect(
					balanceOver([row(1, state, { asset: false, funded })]),
					`ordinary, funded ${funded}`
				).to.deep.equal(NOTHING);
			}
			// Beside each other, only the asset channel is counted.
			expect(
				balanceOver([
					row(1, state, { asset: false, funded: true }),
					row(7, state, { asset: true, funded: true })
				])
			).to.deep.equal(holding(FUNDED[state]));
		});
	}

	it('holds an asset channel that never had a funding transaction in neither, in every state', () => {
		for (const state of STATES) {
			expect(
				balanceOver([row(7, state, { asset: true, funded: false })]),
				state
			).to.deep.equal(NOTHING);
		}
	});

	it('reads an asset channel whose peer is away by the state it was in, for every state', () => {
		const away = [
			row(7, ChannelState.AWAITING_REESTABLISH, { asset: true, funded: true })
		];
		for (const was of STATES) {
			expect(balanceOver(away, { 7: was }), was).to.deep.equal(
				holding(FUNDED[was])
			);
		}
		// With no record of what it was, it is a channel waiting for its peer.
		expect(balanceOver(away)).to.deep.equal(holding('assetChannelSats'));
	});

	it('sums a wallet of many channels, each asset channel into its one figure', () => {
		const asset = (fill: number, state: ChannelState, sats: number): Row =>
			row(fill, state, { asset: true, funded: true, sats });
		const rows = [
			asset(1, ChannelState.AWAITING_FUNDING_CONFIRMED, 100_000),
			asset(2, ChannelState.NORMAL, 200_000),
			asset(3, ChannelState.ERRORED, 300_000),
			asset(4, ChannelState.AWAITING_REESTABLISH, 400_000),
			asset(5, ChannelState.SHUTTING_DOWN, 50_000),
			asset(6, ChannelState.FORCE_CLOSED, 60_000),
			asset(7, ChannelState.CLOSED, 999_000),
			row(8, ChannelState.SENT_OPEN, {
				asset: true,
				funded: false,
				sats: 888_000
			}),
			row(9, ChannelState.NORMAL, {
				asset: false,
				funded: true,
				sats: 7_000_000
			}),
			row(10, ChannelState.SHUTTING_DOWN, {
				asset: false,
				funded: true,
				sats: 5_000_000
			})
		];
		expect(balanceOver(rows)).to.deep.equal({
			...NOTHING,
			assetChannelSats: 1_000_000,
			assetChannelClosingSats: 110_000
		});
		// Each asset channel that is not over was counted once.
		const perChannel = rows.map((one) => balanceOver([one]));
		const total = (key: string): number =>
			perChannel.reduce(
				(sum, answer) => sum + ((answer[key] as number) ?? 0),
				0
			);
		expect(total('assetChannelSats')).to.equal(1_000_000);
		expect(total('assetChannelClosingSats')).to.equal(110_000);
		for (const answer of perChannel) {
			expect(
				'assetChannelSats' in answer && 'assetChannelClosingSats' in answer
			).to.equal(false);
		}
	});

	it('counts a real asset channel while it is still opening, and after it has failed', async () => {
		const alice = assetHost('asset-states', 1, {}, { sqlite: true });
		const bob = assetHost('asset-states', 2, {}, { sqlite: true });
		hosts.push(alice, bob);
		connectHosts(alice, bob);

		// What each wallet answers at the moment its node says the channel
		// is opening: the funding transaction exists and nothing confirmed.
		const opening: Array<{ who: string; state: ChannelState; balance: Row }> =
			[];
		for (const [who, host] of [
			['alice', alice],
			['bob', bob]
		] as const) {
			host.node.on('channel:opening', ({ channelId }) => {
				opening.push({
					who,
					state: host.node
						.getChannelManager()
						.getChannel(channelId)!
						.getFullState().state,
					balance: balanceOf(host)
				});
			});
		}
		const channelId = await openAssetChannel(alice, bob, {
			tag: 'asset-states',
			openerUnits: 9000n,
			acceptorUnits: 1000n
		});
		expect(opening.map((seen) => seen.who).sort()).to.deep.equal([
			'alice',
			'bob'
		]);
		for (const seen of opening) {
			expect(seen.state, seen.who).to.be.oneOf([
				ChannelState.SENT_FUNDING_CREATED,
				ChannelState.AWAITING_FUNDING_CONFIRMED,
				ChannelState.AWAITING_CHANNEL_READY
			]);
			expect(seen.balance, seen.who).to.deep.equal({
				...NOTHING,
				assetChannelSats: seen.who === 'alice' ? 1_500_000 : 500_000
			});
		}

		// Open, then failed and not yet closed: the same figure holds it.
		expect(balanceOf(alice)).to.deep.equal({
			...NOTHING,
			assetChannelSats: 1_500_000
		});
		const channel = alice.node.getChannelManager().getChannel(channelId)!;
		writableState(channel).state = ChannelState.ERRORED;
		expect(alice.node.getChannel(channelId)!.state).to.equal(
			ChannelState.ERRORED
		);
		expect(balanceOf(alice)).to.deep.equal({
			...NOTHING,
			assetChannelSats: 1_500_000
		});
	});
});
