/**
 * Every asset channel that is not over is in exactly one of the two asset
 * figures of the daemon's balance (issue #2093).
 *
 * `assetChannelClosingSats` holds an asset channel that is shutting down,
 * negotiating its close, or force closed with the wallet's balance output
 * not yet spent in a block. `assetChannelSats` holds every other one that
 * is not over, whatever its state: still opening; open; waiting for its
 * peer; failed and not yet closed. A closed channel is in neither, and so
 * is every ordinary channel, whose balance of a wallet without an asset
 * channel is the keys it always was.
 *
 * A channel is counted once its funding transaction is out. One this node
 * funds: once the node has broadcast the transaction and the network took
 * it. One the peer funds: once the node has seen it confirmed. Until then
 * it is in neither, whatever its state: the coins a funding transaction
 * spends are still in the wallet while the transaction only exists, so an
 * opening given up between funding_created and the broadcast is never
 * counted.
 *
 * The table below is a Record over the engine's state type, so a state
 * the engine gains does not compile until it has a row, and the cases run
 * over the values of that type. Two real nodes then show when each side
 * of an opening begins to count it, and that a channel that has failed is
 * still counted.
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

/** Let queued work run. */
const turns = async (rounds = 40): Promise<void> => {
	for (let i = 0; i < rounds; i++) {
		await new Promise<void>((resolve) => setImmediate(resolve));
	}
};

/** The broadcaster a loopback host's node hands its funding to. */
interface IBroadcaster {
	broadcastTransaction: (txHex: string) => Promise<string>;
}
const broadcasterOf = (host: IAssetHost): IBroadcaster =>
	(host.node as unknown as { fundingProvider: IBroadcaster }).fundingProvider;

const methods = BeignetNode.prototype as unknown as Record<
	string,
	(this: unknown, ...args: unknown[]) => unknown
>;

type Row = Record<string, unknown>;
type Figure = 'assetChannelSats' | 'assetChannelClosingSats' | 'neither';

/**
 * The figure that holds the local balance of an asset channel whose
 * funding transaction is out (broadcast by this node, or seen confirmed),
 * by the state the channel is in.
 */
const FUNDED: Record<ChannelState, Figure> = {
	[ChannelState.NONE]: 'assetChannelSats',
	[ChannelState.SENT_OPEN]: 'assetChannelSats',
	[ChannelState.SENT_ACCEPT]: 'assetChannelSats',
	[ChannelState.SENT_FUNDING_CREATED]: 'assetChannelSats',
	[ChannelState.SENT_FUNDING_SIGNED]: 'assetChannelSats',
	[ChannelState.AWAITING_FUNDING_CONFIRMED]: 'assetChannelSats',
	[ChannelState.AWAITING_CHANNEL_READY]: 'assetChannelSats',
	[ChannelState.CHANNEL_READY]: 'assetChannelSats',
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

/** The rows whose funding transaction the node says is out. */
const OUT = new WeakSet<Row>();

/**
 * A channel row as the node lists one, with 1,500,000 sats on this side.
 * `funded`: its funding transaction exists. `out`: the node broadcast that
 * transaction or saw it confirmed, which a funded row is unless said not.
 */
const row = (
	fill: number,
	state: ChannelState,
	given: { asset: boolean; funded: boolean; out?: boolean; sats?: number }
): Row => {
	const made: Row = {
		channelId: Buffer.alloc(32, fill),
		state,
		localBalanceMsat: BigInt(given.sats ?? 1_500_000) * 1000n,
		...(given.asset ? { auxiliary: true } : {}),
		...(given.funded ? { fundingTxid: TXID, fundingOutputIndex: 0 } : {})
	};
	if (given.out ?? given.funded) OUT.add(made);
	return made;
};

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
				isFundingBroadcastOrConfirmed: (channelId: Buffer): boolean =>
					rows.some(
						(one) => OUT.has(one) && (one.channelId as Buffer).equals(channelId)
					),
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

	it('holds an asset channel whose funding transaction exists and is not out in neither, in every state', () => {
		const notOut = (state: ChannelState): Row =>
			row(7, state, { asset: true, funded: true, out: false });
		for (const state of STATES) {
			expect(balanceOver([notOut(state)]), state).to.deep.equal(NOTHING);
			// Beside one whose funding is out, only that one is counted.
			expect(
				balanceOver([
					notOut(state),
					row(8, state, { asset: true, funded: true })
				]),
				`${state}, beside one that is out`
			).to.deep.equal(holding(FUNDED[state]));
		}
		// Whatever state its peer's absence found it in.
		const away = [notOut(ChannelState.AWAITING_REESTABLISH)];
		for (const was of STATES) {
			expect(balanceOver(away, { 7: was }), was).to.deep.equal(NOTHING);
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
			}),
			// Funded and not out: given up before the broadcast, waiting
			// for the peer's funding to confirm, failed before either.
			row(11, ChannelState.SENT_FUNDING_CREATED, {
				asset: true,
				funded: true,
				out: false,
				sats: 777_000
			}),
			row(12, ChannelState.AWAITING_FUNDING_CONFIRMED, {
				asset: true,
				funded: true,
				out: false,
				sats: 666_000
			}),
			row(13, ChannelState.ERRORED, {
				asset: true,
				funded: true,
				out: false,
				sats: 555_000
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

	/** What both wallets answer, and the state each holds the channel in. */
	const read = (
		alice: IAssetHost,
		bob: IAssetHost,
		channelId: Buffer
	): { alice: Row; bob: Row; states: ChannelState[] } => ({
		alice: balanceOf(alice),
		bob: balanceOf(bob),
		states: [alice, bob].map(
			(host) =>
				host.node.getChannelManager().getChannel(channelId)!.getFullState()
					.state
		)
	});

	it('counts a real asset channel on the opener from its broadcast and on the acceptor from its confirmation, and after it has failed', async () => {
		const alice = assetHost('asset-states', 1, {}, { sqlite: true });
		const bob = assetHost('asset-states', 2, {}, { sqlite: true });
		hosts.push(alice, bob);
		connectHosts(alice, bob);

		// The network takes alice's funding transaction when the test says.
		let release = (): void => undefined;
		const taken = new Promise<void>((resolve) => {
			release = resolve;
		});
		const broadcaster = broadcasterOf(alice);
		const hand = broadcaster.broadcastTransaction.bind(broadcaster);
		let asked = 0;
		broadcaster.broadcastTransaction = async (txHex): Promise<string> => {
			asked++;
			await taken;
			return hand(txHex);
		};

		let signed: ReturnType<typeof read> | undefined;
		let broadcast: ReturnType<typeof read> | undefined;
		const channelId = await openAssetChannel(alice, bob, {
			tag: 'asset-states',
			openerUnits: 9000n,
			acceptorUnits: 1000n,
			beforeConfirmation: async (id) => {
				// Both have signed. The funding transaction exists, the node
				// has handed it to the network and the network has not
				// answered: its coins are still in the wallet.
				signed = read(alice, bob, id);
				expect(asked).to.equal(1);
				expect(alice.broadcasts).to.deep.equal([]);
				release();
				await turns();
				// Taken by the network, and confirmed for neither.
				broadcast = read(alice, bob, id);
				expect(alice.broadcasts).to.have.length(1);
			}
		});
		for (const seen of [signed!, broadcast!]) {
			expect(seen.states).to.deep.equal([
				ChannelState.AWAITING_FUNDING_CONFIRMED,
				ChannelState.AWAITING_FUNDING_CONFIRMED
			]);
		}
		// Before the broadcast neither counts it.
		expect(signed!.alice).to.deep.equal(NOTHING);
		expect(signed!.bob).to.deep.equal(NOTHING);
		// From the broadcast the opener does, and the acceptor does not: the
		// funding is the peer's, and nothing of it is confirmed.
		expect(broadcast!.alice).to.deep.equal({
			...NOTHING,
			assetChannelSats: 1_500_000
		});
		expect(broadcast!.bob).to.deep.equal(NOTHING);
		expect(alice.node.isFundingBroadcastOrConfirmed(channelId)).to.equal(true);

		// Confirmed and open: both count it.
		expect(balanceOf(alice)).to.deep.equal({
			...NOTHING,
			assetChannelSats: 1_500_000
		});
		expect(balanceOf(bob)).to.deep.equal({
			...NOTHING,
			assetChannelSats: 500_000
		});
		// Failed and not yet closed: the same figure holds it.
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

	it('never counts a real asset channel whose funding the network did not take, whatever becomes of it, until the funding is seen confirmed', async () => {
		const alice = assetHost('asset-states-refused', 1, {}, { sqlite: true });
		const bob = assetHost('asset-states-refused', 2, {}, { sqlite: true });
		hosts.push(alice, bob);
		connectHosts(alice, bob);
		let asked = 0;
		broadcasterOf(alice).broadcastTransaction = async (): Promise<string> => {
			asked++;
			throw new Error('the network is away');
		};

		// The open stops with both signatures and nothing confirmed.
		const channelId = await openAssetChannel(alice, bob, {
			tag: 'asset-states-refused',
			openerUnits: 9000n,
			acceptorUnits: 1000n,
			beforeConfirmation: () => false
		});
		await turns();
		expect(asked).to.be.greaterThan(0);
		expect(
			alice.errors.filter((error) =>
				error.startsWith('FUNDING_BROADCAST_FAILED')
			)
		).to.have.length(asked);
		const waiting = read(alice, bob, channelId);
		expect(waiting.states).to.deep.equal([
			ChannelState.AWAITING_FUNDING_CONFIRMED,
			ChannelState.AWAITING_FUNDING_CONFIRMED
		]);
		// The transaction exists and has gone nowhere: the row has its
		// funding, and neither wallet counts the channel.
		expect(alice.node.getChannel(channelId)!.fundingTxid).to.be.a('string');
		expect(alice.node.isFundingBroadcastOrConfirmed(channelId)).to.equal(false);
		expect(waiting.alice).to.deep.equal(NOTHING);
		expect(waiting.bob).to.deep.equal(NOTHING);

		// Given up there: failed, and still not counted.
		const channel = alice.node.getChannelManager().getChannel(channelId)!;
		writableState(channel).state = ChannelState.ERRORED;
		expect(balanceOf(alice)).to.deep.equal(NOTHING);
		writableState(channel).state = ChannelState.AWAITING_FUNDING_CONFIRMED;

		// The funding reached the chain some other way and the node's
		// watcher sees it confirmed: from then on it is counted.
		alice.node.handleFundingConfirmed(channelId);
		bob.node.handleFundingConfirmed(channelId);
		await turns();
		expect(alice.node.isFundingBroadcastOrConfirmed(channelId)).to.equal(true);
		expect(balanceOf(alice)).to.deep.equal({
			...NOTHING,
			assetChannelSats: 1_500_000
		});
		expect(balanceOf(bob)).to.deep.equal({
			...NOTHING,
			assetChannelSats: 500_000
		});
	});
});
