/**
 * The bitcoin of an asset channel that is closing has a figure of its own
 * on the daemon's balance (issue #2093).
 *
 * An asset channel's bitcoin only carries asset outputs. It is not a
 * Lightning balance on its way back to the wallet, so a closing asset
 * channel is left out of `pendingCloseBalanceSats`, and `assetChannelSats`
 * counts the channels that are open. `assetChannelClosingSats` is where it
 * is read from the shutdown to the close of a cooperative close, and from a
 * force close until the wallet's balance output has been spent in a block,
 * which for the closer is the whole of its delay.
 *
 * The daemon's read runs here over real nodes that close a real asset
 * channel, cooperatively over a loopback and by force on a chain that
 * judges every spend. A wallet with no such channel answers the keys it
 * always answered.
 */

import { expect } from 'chai';
import { BeignetNode } from '../../src/cli/beignet-node';
import { getOpenApiSpec } from '../../src/cli/openapi';
import {
	CommitmentType,
	OutputStatus,
	OutputType,
	type ITrackedOutput
} from '../../src/lightning/chain/types';
import { ChannelState } from '../../src/lightning/channel/types';
import {
	assetHost,
	connectHosts,
	openAssetChannel,
	withAssetOpens,
	type IAssetHost
} from '../lightning/helpers/auxiliary-nodes';
import {
	SWEEP_DESTINATION,
	assetChainWorld,
	settle,
	trackedOutputs
} from '../lightning/helpers/auxiliary-on-chain';
import { amountRecord } from '../lightning/helpers/auxiliary-pair';

const methods = BeignetNode.prototype as unknown as Record<
	string,
	(this: unknown, ...args: unknown[]) => unknown
>;

type Row = Record<string, unknown>;

/** A daemon over `node`, with a wallet that holds nothing. */
const daemonOver = (node: unknown): unknown =>
	Object.assign(Object.create(BeignetNode.prototype), {
		node,
		wallet: { getBalance: (): number => 0, transactions: {} }
	});

/** What the daemon answers `GET /balance` over a host's node. */
const balanceOf = (host: IAssetHost): Row =>
	methods.getBalance.call(daemonOver(host.node)) as Row;

/** The figure for ordinary channels on their way back to the wallet. */
const pendingCloseOf = (host: IAssetHost): number =>
	methods.getPendingCloseBalanceSats.call(daemonOver(host.node)) as number;

/** The balance of a wallet with no channel at all: the keys of master. */
const NOTHING = {
	onchain: 0,
	lightning: 0,
	total: 0,
	unsettledSats: 0,
	splicingSats: 0
};

const stateOf = (host: IAssetHost, channelId: Buffer): ChannelState =>
	host.node.getChannelManager().getChannel(channelId)!.getFullState().state;

/** What a wallet would ask to be paid to. The provider names its own script. */
const DESTINATION = Buffer.from('0014' + '11'.repeat(20), 'hex');

describe('The daemon and an asset channel that is closing: its bitcoin (#2093)', function () {
	this.timeout(120_000);
	withAssetOpens();
	const hosts: IAssetHost[] = [];
	const world = assetChainWorld();
	afterEach(() => {
		for (const host of hosts.splice(0)) host.node.destroy();
		world.dispose();
	});

	it('counts an asset channel from its shutdown to its close, and nowhere once it is closed', async () => {
		const alice = assetHost('asset-closing', 1, {}, { sqlite: true });
		const bob = assetHost(
			'asset-closing',
			2,
			{
				valueIncomingHtlc: (context) =>
					context.auxiliaryAmount === undefined
						? undefined
						: context.auxiliaryAmount * 1000n
			},
			{ sqlite: true }
		);
		hosts.push(alice, bob);
		connectHosts(alice, bob);
		const channelId = await openAssetChannel(alice, bob, {
			tag: 'asset-closing',
			openerUnits: 9000n,
			acceptorUnits: 1000n
		});
		// Open: the figure of open asset channels, and no other.
		expect(balanceOf(alice)).to.deep.equal({
			...NOTHING,
			assetChannelSats: 1_500_000
		});
		expect(balanceOf(bob)).to.deep.equal({
			...NOTHING,
			assetChannelSats: 500_000
		});

		// An HTLC in flight keeps the close from being signed: 354 sats of
		// Alice's side carry it.
		const invoice = bob.node.createInvoice({
			amountMsat: 5_000_000n,
			description: 'held',
			hold: true
		});
		alice.node.sendPaymentToRoute(
			{
				hops: [
					{
						pubkey: Buffer.from(bob.node.getNodeId(), 'hex'),
						shortChannelId: Buffer.alloc(8, 9),
						amountToForwardMsat: 5_000_000n,
						outgoingCltvValue: 40
					}
				]
			},
			invoice.paymentHash,
			40,
			invoice.paymentSecret,
			undefined,
			undefined,
			undefined,
			undefined,
			{
				assetPayment: {
					channelId,
					wireAmountMsat: 354_000n,
					customRecords: amountRecord(5000n)
				}
			}
		);
		await settle();
		expect(alice.node.closeChannel(channelId, DESTINATION)).to.deep.equal({
			ok: true
		});
		await settle();

		// Shutting down on both sides: each side's sats are in the closing
		// figure, and in no other.
		for (const host of [alice, bob]) {
			expect(stateOf(host, channelId)).to.equal(ChannelState.SHUTTING_DOWN);
			expect(pendingCloseOf(host)).to.equal(0);
		}
		expect(balanceOf(alice)).to.deep.equal({
			...NOTHING,
			assetChannelClosingSats: 1_500_000 - 354
		});
		expect(balanceOf(bob)).to.deep.equal({
			...NOTHING,
			assetChannelClosingSats: 500_000
		});

		// The HTLC settles and the close is signed: the bitcoin is under the
		// outputs the provider closed to, and the wallet answers the keys of
		// a wallet that never had an asset channel.
		expect(bob.node.settleHeldHtlc(invoice.paymentHash)).to.equal(true);
		await settle();
		for (const host of [alice, bob]) {
			expect(stateOf(host, channelId)).to.equal(ChannelState.CLOSED);
			expect(balanceOf(host)).to.deep.equal(NOTHING);
			expect(pendingCloseOf(host)).to.equal(0);
			expect(host.errors).to.deep.equal([]);
		}
	});

	it('counts a force closed asset channel until its balance output is spent in a block: the peer for a few blocks, the closer for its delay', async () => {
		const pair = await world.open('asset-closing-force');
		const { alice, bob, channelId } = pair;
		const balanceOutput = (host: IAssetHost): ITrackedOutput => {
			const type = host === alice ? OutputType.TO_LOCAL : OutputType.TO_REMOTE;
			const found = trackedOutputs(host, channelId).filter(
				(output) => output.outputType === type
			);
			expect(found, type).to.have.length(1);
			return found[0];
		};
		expect(balanceOf(alice)).to.deep.equal({
			...NOTHING,
			assetChannelSats: 1_500_000
		});

		// Alice publishes her commitment. Before it is in a block she is
		// force closed and Bob knows nothing of it.
		const closed = alice.node.forceCloseChannel(channelId, SWEEP_DESTINATION);
		expect(closed.error).to.equal(undefined);
		await settle();
		expect(stateOf(alice, channelId)).to.equal(ChannelState.FORCE_CLOSED);
		expect(balanceOf(alice)).to.deep.equal({
			...NOTHING,
			assetChannelClosingSats: 1_500_000
		});
		expect(stateOf(bob, channelId)).to.equal(ChannelState.NORMAL);
		expect(balanceOf(bob)).to.deep.equal({
			...NOTHING,
			assetChannelSats: 500_000
		});

		// In a block: both are force closed and neither output is spent.
		await world.mine(pair, 1);
		expect(
			alice.node.getChannelMonitorState(channelId)!.commitmentBroadcast
		).to.include({ commitmentType: CommitmentType.OUR_COMMITMENT });
		expect(
			bob.node.getChannelMonitorState(channelId)!.commitmentBroadcast
		).to.include({ commitmentType: CommitmentType.THEIR_CURRENT_COMMITMENT });
		expect(stateOf(bob, channelId)).to.equal(ChannelState.FORCE_CLOSED);
		expect(balanceOutput(bob).status).to.equal(OutputStatus.CONFIRMED);
		expect(balanceOf(bob)).to.deep.equal({
			...NOTHING,
			assetChannelClosingSats: 500_000
		});

		// Bob's output waits one block. Once its sweep is in a block his
		// sats are under the output the provider swept to: the channel is
		// still FORCE_CLOSED, and it is counted no longer.
		await world.mine(pair, 3);
		expect(balanceOutput(bob).status).to.equal(OutputStatus.SPEND_CONFIRMED);
		expect(stateOf(bob, channelId)).to.equal(ChannelState.FORCE_CLOSED);
		expect(balanceOf(bob)).to.deep.equal(NOTHING);

		// Alice's waits her delay, and is counted for all of it.
		const delay = alice.node
			.getChannelManager()
			.getChannel(channelId)!
			.getFullState().remoteConfig.toSelfDelay;
		expect(delay).to.be.greaterThan(100);
		await world.mine(pair, delay - 6);
		expect(balanceOutput(alice).status).to.equal(OutputStatus.CONFIRMED);
		expect(balanceOf(alice)).to.deep.equal({
			...NOTHING,
			assetChannelClosingSats: 1_500_000
		});
		await world.mine(pair, 8);
		expect(balanceOutput(alice).status).to.equal(OutputStatus.SPEND_CONFIRMED);
		expect(stateOf(alice, channelId)).to.equal(ChannelState.FORCE_CLOSED);
		expect(balanceOf(alice)).to.deep.equal(NOTHING);

		// Nothing of it was ever a balance on its way back to the wallet.
		expect(pendingCloseOf(alice)).to.equal(0);
		expect(pendingCloseOf(bob)).to.equal(0);
	});

	describe('over the rows of a node', () => {
		interface IFakeMonitor {
			commitmentType: CommitmentType;
			outputs: Array<{
				outputType: OutputType;
				status: OutputStatus;
				isSecondLevelHtlc?: boolean;
			}>;
		}
		const TXID = 'c0'.repeat(32);
		const id = (fill: number): Buffer => Buffer.alloc(32, fill);

		/** A daemon whose node lists `rows`. */
		const over = (
			rows: Row[],
			monitors: Record<number, IFakeMonitor> = {},
			wrapped: Record<number, ChannelState> = {}
		): unknown =>
			daemonOver({
				listChannels: (): Row[] => rows,
				// The funding of each of them is confirmed.
				isFundingBroadcastOrConfirmed: (): boolean => true,
				getChannelManager: (): unknown => ({
					getChannel: (channelId: Buffer): unknown =>
						wrapped[channelId[0]]
							? {
									getFullState: (): Row => ({
										preReestablishState: wrapped[channelId[0]]
									})
							  }
							: undefined,
					getMonitor: (channelId: Buffer): unknown => {
						const monitor = monitors[channelId[0]];
						return monitor
							? {
									getFullState: (): Row => ({
										commitmentBroadcast: {
											commitmentType: monitor.commitmentType,
											txid: TXID
										}
									}),
									getTrackedOutputs: (): Row[] =>
										monitor.outputs.map((output) => ({ txid: TXID, ...output }))
							  }
							: undefined;
					}
				})
			});
		const closing = (...given: Parameters<typeof over>): number | undefined =>
			methods.sumAssetChannelFigure.call(
				over(...given),
				'assetChannelClosingSats'
			) as number | undefined;
		const pending = (...given: Parameters<typeof over>): number =>
			methods.getPendingCloseBalanceSats.call(over(...given)) as number;
		const asset = (fill: number, state: ChannelState, msat: bigint): Row => ({
			channelId: id(fill),
			state,
			localBalanceMsat: msat,
			auxiliary: true,
			fundingTxid: 'f0'.repeat(32)
		});
		const ordinary = (
			fill: number,
			state: ChannelState,
			msat: bigint
		): Row => ({
			channelId: id(fill),
			state,
			localBalanceMsat: msat
		});

		it('is absent for a wallet with no closing asset channel, whatever else it holds', () => {
			expect(closing([])).to.equal(undefined);
			// Ordinary channels that close are the wallet's own figure.
			const closingOrdinary = [
				ordinary(1, ChannelState.SHUTTING_DOWN, 700_000_000n),
				ordinary(2, ChannelState.NEGOTIATING_CLOSING, 200_000_000n),
				ordinary(3, ChannelState.FORCE_CLOSED, 100_000_000n)
			];
			expect(closing(closingOrdinary)).to.equal(undefined);
			expect(pending(closingOrdinary)).to.equal(1_000_000);
			// An asset channel in any state but the three is not closing.
			for (const state of Object.values(ChannelState)) {
				if (
					state === ChannelState.SHUTTING_DOWN ||
					state === ChannelState.NEGOTIATING_CLOSING ||
					state === ChannelState.FORCE_CLOSED
				) {
					continue;
				}
				expect(closing([asset(7, state, 1_500_000_000n)]), state).to.equal(
					undefined
				);
			}
		});

		it('counts each closing asset channel whole, and only those', () => {
			for (const state of [
				ChannelState.SHUTTING_DOWN,
				ChannelState.NEGOTIATING_CLOSING,
				ChannelState.FORCE_CLOSED
			]) {
				const rows = [
					ordinary(1, ChannelState.SHUTTING_DOWN, 700_000_000n),
					ordinary(2, ChannelState.NORMAL, 9_000_000_000n),
					asset(7, state, 1_500_000_999n),
					asset(8, ChannelState.NORMAL, 4_000_000_000n)
				];
				expect(closing(rows), state).to.equal(1_500_000);
				// The ordinary figure is what it is without the asset channels.
				expect(pending(rows), state).to.equal(700_000);
			}
			// Several are summed before the sats are taken.
			expect(
				closing([
					asset(7, ChannelState.SHUTTING_DOWN, 1_000_600n),
					asset(8, ChannelState.FORCE_CLOSED, 2_000_600n)
				])
			).to.equal(3_001);
			// One with nothing on this side is still a closing asset channel.
			expect(closing([asset(7, ChannelState.SHUTTING_DOWN, 0n)])).to.equal(0);
		});

		it('reads a channel whose peer is away by the state it was in', () => {
			const away = [asset(7, ChannelState.AWAITING_REESTABLISH, 800_000_000n)];
			expect(closing(away, {}, { 7: ChannelState.SHUTTING_DOWN })).to.equal(
				800_000
			);
			expect(
				closing(away, {}, { 7: ChannelState.NEGOTIATING_CLOSING })
			).to.equal(800_000);
			expect(closing(away, {}, { 7: ChannelState.NORMAL })).to.equal(undefined);
			expect(closing(away)).to.equal(undefined);
		});

		it('counts a force closed one until its own balance output is spent in a block', () => {
			const rows = [asset(7, ChannelState.FORCE_CLOSED, 600_000_000n)];
			const cases: Array<[CommitmentType, OutputType, OutputType]> = [
				[
					CommitmentType.OUR_COMMITMENT,
					OutputType.TO_LOCAL,
					OutputType.TO_REMOTE
				],
				[
					CommitmentType.THEIR_CURRENT_COMMITMENT,
					OutputType.TO_REMOTE,
					OutputType.TO_LOCAL
				],
				[
					CommitmentType.THEIR_REVOKED_COMMITMENT,
					OutputType.TO_REMOTE,
					OutputType.TO_LOCAL
				]
			];
			for (const [commitmentType, mine, theirs] of cases) {
				const withMine = (status: OutputStatus): number | undefined =>
					closing(rows, {
						7: {
							commitmentType,
							outputs: [
								// The peer's output and an HTLC's second level are
								// not this wallet's balance, spent or not.
								{ outputType: theirs, status: OutputStatus.SPEND_CONFIRMED },
								{
									outputType: mine,
									status: OutputStatus.SPEND_CONFIRMED,
									isSecondLevelHtlc: true
								},
								{ outputType: mine, status }
							]
						}
					});
				for (const status of [
					OutputStatus.UNCONFIRMED,
					OutputStatus.CONFIRMED,
					OutputStatus.SPEND_BROADCAST
				]) {
					expect(withMine(status), `${commitmentType} ${status}`).to.equal(
						600_000
					);
				}
				for (const status of [
					OutputStatus.SPEND_CONFIRMED,
					OutputStatus.IRREVOCABLY_RESOLVED
				]) {
					expect(withMine(status), `${commitmentType} ${status}`).to.equal(
						undefined
					);
				}
				// No balance output on the commitment: counted until it is closed.
				expect(
					closing(rows, {
						7: {
							commitmentType,
							outputs: [
								{ outputType: theirs, status: OutputStatus.SPEND_CONFIRMED }
							]
						}
					}),
					commitmentType
				).to.equal(600_000);
			}
			// No monitor, as before the commitment is classified.
			expect(closing(rows)).to.equal(600_000);
		});
	});

	it('is documented for the API beside the figure of open asset channels', () => {
		const balance = (
			getOpenApiSpec() as unknown as {
				components: { schemas: Record<string, { properties: Row }> };
			}
		).components.schemas.BalanceInfo.properties;
		expect(Object.keys(balance)).to.deep.equal([
			'onchain',
			'lightning',
			'total',
			'unsettledSats',
			'splicingSats',
			'assetChannelSats',
			'assetChannelClosingSats'
		]);
		expect(balance.assetChannelClosingSats).to.include({ type: 'integer' });
	});
});
