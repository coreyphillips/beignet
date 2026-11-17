/**
 * Asset channels (issue #2093): how many HTLCs an asset channel carries at
 * once.
 *
 * What a node can do on the chain in time is bounded by the coins of its
 * fee pool, while a commitment could carry far more HTLC outputs than
 * that. A node with asset channels is an endpoint that makes and receives
 * single payments, so the bound is put at the source: the node announces a
 * small max_accepted_htlcs for itself on every asset channel, and offers
 * no more than the same number at once whatever its peer would accept.
 */
import { expect } from 'chai';
import type { IAuxiliaryChannelConfig } from '../../src/lightning/channel/auxiliary-funding';
import type { IChannelState } from '../../src/lightning/channel/channel-state';
import { ChannelState } from '../../src/lightning/channel/types';
import { AuxiliaryPaymentError } from '../../src/lightning/node/types';
import {
	assetHost,
	connectHosts,
	reconnectHosts,
	withAssetOpens,
	type IAssetHost
} from './helpers/auxiliary-nodes';
import {
	assetChainWorld,
	holdUnits,
	payUnits,
	settle,
	sweepingProvider,
	type IAssetChainPair
} from './helpers/auxiliary-on-chain';

describe('asset channels: the HTLCs a channel carries at once', function () {
	this.timeout(240_000);
	withAssetOpens();
	const world = assetChainWorld();
	afterEach(() => world.dispose());

	const valued = {
		valueIncomingHtlc: (context: { auxiliaryAmount?: bigint }) =>
			(context.auxiliaryAmount ?? 0n) * 1000n
	} as Partial<IAuxiliaryChannelConfig>;
	const bounded = (most: number): Partial<IAuxiliaryChannelConfig> =>
		({ ...valued, maxHtlcs: most }) as Partial<IAuxiliaryChannelConfig>;
	const stateOf = (host: IAssetHost, pair: IAssetChainPair): IChannelState =>
		host.node.getChannelManager().getChannel(pair.channelId)!.getFullState();
	const inFlight = (host: IAssetHost, pair: IAssetChainPair): number =>
		stateOf(host, pair).htlcs.size;
	const refusalOf = async (
		pair: IAssetChainPair,
		tag: string
	): Promise<unknown> =>
		holdUnits(pair, 10n, tag).then(
			() => undefined,
			(error: unknown) => error
		);

	it('each node announces 8 as the most HTLCs it accepts, on an open and on an accept', async () => {
		const pair = await world.open('aux-bound-announced', {
			hooks: { bob: valued }
		});
		// What the opener put in open_channel, and what the acceptor read.
		expect(stateOf(pair.alice, pair).localConfig.maxAcceptedHtlcs).to.equal(8);
		expect(stateOf(pair.bob, pair).remoteConfig.maxAcceptedHtlcs).to.equal(8);
		// What the acceptor put in accept_channel, and what the opener read.
		expect(stateOf(pair.bob, pair).localConfig.maxAcceptedHtlcs).to.equal(8);
		expect(stateOf(pair.alice, pair).remoteConfig.maxAcceptedHtlcs).to.equal(8);
		// The channel pays as before.
		await payUnits(pair, 100n);
		expect(inFlight(pair.alice, pair)).to.equal(0);
	});

	it('a host sets another number for its node, and a number that cannot be one is refused when the node is made', async () => {
		const pair = await world.open('aux-bound-host', {
			hooks: { alice: bounded(5), bob: bounded(12) }
		});
		expect(stateOf(pair.alice, pair).localConfig.maxAcceptedHtlcs).to.equal(5);
		expect(stateOf(pair.bob, pair).remoteConfig.maxAcceptedHtlcs).to.equal(5);
		expect(stateOf(pair.bob, pair).localConfig.maxAcceptedHtlcs).to.equal(12);
		expect(stateOf(pair.alice, pair).remoteConfig.maxAcceptedHtlcs).to.equal(
			12
		);
		for (const most of [0, 84, 2.5, Number.NaN]) {
			expect(() =>
				assetHost('aux-bound-bad', 7, {
					provider: sweepingProvider([]),
					...bounded(most)
				})
			).to.throw(/whole number from 1 to 83/);
		}
	});

	it('the ninth HTLC of its own is refused with ASSET_HTLC_LIMIT_REACHED before anything is sent', async () => {
		const pair = await world.open('aux-bound-own', {
			// The peer would accept more than this node offers.
			hooks: { bob: bounded(40) }
		});
		expect(stateOf(pair.alice, pair).remoteConfig.maxAcceptedHtlcs).to.equal(
			40
		);
		for (let i = 0; i < 8; i++) await holdUnits(pair, 10n, `own-${i}`);
		expect(inFlight(pair.alice, pair)).to.equal(8);
		const before = stateOf(pair.alice, pair);
		const sent: unknown[] = [];
		pair.alice.node.on('message:outbound', (...told: unknown[]) => {
			sent.push(told);
		});

		const refusal = await refusalOf(pair, 'own-ninth');
		await settle();
		expect(refusal).to.be.instanceOf(AuxiliaryPaymentError);
		const refused = refusal as AuxiliaryPaymentError;
		expect(refused.code).to.equal('ASSET_HTLC_LIMIT_REACHED');
		expect(refused.channelId).to.equal(pair.channelId.toString('hex'));
		expect(refused.message).to.include('8');
		// Nothing was sent, and neither side holds a ninth.
		expect(sent).to.deep.equal([]);
		const after = stateOf(pair.alice, pair);
		expect(after.htlcs.size).to.equal(8);
		expect(after.localHtlcCounter).to.equal(before.localHtlcCounter);
		expect(after.remoteCommitmentNumber).to.equal(
			before.remoteCommitmentNumber
		);
		expect(inFlight(pair.bob, pair)).to.equal(8);
		expect(stateOf(pair.alice, pair).state).to.equal(ChannelState.NORMAL);
	});

	it('the ninth HTLC of the peer is refused by the check on what this node announced', async () => {
		const pair = await world.open('aux-bound-peer', {
			hooks: { alice: bounded(20), bob: valued }
		});
		expect(stateOf(pair.bob, pair).localConfig.maxAcceptedHtlcs).to.equal(8);
		// A peer that does not keep to what it was told: Alice's channel is
		// made to believe Bob accepts 20.
		(
			pair.alice.node
				.getChannelManager()
				.getChannel(pair.channelId) as unknown as {
				_state: IChannelState;
			}
		)._state.remoteConfig.maxAcceptedHtlcs = 20;
		for (let i = 0; i < 8; i++) await holdUnits(pair, 10n, `peer-${i}`);
		expect(inFlight(pair.bob, pair)).to.equal(8);

		const refusal = await refusalOf(pair, 'peer-ninth');
		expect(refusal).to.be.instanceOf(Error);
		expect(refusal).to.not.be.instanceOf(AuxiliaryPaymentError);
		expect(
			pair.bob.errors.filter((error) =>
				error.includes('Max inbound pending HTLCs exceeded')
			)
		).to.have.length.greaterThan(0);
	});

	it('a channel opened when both nodes announced 83 keeps working, and this node offers no more than 8 at once on it', async () => {
		const tag = 'aux-bound-old-row';
		const pair = await world.open(tag, {
			hooks: { alice: bounded(83), bob: bounded(83) }
		});
		expect(stateOf(pair.alice, pair).localConfig.maxAcceptedHtlcs).to.equal(83);
		expect(stateOf(pair.alice, pair).remoteConfig.maxAcceptedHtlcs).to.equal(
			83
		);
		await payUnits(pair, 100n);

		// The node comes back with no number set by its host: the row keeps
		// what was announced, which cannot be taken back, and the bound of
		// this node is on what it offers.
		await world.restartAlice(pair, tag);
		connectHosts(pair.alice, pair.bob);
		await reconnectHosts(pair.alice, pair.bob);
		await settle();
		await world.mine(pair, 1);
		expect(stateOf(pair.alice, pair).state).to.equal(ChannelState.NORMAL);
		expect(stateOf(pair.alice, pair).localConfig.maxAcceptedHtlcs).to.equal(83);
		await payUnits(pair, 100n);
		for (let i = 0; i < 8; i++) await holdUnits(pair, 10n, `old-${i}`);
		expect(inFlight(pair.alice, pair)).to.equal(8);
		const refusal = await refusalOf(pair, 'old-ninth');
		expect(refusal).to.be.instanceOf(AuxiliaryPaymentError);
		expect((refusal as AuxiliaryPaymentError).code).to.equal(
			'ASSET_HTLC_LIMIT_REACHED'
		);
		expect(inFlight(pair.bob, pair)).to.equal(8);
	});
});
