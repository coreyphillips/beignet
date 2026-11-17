/**
 * Issue #2093: asset channels as the build ships them.
 *
 * No test here turns the switch on: openings are enabled in the build and
 * the API says version 1. Two nodes are made through the public
 * configuration with a provider, a funding provider that keeps a fee pool
 * and the default feature set, and neither has a hook that allows the older
 * HTLC signatures. Each reads the features the other really advertises.
 */
import { expect } from 'chai';
import { OutputStatus, OutputType } from '../../src/lightning/chain/types';
import { AUXILIARY_CHANNELS_API } from '../../src/lightning/channel/auxiliary-api';
import { auxiliaryChannelOpens } from '../../src/lightning/channel/auxiliary-switch';
import { isFixedAssetHtlcChannel } from '../../src/lightning/channel/types';
import {
	SWEEP_DESTINATION,
	assetChainWorld,
	errorsOf,
	holdUnits,
	payUnits,
	settle,
	trackedOutputs
} from './helpers/auxiliary-on-chain';

describe('asset channels as the build ships them (issue #2093)', function () {
	this.timeout(120000);
	const world = assetChainWorld();
	afterEach(() => world.dispose());

	const valueIncomingHtlc = (context: { auxiliaryAmount?: bigint }): bigint =>
		(context.auxiliaryAmount ?? 0n) * 1000n;

	it('says so itself: openings are enabled and the API is at version 1', () => {
		expect(auxiliaryChannelOpens.enabled).to.equal(true);
		expect(AUXILIARY_CHANNELS_API.version).to.equal(1);
	});

	it('two nodes with the default feature set offer fixed HTLC outputs, open an asset channel in fixed mode with no hook for the older signatures, pay both ways, and resolve an HTLC in flight at a force close through the fee pool', async () => {
		const pair = await world.open('aux-switched-on', {
			feeWallet: { alice: true, bob: true },
			realInit: true,
			hooks: {
				alice: { allowLegacyHtlcSignatures: undefined, valueIncomingHtlc },
				bob: { allowLegacyHtlcSignatures: undefined, valueIncomingHtlc }
			}
		});
		const { alice, bob, channelId } = pair;
		for (const host of [alice, bob]) {
			const bits = host.node.getLocalFeatures().listSetBits();
			expect(bits).to.include(451);
			expect(bits).to.include(2025);
			for (const bit of [450, 452, 453]) expect(bits).to.not.include(bit);
			expect(
				isFixedAssetHtlcChannel(
					host.node.getChannelManager().getChannel(channelId)!.getFullState()
						.channelType
				)
			).to.equal(true);
		}
		expect(alice.node.getAuxiliaryHtlcMode(bob.node.getNodeId())).to.equal(
			'fixed'
		);
		expect(bob.node.getAuxiliaryHtlcMode(alice.node.getNodeId())).to.equal(
			'fixed'
		);

		// Units go both ways.
		const unitsOf = (): bigint =>
			alice.node.getChannelManager().getChannel(channelId)!.getFullState()
				.auxiliaryState!.localBalance;
		const before = unitsOf();
		await payUnits(pair, 100n);
		expect(unitsOf()).to.equal(before - 100n);
		await payUnits({ ...pair, alice: bob, bob: alice }, 40n);
		expect(unitsOf()).to.equal(before - 60n);

		// An HTLC in flight at a force close: the second-level transaction
		// keeps every output the peer signed for and a wallet input of the
		// fee pool brings its fee.
		pair.wallets.alice!.fund(100_000);
		pair.wallets.alice!.fund(100_000);
		await world.mine(pair, 1);
		const held = await holdUnits(pair, 5000n, 'switched-on');
		const closed = alice.node.forceCloseChannel(channelId, SWEEP_DESTINATION);
		expect(closed.ok, closed.error).to.equal(true);
		await settle();
		const htlc = (): ReturnType<typeof trackedOutputs>[number] =>
			trackedOutputs(alice, channelId).find(
				(output) => output.outputType === OutputType.OFFERED_HTLC
			)!;
		await world.mine(pair, 2);
		if (pair.chain.height < held.cltvExpiry - 1) {
			pair.chain.advance(held.cltvExpiry - 1 - pair.chain.height);
			await settle();
		}
		for (
			let i = 0;
			i < 40 && htlc().status !== OutputStatus.SPEND_CONFIRMED;
			i++
		) {
			await world.mine(pair, 1);
		}
		expect(htlc().status, errorsOf(alice).join(' | ')).to.equal(
			OutputStatus.SPEND_CONFIRMED
		);
		const timeout = pair.chain.confirmed.get(htlc().resolutionTxid!)!.tx;
		expect(timeout.ins.length).to.equal(2);
		expect(timeout.outs.map((out) => out.value)).to.deep.equal([354]);
		// The peer signed every output and its own input only (0x81): fixed
		// mode. The older signatures cover one output (0x83).
		const kinds = timeout.ins[0].witness
			.filter((item) => item.length === 65)
			.map((item) => item[64]);
		expect(kinds).to.include(0x81);
		expect(kinds).to.not.include(0x83);
		expect(htlc().auxiliaryData!.toString()).to.match(
			/^sweep:local:\d+:htlc_second_level_timeout:/
		);
		expect(pair.backends.alice.refused).to.deep.equal([]);
	});

	it('a node whose funding provider keeps no fee pool does not offer fixed HTLC outputs, and with a peer that does it opens no asset channel unless both hosts allow the older signatures', async () => {
		let failure = '';
		try {
			await world.open('aux-switched-on-poor', {
				feeWallet: { bob: true },
				realInit: true,
				hooks: {
					alice: { allowLegacyHtlcSignatures: undefined },
					bob: { allowLegacyHtlcSignatures: undefined }
				}
			});
		} catch (error) {
			failure = (error as Error).message;
		}
		expect(failure).to.include(
			'New asset channels require fixed HTLC outputs or explicit peer compatibility'
		);
	});
});
