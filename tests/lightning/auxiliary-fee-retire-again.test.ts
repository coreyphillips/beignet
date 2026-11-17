/**
 * Asset channels (issue #2093): the retirement of a fee action that failed.
 *
 * A fee action is retired when the output it paid for is settled for good.
 * When the wallet refuses that once, the action is retired on a later
 * block, and when it refuses until the node stops, the action is retired
 * after the next start, also for a channel whose monitor has nothing else
 * left to do. Its cap does not stay charged and its coins do not stay
 * frozen.
 */

import * as bitcoin from 'bitcoinjs-lib';
import { expect } from 'chai';
import {
	IRREVOCABLE_DEPTH,
	OutputStatus,
	OutputType
} from '../../src/lightning/chain/types';
import type { WalletFundingProvider } from '../../src/lightning/wallet/wallet-funding-provider';
import { withAssetOpens, type IAssetHost } from './helpers/auxiliary-nodes';
import {
	assetChainWorld,
	errorsOf,
	payUnits,
	settle,
	trackedOutputs,
	type IAssetChainPair
} from './helpers/auxiliary-on-chain';

describe('asset channels: the retirement of a fee action that failed', function () {
	this.timeout(240_000);
	withAssetOpens();
	const world = assetChainWorld();
	afterEach(() => world.dispose());
	const valueIncomingHtlc = (context: { auxiliaryAmount?: bigint }): bigint =>
		(context.auxiliaryAmount ?? 0n) * 1000n;
	const poolOf = (host: IAssetHost): WalletFundingProvider =>
		(host.node as unknown as { fundingProvider: WalletFundingProvider })
			.fundingProvider;
	const done = [
		OutputStatus.SPEND_CONFIRMED,
		OutputStatus.IRREVOCABLY_RESOLVED
	];

	/**
	 * Alice punishes a revoked commitment of Bob with a penalty that a fee
	 * coin pays for, while her wallet refuses to retire a fee action as
	 * often as `refusals` says.
	 */
	const punished = async (
		tag: string,
		refusals: number
	): Promise<{ pair: IAssetChainPair; asked: () => number }> => {
		const pair = await world.open(tag, {
			pushMsat: 354_000n,
			feeWallet: { alice: true },
			hooks: { bob: { valueIncomingHtlc } }
		});
		const { alice, channelId } = pair;
		pair.wallets.alice!.fund(100_000);
		pair.wallets.alice!.fund(100_000);
		await world.mine(pair, 1);
		const channel = pair.bob.node.getChannelManager().getChannel(channelId)!;
		const plan = channel.prepareForceClose(channel.getSigner()!);
		if (!plan.ok) throw new Error(plan.error);
		const revoked = bitcoin.Transaction.fromBuffer(plan.commitmentTx);
		await payUnits(pair, 100n);
		await payUnits(pair, 100n);
		await pair.backends.bob.broadcastTransaction(revoked.toHex());
		await settle();
		const pool = poolOf(alice);
		const retire = pool.retireFixedOutputFeeAction.bind(pool);
		let asked = 0;
		(
			pool as unknown as {
				retireFixedOutputFeeAction: typeof pool.retireFixedOutputFeeAction;
			}
		).retireFixedOutputFeeAction = (...args) => {
			if (asked++ < refusals) {
				return Promise.reject(new Error('the wallet is busy'));
			}
			return retire(...args);
		};
		for (let i = 0; i < 4; i++) await world.mine(pair, 1);
		const theirs = trackedOutputs(alice, channelId).find(
			(output) => output.outputType === OutputType.TO_LOCAL
		)!;
		expect(done.includes(theirs.status)).to.equal(true);
		expect(pool.getFixedOutputFeeActionIds(channelId).length).to.equal(1);
		pair.chain.advance(IRREVOCABLE_DEPTH);
		for (let i = 0; i < 20; i++) await settle();
		return { pair, asked: () => asked };
	};

	it('retires on a later block a fee action whose retirement the wallet refused once, and says the refusal once', async () => {
		const { pair, asked } = await punished('fee-retire-again', 1);
		const { alice, channelId } = pair;
		for (let i = 0; i < 6; i++) await world.mine(pair, 1);
		for (let i = 0; i < 20; i++) await settle();
		expect(asked()).to.equal(2);
		expect(poolOf(alice).getFixedOutputFeeActionIds(channelId)).to.deep.equal(
			[]
		);
		expect(poolOf(alice).getFixedOutputFeeBudget()!.reservedSatoshis).to.equal(
			0n
		);
		expect(
			errorsOf(alice).filter((e) => e.includes('could not be retired'))
		).to.have.length(1);
	});

	it('retires after a restart a fee action whose retirement the wallet refused until the node stopped, for a channel that is fully resolved', async () => {
		const tag = 'fee-retire-start';
		const { pair, asked } = await punished(tag, Infinity);
		const { channelId } = pair;
		for (let i = 0; i < 6; i++) await world.mine(pair, 1);
		for (let i = 0; i < 20; i++) await settle();
		expect(asked()).to.be.at.least(2);
		expect(
			poolOf(pair.alice).getFixedOutputFeeActionIds(channelId)
		).to.have.length(1);
		// Said once, however often it was tried.
		expect(
			errorsOf(pair.alice).filter((e) => e.includes('could not be retired'))
		).to.have.length(1);
		expect(
			pair.alice.node.getChannelMonitorState(channelId)?.monitorState
		).to.equal('FULLY_RESOLVED');

		await world.restartAlice(pair, tag);
		for (let i = 0; i < 2; i++) await world.mine(pair, 1);
		for (let i = 0; i < 20; i++) await settle();
		expect(
			poolOf(pair.alice).getFixedOutputFeeActionIds(channelId)
		).to.deep.equal([]);
		expect(
			poolOf(pair.alice).getFixedOutputFeeBudget()!.reservedSatoshis
		).to.equal(0n);
	});
});
