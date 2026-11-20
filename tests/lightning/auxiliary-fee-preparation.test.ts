/**
 * Asset channels (issue #2098, step 6): a node that forwards asset HTLCs
 * prepares its fee coins ahead of any claim, on each block, and says in its
 * status what it keeps for the spends with a deadline. A host may ask that
 * an asset HTLC ending at the node be taken only while those coins would
 * pay to claim it. A node that does not forward prepares nothing.
 */

import { expect } from 'chai';
import { reserveCoinSatoshis } from '../../src/lightning/channel/fixed-output-reserve';
import { isFixedAssetHtlcChannel } from '../../src/lightning/channel/types';
import {
	FixedOutputFeeError,
	type IFixedOutputFeePolicy,
	type IFixedOutputFeePoolState
} from '../../src/lightning/wallet/fixed-output-fees';
import { withAssetOpens } from './helpers/auxiliary-nodes';
import {
	assetChainWorld,
	holdUnits,
	payUnits,
	settle,
	type IAssetChainPair
} from './helpers/auxiliary-on-chain';

describe('fee coins prepared ahead by a node that forwards (#2098 step 6)', function () {
	this.timeout(240_000);
	withAssetOpens();
	const world = assetChainWorld();
	afterEach(() => world.dispose());
	const valueIncomingHtlc = (context: { auxiliaryAmount?: bigint }): bigint =>
		(context.auxiliaryAmount ?? 0n) * 1000n;
	const prepareForward = (): undefined => undefined;

	const open = async (
		tag: string,
		bob: {
			forwards: boolean;
			requireFeeCoinsToSettle?: boolean;
			policy?: Partial<IFixedOutputFeePolicy>;
		}
	): Promise<IAssetChainPair> => {
		// Of the fixed mode: each node reads the features the other advertises,
		// and neither allows the older HTLC signatures.
		const pair = await world.open(tag, {
			realInit: true,
			feeWallet: { alice: true, bob: bob.policy ?? true },
			hooks: {
				alice: { valueIncomingHtlc, allowLegacyHtlcSignatures: undefined },
				bob: {
					valueIncomingHtlc,
					allowLegacyHtlcSignatures: undefined,
					...(bob.forwards ? { prepareForward } : {}),
					...(bob.requireFeeCoinsToSettle !== undefined
						? { requireFeeCoinsToSettle: bob.requireFeeCoinsToSettle }
						: {})
				}
			}
		});
		expect(
			isFixedAssetHtlcChannel(
				pair.bob.node
					.getChannelManager()
					.getChannel(pair.channelId)!
					.getFullState().channelType
			),
			'the channel is of the fixed mode'
		).to.equal(true);
		for (const wallet of [pair.wallets.alice!, pair.wallets.bob!]) {
			for (let i = 0; i < 3; i++) wallet.fund(200_000);
		}
		return pair;
	};
	const statusOf = (pair: IAssetChainPair): IFixedOutputFeePoolState => {
		const status = pair.bob.node.getFixedOutputFeeStatus();
		if (!status?.available) throw new Error('Bob has no fee coin pool');
		return status;
	};
	const logsOf = (pair: IAssetChainPair): string[] => {
		const logs: string[] = [];
		pair.bob.node.on('log', (log: { category: string; action: string }) => {
			logs.push(`${log.category}:${log.action}`);
		});
		return logs;
	};

	it('a node that forwards prepares, on its blocks, coins of the size it keeps for a spend with a deadline, as many as those spends need and the feeCoinCount of the policy, and says so in its status', async () => {
		const pair = await open('prepare-forwarding', { forwards: true });
		const logs = logsOf(pair);
		await world.mine(pair, 3);
		const status = statusOf(pair);
		const reserve = status.reserve!;
		expect(reserve, 'the status says what is kept').to.not.equal(undefined);
		expect(reserve.coinSatoshis).to.equal(
			reserveCoinSatoshis(reserve.ratePerVbyte)
		);
		expect(reserve.need).to.equal(0);
		expect(status.feeCoins.ready).to.be.at.least(status.policy!.feeCoinCount);
		for (const value of status.feeCoins.readyCoinSatoshis!) {
			expect(value >= reserve.coinSatoshis, `a coin of ${value}`).to.equal(
				true
			);
		}
		expect(reserve.fundable).to.equal(status.feeCoins.ready);
		expect(reserve.shortfall).to.equal(0);
		expect(logs).to.include('fee:fee_coins_prepared');
		// No fee action was opened for it, and no cap is held.
		expect(status.actions).to.deep.equal([]);
	});

	it('a node that does not forward prepares no coin ahead, and its status says nothing kept', async () => {
		const pair = await open('prepare-wallet', { forwards: false });
		await world.mine(pair, 3);
		const status = statusOf(pair);
		expect(status.reserve).to.equal(undefined);
		expect(status.feeCoins.ready).to.equal(0);
		expect(status.splits).to.deep.equal([]);
	});

	it('after fees rise, the coins prepared at the lower rate pay for fewer spends, and coins of the new size are prepared', async () => {
		const pair = await open('prepare-rise', { forwards: true });
		await world.mine(pair, 3);
		const before = statusOf(pair).reserve!;
		expect(before.fundable).to.be.greaterThan(0);
		// The node's estimate triples.
		(
			pair.bob.node as unknown as { feeAdvisor: { getCurrentRate(): number } }
		).feeAdvisor.getCurrentRate = (): number => before.ratePerVbyte * 3;
		const risen = statusOf(pair).reserve!;
		expect(risen.ratePerVbyte).to.equal(before.ratePerVbyte * 3);
		expect(risen.coinSatoshis).to.equal(
			reserveCoinSatoshis(before.ratePerVbyte * 3)
		);
		expect(risen.fundable).to.be.lessThan(before.fundable);
		await world.mine(pair, 3);
		const after = statusOf(pair);
		// At three times the rate a split's own fee, held to the policy's
		// maxPreparationFeeSatoshis, makes fewer coins at once: the coins kept
		// are best prepared while fees are low.
		expect(
			after.feeCoins.readyCoinSatoshis!.filter(
				(value) => value >= risen.coinSatoshis
			).length
		).to.be.at.least(1);
		expect(after.reserve!.fundable).to.be.greaterThan(risen.fundable);
	});

	it('with requireFeeCoinsToSettle, an asset payment that ends at the node is failed back while the coins ready would not pay to claim it, and taken once they would', async () => {
		const pair = await open('settle-required-payment', {
			forwards: true,
			requireFeeCoinsToSettle: true
		});
		const logs: string[] = [];
		pair.bob.node.on('log', (log: { action: string }) => logs.push(log.action));
		// No block yet: Bob has no fee coin ready.
		let refused: string | undefined;
		try {
			await payUnits(pair, 1000n);
		} catch (err) {
			refused = (err as Error).message;
		}
		expect(refused, 'the payment failed').to.include('FAILED');
		expect(logs).to.include('asset_settle_declined');
		await world.mine(pair, 3);
		await payUnits(pair, 1000n);
	});

	it('requireFeeCoinsToSettle on a node that does not forward changes nothing: an asset payment that ends at it is taken as before', async () => {
		const pair = await open('settle-required-wallet', {
			forwards: false,
			requireFeeCoinsToSettle: true
		});
		await world.mine(pair, 3);
		expect(statusOf(pair).reserve).to.equal(undefined);
		await payUnits(pair, 1000n);
	});

	it('a node that forwards prepares no coin over the cap of one fee action, which no spend could use, and prepares coins once the rate puts a kept coin within it', async () => {
		const pair = await open('prepare-over-cap', {
			forwards: true,
			policy: { maxFeeSatoshis: 2_000n }
		});
		await world.mine(pair, 3);
		const before = statusOf(pair);
		// At the fallback rate of 10 sat/vB a kept coin is 3080 sat, over the
		// cap of 2000: nothing is prepared, and a forward would be refused.
		expect(before.reserve!.coinSatoshis > 2_000n).to.equal(true);
		expect(before.feeCoins.ready).to.equal(0);
		expect(before.splits).to.deep.equal([]);
		// The estimate falls by half: a kept coin is 1540 sat.
		(
			pair.bob.node as unknown as { feeAdvisor: { getCurrentRate(): number } }
		).feeAdvisor.getCurrentRate = (): number =>
			before.reserve!.ratePerVbyte / 2;
		await world.mine(pair, 3);
		const after = statusOf(pair);
		for (const value of after.feeCoins.readyCoinSatoshis!) {
			expect(value <= 2_000n, `a coin of ${value}`).to.equal(true);
		}
		expect(after.reserve!.fundable).to.be.greaterThan(0);
		expect(
			(
				pair.bob.node as unknown as {
					assetForwardFeeRefusal(adding: number): string | undefined;
				}
			).assetForwardFeeRefusal(1)
		).to.equal(undefined);
	});

	it('without requireFeeCoinsToSettle, an asset payment that ends at the node is taken as before, coins ready or not', async () => {
		const pair = await open('settle-not-required', { forwards: true });
		await payUnits(pair, 1000n);
	});

	it('with requireFeeCoinsToSettle, a hold invoice of asset parts is refused at its settle with FEE_COINS_SHORT and its parts stay held, until the coins are ready', async () => {
		const pair = await open('settle-required-hold', {
			forwards: true,
			requireFeeCoinsToSettle: true
		});
		const held = await holdUnits(pair, 1000n, 'settle-required-hold');
		let error: unknown;
		try {
			pair.bob.node.settleHeldHtlc(held.paymentHash, held.preimage);
		} catch (err) {
			error = err;
		}
		expect(error).to.be.instanceOf(FixedOutputFeeError);
		expect((error as FixedOutputFeeError).code).to.equal('FEE_COINS_SHORT');
		expect((error as FixedOutputFeeError).remedy).to.equal('wait');
		const entries = [
			...pair.bob.node
				.getChannelManager()
				.getChannel(pair.channelId)!
				.getFullState()
				.htlcs.values()
		].filter((entry) => entry.paymentHash.equals(held.paymentHash));
		expect(entries, 'the part is still held').to.have.length(1);
		await world.mine(pair, 3);
		expect(
			pair.bob.node.settleHeldHtlc(held.paymentHash, held.preimage)
		).to.equal(true);
		await settle();
	});
});
