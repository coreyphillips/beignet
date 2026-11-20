/**
 * Asset channels (issue #2098, step 6): a node that forwards asset HTLCs
 * keeps fee coins for the spends of its asset channels' outputs that have a
 * deadline. Their size, what the coins ready can pay for, and a spend
 * without a deadline that asks for its fee input only shortly before it can
 * confirm and only from coins beyond those. A node that does not forward
 * funds its spends as before.
 */

import { expect } from 'chai';
import {
	FIXED_OUTPUT_DEADLINE_SPEND_VBYTES,
	FIXED_OUTPUT_FEE_INPUT_VBYTES,
	fundableDeadlineSpends,
	noDeadlineSpendMayAsk,
	reserveCoinSatoshis
} from '../../src/lightning/channel/fixed-output-reserve';
import {
	FIXED_OUTPUT_FEE_TIMING,
	OutputStatus,
	OutputType,
	fixedOutputHtlcFeeActionId,
	type ITrackedOutput
} from '../../src/lightning/chain/types';
import type { IFeeBumpSelectionOpts } from '../../src/lightning/node/types';
import type { WalletFundingProvider } from '../../src/lightning/wallet/wallet-funding-provider';
import { withAssetOpens, type IAssetHost } from './helpers/auxiliary-nodes';
import {
	SWEEP_DESTINATION,
	assetChainWorld,
	disconnect,
	holdUnits,
	settle,
	trackedOutputs,
	type IAssetChainPair
} from './helpers/auxiliary-on-chain';

describe('fee coins kept for spends with a deadline: the arithmetic (#2098 step 6)', () => {
	it('sizes a kept coin at the largest spend with a deadline and one fee input, never under the dust limit', () => {
		const vbytes =
			FIXED_OUTPUT_DEADLINE_SPEND_VBYTES + FIXED_OUTPUT_FEE_INPUT_VBYTES;
		expect(reserveCoinSatoshis(10)).to.equal(BigInt(vbytes * 10));
		expect(reserveCoinSatoshis(2.5)).to.equal(BigInt(Math.ceil(vbytes * 2.5)));
		expect(reserveCoinSatoshis(1)).to.equal(330n);
		expect(() => reserveCoinSatoshis(0)).to.throw('positive');
	});

	it('counts what the coins ready pay for spend by spend, with whole coins, at the rate of the moment and within the cap', () => {
		const coin = reserveCoinSatoshis(10);
		const five = Array.from({ length: 5 }, () => coin);
		// At the rate the coins were made for, one coin pays for one spend.
		expect(fundableDeadlineSpends(five, 10, 20_000n)).to.equal(5);
		// At twice that rate a spend takes three of them, with the inputs
		// they add: five coins pay for one spend, not two and a half.
		expect(fundableDeadlineSpends(five, 20, 20_000n)).to.equal(1);
		// A coin over the cap of an action is never spent.
		expect(fundableDeadlineSpends([50_000n], 10, 20_000n)).to.equal(0);
		// Two small coins do not make up a spend that one large coin pays.
		expect(fundableDeadlineSpends([coin, 400n, 400n], 10, 20_000n)).to.equal(1);
		expect(fundableDeadlineSpends([], 10, 20_000n)).to.equal(0);
	});

	it('lets a spend without a deadline ask when none with a deadline waits, and otherwise only from coins beyond what those need', () => {
		const coin = reserveCoinSatoshis(10);
		const three = [coin, coin, coin];
		const ask = (need: number, coins: bigint[] = three): boolean =>
			noDeadlineSpendMayAsk({
				readyCoins: coins,
				ratePerVbyte: 10,
				capSatoshis: 20_000n,
				need
			});
		expect(ask(0, [])).to.equal(true);
		expect(ask(2)).to.equal(true);
		expect(ask(3)).to.equal(false);
		expect(ask(1, [])).to.equal(false);
	});
});

describe('fee coins kept for spends with a deadline: on the chain (#2098 step 6)', function () {
	this.timeout(300_000);
	withAssetOpens();
	const world = assetChainWorld();
	afterEach(() => world.dispose());
	const valueIncomingHtlc = (context: { auxiliaryAmount?: bigint }): bigint =>
		(context.auxiliaryAmount ?? 0n) * 1000n;
	/** A host that takes forwards: one that supplies prepareForward. */
	const prepareForward = (): undefined => undefined;

	/** Every pool request of a host's provider, by fee action, with the height. */
	const recordAsks = (
		host: IAssetHost,
		pair: IAssetChainPair
	): Array<{ feeActionId: string; height: number }> => {
		const asks: Array<{ feeActionId: string; height: number }> = [];
		const provider = (
			host.node as unknown as { fundingProvider: WalletFundingProvider }
		).fundingProvider;
		const select = provider.selectFeeBumpInputs.bind(provider);
		provider.selectFeeBumpInputs = ((
			target: bigint,
			rate: number,
			opts?: IFeeBumpSelectionOpts
		) => {
			if (opts?.feeActionId) {
				asks.push({ feeActionId: opts.feeActionId, height: pair.chain.height });
			}
			return select(target, rate, opts);
		}) as typeof provider.selectFeeBumpInputs;
		return asks;
	};

	const actionOf = (pair: IAssetChainPair, output: ITrackedOutput): string =>
		fixedOutputHtlcFeeActionId(pair.channelId, output.txid, output.outputIndex);

	/**
	 * Bob holds two HTLCs Alice offered him and has not settled, one he
	 * settled while Alice is away, and one he offered Alice that she holds,
	 * which expires first; then he closes the channel by force.
	 */
	const staged = async (
		tag: string,
		forwards: boolean
	): Promise<{
		pair: IAssetChainPair;
		asks: Array<{ feeActionId: string; height: number }>;
		offered: ITrackedOutput;
		settled: ITrackedOutput;
		timeoutAt: number;
	}> => {
		const pair = await world.open(tag, {
			feeWallet: { alice: true, bob: true },
			hooks: {
				alice: { valueIncomingHtlc },
				bob: {
					valueIncomingHtlc,
					...(forwards ? { prepareForward } : {})
				}
			}
		});
		for (const wallet of [pair.wallets.alice!, pair.wallets.bob!]) {
			for (let i = 0; i < 3; i++) wallet.fund(200_000);
		}
		await world.mine(pair, 1);
		const swapped = { ...pair, alice: pair.bob, bob: pair.alice };
		const toAlice = await holdUnits(swapped, 1000n, `${tag} to alice`, 20);
		const claim = await holdUnits(pair, 1000n, `${tag} claim`, 40);
		await holdUnits(pair, 1000n, `${tag} open a`, 40);
		await holdUnits(pair, 1000n, `${tag} open b`, 40);
		disconnect(pair);
		pair.bob.node.settleHeldHtlc(claim.paymentHash, claim.preimage);
		await settle();
		const asks = recordAsks(pair.bob, pair);
		const closed = pair.bob.node.forceCloseChannel(
			pair.channelId,
			SWEEP_DESTINATION
		);
		expect(closed.ok, closed.error).to.equal(true);
		await settle();
		await world.mine(pair, 1);
		const outputs = trackedOutputs(pair.bob, pair.channelId);
		const offered = outputs.find(
			(output) =>
				output.outputType === OutputType.OFFERED_HTLC &&
				output.paymentHash?.equals(toAlice.paymentHash)
		)!;
		const settled = outputs.find(
			(output) =>
				output.outputType === OutputType.RECEIVED_HTLC &&
				output.paymentHash?.equals(claim.paymentHash)
		)!;
		expect(offered, 'the offered HTLC is on the chain').to.not.equal(undefined);
		expect(settled, 'the settled HTLC is on the chain').to.not.equal(undefined);
		return { pair, asks, offered, settled, timeoutAt: toAlice.cltvExpiry };
	};

	it('a node that does not forward asks for the fee input of an HTLC timeout from the block it is made, as before', async () => {
		const { pair, asks, offered, settled } = await staged(
			'reserve-wallet',
			false
		);
		await world.mine(pair, 2);
		const asked = new Set(asks.map((ask) => ask.feeActionId));
		expect(asked.has(actionOf(pair, settled)), 'the claim asked').to.equal(
			true
		);
		expect(asked.has(actionOf(pair, offered)), 'the timeout asked').to.equal(
			true
		);
	});

	it('a node that forwards asks for the fee input of an HTLC timeout only 6 blocks before it can confirm, and then pays it with coins it prepared ahead', async () => {
		const { pair, asks, offered, settled, timeoutAt } = await staged(
			'reserve-forwarding',
			true
		);
		await world.mine(pair, 2);
		const askedFor = (output: ITrackedOutput): number[] =>
			asks
				.filter((ask) => ask.feeActionId === actionOf(pair, output))
				.map((ask) => ask.height);
		// The claim by preimage has a deadline and asks at once.
		expect(askedFor(settled).length).to.be.greaterThan(0);
		// The timeout does not ask before it is near its height.
		const near = timeoutAt - FIXED_OUTPUT_FEE_TIMING.noDeadlineAskBlocks;
		while (pair.chain.height < near - 1) await world.mine(pair, 1);
		expect(askedFor(offered)).to.deep.equal([]);
		await world.mine(pair, 3);
		expect(askedFor(offered).length).to.be.greaterThan(0);
		const funded = trackedOutputs(pair.bob, pair.channelId).find(
			(output) =>
				output.txid === offered.txid &&
				output.outputIndex === offered.outputIndex
		)!;
		expect(funded.auxiliaryFeeWait).to.equal(undefined);
	});

	it('a node that forwards keeps a spend without a deadline waiting while the coins ready, as its pool reports them, would not pay for its spends with a deadline', async () => {
		const { pair, asks, offered, timeoutAt } = await staged(
			'reserve-kept',
			true
		);
		// The pool reports no coin ready, whatever it holds.
		const provider = (
			pair.bob.node as unknown as { fundingProvider: WalletFundingProvider }
		).fundingProvider;
		const status = provider.getFixedOutputFeeStatus.bind(provider);
		provider.getFixedOutputFeeStatus = (
			forFee?: bigint
		): ReturnType<typeof status> => {
			const real = status(forFee);
			return real?.available
				? {
						...real,
						feeCoins: {
							...real.feeCoins,
							ready: 0,
							readySatoshis: 0n,
							readyCoinSatoshis: []
						}
				  }
				: real;
		};
		const near = timeoutAt - FIXED_OUTPUT_FEE_TIMING.noDeadlineAskBlocks;
		while (pair.chain.height < near + 1) await world.mine(pair, 1);
		// Two HTLCs Bob has not settled may still need a claim each: the
		// timeout waits for coins beyond theirs, and asks the pool nothing.
		const waiting = trackedOutputs(pair.bob, pair.channelId).find(
			(output) =>
				output.txid === offered.txid &&
				output.outputIndex === offered.outputIndex
		)!;
		expect(waiting.auxiliaryFeeWait?.code).to.equal('FEE_KEPT_FOR_DEADLINES');
		expect(waiting.status).to.equal(OutputStatus.CONFIRMED);
		expect(
			asks.filter((ask) => ask.feeActionId === actionOf(pair, offered))
		).to.deep.equal([]);
	});
});
