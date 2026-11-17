/**
 * Asset channels (issue #2093): the balance output of the node that force
 * closes its own asset channel.
 *
 * The acceptor of an asset channel holds units and almost no bitcoin: its
 * output holds the 354 sat an output of units must hold and nothing more.
 * Such an output cannot pay for its own sweep. When the peer force closes,
 * the output is a to_remote; when the node force closes itself, it is a
 * delayed to_local. Either way its sweep takes its fee from a wallet input
 * of the fee pool, and the wait for that input is on the output for a host
 * to read. An output that carries units is never declined as uneconomic.
 */
import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import {
	CommitmentType,
	IRREVOCABLE_DEPTH,
	OutputStatus,
	OutputType,
	type ITrackedOutput
} from '../../src/lightning/chain/types';
import { withAssetOpens, type IAssetHost } from './helpers/auxiliary-nodes';
import {
	ASSET_SWEEP_SCRIPT,
	SWEEP_DESTINATION,
	assetChainWorld,
	errorsOf,
	settle,
	trackedOutputs,
	type IAssetChainPair
} from './helpers/auxiliary-on-chain';

const say = (text: string): void => {
	if (process.env.AUX_TRACE) console.log(text);
};

describe('asset channels: the own balance output on chain', function () {
	this.timeout(240_000);
	withAssetOpens();
	const world = assetChainWorld();
	afterEach(() => world.dispose());
	const done = [
		OutputStatus.SPEND_CONFIRMED,
		OutputStatus.IRREVOCABLY_RESOLVED
	];
	const output = (
		host: IAssetHost,
		pair: IAssetChainPair,
		type: OutputType
	): ITrackedOutput | undefined =>
		trackedOutputs(host, pair.channelId).find(
			(tracked) => tracked.outputType === type
		);
	const poolOf = (
		host: IAssetHost
	): {
		getFixedOutputFeeActionIds(id: Buffer): readonly string[];
	} =>
		(
			host.node as unknown as {
				fundingProvider: {
					getFixedOutputFeeActionIds(id: Buffer): readonly string[];
				};
			}
		).fundingProvider;
	const atRate = (host: IAssetHost, feeRate: number): void => {
		(
			host.node as unknown as {
				resolveForceCloseFeeRatePerVbyte: () => number;
			}
		).resolveForceCloseFeeRatePerVbyte = (): number => feeRate;
	};
	const uneconomicOf = (host: IAssetHost): unknown[] => {
		const said: unknown[] = [];
		host.node
			.getChannelManager()
			.on('sweep:uneconomic', (_id: unknown, action: unknown) => {
				said.push(action);
			});
		return said;
	};
	/** The acceptor holds its units and the 354 sat their output must hold. */
	const opened = async (
		tag: string,
		feeRate: number,
		wallets: { alice?: true; bob?: true } = { alice: true, bob: true }
	): Promise<IAssetChainPair> => {
		const pair = await world.open(tag, {
			pushMsat: 354_000n,
			acceptorUnits: 1000n,
			feeWallet: wallets
		});
		for (const wallet of [pair.wallets.alice, pair.wallets.bob]) {
			wallet?.fund(100_000);
			wallet?.fund(100_000);
		}
		for (const host of [pair.alice, pair.bob]) atRate(host, feeRate);
		await world.mine(pair, 1);
		return pair;
	};
	const delayOf = (host: IAssetHost, pair: IAssetChainPair): number =>
		host.node.getChannelManager().getChannel(pair.channelId)!.getFullState()
			.remoteConfig.toSelfDelay;

	it('is swept with a wallet input when the peer force closes (to_remote)', async () => {
		const pair = await opened('aux-own-remote', 1);
		const closed = pair.alice.node.forceCloseChannel(
			pair.channelId,
			SWEEP_DESTINATION
		);
		expect(closed.ok, closed.error).to.equal(true);
		await settle();
		for (let i = 0; i < 6; i++) await world.mine(pair, 1);
		const mine = output(pair.bob, pair, OutputType.TO_REMOTE)!;
		expect(mine.amount).to.equal(354n);
		expect(done.includes(mine.status)).to.equal(true);
		const spend = pair.chain.confirmed.get(mine.resolutionTxid!)!.tx;
		expect(spend.ins.length).to.equal(2);
		expect(spend.outs[0].script.equals(ASSET_SWEEP_SCRIPT)).to.equal(true);
	});

	for (const feeRate of [1, 10]) {
		it(`is swept with a wallet input when the node force closes itself (to_local, delayed), at ${feeRate} sat/vB`, async () => {
			const tag = `aux-own-local-${feeRate}`;
			const pair = await opened(tag, feeRate);
			const { bob, channelId } = pair;
			const uneconomic = uneconomicOf(bob);
			const closed = bob.node.forceCloseChannel(channelId, SWEEP_DESTINATION);
			expect(closed.ok, closed.error).to.equal(true);
			await settle();
			const toSelfDelay = delayOf(bob, pair);

			// As soon as the commitment is out the output has a spend that
			// takes its fee from a wallet input, and the fee pool was asked for
			// one under the identity of the output. The pool splits a coin
			// first: until the split is in a block the wait is on the output,
			// with its code, its remedy and since when. Nobody else can spend
			// this output, so the wait has no deadline.
			const first = output(bob, pair, OutputType.TO_LOCAL)!;
			say(
				`[${tag}] commitment out: ${first.status} ins=${
					bitcoin.Transaction.fromHex(first.sweepTxHex!).ins.length
				} wait=${JSON.stringify(first.auxiliaryFeeWait)}`
			);
			expect(first.amount).to.equal(354n);
			expect(first.auxiliaryCommitmentNumber).to.not.equal(undefined);
			expect(first.auxiliaryFeeFunding).to.equal(true);
			expect(
				bitcoin.Transaction.fromHex(first.sweepTxHex!).ins.length
			).to.equal(1);
			expect(poolOf(bob).getFixedOutputFeeActionIds(channelId)).to.have.length(
				1
			);
			expect(first.auxiliaryFeeWait).to.deep.include({
				code: 'FEE_PREPARATION_PENDING',
				remedy: 'wait',
				sinceHeight: pair.chain.height
			});
			expect(first.auxiliaryFeeWait!.deadlineHeight).to.equal(undefined);

			await world.mine(pair, 1);
			const h = pair.chain.height;
			expect(
				bob.node.getChannelMonitorState(channelId)!.commitmentBroadcast!
					.commitmentType
			).to.equal(CommitmentType.OUR_COMMITMENT);

			// The input is attached during the delay, and nothing is published
			// before the delay has passed.
			for (let i = 0; i < 2; i++) await world.mine(pair, 1);
			const held = output(bob, pair, OutputType.TO_LOCAL)!;
			expect(held.status).to.equal(OutputStatus.CONFIRMED);
			expect(held.maturityHeight).to.equal(h + toSelfDelay);
			expect(held.auxiliaryFeeWait).to.equal(undefined);
			expect(bitcoin.Transaction.fromHex(held.sweepTxHex!).ins.length).to.equal(
				2
			);
			while (pair.chain.height < h + toSelfDelay - 1) {
				await world.mine(pair, 1);
			}
			expect(pair.chain.spender(held.txid, held.outputIndex)).to.equal(
				undefined
			);

			for (let i = 0; i < 4; i++) await world.mine(pair, 1);
			const mine = output(bob, pair, OutputType.TO_LOCAL)!;
			say(
				`[${tag}] commitment +${pair.chain.height - h}: ${
					mine.status
				}; provider asked ${pair.sweeps.bob.length} times; errors ${errorsOf(
					bob
				).join(' | ')}`
			);
			expect(done.includes(mine.status)).to.equal(true);
			const spend = pair.chain.confirmed.get(mine.resolutionTxid!)!;
			// It leaves at the block that ends the delay and is in the next one.
			expect(spend.height).to.equal(h + toSelfDelay + 1);
			expect(spend.tx.ins.length).to.equal(2);
			expect(spend.tx.ins[0].sequence).to.equal(toSelfDelay);
			expect(spend.tx.outs.length).to.equal(1);
			expect(spend.tx.outs[0].value).to.equal(354);
			expect(spend.tx.outs[0].script.equals(ASSET_SWEEP_SCRIPT)).to.equal(true);
			expect(
				pair.sweeps.bob.map((call) => `${call.side}:${call.kinds.join()}`)
			).to.include('local:to_local_delayed');
			// Units are never said to be uneconomic to sweep.
			expect(uneconomic).to.deep.equal([]);
			expect(
				pair.backends.bob.refused.filter(
					(refusal) => !refusal.reason.includes('unconfirmed output')
				)
			).to.deep.equal([]);

			// Once the sweep is irrevocable its fee action is retired.
			pair.chain.advance(IRREVOCABLE_DEPTH);
			await settle();
			await world.mine(pair, 2);
			for (let i = 0; i < 20; i++) await settle();
			expect(output(bob, pair, OutputType.TO_LOCAL)!.status).to.equal(
				OutputStatus.IRREVOCABLY_RESOLVED
			);
			expect(poolOf(bob).getFixedOutputFeeActionIds(channelId)).to.deep.equal(
				[]
			);
		});
	}

	it('says what the sweep of the own balance waits for when the node has no wallet for fee inputs, and never that units are uneconomic', async () => {
		const tag = 'aux-own-local-no-wallet';
		const pair = await opened(tag, 1, { alice: true });
		const { bob, channelId } = pair;
		const uneconomic = uneconomicOf(bob);
		const closed = bob.node.forceCloseChannel(channelId, SWEEP_DESTINATION);
		expect(closed.ok, closed.error).to.equal(true);
		await settle();
		const since = pair.chain.height;
		await world.mine(pair, 1);
		const h = pair.chain.height;
		const toSelfDelay = delayOf(bob, pair);
		while (pair.chain.height < h + toSelfDelay + 3) await world.mine(pair, 1);
		const mine = output(bob, pair, OutputType.TO_LOCAL)!;
		expect(mine.status).to.equal(OutputStatus.CONFIRMED);
		expect(mine.auxiliaryFeeFunding).to.equal(true);
		expect(bitcoin.Transaction.fromHex(mine.sweepTxHex!).ins.length).to.equal(
			1
		);
		expect(mine.auxiliaryFeeWait).to.deep.include({
			code: 'FEE_WALLET_UNAVAILABLE',
			remedy: 'operator',
			sinceHeight: since
		});
		expect(uneconomic).to.deep.equal([]);
		expect(pair.chain.spender(mine.txid, mine.outputIndex)).to.equal(undefined);
		// The provider is not asked about a spend that cannot go out.
		expect(pair.sweeps.bob).to.deep.equal([]);
		expect(
			errorsOf(bob).filter((error) => error.includes('FEE_WALLET_UNAVAILABLE'))
		).to.have.length(1);
	});
});
