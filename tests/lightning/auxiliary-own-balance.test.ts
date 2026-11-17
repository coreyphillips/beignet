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
	ownSpends,
	payUnits,
	settle,
	trackedOutputs,
	underpaidSpends,
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
			// The wallet input pays for the size the sweep really has: 146
			// vbytes of its own and 68 of the input.
			const [paid] = ownSpends(pair, bob).filter(
				(own) => own.output.outputType === OutputType.TO_LOCAL
			);
			expect(paid.vbytes).to.equal(214);
			expect(paid.fee).to.be.at.least(214 * feeRate);
			expect(underpaidSpends(pair)).to.deep.equal([]);
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

	for (const restart of [false, true]) {
		it(`an own balance output of about 1 000 sat, whose sweep is signed at 1 sat/vB and held for its delay, is swept ${
			restart
				? 'when the node restarts during the delay, by the sweep it held'
				: 'when the node keeps running'
		}`, async () => {
			const tag = `aux-own-held-${restart}`;
			// Alice, the opener, keeps about 1 000 sat beside her units.
			const pair = await world.open(tag, {
				pushMsat: 1_998_096_000n,
				feeWallet: { alice: true, bob: true }
			});
			atRate(pair.alice, 1);
			pair.wallets.alice!.fund(100_000);
			pair.wallets.alice!.fund(100_000);
			await world.mine(pair, 1);
			const { channelId } = pair;
			const closed = pair.alice.node.forceCloseChannel(
				channelId,
				SWEEP_DESTINATION
			);
			expect(closed.ok, closed.error).to.equal(true);
			await settle();
			await world.mine(pair, 2);
			const held = output(pair.alice, pair, OutputType.TO_LOCAL)!;
			expect(held.auxiliaryCommitmentNumber).to.not.equal(undefined);
			expect(held.sweepTxHex, 'a signed sweep is held').to.be.a('string');
			const signed = bitcoin.Transaction.fromHex(held.sweepTxHex!);
			expect(signed.ins.length).to.equal(1);
			expect(signed.ins[0].witness.length).to.equal(3);
			expect(held.auxiliaryFeeFunding).to.equal(undefined);
			expect(held.status).to.equal(OutputStatus.CONFIRMED);

			if (restart) {
				// The node comes back at another fee rate than the one the sweep
				// was signed at, one at which the output could not pay for its
				// sweep. The sweep it holds is signed and stored: it is kept as
				// it was, nothing is said to wait, and no fee action is opened.
				await world.restartAlice(pair, tag);
				await world.mine(pair, 1);
				const after = output(pair.alice, pair, OutputType.TO_LOCAL)!;
				expect(after.sweepTxHex).to.equal(held.sweepTxHex);
				expect(after.auxiliaryData).to.deep.equal(held.auxiliaryData);
				expect(after.status).to.equal(OutputStatus.CONFIRMED);
				expect(after.auxiliaryFeeFunding).to.equal(undefined);
				expect(after.auxiliaryFeeWait).to.equal(undefined);
				expect(after.auxiliaryRefusal).to.equal(undefined);
				expect(
					poolOf(pair.alice).getFixedOutputFeeActionIds(channelId)
				).to.deep.equal([]);
				atRate(pair.alice, 1);
			}
			// Block by block, so that a split of the fee pool would confirm and
			// be seen as it would be on a real chain.
			while (pair.chain.height < held.maturityHeight! - 1) {
				await world.mine(pair, 1);
			}
			expect(pair.chain.spender(held.txid, held.outputIndex)).to.equal(
				undefined
			);
			const until = held.maturityHeight! + 30;
			while (pair.chain.height < until) await world.mine(pair, 1);
			const mine = output(pair.alice, pair, OutputType.TO_LOCAL)!;
			say(
				`[${tag}] to_local ${mine.status}, feeFunding=${
					mine.auxiliaryFeeFunding
				}, wait=${JSON.stringify(
					mine.auxiliaryFeeWait
				)}, spent in block maturity +${
					mine.resolutionTxid
						? pair.chain.confirmed.get(mine.resolutionTxid)!.height -
						  held.maturityHeight!
						: 'never'
				} by ${
					mine.resolutionTxid === signed.getId() ? 'the held sweep' : 'another'
				}; errors ${errorsOf(pair.alice)
					.filter((e) => !e.startsWith('BROADCAST_FAILED'))
					.join(' | ')}`
			);
			expect(done.includes(mine.status)).to.equal(true);
			const spend = pair.chain.confirmed.get(mine.resolutionTxid!)!.tx;
			expect(spend.outs[0].script.equals(ASSET_SWEEP_SCRIPT)).to.equal(true);
			expect(spend.outs[0].value).to.be.at.least(330);
			expect(mine.auxiliaryFeeWait).to.equal(undefined);
			// The sweep that was held is the one a block took, in the block
			// after the one that ended the delay: it was signed for the size
			// it has, so the network took it at the floor rate.
			expect(mine.resolutionTxid).to.equal(signed.getId());
			expect(pair.chain.confirmed.get(mine.resolutionTxid!)!.height).to.equal(
				held.maturityHeight! + 1
			);
			expect(signed.virtualSize()).to.equal(146);
			expect(Number(held.amount) - signed.outs[0].value).to.equal(146);
			expect(mine.auxiliaryFeeFunding).to.equal(undefined);
			expect(underpaidSpends(pair)).to.deep.equal([]);
		});
	}

	it('after a restart the fee pool still brings a fee input (a penalty of a 354 sat output)', async () => {
		const tag = 'aux-own-control';
		const pair = await world.open(tag, {
			pushMsat: 354_000n,
			feeWallet: { alice: true },
			hooks: {
				bob: {
					valueIncomingHtlc: (context: { auxiliaryAmount?: bigint }) =>
						(context.auxiliaryAmount ?? 0n) * 1000n
				}
			}
		});
		pair.wallets.alice!.fund(100_000);
		pair.wallets.alice!.fund(100_000);
		await world.mine(pair, 1);
		const channel = pair.bob.node
			.getChannelManager()
			.getChannel(pair.channelId)!;
		const plan = channel.prepareForceClose(channel.getSigner()!);
		if (!plan.ok) throw new Error(plan.error);
		await payUnits(pair, 100n);
		await payUnits(pair, 100n);
		await world.restartAlice(pair, tag);
		await world.mine(pair, 1);
		await pair.backends.bob.broadcastTransaction(
			bitcoin.Transaction.fromBuffer(plan.commitmentTx).toHex()
		);
		await settle();
		for (let i = 0; i < 8; i++) await world.mine(pair, 1);
		const theirs = output(pair.alice, pair, OutputType.TO_LOCAL)!;
		expect(done.includes(theirs.status)).to.equal(true);
	});

	it('a spend that has its fee input and cannot be made again says why, once, and its row reads the reason in place of a wait for the pool', async () => {
		const tag = 'aux-own-not-made';
		// Bob has a wallet with no coin in it yet.
		const pair = await world.open(tag, {
			pushMsat: 354_000n,
			acceptorUnits: 1000n,
			feeWallet: { alice: true, bob: true }
		});
		const { bob, channelId } = pair;
		atRate(bob, 1);
		await world.mine(pair, 1);
		const closed = bob.node.forceCloseChannel(channelId, SWEEP_DESTINATION);
		expect(closed.ok, closed.error).to.equal(true);
		await settle();
		await world.mine(pair, 2);
		const waiting = output(bob, pair, OutputType.TO_LOCAL)!;
		expect(waiting.auxiliaryFeeFunding).to.equal(true);
		expect(waiting.auxiliaryFeeWait?.code).to.be.a('string');
		expect(waiting.auxiliaryFeeWait!.code).to.not.equal(
			'FEE_SPEND_UNAVAILABLE'
		);
		const since = waiting.auxiliaryFeeWait!.sinceHeight;

		// What stands in for a spend that cannot be made again: the asset
		// side of the commitment is gone from what the monitor holds.
		const monitor = bob.node.getChannelManager().getMonitor(channelId)!;
		const number = waiting.auxiliaryCommitmentNumber!;
		const lost = (state: {
			auxiliaryState?: { localCommitments: Map<bigint, unknown> };
		}): void => {
			state.auxiliaryState!.localCommitments.delete(number);
		};
		lost(
			(monitor as unknown as { _channelState: Parameters<typeof lost>[0] })
				._channelState
		);

		// A monitor asked about an output it holds no fee-funded spend for
		// answers with a reason too, and says the output is not waiting.
		const none = monitor.fundFixedOutputSpend('00'.repeat(32), 0, 1, [], () => {
			throw new Error('nothing to sign');
		});
		expect(none.ok).to.equal(false);
		expect(none).to.include({ gone: true });
		expect((none as { refusal: string }).refusal).to.be.a('string');

		// Coins arrive, the pool splits one, and the input is there.
		pair.wallets.bob!.fund(100_000);
		pair.wallets.bob!.fund(100_000);
		for (let i = 0; i < 6; i++) await world.mine(pair, 1);
		const stuck = output(bob, pair, OutputType.TO_LOCAL)!;
		say(
			`[${tag}] ${stuck.status} wait=${JSON.stringify(
				stuck.auxiliaryFeeWait
			)}; errors ${errorsOf(bob).join(' | ')}`
		);
		expect(stuck.status).to.equal(OutputStatus.CONFIRMED);
		expect(stuck.auxiliaryFeeWait).to.deep.include({
			code: 'FEE_SPEND_UNAVAILABLE',
			remedy: 'operator',
			sinceHeight: since
		});
		expect(stuck.auxiliaryFeeWait!.message).to.include(
			`The asset side of commitment ${number} is not held`
		);
		const said = errorsOf(bob).filter((error) =>
			error.includes('has its fee input and cannot go out')
		);
		expect(said).to.have.length(1);
		expect(said[0]).to.include(`${stuck.txid}:${stuck.outputIndex}`);
		expect(said[0]).to.include(
			`The asset side of commitment ${number} is not held`
		);
	});
});
