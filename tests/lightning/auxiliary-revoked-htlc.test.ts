/**
 * Issue #2093 step 10: the HTLC outputs of a revoked commitment of an asset
 * channel on the chain.
 *
 * The cheater puts an old copy of its store back, one in which an HTLC that
 * has since failed is still in flight, and force closes from it. The other
 * node takes the HTLC output with the revocation key, and when the cheater's
 * second-level transaction gets there first, takes the output of that. Each
 * penalty keeps the whole amount in its output and takes its fee from a
 * wallet input of the fee pool, through the real WalletFundingProvider. The
 * chain judges every spend against the script tree of the output it spends.
 */
import * as fs from 'fs';
import * as bitcoin from 'bitcoinjs-lib';
import { expect } from 'chai';
import type Database from 'better-sqlite3';
import {
	CommitmentType,
	IRREVOCABLE_DEPTH,
	OutputStatus,
	OutputType,
	type ITrackedOutput
} from '../../src/lightning/chain/types';
import type { WalletFundingProvider } from '../../src/lightning/wallet/wallet-funding-provider';
import { withAssetOpens, type IAssetHost } from './helpers/auxiliary-nodes';
import {
	ASSET_SWEEP_SCRIPT,
	SWEEP_DESTINATION,
	assetChainWorld,
	errorsOf,
	holdUnits,
	monitorRoundTrips,
	settle,
	trackedOutputs,
	type IAssetChainPair
} from './helpers/auxiliary-on-chain';

/** One input by the key of the output, one wallet input, one output. */
const PENALTY_VBYTES = 179;
const SECOND_PENALTY_VBYTES = 179;

describe('the HTLC outputs of a revoked commitment of an asset channel (issue #2093 step 10)', function () {
	this.timeout(120000);
	withAssetOpens();
	const world = assetChainWorld();
	const kept: string[] = [];
	afterEach(function () {
		// Every spend either node made in a test that passed paid, for the
		// size it really has, the rate its output was first given a spend
		// at, and none was refused as below the relay floor.
		const underpaid =
			this.currentTest?.state === 'passed' ? world.underpaid() : [];
		world.dispose();
		for (const file of kept.splice(0)) fs.rmSync(file, { force: true });
		expect(underpaid).to.deep.equal([]);
	});

	const done = [
		OutputStatus.SPEND_CONFIRMED,
		OutputStatus.IRREVOCABLY_RESOLVED
	];
	const until = async (
		what: string,
		pair: IAssetChainPair,
		reached: () => boolean,
		most = 40
	): Promise<void> => {
		for (let i = 0; i < most && !reached(); i++) await world.mine(pair, 1);
		if (!reached()) {
			throw new Error(
				`never reached: ${what}; alice: ${errorsOf(pair.alice).join(
					' | '
				)}; bob: ${errorsOf(pair.bob).join(' | ')}; refused: ${JSON.stringify(
					pair.backends.alice.refused.concat(pair.backends.bob.refused)
				)}`
			);
		}
	};
	const passTo = async (
		pair: IAssetChainPair,
		height: number
	): Promise<void> => {
		if (pair.chain.height < height) {
			pair.chain.advance(height - pair.chain.height);
			await settle();
		}
	};
	const of = (
		host: IAssetHost,
		pair: IAssetChainPair,
		txid: string | undefined
	): ITrackedOutput[] =>
		trackedOutputs(host, pair.channelId).filter(
			(output) => output.txid === txid
		);
	const htlcOf = (
		host: IAssetHost,
		pair: IAssetChainPair,
		txid: string | undefined
	): ITrackedOutput | undefined =>
		of(host, pair, txid).find(
			(output) =>
				output.outputType === OutputType.OFFERED_HTLC ||
				output.outputType === OutputType.RECEIVED_HTLC
		);
	const confirmed = (
		pair: IAssetChainPair,
		txid: string | undefined
	): { tx: bitcoin.Transaction; height: number } => {
		const entry = txid ? pair.chain.confirmed.get(txid) : undefined;
		if (!entry) throw new Error(`transaction ${txid} is not in a block`);
		return entry;
	};
	const poolOf = (host: IAssetHost): WalletFundingProvider =>
		(host.node as unknown as { fundingProvider: WalletFundingProvider })
			.fundingProvider;
	const trace = (pair: IAssetChainPair, at: string): void => {
		if (!process.env.AUX_TRACE) return;
		for (const who of ['alice', 'bob'] as const) {
			const rows = trackedOutputs(pair[who], pair.channelId).map(
				(o) =>
					`${o.txid.slice(0, 6)}:${o.outputIndex} ${o.outputType} ${
						o.status
					} n=${o.auxiliaryCommitmentNumber} ins=${
						o.sweepTxHex
							? bitcoin.Transaction.fromHex(o.sweepTxHex).ins.length
							: 0
					} wait=${o.auxiliaryFeeWait?.code} ref=${o.auxiliaryRefusal}`
			);
			console.log(
				`[${at}] height ${pair.chain.height} ${who}: ${rows.join(
					' | '
				)}; refused ${JSON.stringify(
					pair.backends[who].refused
				)}; errors ${errorsOf(pair[who]).join(' ; ')}`
			);
		}
	};
	/**
	 * What the chain turned away of what Bob published, but for what the
	 * previous release publishes too: a claim that waits a block, ahead of
	 * the block, and a sweep signed anew for an output already spent.
	 */
	const unexpectedRefusals = (pair: IAssetChainPair): string[] =>
		pair.backends.bob.refused
			.map((refusal) => refusal.reason)
			.filter(
				(reason) =>
					!reason.includes('is already spent by') &&
					!reason.includes('waits 1 blocks on an unconfirmed output')
			);

	/**
	 * Alice pays Bob through a hold invoice and keeps a copy of her store
	 * while the HTLC is in flight. Bob cancels the hold, the HTLC fails back
	 * and Alice revokes the commitment that held it. Alice then puts the
	 * copy back and force closes from it.
	 */
	const cheated = async (
		tag: string,
		bobHasCoins: boolean
	): Promise<{
		pair: IAssetChainPair;
		number: bigint;
		txid: string;
		cltvExpiry: number;
	}> => {
		const pair = await world.open(tag, {
			feeWallet: { alice: true, bob: true },
			hooks: {
				bob: {
					valueIncomingHtlc: (context: { auxiliaryAmount?: bigint }): bigint =>
						(context.auxiliaryAmount ?? 0n) * 1000n
				}
			}
		});
		for (const wallet of bobHasCoins
			? [pair.wallets.alice!, pair.wallets.bob!]
			: [pair.wallets.alice!]) {
			wallet.fund(100_000);
			wallet.fund(100_000);
		}
		await world.mine(pair, 1);
		const held = await holdUnits(pair, 5000n, tag);
		const stateOf = (): {
			localCommitmentNumber: bigint;
			htlcs: Map<string, unknown>;
		} =>
			pair.alice.node
				.getChannelManager()
				.getChannel(pair.channelId)!
				.getFullState();
		const number = stateOf().localCommitmentNumber;
		expect(stateOf().htlcs.size).to.equal(1);
		const copy = `${pair.alicePath}.kept`;
		kept.push(copy);
		(pair.alice.storage as unknown as { db: Database.Database }).db.exec(
			`VACUUM INTO '${copy}'`
		);
		pair.bob.node.cancelHoldInvoice(held.paymentHash);
		for (let i = 0; i < 20 && stateOf().htlcs.size > 0; i++) await settle();
		expect(stateOf().htlcs.size, 'the HTLC failed back').to.equal(0);
		expect(stateOf().localCommitmentNumber > number).to.equal(true);
		await world.restartAlice(pair, tag, undefined, () => {
			for (const suffix of ['', '-wal', '-shm']) {
				fs.rmSync(`${pair.alicePath}${suffix}`, { force: true });
			}
			fs.copyFileSync(copy, pair.alicePath);
		});
		expect(stateOf().localCommitmentNumber).to.equal(number);
		const closed = pair.alice.node.forceCloseChannel(
			pair.channelId,
			SWEEP_DESTINATION
		);
		expect(closed.ok, closed.error).to.equal(true);
		await settle();
		return {
			pair,
			number,
			txid: closed.commitmentTxid!,
			cltvExpiry: held.cltvExpiry
		};
	};

	it('are taken with the revocation key: the commitment and the split of a wallet coin in block h, the penalty in h+1 with the whole amount in its output', async () => {
		const { pair, number, txid } = await cheated('aux-revoked-htlc', true);
		const { bob, channelId } = pair;
		await world.mine(pair, 1);
		const h = pair.chain.height;
		trace(pair, 'h');
		expect(confirmed(pair, txid).height).to.equal(h);
		expect(
			bob.node.getChannelMonitorState(channelId)!.commitmentBroadcast
		).to.include({
			txid,
			commitmentType: CommitmentType.THEIR_REVOKED_COMMITMENT,
			commitmentNumber: number
		});
		const waiting = htlcOf(bob, pair, txid)!;
		expect(waiting.outputType).to.equal(OutputType.RECEIVED_HTLC);
		expect(waiting.amount).to.equal(354n);
		expect(waiting.auxiliaryCommitmentNumber).to.equal(number);
		// The commitment was seen before its block: the split is in block h too.
		await world.mine(pair, 1);
		trace(pair, 'h+1');
		const spent = htlcOf(bob, pair, txid)!;
		expect(spent.status).to.equal(OutputStatus.SPEND_CONFIRMED);
		const penalty = confirmed(pair, spent.resolutionTxid);
		expect(penalty.height).to.equal(h + 1);
		expect(penalty.tx.ins.length).to.equal(2);
		// The key of the output, tweaked: one signature and nothing else.
		expect(penalty.tx.ins[0].witness.length).to.equal(1);
		expect(penalty.tx.outs.map((out) => out.value)).to.deep.equal([354]);
		expect(penalty.tx.outs[0].script.equals(ASSET_SWEEP_SCRIPT)).to.equal(true);
		expect(spent.auxiliaryData!.toString()).to.match(
			/^sweep:remote:\d+:htlc_revocation:/
		);
		expect(spent.auxiliarySweepAttempts![penalty.tx.getId()]).to.deep.include({
			transaction: penalty.tx.toHex()
		});
		expect(spent.auxiliaryFeeWait).to.equal(undefined);
		if (process.env.AUX_TRACE) {
			console.log(`penalty of an HTLC output: ${penalty.tx.virtualSize()} vB`);
		}
		expect(penalty.tx.virtualSize()).to.be.closeTo(PENALTY_VBYTES, 1);

		// The cheater's balance and the node's own, each with its asset side.
		await until('both balance outputs spent', pair, () =>
			[OutputType.TO_LOCAL, OutputType.TO_REMOTE].every((type) =>
				of(bob, pair, txid).some(
					(output) => output.outputType === type && done.includes(output.status)
				)
			)
		);
		const kinds = pair.sweeps.bob.map((call) => call.kinds.join());
		expect(kinds).to.include('htlc_revocation');
		expect(kinds).to.include('to_local_revocation');
		expect(kinds).to.include('to_remote');
		expect(
			pair.sweeps.bob.every(
				(call) => call.side === 'remote' && call.commitmentNumber === number
			)
		).to.equal(true);
		expect(unexpectedRefusals(pair)).to.deep.equal([]);

		// Once the penalty is irrevocable its fee action is retired.
		expect(poolOf(bob).getFixedOutputFeeActionIds(channelId)).to.not.deep.equal(
			[]
		);
		await passTo(pair, pair.chain.height + IRREVOCABLE_DEPTH);
		await world.mine(pair, 2);
		for (let i = 0; i < 20; i++) await settle();
		expect(poolOf(bob).getFixedOutputFeeActionIds(channelId)).to.deep.equal([]);
		expect(poolOf(bob).getFixedOutputFeeBudget()!.reservedSatoshis).to.equal(
			0n
		);
		expect(
			errorsOf(bob).filter(
				(error) =>
					!error.startsWith('BROADCAST_FAILED') &&
					!error.includes('waits for a fee input')
			)
		).to.deep.equal([]);
	});

	it('are followed into the second-level transaction of the cheater when that gets there first: its output is taken with the revocation key, and the fee action of the output the cheater spent is retired', async () => {
		const { pair, number, txid, cltvExpiry } = await cheated(
			'aux-revoked-second',
			false
		);
		const { alice, bob, channelId } = pair;
		await world.mine(pair, 1);
		trace(pair, 'h');
		// Bob has no coin: the penalty of the HTLC output waits, and says so.
		const waiting = htlcOf(bob, pair, txid)!;
		expect(waiting.auxiliaryFeeWait).to.deep.include({
			code: 'FEE_FUNDS_UNAVAILABLE'
		});
		expect(waiting.status).to.equal(OutputStatus.CONFIRMED);
		// The cheater times the HTLC out with its second-level transaction.
		await passTo(pair, cltvExpiry - 1);
		await until('the HTLC-timeout of the cheater in a block', pair, () =>
			done.includes(htlcOf(alice, pair, txid)?.status as OutputStatus)
		);
		trace(pair, 'timed out');
		const lost = htlcOf(bob, pair, txid)!;
		const second = confirmed(pair, lost.resolutionTxid);
		expect(lost.resolutionTxid).to.equal(
			htlcOf(alice, pair, txid)!.resolutionTxid
		);
		const child = of(bob, pair, lost.resolutionTxid)[0];
		expect(child, 'the second-level output is tracked').to.not.equal(undefined);
		expect(child.amount).to.equal(354n);
		expect(child.auxiliaryCommitmentNumber).to.equal(number);
		expect(child.auxiliaryFeeWait).to.deep.include({
			code: 'FEE_FUNDS_UNAVAILABLE'
		});
		// What says so is in the monitor's row and reads back from it.
		monitorRoundTrips(bob, channelId, [
			'auxiliaryFeeWait',
			'auxiliaryHtlc',
			'auxiliaryFeeActionOpen',
			'auxiliaryFeeFunding',
			'secondLevelTxHex'
		]);
		// Bob gets coins: a split, then the penalty of the second-level output.
		pair.wallets.bob!.fund(100_000);
		pair.wallets.bob!.fund(100_000);
		await until(
			'the penalty of the second-level output in a block',
			pair,
			() => done.includes(of(bob, pair, lost.resolutionTxid)[0].status),
			10
		);
		trace(pair, 'punished');
		const taken = of(bob, pair, lost.resolutionTxid)[0];
		const penalty = confirmed(pair, taken.resolutionTxid);
		expect(penalty.height).to.be.lessThan(second.height + 10);
		expect(penalty.tx.ins.length).to.equal(2);
		expect(penalty.tx.ins[0].witness.length).to.equal(1);
		expect(penalty.tx.outs.map((out) => out.value)).to.deep.equal([354]);
		expect(penalty.tx.outs[0].script.equals(ASSET_SWEEP_SCRIPT)).to.equal(true);
		expect(taken.auxiliaryData!.toString()).to.match(
			/^sweep:remote:\d+:second_level_revocation:/
		);
		if (process.env.AUX_TRACE) {
			console.log(
				`penalty of a second-level output: ${penalty.tx.virtualSize()} vB`
			);
		}
		expect(penalty.tx.virtualSize()).to.be.closeTo(SECOND_PENALTY_VBYTES, 1);
		expect(unexpectedRefusals(pair)).to.deep.equal([]);

		// Both fee actions are retired once their spends are irrevocable: the
		// one of the output the cheater spent names the cheater's transaction.
		await passTo(pair, pair.chain.height + IRREVOCABLE_DEPTH);
		await world.mine(pair, 2);
		for (let i = 0; i < 20; i++) await settle();
		expect(poolOf(bob).getFixedOutputFeeActionIds(channelId)).to.deep.equal([]);
		expect(poolOf(bob).getFixedOutputFeeBudget()!.reservedSatoshis).to.equal(
			0n
		);
	});
});
