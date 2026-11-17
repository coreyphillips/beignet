/**
 * The HTLCs of an asset channel that ends on the chain (issue #2093 step 10).
 *
 * Each test puts the transactions on a test chain that judges every spend:
 * the commitment, the split the fee pool makes of a wallet coin, the
 * second-level HTLC transaction or the claim with its fee input attached,
 * and the sweep of what that leaves. The fee comes from the real
 * `WalletFundingProvider` with a fixed-output policy, over a wallet whose
 * coins are on the same chain.
 */

import * as bitcoin from 'bitcoinjs-lib';
import { expect } from 'chai';
import {
	IRREVOCABLE_DEPTH,
	OutputStatus,
	OutputType
} from '../../src/lightning/chain/types';
import { ChannelState } from '../../src/lightning/channel/types';
import type { ITrackedOutput } from '../../src/lightning/chain/types';
import { PaymentStatus } from '../../src/lightning/node/types';
import { withAssetOpens, type IAssetHost } from './helpers/auxiliary-nodes';
import {
	ASSET_SWEEP_SCRIPT,
	SWEEP_DESTINATION,
	assetChainWorld,
	disconnect,
	errorsOf,
	gateMessages,
	holdUnits,
	monitorRoundTrips,
	offerUnitsAgain,
	settle,
	trackedOutputs,
	type IAssetChainPair
} from './helpers/auxiliary-on-chain';

/** What Bob takes an HTLC of units to be worth. */
/** Measured: the block of the commitment after the claim deadline, and the blocks left before the expiry once the claim is in a block. */
const DEADLINE_COMMITMENT = 1;
/** The message types by which a node fails an HTLC back. */
const UPDATE_FAIL_HTLC = 131;
const UPDATE_FAIL_MALFORMED_HTLC = 135;
const DEADLINE_SPARE = 15;
const outcomes: { alice: string[]; bob: string[] } = { alice: [], bob: [] };
const told =
	(who: 'alice' | 'bob') =>
	(context: {
		direction: string;
		outcome: string;
		auxiliaryAmount: bigint;
	}): void => {
		outcomes[who].push(
			`${context.direction}:${context.outcome}:${context.auxiliaryAmount}`
		);
	};
const hooks = {
	alice: { onHtlcResolved: told('alice') },
	bob: {
		valueIncomingHtlc: (context: { auxiliaryAmount?: bigint }): bigint =>
			context.auxiliaryAmount! * 1000n,
		onHtlcResolved: told('bob')
	}
};
/** The parts of a hold invoice a node still has parked. */
const parkedOf = (host: IAssetHost, paymentHash: Buffer): number =>
	(host.node as unknown as { heldHtlcs: Map<string, unknown[]> }).heldHtlcs.get(
		paymentHash.toString('hex')
	)?.length ?? 0;

describe('the HTLCs of an asset channel on the chain (issue #2093 step 10)', function () {
	this.timeout(120000);
	withAssetOpens();
	const world = assetChainWorld();
	beforeEach(() => {
		outcomes.alice = [];
		outcomes.bob = [];
	});
	afterEach(function () {
		// Every spend either node made in a test that passed paid, for the
		// size it really has, the rate its output was first given a spend
		// at, and none was refused as below the relay floor.
		const underpaid =
			this.currentTest?.state === 'passed' ? world.underpaid() : [];
		world.dispose();
		expect(underpaid).to.deep.equal([]);
	});

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
	/** Let blocks pass up to a height, hearing only of the last. */
	const passTo = async (
		pair: IAssetChainPair,
		height: number
	): Promise<void> => {
		if (pair.chain.height < height) {
			pair.chain.advance(height - pair.chain.height);
			await settle();
		}
	};
	const htlcOf = (
		host: IAssetHost,
		pair: IAssetChainPair
	): ITrackedOutput | undefined =>
		trackedOutputs(host, pair.channelId).find(
			(output) =>
				output.outputType === OutputType.OFFERED_HTLC ||
				output.outputType === OutputType.RECEIVED_HTLC
		);
	const secondLevelOf = (
		host: IAssetHost,
		pair: IAssetChainPair
	): ITrackedOutput | undefined =>
		trackedOutputs(host, pair.channelId).find(
			(output) => output.isSecondLevelHtlc
		);
	const inputsOf = (output: ITrackedOutput | undefined): number =>
		output?.sweepTxHex
			? bitcoin.Transaction.fromHex(output.sweepTxHex).ins.length
			: 0;
	const trace = (
		pair: IAssetChainPair,
		who: 'alice' | 'bob',
		at: string
	): void => {
		if (!process.env.AUX_TRACE) return;
		const rows = trackedOutputs(pair[who], pair.channelId).map(
			(o) =>
				`${o.outputType}${o.isSecondLevelHtlc ? '/2nd' : ''} ${
					o.status
				} ins=${inputsOf(o)} mat=${o.maturityHeight} wait=${o.auxiliaryFeeWait
					?.code} ref=${o.auxiliaryRefusal}`
		);
		// eslint-disable-next-line no-console
		console.log(
			`[${at}] height ${pair.chain.height} ${who}: ${rows.join(
				' | '
			)}; sent ${pair.wallets[who]?.sent
				.map((x) => `${x.txid.slice(0, 6)}${x.refused ? '!' + x.refused : ''}`)
				.join(',')}; refused ${JSON.stringify(
				pair.backends[who].refused
			)}; errors ${errorsOf(pair[who]).join(' ; ')}`
		);
	};
	const confirmed = (
		pair: IAssetChainPair,
		txid: string | undefined
	): { tx: bitcoin.Transaction; height: number } => {
		const entry = txid ? pair.chain.confirmed.get(txid) : undefined;
		if (!entry) throw new Error(`transaction ${txid} is not in a block`);
		return entry;
	};

	it('times out an HTLC it offered on its own commitment: the second-level transaction keeps its output and takes its fee from a wallet input, and its output is swept after the delay', async () => {
		const pair = await world.open('aux-htlc-timeout', {
			feeWallet: { alice: true },
			hooks
		});
		// Two coins: the child that pays for the commitment takes one.
		pair.wallets.alice!.fund(100_000);
		pair.wallets.alice!.fund(100_000);
		await world.mine(pair, 1);
		const held = await holdUnits(pair, 5000n, 'timeout');

		const closed = pair.alice.node.forceCloseChannel(
			pair.channelId,
			SWEEP_DESTINATION
		);
		expect(closed.ok, closed.error).to.equal(true);
		await settle();
		// The commitment is seen at once, and the fee input is asked for at
		// once: the pool splits a wallet coin and says to wait for it.
		const waiting = htlcOf(pair.alice, pair)!;
		expect(waiting.outputType).to.equal(OutputType.OFFERED_HTLC);
		expect(waiting.amount).to.equal(354n);
		expect(waiting.auxiliaryFeeWait).to.deep.include({
			code: 'FEE_PREPARATION_PENDING',
			remedy: 'wait',
			sinceHeight: pair.chain.height
		});
		expect(waiting.auxiliaryFeeWait!.deadlineHeight).to.equal(undefined);

		for (let i = 0; i < 20 && pair.wallets.alice!.sent.length === 0; i++) {
			await settle();
		}
		expect(pair.wallets.alice!.sent.map((s) => s.refused)).to.deep.equal([
			undefined
		]);

		expect(inputsOf(waiting)).to.equal(1);

		// The split confirms with the commitment; one block on, the pool
		// gives the input and the transaction is whole, long before it may
		// leave.
		trace(pair, 'alice', 'closed');
		await world.mine(pair, 1);
		trace(pair, 'alice', 'h');
		await world.mine(pair, 1);
		trace(pair, 'alice', 'h+1');
		const whole = htlcOf(pair.alice, pair)!;
		expect(whole.auxiliaryFeeWait).to.equal(undefined);
		expect(inputsOf(whole)).to.equal(2);
		expect(whole.status).to.equal(OutputStatus.CONFIRMED);
		expect(pair.backends.alice.refused).to.deep.equal([]);

		await passTo(pair, held.cltvExpiry - 1);
		await until('the HTLC-timeout in a block', pair, () =>
			[
				OutputStatus.SPEND_CONFIRMED,
				OutputStatus.IRREVOCABLY_RESOLVED
			].includes(htlcOf(pair.alice, pair)!.status)
		);
		const spent = htlcOf(pair.alice, pair)!;
		const timeout = confirmed(pair, spent.resolutionTxid);
		expect(timeout.height).to.be.greaterThan(held.cltvExpiry);
		expect(timeout.tx.ins.length).to.equal(2);
		// The output the peer signed for, and nothing beside it.
		expect(timeout.tx.outs.map((out) => out.value)).to.deep.equal([354]);
		expect(spent.auxiliaryData!.toString()).to.match(
			/^sweep:local:\d+:htlc_second_level_timeout:/
		);
		expect(spent.auxiliaryFeeRate).to.be.greaterThan(0);

		// Its output is this node's after the delay, by the leaf the round
		// signed, and its sweep builds on the asset side of the transaction
		// that made it.
		const second = secondLevelOf(pair.alice, pair)!;
		expect(second.txid).to.equal(spent.resolutionTxid);
		expect(second.auxiliaryParentData!.equals(spent.auxiliaryData!)).to.equal(
			true
		);
		expect(second.auxiliaryHtlc).to.deep.equal({
			id: spent.htlcId,
			direction: 'OFFERED'
		});
		await passTo(pair, (second.maturityHeight ?? pair.chain.height) - 1);
		await until('the sweep of the second-level output in a block', pair, () =>
			[
				OutputStatus.SPEND_CONFIRMED,
				OutputStatus.IRREVOCABLY_RESOLVED
			].includes(secondLevelOf(pair.alice, pair)!.status)
		);
		const swept = secondLevelOf(pair.alice, pair)!;
		const sweep = confirmed(pair, swept.resolutionTxid);
		expect(sweep.tx.outs.map((out) => out.value)).to.deep.equal([354]);
		expect(sweep.tx.outs[0].script.equals(ASSET_SWEEP_SCRIPT)).to.equal(true);
		expect(swept.auxiliaryData!.toString()).to.match(
			/^sweep:local:\d+:second_level_delayed:/
		);
		const kinds = pair.sweeps.alice.map((call) => call.kinds.join());
		expect(kinds).to.include('htlc_second_level_timeout');
		expect(kinds).to.include('second_level_delayed');
		monitorRoundTrips(pair.alice, pair.channelId, [
			'auxiliaryHtlc',
			'auxiliaryParentData',
			'auxiliaryFeeRate',
			'auxiliaryFeeActionOpen'
		]);
		expect(pair.backends.alice.refused).to.deep.equal([]);
		expect(
			errorsOf(pair.alice).filter((e) => !e.includes('waits for'))
		).to.deep.equal([]);
		// What each transaction weighs, with its one fee input.
		expect(timeout.tx.virtualSize()).to.be.closeTo(238, 1);
		expect(sweep.tx.virtualSize()).to.be.closeTo(206, 1);
	});

	it('claims by preimage an HTLC it received, on its own commitment, when the settlement was owed: commitment in block h, claim in block h+2, and the payer learns the preimage from the chain', async () => {
		const pair = await world.open('aux-htlc-success', {
			feeWallet: { alice: true, bob: true },
			hooks
		});
		for (const wallet of [pair.wallets.alice!, pair.wallets.bob!]) {
			wallet.fund(100_000);
			wallet.fund(100_000);
		}
		await world.mine(pair, 1);
		const held = await holdUnits(pair, 5000n, 'success');

		// Bob decides to settle while Alice cannot be reached: the fulfil is
		// owed, and Bob goes to the chain for it.
		disconnect(pair);

		// The settle binds though the fulfil cannot leave: false says the
		// part is still parked, and the preimage is with the monitors.
		expect(
			pair.bob.node.settleHeldHtlc(held.paymentHash, held.preimage)
		).to.equal(false);

		await settle();
		const closed = pair.bob.node.forceCloseChannel(
			pair.channelId,
			SWEEP_DESTINATION
		);
		expect(closed.ok, closed.error).to.equal(true);
		await settle();
		const waiting = htlcOf(pair.bob, pair)!;
		expect(waiting.outputType).to.equal(OutputType.RECEIVED_HTLC);
		expect(waiting.auxiliaryFeeWait).to.deep.include({
			code: 'FEE_PREPARATION_PENDING',
			remedy: 'wait',
			deadlineHeight: held.cltvExpiry
		});

		trace(pair, 'bob', 'closed');
		await world.mine(pair, 1);
		const h = pair.chain.height;
		trace(pair, 'bob', 'h');
		expect(confirmed(pair, closed.commitmentTxid).height).to.equal(h);
		await world.mine(pair, 1);
		trace(pair, 'bob', 'h+1');
		await world.mine(pair, 1);
		trace(pair, 'bob', 'h+2');
		const spent = htlcOf(pair.bob, pair)!;
		expect(spent.status).to.equal(OutputStatus.SPEND_CONFIRMED);
		const success = confirmed(pair, spent.resolutionTxid);
		expect(success.height).to.equal(h + 2);
		expect(success.tx.outs.map((out) => out.value)).to.deep.equal([354]);
		expect(spent.auxiliaryData!.toString()).to.match(
			/^sweep:local:\d+:htlc_second_level_success:/
		);
		expect(pair.backends.bob.refused).to.deep.equal([]);

		// Alice had asked for the fee input of her own claim by timeout; the
		// peer's transaction took the output, and she has the preimage of it.
		const lost = htlcOf(pair.alice, pair)!;
		expect(lost.outputType).to.equal(OutputType.OFFERED_HTLC);
		expect(lost.resolutionTxid).to.equal(spent.resolutionTxid);
		expect(pair.alice.node.getPayment(held.paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
		expect(success.tx.virtualSize()).to.be.closeTo(253, 1);
	});

	/** A pair whose two hosts each have a wallet with two coins in a block. */
	const opened = async (tag: string): Promise<IAssetChainPair> => {
		const pair = await world.open(tag, {
			feeWallet: { alice: true, bob: true },
			hooks
		});
		// Two coins each: the child that pays for a commitment takes one.
		for (const wallet of [pair.wallets.alice!, pair.wallets.bob!]) {
			wallet.fund(100_000);
			wallet.fund(100_000);
		}
		await world.mine(pair, 1);
		return pair;
	};
	/**
	 * What the chain would not take from a node, but for one thing master
	 * does on every channel: a balance output its own confirmed sweep spent
	 * is signed for again at another fee and offered to the chain, which
	 * says the output is spent.
	 */
	const refusedOf = (
		pair: IAssetChainPair,
		who: 'alice' | 'bob'
	): Array<{ txid: string; reason: string }> => {
		const own = trackedOutputs(pair[who], pair.channelId)
			.filter((output) =>
				[OutputType.TO_LOCAL, OutputType.TO_REMOTE].includes(output.outputType)
			)
			.map((output) => output.resolutionTxid)
			.filter((txid): txid is string => !!txid);
		return pair.backends[who].refused.filter(
			(refusal) =>
				!own.some((txid) =>
					refusal.reason.endsWith(`is already spent by ${txid}`)
				)
		);
	};
	const isSpent = (output: ITrackedOutput | undefined): boolean =>
		!!output &&
		[OutputStatus.SPEND_CONFIRMED, OutputStatus.IRREVOCABLY_RESOLVED].includes(
			output.status
		);
	/** What a transaction pays, from the outputs the chain has for its inputs. */
	const feeOf = (pair: IAssetChainPair, tx: bitcoin.Transaction): number =>
		tx.ins.reduce(
			(sum, input) =>
				sum +
				pair.chain.transaction(
					Buffer.from(input.hash).reverse().toString('hex')
				)!.outs[input.index].value,
			0
		) - tx.outs.reduce((sum, out) => sum + out.value, 0);

	it('claims by preimage, on the commitment of its peer, an HTLC it received whose hold invoice is settled after the force close', async () => {
		const pair = await opened('aux-htlc-claim-after');
		const held = await holdUnits(pair, 5000n, 'claim after');
		const closed = pair.alice.node.forceCloseChannel(
			pair.channelId,
			SWEEP_DESTINATION
		);
		expect(closed.ok, closed.error).to.equal(true);
		await settle();
		await world.mine(pair, 1);
		// The held HTLC is in a channel that is on the chain: it is left as
		// it is, with nothing signed for its output, until the hold ends.
		const kept = htlcOf(pair.bob, pair)!;
		expect(kept.outputType).to.equal(OutputType.RECEIVED_HTLC);
		expect(kept.sweepTxHex).to.equal(undefined);
		expect(kept.auxiliaryFeeWait).to.equal(undefined);

		pair.bob.node.settleHeldHtlc(held.paymentHash, held.preimage);
		await settle();
		trace(pair, 'bob', 'settled');
		await until('the claim of the payee in a block', pair, () =>
			isSpent(htlcOf(pair.bob, pair))
		);
		trace(pair, 'bob', 'claimed');
		const spent = htlcOf(pair.bob, pair)!;
		const claim = confirmed(pair, spent.resolutionTxid);
		expect(claim.height).to.be.at.most(held.cltvExpiry);
		expect(claim.tx.outs.map((out) => out.value)).to.deep.equal([354]);
		expect(claim.tx.outs[0].script.equals(ASSET_SWEEP_SCRIPT)).to.equal(true);
		expect(spent.auxiliaryData!.toString()).to.match(
			/^sweep:remote:\d+:htlc_success:/
		);
		expect(pair.backends.bob.refused).to.deep.equal([]);
		expect(pair.alice.node.getPayment(held.paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
		expect(claim.tx.virtualSize()).to.be.closeTo(228, 1);

		// The ending is told at irrevocable depth, to the host of each side,
		// and the hold invoice ends paid with nothing parked.
		expect(parkedOf(pair.bob, held.paymentHash)).to.equal(1);
		expect(outcomes).to.deep.equal({ alice: [], bob: [] });
		await passTo(pair, pair.chain.height + IRREVOCABLE_DEPTH);
		await world.mine(pair, 2);
		await settle();
		expect(outcomes.bob).to.deep.equal(['RECEIVED:fulfilled:5000']);
		expect(outcomes.alice).to.deep.equal(['OFFERED:fulfilled:5000']);
		monitorRoundTrips(pair.bob, pair.channelId, ['auxiliaryOutcomeRecorded']);
		expect(parkedOf(pair.bob, held.paymentHash)).to.equal(0);
		expect(pair.bob.node.getPayment(held.paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
		for (const host of [pair.alice, pair.bob]) {
			expect(
				host.node.getAuxiliaryChannelInfo(pair.channelId)
					?.undeliveredOutcomes ?? 0
			).to.equal(0);
		}
		// Told once: later blocks bring nothing more.
		await world.mine(pair, 3);
		expect(outcomes.bob).to.have.length(1);
		expect(outcomes.alice).to.have.length(1);
	});

	it('claims by preimage, on the commitment of its peer, an HTLC whose hold invoice was settled before the force close: first heard of in block h, the split is in block h+1 and the claim in block h+2', async () => {
		const pair = await opened('aux-htlc-claim-before');
		const held = await holdUnits(pair, 5000n, 'claim before');
		disconnect(pair);
		// A channel whose peer is gone is not in its normal state: the
		// force close at the claim deadline is not held back for it.
		expect(
			pair.bob.node
				.getChannelManager()
				.getChannel(pair.channelId)!
				.getFullState().state
		).to.not.equal(ChannelState.NORMAL);
		expect(
			pair.bob.node.settleHeldHtlc(held.paymentHash, held.preimage)
		).to.equal(false);
		await settle();
		// Bob hears nothing of the chain until the commitment is in a block.
		pair.backends.bob.hold();
		const closed = pair.alice.node.forceCloseChannel(
			pair.channelId,
			SWEEP_DESTINATION
		);
		expect(closed.ok, closed.error).to.equal(true);
		await settle();
		await world.mine(pair, 1);
		const h = pair.chain.height;
		expect(confirmed(pair, closed.commitmentTxid).height).to.equal(h);
		expect(pair.wallets.bob!.sent).to.have.length(0);
		pair.backends.bob.release();
		await settle();
		for (let i = 0; i < 20 && pair.wallets.bob!.sent.length === 0; i++) {
			await settle();
		}
		trace(pair, 'bob', 'h');
		expect(htlcOf(pair.bob, pair)!.auxiliaryFeeWait).to.deep.include({
			code: 'FEE_PREPARATION_PENDING',
			remedy: 'wait',
			sinceHeight: h,
			deadlineHeight: held.cltvExpiry
		});
		await world.mine(pair, 1);
		trace(pair, 'bob', 'h+1');
		expect(confirmed(pair, pair.wallets.bob!.sent[0].txid).height).to.equal(
			h + 1
		);
		await world.mine(pair, 1);
		trace(pair, 'bob', 'h+2');
		const spent = htlcOf(pair.bob, pair)!;
		expect(isSpent(spent)).to.equal(true);
		const claim = confirmed(pair, spent.resolutionTxid);
		expect(claim.height).to.equal(h + 2);
		expect(spent.auxiliaryData!.toString()).to.match(
			/^sweep:remote:\d+:htlc_success:/
		);
		expect(pair.backends.bob.refused).to.deep.equal([]);
	});

	it('takes back by timeout, on the commitment of its peer, an HTLC it offered', async () => {
		const pair = await opened('aux-htlc-timeout-theirs');
		const held = await holdUnits(pair, 5000n, 'timeout theirs');
		const closed = pair.bob.node.forceCloseChannel(
			pair.channelId,
			SWEEP_DESTINATION
		);
		expect(closed.ok, closed.error).to.equal(true);
		await settle();
		await world.mine(pair, 2);
		trace(pair, 'alice', 'h+1');
		const whole = htlcOf(pair.alice, pair)!;
		expect(whole.outputType).to.equal(OutputType.OFFERED_HTLC);
		expect(inputsOf(whole)).to.equal(2);
		expect(whole.status).to.equal(OutputStatus.CONFIRMED);
		await passTo(pair, held.cltvExpiry - 1);
		await until('the claim by timeout in a block', pair, () =>
			isSpent(htlcOf(pair.alice, pair))
		);
		const spent = htlcOf(pair.alice, pair)!;
		const claim = confirmed(pair, spent.resolutionTxid);
		expect(claim.height).to.be.greaterThan(held.cltvExpiry);
		expect(claim.tx.outs.map((out) => out.value)).to.deep.equal([354]);
		expect(claim.tx.outs[0].script.equals(ASSET_SWEEP_SCRIPT)).to.equal(true);
		expect(spent.auxiliaryData!.toString()).to.match(
			/^sweep:remote:\d+:htlc_timeout:/
		);
		expect(refusedOf(pair, 'alice')).to.deep.equal([]);
		if (process.env.AUX_TRACE) {
			// eslint-disable-next-line no-console
			console.log(`[size] htlc_timeout ${claim.tx.virtualSize()}`);
		}
		expect(claim.tx.virtualSize()).to.be.closeTo(215, 1);

		// The HTLC failed for both. The payee, who decided nothing and so
		// will not claim, was told when the expiry passed: its commitment
		// was there for good by then. The payer is told when its timeout
		// is. The payment ends failed and the hold invoice cancelled.
		expect(outcomes).to.deep.equal({
			alice: [],
			bob: ['RECEIVED:failed:5000']
		});
		await passTo(pair, pair.chain.height + IRREVOCABLE_DEPTH);
		await world.mine(pair, 2);
		await settle();
		expect(outcomes.alice).to.deep.equal(['OFFERED:failed:5000']);
		expect(outcomes.bob).to.deep.equal(['RECEIVED:failed:5000']);
		expect(pair.alice.node.getPayment(held.paymentHash)!.status).to.equal(
			PaymentStatus.FAILED
		);
		expect(parkedOf(pair.bob, held.paymentHash)).to.equal(0);
		expect(pair.bob.node.getPayment(held.paymentHash)?.status).to.not.equal(
			PaymentStatus.COMPLETED
		);
	});

	it('says what its claim waits for while its wallet has no coin, goes on when one arrives, and finishes after a restart between the split and the claim', async () => {
		const pair = await world.open('aux-htlc-restart', {
			feeWallet: { alice: true },
			hooks
		});
		const held = await holdUnits(pair, 5000n, 'restart');
		const closed = pair.alice.node.forceCloseChannel(
			pair.channelId,
			SWEEP_DESTINATION
		);
		expect(closed.ok, closed.error).to.equal(true);
		await settle();
		await world.mine(pair, 1);
		const since = pair.chain.height;
		trace(pair, 'alice', 'no coin');
		const first = htlcOf(pair.alice, pair)!.auxiliaryFeeWait!;
		expect(first).to.deep.include({
			code: 'FEE_FUNDS_UNAVAILABLE',
			remedy: 'operator'
		});
		expect(first.sinceHeight).to.be.at.most(since);
		await world.mine(pair, 2);
		expect(htlcOf(pair.alice, pair)!.auxiliaryFeeWait).to.deep.equal(first);
		expect(
			errorsOf(pair.alice).filter((e) => e.includes('FEE_FUNDS_UNAVAILABLE'))
		).to.have.length(1);

		// A coin arrives: the pool splits it on the next block.
		pair.wallets.alice!.fund(100_000);
		await world.mine(pair, 1);
		for (let i = 0; i < 20 && pair.wallets.alice!.sent.length === 0; i++) {
			await settle();
		}
		trace(pair, 'alice', 'coin');
		expect(htlcOf(pair.alice, pair)!.auxiliaryFeeWait).to.deep.include({
			code: 'FEE_PREPARATION_PENDING',
			remedy: 'wait',
			sinceHeight: first.sinceHeight
		});
		expect(pair.wallets.alice!.sent).to.have.length(1);

		await world.restartAlice(pair, 'aux-htlc-restart');
		await world.mine(pair, 2);
		trace(pair, 'alice', 'restarted');
		const whole = htlcOf(pair.alice, pair)!;
		expect(whole.auxiliaryFeeWait).to.equal(undefined);
		expect(inputsOf(whole)).to.equal(2);
		// The same split served: nothing more left the wallet.
		expect(pair.wallets.alice!.sent).to.have.length(1);
		await passTo(pair, held.cltvExpiry - 1);
		await until('the HTLC-timeout in a block', pair, () =>
			isSpent(htlcOf(pair.alice, pair))
		);
		const timeout = confirmed(pair, htlcOf(pair.alice, pair)!.resolutionTxid);
		expect(timeout.tx.outs.map((out) => out.value)).to.deep.equal([354]);
		expect(pair.backends.alice.refused).to.deep.equal([]);
	});

	it('raises the fee of a second-level transaction that does not confirm: the pool is asked again naming the inputs it replaces, and the asset side of each transaction is kept', async () => {
		const pair = await opened('aux-htlc-raise');
		const held = await holdUnits(pair, 5000n, 'raise');
		const closed = pair.alice.node.forceCloseChannel(
			pair.channelId,
			SWEEP_DESTINATION
		);
		expect(closed.ok, closed.error).to.equal(true);
		await settle();
		await world.mine(pair, 2);
		const outpoint = htlcOf(pair.alice, pair)!;
		expect(inputsOf(outpoint)).to.equal(2);
		// From here the chain is not told of what spends the HTLC output.
		const publish = pair.backends.alice.broadcastTransaction.bind(
			pair.backends.alice
		);
		const lost: string[] = [];
		pair.backends.alice.broadcastTransaction = async (
			hex: string
		): Promise<string> => {
			const tx = bitcoin.Transaction.fromHex(hex);
			const spendsHtlc =
				Buffer.from(tx.ins[0].hash).reverse().toString('hex') ===
					outpoint.txid && tx.ins[0].index === outpoint.outputIndex;
			if (!spendsHtlc) return publish(hex);
			if (!lost.includes(hex)) lost.push(hex);
			return tx.getId();
		};
		await passTo(pair, held.cltvExpiry - 1);
		await until(
			'a second transaction for the HTLC output',
			pair,
			() => lost.length >= 2,
			24
		);
		trace(pair, 'alice', 'raised');
		const [first, second] = lost.map((hex) => bitcoin.Transaction.fromHex(hex));
		expect(second.getId()).to.not.equal(first.getId());
		expect(feeOf(pair, second)).to.be.greaterThan(feeOf(pair, first));
		for (const tx of [first, second]) {
			expect(tx.outs.map((out) => out.value)).to.deep.equal([354]);
		}
		const attempts = htlcOf(pair.alice, pair)!.auxiliarySweepAttempts!;
		expect(Object.keys(attempts)).to.include.members([
			first.getId(),
			second.getId()
		]);
		expect(
			attempts[first.getId()].auxiliaryData!.equals(
				attempts[second.getId()].auxiliaryData!
			)
		).to.equal(false);
		// The raised one reaches the chain and confirms.
		await publish(lost[1]);
		await world.mine(pair, 1);
		const spent = htlcOf(pair.alice, pair)!;
		expect(spent.resolutionTxid).to.equal(second.getId());
		expect(
			spent.auxiliaryData!.equals(attempts[second.getId()].auxiliaryData!)
		).to.equal(true);
		expect(secondLevelOf(pair.alice, pair)!.txid).to.equal(second.getId());
	});

	it('claims what its lifetime fee budget allows and says which claim waits for the operator when the budget is used up', async () => {
		const pair = await world.open('aux-htlc-budget', {
			feeWallet: {
				alice: {
					maxFeeSatoshis: 4_000n,
					maxPreparationFeeSatoshis: 1_000n,
					maxTotalFeeSatoshis: 6_000n
				}
			},
			hooks
		});
		pair.wallets.alice!.fund(100_000);
		pair.wallets.alice!.fund(100_000);
		await world.mine(pair, 1);
		await holdUnits(pair, 3000n, 'budget one');
		await holdUnits(pair, 2000n, 'budget two');
		const closed = pair.alice.node.forceCloseChannel(
			pair.channelId,
			SWEEP_DESTINATION
		);
		expect(closed.ok, closed.error).to.equal(true);
		await settle();
		await world.mine(pair, 3);
		trace(pair, 'alice', 'budget');
		const htlcs = trackedOutputs(pair.alice, pair.channelId).filter(
			(output) => output.outputType === OutputType.OFFERED_HTLC
		);
		expect(htlcs).to.have.length(2);
		expect(htlcs.map(inputsOf).sort()).to.deep.equal([1, 2]);
		const waiting = htlcs.find((output) => inputsOf(output) === 1)!;
		expect(waiting.auxiliaryFeeWait).to.deep.include({
			code: 'FEE_BUDGET_EXHAUSTED',
			remedy: 'operator'
		});
		await world.mine(pair, 3);
		// Still asked for on every block, and said once.
		expect(
			errorsOf(pair.alice).filter((e) => e.includes('FEE_BUDGET_EXHAUSTED'))
		).to.have.length(1);
		expect(pair.backends.alice.refused).to.deep.equal([]);
	});

	it('claims by preimage, on its own commitment, an HTLC whose hold invoice is settled after its force close: until the fee input is attached its output is not said to be spent', async () => {
		const pair = await opened('aux-htlc-own-after');
		const held = await holdUnits(pair, 5000n, 'own after');
		const closed = pair.bob.node.forceCloseChannel(
			pair.channelId,
			SWEEP_DESTINATION
		);
		expect(closed.ok, closed.error).to.equal(true);
		await settle();
		await world.mine(pair, 1);
		const kept = htlcOf(pair.bob, pair)!;
		expect(kept.outputType).to.equal(OutputType.RECEIVED_HTLC);
		expect(kept.status).to.equal(OutputStatus.CONFIRMED);
		expect(kept.auxiliaryFeeWait).to.equal(undefined);

		pair.bob.node.settleHeldHtlc(held.paymentHash, held.preimage);
		await settle();
		for (let i = 0; i < 20 && pair.wallets.bob!.sent.length === 0; i++) {
			await settle();
		}
		trace(pair, 'bob', 'own settled');
		const waiting = htlcOf(pair.bob, pair)!;
		expect(waiting.status).to.equal(OutputStatus.CONFIRMED);
		expect(inputsOf(waiting)).to.equal(1);
		expect(waiting.auxiliaryFeeWait).to.deep.include({
			code: 'FEE_PREPARATION_PENDING',
			remedy: 'wait',
			deadlineHeight: held.cltvExpiry
		});
		await until('the HTLC-success in a block', pair, () =>
			isSpent(htlcOf(pair.bob, pair))
		);
		trace(pair, 'bob', 'own claimed');
		const spent = htlcOf(pair.bob, pair)!;
		const success = confirmed(pair, spent.resolutionTxid);
		expect(success.height).to.be.at.most(held.cltvExpiry);
		expect(success.tx.outs.map((out) => out.value)).to.deep.equal([354]);
		expect(spent.auxiliaryData!.toString()).to.match(
			/^sweep:local:\d+:htlc_second_level_success:/
		);
		expect(refusedOf(pair, 'bob')).to.deep.equal([]);
		expect(pair.alice.node.getPayment(held.paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
	});

	for (const scenario of [
		{
			name: 'a hold invoice the host never decided',
			tag: 'undecided',
			cancel: false
		},
		{
			name: 'a hold invoice the host cancelled while the fail back could not leave',
			tag: 'cancelled',
			cancel: true
		}
	]) {
		it(`does not claim an HTLC of ${scenario.name}, though a preimage for its hash is stored: the payer takes it back and the host is told it failed`, async () => {
			const pair = await opened(`aux-htlc-${scenario.tag}`);
			const held = await holdUnits(pair, 5000n, scenario.tag);
			if (scenario.cancel) {
				disconnect(pair);
				pair.bob.node.cancelHoldInvoice(held.paymentHash);
				await settle();
			}
			// A preimage in the store is not a decision to settle: one that
			// an earlier settle left behind, say.
			pair.bob.node
				.getChannelManager()
				.recordPreimage(held.paymentHash, held.preimage);
			const closed = pair.alice.node.forceCloseChannel(
				pair.channelId,
				SWEEP_DESTINATION
			);
			expect(closed.ok, closed.error).to.equal(true);
			await settle();
			await world.mine(pair, 3);
			trace(pair, 'bob', scenario.tag);
			const kept = htlcOf(pair.bob, pair)!;
			expect(kept.outputType).to.equal(OutputType.RECEIVED_HTLC);
			expect(kept.status).to.equal(OutputStatus.CONFIRMED);
			expect(kept.sweepTxHex).to.equal(undefined);
			expect(kept.auxiliaryFeeWait).to.equal(undefined);
			// No fee input was asked for: nothing left Bob's wallet.
			expect(pair.wallets.bob!.sent).to.have.length(0);

			// Block by block through the margin at which a hold is given up
			// and past the expiry: once the channel is on chain nothing is
			// asked of it, neither a fail back nor a fulfil.
			await passTo(pair, held.cltvExpiry - 30);
			await world.mine(pair, 29);
			await until('the HTLC-timeout of the payer in a block', pair, () =>
				isSpent(htlcOf(pair.alice, pair))
			);
			const taken = htlcOf(pair.bob, pair)!;
			expect(taken.resolutionTxid).to.equal(
				htlcOf(pair.alice, pair)!.resolutionTxid
			);
			expect(pair.wallets.bob!.sent).to.have.length(0);
			await passTo(pair, pair.chain.height + IRREVOCABLE_DEPTH);
			await world.mine(pair, 2);
			await settle();
			// The one refusal is the host's own cancel, made before the channel
			// was on chain while the peer was gone.
			const asked = errorsOf(pair.bob).filter((e) =>
				/Cannot (fail|fulfill) HTLC/.test(e)
			);
			expect(asked.length, asked.slice(0, 3).join(' | ')).to.equal(
				scenario.cancel ? 1 : 0
			);
			expect(outcomes.bob).to.deep.equal(['RECEIVED:failed:5000']);
			expect(outcomes.alice).to.deep.equal(['OFFERED:failed:5000']);
			expect(parkedOf(pair.bob, held.paymentHash)).to.equal(0);
			expect(pair.bob.node.getPayment(held.paymentHash)?.status).to.not.equal(
				PaymentStatus.COMPLETED
			);
			expect(pair.alice.node.getPayment(held.paymentHash)!.status).to.equal(
				PaymentStatus.FAILED
			);
		});
	}
	it('does not claim a later HTLC of the payment hash of a hold invoice that was cancelled, though a preimage for the hash is stored: the payer takes it back and both hosts are told it failed', async function () {
		const pair = await opened('aux-htlc-later');
		const held = await holdUnits(pair, 5000n, 'later');
		// A preimage in the store is not a decision to settle: here it is
		// there from the time of the hold, which is then cancelled. Its
		// HTLC fails back, all of it, and both hosts are told.
		const store = pair.bob.node.getChannelManager();
		store.recordPreimage(held.paymentHash, held.preimage);
		pair.bob.node.cancelHoldInvoice(held.paymentHash);
		await settle();
		expect(outcomes).to.deep.equal({
			alice: ['OFFERED:failed:5000'],
			bob: ['RECEIVED:failed:5000']
		});
		expect(parkedOf(pair.bob, held.paymentHash)).to.equal(0);

		// A second HTLC of the same payment hash. Bob refuses it, and his
		// fail back is kept from Alice, so it stays in both commitments.
		let failing = false;
		const gate = gateMessages(pair, 'bob', (type) => {
			if (type === UPDATE_FAIL_HTLC || type === UPDATE_FAIL_MALFORMED_HTLC) {
				failing = true;
			}
			return failing;
		});
		await offerUnitsAgain(pair, 5000n, held.paymentHash, held.paymentSecret);
		expect(gate.kept.length, 'the fail back was kept').to.be.greaterThan(0);
		const later = [
			...pair.bob.node
				.getChannelManager()
				.getChannel(pair.channelId)!
				.getFullState()
				.htlcs.values()
		].filter((entry) => entry.paymentHash.equals(held.paymentHash));
		expect(later).to.have.length(1);
		expect(later[0].id).to.equal(1n);
		expect(parkedOf(pair.bob, held.paymentHash)).to.equal(0);
		store.recordPreimage(held.paymentHash, held.preimage);

		gateMessages(pair, 'alice', () => true);
		const closed = pair.alice.node.forceCloseChannel(
			pair.channelId,
			SWEEP_DESTINATION
		);
		expect(closed.ok, closed.error).to.equal(true);
		await settle();
		await world.mine(pair, 3);
		trace(pair, 'bob', 'later');
		const kept = htlcOf(pair.bob, pair)!;
		expect(kept.outputType).to.equal(OutputType.RECEIVED_HTLC);
		expect(kept.htlcId).to.equal(1n);
		expect(kept.status).to.equal(OutputStatus.CONFIRMED);
		expect(kept.sweepTxHex).to.equal(undefined);
		expect(kept.auxiliaryFeeWait).to.equal(undefined);
		// No fee input was asked for: nothing left Bob's wallet.
		expect(pair.wallets.bob!.sent).to.have.length(0);

		await passTo(pair, later[0].cltvExpiry - 30);
		await world.mine(pair, 29);
		await until('the HTLC-timeout of the payer in a block', pair, () =>
			isSpent(htlcOf(pair.alice, pair))
		);
		expect(htlcOf(pair.bob, pair)!.resolutionTxid).to.equal(
			htlcOf(pair.alice, pair)!.resolutionTxid
		);
		expect(pair.wallets.bob!.sent).to.have.length(0);
		await passTo(pair, pair.chain.height + IRREVOCABLE_DEPTH);
		await world.mine(pair, 2);
		await settle();
		expect(outcomes).to.deep.equal({
			alice: ['OFFERED:failed:5000', 'OFFERED:failed:5000'],
			bob: ['RECEIVED:failed:5000', 'RECEIVED:failed:5000']
		});
		expect(pair.bob.node.getPayment(held.paymentHash)?.status).to.not.equal(
			PaymentStatus.COMPLETED
		);
		expect(pair.alice.node.getPayment(held.paymentHash)!.status).to.equal(
			PaymentStatus.FAILED
		);
	});

	it('closes by itself 18 blocks before the expiry of an HTLC whose settlement could not leave, and has its claim in a block with blocks to spare', async () => {
		const pair = await opened('aux-htlc-deadline');
		const held = await holdUnits(pair, 5000n, 'deadline');
		disconnect(pair);
		expect(
			pair.bob.node.settleHeldHtlc(held.paymentHash, held.preimage)
		).to.equal(false);
		await settle();
		// The node force closes on its own 18 blocks before the expiry.
		const deadline = held.cltvExpiry - 18;
		// While the payer is away the bound settle is not tried again on
		// every block: what the first try said is all that is said.
		const refusals = (): number =>
			errorsOf(pair.bob).filter((error) =>
				/Cannot (fail|fulfill) HTLC/.test(error)
			).length;
		const saidOnce = refusals();
		expect(saidOnce).to.be.at.most(1);
		await world.mine(pair, 8);
		expect(refusals()).to.equal(saidOnce);
		expect(parkedOf(pair.bob, held.paymentHash)).to.equal(1);
		await passTo(pair, deadline - 2);
		await world.mine(pair, 1);
		expect(pair.chain.height).to.equal(deadline - 1);
		expect(htlcOf(pair.bob, pair), 'still open').to.equal(undefined);
		await until(
			'bob closes the channel by itself',
			pair,
			() => htlcOf(pair.bob, pair)?.status !== undefined,
			6
		);
		const tracked = htlcOf(pair.bob, pair)!;
		await until(
			'the claim in a block',
			pair,
			() => htlcOf(pair.bob, pair)!.status === OutputStatus.SPEND_CONFIRMED,
			10
		);
		const commitment = confirmed(pair, tracked.txid);
		const claim = confirmed(pair, htlcOf(pair.bob, pair)!.resolutionTxid);
		if (process.env.AUX_TRACE) {
			console.log(
				`deadline case: expiry ${held.cltvExpiry}, deadline ${deadline}, commitment in ${commitment.height}, claim in ${claim.height}`
			);
		}
		expect(commitment.height).to.equal(DEADLINE_COMMITMENT + deadline);
		expect(claim.height).to.equal(commitment.height + 2);
		expect(held.cltvExpiry - claim.height).to.equal(DEADLINE_SPARE);
		expect(claim.tx.ins.length).to.equal(2);
		expect(htlcOf(pair.bob, pair)!.auxiliaryData!.toString()).to.match(
			/^sweep:local:\d+:htlc_second_level_success:/
		);
	});
});
