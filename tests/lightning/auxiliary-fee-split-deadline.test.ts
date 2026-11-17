/**
 * Asset channels (issue #2093): a claim by preimage that waits for a fee
 * coin, and the deadline it has.
 *
 * The payee has made its fulfil, the payer has the preimage and does not
 * answer, and the payee closes by itself before the expiry. Its claim needs
 * a fee coin, and the fee coin comes of a split of a wallet coin.
 *
 * The split pays the rate of the claim it is made for, and one that does
 * not confirm is replaced by one that pays more, sooner when the deadline
 * is near. A claim whose deadline is within a few blocks takes a coin of
 * the pool's own split before the split has confirmed, so the two are in
 * one block. And a wait that can no longer make the deadline stops reading
 * "wait", and the node says so once.
 */

import * as bitcoin from 'bitcoinjs-lib';
import { expect } from 'chai';
import {
	FIXED_OUTPUT_FEE_TIMING,
	OutputStatus,
	OutputType
} from '../../src/lightning/chain/types';
import type { ITrackedOutput } from '../../src/lightning/chain/types';
import { HtlcState } from '../../src/lightning/channel/types';
import { PaymentStatus } from '../../src/lightning/node/types';
import type { TestChainBackend } from './helpers/auxiliary-chain';
import { withAssetOpens, type IAssetHost } from './helpers/auxiliary-nodes';
import {
	assetChainWorld,
	errorsOf,
	holdUnits,
	settle,
	trackedOutputs,
	type IAssetChainPair
} from './helpers/auxiliary-on-chain';

type Waiting = { tx: bitcoin.Transaction; fee: number; vsize: number };

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

describe('asset channels: a claim by preimage that waits for a fee coin', function () {
	this.timeout(180000);
	withAssetOpens();
	const world = assetChainWorld();
	beforeEach(() => {
		outcomes.alice = [];
		outcomes.bob = [];
	});
	afterEach(() => world.dispose());

	const htlcOf = (
		host: IAssetHost,
		pair: IAssetChainPair
	): ITrackedOutput | undefined =>
		trackedOutputs(host, pair.channelId).find(
			(output) =>
				output.outputType === OutputType.OFFERED_HTLC ||
				output.outputType === OutputType.RECEIVED_HTLC
		);
	const isSpent = (output: ITrackedOutput | undefined): boolean =>
		!!output &&
		[OutputStatus.SPEND_CONFIRMED, OutputStatus.IRREVOCABLY_RESOLVED].includes(
			output.status
		);
	const lastRefusal = (host: IAssetHost): unknown =>
		(
			host.node.getFixedOutputFeeStatus() as
				| { lastRefusal?: unknown }
				| undefined
		)?.lastRefusal;
	const mempoolOf = (pair: IAssetChainPair): Map<string, Waiting> =>
		(pair.chain as unknown as { mempool: Map<string, Waiting> }).mempool;
	const outpointOf = (input: { hash: Buffer; index: number }): string =>
		`${Buffer.from(input.hash).reverse().toString('hex')}:${input.index}`;
	const rateOf = (pair: IAssetChainPair, raw: string): number => {
		const tx = bitcoin.Transaction.fromHex(raw);
		const paidIn = tx.ins.reduce(
			(sum, input) =>
				sum +
				pair.chain.transaction(
					Buffer.from(input.hash).reverse().toString('hex')
				)!.outs[input.index].value,
			0
		);
		const paidOut = tx.outs.reduce((sum, out) => sum + out.value, 0);
		return (paidIn - paidOut) / tx.virtualSize();
	};

	/**
	 * Blocks that take none of Bob's wallet's transactions paying `floor`
	 * sat/vB or less: those stay in the mempool, as a transaction below the
	 * rate of the day does.
	 */
	const mineAbove = async (
		pair: IAssetChainPair,
		blocks: number,
		floor: number
	): Promise<void> => {
		const mempool = mempoolOf(pair);
		for (let i = 0; i < blocks; i++) {
			const kept: Array<[string, Waiting]> = [];
			for (const sent of pair.wallets.bob!.sent) {
				const waiting = mempool.get(sent.txid);
				if (waiting && waiting.fee / waiting.vsize <= floor) {
					kept.push([sent.txid, waiting]);
					mempool.delete(sent.txid);
				}
			}
			pair.chain.mine();
			for (const [txid, waiting] of kept) mempool.set(txid, waiting);
			await settle();
		}
	};

	/**
	 * A held payment that Bob settles and Alice takes, after which Bob hears
	 * nothing more of her: she has the preimage and never signs the HTLC out
	 * of the commitment Bob holds.
	 */
	const stage = async (
		tag: string,
		bobHasCoins: boolean
	): Promise<{
		pair: IAssetChainPair;
		held: Awaited<ReturnType<typeof holdUnits>>;
	}> => {
		const pair = await world.open(tag, {
			feeWallet: { alice: true, bob: true },
			hooks
		});
		for (const wallet of [pair.wallets.alice!, pair.wallets.bob!]) {
			if (wallet === pair.wallets.bob && !bobHasCoins) continue;
			wallet.fund(100_000);
			wallet.fund(100_000);
		}
		await world.mine(pair, 1);
		const held = await holdUnits(pair, 5000n, tag);
		(
			pair.bob.node as unknown as { handlePeerMessage: unknown }
		).handlePeerMessage = (): undefined => undefined;
		pair.bob.node.settleHeldHtlc(held.paymentHash, held.preimage);
		await settle();
		expect(pair.alice.node.getPayment(held.paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
		const entry = [
			...pair.bob.node
				.getChannelManager()
				.getChannel(pair.channelId)!
				.getFullState()
				.htlcs.values()
		].find((e) => e.paymentHash.equals(held.paymentHash))!;
		expect(entry.state).to.equal(HtlcState.FULFILLED);
		return { pair, held };
	};

	it('makes its deadline though the split never confirms at the rate it first paid: the split pays the rate of the claim and is replaced by one that pays more', async () => {
		const { pair, held } = await stage('fee-split-deadline', true);
		const { alice, bob, chain } = pair;
		const deadline = held.cltvExpiry;
		const sent = pair.wallets.bob!.sent;

		chain.advance(deadline - 19 - chain.height);
		await settle();
		expect(htlcOf(bob, pair), 'still open').to.equal(undefined);
		// Bob closes by itself 18 blocks before the expiry, and no block
		// takes a split of his.
		for (let i = 0; i < 3 && sent.length === 0; i++) {
			await mineAbove(pair, 1, Infinity);
		}
		const askedAt = chain.height;
		const tracked = htlcOf(bob, pair)!;
		expect(tracked.outputType).to.equal(OutputType.RECEIVED_HTLC);
		expect(tracked.auxiliaryFeeWait).to.deep.include({
			code: 'FEE_PREPARATION_PENDING',
			remedy: 'wait',
			deadlineHeight: deadline
		});
		// The split is in the mempool at the rate of the claim it is for,
		// and says it may be replaced.
		expect(sent).to.have.length(1);
		const first = bitcoin.Transaction.fromHex(sent[0].raw);
		const firstRate = rateOf(pair, sent[0].raw);
		expect(tracked.originalFeeRate).to.equal(10);
		expect(firstRate).to.be.closeTo(tracked.originalFeeRate!, 0.5);
		expect(first.ins[0].sequence).to.equal(0xfffffffd);
		expect(mempoolOf(pair).has(sent[0].txid)).to.equal(true);

		// No block takes a split at that rate. With the deadline near, the
		// split is replaced after two blocks by one that pays more.
		while (chain.height < deadline && !isSpent(htlcOf(bob, pair))) {
			await mineAbove(pair, 1, firstRate + 1);
		}
		const claimed = htlcOf(bob, pair)!;
		expect(isSpent(claimed), 'claimed before the expiry').to.equal(true);
		expect(sent).to.have.length(2);
		expect(sent[1].refused).to.equal(undefined);
		const second = bitcoin.Transaction.fromHex(sent[1].raw);
		expect(outpointOf(second.ins[0])).to.equal(outpointOf(first.ins[0]));
		expect(rateOf(pair, sent[1].raw)).to.be.at.least(firstRate * 1.45);
		expect(chain.confirmed.has(sent[0].txid)).to.equal(false);
		expect(mempoolOf(pair).has(sent[0].txid)).to.equal(false);
		const splitHeight = chain.confirmed.get(sent[1].txid)!.height;
		expect(splitHeight - askedAt).to.be.at.most(
			FIXED_OUTPUT_FEE_TIMING.splitRaiseBlocksNearDeadline + 1
		);

		// The claim is Bob's own, it spends a fee coin of the replacement,
		// and it is in a block before the expiry.
		const claim = chain.confirmed.get(claimed.resolutionTxid!)!;
		expect(claim.height).to.be.below(deadline);
		expect(claim.tx.ins).to.have.length(2);
		expect(
			Buffer.from(claim.tx.ins[1].hash).reverse().toString('hex')
		).to.equal(sent[1].txid);
		expect(claimed.auxiliaryFeeWait).to.equal(undefined);
		expect(htlcOf(alice, pair)!.resolutionTxid).to.equal(claim.tx.getId());
		expect(
			outcomes.bob.filter((o) => o.startsWith('RECEIVED:failed'))
		).to.deep.equal([]);
		expect(errorsOf(bob).filter((e) => /deadline/i.test(e))).to.deep.equal([]);
	});

	it('is funded from the split it replaced when a block takes that one after all, and is charged the fee of that one', async () => {
		const { pair, held } = await stage('fee-split-first-wins', true);
		const { bob, chain } = pair;
		const deadline = held.cltvExpiry;
		const sent = pair.wallets.bob!.sent;

		chain.advance(deadline - 19 - chain.height);
		await settle();
		for (let i = 0; i < 6 && sent.length < 2; i++) {
			await mineAbove(pair, 1, Infinity);
		}
		expect(sent).to.have.length(2);
		const first = bitcoin.Transaction.fromHex(sent[0].raw);
		const firstFee =
			chain.transaction(
				Buffer.from(first.ins[0].hash).reverse().toString('hex')
			)!.outs[first.ins[0].index].value -
			first.outs.reduce((sum, out) => sum + out.value, 0);
		expect(mempoolOf(pair).has(sent[1].txid)).to.equal(true);
		expect(
			Number(
				pair.wallets.bob!.provider().getFixedOutputFeeBudget()!.spentSatoshis
			)
		).to.be.above(firstFee);

		// A miner that never saw the replacement takes the first split.
		const inner = chain as unknown as { spentBy: Map<string, string> };
		mempoolOf(pair).delete(sent[1].txid);
		for (const [point, by] of [...inner.spentBy]) {
			if (by === sent[1].txid) inner.spentBy.delete(point);
		}
		chain.mine(first);
		await settle();
		expect(chain.confirmed.has(sent[0].txid)).to.equal(true);

		// The claim takes a coin of the split that is in the block, and the
		// budget is charged what that split paid.
		chain.mine();
		await settle();
		const claimed = htlcOf(bob, pair)!;
		expect(isSpent(claimed)).to.equal(true);
		const claim = chain.confirmed.get(claimed.resolutionTxid!)!;
		expect(claim.height).to.be.below(deadline);
		expect(
			Buffer.from(claim.tx.ins[1].hash).reverse().toString('hex')
		).to.equal(sent[0].txid);
		expect(
			pair.wallets.bob!.provider().getFixedOutputFeeBudget()!.spentSatoshis
		).to.equal(BigInt(firstFee));
	});

	it('takes a coin of its own split before the split has confirmed when the deadline is within a few blocks: both are in the block of the deadline', async () => {
		const { pair, held } = await stage('fee-coin-unconfirmed', false);
		const { bob, chain } = pair;
		const deadline = held.cltvExpiry;
		const sent = pair.wallets.bob!.sent;

		chain.advance(deadline - 19 - chain.height);
		await settle();
		// Bob's wallet has no coin: the claim waits, and says by when.
		while (chain.height < deadline - 2) {
			chain.mine();
			await settle();
		}
		expect(htlcOf(bob, pair)!.auxiliaryFeeWait).to.deep.include({
			code: 'FEE_FUNDS_UNAVAILABLE',
			remedy: 'operator',
			deadlineHeight: deadline
		});
		expect(sent).to.have.length(0);

		// A coin arrives two blocks before the deadline. In the next block
		// the split goes out and the claim with it, on a coin of the split.
		pair.wallets.bob!.fund(100_000);
		chain.mine();
		await settle();
		expect(chain.height).to.equal(deadline - 1);
		expect(sent).to.have.length(1);
		const claim = bitcoin.Transaction.fromHex(htlcOf(bob, pair)!.sweepTxHex!);
		expect(claim.ins).to.have.length(2);
		expect(Buffer.from(claim.ins[1].hash).reverse().toString('hex')).to.equal(
			sent[0].txid
		);
		expect(mempoolOf(pair).has(sent[0].txid)).to.equal(true);
		expect(mempoolOf(pair).has(claim.getId())).to.equal(true);

		chain.mine();
		await settle();
		expect(chain.confirmed.get(sent[0].txid)!.height).to.equal(deadline);
		expect(chain.confirmed.get(claim.getId())!.height).to.equal(deadline);
		const claimed = htlcOf(bob, pair)!;
		expect(isSpent(claimed)).to.equal(true);
		expect(claimed.resolutionTxid).to.equal(claim.getId());
	});

	it('stops reading "wait" when waiting can no longer make the deadline, and says so once', async () => {
		const { pair, held } = await stage('fee-wait-deadline', true);
		const { bob, chain } = pair;
		const deadline = held.cltvExpiry;
		// Bob's wallet cannot reach the chain: its split is never sent.
		pair.wallets.bob!.attach(undefined as unknown as TestChainBackend);

		chain.advance(deadline - 19 - chain.height);
		await settle();
		while (chain.height < deadline - 1) {
			chain.mine();
			await settle();
		}
		expect(htlcOf(bob, pair)!.auxiliaryFeeWait).to.deep.include({
			code: 'FEE_PREPARATION_NOT_PUBLISHED',
			remedy: 'wait',
			deadlineHeight: deadline
		});
		const said = (): string[] =>
			errorsOf(bob).filter((e) => /deadline/i.test(e));
		expect(said()).to.deep.equal([]);
		expect(lastRefusal(bob)).to.deep.include({
			code: 'FEE_PREPARATION_NOT_PUBLISHED',
			remedy: 'wait',
			deadlineHeight: deadline
		});

		// The block of the deadline: the next one can take the payer's
		// timeout, so waiting is no remedy any more.
		chain.mine();
		await settle();
		const late = htlcOf(bob, pair)!.auxiliaryFeeWait!;
		expect(late).to.deep.include({
			code: 'FEE_PREPARATION_NOT_PUBLISHED',
			remedy: 'none',
			deadlineHeight: deadline
		});
		expect(late.message).to.include(`the deadline at height ${deadline}`);
		expect(said()).to.have.length(1);
		expect(said()[0]).to.include(`its deadline at height ${deadline}`);
		expect(lastRefusal(bob)).to.deep.include({
			remedy: 'none',
			deadlineHeight: deadline
		});
	});
});
