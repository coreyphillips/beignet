/**
 * Asset channels (issue #2093): a fee action opened for an output of a
 * commitment that was seen in the mempool, when another commitment is
 * confirmed in its place.
 *
 * The output it was opened for never comes to exist. Once the commitment
 * that confirmed is settled for good the action is retired: it is charged
 * nothing and its coins go back to the pool, without a restart and after
 * one.
 */

import * as bitcoin from 'bitcoinjs-lib';
import { expect } from 'chai';
import {
	CommitmentType,
	IRREVOCABLE_DEPTH
} from '../../src/lightning/chain/types';
import type { WalletFundingProvider } from '../../src/lightning/wallet/wallet-funding-provider';
import { withAssetOpens, type IAssetHost } from './helpers/auxiliary-nodes';
import {
	assetChainWorld,
	payUnits,
	settle,
	trackedOutputs
} from './helpers/auxiliary-on-chain';

describe('asset channels: a fee action of a commitment that did not confirm', function () {
	this.timeout(240_000);
	withAssetOpens();
	const world = assetChainWorld();
	afterEach(() => world.dispose());
	const valueIncomingHtlc = (context: { auxiliaryAmount?: bigint }): bigint =>
		(context.auxiliaryAmount ?? 0n) * 1000n;
	const poolOf = (host: IAssetHost): WalletFundingProvider =>
		(host.node as unknown as { fundingProvider: WalletFundingProvider })
			.fundingProvider;

	it('is retired, charged nothing, once the commitment that confirmed in its place is settled for good', async () => {
		const tag = 'fee-orphan-action';
		// The cheater, Bob, holds 354 sat beside his units: the penalty of
		// his balance output takes its fee from the pool.
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
		const keep = (): bitcoin.Transaction => {
			const plan = channel.prepareForceClose(channel.getSigner()!);
			if (!plan.ok) throw new Error(plan.error);
			return bitcoin.Transaction.fromBuffer(plan.commitmentTx);
		};
		// Two commitments Bob keeps, both revoked by the payments after them.
		const first = keep();
		await payUnits(pair, 100n);
		const second = keep();
		await payUnits(pair, 100n);
		await payUnits(pair, 100n);
		expect(first.getId()).to.not.equal(second.getId());

		// The first is seen in the mempool: the pool is asked for its penalty.
		await pair.backends.bob.broadcastTransaction(first.toHex());
		await settle();
		for (let i = 0; i < 10; i++) await settle();
		const opened = poolOf(alice).getFixedOutputFeeActionIds(channelId);
		expect(opened.length).to.equal(1);
		expect(opened[0]).to.include(first.getId());

		// The second confirms in its place (it outbids the first).
		for (const entry of pair.chain.mempool.values()) {
			if (
				entry.tx.getId() === first.getId() ||
				entry.tx.ins.some(
					(input) =>
						Buffer.from(input.hash).reverse().toString('hex') === first.getId()
				)
			) {
				entry.fee = 0;
			}
		}
		pair.chain.mine(second);
		await settle();
		expect(pair.chain.confirmed.has(second.getId())).to.equal(true);
		expect(pair.chain.confirmed.has(first.getId())).to.equal(false);
		for (let i = 0; i < 4; i++) await world.mine(pair, 1);
		expect(
			alice.node.getChannelMonitorState(channelId)!.commitmentBroadcast
		).to.include({
			txid: second.getId(),
			commitmentType: CommitmentType.THEIR_REVOKED_COMMITMENT
		});
		// Everything of the commitment that confirmed is taken.
		const tracked = trackedOutputs(alice, channelId);
		expect(tracked.every((output) => output.txid !== first.getId())).to.equal(
			true
		);

		// The commitment that confirmed is settled for good: the action of
		// the other is retired with the rest, and nothing stays held.
		pair.chain.advance(IRREVOCABLE_DEPTH + 2);
		await settle();
		for (let i = 0; i < 4; i++) await world.mine(pair, 1);
		for (let i = 0; i < 20; i++) await settle();
		expect(poolOf(alice).getFixedOutputFeeActionIds(channelId)).to.deep.equal(
			[]
		);
		const budget = poolOf(alice).getFixedOutputFeeBudget()!;
		expect(budget.reservedSatoshis).to.equal(0n);
		// Charged the splits and the penalties that confirmed, far under one
		// cap: the action of the commitment that did not confirm cost nothing.
		expect(Number(budget.spentSatoshis)).to.be.below(20_000);

		await world.restartAlice(pair, tag);
		for (let i = 0; i < 3; i++) await world.mine(pair, 1);
		for (let i = 0; i < 20; i++) await settle();
		expect(
			poolOf(pair.alice).getFixedOutputFeeActionIds(channelId)
		).to.deep.equal([]);
		expect(
			poolOf(pair.alice).getFixedOutputFeeBudget()!.reservedSatoshis
		).to.equal(0n);
	});
});
