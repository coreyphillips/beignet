/**
 * Asset channels (issue #2093): what an open fee action holds against the
 * lifetime budget of the fee pool.
 *
 * An action holds its cap until it has fee coins. From then on it holds the
 * coins it has, which is what its spend can still pay, so a budget of a few
 * caps is not used up by spends that cost a small part of one. A revoked
 * commitment with more outputs to punish than the budget holds caps is
 * punished whole.
 */

import * as fs from 'fs';
import { expect } from 'chai';
import type Database from 'better-sqlite3';
import {
	CommitmentType,
	OutputStatus,
	OutputType,
	type ITrackedOutput
} from '../../src/lightning/chain/types';
import type { WalletFundingProvider } from '../../src/lightning/wallet/wallet-funding-provider';
import { withAssetOpens, type IAssetHost } from './helpers/auxiliary-nodes';
import {
	SWEEP_DESTINATION,
	assetChainWorld,
	holdUnits,
	settle,
	trackedOutputs,
	type IAssetChainPair
} from './helpers/auxiliary-on-chain';

describe('asset channels: what an open fee action holds against the lifetime budget', function () {
	this.timeout(240_000);
	withAssetOpens();
	const world = assetChainWorld();
	const kept: string[] = [];
	afterEach(() => {
		world.dispose();
		for (const file of kept.splice(0)) fs.rmSync(file, { force: true });
	});
	const valueIncomingHtlc = (context: { auxiliaryAmount?: bigint }): bigint =>
		(context.auxiliaryAmount ?? 0n) * 1000n;
	const poolOf = (host: IAssetHost): WalletFundingProvider =>
		(host.node as unknown as { fundingProvider: WalletFundingProvider })
			.fundingProvider;
	const done = [
		OutputStatus.SPEND_CONFIRMED,
		OutputStatus.IRREVOCABLY_RESOLVED
	];
	const htlcsOf = (
		host: IAssetHost,
		pair: IAssetChainPair,
		txid: string
	): ITrackedOutput[] =>
		trackedOutputs(host, pair.channelId).filter(
			(output) =>
				output.txid === txid &&
				(output.outputType === OutputType.OFFERED_HTLC ||
					output.outputType === OutputType.RECEIVED_HTLC)
		);

	it('punishes all three HTLC outputs of a revoked commitment under a budget of two caps: an action that has its fee coin holds that coin, not its cap', async () => {
		const tag = 'fee-budget-held';
		const pair = await world.open(tag, {
			feeWallet: {
				alice: true,
				// Two caps fit the lifetime budget, a third does not.
				bob: { maxFeeSatoshis: 20_000n, maxTotalFeeSatoshis: 50_000n }
			},
			hooks: { bob: { valueIncomingHtlc } }
		});
		const { bob, channelId } = pair;
		for (const wallet of [pair.wallets.alice!, pair.wallets.bob!]) {
			for (let i = 0; i < 4; i++) wallet.fund(100_000);
		}
		await world.mine(pair, 1);
		const held = [];
		for (const name of ['a', 'b', 'c']) {
			held.push(await holdUnits(pair, 1000n, `${tag} ${name}`, 40));
		}
		const stateOf = (): {
			localCommitmentNumber: bigint;
			htlcs: Map<string, unknown>;
		} =>
			pair.alice.node
				.getChannelManager()
				.getChannel(pair.channelId)!
				.getFullState();
		const number = stateOf().localCommitmentNumber;
		expect(stateOf().htlcs.size).to.equal(3);
		const copy = `${pair.alicePath}.kept`;
		kept.push(copy);
		(pair.alice.storage as unknown as { db: Database.Database }).db.exec(
			`VACUUM INTO '${copy}'`
		);
		for (const each of held) bob.node.cancelHoldInvoice(each.paymentHash);
		for (let i = 0; i < 40 && stateOf().htlcs.size > 0; i++) await settle();
		expect(stateOf().htlcs.size, 'the HTLCs failed back').to.equal(0);
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
		const txid = closed.commitmentTxid!;

		await world.mine(pair, 1);
		const h = pair.chain.height;
		expect(
			bob.node.getChannelMonitorState(channelId)!.commitmentBroadcast
		).to.include({
			txid,
			commitmentType: CommitmentType.THEIR_REVOKED_COMMITMENT
		});
		expect(htlcsOf(bob, pair, txid).length).to.equal(3);

		// Two blocks more: every penalty is in a block.
		for (let i = 0; i < 2; i++) await world.mine(pair, 1);
		const after = htlcsOf(bob, pair, txid);
		expect(
			after.filter((output) => done.includes(output.status)).length
		).to.equal(3);
		expect(after.map((output) => output.auxiliaryFeeWait)).to.deep.equal([
			undefined,
			undefined,
			undefined
		]);
		const penalties = after.map(
			(output) => pair.chain.confirmed.get(output.resolutionTxid!)!
		);
		const blocks = penalties.map((penalty) => penalty.height - h);
		// eslint-disable-next-line no-console
		if (process.env.AUX_TRACE) console.log(`[${tag}] blocks ${blocks}`);
		// All three are in the block after the commitment.
		expect(blocks).to.deep.equal([1, 1, 1]);

		// Each action holds the fee coin its penalty spent, and the three
		// together hold far less than one cap.
		const coins = penalties.map((penalty) => {
			expect(penalty.tx.ins).to.have.length(2);
			const input = penalty.tx.ins[1];
			return pair.chain.confirmed.get(
				Buffer.from(input.hash).reverse().toString('hex')
			)!.tx.outs[input.index].value;
		});
		const budget = poolOf(bob).getFixedOutputFeeBudget()!;
		expect(budget.totalSatoshis).to.equal(50_000n);
		expect(budget.reservedSatoshis).to.equal(
			BigInt(coins.reduce((sum, value) => sum + value, 0))
		);
		expect(Number(budget.reservedSatoshis)).to.be.below(20_000);
		expect(
			budget.reservedSatoshis + budget.spentSatoshis + budget.remainingSatoshis
		).to.equal(50_000n);
	});
});
