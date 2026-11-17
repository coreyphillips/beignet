/**
 * Asset channels (issue #2093): a claim whose spend is made and that only
 * waits for a fee coin.
 *
 * Nothing has left the node while the spend has no fee input, so there is
 * nothing to raise: the rate the pool is asked at stays the rate the spend
 * was made at, however long the wait, and the claim pays that rate once a
 * coin is there. The raise of a fee counts from a real broadcast.
 */

import * as bitcoin from 'bitcoinjs-lib';
import { expect } from 'chai';
import { OutputStatus, OutputType } from '../../src/lightning/chain/types';
import type { ITrackedOutput } from '../../src/lightning/chain/types';
import { withAssetOpens, type IAssetHost } from './helpers/auxiliary-nodes';
import {
	SWEEP_DESTINATION,
	assetChainWorld,
	holdUnits,
	settle,
	trackedOutputs,
	type IAssetChainPair
} from './helpers/auxiliary-on-chain';

const hooks = {
	bob: {
		valueIncomingHtlc: (context: { auxiliaryAmount?: bigint }): bigint =>
			context.auxiliaryAmount! * 1000n
	}
};

describe('asset channels: the rate of a claim that waits for a fee input', function () {
	this.timeout(120000);
	withAssetOpens();
	const world = assetChainWorld();
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
	const feeOf = (pair: IAssetChainPair, tx: bitcoin.Transaction): number =>
		tx.ins.reduce(
			(sum, input) =>
				sum +
				pair.chain.transaction(
					Buffer.from(input.hash).reverse().toString('hex')
				)!.outs[input.index].value,
			0
		) - tx.outs.reduce((sum, out) => sum + out.value, 0);

	/** Bob holds an HTLC, Alice's commitment is in a block, and Bob settles. */
	const settledAfterClose = async (
		tag: string,
		policy: Record<string, bigint> | true
	): Promise<{
		pair: IAssetChainPair;
		held: { paymentHash: Buffer; preimage: Buffer; cltvExpiry: number };
	}> => {
		const pair = await world.open(tag, {
			feeWallet: { alice: true, bob: policy },
			hooks
		});
		pair.wallets.alice!.fund(100_000);
		pair.wallets.alice!.fund(100_000);
		await world.mine(pair, 1);
		const held = await holdUnits(pair, 5000n, tag);
		const closed = pair.alice.node.forceCloseChannel(
			pair.channelId,
			SWEEP_DESTINATION
		);
		expect(closed.ok, closed.error).to.equal(true);
		await settle();
		await world.mine(pair, 2);
		pair.bob.node.settleHeldHtlc(held.paymentHash, held.preimage);
		await settle();
		return { pair, held };
	};

	it('asks at the rate the claim was made at after thirteen blocks of waiting for a coin, and the claim pays that rate', async () => {
		const { pair, held } = await settledAfterClose('fee-wait-rate', true);
		const first = htlcOf(pair.bob, pair)!;
		expect(first.auxiliaryFeeWait).to.deep.include({
			code: 'FEE_FUNDS_UNAVAILABLE',
			remedy: 'operator',
			deadlineHeight: held.cltvExpiry
		});
		expect(bitcoin.Transaction.fromHex(first.sweepTxHex!).ins.length).to.equal(
			1
		);
		const base = first.originalFeeRate!;
		expect(first.currentFeeRate ?? base).to.equal(base);

		// Thirteen blocks pass without a coin in the wallet: nothing was
		// sent, and the rate is the one the claim was made at.
		await world.mine(pair, 13);
		const waited = htlcOf(pair.bob, pair)!;
		expect(bitcoin.Transaction.fromHex(waited.sweepTxHex!).ins.length).to.equal(
			1
		);
		expect(pair.wallets.bob!.sent).to.have.length(0);
		expect(waited.currentFeeRate ?? base).to.equal(base);

		// A coin arrives, and the claim pays the rate it was made at.
		pair.wallets.bob!.fund(100_000);
		for (let i = 0; i < 8 && !isSpent(htlcOf(pair.bob, pair)); i++) {
			await world.mine(pair, 1);
		}
		const spent = htlcOf(pair.bob, pair)!;
		expect(isSpent(spent)).to.equal(true);
		const claim = pair.chain.confirmed.get(spent.resolutionTxid!)!.tx;
		const rate = feeOf(pair, claim) / claim.virtualSize();
		expect(spent.auxiliaryFeeRate).to.equal(base);
		expect(rate).to.be.at.least(base);
		expect(rate).to.be.below(base * 1.2);
	});

	it('claims under a cap that the fee at the first rate fits, after thirteen blocks of waiting for a coin', async () => {
		// The claim weighs about 228 vB: about 2 300 sat at 10 sat/vB, which
		// this cap fits, and more than the cap at 2.25 times that rate.
		const cap = 3_000n;
		const { pair, held } = await settledAfterClose('fee-wait-cap', {
			maxFeeSatoshis: cap,
			maxPreparationFeeSatoshis: 1_000n,
			maxTotalFeeSatoshis: cap * 10n
		});
		expect(htlcOf(pair.bob, pair)!.originalFeeRate).to.equal(10);
		await world.mine(pair, 13);
		pair.wallets.bob!.fund(100_000);
		pair.wallets.bob!.fund(100_000);
		for (let i = 0; i < 8 && !isSpent(htlcOf(pair.bob, pair)); i++) {
			await world.mine(pair, 1);
		}
		const claimed = htlcOf(pair.bob, pair)!;
		expect(isSpent(claimed)).to.equal(true);
		const claim = pair.chain.confirmed.get(claimed.resolutionTxid!)!;
		expect(claim.height).to.be.below(held.cltvExpiry);
		expect(claim.tx.ins).to.have.length(2);
		expect(feeOf(pair, claim.tx)).to.be.at.most(Number(cap) + 354);
		expect(claimed.auxiliaryFeeWait).to.equal(undefined);
		expect(pair.wallets.bob!.sent.length).to.be.at.least(1);
	});
});
