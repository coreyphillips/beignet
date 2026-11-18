/**
 * Asset channels (issue #2093): every spend of an output that carries units
 * is signed for the size it really has.
 *
 * The fee of a spend is its fee rate times a size. When that size is an
 * estimate below the real one, a spend signed at the floor rate is under
 * the relay floor and the network refuses it, and at any other rate it
 * pays less than it was asked to. Each kind is measured here on the
 * transaction a block took: all it spends less all it pays out, over its
 * virtual size.
 */
import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import {
	AUXILIARY_SPEND_SIGNATURE_BYTES,
	auxiliarySpendVbytes
} from '../../src/lightning/chain/auxiliary-sweep';
import { CommitmentType, OutputType } from '../../src/lightning/chain/types';
import { withAssetOpens, type IAssetHost } from './helpers/auxiliary-nodes';
import {
	ASSET_SWEEP_SCRIPT,
	SWEEP_DESTINATION,
	assetChainWorld,
	ownSpends,
	payUnits,
	settle,
	underpaidSpends,
	type IAssetChainOptions,
	type IAssetChainPair,
	type IOwnSpend
} from './helpers/auxiliary-on-chain';

describe('asset channels: the size a spend of units is signed for', function () {
	this.timeout(240_000);
	withAssetOpens();
	const world = assetChainWorld();
	afterEach(() => world.dispose());

	// Every force close of the host at one rate, with an HTLC on the
	// commitment or none.
	const atRate = (host: IAssetHost, feeRate: number): void => {
		const node = host.node as unknown as {
			resolveForceCloseFeeRatePerVbyte: () => number;
			resolveNoDeadlineFeeRatePerVbyte: () => number;
		};
		node.resolveForceCloseFeeRatePerVbyte = (): number => feeRate;
		node.resolveNoDeadlineFeeRatePerVbyte = (): number => feeRate;
	};
	const spendOf = (
		pair: IAssetChainPair,
		host: IAssetHost,
		type: OutputType
	): IOwnSpend => {
		const spend = ownSpends(pair, host).find(
			(candidate) => candidate.output.outputType === type
		);
		if (!spend) throw new Error(`no spend of a ${type} is in a block`);
		return spend;
	};
	const delayOf = (host: IAssetHost, pair: IAssetChainPair): number =>
		host.node.getChannelManager().getChannel(pair.channelId)!.getFullState()
			.remoteConfig.toSelfDelay;

	it('the size computed for a spend is the size the signed transaction has, for every shape of witness', () => {
		const signature = AUXILIARY_SPEND_SIGNATURE_BYTES;
		const shapes: number[][] = [
			// A key spend: an HTLC output or a second-level output of a
			// revoked commitment.
			[signature],
			// to_remote, to_local by its delay, to_local by its revocation.
			[signature, 37, 65],
			[signature, 40, 97],
			[signature, 68, 97],
			// A claim by one leaf with a preimage, and a long leaf.
			[signature, 32, 110, 129],
			[signature, 300, 161]
		];
		for (const destination of [SWEEP_DESTINATION, ASSET_SWEEP_SCRIPT]) {
			for (const shape of shapes) {
				const spend = new bitcoin.Transaction();
				spend.version = 2;
				spend.addInput(Buffer.alloc(32, 1), 0, 0xfffffffd);
				// The provider puts a script of 34 bytes in place of the
				// destination.
				spend.addOutput(ASSET_SWEEP_SCRIPT, 354);
				spend.setWitness(
					0,
					shape.map((size) => Buffer.alloc(size, 2))
				);
				expect(auxiliarySpendVbytes(shape, destination)).to.equal(
					spend.virtualSize()
				);
			}
		}
	});

	for (const feeRate of [1, 10]) {
		it(`both balance outputs of a commitment that pay their own fee are signed for their size, at ${feeRate} sat/vB`, async () => {
			const tag = `aux-sizes-balance-${feeRate}`;
			const pair = await world.open(tag, { pushMsat: 500_000_000n });
			for (const host of [pair.alice, pair.bob]) atRate(host, feeRate);
			await world.mine(pair, 1);
			const closed = pair.alice.node.forceCloseChannel(
				pair.channelId,
				SWEEP_DESTINATION
			);
			expect(closed.ok, closed.error).to.equal(true);
			await settle();
			await world.mine(pair, 1);
			const h = pair.chain.height;
			const delay = delayOf(pair.alice, pair);
			while (pair.chain.height < h + delay + 2) await world.mine(pair, 1);

			// The delayed balance of the node that closed: its signature, the
			// delay leaf and a proof two levels deep.
			const local = spendOf(pair, pair.alice, OutputType.TO_LOCAL);
			expect(local.output.auxiliaryCommitmentNumber).to.not.equal(undefined);
			expect(local.transaction.ins.length).to.equal(1);
			expect(local.vbytes).to.equal(146);
			expect(local.fee).to.equal(146 * feeRate);
			// It leaves at the block that ends the delay and is in the next.
			expect(local.height).to.equal(h + delay + 1);

			// The balance of the peer: its signature, the leaf and a proof one
			// level deep.
			const remote = spendOf(pair, pair.bob, OutputType.TO_REMOTE);
			expect(remote.output.auxiliaryCommitmentNumber).to.not.equal(undefined);
			expect(remote.transaction.ins.length).to.equal(1);
			expect(remote.vbytes).to.equal(137);
			expect(remote.fee).to.equal(137 * feeRate);
			expect(remote.height).to.equal(h + 2);

			expect(underpaidSpends(pair)).to.deep.equal([]);
		});
	}

	const options = (pushMsat: bigint): IAssetChainOptions => ({
		pushMsat,
		feeWallet: { alice: true },
		hooks: {
			bob: {
				valueIncomingHtlc: (context: { auxiliaryAmount?: bigint }) =>
					(context.auxiliaryAmount ?? 0n) * 1000n
			}
		}
	});
	/** Bob keeps the commitment he holds now, two payments pass, he publishes it. */
	const cheated = async (pair: IAssetChainPair): Promise<void> => {
		const channel = pair.bob.node
			.getChannelManager()
			.getChannel(pair.channelId)!;
		const plan = channel.prepareForceClose(channel.getSigner()!);
		if (!plan.ok) throw new Error(plan.error);
		const kept = bitcoin.Transaction.fromBuffer(plan.commitmentTx);
		await payUnits(pair, 100n);
		await payUnits(pair, 100n);
		await pair.backends.bob.broadcastTransaction(kept.toHex());
		await settle();
		await world.mine(pair, 1);
		expect(
			pair.alice.node.getChannelMonitorState(pair.channelId)!
				.commitmentBroadcast!.commitmentType
		).to.equal(CommitmentType.THEIR_REVOKED_COMMITMENT);
	};

	for (const feeRate of [1, 10]) {
		it(`the penalty of a balance output of 354 sat takes a fee input that pays for the size it has, at ${feeRate} sat/vB`, async () => {
			const tag = `aux-sizes-penalty-${feeRate}`;
			const pair = await world.open(tag, options(354_000n));
			atRate(pair.alice, feeRate);
			pair.wallets.alice!.fund(100_000);
			pair.wallets.alice!.fund(100_000);
			await world.mine(pair, 1);
			await cheated(pair);
			for (let i = 0; i < 12; i++) await world.mine(pair, 1);

			// The cheater's balance by its revocation leaf, and one wallet
			// input: 153 vbytes of its own and 68 of the input.
			const penalty = spendOf(pair, pair.alice, OutputType.TO_LOCAL);
			expect(penalty.output.amount).to.equal(354n);
			expect(penalty.transaction.ins.length).to.equal(2);
			expect(penalty.transaction.outs[0].value).to.equal(354);
			expect(penalty.vbytes).to.equal(221);
			expect(penalty.fee).to.be.at.least(221 * feeRate);

			// The node's own balance on the revoked commitment pays for itself.
			// What is taken from a revoked commitment is asked for at more
			// than the rate of the node, so the fee is a floor here.
			const own = spendOf(pair, pair.alice, OutputType.TO_REMOTE);
			expect(own.transaction.ins.length).to.equal(1);
			expect(own.vbytes).to.equal(137);
			expect(own.fee).to.be.at.least(137 * feeRate);

			expect(underpaidSpends(pair)).to.deep.equal([]);
		});

		it(`the penalty of a balance output that pays its own fee is never under the rate asked, at ${feeRate} sat/vB`, async () => {
			const tag = `aux-sizes-penalty-self-${feeRate}`;
			// The cheater holds 500 000 sat: its output pays for its penalty.
			const pair = await world.open(tag, options(500_000_000n));
			atRate(pair.alice, feeRate);
			await world.mine(pair, 1);
			await cheated(pair);
			const h = pair.chain.height;
			for (let i = 0; i < 6; i++) await world.mine(pair, 1);

			const penalty = spendOf(pair, pair.alice, OutputType.TO_LOCAL);
			expect(penalty.transaction.ins.length).to.equal(1);
			expect(penalty.vbytes).to.equal(153);
			expect(penalty.fee).to.be.at.least(153 * feeRate);
			// The penalty is in the block of the commitment it punishes.
			expect(penalty.height).to.equal(h);
			const own = spendOf(pair, pair.alice, OutputType.TO_REMOTE);
			expect(own.vbytes).to.equal(137);
			expect(own.fee).to.be.at.least(137 * feeRate);
			expect(own.height).to.equal(h + 1);
			expect(underpaidSpends(pair)).to.deep.equal([]);
		});
	}
});
