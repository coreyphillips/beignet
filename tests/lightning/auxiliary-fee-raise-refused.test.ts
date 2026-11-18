/**
 * Asset channels (issue #2093): a raise of the fee of a claim that the fee
 * pool refuses for good.
 *
 * The node raises the fee of a spend it holds by naming the fee coins of
 * that spend. When the pool refuses such a raise with remedy none, the node
 * asks once more without naming them: the pool serves it with the coins the
 * action holds or with others, and the spend made of them replaces the one
 * held through the output both spend, and is in a block before the
 * deadline.
 */

import * as bitcoin from 'bitcoinjs-lib';
import { expect } from 'chai';
import { OutputStatus, OutputType } from '../../src/lightning/chain/types';
import type { ITrackedOutput } from '../../src/lightning/chain/types';
import { HtlcState } from '../../src/lightning/channel/types';
import { PaymentStatus } from '../../src/lightning/node/types';
import { FixedOutputFeeError } from '../../src/lightning/wallet/fixed-output-fees';
import type { WalletFundingProvider } from '../../src/lightning/wallet/wallet-funding-provider';
import { withAssetOpens, type IAssetHost } from './helpers/auxiliary-nodes';
import {
	assetChainWorld,
	holdUnits,
	settle,
	trackedOutputs,
	type IAssetChainPair
} from './helpers/auxiliary-on-chain';

type Waiting = { tx: bitcoin.Transaction; fee: number; vsize: number };

describe('asset channels: a raise of a claim that the fee pool refuses for good', function () {
	this.timeout(180000);
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
	const mempoolOf = (pair: IAssetChainPair): Map<string, Waiting> =>
		(pair.chain as unknown as { mempool: Map<string, Waiting> }).mempool;
	const outpointOf = (input: { hash: Buffer; index: number }): string =>
		`${Buffer.from(input.hash).reverse().toString('hex')}:${input.index}`;

	/**
	 * Bob's claim by preimage goes out with a fee coin, no block takes it,
	 * and the first raise of it is refused for good. Until then every request
	 * asks `firstPays` times the fee the node asks, so that the claim held
	 * pays that much more than its rate.
	 */
	const raiseRefused = async (
		tag: string,
		firstPays: bigint
	): Promise<void> => {
		const pair = await world.open(tag, {
			feeWallet: { alice: true, bob: true },
			hooks: {
				bob: {
					valueIncomingHtlc: (context: { auxiliaryAmount?: bigint }): bigint =>
						context.auxiliaryAmount! * 1000n
				}
			}
		});
		const { bob, chain } = pair;
		for (const wallet of [pair.wallets.alice!, pair.wallets.bob!]) {
			wallet.fund(100_000);
			wallet.fund(100_000);
		}
		await world.mine(pair, 1);
		// Bob settles a held payment and Alice takes it, after which Bob
		// hears nothing more of her: his claim by preimage goes on chain.
		const held = await holdUnits(pair, 5000n, 'raise refused');
		(
			pair.bob.node as unknown as { handlePeerMessage: unknown }
		).handlePeerMessage = (): undefined => undefined;
		pair.bob.node.settleHeldHtlc(held.paymentHash, held.preimage);
		await settle();
		expect(pair.alice.node.getPayment(held.paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
		const entry = [
			...bob.node
				.getChannelManager()
				.getChannel(pair.channelId)!
				.getFullState()
				.htlcs.values()
		].find((e) => e.paymentHash.equals(held.paymentHash))!;
		expect(entry.state).to.equal(HtlcState.FULFILLED);
		const deadline = held.cltvExpiry;

		// The pool refuses the first raise that names the fee coins of the
		// spend Bob holds, as it does when they are not the action's any more.
		const provider = (
			bob.node as unknown as { fundingProvider: WalletFundingProvider }
		).fundingProvider;
		const select = provider.selectFeeBumpInputs.bind(provider);
		const asked: Array<{ named: boolean; answer: string }> = [];
		let refused = false;
		let afterRefusal: string[] | undefined;
		provider.selectFeeBumpInputs = async (target, rate, opts) => {
			const named = (opts?.replacementInputs?.length ?? 0) > 0;
			if (named && !refused) {
				refused = true;
				asked.push({ named, answer: 'FEE_INPUT_UNAVAILABLE' });
				throw new FixedOutputFeeError(
					'FEE_INPUT_UNAVAILABLE',
					'none',
					'Unreserved fixed-output replacement input'
				);
			}
			try {
				const answer = await select(
					refused ? target : target * firstPays,
					rate,
					opts
				);
				asked.push({ named, answer: 'served' });
				if (refused && !named && afterRefusal === undefined)
					afterRefusal = answer.inputs.map(
						(input) =>
							`${bitcoin.Transaction.fromBuffer(input.prevTx).getId()}:${
								input.prevOutputIndex
							}`
					);
				return answer;
			} catch (error) {
				asked.push({
					named,
					answer: (error as FixedOutputFeeError).code ?? 'error'
				});
				throw error;
			}
		};

		// Bob closes by itself 18 blocks before the expiry. Blocks take his
		// splits, and none takes the first claim with a fee coin: it stays in
		// the mempool, and the node raises it.
		chain.advance(deadline - 19 - chain.height);
		await settle();
		let first: string | undefined;
		const spendsOutput = (tx: bitcoin.Transaction): boolean => {
			const output = htlcOf(bob, pair);
			return (
				!!output &&
				tx.ins.some(
					(input) =>
						outpointOf(input) === `${output.txid}:${output.outputIndex}`
				)
			);
		};
		const other = (): string | undefined =>
			[...mempoolOf(pair).values()]
				.map((waiting) => waiting.tx)
				.find((tx) => spendsOutput(tx) && tx.getId() !== first)
				?.getId();
		for (let i = 0; i < 24 && chain.height < deadline - 1; i++) {
			const mempool = mempoolOf(pair);
			first ??= [...mempool.values()]
				.map((waiting) => waiting.tx)
				.find((tx) => spendsOutput(tx) && tx.ins.length > 1)
				?.getId();
			if (first && other()) break;
			const kept = first ? mempool.get(first) : undefined;
			if (first) mempool.delete(first);
			chain.mine();
			if (first && kept) mempool.set(first, kept);
			await settle();
		}
		expect(first, 'a claim with a fee coin went out').to.not.equal(undefined);

		// The raise that named the fee coins of that claim was refused, and the
		// node asked at once without them, and was served.
		const at = asked.findIndex(
			(each) => each.named && each.answer === 'FEE_INPUT_UNAVAILABLE'
		);
		expect(at, JSON.stringify(asked)).to.be.at.least(0);
		expect(asked[at + 1]).to.deep.equal({ named: false, answer: 'served' });

		// The claim made of that answer replaced the one held, and is in a
		// block before the deadline.
		const replacement = other();
		expect(replacement, 'the claim was replaced').to.not.equal(undefined);
		// It is the spend made of that answer: the network took it in place of
		// the one held (BIP 125: it pays more, by the relay rate on its size).
		expect(
			mempoolOf(pair).get(replacement!)!.tx.ins.slice(1).map(outpointOf).sort()
		).to.deep.equal([...afterRefusal!].sort());
		while (chain.height < deadline && !isSpent(htlcOf(bob, pair))) {
			await world.mine(pair, 1);
		}
		const claimed = htlcOf(bob, pair)!;
		expect(isSpent(claimed), 'claimed before the expiry').to.equal(true);
		expect(claimed.resolutionTxid).to.not.equal(first);
		expect(chain.confirmed.get(claimed.resolutionTxid!)!.height).to.be.below(
			deadline
		);
		expect(mempoolOf(pair).has(first!)).to.equal(false);
	};

	it('asks once more without the fee coins it named, and the spend made of the answer replaces the one held and is in a block before the deadline', () =>
		raiseRefused('fee-raise-refused', 1n));

	it('asks once more without the fee coins it named, and the spend made of the answer pays what the one held paid with the relay rate on its size over it, so that it replaces it', () =>
		raiseRefused('fee-raise-refused-paid', 3n));
});
