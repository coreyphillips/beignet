/**
 * Asset channels (issue #2093): the free coins of the fee pool go back to
 * the wallet once no asset channel can need them.
 *
 * The fee pool keeps the coins of its splits that no fee action holds
 * frozen, for the next spend of an asset channel that needs one. The node
 * asks the wallet to take them back on a block after which no asset channel
 * is open or opening and none has anything left to resolve. Until then they
 * stay frozen, and a provider that cannot take them back changes nothing.
 */

import * as bitcoin from 'bitcoinjs-lib';
import { expect } from 'chai';
import { IRREVOCABLE_DEPTH } from '../../src/lightning/chain/types';
import { ChannelState } from '../../src/lightning/channel/types';
import type { WalletFundingProvider } from '../../src/lightning/wallet/wallet-funding-provider';
import type { IChainWallet } from './helpers/auxiliary-fee-wallet';
import { withAssetOpens, type IAssetHost } from './helpers/auxiliary-nodes';
import {
	assetChainWorld,
	errorsOf,
	payUnits,
	settle,
	type IAssetChainPair
} from './helpers/auxiliary-on-chain';

describe('asset channels: the free fee coins handed back to the wallet', function () {
	this.timeout(240_000);
	withAssetOpens();
	const world = assetChainWorld();
	afterEach(() => world.dispose());
	const valueIncomingHtlc = (context: { auxiliaryAmount?: bigint }): bigint =>
		(context.auxiliaryAmount ?? 0n) * 1000n;
	const poolOf = (host: IAssetHost): WalletFundingProvider =>
		(host.node as unknown as { fundingProvider: WalletFundingProvider })
			.fundingProvider;
	/** The coins the wallet lists that are frozen as the pool's free fee coins. */
	const held = (wallet: IChainWallet): string[] => {
		const listed = new Set(
			wallet.coins().map((coin) => `${coin.tx_hash}:${coin.tx_pos}`)
		);
		return (wallet.wallet.listFrozenUtxos?.() ?? [])
			.filter(
				(hold) =>
					/^fixed-output-fees:[0-9a-f]{64}:coin$/.test(hold.freezeTag ?? '') &&
					listed.has(`${hold.tx_hash}:${hold.tx_pos}`)
			)
			.map((hold) => `${hold.tx_hash}:${hold.tx_pos}`)
			.sort();
	};
	/** The free fee coins the pool says it holds. */
	const freeCoins = (host: IAssetHost): number => {
		const status = poolOf(host).getFixedOutputFeeStatus();
		return status?.available
			? status.feeCoins.ready + status.feeCoins.unconfirmed
			: 0;
	};
	const monitorState = (pair: IAssetChainPair): string | undefined =>
		pair.alice.node.getChannelMonitorState(pair.channelId)?.monitorState;
	const block = async (pair: IAssetChainPair): Promise<void> => {
		await world.mine(pair, 1);
		for (let i = 0; i < 5; i++) await settle();
	};

	/**
	 * Bob puts a revoked commitment on chain, and Alice punishes it with a
	 * penalty that a fee coin of her pool pays for. `whileOpen` runs once
	 * her wallet has coins, before anything is paid over the channel.
	 */
	const punished = async (
		tag: string,
		whileOpen?: (pair: IAssetChainPair) => Promise<void>
	): Promise<IAssetChainPair> => {
		const pair = await world.open(tag, {
			pushMsat: 354_000n,
			feeWallet: { alice: true },
			hooks: { bob: { valueIncomingHtlc } }
		});
		pair.wallets.alice!.fund(100_000);
		pair.wallets.alice!.fund(100_000);
		await world.mine(pair, 1);
		await whileOpen?.(pair);
		const channel = pair.bob.node
			.getChannelManager()
			.getChannel(pair.channelId)!;
		const plan = channel.prepareForceClose(channel.getSigner()!);
		if (!plan.ok) throw new Error(plan.error);
		const revoked = bitcoin.Transaction.fromBuffer(plan.commitmentTx);
		await payUnits(pair, 100n);
		await payUnits(pair, 100n);
		await pair.backends.bob.broadcastTransaction(revoked.toHex());
		await settle();
		return pair;
	};

	/** Blocks until Alice's monitor has nothing left to resolve, and one more. */
	const untilResolved = async (
		pair: IAssetChainPair,
		each: (resolved: boolean) => void
	): Promise<number> => {
		pair.chain.advance(IRREVOCABLE_DEPTH);
		for (let i = 0; i < 20; i++) await settle();
		let resolvedAt: number | undefined;
		for (let i = 0; i < 12; i++) {
			const resolved = monitorState(pair) === 'FULLY_RESOLVED';
			if (resolved) resolvedAt ??= pair.chain.height;
			if (resolvedAt !== undefined && pair.chain.height > resolvedAt) break;
			each(resolved);
			await block(pair);
		}
		expect(resolvedAt, errorsOf(pair.alice).join('; ')).to.not.equal(undefined);
		return resolvedAt!;
	};

	it('keeps the free fee coins while the asset channel is open, while it closes and while its claim is pending, and hands them back on the first block after the channel is resolved for good', async () => {
		const tag = 'fee-coins-release';
		// The heights at which the node asks the wallet to take the coins back.
		const asked: number[] = [];
		const pair = await punished(tag, async (open) => {
			// A claim of an earlier channel left free coins in Alice's pool.
			const pool = poolOf(open.alice);
			const release = pool.releaseFixedOutputFeeCoins.bind(pool);
			pool.releaseFixedOutputFeeCoins = (): Promise<boolean> => {
				asked.push(open.chain.height);
				return release();
			};
			const ask = (): ReturnType<typeof pool.selectFeeBumpInputs> =>
				pool.selectFeeBumpInputs(500n, 1000, {
					fixedOutputs: true,
					feeActionId: 'a claim of an earlier channel',
					blockHeight: open.chain.height
				});
			await ask().catch(async () => {
				await block(open);
				return ask();
			});
			await pool.retireFixedOutputFeeAction('a claim of an earlier channel', {
				impossible: true
			});
			for (let i = 0; i < 2; i++) {
				await block(open);
				expect(
					open.alice.node
						.getChannelManager()
						.getChannel(open.channelId)!
						.getState()
				).to.equal(ChannelState.NORMAL);
				expect(held(open.wallets.alice!), 'kept while open').to.have.length(
					freeCoins(open.alice)
				);
				expect(freeCoins(open.alice)).to.be.above(0);
			}
			expect(asked, 'asked while open').to.deep.equal([]);
		});
		const wallet = pair.wallets.alice!;

		// The close and the penalty: the coins stay frozen block after block.
		for (let i = 0; i < 4; i++) {
			await block(pair);
			expect(monitorState(pair)).to.not.equal('FULLY_RESOLVED');
			expect(held(wallet), 'kept while it closes').to.have.length(
				freeCoins(pair.alice)
			);
			expect(freeCoins(pair.alice)).to.be.above(0);
		}
		expect(asked, 'asked while it closes').to.deep.equal([]);

		let last: string[] = [];
		const resolvedAt = await untilResolved(pair, (resolved) => {
			if (resolved) return;
			last = held(wallet);
			expect(last, 'kept while a claim is pending').to.have.length(
				freeCoins(pair.alice)
			);
			expect(last).to.not.deep.equal([]);
			expect(asked, 'asked while a claim is pending').to.deep.equal([]);
		});
		expect(pair.chain.height).to.equal(resolvedAt + 1);
		expect(asked.length, 'asked once resolved').to.be.at.least(1);
		expect(asked[0]).to.be.within(resolvedAt, resolvedAt + 1);
		expect(held(wallet), 'handed back').to.deep.equal([]);
		expect(freeCoins(pair.alice)).to.equal(0);
		expect(
			poolOf(pair.alice).getFixedOutputFeeActionIds(pair.channelId)
		).to.deep.equal([]);
		// The wallet lists them, unfrozen, and its own sends may take them.
		const listed = wallet
			.coins()
			.filter((coin) => last.includes(`${coin.tx_hash}:${coin.tx_pos}`));
		expect(listed).to.have.length(last.length);
		for (const coin of listed) {
			expect(wallet.wallet.isUtxoFrozen?.(coin.tx_hash, coin.tx_pos)).to.equal(
				false
			);
		}
	});

	it('changes nothing with a provider that cannot take the coins back, and the first block after one that can hands them back', async () => {
		const pair = await punished('fee-coins-kept');
		const pool = poolOf(pair.alice) as unknown as {
			releaseFixedOutputFeeCoins?: unknown;
		};
		pool.releaseFixedOutputFeeCoins = undefined;
		const wallet = pair.wallets.alice!;
		for (let i = 0; i < 4; i++) await block(pair);
		const resolvedAt = await untilResolved(pair, () => undefined);
		const said = errorsOf(pair.alice).length;
		for (let i = 0; i < 2; i++) await block(pair);
		expect(pair.chain.height).to.equal(resolvedAt + 3);
		const kept = held(wallet);
		expect(kept).to.not.deep.equal([]);
		expect(kept).to.have.length(freeCoins(pair.alice));
		expect(errorsOf(pair.alice).slice(said)).to.deep.equal([]);

		// The same node, with a provider that can.
		delete pool.releaseFixedOutputFeeCoins;
		await block(pair);
		expect(held(wallet)).to.deep.equal([]);
		expect(freeCoins(pair.alice)).to.equal(0);
	});
});
