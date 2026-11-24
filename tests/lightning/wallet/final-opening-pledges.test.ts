import { expect } from 'chai';
import { rejects } from 'assert';
import { Transaction } from 'bitcoinjs-lib';
import { opening } from '../helpers/final-opening';
import {
	type IWalletLike,
	WalletFundingProvider
} from '../../../src/lightning/wallet/wallet-funding-provider';

describe('Final wallet funding pledges after restart', () => {
	it('keeps live local coins reserved during unrelated cleanup and coin selection while allowing spent coins to clear', async () => {
		const candidate = opening();
		const tx = Transaction.fromHex(candidate.fundingTxHex);
		const coins = tx.ins.map(({ hash, index }) => ({
			tx_hash: Buffer.from(hash).reverse().toString('hex'),
			tx_pos: index,
			address: '',
			path: '',
			publicKey: '',
			height: 1,
			value: 100_000
		}));
		const index = candidate.inputs.findIndex((input) => input.isLocal);
		const mine = coins[index];
		const other = coins[1 - index];
		let live = coins.slice();
		const frozen = new Set([mine.tx_hash]);
		const wallet: IWalletLike = {
			listUtxos: () => live,
			listFrozenUtxos: () =>
				coins
					.filter((coin) => frozen.has(coin.tx_hash))
					.map((coin) => ({
						...coin,
						frozenAt: 1,
						freezeTag: 'funding-pledge'
					})),
			isUtxoFrozen: (id) => frozen.has(id),
			freezeUtxoIfUnfrozen: async ({ txid }) => {
				const created = !frozen.has(txid);
				frozen.add(txid);
				return { isOk: () => true, isErr: () => false, value: { created } };
			},
			unfreezeUtxoIfTagged: async ({ txid }) => {
				frozen.delete(txid);
				return {
					isOk: () => true,
					isErr: () => false,
					value: { unfrozen: true }
				};
			},
			send: async () => {
				throw new Error('stop after coin selection');
			},
			electrum: {
				broadcastTransaction: async () => {
					throw new Error('unexpected broadcast');
				}
			}
		};
		const provider = new WalletFundingProvider(wallet, {
			finalOpeningCandidates: (): (typeof candidate)[] => [candidate]
		});
		await provider.releaseInputPledges([
			{ txid: mine.tx_hash, vout: mine.tx_pos }
		]);
		expect(frozen.has(mine.tx_hash)).to.equal(true);
		await rejects(
			() => provider.buildFundingTransaction('unused', 1n),
			/stop after coin selection/
		);
		expect(frozen.has(mine.tx_hash)).to.equal(true);
		frozen.clear();
		await provider.renewFinalOpeningPledges();
		expect([...frozen]).to.deep.equal([mine.tx_hash]);
		live = [other];
		await rejects(
			() => provider.buildFundingTransaction('unused', 1n),
			/stop after coin selection/
		);
		expect(frozen.size).to.equal(0);

		// A losing splice selection can release its coins even if the winner already reserved one.
		frozen.add(mine.tx_hash);
		frozen.add(other.tx_hash);
		const afterSplice = new WalletFundingProvider(wallet, {
			finalSpliceOutpoints: () => new Set([other.tx_hash + ':' + other.tx_pos])
		});
		await afterSplice.releaseInputPledges(
			coins.map((coin) => ({ txid: coin.tx_hash, vout: coin.tx_pos }))
		);
		expect([...frozen]).to.deep.equal([other.tx_hash]);
	});
});
