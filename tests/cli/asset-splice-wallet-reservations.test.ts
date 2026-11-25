import { strict as assert } from 'assert';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { BeignetNode } from '../../src/cli/beignet-node';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { setupAssetSpliceProofs } from '../lightning/helpers/asset-splice-proof-release';

const attempt = '3a'.repeat(32);
const competing = '3b'.repeat(32);
const unrelated = '6e'.repeat(32) + ':2';
const hashOf = (hash: Buffer) => Buffer.from(hash).reverse().toString('hex');

describe('original asset splice wallet input reservations', () => {
	let dir: string, f: ReturnType<typeof setupAssetSpliceProofs>;
	let coin: string, parent: string;
	beforeEach(() => {
		dir = fs.mkdtempSync(
			path.join(os.tmpdir(), 'asset-splice-wallet-reserves-')
		);
		f = setupAssetSpliceProofs(dir);
		f.fundOpening();
		const c = f.candidates[0];
		const input = c.tx.ins[c.localInputs[0]];
		coin = hashOf(input.hash) + ':' + input.index;
		const prev = f.terms[0];
		parent = prev.parent.getId() + ':' + prev.parentIndex;
	});
	afterEach(() => {
		for (const d of f.devices) d.store.close();
		fs.rmSync(dir, { recursive: true, force: true });
	});
	function reserve() {
		f.devices[0].store.reserveAssetSpliceWalletInputs(f.id, attempt, parent, [
			coin
		]);
	}
	function restart() {
		const d = f.devices[0];
		d.store.close();
		d.store = SqliteStorage.openFinalWallet(d.file, d.party.binding);
		return d.store;
	}

	it('rejects ambiguous and competing pre-release selections while permitting an unsigned abort to free the coin', () => {
		const db = f.devices[0].store;
		assert.throws(() =>
			db.reserveAssetSpliceWalletInputs(f.id, attempt, unrelated, [coin])
		);
		for (const invalid of [coin.replace(':0', ':00'), coin.slice(1), parent])
			assert.throws(() =>
				db.reserveAssetSpliceWalletInputs(f.id, attempt, parent, [invalid])
			);
		reserve();
		reserve();
		assert.throws(() =>
			db.reserveAssetSpliceWalletInputs(f.id, attempt, parent, [unrelated])
		);
		assert.throws(() =>
			db.reserveAssetSpliceWalletInputs(f.id, competing, parent, [coin])
		);
		assert.deepEqual(db.loadFinalSpliceWalletOutpoints(), new Set([coin]));
		db.releaseAssetSpliceWalletInputs(f.id, attempt);
		db.releaseAssetSpliceWalletInputs(f.id, attempt);
		assert.deepEqual(db.loadFinalSpliceWalletOutpoints(), new Set());
		assert.throws(() =>
			db.reserveAssetSpliceWalletInputs(f.id, attempt, parent, [coin])
		);
		db.reserveAssetSpliceWalletInputs(f.id, competing, parent, [coin]);
		assert.deepEqual(db.loadFinalSpliceWalletOutpoints(), new Set([coin]));
	});

	it('preserves the actual local input over a crash inside the wallet signer even when no wire packet was returned', () => {
		reserve();
		f.retain(0);
		f.retain(1);
		assert.throws(
			() =>
				f.sign(0, f.context(0), f.views[0], () => {
					throw Error('wallet interrupted');
				}),
			/interrupted/
		);
		const db = restart();
		assert.deepEqual(db.loadFinalSpliceWalletOutpoints(), new Set([coin]));
		assert.throws(() => db.releaseAssetSpliceWalletInputs(f.id, attempt));
		assert.deepEqual(db.loadFinalSpliceWalletOutpoints(), new Set([coin]));
		f.sign(0, f.context(0));
		f.sign(1, f.context(1));
		assert.deepEqual(
			f.devices[1].store.loadFinalSpliceWalletOutpoints(),
			new Set()
		);
	});

	it('reinstates freezes on restart and refuses a manual unfreeze through the ordinary public wallet facade', async () => {
		reserve();
		const db = restart();
		const frozen = new Set<string>();
		const [txid, idx] = coin.split(':');
		const wallet = {
			listUtxos: () =>
				[coin, unrelated].map((op) => {
					const [id, index] = op.split(':');
					return {
						tx_hash: id,
						tx_pos: Number(index),
						address: '',
						path: '',
						publicKey: '',
						height: 2,
						value: 20500
					};
				}),
			listFrozenUtxos: () => [],
			withSendLock: async (
				fn: (locked: { send: () => Promise<unknown> }) => Promise<unknown>
			) =>
				fn({
					send: async () => {
						assert(
							frozen.has(coin),
							'ordinary sender considered an unfrozen reserved coin'
						);
						return { isErr: () => false, value: f.candidates[0].tx.toHex() };
					}
				}),
			resetSendTransaction: async () => undefined,
			electrum: {
				broadcastTransaction: async () => {
					throw Error('reserved input reached broadcast');
				}
			},
			isUtxoFrozen: () => false,
			freezeUtxoIfUnfrozen: async (x: { txid: string; index: number }) => {
				frozen.add(x.txid + ':' + x.index);
				return {
					isOk: () => true,
					isErr: () => false,
					value: { created: true }
				};
			},
			unfreezeUtxo: async (x: { txid: string; vout: number }) => {
				frozen.delete(x.txid + ':' + x.vout);
				return { isErr: () => false };
			}
		};
		const facade: BeignetNode = Object.assign(
			Object.create(BeignetNode.prototype),
			{
				storage: db,
				networkName: 'regtest',
				_bootOpts: { finalTaprootWallet: true, assetSplice: true },
				_onchainSendLock: Promise.resolve(),
				wallet
			}
		);
		await facade['walletFundingProvider'](undefined).renewFinalOpeningPledges();
		assert.deepEqual(frozen, new Set([coin]));
		await assert.rejects(facade.unfreezeUtxo(txid, Number(idx)), /splice/i);
		await facade.unfreezeUtxo(unrelated.slice(0, 64), 2);
		frozen.clear();
		await assert.rejects(
			facade.sendOnchain('fixture', 500),
			/reserved by an asset splice/
		);

		assert.deepEqual(frozen, new Set([coin]));
	});
});
