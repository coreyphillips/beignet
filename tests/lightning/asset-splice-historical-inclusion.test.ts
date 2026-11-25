import { strict as assert } from 'assert';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { Block, crypto } from 'bitcoinjs-lib';
import { ElectrumBackend } from '../../src/lightning/chain/electrum-backend';
import { ChainBackendUnavailableError } from '../../src/lightning/chain/chain-watcher';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	finalDigest,
	setupAssetSpliceProofs
} from './helpers/asset-splice-proof-release';

const fundingHeight = 101;
const coinbase = Buffer.alloc(32, 62);
const display = (b: Buffer) => Buffer.from(b).reverse().toString('hex');
function block(parent: Buffer, root: Buffer, stamp: number) {
	const h = new Block();
	h.prevHash = parent;
	h.version = 4;
	h.merkleRoot = root;
	h.timestamp = stamp;
	h.bits = 0x207fffff;
	h.nonce = 0;
	while (!h.checkProofOfWork()) h.nonce++;
	return h;
}
function chain(txid: string, stamp = 1700000100) {
	const inclusion = crypto.hash256(
		Buffer.concat([coinbase, Buffer.from(txid, 'hex').reverse()])
	);
	const headers = [block(Buffer.alloc(32, 60), inclusion, stamp)];
	function extend(count: number) {
		for (let i = 0; i < count; i++)
			headers.push(
				block(
					headers[headers.length - 1].getHash(),
					coinbase,
					stamp + headers.length
				)
			);
	}
	extend(2057);
	return { headers, extend };
}

describe('historical asset funding checks on the original device', () => {
	let dir: string, f: ReturnType<typeof setupAssetSpliceProofs>;
	beforeEach(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'asset-splice-historical-'));
		f = setupAssetSpliceProofs(dir);
		f.retain(0);
	});
	afterEach(() => {
		for (const d of f.devices) d.store.close();
		fs.rmSync(dir, { recursive: true, force: true });
	});
	function setup() {
		const d = f.devices[0],
			txid = f.candidates[0].tx.getId();
		let active = chain(txid);
		const requested: number[] = [];
		let proofs = 0;
		const server = {
			electrumNetwork: 'bitcoinRegtest',
			getBlockHeader: () => {
				const tip = active.headers[active.headers.length - 1];
				return {
					height: fundingHeight + active.headers.length - 1,
					hash: tip.getId(),
					hex: tip.toHex(true)
				};
			},
			getBlockHex: async ({ height }: { height: number }) => {
				requested.push(height);
				return {
					isErr: () => false,
					value: active.headers[height - fundingHeight].toHex(true)
				};
			},
			getTransactionMerkle: async () => {
				proofs++;
				return {
					block_height: fundingHeight,
					pos: 1,
					merkle: [display(coinbase)]
				};
			}
		};
		let backend = new ElectrumBackend(server as never, 4000);
		const check = (store = d.store) =>
			backend.getAssetSpliceInclusion(txid, fundingHeight, {
				store,
				channelId: f.id,
				finalDigest
			});
		return {
			d,
			txid,
			requested,
			check,
			proofs: () => proofs,
			active: () => active,
			replace: (next: ReturnType<typeof chain>) => {
				active = next;
			},
			restart: () => {
				d.store.close();
				d.store = SqliteStorage.openFinalWallet(d.file, d.party.binding);
				backend = new ElectrumBackend(server as never, 4000);
			}
		};
	}
	it('retains a bounded original-device cursor, follows an advancing tip, and proves the funding block only after all intervening links validate', async () => {
		const h = setup();
		await assert.rejects(h.check(), ChainBackendUnavailableError);
		const first = h.requested.length;
		assert(first > 0 && first < 300);
		h.restart();
		h.active().extend(2);
		let settled = false;
		for (let i = 0; i < 40; i++) {
			const before = h.requested.length;
			try {
				const result = await h.check();
				assert.deepEqual(result, {
					txid: h.txid,
					blockHash: h.active().headers[0].getId(),
					confirmations: h.active().headers.length
				});
				settled = true;
			} catch (error) {
				if (!(error instanceof ChainBackendUnavailableError)) throw error;
			}
			assert(h.requested.length - before < 300);
			if (settled) break;
		}
		assert(settled);
		assert(h.proofs() > 0);
		assert.equal(new Set(h.requested).size, h.active().headers.length);
	});
	it('rejects a copied cursor and a replacement tip whose linked funding block omits the candidate', async () => {
		const h = setup();
		await assert.rejects(h.check(), ChainBackendUnavailableError);
		const snapshot = path.join(dir, 'wallet-copy');
		await h.d.store.backup(snapshot);
		const copy = SqliteStorage.openFinalWallet(snapshot, h.d.party.binding);
		try {
			await assert.rejects(h.check(copy), /original/);
		} finally {
			copy.close();
		}
		h.replace(chain('cb'.repeat(32), 1701000000));
		let refused = false;
		for (let i = 0; i < 40; i++) {
			try {
				await h.check();
				assert.fail('Accepted an unproven funding block');
			} catch (error) {
				if (error instanceof ChainBackendUnavailableError) continue;
				assert.match(String(error), /proof.*funding block/);
				refused = true;
				break;
			}
		}
		assert(refused);
	});
});
