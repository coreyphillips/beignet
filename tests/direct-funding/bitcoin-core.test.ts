import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import { ecc } from '../../src/utils/ecc';
import { BitcoinCoreWalletAdapter } from '../../src/direct-funding/bitcoin-core';
import type { BitcoinCoreRpc } from '../../src/direct-funding/bitcoin-core';
import { Network } from '../../src/lightning/invoice/types';
import { ownershipProbeTransaction } from '../../src/lightning/direct-funding/messages';
import { makeCoin } from '../lightning/helpers/df-sender';

const missing = (): Error & { code: number } =>
	Object.assign(new Error('Not found'), { code: -5 });

function harness() {
	const coin = makeCoin(200_001, 'p2wpkh');
	const journal = new Map<string, string>();
	const locks = new Set<string>();
	const transactions = new Map<string, Record<string, unknown>>([
		[coin.txidHex, { hex: coin.prevTx.toHex(), confirmations: 10 }]
	]);
	const mempool = new Set<string>();
	const calls: Array<{ method: string; params: unknown[] }> = [];
	const state = {
		chain: 'regtest',
		amount: 0.00200001 as number | string,
		present: true,
		failSave: false,
		failOwnedSave: false,
		lostLockResponse: false,
		lostUnlockResponse: false,
		lockRejected: false,
		foreignMine: false,
		unsafe: false,
		includeLegacy: false,
		address: bitcoin.payments.p2wpkh({
			pubkey: coin.pubkey,
			network: bitcoin.networks.regtest
		}).address!,
		history: [] as Array<Record<string, unknown>>
	};
	const outpoint = `${coin.txidHex}:${coin.vout}`;
	const storage = {
		loadWalletData(name: string): string | null {
			return journal.get(name) ?? null;
		},
		saveWalletData(name: string, value: string): void {
			if (
				state.failSave ||
				(state.failOwnedSave && value.includes('"owned"'))
			) {
				throw new Error('Disk unavailable');
			}
			journal.set(name, value);
		}
	};
	const rpc: BitcoinCoreRpc = async (method, params = []) => {
		calls.push({ method, params });
		switch (method) {
			case 'getblockchaininfo':
				return { chain: state.chain, blocks: 109 };
			case 'listlockunspent':
				return [...locks].map((value) => {
					const [txid, output] = value.split(':');
					return { txid, vout: Number(output) };
				});
			case 'listunspent':
				return state.present
					? [
							...(!locks.has(outpoint)
								? [
										{
											txid: coin.txidHex,
											vout: coin.vout,
											amount: state.amount,
											scriptPubKey: coin.script.toString('hex'),
											confirmations: 10,
											spendable: true,
											solvable: true,
											safe: !state.unsafe
										}
								  ]
								: []),
							...(state.includeLegacy
								? [
										{
											txid: '11'.repeat(32),
											vout: 0,
											amount: 1,
											scriptPubKey: bitcoin.payments
												.p2pkh({ pubkey: coin.pubkey })
												.output!.toString('hex'),
											confirmations: 10,
											spendable: true,
											solvable: true,
											safe: true
										}
								  ]
								: [])
					  ]
					: [];
			case 'gettxout':
				return state.present
					? {
							value: state.amount,
							scriptPubKey: { hex: coin.script.toString('hex') },
							confirmations: 10
					  }
					: null;
			case 'listsinceblock':
				return { transactions: state.history };
			case 'gettransaction': {
				const result = transactions.get(String(params[0]));
				if (!result) throw missing();
				return result;
			}
			case 'getrawtransaction': {
				if (params[0] === coin.txidHex) return coin.prevTx.toHex();
				throw missing();
			}
			case 'getmempoolentry': {
				if (!mempool.has(String(params[0]))) throw missing();
				return { vsize: 100 };
			}
			case 'getrawchangeaddress':
				return state.address;
			case 'getaddressinfo':
				return { ismine: state.foreignMine };
			case 'lockunspent': {
				const values = params[1] as Array<{ txid: string; vout: number }>;
				expect(values).to.have.length(1);
				const value = `${values[0].txid}:${values[0].vout}`;
				if (params[0] === false) {
					if (state.lockRejected) throw new Error('Lock declined');
					locks.add(value);
					if (state.lostLockResponse) throw new Error('Connection reset');
				} else {
					locks.delete(value);
					if (state.lostUnlockResponse) throw new Error('Connection reset');
				}
				return true;
			}
			case 'walletprocesspsbt': {
				const psbt = bitcoin.Psbt.fromBase64(String(params[0]));
				psbt.signInput(0, {
					publicKey: coin.pubkey,
					sign: (hash: Buffer): Buffer =>
						Buffer.from(ecc.sign(hash, coin.privkey))
				});
				return { psbt: psbt.toBase64(), complete: false };
			}
			default:
				throw new Error(`Unexpected RPC ${method}`);
		}
	};
	const create = (): Promise<BitcoinCoreWalletAdapter> =>
		BitcoinCoreWalletAdapter.create({
			rpc,
			storage,
			network: Network.REGTEST
		});
	return {
		coin,
		journal,
		locks,
		transactions,
		mempool,
		calls,
		state,
		outpoint,
		storage,
		rpc,
		create
	};
}

async function rejected(
	operation: Promise<unknown>,
	text: string
): Promise<void> {
	try {
		await operation;
		expect.fail('Expected rejection');
	} catch (error) {
		expect(String(error)).to.include(text);
	}
}

describe('Bitcoin Core direct-funding wallet adapter', () => {
	it('loads exact satoshi amounts, preserves legacy ownership, and excludes unsafe coins', async () => {
		const h = harness();
		h.state.includeLegacy = true;
		const wallet = await h.create();
		expect(wallet.listSpendable()).to.have.length(1);
		expect(wallet.listSpendable()[0].valueSat).to.equal(200_001n);
		expect(wallet.blockHeight()).to.equal(109);
		expect(wallet.listSpendable()[0].height).to.equal(100);
		expect(wallet.ownsOutpoint('11'.repeat(32), 0)).to.equal(true);
		h.state.unsafe = true;
		await wallet.refresh();
		expect(wallet.listSpendable()).to.have.length(0);
	});

	it('converts scientific and string decimal amounts without fractional-satoshi rounding', async () => {
		const h = harness();
		h.state.amount = 1e-8;
		const wallet = await h.create();
		expect(wallet.listSpendable()[0].valueSat).to.equal(1n);
		h.state.amount = '0.12345678';
		await wallet.refresh();
		expect(wallet.listSpendable()[0].valueSat).to.equal(12_345_678n);
		h.state.amount = '0.000000001';
		await rejected(wallet.refresh(), 'Fractional satoshi');
		expect(wallet.listSpendable()[0].valueSat).to.equal(12_345_678n);
	});

	it('refuses the wrong chain before accessing wallet funds', async () => {
		const h = harness();
		h.state.chain = 'main';
		await rejected(h.create(), 'network');
		expect(h.calls.map((call) => call.method)).to.deep.equal([
			'getblockchaininfo'
		]);
	});

	it('does not mutate or release preexisting locks', async () => {
		const h = harness();
		h.locks.add(h.outpoint);
		const wallet = await h.create();
		expect(wallet.findCoin(h.coin.txidHex, 0)?.valueSat).to.equal(
			h.coin.valueSat
		);
		expect(wallet.listSpendable()).to.have.length(0);
		expect(await wallet.freezeUtxo(h.coin.txidHex, 0)).to.equal(false);
		expect(await wallet.unfreezeUtxo(h.coin.txidHex, 0)).to.equal(true);
		expect(h.locks.has(h.outpoint)).to.equal(true);
		expect(
			h.calls.filter((call) => call.method === 'lockunspent')
		).to.have.length(0);
	});

	it('persists reservation ownership and resumes a persistent lock after restart', async () => {
		const h = harness();
		const wallet = await h.create();
		expect(await wallet.freezeUtxo(h.coin.txidHex, 0)).to.equal(true);
		expect(
			h.calls.find((call) => call.method === 'lockunspent')?.params
		).to.deep.equal([false, [{ txid: h.coin.txidHex, vout: 0 }], true]);
		const restarted = await h.create();
		expect(restarted.findCoin(h.coin.txidHex, 0)).not.to.equal(null);
		expect(await restarted.freezeUtxo(h.coin.txidHex, 0)).to.equal(true);
		expect(await restarted.unfreezeUtxo(h.coin.txidHex, 0)).to.equal(true);
		expect(h.locks.has(h.outpoint)).to.equal(false);
		expect(JSON.parse(h.journal.get('df:core-reservations')!)).to.deep.equal(
			[]
		);
	});

	it('does not attempt a lock when the durable intent cannot be saved', async () => {
		const h = harness();
		const wallet = await h.create();
		h.state.failSave = true;
		expect(await wallet.freezeUtxo(h.coin.txidHex, 0)).to.equal(false);
		expect(
			h.calls.filter((call) => call.method === 'lockunspent')
		).to.have.length(0);
	});

	it('refuses an asynchronous reservation save before any lock RPC', async () => {
		const h = harness();
		const wallet = await BitcoinCoreWalletAdapter.create({
			rpc: h.rpc,
			network: Network.REGTEST,
			storage: {
				loadWalletData: h.storage.loadWalletData,
				// Runtime guard for a mistake that TypeScript's void return permits.
				// eslint-disable-next-line @typescript-eslint/no-misused-promises
				saveWalletData: async (): Promise<void> => {
					throw new Error('Asynchronous disk failure');
				}
			}
		});
		expect(await wallet.freezeUtxo(h.coin.txidHex, 0)).to.equal(false);
		expect(h.calls.some((call) => call.method === 'lockunspent')).to.equal(
			false
		);
		await new Promise((resolve) => setImmediate(resolve));
	});

	it('refuses an asynchronous reservation load and observes its rejection', async () => {
		const h = harness();
		await rejected(
			BitcoinCoreWalletAdapter.create({
				rpc: h.rpc,
				network: Network.REGTEST,
				storage: {
					loadWalletData: (() =>
						Promise.reject(new Error('Disk read failed'))) as unknown as (
						key: string
					) => string | null,
					saveWalletData: h.storage.saveWalletData
				}
			}),
			'load synchronously'
		);
		expect(h.calls).to.have.length(0);
		await new Promise((resolve) => setImmediate(resolve));
	});

	it('quarantines a lost acquisition response across restart and never unlocks it', async () => {
		const h = harness();
		h.state.lostLockResponse = true;
		const wallet = await h.create();
		expect(await wallet.freezeUtxo(h.coin.txidHex, 0)).to.equal(false);
		const restarted = await h.create();
		expect(restarted.unresolvedReservations()).to.deep.equal([
			{ txid: h.coin.txidHex, vout: 0 }
		]);
		expect(await restarted.freezeUtxo(h.coin.txidHex, 0)).to.equal(false);
		expect(await restarted.unfreezeUtxo(h.coin.txidHex, 0)).to.equal(false);
		expect(h.locks.has(h.outpoint)).to.equal(true);
	});

	it('quarantines an acquired lock if its ownership commit fails', async () => {
		const h = harness();
		h.state.failOwnedSave = true;
		const wallet = await h.create();
		expect(await wallet.freezeUtxo(h.coin.txidHex, 0)).to.equal(false);
		expect(wallet.unresolvedReservations()).to.have.length(1);
		expect(await wallet.unfreezeUtxo(h.coin.txidHex, 0)).to.equal(false);
	});

	it('clears a rejected acquisition only after observing no Core lock', async () => {
		const h = harness();
		h.state.lockRejected = true;
		const wallet = await h.create();
		expect(await wallet.freezeUtxo(h.coin.txidHex, 0)).to.equal(false);
		expect(wallet.unresolvedReservations()).to.have.length(0);
		expect(wallet.listSpendable()).to.have.length(1);
	});

	it('reconciles a lost unlock response without broad wallet unlocks', async () => {
		const h = harness();
		const wallet = await h.create();
		expect(await wallet.freezeUtxo(h.coin.txidHex, 0)).to.equal(true);
		h.state.lostUnlockResponse = true;
		expect(await wallet.unfreezeUtxo(h.coin.txidHex, 0)).to.equal(true);
		expect(h.locks.size).to.equal(0);
	});

	it('waits for reservation cleanup to finish before storage can be closed', async () => {
		const h = harness();
		let release!: () => void;
		const gate = new Promise<void>((resolve) => {
			release = resolve;
		});
		const wallet = await BitcoinCoreWalletAdapter.create({
			rpc: async (method, params) => {
				if (method === 'lockunspent' && params?.[0] === true) await gate;
				return h.rpc(method, params);
			},
			storage: h.storage,
			network: Network.REGTEST
		});
		expect(await wallet.freezeUtxo(h.coin.txidHex, 0)).to.equal(true);
		const unlocking = wallet.unfreezeUtxo(h.coin.txidHex, 0);
		let drained = false;
		const draining = wallet.waitForIdle().then(() => {
			drained = true;
		});
		await new Promise((resolve) => setImmediate(resolve));
		expect(drained).to.equal(false);
		expect(h.locks.has(h.outpoint)).to.equal(true);
		release();
		await draining;
		expect(await unlocking).to.equal(true);
		expect(h.locks.size).to.equal(0);
		expect(JSON.parse(h.journal.get('df:core-reservations')!)).to.deep.equal(
			[]
		);
	});

	it('fails closed on corrupt reservation state', async () => {
		const h = harness();
		h.journal.set('df:core-reservations', '{');
		await rejected(h.create(), 'SyntaxError');
		h.journal.set(
			'df:core-reservations',
			'[{"txid":"bad","vout":0,"state":"owned"}]'
		);
		await rejected(h.create(), 'transaction id');
	});

	it('falls back to raw transaction lookup and verifies the returned txid', async () => {
		const h = harness();
		const wallet = await h.create();
		h.transactions.delete(h.coin.txidHex);
		expect(
			(await wallet.getTransaction(h.coin.txidHex)).equals(
				h.coin.prevTx.toBuffer()
			)
		).to.equal(true);
		h.transactions.set('22'.repeat(32), { hex: h.coin.prevTx.toHex() });
		await rejected(wallet.getTransaction('22'.repeat(32)), 'wrong transaction');
	});

	it('gets a fresh change script on the expected network', async () => {
		const h = harness();
		const wallet = await h.create();
		expect((await wallet.changeScript()).equals(h.coin.script)).to.equal(true);
		h.state.address = bitcoin.payments.p2wpkh({
			pubkey: h.coin.pubkey
		}).address!;
		await rejected(wallet.changeScript(), 'invalid prefix');
	});

	it('does not treat a retained but evicted parent as positive spend evidence', async () => {
		const h = harness();
		const wallet = await h.create();
		h.state.present = false;
		h.transactions.set(h.coin.txidHex, {
			hex: h.coin.prevTx.toHex(),
			confirmations: 0
		});
		expect(await wallet.spentOnChain(h.coin)).to.equal(false);
		h.transactions.set(h.coin.txidHex, {
			hex: h.coin.prevTx.toHex(),
			confirmations: 10
		});
		expect(await wallet.spentOnChain(h.coin)).to.equal(true);
	});

	it('tracks mempool and confirmed transactions, and confirmed conflicts only', async () => {
		const h = harness();
		const wallet = await h.create();
		const spend = new bitcoin.Transaction();
		spend.addInput(Buffer.from(h.coin.txidHex, 'hex').reverse(), 0);
		spend.addOutput(h.coin.script, 190_000);
		const id = spend.getId();
		h.transactions.set(id, { hex: spend.toHex(), confirmations: 0 });
		h.state.history = [{ txid: id, confirmations: 0, category: 'send' }];
		await wallet.refresh([id]);
		expect(wallet.txStatus(id)).to.deep.equal({
			known: false,
			confirmed: false
		});
		expect(wallet.confirmedSpendOf(h.coin.txidHex, 0)).to.equal(null);
		h.mempool.add(id);
		await wallet.refresh();
		expect(wallet.txStatus(id)).to.deep.equal({
			known: true,
			confirmed: false
		});
		h.transactions.set(id, { hex: spend.toHex(), confirmations: 1 });
		h.state.history = [{ txid: id, confirmations: 1, category: 'send' }];
		await wallet.refresh();
		expect(wallet.txStatus(id)).to.deep.equal({ known: true, confirmed: true });
		expect(wallet.confirmedSpendOf(h.coin.txidHex, 0)).to.equal(id);
		h.transactions.set(id, { hex: spend.toHex(), confirmations: -1 });
		h.state.history = [{ txid: id, confirmations: -1, category: 'send' }];
		await wallet.refresh();
		expect(wallet.txStatus(id)).to.deep.equal({
			known: false,
			confirmed: false
		});
		expect(wallet.confirmedSpendOf(h.coin.txidHex, 0)).to.equal(null);
	});

	it('signs an ownership probe using Core PSBT RPC without broadcasting', async () => {
		const h = harness();
		const wallet = await h.create();
		const signer = wallet.signerFor(h.coin)!;
		const probe = ownershipProbeTransaction(
			Buffer.alloc(16, 1),
			Buffer.from(h.coin.txidHex, 'hex'),
			0,
			0xfffffffd,
			h.coin.script,
			h.coin.valueSat,
			Buffer.alloc(32, 2),
			h.coin.pubkey
		);
		const proof = await signer.signOwnershipProbe!(probe.tx, probe.prevouts);
		expect(proof.signature).to.have.length(64);
		expect(proof.pubkey.equals(h.coin.pubkey)).to.equal(true);
		const call = h.calls.find((item) => item.method === 'walletprocesspsbt')!;
		expect(call.params.slice(1)).to.deep.equal([true, 'ALL', false, false]);
		expect(
			h.calls.some((item) => item.method === 'sendrawtransaction')
		).to.equal(false);
	});

	it('refuses a second payer input discovered immediately before Core signing', async () => {
		const h = harness();
		const wallet = await h.create();
		h.state.foreignMine = true;
		const tx = new bitcoin.Transaction();
		tx.addInput(Buffer.from(h.coin.txidHex, 'hex').reverse(), 0);
		tx.addInput(Buffer.alloc(32, 7), 0);
		tx.addOutput(h.coin.script, 190_000);
		await rejected(
			Promise.resolve(
				wallet.signerFor(h.coin)!.signInput(tx, 0, {
					scripts: [h.coin.script, h.coin.script],
					values: [h.coin.valueSat, 1_000n]
				})
			),
			'Additional input'
		);
		expect(
			h.calls.some((item) => item.method === 'walletprocesspsbt')
		).to.equal(false);
	});
});
