import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import {
	OnchainSweeps,
	ONCHAIN_SWEEPS_KEY,
	OnchainSweepRequest
} from '../../src/cli/onchain-sweep';
import { ok, err } from '../../src/utils/result';
import { BeignetNode, DAILY_SPEND_STATE_KEY } from '../../src/cli/beignet-node';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';

const ADDRESS = bitcoin.payments.p2wpkh({
	pubkey: Buffer.from(
		'0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
		'hex'
	),
	network: bitcoin.networks.regtest
}).address!;
const COIN = { tx_hash: 'ab'.repeat(32), tx_pos: 0, value: 10000 };
const FREEZE_KEY = 'sweep-test-regtest-blacklistedUtxos';
const REQUEST: OnchainSweepRequest = {
	requestId: 'drain-sweep-one',
	address: ADDRESS,
	satsPerVbyte: 2,
	inputOutpoints: [{ txid: COIN.tx_hash, vout: 0 }],
	debitSats: 10000,
	maxFeeSats: 250
};

function harness(storageOverride?: SqliteStorage) {
	const data = new Map<string, string>();
	let failSave: ((value: string) => boolean) | undefined;
	let failBroadcast = false;
	let failRelease = false;
	let buildFee = 200;
	let builds = 0;
	let charges = 0;
	const broadcasts: string[] = [];
	let inputs = [COIN];
	let outputAddress = ADDRESS;
	const coins = [COIN];
	const frozen: Array<typeof COIN & { freezeTag?: string }> = [];
	const transactions: Record<string, { height?: number; exists?: boolean }> =
		{};
	const wallet = {
		data: { utxos: coins },
		isWatchOnly: false,
		isMultisig: false,
		transactions,
		getWalletDataKey: () => FREEZE_KEY,
		listFrozenUtxos: () => frozen,
		freezeUtxoIfUnfrozen: async ({
			txid,
			index,
			tag
		}: {
			txid: string;
			index: number;
			tag?: string;
		}) => {
			if (frozen.some((coin) => coin.tx_hash === txid && coin.tx_pos === index))
				return ok({ created: false });
			const coin = coins.find(
				(item) => item.tx_hash === txid && item.tx_pos === index
			);
			if (!coin) return err('Unknown input');
			frozen.push({ ...coin, freezeTag: tag });
			storage.saveWalletData(FREEZE_KEY, JSON.stringify(frozen));
			return ok({ created: true });
		},
		unfreezeUtxoIfTagged: async ({
			txid,
			index,
			tag
		}: {
			txid: string;
			index: number;
			tag: string;
		}) => {
			if (failRelease) return err('disk full');
			const found = frozen.findIndex(
				(coin) =>
					coin.tx_hash === txid &&
					coin.tx_pos === index &&
					coin.freezeTag === tag
			);
			if (found >= 0) frozen.splice(found, 1);
			storage.saveWalletData(FREEZE_KEY, JSON.stringify(frozen));
			return ok({ unfrozen: found >= 0 });
		},
		resetSendTransaction: async () => ok('reset'),
		transaction: {
			setupTransaction: async ({ utxos }: { utxos: typeof inputs }) => {
				inputs = utxos;
				return ok({});
			},
			sendMax: async ({ address }: { address: string }) => {
				outputAddress = address;
				return ok('ready');
			},
			createTransaction: async () => {
				builds++;
				const tx = new bitcoin.Transaction();
				for (const coin of inputs) {
					tx.addInput(Buffer.from(coin.tx_hash, 'hex').reverse(), coin.tx_pos);
					tx.setWitness(tx.ins.length - 1, [
						Buffer.alloc(72, 1),
						Buffer.alloc(33, 2)
					]);
				}
				tx.addOutput(
					bitcoin.address.toOutputScript(
						outputAddress,
						bitcoin.networks.regtest
					),
					inputs.reduce((sum, coin) => sum + coin.value, 0) - buildFee
				);
				return ok({ hex: tx.toHex() });
			}
		}
	};
	const storage = storageOverride ?? {
		loadWalletData: (key: string) => data.get(key) ?? null,
		saveWalletData: (key: string, value: string) => {
			if (failSave?.(value)) throw new Error('disk full');
			data.set(key, value);
		}
	};
	const create = () =>
		new OnchainSweeps({
			storage,
			wallet: wallet as unknown as ConstructorParameters<
				typeof OnchainSweeps
			>[0]['wallet'],
			network: bitcoin.networks.regtest,
			broadcast: async (hex) => {
				const stored = JSON.parse(
					storage.loadWalletData(ONCHAIN_SWEEPS_KEY)!
				)[0];
				expect(stored.status).to.equal('submitted');
				expect(stored.hex).to.equal(hex);
				broadcasts.push(hex);
				if (failBroadcast) throw new Error('Connection ended after broadcast');
			},
			admitAndSave: (_amount, save) => {
				save();
				charges++;
			}
		});
	return {
		create,
		storage,
		data,
		wallet,
		coins,
		frozen,
		broadcasts,
		transactions,
		builds: () => builds,
		charges: () => charges,
		failSave: (fn?: typeof failSave) => {
			failSave = fn;
		},
		failBroadcast: (value: boolean) => {
			failBroadcast = value;
		},
		failRelease: (value: boolean) => {
			failRelease = value;
		},
		fee: (value: number) => {
			buildFee = value;
		}
	};
}

async function rejectsCode(
	work: Promise<unknown>,
	code: string
): Promise<void> {
	try {
		await work;
		expect.fail('Expected refusal');
	} catch (error) {
		expect((error as { code: string }).code).to.equal(code);
	}
}

describe('Durable on-chain sweep', () => {
	it('prepares privately and retries the exact signed transaction after a lost broadcast and restart', async () => {
		const h = harness();
		const prepared = await h.create().prepare(REQUEST);
		expect(prepared.status).to.equal('prepared');
		expect(prepared.amountSats).to.equal(9800);
		expect(prepared).not.to.have.property('hex');
		expect(h.broadcasts).to.deep.equal([]);
		h.coins.push({ tx_hash: 'cd'.repeat(32), tx_pos: 1, value: 5000 });
		h.failBroadcast(true);
		const first = await h.create().submit(REQUEST.requestId);
		expect(first.status).to.equal('submitted');
		expect(first.error).to.contain('Connection ended');
		h.coins.splice(0, 1);
		h.failBroadcast(false);
		const second = await h.create().submit(REQUEST.requestId);
		expect(second.txid).to.equal(prepared.txid);
		expect(second.amountSats).to.equal(9800);
		expect(h.broadcasts[1]).to.equal(h.broadcasts[0]);
		expect(h.builds()).to.equal(1);
		expect(h.charges()).to.equal(1);
		expect(bitcoin.Transaction.fromHex(h.broadcasts[1]).ins).to.have.length(1);
	});

	it('a crash after broadcast but before result persistence still recovers the stored transaction', async () => {
		const h = harness();
		await h.create().prepare(REQUEST);
		h.failSave((value) => JSON.parse(value)[0].broadcastAccepted === true);
		try {
			await h.create().submit(REQUEST.requestId);
			expect.fail('Expected failed save');
		} catch (error) {
			expect((error as Error).message).to.equal('disk full');
		}
		h.failSave();
		await h.create().submit(REQUEST.requestId);
		expect(h.broadcasts[1]).to.equal(h.broadcasts[0]);
		expect(h.charges()).to.equal(1);
		expect(h.builds()).to.equal(1);
	});

	it('failed persistence before either signature publication or broadcast sends nothing', async () => {
		const h = harness();
		h.failSave((value) => JSON.parse(value)[0].status === 'prepared');
		try {
			await h.create().prepare(REQUEST);
			expect.fail('Expected failed save');
		} catch (error) {
			expect((error as Error).message).to.equal('disk full');
		}
		expect(h.create().get(REQUEST.requestId)?.status).to.equal('preparing');
		expect(h.broadcasts).to.deep.equal([]);
		h.failSave();
		await h.create().prepare(REQUEST);
		h.failSave((value) => JSON.parse(value)[0].status === 'submitted');
		try {
			await h.create().submit(REQUEST.requestId);
			expect.fail('Expected failed save');
		} catch (error) {
			expect((error as Error).message).to.equal('disk full');
		}
		expect(h.broadcasts).to.deep.equal([]);
		expect(h.charges()).to.equal(0);
		expect(h.create().get(REQUEST.requestId)?.status).to.equal('prepared');
	});

	it('a request identity cannot acquire another destination, budget or input set', async () => {
		const h = harness();
		await h.create().prepare(REQUEST);
		for (const changed of [
			{ maxFeeSats: 251 },
			{ debitSats: 10001 },
			{ inputOutpoints: [{ txid: 'cd'.repeat(32), vout: 0 }] }
		])
			await rejectsCode(
				h.create().prepare({ ...REQUEST, ...changed }),
				'REQUEST_ID_CONFLICT'
			);
		await h.create().prepare(REQUEST);
		expect(h.builds()).to.equal(1);
	});

	it('foreign, frozen and funding-pledged inputs are refused without signing', async () => {
		for (const freezeTag of [
			undefined,
			'funding-pledge',
			'onchain-sweep:other-request'
		]) {
			const h = harness();
			h.frozen.push({ ...COIN, freezeTag });
			await rejectsCode(h.create().prepare(REQUEST), 'SWEEP_INPUT_UNAVAILABLE');
			expect(h.builds()).to.equal(0);
			expect(h.data.size).to.equal(0);
		}
		const h = harness();
		await rejectsCode(
			h.create().prepare({
				...REQUEST,
				inputOutpoints: [{ txid: 'ef'.repeat(32), vout: 0 }]
			}),
			'SWEEP_INPUT_UNAVAILABLE'
		);
		await rejectsCode(
			h.create().prepare({ ...REQUEST, debitSats: 10001 }),
			'SWEEP_QUOTE_EXPIRED'
		);
		expect(h.builds()).to.equal(0);
	});

	it('a fee beyond the review remains unsubmitted and can release only its own reservations', async () => {
		const h = harness();
		h.fee(300);
		await rejectsCode(h.create().prepare(REQUEST), 'SWEEP_QUOTE_EXPIRED');
		expect(h.frozen).to.have.length(1);
		expect((await h.create().cancel(REQUEST.requestId)).status).to.equal(
			'cancelled'
		);
		expect(h.frozen).to.have.length(0);
		expect(h.broadcasts).to.deep.equal([]);
		expect((await h.create().prepare(REQUEST)).status).to.equal('cancelled');
	});

	it('submitted sweeps cannot be cancelled and keep their reservations across confirmation and reorg', async () => {
		const h = harness();
		const prepared = await h.create().prepare(REQUEST);
		await h.create().submit(REQUEST.requestId);
		await rejectsCode(
			h.create().cancel(REQUEST.requestId),
			'SWEEP_ALREADY_SUBMITTED'
		);
		h.transactions[prepared.txid!] = { height: 10 };
		expect(h.create().get(REQUEST.requestId)?.status).to.equal('confirmed');
		await h.create().submit(REQUEST.requestId);
		expect(h.broadcasts).to.have.length(1);
		expect(h.frozen).to.have.length(1);
		h.transactions[prepared.txid!] = { height: 0 };
		expect(h.create().get(REQUEST.requestId)?.status).to.equal('submitted');
		await h.create().submit(REQUEST.requestId);
		expect(h.frozen).to.have.length(1);
		expect(h.broadcasts[1]).to.equal(h.broadcasts[0]);
		expect(h.charges()).to.equal(1);
	});

	it('malformed or altered journal transactions fail closed', async () => {
		const h = harness();
		await h.create().prepare(REQUEST);
		const saved = JSON.parse(h.data.get(ONCHAIN_SWEEPS_KEY)!);
		saved[0].amountSats++;
		h.data.set(ONCHAIN_SWEEPS_KEY, JSON.stringify(saved));
		await rejectsCode(
			h.create().submit(REQUEST.requestId),
			'SWEEP_JOURNAL_INVALID'
		);
		expect(h.broadcasts).to.deep.equal([]);
	});

	it('database replacement waits until every active sweep has resolved or been cancelled', async () => {
		const h = harness();
		h.create().assertRestorable();
		await h.create().prepare(REQUEST);
		expect(() => h.create().assertRestorable()).to.throw('Resolve or cancel');
		await h.create().cancel(REQUEST.requestId);
		h.create().assertRestorable();
		await h.create().prepare({ ...REQUEST, requestId: 'second-drain-sweep' });
		const sent = await h.create().submit('second-drain-sweep');
		expect(() => h.create().assertRestorable()).to.throw('Resolve or cancel');
		h.transactions[sent.txid!] = { height: 10 };
		await h.create().submit('second-drain-sweep');
		h.create().assertRestorable();
		h.transactions[sent.txid!] = { height: 0 };
		expect(() => h.create().assertRestorable()).to.throw('Resolve or cancel');
	});

	it('mempool, missing and nonfinite transaction heights never release reservations', async () => {
		for (const transaction of [
			{ height: -1 },
			{ height: 0 },
			{ height: Infinity },
			{ height: NaN },
			{ height: 10, exists: false }
		]) {
			const h = harness();
			const prepared = await h.create().prepare(REQUEST);
			await h.create().submit(REQUEST.requestId);
			h.transactions[prepared.txid!] = transaction;
			expect(h.create().get(REQUEST.requestId)?.status).to.equal('submitted');
			expect((await h.create().submit(REQUEST.requestId)).status).to.equal(
				'submitted'
			);
			expect(h.frozen).to.have.length(1);
			expect(h.broadcasts).to.have.length(2);
			expect(h.broadcasts[1]).to.equal(h.broadcasts[0]);
			expect(h.charges()).to.equal(1);
		}
	});

	it('interrupted cancellation remains pending until its reservations are released', async () => {
		const h = harness();
		await h.create().prepare(REQUEST);
		h.failRelease(true);
		await rejectsCode(
			h.create().cancel(REQUEST.requestId),
			'SWEEP_NOT_PERSISTED'
		);
		expect(h.create().get(REQUEST.requestId)?.status).to.equal('cancelling');
		expect(() => h.create().assertRestorable()).to.throw('Resolve or cancel');
		await rejectsCode(
			h.create().submit(REQUEST.requestId),
			'SWEEP_NOT_PREPARED'
		);
		expect(h.frozen).to.have.length(1);
		h.failRelease(false);
		expect((await h.create().cancel(REQUEST.requestId)).status).to.equal(
			'cancelled'
		);
		expect(h.frozen).to.have.length(0);
		h.create().assertRestorable();
		expect(h.broadcasts).to.deep.equal([]);
	});

	it('database replacement preserves confirmed sweep ownership and refuses missing or conflicting reservations', async () => {
		const h = harness();
		const prepared = await h.create().prepare(REQUEST);
		await h.create().submit(REQUEST.requestId);
		h.transactions[prepared.txid!] = { height: 10 };
		await h.create().submit(REQUEST.requestId);
		const rows = new Map<string, string>();
		const unrelated = {
			...COIN,
			tx_hash: 'cd'.repeat(32),
			freezeTag: 'user-freeze'
		};
		rows.set(FREEZE_KEY, JSON.stringify([unrelated]));
		const target = {
			loadWalletData: (key: string) => rows.get(key) ?? null,
			saveWalletData: (key: string, value: string) => {
				rows.set(key, value);
			},
			transaction: <T>(fn: () => T): T => fn()
		};
		h.create().carryTo(target);
		h.create().carryTo(target);
		expect(JSON.parse(rows.get(FREEZE_KEY)!)).to.deep.equal([
			unrelated,
			...h.frozen
		]);
		expect(rows.get(ONCHAIN_SWEEPS_KEY)).to.equal(
			h.data.get(ONCHAIN_SWEEPS_KEY)
		);
		rows.set(
			FREEZE_KEY,
			JSON.stringify([{ ...COIN, freezeTag: 'another-owner' }])
		);
		expect(() => h.create().carryTo(target)).to.throw('another reservation');
		rows.delete(FREEZE_KEY);
		h.data.delete(FREEZE_KEY);
		expect(() => h.create().carryTo(target)).to.throw(
			'missing its durable input reservation'
		);
	});

	it('the daemon commits its spend ledger and submission together, then rebroadcasts without charging again', async () => {
		for (const failingWrite of ['journal', 'spend']) {
			const storage = new SqliteStorage(':memory:');
			storage.open();
			try {
				const h = harness(storage);
				const internal = Object.assign(Object.create(BeignetNode.prototype), {
					storage,
					wallet: h.wallet,
					getBitcoinNetwork: () => bitcoin.networks.regtest,
					_onchainSendLock: Promise.resolve(),
					_dailySpendLimitSats: 10000,
					_dailySpentSats: 0,
					_dailySpentOnchainSats: 0,
					_dailySpentLightningSats: 0,
					_pendingSpendSats: 0,
					_asyncSpendClaims: new Map(),
					_dailySpendResetTime: Date.now() + 86400000,
					log: () => {},
					_broadcastRawTx: async (hex: string) => {
						h.broadcasts.push(hex);
					}
				});
				const node = internal as BeignetNode;
				await node.prepareOnchainSweep(REQUEST);
				await rejectsCode(
					node.freezeUtxo(COIN.tx_hash, COIN.tx_pos),
					'SWEEP_INPUT_RESERVED'
				);
				await rejectsCode(
					node.unfreezeUtxo(COIN.tx_hash, COIN.tx_pos),
					'SWEEP_INPUT_RESERVED'
				);
				const saveWallet = storage.saveWalletData.bind(storage);
				const saveMetadata = storage.saveMetadata.bind(storage);
				storage.saveWalletData = (key, value) => {
					if (failingWrite === 'journal' && key === ONCHAIN_SWEEPS_KEY)
						throw new Error('journal unavailable');
					return saveWallet(key, value);
				};
				storage.saveMetadata = (key, value) => {
					if (failingWrite === 'spend') throw new Error('spend unavailable');
					return saveMetadata(key, value);
				};
				try {
					await node.submitOnchainSweep(REQUEST.requestId);
					expect.fail('Expected durable write failure');
				} catch (error) {
					expect((error as Error).message).to.contain('unavailable');
				}
				expect(node.getOnchainSweep(REQUEST.requestId)?.status).to.equal(
					'prepared'
				);
				expect(internal._dailySpentSats).to.equal(0);
				expect(internal._dailySpentOnchainSats).to.equal(0);
				expect(storage.loadMetadata(DAILY_SPEND_STATE_KEY)).to.equal(null);
				expect(h.broadcasts).to.have.length(0);
				storage.saveWalletData = saveWallet;
				storage.saveMetadata = saveMetadata;
				await node.submitOnchainSweep(REQUEST.requestId);
				await node.submitOnchainSweep(REQUEST.requestId);
				await rejectsCode(
					node.freezeUtxo(COIN.tx_hash, COIN.tx_pos),
					'SWEEP_INPUT_RESERVED'
				);
				await rejectsCode(
					node.unfreezeUtxo(COIN.tx_hash, COIN.tx_pos),
					'SWEEP_INPUT_RESERVED'
				);
				expect(internal._dailySpentSats).to.equal(10000);
				expect(
					JSON.parse(storage.loadMetadata(DAILY_SPEND_STATE_KEY)!).totalSats
				).to.equal(10000);
				expect(h.broadcasts).to.have.length(2);
				expect(h.broadcasts[1]).to.equal(h.broadcasts[0]);
			} finally {
				storage.close();
			}
		}
	});
});
