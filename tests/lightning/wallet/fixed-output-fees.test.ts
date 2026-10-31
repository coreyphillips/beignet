import { expect } from 'chai';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { SqliteStorage } from '../../../src/lightning/storage/sqlite-storage';
import * as bitcoin from 'bitcoinjs-lib';
import { getECPair } from '../../../src/utils/ecc-apis';
import { ecc } from '../../../src/utils/ecc';
import {
	WalletFundingProvider,
	IWalletLike,
	ISpliceUtxo
} from '../../../src/lightning/wallet/wallet-funding-provider';
import {
	IFixedOutputFeePolicy,
	FixedOutputFeePreparationPendingError
} from '../../../src/lightning/wallet/fixed-output-fees';
import { ILedgerKeyValueStorage } from '../../../src/lightning/storage/durable-ledger';
import { attachFeeInputsToZeroFeeHtlcTx } from '../../../src/lightning/chain/sweep';
import { fixedOutputHtlcFeeActionId } from '../../../src/lightning/chain/types';
bitcoin.initEccLib(ecc);
const ok = <T>(
	value: T
): { isErr: () => boolean; isOk: () => boolean; value: T } => ({
	isErr: () => false,
	isOk: () => true,
	value
});
const err = (): {
	isErr: () => boolean;
	isOk: () => boolean;
	error: { message: string };
} => ({
	isErr: () => true,
	isOk: () => false,
	error: { message: 'injected failure' }
});
class Store implements ILedgerKeyValueStorage {
	rows = new Map<string, string>();
	refuse?: (value: string) => boolean;
	loadMetadata(key: string): string | null {
		return this.rows.get(key) ?? null;
	}
	saveMetadata(key: string, value: string): void {
		if (this.refuse?.(value)) throw new Error('journal refusal');
		this.rows.set(key, value);
	}
	transaction<T>(fn: () => T): T {
		const saved = new Map(this.rows);
		try {
			return fn();
		} catch (error) {
			this.rows = saved;
			throw error;
		}
	}
}
function fixture(): {
	wallet: IWalletLike;
	store: Store;
	policy: IFixedOutputFeePolicy;
	provider: () => WalletFundingProvider;
	parent: bitcoin.Transaction;
	payment: bitcoin.payments.Payment;
	asset: {
		tx_hash: string;
		address: string;
		value: number;
		path: string;
		tx_pos: number;
		height: number;
		publicKey: string;
	};
	frozen: Map<string, { freezeTag?: string | undefined; frozenAt: number }>;
	broadcasts: string[];
	signedTransactions: string[];
	counts: () => { signCalls: number };
	failure: (
		kind: 'sign' | 'broadcast' | 'visibility',
		active?: boolean
	) => void;
	confirm: () => void;
	coins: () => ISpliceUtxo[];
	spendSource: () => void;
	addCoin: (value?: number) => {
		tx_hash: string;
		value: number;
		address: string;
		path: string;
		tx_pos: number;
		height: number;
		publicKey: string;
	};
	journal: () => {
		actions: Record<string, { cap: string; inputs: unknown[] }>;
		preparations: { state: string; unsigned?: string; signed?: string }[];
	};
} {
	const owner = getECPair().fromPrivateKey(Buffer.alloc(32, 45), {
		network: bitcoin.networks.regtest
	});
	const publicKey = Buffer.from(owner.publicKey),
		payment = bitcoin.payments.p2wpkh({
			pubkey: publicKey,
			network: bitcoin.networks.regtest
		});
	const parent = new bitcoin.Transaction();
	parent.addInput(Buffer.alloc(32, 13), 0);
	parent.addOutput(payment.output!, 50000);
	const original: ISpliceUtxo = {
		address: payment.address!,
		path: "m/84'/1'/0'/1/0",
		publicKey: publicKey.toString('hex'),
		tx_hash: parent.getId(),
		tx_pos: 0,
		value: 50000,
		height: 100
	};
	const asset = {
		...original,
		tx_hash: 'aa'.repeat(32),
		address: bitcoin.payments.p2tr({
			internalPubkey: publicKey.subarray(1),
			network: bitcoin.networks.regtest
		}).address!,
		value: 100000
	};
	let locked = false;
	let coins = [original, asset],
		signCalls = 0;
	let failSign = false,
		failBroadcast = false,
		hideOutputs = false;
	const frozen = new Map<string, { freezeTag?: string; frozenAt: number }>(),
		transactions = new Map([[parent.getId(), parent]]),
		broadcasts: string[] = [],
		signedTransactions: string[] = [];
	frozen.set(`${asset.tx_hash}:0`, {
		freezeTag: 'asset-anchor',
		frozenAt: Date.now()
	});
	const store = new Store();
	const wallet: IWalletLike = {
		id: 'fixed-fee-wallet',
		network: 'regtest',
		send: async () => ok(''),
		withSendLock: async (fn) => {
			if (locked) throw new Error('nested send lock');
			locked = true;
			try {
				return await fn();
			} finally {
				locked = false;
			}
		},
		listUtxos: () => coins.map((c) => ({ ...c })),
		refreshWallet: async () => ok(''),
		getPrivateKey: (path) => {
			if (path !== "m/84'/1'/0'/1/0") throw new Error('unknown key');
			return owner.toWIF();
		},
		getChangeAddress: async () => ok({ address: payment.address! }),
		getAddressFromScriptHash: (hash) =>
			hash ===
			Buffer.from(bitcoin.crypto.sha256(payment.output!))
				.reverse()
				.toString('hex')
				? {
						address: payment.address!,
						path: "m/84'/1'/0'/1/0",
						publicKey: publicKey.toString('hex')
				  }
				: undefined,
		isUtxoFrozen: (txid, index) => frozen.has(`${txid}:${index}`),
		listFrozenUtxos: () =>
			[...frozen].map(([key, value]) => ({
				tx_hash: key.split(':')[0],
				tx_pos: Number(key.split(':')[1]),
				...value
			})),
		freezeUtxoIfUnfrozen: async ({ txid, index, tag }) => {
			const key = `${txid}:${index}`,
				created = !frozen.has(key);
			if (created) frozen.set(key, { freezeTag: tag, frozenAt: Date.now() });
			return ok({ created });
		},
		unfreezeUtxoIfTagged: async ({ txid, index, tag }) => {
			const key = `${txid}:${index}`,
				unfrozen = frozen.get(key)?.freezeTag === tag;
			if (unfrozen) frozen.delete(key);
			return ok({ unfrozen });
		},
		signPsbtWithOurKey: (raw) => {
			signCalls++;
			if (failSign) return err();
			const psbt = bitcoin.Psbt.fromBase64(raw);
			psbt.signInput(0, owner);
			return ok(psbt.toBase64());
		},
		importSignedPsbt: (signed, unsigned) => {
			const psbt = bitcoin.Psbt.fromBase64(signed);
			expect(
				psbt.data
					.getTransaction()
					.equals(bitcoin.Psbt.fromBase64(unsigned!).data.getTransaction())
			).equal(true);
			psbt.finalizeAllInputs();
			const tx = psbt.extractTransaction();
			signedTransactions.push(tx.toHex());
			return ok({ txHex: tx.toHex(), txid: tx.getId() });
		},
		electrum: {
			getTransactions: async ({ txHashes }) =>
				ok({
					data: txHashes.map(({ tx_hash }) => ({
						data: { tx_hash },
						result: { txid: tx_hash, hex: transactions.get(tx_hash)?.toHex() }
					}))
				}),
			broadcastTransaction: async ({ rawTx }) => {
				broadcasts.push(rawTx);
				if (failBroadcast) return err();
				const tx = bitcoin.Transaction.fromHex(rawTx);
				transactions.set(tx.getId(), tx);
				coins = coins.filter(
					(c) =>
						!tx.ins.some(
							(input) =>
								Buffer.from(input.hash).reverse().toString('hex') ===
									c.tx_hash && input.index === c.tx_pos
						)
				);
				if (!hideOutputs)
					for (let i = 0; i < tx.outs.length; i++)
						if (tx.outs[i].script.equals(payment.output!))
							coins.push({
								...original,
								tx_hash: tx.getId(),
								tx_pos: i,
								value: tx.outs[i].value,
								height: 0
							});
				return ok(tx.getId());
			}
		}
	};
	const policy: IFixedOutputFeePolicy = {
		storage: store,
		maxFeeSatoshis: 2000n,
		maxTotalFeeSatoshis: 20000n,
		maxPreparationFeeSatoshis: 1000n
	};
	const provider = (): WalletFundingProvider =>
		new WalletFundingProvider(wallet, { fixedOutputFees: policy });
	return {
		wallet,
		store,
		policy,
		provider,
		parent,
		payment,
		asset,
		frozen,
		broadcasts,
		signedTransactions,
		counts: (): { signCalls: number } => ({ signCalls }),
		failure: (
			kind: 'sign' | 'broadcast' | 'visibility',
			active = true
		): void => {
			if (kind === 'sign') failSign = active;
			else if (kind === 'broadcast') failBroadcast = active;
			else hideOutputs = active;
		},
		confirm: (): void => {
			coins = coins.map((c) => ({ ...c, height: 101 }));
		},
		coins: (): ISpliceUtxo[] => coins,
		spendSource: (): void => {
			coins = coins.filter((c) => c.tx_hash !== parent.getId());
		},
		addCoin: (value = 50000): ISpliceUtxo => {
			const tx = new bitcoin.Transaction();
			tx.addInput(Buffer.alloc(32, 25), transactions.size);
			tx.addOutput(payment.output!, value);
			transactions.set(tx.getId(), tx);
			const coin = { ...original, tx_hash: tx.getId(), value };
			coins.push(coin);
			return coin;
		},
		journal: () => JSON.parse([...store.rows.values()][0])
	};
}
const opts = {
	fixedOutputs: true,
	feeActionId: 'asset-htlc:channel:original:0'
};
async function reject(promise: Promise<unknown>, part: string): Promise<void> {
	let message = '';
	try {
		await promise;
	} catch (error) {
		message = (error as Error).message;
	}
	expect(message).contains(part);
}
async function prepare(provider: WalletFundingProvider): Promise<void> {
	try {
		await provider.selectFeeBumpInputs(500n, 250, opts);
		throw new Error('expected preparation');
	} catch (error) {
		expect(error).instanceof(FixedOutputFeePreparationPendingError);
	}
}

describe('durable fixed-output fee preparation', () => {
	it('splits one ordinary coin into bounded owned fees and restores their reservation', async () => {
		const f = fixture(),
			p = f.provider();
		expect(p.supportsFixedOutputFees()).equal(true);
		await prepare(p);
		expect(f.counts()).deep.equal({ signCalls: 1 });
		expect(f.broadcasts).length(1);
		const split = bitcoin.Transaction.fromHex(f.broadcasts[0]);
		expect(split.ins).length(1);
		expect(split.ins[0].hash.equals(f.parent.getHash())).equal(true);
		expect(split.outs.filter((o) => o.value === 568)).length(4);
		expect(f.frozen.get(`${f.asset.tx_hash}:0`)!.freezeTag).equal(
			'asset-anchor'
		);
		const result = await f.provider().selectFeeBumpInputs(500n, 250, opts);
		expect(result.maxFeeSatoshis).equal(2000n);
		expect(result.inputs).length(1);
		expect(result.inputs[0].value).equal(568n);
		expect(result.changeScript.length).equal(0);
		await p.releaseInputPledges([
			{ txid: split.getId(), vout: result.inputs[0].prevOutputIndex }
		]);
		expect(
			f.frozen.has(`${split.getId()}:${result.inputs[0].prevOutputIndex}`)
		).equal(true);
		const repeated = await f.provider().selectFeeBumpInputs(500n, 250, opts);
		expect(repeated.inputs[0].prevOutputIndex).equal(
			result.inputs[0].prevOutputIndex
		);
		expect(f.counts().signCalls).equal(1);
	});
	it('persists the unsigned split before signing and retains it after signer failure', async () => {
		const f = fixture();
		f.failure('sign');
		await reject(
			f.provider().selectFeeBumpInputs(500n, 250, opts),
			'signing failed'
		);
		expect(f.journal().preparations[0].state).equal('unsigned');
		expect(f.broadcasts).length(0);
		f.failure('sign', false);
		await f.provider().selectFeeBumpInputs(500n, 250, opts);
		expect(f.broadcasts).length(1);
	});
	it('refuses publication on a signed journal failure and retries the same bytes without signing again', async () => {
		const f = fixture(),
			p = f.provider();
		f.store.refuse = (value): boolean =>
			JSON.parse(value).preparations.some(
				(r: { state: string }) => r.state === 'signed'
			);
		await reject(p.selectFeeBumpInputs(500n, 250, opts), 'journal refusal');
		expect(f.broadcasts).length(0);
		expect(f.counts().signCalls).equal(1);
		f.store.refuse = undefined;
		await p.selectFeeBumpInputs(500n, 250, opts);
		expect(f.counts().signCalls).equal(1);
		expect(f.broadcasts[0]).equal(f.signedTransactions[0]);
	});
	it('restores a signed split after a broadcast failure and publishes identical bytes', async () => {
		const f = fixture();
		f.failure('broadcast');
		await reject(
			f.provider().selectFeeBumpInputs(500n, 250, opts),
			'publication failed'
		);
		expect(f.journal().preparations[0].state).equal('signed');
		f.failure('broadcast', false);
		await f.provider().selectFeeBumpInputs(500n, 250, opts);
		expect(f.broadcasts).length(2);
		expect(f.broadcasts[0]).equal(f.broadcasts[1]);
		expect(f.counts().signCalls).equal(1);
	});
	it('does not sign before an unsigned journal acknowledgement or consume asset anchors', async () => {
		const f = fixture();
		f.store.refuse = (value): boolean =>
			JSON.parse(value).preparations.some(
				(r: { state: string }) => r.state === 'unsigned'
			);
		await reject(
			f.provider().selectFeeBumpInputs(500n, 250, opts),
			'journal refusal'
		);
		expect(f.counts().signCalls).equal(0);
		expect(f.broadcasts).length(0);
		expect(f.frozen.get(`${f.asset.tx_hash}:0`)!.freezeTag).equal(
			'asset-anchor'
		);
		f.store.refuse = undefined;
		await f.provider().selectFeeBumpInputs(500n, 250, opts);
		expect(f.counts().signCalls).equal(1);
		expect(f.frozen.get(`${f.asset.tx_hash}:0`)!.freezeTag).equal(
			'asset-anchor'
		);
	});
	it('counts pending action caps and preparation fees toward the lifetime budget', async () => {
		const f = fixture();
		f.policy.maxTotalFeeSatoshis = 4250n;
		const p = f.provider();
		await prepare(p);
		await p.selectFeeBumpInputs(500n, 250, opts);
		await p.selectFeeBumpInputs(500n, 250, { ...opts, feeActionId: 'second' });
		await reject(
			f
				.provider()
				.selectFeeBumpInputs(500n, 250, { ...opts, feeActionId: 'third' }),
			'lifetime fee budget'
		);
		expect(f.broadcasts).length(1);
		await reject(p.selectFeeBumpInputs(2500n, 250, opts), 'action fee cap');
	});
	it('waits for confirmed replacement top-ups and keeps every input within the action cap', async () => {
		const f = fixture(),
			p = f.provider();
		await prepare(p);
		const first = await p.selectFeeBumpInputs(500n, 250, opts),
			input = first.inputs[0];
		const replacementInputs = [
			{
				txid: bitcoin.Transaction.fromBuffer(input.prevTx).getId(),
				vout: input.prevOutputIndex,
				sequence: input.sequence
			}
		];
		await reject(
			p.selectFeeBumpInputs(900n, 250, {
				...opts,
				confirmedOnly: true,
				replacementInputs
			}),
			'awaiting wallet visibility or confirmation'
		);
		f.confirm();
		const second = await p.selectFeeBumpInputs(900n, 250, {
			...opts,
			confirmedOnly: true,
			replacementInputs
		});
		expect(second.inputs).length(2);
		expect(second.inputs.reduce((sum, i) => sum + i.value, 0n)).equal(1136n);
		await reject(
			p.selectFeeBumpInputs(900n, 250, {
				...opts,
				excludeTxids: [replacementInputs[0].txid],
				replacementInputs
			}),
			'unavailable'
		);
	});
	it('reopens its SQLite journal after a signing failure with identical unsigned intent and reservations', async () => {
		const directory = mkdtempSync(join(tmpdir(), 'fixed-fees-')),
			path = join(directory, 'fees.sqlite');
		let storage = new SqliteStorage(path);
		storage.open();
		try {
			const f = fixture();
			f.policy.storage = storage;
			f.failure('sign');
			await reject(
				f.provider().selectFeeBumpInputs(500n, 250, opts),
				'signing failed'
			);
			const namespace =
				'fixed-output-fees:' +
				bitcoin.crypto
					.sha256(Buffer.from('regtest:fixed-fee-wallet'))
					.toString('hex') +
				':journal';
			const before = JSON.parse(storage.loadMetadata(namespace)!);
			const unsigned = before.preparations[0].unsigned;
			storage.close();
			storage = new SqliteStorage(path);
			storage.open();
			f.policy.storage = storage;
			f.failure('sign', false);
			const restored = await f.provider().selectFeeBumpInputs(500n, 250, opts);
			expect(restored.inputs).length(1);
			const saved = JSON.parse(storage.loadMetadata(namespace)!);
			expect(saved.preparations[0].unsigned).equal(unsigned);
			expect(saved.preparations[0].signed).equal(f.broadcasts[0]);
			expect(f.frozen.get(`${f.parent.getId()}:0`)!.freezeTag).contains(
				':source:0'
			);
		} finally {
			storage.close();
			rmSync(directory, { recursive: true, force: true });
		}
	});
	it('serializes separate provider instances and never assigns one coin to different actions', async () => {
		const f = fixture();
		await prepare(f.provider());
		const [a, b] = await Promise.all([
			f.provider().selectFeeBumpInputs(500n, 250, opts),
			f.provider().selectFeeBumpInputs(500n, 250, {
				...opts,
				feeActionId: 'another-action'
			})
		]);
		expect(a.inputs[0].prevOutputIndex).not.equal(b.inputs[0].prevOutputIndex);
		expect(f.broadcasts).length(1);
	});
	it('retains an unseen published split rather than spending another source to prepare again', async () => {
		const f = fixture();
		f.failure('visibility');
		await prepare(f.provider());
		f.addCoin();
		for (let i = 0; i < 2; i++)
			await reject(
				f.provider().selectFeeBumpInputs(500n, 250, opts),
				'awaiting wallet visibility'
			);
		expect(f.journal().preparations).length(1);
		expect(f.broadcasts).length(1);
	});
	it('refuses a building recovery whose reserved source has since been spent', async () => {
		const f = fixture();
		f.store.refuse = (value): boolean =>
			JSON.parse(value).preparations.some(
				(p: { state: string }) => p.state === 'unsigned'
			);
		await reject(
			f.provider().selectFeeBumpInputs(500n, 250, opts),
			'journal refusal'
		);
		expect(f.frozen.get(`${f.parent.getId()}:0`)!.freezeTag).contains(
			':source:0'
		);
		f.store.refuse = undefined;
		f.spendSource();
		f.addCoin();
		await reject(
			f.provider().selectFeeBumpInputs(500n, 250, opts),
			'no longer unspent and owned'
		);
		expect(f.counts().signCalls).equal(0);
		expect(f.broadcasts).length(0);
	});
	it('honors a caller cap and retains it even when the caller later requests a larger one', async () => {
		const f = fixture();
		f.policy.maxFeeSatoshis = 20000n;
		f.policy.maxTotalFeeSatoshis = 100000n;
		await reject(
			f
				.provider()
				.selectFeeBumpInputs(500n, 250, { ...opts, maxFeeSatoshis: 1000n }),
			'awaiting wallet visibility'
		);
		const result = await f
			.provider()
			.selectFeeBumpInputs(500n, 250, { ...opts, maxFeeSatoshis: 2000n });
		expect(result.maxFeeSatoshis).equal(1000n);
		expect(result.inputs[0].value).equal(568n);
		await reject(
			f.provider().selectFeeBumpInputs(1100n, 250, opts),
			'action fee cap'
		);
	});
	it('rejects a switched wallet identity before signing or changing the journal', async () => {
		const f = fixture(),
			p = f.provider();
		f.wallet.network = 'testnet';
		await reject(p.selectFeeBumpInputs(500n, 250, opts), 'identity changed');
		expect(f.store.rows.size).equal(0);
		expect(f.counts().signCalls).equal(0);
	});
	it('applies a newly stricter caller cap to an existing reservation after restart', async () => {
		const f = fixture();
		await prepare(f.provider());
		await f.provider().selectFeeBumpInputs(500n, 250, opts);
		await reject(
			f
				.provider()
				.selectFeeBumpInputs(300n, 250, { ...opts, maxFeeSatoshis: 500n }),
			'action fee cap'
		);
		expect(
			Object.values(f.journal().actions).map((a) => (a as { cap: string }).cap)
		).deep.equal(['2000']);
		expect(f.broadcasts).length(1);
	});
	it('prevents another provider selecting the source while a split reservation is pending', async () => {
		const f = fixture(),
			originalFreeze = f.wallet.freezeUtxoIfUnfrozen!;
		let release!: () => void,
			entered!: () => void,
			competingFinished = false;
		const gate = new Promise<void>((resolve) => {
				release = resolve;
			}),
			started = new Promise<void>((resolve) => {
				entered = resolve;
			});
		let first = true;
		f.wallet.freezeUtxoIfUnfrozen = async (
			args
		): ReturnType<NonNullable<IWalletLike['freezeUtxoIfUnfrozen']>> => {
			const result = await originalFreeze(args);
			if (first && args.txid === f.parent.getId()) {
				first = false;
				entered();
				await gate;
			}
			return result;
		};
		const preparation = prepare(f.provider());
		await started;
		const competing = new WalletFundingProvider(f.wallet)
			.selectFeeBumpInputs(500n, 250)
			.then((result) => {
				competingFinished = true;
				return result;
			});
		await new Promise((resolve) => setImmediate(resolve));
		expect(competingFinished).equal(false);
		release();
		await preparation;
		const result = await competing;
		expect(
			bitcoin.Transaction.fromBuffer(result.inputs[0].prevTx).getId()
		).not.equal(f.parent.getId());
	});
	it('retains exact signed bytes after the publication-state write fails', async () => {
		const f = fixture();
		f.store.refuse = (value): boolean =>
			JSON.parse(value).preparations.some(
				(p: { state: string }) => p.state === 'published'
			);
		await reject(
			f.provider().selectFeeBumpInputs(500n, 250, opts),
			'journal refusal'
		);
		expect(f.broadcasts).length(1);
		expect(f.journal().preparations[0].state).equal('signed');
		f.store.refuse = undefined;
		await f.provider().selectFeeBumpInputs(500n, 250, opts);
		expect(f.broadcasts).length(1);
		expect(f.counts().signCalls).equal(1);
		expect(f.journal().preparations[0].signed).equal(f.broadcasts[0]);
	});
	it('re-signs the exact persisted unsigned transaction deterministically after a signed-write crash', async () => {
		const f = fixture();
		f.store.refuse = (value): boolean =>
			JSON.parse(value).preparations.some(
				(p: { state: string }) => p.state === 'signed'
			);
		await reject(
			f.provider().selectFeeBumpInputs(500n, 250, opts),
			'journal refusal'
		);
		const candidate = f.signedTransactions[0];
		f.store.refuse = undefined;
		await f.provider().selectFeeBumpInputs(500n, 250, opts);
		expect(f.broadcasts).deep.equal([candidate]);
		expect(f.counts().signCalls).equal(2);
	});
	it('does not derive action signing keys until the input reservation write succeeds', async () => {
		const f = fixture();
		await prepare(f.provider());
		let keys = 0;
		const original = f.wallet.getPrivateKey!;
		f.wallet.getPrivateKey = (path): string => {
			keys++;
			return original(path);
		};
		f.store.refuse = (value): boolean =>
			Object.values(JSON.parse(value).actions).some(
				(a) => (a as { inputs: unknown[] }).inputs.length > 0
			);
		await reject(
			f.provider().selectFeeBumpInputs(500n, 250, opts),
			'journal refusal'
		);
		expect(keys).equal(0);
		f.store.refuse = undefined;
		await f.provider().selectFeeBumpInputs(500n, 250, opts);
		expect(keys).equal(1);
	});
	it('preserves another owner freeze when a race prevents retaining the selected source', async () => {
		const f = fixture(),
			original = f.wallet.freezeUtxoIfUnfrozen!;
		f.wallet.freezeUtxoIfUnfrozen = async (
			args
		): ReturnType<NonNullable<IWalletLike['freezeUtxoIfUnfrozen']>> => {
			if (args.txid === f.parent.getId())
				f.frozen.set(`${args.txid}:${args.index}`, {
					freezeTag: 'another-owner',
					frozenAt: Date.now()
				});
			return original(args);
		};
		await reject(
			f.provider().selectFeeBumpInputs(500n, 250, opts),
			'another owner'
		);
		expect(f.frozen.get(`${f.parent.getId()}:0`)!.freezeTag).equal(
			'another-owner'
		);
		expect(f.journal().preparations).length(0);
		expect(f.counts().signCalls).equal(0);
		expect(f.broadcasts).length(0);
	});
	it('recovers only its orphan source freeze after a preparation reservation write fails', async () => {
		const f = fixture();
		f.store.refuse = (value): boolean =>
			JSON.parse(value).preparations.length > 0;
		await reject(
			f.provider().selectFeeBumpInputs(500n, 250, opts),
			'journal refusal'
		);
		expect(f.frozen.get(`${f.parent.getId()}:0`)!.freezeTag).contains(
			':source:0'
		);
		expect(f.journal().preparations).length(0);
		expect(f.counts().signCalls).equal(0);
		f.store.refuse = undefined;
		await prepare(f.provider());
		expect(f.broadcasts).length(1);
		expect(f.frozen.get(`${f.asset.tx_hash}:0`)!.freezeTag).equal(
			'asset-anchor'
		);
	});
	it('does not reserve or sign when the initial lifetime action write is refused', async () => {
		const f = fixture();
		f.store.refuse = (): true => true;
		await reject(
			f.provider().selectFeeBumpInputs(500n, 250, opts),
			'journal refusal'
		);
		expect(f.frozen.has(`${f.parent.getId()}:0`)).equal(false);
		expect(f.counts().signCalls).equal(0);
		expect(f.broadcasts).length(0);
	});
	it('refuses a wallet signature that does not authorize the exact split', async () => {
		const f = fixture(),
			original = f.wallet.importSignedPsbt!;
		f.wallet.importSignedPsbt = (
			signed,
			unsigned
		): {
			isErr: () => boolean;
			isOk: () => boolean;
			value: { txHex: string; txid: string };
		} => {
			const result = original(signed, unsigned) as ReturnType<
				typeof ok<{ txHex: string; txid: string }>
			>;
			const tx = bitcoin.Transaction.fromHex(result.value.txHex);
			tx.ins[0].witness[0][10] ^= 1;
			return ok({ txHex: tx.toHex(), txid: tx.getId() });
		};
		await reject(
			f.provider().selectFeeBumpInputs(500n, 250, opts),
			'Invalid fixed-output split signature'
		);
		expect(f.journal().preparations[0].state).equal('unsigned');
		expect(f.broadcasts).length(0);
	});
	it('defers preparation while an authenticated eligible CPFP change coin is unconfirmed', async () => {
		const f = fixture();
		f.coins().find((c) => c.tx_hash === f.parent.getId())!.height = 0;
		await reject(
			f.provider().selectFeeBumpInputs(500n, 250, opts),
			'awaiting wallet visibility or confirmation'
		);
		expect(f.journal().preparations).length(0);
		expect(f.counts().signCalls).equal(0);
		f.confirm();
		await prepare(f.provider());
		expect(f.broadcasts).length(1);
	});
	it('keeps insufficient, excluded or invalid unconfirmed sources as genuine errors', async () => {
		const f = fixture();
		f.coins().find((c) => c.tx_hash === f.parent.getId())!.height = 0;
		await reject(
			f.provider().selectFeeBumpInputs(500n, 250, {
				...opts,
				excludeTxids: [f.parent.getId()]
			}),
			'No confirmed ordinary'
		);
		f.coins().find((c) => c.tx_hash === f.parent.getId())!.value = 49000;
		await reject(
			f.provider().selectFeeBumpInputs(500n, 250, opts),
			'not an authenticated'
		);
		f.spendSource();
		await reject(
			f.provider().selectFeeBumpInputs(500n, 250, opts),
			'No confirmed ordinary'
		);
		expect(f.broadcasts).length(0);
		expect(f.counts().signCalls).equal(0);
	});
	it('retires unused replacement coins without refunding their lifetime cap', async () => {
		const f = fixture();
		f.policy.maxTotalFeeSatoshis = 4250n;
		const p = f.provider();
		await prepare(p);
		const first = await p.selectFeeBumpInputs(500n, 250, opts);
		f.confirm();
		const replacement = await p.selectFeeBumpInputs(900n, 250, {
			...opts,
			replacementInputs: first.inputs.map((i) => ({
				txid: bitcoin.Transaction.fromBuffer(i.prevTx).getId(),
				vout: i.prevOutputIndex,
				sequence: i.sequence
			}))
		});
		expect(replacement.inputs).length(2);
		await p.retireFixedOutputFeeAction(opts.feeActionId);
		for (const input of replacement.inputs)
			expect(
				f.frozen.has(
					`${bitcoin.Transaction.fromBuffer(input.prevTx).getId()}:${
						input.prevOutputIndex
					}`
				)
			).equal(false);
		expect(Object.values(f.journal().actions).map((a) => a.cap)).deep.equal([
			'2000'
		]);
		await reject(
			f.provider().selectFeeBumpInputs(500n, 250, opts),
			'action is retired'
		);
		await f
			.provider()
			.selectFeeBumpInputs(500n, 250, { ...opts, feeActionId: 'next' });
		await reject(
			f
				.provider()
				.selectFeeBumpInputs(500n, 250, { ...opts, feeActionId: 'third' }),
			'lifetime fee budget'
		);
	});
	it('does not unfreeze an action before its retirement record commits', async () => {
		const f = fixture(),
			p = f.provider();
		await prepare(p);
		const result = await p.selectFeeBumpInputs(500n, 250, opts),
			input = result.inputs[0],
			key = `${bitcoin.Transaction.fromBuffer(input.prevTx).getId()}:${
				input.prevOutputIndex
			}`;
		f.store.refuse = (value): boolean =>
			Object.values(JSON.parse(value).actions).some(
				(a) => (a as { retired?: boolean }).retired === true
			);
		await reject(
			p.retireFixedOutputFeeAction(opts.feeActionId),
			'journal refusal'
		);
		expect(f.frozen.has(key)).equal(true);
		f.store.refuse = undefined;
		await f.provider().retireFixedOutputFeeAction(opts.feeActionId);
		expect(f.frozen.has(key)).equal(false);
	});
	it('retries retirement after a marker-write crash without releasing a subsequent owner', async () => {
		const f = fixture(),
			p = f.provider();
		await prepare(p);
		const result = await p.selectFeeBumpInputs(500n, 250, opts),
			input = result.inputs[0],
			key = `${bitcoin.Transaction.fromBuffer(input.prevTx).getId()}:${
				input.prevOutputIndex
			}`;
		f.store.refuse = (value): boolean =>
			Object.values(JSON.parse(value).actions).some(
				(a) => (a as { released?: boolean }).released === true
			);
		await reject(
			p.retireFixedOutputFeeAction(opts.feeActionId),
			'journal refusal'
		);
		expect(f.frozen.has(key)).equal(false);
		f.frozen.set(key, { freezeTag: 'funding-pledge', frozenAt: Date.now() });
		f.store.refuse = undefined;
		await f.provider().retireFixedOutputFeeAction(opts.feeActionId);
		expect(f.frozen.get(key)!.freezeTag).equal('funding-pledge');
	});
	it('resumes committed retirement after SQLite restart and a refused tagged release', async () => {
		const directory = mkdtempSync(join(tmpdir(), 'retired-fees-')),
			path = join(directory, 'fees.sqlite');
		let storage = new SqliteStorage(path);
		storage.open();
		try {
			const f = fixture();
			f.policy.storage = storage;
			const p = f.provider();
			await prepare(p);
			const result = await p.selectFeeBumpInputs(500n, 250, opts),
				input = result.inputs[0],
				key = `${bitcoin.Transaction.fromBuffer(input.prevTx).getId()}:${
					input.prevOutputIndex
				}`;
			const unfreeze = f.wallet.unfreezeUtxoIfTagged!;
			f.wallet.unfreezeUtxoIfTagged = async (): ReturnType<
				NonNullable<IWalletLike['unfreezeUtxoIfTagged']>
			> => err();
			await reject(
				p.retireFixedOutputFeeAction(opts.feeActionId),
				'retired reservation release failed'
			);
			expect(f.frozen.has(key)).equal(true);
			storage.close();
			storage = new SqliteStorage(path);
			storage.open();
			f.policy.storage = storage;
			f.wallet.unfreezeUtxoIfTagged = unfreeze;
			await f.provider().retireFixedOutputFeeAction(opts.feeActionId);
			expect(f.frozen.has(key)).equal(false);
			await reject(
				f.provider().selectFeeBumpInputs(500n, 250, opts),
				'action is retired'
			);
		} finally {
			storage.close();
			rmSync(directory, { recursive: true, force: true });
		}
	});
	it('enumerates only authenticated complete native action identities for the exact channel', async () => {
		const f = fixture(),
			p = f.provider(),
			channel = Buffer.alloc(32, 1),
			other = Buffer.alloc(32, 2),
			id = fixedOutputHtlcFeeActionId(channel, 'ab'.repeat(32), 3);
		await prepare(p);
		await p.selectFeeBumpInputs(500n, 250, { ...opts, feeActionId: id });
		await p.selectFeeBumpInputs(500n, 250, {
			...opts,
			feeActionId: fixedOutputHtlcFeeActionId(other, 'ab'.repeat(32), 3)
		});
		await p.selectFeeBumpInputs(500n, 250, {
			...opts,
			feeActionId: id + ':extra'
		});
		expect(f.provider().getFixedOutputFeeActionIds(channel)).deep.equal([id]);
		await p.retireFixedOutputFeeAction(id);
		expect(f.provider().getFixedOutputFeeActionIds(channel)).deep.equal([]);
	});
	it('uses distinct action tags so an ordinary provider cannot retire a live fixed reservation', async () => {
		const f = fixture(),
			p = f.provider();
		await prepare(p);
		const result = await p.selectFeeBumpInputs(500n, 250, opts),
			input = result.inputs[0],
			txid = bitcoin.Transaction.fromBuffer(input.prevTx).getId();
		expect(
			f.frozen.get(`${txid}:${input.prevOutputIndex}`)!.freezeTag
		).contains(':action:');
		await new WalletFundingProvider(f.wallet).releaseInputPledges([
			{ txid, vout: input.prevOutputIndex }
		]);
		expect(f.frozen.has(`${txid}:${input.prevOutputIndex}`)).equal(true);
		const restored = await f.provider().restoreFeeBumpInputs([
			{
				prevTx: input.prevTx,
				prevOutputIndex: input.prevOutputIndex,
				sequence: input.sequence
			}
		]);
		expect(restored[0].value).equal(input.value);
	});
	it('does not advertise preparation without a configured durable bounded policy', () => {
		const f = fixture();
		expect(new WalletFundingProvider(f.wallet).supportsFixedOutputFees()).equal(
			false
		);
		expect(
			() =>
				new WalletFundingProvider(f.wallet, {
					fixedOutputFees: { ...f.policy, maxTotalFeeSatoshis: 1n }
				})
		).throw('durable bounded');
	});
	it('authenticates fixed-output fee prevouts and refuses malformed inputs before signing', async () => {
		const f = fixture(),
			p = f.provider();
		await prepare(p);
		const selected = await p.selectFeeBumpInputs(500n, 250, opts),
			input = selected.inputs[0];
		const original = new bitcoin.Transaction();
		original.addInput(Buffer.alloc(32, 29), 0);
		original.addOutput(Buffer.from('5120' + '31'.repeat(32), 'hex'), 355);
		let signingCalls = 0;
		const guarded = {
			...input,
			signWitness: (): Buffer[] => {
				signingCalls++;
				throw new Error('unexpected signer');
			}
		};
		const params = {
			htlcTx: original,
			htlcWitness: [
				Buffer.concat([Buffer.alloc(64, 1), Buffer.from([0x81])]),
				Buffer.concat([Buffer.alloc(64, 2), Buffer.from([0x81])])
			],
			walletInputs: [guarded],
			changeScript: Buffer.alloc(0),
			feeratePerVbyte: 1,
			fixedOutputs: true,
			maxFeeSatoshis: 2000n,
			signHtlcFunding: (): Buffer => {
				signingCalls++;
				throw new Error('unexpected signer');
			}
		};
		expect(() =>
			attachFeeInputsToZeroFeeHtlcTx({
				...params,
				walletInputs: [{ ...guarded, value: 1n }]
			})
		).throw('P2WPKH prevout');
		expect(() =>
			attachFeeInputsToZeroFeeHtlcTx({
				...params,
				walletInputs: [{ ...guarded, prevOutputIndex: 999 }]
			})
		).throw('P2WPKH prevout');
		expect(() =>
			attachFeeInputsToZeroFeeHtlcTx({
				...params,
				walletInputs: [guarded, guarded]
			})
		).throw('Duplicate');
		const duplicate = original.clone();
		duplicate.ins[0].hash = bitcoin.Transaction.fromBuffer(
			input.prevTx
		).getHash();
		duplicate.ins[0].index = input.prevOutputIndex;
		expect(() =>
			attachFeeInputsToZeroFeeHtlcTx({ ...params, htlcTx: duplicate })
		).throw('Duplicate');
		for (const rate of [0, -1, NaN, Infinity])
			expect(() =>
				attachFeeInputsToZeroFeeHtlcTx({ ...params, feeratePerVbyte: rate })
			).throw('fee policy');
		const wrongScript = bitcoin.Transaction.fromBuffer(input.prevTx);
		wrongScript.outs[input.prevOutputIndex].script = Buffer.from(
			'5120' + '32'.repeat(32),
			'hex'
		);
		expect(() =>
			attachFeeInputsToZeroFeeHtlcTx({
				...params,
				walletInputs: [{ ...guarded, prevTx: wrongScript.toBuffer() }]
			})
		).throw('P2WPKH prevout');
		expect(signingCalls).equal(0);
	});
	it('burns bounded fee coins without adding an output or changing either original signature', async () => {
		const f = fixture(),
			p = f.provider();
		await prepare(p);
		const selected = await p.selectFeeBumpInputs(500n, 250, opts);
		const original = new bitcoin.Transaction();
		original.version = 2;
		original.addInput(Buffer.alloc(32, 29), 0, 1);
		original.addOutput(Buffer.from('5120' + '31'.repeat(32), 'hex'), 355);
		const witness = [
			Buffer.concat([Buffer.alloc(64, 1), Buffer.from([0x81])]),
			Buffer.concat([Buffer.alloc(64, 2), Buffer.from([0x81])]),
			Buffer.from('51', 'hex'),
			Buffer.alloc(33, 3)
		];
		const result = attachFeeInputsToZeroFeeHtlcTx({
			htlcTx: original,
			htlcWitness: witness,
			walletInputs: selected.inputs,
			changeScript: Buffer.alloc(0),
			feeratePerVbyte: 1,
			fixedOutputs: true,
			maxFeeSatoshis: 2000n
		});
		expect(result.tx.outs).deep.equal(original.outs);
		expect(result.tx.ins[0].witness).deep.equal(witness);
		const feeWitness = result.tx.ins[1].witness,
			decoded = bitcoin.script.signature.decode(feeWitness[0]);
		expect(
			ecc.verify(
				result.tx.hashForWitnessV0(
					1,
					bitcoin.payments.p2pkh({ pubkey: feeWitness[1] }).output!,
					568,
					bitcoin.Transaction.SIGHASH_ALL
				),
				feeWitness[1],
				decoded.signature
			)
		).equal(true);
		expect(() =>
			attachFeeInputsToZeroFeeHtlcTx({
				htlcTx: original,
				htlcWitness: witness,
				walletInputs: selected.inputs,
				changeScript: Buffer.alloc(0),
				feeratePerVbyte: 1,
				fixedOutputs: true,
				maxFeeSatoshis: 500n
			})
		).throw('bounded inputs');
	});
});
