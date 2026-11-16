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
	FixedOutputFeeError,
	FixedOutputFeeBudgetExhaustedError,
	FixedOutputFeePreparationPendingError
} from '../../../src/lightning/wallet/fixed-output-fees';
import { ILedgerKeyValueStorage } from '../../../src/lightning/storage/durable-ledger';
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

const txidOf = (input: { prevTx: Buffer }): string =>
	bitcoin.Transaction.fromBuffer(input.prevTx).getId();
const outpointOf = (input: {
	prevTx: Buffer;
	prevOutputIndex: number;
}): string => `${txidOf(input)}:${input.prevOutputIndex}`;
/** What a broadcast split paid, given the value of the coin it spent. */
const feeOf = (raw: string, source = 50000n): bigint =>
	source -
	bitcoin.Transaction.fromHex(raw).outs.reduce(
		(sum, o) => sum + BigInt(o.value),
		0n
	);
const attempt = async (
	promise: Promise<unknown>
): Promise<Error | undefined> => {
	try {
		await promise;
		return undefined;
	} catch (error) {
		return error as Error;
	}
};
/** A refusal of the pool, with its code and what it asks of the caller. */
async function refused(
	promise: Promise<unknown>,
	code: string,
	remedy: string
): Promise<FixedOutputFeeError> {
	const error = await attempt(promise);
	expect(error, code).instanceof(FixedOutputFeeError);
	expect((error as FixedOutputFeeError).code).equal(code);
	expect((error as FixedOutputFeeError).remedy).equal(remedy);
	return error as FixedOutputFeeError;
}
/** Wait for whatever a provider queued when it was built. */
const drain = (provider: WalletFundingProvider): Promise<void> =>
	provider.releaseInputPledges([{ txid: 'ee'.repeat(32), vout: 0 }]);
/** A transaction that spends the named outpoints, as one that settled an action. */
const spending = (outpoints: string[]): Buffer => {
	const tx = new bitcoin.Transaction();
	for (const outpoint of outpoints) {
		const [txid, index] = outpoint.split(':');
		tx.addInput(Buffer.from(txid, 'hex').reverse(), Number(index));
	}
	if (!outpoints.length) tx.addInput(Buffer.alloc(32, 77), 0);
	tx.addOutput(Buffer.from('0014' + '11'.repeat(20), 'hex'), 1000);
	return tx.toBuffer();
};
const ownTags = (f: ReturnType<typeof fixture>): string[] =>
	[...f.frozen.values()]
		.map((entry) => entry.freezeTag ?? '')
		.filter((tag) => tag.startsWith('fixed-output-fees:'));

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
		await prepare(f.provider());
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
			expect(f.frozen.get(`${f.parent.getId()}:0`)!.freezeTag).contains(
				':source:0'
			);
			storage.close();
			storage = new SqliteStorage(path);
			storage.open();
			f.policy.storage = storage;
			f.failure('sign', false);
			const restored = await f.provider().selectFeeBumpInputs(500n, 250, opts);
			expect(restored.inputs).length(1);
			// The split that went out is the one recorded before the restart.
			// It is closed, and its other fee coins are the pool's.
			expect(bitcoin.Transaction.fromHex(f.broadcasts[0]).getId()).equal(
				bitcoin.Transaction.fromBuffer(
					bitcoin.Psbt.fromBase64(unsigned).data.getTransaction()
				).getId()
			);
			const saved = JSON.parse(storage.loadMetadata(namespace)!);
			expect(saved.preparations).length(0);
			expect(saved.coins).length(3);
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
	it('waits one look for a published split the wallet knows and does not list, then closes it and prepares again', async () => {
		const f = fixture();
		// As the real wallet: a broadcast removes the spent coin, and here the
		// fee coins are never listed (an ordinary send took them first).
		f.failure('visibility');
		await prepare(f.provider());
		f.addCoin();
		// The wallet knows the transaction and lists none of its fee coins.
		// One look is waited, so a listing that lags costs no second split.
		await reject(
			f.provider().selectFeeBumpInputs(500n, 250, opts),
			'awaiting wallet visibility'
		);
		expect(f.journal().preparations).length(1);
		expect(f.broadcasts).length(1);
		// Still none at the next look: they were spent. The split is closed,
		// its fee stays charged, and another is prepared and then serves.
		f.failure('visibility', false);
		await reject(
			f.provider().selectFeeBumpInputs(500n, 250, opts),
			'awaiting wallet visibility'
		);
		expect(f.broadcasts).length(2);
		const result = await f.provider().selectFeeBumpInputs(500n, 250, opts);
		expect(txidOf(result.inputs[0])).equal(
			bitcoin.Transaction.fromHex(f.broadcasts[1]).getId()
		);
		expect(f.journal().preparations).length(0);
		expect(f.provider().getFixedOutputFeeBudget()!.spentSatoshis).equal(
			feeOf(f.broadcasts[0]) + feeOf(f.broadcasts[1])
		);
	});
	it('abandons a split that was never signed once its source is spent, and prepares from another coin', async () => {
		const f = fixture();
		f.failure('sign');
		await refused(
			f.provider().selectFeeBumpInputs(500n, 250, opts),
			'FEE_PREPARATION_SIGNING_FAILED',
			'operator'
		);
		expect(f.journal().preparations[0].state).equal('unsigned');
		expect(f.frozen.get(`${f.parent.getId()}:0`)!.freezeTag).contains(
			':source:0'
		);
		f.failure('sign', false);
		f.spendSource();
		const other = f.addCoin();
		await prepare(f.provider());
		// The first split left the journal with its reservation and its
		// source freeze. Nothing of it was ever signed for the wire.
		expect(f.frozen.has(`${f.parent.getId()}:0`)).equal(false);
		expect(f.broadcasts).length(1);
		expect(
			Buffer.from(bitcoin.Transaction.fromHex(f.broadcasts[0]).ins[0].hash)
				.reverse()
				.toString('hex')
		).equal(other.tx_hash);
		expect(f.provider().getFixedOutputFeeBudget()).deep.equal({
			totalSatoshis: 20000n,
			reservedSatoshis: 2000n,
			spentSatoshis: feeOf(f.broadcasts[0]),
			remainingSatoshis: 18000n - feeOf(f.broadcasts[0])
		});
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
		// A wallet has one funding provider, and one that prepares fixed-output
		// fees shares its lock with any other so configured. The competing
		// selection is a sweep's, so it passes fee options.
		const competing = f
			.provider()
			.selectFeeBumpInputs(500n, 250, {})
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
		expect(f.journal().preparations).length(0);
		expect(f.signedTransactions).deep.equal([f.broadcasts[0]]);
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
	it('retires an action by the transaction that settled it, and gives the coins it did not spend, with their cap, back to the pool', async () => {
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
		// The transaction that settled the action is named, and it spent
		// neither coin: both go back to the pool, under its own tag.
		await p.retireFixedOutputFeeAction(opts.feeActionId, {
			spendingTransaction: spending([])
		});
		for (const input of replacement.inputs)
			expect(f.frozen.get(outpointOf(input))!.freezeTag).match(/:coin$/);
		expect(Object.keys(f.journal().actions)).length(0);
		await refused(
			f.provider().selectFeeBumpInputs(500n, 250, opts),
			'FEE_ACTION_RETIRED',
			'none'
		);
		// So the retired action is charged nothing, and two more actions fit
		// where one did.
		expect(f.provider().getFixedOutputFeeBudget()).deep.equal({
			totalSatoshis: 4250n,
			reservedSatoshis: 0n,
			spentSatoshis: feeOf(f.broadcasts[0]),
			remainingSatoshis: 4250n - feeOf(f.broadcasts[0])
		});
		await f
			.provider()
			.selectFeeBumpInputs(500n, 250, { ...opts, feeActionId: 'next' });
		await f
			.provider()
			.selectFeeBumpInputs(500n, 250, { ...opts, feeActionId: 'third' });
		await reject(
			f
				.provider()
				.selectFeeBumpInputs(500n, 250, { ...opts, feeActionId: 'fourth' }),
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
			(JSON.parse(value).retiredIds ?? []).length > 0;
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
					fixedOutputFees: { ...f.policy, maxFeeSatoshis: 0n }
				})
		).throw('durable bounded');
	});
});

describe('a fixed-output fee policy lowered below what the journal holds', () => {
	/** A refusal of new spending, with the figures it names. */
	async function exhausted(
		promise: Promise<unknown>
	): Promise<FixedOutputFeeBudgetExhaustedError> {
		let thrown: unknown;
		try {
			await promise;
		} catch (error) {
			thrown = error;
		}
		expect(thrown).instanceof(FixedOutputFeeBudgetExhaustedError);
		return thrown as FixedOutputFeeBudgetExhaustedError;
	}
	/** The exact fee of the one split the journal holds. */
	const splitFee = (f: ReturnType<typeof fixture>): bigint =>
		feeOf(f.broadcasts[0]);
	const outpoints = (result: {
		inputs: { prevTx: Buffer; prevOutputIndex: number }[];
	}): string[] =>
		result.inputs.map(
			(i) =>
				`${bitcoin.Transaction.fromBuffer(i.prevTx).getId()}:${
					i.prevOutputIndex
				}`
		);
	const replacementOf = (result: {
		inputs: { prevTx: Buffer; prevOutputIndex: number; sequence: number }[];
	}): { txid: string; vout: number; sequence: number }[] =>
		result.inputs.map((i) => ({
			txid: bitcoin.Transaction.fromBuffer(i.prevTx).getId(),
			vout: i.prevOutputIndex,
			sequence: i.sequence
		}));

	it('builds with a total below what is reserved, serves every recorded action and refuses only a new one, by name', async () => {
		const f = fixture(),
			p = f.provider();
		await prepare(p);
		const first = await p.selectFeeBumpInputs(500n, 250, opts);
		const fee = splitFee(f);
		expect(p.getFixedOutputFeeBudget()).deep.equal({
			totalSatoshis: 20000n,
			reservedSatoshis: 2000n,
			spentSatoshis: fee,
			remainingSatoshis: 18000n - fee
		});

		// The setting goes down, and the wallet restarts.
		f.policy.maxTotalFeeSatoshis = 100n;
		const q = f.provider();
		expect(q.supportsFixedOutputFees()).equal(true);
		expect(q.getFixedOutputFeeBudget()).deep.equal({
			totalSatoshis: 100n,
			reservedSatoshis: 2000n,
			spentSatoshis: fee,
			remainingSatoshis: 0n
		});
		// The recorded action is restored with the coins and the cap it had,
		// replaced with a second coin, and listed for its channel as before.
		const again = await q.selectFeeBumpInputs(500n, 250, opts);
		expect(outpoints(again)).deep.equal(outpoints(first));
		expect(again.maxFeeSatoshis).equal(2000n);
		f.confirm();
		const replaced = await q.selectFeeBumpInputs(900n, 250, {
			...opts,
			replacementInputs: replacementOf(again)
		});
		expect(replaced.inputs).length(2);
		const restored = await q.restoreFeeBumpInputs(replaced.inputs);
		expect(restored).length(2);

		// Only new spending is refused, with the figures.
		const refusal = await exhausted(
			q.selectFeeBumpInputs(500n, 250, { ...opts, feeActionId: 'second' })
		);
		expect(refusal.code).equal('FEE_BUDGET_EXHAUSTED');
		expect(refusal.neededSatoshis).equal(2000n);
		expect(refusal.budget).deep.equal(q.getFixedOutputFeeBudget());
		expect(refusal.message).equal(
			'Fixed-output lifetime fee budget is used up: 2000 sats are needed and ' +
				`0 of 100 remain (2000 reserved, ${fee} spent)`
		);
		expect(Object.keys(f.journal().actions)).length(1);

		// And the recorded action is retired like any other. No transaction
		// is named, so its whole cap stays charged and its coins are given
		// up to the wallet.
		await q.retireFixedOutputFeeAction(opts.feeActionId);
		for (const outpoint of outpoints(replaced))
			expect(f.frozen.has(outpoint)).equal(false);
		expect(f.provider().getFixedOutputFeeBudget()).deep.equal({
			totalSatoshis: 100n,
			reservedSatoshis: 0n,
			spentSatoshis: fee + 2000n,
			remainingSatoshis: 0n
		});
	});

	it('keeps the cap an action was recorded with when the per-transaction cap is lowered', async () => {
		const f = fixture(),
			p = f.provider();
		await prepare(p);
		const first = await p.selectFeeBumpInputs(500n, 250, opts);
		expect(first.maxFeeSatoshis).equal(2000n);

		f.policy.maxFeeSatoshis = 600n;
		const q = f.provider();
		const again = await q.selectFeeBumpInputs(500n, 250, opts);
		expect(outpoints(again)).deep.equal(outpoints(first));
		expect(again.maxFeeSatoshis).equal(2000n);
		// Two coins are 1136 sats: past the new cap, within the recorded one.
		f.confirm();
		const replaced = await q.selectFeeBumpInputs(900n, 250, {
			...opts,
			replacementInputs: replacementOf(again)
		});
		expect(replaced.inputs).length(2);
		expect(replaced.maxFeeSatoshis).equal(2000n);
		// A caller's own stricter cap still binds a recorded action.
		expect(
			(
				await q.selectFeeBumpInputs(900n, 250, {
					...opts,
					maxFeeSatoshis: 1500n,
					replacementInputs: replacementOf(replaced)
				})
			).maxFeeSatoshis
		).equal(1500n);

		// A new action takes the cap the policy has now.
		const second = await q.selectFeeBumpInputs(500n, 250, {
			...opts,
			feeActionId: 'second'
		});
		expect(second.maxFeeSatoshis).equal(600n);
		expect(
			Object.values(f.journal().actions)
				.map((a) => a.cap)
				.sort()
		).deep.equal(['2000', '600']);
		await f.provider().retireFixedOutputFeeAction(opts.feeActionId);
		await f.provider().retireFixedOutputFeeAction('second');
	});

	it('completes a split that was recorded under a larger preparation cap', async () => {
		const f = fixture();
		f.failure('sign');
		await reject(
			f.provider().selectFeeBumpInputs(500n, 250, opts),
			'signing failed'
		);
		const recorded = f.journal().preparations[0] as {
			state: string;
			fee: string;
			cap?: string;
			rate?: number;
		};
		expect(recorded.state).equal('unsigned');
		expect(recorded.cap).equal('1000');
		expect(recorded.rate).equal(1);
		expect(BigInt(recorded.fee) > 1n).equal(true);

		// Both the cap and the feerate change before the wallet restarts.
		f.policy.maxPreparationFeeSatoshis = 1n;
		f.policy.preparationFeeRatePerVbyte = 50;
		f.failure('sign', false);
		const q = f.provider();
		const result = await q.selectFeeBumpInputs(500n, 250, opts);
		expect(result.inputs).length(1);
		expect(f.broadcasts).length(1);
		expect(f.counts().signCalls).equal(2);
		// The same split, at the fee it was recorded with, and closed.
		expect(feeOf(f.broadcasts[0])).equal(BigInt(recorded.fee));
		expect(f.journal().preparations).length(0);
		expect(f.provider().getFixedOutputFeeBudget()?.spentSatoshis).equal(
			BigInt(recorded.fee)
		);
	});

	it('builds with a total below its own per-transaction cap and refuses the first action by name', async () => {
		const f = fixture();
		f.policy.maxTotalFeeSatoshis = 1n;
		const p = f.provider();
		const refusal = await exhausted(p.selectFeeBumpInputs(500n, 250, opts));
		expect(refusal.neededSatoshis).equal(2000n);
		expect(refusal.budget).deep.equal({
			totalSatoshis: 1n,
			reservedSatoshis: 0n,
			spentSatoshis: 0n,
			remainingSatoshis: 1n
		});
		expect(f.store.rows.size).equal(0);
		expect(f.broadcasts).length(0);
		expect(f.counts().signCalls).equal(0);
	});

	it('refuses a new split the budget has no room for, and leaves its action recorded', async () => {
		const f = fixture();
		// Room for the action's cap, and not for a preparation beside it.
		f.policy.maxTotalFeeSatoshis = 2500n;
		const refusal = await exhausted(
			f.provider().selectFeeBumpInputs(500n, 250, opts)
		);
		expect(refusal.neededSatoshis).equal(1000n);
		expect(refusal.budget.reservedSatoshis).equal(2000n);
		expect(f.journal().preparations).length(0);
		expect(f.frozen.has(`${f.parent.getId()}:0`)).equal(false);
		// A larger total lets the same action go on.
		f.policy.maxTotalFeeSatoshis = 3000n;
		await prepare(f.provider());
		expect(f.broadcasts).length(1);
	});

	it('charges a retired action the coins the named transaction spent, and its whole cap when none is named', async () => {
		const f = fixture(),
			p = f.provider();
		await prepare(p);
		const first = await p.selectFeeBumpInputs(500n, 250, opts);
		const second = await p.selectFeeBumpInputs(500n, 250, {
			...opts,
			feeActionId: 'second'
		});
		const fee = splitFee(f);
		expect(p.getFixedOutputFeeBudget()?.reservedSatoshis).equal(4000n);

		// The first action's transaction spent its coin, and is named.
		await p.retireFixedOutputFeeAction(opts.feeActionId, {
			spendingTransaction: spending(outpoints(first))
		});
		expect(p.getFixedOutputFeeBudget()).deep.equal({
			totalSatoshis: 20000n,
			reservedSatoshis: 2000n,
			spentSatoshis: fee + first.inputs[0].value,
			remainingSatoshis: 18000n - fee - first.inputs[0].value
		});

		// The second is retired with nothing named. The wallet still lists
		// its coin, which shows nothing: the whole cap stays charged.
		await p.retireFixedOutputFeeAction('second');
		expect(f.frozen.has(outpoints(second)[0])).equal(false);
		expect(f.provider().getFixedOutputFeeBudget()).deep.equal({
			totalSatoshis: 20000n,
			reservedSatoshis: 0n,
			spentSatoshis: fee + first.inputs[0].value + 2000n,
			remainingSatoshis: 18000n - fee - first.inputs[0].value
		});
	});
});

describe('a fee coin pool that one split cannot stop', () => {
	it('makes a split of fewer fee coins when its whole fee would pass the cap, and refuses by name, with nothing recorded, when not even one fits', async () => {
		const f = fixture();
		// 1 input, 4 fee coins and change at 1 sat/vB is 234 sats.
		f.policy.maxPreparationFeeSatoshis = 200n;
		await prepare(f.provider());
		const split = bitcoin.Transaction.fromHex(f.broadcasts[0]);
		expect(split.outs.filter((o) => o.value === 568)).length(2);
		expect(feeOf(f.broadcasts[0]) <= 200n).equal(true);
		// Nothing is left behind to stop a later action.
		const later = await f
			.provider()
			.selectFeeBumpInputs(500n, 250, { ...opts, feeActionId: 'second' });
		expect(later.inputs[0].value).equal(568n);

		// A cap that no split can fit.
		const g = fixture();
		g.policy.maxPreparationFeeSatoshis = 100n;
		const refusal = await refused(
			g.provider().selectFeeBumpInputs(500n, 250, opts),
			'FEE_PREPARATION_FEE_EXCEEDS_CAP',
			'operator'
		);
		expect(refusal.message).contains('maxPreparationFeeSatoshis is 100');
		expect(g.journal().preparations).length(0);
		expect(g.frozen.has(`${g.parent.getId()}:0`)).equal(false);
		expect(g.counts().signCalls).equal(0);
		expect(g.broadcasts).length(0);
		// The operator corrects the policy, and the same action goes on.
		g.policy.maxPreparationFeeSatoshis = 1000n;
		await prepare(g.provider());
		expect(g.broadcasts).length(1);
	});

	it('counts change under dust in the fee before the split is measured against its cap', async () => {
		const f = fixture();
		f.policy.maxPreparationFeeSatoshis = 400n;
		f.spendSource();
		f.addCoin(2150);
		// Three coins of 568 would leave 243 sats of change, under dust, and
		// a fee of 446 with it: past the cap. Two leave real change.
		await prepare(f.provider());
		const split = bitcoin.Transaction.fromHex(f.broadcasts[0]);
		expect(split.outs.filter((o) => o.value === 568)).length(2);
		expect(split.outs).length(3);
		expect(feeOf(f.broadcasts[0], 2150n) <= 400n).equal(true);
		const later = await f
			.provider()
			.selectFeeBumpInputs(500n, 250, { ...opts, feeActionId: 'second' });
		expect(later.inputs).length(1);
	});

	it('serves an action from the fee coins it has while a split the network refuses waits, and builds that split again at a raised rate', async () => {
		const f = fixture(),
			p = f.provider();
		await prepare(p);
		f.confirm();
		await p.selectFeeBumpInputs(500n, 250, opts);
		// An action that needs more than the three coins left can give begins
		// a second split, and the network will not take it.
		f.failure('broadcast');
		const large = { ...opts, feeActionId: 'large' };
		const refusal = await refused(
			p.selectFeeBumpInputs(1700n, 250, large),
			'FEE_PREPARATION_NOT_PUBLISHED',
			'wait'
		);
		expect(refusal.message).contains('publication failed');
		expect(f.journal().preparations[0].state).equal('signed');
		const stuck = f.broadcasts[1];
		// Another action, which a fee coin of the first split serves, is not
		// held back by it.
		const other = await p.selectFeeBumpInputs(500n, 250, {
			...opts,
			feeActionId: 'second'
		});
		expect(other.inputs[0].value).equal(568n);
		// The one that needs the split is told why, and the same bytes are
		// offered again.
		await refused(
			p.selectFeeBumpInputs(1700n, 250, large),
			'FEE_PREPARATION_NOT_PUBLISHED',
			'wait'
		);
		expect(f.broadcasts.slice(1).every((raw) => raw === stuck)).equal(true);

		// The operator raises the preparation rate. The network still refuses
		// the old bytes, so the split is built again from the same coin.
		f.failure('broadcast', false);
		const send = f.wallet.electrum.broadcastTransaction;
		f.wallet.electrum.broadcastTransaction = async (
			args
		): ReturnType<typeof send> => (args.rawTx === stuck ? err() : send(args));
		f.policy.preparationFeeRatePerVbyte = 3;
		const served = await f.provider().selectFeeBumpInputs(1700n, 250, large);
		const rebuilt = f.broadcasts[f.broadcasts.length - 1];
		expect(rebuilt).not.equal(stuck);
		expect(
			bitcoin.Transaction.fromHex(rebuilt).ins[0].hash.equals(
				bitcoin.Transaction.fromHex(stuck).ins[0].hash
			)
		).equal(true);
		const paid = (raw: string): bigint => feeOf(raw, 47494n);
		expect(paid(rebuilt) >= 3n * paid(stuck) - 3n).equal(true);
		expect(paid(rebuilt) <= 1000n).equal(true);
		expect(served.inputs[0].value).equal(1768n);
		expect(txidOf(served.inputs[0])).equal(
			bitcoin.Transaction.fromHex(rebuilt).getId()
		);
		// The budget is charged the split that went out, not the one that
		// never did.
		expect(f.provider().getFixedOutputFeeBudget()!.spentSatoshis).equal(
			feeOf(f.broadcasts[0]) + paid(rebuilt)
		);
	});

	it('closes a signed split whose source went to another transaction, and prepares again', async () => {
		const f = fixture();
		f.failure('broadcast');
		await reject(
			f.provider().selectFeeBumpInputs(500n, 250, opts),
			'publication failed'
		);
		expect(f.journal().preparations[0].state).equal('signed');
		// Something else spends the source. The wallet's server never took
		// the split, so it can never confirm.
		f.failure('broadcast', false);
		f.spendSource();
		const other = f.addCoin();
		await prepare(f.provider());
		expect(f.journal().preparations).length(1);
		expect(f.broadcasts).length(2);
		expect(
			Buffer.from(bitcoin.Transaction.fromHex(f.broadcasts[1]).ins[0].hash)
				.reverse()
				.toString('hex')
		).equal(other.tx_hash);
		const result = await f.provider().selectFeeBumpInputs(500n, 250, opts);
		expect(txidOf(result.inputs[0])).equal(
			bitcoin.Transaction.fromHex(f.broadcasts[1]).getId()
		);
	});

	it('lets go of a reserved coin the wallet no longer lists, funds the action from another, and still charges the lost coin if it was spent', async () => {
		const f = fixture(),
			p = f.provider();
		// A coin a stranger just sent, unconfirmed, is not the pool's: it is
		// never taken as a fee coin.
		const stranger = f.addCoin(600);
		f.coins().find((c) => c.tx_hash === stranger.tx_hash)!.height = 0;
		await prepare(p);
		const first = await p.selectFeeBumpInputs(500n, 250, opts);
		const split = txidOf(first.inputs[0]);
		expect(split).not.equal(stranger.tx_hash);
		// The split is replaced before it confirms: every coin of it is gone.
		const coins = f.coins();
		for (let i = coins.length - 1; i >= 0; i--)
			if (coins[i].tx_hash === split) coins.splice(i, 1);
		f.addCoin(50000);
		// The same action is not refused for ever: it waits for a new split,
		// and is then funded from it.
		await prepare(f.provider());
		const again = await f.provider().selectFeeBumpInputs(500n, 250, opts);
		expect(again.inputs).length(1);
		expect(txidOf(again.inputs[0])).equal(
			bitcoin.Transaction.fromHex(f.broadcasts[1]).getId()
		);
		// The action's earlier transaction, with the coin it let go of,
		// confirmed after all: named at retirement, that coin is charged and
		// the newer one goes back to the pool.
		const before = f.provider().getFixedOutputFeeBudget()!;
		await f.provider().retireFixedOutputFeeAction(opts.feeActionId, {
			spendingTransaction: spending([outpointOf(first.inputs[0])])
		});
		expect(f.provider().getFixedOutputFeeBudget()).deep.equal({
			totalSatoshis: 20000n,
			reservedSatoshis: 0n,
			spentSatoshis: before.spentSatoshis + first.inputs[0].value,
			remainingSatoshis: 20000n - before.spentSatoshis - first.inputs[0].value
		});
		expect(f.frozen.get(outpointOf(again.inputs[0]))!.freezeTag).match(
			/:coin$/
		);
	});

	it('never burns an ordinary coin whole: it is split, and the change comes back to the wallet', async () => {
		const f = fixture();
		// A cap that the wallet's one coin of 50000 sats fits under.
		f.policy.maxFeeSatoshis = 60000n;
		f.policy.maxTotalFeeSatoshis = 600000n;
		await prepare(f.provider());
		const result = await f.provider().selectFeeBumpInputs(500n, 250, opts);
		expect(result.inputs.reduce((sum, i) => sum + i.value, 0n)).equal(568n);
		expect(f.broadcasts).length(1);
		const split = bitcoin.Transaction.fromHex(f.broadcasts[0]).getId();
		const change = f
			.coins()
			.find((c) => c.tx_hash === split && c.value > 40000)!;
		expect(f.frozen.has(`${split}:${change.tx_pos}`)).equal(false);
		expect(f.provider().getFixedOutputFeeBudget()!.reservedSatoshis).equal(
			60000n
		);
	});

	it('keeps the fee coins of a split out of an ordinary selection from the moment it is signed, and freezes them once the wallet lists them', async () => {
		const f = fixture(),
			p = f.provider();
		await prepare(p);
		f.confirm();
		const split = bitcoin.Transaction.fromHex(f.broadcasts[0]).getId();
		// No pool call has looked at the split since it was published: its
		// fee coins are held by the journal alone.
		expect(ownTags(f).filter((tag) => tag.endsWith(':coin'))).length(0);
		const ordinary = await p.selectFeeBumpInputs(40000n, 250);
		expect(ordinary.inputs.filter((i) => txidOf(i) === split)).length(1);
		expect(ordinary.inputs.filter((i) => i.value === 568n)).length(0);
		// More than the change holds is refused, not served from fee coins.
		await reject(p.selectFeeBumpInputs(48000n, 250), 'insufficient');
		// At the next pool call the wallet lists them, and they are frozen.
		const fee = await p.selectFeeBumpInputs(500n, 250, opts);
		const tags = [0, 1, 2, 3].map(
			(index) => f.frozen.get(`${split}:${index}`)?.freezeTag ?? ''
		);
		expect(tags.filter((tag) => tag.endsWith(':coin'))).length(3);
		expect(tags.filter((tag) => tag.includes(':action:'))).length(1);
		expect(fee.inputs[0].value).equal(568n);
	});

	it('charges the whole cap for a retirement that names no transaction, and never hands its coin to another action', async () => {
		const f = fixture(),
			p = f.provider();
		await prepare(p);
		f.confirm();
		const a = await p.selectFeeBumpInputs(500n, 250, opts);
		const spent = outpointOf(a.inputs[0]);
		const before = p.getFixedOutputFeeBudget()!;
		// The HTLC transaction that burns the coin is on the wire, and the
		// wallet's server has not shown it yet: the refresh succeeds and
		// still lists the coin.
		await p.retireFixedOutputFeeAction(opts.feeActionId);
		expect(p.getFixedOutputFeeBudget()).deep.equal({
			totalSatoshis: 20000n,
			reservedSatoshis: 0n,
			spentSatoshis: before.spentSatoshis + 2000n,
			remainingSatoshis: 18000n - before.spentSatoshis
		});
		// The three other fee coins go to three other actions. The next one
		// is not given the coin that was burned: it waits for a new split.
		const used = new Set<string>();
		for (const id of ['b', 'c', 'd']) {
			const r = await p.selectFeeBumpInputs(500n, 250, {
				...opts,
				feeActionId: id
			});
			for (const i of r.inputs) used.add(outpointOf(i));
		}
		expect(used.size).equal(3);
		expect(
			await attempt(
				p.selectFeeBumpInputs(500n, 250, { ...opts, feeActionId: 'e' })
			)
		).instanceof(FixedOutputFeePreparationPendingError);
		expect(f.broadcasts).length(2);
		const e = await p.selectFeeBumpInputs(500n, 250, {
			...opts,
			feeActionId: 'e'
		});
		for (const i of e.inputs) used.add(outpointOf(i));
		expect(used.has(spent)).equal(false);
	});

	it('tells a refusal to wait for from one that needs the operator, by code', async () => {
		const f = fixture(),
			p = f.provider();
		// Wait: the wallet cannot be refreshed.
		const refresh = f.wallet.refreshWallet!;
		(f.wallet as { refreshWallet: unknown }).refreshWallet = async (): Promise<
			ReturnType<typeof err>
		> => err();
		await refused(
			p.selectFeeBumpInputs(500n, 250, opts),
			'FEE_WALLET_UNAVAILABLE',
			'wait'
		);
		f.wallet.refreshWallet = refresh;
		// Wait: a split is on its way.
		await refused(
			p.selectFeeBumpInputs(500n, 250, opts),
			'FEE_PREPARATION_PENDING',
			'wait'
		);
		const first = await p.selectFeeBumpInputs(500n, 250, opts);
		// Operator: the fee asked for passes the cap the action was recorded with.
		await refused(
			p.selectFeeBumpInputs(2500n, 250, opts),
			'FEE_ACTION_CAP_EXHAUSTED',
			'operator'
		);
		// Neither: the caller excludes the coin it also holds.
		await refused(
			p.selectFeeBumpInputs(500n, 250, {
				...opts,
				excludeTxids: [txidOf(first.inputs[0])]
			}),
			'FEE_INPUT_UNAVAILABLE',
			'none'
		);
		// Neither: a replacement input the action does not hold.
		await refused(
			p.selectFeeBumpInputs(500n, 250, {
				...opts,
				replacementInputs: [{ txid: 'cd'.repeat(32), vout: 0, sequence: 0 }]
			}),
			'FEE_INPUT_UNAVAILABLE',
			'none'
		);
		// Operator: no coin can prepare fee coins.
		const g = fixture();
		g.spendSource();
		await refused(
			g.provider().selectFeeBumpInputs(500n, 250, opts),
			'FEE_FUNDS_UNAVAILABLE',
			'operator'
		);
		// Operator: the lifetime budget.
		const h = fixture();
		h.policy.maxTotalFeeSatoshis = 1n;
		await refused(
			h.provider().selectFeeBumpInputs(500n, 250, opts),
			'FEE_BUDGET_EXHAUSTED',
			'operator'
		);
		// Neither: the action was retired. Its name is kept after the action
		// itself has left the journal.
		await p.retireFixedOutputFeeAction(opts.feeActionId);
		expect(Object.keys(f.journal().actions)).length(0);
		await refused(
			f.provider().selectFeeBumpInputs(500n, 250, opts),
			'FEE_ACTION_RETIRED',
			'none'
		);
	});
});

describe('a wallet call that does not answer', () => {
	const pause = (ms: number): Promise<void> =>
		new Promise((resolve) => setTimeout(resolve, ms));

	it('gives up the selection at the bound, frees the lock for the next, and lets nothing follow a late answer', async () => {
		const f = fixture();
		f.policy.walletCallTimeoutMs = 40;
		const p = f.provider();
		await prepare(p);
		const refresh = f.wallet.refreshWallet!;
		let release!: () => void,
			calls = 0,
			answered = false;
		const stuck = new Promise<void>((resolve) => {
			release = resolve;
		});
		f.wallet.refreshWallet = async (options): ReturnType<typeof refresh> => {
			if (calls++ === 0) {
				await stuck;
				answered = true;
			}
			return refresh(options);
		};
		const began = Date.now();
		const refusal = await refused(
			p.selectFeeBumpInputs(500n, 250, opts),
			'FEE_WALLET_TIMEOUT',
			'wait'
		);
		expect(refusal.message).contains('within 40 ms');
		expect(Date.now() - began).lessThan(2000);
		// The lock is free: a selection by another provider over the same
		// wallet goes through, and moves the journal on.
		const other = await f
			.provider()
			.selectFeeBumpInputs(500n, 250, { ...opts, feeActionId: 'second' });
		expect(other.inputs).length(1);
		const journal = [...f.store.rows.values()][0];
		const frozen = JSON.stringify([...f.frozen]);
		const broadcasts = f.broadcasts.length;
		// The stuck call answers at last. Nothing follows it.
		release();
		await pause(20);
		expect(answered).equal(true);
		expect([...f.store.rows.values()][0]).equal(journal);
		expect(JSON.stringify([...f.frozen])).equal(frozen);
		expect(f.broadcasts.length).equal(broadcasts);
		// And the first action is served when it is asked for again.
		const retried = await p.selectFeeBumpInputs(500n, 250, opts);
		expect(retried.inputs).length(1);
		expect(outpointOf(retried.inputs[0])).not.equal(
			outpointOf(other.inputs[0])
		);
	});

	it('runs nothing of a selection that is granted the wallet lock after it gave up waiting for it', async () => {
		const f = fixture();
		f.policy.walletCallTimeoutMs = 40;
		const p = f.provider();
		await drain(p);
		// The wallet's own lock is held by something that does not settle.
		const lock = f.wallet.withSendLock!;
		let release!: () => void,
			granted = 0;
		const held = new Promise<void>((resolve) => {
			release = resolve;
		});
		f.wallet.withSendLock = async <T>(fn: () => Promise<T>): Promise<T> => {
			await held;
			granted++;
			return lock(fn);
		};
		await refused(
			p.selectFeeBumpInputs(500n, 250, opts),
			'FEE_WALLET_TIMEOUT',
			'wait'
		);
		expect(f.store.rows.size).equal(0);
		f.wallet.withSendLock = lock;
		release();
		await pause(20);
		// The lock was granted to the call that had given up: it ran nothing.
		expect(granted).equal(1);
		expect(f.store.rows.size).equal(0);
		expect(f.counts().signCalls).equal(0);
		expect(f.broadcasts).length(0);
		expect(ownTags(f)).length(0);
		await prepare(p);
	});

	it('refuses a bound that is not from 1 through 600000 ms', () => {
		const f = fixture();
		for (const walletCallTimeoutMs of [0, 1.5, 600_001])
			expect(
				() =>
					new WalletFundingProvider(f.wallet, {
						fixedOutputFees: { ...f.policy, walletCallTimeoutMs }
					})
			).throw('durable bounded');
	});
});

describe('the fee journal, its size and a restore without it', function () {
	this.timeout(120_000);

	it('reads the journal a fixed number of times for an ordinary selection, whatever the wallet holds, and drops retired actions at its next write', async () => {
		const reads = async (
			count: number
		): Promise<{ loads: number; f: ReturnType<typeof fixture> }> => {
			const f = fixture();
			// What a journal of an earlier build looks like after a long life:
			// every retired, released action kept, each with its coin and that
			// coin's parent transaction.
			const identity = 'regtest:fixed-fee-wallet';
			const prefix =
				'fixed-output-fees:' +
				bitcoin.crypto.sha256(Buffer.from(identity)).toString('hex');
			const actions: Record<string, unknown> = {};
			for (let i = 0; i < count; i++) {
				const feeActionId = `asset-htlc:${'ab'.repeat(32)}:${i
					.toString(16)
					.padStart(64, '0')}:0`;
				actions[
					bitcoin.crypto.sha256(Buffer.from(feeActionId)).toString('hex')
				] = {
					cap: '2000',
					feeActionId,
					retired: true,
					released: true,
					paid: '7',
					inputs: [
						{
							utxo: {
								...f.coins()[0],
								tx_hash: i.toString(16).padStart(64, '0')
							},
							previous: f.parent.toHex()
						}
					]
				};
			}
			f.store.rows.set(
				prefix + ':journal',
				JSON.stringify({ version: 1, identity, actions, preparations: [] })
			);
			for (let i = 0; i < count; i++) f.addCoin(1000 + i);
			const p = f.provider();
			const before = p.getFixedOutputFeeBudget()!;
			expect(before.spentSatoshis).equal(BigInt(7 * count));
			let loads = 0;
			const load = f.store.loadMetadata.bind(f.store);
			f.store.loadMetadata = (name: string): string | null => {
				loads++;
				return load(name);
			};
			await p.selectFeeBumpInputs(1000n, 250);
			// The actions are gone from the journal, the most recent by name
			// only, and what they were charged is still charged.
			const journal = f.journal() as unknown as {
				actions: Record<string, unknown>;
				retiredIds: string[];
				spent: string;
			};
			expect(Object.keys(journal.actions)).length(0);
			expect(journal.retiredIds).length(Math.min(count, 128));
			expect(journal.spent).equal(String(7 * count));
			expect(p.getFixedOutputFeeBudget()).deep.equal(before);
			return { loads, f };
		};
		const small = await reads(20);
		const large = await reads(1500);
		expect(large.loads).equal(small.loads);
		expect(large.loads).lessThan(16);
		expect([...large.f.store.rows.values()][0].length).lessThan(16 * 1024);
	});

	it('releases, when it is built, the freezes under its tags that no journal owns, and starts the budget afresh after a restore without the journal', async () => {
		const f = fixture(),
			p = f.provider();
		await prepare(p);
		await p.selectFeeBumpInputs(500n, 250, opts);
		// One coin under its action, three under the pool's own tag, and the
		// source of the split that made them.
		expect(ownTags(f).filter((tag) => tag.includes(':action:'))).length(1);
		expect(ownTags(f).filter((tag) => tag.endsWith(':coin'))).length(3);
		expect(p.getFixedOutputFeeBudget()!.reservedSatoshis).equal(2000n);
		// A restore puts the node's database back without the fee journal,
		// and the wallet keeps its freezes.
		f.store.rows.clear();
		const restored = f.provider();
		await drain(restored);
		expect(ownTags(f)).length(0);
		expect(f.frozen.get(`${f.asset.tx_hash}:0`)!.freezeTag).equal(
			'asset-anchor'
		);
		expect(restored.getFixedOutputFeeBudget()).deep.equal({
			totalSatoshis: 20000n,
			reservedSatoshis: 0n,
			spentSatoshis: 0n,
			remainingSatoshis: 20000n
		});
		// The coins are ordinary coins of the wallet again.
		const ordinary = await restored.selectFeeBumpInputs(49000n, 250);
		expect(ordinary.inputs.length).greaterThan(1);
	});
});

describe('reading the state of the fee coin pool', () => {
	it('answers nothing on a provider without a fee policy', () => {
		const f = fixture();
		expect(new WalletFundingProvider(f.wallet).getFixedOutputFeeStatus()).equal(
			undefined
		);
	});

	it('reports the budget, the fee coins, the open actions, the split on its way and the last refusal, and changes nothing by being asked', async () => {
		const f = fixture(),
			p = f.provider();
		await drain(p);
		// Before anything: the wallet's one coin of 50000 sats could be split.
		// The frozen asset anchor of 100000 is not counted.
		expect(p.getFixedOutputFeeStatus()).deep.equal({
			available: true,
			budget: {
				totalSatoshis: 20000n,
				reservedSatoshis: 0n,
				spentSatoshis: 0n,
				remainingSatoshis: 20000n
			},
			feeCoins: { ready: 0, readySatoshis: 0n, unconfirmed: 0 },
			actions: [],
			splits: [],
			preparation: {
				possible: true,
				forFeeSatoshis: 2000n,
				neededSatoshis: 3000n,
				largestConfirmedSatoshis: 50000n
			}
		});
		expect(f.store.rows.size).equal(0);
		expect(f.broadcasts).length(0);

		await prepare(p);
		const split = bitcoin.Transaction.fromHex(f.broadcasts[0]).getId();
		const journal = [...f.store.rows.values()][0],
			frozen = JSON.stringify([...f.frozen]);
		const during = p.getFixedOutputFeeStatus()!;
		expect(during.splits).deep.equal([
			{
				state: 'published',
				transactionId: split,
				feeSatoshis: feeOf(f.broadcasts[0]),
				feeCoins: 4,
				feeCoinSatoshis: 568n
			}
		]);
		expect(during.actions).deep.equal([
			{
				feeActionId: opts.feeActionId,
				capSatoshis: 2000n,
				inputs: 0,
				heldSatoshis: 0n
			}
		]);
		expect(during.lastRefusal).include({
			code: 'FEE_PREPARATION_PENDING',
			remedy: 'wait'
		});
		expect(during.lastRefusal!.at).closeTo(Date.now(), 5000);
		// The split spent the only confirmed coin, and its change has not
		// confirmed: a second split could not be made now.
		expect(during.preparation).deep.equal({
			possible: false,
			forFeeSatoshis: 2000n,
			neededSatoshis: 3000n,
			largestConfirmedSatoshis: 0n,
			reason: 'FEE_FUNDS_UNAVAILABLE'
		});
		expect([...f.store.rows.values()][0]).equal(journal);
		expect(JSON.stringify([...f.frozen])).equal(frozen);
		expect(f.broadcasts).length(1);

		await p.selectFeeBumpInputs(500n, 250, opts);
		expect(p.getFixedOutputFeeStatus()!.feeCoins).deep.equal({
			ready: 0,
			readySatoshis: 0n,
			unconfirmed: 3
		});
		f.confirm();
		const after = p.getFixedOutputFeeStatus(500n)!;
		expect(after.feeCoins).deep.equal({
			ready: 3,
			readySatoshis: 1704n,
			unconfirmed: 0
		});
		expect(after.actions).deep.equal([
			{
				feeActionId: opts.feeActionId,
				capSatoshis: 2000n,
				inputs: 1,
				heldSatoshis: 568n
			}
		]);
		expect(after.splits).deep.equal([]);
		expect(after.preparation).deep.equal({
			possible: true,
			forFeeSatoshis: 500n,
			neededSatoshis: 1500n,
			largestConfirmedSatoshis: 47494n
		});
		expect(after.budget).deep.equal(p.getFixedOutputFeeBudget());
		// A selection that was served does not clear the last refusal: its
		// time says how old it is.
		expect(after.lastRefusal).deep.equal(during.lastRefusal);
		// Another provider over the same wallet has refused nothing.
		expect(f.provider().getFixedOutputFeeStatus()).not.have.property(
			'lastRefusal'
		);
	});

	it('says a split could not be made now when the budget has no room for it, or no confirmed coin is large enough', () => {
		const f = fixture();
		f.policy.maxTotalFeeSatoshis = 900n;
		expect(f.provider().getFixedOutputFeeStatus()!.preparation).deep.equal({
			possible: false,
			forFeeSatoshis: 2000n,
			neededSatoshis: 3000n,
			largestConfirmedSatoshis: 50000n,
			reason: 'FEE_BUDGET_EXHAUSTED'
		});
		const g = fixture();
		g.spendSource();
		g.addCoin(2500);
		const p = g.provider();
		expect(p.getFixedOutputFeeStatus()!.preparation).deep.equal({
			possible: false,
			forFeeSatoshis: 2000n,
			neededSatoshis: 3000n,
			largestConfirmedSatoshis: 2500n,
			reason: 'FEE_FUNDS_UNAVAILABLE'
		});
		// The same wallet could pay for a smaller fee coin.
		expect(p.getFixedOutputFeeStatus(1000n)!.preparation).deep.equal({
			possible: true,
			forFeeSatoshis: 1000n,
			neededSatoshis: 2000n,
			largestConfirmedSatoshis: 2500n
		});
		// A fee coin is never smaller than dust.
		expect(p.getFixedOutputFeeStatus(1n)!.preparation.neededSatoshis).equal(
			1330n
		);
		expect(() => p.getFixedOutputFeeStatus(0n)).throw('Invalid fixed-output');
	});
});
