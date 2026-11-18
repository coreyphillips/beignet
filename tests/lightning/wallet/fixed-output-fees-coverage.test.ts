/**
 * The fee coin pool (fixed-output-fees.ts) in the chain-and-mempool world of
 * fixed-output-fees-replacement.test.ts, copied here unchanged: replacements
 * of a spend the node holds, the hand-back of the free coins, and claims
 * near their deadlines.
 */
import { expect } from 'chai';
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
	FixedOutputFeePool
} from '../../../src/lightning/wallet/fixed-output-fees';
import { FixedOutputFeePool as PreviousPool } from './fixed-output-fees-0.43.0';
import { ILedgerKeyValueStorage } from '../../../src/lightning/storage/durable-ledger';
import { satPerVbyteToSatPerKw } from '../../../src/lightning/chain/types';
import crypto from 'crypto';
import { ChannelManager } from '../../../src/lightning/channel/channel-manager';
import { getPublicKey } from '../../../src/lightning/crypto/ecdh';
import { COMMIT_ALL } from '../helpers/channel-persistence';
bitcoin.initEccLib(ecc);

const ok = <T>(
	value: T
): { isErr: () => boolean; isOk: () => boolean; value: T } => ({
	isErr: () => false,
	isOk: () => true,
	value
});
const err = (
	message: string
): {
	isErr: () => boolean;
	isOk: () => boolean;
	error: { message: string };
} => ({ isErr: () => true, isOk: () => false, error: { message } });

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

const idOf = (input: { hash: Buffer }): string =>
	Buffer.from(input.hash).reverse().toString('hex');
const txidOf = (input: { prevTx: Buffer }): string =>
	bitcoin.Transaction.fromBuffer(input.prevTx).getId();
const outpointOf = (input: {
	prevTx: Buffer;
	prevOutputIndex: number;
}): string => `${txidOf(input)}:${input.prevOutputIndex}`;
const attempt = async (
	promise: Promise<unknown>
): Promise<FixedOutputFeeError | Error | undefined> => {
	try {
		await promise;
		return undefined;
	} catch (error) {
		return error as Error;
	}
};
const wait = (ms: number): Promise<void> =>
	new Promise((resolve) => setTimeout(resolve, ms));

// eslint-disable-next-line @typescript-eslint/explicit-function-return-type
function world(policyChanges: Partial<IFixedOutputFeePolicy> = {}) {
	const network = bitcoin.networks.regtest;
	const owner = getECPair().fromPrivateKey(Buffer.alloc(32, 45), { network });
	const publicKey = Buffer.from(owner.publicKey);
	const payment = bitcoin.payments.p2wpkh({ pubkey: publicKey, network });
	const script = payment.output!;
	const path = "m/84'/1'/0'/1/0";
	const scriptHash = Buffer.from(bitcoin.crypto.sha256(script))
		.reverse()
		.toString('hex');
	/** Every transaction the server knows: in a block or in the mempool. */
	const known = new Map<string, bitcoin.Transaction>();
	/** The height of each transaction in a block. */
	const confirmed = new Map<string, number>();
	let tip = 100,
		funded = 0,
		locked = false,
		slowBroadcast = 0;
	const spenderOf = (txid: string, index: number): string | undefined => {
		for (const [id, tx] of known)
			if (tx.ins.some((i) => idOf(i) === txid && i.index === index)) return id;
		return undefined;
	};
	const evict = (txid: string): void => {
		const tx = known.get(txid);
		if (!tx || confirmed.has(txid)) return;
		known.delete(txid);
		for (let i = 0; i < tx.outs.length; i++) {
			const child = spenderOf(txid, i);
			if (child) evict(child);
		}
	};
	/** Take a transaction into the mempool. Undefined when taken. */
	const accept = (tx: bitcoin.Transaction): string | undefined => {
		const txid = tx.getId();
		if (known.has(txid)) return undefined;
		for (const input of tx.ins) {
			const parent = known.get(idOf(input));
			if (!parent || !parent.outs[input.index]) return 'missing inputs';
			const other = spenderOf(idOf(input), input.index);
			if (other && confirmed.has(other)) return 'input spent in a block';
		}
		for (const input of tx.ins) {
			const other = spenderOf(idOf(input), input.index);
			if (other) evict(other);
		}
		known.set(txid, tx);
		return undefined;
	};
	const coins = (): ISpliceUtxo[] => {
		const found: ISpliceUtxo[] = [];
		for (const [txid, tx] of known)
			tx.outs.forEach((out, index) => {
				if (!out.script.equals(script) || spenderOf(txid, index)) return;
				found.push({
					address: payment.address!,
					path,
					publicKey: publicKey.toString('hex'),
					tx_hash: txid,
					tx_pos: index,
					value: out.value,
					height: confirmed.get(txid) ?? 0
				});
			});
		return found;
	};
	/** A block that takes every transaction of the mempool but those named. */
	const mine = (skip: string[] = []): void => {
		tip++;
		let more = true;
		while (more) {
			more = false;
			for (const [txid, tx] of known) {
				if (confirmed.has(txid) || skip.includes(txid)) continue;
				if (tx.ins.every((i) => confirmed.has(idOf(i)))) {
					confirmed.set(txid, tip);
					more = true;
				}
			}
		}
	};
	/**
	 * A block from a miner that never saw what replaced `tx`: it takes `tx`,
	 * and whatever spends what `tx` spends leaves the mempool.
	 */
	const mineInstead = (tx: bitcoin.Transaction): void => {
		for (const input of tx.ins) {
			const other = spenderOf(idOf(input), input.index);
			if (other) evict(other);
		}
		known.set(tx.getId(), tx);
		mine();
	};
	const frozen = new Map<string, { freezeTag?: string; frozenAt: number }>();
	const broadcasts: string[] = [];
	const store = new Store();
	const wallet: IWalletLike = {
		id: 'fee-wallet',
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
		listUtxos: coins,
		refreshWallet: async () => ok(''),
		getPrivateKey: (asked) => {
			if (asked !== path) throw new Error('unknown key');
			return owner.toWIF();
		},
		getChangeAddress: async () => ok({ address: payment.address! }),
		getAddressFromScriptHash: (asked) =>
			asked === scriptHash
				? {
						address: payment.address!,
						path,
						publicKey: publicKey.toString('hex')
				  }
				: undefined,
		isUtxoFrozen: (txid, index) => frozen.has(`${txid}:${index}`),
		listFrozenUtxos: () =>
			[...frozen].map(([k, v]) => ({
				tx_hash: k.split(':')[0],
				tx_pos: Number(k.split(':')[1]),
				...v
			})),
		freezeUtxoIfUnfrozen: async ({ txid, index, tag }) => {
			const k = `${txid}:${index}`,
				created = !frozen.has(k);
			if (created) frozen.set(k, { freezeTag: tag, frozenAt: Date.now() });
			return ok({ created });
		},
		unfreezeUtxoIfTagged: async ({ txid, index, tag }) => {
			const k = `${txid}:${index}`,
				unfrozen = frozen.get(k)?.freezeTag === tag;
			if (unfrozen) frozen.delete(k);
			return ok({ unfrozen });
		},
		signPsbtWithOurKey: (raw) => {
			const psbt = bitcoin.Psbt.fromBase64(raw);
			psbt.signAllInputs(owner);
			return ok(psbt.toBase64());
		},
		importSignedPsbt: (signed) => {
			const psbt = bitcoin.Psbt.fromBase64(signed);
			psbt.finalizeAllInputs();
			const tx = psbt.extractTransaction();
			return ok({ txHex: tx.toHex(), txid: tx.getId() });
		},
		electrum: {
			getTransactions: async ({ txHashes }) =>
				ok({
					data: txHashes.map(({ tx_hash }) => ({
						data: { tx_hash },
						result: { txid: tx_hash, hex: known.get(tx_hash)?.toHex() }
					}))
				}),
			broadcastTransaction: async ({ rawTx }) => {
				broadcasts.push(rawTx);
				const tx = bitcoin.Transaction.fromHex(rawTx);
				// The server answers late, and takes the transaction all the same.
				if (slowBroadcast > 0) await wait(slowBroadcast);
				const refusal = accept(tx);
				return refusal ? err(refusal) : ok(tx.getId());
			}
		}
	};
	const policy: IFixedOutputFeePolicy = {
		storage: store,
		maxFeeSatoshis: 2000n,
		maxTotalFeeSatoshis: 20000n,
		maxPreparationFeeSatoshis: 1000n,
		...policyChanges
	};
	return {
		wallet,
		store,
		policy,
		frozen,
		broadcasts,
		known,
		confirmed,
		coins,
		mine,
		mineInstead,
		accept,
		script,
		slow: (ms: number): void => {
			slowBroadcast = ms;
		},
		/** A confirmed coin of the wallet. */
		fund(value: number): string {
			const tx = new bitcoin.Transaction();
			tx.version = 2;
			tx.addInput(Buffer.alloc(32, 200 + funded++), 0);
			tx.addOutput(script, value);
			known.set(tx.getId(), tx);
			confirmed.set(tx.getId(), tip);
			return tx.getId();
		},
		provider: (): WalletFundingProvider =>
			new WalletFundingProvider(wallet, { fixedOutputFees: policy }),
		journal: (): {
			actions: Record<
				string,
				{ inputs: Array<{ utxo: ISpliceUtxo }>; gone?: unknown[] }
			>;
			coins?: Array<{ utxo: ISpliceUtxo }>;
			unconfirmed?: unknown[];
			spent?: string;
		} => JSON.parse([...store.rows.values()][0])
	};
}

/** What a transaction of the wallet paid, its inputs read from the chain. */
const feeOf = (
	w: ReturnType<typeof world>,
	tx: bitcoin.Transaction
): bigint => {
	const paidIn = tx.ins.reduce(
		(sum, input) =>
			sum + BigInt(w.known.get(idOf(input))!.outs[input.index].value),
		0n
	);
	return paidIn - tx.outs.reduce((sum, out) => sum + BigInt(out.value), 0n);
};

/** The spend of an output of an asset channel with its fee inputs, as the node holds it. */
const spendWith = (
	w: ReturnType<typeof world>,
	feeInputs: Array<{
		prevTx: Buffer;
		prevOutputIndex: number;
		sequence: number;
	}>
): bitcoin.Transaction => {
	const tx = new bitcoin.Transaction();
	tx.version = 2;
	for (const input of feeInputs)
		tx.addInput(
			Buffer.from(txidOf(input), 'hex').reverse(),
			input.prevOutputIndex,
			input.sequence
		);
	tx.addOutput(Buffer.from('0014' + '22'.repeat(20), 'hex'), 330);
	return tx;
};
/** The outpoints a transaction spends. */
const spends = (tx: bitcoin.Transaction): Set<string> =>
	new Set(tx.ins.map((input) => `${idOf(input)}:${input.index}`));

const asReplacement = (input: {
	prevTx: Buffer;
	prevOutputIndex: number;
	sequence: number;
}): { txid: string; vout: number; sequence: number } => ({
	txid: txidOf(input),
	vout: input.prevOutputIndex,
	sequence: input.sequence
});
/** What the wallet lists of `outpoints`. */
const listedOf = (
	w: ReturnType<typeof world>,
	outpoints: string[]
): ISpliceUtxo[] =>
	w.coins().filter((c) => outpoints.includes(`${c.tx_hash}:${c.tx_pos}`));
/** Every outpoint frozen under any tag of the pool that the wallet lists. */
const poolFreezesListed = (w: ReturnType<typeof world>): string[] => {
	const listed = new Set(w.coins().map((c) => `${c.tx_hash}:${c.tx_pos}`));
	return [...w.frozen]
		.filter(
			([outpoint, hold]) =>
				listed.has(outpoint) &&
				(hold.freezeTag ?? '').startsWith('fixed-output-fees:')
		)
		.map(([outpoint, hold]) => `${outpoint} (${hold.freezeTag})`)
		.sort();
};

/** Every outpoint frozen under the pool's tag for its free fee coins. */
const coinFreezes = (w: ReturnType<typeof world>): string[] =>
	[...w.frozen]
		.filter(([, hold]) =>
			/^fixed-output-fees:[0-9a-f]{64}:coin$/.test(hold.freezeTag ?? '')
		)
		.map(([outpoint]) => outpoint)
		.sort();

/** Bitcoin Core's answer for an unknown transaction from a node without a txindex, as electrs relays it. */
const NO_TXINDEX_MISS =
	'No such mempool transaction. Use -txindex or provide a block hash to enable blockchain transaction queries. Use gettransaction for wallet transactions.';
/** A server that answers an unknown transaction as electrs on a node without a txindex does. */
const withoutTxindex = (w: ReturnType<typeof world>): void => {
	w.wallet.electrum.getTransactions = (async ({
		txHashes
	}: {
		txHashes: Array<{ tx_hash: string }>;
	}) =>
		ok({
			data: txHashes.map(({ tx_hash }) => {
				const tx = w.known.get(tx_hash);
				return tx
					? { data: { tx_hash }, result: { txid: tx_hash, hex: tx.toHex() } }
					: { data: { tx_hash }, error: { code: 2, message: NO_TXINDEX_MISS } };
			})
		})) as unknown as typeof w.wallet.electrum.getTransactions;
};

describe('fee coin pool: replacements, hand-back and deadlines', function () {
	this.timeout(20000);

	it('a raise that names the spend it replaces and no fee coin, near its deadline, adds no unconfirmed input that spend did not have (BIP 125 rule 2)', async () => {
		const w = world({ feeCoinCount: 1 });
		w.fund(50_000);
		const p = w.provider();
		// A claim four blocks from its deadline takes the coin of its own split.
		const a = await p.selectFeeBumpInputs(500n, 250, {
			fixedOutputs: true,
			feeActionId: 'claim-a',
			blockHeight: 100,
			deadlineHeight: 104
		});
		expect(a.inputs).length(1);
		// A block takes the split; the spend made of its coin goes out.
		w.mine();
		const held = spendWith(w, a.inputs);
		expect(w.accept(held)).equal(undefined);
		// The node's raise of that spend was refused for good (remedy none),
		// and it asks once more as channel-manager.ts handleFixedOutputFee
		// does: no fee coin named, the spend it replaces named, and
		// confirmedOnly false since the deadline is within
		// FIXED_OUTPUT_FEE_TIMING.unconfirmedCoinBlocks.
		let served: string[] = [];
		const outcome = await attempt(
			p
				.selectFeeBumpInputs(600n, 750, {
					fixedOutputs: true,
					feeActionId: 'claim-a',
					blockHeight: 101,
					deadlineHeight: 104,
					confirmedOnly: false,
					replacedTxid: held.getId()
				})
				.then((selection) => {
					served = selection.inputs.map(outpointOf);
				})
		);
		expect(
			outcome === undefined ||
				(outcome as FixedOutputFeeError).code === 'FEE_PREPARATION_PENDING',
			String(outcome)
		).equal(true);
		// The spend made of the answer replaces the one in the mempool through
		// the output both spend. A replacement may add an unconfirmed input
		// only if a transaction it replaces spent it (BIP 125 rule 2).
		const before = spends(held);
		expect(
			served.filter(
				(outpoint) =>
					!before.has(outpoint) && !w.confirmed.has(outpoint.split(':')[0])
			),
			'unconfirmed inputs the replaced spend did not have'
		).deep.equal([]);
	});

	it('once the action is retired and the free coins are handed back, no coin the wallet lists stays frozen under a tag of the pool, a coin a raise let go of included', async () => {
		const w = world();
		w.fund(50_000);
		w.fund(50_000);
		const p = w.provider();
		const a = await p.selectFeeBumpInputs(500n, 250, {
			fixedOutputs: true,
			feeActionId: 'claim-a',
			blockHeight: 100,
			deadlineHeight: 104
		});
		const split = txidOf(a.inputs[0]);
		const coin = outpointOf(a.inputs[0]);
		// The node holds its spend: it has not gone out.
		const held = spendWith(w, a.inputs);
		expect(w.frozen.get(coin)!.freezeTag).match(/:action:[0-9a-f]{64}$/);
		// The rate rises to 10 sat/vB. The split pays 1 sat/vB and a split of
		// four coins cannot pay the rate within the cap of a split: a raise
		// lets go of the coin and is funded from confirmed coins.
		const raise = (
			height: number
		): ReturnType<WalletFundingProvider['selectFeeBumpInputs']> =>
			p.selectFeeBumpInputs(500n, 2500, {
				fixedOutputs: true,
				feeActionId: 'claim-a',
				blockHeight: height,
				deadlineHeight: 130,
				replacementInputs: a.inputs.map(asReplacement),
				replacedTxid: held.getId()
			});
		await attempt(raise(101));
		w.mine([split]);
		const r = await raise(102);
		expect(r.inputs.map(outpointOf)).not.include(coin);
		// The output is settled for good, and no asset channel is left.
		await p.retireFixedOutputFeeAction('claim-a', { impossible: true });
		expect(await p.releaseFixedOutputFeeCoins()).equal(true);
		expect(w.journal().actions).deep.equal({});
		// The coin the raise let go of is the wallet's and is listed.
		expect(listedOf(w, [coin])).length(1);
		expect(poolFreezesListed(w)).deep.equal([]);
	});

	it('a split replacement leaves in the mempool a payment of the wallet that spent the change of the split', async () => {
		const w = world();
		w.fund(50_000);
		const p = w.provider();
		const a = await p.selectFeeBumpInputs(500n, 250, {
			fixedOutputs: true,
			feeActionId: 'claim-a',
			blockHeight: 100,
			deadlineHeight: 104
		});
		const split = txidOf(a.inputs[0]);
		const splitTx = w.known.get(split)!;
		const change = `${split}:${splitTx.outs.length - 1}`;
		// The change of the split is an ordinary coin: the provider's own
		// selections (a splice-in, a funding) may take it.

		const spendable = p.quoteSpliceIn(253);
		expect(Number(spendable.spendableSats)).equal(
			splitTx.outs[splitTx.outs.length - 1].value
		);
		// The wallet pays someone from it before the split confirms.
		const pay = new bitcoin.Transaction();
		pay.version = 2;
		pay.addInput(
			Buffer.from(split, 'hex').reverse(),
			splitTx.outs.length - 1,
			0xfffffffd
		);
		pay.addOutput(Buffer.from('0014' + '33'.repeat(20), 'hex'), 40_000);
		expect(w.accept(pay)).equal(undefined);
		expect(listedOf(w, [change]), 'the change is spent').length(0);
		// Another claim near its deadline at a higher rate, a block later.
		await attempt(
			p.selectFeeBumpInputs(500n, 750, {
				fixedOutputs: true,
				feeActionId: 'claim-b',
				blockHeight: 101,
				deadlineHeight: 104
			})
		);
		expect(
			w.known.has(pay.getId()),
			'the payment of the wallet is still in the mempool'
		).equal(true);
	});

	/**
	 * A split the pool follows, and a replacement of it recorded and charged
	 * whose broadcast never answers (a stop between the journal write and the
	 * send behaves the same). Both actions are then retired.
	 */
	const recordedReplacement = async (
		w: ReturnType<typeof world>,
		p: WalletFundingProvider
	): Promise<{ split: string; replacement: string }> => {
		await attempt(
			p.selectFeeBumpInputs(500n, 250, {
				fixedOutputs: true,
				feeActionId: 'claim-x',
				blockHeight: 100
			})
		);
		const split = bitcoin.Transaction.fromHex(w.broadcasts[0]).getId();
		const send = w.wallet.electrum.broadcastTransaction;
		w.wallet.electrum.broadcastTransaction = (async ({
			rawTx
		}: {
			rawTx: string;
		}) => {
			w.broadcasts.push(rawTx);
			return new Promise(() => undefined);
		}) as typeof send;
		const timedOut = await attempt(
			p.selectFeeBumpInputs(500n, 750, {
				fixedOutputs: true,
				feeActionId: 'claim-a',
				blockHeight: 101,
				deadlineHeight: 104
			})
		);
		expect((timedOut as FixedOutputFeeError).code).equal('FEE_WALLET_TIMEOUT');
		w.wallet.electrum.broadcastTransaction = send;
		const replacement = bitcoin.Transaction.fromHex(
			w.broadcasts[w.broadcasts.length - 1]
		).getId();
		expect(replacement).not.equal(split);
		expect(w.known.has(replacement), 'the replacement never went out').equal(
			false
		);
		await p.retireFixedOutputFeeAction('claim-x', { impossible: true });
		await p.retireFixedOutputFeeAction('claim-a', { impossible: true });
		return { split, replacement };
	};

	it('hands the free coins back once no action is open, and settles a split replacement recorded and never sent that the last selection left in the journal', async () => {
		const w = world({ walletCallTimeoutMs: 50 });
		w.fund(50_000);
		const p = w.provider();
		await recordedReplacement(w, p);
		expect(w.journal().actions).deep.equal({});
		// No asset channel is left, so the node asks on every block, and no
		// selection comes any more. A block takes the split.
		w.mine();
		let handed = false;
		for (let i = 0; i < 3; i++) {
			handed = (await p.releaseFixedOutputFeeCoins()) || handed;
			w.mine();
		}
		expect(handed, 'handed back').equal(true);
		expect(coinFreezes(w)).deep.equal([]);
	});

	it('charges nothing for a split replacement recorded and never sent once the previous release drops the row of its split', async () => {
		const w = world({ walletCallTimeoutMs: 50 });
		w.fund(50_000);
		const p = w.provider();
		const { split } = await recordedReplacement(w, p);
		// The node is run on the previous release, and a block takes the split.
		usePool(p, w, 'previous');
		w.mine();
		await attempt(
			p.selectFeeBumpInputs(500n, 250, {
				fixedOutputs: true,
				feeActionId: 'claim-y',
				blockHeight: 102
			})
		);
		await p.retireFixedOutputFeeAction('claim-y', { impossible: true });
		// And on this release again.
		usePool(p, w, 'current');
		await attempt(
			p.selectFeeBumpInputs(500n, 250, {
				fixedOutputs: true,
				feeActionId: 'claim-z',
				blockHeight: 103
			})
		);
		await p.retireFixedOutputFeeAction('claim-z', { impossible: true });
		// What the splits on the chain paid is what the budget says was spent.
		const onChain = w.broadcasts
			.map((raw) => bitcoin.Transaction.fromHex(raw))
			.filter((tx) => w.confirmed.has(tx.getId()) || w.known.has(tx.getId()))
			.filter(
				(tx, i, all) => all.findIndex((o) => o.getId() === tx.getId()) === i
			)
			.reduce((sum, tx) => sum + feeOf(w, tx), 0n);
		expect(w.confirmed.has(split)).equal(true);
		expect(p.getFixedOutputFeeBudget()!.spentSatoshis).equal(onChain);
	});

	it('a raise of a spend asked at a rate that is not a whole sat/vB pays what that spend paid with 1 sat/vB of its whole size over it', async () => {
		const w = world({
			feeCoinCount: 1,
			maxFeeSatoshis: 20_000n,
			maxTotalFeeSatoshis: 200_000n
		});
		w.fund(50_000);
		const p = w.provider();
		// The node asks for a spend of 1000 vbytes at 1.001 sat/vB: its own
		// fee rounded up, and the rate in sat/kw rounded up.
		const vbytes = 1000,
			rate = 1.001;
		const ask = (
			height: number,
			more: Partial<
				Parameters<WalletFundingProvider['selectFeeBumpInputs']>[2]
			> = {}
		): ReturnType<WalletFundingProvider['selectFeeBumpInputs']> =>
			p.selectFeeBumpInputs(
				BigInt(Math.ceil(vbytes * rate)),
				satPerVbyteToSatPerKw(rate),
				{
					fixedOutputs: true,
					feeActionId: 'claim-a',
					blockHeight: height,
					...more
				}
			);
		await attempt(ask(100));
		w.mine();
		const a = await ask(101);
		const held = spendWith(w, a.inputs);
		expect(w.accept(held)).equal(undefined);
		const paid = a.inputs.reduce((sum, input) => sum + input.value, 0n);
		// The rate stays, and the node raises the spend held: a split of the
		// pool's own makes the coin the raise needs, exactly at its target.
		const raise = (
			height: number
		): ReturnType<WalletFundingProvider['selectFeeBumpInputs']> =>
			ask(height, {
				replacementInputs: a.inputs.map(asReplacement),
				replacedTxid: held.getId()
			});
		await attempt(raise(102));
		w.mine([held.getId()]);
		const r = await raise(103);
		expect(r.inputs.length).equal(2);
		// It pays what the spend it replaces paid, with the relay rate of
		// 1 sat/vB on its own size over it (BIP 125 rules 3 and 4).
		const fee = r.inputs.reduce((sum, input) => sum + input.value, 0n);
		expect(Number(fee), 'fee of the raise, sats').to.be.at.least(
			Number(paid) + vbytes + 68 * r.inputs.length
		);
	});

	it('a raise that names the spend it replaces and none of its fee coins is served while the server cannot give that spend, and never pays less than it', async () => {
		const w = world({
			maxFeeSatoshis: 20_000n,
			maxTotalFeeSatoshis: 200_000n
		});
		w.fund(50_000);
		const p = w.provider();
		const ask = (
			height: number,
			more: Partial<
				Parameters<WalletFundingProvider['selectFeeBumpInputs']>[2]
			> = {}
		): ReturnType<WalletFundingProvider['selectFeeBumpInputs']> =>
			p.selectFeeBumpInputs(500n, 250, {
				fixedOutputs: true,
				feeActionId: 'claim-a',
				blockHeight: height,
				confirmedOnly: true,
				...more
			});
		await attempt(ask(100));
		w.mine();
		const a = await ask(101);
		const held = spendWith(w, a.inputs);
		expect(w.accept(held)).equal(undefined);
		const paid = a.inputs.reduce((sum, input) => sum + input.value, 0n);
		// The server gives no answer for the spend held.
		const lookup = w.wallet.electrum.getTransactions!;
		w.wallet.electrum.getTransactions = (async (asked: {
			txHashes: Array<{ tx_hash: string }>;
		}) =>
			asked.txHashes.some(({ tx_hash }) => tx_hash === held.getId())
				? err('the server is busy')
				: lookup(asked as Parameters<typeof lookup>[0])) as typeof lookup;
		// The node's second request: the spend held named, and none of its
		// fee coins.
		let served: Array<{ value: bigint }> | undefined;
		const outcome = await attempt(
			ask(102, { replacedTxid: held.getId() }).then((selection) => {
				served = selection.inputs;
			})
		);
		expect(outcome, String(outcome)).equal(undefined);
		expect(
			Number(served!.reduce((sum, input) => sum + input.value, 0n)),
			'fee of the raise, sats'
		).to.be.at.least(Number(paid) + 500 + 68 * served!.length);
	});

	it('keeps charging a split replacement that went out with no answer once the previous release drops the row of its split and a block takes it', async () => {
		const w = world({ walletCallTimeoutMs: 50 });
		w.fund(50_000);
		const p = w.provider();
		await attempt(
			p.selectFeeBumpInputs(500n, 250, {
				fixedOutputs: true,
				feeActionId: 'claim-x',
				blockHeight: 100
			})
		);
		const split = bitcoin.Transaction.fromHex(w.broadcasts[0]).getId();
		// The split is replaced; the server takes the replacement and answers
		// after the bound.
		w.slow(150);
		const timedOut = await attempt(
			p.selectFeeBumpInputs(500n, 750, {
				fixedOutputs: true,
				feeActionId: 'claim-a',
				blockHeight: 101,
				deadlineHeight: 104
			})
		);
		expect((timedOut as FixedOutputFeeError).code).equal('FEE_WALLET_TIMEOUT');
		await wait(300);
		w.slow(0);
		const replacement = bitcoin.Transaction.fromHex(
			w.broadcasts[w.broadcasts.length - 1]
		).getId();
		expect(w.known.has(replacement), 'the replacement is out').equal(true);
		expect(w.known.has(split)).equal(false);
		await p.retireFixedOutputFeeAction('claim-x', { impossible: true });
		await p.retireFixedOutputFeeAction('claim-a', { impossible: true });
		// The node is run on the previous release, which drops the row of the
		// split; a block takes the replacement.
		usePool(p, w, 'previous');
		await attempt(
			p.selectFeeBumpInputs(500n, 250, {
				fixedOutputs: true,
				feeActionId: 'claim-y',
				blockHeight: 102
			})
		);
		await p.retireFixedOutputFeeAction('claim-y', { impossible: true });
		w.mine();
		expect(w.confirmed.has(replacement)).equal(true);
		// And on this release again.
		usePool(p, w, 'current');
		await attempt(
			p.selectFeeBumpInputs(500n, 250, {
				fixedOutputs: true,
				feeActionId: 'claim-z',
				blockHeight: 103
			})
		);
		await p.retireFixedOutputFeeAction('claim-z', { impossible: true });
		// What the splits on the chain and in the mempool paid is what the
		// budget says was spent.
		const paid = w.broadcasts
			.map((raw) => bitcoin.Transaction.fromHex(raw))
			.filter((tx) => w.known.has(tx.getId()))
			.filter(
				(tx, i, all) => all.findIndex((o) => o.getId() === tx.getId()) === i
			)
			.reduce((sum, tx) => sum + feeOf(w, tx), 0n);
		expect(p.getFixedOutputFeeBudget()!.spentSatoshis).equal(paid);
	});

	it('keeps charging a split replacement that went out when it hands the free coins back while the wallet still lists the split it replaced', async () => {
		const w = world({ walletCallTimeoutMs: 50 });
		w.fund(50_000);
		const p = w.provider();
		await attempt(
			p.selectFeeBumpInputs(500n, 250, {
				fixedOutputs: true,
				feeActionId: 'claim-x',
				blockHeight: 100
			})
		);
		// The listing of the wallet as it stands before the replacement.
		const before = w.coins();
		// The split is replaced; the server takes the replacement and answers
		// after the bound.
		w.slow(150);
		await attempt(
			p.selectFeeBumpInputs(500n, 750, {
				fixedOutputs: true,
				feeActionId: 'claim-a',
				blockHeight: 101,
				deadlineHeight: 104
			})
		);
		await wait(300);
		w.slow(0);
		const replacement = bitcoin.Transaction.fromHex(
			w.broadcasts[w.broadcasts.length - 1]
		).getId();
		expect(w.known.has(replacement), 'the replacement is out').equal(true);
		await p.retireFixedOutputFeeAction('claim-x', { impossible: true });
		await p.retireFixedOutputFeeAction('claim-a', { impossible: true });
		// The wallet's listing lags: it still lists the split replaced.
		const list = w.wallet.listUtxos!;
		w.wallet.listUtxos = (): ISpliceUtxo[] => before;
		expect(await p.releaseFixedOutputFeeCoins()).equal(true);
		w.wallet.listUtxos = list;
		// What the transactions on the chain and in the mempool paid is what
		// the budget says was spent.
		const paid = w.broadcasts
			.map((raw) => bitcoin.Transaction.fromHex(raw))
			.filter((tx) => w.known.has(tx.getId()))
			.filter(
				(tx, i, all) => all.findIndex((o) => o.getId() === tx.getId()) === i
			)
			.reduce((sum, tx) => sum + feeOf(w, tx), 0n);
		expect(p.getFixedOutputFeeBudget()!.spentSatoshis).equal(paid);
	});
});
/** Run the provider on the pool as it is now, or on the pool of the previous release, over the same journal. */
const usePool = (
	p: WalletFundingProvider,
	w: ReturnType<typeof world>,
	which: 'previous' | 'current'
): void => {
	const inner = p as unknown as {
		fixedOutputFeePool: {
			host: ConstructorParameters<typeof FixedOutputFeePool>[2];
		};
	};
	const host = inner.fixedOutputFeePool.host;
	inner.fixedOutputFeePool = (which === 'previous'
		? new PreviousPool(w.wallet, w.policy, host)
		: new FixedOutputFeePool(
				w.wallet,
				w.policy,
				host
		  )) as unknown as typeof inner.fixedOutputFeePool;
};

describe('fee coin pool: claims near their deadlines', function () {
	this.timeout(20000);

	it('serves a claim near its deadline with a split of its own at the rate asked, made from a confirmed coin, not with a coin of a split that pays a fifth of that rate and cannot be replaced', async () => {
		const w = world({
			maxFeeSatoshis: 20_000n,
			maxTotalFeeSatoshis: 200_000n,
			maxPreparationFeeSatoshis: 1_000n
		});
		w.fund(50_000);
		w.fund(50_000);
		const p = w.provider();
		// A claim at 1 sat/vB near its deadline takes a coin of its own split
		// at 1 sat/vB, and its spend goes out: the split cannot be replaced.
		const a = await p.selectFeeBumpInputs(500n, 250, {
			fixedOutputs: true,
			feeActionId: 'claim-a',
			blockHeight: 100,
			deadlineHeight: 104
		});
		const split = txidOf(a.inputs[0]);
		expect(w.accept(spendWith(w, a.inputs))).equal(undefined);
		// A block later the rate is 5 sat/vB, and another claim is three
		// blocks from its deadline. The wallet has a confirmed 50 000 sat coin.
		const b = await p.selectFeeBumpInputs(200n, 1250, {
			fixedOutputs: true,
			feeActionId: 'claim-b',
			blockHeight: 101,
			deadlineHeight: 104
		});
		// The spend made of the answer and the unconfirmed parent of its coins
		// pay the rate asked together, as a package.
		const ownVbytes = 40; // 200 sats at 5 sat/vB
		let fee = b.inputs.reduce((sum, i) => sum + i.value, 0n),
			vsize = ownVbytes + 68 * b.inputs.length;
		for (const parent of new Set(b.inputs.map(txidOf)))
			if (!w.confirmed.has(parent)) {
				const tx = w.known.get(parent)!;
				fee += feeOf(w, tx);
				vsize += tx.virtualSize();
			}
		// Not with a coin of the split at 1 sat/vB.
		expect(b.inputs.map(txidOf)).to.not.include(split);
		expect(Number(fee) / vsize, 'package rate, sat/vB').to.be.at.least(5);
	});

	it('serves a claim near its deadline with a coin of a split that cannot pay its rate when the wallet cannot give a change address for a split of its own', async () => {
		const w = world({
			maxFeeSatoshis: 20_000n,
			maxTotalFeeSatoshis: 200_000n,
			maxPreparationFeeSatoshis: 1_000n
		});
		w.fund(50_000);
		w.fund(50_000);
		const p = w.provider();
		const a = await p.selectFeeBumpInputs(500n, 250, {
			fixedOutputs: true,
			feeActionId: 'claim-a',
			blockHeight: 100,
			deadlineHeight: 104
		});
		expect(w.accept(spendWith(w, a.inputs))).equal(undefined);
		// The wallet cannot give a change address now (any failure of the
		// wallet or its server in the making of a split behaves the same).
		w.wallet.getChangeAddress = async (): Promise<never> =>
			err('no change address') as never;
		// Three blocks from its deadline, at 5 sat/vB. A free coin of the
		// pool's split covers it; that split pays 1 sat/vB.
		const outcome = await attempt(
			p.selectFeeBumpInputs(200n, 1250, {
				fixedOutputs: true,
				feeActionId: 'claim-b',
				blockHeight: 101,
				deadlineHeight: 104
			})
		);
		// A spend that waits on a slow parent can still confirm; one with no
		// fee input does not go out at all.
		expect(
			outcome === undefined
				? 'served'
				: `${(outcome as FixedOutputFeeError).code}: ${outcome.message}`
		).equal('served');
	});

	it('serves a raise that names the spend it replaces and none of its fee coins, for a spend that never went out, from a server that says it does not know that spend in the words of a node without a txindex', async () => {
		const w = world();
		withoutTxindex(w);
		w.fund(50_000);
		const p = w.provider();
		await attempt(
			p.selectFeeBumpInputs(500n, 250, {
				fixedOutputs: true,
				feeActionId: 'claim-a',
				blockHeight: 100
			})
		);
		w.mine();
		const a = await p.selectFeeBumpInputs(500n, 250, {
			fixedOutputs: true,
			feeActionId: 'claim-a',
			blockHeight: 101
		});
		// The node holds the spend made of that coin: it never went out.
		const held = spendWith(w, a.inputs);
		// Its raise was refused for good, and it asks once more, three
		// blocks from the deadline, on each block.
		const told: string[] = [];
		for (const height of [101, 102, 103]) {
			const outcome = await attempt(
				p.selectFeeBumpInputs(500n, 250, {
					fixedOutputs: true,
					feeActionId: 'claim-a',
					blockHeight: height,
					deadlineHeight: 104,
					confirmedOnly: false,
					replacedTxid: held.getId()
				})
			);
			told.push(
				outcome === undefined
					? 'served'
					: `${(outcome as FixedOutputFeeError).code}`
			);
			if (outcome === undefined) break;
			w.mine();
		}
		expect(told[told.length - 1], told.join(', ')).equal('served');
	});

	it('goes on serving selections when a split replacement recorded and never sent, whose split left the mempool, is one the server cannot say it knows, in the words of a node without a txindex', async () => {
		const w = world({ walletCallTimeoutMs: 50 });
		w.fund(50_000);
		w.fund(50_000);
		const p = w.provider();
		await attempt(
			p.selectFeeBumpInputs(500n, 250, {
				fixedOutputs: true,
				feeActionId: 'claim-x',
				blockHeight: 100
			})
		);
		const split = bitcoin.Transaction.fromHex(w.broadcasts[0]).getId();
		// A replacement of the split is recorded, and its broadcast never
		// answers (a stop between the journal write and the send is the same).
		const send = w.wallet.electrum.broadcastTransaction;
		w.wallet.electrum.broadcastTransaction = (async ({
			rawTx
		}: {
			rawTx: string;
		}) => {
			w.broadcasts.push(rawTx);
			return new Promise(() => undefined);
		}) as typeof send;
		const timedOut = await attempt(
			p.selectFeeBumpInputs(500n, 750, {
				fixedOutputs: true,
				feeActionId: 'claim-a',
				blockHeight: 101,
				deadlineHeight: 104
			})
		);
		expect((timedOut as FixedOutputFeeError).code).equal('FEE_WALLET_TIMEOUT');
		w.wallet.electrum.broadcastTransaction = send;
		// The server is electrs on a node without a txindex, and the split,
		// at 1 sat/vB, is purged from the mempool in a fee spike.
		withoutTxindex(w);
		w.known.delete(split);
		// Another claim asks on each block before its deadline.
		const told: string[] = [];
		for (const height of [102, 103, 104]) {
			const outcome = await attempt(
				p.selectFeeBumpInputs(500n, 250, {
					fixedOutputs: true,
					feeActionId: 'claim-b',
					blockHeight: height,
					deadlineHeight: 105
				})
			);
			told.push(
				outcome === undefined
					? 'served'
					: `${(outcome as FixedOutputFeeError).code}`
			);
			if (outcome === undefined) break;
			w.mine();
		}
		expect(
			told.filter((answer) => answer === 'FEE_WALLET_UNAVAILABLE'),
			told.join(', ')
		).deep.equal([]);
	});

	it('serves a claim near its deadline with a coin of a split that cannot pay its rate when the wallet does not answer in time for a change address for a split of its own', async () => {
		const w = world({
			maxFeeSatoshis: 20_000n,
			maxTotalFeeSatoshis: 200_000n,
			maxPreparationFeeSatoshis: 1_000n,
			walletCallTimeoutMs: 50
		});
		w.fund(50_000);
		w.fund(50_000);
		const p = w.provider();
		const a = await p.selectFeeBumpInputs(500n, 250, {
			fixedOutputs: true,
			feeActionId: 'claim-a',
			blockHeight: 100,
			deadlineHeight: 104
		});
		expect(w.accept(spendWith(w, a.inputs))).equal(undefined);
		// The wallet's change address request never answers.
		w.wallet.getChangeAddress = (): Promise<never> =>
			new Promise<never>(() => undefined);
		const told: string[] = [];
		for (const height of [101, 102, 103]) {
			const outcome = await attempt(
				p.selectFeeBumpInputs(200n, 1250, {
					fixedOutputs: true,
					feeActionId: 'claim-b',
					blockHeight: height,
					deadlineHeight: 104
				})
			);
			told.push(
				outcome === undefined
					? 'served'
					: `${(outcome as FixedOutputFeeError).code}`
			);
			if (outcome === undefined) break;
		}
		expect(told[told.length - 1], told.join(', ')).equal('served');
	});

	it('serves a raise that names the spend it replaces and none of its fee coins within the action cap when the server cannot give that spend and the action let go of a coin', async () => {
		const w = world();
		w.fund(50_000);
		const p = w.provider();
		await attempt(
			p.selectFeeBumpInputs(500n, 250, {
				fixedOutputs: true,
				feeActionId: 'claim-a',
				blockHeight: 100
			})
		);
		w.mine();
		const a = await p.selectFeeBumpInputs(500n, 250, {
			fixedOutputs: true,
			feeActionId: 'claim-a',
			blockHeight: 101
		});
		// Its spend goes out with that coin.
		const first = spendWith(w, a.inputs);
		expect(w.accept(first)).equal(undefined);
		// A raise refused for good is asked once more without fee coins: the
		// pool reads that spend, lets go of its coin, and serves the raise
		// with other coins. The node holds the spend made of them; it has not
		// gone out.
		const b = await p.selectFeeBumpInputs(500n, 250, {
			fixedOutputs: true,
			feeActionId: 'claim-a',
			blockHeight: 102,
			deadlineHeight: 110,
			confirmedOnly: true,
			replacedTxid: first.getId()
		});
		const held = spendWith(w, b.inputs);
		const heldPays = b.inputs.reduce((sum, i) => sum + i.value, 0n);
		// The server is electrs on a node without a txindex, and the rate
		// rises to 1.5 sat/vB. The node's next second request names the spend
		// it holds, which the server cannot give.
		withoutTxindex(w);
		const outcome = await attempt(
			p.selectFeeBumpInputs(750n, 375, {
				fixedOutputs: true,
				feeActionId: 'claim-a',
				blockHeight: 103,
				deadlineHeight: 110,
				confirmedOnly: true,
				replacedTxid: held.getId()
			})
		);
		// The coins the node holds cover the raise, and what the spend in the
		// mempool paid with 1 sat/vB of the new size over it, within the cap.
		expect(heldPays < 2000n).equal(true);
		expect(
			outcome === undefined
				? 'served'
				: `${(outcome as FixedOutputFeeError).code}: ${outcome.message}`
		).equal('served');
	});
});

describe('fee coin pool: the node hands the free coins back', function () {
	it('handles a block whole, and asks again on the next, when the provider throws at once on being asked to take the free fee coins back', async () => {
		const secret = (label: string): Buffer =>
			crypto.createHash('sha256').update(`hand-back-${label}`).digest();
		const point = (i: number): Buffer => getPublicKey(secret(String(i)));
		const cm = new ChannelManager({
			localBasepoints: {
				fundingPubkey: point(0),
				revocationBasepoint: point(1),
				paymentBasepoint: point(2),
				delayedPaymentBasepoint: point(3),
				htlcBasepoint: point(4),
				firstPerCommitmentPoint: Buffer.alloc(33)
			},
			localPerCommitmentSeed: secret('seed'),
			localFundingPrivkey: secret('funding'),
			persistence: COMMIT_ALL
		});
		cm.on('error', () => undefined);
		// No asset channel is open or left to resolve, so every block asks.
		let asked = 0;
		cm.setFundingProvider({
			releaseFixedOutputFeeCoins: (): Promise<boolean> => {
				asked++;
				throw new Error('the wallet is closed');
			}
		} as unknown as Parameters<ChannelManager['setFundingProvider']>[0]);
		expect(() => cm.handleNewBlock(101)).to.not.throw();
		await new Promise((resolve) => setImmediate(resolve));
		expect(() => cm.handleNewBlock(102)).to.not.throw();
		expect(asked).equal(2);
	});
});

describe('fee coin pool: what a hand-back of the free coins leaves behind', function () {
	it('does not send again a split replacement recorded and never sent once the free coins of its split were handed back, on a server without a txindex', async () => {
		const w = world({ walletCallTimeoutMs: 50 });
		w.fund(50_000);
		w.fund(50_000);
		const p = w.provider();
		await attempt(
			p.selectFeeBumpInputs(500n, 250, {
				fixedOutputs: true,
				feeActionId: 'claim-x',
				blockHeight: 100
			})
		);
		const split = bitcoin.Transaction.fromHex(w.broadcasts[0]).getId();
		const send = w.wallet.electrum.broadcastTransaction;
		w.wallet.electrum.broadcastTransaction = (async ({
			rawTx
		}: {
			rawTx: string;
		}) => {
			w.broadcasts.push(rawTx);
			return new Promise(() => undefined);
		}) as typeof send;
		const timedOut = await attempt(
			p.selectFeeBumpInputs(500n, 750, {
				fixedOutputs: true,
				feeActionId: 'claim-a',
				blockHeight: 101,
				deadlineHeight: 104
			})
		);
		expect((timedOut as FixedOutputFeeError).code).equal('FEE_WALLET_TIMEOUT');
		w.wallet.electrum.broadcastTransaction = send;
		const replacement = bitcoin.Transaction.fromHex(
			w.broadcasts[w.broadcasts.length - 1]
		).getId();
		withoutTxindex(w);
		await p.retireFixedOutputFeeAction('claim-x', { impossible: true });
		await p.retireFixedOutputFeeAction('claim-a', { impossible: true });
		// No asset channel is left: the free coins of the split go back to the
		// wallet, and are its own from now on.
		expect(await p.releaseFixedOutputFeeCoins()).equal(true);
		expect(
			(w.journal().coins ?? []).map((c) => `${c.utxo.tx_hash}:${c.utxo.tx_pos}`)
		).deep.equal([]);
		const given = w.coins().filter((c) => c.tx_hash === split);
		expect(given.length).to.be.above(0);
		// Later a new asset channel needs a fee coin, while the split is still
		// unconfirmed.
		await attempt(
			p.selectFeeBumpInputs(500n, 250, {
				fixedOutputs: true,
				feeActionId: 'claim-b',
				blockHeight: 105,
				deadlineHeight: 120
			})
		);
		// The pool does not pay to replace a split whose coins it gave back.
		expect(w.known.has(replacement), 'the replacement was sent again').equal(
			false
		);
		expect(w.known.has(split)).equal(true);
	});
});
