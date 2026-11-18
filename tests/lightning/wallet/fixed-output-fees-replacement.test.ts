/**
 * The fee coin pool (fixed-output-fees.ts) as split replacements, blocks
 * and raises of a spend move its coins, and the journal it keeps across
 * versions of the pool.
 *
 * The wallet sits on a small chain with a mempool: a transaction that spends
 * what one in the mempool spends replaces it, every transaction that spends
 * an output of the one replaced goes with it, and the wallet lists only the
 * outputs nothing spends.
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
const asReplacement = (input: {
	prevTx: Buffer;
	prevOutputIndex: number;
	sequence: number;
}): { txid: string; vout: number; sequence: number } => ({
	txid: txidOf(input),
	vout: input.prevOutputIndex,
	sequence: input.sequence
});

describe('fee coin pool: split replacements and the coins they move', function () {
	this.timeout(20000);

	it('a split replacement moves the fee coin of a spend the node holds, and a raise of that spend is served with the coin where it is now', async () => {
		const w = world();
		w.fund(50_000);
		const p = w.provider();
		// A claim by preimage four blocks from its deadline takes a coin of its
		// own split before the split confirms.
		const a = await p.selectFeeBumpInputs(500n, 250, {
			fixedOutputs: true,
			feeActionId: 'claim-a',
			blockHeight: 100,
			deadlineHeight: 104
		});
		expect(a.inputs).length(1);
		const split = txidOf(a.inputs[0]);
		// The node signs its spend with that coin and keeps it as the spend of
		// the output. It has not reached the wallet's server yet (its output
		// has not matured, or it is still held for the monitor write).
		const held = spendWith(w, a.inputs);

		// Another claim, a block later and at a higher rate: the pool replaces
		// the split by one that pays more.
		await p.selectFeeBumpInputs(500n, 750, {
			fixedOutputs: true,
			feeActionId: 'claim-b',
			blockHeight: 101,
			deadlineHeight: 104
		});
		expect(w.known.has(split), 'the split was replaced').equal(false);
		const replacement = bitcoin.Transaction.fromHex(
			w.broadcasts[w.broadcasts.length - 1]
		).getId();
		// The coin the held spend names no longer exists: that spend can never
		// be taken by the network.
		expect(w.accept(held)).equal('missing inputs');
		w.mine();

		// The node asks for a raise of the spend it holds, naming its fee input,
		// as it does for every spend whose fee inputs it already has
		// (channel-manager.ts handleFixedOutputFee). The pool holds the coin
		// at the same position of the replacement for this very action, and
		// has a confirmed free coin beside it.
		let served: string[] = [];
		const raised = await attempt(
			p
				.selectFeeBumpInputs(600n, 750, {
					fixedOutputs: true,
					feeActionId: 'claim-a',
					blockHeight: 102,
					deadlineHeight: 104,
					replacementInputs: a.inputs.map(asReplacement),
					replacedTxid: held.getId()
				})
				.then((selection) => {
					served = selection.inputs.map(outpointOf);
				})
		);
		expect(
			raised === undefined
				? 'served'
				: `${(raised as FixedOutputFeeError).code}: ${raised.message}`
		).equal('served');
		// The node is told where its coin is now, and makes its next spend
		// with it.
		expect(served).to.include(`${replacement}:${a.inputs[0].prevOutputIndex}`);
	});

	it('a block that takes the split a replacement replaced moves the fee coin of a spend already sent, and a raise of that spend is served with the coin where it is now', async () => {
		const w = world();
		w.fund(50_000);
		const p = w.provider();
		// A claim with no deadline near makes a split, and waits for it.
		await attempt(
			p.selectFeeBumpInputs(500n, 250, {
				fixedOutputs: true,
				feeActionId: 'claim-x',
				blockHeight: 100
			})
		);
		const first = bitcoin.Transaction.fromHex(w.broadcasts[0]);
		// A claim near its deadline, at a higher rate: the split is replaced,
		// and the claim takes a coin of the replacement.
		const a = await p.selectFeeBumpInputs(500n, 750, {
			fixedOutputs: true,
			feeActionId: 'claim-a',
			blockHeight: 101,
			deadlineHeight: 104
		});
		const replacement = txidOf(a.inputs[0]);
		expect(replacement).not.equal(first.getId());
		// Its spend goes out and the mempool takes it.
		const sent = spendWith(w, a.inputs);
		expect(w.accept(sent)).equal(undefined);
		// A miner that never saw the replacement takes the first split: the
		// replacement and the spend leave the mempool.
		w.mineInstead(first);
		expect(w.known.has(sent.getId())).equal(false);

		// The node asks for a raise of the spend it holds, naming its fee input.
		let served: string[] = [];
		const raised = await attempt(
			p
				.selectFeeBumpInputs(600n, 750, {
					fixedOutputs: true,
					feeActionId: 'claim-a',
					blockHeight: 102,
					deadlineHeight: 104,
					replacementInputs: a.inputs.map(asReplacement),
					replacedTxid: sent.getId()
				})
				.then((selection) => {
					served = selection.inputs.map(outpointOf);
				})
		);
		expect(
			raised === undefined
				? 'served'
				: `${(raised as FixedOutputFeeError).code}: ${raised.message}`
		).equal('served');
		// The node is told where its coins are now: at the same positions of
		// the split the block took.
		expect(served).to.include.members(
			a.inputs.map((input) => `${first.getId()}:${input.prevOutputIndex}`)
		);
	});

	it('a split replacement that the server takes after the wallet call timed out is recorded and charged, and its fee coins stay in the pool', async () => {
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
		const first = bitcoin.Transaction.fromHex(w.broadcasts[0]);
		// The server takes the replacement, and answers after the bound.
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
		);
		expect(w.known.has(replacement.getId()), 'the replacement is out').equal(
			true
		);
		expect(w.known.has(first.getId())).equal(false);
		// The next selection.
		await attempt(
			p.selectFeeBumpInputs(500n, 750, {
				fixedOutputs: true,
				feeActionId: 'claim-a',
				blockHeight: 101,
				deadlineHeight: 104
			})
		);
		// What the splits on the chain paid is what the budget says was spent.
		expect(p.getFixedOutputFeeBudget()!.spentSatoshis).equal(
			feeOf(w, replacement)
		);
	});

	it('the coins a split replacement moves are frozen, so a send of the wallet itself cannot take a coin an action holds', async () => {
		const w = world();
		w.fund(50_000);
		const p = w.provider();
		await p.selectFeeBumpInputs(500n, 250, {
			fixedOutputs: true,
			feeActionId: 'claim-a',
			blockHeight: 100,
			deadlineHeight: 104
		});
		await p.selectFeeBumpInputs(500n, 750, {
			fixedOutputs: true,
			feeActionId: 'claim-b',
			blockHeight: 101,
			deadlineHeight: 104
		});
		// Every coin the pool holds, for an action or free, that the wallet
		// lists is frozen: the wallet's own send (buildFundingTransaction,
		// sendMax) passes over frozen coins only.
		const journal = w.journal();
		const held = [
			...Object.values(journal.actions).flatMap((action) =>
				action.inputs.map((c) => `${c.utxo.tx_hash}:${c.utxo.tx_pos}`)
			),
			...(journal.coins ?? []).map((c) => `${c.utxo.tx_hash}:${c.utxo.tx_pos}`)
		];
		const listed = new Set(w.coins().map((c) => `${c.tx_hash}:${c.tx_pos}`));
		expect(held.filter((k) => listed.has(k) && !w.frozen.has(k))).deep.equal(
			[]
		);
	});

	it('a claim whose spend took a coin of a split that cannot be replaced raises that spend from confirmed coins of a split of its own', async () => {
		const w = world({
			maxFeeSatoshis: 20_000n,
			maxTotalFeeSatoshis: 200_000n,
			maxPreparationFeeSatoshis: 5_000n
		});
		w.fund(50_000);
		w.fund(50_000);
		const p = w.provider();
		// A claim by preimage four blocks from its deadline takes a coin of its
		// own split before the split confirms, and its spend goes out with it.
		const a = await p.selectFeeBumpInputs(500n, 250, {
			fixedOutputs: true,
			feeActionId: 'claim-a',
			blockHeight: 100,
			deadlineHeight: 104
		});
		const split = txidOf(a.inputs[0]);
		const spend = spendWith(w, a.inputs);
		expect(w.accept(spend)).equal(undefined);
		// The rate of the day rises: no block takes the split or the spend.
		w.mine([split, spend.getId()]);
		w.mine([split, spend.getId()]);
		// The node raises the spend at the new rate, block after block. A
		// replacement may add confirmed inputs only (BIP 125 rule 2), and the
		// wallet has a confirmed coin to split.
		const raise = (
			height: number
		): ReturnType<WalletFundingProvider['selectFeeBumpInputs']> =>
			p.selectFeeBumpInputs(1500n, 2500, {
				fixedOutputs: true,
				feeActionId: 'claim-a',
				blockHeight: height,
				deadlineHeight: 104,
				replacementInputs: a.inputs.map(asReplacement),
				replacedTxid: spend.getId()
			});
		await attempt(raise(102));
		w.mine([split, spend.getId()]);
		// One block before the deadline the raise has to go out.
		let served: string[] = [];
		const last = await attempt(
			raise(103).then((selection) => {
				served = selection.inputs.map(outpointOf);
			})
		);
		expect(
			last === undefined
				? 'served'
				: `${(last as FixedOutputFeeError).code}: ${last.message}`
		).equal('served');
		// It lets go of the coin of the split that is stuck: a spend that kept
		// it would wait on that split, at the rate the split pays. Every coin
		// it has is confirmed.
		expect(served.filter((outpoint) => outpoint.startsWith(split))).deep.equal(
			[]
		);
		expect(
			served.every((outpoint) => w.confirmed.has(outpoint.split(':')[0]))
		).equal(true);
	});

	it('a selection that may take an unconfirmed coin replaces only a split it takes a coin of', async () => {
		const w = world({
			maxFeeSatoshis: 20_000n,
			maxTotalFeeSatoshis: 200_000n,
			maxPreparationFeeSatoshis: 5_000n
		});
		w.fund(50_000);
		const p = w.provider();
		// A claim with no deadline near makes a split, which confirms, and is
		// served from it: three coins of that split are left free.
		await attempt(
			p.selectFeeBumpInputs(500n, 250, {
				fixedOutputs: true,
				feeActionId: 'claim-c',
				blockHeight: 100
			})
		);
		w.mine();
		await p.selectFeeBumpInputs(500n, 250, {
			fixedOutputs: true,
			feeActionId: 'claim-c',
			blockHeight: 101
		});
		// Another claim with no deadline near needs larger coins: a second
		// split goes out at 1 sat/vB, as that claim asked.
		await attempt(
			p.selectFeeBumpInputs(5000n, 250, {
				fixedOutputs: true,
				feeActionId: 'claim-d',
				blockHeight: 101
			})
		);
		const splits = w.broadcasts.length;
		// A claim near its deadline at 3 sat/vB, that a confirmed free coin of
		// the first split serves.
		const b = await p.selectFeeBumpInputs(300n, 750, {
			fixedOutputs: true,
			feeActionId: 'claim-b',
			blockHeight: 102,
			deadlineHeight: 104
		});
		expect(b.inputs.every((input) => w.confirmed.has(txidOf(input)))).equal(
			true
		);
		// It takes no coin of the second split, and nothing was paid to
		// replace that split for it.
		expect(
			w.broadcasts.slice(splits).map((raw) => {
				const tx = bitcoin.Transaction.fromHex(raw);
				return `replacement paying ${feeOf(w, tx)} sats`;
			})
		).deep.equal([]);
	});

	it('a claim takes two small free coins that cover it for a tenth of the fee in place of one large one', async () => {
		const w = world({
			maxFeeSatoshis: 20_000n,
			maxTotalFeeSatoshis: 200_000n,
			maxPreparationFeeSatoshis: 5_000n
		});
		w.fund(100_000);
		const p = w.provider();
		// Free coins of two sizes, from splits made for two claims: three of
		// 568 sats and three of 14,068 sats.
		for (const [id, target] of [
			['claim-small', 500n],
			['claim-large', 14_000n]
		] as const) {
			await attempt(
				p.selectFeeBumpInputs(target, 250, {
					fixedOutputs: true,
					feeActionId: id,
					blockHeight: 100
				})
			);
			w.mine();
			await p.selectFeeBumpInputs(target, 250, {
				fixedOutputs: true,
				feeActionId: id,
				blockHeight: 101
			});
		}
		const free = w
			.journal()
			.coins!.map((c) => c.utxo.value)
			.sort((a, b) => a - b);
		expect(free).deep.equal([568, 568, 568, 14068, 14068, 14068]);
		// A claim that needs 1,000 sats with one fee input, or 1,068 with two
		// (1 sat/vB): two coins of 568 cover it. Every fee input is burned
		// whole, so what the inputs hold is the fee.
		const c = await p.selectFeeBumpInputs(932n, 250, {
			fixedOutputs: true,
			feeActionId: 'claim-c',
			blockHeight: 102
		});
		const paid = c.inputs.reduce((sum, input) => sum + input.value, 0n);
		expect(Number(paid)).at.most(1136);
	});

	it('after a reorganisation puts a split back in the mempool, a claim that wants confirmed coins makes a split of its own', async () => {
		const w = world({
			maxFeeSatoshis: 20_000n,
			maxTotalFeeSatoshis: 200_000n,
			maxPreparationFeeSatoshis: 5_000n
		});
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
		w.mine();
		await p.selectFeeBumpInputs(500n, 250, {
			fixedOutputs: true,
			feeActionId: 'claim-x',
			blockHeight: 101
		});
		// A reorganisation takes the split out of its block, and no block of
		// the new branch takes it at its rate of 1 sat/vB.
		w.confirmed.delete(split);
		// A claim with no deadline (one the node asks confirmed coins for), at
		// 10 sat/vB, block after block. The wallet has a confirmed coin to split.
		let last: unknown;
		for (let height = 102; height <= 106; height++) {
			last = await attempt(
				p.selectFeeBumpInputs(1500n, 2500, {
					fixedOutputs: true,
					feeActionId: 'claim-y',
					blockHeight: height,
					confirmedOnly: true
				})
			);
			if (last === undefined) break;
			w.mine([split]);
		}
		expect(
			last === undefined
				? 'served'
				: `${(last as FixedOutputFeeError).code} on ${
						(last as { transactionId?: string }).transactionId === split
							? 'the split put back'
							: 'something else'
				  }, ${w.broadcasts.length} transaction(s) sent`
		).equal('served');
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
/** The rate a transaction of the wallet pays, in sat/vB. */
const rateOf = (w: ReturnType<typeof world>, txid: string): number => {
	const tx = w.known.get(txid)!;
	return Number(feeOf(w, tx)) / tx.virtualSize();
};
const told = (error: unknown): string =>
	error === undefined
		? 'served'
		: `${(error as FixedOutputFeeError).code} (${
				(error as FixedOutputFeeError).remedy
		  }): ${(error as Error).message}`;

describe('fee coin pool: raises, the coins a selection takes, and the journal across versions', function () {
	this.timeout(20000);

	it('a raise that names a fee coin the action let go of in an earlier raise, which the node did not take up, is served with the coins the action holds', async () => {
		const w = world({
			maxFeeSatoshis: 20_000n,
			maxTotalFeeSatoshis: 200_000n,
			maxPreparationFeeSatoshis: 5_000n
		});
		w.fund(50_000);
		w.fund(50_000);
		const p = w.provider();
		// A claim by preimage five blocks from its deadline takes a coin of its
		// own split before the split confirms, and its spend goes out with it.
		const a = await p.selectFeeBumpInputs(500n, 250, {
			fixedOutputs: true,
			feeActionId: 'claim-a',
			blockHeight: 100,
			deadlineHeight: 105
		});
		const split = txidOf(a.inputs[0]);
		const spend = spendWith(w, a.inputs);
		expect(w.accept(spend)).equal(undefined);
		w.mine([split, spend.getId()]);
		w.mine([split, spend.getId()]);
		// The node raises the spend it holds at 10 sat/vB, naming its fee input,
		// as handleFixedOutputFee does.
		const raise = (
			height: number
		): ReturnType<WalletFundingProvider['selectFeeBumpInputs']> =>
			p.selectFeeBumpInputs(1500n, 2500, {
				fixedOutputs: true,
				feeActionId: 'claim-a',
				blockHeight: height,
				deadlineHeight: 105,
				replacementInputs: a.inputs.map(asReplacement),
				replacedTxid: spend.getId()
			});
		// The pool lets go of the coin of the stuck split and makes a split of
		// its own; a block later the raise is served from it.
		expect(((await attempt(raise(102))) as FixedOutputFeeError).code).equal(
			'FEE_PREPARATION_PENDING'
		);
		w.mine([split, spend.getId()]);
		const served = await raise(103);
		expect(
			served.inputs.map(outpointOf).some((o) => o.startsWith(split))
		).equal(false);
		// The node does not take that raise up: the monitor refused to make the
		// spend with those inputs (fundFixedOutputSpend answered not ok), or the
		// node stopped before the monitor was stored, while the pool's journal
		// was. The spend it holds is the one that names the stuck coin, and it
		// is still in the mempool.
		expect(w.known.has(spend.getId())).equal(true);
		w.mine([split, spend.getId()]);
		// A block before the deadline it asks again, exactly as before.
		const again = await attempt(raise(104));
		expect(told(again)).equal('served');
	});

	it('a selection served from a coin the action holds has the split of that coin replaced when it is due and pays less than the rate asked', async () => {
		const w = world();
		w.fund(50_000);
		const p = w.provider();
		// A claim by preimage four blocks from its deadline takes a coin of its
		// own split, made at 1 sat/vB, before the split confirms.
		const a = await p.selectFeeBumpInputs(500n, 250, {
			fixedOutputs: true,
			feeActionId: 'claim-a',
			blockHeight: 100,
			deadlineHeight: 104
		});
		const split = txidOf(a.inputs[0]);
		expect(rateOf(w, split)).below(1.1);
		// The node could not make its spend with that coin (the monitor refused,
		// or the node stopped before its monitor was stored), so the spend it
		// holds has no fee input. A block later it asks again, at 3 sat/vB.
		const again = await p.selectFeeBumpInputs(300n, 750, {
			fixedOutputs: true,
			feeActionId: 'claim-a',
			blockHeight: 101,
			deadlineHeight: 104
		});
		// The coin it is served with is of a split that has not confirmed. That
		// split pays the rate asked, so that the two can confirm in one block.
		const parents = [...new Set(again.inputs.map(txidOf))];
		expect(parents.every((id) => !w.confirmed.has(id))).equal(true);
		expect(
			parents.map(
				(id) =>
					`${id === split ? 'the split' : 'a replacement'} at ${rateOf(
						w,
						id
					).toFixed(2)} sat/vB`
			)
		).deep.equal(
			parents.map(
				(id) =>
					`${id === split ? 'the split' : 'a replacement'} at ${Math.max(
						3,
						rateOf(w, id)
					).toFixed(2)} sat/vB`
			)
		);
	});

	it('a claim near its deadline takes a confirmed free coin that covers it before coins of a split made in the same block at a lower rate', async () => {
		const w = world({
			maxFeeSatoshis: 20_000n,
			maxTotalFeeSatoshis: 200_000n,
			maxPreparationFeeSatoshis: 5_000n
		});
		w.fund(100_000);
		const p = w.provider();
		// Confirmed free coins of 2,068 sats, from a split made for a claim.
		await attempt(
			p.selectFeeBumpInputs(2000n, 250, {
				fixedOutputs: true,
				feeActionId: 'claim-large',
				blockHeight: 100,
				confirmedOnly: true
			})
		);
		w.mine();
		await p.selectFeeBumpInputs(2000n, 250, {
			fixedOutputs: true,
			feeActionId: 'claim-large',
			blockHeight: 101,
			confirmedOnly: true
		});
		// Another claim, with no deadline near and a cap of its own below
		// 2,068 sats, has a split of 568-sat coins made at 1 sat/vB, and waits
		// for it to confirm.
		await attempt(
			p.selectFeeBumpInputs(500n, 250, {
				fixedOutputs: true,
				feeActionId: 'claim-x',
				blockHeight: 101,
				confirmedOnly: true,
				maxFeeSatoshis: 1500n
			})
		);
		const small = bitcoin.Transaction.fromHex(
			w.broadcasts[w.broadcasts.length - 1]
		).getId();
		expect(w.confirmed.has(small)).equal(false);
		// In the same block, a claim three blocks from its deadline, at 3 sat/vB,
		// that one confirmed free coin of 2,068 sats covers alone.
		const c = await p.selectFeeBumpInputs(900n, 750, {
			fixedOutputs: true,
			feeActionId: 'claim-c',
			blockHeight: 101,
			deadlineHeight: 104
		});
		// Every coin it is given is confirmed, or of a split that pays the rate
		// asked: a spend that takes a coin of a split at 1 sat/vB waits on it.
		expect(
			[...new Set(c.inputs.map(txidOf))]
				.filter((id) => !w.confirmed.has(id) && rateOf(w, id) < 3)
				.map(
					(id) =>
						`${inputsOf(c, id)} coin(s) of a split at ${rateOf(w, id).toFixed(
							2
						)} sat/vB, unconfirmed`
				)
		).deep.equal([]);
	});

	it('a selection counts what the split replacement its coins set off pays, and takes a confirmed coin when the small coins and that replacement cost more', async () => {
		const w = world({
			maxFeeSatoshis: 20_000n,
			maxTotalFeeSatoshis: 200_000n,
			maxPreparationFeeSatoshis: 5_000n
		});
		w.fund(100_000);
		const p = w.provider();
		await attempt(
			p.selectFeeBumpInputs(2000n, 250, {
				fixedOutputs: true,
				feeActionId: 'claim-large',
				blockHeight: 100,
				confirmedOnly: true
			})
		);
		w.mine();
		await p.selectFeeBumpInputs(2000n, 250, {
			fixedOutputs: true,
			feeActionId: 'claim-large',
			blockHeight: 101,
			confirmedOnly: true
		});
		await attempt(
			p.selectFeeBumpInputs(500n, 250, {
				fixedOutputs: true,
				feeActionId: 'claim-x',
				blockHeight: 101,
				confirmedOnly: true,
				maxFeeSatoshis: 1500n
			})
		);
		const before = p.getFixedOutputFeeBudget()!.spentSatoshis;
		// A block later, the same claim near its deadline at 3 sat/vB.
		const c = await p.selectFeeBumpInputs(900n, 750, {
			fixedOutputs: true,
			feeActionId: 'claim-c',
			blockHeight: 102,
			deadlineHeight: 104
		});
		const burned = c.inputs.reduce((sum, i) => sum + i.value, 0n);
		const replacement = p.getFixedOutputFeeBudget()!.spentSatoshis - before;
		// What the wallet gives up for this claim: the coins it burns, and what
		// the split replacement its choice set off pays over the split. The
		// confirmed coin of 2,068 sats it passed over would have cost that alone.
		expect(
			`${burned} burned + ${replacement} for a split replacement = ${
				burned + replacement
			}`
		).equal(
			`${burned} burned + ${replacement} for a split replacement = ${
				burned + replacement <= 2068n ? burned + replacement : '<= 2068'
			}`
		);
	});

	it('a raise lets go of a coin of a split a reorganisation put back in the mempool that pays less than the rate asked, and is funded from confirmed coins', async () => {
		const w = world({
			maxFeeSatoshis: 20_000n,
			maxTotalFeeSatoshis: 200_000n,
			maxPreparationFeeSatoshis: 5_000n
		});
		w.fund(50_000);
		w.fund(50_000);
		const p = w.provider();
		await attempt(
			p.selectFeeBumpInputs(500n, 250, {
				fixedOutputs: true,
				feeActionId: 'claim-x',
				blockHeight: 100,
				confirmedOnly: true
			})
		);
		const split = bitcoin.Transaction.fromHex(w.broadcasts[0]).getId();
		w.mine();
		await p.selectFeeBumpInputs(500n, 250, {
			fixedOutputs: true,
			feeActionId: 'claim-x',
			blockHeight: 101,
			confirmedOnly: true
		});
		// A reorganisation takes the split out of its block, and no block of
		// the new branch takes it at its rate of 1 sat/vB.
		w.confirmed.delete(split);
		// A claim by preimage four blocks from its deadline takes a free coin of
		// that split, and its spend goes out with it.
		const a = await p.selectFeeBumpInputs(500n, 250, {
			fixedOutputs: true,
			feeActionId: 'claim-a',
			blockHeight: 102,
			deadlineHeight: 106
		});
		expect(a.inputs.map(txidOf)).deep.equal([split]);
		const spend = spendWith(w, a.inputs);
		expect(w.accept(spend)).equal(undefined);
		w.mine([split, spend.getId()]);
		// The rate rises to 10 sat/vB, and the node raises the spend block
		// after block.
		const raise = (
			height: number
		): ReturnType<WalletFundingProvider['selectFeeBumpInputs']> =>
			p.selectFeeBumpInputs(1500n, 2500, {
				fixedOutputs: true,
				feeActionId: 'claim-a',
				blockHeight: height,
				deadlineHeight: 106,
				replacementInputs: a.inputs.map(asReplacement),
				replacedTxid: spend.getId()
			});
		await attempt(raise(103));
		w.mine([split, spend.getId()]);
		let served: string[] = [];
		const last = await attempt(
			raise(104).then((selection) => {
				served = selection.inputs.map(outpointOf);
			})
		);
		expect(told(last)).equal('served');
		// As with a split a spend took a coin of, the raise lets go of the coin
		// of a split that cannot be replaced and pays less than the rate asked:
		// every coin of it is confirmed.
		expect(served.filter((o) => !w.confirmed.has(o.split(':')[0]))).deep.equal(
			[]
		);
	});

	it('a raise that names a fee coin the previous release moved by a split replacement is served with the coin where the record of that replacement puts it', async () => {
		const w = world();
		w.fund(50_000);
		const p = w.provider();
		// The previous release runs the pool: a split replacement moves the
		// coin of claim-a.
		usePool(p, w, 'previous');
		const a = await p.selectFeeBumpInputs(500n, 250, {
			fixedOutputs: true,
			feeActionId: 'claim-a',
			blockHeight: 100,
			deadlineHeight: 104
		});
		const split = txidOf(a.inputs[0]);
		const held = spendWith(w, a.inputs);
		await p.selectFeeBumpInputs(500n, 750, {
			fixedOutputs: true,
			feeActionId: 'claim-b',
			blockHeight: 101,
			deadlineHeight: 104
		});
		expect(w.known.has(split), 'the split was replaced').equal(false);
		// The journal the previous release wrote names the split replaced
		// among the splits the one that stands replaced (its prior field).
		const stands = (
			w.journal().unconfirmed as Array<{
				txid?: string;
				prior?: Array<{ txid: string }>;
			}>
		).find((row) => row.prior?.some((old) => old.txid === split));
		expect(stands, 'the journal holds where the coin went').not.equal(
			undefined
		);
		// The node is upgraded to this release, and a block takes the split
		// that stands: the pool has a confirmed free coin beside the coin of
		// claim-a.
		usePool(p, w, 'current');
		w.mine();
		let served: string[] = [];
		const raised = await attempt(
			p
				.selectFeeBumpInputs(600n, 750, {
					fixedOutputs: true,
					feeActionId: 'claim-a',
					blockHeight: 102,
					deadlineHeight: 104,
					replacementInputs: a.inputs.map(asReplacement),
					replacedTxid: held.getId()
				})
				.then((selection) => {
					served = selection.inputs.map(outpointOf);
				})
		);
		expect(told(raised)).equal('served');
		// The node is told where its coin is now, and makes its next spend
		// with it.
		expect(served).to.include(`${stands!.txid}:${a.inputs[0].prevOutputIndex}`);
	});

	it('a retirement that names the spend which took a fee coin where it was before a split replacement moved it charges that coin', async () => {
		const w = world();
		w.fund(50_000);
		const p = w.provider();
		const a = await p.selectFeeBumpInputs(500n, 250, {
			fixedOutputs: true,
			feeActionId: 'claim-a',
			blockHeight: 100,
			deadlineHeight: 104
		});
		const first = bitcoin.Transaction.fromHex(w.broadcasts[0]);
		// The node holds its spend with that coin (not yet sent).
		const held = spendWith(w, a.inputs);
		// Another claim at a higher rate: the split is replaced, and the coin of
		// claim-a moves to the replacement.
		await p.selectFeeBumpInputs(500n, 750, {
			fixedOutputs: true,
			feeActionId: 'claim-b',
			blockHeight: 101,
			deadlineHeight: 104
		});
		// A miner that never saw the replacement takes the first split; the
		// held spend then goes out, with the coin where it was, and confirms.
		w.mineInstead(first);
		expect(w.accept(held)).equal(undefined);
		w.mine();
		expect(w.confirmed.has(held.getId())).equal(true);
		// The output is settled for good and the action is retired, naming the
		// spend that settled it. No fee selection ran in between.
		await p.retireFixedOutputFeeAction('claim-a', {
			spendingTransaction: held.toBuffer()
		});
		// The next selection settles the splits.
		await p.selectFeeBumpInputs(500n, 750, {
			fixedOutputs: true,
			feeActionId: 'claim-b',
			blockHeight: 103,
			deadlineHeight: 104
		});
		// The chain burned the fee of the first split and the coin the held
		// spend took.
		expect(p.getFixedOutputFeeBudget()!.spentSatoshis).equal(
			feeOf(w, first) + a.inputs[0].value
		);
	});

	it('a retirement that names the spend which took a fee coin where it was before the previous release moved it charges that coin', async () => {
		const w = world();
		w.fund(50_000);
		const p = w.provider();
		// The previous release runs the pool: claim-a takes a coin of its
		// split, the node holds its spend, and the split is replaced for
		// claim-b, which moves the coin of claim-a.
		usePool(p, w, 'previous');
		const a = await p.selectFeeBumpInputs(500n, 250, {
			fixedOutputs: true,
			feeActionId: 'claim-a',
			blockHeight: 100,
			deadlineHeight: 104
		});
		const first = bitcoin.Transaction.fromHex(w.broadcasts[0]);
		const held = spendWith(w, a.inputs);
		await p.selectFeeBumpInputs(500n, 750, {
			fixedOutputs: true,
			feeActionId: 'claim-b',
			blockHeight: 101,
			deadlineHeight: 104
		});
		expect(w.known.has(first.getId()), 'the split was replaced').equal(false);
		// A miner that never saw the replacement takes the first split; the
		// held spend then goes out, with the coin where it was, and confirms.
		w.mineInstead(first);
		expect(w.accept(held)).equal(undefined);
		w.mine();
		// The node is upgraded, and retires the action naming that spend
		// before any selection.
		usePool(p, w, 'current');
		await p.retireFixedOutputFeeAction('claim-a', {
			spendingTransaction: held.toBuffer()
		});
		await p.selectFeeBumpInputs(500n, 750, {
			fixedOutputs: true,
			feeActionId: 'claim-b',
			blockHeight: 103,
			deadlineHeight: 104
		});
		// The chain burned the fee of the first split and the coin the held
		// spend took.
		expect(p.getFixedOutputFeeBudget()!.spentSatoshis).equal(
			feeOf(w, first) + a.inputs[0].value
		);
	});

	it('a moved record is followed only while the action holds the coin it points to: after the previous release moved the coin back, a raise is served with the coin the action holds', async () => {
		const w = world();
		w.fund(50_000);
		const p = w.provider();
		// This release: claim-a takes a coin of its split; the node holds its
		// spend.
		const a = await p.selectFeeBumpInputs(500n, 250, {
			fixedOutputs: true,
			feeActionId: 'claim-a',
			blockHeight: 100,
			deadlineHeight: 104
		});
		const first = bitcoin.Transaction.fromHex(w.broadcasts[0]);
		const held = spendWith(w, a.inputs);
		// Another claim replaces the split: claim-a's coin moves, and its row
		// records where (the moved field).
		await p.selectFeeBumpInputs(500n, 750, {
			fixedOutputs: true,
			feeActionId: 'claim-b',
			blockHeight: 101,
			deadlineHeight: 104
		});
		expect(w.known.has(first.getId())).equal(false);
		// The node goes back to the previous release. A miner that never saw
		// the replacement takes the first split, and a selection of the
		// previous release moves the coins back to it, leaving the moved field
		// as it was, since it does not know it.
		usePool(p, w, 'previous');
		w.mineInstead(first);
		await p.selectFeeBumpInputs(500n, 750, {
			fixedOutputs: true,
			feeActionId: 'claim-b',
			blockHeight: 102,
			deadlineHeight: 104
		});
		// The held spend now goes out: its coin exists again.
		expect(w.accept(held)).equal(undefined);
		// The node is upgraded again, and raises that spend, naming its coin
		// where it is.
		usePool(p, w, 'current');
		const raised = await attempt(
			p.selectFeeBumpInputs(600n, 750, {
				fixedOutputs: true,
				feeActionId: 'claim-a',
				blockHeight: 103,
				deadlineHeight: 104,
				replacementInputs: a.inputs.map(asReplacement),
				replacedTxid: held.getId()
			})
		);
		expect(told(raised)).equal('served');
	});

	it('a selection that wants confirmed coins does not wait on a split whose coins cannot cover it, and makes a split of its own at once', async () => {
		const w = world({
			maxFeeSatoshis: 20_000n,
			maxTotalFeeSatoshis: 200_000n,
			maxPreparationFeeSatoshis: 5_000n
		});
		w.fund(50_000);
		w.fund(50_000);
		const p = w.provider();
		// A small claim has a split of four 568-sat coins made at 1 sat/vB.
		await attempt(
			p.selectFeeBumpInputs(500n, 250, {
				fixedOutputs: true,
				feeActionId: 'claim-x',
				blockHeight: 100,
				confirmedOnly: true
			})
		);
		const small = bitcoin.Transaction.fromHex(w.broadcasts[0]).getId();
		// A raise of a claim near its deadline, in the same block, that wants
		// confirmed coins and needs 3,068 sats: the four coins of that split,
		// 2,272 sats in all, can never cover it.
		const big = (height: number): Promise<unknown> =>
			p.selectFeeBumpInputs(3000n, 250, {
				fixedOutputs: true,
				feeActionId: 'claim-y',
				blockHeight: height,
				deadlineHeight: 104,
				confirmedOnly: true
			});
		// It makes a split of its own at the first try, and does not wait on
		// that split.
		const firstTry = await attempt(big(100));
		expect((firstTry as FixedOutputFeeError).code).equal(
			'FEE_PREPARATION_PENDING'
		);
		expect((firstTry as { transactionId?: string }).transactionId).not.equal(
			small
		);
		// A block later every split made so far has confirmed, and the claim
		// is served from its own.
		w.mine();
		expect(told(await attempt(big(101)))).equal('served');
	});

	it('a recorded split replacement that the previous release carried into a replacement of its own is dropped, and the budget is charged what the split that stands paid', async () => {
		const w = world({ walletCallTimeoutMs: 50 });
		w.fund(50_000);
		const p = w.provider();
		const send = w.wallet.electrum.broadcastTransaction;
		// The mempool refuses a replacement that pays no more than what it
		// throws out (BIP 125 rule 3).
		const strict: typeof send = async (args) => {
			const tx = bitcoin.Transaction.fromHex(args.rawTx);
			const spends = new Set(tx.ins.map((i) => `${idOf(i)}:${i.index}`));
			const out = new Set<string>();
			const drop = (id: string): void => {
				if (out.has(id) || w.confirmed.has(id)) return;
				out.add(id);
				for (const [other, t] of w.known)
					if (t.ins.some((i) => idOf(i) === id)) drop(other);
			};
			for (const [id, t] of w.known)
				if (
					id !== tx.getId() &&
					t.ins.some((i) => spends.has(`${idOf(i)}:${i.index}`))
				)
					drop(id);
			const thrown = [...out].reduce(
				(sum, id) => sum + feeOf(w, w.known.get(id)!),
				0n
			);
			if (out.size && feeOf(w, tx) <= thrown)
				return err('insufficient fee') as never;
			return send(args);
		};
		w.wallet.electrum.broadcastTransaction = strict;
		await attempt(
			p.selectFeeBumpInputs(500n, 250, {
				fixedOutputs: true,
				feeActionId: 'claim-x',
				blockHeight: 100,
				confirmedOnly: true
			})
		);
		const split = bitcoin.Transaction.fromHex(w.broadcasts[0]);
		// The replacement of the split goes to a server that never answers and
		// never takes it: the selection ends at its bound with the replacement
		// recorded and charged.
		w.wallet.electrum.broadcastTransaction = () => new Promise(() => undefined);
		const timedOut = await attempt(
			p.selectFeeBumpInputs(500n, 750, {
				fixedOutputs: true,
				feeActionId: 'claim-a',
				blockHeight: 101,
				deadlineHeight: 104
			})
		);
		expect((timedOut as FixedOutputFeeError).code).equal('FEE_WALLET_TIMEOUT');
		w.wallet.electrum.broadcastTransaction = strict;
		// The node goes back to the previous release, which replaces the
		// split, at the highest rate the cap of a split pays.
		usePool(p, w, 'previous');
		await p.selectFeeBumpInputs(500n, 1250, {
			fixedOutputs: true,
			feeActionId: 'claim-a',
			blockHeight: 102,
			deadlineHeight: 104
		});
		const stands = bitcoin.Transaction.fromHex(
			w.broadcasts[w.broadcasts.length - 1]
		);
		expect(w.known.has(split.getId())).equal(false);
		// The node is upgraded again, and asks for a fee coin once more.
		usePool(p, w, 'current');
		await attempt(
			p.selectFeeBumpInputs(500n, 1250, {
				fixedOutputs: true,
				feeActionId: 'claim-a',
				blockHeight: 103,
				deadlineHeight: 104
			})
		);
		// No action has burned a coin: what was spent is the fee of the split
		// that stands.
		expect(w.known.has(stands.getId())).equal(true);
		expect(p.getFixedOutputFeeBudget()!.spentSatoshis).equal(feeOf(w, stands));
	});

	it('a recorded split replacement that the previous release carried into a replacement of its own is not sent again, though it pays more than the split that stands', async () => {
		const w = world({ walletCallTimeoutMs: 50 });
		w.fund(50_000);
		const p = w.provider();
		await attempt(
			p.selectFeeBumpInputs(500n, 250, {
				fixedOutputs: true,
				feeActionId: 'claim-x',
				blockHeight: 100,
				confirmedOnly: true
			})
		);
		// The replacement of the split, at 4 sat/vB, goes to a server that
		// never answers and never takes it: it is recorded and charged.
		const send = w.wallet.electrum.broadcastTransaction;
		w.wallet.electrum.broadcastTransaction = () => new Promise(() => undefined);
		const timedOut = await attempt(
			p.selectFeeBumpInputs(500n, 1000, {
				fixedOutputs: true,
				feeActionId: 'claim-a',
				blockHeight: 101,
				deadlineHeight: 104
			})
		);
		expect((timedOut as FixedOutputFeeError).code).equal('FEE_WALLET_TIMEOUT');
		w.wallet.electrum.broadcastTransaction = send;
		const recorded = (
			w.journal().unconfirmed as Array<{ replacement?: { txid: string } }>
		)[0].replacement!.txid;
		// The node goes back to the previous release, which replaces the
		// split by one at 2 sat/vB: less than the replacement recorded pays.
		usePool(p, w, 'previous');
		await p.selectFeeBumpInputs(500n, 500, {
			fixedOutputs: true,
			feeActionId: 'claim-a',
			blockHeight: 102,
			deadlineHeight: 104
		});
		const stands = bitcoin.Transaction.fromHex(
			w.broadcasts[w.broadcasts.length - 1]
		);
		// The node is upgraded again, and asks for a fee coin once more.
		usePool(p, w, 'current');
		await attempt(
			p.selectFeeBumpInputs(500n, 500, {
				fixedOutputs: true,
				feeActionId: 'claim-a',
				blockHeight: 103,
				deadlineHeight: 104
			})
		);
		// The replacement recorded for the first split is not sent in place
		// of the split that stands, and the budget is charged what that one
		// paid.
		expect(w.known.has(recorded)).equal(false);
		expect(w.known.has(stands.getId())).equal(true);
		expect(p.getFixedOutputFeeBudget()!.spentSatoshis).equal(feeOf(w, stands));
	});

	it('a raise that keeps a coin of a split it can still replace has that split replaced when it pays less than the rate asked', async () => {
		const w = world({
			maxFeeSatoshis: 20_000n,
			maxTotalFeeSatoshis: 200_000n,
			maxPreparationFeeSatoshis: 5_000n
		});
		w.fund(100_000);
		const p = w.provider();
		// A claim with no deadline near has a split of 2,068-sat coins made at
		// 1 sat/vB, and waits for it.
		await attempt(
			p.selectFeeBumpInputs(2000n, 250, {
				fixedOutputs: true,
				feeActionId: 'claim-l',
				blockHeight: 100,
				confirmedOnly: true
			})
		);
		// A claim by preimage four blocks from its deadline takes a coin of it.
		const a = await p.selectFeeBumpInputs(500n, 250, {
			fixedOutputs: true,
			feeActionId: 'claim-a',
			blockHeight: 100,
			deadlineHeight: 104
		});
		const split = txidOf(a.inputs[0]);
		expect(w.confirmed.has(split)).equal(false);
		// Its spend never reached the network (it was held for its monitor
		// write, or refused). A block later the node raises it, at 3 sat/vB.
		const held = spendWith(w, a.inputs);
		const raised = await p.selectFeeBumpInputs(1500n, 750, {
			fixedOutputs: true,
			feeActionId: 'claim-a',
			blockHeight: 101,
			deadlineHeight: 104,
			replacementInputs: a.inputs.map(asReplacement),
			replacedTxid: held.getId()
		});
		// Every coin of the raise is confirmed, or of a split that pays the rate
		// asked. The split it keeps a coin of could be replaced, and was due.
		expect(
			[...new Set(raised.inputs.map(txidOf))]
				.filter((id) => !w.confirmed.has(id) && rateOf(w, id) < 3)
				.map(
					(id) =>
						`${id === split ? 'the split' : id} at ${rateOf(w, id).toFixed(
							2
						)} sat/vB, unconfirmed`
				)
		).deep.equal([]);
	});

	it('a selection does not wait on a split the cap of a split holds below the rate asked when a split of fewer coins pays that rate within the same cap', async () => {
		const w = world({
			maxFeeSatoshis: 20_000n,
			maxTotalFeeSatoshis: 200_000n
		});
		expect(w.policy.maxPreparationFeeSatoshis).equal(1000n);
		w.fund(50_000);
		w.fund(50_000);
		const p = w.provider();
		// A claim with no deadline near has a split of four 1,568-sat coins
		// made at 1 sat/vB.
		await attempt(
			p.selectFeeBumpInputs(1500n, 250, {
				fixedOutputs: true,
				feeActionId: 'claim-x',
				blockHeight: 100,
				confirmedOnly: true
			})
		);
		// The rate of the day is 7 sat/vB. A claim that wants confirmed coins,
		// with its deadline five blocks away, block after block; no block takes
		// a transaction that pays less than 7 sat/vB.
		const y = (height: number): Promise<unknown> =>
			p.selectFeeBumpInputs(1000n, 1750, {
				fixedOutputs: true,
				feeActionId: 'claim-y',
				blockHeight: height,
				deadlineHeight: 106,
				confirmedOnly: true
			});
		const below = (): string[] =>
			[...w.known.keys()].filter(
				(id) => !w.confirmed.has(id) && rateOf(w, id) < 7
			);
		let last: unknown;
		for (let height = 101; height <= 104; height++) {
			last = await attempt(y(height));
			if (last === undefined) break;
			w.mine(below());
		}
		// By the block before its deadline it has a split that pays the rate,
		// or is served.
		const splits = [...w.known.keys()].filter(
			(id) => !w.confirmed.has(id) || w.confirmed.get(id)! > 100
		);
		expect(
			told(last) === 'served'
				? 'served'
				: `${told(last)}; splits at ${splits
						.map((id) => rateOf(w, id).toFixed(2))
						.join(', ')} sat/vB`
		).equal('served');
	});
	it('a new action is measured against the budget once a recorded split replacement that was refused is settled', async () => {
		const w = world({ walletCallTimeoutMs: 50, maxTotalFeeSatoshis: 6_500n });
		w.fund(50_000);
		const p = w.provider();
		await attempt(
			p.selectFeeBumpInputs(500n, 250, {
				fixedOutputs: true,
				feeActionId: 'claim-x',
				blockHeight: 100,
				confirmedOnly: true
			})
		);
		// A claim near its deadline at 3 sat/vB takes a coin of that split:
		// its replacement is recorded and charged, and the server never
		// answers.
		const send = w.wallet.electrum.broadcastTransaction;
		w.wallet.electrum.broadcastTransaction = () => new Promise(() => undefined);
		const timedOut = await attempt(
			p.selectFeeBumpInputs(500n, 750, {
				fixedOutputs: true,
				feeActionId: 'claim-a',
				blockHeight: 101,
				deadlineHeight: 104
			})
		);
		expect((timedOut as FixedOutputFeeError).code).equal('FEE_WALLET_TIMEOUT');
		const recorded = (
			w.journal().unconfirmed as Array<{ replacement?: { txid: string } }>
		)[0].replacement!.txid;
		// The server refuses that replacement when it is sent again.
		w.wallet.electrum.broadcastTransaction = async (args) =>
			bitcoin.Transaction.fromHex(args.rawTx).getId() === recorded
				? (err('insufficient fee') as never)
				: send(args);
		// A new claim, whose cap fits the budget once that charge is refunded.
		const n = await attempt(
			p.selectFeeBumpInputs(500n, 750, {
				fixedOutputs: true,
				feeActionId: 'claim-n',
				blockHeight: 102,
				deadlineHeight: 104
			})
		);
		expect(told(n)).not.match(/FEE_BUDGET_EXHAUSTED/);
		expect(w.known.has(recorded)).equal(false);
	});

	it('a raise pays what the spend it replaces paid, with 1 sat/vB of its own size over that', async () => {
		const w = world({
			maxFeeSatoshis: 20_000n,
			maxTotalFeeSatoshis: 200_000n,
			maxPreparationFeeSatoshis: 5_000n
		});
		w.fund(100_000);
		const p = w.provider();
		// Free confirmed coins of 1,068 and of 568 sats: the second claim has a
		// cap of its own below 1,068 sats, so it has a split of its own made.
		for (const [id, target, cap] of [
			['claim-large', 1000n, 20_000n],
			['claim-small', 500n, 600n]
		] as const) {
			await attempt(
				p.selectFeeBumpInputs(target, 250, {
					fixedOutputs: true,
					feeActionId: id,
					blockHeight: 100,
					confirmedOnly: true,
					maxFeeSatoshis: cap
				})
			);
			w.mine();
			await p.selectFeeBumpInputs(target, 250, {
				fixedOutputs: true,
				feeActionId: id,
				blockHeight: 101,
				confirmedOnly: true,
				maxFeeSatoshis: cap
			});
		}
		expect(
			(w.journal().coins ?? []).map((c) => c.utxo.value).sort((x, y) => x - y)
		).deep.equal([568, 568, 568, 1068, 1068, 1068]);
		// A claim takes a coin of 1,068 sats, and its spend goes out.
		const a = await p.selectFeeBumpInputs(932n, 250, {
			fixedOutputs: true,
			feeActionId: 'claim-a',
			blockHeight: 101,
			confirmedOnly: true
		});
		expect(a.inputs.map((i) => i.value)).deep.equal([1068n]);
		const spend = spendWith(w, a.inputs);
		expect(w.accept(spend)).equal(undefined);
		// The node raises it to 2 sat/vB, for a spend of 500 vB of its own.
		const raised = await p.selectFeeBumpInputs(1000n, 500, {
			fixedOutputs: true,
			feeActionId: 'claim-a',
			blockHeight: 102,
			replacementInputs: a.inputs.map(asReplacement),
			replacedTxid: spend.getId()
		});
		// A replacement pays more than what it replaces by at least the relay
		// rate of 1 sat/vB on its own size (BIP 125): 500 vB and 68 vB for
		// each fee input.
		const paid = raised.inputs.reduce((sum, i) => sum + i.value, 0n);
		expect(Number(paid - 1068n)).at.least(500 + 68 * raised.inputs.length);
	});

	it('a raise whose lookup of the spend it replaces gets no answer keeps the fee coins that spend names', async () => {
		const w = world();
		w.fund(50_000);
		const p = w.provider();
		await attempt(
			p.selectFeeBumpInputs(500n, 250, {
				fixedOutputs: true,
				feeActionId: 'claim-a',
				blockHeight: 100,
				confirmedOnly: true
			})
		);
		w.mine();
		const a = await p.selectFeeBumpInputs(500n, 250, {
			fixedOutputs: true,
			feeActionId: 'claim-a',
			blockHeight: 101,
			confirmedOnly: true
		});
		const spend = spendWith(w, a.inputs);
		expect(w.accept(spend)).equal(undefined);
		// The answer for the spend is lost: the wallet drops a batch that
		// failed and answers with no data for it.
		const lookup = w.wallet.electrum.getTransactions!;
		w.wallet.electrum.getTransactions = async (args) =>
			args.txHashes.some(({ tx_hash }) => tx_hash === spend.getId())
				? (ok({ data: [] }) as never)
				: lookup(args);
		const raised = await p.selectFeeBumpInputs(600n, 500, {
			fixedOutputs: true,
			feeActionId: 'claim-a',
			blockHeight: 102,
			replacementInputs: a.inputs.map(asReplacement),
			replacedTxid: spend.getId()
		});
		// That spend may still be the one in the mempool: the coin it names is
		// kept, not let go of.
		expect(raised.inputs.map(outpointOf)).to.include(outpointOf(a.inputs[0]));
	});

	it('the coins of a split a replacement replaced stay frozen, so a block that takes that split leaves no coin of the pool unfrozen', async () => {
		const w = world();
		w.fund(50_000);
		const p = w.provider();
		await p.selectFeeBumpInputs(500n, 250, {
			fixedOutputs: true,
			feeActionId: 'claim-a',
			blockHeight: 100,
			deadlineHeight: 104
		});
		const first = bitcoin.Transaction.fromHex(w.broadcasts[0]);
		await p.selectFeeBumpInputs(500n, 750, {
			fixedOutputs: true,
			feeActionId: 'claim-b',
			blockHeight: 101,
			deadlineHeight: 104
		});
		expect(w.known.has(first.getId())).equal(false);
		// Another selection runs while the replacement stands.
		await p.selectFeeBumpInputs(500n, 750, {
			fixedOutputs: true,
			feeActionId: 'claim-b',
			blockHeight: 101,
			deadlineHeight: 104
		});
		// A miner that never saw the replacement takes the first split. Before
		// any selection, every fee coin of it is frozen.
		w.mineInstead(first);
		expect(
			w
				.coins()
				.filter(
					(c) =>
						c.tx_hash === first.getId() &&
						c.tx_pos < 4 &&
						!w.wallet.isUtxoFrozen!(c.tx_hash, c.tx_pos)
				)
				.map((c) => `${c.tx_hash}:${c.tx_pos}`)
		).deep.equal([]);
	});

	it('a split replacement sent again and taken has its coins frozen in that selection, with a wallet whose listing changes only when it is refreshed', async () => {
		const w = world({ walletCallTimeoutMs: 50 });
		w.fund(50_000);
		// The wallet lists what it saw at its last refresh.
		let seen = w.coins();
		w.wallet.listUtxos = (): ISpliceUtxo[] => seen;
		w.wallet.refreshWallet = async () => {
			seen = w.coins();
			return ok('') as never;
		};
		const p = w.provider();
		await attempt(
			p.selectFeeBumpInputs(500n, 250, {
				fixedOutputs: true,
				feeActionId: 'claim-x',
				blockHeight: 100,
				confirmedOnly: true
			})
		);
		// The replacement of the split goes to a server that never answers.
		const send = w.wallet.electrum.broadcastTransaction;
		w.wallet.electrum.broadcastTransaction = () => new Promise(() => undefined);
		await attempt(
			p.selectFeeBumpInputs(500n, 750, {
				fixedOutputs: true,
				feeActionId: 'claim-a',
				blockHeight: 101,
				deadlineHeight: 104
			})
		);
		const recorded = (
			w.journal().unconfirmed as Array<{ replacement?: { txid: string } }>
		)[0].replacement!.txid;
		// The next selection sends it again, and the server takes it.
		w.wallet.electrum.broadcastTransaction = send;
		await attempt(
			p.selectFeeBumpInputs(500n, 750, {
				fixedOutputs: true,
				feeActionId: 'claim-a',
				blockHeight: 102,
				deadlineHeight: 104
			})
		);
		expect(w.known.has(recorded)).equal(true);
		// The wallet refreshes on its own: every fee coin of the replacement
		// it lists is frozen.
		await w.wallet.refreshWallet!({});
		expect(
			w
				.coins()
				.filter(
					(c) =>
						c.tx_hash === recorded &&
						c.tx_pos < 4 &&
						!w.wallet.isUtxoFrozen!(c.tx_hash, c.tx_pos)
				)
				.map((c) => `${c.tx_hash}:${c.tx_pos}`)
		).deep.equal([]);
	});
});
/** The fee coins the pool holds that no action holds. */
const freeCoinsOf = (w: ReturnType<typeof world>): string[] =>
	(w.journal().coins ?? []).map((c) => `${c.utxo.tx_hash}:${c.utxo.tx_pos}`);
/** Every outpoint frozen under the pool's tag for its free fee coins. */
const coinFreezes = (w: ReturnType<typeof world>): string[] =>
	[...w.frozen]
		.filter(([, hold]) =>
			/^fixed-output-fees:[0-9a-f]{64}:coin$/.test(hold.freezeTag ?? '')
		)
		.map(([outpoint]) => outpoint)
		.sort();
/** What the wallet lists of `outpoints`. */
const listedOf = (
	w: ReturnType<typeof world>,
	outpoints: string[]
): ISpliceUtxo[] =>
	w.coins().filter((c) => outpoints.includes(`${c.tx_hash}:${c.tx_pos}`));
/**
 * A pool whose coins are all free: a claim near its deadline took a coin of
 * the pool's split, the output it was for can never be spent, and a block
 * took the split.
 */
const onlyFreeCoins = async (
	w: ReturnType<typeof world>
): Promise<{ p: WalletFundingProvider; split: string }> => {
	const p = w.provider();
	const a = await p.selectFeeBumpInputs(500n, 250, {
		fixedOutputs: true,
		feeActionId: 'claim-a',
		blockHeight: 100,
		deadlineHeight: 104
	});
	await p.retireFixedOutputFeeAction('claim-a', { impossible: true });
	w.mine();
	return { p, split: txidOf(a.inputs[0]) };
};

describe('fee coin pool: the free coins handed back once no action can need them', function () {
	this.timeout(20000);

	it('hands the free coins back once no action is open: their freezes are released, the wallet can spend them, and what the split paid stays charged', async () => {
		const w = world();
		w.fund(50_000);
		const { p } = await onlyFreeCoins(w);
		const free = freeCoinsOf(w);
		expect(free).length(4);
		expect(coinFreezes(w)).deep.equal([...free].sort());
		const spendable = p.quoteSpliceIn(253).spendableSats;
		const spent = p.getFixedOutputFeeBudget()!.spentSatoshis;

		expect(await p.releaseFixedOutputFeeCoins()).equal(true);
		expect(coinFreezes(w)).deep.equal([]);
		expect(w.journal().coins ?? []).deep.equal([]);
		expect(w.journal().unconfirmed ?? []).deep.equal([]);
		// The wallet lists them, and its own sends may take them.
		const listed = listedOf(w, free);
		expect(listed).length(4);
		expect(p.quoteSpliceIn(253).spendableSats).equal(
			spendable + listed.reduce((sum, c) => sum + BigInt(c.value), 0n)
		);
		expect(p.getFixedOutputFeeBudget()!.spentSatoshis).equal(spent);
		// Nothing is left to hand back.
		expect(await p.releaseFixedOutputFeeCoins()).equal(false);
	});

	it('keeps the free coins while an action is open, and leaves the coin the action holds frozen under its own tag', async () => {
		const w = world();
		w.fund(50_000);
		const p = w.provider();
		const a = await p.selectFeeBumpInputs(500n, 250, {
			fixedOutputs: true,
			feeActionId: 'claim-a',
			blockHeight: 100,
			deadlineHeight: 104
		});
		const own = outpointOf(a.inputs[0]);
		const free = freeCoinsOf(w);
		expect(free).length(3);

		expect(await p.releaseFixedOutputFeeCoins()).equal(false);
		expect(freeCoinsOf(w)).deep.equal(free);
		expect(coinFreezes(w)).deep.equal([...free].sort());
		expect(w.frozen.get(own)!.freezeTag).match(/:action:[0-9a-f]{64}$/);

		// Once the action is retired, the coin it held is handed back with the
		// others.
		await p.retireFixedOutputFeeAction('claim-a', { impossible: true });
		expect(await p.releaseFixedOutputFeeCoins()).equal(true);
		expect([...free, own].filter((k) => w.frozen.has(k))).deep.equal([]);
	});

	it('keeps the free coins while a split is unsigned, and while a signed split has not gone out', async () => {
		const w = world();
		w.fund(50_000);
		w.fund(50_000);
		const { p, split } = await onlyFreeCoins(w);
		const free = freeCoinsOf(w);
		// A claim that may not take those coins has a split of its own
		// recorded, and the signer refuses it.
		const ask = (id: string, exclude: string[]): Promise<unknown> =>
			attempt(
				p.selectFeeBumpInputs(500n, 250, {
					fixedOutputs: true,
					feeActionId: id,
					blockHeight: 101,
					excludeTxids: exclude
				})
			);
		const sign = w.wallet.signPsbtWithOurKey!;
		w.wallet.signPsbtWithOurKey = (): never =>
			err('the signer is away') as never;
		expect(told(await ask('claim-b', [split]))).match(
			/^FEE_PREPARATION_SIGNING_FAILED/
		);
		await p.retireFixedOutputFeeAction('claim-b', { impossible: true });
		expect(await p.releaseFixedOutputFeeCoins()).equal(false);
		expect(freeCoinsOf(w)).deep.equal(free);
		expect(coinFreezes(w)).deep.equal([...free].sort());

		// It is signed, and no server takes it yet: it may still go out.
		w.wallet.signPsbtWithOurKey = sign;
		const send = w.wallet.electrum.broadcastTransaction;
		w.wallet.electrum.broadcastTransaction = async (): Promise<never> =>
			err('no peer took it') as never;
		expect(told(await ask('claim-c', [split]))).match(
			/^FEE_PREPARATION_NOT_PUBLISHED/
		);
		await p.retireFixedOutputFeeAction('claim-c', { impossible: true });
		expect(await p.releaseFixedOutputFeeCoins()).equal(false);
		expect(freeCoinsOf(w)).deep.equal(free);
		expect(coinFreezes(w)).deep.equal([...free].sort());

		// It goes out with the next selection, whose action is retired: every
		// free coin of both splits is handed back.
		w.wallet.electrum.broadcastTransaction = send;
		await p.selectFeeBumpInputs(500n, 250, {
			fixedOutputs: true,
			feeActionId: 'claim-d',
			blockHeight: 101
		});
		await p.retireFixedOutputFeeAction('claim-d', { impossible: true });
		expect(freeCoinsOf(w)).length(8);
		expect(await p.releaseFixedOutputFeeCoins()).equal(true);
		expect(coinFreezes(w)).deep.equal([]);
		expect(w.journal().coins ?? []).deep.equal([]);
	});

	it('settles a recorded split replacement when it hands the free coins back, and releases every freeze of them, where the replacement moved them from too', async () => {
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
		const first = bitcoin.Transaction.fromHex(w.broadcasts[0]).getId();
		// The split is replaced, and the server answers after the bound.
		w.slow(150);
		expect(
			told(
				await attempt(
					p.selectFeeBumpInputs(500n, 750, {
						fixedOutputs: true,
						feeActionId: 'claim-a',
						blockHeight: 101,
						deadlineHeight: 104
					})
				)
			)
		).match(/^FEE_WALLET_TIMEOUT/);
		await wait(300);
		w.slow(0);
		for (const id of ['claim-x', 'claim-a'])
			await p.retireFixedOutputFeeAction(id, { impossible: true });
		const rows = (): Array<{ replacement?: { txid: string } }> =>
			(w.journal().unconfirmed ?? []) as Array<{
				replacement?: { txid: string };
			}>;
		const recorded = rows()[0].replacement!.txid;
		expect(w.known.has(recorded)).equal(true);
		const free = freeCoinsOf(w);
		expect(free.every((k) => k.startsWith(first))).equal(true);
		expect(coinFreezes(w)).deep.equal([...free].sort());

		// The hand back settles the replacement: the wallet lists its coins,
		// so it went out, and the coins it moved are handed back with every
		// freeze of them, where it moved them from too.
		const spent = p.getFixedOutputFeeBudget()!.spentSatoshis;
		expect(await p.releaseFixedOutputFeeCoins()).equal(true);
		expect(freeCoinsOf(w)).deep.equal([]);
		expect(coinFreezes(w)).deep.equal([]);
		expect(w.journal().unconfirmed ?? []).deep.equal([]);
		expect(listedOf(w, free)).length(0);
		expect(w.coins().filter((c) => c.tx_hash === recorded)).length(5);
		// It stays charged what it paid over the split it replaced.
		expect(p.getFixedOutputFeeBudget()!.spentSatoshis).equal(spent);
	});

	it('neither loses nor freezes again the coins of a hand back that stopped between its journal write and the release of their freezes, after a start', async () => {
		const w = world();
		w.fund(50_000);
		const { p } = await onlyFreeCoins(w);
		const free = freeCoinsOf(w);
		const spent = p.getFixedOutputFeeBudget()!.spentSatoshis;
		const spendable = p.quoteSpliceIn(253).spendableSats;
		// The wallet refuses to release a freeze: the journal has let go of the
		// coins, and the hand back stops there.
		const unfreeze = w.wallet.unfreezeUtxoIfTagged!;
		w.wallet.unfreezeUtxoIfTagged = async (): Promise<never> =>
			err('the wallet is busy') as never;
		expect(told(await attempt(p.releaseFixedOutputFeeCoins()))).match(
			/^FEE_WALLET_UNAVAILABLE/
		);
		expect(w.journal().coins ?? []).deep.equal([]);
		expect(coinFreezes(w)).deep.equal([...free].sort());
		w.wallet.unfreezeUtxoIfTagged = unfreeze;

		// The node starts again, and reads the journal from its store.
		const again = w.provider();
		await again.releaseInputPledges([{ txid: 'ee'.repeat(32), vout: 0 }]);
		expect(coinFreezes(w)).deep.equal([]);
		expect(listedOf(w, free)).length(4);
		expect(again.quoteSpliceIn(253).spendableSats).equal(
			spendable +
				listedOf(w, free).reduce((sum, c) => sum + BigInt(c.value), 0n)
		);
		// A retirement freezes every coin the pool holds: none of these.
		await again.retireFixedOutputFeeAction('claim-gone', { impossible: true });
		expect(free.filter((k) => w.frozen.has(k))).deep.equal([]);
		expect(await again.releaseFixedOutputFeeCoins()).equal(false);
		expect(again.getFixedOutputFeeBudget()!.spentSatoshis).equal(spent);
	});

	it('makes a split of its own for a selection after the coins were handed back', async () => {
		const w = world();
		w.fund(50_000);
		const { p } = await onlyFreeCoins(w);
		const free = freeCoinsOf(w);
		expect(await p.releaseFixedOutputFeeCoins()).equal(true);
		const sent = w.broadcasts.length;
		const pending = await attempt(
			p.selectFeeBumpInputs(500n, 250, {
				fixedOutputs: true,
				feeActionId: 'claim-n',
				blockHeight: 102
			})
		);
		expect(told(pending)).match(/^FEE_PREPARATION_PENDING/);
		expect(w.broadcasts.length).equal(sent + 1);
		const split = bitcoin.Transaction.fromHex(w.broadcasts[sent]);
		expect(
			split.ins
				.map((i) => `${idOf(i)}:${i.index}`)
				.filter((outpoint) => free.includes(outpoint))
		).deep.equal([]);
		w.mine();
		const served = await p.selectFeeBumpInputs(500n, 250, {
			fixedOutputs: true,
			feeActionId: 'claim-n',
			blockHeight: 103
		});
		expect(served.inputs.map(txidOf)).deep.equal([split.getId()]);
		expect(free.filter((k) => w.frozen.has(k))).deep.equal([]);
	});
});

/** How many inputs of a selection are of transaction `id`. */
function inputsOf(
	selection: { inputs: Array<{ prevTx: Buffer }> },
	id: string
): number {
	return selection.inputs.filter((i) => txidOf(i) === id).length;
}
