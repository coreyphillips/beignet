/**
 * A wallet on a test chain (issue #2093): one P2WPKH key whose coins are read
 * from the chain and whose transactions go to it, behind the interface the
 * real `WalletFundingProvider` wraps. The fee pool of an asset channel is
 * tested through that provider with this wallet under it, so every split
 * and every fee input is a transaction the chain judges.
 */

import * as bitcoin from 'bitcoinjs-lib';
import type { ILedgerKeyValueStorage } from '../../../src/lightning/storage/durable-ledger';
import type { IFixedOutputFeePolicy } from '../../../src/lightning/wallet/fixed-output-fees';
import {
	WalletFundingProvider,
	type ISpliceUtxo,
	type IWalletLike
} from '../../../src/lightning/wallet/wallet-funding-provider';
import { getECPair } from '../../../src/utils/ecc-apis';
import {
	electrumScriptHash,
	type TestChain,
	type TestChainBackend
} from './auxiliary-chain';
import { hash } from './auxiliary-pair';

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
} => ({
	isErr: () => true,
	isOk: () => false,
	error: { message }
});

/** The journal of the fee pool, kept across a restart of its node. */
export class FeeJournal implements ILedgerKeyValueStorage {
	rows = new Map<string, string>();
	loadMetadata(key: string): string | null {
		return this.rows.get(key) ?? null;
	}
	saveMetadata(key: string, value: string): void {
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

export interface IChainWallet {
	wallet: IWalletLike;
	journal: FeeJournal;
	policy: IFixedOutputFeePolicy;
	/** The script every coin of the wallet pays. */
	script: Buffer;
	/** Every transaction the wallet handed to the chain, and whether it was taken. */
	sent: Array<{ txid: string; raw: string; refused?: string }>;
	/** Put a coin of the wallet on the chain; it is in a block at once. */
	fund(value: number): bitcoin.Transaction;
	/** The wallet's unspent coins as the chain has them. */
	coins(): ISpliceUtxo[];
	/** Use another connection to the chain, as after a restart. */
	attach(backend: TestChainBackend): void;
	/** The provider a node is given: the real one, over this wallet and policy. */
	provider(): WalletFundingProvider;
}

export function chainWallet(
	chain: TestChain,
	tag: string,
	policy: Partial<IFixedOutputFeePolicy> = {}
): IChainWallet {
	const network = bitcoin.networks.regtest;
	const path = "m/84'/1'/0'/1/0";
	const owner = getECPair().fromPrivateKey(hash(`fee wallet ${tag}`), {
		network
	});
	const publicKey = Buffer.from(owner.publicKey);
	const payment = bitcoin.payments.p2wpkh({ pubkey: publicKey, network });
	const script = payment.output!;
	const scriptHash = electrumScriptHash(script);
	const frozen = new Map<string, { freezeTag?: string; frozenAt: number }>();
	const sent: IChainWallet['sent'] = [];
	const journal = new FeeJournal();
	let backend: TestChainBackend | undefined;
	let locked = false;
	let funded = 0;

	const coins = (): ISpliceUtxo[] => {
		const found: ISpliceUtxo[] = [];
		for (const entry of chain.history(scriptHash)) {
			const tx = chain.transaction(entry.txid);
			if (!tx) continue;
			tx.outs.forEach((out, index) => {
				if (!out.script.equals(script)) return;
				if (chain.spender(entry.txid, index)) return;
				found.push({
					address: payment.address!,
					path,
					publicKey: publicKey.toString('hex'),
					tx_hash: entry.txid,
					tx_pos: index,
					value: out.value,
					height: entry.height > 0 ? entry.height : 0
				});
			});
		}
		return found;
	};

	const wallet: IWalletLike = {
		id: `fee-wallet-${tag}`,
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
			[...frozen].map(([key, value]) => ({
				tx_hash: key.split(':')[0],
				tx_pos: Number(key.split(':')[1]),
				...value
			})),
		freezeUtxoIfUnfrozen: async ({ txid, index, tag: freezeTag }) => {
			const key = `${txid}:${index}`;
			const created = !frozen.has(key);
			if (created) frozen.set(key, { freezeTag, frozenAt: Date.now() });
			return ok({ created });
		},
		unfreezeUtxoIfTagged: async ({ txid, index, tag: freezeTag }) => {
			const key = `${txid}:${index}`;
			const unfrozen = frozen.get(key)?.freezeTag === freezeTag;
			if (unfrozen) frozen.delete(key);
			return ok({ unfrozen });
		},
		signPsbtWithOurKey: (raw) => {
			try {
				const psbt = bitcoin.Psbt.fromBase64(raw);
				psbt.signAllInputs(owner);
				return ok(psbt.toBase64());
			} catch (error) {
				return err((error as Error).message);
			}
		},
		importSignedPsbt: (signed) => {
			try {
				const psbt = bitcoin.Psbt.fromBase64(signed);
				psbt.finalizeAllInputs();
				const tx = psbt.extractTransaction();
				return ok({ txHex: tx.toHex(), txid: tx.getId() });
			} catch (error) {
				return err((error as Error).message);
			}
		},
		electrum: {
			getTransactions: async ({ txHashes }) =>
				ok({
					data: txHashes.map(({ tx_hash }) => ({
						data: { tx_hash },
						result: {
							txid: tx_hash,
							hex: chain.transaction(tx_hash)?.toHex()
						}
					}))
				}),
			broadcastTransaction: async ({ rawTx }) => {
				const txid = bitcoin.Transaction.fromHex(rawTx).getId();
				if (!backend) {
					sent.push({ txid, raw: rawTx, refused: 'no connection' });
					return err('the wallet has no connection to the chain');
				}
				try {
					await backend.broadcastTransaction(rawTx);
					sent.push({ txid, raw: rawTx });
					return ok(txid);
				} catch (error) {
					sent.push({ txid, raw: rawTx, refused: (error as Error).message });
					return err((error as Error).message);
				}
			}
		}
	};

	const whole: IFixedOutputFeePolicy = {
		storage: journal,
		maxFeeSatoshis: 20_000n,
		maxTotalFeeSatoshis: 200_000n,
		maxPreparationFeeSatoshis: 5_000n,
		...policy
	};

	return {
		wallet,
		journal,
		policy: whole,
		script,
		sent,
		coins,
		fund(value: number): bitcoin.Transaction {
			const tx = new bitcoin.Transaction();
			tx.version = 2;
			tx.addInput(hash(`fee wallet coin ${tag} ${funded++}`), 0);
			tx.addOutput(script, value);
			chain.seed(tx);
			return tx;
		},
		attach(next: TestChainBackend): void {
			backend = next;
		},
		provider: () =>
			new WalletFundingProvider(wallet, { fixedOutputFees: whole })
	};
}
