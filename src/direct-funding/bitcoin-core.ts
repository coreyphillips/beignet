import * as bitcoin from 'bitcoinjs-lib';
import type {
	IDfCoinSigner,
	IDfSenderCoin,
	IDfSenderWallet
} from '../lightning/direct-funding/sender/types';
import { Network } from '../lightning/invoice/types';
import { createPsbtCoinSigner } from './psbt';

/** A wallet-scoped Bitcoin Core JSON-RPC connection. Credentials stay with the host. */
export type BitcoinCoreRpc = (
	method: string,
	params?: unknown[]
) => Promise<unknown>;

export interface IBitcoinCoreWalletOptions {
	rpc: BitcoinCoreRpc;
	network?: Network;
	/** Durable, synchronous storage, scoped to this Core wallet and network. */
	storage: {
		loadWalletData(key: string): string | null;
		saveWalletData(key: string, value: string): void;
	};
	storageKey?: string;
}

interface IReservation {
	txid: string;
	vout: number;
	state: 'acquiring' | 'owned' | 'releasing';
}

type RpcObject = Record<string, unknown>;

const CHAINS: Record<Network, string> = {
	[Network.MAINNET]: 'main',
	[Network.TESTNET]: 'test',
	[Network.SIGNET]: 'signet',
	[Network.REGTEST]: 'regtest'
};

function object(value: unknown, name: string): RpcObject {
	if (!value || typeof value !== 'object' || Array.isArray(value)) {
		throw new Error(`Bitcoin Core returned an invalid ${name}`);
	}
	return value as RpcObject;
}

function array(value: unknown, name: string): unknown[] {
	if (!Array.isArray(value)) {
		throw new Error(`Bitcoin Core returned an invalid ${name}`);
	}
	return value;
}

function txid(value: unknown): string {
	if (typeof value !== 'string' || !/^[0-9a-f]{64}$/i.test(value)) {
		throw new Error('Invalid Bitcoin transaction id');
	}
	return value.toLowerCase();
}

function integer(value: unknown, name: string, minimum = 0): number {
	if (!Number.isSafeInteger(value) || (value as number) < minimum) {
		throw new Error(`Bitcoin Core returned an invalid ${name}`);
	}
	return value as number;
}

function hex(value: unknown, name: string): Buffer {
	if (typeof value !== 'string' || !/^(?:[0-9a-f]{2})+$/i.test(value)) {
		throw new Error(`Bitcoin Core returned invalid ${name} hex`);
	}
	return Buffer.from(value, 'hex');
}

/** Convert decimal BTC exactly without rounding a fractional satoshi. */
function satoshis(value: unknown): bigint {
	const text = typeof value === 'number' ? String(value) : value;
	if (typeof text !== 'string') throw new Error('Invalid Bitcoin Core amount');
	const match = /^(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$/.exec(text);
	if (!match) throw new Error('Invalid Bitcoin Core amount');
	const fraction = match[2] ?? '';
	const scale = 8 + Number(match[3] ?? 0) - fraction.length;
	if (!Number.isSafeInteger(scale) || Math.abs(scale) > 100) {
		throw new Error('Invalid Bitcoin Core amount precision');
	}
	let amount = BigInt(match[1] + fraction);
	if (scale < 0) {
		const divisor = 10n ** BigInt(-scale);
		if (amount % divisor !== 0n) throw new Error('Fractional satoshi amount');
		amount /= divisor;
	} else amount *= 10n ** BigInt(scale);
	if (amount > 2_100_000_000_000_000n) {
		throw new Error('Bitcoin Core amount exceeds the monetary supply');
	}
	return amount;
}

function key(id: string, vout: number): string {
	return `${txid(id)}:${integer(vout, 'output index')}`;
}

function supported(script: Buffer): boolean {
	return (
		(script.length === 22 && script[0] === 0 && script[1] === 20) ||
		(script.length === 34 && script[0] === 0x51 && script[1] === 32)
	);
}

function missingTransaction(error: unknown): boolean {
	return (
		!!error && typeof error === 'object' && (error as RpcObject).code === -5
	);
}

/**
 * Bitcoin Core 24+ wallet adapter. Core performs PSBT signing without exporting
 * keys. Use one adapter and one durable storage namespace per wallet. Refresh
 * before paying or reconciling, including restored funding transaction ids.
 *
 * Persistent Core locks stop automatic coin selection. Core intentionally allows
 * manual selection to bypass locks, so hosts must not manually spend, unlock, or
 * reassign these reservations while a payment is pending. Other lock managers
 * must not race this adapter. An ambiguous acquisition is quarantined, never
 * adopted or automatically unlocked. Inspect unresolvedReservations() to recover
 * that exceptional condition with the wallet operator.
 */
export class BitcoinCoreWalletAdapter implements IDfSenderWallet {
	readonly network: Network;
	private coins = new Map<string, IDfSenderCoin>();
	private spendable = new Set<string>();
	private owned = new Set<string>();
	private locks = new Set<string>();
	private reservations = new Map<string, IReservation>();
	private statuses = new Map<string, { known: boolean; confirmed: boolean }>();
	private spends = new Map<string, string>();
	private tracked = new Set<string>();
	private height = 0;
	private queue: Promise<unknown> = Promise.resolve();
	private readonly storageKey: string;
	private readonly bitcoinNetwork: bitcoin.Network;

	private constructor(private readonly options: IBitcoinCoreWalletOptions) {
		this.network = options.network ?? Network.MAINNET;
		this.bitcoinNetwork =
			this.network === Network.MAINNET
				? bitcoin.networks.bitcoin
				: this.network === Network.REGTEST
				? bitcoin.networks.regtest
				: bitcoin.networks.testnet;
		this.storageKey = options.storageKey ?? 'df:core-reservations';
		const raw: unknown = options.storage.loadWalletData(this.storageKey);
		if (raw !== null && typeof raw !== 'string') {
			if (raw && typeof (raw as Promise<unknown>).then === 'function') {
				void Promise.resolve(raw).catch(() => undefined);
			}
			throw new Error(
				'Bitcoin Core reservation storage must load synchronously'
			);
		}
		if (raw !== null) {
			for (const row of array(JSON.parse(raw), 'reservation journal')) {
				const entry = object(row, 'reservation');
				const id = txid(entry.txid);
				const vout = integer(entry.vout, 'output index');
				if (
					entry.state !== 'acquiring' &&
					entry.state !== 'owned' &&
					entry.state !== 'releasing'
				) {
					throw new Error('Invalid Bitcoin Core reservation state');
				}
				const outpoint = key(id, vout);
				if (this.reservations.has(outpoint)) {
					throw new Error('Duplicate Bitcoin Core reservation');
				}
				this.reservations.set(outpoint, {
					txid: id,
					vout,
					state: entry.state
				});
			}
		}
	}

	static async create(
		options: IBitcoinCoreWalletOptions
	): Promise<BitcoinCoreWalletAdapter> {
		const wallet = new BitcoinCoreWalletAdapter(options);
		await wallet.refresh();
		return wallet;
	}

	private exclusive<T>(operation: () => Promise<T>): Promise<T> {
		const result = this.queue.then(operation);
		this.queue = result.catch(() => undefined);
		return result;
	}

	/**
	 * Drain queued wallet refreshes and reservation changes before closing storage.
	 * The host must stop starting payments and refreshes before calling this.
	 */
	async waitForIdle(): Promise<void> {
		let pending: Promise<unknown>;
		do {
			pending = this.queue;
			await pending;
		} while (pending !== this.queue);
	}

	private persist(): void {
		const result: unknown = this.options.storage.saveWalletData(
			this.storageKey,
			JSON.stringify([...this.reservations.values()])
		);
		// A Promise-returning function is assignable to () => void in TypeScript.
		// Accepting one here would acknowledge a reservation before it was durable.
		if (
			result !== null &&
			(typeof result === 'object' || typeof result === 'function') &&
			typeof (result as { then?: unknown }).then === 'function'
		) {
			void Promise.resolve(result).catch(() => undefined);
			throw new Error(
				'Bitcoin Core reservation storage must save synchronously'
			);
		}
	}

	private async readLocks(): Promise<Set<string>> {
		const rows = array(
			await this.options.rpc('listlockunspent'),
			'locked coins'
		);
		return new Set(
			rows.map((row) => {
				const entry = object(row, 'locked coin');
				return key(txid(entry.txid), integer(entry.vout, 'output index'));
			})
		);
	}

	/** Failed or interrupted acquisition requires operator reconciliation. */
	unresolvedReservations(): ReadonlyArray<{ txid: string; vout: number }> {
		return [...this.reservations.values()]
			.filter((entry) => entry.state === 'acquiring')
			.map(({ txid: id, vout }) => ({ txid: id, vout }));
	}

	/** Atomically replace the cached wallet view only after all reads succeed. */
	refresh(fundingTxids: readonly string[] = []): Promise<void> {
		return this.exclusive(async () => {
			fundingTxids.forEach((id) => this.tracked.add(txid(id)));
			const chain = object(
				await this.options.rpc('getblockchaininfo'),
				'chain info'
			);
			if (chain.chain !== CHAINS[this.network]) {
				throw new Error(
					'Bitcoin Core network does not match the adapter network'
				);
			}
			const height = integer(chain.blocks, 'block height');
			const locks = await this.readLocks();
			const rows = array(
				await this.options.rpc('listunspent', [0, 9_999_999, [], true]),
				'unspent coins'
			);
			const coins = new Map<string, IDfSenderCoin>();
			const owned = new Set<string>();
			const spendable = new Set<string>();
			for (const row of rows) {
				const entry = object(row, 'unspent coin');
				const id = txid(entry.txid);
				const vout = integer(entry.vout, 'output index');
				const outpoint = key(id, vout);
				owned.add(outpoint);
				const script = hex(entry.scriptPubKey, 'script');
				if (
					!supported(script) ||
					entry.spendable === false ||
					!entry.solvable
				) {
					continue;
				}
				const confirmations = integer(entry.confirmations, 'confirmations');
				coins.set(outpoint, {
					txidHex: id,
					vout,
					valueSat: satoshis(entry.amount),
					script,
					height:
						confirmations > 0 ? Math.max(1, height - confirmations + 1) : 0
				});
				if (entry.safe === true && !locks.has(outpoint))
					spendable.add(outpoint);
			}
			for (const outpoint of locks) {
				owned.add(outpoint);
				if (coins.has(outpoint)) continue;
				const [id, output] = outpoint.split(':');
				const vout = Number(output);
				const value = await this.options.rpc('gettxout', [id, vout, true]);
				if (value === null) continue;
				const entry = object(value, 'locked previous output');
				const script = hex(object(entry.scriptPubKey, 'script').hex, 'script');
				if (!supported(script)) continue;
				const confirmations = integer(entry.confirmations, 'confirmations');
				coins.set(outpoint, {
					txidHex: id,
					vout,
					valueSat: satoshis(entry.value),
					script,
					height:
						confirmations > 0 ? Math.max(1, height - confirmations + 1) : 0
				});
			}
			const history = object(
				await this.options.rpc('listsinceblock'),
				'history'
			);
			const statuses = new Map<
				string,
				{ known: boolean; confirmed: boolean }
			>();
			const spends = new Map<string, string>();
			const inspect = new Set(this.tracked);
			for (const row of array(history.transactions, 'transaction history')) {
				const entry = object(row, 'transaction');
				const id = txid(entry.txid);
				const confirmations = integer(
					entry.confirmations,
					'confirmations',
					-1_000_000_000
				);
				if (confirmations > 0 && entry.category === 'send') inspect.add(id);
			}
			for (const id of inspect) {
				let entry: RpcObject;
				try {
					entry = object(
						await this.options.rpc('gettransaction', [id]),
						'transaction'
					);
				} catch (error) {
					if (!missingTransaction(error)) throw error;
					continue;
				}
				const confirmations = integer(
					entry.confirmations,
					'confirmations',
					-1_000_000_000
				);
				let known = confirmations > 0;
				if (confirmations === 0 && entry.abandoned !== true) {
					try {
						object(
							await this.options.rpc('getmempoolentry', [id]),
							'mempool entry'
						);
						known = true;
					} catch (error) {
						if (!missingTransaction(error)) throw error;
					}
				}
				statuses.set(id, { known, confirmed: confirmations > 0 });
				if (confirmations > 0) {
					const tx = this.parseTransaction(entry.hex, id);
					for (const input of tx.ins) {
						spends.set(
							key(
								Buffer.from(input.hash).reverse().toString('hex'),
								input.index
							),
							id
						);
					}
				}
			}
			this.height = height;
			this.locks = locks;
			this.coins = coins;
			this.owned = owned;
			this.spendable = spendable;
			this.statuses = statuses;
			this.spends = spends;
		});
	}

	listSpendable(): IDfSenderCoin[] {
		return [...this.spendable]
			.filter(
				(outpoint) =>
					!this.reservations.has(outpoint) && !this.locks.has(outpoint)
			)
			.map((outpoint) => this.copyCoin(this.coins.get(outpoint)!));
	}

	findCoin(id: string, vout: number): IDfSenderCoin | null {
		const coin = this.coins.get(key(id, vout));
		return coin ? this.copyCoin(coin) : null;
	}

	private copyCoin(coin: IDfSenderCoin): IDfSenderCoin {
		return { ...coin, script: Buffer.from(coin.script) };
	}

	private parseTransaction(value: unknown, id: string): bitcoin.Transaction {
		const tx = bitcoin.Transaction.fromBuffer(hex(value, 'transaction'));
		if (tx.getId() !== id)
			throw new Error('Bitcoin Core returned the wrong transaction');
		return tx;
	}

	async getTransaction(id: string): Promise<Buffer> {
		id = txid(id);
		let value: unknown;
		try {
			value = object(
				await this.options.rpc('gettransaction', [id]),
				'transaction'
			).hex;
		} catch (error) {
			if (!missingTransaction(error)) throw error;
			value = await this.options.rpc('getrawtransaction', [id, false]);
		}
		return this.parseTransaction(value, id).toBuffer();
	}

	async changeScript(): Promise<Buffer> {
		const address = await this.options.rpc('getrawchangeaddress', ['bech32']);
		if (typeof address !== 'string')
			throw new Error('Invalid Bitcoin Core change address');
		return bitcoin.address.toOutputScript(address, this.bitcoinNetwork);
	}

	signerFor(coin: IDfSenderCoin): IDfCoinSigner | null {
		const current = this.findCoin(coin.txidHex, coin.vout);
		if (
			!current ||
			current.valueSat !== coin.valueSat ||
			!current.script.equals(coin.script)
		)
			return null;
		return createPsbtCoinSigner(coin, {
			getTransaction: (id) => this.getTransaction(id),
			signPsbt: async (base64, context) => {
				const psbt = bitcoin.Psbt.fromBase64(base64);
				// walletprocesspsbt signs every input it controls. Check other input
				// scripts against Core again so a stale wallet view cannot authorize
				// an additional payer coin, including unsupported script types.
				for (let i = 0; i < psbt.inputCount; i++) {
					if (i === context.inputIndex) continue;
					const script = psbt.data.inputs[i].witnessUtxo?.script;
					if (!script) throw new Error('Missing PSBT previous output');
					let address: string;
					try {
						address = bitcoin.address.fromOutputScript(
							script,
							this.bitcoinNetwork
						);
					} catch {
						// The ownership probe's poison input is provably unspendable.
						if (
							context.purpose === 'ownership' &&
							script[0] === bitcoin.opcodes.OP_RETURN
						)
							continue;
						throw new Error(
							'Cannot check ownership of an additional input script'
						);
					}
					const info = object(
						await this.options.rpc('getaddressinfo', [address]),
						'address info'
					);
					if (info.ismine !== false)
						throw new Error('Additional input may belong to the payer wallet');
				}
				const signed = object(
					await this.options.rpc('walletprocesspsbt', [
						base64,
						true,
						coin.script[0] === 0x51 ? 'DEFAULT' : 'ALL',
						false,
						false
					]),
					'signed PSBT'
				);
				if (typeof signed.psbt !== 'string')
					throw new Error('Bitcoin Core did not return a signed PSBT');
				return signed.psbt;
			}
		});
	}

	ownsOutpoint(id: string, vout: number): boolean {
		return this.owned.has(key(id, vout));
	}

	async spentOnChain(coin: IDfSenderCoin): Promise<boolean> {
		try {
			if (
				(await this.options.rpc('gettxout', [
					coin.txidHex,
					coin.vout,
					true
				])) !== null
			)
				return false;
			// A wallet may retain an evicted or abandoned parent. Its bytes alone
			// do not prove the output ever existed on our current chain view.
			const entry = object(
				await this.options.rpc('gettransaction', [coin.txidHex]),
				'transaction'
			);
			const confirmations = integer(
				entry.confirmations,
				'confirmations',
				-1_000_000_000
			);
			if (confirmations < 0 || entry.abandoned === true) return false;
			if (confirmations === 0)
				object(
					await this.options.rpc('getmempoolentry', [coin.txidHex]),
					'mempool entry'
				);
			const parent = this.parseTransaction(entry.hex, coin.txidHex);
			const output = parent.outs[coin.vout];
			return (
				!!output &&
				output.script.equals(coin.script) &&
				BigInt(output.value) === coin.valueSat
			);
		} catch {
			return false;
		}
	}

	freezeUtxo(id: string, vout: number): Promise<boolean> {
		return this.exclusive(async () => {
			const outpoint = key(id, vout);
			const previous = this.reservations.get(outpoint);
			if (previous && previous.state !== 'owned') return false;
			this.locks = await this.readLocks();
			if (this.locks.has(outpoint)) return previous?.state === 'owned';
			if (!this.coins.has(outpoint)) return false;
			const entry: IReservation = { txid: txid(id), vout, state: 'acquiring' };
			this.reservations.set(outpoint, entry);
			try {
				this.persist();
			} catch {
				if (previous) this.reservations.set(outpoint, previous);
				else this.reservations.delete(outpoint);
				return false;
			}
			let acquired = false;
			try {
				acquired =
					(await this.options.rpc('lockunspent', [
						false,
						[{ txid: entry.txid, vout }],
						true
					])) === true;
			} catch {
				// A lost response cannot prove ownership. Keep the journal entry
				// quarantined if Core might have accepted the lock.
			}
			if (!acquired) {
				try {
					this.locks = await this.readLocks();
					if (!this.locks.has(outpoint)) {
						this.reservations.delete(outpoint);
						this.persist();
					}
				} catch {
					/* Keep the durable acquisition intent. */
				}
				return false;
			}
			this.locks.add(outpoint);
			entry.state = 'owned';
			try {
				this.persist();
				return true;
			} catch {
				entry.state = 'acquiring';
				return false;
			}
		});
	}

	unfreezeUtxo(id: string, vout: number): Promise<boolean> {
		return this.exclusive(async () => {
			const outpoint = key(id, vout);
			const entry = this.reservations.get(outpoint);
			if (!entry) return true;
			if (entry.state === 'acquiring') return false;
			entry.state = 'releasing';
			try {
				this.persist();
				this.locks = await this.readLocks();
				if (this.locks.has(outpoint)) {
					try {
						await this.options.rpc('lockunspent', [
							true,
							[{ txid: entry.txid, vout }]
						]);
					} catch {
						/* Reconcile a lost unlock response below. */
					}
					this.locks = await this.readLocks();
					if (this.locks.has(outpoint)) return false;
				}
				this.reservations.delete(outpoint);
				try {
					this.persist();
				} catch (error) {
					this.reservations.set(outpoint, entry);
					throw error;
				}
				return true;
			} catch {
				return false;
			}
		});
	}

	blockHeight(): number {
		return this.height;
	}

	txStatus(id: string): { known: boolean; confirmed: boolean } | null {
		id = txid(id);
		this.tracked.add(id);
		const status = this.statuses.get(id);
		return status ? { ...status } : null;
	}

	confirmedSpendOf(id: string, vout: number): string | null {
		return this.spends.get(key(id, vout)) ?? null;
	}
}
