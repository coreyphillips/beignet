import type {
	IBalanceBreakdown,
	IIndexedOutpoint,
	IOutpoint,
	IUtxo,
	IWalletData
} from '../types';
import type { Result } from '../utils';
import { err, ok } from '../utils';
import type { Wallet } from '.';
import { liveWalletData } from './live-data';

type TCoinControlWallet = Pick<
	Wallet,
	'data' | 'saveWalletData' | 'getBalance'
>;

/**
 * Reads the deprecated `{ txid, index }` form as well. An argument carrying
 * both fields must name one output.
 */
const toOutpoint = (
	outpoint: IOutpoint | IIndexedOutpoint
): Result<IOutpoint> => {
	const { vout } = outpoint as Partial<IOutpoint>;
	const { index } = outpoint as Partial<IIndexedOutpoint>;
	if (vout !== undefined && index !== undefined && vout !== index) {
		return err(`vout ${vout} and index ${index} name different outputs.`);
	}
	return ok({ txid: outpoint.txid, vout: (vout ?? index) as number });
};

/**
 * The wallet's frozen coins: the blacklistedUtxos entries that every
 * wallet-driven coin selection skips. The Wallet methods of the same names
 * delegate here and carry the documentation.
 */
export class CoinControl {
	private readonly _wallet: TCoinControlWallet;

	constructor({ wallet }: { wallet: TCoinControlWallet }) {
		this._wallet = wallet;
	}

	// Read at each use: loading from storage replaces the wallet's object.
	private get _data(): IWalletData {
		return liveWalletData(this._wallet);
	}

	private saveWalletData(
		key: 'blacklistedUtxos',
		data: IUtxo[]
	): Promise<Result<string>> {
		return this._wallet.saveWalletData(key, data);
	}

	private getBalance(): number {
		return this._wallet.getBalance();
	}

	public isUtxoFrozen(outpoint: IOutpoint | string, index?: number): boolean {
		const { txid, vout } =
			typeof outpoint === 'string' ? { txid: outpoint, vout: index } : outpoint;
		return this._data.blacklistedUtxos.some(
			(frozen) => frozen.tx_hash === txid && frozen.tx_pos === vout
		);
	}

	/**
	 * Serializes blacklist mutations. Both freezeUtxo and unfreezeUtxo publish
	 * their change to the in-memory list before the storage write that may
	 * force them to roll it back, so a second caller landing in that window
	 * would read a provisional entry: it would answer "already frozen" for a
	 * freeze that then vanished, or "not frozen" for one that came back.
	 * Queueing the mutations means every caller decides against a settled list.
	 */
	private blacklistLock: Promise<unknown> = Promise.resolve();

	public runBlacklistWrite<T>(fn: () => Promise<T>): Promise<T> {
		const run = this.blacklistLock.then(fn, fn);
		this.blacklistLock = run.catch(() => undefined);
		return run;
	}

	public async freezeUtxo(
		params: (IOutpoint | IIndexedOutpoint) & { tag?: string }
	): Promise<Result<string>> {
		const outpoint = toOutpoint(params);
		if (outpoint.isErr()) return err(outpoint.error);
		const { txid, vout } = outpoint.value;
		const res = await this.freezeUtxoIfUnfrozen({
			txid,
			vout,
			tag: params.tag
		});
		if (res.isErr()) return err(res.error);
		return ok(
			res.value.created
				? `UTXO ${txid}:${vout} frozen.`
				: `UTXO ${txid}:${vout} is already frozen.`
		);
	}

	public async freezeUtxoIfUnfrozen(
		params: (IOutpoint | IIndexedOutpoint) & { tag?: string }
	): Promise<Result<{ created: boolean }>> {
		const outpoint = toOutpoint(params);
		if (outpoint.isErr()) return err(outpoint.error);
		const { tag } = params;
		return this.runBlacklistWrite(() =>
			this.freezeUtxoLocked({ ...outpoint.value, tag })
		);
	}

	private async freezeUtxoLocked({
		txid,
		vout,
		tag
	}: IOutpoint & { tag?: string }): Promise<Result<{ created: boolean }>> {
		if (typeof txid !== 'string' || !/^[0-9a-fA-F]{64}$/.test(txid)) {
			return err('txid must be a 64-character hex string.');
		}
		if (!Number.isInteger(vout) || vout < 0) {
			return err('vout must be a non-negative integer.');
		}
		const utxo = this._data.utxos.find(
			(u) => u.tx_hash === txid && u.tx_pos === vout
		);
		if (!utxo) {
			return err(`UTXO ${txid}:${vout} is not known to this wallet.`);
		}
		if (this.isUtxoFrozen({ txid, vout })) {
			return tag === undefined
				? this.untagFrozenUtxo(txid, vout)
				: ok({ created: false });
		}
		// keyPair must never be persisted with the frozen entry.
		const { keyPair, ...frozen } = utxo;
		void keyPair;
		const entry = {
			...frozen,
			...(tag !== undefined ? { freezeTag: tag, frozenAt: Date.now() } : {})
		};
		this._data.blacklistedUtxos.push(entry);
		const saved = await this.saveWalletData(
			'blacklistedUtxos',
			this._data.blacklistedUtxos
		);
		if (saved.isErr()) {
			// The row never reached storage, so the freeze dies with this
			// process: the next run hands the coin back to coin selection while
			// whatever reserved it (a funding pledge) believes it is held. Drop
			// the in-memory entry so memory and storage agree, and let the
			// caller decide whether it can proceed without the reservation.
			const at = this._data.blacklistedUtxos.indexOf(entry);
			if (at !== -1) this._data.blacklistedUtxos.splice(at, 1);
			return err(
				saved.error.code,
				`Failed to persist the freeze for UTXO ${txid}:${vout}: ${saved.error.message}`,
				saved.error
			);
		}
		return ok({ created: true });
	}

	/**
	 * Clears the tag on a frozen outpoint's entries. Automated freezers
	 * recognize their own freezes by the tag, so an entry that kept it would
	 * be lifted when that freezer lets go, taking the caller's freeze with it.
	 */
	private async untagFrozenUtxo(
		txid: string,
		vout: number
	): Promise<Result<{ created: boolean }>> {
		const tagged = this._data.blacklistedUtxos.filter(
			(frozen) =>
				frozen.tx_hash === txid &&
				frozen.tx_pos === vout &&
				frozen.freezeTag !== undefined
		);
		if (tagged.length === 0) return ok({ created: false });
		const untagged = tagged.map((frozen) => {
			const entry = { ...frozen };
			delete entry.freezeTag;
			delete entry.frozenAt;
			return entry;
		});
		const swap = (from: IUtxo[], to: IUtxo[]): void => {
			this._data.blacklistedUtxos = this._data.blacklistedUtxos.map(
				(frozen) => to[from.indexOf(frozen)] ?? frozen
			);
		};
		swap(tagged, untagged);
		const saved = await this.saveWalletData(
			'blacklistedUtxos',
			this._data.blacklistedUtxos
		);
		if (saved.isErr()) {
			swap(untagged, tagged);
			return err(
				saved.error.code,
				`Failed to persist the freeze for UTXO ${txid}:${vout}: ${saved.error.message}`,
				saved.error
			);
		}
		return ok({ created: true });
	}

	public async unfreezeUtxo(
		params: IOutpoint | IIndexedOutpoint
	): Promise<Result<string>> {
		const outpoint = toOutpoint(params);
		if (outpoint.isErr()) return err(outpoint.error);
		return this.runBlacklistWrite(() =>
			this.unfreezeUtxoLocked(outpoint.value)
		);
	}

	private async unfreezeUtxoLocked({
		txid,
		vout
	}: IOutpoint): Promise<Result<string>> {
		const removed = this._data.blacklistedUtxos.filter(
			(frozen) => frozen.tx_hash === txid && frozen.tx_pos === vout
		);
		if (removed.length === 0) {
			return err(`UTXO ${txid}:${vout} is not frozen.`);
		}
		this._data.blacklistedUtxos = this._data.blacklistedUtxos.filter(
			(frozen) => !(frozen.tx_hash === txid && frozen.tx_pos === vout)
		);
		const saved = await this.saveWalletData(
			'blacklistedUtxos',
			this._data.blacklistedUtxos
		);
		if (saved.isErr()) {
			// Storage still holds the freeze, so a restart would restore it.
			// Put the entry back rather than report a release the wallet will
			// take away again, unless a freeze landed while the write was in
			// flight and already owns the outpoint.
			if (!this.isUtxoFrozen({ txid, vout })) {
				this._data.blacklistedUtxos.push(...removed);
			}
			return err(
				saved.error.code,
				`Failed to persist the unfreeze for UTXO ${txid}:${vout}: ${saved.error.message}`,
				saved.error
			);
		}
		return ok(`UTXO ${txid}:${vout} unfrozen.`);
	}

	public async unfreezeUtxoIfTagged(
		params: (IOutpoint | IIndexedOutpoint) & { tag: string }
	): Promise<Result<{ unfrozen: boolean }>> {
		const outpoint = toOutpoint(params);
		if (outpoint.isErr()) return err(outpoint.error);
		const { txid, vout } = outpoint.value;
		const { tag } = params;
		return this.runBlacklistWrite(async () => {
			const entries = this._data.blacklistedUtxos.filter(
				(frozen) => frozen.tx_hash === txid && frozen.tx_pos === vout
			);
			if (entries.length === 0) return ok({ unfrozen: true });
			const heldByOther = entries.some((frozen) => frozen.freezeTag !== tag);
			if (heldByOther) return ok({ unfrozen: false });
			const res = await this.unfreezeUtxoLocked(outpoint.value);
			if (res.isErr()) return err(res.error);
			return ok({ unfrozen: true });
		});
	}

	public listFrozenUtxos(): IUtxo[] {
		return this._data.blacklistedUtxos;
	}

	public getBalanceBreakdown(): IBalanceBreakdown {
		const total = this.getBalance();
		const frozen = this._data.utxos.reduce((acc, utxo) => {
			return this.isUtxoFrozen({ txid: utxo.tx_hash, vout: utxo.tx_pos })
				? acc + utxo.value
				: acc;
		}, 0);
		return { total, spendable: total - frozen, frozen };
	}
}
