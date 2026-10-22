/**
 * IWalletStorage adapter backed by the node's SqliteStorage.
 *
 * Persists the on-chain wallet's IWalletData values (addresses, indexes,
 * UTXOs, transactions, balance, ...) in the wallet_data table so a restarted
 * daemon reloads its wallet state from disk and refreshWallet() performs an
 * incremental Electrum sync instead of a full rebuild.
 *
 * Values are stored as JSON strings. Encryption at rest follows the storage
 * encryption key: when BeignetNode derives one (storageEncryption, default
 * on), SqliteStorage encrypts the value column; without a key the rows stay
 * plaintext. Keys already embed the wallet name and network
 * ("<name>-<network>-<field>", see getWalletDataStorageKey) and the DB file
 * itself is per-network, so networks can never mix.
 */

import type { IStorageBackend } from '../lightning/storage/types';
import type {
	IWalletData,
	IWalletStorage,
	TWalletDataKeys,
	TWalletStorageKey
} from '../types/wallet';
import type { Result } from '../utils/result';
import { ok, err } from '../utils/result';

export function createWalletStorage(storage: IStorageBackend): IWalletStorage {
	if (!storage.saveWalletData || !storage.loadWalletData) {
		// Backends without the optional wallet-data methods cannot persist:
		// the Wallet then falls back to in-memory defaults.
		return {};
	}
	return {
		getData: async <K extends TWalletDataKeys>(
			key: TWalletStorageKey<K>
		): Promise<Result<IWalletData[K] | undefined>> => {
			try {
				const raw = storage.loadWalletData!(key);
				if (raw === null) {
					// Missing key: the Wallet substitutes its default for this field.
					return ok(undefined);
				}
				return ok(JSON.parse(raw) as IWalletData[K]);
			} catch (e) {
				return err(e instanceof Error ? e.message : String(e));
			}
		},
		setData: async <K extends TWalletDataKeys>(
			key: TWalletStorageKey<K>,
			value: IWalletData[K]
		): Promise<Result<boolean>> => {
			try {
				storage.saveWalletData!(key, JSON.stringify(value));
				return ok(true);
			} catch (e) {
				return err(e instanceof Error ? e.message : String(e));
			}
		}
	};
}
