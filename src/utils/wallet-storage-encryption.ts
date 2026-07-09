/**
 * Optional encryption wrapper for the host-injected onchain wallet TStorage.
 *
 * The Wallet class hands setData plain values (objects or strings) and expects
 * getData to return them deserialized. This wrapper JSON-stringifies each
 * value, encrypts it with AES-256-GCM under an HKDF key derived from the
 * wallet seed, and stores the result as 'encw1:' + base64(iv || tag || ct).
 * On read, values carrying the prefix are decrypted and parsed; anything else
 * (legacy plaintext rows, host defaults) passes through unchanged so
 * pre-encryption data migrates lazily as it is rewritten.
 *
 * The HKDF info string domain-separates this key from the lightning storage
 * and channel-backup keys derived from the same seed.
 */

import {
	decryptWithPrefix,
	encryptWithPrefix,
	hkdfKey
} from '../lightning/storage/encryption';
import { IWalletData, TStorage } from '../types';
import { err, ok, Result } from './result';

const WALLET_ENC_PREFIX = 'encw1:';
const WALLET_HKDF_INFO = 'beignet-wallet-storage-v1';

/**
 * Wraps a TStorage so all values are encrypted at rest.
 * @param {TStorage} inner The host storage to wrap.
 * @param {Buffer} seed Wallet seed material (e.g. the BIP39 seed) to derive the key from.
 * @returns {TStorage}
 */
export const createEncryptedStorage = (
	inner: TStorage,
	seed: Buffer
): TStorage => {
	const key = hkdfKey(seed, WALLET_HKDF_INFO);
	const innerGetData = inner.getData;
	const innerSetData = inner.setData;
	const storage: TStorage = {};
	if (innerGetData) {
		storage.getData = async <K extends keyof IWalletData>(
			storageKey: string
		): Promise<Result<IWalletData[K]>> => {
			const res = await innerGetData<K>(storageKey);
			if (res.isErr()) return res;
			const value: unknown = res.value;
			// Non-prefixed values are legacy plaintext or host defaults.
			if (typeof value !== 'string' || !value.startsWith(WALLET_ENC_PREFIX)) {
				return res;
			}
			try {
				const plaintext = decryptWithPrefix(key, value, WALLET_ENC_PREFIX);
				return ok(JSON.parse(plaintext) as IWalletData[K]);
			} catch (e) {
				// Wrong seed or tampered ciphertext (GCM auth failure).
				return err(e);
			}
		};
	}
	if (innerSetData) {
		storage.setData = async <K extends keyof IWalletData>(
			storageKey: string,
			value: IWalletData[K]
		): Promise<Result<boolean>> => {
			try {
				const ciphertext = encryptWithPrefix(
					key,
					JSON.stringify(value),
					WALLET_ENC_PREFIX
				);
				// The inner storage persists an opaque string in place of the
				// typed value; hosts already JSON-serialize values, so a string
				// round-trips through any conforming TStorage.
				return await innerSetData(storageKey, ciphertext as IWalletData[K]);
			} catch (e) {
				return err(e);
			}
		};
	}
	return storage;
};
