import type { IWalletData } from '../types';

// Each Wallet's own data object, for the library code that works on it
// alongside the wallet: Electrum and Transaction, which the wallet builds,
// and the daemon. Wallet.data hands out a frozen copy instead, which costs a
// walk of the whole history per read and would not show a change the wallet
// makes while the reader awaits.
const liveData = new WeakMap<object, () => IWalletData>();

export const registerLiveWalletData = (
	wallet: object,
	read: () => IWalletData
): void => {
	liveData.set(wallet, read);
};

/**
 * The wallet's own data object. Falls back to `data` for an object no Wallet
 * registered, such as a test double.
 * @param {{ data: Readonly<IWalletData> }} wallet
 * @returns {IWalletData}
 */
export const liveWalletData = (wallet: {
	readonly data: Readonly<IWalletData>;
}): IWalletData => liveData.get(wallet)?.() ?? (wallet.data as IWalletData);
