import type { IWalletData } from '../types';
import type { Result } from '../utils/result';

type TLiveRefreshOptions = { onStart?: () => void };

type TLiveWallet = {
	data: () => IWalletData;
	refresh: (options: TLiveRefreshOptions) => Promise<Result<unknown>>;
};

// Each Wallet's own data object and refresh, for the library code that works
// on it alongside the wallet: Electrum and Transaction, which the wallet
// builds, and the daemon. Wallet.data and refreshWallet hand out a frozen copy
// instead, which costs a walk of the whole history each time and would not
// show a change the wallet makes while the reader awaits.
const live = new WeakMap<object, TLiveWallet>();

export const registerLiveWallet = (
	wallet: object,
	access: TLiveWallet
): void => {
	live.set(wallet, access);
};

/**
 * The wallet's own data object. Falls back to `data` for an object no Wallet
 * registered, such as a test double.
 * @param {{ data: Readonly<IWalletData> }} wallet
 * @returns {IWalletData}
 */
export const liveWalletData = (wallet: {
	readonly data: Readonly<IWalletData>;
}): IWalletData => live.get(wallet)?.data() ?? (wallet.data as IWalletData);

/**
 * Refreshes the wallet as refreshWallet does, settling with whether it worked
 * but without the copy of the data, for a caller that only waits for the
 * refresh. Falls back to refreshWallet for an object no Wallet registered,
 * such as a test double.
 * @param {{ refreshWallet: Function }} wallet
 * @param {TLiveRefreshOptions} [options]
 * @returns {Promise<Result<unknown>>}
 */
export const refreshLiveWallet = (
	wallet: {
		refreshWallet: (options?: TLiveRefreshOptions) => Promise<Result<unknown>>;
	},
	options: TLiveRefreshOptions = {}
): Promise<Result<unknown>> => {
	const access = live.get(wallet);
	return access ? access.refresh(options) : wallet.refreshWallet(options);
};
