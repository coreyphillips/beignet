import type { IWalletData, Wallet } from '../src';

/**
 * The wallet's own data object, for a test that has to change memory without
 * saving the change: one that makes memory and storage disagree, or counts
 * the writes storage receives. Every other test changes data through
 * wallet.updateData, as a host does.
 * @param {Wallet} wallet
 * @returns {IWalletData}
 */
export const writableData = (wallet: Wallet): IWalletData => wallet['_data'];
