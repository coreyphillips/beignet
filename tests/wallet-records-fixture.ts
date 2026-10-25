import {
	EAddressType,
	EPaymentType,
	IAddresses,
	IFormattedTransactions,
	Wallet
} from '../src';
import { writableData } from './writable-wallet-data';

/**
 * Replaces the wallet's p2wpkh receive addresses and its transactions with
 * `records` of each: one address and one confirmed receive per record. Memory
 * only, for measuring work that grows with the history.
 * @param {Wallet} wallet
 * @param {number} records
 */
export const seedWalletRecords = (wallet: Wallet, records: number): void => {
	const addresses: IAddresses = {};
	const transactions: IFormattedTransactions = {};
	for (let i = 0; i < records; i++) {
		const scriptHash = i.toString(16).padStart(64, '0');
		const txid = i.toString(16).padStart(64, 'a');
		const address = `bcrt1q${i.toString(36).padStart(38, '0')}`;
		addresses[scriptHash] = {
			index: i,
			path: `m/84'/1'/0'/0/${i}`,
			address,
			scriptHash,
			publicKey: `02${scriptHash}`
		};
		transactions[txid] = {
			address,
			height: 1000 + i,
			blockhash: scriptHash,
			scriptHash,
			totalInputValue: 0.0002,
			totalInputSats: 20_000,
			matchedInputValue: 0,
			matchedInputSats: 0,
			totalOutputValue: 0.00019,
			totalOutputSats: 19_000,
			matchedOutputValue: 0.0001,
			matchedOutputSats: 10_000,
			fee: 0.00001,
			feeSats: 1_000,
			satsPerByte: 7,
			type: EPaymentType.received,
			value: 0.0001,
			valueSats: 10_000,
			txid,
			messages: [],
			vin: [{ txid: 'ee'.repeat(32), vout: i, sequence: 0xfffffffd }],
			timestamp: 1_700_000_000_000 + i,
			confirmTimestamp: 1_700_000_600_000 + i,
			exists: true,
			rbf: false,
			vsize: 141
		};
	}
	const data = writableData(wallet);
	data.addresses = { ...data.addresses, [EAddressType.p2wpkh]: addresses };
	data.transactions = transactions;
};
