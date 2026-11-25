import { Transaction } from 'bitcoinjs-lib';
import type { IAuxiliaryDualFunding } from '../channel/asset-opening-provider';
import type { SqliteStorage } from '../storage/sqlite-storage';

export function detached(tx: Transaction): Transaction {
	const copy = Transaction.fromBuffer(tx.toBuffer());
	// bitcoinjs reuses a mutable empty witness array when decoding unsigned inputs.
	for (const input of copy.ins) if (!input.witness.length) input.witness = [];
	return copy;
}

/** Commit the independently checked Bitcoin witness and wallet proof receipt together. */
export function retainAssetPayout(
	store: SqliteStorage,
	provider: IAuxiliaryDualFunding,
	id: string,
	parent: string,
	index: number,
	tx: Transaction
): Transaction {
	const raw = tx.toBuffer();
	const receipt = provider.outputRecoveryReceipt?.(
		id,
		parent,
		index,
		detached(tx)
	);
	if (!Buffer.isBuffer(receipt) || !provider.restoreOutputReceipt)
		throw Error(
			'Cannot publish an asset payout without its wallet recovery receipt'
		);
	return Transaction.fromBuffer(
		store.assetOpeningPayout(id, parent, raw, index, Buffer.from(receipt))!
	);
}

export function confirmAssetPayout(
	store: SqliteStorage,
	provider: IAuxiliaryDualFunding | undefined,
	id: string,
	parent: string,
	index: number
) {
	return async (spend: Transaction): Promise<boolean> => {
		if (!provider?.restoreOutputReceipt) return false;
		const row = store.assetOpeningPayoutReceipt(id, parent, index);
		if (!row || !row.transaction.equals(spend.toBuffer())) return false;
		await provider.restoreOutputReceipt(
			id,
			parent,
			index,
			detached(Transaction.fromBuffer(row.transaction)),
			Buffer.from(row.receipt)
		);
		return true;
	};
}
