/**
 * The funding output a spend comes from, among every funding a channel has
 * had (#2151 step 2b): the opening, a record's funding, a plain or asset
 * splice's candidate, and a pending conversion's candidate. Its type and era
 * decide which builder claims the commitment and with which views.
 */
import type { Transaction } from 'bitcoinjs-lib';
import {
	finalBranchReaders,
	type IFinalChannelFunding
} from '../storage/final-branch-readers';
import type { SqliteStorage } from '../storage/sqlite-storage';

export type { IFinalChannelFunding } from '../storage/final-branch-readers';

/** The channel's funding that `spendingTx.ins[0]` spends, or null for an outpoint the channel never had. */
export function finalSpendBranch(
	storage: SqliteStorage,
	channelId: string,
	spendingTx: Transaction
): IFinalChannelFunding | null {
	const input = spendingTx.ins[0];
	const readers = finalBranchReaders(storage);
	if (!input || !readers) return null;
	const txid = Buffer.from(input.hash).reverse().toString('hex');
	return (
		readers
			.finalChannelFundings(channelId)
			.find((f) => f.txid === txid && f.outputIndex === input.index) ?? null
	);
}

/**
 * The fast path: a channel with no `channel-type` or `conversion` row is
 * claimed as today. One row count in generation 6, and no query elsewhere.
 */
export function hasFinalBranchRows(
	storage: SqliteStorage,
	channelId: string
): boolean {
	return (finalBranchReaders(storage)?.finalBranchRows(channelId) ?? 0) > 0;
}

/** Whether a commitment spends exactly the branch's outpoint. */
export function spendsBranch(
	parent: Transaction,
	branch: IFinalChannelFunding
): boolean {
	return (
		parent.ins.length === 1 &&
		parent.ins[0].index === branch.outputIndex &&
		Buffer.from(parent.ins[0].hash).reverse().toString('hex') === branch.txid
	);
}
