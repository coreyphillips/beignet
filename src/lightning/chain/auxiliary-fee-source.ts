import * as bitcoin from 'bitcoinjs-lib';
import type { IChainBackend } from './chain-watcher';

export interface IAuxiliaryFeeSourceCheck {
	transaction: Buffer;
	prevoutScripts: readonly Buffer[];
	prevoutValues: readonly bigint[];
}

/** Confirmed spend evidence only; unconfirmed competitors never suppress a claim. */
export async function hasAuxiliaryFeeSourceConflict(
	backend: IChainBackend,
	check: IAuxiliaryFeeSourceCheck
): Promise<boolean> {
	const transaction = bitcoin.Transaction.fromBuffer(check.transaction);
	if (
		!transaction.ins.length ||
		transaction.ins.length !== check.prevoutScripts.length ||
		transaction.ins.length !== check.prevoutValues.length
	)
		throw new Error('Auxiliary sweep source metadata is incomplete');
	const parents = new Map<string, bitcoin.Transaction>();
	const histories = new Map<
		string,
		Awaited<ReturnType<IChainBackend['getScriptHashHistory']>>
	>();
	for (let index = 0; index < transaction.ins.length; index++) {
		const input = transaction.ins[index];
		const txid = Buffer.from(input.hash).reverse().toString('hex');
		let parent = parents.get(txid);
		if (!parent) {
			let raw: Buffer;
			try {
				raw = await backend.getTransaction(txid);
			} catch {
				continue;
			}
			parent = bitcoin.Transaction.fromBuffer(raw);
			if (parent.getId() !== txid)
				throw new Error('Auxiliary sweep source transaction identity changed');
			parents.set(txid, parent);
		}
		const source = parent.outs[input.index];
		if (
			!source ||
			!source.script.equals(check.prevoutScripts[index]) ||
			BigInt(source.value) !== check.prevoutValues[index]
		)
			throw new Error(
				'Auxiliary sweep source differs from its authenticated prevout'
			);
		const scriptHash = bitcoin.crypto
			.sha256(source.script)
			.reverse()
			.toString('hex');
		let history = histories.get(scriptHash);
		if (!history) {
			try {
				history = await backend.getScriptHashHistory(scriptHash);
			} catch {
				continue;
			}
			histories.set(scriptHash, history);
		}
		for (const entry of history) {
			if (
				entry.txid === txid ||
				!Number.isSafeInteger(entry.height) ||
				entry.height <= 0 ||
				!/^[0-9a-f]{64}$/.test(entry.txid)
			)
				continue;
			try {
				const spent = bitcoin.Transaction.fromBuffer(
					await backend.getTransaction(entry.txid)
				);
				if (
					spent.getId() === entry.txid &&
					spent.ins.some(
						(candidate) =>
							candidate.hash.equals(input.hash) &&
							candidate.index === input.index
					)
				)
					return true;
			} catch {
				// Missing or malformed candidate bytes are not authenticated spend evidence.
			}
		}
	}
	return false;
}
