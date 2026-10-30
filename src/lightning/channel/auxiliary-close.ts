import type * as bitcoin from 'bitcoinjs-lib';
import type { IChannelState } from './channel-state';
import { requireAuxiliaryProvider } from './auxiliary';

/** Apply asset commitments before the Bitcoin closing signature is created. */
export function applyAuxiliaryClose(
	state: IChannelState,
	transaction: bitcoin.Transaction,
	feeSatoshis: bigint
): void {
	if (!state.auxiliaryState && !state.fundingTaprootMerkleRoot) return;
	const provider = requireAuxiliaryProvider(state);
	if (
		!state.auxiliaryState!.localShutdownRecords ||
		!state.auxiliaryState!.remoteShutdownRecords
	)
		throw new Error('Asset close requires both shutdown descriptors');
	const indexes = new Set<number>();
	const find = (script: Buffer | null): number | undefined => {
		const index = transaction.outs.findIndex(
			(out, candidateIndex) =>
				!indexes.has(candidateIndex) && script?.equals(out.script)
		);
		if (index < 0) return undefined;
		indexes.add(index);
		return index;
	};
	const localOutputIndex = find(state.localShutdownScript);
	const remoteOutputIndex = find(state.remoteShutdownScript);
	if (
		(state.auxiliaryState!.localBalance > 0n &&
			localOutputIndex === undefined) ||
		(state.auxiliaryState!.remoteBalance > 0n &&
			remoteOutputIndex === undefined)
	)
		throw new Error('Asset close output would be omitted as dust');
	const result = provider.buildClose({
		state,
		transaction: transaction.clone(),
		localOutputIndex,
		remoteOutputIndex,
		feeSatoshis
	});
	for (const [index, script] of result.outputScripts) {
		if (
			!Number.isSafeInteger(index) ||
			!transaction.outs[index] ||
			script.length !== 34 ||
			script[0] !== 0x51 ||
			script[1] !== 0x20
		)
			throw new Error('Invalid asset close output');
		transaction.outs[index].script = Buffer.from(script);
	}
	for (const [balance, index] of [
		[state.auxiliaryState!.localBalance, localOutputIndex],
		[state.auxiliaryState!.remoteBalance, remoteOutputIndex]
	] as const) {
		if (balance > 0n && !result.outputScripts.has(index!))
			throw new Error('Missing asset close commitment');
	}
	state.auxiliaryState!.closeTransactions ??= new Map();
	state.auxiliaryState!.closeTransactions.set(
		transaction.getId(),
		Buffer.from(result.customData)
	);
}
