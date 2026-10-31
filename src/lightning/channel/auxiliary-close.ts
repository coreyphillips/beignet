import type * as bitcoin from 'bitcoinjs-lib';
import { ChannelRole } from './types';
import { buildClosingTx } from '../chain/closing';
import type { IChannelState } from './channel-state';
import { requireAuxiliaryProvider } from './auxiliary';

/** Apply asset commitments before the Bitcoin closing signature is created. */
export function applyAuxiliaryClose(
	state: IChannelState,
	transaction: bitcoin.Transaction,
	feeSatoshis: bigint,
	retain = true
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
	const localAmount =
		state.localBalanceMsat / 1000n -
		(state.role === ChannelRole.OPENER ? feeSatoshis : 0n);
	const remoteAmount =
		state.remoteBalanceMsat / 1000n -
		(state.role === ChannelRole.OPENER ? 0n : feeSatoshis);
	if (localAmount < 0n || remoteAmount < 0n)
		throw new Error('Asset close fee exceeds balance');
	const result = provider.buildClose({
		state,
		transaction: transaction.clone(),
		localOutputIndex,
		remoteOutputIndex,
		feeSatoshis,
		localAmount,
		remoteAmount,
		localDustLimit: state.localConfig.dustLimitSatoshis,
		remoteDustLimit: state.remoteConfig.dustLimitSatoshis
	});
	if (result.outputs) {
		if (!result.outputs.length || result.outputs.length > 64)
			throw new Error('Invalid asset close output count');
		for (const output of result.outputs) {
			if (
				(output.side !== 'local' && output.side !== 'remote') ||
				typeof output.asset !== 'boolean' ||
				output.value <= 0n ||
				output.value > BigInt(Number.MAX_SAFE_INTEGER) ||
				output.script.length !== 34 ||
				output.script[0] !== 0x51 ||
				output.script[1] !== 0x20 ||
				(output.asset && output.value < 330n)
			)
				throw new Error('Invalid asset close payout');
		}
		for (const [side, amount, assetBalance, dust] of [
			[
				'local',
				localAmount,
				state.auxiliaryState!.localBalance,
				state.localConfig.dustLimitSatoshis
			],
			[
				'remote',
				remoteAmount,
				state.auxiliaryState!.remoteBalance,
				state.remoteConfig.dustLimitSatoshis
			]
		] as const) {
			const outputs = result.outputs.filter((output) => output.side === side);
			const total = outputs.reduce((sum, output) => sum + output.value, 0n);
			if (assetBalance > 0n) {
				if (total !== amount || !outputs.some((output) => output.asset))
					throw new Error('Asset close payout would lose funds');
			} else if (
				outputs.some((output) => output.asset) ||
				(total !== amount && !(total === 0n && amount <= dust))
			) {
				throw new Error('Bitcoin close payout changed');
			}
		}
		transaction.outs = result.outputs.map((output) => ({
			script: Buffer.from(output.script),
			value: Number(output.value)
		}));
	} else {
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
	}
	if (!retain) return;
	state.auxiliaryState!.closeTransactions ??= new Map();
	state.auxiliaryState!.closeTransactions.set(
		transaction.getId(),
		Buffer.from(result.customData)
	);
}

/** Include provider-declared asset anchors in the existing close fee model. */
export function auxiliaryClosingWeight(
	state: IChannelState,
	baseWeight: number
): number {
	if (!state.auxiliaryState) return baseWeight;
	const lengths =
		requireAuxiliaryProvider(state).extraCloseOutputScriptLengths?.(state) ??
		[];
	if (
		lengths.length > 62 ||
		lengths.some(
			(length) => !Number.isSafeInteger(length) || length < 0 || length > 10000
		)
	)
		throw new Error('Invalid auxiliary close shape');
	return (
		baseWeight +
		lengths.reduce(
			(sum, length) => sum + 4 * (8 + (length < 253 ? 1 : 3) + length),
			0
		)
	);
}

/** Evaluate relay fees on the exact asset payout layout without retaining a candidate. */
export function auxiliaryClosingRelayProfile(
	state: IChannelState,
	feeSatoshis: bigint
): { weight: number; feePaid: bigint } {
	const opener = state.role === ChannelRole.OPENER;
	const { tx } = buildClosingTx({
		fundingTxid: state.fundingTxid!.toString('hex'),
		fundingOutputIndex: state.fundingOutputIndex!,
		fundingAmount: state.fundingSatoshis,
		localScriptPubkey: state.localShutdownScript!,
		remoteScriptPubkey: state.remoteShutdownScript!,
		localAmount: state.localBalanceMsat / 1000n - (opener ? feeSatoshis : 0n),
		remoteAmount: state.remoteBalanceMsat / 1000n - (opener ? 0n : feeSatoshis),
		feeAmount: feeSatoshis,
		localDustLimit: state.localConfig.dustLimitSatoshis,
		remoteDustLimit: state.remoteConfig.dustLimitSatoshis,
		sequence: 0xfffffffd
	});
	applyAuxiliaryClose(state, tx, feeSatoshis, false);
	tx.setWitness(0, [Buffer.alloc(64)]);
	return {
		weight: tx.weight(),
		feePaid:
			state.fundingSatoshis -
			tx.outs.reduce((sum, output) => sum + BigInt(output.value), 0n)
	};
}
