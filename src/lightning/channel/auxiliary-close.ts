/**
 * The asset side of a cooperative close (issue #2093).
 *
 * An asset channel closes with the same message exchange as any simple
 * taproot channel. What differs is the transaction: its provider lays the
 * asset outputs over the bitcoin payouts, and both peers have to arrive at
 * the same transaction on their own. Everything the provider answers is
 * checked here, before anything is signed or verified against it.
 */

import type * as bitcoin from 'bitcoinjs-lib';
import { ChannelRole } from './types';
import { buildClosingTx } from '../chain/closing';
import type { IChannelState } from './channel-state';
import { requireAuxiliaryProvider } from './auxiliary';

/** The smallest bitcoin value an output that carries assets may hold. */
export const AUXILIARY_CLOSE_ASSET_OUTPUT_MINIMUM = 330n;

/** The most outputs a provider may lay out for one closing transaction. */
export const MAX_AUXILIARY_CLOSE_OUTPUTS = 64;

/**
 * The most closing transactions one channel signs and keeps the provider's
 * payload for. A transaction is one fee over one pair of scripts, so a
 * close meets this only if its fee is renegotiated again and again; the
 * unilateral exit is what is left then.
 */
export const MAX_AUXILIARY_CLOSE_CANDIDATES = 32;

const isTaprootScript = (script: unknown): script is Buffer =>
	Buffer.isBuffer(script) &&
	script.length === 34 &&
	script[0] === 0x51 &&
	script[1] === 0x20;

/**
 * Lay the provider's asset outputs over a closing transaction, in place,
 * and return the provider's payload for it. Returns undefined, and touches
 * nothing, for a channel without asset state. Throws when the provider
 * cannot answer or its answer would lose either party's funds. Stores
 * nothing: see recordAuxiliaryClose.
 *
 * `outputMap` is the builder's own account of which output it made for
 * which party (buildClosingTx). It is the only source of the two indexes
 * the provider is handed: two outputs are never told apart by their
 * scripts, which a peer chooses.
 */
export function applyAuxiliaryClose(
	state: IChannelState,
	transaction: bitcoin.Transaction,
	feeSatoshis: bigint,
	outputMap: { local?: number; remote?: number }
): Buffer | undefined {
	const auxiliary = state.auxiliaryState;
	if (!auxiliary) {
		if (state.fundingTaprootMerkleRoot) {
			throw new Error('Asset close requires the asset state of the channel');
		}
		return undefined;
	}
	const provider = requireAuxiliaryProvider(state);
	if (!auxiliary.localShutdownRecords || !auxiliary.remoteShutdownRecords) {
		throw new Error('Asset close requires both shutdown descriptors');
	}
	if (
		!state.localShutdownScript ||
		!state.remoteShutdownScript ||
		state.localShutdownScript.equals(state.remoteShutdownScript)
	) {
		// The shutdown exchange refuses a script named by both parties. A
		// row that holds one all the same closes on chain, not here.
		throw new Error('Asset close requires two different payout scripts');
	}
	const localOutputIndex = outputMap.local;
	const remoteOutputIndex = outputMap.remote;
	const opener = state.role === ChannelRole.OPENER;
	const localAmount =
		state.localBalanceMsat / 1000n - (opener ? feeSatoshis : 0n);
	const remoteAmount =
		state.remoteBalanceMsat / 1000n - (opener ? 0n : feeSatoshis);
	if (localAmount < 0n || remoteAmount < 0n) {
		throw new Error('Asset close fee exceeds balance');
	}
	// Each index has to hold its party's amount, and every output has to be
	// one party's, before the provider is told which is whose: an asset
	// commitment laid over the wrong output pays one party's bitcoin to the
	// other.
	const mapped = [
		[localOutputIndex, localAmount],
		[remoteOutputIndex, remoteAmount]
	] as const;
	for (const [index, amount] of mapped) {
		if (index === undefined) continue;
		const output = Number.isSafeInteger(index)
			? transaction.outs[index]
			: undefined;
		if (!output || BigInt(output.value) !== amount) {
			throw new Error('Asset close payout index does not hold its amount');
		}
	}
	if (
		localOutputIndex === remoteOutputIndex ||
		transaction.outs.length !==
			mapped.filter(([index]) => index !== undefined).length
	) {
		throw new Error('Asset close payout index does not hold its amount');
	}
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
	if (
		!result ||
		!Buffer.isBuffer(result.customData) ||
		!(result.outputScripts instanceof Map)
	) {
		throw new Error('Invalid asset close answer');
	}
	if (result.outputs) {
		if (
			!Array.isArray(result.outputs) ||
			result.outputs.length === 0 ||
			result.outputs.length > MAX_AUXILIARY_CLOSE_OUTPUTS
		) {
			throw new Error('Invalid asset close output count');
		}
		for (const output of result.outputs) {
			if (
				!output ||
				(output.side !== 'local' && output.side !== 'remote') ||
				typeof output.asset !== 'boolean' ||
				typeof output.value !== 'bigint' ||
				output.value <= 0n ||
				output.value > BigInt(Number.MAX_SAFE_INTEGER) ||
				!isTaprootScript(output.script) ||
				(output.asset && output.value < AUXILIARY_CLOSE_ASSET_OUTPUT_MINIMUM)
			) {
				throw new Error('Invalid asset close payout');
			}
		}
		for (const [side, amount, units, dust] of [
			[
				'local',
				localAmount,
				auxiliary.localBalance,
				state.localConfig.dustLimitSatoshis
			],
			[
				'remote',
				remoteAmount,
				auxiliary.remoteBalance,
				state.remoteConfig.dustLimitSatoshis
			]
		] as const) {
			const outputs = result.outputs.filter((output) => output.side === side);
			const total = outputs.reduce((sum, output) => sum + output.value, 0n);
			if (units > 0n) {
				// A party that holds units is paid all of its bitcoin, and its
				// units ride one of its outputs.
				if (total !== amount || !outputs.some((output) => output.asset)) {
					throw new Error('Asset close payout would lose funds');
				}
			} else if (
				outputs.some((output) => output.asset) ||
				(total !== amount && !(total === 0n && amount <= dust))
			) {
				// A party without units is paid as in any close: its amount, or
				// nothing when that is dust.
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
				!isTaprootScript(script)
			) {
				throw new Error('Invalid asset close output');
			}
			if (
				BigInt(transaction.outs[index].value) <
				AUXILIARY_CLOSE_ASSET_OUTPUT_MINIMUM
			) {
				throw new Error('Invalid asset close payout');
			}
			transaction.outs[index].script = Buffer.from(script);
		}
		for (const [units, index] of [
			[auxiliary.localBalance, localOutputIndex],
			[auxiliary.remoteBalance, remoteOutputIndex]
		] as const) {
			// A party that holds units and has no output, or whose output the
			// provider left alone, would lose them.
			if (
				units > 0n &&
				(index === undefined || !result.outputScripts.has(index))
			) {
				throw new Error('Missing asset close commitment');
			}
		}
	}
	return Buffer.from(result.customData);
}

/**
 * Keep the provider's payload for a closing transaction this node is about
 * to sign, by transaction id, in the channel's asset state. The same
 * transaction again is the same entry.
 */
export function recordAuxiliaryClose(
	state: IChannelState,
	txid: string,
	customData: Buffer
): void {
	const auxiliary = state.auxiliaryState;
	if (!auxiliary) throw new Error('Asset close requires asset state');
	const known = auxiliary.closeTransactions ?? new Map<string, Buffer>();
	if (!known.has(txid) && known.size >= MAX_AUXILIARY_CLOSE_CANDIDATES) {
		throw new Error('Too many asset closing transactions were signed');
	}
	known.set(txid, Buffer.from(customData));
	auxiliary.closeTransactions = known;
}

/** The closing weight with the outputs the provider adds beyond the two payouts. */
export function auxiliaryClosingWeight(
	state: IChannelState,
	baseWeight: number
): number {
	if (!state.auxiliaryState) return baseWeight;
	const lengths =
		requireAuxiliaryProvider(state).extraCloseOutputScriptLengths?.(state) ??
		[];
	if (
		!Array.isArray(lengths) ||
		lengths.length > MAX_AUXILIARY_CLOSE_OUTPUTS - 2 ||
		lengths.some(
			(length) => !Number.isSafeInteger(length) || length < 0 || length > 10000
		)
	) {
		throw new Error('Invalid auxiliary close shape');
	}
	return (
		baseWeight +
		lengths.reduce(
			(sum, length) => sum + 4 * (8 + (length < 253 ? 1 : 3) + length),
			0
		)
	);
}

/**
 * What the asset closing transaction at this fee weighs and pays, judged
 * on the exact layout the provider answers. Keeps nothing.
 */
export function auxiliaryClosingRelayProfile(
	state: IChannelState,
	feeSatoshis: bigint
): { weight: number; feePaid: bigint } {
	const opener = state.role === ChannelRole.OPENER;
	const { tx, outputMap } = buildClosingTx({
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
	applyAuxiliaryClose(state, tx, feeSatoshis, outputMap);
	tx.setWitness(0, [Buffer.alloc(64)]);
	return {
		weight: tx.weight(),
		feePaid:
			state.fundingSatoshis -
			tx.outs.reduce((sum, output) => sum + BigInt(output.value), 0n)
	};
}
