import type * as bitcoin from 'bitcoinjs-lib';
import type { IChannelState } from './channel-state';
import type { IAuxiliaryFundingDescriptor } from './auxiliary-funding';
import type {
	IInteractiveTxInput,
	IInteractiveTxOutput
} from '../interactive-tx/types';

/** A peer-agreed asset plan, ready before native Bitcoin negotiation begins. */
export interface IAuxiliaryInteractiveFundingPlan {
	sessionId: Buffer;
	kind: 'dual' | 'splice';
	fundingTaprootMerkleRoot: Buffer;
	localBalance: bigint;
	remoteBalance: bigint;
	/** Encoded verified packets, provenance and source-state binding. No secret keys. */
	data: Buffer;
}
export interface IAuxiliaryFundingBuildContext {
	state: IChannelState;
	plan: IAuxiliaryInteractiveFundingPlan;
	transaction: bitcoin.Transaction;
	fundingOutputIndex: number;
	/** Aggregate key before the new funding commitment tweak, compressed. */
	fundingInternalKey: Buffer;
}
export type AuxiliaryFundingBuilder = (
	context: IAuxiliaryFundingBuildContext
) => IAuxiliaryFundingDescriptor;
/** Explicit serial IDs bind asset output indexes on both peers. */
export type NativeFundingContribution =
	| { kind: 'input'; input: IInteractiveTxInput; sharedInputTxid?: Buffer }
	| { kind: 'output'; output: IInteractiveTxOutput; funding?: boolean };
export function serializeInteractiveFundingPlan(
	plan: IAuxiliaryInteractiveFundingPlan
) {
	return {
		sessionId: plan.sessionId.toString('hex'),
		kind: plan.kind,
		fundingTaprootMerkleRoot: plan.fundingTaprootMerkleRoot.toString('hex'),
		localBalance: plan.localBalance.toString(),
		remoteBalance: plan.remoteBalance.toString(),
		data: plan.data.toString('hex')
	};
}
export function deserializeInteractiveFundingPlan(
	value: ReturnType<typeof serializeInteractiveFundingPlan>
): IAuxiliaryInteractiveFundingPlan {
	if (
		!/^[0-9a-f]{64}$/.test(value.sessionId) ||
		!/^[0-9a-f]{64}$/.test(value.fundingTaprootMerkleRoot) ||
		!['dual', 'splice'].includes(value.kind) ||
		!/^(?:[0-9a-f]{2})+$/.test(value.data) ||
		value.data.length > 128 * 1024 * 1024 ||
		!/^\d+$/.test(value.localBalance) ||
		!/^\d+$/.test(value.remoteBalance)
	)
		throw new Error('Invalid interactive asset funding plan');
	const localBalance = BigInt(value.localBalance),
		remoteBalance = BigInt(value.remoteBalance);
	if (localBalance + remoteBalance > 0xffffffffffffffffn)
		throw new Error('Interactive asset balances exceed uint64');
	return {
		sessionId: Buffer.from(value.sessionId, 'hex'),
		kind: value.kind,
		fundingTaprootMerkleRoot: Buffer.from(
			value.fundingTaprootMerkleRoot,
			'hex'
		),
		localBalance,
		remoteBalance,
		data: Buffer.from(value.data, 'hex')
	};
}

/** Local wallet registration associated with a verified asset plan. */
export interface INativeInteractiveFundingSetup {
	plan: IAuxiliaryInteractiveFundingPlan;
	/** Our Bitcoin funding contribution, or signed splice capacity change. */
	contributionSats: bigint;
	inputs: import('./channel').ISpliceWalletInput[];
	changeScript: Buffer;
	contributions: NativeFundingContribution[];
	lockAtDepth?: number;
}
