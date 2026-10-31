import type { IChannelState } from './channel-state';
import {
	serializeHtlcEntry,
	deserializeHtlcEntry
} from '../storage/htlc-serialization';
import type { IChannelAuxiliaryState } from './auxiliary';
import {
	serializeAuxiliaryState,
	deserializeAuxiliaryState
} from '../storage/auxiliary-serialization';

/** Funding-specific public data retained for historical commitment recovery. */
export interface IFundingEpoch {
	/** Exact immutable commitment profile for this historical funding. */
	channelType?: Buffer;
	fundingTxid: Buffer;
	fundingOutputIndex: number;
	fundingSatoshis: bigint;
	localBalanceMsat: bigint;
	remoteBalanceMsat: bigint;
	localFundingPubkey: Buffer;
	remoteFundingPubkey: Buffer;
	fundingTaprootMerkleRoot?: Buffer;
	taprootNonceDomain?: Buffer;
	auxiliaryState?: IChannelAuxiliaryState;
	localCommitmentNumber?: bigint;
	remoteCommitmentSignature?: Buffer | null;
	remoteSigningNonce?: Buffer;
	remoteHtlcSignatures?: Buffer[];
	remoteCurrentPerCommitmentPoint?: Buffer | null;
	htlcs?: IChannelState['htlcs'];
	signedLocalRemovals?: IChannelState['signedLocalRemovals'];
	commitmentFeeratePerkw?: number;
	lastSignedCommitFeeratePerKw?: number;
}
const keyOf = (txid: Buffer, index: number): string =>
	`${txid.toString('hex')}:${index}`;
export function serializeFundingEpoch(epoch: IFundingEpoch) {
	return {
		channelType: epoch.channelType?.toString('hex'),
		fundingTxid: epoch.fundingTxid.toString('hex'),
		fundingOutputIndex: epoch.fundingOutputIndex,
		fundingSatoshis: epoch.fundingSatoshis.toString(),
		localBalanceMsat: epoch.localBalanceMsat.toString(),
		remoteBalanceMsat: epoch.remoteBalanceMsat.toString(),
		localFundingPubkey: epoch.localFundingPubkey.toString('hex'),
		remoteFundingPubkey: epoch.remoteFundingPubkey.toString('hex'),
		fundingTaprootMerkleRoot: epoch.fundingTaprootMerkleRoot?.toString('hex'),
		taprootNonceDomain: epoch.taprootNonceDomain?.toString('hex'),
		auxiliaryState: serializeAuxiliaryState(epoch.auxiliaryState),
		localCommitmentNumber: epoch.localCommitmentNumber?.toString(),
		remoteCommitmentSignature: epoch.remoteCommitmentSignature?.toString('hex'),
		remoteSigningNonce: epoch.remoteSigningNonce?.toString('hex'),
		remoteHtlcSignatures: epoch.remoteHtlcSignatures?.map((x) =>
			x.toString('hex')
		),
		remoteCurrentPerCommitmentPoint:
			epoch.remoteCurrentPerCommitmentPoint?.toString('hex'),
		htlcs: epoch.htlcs
			? [...epoch.htlcs].map(([key, entry]) => serializeHtlcEntry(key, entry))
			: undefined,
		signedLocalRemovals: epoch.signedLocalRemovals?.map((entry) =>
			serializeHtlcEntry(`removed-${entry.id}`, entry)
		),
		commitmentFeeratePerkw: epoch.commitmentFeeratePerkw,
		lastSignedCommitFeeratePerKw: epoch.lastSignedCommitFeeratePerKw
	};
}
export function deserializeFundingEpoch(
	value: ReturnType<typeof serializeFundingEpoch>
): IFundingEpoch {
	const bytes = (hex: string, size: number): Buffer => {
		if (!new RegExp(`^[0-9a-f]{${size * 2}}$`).test(hex))
			throw new Error('Invalid historical funding bytes');
		return Buffer.from(hex, 'hex');
	};
	const amount = (decimal: string): bigint => {
		if (!/^(0|[1-9][0-9]*)$/.test(decimal))
			throw new Error('Invalid historical funding amount');
		const parsed = BigInt(decimal);
		if (parsed > 0xffffffffffffffffn)
			throw new Error('Historical funding amount overflows');
		return parsed;
	};
	if (
		!Number.isInteger(value.fundingOutputIndex) ||
		value.fundingOutputIndex < 0 ||
		value.fundingOutputIndex > 0xffffffff
	)
		throw new Error('Invalid historical funding output index');
	if (
		value.htlcs &&
		new Set(value.htlcs.map((x) => x.key)).size !== value.htlcs.length
	)
		throw new Error('Duplicate historical HTLC');
	for (const rate of [
		value.commitmentFeeratePerkw,
		value.lastSignedCommitFeeratePerKw
	])
		if (
			rate !== undefined &&
			(!Number.isInteger(rate) || rate < 0 || rate > 0xffffffff)
		)
			throw new Error('Invalid historical commitment feerate');
	if (
		value.channelType !== undefined &&
		!/^(?:[0-9a-f]{2}){1,512}$/.test(value.channelType)
	)
		throw new Error('Invalid historical channel type');
	return {
		...(value.channelType !== undefined
			? { channelType: Buffer.from(value.channelType, 'hex') }
			: {}),
		fundingTxid: bytes(value.fundingTxid, 32),
		fundingOutputIndex: value.fundingOutputIndex,
		fundingSatoshis: amount(value.fundingSatoshis),
		localBalanceMsat: amount(value.localBalanceMsat),
		remoteBalanceMsat: amount(value.remoteBalanceMsat),
		localFundingPubkey: bytes(value.localFundingPubkey, 33),
		remoteFundingPubkey: bytes(value.remoteFundingPubkey, 33),
		fundingTaprootMerkleRoot: value.fundingTaprootMerkleRoot
			? bytes(value.fundingTaprootMerkleRoot, 32)
			: undefined,
		taprootNonceDomain: value.taprootNonceDomain
			? bytes(value.taprootNonceDomain, 32)
			: undefined,
		auxiliaryState: deserializeAuxiliaryState(value.auxiliaryState),
		...(value.localCommitmentNumber !== undefined
			? { localCommitmentNumber: amount(value.localCommitmentNumber) }
			: {}),
		...(value.remoteCommitmentSignature
			? {
					remoteCommitmentSignature: bytes(
						value.remoteCommitmentSignature,
						value.remoteCommitmentSignature.length === 64 ? 32 : 64
					)
			  }
			: {}),
		...(value.remoteSigningNonce
			? { remoteSigningNonce: bytes(value.remoteSigningNonce, 66) }
			: {}),
		...(value.remoteHtlcSignatures
			? {
					remoteHtlcSignatures: value.remoteHtlcSignatures.map((x) =>
						bytes(x, 64)
					)
			  }
			: {}),
		...(value.remoteCurrentPerCommitmentPoint
			? {
					remoteCurrentPerCommitmentPoint: bytes(
						value.remoteCurrentPerCommitmentPoint,
						33
					)
			  }
			: {}),
		...(value.htlcs
			? {
					htlcs: new Map(
						value.htlcs.map((x) => {
							const entry = deserializeHtlcEntry(x);
							return [entry.key, entry.entry];
						})
					)
			  }
			: {}),
		...(value.signedLocalRemovals
			? {
					signedLocalRemovals: value.signedLocalRemovals.map(
						(x) => deserializeHtlcEntry(x).entry
					)
			  }
			: {}),
		...(value.commitmentFeeratePerkw !== undefined
			? { commitmentFeeratePerkw: value.commitmentFeeratePerkw }
			: {}),
		...(value.lastSignedCommitFeeratePerKw !== undefined
			? { lastSignedCommitFeeratePerKw: value.lastSignedCommitFeeratePerKw }
			: {})
	};
}
export function retainFundingEpoch(state: IChannelState): void {
	if (!state.fundingTxid || !state.remoteBasepoints)
		throw new Error('Cannot retain an unbound funding epoch');
	const snapshot = deserializeFundingEpoch(
		serializeFundingEpoch({
			...(state.channelType ? { channelType: state.channelType } : {}),
			fundingTxid: state.fundingTxid,
			fundingOutputIndex: state.fundingOutputIndex,
			fundingSatoshis: state.fundingSatoshis,
			localBalanceMsat: state.localBalanceMsat,
			remoteBalanceMsat: state.remoteBalanceMsat,
			localFundingPubkey: state.localBasepoints.fundingPubkey,
			remoteFundingPubkey: state.remoteBasepoints.fundingPubkey,
			fundingTaprootMerkleRoot: state.fundingTaprootMerkleRoot,
			taprootNonceDomain: state.taprootNonceDomain,
			auxiliaryState: state.auxiliaryState,
			localCommitmentNumber: state.localCommitmentNumber,
			remoteCommitmentSignature: state.remoteCommitmentSignature,
			remoteSigningNonce: state.remoteSigningNonce,
			remoteHtlcSignatures: state.remoteHtlcSignatures,
			remoteCurrentPerCommitmentPoint: state.remoteCurrentPerCommitmentPoint,
			htlcs: state.htlcs,
			signedLocalRemovals: state.signedLocalRemovals,
			commitmentFeeratePerkw: state.commitmentFeeratePerkw,
			lastSignedCommitFeeratePerKw: state.lastSignedCommitFeeratePerKw
		})
	);
	state.fundingEpochs ??= new Map();
	state.fundingEpochs.set(
		keyOf(snapshot.fundingTxid, snapshot.fundingOutputIndex),
		snapshot
	);
}
/** Select public funding data while preserving the global revocation history. */
export function selectFundingEpoch(
	state: IChannelState,
	fundingTxid: Buffer,
	fundingOutputIndex: number
): IChannelState {
	if (
		state.fundingTxid?.equals(fundingTxid) &&
		state.fundingOutputIndex === fundingOutputIndex
	)
		return state;
	const stored = state.fundingEpochs?.get(
		keyOf(fundingTxid, fundingOutputIndex)
	);
	if (!stored || !state.remoteBasepoints)
		throw new Error('Unknown historical funding outpoint');
	const epoch = deserializeFundingEpoch(serializeFundingEpoch(stored));
	return {
		...state,
		...epoch,
		localNonce: undefined,
		localNextNonce: undefined,
		localBasepoints: {
			...state.localBasepoints,
			fundingPubkey: epoch.localFundingPubkey
		},
		remoteBasepoints: {
			...state.remoteBasepoints,
			fundingPubkey: epoch.remoteFundingPubkey
		}
	};
}

/** Select a retained epoch from the transaction's actual funding input. */
export function selectFundingEpochForTransaction(
	state: IChannelState,
	transaction: { ins: readonly { hash: Buffer; index: number }[] }
): IChannelState {
	const matches = transaction.ins.filter(
		(input) =>
			(state.fundingTxid?.equals(input.hash) &&
				state.fundingOutputIndex === input.index) ||
			state.fundingEpochs?.has(keyOf(input.hash, input.index))
	);
	if (matches.length > 1)
		throw new Error('Transaction spends multiple funding epochs');
	return matches.length
		? selectFundingEpoch(state, matches[0].hash, matches[0].index)
		: state;
}
