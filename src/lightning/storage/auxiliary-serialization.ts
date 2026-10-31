import type { HtlcDirection } from '../channel/types';
import type {
	IAuxiliaryCommitmentData,
	IChannelAuxiliaryState
} from '../channel/auxiliary';
import type { CustomRecords } from '../message/custom-records';
import { copyCustomRecords } from '../message/custom-records';
import type { ITaprootAuxLeaf } from '../script/commitment-taproot';

export type SerializedCustomRecords = [string, string][];
interface ISerializedAuxiliaryCommitment {
	customData: string;
	outputLeaves: [number, { script: string; leafVersion?: number }][];
	secondLevelLeaves: [string, { script: string; leafVersion?: number }][];
	peerSignatures?: SerializedCustomRecords;
	htlcOutputIndexes?: [string, number][];
}
export interface ISerializedAuxiliaryState {
	channelData: string;
	resolvedHtlcs?: [
		string,
		{
			htlcId: string;
			direction: HtlcDirection;
			paymentHash: string;
			auxiliaryAmount: string;
			customRecords?: SerializedCustomRecords;
			outcome: 'fulfilled' | 'failed';
		}
	][];
	localBalance: string;
	remoteBalance: string;
	localShutdownRecords?: SerializedCustomRecords;
	remoteShutdownRecords?: SerializedCustomRecords;
	closeTransactions?: [string, string][];
	acceptedClosingSigned?: string;
	localCommitments: [string, ISerializedAuxiliaryCommitment][];
	remoteCommitments: [string, ISerializedAuxiliaryCommitment][];
}

function bytes(hex: string): Buffer {
	if (
		typeof hex !== 'string' ||
		hex.length > 128 * 1024 * 1024 ||
		!/^(?:[a-f0-9]{2})*$/i.test(hex)
	)
		throw new Error('Malformed serialized asset bytes');
	return Buffer.from(hex, 'hex');
}

function unsigned(value: string, maximum = 0xffffffffffffffffn): bigint {
	if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value))
		throw new Error('Malformed serialized asset integer');
	const result = BigInt(value);
	if (result > maximum)
		throw new Error('Serialized asset integer is out of range');
	return result;
}
function uniqueMap<K, V>(entries: Array<[K, V]>): Map<K, V> {
	const result = new Map(entries);
	if (result.size !== entries.length)
		throw new Error('Duplicate serialized asset map entry');
	return result;
}
function outputIndex(index: number): number {
	if (!Number.isInteger(index) || index < 0 || index > 0xffffffff)
		throw new Error('Malformed serialized asset output index');
	return index;
}
function htlcKey(key: string): string {
	const match = /^(OFFERED|RECEIVED):(0|[1-9][0-9]*)$/.exec(key);
	if (!match) throw new Error('Malformed serialized asset HTLC identity');
	unsigned(match[2]);
	return key;
}

export function serializeCustomRecords(
	records?: CustomRecords
): SerializedCustomRecords | undefined {
	return records
		? [...records].map(([type, value]) => [
				type.toString(),
				value.toString('hex')
		  ])
		: undefined;
}
export function deserializeCustomRecords(
	records?: SerializedCustomRecords
): Map<bigint, Buffer> | undefined {
	if (!records) return undefined;
	const result = new Map(
		records.map(([type, value]) => [unsigned(type), bytes(value)])
	);
	if (result.size !== records.length)
		throw new Error('Duplicate serialized custom record');
	return copyCustomRecords(result);
}

export function serializeAuxiliaryState(
	state?: IChannelAuxiliaryState
): ISerializedAuxiliaryState | undefined {
	if (!state) return undefined;
	const leaf = (
		value: ITaprootAuxLeaf
	): { script: string; leafVersion?: number } => ({
		script: value.script.toString('hex'),
		leafVersion: value.leafVersion
	});
	const commitment = (
		value: IAuxiliaryCommitmentData
	): ISerializedAuxiliaryCommitment => ({
		customData: value.customData.toString('hex'),
		htlcOutputIndexes: value.htlcOutputIndexes
			? [...value.htlcOutputIndexes]
			: undefined,
		outputLeaves: [...value.outputLeaves].map(([index, item]) => [
			index,
			leaf(item)
		]),
		secondLevelLeaves: [...value.secondLevelLeaves].map(([id, item]) => [
			id,
			leaf(item)
		]),
		peerSignatures: serializeCustomRecords(value.peerSignatures)
	});
	return {
		channelData: state.channelData.toString('hex'),
		resolvedHtlcs: state.resolvedHtlcs
			? [...state.resolvedHtlcs].map(([key, value]) => [
					key,
					{
						...value,
						htlcId: value.htlcId.toString(),
						paymentHash: value.paymentHash.toString('hex'),
						auxiliaryAmount: value.auxiliaryAmount.toString(),
						customRecords: serializeCustomRecords(value.customRecords)
					}
			  ])
			: undefined,
		localBalance: state.localBalance.toString(),
		remoteBalance: state.remoteBalance.toString(),
		localShutdownRecords: serializeCustomRecords(state.localShutdownRecords),
		remoteShutdownRecords: serializeCustomRecords(state.remoteShutdownRecords),
		acceptedClosingSigned: state.acceptedClosingSigned?.toString('hex'),
		closeTransactions: state.closeTransactions
			? [...state.closeTransactions].map(([txid, data]) => [
					txid,
					data.toString('hex')
			  ])
			: undefined,
		localCommitments: [...state.localCommitments].map(([number, value]) => [
			number.toString(),
			commitment(value)
		]),
		remoteCommitments: [...state.remoteCommitments].map(([number, value]) => [
			number.toString(),
			commitment(value)
		])
	};
}

export function deserializeAuxiliaryState(
	state?: ISerializedAuxiliaryState
): IChannelAuxiliaryState | undefined {
	if (!state) return undefined;
	const leaf = (value: {
		script: string;
		leafVersion?: number;
	}): ITaprootAuxLeaf => {
		const script = bytes(value.script);
		const version = value.leafVersion ?? 0xc0;
		if (
			script.length > 10000 ||
			!Number.isInteger(version) ||
			version < 0 ||
			version > 254 ||
			version & 1
		)
			throw new Error('Malformed serialized auxiliary leaf');
		return { script, leafVersion: value.leafVersion };
	};
	const commitment = (
		value: ISerializedAuxiliaryCommitment
	): IAuxiliaryCommitmentData => ({
		customData: bytes(value.customData),
		htlcOutputIndexes: value.htlcOutputIndexes
			? uniqueMap(
					value.htlcOutputIndexes.map(([id, index]) => [
						htlcKey(id),
						outputIndex(index)
					])
			  )
			: undefined,
		outputLeaves: uniqueMap(
			value.outputLeaves.map(([index, item]) => [
				outputIndex(index),
				leaf(item)
			])
		),
		secondLevelLeaves: uniqueMap(
			value.secondLevelLeaves.map(([id, item]) => [htlcKey(id), leaf(item)])
		),
		peerSignatures: deserializeCustomRecords(value.peerSignatures)
	});
	const localBalance = unsigned(state.localBalance);
	const remoteBalance = unsigned(state.remoteBalance);
	if (localBalance + remoteBalance > 0xffffffffffffffffn)
		throw new Error('Serialized asset balances overflow');
	return {
		channelData: bytes(state.channelData),
		resolvedHtlcs: state.resolvedHtlcs
			? uniqueMap(
					state.resolvedHtlcs.map(([key, value]) => {
						const htlcId = unsigned(value.htlcId);
						const auxiliaryAmount = unsigned(value.auxiliaryAmount);
						const paymentHash = bytes(value.paymentHash);
						if (
							htlcKey(key) !== `${value.direction}:${htlcId}` ||
							!auxiliaryAmount ||
							paymentHash.length !== 32 ||
							!['fulfilled', 'failed'].includes(value.outcome)
						)
							throw new Error('Malformed serialized asset resolution');
						return [
							key,
							{
								...value,
								htlcId,
								auxiliaryAmount,
								paymentHash,
								customRecords: deserializeCustomRecords(value.customRecords)
							}
						];
					})
			  )
			: undefined,
		localBalance,
		remoteBalance,
		localShutdownRecords: deserializeCustomRecords(state.localShutdownRecords),
		remoteShutdownRecords: deserializeCustomRecords(
			state.remoteShutdownRecords
		),
		acceptedClosingSigned: state.acceptedClosingSigned
			? bytes(state.acceptedClosingSigned)
			: undefined,
		closeTransactions: state.closeTransactions
			? uniqueMap(
					state.closeTransactions.map(([txid, data]) => {
						if (!/^[a-f0-9]{64}$/.test(txid))
							throw new Error('Malformed serialized asset close identity');
						return [txid, bytes(data)];
					})
			  )
			: undefined,
		localCommitments: uniqueMap(
			state.localCommitments.map(([number, value]) => [
				unsigned(number, 0xffffffffffffn),
				commitment(value)
			])
		),
		remoteCommitments: uniqueMap(
			state.remoteCommitments.map(([number, value]) => [
				unsigned(number, 0xffffffffffffn),
				commitment(value)
			])
		)
	};
}
