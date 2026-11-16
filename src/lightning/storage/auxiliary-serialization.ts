/**
 * Storage codec for the asset state of a channel (IChannelAuxiliaryState)
 * and for custom records. Used only for channels that have asset state: the
 * row of any other channel never reaches this module.
 *
 * Reading is strict. Every integer is a canonical decimal in range, every
 * byte string is hex, every map key is unique and well formed. A stored row
 * that fails any of it throws, which stops the restore of that channel
 * rather than run it on guessed asset balances. An optional field is
 * written only when present and read back only when written, so a row
 * encodes to the same bytes after any number of round trips.
 */

import { copyAuxiliaryOpeningCsvPolicy } from '../channel/auxiliary-csv';
import { ecc } from '../../utils/ecc';
import type { HtlcDirection } from '../channel/types';
import type {
	IAuxiliaryCommitmentData,
	IAuxiliaryHtlcResolution,
	IChannelAuxiliaryState
} from '../channel/auxiliary';
import type { CustomRecords } from '../message/custom-records';
import { copyCustomRecords } from '../message/custom-records';
import type { ITaprootAuxLeaf } from '../script/commitment-taproot';

/** Custom records as [decimal type, hex value] pairs, in map order. */
export type SerializedCustomRecords = [string, string][];
interface ISerializedAuxiliaryLeaf {
	script: string;
	leafVersion?: number;
}
interface ISerializedAuxiliaryCommitment {
	secondLevelRevocationKey?: string;
	secondLevelRevocationBasepoint?: string;
	secondLevelCommitmentTxid?: string;
	customData: string;
	outputLeaves: [number, ISerializedAuxiliaryLeaf][];
	secondLevelLeaves: [string, ISerializedAuxiliaryLeaf][];
	peerSignatures?: SerializedCustomRecords;
	htlcOutputIndexes?: [string, number][];
}
/** The stored form of IChannelAuxiliaryState. */
export interface ISerializedAuxiliaryState {
	openingCsvPolicy?: IChannelAuxiliaryState['openingCsvPolicy'];
	childRevocationBasepoints?: [string, string][];
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

function encodeCustomRecords(records: CustomRecords): SerializedCustomRecords {
	return [...records].map(([type, value]) => [
		type.toString(),
		value.toString('hex')
	]);
}

/**
 * Custom records as stored. The reader is strict, so the writer runs it
 * over what it is about to store: records the reader would refuse fail
 * here, at the save, and not when the row is next read.
 */
export function serializeCustomRecords(
	records: CustomRecords
): SerializedCustomRecords {
	const serialized = encodeCustomRecords(records);
	deserializeCustomRecords(serialized);
	return serialized;
}
export function deserializeCustomRecords(
	records: SerializedCustomRecords
): Map<bigint, Buffer> {
	if (!Array.isArray(records)) {
		throw new Error('Malformed serialized custom records');
	}
	const result = new Map(
		records.map(([type, value]) => [unsigned(type), bytes(value)])
	);
	if (result.size !== records.length)
		throw new Error('Duplicate serialized custom record');
	// Validates every type as a custom record and copies every value.
	return copyCustomRecords(result)!;
}

/**
 * Asset channel state as stored. As with custom records, the strict reader
 * runs over the result before it is returned, so every check the reader
 * makes is made at the save and state that could not be read back is never
 * written.
 */
export function serializeAuxiliaryState(
	state: IChannelAuxiliaryState
): ISerializedAuxiliaryState {
	const serialized = encodeAuxiliaryState(state);
	deserializeAuxiliaryState(serialized);
	return serialized;
}

function encodeAuxiliaryState(
	state: IChannelAuxiliaryState
): ISerializedAuxiliaryState {
	const leaf = (value: ITaprootAuxLeaf): ISerializedAuxiliaryLeaf => ({
		script: value.script.toString('hex'),
		...(value.leafVersion !== undefined
			? { leafVersion: value.leafVersion }
			: {})
	});
	const commitment = (
		value: IAuxiliaryCommitmentData
	): ISerializedAuxiliaryCommitment => ({
		customData: value.customData.toString('hex'),
		...(value.secondLevelRevocationKey
			? {
					secondLevelRevocationKey:
						value.secondLevelRevocationKey.toString('hex')
			  }
			: {}),
		...(value.secondLevelRevocationBasepoint
			? {
					secondLevelRevocationBasepoint:
						value.secondLevelRevocationBasepoint.toString('hex')
			  }
			: {}),
		...(value.secondLevelCommitmentTxid !== undefined
			? { secondLevelCommitmentTxid: value.secondLevelCommitmentTxid }
			: {}),
		...(value.htlcOutputIndexes
			? { htlcOutputIndexes: [...value.htlcOutputIndexes] }
			: {}),
		outputLeaves: [...value.outputLeaves].map(([index, item]) => [
			index,
			leaf(item)
		]),
		secondLevelLeaves: [...value.secondLevelLeaves].map(([id, item]) => [
			id,
			leaf(item)
		]),
		...(value.peerSignatures
			? { peerSignatures: encodeCustomRecords(value.peerSignatures) }
			: {})
	});
	return {
		...(state.openingCsvPolicy
			? {
					openingCsvPolicy: copyAuxiliaryOpeningCsvPolicy(
						state.openingCsvPolicy
					)
			  }
			: {}),
		channelData: state.channelData.toString('hex'),
		...(state.childRevocationBasepoints
			? {
					childRevocationBasepoints: [...state.childRevocationBasepoints].map(
						([id, point]): [string, string] => [id, point.toString('hex')]
					)
			  }
			: {}),
		...(state.resolvedHtlcs
			? {
					resolvedHtlcs: [...state.resolvedHtlcs].map(
						([key, value]): NonNullable<
							ISerializedAuxiliaryState['resolvedHtlcs']
						>[number] => [
							key,
							{
								htlcId: value.htlcId.toString(),
								direction: value.direction,
								paymentHash: value.paymentHash.toString('hex'),
								auxiliaryAmount: value.auxiliaryAmount.toString(),
								...(value.customRecords
									? {
											customRecords: encodeCustomRecords(value.customRecords)
									  }
									: {}),
								outcome: value.outcome
							}
						]
					)
			  }
			: {}),
		localBalance: state.localBalance.toString(),
		remoteBalance: state.remoteBalance.toString(),
		...(state.localShutdownRecords
			? {
					localShutdownRecords: encodeCustomRecords(state.localShutdownRecords)
			  }
			: {}),
		...(state.remoteShutdownRecords
			? {
					remoteShutdownRecords: encodeCustomRecords(
						state.remoteShutdownRecords
					)
			  }
			: {}),
		...(state.closeTransactions
			? {
					closeTransactions: [...state.closeTransactions].map(
						([txid, data]): [string, string] => [txid, data.toString('hex')]
					)
			  }
			: {}),
		...(state.acceptedClosingSigned
			? { acceptedClosingSigned: state.acceptedClosingSigned.toString('hex') }
			: {}),
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
	state: ISerializedAuxiliaryState
): IChannelAuxiliaryState {
	if (!state || typeof state !== 'object') {
		throw new Error('Malformed serialized asset channel state');
	}
	const leaf = (value: ISerializedAuxiliaryLeaf): ITaprootAuxLeaf => {
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
		return {
			script,
			...(value.leafVersion !== undefined
				? { leafVersion: value.leafVersion }
				: {})
		};
	};
	const commitment = (
		value: ISerializedAuxiliaryCommitment
	): IAuxiliaryCommitmentData => ({
		customData: bytes(value.customData),
		...(value.secondLevelRevocationKey !== undefined
			? { secondLevelRevocationKey: childPoint(value.secondLevelRevocationKey) }
			: {}),
		...(value.secondLevelRevocationBasepoint !== undefined
			? {
					secondLevelRevocationBasepoint: childPoint(
						value.secondLevelRevocationBasepoint
					)
			  }
			: {}),
		...(value.secondLevelCommitmentTxid !== undefined
			? {
					secondLevelCommitmentTxid: childTxid(value.secondLevelCommitmentTxid)
			  }
			: {}),
		...(value.htlcOutputIndexes !== undefined
			? {
					htlcOutputIndexes: uniqueMap(
						value.htlcOutputIndexes.map(([id, index]): [string, number] => [
							htlcKey(id),
							outputIndex(index)
						])
					)
			  }
			: {}),
		outputLeaves: uniqueMap(
			value.outputLeaves.map(([index, item]): [number, ITaprootAuxLeaf] => [
				outputIndex(index),
				leaf(item)
			])
		),
		secondLevelLeaves: uniqueMap(
			value.secondLevelLeaves.map(([id, item]): [string, ITaprootAuxLeaf] => [
				htlcKey(id),
				leaf(item)
			])
		),
		...(value.peerSignatures !== undefined
			? { peerSignatures: deserializeCustomRecords(value.peerSignatures) }
			: {})
	});
	const localBalance = unsigned(state.localBalance);
	const remoteBalance = unsigned(state.remoteBalance);
	if (localBalance + remoteBalance > 0xffffffffffffffffn)
		throw new Error('Serialized asset balances overflow');
	return {
		...(state.openingCsvPolicy !== undefined
			? {
					openingCsvPolicy: copyAuxiliaryOpeningCsvPolicy(
						state.openingCsvPolicy
					)
			  }
			: {}),
		channelData: bytes(state.channelData),
		...(state.childRevocationBasepoints !== undefined
			? {
					childRevocationBasepoints: uniqueMap(
						state.childRevocationBasepoints.map(
							([id, point]): [string, Buffer] => [
								childTxid(id),
								childPoint(point)
							]
						)
					)
			  }
			: {}),
		...(state.resolvedHtlcs !== undefined
			? {
					resolvedHtlcs: uniqueMap(
						state.resolvedHtlcs.map(
							([key, value]): [string, IAuxiliaryHtlcResolution] => {
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
										htlcId,
										direction: value.direction,
										paymentHash,
										auxiliaryAmount,
										...(value.customRecords !== undefined
											? {
													customRecords: deserializeCustomRecords(
														value.customRecords
													)
											  }
											: {}),
										outcome: value.outcome
									}
								];
							}
						)
					)
			  }
			: {}),
		localBalance,
		remoteBalance,
		...(state.localShutdownRecords !== undefined
			? {
					localShutdownRecords: deserializeCustomRecords(
						state.localShutdownRecords
					)
			  }
			: {}),
		...(state.remoteShutdownRecords !== undefined
			? {
					remoteShutdownRecords: deserializeCustomRecords(
						state.remoteShutdownRecords
					)
			  }
			: {}),
		...(state.closeTransactions !== undefined
			? {
					closeTransactions: uniqueMap(
						state.closeTransactions.map(([txid, data]): [string, Buffer] => {
							if (!/^[a-f0-9]{64}$/.test(txid))
								throw new Error('Malformed serialized asset close identity');
							return [txid, bytes(data)];
						})
					)
			  }
			: {}),
		...(state.acceptedClosingSigned !== undefined
			? { acceptedClosingSigned: bytes(state.acceptedClosingSigned) }
			: {}),
		localCommitments: uniqueMap(
			state.localCommitments.map(
				([number, value]): [bigint, IAuxiliaryCommitmentData] => [
					unsigned(number, 0xffffffffffffn),
					commitment(value)
				]
			)
		),
		remoteCommitments: uniqueMap(
			state.remoteCommitments.map(
				([number, value]): [bigint, IAuxiliaryCommitmentData] => [
					unsigned(number, 0xffffffffffffn),
					commitment(value)
				]
			)
		)
	};
}

function childPoint(value: string): Buffer {
	const point = bytes(value);
	if (point.length !== 33 || !ecc.isPoint(point))
		throw new Error('Malformed child custody point');
	return point;
}
function childTxid(value: string): string {
	if (!/^[0-9a-f]{64}$/.test(value))
		throw new Error('Malformed child custody transaction');
	return value;
}
