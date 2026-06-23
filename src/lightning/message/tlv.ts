/**
 * BOLT 1: TLV (Type-Length-Value) stream encoding and decoding.
 *
 * TLV records are used for extensible message fields in the Lightning protocol.
 * Each record consists of:
 *   - type: BigSize-encoded record type
 *   - length: BigSize-encoded value length
 *   - value: `length` bytes of data
 *
 * Rules:
 *   - Records MUST be in strictly increasing type order
 *   - Even types are required (unknown even type = fail)
 *   - Odd types are optional (unknown odd type = skip)
 */

import { encodeBigSize, decodeBigSize } from './codec';

/**
 * A single TLV record.
 */
export interface ITlvRecord {
	type: bigint;
	value: Buffer;
}

/**
 * Encode a TLV record into a buffer.
 * @param record - TLV record to encode
 * @returns Encoded record bytes
 */
export function encodeTlvRecord(record: ITlvRecord): Buffer {
	const typeBytes = encodeBigSize(record.type);
	const lengthBytes = encodeBigSize(BigInt(record.value.length));
	return Buffer.concat([typeBytes, lengthBytes, record.value]);
}

/**
 * Encode a stream of TLV records into a buffer.
 * Records must be provided in strictly increasing type order.
 * @param records - Array of TLV records, sorted by type
 * @returns Encoded TLV stream
 */
export function encodeTlvStream(records: ITlvRecord[]): Buffer {
	// Validate strict ordering
	for (let i = 1; i < records.length; i++) {
		if (records[i].type <= records[i - 1].type) {
			throw new Error(
				`TLV records must be in strictly increasing order: ` +
					`type ${records[i].type} follows ${records[i - 1].type}`
			);
		}
	}

	const parts: Buffer[] = [];
	for (const record of records) {
		parts.push(encodeTlvRecord(record));
	}
	return Buffer.concat(parts);
}

/**
 * Result of decoding a TLV stream.
 */
export interface ITlvStreamResult {
	records: ITlvRecord[];
	bytesRead: number;
}

/**
 * Decode a TLV stream from a buffer.
 * Validates strict type ordering and canonical BigSize encoding.
 * @param data - Buffer containing TLV stream
 * @param offset - Starting offset
 * @param knownTypes - Optional set of known types; unknown even types cause errors
 * @returns Decoded records and bytes consumed
 */
export function decodeTlvStream(
	data: Buffer,
	offset = 0,
	knownTypes?: Set<bigint>
): ITlvStreamResult {
	const records: ITlvRecord[] = [];
	let pos = offset;
	let lastType = -1n;

	while (pos < data.length) {
		// Decode type
		const typeResult = decodeBigSize(data, pos);
		pos += typeResult.bytesRead;
		const recordType = typeResult.value;

		// Validate strict ordering
		if (recordType <= lastType) {
			throw new Error(
				`TLV stream not in order: type ${recordType} follows ${lastType}`
			);
		}
		lastType = recordType;

		// Decode length
		const lengthResult = decodeBigSize(data, pos);
		pos += lengthResult.bytesRead;
		const recordLength = Number(lengthResult.value);

		// Validate we have enough data
		if (pos + recordLength > data.length) {
			throw new Error(
				`TLV record type ${recordType}: expected ${recordLength} bytes ` +
					`but only ${data.length - pos} available`
			);
		}

		// Extract value
		const value = data.subarray(pos, pos + recordLength);
		pos += recordLength;

		// Check unknown even types (even = required, unknown even = error)
		if (knownTypes && recordType % 2n === 0n && !knownTypes.has(recordType)) {
			throw new Error(`Unknown required TLV type: ${recordType}`);
		}

		records.push({ type: recordType, value: Buffer.from(value) });
	}

	return { records, bytesRead: pos - offset };
}

/**
 * Find a TLV record by type in a decoded stream.
 * @param records - Array of decoded TLV records
 * @param type - Type to search for
 * @returns The record value if found, undefined otherwise
 */
export function findTlvRecord(
	records: ITlvRecord[],
	type: bigint
): Buffer | undefined {
	const record = records.find((r) => r.type === type);
	return record?.value;
}
