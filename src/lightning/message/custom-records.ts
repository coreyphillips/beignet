/**
 * Custom TLV records: types at or above 65536, which BOLT 1 leaves to
 * experiments and extensions. An asset channel carries its asset data in
 * them, beside the standard fields of init, update_add_htlc,
 * commitment_signed, shutdown and closing_signed.
 *
 * Nothing here runs for a node without an auxiliary channel provider: its
 * codecs keep the standard TLV decoder, which rejects an unknown even type
 * whatever its number.
 */

import type { ITlvRecord } from './tlv';
import { decodeTlvStream } from './tlv';

/** Custom records by TLV type, every type at or above CUSTOM_RECORD_START. */
export type CustomRecords = ReadonlyMap<bigint, Buffer>;
/** The first TLV type of the custom range (BOLT 1). */
export const CUSTOM_RECORD_START = 65536n;
/** The largest payload a BOLT 8 frame carries after its two-byte type. */
export const MAX_LIGHTNING_PAYLOAD = 65533;

/** An independent copy, validated as custom records. */
export function copyCustomRecords(
	records?: CustomRecords
): Map<bigint, Buffer> | undefined {
	if (records === undefined) return undefined;
	return new Map(
		customRecordEntries(records).map(({ type, value }) => [
			type,
			Buffer.from(value)
		])
	);
}

/**
 * The records as TLV entries, in map order. Throws on a type below the
 * custom range, above a u64, or in `reserved`, and on a value that is not
 * a Buffer.
 */
export function customRecordEntries(
	records?: CustomRecords,
	reserved: ReadonlySet<bigint> = new Set()
): ITlvRecord[] {
	return [...(records ?? [])].map(([type, value]) => {
		if (
			typeof type !== 'bigint' ||
			type < CUSTOM_RECORD_START ||
			type > 0xffffffffffffffffn ||
			reserved.has(type) ||
			!Buffer.isBuffer(value)
		) {
			throw new Error('Invalid or reserved Lightning custom record');
		}
		return { type, value };
	});
}

/**
 * Decode a TLV stream that may carry custom records. A type below the
 * custom range keeps the BOLT 1 rule (an unknown even type is an error);
 * a type in the custom range is returned whatever its parity, for the
 * auxiliary provider to judge.
 */
export function decodeWithCustomRecords(
	payload: Buffer,
	offset: number,
	known: ReadonlySet<bigint>
): ITlvRecord[] {
	if (payload.length > MAX_LIGHTNING_PAYLOAD)
		throw new Error('Lightning message exceeds BOLT 8 payload limit');
	const { records } = decodeTlvStream(payload, offset);
	for (const record of records) {
		if (
			record.type < CUSTOM_RECORD_START &&
			record.type % 2n === 0n &&
			!known.has(record.type)
		) {
			throw new Error(`Unknown required TLV type: ${record.type}`);
		}
	}
	return records;
}

/** The payload, or a throw when it cannot fit one BOLT 8 frame. */
export function boundedLightningPayload(payload: Buffer): Buffer {
	if (payload.length > MAX_LIGHTNING_PAYLOAD)
		throw new Error('Lightning message exceeds BOLT 8 payload limit');
	return payload;
}
