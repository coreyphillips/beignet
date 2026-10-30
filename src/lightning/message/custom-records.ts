import type { ITlvRecord } from './tlv';
import { decodeTlvStream } from './tlv';

export type CustomRecords = ReadonlyMap<bigint, Buffer>;
export const CUSTOM_RECORD_START = 65536n;
export const MAX_LIGHTNING_PAYLOAD = 65533;

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

export function boundedLightningPayload(payload: Buffer): Buffer {
	if (payload.length > MAX_LIGHTNING_PAYLOAD)
		throw new Error('Lightning message exceeds BOLT 8 payload limit');
	return payload;
}
