import { IChannelState } from '../channel/channel-state';
import { HtlcDirection, IHtlcSnapshotEntry } from '../channel/types';
import { isFforConcurrentVersion } from '../ffor/types';

interface IHistoryEntry {
	paymentHash: string;
	amountMsat: string;
	cltvExpiry: number;
	direction: HtlcDirection;
}

/** Lossless dictionary plus one ordered splice per commitment snapshot. */
export interface ICompactHtlcHistory {
	version: 1;
	entries: IHistoryEntry[];
	snapshots: {
		commitmentNumber: string;
		prefix: number;
		remove: number;
		add: number[];
	}[];
}

export function usesCompactHtlcHistory(state: IChannelState): boolean {
	return (
		state.compactHtlcHistory === true ||
		isFforConcurrentVersion(state.ffor?.concurrentVersion)
	);
}

export function encodeHtlcHistory(
	history: Map<string, IHtlcSnapshotEntry[]> | undefined
): ICompactHtlcHistory {
	const result: ICompactHtlcHistory = {
		version: 1,
		entries: [],
		snapshots: []
	};
	const indices = new Map<string, number>();
	let previous: number[] = [];
	for (const [commitmentNumber, entries] of history ?? []) {
		const current = entries.map((entry) => {
			const value: IHistoryEntry = {
				paymentHash: entry.paymentHash.toString('hex'),
				amountMsat: entry.amountMsat.toString(),
				cltvExpiry: entry.cltvExpiry,
				direction: entry.direction
			};
			const key = JSON.stringify(value);
			let index = indices.get(key);
			if (index === undefined) {
				index = result.entries.length;
				indices.set(key, index);
				result.entries.push(value);
			}
			return index;
		});
		let prefix = 0;
		while (
			prefix < previous.length &&
			prefix < current.length &&
			previous[prefix] === current[prefix]
		)
			prefix++;
		let suffix = 0;
		while (
			suffix < previous.length - prefix &&
			suffix < current.length - prefix &&
			previous[previous.length - suffix - 1] ===
				current[current.length - suffix - 1]
		)
			suffix++;
		result.snapshots.push({
			commitmentNumber,
			prefix,
			remove: previous.length - prefix - suffix,
			add: current.slice(prefix, current.length - suffix)
		});
		previous = current;
	}
	return result;
}

export function decodeHtlcHistory(
	history: ICompactHtlcHistory
): Map<string, IHtlcSnapshotEntry[]> | undefined {
	if (
		!history ||
		history.version !== 1 ||
		!Array.isArray(history.entries) ||
		!Array.isArray(history.snapshots)
	)
		throw new Error('Unsupported compact HTLC history');
	for (const entry of history.entries) {
		if (
			!entry ||
			typeof entry.paymentHash !== 'string' ||
			!/^[0-9a-f]{64}$/.test(entry.paymentHash) ||
			typeof entry.amountMsat !== 'string' ||
			!/^\d+$/.test(entry.amountMsat) ||
			BigInt(entry.amountMsat) > 0xffffffffffffffffn ||
			!Number.isInteger(entry.cltvExpiry) ||
			entry.cltvExpiry < 0 ||
			entry.cltvExpiry > 0xffffffff ||
			(entry.direction !== HtlcDirection.OFFERED &&
				entry.direction !== HtlcDirection.RECEIVED)
		)
			throw new Error('Invalid compact HTLC history entry');
	}
	const result = new Map<string, IHtlcSnapshotEntry[]>();
	let previous: number[] = [];
	for (const snapshot of history.snapshots) {
		if (
			!snapshot ||
			typeof snapshot.commitmentNumber !== 'string' ||
			!/^\d+$/.test(snapshot.commitmentNumber) ||
			result.has(snapshot.commitmentNumber) ||
			!Number.isSafeInteger(snapshot.prefix) ||
			snapshot.prefix < 0 ||
			snapshot.prefix > previous.length ||
			!Number.isSafeInteger(snapshot.remove) ||
			snapshot.remove < 0 ||
			snapshot.remove > previous.length - snapshot.prefix ||
			!Array.isArray(snapshot.add) ||
			snapshot.add.some(
				(index) =>
					!Number.isSafeInteger(index) ||
					index < 0 ||
					index >= history.entries.length
			)
		)
			throw new Error('Invalid compact HTLC history snapshot');
		previous = [
			...previous.slice(0, snapshot.prefix),
			...snapshot.add,
			...previous.slice(snapshot.prefix + snapshot.remove)
		];
		// Every occurrence owns its Buffer, including duplicate dictionary ids.
		result.set(
			snapshot.commitmentNumber,
			previous.map((index) => {
				const entry = history.entries[index];
				return {
					paymentHash: Buffer.from(entry.paymentHash, 'hex'),
					amountMsat: BigInt(entry.amountMsat),
					cltvExpiry: entry.cltvExpiry,
					direction: entry.direction
				};
			})
		);
	}
	return result.size > 0 ? result : undefined;
}
