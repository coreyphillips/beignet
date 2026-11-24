import type Database from 'better-sqlite3';
import type { FinalOpeningAuthority } from './final-opening-authority';
import { hkdfKey, encryptValue, decryptValue } from './encryption';
import { sha256 } from '../crypto/provider';
import type { IFinalLedgerState } from './final-channel-updates';

interface Row {
	sequence: number;
	record: string;
}
export interface FinalJournalEntry extends Row {
	state: IFinalLedgerState;
}
function recordHash(record: string | null): string | null {
	return record === null ? null : sha256(Buffer.from(record)).toString('hex');
}
function decode(
	row: Row,
	key: Buffer,
	previous?: string | null
): FinalJournalEntry {
	const frame = JSON.parse(
		decryptValue(
			hkdfKey(key, 'final-update-record/' + row.sequence),
			row.record
		)
	);
	if (
		frame.sequence !== row.sequence ||
		!frame.state ||
		(previous !== undefined && frame.parent !== recordHash(previous))
	)
		throw new Error('Invalid final commitment journal chain');
	return { ...row, state: frame.state };
}
export function verifyFinalJournal(
	db: Database.Database,
	id: string,
	key: Buffer
): void {
	let previous: string | null = null,
		sequence = 1;
	for (const row of db
		.prepare(
			'SELECT sequence, record FROM final_channel_update_log WHERE channel_id=? ORDER BY sequence'
		)
		.iterate(id) as Iterable<Row>) {
		if (row.sequence !== sequence++)
			throw new Error('Missing final commitment journal entry');
		decode(row, key, previous);
		previous = row.record;
	}
}
export function preserveFinalJournal(
	old: Database.Database,
	next: Database.Database
): void {
	const find = next.prepare(
		'SELECT record FROM final_channel_update_log WHERE channel_id=? AND sequence=?'
	);
	for (const row of old
		.prepare(
			'SELECT channel_id, sequence, record FROM final_channel_update_log'
		)
		.iterate() as Iterable<Row & { channel_id: string }>) {
		const incoming = find.get(row.channel_id, row.sequence) as
			| { record: string }
			| undefined;
		if (incoming?.record !== row.record)
			throw new Error(
				'Cannot roll back final commitment update history in backup'
			);
	}
}
/** Always reconcile with the original device before exposing an exit or signing. */
export function currentFinalJournal(
	db: Database.Database,
	authority: FinalOpeningAuthority,
	id: string,
	key: Buffer
): FinalJournalEntry | null {
	let last = db
		.prepare(
			'SELECT sequence, record FROM final_channel_update_log WHERE channel_id=? ORDER BY sequence DESC LIMIT 1'
		)
		.get(id) as Row | undefined;
	if (
		last &&
		authority.lifecycleEntry('update/' + id + '/' + last.sequence) !==
			last.record
	)
		throw new Error('Wallet commitment disagrees with original device');
	let next: number = (last?.sequence ?? 0) + 1;
	let record = authority.lifecycleEntry('update/' + id + '/' + next);
	while (record !== null) {
		decode({ sequence: next, record }, key, last?.record ?? null);
		db.prepare(
			'INSERT INTO final_channel_update_log(channel_id,sequence,record) VALUES(?,?,?)'
		).run(id, next, record);
		last = { sequence: next, record };
		next++;
		record = authority.lifecycleEntry('update/' + id + '/' + next);
	}
	return last ? decode(last, key) : null;
}
export function appendFinalJournal(
	db: Database.Database,
	authority: FinalOpeningAuthority,
	id: string,
	key: Buffer,
	previous: FinalJournalEntry | null,
	state: IFinalLedgerState,
	acknowledgingDelivery = false
): void {
	const sequence = (previous?.sequence ?? 0) + 1;
	if (!Number.isSafeInteger(sequence))
		throw new Error('Commitment journal exhausted');
	// The immutable opening can be large. The first record retains it for wallet-only rollback repair.
	const { openingRecovery, ...body } = state;
	const persistedState = sequence === 1 && openingRecovery ? state : body;
	const record = encryptValue(
		hkdfKey(key, 'final-update-record/' + sequence),
		JSON.stringify({
			sequence,
			parent: recordHash(previous?.record ?? null),
			state: persistedState
		})
	);
	if (!acknowledgingDelivery && authority.exitRequest(id))
		throw new Error('Final exit already requested');
	authority.commitLifecycleEntry('update/' + id + '/' + sequence, record);
	db.prepare(
		'INSERT INTO final_channel_update_log(channel_id,sequence,record) VALUES(?,?,?)'
	).run(id, sequence, record);
}

export function* finalJournalHistory(
	db: Database.Database,
	id: string,
	key: Buffer
) {
	for (const row of db
		.prepare(
			'SELECT sequence,record FROM final_channel_update_log WHERE channel_id=? ORDER BY sequence'
		)
		.iterate(id) as Iterable<Row>)
		yield decode(row, key).state;
}

export function recoveryOpening(
	db: Database.Database,
	id: string,
	key: Buffer
) {
	const row = db
		.prepare(
			'SELECT sequence,record FROM final_channel_update_log WHERE channel_id=? AND sequence=1'
		)
		.get(id) as Row | undefined;
	return row ? decode(row, key, null).state.openingRecovery : undefined;
}
