import type Database from 'better-sqlite3';
import type { FinalOpeningAuthority } from './final-opening-authority';
import { decryptValue, encryptValue, hkdfKey } from './encryption';
import { sha256 } from '../crypto/provider';

const scopes = [
	'splice',
	'asset-splice',
	'simple-close',
	'output-claim',
	'htlc-timeout',
	'channel-type'
] as const;
type Scope = (typeof scopes)[number] | 'asset-recovery-frame';
interface JournalRow {
	sequence: number;
	record: string;
}

export interface IFinalJournalHead {
	sequence: number;
	hash: string;
}
export interface IFinalJournalRead<T> extends IFinalJournalHead {
	records: T[];
}

/** Only the original device can extend these logs. A copied wallet can inspect its authenticated prefix. */
export class FinalDeviceJournal {
	constructor(
		private readonly db: Database.Database,
		private readonly walletKey: Buffer,
		private readonly identity: string,
		private readonly authority: FinalOpeningAuthority | null
	) {}

	private prefix(scope: Scope, channelId: string): string {
		if (
			(scope !== 'asset-recovery-frame' && !scopes.includes(scope)) ||
			!/^[a-f0-9]{64}$/.test(channelId)
		)
			throw new Error('Invalid final journal identity');
		return scope + '/' + channelId;
	}

	private readPrefix<T>(
		scope: Scope,
		id: string,
		checkpoint?: IFinalJournalHead
	): IFinalJournalRead<T> {
		if (
			checkpoint &&
			(!Number.isSafeInteger(checkpoint.sequence) ||
				checkpoint.sequence < 0 ||
				!/^[a-f0-9]{64}$/.test(checkpoint.hash))
		)
			throw new Error('Invalid final journal checkpoint');
		const prefix = this.prefix(scope, id);
		const key = hkdfKey(
			this.walletKey,
			'beignet-final-journal-v1/' + this.identity + '/' + prefix
		);
		const rows = this.db
			.prepare(
				'SELECT sequence,record FROM final_lifecycle_log WHERE scope=? AND channel_id=? ORDER BY sequence'
			)
			.all(scope, id) as JournalRow[];
		const records: T[] = [];
		let hash = sha256(Buffer.from(prefix)).toString('hex');
		for (let seq = 1; ; seq++) {
			const row = rows[seq - 1],
				slot = prefix + '/' + seq;
			if (checkpoint?.sequence === seq - 1 && checkpoint.hash !== hash)
				throw new Error(
					'Recovery frame splice history differs from the original device'
				);
			const device = this.authority?.lifecycleEntry(slot);
			if (row?.sequence !== undefined && row.sequence !== seq)
				throw new Error('Final journal has missing records');
			if (!row && !device) {
				if (checkpoint && checkpoint.sequence >= seq)
					throw new Error(
						'Recovery frame splice history exceeds the original device'
					);
				return { records, sequence: seq - 1, hash };
			}
			const encoded = row?.record ?? device!;
			if (this.authority && encoded !== device)
				throw new Error('Final journal differs from the original device');
			const entry = JSON.parse(decryptValue(key, encoded)) as {
				sequence: number;
				previous: string;
				event: T;
			};
			if (
				entry.sequence !== seq ||
				entry.previous !== hash ||
				entry.event === undefined
			)
				throw new Error('Invalid final journal chain');
			if (!row)
				this.db
					.prepare(
						'INSERT INTO final_lifecycle_log (scope,channel_id,sequence,record) VALUES(?,?,?,?)'
					)
					.run(scope, id, seq, encoded);
			hash = sha256(Buffer.from(encoded)).toString('hex');
			records.push(entry.event);
		}
	}

	/** Copy every device-ahead byte before SQLite takes a portable wallet snapshot. */
	reconcile(channelId: string, includeAssetFrames = false): void {
		this.db
			.transaction(() => {
				for (const scope of scopes) this.readPrefix(scope, channelId);
				if (includeAssetFrames)
					this.readPrefix('asset-recovery-frame', channelId);
			})
			.deferred();
	}

	read<T>(
		scope: Scope,
		id: string,
		checkpoint?: IFinalJournalHead
	): IFinalJournalRead<T> {
		return this.db
			.transaction(() => this.readPrefix<T>(scope, id, checkpoint))
			.deferred();
	}

	append<T>(
		scope: Scope,
		id: string,
		head: IFinalJournalHead,
		event: T
	): IFinalJournalHead {
		const authority = this.authority;
		if (!authority)
			throw new Error('Final journal requires the original wallet device');
		return this.db
			.transaction(() => {
				const prior = this.readPrefix(scope, id);
				if (prior.sequence !== head.sequence || prior.hash !== head.hash)
					throw new Error('Final journal head changed');
				const prefix = this.prefix(scope, id),
					sequence = head.sequence + 1;
				const key = hkdfKey(
					this.walletKey,
					'beignet-final-journal-v1/' + this.identity + '/' + prefix
				);
				const encoded = encryptValue(
					key,
					JSON.stringify({ sequence, previous: head.hash, event })
				);
				authority.commitLifecycleEntry(prefix + '/' + sequence, encoded);
				this.db
					.prepare(
						'INSERT INTO final_lifecycle_log (scope,channel_id,sequence,record) VALUES(?,?,?,?)'
					)
					.run(scope, id, sequence, encoded);
				return { sequence, hash: sha256(Buffer.from(encoded)).toString('hex') };
			})
			.immediate();
	}
}

/** All existing recovery bytes must be included in a backup refresh. */
export function checkFinalLifecycleBackup(
	old: Database.Database,
	next: Database.Database
): void {
	const find = next.prepare(
		'SELECT record FROM final_lifecycle_log WHERE scope=? AND channel_id=? AND sequence=?'
	);
	for (const row of old
		.prepare('SELECT * FROM final_lifecycle_log')
		.iterate() as Iterable<
		JournalRow & { scope: string; channel_id: string }
	>) {
		if (
			(
				find.get(row.scope, row.channel_id, row.sequence) as
					| { record: string }
					| undefined
			)?.record !== row.record
		)
			throw new Error('Cannot roll back a final lifecycle journal');
	}
}
