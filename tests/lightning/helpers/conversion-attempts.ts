/**
 * The attempt record of #2151 Step 4a (contract sections 2, 3 and 4 and
 * amendments A1 and A4): the device-journal scope `conversion-attempt`, its
 * writers and readers on the store's branch readers, the manager's private
 * quiet flag and the canonical reason. None of them exists before Step 4a,
 * so each is reached when a test runs, and a missing one fails that test
 * with "not implemented: <name>" instead of failing the file at load time.
 *
 * Shapes the contract leaves open are fixed here, after the house style of
 * `storage/final-conversion-exits.ts`:
 * - a stored event carries a `kind`, `conversion-attempt` or
 *   `conversion-withdrawn`, beside the fields of section 2.2;
 * - `recordConversionAttempt` takes the fields without the `kind`, as
 *   `retainFinalConversionExits` takes the exits, and returns the scope
 *   sequence of the attempt row (A1).
 */
import path from 'path';
import type Database from 'better-sqlite3';
import type { ChannelManager } from '../../../src/lightning/channel/channel-manager';
import { finalBranchReaders } from '../../../src/lightning/storage/final-branch-readers';
import type { SqliteStorage } from '../../../src/lightning/storage/sqlite-storage';
import { method } from './conversion-modules';

/** The device-journal scope of the attempt records (section 2.1). */
export const ATTEMPT_SCOPE = 'conversion-attempt';

/** Section 7's new texts. */
export const ATTEMPT_TEXTS = {
	topLevel: 'Conversion attempts require a top-level commit',
	wallet: 'Conversion attempts require an original conversion wallet',
	notRecorded: 'Conversion attempt was not recorded',
	withdrawalFailed: 'Asset conversion withdrawal could not be recorded: ',
	restart: 'Asset conversion ended by a restart',
	invalid: 'Invalid conversion attempt record'
} as const;

/** The fields of a `conversion-attempt` event (section 2.2), all hex lowercase. */
export interface IConversionAttemptFields {
	/** 32 bytes. */
	attempt: string;
	/** 33 bytes. */
	peer: string;
	isInitiator: boolean;
	isOpener: boolean;
	giver: 'opener' | 'acceptor';
	direction: 'to-asset' | 'to-plain';
	/** The snapshot's parent, as in IAssetConversionContext.parent. */
	parent: {
		txid: string;
		outputIndex: number;
		stateNumber: string;
		type: 'plain' | 'asset';
		channelType: string;
	};
	termsDigest: string;
	layoutDigest: string;
	planDigest: string;
	agreement: string;
	/** The candidate funding key's index. */
	keyIndex: number;
}

export type ConversionAttemptEvent =
	| ({ kind: 'conversion-attempt' } & IConversionAttemptFields)
	| { kind: 'conversion-withdrawn'; attempt: string; reason: string };

/** The writers and readers of section 2.4, 2.5 and A1, reached through `finalBranchReaders`. */
export interface IConversionAttemptStorage {
	/** Appends the attempt row and returns its scope sequence n. */
	recordConversionAttempt(
		channelId: string,
		event: IConversionAttemptFields
	): number;
	/** Appends the withdrawal of the record at sequence n (A1). */
	withdrawConversionAttempt(
		channelId: string,
		sequence: number,
		attempt: string,
		reason: string
	): void;
	/** The startup sweep: never throws. */
	withdrawOpenConversionAttempts(reason: string): unknown;
	/** The scope's row count is odd: one COUNT. */
	conversionAttemptOpen(channelId: string): boolean;
	/** The open record, or null. */
	openConversionAttempt(
		channelId: string
	): (Partial<IConversionAttemptFields> & Record<string, unknown>) | null;
}

const STORAGE_MEMBERS = [
	'recordConversionAttempt',
	'withdrawConversionAttempt',
	'withdrawOpenConversionAttempts',
	'conversionAttemptOpen',
	'openConversionAttempt'
] as const;

/**
 * The store's attempt writers and readers. Each member is looked up when it
 * is called, so a missing one throws "not implemented:
 * finalBranchReaders.<name>" from that call.
 */
export function attemptStorage(
	store: SqliteStorage
): IConversionAttemptStorage {
	const out: Record<string, unknown> = {};
	for (const name of STORAGE_MEMBERS)
		out[name] = (...args: unknown[]): unknown => {
			const readers = finalBranchReaders(store);
			if (!readers) throw new Error('not implemented: finalBranchReaders');
			return method<unknown[], unknown>(
				readers,
				name,
				'finalBranchReaders'
			)(...args);
		};
	return out as unknown as IConversionAttemptStorage;
}

function rawDb(store: SqliteStorage): Database.Database {
	return (store as unknown as { db: Database.Database }).db;
}

/**
 * The wallet's rows of the scope for a channel, counted by plain SQL (no
 * production reader): 0 on a tree that has no such scope.
 */
export function attemptRowCount(store: SqliteStorage, id: string): number {
	return (
		rawDb(store)
			.prepare(
				'SELECT COUNT(*) AS n FROM final_lifecycle_log WHERE scope = ? AND channel_id = ?'
			)
			.get(ATTEMPT_SCOPE, id) as { n: number }
	).n;
}

/**
 * The scope's events for a channel, oldest first, decrypted by the store's
 * own device journal (which also pulls in a device-ahead row).
 */
export function attemptEvents(
	store: SqliteStorage,
	id: string
): ConversionAttemptEvent[] {
	const journal = (
		store as unknown as {
			finalJournal(): {
				read<T>(scope: string, id: string): { records: T[] };
			};
		}
	).finalJournal();
	try {
		return journal.read<ConversionAttemptEvent>(ATTEMPT_SCOPE, id).records;
	} catch (error) {
		if ((error as Error).message === 'Invalid final journal identity')
			throw new Error('not implemented: the conversion-attempt scope');
		throw error;
	}
}

/** The private `ChannelManager.conversionQuiet(id)` (section 3.1 and A1). */
export function conversionQuiet(manager: ChannelManager, id: string): boolean {
	return method<[string], boolean>(
		manager,
		'conversionQuiet',
		'ChannelManager'
	)(id);
}

const SRC = path.join(__dirname, '..', '..', '..', 'src', 'lightning');
/** Where amendment A4's function may live: the record module first. */
const REASON_MODULES = [
	'storage/final-conversion-attempt',
	'channel/asset-conversion-transport',
	'channel/asset-conversion-terms'
];

/**
 * The engine's `canonicalConversionReason(text)` (amendment A4), from the
 * first module that exports it.
 */
export function canonicalConversionReason(text: string): string {
	for (const rel of REASON_MODULES) {
		const file = path.join(SRC, rel);
		let mod: Record<string, unknown>;
		try {
			mod = require(file) as Record<string, unknown>;
		} catch (error) {
			const e = error as NodeJS.ErrnoException;
			if (e?.code === 'MODULE_NOT_FOUND' && String(e.message).includes(file))
				continue;
			throw error;
		}
		const fn = mod.canonicalConversionReason;
		if (typeof fn === 'function') return (fn as (t: string) => string)(text);
	}
	throw new Error('not implemented: canonicalConversionReason');
}

/** REASON_LIMIT (section 2.6). */
export const REASON_LIMIT = 200;

/**
 * Amendment A4's rule, computed here and not by the code under test: each
 * UTF-8 byte from 0x20 to 0x7e except `\` kept, every other byte written as
 * `\xNN` in lowercase hex, then cut to at most 200 bytes, never inside an
 * escape.
 */
export function expectedReason(text: string | Buffer): string {
	const bytes = Buffer.isBuffer(text) ? text : Buffer.from(text, 'utf8');
	let out = '';
	for (const b of bytes) {
		const token =
			b >= 0x20 && b <= 0x7e && b !== 0x5c
				? String.fromCharCode(b)
				: '\\x' + b.toString(16).padStart(2, '0');
		if (out.length + token.length > REASON_LIMIT) break;
		out += token;
	}
	return out;
}
