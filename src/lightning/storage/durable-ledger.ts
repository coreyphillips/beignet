/**
 * Durable, idempotent record ledger with compare-and-swap transitions.
 *
 * The infrastructure under the LSP held-forward ledger (issue #708), written
 * so that a second record type with its own state machine (the FFOR
 * receipt-witness ledger, coreyphillips/ffor#24) instantiates the SAME
 * store, transition helper and rehydrate-before-serve rule without being
 * modelled as a variant of anyone else's record. A ledger is parameterised
 * over its record type; the only thing it asks of a record is an `id` and
 * a string `state`.
 *
 * Rules the ledger enforces, and that every record type inherits:
 *
 *  - A transition is compare-and-swap: it names the states it may start
 *    from and the state it moves to. A record in any other state leaves the
 *    ledger untouched and reports `stale`, so a duplicate message, a
 *    replayed channel update, or a crash-recovery re-drive that lands after
 *    the transition already happened is a no-op, never a second action.
 *  - The durable write lands BEFORE the in-memory copy changes. A storage
 *    failure leaves memory exactly as it was and reports `storage_failed`,
 *    so a caller that acts only on `applied` never acts on a transition
 *    that is not on disk.
 *  - A set transition (several records moving together) runs inside one
 *    store transaction and is checked against every member first: either
 *    all members move or none does.
 *  - Rehydrate before serve: no transition is applied until `rehydrate()`
 *    has loaded the store. A request that arrives earlier is refused as
 *    `not_rehydrated` rather than judged against an empty ledger, which is
 *    what would let a restart forget a hold it still owed.
 */

/** The minimum a ledger record must carry. */
export interface ILedgerRecord {
	/** Unique record id (hex). Never a payment hash: hashes are shared. */
	id: string;
	/** Current lifecycle state, one of the record type's own state names. */
	state: string;
}

/**
 * The durable home of a ledger's records. `transaction` must make a group of
 * puts/deletes atomic; the in-memory implementation runs the group inline.
 */
export interface IDurableLedgerStore<R extends ILedgerRecord> {
	load(id: string): R | null;
	loadAll(): R[];
	put(record: R): void;
	delete(id: string): void;
	transaction<T>(fn: () => T): T;
}

/** Encodes one record to and from the string a key/value store keeps. */
export interface ILedgerCodec<R extends ILedgerRecord> {
	encode(record: R): string;
	decode(raw: string): R | null;
}

/**
 * The slice of the node's storage adapter the metadata-backed store needs.
 * `IStorageBackend` satisfies it; so does any key/value adapter with a
 * transaction wrapper.
 */
export interface ILedgerKeyValueStorage {
	saveMetadata(key: string, value: string): void;
	loadMetadata(key: string): string | null;
	transaction<T>(fn: () => T): T;
}

/* eslint-disable brace-style -- prettier wraps the long class heads */
/** Process-memory store: for nodes without storage, and for tests. */
export class MemoryLedgerStore<R extends ILedgerRecord>
	implements IDurableLedgerStore<R>
{
	private rows = new Map<string, R>();

	load(id: string): R | null {
		const row = this.rows.get(id);
		return row ? { ...row } : null;
	}

	loadAll(): R[] {
		return [...this.rows.values()].map((r) => ({ ...r }));
	}

	put(record: R): void {
		this.rows.set(record.id, { ...record });
	}

	delete(id: string): void {
		this.rows.delete(id);
	}

	transaction<T>(fn: () => T): T {
		return fn();
	}
}

/**
 * Store over the node's key/value metadata table. Each record is one row
 * under `<prefix>:row:<id>`; the set of live ids is one index row under
 * `<prefix>:index`, rewritten inside the same transaction as the row it
 * changes, because the metadata table has no prefix scan and no delete. A
 * deleted record's row is overwritten with an empty tombstone and dropped
 * from the index.
 */
export class MetadataLedgerStore<R extends ILedgerRecord>
	implements IDurableLedgerStore<R>
{
	constructor(
		private readonly storage: ILedgerKeyValueStorage,
		private readonly prefix: string,
		private readonly codec: ILedgerCodec<R>
	) {}

	private rowKey(id: string): string {
		return `${this.prefix}:row:${id}`;
	}

	private indexKey(): string {
		return `${this.prefix}:index`;
	}

	private loadIndex(): string[] {
		const raw = this.storage.loadMetadata(this.indexKey());
		if (!raw) return [];
		try {
			const parsed = JSON.parse(raw) as unknown;
			return Array.isArray(parsed)
				? parsed.filter((x): x is string => typeof x === 'string')
				: [];
		} catch {
			return [];
		}
	}

	private saveIndex(ids: string[]): void {
		this.storage.saveMetadata(this.indexKey(), JSON.stringify(ids));
	}

	load(id: string): R | null {
		const raw = this.storage.loadMetadata(this.rowKey(id));
		if (!raw) return null;
		return this.codec.decode(raw);
	}

	loadAll(): R[] {
		const out: R[] = [];
		for (const id of this.loadIndex()) {
			const row = this.load(id);
			if (row) out.push(row);
		}
		return out;
	}

	put(record: R): void {
		this.storage.transaction(() => {
			this.storage.saveMetadata(
				this.rowKey(record.id),
				this.codec.encode(record)
			);
			const ids = this.loadIndex();
			if (!ids.includes(record.id)) {
				ids.push(record.id);
				this.saveIndex(ids);
			}
		});
	}

	delete(id: string): void {
		this.storage.transaction(() => {
			this.storage.saveMetadata(this.rowKey(id), '');
			const ids = this.loadIndex().filter((x) => x !== id);
			this.saveIndex(ids);
		});
	}

	transaction<T>(fn: () => T): T {
		return this.storage.transaction(fn);
	}
}

/** Outcome of a compare-and-swap transition. */
export type LedgerTransitionOutcome =
	| 'applied'
	| 'stale'
	| 'missing'
	| 'storage_failed'
	| 'not_rehydrated';

export interface ILedgerTransitionResult<R extends ILedgerRecord> {
	outcome: LedgerTransitionOutcome;
	/** The record after the call (unchanged unless `applied`), if it exists. */
	record?: R;
	/** For `stale`: the state the record was actually in. */
	actualState?: string;
}

/**
 * The in-memory view of a durable store plus the compare-and-swap helper.
 * Memory is a cache of the store, never the other way round: every mutation
 * goes to the store first.
 */
export class DurableLedger<R extends ILedgerRecord> {
	private records = new Map<string, R>();
	private rehydrated = false;

	constructor(private readonly store: IDurableLedgerStore<R>) {}

	/**
	 * Load every stored record. Must run before the ledger serves any
	 * transition; safe to call again (it reloads from the store).
	 */
	rehydrate(): number {
		this.records.clear();
		for (const row of this.store.loadAll()) {
			this.records.set(row.id, row);
		}
		this.rehydrated = true;
		return this.records.size;
	}

	isRehydrated(): boolean {
		return this.rehydrated;
	}

	get(id: string): R | undefined {
		const r = this.records.get(id);
		return r ? { ...r } : undefined;
	}

	list(): R[] {
		return [...this.records.values()].map((r) => ({ ...r }));
	}

	find(predicate: (record: R) => boolean): R[] {
		return this.list().filter(predicate);
	}

	/**
	 * Insert a new record. Refuses an id already present (`stale`), so a
	 * duplicate registration is idempotent rather than a silent overwrite.
	 */
	insert(record: R): ILedgerTransitionResult<R> {
		if (!this.rehydrated) return { outcome: 'not_rehydrated' };
		const existing = this.records.get(record.id);
		if (existing) {
			return {
				outcome: 'stale',
				record: { ...existing },
				actualState: existing.state
			};
		}
		try {
			this.store.put(record);
		} catch {
			return { outcome: 'storage_failed' };
		}
		this.records.set(record.id, { ...record });
		return { outcome: 'applied', record: { ...record } };
	}

	/**
	 * Move one record from any of `from` to `to`, applying `patch` to the
	 * stored copy in the same write.
	 */
	transition(
		id: string,
		from: readonly string[],
		to: string,
		patch?: Partial<R>
	): ILedgerTransitionResult<R> {
		const results = this.transitionSet([id], from, to, patch);
		return results;
	}

	/**
	 * Move every record in `ids` from any of `from` to `to`, atomically: the
	 * whole set is checked first, then written in one store transaction.
	 * A single member in the wrong state makes the whole call `stale` and
	 * leaves every member untouched.
	 */
	transitionSet(
		ids: readonly string[],
		from: readonly string[],
		to: string,
		patch?: Partial<R>
	): ILedgerTransitionResult<R> {
		if (!this.rehydrated) return { outcome: 'not_rehydrated' };
		const unique = [...new Set(ids)];
		const current: R[] = [];
		for (const id of unique) {
			const r = this.records.get(id);
			if (!r) return { outcome: 'missing' };
			if (!from.includes(r.state)) {
				return { outcome: 'stale', record: { ...r }, actualState: r.state };
			}
			current.push(r);
		}
		const next = current.map((r) => ({ ...r, ...patch, state: to }) as R);
		try {
			this.store.transaction(() => {
				for (const r of next) this.store.put(r);
			});
		} catch {
			return { outcome: 'storage_failed' };
		}
		for (const r of next) this.records.set(r.id, r);
		return { outcome: 'applied', record: { ...next[0] } };
	}

	/** Drop a record for good (terminal-state housekeeping). */
	remove(id: string): boolean {
		if (!this.records.has(id)) return false;
		try {
			this.store.delete(id);
		} catch {
			return false;
		}
		this.records.delete(id);
		return true;
	}
}
