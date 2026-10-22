/**
 * A pure-JS storage backend that keeps everything in memory.
 *
 * Every capability group is implemented, with the semantics SqliteStorage
 * has: values are stored encoded, so neither a later change to a saved
 * object nor one to a loaded object reaches what is stored; transactions
 * roll back every write on a throw, and nest as savepoints. It is the
 * starting point for a custom backend, and what to use where SQLite is not
 * available: tests, a capsule restore's scratch storage, a short-lived node.
 * Nothing is persisted, so a process exit loses it all.
 */

import type { IPeerTransportOptions } from '../transport/duplex-transport';
import type { IFforVoucherArchive } from '../ffor/voucher-archive';
import {
	fforVoucherArchiveId,
	mergeFforVoucherArchive,
	validateFforVoucherArchive
} from '../ffor/voucher-archive';
import type { IChannelState } from '../channel/channel-state';
import type { IHtlcSnapshotEntry } from '../channel/types';
import {
	attachStoredRevokedHtlcSnapshots,
	unsavedRevokedHtlcSnapshots
} from '../channel/htlc-snapshots';
import type { IPaymentInfo } from '../node/payment-types';
import type { IChainMonitorState } from '../chain/chain-monitor';
import type { IGraphChannel, IGraphNode } from '../gossip/types';
import type {
	IWatchtowerSession,
	IWatchtowerUpdate
} from '../watchtower/types';
import type {
	IActionLogStorage,
	IForwardingEvent,
	IForwardingEventFilter,
	IForwardingSummary,
	IGossipRowPage,
	IInvoiceInfo,
	IPersistedChannelPolicy,
	IRecoveryOutboxMessage,
	IRecoveryOutboxStoredMessage,
	IStorageBackend,
	IStoredRecoveryFrame,
	IStoredRecoveryFrameHeader,
	RecoveryOutboxDisposition
} from './types';
import {
	serializeChannelState,
	deserializeChannelState,
	serializeHtlcSnapshotEntries,
	deserializeHtlcSnapshotEntries,
	serializePaymentInfo,
	deserializePaymentInfo,
	serializeChainMonitorState,
	deserializeChainMonitorState,
	serializeGraphChannel,
	deserializeGraphChannel,
	serializeGraphNode,
	deserializeGraphNode,
	serializeInvoiceInfo,
	deserializeInvoiceInfo
} from './serialization';

/** Rows the action log keeps, newest first, as SqliteStorage does. */
const ACTION_LOG_MAX_ROWS = 10_000;

/** Rows a list call returns when the caller sets no limit. */
const DEFAULT_LIST_LIMIT = 1000;

/** Undo steps of the open transactions, newest last. */
type UndoLog = Array<() => void>;

interface IRow<V> {
	rowid: number;
	value: V;
}

/**
 * One table. Rows are read back in rowid order, as SQLite reads a table
 * with no ORDER BY: a replaced row gets a new rowid and moves last, an
 * updated one keeps its place. A table whose key is its integer primary key
 * passes that key as the rowid. While a transaction is open, every write
 * records how to undo itself.
 */
class MemoryTable<K extends string | number, V> {
	private rows = new Map<K, IRow<V>>();
	private nextRowid = 1;
	private maxRowid = 0;
	/** False once a row went back out of rowid order; the next read sorts. */
	private ordered = true;

	constructor(private readonly undoLog: () => UndoLog | null) {}

	get size(): number {
		return this.rows.size;
	}

	get(key: K): V | undefined {
		return this.rows.get(key)?.value;
	}

	has(key: K): boolean {
		return this.rows.has(key);
	}

	/** INSERT OR REPLACE. */
	put(key: K, value: V, rowid?: number): void {
		const previous = this.rows.get(key);
		if (previous && rowid === previous.rowid) {
			this.recordUndo(key, previous, true);
			this.rows.set(key, { rowid, value });
			return;
		}
		this.recordUndo(key, previous, false);
		if (previous) this.rows.delete(key);
		const id = rowid ?? this.nextRowid;
		if (id <= this.maxRowid) this.ordered = false;
		this.maxRowid = Math.max(this.maxRowid, id);
		this.nextRowid = Math.max(this.nextRowid, id + 1);
		this.rows.set(key, { rowid: id, value });
	}

	/** UPDATE of one row; a missing key is not an error. */
	update(key: K, value: V): void {
		const previous = this.rows.get(key);
		if (!previous) return;
		this.recordUndo(key, previous, true);
		this.rows.set(key, { rowid: previous.rowid, value });
	}

	delete(key: K): void {
		const previous = this.rows.get(key);
		if (!previous) return;
		this.recordUndo(key, previous, false);
		this.rows.delete(key);
	}

	/** Every row, in rowid order. A copy, so callers may write while reading. */
	entries(): Array<[K, V]> {
		return this.ordinal().map(([key, row]) => [key, row.value]);
	}

	values(): V[] {
		return this.ordinal().map(([, row]) => row.value);
	}

	/** Up to `limit` rows after `afterRowid`, with their rowids. */
	rowsAfter(afterRowid: number, limit: number): Array<IRow<V>> {
		const page: Array<IRow<V>> = [];
		if (limit <= 0) return page;
		for (const [, row] of this.ordinal()) {
			if (row.rowid <= afterRowid) continue;
			page.push(row);
			if (page.length === limit) break;
		}
		return page;
	}

	private ordinal(): Array<[K, IRow<V>]> {
		if (!this.ordered) {
			this.rows = new Map(
				[...this.rows].sort(([, a], [, b]) => a.rowid - b.rowid)
			);
			this.ordered = true;
		}
		return [...this.rows];
	}

	/** `inPlace`: the write left the row where it was. */
	private recordUndo(
		key: K,
		previous: IRow<V> | undefined,
		inPlace: boolean
	): void {
		this.undoLog()?.push(() => {
			if (previous && inPlace) {
				this.rows.set(key, previous);
				return;
			}
			this.rows.delete(key);
			if (!previous) return;
			this.rows.set(key, previous);
			this.ordered = false;
		});
	}
}

interface IChannelRow {
	json: string;
	peerPubkey: string;
}

interface IForwardedHtlcRow {
	inChannelIdHex: string;
	inHtlcId: string;
}

interface IPeerAddressRow {
	host: string;
	port: number;
	transportJson: string | null;
}

interface IAnnouncedPeerAddressRow {
	timestamp: number;
	addressesJson: string;
}

interface IPeerStorageBlobRow {
	blobHex: string;
	receivedAt: number;
}

interface IOfferRow {
	encoded: string;
	pathIdHex: string | null;
	createdAt: number;
	asyncHold: boolean;
}

interface IWatchtowerSessionRow {
	session: IWatchtowerSession;
	sessionKeyHex: string;
}

interface IFrameRow {
	sequence: number;
	writerEpoch: number;
	frameHashHex: string;
	previousFrameHashHex: string;
	ciphertextHex: string;
	createdAt: number;
}

type IOutboxRow = Omit<IRecoveryOutboxStoredMessage, 'wireMessage'> & {
	wireMessageHex: string;
};

type IActionLogEntry = Parameters<IActionLogStorage['saveActionLog']>[0];

/** Revoked-commitment snapshot rows are keyed channel id, then this, then the number. */
const SNAPSHOT_KEY_SEPARATOR = ':';

/** Commitment numbers are decimal strings: shorter first, then lexically. */
function compareCommitmentNumbers(a: string, b: string): number {
	if (a.length !== b.length) return a.length - b.length;
	return a < b ? -1 : a > b ? 1 : 0;
}

function hex(buffer: Buffer): string {
	return buffer.toString('hex');
}

function fromHex(value: string): Buffer {
	return Buffer.from(value, 'hex');
}

export class MemoryStorage implements IStorageBackend {
	/**
	 * Row cap for the forwarding ledger: the oldest rows are pruned on
	 * insert past it. A property so tests can exercise pruning with a small
	 * cap, as on SqliteStorage.
	 */
	forwardingEventsMaxRows = 100_000;

	/** Null outside a transaction, so writes there record nothing. */
	private undo: UndoLog | null = null;
	private readonly undoLog = (): UndoLog | null => this.undo;

	private readonly channels = this.table<string, IChannelRow>();
	private readonly revokedHtlcSnapshots = this.table<string, string>();
	private readonly fforVouchers = this.table<string, string>();
	private readonly payments = this.table<string, string>();
	private readonly preimages = this.table<string, string>();
	private readonly scidMappings = this.table<string, string>();
	private readonly htlcPaymentMap = this.table<string, string>();
	private readonly forwardedHtlcs = this.table<string, IForwardedHtlcRow>();
	private readonly chainMonitors = this.table<string, string>();
	private readonly gossipChannels = this.table<string, string>();
	private readonly gossipNodes = this.table<string, string>();
	private readonly paymentSecrets = this.table<string, string>();
	private readonly invoicePathIds = this.table<string, string>();
	private readonly invoices = this.table<string, string>();
	private readonly missionControl = this.table<number, string>();
	private readonly peerAddresses = this.table<string, IPeerAddressRow>();
	private readonly announcedPeerAddresses = this.table<
		string,
		IAnnouncedPeerAddressRow
	>();
	private readonly channelKeyIndices = this.table<string, number>();
	private readonly metadata = this.table<string, string>();
	private readonly walletData = this.table<string, string>();
	private readonly htlcSharedSecrets = this.table<string, string>();
	private readonly channelPolicies = this.table<string, string>();
	private readonly peerStorageBlobs = this.table<string, IPeerStorageBlobRow>();
	private readonly forwardingEvents = this.table<
		number,
		Omit<IForwardingEvent, 'id'>
	>();
	private readonly actionLog = this.table<number, IActionLogEntry>();
	private readonly watchtowerSessions = this.table<
		string,
		IWatchtowerSessionRow
	>();
	private readonly watchtowerUpdates = this.table<number, IWatchtowerUpdate>();
	private readonly outbox = this.table<number, IOutboxRow>();
	private readonly recoveryFrames = this.table<number, IFrameRow>();
	private readonly recoveryMeta = this.table<string, string>();
	private readonly offers = this.table<string, IOfferRow>();

	/** Ids for the append-only tables. Never reused, rollback included. */
	private nextId = 1;

	private table<K extends string | number, V>(): MemoryTable<K, V> {
		return new MemoryTable<K, V>(this.undoLog);
	}

	open(): void {
		// Nothing to open.
	}

	/**
	 * The contents outlive close(), so a test can hand the same instance to
	 * a new node to simulate a restart.
	 */
	close(): void {
		// Nothing to release.
	}

	// ─── Transaction ───

	/**
	 * Run `fn` atomically. A throw undoes every write `fn` made, then
	 * propagates. A nested call is a savepoint: its throw undoes only its
	 * own writes. Like better-sqlite3, refuses a function that returns a
	 * promise, whose writes after its first await would escape the
	 * transaction.
	 */
	transaction<T>(fn: () => T): T {
		const outermost = this.undo === null;
		const undo = (this.undo ??= []);
		const mark = undo.length;
		try {
			const result = fn();
			if (typeof (result as { then?: unknown } | null)?.then === 'function') {
				throw new TypeError('Transaction function cannot return a promise');
			}
			return result;
		} catch (error) {
			while (undo.length > mark) undo.pop()!();
			throw error;
		} finally {
			if (outermost) this.undo = null;
		}
	}

	inTransaction(): boolean {
		return this.undo !== null;
	}

	/** Nothing is at rest: the contents never leave this process's memory. */
	secretsEncryptedAtRest(): boolean {
		return true;
	}

	/** Every row decodes what this instance encoded, so none is skipped. */
	corruptRowCount(): number {
		return 0;
	}

	// ─── Channels ───

	saveChannel(id: string, state: IChannelState, peerPubkey: string): void {
		const json = JSON.stringify(
			serializeChannelState(state, { htlcHistory: 'none' })
		);
		const history = unsavedRevokedHtlcSnapshots(state, this);
		const snapshots: Array<[string, string]> = [];
		for (const [commitmentNumber, entries] of history ?? []) {
			if (entries.length === 0) continue;
			snapshots.push([
				commitmentNumber,
				JSON.stringify(serializeHtlcSnapshotEntries(entries))
			]);
		}
		this.transaction(() => {
			this.channels.put(id, { json, peerPubkey });
			for (const [commitmentNumber, snapshot] of snapshots) {
				this.revokedHtlcSnapshots.put(
					`${id}${SNAPSHOT_KEY_SEPARATOR}${commitmentNumber}`,
					snapshot
				);
			}
		});
	}

	revokedHtlcSnapshotStore(): object {
		return this;
	}

	loadChannel(id: string): { state: IChannelState; peerPubkey: string } | null {
		const row = this.channels.get(id);
		if (!row) return null;
		return {
			state: this.decodeChannel(row, this.snapshotsByChannel(id).get(id)),
			peerPubkey: row.peerPubkey
		};
	}

	loadAllChannels(): Array<{
		channelId: string;
		state: IChannelState;
		peerPubkey: string;
	}> {
		const history = this.snapshotsByChannel();
		return this.channels.entries().map(([channelId, row]) => ({
			channelId,
			state: this.decodeChannel(row, history.get(channelId)),
			peerPubkey: row.peerPubkey
		}));
	}

	private decodeChannel(
		row: IChannelRow,
		stored: Map<string, IHtlcSnapshotEntry[]> | undefined
	): IChannelState {
		const state = deserializeChannelState(JSON.parse(row.json));
		attachStoredRevokedHtlcSnapshots(
			state,
			stored,
			this,
			!this.inTransaction()
		);
		return state;
	}

	/**
	 * Stored snapshots by channel id, each in commitment order; only
	 * `channelId`'s when given.
	 */
	private snapshotsByChannel(
		channelId?: string
	): Map<string, Map<string, IHtlcSnapshotEntry[]>> {
		const prefix =
			channelId === undefined ? '' : `${channelId}${SNAPSHOT_KEY_SEPARATOR}`;
		const rows = this.revokedHtlcSnapshots
			.entries()
			.filter(([key]) => key.startsWith(prefix))
			.map(([key, json]) => {
				const at = key.indexOf(SNAPSHOT_KEY_SEPARATOR);
				return {
					channelId: key.slice(0, at),
					commitmentNumber: key.slice(at + 1),
					json
				};
			});
		rows.sort(
			(a, b) =>
				(a.channelId < b.channelId ? -1 : a.channelId > b.channelId ? 1 : 0) ||
				compareCommitmentNumbers(a.commitmentNumber, b.commitmentNumber)
		);
		const byChannel = new Map<string, Map<string, IHtlcSnapshotEntry[]>>();
		for (const row of rows) {
			let history = byChannel.get(row.channelId);
			if (!history) {
				history = new Map();
				byChannel.set(row.channelId, history);
			}
			history.set(
				row.commitmentNumber,
				deserializeHtlcSnapshotEntries(JSON.parse(row.json))
			);
		}
		return byChannel;
	}

	deleteChannel(id: string): void {
		// Retransmission and penalties both need the channel row, so its
		// outbound bytes and HTLC snapshots go with it.
		this.transaction(() => {
			this.channels.delete(id);
			const prefix = `${id}${SNAPSHOT_KEY_SEPARATOR}`;
			for (const [key] of this.revokedHtlcSnapshots.entries()) {
				if (key.startsWith(prefix)) this.revokedHtlcSnapshots.delete(key);
			}
			for (const [rowId, row] of this.outbox.entries()) {
				if (row.channelId === id) this.outbox.delete(rowId);
			}
		});
	}

	// ─── FFOR Voucher Archive ───

	saveFforVoucher(record: IFforVoucherArchive): void {
		const id = fforVoucherArchiveId(record);
		const merged = mergeFforVoucherArchive(this.loadFforVoucher(id), record);
		this.fforVouchers.put(id, JSON.stringify(merged));
	}

	loadFforVoucher(id: string): IFforVoucherArchive | null {
		const json = this.fforVouchers.get(id);
		return json === undefined ? null : this.decodeFforVoucher(id, json);
	}

	loadAllFforVouchers(): IFforVoucherArchive[] {
		return this.fforVouchers
			.entries()
			.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
			.map(([id, json]) => this.decodeFforVoucher(id, json));
	}

	private decodeFforVoucher(id: string, json: string): IFforVoucherArchive {
		const record = validateFforVoucherArchive(JSON.parse(json));
		if (fforVoucherArchiveId(record) !== id)
			throw new Error('FFOR archive row key mismatch');
		return record;
	}

	// ─── Payments ───

	savePayment(paymentHash: string, payment: IPaymentInfo): void {
		this.payments.put(
			paymentHash,
			JSON.stringify(serializePaymentInfo(payment))
		);
	}

	loadPayment(paymentHash: string): IPaymentInfo | null {
		const json = this.payments.get(paymentHash);
		return json === undefined ? null : deserializePaymentInfo(JSON.parse(json));
	}

	loadAllPayments(): Array<{ paymentHash: string; payment: IPaymentInfo }> {
		return this.payments.entries().map(([paymentHash, json]) => ({
			paymentHash,
			payment: deserializePaymentInfo(JSON.parse(json))
		}));
	}

	deletePayment(paymentHash: string): void {
		this.payments.delete(paymentHash);
	}

	// ─── Preimages ───

	savePreimage(paymentHash: string, preimage: Buffer): void {
		this.preimages.put(paymentHash, hex(preimage));
	}

	loadPreimage(paymentHash: string): Buffer | null {
		const value = this.preimages.get(paymentHash);
		return value === undefined ? null : fromHex(value);
	}

	loadAllPreimages(): Array<{ paymentHash: string; preimage: Buffer }> {
		return this.preimages.entries().map(([paymentHash, value]) => ({
			paymentHash,
			preimage: fromHex(value)
		}));
	}

	deletePreimage(paymentHash: string): void {
		this.preimages.delete(paymentHash);
	}

	// ─── SCID Mappings ───

	saveScidMapping(scidHex: string, channelId: Buffer): void {
		this.scidMappings.put(scidHex, hex(channelId));
	}

	loadAllScidMappings(): Array<{ scidHex: string; channelId: Buffer }> {
		return this.scidMappings.entries().map(([scidHex, value]) => ({
			scidHex,
			channelId: fromHex(value)
		}));
	}

	// ─── HTLC Payment Map ───

	saveHtlcPaymentMapping(key: string, paymentHashHex: string): void {
		this.htlcPaymentMap.put(key, paymentHashHex);
	}

	loadAllHtlcPaymentMappings(): Array<{ key: string; paymentHashHex: string }> {
		return this.htlcPaymentMap
			.entries()
			.map(([key, paymentHashHex]) => ({ key, paymentHashHex }));
	}

	deleteHtlcPaymentMapping(key: string): void {
		this.htlcPaymentMap.delete(key);
	}

	// ─── Forwarded HTLCs ───

	saveForwardedHtlc(
		outKey: string,
		inChannelId: Buffer,
		inHtlcId: bigint
	): void {
		this.forwardedHtlcs.put(outKey, {
			inChannelIdHex: hex(inChannelId),
			inHtlcId: inHtlcId.toString()
		});
	}

	loadAllForwardedHtlcs(): Array<{
		outKey: string;
		inChannelId: Buffer;
		inHtlcId: bigint;
	}> {
		return this.forwardedHtlcs.entries().map(([outKey, row]) => ({
			outKey,
			inChannelId: fromHex(row.inChannelIdHex),
			inHtlcId: BigInt(row.inHtlcId)
		}));
	}

	deleteForwardedHtlc(outKey: string): void {
		this.forwardedHtlcs.delete(outKey);
	}

	// ─── Chain Monitors ───

	saveChainMonitor(channelId: string, state: IChainMonitorState): void {
		this.chainMonitors.put(channelId, serializeChainMonitorState(state));
	}

	loadChainMonitor(channelId: string): IChainMonitorState | null {
		const json = this.chainMonitors.get(channelId);
		return json === undefined ? null : deserializeChainMonitorState(json);
	}

	loadAllChainMonitors(): Array<{
		channelId: string;
		state: IChainMonitorState;
	}> {
		return this.chainMonitors.entries().map(([channelId, json]) => ({
			channelId,
			state: deserializeChainMonitorState(json)
		}));
	}

	// ─── Gossip ───

	saveGossipChannel(scidHex: string, channel: IGraphChannel): void {
		this.gossipChannels.put(scidHex, serializeGraphChannel(channel));
	}

	loadAllGossipChannels(): IGraphChannel[] {
		return this.gossipChannels.values().map(deserializeGraphChannel);
	}

	loadGossipChannelsAfter(
		afterRowid: number,
		limit: number
	): IGossipRowPage<IGraphChannel> {
		return this.gossipPage(
			this.gossipChannels,
			afterRowid,
			limit,
			deserializeGraphChannel
		);
	}

	deleteGossipChannel(scidHex: string): void {
		this.gossipChannels.delete(scidHex);
	}

	saveGossipNode(nodeIdHex: string, node: IGraphNode): void {
		this.gossipNodes.put(nodeIdHex, serializeGraphNode(node));
	}

	loadAllGossipNodes(): IGraphNode[] {
		return this.gossipNodes.values().map(deserializeGraphNode);
	}

	loadGossipNodesAfter(
		afterRowid: number,
		limit: number
	): IGossipRowPage<IGraphNode> {
		return this.gossipPage(
			this.gossipNodes,
			afterRowid,
			limit,
			deserializeGraphNode
		);
	}

	deleteGossipNode(nodeIdHex: string): void {
		this.gossipNodes.delete(nodeIdHex);
	}

	private gossipPage<T>(
		table: MemoryTable<string, string>,
		afterRowid: number,
		limit: number,
		decode: (json: string) => T
	): IGossipRowPage<T> {
		const rows = table.rowsAfter(afterRowid, limit);
		return {
			rows: rows.map((row) => decode(row.value)),
			cursor: rows.length > 0 ? rows[rows.length - 1].rowid : afterRowid,
			done: rows.length < limit
		};
	}

	// ─── Payment Secrets ───

	savePaymentSecret(paymentHashHex: string, secret: Buffer): void {
		this.paymentSecrets.put(paymentHashHex, hex(secret));
	}

	loadAllPaymentSecrets(): Array<{ paymentHashHex: string; secret: Buffer }> {
		return this.paymentSecrets.entries().map(([paymentHashHex, value]) => ({
			paymentHashHex,
			secret: fromHex(value)
		}));
	}

	deletePaymentSecret(paymentHashHex: string): void {
		this.paymentSecrets.delete(paymentHashHex);
	}

	// ─── BOLT 12 Invoice Path IDs ───

	saveInvoicePathId(paymentHashHex: string, pathId: Buffer): void {
		this.invoicePathIds.put(paymentHashHex, hex(pathId));
	}

	loadAllInvoicePathIds(): Array<{ paymentHashHex: string; pathId: Buffer }> {
		return this.invoicePathIds.entries().map(([paymentHashHex, value]) => ({
			paymentHashHex,
			pathId: fromHex(value)
		}));
	}

	deleteInvoicePathId(paymentHashHex: string): void {
		this.invoicePathIds.delete(paymentHashHex);
	}

	// ─── Invoices ───

	saveInvoice(paymentHashHex: string, invoice: IInvoiceInfo): void {
		this.invoices.put(
			paymentHashHex,
			JSON.stringify(serializeInvoiceInfo(invoice))
		);
	}

	loadAllInvoices(): Array<{ paymentHashHex: string; invoice: IInvoiceInfo }> {
		return this.invoices.entries().map(([paymentHashHex, json]) => ({
			paymentHashHex,
			invoice: deserializeInvoiceInfo(JSON.parse(json))
		}));
	}

	deleteInvoice(paymentHashHex: string): void {
		this.invoices.delete(paymentHashHex);
	}

	// ─── Mission Control ───

	saveMissionControl(json: string): void {
		this.missionControl.put(1, json, 1);
	}

	loadMissionControl(): string | null {
		return this.missionControl.get(1) ?? null;
	}

	// ─── Peer Addresses ───

	savePeerAddress(
		pubkey: string,
		host: string,
		port: number,
		transport?: IPeerTransportOptions
	): void {
		this.peerAddresses.put(pubkey, {
			host,
			port,
			transportJson: transport ? JSON.stringify(transport) : null
		});
	}

	loadAllPeerAddresses(): Array<{
		pubkey: string;
		host: string;
		port: number;
		transport?: IPeerTransportOptions;
	}> {
		return this.peerAddresses.entries().map(([pubkey, row]) => ({
			pubkey,
			host: row.host,
			port: row.port,
			...(row.transportJson
				? { transport: JSON.parse(row.transportJson) as IPeerTransportOptions }
				: {})
		}));
	}

	deletePeerAddress(pubkey: string): void {
		this.peerAddresses.delete(pubkey);
	}

	saveAnnouncedPeerAddresses(
		pubkey: string,
		timestamp: number,
		addresses: Array<{ host: string; port: number }>
	): void {
		this.announcedPeerAddresses.put(pubkey, {
			timestamp,
			addressesJson: JSON.stringify(addresses)
		});
	}

	loadAllAnnouncedPeerAddresses(): Array<{
		pubkey: string;
		timestamp: number;
		addresses: Array<{ host: string; port: number }>;
	}> {
		return this.announcedPeerAddresses.entries().map(([pubkey, row]) => ({
			pubkey,
			timestamp: row.timestamp,
			addresses: JSON.parse(row.addressesJson) as Array<{
				host: string;
				port: number;
			}>
		}));
	}

	// ─── Channel Key Indices ───

	saveChannelKeyIndex(channelId: string, channelIndex: number): void {
		this.channelKeyIndices.put(channelId, channelIndex);
	}

	loadChannelKeyIndex(channelId: string): number | null {
		return this.channelKeyIndices.get(channelId) ?? null;
	}

	loadAllChannelKeyIndices(): Array<{
		channelId: string;
		channelIndex: number;
	}> {
		return this.channelKeyIndices
			.entries()
			.map(([channelId, channelIndex]) => ({ channelId, channelIndex }));
	}

	loadNextChannelIndex(): number {
		let max: number | null = null;
		for (const index of this.channelKeyIndices.values()) {
			if (max === null || index > max) max = index;
		}
		return max !== null ? max + 1 : 1;
	}

	hasChannelKeyIndices(): boolean {
		return this.channelKeyIndices.size > 0;
	}

	// ─── HTLC Shared Secrets ───

	saveHtlcSharedSecret(key: string, secret: Buffer): void {
		this.htlcSharedSecrets.put(key, hex(secret));
	}

	deleteHtlcSharedSecret(key: string): void {
		this.htlcSharedSecrets.delete(key);
	}

	loadAllHtlcSharedSecrets(): Array<{ key: string; secret: Buffer }> {
		return this.htlcSharedSecrets
			.entries()
			.map(([key, value]) => ({ key, secret: fromHex(value) }));
	}

	// ─── Metadata ───

	saveMetadata(key: string, value: string): void {
		this.metadata.put(key, value);
	}

	loadMetadata(key: string): string | null {
		return this.metadata.get(key) ?? null;
	}

	loadMetadataByPrefix(prefix: string): Array<{ key: string; value: string }> {
		if (!prefix) throw new Error('metadata prefix must not be empty');
		return this.metadata
			.entries()
			.filter(([key]) => key.startsWith(prefix))
			.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
			.map(([key, value]) => ({ key, value }));
	}

	deleteMetadata(key: string): void {
		this.metadata.delete(key);
	}

	// ─── On-chain Wallet Data ───

	saveWalletData(key: string, value: string): void {
		this.walletData.put(key, value);
	}

	loadWalletData(key: string): string | null {
		return this.walletData.get(key) ?? null;
	}

	// ─── Channel Routing Policies ───

	saveChannelPolicy(channelId: string, policy: IPersistedChannelPolicy): void {
		this.channelPolicies.put(channelId, JSON.stringify(policy));
	}

	loadAllChannelPolicies(): Array<{
		channelId: string;
		policy: IPersistedChannelPolicy;
	}> {
		return this.channelPolicies.entries().map(([channelId, json]) => ({
			channelId,
			policy: JSON.parse(json) as IPersistedChannelPolicy
		}));
	}

	deleteChannelPolicy(channelId: string): void {
		this.channelPolicies.delete(channelId);
	}

	// ─── Peer Storage Blobs ───

	savePeerStorageBlob(
		peerPubkey: string,
		blob: Buffer,
		receivedAt: number
	): void {
		this.peerStorageBlobs.put(peerPubkey, { blobHex: hex(blob), receivedAt });
	}

	loadPeerStorageBlob(
		peerPubkey: string
	): { blob: Buffer; receivedAt: number } | null {
		const row = this.peerStorageBlobs.get(peerPubkey);
		if (!row) return null;
		return { blob: fromHex(row.blobHex), receivedAt: row.receivedAt };
	}

	deletePeerStorageBlob(peerPubkey: string): void {
		this.peerStorageBlobs.delete(peerPubkey);
	}

	// ─── BOLT 12 Offers ───

	saveOffer(
		offerIdHex: string,
		encoded: string,
		pathId: Buffer | null,
		createdAt: number,
		asyncHold?: boolean
	): void {
		// Re-creating an identical offer hits the same id: keep its creation
		// time, and never let a null pathId downgrade its blinded-path
		// authentication.
		const previous = this.offers.get(offerIdHex);
		const row: IOfferRow = {
			encoded,
			pathIdHex: pathId ? hex(pathId) : previous?.pathIdHex ?? null,
			createdAt: previous?.createdAt ?? createdAt,
			asyncHold: !!asyncHold
		};
		if (previous) this.offers.update(offerIdHex, row);
		else this.offers.put(offerIdHex, row);
	}

	loadAllOffers(): Array<{
		offerIdHex: string;
		encoded: string;
		pathId: Buffer | null;
		createdAt: number;
		asyncHold: boolean;
	}> {
		return this.offers.entries().map(([offerIdHex, row]) => ({
			offerIdHex,
			encoded: row.encoded,
			pathId: row.pathIdHex === null ? null : fromHex(row.pathIdHex),
			createdAt: row.createdAt,
			asyncHold: row.asyncHold
		}));
	}

	deleteOffer(offerIdHex: string): void {
		this.offers.delete(offerIdHex);
	}

	// ─── Recovery Outbox ───

	saveOutboxMessage(message: IRecoveryOutboxMessage): number {
		const id = this.nextId++;
		this.outbox.put(
			id,
			{
				id,
				peerId: message.peerId,
				channelId: message.channelId,
				messageType: message.messageType,
				wireMessageHex: hex(message.wireMessage),
				disposition: message.disposition,
				frameSequence: null,
				createdAt: Date.now()
			},
			id
		);
		return id;
	}

	loadOutboxMessages(channelId?: string): IRecoveryOutboxStoredMessage[] {
		return this.outbox
			.values()
			.filter((row) => !channelId || row.channelId === channelId)
			.map(({ wireMessageHex, ...row }) => ({
				...row,
				wireMessage: fromHex(wireMessageHex)
			}));
	}

	countOutboxMessages(channelId: string): number {
		return this.outbox.values().filter((row) => row.channelId === channelId)
			.length;
	}

	setOutboxDisposition(
		id: number,
		disposition: RecoveryOutboxDisposition
	): void {
		const row = this.outbox.get(id);
		if (row) this.outbox.update(id, { ...row, disposition });
	}

	deleteOutboxMessages(channelId: string, messageTypes?: number[]): void {
		const types =
			messageTypes && messageTypes.length > 0 ? new Set(messageTypes) : null;
		for (const [id, row] of this.outbox.entries()) {
			if (row.channelId !== channelId) continue;
			if (types && !types.has(row.messageType)) continue;
			this.outbox.delete(id);
		}
	}

	pruneOutboxMessages(channelId: string, keepNewest: number): void {
		// SQLite reads a negative LIMIT as no limit.
		if (keepNewest < 0) return;
		const ids = this.outbox
			.values()
			.filter((row) => row.channelId === channelId)
			.map((row) => row.id);
		for (const id of ids.slice(0, Math.max(0, ids.length - keepNewest))) {
			this.outbox.delete(id);
		}
	}

	// ─── Recovery Journal ───

	saveRecoveryFrame(frame: IStoredRecoveryFrame): void {
		if (this.recoveryFrames.has(frame.sequence)) {
			throw new Error(
				`recovery frame ${frame.sequence} already exists (frames are append-only)`
			);
		}
		this.recoveryFrames.put(
			frame.sequence,
			{
				sequence: frame.sequence,
				writerEpoch: frame.writerEpoch,
				frameHashHex: hex(frame.frameHash),
				previousFrameHashHex: hex(frame.previousFrameHash),
				ciphertextHex: hex(frame.ciphertext),
				createdAt: frame.createdAt
			},
			frame.sequence
		);
	}

	loadRecoveryFrames(afterSequence?: number): IStoredRecoveryFrame[] {
		return this.recoveryFrames
			.values()
			.filter((row) => afterSequence == null || row.sequence > afterSequence)
			.map(decodeFrame);
	}

	loadRecoveryFrame(sequence: number): IStoredRecoveryFrame | null {
		const row = this.recoveryFrames.get(sequence);
		return row ? decodeFrame(row) : null;
	}

	loadRecoveryFrameHeader(sequence: number): IStoredRecoveryFrameHeader | null {
		const row = this.recoveryFrames.get(sequence);
		return row ? decodeFrameHeader(row) : null;
	}

	deleteRecoveryFramesBelow(sequence: number): void {
		for (const [key] of this.recoveryFrames.entries()) {
			if (key < sequence) this.recoveryFrames.delete(key);
		}
	}

	setOutboxFrameSequence(ids: number[], frameSequence: number): void {
		for (const id of ids) {
			const row = this.outbox.get(id);
			if (row) this.outbox.update(id, { ...row, frameSequence });
		}
	}

	getRecoveryMeta(key: string): string | null {
		return this.recoveryMeta.get(key) ?? null;
	}

	setRecoveryMeta(key: string, value: string): void {
		this.recoveryMeta.put(key, value);
	}

	deleteRecoveryMeta(key: string): void {
		this.recoveryMeta.delete(key);
	}

	listRecoveryMetaKeys(): string[] {
		return this.recoveryMeta.entries().map(([key]) => key);
	}

	recoveryFrameStats(): {
		count: number;
		minSequence: number;
		maxSequence: number;
	} | null {
		// Frames are read in sequence order: their sequence is their rowid.
		const sequences = this.recoveryFrames.entries().map(([key]) => key);
		if (sequences.length === 0) return null;
		return {
			count: sequences.length,
			minSequence: sequences[0],
			maxSequence: sequences[sequences.length - 1]
		};
	}

	// ─── Watchtower ───

	saveWatchtowerSession(session: IWatchtowerSession, sessionKey: Buffer): void {
		this.watchtowerSessions.put(session.sessionId, {
			session: {
				sessionId: session.sessionId,
				towerUri: session.towerUri,
				towerPubkey: session.towerPubkey,
				blobType: session.blobType,
				maxUpdates: session.maxUpdates,
				sweepFeeRate: session.sweepFeeRate,
				seqNum: session.seqNum,
				lastApplied: session.lastApplied,
				createdAt: session.createdAt,
				dialsWithSessionKey: !!session.dialsWithSessionKey
			},
			sessionKeyHex: hex(sessionKey)
		});
	}

	loadWatchtowerSessions(): Array<IWatchtowerSession & { sessionKey: Buffer }> {
		return this.watchtowerSessions.values().map((row) => ({
			...row.session,
			sessionKey: fromHex(row.sessionKeyHex)
		}));
	}

	setWatchtowerSessionProgress(
		sessionId: string,
		seqNum: number,
		lastApplied: number
	): void {
		const row = this.watchtowerSessions.get(sessionId);
		if (!row) return;
		this.watchtowerSessions.update(sessionId, {
			...row,
			session: { ...row.session, seqNum, lastApplied }
		});
	}

	deleteWatchtowerTower(towerUri: string): void {
		this.transaction(() => {
			for (const [sessionId, row] of this.watchtowerSessions.entries()) {
				if (row.session.towerUri === towerUri)
					this.watchtowerSessions.delete(sessionId);
			}
			for (const [id, update] of this.watchtowerUpdates.entries()) {
				if (update.towerUri === towerUri) this.watchtowerUpdates.delete(id);
			}
		});
	}

	addWatchtowerUpdate(update: IWatchtowerUpdate): number {
		const id = this.nextId++;
		this.watchtowerUpdates.put(
			id,
			{
				towerUri: update.towerUri,
				channelId: update.channelId,
				blobType: update.blobType,
				hint: update.hint,
				encryptedBlob: update.encryptedBlob,
				seqNum: update.seqNum,
				acked: !!update.acked,
				createdAt: update.createdAt
			},
			id
		);
		return id;
	}

	loadPendingWatchtowerUpdates(): Array<IWatchtowerUpdate & { id: number }> {
		return this.watchtowerUpdates
			.entries()
			.filter(([, update]) => !update.acked)
			.map(([id, update]) => ({ id, ...update }));
	}

	markWatchtowerUpdateAcked(id: number, seqNum: number): void {
		const update = this.watchtowerUpdates.get(id);
		if (update)
			this.watchtowerUpdates.update(id, { ...update, acked: true, seqNum });
	}

	// ─── Forwarding Events ───

	saveForwardingEvent(event: Omit<IForwardingEvent, 'id'>): void {
		const id = this.nextId++;
		this.transaction(() => {
			this.forwardingEvents.put(
				id,
				{
					settledAt: event.settledAt,
					inChannelId: event.inChannelId,
					outChannelId: event.outChannelId,
					inScid: event.inScid,
					outScid: event.outScid,
					amountInMsat: event.amountInMsat,
					amountOutMsat: event.amountOutMsat,
					feeMsat: event.feeMsat
				},
				id
			);
			pruneOldest(this.forwardingEvents, this.forwardingEventsMaxRows);
		});
	}

	listForwardingEvents(filter?: IForwardingEventFilter): IForwardingEvent[] {
		const limit =
			filter?.limit !== undefined && filter.limit > 0
				? filter.limit
				: DEFAULT_LIST_LIMIT;
		const offset =
			filter?.offset !== undefined && filter.offset > 0 ? filter.offset : 0;
		return this.forwardingEvents
			.entries()
			.filter(
				([, event]) =>
					(filter?.since === undefined || event.settledAt >= filter.since) &&
					(filter?.until === undefined || event.settledAt <= filter.until) &&
					(filter?.channelId === undefined ||
						event.inChannelId === filter.channelId ||
						event.outChannelId === filter.channelId)
			)
			.sort(([idA, a], [idB, b]) => b.settledAt - a.settledAt || idB - idA)
			.slice(offset, offset + limit)
			.map(([id, event]) => ({ id, ...event }));
	}

	getForwardingSummary(options?: { since?: number }): IForwardingSummary {
		let count = 0;
		let volumeOutMsat = 0n;
		let feesEarnedMsat = 0n;
		for (const event of this.forwardingEvents.values()) {
			if (options?.since !== undefined && event.settledAt < options.since)
				continue;
			count++;
			volumeOutMsat += event.amountOutMsat;
			feesEarnedMsat += event.feeMsat;
		}
		return { count, volumeOutMsat, feesEarnedMsat };
	}

	// ─── Action Log ───

	saveActionLog(entry: {
		category: string;
		action: string;
		timestamp: number;
		data: string;
	}): void {
		const id = this.nextId++;
		this.transaction(() => {
			this.actionLog.put(
				id,
				{
					category: entry.category,
					action: entry.action,
					timestamp: entry.timestamp,
					data: entry.data
				},
				id
			);
			pruneOldest(this.actionLog, ACTION_LOG_MAX_ROWS);
		});
	}

	loadActionLog(options?: {
		category?: string;
		since?: number;
		limit?: number;
	}): Array<{
		category: string;
		action: string;
		timestamp: number;
		data: string;
	}> {
		const limit =
			options?.limit !== undefined && options.limit > 0
				? options.limit
				: DEFAULT_LIST_LIMIT;
		return this.actionLog
			.entries()
			.filter(
				([, entry]) =>
					(!options?.category || entry.category === options.category) &&
					(options?.since === undefined || entry.timestamp >= options.since)
			)
			.sort(([idA, a], [idB, b]) => b.timestamp - a.timestamp || idB - idA)
			.slice(0, limit)
			.map(([, entry]) => ({ ...entry }));
	}
}

/** Delete the oldest rows (lowest ids) of an append-only table past `cap`. */
function pruneOldest<V>(table: MemoryTable<number, V>, cap: number): void {
	const excess = table.size - cap;
	if (cap < 0 || excess <= 0) return;
	for (const [id] of table.entries().slice(0, excess)) table.delete(id);
}

function decodeFrameHeader(row: IFrameRow): IStoredRecoveryFrameHeader {
	return {
		sequence: row.sequence,
		writerEpoch: row.writerEpoch,
		frameHash: fromHex(row.frameHashHex),
		previousFrameHash: fromHex(row.previousFrameHashHex)
	};
}

function decodeFrame(row: IFrameRow): IStoredRecoveryFrame {
	return {
		...decodeFrameHeader(row),
		ciphertext: fromHex(row.ciphertextHex),
		createdAt: row.createdAt
	};
}
