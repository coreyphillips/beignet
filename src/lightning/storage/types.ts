/**
 * Storage backend interface for Lightning node persistence.
 *
 * All state changes are written synchronously so the DB always
 * reflects the latest in-memory state.
 */

import { IChannelState } from '../channel/channel-state';
import { IPaymentInfo } from '../node/types';
import { IChainMonitorState } from '../chain/chain-monitor';
import { IGraphChannel, IGraphNode } from '../gossip/types';
import { IWatchtowerSession, IWatchtowerUpdate } from '../watchtower/types';

/**
 * Abstract storage backend. SqliteStorage implements this.
 */
export interface IStorageBackend {
	open(): void;
	close(): void;

	// ─── Channels ───
	saveChannel(id: string, state: IChannelState, peerPubkey: string): void;
	loadChannel(id: string): { state: IChannelState; peerPubkey: string } | null;
	loadAllChannels(): Array<{
		channelId: string;
		state: IChannelState;
		peerPubkey: string;
	}>;
	deleteChannel(id: string): void;

	// ─── Payments ───
	savePayment(paymentHash: string, payment: IPaymentInfo): void;
	loadPayment(paymentHash: string): IPaymentInfo | null;
	loadAllPayments(): Array<{ paymentHash: string; payment: IPaymentInfo }>;
	deletePayment(paymentHash: string): void;

	// ─── Preimages ───
	savePreimage(paymentHash: string, preimage: Buffer): void;
	loadPreimage(paymentHash: string): Buffer | null;
	loadAllPreimages(): Array<{ paymentHash: string; preimage: Buffer }>;
	/**
	 * Delete a stored preimage. Used by the issued-invoice sweep for expired,
	 * never-paid BOLT 12 invoices; a settled payment's preimage is never
	 * deleted this way. REQUIRED (not optional): a backend that skipped it
	 * would leave an orphaned preimage row that a restart restores without
	 * the invoice's bolt12 marker or expected path_id, making the hash
	 * claimable outside the fail-closed path-id check.
	 */
	deletePreimage(paymentHash: string): void;

	// ─── SCID Mappings ───
	saveScidMapping(scidHex: string, channelId: Buffer): void;
	loadAllScidMappings(): Array<{ scidHex: string; channelId: Buffer }>;

	// ─── HTLC Payment Map ───
	saveHtlcPaymentMapping(key: string, paymentHashHex: string): void;
	loadAllHtlcPaymentMappings(): Array<{ key: string; paymentHashHex: string }>;
	deleteHtlcPaymentMapping(key: string): void;

	// ─── Forwarded HTLCs ───
	saveForwardedHtlc(
		outKey: string,
		inChannelId: Buffer,
		inHtlcId: bigint
	): void;
	loadAllForwardedHtlcs(): Array<{
		outKey: string;
		inChannelId: Buffer;
		inHtlcId: bigint;
	}>;
	deleteForwardedHtlc(outKey: string): void;

	// ─── Chain Monitors ───
	saveChainMonitor(channelId: string, state: IChainMonitorState): void;
	loadChainMonitor(channelId: string): IChainMonitorState | null;
	loadAllChainMonitors(): Array<{
		channelId: string;
		state: IChainMonitorState;
	}>;

	// ─── Gossip ───
	saveGossipChannel(scidHex: string, channel: IGraphChannel): void;
	loadAllGossipChannels(): IGraphChannel[];
	saveGossipNode(nodeIdHex: string, node: IGraphNode): void;
	loadAllGossipNodes(): IGraphNode[];

	// ─── Payment Secrets ───
	savePaymentSecret(paymentHashHex: string, secret: Buffer): void;
	loadAllPaymentSecrets(): Array<{ paymentHashHex: string; secret: Buffer }>;
	deletePaymentSecret(paymentHashHex: string): void;

	/**
	 * Persist the expected blinded-path path_id of a BOLT 12 invoice WE issued,
	 * the receive-side authentication analogue of a BOLT 11 payment secret.
	 * Written in the same transaction as the invoice's preimage so
	 * authentication state can never be lost while the payment stays claimable.
	 */
	saveInvoicePathId?(paymentHashHex: string, pathId: Buffer): void;
	loadAllInvoicePathIds?(): Array<{ paymentHashHex: string; pathId: Buffer }>;
	/**
	 * REQUIRED even though save/load are optional: a backend that persisted
	 * path_ids but could not delete them would accumulate rows forever, the
	 * amplification the issued-invoice sweep exists to stop. Backends that do
	 * not persist path_ids implement this as a no-op.
	 */
	deleteInvoicePathId(paymentHashHex: string): void;

	// ─── Invoices ───
	saveInvoice(paymentHashHex: string, invoice: IInvoiceInfo): void;
	loadAllInvoices(): Array<{ paymentHashHex: string; invoice: IInvoiceInfo }>;
	deleteInvoice(paymentHashHex: string): void;

	// ─── Mission Control ───
	saveMissionControl(json: string): void;
	loadMissionControl(): string | null;

	// ─── Peer Addresses ───
	savePeerAddress(pubkey: string, host: string, port: number): void;
	loadAllPeerAddresses(): Array<{ pubkey: string; host: string; port: number }>;
	deletePeerAddress(pubkey: string): void;

	// ─── Announced Peer Addresses (optional) ───
	// Reconnect fallbacks from a channel peer's signature-verified
	// node_announcement, kept separate from peer_addresses: those hold
	// last-known-good addresses proven by a successful outbound dial, while
	// these are unproven claims that the peer's next announcement (tracked by
	// its timestamp) supersedes — including down to an empty list.
	/** Persist the newest announced address set for a channel peer. */
	saveAnnouncedPeerAddresses?(
		pubkey: string,
		timestamp: number,
		addresses: Array<{ host: string; port: number }>
	): void;
	/** Load every persisted announced address set. */
	loadAllAnnouncedPeerAddresses?(): Array<{
		pubkey: string;
		timestamp: number;
		addresses: Array<{ host: string; port: number }>;
	}>;

	// ─── Channel Key Indices ───
	saveChannelKeyIndex(channelId: string, channelIndex: number): void;
	loadChannelKeyIndex(channelId: string): number | null;
	loadNextChannelIndex(): number;

	// ─── Metadata (key/value) ───
	saveMetadata(key: string, value: string): void;
	loadMetadata(key: string): string | null;

	// ─── On-chain Wallet Data (optional, key/value) ───
	/** Persist one on-chain wallet data value (JSON string) under its key. */
	saveWalletData?(key: string, value: string): void;
	/** Load one on-chain wallet data value, or null when absent. */
	loadWalletData?(key: string): string | null;

	// ─── Transaction wrapper ───
	transaction<T>(fn: () => T): T;

	// ─── WAL Checkpoint (optional) ───
	/** Checkpoint the WAL file, flushing pending writes to the main database. */
	checkpoint?(): void;

	// ─── HTLC Shared Secrets ───
	/** Save an HTLC shared secret for failure decryption. */
	saveHtlcSharedSecret(key: string, secret: Buffer): void;
	/** Delete an HTLC shared secret after cleanup. */
	deleteHtlcSharedSecret(key: string): void;
	/** Load all persisted HTLC shared secrets. */
	loadAllHtlcSharedSecrets(): Array<{ key: string; secret: Buffer }>;

	// ─── Gossip Cleanup (optional) ───
	/** Delete a gossip channel by SCID hex. Used during graph pruning. */
	deleteGossipChannel?(scidHex: string): void;

	// ─── Channel Routing Policies (optional) ───
	/** Save a per-channel routing-policy override (msat fields as strings). */
	saveChannelPolicy?(channelId: string, policy: IPersistedChannelPolicy): void;
	/** Load all persisted routing-policy overrides. */
	loadAllChannelPolicies?(): Array<{
		channelId: string;
		policy: IPersistedChannelPolicy;
	}>;
	/** Delete a per-channel routing-policy override. */
	deleteChannelPolicy?(channelId: string): void;

	// ─── Peer Storage Blobs (optional, BOLT 1 option_provide_storage) ───
	/** Persist the latest peer_storage blob for a peer (one blob per peer). */
	savePeerStorageBlob?(
		peerPubkey: string,
		blob: Buffer,
		receivedAt: number
	): void;
	/** Load the stored peer_storage blob for a peer. */
	loadPeerStorageBlob?(
		peerPubkey: string
	): { blob: Buffer; receivedAt: number } | null;
	/** Delete the stored peer_storage blob for a peer. */
	deletePeerStorageBlob?(peerPubkey: string): void;

	// ─── Forwarding Events (optional, settled-forward ledger) ───
	/** Persist one settled forward (both legs fulfilled). */
	saveForwardingEvent?(event: Omit<IForwardingEvent, 'id'>): void;
	/** List settled forwards, newest first. */
	listForwardingEvents?(filter?: IForwardingEventFilter): IForwardingEvent[];
	/** Aggregate totals over settled forwards. */
	getForwardingSummary?(options?: { since?: number }): IForwardingSummary;

	// ─── Action Log (optional) ───
	/** Save a structured log entry. Capped at maxRows (default 10000). */
	saveActionLog?(entry: {
		category: string;
		action: string;
		timestamp: number;
		data: string;
	}): void;
	/** Load action log entries with optional filters. */
	loadActionLog?(options?: {
		category?: string;
		since?: number;
		limit?: number;
	}): Array<{
		category: string;
		action: string;
		timestamp: number;
		data: string;
	}>;

	// ─── Watchtower (optional, LND altruist client) ───
	/** Persist a negotiated tower session plus its per-session Noise key. */
	saveWatchtowerSession?(session: IWatchtowerSession, sessionKey: Buffer): void;
	/** Load all persisted tower sessions with their session keys. */
	loadWatchtowerSessions?(): Array<IWatchtowerSession & { sessionKey: Buffer }>;
	/** Advance a session's shipped/acked sequence counters. */
	setWatchtowerSessionProgress?(
		sessionId: string,
		seqNum: number,
		lastApplied: number
	): void;
	/** Drop all sessions + queued updates for a removed tower. */
	deleteWatchtowerTower?(towerUri: string): void;
	/** Queue an un-acked justice update; returns its row id. */
	addWatchtowerUpdate?(update: IWatchtowerUpdate): number;
	/** Load the un-acked backlog (oldest first). */
	loadPendingWatchtowerUpdates?(): Array<IWatchtowerUpdate & { id: number }>;
	/** Mark a queued update acked at the given sequence number. */
	markWatchtowerUpdateAcked?(id: number, seqNum: number): void;

	// ─── Recovery Outbox (optional, docs/RECOVERY-PROTOCOL.md 5.2) ───
	// The transactional outbox: a row commits in the SAME transaction as the
	// state that makes its message necessary, and the socket write happens only
	// after that commit. Optional rather than required because a backend
	// without it degrades to reconstructing retransmissions from channel state,
	// which is exactly the pre-outbox behavior; the atomicity fixes in
	// RecoveryManager hold either way. Contrast deletePreimage, which is
	// required because its absence would leave a claimable hash behind.
	/** Persist one outbound message; returns the new row id. */
	saveOutboxMessage?(message: IRecoveryOutboxMessage): number;
	/** Load retained rows, oldest first, optionally for one channel. */
	loadOutboxMessages?(channelId?: string): IRecoveryOutboxStoredMessage[];
	/**
	 * Count a channel's retained rows. Kept separate from loadOutboxMessages
	 * so the per-channel row cap can be enforced without decrypting every
	 * retained wire message just to take the length of the result.
	 */
	countOutboxMessages?(channelId: string): number;
	/** Advance one row's disposition (e.g. after the socket write). */
	setOutboxDisposition?(
		id: number,
		disposition: 'pending_send' | 'sent_unacked' | 'superseded'
	): void;
	/**
	 * Delete a channel's rows, optionally only those of the given message
	 * types. Used when reestablish proves the peer already holds them.
	 */
	deleteOutboxMessages?(channelId: string, messageTypes?: number[]): void;
	/** Keep only the newest `keepNewest` rows for a channel. */
	pruneOutboxMessages?(channelId: string, keepNewest: number): void;

	// ─── Recovery Journal (optional, docs/RECOVERY-PROTOCOL.md 5.3) ───
	// Append-only hash-chained frames plus the journal's own metadata (tip,
	// epoch, last snapshot). Rows are written INSIDE the same transaction as
	// the transition they record; the ciphertext arrives already
	// AEAD-encrypted with the per-epoch frame key, so it is deliberately NOT
	// in ENCRYPTED_COLUMNS (a second storage-key layer would add nothing and
	// break the AAD binding checks on load).
	/** Append one encrypted frame. Throws if the sequence already exists. */
	saveRecoveryFrame?(frame: IStoredRecoveryFrame): void;
	/** Load frames in sequence order, optionally after a given sequence. */
	loadRecoveryFrames?(afterSequence?: number): IStoredRecoveryFrame[];
	/** Compaction: drop every frame with sequence below the given one. */
	deleteRecoveryFramesBelow?(sequence: number): void;
	/** Stamp outbox rows with the journal frame that carried their insert. */
	setOutboxFrameSequence?(ids: number[], frameSequence: number): void;
	/** Read one journal metadata value (tip hash, epoch, snapshot marker). */
	getRecoveryMeta?(key: string): string | null;
	/** Write one journal metadata value. */
	setRecoveryMeta?(key: string, value: string): void;

	// ─── BOLT 12 Offers (optional) ───
	/**
	 * Persist a created offer. The bech32m encoding is the authoritative
	 * artifact (offer, TLV bytes and offer id are all re-derived from it on
	 * load); pathId is the secret bound into the offer's blinded paths, null
	 * for offers without one.
	 */
	saveOffer?(
		offerIdHex: string,
		encoded: string,
		pathId: Buffer | null,
		createdAt: number,
		asyncHold?: boolean
	): void;
	/** Load every persisted offer. */
	loadAllOffers?(): Array<{
		offerIdHex: string;
		encoded: string;
		pathId: Buffer | null;
		createdAt: number;
		asyncHold?: boolean;
	}>;
	/** Delete a persisted offer. */
	deleteOffer?(offerIdHex: string): void;
}

/**
 * Lifecycle of a recovery outbox row.
 *
 * `pending_send`   committed, not yet written to the socket
 * `sent_unacked`   written to the socket, peer has not proven receipt
 * `superseded`     the reestablish exchange proved the peer holds it
 */
export type RecoveryOutboxDisposition =
	| 'pending_send'
	| 'sent_unacked'
	| 'superseded';

/**
 * An outbound wire message whose durability is tied to the state that makes it
 * necessary (docs/RECOVERY-PROTOCOL.md 5.2). Defined here, in the layer that
 * owns the row, and re-exported from src/lightning/recovery under its
 * spec name.
 *
 * `wireMessage` holds the EXACT encoded bytes rather than the material needed
 * to re-encode them. That is load-bearing: a retransmitted commitment_signed
 * must be byte-identical, because re-signing would bind a fresh MuSig2 secret
 * nonce to material the peer may already hold under the old one.
 */
/**
 * One recovery journal frame as stored (docs/RECOVERY-PROTOCOL.md 5.3).
 * Sequence and epoch are plain numbers at this layer (SQLite INTEGER);
 * the journal converts to bigint at its boundary.
 */
export interface IStoredRecoveryFrame {
	sequence: number;
	writerEpoch: number;
	/** SHA-256 of the plaintext frame bytes. */
	frameHash: Buffer;
	previousFrameHash: Buffer;
	/** AES-256-GCM: iv || authTag || ciphertext, keyed per epoch. */
	ciphertext: Buffer;
	createdAt: number;
}

export interface IRecoveryOutboxMessage {
	/** Peer node id, hex. */
	peerId: string;
	/** Channel this message belongs to, hex. Absent for node-level messages. */
	channelId?: string;
	/** BOLT message type. */
	messageType: number;
	/** Exact encoded wire bytes, message type prefix excluded. */
	wireMessage: Buffer;
	disposition: RecoveryOutboxDisposition;
}

/** A persisted outbox row: the message plus its storage identity. */
export interface IRecoveryOutboxStoredMessage extends IRecoveryOutboxMessage {
	id: number;
	/** Journal frame that carried this row. Always null until Phase 2. */
	frameSequence: number | null;
	/** ms since epoch, for diagnostics and bounded-retention pruning. */
	createdAt: number;
}

/**
 * JSON-safe shape of a per-channel routing-policy override. Msat fields are
 * decimal strings because they are bigint in the node layer.
 */
export interface IPersistedChannelPolicy {
	feeBaseMsat?: number;
	feeProportionalMillionths?: number;
	cltvExpiryDelta?: number;
	htlcMinimumMsat?: string;
	htlcMaximumMsat?: string;
}

/**
 * One settled forward: an HTLC we relayed whose downstream fulfill completed
 * both legs. Msat fields are bigint in the library (strings in JSON surfaces).
 */
export interface IForwardingEvent {
	id: number;
	/** When the downstream fulfill settled the forward (ms since epoch). */
	settledAt: number;
	inChannelId: string;
	outChannelId: string;
	inScid?: string;
	outScid?: string;
	amountInMsat: bigint;
	amountOutMsat: bigint;
	/** amountInMsat - amountOutMsat: the fee we earned. */
	feeMsat: bigint;
}

export interface IForwardingEventFilter {
	/** Only events with settledAt >= since (ms). */
	since?: number;
	/** Only events with settledAt <= until (ms). */
	until?: number;
	limit?: number;
	offset?: number;
	/** Match events where this channel was the inbound OR outbound leg. */
	channelId?: string;
}

export interface IForwardingSummary {
	count: number;
	volumeOutMsat: bigint;
	feesEarnedMsat: bigint;
}

export interface IInvoiceInfo {
	paymentHash: string;
	bolt11: string;
	amountMsat?: bigint;
	description?: string;
	expiry: number;
	createdAt: number;
	/** Hold invoice — matching HTLCs are parked until settle/cancel. */
	hold?: boolean;
	/**
	 * BOLT 12-issued invoice (created for an offer's invoice_request). The
	 * receive path authenticates these by blinded-path path_id, never by
	 * payment secret, and FAILS CLOSED when the expected path_id is missing.
	 */
	bolt12?: boolean;
	/**
	 * Hold invoice cancelled (ms timestamp). Kept so a restart does not
	 * re-arm parking for a hash the operator already cancelled.
	 */
	cancelledAt?: number;
}
