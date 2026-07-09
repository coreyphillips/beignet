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

	// ─── Channel Key Indices ───
	saveChannelKeyIndex(channelId: string, channelIndex: number): void;
	loadChannelKeyIndex(channelId: string): number | null;
	loadNextChannelIndex(): number;

	// ─── Metadata (key/value) ───
	saveMetadata(key: string, value: string): void;
	loadMetadata(key: string): string | null;

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

export interface IInvoiceInfo {
	paymentHash: string;
	bolt11: string;
	amountMsat?: bigint;
	description?: string;
	expiry: number;
	createdAt: number;
	/** Hold invoice — matching HTLCs are parked until settle/cancel. */
	hold?: boolean;
}
