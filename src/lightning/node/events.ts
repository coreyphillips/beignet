import type { IReceiverGrant } from '../async-payments/receiver-grant';
import type { IHeldForwardRecord } from '../async-payments/held-forward-ledger';
import type { IHeldForwardNotice } from '../async-payments/types';
import type { ISweepUneconomicChainAction } from '../chain/types';
import type { FforState, IFforEpochRecord } from '../ffor/types';
import type { FforIssuerEvents } from '../ffor/issuer-service';
import type { FforWitnessEvents } from '../ffor/witness-service';
import type { JitReceiveEvents } from '../liquidity/jit-receive';
import type { IBolt12Invoice, IOffer } from '../offer/types';
import type { IOnionMessagePayload } from '../onion-message/types';
import type { GuardianState } from '../recovery/guardian-wire';
import type { ISwapEvent } from '../swaps/engine-common';
import type { IPeerDisconnectInfo } from '../transport/peer-manager';
import type {
	IGraphRestoreStats,
	IHoldCancelledEvent,
	IHoldInvoiceStateEvent,
	ILightningError,
	IPaymentHtlcResolvedEvent,
	IPaymentInfo,
	IPaymentPreimageEvent,
	IStructuredLog
} from './types';

/**
 * Every code `node:error` carries. Raised by LightningNode, except
 * LISTEN_FAILED, which BeignetNode raises through the node's own funnel.
 */
export type NodeErrorCode =
	| 'AUTO_FUNDING_FAILED'
	| 'AUTO_RECONNECT_FAILED'
	| 'BARRIER_DISPATCH_FAILED'
	| 'BLOCK_WORK_FAILED'
	| 'BOLT12_INVOICE_ERROR'
	| 'BROADCAST_FAILED'
	| 'BROADCAST_PERMANENT_FAILURE'
	| 'CHAIN_RESTORE_WATCH_FAILED'
	| 'CHAIN_WATCHER_ERROR'
	| 'CHAIN_WATCHER_START_FAILED'
	| 'CHANNEL_ERROR'
	| 'CHANNEL_FAILED_FORCE_CLOSED'
	| 'CHANNEL_FAILED_FORCE_CLOSE_FAILED'
	| 'CLOSE_CHANNEL_FAILED'
	| 'DURABILITY_BARRIER_TIMEOUT'
	| 'ERRORED_TIMEOUT_FORCE_CLOSED'
	| 'FORCE_CLOSE_FAILED'
	| 'FORCE_CLOSE_REVOKED'
	| 'FORWARD_TIMEOUT_FORCE_CLOSE'
	| 'FUNDING_BROADCAST_FAILED'
	| 'FUNDING_MISSING'
	| 'GRAPH_RESTORE_FAILED'
	| 'HTLC_CLAIM_FORCE_CLOSE'
	| 'HTLC_DEADLINE_HELD'
	| 'HTLC_EXPIRY_FORCE_CLOSE'
	| 'LISTEN_FAILED'
	| 'MESSAGE_TOO_LARGE'
	| 'NO_ROUTING_HINTS'
	| 'ONION_MESSAGE_ERROR'
	| 'ONION_PROCESSING_FAILED'
	| 'PERSISTENCE_ERROR'
	| 'PRESPLICE_WATCH_FAILED'
	| 'PROVIDE_EXTERNAL_WITNESS_FAILED'
	| 'RBF_OPEN_FAILED'
	| 'RECOVERY_WATCH_FAILED'
	| 'REESTABLISH_SECRET_MISSING'
	| 'REESTABLISH_TIMEOUT_FORCE_CLOSED'
	| 'SEND_TX_SIGNATURES_FAILED'
	| 'SPLICE_BROADCAST_REFUSED'
	| 'SPLICE_INPUT_CONFLICT'
	| 'SPLICE_IN_FAILED'
	| 'SPLICE_OUT_FAILED'
	| 'STARTUP_RECONNECT_FAILED'
	| 'STARTUP_REPAIR_COMPLETION_FAILED'
	| 'STARTUP_REPAIR_UNRECEIPTED'
	| 'STUCK_CHANNEL'
	| 'STUCK_CHANNEL_FORCE_CLOSED'
	| 'UPDATE_FEE_FAILED'
	| 'WAL_CHECKPOINT_FAILED'
	| 'WATCH_OUTPUT_FAILED';

/**
 * Every event LightningNode emits, with its listener's signature. The Events
 * Reference table in src/lightning/README.md is generated from this map
 * (`npm run docs:tables`), so the description of each event lives here.
 *
 * Channel-scoped events carry an object with a 32-byte `channelId` Buffer;
 * `announcement:ready`, `channel:aborted` and `sweep:uneconomic` pass it as
 * a bare first argument instead. BeignetNode relays most of these with hex
 * strings in place of Buffers and decimal strings in place of bigints.
 */
export interface LightningNodeEvents
	extends JitReceiveEvents,
		FforWitnessEvents,
		FforIssuerEvents {
	// ─── Payments ───

	/** Incoming payment settled. */
	'payment:received': (payment: IPaymentInfo) => void;
	/** Outgoing payment completed. */
	'payment:sent': (payment: IPaymentInfo) => void;
	/** Outgoing payment failed. */
	'payment:failed': (payment: IPaymentInfo) => void;
	/** One offered HTLC of an outgoing payment reached a terminal state (fulfilled, irrevocably failed, or resolved on chain). */
	'payment:htlc-resolved': (event: IPaymentHtlcResolvedEvent) => void;
	/** An outgoing payment's preimage became known, from update_fulfill_htlc or an on-chain claim, whatever the record's status was. */
	'payment:preimage': (event: IPaymentPreimageEvent) => void;
	/** Preimage recorded (forwarding and settlement chokepoint). */
	'preimage:learned': (paymentHash: Buffer, preimage: Buffer) => void;
	/** Invoice this node issued was settled. */
	'invoice:settled': (data: {
		paymentHash: Buffer;
		bolt11: string;
		amountMsat: bigint;
	}) => void;

	// ─── Hold invoices ───

	/** HTLC parked by a hold invoice (one part; read `getHeldInvoiceSnapshot` for the committed set). */
	'htlc:held': (data: { paymentHash: Buffer; amountMsat: bigint }) => void;
	/** A part joined a hold invoice's parked set, with the set's running total. A re-park on reestablish does not fire. Acceptance can be a partial MPP payment: compare `heldAmountMsat` with the full expected amount before committing funds. */
	'hold:accepted': (event: IHoldInvoiceStateEvent) => void;
	/** A hold invoice's preimage was revealed and every parked part fulfilled. */
	'hold:settled': (event: IHoldInvoiceStateEvent) => void;
	/** A hold invoice was cancelled by the CLTV sweeper (`expiry-scan`) or the API; every parked part was failed back. */
	'hold:cancelled': (event: IHoldCancelledEvent) => void;

	// ─── Async payments ───

	/** Receiver side: a wake message says a sender is waiting. Reconnect to the LSP so it can release the held HTLC. */
	'payment:async-wake': (paymentHash: Buffer | undefined) => void;
	/** Receiver side: the LSP reported forwards it holds for this node. With `autoReleaseHeldForwards` off, release them with `sendAsyncRelease`. */
	'payment:held-notice': (data: {
		lspNodeId: Buffer;
		notice: IHeldForwardNotice;
	}) => void;
	/** Receiver side: an LSP granted this node an async receive registration. */
	'async-receive:granted': (grant: IReceiverGrant) => void;
	/** LSP side: a forward to an offline receiver was parked until the receiver releases it or `cutoffHeight` passes. */
	'htlc:held-forward': (data: {
		holdId: Buffer;
		paymentHash: Buffer;
		amountMsat: bigint;
		cutoffHeight: number;
	}) => void;
	/** LSP side: a parked forward was released to the receiver. */
	'htlc:held-forward-released': (record: IHeldForwardRecord) => void;
	/** LSP side: a parked forward was failed back upstream. */
	'htlc:held-forward-failed': (record: IHeldForwardRecord) => void;

	// ─── Channels ───

	/** Funding flow started. */
	'channel:opening': (data: { channelId: Buffer; fundingTxid: Buffer }) => void;
	/** Channel reached NORMAL state. */
	'channel:ready': (data: { channelId: Buffer }) => void;
	/** A caller-driven v2 open owes its tx_signatures and only the embedder holds the witnesses: answer with `sendTxSignatures`. `externalInputIndices` names the inputs a third party owes, answered with `provideV2ExternalWitness`. */
	'channel:txsigs-needed': (data: {
		channelId: Buffer;
		fundingTxid: Buffer;
		fundingOutputIndex: number;
		inputIndices: number[];
		externalInputIndices?: number[];
	}) => void;
	/** A splice is withholding its tx_signatures on external inputs whose witnesses a third party owes: collect them and answer with `provideSpliceExternalWitness`. Re-armed per connection cycle. */
	'channel:splice-txsigs-needed': (data: {
		channelId: Buffer;
		spliceTxid: Buffer;
		newFundingOutputIndex: number;
		externalInputIndices: number[];
	}) => void;
	/** A cooperative close started. */
	'channel:pending-close': (data: {
		channelId: Buffer;
		initiator: 'local' | 'remote';
	}) => void;
	/** A force close started: this node broadcast its commitment (`local`) or the peer's appeared on chain (`remote`). */
	'channel:force-closing': (data: {
		channelId: Buffer;
		initiator: 'local' | 'remote';
	}) => void;
	/** Channel closed. */
	'channel:closed': (data: { channelId: Buffer }) => void;
	/** All on-chain outputs of the close resolved. */
	'channel:resolved': (data: { channelId: Buffer }) => void;
	/** A negotiated but unfunded open was torn down. */
	'channel:aborted': (temporaryChannelId: Buffer, reason: string) => void;
	/** Unfunded or abandoned channel discarded. */
	'channel:voided': (data: { channelId: Buffer }) => void;
	/** Channel eligible for announcement. */
	'announcement:ready': (channelId: Buffer) => void;

	// ─── Splices ───

	/** splice_locked exchanged both ways: the channel runs on the new funding. */
	'splice:complete': (data: {
		channelId: Buffer;
		fundingTxid: Buffer | null | undefined;
	}) => void;
	/** A splice negotiation was unwound by tx_abort before its point of no return. */
	'splice:aborted': (data: { channelId: Buffer; reason: string }) => void;
	/** An input of an in-flight splice that this node does not vouch for (a depth-locked splice carrying a stranger's coin, issue #760) was spent by another transaction, confirmed six deep while the splice is not on chain: the splice can never confirm. The node records it durably, raises `node:error` code `SPLICE_INPUT_CONFLICT`, and asks the peer to verify and revert; the request is re-sent every block and on reconnect until agreed. */
	'splice:conflicted': (data: {
		channelId: Buffer;
		spliceTxid: string;
		conflictTxid: string;
		inputIndex: number;
		height: number;
	}) => void;
	/** A conflicted splice was unwound by agreement: both sides verified the conflict on their own chain view and returned to the pre-splice funding, which both still hold valid commitments for. The channel is NORMAL on the old outpoint, its watch re-armed; a `spliceInAndWait` on that splice rejects, and a direct-funding request behind it is failed (`direct-funding:offer:failed`, "the payer spent the offered coin elsewhere"). */
	'splice:reverted': (data: {
		channelId: Buffer;
		spliceTxid: string;
		conflictTxid: string;
	}) => void;

	// ─── HTLCs and forwarding ───

	/** An HTLC was relayed to the next hop. */
	'htlc:forward': (
		inChannelId: Buffer,
		outChannelId: Buffer,
		amountMsat: bigint,
		paymentHash: Buffer
	) => void;
	/** A forwarded HTLC settled: the fee was earned. */
	'htlc:forwarded': (data: {
		inChannelId: Buffer;
		outChannelId: Buffer;
		amountInMsat: bigint;
		amountOutMsat: bigint;
		feeMsat: bigint;
	}) => void;
	/** A forwarded HTLC failed downstream. */
	'htlc:forward-failed': (data: {
		inChannelId: Buffer;
		outChannelId: Buffer;
	}) => void;
	/** The peer fulfilled an HTLC this node offered: a part of its own payment or the outgoing leg of a forward. */
	'htlc:fulfilled': (data: { channelId: Buffer; htlcId: bigint }) => void;
	/** The peer failed an HTLC this node offered: a part of its own payment or the outgoing leg of a forward. */
	'htlc:failed': (data: { channelId: Buffer; htlcId: bigint }) => void;

	// ─── Chain ───

	/** Transaction to broadcast on chain. */
	'broadcast:tx': (tx: Buffer) => void;
	/** An on-chain claim was declined because it cannot pay its own fee (`reason: 'skipped'`), or a competing spend path opened while it stayed unclaimed (`reason: 'contested'`). Retries continue in both cases, until the outpoint is spent. */
	'sweep:uneconomic': (
		channelId: Buffer,
		action: ISweepUneconomicChainAction
	) => void;
	/** The per-block work for this height has run. */
	'block:processed': (height: number) => void;

	// ─── Peers and messages ───

	/** Message to send to a peer (event-transport mode). */
	'message:outbound': (
		peerPubkey: string,
		type: number,
		payload: Buffer
	) => void;
	/** Peer connected (networking mode). */
	'peer:connect': (pubkey: string) => void;
	/** Peer disconnected (networking mode). `info` says who closed the connection and why, when known. */
	'peer:disconnect': (pubkey: string, info?: IPeerDisconnectInfo) => void;
	/** The node needs this peer's connection severed but holds no socket for it (event-transport mode, or an unconnected peer): the host must close its transport. The protocol side (channels marked for reestablish) is already applied; reconnect and reestablish as usual. */
	'peer:disconnect-requested': (pubkey: string) => void;
	/** Peer error (networking mode). */
	'peer:error': (pubkey: string, error: Error) => void;
	/** A beignet custom message (type 44069) arrived from a peer. */
	'custom-message': (message: {
		peerPubkey: string;
		version: number;
		subtype: number;
		payload: Buffer;
	}) => void;
	/** A peer returned the blob it stores for this node (BOLT 1 peer storage), unpadded. */
	'peer_storage:retrieved': (peerPubkey: string, blob: Buffer) => void;

	// ─── BOLT 12 and onion messages ───

	/** Onion message received (type 513). */
	'onion:received': (payload: IOnionMessagePayload) => void;
	/** BOLT 12 offer created. */
	'offer:created': (offer: IOffer) => void;
	/** BOLT 12 invoice received. */
	'bolt12:invoice:received': (invoice: IBolt12Invoice) => void;
	/** BOLT 12 invoice issued to a payer. */
	'bolt12:invoice:issued': (invoice: IBolt12Invoice) => void;

	// ─── Recovery ───

	/** The recovery journal is durable through this frame sequence. */
	'recovery:durable': (through: bigint) => void;
	/** A newer writer epoch owns this recovery namespace: this device must not send another channel message. Carries the superseding writer's guardian state when the barrier saw one, null or undefined otherwise (as after the node rotated away from its guardian set). */
	'recovery:fenced': (supersededBy: GuardianState | null | undefined) => void;
	/** The journal was compacted past frames a guardian had not yet received, so that guardian cannot be backfilled. */
	'recovery:backfill-lost': (detail: string) => void;
	/** A peer's channel_reestablish for a channel this node has no record of was parked instead of failed, because the node may still be an incomplete restore target (issue #462). Apply a Recovery Capsule before `expiresAt` or the peer force-closes. */
	'recovery:reestablish-held': (
		peerPubkey: string,
		channelIdHex: string,
		expiresAt: number
	) => void;

	// ─── Gossip ───

	/** A deferred restore of the stored network map (`deferGraphRestore`) ended; the same figures `getGraphRestoreStats()` returns. */
	'graph:restored': (stats: IGraphRestoreStats) => void;

	// ─── FFOR offline receive ───

	/** An FFOR epoch's committed state changed. */
	'ffor:state': (data: {
		channelId: Buffer;
		state: FforState;
		record: IFforEpochRecord;
	}) => void;
	/** A peer contradicted an ACTIVE FFOR epoch: enforce it on chain (`fforEnforce`). */
	'ffor:enforce': (data: {
		channelId: Buffer;
		record: IFforEpochRecord;
	}) => void;
	/** Settlement peer side: a delegated slot settled upstream. */
	'ffor:settled': (data: {
		channelId: Buffer;
		k: number;
		paymentHash: Buffer;
		upstreamChannelId: Buffer;
		upstreamHtlcId: bigint;
	}) => void;
	/** Settlement peer side: a delegated slot's payment was failed back upstream. */
	'ffor:delegated-failed': (data: {
		channelId: Buffer;
		k: number;
		paymentHash: Buffer;
		upstreamChannelId: Buffer;
		upstreamHtlcId: bigint;
		reason: string;
	}) => void;
	/** A concurrent-profile slot reached its terminal outcome. JSON-safe: hex and decimal strings. */
	'ffor:slot-resolved': (data: {
		channelId: string;
		epochId: string;
		k: number;
		paymentHash: string;
		amountMsat: string;
		outcome: 'fulfilled' | 'cancelled';
	}) => void;
	/** A witness record fetched for a slot failed verification. */
	'ffor:witness-audit': (data: {
		channelId: Buffer;
		witnessNodeId: Buffer;
		k: number;
		reason: string | undefined;
	}) => void;

	// ─── Direct funding, receiver side (the receiver's offer:* events) ───

	/** A payer's offer was accepted. `paired` says whether it came from a peer in the trusted set, which decides zero-conf and the splice path; `resumed` marks one picked up again after a restart. */
	'direct-funding:offer:accepted': (data: {
		offerId: string;
		paired: boolean;
		resumed?: boolean;
	}) => void;
	/** A payer's offer was declined with the reason. */
	'direct-funding:offer:declined': (data: {
		offerId: string;
		reason: string;
	}) => void;
	/** An accepted offer failed with the reason. */
	'direct-funding:offer:failed': (data: {
		offerId: string;
		reason: string;
	}) => void;
	/** An offer completed with the funding out. */
	'direct-funding:offer:completed': (data: { offerId: string }) => void;

	// ─── Swap provider (src/lightning/swaps/README.md); submarine payloads carry `direction` ───

	/** A swap row was created: for a reverse swap with its hold invoice minted, for a submarine swap once its terms verified. */
	'swap:created': (event: ISwapEvent) => void;
	/** Reverse swap: the complete committed payment set is held by the hold invoice; a partial MPP set never funds. */
	'swap:held': (event: ISwapEvent) => void;
	/** Reverse swap: the funding transaction was built, verified and recorded, and is being broadcast (`fundingTxid`, `fundingVout`). */
	'swap:funding': (event: ISwapEvent) => void;
	/** The swap's funding confirmed to the configured depth (`fundingHeight` on a reverse swap). */
	'swap:funded': (event: ISwapEvent) => void;
	/** Reverse swap: a claim spend with a verified preimage was seen at any depth (`claimTxid`); the preimage is recorded before the hold settles. */
	'swap:claimed': (event: ISwapEvent) => void;
	/** Reverse swap: the hold was released with the claimed preimage. */
	'swap:settled': (event: ISwapEvent) => void;
	/** Reverse swap: no claim by the refund height, so a refund to the node's sweep destination was broadcast. */
	'swap:refund-broadcast': (event: ISwapEvent) => void;
	/** Reverse swap: the refund confirmed, and only then the hold is cancelled. */
	'swap:refunded': (event: ISwapEvent) => void;
	/** Reverse swap: the hold invoice was cancelled. */
	'swap:hold-cancelled': (event: ISwapEvent) => void;
	/** Funds are at risk (`reason`, `previousState`): on a reverse swap the hold was cancelled while coins were or may be on chain; on a submarine swap a payment is out while the contract is not claimable. */
	'swap:exposed': (event: ISwapEvent) => void;
	/** The swap failed (`reason`). */
	'swap:failed': (event: ISwapEvent) => void;
	/** Submarine swap: an output paying the contract, of at least the amount, was seen at any depth. */
	'swap:funding-seen': (event: ISwapEvent) => void;
	/** Submarine swap: the unconfirmed funding was replaced or vanished and none is left. */
	'swap:funding-lost': (event: ISwapEvent) => void;
	/** Submarine swap: this node started paying the client's invoice under the swap's expiry ceiling. */
	'swap:paying': (event: ISwapEvent) => void;
	/** Submarine swap: HTLCs are still out past `unresolvedAfterBlocks` (informational). */
	'swap:payment-unresolved': (event: ISwapEvent) => void;
	/** Submarine swap: the payment's preimage is known, from a fulfil or a claim seen on chain downstream. */
	'swap:preimage': (event: ISwapEvent) => void;
	/** Submarine swap: the claim to the sweep destination was built, persisted and broadcast. */
	'swap:claim-broadcast': (event: ISwapEvent) => void;
	/** Submarine swap: the claim confirmed to the resolution depth. */
	'swap:claim-confirmed': (event: ISwapEvent) => void;
	/** Submarine swap: every HTLC ended without a preimage; a preimage learned later still promotes the row. */
	'swap:payment-failed': (event: ISwapEvent) => void;
	/** Submarine swap: cancelled before anything was paid (invoice expired, ceiling no longer fits, client spent the funding, or the operator cancelled). */
	'swap:cancelled': (event: ISwapEvent) => void;

	// ─── Node ───

	/** Structured action log entry. */
	log: (entry: IStructuredLog) => void;
	/** Operational error (non-fatal). LightningNode never emits the bare `'error'` event. */
	'node:error': (error: ILightningError<NodeErrorCode>) => void;
	/** Node fully operational (peers reconnected, channels restored). */
	'node:ready': () => void;
}
