/**
 * BOLT 2: Channel action and event types.
 *
 * The Channel class returns ChannelAction arrays instead of directly
 * interacting with transport. The caller (ChannelManager) processes
 * these actions.
 */

import { MessageType } from '../message/types';
import { IRecoveryOutboxMessage } from '../storage/types';
import type { Channel } from './channel';

export enum ChannelActionType {
	SEND_MESSAGE = 'SEND_MESSAGE',
	BROADCAST_TX = 'BROADCAST_TX',
	AUTHORIZE_FUNDING_BROADCAST = 'AUTHORIZE_FUNDING_BROADCAST',
	WATCH_FUNDING = 'WATCH_FUNDING',
	CHANNEL_READY = 'CHANNEL_READY',
	CHANNEL_CLOSED = 'CHANNEL_CLOSED',
	ERROR = 'ERROR',
	HTLC_FORWARDED = 'HTLC_FORWARDED',
	HTLC_FULFILLED = 'HTLC_FULFILLED',
	HTLC_FAILED = 'HTLC_FAILED',
	FORCE_CLOSE = 'FORCE_CLOSE',
	WATCH_OUTPUT = 'WATCH_OUTPUT',
	PREIMAGE_LEARNED = 'PREIMAGE_LEARNED',
	CHANNEL_FULLY_RESOLVED = 'CHANNEL_FULLY_RESOLVED',
	ANNOUNCEMENT_READY = 'ANNOUNCEMENT_READY',
	PROPOSE_CLOSING_FEE = 'PROPOSE_CLOSING_FEE',
	/** Persist channel state before sending messages (Fix 2.2) */
	PERSIST_STATE = 'PERSIST_STATE',
	SPLICE_COMPLETE = 'SPLICE_COMPLETE'
}

export interface ISendMessageAction {
	type: ChannelActionType.SEND_MESSAGE;
	messageType: MessageType;
	payload: Buffer;
	/**
	 * A retransmission of bytes already sent once, replayed after a reconnect
	 * per BOLT 2. It is still withheld when the batch's persist fails (the
	 * state justifying it must be on disk before the peer sees it again), but
	 * it is NOT written to the recovery outbox: the row from the original send
	 * is already there, and re-inserting the same bytes on every reconnect
	 * would churn the table for nothing.
	 */
	replay?: boolean;
	/**
	 * A recovery declaration, held by the quorum barrier until the state that
	 * authorizes it is durable (docs/RECOVERY-PROTOCOL.md 5.8).
	 *
	 * Marked per ACTION rather than inferred from the message type, because
	 * `error` is also BOLT 1's ordinary protocol-violation message. Holding
	 * those would buy nothing and cost a great deal: an ordinary error is not
	 * retransmittable, so a refused one is lost for good, and the local
	 * force-close it drives (the `channel:errored` emit rides the send) would
	 * be lost with it. The declarations are different in kind. Losing the
	 * record that broadcasting is FORBIDDEN re-enables broadcasting a
	 * commitment the peer has provably revoked, which is the whole balance.
	 */
	durabilityCritical?: boolean;
}

export interface IBroadcastTxAction {
	type: ChannelActionType.BROADCAST_TX;
	tx: Buffer;
	/**
	 * This broadcast creates a funding output naming us, so it is held until
	 * the frame recording the channel is quorum durable (5.8): a restore below
	 * that frame comes back with no channel at all while a 2-of-2 we are a
	 * party to exists on the network.
	 *
	 * A MARK rather than gating BROADCAST_TX wholesale, because the type is
	 * overloaded and one of its other users must never be refusable: a force
	 * close returns [BROADCAST_TX, CHANNEL_CLOSED] with no PERSIST_STATE at
	 * all, so gating the type would send it through the unattributed-batch
	 * refusal and take away the only exit an operator has left.
	 */
	fundingCritical?: true;
}

/**
 * BOLT 2's point of no return for a v1 funder.
 *
 * The obligation begins at funding_signed and never at funding_created:
 * without the acceptor's signature over our commitment #0 the funding output
 * has no unilateral exit for us. It is an ACTION rather than a side effect of
 * the funding watch because everything this dispatch path gates is an action:
 * as a bare emit it could be withheld by neither a failed persist nor a quorum
 * barrier. It carries no transaction, because the signed v1 funding tx lives
 * in the node's pending map and never in the channel.
 */
export interface IAuthorizeFundingBroadcastAction {
	type: ChannelActionType.AUTHORIZE_FUNDING_BROADCAST;
	/** Internal byte order, the key the node's pending map uses. */
	fundingTxid: Buffer;
}

export interface IWatchFundingAction {
	type: ChannelActionType.WATCH_FUNDING;
	fundingTxid: Buffer;
	fundingOutputIndex: number;
	minimumDepth: number;
}

export interface IChannelReadyAction {
	type: ChannelActionType.CHANNEL_READY;
	channelId: Buffer;
}

export interface IChannelClosedAction {
	type: ChannelActionType.CHANNEL_CLOSED;
	channelId: Buffer;
}

export interface IErrorAction {
	type: ChannelActionType.ERROR;
	message: string;
}

export interface IHtlcForwardedAction {
	type: ChannelActionType.HTLC_FORWARDED;
	htlcId: bigint;
	amountMsat: bigint;
	paymentHash: Buffer;
}

export interface IHtlcFulfilledAction {
	type: ChannelActionType.HTLC_FULFILLED;
	htlcId: bigint;
	paymentPreimage: Buffer;
}

export interface IHtlcFailedAction {
	type: ChannelActionType.HTLC_FAILED;
	htlcId: bigint;
	reason: Buffer;
}

export interface IForceCloseAction {
	type: ChannelActionType.FORCE_CLOSE;
	commitmentTx: Buffer;
	channelId: Buffer;
}

export interface IWatchOutputAction {
	type: ChannelActionType.WATCH_OUTPUT;
	txid: string;
	outputIndex: number;
}

export interface IPreimageLearnedAction {
	type: ChannelActionType.PREIMAGE_LEARNED;
	paymentHash: Buffer;
	preimage: Buffer;
}

export interface IChannelFullyResolvedAction {
	type: ChannelActionType.CHANNEL_FULLY_RESOLVED;
	channelId: Buffer;
}

export interface IAnnouncementReadyAction {
	type: ChannelActionType.ANNOUNCEMENT_READY;
	channelAnnouncement: Buffer;
	channelUpdate: Buffer;
	channelId: Buffer;
}

export interface IProposeClosingFeeAction {
	type: ChannelActionType.PROPOSE_CLOSING_FEE;
	channelId: Buffer;
}

export interface IPersistStateAction {
	type: ChannelActionType.PERSIST_STATE;
}

/** A splice finished (both splice_locked exchanged): the channel now lives on
 *  a NEW funding outpoint and must be re-announced with its new SCID. */
export interface ISpliceCompleteAction {
	type: ChannelActionType.SPLICE_COMPLETE;
}

/**
 * Wire messages BOLT 2 can require us to retransmit after a reconnect, and so
 * the ones worth retaining byte-exactly in the recovery outbox
 * (docs/RECOVERY-PROTOCOL.md 5.2). Anything outside this set is either
 * re-derivable from channel state or meaningless to replay.
 */
export const RETRANSMITTABLE_MESSAGE_TYPES: ReadonlySet<number> =
	new Set<number>([
		MessageType.CHANNEL_READY,
		MessageType.UPDATE_ADD_HTLC,
		MessageType.UPDATE_FULFILL_HTLC,
		MessageType.UPDATE_FAIL_HTLC,
		MessageType.UPDATE_FAIL_MALFORMED_HTLC,
		MessageType.UPDATE_FEE,
		MessageType.START_BATCH,
		MessageType.COMMITMENT_SIGNED,
		MessageType.REVOKE_AND_ACK,
		MessageType.SPLICE,
		MessageType.SPLICE_ACK,
		MessageType.SPLICE_LOCKED
	]);

/**
 * The subset a peer's revoke_and_ack proves receipt of: our queued updates and
 * the commitment_signed (batched or not) that covered them. Our OWN
 * revoke_and_ack is deliberately excluded, since the peer's revocation says
 * nothing about whether it received ours; those rows are instead replaced by
 * the next revoke_and_ack for the channel (see
 * {@link SUPERSEDES_OWN_KIND_MESSAGE_TYPES}), of which only the latest can ever
 * be requested.
 */
export const SUPERSEDED_ON_REVOKE_MESSAGE_TYPES: readonly number[] = [
	MessageType.UPDATE_ADD_HTLC,
	MessageType.UPDATE_FULFILL_HTLC,
	MessageType.UPDATE_FAIL_HTLC,
	MessageType.UPDATE_FAIL_MALFORMED_HTLC,
	MessageType.UPDATE_FEE,
	MessageType.START_BATCH,
	MessageType.COMMITMENT_SIGNED
];

/**
 * Message types where only the newest row can ever be retransmitted, so
 * writing one supersedes the channel's earlier rows of the same type.
 *
 * Nothing else retires these. A peer's revoke_and_ack proves nothing about our
 * own revoke_and_ack, and no wire message acknowledges channel_ready or
 * splice_locked at all, so without this rule they accumulate for the life of
 * the channel until the row cap starts evicting them: one row per commitment
 * round, forever, on a busy channel. Retransmission only ever wants the latest
 * of each, which is exactly what this keeps.
 */
export const SUPERSEDES_OWN_KIND_MESSAGE_TYPES: readonly number[] = [
	MessageType.REVOKE_AND_ACK,
	MessageType.CHANNEL_READY,
	MessageType.SPLICE_LOCKED
];

/**
 * The payload of the `channel:persist` event.
 *
 * ChannelManager fills in `outbound` (the retransmittable messages this
 * batch's PERSIST_STATE authorizes) and the listener that owns storage
 * answers with `committed` plus the ids of the rows it wrote. A listener
 * reporting `committed: false` withholds those sends: the state that
 * justifies them is not on disk.
 */
export interface IChannelPersistRequest {
	/** Messages to commit alongside the channel state, in send order. */
	outbound: IRecoveryOutboxMessage[];
	/** Set false by the listener when the transaction rolled back. */
	committed: boolean;
	/** Row ids written for `outbound`, same order; empty without an outbox. */
	outboxIds: Array<number | null>;
	/**
	 * Outbox rows of these message types are proven held by the peer (its
	 * revoke_and_ack acknowledged them) and must be deleted IN the same
	 * transaction as this batch's state. In-transaction rather than eager so a
	 * failed persist (or a crash before it) cannot leave disk holding
	 * pre-revoke state whose retransmission bytes are already gone.
	 */
	supersede?: { messageTypes: number[] };
	/**
	 * The recovery journal frame this transition landed in, or null when the
	 * journal is off. Set by the listener alongside `committed`. This is the
	 * sequence a Phase 6 quorum barrier waits on before the batch's messages
	 * are allowed onto the wire (docs/RECOVERY-PROTOCOL.md 5.8).
	 */
	frameSequence?: bigint | null;
}

/**
 * The `channel:persist` event itself.
 *
 * The channel and its peer are passed BY REFERENCE rather than by an id the
 * listener has to resolve again, because the id a channel answers to is not
 * stable across its own opening. A v2 channel derives its permanent
 * channel_id during accept_channel2 but stays registered under its TEMPORARY
 * id until the open leaves AWAITING_TX_SIGNATURES, so the first v2
 * commitment_signed used to emit a permanent id that resolved to nothing:
 * the listener returned without committing, the batch reported committed
 * anyway, and the message left with no state on disk behind it.
 *
 * `channelId` is what the row is KEYED by (permanent once derived), which is
 * a separate question from which map currently holds the object.
 */
export interface IChannelPersistEvent {
	/** The channel to commit. Already resolved; never looked up again. */
	channel: Channel;
	/** The peer this channel belongs to, for the channel_state mutation. */
	peerPubkey: string;
	/** The id to key the persisted row by: permanent when one exists. */
	channelId: Buffer;
	/** Present when the batch has messages whose release depends on it. */
	request?: IChannelPersistRequest;
}

/**
 * The Phase 6 durability barrier, as the dispatch path sees it
 * (docs/RECOVERY-PROTOCOL.md 5.8).
 *
 * Structural rather than an import so the channel layer keeps knowing nothing
 * about guardians, replication or recovery storage. DurabilityBarrier in
 * src/lightning/recovery satisfies it.
 */
export interface IWireDurabilityBarrier {
	/** False in local and async-remote, where nothing is ever held. */
	readonly enforcing: boolean;
	/**
	 * This namespace can never be proven durable again (compaction outran
	 * replication). Optional so a test double or a non-guardian barrier needs
	 * no opinion on it.
	 *
	 * The channel layer consults it for ONE thing: refusing a new channel.
	 * Every other irreversible step is already gated by the barrier itself,
	 * and would now refuse immediately rather than after a timeout, but
	 * funding_created and channel_ready are not barrier-class, so opening is
	 * the one irreversible commitment that would otherwise proceed into a
	 * namespace that can never record it.
	 */
	readonly namespaceLost?: boolean;
	/** The synchronous question: is this frame already quorum durable? */
	isReleased(sequence: bigint | null): boolean;
	/** Park until it is, or until the wait is refused. */
	whenReleased(
		sequence: bigint | null
	): Promise<{ released: boolean; reason: string }>;
}

/**
 * The messages a quorum barrier holds, one per row of spec 5.8.
 *
 * - `revoke_and_ack` follows the new commitment being persisted. Releasing it
 *   before the quorum holds that state is exactly what makes a restored
 *   device broadcastable: the peer would hold our revocation for a commitment
 *   our replicas never learned we had moved past.
 * - `update_fulfill_htlc` follows the preimage and its HTLC linkage. A
 *   forgotten preimage, after the peer has already seen the fulfill, is a
 *   paid HTLC we can no longer claim.
 * - `commitment_signed` is where an outgoing forwarded HTLC becomes
 *   irrevocable, which is the spec's "forward linkage" row expressed in this
 *   codebase's message set. `start_batch` rides in the same batch and is
 *   therefore held with it.
 * - `tx_signatures` and `splice_locked` are the irreversible splice steps.
 *   Splice negotiation up to them is abortable and deliberately not held.
 *
 * The data-loss `error` of spec 5.8's last row is NOT here, and its absence is
 * deliberate: it is gated by the per-action `durabilityCritical` mark instead,
 * because `error` is one wire type serving two unrelated purposes and only one
 * of them is a recovery declaration. See ISendMessageAction.durabilityCritical.
 */
export const QUORUM_BARRIER_MESSAGE_TYPES: ReadonlySet<number> =
	new Set<number>([
		MessageType.REVOKE_AND_ACK,
		MessageType.UPDATE_FULFILL_HTLC,
		MessageType.COMMITMENT_SIGNED,
		MessageType.TX_SIGNATURES,
		MessageType.SPLICE_LOCKED,
		// The acceptor's authorization for the opener to put the funding output
		// on chain. A restore below the frame that FIRST records this channel
		// comes back with no channel at all, while a 2-of-2 naming us exists on
		// the network and the peer's reestablish gets an unknown-channel error.
		// The v2 counterpart, tx_signatures, has been gated since phase 6
		// landed, so leaving this out would give the identical role different
		// exactness guarantees depending on which open the peer chose.
		MessageType.FUNDING_SIGNED
	]);

/**
 * The version of the gated set above, plus the `durabilityCritical` mark.
 *
 * A frame declaring `quorum` is a claim about WHICH messages its writer held
 * back, and that claim is only as strong as the policy in force when the frame
 * was written. Without a version a later release could widen this set and then
 * read an old frame's bare `quorum` as a promise about messages that frame's
 * writer never gated, which is a restore resuming a channel on evidence nobody
 * produced. Bump this in the SAME commit as any change to what is gated; the
 * pinned-set test in tests/lightning/recovery-phase6-exactness.test.ts fails
 * otherwise.
 */
export const WIRE_SAFETY_POLICY_VERSION = 2;

export type ChannelAction =
	| ISendMessageAction
	| IBroadcastTxAction
	| IAuthorizeFundingBroadcastAction
	| IWatchFundingAction
	| IChannelReadyAction
	| IChannelClosedAction
	| IErrorAction
	| IHtlcForwardedAction
	| IHtlcFulfilledAction
	| IHtlcFailedAction
	| IForceCloseAction
	| IWatchOutputAction
	| IPreimageLearnedAction
	| IChannelFullyResolvedAction
	| IAnnouncementReadyAction
	| IProposeClosingFeeAction
	| IPersistStateAction
	| ISpliceCompleteAction;
