/**
 * BOLT 2: Channel action and event types.
 *
 * The Channel class returns ChannelAction arrays instead of directly
 * interacting with transport. The caller (ChannelManager) processes
 * these actions.
 */

import { MessageType } from '../message/types';
import { IRecoveryOutboxMessage } from '../storage/types';

export enum ChannelActionType {
	SEND_MESSAGE = 'SEND_MESSAGE',
	BROADCAST_TX = 'BROADCAST_TX',
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
}

export interface IBroadcastTxAction {
	type: ChannelActionType.BROADCAST_TX;
	tx: Buffer;
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
 * the next revoke_and_ack for the channel, of which only the latest can ever
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
}

export type ChannelAction =
	| ISendMessageAction
	| IBroadcastTxAction
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
