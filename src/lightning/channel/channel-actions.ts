/**
 * BOLT 2: Channel action and event types.
 *
 * The Channel class returns ChannelAction arrays instead of directly
 * interacting with transport. The caller (ChannelManager) processes
 * these actions.
 */

import { MessageType } from '../message/types';

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
