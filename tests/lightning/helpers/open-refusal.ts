/**
 * Assertions for a refusal that must reach the PEER (#381 and #393 opens, #404
 * updates).
 *
 * A refusal that produces only a local ERROR action never reaches the wire, so
 * the peer sits awaiting an answer it will never get, or keeps an update in its
 * book that ours will never hold. Every wire-visible refusal therefore pairs a
 * wire error with the local ERROR in a fixed order, and these helpers assert
 * that pairing rather than an action index, so a test cannot pass on a refusal
 * the peer never sees.
 *
 * Two shapes:
 *  - `expectWireRefusal`, for a negotiation that is merely discarded (the open
 *    handshake): wire error, then local ERROR.
 *  - `expectWireFailure`, for a channel that is FAILED (the update path):
 *    PERSIST_STATE, then wire error, then local ERROR.
 */

import { expect } from 'chai';
import {
	ChannelAction,
	ChannelActionType
} from '../../../src/lightning/channel/channel-actions';
import { MessageType } from '../../../src/lightning/message/types';
import { decodeErrorMessage } from '../../../src/lightning/message/error';

/**
 * The reason text of the wire `error` in `actions`, asserting there is exactly
 * one and that it is scoped to `channelId`. Null when none was produced.
 */
export function wireRefusalOf(
	actions: ChannelAction[],
	channelId?: Buffer
): string | null {
	const sends = actions.filter(
		(a) =>
			a.type === ChannelActionType.SEND_MESSAGE &&
			a.messageType === MessageType.ERROR
	) as Array<{ payload: Buffer }>;
	if (sends.length === 0) return null;
	expect(sends, 'one wire error per refusal').to.have.length(1);
	const decoded = decodeErrorMessage(sends[0].payload);
	if (channelId) {
		expect(
			decoded.channelId.equals(channelId),
			'refusal scoped to the id the opener used'
		).to.equal(true);
	}
	// BOLT 1 reserves the all-zero id for every channel with the peer; a refusal
	// must never widen into one.
	expect(
		decoded.channelId.every((b) => b === 0),
		'refusal is not connection-wide'
	).to.equal(false);
	return decoded.data.toString('ascii');
}

/**
 * Assert a refusal reached BOTH the peer and the local caller, with the wire
 * action ahead of the local one so the temporary channel is still alive when the
 * cancellation is handed to the transport.
 */
export function expectWireRefusal(
	actions: ChannelAction[],
	channelId: Buffer,
	reason: RegExp
): void {
	expect(wireRefusalOf(actions, channelId), 'wire refusal').to.match(reason);
	const local = actions.find((a) => a.type === ChannelActionType.ERROR) as
		| { message: string }
		| undefined;
	expect(local, 'local ERROR action').to.not.equal(undefined);
	expect(local!.message).to.match(reason);
	expect(
		actions.findIndex(
			(a) =>
				a.type === ChannelActionType.SEND_MESSAGE &&
				a.messageType === MessageType.ERROR
		),
		'wire error precedes the action that forgets the channel'
	).to.be.lessThan(
		actions.findIndex((a) => a.type === ChannelActionType.ERROR)
	);
}

/**
 * Assert an update-path refusal FAILED the channel on the wire (#404).
 *
 * The order is the assertion. The persist LEADS, because the ERRORED state that
 * justifies the error has to be durable before the peer acts on it; the wire
 * error follows, because a refusal the peer never sees is #404 itself; and the
 * local ERROR is last so the embedder still learns. Callers assert
 * `ChannelState.ERRORED` themselves, which keeps Channel out of this module.
 */
export function expectWireFailure(
	actions: ChannelAction[],
	channelId: Buffer,
	reason: RegExp
): void {
	expect(actions, 'persist, wire error, local error').to.have.length(3);
	expect(actions[0].type, 'persist leads').to.equal(
		ChannelActionType.PERSIST_STATE
	);
	expect(wireRefusalOf(actions, channelId), 'wire failure').to.match(reason);
	expect(actions[1].type, 'wire error follows the persist').to.equal(
		ChannelActionType.SEND_MESSAGE
	);
	const local = actions[2] as { type: ChannelActionType; message: string };
	expect(local.type, 'local ERROR is last').to.equal(ChannelActionType.ERROR);
	expect(local.message).to.match(reason);
}
