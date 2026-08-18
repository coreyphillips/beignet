/**
 * Assertions for a refused inbound channel open (#381).
 *
 * A refusal that produces only a local ERROR action never reaches the wire, so
 * the opener sits awaiting an accept it will never get. Every arm that refuses a
 * FRESH open therefore returns the wire error FIRST and the local ERROR second,
 * and these helpers assert exactly that pairing rather than an action index, so
 * a test cannot pass on a refusal the peer never sees.
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
