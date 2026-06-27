/**
 * BOLT 2: STFU (quiescence) message encode/decode.
 *
 * Message type 2: stfu
 * Fields:
 *   [32: channel_id]
 *   [1: initiator] (1 = we initiated, 0 = responding)
 */

export interface IStfuMessage {
	channelId: Buffer;
	initiator: boolean;
}

export function encodeStfuMessage(msg: IStfuMessage): Buffer {
	const buf = Buffer.alloc(33);
	msg.channelId.copy(buf, 0);
	buf[32] = msg.initiator ? 1 : 0;
	return buf;
}

export function decodeStfuMessage(payload: Buffer): IStfuMessage {
	if (payload.length < 33) {
		throw new Error('STFU message too short');
	}
	return {
		channelId: Buffer.from(payload.subarray(0, 32)),
		initiator: payload[32] === 1
	};
}
