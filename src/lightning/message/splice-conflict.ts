/**
 * Splice conflict recovery (issue #760): the beignet extension that gets a
 * channel out of a splice that can never confirm.
 *
 * A splice may carry an input its initiator does not vouch for (a stranger's
 * direct funding into a zero-conf channel, locked at depth). If that input is
 * spent elsewhere and the spend confirms, the splice is dead, BOLT 2 offers
 * no abort past tx_signatures, and the channel would sit mid-splice forever.
 * Both sides still hold valid commitments on the pre-splice funding, so the
 * recovery is to agree the conflict and revert to it.
 *
 * Two subtypes ride the beignet custom message type (message/custom.ts):
 *
 *   SPLICE_CONFLICT (64), 98 bytes:
 *     [32 channel_id][32 splice_txid][32 conflict_txid][u16 input_index]
 *   SPLICE_CONFLICT_ACK (65), 67 bytes plus the reason:
 *     [32 channel_id][32 splice_txid][u8 agreed][u16 reason_len][reason utf8]
 *
 * Txids are in the byte order tx.getHash() returns (the order
 * ISpliceInFlight.spliceTxid is kept in), never display order. `input_index`
 * is the position of the spent input in the splice transaction. The receiver
 * of SPLICE_CONFLICT verifies the claim against ITS OWN chain view before
 * reverting; nothing here is trusted on the peer's word, so the message is
 * a prompt and the ack a report, and a peer that cannot verify answers
 * agreed=0 with a reason and changes nothing. The sender re-sends on each
 * block and on reconnect until it hears agreed=1.
 */

export interface ISpliceConflictMessage {
	channelId: Buffer;
	/** Internal byte order (tx.getHash()). */
	spliceTxid: Buffer;
	/** Internal byte order. */
	conflictTxid: Buffer;
	/** The spent input's position in the splice transaction. */
	inputIndex: number;
}

export interface ISpliceConflictAckMessage {
	channelId: Buffer;
	/** Internal byte order (tx.getHash()). */
	spliceTxid: Buffer;
	agreed: boolean;
	/** Why not, when agreed is false; empty otherwise. */
	reason: string;
}

export const SPLICE_CONFLICT_LENGTH = 32 + 32 + 32 + 2;
const ACK_FIXED_LENGTH = 32 + 32 + 1 + 2;
/** Bound on the ack's reason, so a peer cannot make us keep a novel. */
export const SPLICE_CONFLICT_REASON_MAX = 256;

function fixed(buf: Buffer, len: number, name: string): Buffer {
	if (!Buffer.isBuffer(buf) || buf.length !== len) {
		throw new Error(`${name} must be ${len} bytes`);
	}
	return buf;
}

export function encodeSpliceConflict(msg: ISpliceConflictMessage): Buffer {
	if (
		!Number.isInteger(msg.inputIndex) ||
		msg.inputIndex < 0 ||
		msg.inputIndex > 0xffff
	) {
		throw new Error('inputIndex must be a u16');
	}
	const out = Buffer.alloc(SPLICE_CONFLICT_LENGTH);
	fixed(msg.channelId, 32, 'channelId').copy(out, 0);
	fixed(msg.spliceTxid, 32, 'spliceTxid').copy(out, 32);
	fixed(msg.conflictTxid, 32, 'conflictTxid').copy(out, 64);
	out.writeUInt16BE(msg.inputIndex, 96);
	return out;
}

export function decodeSpliceConflict(data: Buffer): ISpliceConflictMessage {
	if (data.length !== SPLICE_CONFLICT_LENGTH) {
		throw new Error(
			`splice_conflict must be ${SPLICE_CONFLICT_LENGTH} bytes, got ${data.length}`
		);
	}
	return {
		channelId: Buffer.from(data.subarray(0, 32)),
		spliceTxid: Buffer.from(data.subarray(32, 64)),
		conflictTxid: Buffer.from(data.subarray(64, 96)),
		inputIndex: data.readUInt16BE(96)
	};
}

export function encodeSpliceConflictAck(
	msg: ISpliceConflictAckMessage
): Buffer {
	const reason = Buffer.from(msg.reason, 'utf8');
	if (reason.length > SPLICE_CONFLICT_REASON_MAX) {
		throw new Error(
			`reason exceeds ${SPLICE_CONFLICT_REASON_MAX} bytes (${reason.length})`
		);
	}
	const out = Buffer.alloc(ACK_FIXED_LENGTH + reason.length);
	fixed(msg.channelId, 32, 'channelId').copy(out, 0);
	fixed(msg.spliceTxid, 32, 'spliceTxid').copy(out, 32);
	out.writeUInt8(msg.agreed ? 1 : 0, 64);
	out.writeUInt16BE(reason.length, 65);
	reason.copy(out, ACK_FIXED_LENGTH);
	return out;
}

export function decodeSpliceConflictAck(
	data: Buffer
): ISpliceConflictAckMessage {
	if (data.length < ACK_FIXED_LENGTH) {
		throw new Error(
			`splice_conflict_ack must be at least ${ACK_FIXED_LENGTH} bytes, got ${data.length}`
		);
	}
	const agreedByte = data.readUInt8(64);
	if (agreedByte > 1) {
		throw new Error(
			`splice_conflict_ack agreed must be 0 or 1, got ${agreedByte}`
		);
	}
	const reasonLen = data.readUInt16BE(65);
	if (reasonLen > SPLICE_CONFLICT_REASON_MAX) {
		throw new Error(
			`splice_conflict_ack reason exceeds ${SPLICE_CONFLICT_REASON_MAX} bytes`
		);
	}
	if (data.length !== ACK_FIXED_LENGTH + reasonLen) {
		throw new Error(
			`splice_conflict_ack length ${data.length} does not match its reason length ${reasonLen}`
		);
	}
	return {
		channelId: Buffer.from(data.subarray(0, 32)),
		spliceTxid: Buffer.from(data.subarray(32, 64)),
		agreed: agreedByte === 1,
		reason: data.subarray(ACK_FIXED_LENGTH).toString('utf8')
	};
}
