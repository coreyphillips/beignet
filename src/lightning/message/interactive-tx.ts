/**
 * BOLT 2: Interactive transaction construction messages.
 *
 * Message types 66-74 for collaborative transaction building.
 *
 * tx_add_input (66):   [32:channel_id][8:serial_id][2:prevtx_len][prevtx][4:prevtx_vout][4:sequence]
 * tx_add_output (67):  [32:channel_id][8:serial_id][8:sats][2:scriptpubkey_len][scriptpubkey]
 * tx_remove_input (68):[32:channel_id][8:serial_id]
 * tx_remove_output (69):[32:channel_id][8:serial_id]
 * tx_complete (70):    [32:channel_id]
 * tx_signatures (71):  [32:channel_id][32:txid][2:num_witnesses][witness...]
 * tx_init_rbf (72):    [32:channel_id][4:locktime][4:feerate]
 * tx_ack_rbf (73):     [32:channel_id]
 * tx_abort (74):       [32:channel_id][2:len][data]
 */

import { encodeTlvStream, decodeTlvStream } from './tlv';

// ---- Interfaces ----

export interface ITxAddInputMessage {
	channelId: Buffer;
	serialId: bigint;
	prevTx: Buffer;
	prevTxVout: number;
	sequence: number;
	/**
	 * Splicing only: the previous funding txid of the shared input being spent
	 * (BOLT 2 `tx_add_input_tlvs.shared_input_txid`, TLV type 0). Present only on
	 * the tx_add_input that contributes the channel's existing funding output;
	 * for such inputs `prevTx` is empty. 32 bytes, internal byte order.
	 */
	sharedInputTxid?: Buffer;
}

export interface ITxAddOutputMessage {
	channelId: Buffer;
	serialId: bigint;
	amountSats: bigint;
	scriptPubkey: Buffer;
}

export interface ITxRemoveInputMessage {
	channelId: Buffer;
	serialId: bigint;
}

export interface ITxRemoveOutputMessage {
	channelId: Buffer;
	serialId: bigint;
}

export interface ITxCompleteMessage {
	channelId: Buffer;
}

export interface ITxSignaturesMessage {
	channelId: Buffer;
	txid: Buffer;
	/** Witness stacks for the sender's OWN inputs, in tx-input order. */
	witnesses: Buffer[][];
	/**
	 * Splicing: the sender's 64-byte signature for the shared 2-of-2 funding
	 * input, carried in the `shared_input_signature` TLV (type 0) — NOT in the
	 * witnesses array (witnesses only cover the sender's own inputs).
	 */
	sharedInputSignature?: Buffer;
}

export interface ITxInitRbfMessage {
	channelId: Buffer;
	locktime: number;
	feerate: number;
}

export interface ITxAckRbfMessage {
	channelId: Buffer;
}

export interface ITxAbortMessage {
	channelId: Buffer;
	data: Buffer;
}

// ---- tx_add_input (66) ----

/**
 * Encode a tx_add_input message payload (without 2-byte type prefix).
 */
export function encodeTxAddInputMessage(msg: ITxAddInputMessage): Buffer {
	if (msg.channelId.length !== 32) {
		throw new Error(`Channel ID must be 32 bytes, got ${msg.channelId.length}`);
	}

	if (msg.sharedInputTxid && msg.sharedInputTxid.length !== 32) {
		throw new Error(
			`sharedInputTxid must be 32 bytes, got ${msg.sharedInputTxid.length}`
		);
	}

	// 32 channelId + 8 serialId + 2 prevTxLen + prevTx.length + 4 prevTxVout + 4 sequence
	// + optional TLV: shared_input_txid (type 0, len 32) = 0x00 0x20 <32 bytes>
	const tlvLen = msg.sharedInputTxid ? 2 + 32 : 0;
	const fixedLen = 32 + 8 + 2 + msg.prevTx.length + 4 + 4 + tlvLen;
	const buf = Buffer.alloc(fixedLen);
	let offset = 0;

	msg.channelId.copy(buf, offset);
	offset += 32;
	buf.writeBigUInt64BE(msg.serialId, offset);
	offset += 8;
	buf.writeUInt16BE(msg.prevTx.length, offset);
	offset += 2;
	msg.prevTx.copy(buf, offset);
	offset += msg.prevTx.length;
	buf.writeUInt32BE(msg.prevTxVout, offset);
	offset += 4;
	buf.writeUInt32BE(msg.sequence, offset);
	offset += 4;

	if (msg.sharedInputTxid) {
		buf.writeUInt8(0, offset);
		offset += 1; // TLV type 0 (shared_input_txid)
		buf.writeUInt8(32, offset);
		offset += 1; // TLV length 32
		msg.sharedInputTxid.copy(buf, offset);
	}

	return buf;
}

/**
 * Decode a tx_add_input message payload.
 */
export function decodeTxAddInputMessage(payload: Buffer): ITxAddInputMessage {
	if (payload.length < 50) {
		throw new Error(
			`tx_add_input too short: need at least 50 bytes, got ${payload.length}`
		);
	}

	let offset = 0;

	const channelId = Buffer.from(payload.subarray(offset, offset + 32));
	offset += 32;
	const serialId = payload.readBigUInt64BE(offset);
	offset += 8;
	const prevTxLen = payload.readUInt16BE(offset);
	offset += 2;

	if (offset + prevTxLen + 8 > payload.length) {
		throw new Error('tx_add_input: prevTx length exceeds payload');
	}

	const prevTx = Buffer.from(payload.subarray(offset, offset + prevTxLen));
	offset += prevTxLen;
	const prevTxVout = payload.readUInt32BE(offset);
	offset += 4;
	const sequence = payload.readUInt32BE(offset);
	offset += 4;

	// Optional TLV stream. We only understand shared_input_txid (type 0, len 32).
	let sharedInputTxid: Buffer | undefined;
	while (offset + 2 <= payload.length) {
		const tlvType = payload.readUInt8(offset);
		offset += 1;
		const tlvLen = payload.readUInt8(offset);
		offset += 1;
		if (offset + tlvLen > payload.length) break;
		if (tlvType === 0 && tlvLen === 32) {
			sharedInputTxid = Buffer.from(payload.subarray(offset, offset + 32));
		}
		offset += tlvLen;
	}

	return { channelId, serialId, prevTx, prevTxVout, sequence, sharedInputTxid };
}

// ---- tx_add_output (67) ----

/**
 * Encode a tx_add_output message payload (without 2-byte type prefix).
 */
export function encodeTxAddOutputMessage(msg: ITxAddOutputMessage): Buffer {
	if (msg.channelId.length !== 32) {
		throw new Error(`Channel ID must be 32 bytes, got ${msg.channelId.length}`);
	}

	// 32 channelId + 8 serialId + 8 amountSats + 2 scriptLen + scriptPubkey.length
	const fixedLen = 32 + 8 + 8 + 2 + msg.scriptPubkey.length;
	const buf = Buffer.alloc(fixedLen);
	let offset = 0;

	msg.channelId.copy(buf, offset);
	offset += 32;
	buf.writeBigUInt64BE(msg.serialId, offset);
	offset += 8;
	buf.writeBigUInt64BE(msg.amountSats, offset);
	offset += 8;
	buf.writeUInt16BE(msg.scriptPubkey.length, offset);
	offset += 2;
	msg.scriptPubkey.copy(buf, offset);

	return buf;
}

/**
 * Decode a tx_add_output message payload.
 */
export function decodeTxAddOutputMessage(payload: Buffer): ITxAddOutputMessage {
	if (payload.length < 50) {
		throw new Error(
			`tx_add_output too short: need at least 50 bytes, got ${payload.length}`
		);
	}

	let offset = 0;

	const channelId = Buffer.from(payload.subarray(offset, offset + 32));
	offset += 32;
	const serialId = payload.readBigUInt64BE(offset);
	offset += 8;
	const amountSats = payload.readBigUInt64BE(offset);
	offset += 8;
	const scriptLen = payload.readUInt16BE(offset);
	offset += 2;

	if (offset + scriptLen > payload.length) {
		throw new Error('tx_add_output: scriptPubkey length exceeds payload');
	}

	const scriptPubkey = Buffer.from(
		payload.subarray(offset, offset + scriptLen)
	);

	return { channelId, serialId, amountSats, scriptPubkey };
}

// ---- tx_remove_input (68) ----

/**
 * Encode a tx_remove_input message payload (without 2-byte type prefix).
 */
export function encodeTxRemoveInputMessage(msg: ITxRemoveInputMessage): Buffer {
	if (msg.channelId.length !== 32) {
		throw new Error(`Channel ID must be 32 bytes, got ${msg.channelId.length}`);
	}

	const buf = Buffer.alloc(40);
	msg.channelId.copy(buf, 0);
	buf.writeBigUInt64BE(msg.serialId, 32);

	return buf;
}

/**
 * Decode a tx_remove_input message payload.
 */
export function decodeTxRemoveInputMessage(
	payload: Buffer
): ITxRemoveInputMessage {
	if (payload.length < 40) {
		throw new Error(
			`tx_remove_input too short: need 40 bytes, got ${payload.length}`
		);
	}

	const channelId = Buffer.from(payload.subarray(0, 32));
	const serialId = payload.readBigUInt64BE(32);

	return { channelId, serialId };
}

// ---- tx_remove_output (69) ----

/**
 * Encode a tx_remove_output message payload (without 2-byte type prefix).
 */
export function encodeTxRemoveOutputMessage(
	msg: ITxRemoveOutputMessage
): Buffer {
	if (msg.channelId.length !== 32) {
		throw new Error(`Channel ID must be 32 bytes, got ${msg.channelId.length}`);
	}

	const buf = Buffer.alloc(40);
	msg.channelId.copy(buf, 0);
	buf.writeBigUInt64BE(msg.serialId, 32);

	return buf;
}

/**
 * Decode a tx_remove_output message payload.
 */
export function decodeTxRemoveOutputMessage(
	payload: Buffer
): ITxRemoveOutputMessage {
	if (payload.length < 40) {
		throw new Error(
			`tx_remove_output too short: need 40 bytes, got ${payload.length}`
		);
	}

	const channelId = Buffer.from(payload.subarray(0, 32));
	const serialId = payload.readBigUInt64BE(32);

	return { channelId, serialId };
}

// ---- tx_complete (70) ----

/**
 * Encode a tx_complete message payload (without 2-byte type prefix).
 */
export function encodeTxCompleteMessage(msg: ITxCompleteMessage): Buffer {
	if (msg.channelId.length !== 32) {
		throw new Error(`Channel ID must be 32 bytes, got ${msg.channelId.length}`);
	}

	return Buffer.from(msg.channelId);
}

/**
 * Decode a tx_complete message payload.
 */
export function decodeTxCompleteMessage(payload: Buffer): ITxCompleteMessage {
	if (payload.length < 32) {
		throw new Error(
			`tx_complete too short: need 32 bytes, got ${payload.length}`
		);
	}

	const channelId = Buffer.from(payload.subarray(0, 32));

	return { channelId };
}

// ---- tx_signatures (71) ----

/**
 * Encode a tx_signatures message payload (without 2-byte type prefix).
 *
 * BOLT 2 wire format: [32:channelId][32:txid][2:numWitnesses]
 *   for each witness: [2:len][witness_data]
 *     where witness_data is the input's witness stack in standard Bitcoin
 *     serialization: CompactSize element count, then per element a
 *     CompactSize length + bytes.
 *   TLV stream: type 0 (shared_input_signature, splicing) = 64-byte signature
 */
export function encodeTxSignaturesMessage(msg: ITxSignaturesMessage): Buffer {
	if (msg.channelId.length !== 32) {
		throw new Error(`Channel ID must be 32 bytes, got ${msg.channelId.length}`);
	}
	if (msg.txid.length !== 32) {
		throw new Error(`Txid must be 32 bytes, got ${msg.txid.length}`);
	}

	const parts: Buffer[] = [];

	// Header: channelId + txid + numWitnesses
	const header = Buffer.alloc(32 + 32 + 2);
	msg.channelId.copy(header, 0);
	msg.txid.copy(header, 32);
	header.writeUInt16BE(msg.witnesses.length, 64);
	parts.push(header);

	for (const witness of msg.witnesses) {
		const witnessData = serializeWitnessStack(witness);
		const lenBuf = Buffer.alloc(2);
		lenBuf.writeUInt16BE(witnessData.length);
		parts.push(lenBuf, witnessData);
	}

	if (msg.sharedInputSignature) {
		if (msg.sharedInputSignature.length !== 64) {
			throw new Error(
				`shared_input_signature must be 64 bytes, got ${msg.sharedInputSignature.length}`
			);
		}
		parts.push(
			encodeTlvStream([{ type: 0n, value: msg.sharedInputSignature }])
		);
	}

	return Buffer.concat(parts);
}

/**
 * Decode a tx_signatures message payload.
 */
export function decodeTxSignaturesMessage(
	payload: Buffer
): ITxSignaturesMessage {
	if (payload.length < 66) {
		throw new Error(
			`tx_signatures too short: need at least 66 bytes, got ${payload.length}`
		);
	}

	let offset = 0;

	const channelId = Buffer.from(payload.subarray(offset, offset + 32));
	offset += 32;
	const txid = Buffer.from(payload.subarray(offset, offset + 32));
	offset += 32;
	const numWitnesses = payload.readUInt16BE(offset);
	offset += 2;

	const witnesses: Buffer[][] = [];

	for (let w = 0; w < numWitnesses; w++) {
		if (offset + 2 > payload.length) {
			throw new Error('tx_signatures: unexpected end of witness data');
		}
		const witnessLen = payload.readUInt16BE(offset);
		offset += 2;
		if (offset + witnessLen > payload.length) {
			throw new Error('tx_signatures: witness length exceeds payload');
		}
		witnesses.push(
			parseWitnessStack(payload.subarray(offset, offset + witnessLen))
		);
		offset += witnessLen;
	}

	const result: ITxSignaturesMessage = { channelId, txid, witnesses };

	if (offset < payload.length) {
		const { records } = decodeTlvStream(payload, offset);
		for (const record of records) {
			if (record.type === 0n && record.value.length === 64) {
				result.sharedInputSignature = Buffer.from(record.value);
			}
		}
	}

	return result;
}

/** Serialize a witness stack per Bitcoin wire encoding (CompactSize counts). */
function serializeWitnessStack(elements: Buffer[]): Buffer {
	const parts: Buffer[] = [encodeCompactSize(elements.length)];
	for (const el of elements) {
		parts.push(encodeCompactSize(el.length), el);
	}
	return Buffer.concat(parts);
}

/** Parse a Bitcoin wire-encoded witness stack back to its elements. */
function parseWitnessStack(data: Buffer): Buffer[] {
	let offset = 0;
	const readCompact = (): number => {
		const first = data[offset];
		offset += 1;
		if (first < 0xfd) return first;
		if (first === 0xfd) {
			const v = data.readUInt16LE(offset);
			offset += 2;
			return v;
		}
		if (first === 0xfe) {
			const v = data.readUInt32LE(offset);
			offset += 4;
			return v;
		}
		throw new Error('tx_signatures: witness element too large');
	};
	const count = readCompact();
	const elements: Buffer[] = [];
	for (let i = 0; i < count; i++) {
		const len = readCompact();
		if (offset + len > data.length) {
			throw new Error('tx_signatures: witness stack element exceeds data');
		}
		elements.push(Buffer.from(data.subarray(offset, offset + len)));
		offset += len;
	}
	return elements;
}

function encodeCompactSize(n: number): Buffer {
	if (n < 0xfd) return Buffer.from([n]);
	if (n <= 0xffff) {
		const b = Buffer.alloc(3);
		b[0] = 0xfd;
		b.writeUInt16LE(n, 1);
		return b;
	}
	const b = Buffer.alloc(5);
	b[0] = 0xfe;
	b.writeUInt32LE(n, 1);
	return b;
}

// ---- tx_init_rbf (72) ----

/**
 * Encode a tx_init_rbf message payload (without 2-byte type prefix).
 */
export function encodeTxInitRbfMessage(msg: ITxInitRbfMessage): Buffer {
	if (msg.channelId.length !== 32) {
		throw new Error(`Channel ID must be 32 bytes, got ${msg.channelId.length}`);
	}

	const buf = Buffer.alloc(40);
	msg.channelId.copy(buf, 0);
	buf.writeUInt32BE(msg.locktime, 32);
	buf.writeUInt32BE(msg.feerate, 36);

	return buf;
}

/**
 * Decode a tx_init_rbf message payload.
 */
export function decodeTxInitRbfMessage(payload: Buffer): ITxInitRbfMessage {
	if (payload.length < 40) {
		throw new Error(
			`tx_init_rbf too short: need 40 bytes, got ${payload.length}`
		);
	}

	const channelId = Buffer.from(payload.subarray(0, 32));
	const locktime = payload.readUInt32BE(32);
	const feerate = payload.readUInt32BE(36);

	return { channelId, locktime, feerate };
}

// ---- tx_ack_rbf (73) ----

/**
 * Encode a tx_ack_rbf message payload (without 2-byte type prefix).
 */
export function encodeTxAckRbfMessage(msg: ITxAckRbfMessage): Buffer {
	if (msg.channelId.length !== 32) {
		throw new Error(`Channel ID must be 32 bytes, got ${msg.channelId.length}`);
	}

	return Buffer.from(msg.channelId);
}

/**
 * Decode a tx_ack_rbf message payload.
 */
export function decodeTxAckRbfMessage(payload: Buffer): ITxAckRbfMessage {
	if (payload.length < 32) {
		throw new Error(
			`tx_ack_rbf too short: need 32 bytes, got ${payload.length}`
		);
	}

	const channelId = Buffer.from(payload.subarray(0, 32));

	return { channelId };
}

// ---- tx_abort (74) ----

/**
 * Encode a tx_abort message payload (without 2-byte type prefix).
 */
export function encodeTxAbortMessage(msg: ITxAbortMessage): Buffer {
	if (msg.channelId.length !== 32) {
		throw new Error(`Channel ID must be 32 bytes, got ${msg.channelId.length}`);
	}

	const buf = Buffer.alloc(34 + msg.data.length);
	msg.channelId.copy(buf, 0);
	buf.writeUInt16BE(msg.data.length, 32);
	msg.data.copy(buf, 34);

	return buf;
}

/**
 * Decode a tx_abort message payload.
 */
export function decodeTxAbortMessage(payload: Buffer): ITxAbortMessage {
	if (payload.length < 34) {
		throw new Error(
			`tx_abort too short: need at least 34 bytes, got ${payload.length}`
		);
	}

	const channelId = Buffer.from(payload.subarray(0, 32));
	const dataLen = payload.readUInt16BE(32);

	if (34 + dataLen > payload.length) {
		throw new Error('tx_abort: data length exceeds payload');
	}

	const data = Buffer.from(payload.subarray(34, 34 + dataLen));

	return { channelId, data };
}
