/**
 * Hand-rolled proto3 codec for the guardian envelope (wire spec section 6).
 *
 * Field numbers are frozen forever; new fields append. The envelope is
 * TRANSPORT encoding only: signatures cover the canonical transcripts of
 * section 4, never these bytes, so nothing here is security-critical beyond
 * refusing to crash on hostile input. The messages use only varint scalars,
 * bytes, strings, bools and simple nested messages, deliberately, so the
 * browser and React Native ports can hand-roll the same shapes without a
 * protobuf dependency.
 *
 * Decoders throw only on structurally broken protobuf (truncation, absurd
 * lengths, unsupported wire types); semantic validation (key lengths, zero
 * epochs, unknown sets) belongs to the guardian state machine, which answers
 * with proper status codes. Unknown fields are skipped for forward
 * compatibility. proto3 defaults apply: absent scalars decode as zero,
 * absent bytes as empty, absent messages as undefined.
 */

import { GuardianState } from './guardian-wire';
import {
	IGuardianAcquireEpochRequest,
	IGuardianAcquireEpochResponse,
	IGuardianGetHeadRequest,
	IGuardianGetHeadResponse,
	IGuardianGetStateRequest,
	IGuardianGetStateResponse,
	IGuardianInfoResponse,
	IGuardianPutStateRequest,
	IGuardianPutStateResponse,
	IGuardianReceipt,
	IGuardianRecord,
	IGuardianRegisterNodeRequest,
	IGuardianRegisterNodeResponse,
	IGuardianSyncEpochRequest,
	IGuardianSyncEpochResponse,
	IGuardianSyncRecordRequest,
	IGuardianSyncRecordResponse,
	IGuardianTakeoverCertificate
} from './guardian';

export const GUARDIAN_CONTENT_TYPE = 'application/x-protobuf';
export const GUARDIAN_HTTP_BASE_PATH = '/beignet-guardian/v1';

const WIRE_VARINT = 0;
const WIRE_64BIT = 1;
const WIRE_LEN = 2;
const WIRE_32BIT = 5;
const U32_MAX = 0xffffffff;
const U64_MAX = 0xffffffffffffffffn;

// ─────────────── primitive writer ───────────────

class ProtoWriter {
	private readonly chunks: Buffer[] = [];

	private varint(value: bigint): void {
		if (value < 0n || value > U64_MAX) {
			throw new Error(`varint out of u64 range: ${value}`);
		}
		let v = value;
		const bytes: number[] = [];
		do {
			let byte = Number(v & 0x7fn);
			v >>= 7n;
			if (v > 0n) byte |= 0x80;
			bytes.push(byte);
		} while (v > 0n);
		this.chunks.push(Buffer.from(bytes));
	}

	private tag(field: number, wireType: number): void {
		this.varint(BigInt((field << 3) | wireType));
	}

	/** uint32/uint64/enum field; proto3 omits the default zero. */
	uint(field: number, value: bigint | number): void {
		const v = typeof value === 'bigint' ? value : BigInt(value);
		if (v === 0n) return;
		this.tag(field, WIRE_VARINT);
		this.varint(v);
	}

	bool(field: number, value: boolean): void {
		if (!value) return;
		this.tag(field, WIRE_VARINT);
		this.varint(1n);
	}

	/** bytes field; proto3 omits the default empty value. */
	bytes(field: number, value: Buffer): void {
		if (value.length === 0) return;
		this.tag(field, WIRE_LEN);
		this.varint(BigInt(value.length));
		this.chunks.push(value);
	}

	string(field: number, value: string): void {
		this.bytes(field, Buffer.from(value, 'utf8'));
	}

	/**
	 * Nested message; presence is meaningful (a receipt is attached exactly
	 * on OK and OK_DUPLICATE), so undefined skips and a defined message is
	 * written even when its encoding is empty.
	 */
	message(field: number, encoded: Buffer | undefined): void {
		if (encoded === undefined) return;
		this.tag(field, WIRE_LEN);
		this.varint(BigInt(encoded.length));
		this.chunks.push(encoded);
	}

	finish(): Buffer {
		return Buffer.concat(this.chunks);
	}
}

// ─────────────── primitive reader ───────────────

class ProtoReader {
	private offset = 0;

	constructor(private readonly buf: Buffer) {}

	get done(): boolean {
		return this.offset >= this.buf.length;
	}

	readTag(): { field: number; wireType: number } {
		const key = this.readVarint();
		if (key > BigInt(U32_MAX)) {
			throw new Error('protobuf tag out of range');
		}
		const keyNum = Number(key);
		const field = keyNum >>> 3;
		if (field === 0) throw new Error('protobuf field number 0 is illegal');
		return { field, wireType: keyNum & 0x07 };
	}

	readVarint(): bigint {
		let result = 0n;
		let shift = 0n;
		for (let i = 0; i < 10; i++) {
			if (this.offset >= this.buf.length) {
				throw new Error('protobuf varint truncated');
			}
			const byte = this.buf[this.offset++];
			result |= BigInt(byte & 0x7f) << shift;
			if ((byte & 0x80) === 0) {
				if (result > U64_MAX) throw new Error('protobuf varint overflows u64');
				return result;
			}
			shift += 7n;
		}
		throw new Error('protobuf varint longer than 10 bytes');
	}

	readUint32(): number {
		const value = this.readVarint();
		if (value > BigInt(U32_MAX)) {
			throw new Error('protobuf uint32 out of range');
		}
		return Number(value);
	}

	readBytes(): Buffer {
		const length = this.readVarint();
		if (length > BigInt(this.buf.length - this.offset)) {
			throw new Error('protobuf length-delimited field truncated');
		}
		const start = this.offset;
		this.offset += Number(length);
		return Buffer.from(this.buf.subarray(start, this.offset));
	}

	readString(): string {
		return this.readBytes().toString('utf8');
	}

	skip(wireType: number): void {
		switch (wireType) {
			case WIRE_VARINT:
				this.readVarint();
				return;
			case WIRE_64BIT:
				if (this.offset + 8 > this.buf.length) {
					throw new Error('protobuf 64-bit field truncated');
				}
				this.offset += 8;
				return;
			case WIRE_LEN:
				this.readBytes();
				return;
			case WIRE_32BIT:
				if (this.offset + 4 > this.buf.length) {
					throw new Error('protobuf 32-bit field truncated');
				}
				this.offset += 4;
				return;
			default:
				throw new Error(`unsupported protobuf wire type ${wireType}`);
		}
	}
}

const EMPTY = (): Buffer => Buffer.alloc(0);

// ─────────────── GuardianState and its parts ───────────────

export function encodeGuardianState(state: GuardianState): Buffer {
	const lease = new ProtoWriter();
	lease.uint(1, state.lease.epoch);
	lease.bytes(2, state.lease.writerPublicKey);
	const head = new ProtoWriter();
	head.uint(1, state.logHead.sequence);
	head.bytes(2, state.logHead.frameHash);
	head.bytes(3, state.logHead.ciphertextHash);
	head.uint(4, state.logHead.recordEpoch);
	const origin = new ProtoWriter();
	origin.uint(1, state.origin.firstSequence);
	origin.bytes(2, state.origin.previousHash);
	const writer = new ProtoWriter();
	writer.bytes(1, state.recoveryId);
	writer.message(2, lease.finish());
	writer.message(3, origin.finish());
	writer.message(4, head.finish());
	return writer.finish();
}

export function decodeGuardianState(buf: Buffer): GuardianState {
	const state: GuardianState = {
		recoveryId: EMPTY(),
		lease: { epoch: 0n, writerPublicKey: EMPTY() },
		origin: { firstSequence: 0n, previousHash: EMPTY() },
		logHead: {
			sequence: 0n,
			frameHash: EMPTY(),
			ciphertextHash: EMPTY(),
			recordEpoch: 0n
		}
	};
	const reader = new ProtoReader(buf);
	while (!reader.done) {
		const { field, wireType } = reader.readTag();
		if (field === 1 && wireType === WIRE_LEN) {
			state.recoveryId = reader.readBytes();
		} else if (field === 2 && wireType === WIRE_LEN) {
			const lease = new ProtoReader(reader.readBytes());
			while (!lease.done) {
				const tag = lease.readTag();
				if (tag.field === 1 && tag.wireType === WIRE_VARINT) {
					state.lease.epoch = lease.readVarint();
				} else if (tag.field === 2 && tag.wireType === WIRE_LEN) {
					state.lease.writerPublicKey = lease.readBytes();
				} else {
					lease.skip(tag.wireType);
				}
			}
		} else if (field === 3 && wireType === WIRE_LEN) {
			const origin = new ProtoReader(reader.readBytes());
			while (!origin.done) {
				const tag = origin.readTag();
				if (tag.field === 1 && tag.wireType === WIRE_VARINT) {
					state.origin.firstSequence = origin.readVarint();
				} else if (tag.field === 2 && tag.wireType === WIRE_LEN) {
					state.origin.previousHash = origin.readBytes();
				} else {
					origin.skip(tag.wireType);
				}
			}
		} else if (field === 4 && wireType === WIRE_LEN) {
			const head = new ProtoReader(reader.readBytes());
			while (!head.done) {
				const tag = head.readTag();
				if (tag.field === 1 && tag.wireType === WIRE_VARINT) {
					state.logHead.sequence = head.readVarint();
				} else if (tag.field === 2 && tag.wireType === WIRE_LEN) {
					state.logHead.frameHash = head.readBytes();
				} else if (tag.field === 3 && tag.wireType === WIRE_LEN) {
					state.logHead.ciphertextHash = head.readBytes();
				} else if (tag.field === 4 && tag.wireType === WIRE_VARINT) {
					state.logHead.recordEpoch = head.readVarint();
				} else {
					head.skip(tag.wireType);
				}
			}
		} else {
			reader.skip(wireType);
		}
	}
	return state;
}

// ─────────────── Record, Receipt, TakeoverCertificate ───────────────

export function encodeRecord(record: IGuardianRecord): Buffer {
	const writer = new ProtoWriter();
	writer.uint(1, record.protocolVersion);
	writer.bytes(2, record.guardianSetId);
	writer.bytes(3, record.recoveryId);
	writer.uint(4, record.epoch);
	writer.uint(5, record.sequence);
	writer.bytes(6, record.previousHash);
	writer.bytes(7, record.frameHash);
	writer.bytes(8, record.ciphertext);
	writer.bytes(9, record.writerSignature);
	return writer.finish();
}

export function decodeRecord(buf: Buffer): IGuardianRecord {
	const record: IGuardianRecord = {
		protocolVersion: 0,
		guardianSetId: EMPTY(),
		recoveryId: EMPTY(),
		epoch: 0n,
		sequence: 0n,
		previousHash: EMPTY(),
		frameHash: EMPTY(),
		ciphertext: EMPTY(),
		writerSignature: EMPTY()
	};
	const reader = new ProtoReader(buf);
	while (!reader.done) {
		const { field, wireType } = reader.readTag();
		if (field === 1 && wireType === WIRE_VARINT) {
			record.protocolVersion = reader.readUint32();
		} else if (field === 2 && wireType === WIRE_LEN) {
			record.guardianSetId = reader.readBytes();
		} else if (field === 3 && wireType === WIRE_LEN) {
			record.recoveryId = reader.readBytes();
		} else if (field === 4 && wireType === WIRE_VARINT) {
			record.epoch = reader.readVarint();
		} else if (field === 5 && wireType === WIRE_VARINT) {
			record.sequence = reader.readVarint();
		} else if (field === 6 && wireType === WIRE_LEN) {
			record.previousHash = reader.readBytes();
		} else if (field === 7 && wireType === WIRE_LEN) {
			record.frameHash = reader.readBytes();
		} else if (field === 8 && wireType === WIRE_LEN) {
			record.ciphertext = reader.readBytes();
		} else if (field === 9 && wireType === WIRE_LEN) {
			record.writerSignature = reader.readBytes();
		} else {
			reader.skip(wireType);
		}
	}
	return record;
}

export function encodeReceipt(receipt: IGuardianReceipt): Buffer {
	const writer = new ProtoWriter();
	writer.uint(1, receipt.protocolVersion);
	writer.bytes(2, receipt.guardianSetId);
	writer.bytes(3, receipt.guardianId);
	writer.message(4, encodeGuardianState(receipt.state));
	writer.uint(5, receipt.issuedAt);
	writer.bytes(6, receipt.signature);
	return writer.finish();
}

export function decodeReceipt(buf: Buffer): IGuardianReceipt {
	const receipt: IGuardianReceipt = {
		protocolVersion: 0,
		guardianSetId: EMPTY(),
		guardianId: EMPTY(),
		state: decodeGuardianState(EMPTY()),
		issuedAt: 0n,
		signature: EMPTY()
	};
	const reader = new ProtoReader(buf);
	while (!reader.done) {
		const { field, wireType } = reader.readTag();
		if (field === 1 && wireType === WIRE_VARINT) {
			receipt.protocolVersion = reader.readUint32();
		} else if (field === 2 && wireType === WIRE_LEN) {
			receipt.guardianSetId = reader.readBytes();
		} else if (field === 3 && wireType === WIRE_LEN) {
			receipt.guardianId = reader.readBytes();
		} else if (field === 4 && wireType === WIRE_LEN) {
			receipt.state = decodeGuardianState(reader.readBytes());
		} else if (field === 5 && wireType === WIRE_VARINT) {
			receipt.issuedAt = reader.readVarint();
		} else if (field === 6 && wireType === WIRE_LEN) {
			receipt.signature = reader.readBytes();
		} else {
			reader.skip(wireType);
		}
	}
	return receipt;
}

export function encodeTakeoverCertificate(
	cert: IGuardianTakeoverCertificate
): Buffer {
	const writer = new ProtoWriter();
	writer.uint(1, cert.protocolVersion);
	writer.bytes(2, cert.guardianSetId);
	writer.bytes(3, cert.guardianId);
	writer.message(4, encodeGuardianState(cert.supersededState));
	writer.uint(5, cert.newEpoch);
	writer.bytes(6, cert.newWriterPublicKey);
	writer.uint(7, cert.issuedAt);
	writer.bytes(8, cert.signature);
	return writer.finish();
}

export function decodeTakeoverCertificate(
	buf: Buffer
): IGuardianTakeoverCertificate {
	const cert: IGuardianTakeoverCertificate = {
		protocolVersion: 0,
		guardianSetId: EMPTY(),
		guardianId: EMPTY(),
		supersededState: decodeGuardianState(EMPTY()),
		newEpoch: 0n,
		newWriterPublicKey: EMPTY(),
		issuedAt: 0n,
		signature: EMPTY()
	};
	const reader = new ProtoReader(buf);
	while (!reader.done) {
		const { field, wireType } = reader.readTag();
		if (field === 1 && wireType === WIRE_VARINT) {
			cert.protocolVersion = reader.readUint32();
		} else if (field === 2 && wireType === WIRE_LEN) {
			cert.guardianSetId = reader.readBytes();
		} else if (field === 3 && wireType === WIRE_LEN) {
			cert.guardianId = reader.readBytes();
		} else if (field === 4 && wireType === WIRE_LEN) {
			cert.supersededState = decodeGuardianState(reader.readBytes());
		} else if (field === 5 && wireType === WIRE_VARINT) {
			cert.newEpoch = reader.readVarint();
		} else if (field === 6 && wireType === WIRE_LEN) {
			cert.newWriterPublicKey = reader.readBytes();
		} else if (field === 7 && wireType === WIRE_VARINT) {
			cert.issuedAt = reader.readVarint();
		} else if (field === 8 && wireType === WIRE_LEN) {
			cert.signature = reader.readBytes();
		} else {
			reader.skip(wireType);
		}
	}
	return cert;
}

// ─────────────── requests ───────────────

export function encodeRegisterNodeRequest(
	request: IGuardianRegisterNodeRequest
): Buffer {
	const writer = new ProtoWriter();
	writer.uint(1, request.protocolVersion);
	writer.bytes(2, request.guardianSetId);
	writer.message(3, encodeGuardianState(request.initialState));
	writer.bytes(4, request.rootSignature);
	return writer.finish();
}

export function decodeRegisterNodeRequest(
	buf: Buffer
): IGuardianRegisterNodeRequest {
	const request: IGuardianRegisterNodeRequest = {
		protocolVersion: 0,
		guardianSetId: EMPTY(),
		initialState: decodeGuardianState(EMPTY()),
		rootSignature: EMPTY()
	};
	const reader = new ProtoReader(buf);
	while (!reader.done) {
		const { field, wireType } = reader.readTag();
		if (field === 1 && wireType === WIRE_VARINT) {
			request.protocolVersion = reader.readUint32();
		} else if (field === 2 && wireType === WIRE_LEN) {
			request.guardianSetId = reader.readBytes();
		} else if (field === 3 && wireType === WIRE_LEN) {
			request.initialState = decodeGuardianState(reader.readBytes());
		} else if (field === 4 && wireType === WIRE_LEN) {
			request.rootSignature = reader.readBytes();
		} else {
			reader.skip(wireType);
		}
	}
	return request;
}

export function encodePutStateRequest(
	request: IGuardianPutStateRequest
): Buffer {
	const writer = new ProtoWriter();
	writer.message(1, encodeRecord(request.record));
	return writer.finish();
}

export function decodePutStateRequest(buf: Buffer): IGuardianPutStateRequest {
	let record = decodeRecord(EMPTY());
	const reader = new ProtoReader(buf);
	while (!reader.done) {
		const { field, wireType } = reader.readTag();
		if (field === 1 && wireType === WIRE_LEN) {
			record = decodeRecord(reader.readBytes());
		} else {
			reader.skip(wireType);
		}
	}
	return { record };
}

export const encodeSyncRecordRequest = (
	request: IGuardianSyncRecordRequest
): Buffer => encodePutStateRequest(request);

export const decodeSyncRecordRequest = (
	buf: Buffer
): IGuardianSyncRecordRequest => decodePutStateRequest(buf);

export function encodeGetHeadRequest(request: IGuardianGetHeadRequest): Buffer {
	const writer = new ProtoWriter();
	writer.uint(1, request.protocolVersion);
	writer.bytes(2, request.guardianSetId);
	writer.bytes(3, request.recoveryId);
	return writer.finish();
}

export function decodeGetHeadRequest(buf: Buffer): IGuardianGetHeadRequest {
	const request: IGuardianGetHeadRequest = {
		protocolVersion: 0,
		guardianSetId: EMPTY(),
		recoveryId: EMPTY()
	};
	const reader = new ProtoReader(buf);
	while (!reader.done) {
		const { field, wireType } = reader.readTag();
		if (field === 1 && wireType === WIRE_VARINT) {
			request.protocolVersion = reader.readUint32();
		} else if (field === 2 && wireType === WIRE_LEN) {
			request.guardianSetId = reader.readBytes();
		} else if (field === 3 && wireType === WIRE_LEN) {
			request.recoveryId = reader.readBytes();
		} else {
			reader.skip(wireType);
		}
	}
	return request;
}

export function encodeGetStateRequest(
	request: IGuardianGetStateRequest
): Buffer {
	const writer = new ProtoWriter();
	writer.uint(1, request.protocolVersion);
	writer.bytes(2, request.guardianSetId);
	writer.bytes(3, request.recoveryId);
	writer.uint(4, request.fromSequence);
	writer.uint(5, request.maxRecords);
	return writer.finish();
}

export function decodeGetStateRequest(buf: Buffer): IGuardianGetStateRequest {
	const request: IGuardianGetStateRequest = {
		protocolVersion: 0,
		guardianSetId: EMPTY(),
		recoveryId: EMPTY(),
		fromSequence: 0n,
		maxRecords: 0
	};
	const reader = new ProtoReader(buf);
	while (!reader.done) {
		const { field, wireType } = reader.readTag();
		if (field === 1 && wireType === WIRE_VARINT) {
			request.protocolVersion = reader.readUint32();
		} else if (field === 2 && wireType === WIRE_LEN) {
			request.guardianSetId = reader.readBytes();
		} else if (field === 3 && wireType === WIRE_LEN) {
			request.recoveryId = reader.readBytes();
		} else if (field === 4 && wireType === WIRE_VARINT) {
			request.fromSequence = reader.readVarint();
		} else if (field === 5 && wireType === WIRE_VARINT) {
			request.maxRecords = reader.readUint32();
		} else {
			reader.skip(wireType);
		}
	}
	return request;
}

export function encodeAcquireEpochRequest(
	request: IGuardianAcquireEpochRequest
): Buffer {
	const writer = new ProtoWriter();
	writer.uint(1, request.protocolVersion);
	writer.bytes(2, request.guardianSetId);
	writer.message(3, encodeGuardianState(request.expectedState));
	writer.uint(4, request.newEpoch);
	writer.bytes(5, request.newWriterPublicKey);
	writer.bytes(6, request.rootSignature);
	writer.bytes(7, request.newWriterSignature);
	return writer.finish();
}

export function decodeAcquireEpochRequest(
	buf: Buffer
): IGuardianAcquireEpochRequest {
	const request: IGuardianAcquireEpochRequest = {
		protocolVersion: 0,
		guardianSetId: EMPTY(),
		expectedState: decodeGuardianState(EMPTY()),
		newEpoch: 0n,
		newWriterPublicKey: EMPTY(),
		rootSignature: EMPTY(),
		newWriterSignature: EMPTY()
	};
	const reader = new ProtoReader(buf);
	while (!reader.done) {
		const { field, wireType } = reader.readTag();
		if (field === 1 && wireType === WIRE_VARINT) {
			request.protocolVersion = reader.readUint32();
		} else if (field === 2 && wireType === WIRE_LEN) {
			request.guardianSetId = reader.readBytes();
		} else if (field === 3 && wireType === WIRE_LEN) {
			request.expectedState = decodeGuardianState(reader.readBytes());
		} else if (field === 4 && wireType === WIRE_VARINT) {
			request.newEpoch = reader.readVarint();
		} else if (field === 5 && wireType === WIRE_LEN) {
			request.newWriterPublicKey = reader.readBytes();
		} else if (field === 6 && wireType === WIRE_LEN) {
			request.rootSignature = reader.readBytes();
		} else if (field === 7 && wireType === WIRE_LEN) {
			request.newWriterSignature = reader.readBytes();
		} else {
			reader.skip(wireType);
		}
	}
	return request;
}

export function encodeSyncEpochRequest(
	request: IGuardianSyncEpochRequest
): Buffer {
	const writer = new ProtoWriter();
	for (const cert of request.certificates) {
		writer.message(1, encodeTakeoverCertificate(cert));
	}
	return writer.finish();
}

export function decodeSyncEpochRequest(buf: Buffer): IGuardianSyncEpochRequest {
	const certificates: IGuardianTakeoverCertificate[] = [];
	const reader = new ProtoReader(buf);
	while (!reader.done) {
		const { field, wireType } = reader.readTag();
		if (field === 1 && wireType === WIRE_LEN) {
			certificates.push(decodeTakeoverCertificate(reader.readBytes()));
		} else {
			reader.skip(wireType);
		}
	}
	return { certificates };
}

// ─────────────── responses ───────────────

export function encodeRegisterNodeResponse(
	response: IGuardianRegisterNodeResponse
): Buffer {
	const writer = new ProtoWriter();
	writer.uint(1, response.status);
	writer.string(2, response.detail ?? '');
	writer.message(
		3,
		response.receipt ? encodeReceipt(response.receipt) : undefined
	);
	writer.message(
		4,
		response.current ? encodeGuardianState(response.current) : undefined
	);
	return writer.finish();
}

export function decodeRegisterNodeResponse(
	buf: Buffer
): IGuardianRegisterNodeResponse {
	const response: IGuardianRegisterNodeResponse = { status: 0 };
	const reader = new ProtoReader(buf);
	while (!reader.done) {
		const { field, wireType } = reader.readTag();
		if (field === 1 && wireType === WIRE_VARINT) {
			response.status = reader.readUint32();
		} else if (field === 2 && wireType === WIRE_LEN) {
			response.detail = reader.readString();
		} else if (field === 3 && wireType === WIRE_LEN) {
			response.receipt = decodeReceipt(reader.readBytes());
		} else if (field === 4 && wireType === WIRE_LEN) {
			response.current = decodeGuardianState(reader.readBytes());
		} else {
			reader.skip(wireType);
		}
	}
	return response;
}

export function encodePutStateResponse(
	response: IGuardianPutStateResponse
): Buffer {
	const writer = new ProtoWriter();
	writer.uint(1, response.status);
	writer.string(2, response.detail ?? '');
	writer.message(
		3,
		response.receipt ? encodeReceipt(response.receipt) : undefined
	);
	writer.message(
		4,
		response.current ? encodeGuardianState(response.current) : undefined
	);
	return writer.finish();
}

export function decodePutStateResponse(buf: Buffer): IGuardianPutStateResponse {
	const response: IGuardianPutStateResponse = { status: 0 };
	const reader = new ProtoReader(buf);
	while (!reader.done) {
		const { field, wireType } = reader.readTag();
		if (field === 1 && wireType === WIRE_VARINT) {
			response.status = reader.readUint32();
		} else if (field === 2 && wireType === WIRE_LEN) {
			response.detail = reader.readString();
		} else if (field === 3 && wireType === WIRE_LEN) {
			response.receipt = decodeReceipt(reader.readBytes());
		} else if (field === 4 && wireType === WIRE_LEN) {
			response.current = decodeGuardianState(reader.readBytes());
		} else {
			reader.skip(wireType);
		}
	}
	return response;
}

export function encodeGetHeadResponse(
	response: IGuardianGetHeadResponse
): Buffer {
	const writer = new ProtoWriter();
	writer.uint(1, response.status);
	writer.string(2, response.detail ?? '');
	writer.message(
		3,
		response.state ? encodeGuardianState(response.state) : undefined
	);
	writer.message(
		4,
		response.receipt ? encodeReceipt(response.receipt) : undefined
	);
	for (const cert of response.certificates ?? []) {
		writer.message(5, encodeTakeoverCertificate(cert));
	}
	writer.bool(6, response.possiblyStale ?? false);
	writer.message(
		7,
		response.registration
			? encodeRegisterNodeRequest(response.registration)
			: undefined
	);
	return writer.finish();
}

export function decodeGetHeadResponse(buf: Buffer): IGuardianGetHeadResponse {
	const response: IGuardianGetHeadResponse = { status: 0 };
	const certificates: IGuardianTakeoverCertificate[] = [];
	const reader = new ProtoReader(buf);
	while (!reader.done) {
		const { field, wireType } = reader.readTag();
		if (field === 1 && wireType === WIRE_VARINT) {
			response.status = reader.readUint32();
		} else if (field === 2 && wireType === WIRE_LEN) {
			response.detail = reader.readString();
		} else if (field === 3 && wireType === WIRE_LEN) {
			response.state = decodeGuardianState(reader.readBytes());
		} else if (field === 4 && wireType === WIRE_LEN) {
			response.receipt = decodeReceipt(reader.readBytes());
		} else if (field === 5 && wireType === WIRE_LEN) {
			certificates.push(decodeTakeoverCertificate(reader.readBytes()));
		} else if (field === 6 && wireType === WIRE_VARINT) {
			response.possiblyStale = reader.readVarint() !== 0n;
		} else if (field === 7 && wireType === WIRE_LEN) {
			response.registration = decodeRegisterNodeRequest(reader.readBytes());
		} else {
			reader.skip(wireType);
		}
	}
	if (response.status === 0) {
		response.certificates = certificates;
		response.possiblyStale = response.possiblyStale ?? false;
	} else if (certificates.length > 0) {
		response.certificates = certificates;
	}
	return response;
}

export function encodeGetStateResponse(
	response: IGuardianGetStateResponse
): Buffer {
	const writer = new ProtoWriter();
	writer.uint(1, response.status);
	writer.string(2, response.detail ?? '');
	for (const record of response.records ?? []) {
		writer.message(3, encodeRecord(record));
	}
	writer.bool(4, response.hasMore ?? false);
	writer.bool(5, response.possiblyStale ?? false);
	return writer.finish();
}

export function decodeGetStateResponse(buf: Buffer): IGuardianGetStateResponse {
	const response: IGuardianGetStateResponse = { status: 0 };
	const records: IGuardianRecord[] = [];
	const reader = new ProtoReader(buf);
	while (!reader.done) {
		const { field, wireType } = reader.readTag();
		if (field === 1 && wireType === WIRE_VARINT) {
			response.status = reader.readUint32();
		} else if (field === 2 && wireType === WIRE_LEN) {
			response.detail = reader.readString();
		} else if (field === 3 && wireType === WIRE_LEN) {
			records.push(decodeRecord(reader.readBytes()));
		} else if (field === 4 && wireType === WIRE_VARINT) {
			response.hasMore = reader.readVarint() !== 0n;
		} else if (field === 5 && wireType === WIRE_VARINT) {
			response.possiblyStale = reader.readVarint() !== 0n;
		} else {
			reader.skip(wireType);
		}
	}
	if (response.status === 0) {
		response.records = records;
		response.hasMore = response.hasMore ?? false;
		response.possiblyStale = response.possiblyStale ?? false;
	} else if (records.length > 0) {
		response.records = records;
	}
	return response;
}

export function encodeAcquireEpochResponse(
	response: IGuardianAcquireEpochResponse
): Buffer {
	const writer = new ProtoWriter();
	writer.uint(1, response.status);
	writer.string(2, response.detail ?? '');
	writer.message(
		3,
		response.certificate
			? encodeTakeoverCertificate(response.certificate)
			: undefined
	);
	writer.message(
		4,
		response.receipt ? encodeReceipt(response.receipt) : undefined
	);
	writer.message(
		5,
		response.current ? encodeGuardianState(response.current) : undefined
	);
	for (const cert of response.certificates ?? []) {
		writer.message(6, encodeTakeoverCertificate(cert));
	}
	return writer.finish();
}

export function decodeAcquireEpochResponse(
	buf: Buffer
): IGuardianAcquireEpochResponse {
	const response: IGuardianAcquireEpochResponse = { status: 0 };
	const certificates: IGuardianTakeoverCertificate[] = [];
	const reader = new ProtoReader(buf);
	while (!reader.done) {
		const { field, wireType } = reader.readTag();
		if (field === 1 && wireType === WIRE_VARINT) {
			response.status = reader.readUint32();
		} else if (field === 2 && wireType === WIRE_LEN) {
			response.detail = reader.readString();
		} else if (field === 3 && wireType === WIRE_LEN) {
			response.certificate = decodeTakeoverCertificate(reader.readBytes());
		} else if (field === 4 && wireType === WIRE_LEN) {
			response.receipt = decodeReceipt(reader.readBytes());
		} else if (field === 5 && wireType === WIRE_LEN) {
			response.current = decodeGuardianState(reader.readBytes());
		} else if (field === 6 && wireType === WIRE_LEN) {
			certificates.push(decodeTakeoverCertificate(reader.readBytes()));
		} else {
			reader.skip(wireType);
		}
	}
	if (certificates.length > 0) {
		response.certificates = certificates;
	}
	return response;
}

export function encodeSyncRecordResponse(
	response: IGuardianSyncRecordResponse
): Buffer {
	const writer = new ProtoWriter();
	writer.uint(1, response.status);
	writer.string(2, response.detail ?? '');
	writer.message(
		3,
		response.receipt ? encodeReceipt(response.receipt) : undefined
	);
	return writer.finish();
}

export function decodeSyncRecordResponse(
	buf: Buffer
): IGuardianSyncRecordResponse {
	const response: IGuardianSyncRecordResponse = { status: 0 };
	const reader = new ProtoReader(buf);
	while (!reader.done) {
		const { field, wireType } = reader.readTag();
		if (field === 1 && wireType === WIRE_VARINT) {
			response.status = reader.readUint32();
		} else if (field === 2 && wireType === WIRE_LEN) {
			response.detail = reader.readString();
		} else if (field === 3 && wireType === WIRE_LEN) {
			response.receipt = decodeReceipt(reader.readBytes());
		} else {
			reader.skip(wireType);
		}
	}
	return response;
}

export function encodeSyncEpochResponse(
	response: IGuardianSyncEpochResponse
): Buffer {
	const writer = new ProtoWriter();
	writer.uint(1, response.status);
	writer.string(2, response.detail ?? '');
	writer.message(
		3,
		response.certificate
			? encodeTakeoverCertificate(response.certificate)
			: undefined
	);
	writer.message(
		4,
		response.receipt ? encodeReceipt(response.receipt) : undefined
	);
	return writer.finish();
}

export function decodeSyncEpochResponse(
	buf: Buffer
): IGuardianSyncEpochResponse {
	const response: IGuardianSyncEpochResponse = { status: 0 };
	const reader = new ProtoReader(buf);
	while (!reader.done) {
		const { field, wireType } = reader.readTag();
		if (field === 1 && wireType === WIRE_VARINT) {
			response.status = reader.readUint32();
		} else if (field === 2 && wireType === WIRE_LEN) {
			response.detail = reader.readString();
		} else if (field === 3 && wireType === WIRE_LEN) {
			response.certificate = decodeTakeoverCertificate(reader.readBytes());
		} else if (field === 4 && wireType === WIRE_LEN) {
			response.receipt = decodeReceipt(reader.readBytes());
		} else {
			reader.skip(wireType);
		}
	}
	return response;
}

export function encodeInfoResponse(info: IGuardianInfoResponse): Buffer {
	const writer = new ProtoWriter();
	writer.bytes(1, info.guardianId);
	writer.uint(2, info.minProtocolVersion);
	writer.uint(3, info.maxProtocolVersion);
	for (const setId of info.guardianSetIds) {
		writer.bytes(4, setId);
	}
	writer.uint(5, BigInt(info.maxCiphertextBytes));
	writer.uint(6, info.maxRecordsPerGet);
	writer.uint(7, info.rateLimitPerMinute);
	return writer.finish();
}

export function decodeInfoResponse(buf: Buffer): IGuardianInfoResponse {
	const info: IGuardianInfoResponse = {
		guardianId: EMPTY(),
		minProtocolVersion: 0,
		maxProtocolVersion: 0,
		guardianSetIds: [],
		maxCiphertextBytes: 0,
		maxRecordsPerGet: 0,
		rateLimitPerMinute: 0
	};
	const reader = new ProtoReader(buf);
	while (!reader.done) {
		const { field, wireType } = reader.readTag();
		if (field === 1 && wireType === WIRE_LEN) {
			info.guardianId = reader.readBytes();
		} else if (field === 2 && wireType === WIRE_VARINT) {
			info.minProtocolVersion = reader.readUint32();
		} else if (field === 3 && wireType === WIRE_VARINT) {
			info.maxProtocolVersion = reader.readUint32();
		} else if (field === 4 && wireType === WIRE_LEN) {
			info.guardianSetIds.push(reader.readBytes());
		} else if (field === 5 && wireType === WIRE_VARINT) {
			const value = reader.readVarint();
			if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
				throw new Error('max_ciphertext_bytes out of range');
			}
			info.maxCiphertextBytes = Number(value);
		} else if (field === 6 && wireType === WIRE_VARINT) {
			info.maxRecordsPerGet = reader.readUint32();
		} else if (field === 7 && wireType === WIRE_VARINT) {
			info.rateLimitPerMinute = reader.readUint32();
		} else {
			reader.skip(wireType);
		}
	}
	return info;
}
