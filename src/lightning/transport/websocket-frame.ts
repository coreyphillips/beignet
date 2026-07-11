/**
 * Minimal RFC 6455 WebSocket frame codec (server-side needs only).
 *
 * Beignet's WS listener implements the framing layer in-repo instead of
 * depending on the `ws` package: the Noise layer above provides all
 * authentication and confidentiality, so the WS layer only has to frame
 * bytes correctly — a small, fully-tested surface is a better supply-chain
 * trade than a large external dependency for a wallet library.
 *
 * Covers: frame parse/build, client masking rules, extended lengths,
 * fragmentation sequencing, control-frame rules, close codes, and a
 * configurable payload sanity cap (default 16 MiB).
 */

export const WsOpcode = {
	CONTINUATION: 0x0,
	TEXT: 0x1,
	BINARY: 0x2,
	CLOSE: 0x8,
	PING: 0x9,
	PONG: 0xa
} as const;

export const WsCloseCode = {
	NORMAL: 1000,
	GOING_AWAY: 1001,
	PROTOCOL_ERROR: 1002,
	UNSUPPORTED_DATA: 1003,
	MESSAGE_TOO_BIG: 1009,
	INTERNAL_ERROR: 1011
} as const;

/** Default per-frame payload sanity cap: 16 MiB. */
export const DEFAULT_MAX_WS_PAYLOAD_BYTES = 16 * 1024 * 1024;

const MAX_CONTROL_PAYLOAD = 125;

/** Fatal WS protocol violation; closeCode is sent in the close frame. */
export class WsProtocolError extends Error {
	readonly closeCode: number;

	constructor(closeCode: number, message: string) {
		super(message);
		this.name = 'WsProtocolError';
		this.closeCode = closeCode;
	}
}

export interface IWsFrame {
	fin: boolean;
	opcode: number;
	masked: boolean;
	payload: Buffer;
}

/** XOR `payload` with the 4-byte mask key (returns a new Buffer). */
export function applyWsMask(payload: Buffer, maskKey: Buffer): Buffer {
	const out = Buffer.allocUnsafe(payload.length);
	for (let i = 0; i < payload.length; i++) {
		out[i] = payload[i] ^ maskKey[i & 3];
	}
	return out;
}

/**
 * Build a single WebSocket frame. Server-to-client frames MUST NOT be
 * masked (omit maskKey); client-to-server frames MUST be masked (pass a
 * 4-byte maskKey — used by tests to synthesize client traffic).
 */
export function encodeWsFrame(opts: {
	opcode: number;
	payload?: Buffer;
	fin?: boolean;
	maskKey?: Buffer;
}): Buffer {
	const payload = opts.payload ?? Buffer.alloc(0);
	const fin = opts.fin ?? true;
	if (opts.maskKey && opts.maskKey.length !== 4) {
		throw new Error('WebSocket mask key must be 4 bytes');
	}

	let headerLen = 2;
	if (payload.length > 65535) headerLen += 8;
	else if (payload.length > 125) headerLen += 2;
	if (opts.maskKey) headerLen += 4;

	const frame = Buffer.allocUnsafe(headerLen + payload.length);
	frame[0] = (fin ? 0x80 : 0x00) | (opts.opcode & 0x0f);

	let offset = 2;
	if (payload.length > 65535) {
		frame[1] = 127;
		frame.writeBigUInt64BE(BigInt(payload.length), 2);
		offset = 10;
	} else if (payload.length > 125) {
		frame[1] = 126;
		frame.writeUInt16BE(payload.length, 2);
		offset = 4;
	} else {
		frame[1] = payload.length;
	}

	if (opts.maskKey) {
		frame[1] |= 0x80;
		opts.maskKey.copy(frame, offset);
		offset += 4;
		applyWsMask(payload, opts.maskKey).copy(frame, offset);
	} else {
		payload.copy(frame, offset);
	}
	return frame;
}

/** Build a close frame payload (2-byte code + optional UTF-8 reason). */
export function encodeWsClosePayload(code: number, reason = ''): Buffer {
	const reasonBuf = Buffer.from(reason, 'utf8').subarray(
		0,
		MAX_CONTROL_PAYLOAD - 2
	);
	const payload = Buffer.allocUnsafe(2 + reasonBuf.length);
	payload.writeUInt16BE(code, 0);
	reasonBuf.copy(payload, 2);
	return payload;
}

/** Parse a close frame payload into { code, reason }. */
export function decodeWsClosePayload(payload: Buffer): {
	code: number;
	reason: string;
} {
	if (payload.length === 0) return { code: WsCloseCode.NORMAL, reason: '' };
	if (payload.length === 1) {
		throw new WsProtocolError(
			WsCloseCode.PROTOCOL_ERROR,
			'Close frame payload must be 0 or >= 2 bytes'
		);
	}
	return {
		code: payload.readUInt16BE(0),
		reason: payload.subarray(2).toString('utf8')
	};
}

/**
 * Incremental WebSocket frame parser. Feed raw socket bytes to push();
 * complete frames come back unmasked. Throws WsProtocolError on violations
 * (caller sends the closeCode and drops the connection).
 */
export class WsFrameParser {
	private buffer: Buffer = Buffer.alloc(0);
	private readonly maxPayloadBytes: number;
	private readonly requireMasked: boolean;

	constructor(opts?: { maxPayloadBytes?: number; requireMasked?: boolean }) {
		this.maxPayloadBytes =
			opts?.maxPayloadBytes ?? DEFAULT_MAX_WS_PAYLOAD_BYTES;
		this.requireMasked = opts?.requireMasked ?? true;
	}

	/** Bytes currently buffered awaiting a complete frame. */
	get bufferedLength(): number {
		return this.buffer.length;
	}

	push(data: Buffer): IWsFrame[] {
		this.buffer = this.buffer.length
			? Buffer.concat([this.buffer, data])
			: data;
		const frames: IWsFrame[] = [];
		for (;;) {
			const frame = this.tryParseFrame();
			if (!frame) return frames;
			frames.push(frame);
		}
	}

	private tryParseFrame(): IWsFrame | null {
		const buf = this.buffer;
		if (buf.length < 2) return null;

		const b0 = buf[0];
		const b1 = buf[1];
		const fin = (b0 & 0x80) !== 0;
		const rsv = (b0 >> 4) & 0x07;
		const opcode = b0 & 0x0f;
		const masked = (b1 & 0x80) !== 0;
		const len7 = b1 & 0x7f;

		if (rsv !== 0) {
			throw new WsProtocolError(
				WsCloseCode.PROTOCOL_ERROR,
				'RSV bits set without a negotiated extension'
			);
		}
		const isControl = (opcode & 0x08) !== 0;
		const isKnown =
			opcode === WsOpcode.CONTINUATION ||
			opcode === WsOpcode.TEXT ||
			opcode === WsOpcode.BINARY ||
			opcode === WsOpcode.CLOSE ||
			opcode === WsOpcode.PING ||
			opcode === WsOpcode.PONG;
		if (!isKnown) {
			throw new WsProtocolError(
				WsCloseCode.PROTOCOL_ERROR,
				`Reserved WebSocket opcode 0x${opcode.toString(16)}`
			);
		}
		if (isControl) {
			if (!fin) {
				throw new WsProtocolError(
					WsCloseCode.PROTOCOL_ERROR,
					'Control frames must not be fragmented'
				);
			}
			if (len7 > MAX_CONTROL_PAYLOAD) {
				throw new WsProtocolError(
					WsCloseCode.PROTOCOL_ERROR,
					'Control frame payload exceeds 125 bytes'
				);
			}
		}
		if (this.requireMasked && !masked) {
			throw new WsProtocolError(
				WsCloseCode.PROTOCOL_ERROR,
				'Client-to-server frames must be masked'
			);
		}

		let offset = 2;
		let payloadLen = len7;
		if (len7 === 126) {
			if (buf.length < offset + 2) return null;
			payloadLen = buf.readUInt16BE(offset);
			offset += 2;
			if (payloadLen < 126) {
				throw new WsProtocolError(
					WsCloseCode.PROTOCOL_ERROR,
					'Non-minimal 16-bit length encoding'
				);
			}
		} else if (len7 === 127) {
			if (buf.length < offset + 8) return null;
			const big = buf.readBigUInt64BE(offset);
			offset += 8;
			if (big < 65536n) {
				throw new WsProtocolError(
					WsCloseCode.PROTOCOL_ERROR,
					'Non-minimal 64-bit length encoding'
				);
			}
			if (big > BigInt(this.maxPayloadBytes)) {
				throw new WsProtocolError(
					WsCloseCode.MESSAGE_TOO_BIG,
					`Frame payload ${big} exceeds cap ${this.maxPayloadBytes}`
				);
			}
			payloadLen = Number(big);
		}
		// Cap applies to every declared length (checked before buffering the
		// payload, so an attacker cannot make us accumulate an oversize frame).
		if (payloadLen > this.maxPayloadBytes) {
			throw new WsProtocolError(
				WsCloseCode.MESSAGE_TOO_BIG,
				`Frame payload ${payloadLen} exceeds cap ${this.maxPayloadBytes}`
			);
		}

		let maskKey: Buffer | null = null;
		if (masked) {
			if (buf.length < offset + 4) return null;
			maskKey = buf.subarray(offset, offset + 4);
			offset += 4;
		}

		if (buf.length < offset + payloadLen) return null;
		let payload = buf.subarray(offset, offset + payloadLen);
		payload = maskKey ? applyWsMask(payload, maskKey) : Buffer.from(payload);
		this.buffer = this.buffer.subarray(offset + payloadLen);

		return { fin, opcode, masked, payload };
	}
}
