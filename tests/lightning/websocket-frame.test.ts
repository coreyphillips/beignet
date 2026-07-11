/**
 * RFC 6455 WebSocket frame codec vectors.
 *
 * Exercises the in-repo framing layer used by the WS peer listener:
 * masked/unmasked frames, extended lengths, minimal-encoding rules,
 * control-frame rules, fragmentation, close payloads and the payload cap.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	WsFrameParser,
	WsProtocolError,
	WsOpcode,
	WsCloseCode,
	encodeWsFrame,
	encodeWsClosePayload,
	decodeWsClosePayload,
	applyWsMask,
	DEFAULT_MAX_WS_PAYLOAD_BYTES
} from '../../src/lightning/transport/websocket-frame';
import { computeWebSocketAccept } from '../../src/lightning/transport/websocket-server';

describe('WebSocket frame codec (RFC 6455)', function () {
	describe('encodeWsFrame', function () {
		it('encodes a small unmasked binary frame', function () {
			const payload = Buffer.from([1, 2, 3]);
			const frame = encodeWsFrame({ opcode: WsOpcode.BINARY, payload });
			expect(frame[0]).to.equal(0x82); // FIN + binary
			expect(frame[1]).to.equal(3); // unmasked, len 3
			expect(frame.subarray(2).equals(payload)).to.equal(true);
		});

		it('encodes a masked client frame (RFC 6455 masking)', function () {
			const payload = Buffer.from('Hello');
			const maskKey = Buffer.from([0x37, 0xfa, 0x21, 0x3d]);
			const frame = encodeWsFrame({
				opcode: WsOpcode.TEXT,
				payload,
				maskKey
			});
			// RFC 6455 §5.7 example: masked "Hello" text frame
			expect(frame.toString('hex')).to.equal('818537fa213d7f9f4d5158');
		});

		it('uses 16-bit extended length for 126..65535', function () {
			const payload = Buffer.alloc(126, 0xaa);
			const frame = encodeWsFrame({ opcode: WsOpcode.BINARY, payload });
			expect(frame[1]).to.equal(126);
			expect(frame.readUInt16BE(2)).to.equal(126);
			expect(frame.length).to.equal(4 + 126);
		});

		it('uses 64-bit extended length above 65535', function () {
			const payload = Buffer.alloc(65536);
			const frame = encodeWsFrame({ opcode: WsOpcode.BINARY, payload });
			expect(frame[1]).to.equal(127);
			expect(Number(frame.readBigUInt64BE(2))).to.equal(65536);
		});

		it('rejects a bad mask key length', function () {
			expect(() =>
				encodeWsFrame({
					opcode: WsOpcode.BINARY,
					payload: Buffer.alloc(1),
					maskKey: Buffer.alloc(3)
				})
			).to.throw('4 bytes');
		});

		it('supports non-FIN (fragment) frames', function () {
			const frame = encodeWsFrame({
				opcode: WsOpcode.BINARY,
				payload: Buffer.alloc(1),
				fin: false
			});
			expect(frame[0] & 0x80).to.equal(0);
		});
	});

	describe('applyWsMask', function () {
		it('is an involution (mask twice = identity)', function () {
			const payload = crypto.randomBytes(100);
			const key = crypto.randomBytes(4);
			const once = applyWsMask(payload, key);
			const twice = applyWsMask(once, key);
			expect(twice.equals(payload)).to.equal(true);
			expect(once.equals(payload)).to.equal(false);
		});
	});

	describe('WsFrameParser', function () {
		function parserFor(opts?: {
			maxPayloadBytes?: number;
			requireMasked?: boolean;
		}): WsFrameParser {
			return new WsFrameParser(opts ?? { requireMasked: false });
		}

		it('parses an unmasked binary frame (server-to-client mode)', function () {
			const payload = crypto.randomBytes(10);
			const frames = parserFor().push(
				encodeWsFrame({ opcode: WsOpcode.BINARY, payload })
			);
			expect(frames.length).to.equal(1);
			expect(frames[0].opcode).to.equal(WsOpcode.BINARY);
			expect(frames[0].fin).to.equal(true);
			expect(frames[0].payload.equals(payload)).to.equal(true);
		});

		it('parses and unmasks a masked client frame', function () {
			const payload = crypto.randomBytes(50);
			const maskKey = crypto.randomBytes(4);
			const parser = new WsFrameParser(); // requireMasked defaults true
			const frames = parser.push(
				encodeWsFrame({ opcode: WsOpcode.BINARY, payload, maskKey })
			);
			expect(frames.length).to.equal(1);
			expect(frames[0].masked).to.equal(true);
			expect(frames[0].payload.equals(payload)).to.equal(true);
		});

		it('rejects unmasked client frames when masking is required', function () {
			const parser = new WsFrameParser();
			try {
				parser.push(
					encodeWsFrame({
						opcode: WsOpcode.BINARY,
						payload: Buffer.alloc(1)
					})
				);
				expect.fail('should have thrown');
			} catch (err) {
				expect(err).to.be.instanceOf(WsProtocolError);
				expect((err as WsProtocolError).closeCode).to.equal(
					WsCloseCode.PROTOCOL_ERROR
				);
			}
		});

		it('reassembles frames split across arbitrary chunk boundaries', function () {
			const payload = crypto.randomBytes(300); // forces 16-bit length
			const frame = encodeWsFrame({
				opcode: WsOpcode.BINARY,
				payload,
				maskKey: crypto.randomBytes(4)
			});
			const parser = new WsFrameParser();
			const collected: Buffer[] = [];
			// Feed one byte at a time — worst-case fragmentation
			for (let i = 0; i < frame.length; i++) {
				for (const f of parser.push(frame.subarray(i, i + 1))) {
					collected.push(f.payload);
				}
			}
			expect(Buffer.concat(collected).equals(payload)).to.equal(true);
			expect(parser.bufferedLength).to.equal(0);
		});

		it('parses multiple frames from a single chunk', function () {
			const p1 = Buffer.from('one');
			const p2 = Buffer.from('two!');
			const chunk = Buffer.concat([
				encodeWsFrame({ opcode: WsOpcode.BINARY, payload: p1 }),
				encodeWsFrame({ opcode: WsOpcode.BINARY, payload: p2 })
			]);
			const frames = parserFor().push(chunk);
			expect(frames.length).to.equal(2);
			expect(frames[0].payload.equals(p1)).to.equal(true);
			expect(frames[1].payload.equals(p2)).to.equal(true);
		});

		it('parses 16-bit and 64-bit extended lengths', function () {
			const p16 = crypto.randomBytes(4568); // 126..65535 → 16-bit length
			const p64 = crypto.randomBytes(66_000);
			const parser = parserFor();
			const frames = [
				...parser.push(
					encodeWsFrame({ opcode: WsOpcode.BINARY, payload: p16 })
				),
				...parser.push(encodeWsFrame({ opcode: WsOpcode.BINARY, payload: p64 }))
			];
			expect(frames.length).to.equal(2);
			expect(frames[0].payload.equals(p16)).to.equal(true);
			expect(frames[1].payload.equals(p64)).to.equal(true);
		});

		it('rejects non-minimal length encodings', function () {
			// 16-bit length field carrying a value < 126
			const bad16 = Buffer.from([0x82, 126, 0x00, 0x05, 1, 2, 3, 4, 5]);
			expect(() => parserFor().push(bad16)).to.throw(WsProtocolError);
			// 64-bit length field carrying a value < 65536
			const len64 = Buffer.alloc(8);
			len64.writeBigUInt64BE(5n);
			const bad64 = Buffer.concat([
				Buffer.from([0x82, 127]),
				len64,
				Buffer.alloc(5)
			]);
			expect(() => parserFor().push(bad64)).to.throw(WsProtocolError);
		});

		it('rejects RSV bits (no extension negotiated)', function () {
			const frame = encodeWsFrame({
				opcode: WsOpcode.BINARY,
				payload: Buffer.alloc(1)
			});
			frame[0] |= 0x40; // RSV1
			expect(() => parserFor().push(frame)).to.throw(/RSV/);
		});

		it('rejects reserved opcodes', function () {
			const frame = encodeWsFrame({
				opcode: 0x3,
				payload: Buffer.alloc(0)
			});
			expect(() => parserFor().push(frame)).to.throw(/opcode/i);
		});

		it('rejects fragmented control frames', function () {
			const frame = encodeWsFrame({
				opcode: WsOpcode.PING,
				payload: Buffer.alloc(0),
				fin: false
			});
			expect(() => parserFor().push(frame)).to.throw(/fragmented/i);
		});

		it('rejects control frames with payload > 125', function () {
			// Hand-build: ping with 16-bit length 126
			const frame = Buffer.concat([
				Buffer.from([0x89, 126, 0x00, 0x7e]),
				Buffer.alloc(126)
			]);
			expect(() => parserFor().push(frame)).to.throw(/125/);
		});

		it('enforces the payload sanity cap with MESSAGE_TOO_BIG', function () {
			const parser = new WsFrameParser({
				maxPayloadBytes: 1024,
				requireMasked: false
			});
			const header = Buffer.from([0x82, 126, 0x08, 0x00]); // declares 2048
			try {
				parser.push(header);
				expect.fail('should have thrown');
			} catch (err) {
				expect((err as WsProtocolError).closeCode).to.equal(
					WsCloseCode.MESSAGE_TOO_BIG
				);
			}
		});

		it('rejects oversize 64-bit declared lengths without buffering', function () {
			const parser = parserFor();
			const header = Buffer.alloc(10);
			header[0] = 0x82;
			header[1] = 127;
			header.writeBigUInt64BE(BigInt(DEFAULT_MAX_WS_PAYLOAD_BYTES) + 1n, 2);
			try {
				parser.push(header);
				expect.fail('should have thrown');
			} catch (err) {
				expect((err as WsProtocolError).closeCode).to.equal(
					WsCloseCode.MESSAGE_TOO_BIG
				);
			}
		});

		it('parses ping and pong control frames', function () {
			const body = Buffer.from('keepalive');
			const parser = parserFor();
			const frames = [
				...parser.push(encodeWsFrame({ opcode: WsOpcode.PING, payload: body })),
				...parser.push(encodeWsFrame({ opcode: WsOpcode.PONG, payload: body }))
			];
			expect(frames.length).to.equal(2);
			expect(frames[0].opcode).to.equal(WsOpcode.PING);
			expect(frames[1].opcode).to.equal(WsOpcode.PONG);
			expect(frames[0].payload.equals(body)).to.equal(true);
		});
	});

	describe('close payloads', function () {
		it('round-trips code + reason', function () {
			const payload = encodeWsClosePayload(
				WsCloseCode.GOING_AWAY,
				'restarting'
			);
			const decoded = decodeWsClosePayload(payload);
			expect(decoded.code).to.equal(WsCloseCode.GOING_AWAY);
			expect(decoded.reason).to.equal('restarting');
		});

		it('treats an empty close payload as NORMAL', function () {
			const decoded = decodeWsClosePayload(Buffer.alloc(0));
			expect(decoded.code).to.equal(WsCloseCode.NORMAL);
		});

		it('rejects a 1-byte close payload', function () {
			expect(() => decodeWsClosePayload(Buffer.alloc(1))).to.throw(
				WsProtocolError
			);
		});

		it('truncates over-long reasons to fit a control frame', function () {
			const payload = encodeWsClosePayload(1000, 'x'.repeat(500));
			expect(payload.length).to.be.at.most(125);
		});
	});

	describe('Sec-WebSocket-Accept', function () {
		it('matches the RFC 6455 §4.2.2 example vector', function () {
			expect(computeWebSocketAccept('dGhlIHNhbXBsZSBub25jZQ==')).to.equal(
				's3pPLMBiTxaQ9kYGzzhZRbK+xOo='
			);
		});
	});
});
