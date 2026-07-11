/**
 * Minimal RFC 6455 WebSocket CLIENT for Node (net/tls based).
 *
 * Why this exists: CLN's WebSocket listener (`bind-addr=ws:`) parses the
 * HTTP upgrade with case-SENSITIVE literal matching — it requires exactly
 * `Connection: Upgrade`, `Upgrade: websocket`, `Sec-WebSocket-Key` and
 * `Sec-WebSocket-Version`. Node's built-in WebSocket (undici) lowercases
 * every request header, so it can never complete CLN's handshake (verified
 * against CLN v26.06.1: "400 I only speak websocket"). Browsers send
 * RFC-cased headers and work fine.
 *
 * This client implements the same IWebSocketLike surface the transport layer
 * consumes, sends RFC-cased headers, and reuses the audited in-repo frame
 * codec — so Node gets CLN interop with zero new dependencies while browser
 * builds keep using the native WebSocket.
 */

import net from 'net';
import tls from 'tls';
import crypto from 'crypto';
import { IWebSocketLike, parseWebSocketUrl } from './websocket';
import { computeWebSocketAccept } from './websocket-server';
import {
	WsFrameParser,
	WsProtocolError,
	WsOpcode,
	WsCloseCode,
	IWsFrame,
	encodeWsFrame,
	encodeWsClosePayload,
	DEFAULT_MAX_WS_PAYLOAD_BYTES
} from './websocket-frame';

const CONNECTING = 0;
const OPEN = 1;
const CLOSING = 2;
const CLOSED = 3;

/**
 * Standard-shaped WebSocket client over net/tls for Node. Construct with
 * `new NodeWebSocket(url)` — the same signature the injectable
 * WebSocketConstructor expects, so it drops into webSocketImpl directly.
 * Binary-only delivery is exercised (binaryType 'arraybuffer'); text frames
 * are surfaced as strings so the transport layer can reject them.
 */
export class NodeWebSocket implements IWebSocketLike {
	binaryType = 'arraybuffer';
	readyState: number = CONNECTING;

	onopen: ((ev?: unknown) => void) | null = null;
	onmessage: ((ev: { data: unknown }) => void) | null = null;
	onclose:
		| ((ev?: { code?: number; reason?: string; wasClean?: boolean }) => void)
		| null = null;
	onerror: ((ev?: unknown) => void) | null = null;

	private socket: net.Socket | null = null;
	private parser = new WsFrameParser({
		maxPayloadBytes: DEFAULT_MAX_WS_PAYLOAD_BYTES,
		requireMasked: false // server-to-client frames are unmasked
	});
	private handshakeBuffer = Buffer.alloc(0);
	private handshakeDone = false;
	private closeSent = false;
	private closeReceived: { code?: number; reason?: string } | null = null;
	private closedFired = false;
	// Reassembles a fragmented server message (message-level API contract)
	private fragments: Buffer[] = [];
	private fragmentBytes = 0;
	private fragmentText = false;
	private fragmentInProgress = false;

	constructor(url: string) {
		const { host, port, secure } = parseWebSocketUrl(url);
		const key = crypto.randomBytes(16).toString('base64');
		const parsedPath = ((): string => {
			try {
				const u = new URL(url);
				return `${u.pathname || '/'}${u.search || ''}`;
			} catch {
				return '/';
			}
		})();

		const onConnect = (): void => {
			// RFC-cased headers: CLN's handshake parser matches these literally.
			this.socket!.write(
				`GET ${parsedPath} HTTP/1.1\r\n` +
					`Host: ${host.includes(':') ? `[${host}]` : host}:${port}\r\n` +
					'Connection: Upgrade\r\n' +
					'Upgrade: websocket\r\n' +
					`Sec-WebSocket-Key: ${key}\r\n` +
					'Sec-WebSocket-Version: 13\r\n' +
					'\r\n'
			);
		};

		const socket = secure
			? tls.connect({ host, port, servername: host }, onConnect)
			: net.connect({ host, port }, onConnect);
		this.socket = socket;
		socket.setNoDelay(true);

		socket.on('data', (chunk: Buffer) => {
			if (!this.handshakeDone) {
				this.handleHandshakeData(chunk, key);
			} else {
				this.handleFrames(chunk);
			}
		});
		socket.on('error', (err: Error) => {
			this.failConnection(err);
		});
		socket.on('close', () => {
			if (this.readyState === CLOSED) return;
			const wasOpen = this.readyState === OPEN;
			this.readyState = CLOSED;
			this.fireClose(
				this.closeReceived?.code ??
					(wasOpen ? WsCloseCode.GOING_AWAY : undefined),
				this.closeReceived?.reason ?? '',
				this.closeReceived !== null
			);
		});
	}

	get bufferedAmount(): number {
		return this.socket ? this.socket.writableLength : 0;
	}

	send(data: Uint8Array): void {
		if (this.readyState === CONNECTING) {
			throw new Error('NodeWebSocket: cannot send while CONNECTING');
		}
		if (this.readyState !== OPEN || !this.socket) {
			return; // CLOSING/CLOSED: standard behavior is to discard
		}
		const payload = Buffer.isBuffer(data)
			? data
			: Buffer.from(data.buffer, data.byteOffset, data.byteLength);
		this.socket.write(
			encodeWsFrame({
				opcode: WsOpcode.BINARY,
				payload,
				maskKey: crypto.randomBytes(4) // client frames MUST be masked
			})
		);
	}

	close(code = WsCloseCode.NORMAL, reason = ''): void {
		if (this.readyState === CLOSED || this.readyState === CLOSING) {
			return;
		}
		if (this.readyState === CONNECTING || !this.handshakeDone) {
			this.readyState = CLOSED;
			this.socket?.destroy();
			this.fireClose(undefined, '', false);
			return;
		}
		this.readyState = CLOSING;
		this.sendCloseFrame(code, reason);
		// Give the server a moment to echo the close, then drop the TCP link.
		const timer = setTimeout(() => this.socket?.destroy(), 1000);
		if (timer.unref) timer.unref();
	}

	// ── Internal ─────────────────────────────────────────────────

	private handleHandshakeData(chunk: Buffer, key: string): void {
		this.handshakeBuffer = Buffer.concat([this.handshakeBuffer, chunk]);
		if (this.handshakeBuffer.length > 16384) {
			this.failConnection(
				new Error('NodeWebSocket: oversized handshake response')
			);
			return;
		}
		const idx = this.handshakeBuffer.indexOf('\r\n\r\n');
		if (idx < 0) return;

		const header = this.handshakeBuffer.subarray(0, idx).toString('latin1');
		const rest = this.handshakeBuffer.subarray(idx + 4);
		this.handshakeBuffer = Buffer.alloc(0);

		const lines = header.split('\r\n');
		const status = lines[0];
		if (!/^HTTP\/1\.1 101/.test(status)) {
			this.failConnection(
				new Error(`NodeWebSocket: server refused upgrade: ${status}`)
			);
			return;
		}
		const headers = new Map<string, string>();
		for (const line of lines.slice(1)) {
			const colon = line.indexOf(':');
			if (colon > 0) {
				headers.set(
					line.slice(0, colon).trim().toLowerCase(),
					line.slice(colon + 1).trim()
				);
			}
		}
		if (
			(headers.get('upgrade') || '').toLowerCase() !== 'websocket' ||
			headers.get('sec-websocket-accept') !== computeWebSocketAccept(key)
		) {
			this.failConnection(
				new Error('NodeWebSocket: invalid upgrade response headers')
			);
			return;
		}

		this.handshakeDone = true;
		this.readyState = OPEN;
		if (this.onopen) this.onopen();
		if (rest.length > 0) this.handleFrames(Buffer.from(rest));
	}

	private handleFrames(chunk: Buffer): void {
		let frames: IWsFrame[];
		try {
			frames = this.parser.push(chunk);
		} catch (err) {
			const code =
				err instanceof WsProtocolError
					? err.closeCode
					: WsCloseCode.INTERNAL_ERROR;
			this.sendCloseFrame(code, (err as Error).message);
			this.failConnection(err as Error);
			return;
		}
		for (const frame of frames) {
			if (this.readyState === CLOSED) return;
			this.handleFrame(frame);
		}
	}

	private handleFrame(frame: IWsFrame): void {
		switch (frame.opcode) {
			case WsOpcode.BINARY:
			case WsOpcode.TEXT:
				if (this.fragmentInProgress) {
					this.protocolFail('data frame during fragmented message');
					return;
				}
				if (!frame.fin) {
					this.fragmentInProgress = true;
					this.fragmentText = frame.opcode === WsOpcode.TEXT;
					this.pushFragment(frame.payload);
					return;
				}
				this.deliver(frame.payload, frame.opcode === WsOpcode.TEXT);
				return;

			case WsOpcode.CONTINUATION: {
				if (!this.fragmentInProgress) {
					this.protocolFail('continuation without fragmented message');
					return;
				}
				if (!this.pushFragment(frame.payload)) return;
				if (frame.fin) {
					const message = Buffer.concat(this.fragments);
					const wasText = this.fragmentText;
					this.fragments = [];
					this.fragmentBytes = 0;
					this.fragmentInProgress = false;
					this.deliver(message, wasText);
				}
				return;
			}

			case WsOpcode.PING:
				if (this.socket && this.readyState === OPEN) {
					this.socket.write(
						encodeWsFrame({
							opcode: WsOpcode.PONG,
							payload: frame.payload,
							maskKey: crypto.randomBytes(4)
						})
					);
				}
				return;

			case WsOpcode.PONG:
				return;

			case WsOpcode.CLOSE: {
				let code: number | undefined;
				let reason = '';
				if (frame.payload.length >= 2) {
					code = frame.payload.readUInt16BE(0);
					reason = frame.payload.subarray(2).toString('utf8');
				}
				this.closeReceived = { code, reason };
				this.sendCloseFrame(code ?? WsCloseCode.NORMAL, '');
				this.readyState = CLOSING;
				this.socket?.end();
				const timer = setTimeout(() => this.socket?.destroy(), 1000);
				if (timer.unref) timer.unref();
				return;
			}

			default:
				this.protocolFail('unexpected opcode');
		}
	}

	private pushFragment(payload: Buffer): boolean {
		this.fragmentBytes += payload.length;
		if (this.fragmentBytes > DEFAULT_MAX_WS_PAYLOAD_BYTES) {
			this.sendCloseFrame(WsCloseCode.MESSAGE_TOO_BIG, '');
			this.failConnection(
				new Error('NodeWebSocket: fragmented message exceeds cap')
			);
			return false;
		}
		this.fragments.push(payload);
		return true;
	}

	private deliver(payload: Buffer, isText: boolean): void {
		if (!this.onmessage) return;
		if (isText) {
			// Text frames are surfaced as strings (the BOLT 8 transport layer
			// treats them as a protocol violation and disconnects).
			this.onmessage({ data: payload.toString('utf8') });
			return;
		}
		// Fresh ArrayBuffer copy (binaryType 'arraybuffer' semantics)
		const ab = payload.buffer.slice(
			payload.byteOffset,
			payload.byteOffset + payload.byteLength
		);
		this.onmessage({ data: ab });
	}

	private sendCloseFrame(code: number, reason: string): void {
		if (this.closeSent) return;
		this.closeSent = true;
		if (!this.socket || this.socket.destroyed || !this.socket.writable) {
			return;
		}
		try {
			this.socket.write(
				encodeWsFrame({
					opcode: WsOpcode.CLOSE,
					payload: encodeWsClosePayload(code, reason),
					maskKey: crypto.randomBytes(4)
				})
			);
		} catch {
			// Socket already going away
		}
	}

	private protocolFail(message: string): void {
		this.sendCloseFrame(WsCloseCode.PROTOCOL_ERROR, message);
		this.failConnection(new Error(`NodeWebSocket: ${message}`));
	}

	private failConnection(err: Error): void {
		if (this.readyState === CLOSED) return;
		this.readyState = CLOSED;
		if (this.onerror) this.onerror(err);
		this.socket?.destroy();
		this.fireClose(undefined, '', false);
	}

	private fireClose(code?: number, reason = '', wasClean = false): void {
		if (this.closedFired) return;
		this.closedFired = true;
		this.readyState = CLOSED;
		if (this.onclose) this.onclose({ code, reason, wasClean });
	}
}
