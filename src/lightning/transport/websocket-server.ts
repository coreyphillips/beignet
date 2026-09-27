/**
 * Minimal RFC 6455 WebSocket server for inbound Lightning peers (Node only).
 *
 * Accepts HTTP Upgrade requests (Sec-WebSocket-Accept per RFC 6455 §4.2.2),
 * then wraps the raw TCP socket in an IDuplexTransport that frames/deframes
 * binary WebSocket messages so the BOLT 8 Noise responder above sees a plain
 * byte stream. Auto-replies to pings, performs the close handshake, enforces
 * client masking, fragmentation sequencing and a payload sanity cap.
 *
 * In-repo instead of the `ws` dependency by design: Noise gives us
 * authenticated crypto above this layer, the server only frames bytes, and a
 * wallet library should not widen its supply chain for that.
 */

import { EventEmitter } from 'events';
import http from 'http';
import net from 'net';
import crypto from 'crypto';
import { IDuplexTransport } from './duplex-transport';
import { BufferedDataEmitter } from './websocket';
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

const WS_ACCEPT_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

/** Compute the Sec-WebSocket-Accept header value for a client key. */
export function computeWebSocketAccept(secWebSocketKey: string): string {
	return crypto
		.createHash('sha1')
		.update(secWebSocketKey + WS_ACCEPT_GUID)
		.digest('base64');
}

// ─── Server-side connection transport ──────────────────────────

/**
 * IDuplexTransport over an accepted (already-upgraded) WebSocket connection.
 * Emits raw binary payload bytes as 'data' (fragment by fragment — the Noise
 * layer re-frames on its encrypted length prefixes, so WS message boundaries
 * carry no meaning).
 */
/* eslint-disable brace-style -- prettier wraps the long class head */
export class WebSocketServerTransport
	extends BufferedDataEmitter
	implements IDuplexTransport
{
	/* eslint-enable brace-style */
	private socket: net.Socket;
	private parser: WsFrameParser;
	private closeSent = false;
	private closed = false;
	private closing = false;
	private hadError = false;
	// null = no fragmented data message in progress
	private fragmentedOpcode: number | null = null;
	private onClosing?: () => void;

	constructor(
		socket: net.Socket,
		opts?: {
			maxFramePayloadBytes?: number;
			initialData?: Buffer;
			/** Called once when we start closing a still-open socket. */
			onClosing?: () => void;
		}
	) {
		super();
		this.socket = socket;
		this.onClosing = opts?.onClosing;
		this.parser = new WsFrameParser({
			maxPayloadBytes:
				opts?.maxFramePayloadBytes ?? DEFAULT_MAX_WS_PAYLOAD_BYTES,
			requireMasked: true // client-to-server frames MUST be masked
		});

		socket.on('data', (chunk: Buffer) => this.handleRawData(chunk));
		socket.on('close', (hadError: boolean) => {
			if (this.closed) return;
			this.closed = true;
			this.emit('close', hadError || this.hadError);
		});
		socket.on('error', (err: Error) => {
			this.hadError = true;
			if (this.listenerCount('error') > 0) this.emit('error', err);
		});
		// Forward inactivity timeouts armed via setTimeout() (the Peer layer
		// uses them to bound the inbound handshake, then disarms).
		socket.on('timeout', () => {
			this.emit('timeout');
		});

		if (opts?.initialData && opts.initialData.length > 0) {
			// Bytes that arrived with the upgrade request (http 'upgrade' head)
			this.handleRawData(opts.initialData);
		}
	}

	get writableLength(): number {
		return this.socket.writableLength;
	}

	get remoteAddress(): string | undefined {
		return this.socket.remoteAddress;
	}

	get remotePort(): number | undefined {
		return this.socket.remotePort;
	}

	write(data: Uint8Array | string, cb?: (err?: Error) => void): boolean {
		const payload =
			typeof data === 'string'
				? Buffer.from(data, 'utf8')
				: Buffer.isBuffer(data)
				? data
				: Buffer.from(data.buffer, data.byteOffset, data.byteLength);
		const frame = encodeWsFrame({ opcode: WsOpcode.BINARY, payload });
		return this.socket.write(frame, cb);
	}

	setTimeout(timeout: number, callback?: () => void): this {
		if (callback) this.once('timeout', callback);
		this.socket.setTimeout(timeout);
		return this;
	}

	setKeepAlive(enable?: boolean, initialDelay?: number): this {
		this.socket.setKeepAlive(enable, initialDelay);
		return this;
	}

	destroy(error?: Error): this {
		if (this.closed && this.socket.destroyed) return this;
		if (error) {
			this.hadError = true;
			if (this.listenerCount('error') > 0) this.emit('error', error);
		}
		// Best-effort close frame so conforming peers see a clean close,
		// then drop the TCP socket (socket 'close' emits our 'close').
		this.sendClose(
			error ? WsCloseCode.INTERNAL_ERROR : WsCloseCode.NORMAL,
			error ? 'internal error' : ''
		);
		this.teardown();
		return this;
	}

	// ── Internal ─────────────────────────────────────────────────

	private handleRawData(chunk: Buffer): void {
		// Nothing arriving while we close is delivered, so none of it is
		// parsed or buffered while the socket lingers.
		if (this.closing) return;
		let frames: IWsFrame[];
		try {
			frames = this.parser.push(chunk);
		} catch (err) {
			if (err instanceof WsProtocolError) {
				this.fail(err.closeCode, err.message);
			} else {
				this.fail(WsCloseCode.INTERNAL_ERROR, (err as Error).message);
			}
			return;
		}
		for (const frame of frames) {
			if (this.closing || !this.handleFrame(frame)) return; // torn down
		}
	}

	/** Returns false when the connection was torn down by this frame. */
	private handleFrame(frame: IWsFrame): boolean {
		switch (frame.opcode) {
			case WsOpcode.BINARY:
				if (this.fragmentedOpcode !== null) {
					this.fail(
						WsCloseCode.PROTOCOL_ERROR,
						'New data frame while a fragmented message is in progress'
					);
					return false;
				}
				if (!frame.fin) this.fragmentedOpcode = WsOpcode.BINARY;
				if (frame.payload.length > 0) this.emitData(frame.payload);
				return true;

			case WsOpcode.CONTINUATION:
				if (this.fragmentedOpcode === null) {
					this.fail(
						WsCloseCode.PROTOCOL_ERROR,
						'Continuation frame without a fragmented message'
					);
					return false;
				}
				if (frame.fin) this.fragmentedOpcode = null;
				if (frame.payload.length > 0) this.emitData(frame.payload);
				return true;

			case WsOpcode.TEXT:
				// Lightning peers are binary-only; a text frame corrupts the
				// Noise stream.
				this.fail(
					WsCloseCode.UNSUPPORTED_DATA,
					'Text frames are not supported on a BOLT 8 link'
				);
				return false;

			case WsOpcode.PING:
				// Auto-reply with the same payload (RFC 6455 §5.5.3)
				this.socket.write(
					encodeWsFrame({ opcode: WsOpcode.PONG, payload: frame.payload })
				);
				return true;

			case WsOpcode.PONG:
				return true; // unsolicited pongs are ignored

			case WsOpcode.CLOSE: {
				// Echo the close (once), then drop the TCP connection.
				this.sendClose(WsCloseCode.NORMAL, '');
				this.teardown();
				return false;
			}

			default:
				this.fail(WsCloseCode.PROTOCOL_ERROR, 'Unexpected opcode');
				return false;
		}
	}

	private fail(closeCode: number, message: string): void {
		this.hadError = true;
		if (this.listenerCount('error') > 0) {
			this.emit('error', new Error(`WebSocket protocol error: ${message}`));
		}
		this.sendClose(closeCode, message);
		this.teardown();
	}

	protected onPendingOverflow(): void {
		super.onPendingOverflow();
		this.fail(WsCloseCode.INTERNAL_ERROR, 'receive buffer overflow');
	}

	/**
	 * Flush pending writes (including any just-queued close frame) with a FIN,
	 * then hard-destroy shortly after in case the peer never closes its side.
	 */
	private teardown(): void {
		if (this.socket.destroyed || this.closing) return;
		this.closing = true;
		this.socket.end();
		this.onClosing?.();
		const timer = setTimeout(() => this.socket.destroy(), 1000);
		if (timer.unref) timer.unref();
	}

	private sendClose(code: number, reason: string): void {
		if (this.closeSent) return;
		this.closeSent = true;
		if (this.socket.destroyed || !this.socket.writable) return;
		try {
			this.socket.write(
				encodeWsFrame({
					opcode: WsOpcode.CLOSE,
					payload: encodeWsClosePayload(code, reason)
				})
			);
		} catch {
			// Socket already going away — nothing to do
		}
	}
}

// ─── Listener ──────────────────────────────────────────────────

export interface IWebSocketServerOptions {
	/** Only accept upgrades on this path (default: any path). */
	path?: string;
	/** Per-frame payload sanity cap in bytes (default 16 MiB). */
	maxFramePayloadBytes?: number;
	/** Accepted connections still waiting to upgrade, or upgraded and now
	 *  closing, all addresses together; sockets past it are destroyed on
	 *  accept (default 50). */
	maxPendingUpgrades?: number;
	/** The same, from one source address (default: no limit). */
	maxPendingUpgradesPerAddress?: number;
	/** The key a source address counts under for
	 *  maxPendingUpgradesPerAddress, or null to leave it unlimited (default:
	 *  the address itself). */
	upgradeAddressKey?: (address: string | undefined) => string | null;
	/** Hard deadline in ms for a connection to complete its upgrade
	 *  (default 10000). */
	upgradeTimeoutMs?: number;
}

/**
 * Accepts WebSocket connections and emits IDuplexTransport instances.
 *
 * Events:
 * - 'connection' (transport: WebSocketServerTransport, req: http.IncomingMessage)
 * - 'error' (err: Error) — listener-level errors (e.g. EADDRINUSE)
 * - 'listening'
 */
export class WebSocketServer extends EventEmitter {
	private httpServer: http.Server;
	private options: IWebSocketServerOptions;
	private listeningFlag = false;
	/**
	 * Sockets accepted but not yet upgraded, with their address key and
	 * deadline. The HTTP phase sits in front of the peer manager's own
	 * admission, so without this a flood of silent connections would be held
	 * here unbounded for the HTTP server's much longer header timeout. An
	 * upgraded socket we close returns here until it is gone: it lingers so
	 * the client can read our close frame, and the peer manager no longer
	 * counts it.
	 */
	private pendingUpgrades = new Map<
		net.Socket,
		{ key: string | null; deadline?: ReturnType<typeof setTimeout> }
	>();
	private addressKey: (address: string | undefined) => string | null;

	constructor(options?: IWebSocketServerOptions) {
		super();
		this.options = options ?? {};
		const maxPendingUpgrades = this.options.maxPendingUpgrades ?? 50;
		const maxPerAddress = this.options.maxPendingUpgradesPerAddress ?? Infinity;
		const upgradeTimeoutMs = this.options.upgradeTimeoutMs ?? 10_000;
		this.addressKey =
			this.options.upgradeAddressKey ??
			((address): string | null => address ?? null);
		this.httpServer = http.createServer((req, res) => {
			// Plain HTTP requests are not part of the peer protocol
			res.writeHead(426, {
				'Content-Type': 'text/plain',
				Upgrade: 'websocket',
				Connection: 'Upgrade'
			});
			res.end('Upgrade Required');
		});
		this.httpServer.on('connection', (socket: net.Socket) => {
			const key = this.addressKey(socket.remoteAddress);
			let fromAddress = 0;
			for (const pending of this.pendingUpgrades.values()) {
				if (key !== null && pending.key === key) fromAddress++;
			}
			if (
				this.pendingUpgrades.size >= maxPendingUpgrades ||
				fromAddress >= maxPerAddress
			) {
				socket.destroy();
				return;
			}
			this.pendingUpgrades.set(socket, {
				key,
				deadline: setTimeout(() => socket.destroy(), upgradeTimeoutMs)
			});
			socket.once('close', () => this.settleUpgrade(socket));
		});
		this.httpServer.on(
			'upgrade',
			(req: http.IncomingMessage, socket, head: Buffer) => {
				this.settleUpgrade(socket as net.Socket);
				this.handleUpgrade(req, socket as net.Socket, head);
			}
		);
		this.httpServer.on('error', (err) => {
			this.emit('error', err);
		});
	}

	listen(port: number, host?: string): Promise<void> {
		return new Promise((resolve, reject) => {
			const onError = (err: Error): void => reject(err);
			this.httpServer.once('error', onError);
			this.httpServer.listen(port, host, () => {
				this.httpServer.removeListener('error', onError);
				this.listeningFlag = true;
				this.emit('listening');
				resolve();
			});
		});
	}

	address(): net.AddressInfo | string | null {
		return this.httpServer.address();
	}

	isListening(): boolean {
		return this.listeningFlag && this.httpServer.listening;
	}

	close(): void {
		this.listeningFlag = false;
		this.httpServer.close();
	}

	private settleUpgrade(socket: net.Socket): void {
		const pending = this.pendingUpgrades.get(socket);
		if (pending === undefined) return;
		clearTimeout(pending.deadline);
		this.pendingUpgrades.delete(socket);
	}

	private handleUpgrade(
		req: http.IncomingMessage,
		socket: net.Socket,
		head: Buffer
	): void {
		const deny = (status: number, message: string, headers = ''): void => {
			socket.write(
				`HTTP/1.1 ${status} ${message}\r\n` +
					'Connection: close\r\n' +
					headers +
					'\r\n'
			);
			socket.destroy();
		};

		if ((req.method || 'GET').toUpperCase() !== 'GET') {
			return deny(405, 'Method Not Allowed');
		}
		const upgrade = String(req.headers.upgrade || '').toLowerCase();
		if (upgrade !== 'websocket') {
			return deny(400, 'Bad Request');
		}
		const version = req.headers['sec-websocket-version'];
		if (version !== '13') {
			return deny(426, 'Upgrade Required', 'Sec-WebSocket-Version: 13\r\n');
		}
		const key = req.headers['sec-websocket-key'];
		if (typeof key !== 'string' || Buffer.from(key, 'base64').length !== 16) {
			return deny(400, 'Bad Request');
		}
		if (this.options.path) {
			const reqPath = (req.url || '/').split('?')[0];
			if (reqPath !== this.options.path) {
				return deny(404, 'Not Found');
			}
		}

		socket.write(
			'HTTP/1.1 101 Switching Protocols\r\n' +
				'Upgrade: websocket\r\n' +
				'Connection: Upgrade\r\n' +
				`Sec-WebSocket-Accept: ${computeWebSocketAccept(key)}\r\n` +
				'\r\n'
		);

		const transport = new WebSocketServerTransport(socket, {
			maxFramePayloadBytes: this.options.maxFramePayloadBytes,
			initialData: head,
			onClosing: () =>
				this.pendingUpgrades.set(socket, {
					key: this.addressKey(socket.remoteAddress)
				})
		});
		this.emit('connection', transport, req);
	}
}
