/**
 * WebSocket client transport for Lightning peer connections.
 *
 * Carries BOLT 8 Noise bytes over binary WebSocket messages (each write is
 * one binary frame; received frames are treated as a byte stream — the Noise
 * layer re-frames on its own 18-byte encrypted length prefixes, so WS message
 * boundaries are irrelevant).
 *
 * Written against the STANDARD WebSocket API only (binaryType 'arraybuffer',
 * bufferedAmount for backpressure) so the same code runs in browsers and in
 * Node >= 22 (global WebSocket). No dependency on any WS npm package: an
 * implementation can be injected via options (mirroring how electrumOptions
 * injects net/tls), with default resolution to `globalThis.WebSocket`.
 */

import { EventEmitter } from 'events';
import { IDuplexTransport } from './duplex-transport';

// ─── Standard-API structural types (no DOM lib dependency) ─────

/** WebSocket readyState values (RFC 6455 / WHATWG). */
export const WS_CONNECTING = 0;
export const WS_OPEN = 1;
export const WS_CLOSING = 2;
export const WS_CLOSED = 3;

/**
 * The subset of the WHATWG WebSocket interface this transport uses.
 * Browser WebSocket, Node's global WebSocket (undici) and the `ws` package
 * all satisfy it structurally.
 */
export interface IWebSocketLike {
	binaryType: string;
	readonly bufferedAmount: number;
	readonly readyState: number;
	send(data: Uint8Array): void;
	close(code?: number, reason?: string): void;
	onopen: ((ev?: unknown) => void) | null;
	onmessage: ((ev: { data: unknown }) => void) | null;
	onclose:
		| ((ev?: { code?: number; reason?: string; wasClean?: boolean }) => void)
		| null;
	onerror: ((ev?: unknown) => void) | null;
}

/** Injectable WebSocket constructor (standard `new WebSocket(url)` shape). */
export type WebSocketConstructor = new (
	url: string,
	protocols?: string | string[]
) => IWebSocketLike;

/**
 * Resolve the WebSocket implementation to use: an injected constructor wins;
 * otherwise `globalThis.WebSocket` (browsers, Node >= 22). Throws a
 * descriptive error when neither exists (older Node without the `ws`
 * package injected).
 */
export function resolveWebSocketConstructor(
	injected?: WebSocketConstructor
): WebSocketConstructor {
	if (injected) return injected;
	const g = globalThis as { WebSocket?: unknown };
	if (typeof g.WebSocket === 'function') {
		return g.WebSocket as WebSocketConstructor;
	}
	throw new Error(
		'No WebSocket implementation available: inject one via webSocketImpl ' +
			'(e.g. require("ws").WebSocket) or run where globalThis.WebSocket ' +
			'exists (browsers, Node >= 22)'
	);
}

/** Build a ws:// URL from a dial address (brackets IPv6 literals). */
export function buildWebSocketUrl(host: string, port: number): string {
	const needsBrackets = host.includes(':') && !host.startsWith('[');
	return `ws://${needsBrackets ? `[${host}]` : host}:${port}`;
}

/** Parse a ws:// or wss:// URL into a dialable host/port (for bookkeeping). */
export function parseWebSocketUrl(url: string): {
	host: string;
	port: number;
	secure: boolean;
} {
	let parsed: URL;
	try {
		parsed = new URL(url);
	} catch {
		throw new Error(`Invalid WebSocket URL: ${url}`);
	}
	if (parsed.protocol !== 'ws:' && parsed.protocol !== 'wss:') {
		throw new Error(`Invalid WebSocket URL (expected ws:// or wss://): ${url}`);
	}
	const secure = parsed.protocol === 'wss:';
	const port = parsed.port ? parseInt(parsed.port, 10) : secure ? 443 : 80;
	if (!parsed.hostname || !Number.isInteger(port) || port <= 0) {
		throw new Error(`Invalid WebSocket URL host/port: ${url}`);
	}
	// URL keeps IPv6 literals bracketed in hostname; strip for net-style host.
	const host = parsed.hostname.replace(/^\[|\]$/g, '');
	return { host, port, secure };
}

// ─── Transport ─────────────────────────────────────────────────

export interface IWebSocketConnectOptions {
	/** WebSocket constructor to use (default: globalThis.WebSocket). */
	webSocketImpl?: WebSocketConstructor;
}

/**
 * EventEmitter that never drops 'data': chunks emitted while no 'data'
 * listener is attached are buffered and flushed when one attaches.
 *
 * WebSocket messages arrive one 'data' event per frame, so two frames in a
 * single TCP segment emit back-to-back synchronously. The Noise layer's
 * fixed-length reads detach their 'data' listener as soon as they are
 * satisfied, which would silently drop the second frame (raw TCP never hits
 * this: one segment = one 'data' event). Buffering in that window makes the
 * WS transports strictly safer than a bare socket.
 */
export class BufferedDataEmitter extends EventEmitter {
	private pendingData: Buffer[] = [];
	private pendingBytes = 0;
	/** Overflow guard for the no-listener window (destroy() on breach). */
	protected static readonly MAX_PENDING_DATA_BYTES = 16 * 1024 * 1024;

	/** Subclasses route incoming bytes through this instead of emit('data'). */
	protected emitData(chunk: Buffer): void {
		if (this.listenerCount('data') > 0) {
			this.emit('data', chunk);
			return;
		}
		this.pendingData.push(chunk);
		this.pendingBytes += chunk.length;
		if (this.pendingBytes > BufferedDataEmitter.MAX_PENDING_DATA_BYTES) {
			this.onPendingOverflow();
		}
	}

	/** Subclasses tear the transport down on pending-buffer overflow. */
	protected onPendingOverflow(): void {
		this.pendingData = [];
		this.pendingBytes = 0;
	}

	private flushPendingData(): void {
		while (this.pendingData.length > 0 && this.listenerCount('data') > 0) {
			const chunk = this.pendingData.shift()!;
			this.pendingBytes -= chunk.length;
			this.emit('data', chunk);
		}
	}

	// `never[]` keeps callers' typed listeners assignable (contravariance)
	// without resorting to `any`.
	on(event: string | symbol, listener: (...args: never[]) => void): this {
		super.on(event, listener as (...args: unknown[]) => void);
		if (event === 'data') this.flushPendingData();
		return this;
	}

	addListener(
		event: string | symbol,
		listener: (...args: never[]) => void
	): this {
		return this.on(event, listener);
	}

	once(event: string | symbol, listener: (...args: never[]) => void): this {
		super.once(event, listener as (...args: unknown[]) => void);
		if (event === 'data') this.flushPendingData();
		return this;
	}
}

function toError(ev: unknown, fallback: string): Error {
	if (ev instanceof Error) return ev;
	if (ev && typeof ev === 'object') {
		const anyEv = ev as { error?: unknown; message?: unknown };
		if (anyEv.error instanceof Error) return anyEv.error;
		if (typeof anyEv.message === 'string' && anyEv.message.length > 0) {
			return new Error(anyEv.message);
		}
	}
	return new Error(fallback);
}

/**
 * IDuplexTransport over an already-OPEN standard WebSocket. Use
 * connectWebSocket() to dial; wrap an accepted/open socket directly for
 * custom setups.
 */
/* eslint-disable brace-style -- prettier wraps the long class head */
export class WebSocketTransport
	extends BufferedDataEmitter
	implements IDuplexTransport
{
	/* eslint-enable brace-style */
	readonly remoteAddress?: string;
	readonly remotePort?: number;

	private ws: IWebSocketLike;
	private destroyed = false;
	private hadError = false;
	private deadline: ReturnType<typeof setTimeout> | null = null;

	constructor(
		ws: IWebSocketLike,
		remote?: { address?: string; port?: number }
	) {
		super();
		this.ws = ws;
		this.remoteAddress = remote?.address;
		this.remotePort = remote?.port;
		ws.onopen = null;
		ws.onmessage = (ev): void => this.handleMessage(ev.data);
		ws.onclose = (): void => this.handleClose();
		ws.onerror = (ev): void => this.handleError(ev);
	}

	get writableLength(): number {
		// Standard-API backpressure signal: bytes queued but not yet sent.
		return this.ws.bufferedAmount;
	}

	write(data: Uint8Array | string, cb?: (err?: Error) => void): boolean {
		if (this.destroyed) {
			const err = new Error('WebSocket transport is destroyed');
			if (cb) queueMicrotask(() => cb(err));
			else this.emitErrorSafe(err);
			return false;
		}
		try {
			const bytes = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
			this.ws.send(bytes);
			if (cb) queueMicrotask(() => cb());
			return true;
		} catch (err) {
			const e = err instanceof Error ? err : new Error(String(err));
			if (cb) queueMicrotask(() => cb(e));
			else this.emitErrorSafe(e);
			return false;
		}
	}

	setTimeout(timeout: number, callback?: () => void): this {
		if (callback) this.once('timeout', callback);
		if (this.deadline) {
			clearTimeout(this.deadline);
			this.deadline = null;
		}
		if (timeout > 0) {
			// Simple deadline (not idle-reset): the Peer layer only uses this to
			// bound the connect/handshake phase, then disarms with setTimeout(0).
			this.deadline = setTimeout(() => {
				this.deadline = null;
				this.emit('timeout');
			}, timeout);
			if (this.deadline.unref) this.deadline.unref();
		}
		return this;
	}

	setKeepAlive(): this {
		// The standard WebSocket API has no keepalive control; liveness is
		// covered by BOLT 1 ping/pong above and WS-level ping auto-replies in
		// conforming implementations.
		return this;
	}

	destroy(error?: Error): this {
		if (this.destroyed) return this;
		this.destroyed = true;
		this.clearDeadline();
		if (error) {
			this.hadError = true;
			this.emitErrorSafe(error);
		}
		this.detach();
		try {
			this.ws.close(1000);
		} catch {
			// Closing a CONNECTING/CLOSED socket may throw in some impls
		}
		this.emit('close', this.hadError);
		return this;
	}

	// ── Internal ─────────────────────────────────────────────────

	private handleMessage(data: unknown): void {
		if (this.destroyed) return;
		if (data instanceof ArrayBuffer) {
			this.emitData(Buffer.from(data));
			return;
		}
		if (ArrayBuffer.isView(data)) {
			const view = data as ArrayBufferView;
			this.emitData(Buffer.from(view.buffer, view.byteOffset, view.byteLength));
			return;
		}
		// Text (or Blob from an impl ignoring binaryType) is a protocol
		// violation for a BOLT 8 peer — fail fast rather than corrupt the
		// Noise stream.
		this.destroy(
			new Error('WebSocket peer sent a non-binary message on a BOLT 8 link')
		);
	}

	private handleClose(): void {
		if (this.destroyed) return;
		this.destroyed = true;
		this.clearDeadline();
		this.detach();
		this.emit('close', this.hadError);
	}

	private handleError(ev: unknown): void {
		this.hadError = true;
		if (this.destroyed) return;
		this.emitErrorSafe(toError(ev, 'WebSocket error'));
		// Standard implementations fire onclose right after onerror; 'close'
		// is emitted there (handleClose) exactly once.
	}

	private emitErrorSafe(err: Error): void {
		// An unhandled 'error' on an EventEmitter crashes the process; every
		// live Peer attaches an error listener, but be safe during teardown.
		if (this.listenerCount('error') > 0) this.emit('error', err);
	}

	protected onPendingOverflow(): void {
		super.onPendingOverflow();
		this.destroy(new Error('WebSocket receive buffer overflow'));
	}

	private clearDeadline(): void {
		if (this.deadline) {
			clearTimeout(this.deadline);
			this.deadline = null;
		}
	}

	private detach(): void {
		this.ws.onmessage = null;
		this.ws.onclose = null;
		this.ws.onerror = null;
	}
}

/**
 * Dial a WebSocket peer and resolve once the socket is OPEN. Callers bound
 * the wait themselves (the Peer layer races this against its connect
 * timeout and destroys a late-resolving transport).
 */
export function connectWebSocket(
	url: string,
	options?: IWebSocketConnectOptions
): Promise<WebSocketTransport> {
	const Ctor = resolveWebSocketConstructor(options?.webSocketImpl);
	const { host, port } = parseWebSocketUrl(url);
	return new Promise<WebSocketTransport>((resolve, reject) => {
		let ws: IWebSocketLike;
		try {
			ws = new Ctor(url);
		} catch (err) {
			reject(err instanceof Error ? err : new Error(String(err)));
			return;
		}
		let settled = false;
		ws.binaryType = 'arraybuffer';
		ws.onopen = (): void => {
			if (settled) return;
			settled = true;
			resolve(new WebSocketTransport(ws, { address: host, port }));
		};
		ws.onerror = (ev): void => {
			if (settled) return;
			settled = true;
			reject(toError(ev, `WebSocket connection to ${url} failed`));
		};
		ws.onclose = (ev): void => {
			if (settled) return;
			settled = true;
			reject(
				new Error(
					`WebSocket to ${url} closed before open` +
						(ev && ev.code !== undefined ? ` (code ${ev.code})` : '')
				)
			);
		};
	});
}
