/**
 * Duplex byte-stream transport for Lightning peer connections.
 *
 * The interface is shaped from the exact subset of `net.Socket` that the
 * BOLT 8 Noise/Peer layer actually uses, so a plain `net.Socket` satisfies it
 * structurally — the existing TCP (and SOCKS5-proxied TCP) path passes real
 * sockets through completely unchanged. Alternative transports (WebSocket, Iroh)
 * implement the same surface.
 *
 * Events a transport must emit:
 * - 'data'    (chunk: Buffer)       incoming raw bytes, transport framing removed
 * - 'close'   (hadError: boolean)   transport fully closed (exactly once)
 * - 'error'   (err: Error)          fatal transport error, followed by 'close'
 * - 'timeout'                        deadline armed via setTimeout(ms) elapsed;
 *                                    must NOT close the transport by itself
 */

import { EventEmitter } from 'events';
import type { IIrohDiagnostics } from './iroh';

export interface IDuplexTransport extends EventEmitter {
	readonly transportType?: 'tcp' | 'ws' | 'iroh';
	getIrohDiagnostics?(): IIrohDiagnostics;
	/**
	 * Queue bytes for sending. The optional callback fires once the data has
	 * been handed to the underlying transport (or with an error on failure).
	 */
	write(data: Uint8Array | string, cb?: (err?: Error) => void): boolean;
	/** Bytes queued but not yet flushed — the backpressure signal. */
	readonly writableLength: number;
	/**
	 * Arm a timeout that emits 'timeout' after `timeout` ms; 0 disarms it.
	 * For TCP sockets this is Node's inactivity timeout; other transports may
	 * implement it as a simple deadline (the Peer layer only uses it to bound
	 * connect/handshake, then disarms it).
	 */
	setTimeout(timeout: number, callback?: () => void): this;
	/** Enable transport-level keepalive probing where supported (else no-op). */
	setKeepAlive(enable?: boolean, initialDelay?: number): this;
	/**
	 * Tear the transport down immediately. When `error` is provided it is
	 * emitted as 'error' (if listeners exist) and 'close' reports hadError.
	 */
	destroy(error?: Error): this;
	/**
	 * Called once the BOLT 8 handshake and init exchange complete on an
	 * connection. A transport that holds an unauthenticated peer to
	 * tighter limits lifts them here.
	 */
	markEstablished?(): void;
	/** Remote endpoint info, when known (used for inbound peer bookkeeping). */
	readonly remoteAddress?: string;
	readonly remotePort?: number;
}

/**
 * Establishes an outbound transport to `host:port`. This is the shape of
 * `IPeerOptions.createSocket` — the SOCKS5 factory and the WebSocket client
 * factory both produce it; a bare TCP dial is the default when absent.
 */
export type TransportConnectFn = (
	host: string,
	port: number
) => Promise<IDuplexTransport>;

/** TCP (including SOCKS5/Tor), WebSocket, or opt-in Iroh carrying BOLT 8. */
export interface IPeerTransportOptions {
	/** Transport protocol. 'tcp' preserves today's behavior exactly. */
	type: 'tcp' | 'ws' | 'iroh';
	/** Iroh endpoint id (32-byte hex or base32), never a gossip address. */
	endpointId?: string;
	/** Optional Iroh relay hint for private discovery. */
	relayUrl?: string;
	/** Iroh only: optional Tor fallback for the same Lightning node key. */
	fallbackOnion?: { host: string; port: number };
	/**
	 * WS only: explicit WebSocket URL (ws:// or wss://). Defaults to
	 * `ws://host:port` built from the dial address. Note that WebSocket
	 * connections do not route through the SOCKS5 proxy.
	 */
	url?: string;
}
