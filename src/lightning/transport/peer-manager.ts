/**
 * Peer connection pool manager.
 *
 * Manages multiple simultaneous peer connections, providing:
 * - Connection/disconnection by pubkey
 * - Message routing to specific peers
 * - Message handler registration by type
 * - Reconnection with exponential backoff
 */

import { EventEmitter } from 'events';
import net from 'net';
import { SocksClient } from 'socks';
import { Peer } from './peer';
import { FeatureFlags } from '../features/flags';
import { IInitMessage } from '../message/init';
import { captureWireMessage, captureWireEvent } from './wire-capture';
import { IDuplexTransport, IPeerTransportOptions } from './duplex-transport';
import {
	connectWebSocket,
	buildWebSocketUrl,
	WebSocketConstructor
} from './websocket';
import { WebSocketServer } from './websocket-server';
import { NodeWebSocket } from './websocket-node-client';

/**
 * Default WS client for outbound peers when none is injected. Under Node the
 * built-in WebSocket (undici) lowercases request headers, which CLN's
 * case-sensitive `bind-addr=ws:` handshake parser rejects — so Node uses the
 * in-repo RFC-cased client. Everywhere else (browsers) connectWebSocket
 * resolves globalThis.WebSocket.
 */
function defaultWebSocketImpl(): WebSocketConstructor | undefined {
	const proc = (globalThis as { process?: { versions?: { node?: string } } })
		.process;
	if (proc?.versions?.node) {
		return NodeWebSocket;
	}
	return undefined;
}

const DEFAULT_MAX_RECONNECT_DELAY_MS = 300_000; // 5 minutes
const DEFAULT_INITIAL_RECONNECT_DELAY_MS = 1_000; // 1 second
// A connection must stay up this long before we treat it as healthy and reset
// the reconnect backoff. Without this, a peer that connects then immediately
// drops (a "flapping" peer — e.g. a closing channel, or an unstable Tor circuit)
// resets the backoff every cycle and reconnects in a tight 1s loop forever.
const STABLE_CONNECTION_MS = 60_000;
const DEFAULT_TOR_PROXY = { host: '127.0.0.1', port: 9050 };

/**
 * True for hosts that must be dialed directly and never through the SOCKS5/Tor
 * proxy: localhost, loopback, and RFC1918 / link-local / unique-local IPs.
 *
 * Tor refuses to proxy connections to private and loopback addresses
 * ("Rejecting SOCKS request for anonymous connection to private address"), so
 * with a proxy configured, routing a LAN or localhost peer through it turns
 * every dial and every auto-reconnect into a hard failure. A user who enables
 * Tor to gain privacy on public peers should not thereby lose the channel peer
 * that lives on their own network. Onion routing is decided by the caller; this
 * only classifies literal IP addresses (and `localhost`). A hostname that
 * happens to resolve to a private address is not caught here, because that would
 * require resolving it first; peers on a LAN are addressed by IP in practice.
 */
export function isPrivateOrLoopbackHost(host: string): boolean {
	const h = host.trim().toLowerCase();
	if (h === '' || h === 'localhost') return h === 'localhost';

	// IPv6: drop brackets and any zone id, then match the reserved ranges.
	const v6 = h.replace(/^\[/, '').replace(/\]$/, '').split('%')[0];
	if (v6 === '::1' || v6 === '::') return true;
	if (/^fe[89ab][0-9a-f]:/.test(v6)) return true; // fe80::/10 link-local
	if (/^f[cd][0-9a-f]{2}:/.test(v6)) return true; // fc00::/7  unique-local
	// IPv4-mapped IPv6 (e.g. ::ffff:192.168.1.2) reduces to the IPv4 check.
	const mapped = v6.match(/^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);

	const v4 = mapped ? mapped[1] : h;
	const m = v4.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
	if (!m) return false;
	const parts = m.slice(1).map(Number);
	if (parts.some((n) => n > 255)) return false;
	const [a, b] = parts;
	if (a === 0) return true; // 0.0.0.0/8 "this host on this network"
	if (a === 127) return true; // 127.0.0.0/8 loopback
	if (a === 10) return true; // 10.0.0.0/8
	if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
	if (a === 192 && b === 168) return true; // 192.168.0.0/16
	if (a === 169 && b === 254) return true; // 169.254.0.0/16 link-local
	return false;
}

export interface IPeerManagerOptions {
	/** Local node private key (32 bytes) */
	localPrivateKey: Buffer;
	/** Local feature flags to advertise */
	localFeatures?: FeatureFlags;
	/** Chain hashes to advertise */
	networks?: Buffer[];
	/** Enable auto-reconnect (default false) */
	autoReconnect?: boolean;
	/** Max reconnect delay in ms (default 5 min) */
	maxReconnectDelay?: number;
	/** SOCKS5 proxy for ALL outbound connections (e.g. Tor on 127.0.0.1:9050).
	 *  When not set, .onion addresses auto-route through 127.0.0.1:9050. */
	socks5Proxy?: { host: string; port: number };
	/** SOCKS5 connect/negotiation timeout in ms (default 20000). Lower it when a
	 *  fast failure is preferable to waiting out a stalled/filtered proxy. */
	socks5TimeoutMs?: number;
	/** Maximum number of inbound peer connections (default 125) */
	maxInboundPeers?: number;
	/** WebSocket constructor for outbound WS peer connections. Defaults to
	 *  the in-repo RFC-cased Node client under Node (CLN's ws listener
	 *  rejects the built-in WebSocket's lowercased headers) and to
	 *  globalThis.WebSocket in browsers. Only consulted when a peer is
	 *  dialed with transport {type: 'ws'}. */
	webSocketImpl?: WebSocketConstructor;
}

export interface IPeerInfo {
	pubkey: string;
	host: string;
	port: number;
	state: string;
	remoteInit: IInitMessage | null;
	/** Transport used to dial this peer ('tcp' when absent/unknown). */
	transport?: 'tcp' | 'ws';
}

type MessageHandler = (pubkey: string, type: number, payload: Buffer) => void;

export class PeerManager extends EventEmitter {
	private localPrivateKey: Buffer;
	private localFeatures: FeatureFlags;
	private networks?: Buffer[];
	private peers: Map<string, Peer> = new Map();
	private peerAddresses: Map<
		string,
		{ host: string; port: number; transport?: IPeerTransportOptions }
	> = new Map();
	private messageHandlers: Map<number, MessageHandler[]> = new Map();
	private reconnectTimers: Map<string, ReturnType<typeof setTimeout>> =
		new Map();
	private reconnectDelays: Map<string, number> = new Map();
	// Per-peer timers that reset the backoff once a connection has stayed up for
	// STABLE_CONNECTION_MS. Cleared if the peer disconnects before then.
	private stabilityTimers: Map<string, ReturnType<typeof setTimeout>> =
		new Map();
	private autoReconnect: boolean;
	private maxReconnectDelay: number;
	private server: net.Server | null = null;
	private wsServer: WebSocketServer | null = null;
	private socks5Proxy?: { host: string; port: number };
	private socks5TimeoutMs: number;
	private maxInboundPeers: number;
	private inboundPeerCount = 0;
	private inboundPeerSet: Set<string> = new Set();
	private webSocketImpl?: WebSocketConstructor;

	constructor(options: IPeerManagerOptions) {
		super();
		this.localPrivateKey = options.localPrivateKey;
		this.localFeatures = options.localFeatures || FeatureFlags.empty();
		this.networks = options.networks;
		this.autoReconnect = options.autoReconnect ?? false;
		this.maxReconnectDelay =
			options.maxReconnectDelay ?? DEFAULT_MAX_RECONNECT_DELAY_MS;
		this.socks5Proxy = options.socks5Proxy;
		this.socks5TimeoutMs = options.socks5TimeoutMs ?? 20_000;
		this.maxInboundPeers = options.maxInboundPeers ?? 125;
		this.webSocketImpl = options.webSocketImpl;
	}

	/**
	 * Connect to a peer.
	 * @param pubkey - Remote node's public key (hex string)
	 * @param host - Remote host address
	 * @param port - Remote port
	 * @param transport - Optional transport selection; omit for TCP (default,
	 *                    unchanged behavior). {type: 'ws', url?} dials over
	 *                    WebSocket (url defaults to ws://host:port).
	 */
	async connectPeer(
		pubkey: string,
		host: string,
		port: number,
		transport?: IPeerTransportOptions
	): Promise<void> {
		// Keep stored address objects shaped exactly as before for TCP peers
		// (no `transport` key unless a non-default transport was requested).
		const addressEntry = transport ? { host, port, transport } : { host, port };
		if (this.peers.has(pubkey)) {
			// Idempotent: the post-condition "connected to this peer" already holds.
			// Throwing here forces every caller (reconnect loops, app code) to special-
			// case an already-connected peer; instead refresh the cached address and
			// return successfully.
			this.peerAddresses.set(pubkey, addressEntry);
			return;
		}

		// Remember the last-known-good address: a failed dial to a NEW address
		// must not clobber it, or every future auto-reconnect dials the bad
		// address (e.g. one typo'd manual connectPeer permanently breaks
		// reconnection to a channel peer).
		const previousAddress = this.peerAddresses.get(pubkey);
		this.peerAddresses.set(pubkey, addressEntry);

		let createSocket:
			| ((h: string, p: number) => Promise<IDuplexTransport>)
			| undefined;
		if (transport?.type === 'ws') {
			// WebSocket transport (does NOT route through the SOCKS5 proxy)
			const url = transport.url ?? buildWebSocketUrl(host, port);
			const webSocketImpl = this.webSocketImpl ?? defaultWebSocketImpl();
			createSocket = (): Promise<IDuplexTransport> =>
				connectWebSocket(url, { webSocketImpl });
		} else {
			// Route selection for the outbound socket:
			//   .onion           → always via Tor (explicit proxy, else the default)
			//   private/loopback → always direct; Tor rejects these, so proxying a
			//                      LAN or localhost peer would only ever fail
			//   public clearnet  → via the configured proxy (privacy), else direct
			const proxy = host.endsWith('.onion')
				? this.socks5Proxy ?? DEFAULT_TOR_PROXY
				: isPrivateOrLoopbackHost(host)
				? undefined
				: this.socks5Proxy;
			createSocket = proxy ? this.buildSocks5Factory(proxy) : undefined;
		}

		const peer = new Peer({
			localPrivateKey: this.localPrivateKey,
			remotePublicKey: Buffer.from(pubkey, 'hex'),
			host,
			port,
			localFeatures: this.localFeatures,
			networks: this.networks,
			createSocket
		});

		this.setupPeerListeners(pubkey, peer);

		try {
			await peer.connect();
		} catch (err) {
			// Restore the last-known-good address (keep the attempted one only
			// when there was no previous address, so initial connects still retry).
			if (previousAddress) {
				this.peerAddresses.set(pubkey, previousAddress);
			}
			if (this.autoReconnect) {
				this.scheduleReconnect(pubkey);
			}
			throw err;
		}
		this.peers.set(pubkey, peer);
		// Reset the backoff only AFTER the connection proves stable, not
		// immediately — otherwise a peer that drops right after connecting keeps
		// reconnecting at the minimum delay. The disconnect handler clears this
		// timer if the connection is short-lived, so the backoff keeps growing.
		this.clearStabilityTimer(pubkey);
		const stabilityTimer = setTimeout(() => {
			this.reconnectDelays.delete(pubkey);
			this.stabilityTimers.delete(pubkey);
		}, STABLE_CONNECTION_MS);
		if (typeof stabilityTimer.unref === 'function') stabilityTimer.unref();
		this.stabilityTimers.set(pubkey, stabilityTimer);
		captureWireEvent('connect', pubkey, 'outbound');
		this.emit('peer:connect', pubkey);
	}

	private clearStabilityTimer(pubkey: string): void {
		const t = this.stabilityTimers.get(pubkey);
		if (t) {
			clearTimeout(t);
			this.stabilityTimers.delete(pubkey);
		}
	}

	/**
	 * Disconnect from a peer.
	 */
	disconnectPeer(pubkey: string): void {
		const timer = this.reconnectTimers.get(pubkey);
		if (timer) {
			clearTimeout(timer);
			this.reconnectTimers.delete(pubkey);
		}
		this.reconnectDelays.delete(pubkey);
		this.clearStabilityTimer(pubkey);

		const peer = this.peers.get(pubkey);
		if (peer) {
			peer.disconnect();
			this.peers.delete(pubkey);
			this.emit('peer:disconnect', pubkey);
		}
	}

	/**
	 * Send a message to a specific peer.
	 */
	sendToPeer(pubkey: string, type: number, payload: Buffer): void {
		const peer = this.peers.get(pubkey);
		if (!peer) {
			throw new Error(`Not connected to peer ${pubkey}`);
		}
		captureWireMessage('out', pubkey, type, payload);
		peer.sendMessage(type, payload);
	}

	/**
	 * Get a connected peer by pubkey.
	 */
	getPeer(pubkey: string): Peer | undefined {
		return this.peers.get(pubkey);
	}

	/**
	 * List all connected peers.
	 */
	listPeers(): IPeerInfo[] {
		const result: IPeerInfo[] = [];
		for (const [pubkey, peer] of this.peers) {
			const addr = this.peerAddresses.get(pubkey);
			const info: IPeerInfo = {
				pubkey,
				host: addr?.host || peer.host,
				port: addr?.port || peer.port,
				state: peer.getState(),
				remoteInit: peer.getRemoteInit()
			};
			if (addr?.transport?.type === 'ws') info.transport = 'ws';
			result.push(info);
		}
		return result;
	}

	/**
	 * Get a stored peer address.
	 */
	getPeerAddress(pubkey: string): { host: string; port: number } | undefined {
		return this.peerAddresses.get(pubkey);
	}

	/**
	 * Register a handler for a specific message type.
	 * The handler receives (pubkey, type, payload).
	 */
	onMessage(type: number, handler: MessageHandler): void {
		const handlers = this.messageHandlers.get(type) || [];
		handlers.push(handler);
		this.messageHandlers.set(type, handlers);
	}

	/**
	 * Start listening for inbound peer connections.
	 */
	async listen(port: number, host = '0.0.0.0'): Promise<void> {
		if (this.server) {
			throw new Error('Already listening');
		}

		return new Promise((resolve, reject) => {
			const server = net.createServer((socket) => {
				this.handleInboundConnection(socket);
			});

			server.on('error', (err) => {
				this.emit('listen:error', err);
			});

			server.listen(port, host, () => {
				this.server = server;
				this.emit('listening', port, host);
				resolve();
			});

			server.once('error', (err) => {
				if (!this.server) {
					reject(err);
				}
			});
		});
	}

	/**
	 * Start listening for inbound peers over WebSocket (RFC 6455). Opt-in and
	 * additive: coexists with (does not replace) the TCP listener.
	 */
	async listenWebSocket(port: number, host = '0.0.0.0'): Promise<void> {
		if (this.wsServer) {
			throw new Error('Already listening for WebSocket peers');
		}
		const server = new WebSocketServer();
		server.on('connection', (transport: IDuplexTransport) => {
			this.handleInboundConnection(transport);
		});
		server.on('error', (err: Error) => {
			this.emit('listen:error', err);
		});
		await server.listen(port, host);
		this.wsServer = server;
		const addr = server.address();
		const boundPort = addr && typeof addr === 'object' ? addr.port : port;
		this.emit('listening:ws', boundPort, host);
	}

	/**
	 * Stop listening for inbound connections (TCP and WebSocket).
	 */
	stopListening(): void {
		if (this.server) {
			this.server.close();
			this.server = null;
		}
		if (this.wsServer) {
			this.wsServer.close();
			this.wsServer = null;
		}
	}

	/**
	 * Whether the peer manager is listening for inbound connections
	 * (TCP or WebSocket).
	 */
	isListening(): boolean {
		return (
			(this.server !== null && this.server.listening) ||
			(this.wsServer !== null && this.wsServer.isListening())
		);
	}

	/**
	 * Whether the WebSocket listener is active.
	 */
	isListeningWebSocket(): boolean {
		return this.wsServer !== null && this.wsServer.isListening();
	}

	/**
	 * Bound WebSocket listener port (null when not listening). Useful when
	 * listening on port 0.
	 */
	getWebSocketListenerPort(): number | null {
		const addr = this.wsServer?.address();
		return addr && typeof addr === 'object' ? addr.port : null;
	}

	/**
	 * Disconnect all peers and clean up.
	 */
	destroy(): void {
		this.stopListening();
		for (const [pubkey] of this.peers) {
			this.disconnectPeer(pubkey);
		}
		for (const timer of this.reconnectTimers.values()) {
			clearTimeout(timer);
		}
		this.reconnectTimers.clear();
		this.reconnectDelays.clear();
		for (const timer of this.stabilityTimers.values()) {
			clearTimeout(timer);
		}
		this.stabilityTimers.clear();
		this.messageHandlers.clear();
	}

	private handleInboundConnection(socket: IDuplexTransport): void {
		// Reject if at inbound peer limit
		if (this.inboundPeerCount >= this.maxInboundPeers) {
			socket.destroy();
			return;
		}

		// Create peer with placeholder pubkey — discovered during Noise handshake
		const peer = new Peer({
			localPrivateKey: this.localPrivateKey,
			remotePublicKey: Buffer.alloc(33, 0),
			host: socket.remoteAddress || 'unknown',
			port: socket.remotePort || 0,
			localFeatures: this.localFeatures,
			networks: this.networks
		});

		peer
			.acceptInbound(socket)
			.then(() => {
				const pubkey = peer.remotePublicKey.toString('hex');

				// Reject if already connected
				if (this.peers.has(pubkey)) {
					peer.disconnect();
					return;
				}

				this.setupPeerListeners(pubkey, peer);
				this.peers.set(pubkey, peer);
				// Track inbound peer count
				this.inboundPeerCount++;
				this.inboundPeerSet.add(pubkey);
				// Do NOT store inbound peer address — peer.port is the TCP source (ephemeral) port,
				// not the node's listening port. Reconnect attempts to ephemeral ports always fail.
				captureWireEvent('connect', pubkey, 'inbound');
				this.emit('peer:connect', pubkey);
			})
			.catch(() => {
				// Handshake/init failed — socket already cleaned up by Peer
			});
	}

	private setupPeerListeners(pubkey: string, peer: Peer): void {
		peer.on('message', (type: number, payload: Buffer) => {
			captureWireMessage('in', pubkey, type, payload);

			// Route to type-specific handlers
			const handlers = this.messageHandlers.get(type);
			if (handlers) {
				for (const handler of handlers) {
					handler(pubkey, type, payload);
				}
			}

			// Also emit as generic event
			this.emit('message', pubkey, type, payload);
		});

		peer.on('error', (err: Error) => {
			captureWireEvent('error', pubkey, err.message);
			this.emit('peer:error', pubkey, err);
		});

		peer.on('close', () => {
			captureWireEvent('close', pubkey);
			this.peers.delete(pubkey);
			// A short-lived connection: don't let it reset the backoff.
			this.clearStabilityTimer(pubkey);
			// Decrement inbound peer count if this was an inbound connection
			if (this.inboundPeerSet.has(pubkey)) {
				this.inboundPeerCount--;
				this.inboundPeerSet.delete(pubkey);
			}
			this.emit('peer:disconnect', pubkey);

			if (this.autoReconnect && this.peerAddresses.has(pubkey)) {
				this.scheduleReconnect(pubkey);
			}
		});
	}

	private buildSocks5Factory(proxy: {
		host: string;
		port: number;
	}): (host: string, port: number) => Promise<net.Socket> {
		return async (host: string, port: number): Promise<net.Socket> => {
			const { socket } = await SocksClient.createConnection({
				proxy: { host: proxy.host, port: proxy.port, type: 5 },
				command: 'connect',
				destination: { host, port },
				// Tor circuit establishment can hang for minutes; without this the
				// SOCKS negotiation has no deadline of its own (SocksClient destroys
				// its socket on timeout, so nothing leaks). Configurable so callers
				// (and tests) can fail fast instead of waiting out a stalled proxy.
				timeout: this.socks5TimeoutMs
			});
			return socket;
		};
	}

	private scheduleReconnect(pubkey: string): void {
		if (this.reconnectTimers.has(pubkey)) return; // already scheduled
		const addr = this.peerAddresses.get(pubkey);
		if (!addr) return;

		const baseDelay =
			this.reconnectDelays.get(pubkey) || DEFAULT_INITIAL_RECONNECT_DELAY_MS;
		// Add ±25% jitter to prevent thundering herd (Fix 3.5)
		const jitter = 0.75 + Math.random() * 0.5;
		const actualDelay = Math.floor(baseDelay * jitter);
		const nextBaseDelay = Math.min(baseDelay * 2, this.maxReconnectDelay);
		this.reconnectDelays.set(pubkey, nextBaseDelay);

		const timer = setTimeout(async () => {
			this.reconnectTimers.delete(pubkey);
			try {
				await this.connectPeer(pubkey, addr.host, addr.port, addr.transport);
			} catch {
				// connectPeer re-schedules when autoReconnect is enabled
			}
		}, actualDelay);

		this.reconnectTimers.set(pubkey, timer);
	}
}
