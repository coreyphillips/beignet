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
import { getPublicKey } from '../crypto/ecdh';
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
// Cap on gossip-announced reconnect candidates kept per peer. Announcements
// are peer-controlled input; without a cap a peer could make every reconnect
// round crawl through a long list of dead addresses.
const MAX_ANNOUNCED_ADDRESSES = 5;

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
	private localPubkeyHex: string;
	private localFeatures: FeatureFlags;
	private networks?: Buffer[];
	private peers: Map<string, Peer> = new Map();
	private peerAddresses: Map<
		string,
		{ host: string; port: number; transport?: IPeerTransportOptions }
	> = new Map();
	// Addresses learned from a peer's signature-verified node_announcement.
	// Reconnect fallbacks only: a peer that has only ever connected inbound
	// exposes no dialable address (its TCP source port is ephemeral), so these
	// are the one self-recovery path for its channels. Never dialed before the
	// last-known-good outbound address in peerAddresses.
	private announcedAddresses: Map<
		string,
		Array<{ host: string; port: number }>
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
		this.localPubkeyHex = getPublicKey(options.localPrivateKey).toString('hex');
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
		try {
			await this.dialPeer(pubkey, host, port, transport);
		} catch (err) {
			if (this.autoReconnect) {
				this.scheduleReconnect(pubkey);
			}
			throw err;
		}
	}

	/**
	 * Single dial attempt. Unlike connectPeer, a failure does NOT schedule a
	 * reconnect — the reconnect loop tries several candidate addresses per round
	 * and must control when the next round starts.
	 */
	private async dialPeer(
		pubkey: string,
		host: string,
		port: number,
		transport?: IPeerTransportOptions
	): Promise<void> {
		if (this.connectionsDisabled()) {
			throw new Error(
				`Connections are ${this.connectionsDisabledReason()}; refusing dial to peer ${pubkey}`
			);
		}
		if (this.connectionGate && !this.connectionGate()) {
			throw new Error(
				`Connection gate refused dial to peer ${pubkey}: writer ownership is not confirmed`
			);
		}
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
			createSocket,
			// Held until bring-up completes: the post-handshake drain must
			// not race registration or the peer:connect handlers (a queued
			// channel_reestablish processed before our own reconnect hook
			// would suppress the reestablish WE owe).
			holdMessagesUntilRelease: true
		});

		this.setupPeerListeners(pubkey, peer);
		// Visible to freezeConnections() while establishing: a freeze aborts
		// the handshake instead of letting it complete and register later.
		this.pendingPeers.add(peer);

		try {
			await peer.connect();
		} catch (err) {
			// Restore the last-known-good address (keep the attempted one only
			// when there was no previous address, so initial connects still retry).
			if (previousAddress) {
				this.peerAddresses.set(pubkey, previousAddress);
			}
			throw err;
		} finally {
			this.pendingPeers.delete(peer);
		}
		// Recheck AFTER the async establishment: a freeze, destroy or gate
		// closure that landed mid-handshake must win over registration.
		if (
			this.connectionsDisabled() ||
			(this.connectionGate && !this.connectionGate())
		) {
			peer.removeAllListeners();
			peer.disconnect();
			throw new Error(
				`Connection to peer ${pubkey} was invalidated while establishing`
			);
		}
		// The peer may have dialed US while our handshake was in flight. Apply
		// the deterministic tie-break (see preferOutboundTo): if the registered
		// connection is inbound and we are the smaller-pubkey side, our
		// outbound wins — replace it with the same teardown bookkeeping the
		// newest-wins inbound path uses. Otherwise discard ours quietly: no
		// peer:connect for it, and no peer:disconnect when it closes. A
		// same-direction winner (two concurrent local dials) is never
		// replaced — the connections are interchangeable, keep the first.
		const raceWinner = this.peers.get(pubkey);
		if (raceWinner && raceWinner !== peer) {
			const winnerIsInbound = this.inboundPeerSet.has(pubkey);
			if (!winnerIsInbound || !this.preferOutboundTo(pubkey)) {
				peer.removeAllListeners();
				peer.disconnect();
				return;
			}
			// peer:disconnect is emitted before our peer:connect below, mirroring
			// the inbound replacement path: channels mark AWAITING_REESTABLISH
			// first, then the connect handler re-drives channel_reestablish.
			this.removeRegisteredPeer(pubkey, raceWinner);
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
		// The connect hook IS the required bring-up: the node marks its
		// channels for reestablish and sends OUR channel_reestablish in it.
		// If that work fails, releasing the held traffic (the peer's own
		// reestablish among it) would reopen the exact ordering hazard the
		// hold exists to prevent, so the connection is torn down instead
		// and the dial fails visibly. Only a completed bring-up releases.
		try {
			this.emit('peer:connect', pubkey);
		} catch (err) {
			this.removeRegisteredPeer(pubkey, peer);
			throw err instanceof Error ? err : new Error(String(err));
		}
		peer.releaseHeldMessages();
		// The release itself can legitimately end in teardown (a failed
		// held handler disconnects); make the registry agree even when no
		// socket close event backs it (both cleanups are idempotent).
		if (peer.getState() !== 'ready') {
			this.removeRegisteredPeer(pubkey, peer);
		}
	}

	private clearStabilityTimer(pubkey: string): void {
		const t = this.stabilityTimers.get(pubkey);
		if (t) {
			clearTimeout(t);
			this.stabilityTimers.delete(pubkey);
		}
	}

	/**
	 * Deterministic direction preference for simultaneous cross-dials (both
	 * nodes reconnecting to each other at once, routine after a drop when both
	 * sides auto-reconnect). Each side keeping "its" connection can select
	 * OPPOSITE physical sockets — A keeps the one B just discarded and vice
	 * versa — killing both. The convention (LND uses the same shape): the node
	 * with the lexicographically smaller pubkey keeps its outbound connection,
	 * the other keeps its inbound one, so both ends independently converge on
	 * the same socket (BOLT 1: a single connection per peer). Only applied to
	 * cross-DIRECTION collisions; same-direction ones are not ambiguous
	 * between the ends and keep their existing rules.
	 */
	private preferOutboundTo(remotePubkey: string): boolean {
		return this.localPubkeyHex < remotePubkey;
	}

	/**
	 * Tear down the registered connection for a peer, synchronously and with
	 * ALL its bookkeeping. Every removal path must go through here: the
	 * direction bookkeeping (inboundPeerSet/inboundPeerCount) feeds the
	 * cross-dial tie-break, so a path that forgets it leaves a stale entry
	 * that can flip a later collision decision (and leak the inbound count
	 * toward maxInboundPeers). Listeners are detached first: the Peer's
	 * 'close' fires on a later tick and must never act on a pubkey whose
	 * registration has already moved on.
	 */
	private removeRegisteredPeer(pubkey: string, peer: Peer): void {
		if (this.peers.get(pubkey) !== peer) return;
		peer.removeAllListeners();
		peer.disconnect();
		this.peers.delete(pubkey);
		this.clearStabilityTimer(pubkey);
		if (this.inboundPeerSet.delete(pubkey)) {
			this.inboundPeerCount--;
		}
		captureWireEvent('close', pubkey);
		this.emit('peer:disconnect', pubkey);
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
			this.removeRegisteredPeer(pubkey, peer);
		}
	}

	/**
	 * Install a gate consulted before every outbound wire message. This is
	 * the socket boundary itself: ChannelManager, gossip, peer storage and
	 * onion messages all converge here, so a closed gate holds them ALL,
	 * including any future caller that does not know the gate exists.
	 * Refused sends throw, the same contract as an unconnected peer, which
	 * every caller already treats as best-effort. Connection-level ping/pong
	 * lives inside Peer and is deliberately not gated: an inert connection
	 * stays alive.
	 */
	setOutboundGate(
		gate: ((pubkey: string, type: number) => boolean) | null
	): void {
		this.outboundGate = gate;
	}

	private outboundGate: ((pubkey: string, type: number) => boolean) | null =
		null;

	/**
	 * Install a gate consulted before any connection is ESTABLISHED, in both
	 * directions. Startup ownership quarantine (recovery 5.6) says the node
	 * may not even connect to channel peers until the writer lease is
	 * confirmed, so while the gate is closed every dial throws (dialPeer is
	 * the one chokepoint both connectPeer and the reconnect rounds use) and
	 * an inbound socket is destroyed BEFORE the BOLT 8 handshake begins:
	 * a quarantined node never authenticates, sends init, or reveals itself.
	 */
	setConnectionGate(gate: (() => boolean) | null): void {
		this.connectionGate = gate;
	}

	private connectionGate: (() => boolean) | null = null;

	/** freezeConnections() ran; no connection may ever be established again. */
	private permanentlyFrozen = false;

	/** destroy() ran; ordinary shutdown must not arm new reconnect work. */
	private destroyed = false;

	/**
	 * Both irreversible end states. Consulted wherever a connection could be
	 * established or scheduled: destroy() aborting an in-flight connectPeer
	 * lands in its catch path, which would otherwise schedule a fresh
	 * reconnect on a manager that just shut down.
	 */
	private connectionsDisabled(): boolean {
		return this.destroyed || this.permanentlyFrozen;
	}

	private connectionsDisabledReason(): string {
		return this.permanentlyFrozen ? 'permanently frozen' : 'destroyed';
	}

	/**
	 * Peers whose connect/accept is still in flight. They are invisible to
	 * listPeers() until registration, so a freeze must sweep this set or an
	 * in-flight handshake survives it and registers afterwards.
	 */
	private pendingPeers = new Set<Peer>();

	/**
	 * Listeners whose bind has not completed. this.server / this.wsServer are
	 * only assigned after the asynchronous bind, so a freeze landing mid-bind
	 * would otherwise miss the listener and leave a fenced node bound.
	 */
	private pendingTcpServers = new Set<net.Server>();
	private pendingWsServers = new Set<WebSocketServer>();

	/**
	 * Rejects listen()/listenWebSocket() calls whose bind is in flight when
	 * a teardown lands. Closing a net.Server mid-bind silently CANCELS the
	 * pending bind (no 'listening', no 'error'), so without this hook the
	 * awaiting caller would hang forever.
	 */
	private pendingListenAborts = new Set<(err: Error) => void>();

	/**
	 * Permanently stop ALL connection activity: close listeners, clear every
	 * reconnect and stability timer (they can exist for peers that are
	 * currently disconnected, which no listPeers() sweep reaches), abort
	 * every connection still ESTABLISHING, and drop every registered peer.
	 * Used by the recovery startup gate when a newer writer epoch is proven
	 * (spec 5.6 hard-freeze): after this, not one more byte leaves the node
	 * toward a Lightning peer, handshake bytes included. Irreversible.
	 */
	freezeConnections(): void {
		if (this.permanentlyFrozen) return;
		this.permanentlyFrozen = true;
		this.teardownConnections();
	}

	/**
	 * Shared teardown for freezeConnections() and destroy(), kept in one
	 * place so the two shutdown paths cannot drift apart: listeners bound
	 * AND still binding, every reconnect and stability timer, establishments
	 * still in flight, and every registered peer.
	 */
	private teardownConnections(): void {
		this.stopListening();
		for (const server of this.pendingTcpServers) {
			try {
				server.close();
			} catch {
				// The bind may not have completed; listen()'s own recheck
				// closes such a server the moment its bind resolves.
			}
		}
		this.pendingTcpServers.clear();
		for (const server of this.pendingWsServers) {
			try {
				server.close();
			} catch {
				// Same as above for the WebSocket bind.
			}
		}
		this.pendingWsServers.clear();
		for (const abort of [...this.pendingListenAborts]) {
			abort(new Error('Listener aborted: connections were torn down'));
		}
		this.pendingListenAborts.clear();
		for (const timer of this.reconnectTimers.values()) {
			clearTimeout(timer);
		}
		this.reconnectTimers.clear();
		this.reconnectDelays.clear();
		for (const timer of this.stabilityTimers.values()) {
			clearTimeout(timer);
		}
		this.stabilityTimers.clear();
		for (const peer of [...this.pendingPeers]) {
			peer.disconnect();
		}
		this.pendingPeers.clear();
		for (const pubkey of [...this.peers.keys()]) {
			this.disconnectPeer(pubkey);
		}
	}

	/**
	 * Install a gate consulted before an inbound message is dispatched to
	 * any registered handler or the generic 'message' event. Defense in
	 * depth behind the connection gate: if a connection survives from before
	 * a fence (or a race), a refused message is dropped at the transport, so
	 * nothing reaches the channel manager, gossip, onion or peer storage
	 * handlers. Ping/pong live inside Peer and are unaffected.
	 */
	setInboundGate(
		gate: ((pubkey: string, type: number) => boolean) | null
	): void {
		this.inboundGate = gate;
	}

	private inboundGate: ((pubkey: string, type: number) => boolean) | null =
		null;

	/**
	 * Send a message to a specific peer.
	 */
	sendToPeer(pubkey: string, type: number, payload: Buffer): void {
		const peer = this.peers.get(pubkey);
		if (!peer) {
			throw new Error(`Not connected to peer ${pubkey}`);
		}
		if (this.outboundGate && !this.outboundGate(pubkey, type)) {
			throw new Error(
				`Outbound gate refused message type ${type} to peer ${pubkey}`
			);
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
	 * Record dialable addresses learned from the peer's signature-verified
	 * node_announcement, used as reconnect fallbacks after the last-known-good
	 * outbound address (if any). Replaces any previous set for the peer; an
	 * empty list clears it.
	 */
	setAnnouncedAddresses(
		pubkey: string,
		addresses: Array<{ host: string; port: number }>
	): void {
		if (addresses.length === 0) {
			this.announcedAddresses.delete(pubkey);
			return;
		}
		this.announcedAddresses.set(
			pubkey,
			addresses
				.slice(0, MAX_ANNOUNCED_ADDRESSES)
				.map((a) => ({ host: a.host, port: a.port }))
		);
	}

	/**
	 * Gossip-announced reconnect fallbacks currently held for a peer.
	 */
	getAnnouncedAddresses(pubkey: string): Array<{ host: string; port: number }> {
		return [...(this.announcedAddresses.get(pubkey) ?? [])];
	}

	/**
	 * Addresses a reconnect round dials, in order: the last-known-good outbound
	 * address first, then gossip-announced fallbacks (deduplicated against it).
	 */
	private reconnectCandidates(
		pubkey: string
	): Array<{ host: string; port: number; transport?: IPeerTransportOptions }> {
		const candidates: Array<{
			host: string;
			port: number;
			transport?: IPeerTransportOptions;
		}> = [];
		const dialed = this.peerAddresses.get(pubkey);
		if (dialed) candidates.push(dialed);
		for (const addr of this.announcedAddresses.get(pubkey) ?? []) {
			if (
				!candidates.some((c) => c.host === addr.host && c.port === addr.port)
			) {
				candidates.push(addr);
			}
		}
		return candidates;
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
		if (this.connectionsDisabled()) {
			throw new Error(
				`Connections are ${this.connectionsDisabledReason()}; refusing to listen`
			);
		}
		if (this.server) {
			throw new Error('Already listening');
		}

		const server = net.createServer((socket) => {
			this.handleInboundConnection(socket);
		});
		server.on('error', (err) => {
			this.emit('listen:error', err);
		});
		// Visible to freezeConnections() while the bind is in flight.
		this.pendingTcpServers.add(server);
		let abortBind: (err: Error) => void = () => undefined;
		const abortPromise = new Promise<never>((_, reject) => {
			abortBind = reject;
		});
		abortPromise.catch(() => {
			// Consumed via the race when a teardown lands mid-bind.
		});
		this.pendingListenAborts.add(abortBind);
		try {
			await Promise.race([
				new Promise<void>((resolve, reject) => {
					server.once('error', (err) => {
						if (!this.server) {
							reject(err);
						}
					});
					server.listen(port, host, () => {
						resolve();
					});
				}),
				abortPromise
			]);
			// Recheck AFTER the bind: a freeze that landed mid-bind must win
			// over publication, or a fenced node stays externally bound.
			if (this.connectionsDisabled()) {
				server.close();
				throw new Error(
					`Listener invalidated while starting: connections are ${this.connectionsDisabledReason()}`
				);
			}
			this.server = server;
			this.emit('listening', port, host);
		} finally {
			this.pendingListenAborts.delete(abortBind);
			this.pendingTcpServers.delete(server);
		}
	}

	/**
	 * Start listening for inbound peers over WebSocket (RFC 6455). Opt-in and
	 * additive: coexists with (does not replace) the TCP listener.
	 */
	async listenWebSocket(port: number, host = '0.0.0.0'): Promise<void> {
		if (this.connectionsDisabled()) {
			throw new Error(
				`Connections are ${this.connectionsDisabledReason()}; refusing to listen`
			);
		}
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
		// Visible to freezeConnections() while the bind is in flight.
		this.pendingWsServers.add(server);
		let abortBind: (err: Error) => void = () => undefined;
		const abortPromise = new Promise<never>((_, reject) => {
			abortBind = reject;
		});
		abortPromise.catch(() => {
			// Consumed via the race when a teardown lands mid-bind.
		});
		this.pendingListenAborts.add(abortBind);
		try {
			const bind = server.listen(port, host);
			bind.catch(() => {
				// Consumed via the race; an abort winning must not leave the
				// losing bind's rejection unhandled.
			});
			await Promise.race([bind, abortPromise]);
			// Recheck AFTER the bind, exactly as in listen().
			if (this.connectionsDisabled()) {
				server.close();
				throw new Error(
					`Listener invalidated while starting: connections are ${this.connectionsDisabledReason()}`
				);
			}
			this.wsServer = server;
			const addr = server.address();
			const boundPort = addr && typeof addr === 'object' ? addr.port : port;
			this.emit('listening:ws', boundPort, host);
		} finally {
			this.pendingListenAborts.delete(abortBind);
			this.pendingWsServers.delete(server);
		}
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
		if (this.destroyed) return;
		// Set BEFORE the teardown: aborting an in-flight connectPeer lands in
		// its catch path, which consults this flag before rescheduling.
		this.destroyed = true;
		this.teardownConnections();
		this.announcedAddresses.clear();
		this.messageHandlers.clear();
	}

	private handleInboundConnection(socket: IDuplexTransport): void {
		// Quarantined, fenced or frozen (recovery 5.6): destroy the socket
		// BEFORE the BOLT 8 handshake, so a node that cannot prove writer
		// ownership never authenticates or exchanges init with anyone.
		if (
			this.connectionsDisabled() ||
			(this.connectionGate && !this.connectionGate())
		) {
			socket.destroy();
			return;
		}
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
			networks: this.networks,
			// Held until bring-up completes; see the outbound twin. For
			// inbound this also closes the harder gap: the drain runs
			// before acceptInbound() resolves, when no listener is even
			// attached yet, so unheld coalesced frames would be LOST, not
			// merely early.
			holdMessagesUntilRelease: true
		});

		// Visible to freezeConnections() while the handshake is in flight.
		this.pendingPeers.add(peer);

		peer
			.acceptInbound(socket)
			.then(() => {
				this.pendingPeers.delete(peer);
				// Recheck AFTER the handshake: a freeze or gate closure that
				// landed mid-establishment must win over registration.
				if (
					this.connectionsDisabled() ||
					(this.connectionGate && !this.connectionGate())
				) {
					peer.disconnect();
					return;
				}
				const pubkey = peer.remotePublicKey.toString('hex');

				const existing = this.peers.get(pubkey);

				// Cross-direction collision (we hold an outbound connection or
				// dial to this peer): resolve deterministically so both ends
				// keep the SAME socket (see preferOutboundTo). When we are the
				// smaller-pubkey side our outbound wins — drop this inbound; the
				// peer's dialPeer discards its outbound symmetrically. This
				// intentionally covers a possibly-stale outbound too (matching
				// LND): rejecting the re-dial costs at most one ping cycle
				// before the dead socket is noticed, whereas newest-wins on
				// cross-direction collisions lets the two ends select opposite
				// sockets and kill both.
				if (
					existing &&
					!this.inboundPeerSet.has(pubkey) &&
					this.preferOutboundTo(pubkey)
				) {
					peer.disconnect();
					return;
				}

				// Newest wins (matches LND/CLN/LDK): when a peer's old inbound
				// connection dies on its side (common over Tor circuits), the
				// remote re-dials before our ping/pong timeout notices the stale
				// socket. Rejecting the fresh connection keeps the dead one, and
				// inbound peers store no dialable address (their TCP source port
				// is ephemeral), so the only self-recovery is a gossip-announced
				// fallback that may not exist: channels could sit in
				// AWAITING_REESTABLISH until a human forces a reconnect.
				if (existing) {
					// Tear the old connection down synchronously with our own
					// bookkeeping. peer:disconnect is emitted before the
					// replacement's peer:connect so channels are marked
					// AWAITING_REESTABLISH first and the connect handler then
					// re-drives channel_reestablish over the new connection.
					this.removeRegisteredPeer(pubkey, existing);
				}

				this.setupPeerListeners(pubkey, peer);
				this.peers.set(pubkey, peer);
				// Track inbound peer count
				this.inboundPeerCount++;
				this.inboundPeerSet.add(pubkey);
				// Do NOT store inbound peer address — peer.port is the TCP source (ephemeral) port,
				// not the node's listening port. Reconnect attempts to ephemeral ports always fail.
				captureWireEvent('connect', pubkey, 'inbound');
				// The outbound twin's rule: only a completed bring-up
				// releases; a failed one tears the connection down (the
				// remote will redial and BOTH sides retry the bring-up).
				try {
					this.emit('peer:connect', pubkey);
				} catch (err) {
					this.removeRegisteredPeer(pubkey, peer);
					try {
						this.emit(
							'peer:error',
							pubkey,
							err instanceof Error ? err : new Error(String(err))
						);
					} catch {
						// The error observer threw too; the teardown already
						// happened, which is the outcome that matters.
					}
					return;
				}
				peer.releaseHeldMessages();
				if (peer.getState() !== 'ready') {
					this.removeRegisteredPeer(pubkey, peer);
				}
			})
			.catch(() => {
				// Handshake/init failed — socket already cleaned up by Peer
				this.pendingPeers.delete(peer);
			});
	}

	private dispatchPeerMessage(
		pubkey: string,
		type: number,
		payload: Buffer
	): void {
		// Inbound dispatch gate: a refused message is dropped here, before
		// any handler (channel, gossip, onion, peer storage) can act on it.
		if (this.inboundGate && !this.inboundGate(pubkey, type)) {
			return;
		}

		// Route to type-specific handlers
		const handlers = this.messageHandlers.get(type);
		if (handlers) {
			for (const handler of handlers) {
				handler(pubkey, type, payload);
			}
		}

		// Also emit as generic event
		this.emit('message', pubkey, type, payload);
	}

	private setupPeerListeners(pubkey: string, peer: Peer): void {
		peer.on('message', (type: number, payload: Buffer) => {
			captureWireMessage('in', pubkey, type, payload);
			this.dispatchPeerMessage(pubkey, type, payload);
		});

		peer.on('error', (err: Error) => {
			captureWireEvent('error', pubkey, err.message);
			this.emit('peer:error', pubkey, err);
		});

		peer.on('close', () => {
			// Only the currently registered instance may tear down the peer's
			// bookkeeping. A connection that lost a cross-dial race (or was
			// replaced by a fresh inbound) closes later; keying the map by
			// pubkey alone would let that stale close delete the live
			// replacement's entry and emit a spurious peer:disconnect.
			if (this.peers.get(pubkey) !== peer) return;
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

			if (this.autoReconnect && this.reconnectCandidates(pubkey).length > 0) {
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
		if (this.connectionsDisabled()) return; // frozen or destroyed: never redial
		if (this.reconnectTimers.has(pubkey)) return; // already scheduled
		if (this.reconnectCandidates(pubkey).length === 0) return;

		const baseDelay =
			this.reconnectDelays.get(pubkey) || DEFAULT_INITIAL_RECONNECT_DELAY_MS;
		// Add ±25% jitter to prevent thundering herd (Fix 3.5)
		const jitter = 0.75 + Math.random() * 0.5;
		const actualDelay = Math.floor(baseDelay * jitter);
		const nextBaseDelay = Math.min(baseDelay * 2, this.maxReconnectDelay);
		this.reconnectDelays.set(pubkey, nextBaseDelay);

		const timer = setTimeout(async () => {
			this.reconnectTimers.delete(pubkey);
			// The peer may have re-dialed us while we waited (common over Tor).
			if (this.peers.has(pubkey)) return;
			// Candidates are re-read at fire time so addresses learned while
			// waiting (e.g. a fresh node_announcement) are included.
			for (const addr of this.reconnectCandidates(pubkey)) {
				try {
					await this.dialPeer(pubkey, addr.host, addr.port, addr.transport);
					return;
				} catch {
					// try the next candidate
				}
			}
			// Every candidate failed: next round with a larger backoff.
			this.scheduleReconnect(pubkey);
		}, actualDelay);

		this.reconnectTimers.set(pubkey, timer);
	}
}
