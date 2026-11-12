/**
 * The Porch relay server (docs/PORCH-PROTOCOL.md): it pairs a host's standby
 * connection with a visitor's and copies WebSocket frames between them.
 *
 * It holds no keys and stores nothing. A route exists exactly while an idle
 * standby lists it, so restarting the relay loses only the connections that
 * were open. Everything it sees after pairing is BOLT 8 ciphertext.
 *
 * Standalone by design: `beignet porch-relay` runs it on a machine that has
 * no wallet, and nothing a node loads imports this file. The command's flags
 * are read at the end of the file.
 */

import crypto from 'crypto';
import { EventEmitter } from 'events';
import fs from 'fs';
import http from 'http';
import https from 'https';
import type net from 'net';
import { isIP } from 'net';
import { inboundAddressKey } from '../lightning/transport/peer-manager';
import { HttpRateLimiter, clientKeyForRequest } from './http-rate-limiter';
import type {
	IPorchRegistration,
	PorchControlMessage
} from '../lightning/transport/porch';
import {
	PORCH_CLOSE_REFUSED,
	PORCH_CLOSE_TRY_LATER,
	PORCH_HOST_PATH,
	PORCH_MAX_CONTROL_BYTES,
	PORCH_MAX_TAGS,
	PORCH_MAX_TOKEN_BYTES,
	PORCH_NONCE_BYTES,
	PORCH_VERSION,
	PORCH_VISITOR_PATH_PREFIX,
	checkPorchRegister,
	decodePorchControl,
	encodePorchControl,
	isPorchRouteId,
	parsePorchRelayUrl
} from '../lightning/transport/porch';
import type { IWsFrame } from '../lightning/transport/websocket-frame';
import {
	WsCloseCode,
	WsFrameParser,
	WsOpcode,
	WsProtocolError,
	encodeWsClosePayload,
	encodeWsFrame
} from '../lightning/transport/websocket-frame';
import {
	acceptWebSocketUpgrade,
	checkWebSocketUpgrade,
	denyWebSocketUpgrade
} from '../lightning/transport/websocket-server';

export interface IPorchRelayLimits {
	/** Idle standbys one host key may hold; a further one replaces the oldest. */
	standbysPerHost: number;
	/** Circuits open at once under one host key. */
	circuitsPerHost: number;
	/** Links one registration may list. */
	tagsPerRegistration: number;
	/** Distinct host keys with a standby or a circuit. */
	hosts: number;
	/** Visitors at once from one source address, waiting or paired. */
	visitorsPerAddress: number;
	/** Connections from one source address not yet registered or paired. */
	pendingPerAddress: number;
	/**
	 * Idle standbys from one source address, whatever keys they registered:
	 * what stops one address from filling the table of hosts.
	 */
	standbysPerAddress: number;
	/**
	 * Upgrades one source address may start in a minute, as a host or as a
	 * visitor. Each one costs the relay a signature check or a host a standby.
	 */
	upgradesPerMinute: number;
	/** Sockets in total, whatever they are doing. */
	connections: number;
	/** From the challenge to a valid registration. */
	registerTimeoutMs: number;
	/** How long a visitor is held for a standby that is on its way. */
	pairWaitMs: number;
	/** Largest WebSocket frame accepted from either side. */
	messageBytes: number;
	/** Bytes held for a visitor that is not paired yet. */
	visitorHoldBytes: number;
	/** Unsent bytes toward a slow side before the other is paused. */
	queueBytes: number;
	/** A circuit with no bytes in either direction is closed after this. */
	circuitIdleMs: number;
	/** How often an idle standby is pinged. */
	pingIntervalMs: number;
	/** Unanswered pings after which a standby is dropped. */
	missedPings: number;
}

export const DEFAULT_PORCH_RELAY_LIMITS: Readonly<IPorchRelayLimits> = {
	standbysPerHost: 8,
	circuitsPerHost: 64,
	tagsPerRegistration: PORCH_MAX_TAGS,
	hosts: 1_024,
	visitorsPerAddress: 16,
	pendingPerAddress: 32,
	standbysPerAddress: 16,
	upgradesPerMinute: 120,
	connections: 4_096,
	registerTimeoutMs: 10_000,
	pairWaitMs: 3_000,
	messageBytes: 128 * 1024,
	visitorHoldBytes: 64 * 1024,
	queueBytes: 256 * 1024,
	circuitIdleMs: 10 * 60_000,
	pingIntervalMs: 20_000,
	missedPings: 2
};

export interface IPorchRelayOptions {
	/**
	 * The relay's public names (`host` or `host:port`, lower case, without a
	 * port that is the scheme's default): what a host's URL says. A challenge
	 * names the one the request's Host header matches, or the first. The
	 * header only ever selects among these.
	 */
	authorities: string[];
	/** When set, a registration must carry it: a private relay. */
	token?: string;
	/** Serve wss:// directly. Without it, put a TLS terminator in front. */
	tls?: { cert: string | Buffer; key: string | Buffer };
	/**
	 * Reverse proxies whose X-Forwarded-For is believed, by address. Without
	 * this every connection through a proxy counts as the proxy's.
	 */
	trustedProxies?: string[];
	limits?: Partial<IPorchRelayLimits>;
	/**
	 * The admission key of a source address, null for one that is not
	 * limited. Defaults to the node's own rule: public IPv4 by address,
	 * IPv6 by /64, private and loopback unlimited.
	 */
	addressKey?: (address: string | undefined) => string | null;
}

export interface IPorchRelayStats {
	hosts: number;
	standbys: number;
	circuits: number;
	visitorsWaiting: number;
	connections: number;
	/** Since start. */
	paired: number;
	refusedRegistrations: number;
	visitorsTurnedAway: number;
}

// ─── One WebSocket connection, already upgraded ────────────────

/**
 * Frames in, frames out. Pings are answered and the close handshake is
 * completed here; data frames go to `onData` untouched, fragment by
 * fragment, which is all a relay needs.
 */
class RelayConnection {
	onText: (text: string) => void = () => undefined;
	onData: (frame: IWsFrame) => void = () => undefined;
	/** Once, when the connection is gone for any reason. */
	onGone: (code: number) => void = () => undefined;
	private readonly parser: WsFrameParser;
	private closeSent = false;
	private gone = false;
	/** A text message may not be fragmented, so one flag is enough. */
	private fragmentedData = false;

	constructor(
		readonly socket: net.Socket,
		maxFrameBytes: number
	) {
		this.parser = new WsFrameParser({
			maxPayloadBytes: maxFrameBytes,
			requireMasked: true
		});
		socket.setNoDelay(true);
		socket.on('data', (chunk: Buffer) => this.read(chunk));
		socket.on('error', () => undefined);
		// The HTTP server hands out sockets that stay writable after the peer
		// ends its side: a peer that leaves without a close frame is gone.
		socket.on('end', () => socket.destroy());
		socket.on('close', () => this.finish(WsCloseCode.GOING_AWAY));
	}

	get open(): boolean {
		return !this.gone && !this.closeSent;
	}

	read(chunk: Buffer): void {
		if (this.gone || this.closeSent) return;
		let frames: IWsFrame[];
		try {
			frames = this.parser.push(chunk);
		} catch (err) {
			this.close(
				err instanceof WsProtocolError
					? err.closeCode
					: WsCloseCode.PROTOCOL_ERROR
			);
			return;
		}
		for (const frame of frames) {
			if (this.gone || this.closeSent) return;
			this.handle(frame);
		}
	}

	private handle(frame: IWsFrame): void {
		switch (frame.opcode) {
			case WsOpcode.PING:
				this.write(WsOpcode.PONG, frame.payload);
				return;
			case WsOpcode.PONG:
				return;
			case WsOpcode.CLOSE: {
				const code =
					frame.payload.length >= 2
						? frame.payload.readUInt16BE(0)
						: WsCloseCode.NORMAL;
				this.close(WsCloseCode.NORMAL, code);
				return;
			}
			case WsOpcode.TEXT:
				if (!frame.fin || this.fragmentedData) {
					this.close(WsCloseCode.PROTOCOL_ERROR);
					return;
				}
				this.onText(frame.payload.toString('utf8'));
				return;
			case WsOpcode.BINARY:
				if (this.fragmentedData) {
					this.close(WsCloseCode.PROTOCOL_ERROR);
					return;
				}
				this.fragmentedData = !frame.fin;
				this.onData(frame);
				return;
			case WsOpcode.CONTINUATION:
				if (!this.fragmentedData) {
					this.close(WsCloseCode.PROTOCOL_ERROR);
					return;
				}
				this.fragmentedData = !frame.fin;
				this.onData(frame);
				return;
			default:
				this.close(WsCloseCode.PROTOCOL_ERROR);
		}
	}

	/** Returns the socket's unsent byte count after the write. */
	write(opcode: number, payload: Buffer, fin = true): number {
		if (this.gone || this.closeSent || this.socket.destroyed) return 0;
		this.socket.write(encodeWsFrame({ opcode, payload, fin }));
		return this.socket.writableLength;
	}

	sendControl(message: PorchControlMessage): void {
		this.write(WsOpcode.TEXT, Buffer.from(encodePorchControl(message)));
	}

	/**
	 * Send a close frame and let go of the socket. `reported` is the code
	 * handed to onGone when it differs from the one sent: the other side's
	 * own close code, when this is the echo of its close.
	 */
	close(code: number, reported = code): void {
		if (this.gone) return;
		if (!this.closeSent) {
			if (!this.socket.destroyed && this.socket.writable) {
				this.socket.write(
					encodeWsFrame({
						opcode: WsOpcode.CLOSE,
						payload: encodeWsClosePayload(code, '')
					})
				);
			}
			this.closeSent = true;
			this.socket.end();
			const timer = setTimeout(() => this.socket.destroy(), 1000);
			timer.unref();
		}
		this.finish(reported);
	}

	private finish(code: number): void {
		if (this.gone) return;
		this.gone = true;
		this.onGone(code);
	}
}

// ─── Relay state ───────────────────────────────────────────────

interface IHostRecord {
	/** Idle standbys, oldest first. */
	standbys: Set<IStandby>;
	circuits: number;
}

interface IStandby {
	conn: RelayConnection;
	hostKey: string;
	/** The source address it counts under. */
	source: string | null;
	/** Route id to the tag it stands for, hex. */
	routes: Map<string, string>;
	unanswered: number;
}

interface IVisitor {
	conn: RelayConnection;
	routeId: string;
	held: IWsFrame[];
	heldBytes: number;
	timer: ReturnType<typeof setTimeout>;
	/** Stop counting this connection as one that is not paired yet. */
	settle: () => void;
}

interface ICircuit {
	host: RelayConnection;
	visitor: RelayConnection;
	hostKey: string;
	lastActivity: number;
}

function sameToken(a: string, b: string): boolean {
	return crypto.timingSafeEqual(
		crypto.createHash('sha256').update(a).digest(),
		crypto.createHash('sha256').update(b).digest()
	);
}

/** A close code that may be passed on to the other side of a circuit. */
function forwardableCloseCode(code: number): number {
	return code === WsCloseCode.NORMAL || (code >= 3000 && code <= 4999)
		? code
		: WsCloseCode.GOING_AWAY;
}

/**
 * Events: 'error' (the listening socket failed). The relay reports nothing
 * about who connected; stats() has the counts.
 */
export class PorchRelay extends EventEmitter {
	readonly limits: Readonly<IPorchRelayLimits>;
	private readonly authorities: string[];
	private readonly token?: string;
	private readonly trustedProxies: string[];
	private readonly upgradeRate: HttpRateLimiter;
	private readonly addressKey: (address: string | undefined) => string | null;
	private readonly server: http.Server;
	/** Every TCP connection; under TLS, the socket beneath the stream. */
	private readonly sockets = new Set<net.Socket>();
	private readonly hosts = new Map<string, IHostRecord>();
	/** Idle standbys by each route id they serve, oldest first. */
	private readonly idle = new Map<string, Set<IStandby>>();
	private readonly waiting = new Map<string, Set<IVisitor>>();
	private readonly circuits = new Set<ICircuit>();
	private readonly pendingByAddress = new Map<string, number>();
	private readonly standbysByAddress = new Map<string, number>();
	private readonly visitorsByAddress = new Map<string, number>();
	private timers: Array<ReturnType<typeof setInterval>> = [];
	private counters = {
		paired: 0,
		refusedRegistrations: 0,
		visitorsTurnedAway: 0
	};

	constructor(options: IPorchRelayOptions) {
		super();
		this.authorities = options.authorities.map((a) => a.toLowerCase());
		if (this.authorities.length === 0 || this.authorities.some((a) => !a)) {
			throw new Error('A Porch relay needs its public name (authority)');
		}
		if (options.token !== undefined && options.token === '') {
			throw new Error('The Porch relay token is empty');
		}
		this.token = options.token;
		this.limits = { ...DEFAULT_PORCH_RELAY_LIMITS, ...options.limits };
		for (const [name, value] of Object.entries(this.limits)) {
			if (!Number.isInteger(value) || value < 1) {
				throw new Error(`Porch relay limit ${name} must be a positive integer`);
			}
		}
		if (this.limits.messageBytes < PORCH_MAX_CONTROL_BYTES) {
			throw new Error(
				`Porch relay limit messageBytes must be at least ${PORCH_MAX_CONTROL_BYTES}`
			);
		}
		this.trustedProxies = options.trustedProxies ?? [];
		this.upgradeRate = new HttpRateLimiter({
			maxRequests: this.limits.upgradesPerMinute,
			windowMs: 60_000
		});
		this.addressKey = options.addressKey ?? inboundAddressKey;

		const onRequest = (
			req: http.IncomingMessage,
			res: http.ServerResponse
		): void => {
			const path = (req.url ?? '/').split('?')[0];
			const ok = req.method === 'GET' && path === '/health';
			const body = ok ? '{"ok":true}' : '{"ok":false}';
			res.writeHead(ok ? 200 : 404, {
				'Content-Type': 'application/json',
				'Content-Length': Buffer.byteLength(body),
				Connection: 'close'
			});
			res.end(body);
		};
		this.server = options.tls
			? https.createServer(options.tls, onRequest)
			: http.createServer(onRequest);
		this.server.maxConnections = this.limits.connections;
		this.server.headersTimeout = 10_000;
		this.server.requestTimeout = 10_000;
		this.server.keepAliveTimeout = 1_000;
		// 'connection' is the TCP socket with or without TLS, so a connection
		// is counted once and destroying it ends whatever runs on top.
		this.server.on('connection', (socket: net.Socket) => {
			this.sockets.add(socket);
			socket.once('close', () => this.sockets.delete(socket));
		});
		this.server.on('tlsClientError', () => undefined);
		this.server.on('clientError', (_err, socket) => socket.destroy());
		this.server.on(
			'upgrade',
			(req: http.IncomingMessage, socket: net.Socket, head: Buffer) =>
				this.handleUpgrade(req, socket, head)
		);
		this.server.on('error', (err) => this.emit('error', err));
	}

	listen(port: number, host?: string): Promise<void> {
		return new Promise((resolve, reject) => {
			const onError = (err: Error): void => reject(err);
			this.server.once('error', onError);
			this.server.listen(port, host, () => {
				this.server.removeListener('error', onError);
				const ping = setInterval(
					() => this.pingStandbys(),
					this.limits.pingIntervalMs
				);
				const reap = setInterval(
					() => this.reapIdleCircuits(),
					Math.max(100, Math.floor(this.limits.circuitIdleMs / 4))
				);
				ping.unref();
				reap.unref();
				this.timers = [ping, reap];
				resolve();
			});
		});
	}

	address(): net.AddressInfo | string | null {
		return this.server.address();
	}

	stats(): IPorchRelayStats {
		let standbys = 0;
		for (const host of this.hosts.values()) standbys += host.standbys.size;
		let visitorsWaiting = 0;
		for (const set of this.waiting.values()) visitorsWaiting += set.size;
		return {
			hosts: this.hosts.size,
			standbys,
			circuits: this.circuits.size,
			visitorsWaiting,
			connections: this.sockets.size,
			...this.counters
		};
	}

	/** Stop listening and drop every connection. */
	close(): Promise<void> {
		for (const timer of this.timers) clearInterval(timer);
		this.timers = [];
		this.upgradeRate.destroy();
		const closed = new Promise<void>((resolve) => {
			this.server.close(() => resolve());
		});
		for (const socket of this.sockets) socket.destroy();
		return closed;
	}

	// ── Admission ────────────────────────────────────────────────

	/**
	 * The source a connection counts under, or null when it is not limited.
	 * Behind a proxy it was told to trust, that is the address the proxy saw.
	 */
	private sourceKey(
		req: http.IncomingMessage,
		socket: net.Socket
	): string | null {
		return this.addressKey(
			clientKeyForRequest(
				socket.remoteAddress,
				req.headers['x-forwarded-for'],
				this.trustedProxies
			)
		);
	}

	private static count(
		map: Map<string, number>,
		key: string | null,
		delta: 1 | -1
	): void {
		if (key === null) return;
		const next = (map.get(key) ?? 0) + delta;
		if (next <= 0) map.delete(key);
		else map.set(key, next);
	}

	private challengeAuthority(req: http.IncomingMessage): string {
		const named = (req.headers.host ?? '').toLowerCase();
		for (const candidate of [named, named.replace(/:(443|80)$/, '')]) {
			if (this.authorities.includes(candidate)) return candidate;
		}
		return this.authorities[0];
	}

	private handleUpgrade(
		req: http.IncomingMessage,
		socket: net.Socket,
		head: Buffer
	): void {
		socket.on('error', () => undefined);
		const checked = checkWebSocketUpgrade(req);
		if ('deny' in checked) return denyWebSocketUpgrade(socket, checked.deny);
		const path = (req.url ?? '/').split('?')[0];
		const routeId = path.startsWith(PORCH_VISITOR_PATH_PREFIX)
			? path.slice(PORCH_VISITOR_PATH_PREFIX.length)
			: undefined;
		const isHost = path === PORCH_HOST_PATH;
		if (!isHost && !isPorchRouteId(routeId)) {
			return denyWebSocketUpgrade(socket, {
				status: 404,
				message: 'Not Found'
			});
		}
		const source = this.sourceKey(req, socket);
		const tooMany = { status: 429, message: 'Too Many Requests' };
		if (
			source !== null &&
			((this.pendingByAddress.get(source) ?? 0) >=
				this.limits.pendingPerAddress ||
				!this.upgradeRate.isAllowed(source))
		) {
			return denyWebSocketUpgrade(socket, tooMany);
		}
		if (
			!isHost &&
			source !== null &&
			(this.visitorsByAddress.get(source) ?? 0) >=
				this.limits.visitorsPerAddress
		) {
			this.counters.visitorsTurnedAway++;
			return denyWebSocketUpgrade(socket, tooMany);
		}

		acceptWebSocketUpgrade(socket, checked.key);
		const conn = new RelayConnection(socket, this.limits.messageBytes);
		PorchRelay.count(this.pendingByAddress, source, 1);
		let pending = true;
		const settle = (): void => {
			if (!pending) return;
			pending = false;
			PorchRelay.count(this.pendingByAddress, source, -1);
		};
		if (isHost) {
			this.acceptHost(conn, this.challengeAuthority(req), source, settle);
		} else this.acceptVisitor(conn, routeId as string, source, settle);
		if (head.length > 0) conn.read(head);
	}

	// ── Hosts ────────────────────────────────────────────────────

	private acceptHost(
		conn: RelayConnection,
		authority: string,
		source: string | null,
		settle: () => void
	): void {
		const nonce = crypto.randomBytes(PORCH_NONCE_BYTES);
		const deadline = setTimeout(
			() => conn.close(PORCH_CLOSE_REFUSED),
			this.limits.registerTimeoutMs
		);
		deadline.unref();
		let standby: IStandby | undefined;
		conn.onGone = (): void => {
			clearTimeout(deadline);
			settle();
			if (standby) this.dropStandby(standby);
		};
		// A host sends nothing but control messages until it is paired.
		conn.onData = (): void => conn.close(WsCloseCode.PROTOCOL_ERROR);
		conn.onText = (text): void => {
			const message = decodePorchControl(text);
			if (standby) {
				if (message?.t === 'pong') standby.unanswered = 0;
				else conn.close(WsCloseCode.PROTOCOL_ERROR);
				return;
			}
			if (message?.t !== 'register') {
				this.counters.refusedRegistrations++;
				conn.close(PORCH_CLOSE_REFUSED);
				return;
			}
			const checked = checkPorchRegister(
				message,
				{ nonce, authority },
				this.limits.tagsPerRegistration
			);
			if (
				'refused' in checked ||
				(this.token !== undefined &&
					!sameToken(checked.token ?? '', this.token))
			) {
				this.counters.refusedRegistrations++;
				conn.close(PORCH_CLOSE_REFUSED);
				return;
			}
			clearTimeout(deadline);
			standby = this.addStandby(conn, checked, source);
			if (!standby) {
				conn.close(PORCH_CLOSE_TRY_LATER);
				return;
			}
			settle();
			conn.sendControl({ t: 'ready' });
			this.serveWaitingVisitor(standby);
		};
		conn.sendControl({
			t: 'challenge',
			v: PORCH_VERSION,
			nonce: nonce.toString('hex'),
			authority
		});
	}

	private addStandby(
		conn: RelayConnection,
		registration: IPorchRegistration,
		source: string | null
	): IStandby | undefined {
		if (
			source !== null &&
			(this.standbysByAddress.get(source) ?? 0) >=
				this.limits.standbysPerAddress
		) {
			return undefined;
		}
		const hostKey = registration.hostKey.toString('hex');
		let host = this.hosts.get(hostKey);
		if (!host) {
			if (this.hosts.size >= this.limits.hosts) return undefined;
			host = { standbys: new Set(), circuits: 0 };
			this.hosts.set(hostKey, host);
		}
		// The newest connection proved the key against a fresh nonce: when the
		// host is at its cap, the oldest standby is the one most likely dead.
		while (host.standbys.size >= this.limits.standbysPerHost) {
			const oldest = host.standbys.values().next().value as IStandby;
			oldest.conn.close(WsCloseCode.GOING_AWAY);
		}
		// Closing the last standby of a host with no circuit forgets the host.
		this.hosts.set(hostKey, host);
		const standby: IStandby = {
			conn,
			hostKey,
			source,
			routes: new Map(
				registration.routeIds.map((routeId, i) => [
					routeId,
					registration.tags[i].toString('hex')
				])
			),
			unanswered: 0
		};
		host.standbys.add(standby);
		PorchRelay.count(this.standbysByAddress, source, 1);
		for (const routeId of standby.routes.keys()) {
			let set = this.idle.get(routeId);
			if (!set) this.idle.set(routeId, (set = new Set()));
			set.add(standby);
		}
		return standby;
	}

	/**
	 * Take a standby out of the idle sets; its connection is left alone.
	 * `paired` keeps the host's record for the circuit that follows.
	 */
	private dropStandby(standby: IStandby, paired = false): void {
		const host = this.hosts.get(standby.hostKey);
		if (!host || !host.standbys.delete(standby)) return;
		PorchRelay.count(this.standbysByAddress, standby.source, -1);
		for (const routeId of standby.routes.keys()) {
			const set = this.idle.get(routeId);
			if (set?.delete(standby) && set.size === 0) this.idle.delete(routeId);
		}
		if (!paired) this.forgetHostIfUnused(standby.hostKey);
	}

	private forgetHostIfUnused(hostKey: string): void {
		const host = this.hosts.get(hostKey);
		if (host && host.standbys.size === 0 && host.circuits === 0) {
			this.hosts.delete(hostKey);
		}
	}

	private pingStandbys(): void {
		for (const host of this.hosts.values()) {
			for (const standby of [...host.standbys]) {
				if (standby.unanswered >= this.limits.missedPings) {
					standby.conn.close(WsCloseCode.GOING_AWAY);
					continue;
				}
				standby.unanswered++;
				standby.conn.sendControl({ t: 'ping' });
			}
		}
	}

	// ── Visitors ─────────────────────────────────────────────────

	private acceptVisitor(
		conn: RelayConnection,
		routeId: string,
		source: string | null,
		settle: () => void
	): void {
		PorchRelay.count(this.visitorsByAddress, source, 1);
		const visitor: IVisitor = {
			conn,
			routeId,
			held: [],
			heldBytes: 0,
			timer: setTimeout(() => {
				this.counters.visitorsTurnedAway++;
				conn.close(PORCH_CLOSE_TRY_LATER);
			}, this.limits.pairWaitMs),
			settle
		};
		visitor.timer.unref();
		conn.onGone = (): void => {
			clearTimeout(visitor.timer);
			settle();
			PorchRelay.count(this.visitorsByAddress, source, -1);
			this.stopWaiting(visitor);
		};
		// A visitor speaks BOLT 8 and nothing else.
		conn.onText = (): void => conn.close(WsCloseCode.UNSUPPORTED_DATA);
		conn.onData = (frame): void => {
			visitor.heldBytes += frame.payload.length;
			if (visitor.heldBytes > this.limits.visitorHoldBytes) {
				conn.close(WsCloseCode.MESSAGE_TOO_BIG);
				return;
			}
			visitor.held.push(frame);
		};

		for (const standby of [...(this.idle.get(routeId) ?? [])]) {
			if (this.pair(standby, visitor)) return;
		}
		let set = this.waiting.get(routeId);
		if (!set) this.waiting.set(routeId, (set = new Set()));
		set.add(visitor);
	}

	private stopWaiting(visitor: IVisitor): void {
		const set = this.waiting.get(visitor.routeId);
		if (set?.delete(visitor) && set.size === 0) {
			this.waiting.delete(visitor.routeId);
		}
	}

	/** A standby just became idle: give it to the visitor waiting longest. */
	private serveWaitingVisitor(standby: IStandby): void {
		for (const routeId of standby.routes.keys()) {
			for (const visitor of [...(this.waiting.get(routeId) ?? [])]) {
				if (!this.pair(standby, visitor)) return;
				// Paired, or that visitor was turned away and the standby is
				// still idle for the next one.
				if (!standby.conn.open || !this.isIdle(standby)) return;
			}
		}
	}

	private isIdle(standby: IStandby): boolean {
		return this.hosts.get(standby.hostKey)?.standbys.has(standby) ?? false;
	}

	/**
	 * Join a visitor to a standby. False when the standby cannot be used and
	 * the visitor is still looking; true when the visitor is dealt with,
	 * whether paired or turned away.
	 */
	private pair(standby: IStandby, visitor: IVisitor): boolean {
		const host = this.hosts.get(standby.hostKey);
		const tag = standby.routes.get(visitor.routeId);
		if (!host || tag === undefined || !standby.conn.open) return false;
		if (!visitor.conn.open) return true;
		if (host.circuits >= this.limits.circuitsPerHost) {
			// The standby stays idle; this visitor is the one turned away.
			this.counters.visitorsTurnedAway++;
			visitor.conn.close(PORCH_CLOSE_TRY_LATER);
			return true;
		}
		clearTimeout(visitor.timer);
		this.stopWaiting(visitor);
		visitor.settle();
		this.dropStandby(standby, true);
		host.circuits++;
		this.counters.paired++;

		const circuit: ICircuit = {
			host: standby.conn,
			visitor: visitor.conn,
			hostKey: standby.hostKey,
			lastActivity: Date.now()
		};
		this.circuits.add(circuit);
		const end = (from: RelayConnection, code: number): void => {
			if (!this.circuits.delete(circuit)) return;
			const other = from === circuit.host ? circuit.visitor : circuit.host;
			other.close(forwardableCloseCode(code));
			const record = this.hosts.get(circuit.hostKey);
			if (record) record.circuits--;
			this.forgetHostIfUnused(circuit.hostKey);
		};
		const join = (from: RelayConnection, to: RelayConnection): void => {
			// After pairing there are no control messages in either direction.
			from.onText = (): void => from.close(WsCloseCode.UNSUPPORTED_DATA);
			from.onData = (frame): void => {
				circuit.lastActivity = Date.now();
				const queued = to.write(frame.opcode, frame.payload, frame.fin);
				// Only when a 'drain' is owed, or nothing would resume it.
				if (queued > this.limits.queueBytes && to.socket.writableNeedDrain) {
					from.socket.pause();
				}
			};
			to.socket.on('drain', () => from.socket.resume());
		};
		const visitorGone = visitor.conn.onGone;
		circuit.host.onGone = (code): void => end(circuit.host, code);
		circuit.visitor.onGone = (code): void => {
			visitorGone(code);
			end(circuit.visitor, code);
		};
		join(circuit.host, circuit.visitor);
		join(circuit.visitor, circuit.host);

		// Order matters: the host must read `paired` before the first byte of
		// the visitor's handshake, and both go out on the one connection.
		circuit.host.sendControl({ t: 'paired', tag });
		for (const frame of visitor.held) {
			circuit.host.write(frame.opcode, frame.payload, frame.fin);
		}
		visitor.held = [];
		return true;
	}

	private reapIdleCircuits(): void {
		const cutoff = Date.now() - this.limits.circuitIdleMs;
		for (const circuit of [...this.circuits]) {
			if (circuit.lastActivity <= cutoff) {
				circuit.host.close(WsCloseCode.GOING_AWAY);
			}
		}
	}
}

// ─── The `beignet porch-relay` command ─────────────────────────

export const DEFAULT_PORCH_RELAY_PORT = 2114;

export interface IPorchRelayCommand {
	port: number;
	host: string;
	/** The relay's public URLs, normalised: what a node is configured with. */
	urls: string[];
	/** Print stats() to stderr this often. */
	statsSeconds?: number;
	/** What the operator should read before leaving it running. */
	warnings: string[];
	options: IPorchRelayOptions;
}

const PORCH_RELAY_FLAGS = new Set([
	'--url',
	'--port',
	'--host',
	'--tls-cert',
	'--tls-key',
	'--token-file',
	'--trusted-proxy',
	'--limit',
	'--stats'
]);

/**
 * Read the flags of `beignet porch-relay`. Strict: an unknown flag, a flag
 * without its value or a limit the relay does not have is an error, because a
 * mistyped limit that is silently dropped is a relay running with a limit its
 * operator did not choose.
 */
export function porchRelayCommand(
	args: readonly string[],
	env: Readonly<Record<string, string | undefined>> = {},
	readFile: (path: string) => Buffer = (path) => fs.readFileSync(path)
): IPorchRelayCommand {
	const values = new Map<string, string[]>();
	for (let i = 0; i < args.length; i += 2) {
		const flag = args[i];
		if (!PORCH_RELAY_FLAGS.has(flag)) {
			throw new Error(`Unknown porch-relay option: ${flag}`);
		}
		const value = args[i + 1];
		if (value === undefined || value.startsWith('--')) {
			throw new Error(`${flag} needs a value`);
		}
		values.set(flag, [...(values.get(flag) ?? []), value]);
	}
	const one = (flag: string): string | undefined => {
		const given = values.get(flag) ?? [];
		if (given.length > 1) throw new Error(`${flag} was given more than once`);
		return given[0];
	};
	const integer = (
		what: string,
		text: string,
		min: number,
		max: number
	): number => {
		const n = /^\d{1,15}$/.test(text) ? Number(text) : NaN;
		if (!(n >= min && n <= max)) {
			throw new Error(`${what} must be a whole number from ${min} to ${max}`);
		}
		return n;
	};

	const relays = (values.get('--url') ?? []).map(parsePorchRelayUrl);
	if (relays.length === 0) {
		throw new Error(
			"porch-relay needs --url with the relay's public URL, for example --url wss://relay.example"
		);
	}

	const cert = one('--tls-cert');
	const key = one('--tls-key');
	if ((cert === undefined) !== (key === undefined)) {
		throw new Error('--tls-cert and --tls-key go together');
	}
	const tls =
		cert !== undefined && key !== undefined
			? { cert: readFile(cert), key: readFile(key) }
			: undefined;

	const tokenFile = one('--token-file');
	const token =
		tokenFile !== undefined
			? readFile(tokenFile).toString('utf8').trim()
			: env.BEIGNET_PORCH_RELAY_TOKEN;
	if (token !== undefined) {
		if (token === '') throw new Error('The relay token is empty');
		if (Buffer.byteLength(token) > PORCH_MAX_TOKEN_BYTES) {
			throw new Error(
				`The relay token is longer than ${PORCH_MAX_TOKEN_BYTES} bytes`
			);
		}
	}

	const trustedProxies = values.get('--trusted-proxy') ?? [];
	for (const proxy of trustedProxies) {
		if (isIP(proxy) === 0) {
			throw new Error(`--trusted-proxy takes an IP address, not ${proxy}`);
		}
	}

	const limits: Partial<IPorchRelayLimits> = {};
	const names = Object.keys(DEFAULT_PORCH_RELAY_LIMITS);
	for (const entry of values.get('--limit') ?? []) {
		const at = entry.indexOf('=');
		const name = at < 0 ? entry : entry.slice(0, at);
		if (at < 0 || !names.includes(name)) {
			throw new Error(
				`--limit takes <name>=<n>, where the name is one of: ${names.join(
					', '
				)}`
			);
		}
		if (name in limits) throw new Error(`--limit ${name} was given twice`);
		limits[name as keyof IPorchRelayLimits] = integer(
			`--limit ${name}`,
			entry.slice(at + 1),
			1,
			Number.MAX_SAFE_INTEGER
		);
	}

	const stats = one('--stats');
	const warnings: string[] = [];
	if (!tls && trustedProxies.length === 0) {
		warnings.push(
			"no --trusted-proxy: if a reverse proxy is in front, every connection counts as the proxy's own and the per-address limits do nothing"
		);
	}
	if (tls && relays.some((relay) => !relay.secure)) {
		warnings.push(
			'serving TLS, but a --url is ws://: a node dials the URL it is given'
		);
	}
	for (const relay of relays) {
		if (!relay.secure && !relay.host.endsWith('.onion')) {
			warnings.push(
				`${relay.origin} is not encrypted to the relay: the network in between sees host keys and link ids. Use wss://, or an onion service`
			);
		}
	}

	return {
		port: integer(
			'--port',
			one('--port') ?? String(DEFAULT_PORCH_RELAY_PORT),
			0,
			65535
		),
		host: one('--host') ?? '127.0.0.1',
		urls: [...new Set(relays.map((relay) => relay.origin))],
		...(stats !== undefined
			? { statsSeconds: integer('--stats', stats, 1, 86_400) }
			: {}),
		warnings,
		options: {
			authorities: [...new Set(relays.map((relay) => relay.authority))],
			...(token !== undefined ? { token } : {}),
			...(tls ? { tls } : {}),
			...(trustedProxies.length > 0 ? { trustedProxies } : {}),
			...(Object.keys(limits).length > 0 ? { limits } : {})
		}
	};
}
