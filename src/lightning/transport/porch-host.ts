/**
 * The host side of Porch (docs/PORCH-PROTOCOL.md): a node keeps a few standby
 * connections open at a relay, and each one a visitor is paired with becomes
 * a transport that carries the visitor's BOLT 8 handshake.
 *
 * Every connection here is outbound, to the relay. Nothing in this file
 * listens, and nothing in it learns a visitor's address: the only remote the
 * node ever sees is the relay.
 *
 * Portable: it speaks through an injected WebSocket constructor, which is
 * also where a caller routes the dial through a proxy.
 */

import { EventEmitter } from 'events';
import type { IPorchRelayAddress } from './porch';
import {
	PORCH_CLOSE_REFUSED,
	PORCH_NONCE_BYTES,
	PORCH_TAG_BYTES,
	PORCH_VERSION,
	createPorchRegister,
	decodePorchControl,
	encodePorchControl,
	porchHostUrl
} from './porch';
import type { IWebSocketLike, WebSocketConstructor } from './websocket';
import { WebSocketTransport } from './websocket';

/**
 * Unread bytes a circuit may hold before its handshake completes. The same
 * figure as an inbound WebSocket peer gets, for the same reason: a stranger
 * has not earned more.
 */
export const PORCH_PRE_HANDSHAKE_MAX_BYTES = 128 * 1024;

/**
 * The largest message a host takes from a relay, whole. The protocol's limit
 * for one frame, applied to a message however it was fragmented, because a
 * WebSocket client puts a message back together before handing it over and
 * a stranger must not be able to make that a large one.
 */
export const PORCH_MAX_MESSAGE_BYTES = 128 * 1024;

/** How a host reaches its relays. See IPorchConfig.via. */
export type PorchVia = 'direct' | 'tor';

export interface IPorchRelayConfig {
	/** The relay, as `wss://name` or `ws://name`, with a port when it is not the default. */
	url: string;
	/** For a private relay. */
	token?: string;
}

/** What a node needs to be reachable through Porch relays. */
export interface IPorchConfig {
	/** The relays to wait at. A link works through the relay it names. */
	relays: readonly (string | IPorchRelayConfig)[];
	/** derivePorchHostSecret(seed). */
	hostSecret: Uint8Array;
	/** The links to serve at first, 16 bytes each. */
	tags: readonly Uint8Array[];
	/**
	 * How the relays are dialed. Left unset, a relay is dialed as any peer at
	 * that host would be (see selectOutboundProxy): through the SOCKS5 proxy
	 * when one is configured for public hosts, directly otherwise. 'tor'
	 * sends every relay connection through the proxy (Tor's default port
	 * when none is configured), so the relay sees a Tor exit and not this
	 * machine. 'direct' dials from this machine even when a proxy is set.
	 */
	via?: PorchVia;
	/**
	 * A SOCKS5 proxy for the relay connections alone, in place of the one
	 * peers are dialed through. With it every relay is dialed through this
	 * proxy and never directly, as under via 'tor', so the relay sees the
	 * proxy and not this machine. It need not be Tor: any SOCKS5 proxy that
	 * asks for no credentials will do. Setting it with via 'direct' is a
	 * configuration error.
	 */
	proxy?: { host: string; port: number };
	/** Idle standbys to keep at each relay (default 2, at most 8). */
	standbys?: number;
	timing?: Partial<IPorchHostTiming>;
}

/** Where a relayed connection came from, as far as the node can know. */
export interface IPorchCircuitInfo {
	/** The relay's name. */
	relay: string;
	/** The link the visitor used: its tag, hex. */
	tag: string;
}

/** One link through one relay. */
export interface IPorchLink {
	/** `ws(s)://name`, the relay. */
	relay: string;
	/** The link's tag, hex. */
	tag: string;
	/** The peer URI to hand out. */
	uri: string;
}

/** A relayed connection from one visitor, as the peer layer sees it. */
export class PorchCircuitTransport extends WebSocketTransport {
	readonly transportType = 'ws' as const;
	/**
	 * All that is known about where this came from: the relay's name and the
	 * link the visitor used (its tag, hex).
	 */
	readonly porch: IPorchCircuitInfo;
	private closed?: () => void;

	constructor(
		ws: IWebSocketLike,
		relay: IPorchRelayAddress,
		tag: string,
		/** Called once when the circuit ends, however it ends. */
		closed?: () => void
	) {
		// Not an address anyone can dial or be told: it names the relay, so
		// the peer manager's per-address limits count a relay as one source.
		super(ws, { address: `porch:${relay.authority}` });
		this.porch = { relay: relay.authority, tag };
		this.closed = closed;
		this.maxPendingDataBytes = PORCH_PRE_HANDSHAKE_MAX_BYTES;
	}

	protected onClosed(): void {
		const closed = this.closed;
		this.closed = undefined;
		closed?.();
	}

	markEstablished(): void {
		this.maxPendingDataBytes = PorchCircuitTransport.MAX_PENDING_DATA_BYTES;
	}
}

export interface IPorchHostTiming {
	/** From opening a standby to the relay's `ready`. */
	registerTimeoutMs: number;
	/** An idle standby that hears nothing for this long is replaced. */
	silenceMs: number;
	/** Delay before the first retry after a failure; doubles up to maxBackoffMs. */
	backoffMs: number;
	maxBackoffMs: number;
	/** Delay after the relay refuses the registration itself. */
	refusedBackoffMs: number;
	/** Standbys that may be opened in a burst. */
	dialBurst: number;
	/** How long one unit of that allowance takes to come back. */
	dialRefillMs: number;
}

export const DEFAULT_PORCH_HOST_TIMING: Readonly<IPorchHostTiming> = {
	registerTimeoutMs: 15_000,
	silenceMs: 60_000,
	backoffMs: 1_000,
	maxBackoffMs: 60_000,
	refusedBackoffMs: 5 * 60_000,
	dialBurst: 4,
	dialRefillMs: 2_000
};

/** Standbys kept idle unless told otherwise. */
export const DEFAULT_PORCH_STANDBYS = 2;
/** The most a host keeps idle: the relay's own default cap per host. */
export const MAX_PORCH_STANDBYS = 8;

export type PorchHostState =
	/** Not started, or stopped. */
	| 'stopped'
	/** Started with no link to serve, so it stays away from the relay. */
	| 'no-links'
	/** No standby is registered yet, or all were lost and one is on its way. */
	| 'connecting'
	/** At least one standby is registered: the links work. */
	| 'ready'
	/** The relay refused the registration (bad token, too many links). */
	| 'refused'
	/** The last attempts failed; retrying with backoff. */
	| 'unreachable';

export interface IPorchHostStatus {
	/** `ws(s)://name`, the relay as configured. */
	relay: string;
	state: PorchHostState;
	/** Standbys registered and waiting for a visitor. */
	idle: number;
	/** Visitors connected through this relay now. */
	circuits: number;
	/** Why the last standby failed, when one has since the last success. */
	lastError?: string;
}

export interface IPorchHostOptions {
	relay: IPorchRelayAddress;
	/** derivePorchHostSecret(seed). */
	hostSecret: Uint8Array;
	/**
	 * The links to serve, 16 bytes each. Read whenever a standby registers,
	 * so a change takes effect with refresh().
	 */
	tags: () => readonly Uint8Array[];
	/** For a private relay. */
	token?: string;
	/** Idle standbys to keep (default 2, at most 8). */
	standbys?: number;
	/**
	 * Opens a connection to the relay. This is the one place a dial happens,
	 * so it is also where a caller sends it through a proxy.
	 */
	webSocket: WebSocketConstructor;
	/**
	 * A visitor was paired. The transport already holds whatever the visitor
	 * sent; attach to it before returning or in the same turn.
	 */
	onCircuit: (transport: PorchCircuitTransport) => void;
	timing?: Partial<IPorchHostTiming>;
}

interface IStandby {
	ws: IWebSocketLike;
	/** The links this connection registered, hex, as sent. */
	tags: string[];
	state: 'opening' | 'challenged' | 'idle';
	deadline?: ReturnType<typeof setTimeout>;
	silence?: ReturnType<typeof setTimeout>;
	error?: string;
}

function errorText(ev: unknown): string | undefined {
	if (ev instanceof Error) return ev.message;
	if (ev && typeof ev === 'object') {
		const { error, message } = ev as { error?: unknown; message?: unknown };
		if (error instanceof Error) return error.message;
		if (typeof message === 'string' && message) return message;
	}
	return undefined;
}

/**
 * Events: 'status' (IPorchHostStatus) whenever state, idle or circuits
 * change.
 */
export class PorchHost extends EventEmitter {
	readonly relay: IPorchRelayAddress;
	private readonly options: IPorchHostOptions;
	private readonly timing: IPorchHostTiming;
	private readonly target: number;
	private readonly standbys = new Set<IStandby>();
	private readonly circuits = new Set<PorchCircuitTransport>();
	private running = false;
	private failures = 0;
	private refused = false;
	private lastError?: string;
	private retryAt = 0;
	private tokens: number;
	private refilledAt = 0;
	private wake?: ReturnType<typeof setTimeout>;
	private reported = '';

	constructor(options: IPorchHostOptions) {
		super();
		this.options = options;
		this.relay = options.relay;
		this.timing = { ...DEFAULT_PORCH_HOST_TIMING, ...options.timing };
		const target = options.standbys ?? DEFAULT_PORCH_STANDBYS;
		if (
			!Number.isInteger(target) ||
			target < 1 ||
			target > MAX_PORCH_STANDBYS
		) {
			throw new Error(
				`Porch standbys must be a whole number from 1 to ${MAX_PORCH_STANDBYS}`
			);
		}
		this.target = target;
		this.tokens = this.timing.dialBurst;
	}

	start(): void {
		if (this.running) return;
		this.running = true;
		this.refilledAt = Date.now();
		this.ensure();
		this.report();
	}

	/**
	 * Close every standby and stop opening more. Circuits are peers by now and
	 * are the peer manager's to end; closeCircuits() is there for the caller
	 * that wants them gone too.
	 */
	stop(): void {
		if (!this.running) return;
		this.running = false;
		if (this.wake) clearTimeout(this.wake);
		this.wake = undefined;
		for (const standby of [...this.standbys]) this.release(standby);
		this.report();
	}

	/**
	 * Register again with the links as they are now: after one was added or
	 * revoked. Idle standbys are replaced one for one, within the dial
	 * allowance.
	 */
	refresh(): void {
		if (!this.running) return;
		for (const standby of [...this.standbys]) this.release(standby);
		// A change of links is the operator's doing: not a failure to wait
		// out, and not a visitor's dial to ration.
		this.retryAt = 0;
		this.refused = false;
		this.tokens = Math.max(this.tokens, this.target);
		this.ensure();
		this.report();
	}

	/** End the circuits opened through one link (hex), or all of them. */
	closeCircuits(tag?: string): void {
		for (const circuit of [...this.circuits]) {
			if (tag === undefined || circuit.porch.tag === tag) circuit.destroy();
		}
	}

	status(): IPorchHostStatus {
		let idle = 0;
		for (const standby of this.standbys) if (standby.state === 'idle') idle++;
		const state: PorchHostState = !this.running
			? 'stopped'
			: idle > 0
			? 'ready'
			: this.linkTags().length === 0
			? 'no-links'
			: this.refused
			? 'refused'
			: this.failures > 1
			? 'unreachable'
			: 'connecting';
		return {
			relay: this.relay.origin,
			state,
			idle,
			circuits: this.circuits.size,
			...(this.lastError !== undefined &&
			state !== 'ready' &&
			state !== 'no-links'
				? { lastError: this.lastError }
				: {})
		};
	}

	// ── Standbys ─────────────────────────────────────────────────

	private report(): void {
		const status = this.status();
		const key = JSON.stringify(status);
		if (key === this.reported) return;
		this.reported = key;
		try {
			this.emit('status', status);
		} catch {
			// An observer's throw must not unwind into a socket's message
			// handler, where it would read as the relay misbehaving.
		}
	}

	/** Take one unit of the dial allowance, or say when one is due. */
	private allowance(now: number): number {
		const earned = Math.floor(
			(now - this.refilledAt) / this.timing.dialRefillMs
		);
		if (earned > 0) {
			this.tokens = Math.min(this.timing.dialBurst, this.tokens + earned);
			this.refilledAt =
				this.tokens === this.timing.dialBurst
					? now
					: this.refilledAt + earned * this.timing.dialRefillMs;
		}
		if (this.tokens > 0) {
			this.tokens--;
			return 0;
		}
		return this.refilledAt + this.timing.dialRefillMs - now;
	}

	private sleepUntil(delayMs: number): void {
		if (this.wake) clearTimeout(this.wake);
		this.wake = setTimeout(
			() => {
				this.wake = undefined;
				this.ensure();
				this.report();
			},
			Math.max(1, delayMs)
		);
		this.wake.unref?.();
	}

	/** Open standbys until the target is met, the allowance runs out or a backoff holds. */
	private ensure(): void {
		if (!this.running) return;
		while (this.standbys.size < this.target) {
			const now = Date.now();
			if (this.retryAt > now) return this.sleepUntil(this.retryAt - now);
			const wait = this.allowance(now);
			if (wait > 0) return this.sleepUntil(wait);
			if (!this.open()) return;
		}
	}

	/** The links to register now: well formed, ascending, hex. */
	private linkTags(): string[] {
		return this.options
			.tags()
			.map((tag) => Buffer.from(tag))
			.filter((tag) => tag.length === PORCH_TAG_BYTES)
			.sort(Buffer.compare)
			.map((tag) => tag.toString('hex'));
	}

	private open(): boolean {
		const tags = this.linkTags();
		// Nothing to serve: no reason to be known to the relay at all.
		if (tags.length === 0) return false;
		let ws: IWebSocketLike;
		try {
			ws = new this.options.webSocket(porchHostUrl(this.relay));
		} catch (err) {
			this.failed(errorText(err) ?? 'could not open a connection');
			return true;
		}
		ws.binaryType = 'arraybuffer';
		const standby: IStandby = {
			ws,
			tags: [...new Set(tags)],
			state: 'opening'
		};
		standby.deadline = setTimeout(() => {
			standby.error = 'the relay did not complete the registration in time';
			this.lost(standby);
		}, this.timing.registerTimeoutMs);
		standby.deadline.unref?.();
		this.standbys.add(standby);
		ws.onopen = null;
		ws.onerror = (ev): void => {
			standby.error = errorText(ev) ?? standby.error;
		};
		ws.onclose = (ev): void => this.lost(standby, ev?.code);
		ws.onmessage = (ev): void => this.receive(standby, ev.data);
		return true;
	}

	private receive(standby: IStandby, data: unknown): void {
		if (!this.standbys.has(standby)) return;
		const message =
			typeof data === 'string' ? decodePorchControl(data) : undefined;
		if (!message) {
			standby.error = 'the relay sent something that is not Porch';
			return this.lost(standby);
		}
		if (standby.state === 'opening' && message.t === 'challenge') {
			// The relay must name itself as it was dialed: a registration is
			// signed for one name, and signing for whatever name is offered
			// would let any relay collect one that works somewhere else.
			if (
				message.v !== PORCH_VERSION ||
				message.authority !== this.relay.authority ||
				message.nonce.length !== PORCH_NONCE_BYTES * 2
			) {
				standby.error =
					message.authority !== this.relay.authority
						? 'the relay answered under another name'
						: 'the relay speaks another version of Porch';
				return this.lost(standby);
			}
			standby.state = 'challenged';
			try {
				standby.ws.send(
					encodePorchControl(
						createPorchRegister({
							hostSecret: this.options.hostSecret,
							nonce: Buffer.from(message.nonce, 'hex'),
							authority: this.relay.authority,
							tags: standby.tags.map((tag) => Buffer.from(tag, 'hex')),
							...(this.options.token !== undefined
								? { token: this.options.token }
								: {})
						})
					)
				);
			} catch (err) {
				standby.error = errorText(err);
				this.lost(standby);
			}
			return;
		}
		if (standby.state === 'challenged' && message.t === 'ready') {
			standby.state = 'idle';
			if (standby.deadline) clearTimeout(standby.deadline);
			standby.deadline = undefined;
			this.failures = 0;
			this.refused = false;
			this.lastError = undefined;
			this.heard(standby);
			return this.report();
		}
		if (standby.state === 'idle' && message.t === 'ping') {
			this.heard(standby);
			try {
				standby.ws.send(encodePorchControl({ t: 'pong' }));
			} catch (err) {
				standby.error = errorText(err);
				this.lost(standby);
			}
			return;
		}
		if (
			standby.state === 'idle' &&
			message.t === 'paired' &&
			standby.tags.includes(message.tag)
		) {
			return this.paired(standby, message.tag);
		}
		standby.error = 'the relay sent a message out of turn';
		this.lost(standby);
	}

	/** Restart the clock on a standby that has just been heard from. */
	private heard(standby: IStandby): void {
		if (standby.silence) clearTimeout(standby.silence);
		standby.silence = setTimeout(() => {
			standby.error = 'the relay went silent';
			this.lost(standby);
		}, this.timing.silenceMs);
		standby.silence.unref?.();
	}

	private clear(standby: IStandby): void {
		if (standby.deadline) clearTimeout(standby.deadline);
		if (standby.silence) clearTimeout(standby.silence);
		standby.deadline = undefined;
		standby.silence = undefined;
	}

	private paired(standby: IStandby, tag: string): void {
		this.standbys.delete(standby);
		this.clear(standby);
		// Built here, in the turn `paired` arrived in: the visitor's first
		// bytes may be the very next message, and from this line on they land
		// in the transport, which holds them until the peer layer attaches.
		// The count is kept through the transport's own hook: the peer layer
		// strips a transport's listeners before it destroys one.
		const circuit: PorchCircuitTransport = new PorchCircuitTransport(
			standby.ws,
			this.relay,
			tag,
			() => {
				this.circuits.delete(circuit);
				this.report();
			}
		);
		this.circuits.add(circuit);
		try {
			this.options.onCircuit(circuit);
		} catch {
			circuit.destroy();
		}
		// The standby is used up: its replacement is what the next visitor gets.
		this.ensure();
		this.report();
	}

	/** Let go of a standby without counting it as a failure. */
	private release(standby: IStandby): void {
		if (!this.standbys.delete(standby)) return;
		this.clear(standby);
		standby.ws.onmessage = null;
		standby.ws.onclose = null;
		standby.ws.onerror = null;
		try {
			standby.ws.close(1000);
		} catch {
			// Closing a socket that never opened may throw in some stacks.
		}
	}

	/** A standby closed, timed out or misbehaved. */
	private lost(standby: IStandby, code?: number): void {
		if (!this.standbys.has(standby)) return;
		const wasIdle = standby.state === 'idle';
		this.release(standby);
		if (wasIdle && standby.error === undefined) {
			// The relay let a registered standby go: it restarted, replaced the
			// oldest, or the network dropped. Not a reason to slow down beyond
			// the dial allowance.
			this.ensure();
			return this.report();
		}
		if (code === PORCH_CLOSE_REFUSED) this.refused = true;
		this.failed(
			standby.error ??
				(code === PORCH_CLOSE_REFUSED
					? 'the relay refused the registration'
					: code !== undefined
					? `the relay closed the connection (${code})`
					: 'the connection to the relay failed')
		);
	}

	private failed(reason: string): void {
		this.failures++;
		this.lastError = reason;
		const { backoffMs, maxBackoffMs, refusedBackoffMs } = this.timing;
		const delay = this.refused
			? refusedBackoffMs
			: Math.min(
					maxBackoffMs,
					backoffMs * 2 ** Math.min(this.failures - 1, 16)
			  );
		// Half to all of the delay, so many hosts of one relay do not return in
		// step after it restarts.
		this.retryAt = Date.now() + Math.round(delay * (0.5 + Math.random() / 2));
		this.ensure();
		this.report();
	}
}
