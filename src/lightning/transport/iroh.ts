/** Portable BOLT 8 over Iroh contracts and byte-stream adapter. */
import type { IDuplexTransport } from './duplex-transport';
import { BufferedDataEmitter } from './websocket';
import { hkdf } from '../crypto/hkdf';

export const IROH_ALPN = 'beignet/bolt8/1';

export interface IIrohAddress {
	endpointId: string;
	relayUrl?: string;
	/** Explicit IP socket addresses for controlled local networks. Not encoded in URIs. */
	directAddresses?: string[];
}

export interface IIrohDiagnostics {
	endpointId: string;
	path: 'direct' | 'relay' | 'unknown';
	rttMs?: number;
}

/** A native bridge implements this surface without loading the Node binding. */
export interface IIrohStream {
	read(limit: number): Promise<Uint8Array>;
	writeAll(data: Uint8Array): Promise<void>;
	close(): void;
	closed(): Promise<void>;
	diagnostics(): IIrohDiagnostics;
}

/**
 * How a relay-only endpoint keeps its traffic on the relay.
 *
 * - `'native'`: the endpoint has no IP transport at all, so it has no
 *   socket to send from, nothing to map on the router and no address to
 *   discover.
 * - `'loopback-pin'`: the binding cannot remove the IP transport, so its
 *   sockets are bound to loopback instead. No direct path can form, but
 *   Iroh's port mapper still runs, and on a network where UPnP, NAT-PMP or
 *   PCP answers it adds the router's public address to the endpoint's own
 *   address list. The endpoint is watched before it accepts or makes a
 *   connection and for as long as it lives, and it shuts itself down when a
 *   routable address appears. So this mode is best effort: it holds on
 *   networks with no port mapper to answer (a Docker bridge) and refuses to
 *   run on the others. A mapping first granted while peers are connected
 *   can reach them in the moment before the endpoint closes.
 */
export type IrohRelayOnlyMode = 'native' | 'loopback-pin';

/** A relay-only endpoint that can no longer keep the node's address private. */
export class IrohRelayOnlyError extends Error {
	readonly code = 'IROH_RELAY_ONLY_VIOLATED';
	constructor(message: string) {
		super(message);
		this.name = 'IrohRelayOnlyError';
	}
}

/**
 * A dial a relay-only endpoint will not make, because it could not be kept on
 * the endpoint's own relays: any other relay would see where the dial comes
 * from, and whoever is dialed chooses that relay. Nothing was sent, and the
 * endpoint goes on serving, which is what tells this from IrohRelayOnlyError.
 */
export class IrohRelayOnlyDialError extends Error {
	readonly code = 'IROH_RELAY_ONLY_DIAL_REFUSED';
	constructor(message: string) {
		super(message);
		this.name = 'IrohRelayOnlyDialError';
	}
}

export interface IIrohEndpoint {
	address(): IIrohAddress;
	/**
	 * A relay-only endpoint rejects with IrohRelayOnlyDialError when it cannot
	 * keep the dial on its own relays (irohRelayOnlyDialRefusal).
	 */
	connect(address: IIrohAddress, timeoutMs: number): Promise<IDuplexTransport>;
	listen(
		onConnection: (socket: IDuplexTransport) => void,
		onError: (error: Error) => void
	): void;
	stopListening(): void;
	close(): Promise<void>;
	/**
	 * Set by an endpoint that was bound relay-only, and only by one. A factory
	 * that ignores IIrohEndpointOptions.relayOnly leaves it unset, which is how
	 * the peer manager tells a relay-only endpoint from one that would offer
	 * its addresses to every peer.
	 */
	readonly relayOnly?: IrohRelayOnlyMode;
}

export interface IIrohEndpointOptions {
	secretKey: Uint8Array;
	/** Omitted uses n0's relays; an empty list disables relays. */
	relays?: string[];
	/** False disables public address discovery and publication. */
	discovery?: boolean;
	/**
	 * true: no direct paths. All traffic rides the relay and no IP address is
	 * offered to a peer, so whoever holds this endpoint's link cannot learn
	 * where it runs. The relay operator still sees the address. Needs a
	 * relay, and an endpoint that sets IIrohEndpoint.relayOnly in return.
	 *
	 * That covers the relays this endpoint was given and no others. A dial
	 * goes to the relay the dialed peer names, in its link or in the record it
	 * publishes, so the endpoint dials out only with discovery off and only to
	 * a peer on one of its own relays (irohRelayOnlyDialRefusal).
	 */
	relayOnly?: boolean;
	/**
	 * Called once when a bound relay-only endpoint finds it cannot keep that
	 * promise. The endpoint has already closed itself. A problem found while
	 * binding rejects the factory instead.
	 */
	onRelayOnlyViolation?: (error: IrohRelayOnlyError) => void;
	maxPendingInbound?: number;
	handshakeTimeoutMs?: number;
}

export type IrohEndpointFactory = (
	options: IIrohEndpointOptions
) => Promise<IIrohEndpoint>;
export interface IIrohConfig extends IIrohEndpointOptions {
	factory: IrohEndpointFactory;
}

/**
 * Whether an `ip:port` socket address is loopback: 127.0.0.0/8, ::1, or
 * either one mapped into IPv6. Strict on purpose: a private LAN address is
 * not loopback, and neither is anything this cannot parse.
 */
export function isLoopbackSocketAddress(address: string): boolean {
	const bracketed = /^\[([0-9a-f:.]+)\](?::\d+)?$/i.exec(address);
	const host = bracketed ? bracketed[1] : address.replace(/:\d+$/, '');
	const mapped = /^::ffff:(.+)$/i.exec(host);
	const ip = (mapped ? mapped[1] : host).toLowerCase();
	if (/^127(\.\d{1,3}){3}$/.test(ip)) return true;
	return ip === '::1' || ip === '0:0:0:0:0:0:0:1';
}

/** The addresses in an endpoint's list that a peer could route to. */
export function routableSocketAddresses(addresses: string[]): string[] {
	return addresses.filter((address) => !isLoopbackSocketAddress(address));
}

/** HKDF-SHA256 from the BIP39 seed, independent of Lightning signing keys. */
export function deriveIrohSecretKey(seed: Uint8Array): Buffer {
	if (seed.length < 16) throw new Error('Iroh identity requires a wallet seed');
	return hkdf(
		Buffer.alloc(32),
		Buffer.from(seed),
		Buffer.from('beignet/iroh/identity/v1'),
		32
	);
}

/** Accept Iroh's hex and unpadded base32 forms; persist canonical hex. */
export function normalizeIrohEndpointId(value: string): string {
	if (typeof value !== 'string') throw new Error('Invalid Iroh endpoint id');
	const id = value.toLowerCase();
	if (/^[0-9a-f]{64}$/.test(id)) return id;
	if (!/^[a-z2-7]{52}$/.test(id))
		throw new Error('Iroh endpoint id must encode 32 bytes');
	const alphabet = 'abcdefghijklmnopqrstuvwxyz234567';
	const bytes: number[] = [];
	let bits = 0;
	let accumulator = 0;
	for (const char of id) {
		accumulator = (accumulator << 5) | alphabet.indexOf(char);
		bits += 5;
		if (bits >= 8) {
			bits -= 8;
			bytes.push((accumulator >>> bits) & 255);
		}
		accumulator &= (1 << bits) - 1;
	}
	if (accumulator !== 0) throw new Error('Non-canonical Iroh endpoint id');
	return Buffer.from(bytes).toString('hex');
}

export function validateIrohRelayUrl(value: string): string {
	let url: URL;
	try {
		url = new URL(value);
	} catch {
		throw new Error('Invalid Iroh relay URL');
	}
	if (
		!['https:', 'http:'].includes(url.protocol) ||
		!url.hostname ||
		url.username ||
		url.password ||
		url.hash
	) {
		throw new Error(
			'Iroh relay must be an http(s) URL without credentials or fragment'
		);
	}
	return url.toString();
}

/**
 * The server a relay URL reaches, in one spelling: scheme, host and port.
 * Iroh writes its own relays as fully qualified names (a trailing dot) and a
 * link may carry either form, so the dot is dropped. The path and query do
 * not change who runs the server, and are left out.
 */
export function irohRelayServer(value: string): string {
	const url = new URL(validateIrohRelayUrl(value));
	const host = url.hostname.toLowerCase().replace(/\.$/, '');
	return `${url.protocol}//${host}${url.port ? `:${url.port}` : ''}`;
}

/**
 * Why a relay-only endpoint must refuse to dial `address`, or undefined when
 * the dial stays on `ownRelays` (the relays the endpoint was bound with).
 *
 * A dial reaches the peer through the peer's relay, and that relay sees the
 * dialer's IP address. The peer chooses it twice over: as the relay named in
 * its link, and as the relay in the record it publishes, which Iroh looks up
 * on every dial while discovery is on and then sends to as well. So with
 * discovery on no dial can be held to this endpoint's relays, and with it
 * off the relay in the address has to be one of them.
 *
 * An address with no relay is left to the caller's own rules: it names
 * nothing this could leak to.
 */
export function irohRelayOnlyDialRefusal(
	address: Pick<IIrohAddress, 'relayUrl'>,
	discovery: boolean,
	ownRelays: string[]
): string | undefined {
	if (discovery)
		return (
			'Iroh relay-only does not dial out while discovery is on: the dial ' +
			'would also go to whichever relay the peer has published, and that ' +
			"relay would see this node's address. Turn Iroh discovery off to " +
			"dial a peer on one of this node's own relays, or let the peer " +
			'connect in'
		);
	if (!address.relayUrl) return undefined;
	const server = irohRelayServer(address.relayUrl);
	if (ownRelays.some((relay) => irohRelayServer(relay) === server))
		return undefined;
	return (
		`Iroh relay-only does not dial through ${server}: it is not one of ` +
		"this node's own relays, and the relay a dial goes through sees this " +
		"node's address. Let the peer connect in, or add the relay to this " +
		"node's own if you trust whoever runs it"
	);
}

export function parseIrohAddress(address: string): IIrohAddress {
	const match = /^iroh:([^?#]+)(?:\?([^#]*))?$/i.exec(address);
	if (!match) throw new Error('Invalid Iroh address');
	const endpointId = normalizeIrohEndpointId(match[1]);
	const params = new URLSearchParams(match[2]);
	for (const key of params.keys()) {
		if (key !== 'relay')
			throw new Error(`Unknown Iroh address parameter: ${key}`);
	}
	if (params.getAll('relay').length > 1)
		throw new Error('Duplicate Iroh relay parameter');
	return params.has('relay')
		? { endpointId, relayUrl: validateIrohRelayUrl(params.get('relay')!) }
		: { endpointId };
}

export function formatIrohAddress(address: IIrohAddress): string {
	const id = normalizeIrohEndpointId(address.endpointId);
	return `iroh:${id}${
		address.relayUrl
			? `?relay=${encodeURIComponent(validateIrohRelayUrl(address.relayUrl))}`
			: ''
	}`;
}

/** One QUIC stream per Lightning connection. EOF closes both directions. */
export class IrohTransport extends BufferedDataEmitter {
	readonly transportType = 'iroh' as const;
	readonly remotePort = 0;
	readonly remoteAddress: string;
	private stopped = false;
	private queuedBytes = 0;
	private writing = false;
	private queue: Array<{ data: Buffer; cb?: (error?: Error) => void }> = [];
	private timer?: ReturnType<typeof setTimeout>;
	private static readonly HIGH_WATER_MARK = 1024 * 1024;
	private static readonly MAX_QUEUED_BYTES = 16 * 1024 * 1024;

	constructor(private readonly stream: IIrohStream) {
		super();
		this.remoteAddress = `iroh:${stream.diagnostics().endpointId}`;
		this.maxPendingDataBytes = 128 * 1024;
		// Let the caller install handshake guards before observing close/data.
		void Promise.resolve().then(() => this.readLoop());
		void stream.closed().then(
			() => this.destroy(),
			(err) => this.destroy(asError(err))
		);
	}

	get writableLength(): number {
		return this.queuedBytes;
	}
	getIrohDiagnostics(): IIrohDiagnostics {
		return this.stream.diagnostics();
	}
	markEstablished(): void {
		this.maxPendingDataBytes = BufferedDataEmitter.MAX_PENDING_DATA_BYTES;
	}

	write(data: Uint8Array | string, cb?: (error?: Error) => void): boolean {
		if (this.stopped) {
			queueMicrotask(() => cb?.(new Error('Iroh transport is closed')));
			return false;
		}
		const bytes =
			typeof data === 'string' ? Buffer.from(data) : Buffer.from(data);
		if (this.queuedBytes + bytes.length > IrohTransport.MAX_QUEUED_BYTES) {
			const error = new Error('Iroh write buffer limit exceeded');
			queueMicrotask(() => cb?.(error));
			this.destroy(error);
			return false;
		}
		this.queue.push({ data: bytes, cb });
		this.queuedBytes += bytes.length;
		void this.flushWrites();
		return this.queuedBytes < IrohTransport.HIGH_WATER_MARK;
	}

	private async flushWrites(): Promise<void> {
		if (this.writing) return;
		this.writing = true;
		try {
			while (!this.stopped && this.queue.length) {
				const item = this.queue[0];
				await this.stream.writeAll(item.data);
				if (this.stopped) break;
				this.queue.shift();
				this.queuedBytes -= item.data.length;
				item.cb?.();
			}
		} catch (err) {
			this.destroy(asError(err));
		} finally {
			this.writing = false;
		}
	}

	private async readLoop(): Promise<void> {
		try {
			while (!this.stopped) {
				const bytes = await this.stream.read(64 * 1024);
				if (this.stopped) return;
				if (!bytes.length) {
					this.destroy();
					return;
				}
				this.emitData(Buffer.from(bytes));
			}
		} catch (err) {
			this.destroy(asError(err));
		}
	}

	protected onPendingOverflow(): void {
		super.onPendingOverflow();
		this.destroy(new Error('Iroh receive buffer limit exceeded'));
	}

	setTimeout(timeout: number, callback?: () => void): this {
		if (this.timer) clearTimeout(this.timer);
		this.timer = undefined;
		if (callback) this.once('timeout', callback);
		if (timeout > 0 && !this.stopped) {
			this.timer = setTimeout(() => this.emit('timeout'), timeout);
			this.timer.unref?.();
		}
		return this;
	}
	setKeepAlive(): this {
		return this;
	}

	destroy(error?: Error): this {
		if (this.stopped) return this;
		this.stopped = true;
		this.setTimeout(0);
		super.onPendingOverflow();
		const pending = this.queue;
		this.queue = [];
		this.queuedBytes = 0;
		try {
			this.stream.close();
		} catch {
			/* The close event still has to fire. */
		}
		queueMicrotask(() => {
			for (const item of pending)
				item.cb?.(error ?? new Error('Iroh transport is closed'));
			if (error && this.listenerCount('error')) this.emit('error', error);
			this.emit('close', !!error);
		});
		return this;
	}
}

function asError(error: unknown): Error {
	return error instanceof Error ? error : new Error(String(error));
}

/** Race socket establishment only, so exactly one BOLT 8 handshake is sent. */
export function connectIrohWithFallback(
	primary: () => Promise<IDuplexTransport>,
	fallback: () => Promise<IDuplexTransport>,
	delayMs = 1500,
	signal?: AbortSignal
): Promise<IDuplexTransport> {
	return new Promise((resolve, reject) => {
		let finished = false;
		let fallbackStarted = false;
		const failures: Error[] = [];
		const cleanup = (): void => {
			clearTimeout(timer);
			signal?.removeEventListener('abort', onAbort);
		};
		const onAbort = (): void => {
			if (finished) return;
			finished = true;
			cleanup();
			reject(new Error('Iroh dial cancelled'));
		};
		const attempt = (
			connect: () => Promise<IDuplexTransport>,
			isPrimary: boolean
		): void => {
			void Promise.resolve()
				.then(() => (finished ? undefined : connect()))
				.then(
					(socket) => {
						if (!socket) return;
						if (finished) {
							socket.destroy();
							return;
						}
						finished = true;
						cleanup();
						resolve(socket);
					},
					(error) => {
						if (finished) return;
						failures.push(asError(error));
						if (isPrimary) startFallback();
						if (failures.length === 2) {
							finished = true;
							cleanup();
							reject(
								new Error(
									`Iroh and Tor connections failed: ${failures
										.map((failure) => failure.message)
										.join('; ')}`
								)
							);
						}
					}
				);
		};
		const startFallback = (): void => {
			if (finished || fallbackStarted) return;
			fallbackStarted = true;
			attempt(fallback, false);
		};
		const timer = setTimeout(startFallback, delayMs);
		signal?.addEventListener('abort', onAbort, { once: true });
		if (signal?.aborted) onAbort();
		else attempt(primary, true);
	});
}
