/**
 * Node-only Iroh backend. Import this entry explicitly, never in portable code.
 * @module beignet/lightning/iroh-node
 */
import type * as Binding from '@number0/iroh';
import type {
	IIrohAddress,
	IIrohDiagnostics,
	IIrohEndpoint,
	IIrohEndpointOptions,
	IrohRelayOnlyMode
} from './iroh';
import {
	IROH_ALPN,
	IrohRelayOnlyError,
	IrohTransport,
	normalizeIrohEndpointId,
	routableSocketAddresses,
	validateIrohRelayUrl
} from './iroh';
import type { IDuplexTransport } from './duplex-transport';

/** Lazily load the optional native addon only after an explicit opt-in. */
export async function createNodeIrohEndpoint(
	options: IIrohEndpointOptions
): Promise<IIrohEndpoint> {
	if (options.secretKey.length !== 32)
		throw new Error('Iroh secret key must be 32 bytes');
	let binding: typeof Binding;
	try {
		binding = require('@number0/iroh/index.js') as typeof Binding;
		// React Native bundles resolve it to an empty module (package.json).
		if (!binding.Endpoint) throw new Error('empty module');
	} catch {
		throw new Error(
			'Iroh requires the optional @number0/iroh binding and Node >= 20.3'
		);
	}
	if (!options.relayOnly) {
		return new NodeIrohEndpoint(
			binding,
			await configure(binding, options).bind(),
			options
		);
	}
	if (options.relays !== undefined && options.relays.length === 0)
		throw new Error('Iroh relay-only needs a relay; relays are disabled');
	const { endpoint, mode, ipv4Only } = await bindRelayOnly(binding, options);
	try {
		// A socket the pin did not cover would carry direct paths after all.
		const sockets = routableSocketAddresses(endpoint.boundSockets());
		if (sockets.length)
			throw new IrohRelayOnlyError(
				`Iroh relay-only could not be enforced: the endpoint bound ${sockets.length} socket(s) off loopback` +
					(ipv4Only && sockets.every(isIpv6Wildcard) ? NO_IPV6_LOOPBACK : '')
			);
		const violation = relayOnlyViolation(endpoint, mode);
		if (violation) throw violation;
	} catch (err) {
		await endpoint.close().catch(() => undefined);
		throw err;
	}
	return new NodeIrohEndpoint(binding, endpoint, options, mode);
}

/** A builder with everything but the relay-only handling applied. */
function configure(
	binding: typeof Binding,
	options: IIrohEndpointOptions
): Binding.EndpointBuilder {
	const builder = binding.Endpoint.builder();
	if (options.discovery === false) {
		builder.applyMinimal();
		builder.relayMode(binding.RelayMode.defaultMode());
	} else builder.applyN0();
	if (options.relays !== undefined) {
		builder.relayMode(
			options.relays.length
				? binding.RelayMode.customFromUrls(
						options.relays.map(validateIrohRelayUrl)
				  )
				: binding.RelayMode.disabled()
		);
	}
	builder.secretKey(Array.from(options.secretKey));
	builder.alpns([]);
	return builder;
}

/**
 * Bind with no usable IP transport. A binding that exposes Iroh's
 * clear_ip_transports gets exactly that. The bindings up to 1.2.0 do not, so
 * for them the UDP sockets are bound to loopback: a socket the caller binds
 * replaces Iroh's default one for its address family. A host with no IPv6
 * loopback refuses that bind, and a failed bind consumes the builder, so the
 * retry starts from a fresh one with IPv4 alone.
 */
async function bindRelayOnly(
	binding: typeof Binding,
	options: IIrohEndpointOptions
): Promise<{
	endpoint: Binding.Endpoint;
	mode: IrohRelayOnlyMode;
	/** The IPv6 loopback bind was refused, so only IPv4 is pinned. */
	ipv4Only?: boolean;
}> {
	const first = configure(binding, options) as Binding.EndpointBuilder & {
		clearIpTransports?: () => void;
	};
	if (typeof first.clearIpTransports === 'function') {
		first.clearIpTransports();
		return { endpoint: await first.bind(), mode: 'native' };
	}
	const pinned = (
		builder: Binding.EndpointBuilder,
		addresses: string[]
	): Promise<Binding.Endpoint> => {
		for (const address of addresses) builder.bindAddr(address);
		return builder.bind();
	};
	try {
		return {
			endpoint: await pinned(first, ['127.0.0.1:0', '[::1]:0']),
			mode: 'loopback-pin'
		};
	} catch {
		return {
			endpoint: await pinned(configure(binding, options), ['127.0.0.1:0']),
			mode: 'loopback-pin',
			ipv4Only: true
		};
	}
}

/**
 * What the IPv4-only retry leaves behind on a host that has IPv6 sockets and
 * no IPv6 loopback address: Iroh's own IPv6 socket, on every address. Linux
 * with IPv6 switched off by sysctl is such a host. The address comes back
 * with the loopback interface alone, whatever the other interfaces are set to.
 */
const NO_IPV6_LOOPBACK =
	'. Its IPv6 socket could not be pinned to ::1, most likely because IPv6 ' +
	'is switched off on this host (sysctl net.ipv6.conf.all.disable_ipv6=1). ' +
	'Switch it back on for the loopback interface alone ' +
	'(net.ipv6.conf.lo.disable_ipv6=0); the other interfaces can stay as they are';

function isIpv6Wildcard(address: string): boolean {
	return /^\[::\]:\d+$/.test(address);
}

/**
 * How long a loopback-pinned endpoint is watched before it accepts or makes a
 * connection. Iroh asks the router for a port mapping as it binds (an answer
 * takes a second or two), and a granted mapping joins the endpoint's address
 * list at the end of a network report: the one running at the time, or one
 * the mapping itself starts. A report with no UDP path out ends on its 3 s
 * probe timeout and is capped at 5 s, so two of them plus the mapping fit
 * here. Measured on a home network with UPnP: 3 to 4 s after the bind.
 */
const RELAY_ONLY_SETTLE_MS = 12_000;
/**
 * How often the address list is re-read, during the watch and for as long as
 * the endpoint lives. Polled, not watched: watchAddr aborts the process on
 * binding 1.1.0.
 */
const RELAY_ONLY_POLL_MS = 250;

/**
 * The error for a relay-only endpoint that holds an address a peer could
 * route to, or undefined while it holds none. The message counts the
 * addresses and never prints them: it reaches logs and /info.
 */
function relayOnlyViolation(
	endpoint: Binding.Endpoint,
	mode: IrohRelayOnlyMode
): IrohRelayOnlyError | undefined {
	const exposed = routableSocketAddresses(endpoint.addr().directAddresses());
	if (!exposed.length) return undefined;
	return new IrohRelayOnlyError(
		`Iroh relay-only cannot be kept: the endpoint holds ${exposed.length} routable address(es)` +
			(mode === 'loopback-pin'
				? ', most likely a router port mapping (UPnP, NAT-PMP or PCP). ' +
				  'This Iroh binding cannot switch its port mapper off, so turn ' +
				  'port mapping off on the router or run the node in a bridged ' +
				  'container'
				: '')
	);
}

class NodeIrohEndpoint implements IIrohEndpoint {
	private onConnection?: (socket: IDuplexTransport) => void;
	private onError?: (error: Error) => void;
	private closed = false;
	private closing?: Promise<void>;
	private pending = 0;
	private epoch = 0;
	private readonly handshakes = new Set<Binding.Connection>();
	private readonly alpn = Array.from(Buffer.from(IROH_ALPN));
	/** Relay-only: the standing check of the endpoint's address list. */
	private guard?: ReturnType<typeof setInterval>;
	/**
	 * Loopback-pinned only: pending while the endpoint is watched and silent.
	 * It advertises no ALPN, names no relay and makes no connection until this
	 * resolves; it rejects if the endpoint closes first.
	 */
	private settling?: Promise<void>;
	private endSettling?: (error?: Error) => void;

	constructor(
		private readonly binding: typeof Binding,
		private readonly endpoint: Binding.Endpoint,
		private readonly options: IIrohEndpointOptions,
		readonly relayOnly?: IrohRelayOnlyMode
	) {
		if (relayOnly) {
			this.guard = setInterval(
				() => this.checkRelayOnly(relayOnly),
				RELAY_ONLY_POLL_MS
			);
			this.guard.unref?.();
		}
		if (relayOnly === 'loopback-pin') this.watchBeforeUse();
		void this.acceptLoop();
	}

	private watchBeforeUse(): void {
		const timer = setTimeout(() => this.endSettling?.(), RELAY_ONLY_SETTLE_MS);
		timer.unref?.();
		this.settling = new Promise<void>((resolve, reject) => {
			this.endSettling = (error?: Error): void => {
				clearTimeout(timer);
				this.endSettling = undefined;
				if (error) return reject(error);
				this.settling = undefined;
				if (this.onConnection) this.endpoint.setAlpns([this.alpn]);
				resolve();
			};
		});
		// A dial may never come to observe a close during the watch.
		this.settling.catch(() => undefined);
	}

	/**
	 * Hold the endpoint to its relay-only promise for as long as it lives. A
	 * router can start granting port mappings long after the bind, and Iroh
	 * asks again on every network report. An endpoint with no IP transport
	 * has nothing that could change; it is checked all the same, against a
	 * binding that stops honouring the switch.
	 */
	private checkRelayOnly(mode: IrohRelayOnlyMode): void {
		if (this.closed) return;
		let violation: IrohRelayOnlyError | undefined;
		try {
			violation = relayOnlyViolation(this.endpoint, mode);
		} catch {
			return; // The endpoint is going away; close() ends the guard.
		}
		if (!violation) return;
		void this.close().catch(() => undefined);
		this.options.onRelayOnlyViolation?.(violation);
	}

	address(): IIrohAddress {
		// No relay while watched: without one the node publishes no link.
		const relayUrl = this.settling
			? undefined
			: this.endpoint.addr().relayUrl();
		return {
			endpointId: Buffer.from(this.endpoint.id().toBytes()).toString('hex'),
			...(relayUrl ? { relayUrl } : {}),
			// A relay-only endpoint has none worth handing to anyone.
			...(this.relayOnly
				? {}
				: { directAddresses: this.endpoint.addr().directAddresses() })
		};
	}

	async connect(
		address: IIrohAddress,
		timeoutMs: number
	): Promise<IDuplexTransport> {
		if (this.closed) throw new Error('Iroh endpoint is closed');
		if (this.settling) await withDeadline(this.settling, timeoutMs);
		const id = this.binding.EndpointId.fromBytes(
			Array.from(
				Buffer.from(normalizeIrohEndpointId(address.endpointId), 'hex')
			)
		);
		const relay = address.relayUrl
			? validateIrohRelayUrl(address.relayUrl)
			: undefined;
		if (
			this.options.discovery === false &&
			!relay &&
			!address.directAddresses?.length
		)
			throw new Error(
				'Iroh with discovery disabled requires a relay URL or direct addresses'
			);
		const addr = new this.binding.EndpointAddr(
			id,
			relay,
			address.directAddresses
		);
		const connection = await withDeadline(
			this.endpoint.connect(addr, this.alpn),
			timeoutMs,
			closeConnection
		);
		if (this.closed) {
			closeConnection(connection);
			throw new Error('Iroh endpoint is closed');
		}
		try {
			limitIncomingStreams(connection, false);
			const stream = await withDeadline(connection.openBi(), timeoutMs);
			return adapt(connection, stream);
		} catch (err) {
			closeConnection(connection);
			throw err;
		}
	}

	listen(
		onConnection: (socket: IDuplexTransport) => void,
		onError: (error: Error) => void
	): void {
		if (this.closed) throw new Error('Iroh endpoint is closed');
		this.onConnection = onConnection;
		this.onError = onError;
		if (!this.settling) this.endpoint.setAlpns([this.alpn]);
	}

	stopListening(): void {
		this.epoch++;
		this.onConnection = undefined;
		this.endpoint.setAlpns([]);
		for (const connection of this.handshakes) closeConnection(connection);
		this.handshakes.clear();
	}

	close(): Promise<void> {
		if (this.closing) return this.closing;
		this.closed = true;
		if (this.guard) clearInterval(this.guard);
		this.endSettling?.(new Error('Iroh endpoint is closed'));
		this.stopListening();
		this.closing = this.endpoint.close();
		return this.closing;
	}

	private async acceptLoop(): Promise<void> {
		try {
			while (!this.closed) {
				const incoming = await this.endpoint.acceptNext();
				if (!incoming) return;
				if (
					!this.onConnection ||
					this.pending >= (this.options.maxPendingInbound ?? 50)
				) {
					await incoming.refuse();
					continue;
				}
				this.pending++;
				void this.accept(incoming, this.epoch).finally(() => {
					this.pending--;
				});
			}
		} catch (err) {
			if (!this.closed)
				this.onError?.(err instanceof Error ? err : new Error(String(err)));
		}
	}

	private async accept(
		incoming: Binding.Incoming,
		epoch: number
	): Promise<void> {
		let connection: Binding.Connection | undefined;
		try {
			const timeout = this.options.handshakeTimeoutMs ?? 10_000;
			const pending = incoming
				.accept()
				.then((accepting) => accepting.connect());
			connection = await withDeadline(pending, timeout, closeConnection);
			if (!this.onConnection || epoch !== this.epoch || this.closed) {
				closeConnection(connection);
				return;
			}
			this.handshakes.add(connection);
			limitIncomingStreams(connection, true);
			const stream = await withDeadline(connection.acceptBi(), timeout);
			rejectUnexpectedStream(connection, connection.acceptBi());
			if (!this.onConnection || epoch !== this.epoch || this.closed) {
				closeConnection(connection);
				return;
			}
			this.onConnection(adapt(connection, stream));
		} catch {
			if (connection) closeConnection(connection);
			// An unauthenticated connection failing is local to that attempt.
		} finally {
			if (connection) this.handshakes.delete(connection);
		}
	}
}

function limitIncomingStreams(
	connection: Binding.Connection,
	acceptFirstBi: boolean
): void {
	connection.setMaxConcurrentBiStreams(acceptFirstBi ? 1n : 0n);
	connection.setMaxConcurrentUniStreams(0n);
	// Credits advertised during the handshake cannot be retracted. Close on
	// any unexpected stream instead of leaving its native buffers unread.
	rejectUnexpectedStream(connection, connection.acceptUni());
	if (!acceptFirstBi) rejectUnexpectedStream(connection, connection.acceptBi());
}

function rejectUnexpectedStream(
	connection: Binding.Connection,
	stream: Promise<unknown>
): void {
	void stream.then(
		() => connection.close(1n, Array.from(Buffer.from('Unexpected stream'))),
		() => undefined // Normal connection shutdown rejects pending accepts.
	);
}

function adapt(
	connection: Binding.Connection,
	stream: Binding.BiStream
): IrohTransport {
	const endpointId = Buffer.from(connection.remoteId().toBytes()).toString(
		'hex'
	);
	return new IrohTransport({
		read: async (limit) => Uint8Array.from(await stream.recv.read(limit)),
		writeAll: (data) => stream.send.writeAll(Array.from(data)),
		close: () => closeConnection(connection),
		closed: async (): Promise<void> => {
			await connection.closed();
		},
		diagnostics: (): IIrohDiagnostics => {
			const path = connection.paths().find((candidate) => candidate.isSelected);
			return {
				endpointId,
				path: path?.isIp ? 'direct' : path?.isRelay ? 'relay' : 'unknown',
				...(path ? { rttMs: path.rttMs } : {})
			};
		}
	});
}

function closeConnection(connection: Binding.Connection): void {
	connection.close(0n, []);
}

async function withDeadline<T>(
	promise: Promise<T>,
	ms: number,
	dispose?: (value: T) => void
): Promise<T> {
	let expired = false;
	let timer: ReturnType<typeof setTimeout> | undefined;
	try {
		return await Promise.race([
			promise.then((value) => {
				if (expired) dispose?.(value);
				return value;
			}),
			new Promise<never>((_, reject) => {
				timer = setTimeout(() => {
					expired = true;
					reject(new Error('Iroh connection timed out'));
				}, ms);
				timer.unref?.();
			})
		]);
	} finally {
		if (timer) clearTimeout(timer);
	}
}
