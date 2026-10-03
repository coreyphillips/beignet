/** Node-only Iroh backend. Import this entry explicitly, never in portable code. */
import type * as Binding from '@number0/iroh';
import {
	IROH_ALPN,
	IIrohAddress,
	IIrohDiagnostics,
	IIrohEndpoint,
	IIrohEndpointOptions,
	IrohTransport,
	normalizeIrohEndpointId,
	validateIrohRelayUrl
} from './iroh';
import { IDuplexTransport } from './duplex-transport';

/** Lazily load the optional native addon only after an explicit opt-in. */
export async function createNodeIrohEndpoint(
	options: IIrohEndpointOptions
): Promise<IIrohEndpoint> {
	if (options.secretKey.length !== 32)
		throw new Error('Iroh secret key must be 32 bytes');
	let binding: typeof Binding;
	try {
		binding = require('@number0/iroh') as typeof Binding;
	} catch {
		throw new Error(
			'Iroh requires the optional @number0/iroh binding and Node >= 20.3'
		);
	}
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
	return new NodeIrohEndpoint(binding, await builder.bind(), options);
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

	constructor(
		private readonly binding: typeof Binding,
		private readonly endpoint: Binding.Endpoint,
		private readonly options: IIrohEndpointOptions
	) {
		void this.acceptLoop();
	}

	address(): IIrohAddress {
		const relayUrl = this.endpoint.addr().relayUrl();
		return {
			endpointId: Buffer.from(this.endpoint.id().toBytes()).toString('hex'),
			...(relayUrl ? { relayUrl } : {}),
			directAddresses: this.endpoint.addr().directAddresses()
		};
	}

	async connect(
		address: IIrohAddress,
		timeoutMs: number
	): Promise<IDuplexTransport> {
		if (this.closed) throw new Error('Iroh endpoint is closed');
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
		this.endpoint.setAlpns([this.alpn]);
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
			connection.setMaxConcurrentBiStreams(1n);
			connection.setMaxConcurrentUniStreams(0n);
			const stream = await withDeadline(connection.acceptBi(), timeout);
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
