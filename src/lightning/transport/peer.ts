/**
 * BOLT 8: Single peer TCP connection.
 *
 * Manages the full lifecycle of a connection to a Lightning peer:
 * connect → handshake → init exchange → encrypted messaging.
 *
 * Uses Node.js TCP sockets with the Noise_XK handshake protocol
 * and BOLT 8 encrypted message framing.
 */

import { EventEmitter } from 'events';
import net from 'net';
import {
	createInitiatorHandshake,
	createResponderHandshake,
	ACT_ONE_LENGTH,
	ACT_TWO_LENGTH,
	ACT_THREE_LENGTH
} from './noise';
import { TransportCipher } from './cipher';
import { encodeMessage, decodeMessage } from '../message/codec';
import {
	encodeInitMessage,
	decodeInitMessage,
	IInitMessage
} from '../message/init';
import { MessageType, isRequiredMessageType } from '../message/types';
import {
	FeatureFlags,
	hasUnsupportedRequiredFeatures
} from '../features/flags';
import {
	encodePingMessage,
	decodePingMessage,
	encodePongMessage
} from '../message/ping';

const DEFAULT_PING_INTERVAL_MS = 30_000;
// Tor circuits routinely stall for 15-60s without dying; a tight pong timeout
// causes spurious disconnects mid-payment. Dead TCP connections are still
// detected promptly via socket error/close and the keepalive probes below.
const DEFAULT_PONG_TIMEOUT_MS = 60_000;
const TCP_KEEPALIVE_DELAY_MS = 45_000;
const ENCRYPTED_LENGTH_SIZE = 18; // 2-byte length + 16-byte tag
const MAX_READ_BUFFER = 2 * 1024 * 1024; // 2 MB

export interface IPeerOptions {
	/** Local node private key (32 bytes) */
	localPrivateKey: Buffer;
	/** Remote node public key (33 bytes) */
	remotePublicKey: Buffer;
	/** Remote host address */
	host: string;
	/** Remote port */
	port: number;
	/** Local feature flags to advertise */
	localFeatures?: FeatureFlags;
	/** Chain hashes to advertise */
	networks?: Buffer[];
	/** Ping interval in ms (default 30s) */
	pingInterval?: number;
	/** Pong timeout in ms (default 10s) */
	pongTimeout?: number;
	/** Optional socket factory (e.g. for SOCKS5/Tor proxy connections) */
	createSocket?: (host: string, port: number) => Promise<net.Socket>;
	/** TCP connect timeout in ms (default 15000) */
	connectTimeout?: number;
	/** Noise handshake + init exchange timeout in ms (default 30000) */
	handshakeTimeout?: number;
}

export interface IPeerEvents {
	connect: () => void;
	message: (type: number, payload: Buffer) => void;
	close: (hadError: boolean) => void;
	error: (err: Error) => void;
	init: (remoteInit: IInitMessage) => void;
}

type PeerState =
	| 'disconnected'
	| 'connecting'
	| 'handshaking'
	| 'init'
	| 'ready'
	| 'closing';

export class Peer extends EventEmitter {
	remotePublicKey: Buffer;
	readonly host: string;
	readonly port: number;

	private localPrivateKey: Buffer;
	private localFeatures: FeatureFlags;
	private networks?: Buffer[];
	private state: PeerState = 'disconnected';
	private socket: net.Socket | null = null;
	private transport: TransportCipher | null = null;
	private remoteInit: IInitMessage | null = null;

	// Read buffer for partial TCP reads
	private readBuffer: Buffer = Buffer.alloc(0);
	private pendingBodyLength = -1;

	// Ping/pong
	private pingTimer: ReturnType<typeof setInterval> | null = null;
	private pongTimer: ReturnType<typeof setTimeout> | null = null;
	private pingIntervalMs: number;
	private pongTimeoutMs: number;

	// Optional socket factory for proxy connections (e.g. SOCKS5/Tor)
	private createSocketFn?: (host: string, port: number) => Promise<net.Socket>;

	// Connection timeouts (Fix 3.1)
	private connectTimeoutMs: number;
	private handshakeTimeoutMs: number;

	constructor(options: IPeerOptions) {
		super();
		this.localPrivateKey = options.localPrivateKey;
		this.remotePublicKey = options.remotePublicKey;
		this.host = options.host;
		this.port = options.port;
		this.localFeatures = options.localFeatures || FeatureFlags.empty();
		this.networks = options.networks;
		this.pingIntervalMs = options.pingInterval ?? DEFAULT_PING_INTERVAL_MS;
		this.pongTimeoutMs = options.pongTimeout ?? DEFAULT_PONG_TIMEOUT_MS;
		this.createSocketFn = options.createSocket;
		this.connectTimeoutMs = options.connectTimeout ?? 15_000;
		this.handshakeTimeoutMs = options.handshakeTimeout ?? 30_000;
	}

	getState(): PeerState {
		return this.state;
	}

	getRemoteInit(): IInitMessage | null {
		return this.remoteInit;
	}

	/**
	 * Initiate an outbound connection to the peer.
	 */
	async connect(): Promise<void> {
		if (this.state !== 'disconnected') {
			throw new Error(`Cannot connect: peer is ${this.state}`);
		}

		this.state = 'connecting';

		if (this.createSocketFn) {
			// Use custom socket factory (e.g. SOCKS5/Tor proxy) with handshake timeout
			try {
				const socketPromise = this.createSocketFn(this.host, this.port);
				// Don't leak the socket if the factory resolves after we timed out
				// (common with stalled Tor circuits).
				let connectTimedOut = false;
				socketPromise
					.then((s) => {
						if (connectTimedOut) s.destroy();
					})
					.catch(() => {
						/* connection already failed; nothing to clean up */
					});
				const timeoutPromise = new Promise<never>((_, rej) =>
					setTimeout(() => {
						connectTimedOut = true;
						rej(new Error('Connection timeout'));
					}, this.connectTimeoutMs)
				);
				this.socket = await Promise.race([socketPromise, timeoutPromise]);
				this.socket.setKeepAlive(true, TCP_KEEPALIVE_DELAY_MS);
				// Set handshake timeout
				this.socket.setTimeout(this.handshakeTimeoutMs);
				this.socket.once('timeout', () => {
					this.socket?.destroy(new Error('Handshake timeout'));
				});
				await this.doHandshakeAndInit(false);
				this.socket.setTimeout(0); // Clear handshake timeout
				this.state = 'ready';
				this.setupMessageLoop();
				this.startPingTimer();
				this.emit('connect');
			} catch (err) {
				this.state = 'disconnected';
				this.destroySocket();
				throw err;
			}
		} else {
			// Direct TCP connection with connect timeout (Fix 3.1)
			return new Promise<void>((resolve, reject) => {
				this.socket = net.connect(this.port, this.host);

				// Set TCP connect timeout
				this.socket.setTimeout(this.connectTimeoutMs);

				const onError = (err: Error): void => {
					this.state = 'disconnected';
					reject(err);
				};

				const onTimeout = (): void => {
					this.socket?.destroy(new Error('Connection timeout'));
				};

				this.socket.once('error', onError);
				this.socket.once('timeout', onTimeout);

				this.socket.once('connect', async () => {
					this.socket!.removeListener('error', onError);
					this.socket!.removeListener('timeout', onTimeout);
					this.socket!.setKeepAlive(true, TCP_KEEPALIVE_DELAY_MS);
					// Switch to handshake timeout
					this.socket!.setTimeout(this.handshakeTimeoutMs);
					this.socket!.once('timeout', () => {
						this.socket?.destroy(new Error('Handshake timeout'));
					});
					try {
						await this.doHandshakeAndInit(false);
						this.socket!.setTimeout(0); // Clear handshake timeout
						this.state = 'ready';
						this.setupMessageLoop();
						this.startPingTimer();
						this.emit('connect');
						resolve();
					} catch (err) {
						this.destroySocket();
						reject(err);
					}
				});
			});
		}
	}

	/**
	 * Accept an inbound connection from a peer.
	 * @param socket - Already-connected TCP socket
	 */
	async acceptInbound(socket: net.Socket): Promise<void> {
		if (this.state !== 'disconnected') {
			throw new Error(`Cannot accept: peer is ${this.state}`);
		}

		this.socket = socket;
		this.state = 'handshaking';
		socket.setKeepAlive(true, TCP_KEEPALIVE_DELAY_MS);

		// Set handshake timeout for inbound connections
		socket.setTimeout(this.handshakeTimeoutMs);
		socket.once('timeout', () => {
			socket.destroy(new Error('Inbound handshake timeout'));
		});

		try {
			await this.doHandshakeAndInit(true);
			this.socket!.setTimeout(0); // Clear handshake timeout
			this.state = 'ready';
			this.setupMessageLoop();
			this.startPingTimer();
			this.emit('connect');
		} catch (err) {
			this.destroySocket();
			throw err;
		}
	}

	/**
	 * Send a Lightning message to the peer.
	 *
	 * Backpressure: when the socket's write buffer is saturated (slow link, e.g.
	 * a stalled Tor circuit) best-effort gossip messages are dropped instead of
	 * growing the buffer without bound — replying to a full-graph gossip query
	 * over a slow circuit must not OOM the node. Channel-critical messages are
	 * always queued regardless of buffer depth.
	 */
	sendMessage(type: number, payload: Buffer): void {
		if (this.state !== 'ready' || !this.transport || !this.socket) {
			throw new Error('Peer is not ready for messaging');
		}
		if (payload.length > 65535) {
			throw new Error(
				`Message payload ${payload.length} bytes exceeds maximum 65535`
			);
		}

		if (
			Peer.GOSSIP_MESSAGE_TYPES.has(type) &&
			this.socket.writableLength > Peer.MAX_GOSSIP_WRITE_BUFFER
		) {
			return; // drop best-effort gossip under backpressure
		}

		const message = encodeMessage(type, payload);
		const encrypted = this.transport.encryptPacket(message);
		this.socket.write(encrypted);
	}

	/** Best-effort gossip messages that may be dropped under write backpressure. */
	private static readonly GOSSIP_MESSAGE_TYPES = new Set<number>([
		256, // channel_announcement
		257, // node_announcement
		258, // channel_update
		262, // reply_short_channel_ids_end
		264, // reply_channel_range
		265 // gossip_timestamp_filter
	]);

	/** Above this many buffered bytes, gossip sends are dropped. */
	private static readonly MAX_GOSSIP_WRITE_BUFFER = 4 * 1024 * 1024; // 4 MB

	/**
	 * Disconnect from the peer gracefully.
	 */
	disconnect(): void {
		this.state = 'closing';
		this.stopPingTimer();
		this.destroySocket();
		this.state = 'disconnected';
	}

	/**
	 * Run the noise handshake + init exchange with a persistent socket error/close
	 * guard. Without this, a socket 'error' during the handshake (e.g. the peer
	 * resetting the connection because our act-1 didn't decrypt — usually a wrong
	 * node pubkey or address) has no listener and Node throws it as an UNCAUGHT
	 * exception; a graceful close mid-read can also escape the connect() chain.
	 * The guard guarantees an 'error' listener exists and that any failure rejects
	 * cleanly so connect()/acceptInbound() surface it.
	 */
	private async doHandshakeAndInit(isResponder: boolean): Promise<void> {
		const socket = this.socket;
		if (!socket) throw new Error('No socket for handshake');

		let onFail: (err: Error) => void = () => {
			/* set below */
		};
		const failure = new Promise<never>((_, reject) => {
			onFail = reject;
		});
		const onErr = (err: Error): void => onFail(err);
		const onClose = (): void =>
			onFail(new Error('Connection closed during handshake'));

		socket.on('error', onErr);
		socket.on('close', onClose);
		try {
			await Promise.race([
				(async (): Promise<void> => {
					if (isResponder) {
						await this.performResponderHandshake();
					} else {
						await this.performHandshake();
					}
					await this.exchangeInit();
				})(),
				failure
			]);
		} finally {
			socket.removeListener('error', onErr);
			socket.removeListener('close', onClose);
		}
	}

	// ─── Handshake (Initiator) ─────────────────────────────────

	private async performHandshake(): Promise<void> {
		this.state = 'handshaking';

		const handshake = createInitiatorHandshake(
			this.localPrivateKey,
			this.remotePublicKey
		);

		// Send Act 1
		await this.socketWrite(handshake.act1);

		// Read Act 2
		const act2 = await this.socketRead(ACT_TWO_LENGTH);
		handshake.processAct2(act2);

		// Send Act 3
		const act3 = handshake.createAct3();
		await this.socketWrite(act3);

		// Derive transport cipher
		this.transport = handshake.deriveTransport();
	}

	// ─── Handshake (Responder) ─────────────────────────────────

	private async performResponderHandshake(): Promise<void> {
		const handshake = createResponderHandshake(this.localPrivateKey);

		// Read Act 1
		const act1 = await this.socketRead(ACT_ONE_LENGTH);
		handshake.processAct1(act1);

		// Send Act 2
		const act2 = handshake.createAct2();
		await this.socketWrite(act2);

		// Read Act 3
		const act3 = await this.socketRead(ACT_THREE_LENGTH);
		const remotePub = handshake.processAct3(act3);

		// For inbound connections (all-zero placeholder), learn the remote pubkey.
		// For outbound connections, verify it matches what we expect.
		const isPlaceholder = this.remotePublicKey.every((b) => b === 0);
		if (isPlaceholder) {
			this.remotePublicKey = remotePub;
		} else if (!this.remotePublicKey.equals(remotePub)) {
			throw new Error('Remote public key mismatch after handshake');
		}

		// Derive transport cipher
		this.transport = handshake.deriveTransport();
	}

	// ─── Init exchange ─────────────────────────────────────────

	private async exchangeInit(): Promise<void> {
		this.state = 'init';

		// Send our init message
		const initPayload = encodeInitMessage({
			features: this.localFeatures,
			networks: this.networks
		});
		const initMsg = encodeMessage(MessageType.INIT, initPayload);
		const encrypted = this.transport!.encryptPacket(initMsg);
		await this.socketWrite(encrypted);

		// Read remote init message
		const remoteMsg = await this.readEncryptedMessage();
		const decoded = decodeMessage(remoteMsg);

		if (decoded.type !== MessageType.INIT) {
			throw new Error(
				`Expected init message (type ${MessageType.INIT}), got type ${decoded.type}`
			);
		}

		this.remoteInit = decodeInitMessage(decoded.payload);

		// BOLT 1: Disconnect if peer requires features we don't support (Fix 3.2)
		const unsupported = hasUnsupportedRequiredFeatures(
			this.localFeatures,
			this.remoteInit.features
		);
		if (unsupported.length > 0) {
			throw new Error(
				`Peer requires unsupported features: ${unsupported.join(', ')}`
			);
		}

		this.emit('init', this.remoteInit);
	}

	// ─── Encrypted message reading ─────────────────────────────

	private async readEncryptedMessage(): Promise<Buffer> {
		// Read encrypted length (18 bytes)
		const encryptedLength = await this.socketRead(ENCRYPTED_LENGTH_SIZE);
		const bodyLength = this.transport!.decryptLength(encryptedLength);

		// Read encrypted body (bodyLength + 16 bytes for tag)
		const encryptedBody = await this.socketRead(bodyLength + 16);
		return this.transport!.decryptBody(encryptedBody);
	}

	private setupMessageLoop(): void {
		if (!this.socket) return;

		this.socket.on('data', (data: Buffer) => {
			this.readBuffer = Buffer.concat([this.readBuffer, data]);
			if (this.readBuffer.length > MAX_READ_BUFFER) {
				this.emit(
					'error',
					new Error(
						`Read buffer overflow: ${this.readBuffer.length} bytes exceeds ${MAX_READ_BUFFER}`
					)
				);
				this.disconnect();
				return;
			}
			this.processReadBuffer();
		});

		this.socket.on('close', (hadError) => {
			this.state = 'disconnected';
			this.stopPingTimer();
			this.emit('close', hadError);
		});

		this.socket.on('error', (err) => {
			this.emit('error', err);
		});

		// Drain any data buffered during handshake/init exchange.
		// socketRead() stores excess bytes in readBuffer, which won't be
		// processed until the next 'data' event unless we kick it here.
		if (this.readBuffer.length > 0) {
			this.processReadBuffer();
		}
	}

	private processReadBuffer(): void {
		// eslint-disable-next-line no-constant-condition -- drains buffered frames until it returns
		while (true) {
			if (this.pendingBodyLength === -1) {
				// Need to read encrypted length (18 bytes)
				if (this.readBuffer.length < ENCRYPTED_LENGTH_SIZE) {
					return; // Wait for more data
				}

				const encryptedLength = this.readBuffer.subarray(
					0,
					ENCRYPTED_LENGTH_SIZE
				);
				this.readBuffer = this.readBuffer.subarray(ENCRYPTED_LENGTH_SIZE);

				try {
					this.pendingBodyLength =
						this.transport!.decryptLength(encryptedLength);
				} catch (err) {
					this.emit('error', err as Error);
					this.disconnect();
					return;
				}

				if (this.pendingBodyLength > 65535) {
					this.emit(
						'error',
						new Error(
							`Decrypted message length ${this.pendingBodyLength} exceeds maximum 65535`
						)
					);
					this.disconnect();
					return;
				}
			}

			// Need to read encrypted body (bodyLength + 16)
			const needed = this.pendingBodyLength + 16;
			if (this.readBuffer.length < needed) {
				return; // Wait for more data
			}

			const encryptedBody = this.readBuffer.subarray(0, needed);
			this.readBuffer = this.readBuffer.subarray(needed);
			this.pendingBodyLength = -1;

			try {
				const body = this.transport!.decryptBody(encryptedBody);
				const decoded = decodeMessage(body);
				this.handleMessage(decoded.type, decoded.payload);
			} catch (err) {
				this.emit('error', err as Error);
				this.disconnect();
				return;
			}
		}
	}

	private handleMessage(type: number, payload: Buffer): void {
		// Handle ping/pong internally
		if (type === MessageType.PING) {
			const ping = decodePingMessage(payload);
			if (ping.numPongBytes <= 65531) {
				const pong = encodePongMessage(ping.numPongBytes);
				this.sendMessage(MessageType.PONG, pong);
			}
			return;
		}

		if (type === MessageType.PONG) {
			this.handlePong();
			return;
		}

		// BOLT 1: Unknown even (required) message types must trigger disconnect
		const isKnown = Object.values(MessageType).includes(type);
		if (!isKnown && isRequiredMessageType(type)) {
			this.emit('error', new Error(`Unknown required message type ${type}`));
			this.disconnect();
			return;
		}

		// Emit known messages and unknown odd messages to listeners
		this.emit('message', type, payload);
	}

	// ─── Ping/Pong ─────────────────────────────────────────────

	private startPingTimer(): void {
		this.pingTimer = setInterval(() => {
			this.sendPing();
		}, this.pingIntervalMs);
		if (this.pingTimer.unref) {
			this.pingTimer.unref();
		}
	}

	private stopPingTimer(): void {
		if (this.pingTimer) {
			clearInterval(this.pingTimer);
			this.pingTimer = null;
		}
		if (this.pongTimer) {
			clearTimeout(this.pongTimer);
			this.pongTimer = null;
		}
	}

	private sendPing(): void {
		if (this.state !== 'ready') return;

		try {
			const ping = encodePingMessage(1, 0);
			this.sendMessage(MessageType.PING, ping);

			// Clear existing pong timer before starting new one
			if (this.pongTimer) {
				clearTimeout(this.pongTimer);
				this.pongTimer = null;
			}
			// Start pong timeout
			this.pongTimer = setTimeout(() => {
				this.emit('error', new Error('Pong timeout'));
				this.disconnect();
			}, this.pongTimeoutMs);
		} catch {
			// Ignore send errors during ping
		}
	}

	private handlePong(): void {
		if (this.pongTimer) {
			clearTimeout(this.pongTimer);
			this.pongTimer = null;
		}
	}

	// ─── Socket helpers ────────────────────────────────────────

	private socketWrite(data: Buffer): Promise<void> {
		return new Promise((resolve, reject) => {
			if (!this.socket) {
				return reject(new Error('Socket is closed'));
			}
			this.socket.write(data, (err) => {
				if (err) reject(err);
				else resolve();
			});
		});
	}

	private socketRead(length: number): Promise<Buffer> {
		return new Promise((resolve, reject) => {
			if (!this.socket) {
				return reject(new Error('Socket is closed'));
			}

			let collected = Buffer.alloc(0);

			const onData = (data: Buffer): void => {
				collected = Buffer.concat([collected, data]);
				if (collected.length >= length) {
					this.socket!.removeListener('data', onData);
					this.socket!.removeListener('error', onError);
					this.socket!.removeListener('close', onClose);
					const result = collected.subarray(0, length);
					// Put back excess data
					this.readBuffer = Buffer.concat([
						collected.subarray(length),
						this.readBuffer
					]);
					resolve(result);
				}
			};

			const onError = (err: Error): void => {
				this.socket!.removeListener('data', onData);
				this.socket!.removeListener('close', onClose);
				reject(err);
			};

			const onClose = (): void => {
				this.socket!.removeListener('data', onData);
				this.socket!.removeListener('error', onError);
				reject(new Error('Socket closed before read completed'));
			};

			// Check if we already have enough data in the buffer
			if (this.readBuffer.length >= length) {
				const result = this.readBuffer.subarray(0, length);
				this.readBuffer = this.readBuffer.subarray(length);
				resolve(result);
				return;
			}

			// Use existing buffer data
			collected = Buffer.from(this.readBuffer);
			this.readBuffer = Buffer.alloc(0);

			this.socket.on('data', onData);
			this.socket.once('error', onError);
			this.socket.once('close', onClose);
		});
	}

	private destroySocket(): void {
		if (this.socket) {
			this.socket.removeAllListeners();
			this.socket.destroy();
			this.socket = null;
		}
		this.transport = null;
		this.readBuffer = Buffer.alloc(0);
		this.pendingBodyLength = -1;
	}
}
