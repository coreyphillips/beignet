/**
 * BOLT 8: Single peer connection.
 *
 * Manages the full lifecycle of a connection to a Lightning peer:
 * connect → handshake → init exchange → encrypted messaging.
 *
 * Runs the Noise_XK handshake and BOLT 8 encrypted message framing over an
 * IDuplexTransport. The default (and unchanged) transport is a Node.js TCP
 * socket — which satisfies the interface structurally — including the
 * SOCKS5/Tor factory path; WebSocket transports plug in via createSocket.
 */

import { EventEmitter } from 'events';
import net from 'net';
import { IDuplexTransport } from './duplex-transport';
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
	/**
	 * Hold post-init inbound messages until releaseHeldMessages() is
	 * called. The post-handshake drain can surface coalesced traffic (an
	 * init and an open_channel2 in one TCP segment) before the consumer
	 * has finished its bring-up (registration, peer:connect handlers);
	 * holding at the source keeps ONE ordered stream instead of racing
	 * early frames against that bring-up. Managed connections set this;
	 * a raw Peer keeps the historical emit-immediately behavior.
	 */
	holdMessagesUntilRelease?: boolean;
	/** Chain hashes to advertise */
	networks?: Buffer[];
	/** Ping interval in ms (default 30s) */
	pingInterval?: number;
	/** Pong timeout in ms (default 10s) */
	pongTimeout?: number;
	/** Optional transport factory (e.g. SOCKS5/Tor proxy sockets, WebSocket).
	 *  net.Socket satisfies IDuplexTransport, so existing socket factories
	 *  keep working unchanged. */
	createSocket?: (host: string, port: number) => Promise<IDuplexTransport>;
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
	/** Non-null while messages are held (see holdMessagesUntilRelease). */
	private heldMessages: Array<{ type: number; payload: Buffer }> | null = null;
	/** True while releaseHeldMessages() is mid-drain (reentrancy guard). */
	private drainingHeld = false;
	/**
	 * The lifecycle's terminal release outcome, STICKY until the next
	 * establishment re-arms: releaseHeldMessages() is public, so an
	 * observer may drain (and fail) before the manager's own call, and the
	 * manager must still see the causal result rather than a fresh
	 * 'released' from an already-cleared queue.
	 */
	private heldReleaseOutcome: 'released' | 'aborted' | 'failed' | null = null;
	/**
	 * Monotonic id of the held-message lifecycle, bumped ONLY by
	 * rearmHeldMessages(). Array identity cannot scope a drain to its
	 * lifecycle: disconnect() nulls the queue without beginning a new
	 * lifecycle, so `heldMessages === held` reads false for the very
	 * lifecycle the drain still owns. A drain captures this id at entry
	 * and writes sticky outcomes or performs teardown only while it still
	 * matches; a handler that re-armed a fresh lifecycle mid-drain leaves
	 * the old drain with a stale id and no authority over the new state.
	 */
	private heldLifecycleId = 0;
	/** The configured hold behavior, re-armed on every establishment. */
	private readonly holdOnEstablish: boolean = false;
	private socket: IDuplexTransport | null = null;
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

	// Optional transport factory (e.g. SOCKS5/Tor proxy sockets, WebSocket)
	private createSocketFn?: (
		host: string,
		port: number
	) => Promise<IDuplexTransport>;

	// Connection timeouts (Fix 3.1)
	private connectTimeoutMs: number;
	private handshakeTimeoutMs: number;
	/** disconnect() was called after the current connect/accept began. */
	private aborted = false;
	/**
	 * Rejects the in-flight connect/accept. destroySocket strips the socket
	 * listeners BEFORE destroying it and net.Socket emits its close a tick
	 * later, so an abort that relied on socket events would leave the
	 * establishment promise pending forever.
	 */
	private establishmentAbort: ((err: Error) => void) | null = null;

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
		this.holdOnEstablish = options.holdMessagesUntilRelease === true;
		this.heldMessages = this.holdOnEstablish ? [] : null;
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
	/** Arm a fresh hold for a new connection lifecycle (see options). */
	private rearmHeldMessages(): void {
		this.heldLifecycleId++;
		this.heldMessages = this.holdOnEstablish ? [] : null;
		this.drainingHeld = false;
		this.heldReleaseOutcome = null;
	}

	async connect(): Promise<void> {
		// Validate the lifecycle transition BEFORE mutating anything: a
		// rejected connect() on a live peer must not touch that
		// connection's queue (re-arming it would hold its traffic forever).
		if (this.state !== 'disconnected') {
			throw new Error(`Cannot connect: peer is ${this.state}`);
		}
		// A reused Peer must neither replay the previous connection's held
		// frames nor skip holding because the first release nulled the
		// queue: every establishment starts a fresh hold lifecycle.
		this.rearmHeldMessages();

		this.state = 'connecting';
		this.aborted = false;

		if (this.createSocketFn) {
			// Use custom socket factory (e.g. SOCKS5/Tor proxy) with handshake timeout
			let abortEstablish: (err: Error) => void = () => undefined;
			const abortPromise = new Promise<never>((_, reject) => {
				abortEstablish = reject;
			});
			abortPromise.catch(() => {
				// Rejection is consumed by whichever race is in flight; this
				// guard exists for aborts that land between the races.
			});
			this.establishmentAbort = abortEstablish;
			try {
				const socketPromise = this.createSocketFn(this.host, this.port);
				// Don't leak the socket if the factory resolves after we timed out
				// (common with stalled Tor circuits).
				let connectTimedOut = false;
				socketPromise
					.then((s) => {
						if (connectTimedOut || this.aborted) s.destroy();
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
				this.socket = await Promise.race([
					socketPromise,
					timeoutPromise,
					abortPromise
				]);
				if (this.aborted) {
					// disconnect() ran while the factory was pending; the socket
					// only exists now, so it dies now, before any handshake byte.
					throw new Error('Peer aborted while connecting');
				}
				this.socket.setKeepAlive(true, TCP_KEEPALIVE_DELAY_MS);
				// Set handshake timeout
				this.socket.setTimeout(this.handshakeTimeoutMs);
				this.socket.once('timeout', () => {
					this.socket?.destroy(new Error('Handshake timeout'));
				});
				const handshake = this.doHandshakeAndInit(false);
				handshake.catch(() => {
					// Consumed via the race; without this, an abort winning the
					// race leaves the losing handshake's rejection unhandled.
				});
				await Promise.race([handshake, abortPromise]);
				this.socket.setTimeout(0); // Clear handshake timeout
				this.state = 'ready';
				this.setupMessageLoop();
				this.startPingTimer();
				this.emit('connect');
			} catch (err) {
				this.state = 'disconnected';
				this.destroySocket();
				throw err;
			} finally {
				this.establishmentAbort = null;
			}
		} else {
			// Direct TCP connection with connect timeout (Fix 3.1)
			return new Promise<void>((resolve, reject) => {
				this.establishmentAbort = (err): void => {
					this.state = 'disconnected';
					reject(err);
				};
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

				const onConnect = async (): Promise<void> => {
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
				};
				this.socket.once('connect', (): void => {
					void onConnect();
				});
			}).finally(() => {
				this.establishmentAbort = null;
			});
		}
	}

	/**
	 * Accept an inbound connection from a peer.
	 * @param socket - Already-connected transport (TCP socket or accepted
	 *                 WebSocket connection)
	 */
	async acceptInbound(socket: IDuplexTransport): Promise<void> {
		if (this.state !== 'disconnected') {
			throw new Error(`Cannot accept: peer is ${this.state}`);
		}
		// See connect(): state validated first, then a fresh hold lifecycle.
		this.rearmHeldMessages();

		this.socket = socket;
		this.state = 'handshaking';
		this.aborted = false;
		socket.setKeepAlive(true, TCP_KEEPALIVE_DELAY_MS);

		// Set handshake timeout for inbound connections
		socket.setTimeout(this.handshakeTimeoutMs);
		socket.once('timeout', () => {
			socket.destroy(new Error('Inbound handshake timeout'));
		});

		let abortEstablish: (err: Error) => void = () => undefined;
		const abortPromise = new Promise<never>((_, reject) => {
			abortEstablish = reject;
		});
		abortPromise.catch(() => {
			// Consumed via the race below when an abort lands mid-handshake.
		});
		this.establishmentAbort = abortEstablish;
		try {
			const handshake = this.doHandshakeAndInit(true);
			handshake.catch(() => {
				// Consumed via the race; see connect().
			});
			await Promise.race([handshake, abortPromise]);
			this.socket!.setTimeout(0); // Clear handshake timeout
			this.state = 'ready';
			this.setupMessageLoop();
			this.startPingTimer();
			this.emit('connect');
		} catch (err) {
			this.destroySocket();
			throw err;
		} finally {
			this.establishmentAbort = null;
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
		// An in-flight connect/accept must not survive this call: the abort
		// flag stops the handshake at its next boundary, a socket factory
		// that resolves later destroys its socket instead of adopting it, and
		// the establishment promise is rejected HERE, because destroySocket
		// removes the socket listeners the failure guards depend on.
		this.aborted = true;
		this.establishmentAbort?.(new Error('Peer aborted'));
		this.establishmentAbort = null;
		this.state = 'closing';
		// The previous connection's undelivered frames die with it: a later
		// re-establishment re-arms a FRESH hold (rearmHeldMessages).
		this.heldMessages = null;
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
		if (this.aborted) {
			throw new Error('Peer aborted before handshake');
		}
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
		// A terminal connection dispatches nothing: a real closed socket
		// emits no data, and a reentrant observer poking a torn-down peer
		// must not slip a message past the state machines either.
		if (this.state === 'closing' || this.state === 'disconnected') return;
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

		// Emit known messages and unknown odd messages to listeners; while
		// held, queue in arrival order instead (ping/pong above stay live).
		if (this.heldMessages) {
			this.heldMessages.push({ type, payload });
			return;
		}
		this.emit('message', type, payload);
	}

	/**
	 * Deliver everything held and go live. Delivery preserves arrival
	 * order, stops the moment the connection leaves 'ready' (a delivered
	 * message may legitimately tear the connection down), and contains a
	 * throwing listener as a peer error rather than letting it unwind the
	 * caller's bring-up bookkeeping.
	 *
	 * The returned outcome is the CAUSAL record the caller cannot infer
	 * from state alone: 'released' means every held frame was delivered
	 * (or none were held), 'aborted' means a delivered frame's handler
	 * ended the connection without an error, 'failed' means a handler
	 * threw and the connection was torn down over it, and 'pending' means
	 * the call was reentrant while the owning drain was still deciding.
	 * Registry identity cannot stand in for any of this: an error
	 * observer's cleanup disconnect looks exactly like a deliberate
	 * cancellation from the outside.
	 */
	releaseHeldMessages(): 'released' | 'aborted' | 'failed' | 'pending' {
		// A reentrant call during an active drain: the owning drain has no
		// terminal outcome yet (unless one was already recorded, e.g. the
		// failure written before its teardown observers run), and inventing
		// 'released' here would be a false terminal answer for a drain that
		// may still fail.
		if (this.drainingHeld) return this.heldReleaseOutcome ?? 'pending';
		const held = this.heldMessages;
		// An already-cleared queue answers with the lifecycle's STICKY
		// outcome: an earlier caller may have drained and failed, and that
		// result must not be laundered into a fresh 'released' for whoever
		// asks next.
		if (!held) return this.heldReleaseOutcome ?? 'released';
		// Reentrancy guard: a recursive release (an observer calling back
		// into the manager) must not start a second cursor and interleave.
		this.drainingHeld = true;
		// The drain acts for THIS lifecycle only: a delivered handler may
		// disconnect and re-establish, arming a fresh lifecycle whose
		// sticky outcome and queue this (now stale) drain must not touch.
		const lifecycle = this.heldLifecycleId;
		try {
			// Drain with an INDEX CURSOR over the live array: reentrant
			// synchronous arrivals append behind the remaining held frames
			// (handleMessage keeps queueing while heldMessages is non-null),
			// and no per-message shift() compaction makes a hostile
			// coalesced burst quadratic.
			let cursor = 0;
			while (cursor < held.length) {
				if (this.state !== 'ready') {
					// Torn down mid-release: the undelivered tail dies with
					// the connection, exactly as unread socket bytes would.
					if (this.heldLifecycleId === lifecycle) {
						this.heldReleaseOutcome = 'aborted';
					}
					return 'aborted';
				}
				const next = held[cursor++];
				try {
					this.emit('message', next.type, next.payload);
				} catch (err) {
					if (this.heldLifecycleId !== lifecycle) {
						// The throwing handler already moved the peer into a
						// FRESH lifecycle before failing: this drain has no
						// authority left. Tearing down, clearing the queue or
						// recording 'failed' now would destroy the new
						// lifecycle over the old one's error. The failure is
						// still SURFACED as the contract promises (a 'failed'
						// outcome with no error event is invisible to every
						// observer that only listens): the error is emitted
						// and contained, but nothing belonging to the new
						// lifecycle is touched.
						try {
							this.emit(
								'error',
								err instanceof Error ? err : new Error(String(err))
							);
						} catch {
							// A throwing error observer changes nothing here.
						}
						return 'failed';
					}
					// TERMINAL FIRST: tear the connection down before any
					// observer runs, so a reentrant or throwing error
					// listener can neither deliver past the gap nor bypass
					// the teardown. Delivering later frames after a missing
					// predecessor would hand the state machines a hole. The
					// outcome is recorded FIRST so even a reentrant query
					// from inside the teardown observers sees the failure.
					this.heldReleaseOutcome = 'failed';
					this.heldMessages = null;
					try {
						this.disconnect();
					} finally {
						try {
							this.emit(
								'error',
								err instanceof Error ? err : new Error(String(err))
							);
						} catch {
							// The error observer threw; the connection is
							// already down, which is the outcome that matters.
						}
					}
					return 'failed';
				}
			}
			// The loop only observes state at the TOP of an iteration, so a
			// teardown by the FINAL frame's handler has no next iteration to
			// notice it: check once more before declaring success, or that
			// teardown would be reported as 'released'.
			if (this.state !== 'ready') {
				if (this.heldLifecycleId === lifecycle) {
					this.heldReleaseOutcome = 'aborted';
				}
				return 'aborted';
			}
			if (this.heldLifecycleId === lifecycle) {
				this.heldReleaseOutcome = 'released';
			}
			return 'released';
		} finally {
			this.drainingHeld = false;
			// Only THIS drain's queue dies here: a delivered message's
			// observer can tear the connection down and begin a new
			// establishment mid-drain, arming a fresh queue that belongs to
			// the newer lifecycle and must survive to its own release.
			if (this.heldMessages === held) {
				this.heldMessages = null;
			}
		}
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
