import { randomBytes } from 'crypto';
import { ecc } from '../utils/ecc';
import { Peer } from '../lightning/transport/peer';
import type { TransportConnectFn } from '../lightning/transport/duplex-transport';
import {
	BEIGNET_CUSTOM_MESSAGE_TYPE,
	BEIGNET_CUSTOM_PROTOCOL_VERSION,
	decodeCustomMessage,
	encodeCustomMessage
} from '../lightning/message/custom';
import { chainHashForNetwork } from '../lightning/direct-funding/types';
import type { Network } from '../lightning/invoice/types';
import type {
	IDfCustomMessage,
	IDfPeerMessaging
} from '../lightning/direct-funding/transport/types';

export interface INodePeerMessagingOptions {
	network: Network;
	/** Transport identity only, never a wallet spending key. Random by default. */
	identityKey?: Buffer;
	/** Optional SOCKS5/Tor or other transport factory. Default is Node TCP. */
	createSocket?: TransportConnectFn;
	/** Hard total deadline for TCP, Noise, and init together. Default 45 seconds. */
	connectionTimeoutMs?: number;
	/** Bound on connected, connecting, and reconnecting peers. Default 8. */
	maxPeers?: number;
	/** Initial reconnect delay, doubling to at most 30 seconds. Default 1 second. */
	reconnectDelayMs?: number;
	/** Diagnostic only. Exceptions and rejected promises from observers are contained. */
	onError?(error: Error, peerNodeId: string): void;
}

interface IConnection {
	id: string;
	host: string;
	port: number;
	reconnect: boolean;
	everConnected: boolean;
	retries: number;
	peer?: Peer;
	pending?: Promise<void>;
	timer?: NodeJS.Timeout;
}

const DIRECT_FUNDING_SUBTYPES = new Set([16, 17, 18, 19, 21, 22]);

function duration(value: number, name: string): number {
	if (!Number.isFinite(value) || value <= 0 || value > 0x7fffffff) {
		throw new Error(`${name} must be positive and fit a timer`);
	}
	return Math.ceil(value);
}

function privateIdentity(): Buffer {
	let key: Buffer;
	do {
		key = randomBytes(32);
	} while (!ecc.isPrivate(key));
	return key;
}

async function withDeadline(
	promise: Promise<void>,
	timeoutMs: number,
	onTimeout?: () => void
): Promise<void> {
	let timer: NodeJS.Timeout | undefined;
	try {
		await Promise.race([
			promise,
			new Promise<never>((_, reject) => {
				timer = setTimeout(() => {
					reject(new Error('direct-funding peer connection timed out'));
					onTimeout?.();
				}, timeoutMs);
			})
		]);
	} finally {
		if (timer) clearTimeout(timer);
	}
}

/**
 * Outbound BOLT 8 messaging for a payer with no Lightning channels. It speaks
 * init, ping/pong, and direct-funding custom messages using the existing Peer
 * transport. It does not accept channels, route payments, or run a node.
 *
 * A connection a payment lane holds (see holdPeer) stays open and reconnects
 * if it drops, and closes when the last lane using it closes. A connection
 * made without a hold stays until disconnectPeer or close. Initial failures do
 * not start background retry loops. Call close when all payments and receipt
 * recovery operations have finished.
 */
export class NodePeerMessaging implements IDfPeerMessaging {
	private readonly identityKey: Buffer;
	private readonly id: string;
	private readonly chainHash: Buffer;
	private readonly timeoutMs: number;
	private readonly maxPeers: number;
	private readonly reconnectDelayMs: number;
	private readonly connections = new Map<string, IConnection>();
	/** Live holds by peer id. A peer's connection is released when its count ends. */
	private readonly holds = new Map<string, number>();
	private readonly messages = new Set<(message: IDfCustomMessage) => void>();
	private readonly connects = new Set<(peerNodeId: string) => void>();
	private closed = false;

	constructor(private readonly options: INodePeerMessagingOptions) {
		this.identityKey = Buffer.from(options.identityKey ?? privateIdentity());
		if (!ecc.isPrivate(this.identityKey)) {
			throw new Error('transport identity must be a valid 32-byte private key');
		}
		this.id = Buffer.from(ecc.pointFromScalar(this.identityKey)!).toString(
			'hex'
		);
		this.chainHash = chainHashForNetwork(options.network);
		this.timeoutMs = duration(
			options.connectionTimeoutMs ?? 45_000,
			'connectionTimeoutMs'
		);
		this.reconnectDelayMs = duration(
			options.reconnectDelayMs ?? 1_000,
			'reconnectDelayMs'
		);
		this.maxPeers = options.maxPeers ?? 8;
		if (!Number.isInteger(this.maxPeers) || this.maxPeers < 1) {
			throw new Error('maxPeers must be a positive integer');
		}
	}

	nodeIdHex(): string {
		return this.id;
	}

	isPeerConnected(peerNodeId: string): boolean {
		return (
			!this.closed &&
			this.connections.get(peerNodeId.toLowerCase())?.peer?.getState() ===
				'ready'
		);
	}

	async connectPeer(
		peerNodeId: string,
		host: string,
		port: number,
		timeoutMs?: number,
		options?: { reconnect?: boolean }
	): Promise<void> {
		this.assertOpen();
		const id = peerNodeId.toLowerCase();
		if (
			!/^(02|03)[0-9a-f]{64}$/.test(id) ||
			!ecc.isPointCompressed(Buffer.from(id, 'hex'))
		) {
			throw new Error(
				'peer identity must be a compressed secp256k1 public key'
			);
		}
		if (id === this.id) throw new Error('cannot connect the payer to itself');
		if (
			!host ||
			host.length > 255 ||
			[...host].some(
				(character) =>
					character.charCodeAt(0) <= 32 || character.charCodeAt(0) === 127
			) ||
			!Number.isInteger(port) ||
			port < 1 ||
			port > 65535
		) {
			throw new Error('invalid direct-funding peer address');
		}
		const limit = duration(timeoutMs ?? this.timeoutMs, 'timeoutMs');
		let entry = this.connections.get(id);
		if (!entry) {
			if (this.connections.size >= this.maxPeers) {
				throw new Error('direct-funding peer connection limit reached');
			}
			entry = {
				id,
				host,
				port,
				reconnect: options?.reconnect !== false,
				everConnected: false,
				retries: 0
			};
			this.connections.set(id, entry);
		} else if (options?.reconnect !== false) {
			entry.reconnect = true;
		}
		if (entry.peer?.getState() === 'ready') return;
		if (entry.timer) {
			clearTimeout(entry.timer);
			entry.timer = undefined;
		}
		// A peer that is not connected is dialled, and redialled, at the address
		// named last.
		const moved = entry.host !== host || entry.port !== port;
		entry.host = host;
		entry.port = port;
		if (entry.pending && moved) {
			// The running dial went to the old address. Let it settle, then try
			// again here, which dials the new address unless it connected.
			const started = Date.now();
			await withDeadline(
				entry.pending.catch(() => undefined),
				limit
			);
			const remaining = limit - (Date.now() - started);
			if (remaining <= 0) {
				throw new Error('direct-funding peer connection timed out');
			}
			return this.connectPeer(id, host, port, remaining, options);
		}
		// A shorter waiter does not cancel another caller's existing shared dial.
		if (entry.pending) await withDeadline(entry.pending, limit);
		else await this.beginDial(entry, limit);
	}

	/**
	 * Keep this peer's connection, and its reconnects, until the returned
	 * function is called. When the last hold on a peer ends, its connection
	 * closes and its slot is freed. The registry from createPeerTransportRegistry
	 * holds each lane's peer from its dial until the lane closes, so a
	 * long-lived instance does not keep every receiver it has paid.
	 */
	holdPeer(peerNodeId: string): () => void {
		const id = peerNodeId.toLowerCase();
		this.holds.set(id, (this.holds.get(id) ?? 0) + 1);
		let released = false;
		return () => {
			if (released) return;
			released = true;
			const count = (this.holds.get(id) ?? 1) - 1;
			if (count > 0) {
				this.holds.set(id, count);
				return;
			}
			this.holds.delete(id);
			this.disconnectPeer(id);
		};
	}

	keepReconnecting(peerNodeId: string): void {
		const entry = this.connections.get(peerNodeId.toLowerCase());
		if (entry) entry.reconnect = true;
	}

	sendCustomMessage(
		peerNodeId: string,
		subtype: number,
		payload: Buffer
	): void {
		this.assertOpen();
		if (!DIRECT_FUNDING_SUBTYPES.has(subtype)) {
			throw new Error('unsupported direct-funding custom message subtype');
		}
		const peer = this.connections.get(peerNodeId.toLowerCase())?.peer;
		if (!peer || peer.getState() !== 'ready') {
			throw new Error('direct-funding peer is not connected');
		}
		peer.sendMessage(
			BEIGNET_CUSTOM_MESSAGE_TYPE,
			encodeCustomMessage(subtype, payload)
		);
	}

	onCustomMessage(callback: (message: IDfCustomMessage) => void): () => void {
		this.assertOpen();
		this.messages.add(callback);
		return () => {
			this.messages.delete(callback);
		};
	}

	onPeerConnect(callback: (peerNodeId: string) => void): () => void {
		this.assertOpen();
		this.connects.add(callback);
		return () => {
			this.connects.delete(callback);
		};
	}

	/** Release one peer only after its payment and receipt recovery work is done. */
	disconnectPeer(peerNodeId: string): void {
		const id = peerNodeId.toLowerCase();
		const entry = this.connections.get(id);
		if (!entry) return;
		this.connections.delete(id);
		if (entry.timer) clearTimeout(entry.timer);
		entry.peer?.disconnect();
	}

	/** Disconnect sockets and cancel every pending dial and reconnect timer. */
	close(): void {
		if (this.closed) return;
		this.closed = true;
		for (const entry of this.connections.values()) {
			if (entry.timer) clearTimeout(entry.timer);
			entry.peer?.disconnect();
		}
		this.connections.clear();
		this.holds.clear();
		this.messages.clear();
		this.connects.clear();
		this.identityKey.fill(0);
	}

	private beginDial(entry: IConnection, timeoutMs: number): Promise<void> {
		const pending = Promise.resolve().then(() => this.dial(entry, timeoutMs));
		entry.pending = pending;
		const finished = (): void => {
			if (entry.pending === pending) entry.pending = undefined;
			if (this.closed || this.connections.get(entry.id) !== entry) return;
			if (entry.peer?.getState() !== 'ready') this.retryOrForget(entry);
		};
		void pending.then(finished, finished);
		return pending;
	}

	private async dial(entry: IConnection, timeoutMs: number): Promise<void> {
		this.assertOpen();
		if (this.connections.get(entry.id) !== entry) {
			throw new Error('direct-funding peer connection cancelled');
		}
		const peer = new Peer({
			localPrivateKey: Buffer.from(this.identityKey),
			remotePublicKey: Buffer.from(entry.id, 'hex'),
			host: entry.host,
			port: entry.port,
			networks: [Buffer.from(this.chainHash)],
			holdMessagesUntilRelease: true,
			connectTimeout: Math.min(timeoutMs, 15_000),
			handshakeTimeout: Math.min(timeoutMs, 30_000),
			createSocket: this.options.createSocket
		});
		entry.peer = peer;
		peer.on('error', (error: Error) => this.report(error, entry.id));
		peer.on('close', () => {
			if (entry.peer !== peer) return;
			entry.peer = undefined;
			if (!entry.pending) this.retryOrForget(entry);
		});
		peer.on('message', (type: number, payload: Buffer) => {
			if (
				this.closed ||
				entry.peer !== peer ||
				type !== BEIGNET_CUSTOM_MESSAGE_TYPE
			)
				return;
			let message: ReturnType<typeof decodeCustomMessage>;
			try {
				message = decodeCustomMessage(payload);
			} catch (error) {
				this.report(error, entry.id);
				return;
			}
			if (
				message.version !== BEIGNET_CUSTOM_PROTOCOL_VERSION ||
				!DIRECT_FUNDING_SUBTYPES.has(message.subtype)
			)
				return;
			for (const callback of [...this.messages]) {
				this.observe(
					() =>
						callback({
							peerPubkey: entry.id,
							version: message.version,
							subtype: message.subtype,
							payload: Buffer.from(message.payload)
						}),
					entry.id
				);
			}
		});
		try {
			await withDeadline(peer.connect(), timeoutMs, () => peer.disconnect());
			if (this.closed || entry.peer !== peer || peer.getState() !== 'ready') {
				throw new Error('direct-funding peer closed during connection');
			}
			entry.everConnected = true;
			entry.retries = 0;
			for (const callback of [...this.connects])
				this.observe(() => callback(entry.id), entry.id);
			if (
				peer.releaseHeldMessages() !== 'released' ||
				peer.getState() !== 'ready'
			) {
				throw new Error('direct-funding peer closed during message release');
			}
		} catch (error) {
			peer.disconnect();
			if (entry.peer === peer) entry.peer = undefined;
			throw error;
		}
	}

	private retryOrForget(entry: IConnection): void {
		if (
			this.closed ||
			this.connections.get(entry.id) !== entry ||
			entry.pending ||
			entry.timer
		)
			return;
		if (!entry.reconnect || !entry.everConnected) {
			this.connections.delete(entry.id);
			return;
		}
		const delay = Math.min(
			30_000,
			this.reconnectDelayMs * 2 ** Math.min(entry.retries++, 10)
		);
		entry.timer = setTimeout(() => {
			entry.timer = undefined;
			if (this.closed || this.connections.get(entry.id) !== entry) return;
			void this.beginDial(entry, this.timeoutMs).catch((error) =>
				this.report(error, entry.id)
			);
		}, delay);
		entry.timer.unref?.();
	}

	private observe(callback: () => unknown, id: string): void {
		try {
			const result = callback();
			if (result && typeof (result as Promise<unknown>).then === 'function') {
				void Promise.resolve(result).catch((error) => this.report(error, id));
			}
		} catch (error) {
			this.report(error, id);
		}
	}

	private report(error: unknown, id: string): void {
		try {
			const result: unknown = this.options.onError?.(
				error instanceof Error ? error : new Error(String(error)),
				id
			);
			if (result && typeof (result as Promise<unknown>).then === 'function') {
				void Promise.resolve(result).catch(() => undefined);
			}
		} catch {
			/* Diagnostics cannot interrupt a payment or another listener. */
		}
	}

	private assertOpen(): void {
		if (this.closed) throw new Error('direct-funding peer messaging is closed');
	}
}
