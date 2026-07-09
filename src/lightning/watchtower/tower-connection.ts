/**
 * BOLT 8 Noise transport to a single watchtower.
 *
 * Towers speak the LND wtwire protocol (Init type 600) INSTEAD of BOLT 1 init
 * (type 16), so the normal Peer class cannot be reused; this drives the Noise
 * handshake and framing directly, then exchanges raw wtwire messages. Framing
 * mirrors Peer.processReadBuffer (18-byte encrypted length prefix, body + MAC).
 */

import * as net from 'net';
import { EventEmitter } from 'events';
import { SocksClient } from 'socks';
import { createInitiatorHandshake } from '../transport/noise';
import { TransportCipher } from '../transport/cipher';
import { encodeMessage, decodeMessage } from '../message/codec';
import { ITowerAddress, ITowerTransport } from './types';

const ENCRYPTED_LENGTH_SIZE = 18;
const MAC_SIZE = 16;
const MAX_READ_BUFFER = 5 * 1024 * 1024;
const ACT_TWO_LENGTH = 50;
const DEFAULT_TOR_PROXY = { host: '127.0.0.1', port: 9050 };

export interface ITowerConnectionOptions {
	/** Our node identity private key (same key used for peer Noise). */
	localPrivateKey: Buffer;
	address: ITowerAddress;
	connectTimeoutMs?: number;
	/** SOCKS5 proxy for outbound (e.g. Tor). Auto-used for .onion when unset. */
	socks5Proxy?: { host: string; port: number };
}

export class TowerConnection extends EventEmitter implements ITowerTransport {
	private readonly localPrivateKey: Buffer;
	private readonly address: ITowerAddress;
	private readonly connectTimeoutMs: number;
	private readonly socks5Proxy?: { host: string; port: number };
	private socket: net.Socket | null = null;
	private transport: TransportCipher | null = null;
	private readBuffer = Buffer.alloc(0);
	private pendingBodyLength = -1;
	private connected = false;

	constructor(opts: ITowerConnectionOptions) {
		super();
		this.localPrivateKey = opts.localPrivateKey;
		this.address = opts.address;
		this.connectTimeoutMs = opts.connectTimeoutMs ?? 15000;
		this.socks5Proxy =
			opts.socks5Proxy ??
			(opts.address.host.endsWith('.onion') ? DEFAULT_TOR_PROXY : undefined);
	}

	isConnected(): boolean {
		return this.connected;
	}

	async connect(): Promise<void> {
		const socket = await this.openSocket();
		this.socket = socket;

		const handshake = createInitiatorHandshake(
			this.localPrivateKey,
			Buffer.from(this.address.pubkey, 'hex')
		);
		socket.write(handshake.act1);
		const act2 = await this.readExact(socket, ACT_TWO_LENGTH);
		handshake.processAct2(act2);
		socket.write(handshake.createAct3());
		this.transport = handshake.deriveTransport();
		this.connected = true;

		socket.on('data', (data: Buffer) => this.onData(data));
		socket.on('close', () => {
			this.connected = false;
			this.emit('close');
		});
		socket.on('error', (err) => this.emit('error', err));

		// Drain any bytes that arrived during the handshake reads.
		if (this.readBuffer.length > 0) {
			this.processReadBuffer();
		}
		this.emit('connected');
	}

	send(type: number, payload: Buffer): void {
		if (!this.transport || !this.socket) {
			throw new Error('watchtower: transport not connected');
		}
		this.socket.write(
			this.transport.encryptPacket(encodeMessage(type, payload))
		);
	}

	close(): void {
		this.connected = false;
		if (this.socket) {
			this.socket.destroy();
			this.socket = null;
		}
	}

	private onData(data: Buffer): void {
		this.readBuffer = Buffer.concat([this.readBuffer, data]);
		if (this.readBuffer.length > MAX_READ_BUFFER) {
			this.emit('error', new Error('watchtower: read buffer overflow'));
			this.close();
			return;
		}
		this.processReadBuffer();
	}

	private processReadBuffer(): void {
		// eslint-disable-next-line no-constant-condition
		while (true) {
			if (this.pendingBodyLength === -1) {
				if (this.readBuffer.length < ENCRYPTED_LENGTH_SIZE) {
					return;
				}
				const encLen = this.readBuffer.subarray(0, ENCRYPTED_LENGTH_SIZE);
				this.readBuffer = this.readBuffer.subarray(ENCRYPTED_LENGTH_SIZE);
				try {
					this.pendingBodyLength = this.transport!.decryptLength(encLen);
				} catch (err) {
					this.emit('error', err as Error);
					this.close();
					return;
				}
			}
			const needed = this.pendingBodyLength + MAC_SIZE;
			if (this.readBuffer.length < needed) {
				return;
			}
			const encBody = this.readBuffer.subarray(0, needed);
			this.readBuffer = this.readBuffer.subarray(needed);
			this.pendingBodyLength = -1;
			try {
				const body = this.transport!.decryptBody(encBody);
				const decoded = decodeMessage(body);
				this.emit('message', decoded.type, decoded.payload);
			} catch (err) {
				this.emit('error', err as Error);
				this.close();
				return;
			}
		}
	}

	private async openSocket(): Promise<net.Socket> {
		if (this.socks5Proxy) {
			const { socket } = await SocksClient.createConnection({
				proxy: {
					host: this.socks5Proxy.host,
					port: this.socks5Proxy.port,
					type: 5
				},
				command: 'connect',
				destination: { host: this.address.host, port: this.address.port },
				timeout: this.connectTimeoutMs
			});
			return socket as net.Socket;
		}
		return new Promise((resolve, reject) => {
			const socket = net.connect(
				{ host: this.address.host, port: this.address.port },
				() => {
					socket.removeListener('error', reject);
					resolve(socket);
				}
			);
			socket.once('error', reject);
			socket.setTimeout(this.connectTimeoutMs, () => {
				socket.destroy();
				reject(new Error('watchtower: connect timeout'));
			});
		});
	}

	/** Read exactly `n` bytes for the fixed-size handshake acts. */
	private readExact(socket: net.Socket, n: number): Promise<Buffer> {
		return new Promise((resolve, reject) => {
			const tryRead = (): void => {
				if (this.readBuffer.length >= n) {
					const out = this.readBuffer.subarray(0, n);
					this.readBuffer = this.readBuffer.subarray(n);
					socket.removeListener('data', onData);
					socket.removeListener('error', onErr);
					resolve(out);
				}
			};
			const onData = (d: Buffer): void => {
				this.readBuffer = Buffer.concat([this.readBuffer, d]);
				tryRead();
			};
			const onErr = (err: Error): void => {
				socket.removeListener('data', onData);
				reject(err);
			};
			socket.on('data', onData);
			socket.once('error', onErr);
			tryRead();
		});
	}
}

/** Parse a `pubkey@host:port` tower URI. */
export function parseTowerUri(uri: string): ITowerAddress {
	const at = uri.indexOf('@');
	if (at < 0) {
		throw new Error(`watchtower: invalid tower URI (missing @): ${uri}`);
	}
	const pubkey = uri.slice(0, at).toLowerCase();
	if (!/^[0-9a-f]{66}$/.test(pubkey)) {
		throw new Error(`watchtower: invalid tower pubkey in URI: ${uri}`);
	}
	const hostPort = uri.slice(at + 1);
	const lastColon = hostPort.lastIndexOf(':');
	if (lastColon < 0) {
		throw new Error(`watchtower: invalid tower URI (missing port): ${uri}`);
	}
	const host = hostPort.slice(0, lastColon);
	const port = parseInt(hostPort.slice(lastColon + 1), 10);
	if (!host || !Number.isInteger(port) || port <= 0 || port > 65535) {
		throw new Error(`watchtower: invalid tower host/port in URI: ${uri}`);
	}
	return { pubkey, host, port, uri };
}
