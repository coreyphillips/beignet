/**
 * Watchtower client types: tower addressing, transport abstraction, session and
 * backlog persistence shapes, and health reporting.
 */

import { EventEmitter } from 'events';

/** A parsed `pubkey@host:port` tower address. */
export interface ITowerAddress {
	/** 33-byte compressed node pubkey, hex. */
	pubkey: string;
	host: string;
	port: number;
	/** Original URI as configured. */
	uri: string;
}

/**
 * Transport to a single tower. The real implementation runs the BOLT 8 Noise
 * handshake and wtwire framing over a TCP/Tor socket; tests inject an in-memory
 * fake. Emits `connected`, `message` (wtwire type + payload), `close`, `error`.
 */
export interface ITowerTransport extends EventEmitter {
	connect(): Promise<void>;
	/** Send an already-encoded wtwire message (type + payload). */
	send(type: number, payload: Buffer): void;
	close(): void;
	isConnected(): boolean;
}

/** Factory so the client can be tested against a fake transport. */
export type TowerTransportFactory = (addr: ITowerAddress) => ITowerTransport;

/** Persisted per-tower session state. */
export interface IWatchtowerSession {
	/** `pubkey@host:port`. */
	towerUri: string;
	/** Tower node pubkey, hex. */
	towerPubkey: string;
	/** 33-byte session key pubkey identifying this session, hex. */
	sessionId: string;
	blobType: number;
	maxUpdates: number;
	sweepFeeRate: string;
	/** Highest sequence number we have shipped and the tower has acked. */
	seqNum: number;
	/** Tower's last-applied sequence (from replies). */
	lastApplied: number;
	createdAt: number;
}

/** A pending (or shipped-but-unacked) state update for the retry backlog. */
export interface IWatchtowerUpdate {
	towerUri: string;
	channelId: string;
	/** 16-byte breach hint, hex. */
	hint: string;
	/** Encrypted justice blob, hex (encrypted at rest via ENCRYPTED_COLUMNS). */
	encryptedBlob: string;
	/** Sequence number assigned once bound to a session (0 = unassigned). */
	seqNum: number;
	acked: boolean;
	createdAt: number;
}

/** Per-tower health snapshot for getHealth / GET /watchtowers. */
export interface ITowerHealth {
	uri: string;
	pubkey: string;
	connected: boolean;
	sessions: number;
	/** Un-acked updates queued for this tower. */
	pendingBacklog: number;
	/** Unix ms of the last acked update, or null. */
	lastAck: number | null;
}
