/**
 * Watchtower client (LND altruist wtwire protocol).
 *
 * At every revocation the node hands us a justice context; we build one
 * encrypted blob per active tower session, persist it in an un-acked backlog,
 * and ship a StateUpdate. If a tower is offline the backlog survives restarts
 * and is drained on reconnect with exponential backoff. Fund safety: an
 * un-acked update is never dropped silently; every ship/ack transitions the
 * backlog and is logged.
 *
 * LND towers accept exactly one blob type per session, and key each session to
 * the pubkey of the CONNECTION it was created over (wtserver uses
 * NewSessionIDFromPubKey(peer.RemotePub())). A node with legacy, anchor and
 * taproot channels therefore runs one session SLOT per blob type against each
 * tower, each slot dialing with its own session key — mirroring lnd's wtclient,
 * which runs separate session queues for legacy/anchor/taproot. If a tower
 * rejects a blob type (e.g. no taproot support), those backups stay queued for
 * retry and every other slot keeps working.
 *
 * Only the client role is implemented (no server / reward sessions).
 */

import { EventEmitter } from 'events';
import { randomBytes } from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import { getPublicKey } from '../crypto/ecdh';
import {
	WtMessageType,
	WtFeatureBit,
	CreateSessionCode,
	StateUpdateCode,
	encodeInit,
	encodeCreateSession,
	decodeCreateSessionReply,
	encodeStateUpdate,
	decodeStateUpdateReply,
	decodeError
} from './wtwire';
import {
	buildJusticeBackup,
	blobTypeForChannel,
	IJusticeContext
} from './justice';
import { TowerConnection, parseTowerUri } from './tower-connection';
import {
	ITowerAddress,
	ITowerTransport,
	TowerTransportFactory,
	IWatchtowerSession,
	IWatchtowerUpdate,
	ITowerHealth
} from './types';
import { BlobType } from './blob';

/** Default session policy (wtpolicy.DefaultPolicy): altruist, reward 0. */
const DEFAULT_MAX_UPDATES = 1024;
const DEFAULT_SWEEP_FEE_RATE_SAT_PER_KW = 2500n;
const REPLY_TIMEOUT_MS = 30000;
const MIN_RECONNECT_MS = 1000;
const MAX_RECONNECT_MS = 5 * 60 * 1000;

/** Minimal persistence surface used by the client (implemented by SqliteStorage). */
export interface IWatchtowerStore {
	saveWatchtowerSession(session: IWatchtowerSession, sessionKey: Buffer): void;
	loadWatchtowerSessions(): Array<IWatchtowerSession & { sessionKey: Buffer }>;
	setWatchtowerSessionProgress(
		sessionId: string,
		seqNum: number,
		lastApplied: number
	): void;
	deleteWatchtowerTower(towerUri: string): void;
	addWatchtowerUpdate(update: IWatchtowerUpdate): number;
	loadPendingWatchtowerUpdates(): Array<IWatchtowerUpdate & { id: number }>;
	markWatchtowerUpdateAcked(id: number, seqNum: number): void;
}

export interface IWatchtowerClientOptions {
	/** Node identity private key (used as the Noise key for tower sessions). */
	localPrivateKey: Buffer;
	/** 32-byte genesis hash (internal byte order) for the configured network. */
	chainHash: Buffer;
	network: bitcoin.Network;
	towers?: string[];
	store?: IWatchtowerStore;
	transportFactory?: TowerTransportFactory;
	socks5Proxy?: { host: string; port: number };
	maxUpdates?: number;
	sweepFeeRateSatPerKw?: bigint;
	connectTimeoutMs?: number;
}

/** One per-blob-type session (and its dedicated tower connection). */
interface ISessionSlot {
	blobType: number;
	/** Noise key this slot's connection authenticates with. */
	transportKey: Buffer;
	transport: ITowerTransport | null;
	session: IWatchtowerSession | null;
	sessionKey: Buffer | null;
	initReceived: boolean;
	reconnectDelay: number;
	reconnectTimer: NodeJS.Timeout | null;
	/** One-shot reply resolver keyed by expected wtwire type. */
	pending: Map<number, (payload: Buffer) => void> | null;
	draining: boolean;
	negotiating: boolean;
	/** Tower rejected CreateSession for this blob type (cleared on reconnect). */
	rejected: boolean;
}

interface ITowerState {
	address: ITowerAddress;
	/** blob type -> session slot. */
	slots: Map<number, ISessionSlot>;
	/** In-memory mirror of persisted un-acked updates for this tower. */
	backlog: Array<IWatchtowerUpdate & { id: number }>;
	stopped: boolean;
}

export class WatchtowerClient extends EventEmitter {
	private readonly localPrivateKey: Buffer;
	private readonly chainHash: Buffer;
	private readonly store?: IWatchtowerStore;
	private readonly transportFactory: TowerTransportFactory;
	private readonly socks5Proxy?: { host: string; port: number };
	private readonly maxUpdates: number;
	private readonly sweepFeeRate: bigint;
	private readonly connectTimeoutMs: number;
	private readonly towers = new Map<string, ITowerState>();
	private started = false;

	constructor(opts: IWatchtowerClientOptions) {
		super();
		this.localPrivateKey = opts.localPrivateKey;
		this.chainHash = opts.chainHash;
		this.store = opts.store;
		this.socks5Proxy = opts.socks5Proxy;
		this.maxUpdates = opts.maxUpdates ?? DEFAULT_MAX_UPDATES;
		this.sweepFeeRate =
			opts.sweepFeeRateSatPerKw ?? DEFAULT_SWEEP_FEE_RATE_SAT_PER_KW;
		this.connectTimeoutMs = opts.connectTimeoutMs ?? 15000;
		this.transportFactory =
			opts.transportFactory ??
			((addr, transportKey): ITowerTransport =>
				new TowerConnection({
					localPrivateKey: transportKey ?? this.localPrivateKey,
					address: addr,
					connectTimeoutMs: this.connectTimeoutMs,
					socks5Proxy: this.socks5Proxy
				}));

		for (const uri of opts.towers ?? []) {
			this.registerTower(uri);
		}
	}

	/** True when at least one tower is configured. */
	get enabled(): boolean {
		return this.towers.size > 0;
	}

	/** Restore persisted sessions + backlog, then connect + drain. */
	async start(): Promise<void> {
		if (this.started) return;
		this.started = true;
		if (this.store) {
			for (const s of this.store.loadWatchtowerSessions()) {
				const state = this.towers.get(s.towerUri);
				if (!state) continue;
				const { sessionKey, ...session } = s;
				const slot = this.ensureSlot(state, session.blobType);
				// Keep the newest session per blob type (older rows are exhausted
				// predecessors left behind by key rotation).
				if (slot.session && slot.session.createdAt >= session.createdAt) {
					continue;
				}
				slot.session = session;
				slot.sessionKey = sessionKey;
				// Old-schema sessions were negotiated over the node-identity
				// connection; new ones are keyed to their own session key.
				slot.transportKey = session.dialsWithSessionKey
					? sessionKey
					: this.localPrivateKey;
			}
			for (const u of this.store.loadPendingWatchtowerUpdates()) {
				const state = this.towers.get(u.towerUri);
				if (!state) continue;
				state.backlog.push(u);
				this.ensureSlot(state, u.blobType);
			}
		}
		for (const state of this.towers.values()) {
			for (const slot of state.slots.values()) {
				this.connectSlot(state, slot);
			}
		}
	}

	stop(): void {
		this.started = false;
		for (const state of this.towers.values()) {
			state.stopped = true;
			for (const slot of state.slots.values()) {
				if (slot.reconnectTimer) clearTimeout(slot.reconnectTimer);
				slot.reconnectTimer = null;
				slot.transport?.close();
				slot.transport = null;
			}
		}
	}

	listTowers(): string[] {
		return [...this.towers.keys()];
	}

	/** Add a tower at runtime (and connect if already started). */
	addTower(uri: string): void {
		if (this.towers.has(uri)) return;
		const state = this.registerTower(uri);
		if (this.started) {
			for (const slot of state.slots.values()) {
				this.connectSlot(state, slot);
			}
		}
	}

	/** Remove a tower and delete its persisted sessions + backlog. */
	removeTower(uri: string): void {
		const state = this.towers.get(uri);
		if (!state) return;
		state.stopped = true;
		for (const slot of state.slots.values()) {
			if (slot.reconnectTimer) clearTimeout(slot.reconnectTimer);
			slot.transport?.close();
		}
		this.towers.delete(uri);
		this.store?.deleteWatchtowerTower(uri);
	}

	getHealth(): ITowerHealth[] {
		return [...this.towers.values()].map((s) => ({
			uri: s.address.uri,
			pubkey: s.address.pubkey,
			connected: [...s.slots.values()].some(
				(slot) => slot.transport?.isConnected() ?? false
			),
			sessions: [...s.slots.values()].filter((slot) => slot.session).length,
			pendingBacklog: s.backlog.filter((u) => !u.acked).length,
			lastAck: this.lastAckFor(s)
		}));
	}

	/**
	 * Build and ship a justice blob for a revoked commitment to every tower.
	 * Called by the node inside revoke_and_ack handling. Never throws to the
	 * caller: a failure to reach a tower keeps the update queued for retry.
	 */
	backupRevokedState(ctx: IJusticeContext): void {
		if (!this.enabled) return;
		const blobType = blobTypeForChannel(ctx.isAnchor, ctx.isTaproot ?? false);
		for (const state of this.towers.values()) {
			const slot = this.ensureSlot(state, blobType);
			if (this.started) this.connectSlot(state, slot);
			let hint: Buffer;
			let encryptedBlob: Buffer;
			let sweptSats: bigint;
			try {
				const policy = {
					blobType,
					sweepFeeRate: slot.session
						? BigInt(slot.session.sweepFeeRate)
						: this.sweepFeeRate
				};
				const backup = buildJusticeBackup(ctx, policy);
				hint = backup.hint;
				encryptedBlob = backup.encryptedBlob;
				sweptSats = backup.sweptSats;
			} catch (err) {
				// Fail loud: a breach we cannot punish must be visible, not silent.
				this.emitLog('backup_failed', {
					tower: state.address.uri,
					channelId: ctx.channelId,
					error: err instanceof Error ? err.message : String(err)
				});
				continue;
			}

			const update: IWatchtowerUpdate = {
				towerUri: state.address.uri,
				channelId: ctx.channelId,
				blobType,
				hint: hint.toString('hex'),
				encryptedBlob: encryptedBlob.toString('hex'),
				seqNum: 0,
				acked: false,
				createdAt: Date.now()
			};
			const id = this.store ? this.store.addWatchtowerUpdate(update) : -1;
			state.backlog.push({ ...update, id });
			this.emitLog('backup_queued', {
				tower: state.address.uri,
				channelId: ctx.channelId,
				blobType,
				hint: update.hint,
				sweptSats: sweptSats.toString()
			});
			void this.drainSlot(state, slot);
		}
	}

	private registerTower(uri: string): ITowerState {
		const address = parseTowerUri(uri);
		const state: ITowerState = {
			address,
			slots: new Map(),
			backlog: [],
			stopped: false
		};
		// Default slot: legacy altruist sessions are negotiated eagerly so the
		// tower relationship is proven before the first breach backup.
		this.ensureSlot(state, BlobType.ALTRUIST_COMMIT);
		this.towers.set(uri, state);
		return state;
	}

	private ensureSlot(state: ITowerState, blobType: number): ISessionSlot {
		let slot = state.slots.get(blobType);
		if (slot) return slot;
		slot = {
			blobType,
			// Each session dials with its own key: LND towers key the session to
			// the connection pubkey, so distinct sessions need distinct keys.
			transportKey: randomBytes(32),
			transport: null,
			session: null,
			sessionKey: null,
			initReceived: false,
			reconnectDelay: MIN_RECONNECT_MS,
			reconnectTimer: null,
			pending: null,
			draining: false,
			negotiating: false,
			rejected: false
		};
		state.slots.set(blobType, slot);
		return slot;
	}

	private connectSlot(state: ITowerState, slot: ISessionSlot): void {
		if (state.stopped || slot.transport) return;
		const transport = this.transportFactory(state.address, slot.transportKey);
		slot.transport = transport;
		slot.initReceived = false;
		slot.rejected = false;
		slot.pending = new Map();

		transport.on('message', (type: number, payload: Buffer) =>
			this.onMessage(state, slot, type, payload)
		);
		transport.on('error', (err: Error) => {
			this.emitLog('tower_error', {
				tower: state.address.uri,
				blobType: slot.blobType,
				error: err.message
			});
		});
		transport.on('close', () => this.onClose(state, slot));

		transport
			.connect()
			.then(() => this.onConnected(state, slot))
			.catch((err) => {
				this.emitLog('connect_failed', {
					tower: state.address.uri,
					error: err instanceof Error ? err.message : String(err)
				});
				this.onClose(state, slot);
			});
	}

	private onConnected(state: ITowerState, slot: ISessionSlot): void {
		// wtwire Init (type 600): advertise optional altruist/anchor/taproot
		// support + our chain. Optional bits are never rejected by towers that
		// don't know them (feature.ValidateRequired only gates required bits).
		const connFeatures = featureVector(
			WtFeatureBit.ALTRUIST_SESSIONS_OPTIONAL,
			WtFeatureBit.ANCHOR_COMMIT_OPTIONAL,
			WtFeatureBit.TAPROOT_COMMIT_OPTIONAL
		);
		try {
			slot.transport?.send(
				WtMessageType.INIT,
				encodeInit({ connFeatures, chainHash: this.chainHash })
			);
		} catch (err) {
			this.emitLog('init_send_failed', {
				tower: state.address.uri,
				error: err instanceof Error ? err.message : String(err)
			});
			return;
		}
		// Some towers gate on our Init before replying; proceed once we see theirs.
	}

	private onMessage(
		state: ITowerState,
		slot: ISessionSlot,
		type: number,
		payload: Buffer
	): void {
		if (type === WtMessageType.INIT) {
			slot.initReceived = true;
			// Reset backoff on a healthy handshake.
			slot.reconnectDelay = MIN_RECONNECT_MS;
			void this.ensureSessionAndDrain(state, slot);
			return;
		}
		if (type === WtMessageType.ERROR) {
			const err = decodeError(payload);
			this.emitLog('tower_wt_error', {
				tower: state.address.uri,
				blobType: slot.blobType,
				code: err.code
			});
			return;
		}
		const resolver = slot.pending?.get(type);
		if (resolver) {
			slot.pending?.delete(type);
			resolver(payload);
		}
	}

	private onClose(state: ITowerState, slot: ISessionSlot): void {
		slot.transport = null;
		slot.pending = null;
		slot.draining = false;
		slot.negotiating = false;
		if (state.stopped || !this.started) return;
		const delay = slot.reconnectDelay;
		slot.reconnectDelay = Math.min(delay * 2, MAX_RECONNECT_MS);
		slot.reconnectTimer = setTimeout(() => {
			slot.reconnectTimer = null;
			this.connectSlot(state, slot);
		}, delay);
	}

	private async ensureSessionAndDrain(
		state: ITowerState,
		slot: ISessionSlot
	): Promise<void> {
		try {
			if (!slot.session && !slot.rejected && !slot.negotiating) {
				await this.negotiateSession(state, slot);
			}
			await this.drainSlot(state, slot);
		} catch (err) {
			this.emitLog('session_error', {
				tower: state.address.uri,
				blobType: slot.blobType,
				error: err instanceof Error ? err.message : String(err)
			});
		}
	}

	private async negotiateSession(
		state: ITowerState,
		slot: ISessionSlot
	): Promise<void> {
		// The session is keyed (on the tower) to the connection's pubkey, so the
		// slot's transport key IS the session key.
		const sessionKey = slot.transportKey;
		const sessionId = getPublicKey(sessionKey).toString('hex');
		slot.negotiating = true;
		try {
			slot.transport?.send(
				WtMessageType.CREATE_SESSION,
				encodeCreateSession({
					blobType: slot.blobType,
					maxUpdates: this.maxUpdates,
					rewardBase: 0,
					rewardRate: 0,
					sweepFeeRate: this.sweepFeeRate
				})
			);
			const payload = await this.awaitReply(
				slot,
				WtMessageType.CREATE_SESSION_REPLY
			);
			const reply = decodeCreateSessionReply(payload);
			if (reply.code !== CreateSessionCode.OK) {
				// The tower answered but refused this session (e.g. code 64
				// REJECT_BLOB_TYPE from a tower without taproot support). Queued
				// updates of this blob type are NEVER dropped: they wait until a
				// capable session exists, while other blob types keep flowing.
				slot.rejected = true;
				this.emitLog('session_rejected', {
					tower: state.address.uri,
					blobType: slot.blobType,
					code: reply.code
				});
				return;
			}
			const session: IWatchtowerSession = {
				towerUri: state.address.uri,
				towerPubkey: state.address.pubkey,
				sessionId,
				blobType: slot.blobType,
				maxUpdates: this.maxUpdates,
				sweepFeeRate: this.sweepFeeRate.toString(),
				seqNum: 0,
				lastApplied: reply.lastApplied,
				createdAt: Date.now(),
				dialsWithSessionKey: true
			};
			slot.session = session;
			slot.sessionKey = sessionKey;
			this.store?.saveWatchtowerSession(session, sessionKey);
			this.emitLog('session_created', {
				tower: state.address.uri,
				blobType: slot.blobType,
				sessionId,
				maxUpdates: this.maxUpdates
			});
		} finally {
			slot.negotiating = false;
		}
	}

	private async drainSlot(
		state: ITowerState,
		slot: ISessionSlot
	): Promise<void> {
		if (slot.draining) return;
		if (!slot.transport?.isConnected() || !slot.initReceived) return;
		if (!slot.session) {
			// Lazily negotiate when the first update of this blob type arrives on
			// an already-connected slot (unless the tower already refused it).
			if (!slot.rejected && !slot.negotiating) {
				void this.ensureSessionAndDrain(state, slot);
			}
			return;
		}
		slot.draining = true;
		try {
			for (const update of state.backlog) {
				if (update.acked || update.blobType !== slot.blobType) continue;
				if (!slot.transport?.isConnected() || !slot.session) break;
				await this.shipUpdate(state, slot, update);
			}
		} finally {
			slot.draining = false;
		}
	}

	private async shipUpdate(
		state: ITowerState,
		slot: ISessionSlot,
		update: IWatchtowerUpdate & { id: number }
	): Promise<void> {
		const session = slot.session!;
		const seqNum = session.seqNum + 1;
		slot.transport?.send(
			WtMessageType.STATE_UPDATE,
			encodeStateUpdate({
				seqNum,
				lastApplied: session.lastApplied,
				isComplete: 0,
				hint: Buffer.from(update.hint, 'hex'),
				encryptedBlob: Buffer.from(update.encryptedBlob, 'hex')
			})
		);
		const payload = await this.awaitReply(
			slot,
			WtMessageType.STATE_UPDATE_REPLY
		);
		const reply = decodeStateUpdateReply(payload);
		if (reply.code === StateUpdateCode.OK) {
			session.seqNum = seqNum;
			session.lastApplied = reply.lastApplied;
			update.acked = true;
			update.seqNum = seqNum;
			this.store?.setWatchtowerSessionProgress(
				session.sessionId,
				seqNum,
				reply.lastApplied
			);
			this.store?.markWatchtowerUpdateAcked(update.id, seqNum);
			this.emitLog('update_acked', {
				tower: state.address.uri,
				channelId: update.channelId,
				blobType: update.blobType,
				seqNum,
				hint: update.hint
			});
			return;
		}
		if (reply.code === StateUpdateCode.CLIENT_BEHIND) {
			// Tower is ahead: resync our seq to its LastApplied and let the next
			// drain retry. The update stays un-acked (fund safety).
			session.seqNum = reply.lastApplied;
			session.lastApplied = reply.lastApplied;
			this.store?.setWatchtowerSessionProgress(
				session.sessionId,
				reply.lastApplied,
				reply.lastApplied
			);
			this.emitLog('update_client_behind', {
				tower: state.address.uri,
				lastApplied: reply.lastApplied
			});
			throw new Error('client behind; resynced');
		}
		if (reply.code === StateUpdateCode.MAX_UPDATES_EXCEEDED) {
			// Session is full: forget it and rotate the slot's key so the next
			// connection negotiates a genuinely fresh session (the tower keys
			// sessions to the connection pubkey, so reusing the key would just
			// collide with the exhausted session).
			slot.session = null;
			slot.sessionKey = null;
			slot.transportKey = randomBytes(32);
			this.emitLog('session_exhausted', {
				tower: state.address.uri,
				blobType: slot.blobType
			});
			slot.transport?.close();
			throw new Error('session max updates exceeded');
		}
		this.emitLog('update_rejected', {
			tower: state.address.uri,
			code: reply.code,
			hint: update.hint
		});
		throw new Error(`state update rejected (code ${reply.code})`);
	}

	private awaitReply(slot: ISessionSlot, type: number): Promise<Buffer> {
		return new Promise((resolve, reject) => {
			if (!slot.pending) {
				reject(new Error('watchtower: no active connection'));
				return;
			}
			const timer = setTimeout(() => {
				slot.pending?.delete(type);
				reject(new Error('watchtower: reply timeout'));
			}, REPLY_TIMEOUT_MS);
			slot.pending.set(type, (payload) => {
				clearTimeout(timer);
				resolve(payload);
			});
		});
	}

	private lastAckFor(state: ITowerState): number | null {
		let last: number | null = null;
		for (const u of state.backlog) {
			if (u.acked && (last === null || u.createdAt > last)) last = u.createdAt;
		}
		return last;
	}

	private emitLog(event: string, data: Record<string, unknown>): void {
		this.emit('log', { subsystem: 'watchtower', event, ...data });
	}
}

/** Encode a feature vector (lnwire RawFeatureVector body) from bit positions. */
function featureVector(...bits: number[]): Buffer {
	const maxByte = Math.max(...bits.map((b) => Math.floor(b / 8)));
	const buf = Buffer.alloc(maxByte + 1);
	for (const bit of bits) {
		buf[buf.length - 1 - Math.floor(bit / 8)] |= 1 << bit % 8;
	}
	return buf;
}
