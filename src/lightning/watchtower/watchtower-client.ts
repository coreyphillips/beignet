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

interface ITowerState {
	address: ITowerAddress;
	transport: ITowerTransport | null;
	session: IWatchtowerSession | null;
	sessionKey: Buffer | null;
	/** In-memory mirror of persisted un-acked updates for this tower. */
	backlog: Array<IWatchtowerUpdate & { id: number }>;
	initReceived: boolean;
	reconnectDelay: number;
	reconnectTimer: NodeJS.Timeout | null;
	/** One-shot reply resolver keyed by expected wtwire type. */
	pending: Map<number, (payload: Buffer) => void> | null;
	draining: boolean;
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
			((addr): ITowerTransport =>
				new TowerConnection({
					localPrivateKey: this.localPrivateKey,
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
				if (state) {
					const { sessionKey, ...session } = s;
					state.session = session;
					state.sessionKey = sessionKey;
				}
			}
			for (const u of this.store.loadPendingWatchtowerUpdates()) {
				const state = this.towers.get(u.towerUri);
				if (state) state.backlog.push(u);
			}
		}
		for (const state of this.towers.values()) {
			this.connectTower(state);
		}
	}

	stop(): void {
		this.started = false;
		for (const state of this.towers.values()) {
			state.stopped = true;
			if (state.reconnectTimer) clearTimeout(state.reconnectTimer);
			state.reconnectTimer = null;
			state.transport?.close();
			state.transport = null;
		}
	}

	listTowers(): string[] {
		return [...this.towers.keys()];
	}

	/** Add a tower at runtime (and connect if already started). */
	addTower(uri: string): void {
		if (this.towers.has(uri)) return;
		const state = this.registerTower(uri);
		if (this.started) this.connectTower(state);
	}

	/** Remove a tower and delete its persisted sessions + backlog. */
	removeTower(uri: string): void {
		const state = this.towers.get(uri);
		if (!state) return;
		state.stopped = true;
		if (state.reconnectTimer) clearTimeout(state.reconnectTimer);
		state.transport?.close();
		this.towers.delete(uri);
		this.store?.deleteWatchtowerTower(uri);
	}

	getHealth(): ITowerHealth[] {
		return [...this.towers.values()].map((s) => ({
			uri: s.address.uri,
			pubkey: s.address.pubkey,
			connected: s.transport?.isConnected() ?? false,
			sessions: s.session ? 1 : 0,
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
		for (const state of this.towers.values()) {
			let hint: Buffer;
			let encryptedBlob: Buffer;
			let sweptSats: bigint;
			try {
				const policy = {
					blobType: blobTypeForChannel(ctx.isAnchor),
					sweepFeeRate: state.session
						? BigInt(state.session.sweepFeeRate)
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
				hint: update.hint,
				sweptSats: sweptSats.toString()
			});
			void this.drainBacklog(state);
		}
	}

	private registerTower(uri: string): ITowerState {
		const address = parseTowerUri(uri);
		const state: ITowerState = {
			address,
			transport: null,
			session: null,
			sessionKey: null,
			backlog: [],
			initReceived: false,
			reconnectDelay: MIN_RECONNECT_MS,
			reconnectTimer: null,
			pending: null,
			draining: false,
			stopped: false
		};
		this.towers.set(uri, state);
		return state;
	}

	private connectTower(state: ITowerState): void {
		if (state.stopped || state.transport) return;
		const transport = this.transportFactory(state.address);
		state.transport = transport;
		state.initReceived = false;
		state.pending = new Map();

		transport.on('message', (type: number, payload: Buffer) =>
			this.onMessage(state, type, payload)
		);
		transport.on('error', (err: Error) => {
			this.emitLog('tower_error', {
				tower: state.address.uri,
				error: err.message
			});
		});
		transport.on('close', () => this.onClose(state));

		transport
			.connect()
			.then(() => this.onConnected(state))
			.catch((err) => {
				this.emitLog('connect_failed', {
					tower: state.address.uri,
					error: err instanceof Error ? err.message : String(err)
				});
				this.onClose(state);
			});
	}

	private onConnected(state: ITowerState): void {
		// wtwire Init (type 600): advertise altruist-session support + our chain.
		const connFeatures = featureVector(WtFeatureBit.ALTRUIST_SESSIONS_OPTIONAL);
		try {
			state.transport?.send(
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

	private onMessage(state: ITowerState, type: number, payload: Buffer): void {
		if (type === WtMessageType.INIT) {
			state.initReceived = true;
			// Reset backoff on a healthy handshake.
			state.reconnectDelay = MIN_RECONNECT_MS;
			void this.ensureSessionAndDrain(state);
			return;
		}
		if (type === WtMessageType.ERROR) {
			const err = decodeError(payload);
			this.emitLog('tower_wt_error', {
				tower: state.address.uri,
				code: err.code
			});
			return;
		}
		const resolver = state.pending?.get(type);
		if (resolver) {
			state.pending?.delete(type);
			resolver(payload);
		}
	}

	private onClose(state: ITowerState): void {
		state.transport = null;
		state.pending = null;
		state.draining = false;
		if (state.stopped || !this.started) return;
		const delay = state.reconnectDelay;
		state.reconnectDelay = Math.min(delay * 2, MAX_RECONNECT_MS);
		state.reconnectTimer = setTimeout(() => {
			state.reconnectTimer = null;
			this.connectTower(state);
		}, delay);
	}

	private async ensureSessionAndDrain(state: ITowerState): Promise<void> {
		try {
			if (!state.session) {
				await this.negotiateSession(state);
			}
			await this.drainBacklog(state);
		} catch (err) {
			this.emitLog('session_error', {
				tower: state.address.uri,
				error: err instanceof Error ? err.message : String(err)
			});
		}
	}

	private async negotiateSession(state: ITowerState): Promise<void> {
		// Each session uses a distinct client Noise key; its pubkey is the id.
		const sessionKey = randomBytes(32);
		const sessionId = getPublicKey(sessionKey).toString('hex');
		const blobType = blobTypeForChannel(false);
		state.transport?.send(
			WtMessageType.CREATE_SESSION,
			encodeCreateSession({
				blobType,
				maxUpdates: this.maxUpdates,
				rewardBase: 0,
				rewardRate: 0,
				sweepFeeRate: this.sweepFeeRate
			})
		);
		const payload = await this.awaitReply(
			state,
			WtMessageType.CREATE_SESSION_REPLY
		);
		const reply = decodeCreateSessionReply(payload);
		if (reply.code !== CreateSessionCode.OK) {
			throw new Error(`create session rejected (code ${reply.code})`);
		}
		const session: IWatchtowerSession = {
			towerUri: state.address.uri,
			towerPubkey: state.address.pubkey,
			sessionId,
			blobType,
			maxUpdates: this.maxUpdates,
			sweepFeeRate: this.sweepFeeRate.toString(),
			seqNum: 0,
			lastApplied: reply.lastApplied,
			createdAt: Date.now()
		};
		state.session = session;
		state.sessionKey = sessionKey;
		this.store?.saveWatchtowerSession(session, sessionKey);
		this.emitLog('session_created', {
			tower: state.address.uri,
			sessionId,
			maxUpdates: this.maxUpdates
		});
	}

	private async drainBacklog(state: ITowerState): Promise<void> {
		if (state.draining) return;
		if (!state.transport?.isConnected() || !state.initReceived) return;
		if (!state.session) return;
		state.draining = true;
		try {
			for (const update of state.backlog) {
				if (update.acked) continue;
				if (!state.transport?.isConnected() || !state.session) break;
				await this.shipUpdate(state, update);
			}
		} finally {
			state.draining = false;
		}
	}

	private async shipUpdate(
		state: ITowerState,
		update: IWatchtowerUpdate & { id: number }
	): Promise<void> {
		const session = state.session!;
		const seqNum = session.seqNum + 1;
		state.transport?.send(
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
			state,
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
			// Session is full: forget it so the next drain negotiates a fresh one.
			state.session = null;
			state.sessionKey = null;
			this.emitLog('session_exhausted', { tower: state.address.uri });
			throw new Error('session max updates exceeded');
		}
		this.emitLog('update_rejected', {
			tower: state.address.uri,
			code: reply.code,
			hint: update.hint
		});
		throw new Error(`state update rejected (code ${reply.code})`);
	}

	private awaitReply(state: ITowerState, type: number): Promise<Buffer> {
		return new Promise((resolve, reject) => {
			if (!state.pending) {
				reject(new Error('watchtower: no active connection'));
				return;
			}
			const timer = setTimeout(() => {
				state.pending?.delete(type);
				reject(new Error('watchtower: reply timeout'));
			}, REPLY_TIMEOUT_MS);
			state.pending.set(type, (payload) => {
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

/** Encode a single-bit feature vector (lnwire RawFeatureVector body). */
function featureVector(bit: number): Buffer {
	const byteIndex = Math.floor(bit / 8);
	const buf = Buffer.alloc(byteIndex + 1);
	buf[buf.length - 1 - byteIndex] = 1 << bit % 8;
	return buf;
}
