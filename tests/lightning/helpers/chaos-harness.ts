/**
 * Recovery Phase 7 chaos harness (docs/RECOVERY-PROTOCOL.md section 9).
 *
 * Pattern: record-then-kill. A scenario first runs once with passive taps,
 * recording an ordered schedule of semantic kill labels (commit boundaries
 * and delivered sends; the quorum executor adds barrier coverage labels).
 * The scenario then re-runs from scratch once per label. At the armed label
 * the victim dies: the relay goes dead so no further bytes reach the peer,
 * the storage seals so a zombie stack frame cannot write what a killed
 * process could not have written, further commits are refused, and the node
 * object is destroyed once the synchronous turn unwinds. The same database
 * file is reopened by a fresh node, the peer reestablishes, and the verdict
 * oracle (chaos-oracle.ts) judges the outcome.
 *
 * Why an in-process kill is faithful at these boundaries: SQLite
 * transactions are atomic, so a kill anywhere inside the transaction IS the
 * pre-commit cell, and the loopback relay is synchronous, so "the peer got
 * exactly these bytes and nothing after them" is precise. What it cannot
 * reproduce (a genuinely dead process, real sockets, real fsync timing) is
 * covered by the process-level executor over the same matrix
 * (chaos-node-child.ts, SIGKILL).
 */

import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { expect } from 'chai';
import { LightningNode } from '../../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../../src/lightning/node/types';
import { Network } from '../../../src/lightning/invoice/types';
import {
	BITCOIN_CHAIN_HASH,
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../../src/lightning/keys/derivation';
import { IStorageBackend } from '../../../src/lightning/storage/types';
import { SqliteStorage } from '../../../src/lightning/storage/sqlite-storage';
import {
	serializeChannelState,
	serializePaymentInfo
} from '../../../src/lightning/storage/serialization';
import { getPublicKey } from '../../../src/lightning/crypto/ecdh';
import { MessageType } from '../../../src/lightning/message/types';
import { QUORUM_BARRIER_MESSAGE_TYPES } from '../../../src/lightning/channel/channel-actions';
import {
	IRecoveryCommitResult,
	RecoveryDurability,
	SafetyTransition
} from '../../../src/lightning/recovery/types';
import {
	IChannelAnnouncementMessage,
	IChannelUpdateMessage,
	encodeShortChannelId
} from '../../../src/lightning/gossip/types';

/* ------------------------------------------------------------------ */
/* Kill labels                                                        */
/* ------------------------------------------------------------------ */

/**
 * A kill label names one boundary in one run of one scenario:
 *
 *   pre-commit:<n>        the nth RecoveryManager.commit on the victim; the
 *                         transaction never runs, nothing reaches disk.
 *   post-commit:<n>       the nth commit ran and is durable; nothing after
 *                         it leaves the process.
 *   post-send:<TYPE>:<k>  the kth delivered victim-outbound message of that
 *                         wire type reached the peer; nothing after it did.
 *
 * The quorum executor (C3) extends the vocabulary with barrier coverage
 * labels keyed on frame sequence, never on receipt arrival order, because
 * receipt timing over real HTTP is not deterministic while frame coverage
 * is.
 */
export type KillLabel = string;

export const preCommitLabel = (n: number): KillLabel => `pre-commit:${n}`;
export const postCommitLabel = (n: number): KillLabel => `post-commit:${n}`;
export const postSendLabel = (type: number, k: number): KillLabel =>
	`post-send:${MessageType[type] ?? type}:${k}`;

/* ------------------------------------------------------------------ */
/* Kill switch                                                        */
/* ------------------------------------------------------------------ */

/**
 * The shared dead-switch. Everything that must stop at the kill point holds
 * a reference and consults `killed` synchronously, because the whole point
 * of half the matrix is that the boundary sits INSIDE a synchronous window.
 */
export class KillSwitch {
	killed = false;
	firedLabel: KillLabel | null = null;
	private readonly onKill: Array<() => void> = [];

	fire(label: KillLabel): void {
		if (this.killed) return;
		this.killed = true;
		this.firedLabel = label;
		for (const cb of this.onKill) cb();
	}

	notify(cb: () => void): void {
		this.onKill.push(cb);
	}
}

/* ------------------------------------------------------------------ */
/* Sealable storage                                                   */
/* ------------------------------------------------------------------ */

/**
 * Wraps a storage backend so the harness can seal it at the kill point. A
 * SIGKILLed process writes nothing after the kill, but an in-process zombie
 * stack frame would happily keep writing (markSent flips outbox
 * dispositions OUTSIDE RecoveryManager.commit, for one), so the seal is
 * what keeps the in-process executor honest. Sealed methods no-op; reads
 * return undefined, and whatever the zombie does with that is its own
 * problem because the harness swallows everything the dying turn throws.
 * `close` stays callable so victim.destroy() can release the file handle.
 */
export function sealableStorage(
	inner: IStorageBackend,
	kill: KillSwitch
): IStorageBackend {
	return new Proxy(inner, {
		get(target, prop, receiver): unknown {
			const value = Reflect.get(target, prop, receiver);
			if (typeof value !== 'function') return value;
			if (kill.killed && prop !== 'close') {
				return (): undefined => undefined;
			}
			return value.bind(target);
		}
	}) as IStorageBackend;
}

/* ------------------------------------------------------------------ */
/* Commit tap                                                         */
/* ------------------------------------------------------------------ */

/**
 * Intercepts RecoveryManager.commit on the victim, using the same cast the
 * existing tests use (funding-broadcast-retry.test.ts). In record mode it
 * logs pre-commit:<n> and post-commit:<n> around every invocation. Armed
 * with pre-commit:<n> it fires the kill INSTEAD of running the transaction;
 * armed with post-commit:<n> it runs the real transaction, fires the kill,
 * and returns the real result, so the dispatch loop continues into a relay
 * that is already dead. After the kill every later commit is refused: a
 * dead process appends nothing.
 */
export class ChaosCommitTap {
	commitCount = 0;
	private armed: KillLabel | null = null;
	private recording: KillLabel[] | null = null;
	private readonly kill: KillSwitch;

	constructor(node: LightningNode, kill: KillSwitch) {
		this.kill = kill;
		const holder = node as unknown as {
			recovery: {
				commit: (transition: SafetyTransition) => IRecoveryCommitResult;
			};
		};
		const real = holder.recovery.commit.bind(holder.recovery);
		holder.recovery.commit = (
			transition: SafetyTransition
		): IRecoveryCommitResult => {
			if (this.kill.killed) return this.refusal();
			const n = ++this.commitCount;
			this.recording?.push(preCommitLabel(n));
			if (this.armed === preCommitLabel(n)) {
				this.kill.fire(this.armed);
				return this.refusal();
			}
			const result = real(transition);
			this.recording?.push(postCommitLabel(n));
			if (this.armed === postCommitLabel(n)) {
				this.kill.fire(this.armed);
			}
			return result;
		};
	}

	record(into: KillLabel[]): void {
		this.recording = into;
	}

	arm(label: KillLabel): void {
		this.armed = label;
	}

	disarm(): void {
		this.armed = null;
	}

	private refusal(): IRecoveryCommitResult {
		return {
			committed: false,
			released: [],
			frameSequence: null,
			error: new Error('chaos: killed')
		};
	}
}

/* ------------------------------------------------------------------ */
/* Relay                                                              */
/* ------------------------------------------------------------------ */

export interface ICapturedMessage {
	from: string;
	to: string;
	type: number;
	bytes: Buffer;
	/** Victim commits completed at the moment this message was delivered. */
	commitCountAtDelivery: number;
	/** Ordinal among delivered victim-outbound messages of this type. */
	ordinal: number;
}

/**
 * The loopback wire, owned centrally instead of the copy-pasted
 * connectNodes listeners, so the harness can make it die. Delivery is
 * synchronous and nested, exactly like every existing loopback test.
 *
 * post-send kill semantics: the armed message itself IS delivered (the
 * bytes made it to the peer), but the relay is marked dead BEFORE the
 * delivery call, so every response the peer emits inside that call, and
 * everything else the victim tries to send afterwards, is dropped. That is
 * a SIGKILL between the socket write and the next read.
 */
export class ChaosRelay {
	readonly captured: ICapturedMessage[] = [];
	readonly droppedAfterKill: Array<{ from: string; type: number }> = [];
	private readonly nodes = new Map<string, LightningNode>();
	private readonly listeners = new Map<
		LightningNode,
		(pk: string, type: number, payload: Buffer) => void
	>();
	private readonly sendOrdinals = new Map<number, number>();
	private victimId: string | null = null;
	private armed: KillLabel | null = null;
	private recording: KillLabel[] | null = null;
	private kill: KillSwitch;
	private commitTap: ChaosCommitTap | null = null;
	private holding = false;
	private readonly held: Array<{
		from: string;
		to: string;
		type: number;
		payload: Buffer;
	}> = [];

	constructor(kill: KillSwitch) {
		this.kill = kill;
	}

	setVictim(nodeId: string, tap: ChaosCommitTap): void {
		this.victimId = nodeId;
		this.commitTap = tap;
	}

	record(into: KillLabel[]): void {
		this.recording = into;
	}

	arm(label: KillLabel): void {
		this.armed = label;
	}

	disarm(): void {
		this.armed = null;
	}

	register(node: LightningNode): void {
		const id = node.getNodeId();
		this.nodes.set(id, node);
		const listener = (pk: string, type: number, payload: Buffer): void => {
			this.route(id, pk, type, payload);
		};
		this.listeners.set(node, listener);
		node.on('message:outbound', listener);
	}

	/**
	 * Swap the restored victim in for the dead one. The dead node's listener
	 * is detached so a lingering emit from a zombie frame cannot double
	 * deliver (the dead-loopback-listener trap the phase 3 tests hit), and
	 * the relay comes back to life for the reestablish exchange.
	 */
	replaceNode(dead: LightningNode, restored: LightningNode): void {
		const listener = this.listeners.get(dead);
		if (listener) dead.removeListener('message:outbound', listener);
		this.listeners.delete(dead);
		this.register(restored);
	}

	/**
	 * A real connection delivers BOTH reestablish messages before any
	 * responses they trigger. hold() parks everything; drain() then
	 * delivers strictly FIFO, including whatever the deliveries enqueue,
	 * until the wire is quiet.
	 */
	hold(): void {
		this.holding = true;
	}

	drain(): void {
		while (this.held.length > 0) {
			const m = this.held.shift()!;
			this.deliver(m.from, m.to, m.type, m.payload);
		}
		this.holding = false;
	}

	private route(
		fromId: string,
		toId: string,
		type: number,
		payload: Buffer
	): void {
		if (this.holding) {
			this.held.push({ from: fromId, to: toId, type, payload });
			return;
		}
		this.deliver(fromId, toId, type, payload);
	}

	private deliver(
		fromId: string,
		toId: string,
		type: number,
		payload: Buffer
	): void {
		const to = this.nodes.get(toId);
		if (!to) return;
		if (this.kill.killed) {
			if (fromId === this.victimId || toId === this.victimId) {
				this.droppedAfterKill.push({ from: fromId, type });
				return;
			}
			// Messages between surviving nodes keep flowing.
			to.handlePeerMessage(fromId, type, payload);
			return;
		}
		if (fromId !== this.victimId) {
			to.handlePeerMessage(fromId, type, payload);
			return;
		}
		// A victim-outbound message while alive: count, capture, deliver.
		const ordinal = (this.sendOrdinals.get(type) ?? 0) + 1;
		this.sendOrdinals.set(type, ordinal);
		const label = postSendLabel(type, ordinal);
		this.captured.push({
			from: fromId,
			to: toId,
			type,
			bytes: Buffer.from(payload),
			commitCountAtDelivery: this.commitTap?.commitCount ?? 0,
			ordinal
		});
		this.recording?.push(label);
		if (this.armed === label) {
			// Dead first, then deliver: the armed bytes reach the peer, the
			// peer's synchronous responses find a dead wire.
			this.kill.fire(label);
			to.handlePeerMessage(fromId, type, payload);
			return;
		}
		to.handlePeerMessage(fromId, type, payload);
	}
}

/* ------------------------------------------------------------------ */
/* Node construction                                                  */
/* ------------------------------------------------------------------ */

export function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(`beignet-chaos-seed-${id}`)
		.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		keys.push(
			crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from([i]))
				.digest()
		);
	}
	return {
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

export interface IChaosNodeOptions {
	storage?: IStorageBackend;
	recovery?: INodeConfig['recovery'];
}

export function makeChaosNodeConfig(
	seedId: number,
	options: IChaosNodeOptions = {}
): INodeConfig {
	const seed = makeSeed(seedId);
	return {
		nodePrivateKey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from('node-identity'))
			.digest(),
		network: Network.REGTEST as Network,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([0]))
			.digest(),
		htlcBasepointSecret: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([4]))
			.digest(),
		storage: options.storage,
		recovery: options.recovery
	};
}

export function createChaosNode(
	seedId: number,
	options: IChaosNodeOptions = {}
): LightningNode {
	const node = new LightningNode(makeChaosNodeConfig(seedId, options));
	node.on('error', () => {});
	node.on('node:error', () => {});
	return node;
}

export function tempDb(prefix: string): string {
	return path.join(
		fs.mkdtempSync(path.join(os.tmpdir(), `beignet-${prefix}-`)),
		'node.db'
	);
}

/**
 * One deterministic key for every chaos database: the writer signing key
 * refuses plaintext storage at rest (phase 5's fail-closed rule), and the
 * restart must open with the SAME key the dead process wrote with.
 */
export const CHAOS_DB_KEY = crypto
	.createHash('sha256')
	.update('beignet-chaos-db-encryption-key')
	.digest();

export function openChaosStorage(dbPath: string): SqliteStorage {
	const storage = new SqliteStorage(dbPath, undefined, {
		encryptionKey: CHAOS_DB_KEY
	});
	storage.open();
	return storage;
}

export function openReadyChannel(
	opener: LightningNode,
	acceptor: LightningNode,
	amountSat = 1_000_000n
): Buffer {
	const channel = opener.openChannel(acceptor.getNodeId(), amountSat);
	const channelId = opener.createFunding(
		channel,
		crypto.randomBytes(32),
		0,
		crypto.randomBytes(64)
	)!;
	opener.handleFundingConfirmed(channelId);
	acceptor.handleFundingConfirmed(channelId);
	return channelId;
}

/**
 * Like openReadyChannel, but tolerant of a barrier in the opening path: a
 * quorum-mode ACCEPTOR parks its funding_signed until the frame behind it
 * is quorum durable, so the confirmation must wait for the opener to have
 * processed it, or the funding events land on a channel still waiting for
 * its signature. Identical to the synchronous helper in the modes where
 * nothing parks.
 */
export async function openReadyChannelChaos(
	env: IChaosEnv,
	opener: LightningNode,
	acceptor: LightningNode,
	amountSat = 1_000_000n
): Promise<Buffer> {
	const channel = opener.openChannel(acceptor.getNodeId(), amountSat);
	const channelId = opener.createFunding(
		channel,
		crypto.randomBytes(32),
		0,
		crypto.randomBytes(64)
	)!;
	await chaosWait(
		env,
		() =>
			opener.getChannelManager().listChannels()[0]?.getState() !==
			ChannelState.SENT_FUNDING_CREATED
	);
	opener.handleFundingConfirmed(channelId);
	acceptor.handleFundingConfirmed(channelId);
	return channelId;
}

/** Direct payer->payee graph so the payer can route over the one channel. */
export function buildDirectGraph(
	payer: LightningNode,
	payerSeedId: number,
	payeeSeedId: number
): void {
	const payerPubkey = getPublicKey(
		makeChaosNodeConfig(payerSeedId).nodePrivateKey
	);
	const payeePubkey = getPublicKey(
		makeChaosNodeConfig(payeeSeedId).nodePrivateKey
	);
	const scid = encodeShortChannelId({ block: 500, txIndex: 1, outputIndex: 0 });
	const payerIsNode1 = Buffer.compare(payerPubkey, payeePubkey) < 0;
	const announcement: IChannelAnnouncementMessage = {
		nodeSignature1: Buffer.alloc(64),
		nodeSignature2: Buffer.alloc(64),
		bitcoinSignature1: Buffer.alloc(64),
		bitcoinSignature2: Buffer.alloc(64),
		features: Buffer.alloc(0),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		nodeId1: payerIsNode1 ? payerPubkey : payeePubkey,
		nodeId2: payerIsNode1 ? payeePubkey : payerPubkey,
		bitcoinKey1: Buffer.alloc(33, 2),
		bitcoinKey2: Buffer.alloc(33, 3)
	};
	payer.getGraph().addChannelAnnouncement(announcement);
	const update: IChannelUpdateMessage = {
		signature: Buffer.alloc(64),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		timestamp: Math.floor(Date.now() / 1000),
		messageFlags: 1,
		channelFlags: 0,
		cltvExpiryDelta: 40,
		htlcMinimumMsat: 1000n,
		feeBaseMsat: 1000,
		feeProportionalMillionths: 1,
		htlcMaximumMsat: 1_000_000_000n
	};
	payer.getGraph().applyChannelUpdate(update);
	payer.getGraph().applyChannelUpdate({ ...update, channelFlags: 1 });
	payer.registerChannelScid(
		payer.getChannelManager().listChannels()[0].getChannelId()!,
		scid
	);
}

/** Double setImmediate: lets queued microtask/macrotask cascades finish. */
export async function settle(): Promise<void> {
	await new Promise<void>((resolve) => setImmediate(resolve));
	await new Promise<void>((resolve) => setImmediate(resolve));
}

/**
 * Wait for a condition OR the kill: a scenario step that completes
 * asynchronously (a quorum-mode payment finishing round by round as
 * receipts land) must wait kill-aware, because in a kill run the condition
 * legitimately never comes true. A timeout with the victim still alive is
 * a hard failure; a timeout after the kill is the kill doing its job.
 */
export async function chaosWait(
	env: IChaosEnv,
	condition: () => boolean,
	timeoutMs = 15_000
): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (!condition() && !env.kill.killed) {
		if (Date.now() > deadline) {
			throw new Error('chaosWait timed out with the victim alive');
		}
		await new Promise((resolve) => setTimeout(resolve, 10));
	}
}

/* ------------------------------------------------------------------ */
/* Table dump (byte-identity oracle input)                            */
/* ------------------------------------------------------------------ */

/**
 * Deterministic dump of the safety-critical tables (kept in sync with the
 * phase 2 original; row ids and created_at are nonsemantic).
 */
export function dumpTables(storage: IStorageBackend): string {
	const sortByFirst = <T extends { 0: string }>(rows: T[]): T[] =>
		rows.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
	const bigintSafe = (_key: string, value: unknown): unknown =>
		typeof value === 'bigint' ? `${value.toString()}n` : value;
	const dump = {
		channels: sortByFirst(
			storage
				.loadAllChannels()
				.map(
					(c) =>
						[
							c.channelId,
							JSON.stringify(serializeChannelState(c.state)),
							c.peerPubkey,
							String(storage.loadChannelKeyIndex(c.channelId))
						] as [string, string, string, string]
				)
		),
		monitors: sortByFirst(
			storage
				.loadAllChainMonitors()
				.map(
					(m) =>
						[m.channelId, JSON.stringify(m.state, bigintSafe)] as [
							string,
							string
						]
				)
		),
		preimages: sortByFirst(
			storage
				.loadAllPreimages()
				.map(
					(p) => [p.paymentHash, p.preimage.toString('hex')] as [string, string]
				)
		),
		payments: sortByFirst(
			storage
				.loadAllPayments()
				.map(
					(p) =>
						[
							p.paymentHash,
							JSON.stringify(serializePaymentInfo(p.payment))
						] as [string, string]
				)
		),
		htlcPaymentMappings: sortByFirst(
			storage
				.loadAllHtlcPaymentMappings()
				.map((m) => [m.key, m.paymentHashHex] as [string, string])
		),
		outbox: (storage.loadOutboxMessages?.() ?? []).map((row) => [
			row.peerId,
			row.channelId ?? '',
			String(row.messageType),
			row.wireMessage.toString('hex'),
			row.disposition,
			String(row.frameSequence)
		])
	};
	return JSON.stringify(dump);
}

/* ------------------------------------------------------------------ */
/* Scenario driver                                                    */
/* ------------------------------------------------------------------ */

export interface IChaosEnv {
	victim: LightningNode;
	victimSeedId: number;
	peers: LightningNode[];
	relay: ChaosRelay;
	commitTap: ChaosCommitTap;
	kill: KillSwitch;
	dbPath: string;
	mode: RecoveryDurability;
	channelId: Buffer | null;
	/**
	 * Scenario-owned state that must survive the kill: the env object is the
	 * one thing shared between the killed run() and the probe(), which runs
	 * on a FRESH scenario instance (a payment hash the probe must resolve,
	 * for example).
	 */
	scratch: Record<string, unknown>;
}

export interface IChaosScenario {
	name: string;
	/** Channel/graph setup; runs BEFORE recording or arming starts. */
	setup(env: IChaosEnv): Promise<void> | void;
	/** The protocol under test; kill labels exist only inside this window. */
	run(env: IChaosEnv): Promise<void> | void;
	/** Post-restart liveness probe (only called for exact-resume cells). */
	probe(env: IChaosEnv, restored: LightningNode): Promise<void> | void;
}

export interface IChaosEnvOptions {
	victimSeedId?: number;
	peerSeedIds?: number[];
	/** Extra recovery config merged over { enabled, durability } for the victim. */
	victimRecovery?: Partial<NonNullable<INodeConfig['recovery']>>;
	/** Peers get storage too when a scenario needs a journaled peer. */
	peerFactory?: (seedId: number) => LightningNode;
	/**
	 * Per-run recovery config, built over THAT run's storage: quorum mode
	 * needs a DurabilityBarrier wired at node construction, and the
	 * restored node needs its own over the reopened storage (a quorum
	 * journal refuses to start unbarriered). Wins over victimRecovery.
	 */
	victimRecoveryFactory?: (ctx: {
		storage: IStorageBackend;
		dbPath: string;
		phase: 'initial' | 'restored';
		kill: KillSwitch;
	}) => Promise<INodeConfig['recovery']> | INodeConfig['recovery'];
	/**
	 * Runs right after the restored node is constructed, before the
	 * reestablish: the place to kick replication on a gateless quorum node.
	 */
	afterRestart?: (
		env: IChaosEnv,
		restored: LightningNode
	) => Promise<void> | void;
	/** Per-run cleanup (guardian servers, etc.), errors swallowed. */
	teardown?: (env: IChaosEnv) => Promise<void> | void;
}

export interface IChaosRunResult {
	env: IChaosEnv;
	restored: LightningNode;
	restoredStorage: IStorageBackend;
	/** Disk state the kill left behind, dumped before the restored node ran. */
	postKillDump: string;
	firedLabel: KillLabel;
	broadcasts: Array<{ when: 'alive' | 'dead' | 'restored'; txHex: string }>;
	destroyAll: () => void;
}

export async function makeChaosEnv(
	mode: RecoveryDurability,
	options: IChaosEnvOptions
): Promise<IChaosEnv> {
	const victimSeedId = options.victimSeedId ?? 1;
	const peerSeedIds = options.peerSeedIds ?? [2];
	const kill = new KillSwitch();
	const dbPath = tempDb('chaos');
	const raw = openChaosStorage(dbPath);
	const storage = sealableStorage(raw, kill);
	const recovery = options.victimRecoveryFactory
		? await options.victimRecoveryFactory({
				storage,
				dbPath,
				phase: 'initial',
				kill
		  })
		: { enabled: true, durability: mode, ...options.victimRecovery };
	const victim = createChaosNode(victimSeedId, {
		storage,
		recovery
	});
	const peers = peerSeedIds.map(
		(id) => options.peerFactory?.(id) ?? createChaosNode(id)
	);
	const commitTap = new ChaosCommitTap(victim, kill);
	const relay = new ChaosRelay(kill);
	relay.setVictim(victim.getNodeId(), commitTap);
	relay.register(victim);
	for (const peer of peers) relay.register(peer);
	return {
		victim,
		victimSeedId,
		peers,
		relay,
		commitTap,
		kill,
		dbPath,
		mode,
		channelId: null,
		scratch: {}
	};
}

function watchBroadcasts(
	node: LightningNode,
	kill: KillSwitch,
	into: Array<{ when: 'alive' | 'dead' | 'restored'; txHex: string }>,
	restored: boolean
): void {
	node.on('broadcast:tx', (txHex: string) => {
		into.push({
			when: restored ? 'restored' : kill.killed ? 'dead' : 'alive',
			txHex
		});
	});
}

/**
 * One instrumented rehearsal. Returns the ordered kill labels this scenario
 * produces in this mode. The rehearsal also proves the run completes
 * un-killed, which every kill run then relies on for label determinism.
 */
export async function recordSchedule(
	mode: RecoveryDurability,
	scenarioFactory: () => IChaosScenario,
	options: IChaosEnvOptions = {}
): Promise<{ schedule: KillLabel[]; captured: ICapturedMessage[] }> {
	const scenario = scenarioFactory();
	const env = await makeChaosEnv(mode, options);
	const schedule: KillLabel[] = [];
	try {
		await scenario.setup(env);
		env.commitTap.record(schedule);
		env.relay.record(schedule);
		await scenario.run(env);
		await settle();
	} finally {
		env.victim.destroy();
		for (const peer of env.peers) peer.destroy();
		try {
			await options.teardown?.(env);
		} catch {
			// Teardown is best-effort by contract.
		}
	}
	return { schedule, captured: env.relay.captured };
}

/**
 * One kill run: rebuild the world, arm the label, drive the scenario, die
 * at the label, restart from the file, reestablish, hand back everything
 * the oracle needs. A label that never fires is a HARD failure: the
 * vocabulary came from a rehearsal of this exact scenario, so non-arrival
 * means the harness or the product regressed.
 */
export async function runKillPoint(
	mode: RecoveryDurability,
	scenarioFactory: () => IChaosScenario,
	label: KillLabel,
	options: IChaosEnvOptions = {}
): Promise<IChaosRunResult> {
	const scenario = scenarioFactory();
	const env = await makeChaosEnv(mode, options);
	const broadcasts: IChaosRunResult['broadcasts'] = [];
	watchBroadcasts(env.victim, env.kill, broadcasts, false);
	await scenario.setup(env);
	env.commitTap.arm(label);
	env.relay.arm(label);
	try {
		await scenario.run(env);
	} catch (err) {
		// The dying turn may unwind through zombie frames; only a run that
		// throws WITHOUT having been killed is a real failure.
		if (!env.kill.killed) throw err;
	}
	await settle();
	expect(
		env.kill.killed,
		`kill label ${label} never fired for ${scenario.name} in ${mode}`
	).to.equal(true);
	return restartVictim(env, options, broadcasts, label);
}

/**
 * The death-and-restart half of a kill run, usable on its own for
 * hand-driven cells (the quorum choreographies) whose kill is fired
 * manually rather than by an armed label: destroy the dead victim, let the
 * peer observe the disconnect, reopen the file the kill left behind, build
 * a fresh node on it, reconnect over the held FIFO, and hand back the
 * oracle's inputs.
 */
export async function restartVictim(
	env: IChaosEnv,
	options: IChaosEnvOptions = {},
	broadcasts: IChaosRunResult['broadcasts'] = [],
	label?: KillLabel
): Promise<IChaosRunResult> {
	// The label has done its work; disarm so the restored node's own
	// traffic (reestablish, replays) can never re-match it.
	env.commitTap.disarm();
	env.relay.disarm();

	// The victim is dead. Its peer observes the disconnect the way a real
	// TCP peer would.
	env.victim.destroy();
	const victimId = env.victim.getNodeId();
	for (const peer of env.peers) {
		peer.getChannelManager().handlePeerDisconnected(victimId);
	}

	// Reopen the file the kill left behind and restart on it.
	const restoredRaw = openChaosStorage(env.dbPath);
	const postKillDump = dumpTables(restoredRaw);
	const restoredKill = new KillSwitch();
	const restoredStorage = sealableStorage(restoredRaw, restoredKill);
	const recovery = options.victimRecoveryFactory
		? await options.victimRecoveryFactory({
				storage: restoredStorage,
				dbPath: env.dbPath,
				phase: 'restored',
				kill: restoredKill
		  })
		: {
				enabled: true,
				durability: env.mode,
				...options.victimRecovery
		  };
	const restored = createChaosNode(env.victimSeedId, {
		storage: restoredStorage,
		recovery
	});
	watchBroadcasts(restored, env.kill, broadcasts, true);
	env.relay.replaceNode(env.victim, restored);
	env.kill.killed = false;
	await options.afterRestart?.(env, restored);

	// A real connection delivers BOTH reestablish messages before any
	// responses they trigger, so hold a FIFO until both sides sent theirs.
	await reestablishFifo(env.relay, restored, env.peers[0]);
	await settle();

	return {
		env,
		restored,
		restoredStorage,
		postKillDump,
		firedLabel: env.kill.firedLabel ?? label ?? 'manual',
		broadcasts,
		destroyAll: (): void => {
			restored.destroy();
			for (const peer of env.peers) peer.destroy();
		}
	};
}

/**
 * The both-reestablishes-before-responses FIFO from the flagship guardian
 * acceptance test, hoisted onto the relay: hold the wire, let both sides
 * send their channel_reestablish, then drain strictly in order, exactly
 * what a real socket pair delivers.
 */
export async function reestablishFifo(
	relay: ChaosRelay,
	a: LightningNode,
	b: LightningNode
): Promise<void> {
	relay.hold();
	a.getChannelManager().handlePeerReconnected(b.getNodeId());
	b.getChannelManager().handlePeerReconnected(a.getNodeId());
	relay.drain();
	await settle();
}

export type ChaosVerdict = 'exact-resume' | 'safe-dlp' | 'skip';

/**
 * Record once, then kill at every label. `expected` maps a label to its
 * verdict; the oracle assertion and (for exact resumption) the scenario's
 * probe run against every non-skipped cell. Failure messages carry the
 * label, so one failing cell names its exact boundary.
 */
export async function runKillMatrix(
	mode: RecoveryDurability,
	scenarioFactory: () => IChaosScenario,
	expected: (label: KillLabel, schedule: KillLabel[]) => ChaosVerdict,
	assertOutcome: (
		result: IChaosRunResult,
		verdict: Exclude<ChaosVerdict, 'skip'>
	) => Promise<void> | void,
	options: IChaosEnvOptions = {}
): Promise<{ schedule: KillLabel[]; executed: number }> {
	const { schedule, captured } = await recordSchedule(
		mode,
		scenarioFactory,
		options
	);
	expect(
		schedule.length,
		'rehearsal recorded no kill labels'
	).to.be.greaterThan(0);
	// The structural invariant rides every rehearsal for free: the cell
	// "kill after send, before its commit" must not exist to enumerate.
	assertNoGatedSendBeforeCommit(schedule, captured);
	let executed = 0;
	for (const label of schedule) {
		const verdict = expected(label, schedule);
		if (verdict === 'skip') continue;
		const result = await runKillPoint(mode, scenarioFactory, label, options);
		try {
			if (verdict === 'exact-resume') {
				await scenarioFactory().probe(result.env, result.restored);
			}
			await assertOutcome(result, verdict);
		} catch (err) {
			const reason = err instanceof Error ? err.message : String(err);
			throw new Error(
				`chaos cell failed [${
					scenarioFactory().name
				} / ${mode} / ${label}]: ${reason}`
			);
		} finally {
			result.destroyAll();
			try {
				await options.teardown?.(result.env);
			} catch {
				// Teardown is best-effort by contract.
			}
		}
		executed++;
	}
	return { schedule, executed };
}

/* ------------------------------------------------------------------ */
/* Structural schedule invariants                                     */
/* ------------------------------------------------------------------ */

/**
 * The cell the matrix does NOT contain, proven on every recorded schedule:
 * a gated wire message delivered before any commit completed. Persist
 * before send is structural in every mode, so "kill after send, before its
 * commit" cannot exist. The per-delivery capture additionally lets a
 * scenario assert exact pairings when it knows its own shape.
 */
export function assertNoGatedSendBeforeCommit(
	schedule: KillLabel[],
	captured: ICapturedMessage[]
): void {
	let commitsSeen = 0;
	for (const label of schedule) {
		if (label.startsWith('post-commit:')) commitsSeen++;
		if (label.startsWith('post-send:')) {
			const typeName = label.split(':')[1];
			const type = MessageType[typeName as keyof typeof MessageType];
			if (typeof type === 'number' && QUORUM_BARRIER_MESSAGE_TYPES.has(type)) {
				expect(
					commitsSeen,
					`gated ${typeName} delivered before any commit completed`
				).to.be.greaterThan(0);
			}
		}
	}
	for (const message of captured) {
		if (QUORUM_BARRIER_MESSAGE_TYPES.has(message.type)) {
			expect(
				message.commitCountAtDelivery,
				`gated ${MessageType[message.type]} delivered with zero commits`
			).to.be.greaterThan(0);
		}
	}
}
