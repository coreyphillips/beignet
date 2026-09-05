/**
 * Shared world for the async receive suites (issues #708 and #709).
 *
 * Alice -> LSP -> Carol. Carol's invoice carries a blinded path through the
 * LSP marked hold_htlc, so the LSP parks Alice's HTLC in its held-forward
 * ledger until Carol signs a release capability. The LSP runs on SQLite so a
 * restart is a new process over the same file, and its storage adapter can
 * be told to "crash" at a chosen commit boundary (writes stop landing, the
 * wire goes dead), exactly like the recovery suites simulate a kill.
 *
 * The LSP runs the async receive service (issue #709) unless a suite says
 * otherwise, and Carol registers with it once the channel is up; the harness
 * has no peer manager, so what the LSP advertises reaches Carol's graph as a
 * verified node_announcement carrying the LSP's real feature set.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { LightningNode } from '../../../src/lightning/node/lightning-node';
import { Network } from '../../../src/lightning/invoice/types';
import { INodeConfig } from '../../../src/lightning/node/types';
import { SqliteStorage } from '../../../src/lightning/storage/sqlite-storage';
import { IStorageBackend } from '../../../src/lightning/storage/types';
import { getPublicKey } from '../../../src/lightning/crypto/ecdh';
import { IChannelBasepoints } from '../../../src/lightning/keys/derivation';
import {
	BITCOIN_CHAIN_HASH,
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	HtlcState,
	REGTEST_CHAIN_HASH
} from '../../../src/lightning/channel/types';
import { IChannelState } from '../../../src/lightning/channel/channel-state';
import { encodeShortChannelId } from '../../../src/lightning/gossip/types';
import { findRouteToBlindedPath } from '../../../src/lightning/gossip/pathfinding';
import { decode as decodeInvoice } from '../../../src/lightning/invoice/decode';
import { MessageType } from '../../../src/lightning/message/types';
import { IHeldForwardRecord } from '../../../src/lightning/async-payments/held-forward-ledger';
import {
	IAsyncReceiveServiceConfig,
	IHeldForwardNotice,
	RELEASE_HELD_HTLC_TLV_TYPE
} from '../../../src/lightning/async-payments/types';

export const ALICE_SEED = 91;
export const LSP_SEED = 92;
export const CAROL_SEED = 93;
export const MALLORY_SEED = 94;

export function makeSeed(id: number): Buffer {
	return crypto.createHash('sha256').update(`held-forward-seed-${id}`).digest();
}

export function makeBasepoints(seed: Buffer): IChannelBasepoints {
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

export function nodePrivkey(seedId: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(makeSeed(seedId))
		.update(Buffer.from('node-identity'))
		.digest();
}

export function makeNodeConfig(
	seedId: number,
	storage?: IStorageBackend,
	extra: Partial<INodeConfig> = {}
): INodeConfig {
	const seed = makeSeed(seedId);
	return {
		nodePrivateKey: nodePrivkey(seedId),
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
		storage,
		...extra
	};
}

export function createNode(
	seedId: number,
	storage?: IStorageBackend,
	extra: Partial<INodeConfig> = {}
): LightningNode {
	const node = new LightningNode(makeNodeConfig(seedId, storage, extra));
	node.on('error', () => {});
	node.on('node:error', () => {});
	return node;
}

// ─────────────── Crash-injecting storage ───────────────

export interface IWrite {
	method: string;
	args: unknown[];
}

export interface ICrashPlan {
	/** Judged over the writes of ONE storage transaction. */
	when: (writes: IWrite[]) => boolean;
	/**
	 * before-commit: the transaction rolls back and the process is dead
	 * (nothing of it lands). after-commit: it lands, then the process dies.
	 */
	phase: 'before-commit' | 'after-commit';
}

/**
 * Storage that dies at a chosen commit boundary. Dead storage accepts no
 * writes and answers no reads (a killed process does neither); close stays
 * callable so destroy() can release the file. Writes issued outside any
 * transaction are recorded against a transaction of their own.
 */
export function crashingStorage(
	inner: IStorageBackend,
	dead: { val: boolean },
	plan: ICrashPlan | null
): IStorageBackend {
	let current: IWrite[] | null = null;
	let fired = false;
	const judgeAfter = (writes: IWrite[]): void => {
		if (plan && !fired && plan.phase === 'after-commit' && plan.when(writes)) {
			fired = true;
			dead.val = true;
		}
	};
	return new Proxy(inner, {
		get(target, prop, receiver): unknown {
			const value = Reflect.get(target, prop, receiver);
			if (typeof value !== 'function') return value;
			if (dead.val && prop !== 'close') {
				return (): undefined => undefined;
			}
			if (prop === 'transaction') {
				return <T>(fn: () => T): T => {
					const outer = current;
					const writes: IWrite[] = outer ?? [];
					current = writes;
					try {
						const out = (target.transaction as <U>(f: () => U) => U)(() => {
							const r = fn();
							if (
								plan &&
								!fired &&
								plan.phase === 'before-commit' &&
								outer === null &&
								plan.when(writes)
							) {
								fired = true;
								dead.val = true;
								throw new Error('simulated crash before commit');
							}
							return r;
						});
						if (outer === null) judgeAfter(writes);
						return out;
					} finally {
						current = outer;
					}
				};
			}
			return (...args: unknown[]): unknown => {
				const write = { method: String(prop), args };
				if (current) {
					current.push(write);
					return (value as (...a: unknown[]) => unknown).apply(target, args);
				}
				const out = (value as (...a: unknown[]) => unknown).apply(target, args);
				if (/^(save|delete)/.test(String(prop))) judgeAfter([write]);
				return out;
			};
		}
	}) as IStorageBackend;
}

/** A ledger row write inside a transaction, decoded. */
export function ledgerRowWrites(writes: IWrite[]): IHeldForwardRecord[] {
	const out: IHeldForwardRecord[] = [];
	for (const w of writes) {
		if (w.method !== 'saveMetadata') continue;
		const [key, value] = w.args as [string, string];
		if (!key.startsWith('held_forward:row:') || !value) continue;
		out.push(JSON.parse(value) as IHeldForwardRecord);
	}
	return out;
}

export function rowInState(state: string): (writes: IWrite[]) => boolean {
	return (writes) => ledgerRowWrites(writes).some((r) => r.state === state);
}

export function channelSaveWithReceivedHtlcState(
	state: HtlcState
): (writes: IWrite[]) => boolean {
	return (writes) =>
		writes.some((w) => {
			if (w.method !== 'saveChannel') return false;
			const chan = w.args[1] as IChannelState;
			for (const [key, htlc] of chan.htlcs) {
				if (key.startsWith('received-') && htlc.state === state) return true;
			}
			return false;
		});
}

// ─────────────── Wire ───────────────

export interface ICut {
	val: boolean;
}

export interface IWireGate {
	hold: boolean;
	queue: Array<{ to: LightningNode; from: string; type: number; p: Buffer }>;
}

/**
 * Event-relay wire for one node pair. `cut` is the link being down; `dead`
 * is a process that is gone (nothing it emits after death reaches anyone).
 */
export function wire(
	a: LightningNode,
	b: LightningNode,
	cut: ICut,
	dead?: { val: boolean },
	gate?: IWireGate
): void {
	const route = (from: LightningNode, to: LightningNode): void => {
		from.on('message:outbound', (pk: string, t: number, p: Buffer) => {
			if (cut.val || dead?.val) return;
			if (pk !== to.getNodeId()) return;
			if (gate?.hold) {
				gate.queue.push({ to, from: from.getNodeId(), type: t, p });
				return;
			}
			to.handlePeerMessage(from.getNodeId(), t, p);
		});
	};
	route(a, b);
	route(b, a);
}

export function drain(gate: IWireGate): void {
	while (gate.queue.length > 0) {
		const m = gate.queue.shift()!;
		m.to.handlePeerMessage(m.from, m.type, m.p);
	}
}

/** Take a live pair down: the link is cut and both sides notice. */
export async function disconnect(
	a: LightningNode,
	b: LightningNode,
	cut: ICut
): Promise<void> {
	cut.val = true;
	a.getChannelManager().handlePeerDisconnected(b.getNodeId());
	b.getChannelManager().handlePeerDisconnected(a.getNodeId());
	await settle();
}

/**
 * Bring a pair back the way a real socket does: both channel_reestablish
 * messages cross before either side's responses are delivered.
 */
export async function reconnect(
	a: LightningNode,
	b: LightningNode,
	cut: ICut,
	gate: IWireGate,
	between?: () => void
): Promise<void> {
	cut.val = false;
	gate.hold = true;
	a.getChannelManager().handlePeerReconnected(b.getNodeId());
	b.getChannelManager().handlePeerReconnected(a.getNodeId());
	between?.();
	drain(gate);
	gate.hold = false;
	await settle();
}

/** Reconnect a RESTARTED node to a live peer over a fresh wire. */
export async function reconnectRestarted(
	restarted: LightningNode,
	peer: LightningNode,
	dead?: { val: boolean }
): Promise<{ cut: ICut; gate: IWireGate }> {
	const cut: ICut = { val: true };
	const gate: IWireGate = { hold: false, queue: [] };
	wire(restarted, peer, cut, dead, gate);
	await reconnect(restarted, peer, cut, gate);
	return { cut, gate };
}

export async function settle(rounds = 6): Promise<void> {
	for (let i = 0; i < rounds; i++) {
		await new Promise<void>((resolve) => setImmediate(resolve));
	}
}

export async function waitFor(
	predicate: () => boolean,
	what: string,
	timeoutMs = 10_000
): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (!predicate()) {
		if (Date.now() > deadline) {
			throw new Error(`timed out waiting for ${what}`);
		}
		await new Promise<void>((resolve) => setImmediate(resolve));
	}
}

// ─────────────── World ───────────────

export async function openReadyChannel(
	opener: LightningNode,
	acceptor: LightningNode
): Promise<Buffer> {
	const channel = opener.openChannel(acceptor.getNodeId(), 1_000_000n);
	const channelId = opener.createFunding(
		channel,
		crypto.randomBytes(32),
		0,
		crypto.randomBytes(64)
	)!;
	await waitFor(
		() => channel.getState() !== ChannelState.SENT_FUNDING_CREATED,
		'funding_signed to arrive'
	);
	opener.handleFundingConfirmed(channelId);
	acceptor.handleFundingConfirmed(channelId);
	await waitFor(
		() => channel.getState() === ChannelState.NORMAL,
		'the opened channel to reach NORMAL'
	);
	return channelId;
}

export function addGraphChannel(
	node: LightningNode,
	scid: Buffer,
	pubA: Buffer,
	pubB: Buffer,
	chainHash: Buffer = BITCOIN_CHAIN_HASH
): void {
	const aIs1 = Buffer.compare(pubA, pubB) < 0;
	node.getGraph().addChannelAnnouncement({
		nodeSignature1: Buffer.alloc(64),
		nodeSignature2: Buffer.alloc(64),
		bitcoinSignature1: Buffer.alloc(64),
		bitcoinSignature2: Buffer.alloc(64),
		features: Buffer.alloc(0),
		chainHash,
		shortChannelId: scid,
		nodeId1: aIs1 ? pubA : pubB,
		nodeId2: aIs1 ? pubB : pubA,
		bitcoinKey1: Buffer.alloc(33, 2),
		bitcoinKey2: Buffer.alloc(33, 3)
	});
	for (const dir of [0, 1]) {
		node.getGraph().applyChannelUpdate({
			signature: Buffer.alloc(64),
			chainHash,
			shortChannelId: scid,
			timestamp: Math.floor(Date.now() / 1000),
			messageFlags: 1,
			channelFlags: dir,
			cltvExpiryDelta: 40,
			htlcMinimumMsat: 1000n,
			feeBaseMsat: 1000,
			feeProportionalMillionths: 1,
			htlcMaximumMsat: 1_000_000_000n
		});
	}
}

export function nodePubkey(seedId: number): Buffer {
	return getPublicKey(nodePrivkey(seedId));
}

export interface IWorld {
	alice: LightningNode;
	lsp: LightningNode;
	carol: LightningNode;
	abChannelId: Buffer;
	bcChannelId: Buffer;
	cutAB: ICut;
	cutBC: ICut;
	gateAB: IWireGate;
	gateBC: IWireGate;
	scidAB: Buffer;
	scidBC: Buffer;
	dead: { val: boolean };
	/** Every refusal reason the LSP logged for a release. */
	refusals: string[];
	/** Every admission refusal reason the LSP logged (issue #709). */
	admissionRefusals: string[];
	/** Every registration refusal reason the LSP logged (issue #709). */
	registrationRefusals: string[];
	/** Notices Carol received. */
	notices: Array<{ lspNodeId: Buffer; notice: IHeldForwardNotice }>;
	/** Adds the LSP placed downstream (one per released part). */
	forwards: number;
}

/**
 * Teach `node` what `peer` advertises, the way a graph would: a verified
 * node_announcement carrying the peer's real feature set (the harness has
 * no peer manager, so there is no init message to read it from).
 */
export function announceFeatures(
	node: LightningNode,
	peer: LightningNode,
	scid: Buffer
): void {
	const peerId = Buffer.from(peer.getNodeId(), 'hex');
	addGraphChannel(
		node,
		scid,
		peerId,
		Buffer.from(node.getNodeId(), 'hex'),
		REGTEST_CHAIN_HASH
	);
	const applied = node.getGraph().applyNodeAnnouncement(
		{
			signature: Buffer.alloc(64),
			features: peer.getLocalFeatures().toBuffer(),
			timestamp: Math.floor(Date.now() / 1000),
			nodeId: peerId,
			rgbColor: Buffer.alloc(3),
			alias: Buffer.alloc(32),
			addresses: []
		},
		{ verified: true }
	);
	expect(applied, 'node_announcement applied').to.equal(true);
}

export async function setupWorld(opts: {
	lspStorage?: IStorageBackend;
	dead?: { val: boolean };
	carolAutoRelease?: boolean;
	/** The LSP's service config; default enabled with default limits. */
	lspService?: IAsyncReceiveServiceConfig;
	/** Carol registers with the LSP during setup (default true). */
	carolRegisters?: boolean;
	/** Further LSP node config (a JIT receive engine, for instance). */
	lspExtra?: Partial<INodeConfig>;
}): Promise<IWorld> {
	const dead = opts.dead ?? { val: false };
	const alice = createNode(ALICE_SEED);
	// The LSP runs the async receive service (issue #709); Carol registers
	// with it once the channel is up, and her hold paths carry the grant.
	const lsp = createNode(LSP_SEED, opts.lspStorage, {
		asyncReceiveService: opts.lspService ?? { enabled: true },
		...opts.lspExtra
	});
	const carol = createNode(CAROL_SEED, undefined, {
		autoReleaseHeldForwards: opts.carolAutoRelease ?? true
	});
	const cutAB: ICut = { val: false };
	const cutBC: ICut = { val: false };
	const gateAB: IWireGate = { hold: false, queue: [] };
	const gateBC: IWireGate = { hold: false, queue: [] };
	wire(alice, lsp, cutAB, dead, gateAB);
	wire(lsp, carol, cutBC, dead, gateBC);

	const abChannelId = await openReadyChannel(alice, lsp);
	const bcChannelId = await openReadyChannel(lsp, carol);
	await waitFor(
		() =>
			[alice, lsp, carol].every((n) =>
				n
					.getChannelManager()
					.listChannels()
					.every((c) => c.getState() === ChannelState.NORMAL)
			),
		'every channel on every node to reach NORMAL'
	);

	const scidAB = encodeShortChannelId({
		block: 840,
		txIndex: 1,
		outputIndex: 0
	});
	const scidBC = encodeShortChannelId({
		block: 840,
		txIndex: 2,
		outputIndex: 0
	});
	lsp.registerChannelScid(abChannelId, scidAB);
	lsp.registerChannelScid(bcChannelId, scidBC);
	alice.registerChannelScid(abChannelId, scidAB);
	lsp
		.getChannelManager()
		.getChannel(bcChannelId)!
		.getFullState().remoteScidAlias = scidBC;
	carol
		.getChannelManager()
		.getChannel(bcChannelId)!
		.getFullState().remoteScidAlias = scidBC;
	addGraphChannel(alice, scidAB, nodePubkey(ALICE_SEED), nodePubkey(LSP_SEED));
	announceFeatures(carol, lsp, scidBC);
	if (opts.carolRegisters ?? true) {
		await carol.requestAsyncReceiveGrant(lsp.getNodeId(), {
			timeoutMs: 5_000
		});
	}

	const world: IWorld = {
		alice,
		lsp,
		carol,
		abChannelId,
		bcChannelId,
		cutAB,
		cutBC,
		gateAB,
		gateBC,
		scidAB,
		scidBC,
		dead,
		refusals: [],
		admissionRefusals: [],
		registrationRefusals: [],
		notices: [],
		forwards: 0
	};
	observe(world, lsp, carol);
	return world;
}

export function observe(
	world: IWorld,
	lsp: LightningNode,
	carol: LightningNode
): void {
	lsp.on('log', (e: { action?: string; data?: { reason?: string } }) => {
		if (e.action === 'held_forward_release_refused' && e.data?.reason) {
			world.refusals.push(e.data.reason);
		}
		if (e.action === 'held_forward_admission_refused' && e.data?.reason) {
			world.admissionRefusals.push(e.data.reason);
		}
		if (e.action === 'async_receive_registration' && e.data?.reason) {
			world.registrationRefusals.push(e.data.reason);
		}
	});
	lsp.on('htlc:forward', () => {
		world.forwards++;
	});
	carol.on('payment:held-notice', (n: IWorld['notices'][number]) => {
		world.notices.push(n);
	});
}

export function asyncInvoice(
	carol: LightningNode,
	amountMsat: bigint | undefined
) {
	return carol.createInvoice({
		amountMsat,
		description: 'async',
		useBlindedPaths: true,
		asyncHold: true
	});
}

/** Send one explicit part of an MPP payment over the invoice's blinded path. */
export function payPart(
	alice: LightningNode,
	bolt11: string,
	paymentHash: Buffer,
	paymentSecret: Buffer,
	partMsat: bigint,
	totalMsat: bigint
): void {
	const inv = decodeInvoice(bolt11);
	const blinded = inv.blindedPaths![0];
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const a = alice as any;
	const finalCltvExpiry = a.paddedFinalCltvExpiry() as number;
	const route = findRouteToBlindedPath(
		alice.getGraph(),
		Buffer.from(alice.getNodeId(), 'hex'),
		blinded.path,
		blinded.payInfo,
		partMsat,
		finalCltvExpiry,
		undefined,
		undefined,
		undefined,
		a.getLocalChannelEdges()
	);
	expect(route, 'a route to the blinded path').to.not.equal(null);
	alice.sendPaymentToRoute(
		route!,
		paymentHash,
		finalCltvExpiry,
		paymentSecret,
		totalMsat
	);
}

export function heldRecords(lsp: LightningNode): IHeldForwardRecord[] {
	return lsp.listHeldForwards();
}

export function receivedHtlcCount(
	node: LightningNode,
	channelId: Buffer
): number {
	const st = node.getChannelManager().getChannel(channelId)!.getFullState();
	return [...st.htlcs.keys()].filter((k) => k.startsWith('received-')).length;
}

export function tempDb(prefix: string): string {
	return path.join(
		fs.mkdtempSync(path.join(os.tmpdir(), `beignet-${prefix}-`)),
		'node.db'
	);
}

export function readRow(
	dbPath: string,
	holdId: string
): IHeldForwardRecord | null {
	const db = new SqliteStorage(dbPath);
	db.open();
	try {
		const raw = db.loadMetadata(`held_forward:row:${holdId}`);
		return raw ? (JSON.parse(raw) as IHeldForwardRecord) : null;
	} finally {
		db.close();
	}
}

/** Capture the onion messages one node sends to another (raw 513 payloads). */
export function tapOnion(from: LightningNode, to: LightningNode): Buffer[] {
	const captured: Buffer[] = [];
	from.on('message:outbound', (pk: string, t: number, p: Buffer) => {
		if (pk === to.getNodeId() && t === MessageType.ONION_MESSAGE) {
			captured.push(Buffer.from(p));
		}
	});
	return captured;
}

export function destroyAll(...nodes: LightningNode[]): void {
	for (const n of nodes) n.destroy();
}

export function buildOnionFrom(
	from: LightningNode,
	to: Buffer,
	payload: Buffer
): Buffer {
	let captured: Buffer | null = null;
	const om = from.getOnionMessageManager();
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const saved = (om as any).sendMessage;
	om.setSendFunction((_peer: string, _type: number, p: Buffer) => {
		captured = Buffer.from(p);
	});
	om.sendOnionMessage(to, new Map([[RELEASE_HELD_HTLC_TLV_TYPE, payload]]));
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	(om as any).sendMessage = saved;
	expect(captured, 'onion message built').to.not.equal(null);
	return captured!;
}
