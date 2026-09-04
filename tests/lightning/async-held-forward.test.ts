/**
 * Async held forwards (issue #708): authenticated per-part durable state and
 * real offline behaviour.
 *
 * Alice -> LSP -> Carol. Carol's invoice carries a blinded path through the
 * LSP marked hold_htlc, so the LSP parks Alice's HTLC in its held-forward
 * ledger until Carol signs a release capability. The LSP runs on SQLite so a
 * restart is a new process over the same file, and its storage adapter can
 * be told to "crash" at a chosen commit boundary (writes stop landing, the
 * wire goes dead), exactly like the recovery suites simulate a kill.
 *
 * One test per acceptance criterion of the issue:
 *  - an unauthorized peer that knows the payment hash cannot release;
 *  - parts sharing one hash stay distinct and each resolves exactly once;
 *  - duplicate add, release, fail and replay inputs are idempotent;
 *  - a real disconnect/reconnect succeeds while CLTV remains;
 *  - a crash at every lifecycle boundary recovers deterministically;
 *  - restart plus channel_reestablish never duplicates the downstream add;
 *  - a release racing the CLTV cutoff has exactly one durable winner;
 *  - partial MPP arrival, retry reuse and force-close-relevant timing.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { Network } from '../../src/lightning/invoice/types';
import { INodeConfig, PaymentStatus } from '../../src/lightning/node/types';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { IStorageBackend } from '../../src/lightning/storage/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import {
	BITCOIN_CHAIN_HASH,
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	HtlcState
} from '../../src/lightning/channel/types';
import { IChannelState } from '../../src/lightning/channel/channel-state';
import { encodeShortChannelId } from '../../src/lightning/gossip/types';
import { findRouteToBlindedPath } from '../../src/lightning/gossip/pathfinding';
import { decode as decodeInvoice } from '../../src/lightning/invoice/decode';
import { MessageType } from '../../src/lightning/message/types';
import { IHeldForwardRecord } from '../../src/lightning/async-payments/held-forward-ledger';
import {
	IHeldForwardNotice,
	RELEASE_HELD_HTLC_TLV_TYPE
} from '../../src/lightning/async-payments/types';
import {
	deriveHoldRegistrationId,
	encodeReleaseCapability,
	signReleaseCapability
} from '../../src/lightning/async-payments/release-capability';

const ALICE_SEED = 91;
const LSP_SEED = 92;
const CAROL_SEED = 93;
const MALLORY_SEED = 94;

function makeSeed(id: number): Buffer {
	return crypto.createHash('sha256').update(`held-forward-seed-${id}`).digest();
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

function nodePrivkey(seedId: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(makeSeed(seedId))
		.update(Buffer.from('node-identity'))
		.digest();
}

function makeNodeConfig(
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

function createNode(
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

interface IWrite {
	method: string;
	args: unknown[];
}

interface ICrashPlan {
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
function crashingStorage(
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
function ledgerRowWrites(writes: IWrite[]): IHeldForwardRecord[] {
	const out: IHeldForwardRecord[] = [];
	for (const w of writes) {
		if (w.method !== 'saveMetadata') continue;
		const [key, value] = w.args as [string, string];
		if (!key.startsWith('held_forward:row:') || !value) continue;
		out.push(JSON.parse(value) as IHeldForwardRecord);
	}
	return out;
}

function rowInState(state: string): (writes: IWrite[]) => boolean {
	return (writes) => ledgerRowWrites(writes).some((r) => r.state === state);
}

function channelSaveWithReceivedHtlcState(
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

interface ICut {
	val: boolean;
}

interface IWireGate {
	hold: boolean;
	queue: Array<{ to: LightningNode; from: string; type: number; p: Buffer }>;
}

/**
 * Event-relay wire for one node pair. `cut` is the link being down; `dead`
 * is a process that is gone (nothing it emits after death reaches anyone).
 */
function wire(
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

function drain(gate: IWireGate): void {
	while (gate.queue.length > 0) {
		const m = gate.queue.shift()!;
		m.to.handlePeerMessage(m.from, m.type, m.p);
	}
}

/** Take a live pair down: the link is cut and both sides notice. */
async function disconnect(
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
async function reconnect(
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
async function reconnectRestarted(
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

async function settle(rounds = 6): Promise<void> {
	for (let i = 0; i < rounds; i++) {
		await new Promise<void>((resolve) => setImmediate(resolve));
	}
}

async function waitFor(
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

async function openReadyChannel(
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

function addGraphChannel(
	node: LightningNode,
	scid: Buffer,
	pubA: Buffer,
	pubB: Buffer
): void {
	const aIs1 = Buffer.compare(pubA, pubB) < 0;
	node.getGraph().addChannelAnnouncement({
		nodeSignature1: Buffer.alloc(64),
		nodeSignature2: Buffer.alloc(64),
		bitcoinSignature1: Buffer.alloc(64),
		bitcoinSignature2: Buffer.alloc(64),
		features: Buffer.alloc(0),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		nodeId1: aIs1 ? pubA : pubB,
		nodeId2: aIs1 ? pubB : pubA,
		bitcoinKey1: Buffer.alloc(33, 2),
		bitcoinKey2: Buffer.alloc(33, 3)
	});
	for (const dir of [0, 1]) {
		node.getGraph().applyChannelUpdate({
			signature: Buffer.alloc(64),
			chainHash: BITCOIN_CHAIN_HASH,
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

function nodePubkey(seedId: number): Buffer {
	return getPublicKey(nodePrivkey(seedId));
}

interface IWorld {
	alice: LightningNode;
	lsp: LightningNode;
	carol: LightningNode;
	abChannelId: Buffer;
	bcChannelId: Buffer;
	cutAB: ICut;
	cutBC: ICut;
	gateAB: IWireGate;
	gateBC: IWireGate;
	dead: { val: boolean };
	/** Every refusal reason the LSP logged for a release. */
	refusals: string[];
	/** Notices Carol received. */
	notices: Array<{ lspNodeId: Buffer; notice: IHeldForwardNotice }>;
	/** Adds the LSP placed downstream (one per released part). */
	forwards: number;
}

async function setupWorld(opts: {
	lspStorage?: IStorageBackend;
	dead?: { val: boolean };
	carolAutoRelease?: boolean;
}): Promise<IWorld> {
	const dead = opts.dead ?? { val: false };
	const alice = createNode(ALICE_SEED);
	const lsp = createNode(LSP_SEED, opts.lspStorage);
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
		dead,
		refusals: [],
		notices: [],
		forwards: 0
	};
	observe(world, lsp, carol);
	return world;
}

function observe(
	world: IWorld,
	lsp: LightningNode,
	carol: LightningNode
): void {
	lsp.on('log', (e: { action?: string; data?: { reason?: string } }) => {
		if (e.action === 'held_forward_release_refused' && e.data?.reason) {
			world.refusals.push(e.data.reason);
		}
	});
	lsp.on('htlc:forward', () => {
		world.forwards++;
	});
	carol.on('payment:held-notice', (n: IWorld['notices'][number]) => {
		world.notices.push(n);
	});
}

function asyncInvoice(carol: LightningNode, amountMsat: bigint | undefined) {
	return carol.createInvoice({
		amountMsat,
		description: 'async',
		useBlindedPaths: true,
		asyncHold: true
	});
}

/** Send one explicit part of an MPP payment over the invoice's blinded path. */
function payPart(
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

function heldRecords(lsp: LightningNode): IHeldForwardRecord[] {
	return lsp.listHeldForwards();
}

function receivedHtlcCount(node: LightningNode, channelId: Buffer): number {
	const st = node.getChannelManager().getChannel(channelId)!.getFullState();
	return [...st.htlcs.keys()].filter((k) => k.startsWith('received-')).length;
}

function tempDb(prefix: string): string {
	return path.join(
		fs.mkdtempSync(path.join(os.tmpdir(), `beignet-${prefix}-`)),
		'node.db'
	);
}

function readRow(dbPath: string, holdId: string): IHeldForwardRecord | null {
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
function tapOnion(from: LightningNode, to: LightningNode): Buffer[] {
	const captured: Buffer[] = [];
	from.on('message:outbound', (pk: string, t: number, p: Buffer) => {
		if (pk === to.getNodeId() && t === MessageType.ONION_MESSAGE) {
			captured.push(Buffer.from(p));
		}
	});
	return captured;
}

function destroyAll(...nodes: LightningNode[]): void {
	for (const n of nodes) n.destroy();
}

// ─────────────── Tests ───────────────

describe('Async held forwards (issue #708)', () => {
	describe('authorization', () => {
		it('an unauthorized peer that knows the payment hash cannot release a hold', async function () {
			this.timeout(20_000);
			const w = await setupWorld({ carolAutoRelease: false });
			const { alice, lsp, carol } = w;
			// Mallory is a peer of the LSP (onion messages need no channel).
			const mallory = createNode(MALLORY_SEED);
			wire(mallory, lsp, { val: false });

			const invoice = asyncInvoice(carol, 5_000_000n);
			alice.sendPayment(invoice.bolt11);
			await settle();
			const [record] = heldRecords(lsp);
			expect(record.state).to.equal('HELD');
			const holdId = Buffer.from(record.id, 'hex');
			const lspId = Buffer.from(lsp.getNodeId(), 'hex');
			const carolId = Buffer.from(carol.getNodeId(), 'hex');
			const malloryId = Buffer.from(mallory.getNodeId(), 'hex');
			const chainHash = (
				lsp as unknown as { chainHash: () => Buffer }
			).chainHash();
			const sendFrom = (node: LightningNode, bytes: Buffer): void =>
				node
					.getOnionMessageManager()
					.sendOnionMessage(
						lspId,
						new Map([[RELEASE_HELD_HTLC_TLV_TYPE, bytes]])
					);

			// 1. The hash itself, the old protocol's whole token.
			sendFrom(mallory, invoice.paymentHash);
			// 2. A capability naming Carol as receiver, signed by Mallory.
			sendFrom(
				mallory,
				encodeReleaseCapability(
					signReleaseCapability(
						{
							chainHash,
							receiverNodeId: carolId,
							lspNodeId: lspId,
							registrationId: deriveHoldRegistrationId(carolId, lspId),
							amountMsat: BigInt(record.forwardAmountMsat),
							expiresAt: BigInt(Math.floor(Date.now() / 1000) + 600),
							nonce: crypto.randomBytes(32),
							holdIds: [holdId]
						},
						nodePrivkey(MALLORY_SEED)
					)
				)
			);
			// 3. A capability naming Mallory herself, correctly signed, for a
			//    hold that is Carol's.
			sendFrom(
				mallory,
				encodeReleaseCapability(
					signReleaseCapability(
						{
							chainHash,
							receiverNodeId: malloryId,
							lspNodeId: lspId,
							registrationId: deriveHoldRegistrationId(malloryId, lspId),
							amountMsat: BigInt(record.forwardAmountMsat),
							expiresAt: BigInt(Math.floor(Date.now() / 1000) + 600),
							nonce: crypto.randomBytes(32),
							holdIds: [holdId]
						},
						nodePrivkey(MALLORY_SEED)
					)
				)
			);
			// 4. Carol's genuine capability, obtained somehow, replayed by
			//    Mallory over her own connection.
			const genuine = carol
				.getAsyncPaymentManager()
				.buildRelease(lspId, [holdId], BigInt(record.forwardAmountMsat));
			sendFrom(mallory, encodeReleaseCapability(genuine));
			// 5. Carol herself, but with the wrong registration, amount, or an
			//    expired capability.
			sendFrom(
				carol,
				encodeReleaseCapability(
					carol
						.getAsyncPaymentManager()
						.buildRelease(lspId, [holdId], BigInt(record.forwardAmountMsat), {
							registrationId: Buffer.alloc(32, 1)
						})
				)
			);
			sendFrom(
				carol,
				encodeReleaseCapability(
					carol
						.getAsyncPaymentManager()
						.buildRelease(
							lspId,
							[holdId],
							BigInt(record.forwardAmountMsat) + 1n
						)
				)
			);
			sendFrom(
				carol,
				encodeReleaseCapability(
					carol
						.getAsyncPaymentManager()
						.buildRelease(lspId, [holdId], BigInt(record.forwardAmountMsat), {
							ttlSec: -100
						})
				)
			);
			await settle();

			expect(w.refusals).to.deep.equal([
				'malformed',
				'sender_mismatch',
				'unknown_hold',
				'sender_mismatch',
				'registration_mismatch',
				'amount_mismatch',
				'expired'
			]);
			expect(heldRecords(lsp)[0].state, 'still parked').to.equal('HELD');
			expect(w.forwards).to.equal(0);
			expect(carol.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.PENDING
			);

			// The genuine capability from Carol's own connection releases.
			sendFrom(carol, encodeReleaseCapability(genuine));
			await settle();
			expect(heldRecords(lsp)[0].state).to.equal('RELEASED');
			expect(carol.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
			expect(w.forwards).to.equal(1);
			destroyAll(alice, lsp, carol, mallory);
		});
	});

	describe('per-part identity', () => {
		it('two parts with one payment hash stay distinct and each resolves exactly once', async function () {
			this.timeout(20_000);
			const w = await setupWorld({ carolAutoRelease: false });
			const { alice, lsp, carol } = w;
			const total = 100_000_000n;
			const invoice = asyncInvoice(carol, total);
			const released: string[] = [];
			lsp.on('htlc:held-forward-released', (r: IHeldForwardRecord) =>
				released.push(r.id)
			);

			payPart(
				alice,
				invoice.bolt11,
				invoice.paymentHash,
				invoice.paymentSecret,
				total / 2n,
				total
			);
			await settle();
			expect(heldRecords(lsp), 'first part parked').to.have.length(1);
			payPart(
				alice,
				invoice.bolt11,
				invoice.paymentHash,
				invoice.paymentSecret,
				total / 2n,
				total
			);
			await settle();
			const records = heldRecords(lsp);
			expect(records, 'second part parked as its own row').to.have.length(2);
			expect(records[0].id).to.not.equal(records[1].id);
			expect(records[0].paymentHashHex).to.equal(records[1].paymentHashHex);
			expect(records[0].inHtlcId).to.not.equal(records[1].inHtlcId);
			expect(records.every((r) => r.state === 'HELD')).to.equal(true);
			// The payment-level index groups them; the second notice lists both.
			expect(w.notices).to.have.length(2);
			expect(w.notices[1].notice.entries).to.have.length(2);

			// Atomic set release: one capability over the complete set.
			const sum = records.reduce((s, r) => s + BigInt(r.forwardAmountMsat), 0n);
			carol.sendAsyncRelease(
				Buffer.from(lsp.getNodeId(), 'hex'),
				records.map((r) => Buffer.from(r.id, 'hex')),
				sum
			);
			await settle();
			const after = heldRecords(lsp);
			expect(after.map((r) => r.state)).to.deep.equal(['RELEASED', 'RELEASED']);
			expect(after[0].releaseNonceHex, 'released as ONE set').to.equal(
				after[1].releaseNonceHex
			);
			expect(released.sort()).to.deep.equal(records.map((r) => r.id).sort());
			expect(w.forwards, 'one add per part').to.equal(2);
			const carolPayment = carol.getPayment(invoice.paymentHash)!;
			expect(carolPayment.status).to.equal(PaymentStatus.COMPLETED);
			expect(Number(carolPayment.amountMsat)).to.equal(Number(total));
			destroyAll(alice, lsp, carol);
		});

		it('partial MPP arrival is never released; the set goes when the total is covered', async function () {
			this.timeout(20_000);
			const w = await setupWorld({ carolAutoRelease: true });
			const { alice, lsp, carol } = w;
			const total = 100_000_000n;
			const invoice = asyncInvoice(carol, total);

			payPart(
				alice,
				invoice.bolt11,
				invoice.paymentHash,
				invoice.paymentSecret,
				total / 2n,
				total
			);
			await settle();
			expect(w.notices, 'Carol was told about the first part').to.have.length(
				1
			);
			expect(heldRecords(lsp)[0].state, 'half a payment stays parked').to.equal(
				'HELD'
			);
			expect(w.forwards).to.equal(0);

			payPart(
				alice,
				invoice.bolt11,
				invoice.paymentHash,
				invoice.paymentSecret,
				total / 2n,
				total
			);
			await settle();
			const records = heldRecords(lsp);
			expect(records.map((r) => r.state)).to.deep.equal([
				'RELEASED',
				'RELEASED'
			]);
			expect(records[0].releaseNonceHex).to.equal(records[1].releaseNonceHex);
			expect(w.forwards).to.equal(2);
			expect(carol.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
			destroyAll(alice, lsp, carol);
		});

		it('an amount-less invoice releases each part independently', async function () {
			this.timeout(20_000);
			const w = await setupWorld({ carolAutoRelease: true });
			const { alice, lsp, carol } = w;
			const invoice = asyncInvoice(carol, undefined);
			alice.sendPayment(invoice.bolt11, undefined, undefined, 3_000_000n);
			await settle();
			const [record] = heldRecords(lsp);
			expect(record.state).to.equal('RELEASED');
			expect(carol.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
			destroyAll(alice, lsp, carol);
		});
	});

	describe('idempotency', () => {
		it('duplicate add, release, fail and replay inputs are idempotent', async function () {
			this.timeout(20_000);
			const w = await setupWorld({ carolAutoRelease: false });
			const { alice, lsp, carol, abChannelId } = w;
			const invoice = asyncInvoice(carol, 5_000_000n);
			const carolToLsp = tapOnion(carol, lsp);
			alice.sendPayment(invoice.bolt11);
			await settle();
			const [record] = heldRecords(lsp);

			// Duplicate add: the restart redispatch and a replayed dispatch of
			// the same inbound HTLC both re-enter the hold path.
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			const priv = lsp as any;
			priv.redispatchUnresolvedReceivedHtlcs(abChannelId);
			priv.handleIncomingHtlc(
				abChannelId,
				BigInt(record.inHtlcId),
				BigInt(record.incomingAmountMsat),
				invoice.paymentHash
			);
			await settle();
			expect(heldRecords(lsp), 'one row for one HTLC').to.have.length(1);
			expect(heldRecords(lsp)[0].id, 'same hold id').to.equal(record.id);

			// Release, then replay the very same capability bytes.
			carol.sendAsyncRelease(
				Buffer.from(lsp.getNodeId(), 'hex'),
				[Buffer.from(record.id, 'hex')],
				BigInt(record.forwardAmountMsat)
			);
			await settle();
			expect(heldRecords(lsp)[0].state).to.equal('RELEASED');
			expect(w.forwards).to.equal(1);
			expect(carolToLsp, 'the release was captured').to.have.length(1);
			lsp.handlePeerMessage(
				carol.getNodeId(),
				MessageType.ONION_MESSAGE,
				carolToLsp[0]
			);
			lsp.handlePeerMessage(
				carol.getNodeId(),
				MessageType.ONION_MESSAGE,
				carolToLsp[0]
			);
			await settle();
			expect(w.forwards, 'a replayed release forwards nothing').to.equal(1);
			expect(
				w.refusals,
				'a replay is a silent duplicate, not a refusal'
			).to.deep.equal([]);
			expect(heldRecords(lsp)[0].state).to.equal('RELEASED');
			// A fresh capability for a resolved hold is stale, not an action.
			carol.sendAsyncRelease(
				Buffer.from(lsp.getNodeId(), 'hex'),
				[Buffer.from(record.id, 'hex')],
				BigInt(record.forwardAmountMsat)
			);
			await settle();
			expect(w.refusals).to.deep.equal(['stale']);
			expect(w.forwards).to.equal(1);

			// Duplicate fail on a second hold: the first fail acts, the second
			// is a no-op, and a release after the fail loses.
			const invoice2 = asyncInvoice(carol, 4_000_000n);
			alice.sendPayment(invoice2.bolt11);
			await settle();
			const second = heldRecords(lsp).find((r) => r.state === 'HELD')!;
			expect(lsp.failHeldForward(second.id)).to.equal(true);
			expect(lsp.failHeldForward(second.id)).to.equal(false);
			await settle();
			expect(
				lsp.listHeldForwards().find((r) => r.id === second.id)!.state
			).to.equal('FAILED');
			expect(alice.getPayment(invoice2.paymentHash)!.status).to.equal(
				PaymentStatus.FAILED
			);
			carol.sendAsyncRelease(
				Buffer.from(lsp.getNodeId(), 'hex'),
				[Buffer.from(second.id, 'hex')],
				BigInt(second.forwardAmountMsat)
			);
			await settle();
			expect(w.refusals).to.deep.equal(['stale', 'stale']);
			expect(w.forwards).to.equal(1);
			destroyAll(alice, lsp, carol);
		});

		it('a retry after a failed hold gets its own hold, and the old capability cannot touch it', async function () {
			this.timeout(20_000);
			const w = await setupWorld({ carolAutoRelease: false });
			const { alice, lsp, carol } = w;
			const total = 5_000_000n;
			const invoice = asyncInvoice(carol, total);
			payPart(
				alice,
				invoice.bolt11,
				invoice.paymentHash,
				invoice.paymentSecret,
				total,
				total
			);
			await settle();
			const first = heldRecords(lsp)[0];
			const lspId = Buffer.from(lsp.getNodeId(), 'hex');
			const oldCap = carol
				.getAsyncPaymentManager()
				.buildRelease(lspId, [Buffer.from(first.id, 'hex')], total);
			expect(lsp.failHeldForward(first.id)).to.equal(true);
			await settle();
			expect(alice.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.FAILED
			);

			// The payer retries the same invoice: same hash, new HTLC, new hold.
			payPart(
				alice,
				invoice.bolt11,
				invoice.paymentHash,
				invoice.paymentSecret,
				total,
				total
			);
			await settle();
			const records = heldRecords(lsp);
			expect(records).to.have.length(2);
			const retry = records.find((r) => r.state === 'HELD')!;
			expect(retry.id).to.not.equal(first.id);
			expect(retry.paymentHashHex).to.equal(first.paymentHashHex);
			expect(retry.inHtlcId).to.not.equal(first.inHtlcId);

			carol
				.getOnionMessageManager()
				.sendOnionMessage(
					lspId,
					new Map([
						[RELEASE_HELD_HTLC_TLV_TYPE, encodeReleaseCapability(oldCap)]
					])
				);
			await settle();
			expect(w.refusals, 'the old hold is terminal').to.deep.equal(['stale']);
			expect(
				lsp.listHeldForwards().find((r) => r.id === retry.id)!.state
			).to.equal('HELD');
			carol.sendAsyncRelease(lspId, [Buffer.from(retry.id, 'hex')], total);
			await settle();
			expect(
				lsp.listHeldForwards().find((r) => r.id === retry.id)!.state
			).to.equal('RELEASED');
			expect(carol.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
			expect(w.forwards).to.equal(1);
			destroyAll(alice, lsp, carol);
		});
	});

	describe('offline receiver', () => {
		it('a real peer disconnect and reconnect succeeds when enough CLTV remains', async function () {
			this.timeout(20_000);
			const w = await setupWorld({ carolAutoRelease: true });
			const { alice, lsp, carol, bcChannelId } = w;
			const invoice = asyncInvoice(carol, 5_000_000n);

			// Carol goes offline for real: the link is cut and both sides run
			// their disconnect handling, so the LSP's channel to her is
			// AWAITING_REESTABLISH and cannot carry an add.
			await disconnect(lsp, carol, w.cutBC);
			expect(
				lsp.getChannelManager().getChannel(bcChannelId)!.getState()
			).to.equal(ChannelState.AWAITING_REESTABLISH);

			alice.sendPayment(invoice.bolt11);
			await settle();
			const [record] = heldRecords(lsp);
			expect(record.state).to.equal('HELD');
			expect(w.notices, 'nothing reaches an offline receiver').to.have.length(
				0
			);
			expect(alice.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.PENDING
			);

			// Carol comes back: channel_reestablish both ways, then the LSP's
			// notice, Carol's signed release, the add, and the fulfill.
			await reconnect(lsp, carol, w.cutBC, w.gateBC);
			await waitFor(
				() =>
					carol.getPayment(invoice.paymentHash)?.status ===
					PaymentStatus.COMPLETED,
				'Carol to be paid after reconnecting'
			);
			expect(w.notices).to.have.length(1);
			expect(heldRecords(lsp)[0].state).to.equal('RELEASED');
			expect(w.forwards).to.equal(1);
			expect(alice.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
			destroyAll(alice, lsp, carol);
		});

		it('a release that arrives while the outgoing channel is still reestablishing is deferred, not refused', async function () {
			this.timeout(20_000);
			const w = await setupWorld({ carolAutoRelease: false });
			const { alice, lsp, carol, bcChannelId } = w;
			const invoice = asyncInvoice(carol, 5_000_000n);
			alice.sendPayment(invoice.bolt11);
			await settle();
			const [record] = heldRecords(lsp);
			const lspId = Buffer.from(lsp.getNodeId(), 'hex');
			const cap = carol
				.getAsyncPaymentManager()
				.buildRelease(
					lspId,
					[Buffer.from(record.id, 'hex')],
					BigInt(record.forwardAmountMsat)
				);

			await disconnect(lsp, carol, w.cutBC);
			// Reconnect, but deliver Carol's release BEFORE the reestablish
			// messages are drained: the LSP sees it on a channel that is not
			// yet usable.
			await reconnect(lsp, carol, w.cutBC, w.gateBC, () => {
				lsp.handlePeerMessage(
					carol.getNodeId(),
					MessageType.ONION_MESSAGE,
					buildOnionFrom(carol, lspId, encodeReleaseCapability(cap))
				);
				expect(
					lsp.getChannelManager().getChannel(bcChannelId)!.getState()
				).to.equal(ChannelState.AWAITING_REESTABLISH);
				expect(heldRecords(lsp)[0].state, 'release won, add deferred').to.equal(
					'RELEASING'
				);
				expect(w.forwards).to.equal(0);
			});
			await waitFor(
				() => heldRecords(lsp)[0].state === 'RELEASED',
				'the deferred add to be placed once the channel is usable'
			);
			expect(w.forwards).to.equal(1);
			expect(carol.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
			destroyAll(alice, lsp, carol);
		});
	});

	describe('holding-node crash at every lifecycle boundary', () => {
		interface IBoundary {
			name: string;
			plan: ICrashPlan;
			/** What the restarted LSP must end at. */
			expect: 'paid-once' | 'failed';
			/** Whether the pre-crash hold id survives (the row landed). */
			sameHoldId: boolean;
			/** Drive the cutoff before the crash point (fail boundaries). */
			viaCutoff?: boolean;
		}
		const boundaries: IBoundary[] = [
			{
				name: 'before the HELD row commits',
				plan: { phase: 'before-commit', when: rowInState('HELD') },
				expect: 'paid-once',
				sameHoldId: false
			},
			{
				name: 'after the HELD row commits',
				plan: { phase: 'after-commit', when: rowInState('HELD') },
				expect: 'paid-once',
				sameHoldId: true
			},
			{
				name: 'after the RELEASING row commits, before the add',
				plan: { phase: 'after-commit', when: rowInState('RELEASING') },
				expect: 'paid-once',
				sameHoldId: true
			},
			{
				name: 'after the add commits, before the RELEASED row',
				plan: {
					phase: 'after-commit',
					when: (writes) => writes.some((x) => x.method === 'saveForwardedHtlc')
				},
				expect: 'paid-once',
				sameHoldId: true
			},
			{
				name: 'after the FAILING row commits, before the fail',
				plan: { phase: 'after-commit', when: rowInState('FAILING') },
				expect: 'failed',
				sameHoldId: true,
				viaCutoff: true
			},
			{
				name: 'after the fail commits, before the FAILED row',
				plan: {
					phase: 'after-commit',
					when: channelSaveWithReceivedHtlcState(HtlcState.FAILED)
				},
				expect: 'failed',
				sameHoldId: true,
				viaCutoff: true
			}
		];

		for (const b of boundaries) {
			it(`recovers deterministically from a crash ${b.name}`, async function () {
				this.timeout(30_000);
				const dbPath = tempDb('held-forward-crash');
				const raw = new SqliteStorage(dbPath);
				raw.open();
				const dead = { val: false };
				const w = await setupWorld({
					lspStorage: crashingStorage(raw, dead, b.plan),
					dead,
					carolAutoRelease: true
				});
				const { alice, lsp, carol, abChannelId, bcChannelId } = w;
				const invoice = asyncInvoice(carol, 5_000_000n);

				// Carol is offline while Alice pays, as an async receiver is.
				await disconnect(lsp, carol, w.cutBC);
				alice.sendPayment(invoice.bolt11);
				await settle();
				// The zombie's memory is not evidence (its writes stopped landing);
				// only the id it minted matters, and only when the row landed.
				const before: IHeldForwardRecord | undefined = heldRecords(lsp)[0];
				if (b.viaCutoff) {
					expect(dead.val, 'alive until the cutoff').to.equal(false);
					lsp.handleNewBlock(before!.cutoffHeight);
					await settle();
				} else if (!dead.val) {
					// Release boundaries: Carol reconnects and releases.
					await reconnect(lsp, carol, w.cutBC, w.gateBC);
					await settle();
				}
				expect(dead.val, `the LSP died ${b.name}`).to.equal(true);

				// The process is gone: peers notice, and the zombie is dropped.
				const lspId = lsp.getNodeId();
				lsp.destroy();
				alice.getChannelManager().handlePeerDisconnected(lspId);
				carol.getChannelManager().handlePeerDisconnected(lspId);
				alice.removeAllListeners('message:outbound');
				carol.removeAllListeners('message:outbound');
				const paidBeforeRestart =
					carol.getPayment(invoice.paymentHash)?.status ===
					PaymentStatus.COMPLETED;

				const disk = new SqliteStorage(dbPath);
				disk.open();
				const restored = createNode(LSP_SEED, disk);
				const w2: IWorld = { ...w, lsp: restored, refusals: [], forwards: 0 };
				observe(w2, restored, carol);
				// The payer's channel reestablishes first (its redispatch
				// re-parks or re-drives the hold), then the receiver's.
				await reconnectRestarted(restored, alice);
				await reconnectRestarted(restored, carol);
				await settle(10);

				const rows = heldRecords(restored);
				expect(rows, 'exactly one hold on disk after restart').to.have.length(
					1
				);
				if (b.sameHoldId) {
					expect(rows[0].id, 'the hold id survived').to.equal(before!.id);
				} else {
					expect(rows[0].id, 'a fresh hold id').to.not.equal(before?.id);
				}
				if (b.expect === 'paid-once') {
					await waitFor(
						() =>
							carol.getPayment(invoice.paymentHash)?.status ===
							PaymentStatus.COMPLETED,
						'Carol to be paid'
					);
					expect(heldRecords(restored)[0].state).to.equal('RELEASED');
					expect(readRow(dbPath, rows[0].id)!.state, 'durable').to.equal(
						'RELEASED'
					);
					expect(
						Number(carol.getPayment(invoice.paymentHash)!.amountMsat),
						'paid exactly the invoice amount, never twice'
					).to.equal(5_000_000);
					expect(
						receivedHtlcCount(carol, bcChannelId) + (paidBeforeRestart ? 1 : 0),
						'at most one add ever reached Carol'
					).to.be.at.most(1);
					await waitFor(
						() =>
							alice.getPayment(invoice.paymentHash)?.status ===
							PaymentStatus.COMPLETED,
						'Alice to settle'
					);
				} else {
					await waitFor(
						() =>
							alice.getPayment(invoice.paymentHash)?.status ===
							PaymentStatus.FAILED,
						'Alice to see the failure'
					);
					expect(heldRecords(restored)[0].state).to.equal('FAILED');
					expect(readRow(dbPath, rows[0].id)!.state, 'durable').to.equal(
						'FAILED'
					);
					expect(w2.forwards, 'nothing forwarded').to.equal(0);
					expect(carol.getPayment(invoice.paymentHash)!.status).to.equal(
						PaymentStatus.PENDING
					);
				}
				// No channel was lost to the crash.
				expect(
					restored.getChannelManager().getChannel(abChannelId)!.getState()
				).to.equal(ChannelState.NORMAL);
				expect(
					restored.getChannelManager().getChannel(bcChannelId)!.getState()
				).to.equal(ChannelState.NORMAL);
				destroyAll(alice, restored, carol);
			});
		}

		it('restart plus channel_reestablish never duplicates the downstream add', async function () {
			this.timeout(30_000);
			// The add landed and Carol had it, then the LSP died before it
			// could record RELEASED: the retransmission on reestablish and the
			// redispatch of the inbound leg must both leave one add.
			const dbPath = tempDb('held-forward-dup');
			const raw = new SqliteStorage(dbPath);
			raw.open();
			const dead = { val: false };
			const w = await setupWorld({
				lspStorage: crashingStorage(raw, dead, {
					phase: 'after-commit',
					when: (writes) => writes.some((x) => x.method === 'saveForwardedHtlc')
				}),
				dead,
				carolAutoRelease: true
			});
			const { alice, lsp, carol, bcChannelId } = w;
			const invoice = asyncInvoice(carol, 5_000_000n);
			alice.sendPayment(invoice.bolt11);
			await settle();
			expect(dead.val, 'died right after the add committed').to.equal(true);
			const before = heldRecords(lsp)[0];

			const lspId = lsp.getNodeId();
			lsp.destroy();
			alice.getChannelManager().handlePeerDisconnected(lspId);
			carol.getChannelManager().handlePeerDisconnected(lspId);
			alice.removeAllListeners('message:outbound');
			carol.removeAllListeners('message:outbound');

			const disk = new SqliteStorage(dbPath);
			disk.open();
			expect(readRow(dbPath, before.id)!.state, 'RELEASING on disk').to.equal(
				'RELEASING'
			);
			const restored = createNode(LSP_SEED, disk);
			const w2: IWorld = { ...w, lsp: restored, refusals: [], forwards: 0 };
			observe(w2, restored, carol);
			let addsAfterRestart = 0;
			restored.on('message:outbound', (pk: string, t: number) => {
				if (pk === carol.getNodeId() && t === MessageType.UPDATE_ADD_HTLC) {
					addsAfterRestart++;
				}
			});
			await reconnectRestarted(restored, alice);
			await reconnectRestarted(restored, carol);
			await waitFor(
				() =>
					alice.getPayment(invoice.paymentHash)?.status ===
					PaymentStatus.COMPLETED,
				'the payment to complete after the restart'
			);
			expect(heldRecords(restored)[0].state).to.equal('RELEASED');
			expect(w2.forwards, 'the redispatch placed no second add').to.equal(0);
			expect(addsAfterRestart, 'only the BOLT 2 retransmission').to.be.at.most(
				1
			);
			expect(
				Number(carol.getPayment(invoice.paymentHash)!.amountMsat)
			).to.equal(5_000_000);
			expect(receivedHtlcCount(carol, bcChannelId)).to.be.at.most(1);
			destroyAll(alice, restored, carol);
		});
	});

	describe('CLTV cutoff', () => {
		it('fixes the cutoff on the row from the receiver headroom and the LSP margin', async function () {
			this.timeout(20_000);
			const w = await setupWorld({ carolAutoRelease: false });
			const { alice, lsp, carol } = w;
			const invoice = asyncInvoice(carol, 5_000_000n);
			alice.sendPayment(invoice.bolt11);
			await settle();
			const [r] = heldRecords(lsp);
			// DEFAULT_MIN_FINAL_CLTV_EXPIRY = 40 (the receiver refuses less);
			// HELD_HTLC_EXPIRY_MARGIN = 18, htlcSafetyMargin default 6.
			expect(r.cutoffHeight).to.equal(
				Math.min(r.forwardCltv - 40, r.incomingCltvExpiry - 18)
			);
			expect(
				r.cutoffHeight,
				'well before the inbound leg goes on-chain'
			).to.be.below(r.incomingCltvExpiry - 18);
			// A block short of the cutoff changes nothing.
			lsp.handleNewBlock(r.cutoffHeight - 1);
			await settle();
			expect(heldRecords(lsp)[0].state).to.equal('HELD');
			destroyAll(alice, lsp, carol);
		});

		for (const releaseFirst of [true, false]) {
			it(`release racing the cutoff has one durable winner (${
				releaseFirst ? 'release' : 'cutoff'
			} lands first)`, async function () {
				this.timeout(20_000);
				const dbPath = tempDb('held-forward-race');
				const disk = new SqliteStorage(dbPath);
				disk.open();
				const w = await setupWorld({
					lspStorage: disk,
					carolAutoRelease: false
				});
				const { alice, lsp, carol, abChannelId } = w;
				const invoice = asyncInvoice(carol, 5_000_000n);
				alice.sendPayment(invoice.bolt11);
				await settle();
				const [r] = heldRecords(lsp);
				const lspId = Buffer.from(lsp.getNodeId(), 'hex');
				const cap = carol
					.getAsyncPaymentManager()
					.buildRelease(
						lspId,
						[Buffer.from(r.id, 'hex')],
						BigInt(r.forwardAmountMsat)
					);
				const release = (): void =>
					lsp.handlePeerMessage(
						carol.getNodeId(),
						MessageType.ONION_MESSAGE,
						buildOnionFrom(carol, lspId, encodeReleaseCapability(cap))
					);
				const cutoff = (): void => lsp.handleNewBlock(r.cutoffHeight);

				if (releaseFirst) {
					release();
					cutoff();
				} else {
					cutoff();
					release();
				}
				await settle();

				const final = heldRecords(lsp)[0];
				if (releaseFirst) {
					expect(final.state).to.equal('RELEASED');
					expect(w.forwards).to.equal(1);
					expect(carol.getPayment(invoice.paymentHash)!.status).to.equal(
						PaymentStatus.COMPLETED
					);
					expect(w.refusals).to.deep.equal([]);
				} else {
					expect(final.state).to.equal('FAILED');
					expect(final.failReason).to.equal('cutoff');
					expect(w.forwards).to.equal(0);
					expect(w.refusals).to.deep.equal(['past_cutoff']);
					expect(alice.getPayment(invoice.paymentHash)!.status).to.equal(
						PaymentStatus.FAILED
					);
					// Failed off-chain, while the inbound channel stays healthy:
					// the mandatory failure is what keeps this off the chain.
					const inbound = lsp.getChannelManager().getChannel(abChannelId)!;
					expect(inbound.getState()).to.equal(ChannelState.NORMAL);
					expect(
						[...inbound.getFullState().htlcs.values()].some(
							(h) => h.state === HtlcState.COMMITTED
						)
					).to.equal(false);
				}
				// The winner is on disk, not just in memory.
				expect(readRow(dbPath, r.id)!.state).to.equal(final.state);
				destroyAll(alice, lsp, carol);
			});
		}
	});
});

/**
 * Build the raw onion_message a node would send to `to` with this payload,
 * without sending it, so a test can deliver it at a chosen instant.
 */
function buildOnionFrom(
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
