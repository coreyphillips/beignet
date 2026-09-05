/**
 * FFOR Variant D: adversarial recovery review of draft PR #718.
 *
 * Every test here encodes an outcome the spec (specs/ffor-offline-receive.md,
 * sections 7.5.4, 7.5.5, 7.5.6, 9.5.1, 11.1) requires, and each one FAILS on
 * feat/variant-d at 18d4e04. The comment above each test quotes the spec
 * sentence it enforces and names the behaviour observed instead.
 *
 * Harnesses are the ones the M8 suites use: two ChannelManagers in loopback
 * with a wire log for the channel-level matrix, three LightningNodes (payer,
 * settlement peer, recipient) for the settlement side.
 *
 * Candidates that were tried and PASSED (dropped from this file): voucher
 * round cut after R's commitment_signed, before R's stfu, and between the
 * two stfus (disconnect, restart S, restart R); the drain cut at every BOLT 2
 * boundary after ff_close_ack (disconnect, restart S, restart R); R restarted
 * in ACTIVATING completing on the retransmitted ack; S restarted in ACTIVE
 * with the ack unsent; ff_close or ff_close_ack lost then either side
 * restarted; a failed ACTIVE write on S followed by a reconnect; an upstream
 * disconnect between SETTLING and the fulfil with no restart; S refusing to
 * settle after an activation-hash mismatch.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import { Channel } from '../../src/lightning/channel/channel';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	HtlcState,
	REGTEST_CHAIN_HASH
} from '../../src/lightning/channel/types';
import { MessageType } from '../../src/lightning/message/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	deserializeChannelState,
	serializeChannelState
} from '../../src/lightning/storage/serialization';
import {
	FforSlotState,
	FforState,
	IFforEpochRecord
} from '../../src/lightning/ffor/types';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig, PaymentStatus } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import { decode as decodeInvoice } from '../../src/lightning/invoice/decode';
import { encodeShortChannelId } from '../../src/lightning/gossip/types';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { IChannelState } from '../../src/lightning/channel/channel-state';
import { bitmapGet } from '../../src/lightning/ffor/messages';

// ─────────────── Shared ───────────────

function sha(...parts: (Buffer | string)[]): Buffer {
	const h = crypto.createHash('sha256');
	for (const p of parts) h.update(p);
	return h.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const k = (i: number): Buffer => getPublicKey(sha(seed, Buffer.from([i])));
	return {
		fundingPubkey: k(0),
		revocationBasepoint: k(1),
		paymentBasepoint: k(2),
		delayedPaymentBasepoint: k(3),
		htlcBasepoint: k(4),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

const TIP = 790_000;
const T_EXP = 800_000;
const D_DEADLINE = 798_992;

// ─────────────── Two-manager harness ───────────────

function makeConfig(
	seedId: number
): IChannelManagerConfig & { nodePrivateKey: Buffer } {
	const seed = sha(`ffor-adv-seed-${seedId}`);
	return {
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(seed),
		localPerCommitmentSeed: sha(seed, 'per-commitment'),
		localFundingPrivkey: sha(seed, Buffer.from([0])),
		htlcBasepointSecret: sha(seed, Buffer.from([4])),
		nodePrivateKey: sha(seed, 'node-key'),
		preferAnchors: true
	};
}

interface IWireEntry {
	from: 'S' | 'R';
	type: number;
	payload: Buffer;
}

/** A loopback link with a wire log, a drop filter, a cut and a connect switch. */
class Link {
	readonly log: IWireEntry[] = [];
	connected = true;
	drop: ((from: 'S' | 'R', type: number, payload: Buffer) => boolean) | null =
		null;
	private queue: IWireEntry[] | null = null;

	constructor(
		readonly s: ChannelManager,
		readonly sPub: string,
		readonly r: ChannelManager,
		readonly rPub: string
	) {
		s.on('message:outbound', (peer: string, type: number, payload: Buffer) => {
			if (peer === rPub) this.deliver('S', type, payload);
		});
		r.on('message:outbound', (peer: string, type: number, payload: Buffer) => {
			if (peer === sPub) this.deliver('R', type, payload);
		});
	}

	private deliver(from: 'S' | 'R', type: number, payload: Buffer): void {
		if (!this.connected || (this.drop && this.drop(from, type, payload))) {
			return;
		}
		if (this.queue) {
			this.queue.push({ from, type, payload });
			return;
		}
		this.direct({ from, type, payload });
	}

	private direct(m: IWireEntry): void {
		this.log.push(m);
		if (m.from === 'S') this.r.handleMessage(this.sPub, m.type, m.payload);
		else this.s.handleMessage(this.rPub, m.type, m.payload);
	}

	types(): number[] {
		return this.log.map((e) => e.type);
	}

	/**
	 * A socket cut: from the first message matching (from, type) onward,
	 * nothing is delivered in either direction (TCP FIFO loses the tail).
	 */
	cutAt(from: 'S' | 'R', type: number): void {
		let cutting = false;
		this.drop = (f, t): boolean => {
			if (!cutting && f === from && t === type) cutting = true;
			return cutting;
		};
	}

	disconnect(): void {
		this.connected = false;
		this.drop = null;
		this.s.handlePeerDisconnected(this.rPub);
		this.r.handlePeerDisconnected(this.sPub);
	}

	reconnect(): void {
		this.connected = true;
		this.queue = [];
		this.s.handlePeerReconnected(this.rPub);
		this.r.handlePeerReconnected(this.sPub);
		while (this.queue.length > 0) {
			this.direct(this.queue.shift()!);
		}
		this.queue = null;
	}
}

interface IPair {
	link: Link;
	sManager: ChannelManager;
	rManager: ChannelManager;
	sPub: string;
	rPub: string;
	sChannel: Channel;
	rChannel: Channel;
	channelId: Buffer;
	sConfig: ReturnType<typeof makeConfig>;
	rConfig: ReturnType<typeof makeConfig>;
	sErrors: string[];
	rErrors: string[];
	/** htlc:forwarded events R's manager emitted (a voucher must never). */
	rForwarded: number;
}

const FUNDING_SATOSHIS = 1_000_000n;
const AMOUNTS = [994_000n, 546_250n, 49_749_000n];

let pairSeed = 0;

function createPair(): IPair {
	pairSeed += 10;
	const sConfig = makeConfig(700 + pairSeed);
	const rConfig = makeConfig(701 + pairSeed);
	const sPub = getPublicKey(sConfig.nodePrivateKey).toString('hex');
	const rPub = getPublicKey(rConfig.nodePrivateKey).toString('hex');
	const sManager = new ChannelManager(sConfig);
	const rManager = new ChannelManager(rConfig);
	const sErrors: string[] = [];
	const rErrors: string[] = [];
	sManager.on('error', (_id: Buffer | null, msg: string) => sErrors.push(msg));
	rManager.on('error', (_id: Buffer | null, msg: string) => rErrors.push(msg));
	const link = new Link(sManager, sPub, rManager, rPub);
	const sChannel = sManager.openChannel(rPub, FUNDING_SATOSHIS);
	sManager.createFunding(
		sChannel,
		crypto.randomBytes(32),
		0,
		crypto.randomBytes(64)
	);
	const channelId = sChannel.getChannelId()!;
	sManager.handleFundingConfirmed(channelId);
	rManager.handleFundingConfirmed(channelId);
	const rChannel = rManager.getChannelsByPeer(sPub)[0];
	expect(sChannel.getState()).to.equal(ChannelState.NORMAL);
	expect(rChannel.getState()).to.equal(ChannelState.NORMAL);
	sManager.handleNewBlock(TIP);
	rManager.handleNewBlock(TIP);
	link.log.length = 0;
	const pair: IPair = {
		link,
		sManager,
		rManager,
		sPub,
		rPub,
		sChannel,
		rChannel,
		channelId,
		sConfig,
		rConfig,
		sErrors,
		rErrors,
		rForwarded: 0
	};
	rManager.on('htlc:forwarded', () => {
		pair.rForwarded++;
	});
	return pair;
}

function terms(amounts = AMOUNTS): {
	voucherAmountsMsat: bigint[];
	minPaymentMsat: bigint;
	settlementDeadline: number;
	voucherExpiry: number;
	feeBaseMsat: number;
	feeProportionalMillionths: number;
} {
	return {
		voucherAmountsMsat: amounts,
		minPaymentMsat: 400_000n,
		settlementDeadline: D_DEADLINE,
		voucherExpiry: T_EXP,
		feeBaseMsat: 1000,
		feeProportionalMillionths: 5000
	};
}

function record(ch: Channel): IFforEpochRecord {
	const f = ch.getFforEpoch();
	expect(f, 'epoch record').to.not.equal(null);
	return f!;
}

function why(pair: IPair): string {
	return JSON.stringify({
		sErrors: pair.sErrors,
		rErrors: pair.rErrors,
		wire: pair.link.types(),
		sState: FforState[record(pair.sChannel).state],
		rState: FforState[record(pair.rChannel).state],
		sChannel: ChannelState[pair.sChannel.getState()],
		rChannel: ChannelState[pair.rChannel.getState()],
		sHtlcs: pair.sChannel.getFullState().htlcs.size,
		rHtlcs: pair.rChannel.getFullState().htlcs.size,
		rUnwindOwed: record(pair.rChannel).unwindOwed
	});
}

function activate(pair: IPair, epochId?: Buffer): void {
	const res = pair.rManager.initiateFforEpoch(pair.channelId, {
		...terms(),
		...(epochId ? { epochId } : {})
	});
	expect(res.ok, res.error).to.equal(true);
	expect(record(pair.sChannel).state, why(pair)).to.equal(FforState.ACTIVE);
	expect(record(pair.rChannel).state, why(pair)).to.equal(FforState.ACTIVE);
}

/**
 * Crash one side: serialize its channel, bring up a fresh manager and
 * Channel from those bytes, and rewire the pair to it. The link is left
 * disconnected; call pair.link.reconnect() to reestablish.
 */
function restartSide(pair: IPair, side: 'S' | 'R'): void {
	const old = side === 'S' ? pair.sChannel : pair.rChannel;
	const config = side === 'S' ? pair.sConfig : pair.rConfig;
	const peer = side === 'S' ? pair.rPub : pair.sPub;
	const state = deserializeChannelState(
		JSON.parse(JSON.stringify(serializeChannelState(old.getFullState())))
	);
	const manager = new ChannelManager(config);
	const errors = side === 'S' ? pair.sErrors : pair.rErrors;
	manager.on('error', (_id: Buffer | null, msg: string) => errors.push(msg));
	if (side === 'R') {
		manager.on('htlc:forwarded', () => {
			pair.rForwarded++;
		});
	}
	const channel = new Channel(state);
	manager.restoreChannel(channel, peer);
	manager.handleNewBlock(TIP);
	if (side === 'S') {
		pair.sManager = manager;
		pair.sChannel = channel;
		pair.link = new Link(manager, pair.sPub, pair.rManager, pair.rPub);
	} else {
		pair.rManager = manager;
		pair.rChannel = channel;
		pair.link = new Link(pair.sManager, pair.sPub, manager, pair.rPub);
	}
	pair.link.connected = false;
}

type Interruption = 'disconnect' | 'restart-S' | 'restart-R';

/** Sever the pair the named way, then reestablish. */
function interrupt(pair: IPair, how: Interruption): void {
	pair.link.disconnect();
	if (how === 'restart-S') restartSide(pair, 'S');
	if (how === 'restart-R') restartSide(pair, 'R');
	pair.link.log.length = 0;
	pair.link.reconnect();
}

// ─────────────── Three-node harness ───────────────

function makeNodeConfig(seedId: number, storage?: SqliteStorage): INodeConfig {
	const seed = sha(`ffor-adv-node-${seedId}`);
	return {
		...(storage ? { storage } : {}),
		nodePrivateKey: sha(seed, 'node-identity'),
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: sha(seed, 'per-commitment'),
		fundingPrivkey: sha(seed, Buffer.from([0])),
		htlcBasepointSecret: sha(seed, Buffer.from([4]))
	};
}

interface INodeWireEntry {
	from: string;
	type: number;
	payload: Buffer;
}

class NodeLink {
	readonly log: INodeWireEntry[] = [];
	connected = true;
	drop: ((from: string, type: number, payload: Buffer) => boolean) | null =
		null;
	private queue: INodeWireEntry[] | null = null;

	constructor(
		readonly a: LightningNode,
		readonly b: LightningNode
	) {
		a.on(
			'message:outbound',
			(pubkey: string, type: number, payload: Buffer) => {
				if (pubkey === b.getNodeId())
					this.deliver(a.getNodeId(), type, payload);
			}
		);
		b.on(
			'message:outbound',
			(pubkey: string, type: number, payload: Buffer) => {
				if (pubkey === a.getNodeId())
					this.deliver(b.getNodeId(), type, payload);
			}
		);
	}

	private deliver(from: string, type: number, payload: Buffer): void {
		if (!this.connected) return;
		if (this.drop && this.drop(from, type, payload)) return;
		if (this.queue) {
			this.queue.push({ from, type, payload });
			return;
		}
		this.direct({ from, type, payload });
	}

	private direct(m: INodeWireEntry): void {
		this.log.push(m);
		const to = m.from === this.a.getNodeId() ? this.b : this.a;
		to.handlePeerMessage(m.from, m.type, m.payload);
	}

	disconnect(): void {
		this.connected = false;
		this.a.getChannelManager().handlePeerDisconnected(this.b.getNodeId());
		this.b.getChannelManager().handlePeerDisconnected(this.a.getNodeId());
	}

	reconnect(): void {
		this.connected = true;
		this.queue = [];
		this.a.getChannelManager().handlePeerReconnected(this.b.getNodeId());
		this.b.getChannelManager().handlePeerReconnected(this.a.getNodeId());
		while (this.queue.length > 0) this.direct(this.queue.shift()!);
		this.queue = null;
	}
}

function openReadyChannel(
	opener: LightningNode,
	acceptor: LightningNode,
	fundingSatoshis = 1_000_000n
): Buffer {
	const channel = opener.openChannel(acceptor.getNodeId(), fundingSatoshis);
	const channelId = opener.createFunding(
		channel,
		crypto.randomBytes(32),
		0,
		crypto.randomBytes(64)
	)!;
	opener.handleFundingConfirmed(channelId);
	acceptor.handleFundingConfirmed(channelId);
	for (const n of [opener, acceptor]) {
		for (const ch of n.getChannelManager().listChannels()) {
			const st = ch.getFullState();
			st.announceChannel = true;
			st.announcementSigsSent = true;
			st.announcementSigsReceived = true;
		}
	}
	return channelId;
}

function publishChannel(
	viewer: LightningNode,
	x: LightningNode,
	y: LightningNode,
	channelId: Buffer,
	scid: Buffer
): void {
	const xk = Buffer.from(x.getNodeId(), 'hex');
	const yk = Buffer.from(y.getNodeId(), 'hex');
	const xFirst = Buffer.compare(xk, yk) < 0;
	viewer.getGraph().addChannelAnnouncement({
		nodeSignature1: Buffer.alloc(64),
		nodeSignature2: Buffer.alloc(64),
		bitcoinSignature1: Buffer.alloc(64),
		bitcoinSignature2: Buffer.alloc(64),
		features: Buffer.alloc(0),
		chainHash: REGTEST_CHAIN_HASH,
		shortChannelId: scid,
		nodeId1: xFirst ? xk : yk,
		nodeId2: xFirst ? yk : xk,
		bitcoinKey1: Buffer.alloc(33, 2),
		bitcoinKey2: Buffer.alloc(33, 3)
	});
	for (const channelFlags of [0, 1]) {
		viewer.getGraph().applyChannelUpdate({
			signature: Buffer.alloc(64),
			chainHash: REGTEST_CHAIN_HASH,
			shortChannelId: scid,
			timestamp: Math.floor(Date.now() / 1000),
			messageFlags: 1,
			channelFlags,
			cltvExpiryDelta: 40,
			htlcMinimumMsat: 1000n,
			feeBaseMsat: 1000,
			feeProportionalMillionths: 1,
			htlcMaximumMsat: 1_000_000_000n
		});
	}
	viewer.registerChannelScid(channelId, scid);
	x.registerChannelScid(channelId, scid);
	y.registerChannelScid(channelId, scid);
}

const NODE_AMOUNTS = [1_000_000n, 546_250n, 2_000_000n];

interface IWorld {
	p: LightningNode;
	s: LightningNode;
	r: LightningNode;
	sConfig: INodeConfig;
	ps: NodeLink;
	sr: NodeLink;
	psChannelId: Buffer;
	srChannelId: Buffer;
	srHex: string;
	psHex: string;
	errors: { p: string[]; s: string[]; r: string[] };
}

let worldSeed = 0;

function createWorld(
	opts: { sStorage?: SqliteStorage; rStorage?: SqliteStorage } = {}
): IWorld {
	worldSeed += 10;
	const pConfig = makeNodeConfig(worldSeed + 1);
	const sConfig = makeNodeConfig(worldSeed + 2, opts.sStorage);
	const rConfig = makeNodeConfig(worldSeed + 3, opts.rStorage);
	const p = new LightningNode(pConfig);
	const s = new LightningNode(sConfig);
	const r = new LightningNode(rConfig);
	const errors = { p: [] as string[], s: [] as string[], r: [] as string[] };
	p.on('node:error', (e: { message: string }) => errors.p.push(e.message));
	s.on('node:error', (e: { message: string }) => errors.s.push(e.message));
	r.on('node:error', (e: { message: string }) => errors.r.push(e.message));
	const ps = new NodeLink(p, s);
	const sr = new NodeLink(s, r);
	const psChannelId = openReadyChannel(p, s, 1_000_000n);
	const srChannelId = openReadyChannel(s, r, 1_000_000n);
	const scidPS = encodeShortChannelId({
		block: 500,
		txIndex: 1,
		outputIndex: 0
	});
	const scidSR = encodeShortChannelId({
		block: 500,
		txIndex: 2,
		outputIndex: 0
	});
	publishChannel(p, p, s, psChannelId, scidPS);
	publishChannel(s, s, r, srChannelId, scidSR);
	for (const n of [p, s, r]) n.handleNewBlock(TIP);
	ps.log.length = 0;
	sr.log.length = 0;
	return {
		p,
		s,
		r,
		sConfig,
		ps,
		sr,
		psChannelId,
		srChannelId,
		srHex: srChannelId.toString('hex'),
		psHex: psChannelId.toString('hex'),
		errors
	};
}

function nodeRecord(node: LightningNode, srHex: string): IFforEpochRecord {
	const f = node.getFforEpoch(srHex);
	expect(f, 'epoch record').to.not.equal(null);
	return f!;
}

function activateWorld(w: IWorld): void {
	const res = w.r.startFforEpoch(w.srHex, {
		voucherAmountsMsat: NODE_AMOUNTS,
		minPaymentMsat: 400_000n,
		settlementDeadline: D_DEADLINE,
		voucherExpiry: T_EXP,
		feeBaseMsat: 1000,
		feeProportionalMillionths: 5000
	});
	expect(res.ok, res.error).to.equal(true);
	expect(nodeRecord(w.s, w.srHex).state, JSON.stringify(w.errors)).to.equal(
		FforState.ACTIVE
	);
	expect(nodeRecord(w.r, w.srHex).state).to.equal(FforState.ACTIVE);
}

/** Make a storage's channel write fail whenever `when` holds; returns a restore. */
function failSaveWhen(
	storage: SqliteStorage,
	when: (id: string, state: IChannelState) => boolean
): { count: () => number; restore: () => void } {
	const orig = storage.saveChannel.bind(storage);
	let failures = 0;
	storage.saveChannel = (
		id: string,
		state: IChannelState,
		peer: string
	): void => {
		if (when(id, state)) {
			failures++;
			throw new Error('disk full');
		}
		orig(id, state, peer);
	};
	return {
		count: (): number => failures,
		restore: (): void => {
			storage.saveChannel = orig;
		}
	};
}

/**
 * Crash S: a fresh LightningNode from the same SQLite storage, with P and R
 * still holding their live state. Both links come back disconnected.
 */
function restartS(w: IWorld): void {
	w.ps.connected = false;
	w.sr.connected = false;
	const sId = w.s.getNodeId();
	if (
		w.p.getChannelManager().getChannel(w.psChannelId)!.getState() ===
		ChannelState.NORMAL
	) {
		w.p.getChannelManager().handlePeerDisconnected(sId);
	}
	if (
		w.r.getChannelManager().getChannel(w.srChannelId)!.getState() ===
		ChannelState.NORMAL
	) {
		w.r.getChannelManager().handlePeerDisconnected(sId);
	}
	const s2 = new LightningNode(w.sConfig);
	s2.on('node:error', (e: { message: string }) => w.errors.s.push(e.message));
	s2.handleNewBlock(TIP);
	expect(s2.getNodeId()).to.equal(sId);
	expect(s2.getChannelManager().listChannels().length).to.equal(2);
	w.s = s2;
	w.ps = new NodeLink(w.p, s2);
	w.sr = new NodeLink(s2, w.r);
	w.ps.connected = false;
	w.sr.connected = false;
}

// ─────────────── Findings: channel-level matrix ───────────────

describe('FFOR Variant D adversarial recovery: reestablish and restart matrix', function () {
	this.timeout(60_000);

	/**
	 * Section 7.5.5: "An R MUST therefore keep its ACTIVATING record across a
	 * disconnect until the reestablish answers, which is the only pre-ACTIVE
	 * state a disconnect does not erase." and "S MUST NOT abort (it never
	 * aborts from ACTIVE) ... and R MUST complete ACTIVATING -> ACTIVE on
	 * receiving [the ack] with a matching H_act." The timeout the spec grants
	 * is S's ("S SHOULD abort a setup that has not reached ACTIVE within 60
	 * seconds of stfu").
	 *
	 * Observed: the manager arms the 60 s setup timer on R too, in every
	 * pre-ACTIVE state including ACTIVATING, and fforSetupTimedOut aborts an
	 * ACTIVATING R. With S already ACTIVE (acknowledgement loss) R records
	 * ABORTED, fails the vouchers, and S, which cannot leave ACTIVE, fails the
	 * channel with a wire error on the first update_fail_htlc.
	 */
	it('R does not abort an ACTIVATING record on its own timer while the reestablish is owed', () => {
		const pair = createPair();
		pair.link.drop = (_from, type): boolean =>
			type === MessageType.FF_ACTIVATE_ACK;
		expect(
			pair.rManager.initiateFforEpoch(pair.channelId, terms()).ok
		).to.equal(true);
		expect(record(pair.sChannel).state).to.equal(FforState.ACTIVE);
		expect(record(pair.rChannel).state).to.equal(FforState.ACTIVATING);
		pair.link.disconnect();
		// The 60 s timer fires while the peer is away.
		pair.rManager.fforSetupTimeout(pair.channelId);
		pair.link.log.length = 0;
		pair.link.reconnect();
		expect(record(pair.rChannel).state, why(pair)).to.equal(FforState.ACTIVE);
		expect(pair.sChannel.getState(), why(pair)).to.equal(ChannelState.NORMAL);
		expect(pair.rChannel.getState(), why(pair)).to.equal(ChannelState.NORMAL);
	});

	/**
	 * Section 9.5.1 "Abort after the voucher round": "R MUST send
	 * update_fail_htlc for every voucher as soon as the channel is
	 * synchronized after the abort". Section 7.5.5: before ACTIVE a
	 * disconnect aborts the setup on both sides and "a Variant D voucher round
	 * survives as ordinary channel state and is unwound per 9.5.1".
	 *
	 * Observed, two mechanisms:
	 *  - Cut before S's commitment_signed reached R: R aborts at the
	 *    disconnect (_fforOnDisconnect) with no committed voucher, and
	 *    _fforMaybeUnwind clears unwindOwed because nothing is parked yet
	 *    (the reestablish's ABORTED arm does the same). S then replays its
	 *    adds per BOLT 2, _fforClassifyAdd parks them as vouchers of the
	 *    ABORTED epoch (fforVoucher = true), nothing re-arms the unwind, and
	 *    the K HTLCs sit committed in both views until T_exp.
	 *  - Cut after S's commitment_signed reached R: R aborts inside
	 *    markForReestablish and fails the vouchers THERE, before the channel
	 *    is synchronized. Those update_fail_htlc land in pendingLocalUpdates
	 *    and are replayed at reestablish ahead of R's retransmitted
	 *    commitment_signed, which does not cover them: S answers "Invalid
	 *    commitment signature" and both channels are ERRORED.
	 */
	const roundBoundaries: Array<{
		name: string;
		from: 'S' | 'R';
		type: number;
	}> = [
		{
			name: 'after ff_accept, before any add reached R',
			from: 'S',
			type: MessageType.UPDATE_ADD_HTLC
		},
		{
			name: 'after the adds, before S commitment_signed',
			from: 'S',
			type: MessageType.COMMITMENT_SIGNED
		},
		{
			name: 'after S commitment_signed, before R revoke_and_ack',
			from: 'R',
			type: MessageType.REVOKE_AND_ACK
		},
		{
			name: 'after R revoke_and_ack, before R commitment_signed',
			from: 'R',
			type: MessageType.COMMITMENT_SIGNED
		}
	];
	for (const b of roundBoundaries) {
		for (const how of ['disconnect', 'restart-S', 'restart-R'] as const) {
			it(`voucher round cut ${b.name} (${how}): both abort, every voucher failed once, nothing forwarded`, () => {
				const pair = createPair();
				const epochId = crypto.randomBytes(32);
				pair.link.cutAt(b.from, b.type);
				const res = pair.rManager.initiateFforEpoch(pair.channelId, {
					...terms(),
					epochId
				});
				expect(res.ok, res.error).to.equal(true);
				expect(record(pair.rChannel).state).to.be.oneOf([
					FforState.NEGOTIATING,
					FforState.VOUCHERS_COMMITTED
				]);
				interrupt(pair, how);
				expect(record(pair.sChannel).state, why(pair)).to.equal(
					FforState.ABORTED
				);
				expect(record(pair.rChannel).state, why(pair)).to.equal(
					FforState.ABORTED
				);
				expect(pair.sChannel.getState(), why(pair)).to.equal(
					ChannelState.NORMAL
				);
				expect(pair.rChannel.getState(), why(pair)).to.equal(
					ChannelState.NORMAL
				);
				expect(pair.sChannel.getFullState().htlcs.size, why(pair)).to.equal(0);
				expect(pair.rChannel.getFullState().htlcs.size, why(pair)).to.equal(0);
				expect(
					pair.rForwarded,
					'a voucher was dispatched as a payment'
				).to.equal(0);
				expect(pair.sChannel.getFullState().localBalanceMsat).to.equal(
					FUNDING_SATOSHIS * 1000n
				);
				expect(pair.sChannel.getFullState().localBalanceMsat).to.equal(
					pair.rChannel.getFullState().remoteBalanceMsat
				);
				// The epoch id is consumed on R.
				const again = pair.rManager.initiateFforEpoch(pair.channelId, {
					...terms(),
					epochId
				});
				expect(again.ok).to.equal(false);
				// And ordinary operation resumed: a fresh epoch activates.
				activate(pair);
			});
		}
	}

	/**
	 * Section 7.5.5: "R MUST retransmit ff_close whenever S reports ACTIVE
	 * while R has sent ff_close." Section 11.1: "a peer that is already
	 * DRAINING or CLOSED MUST answer a still-ACTIVE peer's reestablish by
	 * retransmitting ff_close_ack, not with an error."
	 *
	 * Observed: the ff_close retransmission is wired only under R's ACTIVE
	 * arm. An R in DRAINING facing an S that reports ACTIVE (S restored from a
	 * backup taken before it processed ff_close) replays its drain updates
	 * straight into S's ACTIVE freeze, which fails the channel.
	 */
	it('R DRAINING facing S ACTIVE retransmits ff_close instead of driving the drain into the freeze', () => {
		const pair = createPair();
		activate(pair);
		record(pair.sChannel).slotStates[0] = FforSlotState.SETTLED;
		// Hold R's drain so both sides sit in DRAINING with the ack exchanged.
		pair.link.drop = (from, type): boolean =>
			from === 'R' &&
			(type === MessageType.UPDATE_FULFILL_HTLC ||
				type === MessageType.UPDATE_FAIL_HTLC ||
				type === MessageType.COMMITMENT_SIGNED);
		expect(pair.rManager.closeFforEpoch(pair.channelId).ok).to.equal(true);
		expect(record(pair.sChannel).state).to.equal(FforState.DRAINING);
		expect(record(pair.rChannel).state).to.equal(FforState.DRAINING);
		pair.link.disconnect();
		// S comes back from a backup that predates ff_close.
		const s = record(pair.sChannel);
		s.state = FforState.ACTIVE;
		s.closeWire = null;
		s.closeAckWire = null;
		s.settledBitmap = null;
		s.closeProcessed = false;
		pair.link.log.length = 0;
		pair.link.reconnect();
		expect(
			pair.link.log.some(
				(e) => e.from === 'R' && e.type === MessageType.FF_CLOSE
			),
			why(pair)
		).to.equal(true);
		expect(pair.sChannel.getState(), why(pair)).to.equal(ChannelState.NORMAL);
		expect(pair.rChannel.getState(), why(pair)).to.equal(ChannelState.NORMAL);
		expect(record(pair.sChannel).state, why(pair)).to.equal(FforState.CLOSED);
		expect(record(pair.rChannel).state, why(pair)).to.equal(FforState.CLOSED);
	});

	/**
	 * Section 7: "both sides MUST enforce per-channel uniqueness across all
	 * epochs *including aborted setups*".
	 *
	 * Observed: only aborted and refused ids are written to fforUsedEpochIds.
	 * A CLOSED epoch's id lives only on the record, and the next epoch
	 * overwrites the record, so once any later epoch exists the closed
	 * epoch's id is accepted again by both R (locally) and S.
	 */
	it('a CLOSED epoch id is refused for a later epoch on both sides', () => {
		const pair = createPair();
		const idA = crypto.randomBytes(32);
		activate(pair, idA);
		expect(pair.rManager.closeFforEpoch(pair.channelId).ok).to.equal(true);
		expect(record(pair.sChannel).state).to.equal(FforState.CLOSED);
		expect(record(pair.rChannel).state).to.equal(FforState.CLOSED);
		// A second epoch that aborts at a disconnect (S's stfu lost).
		pair.link.drop = (from, type): boolean =>
			from === 'S' && type === MessageType.STFU;
		expect(
			pair.rManager.initiateFforEpoch(pair.channelId, {
				...terms(),
				epochId: crypto.randomBytes(32)
			}).ok
		).to.equal(true);
		pair.link.disconnect();
		pair.link.reconnect();
		expect(record(pair.sChannel).state, why(pair)).to.equal(FforState.ABORTED);
		expect(record(pair.rChannel).state, why(pair)).to.equal(FforState.ABORTED);
		expect(pair.rChannel.getFullState().htlcs.size).to.equal(0);
		// Now the closed epoch's id again.
		pair.link.log.length = 0;
		const again = pair.rManager.initiateFforEpoch(pair.channelId, {
			...terms(),
			epochId: idA
		});
		const sAccepted =
			record(pair.sChannel).epochId.equals(idA) &&
			record(pair.sChannel).state !== FforState.ABORTED;
		expect(
			again.ok || sAccepted,
			`R accepted: ${again.ok}, S accepted: ${sAccepted}, wire ${JSON.stringify(
				pair.link.types()
			)}`
		).to.equal(false);
	});

	/**
	 * Section 9.5.1 step 3: R "MUST treat it as a voucher: it parks the HTLC,
	 * and MUST NOT fulfil it, fail it, or process its onion as a payment."
	 *
	 * Observed: the freeze guards start at ACTIVATING. While the round is
	 * still NEGOTIATING (S's revoke_and_ack not yet received) a parked
	 * voucher is committed on R and not quiescent, and the host API
	 * ChannelManager.failHtlc fails it.
	 */
	it('a host failHtlc on a parked voucher during the round is refused', () => {
		const pair = createPair();
		pair.link.drop = (from, type): boolean =>
			from === 'S' && type === MessageType.REVOKE_AND_ACK;
		expect(
			pair.rManager.initiateFforEpoch(pair.channelId, terms()).ok
		).to.equal(true);
		expect(record(pair.rChannel).state).to.equal(FforState.NEGOTIATING);
		const parked = [...pair.rChannel.getFullState().htlcs.values()].filter(
			(e) => e.fforVoucher === true && e.state === HtlcState.COMMITTED
		);
		expect(parked.length).to.equal(AMOUNTS.length);
		pair.link.drop = null;
		const res = pair.rManager.failHtlc(
			pair.channelId,
			parked[0].id,
			Buffer.alloc(292)
		);
		expect(res.ok, 'host failed a parked voucher').to.equal(false);
		expect(
			pair.rChannel.getFullState().htlcs.get(`received-${parked[0].id}`)!.state
		).to.equal(HtlcState.COMMITTED);
	});

	/**
	 * Section 7.5.1: "CLOSED: Every voucher is irrevocably resolved on both
	 * commitments (Variant D)". Section 7.5.6: "CLOSED is reached when no
	 * voucher remains in either commitment." Section 7.5.5: DRAINING -> CLOSED
	 * is "the last voucher irrevocably resolved on both commitments".
	 *
	 * Observed: R moves to CLOSED at S's revoke_and_ack for R's removal
	 * commitment, one full step before S's commitment_signed and R's own
	 * revoke_and_ack remove the vouchers from R's commitment. At that instant
	 * S is still DRAINING and R's freeze is lifted: an ordinary update R's
	 * host sends on the CLOSED event reaches S's freeze and fails the channel.
	 */
	it('R reports CLOSED only once no voucher remains in either commitment', () => {
		const pair = createPair();
		activate(pair);
		record(pair.sChannel).slotStates[0] = FforSlotState.SETTLED;
		let atClosed: {
			sVouchers: number;
			sState: FforState;
			rHtlcs: number;
		} | null = null;
		pair.rManager.on('ffor:state', (_id: Buffer, state: FforState) => {
			if (state === FforState.CLOSED && atClosed === null) {
				atClosed = {
					sVouchers: [...pair.sChannel.getFullState().htlcs.values()].filter(
						(e) => e.fforVoucher === true
					).length,
					sState: record(pair.sChannel).state,
					rHtlcs: pair.rChannel.getFullState().htlcs.size
				};
			}
		});
		expect(pair.rManager.closeFforEpoch(pair.channelId).ok).to.equal(true);
		expect(record(pair.rChannel).state).to.equal(FforState.CLOSED);
		expect(atClosed, 'no CLOSED event').to.not.equal(null);
		expect(
			atClosed!.sVouchers,
			`R announced CLOSED while S was ${FforState[atClosed!.sState]} with ${
				atClosed!.sVouchers
			} vouchers still in its commitment`
		).to.equal(0);
	});

	/**
	 * Section 11.1: "From the moment either side persisted ACTIVE, neither
	 * side may discard the epoch on any reestablish, whatever the peer
	 * reports". Section 7.5.1: "There is no transition out of ACTIVE except
	 * to DRAINING". An S that reports ABORTED to an ACTIVE R has violated the
	 * machine; R must at least notice, as it does for a missing TLV.
	 */
	it('R ACTIVE facing an S that reports ABORTED records the violation', () => {
		const pair = createPair();
		activate(pair);
		pair.link.disconnect();
		record(pair.sChannel).state = FforState.ABORTED;
		pair.link.reconnect();
		expect(record(pair.rChannel).state).to.equal(FforState.ACTIVE);
		expect(
			record(pair.rChannel).activationMismatch ||
				pair.rErrors.some((e) => /FFOR/.test(e)),
			why(pair)
		).to.equal(true);
	});
});

// ─────────────── Findings: settlement side ───────────────

describe('FFOR Variant D adversarial recovery: settlement peer', function () {
	this.timeout(60_000);

	/**
	 * Section 9.5.1 "Settlement": "S MUST keep per-slot state UNUSED ->
	 * SETTLING -> SETTLED durable across restart: a slot in SETTLING after a
	 * crash is resolved by the upstream channel's own reestablish (the fulfil
	 * either went out or it did not), never by settling again on a second
	 * HTLC." Section 7.5.4: a SETTLING slot "counts as settled: S has already
	 * committed to reveal t_k, and its preimage MUST be included" in
	 * ff_close_ack; S "MUST complete or fail upstream every delegated HTLC
	 * that was irrevocably committed upstream before it processed ff_close".
	 *
	 * Observed: fforTrySettleDelegated applies the section 7.5.6 stopping
	 * conditions (not ACTIVE, ff_close processed, tip at D) BEFORE it looks
	 * at the slot's SETTLING record. When S restarts with a slot SETTLING and
	 * R returns and closes before the upstream channel reestablishes, the ack
	 * hands R t_k and R fulfils the voucher, then the upstream re-drive fails
	 * P's HTLC with temporary_node_failure: S paid R and was never paid.
	 */
	it('a SETTLING slot re-driven after a restart fulfils upstream even though ff_close was processed meanwhile', () => {
		const storage = new SqliteStorage(':memory:');
		storage.open();
		const w = createWorld({ sStorage: storage });
		activateWorld(w);
		const inv = w.r.createFforVoucherInvoice(w.srHex, 1).bolt11;
		const hash = decodeInvoice(inv).paymentHash;
		w.sr.disconnect();
		// The crash window: SETTLING is durable, the upstream fulfil is not.
		const fault = failSaveWhen(
			storage,
			(id, st) =>
				id === w.psHex &&
				[...st.htlcs.values()].some((e) => e.state === HtlcState.FULFILLED)
		);
		w.p.sendPayment(inv);
		expect(fault.count()).to.be.at.least(1);
		fault.restore();
		expect(w.p.getPayment(hash)!.status).to.equal(PaymentStatus.PENDING);
		const onDisk = storage.loadChannel(w.srHex)!.state.ffor!;
		expect(onDisk.slotStates[0]).to.be.oneOf([
			FforSlotState.SETTLING,
			FforSlotState.SETTLED
		]);
		const t1 = onDisk.preimages[0];

		restartS(w);
		// R returns first and closes.
		w.sr.reconnect();
		expect(nodeRecord(w.r, w.srHex).state).to.equal(FforState.ACTIVE);
		const rBefore = w.r
			.getChannelManager()
			.getChannel(w.srChannelId)!
			.getFullState().localBalanceMsat;
		expect(w.r.closeFforEpoch(w.srHex).ok).to.equal(true);
		expect(nodeRecord(w.r, w.srHex).knownPreimages[0]!.equals(t1)).to.equal(
			true
		);
		const rAfter = w.r
			.getChannelManager()
			.getChannel(w.srChannelId)!
			.getFullState().localBalanceMsat;
		expect(rAfter).to.equal(rBefore + NODE_AMOUNTS[0]);

		// Then the upstream channel reestablishes and re-drives the slot.
		w.ps.reconnect();
		const payment = w.p.getPayment(hash)!;
		expect(
			payment.status,
			`S revealed t_1 to R but the upstream HTLC ended ${
				PaymentStatus[payment.status]
			}; S errors: ${JSON.stringify(w.errors.s)}`
		).to.equal(PaymentStatus.COMPLETED);
		expect(payment.preimage!.equals(t1)).to.equal(true);
	});

	/**
	 * Same sentences as above. Here R has not returned; S restarts a few
	 * blocks later, so the upstream HTLC's cltv_expiry is now inside S's
	 * safety delta. The section 8 margin check governs whether S may BEGIN a
	 * settlement; a slot already SETTLING has begun, and "the fulfil either
	 * went out or it did not" is the only question left.
	 *
	 * Observed: the re-drive fails P's HTLC on the CLTV margin, the slot stays
	 * SETTLING, and the next ff_close_ack will still reveal t_1.
	 */
	it('a SETTLING slot re-driven after a restart fulfils upstream even when the CLTV margin has since closed', () => {
		const storage = new SqliteStorage(':memory:');
		storage.open();
		const w = createWorld({ sStorage: storage });
		activateWorld(w);
		const inv = w.r.createFforVoucherInvoice(w.srHex, 1).bolt11;
		const hash = decodeInvoice(inv).paymentHash;
		w.sr.disconnect();
		const fault = failSaveWhen(
			storage,
			(id, st) =>
				id === w.psHex &&
				[...st.htlcs.values()].some((e) => e.state === HtlcState.FULFILLED)
		);
		w.p.sendPayment(inv);
		expect(fault.count()).to.be.at.least(1);
		fault.restore();
		const t1 = storage.loadChannel(w.srHex)!.state.ffor!.preimages[0];

		restartS(w);
		const upstream = [
			...w.s
				.getChannelManager()
				.getChannel(w.psChannelId)!
				.getFullState()
				.htlcs.values()
		].find((e) => e.paymentHash.equals(hash))!;
		expect(upstream).to.not.equal(undefined);
		// S was down long enough for the upstream margin to close.
		w.s.handleNewBlock(upstream.cltvExpiry - 30);
		w.ps.reconnect();
		const payment = w.p.getPayment(hash)!;
		// Then R returns and closes: the slot is still recorded as settled.
		w.sr.reconnect();
		expect(w.r.closeFforEpoch(w.srHex).ok).to.equal(true);
		const bitmap = nodeRecord(w.s, w.srHex).settledBitmap!;
		const revealed = nodeRecord(w.r, w.srHex).knownPreimages[0];
		expect(
			payment.status,
			`slot 1 is ${
				nodeRecord(w.s, w.srHex).slotStates[0]
			}, ff_close_ack bit 1 ${bitmapGet(bitmap, 1) ? 'set' : 'clear'}${
				revealed && revealed.equals(t1) ? ' with t_1 handed to R' : ''
			}, yet the upstream HTLC ended ${PaymentStatus[payment.status]}`
		).to.equal(PaymentStatus.COMPLETED);
		expect(payment.preimage!.equals(t1)).to.equal(true);
	});

	/**
	 * Section 7.5.6: "An invoice exposed earlier is an invoice an honest S
	 * will not settle". Section 7.5.5: "Two ACTIVE peers reporting different
	 * H_act values have a protocol error: R enforces on-chain (its vouchers
	 * are real regardless) and S stops settling."
	 *
	 * Observed: R records activationMismatch, S stops settling, but R's
	 * createFforVoucherInvoice checks only state === ACTIVE and keeps handing
	 * out invoices that every payment against will fail.
	 */
	it('R stops exposing invoices once the peer reports a different H_act', () => {
		const w = createWorld();
		activateWorld(w);
		w.sr.disconnect();
		nodeRecord(w.s, w.srHex).hAct = crypto.randomBytes(32);
		w.sr.reconnect();
		expect(nodeRecord(w.r, w.srHex).activationMismatch).to.equal(true);
		expect(() => w.r.createFforVoucherInvoice(w.srHex, 2)).to.throw();
	});

	/**
	 * Section 7.5.4: "R MUST verify activation_hash against its own H_act,
	 * persist ACTIVE with it, and only then treat the epoch as live."
	 * Section 7.5.5: R's ACTIVE is durable "before exposing any invoice".
	 *
	 * Observed: ChannelManager.processActions emits 'ffor:state' before it
	 * dispatches the batch's PERSIST_STATE. A host acting on the ACTIVE event
	 * (the documented way to learn the epoch is live) runs while the record
	 * is still ACTIVATING on disk, and createFforVoucherInvoice succeeds from
	 * inside that handler even when the write then fails.
	 */
	it("the 'ffor:state' ACTIVE event on R fires only after ACTIVE is durable", () => {
		const storage = new SqliteStorage(':memory:');
		storage.open();
		const w = createWorld({ rStorage: storage });
		let fault: { count: () => number; restore: () => void } | null = null;
		w.sr.drop = (_from, type): boolean => {
			if (type === MessageType.FF_ACTIVATE_ACK && !fault) {
				fault = failSaveWhen(
					storage,
					(id, st) => id === w.srHex && st.ffor?.state === FforState.ACTIVE
				);
			}
			return false;
		};
		const seen: Array<{ state: FforState; onDisk: FforState | null }> = [];
		let exposed: string | null = null;
		w.r
			.getChannelManager()
			.on('ffor:state', (_id: Buffer, state: FforState) => {
				const onDisk = storage.loadChannel(w.srHex)?.state.ffor?.state ?? null;
				seen.push({ state, onDisk });
				if (state === FforState.ACTIVE) {
					try {
						exposed = w.r.createFforVoucherInvoice(w.srHex, 1).bolt11;
					} catch {
						exposed = null;
					}
				}
			});
		expect(
			w.r.startFforEpoch(w.srHex, {
				voucherAmountsMsat: NODE_AMOUNTS,
				minPaymentMsat: 400_000n,
				settlementDeadline: D_DEADLINE,
				voucherExpiry: T_EXP,
				feeBaseMsat: 1000,
				feeProportionalMillionths: 5000
			}).ok
		).to.equal(true);
		expect(fault!.count()).to.be.at.least(1);
		const premature = seen.filter(
			(e) => e.state === FforState.ACTIVE && e.onDisk !== FforState.ACTIVE
		);
		expect(
			premature.length,
			`ACTIVE announced with disk at ${premature
				.map((e) => (e.onDisk === null ? 'none' : FforState[e.onDisk]))
				.join(',')}; invoice exposed: ${exposed !== null}`
		).to.equal(0);
	});
});
