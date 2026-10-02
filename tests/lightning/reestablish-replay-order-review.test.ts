/**
 * Ordinary recovery regressions selected from the saved PR #1306 review.
 *
 * Exercise honest traffic, connection cuts, persisted restarts, each
 * delivered prefix, splice batches, taproot, the FFOR hold and cooperative
 * close after pending removals. Both balances and the next payment must
 * remain usable after convergence.
 *
 * Diagnostic pins for pre-existing malformed-row, stale-backup, splice and
 * channel_ready follow-ups remain in the original review file. They are
 * tracked separately in #1305.
 *
 * REPLAY_ORDER_SEEDS and REPLAY_ORDER_TAPROOT_SEEDS size the seeded flows.
 * REPLAY_ORDER_DUMP optionally saves their deterministic wire traces.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import fs from 'fs';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import { Channel } from '../../src/lightning/channel/channel';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	isTaprootChannel,
	receivedAddIrrevocablyCommitted
} from '../../src/lightning/channel/types';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { MessageType } from '../../src/lightning/message/types';
import { FforState, IFforEpochRecord } from '../../src/lightning/ffor/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	serializeChannelState,
	deserializeChannelState
} from '../../src/lightning/storage/serialization';

const sha256 = (b: Buffer): Buffer =>
	crypto.createHash('sha256').update(b).digest();

function makeConfig(name: string, taproot = false): IChannelManagerConfig {
	const seed = sha256(Buffer.from(`reest-adv-${name}`));
	const k = (i: number): Buffer =>
		sha256(Buffer.concat([seed, Buffer.from([i])]));
	const basepoints: IChannelBasepoints = {
		fundingPubkey: getPublicKey(k(0)),
		revocationBasepoint: getPublicKey(k(1)),
		paymentBasepoint: getPublicKey(k(2)),
		delayedPaymentBasepoint: getPublicKey(k(3)),
		htlcBasepoint: getPublicKey(k(4)),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
	return {
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: basepoints,
		localPerCommitmentSeed: sha256(Buffer.from(`${name}-commit`)),
		localFundingPrivkey: k(0),
		htlcBasepointSecret: k(4),
		nodePrivateKey: sha256(Buffer.from(`${name}-node`)),
		preferAnchors: true,
		...(taproot ? { preferTaproot: true } : {})
	};
}

const FUNDING_SATOSHIS = 1_000_000n;
const CAPACITY_MSAT = FUNDING_SATOSHIS * 1000n;
/** What the setup payment moves to B so B can offer HTLCs of its own. */
const B_FLOAT_MSAT = 300_000_000n;

type Side = 'A' | 'B';
const other = (s: Side): Side => (s === 'A' ? 'B' : 'A');
interface IQueued {
	from: string;
	to: string;
	type: number;
	p: Buffer;
}

interface IWire {
	cutBefore: (type: MessageType, fromB?: boolean) => void;
	/** Drop everything on the wire and everything sent from here on. */
	cut: () => void;
	dropFrom: (side: Side) => void;
	dropWhen: (filter: ((from: Side, type: number) => boolean) | null) => void;
	/** Both sides observe the disconnect (idempotent). */
	disconnect: () => void;
	reconnect: (opts?: {
		reorder?: (side: Side, types: IQueued[]) => IQueued[];
		deliverOnly?: number;
		/** Leave the answers on the wire; the test delivers them by step(). */
		manual?: boolean;
	}) => void;
	/** Manual mode: nothing is delivered until step() or drain(). */
	manual: (on: boolean) => void;
	/** Deliver the oldest undelivered message sent by `side`. */
	step: (side: Side) => boolean;
	pending: (side: Side) => number;
	pendingTypes: (side: Side) => string[];
	/** Deliver everything, picking the direction with `rng` at each step. */
	drain: (rng: () => number) => void;
	restartA: (fromRow?: boolean) => void;
	restartB: (fromRow?: boolean) => void;
	/** Restart a side from a row captured earlier (a stale backup). */
	restartWith: (side: Side, row: string) => void;
	replay: Record<Side, string[]>;
	delivered: string[];
	/** Every message put on the wire: side, type, payload hex. */
	sent: string[];
	/** The last row each manager asked to persist. */
	rows: Record<Side, string | null>;
}

interface IPair {
	tag: string;
	A: () => ChannelManager;
	B: () => ChannelManager;
	channelId: Buffer;
	aChannel: () => Channel;
	bChannel: () => Channel;
	errors: string[];
	fulfilled: Record<Side, Buffer[]>;
	failed: Record<Side, bigint[]>;
	wire: IWire;
	nextPreimage: () => Buffer;
	/** Every transaction a side asked to broadcast. */
	broadcasts: Record<Side, Buffer[]>;
}

function makePair(
	tag: string,
	taproot = false,
	/** Dropped from the very first message, until the first reconnect. */
	initialDrop: ((from: Side, type: number) => boolean) | null = null
): IPair {
	const aConfig = makeConfig(`${tag}-A`, taproot);
	const bConfig = makeConfig(`${tag}-B`, taproot);
	const aPub = getPublicKey(aConfig.nodePrivateKey!).toString('hex');
	const bPub = getPublicKey(bConfig.nodePrivateKey!).toString('hex');
	const managers = new Map<string, ChannelManager>();
	managers.set(aPub, new ChannelManager(aConfig));
	managers.set(bPub, new ChannelManager(bConfig));
	const errors: string[] = [];
	const fulfilled: Record<Side, Buffer[]> = { A: [], B: [] };
	const failed: Record<Side, bigint[]> = { A: [], B: [] };
	const replay: Record<Side, string[]> = { A: [], B: [] };
	const delivered: string[] = [];
	const sent: string[] = [];
	const rows: Record<Side, string | null> = { A: null, B: null };
	const broadcasts: Record<Side, Buffer[]> = { A: [], B: [] };
	const sideOf = (pub: string): Side => (pub === aPub ? 'A' : 'B');
	const pubOf = (side: Side): string => (side === 'A' ? aPub : bPub);

	let alive = true;
	let cutType: MessageType | null = null;
	let cutFromB = false;
	let dropped: Side | null = null;
	let deliverBudget: number | null = null;
	let dropFilter: ((from: Side, type: number) => boolean) | null = initialDrop;
	let paused = false;
	let pumping = false;
	let manualMode = false;
	let queue: IQueued[] = [];
	let preimageCounter = 0;

	const dispatch = (m: IQueued): void => {
		if (!alive) return;
		if (dropped === sideOf(m.from)) return;
		if (dropFilter && dropFilter(sideOf(m.from), m.type)) return;
		if (
			cutType !== null &&
			m.type === cutType &&
			(m.from === bPub) === cutFromB
		) {
			alive = false;
			cutType = null;
			return;
		}
		if (deliverBudget !== null) {
			if (deliverBudget === 0) {
				alive = false;
				deliverBudget = null;
				return;
			}
			deliverBudget--;
		}
		delivered.push(`${sideOf(m.from)}:${MessageType[m.type]}`);
		managers.get(m.to)!.handleMessage(m.from, m.type, m.p);
	};
	const pump = (): void => {
		if (paused || pumping || manualMode) return;
		pumping = true;
		try {
			while (queue.length > 0) dispatch(queue.shift()!);
		} finally {
			pumping = false;
		}
	};
	const attach = (pub: string, peer: string): void => {
		const m = managers.get(pub)!;
		const side = sideOf(pub);
		m.on('error', (_id, msg: string) => errors.push(`${side}: ${msg}`));
		m.on('htlc:fulfilled', (_c, _id, preimage: Buffer) =>
			fulfilled[side].push(preimage)
		);
		m.on('htlc:failed', (_c, id: bigint) => failed[side].push(id));
		m.on('broadcast:tx', (tx: Buffer) =>
			broadcasts[side].push(Buffer.from(tx))
		);
		m.on('channel:persist', (ev: { channel: Channel }) => {
			if (managers.get(pub) !== m) return;
			try {
				rows[side] = JSON.stringify(
					serializeChannelState(ev.channel.getFullState())
				);
			} catch {
				// A row that cannot be written is not a restart point.
			}
		});
		m.on('message:outbound', (to: string, type: number, p: Buffer) => {
			if (managers.get(pub) !== m) return;
			if (to !== peer) return;
			sent.push(`${side}:${MessageType[type] ?? type}:${p.toString('hex')}`);
			queue.push({ from: pub, to, type, p });
			pump();
		});
	};
	attach(aPub, bPub);
	attach(bPub, aPub);

	const aChan = managers.get(aPub)!.openChannel(bPub, FUNDING_SATOSHIS);
	managers
		.get(aPub)!
		.createFunding(
			aChan,
			sha256(Buffer.from(`${tag}-funding-txid`)),
			0,
			Buffer.concat([
				sha256(Buffer.from(`${tag}-funding-sig-0`)),
				sha256(Buffer.from(`${tag}-funding-sig-1`))
			])
		);
	const channelId = aChan.getChannelId()!;
	managers.get(aPub)!.handleFundingConfirmed(channelId);
	managers.get(bPub)!.handleFundingConfirmed(channelId);

	const chan = (pub: string, peer: string): Channel =>
		managers.get(pub)!.getChannelsByPeer(peer)[0];
	expect(chan(aPub, bPub).getState()).to.equal(ChannelState.NORMAL);

	const reestPayload = (c: Channel): Buffer =>
		(
			c
				.createReestablish()
				.find((x) => x.type === ChannelActionType.SEND_MESSAGE) as {
				payload: Buffer;
			}
		).payload;

	const restart = (
		pub: string,
		peer: string,
		fromRow: boolean,
		given?: string
	): void => {
		alive = false;
		queue = [];
		const config = pub === aPub ? aConfig : bConfig;
		const row = given
			? given
			: fromRow && rows[sideOf(pub)]
			? rows[sideOf(pub)]!
			: JSON.stringify(serializeChannelState(chan(pub, peer).getFullState()));
		const state = deserializeChannelState(JSON.parse(row));
		const fresh = new ChannelManager(config);
		fresh.restoreChannel(new Channel(state), peer);
		managers.set(pub, fresh);
		attach(pub, peer);
		managers.get(peer)!.handlePeerDisconnected(pub);
	};

	const disconnect = (): void => {
		alive = false;
		queue = [];
		const aC = chan(aPub, bPub);
		const bC = chan(bPub, aPub);
		if (aC.getState() !== ChannelState.AWAITING_REESTABLISH) {
			managers.get(aPub)!.handlePeerDisconnected(bPub);
		}
		if (bC.getState() !== ChannelState.AWAITING_REESTABLISH) {
			managers.get(bPub)!.handlePeerDisconnected(aPub);
		}
	};

	const step = (side: Side): boolean => {
		const i = queue.findIndex((m) => m.from === pubOf(side));
		if (i < 0) return false;
		const [m] = queue.splice(i, 1);
		dispatch(m);
		return true;
	};

	const wire: IWire = {
		cutBefore: (type: MessageType, fromB = false): void => {
			cutType = type;
			cutFromB = fromB;
		},
		cut: (): void => {
			alive = false;
			queue = [];
		},
		dropFrom: (side: Side): void => {
			dropped = side;
		},
		dropWhen: (filter): void => {
			dropFilter = filter;
		},
		disconnect,
		replay,
		delivered,
		sent,
		rows,
		manual: (on: boolean): void => {
			manualMode = on;
			if (!on) pump();
		},
		step,
		pending: (side: Side): number =>
			queue.filter((m) => m.from === pubOf(side)).length,
		pendingTypes: (side: Side): string[] =>
			queue
				.filter((m) => m.from === pubOf(side))
				.map((m) => MessageType[m.type]),
		drain: (rng: () => number): void => {
			let guard = 0;
			while (queue.length > 0) {
				if (++guard > 5000) throw new Error('wire never drained');
				const first: Side = rng() < 0.5 ? 'A' : 'B';
				if (!step(first)) step(other(first));
			}
		},
		reconnect: (opts): void => {
			disconnect();
			const a = managers.get(aPub)!;
			const b = managers.get(bPub)!;
			const aC = chan(aPub, bPub);
			const bC = chan(bPub, aPub);
			alive = true;
			cutType = null;
			dropped = null;
			dropFilter = null;
			deliverBudget = opts?.deliverOnly ?? null;
			delivered.length = 0;
			if (opts?.manual !== undefined) manualMode = opts.manual;
			paused = true;
			const aRe = reestPayload(aC);
			const bRe = reestPayload(bC);
			sent.push(`A:CHANNEL_REESTABLISH:${aRe.toString('hex')}`);
			sent.push(`B:CHANNEL_REESTABLISH:${bRe.toString('hex')}`);
			b.handleMessage(aPub, MessageType.CHANNEL_REESTABLISH, aRe);
			a.handleMessage(bPub, MessageType.CHANNEL_REESTABLISH, bRe);
			paused = false;
			replay.A = queue
				.filter((m) => m.from === aPub)
				.map((m) => MessageType[m.type]);
			replay.B = queue
				.filter((m) => m.from === bPub)
				.map((m) => MessageType[m.type]);
			if (opts?.reorder) {
				const fromB = opts.reorder(
					'B',
					queue.filter((m) => m.from === bPub)
				);
				const fromA = opts.reorder(
					'A',
					queue.filter((m) => m.from === aPub)
				);
				queue = [...fromB, ...fromA];
			}
			pump();
		},
		restartA: (fromRow = false): void => restart(aPub, bPub, fromRow),
		restartB: (fromRow = false): void => restart(bPub, aPub, fromRow),
		restartWith: (side: Side, row: string): void =>
			restart(pubOf(side), pubOf(other(side)), false, row)
	};

	return {
		tag,
		A: (): ChannelManager => managers.get(aPub)!,
		B: (): ChannelManager => managers.get(bPub)!,
		channelId,
		aChannel: (): Channel => chan(aPub, bPub),
		bChannel: (): Channel => chan(bPub, aPub),
		errors,
		fulfilled,
		failed,
		wire,
		broadcasts,
		nextPreimage: (): Buffer =>
			sha256(Buffer.from(`${tag}-preimage-${preimageCounter++}`))
	};
}

const ONION = Buffer.alloc(1366);
const ADD = 'UPDATE_ADD_HTLC';
const FULFILL = 'UPDATE_FULFILL_HTLC';
const FAIL = 'UPDATE_FAIL_HTLC';
const SIG = 'COMMITMENT_SIGNED';
const RAA = 'REVOKE_AND_ACK';

interface IPayment {
	preimage: Buffer;
	hash: Buffer;
	amountMsat: bigint;
}

const mgr = (t: IPair, side: Side): ChannelManager =>
	side === 'A' ? t.A() : t.B();
const chanOf = (t: IPair, side: Side): Channel =>
	side === 'A' ? t.aChannel() : t.bChannel();

function offer(t: IPair, from: Side, amountMsat: bigint): IPayment {
	const preimage = t.nextPreimage();
	const hash = sha256(preimage);
	mgr(t, from).addHtlc(t.channelId, amountMsat, hash, 900, ONION);
	return { preimage, hash, amountMsat };
}

function findReceivedId(t: IPair, receiver: Side, hash: Buffer): bigint | null {
	const entry = [...chanOf(t, receiver).getFullState().htlcs.entries()].find(
		([key, h]) => key.startsWith('received-') && h.paymentHash.equals(hash)
	);
	return entry ? entry[1].id : null;
}

/** The id of a received HTLC the node layer may settle (BOLT 2). */
function findSettleableId(
	t: IPair,
	receiver: Side,
	hash: Buffer
): bigint | null {
	const entry = [...chanOf(t, receiver).getFullState().htlcs.entries()].find(
		([key, h]) =>
			key.startsWith('received-') &&
			h.paymentHash.equals(hash) &&
			receivedAddIrrevocablyCommitted(h)
	);
	return entry ? entry[1].id : null;
}

function receivedId(t: IPair, receiver: Side, p: IPayment): bigint {
	const id = findReceivedId(t, receiver, p.hash);
	expect(id, `${receiver} holds the HTLC`).to.not.equal(null);
	return id!;
}

function settle(t: IPair, receiver: Side, p: IPayment): void {
	mgr(t, receiver).fulfillHtlc(
		t.channelId,
		receivedId(t, receiver, p),
		p.preimage
	);
}

function makeFundedPair(tag: string, taproot = false): IPair {
	const t = makePair(tag, taproot);
	const float = offer(t, 'A', B_FLOAT_MSAT);
	settle(t, 'B', float);
	expect(t.errors, t.errors.join('; ')).to.have.length(0);
	expect(t.bChannel().getBalances().localMsat).to.equal(B_FLOAT_MSAT);
	t.fulfilled.A.length = 0;
	return t;
}

function queueOf(c: Channel): { types: string[]; signed: number } {
	const s = c.getFullState();
	return {
		types: s.pendingLocalUpdates.map((u) => MessageType[u.type]),
		signed: s.pendingLocalUpdatesSignedCount
	};
}

function expectLevel(t: IPair): void {
	expect(t.errors, t.errors.join('; ')).to.have.length(0);
	const a = t.aChannel();
	const b = t.bChannel();
	expect(a.getState(), 'A state').to.equal(ChannelState.NORMAL);
	expect(b.getState(), 'B state').to.equal(ChannelState.NORMAL);
	for (const [name, c] of [
		['A', a],
		['B', b]
	] as Array<[string, Channel]>) {
		expect(queueOf(c).types, `${name} queue`).to.deep.equal([]);
		expect(queueOf(c).signed, `${name} signed count`).to.equal(0);
		expect(c.needsCommitment(), `${name} owes a signature`).to.equal(false);
		expect(
			c.isAwaitingRemoteRevocation(),
			`${name} awaits a revocation`
		).to.equal(false);
	}
	const as = a.getFullState();
	const bs = b.getFullState();
	expect(as.remoteCommitmentNumber, 'A signed == B revoked up to').to.equal(
		bs.localCommitmentNumber
	);
	expect(bs.remoteCommitmentNumber, 'B signed == A revoked up to').to.equal(
		as.localCommitmentNumber
	);
	expect(a.getBalances().localMsat).to.equal(b.getBalances().remoteMsat);
	expect(b.getBalances().localMsat).to.equal(a.getBalances().remoteMsat);
}

function expectStillUsable(t: IPair): void {
	const aBefore = t.aChannel().getBalances().localMsat;
	const bBefore = t.bChannel().getBalances().localMsat;
	const ab = offer(t, 'A', 3_000_000n);
	settle(t, 'B', ab);
	const ba = offer(t, 'B', 2_000_000n);
	settle(t, 'A', ba);
	expectLevel(t);
	expect(t.aChannel().getBalances().localMsat).to.equal(aBefore - 1_000_000n);
	expect(t.bChannel().getBalances().localMsat).to.equal(bBefore + 1_000_000n);
	expect(t.aChannel().getFullState().htlcs.size).to.equal(0);
	expect(t.bChannel().getFullState().htlcs.size).to.equal(0);
}

// ─────────────────────────── flow driver ───────────────────────────

function rngOf(seed: number): () => number {
	let a = (seed * 0x9e3779b1 + 0x85ebca6b) >>> 0;
	return (): number => {
		a = (a + 0x6d2b79f5) >>> 0;
		let x = a;
		x = Math.imul(x ^ (x >>> 15), x | 1);
		x ^= x + Math.imul(x ^ (x >>> 7), x | 61);
		return ((x ^ (x >>> 14)) >>> 0) / 4294967296;
	};
}

interface IFlowPayment extends IPayment {
	from: Side;
	outcome: 'open' | 'fulfilled' | 'failed';
}
type ResolveKind = 'fulfil' | 'fail' | 'malformed';

/**
 * Traffic as an honest node layer drives it: a received HTLC is settled only
 * once it is irrevocably committed, a refused operation leaves no trace, and
 * finish() demands full convergence.
 */
interface IDriver {
	t: IPair;
	payments: IFlowPayment[];
	script: string[];
	add: (side: Side, amountMsat: bigint) => IFlowPayment | null;
	resolve: (
		side: Side,
		kind: ResolveKind,
		startAt?: (n: number) => number
	) => boolean;
	fee: (rate: number) => boolean;
	finish: () => void;
}

function makeDriver(pair: IPair, script: string[] = []): IDriver {
	const payments: IFlowPayment[] = [];
	const add = (side: Side, amountMsat: bigint): IFlowPayment | null => {
		const preimage = pair.nextPreimage();
		const hash = sha256(preimage);
		const before = pair.errors.length;
		const r = mgr(pair, side).addHtlc(
			pair.channelId,
			amountMsat,
			hash,
			900,
			ONION
		);
		if (!r.ok) {
			pair.errors.length = before;
			script.push(`add${side}-refused`);
			return null;
		}
		const p: IFlowPayment = {
			preimage,
			hash,
			amountMsat,
			from: side,
			outcome: 'open'
		};
		payments.push(p);
		script.push(`add${side}`);
		return p;
	};
	const resolve = (
		side: Side,
		kind: ResolveKind,
		startAt: (n: number) => number = (): number => 0
	): boolean => {
		const open = payments.filter(
			(p) => p.from !== side && p.outcome === 'open'
		);
		const start = open.length > 0 ? startAt(open.length) : 0;
		for (let i = 0; i < open.length; i++) {
			const p = open[(start + i) % open.length];
			const id = findSettleableId(pair, side, p.hash);
			if (id === null) continue;
			const before = pair.errors.length;
			const m = mgr(pair, side);
			const r =
				kind === 'fulfil'
					? m.fulfillHtlc(pair.channelId, id, p.preimage)
					: kind === 'fail'
					? m.failHtlc(pair.channelId, id, Buffer.from('no'))
					: m.failMalformedHtlc(pair.channelId, id, sha256(ONION), 0xc005);
			if (!r.ok) {
				pair.errors.length = before;
				continue;
			}
			p.outcome = kind === 'fulfil' ? 'fulfilled' : 'failed';
			script.push(`${kind}${side}`);
			return true;
		}
		script.push(`${kind}${side}-none`);
		return false;
	};
	const fee = (rate: number): boolean => {
		const before = pair.errors.length;
		const r = pair.A().updateChannelFee(pair.channelId, rate);
		if (!r.ok) {
			pair.errors.length = before;
			script.push('fee-refused');
			return false;
		}
		script.push(`fee${rate}`);
		return true;
	};
	const finish = (): void => {
		pair.wire.manual(false);
		expect(pair.errors, pair.errors.join('; ')).to.have.length(0);
		// Everything still open resolves.
		for (const p of payments) {
			if (p.outcome !== 'open') continue;
			const receiver = other(p.from);
			const id = findSettleableId(pair, receiver, p.hash);
			expect(
				id,
				`open HTLC from ${p.from} is irrevocably committed at ${receiver}`
			).to.not.equal(null);
			const r = mgr(pair, receiver).fulfillHtlc(
				pair.channelId,
				id!,
				p.preimage
			);
			expect(r.ok, `late fulfil: ${r.error}`).to.equal(true);
			p.outcome = 'fulfilled';
		}
		expectLevel(pair);
		expect(pair.aChannel().getFullState().htlcs.size, 'A htlcs').to.equal(0);
		expect(pair.bChannel().getFullState().htlcs.size, 'B htlcs').to.equal(0);
		let toB = 0n;
		for (const p of payments) {
			if (p.outcome !== 'fulfilled') continue;
			toB += p.from === 'A' ? p.amountMsat : -p.amountMsat;
			expect(
				pair.fulfilled[p.from].some((x) => x.equals(p.preimage)),
				`${p.from} learned the preimage`
			).to.equal(true);
		}
		expect(pair.bChannel().getBalances().localMsat, 'B balance').to.equal(
			B_FLOAT_MSAT + toB
		);
		expect(pair.aChannel().getBalances().localMsat, 'A balance').to.equal(
			CAPACITY_MSAT - B_FLOAT_MSAT - toB
		);
		expect(
			pair.aChannel().getFullState().localConfig.feeratePerKw,
			'feerate agreed'
		).to.equal(pair.bChannel().getFullState().remoteConfig.feeratePerKw);
		expectStillUsable(pair);
	};
	return { t: pair, payments, script, add, resolve, fee, finish };
}

/** What a reconnect is about to face, read after both sides disconnected. */
function classify(t: IPair): { retransmit: boolean; affected: boolean } {
	let retransmit = false;
	let affected = false;
	for (const side of ['A', 'B'] as Side[]) {
		const mine = chanOf(t, side).getFullState();
		const theirs = chanOf(t, other(side)).getFullState();
		const missed =
			theirs.localCommitmentNumber + 1n <= mine.remoteCommitmentNumber &&
			mine.remoteCommitmentNumber > 0n;
		const cached = isTaprootChannel(mine.channelType)
			? !!mine.lastSentPartialSignatureWithNonce
			: !!mine.lastSentCommitmentSigned;
		if (missed && cached) {
			retransmit = true;
			if (
				mine.pendingLocalUpdates.length > mine.pendingLocalUpdatesSignedCount
			) {
				affected = true;
			}
		}
	}
	return { retransmit, affected };
}

// ─────────────────────────── seeded flows ───────────────────────────

interface IFlowResult {
	seed: number;
	failure: string | null;
	/** Some reconnect had a side retransmit a signature with later updates. */
	affected: boolean;
	/** Reconnects in which some side retransmitted a commitment_signed. */
	retransmits: number;
	reconnects: number;
	script: string[];
	sent: string[];
}

interface IFlowOpts {
	taproot?: boolean;
	/** Restart from the last persisted row instead of the live state. */
	rowRestarts?: boolean;
	fee?: boolean;
}

function runFlow(seed: number, opts: IFlowOpts = {}): IFlowResult {
	const rng = rngOf(seed);
	const pick = (n: number): number => Math.floor(rng() * n);
	const script: string[] = [];
	const result: IFlowResult = {
		seed,
		failure: null,
		affected: false,
		retransmits: 0,
		reconnects: 0,
		script,
		sent: []
	};
	let t: IPair | null = null;
	try {
		t = makeFundedPair(
			`flow-${opts.taproot ? 'tr-' : ''}${seed}`,
			opts.taproot === true
		);
		const pair = t;
		const d = makeDriver(pair, script);
		const add = (side: Side): void => {
			d.add(side, BigInt(1_000_000 + pick(5) * 500_000));
		};
		const deliver = (side: Side): void => {
			script.push(
				pair.wire.step(side) ? `deliver${side}` : `deliver${side}-none`
			);
		};
		const randomStep = (): void => {
			const x = rng();
			if (x < 0.44) {
				deliver(rng() < 0.5 ? 'A' : 'B');
			} else if (x < 0.62) {
				add(rng() < 0.5 ? 'A' : 'B');
			} else if (x < 0.8) {
				d.resolve(rng() < 0.5 ? 'A' : 'B', 'fulfil', pick);
			} else if (x < 0.88) {
				d.resolve(rng() < 0.5 ? 'A' : 'B', 'fail', pick);
			} else if (x < 0.93) {
				d.resolve(rng() < 0.5 ? 'A' : 'B', 'malformed', pick);
			} else if (opts.fee !== false) {
				d.fee([300, 400, 600, 1000, 1500, 253][pick(6)]);
			} else {
				add(rng() < 0.5 ? 'A' : 'B');
			}
		};
		const maybeRestart = (): void => {
			const x = rng();
			const fromRow = opts.rowRestarts === true;
			if (x < 0.15) {
				pair.wire.restartA(fromRow);
				script.push('restartA');
			} else if (x < 0.3) {
				pair.wire.restartB(fromRow);
				script.push('restartB');
			} else if (x < 0.36) {
				pair.wire.restartA(fromRow);
				pair.wire.restartB(fromRow);
				script.push('restartA', 'restartB');
			}
		};
		const reconnect = (): void => {
			pair.wire.disconnect();
			const c = classify(pair);
			result.reconnects++;
			if (c.retransmit) result.retransmits++;
			if (c.affected) result.affected = true;
			pair.wire.reconnect({ manual: true });
			script.push(
				`reconnect[A:${pair.wire.replay.A.join(
					','
				)}|B:${pair.wire.replay.B.join(',')}]`
			);
		};

		// Committed HTLCs both ways, so removals have something to remove.
		const preA = pick(3);
		const preB = pick(3);
		for (let i = 0; i < preA; i++) add('A');
		for (let i = 0; i < preB; i++) add('B');
		expectLevel(pair);

		// The first connection: traffic with the wire in the test's hands.
		pair.wire.manual(true);
		const steps = 3 + pick(12);
		for (let i = 0; i < steps; i++) randomStep();
		pair.wire.cut();
		script.push('cut');
		maybeRestart();

		// Up to two reconnects that die part way through.
		const partials = pick(3);
		for (let r = 0; r < partials; r++) {
			reconnect();
			const more = pick(8);
			for (let i = 0; i < more; i++) randomStep();
			pair.wire.cut();
			script.push('cut');
			maybeRestart();
		}

		// The reconnect that survives.
		reconnect();
		pair.wire.drain(rng);
		d.finish();
	} catch (err) {
		result.failure = (err as Error).message;
	}
	result.sent = t ? t.wire.sent.slice() : [];
	return result;
}

const DUMP = process.env.REPLAY_ORDER_DUMP;
const dumped: Record<string, IFlowResult[]> = {};
const prefixStats: Record<
	string,
	{ schedules: number; retransmits: number; affected: number; failures: number }
> = {};
const seedsOf = (name: string, fallback: number): number =>
	Number(process.env[name] ?? fallback);

function runSeeds(
	label: string,
	from: number,
	count: number,
	opts: IFlowOpts
): { failures: IFlowResult[]; affected: number; retransmits: number } {
	const failures: IFlowResult[] = [];
	let affected = 0;
	let retransmits = 0;
	for (let seed = from; seed < from + count; seed++) {
		const r = runFlow(seed, opts);
		if (r.failure) failures.push(r);
		if (r.affected) affected++;
		if (r.retransmits > 0) retransmits++;
		(dumped[label] ??= []).push(r);
	}
	return { failures, affected, retransmits };
}

const describeFailures = (failures: IFlowResult[]): string =>
	failures
		.slice(0, 6)
		.map((f) => `seed ${f.seed}: ${f.failure}\n    ${f.script.join(' ')}`)
		.join('\n');

// ─────────────────────── every delivered prefix ───────────────────────

interface IShape {
	tag: string;
	/** Committed before the round under test, with the wire delivering. */
	setup: (d: IDriver) => void;
	/** The round under test, with nothing delivered yet. */
	traffic: (d: IDriver) => void;
}

/**
 * Runs the shape once per delivery schedule: every sequence of "deliver the
 * next message from A" / "from B" up to `depth` steps that the wire allows,
 * the connection dying after it. Then one reconnect, and full convergence.
 */
function everyPrefix(
	shape: IShape,
	depth: number,
	taproot = false
): {
	schedules: number;
	retransmits: number;
	affected: number;
	failures: string[];
} {
	const failures: string[] = [];
	let schedules = 0;
	let retransmits = 0;
	let affected = 0;
	const todo: string[] = [''];
	while (todo.length > 0) {
		const schedule = todo.shift()!;
		schedules++;
		const t = makeFundedPair(
			`prefix-${taproot ? 'tr-' : ''}${shape.tag}-${schedule || 'none'}`,
			taproot
		);
		const d = makeDriver(t);
		let replay = '';
		try {
			shape.setup(d);
			expectLevel(t);
			t.wire.manual(true);
			shape.traffic(d);
			for (const side of schedule) {
				expect(t.wire.step(side as Side), 'schedule step').to.equal(true);
			}
			if (schedule.length < depth) {
				if (t.wire.pending('A') > 0) todo.push(`${schedule}A`);
				if (t.wire.pending('B') > 0) todo.push(`${schedule}B`);
			}
			t.wire.cut();
			t.wire.disconnect();
			const c = classify(t);
			if (c.retransmit) retransmits++;
			if (c.affected) affected++;
			t.wire.reconnect({ manual: false });
			replay = `A:${t.wire.replay.A.join(',')}|B:${t.wire.replay.B.join(',')}`;
			d.finish();
		} catch (err) {
			failures.push(
				`[${schedule || 'nothing delivered'}] ${replay}: ${
					(err as Error).message
				}`
			);
		}
	}
	return { schedules, retransmits, affected, failures };
}

const SHAPES: IShape[] = [
	{
		tag: 'add-add',
		setup: (): void => undefined,
		traffic: (d): void => {
			d.add('A', 1_000_000n);
			d.add('A', 2_000_000n);
		}
	},
	{
		tag: 'fulfil-fulfil',
		setup: (d): void => {
			d.add('A', 4_000_000n);
			d.add('A', 5_000_000n);
		},
		traffic: (d): void => {
			d.resolve('B', 'fulfil');
			d.resolve('B', 'fulfil');
		}
	},
	{
		tag: 'fulfil-fail',
		setup: (d): void => {
			d.add('A', 4_000_000n);
			d.add('A', 5_000_000n);
		},
		traffic: (d): void => {
			d.resolve('B', 'fulfil');
			d.resolve('B', 'fail');
		}
	},
	{
		tag: 'malformed-add',
		setup: (d): void => {
			d.add('A', 4_000_000n);
		},
		traffic: (d): void => {
			d.resolve('B', 'malformed');
			d.add('B', 1_500_000n);
		}
	},
	{
		tag: 'add-fulfil',
		setup: (d): void => {
			d.add('B', 4_000_000n);
		},
		traffic: (d): void => {
			d.add('A', 1_000_000n);
			d.resolve('A', 'fulfil');
		}
	},
	{
		tag: 'fee-add',
		setup: (): void => undefined,
		traffic: (d): void => {
			d.fee(1000);
			d.add('A', 1_000_000n);
		}
	},
	{
		tag: 'add-fee-add',
		setup: (): void => undefined,
		traffic: (d): void => {
			d.add('A', 1_000_000n);
			d.fee(1000);
			d.add('A', 2_000_000n);
		}
	},
	{
		// Both sides hold a signature with an update behind it.
		tag: 'crossing',
		setup: (d): void => {
			d.add('A', 4_000_000n);
			d.add('B', 5_000_000n);
		},
		traffic: (d): void => {
			d.add('A', 1_000_000n);
			d.add('B', 1_500_000n);
			d.resolve('A', 'fulfil');
			d.resolve('B', 'fail');
		}
	}
];

// ─────────────────────────── splice helpers ───────────────────────────

function makeSpliceInWallet(amountSats: bigint): {
	walletInput: {
		prevTx: Buffer;
		prevOutputIndex: number;
		value: bigint;
		sequence: number;
		signWitness: (
			tx: bitcoin.Transaction,
			inputIndex: number,
			value: bigint
		) => Buffer[];
	};
	changeScript: Buffer;
} {
	bitcoin.initEccLib(ecc);
	const walletPriv = sha256(Buffer.from('reest-adv-splice-wallet'));
	const walletPub = Buffer.from(ecc.pointFromScalar(walletPriv, true)!);
	const walletScript = bitcoin.payments.p2wpkh({ pubkey: walletPub }).output!;
	const scriptCode = bitcoin.payments.p2pkh({ pubkey: walletPub }).output!;
	const value = amountSats + 100_000n;
	const prevTx = new bitcoin.Transaction();
	prevTx.version = 2;
	prevTx.addInput(crypto.randomBytes(32), 0);
	prevTx.addOutput(walletScript, Number(value));
	return {
		walletInput: {
			prevTx: prevTx.toBuffer(),
			prevOutputIndex: 0,
			value,
			sequence: 0xfffffffd,
			signWitness: (
				tx: bitcoin.Transaction,
				inputIndex: number,
				inputValue: bigint
			): Buffer[] => {
				const sighash = tx.hashForWitnessV0(
					inputIndex,
					scriptCode,
					Number(inputValue),
					bitcoin.Transaction.SIGHASH_ALL
				);
				const sig64 = Buffer.from(ecc.sign(sighash, walletPriv));
				const der = bitcoin.script.signature.encode(
					sig64,
					bitcoin.Transaction.SIGHASH_ALL
				);
				return [der, walletPub];
			}
		},
		changeScript: walletScript
	};
}

function makePendingLockPair(tag: string): IPair {
	const t = makeFundedPair(tag);
	t.A().initiateQuiescence(t.channelId);
	const wallet = makeSpliceInWallet(100_000n);
	t.aChannel().setSpliceInInputs([wallet.walletInput], wallet.changeScript);
	expect(t.A().initiateSplice(t.channelId, 100_000n, 253).ok).to.equal(true);
	expect(t.errors, t.errors.join('; ')).to.have.length(0);
	expect(t.aChannel().isSplicePendingLock()).to.equal(true);
	expect(t.bChannel().isSplicePendingLock()).to.equal(true);
	return t;
}

const BATCH = 'START_BATCH';
const commitmentTraffic = (replay: string[]): string[] =>
	replay.filter((m) => m !== 'TX_SIGNATURES' && m !== 'SPLICE_LOCKED');

// ─────────────────────────────── tests ───────────────────────────────

after(function () {
	if (DUMP) {
		fs.writeFileSync(DUMP, JSON.stringify({ ...dumped, prefixStats }));
	}
});

describe('reestablish replay order: review recovery regressions', function () {
	this.timeout(900_000);

	if (process.env.REPLAY_ORDER_DEBUG) {
		// REPLAY_ORDER_DEBUG=<seed> [REPLAY_ORDER_DEBUG_MODE=row|taproot]
		// with --grep "debug one seed" prints one flow's script and outcome.
		it('debug one seed', function () {
			const mode = process.env.REPLAY_ORDER_DEBUG_MODE;
			const r = runFlow(Number(process.env.REPLAY_ORDER_DEBUG), {
				rowRestarts: mode === 'row',
				taproot: mode === 'taproot',
				...(mode === 'taproot' ? { fee: false } : {})
			});
			// eslint-disable-next-line no-console
			console.log(r.failure, '\n', r.script.join(' '));
		});
	}

	describe('1. seeded flows converge', function () {
		it('random traffic, cuts, live restarts and partial replays', function () {
			const n = seedsOf('REPLAY_ORDER_SEEDS', 120);
			const r = runSeeds('live', 1, n, {});
			// The flows must actually reach the code under review.
			expect(
				r.affected,
				'flows with a later update behind a signature'
			).to.be.greaterThan(n / 20);
			expect(r.failures.length, describeFailures(r.failures)).to.equal(0);
		});

		it('the same with restarts from the last persisted row', function () {
			const n = seedsOf('REPLAY_ORDER_SEEDS', 120);
			const r = runSeeds('row', 10_001, n, { rowRestarts: true });
			expect(r.failures.length, describeFailures(r.failures)).to.equal(0);
		});

		it('option_taproot', function () {
			const n = seedsOf('REPLAY_ORDER_TAPROOT_SEEDS', 20);
			const r = runSeeds('taproot', 20_001, n, { taproot: true, fee: false });
			expect(r.failures.length, describeFailures(r.failures)).to.equal(0);
		});
	});

	describe('2. every delivered prefix of a round, peer revoke_and_ack delivered or lost', function () {
		for (const shape of SHAPES) {
			it(`${shape.tag}: every schedule up to six deliveries converges`, function () {
				const r = everyPrefix(shape, 6);
				prefixStats[shape.tag] = {
					schedules: r.schedules,
					retransmits: r.retransmits,
					affected: r.affected,
					failures: r.failures.length
				};
				expect(r.schedules).to.be.greaterThan(3);
				expect(
					r.retransmits,
					'schedules with a retransmitted signature'
				).to.be.greaterThan(0);
				expect(r.failures, r.failures.join('\n')).to.have.length(0);
			});
		}
	});
});

describe('reestablish replay order: review targeted regressions', function () {
	this.timeout(300_000);

	describe('5. splice pending-lock batch', function () {
		const lockAndCheck = (t: IPair): void => {
			t.A().sendSpliceLocked(t.channelId);
			t.B().sendSpliceLocked(t.channelId);
			expectLevel(t);
			expectStillUsable(t);
		};

		it('fulfil, batch, fulfil from the non-initiator, cached batch', function () {
			const t = makePendingLockPair('splice-fulfils');
			const h1 = offer(t, 'A', 4_000_000n);
			const h2 = offer(t, 'A', 5_000_000n);
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			t.wire.cut();
			settle(t, 'B', h1);
			settle(t, 'B', h2);
			expect(queueOf(t.bChannel())).to.deep.equal({
				types: [FULFILL, FULFILL],
				signed: 1
			});
			t.wire.reconnect();
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(commitmentTraffic(t.wire.replay.B)).to.deep.equal([
				FULFILL,
				BATCH,
				SIG,
				SIG,
				FULFILL
			]);
			expect(t.fulfilled.A).to.have.length(2);
			lockAndCheck(t);
		});

		it('cached batch, both sides crossing: add, batch, add each way', function () {
			const t = makePendingLockPair('splice-crossing');
			t.wire.cut();
			const a1 = offer(t, 'A', 1_000_000n);
			const a2 = offer(t, 'A', 2_000_000n);
			const b1 = offer(t, 'B', 1_500_000n);
			const b2 = offer(t, 'B', 2_500_000n);
			t.wire.reconnect();
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(commitmentTraffic(t.wire.replay.A)).to.deep.equal([
				ADD,
				BATCH,
				SIG,
				SIG,
				ADD
			]);
			expect(commitmentTraffic(t.wire.replay.B)).to.deep.equal([
				ADD,
				BATCH,
				SIG,
				SIG,
				ADD
			]);
			settle(t, 'B', a1);
			settle(t, 'B', a2);
			settle(t, 'A', b1);
			settle(t, 'A', b2);
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			lockAndCheck(t);
		});

		it('a rebuilt batch with nothing behind it converges (same on master)', function () {
			const t = makePendingLockPair('splice-rebuilt-control');
			t.wire.cut();
			const only = offer(t, 'A', 1_000_000n);
			t.wire.restartA();
			t.wire.reconnect();
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(commitmentTraffic(t.wire.replay.A)).to.deep.equal([
				ADD,
				BATCH,
				SIG,
				SIG
			]);
			settle(t, 'B', only);
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			lockAndCheck(t);
		});
	});

	describe('6. option_taproot: every delivered prefix', function () {
		for (const shape of SHAPES.filter((s) =>
			['add-add', 'fulfil-fail'].includes(s.tag)
		)) {
			it(`${shape.tag}: every schedule up to five deliveries converges`, function () {
				const r = everyPrefix(shape, 5, true);
				prefixStats[`taproot-${shape.tag}`] = {
					schedules: r.schedules,
					retransmits: r.retransmits,
					affected: r.affected,
					failures: r.failures.length
				};
				expect(r.retransmits).to.be.greaterThan(0);
				expect(r.failures, r.failures.join('\n')).to.have.length(0);
			});
		}
	});

	describe('7. FFOR drain (section 7.5.5 hold)', function () {
		const TIP = 795_000;
		const AMOUNTS = [994_000n, 546_250n, 49_749_000n];
		const record = (c: Channel): IFforEpochRecord => {
			const f = c.getFforEpoch();
			expect(f, 'epoch record').to.not.equal(null);
			return f!;
		};

		/** As the author's helper: R's drain cut in two, none of it delivered. */
		const drainInTwoHalves = (tag: string): IPair => {
			const t = makePair(tag);
			t.A().handleNewBlock(TIP);
			t.B().handleNewBlock(TIP);
			const started = t.B().initiateFforEpoch(t.channelId, {
				voucherAmountsMsat: AMOUNTS,
				minPaymentMsat: 400_000n,
				settlementDeadline: 798_992,
				voucherExpiry: 800_000,
				feeBaseMsat: 1000,
				feeProportionalMillionths: 5000
			});
			expect(started.ok, started.error).to.equal(true);
			expect(record(t.aChannel()).state).to.equal(FforState.ACTIVE);
			expect(record(t.bChannel()).state).to.equal(FforState.ACTIVE);

			const r = t.bChannel();
			const vouchers = [...r.getFullState().htlcs.values()]
				.filter((h) => h.fforVoucher === true)
				.sort((x, y) => Number(x.id - y.id));
			expect(vouchers).to.have.length(AMOUNTS.length);
			const last = vouchers[vouchers.length - 1];
			const failHtlc = r.failHtlc.bind(r);
			let holdBack = true;
			r.failHtlc = ((id: bigint, ...rest: unknown[]) =>
				holdBack && id === last.id
					? [
							{
								type: ChannelActionType.ERROR,
								message: 'held back by the test'
							}
					  ]
					: (failHtlc as (...a: unknown[]) => unknown)(
							id,
							...rest
					  )) as typeof r.failHtlc;

			t.wire.dropWhen(
				(from, type) =>
					from === 'B' &&
					(type === MessageType.UPDATE_FULFILL_HTLC ||
						type === MessageType.UPDATE_FAIL_HTLC ||
						type === MessageType.COMMITMENT_SIGNED)
			);
			expect(t.B().closeFforEpoch(t.channelId).ok).to.equal(true);
			expect(record(t.aChannel()).state).to.equal(FforState.DRAINING);
			expect(record(r).state).to.equal(FforState.DRAINING);
			expect(queueOf(r)).to.deep.equal({ types: [FAIL, FAIL], signed: 2 });

			holdBack = false;
			const preimage = record(t.aChannel()).preimages[AMOUNTS.length - 1];
			expect(t.B().fforAddPreimage(t.channelId, preimage).ok).to.equal(true);
			expect(queueOf(r)).to.deep.equal({
				types: [FAIL, FAIL, FULFILL],
				signed: 2
			});
			t.wire.cut();
			return t;
		};
		const forgetClose = (t: IPair): void => {
			const s = record(t.aChannel());
			s.state = FforState.ACTIVE;
			s.closeWire = null;
			s.closeAckWire = null;
			s.settledBitmap = null;
			s.closeProcessed = false;
		};
		const expectDrained = (t: IPair): void => {
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(record(t.aChannel()).state).to.equal(FforState.CLOSED);
			expect(record(t.bChannel()).state).to.equal(FforState.CLOSED);
			expect(t.aChannel().getFullState().htlcs.size).to.equal(0);
			expect(t.bChannel().getFullState().htlcs.size).to.equal(0);
			expect(t.bChannel().getBalances().localMsat).to.equal(
				AMOUNTS[AMOUNTS.length - 1]
			);
			expectLevel(t);
		};
		const drainOf = (t: IPair): string[] =>
			t.wire.delivered.filter((m) =>
				[`B:${FAIL}`, `B:${FULFILL}`, `B:${SIG}`, `B:${RAA}`].includes(m)
			);

		it('held, the connection dies before ff_close_ack returns, held again: the release keeps the order', function () {
			const t = drainInTwoHalves('ffor-hold-twice');
			forgetClose(t);
			// ff_close reaches S, whose ack is lost with the connection.
			t.wire.reconnect({ manual: true });
			expect(
				t.wire.replay.B.filter((m) => [FAIL, FULFILL, SIG, RAA].includes(m))
			).to.deep.equal([]);
			while (t.wire.step('B'));
			expect(t.wire.pendingTypes('A')).to.include('FF_CLOSE_ACK');
			t.wire.cut();
			t.wire.manual(false);
			t.wire.reconnect();
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(drainOf(t).slice(0, 4)).to.deep.equal([
				`B:${FAIL}`,
				`B:${FAIL}`,
				`B:${SIG}`,
				`B:${FULFILL}`
			]);
			expectDrained(t);
		});

		it('held after R restarts from its row: the release keeps the order', function () {
			const t = drainInTwoHalves('ffor-hold-restart');
			forgetClose(t);
			t.wire.restartB();
			t.wire.reconnect();
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(
				t.wire.replay.B.filter((m) => [FAIL, FULFILL, SIG, RAA].includes(m))
			).to.deep.equal([]);
			expect(drainOf(t).slice(0, 4)).to.deep.equal([
				`B:${FAIL}`,
				`B:${FAIL}`,
				`B:${SIG}`,
				`B:${FULFILL}`
			]);
			expectDrained(t);
		});

		it('in DRAINING nothing but the drain can enter the queue, so no update outside the held set can overtake a held signature', function () {
			const t = drainInTwoHalves('ffor-queue-types');
			const r = t.bChannel();
			const before = queueOf(r).types.length;
			expect(
				r
					.addHtlc(1_000_000n, sha256(t.nextPreimage()), 900, ONION)
					.some((a) => a.type === ChannelActionType.ERROR)
			).to.equal(true);
			const voucher = [...r.getFullState().htlcs.values()].find(
				(h) => h.fforVoucher === true
			);
			if (voucher) {
				expect(
					r
						.failMalformedHtlc(voucher.id, sha256(ONION), 0xc005)
						.some((a) => a.type === ChannelActionType.ERROR)
				).to.equal(true);
			}
			expect(queueOf(r).types.length).to.equal(before);
			expect(
				queueOf(r).types.every((m) => m === FAIL || m === FULFILL)
			).to.equal(true);
		});
	});

	describe('10. the signature that follows the retransmitted one', function () {
		it('covers exactly the later updates, and the peer revoke_and_ack for it empties the queue', function () {
			const t = makeFundedPair('next-sig');
			const inbound = offer(t, 'B', 2_000_000n);
			expectLevel(t);
			t.wire.cut();
			const covered = offer(t, 'A', 1_000_000n);
			const later = offer(t, 'A', 1_500_000n);
			settle(t, 'A', inbound);
			expect(queueOf(t.aChannel())).to.deep.equal({
				types: [ADD, ADD, FULFILL],
				signed: 1
			});

			t.wire.reconnect({ manual: true });
			expect(t.wire.replay.A).to.deep.equal([ADD, SIG, ADD, FULFILL]);
			for (let i = 0; i < 4; i++) expect(t.wire.step('A')).to.equal(true);
			// Nothing more leaves A until the peer revokes.
			expect(t.wire.pendingTypes('A')).to.deep.equal([]);
			expect(t.aChannel().needsCommitment()).to.equal(true);
			expect(t.wire.pendingTypes('B')).to.deep.equal([RAA, SIG]);
			expect(t.wire.step('B')).to.equal(true);
			// The covered add is acknowledged; the next signature is out and
			// covers the two later updates, no more and no less.
			expect(queueOf(t.aChannel())).to.deep.equal({
				types: [ADD, FULFILL],
				signed: 2
			});
			expect(t.wire.pendingTypes('A')).to.deep.equal([SIG]);
			expect(t.aChannel().needsCommitment()).to.equal(false);
			t.wire.manual(false);
			expectLevel(t);
			expect(t.fulfilled.B).to.have.length(1);
			settle(t, 'B', covered);
			settle(t, 'B', later);
			expectLevel(t);
			expect(t.fulfilled.A).to.have.length(2);
			expectStillUsable(t);
		});
	});

	describe('8. shutdown: removals in flight beside a shutdown', function () {
		const B_SCRIPT = Buffer.concat([
			Buffer.from([0x00, 0x14]),
			sha256(Buffer.from('shutdown-script-b')).subarray(0, 20)
		]);
		const A_SCRIPT = Buffer.concat([
			Buffer.from([0x00, 0x14]),
			sha256(Buffer.from('shutdown-script-a')).subarray(0, 20)
		]);
		const shuttingDown = (
			tag: string,
			htlcs: number
		): { t: IPair; hs: IPayment[] } => {
			const t = makeFundedPair(tag);
			const hs: IPayment[] = [];
			for (let i = 0; i < htlcs; i++) {
				hs.push(offer(t, 'A', BigInt(4_000_000 + i * 1_000_000)));
			}
			expectLevel(t);
			expect(t.B().initiateShutdown(t.channelId, B_SCRIPT).ok).to.equal(true);
			expect(t.aChannel().getState()).to.equal(ChannelState.SHUTTING_DOWN);
			expect(t.bChannel().getState()).to.equal(ChannelState.SHUTTING_DOWN);
			return { t, hs };
		};
		/**
		 * No transaction either side broadcasts may leave an HTLC's value out
		 * of every output. The closing fee here is under 200 sat; the HTLCs
		 * are 4000 sat and more.
		 */
		const expectNothingBurned = (t: IPair): void => {
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(t.broadcasts.A.length + t.broadcasts.B.length).to.be.greaterThan(
				0
			);
			expect(t.aChannel().getFullState().htlcs.size).to.equal(0);
			expect(t.bChannel().getFullState().htlcs.size).to.equal(0);
			for (const raw of [...t.broadcasts.A, ...t.broadcasts.B]) {
				const tx = bitcoin.Transaction.fromBuffer(raw);
				const paid = tx.outs.reduce((sum, o) => sum + BigInt(o.value), 0n);
				expect(
					FUNDING_SATOSHIS - paid < 1_000n,
					`a broadcast transaction pays out ${paid} of ${FUNDING_SATOSHIS} sat: ${
						FUNDING_SATOSHIS - paid
					} sat left to fees while ${
						t.bChannel().getFullState().htlcs.size
					} fulfilled HTLC(s) sit unresolved`
				).to.equal(true);
			}
		};

		it('a lost fulfil and covering signature finish before the retransmitted shutdown closes', function () {
			const { t, hs } = shuttingDown('shutdown-covered', 1);
			t.wire.cut();
			settle(t, 'B', hs[0]);
			t.wire.reconnect();
			expect(t.wire.replay.B).to.deep.equal([FULFILL, SIG, 'SHUTDOWN']);
			// A holds the preimage either way.
			expect(t.fulfilled.A).to.have.length(1);
			expectNothingBurned(t);
		});

		it('two lost fulfils with a signature between them finish before cooperative close', function () {
			const { t, hs } = shuttingDown('shutdown-later', 2);
			t.wire.cut();
			settle(t, 'B', hs[0]);
			settle(t, 'B', hs[1]);
			t.wire.reconnect();
			expectNothingBurned(t);
		});

		it('a shutdown crossing an in-flight fulfil preserves its value in cooperative close', function () {
			const t = makeFundedPair('shutdown-live-race');
			const h = offer(t, 'A', 4_000_000n);
			expectLevel(t);
			t.wire.manual(true);
			settle(t, 'B', h);
			expect(t.wire.pendingTypes('B')).to.deep.equal([FULFILL, SIG]);
			expect(t.A().initiateShutdown(t.channelId, A_SCRIPT).ok).to.equal(true);
			// A's shutdown reaches B while B's fulfil is still on the wire.
			expect(t.wire.step('A')).to.equal(true);
			t.wire.manual(false);
			expect(t.fulfilled.A).to.have.length(1);
			expectNothingBurned(t);
		});
	});
});
