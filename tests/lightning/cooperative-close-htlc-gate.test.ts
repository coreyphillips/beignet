/**
 * Cooperative close starts only once the channel is really empty (issue #1307).
 *
 * BOLT 2 lets closing negotiation begin when neither commitment holds an HTLC,
 * no revocation is owed and every update is on both commitments. The close
 * path used to ask a narrower question (is any HTLC still PENDING or
 * COMMITTED), so a shutdown that met a removal in flight started the
 * negotiation over balances that had the HTLC on neither side, and the closing
 * transaction paid its value to the miners.
 *
 * Two ChannelManagers with real signers talk over one FIFO wire, with a manual
 * mode in which the test delivers one message at a time from either
 * direction. After every delivery the harness checks, per side, that the
 * channel is not negotiating or closed while it still holds HTLC value, and it
 * records the ledger each closing signature was made over. A case passes only
 * when:
 *  - no side ever negotiated with an HTLC entry or a kept removal on its books;
 *  - every closing_signed, closing_complete and closing_sig was signed over
 *    balances that add up to the whole channel and equal what the resolved
 *    HTLCs imply;
 *  - every broadcast transaction pays each side exactly that balance, less the
 *    negotiated fee on the payer's output only;
 *  - both sides end CLOSED.
 *
 * A is always the opener. "Each side as opener" is covered by running every
 * case with the HTLC offered by the opener and by the non-opener, and with the
 * shutdown started by the opener, by the non-opener, and by both at once. Each
 * case runs on the legacy closing_signed negotiation, on option_simple_close
 * and on a taproot channel.
 *
 * Sections:
 *  1. a shutdown crossing a fulfil or a fail at each boundary of its round;
 *  2. a shutdown crossing an add: the add completes, the close waits, then
 *     pays in full;
 *  3. the removal round cut by a disconnect while SHUTTING_DOWN, then
 *     reestablished (the reported [fulfil, signature, shutdown] replay among
 *     them);
 *  4. a restart from the persisted row with a removal in flight, and a row
 *     written by the old close path;
 *  5. a peer that sends its closing signature early: nothing is signed;
 *  6. other updates in flight: crossing removals, a deferred signature, an
 *     empty signature, an update_fee round;
 *  7. a close with nothing in flight broadcasts the transactions master does;
 *  8. the predicate itself, and every signing stage against it.
 *
 * Titles starting with PIN record behaviour this change does not touch.
 * CLOSE_GATE_FULL=1 and CLOSE_GATE_SEEDS=n widen the matrix (see FULL below).
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import { Channel } from '../../src/lightning/channel/channel';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	HtlcDirection,
	HtlcState,
	IHtlcEntry,
	receivedAddIrrevocablyCommitted
} from '../../src/lightning/channel/types';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { MessageType } from '../../src/lightning/message/types';
import {
	decodeClosingCompleteMessage,
	decodeClosingSigMessage,
	decodeClosingSignedMessage,
	encodeClosingSignedMessage
} from '../../src/lightning/message/channel-close';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	serializeChannelState,
	deserializeChannelState
} from '../../src/lightning/storage/serialization';

const sha256 = (b: Buffer): Buffer =>
	crypto.createHash('sha256').update(b).digest();

type Flavor = 'legacy' | 'simple' | 'taproot';
const FLAVORS: Flavor[] = ['legacy', 'simple', 'taproot'];

function simpleCloseFeatures(): FeatureFlags {
	const flags = FeatureFlags.empty();
	flags.setOptional(Feature.SHUTDOWN_ANY_SEGWIT);
	flags.setOptional(Feature.SIMPLE_CLOSE);
	return flags;
}

function makeConfig(name: string, flavor: Flavor): IChannelManagerConfig {
	const seed = sha256(Buffer.from(`close-gate-${name}`));
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
		...(flavor === 'taproot' ? { preferTaproot: true } : {}),
		...(flavor === 'simple' ? { localFeatures: simpleCloseFeatures() } : {})
	};
}

const FUNDING_SATOSHIS = 1_000_000n;
const CAPACITY_MSAT = FUNDING_SATOSHIS * 1000n;
/** Pushed to B at open so B can offer HTLCs of its own. */
const B_FLOAT_MSAT = 300_000_000n;
const A_START_MSAT = CAPACITY_MSAT - B_FLOAT_MSAT;
const HTLC_MSAT = 4_000_000n;
/** No close in this file negotiates a fee anywhere near one HTLC. */
const MAX_SANE_FEE_SAT = 1_000n;

const A_SCRIPT = Buffer.concat([
	Buffer.from([0x00, 0x14]),
	sha256(Buffer.from('close-gate-script-a')).subarray(0, 20)
]);
const B_SCRIPT = Buffer.concat([
	Buffer.from([0x00, 0x14]),
	sha256(Buffer.from('close-gate-script-b')).subarray(0, 20)
]);

type Side = 'A' | 'B';
const other = (s: Side): Side => (s === 'A' ? 'B' : 'A');
/** The script a side asks for when the test starts the shutdown on it. */
const scriptOf = (s: Side): Buffer => (s === 'A' ? A_SCRIPT : B_SCRIPT);

interface IQueued {
	from: string;
	to: string;
	type: number;
	p: Buffer;
}

/** A closing signature as it left, with the ledger it was made over. */
interface IClosingSend {
	side: Side;
	type: string;
	feeSat: bigint;
	localMsat: bigint;
	remoteMsat: bigint;
	htlcEntries: number;
	keptRemovals: number;
}

interface IWire {
	/** Drop everything on the wire and everything sent from here on. */
	cut: () => void;
	/** Both sides observe the disconnect (idempotent). */
	disconnect: () => void;
	/** Exchange channel_reestablish; `manual` leaves the answers queued. */
	reconnect: (manual?: boolean) => void;
	/** Manual mode: nothing is delivered until step() or drain(). */
	manual: (on: boolean) => void;
	/** Deliver the oldest undelivered message sent by `side`. */
	step: (side: Side) => string | null;
	pendingTypes: (side: Side) => string[];
	/** Lose the oldest `count` undelivered messages sent by `side`. */
	drop: (side: Side, count: number) => string[];
	/** Put a message the test built on the wire as if `from` had sent it. */
	send: (from: Side, type: MessageType, payload: Buffer) => void;
	/** Deliver everything; `pick` chooses the direction at each step. */
	drain: (pick: Policy) => void;
	restart: (side: Side, fromRow: boolean) => void;
	replay: Record<Side, string[]>;
	/** Every message delivered, in order: side and type. */
	delivered: string[];
	rows: Record<Side, string | null>;
}

interface IPair {
	tag: string;
	flavor: Flavor;
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
	closingSends: IClosingSend[];
	/** A side seen negotiating or closed with HTLC value on its books. */
	violations: string[];
	/** Run the per-side invariant now (after an API call). */
	check: (when: string) => void;
}

/** Which direction delivers next: the side whose oldest message goes. */
type Policy = (t: { a: number; b: number; n: number }) => Side;

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

interface INamedPolicy {
	name: string;
	make: () => Policy;
}
const A_FIRST: INamedPolicy = {
	name: 'A first',
	make: (): Policy => (): Side => 'A'
};
const B_FIRST: INamedPolicy = {
	name: 'B first',
	make: (): Policy => (): Side => 'B'
};
const ALTERNATING: INamedPolicy = {
	name: 'alternating',
	make:
		(): Policy =>
		({ n }): Side =>
			n % 2 === 0 ? 'A' : 'B'
};
const seeded = (seed: number): INamedPolicy => ({
	name: `seeded ${seed}`,
	make: (): Policy => {
		const r = rngOf(seed);
		return (): Side => (r() < 0.5 ? 'A' : 'B');
	}
});
/**
 * How much of the matrix runs. Every case builds a channel with real
 * signatures, and a taproot pair costs several times a legacy one, while the
 * gate under test is one predicate shared by the three negotiations. By
 * default:
 *  - section 1 (the reported loss) takes every boundary of the removal round
 *    for legacy and simple close, under both extreme delivery orders for
 *    legacy (one direction drained before the other moves) and strict
 *    alternation for simple close; taproot takes the boundaries where the
 *    round changes hands, under alternation;
 *  - the other sections take one delivery order per case (legacy alternates
 *    between the two extremes from one boundary to the next) and fewer
 *    boundaries for simple close and taproot.
 * CLOSE_GATE_FULL=1 runs every boundary under all three orders for every
 * negotiation in every section; CLOSE_GATE_SEEDS=n adds n seeded random
 * orders on top.
 */
const FULL = process.env.CLOSE_GATE_FULL === '1';
const EXTRA_SEEDS = Number(process.env.CLOSE_GATE_SEEDS ?? '0');
const SEEDED = Array.from({ length: EXTRA_SEEDS }, (_, i) => seeded(i + 1));
const EVERY_ORDER = [A_FIRST, B_FIRST, ALTERNATING, ...SEEDED];
const policiesFor = (flavor: Flavor): INamedPolicy[] =>
	FULL
		? EVERY_ORDER
		: flavor === 'legacy'
		? [A_FIRST, B_FIRST, ...SEEDED]
		: [ALTERNATING, ...SEEDED];
/** One order for case number `i`, for the sections that vary something else. */
const onePolicyFor = (flavor: Flavor, i: number): INamedPolicy[] =>
	FULL
		? EVERY_ORDER
		: flavor === 'legacy'
		? [i % 2 === 0 ? A_FIRST : B_FIRST]
		: [ALTERNATING];
/**
 * Boundaries of a five-message round: k messages delivered before the event.
 * 0: the update is still on the wire; 2: the signature has arrived; 3: the
 * first revoke_and_ack has; 5: the round is complete.
 */
const EVERY_BOUNDARY = [0, 1, 2, 3, 4, 5];
const boundariesFor = (flavor: Flavor): number[] =>
	FULL || flavor !== 'taproot' ? EVERY_BOUNDARY : [0, 2, 3];
const fewBoundariesFor = (flavor: Flavor): number[] =>
	FULL || flavor === 'legacy'
		? EVERY_BOUNDARY
		: flavor === 'simple'
		? [0, 2, 3]
		: [0, 3];

/** HTLC value a side still has on its books, outside its two balances. */
function unresolvedOf(c: Channel): { entries: number; kept: number } {
	const s = c.getFullState();
	return {
		entries: s.htlcs.size,
		kept: s.signedLocalRemovals?.length ?? 0
	};
}

function makePair(tag: string, flavor: Flavor = 'legacy'): IPair {
	const aConfig = makeConfig(`${tag}-A`, flavor);
	const bConfig = makeConfig(`${tag}-B`, flavor);
	const aPub = getPublicKey(aConfig.nodePrivateKey!).toString('hex');
	const bPub = getPublicKey(bConfig.nodePrivateKey!).toString('hex');
	const managers = new Map<string, ChannelManager>();
	const errors: string[] = [];
	const fulfilled: Record<Side, Buffer[]> = { A: [], B: [] };
	const failed: Record<Side, bigint[]> = { A: [], B: [] };
	const replay: Record<Side, string[]> = { A: [], B: [] };
	const delivered: string[] = [];
	const rows: Record<Side, string | null> = { A: null, B: null };
	const broadcasts: Record<Side, Buffer[]> = { A: [], B: [] };
	const closingSends: IClosingSend[] = [];
	const violations: string[] = [];
	const sideOf = (pub: string): Side => (pub === aPub ? 'A' : 'B');
	const pubOf = (side: Side): string => (side === 'A' ? aPub : bPub);

	let alive = true;
	let paused = false;
	let pumping = false;
	let manualMode = false;
	let queue: IQueued[] = [];
	let preimageCounter = 0;

	const chan = (pub: string, peer: string): Channel =>
		managers.get(pub)!.getChannelsByPeer(peer)[0];

	const violated = new Set<Side>();
	const check = (when: string): void => {
		for (const side of ['A', 'B'] as Side[]) {
			const c = chan(pubOf(side), pubOf(other(side)));
			if (!c || violated.has(side)) continue;
			const state = c.getState();
			if (
				state !== ChannelState.NEGOTIATING_CLOSING &&
				state !== ChannelState.CLOSED
			) {
				continue;
			}
			const u = unresolvedOf(c);
			if (u.entries === 0 && u.kept === 0) continue;
			const held = [
				...c.getFullState().htlcs.values(),
				...(c.getFullState().signedLocalRemovals ?? [])
			]
				.map((h) => `${h.amountMsat / 1000n} sat ${h.state}`)
				.join(', ');
			// The first sighting per side says it all.
			violated.add(side);
			violations.push(
				`${side} is ${state} ${when} while it still holds ${held}`
			);
		}
	};

	const recordClosingSend = (side: Side, type: number, p: Buffer): void => {
		let feeSat: bigint;
		if (type === MessageType.CLOSING_SIGNED) {
			feeSat = decodeClosingSignedMessage(p).feeSatoshis;
		} else if (type === MessageType.CLOSING_COMPLETE) {
			feeSat = decodeClosingCompleteMessage(p).feeSatoshis;
		} else if (type === MessageType.CLOSING_SIG) {
			feeSat = decodeClosingSigMessage(p).feeSatoshis;
		} else {
			return;
		}
		const c = chan(pubOf(side), pubOf(other(side)));
		const s = c.getFullState();
		const u = unresolvedOf(c);
		closingSends.push({
			side,
			type: MessageType[type],
			feeSat,
			localMsat: s.localBalanceMsat,
			remoteMsat: s.remoteBalanceMsat,
			htlcEntries: u.entries,
			keptRemovals: u.kept
		});
	};

	const dispatch = (m: IQueued): void => {
		if (!alive) return;
		const label = `${sideOf(m.from)}:${MessageType[m.type]}`;
		delivered.push(label);
		managers.get(m.to)!.handleMessage(m.from, m.type, m.p);
		check(`after ${label} is delivered`);
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
		if (flavor === 'simple') {
			// The manager reads the peer's init features through its peer
			// manager; this is the whole of that surface.
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(m as any)['peerManager'] = {
				getPeer: () => ({
					getRemoteInit: () => ({ features: simpleCloseFeatures() })
				})
			};
		}
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
			recordClosingSend(side, type, p);
			queue.push({ from: pub, to, type, p });
			pump();
		});
	};
	managers.set(aPub, new ChannelManager(aConfig));
	managers.set(bPub, new ChannelManager(bConfig));
	attach(aPub, bPub);
	attach(bPub, aPub);

	const aChan = managers
		.get(aPub)!
		.openChannel(bPub, FUNDING_SATOSHIS, B_FLOAT_MSAT);
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
	expect(chan(aPub, bPub).getState()).to.equal(ChannelState.NORMAL);

	const reestPayload = (c: Channel): Buffer =>
		(
			c
				.createReestablish()
				.find((x) => x.type === ChannelActionType.SEND_MESSAGE) as {
				payload: Buffer;
			}
		).payload;

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

	const step = (side: Side): string | null => {
		const i = queue.findIndex((m) => m.from === pubOf(side));
		if (i < 0) return null;
		const [m] = queue.splice(i, 1);
		dispatch(m);
		return MessageType[m.type];
	};

	const wire: IWire = {
		cut: (): void => {
			alive = false;
			queue = [];
		},
		disconnect,
		replay,
		delivered,
		rows,
		manual: (on: boolean): void => {
			manualMode = on;
			if (!on) pump();
		},
		step,
		pendingTypes: (side: Side): string[] =>
			queue
				.filter((m) => m.from === pubOf(side))
				.map((m) => MessageType[m.type]),
		send: (from: Side, type: MessageType, payload: Buffer): void => {
			recordClosingSend(from, type, payload);
			queue.push({
				from: pubOf(from),
				to: pubOf(other(from)),
				type,
				p: payload
			});
			pump();
		},
		drop: (side: Side, count: number): string[] => {
			const lost: string[] = [];
			for (let n = 0; n < count; n++) {
				const i = queue.findIndex((m) => m.from === pubOf(side));
				if (i < 0) break;
				lost.push(MessageType[queue.splice(i, 1)[0].type]);
			}
			return lost;
		},
		drain: (pick: Policy): void => {
			let n = 0;
			while (queue.length > 0) {
				if (++n > 2000) throw new Error('wire never drained');
				const a = queue.filter((m) => m.from === aPub).length;
				const b = queue.length - a;
				const first = pick({ a, b, n });
				if (step(first) === null) step(other(first));
			}
		},
		reconnect: (manual?: boolean): void => {
			disconnect();
			const a = managers.get(aPub)!;
			const b = managers.get(bPub)!;
			alive = true;
			if (manual !== undefined) manualMode = manual;
			paused = true;
			const aRe = reestPayload(chan(aPub, bPub));
			const bRe = reestPayload(chan(bPub, aPub));
			b.handleMessage(aPub, MessageType.CHANNEL_REESTABLISH, aRe);
			a.handleMessage(bPub, MessageType.CHANNEL_REESTABLISH, bRe);
			check('after channel_reestablish');
			paused = false;
			replay.A = queue
				.filter((m) => m.from === aPub)
				.map((m) => MessageType[m.type]);
			replay.B = queue
				.filter((m) => m.from === bPub)
				.map((m) => MessageType[m.type]);
			pump();
		},
		restart: (side: Side, fromRow: boolean): void => {
			const pub = pubOf(side);
			const peer = pubOf(other(side));
			alive = false;
			queue = [];
			const row =
				fromRow && rows[side]
					? rows[side]!
					: JSON.stringify(
							serializeChannelState(chan(pub, peer).getFullState())
					  );
			const state = deserializeChannelState(JSON.parse(row));
			const fresh = new ChannelManager(side === 'A' ? aConfig : bConfig);
			fresh.restoreChannel(new Channel(state), peer);
			managers.set(pub, fresh);
			attach(pub, peer);
			managers.get(peer)!.handlePeerDisconnected(pub);
		}
	};

	return {
		tag,
		flavor,
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
		closingSends,
		violations,
		check,
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
const SHUTDOWN = 'SHUTDOWN';

interface IPayment {
	preimage: Buffer;
	hash: Buffer;
	amountMsat: bigint;
	from: Side;
}
type Removal = 'fulfil' | 'fail';
const REMOVALS: Removal[] = ['fulfil', 'fail'];

const mgr = (t: IPair, side: Side): ChannelManager =>
	side === 'A' ? t.A() : t.B();
const chanOf = (t: IPair, side: Side): Channel =>
	side === 'A' ? t.aChannel() : t.bChannel();

function offer(t: IPair, from: Side, amountMsat: bigint): IPayment {
	const preimage = t.nextPreimage();
	const hash = sha256(preimage);
	const r = mgr(t, from).addHtlc(t.channelId, amountMsat, hash, 900, ONION);
	expect(r.ok, `${from} offers: ${r.error}`).to.equal(true);
	return { preimage, hash, amountMsat, from };
}

/** The id of a received HTLC the node layer may settle (BOLT 2). */
function settleableId(t: IPair, p: IPayment): bigint | null {
	const receiver = other(p.from);
	const entry = [...chanOf(t, receiver).getFullState().htlcs.entries()].find(
		([key, h]) =>
			key.startsWith('received-') &&
			h.paymentHash.equals(p.hash) &&
			receivedAddIrrevocablyCommitted(h)
	);
	return entry ? entry[1].id : null;
}

/** A received HTLC entry as the channel keeps one, for the predicate tests. */
function offerEntry(): IHtlcEntry {
	return {
		id: 0n,
		amountMsat: HTLC_MSAT,
		paymentHash: sha256(Buffer.from('close-gate-entry')),
		cltvExpiry: 900,
		direction: HtlcDirection.RECEIVED,
		state: HtlcState.COMMITTED,
		onionRoutingPacket: ONION
	};
}

/** The receiver removes the HTLC: update and commitment_signed leave at once. */
function remove(t: IPair, p: IPayment, kind: Removal): void {
	const receiver = other(p.from);
	const id = settleableId(t, p);
	expect(id, `${receiver} holds the HTLC, irrevocably committed`).to.not.equal(
		null
	);
	const r =
		kind === 'fulfil'
			? mgr(t, receiver).fulfillHtlc(t.channelId, id!, p.preimage)
			: mgr(t, receiver).failHtlc(t.channelId, id!, Buffer.from('no'));
	expect(r.ok, `${receiver} ${kind}s: ${r.error}`).to.equal(true);
	t.check(`after ${receiver} sends its ${kind}`);
}

function shutdown(t: IPair, side: Side): void {
	const r = mgr(t, side).initiateShutdown(t.channelId, scriptOf(side));
	expect(r.ok, `${side} starts the shutdown: ${r.error}`).to.equal(true);
	// The node persists the row right after starting a close (closeChannel),
	// so a restart remembers the script it asked for.
	t.wire.rows[side] = JSON.stringify(
		serializeChannelState(chanOf(t, side).getFullState())
	);
	t.check(`after ${side} sends shutdown`);
}

/** A opened the channel and pushed B a balance of its own. */
function makeFundedPair(tag: string, flavor: Flavor = 'legacy'): IPair {
	const t = makePair(tag, flavor);
	expect(t.errors, t.errors.join('; ')).to.have.length(0);
	expect(t.aChannel().getBalances().localMsat).to.equal(A_START_MSAT);
	expect(t.bChannel().getBalances().localMsat).to.equal(B_FLOAT_MSAT);
	return t;
}

interface IExpected {
	aMsat: bigint;
	bMsat: bigint;
}

/** Final balances once `p` is resolved the given way on top of `base`. */
function after(base: IExpected, p: IPayment, kind: Removal): IExpected {
	if (kind === 'fail') return base;
	return p.from === 'A'
		? { aMsat: base.aMsat - p.amountMsat, bMsat: base.bMsat + p.amountMsat }
		: { aMsat: base.aMsat + p.amountMsat, bMsat: base.bMsat - p.amountMsat };
}
const START: IExpected = { aMsat: A_START_MSAT, bMsat: B_FLOAT_MSAT };

const stateName = (c: Channel): string => String(c.getState());

/**
 * What a reconnect during the negotiation itself leaves behind, on master as
 * well (pinned in section 3): our first move goes out once on reestablish and
 * once more when the peer's retransmitted shutdown arrives, and the second
 * copy reaches a channel that has already closed on the first. Nothing is
 * signed for it.
 */
const RECONNECT_NOISE =
	/^[AB]: (Unexpected closing_signed|closing_sig without a pending closing_complete)$/;

/**
 * Everything a finished case must satisfy; returns what does not hold.
 * `closed: false` skips the "both CLOSED" demand for cases that stop earlier;
 * `reconnected` tolerates RECONNECT_NOISE and nothing else.
 */
function problemsOf(
	t: IPair,
	expected: IExpected,
	opts: { closed?: boolean; reconnected?: boolean } = {}
): string[] {
	const out: string[] = [...t.violations];
	const expSat = { A: expected.aMsat / 1000n, B: expected.bMsat / 1000n };

	for (const s of t.closingSends) {
		const totalMsat = s.localMsat + s.remoteMsat;
		const want =
			s.side === 'A'
				? { local: expected.aMsat, remote: expected.bMsat }
				: { local: expected.bMsat, remote: expected.aMsat };
		if (
			s.htlcEntries > 0 ||
			s.keptRemovals > 0 ||
			totalMsat !== CAPACITY_MSAT ||
			s.localMsat !== want.local ||
			s.remoteMsat !== want.remote
		) {
			out.push(
				`${s.side} signed ${s.type} (fee ${s.feeSat} sat) over ${
					s.localMsat / 1000n
				} + ${s.remoteMsat / 1000n} = ${
					totalMsat / 1000n
				} of ${FUNDING_SATOSHIS} sat` +
					` (expected ${want.local / 1000n} + ${want.remote / 1000n})` +
					` with ${s.htlcEntries} HTLC entr${
						s.htlcEntries === 1 ? 'y' : 'ies'
					} and ${s.keptRemovals} kept removal(s) on its books`
			);
		}
	}

	const fees = new Set(t.closingSends.map((s) => s.feeSat));
	// A side that answers a shutdown pays to its manager's default script.
	const aScript = t.aChannel().getFullState().localShutdownScript;
	const bScript = t.bChannel().getFullState().localShutdownScript;
	for (const side of ['A', 'B'] as Side[]) {
		for (const raw of t.broadcasts[side]) {
			const tx = bitcoin.Transaction.fromBuffer(raw);
			const valueTo = (script: Buffer | null): bigint =>
				tx.outs
					.filter((o) => script && Buffer.from(o.script).equals(script))
					.reduce((sum, o) => sum + BigInt(o.value), 0n);
			const paid = tx.outs.reduce((sum, o) => sum + BigInt(o.value), 0n);
			const toA = valueTo(aScript);
			const toB = valueTo(bScript);
			const fee = FUNDING_SATOSHIS - paid;
			const aPays = toA === expSat.A - fee && toB === expSat.B;
			const bPays = toA === expSat.A && toB === expSat.B - fee;
			// The legacy and taproot negotiations take the fee from the opener.
			const payerOk = t.flavor === 'simple' ? aPays || bPays : aPays;
			if (
				toA + toB !== paid ||
				!payerOk ||
				!fees.has(fee) ||
				fee > MAX_SANE_FEE_SAT
			) {
				out.push(
					`${side} broadcast a closing transaction paying ${paid} of ${FUNDING_SATOSHIS} sat` +
						` (A ${toA}, B ${toB}; ${fee} sat to fees, negotiated ${[
							...fees
						].join('/')}): expected A ${expSat.A} and B ${
							expSat.B
						} less only the negotiated fee`
				);
			}
		}
	}

	if (opts.closed !== false) {
		const a = stateName(t.aChannel());
		const b = stateName(t.bChannel());
		if (a !== ChannelState.CLOSED || b !== ChannelState.CLOSED) {
			out.push(`the close did not finish: A is ${a}, B is ${b}`);
		} else if (t.broadcasts.A.length + t.broadcasts.B.length === 0) {
			out.push('both sides are CLOSED and nothing was broadcast');
		}
	}
	const errors = opts.reconnected
		? t.errors.filter((e) => !RECONNECT_NOISE.test(e))
		: t.errors;
	if (errors.length > 0) {
		out.push(`errors: ${errors.join('; ')}`);
	}
	return out;
}

/** Fail with every sub-case that broke, each on its own line. */
function expectNoProblems(problems: string[]): void {
	expect(problems, `\n${problems.join('\n')}\n`).to.have.length(0);
}

/**
 * The removal round, in the order its messages are delivered when nothing
 * else interleaves: whose oldest message goes, and what it is.
 */
function removalRound(
	p: IPayment,
	kind: Removal
): Array<{ from: Side; type: string }> {
	const receiver = other(p.from);
	return [
		{ from: receiver, type: kind === 'fulfil' ? FULFILL : FAIL },
		{ from: receiver, type: SIG },
		{ from: p.from, type: RAA },
		{ from: p.from, type: SIG },
		{ from: receiver, type: RAA }
	];
}

/** Deliver the first `k` messages of a round, checking each is the one meant. */
function deliverRound(
	t: IPair,
	round: Array<{ from: Side; type: string }>,
	k: number
): void {
	for (let i = 0; i < k; i++) {
		const got = t.wire.step(round[i].from);
		expect(got, `delivery ${i + 1} of the round`).to.equal(round[i].type);
	}
}

type Initiator = Side | 'both';
const INITIATORS: Initiator[] = ['A', 'B', 'both'];

function startShutdown(t: IPair, who: Initiator): void {
	if (who === 'both') {
		shutdown(t, 'A');
		shutdown(t, 'B');
	} else {
		shutdown(t, who);
	}
}

const who = (side: Side): string =>
	side === 'A' ? 'the opener' : 'the non-opener';
const initiatorName = (i: Initiator): string =>
	i === 'both' ? 'both sides at once' : who(i);

describe('cooperative close waits for every HTLC to be resolved (issue #1307)', function () {
	this.timeout(120_000);

	// ───────────── 1. shutdown crossing a removal in flight ─────────────

	describe('1. a shutdown that crosses a removal in flight', function () {
		/**
		 * One HTLC, fully committed. The receiver removes it; `k` messages of
		 * the removal round are delivered (0: the update is still on the wire;
		 * 5: the round is complete); the shutdown starts; the rest is
		 * delivered in the order the policy picks.
		 */
		const crossing = (
			flavor: Flavor,
			kind: Removal,
			offerer: Side,
			initiator: Initiator,
			k: number,
			policy: INamedPolicy
		): string[] => {
			const tag = `cross-${flavor}-${kind}-${offerer}-${initiator}-${k}`;
			const t = makeFundedPair(tag, flavor);
			const h = offer(t, offerer, HTLC_MSAT);
			t.wire.manual(true);
			remove(t, h, kind);
			deliverRound(t, removalRound(h, kind), k);
			startShutdown(t, initiator);
			t.wire.drain(policy.make());
			return problemsOf(t, after(START, h, kind)).map(
				(p) => `[${k} of 5 delivered, ${policy.name}] ${p}`
			);
		};

		for (const flavor of FLAVORS) {
			describe(flavor, function () {
				for (const kind of REMOVALS) {
					for (const offerer of ['A', 'B'] as Side[]) {
						for (const initiator of INITIATORS) {
							it(`${kind} of an HTLC offered by ${who(
								offerer
							)}, shutdown from ${initiatorName(
								initiator
							)}: the boundaries of the round, across delivery orders`, function () {
								const problems: string[] = [];
								for (const k of boundariesFor(flavor)) {
									for (const policy of policiesFor(flavor)) {
										problems.push(
											...crossing(flavor, kind, offerer, initiator, k, policy)
										);
									}
								}
								expectNoProblems(problems);
							});
						}
					}
				}
			});
		}
	});

	// ───────────── 2. shutdown crossing an add in flight ─────────────

	describe('2. a shutdown that crosses an add in flight', function () {
		const addRound = (from: Side): Array<{ from: Side; type: string }> => [
			{ from, type: ADD },
			{ from, type: SIG },
			{ from: other(from), type: RAA },
			{ from: other(from), type: SIG },
			{ from, type: RAA }
		];

		/**
		 * BOLT 2: no new add once shutdown is sent, but an add already sent
		 * must complete. The add leaves, `k` messages of its round are
		 * delivered, the shutdown starts. The channel has to wait in
		 * SHUTTING_DOWN with the HTLC committed on both sides, and close at
		 * full value once the HTLC is removed.
		 */
		const crossing = (
			flavor: Flavor,
			kind: Removal,
			offerer: Side,
			initiator: Initiator,
			k: number,
			policy: INamedPolicy
		): string[] => {
			const tag = `add-${flavor}-${kind}-${offerer}-${initiator}-${k}`;
			const label = (p: string): string =>
				`[${k} of 5 delivered, ${policy.name}, then ${kind}] ${p}`;
			const t = makeFundedPair(tag, flavor);
			t.wire.manual(true);
			const h = offer(t, offerer, HTLC_MSAT);
			deliverRound(t, addRound(offerer), k);
			startShutdown(t, initiator);
			t.wire.drain(policy.make());

			const early = problemsOf(t, START, { closed: false });
			const a = stateName(t.aChannel());
			const b = stateName(t.bChannel());
			if (
				a !== ChannelState.SHUTTING_DOWN ||
				b !== ChannelState.SHUTTING_DOWN
			) {
				early.push(
					`with the HTLC still live the channel must wait in SHUTTING_DOWN: A is ${a}, B is ${b}`
				);
			}
			if (settleableId(t, h) === null) {
				early.push('the add sent before the shutdown was not committed');
			}
			if (t.closingSends.length > 0) {
				early.push('a closing signature left while the HTLC was live');
			}
			if (early.length > 0) return early.map(label);

			// New adds are refused from here on.
			for (const side of ['A', 'B'] as Side[]) {
				const r = mgr(t, side).addHtlc(
					t.channelId,
					1_000_000n,
					sha256(Buffer.from(`${tag}-late-${side}`)),
					900,
					ONION
				);
				if (r.ok) early.push(`${side} could still add an HTLC after shutdown`);
			}
			t.errors.length = 0;
			if (early.length > 0) return early.map(label);

			remove(t, h, kind);
			t.wire.drain(policy.make());
			return problemsOf(t, after(START, h, kind)).map(label);
		};

		for (const flavor of FLAVORS) {
			describe(flavor, function () {
				for (const offerer of ['A', 'B'] as Side[]) {
					for (const initiator of INITIATORS) {
						it(`add from ${who(offerer)}, shutdown from ${initiatorName(
							initiator
						)}: the add completes, the close waits, then pays in full`, function () {
							const problems: string[] = [];
							// The removal that follows alternates with the boundary and
							// the delivery order, so both are covered throughout.
							for (const k of fewBoundariesFor(flavor)) {
								onePolicyFor(flavor, k).forEach((policy, i) => {
									const kind = REMOVALS[(k + i) % 2];
									problems.push(
										...crossing(flavor, kind, offerer, initiator, k, policy)
									);
								});
							}
							expectNoProblems(problems);
						});
					}
				}
			});
		}
	});

	// ───────────── 3. the removal round is cut by a disconnect ─────────────

	/**
	 * Both sides in SHUTTING_DOWN with one HTLC committed: the state every
	 * case of sections 3 and 4 starts its removal from.
	 */
	const shuttingDownWithHtlc = (
		tag: string,
		flavor: Flavor,
		offerer: Side,
		initiator: Initiator
	): { t: IPair; h: IPayment } => {
		const t = makeFundedPair(tag, flavor);
		const h = offer(t, offerer, HTLC_MSAT);
		startShutdown(t, initiator);
		expect(t.errors, t.errors.join('; ')).to.have.length(0);
		expect(t.aChannel().getState()).to.equal(ChannelState.SHUTTING_DOWN);
		expect(t.bChannel().getState()).to.equal(ChannelState.SHUTTING_DOWN);
		expect(settleableId(t, h)).to.not.equal(null);
		return { t, h };
	};

	describe('3. the removal round is cut while SHUTTING_DOWN, then reestablished', function () {
		it('the reported route: fulfil and its signature lost, replayed as [fulfil, signature, shutdown]', function () {
			const { t, h } = shuttingDownWithHtlc(
				'lost-reported',
				'legacy',
				'A',
				'B'
			);
			t.wire.cut();
			remove(t, h, 'fulfil');
			t.wire.reconnect();
			expect(t.wire.replay.B).to.deep.equal([FULFILL, SIG, SHUTDOWN]);
			// A holds the preimage either way.
			expect(t.fulfilled.A).to.have.length(1);
			expectNoProblems(
				problemsOf(t, after(START, h, 'fulfil'), { reconnected: true })
			);
		});

		for (const flavor of FLAVORS) {
			it(`PIN (same on master): ${flavor}, no HTLC at all, the connection drops during the negotiation`, function () {
				const t = makeFundedPair(`pin-reconnect-${flavor}`, flavor);
				t.wire.manual(true);
				shutdown(t, 'A');
				expect(t.wire.step('A')).to.equal(SHUTDOWN);
				expect(t.wire.step('B')).to.equal(SHUTDOWN);
				expect(t.aChannel().getState()).to.equal(
					ChannelState.NEGOTIATING_CLOSING
				);
				expect(t.bChannel().getState()).to.equal(
					ChannelState.NEGOTIATING_CLOSING
				);
				// The first closing signatures are lost with the connection.
				t.wire.cut();
				t.wire.reconnect(false);
				expectNoProblems(problemsOf(t, START, { reconnected: true }));
				expect(t.errors).to.deep.equal(
					flavor === 'legacy'
						? ['B: Unexpected closing_signed']
						: flavor === 'simple'
						? [
								'A: closing_sig without a pending closing_complete',
								'B: closing_sig without a pending closing_complete'
						  ]
						: []
				);
			});
		}

		const lost = (
			flavor: Flavor,
			kind: Removal,
			offerer: Side,
			k: number,
			policy: INamedPolicy
		): string[] => {
			const tag = `lost-${flavor}-${kind}-${offerer}-${k}`;
			const { t, h } = shuttingDownWithHtlc(tag, flavor, offerer, offerer);
			t.wire.manual(true);
			remove(t, h, kind);
			deliverRound(t, removalRound(h, kind), k);
			// Everything still on the wire is lost with the connection.
			t.wire.cut();
			t.wire.reconnect(true);
			t.wire.drain(policy.make());
			return problemsOf(t, after(START, h, kind), { reconnected: true }).map(
				(p) => `[${k} of 5 delivered before the cut, ${policy.name}] ${p}`
			);
		};

		for (const flavor of FLAVORS) {
			for (const kind of REMOVALS) {
				for (const offerer of ['A', 'B'] as Side[]) {
					it(`${flavor}: ${kind} of an HTLC offered by ${who(
						offerer
					)}, cut at the boundaries of the round`, function () {
						const problems: string[] = [];
						for (const k of fewBoundariesFor(flavor)) {
							for (const policy of onePolicyFor(flavor, k)) {
								problems.push(...lost(flavor, kind, offerer, k, policy));
							}
						}
						expectNoProblems(problems);
					});
				}
			}
		}
	});

	// ───────────── 4. restart in SHUTTING_DOWN with a removal in flight ─────────────

	describe('4. a restart in SHUTTING_DOWN with a removal in flight', function () {
		/**
		 * As section 3, but one side comes back from the last row its manager
		 * asked to persist (serialize, deserialize, a fresh manager). The
		 * side that only answered the shutdown has not necessarily persisted
		 * since, so its row can still say NORMAL: the peer's retransmitted
		 * shutdown brings it back.
		 */
		const restarted = (
			flavor: Flavor,
			kind: Removal,
			offerer: Side,
			side: Side,
			k: number
		): string[] => {
			const tag = `restart-${flavor}-${kind}-${offerer}-${side}-${k}`;
			const { t, h } = shuttingDownWithHtlc(tag, flavor, offerer, other(side));
			t.wire.manual(true);
			remove(t, h, kind);
			deliverRound(t, removalRound(h, kind), k);
			t.wire.restart(side, true);
			const label = (p: string): string =>
				`[${k} of 5 delivered, ${side} restarts] ${p}`;
			t.wire.reconnect(true);
			t.wire.drain(ALTERNATING.make());
			return problemsOf(t, after(START, h, kind), { reconnected: true }).map(
				label
			);
		};

		for (const flavor of FLAVORS) {
			for (const kind of flavor === 'legacy'
				? REMOVALS
				: (['fulfil'] as Removal[])) {
				for (const offerer of ['A', 'B'] as Side[]) {
					it(`${flavor}: ${kind} of an HTLC offered by ${who(
						offerer
					)}, either side restarting at the boundaries of the round`, function () {
						const problems: string[] = [];
						for (const side of ['A', 'B'] as Side[]) {
							for (const k of fewBoundariesFor(flavor)) {
								problems.push(...restarted(flavor, kind, offerer, side, k));
							}
						}
						expectNoProblems(problems);
					});
				}
			}
		}

		it('a shutdown that crossed the removal, then a restart of either side from its row', function () {
			const problems: string[] = [];
			for (const flavor of FLAVORS) {
				for (const side of ['A', 'B'] as Side[]) {
					for (const k of FULL ? EVERY_BOUNDARY : [0, 3]) {
						const tag = `restart-cross-${flavor}-${side}-${k}`;
						const t = makeFundedPair(tag, flavor);
						const h = offer(t, 'A', HTLC_MSAT);
						t.wire.manual(true);
						remove(t, h, 'fulfil');
						deliverRound(t, removalRound(h, 'fulfil'), k);
						shutdown(t, 'A');
						// A's shutdown and whatever it queued behind arrive; B's
						// answers are lost with the restart.
						while (t.wire.step('A') !== null);
						t.wire.restart(side, true);
						t.wire.reconnect(true);
						t.wire.drain(ALTERNATING.make());
						problems.push(
							...problemsOf(t, after(START, h, 'fulfil'), {
								reconnected: true
							}).map(
								(p) => `[${flavor}, ${k} of 5 delivered, ${side} restarts] ${p}`
							)
						);
					}
				}
			}
			expectNoProblems(problems);
		});

		it('a row written before this gate existed: NEGOTIATING_CLOSING with the removal still in flight goes back to SHUTTING_DOWN and finishes it', function () {
			const problems: string[] = [];
			for (const flavor of FLAVORS) {
				for (const k of FULL ? [0, 1, 2, 3, 4] : [1, 3]) {
					const tag = `old-row-${flavor}-${k}`;
					const { t, h } = shuttingDownWithHtlc(tag, flavor, 'A', 'A');
					t.wire.manual(true);
					remove(t, h, 'fulfil');
					deliverRound(t, removalRound(h, 'fulfil'), k);
					// What the old close path had persisted by now: the shutdown
					// exchange saw no PENDING or COMMITTED entry and moved on.
					for (const side of ['A', 'B'] as Side[]) {
						const state = chanOf(t, side).getFullState();
						state.state = ChannelState.NEGOTIATING_CLOSING;
						t.wire.rows[side] = JSON.stringify(serializeChannelState(state));
					}
					t.wire.restart('A', true);
					t.wire.restart('B', true);
					t.wire.reconnect(true);
					for (const side of ['A', 'B'] as Side[]) {
						const c = chanOf(t, side);
						if (
							c.closingBlockedBy() !== null &&
							c.getState() !== ChannelState.SHUTTING_DOWN
						) {
							problems.push(
								`[${flavor}, ${k} of 5 delivered] ${side} resumed in ${c.getState()} with ${c.closingBlockedBy()}`
							);
						}
					}
					t.wire.drain(ALTERNATING.make());
					problems.push(
						...problemsOf(t, after(START, h, 'fulfil'), {
							reconnected: true
						}).map((p) => `[${flavor}, ${k} of 5 delivered] ${p}`)
					);
				}
			}
			expectNoProblems(problems);
		});
	});

	// ───────────── 5. a peer that proposes the close early ─────────────

	describe('5. a peer that sends its closing signature while we still hold an HTLC', function () {
		/**
		 * The peer's ledger has lost the HTLC (its entry is deleted and our
		 * removal never reaches it), so its own code finds the channel empty
		 * and signs a close over balances that leave the HTLC out. From our
		 * side that signature is VALID: our balances are the same two numbers
		 * until the removal is irrevocably committed. We must not counter-sign
		 * it. BOLT 2 forbids the sender from doing this and leaves the
		 * receiver free to fail the channel or ignore the message; ignoring
		 * (a local refusal, nothing signed, the state and the funding watch
		 * untouched) never signs value away and keeps every exit open.
		 */
		const earlyClose = (
			flavor: Flavor,
			victim: Side
		): { t: IPair; h: IPayment } => {
			const peer = other(victim);
			const t = makeFundedPair(`early-${flavor}-${victim}`, flavor);
			// The victim fulfils an HTLC the peer offered: the 4000 sat are the
			// victim's once the removal commits, and until then on neither
			// balance.
			const h = offer(t, peer, HTLC_MSAT);
			t.wire.manual(true);
			remove(t, h, 'fulfil');
			expect(t.wire.drop(victim, 2)).to.deep.equal([FULFILL, SIG]);
			const peerHtlcs = chanOf(t, peer).getFullState().htlcs;
			expect([...peerHtlcs.keys()]).to.deep.equal(['offered-0']);
			peerHtlcs.clear();
			shutdown(t, victim);
			return { t, h };
		};

		/** What the victim must look like after refusing. */
		const expectRefused = (t: IPair, victim: Side, error: RegExp): void => {
			const c = chanOf(t, victim);
			expect(
				t.closingSends.filter((s) => s.side === victim),
				'the victim signed nothing'
			).to.deep.equal([]);
			expect(
				t.broadcasts[victim],
				'the victim broadcast nothing'
			).to.have.length(0);
			expect(c.getState(), 'the victim keeps waiting').to.equal(
				ChannelState.SHUTTING_DOWN
			);
			expect(
				c.getFullState().htlcs.size,
				'the HTLC is still on its books'
			).to.equal(1);
			expect(c.getFullState().lastCooperativeCloseTxHex ?? null).to.equal(null);
			expect(t.violations, t.violations.join('; ')).to.have.length(0);
			const mine = t.errors.filter((e) => e.startsWith(`${victim}: `));
			expect(mine, mine.join('; ')).to.have.length(1);
			expect(mine[0]).to.match(error);
		};

		for (const flavor of ['legacy', 'taproot'] as Flavor[]) {
			it(`${flavor}: closing_signed from the opener is not answered`, function () {
				const { t } = earlyClose(flavor, 'B');
				// A (the opener) answers the shutdown and proposes at once.
				t.wire.drain(ALTERNATING.make());
				expect(t.wire.delivered.slice(-3)).to.deep.equal([
					'B:SHUTDOWN',
					'A:SHUTDOWN',
					'A:CLOSING_SIGNED'
				]);
				expect(t.closingSends.map((s) => `${s.side}:${s.type}`)).to.deep.equal([
					'A:CLOSING_SIGNED'
				]);
				expectRefused(t, 'B', /Unexpected closing_signed: pending HTLCs/);
			});
		}

		it('legacy: an unsolicited closing_signed from the non-opener is not answered', function () {
			const { t } = earlyClose('legacy', 'A');
			t.wire.drain(ALTERNATING.make());
			expect(t.wire.delivered.slice(-2)).to.deep.equal([
				'A:SHUTDOWN',
				'B:SHUTDOWN'
			]);
			// B's ledger is empty; it signs the close it believes in.
			/* eslint-disable @typescript-eslint/no-explicit-any */
			const fee: bigint = (t.bChannel() as any).calculateIdealClosingFee();
			const sig: Buffer = (t.B() as any).signClosingTx(t.bChannel(), fee);
			// The worst case: from A's side the signature verifies.
			expect(
				(t.A() as any).verifyPeerClosingSig(t.aChannel(), fee, sig)
			).to.equal(true);
			/* eslint-enable @typescript-eslint/no-explicit-any */
			t.wire.send(
				'B',
				MessageType.CLOSING_SIGNED,
				encodeClosingSignedMessage({
					channelId: t.channelId,
					feeSatoshis: fee,
					signature: sig
				})
			);
			t.wire.drain(ALTERNATING.make());
			expect(t.wire.delivered.slice(-1)).to.deep.equal(['B:CLOSING_SIGNED']);
			expectRefused(t, 'A', /Unexpected closing_signed: pending HTLCs/);
		});

		for (const victim of ['A', 'B'] as Side[]) {
			it(`simple: closing_complete is not answered with closing_sig (${who(
				victim
			)} holds the HTLC)`, function () {
				const { t } = earlyClose('simple', victim);
				t.wire.drain(ALTERNATING.make());
				const peer = other(victim);
				expect(t.wire.delivered.slice(-3)).to.deep.equal([
					`${victim}:SHUTDOWN`,
					`${peer}:SHUTDOWN`,
					`${peer}:CLOSING_COMPLETE`
				]);
				expectRefused(t, victim, /Unexpected closing_complete: pending HTLCs/);
			});
		}
	});

	// ───────────── 6. other updates in flight ─────────────

	describe('6. other updates in flight beside a shutdown', function () {
		it('two removals crossing each other, one in each direction', function () {
			const problems: string[] = [];
			for (const flavor of FLAVORS) {
				for (const initiator of INITIATORS) {
					for (const policy of policiesFor(flavor)) {
						const tag = `two-way-${flavor}-${initiator}`;
						const t = makeFundedPair(tag, flavor);
						const ab = offer(t, 'A', HTLC_MSAT);
						const ba = offer(t, 'B', 7_000_000n);
						t.wire.manual(true);
						remove(t, ab, 'fulfil');
						remove(t, ba, 'fail');
						startShutdown(t, initiator);
						t.wire.drain(policy.make());
						problems.push(
							...problemsOf(t, after(START, ab, 'fulfil')).map(
								(p) =>
									`[${flavor}, shutdown from ${initiatorName(initiator)}, ${
										policy.name
									}] ${p}`
							)
						);
					}
				}
			}
			expectNoProblems(problems);
		});

		it('two removals back to back, the second behind an unrevoked signature', function () {
			const problems: string[] = [];
			for (const flavor of FLAVORS) {
				for (const initiator of INITIATORS) {
					for (const policy of policiesFor(flavor)) {
						const tag = `back-to-back-${flavor}-${initiator}`;
						const t = makeFundedPair(tag, flavor);
						const first = offer(t, 'A', HTLC_MSAT);
						const second = offer(t, 'A', 7_000_000n);
						t.wire.manual(true);
						remove(t, first, 'fulfil');
						remove(t, second, 'fulfil');
						// The second fulfil left without a signature: the first
						// one is still unrevoked.
						expect(t.wire.pendingTypes('B')).to.deep.equal([
							FULFILL,
							SIG,
							FULFILL
						]);
						startShutdown(t, initiator);
						t.wire.drain(policy.make());
						problems.push(
							...problemsOf(
								t,
								after(after(START, first, 'fulfil'), second, 'fulfil')
							).map(
								(p) =>
									`[${flavor}, shutdown from ${initiatorName(initiator)}, ${
										policy.name
									}] ${p}`
							)
						);
					}
				}
			}
			expectNoProblems(problems);
		});

		it('a signature that covers no update still has to be revoked for before the close', function () {
			// The stale needsCommitment of issue #1305 produces exactly this: a
			// commitment_signed with nothing new in it, in flight, with no
			// HTLC and no staged fee beside it.
			const problems: string[] = [];
			for (const flavor of FLAVORS) {
				for (const initiator of INITIATORS) {
					for (const policy of policiesFor(flavor)) {
						const t = makeFundedPair(
							`empty-sig-${flavor}-${initiator}`,
							flavor
						);
						t.wire.manual(true);
						t.aChannel().getFullState().needsCommitment = true;
						expect(t.aChannel().closingBlockedBy()).to.equal('pending updates');
						expect(t.A().autoSignAndSendCommitment(t.channelId).ok).to.equal(
							true
						);
						expect(t.wire.pendingTypes('A')).to.deep.equal([SIG]);
						expect(t.aChannel().closingBlockedBy()).to.equal('pending updates');
						startShutdown(t, initiator);
						t.wire.drain(policy.make());
						problems.push(
							...problemsOf(t, START).map(
								(p) =>
									`[${flavor}, shutdown from ${initiatorName(initiator)}, ${
										policy.name
									}] ${p}`
							)
						);
					}
				}
			}
			expectNoProblems(problems);
		});

		const feeRound: Array<{ from: Side; type: string }> = [
			{ from: 'A', type: 'UPDATE_FEE' },
			{ from: 'A', type: SIG },
			{ from: 'B', type: RAA },
			{ from: 'B', type: SIG },
			{ from: 'A', type: RAA }
		];

		for (const flavor of FLAVORS) {
			it(`${flavor}: an update_fee round crossed by a shutdown at its boundaries still closes`, function () {
				const problems: string[] = [];
				for (const initiator of INITIATORS) {
					for (const k of fewBoundariesFor(flavor)) {
						for (const policy of onePolicyFor(flavor, k)) {
							const tag = `fee-${flavor}-${initiator}-${k}`;
							const t = makeFundedPair(tag, flavor);
							t.wire.manual(true);
							const r = t.A().updateChannelFee(t.channelId, 600);
							expect(r.ok, r.error).to.equal(true);
							deliverRound(t, feeRound, k);
							startShutdown(t, initiator);
							t.wire.drain(policy.make());
							problems.push(
								...problemsOf(t, START).map(
									(p) =>
										`[shutdown from ${initiatorName(
											initiator
										)}, ${k} of 5 delivered, ${policy.name}] ${p}`
								)
							);
						}
					}
				}
				expectNoProblems(problems);
			});

			it(`${flavor}: an update_fee at the unchanged rate crossed by a shutdown still closes`, function () {
				const problems: string[] = [];
				for (const initiator of INITIATORS) {
					for (const k of fewBoundariesFor(flavor)) {
						for (const policy of policiesFor(flavor)) {
							const t = makeFundedPair(
								`same-fee-${flavor}-${initiator}-${k}-${policy.name}`,
								flavor
							);
							t.wire.manual(true);
							const rate = t.aChannel().getFullState().localConfig.feeratePerKw;
							expect(t.A().updateChannelFee(t.channelId, rate).ok).to.equal(
								true
							);
							deliverRound(t, feeRound, k);
							startShutdown(t, initiator);
							t.wire.drain(policy.make());
							problems.push(
								...problemsOf(t, START).map(
									(p) => `[${initiator}, ${k} delivered, ${policy.name}] ${p}`
								)
							);
						}
					}
				}
				expectNoProblems(problems);
			});

			it(`${flavor}: an unchanged fee awaiting the peer's signature survives restart and reconnect before closing`, function () {
				const problems: string[] = [];
				for (const initiator of INITIATORS) {
					for (const restarted of [null, 'A', 'B'] as Array<Side | null>) {
						const t = makeFundedPair(
							`same-fee-restart-${flavor}-${initiator}-${restarted}`,
							flavor
						);
						t.wire.manual(true);
						const rate = t.aChannel().getFullState().localConfig.feeratePerKw;
						expect(t.A().updateChannelFee(t.channelId, rate).ok).to.equal(true);
						deliverRound(t, feeRound, 3);
						expect(t.aChannel().closingBlockedBy()).to.equal('pending updates');
						startShutdown(t, initiator);
						t.wire.cut();
						if (restarted) t.wire.restart(restarted, true);
						expect(t.aChannel().closingBlockedBy()).to.equal('pending updates');
						t.wire.reconnect(false);
						problems.push(
							...problemsOf(t, START, { reconnected: true }).map(
								(p) => `[${initiator}, restart ${restarted}] ${p}`
							)
						);
					}
				}
				expectNoProblems(problems);
			});

			it(`${flavor}: an update_fee the peer already signed is not staged again on reconnect and the close finishes`, function () {
				const problems: string[] = [];
				for (const initiator of INITIATORS) {
					for (const when of ['before', 'after']) {
						for (const restarted of [null, 'A', 'B'] as Array<Side | null>) {
							const t = makeFundedPair(
								`fee-replay-${flavor}-${initiator}-${when}-${restarted}`,
								flavor
							);
							t.wire.manual(true);
							expect(t.A().updateChannelFee(t.channelId, 600).ok).to.equal(
								true
							);
							deliverRound(t, feeRound, 2);
							if (when === 'before') startShutdown(t, initiator);
							t.wire.cut();
							if (restarted) t.wire.restart(restarted, true);
							t.wire.reconnect(true);
							expect(t.wire.replay.A).to.not.include('UPDATE_FEE');
							if (when === 'after') startShutdown(t, initiator);
							t.wire.drain(policiesFor(flavor)[0].make());
							problems.push(
								...problemsOf(t, START, { reconnected: true }).map(
									(p) =>
										`[${initiator}, ${when} cut, restart ${restarted}] ${p}`
								)
							);
							if (
								t.bChannel().getFullState().pendingFeeratePerKw !== undefined
							) {
								problems.push(
									'the acceptor still stages a fee the opener will not sign'
								);
							}
						}
					}
				}
				expectNoProblems(problems);
			});

			it(`${flavor}: an update_fee whose commitment was lost is still replayed before closing`, function () {
				const t = makeFundedPair(`fee-lost-${flavor}`, flavor);
				t.wire.manual(true);
				expect(t.A().updateChannelFee(t.channelId, 600).ok).to.equal(true);
				expect(t.wire.step('A')).to.equal('UPDATE_FEE');
				t.wire.cut();
				t.wire.reconnect(true);
				expect(t.wire.replay.A.slice(0, 2)).to.deep.equal(['UPDATE_FEE', SIG]);
				startShutdown(t, 'B');
				t.wire.drain(policiesFor(flavor)[0].make());
				expectNoProblems(problemsOf(t, START, { reconnected: true }));
			});

			it(`${flavor}: an update_fee crossing the peer's commitment completes before closing`, function () {
				const problems: string[] = [];
				for (const sameRate of [false, true]) {
					for (const initiator of INITIATORS) {
						for (const policy of policiesFor(flavor)) {
							const t = makeFundedPair(
								`fee-cross-${flavor}-${sameRate}-${initiator}-${policy.name}`,
								flavor
							);
							t.wire.manual(true);
							const h = offer(t, 'B', HTLC_MSAT);
							const rate = sameRate
								? t.aChannel().getFullState().localConfig.feeratePerKw
								: 600;
							expect(t.A().updateChannelFee(t.channelId, rate).ok).to.equal(
								true
							);
							startShutdown(t, initiator);
							t.wire.drain(policy.make());
							remove(t, h, 'fulfil');
							t.wire.drain(policy.make());
							problems.push(...problemsOf(t, after(START, h, 'fulfil')));
						}
					}
				}
				expectNoProblems(problems);
			});
		}
	});

	// ───────────── 7. no HTLC at all ─────────────

	describe('7. a close with nothing in flight is unchanged', function () {
		/**
		 * Recorded on master (f16dfe5b) with this harness: every key, txid and
		 * preimage is derived from the tag, and the ECDSA signatures are
		 * deterministic, so the same close produces the same bytes. Each entry
		 * is the broadcasting side, the txid, and the SHA-256 of the whole
		 * transaction, witness included. Taproot closes sign with fresh MuSig2
		 * nonces; their txid, which leaves the witness out, pins everything
		 * else. CLOSE_GATE_PRINT_GOLDEN=1 prints the current values instead.
		 */
		const GOLDEN: Record<Flavor, Record<Side, string[]>> = {
			legacy: {
				A: [
					'A 4d4d51e0f75314d7d0717eeb42bd82fa9094b47c0fd7dcf21962575b463baa24 d817ffcc19295f00e054ed3b0bfd2c7ac0250f1b8af498136b89ce93506e9386',
					'B 4d4d51e0f75314d7d0717eeb42bd82fa9094b47c0fd7dcf21962575b463baa24 d817ffcc19295f00e054ed3b0bfd2c7ac0250f1b8af498136b89ce93506e9386'
				],
				B: [
					'A df8d453b9367ff8c2d9a51366fe54d6692ab6850d3697b4b721ded1d866e0341 ee83c0ff643e80a84a5a4947e0b581523104e08cae91bf6dfdd6a4991dcb3507',
					'B df8d453b9367ff8c2d9a51366fe54d6692ab6850d3697b4b721ded1d866e0341 ee83c0ff643e80a84a5a4947e0b581523104e08cae91bf6dfdd6a4991dcb3507'
				]
			},
			simple: {
				A: [
					'A 4c1c464682626cad7d64bf735a5727d86dfb9a3216f07d0295c1f43307f9dd0d 679aaacb6df6afd8c211e11b1feb2bf1a84f3f7f62b00357c5e59ba7c01a1349',
					'A 223c60488e5a172e09fe65e42d6f20f87dcbdb14f5bf96e9714309d7cd14c60e 9e5236c25adcf7ee88da54480f79864ee38b642d15bbbf9275018d57f29e38cd',
					'B 223c60488e5a172e09fe65e42d6f20f87dcbdb14f5bf96e9714309d7cd14c60e 9e5236c25adcf7ee88da54480f79864ee38b642d15bbbf9275018d57f29e38cd',
					'B 4c1c464682626cad7d64bf735a5727d86dfb9a3216f07d0295c1f43307f9dd0d 679aaacb6df6afd8c211e11b1feb2bf1a84f3f7f62b00357c5e59ba7c01a1349'
				],
				B: [
					'A 639b00c029727cd1f5a804d8ca8da54c892b86c8ce1d1ee253bc63862ddd5ce9 114b23387904236bbbc4d399f1e7c1829e2cbb55529fffefa32ef81245bbc705',
					'A 559aa21fcf6f66bef88e83ae962b47863681d4f201eb066c586ca79290df11c8 4108baf35f2ff2a845b4701127d02c72775afcd79fdf2216d2780672c560b4fa',
					'B 559aa21fcf6f66bef88e83ae962b47863681d4f201eb066c586ca79290df11c8 4108baf35f2ff2a845b4701127d02c72775afcd79fdf2216d2780672c560b4fa',
					'B 639b00c029727cd1f5a804d8ca8da54c892b86c8ce1d1ee253bc63862ddd5ce9 114b23387904236bbbc4d399f1e7c1829e2cbb55529fffefa32ef81245bbc705'
				]
			},
			taproot: {
				A: [
					'A 925286e5ef3669a95626156a08997561753fd6f008d6cf93b32cf05d8c5681c0',
					'B 925286e5ef3669a95626156a08997561753fd6f008d6cf93b32cf05d8c5681c0'
				],
				B: [
					'A 249720beff937ffa5e1451b80f40b6529e86eab3816cca7188bd1d2f8350532a',
					'B 249720beff937ffa5e1451b80f40b6529e86eab3816cca7188bd1d2f8350532a'
				]
			}
		};

		for (const flavor of FLAVORS) {
			for (const initiator of ['A', 'B'] as Side[]) {
				it(`${flavor}, shutdown from ${who(
					initiator
				)}: the broadcast transactions are the ones master produces`, function () {
					const t = makeFundedPair(`plain-${flavor}`, flavor);
					shutdown(t, initiator);
					expectNoProblems(problemsOf(t, START));
					const seen: string[] = [];
					for (const side of ['A', 'B'] as Side[]) {
						for (const raw of t.broadcasts[side]) {
							const tx = bitcoin.Transaction.fromBuffer(raw);
							seen.push(
								flavor === 'taproot'
									? `${side} ${tx.getId()}`
									: `${side} ${tx.getId()} ${sha256(raw).toString('hex')}`
							);
						}
					}
					if (process.env.CLOSE_GATE_PRINT_GOLDEN) {
						// eslint-disable-next-line no-console
						console.log(
							`GOLDEN ${flavor} ${initiator} ${JSON.stringify(seen)}`
						);
						return;
					}
					expect(seen).to.deep.equal(GOLDEN[flavor][initiator]);
				});
			}
		}
	});

	// ───────────── 8. the predicate itself ─────────────

	describe('8. what counts as not empty', function () {
		const blocked = (t: IPair): Record<Side, string | null> => ({
			A: t.aChannel().closingBlockedBy(),
			B: t.bChannel().closingBlockedBy()
		});
		const HTLCS = 'pending HTLCs';
		const UPDATES = 'pending updates';

		for (const kind of REMOVALS) {
			it(`a ${kind}: every step of the removal round, on both sides`, function () {
				const t = makeFundedPair(`predicate-${kind}`);
				expect(blocked(t)).to.deep.equal({ A: null, B: null });
				t.wire.manual(true);
				const h = offer(t, 'A', HTLC_MSAT);
				// The add round: an entry on each side that has seen the add.
				expect(blocked(t)).to.deep.equal({ A: HTLCS, B: null });
				t.wire.drain(ALTERNATING.make());
				expect(blocked(t)).to.deep.equal({ A: HTLCS, B: HTLCS });

				remove(t, h, kind);
				const round = removalRound(h, kind);
				const entryOf = (side: Side): string | undefined =>
					[...chanOf(t, side).getFullState().htlcs.values()][0]?.state;
				const keptOf = (side: Side): number =>
					chanOf(t, side).getFullState().signedLocalRemovals?.length ?? 0;
				const removed = kind === 'fulfil' ? 'FULFILLED' : 'FAILED';

				// Sent, nothing delivered: the old count saw B's entry no more.
				expect(entryOf('A')).to.equal('COMMITTED');
				expect(entryOf('B')).to.equal(removed);
				expect(blocked(t)).to.deep.equal({ A: HTLCS, B: HTLCS });

				deliverRound(t, round, 1); // the update reaches A
				expect(entryOf('A')).to.equal(removed);
				expect(blocked(t)).to.deep.equal({ A: HTLCS, B: HTLCS });

				deliverRound(t, round.slice(1), 1); // B's signature reaches A
				expect(blocked(t)).to.deep.equal({ A: HTLCS, B: HTLCS });

				deliverRound(t, round.slice(2), 1); // A's revoke_and_ack reaches B
				// B's entry is gone and its amount is on a balance, but the
				// commitment B holds still carries the output.
				expect(entryOf('B')).to.equal(undefined);
				expect(keptOf('B')).to.equal(1);
				expect(blocked(t)).to.deep.equal({ A: HTLCS, B: HTLCS });

				deliverRound(t, round.slice(3), 1); // A's signature reaches B
				// B has sent the last message of the round and is empty; A is
				// not until that revoke_and_ack arrives.
				expect(keptOf('B')).to.equal(0);
				expect(entryOf('A')).to.equal(removed);
				expect(blocked(t)).to.deep.equal({ A: HTLCS, B: null });

				deliverRound(t, round.slice(4), 1); // B's revoke_and_ack reaches A
				expect(blocked(t)).to.deep.equal({ A: null, B: null });
				expect(t.errors, t.errors.join('; ')).to.have.length(0);
			});
		}

		it('an update_fee: every step of its round, including the signature the peer still owes at the new rate', function () {
			const t = makeFundedPair('predicate-fee');
			t.wire.manual(true);
			expect(t.A().updateChannelFee(t.channelId, 600).ok).to.equal(true);
			// A staged it and signed; B has seen nothing.
			expect(blocked(t)).to.deep.equal({ A: UPDATES, B: null });
			expect(t.wire.step('A')).to.equal('UPDATE_FEE');
			expect(blocked(t)).to.deep.equal({ A: UPDATES, B: UPDATES });
			expect(t.wire.step('A')).to.equal(SIG);
			expect(blocked(t)).to.deep.equal({ A: UPDATES, B: UPDATES });
			expect(t.wire.step('B')).to.equal(RAA);
			// A's rate is promoted and nothing is staged any more, but the
			// commitment A holds is still signed at the old rate.
			const a = t.aChannel().getFullState();
			expect(a.pendingFeeratePerKw).to.equal(undefined);
			expect(a.localConfig.feeratePerKw).to.equal(600);
			expect(a.lastSignedCommitFeeratePerKw).to.not.equal(600);
			expect(t.aChannel().isAwaitingRemoteRevocation()).to.equal(false);
			expect(t.aChannel().needsCommitment()).to.equal(false);
			expect(blocked(t)).to.deep.equal({ A: UPDATES, B: UPDATES });
			expect(t.wire.step('B')).to.equal(SIG);
			expect(a.lastSignedCommitFeeratePerKw).to.equal(600);
			expect(blocked(t)).to.deep.equal({ A: null, B: UPDATES });
			expect(t.wire.step('A')).to.equal(RAA);
			expect(blocked(t)).to.deep.equal({ A: null, B: null });
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
		});

		it('each kind of pending update blocks on its own', function () {
			const t = makeFundedPair('predicate-each');
			const c = t.aChannel();
			const state = c.getFullState();
			expect(c.closingBlockedBy()).to.equal(null);
			/** Set one thing, read the gate, put it back. */
			const withOnly = (set: () => void, undo: () => void): string | null => {
				set();
				const got = c.closingBlockedBy();
				undo();
				expect(c.closingBlockedBy(), 'restored').to.equal(null);
				return got;
			};
			const kept = { ...offerEntry(), state: HtlcState.FULFILLED };
			expect(
				withOnly(
					() => (state.signedLocalRemovals = [kept]),
					() => (state.signedLocalRemovals = undefined)
				),
				'a kept removal'
			).to.equal(HTLCS);
			expect(
				withOnly(
					() => (state.needsCommitment = true),
					() => (state.needsCommitment = false)
				),
				'a signature we owe (the stale flag of #1305 included)'
			).to.equal(UPDATES);
			const revoked = state.remoteRevocationNumber;
			expect(
				withOnly(
					() => (state.remoteCommitmentNumber += 1n),
					() => (state.remoteCommitmentNumber -= 1n)
				),
				'a commitment of ours the peer has not revoked for'
			).to.equal(UPDATES);
			expect(state.remoteRevocationNumber).to.equal(revoked);
			expect(
				withOnly(
					() =>
						state.pendingLocalUpdates.push({
							type: MessageType.UPDATE_FEE,
							payload: Buffer.alloc(0)
						}),
					() => state.pendingLocalUpdates.pop()
				),
				'an update the peer has not acknowledged'
			).to.equal(UPDATES);
			// A staged update_fee on a row that predates the signed-rate record.
			const signedRate = state.lastSignedCommitFeeratePerKw;
			expect(signedRate).to.equal(state.localConfig.feeratePerKw);
			expect(
				withOnly(
					() => {
						state.lastSignedCommitFeeratePerKw = undefined;
						state.pendingFeeratePerKw = 600;
					},
					() => {
						state.lastSignedCommitFeeratePerKw = signedRate;
						state.pendingFeeratePerKw = undefined;
					}
				),
				'a staged update_fee'
			).to.equal(UPDATES);
			expect(
				withOnly(
					() => (state.lastSignedCommitFeeratePerKw = signedRate! + 1),
					() => (state.lastSignedCommitFeeratePerKw = signedRate)
				),
				'a commitment still signed at the previous feerate'
			).to.equal(UPDATES);
			expect(
				withOnly(
					() => (state.pendingLeaseBlockheight = 100),
					() => (state.pendingLeaseBlockheight = undefined)
				),
				'a staged update_blockheight'
			).to.equal(UPDATES);
			const signedHeight = state.lastSignedCommitLeaseBlockheight;
			expect(
				withOnly(
					() => (state.lastSignedCommitLeaseBlockheight = 100),
					() => (state.lastSignedCommitLeaseBlockheight = signedHeight)
				),
				'a commitment still signed at the previous lease blockheight'
			).to.equal(UPDATES);
		});

		for (const flavor of ['legacy', 'simple'] as Flavor[]) {
			it(`${flavor}: every signing stage refuses while a removal is in flight, at each step of it`, function () {
				const sign = (): Buffer => {
					throw new Error('a closing signature was asked for');
				};
				const problems: string[] = [];
				for (let k = 0; k <= 4; k++) {
					const t = makeFundedPair(`stages-${flavor}-${k}`, flavor);
					const h = offer(t, 'A', HTLC_MSAT);
					t.wire.manual(true);
					remove(t, h, 'fulfil');
					deliverRound(t, removalRound(h, 'fulfil'), k);
					shutdown(t, 'A');
					shutdown(t, 'B');
					// Each side has the other's shutdown; the round is where it was.
					for (const side of ['A', 'B'] as Side[]) {
						const queued = t.wire.pendingTypes(side);
						expect(queued[queued.length - 1]).to.equal(SHUTDOWN);
						const c = chanOf(t, side);
						c.getFullState().remoteShutdownScript = scriptOf(other(side));
					}
					for (const side of ['A', 'B'] as Side[]) {
						const c = chanOf(t, side);
						const blockedBy = c.closingBlockedBy();
						// After four deliveries B has sent the last message of the
						// round and is empty; every other (side, step) is not.
						if (blockedBy === null) {
							if (!(side === 'B' && k === 4)) {
								problems.push(`[${k}] ${side} reads as empty`);
							}
							continue;
						}
						const before = c.getState();
						const id = t.channelId;
						const scripts = {
							closerScriptPubkey: scriptOf(other(side)),
							closeeScriptPubkey: scriptOf(side)
						};
						type Stage = () => Array<{ type: string }>;
						const stages: Array<[string, Stage]> = [
							[
								'proposeClosingFee',
								(): ReturnType<Stage> => c.proposeClosingFee(sign)
							],
							[
								'handleClosingSigned',
								(): ReturnType<Stage> =>
									c.handleClosingSigned(
										{
											channelId: id,
											feeSatoshis: 171n,
											signature: Buffer.alloc(64)
										},
										sign,
										(): boolean => true
									)
							],
							[
								'sendClosingComplete',
								(): ReturnType<Stage> => c.sendClosingComplete(171n, 0, sign)
							],
							[
								'handleClosingComplete',
								(): ReturnType<Stage> =>
									c.handleClosingComplete(
										{
											channelId: id,
											...scripts,
											feeSatoshis: 171n,
											locktime: 0,
											closerAndCloseeSig: Buffer.alloc(64)
										},
										(): boolean => true,
										sign
									)
							],
							[
								'handleClosingSig',
								(): ReturnType<Stage> => {
									// Only NEGOTIATING_CLOSING reaches this stage, and
									// nothing enters a channel there, so it takes a row
									// from before the gate to arrive with an entry.
									const state = c.getFullState();
									state.state = ChannelState.NEGOTIATING_CLOSING;
									try {
										return c.handleClosingSig(
											{
												channelId: id,
												closerScriptPubkey: scriptOf(side),
												closeeScriptPubkey: scriptOf(other(side)),
												feeSatoshis: 171n,
												locktime: 0,
												closerAndCloseeSig: Buffer.alloc(64)
											},
											(): boolean => true
										);
									} finally {
										state.state = before;
									}
								}
							]
						];
						for (const [name, run] of stages) {
							let outcome: string;
							try {
								const actions = run();
								const error = actions.find(
									(a) => a.type === ChannelActionType.ERROR
								) as { message: string } | undefined;
								outcome =
									actions.length === 1 && error
										? error.message
										: `actions ${actions.map((a) => a.type).join(',')}`;
							} catch (err) {
								outcome = (err as Error).message;
							}
							const expected = new RegExp(`: ${blockedBy}$`);
							if (!expected.test(outcome) || c.getState() !== before) {
								problems.push(
									`[${k}] ${side} ${name} with ${blockedBy}: ${outcome}; state ${before} -> ${c.getState()}`
								);
							}
						}
					}
				}
				expectNoProblems(problems);
			});
		}

		it('beginClosingNegotiationIfReady moves only an empty SHUTTING_DOWN channel that has the peer shutdown', function () {
			const t = makeFundedPair('predicate-begin');
			// NORMAL: not its business.
			expect(t.aChannel().beginClosingNegotiationIfReady()).to.equal(false);
			expect(t.aChannel().getState()).to.equal(ChannelState.NORMAL);
			t.wire.manual(true);
			shutdown(t, 'A');
			// Empty, but the peer has not answered.
			expect(t.aChannel().getState()).to.equal(ChannelState.SHUTTING_DOWN);
			expect(t.aChannel().closingBlockedBy()).to.equal(null);
			expect(t.aChannel().beginClosingNegotiationIfReady()).to.equal(false);
			expect(t.aChannel().getState()).to.equal(ChannelState.SHUTTING_DOWN);
			t.wire.drain(ALTERNATING.make());
			expectNoProblems(problemsOf(t, START));
			// CLOSED: not its business either.
			expect(t.aChannel().beginClosingNegotiationIfReady()).to.equal(false);
			expect(t.aChannel().getState()).to.equal(ChannelState.CLOSED);
		});
	});
});
