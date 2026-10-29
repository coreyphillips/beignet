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
 * This module is the harness the section files share. Each section has a
 * file of its own, so mocha --parallel can spread them (section 1, the
 * longest, is split by flavor):
 *  1. a shutdown crossing a fulfil or a fail at each boundary of its round:
 *     tests/lightning/cooperative-close-htlc-gate-1-removal-crossing-legacy.test.ts
 *     tests/lightning/cooperative-close-htlc-gate-1-removal-crossing-simple.test.ts
 *     tests/lightning/cooperative-close-htlc-gate-1-removal-crossing-taproot.test.ts
 *  2. a shutdown crossing an add: the add completes, the close waits, then
 *     pays in full: tests/lightning/cooperative-close-htlc-gate-2-add-crossing.test.ts
 *  3. the removal round cut by a disconnect while SHUTTING_DOWN, then
 *     reestablished (the reported [fulfil, signature, shutdown] replay among
 *     them): tests/lightning/cooperative-close-htlc-gate-3-reestablish.test.ts
 *  4. a restart from the persisted row with a removal in flight, and a row
 *     written by the old close path: tests/lightning/cooperative-close-htlc-gate-4-restart.test.ts
 *  5. a peer that sends its closing signature early: nothing is signed:
 *     tests/lightning/cooperative-close-htlc-gate-5-early-closing-signature.test.ts
 *  6. other updates in flight: crossing removals, a deferred signature, an
 *     empty signature, an update_fee round: tests/lightning/cooperative-close-htlc-gate-6-other-updates.test.ts
 *  7. a close with nothing in flight broadcasts the transactions master does:
 *     tests/lightning/cooperative-close-htlc-gate-7-nothing-in-flight.test.ts
 *  8. the predicate itself, and every signing stage against it:
 *     tests/lightning/cooperative-close-htlc-gate-8-predicate.test.ts
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
} from '../../../src/lightning/channel/channel-manager';
import { Channel } from '../../../src/lightning/channel/channel';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	HtlcDirection,
	HtlcState,
	IHtlcEntry,
	receivedAddIrrevocablyCommitted
} from '../../../src/lightning/channel/types';
import { ChannelActionType } from '../../../src/lightning/channel/channel-actions';
import { MessageType } from '../../../src/lightning/message/types';
import {
	decodeClosingCompleteMessage,
	decodeClosingSigMessage,
	decodeClosingSignedMessage
} from '../../../src/lightning/message/channel-close';
import { Feature, FeatureFlags } from '../../../src/lightning/features/flags';
import { IChannelBasepoints } from '../../../src/lightning/keys/derivation';
import { getPublicKey } from '../../../src/lightning/crypto/ecdh';
import {
	serializeChannelState,
	deserializeChannelState
} from '../../../src/lightning/storage/serialization';
import { COMMIT_ALL, onPersist } from './channel-persistence';

export const sha256 = (b: Buffer): Buffer =>
	crypto.createHash('sha256').update(b).digest();

export type Flavor = 'legacy' | 'simple' | 'taproot';
export const FLAVORS: Flavor[] = ['legacy', 'simple', 'taproot'];

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
		...(flavor === 'simple' ? { localFeatures: simpleCloseFeatures() } : {}),
		persistence: COMMIT_ALL
	};
}

const FUNDING_SATOSHIS = 1_000_000n;
const CAPACITY_MSAT = FUNDING_SATOSHIS * 1000n;
/** Pushed to B at open so B can offer HTLCs of its own. */
const B_FLOAT_MSAT = 300_000_000n;
const A_START_MSAT = CAPACITY_MSAT - B_FLOAT_MSAT;
export const HTLC_MSAT = 4_000_000n;
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

export type Side = 'A' | 'B';
export const other = (s: Side): Side => (s === 'A' ? 'B' : 'A');
/** The script a side asks for when the test starts the shutdown on it. */
export const scriptOf = (s: Side): Buffer => (s === 'A' ? A_SCRIPT : B_SCRIPT);

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

export interface IPair {
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

export interface INamedPolicy {
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
export const ALTERNATING: INamedPolicy = {
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
export const FULL = process.env.CLOSE_GATE_FULL === '1';
const EXTRA_SEEDS = Number(process.env.CLOSE_GATE_SEEDS ?? '0');
const SEEDED = Array.from({ length: EXTRA_SEEDS }, (_, i) => seeded(i + 1));
const EVERY_ORDER = [A_FIRST, B_FIRST, ALTERNATING, ...SEEDED];
export const policiesFor = (flavor: Flavor): INamedPolicy[] =>
	FULL
		? EVERY_ORDER
		: flavor === 'legacy'
		? [A_FIRST, B_FIRST, ...SEEDED]
		: [ALTERNATING, ...SEEDED];
/** One order for case number `i`, for the sections that vary something else. */
export const onePolicyFor = (flavor: Flavor, i: number): INamedPolicy[] =>
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
export const EVERY_BOUNDARY = [0, 1, 2, 3, 4, 5];
export const boundariesFor = (flavor: Flavor): number[] =>
	FULL || flavor !== 'taproot' ? EVERY_BOUNDARY : [0, 2, 3];
export const fewBoundariesFor = (flavor: Flavor): number[] =>
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
		onPersist(m, ({ channel }) => {
			if (managers.get(pub) !== m) return;
			try {
				rows[side] = JSON.stringify(
					serializeChannelState(channel.getFullState())
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

export const ONION = Buffer.alloc(1366);
export const ADD = 'UPDATE_ADD_HTLC';
export const FULFILL = 'UPDATE_FULFILL_HTLC';
const FAIL = 'UPDATE_FAIL_HTLC';
export const SIG = 'COMMITMENT_SIGNED';
export const RAA = 'REVOKE_AND_ACK';
export const SHUTDOWN = 'SHUTDOWN';

export interface IPayment {
	preimage: Buffer;
	hash: Buffer;
	amountMsat: bigint;
	from: Side;
}
export type Removal = 'fulfil' | 'fail';
export const REMOVALS: Removal[] = ['fulfil', 'fail'];

export const mgr = (t: IPair, side: Side): ChannelManager =>
	side === 'A' ? t.A() : t.B();
export const chanOf = (t: IPair, side: Side): Channel =>
	side === 'A' ? t.aChannel() : t.bChannel();

export function offer(t: IPair, from: Side, amountMsat: bigint): IPayment {
	const preimage = t.nextPreimage();
	const hash = sha256(preimage);
	const r = mgr(t, from).addHtlc(t.channelId, amountMsat, hash, 900, ONION);
	expect(r.ok, `${from} offers: ${r.error}`).to.equal(true);
	return { preimage, hash, amountMsat, from };
}

/** The id of a received HTLC the node layer may settle (BOLT 2). */
export function settleableId(t: IPair, p: IPayment): bigint | null {
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
export function offerEntry(): IHtlcEntry {
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
export function remove(t: IPair, p: IPayment, kind: Removal): void {
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

export function shutdown(t: IPair, side: Side): void {
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
export function makeFundedPair(tag: string, flavor: Flavor = 'legacy'): IPair {
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
export function after(base: IExpected, p: IPayment, kind: Removal): IExpected {
	if (kind === 'fail') return base;
	return p.from === 'A'
		? { aMsat: base.aMsat - p.amountMsat, bMsat: base.bMsat + p.amountMsat }
		: { aMsat: base.aMsat + p.amountMsat, bMsat: base.bMsat - p.amountMsat };
}
export const START: IExpected = { aMsat: A_START_MSAT, bMsat: B_FLOAT_MSAT };

export const stateName = (c: Channel): string => String(c.getState());

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
export function problemsOf(
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
export function expectNoProblems(problems: string[]): void {
	expect(problems, `\n${problems.join('\n')}\n`).to.have.length(0);
}

/**
 * The removal round, in the order its messages are delivered when nothing
 * else interleaves: whose oldest message goes, and what it is.
 */
export function removalRound(
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
export function deliverRound(
	t: IPair,
	round: Array<{ from: Side; type: string }>,
	k: number
): void {
	for (let i = 0; i < k; i++) {
		const got = t.wire.step(round[i].from);
		expect(got, `delivery ${i + 1} of the round`).to.equal(round[i].type);
	}
}

export type Initiator = Side | 'both';
export const INITIATORS: Initiator[] = ['A', 'B', 'both'];

export function startShutdown(t: IPair, who: Initiator): void {
	if (who === 'both') {
		shutdown(t, 'A');
		shutdown(t, 'B');
	} else {
		shutdown(t, who);
	}
}

export const who = (side: Side): string =>
	side === 'A' ? 'the opener' : 'the non-opener';
export const initiatorName = (i: Initiator): string =>
	i === 'both' ? 'both sides at once' : who(i);

/**
 * One HTLC, fully committed. The receiver removes it; `k` messages of
 * the removal round are delivered (0: the update is still on the wire;
 * 5: the round is complete); the shutdown starts; the rest is
 * delivered in the order the policy picks.
 */
export const crossing = (
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

/**
 * Both sides in SHUTTING_DOWN with one HTLC committed: the state every
 * case of sections 3 and 4 starts its removal from.
 */
export const shuttingDownWithHtlc = (
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
