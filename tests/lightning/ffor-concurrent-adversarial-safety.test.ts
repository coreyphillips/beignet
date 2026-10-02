/**
 * Adversarial review of FFOR concurrent receive, PR 1 (issue #1283):
 * fund and protocol safety against a misbehaving or buggy counterparty,
 * and "baseline is unchanged".
 *
 * Every test passes. Most pin a property that held under attack. The
 * defects the review found in PR #1301 are fixed and their cases assert the
 * fixed behaviour. Cases titled PIN record a known gap that is NOT this
 * PR's to close, by asserting what happens today and naming where it is
 * tracked: the assertion fails, visibly, on the day the gap is closed, and
 * the case is then rewritten to the outcome its comment states.
 *
 * Environment knobs, for a longer run than the default:
 *   FFOR_FUZZ_SEEDS=a,b,c   random schedule seeds (default 1,2; each runs for
 *                           both funders, with and without redemptions)
 *   FFOR_FUZZ_STEPS=n       steps per schedule (default 40)
 *   FFOR_DRAIN_SEEDS=a,b,c  DRAINING interleaving seeds (default 101 to 104,
 *                           one per settled book)
 *   FFOR_FUZZ_CEILING=1     also compare the spendable ceiling with the
 *                           admission at every step
 */

import { expect } from 'chai';
import { Channel } from '../../src/lightning/channel/channel';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import {
	ChannelState,
	HtlcDirection,
	HtlcState
} from '../../src/lightning/channel/types';
import {
	buildLocalCommitment,
	buildRemoteCommitment
} from '../../src/lightning/channel/commitment-builder';
import { perCommitmentPointFromSecret } from '../../src/lightning/keys/derivation';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import { MessageType } from '../../src/lightning/message/types';
import {
	decodeUpdateAddHtlcMessage,
	encodeUpdateAddHtlcMessage,
	encodeUpdateFailHtlcMessage,
	encodeUpdateFailMalformedHtlcMessage,
	encodeUpdateFulfillHtlcMessage
} from '../../src/lightning/message/channel-update';
import { FforSlotState, FforState } from '../../src/lightning/ffor/types';
import {
	Feature,
	FeatureFlags,
	hasUnsupportedRequiredFeatures,
	implementedFeatures
} from '../../src/lightning/features/flags';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { PaymentStatus } from '../../src/lightning/node/types';
import { decodeNodeAnnouncementMessage } from '../../src/lightning/gossip/messages';
import { encodeShortChannelId } from '../../src/lightning/gossip/types';
import { decode as decodeInvoice } from '../../src/lightning/invoice/decode';
import {
	activateWorld,
	createConcurrentWorld
} from './helpers/ffor-concurrent-world';
import {
	AMOUNTS as WORLD_AMOUNTS,
	D_DEADLINE as WORLD_D_DEADLINE,
	IWorld,
	makeNodeConfig,
	NodeLink,
	openReadyChannel,
	pay as payInvoice,
	publishChannel,
	record as worldRecord,
	T_EXP as WORLD_T_EXP,
	TIP as WORLD_TIP
} from './helpers/ffor-world';
import { deserializeChannelState } from '../../src/lightning/storage/serialization';
import {
	activate,
	AMOUNTS,
	balances,
	channel,
	createPair,
	expectHealthy,
	expectVouchersCarried,
	IPair,
	manager,
	offer,
	ONION,
	other,
	pay,
	record,
	restart,
	settleSlot,
	sha,
	Side,
	snapshot,
	terms,
	TIP,
	why
} from './helpers/ffor-concurrent-pair';

const BADONION_INVALID_HMAC = 0x8000 | 0x4000 | 5;

function activePair(): IPair {
	const pair = createPair({ pushSat: 200_000n });
	activate(pair, AMOUNTS, true);
	pair.link.log.length = 0;
	return pair;
}

/**
 * The author's own recovery scenario (ffor-concurrent-reconnect.test.ts,
 * "R is DRAINING and S reestablishes without the close"): S comes back from
 * a backup that predates ff_close, R is DRAINING with its drain round lost
 * on the wire and a voucher fail queued, so R holds the whole
 * retransmission chain until S's ff_close_ack returns.
 */
function sLostTheClose(settled: number[]): IPair {
	const pair = activePair();
	const inbound = offer(pair, 'S', 6_000_000n);
	expect(inbound.result.ok, inbound.result.error).to.equal(true);
	for (const k of settled) settleSlot(pair, k);
	const backup = snapshot(pair, 'S');
	const queued = [
		...pair.rChannel.addHtlc(2_000_000n, sha('queued'), TIP + 100, ONION),
		...pair.rChannel.failMalformedHtlc(
			inbound.id,
			sha(ONION),
			BADONION_INVALID_HMAC
		)
	];
	expect(
		queued.filter((a) => a.type === ChannelActionType.ERROR)
	).to.deep.equal([]);
	pair.link.drop = (from, type): boolean =>
		from === 'R' && type !== MessageType.FF_CLOSE;
	const closed = pair.rManager.closeFforEpoch(pair.channelId);
	expect(closed.ok, closed.error).to.equal(true);
	expect(record(pair.rChannel).state).to.equal(FforState.DRAINING);
	pair.link.drop = null;
	restart(pair, 'S', backup);
	expect(record(pair.sChannel).state).to.equal(FforState.ACTIVE);
	pair.link.log.length = 0;
	pair.sErrors.length = 0;
	pair.rErrors.length = 0;
	return pair;
}

describe('FFOR concurrent receive, adversarial: the drain hold reorders the BOLT 2 stream', function () {
	this.timeout(30_000);

	it('control: a baseline epoch in the same recovery takes no add while the chain is held (the channel is frozen), and the released chain closes the book', () => {
		const pair = createPair({ pushSat: 200_000n });
		activate(pair, AMOUNTS, false);
		settleSlot(pair, 2);
		const backup = snapshot(pair, 'S');
		pair.link.drop = (from, type): boolean =>
			from === 'R' && type !== MessageType.FF_CLOSE;
		const closed = pair.rManager.closeFforEpoch(pair.channelId);
		expect(closed.ok, closed.error).to.equal(true);
		pair.link.drop = null;
		restart(pair, 'S', backup);
		pair.link.log.length = 0;
		pair.link.holdAt = (from, type): boolean =>
			from === 'S' && type === MessageType.FF_CLOSE_ACK;
		pair.link.reconnect();
		pair.link.holdAt = null;
		for (const side of ['S', 'R'] as Side[]) {
			const add = offer(pair, side, 1_000_000n);
			expect(add.result.ok, `${side} is frozen`).to.equal(false);
		}
		pair.sErrors.length = 0;
		pair.rErrors.length = 0;
		pair.link.release('S');
		expectHealthy(pair, 'baseline hold released');
		expect(record(pair.rChannel).state).to.equal(FforState.CLOSED);
		expect(record(pair.sChannel).state).to.equal(FforState.CLOSED);
	});

	it('control: the concurrent hold with no new traffic releases cleanly', () => {
		const pair = sLostTheClose([2]);
		pair.link.holdAt = (from, type): boolean =>
			from === 'S' && type === MessageType.FF_CLOSE_ACK;
		pair.link.reconnect();
		pair.link.holdAt = null;
		pair.link.release('S');
		expectHealthy(pair, 'concurrent hold released');
		expect(record(pair.rChannel).state).to.equal(FforState.CLOSED);
	});

	// Review round 1 of PR #1301: the channel is NORMAL while the chain is
	// held, and what it sent then left ahead of a commitment_signed made
	// before it, so S failed the channel when the chain was released. Fixed:
	// every BOLT 2 stream message R would send while holding joins the chain
	// (Channel.fforHoldStream), and a new add of R's is refused.
	it('an ordinary add of R made while the drain chain is held is refused locally, and the released chain closes the book', () => {
		const pair = sLostTheClose([2]);
		// S's ff_close_ack is delayed (S slow, or withholding it).
		pair.link.holdAt = (from, type): boolean =>
			from === 'S' && type === MessageType.FF_CLOSE_ACK;
		pair.link.reconnect();
		pair.link.holdAt = null;
		expect(pair.rChannel.getState()).to.equal(ChannelState.NORMAL);
		expect(record(pair.rChannel).state).to.equal(FforState.DRAINING);
		// The channel is NORMAL and the epoch concurrent, but R's wallet does
		// not pay into a close that is still being recovered.
		const add = offer(pair, 'R', 1_000_000n);
		expect(add.result.ok).to.equal(false);
		expect(add.result.error).to.match(
			/no new add while the close of the voucher book is being recovered/
		);
		expect(
			pair.link.log.filter((e) => e.from === 'R').map((e) => e.type),
			'nothing left ahead of the chain'
		).to.deep.equal([MessageType.CHANNEL_REESTABLISH, MessageType.FF_CLOSE]);
		pair.rErrors.length = 0;
		// The acknowledgement arrives and the held chain is released.
		pair.link.release('S');
		expect(pair.link.types(), `no wire error ${why(pair)}`).to.not.include(
			MessageType.ERROR
		);
		expectHealthy(pair, 'held chain released');
		expect(record(pair.rChannel).state).to.equal(FforState.CLOSED);
		expect(record(pair.sChannel).state).to.equal(FforState.CLOSED);
		// The hold is over and R pays again.
		pay(pair, 'R', 1_000_000n);
		expectHealthy(pair, 'a payment after the release');
	});

	it("an ordinary add S makes before R's ff_close reaches it is answered by R behind the held chain: the revoke_and_ack follows the held commitment_signed, and the add commits", () => {
		const pair = sLostTheClose([2]);
		// R's retransmitted ff_close is still on the wire when S, ACTIVE from
		// its backup and concurrent, originates an ordinary add.
		pair.link.holdAt = (from, type): boolean =>
			from === 'R' && type === MessageType.FF_CLOSE;
		pair.link.reconnect();
		pair.link.holdAt = null;
		expect(record(pair.sChannel).state).to.equal(FforState.ACTIVE);
		const add = offer(pair, 'S', 1_000_000n);
		expect(add.result.ok, add.result.error).to.equal(true);
		// R took S's commitment_signed. Its revoke_and_ack is not on the wire
		// behind ff_close: it waits with the held chain.
		expect(pair.link.inFlight('R')).to.deep.equal([MessageType.FF_CLOSE]);
		pair.link.release('R');
		const fromR = pair.link.log
			.filter((e) => e.from === 'R')
			.map((e) => e.type);
		expect(fromR.indexOf(MessageType.REVOKE_AND_ACK)).to.be.greaterThan(
			fromR.indexOf(MessageType.COMMITMENT_SIGNED)
		);
		expect(fromR.indexOf(MessageType.COMMITMENT_SIGNED)).to.be.greaterThan(-1);
		expect(pair.link.types(), `no wire error ${why(pair)}`).to.not.include(
			MessageType.ERROR
		);
		expectHealthy(pair, 'held chain released after a peer add');
		expect(record(pair.rChannel).state).to.equal(FforState.CLOSED);
		expect(
			pair.rChannel.getFullState().htlcs.has(`received-${add.id}`),
			"S's add is committed on R"
		).to.equal(true);
	});
});

// ─────────────── Randomized schedules ───────────────

/** Deterministic PRNG (mulberry32), so a failing seed replays exactly. */
function prng(seed: number): () => number {
	let a = seed >>> 0;
	return (): number => {
		a = (a + 0x6d2b79f5) >>> 0;
		let t = a;
		t = Math.imul(t ^ (t >>> 15), t | 1);
		t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
		return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
	};
}

interface IFuzzHtlc {
	from: Side;
	id: bigint;
	preimage: Buffer;
	amountMsat: bigint;
	outcome: 'open' | 'fulfilled' | 'failed';
}

interface IForceClosePlan {
	ok: boolean;
	error?: string;
}

/** prepareForceClose: the held commitment rebuilds under the stored signature. */
function planClose(pair: IPair, side: Side): IForceClosePlan {
	const mgr = manager(pair, side) as unknown as {
		signerFor(ch: Channel, htlc: boolean): unknown;
	};
	const ch = channel(pair, side) as unknown as {
		prepareForceClose(signer: unknown): IForceClosePlan;
	};
	return ch.prepareForceClose(mgr.signerFor(channel(pair, side), true));
}

/** Slots whose voucher is still COMMITTED on both sides. */
function unresolvedSlots(pair: IPair): number[] {
	const base = record(pair.rChannel).sHtlcIdBase!;
	const out: number[] = [];
	for (let k = 1; k <= AMOUNTS.length; k++) {
		const id = base + BigInt(k - 1);
		const r = pair.rChannel.getFullState().htlcs.get(`received-${id}`);
		const s = pair.sChannel.getFullState().htlcs.get(`offered-${id}`);
		if (
			r?.fforVoucher === true &&
			r.state === HtlcState.COMMITTED &&
			s?.fforVoucher === true &&
			s.state === HtlcState.COMMITTED
		) {
			out.push(k);
		}
	}
	return out;
}

/** Issue #1295's window on one side: a received add no signature covers yet. */
function receivedAddAwaitsSignature(pair: IPair, side: Side): boolean {
	for (const e of channel(pair, side).getFullState().htlcs.values()) {
		if (
			e.direction === HtlcDirection.RECEIVED &&
			e.addLocallyRevoked === false
		) {
			return true;
		}
	}
	return false;
}

/** Issue #1300's window on one side: updates queued behind an unrevoked signature. */
function replayOrderWindow(pair: IPair, side: Side): boolean {
	const ch = channel(pair, side);
	const st = ch.getFullState();
	return (
		ch.isAwaitingRemoteRevocation() &&
		st.pendingLocalUpdates.length > st.pendingLocalUpdatesSignedCount
	);
}

/**
 * The ceiling the router reads against what the two channels then do: an
 * add of exactly getSpendableOutboundMsat() is tried on copies of both
 * sides. It must not be refused by the sender for balance, the funder fee
 * or the fee-spike buffer, and the receiver must neither fail the channel
 * over it nor stamp it for a fail-back. Returns a description of the
 * mismatch, or null.
 */
function ceilingMismatch(pair: IPair, from: Side): string | null {
	const ceiling = channel(pair, from).getSpendableOutboundMsat();
	if (ceiling < 0n) return `negative ceiling ${ceiling}`;
	const min = channel(pair, from).getFullState().remoteConfig.htlcMinimumMsat;
	if (ceiling === 0n || ceiling < min) return null;
	const copy = (side: Side): Channel =>
		new Channel(deserializeChannelState(JSON.parse(snapshot(pair, side))));
	const sender = copy(from);
	const receiver = copy(other(from));
	const actions = sender.addHtlc(ceiling, sha('probe'), TIP + 100, ONION);
	const refused = actions.find((a) => a.type === ChannelActionType.ERROR);
	if (refused && refused.type === ChannelActionType.ERROR) {
		return /Insufficient balance|fee-spike buffer|cannot afford/.test(
			refused.message
		)
			? `${from}'s own ceiling ${ceiling} is refused: ${refused.message}`
			: null;
	}
	const send = actions.find(
		(a) =>
			a.type === ChannelActionType.SEND_MESSAGE &&
			a.messageType === MessageType.UPDATE_ADD_HTLC
	);
	if (!send || send.type !== ChannelActionType.SEND_MESSAGE) {
		return 'no update_add_htlc';
	}
	const msg = decodeUpdateAddHtlcMessage(send.payload);
	const taken = receiver.handleUpdateAddHtlc(msg);
	const failed = taken.find(
		(a) =>
			a.type === ChannelActionType.ERROR ||
			(a.type === ChannelActionType.SEND_MESSAGE &&
				a.messageType === MessageType.ERROR)
	);
	if (failed) {
		return `${other(from)} fails the channel on ${from}'s ceiling ${ceiling}: ${
			failed.type === ChannelActionType.ERROR ? failed.message : 'wire error'
		}`;
	}
	const entry = receiver.getFullState().htlcs.get(`received-${msg.id}`);
	if (entry?.funderFeeFailback === true) {
		return `${other(from)} stamps ${from}'s ceiling ${ceiling} for a fail-back`;
	}
	return null;
}

const FUZZ_AMOUNTS = [
	1n, // below every minimum
	999n,
	1_000n,
	353_999n, // dust, fractional
	354_000n, // the dust limit
	354_001n,
	546_250n, // a voucher's amount
	994_000n, // a voucher's amount
	1_234_567n,
	5_000_001n,
	20_000_000n,
	49_749_000n, // a voucher's amount
	150_000_000n
];

/**
 * One random schedule of ordinary traffic, crossings, disconnects, restarts
 * and a retirement beside a live concurrent book. Returns the trace.
 */
function runSchedule(
	seed: number,
	funder: Side,
	steps: number,
	redemptions = false
): string[] {
	const rand = prng(seed);
	const pick = <T>(xs: T[]): T => xs[Math.floor(rand() * xs.length)];
	const pair =
		funder === 'S'
			? createPair({ pushSat: 200_000n })
			: createPair({ funder: 'R', pushSat: 600_000n });
	activate(pair, AMOUNTS, true);
	pair.link.log.length = 0;
	const trace: string[] = [];
	const htlcs: IFuzzHtlc[] = [];
	const start = balances(pair);
	const held = new Set<Side>();
	let closeAsked = false;
	let settled: number[] = [];
	const ceilingMismatches: string[] = [];
	const tell = (): string =>
		`seed ${seed} funder ${funder}: ${trace.join(' | ')}`;

	const applyHold = (): void => {
		pair.link.holdAt =
			held.size === 0 ? null : (from): boolean => held.has(from);
	};
	const releaseAll = (): void => {
		held.clear();
		applyHold();
		// Alternate until nothing is in flight: a release can queue more.
		for (let i = 0; i < 20; i++) {
			pair.link.release('S');
			pair.link.release('R');
			if (
				pair.link.inFlight('S').length === 0 &&
				pair.link.inFlight('R').length === 0
			) {
				break;
			}
		}
	};
	/** A local refusal reports on the manager's error channel: not a fault. */
	const forgive = (side: Side, error: string | undefined): void => {
		const errors = side === 'S' ? pair.sErrors : pair.rErrors;
		const at = errors.lastIndexOf(error ?? '');
		if (at >= 0) errors.splice(at, 1);
	};
	const check = (label: string): void => {
		expect(
			pair.link.types(),
			`${label}: wire error; ${tell()} ${why(pair)}`
		).to.not.include(MessageType.ERROR);
		expect(pair.sErrors, `${label}: S errors; ${tell()}`).to.deep.equal([]);
		expect(pair.rErrors, `${label}: R errors; ${tell()}`).to.deep.equal([]);
		if (!pair.link.connected) return;
		expect(pair.sChannel.getState(), `${label}; ${tell()}`).to.equal(
			ChannelState.NORMAL
		);
		expect(pair.rChannel.getState(), `${label}; ${tell()}`).to.equal(
			ChannelState.NORMAL
		);
		const quiet =
			held.size === 0 &&
			pair.link.inFlight('S').length === 0 &&
			pair.link.inFlight('R').length === 0;
		// Whatever is in flight, each side can always close with what it holds.
		// Known and filed apart (#1295, fixed by #1296): a received add whose
		// commitment_signed has not arrived refuses the close by itself.
		for (const side of ['S', 'R'] as Side[]) {
			if (receivedAddAwaitsSignature(pair, side)) continue;
			const plan = planClose(pair, side);
			expect(
				plan.ok,
				`${label}: ${side} cannot force close: ${plan.error}; ${tell()}`
			).to.equal(true);
		}
		if (!quiet) return;
		const rState = record(pair.rChannel).state;
		if (rState === FforState.ACTIVE || rState === FforState.DRAINING) {
			expectVouchersCarried(pair, unresolvedSlots(pair), `${label}; ${tell()}`);
		}
		if (rState === FforState.ACTIVE && !redemptions) {
			expect(unresolvedSlots(pair), `${label}; ${tell()}`).to.deep.equal([
				1, 2, 3
			]);
		}
		if (rState === FforState.ACTIVE || rState === FforState.DRAINING) {
			for (const side of ['S', 'R'] as Side[]) {
				const mismatch = ceilingMismatch(pair, side);
				if (mismatch)
					ceilingMismatches.push(`${label}: ${mismatch}; ${tell()}`);
			}
		}
		const b = balances(pair);
		expect(b.s, `${label}: S's balance, both books; ${tell()}`).to.equal(
			b.rViewOfS
		);
		expect(b.r, `${label}: R's balance, both books; ${tell()}`).to.equal(
			b.sViewOfR
		);
		expect(b.s >= 0n && b.r >= 0n, `${label}: no negative balance`).to.equal(
			true
		);
	};

	for (let step = 0; step < steps; step++) {
		const roll = rand();
		if (!pair.link.connected) {
			if (roll < 0.3) {
				const side = pick<Side>(['S', 'R']);
				trace.push(`restart ${side}`);
				restart(pair, side);
			} else {
				trace.push('reconnect');
				pair.link.reconnect();
				check('reconnect');
			}
			continue;
		}
		if (roll < 0.34) {
			const from = pick<Side>(['S', 'R']);
			const amount = pick(FUZZ_AMOUNTS);
			const ceiling = channel(pair, from).getSpendableOutboundMsat();
			const a = offer(pair, from, amount);
			trace.push(`${from} offers ${amount}${a.result.ok ? '' : ' (refused)'}`);
			if (a.result.ok) {
				htlcs.push({
					from,
					id: a.id,
					preimage: a.preimage,
					amountMsat: amount,
					outcome: 'open'
				});
			} else {
				forgive(from, a.result.error);
				// The ceiling the router reads never admits what addHtlc then
				// refuses for balance or the fee-spike buffer.
				if (amount <= ceiling) {
					expect(
						a.result.error,
						`an amount under the ceiling ${ceiling} was refused; ${tell()}`
					).to.not.match(/Insufficient balance|fee-spike buffer/);
				}
			}
			check('offer');
		} else if (roll < 0.62) {
			const open = htlcs.filter(
				(h) =>
					h.outcome === 'open' &&
					pair.events[other(h.from)].forwarded.includes(h.id) &&
					channel(pair, other(h.from)).canFulfillHtlc(h.id)
			);
			if (open.length === 0) continue;
			const h = pick(open);
			const to = other(h.from);
			const stamped =
				channel(pair, to).receivedHtlcExceedsFunderFee(h.id) ||
				channel(pair, to).receivedHtlcExceedsDustExposure(h.id);
			const how = stamped ? 1 : rand();
			const res =
				how < 0.6
					? manager(pair, to).fulfillHtlc(pair.channelId, h.id, h.preimage)
					: how < 0.8
					? manager(pair, to).failHtlc(pair.channelId, h.id, Buffer.alloc(292))
					: manager(pair, to).failMalformedHtlc(
							pair.channelId,
							h.id,
							sha(ONION),
							BADONION_INVALID_HMAC
					  );
			trace.push(
				`${to} ${how < 0.6 ? 'fulfils' : 'fails'} ${h.from}:${h.id}${
					res.ok ? '' : ' (refused)'
				}`
			);
			if (res.ok) h.outcome = how < 0.6 ? 'fulfilled' : 'failed';
			else forgive(to, res.error);
			check('settle');
		} else if (roll < 0.74) {
			const side = pick<Side>(['S', 'R']);
			if (held.has(side)) {
				held.delete(side);
				applyHold();
				trace.push(`release ${side}`);
				pair.link.release(side);
			} else {
				held.add(side);
				applyHold();
				trace.push(`hold ${side}`);
			}
			check('hold');
		} else if (roll < 0.82) {
			// Known and filed apart (#1300): a reconnect replays updates queued
			// after an unrevoked commitment_signed ahead of it. Not this PR's;
			// the schedules stay out of that window.
			if (replayOrderWindow(pair, 'S') || replayOrderWindow(pair, 'R')) {
				continue;
			}
			trace.push('disconnect');
			held.clear();
			applyHold();
			pair.link.disconnect();
		} else if (roll < 0.9 && !closeAsked) {
			const now = [1, 2, 3].filter((k) => !settled.includes(k) && rand() < 0.5);
			for (const k of now) settleSlot(pair, k);
			settled = [...settled, ...now];
			const res = pair.rManager.closeFforEpoch(pair.channelId);
			trace.push(`close, settled [${settled}]${res.ok ? '' : ' (refused)'}`);
			if (res.ok) closeAsked = true;
			else forgive('R', res.error);
			check('close');
		} else if (roll < 0.96 && !closeAsked && redemptions) {
			// A paid voucher redeemed while ACTIVE, driven by hand: S takes
			// it from any R that sends it (PR 2 gives ours the caller).
			const open = [1, 2, 3].filter((k) => !settled.includes(k));
			if (open.length === 0) continue;
			const k = pick(open);
			const base = record(pair.rChannel).sHtlcIdBase!;
			const t = record(pair.sChannel).preimages[k - 1];
			settleSlot(pair, k);
			settled = [...settled, k];
			const learned = pair.rManager.fforAddPreimage(pair.channelId, t);
			expect(learned.ok, `${learned.error}; ${tell()}`).to.equal(true);
			const internal = pair.rChannel as unknown as {
				_fforInternalSettle: boolean;
			};
			internal._fforInternalSettle = true;
			const res = pair.rManager.fulfillHtlc(
				pair.channelId,
				base + BigInt(k - 1),
				t
			);
			internal._fforInternalSettle = false;
			trace.push(`redeem ${k}${res.ok ? '' : ' (refused)'}`);
			expect(res.ok, `${res.error}; ${tell()}`).to.equal(true);
			check('redeem');
		}
	}

	// Wind down: deliver everything, reconnect, retire the book, settle all.
	releaseAll();
	if (!pair.link.connected) pair.link.reconnect();
	trace.push('wind down');
	check('wind down');
	if (!closeAsked) {
		const res = pair.rManager.closeFforEpoch(pair.channelId);
		expect(res.ok, `${res.error}; ${tell()}`).to.equal(true);
	}
	check('retired');
	const expectClosed = (): void => {
		expect(
			record(pair.rChannel).state,
			`R closed; ${tell()} ${why(pair)}`
		).to.equal(FforState.CLOSED);
		expect(
			record(pair.sChannel).state,
			`S closed; ${tell()} ${why(pair)}`
		).to.equal(FforState.CLOSED);
	};
	// With every voucher redeemed while ACTIVE the interim CLOSED rule needs
	// one more commitment round after ff_close (pinned above),
	// which the final settles below supply; otherwise CLOSED is already due.
	const drainedBeforeClose =
		redemptions && record(pair.rChannel).state === FforState.DRAINING;
	if (drainedBeforeClose) {
		expect(unresolvedSlots(pair), tell()).to.deep.equal([]);
		const nudge = offer(pair, 'S', 1_000_000n);
		expect(nudge.result.ok, `${nudge.result.error}; ${tell()}`).to.equal(true);
		htlcs.push({
			from: 'S',
			id: nudge.id,
			preimage: nudge.preimage,
			amountMsat: 1_000_000n,
			outcome: 'open'
		});
	}
	expectClosed();
	for (const h of htlcs) {
		if (h.outcome !== 'open') continue;
		const to = other(h.from);
		const res = manager(pair, to).failHtlc(
			pair.channelId,
			h.id,
			Buffer.alloc(292)
		);
		expect(
			res.ok,
			`final fail of ${h.from}:${h.id}: ${res.error}; ${tell()}`
		).to.equal(true);
		h.outcome = 'failed';
	}
	check('settled');
	expect(pair.sChannel.getFullState().htlcs.size, tell()).to.equal(0);
	expect(pair.rChannel.getFullState().htlcs.size, tell()).to.equal(0);
	let sExpected = start.s;
	let rExpected = start.r;
	for (let k = 1; k <= AMOUNTS.length; k++) {
		if (settled.includes(k)) rExpected += AMOUNTS[k - 1];
		else sExpected += AMOUNTS[k - 1];
	}
	for (const h of htlcs) {
		if (h.outcome !== 'fulfilled') continue;
		if (h.from === 'S') {
			sExpected -= h.amountMsat;
			rExpected += h.amountMsat;
		} else {
			rExpected -= h.amountMsat;
			sExpected += h.amountMsat;
		}
	}
	expect(balances(pair), tell()).to.deep.equal({
		s: sExpected,
		r: rExpected,
		sViewOfR: rExpected,
		rViewOfS: sExpected
	});
	// HTLC ids never returned to the voucher range and never reset.
	const sOffered = htlcs.filter((h) => h.from === 'S').map((h) => h.id);
	const base = record(pair.sChannel).sHtlcIdBase!;
	for (const id of sOffered) {
		expect(id >= base + BigInt(AMOUNTS.length), tell()).to.equal(true);
	}
	expect(new Set(sOffered).size, tell()).to.equal(sOffered.length);
	if (process.env.FFOR_FUZZ_CEILING) {
		expect(
			ceilingMismatches.slice(0, 3),
			'ceiling and admission agree'
		).to.deep.equal([]);
	}
	return trace;
}

describe('FFOR concurrent receive, adversarial: random schedules beside a live book', function () {
	this.timeout(600_000);
	const seeds = process.env.FFOR_FUZZ_SEEDS
		? process.env.FFOR_FUZZ_SEEDS.split(',').map(Number)
		: [1, 2];
	const steps = Number(process.env.FFOR_FUZZ_STEPS ?? 40);
	for (const funder of ['S', 'R'] as Side[]) {
		for (const seed of seeds) {
			it(`funder ${funder}, seed ${seed}: balances exact, vouchers kept, both sides can always close`, () => {
				runSchedule(seed, funder, steps);
			});
			it(`funder ${funder}, seed ${seed}, with vouchers redeemed while ACTIVE: balances exact, the rest kept, both sides can always close`, () => {
				runSchedule(seed + 5000, funder, steps, true);
			});
		}
	}
});

// ─────────────── The unilateral exit beside an admitted add ───────────────

describe('FFOR concurrent receive, adversarial: the unilateral exit while ACTIVE', function () {
	this.timeout(30_000);

	/** S's next ordinary update_add_htlc, sent with no commitment_signed. */
	function unsignedAddFromS(pair: IPair): void {
		const id = pair.sChannel.getFullState().localHtlcCounter;
		pair.rManager.handleMessage(
			pair.sPub,
			MessageType.UPDATE_ADD_HTLC,
			encodeUpdateAddHtlcMessage({
				channelId: pair.channelId,
				id,
				amountMsat: 1_000_000n,
				paymentHash: sha('withheld'),
				cltvExpiry: TIP + 100,
				onionRoutingPacket: ONION
			})
		);
	}

	it('control: R can force close a concurrent ACTIVE epoch with the vouchers live', () => {
		const pair = activePair();
		const plan = planClose(pair, 'R');
		expect(plan.ok, plan.error).to.equal(true);
	});

	it('control: a baseline epoch answers the same add by failing the channel, so nothing is left to block the close', () => {
		const pair = createPair({ pushSat: 200_000n });
		activate(pair, AMOUNTS, false);
		unsignedAddFromS(pair);
		expect(pair.link.types()).to.include(MessageType.ERROR);
		expect(
			pair.rChannel.getFullState().htlcs.size,
			'only the vouchers are on the channel'
		).to.equal(AMOUNTS.length);
	});

	// Issue #1295, fixed on master by #1296: a received add the peer has not
	// signed in no longer blocks the force close. A concurrent epoch is where
	// a peer can send such an add beside live vouchers, so both directions
	// are kept here as regressions.
	it('regression (#1295): S sends one ordinary update_add_htlc and withholds its commitment_signed; R can still force close, so a voucher it holds the preimage of stays claimable on chain', () => {
		const pair = activePair();
		// R holds the preimage of slot 2 (a payer's receipt): its claim on the
		// voucher is enforceable on chain only through a force close.
		const learned = pair.rManager.fforAddPreimage(
			pair.channelId,
			record(pair.sChannel).preimages[1]
		);
		expect(learned.ok, learned.error).to.equal(true);
		unsignedAddFromS(pair);
		expect(pair.link.types(), 'the add is admitted').to.not.include(
			MessageType.ERROR
		);
		expect(pair.rChannel.getState()).to.equal(ChannelState.NORMAL);
		const plan = planClose(pair, 'R');
		expect(plan.ok, `R cannot force close: ${plan.error}`).to.equal(true);
		expect(pair.rChannel.getFullState().htlcs.size).to.equal(
			AMOUNTS.length + 1
		);
	});
});

describe('FFOR concurrent receive, adversarial: the unilateral exit while ACTIVE, S side', function () {
	this.timeout(30_000);

	it('regression (#1295): R sends one ordinary update_add_htlc and withholds its commitment_signed; S can still force close, so its expiry backstop for the vouchers and for every other HTLC stays armed', () => {
		const pair = activePair();
		const id = pair.rChannel.getFullState().localHtlcCounter;
		pair.sManager.handleMessage(
			pair.rPub,
			MessageType.UPDATE_ADD_HTLC,
			encodeUpdateAddHtlcMessage({
				channelId: pair.channelId,
				id,
				amountMsat: 1_000_000n,
				paymentHash: sha('withheld by R'),
				cltvExpiry: TIP + 100,
				onionRoutingPacket: ONION
			})
		);
		expect(pair.link.types(), 'the add is admitted').to.not.include(
			MessageType.ERROR
		);
		const plan = planClose(pair, 'S');
		expect(plan.ok, `S cannot force close: ${plan.error}`).to.equal(true);
	});
});

// ─────────────── Voucher settles from the peer, on the wire ───────────────

describe('FFOR concurrent receive, adversarial: voucher settles a malicious R sends', function () {
	this.timeout(30_000);

	/** Redeem slot k by hand, as an R with a caller for it (PR 2, or not ours) does. */
	function redeem(pair: IPair, k: number): void {
		const base = record(pair.rChannel).sHtlcIdBase!;
		const t = record(pair.sChannel).preimages[k - 1];
		settleSlot(pair, k);
		const learned = pair.rManager.fforAddPreimage(pair.channelId, t);
		expect(learned.ok, learned.error).to.equal(true);
		const internal = pair.rChannel as unknown as {
			_fforInternalSettle: boolean;
		};
		internal._fforInternalSettle = true;
		const res = pair.rManager.fulfillHtlc(
			pair.channelId,
			base + BigInt(k - 1),
			t
		);
		internal._fforInternalSettle = false;
		expect(res.ok, res.error).to.equal(true);
	}

	for (const how of [
		'update_fail_htlc',
		'update_fail_malformed_htlc'
	] as const) {
		it(`ACTIVE: ${how} for a voucher fails the channel on S, the voucher stays COMMITTED and S can still close with it`, () => {
			const pair = activePair();
			const base = record(pair.sChannel).sHtlcIdBase!;
			const before = balances(pair);
			pair.sManager.handleMessage(
				pair.rPub,
				how === 'update_fail_htlc'
					? MessageType.UPDATE_FAIL_HTLC
					: MessageType.UPDATE_FAIL_MALFORMED_HTLC,
				how === 'update_fail_htlc'
					? encodeUpdateFailHtlcMessage({
							channelId: pair.channelId,
							id: base + 2n,
							reason: Buffer.alloc(292)
					  })
					: encodeUpdateFailMalformedHtlcMessage({
							channelId: pair.channelId,
							id: base + 2n,
							sha256OfOnion: sha(ONION),
							failureCode: BADONION_INVALID_HMAC
					  })
			);
			expect(pair.link.types()).to.include(MessageType.ERROR);
			const entry = pair.sChannel
				.getFullState()
				.htlcs.get(`offered-${base + 2n}`)!;
			expect(entry.state).to.equal(HtlcState.COMMITTED);
			expect(entry.fforVoucher).to.equal(true);
			expect(balances(pair).s).to.equal(before.s);
			expect(planClose(pair, 'S').ok).to.equal(true);
		});
	}

	it('ACTIVE: a voucher fulfil with a wrong preimage fails the channel and credits nothing', () => {
		const pair = activePair();
		const base = record(pair.sChannel).sHtlcIdBase!;
		const before = balances(pair);
		pair.sManager.handleMessage(
			pair.rPub,
			MessageType.UPDATE_FULFILL_HTLC,
			encodeUpdateFulfillHtlcMessage({
				channelId: pair.channelId,
				id: base,
				// Slot 2's preimage aimed at slot 1's id.
				paymentPreimage: record(pair.sChannel).preimages[1]
			})
		);
		expect(pair.link.types()).to.include(MessageType.ERROR);
		expect(
			pair.sChannel.getFullState().htlcs.get(`offered-${base}`)!.state
		).to.equal(HtlcState.COMMITTED);
		expect(balances(pair).s).to.equal(before.s);
	});

	it('ACTIVE: every voucher redeemed one by one beside ordinary traffic; balances exact, the rest carried, ids never reused', () => {
		const pair = activePair();
		const start = balances(pair);
		redeem(pair, 3);
		expectVouchersCarried(pair, [1, 2], 'after 3');
		pay(pair, 'S', 7_000_001n);
		redeem(pair, 1);
		expectVouchersCarried(pair, [2], 'after 1');
		pay(pair, 'R', 60_000_999n);
		expectHealthy(pair, 'redemptions beside traffic');
		expect(balances(pair)).to.deep.equal({
			s: start.s - 7_000_001n + 60_000_999n,
			r: start.r + AMOUNTS[2] + AMOUNTS[0] + 7_000_001n - 60_000_999n,
			sViewOfR: start.r + AMOUNTS[2] + AMOUNTS[0] + 7_000_001n - 60_000_999n,
			rViewOfS: start.s - 7_000_001n + 60_000_999n
		});
		expect(planClose(pair, 'S').ok).to.equal(true);
		expect(planClose(pair, 'R').ok).to.equal(true);
	});

	// PR 1 of #1283 has an interim CLOSED rule (DRAINING, no voucher entry
	// left, checked at a commitment round boundary). R has no caller that
	// redeems while ACTIVE until PR 2 of #1283, whose terminal slot records
	// replace the rule. Until then this case PINS what the interim rule does
	// when a hand-driven R redeemed every voucher before ff_close. Required
	// once PR 2 lands (CONCURRENT-RECEIVE.md section 7: CLOSED means every
	// voucher has been irrevocably resolved): both sides CLOSED at the
	// acknowledgement, with no ordinary round needed.
	it('PIN [PR 2 of #1283] (interim CLOSED rule): when every voucher was redeemed while ACTIVE, ff_close and its acknowledgement leave both sides DRAINING with nothing to drain, until an ordinary round passes', () => {
		const pair = activePair();
		redeem(pair, 1);
		redeem(pair, 2);
		redeem(pair, 3);
		expectHealthy(pair, 'all redeemed');
		expect(pair.sChannel.getFullState().htlcs.size).to.equal(0);
		expect(pair.rChannel.getFullState().htlcs.size).to.equal(0);
		const closed = pair.rManager.closeFforEpoch(pair.channelId);
		expect(closed.ok, closed.error).to.equal(true);
		expectHealthy(pair, 'retired');
		const states = (): string[] =>
			[record(pair.sChannel).state, record(pair.rChannel).state].map(
				(s) => FforState[s]
			);
		// Today: no round boundary follows the acknowledgement.
		expect(states(), 'the interim rule').to.deep.equal([
			'DRAINING',
			'DRAINING'
		]);
		// Not stuck for good: the next ordinary round is the boundary.
		pay(pair, 'S', 1_000_000n);
		expectHealthy(pair, 'an ordinary round');
		expect(states(), 'after an ordinary round').to.deep.equal([
			'CLOSED',
			'CLOSED'
		]);
	});
});

describe('FFOR concurrent receive, adversarial: the interim CLOSED rule splits the two sides', function () {
	this.timeout(60_000);

	// The same interim rule, seen from the two sides: S checks it when R's
	// commitment_signed arrives and R one boundary later. It takes an R that
	// redeemed every voucher while ACTIVE, which nothing in PR 1 does on its
	// own. A PIN of what happens today; required once PR 2 of #1283 replaces
	// the rule with terminal slot records: no wire error, both channels
	// NORMAL (expectHealthy) after S's fee update.
	it("PIN [PR 2 of #1283] (interim CLOSED rule, needs an R that redeems while ACTIVE): S reports CLOSED at R's commitment_signed while R is still DRAINING, and S's then-legal update_fee fails the channel at R", () => {
		const pair = createPair({ pushSat: 200_000n });
		activate(pair, AMOUNTS, true);
		// Every voucher is redeemed while ACTIVE (S accepts that in this PR).
		const base = record(pair.rChannel).sHtlcIdBase!;
		for (const k of [1, 2, 3]) {
			const t = record(pair.sChannel).preimages[k - 1];
			settleSlot(pair, k);
			const learned = pair.rManager.fforAddPreimage(pair.channelId, t);
			expect(learned.ok, learned.error).to.equal(true);
			const internal = pair.rChannel as unknown as {
				_fforInternalSettle: boolean;
			};
			internal._fforInternalSettle = true;
			const res = pair.rManager.fulfillHtlc(
				pair.channelId,
				base + BigInt(k - 1),
				t
			);
			internal._fforInternalSettle = false;
			expect(res.ok, res.error).to.equal(true);
		}
		expectHealthy(pair, 'all redeemed');
		pair.link.log.length = 0;
		// S's messages are slow from here on. S has an ordinary add and its
		// commitment_signed on the wire.
		pair.link.holdAt = (from): boolean => from === 'S';
		const fromS = offer(pair, 'S', 1_000_000n);
		expect(fromS.result.ok, fromS.result.error).to.equal(true);
		// R retires the book and makes an ordinary payment.
		const closed = pair.rManager.closeFforEpoch(pair.channelId);
		expect(closed.ok, closed.error).to.equal(true);
		const fromR = offer(pair, 'R', 1_000_000n);
		expect(fromR.result.ok, fromR.result.error).to.equal(true);
		// S took R's commitment_signed with no voucher left: CLOSED on S.
		expect(record(pair.sChannel).state).to.equal(FforState.CLOSED);
		// Baseline ordinary operation on S: a fee update is legal again.
		const fee = pair.sManager.updateChannelFee(
			pair.channelId,
			pair.sChannel.getFullState().localConfig.feeratePerKw + 50
		);
		expect(fee.ok, fee.error).to.equal(true);
		pair.link.holdAt = null;
		pair.link.release('S');
		// Today: R, still DRAINING, refuses the fee update and fails the
		// channel.
		expect(pair.link.types(), why(pair)).to.include(MessageType.ERROR);
		expect(pair.rErrors.join('|')).to.match(
			/FFOR epoch is DRAINING: no fee while the voucher book is live/
		);
	});
});

// ─────────────── DRAINING to CLOSED, one message at a time ───────────────

/** How many voucher outputs the commitments one side holds and has signed carry. */
function voucherOutputs(
	pair: IPair,
	side: Side
): { held: number; peerLatest: number } {
	const f = record(pair.rChannel);
	const st = channel(pair, side).getFullState();
	const direction =
		side === 'R' ? HtlcDirection.RECEIVED : HtlcDirection.OFFERED;
	const isVoucher = (o: {
		direction: HtlcDirection;
		paymentHash: Buffer;
	}): boolean =>
		o.direction === direction &&
		f.paymentHashes.some((h) => h.equals(o.paymentHash));
	// The commitment the stored signature covers (signedLocal).
	const held = buildLocalCommitment(
		st,
		perCommitmentPointFromSecret(
			generateFromSeed(
				st.localPerCommitmentSeed,
				MAX_INDEX - st.localCommitmentNumber
			)
		),
		undefined,
		true
	).htlcOutputs.filter(isVoucher).length;
	const peerLatest = buildRemoteCommitment(
		st,
		st.remoteCurrentPerCommitmentPoint!,
		st.remoteCommitmentNumber
	).htlcOutputs.filter(isVoucher).length;
	return { held, peerLatest };
}

/**
 * A retirement delivered one message at a time in a random interleaving of
 * the two directions, with ordinary adds crossing the drain. After every
 * single delivery: no wire error, each side can force close with what it
 * holds, and a side that reports CLOSED holds no commitment with a voucher
 * and has signed none that the peer has not revoked past.
 */
function runDrainInterleaving(seed: number, settled: number[]): void {
	const rand = prng(seed);
	const pair = activePair();
	const start = balances(pair);
	for (const k of settled) settleSlot(pair, k);
	const trace: string[] = [];
	const tell = (): string => `seed ${seed}: ${trace.join(' ')}`;
	pair.link.holdAt = (): boolean => true;
	const extra: IFuzzHtlc[] = [];
	const add = (from: Side, amountMsat: bigint): void => {
		const a = offer(pair, from, amountMsat);
		if (!a.result.ok) {
			const errors = from === 'S' ? pair.sErrors : pair.rErrors;
			const at = errors.lastIndexOf(a.result.error ?? '');
			if (at >= 0) errors.splice(at, 1);
			return;
		}
		trace.push(`[${from} adds]`);
		extra.push({
			from,
			id: a.id,
			preimage: a.preimage,
			amountMsat,
			outcome: 'open'
		});
	};
	if (rand() < 0.6) add('S', 3_000_000n);
	if (rand() < 0.6) add('R', 2_000_000n);
	const closed = pair.rManager.closeFforEpoch(pair.channelId);
	expect(closed.ok, closed.error).to.equal(true);

	const step = (): void => {
		expect(
			pair.link.types(),
			`wire error; ${tell()} ${why(pair)}`
		).to.not.include(MessageType.ERROR);
		expect(pair.sErrors, tell()).to.deep.equal([]);
		expect(pair.rErrors, tell()).to.deep.equal([]);
		for (const side of ['S', 'R'] as Side[]) {
			if (!receivedAddAwaitsSignature(pair, side)) {
				const plan = planClose(pair, side);
				expect(
					plan.ok,
					`${side} cannot force close: ${plan.error}; ${tell()}`
				).to.equal(true);
			}
			if (record(channel(pair, side)).state !== FforState.CLOSED) continue;
			const outs = voucherOutputs(pair, side);
			expect(
				outs,
				`${side} reports CLOSED while a commitment carries a voucher; ${tell()}`
			).to.deep.equal({ held: 0, peerLatest: 0 });
			expect(
				voucherOutputs(pair, other(side)).held,
				`${side} reports CLOSED while the peer still holds a voucher commitment; ${tell()}`
			).to.equal(0);
			// CLOSED burned the id; no new epoch while anything is unresolved.
			expect(
				channel(pair, side).getFullState().fforUsedEpochIds ?? [],
				tell()
			).to.include(record(channel(pair, side)).epochId.toString('hex'));
		}
	};

	for (let n = 0; n < 400; n++) {
		const s = pair.link.inFlight('S').length;
		const r = pair.link.inFlight('R').length;
		if (s === 0 && r === 0) break;
		const from: Side = s === 0 ? 'R' : r === 0 ? 'S' : rand() < 0.5 ? 'S' : 'R';
		trace.push(`${from}:${pair.link.inFlight(from)[0]}`);
		pair.link.release(from, 1);
		step();
		if (rand() < 0.08) add(rand() < 0.5 ? 'S' : 'R', 1_000_000n);
	}
	expect(pair.link.inFlight('S'), tell()).to.deep.equal([]);
	expect(pair.link.inFlight('R'), tell()).to.deep.equal([]);
	pair.link.holdAt = null;
	pair.link.release('S');
	pair.link.release('R');
	expect(record(pair.rChannel).state, `R closed; ${tell()}`).to.equal(
		FforState.CLOSED
	);
	expect(record(pair.sChannel).state, `S closed; ${tell()}`).to.equal(
		FforState.CLOSED
	);
	// A new epoch needs an idle channel: refused while ordinary HTLCs remain.
	if (extra.length > 0) {
		const again = pair.rManager.initiateFforEpoch(
			pair.channelId,
			terms(AMOUNTS)
		);
		expect(again.ok, 'no new epoch beside HTLCs in flight').to.equal(false);
		pair.rErrors.length = 0;
	}
	for (const h of extra) {
		const res = manager(pair, other(h.from)).fulfillHtlc(
			pair.channelId,
			h.id,
			h.preimage
		);
		expect(res.ok, `${res.error}; ${tell()}`).to.equal(true);
	}
	step();
	let sExpected = start.s;
	let rExpected = start.r;
	for (let k = 1; k <= AMOUNTS.length; k++) {
		if (settled.includes(k)) rExpected += AMOUNTS[k - 1];
		else sExpected += AMOUNTS[k - 1];
	}
	for (const h of extra) {
		const sign = h.from === 'S' ? 1n : -1n;
		sExpected -= sign * h.amountMsat;
		rExpected += sign * h.amountMsat;
	}
	expect(balances(pair), tell()).to.deep.equal({
		s: sExpected,
		r: rExpected,
		sViewOfR: rExpected,
		rViewOfS: sExpected
	});
}

describe('FFOR concurrent receive, adversarial: DRAINING to CLOSED one message at a time', function () {
	this.timeout(600_000);
	const seeds = process.env.FFOR_DRAIN_SEEDS
		? process.env.FFOR_DRAIN_SEEDS.split(',').map(Number)
		: [101, 102, 103, 104];
	const books = [[2], [], [1, 2, 3], [1, 3]];
	for (const seed of seeds) {
		const settled = books[seed % books.length];
		it(`seed ${seed}, settled [${settled}]: CLOSED is never declared over a live voucher, and both sides can close at every step`, () => {
			runDrainInterleaving(seed, settled);
		});
	}
});

// ─────────────── The ceiling against the admission, at the boundary ───────────────

describe('FFOR concurrent receive, adversarial: getSpendableOutboundMsat against what both sides then do', function () {
	this.timeout(300_000);

	for (const funder of ['S', 'R'] as Side[]) {
		for (const drainer of ['S', 'R'] as Side[]) {
			it(`${funder} funds, ${drainer} spends down to its ceiling in halves beside dust and untrimmed HTLCs in flight: an add at the ceiling is never refused, failed or stamped`, () => {
				const pair =
					funder === 'S'
						? createPair({ pushSat: 200_000n })
						: createPair({ funder: 'R', pushSat: 600_000n });
				activate(pair, AMOUNTS, true);
				// In flight for the whole walk: dust and untrimmed, both ways.
				for (const from of ['S', 'R'] as Side[]) {
					for (const amount of [300_123n, 2_000_456n]) {
						const a = offer(pair, from, amount);
						expect(a.result.ok, a.result.error).to.equal(true);
					}
				}
				const mismatches: string[] = [];
				const probe = (label: string): void => {
					for (const side of ['S', 'R'] as Side[]) {
						const m = ceilingMismatch(pair, side);
						if (m) mismatches.push(`${label}: ${m}`);
					}
				};
				probe('start');
				for (let i = 0; i < 60; i++) {
					const ceiling = channel(pair, drainer).getSpendableOutboundMsat();
					expect(ceiling >= 0n, 'no negative ceiling').to.equal(true);
					if (ceiling < 2_000n) break;
					const amount = ceiling > 400_000n ? ceiling / 2n : ceiling;
					const a = offer(pair, drainer, amount);
					expect(
						a.result.ok,
						`step ${i}: ${amount} of ceiling ${ceiling}: ${a.result.error}`
					).to.equal(true);
					const stamped = channel(
						pair,
						other(drainer)
					).receivedHtlcExceedsFunderFee(a.id);
					if (stamped) {
						mismatches.push(
							`step ${i}: ${amount} of ceiling ${ceiling} was stamped for a fail-back`
						);
					}
					const res = stamped
						? manager(pair, other(drainer)).failHtlc(
								pair.channelId,
								a.id,
								Buffer.alloc(292)
						  )
						: manager(pair, other(drainer)).fulfillHtlc(
								pair.channelId,
								a.id,
								a.preimage
						  );
					expect(res.ok, res.error).to.equal(true);
					expectHealthy(pair, `step ${i}`);
					expectVouchersCarried(pair, [1, 2, 3], `step ${i}`);
					probe(`step ${i}`);
				}
				// With the drainer at its ceiling, the other side stacks
				// untrimmed HTLCs and leaves them open: each one costs the
				// funder a fee slot, until the ceiling says no more.
				const stacker = other(drainer);
				const stacked: string[] = [];
				for (let j = 0; j < 12; j++) {
					const ceiling = channel(pair, stacker).getSpendableOutboundMsat();
					if (ceiling === 0n) break;
					const amount = ceiling < 700_000n ? ceiling : 700_000n;
					const a = offer(pair, stacker, amount);
					expect(
						a.result.ok,
						`stack ${j}: ${amount} of ceiling ${ceiling}: ${a.result.error}`
					).to.equal(true);
					stacked.push(`${amount}`);
					if (
						channel(pair, other(stacker)).receivedHtlcExceedsFunderFee(a.id)
					) {
						mismatches.push(
							`stack ${j}: ${amount} of ceiling ${ceiling} was stamped for a fail-back`
						);
					}
					expectHealthy(pair, `stack ${j}`);
					expectVouchersCarried(pair, [1, 2, 3], `stack ${j}`);
					probe(`stack ${j}`);
				}
				for (const side of ['S', 'R'] as Side[]) {
					expect(planClose(pair, side).ok, `${side} can close`).to.equal(true);
				}
				expect(mismatches).to.deep.equal([]);
			});
		}
	}
});

// ─────────────── Negotiation and downgrade ───────────────

describe('FFOR concurrent receive, adversarial: negotiation and downgrade', function () {
	this.timeout(60_000);

	it('a replayed ff_accept changes nothing once the epoch is ACTIVE, on either profile', () => {
		for (const concurrent of [true, false]) {
			const pair = createPair({ pushSat: 200_000n });
			activate(pair, AMOUNTS, concurrent);
			const accept = pair.link.log.find(
				(e) => e.from === 'S' && e.type === MessageType.FF_ACCEPT
			)!;
			const before = snapshot(pair, 'R');
			pair.rErrors.length = 0;
			pair.rManager.handleMessage(
				pair.sPub,
				MessageType.FF_ACCEPT,
				accept.payload
			);
			expect(record(pair.rChannel).state).to.equal(FforState.ACTIVE);
			expect(record(pair.rChannel).concurrentVersion ?? 0).to.equal(
				concurrent ? 1 : 0
			);
			expect(snapshot(pair, 'R'), 'nothing was rewritten').to.equal(before);
			expect(pair.rChannel.getState()).to.equal(ChannelState.NORMAL);
		}
	});

	it("a concurrent ff_accept captured from one epoch cannot select the profile for another: R's next baseline setup aborts on it and the id is burned", () => {
		const pair = createPair({ pushSat: 200_000n });
		activate(pair, AMOUNTS, true);
		const captured = pair.link.log.find(
			(e) => e.from === 'S' && e.type === MessageType.FF_ACCEPT
		)!.payload;
		const closed = pair.rManager.closeFforEpoch(pair.channelId);
		expect(closed.ok, closed.error).to.equal(true);
		expect(record(pair.rChannel).state).to.equal(FforState.CLOSED);
		// A baseline request; S's real answer is swapped for the old echo.
		pair.link.drop = (from, type): boolean =>
			from === 'S' && type !== MessageType.FF_ABORT;
		const res = pair.rManager.initiateFforEpoch(pair.channelId, terms(AMOUNTS));
		expect(res.ok, res.error).to.equal(true);
		const fresh = record(pair.rChannel);
		expect(fresh.state).to.equal(FforState.NEGOTIATING);
		pair.rManager.handleMessage(pair.sPub, MessageType.FF_ACCEPT, captured);
		pair.link.drop = null;
		const after = record(pair.rChannel);
		expect(after.concurrentVersion ?? 0, 'nothing selected').to.equal(0);
		expect(after.acceptWire, 'the stale accept was not adopted').to.equal(null);
		expect(pair.rChannel.getState()).to.equal(ChannelState.NORMAL);
	});

	it("S's policy and both sides' advertisements changing after the echo do not move a live epoch off the profile it selected", () => {
		const pair = createPair({ pushSat: 200_000n });
		activate(pair, AMOUNTS, true);
		pair.sPolicy = { enabled: true, allowConcurrent: false };
		pair.sManager.setFforSettlePolicy(pair.sPolicy);
		pay(pair, 'S', 3_000_000n);
		pay(pair, 'R', 2_000_000n);
		expectHealthy(pair, 'traffic after the policy changed');
		for (const ch of [pair.sChannel, pair.rChannel]) {
			expect(record(ch).concurrentVersion).to.equal(1);
		}
		// And a baseline epoch between peers that advertise the extension
		// stays frozen: the same add fails the channel.
		const base = createPair({ pushSat: 200_000n });
		activate(base, AMOUNTS, false);
		const refused = offer(base, 'R', 2_000_000n);
		expect(refused.result.ok).to.equal(false);
		expect(refused.result.error).to.match(/FFOR epoch is ACTIVE: no add/);
	});

	for (const side of ['S', 'R'] as Side[]) {
		it(`${side} restarts between the request and the echo: both abort, nothing is left on the channel, the id is burned, and the next epoch is the profile it asks for`, () => {
			const pair = createPair({ pushSat: 200_000n });
			const start = balances(pair);
			// S's ff_accept (and the voucher round behind it) never arrives.
			pair.link.holdAt = (from, type): boolean =>
				from === 'S' && type === MessageType.FF_ACCEPT;
			const res = pair.rManager.initiateFforEpoch(
				pair.channelId,
				terms(AMOUNTS, { concurrent: true })
			);
			expect(res.ok, res.error).to.equal(true);
			pair.link.holdAt = null;
			const epochId = record(pair.rChannel).epochId.toString('hex');
			// S selected as it answered; R has only asked.
			expect(record(pair.sChannel).concurrentVersion).to.equal(1);
			expect(record(pair.rChannel).concurrentVersion ?? 0).to.equal(0);
			restart(pair, side);
			pair.link.reconnect();
			pair.sErrors.length = 0;
			pair.rErrors.length = 0;
			// BOLT 2 replays S's voucher adds into the aborted setup. R never
			// saw ff_accept, so they are plain HTLCs to it (on either
			// profile, as on master) and its node fails them back; done by
			// hand here, where no node runs.
			for (const [key, e] of [...pair.rChannel.getFullState().htlcs]) {
				expect(key.startsWith('received-')).to.equal(true);
				expect(e.fforVoucher, 'not parked: no book to match').to.not.equal(
					true
				);
				const failed = pair.rManager.failHtlc(
					pair.channelId,
					e.id,
					Buffer.alloc(292)
				);
				expect(failed.ok, failed.error).to.equal(true);
			}
			for (const ch of [pair.sChannel, pair.rChannel]) {
				expect(record(ch).state, why(pair)).to.equal(FforState.ABORTED);
				expect(ch.getFullState().htlcs.size, 'no voucher left').to.equal(0);
				expect(ch.getState()).to.equal(ChannelState.NORMAL);
				expect(ch.getFullState().fforUsedEpochIds ?? []).to.include(epochId);
			}
			expect(balances(pair)).to.deep.equal(start);
			// The spent id cannot carry a baseline retry.
			const retry = pair.rManager.initiateFforEpoch(
				pair.channelId,
				terms(AMOUNTS, { epochId: Buffer.from(epochId, 'hex') })
			);
			expect(retry.ok, 'same id refused').to.equal(false);
			pair.rErrors.length = 0;
			pair.sErrors.length = 0;
			// Ordinary traffic is not frozen by the aborted concurrent record.
			pay(pair, 'S', 1_000_000n);
			pay(pair, 'R', 1_000_000n);
			expectHealthy(pair, 'after the aborted setup');
			// A new baseline epoch is baseline on both sides, and frozen.
			activate(pair, AMOUNTS, false);
			const frozen = offer(pair, 'S', 1_000_000n);
			expect(frozen.result.ok).to.equal(false);
		});
	}
});

// ─────────────── Baseline unchanged, by message flow ───────────────

/**
 * One baseline epoch from setup to CLOSED with a reconnect in ACTIVE, on a
 * pair whose sides advertise the extension as given. Returns everything a
 * peer or a disk could observe: the wire (sender, type, length), every
 * local refusal string, and the key set of each stored record.
 */
function baselineFlow(sAdvertises: boolean, rAdvertises: boolean): unknown {
	const pair = createPair({
		concurrent: false,
		sAdvertises,
		rAdvertises,
		pushSat: 200_000n
	});
	const refusals: string[] = [];
	const note = (what: string, error: string | undefined): void => {
		refusals.push(
			`${what}: ${(error ?? 'ok').replace(/[0-9a-f]{64}/g, '<id>')}`
		);
	};
	activate(pair, AMOUNTS, false);
	const keysAt: Record<string, string[]> = {};
	const keys = (label: string): void => {
		for (const side of ['S', 'R'] as Side[]) {
			const row = JSON.parse(snapshot(pair, side));
			keysAt[`${label} ${side}`] = Object.keys(row.ffor).sort();
			expect(row.ffor.concurrentVersion, 'no selection is written').to.equal(
				undefined
			);
			expect(row.ffor.params.concurrentVersion).to.equal(undefined);
		}
	};
	keys('ACTIVE');
	// Everything ordinary is refused, with the strings master answers.
	for (const side of ['S', 'R'] as Side[]) {
		note(`${side} add`, offer(pair, side, 2_000_000n).result.error);
		note(
			`${side} fee`,
			manager(pair, side).updateChannelFee(pair.channelId, 1000).error
		);
		note(
			`${side} shutdown`,
			manager(pair, side).initiateShutdown(
				pair.channelId,
				Buffer.concat([Buffer.from([0x00, 0x14]), Buffer.alloc(20, 7)])
			).error
		);
		note(
			`${side} stfu`,
			manager(pair, side).initiateQuiescence(pair.channelId).error
		);
		note(
			`${side} voucher fail`,
			manager(pair, side).failHtlc(
				pair.channelId,
				record(pair.rChannel).sHtlcIdBase!,
				Buffer.alloc(292)
			).error
		);
		note(
			`${side} can offer`,
			String(channel(pair, side).canOfferHtlcSet([1_000_000n]))
		);
		note(`${side} accepts`, String(channel(pair, side).acceptsNewHtlcs()));
		note(
			`${side} accepts, reservation hint`,
			String(channel(pair, side).acceptsNewHtlcs(false, true))
		);
		note(
			`${side} spendable`,
			String(channel(pair, side).getSpendableOutboundMsat())
		);
		note(`${side} frozen`, String(channel(pair, side).fforIsFrozen()));
		note(`${side} hold`, String(channel(pair, side).fforAdmissionHold()));
	}
	pair.sErrors.length = 0;
	pair.rErrors.length = 0;
	// R leaves and returns; S settles a slot meanwhile.
	pair.link.disconnect();
	settleSlot(pair, 2);
	note(
		'settlement refusal',
		String(pair.sChannel.fforSettlementRefusal(1, TIP))
	);
	pair.link.reconnect();
	keys('reconnected');
	note('R state after return', FforState[record(pair.rChannel).state]);
	const closed = pair.rManager.closeFforEpoch(pair.channelId);
	note('close', closed.error);
	keys('CLOSED');
	note('R final', FforState[record(pair.rChannel).state]);
	note('S final', FforState[record(pair.sChannel).state]);
	const b = balances(pair);
	return {
		wire: pair.link.log.map((e) => `${e.from}:${e.type}:${e.payload.length}`),
		refusals,
		keysAt,
		balances: [b.s, b.r, b.sViewOfR, b.rViewOfS].map(String),
		errors: [pair.sErrors, pair.rErrors]
	};
}

describe('FFOR concurrent receive, adversarial: a baseline epoch is the same whatever is advertised', function () {
	this.timeout(120_000);

	it('the wire, the refusals, the stored keys and the balances of a baseline epoch are identical with the extension advertised by neither side, both, only S, only R', () => {
		const reference = baselineFlow(false, false);
		const ref = reference as { wire: string[]; refusals: string[] };
		// The reference itself is a full baseline epoch that froze the channel.
		expect(ref.wire.length).to.be.greaterThan(20);
		expect(ref.refusals.join('\n')).to.match(
			/S add: Cannot add HTLC: FFOR epoch is ACTIVE: no add until it drains/
		);
		expect(ref.refusals).to.include('R final: CLOSED');
		for (const [s, r] of [
			[true, true],
			[true, false],
			[false, true]
		]) {
			expect(baselineFlow(s, r), `S ${s}, R ${r}`).to.deep.equal(reference);
		}
	});

	it('with the extension advertised by both and no TLV 17, a peer ordinary add, fulfil, fee and commitment in ACTIVE each fail the channel as on master', () => {
		const wires: Array<[string, number, (pair: IPair) => Buffer]> = [
			[
				'update_add_htlc',
				MessageType.UPDATE_ADD_HTLC,
				(pair): Buffer =>
					encodeUpdateAddHtlcMessage({
						channelId: pair.channelId,
						id: pair.rChannel.getFullState().localHtlcCounter,
						amountMsat: 1_000_000n,
						paymentHash: sha('x'),
						cltvExpiry: TIP + 100,
						onionRoutingPacket: ONION
					})
			],
			[
				'update_fulfill_htlc',
				MessageType.UPDATE_FULFILL_HTLC,
				(pair): Buffer =>
					encodeUpdateFulfillHtlcMessage({
						channelId: pair.channelId,
						id: record(pair.sChannel).sHtlcIdBase!,
						paymentPreimage: record(pair.sChannel).preimages[0]
					})
			]
		];
		for (const [name, type, build] of wires) {
			const pair = createPair({ concurrent: true, pushSat: 200_000n });
			activate(pair, AMOUNTS, false);
			pair.link.log.length = 0;
			pair.sManager.handleMessage(pair.rPub, type, build(pair));
			expect(pair.link.types(), name).to.include(MessageType.ERROR);
			expect(pair.sErrors.join('|'), name).to.match(
				/FFOR epoch is ACTIVE: no (add|settle) until it drains/
			);
		}
	});
});

// ─────────────── Feature bit hygiene ───────────────

describe('FFOR concurrent receive, adversarial: feature bit hygiene', function () {
	this.timeout(60_000);

	const requires562 = (): FeatureFlags => {
		const f = LightningNode.defaultFeatures();
		f.setCompulsory(Feature.OPTION_FF_CONCURRENT);
		return f;
	};

	it('option off: neither bit is advertised or implemented, and a peer REQUIRING 562 is one we disconnect', () => {
		const node = new LightningNode(makeNodeConfig(9101));
		const local = node.getLocalFeatures();
		expect(local.hasBit(562) || local.hasBit(563)).to.equal(false);
		expect(implementedFeatures().hasBit(562)).to.equal(false);
		expect(implementedFeatures().hasBit(563)).to.equal(false);
		expect(LightningNode.defaultFeatures().hasBit(563)).to.equal(false);
		expect(hasUnsupportedRequiredFeatures(local, requires562())).to.deep.equal([
			562
		]);
		// A peer merely offering it (563) is not disconnected, and selects nothing.
		const offers = LightningNode.defaultFeatures();
		offers.setOptional(Feature.OPTION_FF_CONCURRENT);
		expect(hasUnsupportedRequiredFeatures(local, offers)).to.deep.equal([]);
	});

	it('option off: a caller-supplied set carrying 562 and 563 is stripped of both, so the requiring peer is still disconnected', () => {
		const supplied = LightningNode.defaultFeatures();
		supplied.setCompulsory(Feature.OPTION_FF_CONCURRENT);
		supplied.setOptional(Feature.OPTION_FF_CONCURRENT);
		const node = new LightningNode(
			makeNodeConfig(9102, undefined, { localFeatures: supplied })
		);
		const local = node.getLocalFeatures();
		expect(local.hasBit(562) || local.hasBit(563)).to.equal(false);
		expect(hasUnsupportedRequiredFeatures(local, requires562())).to.deep.equal([
			562
		]);
	});

	it('option on: a peer requiring 562 is accepted, although the bit is not in implementedFeatures()', () => {
		const node = new LightningNode(
			makeNodeConfig(9103, undefined, { fforConcurrent: { enabled: true } })
		);
		const local = node.getLocalFeatures();
		expect(local.hasBit(563)).to.equal(true);
		expect(local.hasBit(562), 'never compulsory by our own doing').to.equal(
			false
		);
		expect(hasUnsupportedRequiredFeatures(local, requires562())).to.deep.equal(
			[]
		);
	});

	it('option on: an init advertisement alone selects nothing; S refuses TLV 17 until its policy allows it', () => {
		const w = createConcurrentWorld({ allowConcurrent: false });
		const res = w.r.startFforEpoch(w.srHex, {
			voucherAmountsMsat: WORLD_AMOUNTS,
			minPaymentMsat: 400_000n,
			settlementDeadline: WORLD_D_DEADLINE,
			voucherExpiry: WORLD_T_EXP,
			feeBaseMsat: 1000,
			feeProportionalMillionths: 5000,
			concurrent: true
		});
		void res;
		expect(worldRecord(w.r, w.srHex).state).to.equal(FforState.ABORTED);
		expect(worldRecord(w.r, w.srHex).concurrentVersion ?? 0).to.equal(0);
		expect(w.s.getFforEpoch(w.srHex)?.concurrentVersion ?? 0).to.equal(0);
	});

	// The review observed that with the option on, bit 563 also rode in
	// node_announcement, because the node reuses its init set there.
	// CONCURRENT-RECEIVE.md section 1.1 names the init context only, so the
	// announcement now leaves it out.
	it('with the option on, bit 563 is advertised in init and left out of node_announcement, whose features are those of a node with the option off', () => {
		const announce = (node: LightningNode): Buffer => {
			const payload = (
				node as unknown as { buildNodeAnnouncement(t: number): Buffer | null }
			).buildNodeAnnouncement(1_790_000_000);
			expect(payload, 'announcement built').to.not.equal(null);
			return decodeNodeAnnouncementMessage(payload!).features;
		};
		const off = new LightningNode(makeNodeConfig(9104));
		expect(
			FeatureFlags.fromBuffer(announce(off)).hasFeature(
				Feature.OPTION_FF_CONCURRENT
			)
		).to.equal(false);
		const on = new LightningNode(
			makeNodeConfig(9105, undefined, { fforConcurrent: { enabled: true } })
		);
		expect(on.getLocalFeatures().hasBit(563), 'in init').to.equal(true);
		const announced = FeatureFlags.fromBuffer(announce(on));
		expect(announced.hasBit(563)).to.equal(false);
		expect(announced.hasBit(562)).to.equal(false);
		// Everything else the node advertises is still announced, the base
		// capability included.
		expect(announced.hasFeature(Feature.OPTION_FF_RECEIVE)).to.equal(true);
		expect(announce(on).equals(announce(off))).to.equal(true);
		// And the init set itself is not touched by building an announcement.
		expect(on.getLocalFeatures().hasBit(563)).to.equal(true);
		// With the option off the announcement is the init set, byte for byte.
		expect(announce(off).equals(off.getLocalFeatures().toBuffer())).to.equal(
			true
		);
	});
});

// ─────────────── The capability hold ───────────────

describe('FFOR concurrent receive, adversarial: the capability hold', function () {
	this.timeout(60_000);

	it("control: an incompatible reconnect holds S's delegated settlement, and a plain disconnect afterwards does not lift it", () => {
		const pair = activePair();
		pair.link.disconnect();
		pair.rConfig.localFeatures.clearBit(Feature.OPTION_FF_CONCURRENT + 1);
		pair.link.reconnect();
		expect(pair.sChannel.fforSettlementRefusal(1, TIP)).to.match(
			/capability hold/
		);
		pair.link.disconnect();
		expect(pair.sChannel.fforSettlementRefusal(1, TIP)).to.match(
			/capability hold/
		);
	});

	// Review round 1 of PR #1301: the hold was memory only, so a restart of
	// the holding side lifted it with no compatible init having been seen.
	// Fixed: it is on the epoch record.
	it('the hold survives a restart of the holding side: S does not resume delegated settlement for an R that last connected without the capability', () => {
		const pair = activePair();
		pair.link.disconnect();
		pair.rConfig.localFeatures.clearBit(Feature.OPTION_FF_CONCURRENT + 1);
		pair.link.reconnect();
		expect(pair.sChannel.fforSettlementRefusal(1, TIP)).to.match(
			/capability hold/
		);
		// S's process restarts. R has not reconnected, compatibly or otherwise.
		restart(pair, 'S');
		expect(record(pair.sChannel).concurrentVersion).to.equal(1);
		expect(
			pair.sChannel.fforSettlementRefusal(1, TIP),
			'CONCURRENT-RECEIVE.md section 8: the hold lasts until the current init exchange advertises both capabilities'
		).to.match(/capability hold/);
	});
});

// ─────────────── Through the node ───────────────

/** A second payer with its own channel to S. */
function addPayer(w: IWorld): LightningNode {
	const p2 = new LightningNode(
		makeNodeConfig(9_300 + Math.floor(Math.random() * 500))
	);
	p2.on('node:error', () => {});
	new NodeLink(p2, w.s);
	const channelId = openReadyChannel(p2, w.s, 1_000_000n);
	const scid = encodeShortChannelId({ block: 500, txIndex: 9, outputIndex: 0 });
	publishChannel(p2, p2, w.s, channelId, scid);
	p2.handleNewBlock(WORLD_TIP);
	return p2;
}

function srChannel(node: LightningNode, w: IWorld): Channel {
	return node.getChannelManager().getChannel(w.srChannelId)!;
}

describe('FFOR concurrent receive, adversarial: through the node', function () {
	this.timeout(120_000);

	it("S's settlement ledger after a voucher is redeemed while ACTIVE: a second payer on that hash is failed, never settled again and never forwarded to R; S paid d_k once", () => {
		const w = createConcurrentWorld();
		activateWorld(w, true);
		const p2 = addPayer(w);
		const reasons: string[] = [];
		w.s.on('ffor:delegated-failed', (e: { reason: string }) =>
			reasons.push(e.reason)
		);
		const invoice = w.r.createFforVoucherInvoice(w.srHex, 2).bolt11;
		// R is online: the first payer is still settled by S, not forwarded.
		w.sr.log.length = 0;
		const paid = payInvoice(w, invoice);
		expect(paid.status, JSON.stringify(w.errors)).to.equal(
			PaymentStatus.COMPLETED
		);
		expect(worldRecord(w.s, w.srHex).slotStates[1]).to.equal(
			FforSlotState.SETTLED
		);
		expect(
			w.sr.log.filter((e) => e.type === MessageType.UPDATE_ADD_HTLC),
			'nothing was forwarded to R'
		).to.deep.equal([]);
		// R redeems with the payer's receipt while the book stays ACTIVE.
		const rCh = srChannel(w.r, w);
		const sBefore = srChannel(w.s, w).getFullState().localBalanceMsat;
		const rBefore = rCh.getFullState().localBalanceMsat;
		const base = worldRecord(w.r, w.srHex).sHtlcIdBase!;
		const learned = w.r.fforAddPreimage(w.srHex, paid.preimage!);
		expect(learned.ok, learned.error).to.equal(true);
		const internal = rCh as unknown as { _fforInternalSettle: boolean };
		internal._fforInternalSettle = true;
		const res = w.r
			.getChannelManager()
			.fulfillHtlc(w.srChannelId, base + 1n, paid.preimage!);
		internal._fforInternalSettle = false;
		expect(res.ok, res.error).to.equal(true);
		expect(rCh.getFullState().localBalanceMsat).to.equal(
			rBefore + WORLD_AMOUNTS[1]
		);
		expect(srChannel(w.s, w).getFullState().localBalanceMsat).to.equal(sBefore);
		expect(worldRecord(w.s, w.srHex).state).to.equal(FforState.ACTIVE);
		expect(worldRecord(w.s, w.srHex).slotStates[1]).to.equal(
			FforSlotState.SETTLED
		);
		// The voucher is gone from S's channel; the hash is still consumed.
		w.sr.log.length = 0;
		const decoded = decodeInvoice(invoice);
		try {
			p2.sendPayment(invoice);
		} catch {
			// retries may exhaust; the status is what matters
		}
		expect(p2.getPayment(decoded.paymentHash)?.status).to.equal(
			PaymentStatus.FAILED
		);
		expect(reasons).to.include('duplicate delegated payment for consumed hash');
		expect(
			w.sr.log.filter((e) => e.type === MessageType.UPDATE_ADD_HTLC),
			'the second payment was not forwarded to R as an ordinary HTLC'
		).to.deep.equal([]);
		expect(rCh.getFullState().localBalanceMsat, 'R credited once').to.equal(
			rBefore + WORLD_AMOUNTS[1]
		);
	});

	it('an add past the fee-spike buffer from an R that skips its own check is admitted, failed back by the node and never settled; the vouchers and the channel stand', () => {
		const w = createConcurrentWorld();
		activateWorld(w, true);
		const sCh = srChannel(w.s, w);
		const rCh = srChannel(w.r, w);
		// S, the funder, spends down to its own ceiling.
		for (let i = 0; i < 4; i++) {
			const ceiling = sCh.getSpendableOutboundMsat();
			if (ceiling < 1_000_000n) break;
			const inv = w.r.createInvoice({
				amountMsat: ceiling,
				description: `d${i}`
			});
			w.s.sendPayment(inv.bolt11);
			expect(
				w.s.getPayment(inv.paymentHash)!.status,
				JSON.stringify(w.errors)
			).to.equal(PaymentStatus.COMPLETED);
		}
		expect(sCh.getSpendableOutboundMsat() < 1_000_000n).to.equal(true);
		// R parks untrimmed HTLCs on S (hold invoices) until its own ceiling
		// says the funder's buffer has no slot left.
		let parked = 0;
		for (let i = 0; i < 6; i++) {
			if (rCh.getSpendableOutboundMsat() < 2_000_000n) break;
			const held = w.s.createInvoice({
				amountMsat: 2_000_000n,
				description: `held${i}`,
				hold: true
			});
			w.r.sendPayment(held.bolt11);
			expect(w.r.getPayment(held.paymentHash)!.status).to.equal(
				PaymentStatus.PENDING
			);
			parked++;
		}
		expect(parked, 'the buffer had room for some').to.be.greaterThan(0);
		expect(
			rCh.getSpendableOutboundMsat() < 2_000_000n,
			"R's ceiling closed the untrimmed slot"
		).to.equal(true);
		const stampedBefore = [...sCh.getFullState().htlcs.values()].filter(
			(e) => e.funderFeeFailback === true
		);
		expect(stampedBefore, 'nothing honest was stamped').to.deep.equal([]);
		// A misbehaving R: its own buffer check and ceiling are skipped.
		const hostile = rCh as unknown as {
			_fforMixedBufferRefusal(c: unknown): string | null;
			_fforMixedBufferCeilingMsat(m: bigint): bigint;
		};
		hostile._fforMixedBufferRefusal = (): string | null => null;
		hostile._fforMixedBufferCeilingMsat = (m: bigint): bigint => m;
		const refusals: string[] = [];
		w.s.on('log', (l: { category: string; action: string }) =>
			refusals.push(`${l.category}:${l.action}`)
		);
		const sBefore = sCh.getFullState().localBalanceMsat;
		const rBefore = rCh.getFullState().localBalanceMsat;
		const target = w.s.createInvoice({
			amountMsat: 3_000_000n,
			description: 'past the buffer'
		});
		w.sr.log.length = 0;
		try {
			w.r.sendPayment(target.bolt11);
		} catch {
			// a refused send throws; the statuses below are what matters
		}
		expect(
			w.sr.log.some(
				(e) =>
					e.from === w.r.getNodeId() && e.type === MessageType.UPDATE_ADD_HTLC
			),
			'the add reached S'
		).to.equal(true);
		expect(refusals, 'S failed it back for the funder fee').to.include(
			'htlc:refused_funder_fee'
		);
		expect(
			w.sr.log.some((e) => e.type === MessageType.ERROR),
			'the channel was not failed'
		).to.equal(false);
		expect(w.r.getPayment(target.paymentHash)?.status).to.equal(
			PaymentStatus.FAILED
		);
		expect(w.s.getPayment(target.paymentHash)?.status).to.not.equal(
			PaymentStatus.COMPLETED
		);
		expect(sCh.getFullState().localBalanceMsat, 'S was not paid').to.equal(
			sBefore
		);
		expect(rCh.getFullState().localBalanceMsat, 'R got it back').to.equal(
			rBefore
		);
		expect(sCh.getState()).to.equal(ChannelState.NORMAL);
		for (const node of [w.s, w.r]) {
			expect(worldRecord(node, w.srHex).state).to.equal(FforState.ACTIVE);
			expect(
				[...srChannel(node, w).getFullState().htlcs.values()].filter(
					(e) => e.fforVoucher === true && e.state === HtlcState.COMMITTED
				).length
			).to.equal(WORLD_AMOUNTS.length);
		}
	});

	it('fee update, cooperative close and splice asked of the node while a concurrent book is ACTIVE or DRAINING are refused and send nothing', () => {
		const w = createConcurrentWorld();
		activateWorld(w, true);
		const script = Buffer.concat([
			Buffer.from([0x00, 0x14]),
			Buffer.alloc(20, 9)
		]);
		const probe = (label: string): void => {
			w.sr.log.length = 0;
			const fee = w.s.updateChannelFee(w.srChannelId, 2000);
			expect(fee.ok, `${label} fee`).to.equal(false);
			expect(fee.error).to.match(/while the voucher book is live/);
			for (const node of [w.s, w.r]) {
				const close = node.closeChannel(w.srChannelId, script);
				expect(close.ok, `${label} close`).to.equal(false);
				expect(close.error).to.match(/while the voucher book is live/);
				expect(srChannel(node, w).spliceBusyReason()).to.match(
					/while the voucher book is live/
				);
				expect(srChannel(node, w).getState()).to.equal(ChannelState.NORMAL);
			}
			expect(w.sr.log, `${label}: nothing sent`).to.deep.equal([]);
		};
		probe('ACTIVE');
		// DRAINING: R's drain round is lost on the wire, so both sides sit in
		// DRAINING with every voucher still on S's channel.
		w.s
			.getChannelManager()
			.fforSetSlot(w.srChannelId, 2, FforSlotState.SETTLED, 'x:1');
		w.sr.drop = (from, type): boolean =>
			from === w.r.getNodeId() && type !== MessageType.FF_CLOSE;
		const closed = w.r.closeFforEpoch(w.srHex);
		w.sr.drop = null;
		expect(closed.ok, closed.error).to.equal(true);
		expect(worldRecord(w.r, w.srHex).state).to.equal(FforState.DRAINING);
		expect(worldRecord(w.s, w.srHex).state).to.equal(FforState.DRAINING);
		probe('DRAINING');
		w.sr.disconnect();
		w.sr.reconnect();
		expect(worldRecord(w.r, w.srHex).state, JSON.stringify(w.errors)).to.equal(
			FforState.CLOSED
		);
		expect(worldRecord(w.s, w.srHex).state).to.equal(FforState.CLOSED);
		// CLOSED: the same requests are no longer refused by the epoch.
		const fee = w.s.updateChannelFee(w.srChannelId, 2000);
		expect(fee.ok, fee.error).to.equal(true);
	});
});

// ─────────────── An ordinary HTLC that copies a voucher ───────────────

describe("FFOR concurrent receive, adversarial: an ordinary HTLC with a voucher's hash, amount and expiry", function () {
	this.timeout(60_000);

	/** A raw add from one side that repeats voucher k's tuple under its own next id. */
	function twin(pair: IPair, from: Side, k: number): bigint {
		const f = record(pair.rChannel);
		const id = channel(pair, from).getFullState().localHtlcCounter;
		const res = manager(pair, from).addHtlc(
			pair.channelId,
			f.params.voucherAmountsMsat[k - 1],
			f.paymentHashes[k - 1],
			f.params.voucherExpiry,
			ONION
		);
		expect(res.ok, res.error).to.equal(true);
		return id;
	}

	it('from S: it is an ordinary HTLC on R under a new id, the voucher is still required beside it, and failing or fulfilling it by id never touches the voucher', () => {
		const pair = activePair();
		const base = record(pair.rChannel).sHtlcIdBase!;
		const start = balances(pair);
		const id = twin(pair, 'S', 3);
		expect(id).to.equal(base + 3n);
		const entry = pair.rChannel.getFullState().htlcs.get(`received-${id}`)!;
		expect(entry.fforVoucher, 'not a second voucher').to.not.equal(true);
		expect(pair.events.R.forwarded, 'dispatched as ordinary').to.include(id);
		expectVouchersCarried(pair, [1, 2, 3], 'twin beside the book');
		// R, holding slot 3's preimage, settles the twin by its own id: the
		// voucher stays parked and stays in every commitment.
		const t3 = record(pair.sChannel).preimages[2];
		const res = pair.rManager.fulfillHtlc(pair.channelId, id, t3);
		expect(res.ok, res.error).to.equal(true);
		expectHealthy(pair, 'twin fulfilled');
		expectVouchersCarried(pair, [1, 2, 3], 'after the twin');
		expect(balances(pair).r).to.equal(start.r + AMOUNTS[2]);
		// The voucher itself is still refused to every outside settle.
		const parked = pair.rManager.fulfillHtlc(pair.channelId, base + 2n, t3);
		expect(parked.ok).to.equal(false);
		expect(parked.error).to.match(/is parked/);
		pair.rErrors.length = 0;
		// And still drains exactly once at the close.
		settleSlot(pair, 3);
		const closed = pair.rManager.closeFforEpoch(pair.channelId);
		expect(closed.ok, closed.error).to.equal(true);
		expect(record(pair.rChannel).state, why(pair)).to.equal(FforState.CLOSED);
		expect(balances(pair)).to.deep.equal({
			s: start.s - AMOUNTS[2] + AMOUNTS[0] + AMOUNTS[1],
			r: start.r + AMOUNTS[2] + AMOUNTS[2],
			sViewOfR: start.r + AMOUNTS[2] + AMOUNTS[2],
			rViewOfS: start.s - AMOUNTS[2] + AMOUNTS[0] + AMOUNTS[1]
		});
	});

	it("from R: it is an ordinary HTLC S received, S's own offered voucher is untouched by a settle of it, and R's fulfil of the voucher id is still judged as the voucher", () => {
		const pair = activePair();
		const base = record(pair.rChannel).sHtlcIdBase!;
		const start = balances(pair);
		const id = twin(pair, 'R', 1);
		const onS = pair.sChannel.getFullState().htlcs.get(`received-${id}`)!;
		expect(onS.fforVoucher).to.not.equal(true);
		expectVouchersCarried(pair, [1, 2, 3], 'R-offered twin');
		// S (which knows t_1) fulfils what it received, by that id.
		const t1 = record(pair.sChannel).preimages[0];
		const res = pair.sManager.fulfillHtlc(pair.channelId, id, t1);
		expect(res.ok, res.error).to.equal(true);
		expectHealthy(pair, 'R-offered twin fulfilled');
		expectVouchersCarried(pair, [1, 2, 3], 'after the R-offered twin');
		expect(balances(pair).s).to.equal(start.s + AMOUNTS[0]);
		expect(balances(pair).r).to.equal(start.r - AMOUNTS[0]);
		expect(
			pair.sChannel.getFullState().htlcs.get(`offered-${base}`)!.state
		).to.equal(HtlcState.COMMITTED);
	});
});
