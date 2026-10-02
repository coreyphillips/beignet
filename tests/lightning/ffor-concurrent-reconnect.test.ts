/**
 * FFOR concurrent receive, version 1: reconnect
 * (specs/CONCURRENT-RECEIVE.md section 8, base section 7.5.5).
 *
 * A reconnect completes the ordinary channel_reestablish and the base FFOR
 * state checks and does not close the book. Before either side resumes new
 * ordinary adds or new delegated admissions, the current init exchange must
 * advertise the base and concurrent capabilities: an incompatible reconnect
 * holds new admission without changing the persisted mode, and fulfils,
 * fails and replays for existing obligations continue. An ordinary
 * disconnection sets no hold.
 */

import { expect } from 'chai';
import {
	ChannelAction,
	ChannelActionType
} from '../../src/lightning/channel/channel-actions';
import { ChannelState, HtlcState } from '../../src/lightning/channel/types';
import { MessageType } from '../../src/lightning/message/types';
import { Feature } from '../../src/lightning/features/flags';
import { FforState } from '../../src/lightning/ffor/types';
import { PaymentStatus } from '../../src/lightning/node/types';
import {
	activateWorld,
	createConcurrentWorld
} from './helpers/ffor-concurrent-world';
import { pay as payInvoice, record as nodeRecord } from './helpers/ffor-world';
import {
	activate,
	AMOUNTS,
	balances,
	channel,
	createPair,
	expectHealthy,
	expectVouchersCarried,
	FUNDING_SATOSHIS,
	IPair,
	offer,
	ONION,
	ordinaryHtlcs,
	pay,
	record,
	restart,
	settleSlot,
	sha,
	Side,
	snapshot,
	terms,
	TIP,
	vouchers,
	why
} from './helpers/ffor-concurrent-pair';

const BUDGET = AMOUNTS.reduce((a, b) => a + b, 0n);
const S_AFTER_BOOK = (FUNDING_SATOSHIS - 200_000n) * 1000n - BUDGET;
const R_START = 200_000_000n;
const ALL = [1, 2, 3];
const BADONION_INVALID_HMAC = 0x8000 | 0x4000 | 5;

function activePair(): IPair {
	const pair = createPair({ pushSat: 200_000n });
	activate(pair, AMOUNTS, true);
	pair.link.log.length = 0;
	return pair;
}

/** Stop or resume advertising option_ff_concurrent on one side. */
function advertise(pair: IPair, side: Side, on: boolean): void {
	const flags =
		side === 'S' ? pair.sConfig.localFeatures : pair.rConfig.localFeatures;
	if (on) flags.setOptional(Feature.OPTION_FF_CONCURRENT);
	else flags.clearBit(Feature.OPTION_FF_CONCURRENT + 1);
}

function sentBy(pair: IPair, side: Side): number[] {
	return pair.link.log.filter((e) => e.from === side).map((e) => e.type);
}

describe('FFOR concurrent receive: reconnect (CONCURRENT-RECEIVE.md 8)', function () {
	this.timeout(120_000);

	describe('a reconnect does not close the book', () => {
		it('two ACTIVE peers with ordinary HTLCs in flight owe each other nothing', () => {
			const pair = activePair();
			const fromS = offer(pair, 'S', 20_000_000n);
			const fromR = offer(pair, 'R', 4_000_000n);
			expect(fromS.result.ok, fromS.result.error).to.equal(true);
			expect(fromR.result.ok, fromR.result.error).to.equal(true);
			pair.link.log.length = 0;
			pair.link.disconnect();
			pair.link.reconnect();
			expect(pair.link.types()).to.deep.equal([
				MessageType.CHANNEL_REESTABLISH,
				MessageType.CHANNEL_REESTABLISH
			]);
			expectHealthy(pair, 'reconnected');
			for (const ch of [pair.sChannel, pair.rChannel]) {
				expect(record(ch).state).to.equal(FforState.ACTIVE);
				expect(record(ch).closeSent).to.equal(false);
				expect(vouchers(ch).length).to.equal(3);
				expect(ordinaryHtlcs(ch).length).to.equal(2);
				expect(ch.fforAdmissionHold()).to.equal(null);
			}
			expectVouchersCarried(pair, ALL, 'reconnected');
			// Ordinary traffic resumes at once: no fetch, no close first.
			pay(pair, 'S', 1_000_000n);
			pay(pair, 'R', 1_000_000n);
			expectHealthy(pair, 'traffic after the reconnect');
		});

		for (const side of ['S', 'R'] as const) {
			it(`${side} restarts while a fulfil of an ordinary HTLC is in flight; the round completes beside the vouchers`, () => {
				const pair = activePair();
				const from = side === 'S' ? 'R' : 'S';
				const add = offer(pair, from, 9_000_000n);
				expect(add.result.ok, add.result.error).to.equal(true);
				// The fulfil and its commitment_signed leave and are lost.
				pair.link.drop = (f): boolean => f === side;
				const settle = (
					side === 'S' ? pair.sManager : pair.rManager
				).fulfillHtlc(pair.channelId, add.id, add.preimage);
				expect(settle.ok, settle.error).to.equal(true);
				pair.link.drop = null;
				restart(pair, side);
				pair.link.log.length = 0;
				pair.link.reconnect();
				expectHealthy(pair, 'fulfil retransmitted');
				expect(sentBy(pair, side)).to.include(MessageType.UPDATE_FULFILL_HTLC);
				expect(ordinaryHtlcs(pair.sChannel)).to.deep.equal([]);
				expect(ordinaryHtlcs(pair.rChannel)).to.deep.equal([]);
				expectVouchersCarried(pair, ALL, 'fulfil retransmitted');
				const delta = side === 'S' ? 9_000_000n : -9_000_000n;
				expect(balances(pair).s).to.equal(S_AFTER_BOOK + delta);
				expect(balances(pair).r).to.equal(R_START - delta);
			});
		}
	});

	describe('acknowledgement loss', () => {
		it('R completes ACTIVATING on the retransmitted ack, as in baseline', () => {
			const pair = createPair({ pushSat: 200_000n });
			pair.link.drop = (_from, type): boolean =>
				type === MessageType.FF_ACTIVATE_ACK;
			const res = pair.rManager.initiateFforEpoch(
				pair.channelId,
				terms(AMOUNTS, { concurrent: true })
			);
			expect(res.ok, res.error).to.equal(true);
			pair.link.drop = null;
			expect(record(pair.sChannel).state).to.equal(FforState.ACTIVE);
			expect(record(pair.rChannel).state).to.equal(FforState.ACTIVATING);
			pair.link.disconnect();
			pair.link.log.length = 0;
			pair.link.reconnect();
			expect(record(pair.rChannel).state, why(pair)).to.equal(FforState.ACTIVE);
			expect(record(pair.rChannel).concurrentVersion).to.equal(1);
			expectHealthy(pair, 'ack retransmitted');
			pay(pair, 'S', 5_000_000n);
			pay(pair, 'R', 1_000_000n);
			expectHealthy(pair, 'traffic after the ack');
			expectVouchersCarried(pair, ALL, 'traffic after the ack');
		});

		it('S retransmits the ack BEFORE the ordinary updates it sent after activating', () => {
			const pair = createPair({ pushSat: 200_000n });
			// S's ack, and everything S sends after it, is lost.
			pair.link.drop = (from, type): boolean =>
				from === 'S' && type === MessageType.FF_ACTIVATE_ACK;
			const res = pair.rManager.initiateFforEpoch(
				pair.channelId,
				terms(AMOUNTS, { concurrent: true })
			);
			expect(res.ok, res.error).to.equal(true);
			expect(record(pair.sChannel).state).to.equal(FforState.ACTIVE);
			expect(record(pair.rChannel).state).to.equal(FforState.ACTIVATING);
			// S is ACTIVE and no longer quiescent: it forwards a payment to R.
			pair.link.drop = (from): boolean => from === 'S';
			const add = offer(pair, 'S', 7_000_000n);
			expect(add.result.ok, add.result.error).to.equal(true);
			pair.link.drop = null;
			expect(ordinaryHtlcs(pair.rChannel)).to.deep.equal([]);
			pair.link.disconnect();
			pair.link.log.length = 0;
			pair.link.reconnect();
			const fromS = sentBy(pair, 'S');
			const ack = fromS.indexOf(MessageType.FF_ACTIVATE_ACK);
			const firstUpdate = fromS.indexOf(MessageType.UPDATE_ADD_HTLC);
			expect(ack, why(pair)).to.be.greaterThan(-1);
			expect(firstUpdate).to.be.greaterThan(-1);
			expect(ack).to.be.lessThan(firstUpdate);
			expect(ack).to.be.lessThan(fromS.indexOf(MessageType.COMMITMENT_SIGNED));
			expectHealthy(pair, 'ack leads the replay');
			expect(record(pair.rChannel).state).to.equal(FforState.ACTIVE);
			expect(ordinaryHtlcs(pair.rChannel)).to.deep.equal([
				`received-${add.id}`
			]);
			expectVouchersCarried(pair, ALL, 'ack leads the replay');
			const settle = pair.rManager.fulfillHtlc(
				pair.channelId,
				add.id,
				add.preimage
			);
			expect(settle.ok, settle.error).to.equal(true);
			expect(balances(pair).r).to.equal(R_START + 7_000_000n);
			expectHealthy(pair, 'settled');
		});

		it('an R still ACTIVATING refuses an update that reaches it before the ack', () => {
			// What the ordering above prevents: R holds no ACTIVE epoch yet, so
			// an add is outside every state it knows.
			const pair = createPair({ pushSat: 200_000n });
			pair.link.drop = (from, type): boolean =>
				from === 'S' && type === MessageType.FF_ACTIVATE_ACK;
			const res = pair.rManager.initiateFforEpoch(
				pair.channelId,
				terms(AMOUNTS, { concurrent: true })
			);
			expect(res.ok, res.error).to.equal(true);
			pair.link.drop = null;
			pair.link.disconnect();
			// Hold the retransmitted ack so R stays ACTIVATING after reestablish.
			pair.link.holdAt = (from, type): boolean =>
				from === 'S' && type === MessageType.FF_ACTIVATE_ACK;
			pair.link.reconnect();
			pair.link.holdAt = null;
			expect(record(pair.rChannel).state).to.equal(FforState.ACTIVATING);
			expect(pair.rChannel.getState()).to.equal(ChannelState.NORMAL);
			expect(pair.rChannel.isQuiescing()).to.equal(false);
			// R's own add is refused locally; nothing of R's moves.
			const own = offer(pair, 'R', 1_000_000n);
			expect(own.result.ok).to.equal(false);
			expect(own.result.error).to.match(/FFOR epoch is ACTIVATING/);
			// The ack arrives and everything proceeds.
			pair.rErrors.length = 0;
			pair.link.release('S');
			expect(record(pair.rChannel).state, why(pair)).to.equal(FforState.ACTIVE);
			expectHealthy(pair, 'ack released');
		});
	});

	describe('the capability hold', () => {
		it('an incompatible reconnect holds new adds and new settlement on both sides; existing HTLCs still resolve', () => {
			const pair = activePair();
			const fromS = offer(pair, 'S', 20_000_000n);
			const fromR = offer(pair, 'R', 4_000_000n);
			expect(fromS.result.ok, fromS.result.error).to.equal(true);
			expect(fromR.result.ok, fromR.result.error).to.equal(true);
			pair.link.disconnect();
			advertise(pair, 'S', false);
			pair.link.log.length = 0;
			pair.link.reconnect();
			// The BOLT 2 reestablish itself is unaffected.
			expect(pair.sChannel.getState()).to.equal(ChannelState.NORMAL);
			expect(pair.rChannel.getState()).to.equal(ChannelState.NORMAL);
			expect(pair.link.types()).to.not.include(MessageType.ERROR);
			for (const ch of [pair.sChannel, pair.rChannel]) {
				// The persisted mode does not change.
				expect(record(ch).concurrentVersion).to.equal(1);
				expect(record(ch).state).to.equal(FforState.ACTIVE);
				expect(record(ch).activationMismatch).to.equal(false);
				expect(ch.fforAdmissionHold()).to.match(/did not advertise/);
				expect(ch.acceptsNewHtlcs()).to.equal(false);
				expect(ch.canOfferHtlcSet([1_000_000n])).to.equal(false);
			}
			for (const side of ['S', 'R'] as const) {
				const add = offer(pair, side, 1_000_000n);
				expect(add.result.ok, `${side} add under the hold`).to.equal(false);
				expect(add.result.error).to.match(/no new add while the peer did not/);
			}
			expect(pair.sChannel.fforSettlementRefusal(1, TIP)).to.match(
				/capability hold/
			);
			// Safe fulfil and fail work for what already exists.
			pair.sErrors.length = 0;
			pair.rErrors.length = 0;
			pair.link.log.length = 0;
			const r = pair.rManager.fulfillHtlc(
				pair.channelId,
				fromS.id,
				fromS.preimage
			);
			expect(r.ok, r.error).to.equal(true);
			const s = pair.sManager.failHtlc(
				pair.channelId,
				fromR.id,
				Buffer.alloc(292)
			);
			expect(s.ok, s.error).to.equal(true);
			expectHealthy(pair, 'settles under the hold');
			expect(ordinaryHtlcs(pair.sChannel)).to.deep.equal([]);
			expect(ordinaryHtlcs(pair.rChannel)).to.deep.equal([]);
			expectVouchersCarried(pair, ALL, 'settles under the hold');
			expect(balances(pair).r).to.equal(R_START + 20_000_000n);
			expect(balances(pair).s).to.equal(S_AFTER_BOOK - 20_000_000n);
		});

		it('a compatible reconnect lifts it', () => {
			const pair = activePair();
			pair.link.disconnect();
			advertise(pair, 'R', false);
			pair.link.reconnect();
			expect(pair.sChannel.fforAdmissionHold()).to.not.equal(null);
			expect(pair.rChannel.fforAdmissionHold()).to.not.equal(null);
			pair.link.disconnect();
			advertise(pair, 'R', true);
			pair.link.reconnect();
			expect(pair.sChannel.fforAdmissionHold()).to.equal(null);
			expect(pair.rChannel.fforAdmissionHold()).to.equal(null);
			expect(pair.sChannel.fforSettlementRefusal(1, TIP)).to.equal(null);
			pay(pair, 'S', 5_000_000n);
			pay(pair, 'R', 1_000_000n);
			expectHealthy(pair, 'after the hold lifted');
			expectVouchersCarried(pair, ALL, 'after the hold lifted');
		});

		it('it gates only our own origination: the side that sees no problem keeps adding, and the holding side takes it', () => {
			const pair = activePair();
			pair.link.disconnect();
			// Only S observes an incompatible init.
			pair.sManager.setFforPeerFeatureSource(() => null);
			pair.link.reconnect();
			expect(pair.sChannel.fforAdmissionHold()).to.not.equal(null);
			expect(pair.rChannel.fforAdmissionHold()).to.equal(null);
			const held = offer(pair, 'S', 1_000_000n);
			expect(held.result.ok).to.equal(false);
			pair.sErrors.length = 0;
			// R's add is R's origination; S does not fail the channel over it.
			const add = offer(pair, 'R', 3_000_000n);
			expect(add.result.ok, add.result.error).to.equal(true);
			const settle = pair.sManager.fulfillHtlc(
				pair.channelId,
				add.id,
				add.preimage
			);
			expect(settle.ok, settle.error).to.equal(true);
			expectHealthy(pair, 'peer add under our hold');
			expectVouchersCarried(pair, ALL, 'peer add under our hold');
			expect(balances(pair).s).to.equal(S_AFTER_BOOK + 3_000_000n);
		});

		it('an ordinary disconnect sets no hold, so S keeps settling while R is away', () => {
			const pair = activePair();
			pair.link.disconnect();
			expect(pair.sChannel.getState()).to.equal(
				ChannelState.AWAITING_REESTABLISH
			);
			expect(pair.sChannel.fforSettlementRefusal(1, TIP)).to.equal(null);
			// Nor does a restart of S with R still away.
			restart(pair, 'S');
			expect(record(pair.sChannel).state).to.equal(FforState.ACTIVE);
			expect(pair.sChannel.fforSettlementRefusal(1, TIP)).to.equal(null);
			expect(pair.sChannel.fforSettlementRefusal(3, TIP)).to.equal(null);
		});

		it('once observed, it lasts through a later disconnect until a compatible init', () => {
			const pair = activePair();
			pair.link.disconnect();
			advertise(pair, 'R', false);
			pair.link.reconnect();
			expect(pair.sChannel.fforSettlementRefusal(1, TIP)).to.match(
				/capability hold/
			);
			pair.link.disconnect();
			// R is away again: S still does not start a delegated settlement.
			expect(pair.sChannel.fforSettlementRefusal(1, TIP)).to.match(
				/capability hold/
			);
			advertise(pair, 'R', true);
			pair.link.reconnect();
			expect(pair.sChannel.fforSettlementRefusal(1, TIP)).to.equal(null);
		});

		it('safe retirement still works under it: the book closes and ordinary operation resumes', () => {
			const pair = activePair();
			const fromS = offer(pair, 'S', 6_000_000n);
			expect(fromS.result.ok, fromS.result.error).to.equal(true);
			settleSlot(pair, 2);
			pair.link.disconnect();
			advertise(pair, 'S', false);
			pair.link.reconnect();
			expect(pair.rChannel.fforAdmissionHold()).to.not.equal(null);
			pair.link.log.length = 0;
			const closed = pair.rManager.closeFforEpoch(pair.channelId);
			expect(closed.ok, closed.error).to.equal(true);
			expectHealthy(pair, 'closed under the hold');
			expect(record(pair.rChannel).state, why(pair)).to.equal(FforState.CLOSED);
			expect(record(pair.sChannel).state).to.equal(FforState.CLOSED);
			expect(balances(pair)).to.deep.equal({
				s: S_AFTER_BOOK - 6_000_000n + AMOUNTS[0] + AMOUNTS[2],
				r: R_START + AMOUNTS[1],
				sViewOfR: R_START + AMOUNTS[1],
				rViewOfS: S_AFTER_BOOK - 6_000_000n + AMOUNTS[0] + AMOUNTS[2]
			});
			// CLOSED is baseline ordinary operation: nothing is held.
			expect(pair.rChannel.fforAdmissionHold()).to.equal(null);
			expect(pair.sChannel.fforAdmissionHold()).to.equal(null);
			pay(pair, 'S', 1_000_000n);
			pay(pair, 'R', 1_000_000n);
			expectHealthy(pair, 'after the close');
		});

		it('a baseline epoch is not touched by what a connection advertises', () => {
			const pair = createPair({ pushSat: 200_000n });
			activate(pair, AMOUNTS, false);
			pair.link.disconnect();
			advertise(pair, 'S', false);
			advertise(pair, 'R', false);
			pair.link.reconnect();
			for (const ch of [pair.sChannel, pair.rChannel]) {
				expect(record(ch).state).to.equal(FforState.ACTIVE);
				expect(ch.fforAdmissionHold()).to.equal(null);
				expect(ch.fforIsFrozen()).to.equal(true);
			}
			expect(pair.sChannel.fforSettlementRefusal(1, TIP)).to.equal(null);
			const closed = pair.rManager.closeFforEpoch(pair.channelId);
			expect(closed.ok, closed.error).to.equal(true);
			expect(record(pair.rChannel).state, why(pair)).to.equal(FforState.CLOSED);
		});
	});

	describe('R is DRAINING and S reestablishes without the close', () => {
		/**
		 * S's state from before ff_close (a backup), R DRAINING with its drain
		 * lost on the wire. `settled` are the slots S settled before the
		 * backup, so the acknowledgement it re-issues is the one R holds.
		 *
		 * R also has two ordinary updates in the same lost round: an add of its
		 * own and a malformed-fail of an HTLC S offered. They are queued on the
		 * channel ahead of the drain, so the one commitment_signed R signs
		 * covers all of them and the retransmission is a single chain.
		 */
		function sLostTheClose(settled: number[]): {
			pair: IPair;
			fromS: bigint;
			fromR: bigint;
		} {
			const pair = activePair();
			const inbound = offer(pair, 'S', 6_000_000n);
			expect(inbound.result.ok, inbound.result.error).to.equal(true);
			for (const k of settled) settleSlot(pair, k);
			const backup = snapshot(pair, 'S');
			const fromR = pair.rChannel.getFullState().localHtlcCounter;
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
			// Nothing of R's but ff_close arrives: the round is lost.
			pair.link.drop = (from, type): boolean =>
				from === 'R' && type !== MessageType.FF_CLOSE;
			const closed = pair.rManager.closeFforEpoch(pair.channelId);
			expect(closed.ok, closed.error).to.equal(true);
			expect(record(pair.rChannel).state).to.equal(FforState.DRAINING);
			// One commitment_signed covers the ordinary updates and the drain.
			expect(
				pair.link.dropped.filter(
					(e) => e.from === 'R' && e.type === MessageType.COMMITMENT_SIGNED
				).length
			).to.equal(1);
			pair.link.drop = null;
			restart(pair, 'S', backup);
			expect(record(pair.sChannel).state).to.equal(FforState.ACTIVE);
			expect(record(pair.sChannel).closeWire).to.equal(null);
			pair.link.log.length = 0;
			pair.sErrors.length = 0;
			pair.rErrors.length = 0;
			return { pair, fromS: inbound.id, fromR };
		}

		it('with a voucher fail queued, the whole retransmission chain waits for the acknowledgement', () => {
			const { pair, fromR } = sLostTheClose([2]);
			// Deliver S's acknowledgement last: until it arrives R has sent
			// ff_close again and nothing else.
			pair.link.holdAt = (from, type): boolean =>
				from === 'S' && type === MessageType.FF_CLOSE_ACK;
			pair.link.reconnect();
			pair.link.holdAt = null;
			expect(sentBy(pair, 'R')).to.deep.equal([
				MessageType.CHANNEL_REESTABLISH,
				MessageType.FF_CLOSE
			]);
			expect(pair.sChannel.getState()).to.equal(ChannelState.NORMAL);
			expect(record(pair.sChannel).state).to.equal(FforState.DRAINING);
			pair.link.release('S');
			expectHealthy(pair, 'drain released by the ack');
			// The chain left whole and in its order: the ordinary updates, the
			// drain, then the commitment_signed that covers them all.
			expect(sentBy(pair, 'R').slice(2, 8)).to.deep.equal([
				MessageType.UPDATE_ADD_HTLC,
				MessageType.UPDATE_FAIL_MALFORMED_HTLC,
				MessageType.UPDATE_FAIL_HTLC,
				MessageType.UPDATE_FULFILL_HTLC,
				MessageType.UPDATE_FAIL_HTLC,
				MessageType.COMMITMENT_SIGNED
			]);
			expect(record(pair.rChannel).state, why(pair)).to.equal(FforState.CLOSED);
			expect(record(pair.sChannel).state).to.equal(FforState.CLOSED);
			expect(ordinaryHtlcs(pair.sChannel)).to.deep.equal([`received-${fromR}`]);
			expect(balances(pair).r).to.equal(R_START - 2_000_000n + AMOUNTS[1]);
			expect(balances(pair).s).to.equal(S_AFTER_BOOK + AMOUNTS[0] + AMOUNTS[2]);
		});

		it('with no voucher fail queued, ordinary retransmissions and voucher fulfils are not held', () => {
			// Every slot was settled: the drain is fulfils only.
			const { pair, fromR } = sLostTheClose([1, 2, 3]);
			// Deliver S's fresh acknowledgement last, so what R sends before it
			// provably did not wait for it.
			pair.link.holdAt = (from, type): boolean =>
				from === 'S' && type === MessageType.FF_CLOSE_ACK;
			pair.link.reconnect();
			pair.link.holdAt = null;
			const sent = sentBy(pair, 'R');
			expect(pair.link.types()).to.not.include(MessageType.FF_CLOSE_ACK);
			// An ordinary fail is queued, and is not a voucher fail.
			expect(sent.slice(1, 7)).to.deep.equal([
				MessageType.UPDATE_ADD_HTLC,
				MessageType.UPDATE_FAIL_MALFORMED_HTLC,
				MessageType.UPDATE_FULFILL_HTLC,
				MessageType.UPDATE_FULFILL_HTLC,
				MessageType.UPDATE_FULFILL_HTLC,
				MessageType.COMMITMENT_SIGNED
			]);
			expect(sent).to.not.include(MessageType.UPDATE_FAIL_HTLC);
			// S, still ACTIVE when they arrived, took the fulfils and the rest.
			expect(pair.sChannel.getState()).to.equal(ChannelState.NORMAL);
			expect(pair.link.types()).to.not.include(MessageType.ERROR);
			pair.link.release('S');
			expectHealthy(pair, 'not held');
			expect(record(pair.rChannel).state, why(pair)).to.equal(FforState.CLOSED);
			expect(record(pair.sChannel).state).to.equal(FforState.CLOSED);
			expect(ordinaryHtlcs(pair.sChannel)).to.deep.equal([`received-${fromR}`]);
			expect(balances(pair)).to.deep.equal({
				s: S_AFTER_BOOK,
				r: R_START - 2_000_000n + BUDGET,
				sViewOfR: R_START - 2_000_000n + BUDGET,
				rViewOfS: S_AFTER_BOOK
			});
		});

		it('no new voucher fail is issued until the acknowledgement returns', () => {
			// R is DRAINING with its vouchers still committed (its first drain
			// did not run), and S comes back from a backup that predates the
			// close.
			const pair = activePair();
			const backup = snapshot(pair, 'S');
			const drain = pair.rChannel as unknown as {
				_fforDrain(f: unknown): ChannelAction[];
			};
			const original = drain._fforDrain.bind(pair.rChannel);
			drain._fforDrain = (): ChannelAction[] => [];
			const closed = pair.rManager.closeFforEpoch(pair.channelId);
			expect(closed.ok, closed.error).to.equal(true);
			drain._fforDrain = original;
			expect(record(pair.rChannel).state).to.equal(FforState.DRAINING);
			expect(vouchers(pair.rChannel).map(([, st]) => st)).to.deep.equal([
				HtlcState.COMMITTED,
				HtlcState.COMMITTED,
				HtlcState.COMMITTED
			]);
			restart(pair, 'S', backup);
			pair.link.log.length = 0;
			pair.sErrors.length = 0;
			pair.rErrors.length = 0;
			pair.link.holdAt = (from, type): boolean =>
				from === 'S' && type === MessageType.FF_CLOSE_ACK;
			pair.link.reconnect();
			pair.link.holdAt = null;
			expect(record(pair.sChannel).state).to.equal(FforState.DRAINING);
			// R learns a preimage while S's acknowledgement is still on its
			// way. That slot is fulfilled; the others are NOT failed yet.
			const t1 = record(pair.sChannel).preimages[0];
			const learned = pair.rManager.fforAddPreimage(pair.channelId, t1);
			expect(learned.ok, learned.error).to.equal(true);
			const fromR = sentBy(pair, 'R');
			expect(fromR).to.include(MessageType.UPDATE_FULFILL_HTLC);
			expect(fromR).to.not.include(MessageType.UPDATE_FAIL_HTLC);
			expect(pair.sChannel.getState()).to.equal(ChannelState.NORMAL);
			// The acknowledgement arrives: now the unsettled slots are failed.
			pair.link.release('S');
			expectHealthy(pair, 'fails after the ack');
			expect(sentBy(pair, 'R')).to.include(MessageType.UPDATE_FAIL_HTLC);
			expect(record(pair.rChannel).state, why(pair)).to.equal(FforState.CLOSED);
			expect(record(pair.sChannel).state).to.equal(FforState.CLOSED);
			expect(balances(pair).r).to.equal(R_START + AMOUNTS[0]);
			expect(balances(pair).s).to.equal(S_AFTER_BOOK + AMOUNTS[1] + AMOUNTS[2]);
		});
	});

	describe('DRAINING across a reconnect', () => {
		it('both sides DRAINING with the drain and ordinary traffic in flight: everything is retransmitted and the book closes', () => {
			const pair = activePair();
			settleSlot(pair, 2);
			const fromS = offer(pair, 'S', 5_000_000n);
			expect(fromS.result.ok, fromS.result.error).to.equal(true);
			// The drain is lost with the connection.
			pair.link.drop = (from, type): boolean =>
				from === 'R' && type !== MessageType.FF_CLOSE;
			const closed = pair.rManager.closeFforEpoch(pair.channelId);
			expect(closed.ok, closed.error).to.equal(true);
			pair.link.drop = null;
			expect(record(pair.sChannel).state).to.equal(FforState.DRAINING);
			expect(record(pair.rChannel).state).to.equal(FforState.DRAINING);
			pair.link.disconnect();
			pair.link.log.length = 0;
			pair.link.reconnect();
			expectHealthy(pair, 'drain retransmitted');
			expect(record(pair.rChannel).state, why(pair)).to.equal(FforState.CLOSED);
			expect(record(pair.sChannel).state).to.equal(FforState.CLOSED);
			expect(ordinaryHtlcs(pair.rChannel)).to.deep.equal([
				`received-${fromS.id}`
			]);
			const settle = pair.rManager.fulfillHtlc(
				pair.channelId,
				fromS.id,
				fromS.preimage
			);
			expect(settle.ok, settle.error).to.equal(true);
			expect(balances(pair)).to.deep.equal({
				s: S_AFTER_BOOK - 5_000_000n + AMOUNTS[0] + AMOUNTS[2],
				r: R_START + 5_000_000n + AMOUNTS[1],
				sViewOfR: R_START + 5_000_000n + AMOUNTS[1],
				rViewOfS: S_AFTER_BOOK - 5_000_000n + AMOUNTS[0] + AMOUNTS[2]
			});
			expect(channel(pair, 'S').getFullState().htlcs.size).to.equal(0);
		});
	});
});

describe('FFOR concurrent receive: the capability hold through the node (CONCURRENT-RECEIVE.md 8)', function () {
	this.timeout(120_000);

	it('R exposes no invoice and S starts no delegated settlement after an incompatible reconnect; both resume after a compatible one', () => {
		const w = createConcurrentWorld();
		activateWorld(w, true);
		// Two invoices are out before anything goes wrong.
		const second = w.r.createFforVoucherInvoice(w.srHex, 2).bolt11;
		const third = w.r.createFforVoucherInvoice(w.srHex, 3).bolt11;
		const failed: string[] = [];
		w.s.on('ffor:delegated-failed', (e: { reason: string }) =>
			failed.push(e.reason)
		);

		// S comes back without the extension in its init.
		w.sr.disconnect();
		w.s.getLocalFeatures().clearBit(Feature.OPTION_FF_CONCURRENT + 1);
		w.sr.reconnect();
		for (const node of [w.s, w.r]) {
			expect(nodeRecord(node, w.srHex).state).to.equal(FforState.ACTIVE);
			expect(nodeRecord(node, w.srHex).concurrentVersion).to.equal(1);
		}
		expect(() => w.r.createFforVoucherInvoice(w.srHex, 1)).to.throw(
			/no invoice is exposed while the peer did not advertise/
		);
		expect(nodeRecord(w.r, w.srHex).exposedSlots[0]).to.equal(false);
		// A payer of an invoice already out is failed upstream, not settled.
		const refused = payInvoice(w, second);
		expect(refused.status).to.equal(PaymentStatus.FAILED);
		expect(failed.join('|')).to.match(/capability hold/);
		expect(nodeRecord(w.s, w.srHex).slotStates[1]).to.equal('UNUSED');

		// The capability is restored.
		w.sr.disconnect();
		w.s.getLocalFeatures().setOptional(Feature.OPTION_FF_CONCURRENT);
		w.sr.reconnect();
		const first = w.r.createFforVoucherInvoice(w.srHex, 1).bolt11;
		expect(first).to.be.a('string');
		const paid = payInvoice(w, third);
		expect(paid.status, JSON.stringify(w.errors)).to.equal(
			PaymentStatus.COMPLETED
		);
		expect(nodeRecord(w.s, w.srHex).slotStates[2]).to.equal('SETTLED');
	});

	it('an ordinary disconnect is no hold: S settles for an R that is simply away', () => {
		const w = createConcurrentWorld();
		activateWorld(w, true);
		const invoice = w.r.createFforVoucherInvoice(w.srHex, 1).bolt11;
		w.sr.disconnect();
		const paid = payInvoice(w, invoice);
		expect(paid.status, JSON.stringify(w.errors)).to.equal(
			PaymentStatus.COMPLETED
		);
		expect(nodeRecord(w.s, w.srHex).slotStates[0]).to.equal('SETTLED');
	});
});
