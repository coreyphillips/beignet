/**
 * FFOR Variant D: the parked-voucher guard reads a settle id in the HTLC's
 * own direction (specs/ffor-offline-receive.md sections 7.5.5, 9.5.1 step 3).
 *
 * The vouchers are HTLCs S offered: `received-<id>` on R, `offered-<id>` on
 * S, ids s_htlc_id_base .. s_htlc_id_base + K - 1 of S's counter. R's own
 * offered HTLCs count from R's counter, so an ordinary HTLC R offered can
 * carry the same number as a voucher. A settle names one or the other by
 * its direction, never by the number alone.
 *
 * Two ChannelManagers in loopback, every state reached through real
 * messages. The link can hold one direction back (FIFO, a slow socket) so
 * messages that cross on the wire cross here too.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import { Channel } from '../../src/lightning/channel/channel';
import {
	ChannelAction,
	ChannelActionType
} from '../../src/lightning/channel/channel-actions';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	HtlcState
} from '../../src/lightning/channel/types';
import { MessageType } from '../../src/lightning/message/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	FforAbortReason,
	FforState,
	IFforEpochRecord
} from '../../src/lightning/ffor/types';

// ─────────────── Harness ───────────────

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

function makeConfig(
	seedId: number
): IChannelManagerConfig & { nodePrivateKey: Buffer } {
	const seed = sha(`ffor-direction-seed-${seedId}`);
	return {
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(seed),
		localPerCommitmentSeed: sha(seed, 'per-commitment'),
		localFundingPrivkey: sha(seed, Buffer.from([0])),
		htlcBasepointSecret: sha(seed, Buffer.from([4])),
		nodePrivateKey: sha(seed, 'node-key'),
		// Section 5: anchor commitments.
		preferAnchors: true
	};
}

type Side = 'S' | 'R';

interface IWireEntry {
	from: Side;
	type: number;
	payload: Buffer;
}

/**
 * A loopback link with a wire log. Each direction is a FIFO pipe that can
 * be held: a held message and everything its sender sends after it wait, in
 * order, until `release`.
 */
class Link {
	readonly log: IWireEntry[] = [];
	/** Start holding a direction at the first message this matches. */
	holdAt: ((from: Side, type: number) => boolean) | null = null;
	private readonly held: Record<Side, IWireEntry[] | null> = {
		S: null,
		R: null
	};

	constructor(
		readonly s: ChannelManager,
		readonly sPub: string,
		readonly r: ChannelManager,
		readonly rPub: string
	) {
		s.on('message:outbound', (peer: string, type: number, payload: Buffer) => {
			if (peer === rPub) this.deliver({ from: 'S', type, payload });
		});
		r.on('message:outbound', (peer: string, type: number, payload: Buffer) => {
			if (peer === sPub) this.deliver({ from: 'R', type, payload });
		});
	}

	private deliver(m: IWireEntry): void {
		if (this.held[m.from] === null && this.holdAt?.(m.from, m.type)) {
			this.held[m.from] = [];
		}
		const queue = this.held[m.from];
		if (queue) {
			queue.push(m);
			return;
		}
		this.direct(m);
	}

	private direct(m: IWireEntry): void {
		this.log.push(m);
		if (m.from === 'S') this.r.handleMessage(this.sPub, m.type, m.payload);
		else this.s.handleMessage(this.rPub, m.type, m.payload);
	}

	types(): number[] {
		return this.log.map((e) => e.type);
	}

	/** Message types one side has sent that are still in flight. */
	inFlight(from: Side): number[] {
		return (this.held[from] ?? []).map((m) => m.type);
	}

	/**
	 * Deliver what one side has in flight, in order: the next `count`
	 * messages, or everything, after which the direction is no longer held.
	 * What the sender adds meanwhile queues behind what is in flight.
	 */
	release(from: Side, count = Infinity): void {
		const queue = this.held[from];
		if (!queue) return;
		for (let n = 0; n < count && queue.length > 0; n++) {
			this.direct(queue.shift()!);
		}
		if (count === Infinity) this.held[from] = null;
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
	sErrors: string[];
	rErrors: string[];
}

const FUNDING_SATOSHIS = 1_000_000n;
const T_EXP = 800_000;
const D_DEADLINE = 798_992;
const TIP = 795_000;
const AMOUNTS = [994_000n, 546_250n, 49_749_000n];
const ONION = Buffer.alloc(1366);

let pairSeed = 0;

/** S opens and funds; R accepts. Both at tip 795000. */
function createPair(): IPair {
	pairSeed += 10;
	const sConfig = makeConfig(500 + pairSeed);
	const rConfig = makeConfig(501 + pairSeed);
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
	return {
		link,
		sManager,
		rManager,
		sPub,
		rPub,
		sChannel,
		rChannel,
		channelId,
		sErrors,
		rErrors
	};
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

/** Voucher HTLC entries on one side. */
function vouchers(ch: Channel): Array<[string, HtlcState]> {
	const out: Array<[string, HtlcState]> = [];
	for (const [key, e] of ch.getFullState().htlcs) {
		if (e.fforVoucher === true) out.push([key, e.state]);
	}
	return out;
}

function why(pair: IPair): string {
	return JSON.stringify({
		sErrors: pair.sErrors,
		rErrors: pair.rErrors,
		wire: pair.link.log.map((e) => `${e.from}:${e.type}`),
		inFlight: { S: pair.link.inFlight('S'), R: pair.link.inFlight('R') }
	});
}

/** One side offers an ordinary HTLC; returns its id and preimage. */
function offer(
	pair: IPair,
	from: Side,
	amountMsat: bigint
): { id: bigint; preimage: Buffer } {
	const manager = from === 'S' ? pair.sManager : pair.rManager;
	const channel = from === 'S' ? pair.sChannel : pair.rChannel;
	const preimage = crypto.randomBytes(32);
	const id = channel.getFullState().localHtlcCounter;
	const res = manager.addHtlc(
		pair.channelId,
		amountMsat,
		sha(preimage),
		TIP + 100,
		ONION
	);
	expect(res.ok, res.error).to.equal(true);
	return { id, preimage };
}

/**
 * A peer that does not apply the setup admission barrier (issue #1289: an
 * older build, or one that misbehaves) offers an ordinary HTLC while the
 * setup runs. Its channel lets this one add through as if it were the
 * epoch's own; the other side does not refuse a peer add during the setup.
 */
function offerPastBarrier(
	pair: IPair,
	from: Side,
	amountMsat: bigint
): { id: bigint; preimage: Buffer } {
	const channel = from === 'S' ? pair.sChannel : pair.rChannel;
	const gate = channel as unknown as { _fforInternalAdd: boolean };
	gate._fforInternalAdd = true;
	try {
		return offer(pair, from, amountMsat);
	} finally {
		gate._fforInternalAdd = false;
	}
}

/** An ordinary payment, offered and fulfilled, both rounds complete. */
function pay(pair: IPair, from: Side, amountMsat: bigint): void {
	const { id, preimage } = offer(pair, from, amountMsat);
	const to = from === 'S' ? pair.rManager : pair.sManager;
	const res = to.fulfillHtlc(pair.channelId, id, preimage);
	expect(res.ok, res.error).to.equal(true);
	expect(pair.sChannel.getFullState().htlcs.size, why(pair)).to.equal(0);
	expect(pair.rChannel.getFullState().htlcs.size, why(pair)).to.equal(0);
}

// ─────────────── Tests ───────────────

/** S's three ways to remove an HTLC R offered. */
const SETTLES = ['fulfils', 'fails', 'fails as malformed'] as const;
type Settle = (typeof SETTLES)[number];

const ORDINARY_MSAT = 5_000_000n;
/** Under the 354 sat dust limit: trimmed from both commitments. */
const DUST_MSAT = 100_000n;
const BADONION_INVALID_HMAC = 0x8000 | 0x4000 | 5;

/**
 * S and R each make one ordinary payment, so R has a balance to offer from
 * and both counters stand at 1: the next HTLC R offers and the first
 * voucher S offers both get id 1.
 */
function fundedPair(): IPair {
	const pair = createPair();
	pay(pair, 'S', 300_000_000n);
	pay(pair, 'R', 1_000_000n);
	pair.link.log.length = 0;
	pair.sErrors.length = 0;
	pair.rErrors.length = 0;
	return pair;
}

/** S removes the HTLC R offered under `id`, the way the case names. */
function settle(pair: IPair, how: Settle, id: bigint, preimage: Buffer): void {
	const res =
		how === 'fulfils'
			? pair.sManager.fulfillHtlc(pair.channelId, id, preimage)
			: how === 'fails'
			? pair.sManager.failHtlc(pair.channelId, id, Buffer.alloc(292))
			: pair.sManager.failMalformedHtlc(
					pair.channelId,
					id,
					sha(ONION),
					BADONION_INVALID_HMAC
			  );
	expect(res.ok, res.error).to.equal(true);
}

/**
 * R holds parked vouchers of an ABORTED epoch whose unwind is in flight,
 * beside an ordinary HTLC it offered under a voucher's id.
 */
function expectCollision(
	pair: IPair,
	id: bigint,
	parked = AMOUNTS.length
): void {
	const r = record(pair.rChannel);
	expect(r.state, why(pair)).to.equal(FforState.ABORTED);
	expect(id >= r.sHtlcIdBase!).to.be.true;
	expect(id < r.sHtlcIdBase! + BigInt(parked)).to.be.true;
	const htlcs = pair.rChannel.getFullState().htlcs;
	expect(htlcs.get(`received-${id}`)?.fforVoucher).to.equal(true);
	const ordinary = htlcs.get(`offered-${id}`);
	expect(ordinary?.state).to.equal(HtlcState.COMMITTED);
	expect(ordinary?.fforVoucher).to.not.equal(true);
	expect(vouchers(pair.rChannel).length).to.equal(parked);
	expect(pair.link.inFlight('R')).to.include(MessageType.UPDATE_FAIL_HTLC);
}

/** R took the settle for the HTLC it offered, and the unwind then completes. */
function expectSettledAndUnwound(
	pair: IPair,
	how: Settle,
	id: bigint,
	rBalanceBefore: bigint,
	seen: { fulfilled: bigint[]; failed: bigint[] },
	parked = AMOUNTS.length
): void {
	expect(pair.rErrors, why(pair)).to.deep.equal([]);
	expect(pair.rChannel.getState()).to.equal(ChannelState.NORMAL);
	expect(pair.sChannel.getState()).to.equal(ChannelState.NORMAL);
	expect(pair.link.types()).to.not.include(MessageType.ERROR);
	if (how === 'fulfils')
		expect(seen).to.deep.equal({ fulfilled: [id], failed: [] });
	else expect(seen).to.deep.equal({ fulfilled: [], failed: [id] });
	// The vouchers were not touched by it: still parked, the unwind's
	// update_fail_htlc for each still in flight.
	expect(vouchers(pair.rChannel).length).to.equal(parked);

	pair.link.release('R');
	expect(pair.rErrors, why(pair)).to.deep.equal([]);
	expect(pair.rChannel.getFullState().htlcs.size, why(pair)).to.equal(0);
	expect(pair.sChannel.getFullState().htlcs.size, why(pair)).to.equal(0);
	expect(pair.rChannel.getState()).to.equal(ChannelState.NORMAL);
	expect(pair.sChannel.getState()).to.equal(ChannelState.NORMAL);
	expect(record(pair.rChannel).state).to.equal(FforState.ABORTED);
	expect(record(pair.rChannel).unwindOwed).to.equal(false);
	// Every voucher failed back to S; the ordinary HTLC moved only if paid.
	const paid = how === 'fulfils' ? ORDINARY_MSAT : 0n;
	expect(pair.rChannel.getFullState().localBalanceMsat).to.equal(
		rBalanceBefore - paid
	);
	expect(pair.sChannel.getFullState().remoteBalanceMsat).to.equal(
		rBalanceBefore - paid
	);
	expect(
		pair.sChannel.getFullState().localBalanceMsat +
			pair.rChannel.getFullState().localBalanceMsat
	).to.equal(FUNDING_SATOSHIS * 1000n);
}

/** Record the settles R's manager reports for HTLCs it offered. */
function watchSettles(pair: IPair): { fulfilled: bigint[]; failed: bigint[] } {
	const seen = { fulfilled: [] as bigint[], failed: [] as bigint[] };
	pair.rManager.on('htlc:fulfilled', (_c: Buffer, id: bigint) =>
		seen.fulfilled.push(id)
	);
	pair.rManager.on('htlc:failed', (_c: Buffer, id: bigint) =>
		seen.failed.push(id)
	);
	return seen;
}

describe('FFOR Variant D: voucher settle ids are read in their own direction', function () {
	this.timeout(60_000);

	for (const how of SETTLES) {
		it(`R, epoch ABORTED: S ${how} an HTLC R offered under a parked voucher's id`, () => {
			const pair = fundedPair();
			const seen = watchSettles(pair);
			const rBalanceBefore = pair.rChannel.getFullState().localBalanceMsat;
			// The voucher round's commitment_signed is still on its way when R
			// gives the setup up: the vouchers are parked but not yet committed,
			// so the unwind waits for the round.
			pair.link.holdAt = (from, type): boolean =>
				from === 'S' && type === MessageType.COMMITMENT_SIGNED;
			const init = pair.rManager.initiateFforEpoch(pair.channelId, terms());
			expect(init.ok, init.error).to.equal(true);
			pair.link.holdAt = null;
			expect(record(pair.rChannel).state).to.equal(FforState.NEGOTIATING);
			expect(vouchers(pair.rChannel).length).to.equal(AMOUNTS.length);
			const abort = pair.rManager.abortFforEpoch(pair.channelId);
			expect(abort.ok, abort.error).to.equal(true);
			expect(record(pair.rChannel).state).to.equal(FforState.ABORTED);
			expect(record(pair.sChannel).state).to.equal(FforState.ABORTED);
			// An aborted epoch freezes nothing: R sends an ordinary payment.
			const { id, preimage } = offer(pair, 'R', ORDINARY_MSAT);
			// The rounds complete and R's unwind leaves, but has not reached S
			// when S settles the payment.
			pair.link.holdAt = (from, type): boolean =>
				from === 'R' && type === MessageType.UPDATE_FAIL_HTLC;
			pair.link.release('S');
			pair.link.holdAt = null;
			expectCollision(pair, id);

			settle(pair, how, id, preimage);
			expectSettledAndUnwound(pair, how, id, rBalanceBefore, seen);
		});
	}

	it("R, a payment racing a voucher round that failed: S's fulfil crosses the unwind", () => {
		// R can no longer fail the round with a payment of its own: from
		// ff_init on its adds are refused until the epoch is ACTIVE or over
		// (the setup barrier, issue #1289), and no peer can make R offer one.
		// A round that fails on S's side still leaves R here: S's last voucher
		// add is refused locally, so S aborts with reason 5 behind the adds
		// it did send and ahead of their commitment_signed.
		const pair = fundedPair();
		const seen = watchSettles(pair);
		const rBalanceBefore = pair.rChannel.getFullState().localBalanceMsat;
		const parked = AMOUNTS.length - 1;
		const sAdd = pair.sChannel.addHtlc.bind(pair.sChannel);
		let sAdds = 0;
		(pair.sChannel as unknown as { addHtlc: Channel['addHtlc'] }).addHtlc = (
			...args
		): ChannelAction[] =>
			++sAdds === AMOUNTS.length
				? [{ type: ChannelActionType.ERROR, message: 'voucher add refused' }]
				: sAdd(...args);
		pair.link.holdAt = (from, type): boolean =>
			from === 'S' && type === MessageType.COMMITMENT_SIGNED;
		const init = pair.rManager.initiateFforEpoch(pair.channelId, terms());
		expect(init.ok, init.error).to.equal(true);
		pair.link.holdAt = null;
		expect(record(pair.sChannel).state).to.equal(FforState.ABORTED);
		expect(record(pair.rChannel).state, why(pair)).to.equal(FforState.ABORTED);
		expect(record(pair.rChannel).abortReason, why(pair)).to.equal(
			FforAbortReason.VOUCHER_ROUND_FAILED
		);
		expect(vouchers(pair.rChannel).length).to.equal(parked);
		// The abort lifted the barrier and the round is still open: R pays.
		const { id, preimage } = offer(pair, 'R', ORDINARY_MSAT);
		pair.link.holdAt = (from, type): boolean =>
			from === 'R' && type === MessageType.UPDATE_FAIL_HTLC;
		pair.link.release('S');
		pair.link.holdAt = null;
		expectCollision(pair, id, parked);
		// The abort's own notification; nothing else may follow it.
		expect(pair.rErrors.length).to.equal(1);
		pair.rErrors.length = 0;

		settle(pair, 'fulfils', id, preimage);
		expectSettledAndUnwound(pair, 'fulfils', id, rBalanceBefore, seen, parked);
	});

	it("S, epoch DRAINING: settling an HTLC R offered under a voucher's id is not the drain", () => {
		// R's counter stays at 0 here and S's is at 1: the vouchers are 1..3.
		const pair = createPair();
		pay(pair, 'S', 300_000_000n);
		pair.link.log.length = 0;
		pair.sErrors.length = 0;
		// R makes two small payments while the voucher round is in flight. An
		// R of this build refuses them itself (the setup barrier, issue
		// #1289); S does not refuse a peer add during the setup, so an R
		// without the barrier still puts S here.
		// Both are dust: they add no output, so the section 9.5.1 step 5 count
		// does not see them. S settles the first (id 0, no voucher's); the
		// second (id 1, the first voucher's number) is still on the channel
		// when the epoch activates.
		pair.link.holdAt = (from, type): boolean =>
			from === 'S' && type === MessageType.COMMITMENT_SIGNED;
		const init = pair.rManager.initiateFforEpoch(pair.channelId, terms());
		expect(init.ok, init.error).to.equal(true);
		pair.link.holdAt = null;
		const first = offerPastBarrier(pair, 'R', DUST_MSAT);
		pair.link.release('S', 2);
		const second = offerPastBarrier(pair, 'R', DUST_MSAT);
		pair.link.release('S', 1);
		settle(pair, 'fulfils', first.id, first.preimage);
		pair.link.release('S');
		expect(record(pair.sChannel).state, why(pair)).to.equal(FforState.ACTIVE);
		expect(record(pair.rChannel).state, why(pair)).to.equal(FforState.ACTIVE);
		const id = second.id;
		expect(id).to.equal(record(pair.sChannel).sHtlcIdBase);
		const sHtlcs = pair.sChannel.getFullState().htlcs;
		expect(sHtlcs.get(`offered-${id}`)?.fforVoucher).to.equal(true);
		expect(sHtlcs.get(`received-${id}`)?.state).to.equal(HtlcState.COMMITTED);
		expect(sHtlcs.get(`received-${id}`)?.fforVoucher).to.not.equal(true);

		// Hold R's drain so both sides stay DRAINING with every voucher on.
		pair.link.holdAt = (from, type): boolean =>
			from === 'R' && type === MessageType.UPDATE_FAIL_HTLC;
		expect(pair.rManager.closeFforEpoch(pair.channelId).ok).to.equal(true);
		pair.link.holdAt = null;
		expect(record(pair.sChannel).state).to.equal(FforState.DRAINING);
		expect(record(pair.rChannel).state).to.equal(FforState.DRAINING);
		expect(pair.sErrors, why(pair)).to.deep.equal([]);
		expect(pair.rErrors, why(pair)).to.deep.equal([]);

		// Section 7.5.5: DRAINING admits the voucher drain and nothing else.
		// What S settles here is the HTLC it RECEIVED under that number, not
		// the voucher it offered: the freeze refuses it and nothing is sent.
		const sent = pair.link.log.length;
		const attempts = [
			pair.sManager.fulfillHtlc(pair.channelId, id, second.preimage),
			pair.sManager.failHtlc(pair.channelId, id, Buffer.alloc(292)),
			pair.sManager.failMalformedHtlc(
				pair.channelId,
				id,
				sha(ONION),
				BADONION_INVALID_HMAC
			)
		];
		for (const res of attempts) {
			expect(res.ok, 'an ordinary settle passed the DRAINING freeze').to.equal(
				false
			);
			expect(res.error).to.include(
				'FFOR epoch is DRAINING: only the voucher drain may settle'
			);
		}
		expect(pair.link.log.length).to.equal(sent);
		expect(pair.rErrors, why(pair)).to.deep.equal([]);
		expect(pair.rChannel.getState()).to.equal(ChannelState.NORMAL);
		// On R the same number in the received direction IS the voucher, and
		// stays parked for everything but the epoch's own drain.
		const rFail = pair.rManager.failHtlc(pair.channelId, id, Buffer.alloc(292));
		expect(rFail.ok).to.equal(false);
		expect(rFail.error).to.include(`FFOR voucher ${id} is parked`);

		// The true drain is untouched: R's fails reach S as settles of HTLCs
		// S offered, pass the freeze, and the epoch closes on both sides.
		pair.sErrors.length = 0;
		pair.rErrors.length = 0;
		pair.link.release('R');
		expect(pair.sErrors, why(pair)).to.deep.equal([]);
		expect(pair.rErrors, why(pair)).to.deep.equal([]);
		expect(record(pair.sChannel).state).to.equal(FforState.CLOSED);
		expect(record(pair.rChannel).state).to.equal(FforState.CLOSED);
		expect(vouchers(pair.sChannel)).to.deep.equal([]);
		expect(vouchers(pair.rChannel)).to.deep.equal([]);
		// And the ordinary HTLC settles once the epoch has closed.
		settle(pair, 'fulfils', id, second.preimage);
		expect(pair.sErrors, why(pair)).to.deep.equal([]);
		expect(pair.rErrors, why(pair)).to.deep.equal([]);
		expect(pair.sChannel.getFullState().htlcs.size).to.equal(0);
		expect(pair.rChannel.getFullState().htlcs.size).to.equal(0);
		expect(pair.sChannel.getState()).to.equal(ChannelState.NORMAL);
		expect(pair.rChannel.getState()).to.equal(ChannelState.NORMAL);
	});
});
