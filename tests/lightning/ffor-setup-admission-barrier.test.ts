/**
 * FFOR Variant D: the setup admission barrier (issue #1289).
 *
 * Setup starts on an idle channel (specs/ffor-offline-receive.md section
 * 9.5.1 step 1) and wraps one stock commitment round around the K voucher
 * adds. From the first setup message until the epoch is ACTIVE or over,
 * neither side offers an ordinary HTLC of its own: an add that interleaves
 * with the voucher round rides into the epoch under the freeze, breaks the
 * step 5 output count, or moves the commitment numbers the activation
 * binds. The refusal is local (an ERROR action, the same shape as the
 * freeze refusal in ACTIVE), never a wire error and never a channel
 * failure. Peer adds are not refused here: R must take S's vouchers, and a
 * stray peer add keeps the outcome it had.
 *
 * Two ChannelManagers in loopback. The link can be switched to manual, so
 * each message is delivered by name and the states between two messages of
 * the round can be stood in.
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
	const seed = sha(`ffor-setup-barrier-seed-${seedId}`);
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
 * A loopback link with a wire log. Direct by default; in manual mode every
 * message waits in its sender's FIFO until the test delivers it.
 */
class Link {
	readonly log: IWireEntry[] = [];
	manual = false;
	private readonly queue: Record<Side, IWireEntry[]> = { S: [], R: [] };

	constructor(
		readonly s: ChannelManager,
		readonly sPub: string,
		readonly r: ChannelManager,
		readonly rPub: string
	) {
		s.on('message:outbound', (peer: string, type: number, payload: Buffer) => {
			if (peer === rPub) this.send({ from: 'S', type, payload });
		});
		r.on('message:outbound', (peer: string, type: number, payload: Buffer) => {
			if (peer === sPub) this.send({ from: 'R', type, payload });
		});
	}

	private send(m: IWireEntry): void {
		if (this.manual) this.queue[m.from].push(m);
		else this.direct(m);
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
		return this.queue[from].map((m) => m.type);
	}

	/** Deliver one side's next message; false when it has none in flight. */
	step(from: Side): boolean {
		const m = this.queue[from].shift();
		if (!m) return false;
		this.direct(m);
		return true;
	}

	/** Deliver everything in flight, and whatever that sets in flight. */
	flush(): void {
		while (this.queue.S.length > 0 || this.queue.R.length > 0) {
			this.step('S');
			this.step('R');
		}
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
const K = AMOUNTS.length;
const ONION = Buffer.alloc(1366);
const ORDINARY_MSAT = 5_000_000n;
/** Under the 354 sat dust limit: trimmed from both commitments. */
const DUST_MSAT = 100_000n;
/** What S pays R up front, so R has a balance to offer from. */
const R_FUNDS_MSAT = 300_000_000n;

let pairSeed = 0;

/**
 * S opens and funds; R accepts. Both at tip 795000. S then pays R once, so
 * either side could afford an ordinary HTLC: every refusal below is the
 * barrier's, not a balance check's.
 */
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
	const pair: IPair = {
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
	const funded = tryOffer(pair, 'S', R_FUNDS_MSAT);
	expect(funded.ok, funded.error).to.equal(true);
	settle(pair, 'S', funded);
	expect(sChannel.getFullState().htlcs.size).to.equal(0);
	expect(rChannel.getFullState().htlcs.size).to.equal(0);
	link.log.length = 0;
	sErrors.length = 0;
	rErrors.length = 0;
	return pair;
}

function terms(): {
	voucherAmountsMsat: bigint[];
	minPaymentMsat: bigint;
	settlementDeadline: number;
	voucherExpiry: number;
	feeBaseMsat: number;
	feeProportionalMillionths: number;
} {
	return {
		voucherAmountsMsat: AMOUNTS,
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

function manager(pair: IPair, side: Side): ChannelManager {
	return side === 'S' ? pair.sManager : pair.rManager;
}

function channel(pair: IPair, side: Side): Channel {
	return side === 'S' ? pair.sChannel : pair.rChannel;
}

function errors(pair: IPair, side: Side): string[] {
	return side === 'S' ? pair.sErrors : pair.rErrors;
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
		s: pair.sChannel.getFforEpoch()?.state ?? null,
		r: pair.rChannel.getFforEpoch()?.state ?? null,
		sErrors: pair.sErrors,
		rErrors: pair.rErrors,
		wire: pair.link.log.map((e) => `${e.from}:${e.type}`),
		inFlight: { S: pair.link.inFlight('S'), R: pair.link.inFlight('R') }
	});
}

interface IOffer {
	ok: boolean;
	error?: string;
	id: bigint;
	preimage: Buffer;
}

/** One side asks its manager for an ordinary HTLC, as the node layer does. */
function tryOffer(pair: IPair, from: Side, amountMsat: bigint): IOffer {
	const preimage = crypto.randomBytes(32);
	const id = channel(pair, from).getFullState().localHtlcCounter;
	const res = manager(pair, from).addHtlc(
		pair.channelId,
		amountMsat,
		sha(preimage),
		TIP + 100,
		ONION
	);
	return { ok: res.ok, error: res.error, id, preimage };
}

/**
 * A peer that does not apply the barrier (an older build, or one that
 * misbehaves): its channel lets this one ordinary add through the setup as
 * if it were the epoch's own.
 */
function offerPastBarrier(pair: IPair, from: Side, amountMsat: bigint): IOffer {
	const gate = channel(pair, from) as unknown as { _fforInternalAdd: boolean };
	gate._fforInternalAdd = true;
	try {
		const offered = tryOffer(pair, from, amountMsat);
		expect(offered.ok, offered.error).to.equal(true);
		return offered;
	} finally {
		gate._fforInternalAdd = false;
	}
}

/** The receiver of an HTLC `from` offered fulfils it. */
function settle(pair: IPair, from: Side, offered: IOffer): void {
	const to = from === 'S' ? pair.rManager : pair.sManager;
	const res = to.fulfillHtlc(pair.channelId, offered.id, offered.preimage);
	expect(res.ok, res.error).to.equal(true);
}

/** Deliver one side's next message, which must be of this type. */
function wire(pair: IPair, from: Side, type: number, count = 1): void {
	for (let n = 0; n < count; n++) {
		expect(pair.link.inFlight(from)[0], why(pair)).to.equal(type);
		pair.link.step(from);
	}
}

/**
 * Deliver in a fixed order of senders, skipping a side that has nothing in
 * flight. The orders used below are the ones that go wrong when an
 * ordinary add interleaves with the round; without the add the same order
 * is just one more way to run a clean round.
 */
function deliver(pair: IPair, order: string): void {
	for (const from of order) pair.link.step(from as Side);
}

/**
 * R has sent ff_init and S has answered: ff_accept and the K voucher adds
 * are with R, S's commitment_signed for them is in flight. Both sides are
 * NEGOTIATING.
 */
function toNegotiating(pair: IPair): void {
	pair.link.manual = true;
	const init = pair.rManager.initiateFforEpoch(pair.channelId, terms());
	expect(init.ok, init.error).to.equal(true);
	wire(pair, 'R', MessageType.FF_INIT);
	wire(pair, 'S', MessageType.FF_ACCEPT);
	wire(pair, 'S', MessageType.UPDATE_ADD_HTLC, K);
	expect(pair.link.inFlight('S')).to.deep.equal([
		MessageType.COMMITMENT_SIGNED
	]);
	expect(pair.link.inFlight('R')).to.deep.equal([]);
	expect(record(pair.rChannel).state).to.equal(FforState.NEGOTIATING);
	expect(record(pair.sChannel).state).to.equal(FforState.NEGOTIATING);
	expect(vouchers(pair.rChannel).length).to.equal(K);
	expect(vouchers(pair.sChannel).length).to.equal(K);
}

/**
 * From toNegotiating: S has R's revoke_and_ack and commitment_signed, so
 * the vouchers are irrevocable in both of S's views and S is
 * VOUCHERS_COMMITTED. S's own revoke_and_ack is in flight and R is still
 * NEGOTIATING.
 */
function toVouchersCommittedOnS(pair: IPair): void {
	wire(pair, 'S', MessageType.COMMITMENT_SIGNED);
	wire(pair, 'R', MessageType.REVOKE_AND_ACK);
	wire(pair, 'R', MessageType.COMMITMENT_SIGNED);
	expect(pair.link.inFlight('S')).to.deep.equal([MessageType.REVOKE_AND_ACK]);
	expect(record(pair.sChannel).state).to.equal(FforState.VOUCHERS_COMMITTED);
	expect(record(pair.rChannel).state).to.equal(FforState.NEGOTIATING);
}

/**
 * From toVouchersCommittedOnS: R has S's revoke_and_ack and is
 * VOUCHERS_COMMITTED too, its stfu in flight.
 */
function toVouchersCommittedOnBoth(pair: IPair): void {
	wire(pair, 'S', MessageType.REVOKE_AND_ACK);
	expect(pair.link.inFlight('R')).to.deep.equal([MessageType.STFU]);
	expect(record(pair.rChannel).state).to.equal(FforState.VOUCHERS_COMMITTED);
	expect(record(pair.sChannel).state).to.equal(FforState.VOUCHERS_COMMITTED);
}

/** The epoch is ACTIVE on both sides over exactly the K vouchers. */
function expectActiveOverVouchersOnly(pair: IPair): void {
	expect(record(pair.rChannel).state, why(pair)).to.equal(FforState.ACTIVE);
	expect(record(pair.sChannel).state, why(pair)).to.equal(FforState.ACTIVE);
	expect(pair.rChannel.getFullState().htlcs.size, why(pair)).to.equal(K);
	expect(pair.sChannel.getFullState().htlcs.size, why(pair)).to.equal(K);
	expect(vouchers(pair.rChannel).length).to.equal(K);
	expect(vouchers(pair.sChannel).length).to.equal(K);
	expect(record(pair.rChannel).hAct).to.deep.equal(record(pair.sChannel).hAct);
	expect(pair.rChannel.getState()).to.equal(ChannelState.NORMAL);
	expect(pair.sChannel.getState()).to.equal(ChannelState.NORMAL);
	expect(pair.link.types()).to.not.include(MessageType.ERROR);
	expect(pair.link.types()).to.not.include(MessageType.FF_ABORT);
	expect(pair.link.types()).to.not.include(MessageType.FF_ERROR);
}

/**
 * The add was refused by the barrier and left no trace: one local error
 * from the manager, nothing on the wire, no id consumed, no HTLC added.
 */
function expectRefusedLocally(
	pair: IPair,
	from: Side,
	attempt: () => IOffer,
	state: 'NEGOTIATING' | 'VOUCHERS_COMMITTED'
): void {
	const ch = channel(pair, from);
	const errs = errors(pair, from);
	const before = {
		errors: errs.length,
		inFlight: pair.link.inFlight(from),
		delivered: pair.link.log.length,
		counter: ch.getFullState().localHtlcCounter,
		htlcs: ch.getFullState().htlcs.size
	};
	const offered = attempt();
	expect(offered.ok, `${from}'s add in ${state} was accepted`).to.equal(false);
	expect(offered.error).to.equal(
		`Cannot add HTLC: FFOR epoch is ${state}: no ordinary add while the setup runs`
	);
	// Local: the manager reports it and the channel carries on.
	expect(errs.slice(before.errors)).to.deep.equal([offered.error]);
	errs.length = before.errors;
	expect(pair.link.inFlight(from)).to.deep.equal(before.inFlight);
	expect(pair.link.log.length).to.equal(before.delivered);
	expect(ch.getFullState().localHtlcCounter).to.equal(before.counter);
	expect(ch.getFullState().htlcs.size).to.equal(before.htlcs);
	expect(ch.getState()).to.equal(ChannelState.NORMAL);
	expect(record(ch).state).to.equal(FforState[state]);
}

/** Both predicates the node layer selects a channel by, on one side. */
function admits(pair: IPair, side: Side): { accepts: boolean; set: boolean } {
	const ch = channel(pair, side);
	return {
		accepts: ch.acceptsNewHtlcs(),
		set: ch.canOfferHtlcSet([ORDINARY_MSAT])
	};
}

const SHUT = { accepts: false, set: false };
const OPEN = { accepts: true, set: true };

// ─────────────── Tests ───────────────

describe('FFOR Variant D: the setup admission barrier', function () {
	this.timeout(60_000);

	it("R's ordinary add in NEGOTIATING is refused locally and the epoch still activates", () => {
		const pair = createPair();
		toNegotiating(pair);
		expectRefusedLocally(
			pair,
			'R',
			() => tryOffer(pair, 'R', ORDINARY_MSAT),
			'NEGOTIATING'
		);
		pair.link.flush();
		expectActiveOverVouchersOnly(pair);
		expect(pair.rErrors, why(pair)).to.deep.equal([]);
		expect(pair.sErrors, why(pair)).to.deep.equal([]);
	});

	it("S's ordinary add during the voucher round is refused locally; its voucher adds pass", () => {
		const pair = createPair();
		pair.link.manual = true;
		const init = pair.rManager.initiateFforEpoch(pair.channelId, terms());
		expect(init.ok, init.error).to.equal(true);
		wire(pair, 'R', MessageType.FF_INIT);
		// S answered ff_accept and offered the K vouchers through its own
		// addHtlc, under the same barrier.
		expect(pair.link.inFlight('S')).to.deep.equal([
			MessageType.FF_ACCEPT,
			...AMOUNTS.map(() => MessageType.UPDATE_ADD_HTLC),
			MessageType.COMMITMENT_SIGNED
		]);
		expect(record(pair.sChannel).state).to.equal(FforState.NEGOTIATING);
		expect(vouchers(pair.sChannel).length).to.equal(K);
		expect(pair.sErrors).to.deep.equal([]);
		expectRefusedLocally(
			pair,
			'S',
			() => tryOffer(pair, 'S', ORDINARY_MSAT),
			'NEGOTIATING'
		);
		pair.link.flush();
		expectActiveOverVouchersOnly(pair);
		expect(pair.rErrors, why(pair)).to.deep.equal([]);
		expect(pair.sErrors, why(pair)).to.deep.equal([]);
	});

	it('both sides refuse an ordinary add in VOUCHERS_COMMITTED', () => {
		const pair = createPair();
		toNegotiating(pair);
		toVouchersCommittedOnS(pair);
		// S is not quiescing yet (R's stfu follows S's revoke_and_ack): only
		// the barrier stands between S and an add here.
		expect(pair.sChannel.isQuiescing()).to.equal(false);
		expectRefusedLocally(
			pair,
			'S',
			() => tryOffer(pair, 'S', ORDINARY_MSAT),
			'VOUCHERS_COMMITTED'
		);
		toVouchersCommittedOnBoth(pair);
		// R sent stfu in the step that made it VOUCHERS_COMMITTED, so the
		// quiescence refusal answers first on R; the barrier is behind it.
		expect(pair.rChannel.isQuiescing()).to.equal(true);
		const sent = pair.link.inFlight('R');
		const rAttempt = tryOffer(pair, 'R', ORDINARY_MSAT);
		expect(rAttempt.ok).to.equal(false);
		expect(rAttempt.error).to.equal('Cannot add HTLC: channel is quiescing');
		expect(pair.rErrors).to.deep.equal([rAttempt.error]);
		pair.rErrors.length = 0;
		expect(pair.link.inFlight('R')).to.deep.equal(sent);
		expect(pair.rChannel.getState()).to.equal(ChannelState.NORMAL);
		pair.link.flush();
		expectActiveOverVouchersOnly(pair);
		expect(pair.rErrors, why(pair)).to.deep.equal([]);
		expect(pair.sErrors, why(pair)).to.deep.equal([]);
	});

	it('a dust-sized add is refused the same way and cannot ride into the epoch', () => {
		const pair = createPair();
		toNegotiating(pair);
		// A trimmed HTLC adds no output, so the step 5 count does not see it.
		// R made two dust payments while the voucher round was in flight and
		// S settled the first: the round then closed over the second, which
		// sat under the freeze of an ACTIVE epoch.
		const first = tryOffer(pair, 'R', DUST_MSAT);
		deliver(pair, 'RRSRSR');
		const second = tryOffer(pair, 'R', DUST_MSAT);
		deliver(pair, 'RSR');
		if (first.ok) settle(pair, 'R', first);
		pair.link.flush();
		// Nothing but the vouchers is on the channel when the epoch activates.
		expectActiveOverVouchersOnly(pair);
		for (const attempt of [first, second]) {
			expect(attempt.ok, "R's dust add was accepted").to.equal(false);
			expect(attempt.error).to.include('FFOR epoch is NEGOTIATING');
		}
		expect(pair.rErrors).to.deep.equal([first.error, second.error]);
		expect(pair.sErrors).to.deep.equal([]);

		const other = createPair();
		toNegotiating(other);
		expectRefusedLocally(
			other,
			'S',
			() => tryOffer(other, 'S', DUST_MSAT),
			'NEGOTIATING'
		);
		expectRefusedLocally(
			other,
			'R',
			() => tryOffer(other, 'R', DUST_MSAT),
			'NEGOTIATING'
		);
		toVouchersCommittedOnS(other);
		expectRefusedLocally(
			other,
			'S',
			() => tryOffer(other, 'S', DUST_MSAT),
			'VOUCHERS_COMMITTED'
		);
		other.link.flush();
		expectActiveOverVouchersOnly(other);
	});

	it('acceptsNewHtlcs and canOfferHtlcSet are false through the setup and true again after an abort and after CLOSED', () => {
		const pair = createPair();
		expect(admits(pair, 'R')).to.deep.equal(OPEN);
		expect(admits(pair, 'S')).to.deep.equal(OPEN);
		pair.link.manual = true;
		const init = pair.rManager.initiateFforEpoch(pair.channelId, terms());
		expect(init.ok, init.error).to.equal(true);
		// From the first setup message: R's ff_init has not even arrived.
		expect(record(pair.rChannel).state).to.equal(FforState.NEGOTIATING);
		expect(admits(pair, 'R'), 'R, ff_init sent').to.deep.equal(SHUT);
		expect(pair.sChannel.getFforEpoch()).to.equal(null);
		expect(admits(pair, 'S'), 'S, before ff_init').to.deep.equal(OPEN);
		wire(pair, 'R', MessageType.FF_INIT);
		expect(admits(pair, 'S'), 'S, ff_init taken').to.deep.equal(SHUT);
		wire(pair, 'S', MessageType.FF_ACCEPT);
		wire(pair, 'S', MessageType.UPDATE_ADD_HTLC, K);
		expect(admits(pair, 'R'), 'R, NEGOTIATING').to.deep.equal(SHUT);
		expect(admits(pair, 'S'), 'S, NEGOTIATING').to.deep.equal(SHUT);
		// An empty set asks for nothing and is never refused.
		expect(pair.rChannel.canOfferHtlcSet([])).to.equal(true);
		expect(pair.sChannel.canOfferHtlcSet([])).to.equal(true);
		// The route hint a voucher invoice names S by is built on an ACTIVE
		// epoch only: during the setup the reservation hint is shut as well.
		expect(pair.rChannel.acceptsNewHtlcs(true, true)).to.equal(false);
		expect(pair.sChannel.acceptsNewHtlcs(true, true)).to.equal(false);

		toVouchersCommittedOnS(pair);
		expect(pair.sChannel.isQuiescing()).to.equal(false);
		expect(admits(pair, 'S'), 'S, VOUCHERS_COMMITTED').to.deep.equal(SHUT);
		expect(pair.sChannel.acceptsNewHtlcs(true, true)).to.equal(false);
		toVouchersCommittedOnBoth(pair);
		expect(admits(pair, 'R'), 'R, VOUCHERS_COMMITTED').to.deep.equal(SHUT);
		expect(pair.rChannel.acceptsNewHtlcs(true, true)).to.equal(false);

		// ACTIVE is the freeze of section 7.5.5, unchanged: shut for ordinary
		// traffic, open to the reservation hint.
		pair.link.flush();
		expectActiveOverVouchersOnly(pair);
		expect(admits(pair, 'R'), 'R, ACTIVE').to.deep.equal(SHUT);
		expect(admits(pair, 'S'), 'S, ACTIVE').to.deep.equal(SHUT);
		expect(pair.rChannel.acceptsNewHtlcs(true, true)).to.equal(true);
		expect(pair.sChannel.acceptsNewHtlcs(true, true)).to.equal(true);

		// CLOSED lifts it.
		expect(pair.rManager.closeFforEpoch(pair.channelId).ok).to.equal(true);
		pair.link.flush();
		expect(record(pair.rChannel).state, why(pair)).to.equal(FforState.CLOSED);
		expect(record(pair.sChannel).state, why(pair)).to.equal(FforState.CLOSED);
		expect(admits(pair, 'R'), 'R, CLOSED').to.deep.equal(OPEN);
		expect(admits(pair, 'S'), 'S, CLOSED').to.deep.equal(OPEN);
		for (const from of ['R', 'S'] as const) {
			const offered = tryOffer(pair, from, ORDINARY_MSAT);
			expect(offered.ok, offered.error).to.equal(true);
			pair.link.flush();
			settle(pair, from, offered);
			pair.link.flush();
		}
		expect(pair.rChannel.getFullState().htlcs.size).to.equal(0);
		expect(pair.sChannel.getFullState().htlcs.size).to.equal(0);
		expect(pair.rErrors, why(pair)).to.deep.equal([]);
		expect(pair.sErrors, why(pair)).to.deep.equal([]);

		// ABORTED lifts it, from either setup state.
		for (const at of ['NEGOTIATING', 'VOUCHERS_COMMITTED'] as const) {
			const aborted = createPair();
			toNegotiating(aborted);
			if (at === 'VOUCHERS_COMMITTED') {
				toVouchersCommittedOnS(aborted);
				toVouchersCommittedOnBoth(aborted);
			}
			expect(admits(aborted, 'R'), `R, ${at}`).to.deep.equal(SHUT);
			expect(admits(aborted, 'S'), `S, ${at}`).to.deep.equal(SHUT);
			const abort = aborted.rManager.abortFforEpoch(aborted.channelId);
			expect(abort.ok, abort.error).to.equal(true);
			// On the side that aborts, at once.
			expect(admits(aborted, 'R'), `R, aborting in ${at}`).to.deep.equal(OPEN);
			aborted.link.flush();
			expect(record(aborted.rChannel).state).to.equal(FforState.ABORTED);
			expect(record(aborted.sChannel).state).to.equal(FforState.ABORTED);
			expect(admits(aborted, 'R'), `R, aborted in ${at}`).to.deep.equal(OPEN);
			expect(admits(aborted, 'S'), `S, aborted in ${at}`).to.deep.equal(OPEN);
		}
	});

	it('an abort lifts the barrier at once, and the voucher unwind completes beside the new adds', () => {
		const pair = createPair();
		const rBalance = pair.rChannel.getFullState().localBalanceMsat;
		toNegotiating(pair);
		expectRefusedLocally(
			pair,
			'R',
			() => tryOffer(pair, 'R', ORDINARY_MSAT),
			'NEGOTIATING'
		);
		// R gives the setup up with the voucher round still open: the
		// vouchers are parked but not committed, so the unwind is owed.
		const abort = pair.rManager.abortFforEpoch(pair.channelId);
		expect(abort.ok, abort.error).to.equal(true);
		expect(record(pair.rChannel).state).to.equal(FforState.ABORTED);
		expect(record(pair.rChannel).unwindOwed).to.equal(true);
		expect(vouchers(pair.rChannel).length).to.equal(K);
		// ABORTED on R, before S has even heard of it: R may add again.
		const fromR = tryOffer(pair, 'R', ORDINARY_MSAT);
		expect(fromR.ok, fromR.error).to.equal(true);
		wire(pair, 'S', MessageType.COMMITMENT_SIGNED);
		wire(pair, 'R', MessageType.FF_ABORT);
		expect(record(pair.sChannel).state).to.equal(FforState.ABORTED);
		const fromS = tryOffer(pair, 'S', ORDINARY_MSAT);
		expect(fromS.ok, fromS.error).to.equal(true);
		pair.link.flush();

		// The unwind ran: every voucher failed back to S, by R, and only the
		// two ordinary HTLCs are left.
		const fails = pair.link.log.filter(
			(e) => e.type === MessageType.UPDATE_FAIL_HTLC
		);
		expect(fails.length, why(pair)).to.equal(K);
		expect(fails.every((e) => e.from === 'R')).to.equal(true);
		expect(vouchers(pair.rChannel)).to.deep.equal([]);
		expect(vouchers(pair.sChannel)).to.deep.equal([]);
		expect(record(pair.rChannel).unwindOwed).to.equal(false);
		for (const ch of [pair.rChannel, pair.sChannel]) {
			const htlcs = ch.getFullState().htlcs;
			expect(htlcs.size, why(pair)).to.equal(2);
			for (const e of htlcs.values()) {
				expect(e.state).to.equal(HtlcState.COMMITTED);
			}
			expect(ch.getState()).to.equal(ChannelState.NORMAL);
		}
		settle(pair, 'R', fromR);
		settle(pair, 'S', fromS);
		pair.link.flush();
		expect(pair.rChannel.getFullState().htlcs.size, why(pair)).to.equal(0);
		expect(pair.sChannel.getFullState().htlcs.size, why(pair)).to.equal(0);
		// Each paid the other the same amount: back where they started.
		expect(pair.rChannel.getFullState().localBalanceMsat).to.equal(rBalance);
		expect(
			pair.sChannel.getFullState().localBalanceMsat +
				pair.rChannel.getFullState().localBalanceMsat
		).to.equal(FUNDING_SATOSHIS * 1000n);
		expect(pair.link.types()).to.not.include(MessageType.ERROR);
		expect(pair.rErrors, why(pair)).to.deep.equal([]);
		// S's one error is the notice of R's abort.
		expect(pair.sErrors.length, why(pair)).to.equal(1);
		expect(pair.sErrors[0]).to.include('FFOR epoch aborted by peer');

		// The setup timeout is S's way out, and lifts it the same way.
		const timed = createPair();
		toNegotiating(timed);
		expect(admits(timed, 'S')).to.deep.equal(SHUT);
		expect(timed.sManager.fforSetupTimeout(timed.channelId).ok).to.equal(true);
		expect(record(timed.sChannel).state).to.equal(FforState.ABORTED);
		expect(record(timed.sChannel).abortReason).to.equal(
			FforAbortReason.TIMEOUT
		);
		const late = tryOffer(timed, 'S', ORDINARY_MSAT);
		expect(late.ok, late.error).to.equal(true);
		timed.link.flush();
		expect(record(timed.rChannel).state).to.equal(FforState.ABORTED);
		expect(vouchers(timed.rChannel)).to.deep.equal([]);
		expect(vouchers(timed.sChannel)).to.deep.equal([]);
		settle(timed, 'S', late);
		timed.link.flush();
		expect(timed.rChannel.getFullState().htlcs.size, why(timed)).to.equal(0);
		expect(timed.sChannel.getFullState().htlcs.size, why(timed)).to.equal(0);
		expect(timed.link.types()).to.not.include(MessageType.ERROR);
	});

	// Issue #1289 items 3 to 5: each needed an ordinary add of R's own inside
	// the setup. The add is attempted at the point that used to go wrong and
	// the round is then delivered in the order that used to go wrong.

	it('an R add ahead of ff_accept can no longer move the commitment number the accept binds (item 5)', () => {
		const pair = createPair();
		pair.link.manual = true;
		const init = pair.rManager.initiateFforEpoch(pair.channelId, terms());
		expect(init.ok, init.error).to.equal(true);
		expect(pair.link.inFlight('R')).to.deep.equal([MessageType.FF_INIT]);
		// ff_init is on its way. An add here was signed before ff_accept
		// came back, and R then refused the accept: "ff_accept n0 2 != 3".
		const attempt = tryOffer(pair, 'R', DUST_MSAT);
		pair.link.flush();
		expectActiveOverVouchersOnly(pair);
		expect(attempt.ok, "R's add ahead of ff_accept was accepted").to.equal(
			false
		);
		expect(attempt.error).to.include('FFOR epoch is NEGOTIATING');
		expect(pair.rErrors).to.deep.equal([attempt.error]);
		expect(pair.sErrors).to.deep.equal([]);
	});

	it('R cannot declare VOUCHERS_COMMITTED a message early behind an add of its own (item 3)', () => {
		const pair = createPair();
		toNegotiating(pair);
		wire(pair, 'S', MessageType.COMMITMENT_SIGNED);
		// R has answered the voucher commitment. An add here was covered by
		// R's next commitment_signed, and R took S's revoke_and_ack for it
		// as the end of the round while S's commitment_signed for R's own
		// view was still in flight: ff_activate then bound a stale H_commit.
		const attempt = tryOffer(pair, 'R', DUST_MSAT);
		deliver(pair, 'RRSRRSRSRSR');
		pair.link.flush();
		expectActiveOverVouchersOnly(pair);
		expect(attempt.ok, "R's add inside the round was accepted").to.equal(false);
		expect(attempt.error).to.include('FFOR epoch is NEGOTIATING');
		expect(pair.rErrors).to.deep.equal([attempt.error]);
		expect(pair.sErrors).to.deep.equal([]);
	});

	it('the setup cannot stall on the removal of an HTLC R added inside the round (item 4)', () => {
		const pair = createPair();
		toNegotiating(pair);
		wire(pair, 'S', MessageType.COMMITMENT_SIGNED);
		const attempt = tryOffer(pair, 'R', DUST_MSAT);
		deliver(pair, 'RRSRRS');
		// S fulfilled the interleaved HTLC as R's stfu arrived, answered
		// stfu with the removal still open on R, and R dropped that stfu:
		// "Cannot accept STFU: pending HTLCs exist". Nothing moved again
		// until the setup timer.
		if (attempt.ok) settle(pair, 'R', attempt);
		deliver(pair, 'RSRSSRRSS');
		pair.link.flush();
		expectActiveOverVouchersOnly(pair);
		expect(attempt.ok, "R's add inside the round was accepted").to.equal(false);
		expect(pair.rErrors).to.deep.equal([attempt.error]);
		expect(pair.sErrors).to.deep.equal([]);
	});

	// What remains: the barrier is local. A peer that does not apply it is
	// not refused on the wire during the setup, and an add of its own keeps
	// the outcome it had before.

	it("a peer's ordinary add during the setup is not refused: the round fails its count and aborts", () => {
		const pair = createPair();
		const rBalance = pair.rChannel.getFullState().localBalanceMsat;
		toNegotiating(pair);
		const stray = offerPastBarrier(pair, 'R', ORDINARY_MSAT);
		pair.link.flush();
		// Section 9.5.1 step 5: four outputs for a book of three. No wire
		// error, no channel failure: abort reason 5 and the stock unwind.
		expect(record(pair.rChannel).state, why(pair)).to.equal(FforState.ABORTED);
		expect(record(pair.sChannel).state, why(pair)).to.equal(FforState.ABORTED);
		expect(record(pair.rChannel).abortReason).to.equal(
			FforAbortReason.VOUCHER_ROUND_FAILED
		);
		expect(pair.link.types()).to.not.include(MessageType.ERROR);
		expect(pair.rChannel.getState()).to.equal(ChannelState.NORMAL);
		expect(pair.sChannel.getState()).to.equal(ChannelState.NORMAL);
		expect(vouchers(pair.rChannel)).to.deep.equal([]);
		expect(vouchers(pair.sChannel)).to.deep.equal([]);
		// The stray HTLC is an ordinary one and settles as one.
		expect(pair.sChannel.getFullState().htlcs.size, why(pair)).to.equal(1);
		settle(pair, 'R', stray);
		pair.link.flush();
		expect(pair.rChannel.getFullState().htlcs.size, why(pair)).to.equal(0);
		expect(pair.sChannel.getFullState().htlcs.size, why(pair)).to.equal(0);
		expect(pair.rChannel.getFullState().localBalanceMsat).to.equal(
			rBalance - ORDINARY_MSAT
		);
	});

	it("a peer's dust add during the setup is not refused, and the barrier blocks no settle of it", () => {
		const pair = createPair();
		const rBalance = pair.rChannel.getFullState().localBalanceMsat;
		toNegotiating(pair);
		// The two dust payments of the case above, from a peer without the
		// barrier. S takes both adds: no wire error, no channel failure.
		const first = offerPastBarrier(pair, 'R', DUST_MSAT);
		deliver(pair, 'RRSRSR');
		const second = offerPastBarrier(pair, 'R', DUST_MSAT);
		deliver(pair, 'RSR');
		// The first is irrevocably committed and the setup still runs on
		// both sides. S's fulfil, and the commitments and revocations that
		// remove the HTLC, all pass the barrier.
		const live = [FforState.NEGOTIATING, FforState.VOUCHERS_COMMITTED];
		expect(live).to.include(record(pair.sChannel).state);
		expect(live).to.include(record(pair.rChannel).state);
		expect(admits(pair, 'S')).to.deep.equal(SHUT);
		expect(admits(pair, 'R')).to.deep.equal(SHUT);
		settle(pair, 'R', first);
		pair.link.flush();
		expect(pair.rErrors, why(pair)).to.deep.equal([]);
		expect(pair.sErrors, why(pair)).to.deep.equal([]);
		expect(pair.link.types()).to.include(MessageType.UPDATE_FULFILL_HTLC);
		expect(pair.link.types()).to.not.include(MessageType.ERROR);
		for (const ch of [pair.sChannel, pair.rChannel]) {
			expect(ch.getState()).to.equal(ChannelState.NORMAL);
			expect(ch.getFullState().htlcs.size, why(pair)).to.equal(K + 1);
			expect(vouchers(ch).length).to.equal(K);
		}
		expect(pair.sChannel.getFullState().remoteBalanceMsat).to.equal(
			rBalance - 2n * DUST_MSAT
		);
		// What remains of issue item 1 against such a peer: step 5 counts
		// outputs, so the round closes over the second dust HTLC and it sits
		// under the freeze of an ACTIVE epoch.
		expect(record(pair.sChannel).state, why(pair)).to.equal(FforState.ACTIVE);
		expect(record(pair.rChannel).state, why(pair)).to.equal(FforState.ACTIVE);
		const riding = pair.sChannel
			.getFullState()
			.htlcs.get(`received-${second.id}`);
		expect(riding?.state).to.equal(HtlcState.COMMITTED);
		expect(riding?.fforVoucher).to.not.equal(true);
		const frozen = pair.sManager.fulfillHtlc(
			pair.channelId,
			second.id,
			second.preimage
		);
		expect(frozen.ok).to.equal(false);
		expect(frozen.error).to.include('FFOR epoch is ACTIVE');
	});
});
