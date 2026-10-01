/**
 * FFOR Variant D: the ff_activate recheck of the book charges the voucher
 * value once (specs/ffor-offline-receive.md sections 7.5.3, 7.6, 8).
 *
 * The book's requirements are checked at ff_accept and rechecked at
 * ff_activate. Between the two the voucher round runs, and S's K adds take
 * the budget out of S's balance. The recheck must judge the book against the
 * balance S held before the round: judged against the balance after it, the
 * budget is charged twice and S needs about 2 * budget + reserve + fees to
 * activate an epoch it already funded.
 *
 * Two ChannelManagers in loopback, peer ids = node ids, every message on a
 * wire log (the ffor-variant-d-setup harness). Each channel here gives S
 * enough for the book once (budget + reserve + the fee-spike buffer) and
 * not twice.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import { Channel } from '../../src/lightning/channel/channel';
import {
	calculateCommitmentFee,
	getCommitmentFeeRate
} from '../../src/lightning/channel/commitment-builder';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { MessageType } from '../../src/lightning/message/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { ANCHOR_TOTAL_SAT } from '../../src/lightning/ffor/amounts';
import {
	FF_INIT_TYPE,
	FforAbortReason,
	FforState,
	FforVariant,
	IFforEpochRecord
} from '../../src/lightning/ffor/types';
import {
	decodeFforAbortMessage,
	encodeFforInitUnsigned,
	signFforMessage
} from '../../src/lightning/ffor/messages';

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
	const seed = sha(`ffor-recheck-seed-${seedId}`);
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

interface IWireEntry {
	from: 'S' | 'R';
	type: number;
	payload: Buffer;
}

/** A loopback link with a wire log and a drop filter. */
class Link {
	readonly log: IWireEntry[] = [];
	/** Return true to drop the message (it is kept in `dropped`). */
	drop: ((from: 'S' | 'R', type: number, payload: Buffer) => boolean) | null =
		null;
	readonly dropped: IWireEntry[] = [];

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
		if (this.drop && this.drop(from, type, payload)) {
			this.dropped.push({ from, type, payload });
			return;
		}
		this.log.push({ from, type, payload });
		if (from === 'S') this.r.handleMessage(this.sPub, type, payload);
		else this.s.handleMessage(this.rPub, type, payload);
	}

	types(): number[] {
		return this.log.map((e) => e.type);
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
}

const FUNDING_SATOSHIS = 1_000_000n;
const RESERVE_SAT = DEFAULT_CHANNEL_CONFIG.channelReserveSatoshis;
const T_EXP = 800_000;
const D_DEADLINE = 798_992;
const TIP = 795_000;

let pairSeed = 0;

/**
 * A 1,000,000 sat anchor channel at tip 795000. By default S opens and
 * holds all of it; with `funder: 'R'`, R opens and pushes `sBalanceSat` to S.
 */
function createPair(
	opts: { funder?: 'S' | 'R'; sBalanceSat?: bigint } = {}
): IPair {
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

	let sChannel: Channel;
	let rChannel: Channel;
	let channelId: Buffer;
	if (opts.funder === 'R') {
		rChannel = rManager.openChannel(
			sPub,
			FUNDING_SATOSHIS,
			(opts.sBalanceSat ?? 0n) * 1000n
		);
		rManager.createFunding(
			rChannel,
			crypto.randomBytes(32),
			0,
			crypto.randomBytes(64)
		);
		channelId = rChannel.getChannelId()!;
		sChannel = sManager.getChannelsByPeer(rPub)[0];
	} else {
		sChannel = sManager.openChannel(rPub, FUNDING_SATOSHIS);
		sManager.createFunding(
			sChannel,
			crypto.randomBytes(32),
			0,
			crypto.randomBytes(64)
		);
		channelId = sChannel.getChannelId()!;
		rChannel = rManager.getChannelsByPeer(sPub)[0];
	}
	sManager.handleFundingConfirmed(channelId);
	rManager.handleFundingConfirmed(channelId);
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
		sConfig,
		rConfig,
		sErrors,
		rErrors
	};
}

function terms(amounts: bigint[]): {
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
function voucherCount(ch: Channel): number {
	let n = 0;
	for (const e of ch.getFullState().htlcs.values()) {
		if (e.fforVoucher === true) n++;
	}
	return n;
}

/** Every ff_abort on the wire, as [sender, reason, text]. */
function aborts(pair: IPair): Array<['S' | 'R', FforAbortReason, string]> {
	return pair.link.log
		.filter((e) => e.type === MessageType.FF_ABORT)
		.map((e) => {
			const m = decodeFforAbortMessage(e.payload);
			return [e.from, m.reason, m.data.toString('utf8')];
		});
}

/** Run setup through the real messages and require ACTIVE on both sides. */
function activate(pair: IPair, amounts: bigint[]): void {
	const res = pair.rManager.initiateFforEpoch(pair.channelId, terms(amounts));
	expect(res.ok, res.error).to.equal(true);
	const why = (): string =>
		JSON.stringify({
			sErrors: pair.sErrors,
			rErrors: pair.rErrors,
			aborts: aborts(pair).map(([from, reason, text]) => ({
				from,
				reason,
				text
			})),
			wire: pair.link.types()
		});
	expect(record(pair.sChannel).state, why()).to.equal(FforState.ACTIVE);
	expect(record(pair.rChannel).state, why()).to.equal(FforState.ACTIVE);
	expect(aborts(pair), why()).to.deep.equal([]);
	expect(voucherCount(pair.sChannel)).to.equal(amounts.length);
	expect(voucherCount(pair.rChannel)).to.equal(amounts.length);
}

/** The section 7.6 fee terms for K vouchers on this channel, in sat. */
function feeTerms(
	pair: IPair,
	K: number
): { feerate: number; frozen: bigint; spike: bigint } {
	const feerate = getCommitmentFeeRate(pair.sChannel.getFullState());
	return {
		feerate,
		frozen: calculateCommitmentFee(feerate, K, true, false),
		spike: calculateCommitmentFee(2 * feerate, K, true, false)
	};
}

/** An ff_init R signed itself, past R's own precheck of the book. */
function signedInit(pair: IPair, amounts: bigint[]): Buffer {
	const t = terms(amounts);
	return signFforMessage(
		FF_INIT_TYPE,
		encodeFforInitUnsigned({
			channelId: pair.channelId,
			epochId: crypto.randomBytes(32),
			variant: FforVariant.D,
			budgetMsat: amounts.reduce((a, b) => a + b, 0n),
			maxPayments: amounts.length,
			minPaymentMsat: t.minPaymentMsat,
			settlementDeadline: t.settlementDeadline,
			voucherExpiry: t.voucherExpiry,
			feeBaseMsat: t.feeBaseMsat,
			feeProportionalMillionths: t.feeProportionalMillionths,
			escapeGranularityMsat: 0n,
			rPerCommitmentPoints: [],
			voucherAmountsMsat: amounts
		}),
		pair.rConfig.nodePrivateKey
	);
}

// ─────────────── Tests ───────────────

describe('FFOR Variant D: the activation recheck charges the book once', function () {
	this.timeout(30_000);

	it('S funds: a book S covers once, but not twice, activates (reserve check)', () => {
		const pair = createPair();
		// Two 300,000 sat vouchers: budget 600,000 sat of S's 1,000,000.
		const amounts = [300_000_000n, 300_000_000n];
		const budgetSat = 600_000n;
		const sBalanceSat = pair.sChannel.getFullState().localBalanceMsat / 1000n;
		const fee = feeTerms(pair, amounts.length);
		expect(sBalanceSat).to.equal(FUNDING_SATOSHIS);
		// Once: budget + reserve + the fee-spike buffer + anchors fit.
		expect(
			sBalanceSat >= budgetSat + RESERVE_SAT + fee.spike + ANCHOR_TOTAL_SAT
		).to.be.true;
		// Twice: they do not, and after the round S holds less than
		// budget + reserve.
		expect(sBalanceSat < 2n * budgetSat + RESERVE_SAT).to.be.true;

		activate(pair, amounts);
		expect(pair.sChannel.getFullState().localBalanceMsat / 1000n).to.equal(
			sBalanceSat - budgetSat
		);
		expect(pair.sErrors).to.deep.equal([]);
		expect(pair.rErrors).to.deep.equal([]);
	});

	it('S funds: a book whose second charge only breaks the funder fee check activates', () => {
		const pair = createPair();
		// Budget 495,000 sat: after the round S holds 505,000 sat, exactly
		// budget + reserve, so a second charge passes the reserve check and
		// leaves nothing above the reserve for the commitment fee.
		const amounts = [247_500_000n, 247_500_000n];
		const budgetSat = 495_000n;
		const sBalanceSat = pair.sChannel.getFullState().localBalanceMsat / 1000n;
		const fee = feeTerms(pair, amounts.length);
		expect(sBalanceSat - budgetSat).to.equal(budgetSat + RESERVE_SAT);
		expect(
			sBalanceSat - 2n * budgetSat - RESERVE_SAT < fee.frozen + ANCHOR_TOTAL_SAT
		).to.be.true;

		activate(pair, amounts);
		expect(pair.sErrors).to.deep.equal([]);
		expect(pair.rErrors).to.deep.equal([]);
	});

	it('R funds: a book S covers once, but not twice, activates', () => {
		// R opens and pushes 400,000 sat to S; budget 300,000 sat.
		const pair = createPair({ funder: 'R', sBalanceSat: 400_000n });
		const amounts = [150_000_000n, 150_000_000n];
		const budgetSat = 300_000n;
		const sBalanceSat = pair.sChannel.getFullState().localBalanceMsat / 1000n;
		expect(sBalanceSat).to.equal(400_000n);
		expect(sBalanceSat >= budgetSat + RESERVE_SAT).to.be.true;
		expect(sBalanceSat < 2n * budgetSat + RESERVE_SAT).to.be.true;

		activate(pair, amounts);
		expect(pair.sChannel.getFullState().localBalanceMsat / 1000n).to.equal(
			sBalanceSat - budgetSat
		);
		expect(pair.sErrors).to.deep.equal([]);
		expect(pair.rErrors).to.deep.equal([]);
	});

	it('the largest book the voucher round can carry activates', () => {
		const pair = createPair();
		const K = 2;
		const feerate = feeTerms(pair, K).feerate;
		// addHtlc keeps the funder's cost at twice the rate with room for one
		// more HTLC, so the K-th add needs fee(2 * feerate, K + 1) + anchors
		// above the reserve: the tightest book the round completes.
		const headroomSat =
			calculateCommitmentFee(2 * feerate, K + 1, true, false) +
			ANCHOR_TOTAL_SAT;
		const budgetSat = FUNDING_SATOSHIS - RESERVE_SAT - headroomSat;
		const first = (budgetSat / 2n) * 1000n;
		const amounts = [first, budgetSat * 1000n - first];

		activate(pair, amounts);
		expect(pair.sChannel.getFullState().localBalanceMsat / 1000n).to.equal(
			RESERVE_SAT + headroomSat
		);
	});

	it('a book S cannot afford once is still refused at ff_init', () => {
		const pair = createPair();
		const K = 2;
		const fee = feeTerms(pair, K);
		const split = (budgetSat: bigint): bigint[] => {
			const first = (budgetSat / 2n) * 1000n;
			return [first, budgetSat * 1000n - first];
		};
		// One sat past the fee-spike limit, and one sat past the reserve.
		const pastSpike = split(
			FUNDING_SATOSHIS - RESERVE_SAT - fee.spike - ANCHOR_TOTAL_SAT + 1n
		);
		const pastReserve = split(FUNDING_SATOSHIS - RESERVE_SAT + 1n);
		const cases: Array<[bigint[], string]> = [
			[pastSpike, 'funder cannot cover the fee-spike buffer'],
			[pastReserve, 'S cannot cover budget_msat plus its channel reserve']
		];
		for (const [amounts, text] of cases) {
			// R's own precheck refuses it before anything is sent.
			const res = pair.rManager.initiateFforEpoch(
				pair.channelId,
				terms(amounts)
			);
			expect(res.ok).to.be.false;
			expect(res.error).to.include(text);
			expect(pair.rChannel.getFforEpoch()).to.equal(null);
			expect(pair.link.log.length).to.equal(0);

			// And S refuses the same book from an R that sent it anyway:
			// ff_abort alone (reason 2), no voucher added.
			pair.sManager.handleMessage(
				pair.rPub,
				MessageType.FF_INIT,
				signedInit(pair, amounts)
			);
			const sent = aborts(pair);
			expect(sent.length).to.equal(1);
			expect(sent[0][0]).to.equal('S');
			expect(sent[0][1]).to.equal(FforAbortReason.TERMS_REFUSED);
			expect(sent[0][2]).to.include(text);
			expect(pair.link.types()).to.deep.equal([MessageType.FF_ABORT]);
			expect(pair.sChannel.getFforEpoch()).to.equal(null);
			expect(pair.sChannel.getFullState().htlcs.size).to.equal(0);
			expect(pair.sChannel.getFullState().localBalanceMsat).to.equal(
				FUNDING_SATOSHIS * 1000n
			);
			pair.link.log.length = 0;
		}
	});

	it('the recheck still refuses a shortfall that appears after the round', () => {
		const pair = createPair();
		const amounts = [300_000_000n, 300_000_000n];
		// Hold ff_activate so the channel can change under the committed round.
		pair.link.drop = (from, type): boolean =>
			from === 'R' && type === MessageType.FF_ACTIVATE;
		const res = pair.rManager.initiateFforEpoch(pair.channelId, terms(amounts));
		expect(res.ok, res.error).to.equal(true);
		expect(record(pair.sChannel).state).to.equal(FforState.VOUCHERS_COMMITTED);
		expect(pair.link.dropped.length).to.equal(1);
		const sState = pair.sChannel.getFullState();
		expect(sState.localBalanceMsat).to.equal(400_000_000n);

		// Raise the reserve S must keep past what the round left it: the
		// 1,000,000 sat S held no longer covers 600,000 + 400,001. The
		// reserve is on no commitment, so every transcript hash still matches
		// and only the book recheck can refuse.
		sState.remoteConfig.channelReserveSatoshis = 400_001n;
		pair.link.drop = null;
		pair.sManager.handleMessage(
			pair.rPub,
			MessageType.FF_ACTIVATE,
			pair.link.dropped[0].payload
		);
		const sent = aborts(pair);
		expect(sent.length).to.equal(1);
		expect(sent[0][0]).to.equal('S');
		expect(sent[0][1]).to.equal(FforAbortReason.BOOK_MISMATCH);
		expect(sent[0][2]).to.equal(
			'S cannot cover budget_msat plus its channel reserve'
		);
		expect(record(pair.sChannel).state).to.equal(FforState.ABORTED);
		expect(record(pair.rChannel).state).to.equal(FforState.ABORTED);
	});
});
