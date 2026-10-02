/**
 * FFOR concurrent receive, version 1: legal channel traffic
 * (specs/CONCURRENT-RECEIVE.md sections 1.2, 3, 4, 6 and 7).
 *
 * A concurrent epoch carries ordinary adds, fulfils and fails and their
 * commitment rounds while ACTIVE and DRAINING, beside the vouchers, which
 * every commitment keeps. update_fee, update_blockheight, a new stfu,
 * splice and cooperative close stay refused. A voucher is fulfilled only by
 * the epoch itself and failed only under the final close. CLOSED means
 * every voucher is resolved, whatever ordinary HTLCs are still in flight.
 * A baseline epoch behaves exactly as it did.
 *
 * Three layers:
 *  1. the decision table itself, every row and column for both roles and
 *     both profiles, asked of the guard directly;
 *  2. every call site, with real messages: a refusal of ours is a local
 *     error, the peer's is a wire failure;
 *  3. real ordinary payments in both directions through full commitment
 *     rounds beside live vouchers, with exact balances, checking after
 *     every round that both commitments on both sides still carry every
 *     unresolved voucher.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { Channel } from '../../src/lightning/channel/channel';
import {
	ChannelAction,
	ChannelActionType
} from '../../src/lightning/channel/channel-actions';
import {
	ChannelState,
	HtlcDirection,
	HtlcState
} from '../../src/lightning/channel/types';
import { MessageType } from '../../src/lightning/message/types';
import {
	encodeUpdateAddHtlcMessage,
	encodeUpdateBlockheightMessage,
	encodeUpdateFailHtlcMessage,
	encodeUpdateFailMalformedHtlcMessage,
	encodeUpdateFeeMessage,
	encodeUpdateFulfillHtlcMessage
} from '../../src/lightning/message/channel-update';
import { encodeShutdownMessage } from '../../src/lightning/message/channel-close';
import { encodeStfuMessage } from '../../src/lightning/message/stfu';
import { encodeSpliceMessage } from '../../src/lightning/message/splice';
import { FforState } from '../../src/lightning/ffor/types';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { PaymentStatus } from '../../src/lightning/node/types';
import { IHtlcEntry } from '../../src/lightning/channel/types';
import {
	activateWorld,
	createConcurrentWorld
} from './helpers/ffor-concurrent-world';
import {
	AMOUNTS as WORLD_AMOUNTS,
	IWorld,
	pay as payInvoice,
	record as nodeRecord,
	TIP as WORLD_TIP
} from './helpers/ffor-world';
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
	manager,
	offer,
	ONION,
	ordinaryHtlcs,
	other,
	pay,
	record,
	restart,
	settleSlot,
	sha,
	Side,
	T_EXP,
	terms,
	TIP,
	vouchers,
	why
} from './helpers/ffor-concurrent-pair';

// ─────────────── The guard, asked directly ───────────────

type Kind =
	| 'add'
	| 'settle'
	| 'fee'
	| 'blockheight'
	| 'commit'
	| 'stfu'
	| 'shutdown'
	| 'splice';

interface ICtx {
	origin: 'local' | 'peer';
	settle?: { id: bigint; direction: HtlcDirection; op: 'fulfill' | 'fail' };
}

interface IGuarded {
	_fforUpdateRefusal(kind: Kind, ctx: ICtx): string | null;
	_fforLocalAddRefusal(): string | null;
	_fforInternalSettle: boolean;
	_fforInternalAdd: boolean;
}

function guard(ch: Channel): IGuarded {
	return ch as unknown as IGuarded;
}

const STATES = [
	FforState.NEGOTIATING,
	FforState.VOUCHERS_COMMITTED,
	FforState.ACTIVATING,
	FforState.ACTIVE,
	FforState.DRAINING,
	FforState.CLOSED,
	FforState.ABORTED
];

/**
 * One row of the table: an operation, and for each state in STATES order
 * whether it passes ('.') or is refused ('X').
 */
interface IRow {
	name: string;
	kind: Kind;
	origin: 'local' | 'peer';
	/** A settle: which HTLC it names and how. `voucher` picks slot 1's id. */
	settle?: {
		voucher: boolean;
		direction: HtlcDirection;
		op: 'fulfill' | 'fail';
	};
	/** Run as the epoch's own drain, redemption or unwind. */
	internal?: boolean;
	expect: string;
}

const PLAIN_KINDS: Kind[] = [
	'fee',
	'blockheight',
	'shutdown',
	'stfu',
	'splice'
];

/** The rows that name no voucher, for either role. */
function ordinaryRows(
	add: string,
	settle: string,
	commit: string,
	rest: string
): IRow[] {
	const rows: IRow[] = [];
	for (const origin of ['local', 'peer'] as const) {
		rows.push({ name: `add, ${origin}`, kind: 'add', origin, expect: add });
		for (const op of ['fulfill', 'fail'] as const) {
			// A settle of ours names an HTLC we received, the peer's one we
			// offered. A voucher's NUMBER in the direction the vouchers do not
			// run names an ordinary HTLC.
			rows.push({
				name: `settle, ordinary id, ${origin} ${op}`,
				kind: 'settle',
				origin,
				settle: {
					voucher: false,
					direction:
						origin === 'local' ? HtlcDirection.RECEIVED : HtlcDirection.OFFERED,
					op
				},
				expect: settle
			});
		}
		rows.push({
			name: `commit, ${origin}`,
			kind: 'commit',
			origin,
			expect: commit
		});
		for (const kind of PLAIN_KINDS) {
			rows.push({ name: `${kind}, ${origin}`, kind, origin, expect: rest });
		}
	}
	return rows;
}

//                                    NEG VC ACTIVATING ACTIVE DRAINING CLOSED ABORTED
const CONCURRENT_ORDINARY = ordinaryRows(
	'..X....',
	'..X....',
	'..X....',
	'..XXX..'
);

/** Concurrent, R: its own settle of a voucher (received on R). */
const CONCURRENT_R_VOUCHER: IRow[] = [
	{
		name: 'voucher, local fulfil, from outside the epoch',
		kind: 'settle',
		origin: 'local',
		settle: { voucher: true, direction: HtlcDirection.RECEIVED, op: 'fulfill' },
		expect: 'XXXXX.X'
	},
	{
		name: 'voucher, local fulfil, by the epoch',
		kind: 'settle',
		origin: 'local',
		settle: { voucher: true, direction: HtlcDirection.RECEIVED, op: 'fulfill' },
		internal: true,
		expect: 'XXX....'
	},
	{
		name: 'voucher, local fail, from outside the epoch',
		kind: 'settle',
		origin: 'local',
		settle: { voucher: true, direction: HtlcDirection.RECEIVED, op: 'fail' },
		expect: 'XXXXX.X'
	},
	{
		// DRAINING here is slot 1 with its bit clear and no preimage held;
		// the other DRAINING cases are below.
		name: 'voucher, local fail, by the epoch',
		kind: 'settle',
		origin: 'local',
		settle: { voucher: true, direction: HtlcDirection.RECEIVED, op: 'fail' },
		internal: true,
		expect: 'XXXX...'
	},
	{
		// The peer's settles name HTLCs R offered: never a voucher on R.
		name: "voucher's number, peer fulfil of an HTLC R offered",
		kind: 'settle',
		origin: 'peer',
		settle: { voucher: true, direction: HtlcDirection.OFFERED, op: 'fulfill' },
		expect: '..X....'
	},
	{
		name: "voucher's number, peer fail of an HTLC R offered",
		kind: 'settle',
		origin: 'peer',
		settle: { voucher: true, direction: HtlcDirection.OFFERED, op: 'fail' },
		expect: '..X....'
	}
];

/** Concurrent, S: the peer's settle of a voucher (offered on S). */
const CONCURRENT_S_VOUCHER: IRow[] = [
	{
		name: 'voucher, peer fulfil',
		kind: 'settle',
		origin: 'peer',
		settle: { voucher: true, direction: HtlcDirection.OFFERED, op: 'fulfill' },
		expect: 'XXX....'
	},
	{
		name: 'voucher, peer fail',
		kind: 'settle',
		origin: 'peer',
		settle: { voucher: true, direction: HtlcDirection.OFFERED, op: 'fail' },
		expect: '..XX...'
	},
	{
		// S cannot remove an HTLC it offered off chain at all.
		name: 'voucher, a settle of our own',
		kind: 'settle',
		origin: 'local',
		settle: { voucher: true, direction: HtlcDirection.OFFERED, op: 'fail' },
		expect: 'XXXXX.X'
	},
	{
		// S's own settles name HTLCs it received: never a voucher on S.
		name: "voucher's number, local fulfil of an HTLC S received",
		kind: 'settle',
		origin: 'local',
		settle: { voucher: true, direction: HtlcDirection.RECEIVED, op: 'fulfill' },
		expect: '..X....'
	},
	{
		name: "voucher's number, local fail of an HTLC S received",
		kind: 'settle',
		origin: 'local',
		settle: { voucher: true, direction: HtlcDirection.RECEIVED, op: 'fail' },
		expect: '..X....'
	}
];

// Baseline (base spec section 7.5.5), as it stood before the extension:
// frozen from ACTIVATING, and DRAINING admits only the vouchers' own
// settles and the commitment rounds.
const BASELINE_ORDINARY = ordinaryRows(
	'..XXX..',
	'..XXX..',
	'..XX...',
	'..XXX..'
);

const BASELINE_R_VOUCHER: IRow[] = [
	{
		name: 'voucher, local fulfil, from outside the epoch',
		kind: 'settle',
		origin: 'local',
		settle: { voucher: true, direction: HtlcDirection.RECEIVED, op: 'fulfill' },
		expect: 'XXXXX.X'
	},
	{
		name: 'voucher, local fulfil, by the epoch',
		kind: 'settle',
		origin: 'local',
		settle: { voucher: true, direction: HtlcDirection.RECEIVED, op: 'fulfill' },
		internal: true,
		expect: '..XX...'
	},
	{
		name: 'voucher, local fail, from outside the epoch',
		kind: 'settle',
		origin: 'local',
		settle: { voucher: true, direction: HtlcDirection.RECEIVED, op: 'fail' },
		expect: 'XXXXX.X'
	},
	{
		name: 'voucher, local fail, by the epoch',
		kind: 'settle',
		origin: 'local',
		settle: { voucher: true, direction: HtlcDirection.RECEIVED, op: 'fail' },
		internal: true,
		expect: '..XX...'
	},
	{
		name: "voucher's number, peer fulfil of an HTLC R offered",
		kind: 'settle',
		origin: 'peer',
		settle: { voucher: true, direction: HtlcDirection.OFFERED, op: 'fulfill' },
		expect: '..XXX..'
	},
	{
		name: "voucher's number, peer fail of an HTLC R offered",
		kind: 'settle',
		origin: 'peer',
		settle: { voucher: true, direction: HtlcDirection.OFFERED, op: 'fail' },
		expect: '..XXX..'
	}
];

const BASELINE_S_VOUCHER: IRow[] = [
	{
		name: 'voucher, peer fulfil',
		kind: 'settle',
		origin: 'peer',
		settle: { voucher: true, direction: HtlcDirection.OFFERED, op: 'fulfill' },
		expect: '..XX...'
	},
	{
		name: 'voucher, peer fail',
		kind: 'settle',
		origin: 'peer',
		settle: { voucher: true, direction: HtlcDirection.OFFERED, op: 'fail' },
		expect: '..XX...'
	},
	{
		name: "voucher's number, local fulfil of an HTLC S received",
		kind: 'settle',
		origin: 'local',
		settle: { voucher: true, direction: HtlcDirection.RECEIVED, op: 'fulfill' },
		expect: '..XXX..'
	},
	{
		name: "voucher's number, local fail of an HTLC S received",
		kind: 'settle',
		origin: 'local',
		settle: { voucher: true, direction: HtlcDirection.RECEIVED, op: 'fail' },
		expect: '..XXX..'
	}
];

/** An ACTIVE epoch whose record a test then moves through the states. */
function tablePair(concurrent: boolean): IPair {
	const pair = createPair({ pushSat: 200_000n });
	activate(pair, AMOUNTS, concurrent);
	return pair;
}

function ask(pair: IPair, side: Side, row: IRow, state: FforState): boolean {
	const ch = channel(pair, side);
	const f = record(ch);
	const saved = f.state;
	const savedBitmap = f.settledBitmap;
	f.state = state;
	// DRAINING follows a close acknowledgement; this one settled nothing.
	if (state === FforState.DRAINING) f.settledBitmap = Buffer.from([0]);
	guard(ch)._fforInternalSettle = row.internal === true;
	try {
		const base = f.sHtlcIdBase!;
		// A number no voucher carries, in either direction.
		const id = row.settle?.voucher === false ? base + 1_000n : base;
		const refusal = guard(ch)._fforUpdateRefusal(row.kind, {
			origin: row.origin,
			...(row.settle
				? {
						settle: {
							id,
							direction: row.settle.direction,
							op: row.settle.op
						}
				  }
				: {})
		});
		return refusal === null;
	} finally {
		guard(ch)._fforInternalSettle = false;
		f.state = saved;
		f.settledBitmap = savedBitmap;
	}
}

function runTable(pair: IPair, side: Side, rows: IRow[]): void {
	for (const row of rows) {
		expect(row.expect.length, row.name).to.equal(STATES.length);
		const got = STATES.map((state) =>
			ask(pair, side, row, state) ? '.' : 'X'
		).join('');
		expect(got, `${side}: ${row.name}`).to.equal(row.expect);
	}
}

// ─────────────── Real messages ───────────────

const SHUTDOWN_SCRIPT = Buffer.from('0014' + '11'.repeat(20), 'hex');
const BADONION_INVALID_HMAC = 0x8000 | 0x4000 | 5;

function isError(actions: ChannelAction[]): string | null {
	const err = actions.find((a) => a.type === ChannelActionType.ERROR);
	return err && err.type === ChannelActionType.ERROR ? err.message : null;
}

function sends(actions: ChannelAction[]): number[] {
	return actions
		.filter((a) => a.type === ChannelActionType.SEND_MESSAGE)
		.map((a) => (a as { messageType: number }).messageType);
}

/** A concurrent pair in ACTIVE, R holding a balance of its own. */
function activePair(): IPair {
	const pair = createPair({ pushSat: 200_000n });
	activate(pair, AMOUNTS, true);
	pair.link.log.length = 0;
	return pair;
}

/**
 * A concurrent pair in DRAINING on both sides: slot 2 was settled, and R's
 * drain (a fulfil for 2, fails for 1 and 3, the commitment_signed) is held
 * on the wire, so every voucher is still in both commitments.
 */
function drainingPair(): IPair {
	const pair = activePair();
	settleSlot(pair, 2);
	pair.link.holdAt = (from, type): boolean =>
		from === 'R' &&
		(type === MessageType.UPDATE_FULFILL_HTLC ||
			type === MessageType.UPDATE_FAIL_HTLC);
	const res = pair.rManager.closeFforEpoch(pair.channelId);
	expect(res.ok, res.error).to.equal(true);
	pair.link.holdAt = null;
	expect(record(pair.sChannel).state, why(pair)).to.equal(FforState.DRAINING);
	expect(record(pair.rChannel).state, why(pair)).to.equal(FforState.DRAINING);
	pair.link.log.length = 0;
	return pair;
}

const S_AFTER_BOOK =
	(FUNDING_SATOSHIS - 200_000n) * 1000n - AMOUNTS.reduce((a, b) => a + b, 0n);
const R_START = 200_000_000n;
const BUDGET_MSAT = AMOUNTS.reduce((a, b) => a + b, 0n);

describe('FFOR concurrent receive: traffic (CONCURRENT-RECEIVE.md 3, 4, 6, 7)', function () {
	this.timeout(120_000);

	describe('the decision table', () => {
		it('concurrent epoch, R: every kind in every state', () => {
			const pair = tablePair(true);
			runTable(pair, 'R', [...CONCURRENT_ORDINARY, ...CONCURRENT_R_VOUCHER]);
		});

		it('concurrent epoch, S: every kind in every state', () => {
			const pair = tablePair(true);
			runTable(pair, 'S', [...CONCURRENT_ORDINARY, ...CONCURRENT_S_VOUCHER]);
		});

		it('concurrent epoch, R in DRAINING: a voucher is failed only when the ack marks it unsettled and no preimage is held', () => {
			const pair = tablePair(true);
			const ch = pair.rChannel;
			const f = record(ch);
			const base = f.sHtlcIdBase!;
			const fail = (k: number): string | null =>
				guard(ch)._fforUpdateRefusal('settle', {
					origin: 'local',
					settle: {
						id: base + BigInt(k - 1),
						direction: HtlcDirection.RECEIVED,
						op: 'fail'
					}
				});
			f.state = FforState.DRAINING;
			guard(ch)._fforInternalSettle = true;
			// No acknowledgement at all: nothing authorizes a fail.
			f.settledBitmap = null;
			expect(fail(1)).to.match(/does not mark it unsettled/);
			// Slot 2 settled, 1 and 3 not.
			f.settledBitmap = Buffer.from([0b010]);
			expect(fail(1)).to.equal(null);
			expect(fail(2)).to.match(/does not mark it unsettled/);
			expect(fail(3)).to.equal(null);
			// A preimage held for a slot the ack calls unsettled: never failed.
			f.knownPreimages[2] = crypto.randomBytes(32);
			expect(fail(3)).to.match(/its preimage is held/);
			expect(fail(1)).to.equal(null);
			// And never from outside the epoch, whatever the bitmap says.
			guard(ch)._fforInternalSettle = false;
			expect(fail(1)).to.match(/is parked/);
		});

		it('concurrent epoch: our own add is held by a capability hold or a dispute, the peer add is not', () => {
			for (const side of ['S', 'R'] as const) {
				for (const state of [FforState.ACTIVE, FforState.DRAINING]) {
					const pair = tablePair(true);
					const ch = channel(pair, side);
					const f = record(ch);
					f.state = state;
					const local = (): string | null =>
						guard(ch)._fforUpdateRefusal('add', { origin: 'local' });
					const peer = (): string | null =>
						guard(ch)._fforUpdateRefusal('add', { origin: 'peer' });
					expect(local()).to.equal(null);
					ch.setFforCapabilities(false);
					expect(local()).to.match(
						/no new add while the peer did not advertise/
					);
					expect(peer()).to.equal(null);
					ch.setFforCapabilities(true);
					expect(local()).to.equal(null);
					f.activationMismatch = true;
					expect(local()).to.match(/no new add while the epoch is in dispute/);
					expect(peer()).to.equal(null);
					// Neither holds a settle or a commitment round.
					ch.setFforCapabilities(false);
					for (const origin of ['local', 'peer'] as const) {
						expect(guard(ch)._fforUpdateRefusal('commit', { origin })).to.equal(
							null
						);
						expect(
							guard(ch)._fforUpdateRefusal('settle', {
								origin,
								settle: {
									id: 5_000n,
									direction:
										origin === 'local'
											? HtlcDirection.RECEIVED
											: HtlcDirection.OFFERED,
									op: 'fulfill'
								}
							})
						).to.equal(null);
					}
				}
			}
		});

		it('concurrent epoch: the setup barrier still refuses our own add before ACTIVATING', () => {
			for (const side of ['S', 'R'] as const) {
				const pair = tablePair(true);
				const ch = channel(pair, side);
				const f = record(ch);
				const expected: Array<[FforState, boolean]> = [
					[FforState.NEGOTIATING, true],
					[FforState.VOUCHERS_COMMITTED, true],
					[FforState.ACTIVATING, true],
					[FforState.ACTIVE, false],
					[FforState.DRAINING, false],
					[FforState.CLOSED, false],
					[FforState.ABORTED, false]
				];
				for (const [state, refused] of expected) {
					f.state = state;
					expect(
						guard(ch)._fforLocalAddRefusal() !== null,
						`${side} ${FforState[state]}`
					).to.equal(refused);
				}
				// The epoch's own voucher adds pass the barrier while NEGOTIATING.
				f.state = FforState.NEGOTIATING;
				guard(ch)._fforInternalAdd = true;
				expect(guard(ch)._fforLocalAddRefusal()).to.equal(null);
				guard(ch)._fforInternalAdd = false;
			}
		});

		it('baseline epoch, R: nothing moved', () => {
			const pair = tablePair(false);
			runTable(pair, 'R', [...BASELINE_ORDINARY, ...BASELINE_R_VOUCHER]);
		});

		it('baseline epoch, S: nothing moved', () => {
			const pair = tablePair(false);
			runTable(pair, 'S', [...BASELINE_ORDINARY, ...BASELINE_S_VOUCHER]);
		});

		it('baseline epoch: a capability hold changes nothing', () => {
			const pair = tablePair(false);
			pair.sChannel.setFforCapabilities(false);
			pair.rChannel.setFforCapabilities(false);
			runTable(pair, 'R', [...BASELINE_ORDINARY, ...BASELINE_R_VOUCHER]);
			runTable(pair, 'S', [...BASELINE_ORDINARY, ...BASELINE_S_VOUCHER]);
			expect(pair.sChannel.fforAdmissionHold()).to.equal(null);
			expect(pair.sChannel.fforSettlementRefusal(1, TIP)).to.equal(null);
		});

		it('no epoch at all: nothing is refused', () => {
			const pair = createPair({ pushSat: 200_000n });
			for (const side of ['S', 'R'] as const) {
				const ch = channel(pair, side);
				for (const kind of ['add', 'commit', ...PLAIN_KINDS] as Kind[]) {
					for (const origin of ['local', 'peer'] as const) {
						expect(guard(ch)._fforUpdateRefusal(kind, { origin })).to.equal(
							null
						);
					}
				}
			}
		});
	});

	describe('every call site, concurrent epoch', () => {
		for (const state of ['ACTIVE', 'DRAINING'] as const) {
			const pairIn = state === 'ACTIVE' ? activePair : drainingPair;

			it(`${state}: fee, quiescence, splice and cooperative close of ours are refused locally, nothing is sent`, () => {
				for (const side of ['S', 'R'] as const) {
					const pair = pairIn();
					const ch = channel(pair, side);
					const cases: Array<[string, ChannelAction[]]> = [
						// Only the opener, S here, ever sends update_fee.
						...(side === 'S'
							? [
									['update_fee', ch.updateFee(3000)] as [
										string,
										ChannelAction[]
									]
							  ]
							: []),
						['shutdown', ch.initiateShutdown(SHUTDOWN_SCRIPT)],
						['stfu', ch.initiateQuiescence()],
						['splice', ch.initiateSplice(10_000n, 1000)]
					];
					for (const [name, actions] of cases) {
						expect(isError(actions), `${side} ${name}`).to.match(
							new RegExp(
								`FFOR epoch is ${state}: no .* while the voucher book is live`
							)
						);
						expect(sends(actions), `${side} ${name}`).to.deep.equal([]);
					}
					expect(ch.spliceBusyReason()).to.match(/voucher book is live/);
					expect(ch.getState()).to.equal(ChannelState.NORMAL);
					expect(ch.isQuiescing()).to.equal(false);
					expect(record(ch).state).to.equal(FforState[state]);
					expect(vouchers(ch).length).to.equal(AMOUNTS.length);
				}
			});

			it(`${state}: update_fee, update_blockheight, stfu, splice_init and shutdown from the peer fail the channel on the wire`, () => {
				const probe = pairIn();
				const forbidden = (
					pair: IPair
				): Array<{ name: string; type: number; payload: Buffer }> => [
					{
						name: 'update_fee',
						type: MessageType.UPDATE_FEE,
						payload: encodeUpdateFeeMessage({
							channelId: pair.channelId,
							feeratePerKw: 3000
						})
					},
					{
						name: 'update_blockheight',
						type: MessageType.UPDATE_BLOCKHEIGHT,
						payload: encodeUpdateBlockheightMessage({
							channelId: pair.channelId,
							blockheight: TIP + 1
						})
					},
					{
						name: 'stfu',
						type: MessageType.STFU,
						payload: encodeStfuMessage({
							channelId: pair.channelId,
							initiator: true
						})
					},
					{
						name: 'splice_init',
						type: MessageType.SPLICE,
						payload: encodeSpliceMessage({
							channelId: pair.channelId,
							fundingPubkey: pair.sConfig.localBasepoints.fundingPubkey,
							relativeSatoshis: 10_000n,
							fundingFeeratePerkw: 1000,
							locktime: 0
						})
					},
					{
						name: 'shutdown',
						type: MessageType.SHUTDOWN,
						payload: encodeShutdownMessage({
							channelId: pair.channelId,
							scriptPubkey: SHUTDOWN_SCRIPT
						})
					}
				];
				for (const { name } of forbidden(probe)) {
					for (const into of ['S', 'R'] as const) {
						const pair = pairIn();
						const c = forbidden(pair).find((m) => m.name === name)!;
						const target = channel(pair, into);
						const before = target.getFullState().htlcs.size;
						manager(pair, into).handleMessage(
							into === 'S' ? pair.rPub : pair.sPub,
							c.type,
							c.payload
						);
						const label = `${name} into ${into} in ${state}`;
						expect(target.getState(), label).to.equal(ChannelState.ERRORED);
						// R's direction is held in DRAINING: its error is in flight.
						expect(
							pair.link.log.some(
								(e) => e.from === into && e.type === MessageType.ERROR
							) || pair.link.inFlight(into).includes(MessageType.ERROR),
							`${label}: wire error`
						).to.equal(true);
						// The failure removed nothing: the vouchers are in the
						// commitment the side still holds.
						expect(record(target).state, label).to.equal(FforState[state]);
						expect(target.getFullState().htlcs.size, label).to.equal(before);
						expect(vouchers(target).length, label).to.equal(AMOUNTS.length);
					}
				}
			});

			it(`${state}: a voucher is parked against every settle from outside the epoch`, () => {
				const pair = pairIn();
				// R learns slot 1's real preimage the way a payer's receipt gives
				// it. In ACTIVE that redeems nothing in PR 1; in DRAINING the
				// drain already ran.
				const f = record(pair.rChannel);
				const base = f.sHtlcIdBase!;
				const sRecord = record(pair.sChannel);
				const before = vouchers(pair.rChannel).map(
					([key, st]) => `${key}:${st}`
				);
				for (let k = 1; k <= AMOUNTS.length; k++) {
					const id = base + BigInt(k - 1);
					const fulfil = pair.rChannel.fulfillHtlc(
						id,
						sRecord.preimages[k - 1]
					);
					expect(isError(fulfil), `fulfil ${k}`).to.match(/is parked/);
					expect(sends(fulfil)).to.deep.equal([]);
					const fail = pair.rChannel.failHtlc(id, Buffer.alloc(292));
					expect(isError(fail), `fail ${k}`).to.match(/is parked/);
					expect(sends(fail)).to.deep.equal([]);
					const malformed = pair.rChannel.failMalformedHtlc(
						id,
						sha(ONION),
						BADONION_INVALID_HMAC
					);
					expect(isError(malformed), `malformed ${k}`).to.match(/is parked/);
					expect(sends(malformed)).to.deep.equal([]);
				}
				expect(
					vouchers(pair.rChannel).map(([key, st]) => `${key}:${st}`)
				).to.deep.equal(before);
				expect(pair.rChannel.getState()).to.equal(ChannelState.NORMAL);
			});
		}

		it('ACTIVE: a voucher fail from the peer fails the channel and removes nothing', () => {
			for (const how of ['update_fail_htlc', 'update_fail_malformed_htlc']) {
				const pair = activePair();
				const id = record(pair.sChannel).sHtlcIdBase!;
				const payload =
					how === 'update_fail_htlc'
						? encodeUpdateFailHtlcMessage({
								channelId: pair.channelId,
								id,
								reason: Buffer.alloc(292)
						  })
						: encodeUpdateFailMalformedHtlcMessage({
								channelId: pair.channelId,
								id,
								sha256OfOnion: sha(ONION),
								failureCode: BADONION_INVALID_HMAC
						  });
				pair.sManager.handleMessage(
					pair.rPub,
					how === 'update_fail_htlc'
						? MessageType.UPDATE_FAIL_HTLC
						: MessageType.UPDATE_FAIL_MALFORMED_HTLC,
					payload
				);
				expect(pair.sChannel.getState(), how).to.equal(ChannelState.ERRORED);
				expect(
					pair.link.log.some(
						(e) => e.from === 'S' && e.type === MessageType.ERROR
					)
				).to.equal(true);
				expect(pair.sErrors.join('|')).to.match(
					/failed while the epoch is ACTIVE/
				);
				// S's book and commitment still carry every voucher, so R's
				// claim stays enforceable on chain.
				expect(vouchers(pair.sChannel)).to.deep.equal(
					AMOUNTS.map((_, i) => [
						`offered-${id + BigInt(i)}`,
						HtlcState.COMMITTED
					])
				);
				expect(record(pair.sChannel).state).to.equal(FforState.ACTIVE);
			}
		});

		it('DRAINING: S takes a fail of a voucher its acknowledgement marked settled, and reports it', () => {
			const pair = activePair();
			settleSlot(pair, 2);
			// R loses what the acknowledgement taught it about slot 2 and has
			// its drain fail the slot, which no conforming R does.
			const r = pair.rChannel as unknown as {
				_fforDrain(f: unknown): ChannelAction[];
			};
			const original = r._fforDrain.bind(pair.rChannel);
			r._fforDrain = (f): ChannelAction[] => {
				const rec = record(pair.rChannel);
				rec.knownPreimages[1] = null;
				rec.settledBitmap = Buffer.from([0]);
				return original(f);
			};
			const closed = pair.rManager.closeFforEpoch(pair.channelId);
			r._fforDrain = original;
			expect(closed.ok, closed.error).to.equal(true);
			expect(pair.sErrors).to.deep.equal([
				'FFOR: the receiver failed voucher 2, which the close acknowledgement marks settled'
			]);
			// Accepted all the same: the channel is open, the epoch closed, and
			// the value R gave up is back with S.
			expect(pair.sChannel.getState()).to.equal(ChannelState.NORMAL);
			expect(pair.link.types()).to.not.include(MessageType.ERROR);
			expect(record(pair.sChannel).state, why(pair)).to.equal(FforState.CLOSED);
			expect(balances(pair).s).to.equal(S_AFTER_BOOK + BUDGET_MSAT);
			expect(balances(pair).r).to.equal(R_START);
		});

		it('before ACTIVE: a voucher fulfil from the peer is a violation, a fail is the unwind', () => {
			// NEGOTIATING on S, vouchers committed on S's side of the round.
			const pair = createPair({ pushSat: 200_000n });
			pair.link.holdAt = (from, type): boolean =>
				from === 'R' && type === MessageType.STFU;
			const res = pair.rManager.initiateFforEpoch(
				pair.channelId,
				terms(AMOUNTS, { concurrent: true })
			);
			expect(res.ok, res.error).to.equal(true);
			pair.link.holdAt = null;
			expect(record(pair.sChannel).state).to.equal(
				FforState.VOUCHERS_COMMITTED
			);
			expect(record(pair.sChannel).concurrentVersion).to.equal(1);
			const s = record(pair.sChannel);
			pair.sManager.handleMessage(
				pair.rPub,
				MessageType.UPDATE_FULFILL_HTLC,
				encodeUpdateFulfillHtlcMessage({
					channelId: pair.channelId,
					id: s.sHtlcIdBase!,
					paymentPreimage: s.preimages[0]
				})
			);
			expect(pair.sChannel.getState()).to.equal(ChannelState.ERRORED);
			expect(pair.sErrors.join('|')).to.match(
				/fulfilled before the epoch is ACTIVE/
			);
			expect(vouchers(pair.sChannel).length).to.equal(AMOUNTS.length);
		});

		it('a baseline epoch still fails the channel on the same ordinary add a concurrent one takes', () => {
			for (const concurrent of [true, false]) {
				const pair = createPair({ pushSat: 200_000n });
				activate(pair, AMOUNTS, concurrent);
				pair.link.log.length = 0;
				const add = encodeUpdateAddHtlcMessage({
					channelId: pair.channelId,
					id: 0n,
					amountMsat: 5_000_000n,
					paymentHash: crypto.randomBytes(32),
					cltvExpiry: TIP + 100,
					onionRoutingPacket: ONION
				});
				pair.sManager.handleMessage(
					pair.rPub,
					MessageType.UPDATE_ADD_HTLC,
					add
				);
				if (concurrent) {
					expect(pair.sChannel.getState()).to.equal(ChannelState.NORMAL);
					expect(
						pair.sChannel.getFullState().htlcs.get('received-0')?.fforVoucher
					).to.not.equal(true);
					expect(pair.link.types()).to.not.include(MessageType.ERROR);
				} else {
					expect(pair.sChannel.getState()).to.equal(ChannelState.ERRORED);
					expect(pair.link.types()).to.include(MessageType.ERROR);
				}
			}
		});
	});

	describe('ordinary payments beside live vouchers, ACTIVE', () => {
		const ALL = [1, 2, 3];

		it('S pays R and R pays S through full rounds; balances are exact and every commitment keeps the vouchers', () => {
			const pair = activePair();
			expect(balances(pair)).to.deep.equal({
				s: S_AFTER_BOOK,
				r: R_START,
				sViewOfR: R_START,
				rViewOfS: S_AFTER_BOOK
			});
			expectVouchersCarried(pair, ALL, 'at activation');
			const hCommit = Buffer.from(record(pair.rChannel).hCommit!);
			const hAct = Buffer.from(record(pair.rChannel).hAct!);

			pay(pair, 'S', 30_000_000n);
			expectHealthy(pair, 'S pays R');
			expectVouchersCarried(pair, ALL, 'after S pays R');
			expect(balances(pair)).to.deep.equal({
				s: S_AFTER_BOOK - 30_000_000n,
				r: R_START + 30_000_000n,
				sViewOfR: R_START + 30_000_000n,
				rViewOfS: S_AFTER_BOOK - 30_000_000n
			});

			pay(pair, 'R', 12_345_678n);
			expectHealthy(pair, 'R pays S');
			expectVouchersCarried(pair, ALL, 'after R pays S');
			expect(balances(pair)).to.deep.equal({
				s: S_AFTER_BOOK - 30_000_000n + 12_345_678n,
				r: R_START + 30_000_000n - 12_345_678n,
				sViewOfR: R_START + 30_000_000n - 12_345_678n,
				rViewOfS: S_AFTER_BOOK - 30_000_000n + 12_345_678n
			});

			// The commitments moved on; the book identity did not (section 2).
			for (const ch of [pair.sChannel, pair.rChannel]) {
				expect(record(ch).state).to.equal(FforState.ACTIVE);
				expect(record(ch).hCommit!.equals(hCommit)).to.equal(true);
				expect(record(ch).hAct!.equals(hAct)).to.equal(true);
				expect(vouchers(ch).map(([, st]) => st)).to.deep.equal([
					HtlcState.COMMITTED,
					HtlcState.COMMITTED,
					HtlcState.COMMITTED
				]);
				expect(ordinaryHtlcs(ch)).to.deep.equal([]);
			}
			expect(
				Number(pair.sChannel.getFullState().localCommitmentNumber)
			).to.be.greaterThan(Number(record(pair.sChannel).sCommitmentNumber!) + 1);
		});

		it('an ordinary HTLC is failed, and failed as malformed, in each direction; nothing moves', () => {
			const pair = activePair();
			const start = balances(pair);
			for (const from of ['S', 'R'] as const) {
				const to = other(from);
				const a = offer(pair, from, 5_000_000n);
				expect(a.result.ok, a.result.error).to.equal(true);
				expectVouchersCarried(pair, ALL, `${from} offered`);
				const fail = manager(pair, to).failHtlc(
					pair.channelId,
					a.id,
					Buffer.alloc(292)
				);
				expect(fail.ok, fail.error).to.equal(true);
				expectHealthy(pair, `${to} failed`);
				expectVouchersCarried(pair, ALL, `${to} failed`);
				expect(pair.events[from].failed).to.include(a.id);

				const b = offer(pair, from, 4_000_000n);
				expect(b.result.ok, b.result.error).to.equal(true);
				const malformed = manager(pair, to).failMalformedHtlc(
					pair.channelId,
					b.id,
					sha(ONION),
					BADONION_INVALID_HMAC
				);
				expect(malformed.ok, malformed.error).to.equal(true);
				expectHealthy(pair, `${to} failed as malformed`);
				expectVouchersCarried(pair, ALL, `${to} failed as malformed`);
				expect(balances(pair)).to.deep.equal(start);
			}
			expect(ordinaryHtlcs(pair.sChannel)).to.deep.equal([]);
			expect(ordinaryHtlcs(pair.rChannel)).to.deep.equal([]);
		});

		it('an ordinary received HTLC is dispatched to the node; a voucher never is', () => {
			const pair = activePair();
			pair.events.R.forwarded.length = 0;
			pair.events.S.forwarded.length = 0;
			const a = offer(pair, 'S', 5_000_000n);
			expect(a.result.ok, a.result.error).to.equal(true);
			const b = offer(pair, 'R', 2_000_000n);
			expect(b.result.ok, b.result.error).to.equal(true);
			// S's ordinary add follows the K vouchers in S's id space.
			expect(a.id).to.equal(record(pair.sChannel).sHtlcIdBase! + 3n);
			expect(pair.events.R.forwarded).to.deep.equal([a.id]);
			expect(pair.events.S.forwarded).to.deep.equal([b.id]);
		});

		it('adds that cross on the wire in both directions settle beside the vouchers', () => {
			const pair = activePair();
			// R's add and its commitment_signed are in flight when S adds.
			pair.link.holdAt = (from): boolean => from === 'R';
			const fromR = offer(pair, 'R', 7_000_000n);
			expect(fromR.result.ok, fromR.result.error).to.equal(true);
			pair.link.holdAt = (from): boolean => from === 'S';
			const fromS = offer(pair, 'S', 9_000_000n);
			expect(fromS.result.ok, fromS.result.error).to.equal(true);
			pair.link.holdAt = null;
			expectVouchersCarried(pair, ALL, 'both adds in flight', false);
			pair.link.release('R');
			pair.link.release('S');
			expectHealthy(pair, 'crossed adds');
			expectVouchersCarried(pair, ALL, 'crossed adds committed');
			const s = manager(pair, 'S').fulfillHtlc(
				pair.channelId,
				fromR.id,
				fromR.preimage
			);
			expect(s.ok, s.error).to.equal(true);
			const r = manager(pair, 'R').fulfillHtlc(
				pair.channelId,
				fromS.id,
				fromS.preimage
			);
			expect(r.ok, r.error).to.equal(true);
			expectHealthy(pair, 'crossed adds settled');
			expectVouchersCarried(pair, ALL, 'crossed adds settled');
			expect(balances(pair)).to.deep.equal({
				s: S_AFTER_BOOK + 7_000_000n - 9_000_000n,
				r: R_START - 7_000_000n + 9_000_000n,
				sViewOfR: R_START - 7_000_000n + 9_000_000n,
				rViewOfS: S_AFTER_BOOK + 7_000_000n - 9_000_000n
			});
		});

		for (const how of ['fulfils', 'fails', 'fails as malformed'] as const) {
			it(`S ${how} an HTLC R offered under a voucher's id; the voucher is not touched`, () => {
				const pair = activePair();
				const base = record(pair.rChannel).sHtlcIdBase!;
				// R's own counter starts where S's did: its first three HTLCs
				// carry the vouchers' numbers.
				const a = offer(pair, 'R', 6_000_000n);
				expect(a.result.ok, a.result.error).to.equal(true);
				expect(a.id).to.equal(base);
				const rHtlcs = pair.rChannel.getFullState().htlcs;
				expect(rHtlcs.get(`received-${a.id}`)?.fforVoucher).to.equal(true);
				expect(rHtlcs.get(`offered-${a.id}`)?.fforVoucher).to.not.equal(true);
				const res =
					how === 'fulfils'
						? pair.sManager.fulfillHtlc(pair.channelId, a.id, a.preimage)
						: how === 'fails'
						? pair.sManager.failHtlc(pair.channelId, a.id, Buffer.alloc(292))
						: pair.sManager.failMalformedHtlc(
								pair.channelId,
								a.id,
								sha(ONION),
								BADONION_INVALID_HMAC
						  );
				expect(res.ok, res.error).to.equal(true);
				expectHealthy(pair, how);
				expectVouchersCarried(pair, ALL, how);
				const paid = how === 'fulfils' ? 6_000_000n : 0n;
				expect(balances(pair).r).to.equal(R_START - paid);
				expect(balances(pair).s).to.equal(S_AFTER_BOOK + paid);
				expect(ordinaryHtlcs(pair.rChannel)).to.deep.equal([]);
				expect(vouchers(pair.rChannel).length).to.equal(3);
				expect(vouchers(pair.sChannel).length).to.equal(3);
			});
		}

		it('S takes a valid voucher fulfil while ACTIVE, credits R in full, and the book stays open', () => {
			// PR 2 gives R the caller; here the epoch's own settle is driven by
			// hand, with the preimage R would have verified.
			const pair = activePair();
			const base = record(pair.rChannel).sHtlcIdBase!;
			const t2 = record(pair.sChannel).preimages[1];
			const learned = pair.rManager.fforAddPreimage(pair.channelId, t2);
			expect(learned.ok, learned.error).to.equal(true);
			// Knowing the preimage redeems nothing by itself in PR 1.
			expect(vouchers(pair.rChannel).map(([, st]) => st)).to.deep.equal([
				HtlcState.COMMITTED,
				HtlcState.COMMITTED,
				HtlcState.COMMITTED
			]);
			guard(pair.rChannel)._fforInternalSettle = true;
			const res = pair.rManager.fulfillHtlc(pair.channelId, base + 1n, t2);
			guard(pair.rChannel)._fforInternalSettle = false;
			expect(res.ok, res.error).to.equal(true);
			expectHealthy(pair, 'voucher 2 redeemed');
			// Voucher 2 left both commitments and R was credited exactly d_2.
			expect(vouchers(pair.rChannel).map(([key]) => key)).to.deep.equal([
				`received-${base}`,
				`received-${base + 2n}`
			]);
			expect(vouchers(pair.sChannel).map(([key]) => key)).to.deep.equal([
				`offered-${base}`,
				`offered-${base + 2n}`
			]);
			expect(balances(pair)).to.deep.equal({
				s: S_AFTER_BOOK,
				r: R_START + AMOUNTS[1],
				sViewOfR: R_START + AMOUNTS[1],
				rViewOfS: S_AFTER_BOOK
			});
			expectVouchersCarried(pair, [1, 3], 'after the redemption');
			for (const ch of [pair.sChannel, pair.rChannel]) {
				expect(record(ch).state).to.equal(FforState.ACTIVE);
			}
			// Ordinary traffic continues beside the two that remain, and R can
			// spend what the voucher credited.
			pay(pair, 'S', 10_000_000n);
			pay(pair, 'R', R_START + AMOUNTS[1] - 100_000_000n);
			expectHealthy(pair, 'traffic after the redemption');
			expectVouchersCarried(pair, [1, 3], 'traffic after the redemption');
			// The redeemed id is not a voucher again: S's ids have moved on,
			// and an add that repeats the tuple is an ordinary HTLC.
			pair.rManager.handleMessage(
				pair.sPub,
				MessageType.UPDATE_ADD_HTLC,
				encodeUpdateAddHtlcMessage({
					channelId: pair.channelId,
					id: base + 1n,
					amountMsat: AMOUNTS[1],
					paymentHash: record(pair.rChannel).paymentHashes[1],
					cltvExpiry: T_EXP,
					onionRoutingPacket: ONION
				})
			);
			const again = pair.rChannel
				.getFullState()
				.htlcs.get(`received-${base + 1n}`);
			expect(again, 'the add was taken').to.exist;
			expect(again!.fforVoucher).to.not.equal(true);
			expect(vouchers(pair.rChannel).length).to.equal(2);
		});

		it('R cannot fail a voucher while ACTIVE even as the epoch', () => {
			const pair = activePair();
			const base = record(pair.rChannel).sHtlcIdBase!;
			guard(pair.rChannel)._fforInternalSettle = true;
			const fail = pair.rChannel.failHtlc(base, Buffer.alloc(292));
			guard(pair.rChannel)._fforInternalSettle = false;
			expect(isError(fail)).to.match(/only the final close authorizes a fail/);
			expect(sends(fail)).to.deep.equal([]);
			expect(vouchers(pair.rChannel).map(([, st]) => st)).to.deep.equal([
				HtlcState.COMMITTED,
				HtlcState.COMMITTED,
				HtlcState.COMMITTED
			]);
		});

		it('the setup barrier still holds for a concurrent request, and lifts at ACTIVE', () => {
			const pair = createPair({ pushSat: 200_000n });
			pair.link.holdAt = (from, type): boolean =>
				from === 'S' && type === MessageType.COMMITMENT_SIGNED;
			const res = pair.rManager.initiateFforEpoch(
				pair.channelId,
				terms(AMOUNTS, { concurrent: true })
			);
			expect(res.ok, res.error).to.equal(true);
			pair.link.holdAt = null;
			expect(record(pair.rChannel).state).to.equal(FforState.NEGOTIATING);
			for (const side of ['S', 'R'] as const) {
				const add = offer(pair, side, 5_000_000n);
				expect(add.result.ok, `${side} during the setup`).to.equal(false);
				expect(add.result.error).to.match(
					/no ordinary add while the setup runs/
				);
			}
			pair.sErrors.length = 0;
			pair.rErrors.length = 0;
			pair.link.release('S');
			expect(record(pair.rChannel).state, why(pair)).to.equal(FforState.ACTIVE);
			expect(record(pair.sChannel).state).to.equal(FforState.ACTIVE);
			for (const side of ['S', 'R'] as const) {
				const add = offer(pair, side, 5_000_000n);
				expect(add.result.ok, add.result.error).to.equal(true);
			}
			expectVouchersCarried(pair, ALL, 'adds after activation');
		});
	});

	describe('restart in ACTIVE with ordinary HTLCs in flight', () => {
		for (const side of ['S', 'R'] as const) {
			it(`${side} restarts with a committed ordinary HTLC in each direction; they settle afterwards and the vouchers never left`, () => {
				const pair = activePair();
				const fromS = offer(pair, 'S', 30_000_000n);
				const fromR = offer(pair, 'R', 8_000_000n);
				expect(fromS.result.ok, fromS.result.error).to.equal(true);
				expect(fromR.result.ok, fromR.result.error).to.equal(true);
				expectVouchersCarried(pair, [1, 2, 3], 'before the restart');
				restart(pair, side);
				expect(record(channel(pair, side)).state).to.equal(FforState.ACTIVE);
				expect(record(channel(pair, side)).concurrentVersion).to.equal(1);
				expect(vouchers(channel(pair, side)).length).to.equal(3);
				expect(ordinaryHtlcs(channel(pair, side)).length).to.equal(2);
				pair.link.log.length = 0;
				pair.link.reconnect();
				expectHealthy(pair, 'reconnected');
				expectVouchersCarried(pair, [1, 2, 3], 'after the restart');
				const r = pair.rManager.fulfillHtlc(
					pair.channelId,
					fromS.id,
					fromS.preimage
				);
				expect(r.ok, r.error).to.equal(true);
				const s = pair.sManager.fulfillHtlc(
					pair.channelId,
					fromR.id,
					fromR.preimage
				);
				expect(s.ok, s.error).to.equal(true);
				expectHealthy(pair, 'settled after the restart');
				expectVouchersCarried(pair, [1, 2, 3], 'settled after the restart');
				expect(balances(pair)).to.deep.equal({
					s: S_AFTER_BOOK - 30_000_000n + 8_000_000n,
					r: R_START + 30_000_000n - 8_000_000n,
					sViewOfR: R_START + 30_000_000n - 8_000_000n,
					rViewOfS: S_AFTER_BOOK - 30_000_000n + 8_000_000n
				});
				// And new traffic flows on the restored state.
				pay(pair, 'S', 1_000_000n);
				pay(pair, 'R', 1_000_000n);
				expectHealthy(pair, 'traffic after the restart');
			});

			it(`${side} restarts with its own add signed but lost on the wire; the round is retransmitted beside the vouchers`, () => {
				const pair = activePair();
				// The add and its commitment_signed leave and never arrive.
				pair.link.drop = (from): boolean => from === side;
				const add = offer(pair, side, 6_000_000n);
				expect(add.result.ok, add.result.error).to.equal(true);
				pair.link.drop = null;
				expect(ordinaryHtlcs(channel(pair, other(side)))).to.deep.equal([]);
				restart(pair, side);
				pair.link.log.length = 0;
				pair.link.reconnect();
				expectHealthy(pair, 'retransmitted');
				expect(ordinaryHtlcs(channel(pair, other(side))).length).to.equal(1);
				expectVouchersCarried(pair, [1, 2, 3], 'retransmitted round');
				const res = manager(pair, other(side)).fulfillHtlc(
					pair.channelId,
					add.id,
					add.preimage
				);
				expect(res.ok, res.error).to.equal(true);
				expectHealthy(pair, 'settled');
				expectVouchersCarried(pair, [1, 2, 3], 'settled');
				const delta = side === 'S' ? -6_000_000n : 6_000_000n;
				expect(balances(pair).s).to.equal(S_AFTER_BOOK + delta);
				expect(balances(pair).r).to.equal(R_START - delta);
			});
		}
	});

	describe('retirement: DRAINING beside ordinary traffic, then CLOSED', () => {
		it('the book drains while ordinary HTLCs are in flight in both directions, reaches CLOSED, and the channel carries on', () => {
			const pair = activePair();
			// Ordinary traffic before, and two HTLCs left in flight.
			pay(pair, 'S', 20_000_000n);
			pay(pair, 'R', 5_000_000n);
			const fromS = offer(pair, 'S', 11_000_000n);
			const fromR = offer(pair, 'R', 3_000_000n);
			expect(fromS.result.ok, fromS.result.error).to.equal(true);
			expect(fromR.result.ok, fromR.result.error).to.equal(true);
			expectVouchersCarried(pair, [1, 2, 3], 'ACTIVE, two in flight');
			const sBefore = S_AFTER_BOOK - 20_000_000n + 5_000_000n - 11_000_000n;
			const rBefore = R_START + 20_000_000n - 5_000_000n - 3_000_000n;
			expect(balances(pair).s).to.equal(sBefore);
			expect(balances(pair).r).to.equal(rBefore);

			// Slot 2 was paid while R was away; R retires the book.
			settleSlot(pair, 2);
			pair.link.log.length = 0;
			const closed = pair.rManager.closeFforEpoch(pair.channelId);
			expect(closed.ok, closed.error).to.equal(true);
			expectHealthy(pair, 'drained');
			// Every voucher is resolved: CLOSED on both sides, with the two
			// ordinary HTLCs still in flight and the channel open.
			expect(record(pair.rChannel).state, why(pair)).to.equal(FforState.CLOSED);
			expect(record(pair.sChannel).state, why(pair)).to.equal(FforState.CLOSED);
			expect(vouchers(pair.rChannel)).to.deep.equal([]);
			expect(vouchers(pair.sChannel)).to.deep.equal([]);
			expect(ordinaryHtlcs(pair.rChannel).sort()).to.deep.equal(
				[`offered-${fromR.id}`, `received-${fromS.id}`].sort()
			);
			expect(ordinaryHtlcs(pair.sChannel).sort()).to.deep.equal(
				[`offered-${fromS.id}`, `received-${fromR.id}`].sort()
			);
			expect(pair.link.types()).to.not.include(MessageType.ERROR);
			// R was credited voucher 2 in full; S took 1 and 3 back.
			expect(balances(pair)).to.deep.equal({
				s: sBefore + AMOUNTS[0] + AMOUNTS[2],
				r: rBefore + AMOUNTS[1],
				sViewOfR: rBefore + AMOUNTS[1],
				rViewOfS: sBefore + AMOUNTS[0] + AMOUNTS[2]
			});
			expectVouchersCarried(pair, [], 'CLOSED');

			// Baseline ordinary operation: the two in flight settle, new ones
			// are admitted, and a fee update is legal again.
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
			pay(pair, 'S', 2_000_000n);
			expectHealthy(pair, 'after CLOSED');
			expect(balances(pair)).to.deep.equal({
				s: sBefore + AMOUNTS[0] + AMOUNTS[2] - 2_000_000n,
				r: rBefore + AMOUNTS[1] + 11_000_000n + 3_000_000n + 2_000_000n,
				sViewOfR: rBefore + AMOUNTS[1] + 11_000_000n + 3_000_000n + 2_000_000n,
				rViewOfS: sBefore + AMOUNTS[0] + AMOUNTS[2] - 2_000_000n
			});
			expect(
				balances(pair).s + balances(pair).r,
				'nothing left in flight'
			).to.equal(FUNDING_SATOSHIS * 1000n);
			const fee = pair.sManager.updateChannelFee(
				pair.channelId,
				pair.sChannel.getFullState().localConfig.feeratePerKw + 50
			);
			expect(fee.ok, fee.error).to.equal(true);
			expectHealthy(pair, 'fee update after CLOSED');
			// S's offered ids never returned to the voucher range.
			expect(pair.sChannel.getFullState().localHtlcCounter).to.equal(
				record(pair.sChannel).sHtlcIdBase! + 3n + 3n
			);
		});

		it('ordinary adds from both sides are admitted while the drain is in flight, and every round keeps the vouchers still unresolved', () => {
			const pair = drainingPair();
			// R's drain is on the wire. S, DRAINING with every voucher still
			// committed, takes ordinary work in both directions.
			expect(vouchers(pair.sChannel).map(([, st]) => st)).to.deep.equal([
				HtlcState.COMMITTED,
				HtlcState.COMMITTED,
				HtlcState.COMMITTED
			]);
			const fromS = offer(pair, 'S', 4_000_000n);
			expect(fromS.result.ok, fromS.result.error).to.equal(true);
			const fromR = offer(pair, 'R', 2_000_000n);
			expect(fromR.result.ok, fromR.result.error).to.equal(true);
			expect(record(pair.sChannel).state).to.equal(FforState.DRAINING);
			expect(record(pair.rChannel).state).to.equal(FforState.DRAINING);
			// S's own book still holds all three.
			expectVouchersCarried(pair, [], 'drain in flight', false);
			pair.link.release('R');
			expectHealthy(pair, 'drain delivered');
			expect(record(pair.rChannel).state, why(pair)).to.equal(FforState.CLOSED);
			expect(record(pair.sChannel).state, why(pair)).to.equal(FforState.CLOSED);
			expect(vouchers(pair.rChannel)).to.deep.equal([]);
			expect(vouchers(pair.sChannel)).to.deep.equal([]);
			// The two ordinary HTLCs rode through the drain rounds.
			expect(ordinaryHtlcs(pair.sChannel).length).to.equal(2);
			expect(ordinaryHtlcs(pair.rChannel).length).to.equal(2);
			const r = pair.rManager.fulfillHtlc(
				pair.channelId,
				fromS.id,
				fromS.preimage
			);
			expect(r.ok, r.error).to.equal(true);
			const s = pair.sManager.fulfillHtlc(
				pair.channelId,
				fromR.id,
				fromR.preimage
			);
			expect(s.ok, s.error).to.equal(true);
			expectHealthy(pair, 'settled after the drain');
			expect(balances(pair)).to.deep.equal({
				s: S_AFTER_BOOK + AMOUNTS[0] + AMOUNTS[2] - 4_000_000n + 2_000_000n,
				r: R_START + AMOUNTS[1] + 4_000_000n - 2_000_000n,
				sViewOfR: R_START + AMOUNTS[1] + 4_000_000n - 2_000_000n,
				rViewOfS:
					S_AFTER_BOOK + AMOUNTS[0] + AMOUNTS[2] - 4_000_000n + 2_000_000n
			});
		});

		it('CLOSED does not wait for an ordinary update that is still pending when the last voucher resolves', () => {
			const pair = drainingPair();
			// R's drain is on the wire, and behind it an ordinary add of R's
			// that its next commitment_signed will cover.
			const add = offer(pair, 'R', 2_000_000n);
			expect(add.result.ok, add.result.error).to.equal(true);
			// S's answer to that second commitment never arrives, so R's add
			// stays an update in flight for as long as the test looks.
			let revokes = 0;
			pair.link.holdAt = (from, type): boolean =>
				from === 'S' && type === MessageType.REVOKE_AND_ACK && ++revokes === 2;
			pair.link.release('R');
			pair.link.holdAt = null;
			expect(pair.link.inFlight('S')).to.include(MessageType.REVOKE_AND_ACK);
			const pending = pair.rChannel
				.getFullState()
				.htlcs.get(`offered-${add.id}`)!;
			expect(pending.addRemoteCommitted, 'the add is not yet acked').to.equal(
				false
			);
			// Every voucher is irrevocably resolved in both commitments on both
			// sides: the epoch is CLOSED, the channel is open, nothing failed.
			expect(vouchers(pair.rChannel)).to.deep.equal([]);
			expect(vouchers(pair.sChannel)).to.deep.equal([]);
			expect(record(pair.rChannel).state, why(pair)).to.equal(FforState.CLOSED);
			expect(record(pair.sChannel).state, why(pair)).to.equal(FforState.CLOSED);
			expect(pair.rChannel.getState()).to.equal(ChannelState.NORMAL);
			expect(pair.sChannel.getState()).to.equal(ChannelState.NORMAL);
			expect(pair.link.types()).to.not.include(MessageType.ERROR);
			pair.link.release('S');
			expectHealthy(pair, 'the pending round completed');
			const settle = pair.sManager.fulfillHtlc(
				pair.channelId,
				add.id,
				add.preimage
			);
			expect(settle.ok, settle.error).to.equal(true);
			expect(balances(pair)).to.deep.equal({
				s: S_AFTER_BOOK + AMOUNTS[0] + AMOUNTS[2] + 2_000_000n,
				r: R_START + AMOUNTS[1] - 2_000_000n,
				sViewOfR: R_START + AMOUNTS[1] - 2_000_000n,
				rViewOfS: S_AFTER_BOOK + AMOUNTS[0] + AMOUNTS[2] + 2_000_000n
			});
		});

		it('a voucher R can neither fulfil nor fail keeps the epoch DRAINING while ordinary payments flow', () => {
			const pair = activePair();
			settleSlot(pair, 2);
			// The ack marks slot 2 settled; R drops what it learned of it (a
			// receiver that lost the preimage), so the slot can be neither
			// fulfilled nor failed and waits for T_exp, as in baseline.
			pair.link.holdAt = (from, type): boolean =>
				from === 'S' && type === MessageType.FF_CLOSE_ACK;
			const closed = pair.rManager.closeFforEpoch(pair.channelId);
			expect(closed.ok, closed.error).to.equal(true);
			pair.link.holdAt = null;
			// The close transition is in flight: ordinary work is not blocked.
			expect(record(pair.rChannel).state).to.equal(FforState.ACTIVE);
			expect(record(pair.sChannel).state).to.equal(FforState.DRAINING);
			pay(pair, 'R', 1_000_000n);
			const ackless = offer(pair, 'S', 1_000_000n);
			expect(ackless.result.ok, ackless.result.error).to.equal(true);
			expectVouchersCarried(pair, [1, 2, 3], 'close in flight', false);
			// Deliver the ack with R unable to use the preimage it carries.
			const drain = pair.rChannel as unknown as {
				_fforDrain(f: unknown): ChannelAction[];
			};
			const original = drain._fforDrain.bind(pair.rChannel);
			drain._fforDrain = (f): ChannelAction[] => {
				record(pair.rChannel).knownPreimages[1] = null;
				return original(f);
			};
			pair.link.release('S');
			drain._fforDrain = original;
			expectHealthy(pair, 'partial drain');
			expect(record(pair.rChannel).state, why(pair)).to.equal(
				FforState.DRAINING
			);
			expect(record(pair.sChannel).state).to.equal(FforState.DRAINING);
			const base = record(pair.rChannel).sHtlcIdBase!;
			expect(vouchers(pair.rChannel)).to.deep.equal([
				[`received-${base + 1n}`, HtlcState.COMMITTED]
			]);
			expectVouchersCarried(pair, [2], 'one voucher left');
			// Not waiting for that voucher or for T_exp: unrelated payments
			// are admitted normally in DRAINING, round after round.
			const r = pair.rManager.fulfillHtlc(
				pair.channelId,
				ackless.id,
				ackless.preimage
			);
			expect(r.ok, r.error).to.equal(true);
			pay(pair, 'S', 3_000_000n);
			expectVouchersCarried(pair, [2], 'S paid R in DRAINING');
			pay(pair, 'R', 2_000_000n);
			expectVouchersCarried(pair, [2], 'R paid S in DRAINING');
			expectHealthy(pair, 'payments in DRAINING');
			expect(record(pair.rChannel).state).to.equal(FforState.DRAINING);
			expect(balances(pair)).to.deep.equal({
				s:
					S_AFTER_BOOK +
					AMOUNTS[0] +
					AMOUNTS[2] +
					1_000_000n -
					1_000_000n -
					3_000_000n +
					2_000_000n,
				r: R_START - 1_000_000n + 1_000_000n + 3_000_000n - 2_000_000n,
				sViewOfR: R_START - 1_000_000n + 1_000_000n + 3_000_000n - 2_000_000n,
				rViewOfS:
					S_AFTER_BOOK +
					AMOUNTS[0] +
					AMOUNTS[2] +
					1_000_000n -
					1_000_000n -
					3_000_000n +
					2_000_000n
			});
			// The preimage turns up (a witness, a payer): the last voucher is
			// fulfilled and the epoch closes, beside an HTLC still in flight.
			const pending = offer(pair, 'S', 1_500_000n);
			expect(pending.result.ok, pending.result.error).to.equal(true);
			const learned = pair.rManager.fforAddPreimage(
				pair.channelId,
				record(pair.sChannel).preimages[1]
			);
			expect(learned.ok, learned.error).to.equal(true);
			expectHealthy(pair, 'last voucher fulfilled');
			expect(record(pair.rChannel).state, why(pair)).to.equal(FforState.CLOSED);
			expect(record(pair.sChannel).state).to.equal(FforState.CLOSED);
			expect(ordinaryHtlcs(pair.rChannel)).to.deep.equal([
				`received-${pending.id}`
			]);
			expect(balances(pair).r).to.equal(R_START + 1_000_000n + AMOUNTS[1]);
		});

		it('an add that repeats a drained voucher is an ordinary HTLC once CLOSED', () => {
			const pair = activePair();
			const base = record(pair.rChannel).sHtlcIdBase!;
			const closed = pair.rManager.closeFforEpoch(pair.channelId);
			expect(closed.ok, closed.error).to.equal(true);
			expect(record(pair.rChannel).state, why(pair)).to.equal(FforState.CLOSED);
			pair.rManager.handleMessage(
				pair.sPub,
				MessageType.UPDATE_ADD_HTLC,
				encodeUpdateAddHtlcMessage({
					channelId: pair.channelId,
					id: base,
					amountMsat: AMOUNTS[0],
					paymentHash: record(pair.rChannel).paymentHashes[0],
					cltvExpiry: T_EXP,
					onionRoutingPacket: ONION
				})
			);
			const again = pair.rChannel.getFullState().htlcs.get(`received-${base}`);
			expect(again).to.exist;
			expect(again!.fforVoucher).to.not.equal(true);
			expect(record(pair.rChannel).unwindOwed).to.equal(false);
		});
	});

	describe('baseline epochs behave as before', () => {
		it('ACTIVE: no ordinary add, settle, fee or commitment from either side', () => {
			const pair = createPair({ pushSat: 200_000n });
			activate(pair, AMOUNTS, false);
			pair.link.log.length = 0;
			for (const side of ['S', 'R'] as const) {
				const add = offer(pair, side, 5_000_000n);
				expect(add.result.ok).to.equal(false);
				expect(add.result.error).to.equal(
					'Cannot add HTLC: FFOR epoch is ACTIVE: no add until it drains'
				);
				const ch = channel(pair, side);
				if (side === 'S') {
					expect(isError(ch.updateFee(3000))).to.equal(
						'Cannot update fee: FFOR epoch is ACTIVE: no fee until it drains'
					);
				}
				expect(isError(ch.initiateQuiescence())).to.equal(
					'Cannot quiesce: FFOR epoch is ACTIVE: no stfu until it drains'
				);
				expect(isError(ch.fulfillHtlc(77n, crypto.randomBytes(32)))).to.equal(
					'Cannot fulfill HTLC: FFOR epoch is ACTIVE: no settle until it drains'
				);
				expect(ch.fforIsFrozen()).to.equal(true);
				expect(ch.acceptsNewHtlcs()).to.equal(false);
				expect(ch.canOfferHtlcSet([5_000_000n])).to.equal(false);
			}
			expect(pair.link.log).to.deep.equal([]);
			expect(record(pair.sChannel).state).to.equal(FforState.ACTIVE);
		});

		it('DRAINING to CLOSED: the drain is the only traffic, and CLOSED waits for it all', () => {
			const pair = createPair({ pushSat: 200_000n });
			activate(pair, AMOUNTS, false);
			settleSlot(pair, 2);
			pair.link.holdAt = (from, type): boolean =>
				from === 'R' && type === MessageType.UPDATE_FULFILL_HTLC;
			const closed = pair.rManager.closeFforEpoch(pair.channelId);
			expect(closed.ok, closed.error).to.equal(true);
			pair.link.holdAt = null;
			expect(record(pair.sChannel).state).to.equal(FforState.DRAINING);
			for (const side of ['S', 'R'] as const) {
				const add = offer(pair, side, 5_000_000n);
				expect(add.result.ok).to.equal(false);
				expect(add.result.error).to.equal(
					'Cannot add HTLC: FFOR epoch is DRAINING: only the voucher drain may add'
				);
			}
			pair.sErrors.length = 0;
			pair.rErrors.length = 0;
			pair.link.release('R');
			expectHealthy(pair, 'baseline drain');
			expect(record(pair.rChannel).state).to.equal(FforState.CLOSED);
			expect(record(pair.sChannel).state).to.equal(FforState.CLOSED);
			expect(balances(pair)).to.deep.equal({
				s: S_AFTER_BOOK + AMOUNTS[0] + AMOUNTS[2],
				r: R_START + AMOUNTS[1],
				sViewOfR: R_START + AMOUNTS[1],
				rViewOfS: S_AFTER_BOOK + AMOUNTS[0] + AMOUNTS[2]
			});
			pay(pair, 'S', 1_000_000n);
			expectHealthy(pair, 'after the baseline epoch');
		});
	});
});

// ─────────────── The node layer ───────────────

/** One node's view of the S-R channel's HTLCs, by map key. */
function srHtlcs(node: LightningNode, w: IWorld): Map<string, IHtlcEntry> {
	return node.getChannelManager().getChannel(w.srChannelId)!.getFullState()
		.htlcs;
}

function srBalance(node: LightningNode, w: IWorld): bigint {
	return node.getChannelManager().getChannel(w.srChannelId)!.getFullState()
		.localBalanceMsat;
}

function voucherStates(node: LightningNode, w: IWorld): HtlcState[] {
	return [...srHtlcs(node, w).values()]
		.filter((e) => e.fforVoucher === true)
		.map((e) => e.state);
}

const PARKED = [HtlcState.COMMITTED, HtlcState.COMMITTED, HtlcState.COMMITTED];

describe('FFOR concurrent receive: traffic through the node (CONCURRENT-RECEIVE.md 3, 9)', function () {
	this.timeout(120_000);

	it('P pays R and R pays P through S while the voucher book is live', () => {
		const w = createConcurrentWorld();
		activateWorld(w, true);
		const rStart = srBalance(w.r, w);
		expect(rStart).to.equal(200_000_000n);

		// An unrelated payment to R, routed through S over the epoch channel.
		const toR = w.r.createInvoice({
			amountMsat: 50_000_000n,
			description: 'ordinary receive'
		});
		expect(payInvoice(w, toR.bolt11).status).to.equal(PaymentStatus.COMPLETED);
		expect(w.r.getPayment(toR.paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
		expect(srBalance(w.r, w)).to.equal(rStart + 50_000_000n);
		expect(voucherStates(w.r, w)).to.deep.equal(PARKED);
		expect(voucherStates(w.s, w)).to.deep.equal(PARKED);

		// R spends from the same channel.
		const toP = w.p.createInvoice({
			amountMsat: 3_000_000n,
			description: 'ordinary send'
		});
		w.r.sendPayment(toP.bolt11);
		const sent = w.r.getPayment(toP.paymentHash)!;
		expect(sent.status, JSON.stringify(w.errors)).to.equal(
			PaymentStatus.COMPLETED
		);
		expect(w.p.getPayment(toP.paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
		// What left R is the amount plus S's forwarding fee, nothing else.
		const left = rStart + 50_000_000n - srBalance(w.r, w);
		expect(left >= 3_000_000n && left < 3_010_000n, `left ${left}`).to.equal(
			true
		);
		if (sent.sentMsat !== undefined) expect(left).to.equal(sent.sentMsat);

		for (const node of [w.s, w.r]) {
			expect(nodeRecord(node, w.srHex).state).to.equal(FforState.ACTIVE);
			expect(voucherStates(node, w)).to.deep.equal(PARKED);
			expect(srHtlcs(node, w).size).to.equal(3);
		}
		expect(w.errors).to.deep.equal({ p: [], s: [], r: [] });
		expect(
			w.sr.log.some((e) => e.type === MessageType.ERROR),
			'no wire error'
		).to.equal(false);
	});

	it('an ordinary received HTLC reaching its deadline beside live vouchers is failed back exactly as without an epoch', () => {
		/**
		 * R holds an inbound HTLC it will not settle (a hold invoice nobody
		 * releases) and the chain advances. Returns the block, counted from
		 * the tip, at which R failed it back, what R sent, and how S's
		 * payment ended.
		 */
		const run = (
			withEpoch: boolean
		): {
			failedAt: number;
			sent: number[];
			status: PaymentStatus;
			w: IWorld;
		} => {
			const w = createConcurrentWorld();
			if (withEpoch) activateWorld(w, true);
			const held = w.r.createInvoice({
				amountMsat: 4_000_000n,
				description: 'held',
				hold: true
			});
			w.s.sendPayment(held.bolt11);
			expect(w.s.getPayment(held.paymentHash)!.status).to.equal(
				PaymentStatus.PENDING
			);
			const ordinary = [...srHtlcs(w.r, w).values()].filter(
				(e) => e.fforVoucher !== true
			);
			expect(ordinary.length).to.equal(1);
			expect(ordinary[0].state).to.equal(HtlcState.COMMITTED);
			// The voucher expiry is far beyond the ordinary HTLC's.
			expect(ordinary[0].cltvExpiry).to.be.lessThan(T_EXP - 1000);
			w.sr.log.length = 0;
			let failedAt = -1;
			for (let h = WORLD_TIP + 1; h < ordinary[0].cltvExpiry + 2; h++) {
				w.r.handleNewBlock(h);
				if (w.sr.log.some((e) => e.type === MessageType.UPDATE_FAIL_HTLC)) {
					failedAt = h - WORLD_TIP;
					break;
				}
			}
			return {
				failedAt,
				sent: w.sr.sentBy(w.r).map((e) => e.type),
				status: w.s.getPayment(held.paymentHash)!.status,
				w
			};
		};
		const plain = run(false);
		const beside = run(true);
		expect(plain.failedAt, 'the control failed it back').to.be.greaterThan(0);
		expect(beside.failedAt).to.equal(plain.failedAt);
		expect(beside.sent).to.deep.equal(plain.sent);
		expect(beside.status).to.equal(PaymentStatus.FAILED);
		expect(plain.status).to.equal(PaymentStatus.FAILED);
		// Off chain, with the channel open, the epoch ACTIVE and the vouchers
		// where they were: the long voucher window did not extend the
		// ordinary HTLC's, and its deadline did not touch the vouchers.
		const w = beside.w;
		expect(w.errors.r).to.deep.equal([]);
		expect(
			w.r.getChannelManager().getChannel(w.srChannelId)!.getState()
		).to.equal(ChannelState.NORMAL);
		expect(nodeRecord(w.r, w.srHex).state).to.equal(FforState.ACTIVE);
		expect(voucherStates(w.r, w)).to.deep.equal(PARKED);
		expect(srHtlcs(w.r, w).size).to.equal(3);
		expect(srBalance(w.r, w)).to.equal(200_000_000n);
	});

	it("the same scanner leaves a voucher alone at an ordinary HTLC's deadline and cannot fail one off chain", () => {
		const w = createConcurrentWorld();
		activateWorld(w, true);
		const ch = w.r.getChannelManager().getChannel(w.srChannelId)!;
		const voucher = [...srHtlcs(w.r, w).values()].find(
			(e) => e.fforVoucher === true
		)!;
		// What the expiry scanner would call for a received HTLC at its
		// deadline: refused for a voucher, in ACTIVE as in every state.
		const res = w.r
			.getChannelManager()
			.failHtlc(w.srChannelId, voucher.id, Buffer.alloc(292));
		expect(res.ok).to.equal(false);
		expect(res.error).to.match(/is parked/);
		expect(ch.getState()).to.equal(ChannelState.NORMAL);
		expect(voucherStates(w.r, w)).to.deep.equal(PARKED);
	});

	it('S still settles a voucher while R is away, after ordinary traffic; R returns without closing the book, then retires it', () => {
		const w = createConcurrentWorld();
		activateWorld(w, true);
		// Ordinary traffic moves both commitments past the activation.
		const first = w.r.createInvoice({
			amountMsat: 20_000_000n,
			description: 'before'
		});
		expect(payInvoice(w, first.bolt11).status).to.equal(
			PaymentStatus.COMPLETED
		);
		const voucher = w.r.createFforVoucherInvoice(w.srHex, 2).bolt11;
		w.sr.disconnect();
		// R is offline. The voucher invoice is paid by delegated settlement.
		const paid = payInvoice(w, voucher);
		expect(paid.status, JSON.stringify(w.errors)).to.equal(
			PaymentStatus.COMPLETED
		);
		expect(nodeRecord(w.s, w.srHex).slotStates[1]).to.equal('SETTLED');
		// Nothing was sent to R, and its voucher is still on the channel.
		expect(voucherStates(w.s, w)).to.deep.equal(PARKED);

		w.sr.log.length = 0;
		w.sr.reconnect();
		// Reconnecting is not retiring: both sides are still ACTIVE.
		for (const node of [w.s, w.r]) {
			expect(nodeRecord(node, w.srHex).state).to.equal(FforState.ACTIVE);
		}
		expect(
			w.sr.log.filter((e) => e.type === MessageType.FF_CLOSE)
		).to.deep.equal([]);
		// Ordinary traffic resumes beside the paid voucher.
		const second = w.r.createInvoice({
			amountMsat: 5_000_000n,
			description: 'after'
		});
		expect(payInvoice(w, second.bolt11).status).to.equal(
			PaymentStatus.COMPLETED
		);
		expect(voucherStates(w.r, w)).to.deep.equal(PARKED);

		// R retires the book explicitly; the drain credits the paid slot.
		const before = srBalance(w.r, w);
		const closed = w.r.closeFforEpoch(w.srHex);
		expect(closed.ok, closed.error).to.equal(true);
		for (const node of [w.s, w.r]) {
			expect(
				nodeRecord(node, w.srHex).state,
				JSON.stringify(w.errors)
			).to.equal(FforState.CLOSED);
			expect(srHtlcs(node, w).size).to.equal(0);
		}
		expect(srBalance(w.r, w)).to.equal(before + WORLD_AMOUNTS[1]);
		expect(w.errors).to.deep.equal({ p: [], s: [], r: [] });
	});
});
