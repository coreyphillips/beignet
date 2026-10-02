/**
 * FFOR concurrent receive, version 1: capacity, fees and the voucher-subset
 * invariant (specs/CONCURRENT-RECEIVE.md sections 3.1 and 4, base section
 * 7.6).
 *
 * Vouchers and ordinary S-to-R HTLCs share R's count and in-flight limits;
 * R-to-S HTLCs use S's. The voucher value is charged once. The funder,
 * whichever side that is, keeps the fee-spike buffer (the commitment cost
 * at twice the feerate) over the full mixed commitment, whoever adds: our
 * own add is refused locally, a peer add is failed back once committed and
 * never fails the channel. New work that fails a check is rejected without
 * removing or weakening a voucher, and no commitment is signed or accepted
 * that has lost one.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { Channel } from '../../src/lightning/channel/channel';
import {
	funderCommitmentCostSats,
	getCommitmentFeeRate
} from '../../src/lightning/channel/commitment-builder';
import {
	ChannelState,
	HtlcDirection,
	HtlcState
} from '../../src/lightning/channel/types';
import { MessageType } from '../../src/lightning/message/types';
import { encodeUpdateAddHtlcMessage } from '../../src/lightning/message/channel-update';
import { FforState } from '../../src/lightning/ffor/types';
import {
	activate,
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
	Side,
	TIP,
	vouchers,
	why
} from './helpers/ffor-concurrent-pair';

/** Whole-satoshi vouchers, all above the dust limit. */
const BOOK = [1_000_000n, 2_000_000n, 50_000_000n];
const BUDGET = BOOK.reduce((a, b) => a + b, 0n);
const K = BOOK.length;
/** Under the 354 sat dust limit: no output on either commitment. */
const DUST_MSAT = 100_000n;
const BUFFER_REFUSAL = /the funder cannot keep the fee-spike buffer/;

interface IInternals {
	_fforMixedBufferEpoch(): unknown;
	_fforMixedBufferRefusal(
		candidates: { amountMsat: bigint; direction: HtlcDirection }[]
	): string | null;
	_remoteFunderFeeRefusal(amounts: bigint[]): string | null;
}

function internals(ch: Channel): IInternals {
	return ch as unknown as IInternals;
}

/** The funder's commitment cost at TWICE the feerate, for n HTLC outputs. */
function cost2x(pair: IPair, untrimmed: number): bigint {
	const st = pair.sChannel.getFullState();
	return (
		funderCommitmentCostSats(
			getCommitmentFeeRate(st) * 2,
			untrimmed,
			st.channelType
		) * 1000n
	);
}

function cost1x(pair: IPair, untrimmed: number): bigint {
	const st = pair.sChannel.getFullState();
	return (
		funderCommitmentCostSats(
			getCommitmentFeeRate(st),
			untrimmed,
			st.channelType
		) * 1000n
	);
}

/** The reserve the funder must keep, in msat. */
function funderReserveMsat(pair: IPair): bigint {
	return (
		channel(pair, pair.funder).getFullState().remoteConfig
			.channelReserveSatoshis * 1000n
	);
}

function funderHeadroomMsat(pair: IPair): bigint {
	return (
		channel(pair, pair.funder).getFullState().localBalanceMsat -
		funderReserveMsat(pair)
	);
}

/**
 * Put the funder's balance exactly `headroomMsat` above its reserve, moving
 * the difference to or from the other side on both books: where a payment
 * of that size would have left the channel, without the rounds.
 */
function setFunderHeadroom(pair: IPair, headroomMsat: bigint): void {
	const f = channel(pair, pair.funder).getFullState();
	const o = channel(pair, other(pair.funder)).getFullState();
	const delta = f.localBalanceMsat - (funderReserveMsat(pair) + headroomMsat);
	f.localBalanceMsat -= delta;
	o.remoteBalanceMsat -= delta;
	o.localBalanceMsat += delta;
	f.remoteBalanceMsat += delta;
	expect(funderHeadroomMsat(pair)).to.equal(headroomMsat);
	expect(o.localBalanceMsat >= 0n, 'the other side stays solvent').to.equal(
		true
	);
}

/** A concurrent ACTIVE pair with the K-voucher book and a funded R. */
function bookPair(funder: Side = 'S'): IPair {
	const pair = createPair({
		funder,
		// Either way both sides hold plenty: S for the book, R to spend.
		pushSat: funder === 'S' ? 300_000n : 600_000n
	});
	activate(pair, BOOK, true);
	pair.link.log.length = 0;
	return pair;
}

/** Deliver a hand-built update_add_htlc from `from`, as its next HTLC. */
function rawAdd(pair: IPair, from: Side, amountMsat: bigint): bigint {
	const id = channel(pair, from).getFullState().localHtlcCounter;
	manager(pair, other(from)).handleMessage(
		from === 'S' ? pair.sPub : pair.rPub,
		MessageType.UPDATE_ADD_HTLC,
		encodeUpdateAddHtlcMessage({
			channelId: pair.channelId,
			id,
			amountMsat,
			paymentHash: crypto.randomBytes(32),
			cltvExpiry: TIP + 100,
			onionRoutingPacket: ONION
		})
	);
	return id;
}

describe('FFOR concurrent receive: capacity (CONCURRENT-RECEIVE.md 3.1, 4)', function () {
	this.timeout(120_000);

	describe('shared limits', () => {
		it("vouchers and ordinary S-to-R HTLCs share R's count limit; R-to-S HTLCs use S's", () => {
			const pair = createPair({
				pushSat: 300_000n,
				rLocalConfig: { maxAcceptedHtlcs: K + 2 }
			});
			activate(pair, BOOK, true);
			const a = offer(pair, 'S', 5_000_000n);
			const b = offer(pair, 'S', 5_000_000n);
			expect(a.result.ok, a.result.error).to.equal(true);
			expect(b.result.ok, b.result.error).to.equal(true);
			// K vouchers + 2: R's limit is full.
			const c = offer(pair, 'S', 5_000_000n);
			expect(c.result.ok).to.equal(false);
			expect(c.result.error).to.equal('Max pending HTLCs exceeded');
			expect(pair.sChannel.canOfferHtlcSet([5_000_000n])).to.equal(false);
			// The other direction is counted against S's own limit.
			const d = offer(pair, 'R', 5_000_000n);
			expect(d.result.ok, d.result.error).to.equal(true);
			pair.sErrors.length = 0;
			expectHealthy(pair, 'at the count limit');
			expectVouchersCarried(pair, [1, 2, 3], 'at the count limit');
			// A slot frees when an ordinary HTLC resolves, not a voucher.
			const freed = pair.rManager.fulfillHtlc(pair.channelId, a.id, a.preimage);
			expect(freed.ok, freed.error).to.equal(true);
			const e = offer(pair, 'S', 5_000_000n);
			expect(e.result.ok, e.result.error).to.equal(true);
			expect(vouchers(pair.sChannel).length).to.equal(K);
		});

		it("vouchers and ordinary S-to-R HTLCs share R's in-flight value limit", () => {
			const pair = createPair({
				pushSat: 300_000n,
				rLocalConfig: { maxHtlcValueInFlightMsat: BUDGET + 10_000_000n }
			});
			activate(pair, BOOK, true);
			const over = offer(pair, 'S', 10_000_001n);
			expect(over.result.ok).to.equal(false);
			expect(over.result.error).to.equal('Max HTLC value in flight exceeded');
			const at = offer(pair, 'S', 10_000_000n);
			expect(at.result.ok, at.result.error).to.equal(true);
			const more = offer(pair, 'S', 1_000n);
			expect(more.result.ok).to.equal(false);
			// R's own sends are bounded by S's limit, not this one.
			const back = offer(pair, 'R', 20_000_000n);
			expect(back.result.ok, back.result.error).to.equal(true);
			pair.sErrors.length = 0;
			expectHealthy(pair, 'at the value limit');
			expectVouchersCarried(pair, [1, 2, 3], 'at the value limit');
		});

		it('the voucher value is charged once: S spends what a channel with the same HTLCs and no epoch could', () => {
			const epoch = bookPair();
			// The same balances and the same three HTLCs, with no epoch.
			const plain = createPair({ pushSat: 300_000n });
			for (const amount of BOOK) {
				const o = offer(plain, 'S', amount);
				expect(o.result.ok, o.result.error).to.equal(true);
			}
			expect(balances(epoch)).to.deep.equal(balances(plain));
			const spendable = epoch.sChannel.getSpendableOutboundMsat();
			expect(spendable).to.equal(plain.sChannel.getSpendableOutboundMsat());
			// And it is the balance less the reserve and the buffer: the
			// budget left the balance when the vouchers were added, and is
			// not taken out again.
			expect(spendable).to.equal(
				balances(epoch).s - funderReserveMsat(epoch) - cost2x(epoch, K + 2)
			);
			expect(balances(epoch).s).to.equal(
				(1_000_000n - 300_000n) * 1000n - BUDGET
			);
			const all = offer(epoch, 'S', spendable);
			expect(all.result.ok, all.result.error).to.equal(true);
			expectHealthy(epoch, 'spent to the ceiling');
			expectVouchersCarried(epoch, [1, 2, 3], 'spent to the ceiling');
		});

		it('R spends down to its reserve beside the book, and no further', () => {
			const pair = bookPair();
			const spendable = pair.rChannel.getSpendableOutboundMsat();
			const reserve =
				pair.rChannel.getFullState().remoteConfig.channelReserveSatoshis *
				1000n;
			expect(spendable).to.equal(balances(pair).r - reserve);
			const over = offer(pair, 'R', spendable + 1n);
			expect(over.result.ok).to.equal(false);
			expect(over.result.error).to.equal('Insufficient balance for HTLC');
			const at = offer(pair, 'R', spendable);
			expect(at.result.ok, at.result.error).to.equal(true);
			pair.rErrors.length = 0;
			expectHealthy(pair, 'R at its reserve');
			expectVouchersCarried(pair, [1, 2, 3], 'R at its reserve');
		});
	});

	describe('the fee-spike buffer over the mixed commitment', () => {
		it('we fund and we add: the stock ceiling already keeps it, vouchers counted', () => {
			const pair = bookPair('S');
			const h = funderHeadroomMsat(pair);
			const spendable = pair.sChannel.getSpendableOutboundMsat();
			// Twice the feerate, the K vouchers and two more slots.
			expect(spendable).to.equal(h - cost2x(pair, K + 2));
			expect(pair.sChannel.canOfferHtlcSet([spendable])).to.equal(true);
			expect(pair.sChannel.canOfferHtlcSet([spendable + 1n])).to.equal(false);
			const over = offer(pair, 'S', spendable + 1n);
			expect(over.result.ok).to.equal(false);
			const at = offer(pair, 'S', spendable);
			expect(at.result.ok, at.result.error).to.equal(true);
			pair.sErrors.length = 0;
			expectHealthy(pair, 'funder at its ceiling');
			expectVouchersCarried(pair, [1, 2, 3], 'funder at its ceiling');
		});

		for (const funder of ['S', 'R'] as const) {
			const adder = other(funder);

			it(`${funder} funds, ${adder} adds: refused locally one satoshi short of the buffer, admitted at it`, () => {
				const pair = bookPair(funder);
				const ch = channel(pair, adder);
				const need = cost2x(pair, K + 1);
				setFunderHeadroom(pair, need - 1000n);
				// The stock mirror prices the funder at the live rate and admits.
				expect(internals(ch)._remoteFunderFeeRefusal([5_000_000n])).to.equal(
					null
				);
				expect(need - 1000n >= cost1x(pair, K + 2)).to.equal(true);
				// The ceiling the router reads has the buffer folded in, so the
				// add meets it there; the buffer is the reason.
				const refused = offer(pair, adder, 5_000_000n);
				expect(refused.result.ok).to.equal(false);
				expect(refused.result.error).to.equal('Insufficient balance for HTLC');
				expect(
					internals(ch)._fforMixedBufferRefusal([
						{ amountMsat: 5_000_000n, direction: HtlcDirection.OFFERED }
					])
				).to.match(BUFFER_REFUSAL);
				expect(ch.canOfferHtlcSet([5_000_000n])).to.equal(false);
				// A trimmed add adds no output and no fee: still admitted, and
				// the ceiling the router reads says exactly that.
				expect(ch.getSpendableOutboundMsat()).to.equal(354_000n - 1n);
				expect(ch.canOfferHtlcSet([DUST_MSAT])).to.equal(true);
				const dust = offer(pair, adder, DUST_MSAT);
				expect(dust.result.ok, dust.result.error).to.equal(true);
				// Nothing was sent for the refusal and nothing was weakened.
				pair.sErrors.length = 0;
				pair.rErrors.length = 0;
				expectHealthy(pair, 'refused locally');
				expect(pair.link.types()).to.not.include(MessageType.ERROR);
				expectVouchersCarried(pair, [1, 2, 3], 'refused locally');

				setFunderHeadroom(pair, need);
				expect(ch.getSpendableOutboundMsat() > 354_000n).to.equal(true);
				const ok = offer(pair, adder, 5_000_000n);
				expect(ok.result.ok, ok.result.error).to.equal(true);
				expectHealthy(pair, 'admitted at the buffer');
				expectVouchersCarried(pair, [1, 2, 3], 'admitted at the buffer');
			});

			it(`${funder} funds, ${adder} adds a set: judged whole against the buffer`, () => {
				const pair = bookPair(funder);
				const ch = channel(pair, adder);
				setFunderHeadroom(pair, cost2x(pair, K + 2));
				expect(ch.canOfferHtlcSet([2_000_000n, 2_000_000n])).to.equal(true);
				expect(
					ch.canOfferHtlcSet([2_000_000n, 2_000_000n, 2_000_000n])
				).to.equal(false);
				// Trimmed members cost the funder nothing.
				expect(
					ch.canOfferHtlcSet([2_000_000n, 2_000_000n, DUST_MSAT])
				).to.equal(true);
			});

			it(`${funder} funds, ${adder} adds past the buffer anyway: ${funder} admits it for a fail-back, and the channel and the vouchers stand`, () => {
				const pair = bookPair(funder);
				const receiver = channel(pair, funder);
				const need = cost2x(pair, K + 1);
				setFunderHeadroom(pair, need - 1000n);
				const id = rawAdd(pair, adder, 5_000_000n);
				const entry = receiver.getFullState().htlcs.get(`received-${id}`);
				expect(entry, why(pair)).to.exist;
				expect(entry!.funderFeeFailback).to.equal(true);
				expect(receiver.receivedHtlcExceedsFunderFee(id)).to.equal(true);
				expect(receiver.getState()).to.equal(ChannelState.NORMAL);
				expect(pair.link.types()).to.not.include(MessageType.ERROR);
				expect(vouchers(receiver).length).to.equal(K);
				expect(record(receiver).state).to.equal(FforState.ACTIVE);

				// At the buffer the same add is taken as it is.
				const fine = bookPair(funder);
				setFunderHeadroom(fine, need);
				const fineId = rawAdd(fine, adder, 5_000_000n);
				const taken = channel(fine, funder)
					.getFullState()
					.htlcs.get(`received-${fineId}`);
				expect(taken).to.exist;
				expect(taken!.funderFeeFailback).to.not.equal(true);
				// A trimmed add never needs it.
				const dusty = bookPair(funder);
				setFunderHeadroom(dusty, need - 1000n);
				const dustId = rawAdd(dusty, adder, DUST_MSAT);
				expect(
					channel(dusty, funder).getFullState().htlcs.get(`received-${dustId}`)!
						.funderFeeFailback
				).to.not.equal(true);
			});

			it(`${funder} funds and adds past the buffer: ${adder} admits it for a fail-back`, () => {
				const pair = bookPair(funder);
				const receiver = channel(pair, adder);
				// The add comes out of the balance that pays the fee: one
				// satoshi short of the buffer AFTER it.
				const amount = 5_000_000n;
				setFunderHeadroom(pair, cost2x(pair, K + 1) + amount - 1000n);
				const id = rawAdd(pair, funder, amount);
				const entry = receiver.getFullState().htlcs.get(`received-${id}`);
				expect(entry, why(pair)).to.exist;
				expect(entry!.funderFeeFailback).to.equal(true);
				expect(receiver.getState()).to.equal(ChannelState.NORMAL);
				expect(pair.link.types()).to.not.include(MessageType.ERROR);
				expect(vouchers(receiver).length).to.equal(K);

				const fine = bookPair(funder);
				setFunderHeadroom(fine, cost2x(fine, K + 1) + amount);
				const fineId = rawAdd(fine, funder, amount);
				expect(
					channel(fine, adder).getFullState().htlcs.get(`received-${fineId}`)!
						.funderFeeFailback
				).to.not.equal(true);
			});

			it(`${funder} funds: a stamped add rides full rounds, is failed back, and every commitment kept the vouchers`, () => {
				const pair = bookPair(funder);
				setFunderHeadroom(pair, cost2x(pair, K + 1) - 1000n);
				const before = balances(pair);
				// A sender that does not keep the buffer itself.
				const lax = internals(channel(pair, adder));
				const original = lax._fforMixedBufferEpoch.bind(channel(pair, adder));
				lax._fforMixedBufferEpoch = (): unknown => null;
				const add = offer(pair, adder, 5_000_000n);
				lax._fforMixedBufferEpoch = original;
				expect(add.result.ok, add.result.error).to.equal(true);
				expectHealthy(pair, 'stamped add committed');
				expectVouchersCarried(pair, [1, 2, 3], 'stamped add committed');
				const receiver = channel(pair, funder);
				expect(receiver.receivedHtlcExceedsFunderFee(add.id)).to.equal(true);
				expect(pair.events[funder].forwarded).to.include(add.id);
				// What the node does with a stamped HTLC: fail it back.
				const fail = manager(pair, funder).failHtlc(
					pair.channelId,
					add.id,
					Buffer.alloc(292)
				);
				expect(fail.ok, fail.error).to.equal(true);
				expectHealthy(pair, 'failed back');
				expectVouchersCarried(pair, [1, 2, 3], 'failed back');
				expect(balances(pair)).to.deep.equal(before);
				expect(pair.events[adder].failed).to.include(add.id);
			});
		}

		it('no fold, no stamp and no refusal without a live concurrent book', () => {
			// No epoch at all.
			const none = createPair({ pushSat: 300_000n });
			setFunderHeadroom(none, cost2x(none, 1) - 1000n);
			expect(
				internals(none.rChannel)._fforMixedBufferRefusal([
					{ amountMsat: 5_000_000n, direction: HtlcDirection.OFFERED }
				])
			).to.equal(null);
			const plain = offer(none, 'R', 5_000_000n);
			expect(plain.result.ok, plain.result.error).to.equal(true);
			expect(
				none.sChannel.getFullState().htlcs.get(`received-${plain.id}`)!
					.funderFeeFailback
			).to.not.equal(true);

			// A concurrent epoch that is CLOSED.
			const closed = bookPair('S');
			const done = closed.rManager.closeFforEpoch(closed.channelId);
			expect(done.ok, done.error).to.equal(true);
			expect(record(closed.rChannel).state, why(closed)).to.equal(
				FforState.CLOSED
			);
			setFunderHeadroom(closed, cost2x(closed, 1) - 1000n);
			expect(internals(closed.rChannel)._fforMixedBufferEpoch()).to.equal(null);
			const after = offer(closed, 'R', 5_000_000n);
			expect(after.result.ok, after.result.error).to.equal(true);

			// A baseline epoch, whose record a build flipped by hand: the
			// buffer reads the selected version, nothing else.
			const baseline = createPair({ pushSat: 300_000n });
			activate(baseline, BOOK, false);
			expect(internals(baseline.rChannel)._fforMixedBufferEpoch()).to.equal(
				null
			);
			expect(internals(baseline.sChannel)._fforMixedBufferEpoch()).to.equal(
				null
			);
		});

		it('the ceiling and the admission agree at every funder balance around the buffer', () => {
			for (const funder of ['S', 'R'] as const) {
				const adder = other(funder);
				const pair = bookPair(funder);
				const base = cost2x(pair, K);
				for (let step = -3; step <= 400; step += 13) {
					setFunderHeadroom(pair, base + BigInt(step) * 1000n);
					const ch = channel(pair, adder);
					const ceiling = ch.getSpendableOutboundMsat();
					if (ceiling > 0n) {
						expect(
							ch.canOfferHtlcSet([ceiling]),
							`${funder} funds, step ${step}: at the ceiling`
						).to.equal(true);
						expect(
							internals(ch)._fforMixedBufferRefusal([
								{ amountMsat: ceiling, direction: HtlcDirection.OFFERED }
							]),
							`${funder} funds, step ${step}: no refusal at the ceiling`
						).to.equal(null);
					}
					expect(
						ch.canOfferHtlcSet([ceiling + 1n]),
						`${funder} funds, step ${step}: past the ceiling`
					).to.equal(false);
				}
			}
		});
	});

	describe('the voucher-subset invariant', () => {
		/** R's ledger loses voucher k on both books, as a local fault would. */
		function dropVoucher(pair: IPair, k: number): bigint {
			const id = record(pair.rChannel).sHtlcIdBase! + BigInt(k - 1);
			const r = pair.rChannel.getFullState();
			const s = pair.sChannel.getFullState();
			const amount = r.htlcs.get(`received-${id}`)!.amountMsat;
			r.htlcs.delete(`received-${id}`);
			s.htlcs.delete(`offered-${id}`);
			// The value has to sit somewhere for the two builds to agree.
			r.remoteBalanceMsat += amount;
			s.localBalanceMsat += amount;
			return id;
		}

		it('R does not accept a commitment that lost an unresolved voucher: no revocation, nothing stored', () => {
			const pair = bookPair();
			dropVoucher(pair, 2);
			const before = pair.rChannel.getFullState();
			const number = before.localCommitmentNumber;
			const sig = Buffer.from(before.remoteCommitmentSignature!);
			// S signs a commitment for R that its own (faulty) book also built
			// without the voucher, so the signature verifies.
			const add = offer(pair, 'S', 5_000_000n);
			expect(add.result.ok, add.result.error).to.equal(true);
			expect(pair.rChannel.getState()).to.equal(ChannelState.ERRORED);
			expect(pair.rErrors.join('|')).to.match(
				/FFOR voucher 2 is unresolved and missing from the channel/
			);
			const after = pair.rChannel.getFullState();
			expect(after.localCommitmentNumber).to.equal(number);
			expect(after.remoteCommitmentSignature!.equals(sig)).to.equal(true);
			expect(
				pair.link.log.filter(
					(e) => e.from === 'R' && e.type === MessageType.REVOKE_AND_ACK
				)
			).to.deep.equal([]);
			expect(
				pair.link.log.some(
					(e) => e.from === 'R' && e.type === MessageType.ERROR
				)
			).to.equal(true);
			// The two vouchers R still has are untouched.
			expect(vouchers(pair.rChannel).map(([, st]) => st)).to.deep.equal([
				HtlcState.COMMITTED,
				HtlcState.COMMITTED
			]);
		});

		it('R does not sign a commitment that lost an unresolved voucher', () => {
			const pair = bookPair();
			dropVoucher(pair, 1);
			const number = pair.rChannel.getFullState().remoteCommitmentNumber;
			const add = offer(pair, 'R', 5_000_000n);
			// The add itself is fine; the signature that would cover it is not.
			expect(add.result.ok, add.result.error).to.equal(true);
			expect(pair.rChannel.getState()).to.equal(ChannelState.ERRORED);
			expect(pair.rErrors.join('|')).to.match(
				/FFOR voucher 1 is unresolved and missing from the channel/
			);
			expect(pair.rChannel.getFullState().remoteCommitmentNumber).to.equal(
				number
			);
			expect(
				pair.link.log.filter(
					(e) => e.from === 'R' && e.type === MessageType.COMMITMENT_SIGNED
				)
			).to.deep.equal([]);
		});

		for (const field of ['amountMsat', 'cltvExpiry', 'paymentHash'] as const) {
			for (const side of ['S', 'R'] as const) {
				it(`${side} does not sign once a voucher's ${field} no longer matches the book`, () => {
					const pair = bookPair();
					const f = record(channel(pair, side));
					const key = `${
						side === 'S' ? 'offered' : 'received'
					}-${f.sHtlcIdBase!}`;
					const entry = channel(pair, side).getFullState().htlcs.get(key)!;
					if (field === 'amountMsat') entry.amountMsat += 1000n;
					else if (field === 'cltvExpiry') entry.cltvExpiry += 1;
					else entry.paymentHash = crypto.randomBytes(32);
					const add = offer(pair, side, 5_000_000n);
					expect(add.result.ok, add.result.error).to.equal(true);
					expect(channel(pair, side).getState()).to.equal(ChannelState.ERRORED);
					expect(
						(side === 'S' ? pair.sErrors : pair.rErrors).join('|')
					).to.match(/FFOR voucher 1 no longer matches the book/);
					expect(
						pair.link.log.filter(
							(e) => e.from === side && e.type === MessageType.COMMITMENT_SIGNED
						)
					).to.deep.equal([]);
				});
			}
		}

		it('neither side signs or accepts a commitment that trims a voucher', () => {
			// S signs: its view of R's commitment trims the 1000 sat voucher.
			const signing = bookPair();
			signing.sChannel.getFullState().remoteConfig.dustLimitSatoshis = 1_500n;
			const a = offer(signing, 'S', 5_000_000n);
			expect(a.result.ok, a.result.error).to.equal(true);
			expect(signing.sChannel.getState()).to.equal(ChannelState.ERRORED);
			expect(signing.sErrors.join('|')).to.match(
				/the remote commitment does not carry every unresolved voucher/
			);
			expect(
				signing.link.log.filter(
					(e) => e.from === 'S' && e.type === MessageType.COMMITMENT_SIGNED
				)
			).to.deep.equal([]);

			// R accepts: both books trim it in R's commitment, so S's signature
			// verifies, and R still refuses to revoke for it.
			const accepting = bookPair();
			accepting.sChannel.getFullState().remoteConfig.dustLimitSatoshis = 1_500n;
			accepting.rChannel.getFullState().localConfig.dustLimitSatoshis = 1_500n;
			// S's own guard is taken out of the way: this is R's check.
			(
				accepting.sChannel as unknown as {
					_fforVoucherSubsetRefusal(): string | null;
				}
			)._fforVoucherSubsetRefusal = (): string | null => null;
			const number = accepting.rChannel.getFullState().localCommitmentNumber;
			const b = offer(accepting, 'S', 5_000_000n);
			expect(b.result.ok, b.result.error).to.equal(true);
			expect(accepting.rChannel.getState()).to.equal(ChannelState.ERRORED);
			expect(accepting.rErrors.join('|')).to.match(
				/the local commitment does not carry every unresolved voucher/
			);
			expect(accepting.rChannel.getFullState().localCommitmentNumber).to.equal(
				number
			);
			expect(
				accepting.link.log.filter(
					(e) => e.from === 'R' && e.type === MessageType.REVOKE_AND_ACK
				)
			).to.deep.equal([]);
		});

		it('a fulfilled voucher may leave commitments while other slots remain', () => {
			const pair = bookPair();
			// A held preimage now completes slot 2 through live redemption.
			const learned = pair.rManager.fforAddPreimage(
				pair.channelId,
				record(pair.sChannel).preimages[1]
			);
			expect(learned.ok, learned.error).to.equal(true);
			pay(pair, 'S', 5_000_000n);
			pay(pair, 'R', 1_000_000n);
			expectHealthy(pair, 'slot 2 absent with its preimage held');
			expectVouchersCarried(pair, [1, 3], 'slot 2 absent');
		});

		it('ordinary HTLCs beside the vouchers are not counted against the book', () => {
			const pair = bookPair();
			// More HTLC outputs than the book has slots, in both directions.
			for (let i = 0; i < 4; i++) {
				expect(offer(pair, 'S', 2_000_000n).result.ok).to.equal(true);
				expect(offer(pair, 'R', 2_000_000n).result.ok).to.equal(true);
			}
			expectHealthy(pair, 'eleven HTLC outputs');
			expectVouchersCarried(pair, [1, 2, 3], 'eleven HTLC outputs');
			expect(pair.sChannel.getFullState().htlcs.size).to.equal(K + 8);
		});

		it('an ordinary HTLC with a voucher hash and amount does not stand in for the voucher', () => {
			const pair = bookPair();
			const f = record(pair.rChannel);
			// S offers an ordinary HTLC on voucher 1's hash, amount and expiry
			// (a different id), then R's ledger loses the voucher itself.
			const res = pair.sManager.addHtlc(
				pair.channelId,
				BOOK[0],
				f.paymentHashes[0],
				f.params.voucherExpiry,
				ONION
			);
			expect(res.ok, res.error).to.equal(true);
			expectHealthy(pair, 'look-alike committed');
			dropVoucher(pair, 1);
			const add = offer(pair, 'R', 5_000_000n);
			expect(add.result.ok, add.result.error).to.equal(true);
			expect(pair.rChannel.getState()).to.equal(ChannelState.ERRORED);
			expect(pair.rErrors.join('|')).to.match(
				/FFOR voucher 1 is unresolved and missing from the channel/
			);
		});
	});
});
