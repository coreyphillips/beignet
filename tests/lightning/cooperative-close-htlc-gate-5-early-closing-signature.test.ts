/**
 * Cooperative close starts only once the channel is really empty (issue #1307),
 * section 5: a peer that sends its closing signature early: nothing is signed.
 *
 * The harness, what every case checks and the CLOSE_GATE_FULL and
 * CLOSE_GATE_SEEDS knobs are described in
 * tests/lightning/helpers/cooperative-close-htlc-gate.ts.
 */

import { expect } from 'chai';
import { ChannelState } from '../../src/lightning/channel/types';
import { MessageType } from '../../src/lightning/message/types';
import { encodeClosingSignedMessage } from '../../src/lightning/message/channel-close';
import {
	Flavor,
	HTLC_MSAT,
	Side,
	other,
	IPair,
	ALTERNATING,
	FULFILL,
	SIG,
	IPayment,
	chanOf,
	offer,
	remove,
	shutdown,
	makeFundedPair,
	who
} from './helpers/cooperative-close-htlc-gate';

describe('cooperative close waits for every HTLC to be resolved (issue #1307)', function () {
	this.timeout(120_000);

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
});
