/**
 * Recovery Phase 7, component 2: the commitment and fail sweeps
 * (docs/RECOVERY-PROTOCOL.md section 9, Phase 7). Kill before and after
 * every DB commit and socket send around commitment_signed,
 * revoke_and_ack, fulfill and fail, from BOTH protocol roles, in the two
 * non-quorum durability modes. Same-disk restarts: every cell must end in
 * exact resumption whatever the mode, because SQLite atomicity plus outbox
 * replay owe nothing to replication.
 *
 * S1a kills the payer (its commitment_signed and revoke_and_ack rounds).
 * S1b kills the payee (its revoke_and_ack and its update_fulfill_htlc, the
 * two irreversible sends a receiver owns). S3 kills the payee around a
 * fail it owes on a COMMITTED HTLC (hold invoice parked, then cancelled):
 * the restart must remember the fail it owes, not merely reject at add
 * time. update_fail_htlc is deliberately not barrier-class, so this sweep
 * also pins that a fail crossing a kill point needs nothing beyond
 * ordinary persistence to resolve safely.
 *
 * The receiver sweeps found the #291 defect on their first run (a receiver
 * killed between the peer's revoke_and_ack becoming durable and its own
 * resolution becoming durable stranded the committed HTLC, because the
 * repair pass was driven from an event a reestablish only re-emits for a
 * channel on its first commitment round). Fixed in #292, which gave the
 * repair a one-shot signal armed when a channel is loaded from
 * persistence, so these sweeps now run every cell.
 */

import { expect } from 'chai';
import { MessageType } from '../../src/lightning/message/types';
import { postSendLabel, runKillMatrix } from './helpers/chaos-harness';
import { assertChaosOutcome } from './helpers/chaos-oracle';
import {
	CHAOS_ENV,
	s1aSenderPays,
	s1bReceiverFulfills,
	s3FailsHeldHtlc
} from './helpers/chaos-scenarios';

describe('Recovery phase 7: commitment and fail kill sweeps', () => {
	it('S1a sender: every boundary resumes exactly in async-remote mode', async function () {
		this.timeout(120_000);
		const { schedule, executed } = await runKillMatrix(
			'async-remote',
			s1aSenderPays,
			() => 'exact-resume',
			assertChaosOutcome,
			CHAOS_ENV
		);
		expect(executed).to.equal(schedule.length);
	});

	for (const mode of ['local', 'async-remote'] as const) {
		it(`S1b receiver: every boundary resumes exactly in ${mode} mode`, async function () {
			this.timeout(120_000);
			const { schedule, executed } = await runKillMatrix(
				mode,
				s1bReceiverFulfills,
				() => 'exact-resume',
				assertChaosOutcome,
				CHAOS_ENV
			);
			expect(executed).to.equal(schedule.length);
			expect(
				schedule.includes(postSendLabel(MessageType.UPDATE_FULFILL_HTLC, 1)),
				'the sweep crossed the fulfill boundary'
			).to.equal(true);
		});

		it(`S3 fail: every boundary resumes exactly in ${mode} mode`, async function () {
			this.timeout(120_000);
			const { schedule, executed } = await runKillMatrix(
				mode,
				s3FailsHeldHtlc,
				() => 'exact-resume',
				assertChaosOutcome,
				CHAOS_ENV
			);
			expect(executed).to.equal(schedule.length);
			expect(
				schedule.includes(postSendLabel(MessageType.UPDATE_FAIL_HTLC, 1)),
				'the sweep crossed the fail boundary'
			).to.equal(true);
		});
	}
});
