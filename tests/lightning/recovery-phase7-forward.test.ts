/**
 * Recovery Phase 7, component 4: the forward sweep
 * (docs/RECOVERY-PROTOCOL.md section 9, Phase 7). The victim is the
 * FORWARDER in payer -> victim -> payee, killed at every commit and send
 * boundary of the whole forward: the inbound add rounds, the forward
 * linkage, the onward add, the downstream fulfill, and the upstream
 * fulfill it owes the payer. Same-disk restarts must resume exactly, and
 * the spec's absolute holds in every cell: once the downstream fulfill
 * reached the victim, the preimage must be readable from the restart's
 * disk, because a forwarder that forgets a preimage it was paid to reveal
 * upstream has lost funds outright.
 *
 * The preimage assertion is derived from persist-before-send rather than
 * pinned to ordinals: the upstream update_fulfill_htlc's own commit
 * carries the preimage, so every cell at or past the label immediately
 * before that send must show it on disk. (Empirically it lands several
 * commits earlier, at the downstream fulfill's first commit; the derived
 * bound is the one guaranteed by construction.)
 *
 * The #291 redispatch window appeared here in its FORWARD form (killed
 * between the inbound add becoming durable and the forward linkage
 * becoming durable, the restart re-forwarded only through a repair pass
 * whose trigger was broken; fixed in #292). The widened sweep then found
 * #295 in quorum mode: the pipeline persisted the processed downstream
 * fulfill ahead of the preimage commit, and the restart swallowed the
 * peer's replayed fulfill (fixed in #296). Every mode now runs every
 * cell.
 */

import { expect } from 'chai';
import { MessageType } from '../../src/lightning/message/types';
import {
	IChaosRunResult,
	KillLabel,
	postSendLabel,
	runKillMatrix
} from './helpers/chaos-harness';
import { assertChaosOutcome } from './helpers/chaos-oracle';
import { CHAOS_FORWARD_ENV, s2ForwarderDies } from './helpers/chaos-scenarios';
import { quorumOptions, withNamespace } from './helpers/chaos-quorum';

/**
 * The preimage absolute: for every cell at or past the label immediately
 * preceding the upstream fulfill send, the forwarded payment's preimage
 * must be on the disk the kill left behind.
 */
function assertForwardOutcome(
	schedule: KillLabel[]
): (
	result: IChaosRunResult,
	verdict: 'exact-resume' | 'safe-dlp'
) => Promise<void> {
	const fulfillIdx = schedule.indexOf(
		postSendLabel(MessageType.UPDATE_FULFILL_HTLC, 1)
	);
	expect(fulfillIdx, 'schedule holds the upstream fulfill').to.be.greaterThan(
		0
	);
	const exposedFrom = fulfillIdx - 1;
	return async (result, verdict): Promise<void> => {
		const position = schedule.indexOf(result.firedLabel);
		if (position >= exposedFrom) {
			const dump = JSON.parse(result.postKillDump) as {
				preimages: string[][];
			};
			const hash = result.env.scratch.forwardHash as string;
			expect(
				dump.preimages.some((p) => p[0] === hash),
				`preimage for the forwarded HTLC missing from disk at ${result.firedLabel}`
			).to.equal(true);
		}
		await assertChaosOutcome(result, verdict);
	};
}

describe('Recovery phase 7: forward kill sweep (payer -> victim -> payee)', () => {
	for (const mode of ['local', 'async-remote', 'quorum'] as const) {
		it(`S2 forwarder: every boundary resumes exactly in ${mode} mode`, async function () {
			this.timeout(300_000);
			let outcome: ReturnType<typeof assertForwardOutcome> | null = null;
			const { schedule, executed } = await runKillMatrix(
				mode,
				mode === 'quorum' ? withNamespace(s2ForwarderDies) : s2ForwarderDies,
				(_label, fullSchedule) => {
					outcome ??= assertForwardOutcome(fullSchedule);
					return 'exact-resume';
				},
				async (result, verdict) => outcome!(result, verdict),
				mode === 'quorum'
					? quorumOptions({}, CHAOS_FORWARD_ENV)
					: CHAOS_FORWARD_ENV
			);
			expect(executed).to.equal(schedule.length);
			expect(
				schedule.includes(postSendLabel(MessageType.UPDATE_FULFILL_HTLC, 1)),
				'the sweep crossed the upstream fulfill boundary'
			).to.equal(true);
			expect(
				schedule.includes(postSendLabel(MessageType.UPDATE_ADD_HTLC, 1)),
				'the sweep crossed the onward add boundary'
			).to.equal(true);
		});
	}
});
