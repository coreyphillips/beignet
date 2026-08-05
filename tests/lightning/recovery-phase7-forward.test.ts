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
 * The #291 redispatch window appears here in its FORWARD form: killed
 * between "inbound add durably committed" (forwardEmitted persisted with
 * the peer's revoke) and "forward linkage durable" (the onward leg
 * mapping), the restart re-forwards only through the repair pass whose
 * trigger fix/reestablish-redispatch repairs. Until that merges these
 * sweeps skip exactly that window; the skipped full sweeps at the bottom
 * flip on afterwards.
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
 * Same shape as the C2 window: opens after the inbound round's
 * commitment_signed crosses (the next commit persists forwardEmitted),
 * closes at the commit that makes the ONWARD leg durable, which is the
 * commit immediately preceding the onward update_add_htlc.
 */
function forwardDefectWindow(schedule: KillLabel[]): Set<KillLabel> {
	const opens = schedule.indexOf(
		postSendLabel(MessageType.COMMITMENT_SIGNED, 1)
	);
	const resolveIdx = schedule.indexOf(
		postSendLabel(MessageType.UPDATE_ADD_HTLC, 1)
	);
	expect(opens, 'schedule holds the inbound commitment_signed').to.be.at.least(
		0
	);
	expect(resolveIdx, 'schedule holds the onward add').to.be.greaterThan(opens);
	return new Set(schedule.slice(opens + 1, resolveIdx - 1));
}

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
	for (const mode of ['local', 'async-remote'] as const) {
		it(`S2 forwarder: every boundary outside the redispatch-defect window resumes exactly in ${mode} mode`, async function () {
			this.timeout(240_000);
			let window: Set<KillLabel> | null = null;
			let outcome: ReturnType<typeof assertForwardOutcome> | null = null;
			const { schedule, executed } = await runKillMatrix(
				mode,
				s2ForwarderDies,
				(label, fullSchedule) => {
					window ??= forwardDefectWindow(fullSchedule);
					outcome ??= assertForwardOutcome(fullSchedule);
					return window.has(label) ? 'skip' : 'exact-resume';
				},
				async (result, verdict) => outcome!(result, verdict),
				CHAOS_FORWARD_ENV
			);
			expect(
				schedule.includes(postSendLabel(MessageType.UPDATE_FULFILL_HTLC, 1)),
				'the sweep crossed the upstream fulfill boundary'
			).to.equal(true);
			expect(
				schedule.includes(postSendLabel(MessageType.UPDATE_ADD_HTLC, 1)),
				'the sweep crossed the onward add boundary'
			).to.equal(true);
			expect(executed, 'only the defect window was skipped').to.equal(
				schedule.length - window!.size
			);
		});
	}

	it('S2 forwarder: the fulfill tail resumes exactly in quorum mode, preimage always on disk', async function () {
		this.timeout(300_000);
		// Quorum pipelining renumbers the commits (the onward add is ungated
		// and crosses while gated sends park), so the shape-derived defect
		// window above does not transfer. The cells at or past the upstream
		// fulfill boundary are structurally outside the #291 window in ANY
		// mode: by then the onward leg is durable, since the fulfill came
		// back over it. Sweep those; the earlier cells join the full sweep
		// below when fix/reestablish-redispatch merges.
		let outcome: ReturnType<typeof assertForwardOutcome> | null = null;
		let tailFrom = -1;
		const { schedule, executed } = await runKillMatrix(
			'quorum',
			withNamespace(s2ForwarderDies),
			(label, fullSchedule) => {
				outcome ??= assertForwardOutcome(fullSchedule);
				if (tailFrom < 0) {
					tailFrom =
						fullSchedule.indexOf(
							postSendLabel(MessageType.UPDATE_FULFILL_HTLC, 1)
						) - 1;
				}
				return fullSchedule.indexOf(label) >= tailFrom
					? 'exact-resume'
					: 'skip';
			},
			async (result, verdict) => outcome!(result, verdict),
			quorumOptions({}, CHAOS_FORWARD_ENV)
		);
		expect(tailFrom, 'the schedule holds the fulfill boundary').to.be.at.least(
			0
		);
		expect(executed, 'the whole fulfill tail was executed').to.equal(
			schedule.length - tailFrom
		);
	});

	// Flip on when fix/reestablish-redispatch merges.
	it.skip('S2 forwarder: EVERY boundary resumes exactly in every mode (needs fix/reestablish-redispatch)', async function () {
		this.timeout(600_000);
		for (const mode of ['local', 'async-remote', 'quorum'] as const) {
			let outcome: ReturnType<typeof assertForwardOutcome> | null = null;
			const { schedule, executed } = await runKillMatrix(
				mode,
				mode === 'quorum' ? withNamespace(s2ForwarderDies) : s2ForwarderDies,
				(label, fullSchedule) => {
					outcome ??= assertForwardOutcome(fullSchedule);
					return 'exact-resume';
				},
				async (result, verdict) => outcome!(result, verdict),
				mode === 'quorum'
					? quorumOptions({}, CHAOS_FORWARD_ENV)
					: CHAOS_FORWARD_ENV
			);
			expect(executed).to.equal(schedule.length);
		}
	});
});
