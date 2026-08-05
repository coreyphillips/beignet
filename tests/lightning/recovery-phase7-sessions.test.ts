/**
 * Recovery Phase 7, component 5: the ephemeral signing sessions, part I
 * (docs/RECOVERY-PROTOCOL.md 5.10, docs/RECOVERY-TRANSITION-MATRIX.md
 * section 3). Prose classification is not acceptance: each disposition is
 * enforced by a kill inside the session.
 *
 * Coverage map for the matrix rows this file carries:
 * - Taproot verification nonces (D1 by determinism) and the MuSig2
 *   commitment co-signing nonce (D2): the full taproot payment sweep. A
 *   taproot round only verifies if the restart re-derived the same
 *   verification nonces, and every resumed round re-signs with FRESH
 *   nonces over fresh material, which is what the 5.10 invariant permits.
 * - Taproot cooperative close session (D3, MUST NOT persist) and
 *   lastCooperativeCloseTxHex (D1): the S6 close sweep, with a
 *   non-persistence assertion on every cell's disk and a targeted
 *   rebroadcast cell through a recording chain backend.
 * - Chain monitor deltas (D1) and the terminal force-close path: the S9
 *   sweep. The terminal path broadcasts BEFORE its persists by design
 *   (the operator's exit is unrefusable), so its cells assert the
 *   decision's durability ladder behind the broadcast: killed before the
 *   state commit the restart resumes NORMAL under the funding watch;
 *   killed between state and monitor commits the restart holds
 *   FORCE_CLOSED and recreates the monitor lazily from spend detection
 *   (restoreChainWatches falls through to the funding watch, by design).
 * - Held-HTLC decisions (D1 state + D3 parking): carried by the S3 sweeps
 *   in the commitment component and the standalone regressions on
 *   fix/reestablish-redispatch; noted here so the matrix row maps to a
 *   test.
 *
 * The _lastSentBatch / START_BATCH byte-exact replay row is a SPLICE
 * shape (taproot payment rounds do not batch) and lives with the splice
 * sweeps in part II.
 */

import { expect } from 'chai';
import { ChannelState } from '../../src/lightning/channel/types';
import { MessageType } from '../../src/lightning/message/types';
import {
	IChaosEnvOptions,
	IChaosRunResult,
	KillLabel,
	postSendLabel,
	runKillMatrix,
	recordSchedule,
	runKillPoint,
	settle
} from './helpers/chaos-harness';
import { assertChaosOutcome } from './helpers/chaos-oracle';
import { ChannelRecoveryStatus } from '../../src/lightning/recovery/channel-status';
import {
	CHAOS_ENV,
	s1aSenderPays,
	s6CoopCloses,
	s9ForceCloses
} from './helpers/chaos-scenarios';

const TAPROOT_ENV: IChaosEnvOptions = { ...CHAOS_ENV, preferTaproot: true };

/** No closing-session field may ever reach a serialized channel row. */
function assertNoClosingSessionOnDisk(result: IChaosRunResult): void {
	const disk = JSON.parse(result.postKillDump) as { channels: string[][] };
	for (const row of disk.channels) {
		expect(
			row[1].includes('losingNonce') ||
				row[1].includes('ClosingCache') ||
				row[1].includes('SignedClosing'),
			`closing session state leaked into the serialized channel at ${result.firedLabel}`
		).to.equal(false);
	}
}

/** Poll the restored victim until its channel reaches a terminal state. */
async function waitForCloseConvergence(
	result: IChaosRunResult,
	accepted: ChannelState[]
): Promise<ChannelState | 'GONE'> {
	const deadline = Date.now() + 8_000;
	for (;;) {
		const channel = result.restored
			.getChannelManager()
			.getChannel(result.env.channelId!);
		const state = channel ? channel.getState() : 'GONE';
		if (state === 'GONE' || accepted.includes(state)) return state;
		if (Date.now() > deadline) return state;
		await new Promise((resolve) => setTimeout(resolve, 25));
	}
}

describe('Recovery phase 7: signing sessions I (taproot, close paths)', () => {
	/**
	 * The #293 window: killed between our commitment_signed reaching the
	 * peer and the peer's revoke_and_ack becoming durable, a TAPROOT
	 * channel never resumes the round (the identical cells pass on a plain
	 * channel, which is what makes the defect taproot-specific). Two cells:
	 * the send itself and the commit that would have processed the peer's
	 * revoke.
	 */
	function taprootResumeDefectWindow(schedule: KillLabel[]): Set<KillLabel> {
		const sendIdx = schedule.indexOf(
			postSendLabel(MessageType.COMMITMENT_SIGNED, 1)
		);
		expect(
			sendIdx,
			'schedule holds the taproot commitment send'
		).to.be.at.least(0);
		return new Set(schedule.slice(sendIdx, sendIdx + 2));
	}

	it('taproot payment: every boundary outside the #293 window resumes exactly, so verification nonces re-derive and no round reuses a secret nonce', async function () {
		this.timeout(180_000);
		let window: Set<KillLabel> | null = null;
		const { schedule, executed } = await runKillMatrix(
			'local',
			s1aSenderPays,
			(label, fullSchedule) => {
				window ??= taprootResumeDefectWindow(fullSchedule);
				return window.has(label) ? 'skip' : 'exact-resume';
			},
			assertChaosOutcome,
			TAPROOT_ENV
		);
		expect(executed, 'only the #293 window was skipped').to.equal(
			schedule.length - window!.size
		);
		expect(
			schedule.includes(postSendLabel(MessageType.COMMITMENT_SIGNED, 1)),
			'the sweep crossed the taproot commitment boundary'
		).to.equal(true);
	});

	// Flip on when the #293 fix lands.
	it.skip('taproot payment: EVERY boundary resumes exactly (needs the #293 fix)', async function () {
		this.timeout(180_000);
		const { schedule, executed } = await runKillMatrix(
			'local',
			s1aSenderPays,
			() => 'exact-resume',
			assertChaosOutcome,
			TAPROOT_ENV
		);
		expect(executed).to.equal(schedule.length);
	});

	it('cooperative close: killed anywhere inside the negotiation, the close converges and the session never persists', async function () {
		this.timeout(120_000);
		const { schedule } = await recordSchedule(
			'local',
			s6CoopCloses,
			TAPROOT_ENV
		);
		expect(
			schedule.includes(postSendLabel(MessageType.SHUTDOWN, 1)),
			'the schedule crossed shutdown'
		).to.equal(true);
		for (const label of schedule) {
			const result = await runKillPoint(
				'local',
				s6CoopCloses,
				label,
				TAPROOT_ENV
			);
			try {
				// Row 3: the closing session is in-memory BY DESIGN; no cell
				// may leave any of it on disk.
				assertNoClosingSessionOnDisk(result);
				// The close converges after restart: renegotiated to CLOSED
				// over the fresh session, or FORCE_CLOSED when the peer had
				// already completed the close and answers reestablish with an
				// error (both txs spend the same funding; either confirming
				// distributes the final balances).
				const state = await waitForCloseConvergence(result, [
					ChannelState.CLOSED,
					ChannelState.FORCE_CLOSED
				]);
				expect(
					state === 'GONE' ||
						state === ChannelState.CLOSED ||
						state === ChannelState.FORCE_CLOSED,
					`close did not converge at ${label}: ${state}`
				).to.equal(true);
				// A dead process puts nothing on the wire or the chain.
				expect(
					result.broadcasts.filter((b) => b.when === 'dead'),
					`a broadcast escaped the dead process at ${label}`
				).to.deep.equal([]);
			} finally {
				result.destroyAll();
			}
		}
	});

	it('cooperative close: the fully signed close tx is durable before the close completes (lastCooperativeCloseTxHex)', async function () {
		this.timeout(60_000);
		// Matrix row 4 is D1, persist-before-emit: the signed close
		// transaction is an ordinary channel_state field, so the commit that
		// completes the close carries it. Killed right after that commit, the
		// restart must hold the exact transaction, which is what lets
		// restoreChainWatches push it back into the mempool on a node with a
		// chain backend attached (these in-process nodes have none, so the
		// durability half is what this cell can prove).
		const { schedule } = await recordSchedule(
			'local',
			s6CoopCloses,
			TAPROOT_ENV
		);
		const lastCommit = [...schedule]
			.reverse()
			.find((l) => l.startsWith('post-commit:'));
		expect(lastCommit, 'the close persisted a commit').to.not.equal(undefined);
		const result = await runKillPoint(
			'local',
			s6CoopCloses,
			lastCommit!,
			TAPROOT_ENV
		);
		try {
			await settle();
			const disk = JSON.parse(result.postKillDump) as { channels: string[][] };
			const persisted = disk.channels.find((row) =>
				row[1].includes('lastCooperativeCloseTxHex')
			);
			expect(persisted, 'the signed close tx reached disk').to.not.equal(
				undefined
			);
			const stored = JSON.parse(persisted![1]) as {
				lastCooperativeCloseTxHex?: string | null;
			};
			expect(
				typeof stored.lastCooperativeCloseTxHex === 'string' &&
					stored.lastCooperativeCloseTxHex.length > 0,
				'the persisted close tx is a real transaction'
			).to.equal(true);
			// And the restarted node restored it, so a chain backend has
			// something to rebroadcast.
			const restoredChannel = result.restored
				.getChannelManager()
				.getChannel(result.env.channelId!);
			if (restoredChannel) {
				expect(
					restoredChannel.getFullState().lastCooperativeCloseTxHex,
					'the restart restored the signed close tx'
				).to.equal(stored.lastCooperativeCloseTxHex);
			}
			assertNoClosingSessionOnDisk(result);
		} finally {
			result.destroyAll();
		}
	});

	it('force close: killed anywhere behind the unrefusable broadcast, the decision ladder holds', async function () {
		this.timeout(120_000);
		const { schedule } = await recordSchedule(
			'local',
			s9ForceCloses,
			TAPROOT_ENV
		);
		expect(
			schedule.length,
			'the terminal path has commit cells'
		).to.be.greaterThan(0);
		for (const label of schedule) {
			const result = await runKillPoint(
				'local',
				s9ForceCloses,
				label,
				TAPROOT_ENV
			);
			try {
				// The operator's exit is unrefusable BY DESIGN: the commitment
				// reached the network before any persist could fail, in every
				// cell.
				expect(
					result.broadcasts.some((b) => b.when === 'alive'),
					`the force-close broadcast was suppressed at ${label}`
				).to.equal(true);
				const channel = result.restored
					.getChannelManager()
					.getChannel(result.env.channelId!);
				const state = channel ? channel.getState() : 'GONE';
				// Killed before the state commit: the restart resumes NORMAL
				// and the armed funding watch catches the broadcast (spend
				// detection lazily rebuilds the monitor, per
				// restoreChainWatches). Killed after: FORCE_CLOSED holds.
				expect(
					state === ChannelState.NORMAL ||
						state === ChannelState.FORCE_CLOSED ||
						state === 'GONE',
					`unexpected restored state at ${label}: ${state}`
				).to.equal(true);
				if (state === ChannelState.FORCE_CLOSED) {
					const status = result.restored
						.getRecoveryStatus()
						.channels.find(
							(c) => c.channelId === result.env.channelId!.toString('hex')
						);
					expect(status?.status, `recovery status at ${label}`).to.equal(
						ChannelRecoveryStatus.ForceClosing
					);
				}
			} finally {
				result.destroyAll();
			}
		}
	});
});
