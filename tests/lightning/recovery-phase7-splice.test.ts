/**
 * Recovery Phase 7, component 6: the ephemeral signing sessions, part II
 * (docs/RECOVERY-PROTOCOL.md 5.10, docs/RECOVERY-TRANSITION-MATRIX.md
 * section 3), covering the splice and v2 rows.
 *
 * - Interactive transaction construction and `tx_signatures` (row 6: D3
 *   while unsigned, D2 once `tx_signatures` is out) and splice RBF (row
 *   7, D3): the S4 splice sweep. The sweep found #294 here, an infinite
 *   `tx_abort` loop between two honest nodes after a restart during a
 *   splice (fixed in #299; the harness's wire valve is what turned the
 *   loop into a diagnosable failure instead of a dead runner). Verdicts
 *   are derived from the disk the kill left behind: no in-flight record
 *   means the restart must talk both sides out of the splice and leave a
 *   working channel; a durable in-flight record means both sides must
 *   still agree on the splice after reestablish.
 * - Temporary to permanent channel id promotion (row 10, D1 required):
 *   the S7 sweeps drive every boundary of the promotion window and require
 *   each recorded (promoted) cell to complete the open after the restart.
 *   Quorum no longer scopes this row: the durable v2InFlight record lifted
 *   the phase 6 refusal, so quorum-mode coverage runs the SAME kill points
 *   with the irreversible sends behind the barrier.
 */

import { expect } from 'chai';
import * as ecc from '@bitcoinerlab/secp256k1';
import * as bitcoin from 'bitcoinjs-lib';
import { ChannelState } from '../../src/lightning/channel/types';
import {
	IChaosEnv,
	IChaosEnvOptions,
	IChaosScenario,
	assertNoGatedSendBeforeCommit,
	recordSchedule,
	runKillPoint,
	settle
} from './helpers/chaos-harness';
import {
	quorumOptions,
	registerQuorumNamespace,
	waitFor
} from './helpers/chaos-quorum';
import {
	CHAOS_ENV,
	s4SplicesIn,
	s7OpensV2,
	v2ChaosFundingProvider
} from './helpers/chaos-scenarios';

bitcoin.initEccLib(ecc);

describe('Recovery phase 7: signing sessions II (splice, v2 promotion)', () => {
	it('S4 splice: every boundary converges, abandoning or resuming per what the disk holds', async function () {
		this.timeout(300_000);
		const { schedule } = await recordSchedule('local', s4SplicesIn, CHAOS_ENV);
		expect(
			schedule.length,
			'the splice flow produced kill labels'
		).to.be.at.least(4);
		let abandoned = 0;
		let resumed = 0;
		for (const label of schedule) {
			const result = await runKillPoint('local', s4SplicesIn, label, CHAOS_ENV);
			const at = `at ${label}`;
			for (let i = 0; i < 10; i++) await settle();

			const diskInflight =
				result.restoredStorage.loadAllChannels()[0]?.state.spliceInFlight ??
				null;
			const victimChannel = result.restored
				.getChannelManager()
				.listChannels()[0];
			const peerChannel = result.env.peers[0]
				.getChannelManager()
				.listChannels()[0];
			const victimState = victimChannel.getFullState();
			const peerState = peerChannel.getFullState();

			if (diskInflight === null) {
				// Nothing irreversible was durable: the restart knows no
				// splice, and the reestablish abort exchange must talk BOTH
				// sides out of it, terminating (the valve rode the run) with
				// the channel back in normal operation.
				abandoned++;
				expect(
					victimChannel.getState(),
					`victim back to NORMAL ${at}`
				).to.equal(ChannelState.NORMAL);
				expect(peerChannel.getState(), `peer back to NORMAL ${at}`).to.equal(
					ChannelState.NORMAL
				);
				expect(
					victimState.spliceInFlight,
					`victim carries no splice ${at}`
				).to.equal(null);
				expect(
					peerState.spliceInFlight,
					`peer carries no splice ${at}`
				).to.equal(null);
			} else {
				// The splice was durably in flight: the reestablish must keep
				// both sides on it, agreeing on the same splice transaction.
				resumed++;
				expect(
					victimState.spliceInFlight,
					`victim still holds the splice ${at}`
				).to.not.equal(null);
				expect(
					peerState.spliceInFlight,
					`peer still holds the splice ${at}`
				).to.not.equal(null);
				expect(
					Buffer.from(victimState.spliceInFlight!.spliceTxid).toString('hex'),
					`both sides agree on the splice tx ${at}`
				).to.equal(
					Buffer.from(peerState.spliceInFlight!.spliceTxid).toString('hex')
				);
			}
			result.destroyAll();
		}
		// A schedule change that stops reaching either regime has silently
		// stopped testing the row.
		expect(abandoned, 'cells that abandoned').to.be.at.least(1);
		expect(resumed, 'cells that resumed').to.be.at.least(1);
	});

	it('S7 v2 open: no boundary leaves an orphan temporary row (matrix row 10)', async function () {
		this.timeout(300_000);
		const V2_ENV: IChaosEnvOptions = {
			...CHAOS_ENV,
			victimExtrasFactory: () => ({ fundingProvider: v2ChaosFundingProvider() })
		};
		const { schedule } = await recordSchedule('local', s7OpensV2, V2_ENV);
		expect(schedule.length, 'the open produced kill labels').to.be.at.least(4);
		// The rehearsal names the durable boundary: the first commitment
		// persist is post-commit:1, and the same batch creates the v2InFlight
		// record and writes the first (permanent-id) row. Every label from it
		// onward must leave EXACTLY ONE resumable row; every label before it
		// must leave nothing. Deriving the expectation from the label rather
		// than from whatever survived means a regression that LOSES the
		// durable row reads as the failure it is, not as a valid abandonment.
		const boundary = schedule.indexOf('post-commit:1');
		expect(
			boundary,
			'the rehearsal crossed the durable boundary'
		).to.be.greaterThan(0);
		expect(boundary, 'labels exist beyond the boundary').to.be.lessThan(
			schedule.length - 1
		);
		for (const [index, label] of schedule.entries()) {
			const mustResume = index >= boundary;
			const result = await runKillPoint('local', s7OpensV2, label, V2_ENV);
			const at = `at ${label}`;
			for (let i = 0; i < 10; i++) await settle();
			const rows = result.restoredStorage.loadAllChannels();
			const tempId = result.env.scratch.tempId as string;
			expect(
				rows.every((row) => row.channelId !== tempId),
				`no orphan temporary row ${at}`
			).to.equal(true);
			if (!mustResume) {
				// Nothing durable exists before the boundary: the open is
				// abandoned wholesale and the restart carries no debris.
				expect(rows.length, `nothing durable ${at}`).to.equal(0);
				expect(
					result.restored.getChannelManager().listChannels().length,
					`clean restart after abandon ${at}`
				).to.equal(0);
			} else {
				// The promotion committed: exactly one row, under the
				// permanent id, carrying the durable v2 record. The restart
				// rebuilds the builder-less session from it and the
				// reestablish that follows resumes the signature exchange
				// over next_funding, so every promoted cell must COMPLETE
				// the open. This is the kill-matrix acceptance for the
				// formerly process-local window (issues 288/289).
				expect(rows.length, `exactly one durable row ${at}`).to.equal(1);
				expect(
					rows[0].state.v2InFlight != null ||
						rows[0].state.state !== ChannelState.AWAITING_TX_SIGNATURES,
					`an opening row carries the durable record ${at}`
				).to.equal(true);
				const restoredStates = result.restored
					.getChannelManager()
					.listChannels()
					.map((c) => c.getState());
				expect(restoredStates.length, `one restored channel ${at}`).to.equal(1);
				expect(
					[
						ChannelState.AWAITING_FUNDING_CONFIRMED,
						ChannelState.AWAITING_CHANNEL_READY,
						ChannelState.NORMAL
					],
					`the open resumed to completion ${at}`
				).to.include(restoredStates[0]);
			}
			result.destroyAll();
		}
	});
	it('S7 v2 open under quorum: the same boundaries, gated sends behind the barrier (matrix row 10)', async function () {
		this.timeout(300_000);
		const options = quorumOptions(
			{},
			{
				...CHAOS_ENV,
				victimExtrasFactory: () => ({
					fundingProvider: v2ChaosFundingProvider()
				})
			}
		);
		// s7's setup opens nothing (the RUN is the open), so it registers the
		// namespace itself rather than through withNamespace, whose post-setup
		// wait needs opening traffic to have moved the watermark already.
		const quorumS7 = (): IChaosScenario => {
			const inner = s7OpensV2();
			return {
				...inner,
				async setup(env: IChaosEnv): Promise<void> {
					await registerQuorumNamespace();
					await inner.setup(env);
				}
			};
		};
		const { schedule, captured } = await recordSchedule(
			'quorum',
			quorumS7,
			options
		);
		expect(schedule.length, 'the open produced kill labels').to.be.at.least(4);
		// The barrier property itself, from the rehearsal for free: no gated
		// send may precede the commit of the frame that authorizes it.
		assertNoGatedSendBeforeCommit(schedule, captured);
		// Same boundary classification as the local sweep: expectations come
		// from the rehearsal's label order, not from what survived, so a
		// lost durable row fails its cell instead of counting as abandoned.
		const boundary = schedule.indexOf('post-commit:1');
		expect(
			boundary,
			'the rehearsal crossed the durable boundary (quorum)'
		).to.be.greaterThan(0);
		expect(
			boundary,
			'labels exist beyond the boundary (quorum)'
		).to.be.lessThan(schedule.length - 1);
		for (const [index, label] of schedule.entries()) {
			const mustResume = index >= boundary;
			const result = await runKillPoint('quorum', quorumS7, label, options);
			try {
				const at = `at ${label} (quorum)`;
				for (let i = 0; i < 10; i++) await settle();
				const rows = result.restoredStorage.loadAllChannels();
				const tempId = result.env.scratch.tempId as string;
				expect(
					rows.every((row) => row.channelId !== tempId),
					`no orphan temporary row ${at}`
				).to.equal(true);
				if (!mustResume) {
					expect(rows.length, `nothing durable ${at}`).to.equal(0);
					expect(
						result.restored.getChannelManager().listChannels().length,
						`clean restart after abandon ${at}`
					).to.equal(0);
				} else {
					// Same acceptance as the local sweep: a promoted cell holds
					// the durable record and COMPLETES the open after restart.
					// Quorum adds nothing to the verdict, only to the wire: the
					// commitment_signed and tx_signatures that led here each
					// waited on guardian replication before they left.
					expect(rows.length, `exactly one durable row ${at}`).to.equal(1);
					expect(
						rows[0].state.v2InFlight != null ||
							rows[0].state.state !== ChannelState.AWAITING_TX_SIGNATURES,
						`an opening row carries the durable record ${at}`
					).to.equal(true);
					// Unlike the local sweep, completion is not synchronous
					// here: the resumed exchange's own gated sends wait on
					// real guardian acks over HTTP, so poll in real time.
					await waitFor(() => {
						const states = result.restored
							.getChannelManager()
							.listChannels()
							.map((c) => c.getState());
						return (
							states.length === 1 &&
							[
								ChannelState.AWAITING_FUNDING_CONFIRMED,
								ChannelState.AWAITING_CHANNEL_READY,
								ChannelState.NORMAL
							].includes(states[0])
						);
					});
				}
			} finally {
				result.destroyAll();
				try {
					await options.teardown?.(result.env);
				} catch {
					// Teardown is best-effort by contract.
				}
			}
		}
	});
});
