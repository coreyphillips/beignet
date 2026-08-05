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
 *   covered here through its quorum-mode scope limit. Phase 6 refuses NEW
 *   v2 opens whenever quorum enforcement is active
 *   (`QUORUM_NO_DUAL_FUND_REFUSAL`), and the handoff is explicit that the
 *   matrix must assert that refusal rather than route around it. The
 *   refusal is what makes the row's kill points unreachable in quorum
 *   mode, and it must hold BEFORE any side effect: no key derivation, no
 *   channel index increment, no temporary channel registered, no wire
 *   message.
 */

import { expect } from 'chai';
import { QUORUM_NO_DUAL_FUND_REFUSAL } from '../../src/lightning/channel/channel-manager';
import { ChannelState } from '../../src/lightning/channel/types';
import {
	makeChaosEnv,
	recordSchedule,
	runKillPoint,
	settle
} from './helpers/chaos-harness';
import { quorumOptions, withNamespace } from './helpers/chaos-quorum';
import {
	CHAOS_ENV,
	s1aSenderPays,
	s4SplicesIn
} from './helpers/chaos-scenarios';

describe('Recovery phase 7: signing sessions II (splice, v2 promotion)', () => {
	it('quorum mode refuses a new v2 open before any side effect, so the promotion row has no reachable kill points there', async function () {
		this.timeout(60_000);
		const options = quorumOptions();
		const scenario = withNamespace(s1aSenderPays)();
		const env = await makeChaosEnv('quorum', options);
		try {
			await scenario.setup(env);
			const manager = env.victim.getChannelManager();
			const indexBefore = (manager as unknown as { nextChannelIndex: number })
				.nextChannelIndex;
			const channelsBefore = manager.listChannels().length;
			const sentBefore = env.relay.captured.length;

			let refusal: Error | null = null;
			try {
				manager.createDualFundedChannel(env.peers[0].getNodeId(), {
					fundingSatoshis: 200_000n,
					fundingFeeratePerkw: 253,
					commitmentFeeratePerkw: 253,
					dustLimitSatoshis: 546n,
					maxHtlcValueInFlightMsat: 100_000_000n,
					htlcMinimumMsat: 1n,
					toSelfDelay: 144,
					maxAcceptedHtlcs: 30,
					locktime: 0,
					localBasepoints: (
						manager as unknown as { config: { localBasepoints: unknown } }
					).config.localBasepoints as never,
					localPerCommitmentSeed: Buffer.alloc(32, 3),
					secondPerCommitmentPoint: Buffer.alloc(33, 2)
				} as never);
			} catch (err) {
				refusal = err as Error;
			}

			expect(refusal, 'the v2 open was refused').to.not.equal(null);
			expect(refusal!.message, 'refused for the quorum reason').to.equal(
				QUORUM_NO_DUAL_FUND_REFUSAL
			);
			// Refused BEFORE every side effect: this is the assertion the phase 6
			// decision record pins, and the reason the promotion row cannot be
			// swept in quorum mode.
			expect(
				(manager as unknown as { nextChannelIndex: number }).nextChannelIndex,
				'no channel index was consumed'
			).to.equal(indexBefore);
			expect(
				manager.listChannels().length,
				'no channel was registered'
			).to.equal(channelsBefore);
			expect(
				env.relay.captured.length,
				'no wire message left the node'
			).to.equal(sentBefore);
		} finally {
			env.victim.destroy();
			for (const peer of env.peers) peer.destroy();
			await options.teardown!(env);
		}
	});

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
});
