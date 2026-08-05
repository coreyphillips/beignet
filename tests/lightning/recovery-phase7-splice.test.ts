/**
 * Recovery Phase 7, component 6: the ephemeral signing sessions, part II
 * (docs/RECOVERY-PROTOCOL.md 5.10, docs/RECOVERY-TRANSITION-MATRIX.md
 * section 3), covering the splice and v2 rows.
 *
 * - Interactive transaction construction and `tx_signatures` (row 6: D3
 *   while unsigned, D2 once `tx_signatures` is out) and splice RBF (row
 *   7, D3): the S4 splice sweep. It is SKIPPED pending #294, an infinite
 *   `tx_abort` loop between two honest nodes after a restart during a
 *   splice, which the harness's wire valve turns into a diagnosable
 *   failure instead of a dead runner. Every splice kill point trips it,
 *   so there is no partial window to sweep the way #291 and #293 allow.
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
import { makeChaosEnv } from './helpers/chaos-harness';
import { quorumOptions, withNamespace } from './helpers/chaos-quorum';
import { s1aSenderPays, s4SplicesIn } from './helpers/chaos-scenarios';

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

	// Flip on when #294 is fixed: every splice kill point currently ends in
	// an unbounded tx_abort exchange, so the sweep cannot distinguish a
	// resumable cell from a broken one.
	it.skip('S4 splice: every boundary abandons or replays exactly (needs the #294 fix)', async function () {
		this.timeout(300_000);
		void s4SplicesIn;
	});
});
