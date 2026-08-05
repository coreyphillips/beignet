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
import crypto from 'crypto';
import * as ecc from '@bitcoinerlab/secp256k1';
import * as bitcoin from 'bitcoinjs-lib';
import { ChannelState } from '../../src/lightning/channel/types';
import { IFundingProvider } from '../../src/lightning/node/types';
import {
	IChaosEnvOptions,
	makeChaosEnv,
	recordSchedule,
	runKillPoint,
	settle
} from './helpers/chaos-harness';
import { quorumOptions, withNamespace } from './helpers/chaos-quorum';
import {
	CHAOS_ENV,
	makeChaosSpliceWallet,
	s1aSenderPays,
	s4SplicesIn,
	s7OpensV2
} from './helpers/chaos-scenarios';

bitcoin.initEccLib(ecc);

/**
 * A v2 opener funds through the provider's splice-input surface; the
 * deterministic chaos wallet input serves, and v1 funding must never run.
 */
function v2FundingProvider(): IFundingProvider {
	const wallet = makeChaosSpliceWallet(250_000n);
	const changeScript = bitcoin.payments.p2wpkh({
		hash: crypto.randomBytes(20)
	}).output!;
	return {
		buildFundingTransaction: async () => {
			throw new Error('v1 funding must not run for a v2 open');
		},
		broadcastTransaction: async (txHex: string) =>
			bitcoin.Transaction.fromHex(txHex).getId(),
		selectSpliceInputs: async () => ({
			inputs: [wallet.walletInput],
			changeScript
		})
	};
}

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

	it('S7 v2 open: no boundary leaves an orphan temporary row (matrix row 10)', async function () {
		this.timeout(300_000);
		const V2_ENV: IChaosEnvOptions = {
			...CHAOS_ENV,
			victimExtrasFactory: () => ({ fundingProvider: v2FundingProvider() })
		};
		const { schedule } = await recordSchedule('local', s7OpensV2, V2_ENV);
		expect(schedule.length, 'the open produced kill labels').to.be.at.least(4);
		let abandonedCells = 0;
		let promotedCells = 0;
		for (const label of schedule) {
			const result = await runKillPoint('local', s7OpensV2, label, V2_ENV);
			const at = `at ${label}`;
			for (let i = 0; i < 10; i++) await settle();
			const rows = result.restoredStorage.loadAllChannels();
			const tempId = result.env.scratch.tempId as string;
			expect(
				rows.every((row) => row.channelId !== tempId),
				`no orphan temporary row ${at}`
			).to.equal(true);
			expect(rows.length, `at most one channel row ${at}`).to.be.at.most(1);
			if (rows.length === 0) {
				// Nothing durable: the open is abandoned wholesale and the
				// restart carries no debris.
				abandonedCells++;
				expect(
					result.restored.getChannelManager().listChannels().length,
					`clean restart after abandon ${at}`
				).to.equal(0);
			} else {
				// The promotion committed: exactly one row, under the
				// permanent id, and it carries the durable v2 record (the
				// same batch that creates the record writes the first row).
				// The restart rebuilds the builder-less session from it and
				// the reestablish that follows resumes the signature
				// exchange over next_funding, so every promoted cell must
				// COMPLETE the open. This is the kill-matrix acceptance for
				// the formerly process-local window (issues 288/289).
				promotedCells++;
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
		expect(abandonedCells, 'cells that abandoned').to.be.at.least(1);
		expect(promotedCells, 'cells that promoted').to.be.at.least(1);
	});
});
