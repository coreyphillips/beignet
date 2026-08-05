/**
 * Recovery Phase 7, component 8: device-loss verdicts (S10). The disk
 * does not restart; it burns. The node is rebuilt from the guardian trio
 * through the RestoreDriver, and the durability mode decides the verdict:
 *
 * - quorum: EXACT resumption is required, and DLP is a test failure. The
 *   barrier held every gated send until its frame was quorum durable, so
 *   the guardians hold everything the peer ever saw from us; the restore
 *   carries a wire-safety proof and the channel comes back resumable.
 * - async-remote: safe DLP is required, exact resumption is the failure.
 *   Nothing barriered the sends, so the certified head MAY trail what the
 *   lost device told its peers, and phase 6 refuses to prove otherwise
 *   even when replication happens to have caught up: the restored channel
 *   is stateUncertain, must never broadcast its commitment, and resolves
 *   through the surviving peer.
 * - local: degenerate by construction (no replicas, nothing to restore
 *   from); not represented here.
 *
 * The original phase 7 plan sketched "exact when fully replicated" for
 * async-remote; the merged phase 6 semantics are stricter (a head that
 * carries no quorum declaration is unproven no matter how current it
 * happens to be), and these tests pin the implemented contract.
 */

import { expect } from 'chai';
import { MessageType } from '../../src/lightning/message/types';
import { HtlcState } from '../../src/lightning/channel/types';
import {
	RestoreDriver,
	deriveRecoveryRoot
} from '../../src/lightning/recovery';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	IChaosEnv,
	IChaosScenario,
	KillLabel,
	makeChaosEnv,
	makeChaosNodeConfig,
	openChaosStorage,
	postSendLabel,
	restartVictim,
	settle,
	tempDb
} from './helpers/chaos-harness';
import { assertChaosOutcome } from './helpers/chaos-oracle';
import {
	QUORUM_CONTEXT,
	QUORUM_REQUIRED,
	bindServed,
	currentQuorumRun,
	quorumOptions,
	withNamespace
} from './helpers/chaos-quorum';
import {
	CHAOS_ENV,
	CHAOS_VICTIM_SEED,
	s1aSenderPays
} from './helpers/chaos-scenarios';

let clockNow = 2_400_000_000_000n;
const clock = (): bigint => ++clockNow;

/**
 * The kill half of a chaos run (arm, drive, die), without the same-disk
 * restart half: S10 replaces the disk with a guardian restore.
 */
async function killAt(
	env: IChaosEnv,
	scenario: IChaosScenario,
	label: KillLabel
): Promise<void> {
	env.commitTap.arm(label);
	env.relay.arm(label);
	try {
		await scenario.run(env);
	} catch (err) {
		if (!env.kill.killed) throw err;
	}
	await settle();
	expect(env.kill.killed, `kill label ${label} fired`).to.equal(true);
}

/**
 * Device loss: restore from the live trio into a FRESH file and point the
 * env at it, so restartVictim boots the restored device instead of the
 * burned one. Returns the driver's outcome for the verdict assertions.
 */
async function restoreFromGuardians(
	env: IChaosEnv
): Promise<{ wireSafetyProof: unknown; freshPath: string }> {
	const run = currentQuorumRun();
	const priv = makeChaosNodeConfig(CHAOS_VICTIM_SEED).nodePrivateKey;
	const freshPath = tempDb('chaos-restore');
	const target = openChaosStorage(freshPath);
	const driver = new RestoreDriver({
		target,
		guardians: bindServed(run.served),
		context: QUORUM_CONTEXT,
		required: QUORUM_REQUIRED,
		recoveryRoot: deriveRecoveryRoot(priv),
		nodeSecret: priv,
		nodeId: getPublicKey(priv),
		clock
	});
	const result = await driver.restore();
	target.close();
	env.dbPath = freshPath;
	return { wireSafetyProof: result.wireSafetyProof, freshPath };
}

describe('Recovery phase 7: device-loss verdicts (S10)', () => {
	it('quorum: a device lost after a gated send restores EXACTLY, wire-safety proof in hand', async function () {
		this.timeout(120_000);
		const options = quorumOptions({}, CHAOS_ENV);
		const scenario = withNamespace(s1aSenderPays)();
		const env = await makeChaosEnv('quorum', options);
		try {
			await scenario.setup(env);
			await killAt(env, scenario, postSendLabel(MessageType.REVOKE_AND_ACK, 1));

			const { wireSafetyProof } = await restoreFromGuardians(env);
			expect(
				wireSafetyProof,
				'the quorum head yielded a wire-safety proof'
			).to.not.equal(undefined);
			const restoredDisk = openChaosStorage(env.dbPath);
			const row = restoredDisk.loadAllChannels()[0];
			expect(row, 'the channel came back').to.not.equal(undefined);
			expect(
				row.state.stateUncertain,
				'the restored channel is NOT stateUncertain'
			).to.equal(undefined);
			restoredDisk.close();

			const result = await restartVictim(env, options);
			await assertChaosOutcome(result, 'exact-resume');
			result.destroyAll();
		} finally {
			env.victim.destroy();
			for (const peer of env.peers) peer.destroy();
			await options.teardown?.(env);
		}
	});

	it('async-remote: a lost device restores into safe DLP even when replication kept up', async function () {
		this.timeout(120_000);
		const options = quorumOptions({}, CHAOS_ENV, 'async-remote');
		const scenario = withNamespace(s1aSenderPays)();
		const env = await makeChaosEnv('async-remote', options);
		try {
			await scenario.setup(env);
			await killAt(
				env,
				scenario,
				postSendLabel(MessageType.COMMITMENT_SIGNED, 1)
			);
			// Let in-flight replication of already-written frames land before
			// the restore reads the head: the point is that even a CURRENT
			// async-remote head proves nothing.
			currentQuorumRun().barrier.kickReplication();
			for (let i = 0; i < 20; i++) await settle();

			const { wireSafetyProof } = await restoreFromGuardians(env);
			expect(wireSafetyProof, 'no proof without quorum').to.equal(undefined);
			const restoredDisk = openChaosStorage(env.dbPath);
			expect(
				restoredDisk.loadAllChannels()[0]?.state.stateUncertain,
				'the restored channel is stateUncertain'
			).to.equal(true);
			restoredDisk.close();

			const result = await restartVictim(env, options);
			await assertChaosOutcome(result, 'safe-dlp');
			result.destroyAll();
		} finally {
			env.victim.destroy();
			for (const peer of env.peers) peer.destroy();
			await options.teardown?.(env);
		}
	});

	it('async-remote: a head that trails the wire still restores into safe DLP, minus what never replicated', async function () {
		this.timeout(120_000);
		const options = quorumOptions({}, CHAOS_ENV, 'async-remote');
		const scenario = withNamespace(s1aSenderPays)();
		const env = await makeChaosEnv('async-remote', options);
		try {
			await scenario.setup(env);
			// Cut replication AFTER the opening replicated: everything the
			// payment writes stays device-local, so the guardians' head
			// trails what the peer saw by the whole payment.
			currentQuorumRun().setBlocked(true);
			await killAt(
				env,
				scenario,
				postSendLabel(MessageType.COMMITMENT_SIGNED, 1)
			);
			currentQuorumRun().setBlocked(false);

			const { wireSafetyProof } = await restoreFromGuardians(env);
			expect(wireSafetyProof, 'no proof without quorum').to.equal(undefined);
			const restoredDisk = openChaosStorage(env.dbPath);
			const row = restoredDisk.loadAllChannels()[0];
			expect(
				row?.state.stateUncertain,
				'the restored channel is stateUncertain'
			).to.equal(true);
			// The payment never replicated: the restored state predates it.
			const htlcs = row ? [...row.state.htlcs.values()] : [];
			expect(
				htlcs.some(
					(h) =>
						h.state === HtlcState.PENDING || h.state === HtlcState.COMMITTED
				),
				'the never-replicated HTLC is absent from the restore'
			).to.equal(false);
			restoredDisk.close();

			const result = await restartVictim(env, options);
			await assertChaosOutcome(result, 'safe-dlp');
			result.destroyAll();
		} finally {
			env.victim.destroy();
			for (const peer of env.peers) peer.destroy();
			await options.teardown?.(env);
		}
	});
});
