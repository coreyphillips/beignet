/**
 * Recovery Phase 7, component 1: the chaos harness proves itself on the
 * simplest scenario in the matrix. S1a: a payer with a journaled channel
 * pays its peer, and the harness kills it at every commit and send boundary
 * the payment crosses, in local durability mode. Every cell must end in
 * exact resumption (same-disk restart, SQLite atomicity plus outbox replay
 * make even local mode exact).
 *
 * The harness details under test here, beyond the cells themselves: the
 * rehearsal records a deterministic schedule; the structural
 * persist-before-send invariant holds on that schedule (the "kill after
 * send before its commit" cell provably does not exist); a pre-commit kill
 * leaves no trace of the interrupted transition on disk; and a label that
 * cannot fire is a hard failure, not a silent skip.
 */

import { expect } from 'chai';
import { MessageType } from '../../src/lightning/message/types';
import {
	postSendLabel,
	recordSchedule,
	runKillMatrix,
	runKillPoint
} from './helpers/chaos-harness';
import { assertChaosOutcome } from './helpers/chaos-oracle';
import { CHAOS_ENV, s1aSenderPays } from './helpers/chaos-scenarios';

const ENV = CHAOS_ENV;

describe('Recovery phase 7: chaos harness (S1a, local mode)', () => {
	it('rehearsal records a deterministic schedule with commit and send boundaries', async function () {
		this.timeout(20_000);
		const first = await recordSchedule('local', s1aSenderPays, ENV);
		const second = await recordSchedule('local', s1aSenderPays, ENV);
		expect(first.schedule, 'two rehearsals disagree').to.deep.equal(
			second.schedule
		);
		expect(
			first.schedule.some((l) => l.startsWith('pre-commit:')),
			'no commit boundaries recorded'
		).to.equal(true);
		expect(
			first.schedule.some((l) => l.startsWith('post-commit:')),
			'no completed commits recorded'
		).to.equal(true);
		expect(
			first.schedule.includes(postSendLabel(MessageType.COMMITMENT_SIGNED, 1)),
			'commitment_signed never crossed the wire'
		).to.equal(true);
		expect(
			first.schedule.includes(postSendLabel(MessageType.REVOKE_AND_ACK, 1)),
			'revoke_and_ack never crossed the wire'
		).to.equal(true);
	});

	it('a pre-commit kill leaves the interrupted transition nowhere on disk', async function () {
		this.timeout(20_000);
		const { schedule } = await recordSchedule('local', s1aSenderPays, ENV);
		const firstPreCommit = schedule.find((l) => l.startsWith('pre-commit:'));
		expect(firstPreCommit, 'schedule holds a pre-commit label').to.not.equal(
			undefined
		);
		const result = await runKillPoint(
			'local',
			s1aSenderPays,
			firstPreCommit!,
			ENV
		);
		try {
			const disk = JSON.parse(result.postKillDump) as {
				channels: unknown[];
				payments: unknown[];
				htlcPaymentMappings: unknown[];
				outbox: unknown[];
			};
			// The channel from setup is durable; the payment the kill
			// interrupted before its first commit is nowhere.
			expect(disk.channels.length, 'setup channel survived').to.equal(1);
			expect(disk.payments, 'no payment row').to.deep.equal([]);
			expect(disk.htlcPaymentMappings, 'no HTLC mapping').to.deep.equal([]);
			expect(disk.outbox, 'no outbox rows').to.deep.equal([]);
			// Probe first, oracle second, the matrix runner's order:
			// ReplayRequired legitimately persists until the next commitment
			// activity, and the probe IS that activity.
			await s1aSenderPays().probe(result.env, result.restored);
			await assertChaosOutcome(result, 'exact-resume');
		} finally {
			result.destroyAll();
		}
	});

	it('kills at every recorded boundary and every run resumes exactly', async function () {
		this.timeout(120_000);
		const { schedule, executed } = await runKillMatrix(
			'local',
			s1aSenderPays,
			() => 'exact-resume',
			assertChaosOutcome,
			ENV
		);
		expect(executed, 'every recorded label was executed').to.equal(
			schedule.length
		);
	});

	it('a label that cannot fire is a hard failure, never a silent skip', async function () {
		this.timeout(20_000);
		let failure: Error | null = null;
		try {
			await runKillPoint(
				'local',
				s1aSenderPays,
				postSendLabel(MessageType.PING, 99),
				ENV
			);
		} catch (err) {
			failure = err as Error;
		}
		expect(failure, 'bogus label must fail').to.not.equal(null);
		expect(String(failure?.message)).to.contain('never fired');
	});
});
