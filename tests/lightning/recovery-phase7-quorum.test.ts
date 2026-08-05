/**
 * Recovery Phase 7, component 3: the quorum sweep
 * (docs/RECOVERY-PROTOCOL.md section 9, Phase 7). Kill before and after
 * the guardian ACK, and everywhere else, with the victim in quorum mode
 * against three REAL guardians over real HTTP. Same-disk restarts must
 * resume exactly in every cell: in quorum mode a kill at a barrier point
 * that ended in DLP would be a product failure, because the mode's whole
 * promise is that nothing irreversible reaches the peer before a quorum
 * can restore it.
 *
 * The ACK cells are hand-driven choreographies rather than recorded
 * labels, keyed on frame COVERAGE (what the guardians durably hold),
 * never on receipt arrival order, because receipt timing over real HTTP
 * is not deterministic while coverage is:
 *
 *   pre-ack        the frame is committed locally, put_state is in
 *                  flight, NO quorum holds it, the batch is parked.
 *   post-release   a quorum holds it, the barrier released, the process
 *                  dies before the socket write.
 *   refusal        the barrier timed out (freeze, not proceed), THEN the
 *                  process dies.
 *   sub-quorum     exactly one guardian of three holds the frame, which
 *                  is not a quorum, the batch is parked.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { INodeConfig } from '../../src/lightning/node/types';
import { MessageType } from '../../src/lightning/message/types';
import { ChannelState } from '../../src/lightning/channel/types';
import {
	CRASH_V1_PROFILE,
	DurabilityBarrier,
	GuardianClient,
	GuardianHttpServer,
	GuardianReplicator,
	IBoundGuardianClient,
	IWriterLeaseKeys,
	ReferenceGuardian,
	computeGuardianSetId,
	deriveRecoveryRoot,
	loadWriterLease,
	nodeGuardianTransport,
	xOnlyFromSecret
} from '../../src/lightning/recovery';
import {
	IChaosEnv,
	IChaosEnvOptions,
	KillSwitch,
	makeChaosEnv,
	makeChaosNodeConfig,
	postSendLabel,
	restartVictim,
	runKillMatrix,
	settle
} from './helpers/chaos-harness';
import { assertChaosOutcome } from './helpers/chaos-oracle';
import {
	CHAOS_ENV,
	CHAOS_VICTIM_SEED,
	s1aSenderPays,
	s1bReceiverFulfills
} from './helpers/chaos-scenarios';

const sha = (s: string): Buffer =>
	crypto.createHash('sha256').update(s).digest();

const GUARDIAN_SECRETS = [1, 2, 3].map((i) => sha(`p7-quorum-guardian-${i}`));
const GUARDIAN_IDS = GUARDIAN_SECRETS.map((s) => xOnlyFromSecret(s));
const SET_ID = computeGuardianSetId({
	...CRASH_V1_PROFILE,
	guardianIds: GUARDIAN_IDS
});
const CONTEXT = { guardianSetId: SET_ID, members: GUARDIAN_IDS };

let now = 2_300_000_000_000n;
const clock = (): bigint => ++now;

interface IServed {
	guardian: ReferenceGuardian;
	server: GuardianHttpServer;
	client: GuardianClient;
	id: Buffer;
}

async function serve(index: number): Promise<IServed> {
	const guardian = new ReferenceGuardian({
		path: ':memory:',
		guardianSecret: GUARDIAN_SECRETS[index],
		members: GUARDIAN_IDS,
		clock
	});
	const server = new GuardianHttpServer({ guardian });
	const port = await server.listen(0);
	const client = new GuardianClient({
		url: `http://127.0.0.1:${port}`,
		guardianSetId: SET_ID
	});
	return { guardian, server, client, id: GUARDIAN_IDS[index] };
}

async function shutdown(served: IServed[]): Promise<void> {
	for (const entry of served) {
		try {
			await entry.server.close();
			entry.guardian.close();
		} catch {
			// Already closed by the test.
		}
	}
}

/** Endpoints whose put_state calls are held open while blocked() is true. */
function gateable(
	served: IServed[],
	blocked: (index: number) => boolean
): IBoundGuardianClient[] {
	return served.map((entry, index) => ({
		expectedGuardianId: entry.id,
		client: new GuardianClient({
			url: entry.client.url,
			guardianSetId: SET_ID,
			transport: async (
				url,
				init
			): Promise<{ status: number; body: Buffer }> => {
				if (url.endsWith('/put_state')) {
					while (blocked(index)) {
						await new Promise((resolve) => setTimeout(resolve, 10));
					}
				}
				return nodeGuardianTransport()(url, init);
			}
		})
	}));
}

/**
 * Per-run quorum wiring shared between the option callbacks and the test
 * body. Runs are strictly sequential, so one mutable holder suffices; a
 * fresh trio per run keeps guardian state from leaking across runs (every
 * run re-registers the same recovery namespace).
 */
interface IQuorumRun {
	served: IServed[];
	blocked: (index: number) => boolean;
	setBlocked: (value: boolean | ((index: number) => boolean)) => void;
	barrier: DurabilityBarrier;
	replicator: GuardianReplicator;
	lease: IWriterLeaseKeys | null;
	wrapBarrier?: (barrier: DurabilityBarrier, kill: KillSwitch) => unknown;
	barrierTimeoutMs: number;
}

let current: IQuorumRun | null = null;

function quorumOptions(
	overrides: Partial<Pick<IQuorumRun, 'wrapBarrier' | 'barrierTimeoutMs'>> = {}
): IChaosEnvOptions {
	return {
		...CHAOS_ENV,
		victimRecoveryFactory: async ({
			storage,
			phase,
			kill
		}): Promise<INodeConfig['recovery']> => {
			if (phase === 'initial') {
				let gate: boolean | ((index: number) => boolean) = false;
				const blocked = (index: number): boolean =>
					typeof gate === 'boolean' ? gate : gate(index);
				const served = await Promise.all([serve(0), serve(1), serve(2)]);
				const root = deriveRecoveryRoot(
					makeChaosNodeConfig(CHAOS_VICTIM_SEED).nodePrivateKey
				);
				const replicator = new GuardianReplicator({
					storage,
					guardians: gateable(served, blocked),
					context: CONTEXT,
					required: CRASH_V1_PROFILE.required,
					recoveryRoot: root,
					clock
				});
				const run: IQuorumRun = {
					served,
					blocked,
					setBlocked: (value): void => {
						gate = value;
					},
					replicator,
					lease: null,
					barrier: null as unknown as DurabilityBarrier,
					wrapBarrier: overrides.wrapBarrier,
					barrierTimeoutMs: overrides.barrierTimeoutMs ?? 20_000
				};
				run.barrier = new DurabilityBarrier({
					durability: 'quorum',
					replicator,
					lease: (): IWriterLeaseKeys | null => run.lease,
					timeoutMs: run.barrierTimeoutMs,
					retryDelayMs: 40
				});
				current = run;
				const barrier = (run.wrapBarrier?.(run.barrier, kill) ??
					run.barrier) as DurabilityBarrier;
				return { enabled: true, durability: 'quorum', barrier };
			}
			// Restored: a new replicator and barrier over the reopened
			// storage, against the SAME still-serving trio, with the lease
			// the dead process persisted. A quorum journal refuses to start
			// unbarriered, which is exactly what this factory exists to
			// satisfy.
			const run = current!;
			const loaded = loadWriterLease(storage);
			expect(loaded.state, 'the dead process had persisted its lease').to.equal(
				'present'
			);
			run.lease = (loaded as { lease: IWriterLeaseKeys }).lease;
			const replicator = new GuardianReplicator({
				storage,
				guardians: gateable(run.served, run.blocked),
				context: CONTEXT,
				required: CRASH_V1_PROFILE.required,
				recoveryRoot: deriveRecoveryRoot(
					makeChaosNodeConfig(CHAOS_VICTIM_SEED).nodePrivateKey
				),
				clock
			});
			run.replicator = replicator;
			run.barrier = new DurabilityBarrier({
				durability: 'quorum',
				replicator,
				lease: (): IWriterLeaseKeys | null => run.lease,
				timeoutMs: run.barrierTimeoutMs,
				retryDelayMs: 40
			});
			return { enabled: true, durability: 'quorum', barrier: run.barrier };
		},
		afterRestart: async (): Promise<void> => {
			// Gateless quorum node: kicking replication is the integrator's
			// job, and the restart IS the integrator here.
			current!.barrier.kickReplication();
		},
		teardown: async (): Promise<void> => {
			if (!current) return;
			await shutdown(current.served);
			current = null;
		}
	};
}

/**
 * Quorum scenarios must register the namespace before the channel opens:
 * nothing is provable until it exists, and the lease is what the barrier's
 * closure serves from then on.
 */
function withNamespace(
	factory: () => ReturnType<typeof s1aSenderPays>
): () => ReturnType<typeof s1aSenderPays> {
	return (): ReturnType<typeof s1aSenderPays> => {
		const inner = factory();
		return {
			...inner,
			async setup(env: IChaosEnv): Promise<void> {
				const decision = await current!.replicator.ensureNamespace();
				expect(decision.outcome, 'namespace registered').to.equal('registered');
				current!.lease = (decision as { lease: IWriterLeaseKeys }).lease;
				await inner.setup(env);
				// The opening traffic itself crosses the barrier (the
				// acceptor's funding_signed and the opener's broadcast
				// authorization are barrier-class), so openReadyChannel
				// returns with the tail of the open still parked. Wait for
				// BOTH sides to reach NORMAL and the watermark to move
				// before the scenario acts, or the rehearsal races the
				// opening's own releases.
				await waitFor(
					() =>
						current!.barrier.watermark() > 0n &&
						env.victim.getChannelManager().listChannels()[0]?.getState() ===
							ChannelState.NORMAL &&
						env.peers[0].getChannelManager().listChannels()[0]?.getState() ===
							ChannelState.NORMAL
				);
			}
		};
	};
}

async function waitFor(
	condition: () => boolean,
	timeoutMs = 10_000
): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (!condition()) {
		if (Date.now() > deadline) throw new Error('waitFor timed out');
		await new Promise((resolve) => setTimeout(resolve, 20));
	}
}

describe('Recovery phase 7: quorum kill sweeps (real guardians over HTTP)', () => {
	it('S1a sender: every commit and send boundary resumes exactly in quorum mode', async function () {
		this.timeout(300_000);
		const { schedule, executed } = await runKillMatrix(
			'quorum',
			withNamespace(s1aSenderPays),
			() => 'exact-resume',
			assertChaosOutcome,
			quorumOptions()
		);
		expect(executed).to.equal(schedule.length);
		expect(
			schedule.includes(postSendLabel(MessageType.COMMITMENT_SIGNED, 1)),
			'the sweep crossed the gated commitment boundary'
		).to.equal(true);
	});

	it('pre-ack: killed while the frame is at NO guardian, the peer saw nothing and the restart resumes', async function () {
		this.timeout(60_000);
		const options = quorumOptions();
		const scenario = withNamespace(s1aSenderPays)();
		const env = await makeChaosEnv('quorum', options);
		try {
			await scenario.setup(env);
			const preKillSends = env.relay.captured.length;

			// From here the guardians answer nothing: the commitment's frame
			// commits locally, replication stalls, the batch parks.
			current!.setBlocked(true);
			const invoice = env.peers[0].createInvoice({
				amountMsat: 30_000n,
				description: 'chaos quorum pre-ack'
			});
			try {
				env.victim.sendPayment(invoice.bolt11);
			} catch {
				// A parked commitment means the send does not complete here.
			}
			await waitFor(
				() => env.victim.getRecoveryStatus().awaitingDurabilityCount > 0
			);

			// Nothing gated reached the peer while the frame was uncovered.
			const sentWhileParked = env.relay.captured.slice(preKillSends);
			expect(
				sentWhileParked.map((m) => m.type),
				'no gated message left while parked'
			).to.not.include(MessageType.COMMITMENT_SIGNED);

			// SIGKILL while parked; the new process's transports are fresh, so
			// the guardians answer it.
			env.kill.fire('pre-ack:parked');
			await settle();
			current!.setBlocked(false);
			const result = await restartVictim(env, options);
			try {
				await scenario.probe(result.env, result.restored);
				await assertChaosOutcome(result, 'exact-resume');
			} finally {
				result.destroyAll();
			}
		} finally {
			await options.teardown!(env);
		}
	});

	it('post-release: killed between the quorum receipt and the socket write, the restart delivers the commitment', async function () {
		this.timeout(60_000);
		let released: bigint | null = null;
		// The channel OPENING crosses the barrier too (broadcast
		// authorization); the tap must only fire for the payment's release,
		// so it stays disarmed until setup completes.
		const armed = { val: false };
		const options = quorumOptions({
			// A full delegating Proxy, not a hand-rolled interface object: the
			// node consumes the concrete DurabilityBarrier surface (onFenced,
			// kickReplication, snapshot), and only whenReleased is tapped.
			wrapBarrier: (barrier, kill): unknown =>
				new Proxy(barrier, {
					get(target, prop, receiver): unknown {
						if (prop === 'whenReleased') {
							return async (
								sequence: bigint | null
							): Promise<{ released: boolean; reason: string }> => {
								const outcome = await target.whenReleased(sequence);
								if (
									armed.val &&
									outcome.released &&
									released === null &&
									sequence !== null
								) {
									// The receipt arrived and the barrier
									// released; the process dies before
									// _dispatchHeld reaches the socket.
									released = sequence;
									kill.fire(`post-release:f${sequence}`);
								}
								return outcome;
							};
						}
						const value = Reflect.get(target, prop, receiver);
						return typeof value === 'function' ? value.bind(target) : value;
					}
				})
		});
		const scenario = withNamespace(s1aSenderPays)();
		const env = await makeChaosEnv('quorum', options);
		try {
			await scenario.setup(env);
			armed.val = true;

			current!.setBlocked(true);
			const invoice = env.peers[0].createInvoice({
				amountMsat: 30_000n,
				description: 'chaos quorum post-release'
			});
			try {
				env.victim.sendPayment(invoice.bolt11);
			} catch {
				// Parked until the release fires the kill.
			}
			await waitFor(
				() => env.victim.getRecoveryStatus().awaitingDurabilityCount > 0
			);
			const preReleaseSends = env.relay.captured.length;
			current!.setBlocked(false);
			await waitFor(() => env.kill.killed);

			// Released but never sent: the peer got nothing after the park.
			expect(
				env.relay.captured.slice(preReleaseSends).map((m) => m.type),
				'the released bytes never reached the peer'
			).to.deep.equal([]);

			const result = await restartVictim(env, options);
			try {
				// The frame was quorum-durable, so the dead process's outbox
				// carries the commitment the peer never received.
				const disk = JSON.parse(result.postKillDump) as {
					outbox: string[][];
				};
				expect(
					disk.outbox.filter(
						(row) => Number(row[2]) === MessageType.COMMITMENT_SIGNED
					).length,
					'the dead process left commitment bytes in its outbox'
				).to.be.greaterThan(0);
				// The restart must deliver the commitment the release
				// authorized. On this plain channel the reestablish rebuild
				// re-signs it (byte-exact outbox replay is the taproot batch
				// path, covered by the session sweeps); in quorum mode the
				// re-send parks behind its own fresh frame, so wait for it
				// rather than sampling the wire immediately.
				await waitFor(() =>
					result.env.relay.captured.some(
						(m) => m.type === MessageType.COMMITMENT_SIGNED
					)
				);
				await scenario.probe(result.env, result.restored);
				await assertChaosOutcome(result, 'exact-resume');
			} finally {
				result.destroyAll();
			}
		} finally {
			await options.teardown!(env);
		}
	});

	it('refusal then kill: a barrier timeout freezes, and dying frozen still resumes exactly', async function () {
		this.timeout(60_000);
		const options = quorumOptions({ barrierTimeoutMs: 400 });
		const scenario = withNamespace(s1aSenderPays)();
		const env = await makeChaosEnv('quorum', options);
		try {
			await scenario.setup(env);
			const frozen: string[] = [];
			env.victim.on('node:error', (err: { code?: string }) => {
				if (err.code === 'DURABILITY_BARRIER_TIMEOUT') frozen.push(err.code);
			});

			current!.setBlocked(true);
			const preSends = env.relay.captured.length;
			const invoice = env.peers[0].createInvoice({
				amountMsat: 30_000n,
				description: 'chaos quorum refusal'
			});
			try {
				env.victim.sendPayment(invoice.bolt11);
			} catch {
				// The refusal drops the held bytes.
			}
			await waitFor(() => frozen.length > 0);
			expect(
				env.relay.captured.slice(preSends).map((m) => m.type),
				'freeze, not proceed'
			).to.not.include(MessageType.COMMITMENT_SIGNED);

			env.kill.fire('refusal:frozen');
			await settle();
			current!.setBlocked(false);
			const result = await restartVictim(env, options);
			try {
				await scenario.probe(result.env, result.restored);
				await assertChaosOutcome(result, 'exact-resume');
			} finally {
				result.destroyAll();
			}
		} finally {
			await options.teardown!(env);
		}
	});

	it('sub-quorum: one guardian of three holding the frame is not a quorum; killed there, the restart resumes', async function () {
		this.timeout(60_000);
		const options = quorumOptions();
		const scenario = withNamespace(s1aSenderPays)();
		const env = await makeChaosEnv('quorum', options);
		try {
			await scenario.setup(env);

			// Guardian 0 answers, 1 and 2 do not: coverage 1 of 3 < required 2.
			current!.setBlocked((index: number) => index !== 0);
			const preSends = env.relay.captured.length;
			const invoice = env.peers[0].createInvoice({
				amountMsat: 30_000n,
				description: 'chaos quorum sub-quorum'
			});
			try {
				env.victim.sendPayment(invoice.bolt11);
			} catch {
				// Parked behind a sub-quorum.
			}
			await waitFor(
				() => env.victim.getRecoveryStatus().awaitingDurabilityCount > 0
			);
			// Give the single answering guardian time to prove one receipt is
			// NOT a release.
			await new Promise((resolve) => setTimeout(resolve, 300));
			expect(
				env.relay.captured.slice(preSends).map((m) => m.type),
				'a single receipt released nothing'
			).to.not.include(MessageType.COMMITMENT_SIGNED);

			env.kill.fire('pre-ack:sub-quorum');
			await settle();
			current!.setBlocked(false);
			const result = await restartVictim(env, options);
			try {
				await scenario.probe(result.env, result.restored);
				await assertChaosOutcome(result, 'exact-resume');
			} finally {
				result.destroyAll();
			}
		} finally {
			await options.teardown!(env);
		}
	});

	it('S1b receiver: boundaries outside the redispatch-defect window resume exactly in quorum mode', async function () {
		this.timeout(300_000);
		// The same #291 window as the non-quorum sweeps; flip to a full sweep
		// when fix/reestablish-redispatch merges.
		const windowHolder: { window: Set<string> | null } = { window: null };
		const { schedule, executed } = await runKillMatrix(
			'quorum',
			withNamespace(s1bReceiverFulfills),
			(label, fullSchedule) => {
				if (windowHolder.window === null) {
					const opens = fullSchedule.indexOf(
						postSendLabel(MessageType.COMMITMENT_SIGNED, 1)
					);
					const resolveIdx = fullSchedule.indexOf(
						postSendLabel(MessageType.UPDATE_FULFILL_HTLC, 1)
					);
					windowHolder.window = new Set(
						fullSchedule.slice(opens + 1, resolveIdx - 1)
					);
				}
				return windowHolder.window.has(label) ? 'skip' : 'exact-resume';
			},
			assertChaosOutcome,
			quorumOptions()
		);
		expect(executed).to.equal(schedule.length - windowHolder.window!.size);
	});
});
