/**
 * Shared quorum fixtures for the phase 7 chaos sweeps: three real
 * guardians over real HTTP per run, a genesis registration, a real
 * DurabilityBarrier and GuardianReplicator built outside the node exactly
 * as an integrator builds them, and on restart a NEW barrier over the
 * reopened storage with the lease the dead process persisted, because a
 * quorum journal refuses to start unbarriered. One mutable current-run
 * holder is enough: chaos runs are strictly sequential, and a fresh trio
 * per run keeps guardian state from leaking across runs (every run
 * re-registers the same recovery namespace).
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { INodeConfig } from '../../../src/lightning/node/types';
import { ChannelState } from '../../../src/lightning/channel/types';
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
} from '../../../src/lightning/recovery';
import {
	IChaosEnv,
	IChaosEnvOptions,
	IChaosScenario,
	KillSwitch,
	makeChaosNodeConfig
} from './chaos-harness';
import { CHAOS_ENV, CHAOS_VICTIM_SEED } from './chaos-scenarios';

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

export interface IServed {
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
export interface IQuorumRun {
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

/** The live run's wiring (blocked gate, barrier, replicator, trio). */
export function currentQuorumRun(): IQuorumRun {
	if (!current) throw new Error('no quorum run is active');
	return current;
}

/** The guardian-set context, for tests that drive a RestoreDriver. */
export const QUORUM_CONTEXT = CONTEXT;
export const QUORUM_REQUIRED = CRASH_V1_PROFILE.required;

/** Bind the live trio's clients the way a RestoreDriver consumes them. */
export function bindServed(served: IServed[]): IBoundGuardianClient[] {
	return served.map((entry) => ({
		client: entry.client,
		expectedGuardianId: entry.id
	}));
}

export function quorumOptions(
	overrides: Partial<Pick<IQuorumRun, 'wrapBarrier' | 'barrierTimeoutMs'>> = {},
	base: IChaosEnvOptions = CHAOS_ENV,
	durability: 'quorum' | 'async-remote' = 'quorum'
): IChaosEnvOptions {
	return {
		...base,
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
					durability,
					replicator,
					lease: (): IWriterLeaseKeys | null => run.lease,
					timeoutMs: run.barrierTimeoutMs,
					retryDelayMs: 40
				});
				current = run;
				const barrier = (run.wrapBarrier?.(run.barrier, kill) ??
					run.barrier) as DurabilityBarrier;
				return { enabled: true, durability, barrier };
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
				durability,
				replicator,
				lease: (): IWriterLeaseKeys | null => run.lease,
				timeoutMs: run.barrierTimeoutMs,
				retryDelayMs: 40
			});
			return { enabled: true, durability, barrier: run.barrier };
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
export function withNamespace(
	factory: () => IChaosScenario
): () => IChaosScenario {
	return (): IChaosScenario => {
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
						[env.victim, ...env.peers].every((node) =>
							node
								.getChannelManager()
								.listChannels()
								.every((c) => c.getState() === ChannelState.NORMAL)
						)
				);
			}
		};
	};
}

export async function waitFor(
	condition: () => boolean,
	timeoutMs = 10_000
): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (!condition()) {
		if (Date.now() > deadline) throw new Error('waitFor timed out');
		await new Promise((resolve) => setTimeout(resolve, 20));
	}
}
