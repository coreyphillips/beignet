/**
 * The phase 7 matrix scenarios (docs/RECOVERY-PROTOCOL.md section 9), each
 * an IChaosScenario the record-then-kill driver can rehearse and replay.
 * They live in one module because the matrix has TWO executors over the
 * same scenarios: the in-process harness (fine-grained oracles) and the
 * SIGKILL child (real process death); the cells must mean the same thing
 * in both.
 *
 * Roles are explicit: the VICTIM is the node that dies, whatever its
 * protocol role. S1a kills the payer, S1b kills the payee around its
 * fulfill, S3 kills the payee around a fail it owes on a committed HTLC.
 */

import { expect } from 'chai';
import { PaymentStatus } from '../../../src/lightning/node/types';
import { LightningNode } from '../../../src/lightning/node/lightning-node';
import {
	IChaosEnv,
	IChaosEnvOptions,
	IChaosScenario,
	buildDirectGraph,
	openReadyChannel
} from './chaos-harness';

export const CHAOS_VICTIM_SEED = 71;
export const CHAOS_PEER_SEED = 72;

export const CHAOS_ENV: IChaosEnvOptions = {
	victimSeedId: CHAOS_VICTIM_SEED,
	peerSeedIds: [CHAOS_PEER_SEED]
};

/** S1a: the victim pays its peer; kills land around the sender's rounds. */
export function s1aSenderPays(): IChaosScenario {
	return {
		name: 'S1a sender pays',
		setup(env: IChaosEnv): void {
			env.channelId = openReadyChannel(env.victim, env.peers[0]);
			buildDirectGraph(env.victim, CHAOS_VICTIM_SEED, CHAOS_PEER_SEED);
		},
		run(env: IChaosEnv): void {
			const invoice = env.peers[0].createInvoice({
				amountMsat: 50_000n,
				description: 'chaos S1a'
			});
			// The kill may land anywhere inside this call; the harness owns
			// the outcome, not the return value.
			env.victim.sendPayment(invoice.bolt11);
		},
		probe(env: IChaosEnv, restored: LightningNode): void {
			buildDirectGraph(restored, CHAOS_VICTIM_SEED, CHAOS_PEER_SEED);
			const invoice = env.peers[0].createInvoice({
				amountMsat: 40_000n,
				description: 'chaos S1a probe'
			});
			const payment = restored.sendPayment(invoice.bolt11);
			expect(payment.status, 'probe payment after resume').to.equal(
				PaymentStatus.COMPLETED
			);
		}
	};
}

/**
 * S1b: the peer pays the victim; kills land around the receiver's rounds,
 * in particular its revoke_and_ack and its update_fulfill_htlc, the two
 * irreversible sends a receiver owns.
 */
export function s1bReceiverFulfills(): IChaosScenario {
	return {
		name: 'S1b receiver fulfills',
		setup(env: IChaosEnv): void {
			env.channelId = openReadyChannel(env.peers[0], env.victim);
			buildDirectGraph(env.peers[0], CHAOS_PEER_SEED, CHAOS_VICTIM_SEED);
		},
		run(env: IChaosEnv): void {
			const invoice = env.victim.createInvoice({
				amountMsat: 50_000n,
				description: 'chaos S1b'
			});
			env.peers[0].sendPayment(invoice.bolt11);
		},
		probe(env: IChaosEnv, restored: LightningNode): void {
			const invoice = restored.createInvoice({
				amountMsat: 40_000n,
				description: 'chaos S1b probe'
			});
			const payment = env.peers[0].sendPayment(invoice.bolt11);
			expect(payment.status, 'probe payment after resume').to.equal(
				PaymentStatus.COMPLETED
			);
		}
	};
}

/**
 * S3: the victim owes its peer a fail on a COMMITTED HTLC. A hold invoice
 * parks the inbound HTLC (full add/commit/revoke rounds first), then the
 * cancel drives update_fail_htlc and its own commitment round. That covers
 * the fail boundaries the spec names, on the deliberately harder shape: a
 * fail the restart must remember it owes, not a reject at add time.
 */
export function s3FailsHeldHtlc(): IChaosScenario {
	return {
		name: 'S3 fails a held HTLC',
		setup(env: IChaosEnv): void {
			env.channelId = openReadyChannel(env.peers[0], env.victim);
			buildDirectGraph(env.peers[0], CHAOS_PEER_SEED, CHAOS_VICTIM_SEED);
		},
		run(env: IChaosEnv): void {
			const invoice = env.victim.createInvoice({
				amountMsat: 60_000n,
				description: 'chaos S3',
				hold: true
			});
			env.scratch.holdHash = invoice.paymentHash;
			const payment = env.peers[0].sendPayment(invoice.bolt11);
			// The HTLC parks at the victim; nothing has resolved yet.
			expect(payment.status, 'held payment still pending').to.equal(
				PaymentStatus.PENDING
			);
			env.victim.cancelHoldInvoice(invoice.paymentHash);
		},
		async probe(env: IChaosEnv, restored: LightningNode): Promise<void> {
			// The kill may have landed before the cancel became durable, in
			// which case the held HTLC is legitimately parked again after the
			// restart (the durable truth is that no cancel ever happened).
			// The probe therefore REPEATS the operator's cancel, which is a
			// no-op when the fail already resolved, and only then demands a
			// clean channel: an HTLC neither resolvable nor cancellable is
			// exactly the failure this scenario exists to catch.
			const holdHash = env.scratch.holdHash as Buffer | undefined;
			expect(holdHash, 'scenario stashed its hold hash').to.not.equal(
				undefined
			);
			restored.cancelHoldInvoice(holdHash!);
			const invoice = restored.createInvoice({
				amountMsat: 40_000n,
				description: 'chaos S3 probe'
			});
			const payment = env.peers[0].sendPayment(invoice.bolt11);
			expect(payment.status, 'probe payment after resume').to.equal(
				PaymentStatus.COMPLETED
			);
		}
	};
}
