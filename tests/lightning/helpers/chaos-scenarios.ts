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
import { BITCOIN_CHAIN_HASH } from '../../../src/lightning/channel/types';
import { encodeShortChannelId } from '../../../src/lightning/gossip/types';
import { getPublicKey } from '../../../src/lightning/crypto/ecdh';
import {
	IChaosEnv,
	IChaosEnvOptions,
	IChaosScenario,
	buildDirectGraph,
	chaosWait,
	makeChaosNodeConfig,
	openReadyChannelChaos
} from './chaos-harness';

export const CHAOS_VICTIM_SEED = 71;
export const CHAOS_PEER_SEED = 72;
export const CHAOS_THIRD_SEED = 73;

export const CHAOS_ENV: IChaosEnvOptions = {
	victimSeedId: CHAOS_VICTIM_SEED,
	peerSeedIds: [CHAOS_PEER_SEED]
};

/** S2's world: payer, VICTIM FORWARDER, payee. */
export const CHAOS_FORWARD_ENV: IChaosEnvOptions = {
	victimSeedId: CHAOS_VICTIM_SEED,
	peerSeedIds: [CHAOS_PEER_SEED, CHAOS_THIRD_SEED]
};

/** S1a: the victim pays its peer; kills land around the sender's rounds. */
export function s1aSenderPays(): IChaosScenario {
	return {
		name: 'S1a sender pays',
		async setup(env: IChaosEnv): Promise<void> {
			env.channelId = await openReadyChannelChaos(
				env,
				env.victim,
				env.peers[0]
			);
			buildDirectGraph(env.victim, CHAOS_VICTIM_SEED, CHAOS_PEER_SEED);
		},
		async run(env: IChaosEnv): Promise<void> {
			const invoice = env.peers[0].createInvoice({
				amountMsat: 50_000n,
				description: 'chaos S1a'
			});
			// The kill may land anywhere inside this call; the harness owns
			// the outcome, not the return value. The wait is kill-aware and
			// exists for quorum mode, where the rounds complete
			// asynchronously as receipts land; in the synchronous modes the
			// payment is already settled when sendPayment returns.
			const payment = env.victim.sendPayment(invoice.bolt11);
			await chaosWait(env, () => payment.status !== PaymentStatus.PENDING);
			// Drain the round's tail: the final gated revoke may still be
			// waiting on its receipt in quorum mode, and the schedule must
			// record it deterministically.
			await chaosWait(
				env,
				() => env.victim.getRecoveryStatus().awaitingDurabilityCount === 0
			);
		},
		async probe(env: IChaosEnv, restored: LightningNode): Promise<void> {
			buildDirectGraph(restored, CHAOS_VICTIM_SEED, CHAOS_PEER_SEED);
			const invoice = env.peers[0].createInvoice({
				amountMsat: 40_000n,
				description: 'chaos S1a probe'
			});
			const payment = restored.sendPayment(invoice.bolt11);
			await chaosWait(env, () => payment.status !== PaymentStatus.PENDING);
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
		async setup(env: IChaosEnv): Promise<void> {
			env.channelId = await openReadyChannelChaos(
				env,
				env.peers[0],
				env.victim
			);
			buildDirectGraph(env.peers[0], CHAOS_PEER_SEED, CHAOS_VICTIM_SEED);
		},
		async run(env: IChaosEnv): Promise<void> {
			const invoice = env.victim.createInvoice({
				amountMsat: 50_000n,
				description: 'chaos S1b'
			});
			const payment = env.peers[0].sendPayment(invoice.bolt11);
			await chaosWait(env, () => payment.status !== PaymentStatus.PENDING);
			await chaosWait(
				env,
				() => env.victim.getRecoveryStatus().awaitingDurabilityCount === 0
			);
		},
		async probe(env: IChaosEnv, restored: LightningNode): Promise<void> {
			const invoice = restored.createInvoice({
				amountMsat: 40_000n,
				description: 'chaos S1b probe'
			});
			const payment = env.peers[0].sendPayment(invoice.bolt11);
			await chaosWait(env, () => payment.status !== PaymentStatus.PENDING);
			expect(payment.status, 'probe payment after resume').to.equal(
				PaymentStatus.COMPLETED
			);
		}
	};
}

function addGraphChannel(
	node: LightningNode,
	scid: Buffer,
	pubA: Buffer,
	pubB: Buffer
): void {
	const aIs1 = Buffer.compare(pubA, pubB) < 0;
	node.getGraph().addChannelAnnouncement({
		nodeSignature1: Buffer.alloc(64),
		nodeSignature2: Buffer.alloc(64),
		bitcoinSignature1: Buffer.alloc(64),
		bitcoinSignature2: Buffer.alloc(64),
		features: Buffer.alloc(0),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		nodeId1: aIs1 ? pubA : pubB,
		nodeId2: aIs1 ? pubB : pubA,
		bitcoinKey1: Buffer.alloc(33, 2),
		bitcoinKey2: Buffer.alloc(33, 3)
	});
	for (const dir of [0, 1]) {
		node.getGraph().applyChannelUpdate({
			signature: Buffer.alloc(64),
			chainHash: BITCOIN_CHAIN_HASH,
			shortChannelId: scid,
			timestamp: Math.floor(Date.now() / 1000),
			messageFlags: 1,
			channelFlags: dir,
			cltvExpiryDelta: 40,
			htlcMinimumMsat: 1000n,
			feeBaseMsat: 1000,
			feeProportionalMillionths: 1,
			htlcMaximumMsat: 1_000_000_000n
		});
	}
}

/**
 * S2: payer -> VICTIM -> payee, the forwarder dies. The wiring mirrors the
 * forwarding-history harness: the payer's graph knows only its own hop, the
 * payee's invoice hints the second, and the victim resolves the onward
 * channel through its persisted SCID registration. The victim's forward
 * fee is pinned so the payer attaches exactly what the hint promises.
 */
export function s2ForwarderDies(): IChaosScenario {
	return {
		name: 'S2 forwarder dies',
		async setup(env: IChaosEnv): Promise<void> {
			const [payer, payee] = env.peers;
			const inboundId = await openReadyChannelChaos(env, payer, env.victim);
			const outboundId = await openReadyChannelChaos(env, env.victim, payee);
			env.channelId = inboundId;
			const scidIn = encodeShortChannelId({
				block: 830,
				txIndex: 1,
				outputIndex: 0
			});
			const scidOut = encodeShortChannelId({
				block: 830,
				txIndex: 2,
				outputIndex: 0
			});
			env.victim.registerChannelScid(inboundId, scidIn);
			env.victim.registerChannelScid(outboundId, scidOut);
			payer.registerChannelScid(inboundId, scidIn);
			env.victim
				.getChannelManager()
				.getChannel(outboundId)!
				.getFullState().remoteScidAlias = scidOut;
			payee
				.getChannelManager()
				.getChannel(outboundId)!
				.getFullState().remoteScidAlias = scidOut;
			addGraphChannel(
				payer,
				scidIn,
				getPublicKey(makeChaosNodeConfig(CHAOS_PEER_SEED).nodePrivateKey),
				getPublicKey(makeChaosNodeConfig(CHAOS_VICTIM_SEED).nodePrivateKey)
			);
			env.victim.setChannelPolicy(outboundId, {
				feeBaseMsat: 5000,
				feeProportionalMillionths: 0
			});
		},
		async run(env: IChaosEnv): Promise<void> {
			const [payer, payee] = env.peers;
			const invoice = payee.createInvoice({
				amountMsat: 80_000n,
				description: 'chaos S2'
			});
			env.scratch.forwardHash = invoice.paymentHash.toString('hex');
			const payment = payer.sendPayment(invoice.bolt11);
			await chaosWait(env, () => payment.status !== PaymentStatus.PENDING);
			await chaosWait(
				env,
				() => env.victim.getRecoveryStatus().awaitingDurabilityCount === 0
			);
		},
		async probe(env: IChaosEnv, restored: LightningNode): Promise<void> {
			void restored;
			const [payer, payee] = env.peers;
			const invoice = payee.createInvoice({
				amountMsat: 30_000n,
				description: 'chaos S2 probe'
			});
			const payment = payer.sendPayment(invoice.bolt11);
			await chaosWait(env, () => payment.status !== PaymentStatus.PENDING);
			expect(payment.status, 'probe forward after resume').to.equal(
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
		async setup(env: IChaosEnv): Promise<void> {
			env.channelId = await openReadyChannelChaos(
				env,
				env.peers[0],
				env.victim
			);
			buildDirectGraph(env.peers[0], CHAOS_PEER_SEED, CHAOS_VICTIM_SEED);
		},
		async run(env: IChaosEnv): Promise<void> {
			const invoice = env.victim.createInvoice({
				amountMsat: 60_000n,
				description: 'chaos S3',
				hold: true
			});
			env.scratch.holdHash = invoice.paymentHash;
			const payment = env.peers[0].sendPayment(invoice.bolt11);
			// The HTLC parks at the victim; nothing has resolved yet. In
			// quorum mode the add round completes asynchronously, so wait for
			// the park itself (kill-aware) before cancelling, or the cancel
			// races the round and the schedule loses its determinism.
			expect(payment.status, 'held payment still pending').to.equal(
				PaymentStatus.PENDING
			);
			await chaosWait(env, () =>
				env.victim.listHoldInvoices().some((h) => h.state === 'ACCEPTED')
			);
			env.victim.cancelHoldInvoice(invoice.paymentHash);
			await chaosWait(
				env,
				() => env.victim.getRecoveryStatus().awaitingDurabilityCount === 0
			);
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
			await chaosWait(env, () => payment.status !== PaymentStatus.PENDING);
			expect(payment.status, 'probe payment after resume').to.equal(
				PaymentStatus.COMPLETED
			);
		}
	};
}
