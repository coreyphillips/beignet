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
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { PaymentStatus } from '../../../src/lightning/node/types';
import type { ISpliceWalletInput } from '../../../src/lightning/channel/channel';
import { LightningNode } from '../../../src/lightning/node/lightning-node';
import {
	BITCOIN_CHAIN_HASH,
	ChannelState
} from '../../../src/lightning/channel/types';
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

/**
 * S6: the victim initiates a cooperative close and dies somewhere inside
 * the negotiation. On a taproot channel the closing session (nonces,
 * signed-latch, cache) is in-memory BY DESIGN (transition matrix section
 * 3: journaling it would be exactly the nonce reuse 5.10 forbids), so a
 * restart renegotiates with a fresh session. The setup routes one payment
 * first so the close carries real balances.
 */
export function s6CoopCloses(): IChaosScenario {
	return {
		name: 'S6 cooperative close',
		async setup(env: IChaosEnv): Promise<void> {
			env.channelId = await openReadyChannelChaos(
				env,
				env.victim,
				env.peers[0]
			);
			buildDirectGraph(env.victim, CHAOS_VICTIM_SEED, CHAOS_PEER_SEED);
			const invoice = env.peers[0].createInvoice({
				amountMsat: 50_000n,
				description: 'chaos S6 setup'
			});
			const payment = env.victim.sendPayment(invoice.bolt11);
			await chaosWait(env, () => payment.status === PaymentStatus.COMPLETED);
			await chaosWait(
				env,
				() => env.victim.getRecoveryStatus().awaitingDurabilityCount === 0
			);
		},
		async run(env: IChaosEnv): Promise<void> {
			const destination = Buffer.concat([
				Buffer.from([0x00, 0x14]),
				Buffer.alloc(20, 7)
			]);
			const result = env.victim.closeChannel(env.channelId!, destination);
			expect(result.ok, 'close initiated').to.equal(true);
			await chaosWait(env, () => {
				const channel = env.victim
					.getChannelManager()
					.getChannel(env.channelId!);
				return !channel || channel.getState() === ChannelState.CLOSED;
			});
		},
		probe(): void {
			// Verdicts are cell-dependent (a kill before the shutdown commit
			// legitimately resumes NORMAL); the sweep supplies its own
			// assertOutcome and leaves this unused.
		}
	};
}

/**
 * S9: the victim force-closes and dies between planning and the chain.
 * The terminal path deliberately bypasses the barrier queue (an operator's
 * last exit must be unrefusable), so its cells are about the DECISION
 * surviving: killed before the close commit, nothing moved and the channel
 * resumes; killed after, the restart must hold FORCE_CLOSED with its chain
 * monitor durable beside it (transition matrix row: chain monitor deltas
 * ride their causal transition).
 */
export function s9ForceCloses(): IChaosScenario {
	return {
		name: 'S9 force close',
		async setup(env: IChaosEnv): Promise<void> {
			env.channelId = await openReadyChannelChaos(
				env,
				env.victim,
				env.peers[0]
			);
			buildDirectGraph(env.victim, CHAOS_VICTIM_SEED, CHAOS_PEER_SEED);
			const invoice = env.peers[0].createInvoice({
				amountMsat: 50_000n,
				description: 'chaos S9 setup'
			});
			const payment = env.victim.sendPayment(invoice.bolt11);
			await chaosWait(env, () => payment.status === PaymentStatus.COMPLETED);
			await chaosWait(
				env,
				() => env.victim.getRecoveryStatus().awaitingDurabilityCount === 0
			);
		},
		async run(env: IChaosEnv): Promise<void> {
			const destination = Buffer.concat([
				Buffer.from([0x00, 0x14]),
				Buffer.alloc(20, 9)
			]);
			const result = env.victim
				.getChannelManager()
				.forceClose(env.channelId!, destination);
			expect(result.ok, 'force close accepted').to.equal(true);
			await chaosWait(env, () => {
				const channel = env.victim
					.getChannelManager()
					.getChannel(env.channelId!);
				return !channel || channel.getState() === ChannelState.FORCE_CLOSED;
			});
		},
		probe(): void {
			// Cell-dependent verdicts; the sweep supplies its own assertOutcome.
		}
	};
}

/**
 * A deterministic wallet input for a splice-in, byte-identical to the one
 * splice.test.ts builds (the interactive-tx audit requires a real input
 * with a working witness signer).
 */
export function makeChaosSpliceWallet(amountSats: bigint): {
	walletInput: ISpliceWalletInput;
	changeScript: Buffer;
} {
	bitcoin.initEccLib(ecc);
	const walletPriv = crypto
		.createHash('sha256')
		.update('chaos-splice-in-wallet')
		.digest();
	const walletPub = Buffer.from(ecc.pointFromScalar(walletPriv, true)!);
	const walletScript = bitcoin.payments.p2wpkh({ pubkey: walletPub }).output!;
	const scriptCode = bitcoin.payments.p2pkh({ pubkey: walletPub }).output!;
	const value = amountSats + 100_000n;
	const prevTx = new bitcoin.Transaction();
	prevTx.version = 2;
	prevTx.addInput(crypto.randomBytes(32), 0);
	prevTx.addOutput(walletScript, Number(value));
	return {
		walletInput: {
			prevTx: prevTx.toBuffer(),
			prevOutputIndex: 0,
			value,
			sequence: 0xfffffffd,
			signWitness: (
				tx: bitcoin.Transaction,
				inputIndex: number,
				inputValue: bigint
			): Buffer[] => {
				const sighash = tx.hashForWitnessV0(
					inputIndex,
					scriptCode,
					Number(inputValue),
					bitcoin.Transaction.SIGHASH_ALL
				);
				const sig64 = Buffer.from(ecc.sign(sighash, walletPriv));
				const der = bitcoin.script.signature.encode(
					sig64,
					bitcoin.Transaction.SIGHASH_ALL
				);
				return [der, walletPub];
			}
		},
		changeScript: walletScript
	};
}

/**
 * S4: the victim initiates a splice-in and dies inside it. The
 * interactive-tx session and the splice session are in-memory by design
 * (matrix rows 6 and 7, D3 before anything is signed), while everything
 * from tx_signatures onward is D2, retransmit-exact from the outbox: the
 * pending-lock window is where commitments become start_batch batches and
 * `_lastSentBatch` is the only thing a taproot channel may replay, since
 * re-signing would reuse a MuSig2 nonce.
 */
/**
 * S7: the victim opens a dual-funded (v2) channel and dies inside the
 * open, around the temporary to permanent id promotion (matrix row 10).
 * Before the initial commitment_signed the session dies with the process
 * and the disk holds nothing; from it onward the durable v2InFlight
 * record (issues 288/289) makes every boundary resumable over
 * reestablish next_funding, and the disk must hold exactly one row under
 * the PERMANENT id, never a half-promoted orphan. Local mode only in
 * this suite: quorum mode still refuses v2 opens (the phase 6 guards
 * lift with their own follow-up), which the splice suite asserts
 * separately.
 */
export function s7OpensV2(): IChaosScenario {
	return {
		name: 'S7 v2 open',
		setup(env: IChaosEnv): void {
			void env;
		},
		async run(env: IChaosEnv): Promise<void> {
			const channel = env.victim.openChannelV2(env.peers[0].getNodeId(), {
				fundingSatoshis: 150_000n,
				fundingFeeratePerkw: 1000
			});
			env.scratch.tempId = channel.getTemporaryChannelId().toString('hex');
			await chaosWait(
				env,
				() =>
					channel.getState() === ChannelState.AWAITING_FUNDING_CONFIRMED &&
					env.victim.getRecoveryStatus().awaitingDurabilityCount === 0
			);
			env.scratch.permanentId = channel.getChannelId()?.toString('hex');
		},
		probe(): void {
			// Cell-dependent verdicts; the sweep supplies its own assertions.
		}
	};
}

export function s4SplicesIn(): IChaosScenario {
	return {
		name: 'S4 splice-in',
		async setup(env: IChaosEnv): Promise<void> {
			env.channelId = await openReadyChannelChaos(
				env,
				env.victim,
				env.peers[0]
			);
			buildDirectGraph(env.victim, CHAOS_VICTIM_SEED, CHAOS_PEER_SEED);
		},
		async run(env: IChaosEnv): Promise<void> {
			const manager = env.victim.getChannelManager();
			manager.initiateQuiescence(env.channelId!);
			const wallet = makeChaosSpliceWallet(100_000n);
			manager
				.getChannel(env.channelId!)!
				.setSpliceInInputs([wallet.walletInput], wallet.changeScript);
			manager.initiateSplice(env.channelId!, 100_000n, 253);
			await chaosWait(
				env,
				() => env.victim.getRecoveryStatus().awaitingDurabilityCount === 0
			);
		},
		probe(): void {
			// Verdicts are cell-dependent (a kill inside the negotiation
			// legitimately abandons it); the sweep supplies its own
			// assertOutcome.
		}
	};
}
