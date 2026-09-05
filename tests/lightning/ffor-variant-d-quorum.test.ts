/**
 * FFOR Variant D on a quorum-mode settlement peer (review round 5).
 *
 * The S2 forwarder kill sweep found that a batch the quorum durability
 * barrier PARKS (its state committed, its sends waiting for the guardian
 * receipt) was being read as a batch that never persisted, and the round
 * that has to queue behind it was never signed. The FFOR drives had the
 * same reading, so on a quorum-mode S every epoch would have stalled at
 * ff_accept. This suite runs the whole Variant D life cycle with S as the
 * chaos harness's quorum victim (three served guardians, a real
 * DurabilityBarrier, the same wiring recovery-phase7-forward uses): the
 * setup must reach ACTIVE on both sides, a delegated payment must settle
 * upstream while R is offline, and R's close must drain to CLOSED, with
 * the barrier demonstrably parking S's batches along the way.
 */

import { expect } from 'chai';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { PaymentStatus } from '../../src/lightning/node/types';
import { ChannelState } from '../../src/lightning/channel/types';
import { encodeShortChannelId } from '../../src/lightning/gossip/types';
import { MessageType } from '../../src/lightning/message/types';
import { FforSlotState, FforState } from '../../src/lightning/ffor/types';
import {
	chaosWait,
	IChaosEnv,
	makeChaosEnv,
	openReadyChannelChaos,
	reestablishFifo,
	settle
} from './helpers/chaos-harness';
import { addGraphChannel, CHAOS_FORWARD_ENV } from './helpers/chaos-scenarios';
import {
	currentQuorumRun,
	quorumOptions,
	registerQuorumNamespace,
	waitFor
} from './helpers/chaos-quorum';

const TIP = 790_000;
const T_EXP = 800_000;
const D_DEADLINE = 798_992;
const AMOUNTS = [1_000_000n, 546_250n, 2_000_000n];

function allNormal(nodes: LightningNode[]): boolean {
	return nodes.every((node) =>
		node
			.getChannelManager()
			.listChannels()
			.every((c) => c.getState() === ChannelState.NORMAL)
	);
}

function htlcCount(node: LightningNode, channelId: Buffer): number {
	return node.getChannelManager().getChannel(channelId)!.getFullState().htlcs
		.size;
}

describe('FFOR Variant D on a quorum-mode settlement peer', function () {
	this.timeout(180_000);

	it('sets up to ACTIVE, settles a delegated payment and drains to CLOSED with every S batch crossing the durability barrier', async () => {
		const options = quorumOptions({}, CHAOS_FORWARD_ENV);
		const env: IChaosEnv = await makeChaosEnv('quorum', options);
		try {
			await registerQuorumNamespace();
			// payer -> S (the quorum victim) -> R, the S2 world.
			const [payer, recipient] = env.peers;
			const s = env.victim;
			const psId = await openReadyChannelChaos(env, payer, s);
			const srId = await openReadyChannelChaos(env, s, recipient);
			const srHex = srId.toString('hex');
			// The opens themselves cross the barrier: wait for both channels
			// to settle into NORMAL and the watermark to move (withNamespace).
			await waitFor(
				() =>
					currentQuorumRun().barrier.watermark() > 0n &&
					allNormal([s, payer, recipient])
			);
			const scidPS = encodeShortChannelId({
				block: 830,
				txIndex: 1,
				outputIndex: 0
			});
			const scidSR = encodeShortChannelId({
				block: 830,
				txIndex: 2,
				outputIndex: 0
			});
			payer.registerChannelScid(psId, scidPS);
			s.registerChannelScid(psId, scidPS);
			s.registerChannelScid(srId, scidSR);
			recipient.registerChannelScid(srId, scidSR);
			recipient
				.getChannelManager()
				.getChannel(srId)!
				.getFullState().remoteScidAlias = scidSR;
			addGraphChannel(
				payer,
				scidPS,
				Buffer.from(payer.getNodeId(), 'hex'),
				Buffer.from(s.getNodeId(), 'hex')
			);
			for (const node of [payer, s, recipient]) node.handleNewBlock(TIP);
			await chaosWait(
				env,
				() => s.getRecoveryStatus().awaitingDurabilityCount === 0
			);

			// Every hold the barrier takes on S's channel with R.
			let heldOnSr = 0;
			s.getChannelManager().on(
				'transition:held',
				(_peer: string, channelIdHex: string) => {
					if (channelIdHex === srHex) heldOnSr++;
				}
			);
			const sErrors: string[] = [];
			s.on('node:error', (e: { message: string }) => sErrors.push(e.message));

			// Setup: R starts the epoch; S's ff_accept, voucher round and
			// ff_activate_ack are all barrier-class on S.
			const started = recipient.startFforEpoch(srHex, {
				voucherAmountsMsat: AMOUNTS,
				minPaymentMsat: 400_000n,
				settlementDeadline: D_DEADLINE,
				voucherExpiry: T_EXP,
				feeBaseMsat: 1000,
				feeProportionalMillionths: 5000
			});
			expect(started.ok, started.error).to.equal(true);
			await chaosWait(
				env,
				() =>
					s.getFforEpoch(srHex)?.state === FforState.ACTIVE &&
					recipient.getFforEpoch(srHex)?.state === FforState.ACTIVE,
				30_000
			);
			await chaosWait(
				env,
				() => s.getRecoveryStatus().awaitingDurabilityCount === 0
			);
			const heldBySetup = heldOnSr;
			expect(
				heldBySetup,
				'the barrier parked at least one S batch during setup'
			).to.be.greaterThan(0);
			const sentByS = (type: number): number =>
				env.relay.captured.filter(
					(m) => m.from === s.getNodeId() && m.type === type
				).length;
			expect(sentByS(MessageType.FF_ACCEPT), 'ff_accept left S').to.equal(1);
			expect(
				sentByS(MessageType.FF_ACTIVATE_ACK),
				'ff_activate_ack left S'
			).to.equal(1);

			// R exposes voucher 1 and goes offline.
			const invoice = recipient.createFforVoucherInvoice(srHex, 1).bolt11;
			s.getChannelManager().handlePeerDisconnected(recipient.getNodeId());
			recipient.getChannelManager().handlePeerDisconnected(s.getNodeId());
			await settle();

			// Settlement: S marks SETTLING (a drive), reveals t_1 upstream and
			// signs the removal, each batch parked behind the barrier in turn.
			const payment = payer.sendPayment(invoice);
			await chaosWait(
				env,
				() => payment.status !== PaymentStatus.PENDING,
				30_000
			);
			expect(payment.status, 'delegated payment settled upstream').to.equal(
				PaymentStatus.COMPLETED
			);
			await chaosWait(
				env,
				() => s.getRecoveryStatus().awaitingDurabilityCount === 0
			);
			await chaosWait(env, () => htlcCount(s, psId) === 0, 30_000);
			expect(s.getFforEpoch(srHex)!.slotStates[0]).to.equal(
				FforSlotState.SETTLED
			);
			expect(sentByS(MessageType.UPDATE_FULFILL_HTLC)).to.equal(1);

			// R returns and closes; S's ff_close_ack and the drain round cross
			// the barrier too.
			await reestablishFifo(env.relay, s, recipient);
			await chaosWait(
				env,
				() =>
					allNormal([s, recipient]) &&
					s.getRecoveryStatus().awaitingDurabilityCount === 0,
				30_000
			);
			expect(recipient.getFforEpoch(srHex)!.state).to.equal(FforState.ACTIVE);
			const closed = recipient.closeFforEpoch(srHex);
			expect(closed.ok, closed.error).to.equal(true);
			await chaosWait(
				env,
				() =>
					s.getFforEpoch(srHex)?.state === FforState.CLOSED &&
					recipient.getFforEpoch(srHex)?.state === FforState.CLOSED &&
					htlcCount(s, srId) === 0 &&
					htlcCount(recipient, srId) === 0,
				30_000
			);
			await chaosWait(
				env,
				() => s.getRecoveryStatus().awaitingDurabilityCount === 0
			);
			expect(sentByS(MessageType.FF_CLOSE_ACK), 'ff_close_ack left S').to.equal(
				1
			);
			expect(
				heldOnSr,
				'the barrier parked S batches after setup too'
			).to.be.greaterThan(heldBySetup);
			expect(allNormal([s, payer, recipient])).to.equal(true);
			expect(
				sErrors.filter((e) => /FFOR/.test(e)),
				'no FFOR error on S'
			).to.deep.equal([]);
		} finally {
			env.victim.destroy();
			for (const peer of env.peers) peer.destroy();
			try {
				await options.teardown?.(env);
			} catch {
				// Teardown is best-effort by contract.
			}
		}
	});
});
