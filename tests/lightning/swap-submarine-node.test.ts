/**
 * Submarine swap provider on a real LightningNode (issue #743): two nodes
 * over the loopback harness, the provider wired through
 * INodeConfig.swaps.submarine with a fake chain source, the client minting
 * a real invoice the provider pays with the real payment engine under the
 * real ceiling. Proves the node wiring: both engines on one peer seam and
 * one ledger, the per-block hook, the payment events feeding the engine,
 * the claim broadcast through the chain source, status and cancel routed
 * by direction, and events re-emitted.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { PaymentStatus } from '../../src/lightning/node/types';
import {
	BEIGNET_CUSTOM_MESSAGE_TYPE,
	BeignetCustomSubtype,
	encodeCustomMessage
} from '../../src/lightning/message/custom';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	ISwapSubmarineCreateAck,
	SUBMARINE_SWAP_EVENTS,
	SwapRefusalReason,
	SwapWireDirection,
	decodeSwapSubmarineCreateAck,
	encodeSwapSubmarineCreate
} from '../../src/lightning/swaps';
import {
	buildGraph,
	connectNodes,
	createNode,
	openReadyChannel
} from './helpers/loopback-nodes';
import { FakeSwapChain, fundContract, settle } from './helpers/swap-harness';

const TAG = 'sub-node';
const AMOUNT = 100_000n;

async function awaitAck(
	client: LightningNode,
	providerId: string,
	requestId: Buffer
): Promise<ISwapSubmarineCreateAck> {
	return new Promise((resolve) => {
		const handler = (msg: {
			peerPubkey: string;
			subtype: number;
			payload: Buffer;
		}): void => {
			if (
				msg.peerPubkey !== providerId ||
				msg.subtype !== BeignetCustomSubtype.SWAP_SUBMARINE_CREATE_ACK
			)
				return;
			const ack = decodeSwapSubmarineCreateAck(msg.payload);
			if (!ack.requestId.equals(requestId)) return;
			client.removeListener('custom-message', handler);
			resolve(ack);
		};
		client.on('custom-message', handler);
	});
}

interface IScene {
	alice: LightningNode;
	bob: LightningNode;
	chain: FakeSwapChain;
	events: string[];
}

/** Alice is the client, Bob the provider; Bob funds the channel so he can pay. */
function scene(seed: number): IScene {
	const chain = new FakeSwapChain();
	const alice = createNode(TAG, seed);
	const bob = createNode(TAG, seed + 1, undefined, {
		feeEstimator: { estimateFee: async () => 2 },
		swaps: {
			enabled: true,
			chainSource: chain,
			fee: { flatFeeSat: 100n, feePpm: 1_000 },
			confirmations: { fundingConfirmations: 1, resolutionConfirmations: 2 },
			timeouts: {
				refundDeltaBlocks: 60,
				minRefundDeltaBlocks: 30,
				maxRefundDeltaBlocks: 120,
				fundingSafetyBlocks: 6,
				resolutionSafetyBlocks: 6
			},
			submarine: {
				enabled: true,
				refundDeltaBlocks: 200,
				minRefundDeltaBlocks: 100,
				maxRefundDeltaBlocks: 400,
				claimSafetyBlocks: 12,
				resolutionSafetyBlocks: 6,
				routeCltvBudgetBlocks: 20,
				claimBumpIntervalBlocks: 2,
				minInvoiceExpirySeconds: 60
			}
		}
	});
	connectNodes(alice, bob);
	alice.handleNewBlock(1000);
	bob.handleNewBlock(1000);
	const channel = openReadyChannel(bob, alice, 500_000n);
	buildGraph(bob, alice, [channel], 400_000_000n);
	const events: string[] = [];
	for (const evt of SUBMARINE_SWAP_EVENTS) {
		bob.on(evt, () => events.push(evt));
	}
	return { alice, bob, chain, events };
}

interface IClientSide {
	refundKey: Buffer;
	refundPubkey: Buffer;
	paymentHash: Buffer;
	bolt11: string;
	/** Known only for a hold invoice the test minted the hash for. */
	preimage?: Buffer;
}

function clientInvoice(
	s: IScene,
	invoiceMsat: bigint,
	options: { minFinalCltvExpiry?: number; hold?: boolean } = {}
): IClientSide {
	const refundKey = crypto.randomBytes(32);
	const minFinalCltvExpiry = options.minFinalCltvExpiry ?? 40;
	if (options.hold) {
		// A hold invoice lets the test decide when Alice settles or fails
		// the parked HTLC: the real "payee holds, then answers" timing.
		const preimage = crypto.randomBytes(32);
		const paymentHash = crypto.createHash('sha256').update(preimage).digest();
		const invoice = s.alice.createInvoice({
			hold: true,
			paymentHash,
			amountMsat: invoiceMsat,
			description: 'submarine swap (hold)',
			minFinalCltvExpiry
		});
		return {
			refundKey,
			refundPubkey: getPublicKey(refundKey),
			paymentHash,
			bolt11: invoice.bolt11,
			preimage
		};
	}
	const invoice = s.alice.createInvoice({
		amountMsat: invoiceMsat,
		description: 'submarine swap',
		minFinalCltvExpiry
	});
	return {
		refundKey,
		refundPubkey: getPublicKey(refundKey),
		paymentHash: invoice.paymentHash,
		bolt11: invoice.bolt11
	};
}

async function createSwap(
	s: IScene,
	client: IClientSide,
	onchainAmountSat = AMOUNT
): Promise<ISwapSubmarineCreateAck> {
	const requestId = crypto.randomBytes(8);
	const pending = awaitAck(s.alice, s.bob.getNodeId(), requestId);
	(
		s.alice as unknown as {
			emitOutbound: (p: string, t: number, b: Buffer) => void;
		}
	).emitOutbound(
		s.bob.getNodeId(),
		BEIGNET_CUSTOM_MESSAGE_TYPE,
		encodeCustomMessage(
			BeignetCustomSubtype.SWAP_SUBMARINE_CREATE,
			encodeSwapSubmarineCreate({
				requestId,
				direction: SwapWireDirection.SUBMARINE,
				paymentHash: client.paymentHash,
				refundPubkey: client.refundPubkey,
				bolt11: client.bolt11,
				onchainAmountSat,
				maxTotalFeeSat: 5_000n
			})
		)
	);
	return pending;
}

async function tick(s: IScene, height: number): Promise<void> {
	s.chain.height = height;
	s.alice.handleNewBlock(height);
	s.bob.handleNewBlock(height);
	await settle();
	await s.bob.getSubmarineSwapProvider()!.onBlock(height);
	await settle();
}

describe('Submarine swap provider on LightningNode (issue #743)', function () {
	it('is absent unless enabled, and reports both directions when it is', function () {
		const reverseOnly = createNode(TAG, 90, undefined, {
			swaps: { enabled: true, chainSource: new FakeSwapChain() }
		});
		expect(reverseOnly.getSubmarineSwapProvider()).to.equal(undefined);
		const status = reverseOnly.getSwapStatus();
		expect(status.enabled).to.equal(true);
		if (status.enabled) {
			expect(status.submarine).to.deep.equal({ enabled: false });
		}
		const s = scene(92);
		expect(s.bob.getSubmarineSwapProvider()).to.not.equal(undefined);
		const both = s.bob.getSwapStatus();
		expect(both.enabled).to.equal(true);
		if (both.enabled && both.submarine.enabled) {
			expect(both.submarine.fee).to.deep.equal({
				flatFeeSat: '100',
				feePpm: 1000
			});
			expect(both.submarine.timeouts.refundDeltaBlocks).to.equal(200);
			expect(both.submarine.timeouts.claimSafetyBlocks).to.equal(12);
			expect(both.timeouts.refundDeltaBlocks).to.equal(60);
		} else {
			expect.fail('submarine status missing');
		}
	});

	it('pays the client invoice once the funding confirms, learns the preimage from the real fulfil, and claims', async function () {
		const s = scene(1);
		await s.bob.startSwapProvider();
		// Fee floor: 100 + 100 + 300; the client leaves 600.
		const client = clientInvoice(s, (AMOUNT - 600n) * 1000n);
		const ack = await createSwap(s, client);
		expect(ack.accepted, ack.reasonText).to.equal(true);
		const terms = ack.terms!;
		expect(terms.refundHeight).to.equal(1200);
		expect(terms.paymentCeilingHeight).to.equal(1200 - 12 - 6);
		expect(s.bob.listSwaps()).to.have.length(1);
		expect(s.events).to.deep.equal(['swap:created']);

		const funding = fundContract(s.chain, terms.outputScript, AMOUNT, 0);
		await tick(s, 1001);
		expect(s.bob.listSwaps()[0].state).to.equal('FUNDING_SEEN');
		expect(s.alice.getInvoice(client.paymentHash.toString('hex'))).to.not.equal(
			null
		);
		s.chain.confirm(funding.getId(), 1001);
		await tick(s, 1002);
		// The real payment engine paid Alice over the loopback channel, the
		// fulfil raised payment:preimage, the engine claimed.
		const record = s.bob.listSwaps()[0];
		expect(record.state).to.equal('CLAIM_BROADCAST');
		expect(record.paymentMaxCltvExpiryHeight).to.equal(1182);
		const payment = s.bob.getPayment(client.paymentHash)!;
		expect(payment.status).to.equal(PaymentStatus.COMPLETED);
		expect(record.preimageHex).to.equal(payment.preimage!.toString('hex'));
		expect(record.preimageSource).to.equal('lightning');
		expect(s.events).to.deep.equal([
			'swap:created',
			'swap:funding-seen',
			'swap:funded',
			'swap:paying',
			'swap:preimage',
			'swap:claim-broadcast'
		]);
		const claim = bitcoin.Transaction.fromHex(record.claimTxHex!);
		expect(Buffer.from(claim.ins[0].hash).reverse().toString('hex')).to.equal(
			funding.getId()
		);
		expect(claim.outs[0].script).to.deep.equal(
			s.bob.getSweepDestinationScript()
		);
		expect(s.chain.mempoolHas(record.claimTxid!)).to.equal(true);
		// Every HTLC of the payment sat under the ceiling.
		const view = s.bob.getOutgoingHtlcs(client.paymentHash);
		expect(view.resolved).to.equal(true);
		for (const h of view.htlcs) {
			expect(h.cltvExpiry).to.be.at.most(1182);
		}

		s.chain.confirm(record.claimTxid!, 1003);
		await tick(s, 1003);
		expect(s.bob.listSwaps()[0].state).to.equal('CLAIM_BROADCAST');
		await tick(s, 1004);
		expect(s.bob.listSwaps()[0].state).to.equal('CLAIM_CONFIRMED');
		expect(s.events[s.events.length - 1]).to.equal('swap:claim-confirmed');
		const status = s.bob.getSwapStatus();
		if (status.enabled && status.submarine.enabled) {
			expect(status.submarine.counts).to.deep.equal({ CLAIM_CONFIRMED: 1 });
			expect(status.submarine.exposedCount).to.equal(0);
		} else {
			expect.fail('submarine status missing');
		}
	});

	it('refuses an invoice whose final CLTV cannot fit under the refund height, and one payable to itself', async function () {
		const s = scene(3);
		await s.bob.startSwapProvider();
		const tooLong = clientInvoice(s, (AMOUNT - 600n) * 1000n, {
			minFinalCltvExpiry: 170
		});
		const refused = await createSwap(s, tooLong);
		expect(refused.accepted).to.equal(false);
		expect(refused.reason).to.equal(SwapRefusalReason.CLTV_UNFITTABLE);
		const own = s.bob.createInvoice({
			amountMsat: (AMOUNT - 600n) * 1000n,
			description: 'mine'
		});
		const refundKey = crypto.randomBytes(32);
		const self = await createSwap(s, {
			refundKey,
			refundPubkey: getPublicKey(refundKey),
			paymentHash: own.paymentHash,
			bolt11: own.bolt11
		});
		expect(self.accepted).to.equal(false);
		expect(self.reason).to.equal(SwapRefusalReason.DUPLICATE_HASH);
		expect(s.bob.listSwaps()).to.have.length(0);
	});

	it('a parked HTLC keeps the swap PAYING; the payee failing it fails the swap, settling it claims', async function () {
		const s = scene(5);
		await s.bob.startSwapProvider();
		const failed = clientInvoice(s, (AMOUNT - 600n) * 1000n, {
			hold: true,
			minFinalCltvExpiry: 80
		});
		const ack = await createSwap(s, failed);
		expect(ack.accepted, ack.reasonText).to.equal(true);
		const funding = fundContract(s.chain, ack.terms!.outputScript, AMOUNT, 0);
		await tick(s, 1001);
		s.chain.confirm(funding.getId(), 1001);
		await tick(s, 1002);
		// Alice parked the HTLC: Bob's record is PENDING with one HTLC out.
		expect(s.bob.listSwaps()[0].state).to.equal('PAYING');
		expect(
			s.alice.getHeldInvoiceSnapshot(failed.paymentHash)!.complete
		).to.equal(true);
		const view = s.bob.getOutgoingHtlcs(failed.paymentHash);
		expect(view.resolved).to.equal(false);
		expect(view.latestOutstandingExpiry).to.be.at.most(1182);
		await tick(s, 1003);
		expect(s.bob.listSwaps()[0].state).to.equal('PAYING');
		// The payee fails it back: every HTLC terminal, no preimage.
		s.alice.cancelHoldInvoice(failed.paymentHash);
		await settle();
		await settle();
		const record = s.bob.listSwaps()[0];
		expect(record.state).to.equal('PAYMENT_FAILED');
		expect(record.claimTxHex).to.equal(undefined);
		expect(s.chain.broadcasts).to.have.length(0);
		expect(s.events).to.include('swap:payment-failed');
		expect(s.bob.getPayment(failed.paymentHash)!.status).to.equal(
			PaymentStatus.FAILED
		);

		// A second swap whose parked HTLC the payee settles: the preimage
		// arrives through payment:preimage and the claim follows.
		const settled = clientInvoice(s, (AMOUNT - 600n) * 1000n, {
			hold: true,
			minFinalCltvExpiry: 80
		});
		const ack2 = await createSwap(s, settled);
		expect(ack2.accepted, ack2.reasonText).to.equal(true);
		const funding2 = fundContract(s.chain, ack2.terms!.outputScript, AMOUNT, 0);
		await tick(s, 1004);
		s.chain.confirm(funding2.getId(), 1004);
		await tick(s, 1005);
		const id2 = ack2.terms!.swapId.toString('hex');
		const row = (): typeof record =>
			s.bob.listSwaps().find((r) => r.id === id2)!;
		expect(row().state).to.equal('PAYING');
		s.alice.settleHeldHtlc(settled.paymentHash, settled.preimage!);
		await settle();
		await settle();
		expect(row().state).to.equal('CLAIM_BROADCAST');
		expect(row().preimageHex).to.equal(settled.preimage!.toString('hex'));
	});

	it('routes cancel by direction: before PAYING it is accepted, after it is refused', async function () {
		const s = scene(7);
		await s.bob.startSwapProvider();
		const client = clientInvoice(s, (AMOUNT - 600n) * 1000n);
		const ack = await createSwap(s, client);
		const id = ack.terms!.swapId.toString('hex');
		expect(s.bob.cancelSwap(id)).to.deep.equal({ ok: true });
		expect(s.bob.listSwaps()[0].state).to.equal('CANCELLED');
		expect(s.events).to.include('swap:cancelled');
		const second = clientInvoice(s, (AMOUNT - 600n) * 1000n);
		const ack2 = await createSwap(s, second);
		const funding = fundContract(s.chain, ack2.terms!.outputScript, AMOUNT, 0);
		await tick(s, 1001);
		s.chain.confirm(funding.getId(), 1001);
		await tick(s, 1002);
		const paid = s.bob
			.listSwaps()
			.find((r) => r.id === ack2.terms!.swapId.toString('hex'))!;
		expect(['CLAIM_BROADCAST', 'PAYING']).to.include(paid.state);
		const refused = s.bob.cancelSwap(paid.id);
		expect(refused.ok).to.equal(false);
		expect(refused.reason).to.match(/swap is/);
	});
});
