/**
 * Reverse swap provider on a real LightningNode (issue #737): two nodes over
 * the loopback harness, the provider wired through INodeConfig.swaps with a
 * fake chain source and a fake funding provider, the client paying the real
 * hold invoice. Proves the node wiring: hold snapshot, settle, cancel, the
 * per-block hook, events re-emitted, and the refund path releasing the payer
 * only after the refund confirmed.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	IFundingProvider,
	PaymentStatus
} from '../../src/lightning/node/types';
import {
	BEIGNET_CUSTOM_MESSAGE_TYPE,
	BeignetCustomSubtype,
	encodeCustomMessage
} from '../../src/lightning/message/custom';
import {
	ISwapCreateAck,
	SwapWireDirection,
	decodeSwapCreateAck,
	encodeSwapCreate
} from '../../src/lightning/swaps';
import {
	buildGraph,
	connectNodes,
	createNode,
	openReadyChannel,
	scidForIndex
} from './helpers/loopback-nodes';
import {
	FakeSwapChain,
	IClientSwap,
	claimTxFor,
	clientSwap,
	settle
} from './helpers/swap-harness';

const TAG = 'swap-node';
const AMOUNT = 100_000n;

/** A wallet that builds a real 1-in-1-out transaction to the address. */
function fakeFundingProvider(
	chain: FakeSwapChain
): IFundingProvider & { builds: number } {
	const fp = {
		builds: 0,
		buildFundingTransaction: async (
			address: string,
			amountSats: bigint
		): Promise<{ txHex: string; txid: Buffer; outputIndex: number }> => {
			fp.builds++;
			const tx = new bitcoin.Transaction();
			tx.version = 2;
			tx.addInput(crypto.randomBytes(32), 0, 0xfffffffd);
			tx.addOutput(
				bitcoin.address.toOutputScript(address, bitcoin.networks.regtest),
				Number(amountSats)
			);
			return {
				txHex: tx.toHex(),
				txid: Buffer.from(tx.getId(), 'hex'),
				outputIndex: 0
			};
		},
		broadcastTransaction: (txHex: string): Promise<string> =>
			chain.broadcastTransaction(txHex)
	};
	return fp;
}

async function awaitAck(
	client: LightningNode,
	providerId: string,
	requestId: Buffer
): Promise<ISwapCreateAck> {
	return new Promise((resolve) => {
		const handler = (msg: {
			peerPubkey: string;
			subtype: number;
			payload: Buffer;
		}): void => {
			if (
				msg.peerPubkey !== providerId ||
				msg.subtype !== BeignetCustomSubtype.SWAP_CREATE_ACK
			)
				return;
			const ack = decodeSwapCreateAck(msg.payload);
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
	fp: ReturnType<typeof fakeFundingProvider>;
	events: string[];
	channels: Buffer[];
}

function scene(seed: number, channels = 1): IScene {
	const chain = new FakeSwapChain();
	const fp = fakeFundingProvider(chain);
	const alice = createNode(TAG, seed);
	const bob = createNode(TAG, seed + 1, undefined, {
		fundingProvider: fp,
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
				resolutionSafetyBlocks: 6,
				refundBumpIntervalBlocks: 2
			}
		}
	});
	connectNodes(alice, bob);
	alice.handleNewBlock(1000);
	bob.handleNewBlock(1000);
	const ids = [];
	for (let i = 0; i < channels; i++)
		ids.push(openReadyChannel(alice, bob, 500_000n));
	buildGraph(alice, bob, ids, 400_000_000n);
	const events: string[] = [];
	for (const evt of [
		'swap:created',
		'swap:held',
		'swap:funding',
		'swap:funded',
		'swap:claimed',
		'swap:settled',
		'swap:refund-broadcast',
		'swap:refunded',
		'swap:hold-cancelled',
		'swap:exposed',
		'swap:failed'
	]) {
		bob.on(evt, () => events.push(evt));
	}
	return { alice, bob, chain, fp, events, channels: ids };
}

async function createSwap(
	s: IScene,
	swap: IClientSwap
): Promise<ISwapCreateAck> {
	const requestId = crypto.randomBytes(8);
	const pending = awaitAck(s.alice, s.bob.getNodeId(), requestId);
	// The loopback harness has no peer manager: hand the envelope to the
	// node's outbound path the way its own engines do.
	(
		s.alice as unknown as {
			emitOutbound: (p: string, t: number, b: Buffer) => void;
		}
	).emitOutbound(
		s.bob.getNodeId(),
		BEIGNET_CUSTOM_MESSAGE_TYPE,
		encodeCustomMessage(
			BeignetCustomSubtype.SWAP_CREATE,
			encodeSwapCreate({
				requestId,
				direction: SwapWireDirection.REVERSE,
				paymentHash: swap.paymentHash,
				claimPubkey: swap.claimPubkey,
				onchainAmountSat: AMOUNT,
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
	await s.bob.getSwapProvider()!.onBlock(height);
}

describe('Reverse swap provider on LightningNode (issue #737)', function () {
	it('is absent unless enabled, and reports status when it is', function () {
		const plain = createNode(TAG, 90);
		expect(plain.getSwapProvider()).to.equal(undefined);
		expect(plain.getSwapStatus()).to.deep.equal({ enabled: false });
		expect(plain.cancelSwap('x')).to.deep.equal({
			ok: false,
			reason: 'swaps disabled'
		});
		const s = scene(92);
		const status = s.bob.getSwapStatus();
		expect(status.enabled).to.equal(true);
		if (status.enabled) {
			expect(status.fee).to.deep.equal({ flatFeeSat: '100', feePpm: 1000 });
			expect(status.timeouts.refundDeltaBlocks).to.equal(60);
		}
	});

	it('funds after the client pays the hold invoice and settles on the claim', async function () {
		const s = scene(1);
		await s.bob.startSwapProvider();
		const swap = clientSwap();
		const ack = await createSwap(s, swap);
		expect(ack.accepted, ack.reasonText).to.equal(true);
		const terms = ack.terms!;
		expect(terms.refundHeight).to.equal(1060);
		expect(s.bob.listSwaps()).to.have.length(1);
		expect(s.events).to.deep.equal(['swap:created']);

		const payment = s.alice.sendPayment(terms.bolt11);
		expect(payment.status).to.equal(PaymentStatus.PENDING);
		await settle();
		const record = s.bob.listSwaps()[0];
		expect(record.state).to.equal('FUNDING_BROADCAST');
		expect(s.fp.builds).to.equal(1);
		expect(s.events).to.deep.equal([
			'swap:created',
			'swap:held',
			'swap:funding'
		]);
		expect(s.bob.getHeldInvoiceSnapshot(swap.paymentHash)!.complete).to.equal(
			true
		);

		s.chain.confirm(record.fundingTxid!, 1001);
		await tick(s, 1001);
		expect(s.bob.listSwaps()[0].state).to.equal('FUNDED');

		const claim = claimTxFor(s.bob.listSwaps()[0], swap);
		s.chain.place(claim, 0);
		await tick(s, 1002);
		const done = s.bob.listSwaps()[0];
		expect(done.state).to.equal('SETTLED');
		expect(done.preimageHex).to.equal(swap.preimage.toString('hex'));
		expect(s.alice.getPayment(swap.paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
		expect(s.alice.getPayment(swap.paymentHash)!.preimage).to.deep.equal(
			swap.preimage
		);
		expect(s.bob.listHoldInvoices()[0].state).to.equal('SETTLED');
		expect(s.events.slice(-2)).to.deep.equal(['swap:claimed', 'swap:settled']);
	});

	it('funds only once both MPP parts are committed', async function () {
		const s = scene(3, 2);
		await s.bob.startSwapProvider();
		const swap = clientSwap();
		const ack = await createSwap(s, swap);
		expect(ack.accepted, ack.reasonText).to.equal(true);
		const terms = ack.terms!;
		const total = terms.invoiceAmountMsat;
		const secret = (await import('../../src/lightning/invoice/decode')).decode(
			terms.bolt11
		).paymentSecret!;
		const bobPub = Buffer.from(s.bob.getNodeId(), 'hex');
		const sendPart = (i: number, amount: bigint): void => {
			s.alice.sendPaymentToRoute(
				{
					hops: [
						{
							pubkey: bobPub,
							shortChannelId: scidForIndex(i),
							amountToForwardMsat: amount,
							outgoingCltvValue: 200
						}
					]
				},
				swap.paymentHash,
				200,
				secret,
				total
			);
		};
		sendPart(0, total / 2n);
		await settle();
		expect(s.bob.listSwaps()[0].state).to.equal('CREATED');
		expect(s.fp.builds).to.equal(0);
		sendPart(1, total - total / 2n);
		await settle();
		expect(s.bob.listSwaps()[0].state).to.equal('FUNDING_BROADCAST');
		expect(s.fp.builds).to.equal(1);
	});

	it('refunds when nobody claims and fails the payer only after the refund confirms', async function () {
		const s = scene(5);
		await s.bob.startSwapProvider();
		const swap = clientSwap();
		const ack = await createSwap(s, swap);
		expect(ack.accepted, ack.reasonText).to.equal(true);
		s.alice.sendPayment(ack.terms!.bolt11);
		await settle();
		const record = s.bob.listSwaps()[0];
		s.chain.confirm(record.fundingTxid!, 1001);
		await tick(s, 1001);
		expect(s.bob.listSwaps()[0].state).to.equal('FUNDED');

		await tick(s, 1061);
		const pending = s.bob.listSwaps()[0];
		expect(pending.state).to.equal('REFUND_PENDING');
		expect(s.alice.getPayment(swap.paymentHash)!.status).to.equal(
			PaymentStatus.PENDING
		);
		expect(s.bob.listHoldInvoices()[0].state).to.equal('ACCEPTED');

		s.chain.confirm(pending.refundTxid!, 1062);
		await tick(s, 1062);
		expect(s.bob.listSwaps()[0].state).to.equal('REFUND_PENDING');
		expect(s.alice.getPayment(swap.paymentHash)!.status).to.equal(
			PaymentStatus.PENDING
		);

		await tick(s, 1063);
		expect(s.bob.listSwaps()[0].state).to.equal('REFUNDED');
		expect(s.bob.listHoldInvoices()[0].state).to.equal('CANCELLED');
		expect(s.alice.getPayment(swap.paymentHash)!.status).to.equal(
			PaymentStatus.FAILED
		);
		expect(s.events.slice(-2)).to.deep.equal([
			'swap:refunded',
			'swap:hold-cancelled'
		]);
		const refund = bitcoin.Transaction.fromHex(pending.refundTxHex!);
		expect(refund.outs[0].script).to.deep.equal(
			s.bob.getSweepDestinationScript()
		);
	});

	it('the node sweeper cancelling the hold exposes the swap', async function () {
		const s = scene(7);
		await s.bob.startSwapProvider();
		const swap = clientSwap();
		const ack = await createSwap(s, swap);
		s.alice.sendPayment(ack.terms!.bolt11);
		await settle();
		const record = s.bob.listSwaps()[0];
		s.chain.confirm(record.fundingTxid!, 1001);
		await tick(s, 1001);
		const snapshot = s.bob.getHeldInvoiceSnapshot(swap.paymentHash)!;
		expect(snapshot.cancelHeight).to.be.greaterThan(1060 + 6);
		await tick(s, snapshot.cancelHeight!);
		expect(s.bob.listHoldInvoices()[0].state).to.equal('CANCELLED');
		expect(s.bob.listSwaps()[0].state).to.equal('EXPOSED');
		expect(s.events).to.include('swap:exposed');
	});

	it('an operator cancel before payment closes the invoice', async function () {
		const s = scene(9);
		await s.bob.startSwapProvider();
		const swap = clientSwap();
		const ack = await createSwap(s, swap);
		expect(s.bob.cancelSwap(ack.terms!.swapId.toString('hex')).ok).to.equal(
			true
		);
		expect(s.bob.listHoldInvoices()[0].state).to.equal('CANCELLED');
		expect(() => s.alice.sendPayment(ack.terms!.bolt11)).to.not.throw();
		await settle();
		expect(s.alice.getPayment(swap.paymentHash)!.status).to.equal(
			PaymentStatus.FAILED
		);
		expect(s.bob.listSwaps()[0].state).to.equal('CANCELLED');
	});
});
