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
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
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
import {
	ICut,
	IWireGate,
	disconnect,
	reconnect,
	reconnectRestarted,
	tempDb,
	wire
} from './helpers/async-world';

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

function providerNode(
	seed: number,
	chain: FakeSwapChain,
	fp: ReturnType<typeof fakeFundingProvider>,
	storage?: SqliteStorage
): LightningNode {
	return createNode(TAG, seed, storage, {
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
}

/** A wire the test can cut and bring back. */
interface ILink {
	cut: ICut;
	gate: IWireGate;
}

function scene(
	seed: number,
	channels = 1,
	storage?: SqliteStorage,
	link?: ILink
): IScene {
	const chain = new FakeSwapChain();
	const fp = fakeFundingProvider(chain);
	const alice = createNode(TAG, seed);
	const bob = providerNode(seed + 1, chain, fp, storage);
	if (link) wire(alice, bob, link.cut, undefined, link.gate);
	else connectNodes(alice, bob);
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

function receivedHtlcCount(bob: LightningNode, channelId: Buffer): number {
	return [
		...bob
			.getChannelManager()
			.getChannel(channelId)!
			.getFullState()
			.htlcs.keys()
	].filter((key) => key.startsWith('received-')).length;
}

/** Create a swap and park one dust MPP part with an expiry weeks out. */
async function parkDustPart(
	s: IScene,
	swap: IClientSwap
): Promise<NonNullable<ISwapCreateAck['terms']>> {
	const ack = await createSwap(s, swap);
	expect(ack.accepted, ack.reasonText).to.equal(true);
	const terms = ack.terms!;
	const secret = (await import('../../src/lightning/invoice/decode')).decode(
		terms.bolt11
	).paymentSecret!;
	s.alice.sendPaymentToRoute(
		{
			hops: [
				{
					pubkey: Buffer.from(s.bob.getNodeId(), 'hex'),
					shortChannelId: scidForIndex(0),
					amountToForwardMsat: 1_000n,
					outgoingCltvValue: 5000
				}
			]
		},
		swap.paymentHash,
		5000,
		secret,
		terms.invoiceAmountMsat
	);
	await settle();
	expect(receivedHtlcCount(s.bob, s.channels[0])).to.equal(1);
	return terms;
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
		// A settled hold is payment history, never forgotten (issue #1389).
		expect(s.bob['forgetCancelledHoldInvoice'](swap.paymentHash)).to.equal(
			false
		);
		expect(s.bob.listHoldInvoices()[0].state).to.equal('SETTLED');
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
		// Cancelled, then forgotten with the swap over (issue #1389).
		expect(s.bob.listHoldInvoices()).to.deep.equal([]);
		expect(s.bob.getPayment(swap.paymentHash)).to.equal(undefined);
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
		expect(s.bob.listHoldInvoices()).to.deep.equal([]);
		expect(() => s.alice.sendPayment(ack.terms!.bolt11)).to.not.throw();
		await settle();
		expect(s.alice.getPayment(swap.paymentHash)!.status).to.equal(
			PaymentStatus.FAILED
		);
		expect(s.bob.listSwaps()[0].state).to.equal('CANCELLED');
	});

	it('an unpaid create that expires leaves no invoice, payment or secret behind (issue #1389)', async function () {
		const storage = new SqliteStorage(':memory:');
		storage.open();
		try {
			const s = scene(11, 1, storage);
			await s.bob.startSwapProvider();
			const swap = clientSwap();
			const ack = await createSwap(s, swap);
			expect(ack.accepted, ack.reasonText).to.equal(true);
			const hashHex = swap.paymentHash.toString('hex');
			const stored = (): Record<string, boolean> => ({
				invoice: storage
					.loadAllInvoices()
					.some((r) => r.paymentHashHex === hashHex),
				payment: storage.loadPayment(hashHex) !== null,
				secret: storage
					.loadAllPaymentSecrets()
					.some((r) => r.paymentHashHex === hashHex)
			});
			expect(stored()).to.deep.equal({
				invoice: true,
				payment: true,
				secret: true
			});
			// An open hold is never forgotten.
			expect(s.bob['forgetCancelledHoldInvoice'](swap.paymentHash)).to.equal(
				false
			);

			s.bob['swapLedger']!.patch(ack.terms!.swapId.toString('hex'), {
				invoiceExpiresAt: 1
			});
			await tick(s, 1001);
			expect(s.bob.listSwaps()[0].state).to.equal('CANCELLED');
			expect(s.bob.listHoldInvoices()).to.deep.equal([]);
			expect(s.bob.getPayment(swap.paymentHash)).to.equal(undefined);
			expect(stored()).to.deep.equal({
				invoice: false,
				payment: false,
				secret: false
			});
			// Already gone reads as done, so the swap row can be pruned.
			expect(s.bob['forgetCancelledHoldInvoice'](swap.paymentHash)).to.equal(
				true
			);

			// The swap row still owns the hash, and a late payment fails.
			expect((await createSwap(s, swap)).accepted).to.equal(false);
			s.alice.sendPayment(ack.terms!.bolt11);
			await settle();
			expect(s.alice.getPayment(swap.paymentHash)!.status).to.equal(
				PaymentStatus.FAILED
			);
			s.alice.destroy();
			s.bob.destroy();
		} finally {
			try {
				storage.close();
			} catch {
				// bob.destroy() already closed the shared handle
			}
		}
	});

	it('a partly paid create that expires fails its parked part back (issue #1390)', async function () {
		const s = scene(13);
		await s.bob.startSwapProvider();
		const swap = clientSwap();
		const ack = await createSwap(s, swap);
		expect(ack.accepted, ack.reasonText).to.equal(true);
		const terms = ack.terms!;
		const secret = (await import('../../src/lightning/invoice/decode')).decode(
			terms.bolt11
		).paymentSecret!;
		// One dust part with an expiry weeks out: the sweeper alone would
		// leave it parked until block 5000 - 18.
		s.alice.sendPaymentToRoute(
			{
				hops: [
					{
						pubkey: Buffer.from(s.bob.getNodeId(), 'hex'),
						shortChannelId: scidForIndex(0),
						amountToForwardMsat: 1_000n,
						outgoingCltvValue: 5000
					}
				]
			},
			swap.paymentHash,
			5000,
			secret,
			terms.invoiceAmountMsat
		);
		await settle();
		const receivedHtlcs = (): number =>
			[
				...s.bob
					.getChannelManager()
					.getChannel(s.channels[0])!
					.getFullState()
					.htlcs.keys()
			].filter((key) => key.startsWith('received-')).length;
		expect(receivedHtlcs()).to.equal(1);
		await tick(s, 1001);
		expect(s.bob.listSwaps()[0].state).to.equal('CREATED');

		s.bob['swapLedger']!.patch(terms.swapId.toString('hex'), {
			invoiceExpiresAt: 1
		});
		await tick(s, 1002);
		expect(s.bob.listSwaps()[0].state).to.equal('CANCELLED');
		expect(receivedHtlcs()).to.equal(0);
		expect(s.alice.getPayment(swap.paymentHash)!.status).to.equal(
			PaymentStatus.FAILED
		);
		expect(s.bob.listHoldInvoices()).to.deep.equal([]);
		expect(s.events).to.deep.equal(['swap:created', 'swap:hold-cancelled']);
	});

	it('fails the parts of a cancel refused while the channel was down once it reestablishes (issue #1455)', async function () {
		const link: ILink = {
			cut: { val: false },
			gate: { hold: false, queue: [] }
		};
		const s = scene(15, 1, undefined, link);
		await s.bob.startSwapProvider();
		const swap = clientSwap();
		const terms = await parkDustPart(s, swap);
		await tick(s, 1001);
		expect(s.bob.listSwaps()[0].state).to.equal('CREATED');

		await disconnect(s.alice, s.bob, link.cut);
		s.bob['swapLedger']!.patch(terms.swapId.toString('hex'), {
			invoiceExpiresAt: 1
		});
		await tick(s, 1002);
		const owed = s.bob.listSwaps()[0];
		expect(owed.state).to.equal('CANCELLED');
		// Nothing was failed back, so nothing is recorded as cancelled.
		expect(owed.holdCancelledAt).to.equal(undefined);
		expect(s.bob.listHoldInvoices()[0].state).to.equal('ACCEPTED');
		// A block with the channel still down is refused again.
		await tick(s, 1003);
		expect(receivedHtlcCount(s.bob, s.channels[0])).to.equal(1);

		await reconnect(s.alice, s.bob, link.cut, link.gate);
		await settle();
		expect(receivedHtlcCount(s.bob, s.channels[0])).to.equal(0);
		expect(s.alice.getPayment(swap.paymentHash)!.status).to.equal(
			PaymentStatus.FAILED
		);
		const done = s.bob.listSwaps()[0];
		expect(done.holdCancelledAt).to.be.a('number');
		expect(done.holdCancelReason).to.equal('invoice_expired');
		expect(s.bob.listHoldInvoices()).to.deep.equal([]);
	});

	it('a restart keeps retrying a cancel refused while the channel was down (issue #1455)', async function () {
		this.timeout(20_000);
		const dbPath = tempDb('swap-hold-cancel');
		const storage = new SqliteStorage(dbPath);
		storage.open();
		const link: ILink = {
			cut: { val: false },
			gate: { hold: false, queue: [] }
		};
		const s = scene(17, 1, storage, link);
		await s.bob.startSwapProvider();
		const swap = clientSwap();
		const terms = await parkDustPart(s, swap);

		await disconnect(s.alice, s.bob, link.cut);
		s.bob['swapLedger']!.patch(terms.swapId.toString('hex'), {
			invoiceExpiresAt: 1
		});
		await tick(s, 1001);
		expect(s.bob.listSwaps()[0].state).to.equal('CANCELLED');
		expect(s.bob.listSwaps()[0].holdCancelledAt).to.equal(undefined);

		// The process goes away with the cancel still unsent.
		s.bob.destroy();
		s.alice.removeAllListeners('message:outbound');
		const disk = new SqliteStorage(dbPath);
		disk.open();
		const bob = providerNode(18, s.chain, s.fp, disk);
		await bob.startSwapProvider();
		expect(bob.listHoldInvoices()[0].state).to.equal('ACCEPTED');

		await reconnectRestarted(bob, s.alice);
		await settle();
		expect(receivedHtlcCount(bob, s.channels[0])).to.equal(0);
		expect(s.alice.getPayment(swap.paymentHash)!.status).to.equal(
			PaymentStatus.FAILED
		);
		expect(bob.listSwaps()[0].holdCancelledAt).to.be.a('number');
		expect(bob.listHoldInvoices()).to.deep.equal([]);
		s.alice.destroy();
		bob.destroy();
	});
});
