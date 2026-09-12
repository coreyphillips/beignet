/**
 * Reverse swap provider engine (issue #737) over fakes: wire round trips,
 * admission on the complete committed set only, persist-before-act at every
 * transition, the claim and refund paths with the hold retained until the
 * refund reaches policy depth, exposure by the node's own sweeper, and a
 * restart at every state redoing the owed action exactly once.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import { BeignetCustomSubtype } from '../../src/lightning/message/custom';
import { Network } from '../../src/lightning/invoice/types';
import {
	ISwapCreateAck,
	ISwapQuote,
	ISwapRecord,
	ISwapStatus,
	SwapRefusalReason,
	SwapWireDirection,
	SwapWireState,
	decodeSwapCreateAck,
	decodeSwapQuote,
	decodeSwapStatus,
	encodeSwapCreate,
	encodeSwapQuoteRequest,
	encodeSwapStatusRequest,
	reverseSwapFee,
	verifyReverseSwapTerms
} from '../../src/lightning/swaps';
import { IDfCustomMessage } from '../../src/lightning/direct-funding/transport';
import { FakeDfPeer } from './helpers/df-transport';
import {
	IClientSwap,
	ISwapHarness,
	claimTxFor,
	clientSwap,
	harness,
	settle
} from './helpers/swap-harness';

const AMOUNT = 100_000n;

function lastFrom(peer: FakeDfPeer, subtype: number): Buffer {
	const frames = peer.sent.filter((s) => s.subtype === subtype);
	expect(frames.length, `subtype ${subtype} sent`).to.be.greaterThan(0);
	return frames[frames.length - 1].payload;
}

async function quote(h: ISwapHarness, amountSat = AMOUNT): Promise<ISwapQuote> {
	h.client.sendCustomMessage(
		h.provider.id,
		BeignetCustomSubtype.SWAP_QUOTE_REQUEST,
		encodeSwapQuoteRequest({
			requestId: crypto.randomBytes(8),
			direction: SwapWireDirection.REVERSE,
			amountSat
		})
	);
	await settle();
	return decodeSwapQuote(lastFrom(h.provider, BeignetCustomSubtype.SWAP_QUOTE));
}

async function create(
	h: ISwapHarness,
	swap: IClientSwap,
	overrides: Partial<{
		onchainAmountSat: bigint;
		maxTotalFeeSat: bigint;
		direction: SwapWireDirection;
		from: FakeDfPeer;
	}> = {}
): Promise<ISwapCreateAck> {
	const from = overrides.from ?? h.client;
	const requestId = crypto.randomBytes(8);
	from.sendCustomMessage(
		h.provider.id,
		BeignetCustomSubtype.SWAP_CREATE,
		encodeSwapCreate({
			requestId,
			direction: overrides.direction ?? SwapWireDirection.REVERSE,
			paymentHash: swap.paymentHash,
			claimPubkey: swap.claimPubkey,
			onchainAmountSat: overrides.onchainAmountSat ?? AMOUNT,
			maxTotalFeeSat: overrides.maxTotalFeeSat ?? 5_000n
		})
	);
	await settle();
	const ack = decodeSwapCreateAck(
		lastFrom(h.provider, BeignetCustomSubtype.SWAP_CREATE_ACK)
	);
	expect(ack.requestId).to.deep.equal(requestId);
	return ack;
}

async function status(
	h: ISwapHarness,
	swapId: Buffer,
	from: FakeDfPeer = h.client
): Promise<ISwapStatus> {
	from.sendCustomMessage(
		h.provider.id,
		BeignetCustomSubtype.SWAP_STATUS_REQUEST,
		encodeSwapStatusRequest({ requestId: crypto.randomBytes(8), swapId })
	);
	await settle();
	return decodeSwapStatus(
		lastFrom(h.provider, BeignetCustomSubtype.SWAP_STATUS)
	);
}

function record(h: ISwapHarness, swap: IClientSwap): ISwapRecord {
	const rows = h.ledger.byPaymentHash(swap.paymentHash.toString('hex'));
	expect(rows).to.have.length(1);
	return rows[0];
}

function names(h: ISwapHarness): string[] {
	return h.events.map((e) => e.name);
}

/** Create, pay in full (one committed part), let the engine fund. */
async function fundedSwap(
	h: ISwapHarness,
	swap = clientSwap()
): Promise<{ swap: IClientSwap; ack: ISwapCreateAck }> {
	const ack = await create(h, swap);
	expect(ack.accepted, ack.reasonText).to.equal(true);
	const r = record(h, swap);
	h.holds.hold(swap.paymentHash, BigInt(r.invoiceMsat), r.refundHeight + 60);
	await settle();
	expect(record(h, swap).state).to.equal('FUNDING_BROADCAST');
	return { swap, ack };
}

describe('Reverse swap provider engine (issue #737)', function () {
	describe('quote and create', function () {
		it('quotes limits and fees, and refuses the wrong direction or a missing estimate', async function () {
			const h = await harness();
			const limits = await quote(h, 0n);
			expect(limits.accepted).to.equal(true);
			expect(limits.minSwapSat).to.equal(10_000n);
			expect(limits.totalFeeSat).to.equal(0n);
			expect(limits.minRefundDelta).to.equal(30);

			const q = await quote(h);
			expect(q.accepted).to.equal(true);
			expect(q.minerFeeSat).to.equal(400n);
			expect(q.totalFeeSat).to.equal(
				reverseSwapFee(AMOUNT, {
					flatFeeSat: 100n,
					feePpm: 1_000,
					minerFeeSat: 400n
				})
			);
			expect(q.invoiceAmountMsat).to.equal((AMOUNT + q.totalFeeSat) * 1000n);
			expect(q.refundDeltaBlocks).to.equal(60);

			const big = await quote(h, 5_000_000n);
			expect(big.accepted).to.equal(false);
			expect(big.reason).to.equal(SwapRefusalReason.AMOUNT_ABOVE_MAX);

			h.client.sendCustomMessage(
				h.provider.id,
				BeignetCustomSubtype.SWAP_QUOTE_REQUEST,
				encodeSwapQuoteRequest({
					requestId: crypto.randomBytes(8),
					direction: SwapWireDirection.SUBMARINE,
					amountSat: AMOUNT
				})
			);
			await settle();
			expect(
				decodeSwapQuote(lastFrom(h.provider, BeignetCustomSubtype.SWAP_QUOTE))
					.reason
			).to.equal(SwapRefusalReason.UNSUPPORTED_DIRECTION);

			h.feeRate = null;
			const noFee = await quote(h);
			expect(noFee.reason).to.equal(SwapRefusalReason.CHAIN_UNAVAILABLE);
		});

		it('creates a swap: record persisted, hold invoice minted, terms verifiable by the client', async function () {
			const h = await harness();
			const swap = clientSwap();
			const ack = await create(h, swap);
			expect(ack.accepted).to.equal(true);
			const r = record(h, swap);
			expect(r.state).to.equal('CREATED');
			expect(r.bolt11).to.equal(ack.terms!.bolt11);
			expect(r.refundHeight).to.equal(1060);
			expect(
				h.holds.invoices.get(swap.paymentHash.toString('hex'))!
					.minFinalCltvExpiry
			).to.equal(60 + 6 + 18 + 8);
			const verdict = verifyReverseSwapTerms({
				create: {
					requestId: ack.requestId,
					direction: SwapWireDirection.REVERSE,
					paymentHash: swap.paymentHash,
					claimPubkey: swap.claimPubkey,
					onchainAmountSat: AMOUNT,
					maxTotalFeeSat: 5_000n
				},
				ack,
				currentHeight: 1000,
				network: Network.REGTEST,
				minRefundDelta: 30,
				maxRefundDelta: 120,
				maxTotalFeeSat: 5_000n
			});
			expect(verdict.ok, verdict.ok ? '' : verdict.reason).to.equal(true);
			expect(names(h)).to.deep.equal(['swap:created']);
			const st = await status(h, ack.terms!.swapId);
			expect(st.found).to.equal(true);
			expect(st.state).to.equal(SwapWireState.CREATED);
			expect(st.fundingTxid).to.equal(undefined);
		});

		it('repeats the same ack for an identical create and refuses other duplicates', async function () {
			const h = await harness();
			const swap = clientSwap();
			const first = await create(h, swap);
			const again = await create(h, swap);
			expect(again.accepted).to.equal(true);
			expect(again.terms!.swapId).to.deep.equal(first.terms!.swapId);
			expect(again.terms!.bolt11).to.equal(first.terms!.bolt11);
			expect(h.ledger.list()).to.have.length(1);
			const changed = await create(h, swap, { onchainAmountSat: AMOUNT + 1n });
			expect(changed.reason).to.equal(SwapRefusalReason.DUPLICATE_HASH);
			const other = h.net.add('other-client');
			h.net.connect(h.provider, other);
			const stolen = await create(h, swap, { from: other });
			expect(stolen.reason).to.equal(SwapRefusalReason.DUPLICATE_HASH);
			// The other peer cannot see the swap either.
			const st = await status(h, first.terms!.swapId, other);
			expect(st.found).to.equal(false);
		});

		it('refuses a fee above the client ceiling, a bad direction and the per-peer quota', async function () {
			const h = await harness();
			expect(
				(await create(h, clientSwap(), { maxTotalFeeSat: 10n })).reason
			).to.equal(SwapRefusalReason.FEE_CEILING);
			expect(
				(
					await create(h, clientSwap(), {
						direction: SwapWireDirection.SUBMARINE
					})
				).reason
			).to.equal(SwapRefusalReason.UNSUPPORTED_DIRECTION);
			expect(h.ledger.list()).to.have.length(0);
			for (let i = 0; i < 4; i++)
				expect((await create(h, clientSwap())).accepted).to.equal(true);
			expect((await create(h, clientSwap())).reason).to.equal(
				SwapRefusalReason.RATE_LIMITED
			);
		});

		it('refuses a hash the node already holds a record for, before anything is written', async function () {
			const h = await harness();
			const swap = clientSwap();
			h.holds.inUse.add(swap.paymentHash.toString('hex'));
			const ack = await create(h, swap);
			expect(ack.accepted).to.equal(false);
			expect(ack.reason).to.equal(SwapRefusalReason.DUPLICATE_HASH);
			expect(h.ledger.list()).to.have.length(0);
			expect(h.holds.invoices.size).to.equal(0);
		});

		it('refuses every quote and create while the refund destination is not native segwit', async function () {
			const p2sh = Buffer.concat([
				Buffer.from([0xa9, 0x14]),
				crypto.randomBytes(20),
				Buffer.from([0x87])
			]);
			const h = await harness({ destination: p2sh });
			const q = await quote(h, 50_000n);
			expect(q.accepted).to.equal(false);
			expect(q.reason).to.equal(SwapRefusalReason.INTERNAL);
			const ack = await create(h, clientSwap());
			expect(ack.accepted).to.equal(false);
			expect(ack.reason).to.equal(SwapRefusalReason.INTERNAL);
			expect(h.ledger.list()).to.have.length(0);
			expect(
				h.logs.some((l) => l.action === 'swap_refund_destination_unusable')
			).to.equal(true);
		});

		it('fails closed when the hold invoice cannot be minted, with the row recorded first', async function () {
			const h = await harness();
			h.holds.failCreate = true;
			const ack = await create(h, clientSwap());
			expect(ack.reason).to.equal(SwapRefusalReason.INTERNAL);
			expect(h.ledger.list()[0].state).to.equal('FAILED');
		});
	});

	describe('admission', function () {
		it('never funds a partial MPP set and funds the complete one', async function () {
			const h = await harness();
			const swap = clientSwap();
			await create(h, swap);
			const r = record(h, swap);
			const total = BigInt(r.invoiceMsat);
			h.holds.hold(swap.paymentHash, total / 2n, r.refundHeight + 60);
			await settle();
			expect(record(h, swap).state).to.equal('CREATED');
			expect(h.wallet.builds).to.have.length(0);
			expect(h.logs.some((l) => l.action === 'swap_partial_hold')).to.equal(
				true
			);
			h.holds.hold(swap.paymentHash, total - total / 2n, r.refundHeight + 70);
			await settle();
			const funded = record(h, swap);
			expect(funded.state).to.equal('FUNDING_BROADCAST');
			expect(funded.cancellationHeight).to.equal(r.refundHeight + 60 - 18);
			expect(h.wallet.builds).to.have.length(1);
			expect(h.wallet.pledged[0]).to.equal(h.wallet.builds[0]);
			expect(h.chain.broadcasts[0]).to.equal(h.wallet.builds[0]);
			expect(names(h)).to.deep.equal([
				'swap:created',
				'swap:held',
				'swap:funding'
			]);
		});

		it('refuses a hold whose expiry the sweeper would cancel too soon, and cancels it', async function () {
			const h = await harness();
			const swap = clientSwap();
			await create(h, swap);
			const r = record(h, swap);
			// cancelHeight = expiry - 18 must exceed refundHeight + resolutionSafety(6).
			h.holds.hold(
				swap.paymentHash,
				BigInt(r.invoiceMsat),
				r.refundHeight + 24
			);
			await settle();
			expect(record(h, swap).state).to.equal('CANCELLED');
			expect(h.holds.cancelled).to.deep.equal([
				swap.paymentHash.toString('hex')
			]);
			expect(h.wallet.builds).to.have.length(0);
			expect(names(h)).to.deep.equal(['swap:created', 'swap:failed']);
		});

		it('re-checks exposure at hold time', async function () {
			const h = await harness({
				config: {
					exposure: {
						minSwapSat: 10_000n,
						maxSwapSat: 100_000n,
						maxTotalExposureSat: 150_000n,
						maxConcurrentSwaps: 8,
						feeReserveSat: 0n,
						fundingFeeRateCeilingSatPerVbyte: 100
					}
				}
			});
			const a = clientSwap();
			const b = clientSwap();
			await create(h, a);
			await create(h, b);
			const ra = record(h, a);
			const rb = record(h, b);
			h.holds.hold(a.paymentHash, BigInt(ra.invoiceMsat), ra.refundHeight + 60);
			await settle();
			expect(record(h, a).state).to.equal('FUNDING_BROADCAST');
			h.holds.hold(b.paymentHash, BigInt(rb.invoiceMsat), rb.refundHeight + 60);
			await settle();
			expect(record(h, b).state).to.equal('CANCELLED');
			expect(record(h, b).failureReason).to.match(/exposure/);
		});

		it('expires an unpaid swap with its invoice', async function () {
			const h = await harness();
			const swap = clientSwap();
			await create(h, swap);
			h.ledger.patch(record(h, swap).id, { invoiceExpiresAt: 1 });
			await h.engine.onBlock(1001);
			expect(record(h, swap).state).to.equal('CANCELLED');
			expect(h.holds.cancelled).to.have.length(1);
		});
	});

	describe('funding', function () {
		it('retries a failed build up to the limit, then fails and cancels the hold', async function () {
			const h = await harness();
			h.wallet.failBuilds = 5;
			const swap = clientSwap();
			await create(h, swap);
			const r = record(h, swap);
			h.holds.hold(
				swap.paymentHash,
				BigInt(r.invoiceMsat),
				r.refundHeight + 60
			);
			await settle();
			expect(record(h, swap).state).to.equal('FUNDING');
			expect(record(h, swap).fundingAttempts).to.equal(1);
			await h.engine.onBlock(1001);
			expect(record(h, swap).fundingAttempts).to.equal(2);
			await h.engine.onBlock(1002);
			expect(record(h, swap).state).to.equal('FAILED');
			expect(h.holds.cancelled).to.have.length(1);
			expect(h.chain.broadcasts).to.have.length(0);
		});

		it('rejects a wallet transaction that does not pay the contract exactly', async function () {
			const h = await harness();
			h.wallet.shortBy = 1n;
			const swap = clientSwap();
			await create(h, swap);
			const r = record(h, swap);
			h.holds.hold(
				swap.paymentHash,
				BigInt(r.invoiceMsat),
				r.refundHeight + 60
			);
			await settle();
			expect(record(h, swap).state).to.equal('FAILED');
			expect(record(h, swap).failureReason).to.match(/pays/);
			expect(h.wallet.released).to.have.length(1);
			expect(h.chain.broadcasts).to.have.length(0);
		});

		it('keeps the same bytes across a failed broadcast and retries per block', async function () {
			const h = await harness();
			h.chain.failBroadcasts = 1;
			const swap = clientSwap();
			await create(h, swap);
			const r = record(h, swap);
			h.holds.hold(
				swap.paymentHash,
				BigInt(r.invoiceMsat),
				r.refundHeight + 60
			);
			await settle();
			const stuck = record(h, swap);
			expect(stuck.state).to.equal('FUNDING');
			expect(stuck.fundingTxHex).to.be.a('string');
			expect(stuck.lastError).to.match(/broadcast refused/);
			await h.engine.onBlock(1001);
			const out = record(h, swap);
			expect(out.state).to.equal('FUNDING_BROADCAST');
			expect(h.wallet.builds).to.have.length(1);
			expect(h.chain.broadcasts).to.deep.equal([stuck.fundingTxHex]);
		});

		it('reports funding progress over status and confirms to policy', async function () {
			const h = await harness();
			const { swap, ack } = await fundedSwap(h);
			const r = record(h, swap);
			let st = await status(h, ack.terms!.swapId);
			expect(st.state).to.equal(SwapWireState.FUNDING);
			expect(st.fundingTxid!.toString('hex')).to.equal(r.fundingTxid);
			expect(st.fundingTx!.toString('hex')).to.equal(r.fundingTxHex);
			h.chain.confirm(r.fundingTxid!, 1001);
			h.chain.height = 1001;
			await h.engine.onBlock(1001);
			expect(record(h, swap).state).to.equal('FUNDED');
			expect(record(h, swap).fundingHeight).to.equal(1001);
			st = await status(h, ack.terms!.swapId);
			expect(st.state).to.equal(SwapWireState.FUNDED);
			expect(st.fundingConfirmations).to.equal(1);
			expect(names(h)).to.include('swap:funded');
		});
	});

	describe('claim and settle', function () {
		it('settles the hold on a mempool claim, before any confirmation', async function () {
			const h = await harness();
			const { swap } = await fundedSwap(h);
			const claim = claimTxFor(record(h, swap), swap);
			h.chain.place(claim, 0);
			await h.engine.onBlock(1000);
			const r = record(h, swap);
			expect(r.state).to.equal('SETTLED');
			expect(r.preimageHex).to.equal(swap.preimage.toString('hex'));
			expect(r.preimageSource).to.equal('onchain-claim');
			expect(r.resolution!.kind).to.equal('claim');
			expect(h.holds.settled).to.deep.equal([
				{
					hash: swap.paymentHash.toString('hex'),
					preimage: swap.preimage.toString('hex')
				}
			]);
			expect(h.holds.cancelled).to.have.length(0);
			expect(names(h).slice(-2)).to.deep.equal([
				'swap:claimed',
				'swap:settled'
			]);
		});

		it('a claim with a non-canonical witness still yields its preimage and settles', async function () {
			const h = await harness();
			const { swap } = await fundedSwap(h);
			const claim = claimTxFor(record(h, swap), swap);
			// MINIMALIF byte 0x02 and a high-S signature: consensus-valid when
			// mined by a lenient pool, never relayed by standard nodes.
			const witness = claim.ins[0].witness;
			witness[2] = Buffer.from([0x02]);
			const sig = bitcoin.script.signature.decode(witness[0]);
			const s = Buffer.from(sig.signature.subarray(32));
			const n = BigInt(
				'0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'
			);
			const highS = (n - BigInt('0x' + s.toString('hex')))
				.toString(16)
				.padStart(64, '0');
			witness[0] = bitcoin.script.signature.encode(
				Buffer.concat([
					sig.signature.subarray(0, 32),
					Buffer.from(highS, 'hex')
				]),
				sig.hashType
			);
			claim.setWitness(0, witness);
			h.chain.place(claim, 1001);
			await h.engine.onBlock(1001);
			const r = record(h, swap);
			expect(r.state).to.equal('SETTLED');
			expect(r.preimageHex).to.equal(swap.preimage.toString('hex'));
			expect(h.holds.settled).to.have.length(1);
			expect(h.holds.cancelled).to.have.length(0);
		});

		it('persists the preimage before settling, and a settle that finds nothing parked marks the swap exposed', async function () {
			const h = await harness();
			const { swap } = await fundedSwap(h);
			h.holds.settleReturns = false;
			// Nothing parked, not a refused settle: a refusal over a set still
			// ACCEPTED stays CLAIMED for the next pass.
			h.holds.parts.delete(swap.paymentHash.toString('hex'));
			h.chain.place(claimTxFor(record(h, swap), swap), 0);
			await h.engine.onBlock(1000);
			const r = record(h, swap);
			expect(r.state).to.equal('EXPOSED');
			expect(r.preimageHex).to.equal(swap.preimage.toString('hex'));
			expect(r.holdCancelReason).to.equal('settle_no_held_htlcs');
		});

		it('a refused settle over a still-parked hold stays claimed and settles on the next pass', async function () {
			const h = await harness();
			const { swap } = await fundedSwap(h);
			h.holds.settleReturns = false;
			h.chain.place(claimTxFor(record(h, swap), swap), 0);
			await h.engine.onBlock(1000);
			expect(record(h, swap).state).to.equal('CLAIMED');
			h.holds.settleReturns = undefined;
			await h.engine.onBlock(1001);
			expect(record(h, swap).state).to.equal('SETTLED');
			expect(h.holds.settled).to.have.length(1);
		});

		it('a claim after the refund was broadcast still wins and the hold is never cancelled', async function () {
			const h = await harness();
			const { swap } = await fundedSwap(h);
			const r0 = record(h, swap);
			h.chain.confirm(r0.fundingTxid!, 1001);
			h.chain.height = r0.refundHeight + 1;
			await h.engine.onBlock(h.chain.height);
			const pending = record(h, swap);
			expect(pending.state).to.equal('REFUND_PENDING');
			expect(pending.refundTxHex).to.be.a('string');
			expect(h.chain.mempoolHas(pending.refundTxid!)).to.equal(true);
			expect(h.holds.cancelled).to.have.length(0);
			// The client's claim confirms while our refund sits in the mempool.
			const claim = claimTxFor(pending, swap);
			h.chain.place(claim, h.chain.height);
			h.chain.evict(pending.refundTxid!);
			await h.engine.onBlock(h.chain.height + 1);
			const r = record(h, swap);
			expect(r.state).to.equal('SETTLED');
			expect(h.holds.settled).to.have.length(1);
			expect(h.holds.cancelled).to.have.length(0);
		});
	});

	describe('refund', function () {
		it('refunds after the refund height and cancels the hold only at policy depth', async function () {
			const h = await harness();
			const { swap } = await fundedSwap(h);
			const r0 = record(h, swap);
			h.chain.confirm(r0.fundingTxid!, 1001);
			// At the refund height itself: nothing yet (first eligible block is +1).
			h.chain.height = r0.refundHeight;
			await h.engine.onBlock(h.chain.height);
			expect(record(h, swap).state).to.equal('FUNDED');
			h.chain.height = r0.refundHeight + 1;
			await h.engine.onBlock(h.chain.height);
			const pending = record(h, swap);
			expect(pending.state).to.equal('REFUND_PENDING');
			expect(pending.refundBumps).to.equal(0);
			expect(pending.refundFeeSat).to.equal('320');
			expect(names(h)).to.include('swap:refund-broadcast');
			const refund = bitcoin.Transaction.fromHex(pending.refundTxHex!);
			expect(refund.outs[0].script).to.deep.equal(h.destination);
			expect(refund.locktime).to.equal(r0.refundHeight);
			expect(h.holds.cancelled).to.have.length(0);
			// One confirmation: still pending, still held.
			h.chain.confirm(pending.refundTxid!, h.chain.height + 1);
			h.chain.height += 1;
			await h.engine.onBlock(h.chain.height);
			expect(record(h, swap).state).to.equal('REFUND_PENDING');
			expect(record(h, swap).resolution!.confirmations).to.equal(1);
			expect(h.holds.cancelled).to.have.length(0);
			// Policy depth: refunded, and only now the hold goes.
			h.chain.height += 1;
			await h.engine.onBlock(h.chain.height);
			const done = record(h, swap);
			expect(done.state).to.equal('REFUNDED');
			expect(done.holdCancelReason).to.equal('refund_confirmed');
			expect(h.holds.cancelled).to.deep.equal([
				swap.paymentHash.toString('hex')
			]);
			expect(names(h).slice(-2)).to.deep.equal([
				'swap:refunded',
				'swap:hold-cancelled'
			]);
		});

		it('bumps an unconfirmed refund by rebuilding, persisting before broadcasting, and never above the cap', async function () {
			const h = await harness({ config: { maxFeeRateSatPerVbyte: 4 } });
			const { swap } = await fundedSwap(h);
			const r0 = record(h, swap);
			h.chain.confirm(r0.fundingTxid!, 1001);
			h.chain.height = r0.refundHeight + 1;
			await h.engine.onBlock(h.chain.height);
			const first = record(h, swap);
			expect(first.refundFeeSat).to.equal('320');
			// One block later: interval not reached, same bytes rebroadcast.
			h.chain.height += 1;
			await h.engine.onBlock(h.chain.height);
			expect(record(h, swap).refundBumps).to.equal(0);
			expect(
				h.chain.broadcasts.filter((b) => b === first.refundTxHex)
			).to.have.length(2);
			// Interval reached: a replacement at old fee + vbytes.
			h.chain.height += 1;
			await h.engine.onBlock(h.chain.height);
			const second = record(h, swap);
			expect(second.refundBumps).to.equal(1);
			expect(second.refundFeeSat).to.equal('480');
			expect(second.refundTxid).to.not.equal(first.refundTxid);
			expect(h.chain.broadcasts[h.chain.broadcasts.length - 1]).to.equal(
				second.refundTxHex
			);
			// Cap: 4 sat/vB x 160 = 640; the next bump lands there, then stops.
			h.chain.height += 2;
			await h.engine.onBlock(h.chain.height);
			expect(record(h, swap).refundFeeSat).to.equal('640');
			h.chain.height += 2;
			await h.engine.onBlock(h.chain.height);
			expect(record(h, swap).refundFeeSat).to.equal('640');
			expect(record(h, swap).refundBumps).to.equal(2);
			// The replacement confirms: the earlier txid is nothing.
			const last = record(h, swap);
			h.chain.confirm(last.refundTxid!, h.chain.height);
			h.chain.height += 2;
			await h.engine.onBlock(h.chain.height);
			expect(record(h, swap).state).to.equal('REFUNDED');
		});

		it('a refund reorged below policy keeps the swap pending and the hold intact', async function () {
			const h = await harness();
			const { swap } = await fundedSwap(h);
			const r0 = record(h, swap);
			h.chain.confirm(r0.fundingTxid!, 1001);
			h.chain.height = r0.refundHeight + 1;
			await h.engine.onBlock(h.chain.height);
			const pending = record(h, swap);
			h.chain.confirm(pending.refundTxid!, h.chain.height + 1);
			h.chain.height += 1;
			await h.engine.onBlock(h.chain.height);
			expect(record(h, swap).resolution!.confirmations).to.equal(1);
			// Reorg: the refund is back in the mempool.
			h.chain.confirm(pending.refundTxid!, 0);
			h.chain.height += 1;
			await h.engine.onBlock(h.chain.height);
			expect(record(h, swap).state).to.equal('REFUND_PENDING');
			expect(h.holds.cancelled).to.have.length(0);
		});

		it('an exposed swap counts toward exposure until its resolution reaches policy depth, verified this session', async function () {
			const h = await harness({
				config: {
					resolutionConfirmations: 3,
					exposure: {
						minSwapSat: 10_000n,
						maxSwapSat: AMOUNT,
						maxTotalExposureSat: AMOUNT,
						maxConcurrentSwaps: 8,
						feeReserveSat: 0n,
						fundingFeeRateCeilingSatPerVbyte: 200
					}
				}
			});
			const { swap } = await fundedSwap(h);
			const r0 = record(h, swap);
			h.chain.confirm(r0.fundingTxid!, 1001);
			h.holds.sweep(swap.paymentHash);
			await settle();
			expect(record(h, swap).state).to.equal('EXPOSED');
			// Refund out and confirmed once: still exposure.
			h.chain.height = r0.refundHeight + 1;
			await h.engine.onBlock(h.chain.height);
			const refundTxid = record(h, swap).refundTxid!;
			h.chain.confirm(refundTxid, h.chain.height + 1);
			h.chain.height += 1;
			await h.engine.onBlock(h.chain.height);
			expect(record(h, swap).resolution!.confirmations).to.equal(1);
			let ack = await create(h, clientSwap());
			expect(ack.accepted).to.equal(false);
			expect(ack.reason).to.equal(SwapRefusalReason.EXPOSURE_EXCEEDED);
			// At policy depth the principal is off the books.
			h.chain.height += 2;
			await h.engine.onBlock(h.chain.height);
			expect(record(h, swap).resolution!.confirmations).to.equal(3);
			ack = await create(h, clientSwap());
			expect(ack.accepted).to.equal(true);
			// The refund vanishes from the chain: exposure again.
			const second = h.ledger.list().find((x) => x.id !== r0.id)!;
			h.ledger.move(second.id, 'CANCELLED', { failureReason: 'test' });
			h.chain.evict(refundTxid);
			h.chain.height += 1;
			await h.engine.onBlock(h.chain.height);
			expect(record(h, swap).resolution!.confirmations).to.equal(0);
			expect(
				h.logs.some((l) => l.action === 'swap_resolution_demoted')
			).to.equal(true);
			ack = await create(h, clientSwap());
			expect(ack.accepted).to.equal(false);
			expect(ack.reason).to.equal(SwapRefusalReason.EXPOSURE_EXCEEDED);
			// Back at depth, then a reload: the stored verification is history
			// until this process has observed the spend itself.
			h.chain.place(
				bitcoin.Transaction.fromHex(record(h, swap).refundTxHex!),
				h.chain.height - 2
			);
			await h.engine.onBlock(h.chain.height);
			expect(record(h, swap).resolution!.confirmations).to.equal(3);
			// The memory store hands the same rows back; the codec's reload
			// rule (verifiedThisSession false after a decode) is covered in
			// swap-ledger.test.ts, so stand in for it here.
			const again = await h.restart({ start: false });
			again.ledger.patch(r0.id, {
				resolution: {
					...record(again, swap).resolution!,
					verifiedThisSession: false
				}
			});
			ack = await create(again, clientSwap());
			expect(ack.accepted).to.equal(false);
			expect(ack.reason).to.equal(SwapRefusalReason.EXPOSURE_EXCEEDED);
			await again.engine.onBlock(again.chain.height);
			expect(record(again, swap).resolution!.verifiedThisSession).to.equal(
				true
			);
			ack = await create(again, clientSwap());
			expect(ack.accepted).to.equal(true);
		});

		it('an unknown spend of the funding never cancels the hold', async function () {
			const h = await harness();
			const { swap } = await fundedSwap(h);
			const r0 = record(h, swap);
			h.chain.confirm(r0.fundingTxid!, 1001);
			const odd = new bitcoin.Transaction();
			odd.version = 2;
			odd.addInput(
				Buffer.from(r0.fundingTxid!, 'hex').reverse(),
				r0.fundingVout!
			);
			odd.addOutput(h.destination, 1_000);
			odd.setWitness(0, [
				Buffer.alloc(70, 1),
				Buffer.alloc(0),
				Buffer.alloc(0)
			]);
			h.chain.place(odd, 1002);
			h.chain.height = r0.refundHeight + 10;
			await h.engine.onBlock(h.chain.height);
			expect(record(h, swap).state).to.equal('REFUND_PENDING');
			expect(h.holds.cancelled).to.have.length(0);
		});
	});

	describe('exposure by the node', function () {
		it('a sweeper cancel with signed bytes exposes the swap and keeps the pledge; without bytes it fails', async function () {
			// Bytes exist, the broadcast threw: they may be out all the same.
			const h = await harness();
			h.chain.failBroadcasts = 1;
			const swap = clientSwap();
			await create(h, swap);
			const r = record(h, swap);
			h.holds.hold(
				swap.paymentHash,
				BigInt(r.invoiceMsat),
				r.refundHeight + 60
			);
			await settle();
			expect(record(h, swap).state).to.equal('FUNDING');
			h.holds.sweep(swap.paymentHash);
			await settle();
			expect(record(h, swap).state).to.equal('EXPOSED');
			expect(h.wallet.released).to.have.length(0);
			expect(h.logs.some((l) => l.action === 'swap_exposed')).to.equal(true);
			// Still watched: the refund recovers the coins once the bytes show.
			h.chain.place(
				bitcoin.Transaction.fromHex(record(h, swap).fundingTxHex!),
				1001
			);
			h.chain.height = record(h, swap).refundHeight + 1;
			await h.engine.onBlock(h.chain.height);
			expect(record(h, swap).refundTxHex).to.be.a('string');

			// No bytes were ever built: nothing left, the swap fails.
			const h2 = await harness();
			h2.wallet.failBuilds = 5;
			const swap2 = clientSwap();
			await create(h2, swap2);
			const r2 = record(h2, swap2);
			h2.holds.hold(
				swap2.paymentHash,
				BigInt(r2.invoiceMsat),
				r2.refundHeight + 60
			);
			await settle();
			expect(record(h2, swap2).state).to.equal('FUNDING');
			expect(record(h2, swap2).fundingTxHex).to.equal(undefined);
			h2.holds.sweep(swap2.paymentHash);
			await settle();
			expect(record(h2, swap2).state).to.equal('FAILED');
			await h2.engine.onBlock(1001);
			expect(h2.chain.broadcasts).to.have.length(0);
		});

		it('a hold cancelled while the wallet is signing never has its bytes broadcast', async function () {
			const h = await harness();
			let releaseWallet: () => void = () => undefined;
			h.wallet.gate = () =>
				new Promise<void>((resolve) => {
					releaseWallet = resolve;
				});
			const swap = clientSwap();
			await create(h, swap);
			const r = record(h, swap);
			h.holds.hold(
				swap.paymentHash,
				BigInt(r.invoiceMsat),
				r.refundHeight + 60
			);
			await settle();
			expect(record(h, swap).state).to.equal('FUNDING');
			expect(record(h, swap).fundingTxHex).to.equal(undefined);
			// The sweeper cancels the hold while the wallet holds the pen. The
			// engine's queue is behind the wallet, so the cancel notification
			// waits; the fence before the broadcast reads the hold itself.
			h.holds.sweep(swap.paymentHash);
			await settle();
			expect(record(h, swap).state).to.equal('FUNDING');
			releaseWallet();
			await settle();
			expect(h.chain.broadcasts).to.have.length(0);
			expect(record(h, swap).state).to.equal('FAILED');
			expect(record(h, swap).failureReason).to.match(/broadcast refused/);
			// The bytes the wallet handed back were pledged, judged, dropped:
			// released and erased from the row.
			expect(h.wallet.builds).to.have.length(1);
			expect(h.wallet.pledged).to.deep.equal([h.wallet.builds[0]]);
			expect(h.wallet.released).to.deep.equal([h.wallet.builds[0]]);
			await h.engine.onBlock(1001);
			expect(h.chain.broadcasts).to.have.length(0);
		});

		it('a hold cancelled while the wallet is pledging never has its bytes broadcast', async function () {
			const h = await harness();
			let releasePledge: () => void = () => undefined;
			h.wallet.pledgeGate = () =>
				new Promise<void>((resolve) => {
					releasePledge = resolve;
				});
			const swap = clientSwap();
			await create(h, swap);
			const r = record(h, swap);
			h.holds.hold(
				swap.paymentHash,
				BigInt(r.invoiceMsat),
				r.refundHeight + 60
			);
			await settle();
			expect(record(h, swap).state).to.equal('FUNDING');
			expect(record(h, swap).fundingTxHex).to.be.a('string');
			expect(record(h, swap).fundingBroadcastAttemptedAt).to.equal(undefined);
			h.holds.sweep(swap.paymentHash);
			await settle();
			releasePledge();
			await settle();
			expect(h.chain.broadcasts).to.have.length(0);
			const failed = record(h, swap);
			expect(failed.state).to.equal('FAILED');
			expect(failed.fundingBroadcastAttemptedAt).to.equal(undefined);
			expect(h.wallet.released).to.have.length(1);
			// The bytes never left and are gone from the row, so no status
			// answer can hand the payer a relayable funding.
			expect(failed.fundingTxHex).to.equal(undefined);
			const st = await status(h, Buffer.from(failed.id, 'hex'));
			expect(st.found).to.equal(true);
			expect(st.fundingTx).to.equal(undefined);
			await h.engine.onBlock(1001);
			expect(h.chain.broadcasts).to.have.length(0);
		});

		it('status carries the funding bytes only once a broadcast was attempted', async function () {
			const h = await harness();
			h.chain.failBroadcasts = 1;
			const swap = clientSwap();
			await create(h, swap);
			const r = record(h, swap);
			h.holds.hold(
				swap.paymentHash,
				BigInt(r.invoiceMsat),
				r.refundHeight + 60
			);
			await settle();
			// Attempted and refused by the backend: the bytes may be out,
			// the payer may have them.
			const stuck = record(h, swap);
			expect(stuck.state).to.equal('FUNDING');
			expect(stuck.fundingBroadcastAttemptedAt).to.be.a('number');
			const st = await status(h, Buffer.from(stuck.id, 'hex'));
			expect(st.fundingTx!.toString('hex')).to.equal(stuck.fundingTxHex);
		});

		it('a restart judges the hold again before the first broadcast', async function () {
			// The first build failed; the process stopped; the hold went;
			// the restart builds the bytes and must not put them out.
			const h = await harness();
			h.wallet.failBuilds = 1;
			const swap = clientSwap();
			await create(h, swap);
			const r = record(h, swap);
			h.holds.hold(
				swap.paymentHash,
				BigInt(r.invoiceMsat),
				r.refundHeight + 60
			);
			await settle();
			expect(record(h, swap).state).to.equal('FUNDING');
			expect(record(h, swap).fundingTxHex).to.equal(undefined);
			h.engine.stop();
			h.holds.cancelHold(swap.paymentHash);
			const again = await h.restart();
			expect(record(again, swap).state).to.equal('FAILED');
			expect(record(again, swap).failureReason).to.match(/broadcast refused/);
			expect(again.chain.broadcasts).to.have.length(0);
			expect(again.wallet.released).to.have.length(1);
			expect(
				again.logs.some((l) => l.action === 'swap_broadcast_refused')
			).to.equal(true);

			// The same restart with the hold still live funds normally, and
			// the attempt is marked before the bytes leave.
			const h2 = await harness();
			h2.wallet.failBuilds = 1;
			const swap2 = clientSwap();
			await create(h2, swap2);
			const r2 = record(h2, swap2);
			h2.holds.hold(
				swap2.paymentHash,
				BigInt(r2.invoiceMsat),
				r2.refundHeight + 60
			);
			await settle();
			h2.engine.stop();
			const again2 = await h2.restart();
			const funded = record(again2, swap2);
			expect(funded.state).to.equal('FUNDING_BROADCAST');
			expect(funded.fundingBroadcastAttemptedAt).to.be.a('number');
			expect(again2.chain.broadcasts).to.have.length(1);
		});

		it('a broadcast that throws after relaying is judged by the chain, not the error', async function () {
			const h = await harness();
			h.chain.relayThenFail = 1;
			const swap = clientSwap();
			await create(h, swap);
			const r = record(h, swap);
			h.holds.hold(
				swap.paymentHash,
				BigInt(r.invoiceMsat),
				r.refundHeight + 60
			);
			await settle();
			expect(record(h, swap).state).to.equal('FUNDING_BROADCAST');
			expect(
				h.logs.some(
					(l) => l.action === 'swap_funding_seen_after_failed_broadcast'
				)
			).to.equal(true);
			// The claim on that funding is seen and settles the hold.
			const claim = claimTxFor(record(h, swap), swap);
			h.chain.place(claim, 0);
			await h.engine.onBlock(1001);
			expect(record(h, swap).state).to.equal('SETTLED');
			expect(h.holds.settled).to.have.length(1);
		});

		it('a sweeper cancel while funded exposes the swap; a later claim still records its preimage and the refund still runs', async function () {
			const h = await harness();
			const { swap } = await fundedSwap(h);
			const r0 = record(h, swap);
			h.chain.confirm(r0.fundingTxid!, 1001);
			h.holds.sweep(swap.paymentHash);
			await settle();
			const exposed = record(h, swap);
			expect(exposed.state).to.equal('EXPOSED');
			expect(exposed.holdCancelReason).to.equal('expiry-scan');
			expect(names(h)).to.include('swap:exposed');
			expect(h.logs.some((l) => l.action === 'swap_exposed')).to.equal(true);
			// Refund still recovers our coins.
			h.chain.height = r0.refundHeight + 1;
			await h.engine.onBlock(h.chain.height);
			expect(record(h, swap).state).to.equal('EXPOSED');
			expect(record(h, swap).refundTxHex).to.be.a('string');
			// A claim beats it: preimage recorded, state stays EXPOSED, no settle.
			h.chain.place(claimTxFor(record(h, swap), swap), h.chain.height);
			await h.engine.onBlock(h.chain.height + 1);
			const r = record(h, swap);
			expect(r.state).to.equal('EXPOSED');
			expect(r.preimageHex).to.equal(swap.preimage.toString('hex'));
			expect(h.holds.settled).to.have.length(0);
			const claimed = h.events.filter((e) => e.name === 'swap:claimed');
			expect(claimed).to.have.length(1);
			expect(claimed[0].data.exposed).to.equal(true);
		});

		it('an operator cancel works only before funds move', async function () {
			const h = await harness();
			const a = clientSwap();
			await create(h, a);
			expect(h.engine.cancel(record(h, a).id).ok).to.equal(true);
			expect(record(h, a).state).to.equal('CANCELLED');
			expect(h.holds.cancelled).to.have.length(1);
			const { swap: b } = await fundedSwap(h);
			expect(h.engine.cancel(record(h, b).id)).to.deep.equal({
				ok: false,
				reason: 'swap is FUNDING_BROADCAST'
			});
			expect(h.engine.cancel('nope')).to.deep.equal({
				ok: false,
				reason: 'unknown swap'
			});
		});
	});

	describe('restart', function () {
		it('CREATED without an invoice fails and cancels; CREATED with a complete hold funds', async function () {
			const h = await harness();
			const a = clientSwap();
			await create(h, a);
			h.ledger.patch(record(h, a).id, { bolt11: undefined });
			const b = clientSwap();
			await create(h, b);
			const rb = record(h, b);
			h.holds.heldListeners.clear();
			h.holds.hold(b.paymentHash, BigInt(rb.invoiceMsat), rb.refundHeight + 60);
			const h2 = await h.restart();
			expect(h2.ledger.get(record(h, a).id)!.state).to.equal('FAILED');
			expect(h2.holds.cancelled).to.include(a.paymentHash.toString('hex'));
			expect(h2.ledger.get(rb.id)!.state).to.equal('FUNDING_BROADCAST');
			expect(h2.wallet.builds).to.have.length(1);
		});

		it('FUNDING with bytes rebroadcasts them, never builds again', async function () {
			const h = await harness();
			h.chain.failBroadcasts = 1;
			const swap = clientSwap();
			await create(h, swap);
			const r = record(h, swap);
			h.holds.hold(
				swap.paymentHash,
				BigInt(r.invoiceMsat),
				r.refundHeight + 60
			);
			await settle();
			expect(record(h, swap).state).to.equal('FUNDING');
			const h2 = await h.restart();
			expect(h2.ledger.get(r.id)!.state).to.equal('FUNDING_BROADCAST');
			expect(h2.wallet.builds).to.have.length(1);
			expect(h2.chain.broadcasts).to.deep.equal([h2.wallet.builds[0]]);
		});

		it('CLAIMED retries the settle; REFUND_PENDING observes and finishes; REFUNDED re-cancels', async function () {
			const h = await harness();
			const { swap } = await fundedSwap(h);
			const r0 = record(h, swap);
			h.chain.confirm(r0.fundingTxid!, 1001);
			// Claim seen but the settle threw: the row stays CLAIMED with its
			// preimage, and the restart owes exactly the settle.
			h.chain.place(claimTxFor(r0, swap), 1002);
			h.holds.settleThrows = true;
			await h.engine.onBlock(1002);
			const claimed = record(h, swap);
			expect(claimed.state).to.equal('CLAIMED');
			expect(claimed.preimageHex).to.equal(swap.preimage.toString('hex'));
			expect(h.holds.settled).to.have.length(0);
			h.holds.settleThrows = false;
			const h2 = await h.restart();
			expect(h2.ledger.get(r0.id)!.state).to.equal('SETTLED');
			expect(h2.holds.settled).to.have.length(1);

			// A second swap parked in REFUND_PENDING with a confirmed refund.
			const { swap: two } = await fundedSwap(h2);
			const r2 = record(h2, two);
			h2.chain.confirm(r2.fundingTxid!, 1003);
			h2.chain.height = r2.refundHeight + 1;
			await h2.engine.onBlock(h2.chain.height);
			const pending = record(h2, two);
			expect(pending.state).to.equal('REFUND_PENDING');
			h2.chain.confirm(pending.refundTxid!, h2.chain.height);
			h2.chain.height += 3;
			const h3 = await h2.restart();
			expect(h3.ledger.get(r2.id)!.state).to.equal('REFUNDED');
			expect(h3.holds.cancelled).to.include(two.paymentHash.toString('hex'));
			// REFUNDED without the cancel recorded: re-cancelled on start, once.
			h3.ledger.patch(r2.id, { holdCancelledAt: undefined });
			h3.holds.cancelledHashes.delete(two.paymentHash.toString('hex'));
			const before = h3.holds.cancelled.length;
			const h4 = await h3.restart();
			expect(h4.holds.cancelled.length).to.equal(before + 1);
			expect(h4.ledger.get(r2.id)!.holdCancelledAt).to.be.a('number');
		});
	});

	it('drops a malformed frame and keeps serving', async function () {
		const h = await harness();
		h.client.sendCustomMessage(
			h.provider.id,
			BeignetCustomSubtype.SWAP_CREATE,
			Buffer.from([1, 2, 3])
		);
		await settle();
		expect(h.provider.escapedErrors).to.have.length(0);
		expect(h.logs.some((l) => l.action === 'swap_message_malformed')).to.equal(
			true
		);
		const q = await quote(h);
		expect(q.accepted).to.equal(true);
		const msg: IDfCustomMessage = {
			version: 1,
			peerPubkey: h.client.id,
			subtype: 999,
			payload: Buffer.alloc(0)
		};
		h.provider.deliver(msg);
	});
});
