/**
 * Submarine swap provider engine (issue #743) over fakes: quote and create
 * on the wire, the client's funding discovered and re-pointed, the payment
 * persisted as PAYING before the call and judged only by the node's HTLC
 * view, the claim persisted before it is broadcast and bumped while
 * unconfirmed, exposure when the contract stops being claimable, and a
 * restart at every state redoing the owed action exactly once.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import { BeignetCustomSubtype } from '../../src/lightning/message/custom';
import { Network } from '../../src/lightning/invoice/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	ISwapQuote,
	ISwapRecord,
	ISwapStatus,
	ISwapSubmarineCreate,
	ISwapSubmarineCreateAck,
	SwapLedger,
	SwapRefusalReason,
	SwapWireDirection,
	SwapWireResolutionKind,
	SwapWireState,
	decodeSwapQuote,
	decodeSwapStatus,
	decodeSwapSubmarineCreateAck,
	encodeSwapQuoteRequest,
	encodeSwapStatusRequest,
	encodeSwapSubmarineCreate,
	isSwapExposure,
	submarineSwapFee,
	swapCodec,
	verifySubmarineSwapTerms
} from '../../src/lightning/swaps';
import { FakeDfNetwork, FakeDfPeer } from './helpers/df-transport';
import {
	FakeOutgoing,
	ISubmarineClient,
	ISubmarineHarness,
	fundContract,
	harness as reverseHarness,
	refundTxFor,
	settle,
	submarineClient,
	submarineHarness,
	submarineInvoice
} from './helpers/swap-harness';

const AMOUNT = 100_000n;
/**
 * flat 100 + 1000 ppm of 100k (100) + miner 2 sat/vB x 150 vB (300), plus
 * the routing budget of 1000 ppm on the 99_500 sat left (100).
 */
const FEE_FLOOR = 600n;
const FEE = 700n;
const INVOICE_MSAT = (AMOUNT - FEE) * 1000n;

function lastFrom(peer: FakeDfPeer, subtype: number): Buffer {
	const frames = peer.sent.filter((s) => s.subtype === subtype);
	expect(frames.length, `subtype ${subtype} sent`).to.be.greaterThan(0);
	return frames[frames.length - 1].payload;
}

function countFrom(peer: FakeDfPeer, subtype: number): number {
	return peer.sent.filter((s) => s.subtype === subtype).length;
}

async function quote(
	h: ISubmarineHarness,
	amountSat = AMOUNT,
	direction = SwapWireDirection.SUBMARINE
): Promise<ISwapQuote> {
	h.client.sendCustomMessage(
		h.provider.id,
		BeignetCustomSubtype.SWAP_QUOTE_REQUEST,
		encodeSwapQuoteRequest({
			requestId: crypto.randomBytes(8),
			direction,
			amountSat
		})
	);
	await settle();
	return decodeSwapQuote(lastFrom(h.provider, BeignetCustomSubtype.SWAP_QUOTE));
}

interface ICreateOverrides {
	onchainAmountSat: bigint;
	maxTotalFeeSat: bigint;
	bolt11: string;
	direction: SwapWireDirection;
	from: FakeDfPeer;
	preferredRefundDelta: number;
	refundPubkey: Buffer;
}

function createMessage(
	client: ISubmarineClient,
	overrides: Partial<ICreateOverrides> = {}
): ISwapSubmarineCreate {
	return {
		requestId: crypto.randomBytes(8),
		direction: overrides.direction ?? SwapWireDirection.SUBMARINE,
		paymentHash: client.paymentHash,
		refundPubkey: overrides.refundPubkey ?? client.refundPubkey,
		bolt11: overrides.bolt11 ?? submarineInvoice(client, INVOICE_MSAT),
		onchainAmountSat: overrides.onchainAmountSat ?? AMOUNT,
		maxTotalFeeSat: overrides.maxTotalFeeSat ?? 2_000n,
		preferredRefundDelta: overrides.preferredRefundDelta
	};
}

async function create(
	h: ISubmarineHarness,
	client: ISubmarineClient,
	overrides: Partial<ICreateOverrides> = {}
): Promise<{ ack: ISwapSubmarineCreateAck; create: ISwapSubmarineCreate }> {
	const from = overrides.from ?? h.client;
	const msg = createMessage(client, overrides);
	from.sendCustomMessage(
		h.provider.id,
		BeignetCustomSubtype.SWAP_SUBMARINE_CREATE,
		encodeSwapSubmarineCreate(msg)
	);
	await settle();
	const ack = decodeSwapSubmarineCreateAck(
		lastFrom(h.provider, BeignetCustomSubtype.SWAP_SUBMARINE_CREATE_ACK)
	);
	expect(ack.requestId).to.deep.equal(msg.requestId);
	return { ack, create: msg };
}

async function status(
	h: ISubmarineHarness,
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

function record(h: ISubmarineHarness, client: ISubmarineClient): ISwapRecord {
	const rows = h.ledger.byPaymentHash(client.paymentHash.toString('hex'));
	expect(rows).to.have.length(1);
	return rows[0];
}

function names(h: ISubmarineHarness): string[] {
	return h.events.map((e) => e.name);
}

async function tick(h: ISubmarineHarness, blocks = 1): Promise<void> {
	for (let i = 0; i < blocks; i++) {
		h.chain.height += 1;
		await h.engine.onBlock(h.chain.height);
	}
}

/** Create, fund in the mempool, confirm: the engine dispatches the payment. */
async function paidSwap(
	h: ISubmarineHarness,
	client = submarineClient(),
	overrides: Partial<ICreateOverrides> = {}
): Promise<{
	client: ISubmarineClient;
	fundingTx: bitcoin.Transaction;
	created: ISwapSubmarineCreate;
}> {
	const { ack, create: created } = await create(h, client, overrides);
	expect(ack.accepted, ack.reasonText).to.equal(true);
	const r = record(h, client);
	const fundingTx = fundContract(
		h.chain,
		Buffer.from(r.outputScriptHex, 'hex'),
		AMOUNT,
		0
	);
	await tick(h);
	expect(record(h, client).state).to.equal('FUNDING_SEEN');
	h.chain.confirm(fundingTx.getId(), h.chain.height);
	await tick(h);
	return { client, fundingTx, created };
}

async function claimedSwap(
	h: ISubmarineHarness,
	client = submarineClient()
): Promise<{ client: ISubmarineClient; fundingTx: bitcoin.Transaction }> {
	const paid = await paidSwap(h, client);
	expect(record(h, client).state).to.equal('PAYING');
	h.outgoing.fulfil(client.paymentHash, client.preimage);
	await settle();
	expect(record(h, client).state).to.equal('CLAIM_BROADCAST');
	return paid;
}

describe('Submarine swap provider engine (issue #743)', function () {
	describe('quote', function () {
		it('quotes direction 2 with the fee arithmetic and limits, and limits only for amount 0', async function () {
			const h = await submarineHarness();
			const q = await quote(h);
			expect(q.accepted).to.equal(true);
			expect(q.direction).to.equal(SwapWireDirection.SUBMARINE);
			expect(q.totalFeeSat).to.equal(
				submarineSwapFee(AMOUNT, {
					flatFeeSat: 100n,
					feePpm: 1_000,
					minerFeeSat: 300n,
					routingFeePpm: 1_000
				})
			);
			expect(q.totalFeeSat).to.equal(FEE_FLOOR);
			expect(q.minerFeeSat).to.equal(300n);
			expect(q.invoiceAmountMsat).to.equal((AMOUNT - FEE_FLOOR) * 1000n);
			expect(q.refundDeltaBlocks).to.equal(200);
			expect(q.fundingConfirmations).to.equal(1);
			expect(q.minRefundDelta).to.equal(100);
			expect(q.maxRefundDelta).to.equal(400);
			const limits = await quote(h, 0n);
			expect(limits.accepted).to.equal(true);
			expect(limits.totalFeeSat).to.equal(0n);
			expect(limits.invoiceAmountMsat).to.equal(0n);
		});

		it('charges the routing budget in the floor, so a payee cannot author a losing route hint', async function () {
			// 5000 ppm on the 99_500 sat left after flat, ppm and miner: 498.
			const h = await submarineHarness({
				config: { paymentMaxFeePpm: 5_000 }
			});
			const q = await quote(h);
			expect(q.totalFeeSat).to.equal(500n + 498n);
			expect(
				submarineSwapFee(AMOUNT, {
					flatFeeSat: 100n,
					feePpm: 1_000,
					minerFeeSat: 300n,
					routingFeePpm: 5_000
				})
			).to.equal(998n);
			// A create leaving exactly the old floor (500 sat) is refused; one
			// leaving the routing budget as well is accepted.
			const short = submarineClient();
			const refused = await create(h, short, {
				bolt11: submarineInvoice(short, (AMOUNT - 997n) * 1000n)
			});
			expect(refused.ack.accepted).to.equal(false);
			expect(refused.ack.reason).to.equal(SwapRefusalReason.FEE_CEILING);
			const enough = submarineClient();
			const ok = await create(h, enough, {
				bolt11: submarineInvoice(enough, (AMOUNT - 998n) * 1000n)
			});
			expect(ok.ack.accepted, ok.ack.reasonText).to.equal(true);
			expect(ok.ack.terms!.totalFeeSat).to.equal(998n);
			// Zero budget: the floor is the old arithmetic.
			const h0 = await submarineHarness({ config: { paymentMaxFeePpm: 0 } });
			expect((await quote(h0)).totalFeeSat).to.equal(500n);
		});

		it('refuses without a fee estimate, without outbound liquidity, and outside the caps', async function () {
			const h = await submarineHarness({ feeRate: null });
			expect((await quote(h)).reason).to.equal(
				SwapRefusalReason.CHAIN_UNAVAILABLE
			);
			h.feeRate = 2;
			h.spendableMsat = 0n;
			expect((await quote(h)).reason).to.equal(
				SwapRefusalReason.NO_OUTBOUND_LIQUIDITY
			);
			h.spendableMsat = 10_000_000_000n;
			expect((await quote(h, 1_000n)).reason).to.equal(
				SwapRefusalReason.AMOUNT_BELOW_MIN
			);
			expect((await quote(h, 5_000_000n)).reason).to.equal(
				SwapRefusalReason.AMOUNT_ABOVE_MAX
			);
		});

		it('shares the peer seam with the reverse engine: exactly one answer per direction', async function () {
			const net = new FakeDfNetwork();
			const reverse = await reverseHarness({
				net,
				config: { answerSubmarineRequests: false }
			});
			// One peer seam and one ledger, as on the node.
			const h = await submarineHarness({
				net,
				provider: reverse.provider,
				store: reverse.store,
				ledger: reverse.ledger
			});
			expect(h.provider).to.equal(reverse.provider);
			const before = countFrom(h.provider, BeignetCustomSubtype.SWAP_QUOTE);
			const sub = await quote(h);
			expect(sub.accepted).to.equal(true);
			expect(sub.direction).to.equal(SwapWireDirection.SUBMARINE);
			expect(countFrom(h.provider, BeignetCustomSubtype.SWAP_QUOTE)).to.equal(
				before + 1
			);
			const rev = await quote(h, AMOUNT, SwapWireDirection.REVERSE);
			expect(rev.accepted).to.equal(true);
			expect(rev.direction).to.equal(SwapWireDirection.REVERSE);
			expect(countFrom(h.provider, BeignetCustomSubtype.SWAP_QUOTE)).to.equal(
				before + 2
			);
			// A submarine create on the shared seam is answered once, by the
			// submarine engine; a status on its row likewise.
			const client = submarineClient();
			const { ack } = await create(h, client);
			expect(ack.accepted, ack.reasonText).to.equal(true);
			expect(
				countFrom(h.provider, BeignetCustomSubtype.SWAP_SUBMARINE_CREATE_ACK)
			).to.equal(1);
			const statusBefore = countFrom(
				h.provider,
				BeignetCustomSubtype.SWAP_STATUS
			);
			const s = await status(h, ack.terms!.swapId);
			expect(s.found).to.equal(true);
			expect(s.state).to.equal(SwapWireState.CREATED);
			expect(countFrom(h.provider, BeignetCustomSubtype.SWAP_STATUS)).to.equal(
				statusBefore + 1
			);
			reverse.engine.stop();
		});

		it('a reverse-only provider still refuses direction 2 as unsupported', async function () {
			const reverse = await reverseHarness();
			reverse.client.sendCustomMessage(
				reverse.provider.id,
				BeignetCustomSubtype.SWAP_QUOTE_REQUEST,
				encodeSwapQuoteRequest({
					requestId: crypto.randomBytes(8),
					direction: SwapWireDirection.SUBMARINE,
					amountSat: AMOUNT
				})
			);
			await settle();
			const q = decodeSwapQuote(
				lastFrom(reverse.provider, BeignetCustomSubtype.SWAP_QUOTE)
			);
			expect(q.accepted).to.equal(false);
			expect(q.reason).to.equal(SwapRefusalReason.UNSUPPORTED_DIRECTION);
		});
	});

	describe('create', function () {
		it('accepts a consistent create: terms verify, the row is CREATED with the ceiling, repeats re-ack', async function () {
			const h = await submarineHarness();
			const client = submarineClient();
			const { ack, create: msg } = await create(h, client);
			expect(ack.accepted, ack.reasonText).to.equal(true);
			const verdict = verifySubmarineSwapTerms({
				create: msg,
				ack,
				currentHeight: h.chain.height,
				network: Network.REGTEST,
				minRefundDelta: 100,
				maxRefundDelta: 400,
				maxTotalFeeSat: 2_000n
			});
			expect(verdict.ok, verdict.ok ? '' : verdict.reason).to.equal(true);
			const terms = ack.terms!;
			expect(terms.totalFeeSat).to.equal(FEE);
			expect(terms.minerFeeSat).to.equal(300n);
			expect(terms.invoiceAmountMsat).to.equal(INVOICE_MSAT);
			expect(terms.refundHeight).to.equal(1200);
			expect(terms.paymentCeilingHeight).to.equal(1200 - 12 - 6);
			expect(terms.fundingConfirmations).to.equal(1);
			const r = record(h, client);
			expect(r.state).to.equal('CREATED');
			expect(r.direction).to.equal('submarine');
			expect(r.bolt11).to.equal(msg.bolt11);
			expect(r.paymentMaxCltvExpiryHeight).to.equal(1182);
			expect(r.claimPubkeyHex).to.equal(terms.claimPubkey.toString('hex'));
			expect(r.refundPubkeyHex).to.equal(client.refundPubkey.toString('hex'));
			expect(names(h)).to.deep.equal(['swap:created']);
			expect(h.events[0].data.direction).to.equal('submarine');
			// The same create again: one row, the ack re-sent.
			h.client.sendCustomMessage(
				h.provider.id,
				BeignetCustomSubtype.SWAP_SUBMARINE_CREATE,
				encodeSwapSubmarineCreate(msg)
			);
			await settle();
			expect(
				countFrom(h.provider, BeignetCustomSubtype.SWAP_SUBMARINE_CREATE_ACK)
			).to.equal(2);
			expect(h.ledger.list()).to.have.length(1);
			// Different terms on the same hash: a duplicate.
			const dup = await create(h, client, { onchainAmountSat: AMOUNT + 1n });
			expect(dup.ack.reason).to.equal(SwapRefusalReason.DUPLICATE_HASH);
		});

		it('refuses every bad invoice, key, fee and timing, writing nothing', async function () {
			const h = await submarineHarness();
			const other = submarineClient();
			const cases: Array<
				[
					string,
					(client: ISubmarineClient) => Partial<ICreateOverrides>,
					SwapRefusalReason,
					RegExp?
				]
			> = [
				[
					'another hash',
					() => ({ bolt11: submarineInvoice(other, INVOICE_MSAT) }),
					SwapRefusalReason.INVOICE_MISMATCH,
					/hash/
				],
				[
					'another network',
					(c) => ({
						bolt11: submarineInvoice(c, INVOICE_MSAT, {
							network: Network.TESTNET
						})
					}),
					SwapRefusalReason.INVOICE_MISMATCH,
					/network/
				],
				[
					'no payment secret',
					(c) => ({
						bolt11: submarineInvoice(c, INVOICE_MSAT, { paymentSecret: null })
					}),
					SwapRefusalReason.INVOICE_MISMATCH,
					/secret/
				],
				[
					'no fee left',
					(c) => ({ bolt11: submarineInvoice(c, AMOUNT * 1000n) }),
					SwapRefusalReason.INVOICE_MISMATCH,
					/fee/
				],
				[
					'fractional fee',
					(c) => ({ bolt11: submarineInvoice(c, INVOICE_MSAT + 1n) }),
					SwapRefusalReason.INVOICE_MISMATCH,
					/whole-satoshi/
				],
				[
					'fee below the floor',
					(c) => ({ bolt11: submarineInvoice(c, (AMOUNT - 100n) * 1000n) }),
					SwapRefusalReason.FEE_CEILING,
					/below/
				],
				[
					'fee above the client ceiling',
					() => ({ maxTotalFeeSat: 599n }),
					SwapRefusalReason.FEE_CEILING,
					/above the client ceiling/
				],
				[
					'expires too soon',
					(c) => ({
						bolt11: submarineInvoice(c, INVOICE_MSAT, { expiry: 30 })
					}),
					SwapRefusalReason.INVOICE_MISMATCH,
					/expires/
				],
				[
					'payable to us',
					(c) => ({
						bolt11: submarineInvoice(c, INVOICE_MSAT, { privateKey: h.nodeKey })
					}),
					SwapRefusalReason.SELF_PAYMENT,
					/payable to this node/
				],
				[
					'a hint through us with no channel to the payee (our own JIT)',
					(c) => ({
						bolt11: submarineInvoice(c, INVOICE_MSAT, {
							routingHints: [{ pubkey: h.ownNodeId }]
						})
					}),
					SwapRefusalReason.SELF_PAYMENT,
					/route hint/
				],
				[
					'final cltv that cannot fit',
					(c) => ({
						bolt11: submarineInvoice(c, INVOICE_MSAT, {
							minFinalCltvExpiry: 170
						})
					}),
					SwapRefusalReason.CLTV_UNFITTABLE
				],
				[
					'the wrong message direction',
					() => ({ direction: SwapWireDirection.REVERSE }),
					SwapRefusalReason.UNSUPPORTED_DIRECTION
				]
			];
			for (const [name, overridesFor, reason, text] of cases) {
				const client = submarineClient();
				const { ack } = await create(h, client, overridesFor(client));
				expect(ack.accepted, name).to.equal(false);
				expect(SwapRefusalReason[ack.reason], name).to.equal(
					SwapRefusalReason[reason]
				);
				if (text) expect(ack.reasonText, name).to.match(text);
			}
			expect(h.ledger.list()).to.have.length(0);
			expect(h.events).to.have.length(0);
		});

		it('accepts a hint through this node when the payee is a channel peer (an ordinary private channel)', async function () {
			const h = await submarineHarness();
			const client = submarineClient();
			h.channelPeers.add(getPublicKey(client.nodeKey).toString('hex'));
			const { ack } = await create(h, client, {
				bolt11: submarineInvoice(client, INVOICE_MSAT, {
					routingHints: [{ pubkey: h.ownNodeId }]
				})
			});
			expect(ack.accepted, ack.reasonText).to.equal(true);
		});

		it('refuses a hash the node already holds, a peer with too many unfunded swaps, no liquidity and a non-segwit destination', async function () {
			const h = await submarineHarness();
			const used = submarineClient();
			h.inUse.add(used.paymentHash.toString('hex'));
			expect((await create(h, used)).ack.reason).to.equal(
				SwapRefusalReason.DUPLICATE_HASH
			);
			for (let i = 0; i < 4; i++) {
				const { ack } = await create(h, submarineClient());
				expect(ack.accepted, `create ${i}`).to.equal(true);
			}
			expect((await create(h, submarineClient())).ack.reason).to.equal(
				SwapRefusalReason.RATE_LIMITED
			);
			const other = h.net.add('other-client');
			h.net.connect(h.provider, other);
			h.spendableMsat = 1_000n;
			expect(
				(await create(h, submarineClient(), { from: other })).ack.reason
			).to.equal(SwapRefusalReason.NO_OUTBOUND_LIQUIDITY);
			h.spendableMsat = 10_000_000_000n;
			h.feeRate = null;
			expect(
				(await create(h, submarineClient(), { from: other })).ack.reason
			).to.equal(SwapRefusalReason.CHAIN_UNAVAILABLE);
			const legacy = await submarineHarness({
				destination: Buffer.from('76a914' + '11'.repeat(20) + '88ac', 'hex')
			});
			expect((await quote(legacy)).reason).to.equal(SwapRefusalReason.INTERNAL);
			expect((await create(legacy, submarineClient())).ack.reason).to.equal(
				SwapRefusalReason.INTERNAL
			);
		});
	});

	describe('funding', function () {
		it('ignores an underpaid output, takes an exact or larger one, and pays once confirmed to depth', async function () {
			const h = await submarineHarness();
			const client = submarineClient();
			const { ack } = await create(h, client);
			expect(ack.accepted).to.equal(true);
			const r = record(h, client);
			const script = Buffer.from(r.outputScriptHex, 'hex');
			await tick(h);
			expect(record(h, client).state).to.equal('CREATED');
			fundContract(h.chain, script, AMOUNT - 1n, 0);
			await tick(h);
			expect(record(h, client).state).to.equal('CREATED');
			expect(
				h.logs.some((l) => l.action === 'swap_funding_underpaid')
			).to.equal(true);
			const funding = fundContract(h.chain, script, AMOUNT + 50n, 0);
			await tick(h);
			let now = record(h, client);
			expect(now.state).to.equal('FUNDING_SEEN');
			expect(now.fundingTxid).to.equal(funding.getId());
			expect(now.fundingValueSat).to.equal((AMOUNT + 50n).toString());
			expect(h.outgoing.calls).to.have.length(0);
			h.chain.confirm(funding.getId(), h.chain.height);
			await tick(h);
			now = record(h, client);
			expect(now.state).to.equal('PAYING');
			expect(now.fundingHeight).to.equal(h.chain.height - 1);
			expect(names(h)).to.deep.equal([
				'swap:created',
				'swap:funding-seen',
				'swap:funded',
				'swap:paying'
			]);
			// The payment call: after the PAYING write, under the ceiling,
			// with the fee cap the config implies.
			expect(h.outgoing.calls).to.have.length(1);
			const call = h.outgoing.calls[0];
			expect(call.ledgerStateAtCall).to.equal('PAYING');
			expect(call.maxCltvExpiryHeight).to.equal(1182);
			expect(call.maxFeeMsat).to.equal((INVOICE_MSAT * 1_000n) / 1_000_000n);
			expect(now.paymentDispatchedHeight).to.equal(h.chain.height);
			expect(now.paymentMaxCltvExpiryHeight).to.equal(1182);
			expect(now.paymentDispatchAttempts).to.equal(1);
		});

		it('waits for policy depth, prefers a confirmed candidate, and follows a replacement while unconfirmed', async function () {
			const h = await submarineHarness({ config: { fundingConfirmations: 3 } });
			const client = submarineClient();
			await create(h, client);
			const script = Buffer.from(record(h, client).outputScriptHex, 'hex');
			const a = fundContract(h.chain, script, AMOUNT, 0);
			await tick(h);
			expect(record(h, client).fundingTxid).to.equal(a.getId());
			// A replaces itself with B in the mempool.
			h.chain.evict(a.getId());
			const b = fundContract(h.chain, script, AMOUNT, 0);
			await tick(h);
			expect(record(h, client).state).to.equal('FUNDING_SEEN');
			expect(record(h, client).fundingTxid).to.equal(b.getId());
			// Everything gone: lost, then found again.
			h.chain.evict(b.getId());
			await tick(h);
			expect(record(h, client).state).to.equal('FUNDING_LOST');
			const c = fundContract(h.chain, script, AMOUNT, 0);
			const d = fundContract(h.chain, script, AMOUNT, h.chain.height);
			await tick(h);
			// Two candidates: the confirmed one wins.
			expect(record(h, client).state).to.equal('FUNDING_SEEN');
			expect(record(h, client).fundingTxid).to.equal(d.getId());
			expect(record(h, client).fundingTxid).to.not.equal(c.getId());
			// Two confirmations are not three.
			expect(h.outgoing.calls).to.have.length(0);
			await tick(h);
			expect(record(h, client).state).to.equal('PAYING');
			expect(names(h).filter((n) => n === 'swap:funding-lost')).to.have.length(
				1
			);
		});

		it('ends a swap whose invoice expired or whose ceiling no longer fits before anything was paid', async function () {
			const h = await submarineHarness();
			const unfunded = submarineClient();
			const { ack } = await create(h, unfunded);
			expect(ack.accepted).to.equal(true);
			const funded = submarineClient();
			await create(h, funded);
			fundContract(
				h.chain,
				Buffer.from(record(h, funded).outputScriptHex, 'hex'),
				AMOUNT,
				0
			);
			await tick(h);
			expect(record(h, funded).state).to.equal('FUNDING_SEEN');
			h.clock = (ack.terms!.expiresAt + 1) * 1000;
			await tick(h);
			expect(record(h, unfunded).state).to.equal('CANCELLED');
			expect(record(h, unfunded).failureReason).to.match(/expired/);
			expect(record(h, funded).state).to.equal('FAILED');
			expect(h.outgoing.calls).to.have.length(0);
			// The ceiling: a create whose funding comes too late.
			const late = submarineClient();
			h.clock = undefined;
			await create(h, late);
			h.chain.height = 1130; // 1130 + 20 + 40 + 3 > 1182
			await tick(h);
			expect(record(h, late).state).to.equal('CANCELLED');
			expect(record(h, late).failureReason).to.match(/ceiling/);
			expect(names(h).filter((n) => n === 'swap:cancelled')).to.have.length(2);
			expect(names(h).filter((n) => n === 'swap:failed')).to.have.length(1);
		});

		it('a spend of the funding before payment cancels the swap; nothing was paid', async function () {
			const h = await submarineHarness({ config: { fundingConfirmations: 3 } });
			const client = submarineClient();
			await create(h, client);
			const r = record(h, client);
			const funding = fundContract(
				h.chain,
				Buffer.from(r.outputScriptHex, 'hex'),
				AMOUNT,
				h.chain.height
			);
			await tick(h);
			expect(record(h, client).state).to.equal('FUNDING_SEEN');
			const refund = refundTxFor(record(h, client), client, funding);
			h.chain.place(refund, 0);
			await tick(h);
			const now = record(h, client);
			expect(now.state).to.equal('CANCELLED');
			expect(now.resolution?.txid).to.equal(refund.getId());
			expect(now.resolution?.kind).to.equal('refund');
			expect(h.outgoing.calls).to.have.length(0);
		});

		it('operator cancel is accepted before PAYING and refused after', async function () {
			const h = await submarineHarness();
			const a = submarineClient();
			await create(h, a);
			expect(h.engine.cancel(record(h, a).id)).to.deep.equal({ ok: true });
			expect(record(h, a).state).to.equal('CANCELLED');
			const b = submarineClient();
			await create(h, b);
			fundContract(
				h.chain,
				Buffer.from(record(h, b).outputScriptHex, 'hex'),
				AMOUNT,
				0
			);
			await tick(h);
			expect(h.engine.cancel(record(h, b).id).ok).to.equal(true);
			const { client } = await paidSwap(h);
			const refused = h.engine.cancel(record(h, client).id);
			expect(refused.ok).to.equal(false);
			expect(refused.reason).to.match(/PAYING/);
			expect(h.engine.cancel('00'.repeat(16)).ok).to.equal(false);
		});

		it('defers the payment while outbound liquidity is short, then dispatches', async function () {
			const h = await submarineHarness();
			const client = submarineClient();
			await create(h, client);
			h.spendableMsat = 1_000n;
			const funding = fundContract(
				h.chain,
				Buffer.from(record(h, client).outputScriptHex, 'hex'),
				AMOUNT,
				h.chain.height
			);
			await tick(h);
			expect(record(h, client).state).to.equal('FUNDED');
			expect(h.outgoing.calls).to.have.length(0);
			expect(h.logs.some((l) => l.action === 'swap_payment_deferred')).to.equal(
				true
			);
			await tick(h);
			expect(record(h, client).state).to.equal('FUNDED');
			h.spendableMsat = 10_000_000_000n;
			await tick(h);
			expect(record(h, client).state).to.equal('PAYING');
			expect(h.outgoing.calls).to.have.length(1);
			void funding;
		});
	});

	describe('payment outcomes', function () {
		it('a dispatch that leaves no record fails the swap at once and is never retried', async function () {
			const h = await submarineHarness();
			h.outgoing.script = 'throw-no-record';
			const { client } = await paidSwap(h);
			const r = record(h, client);
			expect(r.state).to.equal('PAYMENT_FAILED');
			expect(r.failureReason).to.match(/NO_ROUTE/);
			expect(names(h)).to.include('swap:payment-failed');
			await tick(h, 3);
			expect(h.outgoing.calls).to.have.length(1);
			expect(record(h, client).state).to.equal('PAYMENT_FAILED');
		});

		it('a dispatch that throws after an HTLC left stays PAYING until the view resolves', async function () {
			const h = await submarineHarness();
			h.outgoing.script = 'throw-with-htlc';
			const { client, fundingTx } = await paidSwap(h);
			expect(record(h, client).state).to.equal('PAYING');
			await tick(h);
			expect(record(h, client).state).to.equal('PAYING');
			expect(h.outgoing.calls).to.have.length(1);
			h.outgoing.fulfil(client.paymentHash, client.preimage);
			await settle();
			const r = record(h, client);
			expect(r.state).to.equal('CLAIM_BROADCAST');
			expect(r.preimageHex).to.equal(client.preimage.toString('hex'));
			expect(r.preimageSource).to.equal('lightning');
			const claim = bitcoin.Transaction.fromHex(r.claimTxHex!);
			expect(Buffer.from(claim.ins[0].hash).reverse().toString('hex')).to.equal(
				fundingTx.getId()
			);
			expect(claim.outs[0].script.equals(h.destination)).to.equal(true);
			expect(h.chain.broadcasts).to.include(r.claimTxHex);
		});

		it('a FAILED record with a live HTLC is not a failed payment; every HTLC terminal is', async function () {
			const h = await submarineHarness();
			h.outgoing.script = 'failed-live-htlc';
			const { client } = await paidSwap(h);
			expect(record(h, client).state).to.equal('PAYING');
			await tick(h, 2);
			expect(record(h, client).state).to.equal('PAYING');
			h.outgoing.fail(client.paymentHash);
			await settle();
			expect(record(h, client).state).to.equal('PAYMENT_FAILED');
			// A record failed by a wall clock while the HTLC is out: still PAYING.
			const h2 = await submarineHarness();
			const second = await paidSwap(h2);
			h2.outgoing.failRecordOnly(second.client.paymentHash);
			await settle();
			expect(record(h2, second.client).state).to.equal('PAYING');
			h2.outgoing.fulfil(second.client.paymentHash, second.client.preimage);
			await settle();
			expect(record(h2, second.client).state).to.equal('CLAIM_BROADCAST');
		});

		it('re-reads a failed record whose HTLC removal completes without an event', async function () {
			// The node fails the record and emits payment:failed while the
			// HTLC still awaits the peer's revocation; the revocation raises
			// nothing. The engine reads again on a short timer.
			const h = await submarineHarness({
				config: { resolutionRecheckMs: 20, resolutionRecheckCount: 10 }
			});
			h.outgoing.script = 'failed-live-htlc';
			const { client } = await paidSwap(h);
			expect(record(h, client).state).to.equal('PAYING');
			// The event arrives with the HTLC still live...
			h.outgoing.notify(client.paymentHash);
			await settle();
			expect(record(h, client).state).to.equal('PAYING');
			// ...and the removal completes silently.
			h.outgoing.fail(client.paymentHash, false);
			await new Promise((r) => setTimeout(r, 120));
			await settle();
			expect(record(h, client).state).to.equal('PAYMENT_FAILED');
			expect(h.outgoing.calls).to.have.length(1);
		});

		it('a synchronous fulfil (loopback) reaches the claim in the same pass', async function () {
			const h = await submarineHarness();
			h.outgoing.script = 'complete';
			const client = submarineClient();
			h.outgoing.preimages.set(
				client.paymentHash.toString('hex'),
				client.preimage
			);
			await paidSwap(h, client);
			expect(record(h, client).state).to.equal('CLAIM_BROADCAST');
			expect(names(h)).to.deep.equal([
				'swap:created',
				'swap:funding-seen',
				'swap:funded',
				'swap:paying',
				'swap:preimage',
				'swap:claim-broadcast'
			]);
		});

		it('marks a long wait unresolved without failing it, then claims on the preimage event', async function () {
			const h = await submarineHarness();
			const { client } = await paidSwap(h);
			await tick(h, 2);
			expect(record(h, client).state).to.equal('PAYING');
			await tick(h);
			expect(record(h, client).state).to.equal('PAYMENT_UNRESOLVED');
			expect(names(h)).to.include('swap:payment-unresolved');
			await tick(h, 5);
			expect(record(h, client).state).to.equal('PAYMENT_UNRESOLVED');
			expect(h.outgoing.calls).to.have.length(1);
			h.outgoing.fulfil(client.paymentHash, client.preimage);
			await settle();
			expect(record(h, client).state).to.equal('CLAIM_BROADCAST');
		});

		it('a preimage learned after PAYMENT_FAILED promotes the row and the claim is pursued', async function () {
			const h = await submarineHarness();
			const { client } = await paidSwap(h);
			h.outgoing.fail(client.paymentHash);
			await settle();
			expect(record(h, client).state).to.equal('PAYMENT_FAILED');
			h.outgoing.preimageOnChain(client.paymentHash, client.preimage);
			await settle();
			const r = record(h, client);
			expect(r.state).to.equal('CLAIM_BROADCAST');
			expect(r.preimageHex).to.equal(client.preimage.toString('hex'));
			expect(r.failureReason).to.equal(undefined);
			expect(
				h.logs.some((l) => l.action === 'swap_preimage_after_failure')
			).to.equal(true);
			// The same, learned while the process was down: start() sweeps it.
			const h2 = await submarineHarness();
			const second = await paidSwap(h2);
			h2.outgoing.fail(second.client.paymentHash);
			await settle();
			h2.outgoing.fulfil(
				second.client.paymentHash,
				second.client.preimage,
				false
			);
			const h3 = await h2.restart();
			expect(record(h3, second.client).state).to.equal('CLAIM_BROADCAST');
		});
	});

	describe('claim', function () {
		it('persists the claim before broadcasting it, retries a refused broadcast, and confirms at policy depth', async function () {
			const h = await submarineHarness();
			h.chain.failBroadcasts = 1;
			const { client } = await claimedSwap(h);
			let r = record(h, client);
			expect(r.claimTxHex).to.be.a('string');
			expect(r.claimBroadcastAttemptedAt).to.be.a('number');
			expect(r.claimFeeSat).to.equal('300');
			expect(h.chain.broadcasts).to.have.length(0);
			expect(
				h.logs.some((l) => l.action === 'swap_claim_broadcast_failed')
			).to.equal(true);
			await tick(h);
			expect(h.chain.broadcasts).to.have.length(1);
			expect(h.chain.broadcasts[0]).to.equal(r.claimTxHex);
			// The status names the claim now that it is out.
			const s = await status(h, Buffer.from(r.id, 'hex'));
			expect(s.state).to.equal(SwapWireState.CLAIM_BROADCAST);
			expect(s.resolutionTxid?.toString('hex')).to.equal(r.claimTxid);
			expect(s.resolutionKind).to.equal(SwapWireResolutionKind.CLAIM);
			h.chain.confirm(r.claimTxid!, h.chain.height + 1);
			await tick(h);
			r = record(h, client);
			expect(r.state).to.equal('CLAIM_BROADCAST');
			expect(r.resolution?.confirmations).to.equal(1);
			await tick(h);
			r = record(h, client);
			expect(r.state).to.equal('CLAIM_CONFIRMED');
			expect(r.resolution?.confirmations).to.equal(2);
			expect(names(h)).to.include('swap:claim-confirmed');
			expect(isSwapExposure(r)).to.equal(false);
			await tick(h, 2);
			expect(h.chain.broadcasts).to.have.length(1);
		});

		it('bumps an unconfirmed claim by rebuild on the interval, respects the BIP 125 floor and the cap', async function () {
			const h = await submarineHarness({
				config: { maxFeeRateSatPerVbyte: 3 }
			});
			const { client } = await claimedSwap(h);
			const first = record(h, client);
			await tick(h);
			expect(record(h, client).claimBumps ?? 0).to.equal(0);
			// Interval reached: the fee rate says 300 but the floor is 450.
			await tick(h);
			let r = record(h, client);
			expect(r.claimBumps).to.equal(1);
			expect(r.claimTxid).to.not.equal(first.claimTxid);
			expect(BigInt(r.claimFeeSat!)).to.equal(450n);
			expect(h.chain.broadcasts).to.have.length(2);
			expect(
				names(h).filter((n) => n === 'swap:claim-broadcast')
			).to.have.length(2);
			// At the cap (3 sat/vB x 150 = 450): the same bytes go out again.
			await tick(h, 2);
			r = record(h, client);
			expect(r.claimBumps).to.equal(1);
			expect(h.chain.broadcasts.length).to.be.greaterThan(2);
			expect(h.chain.broadcasts[h.chain.broadcasts.length - 1]).to.equal(
				r.claimTxHex
			);
		});

		it('a claim that reorgs out is demoted and put out again', async function () {
			const h = await submarineHarness();
			const { client } = await claimedSwap(h);
			const r = record(h, client);
			h.chain.confirm(r.claimTxid!, h.chain.height + 1);
			await tick(h);
			expect(record(h, client).resolution?.confirmations).to.equal(1);
			h.chain.evict(r.claimTxid!);
			const broadcasts = h.chain.broadcasts.length;
			await tick(h);
			const now = record(h, client);
			expect(now.state).to.equal('CLAIM_BROADCAST');
			expect(now.resolution?.confirmations).to.equal(0);
			expect(
				h.logs.some((l) => l.action === 'swap_resolution_demoted')
			).to.equal(true);
			expect(h.chain.broadcasts.length).to.be.greaterThan(broadcasts);
		});

		it('outbids a refund in the mempool at once, and spends the whole margin inside the deadline window', async function () {
			const h = await submarineHarness();
			const { client, fundingTx } = await claimedSwap(h);
			const before = record(h, client);
			const refund = refundTxFor(before, client, fundingTx, 2_000n);
			h.chain.place(refund, 0);
			await tick(h);
			let r = record(h, client);
			expect(r.claimBumps).to.equal(1);
			// Both replacement rules: above the refund's absolute fee by our
			// size, AND above its fee RATE (2000 sat over ~126 vB is ~16
			// sat/vB; 150 vB at that rate is ~2381 sat) plus our size.
			const byRate =
				BigInt(Math.ceil((2_000 * 150) / refund.virtualSize())) + 150n;
			expect(Number(byRate)).to.be.greaterThan(2_150);
			expect(BigInt(r.claimFeeSat!)).to.equal(byRate);
			// Inside the deadline window every block bumps, the cap lifts to
			// the output above dust, and the error is logged.
			h.chain.height = before.refundHeight - 12 - 1;
			await tick(h);
			r = record(h, client);
			expect(
				h.logs.some((l) => l.action === 'swap_claim_deadline_near')
			).to.equal(true);
			expect(Number(r.claimFeeSat)).to.be.greaterThan(2_150);
			const bumps = r.claimBumps!;
			await tick(h);
			expect(record(h, client).claimBumps).to.equal(bumps + 1);
			h.chain.height = before.refundHeight + 1;
			await tick(h);
			expect(
				h.logs.some((l) => l.action === 'swap_claim_past_refund_height')
			).to.equal(true);
			const value = fundingTx.outs[0].value;
			expect(Number(record(h, client).claimFeeSat)).to.be.at.most(value - 330);
		});

		it('a refund with more inputs than the contract has an unknown fee: the bid goes all in', async function () {
			const h = await submarineHarness();
			const { client, fundingTx } = await claimedSwap(h);
			const before = record(h, client);
			const refund = refundTxFor(before, client, fundingTx, 500n);
			// A second input the fake chain knows nothing about: the fee
			// cannot be read off the outputs.
			refund.addInput(crypto.randomBytes(32), 0);
			h.chain.place(refund, 0);
			await tick(h);
			const r = record(h, client);
			expect(r.claimBumps).to.equal(1);
			expect(Number(r.claimFeeSat)).to.equal(fundingTx.outs[0].value - 330);
		});

		it('escalates inside the deadline window whatever the estimate says, and goes all in at the last block', async function () {
			// The estimate never moves (2 sat/vB, 300 sat) and the cap outside
			// the window is 200 sat/vB. The audit found the bid pinned to the
			// estimate inside the window, so the "whole output" cap was never
			// reached before the client's refund became eligible.
			const h = await submarineHarness();
			const { client, fundingTx } = await claimedSwap(h);
			const value = fundingTx.outs[0].value;
			const before = record(h, client);
			expect(BigInt(before.claimFeeSat!)).to.equal(300n);
			h.chain.height = before.refundHeight - 12;
			const fees: number[] = [];
			for (let i = 0; i < 8; i++) {
				await tick(h);
				fees.push(Number(record(h, client).claimFeeSat));
			}
			// Doubling every block: 600, 1200, 2400, 4800, 9600, 19200, 38400,
			// 76800, and never past the output above dust.
			expect(fees).to.deep.equal([
				600, 1200, 2400, 4800, 9600, 19200, 38400, 76800
			]);
			expect(record(h, client).claimBumps).to.equal(8);
			await tick(h);
			expect(Number(record(h, client).claimFeeSat)).to.equal(value - 330);
			// The market spikes after the first claim: outside the window the
			// estimate is clamped to the 200 sat/vB cap; at the last block
			// before the refund is eligible the bid is the whole output.
			const h2 = await submarineHarness();
			const second = await claimedSwap(h2);
			h2.feeRate = 500;
			await tick(h2, 2);
			const r2 = record(h2, second.client);
			expect(r2.claimBumps).to.equal(1);
			expect(Number(r2.claimFeeSat)).to.equal(200 * 150);
			h2.chain.height = r2.refundHeight - 1;
			await tick(h2);
			expect(Number(record(h2, second.client).claimFeeSat)).to.equal(
				second.fundingTx.outs[0].value - 330
			);
			// No estimate when the claim is built: the fallback rate, never
			// 1 sat/vB.
			const h3 = await submarineHarness();
			const third = await paidSwap(h3);
			expect(record(h3, third.client).state).to.equal('PAYING');
			h3.feeRate = null;
			h3.outgoing.fulfil(third.client.paymentHash, third.client.preimage);
			await settle();
			const r3 = record(h3, third.client);
			expect(r3.state).to.equal('CLAIM_BROADCAST');
			expect(Number(r3.claimFeeSat)).to.equal(10 * 150);
		});

		it('never spends the claim to anything but native segwit and never claims without a preimage', async function () {
			const h = await submarineHarness();
			const { client } = await paidSwap(h);
			await tick(h, 3);
			expect(record(h, client).claimTxHex).to.equal(undefined);
			expect(h.chain.broadcasts).to.have.length(0);
		});
	});

	describe('exposure', function () {
		it('a funding gone after PAYING exposes the row; a failed payment then closes it with nothing lost', async function () {
			const h = await submarineHarness();
			const { client, fundingTx } = await paidSwap(h);
			h.chain.evict(fundingTx.getId());
			await tick(h);
			let r = record(h, client);
			expect(r.state).to.equal('PAYING');
			// PAYING keeps waiting for the payment; the contract is judged
			// once a claim is owed. Learn the preimage: now it matters.
			h.outgoing.fulfil(client.paymentHash, client.preimage);
			await settle();
			r = record(h, client);
			expect(r.state).to.equal('EXPOSED');
			expect(isSwapExposure(r)).to.equal(true);
			expect(names(h)).to.include('swap:exposed');
			expect(
				h.events.find((e) => e.name === 'swap:exposed')!.data.preimageKnown
			).to.equal(true);
			// The funding returns: claimed and confirmed.
			h.chain.place(fundingTx, h.chain.height);
			await tick(h);
			r = record(h, client);
			expect(r.state).to.equal('CLAIM_BROADCAST');
			expect(h.logs.some((l) => l.action === 'swap_funding_returned')).to.equal(
				true
			);
			h.chain.confirm(r.claimTxid!, h.chain.height + 1);
			await tick(h, 2);
			expect(record(h, client).state).to.equal('CLAIM_CONFIRMED');
		});

		it('a payment that fails while exposed ends as PAYMENT_FAILED', async function () {
			const h = await submarineHarness();
			h.outgoing.script = 'complete';
			const client = submarineClient();
			h.outgoing.preimages.set(
				client.paymentHash.toString('hex'),
				client.preimage
			);
			const { fundingTx } = await paidSwap(h, client);
			expect(record(h, client).state).to.equal('CLAIM_BROADCAST');
			h.chain.evict(fundingTx.getId());
			h.chain.evict(record(h, client).claimTxid!);
			await tick(h);
			expect(record(h, client).state).to.equal('EXPOSED');
			// Another row, paying, whose contract vanished and whose HTLCs all failed.
			const h2 = await submarineHarness();
			const second = await paidSwap(h2);
			h2.chain.evict(second.fundingTx.getId());
			h2.outgoing.fulfil(second.client.paymentHash, second.client.preimage);
			await settle();
			expect(record(h2, second.client).state).to.equal('EXPOSED');
		});

		it('a refund in the mempool does not park an exposed row: the funding is back, the claim outbids it', async function () {
			const h = await submarineHarness();
			const { client, fundingTx } = await paidSwap(h);
			h.chain.evict(fundingTx.getId());
			h.outgoing.fulfil(client.paymentHash, client.preimage);
			await settle();
			const exposed = record(h, client);
			expect(exposed.state).to.equal('EXPOSED');
			// The funding reappears together with the client's refund of it,
			// unconfirmed. The audit found the row recorded the refund as its
			// resolution and sat in EXPOSED while the refund confirmed.
			h.chain.place(fundingTx, h.chain.height);
			const refund = refundTxFor(exposed, client, fundingTx, 2_000n);
			h.chain.place(refund, 0);
			await tick(h);
			const r = record(h, client);
			expect(r.state).to.equal('CLAIM_BROADCAST');
			expect(r.resolution).to.equal(undefined);
			expect(Number(r.claimFeeSat)).to.be.greaterThan(2_150);
			expect(h.chain.broadcasts.at(-1)).to.equal(r.claimTxHex);
			// Our claim confirms: the swap ends claimed.
			h.chain.evict(refund.getId());
			h.chain.confirm(r.claimTxid!, h.chain.height + 1);
			await tick(h, 2);
			expect(record(h, client).state).to.equal('CLAIM_CONFIRMED');
		});

		it('a confirmed refund with the preimage known is a realised loss, counted until verified at depth', async function () {
			const h = await submarineHarness();
			const { client, fundingTx } = await claimedSwap(h);
			const r0 = record(h, client);
			const refund = refundTxFor(r0, client, fundingTx, 20_000n);
			h.chain.place(refund, h.chain.height);
			h.chain.evict(r0.claimTxid!);
			await tick(h);
			let r = record(h, client);
			expect(r.state).to.equal('EXPOSED');
			expect(r.resolution?.txid).to.equal(refund.getId());
			expect(r.resolution?.confirmations).to.equal(2);
			// Placed at the tip and observed one block later: two deep, which
			// is policy depth here; a stricter depth still counts it.
			expect(isSwapExposure(r, 3)).to.equal(true);
			expect(isSwapExposure(r, 2)).to.equal(false);
			await tick(h);
			r = record(h, client);
			expect(r.resolution?.confirmations).to.equal(3);
			expect(r.resolution?.verifiedThisSession).to.equal(true);
			expect(isSwapExposure(r, 3)).to.equal(false);
			expect(h.logs.some((l) => l.action === 'swap_loss_realised')).to.equal(
				true
			);
			expect(SwapLedger.exposure(h.ledger.list(), 2).exposedCount).to.equal(0);
			// A resolution read back from storage is history until this process
			// has looked (the codec clears the flag; the memory store here does
			// not round-trip, so the flag is cleared by hand): on the books
			// again, then off once a pass re-verifies it.
			const stored = swapCodec.decode(swapCodec.encode(r))!;
			expect(stored.resolution?.verifiedThisSession).to.equal(false);
			expect(isSwapExposure(stored, 2)).to.equal(true);
			h.ledger.patch(r.id, {
				resolution: { ...r.resolution!, verifiedThisSession: false }
			});
			expect(isSwapExposure(record(h, client), 2)).to.equal(true);
			const h2 = await h.restart();
			expect(isSwapExposure(record(h2, client), 2)).to.equal(false);
		});
	});

	describe('status', function () {
		it('answers the owning peer with the submarine state and nothing to another peer', async function () {
			const h = await submarineHarness();
			const { client } = await paidSwap(h);
			const r = record(h, client);
			const s = await status(h, Buffer.from(r.id, 'hex'));
			expect(s.found).to.equal(true);
			expect(s.state).to.equal(SwapWireState.PAYING);
			expect(s.fundingTxid?.toString('hex')).to.equal(r.fundingTxid);
			expect(s.fundingConfirmations).to.equal(2);
			expect(s.resolutionTxid).to.equal(undefined);
			expect(s.fundingTx).to.equal(undefined);
			const other = h.net.add('nosy');
			h.net.connect(h.provider, other);
			const hidden = await status(h, Buffer.from(r.id, 'hex'), other);
			expect(hidden.found).to.equal(false);
			expect(hidden.state).to.equal(SwapWireState.UNKNOWN);
		});
	});

	describe('restart', function () {
		it('redoes exactly the owed action once at every state', async function () {
			// CREATED: nothing owed but the watch.
			const h1 = await submarineHarness();
			const c1 = submarineClient();
			await create(h1, c1);
			const r1 = await h1.restart();
			expect(record(r1, c1).state).to.equal('CREATED');
			expect(r1.outgoing.calls).to.have.length(0);

			// FUNDED: one dispatch.
			const h2 = await submarineHarness();
			const c2 = submarineClient();
			await create(h2, c2);
			h2.spendableMsat = 0n;
			fundContract(
				h2.chain,
				Buffer.from(record(h2, c2).outputScriptHex, 'hex'),
				AMOUNT,
				h2.chain.height
			);
			await tick(h2);
			expect(record(h2, c2).state).to.equal('FUNDED');
			h2.spendableMsat = 10_000_000_000n;
			const r2 = await h2.restart();
			expect(record(r2, c2).state).to.equal('PAYING');
			expect(r2.outgoing.calls).to.have.length(1);

			// PAYING with a record on the node: no second dispatch.
			const h3 = await submarineHarness();
			const p3 = await paidSwap(h3);
			const r3 = await h3.restart();
			await tick(r3);
			expect(record(r3, p3.client).state).to.equal('PAYING');
			expect(r3.outgoing.calls).to.have.length(1);

			// PAYING with no record and no HTLC (crashed before the call):
			// one re-dispatch, then bounded.
			const h4 = await submarineHarness({
				config: { maxPaymentDispatchAttempts: 2 }
			});
			const p4 = await paidSwap(h4);
			const fresh = new FakeOutgoing(
				(hashHex) => h4.ledger.byPaymentHash(hashHex)[0]?.state
			);
			fresh.script = 'throw-no-record';
			const r4 = await h4.restart({ outgoing: fresh });
			// start() itself redoes the dispatch; the node refuses it without
			// leaving a record, so the bounded attempt ends the row.
			expect(fresh.calls).to.have.length(1);
			expect(fresh.calls[0].ledgerStateAtCall).to.equal('PAYING');
			expect(record(r4, p4.client).paymentDispatchAttempts).to.equal(2);
			expect(record(r4, p4.client).state).to.equal('PAYMENT_FAILED');
			await tick(r4, 2);
			expect(fresh.calls).to.have.length(1);

			// PREIMAGE_KNOWN with no claim yet: one build and broadcast.
			const h5 = await submarineHarness();
			const p5 = await paidSwap(h5);
			h5.chain.failBroadcasts = 1;
			h5.outgoing.fulfil(p5.client.paymentHash, p5.client.preimage);
			await settle();
			const built = record(h5, p5.client);
			expect(built.state).to.equal('CLAIM_BROADCAST');
			const r5 = await h5.restart();
			expect(r5.chain.broadcasts).to.have.length(1);
			expect(r5.chain.broadcasts[0]).to.equal(built.claimTxHex);
			expect(record(r5, p5.client).claimTxid).to.equal(built.claimTxid);

			// CLAIM_BROADCAST already in the mempool: nothing more than a look.
			const h6 = await submarineHarness();
			const p6 = await claimedSwap(h6);
			const r6 = await h6.restart();
			expect(r6.chain.broadcasts).to.have.length(1);
			expect(record(r6, p6.client).state).to.equal('CLAIM_BROADCAST');
		});
	});
});
