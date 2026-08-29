/**
 * The direct-funding receiver engine (issue #612, LFBW port #532 workstream
 * 4C).
 *
 * The admission order arm by arm, idempotent replay including the receipt, the
 * id-reuse refusal, every cap (the concurrency one by its exact number), the
 * ownership-proof refusals for both script kinds and for a script we cannot
 * classify, and the unwind: a failure at each stage after funding starts must
 * leave no live channel and no mid-flight splice.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';

import { BeignetCustomSubtype } from '../../src/lightning/message/custom';
import { DirectFundingReceiver } from '../../src/lightning/direct-funding/receiver/engine';
import {
	decodeDfOfferAck,
	decodeDfReceipt,
	decodeDfSignRequest
} from '../../src/lightning/direct-funding/messages';
import {
	buildOffer,
	FakeDfNode,
	FakePayerLane,
	flush,
	IDfOfferOverrides,
	IDfTestCoin,
	LSP_PUBKEY,
	makeCoin
} from './helpers/df-receiver';
import { IDfReceiverConfig } from '../../src/lightning/direct-funding/receiver/types';

const ACK = BeignetCustomSubtype.DIRECT_FUNDING_OFFER_ACK;
const SIGN_REQUEST = BeignetCustomSubtype.DIRECT_FUNDING_SIGN_REQUEST;
const RECEIPT = BeignetCustomSubtype.DIRECT_FUNDING_RECEIPT;

interface IHarness {
	node: FakeDfNode;
	engine: DirectFundingReceiver;
	payer: FakePayerLane;
	coin: IDfTestCoin;
	offer: ReturnType<typeof buildOffer>;
	/** Deliver the offer and let admission run to the point it awaits. */
	sendOffer: (o?: ReturnType<typeof buildOffer>) => Promise<void>;
	acks: () => Array<{ accepted: boolean; reason?: string }>;
	lastAck: () => { accepted: boolean; reason?: string } | undefined;
}

function harness(
	config: IDfReceiverConfig = {},
	opts: {
		coinKind?: 'p2wpkh' | 'p2tr' | 'p2wsh';
		coinValue?: number;
		authenticatedPeer?: string;
		offer?: IDfOfferOverrides;
		publish?: boolean;
	} = {}
): IHarness {
	const node = new FakeDfNode();
	const engine = new DirectFundingReceiver(node, {
		negotiationTimeoutMs: 50,
		witnessTimeoutMs: 50,
		sweepIntervalMs: 60_000,
		...config
	});
	engine.start();
	const record = node.mintRequest();
	const payer = new FakePayerLane(record, 'payer-lane', opts.authenticatedPeer);
	const coin = makeCoin(opts.coinKind ?? 'p2wpkh', opts.coinValue ?? 100_000);
	if (opts.publish !== false) node.publish(coin);
	const offer = buildOffer(record, coin, opts.offer ?? {});
	const acks = (): Array<{ accepted: boolean; reason?: string }> =>
		payer.bodiesOf(ACK).map((b) => {
			const { accepted, reason } = decodeDfOfferAck(b);
			return reason === undefined ? { accepted } : { accepted, reason };
		});
	return {
		node,
		engine,
		payer,
		coin,
		offer,
		sendOffer: async (o = offer): Promise<void> => {
			engine.handleFrame(payer.offerFrame(o));
			await flush();
		},
		acks,
		lastAck: () => acks()[acks().length - 1]
	};
}

describe('Direct funding receiver: admission (issue #612)', () => {
	it('declines an offer when no liquidity peer is configured', async () => {
		const h = harness();
		h.node.lspPubkey = null;
		await h.sendOffer();
		expect(h.lastAck()).to.deep.equal({
			accepted: false,
			reason: 'no liquidity peer'
		});
		expect(h.node.opens).to.have.length(0);
	});

	it('declines an offer naming a receipt hash it did not open under', async () => {
		const h = harness();
		const offer = buildOffer(h.payer.requestRecord, h.coin, {
			receiptHash: crypto.randomBytes(32)
		});
		await h.sendOffer(offer);
		expect(h.lastAck()?.reason).to.contain('receipt hash does not match');
	});

	it('declines a second payment of a request whose receipt was revealed', async () => {
		const h = harness();
		h.node.requests.markReceiptRevealed(h.payer.requestRecord.receiptHash);
		await h.sendOffer();
		expect(h.lastAck()?.reason).to.equal('this request has already been paid');
	});

	it('applies the 5000 sat protocol floor under a lower configured minimum', async () => {
		const h = harness({ minAmountSat: 1_000n });
		const offer = buildOffer(h.payer.requestRecord, h.coin, {
			amountSat: 4_999n
		});
		await h.sendOffer(offer);
		expect(h.lastAck()?.reason).to.contain('5000 sat direct funding minimum');
	});

	it('applies a configured minimum above the floor', async () => {
		const h = harness({ minAmountSat: 50_000n });
		const offer = buildOffer(h.payer.requestRecord, h.coin, {
			amountSat: 20_000n
		});
		await h.sendOffer(offer);
		expect(h.lastAck()?.reason).to.contain('50000 sat direct funding minimum');
	});

	it('bounds the amount above, and against the coin it is offered from', async () => {
		const capped = harness({ maxAmountSat: 10_000n });
		await capped.sendOffer(
			buildOffer(capped.payer.requestRecord, capped.coin, {
				amountSat: 60_000n
			})
		);
		expect(capped.lastAck()?.reason).to.contain('maximum');

		const oversized = harness({}, { coinValue: 30_000 });
		await oversized.sendOffer(
			buildOffer(oversized.payer.requestRecord, oversized.coin, {
				amountSat: 40_000n
			})
		);
		expect(oversized.lastAck()?.reason).to.contain(
			'exceeds the value of the offered coin'
		);
	});

	it('refuses an offer id that is not derived from the outpoint and amount', async () => {
		const h = harness();
		await h.sendOffer(
			buildOffer(h.payer.requestRecord, h.coin, {
				offerId: crypto.randomBytes(16)
			})
		);
		expect(h.lastAck()?.reason).to.contain('offer id is not derived');
	});

	it('refuses a sequence the interactive transaction could never carry', async () => {
		const h = harness();
		await h.sendOffer(
			buildOffer(h.payer.requestRecord, h.coin, { sequence: 0xffffffff })
		);
		expect(h.lastAck()?.reason).to.contain('sequence must be at most');
		expect(h.node.opens).to.have.length(0);
	});

	it('refuses a sequence other than the one the receiver requires', async () => {
		const h = harness({ requiredSequence: 0xfffffffd });
		await h.sendOffer(
			buildOffer(h.payer.requestRecord, h.coin, { sequence: 0xfffffffc })
		);
		expect(h.lastAck()?.reason).to.equal('sequence must be 4294967293');
	});

	// Anything past 520 bytes never decodes at all: the TLV codec bounds the
	// field, which is the class of fork defect the encoding removes (D11).
	it('refuses a change script that is not a standard payable output', async () => {
		for (const changeScript of [
			Buffer.alloc(0),
			Buffer.from('6a0568656c6c6f', 'hex'),
			Buffer.alloc(520, 1)
		]) {
			const h = harness();
			await h.sendOffer(
				buildOffer(h.payer.requestRecord, h.coin, { changeScript })
			);
			expect(h.lastAck()?.reason).to.equal(
				'change script is not a standard payable output'
			);
			expect(h.node.opens).to.have.length(0);
		}
	});

	it('declines when the offered transaction is not on our chain source', async () => {
		const h = harness({}, { publish: false });
		await h.sendOffer();
		expect(h.lastAck()?.reason).to.equal(
			'offered transaction not found on chain'
		);
	});

	it('declines when the chain source answers with a different transaction', async () => {
		const h = harness();
		const other = makeCoin('p2wpkh', 12_345);
		h.node.transactions.set(h.coin.txidHex, other.prevTx.toBuffer());
		await h.sendOffer();
		expect(h.lastAck()?.reason).to.equal(
			'offered transaction not found on chain'
		);
	});

	it('declines when the named output is not worth what the offer claims', async () => {
		const h = harness();
		const lying = buildOffer(h.payer.requestRecord, h.coin, {});
		lying.valueSat = 999_999n;
		await h.sendOffer(lying);
		expect(h.lastAck()?.reason).to.contain('does not match the transaction');
	});

	it('declines a coin the chain says is already spent', async () => {
		const h = harness();
		h.node.markSpent(h.coin);
		await h.sendOffer();
		expect(h.lastAck()?.reason).to.equal('offered coin is already spent');
		expect(h.node.opens).to.have.length(0);
	});

	it('accepts a well-formed offer and opens a channel to the liquidity peer', async () => {
		const h = harness();
		await h.sendOffer();
		expect(h.acks()[0]).to.deep.equal({ accepted: true });
		expect(h.node.opens).to.have.length(1);
		expect(h.node.opens[0].peerHex).to.equal(LSP_PUBKEY);
		expect(h.node.opens[0].params.fundingSatoshis).to.equal(50_000n);
		const input = h.node.opens[0].params.contribution.inputs[0];
		expect(input.external).to.equal(true);
		expect(input.sequence).to.equal(0xfffffffd);
		expect(input.value).to.equal(h.coin.valueSat);
		expect(() => input.signWitness(new bitcoin.Transaction(), 0, 0n)).to.throw(
			'witness comes from the payer'
		);
	});

	it('sets confirmed from what the chain says, not from the payer', async () => {
		const confirmed = harness();
		await confirmed.sendOffer();
		expect(
			confirmed.node.opens[0].params.contribution.inputs[0].confirmed
		).to.equal(true);

		const mempool = harness();
		mempool.node.publish(mempool.coin, 0);
		await mempool.sendOffer();
		expect(
			mempool.node.opens[0].params.contribution.inputs[0].confirmed
		).to.equal(false);
	});

	it('leaves confirmed unknown when the chain source cannot answer', async () => {
		const h = harness();
		h.node.unspent.clear();
		h.node.history.clear();
		await h.sendOffer();
		expect(h.node.opens[0].params.contribution.inputs[0].confirmed).to.equal(
			undefined
		);
	});
});

describe('Direct funding receiver: ownership proof (issue #612)', () => {
	it('accepts a P2TR key-path proof against the output key in the script', async () => {
		const h = harness({}, { coinKind: 'p2tr' });
		await h.sendOffer();
		expect(h.acks()[0]).to.deep.equal({ accepted: true });
	});

	it('refuses a P2WPKH proof by a key that does not control the coin', async () => {
		const h = harness();
		await h.sendOffer(
			buildOffer(h.payer.requestRecord, h.coin, {
				ownershipPubkey: makeCoin().pubkey
			})
		);
		expect(h.lastAck()?.reason).to.equal(
			'ownership pubkey does not control the offered coin'
		);
	});

	it('refuses a P2WPKH proof whose signature does not verify', async () => {
		const h = harness();
		await h.sendOffer(
			buildOffer(h.payer.requestRecord, h.coin, {
				ownershipSignature: Buffer.alloc(64, 1)
			})
		);
		expect(h.lastAck()?.reason).to.equal('invalid ownership signature');
	});

	it('refuses a taproot proof whose signature does not verify', async () => {
		const h = harness({}, { coinKind: 'p2tr' });
		await h.sendOffer(
			buildOffer(h.payer.requestRecord, h.coin, {
				ownershipSignature: Buffer.alloc(64, 1)
			})
		);
		expect(h.lastAck()?.reason).to.equal('invalid taproot ownership signature');
	});

	it('refuses a script kind it cannot classify', async () => {
		const h = harness({}, { coinKind: 'p2wsh' });
		await h.sendOffer();
		expect(h.lastAck()?.reason).to.equal('unsupported input script');
	});

	/**
	 * Defect D1: the fork called the secp256k1 bindings bare, and they THROW on
	 * a malformed scalar. Four such offers took direct funding off the node for
	 * an hour, because the throw escaped before the in-flight flag was cleared.
	 */
	it('declines malformed proof bytes cleanly rather than wedging the session', async () => {
		const h = harness();
		const garbage = Buffer.alloc(64, 0xff);
		for (let i = 0; i < 8; i++) {
			const coin = makeCoin();
			h.node.publish(coin);
			await h.sendOffer(
				buildOffer(h.payer.requestRecord, coin, {
					ownershipSignature: garbage
				})
			);
		}
		expect(h.acks()).to.have.length(8);
		expect(h.acks().every((a) => a.accepted === false)).to.equal(true);
		expect(h.engine.inflightCount()).to.equal(0);
		expect(h.engine.sessionCount()).to.equal(0);

		// And the node still serves a good offer afterwards.
		await h.sendOffer();
		expect(h.lastAck()).to.deep.equal({ accepted: true });
	});
});

describe('Direct funding receiver: caps (issue #612)', () => {
	it('admits exactly maxInflightSessions concurrent sessions', async () => {
		const node = new FakeDfNode();
		const engine = new DirectFundingReceiver(node, {
			negotiationTimeoutMs: 5_000,
			sweepIntervalMs: 60_000
		});
		engine.start();
		const payers: FakePayerLane[] = [];
		for (let i = 0; i < 6; i++) {
			const record = node.mintRequest();
			const payer = new FakePayerLane(record, `lane-${i}`);
			const coin = makeCoin();
			node.publish(coin);
			payers.push(payer);
			engine.handleFrame(payer.offerFrame(buildOffer(record, coin)));
			await flush();
		}
		expect(node.opens, 'the default cap is 4').to.have.length(4);
		expect(engine.inflightCount()).to.equal(4);
		for (let i = 4; i < 6; i++) {
			const ack = decodeDfOfferAck(payers[i].bodiesOf(ACK)[0]);
			expect(ack.accepted).to.equal(false);
			expect(ack.reason).to.equal('too many concurrent funding sessions');
		}
		engine.stop();
	});

	it('spends at most maxRequestAttempts sessions on one request', async () => {
		const node = new FakeDfNode();
		const engine = new DirectFundingReceiver(node, {
			negotiationTimeoutMs: 5,
			witnessTimeoutMs: 5,
			sweepIntervalMs: 60_000
		});
		engine.start();
		const record = node.mintRequest();
		const payer = new FakePayerLane(record, 'lane');
		const reasons: string[] = [];
		for (let i = 0; i < 4; i++) {
			const coin = makeCoin();
			node.publish(coin);
			engine.handleFrame(payer.offerFrame(buildOffer(record, coin)));
			// Each attempt fails on the negotiation timeout, releasing its slot.
			await flush(20);
			reasons.push(
				String(decodeDfOfferAck(payer.bodiesOf(ACK).slice(-1)[0]).reason)
			);
		}
		expect(node.opens, 'three attempts reached a channel').to.have.length(3);
		expect(reasons[3]).to.equal('too many funding attempts for this request');
		engine.stop();
	});

	it('refuses a second offer while one is active on the same request', async () => {
		const node = new FakeDfNode();
		const engine = new DirectFundingReceiver(node, {
			negotiationTimeoutMs: 5_000,
			sweepIntervalMs: 60_000
		});
		engine.start();
		const record = node.mintRequest();
		const payer = new FakePayerLane(record, 'lane');
		const first = makeCoin();
		const second = makeCoin();
		node.publish(first);
		node.publish(second);
		engine.handleFrame(payer.offerFrame(buildOffer(record, first)));
		await flush();
		engine.handleFrame(payer.offerFrame(buildOffer(record, second)));
		await flush();
		expect(node.opens).to.have.length(1);
		expect(decodeDfOfferAck(payer.bodiesOf(ACK)[1]).reason).to.equal(
			'request already has an active funding attempt'
		);
		engine.stop();
	});

	it('refuses a different offer over an outpoint another session holds', async () => {
		const node = new FakeDfNode();
		const engine = new DirectFundingReceiver(node, {
			negotiationTimeoutMs: 5_000,
			sweepIntervalMs: 60_000
		});
		engine.start();
		const coin = makeCoin();
		node.publish(coin);
		const a = new FakePayerLane(node.mintRequest(), 'lane-a');
		const b = new FakePayerLane(node.mintRequest(), 'lane-b');
		engine.handleFrame(a.offerFrame(buildOffer(a.requestRecord, coin)));
		await flush();
		// A different AMOUNT is a different offer id over the same coin.
		engine.handleFrame(
			b.offerFrame(buildOffer(b.requestRecord, coin, { amountSat: 60_000n }))
		);
		await flush();
		expect(node.opens).to.have.length(1);
		expect(decodeDfOfferAck(b.bodiesOf(ACK)[0]).reason).to.equal(
			'input already committed to another offer'
		);
		engine.stop();
	});

	/**
	 * The offer id is a hash of the coin and the amount, so two REQUESTS can
	 * reach for it. A replay hands back a receipt, so it must only ever answer
	 * the request the recorded session was served for.
	 */
	it('never replays one request session to an offer opened under another', async () => {
		const node = new FakeDfNode();
		const engine = new DirectFundingReceiver(node, {
			negotiationTimeoutMs: 5_000,
			sweepIntervalMs: 60_000
		});
		engine.start();
		const coin = makeCoin();
		node.publish(coin);
		const a = new FakePayerLane(node.mintRequest(), 'lane-a');
		const b = new FakePayerLane(node.mintRequest(), 'lane-b');
		const offer = buildOffer(a.requestRecord, coin);
		engine.handleFrame(a.offerFrame(offer));
		await flush();
		// Same coin, same amount, so the SAME offer id, under another request.
		engine.handleFrame(b.offerFrame(buildOffer(b.requestRecord, coin)));
		await flush();
		expect(node.opens).to.have.length(1);
		expect(b.received.map((r) => r.subtype)).to.deep.equal([ACK]);
		expect(decodeDfOfferAck(b.bodiesOf(ACK)[0]).reason).to.equal(
			'offer id reused with different content'
		);
		engine.stop();
	});
});

describe('Direct funding receiver: idempotency (issue #612)', () => {
	it('replays a duplicate offer and starts nothing new', async () => {
		const h = harness({ negotiationTimeoutMs: 5_000 });
		await h.sendOffer();
		expect(h.node.opens).to.have.length(1);
		await h.sendOffer();
		expect(h.node.opens, 'no second channel session').to.have.length(1);
		const acks = h.acks();
		expect(acks).to.have.length(2);
		expect(acks[0]).to.deep.equal(acks[1]);
		expect(
			h.payer.bodiesOf(ACK)[0].equals(h.payer.bodiesOf(ACK)[1]),
			'byte-identical message bodies'
		).to.equal(true);
	});

	it('refuses an offer id reused with different content', async () => {
		const h = harness({ negotiationTimeoutMs: 5_000 });
		await h.sendOffer();
		const twisted = buildOffer(h.payer.requestRecord, h.coin, {
			maxTotalFeeSat: 9_999n
		});
		expect(twisted.offerId.equals(h.offer.offerId), 'same id').to.equal(true);
		await h.sendOffer(twisted);
		expect(h.node.opens).to.have.length(1);
		expect(h.lastAck()).to.deep.equal({
			accepted: false,
			reason: 'offer id reused with different content'
		});
	});

	it('judges a corrected offer fresh after a decline created no session', async () => {
		const h = harness({ negotiationTimeoutMs: 5_000 });
		await h.sendOffer(
			buildOffer(h.payer.requestRecord, h.coin, { sequence: 0xffffffff })
		);
		expect(h.lastAck()?.accepted).to.equal(false);
		expect(h.engine.sessionCount()).to.equal(0);
		await h.sendOffer();
		expect(h.lastAck()).to.deep.equal({ accepted: true });
	});
});

describe('Direct funding receiver: the exchange (issue #612)', () => {
	async function drive(
		config: IDfReceiverConfig = {},
		opts: Parameters<typeof harness>[1] = {}
	): Promise<IHarness> {
		const h = harness({ negotiationTimeoutMs: 5_000, ...config }, opts);
		await h.sendOffer();
		return h;
	}

	it('attests to the negotiated transaction and asks the payer to sign it', async () => {
		const h = await drive();
		const { tx } = h.node.completeNegotiation(h.coin, h.offer);
		await flush();
		const bodies = h.payer.bodiesOf(SIGN_REQUEST);
		expect(bodies).to.have.length(1);
		const request = decodeDfSignRequest(bodies[0]);
		expect(request.offerId.equals(h.offer.offerId)).to.equal(true);
		expect(request.rawTx.equals(tx.toBuffer())).to.equal(true);
		expect(request.prevouts).to.have.length(1);
		expect(request.prevouts[0].valueSat).to.equal(h.coin.valueSat);
		expect(request.prevouts[0].script.equals(h.coin.script)).to.equal(true);
		expect(request.attestation.fundingOutputIndex).to.equal(0);
		expect(request.attestation.signature).to.have.length(65);
		expect(request.sharedInputIndex).to.equal(undefined);
	});

	it('refuses to attest when the funding output is short of the offer', async () => {
		const h = await drive();
		h.node.completeNegotiation(h.coin, h.offer, {
			fundingValueSat: h.offer.amountSat - 1n
		});
		await flush();
		expect(h.payer.bodiesOf(SIGN_REQUEST)).to.have.length(0);
		expect(h.lastAck()?.reason).to.contain('below the offered');
		expect(h.node.aborts.map((a) => a.kind)).to.deep.equal(['open']);
	});

	it('refuses to attest when the payer would pay more fee than it allowed', async () => {
		const h = await drive();
		h.node.completeNegotiation(h.coin, h.offer, { feeSat: 5_000n });
		await flush();
		expect(h.payer.bodiesOf(SIGN_REQUEST)).to.have.length(0);
		expect(h.lastAck()?.reason).to.contain('above the 2000 sat it allowed');
	});

	it('refuses to attest when the change goes somewhere else', async () => {
		const h = await drive();
		h.node.completeNegotiation(h.coin, h.offer, {
			changeScript: bitcoin.payments.p2wpkh({
				hash: crypto.randomBytes(20)
			}).output!
		});
		await flush();
		expect(h.payer.bodiesOf(SIGN_REQUEST)).to.have.length(0);
		// No output pays the offered change script, so the whole remainder reads
		// as fee and blows the payer's ceiling.
		expect(h.lastAck()?.reason).to.contain('in fees');
	});

	it('delivers the witness, reveals the receipt and tombstones the request', async () => {
		const h = await drive();
		const { tx } = h.node.completeNegotiation(h.coin, h.offer, {
			witnessesFilled: true
		});
		await flush();
		h.engine.handleFrame(
			h.payer.witnessFrame(h.offer.offerId, [Buffer.alloc(64, 3)])
		);
		await flush();
		expect(h.node.witnesses).to.have.length(1);
		expect(h.node.witnesses[0].kind).to.equal('open');
		const receipts = h.payer.bodiesOf(RECEIPT);
		expect(receipts).to.have.length(1);
		const receipt = decodeDfReceipt(receipts[0]);
		expect(
			crypto.createHash('sha256').update(receipt.preimage).digest('hex')
		).to.equal(h.payer.requestRecord.receiptHash);
		expect(
			receipt.fundingTxid.equals(Buffer.from(tx.getHash()).reverse())
		).to.equal(true);
		expect(receipt.rawTx?.equals(tx.toBuffer())).to.equal(true);
		expect(h.node.requests.isTombstoned(h.payer.requestRecord.receiptHash)).to
			.be.true;
		expect(h.engine.inflightCount()).to.equal(0);
	});

	it('replays the receipt to a payer whose answer was lost', async () => {
		const h = await drive();
		h.node.completeNegotiation(h.coin, h.offer, { witnessesFilled: true });
		await flush();
		h.engine.handleFrame(
			h.payer.witnessFrame(h.offer.offerId, [Buffer.alloc(64, 3)])
		);
		await flush();
		expect(h.payer.bodiesOf(RECEIPT)).to.have.length(1);

		// The payer re-sends its offer over a DIFFERENT lane, as it would after
		// losing the answer and falling back to another transport.
		const again = new FakePayerLane(h.payer.requestRecord, 'other-lane');
		h.engine.handleFrame(again.offerFrame(h.offer));
		await flush();
		expect(h.node.opens, 'no second channel session').to.have.length(1);
		expect(again.bodiesOf(ACK)).to.have.length(1);
		expect(again.bodiesOf(SIGN_REQUEST)).to.have.length(1);
		const replayed = again.bodiesOf(RECEIPT);
		expect(replayed).to.have.length(1);
		expect(replayed[0].equals(h.payer.bodiesOf(RECEIPT)[0])).to.equal(true);
	});

	it('keeps waiting after a rejected witness and accepts the next one', async () => {
		const h = await drive({ witnessTimeoutMs: 2_000 });
		h.node.completeNegotiation(h.coin, h.offer);
		await flush();
		h.node.witnessError = 'invalid signature';
		h.engine.handleFrame(
			h.payer.witnessFrame(h.offer.offerId, [Buffer.alloc(64, 9)])
		);
		await flush();
		expect(h.payer.bodiesOf(RECEIPT)).to.have.length(0);
		h.node.witnessError = null;
		h.engine.handleFrame(
			h.payer.witnessFrame(h.offer.offerId, [Buffer.alloc(64, 3)])
		);
		await flush();
		expect(h.node.witnesses).to.have.length(2);
		expect(h.payer.bodiesOf(RECEIPT)).to.have.length(1);
	});

	it('ignores a witness naming another offer', async () => {
		const h = await drive();
		h.node.completeNegotiation(h.coin, h.offer);
		await flush();
		h.engine.handleFrame(
			h.payer.witnessFrame(crypto.randomBytes(16), [Buffer.alloc(64, 3)])
		);
		await flush();
		expect(h.node.witnesses).to.have.length(0);
	});

	it('sends the sign request even on a fully synchronous transport', async () => {
		const h = harness({ negotiationTimeoutMs: 5_000 });
		h.node.onOpenSideEffect = (): void => {
			h.node.completeNegotiation(h.coin, h.offer);
		};
		await h.sendOffer();
		expect(h.payer.bodiesOf(SIGN_REQUEST)).to.have.length(1);
	});

	it('accepts a witness answered inside the sign request send', async () => {
		const h = harness({ negotiationTimeoutMs: 5_000 });
		h.payer.onReceive = (subtype): void => {
			if (subtype !== SIGN_REQUEST) return;
			h.engine.handleFrame(
				h.payer.witnessFrame(h.offer.offerId, [Buffer.alloc(64, 3)])
			);
		};
		await h.sendOffer();
		h.node.completeNegotiation(h.coin, h.offer);
		await flush();
		expect(h.node.witnesses).to.have.length(1);
		expect(h.payer.bodiesOf(RECEIPT)).to.have.length(1);
	});
});

describe('Direct funding receiver: unwind (issue #612)', () => {
	it('unwinds the open when the negotiation never completes', async () => {
		const h = harness({ negotiationTimeoutMs: 5 });
		await h.sendOffer();
		expect(h.node.opens).to.have.length(1);
		await flush(20);
		expect(h.node.aborts).to.deep.equal([
			{ kind: 'open', channelId: h.node.opens[0].channelId.toString('hex') }
		]);
		expect(h.lastAck()?.accepted).to.equal(false);
		expect(h.engine.inflightCount()).to.equal(0);
	});

	it('unwinds the open when the attestation cannot be produced', async () => {
		const h = harness({ negotiationTimeoutMs: 5_000 });
		await h.sendOffer();
		h.node.pubkeysAvailable = false;
		h.node.completeNegotiation(h.coin, h.offer);
		await flush();
		expect(h.node.aborts.map((a) => a.kind)).to.deep.equal(['open']);
		expect(h.lastAck()?.reason).to.contain('funding pubkeys are unavailable');
	});

	it('unwinds the open when the payer never delivers its witness', async () => {
		const h = harness({ negotiationTimeoutMs: 5_000, witnessTimeoutMs: 5 });
		await h.sendOffer();
		h.node.completeNegotiation(h.coin, h.offer);
		await flush(20);
		expect(h.payer.bodiesOf(SIGN_REQUEST)).to.have.length(1);
		expect(h.node.aborts.map((a) => a.kind)).to.deep.equal(['open']);
		expect(h.engine.inflightCount()).to.equal(0);
	});

	it('does not unwind once the witness has reached the channel', async () => {
		const h = harness({ negotiationTimeoutMs: 5_000 });
		await h.sendOffer();
		h.node.completeNegotiation(h.coin, h.offer);
		await flush();
		// The tombstone write fails, so the exchange fails AFTER our
		// tx_signatures are already out.
		h.node.requests.markReceiptRevealed = (): void => {
			throw new Error('storage is gone');
		};
		h.engine.handleFrame(
			h.payer.witnessFrame(h.offer.offerId, [Buffer.alloc(64, 3)])
		);
		await flush();
		expect(h.node.witnesses).to.have.length(1);
		expect(
			h.node.aborts,
			'the funding belongs to the network now'
		).to.have.length(0);
		// And no decline contradicts the ack the payer already holds.
		expect(h.acks().filter((a) => !a.accepted)).to.have.length(0);
	});

	it('reports rather than throws when the unwind itself is refused', async () => {
		const h = harness({ negotiationTimeoutMs: 5 });
		h.node.abortError = 'cannot abort a v2 open after tx_signatures';
		await h.sendOffer();
		await flush(20);
		expect(h.node.aborts).to.have.length(1);
		expect(h.engine.inflightCount()).to.equal(0);
	});

	it('unwinds a mid-flight splice', async () => {
		const channelId = crypto.randomBytes(32);
		const h = harness(
			{ allowSplice: true, negotiationTimeoutMs: 5 },
			{ authenticatedPeer: 'payer-node-id' }
		);
		h.node.spliceChannel = channelId;
		h.node.trustedPayers.add('payer-node-id');
		await h.sendOffer();
		expect(h.node.splices).to.have.length(1);
		expect(h.node.opens).to.have.length(0);
		await flush(20);
		expect(h.node.aborts).to.deep.equal([
			{ kind: 'splice', channelId: channelId.toString('hex') }
		]);
	});

	it('releases the slot when the open itself throws', async () => {
		const h = harness();
		h.node.openThrows = new Error('funding provider unavailable');
		await h.sendOffer();
		expect(h.engine.inflightCount()).to.equal(0);
		expect(h.lastAck()?.reason).to.contain('funding provider unavailable');
		expect(h.node.aborts).to.have.length(0);
	});
});

describe('Direct funding receiver: routing and zero-conf (issue #612)', () => {
	async function open(opts: {
		authenticated?: boolean;
		trusted?: boolean;
		zeroConf?: boolean;
	}): Promise<FakeDfNode> {
		const peer = 'payer-node-id';
		const h = harness(
			{ negotiationTimeoutMs: 5_000 },
			{ authenticatedPeer: opts.authenticated ? peer : undefined }
		);
		if (opts.trusted) h.node.trustedPayers.add(peer);
		if (opts.zeroConf) h.node.zeroConfPeers.add(LSP_PUBKEY);
		await h.sendOffer();
		return h.node;
	}

	it('asks for zero-conf only for an authenticated, paired payer', async () => {
		const anonymous = await open({ zeroConf: true, trusted: true });
		expect(anonymous.opens[0].params.trusted).to.equal(undefined);

		const unpaired = await open({ authenticated: true, zeroConf: true });
		expect(unpaired.opens[0].params.trusted).to.equal(undefined);

		const noUpstreamTrust = await open({ authenticated: true, trusted: true });
		expect(noUpstreamTrust.opens[0].params.trusted).to.equal(undefined);

		const allowed = await open({
			authenticated: true,
			trusted: true,
			zeroConf: true
		});
		expect(allowed.opens[0].params.trusted).to.equal(true);
	});

	it('keeps an anonymous payer on the new-channel path even with a channel to splice', async () => {
		const h = harness({ allowSplice: true, negotiationTimeoutMs: 5_000 });
		h.node.spliceChannel = crypto.randomBytes(32);
		await h.sendOffer();
		expect(h.node.splices).to.have.length(0);
		expect(h.node.opens).to.have.length(1);
	});

	it('keeps every payer on the new-channel path while splicing is off', async () => {
		const h = harness(
			{ negotiationTimeoutMs: 5_000 },
			{ authenticatedPeer: 'payer-node-id' }
		);
		h.node.trustedPayers.add('payer-node-id');
		h.node.spliceChannel = crypto.randomBytes(32);
		await h.sendOffer();
		expect(h.node.splices).to.have.length(0);
		expect(h.node.opens).to.have.length(1);
	});

	it('splices for an authenticated, paired payer and attests to the new capacity', async () => {
		const h = harness(
			{ allowSplice: true, negotiationTimeoutMs: 5_000 },
			{ authenticatedPeer: 'payer-node-id' }
		);
		h.node.spliceChannel = crypto.randomBytes(32);
		h.node.trustedPayers.add('payer-node-id');
		await h.sendOffer();
		expect(h.node.splices).to.have.length(1);
		expect(h.node.splices[0].amountSats).to.equal(50_000n);
		expect(h.node.splices[0].inputs[0].external).to.equal(true);
		h.node.completeSpliceNegotiation(h.coin, h.offer, 200_000n);
		await flush();
		const request = decodeDfSignRequest(h.payer.bodiesOf(SIGN_REQUEST)[0]);
		expect(request.sharedInputIndex).to.equal(1);
		expect(request.prevouts).to.have.length(2);
		h.engine.handleFrame(
			h.payer.witnessFrame(h.offer.offerId, [Buffer.alloc(64, 3)])
		);
		await flush();
		expect(h.node.witnesses[0].kind).to.equal('splice');
		expect(h.payer.bodiesOf(RECEIPT)).to.have.length(1);
	});

	it('refuses to attest a splice whose new funding output lost the old capacity', async () => {
		const h = harness(
			{ allowSplice: true, negotiationTimeoutMs: 5_000 },
			{ authenticatedPeer: 'payer-node-id' }
		);
		h.node.spliceChannel = crypto.randomBytes(32);
		h.node.trustedPayers.add('payer-node-id');
		await h.sendOffer();
		// The shared input is worth 200k, so the new funding output owes
		// 200k + the payment; this one holds the payment alone.
		h.node.completeSpliceNegotiation(h.coin, h.offer, 200_000n, {
			fundingValueSat: h.offer.amountSat
		});
		await flush();
		expect(h.payer.bodiesOf(SIGN_REQUEST)).to.have.length(0);
		expect(h.lastAck()?.reason).to.contain('below the offered');
		expect(h.node.aborts.map((a) => a.kind)).to.deep.equal(['splice']);
	});
});

describe('Direct funding receiver: frames it will not open (issue #612)', () => {
	it('is silent about a frame sealed to a request it did not mint', async () => {
		const h = harness();
		const stranger = new FakeDfNode();
		const other = new FakePayerLane(stranger.mintRequest(), 'lane');
		h.engine.handleFrame(
			other.offerFrame(buildOffer(other.requestRecord, h.coin))
		);
		await flush();
		expect(other.sent).to.have.length(0);
		expect(h.engine.sessionCount()).to.equal(0);
	});

	it('is silent about a continuation frame carrying an offer', async () => {
		const h = harness();
		const frame = h.payer.frame(
			BeignetCustomSubtype.DIRECT_FUNDING_OFFER,
			Buffer.alloc(4),
			false
		);
		h.engine.handleFrame(frame);
		await flush();
		expect(h.payer.sent).to.have.length(0);
	});

	it('is silent when the lane bound the frame to a different request', async () => {
		const h = harness();
		const frame = h.payer.offerFrame(h.offer);
		frame.boundRequestId = crypto.randomBytes(16);
		h.engine.handleFrame(frame);
		await flush();
		expect(h.payer.sent).to.have.length(0);
	});

	it('ignores subtypes that belong to the payer role', async () => {
		const h = harness();
		h.engine.handleFrame(h.payer.frame(SIGN_REQUEST, Buffer.alloc(4), false));
		await flush();
		expect(h.payer.sent).to.have.length(0);
	});
});
