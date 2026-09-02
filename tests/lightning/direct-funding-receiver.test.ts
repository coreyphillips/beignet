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
import { DF_REQUESTS_STORAGE_KEY } from '../../src/lightning/direct-funding/requests';
import {
	buildOffer,
	FakeDfNode,
	FakePayerLane,
	flush,
	IDfOfferOverrides,
	IDfTestCoin,
	LSP_PUBKEY,
	makeCoin,
	memoryStorage
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

async function captureUnhandledRejections(
	fn: () => Promise<void>
): Promise<unknown[]> {
	const prior = process.listeners('unhandledRejection');
	process.removeAllListeners('unhandledRejection');
	const seen: unknown[] = [];
	const probe = (reason: unknown): void => {
		seen.push(reason);
	};
	process.on('unhandledRejection', probe);
	try {
		await fn();
	} finally {
		process.removeListener('unhandledRejection', probe);
		for (const listener of prior) {
			process.on('unhandledRejection', listener);
		}
	}
	return seen;
}

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
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

	it('rechecks payment state after a concurrent chain lookup', async () => {
		const node = new FakeDfNode();
		const record = node.mintRequest();
		const firstCoin = makeCoin();
		const delayedCoin = makeCoin();
		node.publish(firstCoin);
		node.publish(delayedCoin);
		const firstOffer = buildOffer(record, firstCoin);
		const delayedOffer = buildOffer(record, delayedCoin, {
			amountSat: 51_000n
		});
		const firstPayer = new FakePayerLane(record, 'first-lane');
		const delayedPayer = new FakePayerLane(record, 'delayed-lane');
		const getTransaction = node.chain.getTransaction;
		let releaseDelayed!: () => void;
		const delayedTransaction = new Promise<Buffer>((resolve) => {
			releaseDelayed = (): void => resolve(delayedCoin.prevTx.toBuffer());
		});
		node.chain.getTransaction = async (txid): Promise<Buffer> =>
			txid === delayedCoin.txidHex ? delayedTransaction : getTransaction(txid);
		const engine = new DirectFundingReceiver(node, {
			negotiationTimeoutMs: 5_000,
			sweepIntervalMs: 60_000
		});
		engine.start();

		engine.handleFrame(delayedPayer.offerFrame(delayedOffer));
		engine.handleFrame(firstPayer.offerFrame(firstOffer));
		await flush();
		node.completeNegotiation(firstCoin, firstOffer, {
			witnessesFilled: true
		});
		await flush();
		engine.handleFrame(
			firstPayer.witnessFrame(firstOffer.offerId, [Buffer.alloc(64, 3)])
		);
		await flush();
		expect(firstPayer.bodiesOf(RECEIPT)).to.have.length(1);

		releaseDelayed();
		await flush(8);
		expect(node.opens).to.have.length(1);
		expect(node.witnesses).to.have.length(1);
		expect(delayedPayer.bodiesOf(RECEIPT)).to.have.length(0);
		expect(decodeDfOfferAck(delayedPayer.bodiesOf(ACK)[0])).to.deep.equal({
			offerId: delayedOffer.offerId,
			accepted: false,
			reason: 'this request has already been paid'
		});
		expect(engine.inflightCount()).to.equal(0);
		engine.stop();
	});

	it('serves a fixed-amount request only at the amount it fixed', async () => {
		const node = new FakeDfNode();
		const engine = new DirectFundingReceiver(node, {
			negotiationTimeoutMs: 5_000,
			sweepIntervalMs: 60_000
		});
		engine.start();
		const record = node.mintRequest(undefined, 100_000n);
		const coin = makeCoin('p2wpkh', 200_000);
		node.publish(coin);

		const underpayer = new FakePayerLane(record, 'under-lane');
		engine.handleFrame(
			underpayer.offerFrame(buildOffer(record, coin, { amountSat: 50_000n }))
		);
		await flush();
		expect(node.opens).to.have.length(0);
		expect(decodeDfOfferAck(underpayer.bodiesOf(ACK)[0]).reason).to.equal(
			'this request must be paid exactly 100000 sat'
		);

		const payer = new FakePayerLane(record, 'exact-lane');
		engine.handleFrame(
			payer.offerFrame(buildOffer(record, coin, { amountSat: 100_000n }))
		);
		await flush();
		expect(node.opens).to.have.length(1);
		expect(node.opens[0].params.fundingSatoshis).to.equal(100_000n);
		engine.stop();
	});

	/**
	 * An expired record answers every attempt question as if the request were
	 * untouched and takes no busy mark, so without an expiry re-read two offers
	 * awaiting the chain across the same expiry would each open a channel for
	 * one payment.
	 */
	it('declines both offers when the request expires under their chain lookups', async () => {
		let clock = Date.now();
		const node = new FakeDfNode(undefined, () => clock);
		const record = node.mintRequest(60_000);
		const firstCoin = makeCoin();
		const secondCoin = makeCoin();
		node.publish(firstCoin);
		node.publish(secondCoin);
		const held = new Map<string, () => void>();
		const getTransaction = node.chain.getTransaction;
		node.chain.getTransaction = (txid): Promise<Buffer> =>
			new Promise((resolve) => {
				held.set(txid, () => resolve(getTransaction(txid)));
			});
		const engine = new DirectFundingReceiver(node, {
			negotiationTimeoutMs: 5_000,
			sweepIntervalMs: 60_000
		});
		engine.start();

		const first = new FakePayerLane(record, 'first-lane');
		const second = new FakePayerLane(record, 'second-lane');
		engine.handleFrame(first.offerFrame(buildOffer(record, firstCoin)));
		engine.handleFrame(
			second.offerFrame(buildOffer(record, secondCoin, { amountSat: 51_000n }))
		);
		await flush();
		expect(held.size).to.equal(2);

		clock += 120_000;
		for (const release of held.values()) release();
		await flush(8);

		expect(node.opens).to.have.length(0);
		for (const payer of [first, second]) {
			expect(decodeDfOfferAck(payer.bodiesOf(ACK)[0]).reason).to.equal(
				'this request has expired'
			);
		}
		expect(engine.inflightCount()).to.equal(0);
		engine.stop();
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

	it('continues an in-flight replay on the new lane', async () => {
		const node = new FakeDfNode();
		const record = node.mintRequest();
		const coin = makeCoin();
		node.publish(coin);
		const offer = buildOffer(record, coin);
		const firstLane = new FakePayerLane(record, 'first-lane');
		const replayLane = new FakePayerLane(record, 'replay-lane');
		const engine = new DirectFundingReceiver(node, {
			negotiationTimeoutMs: 5_000,
			sweepIntervalMs: 60_000
		});
		engine.start();

		engine.handleFrame(firstLane.offerFrame(offer));
		await flush();
		engine.handleFrame(replayLane.offerFrame(offer));
		await flush();
		node.completeNegotiation(coin, offer, { witnessesFilled: true });
		await flush();

		expect(node.opens).to.have.length(1);
		expect(firstLane.bodiesOf(SIGN_REQUEST)).to.have.length(0);
		expect(replayLane.bodiesOf(SIGN_REQUEST)).to.have.length(1);
		engine.handleFrame(
			replayLane.witnessFrame(offer.offerId, [Buffer.alloc(64, 3)])
		);
		await flush();
		expect(node.witnesses).to.have.length(1);
		expect(firstLane.bodiesOf(RECEIPT)).to.have.length(0);
		expect(replayLane.bodiesOf(RECEIPT)).to.have.length(1);
		expect(engine.inflightCount()).to.equal(0);
		engine.stop();
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

	it('replays the receipt over a restart that took the session with it', async () => {
		const storage = memoryStorage();
		const first = new FakeDfNode(storage);
		const record = first.mintRequest();
		const coin = makeCoin();
		first.publish(coin);
		const offer = buildOffer(record, coin);
		const payer = new FakePayerLane(record, 'lane-before');
		const engine = new DirectFundingReceiver(first, {
			negotiationTimeoutMs: 5_000,
			sweepIntervalMs: 60_000
		});
		engine.start();
		engine.handleFrame(payer.offerFrame(offer));
		await flush();
		first.completeNegotiation(coin, offer, { witnessesFilled: true });
		await flush();
		engine.handleFrame(
			payer.witnessFrame(offer.offerId, [Buffer.alloc(64, 3)])
		);
		await flush();
		const paid = decodeDfReceipt(payer.bodiesOf(RECEIPT)[0]);
		engine.stop();

		const second = new FakeDfNode(storage);
		second.publish(coin);
		expect(second.requests.byReceiptHash(record.receiptHash)).to.not.equal(
			null
		);
		const again = new FakePayerLane(record, 'lane-after');
		const restarted = new DirectFundingReceiver(second, {
			negotiationTimeoutMs: 5_000,
			sweepIntervalMs: 60_000
		});
		restarted.start();
		restarted.handleFrame(again.offerFrame(offer));
		await flush();
		expect(second.opens).to.have.length(0);
		const replayed = decodeDfReceipt(again.bodiesOf(RECEIPT)[0]);
		expect(replayed.preimage).to.deep.equal(paid.preimage);
		expect(replayed.fundingTxid).to.deep.equal(paid.fundingTxid);
		// The response log went with the process, so the complete transaction
		// cannot come back with it; the field is optional for exactly this.
		expect(replayed.rawTx).to.equal(undefined);
		restarted.stop();
	});

	it('refuses a duplicate whose attempt a restart left in flight', async () => {
		const storage = memoryStorage();
		const first = new FakeDfNode(storage);
		const record = first.mintRequest();
		const coin = makeCoin();
		first.publish(coin);
		const offer = buildOffer(record, coin);
		const payer = new FakePayerLane(record, 'lane-before');
		const engine = new DirectFundingReceiver(first, {
			negotiationTimeoutMs: 5_000,
			sweepIntervalMs: 60_000
		});
		engine.start();
		engine.handleFrame(payer.offerFrame(offer));
		await flush();
		expect(first.opens).to.have.length(1);
		engine.stop();

		const second = new FakeDfNode(storage);
		second.publish(coin);
		const again = new FakePayerLane(record, 'lane-after');
		const restarted = new DirectFundingReceiver(second, {
			negotiationTimeoutMs: 5_000,
			sweepIntervalMs: 60_000
		});
		restarted.start();
		restarted.handleFrame(again.offerFrame(offer));
		await flush();
		expect(second.opens).to.have.length(0);
		expect(decodeDfOfferAck(again.bodiesOf(ACK)[0])).to.deep.equal({
			offerId: offer.offerId,
			accepted: false,
			reason: 'request already has an active funding attempt'
		});
		restarted.stop();
	});
});

describe('Direct funding receiver: a restart mid-funding (issue #635)', () => {
	/**
	 * A receiver taken down between its sign request and the payer's witness.
	 * The channel is restored and still owes the payer's input a witness; the
	 * sessions and waiters that bound the two are gone with the process.
	 */
	async function crashAfterSignRequest(
		opts: {
			restartAtMs?: number;
			/** Re-send the offer over a second lane, before the crash. */
			movedTo?: string;
			/** Move before the negotiation finishes rather than after. */
			movedEarly?: boolean;
			/** The second lane takes the offer but can carry nothing back. */
			moveRefused?: boolean;
		} = {}
	): Promise<{
		storage: ReturnType<typeof memoryStorage>;
		record: ReturnType<FakeDfNode['mintRequest']>;
		coin: IDfTestCoin;
		offer: ReturnType<typeof buildOffer>;
		channelId: Buffer;
		signedTx: bitcoin.Transaction;
		second: FakeDfNode;
		/** The lane the payer last reached us on, still open at its end. */
		payer: FakePayerLane;
	}> {
		const storage = memoryStorage();
		const first = new FakeDfNode(storage);
		const record = first.mintRequest();
		const coin = makeCoin();
		first.publish(coin);
		const offer = buildOffer(record, coin);
		let payer = new FakePayerLane(record, 'lane-before');
		const engine = new DirectFundingReceiver(first, {
			negotiationTimeoutMs: 5_000,
			witnessTimeoutMs: 5_000,
			sweepIntervalMs: 60_000
		});
		engine.start();
		engine.handleFrame(payer.offerFrame(offer));
		await flush();
		// A payer that lost our answer comes back over another transport, with
		// the fresh lane keys a new exchange mints. The session follows it, so
		// the sign request and the witness that answers it are both that lane's.
		const move = async (): Promise<void> => {
			const next = new FakePayerLane(record, opts.movedTo!);
			const frame = next.offerFrame(offer);
			if (opts.moveRefused) {
				engine.handleFrame({
					...frame,
					reply: {
						type: frame.reply.type,
						send: (): void => {
							throw new Error('lane is gone');
						},
						trySend: (): boolean => false
					}
				});
				await flush();
				return;
			}
			payer = next;
			engine.handleFrame(frame);
			await flush();
		};
		if (opts.movedTo && opts.movedEarly) await move();
		const { channelId, tx } = first.completeNegotiation(coin, offer);
		await flush();
		if (opts.movedTo && !opts.movedEarly) await move();
		expect(payer.bodiesOf(SIGN_REQUEST)).to.have.length(1);
		engine.stop();

		const second = new FakeDfNode(
			storage,
			opts.restartAtMs === undefined
				? undefined
				: (): number => Date.now() + opts.restartAtMs!
		);
		second.publish(coin);
		return {
			storage,
			record,
			coin,
			offer,
			channelId,
			signedTx: tx,
			second,
			payer
		};
	}

	/** Wallet storage exactly as it stood at this instant. */
	function snapshotOf(
		storage: ReturnType<typeof memoryStorage>
	): ReturnType<typeof memoryStorage> {
		const copy = memoryStorage();
		const raw = storage.loadWalletData(DF_REQUESTS_STORAGE_KEY);
		if (raw !== null) copy.saveWalletData(DF_REQUESTS_STORAGE_KEY, raw);
		return copy;
	}

	function restart(node: FakeDfNode): DirectFundingReceiver {
		const engine = new DirectFundingReceiver(node, {
			negotiationTimeoutMs: 5_000,
			witnessTimeoutMs: 5_000,
			sweepIntervalMs: 60_000
		});
		engine.start();
		return engine;
	}

	it('asks the payer to sign the funding the restart left in flight', async () => {
		const c = await crashAfterSignRequest();
		c.second.stagePendingV2(c.channelId, c.coin, c.offer);
		const again = new FakePayerLane(c.record, 'lane-after');
		const engine = restart(c.second);
		engine.handleFrame(again.offerFrame(c.offer));
		await flush();

		expect(c.second.opens, 'no second channel session').to.have.length(0);
		const bodies = again.bodiesOf(SIGN_REQUEST);
		expect(bodies).to.have.length(1);
		const request = decodeDfSignRequest(bodies[0]);
		expect(request.rawTx.equals(c.signedTx.toBuffer())).to.equal(true);

		engine.handleFrame(
			again.witnessFrame(c.offer.offerId, [Buffer.alloc(64, 3)])
		);
		await flush();
		expect(c.second.witnesses).to.have.length(1);
		expect(again.bodiesOf(RECEIPT)).to.have.length(1);
		expect(c.second.requests.isTombstoned(c.record.receiptHash)).to.equal(true);
		engine.stop();
	});

	it('serves the re-sent offer long after the session TTL has passed', async () => {
		const c = await crashAfterSignRequest({ restartAtMs: 20 * 60 * 1000 });
		c.second.stagePendingV2(c.channelId, c.coin, c.offer);
		const again = new FakePayerLane(c.record, 'lane-after');
		const engine = restart(c.second);
		engine.handleFrame(again.offerFrame(c.offer));
		await flush();

		expect(c.second.opens, 'no second channel session').to.have.length(0);
		expect(again.bodiesOf(SIGN_REQUEST)).to.have.length(1);
		expect(
			again.bodiesOf(ACK).map((b) => decodeDfOfferAck(b).accepted)
		).to.deep.equal([true]);
		engine.stop();
	});

	it('waits for the re-armed owed-witness event when the channel has not answered yet', async () => {
		const c = await crashAfterSignRequest();
		const again = new FakePayerLane(c.record, 'lane-after');
		const engine = restart(c.second);
		engine.handleFrame(again.offerFrame(c.offer));
		await flush();
		expect(again.bodiesOf(SIGN_REQUEST)).to.have.length(0);

		c.second.completeNegotiation(c.coin, c.offer, { channelId: c.channelId });
		await flush();
		expect(c.second.opens).to.have.length(0);
		expect(again.bodiesOf(SIGN_REQUEST)).to.have.length(1);
		engine.stop();
	});

	it('resumes a splice from the channel it was negotiated into', async () => {
		const storage = memoryStorage();
		const first = new FakeDfNode(storage);
		first.spliceChannel = crypto.randomBytes(32);
		first.trustedPayers.add(LSP_PUBKEY);
		const record = first.mintRequest();
		const coin = makeCoin();
		first.publish(coin);
		const offer = buildOffer(record, coin);
		const payer = new FakePayerLane(record, 'lane-before', LSP_PUBKEY);
		const engine = new DirectFundingReceiver(first, {
			allowSplice: true,
			negotiationTimeoutMs: 5_000,
			sweepIntervalMs: 60_000
		});
		engine.start();
		engine.handleFrame(payer.offerFrame(offer));
		await flush();
		const { channelId } = first.completeSpliceNegotiation(coin, offer, 40_000n);
		await flush();
		expect(payer.bodiesOf(SIGN_REQUEST)).to.have.length(1);
		engine.stop();

		const second = new FakeDfNode(storage);
		second.publish(coin);
		second.stagePendingSplice(channelId, coin, offer, 40_000n);
		const again = new FakePayerLane(record, 'lane-after', LSP_PUBKEY);
		const restarted = new DirectFundingReceiver(second, {
			allowSplice: true,
			negotiationTimeoutMs: 5_000,
			sweepIntervalMs: 60_000
		});
		restarted.start();
		restarted.handleFrame(again.offerFrame(offer));
		await flush();

		expect(second.splices, 'no second splice').to.have.length(0);
		const bodies = again.bodiesOf(SIGN_REQUEST);
		expect(bodies).to.have.length(1);
		expect(decodeDfSignRequest(bodies[0]).sharedInputIndex).to.equal(1);
		restarted.stop();
	});

	it('refuses an offer id re-sent with different content', async () => {
		const c = await crashAfterSignRequest();
		c.second.stagePendingV2(c.channelId, c.coin, c.offer);
		const again = new FakePayerLane(c.record, 'lane-after');
		const engine = restart(c.second);
		// The id is derived from the outpoint and the amount, so a changed
		// change script keeps it and changes what it means.
		engine.handleFrame(
			again.offerFrame(
				buildOffer(c.record, c.coin, {
					changeScript: bitcoin.payments.p2wpkh({
						hash: crypto.randomBytes(20)
					}).output!
				})
			)
		);
		await flush();
		expect(again.bodiesOf(SIGN_REQUEST)).to.have.length(0);
		expect(decodeDfOfferAck(again.bodiesOf(ACK)[0])).to.deep.equal({
			offerId: c.offer.offerId,
			accepted: false,
			reason: 'offer id reused with different content'
		});
		engine.stop();
	});

	it('keeps the payer coin committed to its funding across the restart', async () => {
		const c = await crashAfterSignRequest();
		c.second.stagePendingV2(c.channelId, c.coin, c.offer);
		const engine = restart(c.second);
		// Another request, the same coin, a different amount: a different offer
		// id, so nothing about the first request's busy mark refuses it.
		const other = c.second.mintRequest();
		const otherPayer = new FakePayerLane(other, 'other-lane');
		engine.handleFrame(
			otherPayer.offerFrame(buildOffer(other, c.coin, { amountSat: 40_000n }))
		);
		await flush();
		expect(c.second.opens).to.have.length(0);
		expect(decodeDfOfferAck(otherPayer.bodiesOf(ACK)[0]).reason).to.equal(
			'input already committed to another offer'
		);
		engine.stop();
	});

	it('keeps it committed against the same coin at the same amount', async () => {
		const c = await crashAfterSignRequest();
		c.second.stagePendingV2(c.channelId, c.coin, c.offer);
		const engine = restart(c.second);
		// The offer id covers the coin and the amount and nothing else, so this
		// one carries the id the restored hold was taken under.
		const other = c.second.mintRequest();
		const otherPayer = new FakePayerLane(other, 'other-lane');
		engine.handleFrame(otherPayer.offerFrame(buildOffer(other, c.coin)));
		await flush();
		expect(c.second.opens, 'no second channel session').to.have.length(0);
		expect(decodeDfOfferAck(otherPayer.bodiesOf(ACK)[0]).reason).to.equal(
			'input already committed to another offer'
		);
		engine.stop();
	});

	it('completes the funding from a witness that arrives after the restart', async () => {
		const c = await crashAfterSignRequest();
		c.second.stagePendingV2(c.channelId, c.coin, c.offer);
		const engine = restart(c.second);
		// The payer's exchange outlived ours: it signed what we asked for before
		// we went down and sends the witness over the lane it already has, which
		// it will not send twice.
		engine.handleFrame(
			c.payer.witnessFrame(c.offer.offerId, [Buffer.alloc(64, 3)])
		);
		await flush();

		expect(c.second.witnesses).to.have.length(1);
		const receipts = c.payer.bodiesOf(RECEIPT);
		expect(receipts).to.have.length(1);
		expect(decodeDfReceipt(receipts[0]).preimage.toString('hex')).to.equal(
			c.record.preimageHex
		);
		expect(c.second.requests.isTombstoned(c.record.receiptHash)).to.equal(true);
		engine.stop();
	});

	it('takes it on the lane a duplicate offer moved the exchange to', async () => {
		const c = await crashAfterSignRequest({ movedTo: 'lane-moved' });
		c.second.stagePendingV2(c.channelId, c.coin, c.offer);
		const engine = restart(c.second);
		engine.handleFrame(
			c.payer.witnessFrame(c.offer.offerId, [Buffer.alloc(64, 3)])
		);
		await flush();

		expect(c.second.witnesses).to.have.length(1);
		expect(c.payer.bodiesOf(RECEIPT)).to.have.length(1);
		engine.stop();
	});

	it('takes it on that lane when the move came before the funding was marked', async () => {
		const c = await crashAfterSignRequest({
			movedTo: 'lane-moved',
			movedEarly: true
		});
		c.second.stagePendingV2(c.channelId, c.coin, c.offer);
		const engine = restart(c.second);
		engine.handleFrame(
			c.payer.witnessFrame(c.offer.offerId, [Buffer.alloc(64, 3)])
		);
		await flush();

		expect(c.second.witnesses).to.have.length(1);
		expect(c.payer.bodiesOf(RECEIPT)).to.have.length(1);
		engine.stop();
	});

	it('keeps the old lane when the duplicate arrived on one that carries nothing', async () => {
		const c = await crashAfterSignRequest({
			movedTo: 'lane-dead',
			moveRefused: true
		});
		c.second.stagePendingV2(c.channelId, c.coin, c.offer);
		const engine = restart(c.second);
		// The sign request never reached the second lane, so the payer answers
		// the one it did reach, on keys the funding must still name.
		engine.handleFrame(
			c.payer.witnessFrame(c.offer.offerId, [Buffer.alloc(64, 3)])
		);
		await flush();

		expect(c.second.witnesses).to.have.length(1);
		expect(c.payer.bodiesOf(RECEIPT)).to.have.length(1);
		engine.stop();
	});

	it('takes a witness answered inside the replayed sign request send', async () => {
		const node = new FakeDfNode();
		const record = node.mintRequest();
		const coin = makeCoin();
		node.publish(coin);
		const offer = buildOffer(record, coin);
		const before = new FakePayerLane(record, 'lane-before');
		const engine = new DirectFundingReceiver(node, {
			negotiationTimeoutMs: 5_000,
			witnessTimeoutMs: 5_000,
			sweepIntervalMs: 60_000
		});
		engine.start();
		engine.handleFrame(before.offerFrame(offer));
		await flush();
		node.completeNegotiation(coin, offer);
		await flush();
		expect(before.bodiesOf(SIGN_REQUEST)).to.have.length(1);

		// The payer comes back over another transport and answers the replayed
		// sign request inside the send, the way one in the same process does.
		const moved = new FakePayerLane(record, 'lane-moved');
		moved.onReceive = (subtype): void => {
			if (subtype !== SIGN_REQUEST) return;
			engine.handleFrame(
				moved.witnessFrame(offer.offerId, [Buffer.alloc(64, 3)])
			);
		};
		engine.handleFrame(moved.offerFrame(offer));
		await flush();

		expect(node.witnesses).to.have.length(1);
		expect(moved.bodiesOf(RECEIPT)).to.have.length(1);
		engine.stop();
	});

	it('records the moved lane before the replayed sign request leaves', async () => {
		const storage = memoryStorage();
		const node = new FakeDfNode(storage);
		const record = node.mintRequest();
		const coin = makeCoin();
		node.publish(coin);
		const offer = buildOffer(record, coin);
		const before = new FakePayerLane(record, 'lane-before');
		const engine = restart(node);
		engine.handleFrame(before.offerFrame(offer));
		await flush();
		const { channelId } = node.completeNegotiation(coin, offer);
		await flush();

		// Taken down INSIDE the replayed send. The payer answers the lane that
		// send reached, so the mark has to name it already: written afterwards it
		// would be the old lane that came back, and the witness is sent once.
		let snapshot: ReturnType<typeof memoryStorage> | null = null;
		const moved = new FakePayerLane(record, 'lane-moved');
		moved.onReceive = (subtype): void => {
			if (subtype === SIGN_REQUEST) snapshot = snapshotOf(storage);
		};
		engine.handleFrame(moved.offerFrame(offer));
		await flush();
		expect(moved.bodiesOf(SIGN_REQUEST)).to.have.length(1);
		engine.stop();

		const second = new FakeDfNode(snapshot!);
		second.publish(coin);
		second.stagePendingV2(channelId, coin, offer);
		const restarted = restart(second);
		restarted.handleFrame(
			moved.witnessFrame(offer.offerId, [Buffer.alloc(64, 3)])
		);
		await flush();
		expect(second.witnesses).to.have.length(1);
		restarted.stop();
	});

	it('keeps the working lane when a duplicate arrives on one that refuses the ack', async () => {
		const node = new FakeDfNode();
		const record = node.mintRequest();
		const coin = makeCoin();
		node.publish(coin);
		const offer = buildOffer(record, coin);
		const before = new FakePayerLane(record, 'lane-before');
		const engine = restart(node);
		engine.handleFrame(before.offerFrame(offer));
		await flush();
		// The duplicate arrives with only the ack recorded, and that lane cannot
		// carry it. A session with nothing at stake still has nothing to gain
		// from a lane that refuses the one frame it did have.
		const dead = new FakePayerLane(record, 'lane-dead');
		const frame = dead.offerFrame(offer);
		engine.handleFrame({
			...frame,
			reply: {
				type: frame.reply.type,
				send: (): void => {
					throw new Error('lane is gone');
				},
				trySend: (): boolean => false
			}
		});
		await flush();
		node.completeNegotiation(coin, offer);
		await flush();

		expect(before.bodiesOf(SIGN_REQUEST)).to.have.length(1);
		engine.stop();
	});

	it('records the resumed lane before its sign request leaves', async () => {
		const c = await crashAfterSignRequest();
		c.second.stagePendingV2(c.channelId, c.coin, c.offer);
		const engine = restart(c.second);
		let snapshot: ReturnType<typeof memoryStorage> | null = null;
		const again = new FakePayerLane(c.record, 'lane-after');
		again.onReceive = (subtype): void => {
			if (subtype === SIGN_REQUEST) snapshot = snapshotOf(c.storage);
		};
		engine.handleFrame(again.offerFrame(c.offer));
		await flush();
		expect(again.bodiesOf(SIGN_REQUEST)).to.have.length(1);
		engine.stop();

		const third = new FakeDfNode(snapshot!);
		third.publish(c.coin);
		third.stagePendingV2(c.channelId, c.coin, c.offer);
		const restarted = restart(third);
		restarted.handleFrame(
			again.witnessFrame(c.offer.offerId, [Buffer.alloc(64, 3)])
		);
		await flush();
		expect(third.witnesses).to.have.length(1);
		restarted.stop();
	});

	it('replays the receipt a late witness earned over the session it settled', async () => {
		const c = await crashAfterSignRequest();
		c.second.stagePendingV2(c.channelId, c.coin, c.offer);
		const engine = restart(c.second);
		const dead = new FakePayerLane(c.record, 'lane-dead');
		const deadFrame = dead.offerFrame(c.offer);
		const refuse = {
			type: deadFrame.reply.type,
			send: (): void => {
				throw new Error('lane is gone');
			},
			trySend: (): boolean => false
		};
		engine.handleFrame({ ...deadFrame, reply: refuse });
		await flush();
		// The witness completes the funding on the old lane and its receipt is
		// lost. What is owed now is that receipt, and the session left over from
		// the resume must not answer the next re-send ahead of it.
		const witnessFrame = c.payer.witnessFrame(c.offer.offerId, [
			Buffer.alloc(64, 3)
		]);
		engine.handleFrame({ ...witnessFrame, reply: refuse });
		await flush();
		expect(c.second.witnesses).to.have.length(1);

		const again = new FakePayerLane(c.record, 'lane-again');
		engine.handleFrame(again.offerFrame(c.offer));
		await flush();
		const receipts = again.bodiesOf(RECEIPT);
		expect(receipts).to.have.length(1);
		expect(decodeDfReceipt(receipts[0]).preimage.toString('hex')).to.equal(
			c.record.preimageHex
		);
		expect(again.bodiesOf(SIGN_REQUEST)).to.have.length(0);
		engine.stop();
	});

	it('keeps the funding lane when a resumed offer cannot be answered', async () => {
		const c = await crashAfterSignRequest();
		c.second.stagePendingV2(c.channelId, c.coin, c.offer);
		const engine = restart(c.second);
		// A lane that takes the resumed offer and carries nothing back: the payer
		// was never asked on it, so it still owes the witness to the lane the
		// previous life asked on, and that lane must still be able to answer.
		const dead = new FakePayerLane(c.record, 'lane-dead');
		const frame = dead.offerFrame(c.offer);
		engine.handleFrame({
			...frame,
			reply: {
				type: frame.reply.type,
				send: (): void => {
					throw new Error('lane is gone');
				},
				trySend: (): boolean => false
			}
		});
		await flush();
		engine.handleFrame(
			c.payer.witnessFrame(c.offer.offerId, [Buffer.alloc(64, 3)])
		);
		await flush();

		expect(c.second.witnesses).to.have.length(1);
		expect(c.payer.bodiesOf(RECEIPT)).to.have.length(1);
		engine.stop();
	});

	it('keeps the funding for the payer when the channel cannot answer for it yet', async () => {
		const c = await crashAfterSignRequest();
		const engine = restart(c.second);
		engine.handleFrame(
			c.payer.witnessFrame(c.offer.offerId, [Buffer.alloc(64, 3)])
		);
		await flush();

		expect(c.second.witnesses).to.have.length(0);
		expect(c.second.requests.isTombstoned(c.record.receiptHash)).to.equal(
			false
		);
		expect(
			c.second.requests.attemptsFor(c.record.receiptHash).funding
		).to.not.equal(undefined);
		engine.stop();
	});

	it('holds that witness until the channel re-arms', async () => {
		const c = await crashAfterSignRequest();
		const engine = restart(c.second);
		engine.handleFrame(
			c.payer.witnessFrame(c.offer.offerId, [Buffer.alloc(64, 3)])
		);
		await flush();
		expect(c.second.witnesses).to.have.length(0);

		// The payer marks the witness sent the moment the wire takes it and never
		// offers again, so nothing re-drives one dropped here.
		c.second.completeNegotiation(c.coin, c.offer, { channelId: c.channelId });
		await flush();
		expect(c.second.witnesses).to.have.length(1);
		expect(c.payer.bodiesOf(RECEIPT)).to.have.length(1);
		expect(c.second.requests.isTombstoned(c.record.receiptHash)).to.equal(true);
		engine.stop();
	});

	it('holds that witness through a duplicate offer waiting on the same re-arm', async () => {
		const c = await crashAfterSignRequest();
		const engine = restart(c.second);
		engine.handleFrame(
			c.payer.witnessFrame(c.offer.offerId, [Buffer.alloc(64, 3)])
		);
		await flush();
		// A re-send lands in the same window and waits on the same re-arm. It
		// cannot take the witness's place in that wait: the payer sends one
		// witness, so the one already here is all there is to finish the funding.
		const again = new FakePayerLane(c.record, 'lane-after');
		engine.handleFrame(again.offerFrame(c.offer));
		await flush();
		expect(c.second.witnesses).to.have.length(0);

		c.second.completeNegotiation(c.coin, c.offer, { channelId: c.channelId });
		await flush();
		expect(c.second.witnesses).to.have.length(1);
		expect(c.second.requests.isTombstoned(c.record.receiptHash)).to.equal(true);
		expect(c.second.aborts).to.have.length(0);
		engine.stop();
	});

	it('serves a re-sent offer after an earlier resume gave up waiting', async () => {
		const c = await crashAfterSignRequest();
		const again = new FakePayerLane(c.record, 'lane-after');
		const engine = new DirectFundingReceiver(c.second, {
			negotiationTimeoutMs: 20,
			witnessTimeoutMs: 5_000,
			sweepIntervalMs: 60_000
		});
		engine.start();
		engine.handleFrame(again.offerFrame(c.offer));
		await new Promise((resolve) => setTimeout(resolve, 40));
		await flush();
		expect(again.bodiesOf(SIGN_REQUEST)).to.have.length(0);
		expect(again.bodiesOf(ACK), 'a wait is not a refusal').to.have.length(0);
		expect(c.second.aborts, 'nor a reason to abort the channel').to.have.length(
			0
		);

		// The peer reconnects and the channel answers; the payer is still
		// re-sending the offer it never got a sign request for.
		c.second.stagePendingV2(c.channelId, c.coin, c.offer);
		engine.handleFrame(again.offerFrame(c.offer));
		await flush();
		expect(c.second.opens).to.have.length(0);
		expect(again.bodiesOf(SIGN_REQUEST)).to.have.length(1);
		engine.stop();
	});

	it('serves the resumed offer with every fresh-admission slot taken', async () => {
		const c = await crashAfterSignRequest();
		c.second.stagePendingV2(c.channelId, c.coin, c.offer);
		const again = new FakePayerLane(c.record, 'lane-after');
		const engine = new DirectFundingReceiver(c.second, {
			maxInflightSessions: 0,
			maxSessions: 1,
			negotiationTimeoutMs: 5_000,
			witnessTimeoutMs: 5_000,
			sweepIntervalMs: 60_000
		});
		engine.start();
		engine.handleFrame(again.offerFrame(c.offer));
		await flush();
		expect(again.bodiesOf(SIGN_REQUEST)).to.have.length(1);
		engine.stop();
	});
});

describe('Direct funding receiver: a completed funding (issue #658)', () => {
	interface ICompleted {
		storage: ReturnType<typeof memoryStorage>;
		record: ReturnType<FakeDfNode['mintRequest']>;
		coin: IDfTestCoin;
		offer: ReturnType<typeof buildOffer>;
		channelId: Buffer;
		fundingTx: bitcoin.Transaction;
		second: FakeDfNode;
		/** The lane the payer sent its witness on, still open at its end. */
		payer: FakePayerLane;
	}

	/**
	 * A receiver taken down between the payer's witness reaching the channel and
	 * the receipt tombstone. On the zero-conf fast track the tx_signatures
	 * release, the early channel_ready, NORMAL and `v2InFlight = null` are one
	 * persisted batch, so the restarted channel answers no in-flight record at
	 * all. What is left of the exchange is the funding on the request record and
	 * the transaction on the chain.
	 */
	async function crashBeforeReceipt(
		opts: { splice?: boolean } = {}
	): Promise<ICompleted> {
		const storage = memoryStorage();
		const first = new FakeDfNode(storage);
		if (opts.splice) {
			first.spliceChannel = crypto.randomBytes(32);
			first.trustedPayers.add(LSP_PUBKEY);
		}
		const record = first.mintRequest();
		const coin = makeCoin();
		first.publish(coin);
		const offer = buildOffer(record, coin);
		const payer = new FakePayerLane(
			record,
			'lane-before',
			opts.splice ? LSP_PUBKEY : undefined
		);
		const engine = new DirectFundingReceiver(first, {
			allowSplice: opts.splice === true,
			negotiationTimeoutMs: 5_000,
			witnessTimeoutMs: 5_000,
			sweepIntervalMs: 60_000
		});
		engine.start();
		engine.handleFrame(payer.offerFrame(offer));
		await flush();
		const { channelId, tx } = opts.splice
			? first.completeSpliceNegotiation(coin, offer, 40_000n)
			: first.completeNegotiation(coin, offer);
		await flush();
		expect(payer.bodiesOf(SIGN_REQUEST)).to.have.length(1);
		engine.stop();

		const second = new FakeDfNode(storage);
		second.publish(coin);
		return {
			storage,
			record,
			coin,
			offer,
			channelId,
			fundingTx: tx,
			second,
			payer
		};
	}

	/** The channel broadcast the funding before it retired its record. */
	function broadcast(node: FakeDfNode, tx: bitcoin.Transaction): void {
		node.transactions.set(tx.getId(), tx.toBuffer());
	}

	function restart(node: FakeDfNode, splice = false): DirectFundingReceiver {
		const engine = new DirectFundingReceiver(node, {
			allowSplice: splice,
			negotiationTimeoutMs: 5_000,
			witnessTimeoutMs: 5_000,
			sweepIntervalMs: 60_000
		});
		engine.start();
		return engine;
	}

	it('answers a re-sent witness with the receipt it never got', async () => {
		const c = await crashBeforeReceipt();
		broadcast(c.second, c.fundingTx);
		const engine = restart(c.second);
		engine.handleFrame(
			c.payer.witnessFrame(c.offer.offerId, [Buffer.alloc(64, 3)])
		);
		await flush();

		// Nothing is delivered: the channel is long past taking a witness.
		expect(c.second.witnesses).to.have.length(0);
		const receipts = c.payer.bodiesOf(RECEIPT);
		expect(receipts).to.have.length(1);
		const receipt = decodeDfReceipt(receipts[0]);
		expect(receipt.preimage.toString('hex')).to.equal(c.record.preimageHex);
		expect(receipt.fundingTxid.toString('hex')).to.equal(c.fundingTx.getId());
		expect(c.second.requests.isTombstoned(c.record.receiptHash)).to.equal(true);
		engine.stop();
	});

	it('answers a re-sent offer with the receipt and starts nothing', async () => {
		const c = await crashBeforeReceipt();
		broadcast(c.second, c.fundingTx);
		const again = new FakePayerLane(c.record, 'lane-after');
		const engine = restart(c.second);
		engine.handleFrame(again.offerFrame(c.offer));
		await flush();

		expect(c.second.opens, 'no second channel session').to.have.length(0);
		expect(again.bodiesOf(SIGN_REQUEST)).to.have.length(0);
		const receipts = again.bodiesOf(RECEIPT);
		expect(receipts).to.have.length(1);
		expect(decodeDfReceipt(receipts[0]).fundingTxid.toString('hex')).to.equal(
			c.fundingTx.getId()
		);
		// The busy mark went with the tombstone, so the request is no longer
		// burned until expiry.
		expect(
			c.second.requests.attemptsFor(c.record.receiptHash).activeOfferId
		).to.equal(undefined);

		// And a payer that comes back once more is replayed from the tombstone.
		const third = new FakePayerLane(c.record, 'lane-later');
		engine.handleFrame(third.offerFrame(c.offer));
		await flush();
		expect(
			decodeDfReceipt(third.bodiesOf(RECEIPT)[0]).fundingTxid
		).to.deep.equal(decodeDfReceipt(receipts[0]).fundingTxid);
		engine.stop();
	});

	it('answers the splice twin, whose record goes at splice_locked', async () => {
		const c = await crashBeforeReceipt({ splice: true });
		broadcast(c.second, c.fundingTx);
		const engine = restart(c.second, true);
		engine.handleFrame(
			c.payer.witnessFrame(c.offer.offerId, [Buffer.alloc(64, 3)])
		);
		await flush();

		expect(c.second.witnesses).to.have.length(0);
		expect(c.payer.bodiesOf(RECEIPT)).to.have.length(1);
		expect(c.second.requests.isTombstoned(c.record.receiptHash)).to.equal(true);
		engine.stop();
	});

	it('reveals nothing for a funding that never reached the chain', async () => {
		const c = await crashBeforeReceipt();
		const again = new FakePayerLane(c.record, 'lane-after');
		const engine = restart(c.second);
		engine.handleFrame(again.offerFrame(c.offer));
		await flush();
		expect(again.bodiesOf(RECEIPT)).to.have.length(0);
		expect(c.second.requests.isTombstoned(c.record.receiptHash)).to.equal(
			false
		);

		// It was the peer that had not reconnected, not a payment. The exchange
		// resumes on the re-armed event exactly as it did before.
		c.second.completeNegotiation(c.coin, c.offer, { channelId: c.channelId });
		await flush();
		expect(again.bodiesOf(SIGN_REQUEST)).to.have.length(1);
		engine.stop();
	});

	it('reveals nothing for a transaction that spends some other coin', async () => {
		const c = await crashBeforeReceipt();
		const decoy = new bitcoin.Transaction();
		decoy.version = 2;
		decoy.addInput(crypto.randomBytes(32), 0);
		decoy.addOutput(Buffer.alloc(34, 9), 50_000);
		c.second.transactions.set(decoy.getId(), decoy.toBuffer());
		// A recorded txid that resolves to a real transaction is not enough: the
		// receipt says a transaction spent the payer's coin, so that is what has
		// to be true of it.
		const rows = JSON.parse(
			c.storage.loadWalletData(DF_REQUESTS_STORAGE_KEY)!
		) as Array<{ activeAttempt: { funding: { fundingTxid: string } } }>;
		rows[0].activeAttempt.funding.fundingTxid = decoy.getId();
		c.storage.saveWalletData(DF_REQUESTS_STORAGE_KEY, JSON.stringify(rows));
		c.second.requests.restore();

		const again = new FakePayerLane(c.record, 'lane-after');
		const engine = restart(c.second);
		engine.handleFrame(again.offerFrame(c.offer));
		await flush();
		expect(again.bodiesOf(RECEIPT)).to.have.length(0);
		expect(c.second.requests.isTombstoned(c.record.receiptHash)).to.equal(
			false
		);
		engine.stop();
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

	/**
	 * Rev 2 caps the transaction at 16 inputs and 8 outputs, so a payer that
	 * enforces the cap will not sign a ninth output: attesting to one spends the
	 * session on bytes the exchange cannot use.
	 */
	it('refuses to attest above the rev 2 output cap', async () => {
		const h = await drive();
		h.node.completeNegotiation(h.coin, h.offer, { extraOutputs: 7 });
		await flush();
		expect(h.payer.bodiesOf(SIGN_REQUEST)).to.be.empty;
		expect(h.lastAck()?.reason).to.contain('9 outputs, above the 8');
		expect(h.node.aborts.map((a) => a.kind)).to.deep.equal(['open']);
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

	it('still delivers the receipt when the request expires mid-session', async () => {
		let clock = Date.now();
		const node = new FakeDfNode(undefined, () => clock);
		const record = node.mintRequest(400);
		const coin = makeCoin();
		node.publish(coin);
		const offer = buildOffer(record, coin);
		const payer = new FakePayerLane(record, 'payer-lane');
		const engine = new DirectFundingReceiver(node, {
			negotiationTimeoutMs: 5_000,
			witnessTimeoutMs: 5_000,
			sweepIntervalMs: 60_000
		});
		engine.start();
		engine.handleFrame(payer.offerFrame(offer));
		await flush();
		node.completeNegotiation(coin, offer, { witnessesFilled: true });
		await flush();
		expect(payer.bodiesOf(SIGN_REQUEST)).to.have.length(1);

		// The request outlives neither the negotiation nor the payer's signing,
		// and the coin is about to be spent either way.
		clock += 1_000;
		expect(node.requests.byReceiptHash(record.receiptHash)).to.equal(null);
		engine.handleFrame(
			payer.witnessFrame(offer.offerId, [Buffer.alloc(64, 3)])
		);
		await flush();
		expect(node.witnesses).to.have.length(1);
		const receipt = decodeDfReceipt(payer.bodiesOf(RECEIPT)[0]);
		expect(
			crypto.createHash('sha256').update(receipt.preimage).digest('hex')
		).to.equal(record.receiptHash);
		engine.stop();
	});

	it('does not take a withheld dispatch for a delivered tx_signatures', async () => {
		const h = await drive({ witnessTimeoutMs: 5_000 });
		h.node.witnessSendsWithheld = true;
		h.node.abortError = 'cannot abort a v2 open after tx_signatures';
		h.node.completeNegotiation(h.coin, h.offer, { witnessesFilled: true });
		await flush();
		h.engine.handleFrame(
			h.payer.witnessFrame(h.offer.offerId, [Buffer.alloc(64, 3)])
		);
		await flush();
		expect(h.node.witnesses).to.have.length(1);
		expect(h.payer.bodiesOf(RECEIPT), 'no receipt for signatures still here').to
			.be.empty;
		expect(
			h.acks().filter((a) => !a.accepted),
			'not declined either'
		).to.be.empty;

		// Once the channel can dispatch again, the retried witness completes it.
		h.node.witnessSendsWithheld = false;
		h.engine.handleFrame(
			h.payer.witnessFrame(h.offer.offerId, [Buffer.alloc(64, 3)])
		);
		await flush();
		expect(h.payer.bodiesOf(RECEIPT)).to.have.length(1);
	});

	it('keeps the witness obligation open when the splice cannot be aborted', async () => {
		const h = harness(
			{
				allowSplice: true,
				negotiationTimeoutMs: 5_000,
				witnessTimeoutMs: 5,
				outpointCooldownMs: 5
			},
			{ authenticatedPeer: 'payer-node-id' }
		);
		h.node.spliceChannel = crypto.randomBytes(32);
		h.node.trustedPayers.add('payer-node-id');
		h.node.spliceAbortError = 'tx_signatures already exchanged';
		await h.sendOffer();
		expect(h.node.splices).to.have.length(1);
		h.node.completeSpliceNegotiation(h.coin, h.offer, 200_000n);
		await flush();
		expect(h.payer.bodiesOf(SIGN_REQUEST)).to.have.length(1);
		await flush(20);
		expect(h.node.aborts.map((a) => a.kind)).to.deep.equal(['splice']);
		expect(h.engine.inflightCount()).to.equal(0);
		// Delivery is the only exit the channel left, so the payer is not told
		// the exchange is over.
		expect(h.acks().filter((a) => !a.accepted)).to.be.empty;
		const competingPayer = new FakePayerLane(
			h.node.mintRequest(),
			'competing-lane',
			'payer-node-id'
		);
		const competing = buildOffer(competingPayer.requestRecord, h.coin, {
			amountSat: 60_000n
		});
		h.engine.handleFrame(competingPayer.offerFrame(competing));
		await flush();
		expect(h.node.splices).to.have.length(1);
		expect(decodeDfOfferAck(competingPayer.bodiesOf(ACK)[0]).reason).to.equal(
			'input already committed to another offer'
		);
		// Nor is the REQUEST free again: the funding still owed a witness can
		// complete and reveal its receipt, so a second coin cannot buy a second
		// one against the same payment.
		const otherCoin = makeCoin('p2wpkh', 400_000);
		h.node.publish(otherCoin);
		const sameRequest = new FakePayerLane(
			h.payer.requestRecord,
			'same-request-lane',
			'payer-node-id'
		);
		h.engine.handleFrame(
			sameRequest.offerFrame(
				buildOffer(h.payer.requestRecord, otherCoin, { amountSat: 70_000n })
			)
		);
		await flush();
		expect(h.node.splices).to.have.length(1);
		expect(decodeDfOfferAck(sameRequest.bodiesOf(ACK)[0]).reason).to.equal(
			'request already has an active funding attempt'
		);

		h.engine.handleFrame(
			h.payer.witnessFrame(h.offer.offerId, [Buffer.alloc(64, 3)])
		);
		await flush();
		expect(h.node.witnesses).to.have.length(1);
		expect(h.payer.bodiesOf(RECEIPT)).to.have.length(1);
	});
});

describe('Direct funding receiver: unwind (issue #612)', () => {
	/**
	 * A tx_abort of a recorded v2 attempt tears nothing down until the peer
	 * echoes it, and a disconnect before that resumes the negotiation. So the
	 * funding is still live and the payer is not told otherwise.
	 */
	it('keeps the witness obligation open when the open abort awaits its echo', async () => {
		const h = harness({
			negotiationTimeoutMs: 5_000,
			witnessTimeoutMs: 5,
			outpointCooldownMs: 5
		});
		h.node.abortPending = true;
		await h.sendOffer();
		h.node.completeNegotiation(h.coin, h.offer, { witnessesFilled: true });
		await flush();
		expect(h.payer.bodiesOf(SIGN_REQUEST)).to.have.length(1);
		await flush(20);
		expect(h.node.aborts.map((a) => a.kind)).to.deep.equal(['open']);
		expect(h.acks().filter((a) => !a.accepted)).to.be.empty;

		h.engine.handleFrame(
			h.payer.witnessFrame(h.offer.offerId, [Buffer.alloc(64, 3)])
		);
		await flush();
		expect(h.node.witnesses).to.have.length(1);
		expect(h.payer.bodiesOf(RECEIPT)).to.have.length(1);
	});

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

	/**
	 * The failure came before the sign request, so there is no witness to wait
	 * for, but the abort is still awaiting its echo and the funding is live. The
	 * request and the coin are held on that, not on how far the exchange got.
	 */
	it('holds the request when a pending abort follows a failed sign request', async () => {
		const h = harness({ negotiationTimeoutMs: 5_000, outpointCooldownMs: 5 });
		h.node.abortPending = true;
		await h.sendOffer();
		h.node.pubkeysAvailable = false;
		h.node.completeNegotiation(h.coin, h.offer);
		await flush();
		expect(h.payer.bodiesOf(SIGN_REQUEST)).to.be.empty;
		expect(h.node.aborts.map((a) => a.kind)).to.deep.equal(['open']);
		expect(
			h.acks().filter((a) => !a.accepted),
			'a live funding is not declined'
		).to.be.empty;

		const otherCoin = makeCoin('p2wpkh', 400_000);
		h.node.publish(otherCoin);
		const again = new FakePayerLane(h.payer.requestRecord, 'second-lane');
		h.engine.handleFrame(
			again.offerFrame(
				buildOffer(h.payer.requestRecord, otherCoin, { amountSat: 70_000n })
			)
		);
		await flush();
		expect(h.node.opens, 'no second channel for one payment').to.have.length(1);
		expect(decodeDfOfferAck(again.bodiesOf(ACK)[0]).reason).to.equal(
			'request already has an active funding attempt'
		);
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

	it('releases the slot without leaking when the open itself throws', async () => {
		const h = harness({ negotiationTimeoutMs: 5 });
		h.node.openThrows = new Error('funding provider unavailable');
		const rejections = await captureUnhandledRejections(async () => {
			await h.sendOffer();
			await flush(20);
		});
		expect(rejections).to.deep.equal([]);
		expect(h.engine.inflightCount()).to.equal(0);
		expect(h.lastAck()?.reason).to.contain('funding provider unavailable');
		expect(h.node.aborts).to.have.length(0);
	});

	it('keeps an abandoned open timer from cancelling an outpoint retry', async () => {
		const node = new FakeDfNode();
		const engine = new DirectFundingReceiver(node, {
			negotiationTimeoutMs: 400,
			witnessTimeoutMs: 5_000,
			outpointCooldownMs: 20,
			sweepIntervalMs: 60_000
		});
		engine.start();
		const coin = makeCoin('p2wpkh', 500_000);
		node.publish(coin);
		const firstPayer = new FakePayerLane(node.mintRequest(), 'first-lane');
		node.openThrows = new Error('funding provider unavailable');
		engine.handleFrame(
			firstPayer.offerFrame(buildOffer(firstPayer.requestRecord, coin))
		);
		await flush();

		node.openThrows = null;
		await sleep(200);
		const secondPayer = new FakePayerLane(node.mintRequest(), 'second-lane');
		const second = buildOffer(secondPayer.requestRecord, coin, {
			amountSat: 60_000n
		});
		engine.handleFrame(secondPayer.offerFrame(second));
		await flush();
		expect(node.opens).to.have.length(1);

		await sleep(250);
		node.completeNegotiation(coin, second);
		await flush();
		expect(secondPayer.bodiesOf(SIGN_REQUEST)).to.have.length(1);
		engine.handleFrame(
			secondPayer.witnessFrame(second.offerId, [Buffer.alloc(64, 3)])
		);
		await flush();
		engine.stop();
	});

	it('releases the slot without leaking when the splice throws', async () => {
		const channelId = crypto.randomBytes(32);
		const h = harness(
			{ allowSplice: true, negotiationTimeoutMs: 5 },
			{ authenticatedPeer: 'payer-node-id' }
		);
		h.node.spliceChannel = channelId;
		h.node.trustedPayers.add('payer-node-id');
		h.node.spliceInWithInputs = (): never => {
			throw new Error('splice provider unavailable');
		};
		const rejections = await captureUnhandledRejections(async () => {
			await h.sendOffer();
			await flush(20);
		});
		expect(rejections).to.deep.equal([]);
		expect(h.engine.inflightCount()).to.equal(0);
		expect(h.lastAck()?.reason).to.contain('splice provider unavailable');
		expect(h.node.aborts).to.have.length(0);
	});

	it('releases the slot without leaking when the splice is refused', async () => {
		const channelId = crypto.randomBytes(32);
		const h = harness(
			{ allowSplice: true, negotiationTimeoutMs: 5 },
			{ authenticatedPeer: 'payer-node-id' }
		);
		h.node.spliceChannel = channelId;
		h.node.trustedPayers.add('payer-node-id');
		h.node.spliceError = 'splice is unavailable';
		const rejections = await captureUnhandledRejections(async () => {
			await h.sendOffer();
			await flush(20);
		});
		expect(rejections).to.deep.equal([]);
		expect(h.engine.inflightCount()).to.equal(0);
		expect(h.lastAck()?.reason).to.contain('splice is unavailable');
		expect(h.node.aborts).to.have.length(0);
	});

	it('keeps an abandoned splice timer from cancelling an outpoint retry', async () => {
		const node = new FakeDfNode();
		const engine = new DirectFundingReceiver(node, {
			allowSplice: true,
			negotiationTimeoutMs: 400,
			witnessTimeoutMs: 5_000,
			outpointCooldownMs: 20,
			sweepIntervalMs: 60_000
		});
		engine.start();
		node.spliceChannel = crypto.randomBytes(32);
		node.trustedPayers.add('payer-node-id');
		const coin = makeCoin('p2wpkh', 500_000);
		node.publish(coin);
		const firstPayer = new FakePayerLane(
			node.mintRequest(),
			'first-lane',
			'payer-node-id'
		);
		node.spliceError = 'splice is unavailable';
		engine.handleFrame(
			firstPayer.offerFrame(buildOffer(firstPayer.requestRecord, coin))
		);
		await flush();

		node.spliceError = null;
		await sleep(200);
		const secondPayer = new FakePayerLane(
			node.mintRequest(),
			'second-lane',
			'payer-node-id'
		);
		const second = buildOffer(secondPayer.requestRecord, coin, {
			amountSat: 60_000n
		});
		engine.handleFrame(secondPayer.offerFrame(second));
		await flush();
		expect(node.splices).to.have.length(2);

		await sleep(250);
		node.completeSpliceNegotiation(coin, second, 200_000n);
		await flush();
		expect(secondPayer.bodiesOf(SIGN_REQUEST)).to.have.length(1);
		engine.handleFrame(
			secondPayer.witnessFrame(second.offerId, [Buffer.alloc(64, 3)])
		);
		await flush();
		engine.stop();
	});
});

describe('Direct funding receiver: routing and zero-conf (issue #612)', () => {
	async function open(opts: {
		authenticated?: boolean;
		trusted?: boolean;
		zeroConf?: boolean;
		allowZeroConf?: boolean;
	}): Promise<FakeDfNode> {
		const peer = 'payer-node-id';
		const h = harness(
			{
				negotiationTimeoutMs: 5_000,
				allowZeroConf: opts.allowZeroConf ?? true
			},
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

	/**
	 * The node's zero-conf trust in the liquidity peer authorizes an open funded
	 * with the operator's OWN confirmed coins. Putting a stranger's
	 * double-spendable input under a channel the counterparty treats as live at
	 * depth zero is a different risk, and needs its own consent.
	 */
	it('never asks for zero-conf while direct funding has not been allowed it', async () => {
		const node = await open({
			authenticated: true,
			trusted: true,
			zeroConf: true,
			allowZeroConf: false
		});
		expect(node.opens[0].params.trusted).to.equal(undefined);
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
