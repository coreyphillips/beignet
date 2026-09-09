/**
 * Swap wire codecs and the client-side terms verifier (issue #737): round
 * trips, refusal acks, an accepted ack missing a term, unknown even and odd
 * types, caps, and every tampered term the verifier must catch.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { encode as encodeInvoice } from '../../src/lightning/invoice/encode';
import { Network } from '../../src/lightning/invoice/types';
import { encodeTlvStream } from '../../src/lightning/message/tlv';
import {
	ISwapCreate,
	ISwapCreateAck,
	ISwapQuote,
	ISwapStatus,
	ISwapSubmarineCreate,
	ISwapSubmarineCreateAck,
	SWAP_MAX_FUNDING_TX_BYTES,
	SwapMessageError,
	SwapRefusalReason,
	SwapWireDirection,
	SwapWireResolutionKind,
	SwapWireState,
	buildSwapHtlc,
	decodeSwapCreate,
	decodeSwapCreateAck,
	decodeSwapQuote,
	decodeSwapQuoteRequest,
	decodeSwapStatus,
	decodeSwapStatusRequest,
	decodeSwapSubmarineCreate,
	decodeSwapSubmarineCreateAck,
	deriveSwapId,
	encodeSwapCreate,
	encodeSwapCreateAck,
	encodeSwapQuote,
	encodeSwapQuoteRequest,
	encodeSwapStatus,
	encodeSwapStatusRequest,
	encodeSwapSubmarineCreate,
	encodeSwapSubmarineCreateAck,
	reverseSwapFee,
	submarineSwapFee,
	verifyReverseSwapTerms,
	verifySubmarineSwapTerms
} from '../../src/lightning/swaps';

const requestId = Buffer.alloc(8, 7);
const preimage = crypto.randomBytes(32);
const paymentHash = crypto.createHash('sha256').update(preimage).digest();
const claimKey = crypto.randomBytes(32);
const claimPubkey = getPublicKey(claimKey);
const refundKey = crypto.randomBytes(32);
const refundPubkey = getPublicKey(refundKey);
const providerKey = crypto.randomBytes(32);

function invoiceFor(
	amountMsat: bigint,
	hash = paymentHash,
	network = Network.REGTEST,
	timestamp = 1_700_000_000
): string {
	return encodeInvoice({
		network,
		amountMsat,
		timestamp,
		paymentHash: hash,
		paymentSecret: crypto.randomBytes(32),
		description: 'swap',
		expiry: 1800,
		minFinalCltvExpiry: 194,
		privateKey: providerKey
	});
}

function termsFor(
	overrides: Partial<ISwapCreateAck['terms'] & Record<string, unknown>> = {}
): ISwapCreateAck {
	const refundHeight = 1144;
	const contract = buildSwapHtlc(
		{
			paymentHash,
			claimPublicKey: claimPubkey,
			refundPublicKey: refundPubkey,
			refundHeight
		},
		bitcoin.networks.regtest
	);
	const onchainAmountSat = 100_000n;
	const totalFeeSat = 1_500n;
	return {
		requestId,
		accepted: true,
		paymentHash,
		reason: SwapRefusalReason.NONE,
		terms: {
			swapId: Buffer.alloc(16, 3),
			bolt11: invoiceFor((onchainAmountSat + totalFeeSat) * 1000n),
			refundPubkey,
			refundHeight,
			outputScript: contract.outputScript,
			address: contract.address,
			invoiceAmountMsat: (onchainAmountSat + totalFeeSat) * 1000n,
			onchainAmountSat,
			totalFeeSat,
			minerFeeSat: 500n,
			fundingConfirmations: 1,
			invoiceExpiresAt: 1_700_000_000 + 1800,
			currentHeight: 1000,
			...overrides
		}
	};
}

const create: ISwapCreate = {
	requestId,
	direction: SwapWireDirection.REVERSE,
	paymentHash,
	claimPubkey,
	onchainAmountSat: 100_000n,
	maxTotalFeeSat: 2_000n,
	preferredRefundDelta: 144
};

function check(
	ack: ISwapCreateAck,
	extra: Partial<Parameters<typeof verifyReverseSwapTerms>[0]> = {}
): ReturnType<typeof verifyReverseSwapTerms> {
	return verifyReverseSwapTerms({
		create,
		ack,
		currentHeight: 1000,
		network: Network.REGTEST,
		minRefundDelta: 36,
		maxRefundDelta: 4320,
		maxTotalFeeSat: 2_000n,
		...extra
	});
}

describe('Swap messages (issue #737)', function () {
	it('round-trips a quote request and a quote', function () {
		const req = decodeSwapQuoteRequest(
			encodeSwapQuoteRequest({
				requestId,
				direction: SwapWireDirection.REVERSE,
				amountSat: 50_000n,
				preferredRefundDelta: 100
			})
		);
		expect(req).to.deep.equal({
			requestId,
			direction: 1,
			amountSat: 50_000n,
			preferredRefundDelta: 100
		});
		const quote: ISwapQuote = {
			requestId,
			direction: SwapWireDirection.REVERSE,
			accepted: true,
			reason: SwapRefusalReason.NONE,
			flatFeeSat: 100n,
			feePpm: 2_000,
			minSwapSat: 10_000n,
			maxSwapSat: 1_000_000n,
			refundDeltaBlocks: 144,
			fundingConfirmations: 1,
			invoiceExpirySeconds: 1800,
			currentHeight: 1000,
			totalFeeSat: 700n,
			minerFeeSat: 500n,
			invoiceAmountMsat: 50_700_000n,
			reasonText: undefined,
			minRefundDelta: 72,
			maxRefundDelta: 288
		};
		expect(decodeSwapQuote(encodeSwapQuote(quote))).to.deep.equal(quote);
		const refused = decodeSwapQuote(
			encodeSwapQuote({
				...quote,
				accepted: false,
				reason: SwapRefusalReason.AMOUNT_ABOVE_MAX,
				reasonText: 'too big'
			})
		);
		expect(refused.accepted).to.equal(false);
		expect(refused.reason).to.equal(SwapRefusalReason.AMOUNT_ABOVE_MAX);
		expect(refused.reasonText).to.equal('too big');
	});

	it('round-trips a create and refuses a zero amount or an invalid key', function () {
		expect(decodeSwapCreate(encodeSwapCreate(create))).to.deep.equal(create);
		expect(() =>
			encodeSwapCreate({ ...create, claimPubkey: Buffer.alloc(33, 1) })
		).to.throw(SwapMessageError);
		expect(() =>
			decodeSwapCreate(encodeSwapCreate({ ...create, onchainAmountSat: 0n }))
		).to.throw(/positive/);
		expect(() =>
			encodeSwapCreate({ ...create, paymentHash: Buffer.alloc(31) })
		).to.throw(/32 bytes/);
	});

	it('round-trips an accepted ack and a refusal, and refuses an accepted ack with a missing term', function () {
		const ack = termsFor();
		const decoded = decodeSwapCreateAck(encodeSwapCreateAck(ack));
		expect(decoded).to.deep.equal({ ...ack, reasonText: undefined });
		const refusal: ISwapCreateAck = {
			requestId,
			accepted: false,
			paymentHash,
			reason: SwapRefusalReason.FEE_CEILING,
			reasonText: 'fee 1500 sat exceeds the client ceiling'
		};
		expect(decodeSwapCreateAck(encodeSwapCreateAck(refusal))).to.deep.equal(
			refusal
		);
		expect(() =>
			encodeSwapCreateAck({ ...refusal, terms: ack.terms })
		).to.throw(/must not carry terms/);
		expect(() => encodeSwapCreateAck({ ...ack, terms: undefined })).to.throw(
			/needs terms/
		);
		// Strip one odd term from an accepted ack: malformed, never "no refund height".
		const records = [
			{ type: 0n, value: requestId },
			{ type: 2n, value: Buffer.from([1]) },
			{ type: 4n, value: paymentHash },
			{ type: 6n, value: Buffer.from([0]) },
			{ type: 9n, value: Buffer.alloc(16, 3) }
		];
		expect(() => decodeSwapCreateAck(encodeTlvStream(records))).to.throw(
			/bolt11 is missing/
		);
		// A P2WSH script is the only accepted output script.
		expect(() =>
			encodeSwapCreateAck(
				termsFor({ outputScript: Buffer.from('0014' + '11'.repeat(20), 'hex') })
			)
		).to.throw(/34 bytes/);
	});

	it('round-trips status messages, with and without facts, and caps the funding tx', function () {
		const req = decodeSwapStatusRequest(
			encodeSwapStatusRequest({ requestId, swapId: Buffer.alloc(16, 9) })
		);
		expect(req.swapId).to.deep.equal(Buffer.alloc(16, 9));
		const bare: ISwapStatus = {
			requestId,
			swapId: Buffer.alloc(16, 9),
			found: false,
			state: SwapWireState.UNKNOWN,
			currentHeight: 1000
		};
		const bareDecoded = decodeSwapStatus(encodeSwapStatus(bare));
		expect(bareDecoded.found).to.equal(false);
		expect(bareDecoded.fundingTxid).to.equal(undefined);
		expect(bareDecoded.fundingTx).to.equal(undefined);
		const full: ISwapStatus = {
			...bare,
			found: true,
			state: SwapWireState.FUNDED,
			refundHeight: 1144,
			fundingTxid: Buffer.alloc(32, 4),
			fundingVout: 1,
			fundingHeight: 1001,
			fundingConfirmations: 2,
			fundingTx: Buffer.alloc(200, 5),
			resolutionTxid: Buffer.alloc(32, 6),
			resolutionKind: SwapWireResolutionKind.CLAIM,
			resolutionHeight: 1002,
			resolutionConfirmations: 1
		};
		expect(decodeSwapStatus(encodeSwapStatus(full))).to.deep.equal(full);
		expect(() =>
			encodeSwapStatus({
				...full,
				fundingTx: Buffer.alloc(SWAP_MAX_FUNDING_TX_BYTES + 1)
			})
		).to.throw(/too large/);
	});

	it('skips unknown odd types and refuses unknown even ones', function () {
		const base = encodeSwapStatusRequest({
			requestId,
			swapId: Buffer.alloc(16, 9)
		});
		const withOdd = Buffer.concat([
			base,
			encodeTlvStream([{ type: 999n, value: Buffer.from([1]) }])
		]);
		expect(decodeSwapStatusRequest(withOdd).swapId).to.deep.equal(
			Buffer.alloc(16, 9)
		);
		const withEven = Buffer.concat([
			base,
			encodeTlvStream([{ type: 1000n, value: Buffer.from([1]) }])
		]);
		expect(() => decodeSwapStatusRequest(withEven)).to.throw(SwapMessageError);
		expect(() => decodeSwapQuoteRequest(Buffer.alloc(5000))).to.throw(
			/max 4096/
		);
	});

	it('derives a stable swap id and the reverse fee', function () {
		const peer = getPublicKey(crypto.randomBytes(32));
		expect(deriveSwapId(peer, paymentHash)).to.deep.equal(
			deriveSwapId(peer, paymentHash)
		);
		expect(
			reverseSwapFee(100_000n, {
				flatFeeSat: 100n,
				feePpm: 2_500,
				minerFeeSat: 400n
			})
		).to.equal(750n);
		// ppm rounds up.
		expect(
			reverseSwapFee(1n, { flatFeeSat: 0n, feePpm: 1, minerFeeSat: 0n })
		).to.equal(1n);
		expect(
			reverseSwapFee(0n, { flatFeeSat: 5n, feePpm: 1, minerFeeSat: 0n })
		).to.equal(5n);
	});

	describe('verifyReverseSwapTerms', function () {
		it('accepts a consistent ack and returns the contract', function () {
			const verdict = check(termsFor());
			expect(verdict.ok).to.equal(true);
			if (verdict.ok) {
				expect(verdict.htlc.refundHeight).to.equal(1144);
				expect(verdict.address).to.equal(termsFor().terms!.address);
				expect(verdict.invoice.amountMsat).to.equal(101_500_000n);
				expect(verdict.invoice.expiresAt).to.equal(1_700_001_800);
			}
		});

		it('reports a refusal with its reason', function () {
			const verdict = check({
				requestId,
				accepted: false,
				paymentHash,
				reason: SwapRefusalReason.EXPOSURE_EXCEEDED,
				reasonText: 'full'
			});
			expect(verdict.ok).to.equal(false);
			if (!verdict.ok) {
				expect(verdict.refusal).to.equal(SwapRefusalReason.EXPOSURE_EXCEEDED);
				expect(verdict.reason).to.match(/EXPOSURE_EXCEEDED/);
			}
		});

		it('rejects every tampered term', function () {
			const otherKey = getPublicKey(crypto.randomBytes(32));
			const cases: Array<
				[
					string,
					ISwapCreateAck,
					Partial<Parameters<typeof verifyReverseSwapTerms>[0]>,
					RegExp
				]
			> = [
				[
					'request id',
					{ ...termsFor(), requestId: Buffer.alloc(8, 1) },
					{},
					/different request/
				],
				[
					'payment hash',
					{ ...termsFor(), paymentHash: crypto.randomBytes(32) },
					{},
					/different payment hash/
				],
				[
					'amount',
					termsFor({ onchainAmountSat: 99_999n }),
					{},
					/amount differs/
				],
				[
					'fee ceiling',
					termsFor(),
					{ maxTotalFeeSat: 1_499n },
					/client ceiling/
				],
				['miner fee', termsFor({ minerFeeSat: 1_501n }), {}, /miner fee/],
				[
					'invoice arithmetic',
					termsFor({ invoiceAmountMsat: 101_500_001n }),
					{},
					/amount plus fee/
				],
				[
					'refund key equals claim key',
					termsFor({ refundPubkey: claimPubkey }),
					{},
					/equals the claim key/
				],
				['refund too soon', termsFor(), { currentHeight: 1120 }, /too soon/],
				['refund too late', termsFor(), { maxRefundDelta: 100 }, /too far/],
				[
					'output script',
					termsFor({ refundPubkey: otherKey }),
					{},
					/output script/
				],
				[
					'address',
					termsFor({
						address: buildSwapHtlc(
							{
								paymentHash,
								claimPublicKey: claimPubkey,
								refundPublicKey: otherKey,
								refundHeight: 1144
							},
							bitcoin.networks.regtest
						).address
					}),
					{},
					/address/
				],
				[
					'invoice network',
					termsFor({
						bolt11: invoiceFor(101_500_000n, paymentHash, Network.TESTNET)
					}),
					{},
					/another network/
				],
				[
					'invoice hash',
					termsFor({
						bolt11: invoiceFor(101_500_000n, crypto.randomBytes(32))
					}),
					{},
					/another payment hash/
				],
				[
					'invoice amount',
					termsFor({ bolt11: invoiceFor(101_500_001n) }),
					{},
					/invoice amount differs/
				],
				[
					'invoice expiry',
					termsFor({ invoiceExpiresAt: 1_700_001_801 }),
					{},
					/expiry differs/
				],
				[
					'invoice garbage',
					termsFor({ bolt11: 'lnbcrt1nonsense' }),
					{},
					/does not decode/
				]
			];
			for (const [label, ack, extra, pattern] of cases) {
				const verdict = check(ack, extra);
				expect(verdict.ok, label).to.equal(false);
				if (!verdict.ok) expect(verdict.reason, label).to.match(pattern);
			}
		});
	});
});

// ─────────────── Submarine direction (issue #743) ───────────────

const SUB_ONCHAIN = 100_000n;
const SUB_FEE = 1_500n;
const SUB_INVOICE_MSAT = (SUB_ONCHAIN - SUB_FEE) * 1000n;

function submarineInvoice(
	amountMsat = SUB_INVOICE_MSAT,
	hash = paymentHash,
	network = Network.REGTEST,
	minFinalCltvExpiry = 40
): string {
	// The CLIENT mints this one under its own key.
	return encodeInvoice({
		network,
		amountMsat,
		timestamp: 1_700_000_000,
		paymentHash: hash,
		paymentSecret: crypto.randomBytes(32),
		description: 'submarine swap',
		expiry: 7200,
		minFinalCltvExpiry,
		privateKey: refundKey
	});
}

const submarineCreate: ISwapSubmarineCreate = {
	requestId,
	direction: SwapWireDirection.SUBMARINE,
	paymentHash,
	refundPubkey,
	bolt11: submarineInvoice(),
	onchainAmountSat: SUB_ONCHAIN,
	maxTotalFeeSat: 2_000n,
	preferredRefundDelta: 288
};

function submarineTermsFor(
	overrides: Partial<
		ISwapSubmarineCreateAck['terms'] & Record<string, unknown>
	> = {}
): ISwapSubmarineCreateAck {
	const refundHeight = 1288;
	const contract = buildSwapHtlc(
		{
			paymentHash,
			claimPublicKey: claimPubkey,
			refundPublicKey: refundPubkey,
			refundHeight
		},
		bitcoin.networks.regtest
	);
	return {
		requestId,
		accepted: true,
		paymentHash,
		reason: SwapRefusalReason.NONE,
		terms: {
			swapId: Buffer.alloc(16, 5),
			claimPubkey,
			refundHeight,
			outputScript: contract.outputScript,
			address: contract.address,
			invoiceAmountMsat: SUB_INVOICE_MSAT,
			onchainAmountSat: SUB_ONCHAIN,
			totalFeeSat: SUB_FEE,
			minerFeeSat: 500n,
			fundingConfirmations: 1,
			expiresAt: 1_700_000_000 + 7200,
			currentHeight: 1000,
			paymentCeilingHeight: 1240,
			...overrides
		}
	};
}

function checkSubmarine(
	ack: ISwapSubmarineCreateAck,
	extra: Partial<Parameters<typeof verifySubmarineSwapTerms>[0]> = {}
): ReturnType<typeof verifySubmarineSwapTerms> {
	return verifySubmarineSwapTerms({
		create: submarineCreate,
		ack,
		currentHeight: 1000,
		network: Network.REGTEST,
		minRefundDelta: 144,
		maxRefundDelta: 432,
		maxTotalFeeSat: 2_000n,
		...extra
	});
}

describe('Submarine swap messages (issue #743)', function () {
	it('round-trips a submarine create and refuses a zero amount, an empty invoice or an invalid key', function () {
		expect(
			decodeSwapSubmarineCreate(encodeSwapSubmarineCreate(submarineCreate))
		).to.deep.equal(submarineCreate);
		const bare = { ...submarineCreate, preferredRefundDelta: undefined };
		expect(
			decodeSwapSubmarineCreate(encodeSwapSubmarineCreate(bare))
		).to.deep.equal(bare);
		expect(() =>
			encodeSwapSubmarineCreate({
				...submarineCreate,
				refundPubkey: Buffer.alloc(33, 1)
			})
		).to.throw(SwapMessageError);
		expect(() =>
			decodeSwapSubmarineCreate(
				encodeSwapSubmarineCreate({ ...submarineCreate, onchainAmountSat: 0n })
			)
		).to.throw(/positive/);
		expect(() =>
			decodeSwapSubmarineCreate(
				encodeSwapSubmarineCreate({ ...submarineCreate, bolt11: '' })
			)
		).to.throw(/bolt11 is empty/);
		expect(() =>
			encodeSwapSubmarineCreate({
				...submarineCreate,
				bolt11: 'x'.repeat(2049)
			})
		).to.throw(/max 2048/);
	});

	it('round-trips an accepted submarine ack (with and without the ceiling) and a refusal, and refuses a hole', function () {
		const ack = submarineTermsFor();
		expect(
			decodeSwapSubmarineCreateAck(encodeSwapSubmarineCreateAck(ack))
		).to.deep.equal({ ...ack, reasonText: undefined });
		const noCeiling = submarineTermsFor({ paymentCeilingHeight: undefined });
		expect(
			decodeSwapSubmarineCreateAck(encodeSwapSubmarineCreateAck(noCeiling))
		).to.deep.equal({ ...noCeiling, reasonText: undefined });
		const refusal: ISwapSubmarineCreateAck = {
			requestId,
			accepted: false,
			paymentHash,
			reason: SwapRefusalReason.CLTV_UNFITTABLE,
			reasonText: 'final cltv 400 cannot fit under the refund height'
		};
		expect(
			decodeSwapSubmarineCreateAck(encodeSwapSubmarineCreateAck(refusal))
		).to.deep.equal(refusal);
		expect(() =>
			encodeSwapSubmarineCreateAck({ ...refusal, terms: ack.terms })
		).to.throw(/must not carry terms/);
		expect(() =>
			encodeSwapSubmarineCreateAck({ ...ack, terms: undefined })
		).to.throw(/needs terms/);
		const records = [
			{ type: 0n, value: requestId },
			{ type: 2n, value: Buffer.from([1]) },
			{ type: 4n, value: paymentHash },
			{ type: 6n, value: Buffer.from([0]) },
			{ type: 9n, value: Buffer.alloc(16, 5) }
		];
		expect(() =>
			decodeSwapSubmarineCreateAck(encodeTlvStream(records))
		).to.throw(/is missing/);
	});

	it('carries every new refusal reason and wire state, and rejects the old maxima plus one', function () {
		for (const reason of [
			SwapRefusalReason.INVOICE_MISMATCH,
			SwapRefusalReason.CLTV_UNFITTABLE,
			SwapRefusalReason.SELF_PAYMENT,
			SwapRefusalReason.NO_OUTBOUND_LIQUIDITY
		]) {
			const ack: ISwapSubmarineCreateAck = {
				requestId,
				accepted: false,
				paymentHash,
				reason
			};
			expect(
				decodeSwapSubmarineCreateAck(encodeSwapSubmarineCreateAck(ack)).reason,
				SwapRefusalReason[reason]
			).to.equal(reason);
		}
		expect(() =>
			encodeSwapCreateAck({
				requestId,
				accepted: false,
				paymentHash,
				reason: (SwapRefusalReason.NO_OUTBOUND_LIQUIDITY +
					1) as SwapRefusalReason
			})
		).to.throw(/out of range/);
		for (const state of [
			SwapWireState.FUNDING_SEEN,
			SwapWireState.FUNDING_LOST,
			SwapWireState.PAYING,
			SwapWireState.PAYMENT_UNRESOLVED,
			SwapWireState.PREIMAGE_KNOWN,
			SwapWireState.CLAIM_BROADCAST,
			SwapWireState.CLAIM_CONFIRMED,
			SwapWireState.PAYMENT_FAILED
		]) {
			const status: ISwapStatus = {
				requestId,
				swapId: Buffer.alloc(16, 9),
				found: true,
				state,
				currentHeight: 1000
			};
			expect(
				decodeSwapStatus(encodeSwapStatus(status)).state,
				SwapWireState[state]
			).to.equal(state);
		}
		expect(() =>
			encodeSwapStatus({
				requestId,
				swapId: Buffer.alloc(16, 9),
				found: true,
				state: (SwapWireState.PAYMENT_FAILED + 1) as SwapWireState,
				currentHeight: 1000
			})
		).to.throw(/out of range/);
		// The direction is accepted on the wire in both quote and create.
		const req = decodeSwapQuoteRequest(
			encodeSwapQuoteRequest({
				requestId,
				direction: SwapWireDirection.SUBMARINE,
				amountSat: 50_000n
			})
		);
		expect(req.direction).to.equal(SwapWireDirection.SUBMARINE);
	});

	it('computes the submarine fee like the reverse fee', function () {
		const terms = { flatFeeSat: 100n, feePpm: 1_000, minerFeeSat: 300n };
		expect(submarineSwapFee(100_000n, terms)).to.equal(
			reverseSwapFee(100_000n, terms)
		);
		expect(submarineSwapFee(100_000n, terms)).to.equal(500n);
	});

	describe('verifySubmarineSwapTerms', function () {
		it('accepts a consistent ack and returns the contract and the invoice facts', function () {
			const verdict = checkSubmarine(submarineTermsFor());
			expect(verdict.ok).to.equal(true);
			if (!verdict.ok) return;
			expect(verdict.htlc.claimPublicKey.equals(claimPubkey)).to.equal(true);
			expect(verdict.htlc.refundPublicKey.equals(refundPubkey)).to.equal(true);
			expect(verdict.htlc.refundHeight).to.equal(1288);
			expect(verdict.address).to.match(/^bcrt1q/);
			expect(verdict.invoice.amountMsat).to.equal(SUB_INVOICE_MSAT);
			expect(verdict.invoice.minFinalCltvExpiry).to.equal(40);
			expect(verdict.invoice.expiresAt).to.equal(1_700_000_000 + 7200);
		});

		it('reports a refusal with its reason', function () {
			const verdict = checkSubmarine({
				requestId,
				accepted: false,
				paymentHash,
				reason: SwapRefusalReason.NO_OUTBOUND_LIQUIDITY,
				reasonText: 'no channel'
			});
			expect(verdict.ok).to.equal(false);
			if (verdict.ok) return;
			expect(verdict.refusal).to.equal(SwapRefusalReason.NO_OUTBOUND_LIQUIDITY);
			expect(verdict.reason).to.match(/NO_OUTBOUND_LIQUIDITY.*no channel/);
		});

		it('rejects every tampered term', function () {
			const cases: Array<[string, () => ReturnType<typeof checkSubmarine>]> = [
				[
					'different request',
					() =>
						checkSubmarine({
							...submarineTermsFor(),
							requestId: Buffer.alloc(8, 8)
						})
				],
				[
					'different payment hash',
					() =>
						checkSubmarine({
							...submarineTermsFor(),
							paymentHash: crypto.randomBytes(32)
						})
				],
				[
					'on-chain amount',
					() => checkSubmarine(submarineTermsFor({ onchainAmountSat: 99_000n }))
				],
				[
					'fee above the client ceiling',
					() =>
						checkSubmarine(
							submarineTermsFor({
								totalFeeSat: 2_500n,
								invoiceAmountMsat: (SUB_ONCHAIN - 2_500n) * 1000n
							}),
							{ maxTotalFeeSat: 2_400n }
						)
				],
				[
					'fee above the request ceiling',
					() =>
						checkSubmarine(
							submarineTermsFor({
								totalFeeSat: 2_500n,
								invoiceAmountMsat: (SUB_ONCHAIN - 2_500n) * 1000n
							}),
							{ maxTotalFeeSat: 5_000n }
						)
				],
				[
					'miner fee above total',
					() => checkSubmarine(submarineTermsFor({ minerFeeSat: 2_000n }))
				],
				[
					'fee swallows the amount',
					() =>
						checkSubmarine(
							submarineTermsFor({
								totalFeeSat: SUB_ONCHAIN,
								invoiceAmountMsat: 0n
							}),
							{ maxTotalFeeSat: SUB_ONCHAIN }
						)
				],
				[
					'invoice amount arithmetic',
					() =>
						checkSubmarine(
							submarineTermsFor({ invoiceAmountMsat: SUB_INVOICE_MSAT + 1000n })
						)
				],
				[
					'claim key equals refund key',
					() => checkSubmarine(submarineTermsFor({ claimPubkey: refundPubkey }))
				],
				[
					'zero funding confirmations',
					() => checkSubmarine(submarineTermsFor({ fundingConfirmations: 0 }))
				],
				[
					'refund too soon',
					() => checkSubmarine(submarineTermsFor(), { minRefundDelta: 300 })
				],
				[
					'refund too far',
					() => checkSubmarine(submarineTermsFor(), { maxRefundDelta: 200 })
				],
				[
					'output script',
					() =>
						checkSubmarine(
							submarineTermsFor({
								outputScript: Buffer.from('0020' + '55'.repeat(32), 'hex')
							})
						)
				],
				[
					'address',
					() =>
						checkSubmarine(
							submarineTermsFor({
								address:
									'bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqs6h0c6d'
							})
						)
				],
				[
					'invoice on another network',
					() =>
						verifySubmarineSwapTerms({
							create: {
								...submarineCreate,
								bolt11: submarineInvoice(
									SUB_INVOICE_MSAT,
									paymentHash,
									Network.TESTNET
								)
							},
							ack: submarineTermsFor(),
							currentHeight: 1000,
							network: Network.REGTEST,
							minRefundDelta: 144,
							maxRefundDelta: 432,
							maxTotalFeeSat: 2_000n
						})
				],
				[
					'invoice with another hash',
					() =>
						verifySubmarineSwapTerms({
							create: {
								...submarineCreate,
								bolt11: submarineInvoice(
									SUB_INVOICE_MSAT,
									crypto.randomBytes(32)
								)
							},
							ack: submarineTermsFor(),
							currentHeight: 1000,
							network: Network.REGTEST,
							minRefundDelta: 144,
							maxRefundDelta: 432,
							maxTotalFeeSat: 2_000n
						})
				],
				[
					'invoice amount differs from the terms',
					() =>
						verifySubmarineSwapTerms({
							create: {
								...submarineCreate,
								bolt11: submarineInvoice(SUB_INVOICE_MSAT - 1000n)
							},
							ack: submarineTermsFor(),
							currentHeight: 1000,
							network: Network.REGTEST,
							minRefundDelta: 144,
							maxRefundDelta: 432,
							maxTotalFeeSat: 2_000n
						})
				],
				[
					'provider watches past the invoice expiry',
					() =>
						checkSubmarine(
							submarineTermsFor({ expiresAt: 1_700_000_000 + 7201 })
						)
				],
				[
					'invoice does not decode',
					() =>
						verifySubmarineSwapTerms({
							create: { ...submarineCreate, bolt11: 'lnbcrt1nonsense' },
							ack: submarineTermsFor(),
							currentHeight: 1000,
							network: Network.REGTEST,
							minRefundDelta: 144,
							maxRefundDelta: 432,
							maxTotalFeeSat: 2_000n
						})
				]
			];
			for (const [name, run] of cases) {
				const verdict = run();
				expect(verdict.ok, name).to.equal(false);
			}
		});
	});
});
