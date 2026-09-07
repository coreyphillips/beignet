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
	deriveSwapId,
	encodeSwapCreate,
	encodeSwapCreateAck,
	encodeSwapQuote,
	encodeSwapQuoteRequest,
	encodeSwapStatus,
	encodeSwapStatusRequest,
	reverseSwapFee,
	verifyReverseSwapTerms
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
