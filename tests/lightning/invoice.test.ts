/**
 * BOLT 11: Invoice (Payment Request) — Tests
 *
 * Tests for encoding, decoding, signing, amount handling, and word utilities.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as secp from '@noble/secp256k1';
import {
	// Types
	Network,
	TagType,
	IInvoiceCreationOptions,
	IRoutingHintHop,
	DEFAULT_EXPIRY,
	DEFAULT_MIN_FINAL_CLTV_EXPIRY,
	BECH32_MAX_LIMIT,
	TIMESTAMP_WORDS,
	SIGNATURE_WORDS,
	ROUTING_HOP_BYTES,
	// Word utilities
	wordsToBuffer,
	bufferToWords,
	encodeUintToWords,
	decodeUintFromWords,
	encodeTaggedField,
	decodeTaggedField,
	// Amount
	msatToHrpAmount,
	hrpAmountToMsat,
	parseHrp,
	buildHrp,
	// Signing
	ensureHmac,
	computeSigningHash,
	signInvoice,
	verifyInvoice,
	// Encode/Decode
	encode,
	decode
} from '../../src/lightning/invoice';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';

// Ensure HMAC is set up for secp256k1
ensureHmac();

/** Generate a random 32-byte private key and its compressed public key. */
function makeKeypair(): { privateKey: Buffer; publicKey: Buffer } {
	let privKey: Buffer;
	do {
		privKey = crypto.randomBytes(32);
	} while (!secp.utils.isValidPrivateKey(privKey));
	const publicKey = Buffer.from(secp.getPublicKey(privKey, true));
	return { privateKey: privKey, publicKey };
}

/** Create minimal valid invoice options. */
function makeMinimalOptions(
	overrides?: Partial<IInvoiceCreationOptions>
): IInvoiceCreationOptions {
	const { privateKey } = makeKeypair();
	return {
		network: Network.MAINNET,
		paymentHash: crypto.randomBytes(32),
		description: 'test',
		privateKey,
		...overrides
	};
}

describe('Invoice (BOLT 11) — Phase 5', function () {
	// ─── Word Utilities (5A) ──────────────────────────────────────────────

	describe('Word Utilities', function () {
		it('should round-trip bytes → words → bytes', function () {
			const original = crypto.randomBytes(32);
			const words = bufferToWords(original);
			const recovered = wordsToBuffer(words);
			expect(recovered).to.deep.equal(original);
		});

		it('should round-trip for empty data', function () {
			const words = bufferToWords(Buffer.alloc(0));
			expect(words).to.have.length(0);
			const buf = wordsToBuffer([]);
			expect(buf).to.have.length(0);
		});

		it('should round-trip for small data', function () {
			const data = Buffer.from([0xff]);
			const words = bufferToWords(data);
			const recovered = wordsToBuffer(words);
			expect(recovered).to.deep.equal(data);
		});

		it('should encode uint to fixed-width words (timestamp)', function () {
			const ts = 1496314658; // Example from BOLT 11
			const words = encodeUintToWords(ts, TIMESTAMP_WORDS);
			expect(words).to.have.length(7);
			expect(decodeUintFromWords(words)).to.equal(ts);
		});

		it('should encode zero as fixed-width words', function () {
			const words = encodeUintToWords(0, 3);
			expect(words).to.deep.equal([0, 0, 0]);
			expect(decodeUintFromWords(words)).to.equal(0);
		});

		it('should encode max value in 7 words', function () {
			const max = 32 ** 7 - 1; // 34359738367
			const words = encodeUintToWords(max, 7);
			expect(decodeUintFromWords(words)).to.equal(max);
			expect(words.every((w) => w === 31)).to.be.true;
		});

		it('should encode/decode tagged field', function () {
			const dataWords = [1, 2, 3, 4, 5];
			const encoded = encodeTaggedField(13, dataWords);
			expect(encoded[0]).to.equal(13); // type
			expect(encoded[1]).to.equal(0); // len high
			expect(encoded[2]).to.equal(5); // len low
			expect(encoded.slice(3)).to.deep.equal(dataWords);

			const decoded = decodeTaggedField(encoded, 0);
			expect(decoded.type).to.equal(13);
			expect(decoded.dataWords).to.deep.equal(dataWords);
			expect(decoded.nextOffset).to.equal(8);
		});

		it('should encode tagged field with length > 31', function () {
			const dataWords = new Array(100).fill(0);
			const encoded = encodeTaggedField(1, dataWords);
			expect(encoded[1]).to.equal(3); // 100 >> 5 = 3
			expect(encoded[2]).to.equal(4); // 100 & 31 = 4
		});

		it('should decode multiple sequential tagged fields', function () {
			const field1 = encodeTaggedField(1, [10, 20]);
			const field2 = encodeTaggedField(6, [5]);
			const combined = [...field1, ...field2];

			const d1 = decodeTaggedField(combined, 0);
			expect(d1.type).to.equal(1);
			expect(d1.dataWords).to.deep.equal([10, 20]);

			const d2 = decodeTaggedField(combined, d1.nextOffset);
			expect(d2.type).to.equal(6);
			expect(d2.dataWords).to.deep.equal([5]);
		});

		it('should throw on truncated tagged field header', function () {
			expect(() => decodeTaggedField([1, 2], 0)).to.throw(
				'not enough words for header'
			);
		});

		it('should throw on truncated tagged field data', function () {
			// Header says 10 words, but only 2 available
			expect(() => decodeTaggedField([1, 0, 10, 1, 2], 0)).to.throw(
				'truncated'
			);
		});
	});

	// ─── Amount Encoding/Decoding (5B) ────────────────────────────────────

	describe('Amount', function () {
		it('should parse milli multiplier (m)', function () {
			expect(hrpAmountToMsat('2500m')).to.equal(250_000_000_000n);
		});

		it('should parse micro multiplier (u)', function () {
			expect(hrpAmountToMsat('2500u')).to.equal(250_000_000n);
		});

		it('should parse nano multiplier (n)', function () {
			expect(hrpAmountToMsat('2500n')).to.equal(250_000n);
		});

		it('should parse pico multiplier (p)', function () {
			expect(hrpAmountToMsat('25000p')).to.equal(2_500n);
		});

		it('should parse whole BTC (no multiplier)', function () {
			expect(hrpAmountToMsat('1')).to.equal(100_000_000_000n);
			expect(hrpAmountToMsat('2')).to.equal(200_000_000_000n);
		});

		it('should encode amount with milli multiplier', function () {
			expect(msatToHrpAmount(100_000_000n)).to.equal('1m');
			expect(msatToHrpAmount(250_000_000_000n)).to.equal('2500m');
		});

		it('should encode amount with micro multiplier', function () {
			expect(msatToHrpAmount(100_000n)).to.equal('1u');
			expect(msatToHrpAmount(250_000_000n)).to.equal('2500u');
		});

		it('should encode amount with nano multiplier', function () {
			expect(msatToHrpAmount(100n)).to.equal('1n');
			expect(msatToHrpAmount(250_000n)).to.equal('2500n');
		});

		it('should encode amount with pico multiplier for odd msat', function () {
			expect(msatToHrpAmount(1n)).to.equal('10p');
			expect(msatToHrpAmount(11n)).to.equal('110p');
		});

		it('should encode whole BTC amounts', function () {
			expect(msatToHrpAmount(100_000_000_000n)).to.equal('1');
			expect(msatToHrpAmount(200_000_000_000n)).to.equal('2');
		});

		it('should choose optimal (largest) multiplier', function () {
			// 1 mBTC = 100,000,000 msat → use 'm' not 'u'
			expect(msatToHrpAmount(100_000_000n)).to.equal('1m');
			// 1000 uBTC = 1 mBTC → use 'm'
			expect(msatToHrpAmount(100_000_000_000n)).to.equal('1');
		});

		it('should round-trip msat → HRP → msat', function () {
			const amounts = [
				1n,
				100n,
				100_000n,
				100_000_000n,
				100_000_000_000n,
				250_000n,
				123_456_789n,
				42n
			];
			for (const msat of amounts) {
				const hrpStr = msatToHrpAmount(msat);
				expect(hrpAmountToMsat(hrpStr)).to.equal(msat);
			}
		});

		it('should reject pico amount not divisible by 10', function () {
			expect(() => hrpAmountToMsat('1p')).to.throw('not divisible by 10');
		});

		it('should reject leading zeros', function () {
			expect(() => hrpAmountToMsat('01m')).to.throw('Leading zeros');
		});

		it('should reject empty amount string', function () {
			expect(() => hrpAmountToMsat('')).to.throw('Empty amount');
		});

		it('should reject amount with no digits before multiplier', function () {
			expect(() => hrpAmountToMsat('m')).to.throw('Invalid amount digits');
		});

		it('should reject zero amount', function () {
			expect(() => msatToHrpAmount(0n)).to.throw('positive');
		});

		it('should parse full HRP string (mainnet)', function () {
			const result = parseHrp('lnbc2500u');
			expect(result.network).to.equal(Network.MAINNET);
			expect(result.amountMsat).to.equal(250_000_000n);
		});

		it('should parse full HRP string (testnet)', function () {
			const result = parseHrp('lntb1m');
			expect(result.network).to.equal(Network.TESTNET);
			expect(result.amountMsat).to.equal(100_000_000n);
		});

		it('should parse full HRP string (regtest)', function () {
			const result = parseHrp('lnbcrt500n');
			expect(result.network).to.equal(Network.REGTEST);
			expect(result.amountMsat).to.equal(50_000n);
		});

		it('should parse full HRP string (signet)', function () {
			const result = parseHrp('lntbs100u');
			expect(result.network).to.equal(Network.SIGNET);
			expect(result.amountMsat).to.equal(10_000_000n);
		});

		it('should parse HRP with no amount', function () {
			const result = parseHrp('lnbc');
			expect(result.network).to.equal(Network.MAINNET);
			expect(result.amountMsat).to.be.null;
		});

		it('should reject invalid HRP prefix', function () {
			expect(() => parseHrp('btc1000')).to.throw('must start with "ln"');
		});

		it('should reject unknown network', function () {
			expect(() => parseHrp('lnxx1000u')).to.throw('Unknown network');
		});

		it('should build HRP string', function () {
			expect(buildHrp(Network.MAINNET, 250_000_000n)).to.equal('lnbc2500u');
			expect(buildHrp(Network.TESTNET)).to.equal('lntb');
			expect(buildHrp(Network.REGTEST, 100_000_000n)).to.equal('lnbcrt1m');
		});

		it('should round-trip HRP build → parse', function () {
			const networks = [
				Network.MAINNET,
				Network.TESTNET,
				Network.REGTEST,
				Network.SIGNET
			];
			const amounts: Array<bigint | undefined> = [
				undefined,
				1n,
				100_000n,
				250_000_000n
			];
			for (const net of networks) {
				for (const amt of amounts) {
					const hrp = buildHrp(net, amt);
					const parsed = parseHrp(hrp);
					expect(parsed.network).to.equal(net);
					if (amt === undefined) {
						expect(parsed.amountMsat).to.be.null;
					} else {
						expect(parsed.amountMsat).to.equal(amt);
					}
				}
			}
		});
	});

	// ─── Signing (5C) ─────────────────────────────────────────────────────

	describe('Signing', function () {
		it('should sign and recover pubkey round-trip', function () {
			const { privateKey, publicKey } = makeKeypair();
			const hrp = 'lnbc2500u';
			const dataWords = encodeUintToWords(1496314658, TIMESTAMP_WORDS);

			const sig = signInvoice(hrp, dataWords, privateKey);
			expect(sig).to.have.length(65);

			const recovered = verifyInvoice(hrp, dataWords, sig);
			expect(recovered).to.not.be.null;
			expect(recovered!).to.deep.equal(publicKey);
		});

		it('should produce deterministic signatures', function () {
			const { privateKey } = makeKeypair();
			const hrp = 'lnbc1m';
			const words = encodeUintToWords(12345, TIMESTAMP_WORDS);

			const sig1 = signInvoice(hrp, words, privateKey);
			const sig2 = signInvoice(hrp, words, privateKey);
			expect(sig1).to.deep.equal(sig2);
		});

		it('should compute deterministic signing hash', function () {
			const hrp = 'lnbc';
			const words = [0, 0, 0, 0, 0, 0, 0];
			const hash1 = computeSigningHash(hrp, words);
			const hash2 = computeSigningHash(hrp, words);
			expect(hash1).to.deep.equal(hash2);
			expect(hash1).to.have.length(32);
		});

		it('should return null for invalid signature length', function () {
			const result = verifyInvoice('lnbc', [0, 0, 0], Buffer.alloc(30));
			expect(result).to.be.null;
		});

		it('should return null for invalid recovery ID', function () {
			const sig = Buffer.alloc(65);
			sig[64] = 4; // invalid recovery ID
			const result = verifyInvoice('lnbc', [0, 0, 0, 0, 0, 0, 0], sig);
			expect(result).to.be.null;
		});

		it('should ensure HMAC setup is idempotent', function () {
			// Call multiple times — should not throw
			ensureHmac();
			ensureHmac();
			ensureHmac();
			// Verify signing still works
			const { privateKey, publicKey } = makeKeypair();
			const sig = signInvoice('lnbc', encodeUintToWords(0, 7), privateKey);
			const recovered = verifyInvoice('lnbc', encodeUintToWords(0, 7), sig);
			expect(recovered).to.deep.equal(publicKey);
		});

		it('should produce different signatures for different data', function () {
			const { privateKey } = makeKeypair();
			const sig1 = signInvoice('lnbc', encodeUintToWords(1, 7), privateKey);
			const sig2 = signInvoice('lnbc', encodeUintToWords(2, 7), privateKey);
			expect(sig1).to.not.deep.equal(sig2);
		});

		it('should produce different signatures for different HRPs', function () {
			const { privateKey } = makeKeypair();
			const words = encodeUintToWords(100, 7);
			const sig1 = signInvoice('lnbc', words, privateKey);
			const sig2 = signInvoice('lntb', words, privateKey);
			expect(sig1).to.not.deep.equal(sig2);
		});
	});

	// ─── Decoding (5D) ────────────────────────────────────────────────────

	describe('Decoding', function () {
		// Helper: encode an invoice then test decoding
		function encodeForDecode(opts?: Partial<IInvoiceCreationOptions>): {
			invoiceStr: string;
			options: IInvoiceCreationOptions;
			publicKey: Buffer;
		} {
			const { privateKey, publicKey } = makeKeypair();
			const options: IInvoiceCreationOptions = {
				network: Network.MAINNET,
				paymentHash: crypto.randomBytes(32),
				description: 'test payment',
				privateKey,
				timestamp: 1700000000,
				...opts
			};
			const invoiceStr = encode(options);
			return { invoiceStr, options, publicKey };
		}

		it('should decode a minimal invoice', function () {
			const { invoiceStr, options, publicKey } = encodeForDecode();
			const inv = decode(invoiceStr);
			expect(inv.network).to.equal(Network.MAINNET);
			expect(inv.paymentHash).to.deep.equal(options.paymentHash);
			expect(inv.description).to.equal('test payment');
			expect(inv.timestamp).to.equal(1700000000);
			expect(inv.recoveredPubkey).to.deep.equal(publicKey);
		});

		it('should decode invoice with amount (micro)', function () {
			const { invoiceStr, options } = encodeForDecode({
				amountMsat: 250_000_000n
			});
			const inv = decode(invoiceStr);
			expect(inv.amountMsat).to.equal(250_000_000n);
			expect(inv.paymentHash).to.deep.equal(options.paymentHash);
		});

		it('should decode invoice with amount (milli)', function () {
			const { invoiceStr } = encodeForDecode({ amountMsat: 100_000_000n });
			const inv = decode(invoiceStr);
			expect(inv.amountMsat).to.equal(100_000_000n);
		});

		it('should decode invoice with amount (nano)', function () {
			const { invoiceStr } = encodeForDecode({ amountMsat: 100n });
			const inv = decode(invoiceStr);
			expect(inv.amountMsat).to.equal(100n);
		});

		it('should decode invoice with amount (pico)', function () {
			const { invoiceStr } = encodeForDecode({ amountMsat: 1n });
			const inv = decode(invoiceStr);
			expect(inv.amountMsat).to.equal(1n);
		});

		it('should decode invoice with no amount', function () {
			const { invoiceStr } = encodeForDecode();
			const inv = decode(invoiceStr);
			expect(inv.amountMsat).to.be.undefined;
		});

		it('should decode invoice with payment_secret', function () {
			const secret = crypto.randomBytes(32);
			const { invoiceStr } = encodeForDecode({ paymentSecret: secret });
			const inv = decode(invoiceStr);
			expect(inv.paymentSecret).to.deep.equal(secret);
		});

		it('should decode invoice with description_hash instead of description', function () {
			const descHash = crypto
				.createHash('sha256')
				.update('long description')
				.digest();
			const { invoiceStr } = encodeForDecode({
				description: undefined,
				descriptionHash: descHash
			});
			const inv = decode(invoiceStr);
			expect(inv.description).to.be.undefined;
			expect(inv.descriptionHash).to.deep.equal(descHash);
		});

		it('should decode invoice with payee node key', function () {
			const { privateKey, publicKey } = makeKeypair();
			const { invoiceStr } = encodeForDecode({
				payeeNodeKey: publicKey,
				privateKey
			});
			const inv = decode(invoiceStr);
			expect(inv.payeeNodeKey).to.deep.equal(publicKey);
		});

		it('should decode invoice with expiry', function () {
			const { invoiceStr } = encodeForDecode({ expiry: 7200 });
			const inv = decode(invoiceStr);
			expect(inv.expiry).to.equal(7200);
		});

		it('should decode invoice with min_final_cltv_expiry', function () {
			const { invoiceStr } = encodeForDecode({ minFinalCltvExpiry: 144 });
			const inv = decode(invoiceStr);
			expect(inv.minFinalCltvExpiry).to.equal(144);
		});

		it('should decode invoice with fallback address (witness v0)', function () {
			const hash = crypto.randomBytes(20);
			const { invoiceStr } = encodeForDecode({
				fallbackAddress: { version: 0, hash }
			});
			const inv = decode(invoiceStr);
			expect(inv.fallbackAddress).to.not.be.undefined;
			expect(inv.fallbackAddress!.version).to.equal(0);
			expect(inv.fallbackAddress!.hash).to.deep.equal(hash);
		});

		it('should decode invoice with fallback address (witness v1)', function () {
			const hash = crypto.randomBytes(32);
			const { invoiceStr } = encodeForDecode({
				fallbackAddress: { version: 1, hash }
			});
			const inv = decode(invoiceStr);
			expect(inv.fallbackAddress!.version).to.equal(1);
			expect(inv.fallbackAddress!.hash).to.deep.equal(hash);
		});

		it('should decode invoice with routing hints', function () {
			const hop1: IRoutingHintHop = {
				pubkey: makeKeypair().publicKey,
				shortChannelId: Buffer.from('0102030405060708', 'hex'),
				feeBaseMsat: 1000,
				feeProportionalMillionths: 100,
				cltvExpiryDelta: 144
			};
			const hop2: IRoutingHintHop = {
				pubkey: makeKeypair().publicKey,
				shortChannelId: Buffer.from('1112131415161718', 'hex'),
				feeBaseMsat: 500,
				feeProportionalMillionths: 50,
				cltvExpiryDelta: 72
			};
			const { invoiceStr } = encodeForDecode({
				routingHints: [[hop1, hop2]]
			});
			const inv = decode(invoiceStr);
			expect(inv.routingHints).to.have.length(1);
			expect(inv.routingHints![0]).to.have.length(2);
			expect(inv.routingHints![0][0].pubkey).to.deep.equal(hop1.pubkey);
			expect(inv.routingHints![0][0].shortChannelId).to.deep.equal(
				hop1.shortChannelId
			);
			expect(inv.routingHints![0][0].feeBaseMsat).to.equal(1000);
			expect(inv.routingHints![0][0].feeProportionalMillionths).to.equal(100);
			expect(inv.routingHints![0][0].cltvExpiryDelta).to.equal(144);
			expect(inv.routingHints![0][1].pubkey).to.deep.equal(hop2.pubkey);
			expect(inv.routingHints![0][1].feeBaseMsat).to.equal(500);
		});

		it('should decode invoice with multiple routing hint routes', function () {
			const route1: IRoutingHintHop[] = [
				{
					pubkey: makeKeypair().publicKey,
					shortChannelId: Buffer.alloc(8, 0x01),
					feeBaseMsat: 100,
					feeProportionalMillionths: 10,
					cltvExpiryDelta: 40
				}
			];
			const route2: IRoutingHintHop[] = [
				{
					pubkey: makeKeypair().publicKey,
					shortChannelId: Buffer.alloc(8, 0x02),
					feeBaseMsat: 200,
					feeProportionalMillionths: 20,
					cltvExpiryDelta: 80
				}
			];
			const { invoiceStr } = encodeForDecode({
				routingHints: [route1, route2]
			});
			const inv = decode(invoiceStr);
			expect(inv.routingHints).to.have.length(2);
			expect(inv.routingHints![0][0].feeBaseMsat).to.equal(100);
			expect(inv.routingHints![1][0].feeBaseMsat).to.equal(200);
		});

		it('should decode invoice with feature bits', function () {
			const features = new FeatureFlags();
			features.setOptional(Feature.PAYMENT_SECRET);
			features.setOptional(Feature.BASIC_MPP);
			const { invoiceStr } = encodeForDecode({ featureBits: features });
			const inv = decode(invoiceStr);
			expect(inv.featureBits).to.not.be.undefined;
			expect(inv.featureBits!.hasFeature(Feature.PAYMENT_SECRET)).to.be.true;
			expect(inv.featureBits!.hasFeature(Feature.BASIC_MPP)).to.be.true;
			expect(inv.featureBits!.hasFeature(Feature.DATA_LOSS_PROTECT)).to.be
				.false;
		});

		it('should decode invoice with metadata', function () {
			const metadata = crypto.randomBytes(16);
			const { invoiceStr } = encodeForDecode({ metadata });
			const inv = decode(invoiceStr);
			expect(inv.metadata).to.deep.equal(metadata);
		});

		it('should decode case-insensitively (uppercase invoice)', function () {
			const { invoiceStr } = encodeForDecode();
			const upper = invoiceStr.toUpperCase();
			const inv = decode(upper);
			expect(inv.network).to.equal(Network.MAINNET);
			expect(inv.description).to.equal('test payment');
		});

		it('should decode invoice on testnet', function () {
			const { invoiceStr } = encodeForDecode({ network: Network.TESTNET });
			const inv = decode(invoiceStr);
			expect(inv.network).to.equal(Network.TESTNET);
		});

		it('should decode invoice on regtest', function () {
			const { invoiceStr } = encodeForDecode({
				network: Network.REGTEST,
				amountMsat: 50_000n
			});
			const inv = decode(invoiceStr);
			expect(inv.network).to.equal(Network.REGTEST);
			expect(inv.amountMsat).to.equal(50_000n);
		});

		it('should decode invoice on signet', function () {
			const { invoiceStr } = encodeForDecode({ network: Network.SIGNET });
			const inv = decode(invoiceStr);
			expect(inv.network).to.equal(Network.SIGNET);
		});

		it('should recover the correct public key from signature', function () {
			const { privateKey, publicKey } = makeKeypair();
			const invoiceStr = encode({
				network: Network.MAINNET,
				paymentHash: crypto.randomBytes(32),
				description: 'verify me',
				privateKey,
				timestamp: 1700000000
			});
			const inv = decode(invoiceStr);
			expect(inv.recoveredPubkey).to.deep.equal(publicKey);
		});

		it('should reject invoice missing payment_hash', function () {
			// Manually craft an invoice without payment_hash:
			// We'll test that our encoder rejects it, which exercises the validation
			const { privateKey } = makeKeypair();
			expect(() =>
				encode({
					network: Network.MAINNET,
					paymentHash: Buffer.alloc(0), // invalid
					description: 'test',
					privateKey
				})
			).to.throw('paymentHash must be 32 bytes');
		});

		it('should reject invoice with both description and description_hash', function () {
			const { privateKey } = makeKeypair();
			expect(() =>
				encode({
					network: Network.MAINNET,
					paymentHash: crypto.randomBytes(32),
					description: 'test',
					descriptionHash: crypto.randomBytes(32),
					privateKey
				})
			).to.throw('both description and descriptionHash');
		});

		it('should reject invoice with neither description nor description_hash', function () {
			const { privateKey } = makeKeypair();
			expect(() =>
				encode({
					network: Network.MAINNET,
					paymentHash: crypto.randomBytes(32),
					privateKey
				} as IInvoiceCreationOptions)
			).to.throw('either description or descriptionHash');
		});

		it('should have 65-byte signature', function () {
			const { invoiceStr } = encodeForDecode();
			const inv = decode(invoiceStr);
			expect(inv.signature).to.have.length(65);
		});
	});

	// ─── Encoding (5E) ────────────────────────────────────────────────────

	describe('Encoding', function () {
		it('should encode a minimal invoice', function () {
			const invoiceStr = encode(makeMinimalOptions({ timestamp: 1700000000 }));
			expect(invoiceStr).to.be.a('string');
			expect(invoiceStr.startsWith('lnbc1')).to.be.true;
		});

		it('should encode invoice with amount', function () {
			const invoiceStr = encode(
				makeMinimalOptions({
					amountMsat: 250_000_000n,
					timestamp: 1700000000
				})
			);
			expect(invoiceStr.startsWith('lnbc2500u1')).to.be.true;
		});

		it('should encode invoice on different networks', function () {
			const tbInvoice = encode(
				makeMinimalOptions({ network: Network.TESTNET, timestamp: 1700000000 })
			);
			expect(tbInvoice.startsWith('lntb1')).to.be.true;

			const bcrtInvoice = encode(
				makeMinimalOptions({ network: Network.REGTEST, timestamp: 1700000000 })
			);
			expect(bcrtInvoice.startsWith('lnbcrt1')).to.be.true;
		});

		it('should encode invoice with payment_secret', function () {
			const secret = crypto.randomBytes(32);
			const invoiceStr = encode(makeMinimalOptions({ paymentSecret: secret }));
			const inv = decode(invoiceStr);
			expect(inv.paymentSecret).to.deep.equal(secret);
		});

		it('should encode invoice with expiry', function () {
			const invoiceStr = encode(makeMinimalOptions({ expiry: 3600 }));
			const inv = decode(invoiceStr);
			expect(inv.expiry).to.equal(3600);
		});

		it('should encode invoice with min_final_cltv_expiry', function () {
			const invoiceStr = encode(makeMinimalOptions({ minFinalCltvExpiry: 72 }));
			const inv = decode(invoiceStr);
			expect(inv.minFinalCltvExpiry).to.equal(72);
		});

		it('should encode invoice with feature bits', function () {
			const features = new FeatureFlags();
			features.setOptional(Feature.PAYMENT_SECRET);
			features.setOptional(Feature.TLV_ONION);
			const invoiceStr = encode(makeMinimalOptions({ featureBits: features }));
			const inv = decode(invoiceStr);
			expect(inv.featureBits!.hasFeature(Feature.PAYMENT_SECRET)).to.be.true;
			expect(inv.featureBits!.hasFeature(Feature.TLV_ONION)).to.be.true;
		});

		it('should encode invoice with routing hints', function () {
			const hops: IRoutingHintHop[] = [
				{
					pubkey: makeKeypair().publicKey,
					shortChannelId: Buffer.from('0a0b0c0d0e0f0102', 'hex'),
					feeBaseMsat: 1000,
					feeProportionalMillionths: 200,
					cltvExpiryDelta: 40
				}
			];
			const invoiceStr = encode(makeMinimalOptions({ routingHints: [hops] }));
			const inv = decode(invoiceStr);
			expect(inv.routingHints).to.have.length(1);
			expect(inv.routingHints![0][0].feeBaseMsat).to.equal(1000);
		});

		it('should encode invoice with multiple routing hint routes', function () {
			const route1: IRoutingHintHop[] = [
				{
					pubkey: makeKeypair().publicKey,
					shortChannelId: Buffer.alloc(8, 1),
					feeBaseMsat: 100,
					feeProportionalMillionths: 10,
					cltvExpiryDelta: 40
				}
			];
			const route2: IRoutingHintHop[] = [
				{
					pubkey: makeKeypair().publicKey,
					shortChannelId: Buffer.alloc(8, 2),
					feeBaseMsat: 200,
					feeProportionalMillionths: 20,
					cltvExpiryDelta: 80
				}
			];
			const invoiceStr = encode(
				makeMinimalOptions({ routingHints: [route1, route2] })
			);
			const inv = decode(invoiceStr);
			expect(inv.routingHints).to.have.length(2);
		});

		it('should encode invoice with fallback address', function () {
			const hash = crypto.randomBytes(20);
			const invoiceStr = encode(
				makeMinimalOptions({
					fallbackAddress: { version: 0, hash }
				})
			);
			const inv = decode(invoiceStr);
			expect(inv.fallbackAddress!.version).to.equal(0);
			expect(inv.fallbackAddress!.hash).to.deep.equal(hash);
		});

		it('should encode invoice with metadata', function () {
			const metadata = crypto.randomBytes(32);
			const invoiceStr = encode(makeMinimalOptions({ metadata }));
			const inv = decode(invoiceStr);
			expect(inv.metadata).to.deep.equal(metadata);
		});

		it('should encode invoice with description_hash', function () {
			const descHash = crypto.createHash('sha256').update('coffee').digest();
			const invoiceStr = encode(
				makeMinimalOptions({
					description: undefined,
					descriptionHash: descHash
				})
			);
			const inv = decode(invoiceStr);
			expect(inv.descriptionHash).to.deep.equal(descHash);
			expect(inv.description).to.be.undefined;
		});

		it('should encode invoice with various amounts', function () {
			const amounts = [1n, 100n, 100_000n, 100_000_000n, 100_000_000_000n];
			for (const msat of amounts) {
				const invoiceStr = encode(makeMinimalOptions({ amountMsat: msat }));
				const inv = decode(invoiceStr);
				expect(inv.amountMsat).to.equal(msat);
			}
		});

		it('should encode invoice with no amount', function () {
			const invoiceStr = encode(makeMinimalOptions());
			const inv = decode(invoiceStr);
			expect(inv.amountMsat).to.be.undefined;
		});

		it('should reject missing payment_hash', function () {
			const { privateKey } = makeKeypair();
			expect(() =>
				encode({
					network: Network.MAINNET,
					paymentHash: Buffer.alloc(16), // wrong size
					description: 'test',
					privateKey
				})
			).to.throw('paymentHash must be 32 bytes');
		});

		it('should reject both description and description_hash', function () {
			expect(() =>
				encode(
					makeMinimalOptions({
						descriptionHash: crypto.randomBytes(32)
					})
				)
			).to.throw('both description and descriptionHash');
		});

		it('should reject neither description nor description_hash', function () {
			const { privateKey } = makeKeypair();
			expect(() =>
				encode({
					network: Network.MAINNET,
					paymentHash: crypto.randomBytes(32),
					privateKey
				} as IInvoiceCreationOptions)
			).to.throw('either description or descriptionHash');
		});
	});

	// ─── Round-Trip (Encode → Decode) ─────────────────────────────────────

	describe('Round-Trip', function () {
		it('should round-trip a minimal invoice', function () {
			const { privateKey, publicKey } = makeKeypair();
			const paymentHash = crypto.randomBytes(32);
			const invoiceStr = encode({
				network: Network.MAINNET,
				paymentHash,
				description: 'round trip test',
				privateKey,
				timestamp: 1700000000
			});
			const inv = decode(invoiceStr);
			expect(inv.network).to.equal(Network.MAINNET);
			expect(inv.paymentHash).to.deep.equal(paymentHash);
			expect(inv.description).to.equal('round trip test');
			expect(inv.timestamp).to.equal(1700000000);
			expect(inv.recoveredPubkey).to.deep.equal(publicKey);
		});

		it('should round-trip invoice with all optional fields', function () {
			const { privateKey, publicKey } = makeKeypair();
			const paymentHash = crypto.randomBytes(32);
			const paymentSecret = crypto.randomBytes(32);
			const metadata = crypto.randomBytes(16);
			const features = new FeatureFlags();
			features.setOptional(Feature.PAYMENT_SECRET);
			features.setOptional(Feature.BASIC_MPP);
			const hop: IRoutingHintHop = {
				pubkey: makeKeypair().publicKey,
				shortChannelId: Buffer.from('0102030405060708', 'hex'),
				feeBaseMsat: 1000,
				feeProportionalMillionths: 200,
				cltvExpiryDelta: 144
			};
			const fallbackHash = crypto.randomBytes(20);

			const invoiceStr = encode({
				network: Network.TESTNET,
				amountMsat: 250_000_000n,
				paymentHash,
				paymentSecret,
				description: 'all fields test',
				expiry: 7200,
				minFinalCltvExpiry: 144,
				featureBits: features,
				fallbackAddress: { version: 0, hash: fallbackHash },
				routingHints: [[hop]],
				metadata,
				payeeNodeKey: publicKey,
				privateKey,
				timestamp: 1700000000
			});

			const inv = decode(invoiceStr);
			expect(inv.network).to.equal(Network.TESTNET);
			expect(inv.amountMsat).to.equal(250_000_000n);
			expect(inv.paymentHash).to.deep.equal(paymentHash);
			expect(inv.paymentSecret).to.deep.equal(paymentSecret);
			expect(inv.description).to.equal('all fields test');
			expect(inv.expiry).to.equal(7200);
			expect(inv.minFinalCltvExpiry).to.equal(144);
			expect(inv.featureBits!.hasFeature(Feature.PAYMENT_SECRET)).to.be.true;
			expect(inv.featureBits!.hasFeature(Feature.BASIC_MPP)).to.be.true;
			expect(inv.fallbackAddress!.version).to.equal(0);
			expect(inv.fallbackAddress!.hash).to.deep.equal(fallbackHash);
			expect(inv.routingHints).to.have.length(1);
			expect(inv.routingHints![0][0].pubkey).to.deep.equal(hop.pubkey);
			expect(inv.routingHints![0][0].feeBaseMsat).to.equal(1000);
			expect(inv.routingHints![0][0].cltvExpiryDelta).to.equal(144);
			expect(inv.metadata).to.deep.equal(metadata);
			expect(inv.payeeNodeKey).to.deep.equal(publicKey);
			expect(inv.recoveredPubkey).to.deep.equal(publicKey);
		});

		it('should round-trip multiple invoices with different networks', function () {
			const networks = [
				Network.MAINNET,
				Network.TESTNET,
				Network.REGTEST,
				Network.SIGNET
			];
			for (const network of networks) {
				const { privateKey } = makeKeypair();
				const paymentHash = crypto.randomBytes(32);
				const invoiceStr = encode({
					network,
					amountMsat: 100_000n,
					paymentHash,
					description: `${network} test`,
					privateKey,
					timestamp: 1700000000
				});
				const inv = decode(invoiceStr);
				expect(inv.network).to.equal(network);
				expect(inv.amountMsat).to.equal(100_000n);
				expect(inv.paymentHash).to.deep.equal(paymentHash);
			}
		});

		it('should round-trip invoice with empty description', function () {
			const { privateKey } = makeKeypair();
			const invoiceStr = encode({
				network: Network.MAINNET,
				paymentHash: crypto.randomBytes(32),
				description: '',
				privateKey,
				timestamp: 1700000000
			});
			const inv = decode(invoiceStr);
			expect(inv.description).to.equal('');
		});

		it('should round-trip invoice with UTF-8 description', function () {
			const { privateKey } = makeKeypair();
			const description = 'Café ☕ Ñoño — 日本語';
			const invoiceStr = encode({
				network: Network.MAINNET,
				paymentHash: crypto.randomBytes(32),
				description,
				privateKey,
				timestamp: 1700000000
			});
			const inv = decode(invoiceStr);
			expect(inv.description).to.equal(description);
		});

		it('should round-trip invoice with large expiry', function () {
			const { privateKey } = makeKeypair();
			const invoiceStr = encode({
				network: Network.MAINNET,
				paymentHash: crypto.randomBytes(32),
				description: 'large expiry',
				expiry: 86400,
				privateKey,
				timestamp: 1700000000
			});
			const inv = decode(invoiceStr);
			expect(inv.expiry).to.equal(86400);
		});

		it('should round-trip invoice with zero expiry', function () {
			const { privateKey } = makeKeypair();
			const invoiceStr = encode({
				network: Network.MAINNET,
				paymentHash: crypto.randomBytes(32),
				description: 'zero expiry',
				expiry: 0,
				privateKey,
				timestamp: 1700000000
			});
			const inv = decode(invoiceStr);
			expect(inv.expiry).to.equal(0);
		});
	});

	// ─── Integration (5F) ─────────────────────────────────────────────────

	describe('Integration', function () {
		it('should export all types and functions from barrel', function () {
			// Types/enums
			expect(Network).to.be.an('object');
			expect(TagType).to.be.an('object');
			expect(Network.MAINNET).to.equal('bc');
			expect(TagType.PAYMENT_HASH).to.equal(1);

			// Constants
			expect(DEFAULT_EXPIRY).to.equal(3600);
			expect(DEFAULT_MIN_FINAL_CLTV_EXPIRY).to.equal(40);
			expect(BECH32_MAX_LIMIT).to.equal(65535);
			expect(TIMESTAMP_WORDS).to.equal(7);
			expect(SIGNATURE_WORDS).to.equal(104);
			expect(ROUTING_HOP_BYTES).to.equal(51);

			// Functions
			expect(encode).to.be.a('function');
			expect(decode).to.be.a('function');
			expect(msatToHrpAmount).to.be.a('function');
			expect(hrpAmountToMsat).to.be.a('function');
			expect(parseHrp).to.be.a('function');
			expect(buildHrp).to.be.a('function');
			expect(wordsToBuffer).to.be.a('function');
			expect(bufferToWords).to.be.a('function');
			expect(encodeUintToWords).to.be.a('function');
			expect(decodeUintFromWords).to.be.a('function');
			expect(encodeTaggedField).to.be.a('function');
			expect(decodeTaggedField).to.be.a('function');
			expect(signInvoice).to.be.a('function');
			expect(verifyInvoice).to.be.a('function');
			expect(computeSigningHash).to.be.a('function');
			expect(ensureHmac).to.be.a('function');
		});

		it('should be accessible via lightning barrel export', async function () {
			const lightning = await import('../../src/lightning');
			expect(lightning.invoice).to.be.an('object');
			expect(lightning.invoice.encode).to.be.a('function');
			expect(lightning.invoice.decode).to.be.a('function');
			expect(lightning.invoice.Network).to.be.an('object');
		});

		it('should handle multi-invoice scenario', function () {
			const { privateKey, publicKey } = makeKeypair();
			const invoices: string[] = [];

			// Create 5 invoices with different amounts
			for (let i = 0; i < 5; i++) {
				const invoiceStr = encode({
					network: Network.MAINNET,
					amountMsat: BigInt((i + 1) * 100000),
					paymentHash: crypto.randomBytes(32),
					description: `Invoice #${i + 1}`,
					privateKey,
					timestamp: 1700000000 + i
				});
				invoices.push(invoiceStr);
			}

			// Decode all and verify
			for (let i = 0; i < 5; i++) {
				const inv = decode(invoices[i]);
				expect(inv.amountMsat).to.equal(BigInt((i + 1) * 100000));
				expect(inv.description).to.equal(`Invoice #${i + 1}`);
				expect(inv.timestamp).to.equal(1700000000 + i);
				expect(inv.recoveredPubkey).to.deep.equal(publicKey);
			}
		});
	});
});
