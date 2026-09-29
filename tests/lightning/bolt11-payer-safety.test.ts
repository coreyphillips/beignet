/**
 * BOLT 11 payer/decoder safety regression tests.
 *
 * Covers three audit findings:
 * - S-4.M6: a p/h/s/n field whose data_length is not exactly 52/52/52/53
 *   words must be skipped, never truncated to the expected size.
 * - S-4.M7: the payer must validate the recovered signing key against the
 *   `n` field, must not pay invoices carrying unknown even feature bits,
 *   and must not pay secretless invoices.
 * - S-4.M8 lives in mpp-sending.test.ts (basic_mpp gate on the MPP fallback).
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { bech32 } from 'bech32';
import { decode as decodeInvoice } from '../../src/lightning/invoice/decode';
import { encode as encodeInvoice } from '../../src/lightning/invoice/encode';
import {
	TagType,
	Network,
	BECH32_MAX_LIMIT,
	TIMESTAMP_WORDS
} from '../../src/lightning/invoice/types';
import {
	bufferToWords,
	encodeUintToWords,
	encodeTaggedField
} from '../../src/lightning/invoice/words';
import { signInvoice } from '../../src/lightning/invoice/signing';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	INodeConfig,
	InvalidRequestError,
	LightningErrorCode,
	LightningPaymentError
} from '../../src/lightning/node/types';
import {
	DEFAULT_CHANNEL_CONFIG,
	REGTEST_CHAIN_HASH,
	TESTNET_CHAIN_HASH
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';
import { IOffer } from '../../src/lightning/offer/types';

// ─────────────── Helpers ───────────────

function makeKey(label: string): Buffer {
	return crypto.createHash('sha256').update(label).digest();
}

/**
 * Hand-build a signed regtest invoice from raw tagged fields so we can
 * produce field lengths the normal encoder refuses to emit.
 */
function craftInvoice(
	fields: Array<{ type: number; dataWords: number[] }>,
	privateKey: Buffer,
	hrp = 'lnbcrt'
): string {
	const dataWords: number[] = encodeUintToWords(
		Math.floor(Date.now() / 1000),
		TIMESTAMP_WORDS
	);
	for (const f of fields) {
		dataWords.push(...encodeTaggedField(f.type, f.dataWords));
	}
	const sigBytes = signInvoice(hrp, dataWords, privateKey);
	return bech32.encode(
		hrp,
		[...dataWords, ...bufferToWords(sigBytes)],
		BECH32_MAX_LIMIT
	);
}

function descriptionField(): { type: number; dataWords: number[] } {
	return {
		type: TagType.DESCRIPTION,
		dataWords: bufferToWords(Buffer.from('test', 'utf8'))
	};
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		keys.push(
			crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from([i]))
				.digest()
		);
	}
	return {
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

function makeNodeConfig(label: string): INodeConfig {
	const seed = makeKey(`payer-safety-${label}`);
	return {
		nodePrivateKey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from('node-identity'))
			.digest(),
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeKey(`payer-safety-pcs-${label}`),
		fundingPrivkey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([0]))
			.digest()
	};
}

// ─────────────── S-4.M6: over-length fixed fields are skipped ───────────────

describe('BOLT 11 payer safety', function () {
	const payeeKey = makeKey('payee');

	describe('over-length p/h/s/n fields (S-4.M6)', function () {
		it('skips an over-length payment_hash instead of truncating it', function () {
			// 33-byte "hash" → 53 words instead of the required 52
			const inv = craftInvoice(
				[
					{
						type: TagType.PAYMENT_HASH,
						dataWords: bufferToWords(crypto.randomBytes(33))
					},
					descriptionField()
				],
				payeeKey
			);
			// The malformed p field is skipped, leaving no payment hash at all
			expect(() => decodeInvoice(inv)).to.throw(
				'missing required payment_hash'
			);
		});

		it('skips an over-length payment_secret instead of truncating it', function () {
			const inv = craftInvoice(
				[
					{
						type: TagType.PAYMENT_HASH,
						dataWords: bufferToWords(crypto.randomBytes(32))
					},
					{
						type: TagType.PAYMENT_SECRET,
						dataWords: bufferToWords(crypto.randomBytes(33))
					},
					descriptionField()
				],
				payeeKey
			);
			const decoded = decodeInvoice(inv);
			expect(decoded.paymentSecret).to.equal(undefined);
			expect(
				decoded.unknownTags?.some((t) => t.type === TagType.PAYMENT_SECRET)
			).to.equal(true);
		});

		it('skips an under-length description_hash and an over-length payee pubkey', function () {
			const inv = craftInvoice(
				[
					{
						type: TagType.PAYMENT_HASH,
						dataWords: bufferToWords(crypto.randomBytes(32))
					},
					descriptionField(),
					{
						type: TagType.DESCRIPTION_HASH,
						dataWords: bufferToWords(crypto.randomBytes(31))
					},
					{
						type: TagType.PAYEE_PUBKEY,
						dataWords: bufferToWords(crypto.randomBytes(34))
					}
				],
				payeeKey
			);
			const decoded = decodeInvoice(inv);
			expect(decoded.descriptionHash).to.equal(undefined);
			expect(decoded.payeeNodeKey).to.equal(undefined);
		});

		it('still decodes exact-length fields as before', function () {
			const paymentHash = crypto.randomBytes(32);
			const paymentSecret = crypto.randomBytes(32);
			const inv = encodeInvoice({
				network: Network.REGTEST,
				paymentHash,
				paymentSecret,
				description: 'exact lengths',
				amountMsat: 1000n,
				payeeNodeKey: getPublicKey(payeeKey),
				privateKey: payeeKey
			});
			const decoded = decodeInvoice(inv);
			expect(decoded.paymentHash.equals(paymentHash)).to.equal(true);
			expect(decoded.paymentSecret?.equals(paymentSecret)).to.equal(true);
			expect(decoded.payeeNodeKey?.equals(getPublicKey(payeeKey))).to.equal(
				true
			);
		});
	});

	// ─────────────── S-4.M7: n field must match the signing key ───────────────

	describe('n field signature validation (S-4.M7)', function () {
		it('rejects an invoice whose n field differs from the signing key', function () {
			const otherKey = makeKey('someone-else');
			const inv = encodeInvoice({
				network: Network.REGTEST,
				paymentHash: crypto.randomBytes(32),
				paymentSecret: crypto.randomBytes(32),
				description: 'wrong signer',
				amountMsat: 1000n,
				// n claims the payee is otherKey, but payeeKey signs
				payeeNodeKey: getPublicKey(otherKey),
				privateKey: payeeKey
			});
			expect(() => decodeInvoice(inv)).to.throw(
				'does not match the payee node id'
			);
		});

		it('accepts an invoice whose n field matches the signing key', function () {
			const inv = encodeInvoice({
				network: Network.REGTEST,
				paymentHash: crypto.randomBytes(32),
				paymentSecret: crypto.randomBytes(32),
				description: 'right signer',
				amountMsat: 1000n,
				payeeNodeKey: getPublicKey(payeeKey),
				privateKey: payeeKey
			});
			expect(
				decodeInvoice(inv).payeeNodeKey?.equals(getPublicKey(payeeKey))
			).to.equal(true);
		});
	});

	// ─────────── S-4.M7: unknown even feature bits fail the payment ───────────

	describe('payer feature/secret checks (S-4.M7)', function () {
		it('refuses to pay an invoice requiring an unknown even feature bit', function () {
			const node = new LightningNode(makeNodeConfig('payer'));
			node.on('error', () => {});

			const features = FeatureFlags.empty();
			features.setCompulsory(Feature.TLV_ONION);
			features.setCompulsory(Feature.PAYMENT_SECRET);
			features.setBit(100); // unknown even (compulsory) bit

			const inv = encodeInvoice({
				network: Network.REGTEST,
				paymentHash: crypto.randomBytes(32),
				paymentSecret: crypto.randomBytes(32),
				description: 'unknown even feature',
				amountMsat: 1000n,
				payeeNodeKey: getPublicKey(payeeKey),
				privateKey: payeeKey,
				featureBits: features
			});
			expect(() => node.sendPayment(inv)).to.throw('unknown feature bit 100');
			node.destroy();
		});

		it('ignores unknown odd feature bits', function () {
			const node = new LightningNode(makeNodeConfig('payer-odd'));
			node.on('error', () => {});

			const features = FeatureFlags.empty();
			features.setCompulsory(Feature.TLV_ONION);
			features.setCompulsory(Feature.PAYMENT_SECRET);
			features.setBit(101); // unknown odd (optional) bit — fine to ignore

			const inv = encodeInvoice({
				network: Network.REGTEST,
				paymentHash: crypto.randomBytes(32),
				paymentSecret: crypto.randomBytes(32),
				description: 'unknown odd feature',
				amountMsat: 1000n,
				payeeNodeKey: getPublicKey(payeeKey),
				privateKey: payeeKey,
				featureBits: features
			});
			// Passes the feature gate; fails later for lack of any route
			expect(() => node.sendPayment(inv)).to.throw('No route found');
			node.destroy();
		});
	});

	// ───────── Issue #1036: case, network and zero-amount leniencies ─────────

	describe('case, network and zero amount (issue #1036)', function () {
		function regtestInvoice(amountMsat?: bigint): string {
			return encodeInvoice({
				network: Network.REGTEST,
				paymentHash: crypto.randomBytes(32),
				paymentSecret: crypto.randomBytes(32),
				description: 'issue 1036',
				amountMsat,
				payeeNodeKey: getPublicKey(payeeKey),
				privateKey: payeeKey
			});
		}

		it('rejects a string that mixes upper and lower case', function () {
			const inv = regtestInvoice(1000n);
			const mixed = inv.slice(0, 20).toUpperCase() + inv.slice(20);
			expect(() => decodeInvoice(mixed)).to.throw('Mixed-case');
			// A single case either way still decodes.
			expect(decodeInvoice(inv.toUpperCase()).network).to.equal(
				Network.REGTEST
			);
		});

		it('rejects a zero amount in the HRP', function () {
			for (const hrp of ['lnbcrt0m', 'lnbcrt0', 'lnbcrt0p']) {
				const inv = craftInvoice(
					[
						{
							type: TagType.PAYMENT_HASH,
							dataWords: bufferToWords(crypto.randomBytes(32))
						},
						descriptionField()
					],
					payeeKey,
					hrp
				);
				expect(() => decodeInvoice(inv), hrp).to.throw(
					'Amount must be positive'
				);
			}
		});

		it('refuses to pay an invoice for another network', function () {
			const node = new LightningNode(makeNodeConfig('payer-network'));
			node.on('error', () => {});
			const inv = encodeInvoice({
				network: Network.TESTNET,
				paymentHash: crypto.randomBytes(32),
				paymentSecret: crypto.randomBytes(32),
				description: 'testnet invoice',
				amountMsat: 1000n,
				payeeNodeKey: getPublicKey(payeeKey),
				privateKey: payeeKey
			});
			let caught: unknown;
			try {
				node.sendPayment(inv);
			} catch (err) {
				caught = err;
			}
			expect(caught).to.be.instanceOf(LightningPaymentError);
			expect((caught as LightningPaymentError).code).to.equal(
				LightningErrorCode.INVALID_INVOICE
			);
			expect((caught as Error).message).to.contain('network "tb"');
			expect(node.listPayments()).to.have.length(0);
			node.destroy();
		});

		it('refuses a zero amountMsat for an amountless invoice', function () {
			const node = new LightningNode(makeNodeConfig('payer-zero'));
			node.on('error', () => {});
			expect(() =>
				node.sendPayment(regtestInvoice(), undefined, undefined, 0n)
			).to.throw('amountMsat must be positive');
			expect(node.listPayments()).to.have.length(0);
			node.destroy();
		});

		it("refuses an offer whose offer_chains do not include the node's chain", async function () {
			const node = new LightningNode(makeNodeConfig('payer-offer'));
			node.on('error', () => {});
			const offerManager = node.getOfferManager();
			const requested: Array<{ chain?: Buffer } | undefined> = [];
			offerManager.requestInvoice = (_offer, options): Promise<never> => {
				requested.push(options);
				return Promise.reject(new Error('not sent in this test'));
			};
			const offer = (chains?: Buffer[]): IOffer => ({
				offerId: crypto.randomBytes(32),
				description: 'widget',
				amount: 1000n,
				...(chains && { chains })
			});

			// No offer_chains means bitcoin mainnet.
			for (const chains of [undefined, [TESTNET_CHAIN_HASH]]) {
				const err = await node.requestInvoice(offer(chains)).catch((e) => e);
				expect(err).to.be.instanceOf(InvalidRequestError);
				expect(err.message).to.contain('offer_chains');
			}
			expect(requested).to.have.length(0);

			// Listed, though not first: the request names our chain.
			await node
				.requestInvoice(offer([TESTNET_CHAIN_HASH, REGTEST_CHAIN_HASH]))
				.catch(() => undefined);
			expect(requested).to.have.length(1);
			expect(requested[0]?.chain?.equals(REGTEST_CHAIN_HASH)).to.equal(true);
			node.destroy();
		});
	});
});
