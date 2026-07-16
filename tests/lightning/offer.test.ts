/**
 * BOLT 12: Offers Test Suite
 *
 * Tests TLV encode/decode, merkle root computation, Schnorr signing,
 * bech32m encode/decode round-trips, OfferManager, and end-to-end flows.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { IBlindedPath } from '../../src/lightning/onion/blinded-path';
import {
	// Types
	IOffer,
	IInvoiceRequest,
	IBolt12Invoice,
	IInvoiceError,
	// TLV
	OfferTlvType,
	InvoiceRequestTlvType,
	InvoiceTlvType,
	InvoiceErrorTlvType,
	encodeOfferTlv,
	decodeOfferTlv,
	encodeInvoiceRequestTlv,
	decodeInvoiceRequestTlv,
	encodeInvoiceTlv,
	decodeInvoiceTlv,
	encodeInvoiceErrorTlv,
	decodeInvoiceErrorTlv,
	encodeTruncatedU64,
	decodeTruncatedU64,
	getTlvRecords,
	getTlvRecordsForSigning,
	encodeTlvRecordRaw,
	// Merkle
	computeMerkleRoot,
	computeMerkleRootFromRecords,
	computeSignatureHash,
	computeOfferId,
	taggedHash,
	// Schnorr
	schnorrSign,
	schnorrVerify,
	toXOnlyPubkey,
	xOnlyPubkeyFromPrivkey,
	// Encode
	encodeOffer,
	encodeInvoiceRequest,
	encodeBolt12Invoice,
	// Decode
	decodeOffer,
	decodeInvoiceRequest,
	decodeBolt12Invoice,
	detectBolt12Type,
	// OfferManager
	OfferManager,
	TLV_INVOICE_REQUEST,
	TLV_INVOICE,
	TLV_INVOICE_ERROR
} from '../../src/lightning/offer';
import { ITlvRecord } from '../../src/lightning/message/tlv';
import { OnionMessageManager } from '../../src/lightning/onion-message/manager';
import { findRouteToBlindedPath } from '../../src/lightning/gossip/pathfinding';
import { NetworkGraph } from '../../src/lightning/gossip/network-graph';
import { BITCOIN_CHAIN_HASH } from '../../src/lightning/channel/types';

describe('BOLT 12: Offers', () => {
	// ── Test Fixtures ───────────────────────────────────────────────

	const privkey1 = crypto.randomBytes(32);
	const pubkey1 = getPublicKey(privkey1);
	const privkey2 = crypto.randomBytes(32);
	const pubkey2 = getPublicKey(privkey2);

	function makeTestBlindedPath(): IBlindedPath {
		return {
			introductionNodeId: pubkey1,
			blindingPoint: pubkey2,
			blindedHops: [
				{
					blindedNodeId: getPublicKey(crypto.randomBytes(32)),
					encryptedData: crypto.randomBytes(32)
				}
			]
		};
	}

	// Build a BOLT 12 invoice_request TLV signed by pubkey2/privkey2, with the
	// required invreq_metadata. handleInvoiceRequest now rejects unsigned requests.
	function makeSignedRequestTlv(
		fields: Partial<IInvoiceRequest>,
		offer?: IOffer
	): Buffer {
		const request: IInvoiceRequest = {
			payerKey: pubkey2,
			offerId: offer ? offer.offerId : Buffer.alloc(32),
			metadata: crypto.randomBytes(16),
			...fields
		};
		const offerTlv = offer ? encodeOfferTlv(offer) : undefined;
		const unsigned = encodeInvoiceRequestTlv(request, offerTlv);
		const merkleRoot = computeMerkleRootFromRecords(getTlvRecords(unsigned));
		const sigHash = computeSignatureHash(
			'lightninginvoice_requestsignature',
			merkleRoot
		);
		request.signature = schnorrSign(sigHash, privkey2);
		return encodeInvoiceRequestTlv(request, offerTlv);
	}

	// ── Truncated U64 ───────────────────────────────────────────────

	describe('Truncated U64 encoding', () => {
		it('should encode 0 as empty buffer', () => {
			const encoded = encodeTruncatedU64(0n);
			expect(encoded.length).to.equal(0);
		});

		it('should decode empty buffer as 0', () => {
			const decoded = decodeTruncatedU64(Buffer.alloc(0));
			expect(decoded).to.equal(0n);
		});

		it('should round-trip small values', () => {
			const val = 42n;
			const encoded = encodeTruncatedU64(val);
			expect(encoded.length).to.equal(1);
			expect(encoded[0]).to.equal(42);
			const decoded = decodeTruncatedU64(encoded);
			expect(decoded).to.equal(val);
		});

		it('should round-trip 256', () => {
			const val = 256n;
			const encoded = encodeTruncatedU64(val);
			expect(encoded.length).to.equal(2);
			const decoded = decodeTruncatedU64(encoded);
			expect(decoded).to.equal(val);
		});

		it('should round-trip large values', () => {
			const val = 1_000_000_000n;
			const encoded = encodeTruncatedU64(val);
			const decoded = decodeTruncatedU64(encoded);
			expect(decoded).to.equal(val);
		});

		it('should round-trip max u64', () => {
			const val = 0xffffffffffffffffn;
			const encoded = encodeTruncatedU64(val);
			expect(encoded.length).to.equal(8);
			const decoded = decodeTruncatedU64(encoded);
			expect(decoded).to.equal(val);
		});
	});

	// ── Offer TLV Encode/Decode ─────────────────────────────────────

	describe('Offer TLV encode/decode', () => {
		it('should encode and decode minimal offer', () => {
			const offer: IOffer = {
				offerId: Buffer.alloc(32),
				description: 'test offer',
				issuerId: pubkey1
			};
			const tlvData = encodeOfferTlv(offer);
			const { offer: decoded } = decodeOfferTlv(tlvData);
			expect(decoded.description).to.equal('test offer');
			expect(decoded.issuerId).to.not.be.undefined;
			expect(decoded.issuerId!.equals(pubkey1)).to.be.true;
		});

		it('should encode and decode offer with amount', () => {
			const offer: IOffer = {
				offerId: Buffer.alloc(32),
				description: 'pay me',
				amount: 50_000n,
				issuerId: pubkey1
			};
			const tlvData = encodeOfferTlv(offer);
			const { offer: decoded } = decodeOfferTlv(tlvData);
			expect(decoded.amount).to.equal(50_000n);
		});

		it('should encode and decode offer with all fields', () => {
			const chainHash = crypto.randomBytes(32);
			const offer: IOffer = {
				offerId: Buffer.alloc(32),
				description: 'full offer',
				amount: 100_000n,
				issuer: 'Test Issuer',
				features: Buffer.from([0x01, 0x02]),
				paths: [makeTestBlindedPath()],
				issuerId: pubkey1,
				quantityMax: 10n,
				absoluteExpiry: BigInt(Math.floor(Date.now() / 1000) + 3600),
				chains: [chainHash],
				metadata: Buffer.from('metadata123')
			};
			const tlvData = encodeOfferTlv(offer);
			const { offer: decoded } = decodeOfferTlv(tlvData);
			expect(decoded.description).to.equal('full offer');
			expect(decoded.amount).to.equal(100_000n);
			expect(decoded.issuer).to.equal('Test Issuer');
			expect(decoded.features).to.not.be.undefined;
			expect(decoded.features!.equals(Buffer.from([0x01, 0x02]))).to.be.true;
			expect(decoded.paths).to.have.length(1);
			expect(decoded.issuerId!.equals(pubkey1)).to.be.true;
			expect(decoded.quantityMax).to.equal(10n);
			expect(decoded.absoluteExpiry).to.not.be.undefined;
			expect(decoded.chains).to.have.length(1);
			expect(decoded.chains![0].equals(chainHash)).to.be.true;
			expect(decoded.metadata!.toString()).to.equal('metadata123');
		});

		it('should throw on missing description', () => {
			// Manually create TLV without description
			const records: ITlvRecord[] = [
				{ type: BigInt(OfferTlvType.ISSUER_ID), value: pubkey1 }
			];
			const { encodeTlvStream } = require('../../src/lightning/message/tlv');
			const data = encodeTlvStream(records);
			expect(() => decodeOfferTlv(data)).to.throw(
				'missing required description'
			);
		});
	});

	// ── Invoice Request TLV Encode/Decode ───────────────────────────

	describe('Invoice Request TLV encode/decode', () => {
		it('should encode and decode minimal invoice request', () => {
			const request: IInvoiceRequest = {
				payerKey: pubkey2,
				offerId: Buffer.alloc(32)
			};
			const tlvData = encodeInvoiceRequestTlv(request);
			const { request: decoded } = decodeInvoiceRequestTlv(tlvData);
			expect(decoded.payerKey.equals(pubkey2)).to.be.true;
		});

		it('should encode and decode invoice request with amount', () => {
			const request: IInvoiceRequest = {
				payerKey: pubkey2,
				offerId: Buffer.alloc(32),
				amount: 75_000n
			};
			const tlvData = encodeInvoiceRequestTlv(request);
			const { request: decoded } = decodeInvoiceRequestTlv(tlvData);
			expect(decoded.amount).to.equal(75_000n);
		});

		it('should encode and decode invoice request with all fields', () => {
			const request: IInvoiceRequest = {
				payerKey: pubkey2,
				offerId: Buffer.alloc(32),
				amount: 75_000n,
				features: Buffer.from([0x01]),
				quantity: 3n,
				chain: crypto.randomBytes(32),
				payerNote: 'for services',
				metadata: Buffer.from('payer-metadata')
			};
			const tlvData = encodeInvoiceRequestTlv(request);
			const { request: decoded } = decodeInvoiceRequestTlv(tlvData);
			expect(decoded.amount).to.equal(75_000n);
			expect(decoded.quantity).to.equal(3n);
			expect(decoded.payerNote).to.equal('for services');
			expect(decoded.metadata!.toString()).to.equal('payer-metadata');
		});

		it('should compute offerId from mirrored offer records on decode', () => {
			const offer: IOffer = {
				offerId: Buffer.alloc(32),
				description: 'offerId decode test',
				issuerId: pubkey1,
				amount: 12_345n
			};
			const offerTlvData = encodeOfferTlv(offer);
			const expectedOfferId = computeOfferId(getTlvRecords(offerTlvData));

			const request: IInvoiceRequest = {
				payerKey: pubkey2,
				offerId: expectedOfferId
			};
			const tlvData = encodeInvoiceRequestTlv(request, offerTlvData);
			const { request: decoded } = decodeInvoiceRequestTlv(tlvData);
			expect(decoded.offerId.equals(expectedOfferId)).to.be.true;
		});

		it('should return zero offerId when no offer records are mirrored', () => {
			const request: IInvoiceRequest = {
				payerKey: pubkey2,
				offerId: Buffer.alloc(32)
			};
			const tlvData = encodeInvoiceRequestTlv(request);
			const { request: decoded } = decodeInvoiceRequestTlv(tlvData);
			expect(decoded.offerId.equals(Buffer.alloc(32))).to.be.true;
		});

		it('should include offer TLV data when provided', () => {
			const offer: IOffer = {
				offerId: Buffer.alloc(32),
				description: 'test',
				issuerId: pubkey1
			};
			const offerTlv = encodeOfferTlv(offer);

			const request: IInvoiceRequest = {
				payerKey: pubkey2,
				offerId: Buffer.alloc(32)
			};
			const tlvData = encodeInvoiceRequestTlv(request, offerTlv);
			const records = getTlvRecords(tlvData);

			// Should contain both offer fields and request fields
			const types = records.map((r) => Number(r.type));
			expect(types).to.include(OfferTlvType.DESCRIPTION);
			expect(types).to.include(InvoiceRequestTlvType.PAYER_KEY);
		});
	});

	// ── Invoice TLV Encode/Decode ───────────────────────────────────

	describe('Invoice TLV encode/decode', () => {
		it('should encode and decode minimal invoice', () => {
			const paymentHash = crypto.randomBytes(32);
			const invoice: IBolt12Invoice = {
				paymentHash,
				amount: 100_000n,
				description: 'test',
				createdAt: BigInt(Math.floor(Date.now() / 1000)),
				nodeId: pubkey1
			};
			const tlvData = encodeInvoiceTlv(invoice);
			const { invoice: decoded } = decodeInvoiceTlv(tlvData);
			expect(decoded.paymentHash.equals(paymentHash)).to.be.true;
			expect(decoded.amount).to.equal(100_000n);
			expect(decoded.nodeId.equals(pubkey1)).to.be.true;
		});

		it('should encode and decode invoice with paths', () => {
			const invoice: IBolt12Invoice = {
				paymentHash: crypto.randomBytes(32),
				amount: 200_000n,
				description: 'with paths',
				createdAt: BigInt(Math.floor(Date.now() / 1000)),
				nodeId: pubkey1,
				paths: [makeTestBlindedPath()]
			};
			const tlvData = encodeInvoiceTlv(invoice);
			const { invoice: decoded } = decodeInvoiceTlv(tlvData);
			expect(decoded.paths).to.have.length(1);
			expect(decoded.paths![0].blindedHops).to.have.length(1);
		});

		it('should encode and decode invoice with relative expiry', () => {
			const invoice: IBolt12Invoice = {
				paymentHash: crypto.randomBytes(32),
				amount: 100_000n,
				description: 'with expiry',
				createdAt: BigInt(Math.floor(Date.now() / 1000)),
				relativeExpiry: 7200,
				nodeId: pubkey1
			};
			const tlvData = encodeInvoiceTlv(invoice);
			const { invoice: decoded } = decodeInvoiceTlv(tlvData);
			expect(decoded.relativeExpiry).to.equal(7200);
		});

		it('should encode and decode invoice with signature', () => {
			const invoice: IBolt12Invoice = {
				paymentHash: crypto.randomBytes(32),
				amount: 100_000n,
				description: 'signed',
				createdAt: BigInt(Math.floor(Date.now() / 1000)),
				nodeId: pubkey1,
				signature: crypto.randomBytes(64)
			};
			const tlvData = encodeInvoiceTlv(invoice);
			const { invoice: decoded } = decodeInvoiceTlv(tlvData);
			expect(decoded.signature).to.not.be.undefined;
			expect(decoded.signature!.length).to.equal(64);
		});

		it('should throw on missing payment_hash', () => {
			// Manually construct TLV without payment_hash
			const records: ITlvRecord[] = [
				{
					type: BigInt(InvoiceTlvType.CREATED_AT),
					value: encodeTruncatedU64(BigInt(Date.now()))
				},
				{
					type: BigInt(InvoiceTlvType.AMOUNT),
					value: encodeTruncatedU64(1000n)
				},
				{ type: BigInt(InvoiceTlvType.NODE_ID), value: pubkey1 }
			];
			const { encodeTlvStream } = require('../../src/lightning/message/tlv');
			const data = encodeTlvStream(records);
			expect(() => decodeInvoiceTlv(data)).to.throw(
				'missing required payment_hash'
			);
		});
	});

	// ── Invoice Error TLV ───────────────────────────────────────────

	describe('Invoice Error TLV encode/decode', () => {
		it('should encode and decode error with message only', () => {
			const err: IInvoiceError = { error: 'something went wrong' };
			const data = encodeInvoiceErrorTlv(err);
			const decoded = decodeInvoiceErrorTlv(data);
			expect(decoded.error).to.equal('something went wrong');
			expect(decoded.erroneousField).to.be.undefined;
			expect(decoded.suggestedValue).to.be.undefined;
		});

		it('should encode and decode error with field and suggested value', () => {
			const err: IInvoiceError = {
				error: 'invalid amount',
				erroneousField: BigInt(OfferTlvType.AMOUNT),
				suggestedValue: encodeTruncatedU64(50_000n)
			};
			const data = encodeInvoiceErrorTlv(err);
			const decoded = decodeInvoiceErrorTlv(data);
			expect(decoded.error).to.equal('invalid amount');
			expect(decoded.erroneousField).to.equal(BigInt(OfferTlvType.AMOUNT));
			expect(decoded.suggestedValue).to.not.be.undefined;
		});

		it('should throw on missing error field', () => {
			const records: ITlvRecord[] = [
				{
					type: BigInt(InvoiceErrorTlvType.ERRONEOUS_FIELD),
					value: Buffer.from([8])
				}
			];
			const { encodeTlvStream } = require('../../src/lightning/message/tlv');
			const data = encodeTlvStream(records);
			expect(() => decodeInvoiceErrorTlv(data)).to.throw(
				'missing required error'
			);
		});
	});

	// ── Merkle Root Computation ─────────────────────────────────────

	describe('Merkle root computation (BOLT 12)', () => {
		// Known-answer vectors from LDK's BOLT 12 merkle tests. The tree
		// interleaves an "LnNonce" leaf per TLV; matching these confirms the
		// construction is byte-identical to CLN/eclair/LDK.
		it('matches the LDK single-record vector', () => {
			const root = computeMerkleRoot([Buffer.from('010203e8', 'hex')]);
			expect(root.toString('hex')).to.equal(
				'b013756c8fee86503a0b4abdab4cddeb1af5d344ca6fc2fa8b6c08938caa6f93'
			);
		});

		it('matches the LDK two-record vector', () => {
			const root = computeMerkleRoot([
				Buffer.from('010203e8', 'hex'),
				Buffer.from('02080000010000020003', 'hex')
			]);
			expect(root.toString('hex')).to.equal(
				'c3774abbf4815aa54ccaa026bff6581f01f3be5fe814c620a252534f434bc0d1'
			);
		});

		it('excludes the signature record (type 240) from the tree', () => {
			const withoutSig = computeMerkleRoot([Buffer.from('010203e8', 'hex')]);
			const withSig = computeMerkleRoot([
				Buffer.from('010203e8', 'hex'),
				// type 240 (0xf0), len 64, value — the signature field.
				Buffer.concat([Buffer.from('f040', 'hex'), Buffer.alloc(64, 0xab)])
			]);
			expect(withSig.equals(withoutSig)).to.be.true;
		});

		it('should throw for empty records', () => {
			expect(() => computeMerkleRoot([])).to.throw('empty');
		});

		it('should compute tagged hash correctly', () => {
			const data = Buffer.from('test');
			const hash = taggedHash('TestTag', data);
			expect(hash.length).to.equal(32);
		});

		it('should compute signature hash', () => {
			const merkleRoot = crypto.randomBytes(32);
			const sigHash = computeSignatureHash('lightning', merkleRoot);
			expect(sigHash.length).to.equal(32);
		});

		it('should compute offer_id from records', () => {
			const records: ITlvRecord[] = [
				{ type: 10n, value: Buffer.from('test offer') },
				{ type: 22n, value: pubkey1 }
			];
			const offerId = computeOfferId(records);
			expect(offerId.length).to.equal(32);
		});

		it('should produce same merkle root for same records', () => {
			const records: ITlvRecord[] = [
				{ type: 10n, value: Buffer.from('test') },
				{ type: 22n, value: pubkey1 }
			];
			const root1 = computeMerkleRootFromRecords(records);
			const root2 = computeMerkleRootFromRecords(records);
			expect(root1.equals(root2)).to.be.true;
		});
	});

	// ── Schnorr Sign/Verify ─────────────────────────────────────────

	describe('Schnorr sign/verify', () => {
		it('should sign and verify a message', () => {
			const msg = crypto.randomBytes(32);
			const sig = schnorrSign(msg, privkey1);
			expect(sig.length).to.equal(64);

			const xOnlyPub = xOnlyPubkeyFromPrivkey(privkey1);
			expect(xOnlyPub.length).to.equal(32);

			const valid = schnorrVerify(msg, xOnlyPub, sig);
			expect(valid).to.be.true;
		});

		it('should fail verification with wrong message', () => {
			const msg = crypto.randomBytes(32);
			const wrongMsg = crypto.randomBytes(32);
			const sig = schnorrSign(msg, privkey1);
			const xOnlyPub = xOnlyPubkeyFromPrivkey(privkey1);

			const valid = schnorrVerify(wrongMsg, xOnlyPub, sig);
			expect(valid).to.be.false;
		});

		it('should fail verification with wrong key', () => {
			const msg = crypto.randomBytes(32);
			const sig = schnorrSign(msg, privkey1);
			const xOnlyPub2 = xOnlyPubkeyFromPrivkey(privkey2);

			const valid = schnorrVerify(msg, xOnlyPub2, sig);
			expect(valid).to.be.false;
		});

		it('should convert compressed pubkey to x-only', () => {
			const xOnly = toXOnlyPubkey(pubkey1);
			expect(xOnly.length).to.equal(32);
			// Should be the last 32 bytes of the 33-byte compressed key
			expect(xOnly.equals(pubkey1.subarray(1))).to.be.true;
		});

		it('should pass through 32-byte pubkey in toXOnlyPubkey', () => {
			const xOnly = crypto.randomBytes(32);
			const result = toXOnlyPubkey(xOnly);
			expect(result.equals(xOnly)).to.be.true;
		});

		it('should throw on invalid message length', () => {
			expect(() => schnorrSign(Buffer.alloc(16), privkey1)).to.throw(
				'32 bytes'
			);
		});

		it('should throw on invalid key length for sign', () => {
			expect(() =>
				schnorrSign(crypto.randomBytes(32), Buffer.alloc(16))
			).to.throw('32 bytes');
		});

		it('should throw on invalid pubkey length for verify', () => {
			expect(() =>
				schnorrVerify(
					crypto.randomBytes(32),
					Buffer.alloc(16),
					crypto.randomBytes(64)
				)
			).to.throw('32 bytes');
		});

		it('should throw on invalid signature length for verify', () => {
			expect(() =>
				schnorrVerify(
					crypto.randomBytes(32),
					crypto.randomBytes(32),
					Buffer.alloc(32)
				)
			).to.throw('64 bytes');
		});
	});

	// ── Bech32m Encode/Decode Round-Trips ───────────────────────────

	describe('Bech32m encode/decode round-trips', () => {
		it('should round-trip a minimal offer', () => {
			const offer: IOffer = {
				offerId: Buffer.alloc(32),
				description: 'test offer',
				issuerId: pubkey1
			};

			const encoded = encodeOffer(offer);
			expect(encoded.startsWith('lno1')).to.be.true;

			const decoded = decodeOffer(encoded);
			expect(decoded.description).to.equal('test offer');
			expect(decoded.issuerId!.equals(pubkey1)).to.be.true;
			expect(decoded.offerId.length).to.equal(32);
		});

		it('should round-trip an offer with amount', () => {
			const offer: IOffer = {
				offerId: Buffer.alloc(32),
				description: 'priced offer',
				amount: 1_000_000n,
				issuerId: pubkey1
			};

			const encoded = encodeOffer(offer);
			const decoded = decodeOffer(encoded);
			expect(decoded.amount).to.equal(1_000_000n);
			expect(decoded.description).to.equal('priced offer');
		});

		it('should round-trip a full offer', () => {
			const offer: IOffer = {
				offerId: Buffer.alloc(32),
				description: 'full offer',
				amount: 500_000n,
				issuer: 'Test Co',
				issuerId: pubkey1,
				quantityMax: 5n,
				absoluteExpiry: BigInt(Math.floor(Date.now() / 1000) + 7200)
			};

			const encoded = encodeOffer(offer);
			const decoded = decodeOffer(encoded);
			expect(decoded.description).to.equal('full offer');
			expect(decoded.amount).to.equal(500_000n);
			expect(decoded.issuer).to.equal('Test Co');
			expect(decoded.quantityMax).to.equal(5n);
		});

		it('should round-trip a minimal invoice request', () => {
			const request: IInvoiceRequest = {
				payerKey: pubkey2,
				offerId: Buffer.alloc(32)
			};

			const encoded = encodeInvoiceRequest(request);
			expect(encoded.startsWith('lnr1')).to.be.true;

			const decoded = decodeInvoiceRequest(encoded);
			expect(decoded.payerKey.equals(pubkey2)).to.be.true;
		});

		it('should round-trip an invoice request with amount', () => {
			const request: IInvoiceRequest = {
				payerKey: pubkey2,
				offerId: Buffer.alloc(32),
				amount: 99_000n,
				payerNote: 'thanks!'
			};

			const encoded = encodeInvoiceRequest(request);
			const decoded = decodeInvoiceRequest(encoded);
			expect(decoded.amount).to.equal(99_000n);
			expect(decoded.payerNote).to.equal('thanks!');
		});

		it('should round-trip a minimal BOLT 12 invoice', () => {
			const paymentHash = crypto.randomBytes(32);
			const invoice: IBolt12Invoice = {
				paymentHash,
				amount: 100_000n,
				description: 'test',
				createdAt: BigInt(Math.floor(Date.now() / 1000)),
				nodeId: pubkey1
			};

			const encoded = encodeBolt12Invoice(invoice);
			expect(encoded.startsWith('lni1')).to.be.true;

			const decoded = decodeBolt12Invoice(encoded);
			expect(decoded.paymentHash.equals(paymentHash)).to.be.true;
			expect(decoded.amount).to.equal(100_000n);
			expect(decoded.nodeId.equals(pubkey1)).to.be.true;
		});

		it('should round-trip a signed BOLT 12 invoice', () => {
			const paymentHash = crypto.randomBytes(32);
			const invoice: IBolt12Invoice = {
				paymentHash,
				amount: 200_000n,
				description: 'signed invoice',
				createdAt: BigInt(Math.floor(Date.now() / 1000)),
				relativeExpiry: 3600,
				nodeId: pubkey1,
				signature: crypto.randomBytes(64)
			};

			const encoded = encodeBolt12Invoice(invoice);
			const decoded = decodeBolt12Invoice(encoded);
			expect(decoded.signature).to.not.be.undefined;
			expect(decoded.signature!.length).to.equal(64);
			expect(decoded.relativeExpiry).to.equal(3600);
		});

		it('should reject wrong prefix for decodeOffer', () => {
			const request: IInvoiceRequest = {
				payerKey: pubkey2,
				offerId: Buffer.alloc(32)
			};
			const encoded = encodeInvoiceRequest(request);
			expect(() => decodeOffer(encoded)).to.throw("Expected 'lno' prefix");
		});

		it('should reject wrong prefix for decodeInvoiceRequest', () => {
			const offer: IOffer = {
				offerId: Buffer.alloc(32),
				description: 'test',
				issuerId: pubkey1
			};
			const encoded = encodeOffer(offer);
			expect(() => decodeInvoiceRequest(encoded)).to.throw(
				"Expected 'lnr' prefix"
			);
		});

		it('should reject wrong prefix for decodeBolt12Invoice', () => {
			const offer: IOffer = {
				offerId: Buffer.alloc(32),
				description: 'test',
				issuerId: pubkey1
			};
			const encoded = encodeOffer(offer);
			expect(() => decodeBolt12Invoice(encoded)).to.throw(
				"Expected 'lni' prefix"
			);
		});
	});

	// ── detectBolt12Type ────────────────────────────────────────────

	describe('detectBolt12Type', () => {
		it('should detect offer prefix', () => {
			expect(detectBolt12Type('lno1xyz')).to.equal('offer');
		});

		it('should detect invoice request prefix', () => {
			expect(detectBolt12Type('lnr1xyz')).to.equal('invoice_request');
		});

		it('should detect invoice prefix', () => {
			expect(detectBolt12Type('lni1xyz')).to.equal('invoice');
		});

		it('should return null for unknown prefix', () => {
			expect(detectBolt12Type('lnbc1xyz')).to.be.null;
		});

		it('should be case-insensitive', () => {
			expect(detectBolt12Type('LNO1xyz')).to.equal('offer');
		});
	});

	// ── OfferManager ────────────────────────────────────────────────

	describe('OfferManager', () => {
		it('should create an offer with minimal fields', () => {
			const mgr = new OfferManager(privkey1);
			const { offer, encoded } = mgr.createOffer({ description: 'test' });

			expect(offer.description).to.equal('test');
			expect(offer.issuerId!.equals(pubkey1)).to.be.true;
			expect(offer.offerId.length).to.equal(32);
			expect(encoded.startsWith('lno1')).to.be.true;

			mgr.destroy();
		});

		it('should create an offer with amount', () => {
			const mgr = new OfferManager(privkey1);
			const { offer } = mgr.createOffer({
				description: 'priced',
				amount: 250_000n
			});

			expect(offer.amount).to.equal(250_000n);
			mgr.destroy();
		});

		it('should create an offer with all fields', () => {
			const mgr = new OfferManager(privkey1);
			const { offer } = mgr.createOffer({
				description: 'full',
				amount: 100_000n,
				issuer: 'Test Store',
				quantityMax: 100n,
				absoluteExpiry: BigInt(Math.floor(Date.now() / 1000) + 86400),
				paths: [makeTestBlindedPath()]
			});

			expect(offer.issuer).to.equal('Test Store');
			expect(offer.quantityMax).to.equal(100n);
			expect(offer.absoluteExpiry).to.not.be.undefined;
			expect(offer.paths).to.have.length(1);
			mgr.destroy();
		});

		it('should store and retrieve offers', () => {
			const mgr = new OfferManager(privkey1);
			const { offer } = mgr.createOffer({ description: 'stored' });

			const retrieved = mgr.getOffer(offer.offerId);
			expect(retrieved).to.not.be.undefined;
			expect(retrieved!.description).to.equal('stored');

			mgr.destroy();
		});

		it('should list all offers', () => {
			const mgr = new OfferManager(privkey1);
			mgr.createOffer({ description: 'offer1' });
			mgr.createOffer({ description: 'offer2' });

			const offers = mgr.listOffers();
			expect(offers).to.have.length(2);

			mgr.destroy();
		});

		it('should remove an offer', () => {
			const mgr = new OfferManager(privkey1);
			const { offer } = mgr.createOffer({ description: 'removable' });

			expect(mgr.removeOffer(offer.offerId)).to.be.true;
			expect(mgr.getOffer(offer.offerId)).to.be.undefined;
			expect(mgr.listOffers()).to.have.length(0);

			mgr.destroy();
		});

		it('should emit offer:created event', (done) => {
			const mgr = new OfferManager(privkey1);
			mgr.on('offer:created', (offer: IOffer) => {
				expect(offer.description).to.equal('evented');
				mgr.destroy();
				done();
			});
			mgr.createOffer({ description: 'evented' });
		});

		it('should compute stable offerId', () => {
			const mgr = new OfferManager(privkey1);
			const { offer: offer1 } = mgr.createOffer({
				description: 'stable',
				amount: 1000n
			});
			mgr.destroy();

			const mgr2 = new OfferManager(privkey1);
			const { offer: offer2 } = mgr2.createOffer({
				description: 'stable',
				amount: 1000n
			});
			mgr2.destroy();

			expect(offer1.offerId.equals(offer2.offerId)).to.be.true;
		});
	});

	// ── OfferManager Invoice Handling ────────────────────────────────

	describe('OfferManager invoice handling', () => {
		it('should handle invoice request for known offer', () => {
			const mgr = new OfferManager(privkey1);
			const { offer } = mgr.createOffer({
				description: 'payable',
				amount: 50_000n
			});

			// Build a signed invoice request
			const requestTlv = makeSignedRequestTlv({ amount: 50_000n }, offer);

			const invoice = mgr.handleInvoiceRequest(requestTlv);
			expect(invoice).to.not.be.null;
			expect(invoice!.amount).to.equal(50_000n);
			expect(invoice!.nodeId.equals(pubkey1)).to.be.true;
			expect(invoice!.paymentHash.length).to.equal(32);
			expect(invoice!.signature!.length).to.equal(64);

			mgr.destroy();
		});

		it('should return null for unknown offer', () => {
			const mgr = new OfferManager(privkey1);

			// A well-formed (signed) request for an offer the manager does not know.
			const requestTlv = makeSignedRequestTlv({
				offerId: crypto.randomBytes(32),
				amount: 50_000n
			});

			const invoice = mgr.handleInvoiceRequest(requestTlv);
			expect(invoice).to.be.null;

			mgr.destroy();
		});

		it('rejects an invoice request with no signature (S-4.H2)', () => {
			const mgr = new OfferManager(privkey1);
			const { offer } = mgr.createOffer({
				description: 'payable',
				amount: 50_000n
			});
			// A request that carries metadata but no signature.
			const request: IInvoiceRequest = {
				payerKey: pubkey2,
				offerId: offer.offerId,
				amount: 50_000n,
				metadata: crypto.randomBytes(16)
			};
			const requestTlv = encodeInvoiceRequestTlv(
				request,
				encodeOfferTlv(offer)
			);
			expect(mgr.handleInvoiceRequest(requestTlv)).to.be.null;
			mgr.destroy();
		});

		it('rejects an invoice request with a forged signature (S-4.H2)', () => {
			const mgr = new OfferManager(privkey1);
			const { offer } = mgr.createOffer({
				description: 'payable',
				amount: 50_000n
			});
			const requestTlv = makeSignedRequestTlv({ amount: 50_000n }, offer);
			// Flip a byte of the serialized signature (type 240, last field).
			requestTlv[requestTlv.length - 1] ^= 0xff;
			expect(mgr.handleInvoiceRequest(requestTlv)).to.be.null;
			mgr.destroy();
		});

		it('retains the issued invoice preimage and emits invoice:issued', () => {
			const mgr = new OfferManager(privkey1);
			const { offer } = mgr.createOffer({
				description: 'payable',
				amount: 50_000n
			});

			let issued: { invoice: IBolt12Invoice; preimage: Buffer } | null = null;
			mgr.on('invoice:issued', (invoice: IBolt12Invoice, preimage: Buffer) => {
				issued = { invoice, preimage };
			});

			const requestTlv = makeSignedRequestTlv({ amount: 50_000n }, offer);
			const invoice = mgr.handleInvoiceRequest(requestTlv)!;

			// The issuer-side event carries the secret preimage (never on the wire).
			expect(issued, 'invoice:issued fired').to.not.be.null;
			expect(issued!.invoice.paymentHash.equals(invoice.paymentHash)).to.be
				.true;
			expect(issued!.preimage.length).to.equal(32);
			// preimage hashes to the invoice payment_hash.
			const hash = crypto
				.createHash('sha256')
				.update(issued!.preimage)
				.digest();
			expect(hash.equals(invoice.paymentHash)).to.be.true;

			// And it is retrievable by payment_hash for the node to fulfill with.
			const got = mgr.getInvoicePreimage(invoice.paymentHash);
			expect(got, 'getInvoicePreimage returns the preimage').to.not.be
				.undefined;
			expect(got!.equals(issued!.preimage)).to.be.true;

			// Unknown hash → undefined (e.g. the payer side, which holds no preimage).
			expect(mgr.getInvoicePreimage(crypto.randomBytes(32))).to.be.undefined;

			mgr.destroy();
		});

		it('should reject expired offer', () => {
			const mgr = new OfferManager(privkey1);
			const { offer } = mgr.createOffer({
				description: 'expired',
				amount: 10_000n,
				absoluteExpiry: BigInt(Math.floor(Date.now() / 1000) - 3600) // 1 hour ago
			});

			const requestTlv = makeSignedRequestTlv({}, offer);

			const invoice = mgr.handleInvoiceRequest(requestTlv);
			expect(invoice).to.be.null;

			mgr.destroy();
		});

		it('should verify invoice signature', () => {
			const mgr = new OfferManager(privkey1);
			const { offer } = mgr.createOffer({
				description: 'signed',
				amount: 50_000n
			});

			const requestTlv = makeSignedRequestTlv({ amount: 50_000n }, offer);

			const invoice = mgr.handleInvoiceRequest(requestTlv);
			expect(invoice).to.not.be.null;

			const valid = mgr.verifyInvoiceSignature(invoice!);
			expect(valid).to.be.true;

			mgr.destroy();
		});

		it('should reject tampered invoice signature', () => {
			const mgr = new OfferManager(privkey1);
			const { offer } = mgr.createOffer({
				description: 'tampered',
				amount: 50_000n
			});

			const requestTlv = makeSignedRequestTlv({ amount: 50_000n }, offer);

			const invoice = mgr.handleInvoiceRequest(requestTlv)!;
			// Tamper with amount
			invoice.amount = 99_000n;

			const valid = mgr.verifyInvoiceSignature(invoice);
			expect(valid).to.be.false;

			mgr.destroy();
		});

		it('should validate invoice against offer', () => {
			const mgr = new OfferManager(privkey1);
			const { offer } = mgr.createOffer({
				description: 'validated',
				amount: 50_000n
			});

			const requestTlv = makeSignedRequestTlv({ amount: 50_000n }, offer);
			const invoice = mgr.handleInvoiceRequest(requestTlv)!;

			const valid = mgr.validateInvoiceForOffer(invoice, offer);
			expect(valid).to.be.true;

			mgr.destroy();
		});

		it('should reject invoice with mismatched description', () => {
			const mgr = new OfferManager(privkey1);
			const { offer } = mgr.createOffer({
				description: 'original',
				amount: 50_000n
			});

			const requestTlv = makeSignedRequestTlv({ amount: 50_000n }, offer);
			const invoice = mgr.handleInvoiceRequest(requestTlv)!;
			invoice.description = 'tampered';

			const valid = mgr.validateInvoiceForOffer(invoice, offer);
			expect(valid).to.be.false;

			mgr.destroy();
		});

		it('should reject invoice with insufficient amount', () => {
			const mgr = new OfferManager(privkey1);
			const { offer } = mgr.createOffer({
				description: 'test',
				amount: 100_000n
			});

			const invoice: IBolt12Invoice = {
				paymentHash: crypto.randomBytes(32),
				amount: 50_000n,
				description: 'test',
				createdAt: BigInt(Math.floor(Date.now() / 1000)),
				nodeId: pubkey1
			};

			const valid = mgr.validateInvoiceForOffer(invoice, offer);
			expect(valid).to.be.false;

			mgr.destroy();
		});

		it('should emit invoice:error for unknown offer request', () => {
			const mgr = new OfferManager(privkey1);
			let errorEmitted = false;

			mgr.on('invoice:error', () => {
				errorEmitted = true;
			});

			const requestTlv = makeSignedRequestTlv({
				offerId: crypto.randomBytes(32)
			});
			mgr.handleInvoiceRequest(requestTlv);

			expect(errorEmitted).to.be.true;
			mgr.destroy();
		});
	});

	// ── OfferManager Expired Offer Rejection ────────────────────────

	describe('OfferManager expired offer rejection', () => {
		it('should reject requestInvoice for expired offer', async () => {
			const mgr = new OfferManager(privkey1);
			const expiredOffer: IOffer = {
				offerId: crypto.randomBytes(32),
				description: 'expired',
				absoluteExpiry: BigInt(Math.floor(Date.now() / 1000) - 1),
				issuerId: pubkey1
			};

			try {
				await mgr.requestInvoice(expiredOffer);
				expect.fail('Should have thrown');
			} catch (e) {
				expect((e as Error).message).to.include('expired');
			}

			mgr.destroy();
		});
	});

	// ── Blinded Path Routing ────────────────────────────────────────

	describe('Blinded path routing', () => {
		it('should find route to blinded path introduction node', () => {
			const graph = new NetworkGraph();

			// Create two nodes sorted lexicographically (required for channel announcements)
			const rawKeys = [
				{ privateKey: privkey1, publicKey: pubkey1 },
				{ privateKey: privkey2, publicKey: pubkey2 }
			].sort((a, b) => Buffer.compare(a.publicKey, b.publicKey));

			const nodeA = rawKeys[0].publicKey;
			const nodeB = rawKeys[1].publicKey;

			const scid = Buffer.alloc(8);
			scid.writeBigUInt64BE(BigInt((100 << 16) | 1));

			// Add channel announcement with proper key ordering
			graph.addChannelAnnouncement({
				nodeId1: nodeA,
				nodeId2: nodeB,
				shortChannelId: scid,
				features: Buffer.alloc(0),
				nodeSignature1: Buffer.alloc(64),
				nodeSignature2: Buffer.alloc(64),
				bitcoinSignature1: Buffer.alloc(64),
				bitcoinSignature2: Buffer.alloc(64),
				chainHash: BITCOIN_CHAIN_HASH,
				bitcoinKey1: nodeA,
				bitcoinKey2: nodeB
			});

			// Direction 0: node1 -> node2 (lower key announces its side)
			graph.applyChannelUpdate({
				signature: Buffer.alloc(64),
				chainHash: BITCOIN_CHAIN_HASH,
				shortChannelId: scid,
				timestamp: Math.floor(Date.now() / 1000),
				messageFlags: 1,
				channelFlags: 0,
				cltvExpiryDelta: 40,
				htlcMinimumMsat: 1n,
				feeBaseMsat: 1000,
				feeProportionalMillionths: 1,
				htlcMaximumMsat: 1_000_000_000n
			});
			// Direction 1: node2 -> node1
			graph.applyChannelUpdate({
				signature: Buffer.alloc(64),
				chainHash: BITCOIN_CHAIN_HASH,
				shortChannelId: scid,
				timestamp: Math.floor(Date.now() / 1000),
				messageFlags: 1,
				channelFlags: 1,
				cltvExpiryDelta: 40,
				htlcMinimumMsat: 1n,
				feeBaseMsat: 1000,
				feeProportionalMillionths: 1,
				htlcMaximumMsat: 1_000_000_000n
			});

			// Create a blinded path with nodeB as introduction
			const blindedPath: IBlindedPath = {
				introductionNodeId: nodeB,
				blindingPoint: getPublicKey(crypto.randomBytes(32)),
				blindedHops: [
					{
						blindedNodeId: getPublicKey(crypto.randomBytes(32)),
						encryptedData: crypto.randomBytes(32)
					}
				]
			};

			const route = findRouteToBlindedPath(
				graph,
				nodeA,
				blindedPath,
				{
					feeBaseMsat: 0,
					feeProportionalMillionths: 0,
					cltvExpiryDelta: 0,
					htlcMinimumMsat: 0n,
					htlcMaximumMsat: 1_000_000_000n
				},
				1000n,
				40
			);
			// Route should exist (we have a path A->B, and then the blinded hop)
			expect(route).to.not.be.null;
			if (route) {
				expect(route.hops.length).to.be.greaterThan(0);
			}
		});

		it('should return route with only blinded hops when source is introduction node', () => {
			const graph = new NetworkGraph();
			const blindedPath: IBlindedPath = {
				introductionNodeId: pubkey1,
				blindingPoint: getPublicKey(crypto.randomBytes(32)),
				blindedHops: [
					{
						blindedNodeId: getPublicKey(crypto.randomBytes(32)),
						encryptedData: crypto.randomBytes(32)
					},
					{
						blindedNodeId: getPublicKey(crypto.randomBytes(32)),
						encryptedData: crypto.randomBytes(32)
					}
				]
			};

			const route = findRouteToBlindedPath(
				graph,
				pubkey1,
				blindedPath,
				{
					feeBaseMsat: 0,
					feeProportionalMillionths: 0,
					cltvExpiryDelta: 0,
					htlcMinimumMsat: 0n,
					htlcMaximumMsat: 1_000_000_000n
				},
				1000n,
				40
			);
			expect(route).to.not.be.null;
			expect(route!.hops).to.have.length(2);
		});

		it('should return null when no route to introduction node', () => {
			const graph = new NetworkGraph();
			const blindedPath: IBlindedPath = {
				introductionNodeId: pubkey2, // No channels in graph
				blindingPoint: getPublicKey(crypto.randomBytes(32)),
				blindedHops: [
					{
						blindedNodeId: getPublicKey(crypto.randomBytes(32)),
						encryptedData: crypto.randomBytes(32)
					}
				]
			};

			const route = findRouteToBlindedPath(
				graph,
				pubkey1,
				blindedPath,
				{
					feeBaseMsat: 0,
					feeProportionalMillionths: 0,
					cltvExpiryDelta: 0,
					htlcMinimumMsat: 0n,
					htlcMaximumMsat: 1_000_000_000n
				},
				1000n,
				40
			);
			expect(route).to.be.null;
		});

		it('should return null for empty blinded hops when source is intro node', () => {
			const graph = new NetworkGraph();
			const blindedPath: IBlindedPath = {
				introductionNodeId: pubkey1,
				blindingPoint: getPublicKey(crypto.randomBytes(32)),
				blindedHops: []
			};

			const route = findRouteToBlindedPath(
				graph,
				pubkey1,
				blindedPath,
				{
					feeBaseMsat: 0,
					feeProportionalMillionths: 0,
					cltvExpiryDelta: 0,
					htlcMinimumMsat: 0n,
					htlcMaximumMsat: 1_000_000_000n
				},
				1000n,
				40
			);
			expect(route).to.be.null;
		});
	});

	// ── End-to-End Flow ─────────────────────────────────────────────

	describe('End-to-end flow', () => {
		it('should create offer, encode, decode, and verify round-trip', () => {
			const mgr = new OfferManager(privkey1);
			const { offer, encoded } = mgr.createOffer({
				description: 'E2E test',
				amount: 100_000n,
				issuer: 'E2E Issuer'
			});

			// Decode the encoded offer
			const decodedOffer = decodeOffer(encoded);
			expect(decodedOffer.description).to.equal('E2E test');
			expect(decodedOffer.amount).to.equal(100_000n);
			expect(decodedOffer.issuer).to.equal('E2E Issuer');
			expect(decodedOffer.offerId.equals(offer.offerId)).to.be.true;

			mgr.destroy();
		});

		it('should complete offer -> request -> invoice flow', () => {
			const issuerMgr = new OfferManager(privkey1);
			const { offer } = issuerMgr.createOffer({
				description: 'Full flow test',
				amount: 50_000n
			});

			// Build a signed invoice request from the payer's side
			const requestTlv = makeSignedRequestTlv({ amount: 50_000n }, offer);

			// Issuer handles the request
			const invoice = issuerMgr.handleInvoiceRequest(requestTlv);
			expect(invoice).to.not.be.null;
			expect(invoice!.amount).to.equal(50_000n);
			expect(invoice!.description).to.equal('Full flow test');

			// Verify signature
			const sigValid = issuerMgr.verifyInvoiceSignature(invoice!);
			expect(sigValid).to.be.true;

			// Validate against offer
			const offerValid = issuerMgr.validateInvoiceForOffer(invoice!, offer);
			expect(offerValid).to.be.true;

			// Encode and decode the invoice
			const encodedInvoice = encodeBolt12Invoice(invoice!);
			expect(encodedInvoice.startsWith('lni1')).to.be.true;
			const decodedInvoice = decodeBolt12Invoice(encodedInvoice);
			expect(decodedInvoice.paymentHash.equals(invoice!.paymentHash)).to.be
				.true;

			issuerMgr.destroy();
		});

		it('should handle invoice request with amount override', () => {
			const mgr = new OfferManager(privkey1);
			const { offer } = mgr.createOffer({
				description: 'any amount'
				// No amount — "any amount" offer
			});

			const requestTlv = makeSignedRequestTlv({ amount: 75_000n }, offer);

			const invoice = mgr.handleInvoiceRequest(requestTlv);
			expect(invoice).to.not.be.null;
			expect(invoice!.amount).to.equal(75_000n);

			mgr.destroy();
		});

		it('should reject invoice request with no amount on amount-less offer', () => {
			const mgr = new OfferManager(privkey1);
			const { offer } = mgr.createOffer({ description: 'no amount' });

			const requestTlv = makeSignedRequestTlv({}, offer);

			const invoice = mgr.handleInvoiceRequest(requestTlv);
			expect(invoice).to.be.null;

			mgr.destroy();
		});
	});

	// ── TLV Type Enum Values ────────────────────────────────────────

	describe('TLV type enum values', () => {
		it('should have correct offer TLV types', () => {
			expect(OfferTlvType.CHAINS).to.equal(2);
			expect(OfferTlvType.METADATA).to.equal(4);
			expect(OfferTlvType.CURRENCY).to.equal(6);
			expect(OfferTlvType.AMOUNT).to.equal(8);
			expect(OfferTlvType.DESCRIPTION).to.equal(10);
			expect(OfferTlvType.FEATURES).to.equal(12);
			expect(OfferTlvType.ABSOLUTE_EXPIRY).to.equal(14);
			expect(OfferTlvType.PATHS).to.equal(16);
			expect(OfferTlvType.ISSUER).to.equal(18);
			expect(OfferTlvType.QUANTITY_MAX).to.equal(20);
			expect(OfferTlvType.ISSUER_ID).to.equal(22);
		});

		it('should have correct invoice request TLV types', () => {
			expect(InvoiceRequestTlvType.CHAIN).to.equal(80);
			expect(InvoiceRequestTlvType.AMOUNT).to.equal(82);
			expect(InvoiceRequestTlvType.FEATURES).to.equal(84);
			expect(InvoiceRequestTlvType.QUANTITY).to.equal(86);
			expect(InvoiceRequestTlvType.METADATA).to.equal(0);
			expect(InvoiceRequestTlvType.PAYER_KEY).to.equal(88);
			expect(InvoiceRequestTlvType.PAYER_NOTE).to.equal(89);
			expect(InvoiceRequestTlvType.SIGNATURE).to.equal(240);
		});

		it('should have correct invoice TLV types', () => {
			expect(InvoiceTlvType.PATHS).to.equal(160);
			expect(InvoiceTlvType.BLINDEDPAY).to.equal(162);
			expect(InvoiceTlvType.CREATED_AT).to.equal(164);
			expect(InvoiceTlvType.RELATIVE_EXPIRY).to.equal(166);
			expect(InvoiceTlvType.PAYMENT_HASH).to.equal(168);
			expect(InvoiceTlvType.AMOUNT).to.equal(170);
			expect(InvoiceTlvType.FALLBACKS).to.equal(172);
			expect(InvoiceTlvType.FEATURES).to.equal(174);
			expect(InvoiceTlvType.NODE_ID).to.equal(176);
			expect(InvoiceTlvType.SIGNATURE).to.equal(240);
		});

		it('should have correct invoice error TLV types', () => {
			expect(InvoiceErrorTlvType.ERRONEOUS_FIELD).to.equal(1);
			expect(InvoiceErrorTlvType.SUGGESTED_VALUE).to.equal(3);
			expect(InvoiceErrorTlvType.ERROR).to.equal(5);
		});

		it('should have correct onion message TLV types', () => {
			expect(TLV_INVOICE_REQUEST).to.equal(64);
			expect(TLV_INVOICE).to.equal(66);
			expect(TLV_INVOICE_ERROR).to.equal(68);
		});
	});

	// ── getTlvRecords and getTlvRecordsForSigning ───────────────────

	describe('TLV record helpers', () => {
		it('should get all TLV records from encoded data', () => {
			const offer: IOffer = {
				offerId: Buffer.alloc(32),
				description: 'test',
				amount: 1000n,
				issuerId: pubkey1
			};
			const data = encodeOfferTlv(offer);
			const records = getTlvRecords(data);
			expect(records.length).to.be.greaterThan(0);

			const types = records.map((r) => Number(r.type));
			expect(types).to.include(OfferTlvType.DESCRIPTION);
			expect(types).to.include(OfferTlvType.AMOUNT);
			expect(types).to.include(OfferTlvType.ISSUER_ID);
		});

		it('should filter out signature when getting records for signing', () => {
			const invoice: IBolt12Invoice = {
				paymentHash: crypto.randomBytes(32),
				amount: 100_000n,
				description: 'signed',
				createdAt: BigInt(Math.floor(Date.now() / 1000)),
				nodeId: pubkey1,
				signature: crypto.randomBytes(64)
			};
			const data = encodeInvoiceTlv(invoice);
			const allRecords = getTlvRecords(data);
			const signingRecords = getTlvRecordsForSigning(data);

			// allRecords should include signature
			const allTypes = allRecords.map((r) => Number(r.type));
			expect(allTypes).to.include(InvoiceTlvType.SIGNATURE);

			// signingRecords should NOT include signature
			const sigTypes = signingRecords.map((r) => Number(r.type));
			expect(sigTypes).to.not.include(InvoiceTlvType.SIGNATURE);
			expect(signingRecords.length).to.equal(allRecords.length - 1);
		});

		it('should encode individual TLV records', () => {
			const record: ITlvRecord = {
				type: 10n,
				value: Buffer.from('hello')
			};
			const encoded = encodeTlvRecordRaw(record);
			expect(encoded.length).to.be.greaterThan(0);
			// Type 10 (1 byte) + length 5 (1 byte) + "hello" (5 bytes) = 7
			expect(encoded.length).to.equal(7);
		});
	});

	// ── OfferManager with OnionMessageManager ───────────────────────

	describe('OfferManager with OnionMessageManager', () => {
		it('should attach onion message manager', () => {
			const omm = new OnionMessageManager(privkey1);
			const mgr = new OfferManager(privkey1, { onionMessageManager: omm });

			// Should not throw
			expect(mgr.listOffers()).to.have.length(0);

			mgr.destroy();
			omm.destroy();
		});

		it('should register TLV handlers on attach', () => {
			const omm = new OnionMessageManager(privkey1);
			const mgr = new OfferManager(privkey1);

			mgr.attachOnionMessageManager(omm);

			// Can't directly inspect handlers, but should not throw
			expect(mgr.listOffers()).to.have.length(0);

			mgr.destroy();
			omm.destroy();
		});
	});

	// ── Offer Decode Round-Trip Stability ────────────────────────────

	describe('Decode round-trip stability', () => {
		it('should produce same offerId on re-encoding', () => {
			const offer: IOffer = {
				offerId: Buffer.alloc(32),
				description: 'stable test',
				amount: 42_000n,
				issuerId: pubkey1
			};

			const encoded1 = encodeOffer(offer);
			const decoded1 = decodeOffer(encoded1);
			const encoded2 = encodeOffer(decoded1);
			const decoded2 = decodeOffer(encoded2);

			expect(decoded1.offerId.equals(decoded2.offerId)).to.be.true;
			expect(decoded1.description).to.equal(decoded2.description);
			expect(decoded1.amount).to.equal(decoded2.amount);
		});

		it('should produce same encoded string on re-encoding minimal offer', () => {
			const offer: IOffer = {
				offerId: Buffer.alloc(32),
				description: 'minimal',
				issuerId: pubkey1
			};

			const encoded1 = encodeOffer(offer);
			const decoded = decodeOffer(encoded1);
			const encoded2 = encodeOffer(decoded);

			expect(encoded1).to.equal(encoded2);
		});
	});

	// ── Invoice with Blinded Pay Info ────────────────────────────────

	describe('Invoice with blinded pay info', () => {
		it('should encode and decode invoice with blinded pay info', () => {
			const invoice: IBolt12Invoice = {
				paymentHash: crypto.randomBytes(32),
				amount: 100_000n,
				description: 'with pay info',
				createdAt: BigInt(Math.floor(Date.now() / 1000)),
				nodeId: pubkey1,
				paths: [makeTestBlindedPath()],
				blindedPayInfo: [
					{
						feeBaseMsat: 1000,
						feeProportionalMillionths: 100,
						cltvExpiryDelta: 40,
						htlcMinimumMsat: 1n,
						htlcMaximumMsat: 1_000_000_000n
					}
				]
			};

			const tlvData = encodeInvoiceTlv(invoice);
			const { invoice: decoded } = decodeInvoiceTlv(tlvData);

			expect(decoded.blindedPayInfo).to.have.length(1);
			expect(decoded.blindedPayInfo![0].feeBaseMsat).to.equal(1000);
			expect(decoded.blindedPayInfo![0].feeProportionalMillionths).to.equal(
				100
			);
			expect(decoded.blindedPayInfo![0].cltvExpiryDelta).to.equal(40);
			expect(decoded.blindedPayInfo![0].htlcMinimumMsat).to.equal(1n);
			expect(decoded.blindedPayInfo![0].htlcMaximumMsat).to.equal(
				1_000_000_000n
			);
		});
	});

	// ── Invoice with Fallback Addresses ─────────────────────────────

	describe('Invoice with fallback addresses', () => {
		it('should encode and decode invoice with fallback addresses', () => {
			const invoice: IBolt12Invoice = {
				paymentHash: crypto.randomBytes(32),
				amount: 100_000n,
				description: 'with fallback',
				createdAt: BigInt(Math.floor(Date.now() / 1000)),
				nodeId: pubkey1,
				fallbacks: [
					{ version: 0, program: crypto.randomBytes(20) },
					{ version: 1, program: crypto.randomBytes(32) }
				]
			};

			const tlvData = encodeInvoiceTlv(invoice);
			const { invoice: decoded } = decodeInvoiceTlv(tlvData);

			expect(decoded.fallbacks).to.have.length(2);
			expect(decoded.fallbacks![0].version).to.equal(0);
			expect(decoded.fallbacks![0].program.length).to.equal(20);
			expect(decoded.fallbacks![1].version).to.equal(1);
			expect(decoded.fallbacks![1].program.length).to.equal(32);
		});
	});

	// ── Multiple Blinded Paths ──────────────────────────────────────

	describe('Multiple blinded paths', () => {
		it('should encode and decode offer with multiple paths', () => {
			const offer: IOffer = {
				offerId: Buffer.alloc(32),
				description: 'multi-path offer',
				issuerId: pubkey1,
				paths: [makeTestBlindedPath(), makeTestBlindedPath()]
			};

			const tlvData = encodeOfferTlv(offer);
			const { offer: decoded } = decodeOfferTlv(tlvData);
			expect(decoded.paths).to.have.length(2);
		});

		it('should encode and decode blinded path with multiple hops', () => {
			const path: IBlindedPath = {
				introductionNodeId: pubkey1,
				blindingPoint: pubkey2,
				blindedHops: [
					{
						blindedNodeId: getPublicKey(crypto.randomBytes(32)),
						encryptedData: crypto.randomBytes(64)
					},
					{
						blindedNodeId: getPublicKey(crypto.randomBytes(32)),
						encryptedData: crypto.randomBytes(48)
					},
					{
						blindedNodeId: getPublicKey(crypto.randomBytes(32)),
						encryptedData: crypto.randomBytes(32)
					}
				]
			};

			const offer: IOffer = {
				offerId: Buffer.alloc(32),
				description: 'multi-hop path',
				issuerId: pubkey1,
				paths: [path]
			};

			const tlvData = encodeOfferTlv(offer);
			const { offer: decoded } = decodeOfferTlv(tlvData);
			expect(decoded.paths).to.have.length(1);
			expect(decoded.paths![0].blindedHops).to.have.length(3);
			expect(decoded.paths![0].blindedHops[0].encryptedData.length).to.equal(
				64
			);
			expect(decoded.paths![0].blindedHops[1].encryptedData.length).to.equal(
				48
			);
			expect(decoded.paths![0].blindedHops[2].encryptedData.length).to.equal(
				32
			);
		});
	});

	// ── Offer with Currency ─────────────────────────────────────────

	describe('Offer with currency', () => {
		it('should encode and decode offer with currency', () => {
			const offer: IOffer = {
				offerId: Buffer.alloc(32),
				description: 'USD offer',
				amount: 500n,
				currency: 'USD',
				issuerId: pubkey1
			};

			const tlvData = encodeOfferTlv(offer);
			const { offer: decoded } = decodeOfferTlv(tlvData);
			expect(decoded.currency).to.equal('USD');
			expect(decoded.amount).to.equal(500n);
		});
	});
});
