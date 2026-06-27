/**
 * Phase 7: Route Blinding (BOLT 4 Extension) tests.
 *
 * Tests for blinding key derivation, encrypted recipient data,
 * blinded path construction/processing, and hop payload TLV types 10/12.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as ecc from '@bitcoinerlab/secp256k1';
import * as bitcoin from 'bitcoinjs-lib';
import {
	deriveBlindingSharedSecret,
	deriveBlindingFactor,
	deriveNextBlindingKey,
	computeBlindedNodeId,
	deriveBlindingEncryptionKey,
	encryptBlindedData,
	decryptBlindedData,
	deriveBlindingKeyChain
} from '../../src/lightning/onion/blinding';
import {
	IBlindedHopData,
	encodeBlindedHopData,
	decodeBlindedHopData,
	constructBlindedPath,
	processBlindedHop
} from '../../src/lightning/onion/blinded-path';
import {
	encodeHopPayload,
	decodeHopPayload
} from '../../src/lightning/onion/hop-payload';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

bitcoin.initEccLib(ecc);

function randomPrivkey(): Buffer {
	let key: Buffer;
	do {
		key = crypto.randomBytes(32);
	} while (!ecc.isPrivate(key));
	return key;
}

describe('Route Blinding (BOLT 4 Extension)', function () {
	// ── Blinding key derivation ────────────────────────────────────────

	describe('Blinding key derivation', function () {
		it('should derive a 32-byte shared secret from blinding key and node privkey', function () {
			const nodePrivkey = randomPrivkey();
			const blindingSecret = randomPrivkey();
			const blindingKey = getPublicKey(blindingSecret);

			const ss = deriveBlindingSharedSecret(blindingKey, nodePrivkey);
			expect(ss).to.be.instanceOf(Buffer);
			expect(ss.length).to.equal(32);
		});

		it('should produce deterministic shared secrets', function () {
			const nodePrivkey = randomPrivkey();
			const blindingSecret = randomPrivkey();
			const blindingKey = getPublicKey(blindingSecret);

			const ss1 = deriveBlindingSharedSecret(blindingKey, nodePrivkey);
			const ss2 = deriveBlindingSharedSecret(blindingKey, nodePrivkey);
			expect(ss1.equals(ss2)).to.be.true;
		});

		it('should derive a 32-byte blinding factor', function () {
			const blindingKey = getPublicKey(randomPrivkey());
			const ss = crypto.randomBytes(32);

			const factor = deriveBlindingFactor(blindingKey, ss);
			expect(factor).to.be.instanceOf(Buffer);
			expect(factor.length).to.equal(32);
		});

		it('should derive the next blinding key as a 33-byte compressed pubkey', function () {
			const blindingKey = getPublicKey(randomPrivkey());
			const nodePrivkey = randomPrivkey();
			const ss = deriveBlindingSharedSecret(blindingKey, nodePrivkey);

			const nextKey = deriveNextBlindingKey(blindingKey, ss);
			expect(nextKey).to.be.instanceOf(Buffer);
			expect(nextKey.length).to.equal(33);
			// Should be a valid compressed pubkey (starts with 0x02 or 0x03)
			expect(nextKey[0] === 0x02 || nextKey[0] === 0x03).to.be.true;
		});

		it('should produce a different next blinding key from the current one', function () {
			const blindingKey = getPublicKey(randomPrivkey());
			const nodePrivkey = randomPrivkey();
			const ss = deriveBlindingSharedSecret(blindingKey, nodePrivkey);

			const nextKey = deriveNextBlindingKey(blindingKey, ss);
			expect(nextKey.equals(blindingKey)).to.be.false;
		});

		it('should compute a blinded node ID as a 33-byte pubkey', function () {
			const nodePubkey = getPublicKey(randomPrivkey());
			const ss = crypto.randomBytes(32);

			const blindedId = computeBlindedNodeId(nodePubkey, ss);
			expect(blindedId).to.be.instanceOf(Buffer);
			expect(blindedId.length).to.equal(33);
			expect(blindedId[0] === 0x02 || blindedId[0] === 0x03).to.be.true;
		});

		it('should produce a blinded node ID different from the original pubkey', function () {
			const nodePubkey = getPublicKey(randomPrivkey());
			const ss = crypto.randomBytes(32);

			const blindedId = computeBlindedNodeId(nodePubkey, ss);
			expect(blindedId.equals(nodePubkey)).to.be.false;
		});

		it('should derive a 32-byte encryption key', function () {
			const ss = crypto.randomBytes(32);

			const encKey = deriveBlindingEncryptionKey(ss);
			expect(encKey).to.be.instanceOf(Buffer);
			expect(encKey.length).to.equal(32);
		});

		it('should return correct count of blinding keys and shared secrets', function () {
			const blindingSecret = randomPrivkey();
			const nodePubkeys = [
				getPublicKey(randomPrivkey()),
				getPublicKey(randomPrivkey()),
				getPublicKey(randomPrivkey())
			];

			const { blindingKeys, sharedSecrets } = deriveBlindingKeyChain(
				blindingSecret,
				nodePubkeys
			);
			expect(blindingKeys.length).to.equal(3);
			expect(sharedSecrets.length).to.equal(3);
		});

		it('should produce different blinding keys at each hop in the chain', function () {
			const blindingSecret = randomPrivkey();
			const nodePubkeys = [
				getPublicKey(randomPrivkey()),
				getPublicKey(randomPrivkey()),
				getPublicKey(randomPrivkey())
			];

			const { blindingKeys } = deriveBlindingKeyChain(
				blindingSecret,
				nodePubkeys
			);
			// All three blinding keys should be distinct
			expect(blindingKeys[0].equals(blindingKeys[1])).to.be.false;
			expect(blindingKeys[1].equals(blindingKeys[2])).to.be.false;
			expect(blindingKeys[0].equals(blindingKeys[2])).to.be.false;
		});
	});

	// ── Encryption/Decryption ──────────────────────────────────────────

	describe('Encryption/Decryption', function () {
		it('should return ciphertext from encryptBlindedData', function () {
			const key = crypto.randomBytes(32);
			const plaintext = Buffer.from('hello blinded world');

			const ciphertext = encryptBlindedData(key, plaintext);
			expect(ciphertext).to.be.instanceOf(Buffer);
			// Ciphertext = plaintext length + 16 bytes Poly1305 tag
			expect(ciphertext.length).to.equal(plaintext.length + 16);
		});

		it('should produce ciphertext different from plaintext', function () {
			const key = crypto.randomBytes(32);
			const plaintext = Buffer.from('test data for encryption');

			const ciphertext = encryptBlindedData(key, plaintext);
			// The ciphertext portion (excluding tag) should differ from plaintext
			const ctBody = ciphertext.subarray(0, plaintext.length);
			expect(ctBody.equals(plaintext)).to.be.false;
		});

		it('should recover plaintext via decryptBlindedData', function () {
			const key = crypto.randomBytes(32);
			const plaintext = Buffer.from('secret route data');

			const ciphertext = encryptBlindedData(key, plaintext);
			const recovered = decryptBlindedData(key, ciphertext);
			expect(recovered.equals(plaintext)).to.be.true;
		});

		it('should round-trip encrypt/decrypt with arbitrary data', function () {
			const key = crypto.randomBytes(32);
			const plaintext = crypto.randomBytes(128);

			const ciphertext = encryptBlindedData(key, plaintext);
			const recovered = decryptBlindedData(key, ciphertext);
			expect(recovered.equals(plaintext)).to.be.true;
		});

		it('should produce different ciphertext with different keys', function () {
			const key1 = crypto.randomBytes(32);
			const key2 = crypto.randomBytes(32);
			const plaintext = Buffer.from('same plaintext');

			const ct1 = encryptBlindedData(key1, plaintext);
			const ct2 = encryptBlindedData(key2, plaintext);
			expect(ct1.equals(ct2)).to.be.false;
		});

		it('should fail decryption with a wrong key', function () {
			const correctKey = crypto.randomBytes(32);
			const wrongKey = crypto.randomBytes(32);
			const plaintext = Buffer.from('encrypted data');

			const ciphertext = encryptBlindedData(correctKey, plaintext);
			expect(() => decryptBlindedData(wrongKey, ciphertext)).to.throw();
		});
	});

	// ── Blinded hop data encode/decode ─────────────────────────────────

	describe('Blinded hop data encode/decode', function () {
		it('should encode/decode minimal (empty) data', function () {
			const data: IBlindedHopData = {};
			const encoded = encodeBlindedHopData(data);
			const decoded = decodeBlindedHopData(encoded);
			expect(decoded.nextNodeId).to.be.undefined;
			expect(decoded.shortChannelId).to.be.undefined;
			expect(decoded.paymentRelay).to.be.undefined;
			expect(decoded.paymentConstraints).to.be.undefined;
			expect(decoded.padding).to.be.undefined;
		});

		it('should encode/decode data with nextNodeId', function () {
			const pubkey = getPublicKey(randomPrivkey());
			const data: IBlindedHopData = { nextNodeId: pubkey };

			const encoded = encodeBlindedHopData(data);
			const decoded = decodeBlindedHopData(encoded);
			expect(decoded.nextNodeId).to.not.be.undefined;
			expect(decoded.nextNodeId!.equals(pubkey)).to.be.true;
		});

		it('should encode/decode data with shortChannelId', function () {
			const scid = Buffer.from('0001000200030004', 'hex');
			const data: IBlindedHopData = { shortChannelId: scid };

			const encoded = encodeBlindedHopData(data);
			const decoded = decodeBlindedHopData(encoded);
			expect(decoded.shortChannelId).to.not.be.undefined;
			expect(decoded.shortChannelId!.equals(scid)).to.be.true;
		});

		it('should encode/decode data with paymentRelay', function () {
			const data: IBlindedHopData = {
				paymentRelay: {
					cltvExpiryDelta: 40,
					feeProportionalMillionths: 1000,
					feeBaseMsat: 500
				}
			};

			const encoded = encodeBlindedHopData(data);
			const decoded = decodeBlindedHopData(encoded);
			expect(decoded.paymentRelay).to.not.be.undefined;
			expect(decoded.paymentRelay!.cltvExpiryDelta).to.equal(40);
			expect(decoded.paymentRelay!.feeProportionalMillionths).to.equal(1000);
			expect(decoded.paymentRelay!.feeBaseMsat).to.equal(500);
		});

		it('should encode/decode data with paymentConstraints', function () {
			const data: IBlindedHopData = {
				paymentConstraints: {
					maxCltvExpiry: 800000,
					htlcMinimumMsat: 1000n
				}
			};

			const encoded = encodeBlindedHopData(data);
			const decoded = decodeBlindedHopData(encoded);
			expect(decoded.paymentConstraints).to.not.be.undefined;
			expect(decoded.paymentConstraints!.maxCltvExpiry).to.equal(800000);
			expect(decoded.paymentConstraints!.htlcMinimumMsat).to.equal(1000n);
		});

		it('should encode/decode data with padding', function () {
			const padding = Buffer.alloc(64, 0x00);
			const data: IBlindedHopData = { padding };

			const encoded = encodeBlindedHopData(data);
			const decoded = decodeBlindedHopData(encoded);
			expect(decoded.padding).to.not.be.undefined;
			expect(decoded.padding!.length).to.equal(64);
			expect(decoded.padding!.equals(padding)).to.be.true;
		});

		it('should encode/decode data with all fields', function () {
			const nextNodeId = getPublicKey(randomPrivkey());
			const scid = Buffer.from('0001000200030004', 'hex');
			const padding = crypto.randomBytes(20);
			const data: IBlindedHopData = {
				nextNodeId,
				shortChannelId: scid,
				paymentRelay: {
					cltvExpiryDelta: 144,
					feeProportionalMillionths: 5000,
					feeBaseMsat: 1000
				},
				paymentConstraints: {
					maxCltvExpiry: 1000000,
					htlcMinimumMsat: 500n
				},
				padding
			};

			const encoded = encodeBlindedHopData(data);
			const decoded = decodeBlindedHopData(encoded);

			expect(decoded.nextNodeId!.equals(nextNodeId)).to.be.true;
			expect(decoded.shortChannelId!.equals(scid)).to.be.true;
			expect(decoded.paymentRelay!.cltvExpiryDelta).to.equal(144);
			expect(decoded.paymentRelay!.feeProportionalMillionths).to.equal(5000);
			expect(decoded.paymentRelay!.feeBaseMsat).to.equal(1000);
			expect(decoded.paymentConstraints!.maxCltvExpiry).to.equal(1000000);
			expect(decoded.paymentConstraints!.htlcMinimumMsat).to.equal(500n);
			expect(decoded.padding!.equals(padding)).to.be.true;
		});

		it('should round-trip encode/decode preserving all data', function () {
			const nextNodeId = getPublicKey(randomPrivkey());
			const data: IBlindedHopData = {
				nextNodeId,
				paymentRelay: {
					cltvExpiryDelta: 10,
					feeProportionalMillionths: 100,
					feeBaseMsat: 50
				}
			};

			const encoded = encodeBlindedHopData(data);
			const decoded = decodeBlindedHopData(encoded);
			const reEncoded = encodeBlindedHopData(decoded);
			expect(reEncoded.equals(encoded)).to.be.true;
		});

		it('should encode nextNodeId as exactly 33 bytes', function () {
			const pubkey = getPublicKey(randomPrivkey());
			const data: IBlindedHopData = { nextNodeId: pubkey };
			const encoded = encodeBlindedHopData(data);
			// 1 byte flags + 33 bytes nextNodeId = 34 bytes total
			expect(encoded.length).to.equal(34);
		});

		it('should encode shortChannelId as exactly 8 bytes', function () {
			const scid = Buffer.alloc(8, 0xab);
			const data: IBlindedHopData = { shortChannelId: scid };
			const encoded = encodeBlindedHopData(data);
			// 1 byte flags + 8 bytes scid = 9 bytes total
			expect(encoded.length).to.equal(9);
		});
	});

	// ── Blinded path construction ──────────────────────────────────────

	describe('Blinded path construction', function () {
		it('should construct a blinded path with a single hop', function () {
			const blindingSecret = randomPrivkey();
			const nodePrivkey = randomPrivkey();
			const nodePubkey = getPublicKey(nodePrivkey);

			const hopData: IBlindedHopData = {};

			const path = constructBlindedPath(
				blindingSecret,
				[nodePubkey],
				[hopData]
			);
			expect(path.blindedHops.length).to.equal(1);
		});

		it('should construct a blinded path with 3 hops', function () {
			const blindingSecret = randomPrivkey();
			const nodeKeys = [randomPrivkey(), randomPrivkey(), randomPrivkey()];
			const nodePubkeys = nodeKeys.map((k) => getPublicKey(k));

			const hopDataList: IBlindedHopData[] = [
				{ nextNodeId: nodePubkeys[1] },
				{ nextNodeId: nodePubkeys[2] },
				{} // final hop
			];

			const path = constructBlindedPath(
				blindingSecret,
				nodePubkeys,
				hopDataList
			);
			expect(path.blindedHops.length).to.equal(3);
		});

		it('should return the correct introductionNodeId', function () {
			const blindingSecret = randomPrivkey();
			const nodeKeys = [randomPrivkey(), randomPrivkey()];
			const nodePubkeys = nodeKeys.map((k) => getPublicKey(k));

			const hopDataList: IBlindedHopData[] = [
				{ nextNodeId: nodePubkeys[1] },
				{}
			];

			const path = constructBlindedPath(
				blindingSecret,
				nodePubkeys,
				hopDataList
			);
			expect(path.introductionNodeId.equals(nodePubkeys[0])).to.be.true;
		});

		it('should return a blinding point as a valid compressed pubkey', function () {
			const blindingSecret = randomPrivkey();
			const nodePubkey = getPublicKey(randomPrivkey());

			const path = constructBlindedPath(blindingSecret, [nodePubkey], [{}]);
			expect(path.blindingPoint.length).to.equal(33);
			expect(path.blindingPoint[0] === 0x02 || path.blindingPoint[0] === 0x03)
				.to.be.true;
			// Blinding point should equal getPublicKey(blindingSecret)
			const expectedBP = getPublicKey(blindingSecret);
			expect(path.blindingPoint.equals(expectedBP)).to.be.true;
		});

		it('should give each hop a blinded node ID', function () {
			const blindingSecret = randomPrivkey();
			const nodeKeys = [randomPrivkey(), randomPrivkey()];
			const nodePubkeys = nodeKeys.map((k) => getPublicKey(k));

			const path = constructBlindedPath(blindingSecret, nodePubkeys, [
				{ nextNodeId: nodePubkeys[1] },
				{}
			]);

			for (const hop of path.blindedHops) {
				expect(hop.blindedNodeId.length).to.equal(33);
				expect(hop.blindedNodeId[0] === 0x02 || hop.blindedNodeId[0] === 0x03)
					.to.be.true;
			}
		});

		it('should give each hop encrypted data', function () {
			const blindingSecret = randomPrivkey();
			const nodePubkeys = [
				getPublicKey(randomPrivkey()),
				getPublicKey(randomPrivkey())
			];

			const path = constructBlindedPath(blindingSecret, nodePubkeys, [
				{ nextNodeId: nodePubkeys[1] },
				{}
			]);

			for (const hop of path.blindedHops) {
				expect(hop.encryptedData.length).to.be.greaterThan(0);
			}
		});

		it('should throw for an empty path', function () {
			const blindingSecret = randomPrivkey();
			expect(() => constructBlindedPath(blindingSecret, [], [])).to.throw(
				'Path must have at least one node'
			);
		});

		it('should throw for mismatched node/data lengths', function () {
			const blindingSecret = randomPrivkey();
			const nodePubkeys = [getPublicKey(randomPrivkey())];
			expect(() =>
				constructBlindedPath(blindingSecret, nodePubkeys, [{}, {}])
			).to.throw('Must have same number of nodes and hop data');
		});

		it('should produce blinded node IDs that differ from real pubkeys', function () {
			const blindingSecret = randomPrivkey();
			const nodeKeys = [randomPrivkey(), randomPrivkey()];
			const nodePubkeys = nodeKeys.map((k) => getPublicKey(k));

			const path = constructBlindedPath(blindingSecret, nodePubkeys, [
				{ nextNodeId: nodePubkeys[1] },
				{}
			]);

			expect(path.blindedHops[0].blindedNodeId.equals(nodePubkeys[0])).to.be
				.false;
			expect(path.blindedHops[1].blindedNodeId.equals(nodePubkeys[1])).to.be
				.false;
		});

		it('should produce different paths from different blinding secrets', function () {
			const secret1 = randomPrivkey();
			const secret2 = randomPrivkey();
			const nodePubkeys = [getPublicKey(randomPrivkey())];
			const hopData: IBlindedHopData[] = [{}];

			const path1 = constructBlindedPath(secret1, nodePubkeys, hopData);
			const path2 = constructBlindedPath(secret2, nodePubkeys, hopData);

			expect(path1.blindingPoint.equals(path2.blindingPoint)).to.be.false;
			expect(
				path1.blindedHops[0].blindedNodeId.equals(
					path2.blindedHops[0].blindedNodeId
				)
			).to.be.false;
		});
	});

	// ── Blinded hop processing ─────────────────────────────────────────

	describe('Blinded hop processing', function () {
		it('should decrypt data correctly at a single hop', function () {
			const blindingSecret = randomPrivkey();
			const nodePrivkey = randomPrivkey();
			const nodePubkey = getPublicKey(nodePrivkey);

			const originalData: IBlindedHopData = {
				paymentRelay: {
					cltvExpiryDelta: 40,
					feeProportionalMillionths: 1000,
					feeBaseMsat: 500
				}
			};

			const path = constructBlindedPath(
				blindingSecret,
				[nodePubkey],
				[originalData]
			);

			const { hopData } = processBlindedHop(
				path.blindingPoint,
				nodePrivkey,
				path.blindedHops[0].encryptedData
			);

			expect(hopData.paymentRelay).to.not.be.undefined;
			expect(hopData.paymentRelay!.cltvExpiryDelta).to.equal(40);
			expect(hopData.paymentRelay!.feeProportionalMillionths).to.equal(1000);
			expect(hopData.paymentRelay!.feeBaseMsat).to.equal(500);
		});

		it('should return a next blinding key', function () {
			const blindingSecret = randomPrivkey();
			const nodePrivkey = randomPrivkey();
			const nodePubkey = getPublicKey(nodePrivkey);

			const path = constructBlindedPath(blindingSecret, [nodePubkey], [{}]);

			const { nextBlindingKey } = processBlindedHop(
				path.blindingPoint,
				nodePrivkey,
				path.blindedHops[0].encryptedData
			);

			expect(nextBlindingKey.length).to.equal(33);
			expect(nextBlindingKey[0] === 0x02 || nextBlindingKey[0] === 0x03).to.be
				.true;
			expect(nextBlindingKey.equals(path.blindingPoint)).to.be.false;
		});

		it('should process a full chain: construct then process each hop', function () {
			const blindingSecret = randomPrivkey();
			const nodeKeys = [randomPrivkey(), randomPrivkey(), randomPrivkey()];
			const nodePubkeys = nodeKeys.map((k) => getPublicKey(k));

			const hopDataList: IBlindedHopData[] = [
				{
					nextNodeId: nodePubkeys[1],
					shortChannelId: Buffer.from('0001000200030004', 'hex')
				},
				{
					nextNodeId: nodePubkeys[2],
					shortChannelId: Buffer.from('0005000600070008', 'hex')
				},
				{
					paymentConstraints: {
						maxCltvExpiry: 1000000,
						htlcMinimumMsat: 1000n
					}
				}
			];

			const path = constructBlindedPath(
				blindingSecret,
				nodePubkeys,
				hopDataList
			);

			// Process hop 0 (introduction node)
			let currentBlindingKey = path.blindingPoint;
			const result0 = processBlindedHop(
				currentBlindingKey,
				nodeKeys[0],
				path.blindedHops[0].encryptedData
			);
			expect(result0.hopData.nextNodeId).to.not.be.undefined;
			expect(result0.hopData.nextNodeId!.equals(nodePubkeys[1])).to.be.true;
			expect(result0.hopData.shortChannelId!.toString('hex')).to.equal(
				'0001000200030004'
			);

			// Process hop 1
			currentBlindingKey = result0.nextBlindingKey;
			const result1 = processBlindedHop(
				currentBlindingKey,
				nodeKeys[1],
				path.blindedHops[1].encryptedData
			);
			expect(result1.hopData.nextNodeId).to.not.be.undefined;
			expect(result1.hopData.nextNodeId!.equals(nodePubkeys[2])).to.be.true;
			expect(result1.hopData.shortChannelId!.toString('hex')).to.equal(
				'0005000600070008'
			);

			// Process hop 2 (final)
			currentBlindingKey = result1.nextBlindingKey;
			const result2 = processBlindedHop(
				currentBlindingKey,
				nodeKeys[2],
				path.blindedHops[2].encryptedData
			);
			expect(result2.hopData.nextNodeId).to.be.undefined;
			expect(result2.hopData.paymentConstraints).to.not.be.undefined;
			expect(result2.hopData.paymentConstraints!.maxCltvExpiry).to.equal(
				1000000
			);
			expect(result2.hopData.paymentConstraints!.htlcMinimumMsat).to.equal(
				1000n
			);
		});

		it('should preserve nextNodeId through construct and process round-trip', function () {
			const blindingSecret = randomPrivkey();
			const nodePrivkey = randomPrivkey();
			const nodePubkey = getPublicKey(nodePrivkey);
			const nextNode = getPublicKey(randomPrivkey());

			const originalData: IBlindedHopData = { nextNodeId: nextNode };

			const path = constructBlindedPath(
				blindingSecret,
				[nodePubkey],
				[originalData]
			);

			const { hopData } = processBlindedHop(
				path.blindingPoint,
				nodePrivkey,
				path.blindedHops[0].encryptedData
			);

			expect(hopData.nextNodeId).to.not.be.undefined;
			expect(hopData.nextNodeId!.equals(nextNode)).to.be.true;
		});

		it('should produce next blinding key consistent with key chain derivation', function () {
			const blindingSecret = randomPrivkey();
			const nodeKeys = [randomPrivkey(), randomPrivkey()];
			const nodePubkeys = nodeKeys.map((k) => getPublicKey(k));

			const { blindingKeys } = deriveBlindingKeyChain(
				blindingSecret,
				nodePubkeys
			);

			const path = constructBlindedPath(blindingSecret, nodePubkeys, [
				{ nextNodeId: nodePubkeys[1] },
				{}
			]);

			const { nextBlindingKey } = processBlindedHop(
				path.blindingPoint,
				nodeKeys[0],
				path.blindedHops[0].encryptedData
			);

			// The next blinding key from processing hop 0 should equal
			// the blinding key at hop 1 from the chain derivation
			expect(nextBlindingKey.equals(blindingKeys[1])).to.be.true;
		});
	});

	// ── Hop payload TLV types 10/12 ────────────────────────────────────

	describe('Hop payload TLV types 10/12', function () {
		it('should encode a hop payload with encryptedRecipientData (type 10)', function () {
			const encData = crypto.randomBytes(64);
			const payload = {
				amountToForwardMsat: 50000n,
				outgoingCltvValue: 144,
				encryptedRecipientData: encData
			};

			const encoded = encodeHopPayload(payload);
			const { payload: decoded } = decodeHopPayload(encoded, 0);

			expect(decoded.encryptedRecipientData).to.not.be.undefined;
			expect(decoded.encryptedRecipientData!.equals(encData)).to.be.true;
		});

		it('should encode a hop payload with blindingPoint (type 12)', function () {
			const bp = getPublicKey(randomPrivkey());
			const payload = {
				amountToForwardMsat: 100000n,
				outgoingCltvValue: 40,
				blindingPoint: bp
			};

			const encoded = encodeHopPayload(payload);
			const { payload: decoded } = decodeHopPayload(encoded, 0);

			expect(decoded.blindingPoint).to.not.be.undefined;
			expect(decoded.blindingPoint!.equals(bp)).to.be.true;
		});

		it('should decode both type 10 and type 12 from the same payload', function () {
			const encData = crypto.randomBytes(48);
			const bp = getPublicKey(randomPrivkey());
			const payload = {
				amountToForwardMsat: 75000n,
				outgoingCltvValue: 80,
				encryptedRecipientData: encData,
				blindingPoint: bp
			};

			const encoded = encodeHopPayload(payload);
			const { payload: decoded } = decodeHopPayload(encoded, 0);

			expect(decoded.encryptedRecipientData).to.not.be.undefined;
			expect(decoded.encryptedRecipientData!.equals(encData)).to.be.true;
			expect(decoded.blindingPoint).to.not.be.undefined;
			expect(decoded.blindingPoint!.equals(bp)).to.be.true;
			expect(decoded.amountToForwardMsat).to.equal(75000n);
			expect(decoded.outgoingCltvValue).to.equal(80);
		});

		it('should round-trip hop payload with blinding TLV fields', function () {
			const encData = crypto.randomBytes(32);
			const bp = getPublicKey(randomPrivkey());
			const scid = Buffer.from('0000000100000002', 'hex');
			const payload = {
				amountToForwardMsat: 200000n,
				outgoingCltvValue: 288,
				shortChannelId: scid,
				encryptedRecipientData: encData,
				blindingPoint: bp
			};

			const encoded = encodeHopPayload(payload);
			const { payload: decoded, bytesRead } = decodeHopPayload(encoded, 0);

			expect(bytesRead).to.equal(encoded.length);
			expect(decoded.amountToForwardMsat).to.equal(200000n);
			expect(decoded.outgoingCltvValue).to.equal(288);
			expect(decoded.shortChannelId!.equals(scid)).to.be.true;
			expect(decoded.encryptedRecipientData!.equals(encData)).to.be.true;
			expect(decoded.blindingPoint!.equals(bp)).to.be.true;
		});
	});
});
