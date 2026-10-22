/**
 * Shared hash constructions (issue #1697). The taggedHash vectors were
 * computed independently with Python hashlib. The call-site digests are the
 * bytes each site's private copy produced before it moved to crypto/hash.ts,
 * so a change to any of them breaks a signature a peer already checks.
 */

import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';

import { taggedHash } from '../../src/lightning/crypto/hash';
import { deriveTaprootFundingKey } from '../../src/lightning/crypto/musig';
import {
	receiverGrantDigest,
	registrationRequestDigest
} from '../../src/lightning/async-payments/receiver-grant';
import {
	deriveHoldRegistrationId,
	releaseCapabilityDigest
} from '../../src/lightning/async-payments/release-capability';
import {
	computeSignatureHash,
	taggedHash as offerTaggedHash
} from '../../src/lightning/offer/merkle';
import { guardianTaggedHash } from '../../src/lightning/recovery/guardian-wire';
import { tweakTaprootKeyPathPrivkey } from '../../src/lightning/script/commitment-taproot';
import { ecc } from '../../src/utils/ecc';

bitcoin.initEccLib(ecc);

const hex = (b: Buffer): string => b.toString('hex');
const fill = (length: number, byte: number): Buffer =>
	Buffer.alloc(length, byte);
const pubkey = (byte: number): Buffer =>
	Buffer.from(ecc.pointFromScalar(fill(32, byte), true)!);

describe('taggedHash', function () {
	it('matches the BIP341 key-path tweak vector', function () {
		const internalKey = Buffer.from(
			'd6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d',
			'hex'
		);
		expect(hex(taggedHash('TapTweak', internalKey))).to.equal(
			'b86e7be8f39bab32a6f2c0443abbc210f0edac0e2c53d501b36b64437d9c6c70'
		);
	});

	it('hashes a string tag as its UTF-8 bytes', function () {
		const tag = 'beignet/tëst/v1';
		const expected =
			'c37021ec558f31be22e3408a2c7aaa55acd1035b3f638bfbea3f862cc597fe80';
		expect(hex(taggedHash(tag, Buffer.from([1, 2, 3])))).to.equal(expected);
		expect(
			hex(taggedHash(Buffer.from(tag, 'utf8'), Buffer.from([1, 2, 3])))
		).to.equal(expected);
	});

	it('takes a byte tag as is', function () {
		const tag = Buffer.from('4c6e4e6f6e6365ff00', 'hex');
		expect(hex(taggedHash(tag, Buffer.from([1])))).to.equal(
			'c0e419d41ca65d38904ef8109efb39bf0614125e7ed2fc0a52b38c322a9cce07'
		);
	});

	it('hashes several messages as their concatenation', function () {
		const expected =
			'6b73e7e55fd43e108e82cd5429010005094fbfd0dd6db14e2d801e0a53c44d8e';
		expect(
			hex(taggedHash('LnBranch', fill(32, 0x11), fill(32, 0x22)))
		).to.equal(expected);
		expect(
			hex(
				taggedHash('LnBranch', Buffer.concat([fill(32, 0x11), fill(32, 0x22)]))
			)
		).to.equal(expected);
	});

	it('agrees with bitcoinjs-lib on every tag it precomputes', function () {
		const message = Buffer.from('beignet', 'utf8');
		for (const tag of bitcoin.crypto.TAGS) {
			expect(hex(taggedHash(tag, message)), tag).to.equal(
				hex(bitcoin.crypto.taggedHash(tag, message))
			);
		}
	});
});

describe('taggedHash call sites', function () {
	it('BOLT 12 offer taggedHash and signature hash', function () {
		expect(hex(offerTaggedHash('TestTag', Buffer.from('test')))).to.equal(
			'8675f0ea2883703eb53f00baad36e3c3dc1966de3a723c4746dad639db3be657'
		);
		expect(
			hex(
				computeSignatureHash('lightninginvoice_requestsignature', fill(32, 7))
			)
		).to.equal(
			'9b90e09b9f7302e7d72ef08a9a89e1debc9b6dad55ffd9a7c2dd64b7c1eecd6b'
		);
	});

	it('guardian transcript tag', function () {
		expect(
			hex(guardianTaggedHash('beignet/recovery/receipt/v1', fill(10, 9)))
		).to.equal(
			'7e8fb76ef372159eaac2afe5560c69ff776ce04fb2f0b67e04977731b278cc27'
		);
	});

	it('async-payments release capability and hold registration id', function () {
		expect(hex(deriveHoldRegistrationId(pubkey(1), pubkey(2)))).to.equal(
			'1df6fc9a794fed9313e026c4d40abb9fb414e7e23ae2c6693a126f0d442a55fe'
		);
		const digest = releaseCapabilityDigest({
			version: 1,
			chainHash: fill(32, 3),
			receiverNodeId: pubkey(1),
			lspNodeId: pubkey(2),
			registrationId: fill(32, 4),
			amountMsat: 123456n,
			expiresAt: 1700000000n,
			nonce: fill(32, 5),
			holdIds: [fill(32, 0xbb), fill(32, 0xaa)]
		});
		expect(hex(digest)).to.equal(
			'd0cee61f1483b6b9ba3b962ecd422ff2ab9aca6a82dd284f6b7b4a15b2813d37'
		);
	});

	it('async-payments registration request and receiver grant', function () {
		const request = registrationRequestDigest({
			version: 1,
			chainHash: fill(32, 3),
			receiverNodeId: pubkey(1),
			lspNodeId: pubkey(2),
			scid: fill(8, 6),
			requestedHoldBlocks: 144,
			timestamp: 1700000000n,
			nonce: fill(32, 5)
		});
		expect(hex(request)).to.equal(
			'bcc1fa87d212c83cb956115e0bcb8b32af0452e14a59907834aa549431ed6e16'
		);
		const grant = receiverGrantDigest({
			version: 1,
			featureBit: 155,
			serviceFlags: 0,
			chainHash: fill(32, 3),
			receiverNodeId: pubkey(1),
			lspNodeId: pubkey(2),
			registrationId: fill(32, 4),
			scid: fill(8, 6),
			maxPartMsat: 1n,
			maxPaymentMsat: 2n,
			maxParts: 3,
			maxHeldMsat: 4n,
			maxHoldBlocks: 5,
			minRemainingCltv: 6,
			admissionFeeMsat: 7n,
			holdingFeeMsatPerBlock: 8n,
			feeCollection: 1,
			creditMsat: 9n,
			issuedAt: 10n,
			expiresAt: 11n,
			nonce: fill(32, 5),
			witnessProfile: fill(32, 0)
		});
		expect(hex(grant)).to.equal(
			'e92da17a0068c9a4c73d13a0ab5d0c37f0fd43e2b44c7ade6a4b08eed301587b'
		);
	});

	it('MuSig2 taproot funding key tweak', function () {
		const key = deriveTaprootFundingKey(pubkey(1), pubkey(2));
		expect(hex(key.tweak)).to.equal(
			'2f44107e4c32b36d126d0ec2d8011f88fb20765d2d7a45a96b80dc2a0eb1e28a'
		);
		expect(hex(key.outputKey)).to.equal(
			'84e1f2a11221025c23b8fb00fd995107412404e43a48dac28fdb2ef7ffe817ce'
		);
		const p2tr = bitcoin.payments.p2tr({ internalPubkey: key.internalKey });
		expect(hex(p2tr.pubkey!)).to.equal(hex(key.outputKey));
	});

	const KEY_PATH_VECTORS = [
		{
			parity: 'odd',
			privkey: fill(32, 0x11),
			tweaked:
				'f1c7684bafd3ea04ba41305a71ac2f82b67bc7497614ebf24ec9a6a8dea4450b'
		},
		{
			parity: 'even',
			privkey: fill(32, 0x03),
			tweaked:
				'dcfcb6c91577201bac8b9207db35763be2e68df86730c0e40c048d8642ed5611'
		}
	];

	for (const { parity, privkey, tweaked } of KEY_PATH_VECTORS) {
		it(`taproot key-path private key tweak, ${parity} internal key`, function () {
			const merkleRoot = fill(32, 0x22);
			const internal = Buffer.from(ecc.pointFromScalar(privkey, true)!);
			expect(internal[0]).to.equal(parity === 'odd' ? 0x03 : 0x02);

			const result = tweakTaprootKeyPathPrivkey(privkey, merkleRoot);
			expect(hex(result)).to.equal(tweaked);
			// The tweaked key must control the output BIP341 derives.
			const p2tr = bitcoin.payments.p2tr({
				internalPubkey: internal.subarray(1),
				hash: merkleRoot
			});
			const tweakedPub = Buffer.from(ecc.pointFromScalar(result, true)!);
			expect(hex(tweakedPub.subarray(1))).to.equal(hex(p2tr.pubkey!));
		});
	}
});
