import { expect } from 'chai';
import crypto from 'crypto';
import {
	encrypt,
	decrypt,
	nonceFromCounter,
	KEY_LENGTH,
	TAG_LENGTH
} from '../../src/lightning/crypto/chacha20poly1305';
import {
	hkdf,
	hkdfExtract,
	hkdfExpand,
	hkdf2,
	hkdf3
} from '../../src/lightning/crypto/hkdf';
import {
	ecdh,
	getPublicKey,
	pointMultiply,
	pointAdd,
	isValidPublicKey,
	isValidPrivateKey,
	sign,
	verify
} from '../../src/lightning/crypto/ecdh';

describe('Lightning Crypto', function () {
	describe('ChaCha20-Poly1305', function () {
		it('Should encrypt and decrypt correctly', function () {
			const key = crypto.randomBytes(KEY_LENGTH);
			const nonce = crypto.randomBytes(12);
			const plaintext = Buffer.from('Hello Lightning Network!');

			const ciphertext = encrypt(key, nonce, plaintext);
			const decrypted = decrypt(key, nonce, ciphertext);

			expect(decrypted.equals(plaintext)).to.be.true;
		});

		it('Should encrypt and decrypt empty plaintext', function () {
			const key = crypto.randomBytes(KEY_LENGTH);
			const nonce = crypto.randomBytes(12);
			const plaintext = Buffer.alloc(0);

			const ciphertext = encrypt(key, nonce, plaintext);
			expect(ciphertext.length).to.equal(TAG_LENGTH); // Only tag

			const decrypted = decrypt(key, nonce, ciphertext);
			expect(decrypted.length).to.equal(0);
		});

		it('Should include AAD in authentication', function () {
			const key = crypto.randomBytes(KEY_LENGTH);
			const nonce = crypto.randomBytes(12);
			const plaintext = Buffer.from('secret data');
			const aad = Buffer.from('additional data');

			const ciphertext = encrypt(key, nonce, plaintext, aad);
			const decrypted = decrypt(key, nonce, ciphertext, aad);
			expect(decrypted.equals(plaintext)).to.be.true;

			// Should fail with wrong AAD
			expect(() => {
				decrypt(key, nonce, ciphertext, Buffer.from('wrong aad'));
			}).to.throw();
		});

		it('Should fail with wrong key', function () {
			const key1 = crypto.randomBytes(KEY_LENGTH);
			const key2 = crypto.randomBytes(KEY_LENGTH);
			const nonce = crypto.randomBytes(12);
			const plaintext = Buffer.from('test');

			const ciphertext = encrypt(key1, nonce, plaintext);
			expect(() => decrypt(key2, nonce, ciphertext)).to.throw();
		});

		it('Should fail with tampered ciphertext', function () {
			const key = crypto.randomBytes(KEY_LENGTH);
			const nonce = crypto.randomBytes(12);
			const plaintext = Buffer.from('test data');

			const ciphertext = encrypt(key, nonce, plaintext);
			// Tamper with a ciphertext byte
			ciphertext[0] ^= 0xff;
			expect(() => decrypt(key, nonce, ciphertext)).to.throw();
		});

		it('Should reject invalid key length', function () {
			const nonce = crypto.randomBytes(12);
			const plaintext = Buffer.from('test');

			expect(() => encrypt(Buffer.alloc(16), nonce, plaintext)).to.throw(
				'Key must be 32 bytes'
			);
		});

		it('Should reject invalid nonce length', function () {
			const key = crypto.randomBytes(KEY_LENGTH);
			const plaintext = Buffer.from('test');

			expect(() => encrypt(key, Buffer.alloc(8), plaintext)).to.throw(
				'Nonce must be 12 bytes'
			);
		});

		it('Should reject ciphertext shorter than tag', function () {
			const key = crypto.randomBytes(KEY_LENGTH);
			const nonce = crypto.randomBytes(12);

			expect(() => decrypt(key, nonce, Buffer.alloc(8))).to.throw(
				'Ciphertext too short'
			);
		});

		describe('nonceFromCounter', function () {
			it('Should produce correct nonce for counter 0', function () {
				const nonce = nonceFromCounter(0n);
				expect(nonce.length).to.equal(12);
				expect(nonce.equals(Buffer.alloc(12))).to.be.true;
			});

			it('Should produce correct nonce for counter 1', function () {
				const nonce = nonceFromCounter(1n);
				expect(nonce.length).to.equal(12);
				// 4 zero bytes + 8-byte LE counter (1)
				const expected = Buffer.alloc(12);
				expected[4] = 1;
				expect(nonce.equals(expected)).to.be.true;
			});

			it('Should produce correct nonce for large counter', function () {
				const nonce = nonceFromCounter(1000n);
				expect(nonce.length).to.equal(12);
				const expected = Buffer.alloc(12);
				expected.writeBigUInt64LE(1000n, 4);
				expect(nonce.equals(expected)).to.be.true;
			});
		});
	});

	describe('HKDF', function () {
		it('Should extract a pseudorandom key', function () {
			const salt = Buffer.from('salt');
			const ikm = Buffer.from('input key material');
			const prk = hkdfExtract(salt, ikm);
			expect(prk.length).to.equal(32);
		});

		it('Should produce deterministic output', function () {
			const salt = Buffer.from('salt');
			const ikm = Buffer.from('input key material');
			const out1 = hkdf(salt, ikm);
			const out2 = hkdf(salt, ikm);
			expect(out1.equals(out2)).to.be.true;
		});

		it('Should produce different output for different input', function () {
			const salt = Buffer.from('salt');
			const out1 = hkdf(salt, Buffer.from('ikm1'));
			const out2 = hkdf(salt, Buffer.from('ikm2'));
			expect(out1.equals(out2)).to.be.false;
		});

		it('Should handle empty salt', function () {
			const ikm = Buffer.from('input key material');
			const prk = hkdfExtract(Buffer.alloc(0), ikm);
			expect(prk.length).to.equal(32);
		});

		it('Should expand to requested length', function () {
			const prk = crypto.randomBytes(32);
			const info = Buffer.from('info');

			const out32 = hkdfExpand(prk, info, 32);
			expect(out32.length).to.equal(32);

			const out64 = hkdfExpand(prk, info, 64);
			expect(out64.length).to.equal(64);

			const out128 = hkdfExpand(prk, info, 128);
			expect(out128.length).to.equal(128);
		});

		it('Should reject excessively long output', function () {
			const prk = crypto.randomBytes(32);
			expect(() => hkdfExpand(prk, Buffer.alloc(0), 256 * 32)).to.throw(
				'exceeds maximum'
			);
		});

		describe('hkdf2 (BOLT 8)', function () {
			it('Should return two 32-byte keys', function () {
				const salt = crypto.randomBytes(32);
				const ikm = crypto.randomBytes(32);
				const [ck, k] = hkdf2(salt, ikm);
				expect(ck.length).to.equal(32);
				expect(k.length).to.equal(32);
				expect(ck.equals(k)).to.be.false;
			});
		});

		describe('hkdf3 (BOLT 8)', function () {
			it('Should return three 32-byte keys', function () {
				const salt = crypto.randomBytes(32);
				const ikm = crypto.randomBytes(32);
				const [ck, k1, k2] = hkdf3(salt, ikm);
				expect(ck.length).to.equal(32);
				expect(k1.length).to.equal(32);
				expect(k2.length).to.equal(32);
				// All should be distinct
				expect(ck.equals(k1)).to.be.false;
				expect(ck.equals(k2)).to.be.false;
				expect(k1.equals(k2)).to.be.false;
			});
		});

		// RFC 5869 Test Vector 1
		it('Should match RFC 5869 Test Case 1', function () {
			const ikm = Buffer.from(
				'0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
				'hex'
			);
			const salt = Buffer.from('000102030405060708090a0b0c', 'hex');
			const info = Buffer.from('f0f1f2f3f4f5f6f7f8f9', 'hex');

			const prk = hkdfExtract(salt, ikm);
			expect(prk.toString('hex')).to.equal(
				'077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5'
			);

			const okm = hkdfExpand(prk, info, 42);
			expect(okm.toString('hex')).to.equal(
				'3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865'
			);
		});
	});

	describe('ECDH', function () {
		it('Should compute shared secret between two keypairs', function () {
			const privA = crypto.randomBytes(32);
			const privB = crypto.randomBytes(32);
			const pubA = getPublicKey(privA);
			const pubB = getPublicKey(privB);

			// ECDH should be symmetric
			const ssAB = ecdh(privA, pubB);
			const ssBA = ecdh(privB, pubA);

			expect(ssAB.length).to.equal(32);
			expect(ssAB.equals(ssBA)).to.be.true;
		});

		it('Should reject invalid private key length', function () {
			const pubkey = getPublicKey(crypto.randomBytes(32));
			expect(() => ecdh(Buffer.alloc(16), pubkey)).to.throw('32 bytes');
		});

		it('Should reject invalid public key length', function () {
			const privkey = crypto.randomBytes(32);
			expect(() => ecdh(privkey, Buffer.alloc(32))).to.throw('33 bytes');
		});

		describe('getPublicKey', function () {
			it('Should derive a 33-byte compressed public key', function () {
				const privkey = crypto.randomBytes(32);
				const pubkey = getPublicKey(privkey);
				expect(pubkey.length).to.equal(33);
				expect(pubkey[0] === 0x02 || pubkey[0] === 0x03).to.be.true;
			});

			it('Should produce deterministic output', function () {
				const privkey = crypto.randomBytes(32);
				const pub1 = getPublicKey(privkey);
				const pub2 = getPublicKey(privkey);
				expect(pub1.equals(pub2)).to.be.true;
			});
		});

		describe('pointMultiply', function () {
			it('Should multiply a point by a scalar', function () {
				const privkey = crypto.randomBytes(32);
				const pubkey = getPublicKey(privkey);
				const scalar = crypto.randomBytes(32);

				const result = pointMultiply(pubkey, scalar);
				expect(result.length).to.equal(33);
				expect(isValidPublicKey(result)).to.be.true;
			});
		});

		describe('pointAdd', function () {
			it('Should add two points', function () {
				const pub1 = getPublicKey(crypto.randomBytes(32));
				const pub2 = getPublicKey(crypto.randomBytes(32));

				const result = pointAdd(pub1, pub2);
				expect(result.length).to.equal(33);
				expect(isValidPublicKey(result)).to.be.true;
			});
		});

		describe('isValidPublicKey', function () {
			it('Should validate a valid compressed public key', function () {
				const pubkey = getPublicKey(crypto.randomBytes(32));
				expect(isValidPublicKey(pubkey)).to.be.true;
			});

			it('Should reject a wrong-length buffer', function () {
				expect(isValidPublicKey(Buffer.alloc(32))).to.be.false;
			});

			it('Should reject an invalid point', function () {
				expect(isValidPublicKey(Buffer.alloc(33))).to.be.false;
			});
		});

		describe('isValidPrivateKey', function () {
			it('Should validate a valid private key', function () {
				const privkey = crypto.randomBytes(32);
				// Most random 32-byte values are valid private keys
				// (but not all; the chance of getting an invalid one is negligible)
				expect(isValidPrivateKey(privkey)).to.be.true;
			});

			it('Should reject wrong-length buffer', function () {
				expect(isValidPrivateKey(Buffer.alloc(16))).to.be.false;
			});

			it('Should reject zero scalar', function () {
				expect(isValidPrivateKey(Buffer.alloc(32))).to.be.false;
			});
		});

		describe('sign/verify', function () {
			it('Should sign and verify a message hash', function () {
				const privkey = crypto.randomBytes(32);
				const pubkey = getPublicKey(privkey);
				const messageHash = crypto.createHash('sha256').update('test').digest();

				const signature = sign(messageHash, privkey);
				expect(signature.length).to.equal(64);

				expect(verify(messageHash, pubkey, signature)).to.be.true;
			});

			it('Should fail verification with wrong public key', function () {
				const privkey = crypto.randomBytes(32);
				const wrongPubkey = getPublicKey(crypto.randomBytes(32));
				const messageHash = crypto.createHash('sha256').update('test').digest();

				const signature = sign(messageHash, privkey);
				expect(verify(messageHash, wrongPubkey, signature)).to.be.false;
			});

			it('Should fail verification with wrong message', function () {
				const privkey = crypto.randomBytes(32);
				const pubkey = getPublicKey(privkey);
				const hash1 = crypto.createHash('sha256').update('test1').digest();
				const hash2 = crypto.createHash('sha256').update('test2').digest();

				const signature = sign(hash1, privkey);
				expect(verify(hash2, pubkey, signature)).to.be.false;
			});
		});
	});
});
