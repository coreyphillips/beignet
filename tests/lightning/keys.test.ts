import { expect } from 'chai';
import crypto from 'crypto';
import {
	derivePublicKey,
	derivePrivateKey,
	deriveRevocationPubkey,
	deriveRevocationPrivkey,
	perCommitmentPointFromSecret
} from '../../src/lightning/keys/derivation';
import {
	generateFromSeed,
	ShaChainStore,
	MAX_INDEX
} from '../../src/lightning/keys/shachain';
import { ChannelSigner } from '../../src/lightning/keys/signer';
import {
	getPublicKey,
	privateAdd,
	privateMultiply
} from '../../src/lightning/crypto/ecdh';

describe('Lightning Key Derivation (BOLT 3)', function () {
	// ─── Key Derivation Tests ───────────────────────────────────

	describe('Per-Commitment Key Derivation', function () {
		it('Should derive a public key from basepoint and per_commitment_point', function () {
			const basepointPriv = crypto.randomBytes(32);
			const perCommitmentPriv = crypto.randomBytes(32);
			const basepoint = getPublicKey(basepointPriv);
			const perCommitmentPoint = getPublicKey(perCommitmentPriv);

			const derivedPub = derivePublicKey(basepoint, perCommitmentPoint);
			expect(derivedPub.length).to.equal(33);

			// Should be deterministic
			const derivedPub2 = derivePublicKey(basepoint, perCommitmentPoint);
			expect(derivedPub.equals(derivedPub2)).to.be.true;
		});

		it('Should derive matching private and public keys', function () {
			const basepointPriv = crypto.randomBytes(32);
			const perCommitmentPriv = crypto.randomBytes(32);
			const basepoint = getPublicKey(basepointPriv);
			const perCommitmentPoint = getPublicKey(perCommitmentPriv);

			const derivedPub = derivePublicKey(basepoint, perCommitmentPoint);
			const derivedPriv = derivePrivateKey(
				basepointPriv,
				perCommitmentPoint,
				basepoint
			);

			// The derived private key should correspond to the derived public key
			const pubFromPriv = getPublicKey(derivedPriv);
			expect(pubFromPriv.equals(derivedPub)).to.be.true;
		});

		it('Should produce different keys for different commitment points', function () {
			const basepointPriv = crypto.randomBytes(32);
			const basepoint = getPublicKey(basepointPriv);

			const commitPriv1 = crypto.randomBytes(32);
			const commitPriv2 = crypto.randomBytes(32);
			const point1 = getPublicKey(commitPriv1);
			const point2 = getPublicKey(commitPriv2);

			const derived1 = derivePublicKey(basepoint, point1);
			const derived2 = derivePublicKey(basepoint, point2);

			expect(derived1.equals(derived2)).to.be.false;
		});
	});

	describe('Revocation Key Derivation', function () {
		it('Should derive a revocation public key', function () {
			const revBasepointPriv = crypto.randomBytes(32);
			const perCommitmentPriv = crypto.randomBytes(32);
			const revBasepoint = getPublicKey(revBasepointPriv);
			const perCommitmentPoint = getPublicKey(perCommitmentPriv);

			const revPub = deriveRevocationPubkey(revBasepoint, perCommitmentPoint);
			expect(revPub.length).to.equal(33);
		});

		it('Should derive matching revocation private and public keys', function () {
			const revBasepointPriv = crypto.randomBytes(32);
			const perCommitmentPriv = crypto.randomBytes(32);
			const revBasepoint = getPublicKey(revBasepointPriv);
			const perCommitmentPoint = getPublicKey(perCommitmentPriv);

			const revPub = deriveRevocationPubkey(revBasepoint, perCommitmentPoint);
			const revPriv = deriveRevocationPrivkey(
				revBasepointPriv,
				perCommitmentPriv,
				revBasepoint,
				perCommitmentPoint
			);

			const pubFromPriv = getPublicKey(revPriv);
			expect(pubFromPriv.equals(revPub)).to.be.true;
		});

		it('Should be deterministic', function () {
			const revBasepointPriv = crypto.randomBytes(32);
			const perCommitmentPriv = crypto.randomBytes(32);
			const revBasepoint = getPublicKey(revBasepointPriv);
			const perCommitmentPoint = getPublicKey(perCommitmentPriv);

			const revPub1 = deriveRevocationPubkey(revBasepoint, perCommitmentPoint);
			const revPub2 = deriveRevocationPubkey(revBasepoint, perCommitmentPoint);
			expect(revPub1.equals(revPub2)).to.be.true;
		});
	});

	describe('Per-Commitment Point', function () {
		it('Should derive point from secret', function () {
			const secret = crypto.randomBytes(32);
			const point = perCommitmentPointFromSecret(secret);
			expect(point.length).to.equal(33);

			// Should match getPublicKey
			const expected = getPublicKey(secret);
			expect(point.equals(expected)).to.be.true;
		});
	});

	// ─── privateAdd / privateMultiply Tests ─────────────────────

	describe('Private Key Operations', function () {
		it('Should add two private keys', function () {
			const key1 = crypto.randomBytes(32);
			const key2 = crypto.randomBytes(32);

			const sum = privateAdd(key1, key2);
			expect(sum.length).to.equal(32);

			// Verify: pubkey(sum) should equal pointAdd(pubkey(key1), pubkey(key2))
			// This is the additive homomorphism of EC
		});

		it('Should multiply two private keys', function () {
			const key1 = crypto.randomBytes(32);
			const key2 = crypto.randomBytes(32);

			const product = privateMultiply(key1, key2);
			expect(product.length).to.equal(32);
		});

		it('Should reject invalid key lengths', function () {
			expect(() => privateAdd(Buffer.alloc(16), Buffer.alloc(32))).to.throw(
				'32 bytes'
			);
			expect(() => privateAdd(Buffer.alloc(32), Buffer.alloc(16))).to.throw(
				'32 bytes'
			);
		});
	});

	// ─── Shachain Tests ─────────────────────────────────────────

	describe('Shachain', function () {
		it('Should generate a deterministic secret from seed', function () {
			const seed = crypto.randomBytes(32);

			const secret1 = generateFromSeed(seed, 0n);
			const secret2 = generateFromSeed(seed, 0n);
			expect(secret1.equals(secret2)).to.be.true;
			expect(secret1.length).to.equal(32);
		});

		it('Should generate different secrets for different indices', function () {
			const seed = crypto.randomBytes(32);

			const secret0 = generateFromSeed(seed, 0n);
			const secret1 = generateFromSeed(seed, 1n);
			expect(secret0.equals(secret1)).to.be.false;
		});

		it('Should generate a secret at MAX_INDEX', function () {
			const seed = crypto.randomBytes(32);
			const secret = generateFromSeed(seed, MAX_INDEX);
			expect(secret.length).to.equal(32);
		});

		it('Should reject invalid seed length', function () {
			expect(() => generateFromSeed(Buffer.alloc(16), 0n)).to.throw('32 bytes');
		});

		it('Should reject out-of-range index', function () {
			const seed = crypto.randomBytes(32);
			expect(() => generateFromSeed(seed, -1n)).to.throw();
			expect(() => generateFromSeed(seed, MAX_INDEX + 1n)).to.throw();
		});

		describe('ShaChainStore', function () {
			it('Should store and retrieve a secret', function () {
				const seed = crypto.randomBytes(32);
				const store = new ShaChainStore();

				const idx = MAX_INDEX;
				const secret = generateFromSeed(seed, idx);
				const ok = store.addSecret(idx, secret);
				expect(ok).to.be.true;

				const retrieved = store.getSecret(idx);
				expect(retrieved).to.not.be.null;
				expect(retrieved!.equals(secret)).to.be.true;
			});

			it('Should store multiple secrets and derive intermediates', function () {
				const seed = crypto.randomBytes(32);
				const store = new ShaChainStore();

				// Add secrets in decreasing index order
				const count = 8;
				for (let i = 0; i < count; i++) {
					const idx = MAX_INDEX - BigInt(i);
					const secret = generateFromSeed(seed, idx);
					const ok = store.addSecret(idx, secret);
					expect(ok).to.be.true;
				}

				// Should be able to retrieve all added secrets
				for (let i = 0; i < count; i++) {
					const idx = MAX_INDEX - BigInt(i);
					const expected = generateFromSeed(seed, idx);
					const retrieved = store.getSecret(idx);
					expect(retrieved).to.not.be.null;
					expect(retrieved!.equals(expected)).to.be.true;
				}
			});

			it('Should reject an invalid secret', function () {
				const seed = crypto.randomBytes(32);
				const store = new ShaChainStore();

				// Add first secret
				const idx0 = MAX_INDEX;
				const secret0 = generateFromSeed(seed, idx0);
				store.addSecret(idx0, secret0);

				// Try to add a wrong secret for the next index
				const idx1 = MAX_INDEX - 1n;
				const wrongSecret = crypto.randomBytes(32);
				const ok = store.addSecret(idx1, wrongSecret);
				expect(ok).to.be.false;
			});

			it('Should maintain compact storage', function () {
				const seed = crypto.randomBytes(32);
				const store = new ShaChainStore();

				// Add many secrets — storage should stay compact
				const count = 100;
				for (let i = 0; i < count; i++) {
					const idx = MAX_INDEX - BigInt(i);
					const secret = generateFromSeed(seed, idx);
					store.addSecret(idx, secret);
				}

				// Should have far fewer than 100 entries stored
				expect(store.getEntryCount()).to.be.lessThan(50);
				expect(store.getKnownCount()).to.equal(BigInt(count));
			});

			it('Should reject invalid secret length', function () {
				const store = new ShaChainStore();
				expect(() => store.addSecret(MAX_INDEX, Buffer.alloc(16))).to.throw(
					'32 bytes'
				);
			});
		});
	});

	// ─── ChannelSigner Tests ────────────────────────────────────

	describe('ChannelSigner', function () {
		it('Should create a signer with correct public key', function () {
			const priv = crypto.randomBytes(32);
			const signer = new ChannelSigner(priv);

			const expectedPub = getPublicKey(priv);
			expect(signer.fundingPubkey.equals(expectedPub)).to.be.true;
		});

		it('Should reject invalid private key length', function () {
			expect(() => new ChannelSigner(Buffer.alloc(16))).to.throw('32 bytes');
		});
	});
});
