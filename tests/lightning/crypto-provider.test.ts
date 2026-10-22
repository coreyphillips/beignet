/**
 * The crypto provider seam (issue #1696): Node's crypto by default, every
 * primitive checked against a known-answer vector before use, and a host
 * provider swapped in for the whole library.
 */

import { expect } from 'chai';
import nodeCrypto from 'crypto';
import fs from 'fs';
import path from 'path';

import type { ICryptoProvider } from '../../src/lightning/crypto/provider';
import {
	aes256GcmDecrypt,
	aes256GcmEncrypt,
	chacha20,
	chacha20Poly1305Decrypt,
	chacha20Poly1305Encrypt,
	hkdfSha256,
	hmacSha256,
	randomBytes,
	selfTestCryptoProvider,
	setCryptoProvider,
	sha256
} from '../../src/lightning/crypto/provider';
import {
	decrypt as chachaDecrypt,
	encrypt as chachaEncrypt
} from '../../src/lightning/crypto/chacha20poly1305';
import { hkdf } from '../../src/lightning/crypto/hkdf';
import { ecdh, getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	createInitiatorHandshake,
	createResponderHandshake
} from '../../src/lightning/transport/noise';
import { generateCipherStream } from '../../src/lightning/onion/sphinx-crypto';
import {
	decryptValue,
	deriveStorageKey,
	encryptValue
} from '../../src/lightning/storage/encryption';
import {
	decryptFrame,
	encryptFrame
} from '../../src/lightning/recovery/journal';
import { deriveRecoveryRoot } from '../../src/lightning/recovery/guardian-wire';
import { createCountingCryptoProvider } from './helpers/counting-crypto-provider';
import { bufferToHex, hexToBuffer, loadVectors } from './conformance/helpers';

const SRC_LIGHTNING = path.resolve(__dirname, '../../src/lightning');

/**
 * Files under src/lightning that may load Node's crypto at runtime, and why.
 * Everything else goes through the provider.
 */
const NODE_CRYPTO_ALLOWED: Record<string, string> = {
	'crypto/provider.ts': 'the default provider',
	'crypto/ecdh.ts':
		'gossip signature fast path, self-tested with a JS fallback',
	'gossip/messages.ts': 'optional sha3-256 Tor checksum, skipped without it',
	'recovery/guardian-bolt8.ts': 'timingSafeEqual',
	'recovery/guardian-http.ts': 'timingSafeEqual in a Node HTTP server',
	'transport/websocket-server.ts': 'SHA-1 handshake in a Node server'
};

const NODE_CRYPTO_LOAD =
	/^import (?!type )[^;]*from '(node:)?crypto'|require\(\s*'(node:)?crypto'\s*\)/m;

function tsFiles(dir: string): string[] {
	return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
		const full = path.join(dir, entry.name);
		if (entry.isDirectory()) return tsFiles(full);
		return entry.name.endsWith('.ts') ? [full] : [];
	});
}

/** One call per primitive, so each one's vector runs. */
function useEveryPrimitive(): void {
	const key = Buffer.alloc(32, 1);
	sha256(Buffer.alloc(1));
	hmacSha256(key, Buffer.alloc(1));
	hkdfSha256(key, Buffer.alloc(0), Buffer.alloc(0), 32);
	aes256GcmDecrypt(
		key,
		Buffer.alloc(12),
		aes256GcmEncrypt(key, Buffer.alloc(12), Buffer.alloc(1))
	);
	chacha20Poly1305Decrypt(
		key,
		Buffer.alloc(12),
		chacha20Poly1305Encrypt(key, Buffer.alloc(12), Buffer.alloc(1))
	);
	chacha20(key, Buffer.alloc(12), Buffer.alloc(1));
	randomBytes(1);
}

describe('Crypto provider (issue #1696)', () => {
	afterEach(() => {
		setCryptoProvider(null);
	});

	it('serves every primitive from Node by default', () => {
		expect(sha256(Buffer.from('abc')).toString('hex')).to.equal(
			'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
		);
		expect(useEveryPrimitive).to.not.throw();
	});

	it('passes a provider built on Node crypto', () => {
		const { provider } = createCountingCryptoProvider();
		expect(selfTestCryptoProvider(provider)).to.deep.equal([]);
	});

	describe('a swapped-in provider', () => {
		it('runs the BOLT 8 handshake vectors', () => {
			const v = loadVectors<{
				keys: Record<string, string>;
				successful_handshake: Record<string, string>;
			}>('bolt08/transport.json');
			const { provider, calls } = createCountingCryptoProvider();
			setCryptoProvider(provider);
			calls.clear();

			const initiator = createInitiatorHandshake(
				hexToBuffer(v.keys.initiator_ls_priv),
				hexToBuffer(v.keys.responder_ls_pub),
				hexToBuffer(v.keys.initiator_e_priv)
			);
			const responder = createResponderHandshake(
				hexToBuffer(v.keys.responder_ls_priv),
				hexToBuffer(v.keys.responder_e_priv)
			);
			expect(bufferToHex(initiator.act1)).to.equal(v.successful_handshake.act1);
			responder.processAct1(initiator.act1);
			const act2 = responder.createAct2();
			expect(bufferToHex(act2)).to.equal(v.successful_handshake.act2);
			initiator.processAct2(act2);
			const act3 = initiator.createAct3();
			expect(bufferToHex(act3)).to.equal(v.successful_handshake.act3);
			responder.processAct3(act3);
			expect(bufferToHex(initiator.state.ck)).to.equal(
				v.successful_handshake.final_ck
			);

			expect(calls.get('sha256')).to.be.greaterThan(0);
			expect(calls.get('hmacSha256')).to.be.greaterThan(0);
			expect(calls.get('chacha20Poly1305Encrypt')).to.be.greaterThan(0);
			expect(calls.get('chacha20Poly1305Decrypt')).to.be.greaterThan(0);
		});

		it('gives the same bytes as the default for every primitive', () => {
			const key = Buffer.alloc(32, 7);
			const nonce = Buffer.alloc(12, 3);
			const secret = Buffer.alloc(32, 9);
			const iv = Buffer.alloc(12, 5);
			const run = (): string[] => [
				chachaEncrypt(key, nonce, Buffer.from('payload')).toString('hex'),
				hkdf(Buffer.alloc(0), secret).toString('hex'),
				generateCipherStream(key, 40).toString('hex'),
				ecdh(secret, getPublicKey(key)).toString('hex'),
				deriveStorageKey(secret).toString('hex'),
				encryptFrame(
					key,
					Buffer.from('frame'),
					Buffer.from('aad'),
					iv
				).toString('hex'),
				deriveRecoveryRoot(secret).recoveryId.toString('hex')
			];
			const byDefault = run();
			const { provider, calls } = createCountingCryptoProvider();
			setCryptoProvider(provider);
			calls.clear();

			expect(run()).to.deep.equal(byDefault);
			for (const method of [
				'chacha20Poly1305Encrypt',
				'hmacSha256',
				'chacha20',
				'sha256',
				'hkdfSha256',
				'aes256GcmEncrypt'
			] as const) {
				expect(calls.get(method), method).to.be.greaterThan(0);
			}
		});

		it('hands back Buffers although it returns plain Uint8Arrays', () => {
			const { provider } = createCountingCryptoProvider();
			setCryptoProvider(provider);
			const key = Buffer.alloc(32, 7);
			const nonce = Buffer.alloc(12);
			const sealed = chachaEncrypt(key, nonce, Buffer.from('hi'));
			expect(Buffer.isBuffer(sealed)).to.equal(true);
			expect(chachaDecrypt(key, nonce, sealed).toString()).to.equal('hi');
			expect(Buffer.isBuffer(randomBytes(4))).to.equal(true);
		});

		it('copies its results, so reused output memory cannot alias keys', () => {
			// Two output slots used in turn, the way a WASM-backed library can
			// hand back views into its heap. No vector can see this.
			const slots = [new Uint8Array(64), new Uint8Array(64)];
			let turn = 0;
			const reuse = (bytes: Uint8Array): Uint8Array => {
				const slot = slots[turn++ % 2].subarray(0, bytes.length);
				slot.set(bytes);
				return slot;
			};
			const base = createCountingCryptoProvider().provider;
			const reusing: ICryptoProvider = {
				...base,
				sha256: (data) => reuse(base.sha256(data)),
				randomBytes: (size) => reuse(base.randomBytes(size))
			};
			expect(selfTestCryptoProvider(reusing)).to.deep.equal([]);
			setCryptoProvider(reusing);

			const preimage = randomBytes(32);
			const drawn = Buffer.from(preimage);
			randomBytes(32);
			const sessionKey = randomBytes(32);
			expect(preimage.equals(drawn)).to.equal(true);
			expect(preimage.equals(sessionKey)).to.equal(false);

			const digest = sha256(Buffer.from('abc'));
			sha256(Buffer.from('a'));
			sha256(Buffer.from('b'));
			expect(digest.toString('hex')).to.equal(
				'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
			);
		});

		it('decrypts what the default encrypted', () => {
			const key = deriveStorageKey(Buffer.alloc(32, 1));
			const row = encryptValue(key, 'stored before the swap');
			const frame = encryptFrame(
				key,
				Buffer.from('frame'),
				Buffer.from('aad'),
				Buffer.alloc(12, 2)
			);
			setCryptoProvider(createCountingCryptoProvider().provider);
			expect(decryptValue(key, row)).to.equal('stored before the swap');
			expect(decryptFrame(key, frame, Buffer.from('aad')).toString()).to.equal(
				'frame'
			);
		});
	});

	describe('a provider that fails a vector', () => {
		const broken = (patch: Partial<ICryptoProvider>): ICryptoProvider => ({
			...createCountingCryptoProvider().provider,
			...patch
		});

		it('is refused, and the current provider stays', () => {
			const { provider, calls } = createCountingCryptoProvider();
			setCryptoProvider(provider);
			expect(() =>
				setCryptoProvider(broken({ sha256: () => new Uint8Array(32) }))
			).to.throw('Crypto provider failed its self-test: sha256');
			calls.clear();
			sha256(Buffer.alloc(1));
			expect(calls.get('sha256')).to.equal(1);
		});

		it('is refused when decryption skips the tag check', () => {
			// GCM's keystream without its tag check: counter block IV || 2.
			const ctr = (
				key: Uint8Array,
				iv: Uint8Array,
				data: Uint8Array
			): Buffer => {
				const counter = Buffer.concat([iv, Buffer.from([0, 0, 0, 2])]);
				const cipher = nodeCrypto.createCipheriv('aes-256-ctr', key, counter);
				return Buffer.concat([cipher.update(data), cipher.final()]);
			};
			const unauthenticated = broken({
				aes256GcmDecrypt: (key, iv, sealed) =>
					ctr(key, iv, sealed.subarray(0, sealed.length - 16))
			});
			expect(selfTestCryptoProvider(unauthenticated)).to.deep.equal([
				'aes256Gcm'
			]);
		});

		it('is refused when randomness is constant', () => {
			expect(
				selfTestCryptoProvider(
					broken({ randomBytes: (size) => new Uint8Array(size).fill(4) })
				)
			).to.deep.equal(['randomBytes']);
		});

		it('is refused when HKDF mishandles an empty salt', () => {
			// Right with a salt, wrong without one, which is how every storage,
			// backup and recovery key is derived.
			const base = createCountingCryptoProvider().provider;
			expect(
				selfTestCryptoProvider(
					broken({
						hkdfSha256: (ikm, salt, info, length) =>
							base.hkdfSha256(
								ikm,
								salt.length > 0 ? salt : Buffer.from('salt'),
								info,
								length
							)
					})
				)
			).to.deep.equal(['hkdfSha256']);
		});

		it('is refused when a method throws', () => {
			expect(
				selfTestCryptoProvider(
					broken({
						chacha20: () => {
							throw new Error('unsupported');
						}
					})
				)
			).to.deep.equal(['chacha20']);
		});
	});

	it('refuses only the platform primitive that fails, and names it', () => {
		const original = nodeCrypto.createCipheriv;
		const patched = ((...args: Parameters<typeof original>) =>
			args[0] === 'chacha20'
				? original('aes-256-ctr', args[1], args[2])
				: original(...args)) as typeof original;
		(nodeCrypto as { createCipheriv: typeof original }).createCipheriv =
			patched;
		try {
			// Clears the cached verdicts so the next use re-runs each vector.
			setCryptoProvider(null);
			expect(() =>
				chacha20(Buffer.alloc(32), Buffer.alloc(12), Buffer.alloc(1))
			).to.throw("The platform's chacha20 failed its self-test");
			expect(sha256(Buffer.from('abc')).length).to.equal(32);
		} finally {
			(nodeCrypto as { createCipheriv: typeof original }).createCipheriv =
				original;
			setCryptoProvider(null);
		}
		expect(() =>
			chacha20(Buffer.alloc(32), Buffer.alloc(12), Buffer.alloc(1))
		).to.not.throw();
	});

	it('leaves Node crypto to a short list of files in src/lightning', () => {
		const loading = tsFiles(SRC_LIGHTNING)
			.filter((file) => NODE_CRYPTO_LOAD.test(fs.readFileSync(file, 'utf8')))
			.map((file) =>
				path.relative(SRC_LIGHTNING, file).split(path.sep).join('/')
			)
			.sort();
		expect(loading).to.deep.equal(Object.keys(NODE_CRYPTO_ALLOWED).sort());
	});
});
