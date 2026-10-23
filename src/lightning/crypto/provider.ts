/**
 * The symmetric primitives and randomness the library takes from its
 * platform, behind one replaceable provider.
 *
 * Node's 'crypto' is the default. React Native has no Node crypto, and the
 * shims that stand in for it commonly omit or stub parts of it, so every
 * primitive must pass a known-answer vector before it is used, and a host
 * can install its own implementation with setCryptoProvider. Elliptic-curve
 * work does not come from here: it uses the JS secp256k1 libraries.
 */

import type * as NodeCrypto from 'crypto';

/**
 * What a provider implements. Every method is synchronous and returns fresh
 * bytes. The AEADs return ciphertext || 16-byte tag, and decrypt must throw
 * when the tag does not verify.
 */
export interface ICryptoProvider {
	sha256(data: Uint8Array): Uint8Array;
	hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array;
	/** RFC 5869 extract-then-expand. */
	hkdfSha256(
		ikm: Uint8Array,
		salt: Uint8Array,
		info: Uint8Array,
		length: number
	): Uint8Array;
	/** 32-byte key, 12-byte IV. */
	aes256GcmEncrypt(
		key: Uint8Array,
		iv: Uint8Array,
		plaintext: Uint8Array,
		aad: Uint8Array
	): Uint8Array;
	aes256GcmDecrypt(
		key: Uint8Array,
		iv: Uint8Array,
		sealed: Uint8Array,
		aad: Uint8Array
	): Uint8Array;
	/** RFC 8439 AEAD: 32-byte key, 12-byte nonce. */
	chacha20Poly1305Encrypt(
		key: Uint8Array,
		nonce: Uint8Array,
		plaintext: Uint8Array,
		aad: Uint8Array
	): Uint8Array;
	chacha20Poly1305Decrypt(
		key: Uint8Array,
		nonce: Uint8Array,
		sealed: Uint8Array,
		aad: Uint8Array
	): Uint8Array;
	/** RFC 8439 ChaCha20 from block counter 0: data XOR keystream. */
	chacha20(key: Uint8Array, nonce: Uint8Array, data: Uint8Array): Uint8Array;
	/** Cryptographically secure random bytes. */
	randomBytes(size: number): Uint8Array;
}

/** The unit a self-test passes or fails; an AEAD's two methods are one. */
export type CryptoPrimitive =
	| 'sha256'
	| 'hmacSha256'
	| 'hkdfSha256'
	| 'aes256Gcm'
	| 'chacha20Poly1305'
	| 'chacha20'
	| 'randomBytes';

const TAG_LENGTH = 16;
const EMPTY = new Uint8Array(0);

const hex = (s: string): Buffer => Buffer.from(s, 'hex');

const equal = (a: Uint8Array, b: Uint8Array): boolean =>
	Buffer.from(a.buffer, a.byteOffset, a.byteLength).equals(b);

/** True when decrypting a sealed box whose last byte was flipped throws. */
function rejectsTampered(
	open: (sealed: Uint8Array) => Uint8Array,
	sealed: Uint8Array
): boolean {
	const tampered = Uint8Array.from(sealed);
	tampered[tampered.length - 1] ^= 0x01;
	try {
		open(tampered);
		return false;
	} catch {
		return true;
	}
}

// Known-answer vectors from the RFCs and the GCM specification. The AEAD
// checks also require a tampered tag to be refused: a stub that decrypts
// without authenticating would otherwise pass.
const SELF_TESTS: Record<CryptoPrimitive, (p: ICryptoProvider) => boolean> = {
	// FIPS 180-2, "abc".
	sha256: (p) =>
		equal(
			p.sha256(Buffer.from('abc')),
			hex('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
		),
	// RFC 4231 test case 2.
	hmacSha256: (p) =>
		equal(
			p.hmacSha256(
				Buffer.from('Jefe'),
				Buffer.from('what do ya want for nothing?')
			),
			hex('5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843')
		),
	// RFC 5869 test cases 1 and 3. Every storage, backup and recovery key the
	// library derives uses an empty salt, which only test case 3 covers.
	hkdfSha256: (p) =>
		equal(
			p.hkdfSha256(
				Buffer.alloc(22, 0x0b),
				hex('000102030405060708090a0b0c'),
				hex('f0f1f2f3f4f5f6f7f8f9'),
				42
			),
			hex(
				'3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf' +
					'34007208d5b887185865'
			)
		) &&
		equal(
			p.hkdfSha256(
				Buffer.alloc(22, 0x0b),
				Buffer.alloc(0),
				Buffer.alloc(0),
				42
			),
			hex(
				'8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d' +
					'9d201395faa4b61a96c8'
			)
		),
	// McGrew and Viega, "The Galois/Counter Mode of Operation", test case 16.
	aes256Gcm: (p) => {
		const key = hex(
			'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308'
		);
		const iv = hex('cafebabefacedbaddecaf888');
		const aad = hex('feedfacedeadbeeffeedfacedeadbeefabaddad2');
		const plaintext = hex(
			'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72' +
				'1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39'
		);
		const sealed = hex(
			'522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa' +
				'8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662' +
				'76fc6ece0f4e1768cddf8853bb2d551b'
		);
		const open = (s: Uint8Array): Uint8Array =>
			p.aes256GcmDecrypt(key, iv, s, aad);
		return (
			equal(p.aes256GcmEncrypt(key, iv, plaintext, aad), sealed) &&
			equal(open(sealed), plaintext) &&
			rejectsTampered(open, sealed)
		);
	},
	// RFC 8439 section 2.8.2.
	chacha20Poly1305: (p) => {
		const key = hex(
			'808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'
		);
		const nonce = hex('070000004041424344454647');
		const aad = hex('50515253c0c1c2c3c4c5c6c7');
		const plaintext = Buffer.from(
			"Ladies and Gentlemen of the class of '99: If I could offer you only " +
				'one tip for the future, sunscreen would be it.'
		);
		const sealed = hex(
			'd31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6' +
				'3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36' +
				'92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc' +
				'3ff4def08e4b7a9de576d26586cec64b6116' +
				'1ae10b594f09e26a7e902ecbd0600691'
		);
		const open = (s: Uint8Array): Uint8Array =>
			p.chacha20Poly1305Decrypt(key, nonce, s, aad);
		return (
			equal(p.chacha20Poly1305Encrypt(key, nonce, plaintext, aad), sealed) &&
			equal(open(sealed), plaintext) &&
			rejectsTampered(open, sealed)
		);
	},
	// RFC 8439 section 2.6.2: the keystream that becomes the Poly1305 key.
	chacha20: (p) => {
		const key = hex(
			'808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'
		);
		const nonce = hex('000000000001020304050607');
		const keystream = hex(
			'8ad5a08b905f81cc815040274ab29471a833b637e3fd0da508dbb8e2fdd1a646'
		);
		return (
			equal(p.chacha20(key, nonce, Buffer.alloc(32)), keystream) &&
			equal(p.chacha20(key, nonce, keystream), Buffer.alloc(32))
		);
	},
	// No vector exists for randomness, so this only catches the stubs: a
	// short read, all zeros, or the same bytes twice.
	randomBytes: (p) => {
		const a = p.randomBytes(32);
		const b = p.randomBytes(32);
		return (
			a.length === 32 &&
			b.length === 32 &&
			!equal(a, Buffer.alloc(32)) &&
			!equal(a, b)
		);
	}
};

const PRIMITIVES = Object.keys(SELF_TESTS) as CryptoPrimitive[];

function failsSelfTest(
	provider: ICryptoProvider,
	primitive: CryptoPrimitive
): boolean {
	try {
		return !SELF_TESTS[primitive](provider);
	} catch {
		return true;
	}
}

/**
 * Run every known-answer vector against a provider.
 * @returns the primitives that failed; empty when all pass
 */
export function selfTestCryptoProvider(
	provider: ICryptoProvider
): CryptoPrimitive[] {
	return PRIMITIVES.filter((primitive) => failsSelfTest(provider, primitive));
}

/** Node's 'crypto' as a provider. */
function createNodeCryptoProvider(
	nodeCrypto: typeof NodeCrypto
): ICryptoProvider {
	// Typed as a GCM name so one seal/open pair serves both AEADs: Node runs
	// chacha20-poly1305 through the same setAAD and auth tag calls as GCM.
	const chachaPoly = 'chacha20-poly1305' as NodeCrypto.CipherGCMTypes;
	const seal = (
		algorithm: NodeCrypto.CipherGCMTypes,
		key: Uint8Array,
		iv: Uint8Array,
		plaintext: Uint8Array,
		aad: Uint8Array
	): Uint8Array => {
		const cipher = nodeCrypto.createCipheriv(algorithm, key, iv, {
			authTagLength: TAG_LENGTH
		});
		cipher.setAAD(aad);
		return Buffer.concat([
			cipher.update(plaintext),
			cipher.final(),
			cipher.getAuthTag()
		]);
	};
	const open = (
		algorithm: NodeCrypto.CipherGCMTypes,
		key: Uint8Array,
		iv: Uint8Array,
		sealed: Uint8Array,
		aad: Uint8Array
	): Uint8Array => {
		if (sealed.length < TAG_LENGTH) {
			throw new Error('Ciphertext too short to contain authentication tag');
		}
		const decipher = nodeCrypto.createDecipheriv(algorithm, key, iv, {
			authTagLength: TAG_LENGTH
		});
		decipher.setAAD(aad);
		decipher.setAuthTag(sealed.subarray(sealed.length - TAG_LENGTH));
		return Buffer.concat([
			decipher.update(sealed.subarray(0, sealed.length - TAG_LENGTH)),
			decipher.final()
		]);
	};
	return {
		sha256: (data) => nodeCrypto.createHash('sha256').update(data).digest(),
		hmacSha256: (key, data) =>
			nodeCrypto.createHmac('sha256', key).update(data).digest(),
		hkdfSha256: (ikm, salt, info, length) =>
			new Uint8Array(nodeCrypto.hkdfSync('sha256', ikm, salt, info, length)),
		aes256GcmEncrypt: (key, iv, plaintext, aad) =>
			seal('aes-256-gcm', key, iv, plaintext, aad),
		aes256GcmDecrypt: (key, iv, sealed, aad) =>
			open('aes-256-gcm', key, iv, sealed, aad),
		chacha20Poly1305Encrypt: (key, nonce, plaintext, aad) =>
			seal(chachaPoly, key, nonce, plaintext, aad),
		chacha20Poly1305Decrypt: (key, nonce, sealed, aad) =>
			open(chachaPoly, key, nonce, sealed, aad),
		chacha20: (key, nonce, data): Uint8Array => {
			// Node takes a 16-byte IV: the 32-bit LE block counter, then the nonce.
			const iv = Buffer.concat([Buffer.alloc(4), nonce]);
			const cipher = nodeCrypto.createCipheriv('chacha20', key, iv);
			return Buffer.concat([cipher.update(data), cipher.final()]);
		},
		randomBytes: (size) => nodeCrypto.randomBytes(size)
	};
}

let installed: ICryptoProvider | null = null;
let nodeDefault: ICryptoProvider | Error | null = null;
/** Self-test outcome per primitive for the active provider. */
const verdicts = new Map<CryptoPrimitive, boolean>();

function defaultProvider(): ICryptoProvider {
	if (nodeDefault === null) {
		try {
			// Required here, not at module scope: the root entry reaches this
			// file, and a React Native host may have no Node 'crypto' at all.
			// eslint-disable-next-line @typescript-eslint/no-var-requires
			nodeDefault = createNodeCryptoProvider(require('crypto'));
		} catch (e) {
			nodeDefault = e instanceof Error ? e : new Error(String(e));
		}
	}
	if (nodeDefault instanceof Error) {
		throw new Error(
			`Node crypto is unavailable (${nodeDefault.message}); ` +
				'install a crypto provider with setCryptoProvider'
		);
	}
	return nodeDefault;
}

/**
 * The active provider, once the primitive about to be used has passed its
 * vector. The default is tested one primitive at a time, so a platform shim
 * that lacks one primitive still serves the others.
 */
function providerFor(primitive: CryptoPrimitive): ICryptoProvider {
	const provider = installed ?? defaultProvider();
	let passed = verdicts.get(primitive);
	if (passed === undefined) {
		passed = !failsSelfTest(provider, primitive);
		verdicts.set(primitive, passed);
	}
	if (!passed) {
		throw new Error(
			`The platform's ${primitive} failed its self-test; ` +
				'install a crypto provider with setCryptoProvider'
		);
	}
	return provider;
}

/**
 * Replace the platform's crypto for the whole process, or pass null to go
 * back to Node's. A provider that fails any vector is refused and the
 * current one stays. The vectors catch a missing or broken primitive, not a
 * weak one: no test can tell predictable randomness from secure randomness,
 * so randomBytes must come from the platform's secure generator.
 * @throws when the provider fails its self-test
 */
export function setCryptoProvider(provider: ICryptoProvider | null): void {
	if (provider !== null) {
		const failed = selfTestCryptoProvider(provider);
		if (failed.length > 0) {
			throw new Error(
				`Crypto provider failed its self-test: ${failed.join(', ')}`
			);
		}
	}
	installed = provider;
	verdicts.clear();
	if (provider !== null) {
		for (const primitive of PRIMITIVES) verdicts.set(primitive, true);
	}
}

/**
 * A provider's result, copied into a Buffer the caller owns. A provider that
 * hands back a view into memory it reuses, as WASM-backed libraries can,
 * would otherwise let a later call overwrite a key or preimage that an
 * earlier call returned. The copy is not gated on an installed provider:
 * on React Native the default wraps whatever 'crypto' shim the app ships,
 * and only real Node is known to return fresh bytes. The copy is off the
 * shared Buffer pool, as Node's own digests are: a key the library keeps
 * must not pin a pool slab that also holds bytes it meant to drop.
 */
function toBuffer(bytes: Uint8Array): Buffer {
	const copy = Buffer.allocUnsafeSlow(bytes.length);
	copy.set(bytes);
	return copy;
}

export function sha256(data: Uint8Array): Buffer {
	return toBuffer(providerFor('sha256').sha256(data));
}

export function hmacSha256(key: Uint8Array, data: Uint8Array): Buffer {
	return toBuffer(providerFor('hmacSha256').hmacSha256(key, data));
}

export function hkdfSha256(
	ikm: Uint8Array,
	salt: Uint8Array,
	info: Uint8Array,
	length: number
): Buffer {
	return toBuffer(
		providerFor('hkdfSha256').hkdfSha256(ikm, salt, info, length)
	);
}

/** @returns ciphertext || 16-byte tag */
export function aes256GcmEncrypt(
	key: Uint8Array,
	iv: Uint8Array,
	plaintext: Uint8Array,
	aad: Uint8Array = EMPTY
): Buffer {
	return toBuffer(
		providerFor('aes256Gcm').aes256GcmEncrypt(key, iv, plaintext, aad)
	);
}

/** @throws when the tag does not verify */
export function aes256GcmDecrypt(
	key: Uint8Array,
	iv: Uint8Array,
	sealed: Uint8Array,
	aad: Uint8Array = EMPTY
): Buffer {
	return toBuffer(
		providerFor('aes256Gcm').aes256GcmDecrypt(key, iv, sealed, aad)
	);
}

/** @returns ciphertext || 16-byte tag */
export function chacha20Poly1305Encrypt(
	key: Uint8Array,
	nonce: Uint8Array,
	plaintext: Uint8Array,
	aad: Uint8Array = EMPTY
): Buffer {
	return toBuffer(
		providerFor('chacha20Poly1305').chacha20Poly1305Encrypt(
			key,
			nonce,
			plaintext,
			aad
		)
	);
}

/** @throws when the tag does not verify */
export function chacha20Poly1305Decrypt(
	key: Uint8Array,
	nonce: Uint8Array,
	sealed: Uint8Array,
	aad: Uint8Array = EMPTY
): Buffer {
	return toBuffer(
		providerFor('chacha20Poly1305').chacha20Poly1305Decrypt(
			key,
			nonce,
			sealed,
			aad
		)
	);
}

export function chacha20(
	key: Uint8Array,
	nonce: Uint8Array,
	data: Uint8Array
): Buffer {
	return toBuffer(providerFor('chacha20').chacha20(key, nonce, data));
}

export function randomBytes(size: number): Buffer {
	const bytes = providerFor('randomBytes').randomBytes(size);
	// Keys are drawn here, so a short read must not pass silently.
	if (bytes.length !== size) {
		throw new Error(`randomBytes returned ${bytes.length} of ${size} bytes`);
	}
	return toBuffer(bytes);
}
