/**
 * Gossip signature verification backend parity (issue #441).
 *
 * verifySha256d routes BOLT 7 signature checks through node:crypto's OpenSSL
 * when the platform proves it works, falling back to the pure-JS lib
 * otherwise (react-native embeddings). The two backends must be
 * indistinguishable by verdict: valid signatures accepted, tampered ones
 * rejected, high-S accepted (gossip is non-strict), and malformed input
 * treated as invalid rather than thrown. These tests pin that contract on
 * raw vectors and through the gossip validation wiring.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	getPublicKey,
	isValidPublicKey,
	sign,
	verifySha256d,
	verifySha256dJs,
	_resetSha256dBackendForTests
} from '../../src/lightning/crypto/ecdh';
import {
	verifyChannelAnnouncement,
	verifyChannelUpdate,
	verifyNodeAnnouncement
} from '../../src/lightning/gossip/validation';
import { encodeShortChannelId } from '../../src/lightning/gossip/types';
import {
	makeSignedChannelAnnouncement,
	makeSignedChannelKeys,
	makeSignedChannelUpdate,
	makeSignedNodeAnnouncement
} from './helpers/signed-gossip';

const SECP256K1_N = Buffer.from(
	'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
	'hex'
);

interface IVector {
	firstHash: Buffer;
	publicKey: Buffer;
	signature: Buffer;
}

function makeVector(): IVector {
	const priv = crypto.randomBytes(32);
	const firstHash = crypto
		.createHash('sha256')
		.update(crypto.randomBytes(100))
		.digest();
	const digest = crypto.createHash('sha256').update(firstHash).digest();
	return {
		firstHash,
		publicKey: getPublicKey(priv),
		signature: sign(digest, priv)
	};
}

/** s -> n - s: still a cryptographically valid, non-canonical signature. */
function toHighS(signature: Buffer): Buffer {
	const out = Buffer.from(signature);
	let borrow = 0;
	for (let i = 31; i >= 0; i--) {
		const diff = SECP256K1_N[i] - signature[32 + i] - borrow;
		out[32 + i] = diff & 0xff;
		borrow = diff < 0 ? 1 : 0;
	}
	return out;
}

describe('Gossip verify backend parity (issue #441)', function () {
	afterEach(() => {
		_resetSha256dBackendForTests();
	});

	const bothBackends = (
		fn: (verify: typeof verifySha256d) => void
	): void => {
		_resetSha256dBackendForTests('node');
		fn(verifySha256d);
		_resetSha256dBackendForTests('js');
		fn(verifySha256d);
		fn(verifySha256dJs);
	};

	it('accepts valid signatures and rejects tampered ones on both backends', () => {
		const vectors = Array.from({ length: 32 }, makeVector);
		bothBackends((verify) => {
			for (const v of vectors) {
				expect(verify(v.firstHash, v.publicKey, v.signature)).to.equal(
					true
				);
				const tampered = Buffer.from(v.signature);
				tampered[40] ^= 0x01;
				expect(verify(v.firstHash, v.publicKey, tampered)).to.equal(
					false
				);
				const wrongKey = getPublicKey(crypto.randomBytes(32));
				expect(verify(v.firstHash, wrongKey, v.signature)).to.equal(
					false
				);
				const wrongHash = crypto
					.createHash('sha256')
					.update('other')
					.digest();
				expect(verify(wrongHash, v.publicKey, v.signature)).to.equal(
					false
				);
			}
		});
	});

	it('accepts high-S signatures on both backends (gossip is non-strict)', () => {
		const vectors = Array.from({ length: 8 }, makeVector);
		bothBackends((verify) => {
			for (const v of vectors) {
				const highS = toHighS(v.signature);
				expect(highS.equals(v.signature)).to.equal(false);
				expect(verify(v.firstHash, v.publicKey, highS)).to.equal(true);
			}
		});
	});

	it('treats malformed input as invalid without throwing, on both backends', () => {
		const v = makeVector();
		// An x coordinate with no curve point: mutate until the lib rejects it.
		const offCurve = Buffer.from(v.publicKey);
		while (isValidPublicKey(offCurve)) {
			offCurve[32] = (offCurve[32] + 1) & 0xff;
		}
		const sGeqN = Buffer.concat([
			v.signature.subarray(0, 32),
			SECP256K1_N
		]);
		const zeroS = Buffer.concat([
			v.signature.subarray(0, 32),
			Buffer.alloc(32)
		]);
		bothBackends((verify) => {
			expect(
				verify(v.firstHash, v.publicKey.subarray(0, 32), v.signature)
			).to.equal(false);
			expect(
				verify(
					v.firstHash,
					Buffer.concat([v.publicKey, Buffer.from([0x01])]),
					v.signature
				)
			).to.equal(false);
			expect(verify(v.firstHash, offCurve, v.signature)).to.equal(false);
			const badPrefix = Buffer.from(v.publicKey);
			badPrefix[0] = 0x05;
			expect(verify(v.firstHash, badPrefix, v.signature)).to.equal(false);
			expect(
				verify(v.firstHash, v.publicKey, v.signature.subarray(0, 63))
			).to.equal(false);
			expect(
				verify(
					v.firstHash,
					v.publicKey,
					Buffer.concat([v.signature, Buffer.from([0x00])])
				)
			).to.equal(false);
			expect(verify(v.firstHash, v.publicKey, sGeqN)).to.equal(false);
			expect(verify(v.firstHash, v.publicKey, zeroS)).to.equal(false);
		});
	});

	it('returns correct verdicts through the key cache (hits and many distinct keys)', () => {
		_resetSha256dBackendForTests('node');
		const v = makeVector();
		// Miss, then hit, then a tampered check against the cached key.
		expect(verifySha256d(v.firstHash, v.publicKey, v.signature)).to.equal(
			true
		);
		expect(verifySha256d(v.firstHash, v.publicKey, v.signature)).to.equal(
			true
		);
		const tampered = Buffer.from(v.signature);
		tampered[5] ^= 0x01;
		expect(verifySha256d(v.firstHash, v.publicKey, tampered)).to.equal(
			false
		);
		for (let i = 0; i < 50; i++) {
			const d = makeVector();
			expect(verifySha256d(d.firstHash, d.publicKey, d.signature)).to.equal(
				true
			);
		}
	});

	it('gossip validation verdicts are identical under both backends', () => {
		const scid = encodeShortChannelId({
			block: 500_000,
			txIndex: 1,
			outputIndex: 0
		});
		const keys = makeSignedChannelKeys();
		const ann = makeSignedChannelAnnouncement(scid, keys);
		const upd = makeSignedChannelUpdate(scid, keys.nodeKey1, 0, 1_700_000_000);
		const nodeAnn = makeSignedNodeAnnouncement(keys.nodeKey2, 1_700_000_000);

		const tamperedAnn = {
			...ann.msg,
			nodeSignature1: (() => {
				const s = Buffer.from(ann.msg.nodeSignature1);
				s[10] ^= 0x01;
				return s;
			})()
		};

		for (const backend of ['node', 'js'] as const) {
			_resetSha256dBackendForTests(backend);
			expect(
				verifyChannelAnnouncement(ann.msg, ann.payload),
				`announcement, ${backend}`
			).to.equal(true);
			expect(
				verifyChannelAnnouncement(tamperedAnn, ann.payload),
				`tampered announcement, ${backend}`
			).to.equal(false);
			expect(
				verifyChannelUpdate(
					upd.msg,
					upd.payload,
					ann.msg.nodeId1,
					ann.msg.nodeId2
				),
				`update, ${backend}`
			).to.equal(true);
			expect(
				verifyNodeAnnouncement(nodeAnn.msg, nodeAnn.payload),
				`node announcement, ${backend}`
			).to.equal(true);
		}
	});
});
