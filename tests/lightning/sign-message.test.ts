/**
 * LND-compatible message signing tests.
 *
 * Format under test: digest = sha256(sha256('Lightning Signed Message:' + msg)),
 * signature = zbase32([27 + 4 + recoveryId || r || s]) (always 104 chars).
 *
 * No externally-produced LND vector is checked in: an (privkey, message,
 * signature) triple could not be reconstructed deterministically from
 * documentation alone, and RFC 6979 nonces make signatures implementation
 * deterministic but not memorable. Compatibility is instead pinned by
 * construction (prefix, double-SHA256, btcec SignCompact header byte,
 * tv42-zbase32 alphabet/bit order) plus the structural checks below.
 * Live cross-check against `lncli verifymessage` is an interop follow-up.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	signMessageWithKey,
	verifyMessageSignature,
	zbase32Encode,
	zbase32Decode
} from '../../src/lightning/crypto/message-signing';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';

const ZBASE32_ALPHABET = 'ybndrfg8ejkmcpqxot1uwisza345h769';

function fixedKey(tag: string): Buffer {
	return crypto.createHash('sha256').update(`sign-message-${tag}`).digest();
}

function makeNode(seedId: number): LightningNode {
	const seed = crypto
		.createHash('sha256')
		.update(`sign-message-node-${seedId}`)
		.digest();
	const priv = (i: number): Buffer =>
		crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([i]))
			.digest();
	const basepoints: IChannelBasepoints = {
		fundingPubkey: getPublicKey(priv(0)),
		revocationBasepoint: getPublicKey(priv(1)),
		paymentBasepoint: getPublicKey(priv(2)),
		delayedPaymentBasepoint: getPublicKey(priv(3)),
		htlcBasepoint: getPublicKey(priv(4)),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
	const config: INodeConfig = {
		nodePrivateKey: priv(10),
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: basepoints,
		perCommitmentSeed: priv(11),
		fundingPrivkey: priv(0),
		htlcBasepointSecret: priv(4)
	};
	return new LightningNode(config);
}

describe('Message Signing (LND-compatible)', function () {
	describe('zbase32', function () {
		it('round-trips arbitrary buffers', function () {
			for (const len of [0, 1, 2, 5, 32, 65, 100]) {
				const buf = crypto
					.createHash('sha512')
					.update(`zb32-${len}`)
					.digest()
					.subarray(0, len);
				const encoded = zbase32Encode(buf);
				expect([...encoded].every((c) => ZBASE32_ALPHABET.includes(c))).to.be
					.true;
				expect(zbase32Decode(encoded)).to.deep.equal(buf);
			}
		});

		it('rejects characters outside the alphabet', function () {
			expect(zbase32Decode('yyl')).to.be.null; // 'l' is not in zbase32
			expect(zbase32Decode('YY')).to.be.null; // uppercase is invalid
			expect(zbase32Decode('y!')).to.be.null;
		});

		it('rejects nonzero padding bits (not a canonical encoding)', function () {
			// One byte encodes to 2 chars whose final 2 bits are zero padding.
			const encoded = zbase32Encode(Buffer.from([0xff]));
			expect(encoded).to.have.length(2);
			const lastIdx = ZBASE32_ALPHABET.indexOf(encoded[1]);
			expect(lastIdx & 0b11).to.equal(0);
			const tampered = encoded[0] + ZBASE32_ALPHABET[lastIdx | 0b11];
			expect(zbase32Decode(tampered)).to.be.null;
		});
	});

	describe('signMessageWithKey / verifyMessageSignature', function () {
		it('produces a 104-char zbase32 signature and recovers the signer', function () {
			const priv = fixedKey('key1');
			const pub = getPublicKey(priv);
			const message = 'hello beignet';

			const signature = signMessageWithKey(message, priv);
			expect(signature).to.have.length(104); // 65 bytes = 520 bits = 104 chars
			expect([...signature].every((c) => ZBASE32_ALPHABET.includes(c))).to.be
				.true;

			// Compact header byte: 27 + 4 (compressed) + recId in [0,3]
			const raw = zbase32Decode(signature)!;
			expect(raw).to.have.length(65);
			expect(raw[0]).to.be.at.least(31);
			expect(raw[0]).to.be.at.most(34);

			const result = verifyMessageSignature(message, signature);
			expect(result.valid).to.be.true;
			expect(result.pubkey).to.deep.equal(pub);
		});

		it('is deterministic (RFC 6979 nonces)', function () {
			const priv = fixedKey('key2');
			const msg = 'determinism check';
			expect(signMessageWithKey(msg, priv)).to.equal(
				signMessageWithKey(msg, priv)
			);
		});

		it('recovers a DIFFERENT pubkey for a tampered message', function () {
			// ECDSA recovery on a tampered message usually still succeeds but
			// yields an unrelated key. Authentication = comparing the recovered
			// pubkey to the expected signer (LND checks its graph).
			const priv = fixedKey('key3');
			const pub = getPublicKey(priv);
			const signature = signMessageWithKey('original message', priv);

			const result = verifyMessageSignature('tampered message', signature);
			if (result.valid) {
				expect(result.pubkey).to.not.deep.equal(pub);
			} else {
				expect(result.pubkey).to.be.null;
			}
		});

		it('rejects malformed signatures', function () {
			expect(verifyMessageSignature('msg', '').valid).to.be.false;
			expect(verifyMessageSignature('msg', 'not-zbase32!!').valid).to.be.false;
			// Valid zbase32 of the wrong length (64 bytes instead of 65)
			const short = zbase32Encode(crypto.randomBytes(64));
			expect(verifyMessageSignature('msg', short).valid).to.be.false;
			// Header byte below 27 is not a compact signature
			const bad = Buffer.concat([Buffer.from([5]), crypto.randomBytes(64)]);
			expect(verifyMessageSignature('msg', zbase32Encode(bad)).valid).to.be
				.false;
		});

		it('signs the double-SHA256 of the prefixed message (empty + utf8 round-trips)', function () {
			const priv = fixedKey('key4');
			const pub = getPublicKey(priv);
			for (const msg of ['', 'ascii', 'unicode ⚡️ snowman ☃']) {
				const sig = signMessageWithKey(msg, priv);
				const result = verifyMessageSignature(msg, sig);
				expect(result.valid, `message: ${JSON.stringify(msg)}`).to.be.true;
				expect(result.pubkey).to.deep.equal(pub);
			}
		});
	});

	describe('LightningNode.signMessage / verifyMessage', function () {
		it('signs with the node identity key and reports graph knowledge', function () {
			const node = makeNode(1);
			node.on('error', () => {});
			const signature = node.signMessage('node level message');

			const result = node.verifyMessage('node level message', signature);
			expect(result.valid).to.be.true;
			expect(result.pubkey).to.equal(node.getNodeId());
			// Our own node is not in our gossip graph in this bare harness.
			expect(result.knownNode).to.be.false;
		});

		it('two nodes verify each other', function () {
			const alice = makeNode(2);
			const bob = makeNode(3);
			alice.on('error', () => {});
			bob.on('error', () => {});
			const sig = alice.signMessage('cross check');
			const result = bob.verifyMessage('cross check', sig);
			expect(result.valid).to.be.true;
			expect(result.pubkey).to.equal(alice.getNodeId());
		});
	});
});
