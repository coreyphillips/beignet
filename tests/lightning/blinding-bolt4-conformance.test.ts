/**
 * BOLT 4 route-blinding key-derivation conformance.
 *
 * The encrypted_recipient_data encryption key MUST be rho = HMAC-SHA256("rho",
 * ss) and the blinded-node-id tweak MUST be HMAC-SHA256("blinded_node_id", ss).
 * Using the spec "rho" label (previously beignet reused "blinded_node_id" for
 * both) is what lets LND/CLN decrypt our encrypted_recipient_data. This guards
 * against regressing back to the non-interoperable label.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	deriveBlindingEncryptionKey,
	deriveBlindedNodeIdTweak,
	computeBlindedNodeId,
	encryptBlindedData,
	decryptBlindedData
} from '../../src/lightning/onion/blinding';
import { pointMultiply, getPublicKey } from '../../src/lightning/crypto/ecdh';

describe('BOLT 4 route-blinding key derivation', function () {
	const ss = crypto.randomBytes(32);

	it('encryption key is HMAC-SHA256("rho", ss) (NOT "blinded_node_id")', function () {
		const expected = crypto
			.createHmac('sha256', Buffer.from('rho'))
			.update(ss)
			.digest();
		expect(deriveBlindingEncryptionKey(ss)).to.deep.equal(expected);

		const wrong = crypto
			.createHmac('sha256', Buffer.from('blinded_node_id'))
			.update(ss)
			.digest();
		expect(deriveBlindingEncryptionKey(ss).equals(wrong)).to.be.false;
	});

	it('blinded-node-id tweak is HMAC-SHA256("blinded_node_id", ss)', function () {
		const expected = crypto
			.createHmac('sha256', Buffer.from('blinded_node_id'))
			.update(ss)
			.digest();
		expect(deriveBlindedNodeIdTweak(ss)).to.deep.equal(expected);
		// And it differs from the encryption key (the two were once conflated).
		expect(deriveBlindedNodeIdTweak(ss).equals(deriveBlindingEncryptionKey(ss)))
			.to.be.false;
	});

	it('blinded node id = node_pubkey * blinded_node_id_tweak', function () {
		const nodePub = getPublicKey(crypto.randomBytes(32));
		expect(computeBlindedNodeId(nodePub, ss)).to.deep.equal(
			pointMultiply(nodePub, deriveBlindedNodeIdTweak(ss))
		);
	});

	it('encrypt/decrypt round-trips with the rho key + zero nonce', function () {
		const key = deriveBlindingEncryptionKey(ss);
		const plaintext = crypto.randomBytes(40);
		const ct = encryptBlindedData(key, plaintext);
		expect(decryptBlindedData(key, ct)).to.deep.equal(plaintext);
		// ChaCha20Poly1305 adds a 16-byte tag.
		expect(ct.length).to.equal(plaintext.length + 16);
	});
});
