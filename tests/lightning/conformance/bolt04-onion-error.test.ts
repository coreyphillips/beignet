/**
 * BOLT 4: onion error (failure message) test vector
 * (bolt04/onion-error-test.json).
 *
 * A failure originates at hops[4] and is wrapped by every hop on the way
 * back to the sender. Asserted byte-exact:
 *  - the sphinx shared-secret chain and each hop's ammag/um keys
 *  - the origin's 292-byte failure plaintext (hmac || failure_len ||
 *    failuremsg || pad_len || pad, message + pad = 256)
 *  - the fully wrapped errorpacket after all five ammag layers
 *  - the sender's decrypt direction (origin index + failure code)
 */

import { expect } from 'chai';
import {
	computeSharedSecrets,
	deriveHopKeys,
	generateCipherStream
} from '../../../src/lightning/onion/sphinx-crypto';
import {
	createFailureMessage,
	wrapFailureMessage,
	decryptFailureMessage
} from '../../../src/lightning/onion/failures';
import { loadVectors, hexToBuffer, bufferToHex } from './helpers';

interface IErrorHop {
	pubkey: string;
	hop_shared_secret: string;
	ammag_key: string;
	um_key?: string;
	payload?: string;
}

interface IOnionErrorVectors {
	generate: {
		session_key: string;
		failure_message: string;
		hops: IErrorHop[];
	};
	errorpacket: string;
}

const v = loadVectors<IOnionErrorVectors>('bolt04/onion-error.json');
const hops = v.generate.hops;
const sharedSecrets = hops.map((h) => hexToBuffer(h.hop_shared_secret));
const failureCode = hexToBuffer(v.generate.failure_message).readUInt16BE(0);

describe('BOLT 4: onion error conformance', function () {
	it('derives the spec shared secrets from the session key', function () {
		const { sharedSecrets: derived } = computeSharedSecrets(
			hexToBuffer(v.generate.session_key),
			hops.map((h) => hexToBuffer(h.pubkey))
		);
		derived.forEach((ss, i) => {
			expect(bufferToHex(ss)).to.equal(hops[i].hop_shared_secret);
		});
	});

	it('derives each hop ammag/um key', function () {
		for (const h of hops) {
			const keys = deriveHopKeys(hexToBuffer(h.hop_shared_secret));
			expect(bufferToHex(keys.ammag)).to.equal(h.ammag_key);
			if (h.um_key) {
				expect(bufferToHex(keys.um)).to.equal(h.um_key);
			}
		}
	});

	it('creates the origin failure plaintext byte-for-byte', function () {
		const origin = hops[hops.length - 1];
		const message = createFailureMessage(
			hexToBuffer(origin.hop_shared_secret),
			failureCode
		);

		// Unwrap the origin's own ammag layer to reveal the plaintext the
		// spec fixes: failure_len || failuremsg || pad_len || pad (the hmac
		// is over exactly these bytes; the vector's `payload` omits it).
		const stream = generateCipherStream(
			hexToBuffer(origin.ammag_key),
			message.length
		);
		const plaintext = Buffer.alloc(message.length);
		for (let i = 0; i < message.length; i++) {
			plaintext[i] = message[i] ^ stream[i];
		}
		expect(bufferToHex(plaintext.subarray(32))).to.equal(origin.payload);
	});

	it('wraps the failure through every hop to the spec errorpacket', function () {
		let message = createFailureMessage(
			sharedSecrets[hops.length - 1],
			failureCode
		);
		for (let i = hops.length - 2; i >= 0; i--) {
			message = wrapFailureMessage(sharedSecrets[i], message);
		}
		expect(bufferToHex(message)).to.equal(v.errorpacket);
	});

	it('decrypts the spec errorpacket back to the origin failure', function () {
		const result = decryptFailureMessage(
			sharedSecrets,
			hexToBuffer(v.errorpacket)
		);
		expect(result).to.not.equal(null);
		expect(result?.originIndex).to.equal(hops.length - 1);
		expect(result?.failure.failureCode).to.equal(failureCode);
		expect(result?.failure.failureData.length).to.equal(0);
	});
});
