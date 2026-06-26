/**
 * BOLT 3 Appendix E: Key Derivation Test Vectors.
 *
 * Asserts beignet's per-commitment key derivation reproduces the spec's
 * expected points/secrets exactly. These are the purest vectors (no tx
 * assembly), so this file also doubles as a smoke test of the vector loader.
 */

import { expect } from 'chai';
import {
	derivePublicKey,
	derivePrivateKey,
	deriveRevocationPubkey,
	deriveRevocationPrivkey
} from '../../../src/lightning/keys/derivation';
import { loadVectors, hexToBuffer, bufferToHex } from './helpers';

interface IDerivationCase {
	name: string;
	kind: 'pubkey' | 'privkey' | 'revocation_pubkey' | 'revocation_privkey';
	basepoint?: string;
	basepoint_secret?: string;
	per_commitment_point?: string;
	per_commitment_secret?: string;
	revocation_basepoint?: string;
	revocation_basepoint_secret?: string;
	expected: string;
}

interface IDerivationVectors {
	cases: IDerivationCase[];
}

describe('BOLT 3 Appendix E: key derivation conformance', function () {
	const vectors = loadVectors<IDerivationVectors>('bolt03/derivation.json');

	for (const tc of vectors.cases) {
		it(tc.name, function () {
			let actual: Buffer;

			switch (tc.kind) {
				case 'pubkey':
					actual = derivePublicKey(
						hexToBuffer(tc.basepoint!),
						hexToBuffer(tc.per_commitment_point!)
					);
					break;
				case 'privkey':
					actual = derivePrivateKey(
						hexToBuffer(tc.basepoint_secret!),
						hexToBuffer(tc.per_commitment_point!),
						hexToBuffer(tc.basepoint!)
					);
					break;
				case 'revocation_pubkey':
					actual = deriveRevocationPubkey(
						hexToBuffer(tc.revocation_basepoint!),
						hexToBuffer(tc.per_commitment_point!)
					);
					break;
				case 'revocation_privkey':
					actual = deriveRevocationPrivkey(
						hexToBuffer(tc.revocation_basepoint_secret!),
						hexToBuffer(tc.per_commitment_secret!),
						hexToBuffer(tc.revocation_basepoint!),
						hexToBuffer(tc.per_commitment_point!)
					);
					break;
			}

			expect(bufferToHex(actual)).to.equal(tc.expected);
		});
	}
});
