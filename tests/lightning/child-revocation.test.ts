import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import { ecc } from '../../src/utils/ecc';
import { sha256 } from '../../src/lightning/crypto/provider';
import {
	childRevocationBasepoint,
	revokedChildPrivateKey
} from '../../src/lightning/channel/child-revocation';
import {
	deriveRevocationPubkey,
	perCommitmentPointFromSecret
} from '../../src/lightning/keys/derivation';

const order = BigInt(
	'0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'
);
const scalar = (value: Buffer): bigint => BigInt('0x' + value.toString('hex'));
function inverse(value: bigint): bigint {
	let result = 1n,
		exponent = order - 2n,
		power = value;
	while (exponent) {
		if (exponent & 1n) result = (result * power) % order;
		power = (power * power) % order;
		exponent >>= 1n;
	}
	return result;
}
const encoded = (value: bigint): Buffer =>
	Buffer.from(value.toString(16).padStart(64, '0'), 'hex');

describe('independent revoked child authority', () => {
	it('reveals only an independent exact-state base secret even with the peer secret', () => {
		const seed = sha256(Buffer.from('independent local seed'));
		const channelBase = sha256(Buffer.from('ordinary revocation base'));
		const peerSecret = sha256(Buffer.from('revealed peer state'));
		const parent = new bitcoin.Transaction();
		parent.version = 2;
		parent.addInput(sha256(Buffer.from('funding epoch')), 1, 0x80000000);
		parent.addOutput(Buffer.from('5120' + '33'.repeat(32), 'hex'), 1000);
		const basepoint = childRevocationBasepoint(seed, parent);
		const delegated = revokedChildPrivateKey(seed, parent, peerSecret);
		const point = perCommitmentPointFromSecret(peerSecret);
		const publicKey = deriveRevocationPubkey(basepoint, point);
		expect(
			Buffer.from(ecc.pointFromScalar(delegated, true)!).equals(publicKey)
		).equal(true);
		// Model the strongest peer/tower collusion: invert the ordinary revocation formula.
		const a = scalar(sha256(Buffer.concat([basepoint, point])));
		const b = scalar(sha256(Buffer.concat([point, basepoint])));
		const recovered =
			((((scalar(delegated) - scalar(peerSecret) * b) % order) + order) *
				inverse(a)) %
			order;
		expect(
			Buffer.from(ecc.pointFromScalar(encoded(recovered), true)!).equals(
				basepoint
			)
		).equal(true);
		expect(encoded(recovered).equals(channelBase)).equal(false);
		expect(encoded(recovered).equals(seed)).equal(false);
		expect(
			revokedChildPrivateKey(seed, parent.getId(), peerSecret).equals(delegated)
		).equal(true);
		for (const change of [
			(tx: bitcoin.Transaction) => {
				tx.ins[0].index++;
			},
			(tx: bitcoin.Transaction) => {
				tx.ins[0].hash[0] ^= 1;
			},
			(tx: bitcoin.Transaction) => {
				tx.outs[0].script[2] ^= 1;
			},
			(tx: bitcoin.Transaction) => {
				tx.outs[0].value--;
			},
			(tx: bitcoin.Transaction) => {
				tx.locktime++;
			}
		]) {
			const variant = parent.clone();
			change(variant);
			expect(childRevocationBasepoint(seed, variant).equals(basepoint)).equal(
				false
			);
			expect(
				revokedChildPrivateKey(seed, variant, peerSecret).equals(delegated)
			).equal(false);
		}
	});
});
