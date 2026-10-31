import { expect } from 'chai';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { buildIssuerPaymentPath } from '../../src/lightning/ffor/issuer-paths';
import { processBlindedHop } from '../../src/lightning/onion/blinded-path';

describe('FFOR issuer payment path payloads', () => {
	it('uses only SCID for each relay and includes the recipient delay in payinfo', () => {
		const keys = [1, 2, 3].map((value) => Buffer.alloc(32, value));
		const hops = keys.map((key, index) => ({
			nodeId: getPublicKey(key),
			shortChannelId: Buffer.alloc(8, index + 1),
			feeBaseMsat: 0,
			feeProportionalMillionths: 0,
			cltvExpiryDelta: 40,
			htlcMinimumMsat: 1n,
			htlcMaximumMsat: 500_000n
		}));
		const { path, payInfo } = buildIssuerPaymentPath(hops, 2016);
		expect(payInfo.cltvExpiryDelta).equal(120);
		let point = path.blindingPoint;
		for (let index = 0; index < keys.length; index++) {
			const decoded = processBlindedHop(
				point,
				keys[index],
				path.blindedHops[index].encryptedData
			);
			point = decoded.nextBlindingKey;
			expect(decoded.hopData.nextNodeId).equal(undefined);
			if (index < keys.length - 1) {
				expect(
					decoded.hopData.shortChannelId!.equals(hops[index].shortChannelId)
				).equal(true);
				expect(decoded.hopData.paymentRelay!.cltvExpiryDelta).equal(40);
			} else {
				expect(decoded.hopData.shortChannelId).equal(undefined);
				expect(decoded.hopData.paymentRelay).equal(undefined);
			}
		}
	});
});
