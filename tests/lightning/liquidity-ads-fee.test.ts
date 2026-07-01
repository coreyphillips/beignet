/**
 * M3.2 — liquidity ads lease fee math + will_fund signature auth.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as secp from '@noble/secp256k1';
import {
	computeLeaseFeeSat,
	computeLeaseExpiry,
	LEASE_DURATION_BLOCKS,
	signWillFund,
	verifyWillFund
} from '../../src/lightning/channel/liquidity-ads';
import { ILeaseRates } from '../../src/lightning/gossip/types';

function validPriv(): Buffer {
	let k: Buffer;
	do {
		k = crypto.randomBytes(32);
	} while (!secp.utils.isValidPrivateKey(k));
	return k;
}

const RATES: ILeaseRates = {
	fundingWeightWitness: 1000,
	leaseFeeBasis: 100, // 1%
	leaseFeeBaseSat: 500,
	channelFeeMaxBaseMsat: 5000,
	channelFeeMaxProportionalThousandths: 10
};

describe('Liquidity ads fee + will_fund (M3.2)', function () {
	it('computes the lease fee = base + proportional + weight share', function () {
		// base 500 + 1% of 1_000_000 (=10_000) + weight 1000 * feerate 2000/1000 (=2000)
		const fee = computeLeaseFeeSat(RATES, 1_000_000n, 2000);
		expect(fee).to.equal(500n + 10_000n + 2000n);
	});

	it('lease expiry is blockheight + LEASE_DURATION', function () {
		expect(computeLeaseExpiry(800000)).to.equal(800000 + LEASE_DURATION_BLOCKS);
	});

	it('verifies a valid will_fund signature and rejects tampering', function () {
		const sellerNodePriv = validPriv();
		const sellerNodeId = Buffer.from(secp.getPublicKey(sellerNodePriv, true));
		const fundingPubkey = Buffer.from(secp.getPublicKey(validPriv(), true));
		const channelType = Buffer.from([0x10]);
		const blockheight = 800000;

		const sig = signWillFund(
			fundingPubkey,
			blockheight,
			channelType,
			RATES,
			sellerNodePriv
		);

		expect(
			verifyWillFund(
				sig,
				RATES,
				sellerNodeId,
				fundingPubkey,
				blockheight,
				channelType
			)
		).to.be.true;

		// Tampered rates → invalid.
		expect(
			verifyWillFund(
				sig,
				{ ...RATES, leaseFeeBaseSat: 9999 },
				sellerNodeId,
				fundingPubkey,
				blockheight,
				channelType
			)
		).to.be.false;

		// Different blockheight → invalid (lease bound to its window).
		expect(
			verifyWillFund(
				sig,
				RATES,
				sellerNodeId,
				fundingPubkey,
				800001,
				channelType
			)
		).to.be.false;

		// Wrong signer → invalid.
		const otherId = Buffer.from(secp.getPublicKey(validPriv(), true));
		expect(
			verifyWillFund(
				sig,
				RATES,
				otherId,
				fundingPubkey,
				blockheight,
				channelType
			)
		).to.be.false;
	});
});
