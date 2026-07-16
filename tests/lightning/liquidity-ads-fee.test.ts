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
		const blockheight = 800000;

		const sig = signWillFund(fundingPubkey, blockheight, RATES, sellerNodePriv);

		expect(verifyWillFund(sig, RATES, sellerNodeId, fundingPubkey, blockheight))
			.to.be.true;

		// Tampered COMMITTED term (channel_fee_max_base_msat) → invalid. Per CLN the
		// signature only covers the routing-fee caps, so tampering an uncommitted
		// field (e.g. leaseFeeBaseSat) does NOT invalidate it (validated separately
		// against the advertised node_announcement rates).
		expect(
			verifyWillFund(
				sig,
				{ ...RATES, channelFeeMaxBaseMsat: RATES.channelFeeMaxBaseMsat + 1 },
				sellerNodeId,
				fundingPubkey,
				blockheight
			)
		).to.be.false;

		// Different blockheight → invalid (lease bound to its window).
		expect(verifyWillFund(sig, RATES, sellerNodeId, fundingPubkey, 800001)).to
			.be.false;

		// Wrong signer → invalid.
		const otherId = Buffer.from(secp.getPublicKey(validPriv(), true));
		expect(verifyWillFund(sig, RATES, otherId, fundingPubkey, blockheight)).to
			.be.false;
	});

	it('signs the exact CLN option_will_fund preimage (S-L.H3)', function () {
		const { verify } = require('../../src/lightning/crypto/ecdh');
		const sellerNodePriv = validPriv();
		const sellerNodeId = Buffer.from(secp.getPublicKey(sellerNodePriv, true));
		const fundingPubkey = Buffer.from(secp.getPublicKey(validPriv(), true));
		const blockheight = 800000;

		// Reconstruct CLN's lease_rates_get_commitment preimage independently:
		// "option_will_fund" || funding_pubkey || lease_expiry(u32)
		//   || channel_fee_max_base_msat(u32) || channel_fee_max_ppt(u16).
		const tail = Buffer.alloc(10);
		tail.writeUInt32BE(blockheight + LEASE_DURATION_BLOCKS, 0);
		tail.writeUInt32BE(RATES.channelFeeMaxBaseMsat, 4);
		tail.writeUInt16BE(RATES.channelFeeMaxProportionalThousandths, 8);
		const expectedSigHash = crypto
			.createHash('sha256')
			.update(
				Buffer.concat([Buffer.from('option_will_fund'), fundingPubkey, tail])
			)
			.digest();

		// signWillFund must have signed exactly that hash.
		const sig = signWillFund(fundingPubkey, blockheight, RATES, sellerNodePriv);
		expect(verify(expectedSigHash, sellerNodeId, sig)).to.be.true;
	});
});
