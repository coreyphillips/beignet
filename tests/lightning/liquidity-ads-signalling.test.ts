/**
 * M3.1 — Liquidity ads (bLIP-0051) signalling round-trips.
 *
 * Covers the node_announcement option_will_fund lease-rates TLV (incl. it being
 * signed), the open_channel2 request_funds TLV, and the accept_channel2
 * will_fund TLV. No funds are at risk here — pure codec/gossip.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as secp from '@noble/secp256k1';
import {
	encodeNodeAnnouncementMessage,
	decodeNodeAnnouncementMessage
} from '../../src/lightning/gossip/messages';
import {
	signNodeAnnouncement,
	verifyNodeAnnouncement
} from '../../src/lightning/gossip/validation';
import {
	INodeAnnouncementMessage,
	ILeaseRates
} from '../../src/lightning/gossip/types';
import {
	encodeOpenChannel2Message,
	decodeOpenChannel2Message,
	encodeAcceptChannel2Message,
	decodeAcceptChannel2Message,
	IOpenChannel2Message,
	IAcceptChannel2Message
} from '../../src/lightning/message/dual-funding';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';

function validPriv(): Buffer {
	let k: Buffer;
	do {
		k = crypto.randomBytes(32);
	} while (!secp.utils.isValidPrivateKey(k));
	return k;
}

const RATES: ILeaseRates = {
	fundingWeightWitness: 666,
	leaseFeeBasis: 40,
	leaseFeeBaseSat: 250,
	channelFeeMaxBaseMsat: 5000,
	channelFeeMaxProportionalThousandths: 10
};

describe('Liquidity ads signalling (M3.1)', function () {
	it('round-trips lease rates in a node_announcement and signs over them', function () {
		const priv = validPriv();
		const nodeId = Buffer.from(secp.getPublicKey(priv, true));
		const unsigned: INodeAnnouncementMessage = {
			signature: Buffer.alloc(64),
			features: Buffer.alloc(0),
			timestamp: 1_700_000_000,
			nodeId,
			rgbColor: Buffer.from([1, 2, 3]),
			alias: Buffer.alloc(32),
			addresses: [],
			leaseRates: RATES
		};

		const unsignedPayload = encodeNodeAnnouncementMessage(unsigned);
		const signature = signNodeAnnouncement(unsignedPayload, priv);
		const signed = { ...unsigned, signature };
		const payload = encodeNodeAnnouncementMessage(signed);

		const decoded = decodeNodeAnnouncementMessage(payload);
		expect(decoded.leaseRates).to.deep.equal(RATES);
		expect(verifyNodeAnnouncement(decoded, payload)).to.be.true;

		// Tampering with the (signed) lease rates must invalidate the signature.
		const tampered = encodeNodeAnnouncementMessage({
			...signed,
			leaseRates: { ...RATES, leaseFeeBaseSat: 9999 }
		});
		expect(
			verifyNodeAnnouncement(decodeNodeAnnouncementMessage(tampered), tampered)
		).to.be.false;
	});

	it('node_announcement without lease rates still round-trips', function () {
		const priv = validPriv();
		const nodeId = Buffer.from(secp.getPublicKey(priv, true));
		const msg: INodeAnnouncementMessage = {
			signature: Buffer.alloc(64),
			features: Buffer.alloc(0),
			timestamp: 1_700_000_000,
			nodeId,
			rgbColor: Buffer.from([0, 0, 0]),
			alias: Buffer.alloc(32),
			addresses: []
		};
		const sig = signNodeAnnouncement(encodeNodeAnnouncementMessage(msg), priv);
		const payload = encodeNodeAnnouncementMessage({ ...msg, signature: sig });
		const decoded = decodeNodeAnnouncementMessage(payload);
		expect(decoded.leaseRates).to.be.undefined;
		expect(verifyNodeAnnouncement(decoded, payload)).to.be.true;
	});

	it('round-trips request_funds in open_channel2', function () {
		const base: IOpenChannel2Message = {
			channelId: crypto.randomBytes(32),
			fundingFeeratePerkw: 2500,
			commitmentFeeratePerkw: 2500,
			fundingSatoshis: 1_000_000n,
			dustLimitSatoshis: 354n,
			maxHtlcValueInFlightMsat: 100_000_000n,
			htlcMinimumMsat: 1n,
			toSelfDelay: 144,
			maxAcceptedHtlcs: 30,
			locktime: 800000,
			fundingPubkey: crypto.randomBytes(33),
			revocationBasepoint: crypto.randomBytes(33),
			paymentBasepoint: crypto.randomBytes(33),
			delayedPaymentBasepoint: crypto.randomBytes(33),
			htlcBasepoint: crypto.randomBytes(33),
			firstPerCommitmentPoint: crypto.randomBytes(33),
			secondPerCommitmentPoint: crypto.randomBytes(33),
			channelFlags: 1,
			channelType: Buffer.from([0x10]),
			requestFunds: { requestedSats: 500_000n, blockheight: 800000 }
		};
		const decoded = decodeOpenChannel2Message(encodeOpenChannel2Message(base));
		expect(decoded.requestFunds).to.deep.equal({
			requestedSats: 500_000n,
			blockheight: 800000
		});
		// channel_type still parses alongside request_funds.
		expect(decoded.channelType).to.deep.equal(Buffer.from([0x10]));
	});

	it('round-trips will_fund (signature + lease rates) in accept_channel2', function () {
		const sig = crypto.randomBytes(64);
		const base: IAcceptChannel2Message = {
			channelId: crypto.randomBytes(32),
			fundingSatoshis: 500_000n,
			dustLimitSatoshis: 354n,
			maxHtlcValueInFlightMsat: 100_000_000n,
			htlcMinimumMsat: 1n,
			minimumDepth: 3,
			toSelfDelay: 144,
			maxAcceptedHtlcs: 30,
			fundingPubkey: crypto.randomBytes(33),
			revocationBasepoint: crypto.randomBytes(33),
			paymentBasepoint: crypto.randomBytes(33),
			delayedPaymentBasepoint: crypto.randomBytes(33),
			htlcBasepoint: crypto.randomBytes(33),
			firstPerCommitmentPoint: crypto.randomBytes(33),
			secondPerCommitmentPoint: crypto.randomBytes(33),
			willFund: { signature: sig, leaseRates: RATES }
		};
		const decoded = decodeAcceptChannel2Message(
			encodeAcceptChannel2Message(base)
		);
		expect(decoded.willFund!.signature).to.deep.equal(sig);
		expect(decoded.willFund!.leaseRates).to.deep.equal(RATES);
	});

	it('advertises OPTION_WILL_FUND as an optional feature bit', function () {
		const f = FeatureFlags.empty();
		f.setOptional(Feature.OPTION_WILL_FUND);
		expect(f.hasFeature(Feature.OPTION_WILL_FUND)).to.be.true;
	});
});
