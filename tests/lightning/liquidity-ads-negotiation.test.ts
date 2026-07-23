/**
 * M3.2 — liquidity ads lease negotiation handshake between two ChannelManagers.
 *
 * Buyer requests inbound liquidity (request_funds in open_channel2); seller
 * answers with a signed will_fund in accept_channel2 and contributes the funds;
 * buyer verifies the signature and emits 'channel:lease'.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as secp from '@noble/secp256k1';
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { IDualFundingParams } from '../../src/lightning/channel/dual-funding';
import { ILeaseRates } from '../../src/lightning/gossip/types';
import { computeLeaseFeeSat } from '../../src/lightning/channel/liquidity-ads';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';
import { isTaprootChannel } from '../../src/lightning/channel/types';

/** channel_type advertising option_taproot (simple taproot channels). */
function taprootChannelType(): Buffer {
	const flags = FeatureFlags.empty();
	flags.setCompulsory(Feature.OPTION_TAPROOT);
	return flags.toBuffer();
}

function validPriv(): Buffer {
	let k: Buffer;
	do {
		k = crypto.randomBytes(32);
	} while (!secp.utils.isValidPrivateKey(k));
	return k;
}

function makeBasepoints(): IChannelBasepoints {
	return {
		fundingPubkey: getPublicKey(validPriv()),
		revocationBasepoint: getPublicKey(validPriv()),
		paymentBasepoint: getPublicKey(validPriv()),
		delayedPaymentBasepoint: getPublicKey(validPriv()),
		htlcBasepoint: getPublicKey(validPriv()),
		firstPerCommitmentPoint: getPublicKey(validPriv())
	};
}

function makeParams(
	overrides?: Partial<IDualFundingParams>
): IDualFundingParams {
	return {
		fundingSatoshis: 100_000n,
		fundingFeeratePerkw: 1000,
		commitmentFeeratePerkw: 253,
		dustLimitSatoshis: 546n,
		maxHtlcValueInFlightMsat: 500_000_000n,
		htlcMinimumMsat: 1000n,
		toSelfDelay: 144,
		maxAcceptedHtlcs: 483,
		locktime: 0,
		localBasepoints: makeBasepoints(),
		localPerCommitmentSeed: crypto.randomBytes(32),
		secondPerCommitmentPoint: getPublicKey(validPriv()),
		...overrides
	};
}

const RATES: ILeaseRates = {
	fundingWeightWitness: 1000,
	leaseFeeBasis: 100,
	leaseFeeBaseSat: 500,
	channelFeeMaxBaseMsat: 5000,
	channelFeeMaxProportionalThousandths: 10
};

// static_remotekey (12) + anchors_zero_fee_htlc_tx (22), both compulsory.
// Script-enforced leases are anchors-only (the lease CLTV lives in the
// confirmed P2WSH to_remote), so lease negotiations must propose this type.
const ANCHOR_CHANNEL_TYPE = Buffer.from('401000', 'hex');

/** Wire two managers so each one's outbound goes to the other's handleMessage. */
function wire(
	a: ChannelManager,
	aId: string,
	b: ChannelManager,
	bId: string
): void {
	a.on('message:outbound', (peer: string, type: number, payload: Buffer) => {
		if (peer === bId) b.handleMessage(aId, type, payload);
	});
	b.on('message:outbound', (peer: string, type: number, payload: Buffer) => {
		if (peer === aId) a.handleMessage(bId, type, payload);
	});
}

describe('Liquidity ads negotiation (M3.2)', function () {
	function setup(sellerSells: boolean) {
		const buyerPriv = validPriv();
		const sellerPriv = validPriv();
		const buyerId = getPublicKey(buyerPriv).toString('hex');
		const sellerId = getPublicKey(sellerPriv).toString('hex');

		const buyer = new ChannelManager({
			localBasepoints: makeBasepoints(),
			localPerCommitmentSeed: crypto.randomBytes(32),
			localFundingPrivkey: validPriv(),
			nodePrivateKey: buyerPriv
		});
		buyer.on('error', () => {});
		const seller = new ChannelManager({
			localBasepoints: makeBasepoints(),
			localPerCommitmentSeed: crypto.randomBytes(32),
			localFundingPrivkey: validPriv(),
			nodePrivateKey: sellerPriv,
			...(sellerSells ? { leaseRates: RATES } : {})
		});
		seller.on('error', () => {});

		wire(buyer, buyerId, seller, sellerId);
		return { buyer, seller, buyerId, sellerId };
	}

	it('negotiates a lease: buyer verifies the seller will_fund', function () {
		const { buyer, sellerId } = setup(true);

		let lease: any = null;
		buyer.on('channel:lease', (l: any) => {
			lease = l;
		});

		buyer.createDualFundedChannel(
			sellerId,
			makeParams({
				channelType: ANCHOR_CHANNEL_TYPE,
				requestFunds: { requestedSats: 500_000n, blockheight: 800000 },
				// Buyer's accepted ceiling = the seller's advertised rates (H3).
				maxLeaseRates: RATES
			})
		);

		expect(lease, 'channel:lease emitted').to.not.be.null;
		expect(lease.requestedSats).to.equal(500_000n);
		expect(lease.leaseRates).to.deep.equal(RATES);
		// Seller actually contributed the requested liquidity as the acceptor.
		expect(lease.sellerFundingSatoshis).to.equal(500_000n);
	});

	it('reconciles balances + applies the lease fee shift (M3.0 + M3.2)', function () {
		const { buyer, seller, buyerId, sellerId } = setup(true);

		const buyerChannel = buyer.createDualFundedChannel(
			sellerId,
			makeParams({
				fundingSatoshis: 200_000n,
				fundingFeeratePerkw: 1000,
				channelType: ANCHOR_CHANNEL_TYPE,
				requestFunds: { requestedSats: 500_000n, blockheight: 800000 },
				// Buyer's accepted ceiling = the seller's advertised rates (H3).
				maxLeaseRates: RATES
			})
		);

		// Lease fee: base 500 + 1% of 500k (5000) + weight 1000*1000/1000 (1000) = 6500.
		const feeMsat = computeLeaseFeeSat(RATES, 500_000n, 1000) * 1000n;

		// Buyer funded 200k, seller leased 500k. CLN's lease accounting
		// (validated live vs CLN): the fee rides in the FUNDING TX, so the
		// capacity is both contributions PLUS the fee, the seller's balance is
		// credited contribution + fee, and the buyer's balance stays intact.
		const feeSats = feeMsat / 1000n;
		const bState = buyerChannel.getFullState();
		expect(bState.fundingSatoshis).to.equal(700_000n + feeSats);
		expect(bState.localBalanceMsat).to.equal(200_000n * 1000n);
		expect(bState.remoteBalanceMsat).to.equal(500_000n * 1000n + feeMsat);
		expect(bState.leaseFeeSats).to.equal(feeSats);

		// Seller's mirror view: it owns the leased funds + the fee; its to_local is
		// CSV-locked until the lease expiry (blockheight + LEASE_DURATION).
		const tempId = buyerChannel.getTemporaryChannelId().toString('hex');
		const sellerChannel = (seller as any).tempChannels.get(tempId);
		expect(sellerChannel, 'seller has the channel').to.exist;
		const sState = sellerChannel.getFullState();
		expect(sState.fundingSatoshis).to.equal(700_000n + feeSats);
		expect(sState.localBalanceMsat).to.equal(500_000n * 1000n + feeMsat);
		expect(sState.remoteBalanceMsat).to.equal(200_000n * 1000n);
		expect(sState.leaseExpiry).to.equal(800000 + 4032);
		// Both sides agree on the lease expiry.
		expect(bState.leaseExpiry).to.equal(800000 + 4032);
		expect(buyerId).to.be.a('string');
	});

	it('no will_fund when the seller does not sell liquidity', function () {
		const { buyer, sellerId } = setup(false);

		let lease: any = null;
		buyer.on('channel:lease', (l: any) => {
			lease = l;
		});

		buyer.createDualFundedChannel(
			sellerId,
			makeParams({
				requestFunds: { requestedSats: 500_000n, blockheight: 800000 }
			})
		);

		expect(lease, 'no lease when seller declines').to.be.null;
	});

	it('does not lease a taproot channel (mutually-exclusive commitment types)', function () {
		// Script-enforced lease and simple taproot are distinct, mutually-exclusive
		// commitment types (LND has no taproot lease script). A liquidity seller must
		// therefore NOT answer a request_funds with a will_fund on a taproot channel;
		// it opens as a normal (unleased) taproot channel instead of an unenforceable
		// leased one.
		const { buyer, seller, sellerId } = setup(true);

		let lease: any = null;
		buyer.on('channel:lease', (l: any) => {
			lease = l;
		});

		const buyerChannel = buyer.createDualFundedChannel(
			sellerId,
			makeParams({
				channelType: taprootChannelType(),
				requestFunds: { requestedSats: 500_000n, blockheight: 800000 }
			})
		);

		// The buyer requested a taproot channel_type in open_channel2 (the value the
		// seller's will_fund guard keys off), so the seller must decline the lease
		// despite selling liquidity — no lease shift.
		expect(
			isTaprootChannel(
				buyerChannel.getDualFundingSession()?.getOpenChannelType() ?? null
			),
			'buyer proposed a taproot channel_type'
		).to.be.true;
		expect(lease, 'no lease negotiated on a taproot channel').to.be.null;

		// The seller mirror never entered the lessor state (no unenforceable lease).
		const tempId = buyerChannel.getTemporaryChannelId().toString('hex');
		const sellerChannel = (seller as any).tempChannels.get(tempId);
		expect(sellerChannel, 'seller has the channel').to.exist;
		const sState = sellerChannel.getFullState();
		expect(sState.isLessor, 'seller is not a lessor').to.not.equal(true);
		expect(sState.leaseExpiry, 'no lease expiry recorded').to.be.undefined;
	});
});
