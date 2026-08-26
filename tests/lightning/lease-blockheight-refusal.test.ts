/**
 * A seller refuses an overflowing lease blockheight BEFORE retaining state
 * (issue #536 review, bLIP-0051).
 *
 * The will_fund witness data writes lease_expiry = blockheight +
 * LEASE_DURATION_BLOCKS as a u32, so a wire-valid request_funds.blockheight
 * of 0xffffffff made writeUInt32BE throw out of signWillFund AFTER the
 * acceptor's temporary channel was stored: the dispatch-layer catch swallowed
 * it, the buyer got no wire answer, and every repeat of the open retained
 * another temp channel. The seller now bounds the blockheight before key
 * derivation or temp-channel insertion and answers with a scoped error.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as secp from '@noble/secp256k1';
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { IDualFundingParams } from '../../src/lightning/channel/dual-funding';
import { ILeaseRates } from '../../src/lightning/gossip/types';
import { MessageType } from '../../src/lightning/message/types';

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

// static_remotekey + anchors_zero_fee_htlc_tx, both compulsory (leases are
// anchors-only).
const ANCHOR_CHANNEL_TYPE = Buffer.from('401000', 'hex');

interface ISellerHarness {
	buyer: ChannelManager;
	seller: ChannelManager;
	sellerId: string;
	sellerOutbound: Array<{ type: number; payload: Buffer }>;
	sellerErrors: string[];
	sellerTempChannels: Map<string, unknown>;
}

function setup(sellerSells: boolean): ISellerHarness {
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
	const sellerErrors: string[] = [];
	seller.on('error', (_id: Buffer | null, message: string) => {
		sellerErrors.push(message);
	});

	const sellerOutbound: Array<{ type: number; payload: Buffer }> = [];
	buyer.on(
		'message:outbound',
		(peer: string, type: number, payload: Buffer) => {
			if (peer === sellerId) seller.handleMessage(buyerId, type, payload);
		}
	);
	seller.on(
		'message:outbound',
		(peer: string, type: number, payload: Buffer) => {
			sellerOutbound.push({ type, payload });
			if (peer === buyerId) buyer.handleMessage(sellerId, type, payload);
		}
	);

	return {
		buyer,
		seller,
		sellerId,
		sellerOutbound,
		sellerErrors,
		sellerTempChannels: (
			seller as unknown as { tempChannels: Map<string, unknown> }
		).tempChannels
	};
}

describe('Seller lease blockheight bound (pre-retention)', () => {
	it('refuses a u32-max blockheight with a scoped error and retains nothing', () => {
		const h = setup(true);

		h.buyer.createDualFundedChannel(
			h.sellerId,
			makeParams({
				channelType: ANCHOR_CHANNEL_TYPE,
				// Wire-valid u32; +LEASE_DURATION_BLOCKS overflows the u32 the
				// will_fund witness data writes.
				requestFunds: { requestedSats: 500_000n, blockheight: 0xffffffff },
				maxLeaseRates: RATES
			})
		);

		// The seller answered on the wire (a scoped BOLT 1 error naming the
		// refusal) instead of dying inside signWillFund.
		const errors = h.sellerOutbound.filter((m) => m.type === MessageType.ERROR);
		expect(errors.length, 'one scoped wire error').to.equal(1);
		expect(errors[0].payload.toString('utf8')).to.include('blockheight');
		expect(
			h.sellerOutbound.some((m) => m.type === MessageType.ACCEPT_CHANNEL2),
			'no accept_channel2 for a refused lease'
		).to.equal(false);
		// Nothing retained: the regression stored the temp channel before the
		// throw, so every repeated open leaked another entry.
		expect(h.sellerTempChannels.size).to.equal(0);
		// And the dispatch-layer catch never fired (no swallowed exception).
		expect(
			h.sellerErrors.some((m) => /Error handling message type/.test(m)),
			'no dispatch-layer catch'
		).to.equal(false);
	});

	it('ignores the hostile blockheight when we do not sell', () => {
		const h = setup(false);

		h.buyer.createDualFundedChannel(
			h.sellerId,
			makeParams({
				channelType: ANCHOR_CHANNEL_TYPE,
				requestFunds: { requestedSats: 500_000n, blockheight: 0xffffffff },
				maxLeaseRates: RATES
			})
		);

		// A non-seller never signs will_fund, so the blockheight is dead data:
		// the open proceeds as a plain (unleased) accept, exactly as before.
		expect(
			h.sellerOutbound.some((m) => m.type === MessageType.ACCEPT_CHANNEL2),
			'plain accept_channel2 sent'
		).to.equal(true);
		expect(
			h.sellerOutbound.some((m) => m.type === MessageType.ERROR),
			'no wire error'
		).to.equal(false);
	});

	it('still negotiates a lease at a sane blockheight', () => {
		const h = setup(true);
		let leased = false;
		h.buyer.on('channel:lease', () => {
			leased = true;
		});

		h.buyer.createDualFundedChannel(
			h.sellerId,
			makeParams({
				channelType: ANCHOR_CHANNEL_TYPE,
				requestFunds: { requestedSats: 500_000n, blockheight: 800_000 },
				maxLeaseRates: RATES
			})
		);

		expect(leased, 'channel:lease emitted').to.equal(true);
		expect(
			h.sellerOutbound.some((m) => m.type === MessageType.ERROR),
			'no wire error on the happy path'
		).to.equal(false);
	});
});
