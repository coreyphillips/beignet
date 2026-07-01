/**
 * Liquidity ads (bLIP-0051) — lease fee accounting and will_fund authentication.
 *
 * A buyer requests inbound liquidity (request_funds in open_channel2); the
 * seller commits to fund it for a fee, signing the lease terms (will_fund in
 * accept_channel2). The buyer pays the lease fee out of its initial balance, and
 * the seller's funds are time-locked until lease_expiry (enforced on-chain in a
 * later milestone). This module is pure: fee math + signature auth only.
 */

import crypto from 'crypto';
import { sign, verify } from '../crypto/ecdh';
import { ILeaseRates, encodeLeaseRates } from '../gossip/types';

/** Lease duration in blocks (bLIP-0051): ~4 weeks. */
export const LEASE_DURATION_BLOCKS = 4032;

/**
 * Total lease fee (satoshis) the buyer pays the seller:
 *   lease_fee_base_sat
 *   + requested_sats * lease_fee_basis / 10_000
 *   + funding_weight * funding_feerate_perkw / 1000
 * The last term reimburses the seller's share of the on-chain funding cost.
 */
export function computeLeaseFeeSat(
	rates: ILeaseRates,
	requestedSats: bigint,
	fundingFeeratePerkw: number
): bigint {
	const base = BigInt(rates.leaseFeeBaseSat);
	const proportional = (requestedSats * BigInt(rates.leaseFeeBasis)) / 10_000n;
	const weightFee =
		(BigInt(rates.fundingWeightWitness) * BigInt(fundingFeeratePerkw)) / 1000n;
	return base + proportional + weightFee;
}

/** Absolute block height the lease expires at. */
export function computeLeaseExpiry(blockheight: number): number {
	return blockheight + LEASE_DURATION_BLOCKS;
}

// On-chain lease enforcement (M3.3) uses LND's "script-enforced lease" encoding:
// the lessor's to_local keeps the normal to_self_delay CSV and gains an absolute
// `<lease_expiry> OP_CHECKLOCKTIMEVERIFY OP_DROP` (see buildToLocalScript's
// leaseExpiry param in script/commitment.ts). An earlier CSV-extension sketch was
// removed in favour of this interoperable encoding.

/**
 * The bytes a seller signs to commit to lease terms: its funding pubkey, the
 * buyer-supplied blockheight, the negotiated channel_type, and the lease rates.
 * Binding the funding pubkey + blockheight ties the signature to this specific
 * channel and lease window.
 */
export function leaseWitnessData(
	sellerFundingPubkey: Buffer,
	blockheight: number,
	channelType: Buffer | undefined,
	rates: ILeaseRates
): Buffer {
	const bh = Buffer.alloc(4);
	bh.writeUInt32BE(blockheight, 0);
	return Buffer.concat([
		sellerFundingPubkey,
		bh,
		channelType ?? Buffer.alloc(0),
		encodeLeaseRates(rates)
	]);
}

function leaseSigHash(
	sellerFundingPubkey: Buffer,
	blockheight: number,
	channelType: Buffer | undefined,
	rates: ILeaseRates
): Buffer {
	return crypto
		.createHash('sha256')
		.update(
			leaseWitnessData(sellerFundingPubkey, blockheight, channelType, rates)
		)
		.digest();
}

/** Seller: sign a will_fund commitment with the node key that advertised the rates. */
export function signWillFund(
	sellerFundingPubkey: Buffer,
	blockheight: number,
	channelType: Buffer | undefined,
	rates: ILeaseRates,
	sellerNodePrivkey: Buffer
): Buffer {
	return sign(
		leaseSigHash(sellerFundingPubkey, blockheight, channelType, rates),
		sellerNodePrivkey
	);
}

/**
 * Buyer: verify a seller's will_fund signature against its node id. The rates
 * MUST match what the seller advertised in node_announcement (verify that
 * separately); this only proves the seller authenticated these exact terms.
 */
export function verifyWillFund(
	signature: Buffer,
	rates: ILeaseRates,
	sellerNodeId: Buffer,
	sellerFundingPubkey: Buffer,
	blockheight: number,
	channelType: Buffer | undefined
): boolean {
	try {
		return verify(
			leaseSigHash(sellerFundingPubkey, blockheight, channelType, rates),
			sellerNodeId,
			signature
		);
	} catch {
		return false;
	}
}
