/**
 * Liquidity ads lessor-safety regression tests (bLIP-0051).
 *
 * Three MEDIUM findings from the 2026-07-15 review, all on the seller/lessor:
 * - buyer blockheight is validated before it becomes our to_local CLTV lock
 *   (a far-future or >= 500,000,000 value would freeze our funds);
 * - the proportional lease fee is charged on min(our funding, requested), so a
 *   partial funder is not billed for liquidity it did not provide;
 * - the signed channel_fee_max_* caps are enforced on the lessor's own
 *   channel_update while the lease is active.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as secp from '@noble/secp256k1';
import { Channel } from '../../src/lightning/channel/channel';
import { createAcceptorState } from '../../src/lightning/channel/channel-state';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { IDualFundingParams } from '../../src/lightning/channel/dual-funding';
import { ILeaseRates } from '../../src/lightning/gossip/types';
import { IOpenChannel2Message } from '../../src/lightning/message/dual-funding';
import {
	computeLeaseFeeSat,
	signWillFund
} from '../../src/lightning/channel/liquidity-ads';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import {
	encodeChannelUpdateMessage,
	decodeChannelUpdateMessage
} from '../../src/lightning/gossip/messages';
import { BITCOIN_CHAIN_HASH } from '../../src/lightning/channel/types';

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

/**
 * Build an acceptor Channel and drive handleOpenChannel2 as the seller, with a
 * buyer request for `requestedSats` at `blockheight` and our own contribution
 * of `sellerFunding`. Returns the channel and the resulting actions.
 */
function driveSellerOpen(opts: {
	requestedSats: bigint;
	blockheight: number;
	sellerFunding: bigint;
	currentBlockHeight?: number;
}): { channel: Channel; actions: ReturnType<Channel['handleOpenChannel2']> } {
	const sellerPriv = validPriv();
	const sellerKeys = makeBasepoints();
	const buyerKeys = makeBasepoints();

	const state = createAcceptorState({
		temporaryChannelId: crypto.randomBytes(32),
		fundingSatoshis: 0n,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: sellerKeys,
		localPerCommitmentSeed: crypto.randomBytes(32),
		remoteBasepoints: buyerKeys,
		remoteConfig: { ...DEFAULT_CHANNEL_CONFIG }
	});
	const channel = new Channel(state);
	if (opts.currentBlockHeight) channel.setBlockHeight(opts.currentBlockHeight);

	const signature = signWillFund(
		sellerKeys.fundingPubkey,
		opts.blockheight,
		RATES,
		sellerPriv
	);
	const localParams: IDualFundingParams = {
		fundingSatoshis: opts.sellerFunding,
		fundingFeeratePerkw: 1000,
		commitmentFeeratePerkw: 253,
		dustLimitSatoshis: 546n,
		maxHtlcValueInFlightMsat: 500_000_000n,
		htlcMinimumMsat: 1000n,
		toSelfDelay: 144,
		maxAcceptedHtlcs: 483,
		locktime: 0,
		localBasepoints: sellerKeys,
		localPerCommitmentSeed: state.localPerCommitmentSeed,
		secondPerCommitmentPoint: getPublicKey(validPriv()),
		willFund: { signature, leaseRates: RATES }
	};

	const msg: IOpenChannel2Message = {
		channelId: state.temporaryChannelId,
		fundingFeeratePerkw: 1000,
		commitmentFeeratePerkw: 253,
		fundingSatoshis: 200_000n, // buyer's own contribution
		dustLimitSatoshis: 546n,
		maxHtlcValueInFlightMsat: 500_000_000n,
		htlcMinimumMsat: 1000n,
		toSelfDelay: 144,
		maxAcceptedHtlcs: 483,
		locktime: 0,
		fundingPubkey: buyerKeys.fundingPubkey,
		revocationBasepoint: buyerKeys.revocationBasepoint,
		paymentBasepoint: buyerKeys.paymentBasepoint,
		delayedPaymentBasepoint: buyerKeys.delayedPaymentBasepoint,
		htlcBasepoint: buyerKeys.htlcBasepoint,
		firstPerCommitmentPoint: buyerKeys.firstPerCommitmentPoint,
		secondPerCommitmentPoint: getPublicKey(validPriv()),
		channelFlags: 0,
		channelType: ANCHOR_CHANNEL_TYPE,
		requestFunds: {
			requestedSats: opts.requestedSats,
			blockheight: opts.blockheight
		}
	};

	const actions = channel.handleOpenChannel2(msg, localParams);
	return { channel, actions };
}

describe('Liquidity ads lessor safety', function () {
	it('records a lease for a sane blockheight', function () {
		const { channel, actions } = driveSellerOpen({
			requestedSats: 500_000n,
			blockheight: 800_000,
			sellerFunding: 500_000n,
			currentBlockHeight: 800_000
		});
		expect(actions.some((a) => a.type === ChannelActionType.ERROR)).to.equal(
			false
		);
		expect(channel.getFullState().isLessor).to.equal(true);
		expect(channel.getFullState().leaseExpiry).to.equal(800_000 + 4032);
	});

	it('rejects a >= 500,000,000 buyer blockheight (would freeze our to_local)', function () {
		const { channel, actions } = driveSellerOpen({
			requestedSats: 500_000n,
			blockheight: 500_000_001,
			sellerFunding: 500_000n
		});
		const err = actions.find((a) => a.type === ChannelActionType.ERROR);
		expect(err, 'errors on out-of-range blockheight').to.exist;
		expect((err as { message: string }).message).to.contain('blockheight');
		expect(channel.getFullState().isLessor).to.not.equal(true);
	});

	it('rejects a far-future buyer blockheight relative to our tip', function () {
		const { actions } = driveSellerOpen({
			requestedSats: 500_000n,
			blockheight: 900_000, // 100k blocks past our tip
			sellerFunding: 500_000n,
			currentBlockHeight: 800_000
		});
		expect(
			actions.some((a) => a.type === ChannelActionType.ERROR),
			'far-future blockheight rejected'
		).to.equal(true);
	});

	it('charges the proportional fee on min(our funding, requested)', function () {
		// Seller funds only 300k of a 500k request: the fee must be computed on
		// 300k, not 500k (a partial funder is billed for what it provides).
		const { channel } = driveSellerOpen({
			requestedSats: 500_000n,
			blockheight: 800_000,
			sellerFunding: 300_000n,
			currentBlockHeight: 800_000
		});
		const feeMsat = computeLeaseFeeSat(RATES, 300_000n, 1000) * 1000n;
		const st = channel.getFullState();
		// Seller (local) gained the leased funds + the fee; buyer (remote) paid it.
		// remote started at 200k (buyer contribution); local at 300k (our funding).
		expect(st.localBalanceMsat).to.equal(300_000n * 1000n + feeMsat);
		expect(st.remoteBalanceMsat).to.equal(200_000n * 1000n - feeMsat);
		// Sanity: the full-request fee is strictly larger, so the min() matters.
		expect(
			computeLeaseFeeSat(RATES, 500_000n, 1000) >
				computeLeaseFeeSat(RATES, 300_000n, 1000)
		).to.equal(true);
		// The signed routing-fee caps are recorded for channel_update enforcement.
		expect(st.leaseChannelFeeMaxBaseMsat).to.equal(RATES.channelFeeMaxBaseMsat);
		expect(st.leaseChannelFeeMaxProportionalThousandths).to.equal(
			RATES.channelFeeMaxProportionalThousandths
		);
	});
});

describe('Liquidity ads lessor channel_update fee cap', function () {
	function nodeConfig(seedId: number): INodeConfig {
		const seed = crypto
			.createHash('sha256')
			.update(`lessor-fee-cap-${seedId}`)
			.digest();
		return {
			nodePrivateKey: crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from('node-identity'))
				.digest(),
			network: Network.REGTEST,
			channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
			channelBasepoints: makeBasepoints(),
			perCommitmentSeed: crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from('pcs'))
				.digest(),
			fundingPrivkey: crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from([0]))
				.digest()
		};
	}

	function openNormalChannel(a: LightningNode, b: LightningNode): Buffer {
		a.on('message:outbound', (pk: string, type: number, payload: Buffer) => {
			if (pk === b.getNodeId())
				b.handlePeerMessage(a.getNodeId(), type, payload);
		});
		b.on('message:outbound', (pk: string, type: number, payload: Buffer) => {
			if (pk === a.getNodeId())
				a.handlePeerMessage(b.getNodeId(), type, payload);
		});
		const ch = a.openChannel(b.getNodeId(), 1_000_000n);
		const txid = crypto.randomBytes(32);
		const channelId = a.createFunding(ch, txid, 0, crypto.randomBytes(64))!;
		a.handleFundingConfirmed(channelId);
		b.handleFundingConfirmed(channelId);
		return channelId;
	}

	function cachedUpdate(): Buffer {
		return encodeChannelUpdateMessage({
			signature: Buffer.alloc(64),
			chainHash: BITCOIN_CHAIN_HASH,
			shortChannelId: Buffer.from('0e88ee000d6f0001', 'hex'),
			timestamp: 1000,
			messageFlags: 1,
			channelFlags: 0,
			cltvExpiryDelta: 80,
			htlcMinimumMsat: 1000n,
			feeBaseMsat: 0,
			feeProportionalMillionths: 1,
			htlcMaximumMsat: 1_000_000_000n
		});
	}

	it('clamps our advertised fees to the signed caps while the lease is active', function () {
		const alice = new LightningNode(nodeConfig(1));
		const bob = new LightningNode(nodeConfig(2));
		alice.on('error', () => {});
		bob.on('error', () => {});
		const channelId = openNormalChannel(alice, bob);

		// Mark this channel as our lease (we are the lessor) with tight fee caps,
		// then set a channel policy that WOULD exceed them.
		const st = alice.getChannelManager().getChannel(channelId)!.getFullState();
		st.isLessor = true;
		st.leaseExpiry = 900_000;
		st.leaseChannelFeeMaxBaseMsat = 5000;
		st.leaseChannelFeeMaxProportionalThousandths = 10; // -> 10_000 millionths
		(alice as any).currentBlockHeight = 800_000; // before expiry: lease active

		alice.setChannelPolicy(channelId, {
			feeBaseMsat: 50_000, // above the 5000 cap
			feeProportionalMillionths: 50_000 // above the 10_000 cap
		});

		const refreshed = (alice as any).refreshChannelUpdate(
			cachedUpdate(),
			2000,
			channelId
		);
		const decoded = decodeChannelUpdateMessage(refreshed);
		expect(decoded.feeBaseMsat).to.equal(5000);
		expect(decoded.feeProportionalMillionths).to.equal(10_000);

		alice.destroy();
		bob.destroy();
	});

	it('does not clamp once the lease has expired', function () {
		const alice = new LightningNode(nodeConfig(3));
		const bob = new LightningNode(nodeConfig(4));
		alice.on('error', () => {});
		bob.on('error', () => {});
		const channelId = openNormalChannel(alice, bob);

		const st = alice.getChannelManager().getChannel(channelId)!.getFullState();
		st.isLessor = true;
		st.leaseExpiry = 900_000;
		st.leaseChannelFeeMaxBaseMsat = 5000;
		st.leaseChannelFeeMaxProportionalThousandths = 10;
		(alice as any).currentBlockHeight = 900_001; // after expiry: lease no longer binds

		alice.setChannelPolicy(channelId, {
			feeBaseMsat: 50_000,
			feeProportionalMillionths: 50_000
		});

		const refreshed = (alice as any).refreshChannelUpdate(
			cachedUpdate(),
			2000,
			channelId
		);
		const decoded = decodeChannelUpdateMessage(refreshed);
		expect(decoded.feeBaseMsat).to.equal(50_000);
		expect(decoded.feeProportionalMillionths).to.equal(50_000);

		alice.destroy();
		bob.destroy();
	});
});
