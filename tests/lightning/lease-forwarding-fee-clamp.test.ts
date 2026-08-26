/**
 * Lessor fee caps bind ONE effective policy, not just the advertisement
 * (issue #536 review, bLIP-0051).
 *
 * The channel_update builders clamped a lessor's advertised fees to the caps
 * signed into will_fund, but the forwarding checks enforced the raw defaults
 * or per-channel override. A lessor configured above its caps then advertised
 * one fee and enforced another, so routes paying the advertised fee failed
 * with fee_insufficient. applyLeaseFeeCaps is now the single clamp behind
 * getChannelPolicy (which the announced and unannounced channel_update
 * builders and GET /channel/policy read) and getForwardingPolicyForChannel
 * (which the forward admission reads); these tests pin both sides to the
 * same numbers.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { perCommitmentPointFromSecret } from '../../src/lightning/keys/derivation';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import { realInitialCommitmentSig } from './helpers/real-signing';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';

interface IForwardingPolicy {
	feeBaseMsat: number;
	feeProportionalMillionths: number;
	cltvExpiryDelta: number;
}

type NodeInternals = {
	currentBlockHeight: number;
	getForwardingPolicyForChannel: (
		channelId: Buffer | undefined
	) => IForwardingPolicy;
};

function nodeConfig(seedId: number): INodeConfig {
	const seed = crypto
		.createHash('sha256')
		.update(`forward-fee-cap-${seedId}`)
		.digest();
	const perCommitmentSeed = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from('pcs'))
		.digest();
	const key = (i: number): Buffer =>
		crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([i]))
			.digest();
	return {
		nodePrivateKey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from('node-identity'))
			.digest(),
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: {
			fundingPubkey: getPublicKey(key(0)),
			revocationBasepoint: getPublicKey(key(1)),
			paymentBasepoint: getPublicKey(key(2)),
			delayedPaymentBasepoint: getPublicKey(key(3)),
			htlcBasepoint: getPublicKey(key(4)),
			firstPerCommitmentPoint: perCommitmentPointFromSecret(
				generateFromSeed(perCommitmentSeed, MAX_INDEX)
			)
		},
		perCommitmentSeed,
		fundingPrivkey: key(0),
		htlcBasepointSecret: key(4)
	};
}

function openNormalChannel(a: LightningNode, b: LightningNode): Buffer {
	a.on('message:outbound', (pk: string, type: number, payload: Buffer) => {
		if (pk === b.getNodeId()) b.handlePeerMessage(a.getNodeId(), type, payload);
	});
	b.on('message:outbound', (pk: string, type: number, payload: Buffer) => {
		if (pk === a.getNodeId()) a.handlePeerMessage(b.getNodeId(), type, payload);
	});
	const ch = a.openChannel(b.getNodeId(), 1_000_000n);
	const txid = crypto.randomBytes(32);
	const channelId = a.createFunding(
		ch,
		txid,
		0,
		realInitialCommitmentSig(ch, txid, 0)
	)!;
	a.handleFundingConfirmed(channelId);
	b.handleFundingConfirmed(channelId);
	return channelId;
}

function leasedNode(): { alice: LightningNode; channelId: Buffer } {
	const alice = new LightningNode(nodeConfig(1));
	const bob = new LightningNode(nodeConfig(2));
	alice.on('error', () => {});
	bob.on('error', () => {});
	const channelId = openNormalChannel(alice, bob);
	const st = alice.getChannelManager().getChannel(channelId)!.getFullState();
	st.isLessor = true;
	st.leaseExpiry = 900_000;
	st.leaseChannelFeeMaxBaseMsat = 5000;
	st.leaseChannelFeeMaxProportionalThousandths = 10; // -> 10_000 millionths
	// The override a careless lessor might set: above both signed caps.
	alice.setChannelPolicy(channelId, {
		feeBaseMsat: 50_000,
		feeProportionalMillionths: 50_000
	});
	bob.destroy();
	return { alice, channelId };
}

describe('Lessor fee caps bind advertisement AND enforcement', () => {
	it('clamps the forwarding-enforcement policy while the lease is active', () => {
		const { alice, channelId } = leasedNode();
		try {
			(alice as unknown as NodeInternals).currentBlockHeight = 800_000;
			const enforced = (
				alice as unknown as NodeInternals
			).getForwardingPolicyForChannel(channelId);
			expect(enforced.feeBaseMsat).to.equal(5000);
			expect(enforced.feeProportionalMillionths).to.equal(10_000);
		} finally {
			alice.destroy();
		}
	});

	it('reports the same clamped policy on the public policy surface', () => {
		const { alice, channelId } = leasedNode();
		try {
			(alice as unknown as NodeInternals).currentBlockHeight = 800_000;
			const advertised = alice.getChannelPolicy(channelId)!;
			expect(advertised.feeBaseMsat).to.equal(5000);
			expect(advertised.feeProportionalMillionths).to.equal(10_000);
			// The two surfaces agree: what gossip advertises is what an HTLC
			// paying that fee will be admitted against.
			const enforced = (
				alice as unknown as NodeInternals
			).getForwardingPolicyForChannel(channelId);
			expect(enforced.feeBaseMsat).to.equal(advertised.feeBaseMsat);
			expect(enforced.feeProportionalMillionths).to.equal(
				advertised.feeProportionalMillionths
			);
		} finally {
			alice.destroy();
		}
	});

	it('stops clamping once the lease expires', () => {
		const { alice, channelId } = leasedNode();
		try {
			(alice as unknown as NodeInternals).currentBlockHeight = 900_001;
			const enforced = (
				alice as unknown as NodeInternals
			).getForwardingPolicyForChannel(channelId);
			expect(enforced.feeBaseMsat).to.equal(50_000);
			expect(enforced.feeProportionalMillionths).to.equal(50_000);
			const advertised = alice.getChannelPolicy(channelId)!;
			expect(advertised.feeBaseMsat).to.equal(50_000);
			expect(advertised.feeProportionalMillionths).to.equal(50_000);
		} finally {
			alice.destroy();
		}
	});

	it('leaves a non-lessor channel untouched', () => {
		const alice = new LightningNode(nodeConfig(3));
		const bob = new LightningNode(nodeConfig(4));
		alice.on('error', () => {});
		bob.on('error', () => {});
		const channelId = openNormalChannel(alice, bob);
		try {
			alice.setChannelPolicy(channelId, {
				feeBaseMsat: 50_000,
				feeProportionalMillionths: 50_000
			});
			const enforced = (
				alice as unknown as NodeInternals
			).getForwardingPolicyForChannel(channelId);
			expect(enforced.feeBaseMsat).to.equal(50_000);
			expect(enforced.feeProportionalMillionths).to.equal(50_000);
		} finally {
			alice.destroy();
			bob.destroy();
		}
	});
});
