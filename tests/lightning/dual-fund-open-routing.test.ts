/**
 * Issue #158: openChannel must select v1 vs v2 from the peer's features.
 *
 * The default feature set advertises option_dual_fund, but openChannel always
 * initiated a v1 open_channel. BOLT 2: once option_dual_fund is negotiated,
 * open_channel must not be used, and dual-fund peers enforce it (CLN:
 * "OPT_DUAL_FUND: cannot use open_channel"). So the default open path,
 * including the dashboard's connect-and-open, failed against any dual-fund
 * peer even though the v2 machinery existed one call away.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';

function makeBasepoints(): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) keys.push(crypto.randomBytes(32));
	return {
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

function makeNode(): LightningNode {
	const node = new LightningNode({
		nodePrivateKey: crypto.randomBytes(32),
		perCommitmentSeed: crypto.randomBytes(32),
		channelBasepoints: makeBasepoints(),
		fundingPrivkey: crypto.randomBytes(32),
		localFeatures: LightningNode.defaultFeatures()
	});
	node.on('error', () => {});
	return node;
}

function peerFeatures(dualFund: boolean): FeatureFlags {
	const flags = FeatureFlags.empty();
	flags.setOptional(Feature.STATIC_REMOTE_KEY);
	if (dualFund) flags.setOptional(Feature.DUAL_FUND);
	return flags;
}

describe('Issue #158: openChannel routes v1 vs v2 by peer features', function () {
	this.timeout(10_000);

	let node: LightningNode;
	let peerPubkey: string;
	let v1Calls: Array<{ fundingSatoshis: bigint; pushMsat?: bigint }>;
	let v2Calls: Array<{
		fundingSatoshis: bigint;
		fundingFeeratePerkw?: number;
	}>;

	function wirePeer(dualFund: boolean, connected = true): void {
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const n = node as any;
		n.peerManager = {
			getPeer: (pubkey: string) =>
				connected && pubkey === peerPubkey
					? {
							getRemoteInit: () => ({ features: peerFeatures(dualFund) })
					  }
					: undefined,
			destroy: (): void => {}
		};
		n.channelManager.openChannel = (
			_pubkey: string,
			fundingSatoshis: bigint,
			pushMsat?: bigint
		): { getTemporaryChannelId: () => Buffer } => {
			v1Calls.push({ fundingSatoshis, pushMsat });
			return { getTemporaryChannelId: (): Buffer => crypto.randomBytes(32) };
		};
		n.openChannelV2 = (
			_pubkey: string,
			params: { fundingSatoshis: bigint; fundingFeeratePerkw?: number }
		): { v2: boolean } => {
			v2Calls.push(params);
			return { v2: true };
		};
	}

	beforeEach(function () {
		node = makeNode();
		peerPubkey = crypto.randomBytes(33).toString('hex');
		peerPubkey = '02' + peerPubkey.slice(2); // valid compressed-key prefix
		v1Calls = [];
		v2Calls = [];
	});

	afterEach(function () {
		node.destroy();
	});

	it('routes to open_channel2 when the peer negotiated option_dual_fund', function () {
		wirePeer(true);
		node.openChannel(peerPubkey, 100_000n);
		expect(v2Calls.length, 'v2 used').to.equal(1);
		expect(v2Calls[0].fundingSatoshis).to.equal(100_000n);
		expect(v1Calls.length, 'v1 not used').to.equal(0);
	});

	it('keeps v1 for a peer without option_dual_fund', function () {
		wirePeer(false);
		node.openChannel(peerPubkey, 100_000n);
		expect(v1Calls.length, 'v1 used').to.equal(1);
		expect(v2Calls.length, 'v2 not used').to.equal(0);
	});

	it('routes to v1 when the peer is not connected (no init to judge by)', function () {
		// Only the ROUTING decision is under test: the stub stands in for
		// ChannelManager.openChannel, which in real code throws 'Not connected
		// to peer' for an unconnected peer. Nothing is queued for later.
		wirePeer(true, false);
		node.openChannel(peerPubkey, 100_000n);
		expect(v1Calls.length).to.equal(1);
		expect(v2Calls.length).to.equal(0);
	});

	it('converts the caller sat/vB rate to sat/kw for the v2 open', function () {
		wirePeer(true);
		node.openChannel(peerPubkey, 100_000n, undefined, 5);
		expect(v2Calls.length).to.equal(1);
		// 1 sat/vB = 250 sat/kw
		expect(v2Calls[0].fundingFeeratePerkw).to.equal(1250);
	});

	it('a v2 open without a caller rate uses the fee estimator, like v1', function () {
		// The v1 path asks the estimator at funding time (handleAutoFunding).
		// v2 cannot defer, since open_channel2 itself carries
		// funding_feerate_perkw, so the estimator's latest sample (the fee
		// advisor) must be pinned at open time. Falling back to the static
		// localConfig feerate here would silently underprice funding during
		// elevated mempool fees.
		wirePeer(true);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(node as any).feeAdvisor = { getCurrentRate: (): number => 20 };
		node.openChannel(peerPubkey, 100_000n);
		expect(v2Calls.length).to.equal(1);
		expect(v2Calls[0].fundingFeeratePerkw).to.equal(20 * 250);
	});

	it('clamps an absurdly low caller rate, matching v1 funding', function () {
		wirePeer(true);
		node.openChannel(peerPubkey, 100_000n, undefined, 0.1);
		expect(v2Calls.length).to.equal(1);
		// clampFeeRateSatPerVbyte floors at 1 sat/vB = 250 sat/kw
		expect(v2Calls[0].fundingFeeratePerkw).to.equal(250);
	});

	it('clamps an absurdly high caller rate, matching v1 funding', function () {
		wirePeer(true);
		node.openChannel(peerPubkey, 100_000n, undefined, 100_000);
		expect(v2Calls.length).to.equal(1);
		// MAX_FEE_RATE_SAT_PER_VBYTE = 5000 sat/vB = 1_250_000 sat/kw
		expect(v2Calls[0].fundingFeeratePerkw).to.equal(1_250_000);
	});

	it('leaves the rate unset when neither caller nor estimator has one', function () {
		// openChannelV2 then falls back to the configured commitment feerate,
		// the same last resort the estimator-less v1 path lands on.
		wirePeer(true);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(node as any).feeAdvisor = { getCurrentRate: (): number => 0 };
		node.openChannel(peerPubkey, 100_000n);
		expect(v2Calls.length).to.equal(1);
		expect(v2Calls[0].fundingFeeratePerkw).to.equal(undefined);
	});

	it('rejects a push on a dual-funded open with an honest error', function () {
		wirePeer(true);
		expect(() => node.openChannel(peerPubkey, 100_000n, 10_000_000n)).to.throw(
			/push.*open_channel2/i
		);
		expect(v1Calls.length).to.equal(0);
		expect(v2Calls.length).to.equal(0);
	});

	it('rejects max funding on a dual-funded open with an honest error', function () {
		wirePeer(true);
		expect(() =>
			node.openChannel(peerPubkey, 100_000n, undefined, 5, true)
		).to.throw(/max funding.*not yet supported/i);
		expect(v2Calls.length).to.equal(0);
	});

	it('a zero push routes to v2 rather than erroring', function () {
		// pushMsat: 0n expresses "no push"; only an actual push is impossible
		// to represent in open_channel2.
		wirePeer(true);
		node.openChannel(peerPubkey, 100_000n, 0n);
		expect(v2Calls.length).to.equal(1);
	});

	it('a v2 open honors preferTaproot in its default channel_type', function () {
		// Same call, same node config, must mean the same channel type whether
		// the peer routed us to v1 or v2. initiateOpen (v1) sends the single
		// OPTION_TAPROOT bit when preferTaproot is set; the v2 default must
		// match rather than silently opening a static_remotekey channel.
		const taprootNode = new LightningNode({
			nodePrivateKey: crypto.randomBytes(32),
			perCommitmentSeed: crypto.randomBytes(32),
			channelBasepoints: makeBasepoints(),
			fundingPrivkey: crypto.randomBytes(32),
			localFeatures: LightningNode.defaultFeatures(),
			preferTaproot: true
		});
		taprootNode.on('error', () => {});
		const channel = taprootNode.openChannelV2(peerPubkey, {
			fundingSatoshis: 100_000n
		});
		const channelType = channel.getDualFundingSession()!.getOpenChannelType();
		expect(channelType, 'channel_type present').to.exist;
		const flags = new FeatureFlags(channelType!);
		expect(
			flags.hasFeature(Feature.OPTION_TAPROOT),
			'taproot bit set'
		).to.equal(true);
		expect(
			flags.hasFeature(Feature.STATIC_REMOTE_KEY),
			'no extra bits beside the taproot bit'
		).to.equal(false);
		taprootNode.destroy();
	});

	it('does not use v2 when our own features omit option_dual_fund', function () {
		const flags = FeatureFlags.empty();
		flags.setCompulsory(Feature.STATIC_REMOTE_KEY);
		const bare = new LightningNode({
			nodePrivateKey: crypto.randomBytes(32),
			perCommitmentSeed: crypto.randomBytes(32),
			channelBasepoints: makeBasepoints(),
			fundingPrivkey: crypto.randomBytes(32),
			localFeatures: flags
		});
		bare.on('error', () => {});
		const saved = node;
		node = bare; // reuse wirePeer/afterEach against this node
		wirePeer(true);
		node.openChannel(peerPubkey, 100_000n);
		expect(v1Calls.length, 'v1 used: dual fund not negotiated by us').to.equal(
			1
		);
		expect(v2Calls.length).to.equal(0);
		saved.destroy();
	});
});
