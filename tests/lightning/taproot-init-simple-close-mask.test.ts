/**
 * Issue #1929: LND 0.21 runs its RBF close (closing_complete / closing_sig)
 * on every taproot channel once both inits carry option_simple_close, and
 * this node only speaks closing_signed for taproot channels. Until the
 * taproot form of simple close exists, a node that advertises taproot must
 * not advertise simple close, so LND keeps its legacy closer for every
 * channel with us.
 */

import { expect } from 'chai';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { makeNodeConfig } from './helpers/ffor-world';

describe('option_simple_close is not advertised beside taproot (issue #1929)', function () {
	const nodes: LightningNode[] = [];
	afterEach(() => {
		for (const node of nodes.splice(0)) node.destroy();
	});

	function createNode(
		seedId: number,
		localFeatures: FeatureFlags
	): LightningNode {
		const node = new LightningNode(
			makeNodeConfig(seedId, undefined, { localFeatures })
		);
		nodes.push(node);
		return node;
	}

	it('the default set plus the staging taproot bit 181 loses bits 60 and 61', function () {
		const features = LightningNode.defaultFeatures();
		features.setOptional(Feature.OPTION_TAPROOT);
		expect(features.hasFeature(Feature.SIMPLE_CLOSE), 'default set').to.equal(
			true
		);

		const local = createNode(19291, features).getLocalFeatures();
		expect(local.hasBit(Feature.OPTION_TAPROOT + 1)).to.equal(true);
		expect(local.hasBit(Feature.SIMPLE_CLOSE)).to.equal(false);
		expect(local.hasBit(Feature.SIMPLE_CLOSE + 1)).to.equal(false);
		// The dependency stays: the mask is about the close form, not the
		// shutdown scripts we accept.
		expect(local.hasFeature(Feature.SHUTDOWN_ANY_SEGWIT)).to.equal(true);
	});

	it('the compulsory taproot bit 180 masks it too', function () {
		const features = LightningNode.defaultFeatures();
		features.setCompulsory(Feature.OPTION_TAPROOT);
		const local = createNode(19292, features).getLocalFeatures();
		expect(local.hasFeature(Feature.OPTION_TAPROOT)).to.equal(true);
		expect(local.hasFeature(Feature.SIMPLE_CLOSE)).to.equal(false);
	});

	it('the taproot interop node shape with bit 61 added ends up without it', function () {
		// tests/lightning/interop/lnd-taproot-helpers.ts, plus SIMPLE_CLOSE.
		const features = FeatureFlags.empty();
		features.setOptional(Feature.DATA_LOSS_PROTECT);
		features.setOptional(Feature.STATIC_REMOTE_KEY);
		features.setOptional(Feature.PAYMENT_SECRET);
		features.setOptional(Feature.TLV_ONION);
		features.setOptional(Feature.CHANNEL_TYPE);
		features.setOptional(Feature.GOSSIP_QUERIES);
		features.setOptional(Feature.ANCHOR_ZERO_FEE_HTLC);
		features.setOptional(Feature.OPTION_TAPROOT);
		features.setOptional(Feature.SIMPLE_CLOSE);

		const local = createNode(19293, features).getLocalFeatures();
		expect(local.hasFeature(Feature.OPTION_TAPROOT)).to.equal(true);
		expect(local.hasFeature(Feature.SIMPLE_CLOSE)).to.equal(false);
	});

	it('without taproot the default set keeps option_simple_close', function () {
		const local = createNode(
			19294,
			LightningNode.defaultFeatures()
		).getLocalFeatures();
		expect(local.hasFeature(Feature.OPTION_TAPROOT)).to.equal(false);
		expect(local.hasFeature(Feature.SIMPLE_CLOSE)).to.equal(true);
	});
});
