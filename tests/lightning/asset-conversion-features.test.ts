/**
 * #2151 step 1, bit 463: the conversion feature and what it stands for
 * between two generation 6 peers (items 4, 5 and 11 at the predicate level).
 * Node masking and the type refusal of a node are in
 * asset-conversion-plain-gates.test.ts, which compiles on the base.
 */
import { expect } from 'chai';
import {
	finalOpeningChannelType,
	finalOpeningNegotiated
} from '../../src/lightning/features/final-opening';
import {
	Feature,
	FeatureFlags,
	implementedFeatures
} from '../../src/lightning/features/flags';
import {
	finalTestNode,
	type IFinalTestNode
} from './helpers/asset-conversion-node';

const today = [
	Feature.CHANNEL_TYPE,
	Feature.SHUTDOWN_ANY_SEGWIT,
	Feature.SIMPLE_CLOSE,
	Feature.DUAL_FUND,
	Feature.OPTION_SIMPLE_TAPROOT
];
const conversion = [
	Feature.OPTION_ASSET_CONVERSION,
	Feature.CHANNEL_TYPE,
	Feature.SHUTDOWN_ANY_SEGWIT,
	Feature.DUAL_FUND
];
function vector(features: readonly Feature[], except?: Feature): FeatureFlags {
	const flags = FeatureFlags.empty();
	for (const f of features) if (f !== except) flags.setOptional(f);
	return flags;
}
const plain = finalOpeningChannelType();
function aliased(): Buffer {
	const t = FeatureFlags.fromBuffer(plain);
	t.setCompulsory(Feature.SCID_ALIAS);
	return t.toBuffer();
}

describe('Asset conversion feature bits (#2151 step 1)', () => {
	it('is the optional pair 462/463, outside the implemented set', () => {
		expect(Feature.OPTION_ASSET_CONVERSION).to.equal(462);
		const flags = FeatureFlags.empty();
		flags.setOptional(Feature.OPTION_ASSET_CONVERSION);
		expect(flags.listSetBits()).to.deep.equal([463]);
		expect(implementedFeatures().hasBit(462)).to.equal(false);
		expect(implementedFeatures().hasBit(463)).to.equal(false);
	});
});

describe('finalOpeningNegotiated for a conversion wallet (#2151 step 1, item 5)', () => {
	it('accepts 463 on both in place of simple close and bits 80 or 81', () => {
		const local = vector(conversion),
			remote = vector(conversion);
		expect(local.hasFeature(Feature.SIMPLE_CLOSE)).to.equal(false);
		expect(local.hasFeature(Feature.OPTION_SIMPLE_TAPROOT)).to.equal(false);
		expect(finalOpeningNegotiated(local, remote, plain, true)).to.equal(true);
		// Today's dependencies alone do not stand in for 463 in a conversion wallet.
		expect(
			finalOpeningNegotiated(vector(today), vector(today), plain, true)
		).to.equal(false);
		expect(
			finalOpeningNegotiated(
				vector([...today, Feature.OPTION_ASSET_CONVERSION]),
				vector([...today, Feature.OPTION_ASSET_CONVERSION]),
				plain,
				true
			)
		).to.equal(true);
	});

	it('refuses 463 on only one side and any other missing dependency', () => {
		const without463 = vector(conversion, Feature.OPTION_ASSET_CONVERSION);
		expect(
			finalOpeningNegotiated(vector(conversion), without463, plain, true)
		).to.equal(false);
		expect(
			finalOpeningNegotiated(without463, vector(conversion), plain, true)
		).to.equal(false);
		for (const missing of conversion)
			for (const [a, b] of [
				[vector(conversion, missing), vector(conversion)],
				[vector(conversion), vector(conversion, missing)]
			])
				expect(
					finalOpeningNegotiated(a, b, plain, true),
					'missing ' + Feature[missing]
				).to.equal(false);
		expect(
			finalOpeningNegotiated(vector(conversion), undefined, plain, true)
		).to.equal(false);
		expect(
			finalOpeningNegotiated(
				vector(conversion),
				vector(conversion),
				Buffer.from('50', 'hex'),
				true
			)
		).to.equal(false);
	});

	it('requires SCID alias on both inits when the type sets the alias bit', () => {
		const local = vector(conversion),
			remote = vector(conversion);
		expect(finalOpeningNegotiated(local, remote, aliased(), true)).to.equal(
			false
		);
		local.setOptional(Feature.SCID_ALIAS);
		expect(finalOpeningNegotiated(local, remote, aliased(), true)).to.equal(
			false
		);
		remote.setOptional(Feature.SCID_ALIAS);
		expect(finalOpeningNegotiated(local, remote, aliased(), true)).to.equal(
			true
		);
	});

	it('gives exactly today results when conversionWallet is false', () => {
		const cases: Array<
			[string, FeatureFlags, FeatureFlags | undefined, Buffer]
		> = [
			['complete', vector(today), vector(today), plain],
			['no peer init', vector(today), undefined, plain],
			[
				'not a final type',
				vector(today),
				vector(today),
				Buffer.from('50', 'hex')
			],
			[
				'alias on one side',
				vector([...today, Feature.SCID_ALIAS]),
				vector(today),
				aliased()
			],
			[
				'alias on both',
				vector([...today, Feature.SCID_ALIAS]),
				vector([...today, Feature.SCID_ALIAS]),
				aliased()
			],
			[
				'463 in place of simple close',
				vector(conversion),
				vector(conversion),
				plain
			],
			[
				'463 beside the rest',
				vector([...today, Feature.OPTION_ASSET_CONVERSION]),
				vector(today),
				plain
			],
			...today.map((missing): [string, FeatureFlags, FeatureFlags, Buffer] => [
				'local missing ' + Feature[missing],
				vector(today, missing),
				vector(today),
				plain
			]),
			...today.map((missing): [string, FeatureFlags, FeatureFlags, Buffer] => [
				'remote missing ' + Feature[missing],
				vector(today),
				vector(today, missing),
				plain
			])
		];
		for (const [name, local, remote, type] of cases) {
			const before = finalOpeningNegotiated(local, remote, type);
			expect(finalOpeningNegotiated(local, remote, type, false), name).to.equal(
				before
			);
		}
		expect(
			cases
				.filter(([, l, r, t]) => finalOpeningNegotiated(l, r, t))
				.map(([n]) => n)
		).to.deep.equal(['complete', 'alias on both', '463 beside the rest']);
	});
});

describe('Plain final close between generation 6 nodes without simple close (#2151 step 1, item 11)', function () {
	this.timeout(60000);
	const nodes: IFinalTestNode[] = [];
	afterEach(() => {
		for (const n of nodes.splice(0)) n.close();
	});
	it('negotiates the plain final type from two node inits that clear simple close and set 463', () => {
		const [a, b] = [finalTestNode(6), finalTestNode(6)];
		nodes.push(a, b);
		const inits = [a, b].map((n) =>
			FeatureFlags.fromBuffer(n.node.getLocalFeatures().toBuffer())
		);
		for (const init of inits) {
			expect(init.hasFeature(Feature.SIMPLE_CLOSE), 'simple close').to.equal(
				false
			);
			expect(init.hasBit(463), 'bit 463').to.equal(true);
		}
		expect(finalOpeningNegotiated(inits[0], inits[1], plain)).to.equal(false);
		expect(finalOpeningNegotiated(inits[0], inits[1], plain, true)).to.equal(
			true
		);
	});
});
