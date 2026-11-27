/**
 * #2151 Step 3b, contract section 8 file 1: the host's conversion surface
 * and its gates (section 1). `completeAssetConversionHost` with each part
 * missing or out of bounds, the bit gate on it, the manager's wiring, and
 * what AUXILIARY_CHANNELS_API declares.
 */
import { expect } from 'chai';
import * as lightningChannel from '../../src/lightning/channel';
import { AUXILIARY_CHANNELS_API } from '../../src/lightning/channel/auxiliary-api';
import { MAX_SPLICE_FEERATE_PERKW } from '../../src/lightning/channel/splice-weight';
import { Feature } from '../../src/lightning/features/flags';
import { BEIGNET_CUSTOM_MESSAGE_TYPE } from '../../src/lightning/message/custom';
import {
	completeRecoveryHost,
	CONVERSION_HOST_KEYS,
	CONVERSION_HOST_MEMBERS,
	finalTestNode,
	type IFinalTestNode
} from './helpers/asset-conversion-node';
import { scratch } from './helpers/channel-type-pairs';
import {
	completeAssetConversionHost,
	conversionTransport
} from './helpers/conversion-modules';
import {
	agreeOnTerms,
	conversionPair,
	readReply,
	startConversion,
	storeTerms,
	termsFrames,
	termsIdentity,
	track
} from './helpers/conversion-managers';

const NOT_OFFERED = 'Asset conversion is not offered by this node';
const CONVERSION = Feature.OPTION_ASSET_CONVERSION;

/** A host with exactly the conversion surface: six members, the version and a margin. */
function conversionHost(): Record<string, unknown> {
	return {
		assetConversionVersion: 1,
		conversionFeerateMarginPerKw: 0,
		...Object.fromEntries(
			CONVERSION_HOST_MEMBERS.map((name) => [name, (): void => undefined])
		)
	};
}

describe('completeAssetConversionHost (#2151 step 3b, section 1)', () => {
	const complete = (host: unknown): boolean =>
		completeAssetConversionHost()(host);

	it('accepts a host with the six members, version 1 and a margin of 0', () => {
		expect(complete(conversionHost())).to.equal(true);
	});

	it('accepts the complete recovery host of the tests', () => {
		expect(complete(completeRecoveryHost())).to.equal(true);
	});

	it('refuses no host at all', () => {
		expect(complete(undefined)).to.equal(false);
		expect(complete(null)).to.equal(false);
	});

	for (const name of CONVERSION_HOST_MEMBERS) {
		it(`refuses a host without ${name}`, () => {
			const host = conversionHost();
			delete host[name];
			expect(complete(host)).to.equal(false);
		});
		it(`refuses a host whose ${name} is not a function`, () => {
			expect(complete({ ...conversionHost(), [name]: {} })).to.equal(false);
		});
	}

	for (const version of [undefined, 0, 2, '1'])
		it(`refuses assetConversionVersion ${JSON.stringify(version)}`, () => {
			expect(
				complete({ ...conversionHost(), assetConversionVersion: version })
			).to.equal(false);
		});

	for (const margin of [
		undefined,
		-1,
		0.5,
		MAX_SPLICE_FEERATE_PERKW + 1,
		Number.NaN,
		Number.POSITIVE_INFINITY,
		'0'
	])
		it(`refuses a margin of ${String(margin)}`, () => {
			expect(
				complete({ ...conversionHost(), conversionFeerateMarginPerKw: margin })
			).to.equal(false);
		});

	for (const margin of [0, 1, MAX_SPLICE_FEERATE_PERKW])
		it(`accepts a margin of ${margin}`, () => {
			expect(
				complete({ ...conversionHost(), conversionFeerateMarginPerKw: margin })
			).to.equal(true);
		});

	it('replaces hasAssetConversionHost, which the transport no longer exports', () => {
		expect(conversionTransport()).to.not.have.property(
			'hasAssetConversionHost'
		);
	});

	it('stays internal, as do the layout check and its digest', () => {
		for (const name of [
			'completeAssetConversionHost',
			'hasAssetConversionHost',
			'checkConversionLayout',
			'assetConversionLayoutDigest'
		])
			expect(lightningChannel, name).to.not.have.property(name);
	});
});

describe('Bit 463 on the complete conversion host (#2151 step 3b, section 1)', function () {
	this.timeout(120000);
	const nodes: IFinalTestNode[] = [];
	afterEach(() => {
		for (const n of nodes.splice(0)) n.close();
	});
	const bits = (host?: ReturnType<typeof completeRecoveryHost>): boolean[] => {
		const n = finalTestNode(6, host ? { host } : {});
		nodes.push(n);
		const local = n.node.getLocalFeatures();
		return [local.hasBit(CONVERSION), local.hasBit(CONVERSION + 1)];
	};

	it('sets 463 on a generation 6 node with a complete conversion host', () => {
		expect(bits()).to.deep.equal([false, true]);
	});

	for (const key of CONVERSION_HOST_KEYS)
		it(`sets neither bit on a generation 6 node whose host lacks ${key}`, () => {
			expect(bits(completeRecoveryHost([], key))).to.deep.equal([false, false]);
		});

	it('sets neither bit when the host margin is out of bounds', () => {
		const host = {
			...completeRecoveryHost(),
			conversionFeerateMarginPerKw: -1
		} as unknown as ReturnType<typeof completeRecoveryHost>;
		expect(bits(host)).to.deep.equal([false, false]);
	});
});

describe('The manager offers conversion only to a complete host (#2151 step 3b, section 1)', function () {
	this.timeout(90000);
	const s = scratch('conversion-host-wiring-');
	after(() => s.release());

	for (const name of [
		'proposeConversion',
		'describeConversion',
		'prepareConversion'
	])
		it(`answers "${NOT_OFFERED}" with 3a's three members but no ${name}`, async () => {
			const p = await conversionPair(s, 'plain');
			delete (p.dualFunding[0] as unknown as Record<string, unknown>)[name];
			await p.restart(0);
			agreeOnTerms(p);
			const start = track(
				startConversion(p.managers[0], p.channelId, {
					reference: Buffer.alloc(8, 1)
				})
			);
			await start.done;
			expect(start.error).to.equal(NOT_OFFERED);
			// Side 1 sends terms; side 0 answers as the no-transport responder.
			p.link.script(1);
			const t = storeTerms(p.stores[1], p.id);
			const id = termsIdentity(t, undefined, 'acceptor');
			for (const raw of termsFrames(id.attempt, id.bytes))
				p.link.send(1, BEIGNET_CUSTOM_MESSAGE_TYPE, raw);
			await p.settle();
			const reply = p.link.inbox[1].find((m) => m.name === 'conversion_reply');
			expect(reply && readReply(reply)).to.deep.include({
				accept: false,
				reason: NOT_OFFERED
			});
		});
});

describe('What the build declares (#2151 step 3b, section 1)', () => {
	it('declares assetConversion:v1, frozen, under the amended rule', () => {
		expect([...AUXILIARY_CHANNELS_API.declared]).to.deep.equal([
			'assetConversion:v1'
		]);
		expect(Object.isFrozen(AUXILIARY_CHANNELS_API.declared)).to.equal(true);
		expect(
			(AUXILIARY_CHANNELS_API.surfaces as readonly string[]).includes(
				'assetConversion:v1'
			)
		).to.equal(false);
	});

	it('leaves the surfaces as they were', () => {
		expect([...AUXILIARY_CHANNELS_API.surfaces]).to.deep.equal([
			'valueIncomingHtlc:three-outcome',
			'sendPaymentToRoute:assetPayment',
			'getAuxiliaryPaymentHtlcs',
			'onHtlcResolved:htlcId',
			'queryAuxiliaryRoute',
			'fundAuxiliaryChannel:unsigned',
			'onFundingSigned',
			'abandonAuxiliaryOpen',
			'IChannelInfo.auxiliary',
			'setAuxiliaryPaymentGate',
			'getChannelMonitorState',
			'IPaymentInfo.auxiliary',
			'IPaymentInfo.auxiliaryValueMsat',
			'IInvoiceInfo.auxiliary',
			'IAuxiliaryChannelInfo.undeliveredOutcomes',
			'onHtlcResolved:never-sent',
			'getFixedOutputFeeStatus',
			'IPaymentInfo.unresolved',
			'IHoldInvoiceStateEvent.auxiliary',
			'prepareForward',
			'getFixedOutputFeeStatus:splitCoins',
			'getFixedOutputFeeStatus:reserve',
			'requireFeeCoinsToSettle',
			'onForwardLegResolved:quote',
			'IForwardingEvent.auxiliary',
			'setAuxiliaryForwardGate',
			'receiveInParts',
			'sendInParts',
			'createInvoice:assetInvoice',
			'dualFunding:v1',
			'assetSplice:v1',
			'assetSpliceRecovery:v1'
		]);
		expect(Object.isFrozen(AUXILIARY_CHANNELS_API.surfaces)).to.equal(true);
	});
});
