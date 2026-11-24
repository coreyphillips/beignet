import { expect } from 'chai';
import {
	DualFundingSession,
	DualFundingState
} from '../../../src/lightning/channel/dual-funding';
import { validateV2ChannelType } from '../../../src/lightning/channel/types';
import {
	FeatureFlags,
	hasUnsupportedRequiredFeatures
} from '../../../src/lightning/features/flags';
import {
	decodeOpenChannel2Message,
	encodeOpenChannel2Message,
	decodeAcceptChannel2Message,
	encodeAcceptChannel2Message
} from '../../../src/lightning/message/dual-funding';
import {
	decodeInitMessage,
	encodeInitMessage
} from '../../../src/lightning/message/init';
import { LightningNode } from '../../../src/lightning/node/lightning-node';

// Eclair v0.14.0 pins the fixed v2 fields and the two type TLVs separately.
// The open fixture below clears the announce flag for a private channel.
// https://github.com/ACINQ/eclair/blob/ec8c63b215b98148887237e3f050342a6ca61f4c/eclair-core/src/test/scala/fr/acinq/eclair/wire/protocol/LightningMessageCodecsSpec.scala#L314
// https://github.com/ACINQ/eclair/blob/ec8c63b215b98148887237e3f050342a6ca61f4c/eclair-core/src/test/scala/fr/acinq/eclair/wire/protocol/LightningMessageCodecsSpec.scala#L344
// https://github.com/lightning/bolts/blob/191462825ae341f0a27098765c075f01ca9bc6c2/bolt-simple-taproot.md#feature-bits
const hex = (s: string): Buffer => Buffer.from(s, 'hex');
const points = [
	'031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f',
	'024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766',
	'02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337',
	'03462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b',
	'0362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f7',
	'03f006a18d5653c4edf5391ff23a61f03ff83d237e880ee61187fa9f379a028e0a',
	'02989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f'
];
const keys = {
	fundingPubkey: hex(points[0]),
	revocationBasepoint: hex(points[1]),
	paymentBasepoint: hex(points[2]),
	delayedPaymentBasepoint: hex(points[3]),
	htlcBasepoint: hex(points[4]),
	firstPerCommitmentPoint: hex(points[5]),
	secondPerCommitmentPoint: hex(points[6])
};
const channelIdHex = '01' + '00'.repeat(31);
const channelId = hex(channelIdHex);
const chainHash = Buffer.alloc(32);
const openFixed =
	'00'.repeat(32) +
	channelIdHex +
	'0000138800000fa0000000000003d09000000000000001f4000000000000c350000000000000000f009001e30009eb10' +
	points.join('') +
	'00';
const acceptFixed =
	channelIdHex +
	'000000000000c35000000000000001d90000000005f5e10000000000000000010000000600900032' +
	points.join('');
const opener = {
	...keys,
	channelId,
	chainHash,
	fundingFeeratePerkw: 5000,
	commitmentFeeratePerkw: 4000,
	fundingSatoshis: 250000n,
	dustLimitSatoshis: 500n,
	maxHtlcValueInFlightMsat: 50000n,
	htlcMinimumMsat: 15n,
	toSelfDelay: 144,
	maxAcceptedHtlcs: 483,
	locktime: 650000,
	channelFlags: 0
};
const acceptor = {
	...keys,
	channelId,
	fundingSatoshis: 50000n,
	dustLimitSatoshis: 473n,
	maxHtlcValueInFlightMsat: 100000000n,
	htlcMinimumMsat: 1n,
	minimumDepth: 6,
	toSelfDelay: 144,
	maxAcceptedHtlcs: 50
};
const cases = [
	{
		name: 'type 80',
		type: '0100000000000000000000',
		tlv: '010b0100000000000000000000',
		typeBits: [80],
		init: '0200002000200028000000',
		initBits: [27, 29, 45, 61, 81]
	},
	{
		name: 'type 80 with SCID alias',
		type: '0100000000400000000000',
		tlv: '010b0100000000400000000000',
		typeBits: [46, 80],
		init: '0200002000a00028000000',
		initBits: [27, 29, 45, 47, 61, 81]
	}
];

describe('Final Taproot explicit channel type vectors', () => {
	for (const v of cases) {
		it(`encodes and decodes the private open_channel2 for ${v.name}`, () => {
			const payload = hex(openFixed + v.tlv);
			const msg = { ...opener, channelType: hex(v.type) };
			expect(
				FeatureFlags.fromBuffer(msg.channelType).listSetBits()
			).to.deep.equal(v.typeBits);
			expect(encodeOpenChannel2Message(msg)).to.deep.equal(payload);
			expect(decodeOpenChannel2Message(payload)).to.deep.equal(msg);
		});
		it(`encodes and decodes the accept_channel2 echo for ${v.name}`, () => {
			const payload = hex(acceptFixed + v.tlv);
			const msg = { ...acceptor, channelType: hex(v.type) };
			expect(encodeAcceptChannel2Message(msg)).to.deep.equal(payload);
			expect(decodeAcceptChannel2Message(payload)).to.deep.equal(msg);
		});
		it(`keeps init dependencies out of the channel type for ${v.name}`, () => {
			// Optional bits for shutdown_anysegwit, dual funding, explicit type,
			// simple close, final Taproot, and the alias when present.
			const flags = FeatureFlags.empty();
			for (const bit of v.initBits) flags.setBit(bit);
			const payload = hex('0000000b' + v.init);
			expect(encodeInitMessage({ features: flags })).to.deep.equal(payload);
			expect(decodeInitMessage(payload).features.listSetBits()).to.deep.equal(
				v.initBits
			);
			expect(validateV2ChannelType(hex(v.type), flags, flags)).to.be.a(
				'string'
			);
		});
	}

	it('does not advertise final Taproot by default or accept the required peer bit', () => {
		const local = LightningNode.defaultFeatures();
		expect(local.hasBit(80)).to.equal(false);
		expect(local.hasBit(81)).to.equal(false);
		const compulsory = FeatureFlags.fromBuffer(hex(cases[0].type));
		const optional = FeatureFlags.fromBuffer(hex(cases[0].init));
		expect(hasUnsupportedRequiredFeatures(local, compulsory)).to.include(80);
		expect(hasUnsupportedRequiredFeatures(local, optional)).to.deep.equal([]);
	});

	it('rejects an absent, padded, or substituted type echo before starting interactive construction', () => {
		for (const [offer, other] of [
			[cases[0], cases[1]],
			[cases[1], cases[0]]
		]) {
			const session = new DualFundingSession(true, channelId);
			// Exercise the wire session directly; the node's admission policy is separate.
			const proposed = session.initiateOpen({
				...opener,
				channelType: hex(offer.type),
				localBasepoints: keys,
				localPerCommitmentSeed: Buffer.alloc(32)
			});
			expect(proposed.ok).to.equal(true);
			for (const returned of [
				undefined,
				hex('00' + offer.type),
				hex(other.type)
			]) {
				const result = session.handleAcceptChannel2({
					...acceptor,
					channelType: returned
				});
				expect(result.ok).to.equal(false);
				expect(result.error).to.match(
					/omitted the channel_type|channel type mismatch/i
				);
				expect(session.getState()).to.equal(DualFundingState.AWAITING_ACCEPT);
				expect(session.getTxState()).to.equal(null);
			}
		}
	});
});
