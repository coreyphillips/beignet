/**
 * FFOR concurrent receive, version 1: negotiation
 * (specs/CONCURRENT-RECEIVE.md section 1.1).
 *
 * R asks for the profile in ff_init TLV 17 and S selects it only by the
 * exact signed echo in ff_accept. Each peer must have advertised either bit
 * of 560/561 and of 562/563 first. An unsupported value, a missing feature,
 * a disallowed variant or profile, a missing, unsolicited or different echo
 * all end the setup, and a failed negotiation never continues as a baseline
 * epoch under the same epoch id.
 *
 * The cases follow `selectMode` in the spec's wire model
 * (specs/tools/concurrent-receive-wire.test.mjs), one for one, against two
 * ChannelManagers in loopback. Where the model says "throws", the engine's
 * answer is named: a local refusal, an ff_abort with its reason, or a
 * message that does not decode.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { MessageType } from '../../src/lightning/message/types';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';
import { Channel } from '../../src/lightning/channel/channel';
import { HtlcState } from '../../src/lightning/channel/types';
import {
	decodeFforAbortMessage,
	decodeFforAcceptMessage,
	decodeFforInitMessage,
	encodeFforAcceptUnsigned,
	encodeFforInitUnsigned,
	signFforMessage
} from '../../src/lightning/ffor/messages';
import {
	FF_ACCEPT_TYPE,
	FF_INIT_TYPE,
	FforAbortReason,
	FforState,
	FforVariant
} from '../../src/lightning/ffor/types';
import { serializeChannelState } from '../../src/lightning/storage/serialization';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	activateWorld,
	createConcurrentWorld
} from './helpers/ffor-concurrent-world';
import {
	AMOUNTS as WORLD_AMOUNTS,
	D_DEADLINE as WORLD_D,
	FEE_BASE,
	FEE_PPM,
	makeNodeConfig,
	record as nodeRecord,
	T_EXP as WORLD_T_EXP
} from './helpers/ffor-world';
import {
	activate,
	advertisedFeatures,
	AMOUNTS,
	createPair,
	D_DEADLINE,
	IPair,
	offer,
	record,
	restart,
	T_EXP,
	terms,
	vouchers,
	why
} from './helpers/ffor-concurrent-pair';

/** Every ff_abort on the wire, as [sender, reason, text]. */
function aborts(pair: IPair): Array<['S' | 'R', FforAbortReason, string]> {
	return pair.link.log
		.filter((e) => e.type === MessageType.FF_ABORT)
		.map((e) => {
			const m = decodeFforAbortMessage(e.payload);
			return [e.from, m.reason, m.data.toString('utf8')];
		});
}

/** The ff_init on the wire, decoded. */
function sentInit(pair: IPair): ReturnType<typeof decodeFforInitMessage> {
	const init = pair.link.log.find((e) => e.type === MessageType.FF_INIT);
	expect(init, 'ff_init on the wire').to.exist;
	return decodeFforInitMessage(init!.payload);
}

function sentAccept(pair: IPair): ReturnType<typeof decodeFforAcceptMessage> {
	const accept = pair.link.log.find((e) => e.type === MessageType.FF_ACCEPT);
	expect(accept, 'ff_accept on the wire').to.exist;
	return decodeFforAcceptMessage(accept!.payload);
}

/**
 * An ff_init R signs by hand: the terms of `terms()`, with `tlvs` (raw
 * bytes) appended to the TLV stream, so a test can carry any TLV 17.
 */
function craftInit(
	pair: IPair,
	tlvs: Buffer,
	over: { variant?: number; hashChain?: boolean } = {}
): { body: Buffer; epochId: Buffer } {
	const epochId = crypto.randomBytes(32);
	const unsigned = encodeFforInitUnsigned({
		channelId: pair.channelId,
		epochId,
		variant: over.variant ?? FforVariant.D,
		budgetMsat: AMOUNTS.reduce((a, b) => a + b, 0n),
		maxPayments: AMOUNTS.length,
		minPaymentMsat: 400_000n,
		settlementDeadline: D_DEADLINE,
		voucherExpiry: T_EXP,
		feeBaseMsat: 1000,
		feeProportionalMillionths: 5000,
		escapeGranularityMsat: 0n,
		rPerCommitmentPoints: [],
		voucherAmountsMsat: AMOUNTS,
		...(over.hashChain ? { hashChain: true } : {})
	});
	return {
		body: signFforMessage(
			FF_INIT_TYPE,
			Buffer.concat([unsigned, tlvs]),
			pair.rConfig.nodePrivateKey
		),
		epochId
	};
}

/**
 * R has sent ff_init (asking for the profile or not) and S's answer never
 * arrived. Returns S's real ff_accept, for a test to rewrite and deliver.
 */
function awaitingAccept(pair: IPair, concurrent: boolean): Buffer {
	pair.link.drop = (from): boolean => from === 'S';
	const res = pair.rManager.initiateFforEpoch(
		pair.channelId,
		terms(AMOUNTS, concurrent ? { concurrent: true } : {})
	);
	expect(res.ok, res.error).to.equal(true);
	pair.link.drop = null;
	const accept = pair.link.dropped.find(
		(e) => e.type === MessageType.FF_ACCEPT
	);
	expect(accept, 'S answered ff_accept').to.exist;
	expect(record(pair.rChannel).state).to.equal(FforState.NEGOTIATING);
	expect(record(pair.rChannel).acceptWire).to.equal(null);
	return accept!.payload;
}

/** S's ff_accept with its TLV 17 replaced by `tlv17` (raw bytes, or none). */
function reEcho(pair: IPair, accept: Buffer, tlv17: Buffer): Buffer {
	const decoded = decodeFforAcceptMessage(accept);
	const unsigned = encodeFforAcceptUnsigned({
		channelId: decoded.channelId,
		epochId: decoded.epochId,
		sCommitmentNumber: decoded.sCommitmentNumber,
		paymentHashes: decoded.paymentHashes,
		sHtlcIdBase: decoded.sHtlcIdBase,
		voucherAmountsMsat: decoded.voucherAmountsMsat,
		initHash: decoded.initHash
	});
	return signFforMessage(
		FF_ACCEPT_TYPE,
		Buffer.concat([unsigned, tlv17]),
		pair.sConfig.nodePrivateKey
	);
}

function usedIds(pair: IPair, side: 'S' | 'R'): string[] {
	const ch = side === 'S' ? pair.sChannel : pair.rChannel;
	return ch.getFullState().fforUsedEpochIds ?? [];
}

const NO_FEATURES = FeatureFlags.empty();
function only(...features: Feature[]): FeatureFlags {
	const flags = FeatureFlags.empty();
	for (const f of features) flags.setOptional(f);
	return flags;
}

describe('FFOR concurrent receive: negotiation (CONCURRENT-RECEIVE.md 1.1)', function () {
	this.timeout(60_000);

	describe('selection', () => {
		it('both pairs advertised, version requested and echoed: concurrent version 1', () => {
			const pair = createPair();
			activate(pair, AMOUNTS, true);
			expect(sentInit(pair).concurrentVersion).to.equal(1);
			expect(sentAccept(pair).concurrentVersion).to.equal(1);
			const init = pair.link.log.find((e) => e.type === MessageType.FF_INIT)!;
			// TLV 17 is the last record before the 64-byte signature.
			expect(init.payload.subarray(-68, -64).toString('hex')).to.equal(
				'11020001'
			);
			const accept = pair.link.log.find(
				(e) => e.type === MessageType.FF_ACCEPT
			)!;
			expect(accept.payload.subarray(-68, -64).toString('hex')).to.equal(
				'11020001'
			);
			for (const ch of [pair.sChannel, pair.rChannel]) {
				expect(record(ch).concurrentVersion).to.equal(1);
				expect(record(ch).params.concurrentVersion).to.equal(1);
			}
			// The fields are covered by T_init and T_setup, so by H_act.
			expect(record(pair.sChannel).hAct!.equals(record(pair.rChannel).hAct!)).to
				.be.true;
			expect(aborts(pair)).to.deep.equal([]);
			expect(pair.sErrors).to.deep.equal([]);
			expect(pair.rErrors).to.deep.equal([]);
		});

		it('no request: a baseline epoch, with TLV 17 in neither message, even between capable peers', () => {
			const pair = createPair();
			activate(pair, AMOUNTS, false);
			expect(sentInit(pair)).to.not.have.property('concurrentVersion');
			expect(sentAccept(pair)).to.not.have.property('concurrentVersion');
			for (const ch of [pair.sChannel, pair.rChannel]) {
				expect(record(ch)).to.not.have.property('concurrentVersion');
				expect(record(ch).params).to.not.have.property('concurrentVersion');
			}
			// An advertisement alone selects nothing: the epoch freezes the
			// channel as every baseline epoch does.
			const add = offer(pair, 'S', 5_000_000n);
			expect(add.result.ok).to.equal(false);
			expect(add.result.error).to.match(/no add until it drains/);
		});

		it('the selection is R setting it only on the echo, S as it answers', () => {
			const pair = createPair();
			const accept = awaitingAccept(pair, true);
			// S selected as it answered; R has only asked.
			expect(record(pair.sChannel).concurrentVersion).to.equal(1);
			expect(record(pair.rChannel).params.concurrentVersion).to.equal(1);
			expect(record(pair.rChannel)).to.not.have.property('concurrentVersion');
			pair.rManager.handleMessage(pair.sPub, MessageType.FF_ACCEPT, accept);
			expect(record(pair.rChannel).concurrentVersion).to.equal(1);
			expect(record(pair.rChannel).state).to.equal(FforState.NEGOTIATING);
		});
	});

	describe('the feature dependency', () => {
		const lacking: Array<[string, FeatureFlags]> = [
			['neither pair', NO_FEATURES],
			[
				'option_ff_receive only',
				only(Feature.QUIESCE, Feature.OPTION_FF_RECEIVE)
			],
			['option_ff_concurrent only', only(Feature.OPTION_FF_CONCURRENT)]
		];

		for (const [name, features] of lacking) {
			it(`R advertises ${name}: R does not ask`, () => {
				const pair = createPair();
				pair.rConfig.localFeatures = features;
				(
					pair.rManager as unknown as {
						config: { localFeatures: FeatureFlags };
					}
				).config.localFeatures = features;
				const res = pair.rManager.initiateFforEpoch(
					pair.channelId,
					terms(AMOUNTS, { concurrent: true })
				);
				expect(res.ok).to.equal(false);
				expect(res.error).to.match(/option_ff_concurrent is not negotiated/);
				// Nothing was sent and no epoch id was spent.
				expect(pair.link.log).to.deep.equal([]);
				expect(pair.rChannel.getFforEpoch()).to.equal(null);
				expect(usedIds(pair, 'R')).to.deep.equal([]);
			});

			it(`S advertises ${name}: R does not ask`, () => {
				const pair = createPair();
				pair.rManager.setFforPeerFeatureSource(() => features);
				const res = pair.rManager.initiateFforEpoch(
					pair.channelId,
					terms(AMOUNTS, { concurrent: true })
				);
				expect(res.ok).to.equal(false);
				expect(res.error).to.match(/option_ff_concurrent is not negotiated/);
				expect(pair.link.log).to.deep.equal([]);
				expect(pair.rChannel.getFforEpoch()).to.equal(null);
			});

			it(`S sees R advertise ${name}: S refuses the request with reason 2`, () => {
				const pair = createPair();
				// R asks anyway (a peer that does not check its own side).
				pair.sManager.setFforPeerFeatureSource(() => features);
				const res = pair.rManager.initiateFforEpoch(
					pair.channelId,
					terms(AMOUNTS, { concurrent: true })
				);
				expect(res.ok, res.error).to.equal(true);
				expect(aborts(pair)).to.deep.equal([
					[
						'S',
						FforAbortReason.TERMS_REFUSED,
						'concurrent_version requested without option_ff_receive and option_ff_concurrent negotiated'
					]
				]);
				expect(pair.sChannel.getFforEpoch()).to.equal(null);
				expect(record(pair.rChannel).state).to.equal(FforState.ABORTED);
				// Nothing was added to the channel.
				expect(pair.link.types()).to.not.include(MessageType.UPDATE_ADD_HTLC);
				expect(pair.sChannel.getFullState().htlcs.size).to.equal(0);
			});

			it(`S itself advertises ${name}: S refuses the request with reason 2`, () => {
				const pair = createPair();
				(
					pair.sManager as unknown as {
						config: { localFeatures: FeatureFlags };
					}
				).config.localFeatures = features;
				// R's view of S is stale: it still sees both pairs.
				pair.rManager.setFforPeerFeatureSource(() => advertisedFeatures(true));
				const res = pair.rManager.initiateFforEpoch(
					pair.channelId,
					terms(AMOUNTS, { concurrent: true })
				);
				expect(res.ok, res.error).to.equal(true);
				expect(aborts(pair).map((a) => a.slice(0, 2))).to.deep.equal([
					['S', FforAbortReason.TERMS_REFUSED]
				]);
				expect(pair.sChannel.getFforEpoch()).to.equal(null);
				expect(record(pair.rChannel).state).to.equal(FforState.ABORTED);
			});
		}

		it('a peer whose init is unknown has negotiated nothing', () => {
			const pair = createPair();
			pair.rManager.setFforPeerFeatureSource(() => null);
			const res = pair.rManager.initiateFforEpoch(
				pair.channelId,
				terms(AMOUNTS, { concurrent: true })
			);
			expect(res.ok).to.equal(false);
			expect(res.error).to.match(/option_ff_concurrent is not negotiated/);
			// A baseline epoch does not need the extension.
			activate(pair, AMOUNTS, false);
		});

		it('with no feature source at all the answer is the peer manager, which holds no init here', () => {
			const pair = createPair();
			pair.rManager.setFforPeerFeatureSource(null);
			const res = pair.rManager.initiateFforEpoch(
				pair.channelId,
				terms(AMOUNTS, { concurrent: true })
			);
			expect(res.ok).to.equal(false);
			expect(res.error).to.match(/option_ff_concurrent is not negotiated/);
		});
	});

	describe('the requested value', () => {
		for (const hex of ['0000', '0003', 'ffff']) {
			it(`ff_init TLV 17 = ${hex}: S refuses with reason 2 and adds nothing`, () => {
				const pair = createPair();
				const { body, epochId } = craftInit(
					pair,
					Buffer.from('1102' + hex, 'hex')
				);
				pair.sManager.handleMessage(pair.rPub, MessageType.FF_INIT, body);
				expect(aborts(pair)).to.deep.equal([
					[
						'S',
						FforAbortReason.TERMS_REFUSED,
						`concurrent_version ${parseInt(hex, 16)} not supported`
					]
				]);
				expect(pair.sChannel.getFforEpoch()).to.equal(null);
				expect(usedIds(pair, 'S')).to.deep.equal([epochId.toString('hex')]);
				expect(pair.link.types()).to.not.include(MessageType.FF_ACCEPT);
				expect(pair.sChannel.getFullState().htlcs.size).to.equal(0);
			});
		}

		for (const hex of ['1100', '110101', '1103000100']) {
			it(`ff_init TLV 17 malformed (${hex}): S answers nothing and starts nothing`, () => {
				const pair = createPair();
				const { body } = craftInit(pair, Buffer.from(hex, 'hex'));
				pair.sManager.handleMessage(pair.rPub, MessageType.FF_INIT, body);
				expect(pair.sErrors.join('|')).to.match(/undecodable ff_init/);
				expect(pair.link.log).to.deep.equal([]);
				expect(pair.sChannel.getFforEpoch()).to.equal(null);
				expect(pair.sChannel.getFullState().htlcs.size).to.equal(0);
			});
		}

		it('a well-formed request passes the same crafted path', () => {
			// The control for the cases above: the hand-built ff_init is one S
			// answers when its TLV 17 is the supported value.
			const pair = createPair();
			pair.link.drop = (from): boolean => from === 'S';
			const { body } = craftInit(pair, Buffer.from('11020001', 'hex'));
			pair.sManager.handleMessage(pair.rPub, MessageType.FF_INIT, body);
			expect(record(pair.sChannel).state).to.equal(FforState.NEGOTIATING);
			expect(record(pair.sChannel).concurrentVersion).to.equal(1);
			const accept = pair.link.dropped.find(
				(e) => e.type === MessageType.FF_ACCEPT
			)!;
			expect(
				decodeFforAcceptMessage(accept.payload).concurrentVersion
			).to.equal(1);
		});
	});

	describe('the variant and the profile', () => {
		for (const variant of [1, 2, 3]) {
			it(`variant ${variant} with TLV 17: S refuses with reason 2`, () => {
				const pair = createPair();
				const { body } = craftInit(pair, Buffer.from('11020001', 'hex'), {
					variant
				});
				pair.sManager.handleMessage(pair.rPub, MessageType.FF_INIT, body);
				expect(aborts(pair).map((a) => a.slice(0, 2))).to.deep.equal([
					['S', FforAbortReason.TERMS_REFUSED]
				]);
				expect(pair.sChannel.getFforEpoch()).to.equal(null);
			});
		}

		it('a hash chain (TLV 15) with TLV 17: S refuses with reason 2', () => {
			const pair = createPair();
			// Uniform amounts, so the chain itself would be acceptable.
			const epochId = crypto.randomBytes(32);
			const amounts = [1_000_000n, 1_000_000n];
			const unsigned = encodeFforInitUnsigned({
				channelId: pair.channelId,
				epochId,
				variant: FforVariant.D,
				budgetMsat: 2_000_000n,
				maxPayments: 2,
				minPaymentMsat: 400_000n,
				settlementDeadline: D_DEADLINE,
				voucherExpiry: T_EXP,
				feeBaseMsat: 1000,
				feeProportionalMillionths: 5000,
				escapeGranularityMsat: 0n,
				rPerCommitmentPoints: [],
				voucherAmountsMsat: amounts,
				hashChain: true,
				concurrentVersion: 1
			});
			pair.sManager.handleMessage(
				pair.rPub,
				MessageType.FF_INIT,
				signFforMessage(FF_INIT_TYPE, unsigned, pair.rConfig.nodePrivateKey)
			);
			expect(aborts(pair)).to.deep.equal([
				[
					'S',
					FforAbortReason.TERMS_REFUSED,
					'the concurrent profile takes no hash chain (ff_init TLV 15 must be absent)'
				]
			]);
			expect(pair.sChannel.getFforEpoch()).to.equal(null);
		});

		it('R does not ask for a hash chain and the profile together', () => {
			const pair = createPair();
			const res = pair.rManager.initiateFforEpoch(
				pair.channelId,
				terms([1_000_000n, 1_000_000n], { concurrent: true, hashChain: true })
			);
			expect(res.ok).to.equal(false);
			expect(res.error).to.match(/independent hashes, not a hash chain/);
			expect(pair.link.log).to.deep.equal([]);
			expect(pair.rChannel.getFforEpoch()).to.equal(null);
		});

		it('a hash chain without the profile is still the baseline chained book', () => {
			const pair = createPair();
			const res = pair.rManager.initiateFforEpoch(
				pair.channelId,
				terms([1_000_000n, 1_000_000n], { hashChain: true })
			);
			expect(res.ok, res.error).to.equal(true);
			expect(record(pair.rChannel).state, why(pair)).to.equal(FforState.ACTIVE);
			expect(record(pair.rChannel).params.hashChain).to.equal(true);
			expect(record(pair.rChannel)).to.not.have.property('concurrentVersion');
		});
	});

	describe("S's policy", () => {
		const refusing: Array<[string, IPair['sPolicy']]> = [
			['allowConcurrent false', { enabled: true, allowConcurrent: false }]
		];
		for (const [name, policy] of refusing) {
			it(`${name}: a concurrent request is refused with reason 2, a baseline one answered`, () => {
				const pair = createPair({ sPolicy: policy });
				const res = pair.rManager.initiateFforEpoch(
					pair.channelId,
					terms(AMOUNTS, { concurrent: true })
				);
				expect(res.ok, res.error).to.equal(true);
				expect(aborts(pair)).to.deep.equal([
					[
						'S',
						FforAbortReason.TERMS_REFUSED,
						'concurrent receive not offered by this peer'
					]
				]);
				expect(pair.sChannel.getFforEpoch()).to.equal(null);
				expect(record(pair.rChannel).state).to.equal(FforState.ABORTED);
				expect(record(pair.rChannel).abortReason).to.equal(
					FforAbortReason.TERMS_REFUSED
				);
				pair.link.log.length = 0;
				pair.sErrors.length = 0;
				pair.rErrors.length = 0;
				// A separate baseline attempt is a new epoch, and works.
				activate(pair, AMOUNTS, false);
			});
		}

		it('a settlement service that is off refuses both', () => {
			const pair = createPair({
				sPolicy: { enabled: false, allowConcurrent: true }
			});
			for (const concurrent of [true, false]) {
				pair.link.log.length = 0;
				const res = pair.rManager.initiateFforEpoch(
					pair.channelId,
					terms(AMOUNTS, concurrent ? { concurrent: true } : {})
				);
				expect(res.ok, res.error).to.equal(true);
				expect(aborts(pair)).to.deep.equal([
					[
						'S',
						FforAbortReason.TERMS_REFUSED,
						'settlement service not offered by this peer'
					]
				]);
			}
		});
	});

	describe('the echo', () => {
		it('missing (an S that ignores the odd TLV): R aborts with reason 2', () => {
			const pair = createPair();
			const accept = awaitingAccept(pair, true);
			pair.link.log.length = 0;
			pair.rManager.handleMessage(
				pair.sPub,
				MessageType.FF_ACCEPT,
				reEcho(pair, accept, Buffer.alloc(0))
			);
			const f = record(pair.rChannel);
			expect(f.state).to.equal(FforState.ABORTED);
			expect(f.abortReason).to.equal(FforAbortReason.TERMS_REFUSED);
			expect(f.acceptWire, 'not adopted').to.equal(null);
			expect(f).to.not.have.property('concurrentVersion');
			expect(aborts(pair)).to.deep.equal([
				[
					'R',
					FforAbortReason.TERMS_REFUSED,
					'ff_accept lacks the concurrent_version echo'
				]
			]);
		});

		for (const hex of ['0000', '0002']) {
			it(`different (${hex}): R aborts with reason 2`, () => {
				const pair = createPair();
				const accept = awaitingAccept(pair, true);
				pair.link.log.length = 0;
				pair.rManager.handleMessage(
					pair.sPub,
					MessageType.FF_ACCEPT,
					reEcho(pair, accept, Buffer.from('1102' + hex, 'hex'))
				);
				const f = record(pair.rChannel);
				expect(f.state).to.equal(FforState.ABORTED);
				expect(f.abortReason).to.equal(FforAbortReason.TERMS_REFUSED);
				expect(f.acceptWire).to.equal(null);
				expect(f).to.not.have.property('concurrentVersion');
				expect(aborts(pair).map((a) => a.slice(0, 2))).to.deep.equal([
					['R', FforAbortReason.TERMS_REFUSED]
				]);
			});
		}

		for (const hex of ['1100', '110101', '1103000100']) {
			it(`malformed (${hex}): R adopts nothing`, () => {
				const pair = createPair();
				const accept = awaitingAccept(pair, true);
				pair.link.log.length = 0;
				pair.rManager.handleMessage(
					pair.sPub,
					MessageType.FF_ACCEPT,
					reEcho(pair, accept, Buffer.from(hex, 'hex'))
				);
				expect(pair.rErrors.join('|')).to.match(/undecodable ff_accept/);
				const f = record(pair.rChannel);
				expect(f.acceptWire).to.equal(null);
				expect(f).to.not.have.property('concurrentVersion');
				// Not selected, and not a voucher round either: without an
				// adopted ff_accept nothing S adds is taken for a voucher.
				expect(f.state).to.equal(FforState.NEGOTIATING);
				expect(vouchers(pair.rChannel)).to.deep.equal([]);
			});
		}

		it('unsolicited (a baseline request answered with an echo): R aborts with reason 7', () => {
			const pair = createPair();
			const accept = awaitingAccept(pair, false);
			pair.link.log.length = 0;
			pair.rManager.handleMessage(
				pair.sPub,
				MessageType.FF_ACCEPT,
				reEcho(pair, accept, Buffer.from('11020001', 'hex'))
			);
			const f = record(pair.rChannel);
			expect(f.state).to.equal(FforState.ABORTED);
			expect(f.abortReason).to.equal(FforAbortReason.PROTOCOL_ERROR);
			expect(f.acceptWire).to.equal(null);
			expect(f).to.not.have.property('concurrentVersion');
			expect(aborts(pair)).to.deep.equal([
				[
					'R',
					FforAbortReason.PROTOCOL_ERROR,
					'ff_accept echoes a concurrent_version we did not request'
				]
			]);
		});

		it('exact: the control, R adopts and selects', () => {
			const pair = createPair();
			const accept = awaitingAccept(pair, true);
			pair.rManager.handleMessage(
				pair.sPub,
				MessageType.FF_ACCEPT,
				reEcho(pair, accept, Buffer.from('11020001', 'hex'))
			);
			const f = record(pair.rChannel);
			expect(f.state).to.equal(FforState.NEGOTIATING);
			expect(f.acceptWire).to.not.equal(null);
			expect(f.concurrentVersion).to.equal(1);
		});

		it('an echo whose signature does not verify selects nothing', () => {
			const pair = createPair();
			const accept = awaitingAccept(pair, true);
			const forged = Buffer.from(accept);
			forged[forged.length - 1] ^= 0x01;
			pair.rManager.handleMessage(pair.sPub, MessageType.FF_ACCEPT, forged);
			const f = record(pair.rChannel);
			expect(f.state).to.equal(FforState.ABORTED);
			expect(f.abortReason).to.equal(FforAbortReason.PROTOCOL_ERROR);
			expect(f).to.not.have.property('concurrentVersion');
		});
	});

	describe('a failed negotiation spends its epoch id', () => {
		it('refused by S: the id is burned on both sides and cannot carry a baseline retry', () => {
			const pair = createPair({
				sPolicy: { enabled: true, allowConcurrent: false }
			});
			const epochId = crypto.randomBytes(32);
			const first = pair.rManager.initiateFforEpoch(
				pair.channelId,
				terms(AMOUNTS, { concurrent: true, epochId })
			);
			expect(first.ok, first.error).to.equal(true);
			expect(record(pair.rChannel).state).to.equal(FforState.ABORTED);
			expect(usedIds(pair, 'S')).to.deep.equal([epochId.toString('hex')]);
			expect(usedIds(pair, 'R')).to.deep.equal([epochId.toString('hex')]);

			// R does not reuse it.
			const retry = pair.rManager.initiateFforEpoch(
				pair.channelId,
				terms(AMOUNTS, { epochId })
			);
			expect(retry.ok).to.equal(false);
			expect(retry.error).to.match(/epoch id is not fresh/);

			// And S does not answer it: a baseline ff_init under the spent id,
			// signed by R, gets ff_error alone and starts nothing.
			pair.link.log.length = 0;
			const unsigned = encodeFforInitUnsigned({
				channelId: pair.channelId,
				epochId,
				variant: FforVariant.D,
				budgetMsat: AMOUNTS.reduce((a, b) => a + b, 0n),
				maxPayments: AMOUNTS.length,
				minPaymentMsat: 400_000n,
				settlementDeadline: D_DEADLINE,
				voucherExpiry: T_EXP,
				feeBaseMsat: 1000,
				feeProportionalMillionths: 5000,
				escapeGranularityMsat: 0n,
				rPerCommitmentPoints: [],
				voucherAmountsMsat: AMOUNTS
			});
			pair.sManager.handleMessage(
				pair.rPub,
				MessageType.FF_INIT,
				signFforMessage(FF_INIT_TYPE, unsigned, pair.rConfig.nodePrivateKey)
			);
			expect(pair.link.types()).to.deep.equal([MessageType.FF_ERROR]);
			expect(pair.sChannel.getFforEpoch()).to.equal(null);
			expect(pair.sChannel.getFullState().htlcs.size).to.equal(0);

			// A baseline attempt under a NEW id is a new epoch.
			pair.link.log.length = 0;
			pair.sErrors.length = 0;
			pair.rErrors.length = 0;
			activate(pair, AMOUNTS, false);
			expect(record(pair.rChannel).epochId.equals(epochId)).to.equal(false);
		});

		it('refused by R at the echo: the id is burned and the record never becomes a baseline epoch', () => {
			const pair = createPair();
			const accept = awaitingAccept(pair, true);
			const epochId = record(pair.rChannel).epochId;
			pair.rManager.handleMessage(
				pair.sPub,
				MessageType.FF_ACCEPT,
				reEcho(pair, accept, Buffer.alloc(0))
			);
			expect(record(pair.rChannel).state).to.equal(FforState.ABORTED);
			expect(usedIds(pair, 'R')).to.include(epochId.toString('hex'));
			// S hears the abort and its epoch is over too.
			expect(record(pair.sChannel).state).to.equal(FforState.ABORTED);
			expect(usedIds(pair, 'S')).to.include(epochId.toString('hex'));
			// The same, late, well-formed echo does not revive it.
			pair.rManager.handleMessage(pair.sPub, MessageType.FF_ACCEPT, accept);
			expect(record(pair.rChannel).state).to.equal(FforState.ABORTED);
			expect(record(pair.rChannel)).to.not.have.property('concurrentVersion');
			const retry = pair.rManager.initiateFforEpoch(
				pair.channelId,
				terms(AMOUNTS, { epochId })
			);
			expect(retry.ok).to.equal(false);
		});
	});

	describe('the selected version is durable and not inferred', () => {
		for (const side of ['S', 'R'] as const) {
			it(`${side} restarts ACTIVE: the version comes back from disk with the transcript`, () => {
				const pair = createPair();
				activate(pair, AMOUNTS, true);
				const ch = side === 'S' ? pair.sChannel : pair.rChannel;
				const stored = serializeChannelState(ch.getFullState());
				expect(stored.ffor!.concurrentVersion).to.equal(1);
				expect(stored.ffor!.params.concurrentVersion).to.equal(1);
				restart(pair, side);
				const back = record(side === 'S' ? pair.sChannel : pair.rChannel);
				expect(back.state).to.equal(FforState.ACTIVE);
				expect(back.concurrentVersion).to.equal(1);
				expect(back.activationMismatch).to.equal(false);
				pair.link.reconnect();
				expect(record(pair.sChannel).state).to.equal(FforState.ACTIVE);
				expect(record(pair.rChannel).state).to.equal(FforState.ACTIVE);
				expect(pair.sErrors, why(pair)).to.deep.equal([]);
				expect(pair.rErrors, why(pair)).to.deep.equal([]);
			});
		}

		it('a concurrent epoch stays concurrent when the features are no longer advertised', () => {
			const pair = createPair();
			activate(pair, AMOUNTS, true);
			pair.link.disconnect();
			pair.sConfig.localFeatures.clearBit(Feature.OPTION_FF_CONCURRENT + 1);
			pair.rConfig.localFeatures.clearBit(Feature.OPTION_FF_CONCURRENT + 1);
			pair.link.reconnect();
			for (const ch of [pair.sChannel, pair.rChannel]) {
				expect(record(ch).concurrentVersion).to.equal(1);
				expect(record(ch).state).to.equal(FforState.ACTIVE);
				expect(record(ch).activationMismatch).to.equal(false);
			}
		});

		it('a baseline epoch stays baseline when the features appear later', () => {
			const pair = createPair({ concurrent: false });
			activate(pair, AMOUNTS, false);
			pair.link.disconnect();
			pair.sConfig.localFeatures.setOptional(Feature.OPTION_FF_CONCURRENT);
			pair.rConfig.localFeatures.setOptional(Feature.OPTION_FF_CONCURRENT);
			pair.link.reconnect();
			for (const ch of [pair.sChannel, pair.rChannel]) {
				expect(record(ch)).to.not.have.property('concurrentVersion');
				expect(record(ch).state).to.equal(FforState.ACTIVE);
			}
			// Still frozen: there is no upgrade of a live epoch.
			const add = offer(pair, 'S', 5_000_000n);
			expect(add.result.ok).to.equal(false);
			expect(add.result.error).to.match(/no add until it drains/);
			expect(
				vouchers(pair.rChannel).every(([, st]) => st === HtlcState.COMMITTED)
			).to.equal(true);
		});
	});
});

describe('FFOR concurrent receive: negotiation through the node (CONCURRENT-RECEIVE.md 1.1)', function () {
	this.timeout(120_000);

	describe('the fforConcurrent option', () => {
		it('advertises by default and honors explicit false', () => {
			const node = new LightningNode(makeNodeConfig(9001));
			expect(
				node.getLocalFeatures().hasFeature(Feature.OPTION_FF_CONCURRENT)
			).to.equal(true);
			const off = new LightningNode(
				makeNodeConfig(9002, undefined, { fforConcurrent: { enabled: false } })
			);
			expect(
				off.getLocalFeatures().hasFeature(Feature.OPTION_FF_CONCURRENT)
			).to.equal(false);
		});

		it('enabled: the optional bit 563 is advertised, beside option_ff_receive', () => {
			const node = new LightningNode(
				makeNodeConfig(9003, undefined, { fforConcurrent: { enabled: true } })
			);
			const flags = node.getLocalFeatures();
			expect(flags.hasBit(563)).to.equal(true);
			expect(flags.hasBit(562)).to.equal(false);
			expect(flags.hasFeature(Feature.OPTION_FF_RECEIVE)).to.equal(true);
		});

		it('a caller-supplied feature set cannot advertise it while the option is off', () => {
			const supplied = LightningNode.defaultFeatures();
			supplied.setOptional(Feature.OPTION_FF_CONCURRENT);
			supplied.setCompulsory(Feature.OPTION_FF_CONCURRENT);
			const node = new LightningNode(
				makeNodeConfig(9004, undefined, {
					localFeatures: supplied,
					fforConcurrent: { enabled: false }
				})
			);
			expect(
				node.getLocalFeatures().hasFeature(Feature.OPTION_FF_CONCURRENT)
			).to.equal(false);
		});

		it('omitted config tolerates missing dependencies, explicit true refuses them', () => {
			for (const missing of [Feature.OPTION_FF_RECEIVE, Feature.QUIESCE]) {
				const supplied = LightningNode.defaultFeatures();
				supplied.clearBit(missing);
				supplied.clearBit(missing + 1);
				const node = new LightningNode(
					makeNodeConfig(9006, undefined, { localFeatures: supplied })
				);
				expect(
					node.getLocalFeatures().hasFeature(Feature.OPTION_FF_CONCURRENT)
				).to.equal(false);
				expect(
					() =>
						new LightningNode(
							makeNodeConfig(9005, undefined, {
								localFeatures: supplied,
								fforConcurrent: { enabled: true }
							})
						)
				).to.throw(/needs option_ff_receive and option_quiesce/);
			}
		});
	});

	describe('between nodes', () => {
		it('both opted in and S allows it: the epoch is concurrent', () => {
			const w = createConcurrentWorld();
			activateWorld(w, true);
			expect(nodeRecord(w.s, w.srHex).concurrentVersion).to.equal(1);
			expect(nodeRecord(w.r, w.srHex).concurrentVersion).to.equal(1);
		});

		it('both opted in, no request: the epoch is baseline', () => {
			const w = createConcurrentWorld();
			activateWorld(w, false);
		});

		it('R has not opted in: it cannot ask', () => {
			const w = createConcurrentWorld({
				rExtra: {},
				concurrent: false,
				sExtra: { fforConcurrent: { enabled: true } }
			});
			const res = w.r.startFforEpoch(w.srHex, {
				voucherAmountsMsat: WORLD_AMOUNTS,
				minPaymentMsat: 400_000n,
				settlementDeadline: WORLD_D,
				voucherExpiry: WORLD_T_EXP,
				feeBaseMsat: FEE_BASE,
				feeProportionalMillionths: FEE_PPM,
				concurrent: true
			});
			expect(res.ok).to.equal(false);
			expect(res.error).to.match(/option_ff_concurrent is not negotiated/);
			expect(w.r.getFforEpoch(w.srHex)).to.equal(null);
		});

		it("S's node policy does not allow it: refused with reason 2, and a baseline epoch still runs", () => {
			const w = createConcurrentWorld({ allowConcurrent: false });
			const res = w.r.startFforEpoch(w.srHex, {
				voucherAmountsMsat: WORLD_AMOUNTS,
				minPaymentMsat: 400_000n,
				settlementDeadline: WORLD_D,
				voucherExpiry: WORLD_T_EXP,
				feeBaseMsat: FEE_BASE,
				feeProportionalMillionths: FEE_PPM,
				concurrent: true
			});
			expect(res.ok, res.error).to.equal(true);
			expect(nodeRecord(w.r, w.srHex).state).to.equal(FforState.ABORTED);
			expect(nodeRecord(w.r, w.srHex).abortReason).to.equal(
				FforAbortReason.TERMS_REFUSED
			);
			expect(w.s.getFforEpoch(w.srHex)).to.equal(null);
			activateWorld(w, false);
		});

		it('an S that answers without the echo: R aborts, the stray voucher adds are failed back and the channel is left clean', () => {
			const w = createConcurrentWorld();
			const sId = w.s.getNodeId();
			// An asynchronous link, so S's whole batch (ff_accept, the K adds,
			// the commitment_signed) is on the wire before R answers any of it.
			const queue: { from: string; type: number; payload: Buffer }[] = [];
			const wire: string[] = [];
			w.sr.drop = (from, type, payload): boolean => {
				queue.push({ from, type, payload });
				return true;
			};
			const srState = (
				node: LightningNode
			): ReturnType<Channel['getFullState']> =>
				node.getChannelManager().getChannel(w.srChannelId)!.getFullState();
			const before = {
				s: srState(w.s).localBalanceMsat,
				r: srState(w.r).localBalanceMsat
			};
			const res = w.r.startFforEpoch(w.srHex, {
				voucherAmountsMsat: WORLD_AMOUNTS,
				minPaymentMsat: 400_000n,
				settlementDeadline: WORLD_D,
				voucherExpiry: WORLD_T_EXP,
				feeBaseMsat: FEE_BASE,
				feeProportionalMillionths: FEE_PPM,
				concurrent: true
			});
			expect(res.ok, res.error).to.equal(true);
			while (queue.length > 0) {
				const m = queue.shift()!;
				let payload = m.payload;
				if (m.from === sId && m.type === MessageType.FF_ACCEPT) {
					// What an S that ignores the odd TLV would have signed.
					const d = decodeFforAcceptMessage(payload);
					expect(d.concurrentVersion).to.equal(1);
					payload = signFforMessage(
						FF_ACCEPT_TYPE,
						encodeFforAcceptUnsigned({
							channelId: d.channelId,
							epochId: d.epochId,
							sCommitmentNumber: d.sCommitmentNumber,
							paymentHashes: d.paymentHashes,
							sHtlcIdBase: d.sHtlcIdBase,
							voucherAmountsMsat: d.voucherAmountsMsat,
							initHash: d.initHash
						}),
						w.sConfig.nodePrivateKey!
					);
				}
				wire.push(`${m.from === sId ? 'S' : 'R'}:${m.type}`);
				(m.from === sId ? w.r : w.s).handlePeerMessage(m.from, m.type, payload);
			}
			w.sr.drop = null;
			const r = nodeRecord(w.r, w.srHex);
			expect(r.state).to.equal(FforState.ABORTED);
			expect(r.abortReason).to.equal(FforAbortReason.TERMS_REFUSED);
			expect(r).to.not.have.property('concurrentVersion');
			expect(nodeRecord(w.s, w.srHex).state).to.equal(FforState.ABORTED);
			// R never took S's adds for vouchers: they were ordinary HTLCs on
			// an unknown hash, and the node failed each one back.
			expect(
				wire.filter((m) => m === `R:${MessageType.UPDATE_FAIL_HTLC}`).length
			).to.equal(WORLD_AMOUNTS.length);
			expect(wire).to.not.include(`R:${MessageType.ERROR}`);
			expect(wire).to.not.include(`S:${MessageType.ERROR}`);
			expect(srState(w.s).htlcs.size).to.equal(0);
			expect(srState(w.r).htlcs.size).to.equal(0);
			expect(srState(w.s).localBalanceMsat).to.equal(before.s);
			expect(srState(w.r).localBalanceMsat).to.equal(before.r);
			// The id is spent; a baseline epoch under a new one runs.
			expect(srState(w.r).fforUsedEpochIds).to.include(
				r.epochId.toString('hex')
			);
			activateWorld(w, false);
		});
	});
});
