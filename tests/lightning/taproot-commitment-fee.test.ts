import { expect } from 'chai';
import crypto from 'crypto';
import { Channel } from '../../src/lightning/channel/channel';
import {
	ChannelAction,
	ChannelActionType
} from '../../src/lightning/channel/channel-actions';
import {
	createAcceptorState,
	IChannelState
} from '../../src/lightning/channel/channel-state';
import {
	calculateCommitmentFee,
	funderCommitmentCostSats
} from '../../src/lightning/channel/commitment-builder';
import {
	ChannelRole,
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	HtlcDirection,
	HtlcState
} from '../../src/lightning/channel/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import {
	IUpdateAddHtlcMessage,
	IUpdateFeeMessage
} from '../../src/lightning/message/channel-update';
import { MessageType } from '../../src/lightning/message/types';

/**
 * Issue 403: calculateCommitmentFee takes an isTaproot flag that selects the
 * 968-weight simple-taproot base instead of the 1124-weight witness-v0 anchor
 * base, and isAnchorChannel() is deliberately TRUE for taproot channels. A
 * caller that passed isAnchor and omitted isTaproot therefore did not fall back
 * to the 724 legacy weight, it landed on 1124: 156 weight units above what the
 * commitment builder actually charges, and above what the peer charges itself.
 *
 * The two receive-side guards then refused an update_add_htlc or an update_fee
 * that was legal by the peer's own arithmetic, and the refusal is a bare ERROR
 * the peer never sees, so its next commitment_signed covers state we do not
 * hold and the channel force closes. The two send-side guards refused our own
 * affordable fee bump and under-reported the outbound ceiling.
 *
 * Every fixture below sits EXACTLY on the 968-priced boundary, so it is
 * admitted after the fix and refused before it, and every one has a sibling one
 * unit past the boundary so the fix cannot overshoot.
 */

const ANCHORS_SATS = 660n;

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		keys.push(
			crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from([i]))
				.digest()
		);
	}
	return {
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: getPublicKey(keys[1])
	};
}

/** channel_type carrying ONLY the taproot bit, which is what LND proposes. */
function taprootType(): Buffer {
	const flags = FeatureFlags.empty();
	flags.setCompulsory(Feature.OPTION_TAPROOT);
	return flags.toBuffer();
}

/** The 3-bit spelling some fixtures use: static_remotekey + anchors + taproot. */
function taprootWithAnchorBitType(): Buffer {
	const flags = FeatureFlags.empty();
	flags.setCompulsory(Feature.STATIC_REMOTE_KEY);
	flags.setCompulsory(Feature.ANCHOR_ZERO_FEE_HTLC);
	flags.setCompulsory(Feature.OPTION_TAPROOT);
	return flags.toBuffer();
}

function anchorType(): Buffer {
	const flags = FeatureFlags.empty();
	flags.setOptional(Feature.ANCHOR_ZERO_FEE_HTLC);
	return flags.toBuffer();
}

interface IFixtureOpts {
	channelType: Buffer | null;
	/** ACCEPTOR (the peer funds) or OPENER (we fund). */
	role?: ChannelRole;
	/** localConfig.feeratePerKw: the committed rate when WE are the opener. */
	localFeeratePerKw?: number;
	/** remoteConfig.feeratePerKw: the committed rate when the PEER is opener. */
	remoteFeeratePerKw?: number;
	/** localConfig.channelReserveSatoshis: what we require of the peer. */
	enforceReserve?: bigint;
	/** remoteConfig.channelReserveSatoshis: what the peer requires of us. */
	keepReserve?: bigint;
	localMsat?: bigint;
	remoteMsat?: bigint;
	/** Extra COMMITTED HTLCs, which move the num_untrimmed_htlcs term. */
	htlcs?: { amountMsat: bigint; direction: HtlcDirection }[];
}

/**
 * A NORMAL channel with default dust limits (354 sat) and a 10,000-sat reserve
 * on both sides. The reserve stays at or above our dust limit, so
 * _localCommitmentEmptyRefusal short-circuits and no guard here ever reaches
 * the commitment builder, a signer or a MuSig2 nonce.
 *
 * pendingFeeratePerKw is deliberately left undefined so both fee-rate getters
 * collapse to the committed rate: remoteConfig.feeratePerKw when we are the
 * acceptor, localConfig.feeratePerKw when we are the opener.
 */
function makeChannel(opts: IFixtureOpts): Channel {
	const state: IChannelState = createAcceptorState({
		temporaryChannelId: crypto.randomBytes(32),
		fundingSatoshis: 1_000_000n,
		pushMsat: 0n,
		localConfig: {
			...DEFAULT_CHANNEL_CONFIG,
			channelReserveSatoshis: opts.enforceReserve ?? 10_000n,
			feeratePerKw: opts.localFeeratePerKw ?? 253
		},
		localBasepoints: makeBasepoints(
			crypto.createHash('sha256').update('local').digest()
		),
		localPerCommitmentSeed: crypto
			.createHash('sha256')
			.update('commit')
			.digest(),
		remoteBasepoints: makeBasepoints(
			crypto.createHash('sha256').update('remote').digest()
		),
		remoteConfig: {
			...DEFAULT_CHANNEL_CONFIG,
			channelReserveSatoshis: opts.keepReserve ?? 10_000n,
			feeratePerKw: opts.remoteFeeratePerKw ?? 253
		}
	});

	state.channelId = crypto.randomBytes(32);
	state.fundingTxid = crypto.randomBytes(32);
	state.fundingOutputIndex = 0;
	state.state = ChannelState.NORMAL;
	state.role = opts.role ?? ChannelRole.ACCEPTOR;
	state.channelType = opts.channelType;
	state.localBalanceMsat = opts.localMsat ?? 500_000_000n;
	state.remoteBalanceMsat = opts.remoteMsat ?? 500_000_000n;
	state.remoteCurrentPerCommitmentPoint =
		state.remoteBasepoints!.firstPerCommitmentPoint;
	state.remoteNextPerCommitmentPoint =
		state.remoteBasepoints!.firstPerCommitmentPoint;

	(opts.htlcs ?? []).forEach((h, i) => {
		const key = `${
			h.direction === HtlcDirection.OFFERED ? 'offered' : 'received'
		}-${i}`;
		state.htlcs.set(key, {
			id: BigInt(i),
			amountMsat: h.amountMsat,
			paymentHash: crypto.randomBytes(32),
			cltvExpiry: 600,
			onionRoutingPacket: Buffer.alloc(1366),
			direction: h.direction,
			state: HtlcState.COMMITTED
		});
	});

	return new Channel(state);
}

function addHtlcMsg(
	channel: Channel,
	amountMsat: bigint
): IUpdateAddHtlcMessage {
	return {
		channelId: channel.getChannelId()!,
		id: 99n,
		amountMsat,
		paymentHash: crypto.randomBytes(32),
		cltvExpiry: 500,
		onionRoutingPacket: Buffer.alloc(1366)
	};
}

function feeMsg(channel: Channel, feeratePerKw: number): IUpdateFeeMessage {
	return { channelId: channel.getChannelId()!, feeratePerKw };
}

const errorOf = (actions: ChannelAction[]): string | null => {
	for (const a of actions) {
		if (a.type === ChannelActionType.ERROR) {
			return (a as unknown as { message: string }).message;
		}
	}
	return null;
};

describe('Taproot commitment weight in the affordability guards (issue 403)', function () {
	describe('funderCommitmentCostSats', function () {
		it('prices each weight class and adds the anchor outputs where the builder does', function () {
			const cases: {
				rate: number;
				htlcs: number;
				taproot: bigint;
				anchor: bigint;
				legacy: bigint;
			}[] = [
				{ rate: 253, htlcs: 0, taproot: 904n, anchor: 944n, legacy: 183n },
				{
					rate: 10_000,
					htlcs: 0,
					taproot: 10_340n,
					anchor: 11_900n,
					legacy: 7_240n
				},
				{
					rate: 2_999,
					htlcs: 1,
					taproot: 4_078n,
					anchor: 4_546n,
					legacy: 2_687n
				},
				{
					rate: 5_000,
					htlcs: 3,
					taproot: 8_080n,
					anchor: 8_860n,
					legacy: 6_200n
				}
			];
			for (const c of cases) {
				expect(
					funderCommitmentCostSats(c.rate, c.htlcs, taprootType()),
					`taproot @ ${c.rate}/${c.htlcs}`
				).to.equal(c.taproot);
				expect(
					funderCommitmentCostSats(c.rate, c.htlcs, anchorType()),
					`anchor @ ${c.rate}/${c.htlcs}`
				).to.equal(c.anchor);
				expect(
					funderCommitmentCostSats(c.rate, c.htlcs, null),
					`legacy @ ${c.rate}/${c.htlcs}`
				).to.equal(c.legacy);
			}
		});

		it('reads the taproot bit ahead of the anchor bit, in either spelling', function () {
			// isAnchorChannel() is true for a taproot-only type, and LND's other
			// spelling sets the anchor bit outright, so the taproot base weight
			// must win in both.
			expect(funderCommitmentCostSats(10_000, 0, taprootType())).to.equal(
				10_340n
			);
			expect(
				funderCommitmentCostSats(10_000, 0, taprootWithAnchorBitType())
			).to.equal(10_340n);
		});

		it('keeps the 660-sat anchor add on taproot channels', function () {
			// A taproot commitment carries the two anchor outputs too, so only the
			// base weight differs from a witness-v0 anchor channel.
			expect(
				funderCommitmentCostSats(5_000, 2, taprootType()) -
					calculateCommitmentFee(5_000, 2, true, true)
			).to.equal(ANCHORS_SATS);
			expect(
				funderCommitmentCostSats(5_000, 2, null) -
					calculateCommitmentFee(5_000, 2, false, false)
			).to.equal(0n);
		});

		it('treats an empty channel_type as legacy', function () {
			expect(funderCommitmentCostSats(10_000, 0, Buffer.alloc(0))).to.equal(
				7_240n
			);
		});

		it('floors the whole weight, not a rounded 156-unit delta', function () {
			// 1140 * 2999 / 1000 floors to 3418 while 1296 * 2999 / 1000 floors to
			// 3886, a 468-sat gap; floor(156 * 2999 / 1000) is 467. Subtracting a
			// pre-rounded delta from the anchor price is off by one satoshi.
			const naive =
				funderCommitmentCostSats(2_999, 1, anchorType()) -
				BigInt(Math.floor((156 * 2_999) / 1000));
			expect(funderCommitmentCostSats(2_999, 1, taprootType())).to.equal(
				4_078n
			);
			expect(naive).to.equal(4_079n);
		});

		it('charges 172 weight units per untrimmed HTLC on every base', function () {
			for (const type of [taprootType(), anchorType(), null]) {
				expect(
					funderCommitmentCostSats(1_000, 2, type) -
						funderCommitmentCostSats(1_000, 1, type)
				).to.equal(172n);
			}
		});
	});

	describe('handleUpdateAddHtlc: the reserve the remote funder must hold', function () {
		// Acceptor at 5,000 sat/kw with one HTLC in the priced commitment:
		// taproot (968 + 172) * 5 = 5,700 sat, anchor (1124 + 172) * 5 = 6,480.
		// required = 10,000 reserve + fee + 660 anchors.
		const fixture = (channelType: Buffer | null, remoteMsat: bigint): Channel =>
			makeChannel({
				channelType,
				role: ChannelRole.ACCEPTOR,
				remoteFeeratePerKw: 5_000,
				enforceReserve: 10_000n,
				remoteMsat
			});

		it('admits an inbound HTLC the taproot 968-weight commitment can afford', function () {
			const channel = fixture(taprootType(), 20_000_000n);
			// 20,000,000 - 3,640,000 = 16,360,000 msat left, and the taproot
			// requirement is exactly (10,000 + 5,700 + 660) * 1000.
			const actions = channel.handleUpdateAddHtlc(
				addHtlcMsg(channel, 3_640_000n)
			);
			expect(errorOf(actions)).to.equal(null);
			const state = channel.getFullState();
			expect(state.htlcs.size).to.equal(1);
			expect(state.remoteBalanceMsat).to.equal(16_360_000n);
		});

		it('still refuses one msat past the taproot ceiling', function () {
			const channel = fixture(taprootType(), 20_000_000n);
			const actions = channel.handleUpdateAddHtlc(
				addHtlcMsg(channel, 3_640_001n)
			);
			expect(errorOf(actions)).to.equal(
				'Remote cannot afford HTLC above channel reserve'
			);
			const state = channel.getFullState();
			expect(state.htlcs.size).to.equal(0);
			expect(state.remoteBalanceMsat).to.equal(20_000_000n);
		});

		it('still prices a witness-v0 anchor channel at 1124', function () {
			const refused = fixture(anchorType(), 20_000_000n);
			expect(
				errorOf(refused.handleUpdateAddHtlc(addHtlcMsg(refused, 3_640_000n)))
			).to.equal('Remote cannot afford HTLC above channel reserve');
			// (10,000 + 6,480 + 660) * 1000 leaves 17,140,000 msat.
			const admitted = fixture(anchorType(), 20_000_000n);
			expect(
				errorOf(admitted.handleUpdateAddHtlc(addHtlcMsg(admitted, 2_860_000n)))
			).to.equal(null);
		});

		it('still prices a legacy channel at 724 with no anchor cost', function () {
			// (724 + 172) * 5 = 4,480 sat, no anchors: required 14,480,000 msat.
			const admitted = fixture(null, 20_000_000n);
			expect(
				errorOf(admitted.handleUpdateAddHtlc(addHtlcMsg(admitted, 5_520_000n)))
			).to.equal(null);
			const refused = fixture(null, 20_000_000n);
			expect(
				errorOf(refused.handleUpdateAddHtlc(addHtlcMsg(refused, 5_520_001n)))
			).to.equal('Remote cannot afford HTLC above channel reserve');
		});

		it('counts the 172-per-HTLC term on top of the taproot base', function () {
			// Two committed HTLCs plus the one being added: (968 + 516) * 5 = 7,420
			// sat taproot, (1124 + 516) * 5 = 8,200 anchor. They are OFFERED so the
			// inbound max-accepted count stays clear while the fee count moves.
			const channel = makeChannel({
				channelType: taprootType(),
				role: ChannelRole.ACCEPTOR,
				remoteFeeratePerKw: 5_000,
				enforceReserve: 10_000n,
				remoteMsat: 25_000_000n,
				htlcs: [
					{ amountMsat: 2_000_000n, direction: HtlcDirection.OFFERED },
					{ amountMsat: 2_000_000n, direction: HtlcDirection.OFFERED }
				]
			});
			// 25,000,000 - 6,920,000 = 18,080,000 = (10,000 + 7,420 + 660) * 1000.
			const actions = channel.handleUpdateAddHtlc(
				addHtlcMsg(channel, 6_920_000n)
			);
			expect(errorOf(actions)).to.equal(null);
			expect(channel.getFullState().remoteBalanceMsat).to.equal(18_080_000n);
		});
	});

	describe('handleUpdateFee: the peer opener must still clear its reserve', function () {
		// Acceptor, no HTLCs, proposed rate 10,000 sat/kw: taproot 968 * 10 = 9,680
		// sat plus 660, anchor 1124 * 10 = 11,240 plus 660. The committed rate is
		// 2,000 so the 10x relative cap (20,000) has headroom either way.
		const fixture = (channelType: Buffer | null, remoteMsat: bigint): Channel =>
			makeChannel({
				channelType,
				role: ChannelRole.ACCEPTOR,
				remoteFeeratePerKw: 2_000,
				enforceReserve: 10_000n,
				remoteMsat
			});

		it('accepts an update_fee the taproot 968-weight commitment can afford', function () {
			const channel = fixture(taprootType(), 20_340_000n);
			const actions = channel.handleUpdateFee(feeMsg(channel, 10_000));
			expect(errorOf(actions)).to.equal(null);
			const state = channel.getFullState();
			expect(state.pendingFeeratePerKw).to.equal(10_000);
			expect(state.remoteConfig.feeratePerKw).to.equal(2_000);
		});

		it('still refuses one msat under the taproot ceiling', function () {
			const channel = fixture(taprootType(), 20_339_999n);
			const actions = channel.handleUpdateFee(feeMsg(channel, 10_000));
			expect(errorOf(actions)).to.equal(
				'Fee rate would drain opener below channel reserve'
			);
			expect(channel.getFullState().pendingFeeratePerKw).to.equal(undefined);
		});

		it('floors the taproot weight rather than a rounded delta', function () {
			// At 2,999 sat/kw with one in-flight HTLC the taproot cost is 4,078 sat
			// and the anchor cost 4,546; a pre-rounded 156-unit delta would give
			// 4,079 and still refuse this exact balance.
			const channel = makeChannel({
				channelType: taprootType(),
				role: ChannelRole.ACCEPTOR,
				remoteFeeratePerKw: 500,
				enforceReserve: 10_000n,
				remoteMsat: 14_078_000n,
				htlcs: [{ amountMsat: 2_000_000n, direction: HtlcDirection.RECEIVED }]
			});
			expect(errorOf(channel.handleUpdateFee(feeMsg(channel, 2_999)))).to.equal(
				null
			);
			expect(channel.getFullState().pendingFeeratePerKw).to.equal(2_999);
		});

		it('still prices a witness-v0 anchor channel at 1124', function () {
			const refused = fixture(anchorType(), 20_340_000n);
			expect(
				errorOf(refused.handleUpdateFee(feeMsg(refused, 10_000)))
			).to.equal('Fee rate would drain opener below channel reserve');
			const admitted = fixture(anchorType(), 21_900_000n);
			expect(
				errorOf(admitted.handleUpdateFee(feeMsg(admitted, 10_000)))
			).to.equal(null);
		});

		it('still prices a legacy channel at 724 with no anchor cost', function () {
			const admitted = fixture(null, 17_240_000n);
			expect(
				errorOf(admitted.handleUpdateFee(feeMsg(admitted, 10_000)))
			).to.equal(null);
			const refused = fixture(null, 17_239_999n);
			expect(
				errorOf(refused.handleUpdateFee(feeMsg(refused, 10_000)))
			).to.equal('Fee rate would drain opener below channel reserve');
		});
	});

	describe('updateFee: our own fee bump as the opener', function () {
		// Opener with one in-flight HTLC proposing 25,000 sat/kw: taproot
		// (968 + 172) * 25 = 28,500 sat plus 660, anchor (1124 + 172) * 25 = 32,400
		// plus 660. There is no 10x relative cap on the send side.
		const fixture = (channelType: Buffer | null, localMsat: bigint): Channel =>
			makeChannel({
				channelType,
				role: ChannelRole.OPENER,
				localFeeratePerKw: 2_500,
				keepReserve: 10_000n,
				localMsat,
				htlcs: [{ amountMsat: 1_000_000n, direction: HtlcDirection.OFFERED }]
			});

		it('lets the opener propose a rate its taproot commitment can afford', function () {
			const channel = fixture(taprootType(), 39_160_000n);
			const actions = channel.updateFee(25_000);
			expect(errorOf(actions)).to.equal(null);
			expect(actions[0].type).to.equal(ChannelActionType.PERSIST_STATE);
			expect(actions[1].type).to.equal(ChannelActionType.SEND_MESSAGE);
			expect(
				(actions[1] as unknown as { messageType: MessageType }).messageType
			).to.equal(MessageType.UPDATE_FEE);
			expect(channel.getFullState().pendingFeeratePerKw).to.equal(25_000);
		});

		it('still refuses one msat under the taproot ceiling', function () {
			const channel = fixture(taprootType(), 39_159_999n);
			expect(errorOf(channel.updateFee(25_000))).to.equal(
				'Fee rate would drain opener below channel reserve'
			);
			const state = channel.getFullState();
			expect(state.pendingFeeratePerKw).to.equal(undefined);
			expect(state.pendingLocalUpdates.length).to.equal(0);
		});

		it('still prices a witness-v0 anchor channel at 1124', function () {
			expect(
				errorOf(fixture(anchorType(), 39_160_000n).updateFee(25_000))
			).to.equal('Fee rate would drain opener below channel reserve');
			expect(
				errorOf(fixture(anchorType(), 43_060_000n).updateFee(25_000))
			).to.equal(null);
		});

		it('still prices a legacy channel at 724 with no anchor cost', function () {
			// (724 + 172) * 25 = 22,400 sat, no anchors.
			expect(errorOf(fixture(null, 32_400_000n).updateFee(25_000))).to.equal(
				null
			);
			expect(errorOf(fixture(null, 32_399_999n).updateFee(25_000))).to.equal(
				'Fee rate would drain opener below channel reserve'
			);
		});
	});

	describe('getSpendableOutboundMsat: the outbound ceiling we report', function () {
		// Opener at 5,000 sat/kw. The fee-spike buffer prices at TWICE the rate
		// with two extra HTLC slots: taproot (968 + 344) * 10 = 13,120 sat, anchor
		// (1124 + 344) * 10 = 14,680. required = 10,000 reserve + fee + 660.
		const fixture = (channelType: Buffer | null, localMsat: bigint): Channel =>
			makeChannel({
				channelType,
				role: ChannelRole.OPENER,
				localFeeratePerKw: 5_000,
				keepReserve: 10_000n,
				localMsat
			});

		it('reports the taproot-priced ceiling', function () {
			expect(
				fixture(taprootType(), 100_000_000n).getSpendableOutboundMsat()
			).to.equal(76_220_000n);
		});

		it('saturates at zero only below the taproot requirement', function () {
			expect(
				fixture(taprootType(), 23_780_001n).getSpendableOutboundMsat()
			).to.equal(1n);
			expect(
				fixture(taprootType(), 23_780_000n).getSpendableOutboundMsat()
			).to.equal(0n);
		});

		it('admits an outbound HTLC at exactly the taproot ceiling', function () {
			const channel = fixture(taprootType(), 100_000_000n);
			const actions = channel.addHtlc(
				76_220_000n,
				crypto.randomBytes(32),
				500,
				Buffer.alloc(1366)
			);
			expect(errorOf(actions)).to.equal(null);
			const state = channel.getFullState();
			expect(state.htlcs.size).to.equal(1);
			expect(state.localBalanceMsat).to.equal(23_780_000n);
		});

		it('still refuses one msat past the taproot ceiling', function () {
			const channel = fixture(taprootType(), 100_000_000n);
			expect(
				errorOf(
					channel.addHtlc(
						76_220_001n,
						crypto.randomBytes(32),
						500,
						Buffer.alloc(1366)
					)
				)
			).to.equal('Insufficient balance for HTLC');
			expect(channel.getFullState().htlcs.size).to.equal(0);
		});

		it('still prices anchor and legacy channels unchanged', function () {
			expect(
				fixture(anchorType(), 100_000_000n).getSpendableOutboundMsat()
			).to.equal(74_660_000n);
			// (724 + 344) * 10 = 10,680 sat, no anchors.
			expect(fixture(null, 100_000_000n).getSpendableOutboundMsat()).to.equal(
				79_320_000n
			);
		});

		it('leaves the acceptor arm alone, where no commitment fee is retained', function () {
			for (const type of [taprootType(), anchorType(), null]) {
				const channel = makeChannel({
					channelType: type,
					role: ChannelRole.ACCEPTOR,
					localFeeratePerKw: 5_000,
					keepReserve: 10_000n,
					localMsat: 100_000_000n
				});
				expect(channel.getSpendableOutboundMsat()).to.equal(90_000_000n);
			}
		});
	});
});
