/**
 * max_htlc_value_in_flight_msat capacity scaling (issue #161).
 *
 * The default used to be a fixed 500k sat sent unclamped in open_channel and
 * accept_channel. CLN and LDK compute a channel's effective capacity as
 * min(capacity, peer's max_htlc_value_in_flight), so the fixed default capped
 * every larger channel's usable in-flight amount at 500k sat, and peers with a
 * min-capacity policy above 500k sat rejected our opens at any funding size.
 *
 * The default is now "no artificial limit". The v1 open/accept builds clamp
 * the advertised value to capacity (exact and known there). The v2 builds
 * advertise it as-is: final capacity is unknown until after the message is
 * sent and the advertisement cannot be renegotiated, so clamping to a partial
 * contribution would permanently cap the channel. The negotiated value is
 * never re-clamped on splice: the peer holds us to what we advertised at
 * open, across capacity changes in both directions.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	Channel,
	createOpenerChannel
} from '../../src/lightning/channel/channel';
import {
	DEFAULT_CHANNEL_CONFIG,
	clampMaxHtlcValueInFlightMsat
} from '../../src/lightning/channel/types';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { MessageType } from '../../src/lightning/message/types';
import {
	IChannelBasepoints,
	perCommitmentPointFromSecret
} from '../../src/lightning/keys/derivation';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import {
	createOpenerState,
	createAcceptorState
} from '../../src/lightning/channel/channel-state';
import {
	decodeOpenChannelMessage,
	decodeAcceptChannelMessage
} from '../../src/lightning/message/channel-open';
import {
	decodeOpenChannel2Message,
	decodeAcceptChannel2Message
} from '../../src/lightning/message/dual-funding';
import { IDualFundingParams } from '../../src/lightning/channel/dual-funding';

const U64_MAX = 0xffffffffffffffffn;

function commitmentPoint(seed: Buffer, n: bigint): Buffer {
	return perCommitmentPointFromSecret(generateFromSeed(seed, MAX_INDEX - n));
}

function makeBasepoints(): IChannelBasepoints {
	return {
		fundingPubkey: getPublicKey(crypto.randomBytes(32)),
		revocationBasepoint: getPublicKey(crypto.randomBytes(32)),
		paymentBasepoint: getPublicKey(crypto.randomBytes(32)),
		delayedPaymentBasepoint: getPublicKey(crypto.randomBytes(32)),
		htlcBasepoint: getPublicKey(crypto.randomBytes(32)),
		firstPerCommitmentPoint: getPublicKey(crypto.randomBytes(32))
	};
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function findSendAction(actions: any[], msgType: MessageType): Buffer | null {
	for (const a of actions) {
		if (
			a.type === ChannelActionType.SEND_MESSAGE &&
			a.messageType === msgType
		) {
			return a.payload;
		}
	}
	return null;
}

function openMsgFor(
	fundingSatoshis: bigint,
	maxHtlcValueInFlightMsat?: bigint
): // eslint-disable-next-line @typescript-eslint/no-explicit-any
{ channel: Channel; msg: any } {
	const channel = createOpenerChannel({
		fundingSatoshis,
		localConfig: maxHtlcValueInFlightMsat
			? { ...DEFAULT_CHANNEL_CONFIG, maxHtlcValueInFlightMsat }
			: undefined,
		localBasepoints: makeBasepoints(),
		localPerCommitmentSeed: crypto.randomBytes(32)
	});
	const actions = channel.initiateOpen();
	const payload = findSendAction(actions, MessageType.OPEN_CHANNEL)!;
	return { channel, msg: decodeOpenChannelMessage(payload) };
}

function v2Params(
	fundingSatoshis: bigint,
	basepoints: IChannelBasepoints,
	seed: Buffer,
	maxHtlcValueInFlightMsat?: bigint
): IDualFundingParams {
	return {
		fundingSatoshis,
		fundingFeeratePerkw: 1000,
		commitmentFeeratePerkw: DEFAULT_CHANNEL_CONFIG.feeratePerKw,
		dustLimitSatoshis: DEFAULT_CHANNEL_CONFIG.dustLimitSatoshis,
		maxHtlcValueInFlightMsat:
			maxHtlcValueInFlightMsat ??
			DEFAULT_CHANNEL_CONFIG.maxHtlcValueInFlightMsat,
		htlcMinimumMsat: DEFAULT_CHANNEL_CONFIG.htlcMinimumMsat,
		toSelfDelay: DEFAULT_CHANNEL_CONFIG.toSelfDelay,
		maxAcceptedHtlcs: DEFAULT_CHANNEL_CONFIG.maxAcceptedHtlcs,
		locktime: 0,
		localBasepoints: basepoints,
		localPerCommitmentSeed: seed,
		secondPerCommitmentPoint: commitmentPoint(seed, 1n)
	};
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function v2OpenMsgFor(
	fundingSatoshis: bigint,
	maxHtlcValueInFlightMsat?: bigint
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
): { channel: Channel; msg: any } {
	const seed = crypto.randomBytes(32);
	const state = createOpenerState({
		temporaryChannelId: crypto.randomBytes(32),
		fundingSatoshis,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(),
		localPerCommitmentSeed: seed
	});
	const channel = new Channel(state);
	const actions = channel.initiateOpenV2(
		v2Params(
			fundingSatoshis,
			state.localBasepoints,
			seed,
			maxHtlcValueInFlightMsat
		)
	);
	const payload = findSendAction(actions, MessageType.OPEN_CHANNEL2)!;
	return { channel, msg: decodeOpenChannel2Message(payload) };
}

describe('max_htlc_value_in_flight_msat clamping', function () {
	describe('clampMaxHtlcValueInFlightMsat helper', function () {
		it('clamps values above capacity down to capacity', function () {
			expect(clampMaxHtlcValueInFlightMsat(500_000_000n, 100_000n)).to.equal(
				100_000_000n
			);
		});

		it('preserves values at or below capacity', function () {
			expect(clampMaxHtlcValueInFlightMsat(100_000_000n, 100_000n)).to.equal(
				100_000_000n
			);
			expect(clampMaxHtlcValueInFlightMsat(50_000_000n, 100_000n)).to.equal(
				50_000_000n
			);
		});
	});

	describe('open_channel (v1)', function () {
		it('advertises full capacity for a small channel (default config)', function () {
			const { msg } = openMsgFor(100_000n);
			expect(msg.maxHtlcValueInFlightMsat).to.equal(100_000_000n);
		});

		it('is not capped at 500k sat for a large channel', function () {
			// The old fixed default (500_000_000 msat) capped a 2M sat channel's
			// in-flight amount at a quarter of its capacity.
			const { msg } = openMsgFor(2_000_000n);
			expect(msg.maxHtlcValueInFlightMsat).to.equal(2_000_000_000n);
		});

		it('preserves an explicitly configured value below capacity', function () {
			const { msg } = openMsgFor(1_000_000n, 200_000_000n);
			expect(msg.maxHtlcValueInFlightMsat).to.equal(200_000_000n);
		});

		it('writes the advertised value back to localConfig for enforcement', function () {
			const { channel, msg } = openMsgFor(750_000n);
			expect(channel.getFullState().localConfig.maxHtlcValueInFlightMsat)
				.to.equal(msg.maxHtlcValueInFlightMsat)
				.and.to.equal(750_000_000n);
		});
	});

	describe('accept_channel (v1)', function () {
		it('clamps the advertised value to the opener capacity', function () {
			const { msg: openMsg } = openMsgFor(150_000n);

			const acceptorState = createAcceptorState({
				temporaryChannelId: openMsg.temporaryChannelId,
				fundingSatoshis: openMsg.fundingSatoshis,
				pushMsat: openMsg.pushMsat,
				localConfig: DEFAULT_CHANNEL_CONFIG,
				localBasepoints: makeBasepoints(),
				localPerCommitmentSeed: crypto.randomBytes(32),
				remoteBasepoints: {
					fundingPubkey: openMsg.fundingPubkey,
					revocationBasepoint: openMsg.revocationBasepoint,
					paymentBasepoint: openMsg.paymentBasepoint,
					delayedPaymentBasepoint: openMsg.delayedPaymentBasepoint,
					htlcBasepoint: openMsg.htlcBasepoint,
					firstPerCommitmentPoint: openMsg.firstPerCommitmentPoint
				},
				remoteConfig: {
					dustLimitSatoshis: openMsg.dustLimitSatoshis,
					maxHtlcValueInFlightMsat: openMsg.maxHtlcValueInFlightMsat,
					channelReserveSatoshis: openMsg.channelReserveSatoshis,
					htlcMinimumMsat: openMsg.htlcMinimumMsat,
					toSelfDelay: openMsg.toSelfDelay,
					maxAcceptedHtlcs: openMsg.maxAcceptedHtlcs,
					feeratePerKw: openMsg.feeratePerKw
				}
			});
			const acceptor = new Channel(acceptorState);
			const acceptActions = acceptor.handleOpenChannel(openMsg);
			const acceptPayload = findSendAction(
				acceptActions,
				MessageType.ACCEPT_CHANNEL
			)!;
			const acceptMsg = decodeAcceptChannelMessage(acceptPayload);

			expect(acceptMsg.maxHtlcValueInFlightMsat).to.equal(150_000_000n);
			expect(
				acceptor.getFullState().localConfig.maxHtlcValueInFlightMsat
			).to.equal(150_000_000n);
		});
	});

	describe('open_channel2 / accept_channel2 (v2)', function () {
		it('does not clamp the opener to its own contribution', function () {
			// Final capacity is unknown when open_channel2 is sent (a 100k
			// opener contribution may end up in a 1M channel once the acceptor
			// contributes), and the advertisement cannot be renegotiated.
			// Clamping to the contribution would permanently cap the channel:
			// the default must go out as-is.
			const { channel, msg } = v2OpenMsgFor(100_000n);
			expect(msg.maxHtlcValueInFlightMsat).to.equal(U64_MAX);
			expect(
				channel.getFullState().localConfig.maxHtlcValueInFlightMsat
			).to.equal(U64_MAX);
		});

		it('preserves an explicit opener policy', function () {
			const { msg } = v2OpenMsgFor(100_000n, 200_000_000n);
			expect(msg.maxHtlcValueInFlightMsat).to.equal(200_000_000n);
		});

		it('does not clamp the acceptor advertisement', function () {
			// A will_fund lease fee can still grow capacity after
			// accept_channel2 is sent, so the acceptor advertises as-is too.
			const { msg: openMsg } = v2OpenMsgFor(100_000n);

			const seed = crypto.randomBytes(32);
			const acceptorState = createAcceptorState({
				temporaryChannelId: Buffer.from(openMsg.channelId),
				fundingSatoshis: 0n,
				pushMsat: 0n,
				localConfig: { ...DEFAULT_CHANNEL_CONFIG },
				localBasepoints: makeBasepoints(),
				localPerCommitmentSeed: seed,
				remoteBasepoints: makeBasepoints(),
				remoteConfig: { ...DEFAULT_CHANNEL_CONFIG }
			});
			const acceptor = new Channel(acceptorState);
			const acceptActions = acceptor.handleOpenChannel2(
				openMsg,
				v2Params(50_000n, acceptorState.localBasepoints, seed)
			);
			const acceptPayload = findSendAction(
				acceptActions,
				MessageType.ACCEPT_CHANNEL2
			)!;
			const acceptMsg = decodeAcceptChannel2Message(acceptPayload);

			expect(acceptMsg.maxHtlcValueInFlightMsat).to.equal(U64_MAX);
			expect(
				acceptor.getFullState().localConfig.maxHtlcValueInFlightMsat
			).to.equal(U64_MAX);
		});
	});

	describe('splice', function () {
		it('keeps the negotiated limit across splice-out then splice-in', function () {
			// The peer holds us to the limit we advertised at open. Re-clamping
			// on splice-out would ratchet enforcement down permanently: after a
			// later splice-in the peer may legitimately fill the original limit
			// and we would erroneously reject its HTLCs. Balance and reserve
			// rules bound what can actually be in flight while capacity is low.
			const { channel } = openMsgFor(1_000_000n);
			expect(
				channel.getFullState().localConfig.maxHtlcValueInFlightMsat
			).to.equal(1_000_000_000n);

			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			const ch = channel as any;
			ch._state.fundingSatoshis = 600_000n;
			ch._finishCompleteSplice();
			expect(
				channel.getFullState().localConfig.maxHtlcValueInFlightMsat
			).to.equal(1_000_000_000n);

			ch._state.fundingSatoshis = 1_500_000n;
			ch._finishCompleteSplice();
			expect(
				channel.getFullState().localConfig.maxHtlcValueInFlightMsat
			).to.equal(1_000_000_000n);
		});
	});
});
