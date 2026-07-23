/**
 * max_htlc_value_in_flight_msat policy (issue #161).
 *
 * The default used to be a fixed 500k sat sent unclamped in open_channel and
 * accept_channel. CLN and LDK compute a channel's effective capacity as
 * min(capacity, peer's max_htlc_value_in_flight), so the fixed default capped
 * every larger channel's usable in-flight amount at 500k sat, and peers with a
 * min-capacity policy above 500k sat rejected our opens at any funding size.
 *
 * The default is now "no artificial limit" (U64 max, the same sentinel CLN
 * advertises), sent as configured on every open/accept path, v1 and v2, and
 * never clamped to capacity: the advertisement is immutable for the life of
 * the channel while capacity is not (splice), so clamping at open would bake
 * the initial capacity in as a permanent ceiling. What we advertise is always
 * what localConfig enforces, and the negotiated value survives splices in
 * both directions.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	Channel,
	createOpenerChannel
} from '../../src/lightning/channel/channel';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
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
function findError(actions: any[]): string | null {
	for (const a of actions) {
		if (a.type === ChannelActionType.ERROR) return a.message;
	}
	return null;
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

describe('max_htlc_value_in_flight_msat policy', function () {
	describe('open_channel (v1)', function () {
		it('advertises the unlimited default, not the old 500k sat cap', function () {
			const { channel, msg } = openMsgFor(2_000_000n);
			expect(msg.maxHtlcValueInFlightMsat).to.equal(U64_MAX);
			expect(
				channel.getFullState().localConfig.maxHtlcValueInFlightMsat
			).to.equal(U64_MAX);
		});

		it('is not clamped to initial capacity (a later splice-in must not inherit a ceiling)', function () {
			const { msg } = openMsgFor(100_000n);
			expect(msg.maxHtlcValueInFlightMsat).to.equal(U64_MAX);
		});

		it('preserves an explicitly configured policy', function () {
			const { channel, msg } = openMsgFor(1_000_000n, 200_000_000n);
			expect(msg.maxHtlcValueInFlightMsat).to.equal(200_000_000n);
			expect(
				channel.getFullState().localConfig.maxHtlcValueInFlightMsat
			).to.equal(200_000_000n);
		});
	});

	describe('accept_channel (v1)', function () {
		it('advertises the configured value, matching localConfig enforcement', function () {
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

			expect(acceptMsg.maxHtlcValueInFlightMsat).to.equal(U64_MAX);
			expect(
				acceptor.getFullState().localConfig.maxHtlcValueInFlightMsat
			).to.equal(U64_MAX);
		});
	});

	describe('open_channel2 / accept_channel2 (v2)', function () {
		it('does not clamp the opener to its own contribution', function () {
			// A 100k opener contribution may end up in a 1M channel once the
			// acceptor contributes; clamping to the contribution would
			// permanently cap the channel.
			const { channel, msg } = v2OpenMsgFor(100_000n);
			expect(msg.maxHtlcValueInFlightMsat).to.equal(U64_MAX);
			expect(
				channel.getFullState().localConfig.maxHtlcValueInFlightMsat
			).to.equal(U64_MAX);
		});

		it('mirrors an explicit opener policy into localConfig enforcement', function () {
			// v2 params arrive separately from the state config: without the
			// write-back, the wire would carry 200M while enforcement read the
			// state config's U64 max (or worse, a lower value, rejecting HTLC
			// totals the peer is entitled to under the advertised limit).
			const { channel, msg } = v2OpenMsgFor(100_000n, 200_000_000n);
			expect(msg.maxHtlcValueInFlightMsat).to.equal(200_000_000n);
			expect(
				channel.getFullState().localConfig.maxHtlcValueInFlightMsat
			).to.equal(200_000_000n);
		});

		it('advertises the acceptor policy unclamped and mirrors it into localConfig', function () {
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
				v2Params(50_000n, acceptorState.localBasepoints, seed, 300_000_000n)
			);
			const acceptPayload = findSendAction(
				acceptActions,
				MessageType.ACCEPT_CHANNEL2
			)!;
			const acceptMsg = decodeAcceptChannel2Message(acceptPayload);

			expect(acceptMsg.maxHtlcValueInFlightMsat).to.equal(300_000_000n);
			expect(
				acceptor.getFullState().localConfig.maxHtlcValueInFlightMsat
			).to.equal(300_000_000n);
		});
	});

	describe('u64 range validation of local policy', function () {
		// The configured value is deliberately an exact wire policy now, so an
		// out-of-range bigint must surface as a channel ERROR action, not a
		// RangeError thrown from writeBigUInt64BE mid-serialization.
		it('rejects a value above u64 max (v1 open)', function () {
			const channel = createOpenerChannel({
				fundingSatoshis: 1_000_000n,
				localConfig: {
					...DEFAULT_CHANNEL_CONFIG,
					maxHtlcValueInFlightMsat: U64_MAX + 1n
				},
				localBasepoints: makeBasepoints(),
				localPerCommitmentSeed: crypto.randomBytes(32)
			});
			const err = findError(channel.initiateOpen());
			expect(err).to.contain('max_htlc_value_in_flight_msat');
		});

		it('rejects a negative value (v1 open)', function () {
			const channel = createOpenerChannel({
				fundingSatoshis: 1_000_000n,
				localConfig: {
					...DEFAULT_CHANNEL_CONFIG,
					maxHtlcValueInFlightMsat: -1n
				},
				localBasepoints: makeBasepoints(),
				localPerCommitmentSeed: crypto.randomBytes(32)
			});
			const err = findError(channel.initiateOpen());
			expect(err).to.contain('max_htlc_value_in_flight_msat');
		});

		it('rejects an out-of-range value (v2 open)', function () {
			const seed = crypto.randomBytes(32);
			const state = createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 100_000n,
				pushMsat: 0n,
				localConfig: { ...DEFAULT_CHANNEL_CONFIG },
				localBasepoints: makeBasepoints(),
				localPerCommitmentSeed: seed
			});
			const channel = new Channel(state);
			const actions = channel.initiateOpenV2(
				v2Params(100_000n, state.localBasepoints, seed, U64_MAX + 1n)
			);
			expect(findError(actions)).to.contain('max_htlc_value_in_flight_msat');
			// The failed open must not have mutated enforcement state.
			expect(
				channel.getFullState().localConfig.maxHtlcValueInFlightMsat
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
			const { channel } = openMsgFor(1_000_000n, 1_000_000_000n);
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
