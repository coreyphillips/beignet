/**
 * max_htlc_value_in_flight_msat capacity scaling (issue #161).
 *
 * The default used to be a fixed 500k sat sent unclamped in open_channel and
 * accept_channel. CLN and LDK compute a channel's effective capacity as
 * min(capacity, peer's max_htlc_value_in_flight), so the fixed default capped
 * every larger channel's usable in-flight amount at 500k sat, and peers with a
 * min-capacity policy above 500k sat rejected our opens at any funding size.
 * The default is now "no artificial limit", clamped to channel capacity at
 * every open/accept build and re-clamped when a splice shrinks capacity.
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
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { createAcceptorState } from '../../src/lightning/channel/channel-state';
import {
	decodeOpenChannelMessage,
	decodeAcceptChannelMessage
} from '../../src/lightning/message/channel-open';

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

	describe('open_channel', function () {
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

	describe('accept_channel', function () {
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

	describe('splice', function () {
		it('re-clamps enforcement when a splice-out shrinks capacity', function () {
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
			).to.equal(600_000_000n);
		});

		it('leaves the limit unchanged when a splice-in grows capacity', function () {
			const { channel } = openMsgFor(1_000_000n);

			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			const ch = channel as any;
			ch._state.fundingSatoshis = 1_500_000n;
			ch._finishCompleteSplice();

			// The peer still holds the value negotiated at open; raising our own
			// enforcement above it would have no wire effect.
			expect(
				channel.getFullState().localConfig.maxHtlcValueInFlightMsat
			).to.equal(1_000_000_000n);
		});
	});
});
