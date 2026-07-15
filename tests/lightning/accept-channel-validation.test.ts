/**
 * Regression (FS-1 / S-2.H2): the opener MUST validate accept_channel before
 * adopting the acceptor's parameters. Without it an adversarial acceptor sets an
 * unbounded dust_limit; every remote commitment we then build trims our
 * to_remote output as "dust", we sign it, and the acceptor force-closes to burn
 * our whole balance to fees.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	Channel,
	createOpenerChannel
} from '../../src/lightning/channel/channel';
import { createAcceptorState } from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { MessageType } from '../../src/lightning/message/types';
import {
	decodeOpenChannelMessage,
	decodeAcceptChannelMessage,
	IAcceptChannelMessage
} from '../../src/lightning/message/channel-open';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';

function realBasepoints(): IChannelBasepoints {
	const p = (): Buffer => getPublicKey(crypto.randomBytes(32));
	return {
		fundingPubkey: p(),
		revocationBasepoint: p(),
		paymentBasepoint: p(),
		delayedPaymentBasepoint: p(),
		htlcBasepoint: p(),
		firstPerCommitmentPoint: p()
	};
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function findSend(actions: any[], type: MessageType): Buffer | null {
	for (const a of actions) {
		if (a.type === ChannelActionType.SEND_MESSAGE && a.messageType === type) {
			return a.payload;
		}
	}
	return null;
}

/**
 * Drive a real opener to SENT_OPEN and produce a genuine accept_channel from an
 * acceptor, so callers can mutate it and feed it back to opener.handleAcceptChannel.
 */
function openerAndAccept(): {
	opener: Channel;
	accept: IAcceptChannelMessage;
} {
	const opener = createOpenerChannel({
		fundingSatoshis: 1_000_000n,
		localBasepoints: realBasepoints(),
		localPerCommitmentSeed: crypto.randomBytes(32)
	});
	const openActions = opener.initiateOpen();
	const openMsg = decodeOpenChannelMessage(
		findSend(openActions, MessageType.OPEN_CHANNEL)!
	);

	const acceptorState = createAcceptorState({
		temporaryChannelId: openMsg.temporaryChannelId,
		fundingSatoshis: openMsg.fundingSatoshis,
		pushMsat: openMsg.pushMsat,
		localConfig: DEFAULT_CHANNEL_CONFIG,
		localBasepoints: realBasepoints(),
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
	const accept = decodeAcceptChannelMessage(
		findSend(acceptActions, MessageType.ACCEPT_CHANNEL)!
	);
	return { opener, accept };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function errorOf(actions: any[]): string | null {
	const e = actions.find((a) => a.type === ChannelActionType.ERROR);
	return e ? e.message : null;
}

describe('FS-1: accept_channel validation', () => {
	it('accepts a well-formed accept_channel', () => {
		const { opener, accept } = openerAndAccept();
		const actions = opener.handleAcceptChannel(accept);
		expect(errorOf(actions), 'no error on a valid accept').to.be.null;
		expect(opener.getState()).to.equal(ChannelState.SENT_ACCEPT);
	});

	it('rejects an accept_channel with an unbounded dust_limit and keeps our state', () => {
		const { opener, accept } = openerAndAccept();
		accept.dustLimitSatoshis = 900_000n; // near our whole 1,000,000-sat balance

		const actions = opener.handleAcceptChannel(accept);
		const err = errorOf(actions);
		expect(err, 'a malicious dust_limit is rejected').to.match(/dust/i);
		// We did NOT adopt the hostile config, and we stay in SENT_OPEN.
		expect(opener.getState()).to.equal(ChannelState.SENT_OPEN);
		expect(opener.getFullState().remoteConfig?.dustLimitSatoshis).to.not.equal(
			900_000n
		);
	});

	it('rejects an accept_channel whose reserve is below our dust limit', () => {
		const { opener, accept } = openerAndAccept();
		accept.channelReserveSatoshis = 0n;

		const actions = opener.handleAcceptChannel(accept);
		expect(errorOf(actions), 'reserve below dust rejected').to.match(
			/reserve/i
		);
		expect(opener.getState()).to.equal(ChannelState.SENT_OPEN);
	});
});
