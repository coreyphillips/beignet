/**
 * Taproot cooperative-close fail-closed guard.
 *
 * Cooperative close is ECDSA/P2WSH-only today; a taproot channel's funding
 * output is a MuSig2 P2TR key-spend, so an attempted coop close could never
 * produce a satisfiable closing tx and would hang in NEGOTIATING_CLOSING.
 * Until a MuSig2 key-spend close exists, both shutdown entry points must
 * fail closed with a clear error and leave channel state untouched.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { Channel } from '../../src/lightning/channel/channel';
import {
	createOpenerState,
	createAcceptorState
} from '../../src/lightning/channel/channel-state';
import {
	DEFAULT_CHANNEL_CONFIG,
	isTaprootChannel
} from '../../src/lightning/channel/types';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { MessageType } from '../../src/lightning/message/types';
import { decodeErrorMessage } from '../../src/lightning/message/error';
import { decodeOpenChannelMessage } from '../../src/lightning/message/channel-open';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`taproot-close-guard-${id}`))
		.digest();
}

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
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

const P2WPKH_SCRIPT = Buffer.from('0014' + '11'.repeat(20), 'hex');

function makeTaprootOpener(): Channel {
	const opener = new Channel(
		createOpenerState({
			temporaryChannelId: crypto.randomBytes(32),
			fundingSatoshis: 500_000n,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: makeBasepoints(makeSeed(1)),
			localPerCommitmentSeed: makeSeed(101)
		})
	);
	// preferTaproot=true sets the option_taproot channel type
	opener.initiateOpen(undefined, false, true);
	expect(isTaprootChannel(opener.getFullState().channelType)).to.equal(true);
	return opener;
}

function makeTaprootAcceptor(): Channel {
	// Drive a taproot open message into a fresh acceptor so it adopts the
	// taproot channel type the same way ChannelManager does.
	const opener2 = new Channel(
		createOpenerState({
			temporaryChannelId: crypto.randomBytes(32),
			fundingSatoshis: 500_000n,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: makeBasepoints(makeSeed(3)),
			localPerCommitmentSeed: makeSeed(103)
		})
	);
	const actions = opener2.initiateOpen(undefined, false, true);
	const send = actions.find((a) => 'payload' in a) as { payload: Buffer };
	const openMsg = decodeOpenChannelMessage(send.payload);

	const acceptor = new Channel(
		createAcceptorState({
			temporaryChannelId: openMsg.temporaryChannelId,
			fundingSatoshis: openMsg.fundingSatoshis,
			pushMsat: openMsg.pushMsat,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: makeBasepoints(makeSeed(2)),
			localPerCommitmentSeed: makeSeed(102),
			remoteBasepoints: makeBasepoints(makeSeed(3)),
			remoteConfig: { ...DEFAULT_CHANNEL_CONFIG }
		})
	);
	acceptor.handleOpenChannel(openMsg);
	expect(isTaprootChannel(acceptor.getFullState().channelType)).to.equal(true);
	return acceptor;
}

describe('Taproot coop-close fail-closed guard', function () {
	it('initiateShutdown on a taproot channel fails closed with a clear error', function () {
		const opener = makeTaprootOpener();
		const stateBefore = opener.getState();

		const actions = opener.initiateShutdown(P2WPKH_SCRIPT);

		const err = actions.find((a) => a.type === ChannelActionType.ERROR) as {
			message: string;
		};
		expect(err, 'expected an ERROR action').to.exist;
		expect(err.message).to.match(/taproot/i);
		expect(err.message).to.match(/force-close/i);
		// No shutdown message sent, state untouched
		expect(
			actions.some((a) => a.type === ChannelActionType.SEND_MESSAGE)
		).to.equal(false);
		expect(opener.getState()).to.equal(stateBefore);
		expect(opener.getFullState().localShutdownScript).to.not.exist;
	});

	it('handleShutdown on a taproot channel warns the peer and leaves state untouched', function () {
		const acceptor = makeTaprootAcceptor();
		const stateBefore = acceptor.getState();
		const channelId = crypto.randomBytes(32);

		const actions = acceptor.handleShutdown({
			channelId,
			scriptPubkey: P2WPKH_SCRIPT
		});

		// ERROR action surfaced locally
		const err = actions.find((a) => a.type === ChannelActionType.ERROR) as {
			message: string;
		};
		expect(err, 'expected an ERROR action').to.exist;
		expect(err.message).to.match(/taproot/i);

		// WARNING sent to the peer, echoing their channel_id
		const warn = actions.find(
			(a) =>
				a.type === ChannelActionType.SEND_MESSAGE &&
				(a as { messageType: MessageType }).messageType === MessageType.WARNING
		) as { payload: Buffer };
		expect(warn, 'expected a WARNING message to the peer').to.exist;
		const decoded = decodeErrorMessage(warn.payload);
		expect(decoded.channelId.equals(channelId)).to.equal(true);
		expect(decoded.data.toString('ascii')).to.match(/taproot/i);

		// No shutdown echo, no state transition, no remote script adopted
		expect(
			actions.some(
				(a) =>
					a.type === ChannelActionType.SEND_MESSAGE &&
					(a as { messageType: MessageType }).messageType ===
						MessageType.SHUTDOWN
			)
		).to.equal(false);
		expect(acceptor.getState()).to.equal(stateBefore);
		expect(acceptor.getFullState().remoteShutdownScript).to.not.exist;
	});

	it('non-taproot channels are unaffected by the guard', function () {
		const opener = new Channel(
			createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 500_000n,
				pushMsat: 0n,
				localConfig: { ...DEFAULT_CHANNEL_CONFIG },
				localBasepoints: makeBasepoints(makeSeed(4)),
				localPerCommitmentSeed: makeSeed(104)
			})
		);
		opener.initiateOpen();
		// Wrong state for shutdown, but the error must be the state error,
		// not the taproot guard.
		const actions = opener.initiateShutdown(P2WPKH_SCRIPT);
		const err = actions.find((a) => a.type === ChannelActionType.ERROR) as {
			message: string;
		};
		expect(err).to.exist;
		expect(err.message).to.not.match(/taproot/i);
	});
});
