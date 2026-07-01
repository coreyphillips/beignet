/**
 * option_taproot: open_channel / accept_channel MuSig2 nonce exchange (M4.3).
 *
 * Verifies that negotiating a taproot channel (preferTaproot) sets the
 * option_taproot channel type, that each side attaches its 66-byte MuSig2 public
 * nonce, and that both sides store the peer's nonce — the prerequisite for
 * co-signing the first commitment.
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
	isTaprootChannel,
	isAnchorChannel
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	decodeOpenChannelMessage,
	decodeAcceptChannelMessage,
	encodeOpenChannelMessage,
	IOpenChannelMessage
} from '../../src/lightning/message/channel-open';

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`taproot-seed-${id}`))
		.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		keys.push(
			crypto.createHash('sha256').update(seed).update(Buffer.from([i])).digest()
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

function makeOpener(): Channel {
	return new Channel(
		createOpenerState({
			temporaryChannelId: crypto.randomBytes(32),
			fundingSatoshis: 500_000n,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: makeBasepoints(makeSeed(1)),
			localPerCommitmentSeed: makeSeed(101)
		})
	);
}

function makeAcceptor(temporaryChannelId: Buffer): Channel {
	// The acceptor adopts the opener's temporary_channel_id (as ChannelManager
	// does when it constructs the acceptor channel from the open_channel message).
	return new Channel(
		createAcceptorState({
			temporaryChannelId,
			fundingSatoshis: 500_000n,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: makeBasepoints(makeSeed(2)),
			localPerCommitmentSeed: makeSeed(102),
			// Overwritten by handleOpenChannel; placeholders for state creation.
			remoteBasepoints: makeBasepoints(makeSeed(1)),
			remoteConfig: { ...DEFAULT_CHANNEL_CONFIG }
		})
	);
}

function payloadOf(actions: ReturnType<Channel['initiateOpen']>): Buffer {
	const send = actions.find((a) => 'payload' in a) as { payload: Buffer };
	expect(send, 'expected a send-message action').to.exist;
	return send.payload;
}

describe('option_taproot open/accept nonce exchange', function () {
	it('open_channel with preferTaproot sets the taproot type + a 66-byte nonce', function () {
		const opener = makeOpener();
		const open = decodeOpenChannelMessage(
			payloadOf(opener.initiateOpen(undefined, false, true))
		);
		expect(isTaprootChannel(open.channelType!)).to.be.true;
		// Taproot implies anchor-style commitments.
		expect(isAnchorChannel(open.channelType!)).to.be.true;
		expect(open.nextLocalNonce).to.have.length(66);
		// Stored in-memory as the secret-nonce handle, not serialized.
		expect(opener.getFullState().localNonce).to.exist;
	});

	it('completes a full taproot handshake with both sides storing the peer nonce', function () {
		const opener = makeOpener();
		const open = decodeOpenChannelMessage(
			payloadOf(opener.initiateOpen(undefined, false, true))
		);
		const acceptor = makeAcceptor(open.temporaryChannelId);
		const accept = decodeAcceptChannelMessage(
			payloadOf(acceptor.handleOpenChannel(open))
		);
		opener.handleAcceptChannel(accept);

		expect(isTaprootChannel(accept.channelType!)).to.be.true;
		expect(accept.nextLocalNonce).to.have.length(66);

		const o = opener.getFullState();
		const a = acceptor.getFullState();

		// Each side holds its own single-use secret-nonce handle.
		expect(o.localNonce).to.exist;
		expect(a.localNonce).to.exist;
		expect(Buffer.from(o.localNonce!).equals(Buffer.from(a.localNonce!))).to.be
			.false;

		// Each side stored the PEER's public nonce (wire bytes).
		expect(o.remoteNonce!.equals(Buffer.from(a.localNonce!))).to.be.true;
		expect(a.remoteNonce!.equals(Buffer.from(o.localNonce!))).to.be.true;
	});

	it('rejects a taproot open_channel missing the nonce', function () {
		const opener = makeOpener();
		const open = decodeOpenChannelMessage(
			payloadOf(opener.initiateOpen(undefined, false, true))
		);
		delete (open as IOpenChannelMessage).nextLocalNonce;
		const actions = makeAcceptor(open.temporaryChannelId).handleOpenChannel(open);
		expect(actions[0].type).to.equal('ERROR');
	});

	it('round-trips the nonce TLV through encode/decode', function () {
		const opener = makeOpener();
		const open = decodeOpenChannelMessage(
			payloadOf(opener.initiateOpen(undefined, false, true))
		);
		const reDecoded = decodeOpenChannelMessage(encodeOpenChannelMessage(open));
		expect(reDecoded.nextLocalNonce!.equals(open.nextLocalNonce!)).to.be.true;
	});

	it('non-taproot open_channel carries no nonce', function () {
		const opener = makeOpener();
		const open = decodeOpenChannelMessage(
			payloadOf(opener.initiateOpen(undefined, true, false))
		);
		expect(isTaprootChannel(open.channelType!)).to.be.false;
		expect(open.nextLocalNonce).to.be.undefined;
	});
});
