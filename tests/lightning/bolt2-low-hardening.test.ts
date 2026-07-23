/**
 * BOLT 2 LOW-severity hardening batch (2026-07-15 review):
 *  - funding cap is 2^24 - 1 (funding_satoshis MUST be < 2^24);
 *  - off-curve basepoints rejected on open_channel / accept_channel;
 *  - accept_channel omitting channel_type after open_channel set it fails;
 *  - accept_channel WE build couples reserve/dust to the opener's values;
 *  - cltv_expiry >= 500000000 rejected on send and receive;
 *  - channel_reestablish next_commitment_number == 0 fails the channel;
 *  - channel_ready retransmitted when peer's next_commitment_number == 1;
 *  - tx_abort echoed from active dual-funding/splice sessions;
 *  - RBF feerate floor is 25/24 of the previous feerate;
 *  - splice-out destination script must be a standard output form.
 * (Splice tx_init_rbf tx_abort reply is covered in splice.test.ts context;
 * per-output penalty splitting near expiry is tracked as its own follow-up.)
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
	DEFAULT_CHANNEL_CONFIG,
	MAX_FUNDING_SATOSHIS
} from '../../src/lightning/channel/types';
import {
	validateOpenChannelParams,
	validateAcceptChannelParams
} from '../../src/lightning/channel/validation';
import { rbfFeerateFloor } from '../../src/lightning/channel/dual-funding';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { MessageType } from '../../src/lightning/message/types';
import {
	decodeOpenChannelMessage,
	decodeAcceptChannelMessage,
	IOpenChannelMessage,
	IAcceptChannelMessage
} from '../../src/lightning/message/channel-open';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { BITCOIN_CHAIN_HASH } from '../../src/lightning/channel/types';

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

/** A 33-byte buffer that is definitely NOT a secp256k1 point (bad prefix). */
function offCurvePoint(): Buffer {
	return Buffer.alloc(33, 0xff);
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

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function errorOf(actions: any[]): string | null {
	const e = actions.find(
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(a: any) => a.type === ChannelActionType.ERROR
	);
	return e ? e.message : null;
}

function makeValidOpenMsg(): IOpenChannelMessage {
	const bp = realBasepoints();
	return {
		chainHash: BITCOIN_CHAIN_HASH,
		temporaryChannelId: crypto.randomBytes(32),
		fundingSatoshis: 1_000_000n,
		pushMsat: 0n,
		dustLimitSatoshis: 546n,
		maxHtlcValueInFlightMsat: 500_000_000n,
		channelReserveSatoshis: 10_000n,
		htlcMinimumMsat: 1_000n,
		feeratePerKw: 253,
		toSelfDelay: 144,
		maxAcceptedHtlcs: 483,
		fundingPubkey: bp.fundingPubkey,
		revocationBasepoint: bp.revocationBasepoint,
		paymentBasepoint: bp.paymentBasepoint,
		delayedPaymentBasepoint: bp.delayedPaymentBasepoint,
		htlcBasepoint: bp.htlcBasepoint,
		firstPerCommitmentPoint: bp.firstPerCommitmentPoint,
		channelFlags: 0x01
	};
}

/** Drive a real opener + acceptor to the accept_channel message. */
function openerAndAccept(
	mutateOpen?: (msg: IOpenChannelMessage) => void,
	acceptorDustLimit?: bigint
): {
	opener: Channel;
	acceptor: Channel;
	openMsg: IOpenChannelMessage;
	acceptActions: ReturnType<Channel['handleOpenChannel']>;
	accept: IAcceptChannelMessage | null;
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
	if (mutateOpen) mutateOpen(openMsg);

	const acceptorState = createAcceptorState({
		temporaryChannelId: openMsg.temporaryChannelId,
		fundingSatoshis: openMsg.fundingSatoshis,
		pushMsat: openMsg.pushMsat,
		localConfig: {
			...DEFAULT_CHANNEL_CONFIG,
			...(acceptorDustLimit !== undefined
				? { dustLimitSatoshis: acceptorDustLimit }
				: {})
		},
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
	const payload = findSend(acceptActions, MessageType.ACCEPT_CHANNEL);
	const accept = payload ? decodeAcceptChannelMessage(payload) : null;
	return { opener, acceptor, openMsg, acceptActions, accept };
}

/** Drive a pair all the way to NORMAL (random sigs; no commitment exchange). */
function normalPair(): { opener: Channel; acceptor: Channel } {
	const { opener, acceptor, accept } = openerAndAccept();
	opener.handleAcceptChannel(accept!);
	const fundingTxid = crypto.randomBytes(32);
	const sig = crypto.randomBytes(64);
	opener.createFundingCreated(fundingTxid, 0, sig);
	const channelId = opener.getChannelId()!;
	acceptor.handleFundingCreated(
		{
			temporaryChannelId: opener.getTemporaryChannelId(),
			fundingTxid,
			fundingOutputIndex: 0,
			signature: sig
		},
		crypto.randomBytes(64)
	);
	opener.handleFundingSigned({ channelId, signature: crypto.randomBytes(64) });
	opener.fundingConfirmed();
	acceptor.fundingConfirmed();
	opener.handleChannelReady({
		channelId,
		secondPerCommitmentPoint: getPublicKey(crypto.randomBytes(32))
	});
	acceptor.handleChannelReady({
		channelId: acceptor.getChannelId()!,
		secondPerCommitmentPoint: getPublicKey(crypto.randomBytes(32))
	});
	return { opener, acceptor };
}

describe('BOLT 2 LOW hardening batch', function () {
	describe('funding cap (funding_satoshis < 2^24)', function () {
		it('the cap constant is 2^24 - 1', function () {
			expect(MAX_FUNDING_SATOSHIS).to.equal(16_777_215n);
		});

		it('rejects funding of exactly 2^24 and accepts 2^24 - 1', function () {
			const at = makeValidOpenMsg();
			at.fundingSatoshis = 16_777_216n;
			expect(validateOpenChannelParams(at)).to.match(/exceeds maximum/);

			const under = makeValidOpenMsg();
			under.fundingSatoshis = 16_777_215n;
			expect(validateOpenChannelParams(under)).to.equal(null);
		});
	});

	describe('secp256k1 point validation on open/accept', function () {
		it('rejects an open_channel with an off-curve basepoint', function () {
			const msg = makeValidOpenMsg();
			msg.htlcBasepoint = offCurvePoint();
			expect(validateOpenChannelParams(msg)).to.match(
				/htlc_basepoint.*not a valid/
			);
		});

		it('rejects an off-curve first_per_commitment_point', function () {
			const msg = makeValidOpenMsg();
			msg.firstPerCommitmentPoint = offCurvePoint();
			expect(validateOpenChannelParams(msg)).to.match(
				/first_per_commitment_point.*not a valid/
			);
		});

		it('rejects an accept_channel with an off-curve basepoint', function () {
			const { openMsg, accept } = openerAndAccept();
			accept!.revocationBasepoint = offCurvePoint();
			expect(validateAcceptChannelParams(openMsg, accept!)).to.match(
				/revocation_basepoint.*not a valid/
			);
		});

		it('accepts real points end-to-end', function () {
			const { openMsg, accept } = openerAndAccept();
			expect(validateAcceptChannelParams(openMsg, accept!)).to.equal(null);
		});
	});

	describe('channel_type mirroring in accept_channel', function () {
		it('fails when accept_channel omits the channel_type open_channel set', function () {
			const { opener, accept } = openerAndAccept();
			expect(accept!.channelType, 'harness sanity: opener set a type').to.not.be
				.undefined;
			delete accept!.channelType;
			const actions = opener.handleAcceptChannel(accept!);
			expect(errorOf(actions)).to.match(/omitted channel_type/);
			expect(opener.getState()).to.equal(ChannelState.SENT_OPEN);
		});
	});

	describe('accept_channel build-side reserve/dust coupling', function () {
		it('raises our channel_reserve to at least the opener dust_limit', function () {
			const { accept, acceptActions } = openerAndAccept((open) => {
				open.dustLimitSatoshis = 20_000n;
				open.channelReserveSatoshis = 25_000n;
			});
			expect(errorOf(acceptActions)).to.equal(null);
			// Our 1% formula would give 10,000; the opener's dust forces >= 20,000.
			expect(accept!.channelReserveSatoshis >= 20_000n).to.equal(true);
		});

		it('rejects an open whose channel_reserve is below our dust_limit', function () {
			// Acceptor configured with a 600-sat dust floor; the opener's reserve
			// (400) cannot cover it, so emitting accept_channel would violate
			// BOLT 2 — reject the open instead.
			const { acceptActions, accept } = openerAndAccept((open) => {
				open.dustLimitSatoshis = 354n;
				open.channelReserveSatoshis = 400n;
			}, 600n);
			expect(accept).to.equal(null);
			expect(errorOf(acceptActions)).to.match(/dust_limit.*channel_reserve/);
		});
	});

	describe('cltv_expiry >= 500000000', function () {
		it('send side: addHtlc refuses a timestamp-range cltv_expiry', function () {
			const { opener } = normalPair();
			const actions = opener.addHtlc(
				10_000n,
				crypto.randomBytes(32),
				500_000_000,
				Buffer.alloc(1366)
			);
			expect(errorOf(actions)).to.match(/not a block height/);
		});

		it('receive side: update_add_htlc with a timestamp-range cltv_expiry is rejected even with no block height', function () {
			const { acceptor } = normalPair();
			const actions = acceptor.handleUpdateAddHtlc({
				channelId: acceptor.getChannelId()!,
				id: 0n,
				amountMsat: 10_000n,
				paymentHash: crypto.randomBytes(32),
				cltvExpiry: 500_000_000,
				onionRoutingPacket: Buffer.alloc(1366)
			});
			expect(errorOf(actions)).to.match(/not a block height/);
		});
	});

	describe('channel_reestablish next_commitment_number == 0', function () {
		it('fails the channel with a wire error', function () {
			const { opener } = normalPair();
			const actions = opener.handleReestablish({
				channelId: opener.getChannelId()!,
				nextCommitmentNumber: 0n,
				nextRevocationNumber: 0n,
				yourLastPerCommitmentSecret: Buffer.alloc(32),
				myCurrentPerCommitmentPoint: getPublicKey(crypto.randomBytes(32))
			});
			expect(errorOf(actions)).to.match(/next_commitment_number is 0/);
			const wireError = findSend(actions, MessageType.ERROR);
			expect(wireError, 'wire error sent').to.not.equal(null);
		});
	});

	describe('channel_ready retransmission trigger', function () {
		it('retransmits channel_ready when the peer expects commitment 1, even from NORMAL', function () {
			const { opener } = normalPair();
			expect(opener.getState()).to.equal(ChannelState.NORMAL);
			const actions = opener.handleReestablish({
				channelId: opener.getChannelId()!,
				nextCommitmentNumber: 1n,
				nextRevocationNumber: 0n,
				yourLastPerCommitmentSecret: Buffer.alloc(32),
				myCurrentPerCommitmentPoint: getPublicKey(crypto.randomBytes(32))
			});
			const ready = findSend(actions, MessageType.CHANNEL_READY);
			expect(ready, 'channel_ready retransmitted').to.not.equal(null);
		});
	});

	describe('RBF feerate floor (25/24)', function () {
		it('computes the spec floor with a strict-increase backstop', function () {
			expect(rbfFeerateFloor(2400)).to.equal(2500);
			expect(rbfFeerateFloor(253)).to.equal(263);
			// Tiny rates round down to the previous value; the floor is then +1.
			expect(rbfFeerateFloor(10)).to.equal(11);
			expect(rbfFeerateFloor(0)).to.equal(1);
		});
	});

	describe('splice-out destination script validation', function () {
		it('rejects an OP_RETURN destination that would burn the funds', function () {
			const node = new LightningNode({
				nodePrivateKey: crypto.randomBytes(32),
				perCommitmentSeed: crypto.randomBytes(32),
				channelBasepoints: realBasepoints(),
				fundingPrivkey: crypto.randomBytes(32)
			});
			const opReturn = Buffer.concat([
				Buffer.from([0x6a, 0x20]),
				crypto.randomBytes(32)
			]);
			expect(() =>
				node.spliceOut(crypto.randomBytes(32), 10_000n, 253, opReturn)
			).to.throw(/not a standard output script/);
			node.destroy();
		});

		it('accepts a standard P2WPKH destination script', function () {
			const node = new LightningNode({
				nodePrivateKey: crypto.randomBytes(32),
				perCommitmentSeed: crypto.randomBytes(32),
				channelBasepoints: realBasepoints(),
				fundingPrivkey: crypto.randomBytes(32)
			});
			const p2wpkh = Buffer.concat([
				Buffer.from([0x00, 0x14]),
				crypto.randomBytes(20)
			]);
			// Passes the script gate; fails later only because the channel
			// does not exist (returned, not thrown).
			const res = node.spliceOut(crypto.randomBytes(32), 10_000n, 253, p2wpkh);
			expect(res.ok).to.equal(false);
			expect(res.error).to.match(/Channel not found/);
			node.destroy();
		});
	});
});
