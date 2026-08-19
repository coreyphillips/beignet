/**
 * Issue #393: the rest of the v1 handshake refuses without telling the peer.
 *
 * `ChannelActionType.ERROR` is never put on the wire. `ChannelManager`'s
 * dispatch turns it into a local event and a temp-channel drop, so a refusal
 * built out of one deletes our half of the negotiation while the peer stays
 * parked on a message it will never get an answer to. PR #392 fixed
 * `handleOpenChannel`; this covers the three handlers it left behind.
 *
 * Two dispositions are asserted here, and the SECOND is the one worth having
 * tests for, because it is what a later "unify these guards" change would
 * break:
 *  - every refusal of a LIVE handshake message is wire-visible, scoped to an id
 *    the peer cannot steer, with the wire action ahead of the local ERROR;
 *  - the state guards and the id-mismatch guards stay deliberately local. They
 *    fire on a duplicated or misrouted message for a negotiation that is still
 *    alive under that id, so answering would cancel something healthy.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { Channel } from '../../src/lightning/channel/channel';
import {
	createOpenerState,
	createAcceptorState
} from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { MessageType } from '../../src/lightning/message/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';
import { isTaprootChannel } from '../../src/lightning/channel/types';
import {
	decodeOpenChannelMessage,
	decodeAcceptChannelMessage,
	IAcceptChannelMessage
} from '../../src/lightning/message/channel-open';
import {
	IFundingCreatedMessage,
	IFundingSignedMessage
} from '../../src/lightning/message/channel-funding';
import { expectWireRefusal, wireRefusalOf } from './helpers/open-refusal';
import { seedKey, signerFromSeed } from './helpers/real-signing';

function realBasepoints(seed: Buffer): IChannelBasepoints {
	return {
		fundingPubkey: getPublicKey(seedKey(seed, 0)),
		revocationBasepoint: getPublicKey(seedKey(seed, 1)),
		paymentBasepoint: getPublicKey(seedKey(seed, 2)),
		delayedPaymentBasepoint: getPublicKey(seedKey(seed, 3)),
		htlcBasepoint: getPublicKey(seedKey(seed, 4)),
		firstPerCommitmentPoint: getPublicKey(seedKey(seed, 5))
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

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function errorOf(actions: any[]): string | null {
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const e = actions.find((a: any) => a.type === ChannelActionType.ERROR);
	return e ? e.message : null;
}

interface IPair {
	opener: Channel;
	acceptor: Channel;
	accept: IAcceptChannelMessage;
}

/**
 * A real opener and acceptor driven to accept_channel, with real signers.
 *
 * `preferTaproot` drives initiateOpen's own taproot branch rather than patching
 * channelType afterwards, so the nonce state both sides hold is the one a real
 * negotiation produces. Patching it after a non-taproot handshake left
 * localNonce/remoteNonce unset and let the nonce arms pass for the wrong
 * reason.
 */
function pair(preferTaproot = false): IPair {
	const openerSeed = crypto.randomBytes(32);
	const acceptorSeed = crypto.randomBytes(32);
	const openerState = createOpenerState({
		temporaryChannelId: crypto.randomBytes(32),
		fundingSatoshis: 1_000_000n,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: realBasepoints(openerSeed),
		localPerCommitmentSeed: crypto.randomBytes(32)
	});
	const opener = new Channel(openerState);
	opener.setSigner(signerFromSeed(openerSeed));
	const openMsg = decodeOpenChannelMessage(
		findSend(
			opener.initiateOpen(undefined, false, preferTaproot),
			MessageType.OPEN_CHANNEL
		)!
	);

	const acceptor = new Channel(
		createAcceptorState({
			temporaryChannelId: openMsg.temporaryChannelId,
			fundingSatoshis: openMsg.fundingSatoshis,
			pushMsat: openMsg.pushMsat,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: realBasepoints(acceptorSeed),
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
		})
	);
	acceptor.setSigner(signerFromSeed(acceptorSeed));
	const acceptActions = acceptor.handleOpenChannel(openMsg);
	const accept = decodeAcceptChannelMessage(
		findSend(acceptActions, MessageType.ACCEPT_CHANNEL)!
	);
	return { opener, acceptor, accept };
}

function fundingCreated(p: IPair): IFundingCreatedMessage {
	return {
		temporaryChannelId: p.acceptor.getTemporaryChannelId(),
		fundingTxid: crypto.randomBytes(32),
		fundingOutputIndex: 0,
		signature: crypto.randomBytes(64)
	};
}

/** Drive the opener to SENT_FUNDING_CREATED so funding_signed is in scope. */
function driveToFundingCreated(p: IPair): { fundingTxid: Buffer } {
	p.opener.handleAcceptChannel(p.accept);
	const fundingTxid = crypto.randomBytes(32);
	p.opener.createFundingCreated(
		fundingTxid,
		0,
		crypto.randomBytes(64),
		undefined
	);
	expect(p.opener.getState()).to.equal(ChannelState.SENT_FUNDING_CREATED);
	return { fundingTxid };
}

function fundingSigned(p: IPair): IFundingSignedMessage {
	return {
		channelId: p.opener.getChannelId()!,
		signature: crypto.randomBytes(64)
	};
}

/**
 * A zero_conf opener, for the minimum_depth arm. Applied to the OPENER only and
 * after the acceptor has answered, because an acceptor refuses an untrusted
 * zero_conf open outright and never produces the accept_channel this needs.
 */
function zeroConfType(): Buffer {
	const f = FeatureFlags.empty();
	f.setCompulsory(Feature.STATIC_REMOTE_KEY);
	f.setCompulsory(Feature.ZERO_CONF);
	return f.toBuffer();
}

describe('The v1 handshake refuses ON THE WIRE (issue 393)', function () {
	describe('handleAcceptChannel (opener side)', function () {
		it('an accept_channel our own open_channel does not license', function () {
			const p = pair();
			const actions = p.opener.handleAcceptChannel({
				...p.accept,
				// Below the 546-sat floor validateAcceptChannelParams enforces.
				dustLimitSatoshis: 1n
			});
			expectWireRefusal(
				actions,
				p.opener.getTemporaryChannelId(),
				/Invalid accept_channel/
			);
		});

		it('a zero_conf accept_channel with a non-zero minimum_depth', function () {
			const p = pair();
			p.opener.getFullState().channelType = zeroConfType();
			const actions = p.opener.handleAcceptChannel({
				...p.accept,
				channelType: zeroConfType(),
				minimumDepth: 3
			});
			expectWireRefusal(
				actions,
				p.opener.getTemporaryChannelId(),
				/minimum_depth 0/
			);
		});

		it('an accept_channel naming a different channel type', function () {
			const p = pair();
			const actions = p.opener.handleAcceptChannel({
				...p.accept,
				channelType: Buffer.from([0x00, 0x01])
			});
			expectWireRefusal(
				actions,
				p.opener.getTemporaryChannelId(),
				/Channel type mismatch/
			);
		});

		it('an accept_channel that omits the type our open_channel set', function () {
			const p = pair();
			const actions = p.opener.handleAcceptChannel({
				...p.accept,
				channelType: undefined
			});
			expectWireRefusal(
				actions,
				p.opener.getTemporaryChannelId(),
				/omitted channel_type/
			);
		});

		it('a taproot accept_channel without a usable next_local_nonce', function () {
			const p = pair(true);
			// A real taproot negotiation: both sides carry live nonce state, so the
			// arm under test is the one a stripped next_local_nonce actually reaches.
			expect(isTaprootChannel(p.accept.channelType!)).to.equal(true);
			expect(p.accept.nextLocalNonce).to.have.length(66);
			expect(p.opener.getFullState().localNonce, 'opener nonce').to.not.equal(
				undefined
			);
			const actions = p.opener.handleAcceptChannel({
				...p.accept,
				nextLocalNonce: undefined
			});
			expectWireRefusal(
				actions,
				p.opener.getTemporaryChannelId(),
				/next_local_nonce/
			);
			expect(
				p.opener.getFullState().remoteNonce,
				'a refused nonce is never adopted'
			).to.equal(undefined);
		});

		it('but a replayed accept_channel for a LIVE open stays local', function () {
			const p = pair();
			expect(p.opener.handleAcceptChannel(p.accept)).to.have.length(0);
			// The opener has advanced and is still keyed by this temporary id, so a
			// wire error would cancel an open the acceptor believes is healthy.
			const replayed = p.opener.handleAcceptChannel(p.accept);
			expect(errorOf(replayed)).to.match(/Unexpected accept_channel/);
			expect(wireRefusalOf(replayed), 'nothing on the wire').to.equal(null);
		});

		it('and an id we do not own is never answered under', function () {
			const p = pair();
			const actions = p.opener.handleAcceptChannel({
				...p.accept,
				temporaryChannelId: crypto.randomBytes(32)
			});
			expect(errorOf(actions)).to.match(/temporary_channel_id mismatch/);
			expect(wireRefusalOf(actions), 'nothing on the wire').to.equal(null);
		});

		it('and the reserved all-zero id is refused silently', function () {
			const p = pair();
			p.opener.getFullState().temporaryChannelId = Buffer.alloc(32);
			const actions = p.opener.handleAcceptChannel({
				...p.accept,
				temporaryChannelId: Buffer.alloc(32),
				dustLimitSatoshis: 1n
			});
			// BOLT 1 reserves it for "all channels with this peer": answering would
			// widen a single refusal into failing every channel we have.
			expect(errorOf(actions)).to.match(/Invalid accept_channel/);
			expect(wireRefusalOf(actions), 'never connection-wide').to.equal(null);
		});
	});

	describe('handleFundingCreated (acceptor side)', function () {
		it('a funding_created whose signature does not verify', function () {
			const p = pair();
			const actions = p.acceptor.handleFundingCreated(
				fundingCreated(p),
				crypto.randomBytes(64),
				undefined
			);
			expectWireRefusal(
				actions,
				p.acceptor.getTemporaryChannelId(),
				/Invalid commitment signature in funding_created/
			);
		});

		it('and our OWN missing signer is told to the opener anyway', function () {
			const p = pair();
			// Blame does not change the opener's problem: it is holding a built,
			// signed, unbroadcast funding transaction either way.
			p.acceptor.setSigner(undefined as never);
			const actions = p.acceptor.handleFundingCreated(
				fundingCreated(p),
				crypto.randomBytes(64),
				undefined
			);
			expectWireRefusal(
				actions,
				p.acceptor.getTemporaryChannelId(),
				/no signer or remote basepoints/
			);
		});

		it('but a funding_created for a LIVE negotiation stays local', function () {
			const p = pair();
			p.acceptor.getFullState().state = ChannelState.NORMAL;
			const actions = p.acceptor.handleFundingCreated(
				fundingCreated(p),
				crypto.randomBytes(64),
				undefined
			);
			expect(errorOf(actions)).to.match(/Unexpected funding_created/);
			expect(wireRefusalOf(actions), 'nothing on the wire').to.equal(null);
		});

		it('and an id we do not own is never answered under', function () {
			const p = pair();
			const actions = p.acceptor.handleFundingCreated(
				{ ...fundingCreated(p), temporaryChannelId: crypto.randomBytes(32) },
				crypto.randomBytes(64),
				undefined
			);
			expect(errorOf(actions)).to.match(/temporary_channel_id mismatch/);
			expect(wireRefusalOf(actions), 'nothing on the wire').to.equal(null);
		});

		it('and a peer-supplied all-zero id is refused silently', function () {
			const p = pair();
			p.acceptor.getFullState().temporaryChannelId = Buffer.alloc(32);
			const actions = p.acceptor.handleFundingCreated(
				{ ...fundingCreated(p), temporaryChannelId: Buffer.alloc(32) },
				crypto.randomBytes(64),
				undefined
			);
			expect(errorOf(actions)).to.match(/Invalid commitment signature/);
			expect(wireRefusalOf(actions), 'never connection-wide').to.equal(null);
		});

		it('scopes to the temporary id, never the peer-derived permanent one', function () {
			// The permanent id is deriveChannelId(PEER-SUPPLIED txid, output index),
			// so an opener quoting an all-zero txid at output 0 could otherwise steer
			// our refusal into a connection-wide error.
			const p = pair();
			const actions = p.acceptor.handleFundingCreated(
				{
					...fundingCreated(p),
					fundingTxid: Buffer.alloc(32),
					fundingOutputIndex: 0
				},
				crypto.randomBytes(64),
				undefined
			);
			expectWireRefusal(
				actions,
				p.acceptor.getTemporaryChannelId(),
				/Invalid commitment signature in funding_created/
			);
		});
	});

	describe('handleFundingSigned (opener side)', function () {
		it('a funding_signed whose signature does not verify', function () {
			const p = pair();
			driveToFundingCreated(p);
			const actions = p.opener.handleFundingSigned(fundingSigned(p));
			expectWireRefusal(
				actions,
				p.opener.getChannelId()!,
				/Invalid commitment signature in funding_signed/
			);
		});

		it('and the refusal does NOT fail the channel: nothing is on chain', function () {
			const p = pair();
			driveToFundingCreated(p);
			const actions = p.opener.handleFundingSigned(fundingSigned(p));
			// AUTHORIZE_FUNDING_BROADCAST is the only signal that permits the
			// broadcast and no refusal arm reaches it, so a force close would be a
			// fiction and a persisted ERRORED row would never be reaped.
			expect(p.opener.getState()).to.not.equal(ChannelState.ERRORED);
			expect(
				actions.some((a) => a.type === ChannelActionType.PERSIST_STATE),
				'no persist'
			).to.equal(false);
			expect(
				actions.some(
					(a) => a.type === ChannelActionType.AUTHORIZE_FUNDING_BROADCAST
				),
				'no broadcast authorization'
			).to.equal(false);
		});

		it('and our OWN missing signer is told to the acceptor anyway', function () {
			const p = pair();
			driveToFundingCreated(p);
			p.opener.setSigner(undefined as never);
			const actions = p.opener.handleFundingSigned(fundingSigned(p));
			expectWireRefusal(
				actions,
				p.opener.getChannelId()!,
				/no signer or remote basepoints/
			);
		});

		it('but a replayed funding_signed for a LIVE channel stays local', function () {
			const p = pair();
			driveToFundingCreated(p);
			p.opener.getFullState().state = ChannelState.AWAITING_FUNDING_CONFIRMED;
			const actions = p.opener.handleFundingSigned(fundingSigned(p));
			expect(errorOf(actions)).to.match(/Unexpected funding_signed/);
			expect(wireRefusalOf(actions), 'nothing on the wire').to.equal(null);
		});

		it('and an id we do not own is never answered under', function () {
			const p = pair();
			driveToFundingCreated(p);
			const actions = p.opener.handleFundingSigned({
				...fundingSigned(p),
				channelId: crypto.randomBytes(32)
			});
			expect(errorOf(actions)).to.match(/channel_id mismatch/);
			expect(wireRefusalOf(actions), 'nothing on the wire').to.equal(null);
		});

		it('and an all-zero derived id is refused silently', function () {
			const p = pair();
			driveToFundingCreated(p);
			const zeroed = Buffer.alloc(32);
			p.opener.getFullState().channelId = zeroed;
			const actions = p.opener.handleFundingSigned({
				channelId: zeroed,
				signature: crypto.randomBytes(64)
			});
			expect(errorOf(actions)).to.match(/Invalid commitment signature/);
			expect(wireRefusalOf(actions), 'never connection-wide').to.equal(null);
		});
	});

	describe('taproot arms, on a REAL taproot negotiation', function () {
		it('a funding_created whose MuSig2 partial we cannot accept', function () {
			const p = pair(true);
			// Both sides hold live nonce state, so _acceptFundingPartial is reached
			// with everything it needs and fails on the partial itself.
			expect(p.acceptor.getFullState().remoteNonce).to.have.length(66);
			expect(
				p.acceptor.getFullState().localNonce,
				'acceptor nonce'
			).to.not.equal(undefined);
			const actions = p.acceptor.handleFundingCreated(
				{ ...fundingCreated(p), partialSignatureWithNonce: Buffer.alloc(10) },
				crypto.randomBytes(64),
				Buffer.alloc(98)
			);
			expectWireRefusal(
				actions,
				p.acceptor.getTemporaryChannelId(),
				/partial|nonce|signature/i
			);
		});

		it('a funding_created partial of the RIGHT length but garbage content (issue 415)', function () {
			// A 98-byte partial whose nonce halves are not curve points made the
			// musig library THROW instead of return false, and the throw escaped
			// the refusal arms entirely. The tighter regex pins the verify path:
			// the missing-nonce arm's reason would not match it.
			const p = pair(true);
			expect(p.acceptor.getFullState().remoteNonce).to.have.length(66);
			const actions = p.acceptor.handleFundingCreated(
				{
					...fundingCreated(p),
					partialSignatureWithNonce: Buffer.alloc(98, 1)
				},
				crypto.randomBytes(64),
				Buffer.alloc(98)
			);
			expectWireRefusal(
				actions,
				p.acceptor.getTemporaryChannelId(),
				/Invalid taproot partial signature/
			);
		});

		it('a funding_signed partial of the RIGHT length but garbage content (issue 415)', function () {
			const p = pair(true);
			// driveToFundingCreated passes no partial, which a taproot opener
			// refuses; drive the same path with a length-valid one.
			p.opener.handleAcceptChannel(p.accept);
			p.opener.createFundingCreated(
				crypto.randomBytes(32),
				0,
				crypto.randomBytes(64),
				Buffer.alloc(98)
			);
			expect(p.opener.getState()).to.equal(ChannelState.SENT_FUNDING_CREATED);
			const actions = p.opener.handleFundingSigned({
				...fundingSigned(p),
				partialSignatureWithNonce: Buffer.alloc(98, 1)
			});
			expectWireRefusal(
				actions,
				p.opener.getChannelId()!,
				/Invalid taproot partial signature/
			);
			// The lifecycle unwind must survive: createFunding promoted the opener
			// to its permanent id, so only cleanup 'lifecycle' reaps it.
			const local = actions.find((a) => a.type === ChannelActionType.ERROR) as {
				type: ChannelActionType;
				cleanup?: string;
			};
			expect(local.cleanup).to.equal('lifecycle');
		});
	});
});
