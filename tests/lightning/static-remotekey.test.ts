/**
 * Phase 3: option_static_remotekey enforcement tests.
 *
 * Verifies:
 * - deriveCommitmentKeys returns raw paymentBasepoint for remotePaymentPubkey
 * - Channel type TLV included in open_channel
 * - Channel type echoed in accept_channel
 * - Channel type mismatch produces error
 * - Default features include static_remotekey
 * - Acceptor rejects channel without static_remotekey
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { deriveCommitmentKeys } from '../../src/lightning/channel/commitment-builder';
import {
	createOpenerChannel,
	createAcceptorChannel,
	Channel
} from '../../src/lightning/channel/channel';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { ChannelState } from '../../src/lightning/channel/types';
import {
	decodeOpenChannelMessage,
	decodeAcceptChannelMessage
} from '../../src/lightning/message/channel-open';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';
import { LightningNode } from '../../src/lightning/node/lightning-node';

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 6; i++) {
		const priv = crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([i]))
			.digest();
		keys.push(getPublicKey(priv));
	}
	return {
		fundingPubkey: keys[0],
		revocationBasepoint: keys[1],
		paymentBasepoint: keys[2],
		delayedPaymentBasepoint: keys[3],
		htlcBasepoint: keys[4],
		firstPerCommitmentPoint: keys[5]
	};
}

function makePerCommitmentPoint(): Buffer {
	return getPublicKey(crypto.randomBytes(32));
}

describe('Phase 3: option_static_remotekey', () => {
	const openerSeed = crypto.randomBytes(32);
	const acceptorSeed = crypto.randomBytes(32);
	const openerBasepoints = makeBasepoints(openerSeed);
	const acceptorBasepoints = makeBasepoints(acceptorSeed);

	describe('deriveCommitmentKeys — static remote key', () => {
		it('should use raw paymentBasepoint for remotePaymentPubkey (local commitment)', () => {
			const perCommitmentPoint = makePerCommitmentPoint();
			const keys = deriveCommitmentKeys(
				openerBasepoints,
				acceptorBasepoints,
				perCommitmentPoint,
				true // isLocal
			);

			// remotePaymentPubkey should be the raw (untweaked) remote paymentBasepoint
			expect(
				keys.remotePaymentPubkey.equals(acceptorBasepoints.paymentBasepoint)
			).to.be.true;
		});

		it('should use raw paymentBasepoint for remotePaymentPubkey (remote commitment)', () => {
			const perCommitmentPoint = makePerCommitmentPoint();
			const keys = deriveCommitmentKeys(
				openerBasepoints,
				acceptorBasepoints,
				perCommitmentPoint,
				false // isRemote
			);

			// When building remote commitment, remotePaymentPubkey is our (local) payment basepoint
			expect(keys.remotePaymentPubkey.equals(openerBasepoints.paymentBasepoint))
				.to.be.true;
		});

		it('should still derive other keys using per-commitment point', () => {
			const perCommitmentPoint = makePerCommitmentPoint();
			const keys = deriveCommitmentKeys(
				openerBasepoints,
				acceptorBasepoints,
				perCommitmentPoint,
				true
			);

			// localDelayedPubkey should NOT be the raw basepoint (it's tweaked)
			expect(
				keys.localDelayedPubkey.equals(openerBasepoints.delayedPaymentBasepoint)
			).to.be.false;
			// localHtlcPubkey should NOT be the raw basepoint
			expect(keys.localHtlcPubkey.equals(openerBasepoints.htlcBasepoint)).to.be
				.false;
			// remoteHtlcPubkey should NOT be the raw basepoint
			expect(keys.remoteHtlcPubkey.equals(acceptorBasepoints.htlcBasepoint)).to
				.be.false;
		});
	});

	describe('Channel type TLV in open_channel', () => {
		it('should include channel type TLV with static_remotekey bit', () => {
			const opener = createOpenerChannel({
				fundingSatoshis: 1_000_000n,
				localBasepoints: openerBasepoints,
				localPerCommitmentSeed: crypto.randomBytes(32)
			});

			const actions = opener.initiateOpen();
			expect(actions).to.have.lengthOf(1);
			expect(actions[0].type).to.equal(ChannelActionType.SEND_MESSAGE);

			// Decode the open_channel message
			const payload = (
				actions[0] as { type: ChannelActionType.SEND_MESSAGE; payload: Buffer }
			).payload;
			const msg = decodeOpenChannelMessage(payload);

			// channelType should be present and contain static_remotekey
			expect(msg.channelType).to.not.be.undefined;
			const flags = FeatureFlags.fromBuffer(msg.channelType!);
			expect(flags.hasFeature(Feature.STATIC_REMOTE_KEY)).to.be.true;
		});

		it('should store channelType in channel state', () => {
			const opener = createOpenerChannel({
				fundingSatoshis: 1_000_000n,
				localBasepoints: openerBasepoints,
				localPerCommitmentSeed: crypto.randomBytes(32)
			});

			opener.initiateOpen();
			const state = opener.getFullState();
			expect(state.channelType).to.not.be.null;

			const flags = FeatureFlags.fromBuffer(state.channelType!);
			expect(flags.hasFeature(Feature.STATIC_REMOTE_KEY)).to.be.true;
		});
	});

	describe('Channel type TLV in accept_channel', () => {
		let opener: Channel;
		let acceptor: Channel;

		beforeEach(() => {
			opener = createOpenerChannel({
				fundingSatoshis: 1_000_000n,
				localBasepoints: openerBasepoints,
				localPerCommitmentSeed: crypto.randomBytes(32)
			});
		});

		it('should echo channel type in accept_channel', () => {
			const openActions = opener.initiateOpen();
			const openPayload = (
				openActions[0] as {
					type: ChannelActionType.SEND_MESSAGE;
					payload: Buffer;
				}
			).payload;
			const openMsg = decodeOpenChannelMessage(openPayload);

			acceptor = createAcceptorChannel({
				temporaryChannelId: openMsg.temporaryChannelId,
				localBasepoints: acceptorBasepoints,
				localPerCommitmentSeed: crypto.randomBytes(32)
			});

			const acceptActions = acceptor.handleOpenChannel(openMsg);
			expect(acceptActions).to.have.lengthOf(1);
			expect(acceptActions[0].type).to.equal(ChannelActionType.SEND_MESSAGE);

			const acceptPayload = (
				acceptActions[0] as {
					type: ChannelActionType.SEND_MESSAGE;
					payload: Buffer;
				}
			).payload;
			const acceptMsg = decodeAcceptChannelMessage(acceptPayload);

			// accept_channel should include the channel type
			expect(acceptMsg.channelType).to.not.be.undefined;
			const flags = FeatureFlags.fromBuffer(acceptMsg.channelType!);
			expect(flags.hasFeature(Feature.STATIC_REMOTE_KEY)).to.be.true;
		});

		it('should store channelType in acceptor state', () => {
			const openActions = opener.initiateOpen();
			const openPayload = (
				openActions[0] as {
					type: ChannelActionType.SEND_MESSAGE;
					payload: Buffer;
				}
			).payload;
			const openMsg = decodeOpenChannelMessage(openPayload);

			acceptor = createAcceptorChannel({
				temporaryChannelId: openMsg.temporaryChannelId,
				localBasepoints: acceptorBasepoints,
				localPerCommitmentSeed: crypto.randomBytes(32)
			});

			acceptor.handleOpenChannel(openMsg);
			const state = acceptor.getFullState();
			expect(state.channelType).to.not.be.null;

			const flags = FeatureFlags.fromBuffer(state.channelType!);
			expect(flags.hasFeature(Feature.STATIC_REMOTE_KEY)).to.be.true;
		});

		it('should default to static_remotekey when no channel type in open_channel', () => {
			const openActions = opener.initiateOpen();
			const openPayload = (
				openActions[0] as {
					type: ChannelActionType.SEND_MESSAGE;
					payload: Buffer;
				}
			).payload;
			const openMsg = decodeOpenChannelMessage(openPayload);

			// Remove channel type to simulate a peer that doesn't send it
			delete openMsg.channelType;

			acceptor = createAcceptorChannel({
				temporaryChannelId: openMsg.temporaryChannelId,
				localBasepoints: acceptorBasepoints,
				localPerCommitmentSeed: crypto.randomBytes(32)
			});

			const acceptActions = acceptor.handleOpenChannel(openMsg);
			expect(acceptActions).to.have.lengthOf(1);

			// Acceptor should still have static_remotekey as default
			const state = acceptor.getFullState();
			expect(state.channelType).to.not.be.null;
			const flags = FeatureFlags.fromBuffer(state.channelType!);
			expect(flags.hasFeature(Feature.STATIC_REMOTE_KEY)).to.be.true;
		});
	});

	describe('Channel type validation', () => {
		it('should reject accept_channel with mismatched channel type', () => {
			const opener = createOpenerChannel({
				fundingSatoshis: 1_000_000n,
				localBasepoints: openerBasepoints,
				localPerCommitmentSeed: crypto.randomBytes(32)
			});

			opener.initiateOpen();

			// Create a fake accept_channel with wrong channel type
			const fakeAcceptMsg = {
				temporaryChannelId: opener.getTemporaryChannelId(),
				dustLimitSatoshis: 546n,
				maxHtlcValueInFlightMsat: 1_000_000_000n,
				channelReserveSatoshis: 10_000n,
				htlcMinimumMsat: 1n,
				minimumDepth: 3,
				toSelfDelay: 144,
				maxAcceptedHtlcs: 483,
				fundingPubkey: acceptorBasepoints.fundingPubkey,
				revocationBasepoint: acceptorBasepoints.revocationBasepoint,
				paymentBasepoint: acceptorBasepoints.paymentBasepoint,
				delayedPaymentBasepoint: acceptorBasepoints.delayedPaymentBasepoint,
				htlcBasepoint: acceptorBasepoints.htlcBasepoint,
				firstPerCommitmentPoint: acceptorBasepoints.firstPerCommitmentPoint,
				// Wrong channel type — set a different feature
				channelType: Buffer.from([0x00, 0x01])
			};

			const actions = opener.handleAcceptChannel(fakeAcceptMsg);
			expect(actions).to.have.lengthOf(1);
			expect(actions[0].type).to.equal(ChannelActionType.ERROR);
			expect(
				(actions[0] as { type: ChannelActionType.ERROR; message: string })
					.message
			).to.include('Channel type mismatch');
		});

		it('should accept matching channel type in accept_channel', () => {
			const opener = createOpenerChannel({
				fundingSatoshis: 1_000_000n,
				localBasepoints: openerBasepoints,
				localPerCommitmentSeed: crypto.randomBytes(32)
			});

			opener.initiateOpen();

			// Build matching channel type
			const channelTypeFlags = FeatureFlags.empty();
			channelTypeFlags.setCompulsory(Feature.STATIC_REMOTE_KEY);
			const channelType = channelTypeFlags.toBuffer();

			const acceptMsg = {
				temporaryChannelId: opener.getTemporaryChannelId(),
				dustLimitSatoshis: 546n,
				maxHtlcValueInFlightMsat: 1_000_000_000n,
				channelReserveSatoshis: 10_000n,
				htlcMinimumMsat: 1n,
				minimumDepth: 3,
				toSelfDelay: 144,
				maxAcceptedHtlcs: 483,
				fundingPubkey: acceptorBasepoints.fundingPubkey,
				revocationBasepoint: acceptorBasepoints.revocationBasepoint,
				paymentBasepoint: acceptorBasepoints.paymentBasepoint,
				delayedPaymentBasepoint: acceptorBasepoints.delayedPaymentBasepoint,
				htlcBasepoint: acceptorBasepoints.htlcBasepoint,
				firstPerCommitmentPoint: acceptorBasepoints.firstPerCommitmentPoint,
				channelType
			};

			const actions = opener.handleAcceptChannel(acceptMsg);
			expect(actions).to.have.lengthOf(0);
			expect(opener.getState()).to.equal(ChannelState.SENT_ACCEPT);
		});

		it('should reject open_channel without static_remotekey in channel type', () => {
			const opener = createOpenerChannel({
				fundingSatoshis: 1_000_000n,
				localBasepoints: openerBasepoints,
				localPerCommitmentSeed: crypto.randomBytes(32)
			});

			const openActions = opener.initiateOpen();
			const openPayload = (
				openActions[0] as {
					type: ChannelActionType.SEND_MESSAGE;
					payload: Buffer;
				}
			).payload;
			const openMsg = decodeOpenChannelMessage(openPayload);

			// Override with a channel type that doesn't include static_remotekey
			openMsg.channelType = Buffer.from([0x00]);

			const acceptor = createAcceptorChannel({
				temporaryChannelId: openMsg.temporaryChannelId,
				localBasepoints: acceptorBasepoints,
				localPerCommitmentSeed: crypto.randomBytes(32)
			});

			const acceptActions = acceptor.handleOpenChannel(openMsg);
			expect(acceptActions).to.have.lengthOf(1);
			expect(acceptActions[0].type).to.equal(ChannelActionType.ERROR);
			expect(
				(acceptActions[0] as { type: ChannelActionType.ERROR; message: string })
					.message
			).to.include('static_remotekey');
		});
	});

	describe('LightningNode default features', () => {
		it('should include static_remotekey in default features', () => {
			const defaults = LightningNode.defaultFeatures();
			expect(defaults.hasFeature(Feature.STATIC_REMOTE_KEY)).to.be.true;
		});

		it('should include data_loss_protect in default features', () => {
			const defaults = LightningNode.defaultFeatures();
			expect(defaults.hasFeature(Feature.DATA_LOSS_PROTECT)).to.be.true;
		});

		it('should set features as optional (odd bits)', () => {
			const defaults = LightningNode.defaultFeatures();
			expect(defaults.isOptional(Feature.STATIC_REMOTE_KEY)).to.be.true;
			expect(defaults.isOptional(Feature.DATA_LOSS_PROTECT)).to.be.true;
		});
	});
});
