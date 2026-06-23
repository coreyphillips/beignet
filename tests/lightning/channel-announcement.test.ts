/**
 * Phase 6: Channel Announcements (BOLT 7) tests.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	Channel,
	createOpenerChannel
} from '../../src/lightning/channel/channel';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { MessageType } from '../../src/lightning/message/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { createAcceptorState } from '../../src/lightning/channel/channel-state';
import {
	decodeAnnouncementSignaturesMessage,
	decodeChannelAnnouncementMessage,
	decodeChannelUpdateMessage
} from '../../src/lightning/gossip/messages';
import {
	encodeShortChannelId,
	decodeShortChannelId
} from '../../src/lightning/gossip/types';

function makeBasepoints(): IChannelBasepoints {
	return {
		fundingPubkey: crypto.randomBytes(33),
		revocationBasepoint: crypto.randomBytes(33),
		paymentBasepoint: crypto.randomBytes(33),
		delayedPaymentBasepoint: crypto.randomBytes(33),
		htlcBasepoint: crypto.randomBytes(33),
		firstPerCommitmentPoint: crypto.randomBytes(33)
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

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function findAction(actions: any[], actionType: ChannelActionType): any | null {
	return (
		actions.find((a: { type: ChannelActionType }) => a.type === actionType) ||
		null
	);
}

/**
 * Generate a pair of ordered node IDs (node1 < node2 lexicographically).
 */
function makeOrderedNodeIds(): { nodeId1: Buffer; nodeId2: Buffer } {
	const a = Buffer.alloc(33, 0);
	a[0] = 0x02;
	a[32] = 0x01;
	const b = Buffer.alloc(33, 0);
	b[0] = 0x02;
	b[32] = 0x02;
	return Buffer.compare(a, b) < 0
		? { nodeId1: a, nodeId2: b }
		: { nodeId1: b, nodeId2: a };
}

function signFn(_data: Buffer): { nodeSig: Buffer; bitcoinSig: Buffer } {
	return {
		nodeSig: crypto.randomBytes(64),
		bitcoinSig: crypto.randomBytes(64)
	};
}

/**
 * Create a channel pair in NORMAL state with announceChannel = true.
 */
function setupNormalChannels(): {
	opener: Channel;
	acceptor: Channel;
	openerBp: IChannelBasepoints;
	acceptorBp: IChannelBasepoints;
} {
	const openerBp = makeBasepoints();
	const acceptorBp = makeBasepoints();

	const opener = createOpenerChannel({
		fundingSatoshis: 1_000_000n,
		localBasepoints: openerBp,
		localPerCommitmentSeed: crypto.randomBytes(32)
	});

	const openActions = opener.initiateOpen();
	const openPayload = findSendAction(openActions, MessageType.OPEN_CHANNEL)!;
	const {
		decodeOpenChannelMessage
	} = require('../../src/lightning/message/channel-open');
	const openMsg = decodeOpenChannelMessage(openPayload);

	const acceptorState = createAcceptorState({
		temporaryChannelId: openMsg.temporaryChannelId,
		fundingSatoshis: openMsg.fundingSatoshis,
		pushMsat: openMsg.pushMsat,
		localConfig: DEFAULT_CHANNEL_CONFIG,
		localBasepoints: acceptorBp,
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

	// Set announceChannel = true on both
	acceptorState.announceChannel = true;

	const acceptor = new Channel(acceptorState);
	const {
		decodeAcceptChannelMessage
	} = require('../../src/lightning/message/channel-open');
	const acceptActions = acceptor.handleOpenChannel(openMsg);
	const acceptPayload = findSendAction(
		acceptActions,
		MessageType.ACCEPT_CHANNEL
	)!;
	const acceptMsg = decodeAcceptChannelMessage(acceptPayload);
	opener.handleAcceptChannel(acceptMsg);

	// Set announceChannel on opener too
	opener.getFullState().announceChannel = true;

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
		secondPerCommitmentPoint: crypto.randomBytes(33)
	});
	acceptor.handleChannelReady({
		channelId: acceptor.getChannelId()!,
		secondPerCommitmentPoint: crypto.randomBytes(33)
	});

	expect(opener.getState()).to.equal(ChannelState.NORMAL);
	expect(acceptor.getState()).to.equal(ChannelState.NORMAL);

	return { opener, acceptor, openerBp, acceptorBp };
}

describe('Channel Announcements (Phase 6)', function () {
	describe('SCID derivation', function () {
		it('should encode SCID from block/txIndex/outputIndex', function () {
			const scid = encodeShortChannelId({
				block: 700000,
				txIndex: 42,
				outputIndex: 1
			});
			expect(scid.length).to.equal(8);
			const decoded = decodeShortChannelId(scid);
			expect(decoded.block).to.equal(700000);
			expect(decoded.txIndex).to.equal(42);
			expect(decoded.outputIndex).to.equal(1);
		});

		it('should handle maximum values', function () {
			const scid = encodeShortChannelId({
				block: 0xffffff,
				txIndex: 0xffffff,
				outputIndex: 0xffff
			});
			const decoded = decodeShortChannelId(scid);
			expect(decoded.block).to.equal(0xffffff);
			expect(decoded.txIndex).to.equal(0xffffff);
			expect(decoded.outputIndex).to.equal(0xffff);
		});
	});

	describe('handleAnnouncementDepthReached', function () {
		it('should send announcement_signatures for public channel', function () {
			const { opener } = setupNormalChannels();
			const { nodeId1, nodeId2 } = makeOrderedNodeIds();

			const actions = opener.handleAnnouncementDepthReached(
				700000,
				42,
				nodeId1,
				nodeId2,
				signFn
			);

			const payload = findSendAction(
				actions,
				MessageType.ANNOUNCEMENT_SIGNATURES
			);
			expect(payload).to.not.be.null;

			const decoded = decodeAnnouncementSignaturesMessage(payload!);
			expect(decoded.channelId.equals(opener.getChannelId()!)).to.be.true;
			expect(decoded.nodeSignature.length).to.equal(64);
			expect(decoded.bitcoinSignature.length).to.equal(64);
		});

		it('should set SCID correctly', function () {
			const { opener } = setupNormalChannels();
			const { nodeId1, nodeId2 } = makeOrderedNodeIds();

			opener.handleAnnouncementDepthReached(
				700000,
				42,
				nodeId1,
				nodeId2,
				signFn
			);

			const scid = opener.getShortChannelId();
			expect(scid).to.not.be.null;
			const decoded = decodeShortChannelId(scid!);
			expect(decoded.block).to.equal(700000);
			expect(decoded.txIndex).to.equal(42);
			expect(decoded.outputIndex).to.equal(0);
		});

		it('should mark announcementSigsSent', function () {
			const { opener } = setupNormalChannels();
			const { nodeId1, nodeId2 } = makeOrderedNodeIds();

			expect(opener.getFullState().announcementSigsSent).to.be.false;
			opener.handleAnnouncementDepthReached(
				700000,
				42,
				nodeId1,
				nodeId2,
				signFn
			);
			expect(opener.getFullState().announcementSigsSent).to.be.true;
		});

		it('should not send twice', function () {
			const { opener } = setupNormalChannels();
			const { nodeId1, nodeId2 } = makeOrderedNodeIds();

			opener.handleAnnouncementDepthReached(
				700000,
				42,
				nodeId1,
				nodeId2,
				signFn
			);
			const actions2 = opener.handleAnnouncementDepthReached(
				700000,
				42,
				nodeId1,
				nodeId2,
				signFn
			);
			expect(actions2.length).to.equal(0);
		});

		it('should do nothing for private channel', function () {
			const { opener } = setupNormalChannels();
			opener.getFullState().announceChannel = false;
			const { nodeId1, nodeId2 } = makeOrderedNodeIds();

			const actions = opener.handleAnnouncementDepthReached(
				700000,
				42,
				nodeId1,
				nodeId2,
				signFn
			);
			expect(actions.length).to.equal(0);
		});

		it('should be a silent no-op in a non-NORMAL state (no error spam)', function () {
			// A channel that reaches announcement depth while not NORMAL (e.g. a
			// force-closed channel whose funding crosses 6 confirmations, or one
			// transiently AWAITING_REESTABLISH after a restart) simply isn't
			// announceable. That must be a no-op, NOT an ERROR action — the ERROR
			// previously spammed "Cannot announce: channel not in NORMAL state".
			const opener = createOpenerChannel({
				fundingSatoshis: 1_000_000n,
				localBasepoints: makeBasepoints(),
				localPerCommitmentSeed: crypto.randomBytes(32)
			});
			const { nodeId1, nodeId2 } = makeOrderedNodeIds();

			const actions = opener.handleAnnouncementDepthReached(
				700000,
				42,
				nodeId1,
				nodeId2,
				signFn
			);
			expect(actions.length).to.equal(0);
			expect(findAction(actions, ChannelActionType.ERROR)).to.be.null;
		});
	});

	describe('handleAnnouncementSignatures', function () {
		it('should store remote sigs', function () {
			const { opener } = setupNormalChannels();
			const { nodeId1, nodeId2 } = makeOrderedNodeIds();

			const remoteSigs = {
				channelId: opener.getChannelId()!,
				shortChannelId: encodeShortChannelId({
					block: 700000,
					txIndex: 42,
					outputIndex: 0
				}),
				nodeSignature: crypto.randomBytes(64),
				bitcoinSignature: crypto.randomBytes(64)
			};

			opener.handleAnnouncementSignatures(remoteSigs, nodeId1, nodeId2);

			expect(opener.getFullState().announcementSigsReceived).to.be.true;
			expect(
				opener
					.getFullState()
					.remoteAnnouncementNodeSig!.equals(remoteSigs.nodeSignature)
			).to.be.true;
			expect(
				opener
					.getFullState()
					.remoteAnnouncementBitcoinSig!.equals(remoteSigs.bitcoinSignature)
			).to.be.true;
		});

		it('should set SCID from remote if not set', function () {
			const { opener } = setupNormalChannels();
			const { nodeId1, nodeId2 } = makeOrderedNodeIds();

			expect(opener.getShortChannelId()).to.be.null;

			const scid = encodeShortChannelId({
				block: 700000,
				txIndex: 42,
				outputIndex: 0
			});
			opener.handleAnnouncementSignatures(
				{
					channelId: opener.getChannelId()!,
					shortChannelId: scid,
					nodeSignature: crypto.randomBytes(64),
					bitcoinSignature: crypto.randomBytes(64)
				},
				nodeId1,
				nodeId2
			);

			expect(opener.getShortChannelId()!.equals(scid)).to.be.true;
		});

		it('should silently ignore in wrong state', function () {
			const opener = createOpenerChannel({
				fundingSatoshis: 1_000_000n,
				localBasepoints: makeBasepoints(),
				localPerCommitmentSeed: crypto.randomBytes(32)
			});

			const actions = opener.handleAnnouncementSignatures(
				{
					channelId: Buffer.alloc(32),
					shortChannelId: Buffer.alloc(8),
					nodeSignature: crypto.randomBytes(64),
					bitcoinSignature: crypto.randomBytes(64)
				},
				crypto.randomBytes(33),
				crypto.randomBytes(33)
			);
			// Silently ignored in non-NORMAL state (no error, no actions)
			expect(actions).to.have.length(0);
		});
	});

	describe('Full announcement exchange', function () {
		it('should produce ANNOUNCEMENT_READY when both sides exchange sigs', function () {
			const { opener } = setupNormalChannels();
			const { nodeId1, nodeId2 } = makeOrderedNodeIds();

			// Opener reaches announcement depth
			const depthActions = opener.handleAnnouncementDepthReached(
				700000,
				42,
				nodeId1,
				nodeId2,
				signFn
			);
			const announceSigsPayload = findSendAction(
				depthActions,
				MessageType.ANNOUNCEMENT_SIGNATURES
			)!;
			const openerSigs =
				decodeAnnouncementSignaturesMessage(announceSigsPayload);

			// Now opener receives remote's announcement_signatures with local sigs for full assembly
			const remoteSigs = {
				channelId: opener.getChannelId()!,
				shortChannelId: opener.getShortChannelId()!,
				nodeSignature: crypto.randomBytes(64),
				bitcoinSignature: crypto.randomBytes(64)
			};

			const actions = opener.handleAnnouncementSignatures(
				remoteSigs,
				nodeId1,
				nodeId2,
				openerSigs.nodeSignature,
				openerSigs.bitcoinSignature
			);

			const readyAction = findAction(
				actions,
				ChannelActionType.ANNOUNCEMENT_READY
			);
			expect(readyAction).to.not.be.null;
			expect(readyAction.channelAnnouncement.length).to.be.greaterThan(0);
			expect(readyAction.channelUpdate.length).to.be.greaterThan(0);
		});

		it('should produce ANNOUNCEMENT_READY when remote sigs arrive first', function () {
			const { opener } = setupNormalChannels();
			const { nodeId1, nodeId2 } = makeOrderedNodeIds();

			// Remote sends announcement_signatures first
			const remoteSigs = {
				channelId: opener.getChannelId()!,
				shortChannelId: encodeShortChannelId({
					block: 700000,
					txIndex: 42,
					outputIndex: 0
				}),
				nodeSignature: crypto.randomBytes(64),
				bitcoinSignature: crypto.randomBytes(64)
			};
			opener.handleAnnouncementSignatures(remoteSigs, nodeId1, nodeId2);

			// Now opener reaches announcement depth — should have ANNOUNCEMENT_READY since remote sigs exist
			const actions = opener.handleAnnouncementDepthReached(
				700000,
				42,
				nodeId1,
				nodeId2,
				signFn
			);

			// Should have both SEND_MESSAGE (our sigs) and ANNOUNCEMENT_READY
			const announcePayload = findSendAction(
				actions,
				MessageType.ANNOUNCEMENT_SIGNATURES
			);
			expect(announcePayload).to.not.be.null;

			const readyAction = findAction(
				actions,
				ChannelActionType.ANNOUNCEMENT_READY
			);
			expect(readyAction).to.not.be.null;
		});

		it('re-signs a stored bitcoin signature made with the wrong key (self-heal)', function () {
			const { opener } = setupNormalChannels();
			const { nodeId1, nodeId2 } = makeOrderedNodeIds();
			const { ChannelSigner } = require('../../src/lightning/keys/signer');
			const { getPublicKey } = require('../../src/lightning/crypto/ecdh');
			const ecc = require('@bitcoinerlab/secp256k1');

			// Real funding keypair + signer on the channel (the announcement
			// advertises this pubkey as our bitcoin_key).
			const fundingPriv = crypto
				.createHash('sha256')
				.update('announce-repair')
				.digest();
			const state = opener.getFullState();
			state.localBasepoints.fundingPubkey = getPublicKey(fundingPriv);
			opener.setSigner(new ChannelSigner(fundingPriv));

			// signFn stores a GARBAGE bitcoin sig — the legacy bug where the
			// announcement was signed with the node-level key instead of the
			// per-channel funding key.
			const depthActions = opener.handleAnnouncementDepthReached(
				700000,
				42,
				nodeId1,
				nodeId2,
				signFn
			);
			const openerSigs = decodeAnnouncementSignaturesMessage(
				findSendAction(depthActions, MessageType.ANNOUNCEMENT_SIGNATURES)!
			);

			const remoteSigs = {
				channelId: opener.getChannelId()!,
				shortChannelId: opener.getShortChannelId()!,
				nodeSignature: crypto.randomBytes(64),
				bitcoinSignature: crypto.randomBytes(64)
			};
			const actions = opener.handleAnnouncementSignatures(
				remoteSigs,
				nodeId1,
				nodeId2,
				openerSigs.nodeSignature,
				openerSigs.bitcoinSignature
			);
			const ready = findAction(actions, ChannelActionType.ANNOUNCEMENT_READY);
			expect(ready).to.not.be.null;

			// Our bitcoin signature in the assembled announcement must verify
			// against the funding pubkey the announcement advertises (we are
			// node_1 in this fixture).
			const payload: Buffer = ready.channelAnnouncement;
			const signedData = payload.subarray(4 * 64);
			const hash = crypto
				.createHash('sha256')
				.update(crypto.createHash('sha256').update(signedData).digest())
				.digest();
			const ann = decodeChannelAnnouncementMessage(payload);
			expect(
				ecc.verify(
					hash,
					state.localBasepoints.fundingPubkey,
					ann.bitcoinSignature1
				),
				'announcement bitcoin sig verifies after repair'
			).to.be.true;
			// The repaired sig replaced the bad one on state (persisted).
			expect(
				state.localAnnouncementBitcoinSig!.equals(openerSigs.bitcoinSignature)
			).to.be.false;
		});

		it('should have correct node ordering in announcement', function () {
			const { opener } = setupNormalChannels();
			const { nodeId1, nodeId2 } = makeOrderedNodeIds();

			opener.handleAnnouncementDepthReached(
				700000,
				42,
				nodeId1,
				nodeId2,
				signFn
			);

			const remoteSigs = {
				channelId: opener.getChannelId()!,
				shortChannelId: opener.getShortChannelId()!,
				nodeSignature: crypto.randomBytes(64),
				bitcoinSignature: crypto.randomBytes(64)
			};

			const actions = opener.handleAnnouncementSignatures(
				remoteSigs,
				nodeId1,
				nodeId2,
				crypto.randomBytes(64),
				crypto.randomBytes(64)
			);

			const readyAction = findAction(
				actions,
				ChannelActionType.ANNOUNCEMENT_READY
			);
			expect(readyAction).to.not.be.null;

			// Decode the announcement and verify node ordering
			const announcement = decodeChannelAnnouncementMessage(
				readyAction.channelAnnouncement
			);
			expect(
				Buffer.compare(announcement.nodeId1, announcement.nodeId2)
			).to.be.lessThan(0);
		});

		it('should include initial channel_update with correct direction', function () {
			const { opener } = setupNormalChannels();
			const { nodeId1, nodeId2 } = makeOrderedNodeIds();

			// If localNodeId == nodeId1, direction bit should be 0
			opener.handleAnnouncementDepthReached(
				700000,
				42,
				nodeId1,
				nodeId2,
				signFn
			);

			const actions = opener.handleAnnouncementSignatures(
				{
					channelId: opener.getChannelId()!,
					shortChannelId: opener.getShortChannelId()!,
					nodeSignature: crypto.randomBytes(64),
					bitcoinSignature: crypto.randomBytes(64)
				},
				nodeId1,
				nodeId2,
				crypto.randomBytes(64),
				crypto.randomBytes(64)
			);

			const readyAction = findAction(
				actions,
				ChannelActionType.ANNOUNCEMENT_READY
			);
			const update = decodeChannelUpdateMessage(readyAction.channelUpdate);
			// localNodeId is nodeId1, so direction bit = 0
			expect(update.channelFlags & 0x01).to.equal(0);
		});

		it('should have direction bit 1 when local is node2', function () {
			const { opener } = setupNormalChannels();
			const { nodeId1, nodeId2 } = makeOrderedNodeIds();

			// Pass nodeId2 as localNodeId — direction bit should be 1
			opener.handleAnnouncementDepthReached(
				700000,
				42,
				nodeId2,
				nodeId1,
				signFn
			);

			const actions = opener.handleAnnouncementSignatures(
				{
					channelId: opener.getChannelId()!,
					shortChannelId: opener.getShortChannelId()!,
					nodeSignature: crypto.randomBytes(64),
					bitcoinSignature: crypto.randomBytes(64)
				},
				nodeId2,
				nodeId1,
				crypto.randomBytes(64),
				crypto.randomBytes(64)
			);

			const readyAction = findAction(
				actions,
				ChannelActionType.ANNOUNCEMENT_READY
			);
			const update = decodeChannelUpdateMessage(readyAction.channelUpdate);
			expect(update.channelFlags & 0x01).to.equal(1);
		});
	});

	describe('Two-party simulation', function () {
		it('should exchange announcement_signatures between opener and acceptor', function () {
			const { opener, acceptor } = setupNormalChannels();
			// Use funding pubkeys as node IDs for simplicity
			const openerNodeId = Buffer.alloc(33, 0);
			openerNodeId[0] = 0x02;
			openerNodeId[32] = 0x01;
			const acceptorNodeId = Buffer.alloc(33, 0);
			acceptorNodeId[0] = 0x02;
			acceptorNodeId[32] = 0x02;

			// Both reach announcement depth
			const openerActions = opener.handleAnnouncementDepthReached(
				700000,
				42,
				openerNodeId,
				acceptorNodeId,
				signFn
			);
			const acceptorActions = acceptor.handleAnnouncementDepthReached(
				700000,
				42,
				acceptorNodeId,
				openerNodeId,
				signFn
			);

			const openerPayload = findSendAction(
				openerActions,
				MessageType.ANNOUNCEMENT_SIGNATURES
			)!;
			const acceptorPayload = findSendAction(
				acceptorActions,
				MessageType.ANNOUNCEMENT_SIGNATURES
			)!;

			expect(openerPayload).to.not.be.null;
			expect(acceptorPayload).to.not.be.null;

			const openerSigs = decodeAnnouncementSignaturesMessage(openerPayload);
			const acceptorSigs = decodeAnnouncementSignaturesMessage(acceptorPayload);

			// Exchange sigs
			const openerResult = opener.handleAnnouncementSignatures(
				acceptorSigs,
				openerNodeId,
				acceptorNodeId,
				openerSigs.nodeSignature,
				openerSigs.bitcoinSignature
			);
			const acceptorResult = acceptor.handleAnnouncementSignatures(
				openerSigs,
				acceptorNodeId,
				openerNodeId,
				acceptorSigs.nodeSignature,
				acceptorSigs.bitcoinSignature
			);

			// Both should produce ANNOUNCEMENT_READY
			expect(findAction(openerResult, ChannelActionType.ANNOUNCEMENT_READY)).to
				.not.be.null;
			expect(findAction(acceptorResult, ChannelActionType.ANNOUNCEMENT_READY))
				.to.not.be.null;

			// Verify both announcements have the same SCID
			const openerReady = findAction(
				openerResult,
				ChannelActionType.ANNOUNCEMENT_READY
			);
			const acceptorReady = findAction(
				acceptorResult,
				ChannelActionType.ANNOUNCEMENT_READY
			);
			const openerAnn = decodeChannelAnnouncementMessage(
				openerReady.channelAnnouncement
			);
			const acceptorAnn = decodeChannelAnnouncementMessage(
				acceptorReady.channelAnnouncement
			);
			expect(openerAnn.shortChannelId.equals(acceptorAnn.shortChannelId)).to.be
				.true;
		});
	});
});
