/**
 * bLIP-0051 update_blockheight (wire type 137), lessor side.
 *
 * The OPENER of a leased channel advances the agreed blockheight, shrinking
 * the lessor's remaining-lease CSV (lease_csv = lease_expiry - blockheight)
 * in the commitment scripts. Beignet used to silently DROP the message (odd
 * type), desyncing every subsequent commitment script against a CLN buyer.
 * The staged height now runs the same two-phase machine as update_fee, and
 * on-chain matchers try every height the channel ever committed.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	createOpenerState,
	createAcceptorState
} from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { Channel } from '../../src/lightning/channel/channel';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { MessageType } from '../../src/lightning/message/types';
import {
	encodeUpdateBlockheightMessage,
	decodeUpdateBlockheightMessage
} from '../../src/lightning/message/channel-update';
import {
	decodeOpenChannelMessage,
	decodeAcceptChannelMessage
} from '../../src/lightning/message/channel-open';
import {
	decodeFundingCreatedMessage,
	decodeFundingSignedMessage,
	decodeChannelReadyMessage
} from '../../src/lightning/message/channel-funding';
import {
	decodeCommitmentSignedMessage,
	decodeRevokeAndAckMessage
} from '../../src/lightning/message/channel-commitment';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import {
	buildLocalCommitment,
	buildRemoteCommitment
} from '../../src/lightning/channel/commitment-builder';
import { leaseCsvBlocks } from '../../src/lightning/channel/liquidity-ads';
import { csvFromToLocalScript } from '../../src/lightning/script/commitment';
import {
	buildToRemoteAnchorOutput,
	leaseCsvFromToRemoteScript
} from '../../src/lightning/script/anchor';
import { classifyOutputs } from '../../src/lightning/chain/output-resolver';
import { CommitmentType, OutputType } from '../../src/lightning/chain/types';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';

bitcoin.initEccLib(ecc);

const OPEN_BH = 800_000;
const LEASE_EXPIRY = OPEN_BH + 4032; // 804032
const NEW_BH = OPEN_BH + 100;

function makeBasepoints(seed: Buffer): {
	basepoints: IChannelBasepoints;
	privkeys: Buffer[];
} {
	const privkeys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		privkeys.push(
			crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from([i]))
				.digest()
		);
	}
	return {
		basepoints: {
			fundingPubkey: getPublicKey(privkeys[0]),
			revocationBasepoint: getPublicKey(privkeys[1]),
			paymentBasepoint: getPublicKey(privkeys[2]),
			delayedPaymentBasepoint: getPublicKey(privkeys[3]),
			htlcBasepoint: getPublicKey(privkeys[4]),
			firstPerCommitmentPoint: Buffer.alloc(33)
		},
		privkeys
	};
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function findSendAction(actions: any[], msgType: MessageType): any {
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	return actions.find(
		(a: any) =>
			a.type === ChannelActionType.SEND_MESSAGE && a.messageType === msgType
	);
}

function makeAnchorChannelType(): Buffer {
	const flags = FeatureFlags.empty();
	flags.setCompulsory(Feature.STATIC_REMOTE_KEY);
	flags.setCompulsory(Feature.ANCHOR_ZERO_FEE_HTLC);
	return flags.toBuffer();
}

/**
 * Loopback buyer(opener)/seller(acceptor) pair driven to NORMAL, then dressed
 * as a leased anchor channel (seller = lessor). Signatures are fake (the
 * Channel state machine does not verify the funding sig itself), which is
 * enough to drive the two-phase blockheight rounds.
 */
function setupLeasedPair(): {
	buyer: Channel;
	seller: Channel;
} {
	const buyerSeed = Buffer.alloc(32, 0x61);
	const sellerSeed = Buffer.alloc(32, 0x62);
	const buyerCommitSeed = crypto
		.createHash('sha256')
		.update(Buffer.from('ubh-buyer'))
		.digest();
	const sellerCommitSeed = crypto
		.createHash('sha256')
		.update(Buffer.from('ubh-seller'))
		.digest();

	const { basepoints: buyerBasepoints } = makeBasepoints(buyerSeed);
	const { basepoints: sellerBasepoints } = makeBasepoints(sellerSeed);

	const buyerState = createOpenerState({
		temporaryChannelId: Buffer.alloc(32, 0xee),
		fundingSatoshis: 1_000_000n,
		pushMsat: 200_000_000n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: buyerBasepoints,
		localPerCommitmentSeed: buyerCommitSeed
	});
	const buyer = new Channel(buyerState);

	const sellerState = createAcceptorState({
		temporaryChannelId: Buffer.alloc(32, 0xee),
		fundingSatoshis: 0n,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: sellerBasepoints,
		localPerCommitmentSeed: sellerCommitSeed,
		remoteBasepoints: buyerBasepoints,
		remoteConfig: { ...DEFAULT_CHANNEL_CONFIG }
	});
	const seller = new Channel(sellerState);

	const openActions = buyer.initiateOpen();
	const openMsg = findSendAction(openActions, MessageType.OPEN_CHANNEL);
	const acceptActions = seller.handleOpenChannel(
		decodeOpenChannelMessage(openMsg.payload)
	);
	const acceptMsg = findSendAction(acceptActions, MessageType.ACCEPT_CHANNEL);
	buyer.handleAcceptChannel(decodeAcceptChannelMessage(acceptMsg.payload));

	const fundingTxid = crypto.randomBytes(32);
	const fcActions = buyer.createFundingCreated(
		fundingTxid,
		0,
		crypto.randomBytes(64)
	);
	const fcMsg = findSendAction(fcActions, MessageType.FUNDING_CREATED);
	const fsActions = seller.handleFundingCreated(
		decodeFundingCreatedMessage(fcMsg.payload),
		crypto.randomBytes(64)
	);
	const fsMsg = findSendAction(fsActions, MessageType.FUNDING_SIGNED);
	buyer.handleFundingSigned(decodeFundingSignedMessage(fsMsg.payload));

	const buyerReady = findSendAction(
		buyer.fundingConfirmed(),
		MessageType.CHANNEL_READY
	);
	seller.handleChannelReady(decodeChannelReadyMessage(buyerReady.payload));
	const sellerReady = findSendAction(
		seller.fundingConfirmed(),
		MessageType.CHANNEL_READY
	);
	buyer.handleChannelReady(decodeChannelReadyMessage(sellerReady.payload));

	expect(buyer.getState()).to.equal(ChannelState.NORMAL);
	expect(seller.getState()).to.equal(ChannelState.NORMAL);

	// Dress as a leased anchor channel: seller is the lessor.
	const anchorType = makeAnchorChannelType();
	const bs = buyer.getFullState();
	const ss = seller.getFullState();
	bs.channelType = anchorType;
	ss.channelType = anchorType;
	bs.leaseExpiry = LEASE_EXPIRY;
	bs.leaseCommitBlockheight = OPEN_BH;
	ss.leaseExpiry = LEASE_EXPIRY;
	ss.leaseCommitBlockheight = OPEN_BH;
	ss.isLessor = true;

	return { buyer, seller };
}

function exchangeCommitments(opener: Channel, acceptor: Channel): void {
	const commitActions1 = opener.signCommitment(crypto.randomBytes(64), []);
	const commitMsg1 = findSendAction(
		commitActions1,
		MessageType.COMMITMENT_SIGNED
	);
	const raaActions1 = acceptor.handleCommitmentSigned(
		decodeCommitmentSignedMessage(commitMsg1.payload)
	);
	const raaMsg1 = findSendAction(raaActions1, MessageType.REVOKE_AND_ACK);
	opener.handleRevokeAndAck(decodeRevokeAndAckMessage(raaMsg1.payload));

	const commitActions2 = acceptor.signCommitment(crypto.randomBytes(64), []);
	const commitMsg2 = findSendAction(
		commitActions2,
		MessageType.COMMITMENT_SIGNED
	);
	const raaActions2 = opener.handleCommitmentSigned(
		decodeCommitmentSignedMessage(commitMsg2.payload)
	);
	const raaMsg2 = findSendAction(raaActions2, MessageType.REVOKE_AND_ACK);
	acceptor.handleRevokeAndAck(decodeRevokeAndAckMessage(raaMsg2.payload));
}

function updateMsg(
	channel: Channel,
	blockheight: number
): { channelId: Buffer; blockheight: number } {
	return { channelId: channel.getChannelId() ?? Buffer.alloc(32), blockheight };
}

describe('update_blockheight (bLIP-0051, lessor side)', function () {
	it('codec round-trips and rejects short payloads; wire type is 137', function () {
		expect(MessageType.UPDATE_BLOCKHEIGHT).to.equal(137);
		const msg = { channelId: crypto.randomBytes(32), blockheight: 812_345 };
		const encoded = encodeUpdateBlockheightMessage(msg);
		expect(encoded.length).to.equal(36);
		const decoded = decodeUpdateBlockheightMessage(encoded);
		expect(decoded.channelId.equals(msg.channelId)).to.be.true;
		expect(decoded.blockheight).to.equal(msg.blockheight);
		expect(() =>
			decodeUpdateBlockheightMessage(encoded.subarray(0, 35))
		).to.throw('too short');
	});

	it('validates sender role, lease presence, monotonicity and staleness', function () {
		const { buyer, seller } = setupLeasedPair();

		// Only the opener may send: the buyer (opener) must reject one.
		const buyerActions = buyer.handleUpdateBlockheight(
			updateMsg(buyer, NEW_BH)
		);
		expect(buyerActions[0]?.type).to.equal(ChannelActionType.ERROR);

		// Not leased / not lessor: strip the lease from the seller.
		const ss = seller.getFullState();
		const savedExpiry = ss.leaseExpiry;
		ss.leaseExpiry = undefined;
		expect(
			seller.handleUpdateBlockheight(updateMsg(seller, NEW_BH))[0]?.type
		).to.equal(ChannelActionType.ERROR);
		ss.leaseExpiry = savedExpiry;

		// Decrease is rejected; equal is a no-op.
		expect(
			seller.handleUpdateBlockheight(updateMsg(seller, OPEN_BH - 1))[0]?.type
		).to.equal(ChannelActionType.ERROR);
		expect(
			seller.handleUpdateBlockheight(updateMsg(seller, OPEN_BH))
		).to.have.length(0);
		expect(ss.pendingLeaseBlockheight).to.be.undefined;

		// Staleness: more than 1008 blocks behind our tip.
		seller.setBlockHeight(NEW_BH + 2000);
		expect(
			seller.handleUpdateBlockheight(updateMsg(seller, NEW_BH))[0]?.type
		).to.equal(ChannelActionType.ERROR);
		seller.setBlockHeight(NEW_BH);

		// Happy path: staged, no error.
		expect(
			seller.handleUpdateBlockheight(updateMsg(seller, NEW_BH))
		).to.have.length(0);
		expect(ss.pendingLeaseBlockheight).to.equal(NEW_BH);
		expect(ss.pendingLeaseBlockheightSignable).to.equal(false);
		expect(ss.leaseCommitBlockheight).to.equal(OPEN_BH);
	});

	it('applies the staged height to the opener-signed commitment immediately, and to commitments we sign only once signable', function () {
		const { seller } = setupLeasedPair();
		const ss = seller.getFullState();
		seller.setBlockHeight(NEW_BH);
		seller.handleUpdateBlockheight(updateMsg(seller, NEW_BH));

		const oldCsv = LEASE_EXPIRY - OPEN_BH;
		const newCsv = LEASE_EXPIRY - NEW_BH;

		// OUR commitment (the opener signs it): staged height applies now.
		const localPoint = getPublicKey(crypto.randomBytes(32));
		const ourTx = buildLocalCommitment(ss, localPoint).result.tx;
		void ourTx;
		// Read the CSV straight from the built to_local script.
		const built = buildLocalCommitment(ss, localPoint);
		const toLocalOut = built.result.toLocalScript;
		expect(toLocalOut).to.exist;
		expect(csvFromToLocalScript(toLocalOut!)).to.equal(
			Math.max(ss.remoteConfig.toSelfDelay, newCsv)
		);

		// THEIR commitment (we sign it): still the OLD height until signable.
		const remotePoint = ss.remoteCurrentPerCommitmentPoint!;
		const theirBuilt = buildRemoteCommitment(ss, remotePoint);
		const theirToRemote = theirBuilt.result.toRemoteScript;
		expect(theirToRemote).to.exist;
		expect(leaseCsvFromToRemoteScript(theirToRemote!)).to.equal(oldCsv);

		// Once signable, commitments we sign use the new height.
		ss.pendingLeaseBlockheightSignable = true;
		const theirBuilt2 = buildRemoteCommitment(ss, remotePoint);
		expect(
			leaseCsvFromToRemoteScript(theirBuilt2.result.toRemoteScript!)
		).to.equal(newCsv);
	});

	it('promotes the height after a full commitment round and records the history', function () {
		const { buyer, seller } = setupLeasedPair();
		seller.setBlockHeight(NEW_BH);
		seller.handleUpdateBlockheight(updateMsg(seller, NEW_BH));
		// Emulate the CLN buyer: it bakes the new height into everything it
		// signs from the moment it sends update_blockheight.
		buyer.getFullState().leaseCommitBlockheight = NEW_BH;

		exchangeCommitments(buyer, seller);

		const ss = seller.getFullState();
		expect(ss.leaseCommitBlockheight).to.equal(NEW_BH);
		expect(ss.pendingLeaseBlockheight).to.be.undefined;
		expect(ss.pendingLeaseBlockheightSignable).to.equal(false);
		expect(ss.pendingLeaseBlockheightCommitted).to.equal(false);
		// History carries both the open height and the promoted one.
		expect(ss.leaseHeightHistory).to.deep.equal([OPEN_BH, NEW_BH]);
	});

	it('rolls back an uncommitted staged height on reestablish; a signable one survives', function () {
		// Uncommitted staged height rolls back on disconnect.
		const a = setupLeasedPair();
		a.seller.setBlockHeight(NEW_BH);
		a.seller.handleUpdateBlockheight(updateMsg(a.seller, NEW_BH));
		expect(a.seller.getFullState().pendingLeaseBlockheight).to.equal(NEW_BH);
		a.seller.markForReestablish();
		expect(a.seller.getFullState().pendingLeaseBlockheight).to.be.undefined;

		// A SIGNABLE staged height is covered by exchanged signatures and
		// survives the reconnect to finish its round.
		const b = setupLeasedPair();
		b.seller.setBlockHeight(NEW_BH);
		b.seller.handleUpdateBlockheight(updateMsg(b.seller, NEW_BH));
		b.seller.getFullState().pendingLeaseBlockheightSignable = true;
		b.seller.markForReestablish();
		expect(b.seller.getFullState().pendingLeaseBlockheight).to.equal(NEW_BH);
	});

	it('leaseCsvBlocks: an at/past-expiry height means the lease ran out (plain scripts)', function () {
		expect(leaseCsvBlocks(LEASE_EXPIRY, LEASE_EXPIRY)).to.be.undefined;
		expect(leaseCsvBlocks(LEASE_EXPIRY, LEASE_EXPIRY + 500)).to.be.undefined;
		// Legacy states with no recorded height keep the full-duration fallback.
		expect(leaseCsvBlocks(LEASE_EXPIRY, undefined)).to.equal(4032);
		expect(leaseCsvBlocks(LEASE_EXPIRY, OPEN_BH)).to.equal(4032);
	});

	it('classifies a to_remote built at an OLD height via the height history', function () {
		const { seller } = setupLeasedPair();
		const ss = seller.getFullState();
		// The channel advanced through two update_blockheight rounds.
		ss.leaseCommitBlockheight = NEW_BH + 50;
		ss.leaseHeightHistory = [OPEN_BH, NEW_BH, NEW_BH + 50];

		// A REVOKED buyer commitment carries our to_remote at the ORIGINAL
		// height's CSV.
		const oldCsv = LEASE_EXPIRY - OPEN_BH;
		const ourToRemoteOld = buildToRemoteAnchorOutput(
			ss.localBasepoints.paymentBasepoint,
			oldCsv
		);

		const tx = new bitcoin.Transaction();
		tx.version = 2;
		tx.addInput(crypto.randomBytes(32), 0);
		tx.addOutput(ourToRemoteOld.script, 5_000);

		const tracked = classifyOutputs(
			tx,
			ss,
			CommitmentType.THEIR_REVOKED_COMMITMENT,
			ss.remoteCommitmentNumber
		);
		const toRemote = tracked.find((o) => o.outputType === OutputType.TO_REMOTE);
		expect(toRemote, 'old-height to_remote matched via history').to.exist;
		expect(leaseCsvFromToRemoteScript(toRemote!.witnessScript!)).to.equal(
			oldCsv
		);
	});
});
