/**
 * BOLT 2 v2 (dual-funding): end-to-end commitment_signed exchange between TWO
 * real `Channel` instances with REAL secp256k1 keys.
 *
 * This drives a full v2 (dual-funded) open all the way through the newly-added
 * commitment_signed round that precedes tx_signatures, and proves the hard
 * fund-safety property: after the flow BOTH sides hold a VERIFIED peer signature
 * over their own commitment #0, reach AWAITING_FUNDING_CONFIRMED, agree on the
 * channel id / funding txid, and can force-close into a broadcastable commitment.
 *
 * Key wiring (why real verification passes):
 *  - Each channel has a ChannelSigner holding the funding private key that
 *    matches its own localBasepoints.fundingPubkey.
 *  - Each side's remoteBasepoints.fundingPubkey is the OTHER side's funding
 *    pubkey (transferred over the wire via open_channel2 / accept_channel2).
 *  - Each side's localBasepoints.firstPerCommitmentPoint is the REAL point
 *    derived from its per-commitment seed at index 0, so the peer's
 *    remoteCurrentPerCommitmentPoint matches the derivation of commitment #0.
 *  The commitment_signed is a 2-of-2 co-signature over the funding output, so
 *  these keys must genuinely correspond or verifyRemoteCommitmentSig fails.
 *
 * Contribution model: BOTH sides contribute exactly one input (opener funds
 * more, so by the BOLT interactive-tx rule the acceptor — lower total input
 * sats — signs tx_signatures first). Because each side owns an input, neither
 * takes the zero-input auto-fill path; both release witnesses via
 * sendTxSignatures. This keeps the ordering deterministic and symmetric.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as ecc from '@bitcoinerlab/secp256k1';
import * as bitcoin from 'bitcoinjs-lib';

bitcoin.initEccLib(ecc);

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
import {
	IChannelBasepoints,
	perCommitmentPointFromSecret
} from '../../src/lightning/keys/derivation';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { ChannelSigner } from '../../src/lightning/keys/signer';
import { IDualFundingParams } from '../../src/lightning/channel/dual-funding';
import {
	IInteractiveTxInput,
	IInteractiveTxOutput
} from '../../src/lightning/interactive-tx/types';
import { createFundingScript } from '../../src/lightning/script/funding';
import {
	decodeOpenChannel2Message,
	decodeAcceptChannel2Message
} from '../../src/lightning/message/dual-funding';
import {
	decodeTxAddInputMessage,
	decodeTxAddOutputMessage,
	decodeTxSignaturesMessage
} from '../../src/lightning/message/interactive-tx';
import { decodeCommitmentSignedMessage } from '../../src/lightning/message/channel-commitment';
import { verifyRemoteCommitmentSig } from '../../src/lightning/channel/commitment-builder';

// ─────────────── Helpers ───────────────

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function findPayload(actions: any[], msgType: MessageType): Buffer | null {
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
function findError(actions: any[]): string | null {
	for (const a of actions) {
		if (a.type === ChannelActionType.ERROR) return a.message;
	}
	return null;
}

function getPerCommitmentPoint(seed: Buffer, n: bigint): Buffer {
	return perCommitmentPointFromSecret(generateFromSeed(seed, MAX_INDEX - n));
}

/**
 * Real basepoints: funding pubkey from a supplied privkey, other basepoints
 * from fresh random keys, and firstPerCommitmentPoint = the actual point at
 * index 0 of `seed` (so commitment #0 verification lines up).
 */
function makeBasepoints(fundingPub: Buffer, seed: Buffer): IChannelBasepoints {
	return {
		fundingPubkey: fundingPub,
		revocationBasepoint: getPublicKey(crypto.randomBytes(32)),
		paymentBasepoint: getPublicKey(crypto.randomBytes(32)),
		delayedPaymentBasepoint: getPublicKey(crypto.randomBytes(32)),
		htlcBasepoint: getPublicKey(crypto.randomBytes(32)),
		firstPerCommitmentPoint: getPerCommitmentPoint(seed, 0n)
	};
}

/** A tiny serialized prevtx with one output of the given value (the wallet UTXO). */
function makePrevTx(valueSats: number): Buffer {
	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.addInput(crypto.randomBytes(32), 0);
	// A 22-byte placeholder scriptPubkey; only the value is read by the flow.
	tx.addOutput(Buffer.alloc(22, 0x00), valueSats);
	return tx.toBuffer();
}

function makeInput(
	serialId: bigint,
	prevTx: Buffer,
	sequence = 0xfffffffd
): IInteractiveTxInput {
	return {
		serialId,
		prevTxid: Buffer.from(bitcoin.Transaction.fromBuffer(prevTx).getHash()),
		prevOutputIndex: 0,
		sequence,
		prevTx,
		prevTxVout: 0
	};
}

interface IHarness {
	opener: Channel;
	acceptor: Channel;
	openerSigner: ChannelSigner;
	acceptorSigner: ChannelSigner;
	openerSeed: Buffer;
	acceptorSeed: Buffer;
	/** commitment_signed payloads captured but NOT yet delivered to the peer. */
	openerCommit: Buffer;
	acceptorCommit: Buffer;
}

const OPENER_FUNDING = 100_000n;
const ACCEPTOR_FUNDING = 50_000n;
const TOTAL_FUNDING = OPENER_FUNDING + ACCEPTOR_FUNDING; // 150_000

/**
 * Wire two real Channels together and drive the v2 open through the
 * tx_complete exchange, stopping right after both sides have EMITTED their
 * commitment_signed (captured, undelivered). Both channels are then in
 * AWAITING_TX_SIGNATURES with a verified-once signer and remote basepoints.
 */
function driveToCommitmentExchange(
	commitmentFeeratePerkw: number = DEFAULT_CHANNEL_CONFIG.feeratePerKw
): IHarness {
	const sharedTempId = crypto.randomBytes(32);

	const openerFundingPriv = crypto.randomBytes(32);
	const acceptorFundingPriv = crypto.randomBytes(32);
	const openerFundingPub = getPublicKey(openerFundingPriv);
	const acceptorFundingPub = getPublicKey(acceptorFundingPriv);
	const openerSigner = new ChannelSigner(openerFundingPriv);
	const acceptorSigner = new ChannelSigner(acceptorFundingPriv);

	const openerSeed = crypto.randomBytes(32);
	const acceptorSeed = crypto.randomBytes(32);
	const openerBp = makeBasepoints(openerFundingPub, openerSeed);
	const acceptorBp = makeBasepoints(acceptorFundingPub, acceptorSeed);

	// ── Opener channel ──
	const openerState = createOpenerState({
		temporaryChannelId: sharedTempId,
		fundingSatoshis: OPENER_FUNDING,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: openerBp,
		localPerCommitmentSeed: openerSeed
	});
	const opener = new Channel(openerState, openerSigner);

	// ── Acceptor channel (funding stub filled in by handleOpenChannel2) ──
	const acceptorState = createAcceptorState({
		temporaryChannelId: sharedTempId,
		fundingSatoshis: 0n,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: acceptorBp,
		localPerCommitmentSeed: acceptorSeed,
		remoteBasepoints: makeBasepoints(
			getPublicKey(crypto.randomBytes(32)),
			crypto.randomBytes(32)
		),
		remoteConfig: { ...DEFAULT_CHANNEL_CONFIG }
	});
	const acceptor = new Channel(acceptorState, acceptorSigner);

	// params.localBasepoints MUST be the SAME object graph as state.localBasepoints
	// so the messages the peer receives match what the signer signs over.
	const openerParams: IDualFundingParams = {
		fundingSatoshis: OPENER_FUNDING,
		fundingFeeratePerkw: 1000,
		// The opener sets the commitment feerate; the acceptor must adopt it into
		// remoteConfig or the commitment_signed round diverges (regression guard).
		commitmentFeeratePerkw,
		dustLimitSatoshis: DEFAULT_CHANNEL_CONFIG.dustLimitSatoshis,
		maxHtlcValueInFlightMsat: DEFAULT_CHANNEL_CONFIG.maxHtlcValueInFlightMsat,
		htlcMinimumMsat: DEFAULT_CHANNEL_CONFIG.htlcMinimumMsat,
		toSelfDelay: DEFAULT_CHANNEL_CONFIG.toSelfDelay,
		maxAcceptedHtlcs: DEFAULT_CHANNEL_CONFIG.maxAcceptedHtlcs,
		locktime: 0,
		localBasepoints: openerState.localBasepoints,
		localPerCommitmentSeed: openerState.localPerCommitmentSeed,
		secondPerCommitmentPoint: getPerCommitmentPoint(openerSeed, 1n)
	};
	const acceptorParams: IDualFundingParams = {
		fundingSatoshis: ACCEPTOR_FUNDING,
		fundingFeeratePerkw: 1000,
		commitmentFeeratePerkw,
		dustLimitSatoshis: DEFAULT_CHANNEL_CONFIG.dustLimitSatoshis,
		maxHtlcValueInFlightMsat: DEFAULT_CHANNEL_CONFIG.maxHtlcValueInFlightMsat,
		htlcMinimumMsat: DEFAULT_CHANNEL_CONFIG.htlcMinimumMsat,
		toSelfDelay: DEFAULT_CHANNEL_CONFIG.toSelfDelay,
		maxAcceptedHtlcs: DEFAULT_CHANNEL_CONFIG.maxAcceptedHtlcs,
		locktime: 0,
		localBasepoints: acceptorState.localBasepoints,
		localPerCommitmentSeed: acceptorState.localPerCommitmentSeed,
		secondPerCommitmentPoint: getPerCommitmentPoint(acceptorSeed, 1n)
	};

	// ── open_channel2 / accept_channel2 ──
	const openActions = opener.initiateOpenV2(openerParams);
	expect(findError(openActions)).to.equal(null);
	const openPayload = findPayload(openActions, MessageType.OPEN_CHANNEL2)!;
	const openMsg = decodeOpenChannel2Message(openPayload);

	// The acceptor adopts the opener's (now BOLT-2-derived) temporary_channel_id,
	// exactly as the ChannelManager does on an inbound open_channel2. Without this
	// the DualFundingSession's temporary_channel_id echo check would fail.
	acceptorState.temporaryChannelId = Buffer.from(openMsg.channelId);

	const acceptActions = acceptor.handleOpenChannel2(openMsg, acceptorParams);
	expect(findError(acceptActions)).to.equal(null);
	const acceptPayload = findPayload(
		acceptActions,
		MessageType.ACCEPT_CHANNEL2
	)!;
	const acceptMsg = decodeAcceptChannel2Message(acceptPayload);

	const handleAcceptActions = opener.handleAcceptChannel2(acceptMsg);
	expect(findError(handleAcceptActions)).to.equal(null);

	// ── interactive-tx: each side contributes one input; opener adds funding out ──
	const openerPrevTx = makePrevTx(120_000); // opener's wallet UTXO (> its funding)
	const acceptorPrevTx = makePrevTx(60_000); // acceptor's wallet UTXO
	const openerInput = makeInput(0n, openerPrevTx); // even serial = initiator
	const acceptorInput = makeInput(1n, acceptorPrevTx); // odd serial = acceptor

	const funding = createFundingScript(openerFundingPub, acceptorFundingPub);
	const fundingOutput: IInteractiveTxOutput = {
		serialId: 2n,
		amountSats: TOTAL_FUNDING,
		scriptPubkey: funding.p2wshOutput
	};

	// opener input -> acceptor
	const oInAct = opener.addTxInput(openerInput);
	expect(findError(oInAct)).to.equal(null);
	acceptor.handleTxAddInput(
		decodeTxAddInputMessage(findPayload(oInAct, MessageType.TX_ADD_INPUT)!)
	);

	// acceptor input -> opener
	const aInAct = acceptor.addTxInput(acceptorInput);
	expect(findError(aInAct)).to.equal(null);
	opener.handleTxAddInput(
		decodeTxAddInputMessage(findPayload(aInAct, MessageType.TX_ADD_INPUT)!)
	);

	// opener funding output -> acceptor
	const oOutAct = opener.addTxOutput(fundingOutput);
	expect(findError(oOutAct)).to.equal(null);
	acceptor.handleTxAddOutput(
		decodeTxAddOutputMessage(findPayload(oOutAct, MessageType.TX_ADD_OUTPUT)!)
	);

	// ── tx_complete exchange. The acceptor (nothing left to add) completes first;
	//    the opener completes second, which tips BOTH sessions into
	//    AWAITING_TX_SIGNATURES and triggers the commitment_signed emission. ──
	const acCompleteA = acceptor.sendTxComplete(); // acceptor tx_complete
	expect(findError(acCompleteA)).to.equal(null);
	expect(
		findPayload(acCompleteA, MessageType.COMMITMENT_SIGNED),
		'acceptor must NOT sign before the opener has also completed'
	).to.equal(null);
	opener.handleTxComplete();

	const opCompleteActions = opener.sendTxComplete(); // opener tx_complete + commitment
	expect(findError(opCompleteActions)).to.equal(null);
	const openerCommit = findPayload(
		opCompleteActions,
		MessageType.COMMITMENT_SIGNED
	);
	expect(
		openerCommit,
		'opener emits commitment_signed after both tx_completes'
	).to.not.equal(null);
	expect(opener.getState()).to.equal(ChannelState.AWAITING_TX_SIGNATURES);

	const acCompleteActions = acceptor.handleTxComplete(); // acceptor commitment
	expect(findError(acCompleteActions)).to.equal(null);
	const acceptorCommit = findPayload(
		acCompleteActions,
		MessageType.COMMITMENT_SIGNED
	);
	expect(
		acceptorCommit,
		'acceptor emits commitment_signed once both tx_completes are in'
	).to.not.equal(null);
	expect(acceptor.getState()).to.equal(ChannelState.AWAITING_TX_SIGNATURES);

	return {
		opener,
		acceptor,
		openerSigner,
		acceptorSigner,
		openerSeed,
		acceptorSeed,
		openerCommit: openerCommit!,
		acceptorCommit: acceptorCommit!
	};
}

// ─────────────── Tests ───────────────

describe('Dual Funding v2 commitment_signed exchange (e2e, real keys)', () => {
	it('completes the commitment round at a NON-default feerate (remoteConfig regression)', () => {
		// The opener sets a commitment feerate well above the 253 default. Before
		// the fix, handleOpenChannel2 left the acceptor's remoteConfig at the
		// default, so the acceptor built the opener's commitment #0 at 253 while
		// the opener signed at 5000 — verifyRemoteCommitmentSig then rejected both
		// sides and the open aborted. With remoteConfig populated from the message,
		// both sides build byte-identically and the peer signatures verify.
		const h = driveToCommitmentExchange(5000);

		const accHandle = h.acceptor.handleCommitmentSigned(
			decodeCommitmentSignedMessage(h.openerCommit)
		);
		expect(
			findError(accHandle),
			'acceptor accepts opener sig at feerate 5000'
		).to.equal(null);
		const opHandle = h.opener.handleCommitmentSigned(
			decodeCommitmentSignedMessage(h.acceptorCommit)
		);
		expect(
			findError(opHandle),
			'opener accepts acceptor sig at feerate 5000'
		).to.equal(null);

		const openerSig = h.opener.getFullState().remoteCommitmentSignature;
		const acceptorSig = h.acceptor.getFullState().remoteCommitmentSignature;
		expect(Buffer.isBuffer(openerSig)).to.be.true;
		expect(Buffer.isBuffer(acceptorSig)).to.be.true;
		// Both sides recorded the negotiated feerate as the signed-commitment rate.
		expect(h.opener.getFullState().lastSignedCommitFeeratePerKw).to.equal(5000);
		expect(h.acceptor.getFullState().lastSignedCommitFeeratePerKw).to.equal(
			5000
		);
		// Independent re-verification confirms the 5000-feerate commitment co-sig.
		expect(
			verifyRemoteCommitmentSig(
				h.opener.getFullState(),
				h.openerSigner,
				getPerCommitmentPoint(h.openerSeed, 0n),
				openerSig!,
				0n
			)
		).to.be.true;
		expect(
			verifyRemoteCommitmentSig(
				h.acceptor.getFullState(),
				h.acceptorSigner,
				getPerCommitmentPoint(h.acceptorSeed, 0n),
				acceptorSig!,
				0n
			)
		).to.be.true;
	});

	it('exchanges commitment_signed and completes a v2 open with verified signatures', () => {
		const h = driveToCommitmentExchange();

		// Before the commitment round is delivered, neither side has a peer
		// signature over its own commitment.
		expect(h.opener.getFullState().remoteCommitmentSignature).to.equal(null);
		expect(h.acceptor.getFullState().remoteCommitmentSignature).to.equal(null);

		// ── Deliver the commitment_signed messages across ──
		const accHandle = h.acceptor.handleCommitmentSigned(
			decodeCommitmentSignedMessage(h.openerCommit)
		);
		expect(findError(accHandle)).to.equal(null);

		const opHandle = h.opener.handleCommitmentSigned(
			decodeCommitmentSignedMessage(h.acceptorCommit)
		);
		expect(findError(opHandle)).to.equal(null);

		// ── Both now hold a peer signature over their own commitment #0 ──
		const openerSig = h.opener.getFullState().remoteCommitmentSignature;
		const acceptorSig = h.acceptor.getFullState().remoteCommitmentSignature;
		expect(Buffer.isBuffer(openerSig), 'opener has a remote commitment sig').to
			.be.true;
		expect(Buffer.isBuffer(acceptorSig), 'acceptor has a remote commitment sig')
			.to.be.true;
		expect(openerSig!.length).to.equal(64);
		expect(acceptorSig!.length).to.equal(64);

		// ── The stored signatures genuinely VERIFY as 2-of-2 co-signatures over
		//    each side's own commitment #0 (independent re-verification). ──
		const openerVerifies = verifyRemoteCommitmentSig(
			h.opener.getFullState(),
			h.openerSigner,
			getPerCommitmentPoint(h.openerSeed, 0n),
			openerSig!,
			0n
		);
		const acceptorVerifies = verifyRemoteCommitmentSig(
			h.acceptor.getFullState(),
			h.acceptorSigner,
			getPerCommitmentPoint(h.acceptorSeed, 0n),
			acceptorSig!,
			0n
		);
		expect(openerVerifies, 'opener commitment #0 signature verifies').to.be
			.true;
		expect(acceptorVerifies, 'acceptor commitment #0 signature verifies').to.be
			.true;

		// lastSignedCommitFeeratePerKw is set so force-close rebuilds at the right rate.
		expect(h.opener.getFullState().lastSignedCommitFeeratePerKw).to.not.be
			.undefined;
		expect(h.acceptor.getFullState().lastSignedCommitFeeratePerKw).to.not.be
			.undefined;

		// ── Release tx_signatures. The acceptor (lower total input sats) signs
		//    first; the opener defers until the acceptor's witnesses arrive. ──
		const accTxid = h.acceptor.getFullState().fundingTxid!;
		const accOidx = h.acceptor.getFullState().fundingOutputIndex;
		const accSigActions = h.acceptor.sendTxSignatures(accTxid, accOidx, [
			[Buffer.alloc(72)]
		]);
		expect(findError(accSigActions)).to.equal(null);
		const accTxSigs = findPayload(accSigActions, MessageType.TX_SIGNATURES);
		expect(accTxSigs, 'acceptor releases tx_signatures first').to.not.equal(
			null
		);

		const openTxid = h.opener.getFullState().fundingTxid!;
		const openOidx = h.opener.getFullState().fundingOutputIndex;
		const openSigDeferred = h.opener.sendTxSignatures(openTxid, openOidx, [
			[Buffer.alloc(72)]
		]);
		expect(findError(openSigDeferred)).to.equal(null);
		expect(
			findPayload(openSigDeferred, MessageType.TX_SIGNATURES),
			'opener holds tx_signatures until the peer signs first'
		).to.equal(null);

		// Deliver acceptor's tx_signatures -> opener releases its own + confirms.
		const opAfterPeer = h.opener.handleTxSignatures(
			decodeTxSignaturesMessage(accTxSigs!)
		);
		expect(findError(opAfterPeer)).to.equal(null);
		const openTxSigs = findPayload(opAfterPeer, MessageType.TX_SIGNATURES);
		expect(
			openTxSigs,
			'opener releases tx_signatures after the peer'
		).to.not.equal(null);

		// Deliver opener's tx_signatures -> acceptor confirms.
		const acAfterPeer = h.acceptor.handleTxSignatures(
			decodeTxSignaturesMessage(openTxSigs!)
		);
		expect(findError(acAfterPeer)).to.equal(null);

		// ── Both reached AWAITING_FUNDING_CONFIRMED ──
		expect(h.opener.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
		expect(h.acceptor.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);

		// ── Both derived the SAME channel id and funding txid ──
		const openerChanId = h.opener.getChannelId()!;
		const acceptorChanId = h.acceptor.getChannelId()!;
		expect(openerChanId.equals(acceptorChanId), 'channel ids match').to.be.true;
		expect(
			h.opener
				.getFullState()
				.fundingTxid!.equals(h.acceptor.getFullState().fundingTxid!),
			'funding txids match'
		).to.be.true;

		// ── Capacity reconciled to the sum of both contributions ──
		expect(h.opener.getFundingSatoshis()).to.equal(TOTAL_FUNDING);
		expect(h.acceptor.getFundingSatoshis()).to.equal(TOTAL_FUNDING);

		// ── forceClose() on each side yields a broadcastable commitment with the
		//    peer signature paired in — no 'no remote signature' error. ──
		const openerForce = h.opener.forceClose(h.openerSigner);
		expect(findError(openerForce), 'opener force-close has no error').to.equal(
			null
		);
		expect(
			openerForce.some((a) => a.type === ChannelActionType.BROADCAST_TX),
			'opener force-close broadcasts a commitment'
		).to.be.true;

		const acceptorForce = h.acceptor.forceClose(h.acceptorSigner);
		expect(
			findError(acceptorForce),
			'acceptor force-close has no error'
		).to.equal(null);
		expect(
			acceptorForce.some((a) => a.type === ChannelActionType.BROADCAST_TX),
			'acceptor force-close broadcasts a commitment'
		).to.be.true;
	});

	it('rejects a corrupted commitment_signed and never releases tx_signatures', () => {
		const h = driveToCommitmentExchange();

		// Flip a byte in the opener's signature (offset 8 lands inside the 64-byte
		// signature field, past the fixed channel_id header).
		const corrupted = Buffer.from(h.openerCommit);
		corrupted[40] ^= 0xff;

		const actions = h.acceptor.handleCommitmentSigned(
			decodeCommitmentSignedMessage(corrupted)
		);

		// The peer's signature is invalid -> the round must fail.
		const err = findError(actions);
		expect(err, 'a corrupted commitment_signed is rejected').to.not.equal(null);
		expect(err!.toLowerCase()).to.contain('invalid');

		// No signature adopted, and no tx_signatures released.
		expect(h.acceptor.getFullState().remoteCommitmentSignature).to.equal(null);
		expect(
			findPayload(actions, MessageType.TX_SIGNATURES),
			'tx_signatures must not leave on a bad commitment sig'
		).to.equal(null);

		// The acceptor cannot force-close into a broadcastable commitment: it never
		// adopted a verified peer signature (and the open never advanced past the
		// commitment round). Either way, no commitment tx may be broadcast.
		const force = h.acceptor.forceClose(h.acceptorSigner);
		expect(findError(force), 'force-close is blocked').to.not.equal(null);
		expect(
			force.some((a) => a.type === ChannelActionType.BROADCAST_TX),
			'no commitment is broadcast without a verified peer signature'
		).to.be.false;
	});
});
