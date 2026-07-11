/**
 * Remote update_fee two-phase commit + commitment-round alternation.
 *
 * Pins the CLN-funded-channel desync observed live: CLN (opener) sends
 * update_fee; beignet (acceptor) applied the staged rate to commitments it
 * SIGNS immediately and marked itself as owing a commitment_signed at
 * update_fee RECEIPT. Per the BOLT 2 two-phase update flow (CLN's fee state
 * machine), the opener's update_fee may only enter commitments the acceptor
 * signs AFTER the acceptor has received a covering commitment_signed and
 * revoked its prior commitment. Signing earlier produces "Bad commit_sig" at
 * CLN; a second commitment_signed pipelined before the first revoke_and_ack
 * desyncs the shachain index ("Invalid per-commitment secret") and inflates
 * channel_reestablish's next_revocation_number ("bad future
 * last_local_per_commit_secret: 3 vs 2" at CLN), ending in force close.
 *
 * The tests drive two real ChannelManagers over MANUALLY DRAINED message
 * queues so the exact live interleavings can be reproduced deterministically.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { MessageType } from '../../src/lightning/message/types';
import { decodeCommitmentSignedMessage } from '../../src/lightning/message/channel-commitment';
import { decodeChannelReestablishMessage } from '../../src/lightning/message/channel-reestablish';
import { verifyRemoteCommitmentSig } from '../../src/lightning/channel/commitment-builder';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import { perCommitmentPointFromSecret } from '../../src/lightning/keys/derivation';
import { IChannelState } from '../../src/lightning/channel/channel-state';

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`fee-desync-seed-${id}`))
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

function makeConfig(seedId: number): IChannelManagerConfig {
	const seed = makeSeed(seedId);
	const fundingPrivkey = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([0]))
		.digest();
	const htlcBasepointSecret = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([4]))
		.digest();
	return {
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(seed),
		localPerCommitmentSeed: makeSeed(seedId + 100),
		localFundingPrivkey: fundingPrivkey,
		htlcBasepointSecret
	};
}

interface IQueuedMsg {
	type: number;
	payload: Buffer;
}

interface IHarness {
	alice: ChannelManager; // opener / funder (CLN analogue)
	bob: ChannelManager; // acceptor (beignet analogue)
	aliceErrors: string[];
	bobErrors: string[];
	aToB: IQueuedMsg[];
	bToA: IQueuedMsg[];
	/** Deliver the next n queued alice→bob messages (default: all queued NOW). */
	deliverToBob: (n?: number) => void;
	/** Deliver the next n queued bob→alice messages (default: all queued NOW). */
	deliverToAlice: (n?: number) => void;
	/** Drain both directions until quiescent. */
	drainAll: () => void;
}

const ALICE_CONFIG = makeConfig(1);
const BOB_CONFIG = makeConfig(2);
const ALICE_PUBKEY = ALICE_CONFIG.localBasepoints.fundingPubkey.toString('hex');
const BOB_PUBKEY = BOB_CONFIG.localBasepoints.fundingPubkey.toString('hex');

/**
 * Two managers connected via manually drained queues, so tests control the
 * exact wire interleaving (a synchronous loopback cannot: it re-enters and,
 * with beignet on BOTH ends, the opener-side and acceptor-side halves of the
 * fee bug cancel each other out).
 */
function makeHarness(): IHarness {
	const alice = new ChannelManager(ALICE_CONFIG);
	const bob = new ChannelManager(BOB_CONFIG);
	const aliceErrors: string[] = [];
	const bobErrors: string[] = [];
	alice.on('error', (_id: Buffer | null, msg: string) => aliceErrors.push(msg));
	bob.on('error', (_id: Buffer | null, msg: string) => bobErrors.push(msg));

	const aToB: IQueuedMsg[] = [];
	const bToA: IQueuedMsg[] = [];
	alice.on(
		'message:outbound',
		(peerPubkey: string, type: number, payload: Buffer) => {
			if (peerPubkey === BOB_PUBKEY) aToB.push({ type, payload });
		}
	);
	bob.on(
		'message:outbound',
		(peerPubkey: string, type: number, payload: Buffer) => {
			if (peerPubkey === ALICE_PUBKEY) bToA.push({ type, payload });
		}
	);

	const deliverToBob = (n?: number): void => {
		let count = n ?? aToB.length;
		while (count-- > 0 && aToB.length > 0) {
			const m = aToB.shift()!;
			bob.handleMessage(ALICE_PUBKEY, m.type, m.payload);
		}
	};
	const deliverToAlice = (n?: number): void => {
		let count = n ?? bToA.length;
		while (count-- > 0 && bToA.length > 0) {
			const m = bToA.shift()!;
			alice.handleMessage(BOB_PUBKEY, m.type, m.payload);
		}
	};
	const drainAll = (): void => {
		while (aToB.length > 0 || bToA.length > 0) {
			deliverToBob();
			deliverToAlice();
		}
	};

	return {
		alice,
		bob,
		aliceErrors,
		bobErrors,
		aToB,
		bToA,
		deliverToBob,
		deliverToAlice,
		drainAll
	};
}

/** Open a channel alice→bob and reach NORMAL on both sides. */
function openChannel(h: IHarness): Buffer {
	const channel = h.alice.openChannel(BOB_PUBKEY, 1_000_000n);
	h.drainAll();
	const channelId = h.alice.createFunding(
		channel,
		crypto.randomBytes(32),
		0,
		crypto.randomBytes(64)
	)!;
	h.drainAll();
	h.alice.handleFundingConfirmed(channelId);
	h.bob.handleFundingConfirmed(channelId);
	h.drainAll();
	return channelId;
}

/** A full clean alice→bob HTLC add round (drained). Returns bob's htlc id. */
function addHtlcAliceToBob(
	h: IHarness,
	channelId: Buffer,
	preimage: Buffer,
	amountMsat: bigint
): bigint {
	const paymentHash = crypto.createHash('sha256').update(preimage).digest();
	let forwardedId: bigint | null = null;
	const onForwarded = (_cid: Buffer, htlcId: bigint): void => {
		forwardedId = htlcId;
	};
	h.bob.on('htlc:forwarded', onForwarded);
	h.alice.addHtlc(
		channelId,
		amountMsat,
		paymentHash,
		500_000,
		crypto.randomBytes(1366)
	);
	h.drainAll();
	h.bob.removeListener('htlc:forwarded', onForwarded);
	expect(forwardedId, 'HTLC must have been forwarded to bob').to.not.equal(
		null
	);
	return forwardedId!;
}

/** Counters of a channel, for symmetric bookkeeping assertions. */
function counters(state: IChannelState): {
	local: bigint;
	remote: bigint;
} {
	return {
		local: state.localCommitmentNumber,
		remote: state.remoteCommitmentNumber
	};
}

describe('remote update_fee two-phase commit (CLN desync pin)', function () {
	it('a commitment signed between update_fee receipt and the covering commitment_signed uses the OLD feerate', function () {
		// Live shape: CLN sends update_fee; before CLN's commitment_signed is
		// processed, beignet fulfills an invoice HTLC (its own trigger) and signs.
		// CLN's own fee is not yet revocation-acked, so CLN builds its local
		// commitment at the OLD rate — a NEW-rate signature is "Bad commit_sig".
		const h = makeHarness();
		const channelId = openChannel(h);

		const preimage = crypto.randomBytes(32);
		const htlcId = addHtlcAliceToBob(h, channelId, preimage, 50_000_000n);

		const aliceChannel = h.alice.getChannel(channelId)!;
		const bobChannel = h.bob.getChannel(channelId)!;
		const oldRate = aliceChannel.getFullState().localConfig.feeratePerKw;
		const newRate = oldRate * 2;

		// Alice (opener) proposes the fee: emits update_fee + commitment_signed.
		h.alice.updateChannelFee(channelId, newRate);
		expect(h.aToB.map((m) => m.type)).to.deep.equal([
			MessageType.UPDATE_FEE,
			MessageType.COMMITMENT_SIGNED
		]);

		// Deliver ONLY the update_fee — alice's covering commitment_signed is
		// still in flight (they arrive as separate TCP reads live).
		h.deliverToBob(1);

		// Bob now fulfills the HTLC — this triggers his commitment_signed.
		h.bob.fulfillHtlc(channelId, htlcId, preimage);
		const csMsg = h.bToA.find((m) => m.type === MessageType.COMMITMENT_SIGNED);
		expect(csMsg, 'bob must sign the fulfill removal').to.exist;
		const cs = decodeCommitmentSignedMessage(csMsg!.payload);

		// Deliver bob's update_fulfill (it precedes the signature on the wire)
		// so alice's state reflects the removal the signature covers.
		expect(h.bToA[0].type).to.equal(MessageType.UPDATE_FULFILL_HTLC);
		h.deliverToAlice(1);

		// Ground truth (CLN semantics): the signature must verify against
		// ALICE's local commitment built at the OLD rate. Build it from alice's
		// state with the staged fee stripped.
		const aliceState = aliceChannel.getFullState();
		const oldRateState: IChannelState = {
			...aliceState,
			pendingFeeratePerKw: undefined
		};
		const nextNum = aliceState.localCommitmentNumber + 1n;
		const alicePoint = perCommitmentPointFromSecret(
			generateFromSeed(aliceState.localPerCommitmentSeed, MAX_INDEX - nextNum)
		);
		const validAtOldRate = verifyRemoteCommitmentSig(
			oldRateState,
			aliceChannel.getSigner()!,
			alicePoint,
			cs.signature,
			nextNum
		);
		expect(
			validAtOldRate,
			'commitment signed before the fee round is revocation-acked must use the OLD feerate'
		).to.equal(true);

		// The staged fee must still be pending on bob (not promoted, not signed).
		expect(bobChannel.getFullState().pendingFeeratePerKw).to.equal(newRate);

		// Now complete everything: fulfill+CS to alice, her replies, alice's
		// fee-CS to bob, and the deferred fee-ack round.
		h.drainAll();

		expect(h.aliceErrors, 'alice saw no channel errors').to.deep.equal([]);
		expect(h.bobErrors, 'bob saw no channel errors').to.deep.equal([]);

		// Fee fully committed on both sides.
		const aliceFinal = aliceChannel.getFullState();
		const bobFinal = bobChannel.getFullState();
		expect(aliceFinal.localConfig.feeratePerKw).to.equal(newRate);
		expect(aliceFinal.pendingFeeratePerKw).to.equal(undefined);
		expect(bobFinal.remoteConfig.feeratePerKw).to.equal(newRate);
		expect(bobFinal.pendingFeeratePerKw).to.equal(undefined);

		// Symmetric commitment bookkeeping, no pipelined desync.
		const a = counters(aliceFinal);
		const b = counters(bobFinal);
		expect(Number(a.local)).to.equal(Number(b.remote));
		expect(Number(a.remote)).to.equal(Number(b.local));

		// The fulfill settled: bob was credited the HTLC amount.
		expect(Number(bobFinal.localBalanceMsat)).to.equal(50_000_000);

		// The channel keeps working: another full payment round.
		const preimage2 = crypto.randomBytes(32);
		const htlcId2 = addHtlcAliceToBob(h, channelId, preimage2, 20_000_000n);
		h.bob.fulfillHtlc(channelId, htlcId2, preimage2);
		h.drainAll();
		expect(h.aliceErrors).to.deep.equal([]);
		expect(h.bobErrors).to.deep.equal([]);
		expect(Number(bobChannel.getFullState().localBalanceMsat)).to.equal(
			70_000_000
		);
	});

	it('does not promote a staged fee on a revoke_and_ack that predates the fee round', function () {
		// Z2 live shape: update_fee is proposed while an unrelated commitment
		// round (a fulfill removal) is still in flight. The revoke_and_ack that
		// answers the REMOVAL commitment must not promote the still-staged fee
		// on either side, and the fee's own commitment_signed must wait for the
		// removal round's revoke_and_ack (alternation).
		const h = makeHarness();
		const channelId = openChannel(h);

		const preimage = crypto.randomBytes(32);
		const htlcId = addHtlcAliceToBob(h, channelId, preimage, 40_000_000n);
		const aliceChannel = h.alice.getChannel(channelId)!;
		const bobChannel = h.bob.getChannel(channelId)!;
		const oldRate = bobChannel.getFullState().remoteConfig.feeratePerKw;
		const newRate = oldRate * 2;

		// Bob fulfills; his commitment_signed goes out and is delivered.
		h.bob.fulfillHtlc(channelId, htlcId, preimage);
		h.deliverToAlice(); // fulfill + CS → alice replies RAA + removal-CS
		expect(h.aToB.map((m) => m.type)).to.deep.equal([
			MessageType.REVOKE_AND_ACK,
			MessageType.COMMITMENT_SIGNED
		]);

		// Alice proposes the fee while her removal-CS is still unrevoked. The
		// update_fee goes out now; its own commitment_signed must be DEFERRED
		// until bob's revoke_and_ack for the removal commitment.
		h.alice.updateChannelFee(channelId, newRate);
		expect(h.aToB.map((m) => m.type)).to.deep.equal([
			MessageType.REVOKE_AND_ACK,
			MessageType.COMMITMENT_SIGNED,
			MessageType.UPDATE_FEE
		]);

		// Bob processes the RAA, the removal-CS (at the OLD rate) and the
		// update_fee. He owes nothing yet: the fee-covering commitment_signed
		// from alice has not arrived, so bob must not sign, promote, or clear.
		h.deliverToBob();
		expect(
			h.bToA.filter((m) => m.type === MessageType.COMMITMENT_SIGNED).length,
			'bob must not sign before the fee-covering commitment_signed arrives'
		).to.equal(0);
		const bobState = bobChannel.getFullState();
		expect(bobState.pendingFeeratePerKw, 'fee stays staged at bob').to.equal(
			newRate
		);
		expect(
			bobState.remoteConfig.feeratePerKw,
			'bob committed rate unchanged'
		).to.equal(oldRate);

		// Bob's revoke_and_ack for the REMOVAL round reaches alice: it must not
		// promote her staged fee (her fee-CS has not even been sent), only
		// release the deferred fee commitment.
		expect(h.bToA[0].type).to.equal(MessageType.REVOKE_AND_ACK);
		h.deliverToAlice(1);
		const aliceState = aliceChannel.getFullState();
		expect(
			aliceState.localConfig.feeratePerKw,
			'a revoke_and_ack for an unrelated round must not promote the staged fee'
		).to.equal(oldRate);
		expect(
			aliceState.pendingFeeratePerKw,
			'fee stays staged at alice'
		).to.equal(newRate);
		expect(
			h.aToB.filter((m) => m.type === MessageType.COMMITMENT_SIGNED).length,
			'the deferred fee commitment_signed goes out after the revoke_and_ack'
		).to.equal(1);

		// Finish the fee round; everything settles cleanly at the new rate.
		h.drainAll();
		expect(h.aliceErrors).to.deep.equal([]);
		expect(h.bobErrors).to.deep.equal([]);
		expect(bobChannel.getFullState().remoteConfig.feeratePerKw).to.equal(
			newRate
		);
		expect(bobChannel.getFullState().pendingFeeratePerKw).to.equal(undefined);
		const aliceFinal = aliceChannel.getFullState();
		expect(aliceFinal.localConfig.feeratePerKw).to.equal(newRate);
		expect(aliceFinal.pendingFeeratePerKw).to.equal(undefined);

		// The channel keeps working after the interleaved rounds.
		const preimage2 = crypto.randomBytes(32);
		const htlcId2 = addHtlcAliceToBob(h, channelId, preimage2, 10_000_000n);
		h.bob.fulfillHtlc(channelId, htlcId2, preimage2);
		h.drainAll();
		expect(h.aliceErrors).to.deep.equal([]);
		expect(h.bobErrors).to.deep.equal([]);
	});
});

describe('commitment round alternation (pipelined commitment_signed desync pin)', function () {
	it('a second update while a commitment is unrevoked defers its commitment_signed until the revoke_and_ack', function () {
		// Live symptom of the pipelined variant: beignet's shachain expected
		// index is computed from the SIGN counter, so the peer's first
		// revoke_and_ack after two pipelined commitment_signed messages fails
		// with "Invalid per-commitment secret" and the channel force-closes.
		const h = makeHarness();
		const channelId = openChannel(h);

		const pre1 = crypto.randomBytes(32);
		const hash1 = crypto.createHash('sha256').update(pre1).digest();
		const pre2 = crypto.randomBytes(32);
		const hash2 = crypto.createHash('sha256').update(pre2).digest();

		// Two back-to-back adds WITHOUT letting bob's revoke_and_ack come back.
		h.alice.addHtlc(
			channelId,
			30_000_000n,
			hash1,
			500_000,
			crypto.randomBytes(1366)
		);
		h.alice.addHtlc(
			channelId,
			20_000_000n,
			hash2,
			500_000,
			crypto.randomBytes(1366)
		);

		// Exactly ONE commitment_signed may be in flight; the second add's
		// commitment must wait for bob's revoke_and_ack.
		expect(
			h.aToB.filter((m) => m.type === MessageType.COMMITMENT_SIGNED).length,
			'no pipelined second commitment_signed before revoke_and_ack'
		).to.equal(1);

		// Drain: bob revokes, alice's deferred commitment for the second add
		// goes out, both HTLCs commit, no shachain errors on either side.
		h.drainAll();
		expect(h.aliceErrors).to.deep.equal([]);
		expect(h.bobErrors).to.deep.equal([]);

		const aliceState = h.alice.getChannel(channelId)!.getFullState();
		const bobState = h.bob.getChannel(channelId)!.getFullState();
		expect(bobState.htlcs.size, 'both HTLCs live at bob').to.equal(2);
		expect(Number(aliceState.localCommitmentNumber)).to.equal(
			Number(bobState.remoteCommitmentNumber)
		);
		expect(Number(aliceState.remoteCommitmentNumber)).to.equal(
			Number(bobState.localCommitmentNumber)
		);
	});
});

describe('channel_reestablish revocation accounting (bad future secret pin)', function () {
	it('next_revocation_number counts received revocations, not sent commitments', function () {
		// Live symptom: with a commitment_signed in flight (unrevoked), beignet
		// claimed next_revocation_number one too high and shipped an all-zero
		// your_last_per_commitment_secret — CLN: "bad future
		// last_local_per_commit_secret: 3 vs 2" → force close.
		const h = makeHarness();
		const channelId = openChannel(h);

		const preimage = crypto.randomBytes(32);
		const htlcId = addHtlcAliceToBob(h, channelId, preimage, 25_000_000n);

		// Bob fulfills; his commitment_signed is LOST with the connection.
		h.bob.fulfillHtlc(channelId, htlcId, preimage);
		expect(
			h.bToA.filter((m) => m.type === MessageType.COMMITMENT_SIGNED).length
		).to.equal(1);
		h.bToA.length = 0; // connection dies; nothing was delivered

		h.alice.handlePeerDisconnected(BOB_PUBKEY);
		h.bob.handlePeerDisconnected(ALICE_PUBKEY);

		// Reconnect: capture bob's channel_reestablish.
		h.bob.handlePeerReconnected(ALICE_PUBKEY);
		const reestMsg = h.bToA.find(
			(m) => m.type === MessageType.CHANNEL_REESTABLISH
		);
		expect(reestMsg).to.exist;
		const reest = decodeChannelReestablishMessage(reestMsg!.payload);

		// Bob signed 2 commitments (add-ack, fulfill) but received only ONE
		// revocation from alice (for the add-ack). He expects revocation #1
		// next — NOT #2 — and must prove alice's LAST revealed secret (#0).
		expect(Number(reest.nextRevocationNumber)).to.equal(1);
		expect(
			reest.yourLastPerCommitmentSecret.equals(Buffer.alloc(32)),
			'your_last_per_commitment_secret must be the real secret, not zeros'
		).to.equal(false);
		expect(
			reest.yourLastPerCommitmentSecret.equals(
				generateFromSeed(ALICE_CONFIG.localPerCommitmentSeed, MAX_INDEX)
			),
			'must reveal exactly the one secret alice released (commitment #0)'
		).to.equal(true);

		// Full reconnect completes the interrupted round: alice reestablishes
		// too, bob retransmits the lost fulfill + commitment_signed, the round
		// finishes, and another payment succeeds.
		h.alice.handlePeerReconnected(BOB_PUBKEY);
		h.drainAll();
		expect(h.aliceErrors).to.deep.equal([]);
		expect(h.bobErrors).to.deep.equal([]);

		const bobFinal = h.bob.getChannel(channelId)!.getFullState();
		expect(Number(bobFinal.localBalanceMsat), 'fulfill settled').to.equal(
			25_000_000
		);

		const preimage2 = crypto.randomBytes(32);
		const htlcId2 = addHtlcAliceToBob(h, channelId, preimage2, 10_000_000n);
		h.bob.fulfillHtlc(channelId, htlcId2, preimage2);
		h.drainAll();
		expect(h.aliceErrors).to.deep.equal([]);
		expect(h.bobErrors).to.deep.equal([]);
		expect(
			Number(h.bob.getChannel(channelId)!.getFullState().localBalanceMsat)
		).to.equal(35_000_000);
	});
});

describe('clean remote update_fee round (regression control)', function () {
	it('an isolated fee round commits on both sides and payments continue', function () {
		const h = makeHarness();
		const channelId = openChannel(h);

		const aliceChannel = h.alice.getChannel(channelId)!;
		const bobChannel = h.bob.getChannel(channelId)!;
		const oldRate = aliceChannel.getFullState().localConfig.feeratePerKw;
		const newRate = oldRate * 2;

		h.alice.updateChannelFee(channelId, newRate);
		h.drainAll();

		expect(h.aliceErrors).to.deep.equal([]);
		expect(h.bobErrors).to.deep.equal([]);
		expect(aliceChannel.getFullState().localConfig.feeratePerKw).to.equal(
			newRate
		);
		expect(aliceChannel.getFullState().pendingFeeratePerKw).to.equal(undefined);
		expect(bobChannel.getFullState().remoteConfig.feeratePerKw).to.equal(
			newRate
		);
		expect(bobChannel.getFullState().pendingFeeratePerKw).to.equal(undefined);

		const a = counters(aliceChannel.getFullState());
		const b = counters(bobChannel.getFullState());
		expect(Number(a.local)).to.equal(Number(b.remote));
		expect(Number(a.remote)).to.equal(Number(b.local));

		// Payments still flow at the new rate.
		const preimage = crypto.randomBytes(32);
		const htlcId = addHtlcAliceToBob(h, channelId, preimage, 15_000_000n);
		h.bob.fulfillHtlc(channelId, htlcId, preimage);
		h.drainAll();
		expect(h.aliceErrors).to.deep.equal([]);
		expect(h.bobErrors).to.deep.equal([]);
		expect(Number(bobChannel.getFullState().localBalanceMsat)).to.equal(
			15_000_000
		);
	});
});
