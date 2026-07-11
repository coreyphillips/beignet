/**
 * update_fee vs force-close safety.
 *
 * A force-close must rebuild the local commitment at the EXACT feerate the
 * stored remote signature covers. Mid-fee-round the in-flight rate (staged
 * pendingFeeratePerKw, or a promoted config rate) can differ from the rate of
 * the last signed commitment; rebuilding at the wrong rate changes the sighash
 * and produces an invalid funding witness — no unilateral exit. These tests
 * pin the lastSignedCommitFeeratePerKw mechanism that prevents that, across
 * promotion, reestablish rollback and restart (serialization).
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
import {
	buildLocalCommitment,
	getCommitmentFeeRate
} from '../../src/lightning/channel/commitment-builder';
import {
	IChannelBasepoints,
	perCommitmentPointFromSecret
} from '../../src/lightning/keys/derivation';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	serializeChannelState,
	deserializeChannelState
} from '../../src/lightning/storage/serialization';

function getPerCommitmentPoint(seed: Buffer, commitmentNumber: bigint): Buffer {
	return perCommitmentPointFromSecret(
		generateFromSeed(seed, MAX_INDEX - commitmentNumber)
	);
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

const localSeed = crypto
	.createHash('sha256')
	.update('update-fee-fc-local')
	.digest();
const remoteSeed = crypto
	.createHash('sha256')
	.update('update-fee-fc-remote')
	.digest();

const OLD_RATE = 2000;
const NEW_RATE = 5000;

function makeNormalAcceptorChannel(): Channel {
	const state = createAcceptorState({
		temporaryChannelId: crypto.randomBytes(32),
		fundingSatoshis: 1_000_000n,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(localSeed),
		localPerCommitmentSeed: localSeed,
		remoteBasepoints: makeBasepoints(remoteSeed),
		remoteConfig: { ...DEFAULT_CHANNEL_CONFIG, feeratePerKw: OLD_RATE }
	});
	state.channelId = crypto.randomBytes(32);
	state.state = ChannelState.NORMAL;
	state.fundingTxid = crypto.randomBytes(32);
	state.localBalanceMsat = 400_000_000n;
	state.remoteBalanceMsat = 600_000_000n;
	return new Channel(state);
}

describe('update_fee force-close safety (lastSignedCommitFeeratePerKw)', function () {
	it('records the staged feerate as the signed-commitment rate on commitment_signed', function () {
		const channel = makeNormalAcceptorChannel();
		const state = channel.getFullState();

		// Opener raises the fee; we stage it.
		channel.handleUpdateFee({
			channelId: state.channelId!,
			feeratePerKw: NEW_RATE
		});
		expect(state.pendingFeeratePerKw).to.equal(NEW_RATE);

		// Their commitment_signed covers our local commitment at the staged
		// rate (no signer in this test, so sig verification is skipped — the
		// bookkeeping under test is identical).
		channel.handleCommitmentSigned({
			channelId: state.channelId!,
			signature: crypto.randomBytes(64),
			htlcSignatures: []
		});

		expect(state.lastSignedCommitFeeratePerKw).to.equal(NEW_RATE);
		// The round has not finalized (no revoke_and_ack from us processed by
		// the opener yet) — pending stays staged.
		expect(state.pendingFeeratePerKw).to.equal(NEW_RATE);
	});

	it('rolls back a staged rate on reestablish ONLY while no signature covers it', function () {
		// Fee staged but the opener's covering commitment_signed never arrived:
		// the round is void — reestablish wipes the staged rate (the opener
		// forgets/replays its update_fee on reconnect).
		const uncovered = makeNormalAcceptorChannel();
		const uncoveredState = uncovered.getFullState();
		uncovered.handleUpdateFee({
			channelId: uncoveredState.channelId!,
			feeratePerKw: NEW_RATE
		});
		uncovered.markForReestablish();
		expect(uncoveredState.pendingFeeratePerKw).to.equal(undefined);

		// Fee staged AND covered by the opener's commitment_signed (we revoked
		// for it): the rate is locked into the exchange — the opener will NOT
		// re-send update_fee, so the OLD rollback here desynced every later
		// commitment (the live CLN "Bad commit_sig" class). It must survive.
		const channel = makeNormalAcceptorChannel();
		const state = channel.getFullState();
		const point = getPerCommitmentPoint(localSeed, 1n);

		channel.handleUpdateFee({
			channelId: state.channelId!,
			feeratePerKw: NEW_RATE
		});
		channel.handleCommitmentSigned({
			channelId: state.channelId!,
			signature: crypto.randomBytes(64),
			htlcSignatures: []
		});

		// The commitment the peer signed: built at the staged rate.
		const signedTx = buildLocalCommitment(state, point).result.tx.toHex();

		channel.markForReestablish();
		expect(state.pendingFeeratePerKw, 'covered fee survives').to.equal(
			NEW_RATE
		);
		expect(state.lastSignedCommitFeeratePerKw).to.equal(NEW_RATE);

		// signedLocal rebuild reproduces the signed tx exactly...
		const rebuilt = buildLocalCommitment(
			state,
			point,
			undefined,
			true
		).result.tx.toHex();
		expect(rebuilt).to.equal(signedTx);

		// ...while a rebuild after the OLD unconditional rollback (staged rate
		// stripped) would produce a DIFFERENT tx, i.e. an invalid witness.
		const rolledBack = {
			...state,
			pendingFeeratePerKw: undefined,
			lastSignedCommitFeeratePerKw: undefined
		};
		const wrong = buildLocalCommitment(rolledBack, point).result.tx.toHex();
		expect(wrong).to.not.equal(signedTx);
	});

	it('opener promotion cannot desync the force-close rebuild (finding #3 window)', function () {
		// Opener-side mirror: after the peer's revoke_and_ack the opener
		// promotes the staged rate into localConfig although its OWN local
		// commitment is still signed at the old rate. The signedLocal rebuild
		// must keep using the old rate until a new commitment_signed arrives.
		const state = createOpenerState({
			temporaryChannelId: crypto.randomBytes(32),
			fundingSatoshis: 1_000_000n,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG, feeratePerKw: OLD_RATE },
			localBasepoints: makeBasepoints(localSeed),
			localPerCommitmentSeed: localSeed
		});
		state.channelId = crypto.randomBytes(32);
		state.state = ChannelState.NORMAL;
		state.fundingTxid = crypto.randomBytes(32);
		state.remoteBasepoints = makeBasepoints(remoteSeed);
		state.remoteConfig = { ...DEFAULT_CHANNEL_CONFIG };
		state.localBalanceMsat = 600_000_000n;
		state.remoteBalanceMsat = 400_000_000n;
		// Our current local commitment was signed at the OLD rate.
		state.lastSignedCommitFeeratePerKw = OLD_RATE;
		state.remoteCommitmentSignature = crypto.randomBytes(64);

		const point = getPerCommitmentPoint(localSeed, 0n);
		const signedTx = buildLocalCommitment(
			state,
			point,
			undefined,
			true
		).result.tx.toHex();

		// Simulate the handleRevokeAndAck promotion.
		state.localConfig.feeratePerKw = NEW_RATE;
		state.pendingFeeratePerKw = undefined;

		expect(getCommitmentFeeRate(state)).to.equal(NEW_RATE);
		expect(getCommitmentFeeRate(state, true)).to.equal(OLD_RATE);
		const rebuilt = buildLocalCommitment(
			state,
			point,
			undefined,
			true
		).result.tx.toHex();
		expect(rebuilt).to.equal(signedTx);
	});

	it('persists pendingFeeratePerKw and lastSignedCommitFeeratePerKw across restart', function () {
		const channel = makeNormalAcceptorChannel();
		const state = channel.getFullState();

		channel.handleUpdateFee({
			channelId: state.channelId!,
			feeratePerKw: NEW_RATE
		});
		channel.handleCommitmentSigned({
			channelId: state.channelId!,
			signature: crypto.randomBytes(64),
			htlcSignatures: []
		});

		const restored = deserializeChannelState(
			JSON.parse(JSON.stringify(serializeChannelState(state)))
		);

		expect(restored.pendingFeeratePerKw).to.equal(NEW_RATE);
		expect(restored.lastSignedCommitFeeratePerKw).to.equal(NEW_RATE);

		// And the restored state rebuilds the signed commitment identically.
		const point = getPerCommitmentPoint(localSeed, 1n);
		const before = buildLocalCommitment(
			state,
			point,
			undefined,
			true
		).result.tx.toHex();
		const after = buildLocalCommitment(
			restored,
			point,
			undefined,
			true
		).result.tx.toHex();
		expect(after).to.equal(before);
	});
});
