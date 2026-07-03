/**
 * Regression: second-level HTLC signature metadata must be indexed in the SAME
 * trimmed basis as the commitment outputs.
 *
 * buildCommitmentTx enumerates only the UNTRIMMED HTLCs and records
 * htlcOriginalIndices as positions in that FILTERED array. The signing/
 * verification paths previously dereferenced those indices into a freshly
 * rebuilt UNFILTERED metadata list. Because Array.filter compacts positions,
 * a trimmed (dust) HTLC ordered BEFORE a surviving one shifts every later
 * index by one, so the counterparty HTLC-success/timeout signature was
 * computed over the WRONG HTLC's amount/script/cltv/hash. Both beignet peers
 * mis-bind identically, so sign+verify agree with each other (they are both
 * wrong) and the corrupt signature is persisted; on force-close the
 * second-level tx is consensus-invalid and the surviving HTLC is unsweepable.
 *
 * These tests order the DUST HTLC FIRST and bind the produced signature to the
 * SURVIVING output's REAL second-level transaction (reconstructed from the
 * survivor's known parameters) — not merely to whatever the signer used, which
 * self-agrees even when wrong. The existing "mixed set" test in
 * htlc-signing.test.ts inserts the dust HTLC LAST, which hides the defect.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import {
	deriveCommitmentKeys,
	buildRemoteCommitment,
	signRemoteCommitment,
	signRemoteHtlcSignaturesTaproot
} from '../../src/lightning/channel/commitment-builder';
import {
	createOpenerState,
	createAcceptorState
} from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	HtlcDirection,
	HtlcState
} from '../../src/lightning/channel/types';
import {
	IChannelBasepoints,
	perCommitmentPointFromSecret,
	derivePublicKey
} from '../../src/lightning/keys/derivation';
import { ChannelSigner } from '../../src/lightning/keys/signer';
import { getPublicKey, verify } from '../../src/lightning/crypto/ecdh';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import { deriveChannelId } from '../../src/lightning/channel/validation';
import { buildReceivedHtlcScript } from '../../src/lightning/script/htlc';
import { buildHtlcSuccessTx } from '../../src/lightning/script/htlc';
import { buildTaprootReceivedHtlcOutput } from '../../src/lightning/script/commitment-taproot';
import {
	buildTaprootHtlcSuccessTx,
	taprootHtlcLeafSighash,
	verifyTaprootHtlcLeaf
} from '../../src/lightning/script/htlc-taproot';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';

bitcoin.initEccLib(ecc);

const HTLC_SUCCESS_WEIGHT = 703;

function makeSeed(id: number): Buffer {
	return crypto.createHash('sha256').update(`trim-sig-${id}`).digest();
}
function getPrivkey(seed: Buffer, index: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([index]))
		.digest();
}
function makeBasepoints(seed: Buffer): IChannelBasepoints {
	return {
		fundingPubkey: getPublicKey(getPrivkey(seed, 0)),
		revocationBasepoint: getPublicKey(getPrivkey(seed, 1)),
		paymentBasepoint: getPublicKey(getPrivkey(seed, 2)),
		delayedPaymentBasepoint: getPublicKey(getPrivkey(seed, 3)),
		htlcBasepoint: getPublicKey(getPrivkey(seed, 4)),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}
function getPerCommitmentPoint(seed: Buffer, n: bigint): Buffer {
	return perCommitmentPointFromSecret(generateFromSeed(seed, MAX_INDEX - n));
}

function createReadyState() {
	const openerSeed = makeSeed(1);
	const acceptorSeed = makeSeed(2);
	const openerCommitSeed = makeSeed(3);
	const acceptorCommitSeed = makeSeed(4);
	const openerBasepoints = makeBasepoints(openerSeed);
	const acceptorBasepoints = makeBasepoints(acceptorSeed);
	openerBasepoints.firstPerCommitmentPoint = getPerCommitmentPoint(
		openerCommitSeed,
		0n
	);
	acceptorBasepoints.firstPerCommitmentPoint = getPerCommitmentPoint(
		acceptorCommitSeed,
		0n
	);
	const fundingTxid = crypto.createHash('sha256').update('funding').digest();
	const channelId = deriveChannelId(fundingTxid, 0);
	const fundingSatoshis = 1_000_000n;

	const openerState = createOpenerState({
		temporaryChannelId: crypto.randomBytes(32),
		fundingSatoshis,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: openerBasepoints,
		localPerCommitmentSeed: openerCommitSeed
	});
	openerState.remoteBasepoints = acceptorBasepoints;
	openerState.remoteConfig = { ...DEFAULT_CHANNEL_CONFIG };
	openerState.fundingTxid = fundingTxid;
	openerState.fundingOutputIndex = 0;
	openerState.channelId = channelId;
	openerState.state = ChannelState.NORMAL;
	openerState.remoteCurrentPerCommitmentPoint =
		acceptorBasepoints.firstPerCommitmentPoint;

	const acceptorState = createAcceptorState({
		temporaryChannelId: openerState.temporaryChannelId,
		fundingSatoshis,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: acceptorBasepoints,
		localPerCommitmentSeed: acceptorCommitSeed,
		remoteBasepoints: openerBasepoints,
		remoteConfig: { ...DEFAULT_CHANNEL_CONFIG }
	});
	acceptorState.fundingTxid = fundingTxid;
	acceptorState.fundingOutputIndex = 0;
	acceptorState.channelId = channelId;
	acceptorState.state = ChannelState.NORMAL;
	acceptorState.remoteCurrentPerCommitmentPoint =
		openerBasepoints.firstPerCommitmentPoint;

	return { openerState, acceptorState, openerSeed, acceptorCommitSeed };
}

function taprootType(): Buffer {
	const f = FeatureFlags.empty();
	f.setCompulsory(Feature.STATIC_REMOTE_KEY);
	f.setCompulsory(Feature.ANCHOR_ZERO_FEE_HTLC);
	f.setCompulsory(Feature.OPTION_TAPROOT);
	return f.toBuffer();
}

// A clearly-dust HTLC (below any dust limit) and a large surviving one.
const DUST_MSAT = 200_000n; // 200 sat
const SURVIVOR_MSAT = 50_000_000n; // 50,000 sat
const DUST_HASH = crypto.createHash('sha256').update('dust-hash').digest();
const SURVIVOR_HASH = crypto
	.createHash('sha256')
	.update('survivor-hash')
	.digest();
const DUST_CLTV = 500_100;
const SURVIVOR_CLTV = 500_000;

/** Insert the DUST HTLC FIRST, then the surviving one (both offered by us). */
function addTrimmedThenSurviving(
	state: ReturnType<typeof createReadyState>['openerState']
): void {
	state.localBalanceMsat = 900_000_000n;
	state.remoteBalanceMsat = 100_000_000n;
	state.htlcs.set('offered-0', {
		id: 0n,
		amountMsat: DUST_MSAT,
		paymentHash: DUST_HASH,
		cltvExpiry: DUST_CLTV,
		onionRoutingPacket: Buffer.alloc(1366),
		direction: HtlcDirection.OFFERED,
		state: HtlcState.COMMITTED
	});
	state.htlcs.set('offered-1', {
		id: 1n,
		amountMsat: SURVIVOR_MSAT,
		paymentHash: SURVIVOR_HASH,
		cltvExpiry: SURVIVOR_CLTV,
		onionRoutingPacket: Buffer.alloc(1366),
		direction: HtlcDirection.OFFERED,
		state: HtlcState.COMMITTED
	});
	state.localBalanceMsat -= DUST_MSAT + SURVIVOR_MSAT;
}

describe('trimmed HTLC ordered first: signature binds to the surviving output', function () {
	it('ECDSA: the counterparty HTLC-success signature verifies against the SURVIVING output', function () {
		const { openerState, openerSeed } = createReadyState();
		addTrimmedThenSurviving(openerState);

		const signer = new ChannelSigner(
			getPrivkey(openerSeed, 0),
			getPrivkey(openerSeed, 4)
		);
		const remotePoint = openerState.remoteCurrentPerCommitmentPoint!;
		const { htlcSignatures } = signRemoteCommitment(
			openerState,
			signer,
			remotePoint
		);
		// Exactly one untrimmed HTLC → one signature.
		expect(htlcSignatures).to.have.length(1);

		// Independently reconstruct the SURVIVING HTLC's real second-level
		// tx + sighash and verify the produced signature binds to IT (not to
		// the trimmed dust HTLC's amount/script/cltv/hash).
		const built = buildRemoteCommitment(openerState, remotePoint);
		const commitTxid = built.result.tx.getId();
		const outputIndex = built.result.outputMap.htlcs[0];
		const keys = deriveCommitmentKeys(
			openerState.localBasepoints,
			openerState.remoteBasepoints!,
			remotePoint,
			false
		);
		const useAnchors = false; // default (non-anchor) channel
		const feeratePerKw = openerState.localConfig.feeratePerKw;
		const fee = BigInt(Math.floor((HTLC_SUCCESS_WEIGHT * feeratePerKw) / 1000));
		// Our offered = their received → HTLC-success second-level tx.
		const survivorScript = buildReceivedHtlcScript(
			keys.revocationPubkey,
			keys.localHtlcPubkey,
			keys.remoteHtlcPubkey,
			SURVIVOR_HASH,
			SURVIVOR_CLTV,
			useAnchors
		);
		const survivorAmountSat = SURVIVOR_MSAT / 1000n;
		const survivorTx = buildHtlcSuccessTx(
			commitTxid,
			outputIndex,
			survivorAmountSat,
			keys.revocationPubkey,
			keys.localDelayedPubkey,
			openerState.localConfig.toSelfDelay,
			fee,
			useAnchors
		);
		const sighash = survivorTx.hashForWitnessV0(
			0,
			survivorScript,
			Number(survivorAmountSat),
			bitcoin.Transaction.SIGHASH_ALL
		);
		// Our HTLC pubkey on the remote commitment (what localHtlcPrivkey signs
		// with) is derivePublicKey(localHtlcBasepoint, remotePoint).
		const ourHtlcPubkey = derivePublicKey(
			openerState.localBasepoints.htlcBasepoint,
			remotePoint
		);
		expect(
			verify(sighash, ourHtlcPubkey, htlcSignatures[0]),
			'HTLC signature must bind to the surviving output, not the trimmed one'
		).to.equal(true);

		// And it must NOT verify against the trimmed HTLC's second-level tx
		// (proves the signature moved to the correct output).
		const dustScript = buildReceivedHtlcScript(
			keys.revocationPubkey,
			keys.localHtlcPubkey,
			keys.remoteHtlcPubkey,
			DUST_HASH,
			DUST_CLTV,
			useAnchors
		);
		const dustTx = buildHtlcSuccessTx(
			commitTxid,
			outputIndex,
			DUST_MSAT / 1000n,
			keys.revocationPubkey,
			keys.localDelayedPubkey,
			openerState.localConfig.toSelfDelay,
			fee,
			useAnchors
		);
		const dustSighash = dustTx.hashForWitnessV0(
			0,
			dustScript,
			Number(DUST_MSAT / 1000n),
			bitcoin.Transaction.SIGHASH_ALL
		);
		expect(verify(dustSighash, ourHtlcPubkey, htlcSignatures[0])).to.equal(
			false
		);
	});

	it('taproot: the Schnorr HTLC-success signature verifies against the SURVIVING output', function () {
		const { openerState, openerSeed, acceptorCommitSeed } = createReadyState();
		openerState.channelType = taprootType();
		addTrimmedThenSurviving(openerState);

		const signer = new ChannelSigner(
			getPrivkey(openerSeed, 0),
			getPrivkey(openerSeed, 4)
		);
		// Sign the acceptor's commitment #1; align the point with its number.
		const acceptorPoint1 = getPerCommitmentPoint(acceptorCommitSeed, 1n);
		const sigs = signRemoteHtlcSignaturesTaproot(
			openerState,
			signer,
			acceptorPoint1,
			1n
		);
		expect(sigs).to.have.length(1);

		const built = buildRemoteCommitment(openerState, acceptorPoint1, 1n);
		const commitTxid = built.result.tx.getId();
		const outputIndex = built.result.outputMap.htlcs[0];
		const keys = deriveCommitmentKeys(
			openerState.localBasepoints,
			openerState.remoteBasepoints!,
			acceptorPoint1,
			false
		);
		// Our offered = their received → success leaf of the received output.
		const survivorOut = buildTaprootReceivedHtlcOutput(
			keys.revocationPubkey,
			keys.localHtlcPubkey,
			keys.remoteHtlcPubkey,
			SURVIVOR_HASH,
			SURVIVOR_CLTV
		);
		const survivorAmountSat = SURVIVOR_MSAT / 1000n;
		const survivorTx = buildTaprootHtlcSuccessTx(
			commitTxid,
			outputIndex,
			survivorAmountSat,
			keys.revocationPubkey,
			keys.localDelayedPubkey,
			openerState.localConfig.toSelfDelay
		);
		const sighash = taprootHtlcLeafSighash(
			survivorTx,
			survivorOut.output,
			Number(survivorAmountSat),
			survivorOut.success.script,
			survivorOut.success.leafVersion
		);
		const ourHtlcPubkey = derivePublicKey(
			openerState.localBasepoints.htlcBasepoint,
			acceptorPoint1
		);
		expect(
			verifyTaprootHtlcLeaf(sighash, ourHtlcPubkey, sigs[0]),
			'taproot HTLC signature must bind to the surviving output'
		).to.equal(true);

		// Must NOT verify against the trimmed HTLC's leaf.
		const dustOut = buildTaprootReceivedHtlcOutput(
			keys.revocationPubkey,
			keys.localHtlcPubkey,
			keys.remoteHtlcPubkey,
			DUST_HASH,
			DUST_CLTV
		);
		const dustTx = buildTaprootHtlcSuccessTx(
			commitTxid,
			outputIndex,
			DUST_MSAT / 1000n,
			keys.revocationPubkey,
			keys.localDelayedPubkey,
			openerState.localConfig.toSelfDelay
		);
		const dustSighash = taprootHtlcLeafSighash(
			dustTx,
			dustOut.output,
			Number(DUST_MSAT / 1000n),
			dustOut.success.script,
			dustOut.success.leafVersion
		);
		expect(verifyTaprootHtlcLeaf(dustSighash, ourHtlcPubkey, sigs[0])).to.equal(
			false
		);
	});
});
