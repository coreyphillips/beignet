/**
 * Anchor Channels (option_anchors_zero_fee_htlc_tx) tests.
 *
 * Verifies:
 * - isAnchorChannel() detection utility
 * - Commitment builder anchor wiring (weights, fees, 660-sat deduction, anchor outputs)
 * - Signer anchor sighash (SIGHASH_SINGLE|SIGHASH_ANYONECANPAY)
 * - Channel negotiation with anchor channel_type
 * - Node config wiring for preferAnchors
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import {
	isAnchorChannel,
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	HtlcDirection,
	HtlcState
} from '../../src/lightning/channel/types';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';
import {
	buildLocalCommitment,
	buildRemoteCommitment,
	signRemoteCommitment
} from '../../src/lightning/channel/commitment-builder';
import {
	createOpenerState,
	createAcceptorState
} from '../../src/lightning/channel/channel-state';
import {
	IChannelBasepoints,
	perCommitmentPointFromSecret
} from '../../src/lightning/keys/derivation';
import { ChannelSigner } from '../../src/lightning/keys/signer';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import { deriveChannelId } from '../../src/lightning/channel/validation';
import { Channel } from '../../src/lightning/channel/channel';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	ANCHOR_OUTPUT_VALUE,
	ANCHOR_TOTAL_COST,
	buildToRemoteAnchorOutput
} from '../../src/lightning/script/anchor';
import { Network } from '../../src/lightning/invoice/types';
import {
	classifyOutputs,
	resolveTheirCurrentCommitmentOutputs
} from '../../src/lightning/chain/output-resolver';
import {
	CommitmentType,
	OutputType,
	OutputStatus,
	ITrackedOutput
} from '../../src/lightning/chain/types';

bitcoin.initEccLib(ecc);

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`anchor-seed-${id}`))
		.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		const privkey = crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([i]))
			.digest();
		keys.push(privkey);
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

function getFundingPrivkey(seed: Buffer): Buffer {
	return crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([0]))
		.digest();
}

function getHtlcBasepointSecret(seed: Buffer): Buffer {
	return crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([4]))
		.digest();
}

function getPerCommitmentPoint(seed: Buffer, commitmentNumber: bigint): Buffer {
	const index = MAX_INDEX - commitmentNumber;
	const secret = generateFromSeed(seed, index);
	return perCommitmentPointFromSecret(secret);
}

function makeAnchorChannelType(): Buffer {
	const flags = FeatureFlags.empty();
	flags.setCompulsory(Feature.STATIC_REMOTE_KEY);
	flags.setCompulsory(Feature.ANCHOR_ZERO_FEE_HTLC);
	return flags.toBuffer();
}

function makeStaticRemotekeyChannelType(): Buffer {
	const flags = FeatureFlags.empty();
	flags.setCompulsory(Feature.STATIC_REMOTE_KEY);
	return flags.toBuffer();
}

function createReadyAnchorState() {
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

	const fundingTxid = crypto
		.createHash('sha256')
		.update(Buffer.from('anchor-funding-tx'))
		.digest();
	const fundingOutputIndex = 0;
	const channelId = deriveChannelId(fundingTxid, fundingOutputIndex);

	const fundingSatoshis = 1_000_000n;
	const pushMsat = 200_000_000n; // 200k sats pushed to acceptor

	const openerState = createOpenerState({
		temporaryChannelId: crypto.randomBytes(32),
		fundingSatoshis,
		pushMsat,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: openerBasepoints,
		localPerCommitmentSeed: openerCommitSeed
	});

	openerState.remoteBasepoints = acceptorBasepoints;
	openerState.remoteConfig = { ...DEFAULT_CHANNEL_CONFIG };
	openerState.fundingTxid = fundingTxid;
	openerState.fundingOutputIndex = fundingOutputIndex;
	openerState.channelId = channelId;
	openerState.state = ChannelState.NORMAL;
	openerState.remoteCurrentPerCommitmentPoint =
		acceptorBasepoints.firstPerCommitmentPoint;
	openerState.channelType = makeAnchorChannelType();

	const acceptorState = createAcceptorState({
		temporaryChannelId: openerState.temporaryChannelId,
		fundingSatoshis,
		pushMsat,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: acceptorBasepoints,
		localPerCommitmentSeed: acceptorCommitSeed,
		remoteBasepoints: openerBasepoints,
		remoteConfig: { ...DEFAULT_CHANNEL_CONFIG }
	});

	acceptorState.fundingTxid = fundingTxid;
	acceptorState.fundingOutputIndex = fundingOutputIndex;
	acceptorState.channelId = channelId;
	acceptorState.state = ChannelState.NORMAL;
	acceptorState.remoteCurrentPerCommitmentPoint =
		openerBasepoints.firstPerCommitmentPoint;
	acceptorState.channelType = makeAnchorChannelType();

	return {
		openerState,
		acceptorState,
		openerSeed,
		acceptorSeed,
		openerCommitSeed,
		acceptorCommitSeed,
		fundingTxid
	};
}

// Same factory without anchors for regression testing
function createReadyNonAnchorState() {
	const result = createReadyAnchorState();
	result.openerState.channelType = makeStaticRemotekeyChannelType();
	result.acceptorState.channelType = makeStaticRemotekeyChannelType();
	return result;
}

describe('Anchor Channels (option_anchors_zero_fee_htlc_tx)', function () {
	// ─── isAnchorChannel() ───

	describe('isAnchorChannel()', function () {
		it('should return false for null', function () {
			expect(isAnchorChannel(null)).to.be.false;
		});

		it('should return false for empty buffer', function () {
			expect(isAnchorChannel(Buffer.alloc(0))).to.be.false;
		});

		it('should return false for static_remotekey only', function () {
			const flags = FeatureFlags.empty();
			flags.setCompulsory(Feature.STATIC_REMOTE_KEY);
			expect(isAnchorChannel(flags.toBuffer())).to.be.false;
		});

		it('should return true when bit 22 is set (compulsory)', function () {
			const flags = FeatureFlags.empty();
			flags.setCompulsory(Feature.STATIC_REMOTE_KEY);
			flags.setCompulsory(Feature.ANCHOR_ZERO_FEE_HTLC);
			expect(isAnchorChannel(flags.toBuffer())).to.be.true;
		});

		it('should return true when bit 23 is set (optional)', function () {
			const flags = FeatureFlags.empty();
			flags.setCompulsory(Feature.STATIC_REMOTE_KEY);
			flags.setOptional(Feature.ANCHOR_ZERO_FEE_HTLC);
			expect(isAnchorChannel(flags.toBuffer())).to.be.true;
		});

		it('should return true with combined bits', function () {
			const flags = FeatureFlags.empty();
			flags.setCompulsory(Feature.STATIC_REMOTE_KEY);
			flags.setCompulsory(Feature.ANCHOR_ZERO_FEE_HTLC);
			flags.setOptional(Feature.BASIC_MPP);
			expect(isAnchorChannel(flags.toBuffer())).to.be.true;
		});

		it('should return false for ANCHOR_OUTPUTS (bit 20) without ANCHOR_ZERO_FEE_HTLC', function () {
			const flags = FeatureFlags.empty();
			flags.setCompulsory(Feature.STATIC_REMOTE_KEY);
			flags.setCompulsory(Feature.ANCHOR_OUTPUTS);
			expect(isAnchorChannel(flags.toBuffer())).to.be.false;
		});
	});

	// ─── Commitment Builder Anchor Wiring ───

	describe('Commitment Builder with Anchors', function () {
		it('should produce commitment with 4 outputs (to_local + to_remote + 2 anchors)', function () {
			const { openerState, openerCommitSeed } = createReadyAnchorState();
			const perCommitPoint = getPerCommitmentPoint(openerCommitSeed, 0n);

			const built = buildLocalCommitment(openerState, perCommitPoint);

			// to_local + to_remote + local_anchor + remote_anchor = 4 outputs
			expect(built.result.tx.outs.length).to.equal(4);

			// Check anchor output values (330 sats each)
			const anchorOuts = built.result.tx.outs.filter(
				(o) => o.value === Number(ANCHOR_OUTPUT_VALUE)
			);
			expect(anchorOuts.length).to.equal(2);
		});

		it('should have P2WSH to_remote (34-byte script) for anchor channels', function () {
			const { openerState, openerCommitSeed } = createReadyAnchorState();
			const perCommitPoint = getPerCommitmentPoint(openerCommitSeed, 0n);

			const built = buildLocalCommitment(openerState, perCommitPoint);

			// to_remote with anchors is P2WSH (34 bytes), not P2WPKH (22 bytes)
			const toRemoteIdx = built.result.outputMap.toRemote;
			expect(toRemoteIdx).to.not.be.undefined;
			const toRemoteScript = built.result.tx.outs[toRemoteIdx!].script;
			// P2WSH: OP_0 <32-byte hash> = 34 bytes
			expect(toRemoteScript.length).to.equal(34);
		});

		it('should deduct 660 sats from opener balance for anchor outputs', function () {
			const anchorResult = createReadyAnchorState();
			const nonAnchorResult = createReadyNonAnchorState();

			const anchorPerCommit = getPerCommitmentPoint(
				anchorResult.openerCommitSeed,
				0n
			);
			const nonAnchorPerCommit = getPerCommitmentPoint(
				nonAnchorResult.openerCommitSeed,
				0n
			);

			const anchorBuilt = buildLocalCommitment(
				anchorResult.openerState,
				anchorPerCommit
			);
			const nonAnchorBuilt = buildLocalCommitment(
				nonAnchorResult.openerState,
				nonAnchorPerCommit
			);

			// Get to_local amounts (opener's balance)
			const anchorToLocal =
				anchorBuilt.result.tx.outs[anchorBuilt.result.outputMap.toLocal!].value;
			const nonAnchorToLocal =
				nonAnchorBuilt.result.tx.outs[nonAnchorBuilt.result.outputMap.toLocal!]
					.value;

			// Anchor to_local should be smaller due to:
			// 1. Higher base weight (1124 vs 724) → higher fee
			// 2. 660 sat anchor deduction
			expect(anchorToLocal).to.be.lessThan(nonAnchorToLocal);

			// The difference should include the 660 sat anchor cost
			const feeDiff = nonAnchorToLocal - anchorToLocal;
			expect(feeDiff).to.be.greaterThan(Number(ANCHOR_TOTAL_COST) - 1);
		});

		it('should use anchor base weight (1124) for fee calculation', function () {
			const { openerState, openerCommitSeed } = createReadyAnchorState();
			const perCommitPoint = getPerCommitmentPoint(openerCommitSeed, 0n);

			const built = buildLocalCommitment(openerState, perCommitPoint);

			// Calculate expected fee with anchor weight
			const feeRate = openerState.localConfig.feeratePerKw;
			const expectedFee = Math.floor((1124 * feeRate) / 1000);

			// Total in should equal total out + fee
			const totalOut = built.result.tx.outs.reduce(
				(sum, o) => sum + o.value,
				0
			);
			const totalIn = Number(openerState.fundingSatoshis);
			const actualFee = totalIn - totalOut;

			expect(actualFee).to.equal(expectedFee);
		});

		it('should not affect non-anchor commitments (backward compat)', function () {
			const { openerState, openerCommitSeed } = createReadyNonAnchorState();
			const perCommitPoint = getPerCommitmentPoint(openerCommitSeed, 0n);

			const built = buildLocalCommitment(openerState, perCommitPoint);

			// Non-anchor: 2 outputs (to_local + to_remote), no anchors
			expect(built.result.tx.outs.length).to.equal(2);

			// to_remote is P2WPKH (22 bytes)
			const toRemoteIdx = built.result.outputMap.toRemote;
			expect(toRemoteIdx).to.not.be.undefined;
			const toRemoteScript = built.result.tx.outs[toRemoteIdx!].script;
			expect(toRemoteScript.length).to.equal(22);

			// No anchor outputs
			const anchorOuts = built.result.tx.outs.filter(
				(o) => o.value === Number(ANCHOR_OUTPUT_VALUE)
			);
			expect(anchorOuts.length).to.equal(0);
		});

		it('should build remote commitment with anchor outputs', function () {
			const { openerState, acceptorCommitSeed } = createReadyAnchorState();
			const remotePerCommit = getPerCommitmentPoint(acceptorCommitSeed, 0n);

			const built = buildRemoteCommitment(openerState, remotePerCommit);

			// 4 outputs: to_local + to_remote + 2 anchors
			// (only to_local because acceptor has 0 balance → to_remote may be dust)
			// Actually opener has all funds, so on remote commitment:
			// to_local = remote's balance (0), to_remote = opener's balance (big)
			// to_local below dust → trimmed, so: to_remote + 2 anchors = 3 outputs
			expect(built.result.tx.outs.length).to.be.greaterThanOrEqual(3);

			const anchorOuts = built.result.tx.outs.filter(
				(o) => o.value === Number(ANCHOR_OUTPUT_VALUE)
			);
			expect(anchorOuts.length).to.equal(2);
		});

		it('should handle anchor commitment with HTLCs', function () {
			const { openerState, openerCommitSeed } = createReadyAnchorState();

			// Add an HTLC
			const paymentHash = crypto
				.createHash('sha256')
				.update(crypto.randomBytes(32))
				.digest();

			openerState.htlcs.set('offered-0', {
				id: 0n,
				amountMsat: 50_000_000n, // 50k sats
				paymentHash,
				cltvExpiry: 500,
				onionRoutingPacket: Buffer.alloc(1366),
				direction: HtlcDirection.OFFERED,
				state: HtlcState.COMMITTED
			});

			const perCommitPoint = getPerCommitmentPoint(openerCommitSeed, 0n);
			const built = buildLocalCommitment(openerState, perCommitPoint);

			// to_local + to_remote + HTLC + 2 anchors = 5 outputs
			expect(built.result.tx.outs.length).to.equal(5);
			expect(built.result.outputMap.htlcs.length).to.equal(1);
		});
	});

	// ─── Signer Anchor Sighash ───

	describe('Signer Anchor Sighash', function () {
		it('should produce different signatures with anchor vs non-anchor sighash', function () {
			const privkey = crypto.randomBytes(32);
			const htlcPrivkey = crypto.randomBytes(32);
			const signer = new ChannelSigner(privkey, htlcPrivkey);

			// Create a minimal tx to sign
			const tx = new bitcoin.Transaction();
			tx.version = 2;
			tx.addInput(Buffer.alloc(32), 0, 0x80000001);
			tx.addOutput(Buffer.alloc(22), 10000);

			const witnessScript = Buffer.from('0020' + '00'.repeat(32), 'hex');
			const amount = 50000;

			const sigAll = signer.signHtlcTx(
				tx,
				witnessScript,
				amount,
				htlcPrivkey,
				false
			);
			const sigAnchor = signer.signHtlcTx(
				tx,
				witnessScript,
				amount,
				htlcPrivkey,
				true
			);

			// Both should be 64 bytes
			expect(sigAll.length).to.equal(64);
			expect(sigAnchor.length).to.equal(64);

			// Signatures must differ (different sighash types)
			expect(sigAll.equals(sigAnchor)).to.be.false;
		});

		it('should default to SIGHASH_ALL when useAnchorSighash is undefined', function () {
			const privkey = crypto.randomBytes(32);
			const htlcPrivkey = crypto.randomBytes(32);
			const signer = new ChannelSigner(privkey, htlcPrivkey);

			const tx = new bitcoin.Transaction();
			tx.version = 2;
			tx.addInput(Buffer.alloc(32), 0, 0x80000001);
			tx.addOutput(Buffer.alloc(22), 10000);

			const witnessScript = Buffer.from('0020' + '00'.repeat(32), 'hex');
			const amount = 50000;

			const sigDefault = signer.signHtlcTx(
				tx,
				witnessScript,
				amount,
				htlcPrivkey
			);
			const sigExplicit = signer.signHtlcTx(
				tx,
				witnessScript,
				amount,
				htlcPrivkey,
				false
			);

			// Should produce the same signature (both SIGHASH_ALL)
			expect(sigDefault.equals(sigExplicit)).to.be.true;
		});
	});

	// ─── signRemoteCommitment with Anchors ───

	describe('signRemoteCommitment with Anchors', function () {
		it('should sign HTLC txs with anchor sighash for anchor channels', function () {
			const { openerState, openerSeed, acceptorCommitSeed } =
				createReadyAnchorState();

			// Add an HTLC so we get HTLC signatures
			const paymentHash = crypto
				.createHash('sha256')
				.update(crypto.randomBytes(32))
				.digest();

			openerState.htlcs.set('offered-0', {
				id: 0n,
				amountMsat: 50_000_000n,
				paymentHash,
				cltvExpiry: 500,
				onionRoutingPacket: Buffer.alloc(1366),
				direction: HtlcDirection.OFFERED,
				state: HtlcState.COMMITTED
			});

			const fundingPrivkey = getFundingPrivkey(openerSeed);
			const htlcSecret = getHtlcBasepointSecret(openerSeed);
			const signer = new ChannelSigner(fundingPrivkey, htlcSecret);

			const remotePerCommit = getPerCommitmentPoint(acceptorCommitSeed, 0n);
			const result = signRemoteCommitment(openerState, signer, remotePerCommit);

			expect(result.signature.length).to.equal(64);
			expect(result.htlcSignatures.length).to.equal(1);
			expect(result.htlcSignatures[0].length).to.equal(64);
		});

		it('should produce different HTLC sigs for anchor vs non-anchor', function () {
			const anchorData = createReadyAnchorState();
			const nonAnchorData = createReadyNonAnchorState();

			const paymentHash = crypto
				.createHash('sha256')
				.update(Buffer.from('test-payment'))
				.digest();

			const htlcEntry = {
				id: 0n,
				amountMsat: 50_000_000n,
				paymentHash,
				cltvExpiry: 500,
				onionRoutingPacket: Buffer.alloc(1366),
				direction: HtlcDirection.OFFERED as const,
				state: HtlcState.COMMITTED as const
			};

			anchorData.openerState.htlcs.set('offered-0', { ...htlcEntry });
			nonAnchorData.openerState.htlcs.set('offered-0', { ...htlcEntry });

			const anchorSigner = new ChannelSigner(
				getFundingPrivkey(anchorData.openerSeed),
				getHtlcBasepointSecret(anchorData.openerSeed)
			);
			const nonAnchorSigner = new ChannelSigner(
				getFundingPrivkey(nonAnchorData.openerSeed),
				getHtlcBasepointSecret(nonAnchorData.openerSeed)
			);

			const anchorPerCommit = getPerCommitmentPoint(
				anchorData.acceptorCommitSeed,
				0n
			);
			const nonAnchorPerCommit = getPerCommitmentPoint(
				nonAnchorData.acceptorCommitSeed,
				0n
			);

			const anchorResult = signRemoteCommitment(
				anchorData.openerState,
				anchorSigner,
				anchorPerCommit
			);
			const nonAnchorResult = signRemoteCommitment(
				nonAnchorData.openerState,
				nonAnchorSigner,
				nonAnchorPerCommit
			);

			// HTLC signatures should differ due to different sighash types and zero-fee
			expect(
				anchorResult.htlcSignatures[0].equals(nonAnchorResult.htlcSignatures[0])
			).to.be.false;
		});
	});

	// ─── Channel Negotiation ───

	describe('Channel Negotiation with Anchors', function () {
		it('should include ANCHOR_ZERO_FEE_HTLC in channel_type when preferAnchors=true', function () {
			const seed = makeSeed(10);
			const basepoints = makeBasepoints(seed);
			const commitSeed = makeSeed(11);
			basepoints.firstPerCommitmentPoint = getPerCommitmentPoint(
				commitSeed,
				0n
			);

			const state = createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 500_000n,
				pushMsat: 0n,
				localConfig: { ...DEFAULT_CHANNEL_CONFIG },
				localBasepoints: basepoints,
				localPerCommitmentSeed: commitSeed
			});

			const channel = new Channel(state);
			const actions = channel.initiateOpen(undefined, true);

			// Should produce a send_message action
			expect(actions.length).to.be.greaterThan(0);

			// Channel state should have anchor channel_type
			const fullState = channel.getFullState();
			expect(isAnchorChannel(fullState.channelType)).to.be.true;

			// Verify both bits are set
			const flags = FeatureFlags.fromBuffer(fullState.channelType!);
			expect(flags.hasFeature(Feature.STATIC_REMOTE_KEY)).to.be.true;
			expect(flags.hasFeature(Feature.ANCHOR_ZERO_FEE_HTLC)).to.be.true;
		});

		it('should only include STATIC_REMOTE_KEY when preferAnchors=false', function () {
			const seed = makeSeed(12);
			const basepoints = makeBasepoints(seed);
			const commitSeed = makeSeed(13);
			basepoints.firstPerCommitmentPoint = getPerCommitmentPoint(
				commitSeed,
				0n
			);

			const state = createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 500_000n,
				pushMsat: 0n,
				localConfig: { ...DEFAULT_CHANNEL_CONFIG },
				localBasepoints: basepoints,
				localPerCommitmentSeed: commitSeed
			});

			const channel = new Channel(state);
			channel.initiateOpen(undefined, false);

			const fullState = channel.getFullState();
			expect(isAnchorChannel(fullState.channelType)).to.be.false;

			const flags = FeatureFlags.fromBuffer(fullState.channelType!);
			expect(flags.hasFeature(Feature.STATIC_REMOTE_KEY)).to.be.true;
			expect(flags.hasFeature(Feature.ANCHOR_ZERO_FEE_HTLC)).to.be.false;
		});

		it('should only include STATIC_REMOTE_KEY by default (no preferAnchors)', function () {
			const seed = makeSeed(14);
			const basepoints = makeBasepoints(seed);
			const commitSeed = makeSeed(15);
			basepoints.firstPerCommitmentPoint = getPerCommitmentPoint(
				commitSeed,
				0n
			);

			const state = createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 500_000n,
				pushMsat: 0n,
				localConfig: { ...DEFAULT_CHANNEL_CONFIG },
				localBasepoints: basepoints,
				localPerCommitmentSeed: commitSeed
			});

			const channel = new Channel(state);
			channel.initiateOpen();

			const fullState = channel.getFullState();
			expect(isAnchorChannel(fullState.channelType)).to.be.false;
		});
	});

	// ─── ChannelManager preferAnchors Wiring ───

	describe('ChannelManager preferAnchors', function () {
		function makeConfig(preferAnchors?: boolean): IChannelManagerConfig {
			const seed = makeSeed(20);
			const basepoints = makeBasepoints(seed);
			const commitSeed = makeSeed(21);
			basepoints.firstPerCommitmentPoint = getPerCommitmentPoint(
				commitSeed,
				0n
			);

			return {
				localConfig: { ...DEFAULT_CHANNEL_CONFIG },
				localBasepoints: basepoints,
				localPerCommitmentSeed: commitSeed,
				localFundingPrivkey: getFundingPrivkey(seed),
				htlcBasepointSecret: getHtlcBasepointSecret(seed),
				preferAnchors
			};
		}

		it('should pass preferAnchors to channel.initiateOpen via openChannel', function () {
			const cm = new ChannelManager(makeConfig(true));
			cm.on('error', () => {
				/* absorb */
			});

			const channel = cm.openChannel('02' + '11'.repeat(32), 500_000n);
			const fullState = channel.getFullState();
			expect(isAnchorChannel(fullState.channelType)).to.be.true;
		});

		it('should not use anchors when preferAnchors is false', function () {
			const cm = new ChannelManager(makeConfig(false));
			cm.on('error', () => {
				/* absorb */
			});

			const channel = cm.openChannel('02' + '22'.repeat(32), 500_000n);
			const fullState = channel.getFullState();
			expect(isAnchorChannel(fullState.channelType)).to.be.false;
		});

		it('should pass preferAnchors through openZeroConfChannel', function () {
			const cm = new ChannelManager(makeConfig(true));
			cm.on('error', () => {
				/* absorb */
			});

			const peerPubkey = '02' + '33'.repeat(32);
			cm.addTrustedPeer(peerPubkey);

			const channel = cm.openZeroConfChannel(peerPubkey, 500_000n);
			expect(channel).to.not.be.null;
			const fullState = channel!.getFullState();
			expect(isAnchorChannel(fullState.channelType)).to.be.true;
		});
	});

	// ─── LightningNode Config ───

	describe('LightningNode preferAnchors Config', function () {
		it('should advertise ANCHOR_ZERO_FEE_HTLC feature when preferAnchors=true', function () {
			const seed = makeSeed(30);
			const basepoints = makeBasepoints(seed);
			const commitSeed = makeSeed(31);
			basepoints.firstPerCommitmentPoint = getPerCommitmentPoint(
				commitSeed,
				0n
			);

			const node = new LightningNode({
				nodePrivateKey: crypto.randomBytes(32),
				channelBasepoints: basepoints,
				perCommitmentSeed: commitSeed,
				fundingPrivkey: getFundingPrivkey(seed),
				htlcBasepointSecret: getHtlcBasepointSecret(seed),
				network: Network.REGTEST,
				preferAnchors: true
			});

			// The preferAnchors should auto-add anchor feature
			// We can verify through channel manager config wiring
			const cm = node.getChannelManager();
			const peerPubkey = '02' + '44'.repeat(32);
			const channel = cm.openChannel(peerPubkey, 500_000n);
			const fullState = channel.getFullState();
			expect(isAnchorChannel(fullState.channelType)).to.be.true;

			node.destroy();
		});

		it('negotiates anchors by default when preferAnchors is undefined', function () {
			const seed = makeSeed(32);
			const basepoints = makeBasepoints(seed);
			const commitSeed = makeSeed(33);
			basepoints.firstPerCommitmentPoint = getPerCommitmentPoint(
				commitSeed,
				0n
			);

			const node = new LightningNode({
				nodePrivateKey: crypto.randomBytes(32),
				channelBasepoints: basepoints,
				perCommitmentSeed: commitSeed,
				fundingPrivkey: getFundingPrivkey(seed),
				network: Network.REGTEST
			});

			const cm = node.getChannelManager();
			const peerPubkey = '02' + '55'.repeat(32);
			const channel = cm.openChannel(peerPubkey, 500_000n);
			const fullState = channel.getFullState();
			// Anchors are the default channel type.
			expect(isAnchorChannel(fullState.channelType)).to.be.true;

			node.destroy();
		});

		it('escape hatch: preferAnchors=false negotiates a non-anchor channel', function () {
			const seed = makeSeed(132);
			const basepoints = makeBasepoints(seed);
			const commitSeed = makeSeed(133);
			basepoints.firstPerCommitmentPoint = getPerCommitmentPoint(
				commitSeed,
				0n
			);

			const node = new LightningNode({
				nodePrivateKey: crypto.randomBytes(32),
				channelBasepoints: basepoints,
				perCommitmentSeed: commitSeed,
				fundingPrivkey: getFundingPrivkey(seed),
				network: Network.REGTEST,
				preferAnchors: false
			});

			const cm = node.getChannelManager();
			const peerPubkey = '02' + '56'.repeat(32);
			const channel = cm.openChannel(peerPubkey, 500_000n);
			const fullState = channel.getFullState();
			expect(isAnchorChannel(fullState.channelType)).to.be.false;

			node.destroy();
		});

		it('should add anchor feature to explicit localFeatures when preferAnchors=true', function () {
			const seed = makeSeed(34);
			const basepoints = makeBasepoints(seed);
			const commitSeed = makeSeed(35);
			basepoints.firstPerCommitmentPoint = getPerCommitmentPoint(
				commitSeed,
				0n
			);

			const features = FeatureFlags.empty();
			features.setOptional(Feature.STATIC_REMOTE_KEY);

			const node = new LightningNode({
				nodePrivateKey: crypto.randomBytes(32),
				channelBasepoints: basepoints,
				perCommitmentSeed: commitSeed,
				fundingPrivkey: getFundingPrivkey(seed),
				network: Network.REGTEST,
				localFeatures: features,
				preferAnchors: true
			});

			// The features object should now have ANCHOR_ZERO_FEE_HTLC
			expect(features.hasFeature(Feature.ANCHOR_ZERO_FEE_HTLC)).to.be.true;

			node.destroy();
		});
	});

	// ─── Cooperative Close Edge Case ───

	describe('Cooperative Close with Anchors', function () {
		it('should build anchor commitment correctly for closing', function () {
			// Verify that anchor state produces valid commitment that can be used
			// as basis for computing closing balances
			const { openerState, openerCommitSeed } = createReadyAnchorState();
			const perCommitPoint = getPerCommitmentPoint(openerCommitSeed, 0n);

			const built = buildLocalCommitment(openerState, perCommitPoint);
			expect(built.result.tx.outs.length).to.equal(4);

			// The fee + anchor cost should be accounted for
			const totalOut = built.result.tx.outs.reduce(
				(sum, o) => sum + o.value,
				0
			);
			const totalIn = Number(openerState.fundingSatoshis);
			expect(totalOut).to.be.lessThan(totalIn);
			expect(totalOut).to.be.greaterThan(0);
		});
	});

	// ─── to_remote claim on a remote force-close ───
	//
	// On anchor channels our to_remote output is a P2WSH with a 1-block CSV, not a
	// plain P2WPKH. The output resolver must recognise and claim it; otherwise our
	// balance is stranded when the peer force-closes.
	describe('Anchor to_remote claim (their commitment)', function () {
		function paymentPrivkey(seed: Buffer): Buffer {
			return crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from([2]))
				.digest();
		}

		it('classifies our anchor to_remote output (P2WSH) on their commitment', function () {
			const { openerState } = createReadyAnchorState();
			const ourPaymentPubkey = openerState.localBasepoints.paymentBasepoint;
			const anchorToRemote = buildToRemoteAnchorOutput(ourPaymentPubkey);

			const tx = new bitcoin.Transaction();
			tx.version = 2;
			tx.addInput(crypto.randomBytes(32), 0);
			tx.addOutput(anchorToRemote.script, 2222);

			const outputs = classifyOutputs(
				tx,
				openerState,
				CommitmentType.THEIR_CURRENT_COMMITMENT,
				openerState.remoteCommitmentNumber
			);
			const toRemote = outputs.find(
				(o) => o.outputType === OutputType.TO_REMOTE
			);
			expect(toRemote, 'to_remote should be classified').to.exist;
			expect(toRemote!.amount).to.equal(2222n);
			expect(toRemote!.witnessScript, 'anchor variant carries a witnessScript')
				.to.exist;
			expect(toRemote!.witnessScript!.equals(anchorToRemote.witnessScript)).to
				.be.true;
		});

		it('classifies the PEER anchor to_remote (P2WSH) on OUR commitment', function () {
			// The peer's balance on our commitment is an anchor CSV-1 P2WSH too;
			// it used to be silently skipped (only the plain P2WPKH was matched),
			// leaving the output untracked.
			const { openerState } = createReadyAnchorState();
			const remotePaymentPubkey =
				openerState.remoteBasepoints!.paymentBasepoint;
			const anchorToRemote = buildToRemoteAnchorOutput(remotePaymentPubkey);

			const tx = new bitcoin.Transaction();
			tx.version = 2;
			tx.addInput(crypto.randomBytes(32), 0);
			tx.addOutput(anchorToRemote.script, 3333);

			const outputs = classifyOutputs(
				tx,
				openerState,
				CommitmentType.OUR_COMMITMENT,
				openerState.localCommitmentNumber
			);
			const toRemote = outputs.find(
				(o) => o.outputType === OutputType.TO_REMOTE
			);
			expect(toRemote, 'peer to_remote should be classified').to.exist;
			expect(toRemote!.amount).to.equal(3333n);
			expect(toRemote!.witnessScript, 'anchor variant carries a witnessScript')
				.to.exist;
			expect(toRemote!.witnessScript!.equals(anchorToRemote.witnessScript)).to
				.be.true;
		});

		it('builds a valid CSV-1 claim spending the anchor to_remote output', function () {
			const { openerState, openerSeed } = createReadyAnchorState();
			const ourPaymentPubkey = openerState.localBasepoints.paymentBasepoint;
			const anchorToRemote = buildToRemoteAnchorOutput(ourPaymentPubkey);

			const commitmentTxid = crypto.randomBytes(32).toString('hex');
			const amount = 2222n;
			const tracked: ITrackedOutput[] = [
				{
					txid: commitmentTxid,
					outputIndex: 0,
					amount,
					outputType: OutputType.TO_REMOTE,
					status: OutputStatus.CONFIRMED,
					confirmationHeight: 100,
					witnessScript: anchorToRemote.witnessScript
				}
			];

			const destScript = bitcoin.payments.p2wpkh({ pubkey: ourPaymentPubkey })
				.output!;
			const resolved = resolveTheirCurrentCommitmentOutputs(
				openerState,
				tracked,
				destScript,
				5,
				new Map(),
				paymentPrivkey(openerSeed)
			);

			expect(resolved).to.have.length(1);
			const r = resolved[0];
			expect(r.spendTx, 'should produce a claim tx').to.exist;
			expect(r.witness, 'should produce a witness').to.exist;
			expect(r.csvDelay).to.equal(1);

			const tx = r.spendTx!;
			// 1-block CSV → input nSequence must be exactly 1
			expect(tx.ins[0].sequence).to.equal(1);
			expect(tx.outs).to.have.length(1);
			expect(Buffer.from(tx.outs[0].script).equals(destScript)).to.be.true;
			expect(tx.outs[0].value)
				.to.be.greaterThan(0)
				.and.lessThan(Number(amount));

			// Witness is [sig, witnessScript]
			expect(r.witness!).to.have.length(2);
			expect(r.witness![1].equals(anchorToRemote.witnessScript)).to.be.true;

			// The signature must verify against our payment pubkey over the BIP143 sighash.
			const sigHash = tx.hashForWitnessV0(
				0,
				anchorToRemote.witnessScript,
				Number(amount),
				bitcoin.Transaction.SIGHASH_ALL
			);
			const decoded = bitcoin.script.signature.decode(r.witness![0]);
			expect(decoded.hashType).to.equal(bitcoin.Transaction.SIGHASH_ALL);
			expect(ecc.verify(sigHash, ourPaymentPubkey, decoded.signature)).to.be
				.true;
		});

		it('still uses the immediate P2WPKH path for non-anchor (static_remotekey) to_remote', function () {
			const { openerState } = createReadyNonAnchorState();
			const ourPaymentPubkey = openerState.localBasepoints.paymentBasepoint;
			const p2wpkh = bitcoin.payments.p2wpkh({ pubkey: ourPaymentPubkey })
				.output!;

			const tx = new bitcoin.Transaction();
			tx.version = 2;
			tx.addInput(crypto.randomBytes(32), 0);
			tx.addOutput(p2wpkh, 2222);

			const outputs = classifyOutputs(
				tx,
				openerState,
				CommitmentType.THEIR_CURRENT_COMMITMENT,
				openerState.remoteCommitmentNumber
			);
			const toRemote = outputs.find(
				(o) => o.outputType === OutputType.TO_REMOTE
			);
			expect(toRemote, 'to_remote should be classified').to.exist;
			expect(
				toRemote!.witnessScript,
				'non-anchor to_remote has no witnessScript'
			).to.be.undefined;
		});

		it('handleFundingSpent signs the to_remote claim with the per-channel key, not the base key', function () {
			const { openerState, openerSeed } = createReadyAnchorState();
			const ourPaymentPubkey = openerState.localBasepoints.paymentBasepoint;
			const sk = (seed: Buffer, j: number) =>
				crypto
					.createHash('sha256')
					.update(seed)
					.update(Buffer.from([j]))
					.digest();

			// A node-level base key set that is DELIBERATELY WRONG for this channel —
			// if the monitor signed with these, the to_remote claim would be invalid.
			const baseSecret = crypto
				.createHash('sha256')
				.update(Buffer.from('wrong-base-secret'))
				.digest();
			const KEY_INDEX = 7;

			const config: IChannelManagerConfig = {
				localBasepoints: openerState.localBasepoints,
				localPerCommitmentSeed: openerState.localPerCommitmentSeed,
				localFundingPrivkey: baseSecret,
				paymentBasepointSecret: baseSecret,
				revocationBasepointSecret: baseSecret,
				delayedPaymentBasepointSecret: baseSecret,
				htlcBasepointSecret: baseSecret,
				channelKeyDeriver: (i: number) => {
					// Only KEY_INDEX yields this channel's real keys.
					const seed =
						i === KEY_INDEX
							? openerSeed
							: crypto
									.createHash('sha256')
									.update(Buffer.from(`other-seed-${i}`))
									.digest();
					return {
						fundingPrivkey: sk(seed, 0),
						basepoints: makeBasepoints(seed),
						perCommitmentSeed: openerState.localPerCommitmentSeed,
						revocationBasepointSecret: sk(seed, 1),
						paymentBasepointSecret: sk(seed, 2),
						delayedPaymentBasepointSecret: sk(seed, 3),
						htlcBasepointSecret: sk(seed, 4)
					};
				}
			};

			const manager = new ChannelManager(config);
			const channel = new Channel(openerState);
			manager.restoreChannel(channel, 'peer-pubkey', KEY_INDEX);
			const channelId = channel.getChannelId()!;

			// Their commitment, as if the peer force-closed.
			const built = buildRemoteCommitment(
				openerState,
				openerState.remoteCurrentPerCommitmentPoint!
			);
			const commitmentTx = built.result.tx;

			const anchorToRemote = buildToRemoteAnchorOutput(ourPaymentPubkey);
			const toRemoteVout = commitmentTx.outs.findIndex((o) =>
				Buffer.from(o.script).equals(anchorToRemote.script)
			);
			expect(
				toRemoteVout,
				'commitment should pay our anchor to_remote'
			).to.be.greaterThan(-1);
			const toRemoteAmount = commitmentTx.outs[toRemoteVout].value;

			const destScript = bitcoin.payments.p2wpkh({ pubkey: ourPaymentPubkey })
				.output!;
			const broadcasts: Buffer[] = [];
			manager.on('broadcast:tx', (raw: Buffer) => broadcasts.push(raw));

			// No explicit secrets passed → must fall back to the channel's per-channel keys.
			manager.handleFundingSpent(channelId, commitmentTx, 100, destScript, 2);
			// The anchor to_remote has a 1-block CSV, so the claim is held until
			// the commitment has one confirmation, then released on the next block.
			manager.handleNewBlock(101);

			// Find the claim spending our to_remote output.
			const commitTxid = commitmentTx.getId();
			let claim: bitcoin.Transaction | undefined;
			for (const raw of broadcasts) {
				const t = bitcoin.Transaction.fromBuffer(raw);
				if (
					t.ins.some(
						(inp) =>
							Buffer.from(inp.hash).reverse().toString('hex') === commitTxid &&
							inp.index === toRemoteVout
					)
				) {
					claim = t;
				}
			}
			expect(claim, 'should broadcast a to_remote claim').to.exist;

			const witness = claim!.ins[0].witness;
			expect(witness).to.have.length(2);
			expect(witness[1].equals(anchorToRemote.witnessScript)).to.be.true;
			expect(claim!.ins[0].sequence).to.equal(1); // 1-block CSV

			const sigHash = claim!.hashForWitnessV0(
				0,
				anchorToRemote.witnessScript,
				toRemoteAmount,
				bitcoin.Transaction.SIGHASH_ALL
			);
			const decoded = bitcoin.script.signature.decode(witness[0]);
			// The per-channel payment key validates the signature...
			expect(
				ecc.verify(sigHash, ourPaymentPubkey, decoded.signature),
				'per-channel key should validate'
			).to.be.true;
			// ...and the (wrong) base key does NOT — proving the per-channel key was used.
			expect(
				ecc.verify(sigHash, getPublicKey(baseSecret), decoded.signature),
				'base key must NOT validate'
			).to.be.false;
		});
	});
});
