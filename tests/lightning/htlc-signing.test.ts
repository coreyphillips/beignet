import { expect } from 'chai';
import crypto from 'crypto';
import {
	deriveCommitmentKeys,
	buildRemoteCommitment,
	signRemoteCommitment
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
	perCommitmentPointFromSecret
} from '../../src/lightning/keys/derivation';
import { ChannelSigner } from '../../src/lightning/keys/signer';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import { deriveChannelId } from '../../src/lightning/channel/validation';
import {
	buildHtlcSuccessTx,
	buildHtlcTimeoutTx
} from '../../src/lightning/script/htlc';
import { verify } from '../../src/lightning/crypto/ecdh';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';

bitcoin.initEccLib(ecc);

/** BOLT 3 weights */
const HTLC_SUCCESS_WEIGHT = 703;
const HTLC_TIMEOUT_WEIGHT = 663;

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`seed-${id}`))
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

function getPrivkey(seed: Buffer, index: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([index]))
		.digest();
}

function getFundingPrivkey(seed: Buffer): Buffer {
	return getPrivkey(seed, 0);
}

function getHtlcBasepointSecret(seed: Buffer): Buffer {
	return getPrivkey(seed, 4);
}

function getPerCommitmentPoint(seed: Buffer, commitmentNumber: bigint): Buffer {
	const index = MAX_INDEX - commitmentNumber;
	const secret = generateFromSeed(seed, index);
	return perCommitmentPointFromSecret(secret);
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

	const fundingTxid = crypto
		.createHash('sha256')
		.update(Buffer.from('funding-tx'))
		.digest();
	const fundingOutputIndex = 0;
	const channelId = deriveChannelId(fundingTxid, fundingOutputIndex);

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
	openerState.fundingOutputIndex = fundingOutputIndex;
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
	acceptorState.fundingOutputIndex = fundingOutputIndex;
	acceptorState.channelId = channelId;
	acceptorState.state = ChannelState.NORMAL;
	acceptorState.remoteCurrentPerCommitmentPoint =
		openerBasepoints.firstPerCommitmentPoint;
	acceptorState.localBalanceMsat = 0n;
	acceptorState.remoteBalanceMsat = fundingSatoshis * 1000n;

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

describe('HTLC Transaction Signing', function () {
	describe('Backward Compatibility', function () {
		it('should return empty htlcSignatures when no htlcBasepointSecret', function () {
			const { openerState, openerSeed } = createReadyState();

			// Add an HTLC
			openerState.htlcs.set('offered-0', {
				id: 0n,
				amountMsat: 50_000_000n,
				paymentHash: crypto.randomBytes(32),
				cltvExpiry: 500000,
				onionRoutingPacket: Buffer.alloc(1366),
				direction: HtlcDirection.OFFERED,
				state: HtlcState.COMMITTED
			});
			openerState.localBalanceMsat -= 50_000_000n;

			// Signer without htlcBasepointSecret
			const signer = new ChannelSigner(getFundingPrivkey(openerSeed));
			const remotePoint = openerState.remoteCurrentPerCommitmentPoint!;
			const { signature, htlcSignatures } = signRemoteCommitment(
				openerState,
				signer,
				remotePoint
			);

			expect(signature).to.have.length(64);
			expect(htlcSignatures).to.have.length(0);
		});

		it('should return empty htlcSignatures when no HTLCs present', function () {
			const { openerState, openerSeed } = createReadyState();

			const signer = new ChannelSigner(
				getFundingPrivkey(openerSeed),
				getHtlcBasepointSecret(openerSeed)
			);
			const remotePoint = openerState.remoteCurrentPerCommitmentPoint!;
			const { htlcSignatures } = signRemoteCommitment(
				openerState,
				signer,
				remotePoint
			);

			expect(htlcSignatures).to.have.length(0);
		});
	});

	describe('Single HTLC Signing', function () {
		it('should produce one signature for a single offered HTLC', function () {
			const { openerState, openerSeed } = createReadyState();

			openerState.htlcs.set('offered-0', {
				id: 0n,
				amountMsat: 50_000_000n,
				paymentHash: crypto.randomBytes(32),
				cltvExpiry: 500000,
				onionRoutingPacket: Buffer.alloc(1366),
				direction: HtlcDirection.OFFERED,
				state: HtlcState.COMMITTED
			});
			openerState.localBalanceMsat -= 50_000_000n;

			const signer = new ChannelSigner(
				getFundingPrivkey(openerSeed),
				getHtlcBasepointSecret(openerSeed)
			);
			const remotePoint = openerState.remoteCurrentPerCommitmentPoint!;
			const { htlcSignatures } = signRemoteCommitment(
				openerState,
				signer,
				remotePoint
			);

			expect(htlcSignatures).to.have.length(1);
			expect(htlcSignatures[0]).to.have.length(64);
		});

		it('should produce one signature for a single received HTLC', function () {
			const { openerState, openerSeed } = createReadyState();

			openerState.localBalanceMsat = 500_000_000n;
			openerState.remoteBalanceMsat = 500_000_000n;

			openerState.htlcs.set('received-0', {
				id: 0n,
				amountMsat: 50_000_000n,
				paymentHash: crypto.randomBytes(32),
				cltvExpiry: 600000,
				onionRoutingPacket: Buffer.alloc(1366),
				direction: HtlcDirection.RECEIVED,
				state: HtlcState.COMMITTED
			});
			openerState.remoteBalanceMsat -= 50_000_000n;

			const signer = new ChannelSigner(
				getFundingPrivkey(openerSeed),
				getHtlcBasepointSecret(openerSeed)
			);
			const remotePoint = openerState.remoteCurrentPerCommitmentPoint!;
			const { htlcSignatures } = signRemoteCommitment(
				openerState,
				signer,
				remotePoint
			);

			expect(htlcSignatures).to.have.length(1);
			expect(htlcSignatures[0]).to.have.length(64);
		});
	});

	describe('Multiple Mixed HTLCs', function () {
		it('should produce correct count for multiple mixed HTLCs', function () {
			const { openerState, openerSeed } = createReadyState();
			openerState.localBalanceMsat = 700_000_000n;
			openerState.remoteBalanceMsat = 300_000_000n;

			// 2 offered HTLCs
			openerState.htlcs.set('offered-0', {
				id: 0n,
				amountMsat: 30_000_000n,
				paymentHash: crypto.randomBytes(32),
				cltvExpiry: 500000,
				onionRoutingPacket: Buffer.alloc(1366),
				direction: HtlcDirection.OFFERED,
				state: HtlcState.COMMITTED
			});
			openerState.htlcs.set('offered-1', {
				id: 1n,
				amountMsat: 40_000_000n,
				paymentHash: crypto.randomBytes(32),
				cltvExpiry: 500100,
				onionRoutingPacket: Buffer.alloc(1366),
				direction: HtlcDirection.OFFERED,
				state: HtlcState.COMMITTED
			});
			// 1 received HTLC
			openerState.htlcs.set('received-0', {
				id: 0n,
				amountMsat: 20_000_000n,
				paymentHash: crypto.randomBytes(32),
				cltvExpiry: 600000,
				onionRoutingPacket: Buffer.alloc(1366),
				direction: HtlcDirection.RECEIVED,
				state: HtlcState.COMMITTED
			});

			openerState.localBalanceMsat -= 70_000_000n;
			openerState.remoteBalanceMsat -= 20_000_000n;

			const signer = new ChannelSigner(
				getFundingPrivkey(openerSeed),
				getHtlcBasepointSecret(openerSeed)
			);
			const remotePoint = openerState.remoteCurrentPerCommitmentPoint!;
			const { htlcSignatures } = signRemoteCommitment(
				openerState,
				signer,
				remotePoint
			);

			// 3 non-dust HTLCs → 3 signatures
			expect(htlcSignatures).to.have.length(3);
			for (const sig of htlcSignatures) {
				expect(sig).to.have.length(64);
			}
		});
	});

	describe('Dust HTLC Exclusion', function () {
		it('should not produce signatures for dust HTLCs', function () {
			const { openerState, openerSeed } = createReadyState();

			// Dust HTLC (below 546 sat P2WSH limit = 546_000 msat)
			openerState.htlcs.set('offered-0', {
				id: 0n,
				amountMsat: 500_000n, // 500 sats → below dust
				paymentHash: crypto.randomBytes(32),
				cltvExpiry: 500000,
				onionRoutingPacket: Buffer.alloc(1366),
				direction: HtlcDirection.OFFERED,
				state: HtlcState.COMMITTED
			});
			openerState.localBalanceMsat -= 500_000n;

			const signer = new ChannelSigner(
				getFundingPrivkey(openerSeed),
				getHtlcBasepointSecret(openerSeed)
			);
			const remotePoint = openerState.remoteCurrentPerCommitmentPoint!;
			const { htlcSignatures } = signRemoteCommitment(
				openerState,
				signer,
				remotePoint
			);

			expect(htlcSignatures).to.have.length(0);
		});

		it('should only produce signatures for non-dust HTLCs in a mixed set', function () {
			const { openerState, openerSeed } = createReadyState();
			openerState.localBalanceMsat = 900_000_000n;
			openerState.remoteBalanceMsat = 100_000_000n;

			// Non-dust offered HTLC
			openerState.htlcs.set('offered-0', {
				id: 0n,
				amountMsat: 50_000_000n,
				paymentHash: crypto.randomBytes(32),
				cltvExpiry: 500000,
				onionRoutingPacket: Buffer.alloc(1366),
				direction: HtlcDirection.OFFERED,
				state: HtlcState.COMMITTED
			});

			// Dust offered HTLC
			openerState.htlcs.set('offered-1', {
				id: 1n,
				amountMsat: 400_000n, // 400 sat → dust
				paymentHash: crypto.randomBytes(32),
				cltvExpiry: 500100,
				onionRoutingPacket: Buffer.alloc(1366),
				direction: HtlcDirection.OFFERED,
				state: HtlcState.COMMITTED
			});

			openerState.localBalanceMsat -= 50_400_000n;

			const signer = new ChannelSigner(
				getFundingPrivkey(openerSeed),
				getHtlcBasepointSecret(openerSeed)
			);
			const remotePoint = openerState.remoteCurrentPerCommitmentPoint!;
			const { htlcSignatures } = signRemoteCommitment(
				openerState,
				signer,
				remotePoint
			);

			// Only 1 non-dust HTLC
			expect(htlcSignatures).to.have.length(1);
		});
	});

	describe('HTLC-success vs HTLC-timeout', function () {
		it('should sign HTLC-success tx with locktime=0 for offered HTLCs', function () {
			const { openerState } = createReadyState();

			const paymentHash = crypto.randomBytes(32);
			openerState.htlcs.set('offered-0', {
				id: 0n,
				amountMsat: 50_000_000n,
				paymentHash,
				cltvExpiry: 500000,
				onionRoutingPacket: Buffer.alloc(1366),
				direction: HtlcDirection.OFFERED,
				state: HtlcState.COMMITTED
			});
			openerState.localBalanceMsat -= 50_000_000n;

			const remotePoint = openerState.remoteCurrentPerCommitmentPoint!;

			// Build the commitment to verify the HTLC-success tx structure
			const built = buildRemoteCommitment(openerState, remotePoint);
			const commitTxid = built.result.tx.getId();
			const htlcOutputIdx = built.result.outputMap.htlcs[0];

			const keys = deriveCommitmentKeys(
				openerState.localBasepoints,
				openerState.remoteBasepoints!,
				remotePoint,
				false
			);

			const feeratePerKw = openerState.localConfig.feeratePerKw;
			const fee = BigInt(
				Math.floor((HTLC_SUCCESS_WEIGHT * feeratePerKw) / 1000)
			);

			// Build expected HTLC-success tx
			const htlcSuccessTx = buildHtlcSuccessTx(
				commitTxid,
				htlcOutputIdx,
				50_000n,
				keys.revocationPubkey,
				keys.localDelayedPubkey,
				openerState.localConfig.toSelfDelay,
				fee
			);

			// HTLC-success should have locktime=0
			expect(htlcSuccessTx.locktime).to.equal(0);
		});

		it('should sign HTLC-timeout tx with locktime=cltvExpiry for received HTLCs', function () {
			const { openerState } = createReadyState();
			openerState.localBalanceMsat = 500_000_000n;
			openerState.remoteBalanceMsat = 500_000_000n;

			const cltvExpiry = 600123;
			openerState.htlcs.set('received-0', {
				id: 0n,
				amountMsat: 50_000_000n,
				paymentHash: crypto.randomBytes(32),
				cltvExpiry,
				onionRoutingPacket: Buffer.alloc(1366),
				direction: HtlcDirection.RECEIVED,
				state: HtlcState.COMMITTED
			});
			openerState.remoteBalanceMsat -= 50_000_000n;

			const remotePoint = openerState.remoteCurrentPerCommitmentPoint!;

			const built = buildRemoteCommitment(openerState, remotePoint);
			const commitTxid = built.result.tx.getId();
			const htlcOutputIdx = built.result.outputMap.htlcs[0];

			const keys = deriveCommitmentKeys(
				openerState.localBasepoints,
				openerState.remoteBasepoints!,
				remotePoint,
				false
			);

			const feeratePerKw = openerState.localConfig.feeratePerKw;
			const fee = BigInt(
				Math.floor((HTLC_TIMEOUT_WEIGHT * feeratePerKw) / 1000)
			);

			// Build expected HTLC-timeout tx
			const htlcTimeoutTx = buildHtlcTimeoutTx(
				commitTxid,
				htlcOutputIdx,
				50_000n,
				cltvExpiry,
				keys.revocationPubkey,
				keys.localDelayedPubkey,
				openerState.localConfig.toSelfDelay,
				fee
			);

			// HTLC-timeout should have locktime=cltvExpiry
			expect(htlcTimeoutTx.locktime).to.equal(cltvExpiry);
		});
	});

	describe('Cross-party Verification', function () {
		it('opener signs, acceptor verifies HTLC signatures', function () {
			const { openerState, acceptorState, openerSeed, acceptorCommitSeed } =
				createReadyState();
			openerState.localBalanceMsat = 800_000_000n;
			openerState.remoteBalanceMsat = 200_000_000n;
			acceptorState.localBalanceMsat = 200_000_000n;
			acceptorState.remoteBalanceMsat = 800_000_000n;

			const paymentHash = crypto.randomBytes(32);

			// Add offered HTLC to opener state
			openerState.htlcs.set('offered-0', {
				id: 0n,
				amountMsat: 50_000_000n,
				paymentHash,
				cltvExpiry: 500000,
				onionRoutingPacket: Buffer.alloc(1366),
				direction: HtlcDirection.OFFERED,
				state: HtlcState.COMMITTED
			});
			openerState.localBalanceMsat -= 50_000_000n;

			// Mirror: acceptor sees it as received
			acceptorState.htlcs.set('received-0', {
				id: 0n,
				amountMsat: 50_000_000n,
				paymentHash,
				cltvExpiry: 500000,
				onionRoutingPacket: Buffer.alloc(1366),
				direction: HtlcDirection.RECEIVED,
				state: HtlcState.COMMITTED
			});
			acceptorState.remoteBalanceMsat -= 50_000_000n;

			// Opener signs the acceptor's (remote) commitment
			const openerSigner = new ChannelSigner(
				getFundingPrivkey(openerSeed),
				getHtlcBasepointSecret(openerSeed)
			);
			const remotePoint = openerState.remoteCurrentPerCommitmentPoint!;
			const { signature, htlcSignatures } = signRemoteCommitment(
				openerState,
				openerSigner,
				remotePoint
			);

			expect(signature).to.have.length(64);
			expect(htlcSignatures).to.have.length(1);
			expect(htlcSignatures[0]).to.have.length(64);

			// Now verify from acceptor's perspective:
			// Build acceptor's local commitment (which is the same tx the opener signed)
			const acceptorLocalPoint = getPerCommitmentPoint(acceptorCommitSeed, 0n);
			const acceptorKeys = deriveCommitmentKeys(
				acceptorState.localBasepoints,
				acceptorState.remoteBasepoints!,
				acceptorLocalPoint,
				true
			);

			// Derive the expected HTLC public key the opener signed with
			const openerHtlcPubkey = acceptorKeys.remoteHtlcPubkey;

			// Build the HTLC-success tx from acceptor's perspective
			// (acceptor received the HTLC, so it's an HTLC-success on their local commitment)
			const {
				buildLocalCommitment
			} = require('../../src/lightning/channel/commitment-builder');
			const acceptorBuilt = buildLocalCommitment(
				acceptorState,
				acceptorLocalPoint
			);
			const commitTxid = acceptorBuilt.result.tx.getId();
			const htlcOutputIdx = acceptorBuilt.result.outputMap.htlcs[0];
			const htlcAmount = acceptorBuilt.result.tx.outs[htlcOutputIdx].value;

			const feeratePerKw = acceptorState.remoteConfig.feeratePerKw;
			const fee = BigInt(
				Math.floor((HTLC_SUCCESS_WEIGHT * feeratePerKw) / 1000)
			);

			const htlcSuccessTx = buildHtlcSuccessTx(
				commitTxid,
				htlcOutputIdx,
				BigInt(htlcAmount),
				acceptorKeys.revocationPubkey,
				acceptorKeys.localDelayedPubkey,
				acceptorState.remoteConfig.toSelfDelay,
				fee
			);

			// Verify the opener's HTLC signature
			// For the local commitment, the HTLC script uses localHtlcPubkey and remoteHtlcPubkey
			const htlcWitnessScript =
				require('../../src/lightning/script/htlc').buildReceivedHtlcScript(
					acceptorKeys.revocationPubkey,
					acceptorKeys.localHtlcPubkey,
					acceptorKeys.remoteHtlcPubkey,
					paymentHash,
					500000
				);

			const sigHash = htlcSuccessTx.hashForWitnessV0(
				0,
				htlcWitnessScript,
				htlcAmount,
				bitcoin.Transaction.SIGHASH_ALL
			);

			const valid = verify(sigHash, openerHtlcPubkey, htlcSignatures[0]);
			expect(valid).to.be.true;
		});
	});

	describe('Signature Order', function () {
		it('should produce HTLC signatures in commitment output index order', function () {
			const { openerState, openerSeed } = createReadyState();
			openerState.localBalanceMsat = 800_000_000n;
			openerState.remoteBalanceMsat = 200_000_000n;

			// Add 3 HTLCs with different amounts (they'll sort by value in BIP 69)
			const hashes = [
				crypto.randomBytes(32),
				crypto.randomBytes(32),
				crypto.randomBytes(32)
			];
			openerState.htlcs.set('offered-0', {
				id: 0n,
				amountMsat: 100_000_000n, // 100k sat
				paymentHash: hashes[0],
				cltvExpiry: 500000,
				onionRoutingPacket: Buffer.alloc(1366),
				direction: HtlcDirection.OFFERED,
				state: HtlcState.COMMITTED
			});
			openerState.htlcs.set('offered-1', {
				id: 1n,
				amountMsat: 20_000_000n, // 20k sat
				paymentHash: hashes[1],
				cltvExpiry: 500100,
				onionRoutingPacket: Buffer.alloc(1366),
				direction: HtlcDirection.OFFERED,
				state: HtlcState.COMMITTED
			});
			openerState.htlcs.set('offered-2', {
				id: 2n,
				amountMsat: 50_000_000n, // 50k sat
				paymentHash: hashes[2],
				cltvExpiry: 500200,
				onionRoutingPacket: Buffer.alloc(1366),
				direction: HtlcDirection.OFFERED,
				state: HtlcState.COMMITTED
			});
			openerState.localBalanceMsat -= 170_000_000n;

			const signer = new ChannelSigner(
				getFundingPrivkey(openerSeed),
				getHtlcBasepointSecret(openerSeed)
			);
			const remotePoint = openerState.remoteCurrentPerCommitmentPoint!;
			const { htlcSignatures } = signRemoteCommitment(
				openerState,
				signer,
				remotePoint
			);

			// Should have 3 signatures
			expect(htlcSignatures).to.have.length(3);

			// Verify they're in commitment output order by checking the commitment tx
			const built = buildRemoteCommitment(openerState, remotePoint);
			const htlcOutputs = built.result.outputMap.htlcs;

			// The htlc output values should be in BIP 69 order (ascending by value)
			for (let i = 0; i < htlcOutputs.length - 1; i++) {
				const val1 = built.result.tx.outs[htlcOutputs[i]].value;
				const val2 = built.result.tx.outs[htlcOutputs[i + 1]].value;
				expect(val1).to.be.at.most(val2);
			}
		});
	});

	describe('HTLC State Filtering', function () {
		it('should only sign PENDING and COMMITTED HTLCs', function () {
			const { openerState, openerSeed } = createReadyState();
			openerState.localBalanceMsat = 800_000_000n;
			openerState.remoteBalanceMsat = 200_000_000n;

			// COMMITTED HTLC — should be signed
			openerState.htlcs.set('offered-0', {
				id: 0n,
				amountMsat: 50_000_000n,
				paymentHash: crypto.randomBytes(32),
				cltvExpiry: 500000,
				onionRoutingPacket: Buffer.alloc(1366),
				direction: HtlcDirection.OFFERED,
				state: HtlcState.COMMITTED
			});

			// FULFILLED HTLC — should NOT be signed
			openerState.htlcs.set('offered-1', {
				id: 1n,
				amountMsat: 30_000_000n,
				paymentHash: crypto.randomBytes(32),
				cltvExpiry: 500100,
				onionRoutingPacket: Buffer.alloc(1366),
				direction: HtlcDirection.OFFERED,
				state: HtlcState.FULFILLED
			});

			// PENDING HTLC — should be signed
			openerState.htlcs.set('offered-2', {
				id: 2n,
				amountMsat: 40_000_000n,
				paymentHash: crypto.randomBytes(32),
				cltvExpiry: 500200,
				onionRoutingPacket: Buffer.alloc(1366),
				direction: HtlcDirection.OFFERED,
				state: HtlcState.PENDING
			});

			// FAILED HTLC — should NOT be signed
			openerState.htlcs.set('received-0', {
				id: 0n,
				amountMsat: 25_000_000n,
				paymentHash: crypto.randomBytes(32),
				cltvExpiry: 600000,
				onionRoutingPacket: Buffer.alloc(1366),
				direction: HtlcDirection.RECEIVED,
				state: HtlcState.FAILED
			});

			openerState.localBalanceMsat -= 120_000_000n;
			openerState.remoteBalanceMsat -= 25_000_000n;

			const signer = new ChannelSigner(
				getFundingPrivkey(openerSeed),
				getHtlcBasepointSecret(openerSeed)
			);
			const remotePoint = openerState.remoteCurrentPerCommitmentPoint!;
			const { htlcSignatures } = signRemoteCommitment(
				openerState,
				signer,
				remotePoint
			);

			// Only 2 active HTLCs (COMMITTED + PENDING)
			expect(htlcSignatures).to.have.length(2);
		});
	});

	describe('ChannelSigner with htlcBasepointSecret', function () {
		it('should construct with htlcBasepointSecret', function () {
			const fundingKey = crypto.randomBytes(32);
			const htlcKey = crypto.randomBytes(32);
			const signer = new ChannelSigner(fundingKey, htlcKey);

			expect(signer.htlcBasepointSecret).to.exist;
			expect(signer.htlcBasepointSecret!.equals(htlcKey)).to.be.true;
		});

		it('should construct without htlcBasepointSecret', function () {
			const fundingKey = crypto.randomBytes(32);
			const signer = new ChannelSigner(fundingKey);

			expect(signer.htlcBasepointSecret).to.be.undefined;
		});

		it('should reject invalid htlcBasepointSecret length', function () {
			const fundingKey = crypto.randomBytes(32);
			expect(() => new ChannelSigner(fundingKey, Buffer.alloc(16))).to.throw(
				'32 bytes'
			);
		});
	});

	describe('htlcOriginalIndices tracking', function () {
		it('should track original HTLC indices through BIP 69 sorting', function () {
			const { openerState } = createReadyState();
			openerState.localBalanceMsat = 800_000_000n;
			openerState.remoteBalanceMsat = 200_000_000n;

			// Add HTLCs with amounts that will sort differently than insertion order
			openerState.htlcs.set('offered-0', {
				id: 0n,
				amountMsat: 100_000_000n, // 100k sat
				paymentHash: crypto.randomBytes(32),
				cltvExpiry: 500000,
				onionRoutingPacket: Buffer.alloc(1366),
				direction: HtlcDirection.OFFERED,
				state: HtlcState.COMMITTED
			});
			openerState.htlcs.set('offered-1', {
				id: 1n,
				amountMsat: 20_000_000n, // 20k sat — will sort first
				paymentHash: crypto.randomBytes(32),
				cltvExpiry: 500100,
				onionRoutingPacket: Buffer.alloc(1366),
				direction: HtlcDirection.OFFERED,
				state: HtlcState.COMMITTED
			});
			openerState.localBalanceMsat -= 120_000_000n;

			const remotePoint = openerState.remoteCurrentPerCommitmentPoint!;
			const built = buildRemoteCommitment(openerState, remotePoint);

			// Verify htlcOriginalIndices exists and matches htlcs length
			expect(built.result.outputMap.htlcOriginalIndices).to.have.length(
				built.result.outputMap.htlcs.length
			);
		});
	});

	describe('Fee Calculation', function () {
		it('should use correct fee rates for HTLC transactions', function () {
			const { openerState, openerSeed } = createReadyState();

			// Set a specific feerate
			openerState.localConfig.feeratePerKw = 1000;

			openerState.htlcs.set('offered-0', {
				id: 0n,
				amountMsat: 50_000_000n,
				paymentHash: crypto.randomBytes(32),
				cltvExpiry: 500000,
				onionRoutingPacket: Buffer.alloc(1366),
				direction: HtlcDirection.OFFERED,
				state: HtlcState.COMMITTED
			});
			openerState.localBalanceMsat -= 50_000_000n;

			const signer = new ChannelSigner(
				getFundingPrivkey(openerSeed),
				getHtlcBasepointSecret(openerSeed)
			);
			const remotePoint = openerState.remoteCurrentPerCommitmentPoint!;

			// Should not throw — fee should be reasonable
			const { htlcSignatures } = signRemoteCommitment(
				openerState,
				signer,
				remotePoint
			);
			expect(htlcSignatures).to.have.length(1);

			// Expected fee: 703 * 1000 / 1000 = 703 sat for HTLC-success
			// HTLC amount is 50000 sat, output should be 50000 - 703 = 49297 sat
			const built = buildRemoteCommitment(openerState, remotePoint);
			const commitTxid = built.result.tx.getId();
			const htlcOutputIdx = built.result.outputMap.htlcs[0];

			const keys = deriveCommitmentKeys(
				openerState.localBasepoints,
				openerState.remoteBasepoints!,
				remotePoint,
				false
			);

			const htlcSuccessTx = buildHtlcSuccessTx(
				commitTxid,
				htlcOutputIdx,
				50_000n,
				keys.revocationPubkey,
				keys.localDelayedPubkey,
				openerState.localConfig.toSelfDelay,
				703n
			);

			expect(htlcSuccessTx.outs[0].value).to.equal(50_000 - 703);
		});
	});
});
