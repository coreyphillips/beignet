/**
 * S-L.H4 regression: the lessor's `to_remote` output must be lease-locked.
 *
 * The BUYER's commitment must pay the seller's balance to a lease-locked
 * to_remote, else the seller could escape the lease by provoking a buyer
 * force-close. CLN's model (bLIP-0051, validated live) is a PURE CSV:
 * <key> OP_CHECKSIGVERIFY <lease_csv> OP_CHECKSEQUENCEVERIFY, where
 * lease_csv = lease_expiry - the agreed blockheight. It is threaded through the
 * commitment builder (mirror of the to_local gates), the output
 * classifier/resolver (sweep input sequence = lease_csv, no nLockTime), the
 * watchtower kit (lease outputs excluded: blob v0 cannot express them), and
 * the SCB (lease fields ride along for post-restore recovery).
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';
import {
	buildLocalCommitment,
	buildRemoteCommitment
} from '../../src/lightning/channel/commitment-builder';
import {
	createOpenerState,
	createAcceptorState
} from '../../src/lightning/channel/channel-state';
import {
	IChannelBasepoints,
	perCommitmentPointFromSecret
} from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { generateFromSeed } from '../../src/lightning/keys/shachain';
import { deriveChannelId } from '../../src/lightning/channel/validation';
import {
	buildToRemoteAnchorScript,
	leaseCsvFromToRemoteScript
} from '../../src/lightning/script/anchor';
import {
	classifyOutputs,
	resolveTheirCurrentCommitmentOutputs
} from '../../src/lightning/chain/output-resolver';
import { CommitmentType, OutputType } from '../../src/lightning/chain/types';
import {
	encodeScb,
	decodeScb,
	IScbChannelEntry
} from '../../src/lightning/backup/scb';

bitcoin.initEccLib(ecc);

const LEASE_EXPIRY = 804032; // computeLeaseExpiry(800000)
const LEASE_COMMIT_BH = 800000; // request_funds.blockheight agreed at open
const LEASE_CSV = LEASE_EXPIRY - LEASE_COMMIT_BH; // 4032

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`lease-to-remote-seed-${id}`))
		.digest();
}

function makeKeys(seed: Buffer): {
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

function getPerCommitmentPoint(seed: Buffer, index: bigint): Buffer {
	return perCommitmentPointFromSecret(generateFromSeed(seed, index));
}

function makeAnchorChannelType(): Buffer {
	const flags = FeatureFlags.empty();
	flags.setCompulsory(Feature.STATIC_REMOTE_KEY);
	flags.setCompulsory(Feature.ANCHOR_ZERO_FEE_HTLC);
	return flags.toBuffer();
}

/**
 * A ready leased anchor channel. The BUYER (lessee) is the opener; the
 * SELLER (lessor) is the acceptor: both record leaseExpiry, only the seller
 * records isLessor, exactly as negotiation does (channel.ts).
 */
function createLeasedChannelStates(withLease = true) {
	const buyerSeed = makeSeed(1);
	const sellerSeed = makeSeed(2);
	const buyerCommitSeed = makeSeed(3);
	const sellerCommitSeed = makeSeed(4);

	const buyer = makeKeys(buyerSeed);
	const seller = makeKeys(sellerSeed);
	buyer.basepoints.firstPerCommitmentPoint = getPerCommitmentPoint(
		buyerCommitSeed,
		0n
	);
	seller.basepoints.firstPerCommitmentPoint = getPerCommitmentPoint(
		sellerCommitSeed,
		0n
	);

	const fundingTxid = crypto
		.createHash('sha256')
		.update(Buffer.from('lease-funding-tx'))
		.digest();
	const channelId = deriveChannelId(fundingTxid, 0);
	const fundingSatoshis = 1_000_000n;
	const pushMsat = 400_000_000n; // seller's leased balance

	const buyerState = createOpenerState({
		temporaryChannelId: crypto.randomBytes(32),
		fundingSatoshis,
		pushMsat,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: buyer.basepoints,
		localPerCommitmentSeed: buyerCommitSeed
	});
	buyerState.remoteBasepoints = seller.basepoints;
	buyerState.remoteConfig = { ...DEFAULT_CHANNEL_CONFIG };
	buyerState.fundingTxid = fundingTxid;
	buyerState.fundingOutputIndex = 0;
	buyerState.channelId = channelId;
	buyerState.state = ChannelState.NORMAL;
	buyerState.remoteCurrentPerCommitmentPoint =
		seller.basepoints.firstPerCommitmentPoint;
	buyerState.channelType = makeAnchorChannelType();

	const sellerState = createAcceptorState({
		temporaryChannelId: buyerState.temporaryChannelId,
		fundingSatoshis,
		pushMsat,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: seller.basepoints,
		localPerCommitmentSeed: sellerCommitSeed,
		remoteBasepoints: buyer.basepoints,
		remoteConfig: { ...DEFAULT_CHANNEL_CONFIG }
	});
	sellerState.fundingTxid = fundingTxid;
	sellerState.fundingOutputIndex = 0;
	sellerState.channelId = channelId;
	sellerState.state = ChannelState.NORMAL;
	sellerState.remoteCurrentPerCommitmentPoint =
		buyer.basepoints.firstPerCommitmentPoint;
	sellerState.channelType = makeAnchorChannelType();

	if (withLease) {
		buyerState.leaseExpiry = LEASE_EXPIRY; // lessee: no isLessor
		buyerState.leaseCommitBlockheight = LEASE_COMMIT_BH;
		sellerState.leaseExpiry = LEASE_EXPIRY;
		sellerState.leaseCommitBlockheight = LEASE_COMMIT_BH;
		sellerState.isLessor = true;
	}

	return {
		buyerState,
		sellerState,
		buyer,
		seller,
		buyerCommitSeed,
		sellerCommitSeed
	};
}

/** The lease-locked confirmed to_remote script, hand-compiled (CLN CSV layout). */
function handBuiltLeaseToRemote(key: Buffer, csv: number): Buffer {
	return bitcoin.script.compile([
		key,
		bitcoin.opcodes.OP_CHECKSIGVERIFY,
		bitcoin.script.number.encode(csv),
		bitcoin.opcodes.OP_CHECKSEQUENCEVERIFY
	]);
}

function p2wsh(script: Buffer): Buffer {
	return bitcoin.payments.p2wsh({ redeem: { output: script } }).output!;
}

describe('S-L.H4: lease-locked to_remote (CLN CSV model)', function () {
	describe('script layout (CLN parity)', function () {
		const key = getPublicKey(crypto.randomBytes(32));

		it('matches the hand-built CLN CSV layout', function () {
			const leased = buildToRemoteAnchorScript(key, LEASE_CSV);
			expect(leased.equals(handBuiltLeaseToRemote(key, LEASE_CSV))).to.be.true;
			// <key> CHECKSIGVERIFY <lease_csv> CHECKSEQUENCEVERIFY — no CLTV.
			const ops = bitcoin.script.decompile(leased)!;
			expect(ops.indexOf(bitcoin.opcodes.OP_CHECKLOCKTIMEVERIFY)).to.equal(-1);
			expect(ops[1]).to.equal(bitcoin.opcodes.OP_CHECKSIGVERIFY);
			expect(ops[3]).to.equal(bitcoin.opcodes.OP_CHECKSEQUENCEVERIFY);
			expect(bitcoin.script.number.decode(ops[2] as Buffer)).to.equal(
				LEASE_CSV
			);
		});

		it('no csv (or 1) returns the plain 37-byte confirmed script', function () {
			const plain = buildToRemoteAnchorScript(key);
			expect(plain.length).to.equal(37); // ToRemoteConfirmedScriptSize
			expect(buildToRemoteAnchorScript(key, 1).equals(plain)).to.be.true;
			expect(leaseCsvFromToRemoteScript(plain)).to.be.undefined;
		});

		it('leaseCsvFromToRemoteScript round-trips the lease CSV', function () {
			const leased = buildToRemoteAnchorScript(key, LEASE_CSV);
			expect(leaseCsvFromToRemoteScript(leased)).to.equal(LEASE_CSV);
			expect(leaseCsvFromToRemoteScript(Buffer.from([0x51]))).to.be.undefined;
		});
	});

	describe('commitment builder gating', function () {
		it('the BUYER local commitment lease-locks the seller to_remote (the S-L.H4 output)', function () {
			const { buyerState, seller, buyerCommitSeed } =
				createLeasedChannelStates();
			const point = getPerCommitmentPoint(buyerCommitSeed, 0n);
			const built = buildLocalCommitment(buyerState, point);

			// The seller (lessor) balance on the buyer's commitment pays the
			// seller's STATIC payment basepoint under the LEASE variant.
			const leasedSpk = p2wsh(
				handBuiltLeaseToRemote(seller.basepoints.paymentBasepoint, LEASE_CSV)
			);
			const plainSpk = p2wsh(
				buildToRemoteAnchorScript(seller.basepoints.paymentBasepoint)
			);
			const outs = built.result.tx.outs.map((o) => o.script);
			expect(
				outs.some((s) => s.equals(leasedSpk)),
				'lease-locked to_remote present'
			).to.be.true;
			expect(
				outs.some((s) => s.equals(plainSpk)),
				'plain to_remote absent'
			).to.be.false;
		});

		it('gates mirror to_local: exactly one lock per commitment, always on the lessor balance', function () {
			const {
				buyerState,
				sellerState,
				buyer,
				seller,
				buyerCommitSeed,
				sellerCommitSeed
			} = createLeasedChannelStates();
			const buyerPoint = getPerCommitmentPoint(buyerCommitSeed, 0n);
			const sellerPoint = getPerCommitmentPoint(sellerCommitSeed, 0n);

			const sellerLeaseSpk = p2wsh(
				handBuiltLeaseToRemote(seller.basepoints.paymentBasepoint, LEASE_CSV)
			);
			const buyerLeaseSpk = p2wsh(
				handBuiltLeaseToRemote(buyer.basepoints.paymentBasepoint, LEASE_CSV)
			);
			const buyerPlainSpk = p2wsh(
				buildToRemoteAnchorScript(buyer.basepoints.paymentBasepoint)
			);

			// Quadrant 1+2: the buyer's commitment (buyer-local == seller-remote):
			// seller's to_remote LEASED.
			const buyerLocal = buildLocalCommitment(buyerState, buyerPoint);
			const sellerRemote = buildRemoteCommitment(sellerState, buyerPoint);
			for (const tx of [buyerLocal.result.tx, sellerRemote.result.tx]) {
				const outs = tx.outs.map((o) => o.script);
				expect(outs.some((s) => s.equals(sellerLeaseSpk))).to.be.true;
			}

			// Quadrant 3+4: the seller's commitment (seller-local == buyer-remote):
			// buyer's to_remote PLAIN (the buyer is not the lessor); the lock on
			// this commitment lives in the seller's to_local instead.
			const sellerLocal = buildLocalCommitment(sellerState, sellerPoint);
			const buyerRemote = buildRemoteCommitment(buyerState, sellerPoint);
			for (const tx of [sellerLocal.result.tx, buyerRemote.result.tx]) {
				const outs = tx.outs.map((o) => o.script);
				expect(
					outs.some((s) => s.equals(buyerPlainSpk)),
					'buyer to_remote stays plain'
				).to.be.true;
				expect(outs.some((s) => s.equals(buyerLeaseSpk))).to.be.false;
			}
		});

		it('anti-inversion: both sides build the identical buyer commitment', function () {
			const { buyerState, sellerState, buyerCommitSeed } =
				createLeasedChannelStates();
			const point = getPerCommitmentPoint(buyerCommitSeed, 0n);
			const fromBuyer = buildLocalCommitment(buyerState, point);
			const fromSeller = buildRemoteCommitment(sellerState, point);
			expect(
				fromBuyer.result.tx.toBuffer().equals(fromSeller.result.tx.toBuffer()),
				'buyer-local and seller-remote commitments byte-identical'
			).to.be.true;
		});

		it('non-lease anchor channels are unchanged (plain to_remote)', function () {
			const { buyerState, seller, buyerCommitSeed } =
				createLeasedChannelStates(false);
			const point = getPerCommitmentPoint(buyerCommitSeed, 0n);
			const built = buildLocalCommitment(buyerState, point);
			const plainSpk = p2wsh(
				buildToRemoteAnchorScript(seller.basepoints.paymentBasepoint)
			);
			expect(built.result.tx.outs.some((o) => o.script.equals(plainSpk))).to.be
				.true;
		});
	});

	describe('classification + sweep (lessor claims after buyer force-close)', function () {
		it('classifies the lease-locked to_remote and sweeps with input sequence = lease_csv', function () {
			const { sellerState, seller, buyerCommitSeed } =
				createLeasedChannelStates();
			// The buyer force-closes: the buyer's commitment is the seller's
			// REMOTE commitment.
			const buyerPoint = getPerCommitmentPoint(buyerCommitSeed, 0n);
			const built = buildRemoteCommitment(sellerState, buyerPoint);

			const tracked = classifyOutputs(
				built.result.tx,
				sellerState,
				CommitmentType.THEIR_CURRENT_COMMITMENT,
				sellerState.remoteCommitmentNumber
			);
			const toRemote = tracked.find(
				(o) => o.outputType === OutputType.TO_REMOTE
			);
			expect(toRemote, 'lease-locked to_remote classified').to.exist;
			expect(toRemote!.witnessScript).to.exist;
			expect(leaseCsvFromToRemoteScript(toRemote!.witnessScript!)).to.equal(
				LEASE_CSV
			);

			const destScript = bitcoin.payments.p2wpkh({
				hash: crypto.randomBytes(20)
			}).output!;
			const resolved = resolveTheirCurrentCommitmentOutputs(
				sellerState,
				[toRemote!],
				destScript,
				4,
				new Map(),
				seller.privkeys[2] // payment basepoint secret
			);
			const claim = resolved.find(
				(r) => r.trackedOutput.outputType === OutputType.TO_REMOTE
			);
			expect(claim?.spendTx, 'to_remote claim built').to.exist;
			// Pure CSV: no nLockTime, input sequence = lease_csv.
			expect(claim!.spendTx!.locktime).to.equal(0);
			expect(claim!.spendTx!.ins[0].sequence).to.equal(LEASE_CSV);
			// Witness spends the lease script: [sig, leaseWitnessScript].
			expect(claim!.witness).to.have.length(2);
			expect(claim!.witness![1].equals(toRemote!.witnessScript!)).to.be.true;
			// The pre-signed claim signature verifies over the LEASE script.
			const sighash = claim!.spendTx!.hashForWitnessV0(
				0,
				toRemote!.witnessScript!,
				Number(toRemote!.amount),
				bitcoin.Transaction.SIGHASH_ALL
			);
			// static_remotekey: the to_remote pays the STATIC payment basepoint.
			const sigDer = claim!.witness![0];
			const sig = bitcoin.script.signature.decode(sigDer).signature;
			expect(
				ecc.verify(sighash, seller.basepoints.paymentBasepoint, sig),
				'claim signature valid over the lease witness script'
			).to.be.true;
		});

		it('classifies the lessor lease-locked to_remote on the BUYER OWN commitment', function () {
			// The seller's balance on the buyer's OWN commitment is the same
			// lease-locked CSV variant; classification of OUR commitment used to
			// match only the plain P2WPKH and silently skipped it.
			const { buyerState, buyerCommitSeed } = createLeasedChannelStates();
			const buyerPoint = getPerCommitmentPoint(buyerCommitSeed, 0n);
			const built = buildLocalCommitment(buyerState, buyerPoint);

			const tracked = classifyOutputs(
				built.result.tx,
				buyerState,
				CommitmentType.OUR_COMMITMENT,
				buyerState.localCommitmentNumber
			);
			const toRemote = tracked.find(
				(o) => o.outputType === OutputType.TO_REMOTE
			);
			expect(toRemote, 'lease-locked to_remote classified on own commitment').to
				.exist;
			expect(toRemote!.witnessScript).to.exist;
			expect(leaseCsvFromToRemoteScript(toRemote!.witnessScript!)).to.equal(
				LEASE_CSV
			);
		});

		it('SCB-restored (DLP) states still find and lock the lease to_remote', function () {
			const { sellerState, buyerCommitSeed } = createLeasedChannelStates();
			const buyerPoint = getPerCommitmentPoint(buyerCommitSeed, 0n);
			const built = buildRemoteCommitment(sellerState, buyerPoint);

			// SCB recovery: no remote basepoints, lease fields restored from the
			// backup entry (see recoverFromStaticChannelBackup).
			const recovered = { ...sellerState };
			recovered.remoteBasepoints = null;
			recovered.dataLossDetected = true;

			const tracked = classifyOutputs(
				built.result.tx,
				recovered,
				CommitmentType.THEIR_FUTURE_COMMITMENT,
				0n
			);
			const toRemote = tracked.find(
				(o) => o.outputType === OutputType.TO_REMOTE
			);
			expect(toRemote, 'to_remote found without remote basepoints').to.exist;
			expect(leaseCsvFromToRemoteScript(toRemote!.witnessScript!)).to.equal(
				LEASE_CSV
			);
		});
	});

	describe('SCB carries the lease fields', function () {
		it('round-trips leaseExpiry/isLessor/leaseCommitBlockheight and still decodes legacy entries', function () {
			const seed = crypto.randomBytes(32);
			const base: IScbChannelEntry = {
				channelId: 'aa'.repeat(32),
				peerNodeId: '02' + 'bb'.repeat(32),
				peerAddresses: [],
				fundingTxid: 'cc'.repeat(32),
				fundingOutputIndex: 0,
				fundingSatoshis: '1000000',
				channelKeyIndex: 1,
				channelType: '401000',
				role: 'ACCEPTOR',
				isTaproot: false,
				isAnchor: true
			};
			const leased: IScbChannelEntry = {
				...base,
				leaseExpiry: LEASE_EXPIRY,
				isLessor: true,
				leaseCommitBlockheight: LEASE_COMMIT_BH
			};
			const encoded = encodeScb(
				{
					version: 1,
					network: 'regtest',
					createdAt: 1_700_000_000_000,
					channels: [leased, base]
				},
				seed
			);
			const decoded = decodeScb(encoded, seed);
			expect(decoded.channels[0].leaseExpiry).to.equal(LEASE_EXPIRY);
			expect(decoded.channels[0].isLessor).to.equal(true);
			expect(decoded.channels[0].leaseCommitBlockheight).to.equal(
				LEASE_COMMIT_BH
			);
			// Legacy-shaped entry (no lease fields) decodes unchanged.
			expect(decoded.channels[1].leaseExpiry).to.be.undefined;
			expect(decoded.channels[1].isLessor).to.be.undefined;
		});
	});
});
