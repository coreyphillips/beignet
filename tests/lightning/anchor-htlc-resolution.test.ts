import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import {
	deriveCommitmentKeys,
	buildLocalCommitment,
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
import { getPublicKey, verify } from '../../src/lightning/crypto/ecdh';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import { deriveChannelId } from '../../src/lightning/channel/validation';
import {
	classifyOutputs,
	resolveOurCommitmentOutputs
} from '../../src/lightning/chain/output-resolver';
import { CommitmentType, OutputType } from '../../src/lightning/chain/types';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';

bitcoin.initEccLib(ecc);

const SIGHASH_ALL = bitcoin.Transaction.SIGHASH_ALL;
const SIGHASH_ANCHOR =
	bitcoin.Transaction.SIGHASH_SINGLE | bitcoin.Transaction.SIGHASH_ANYONECANPAY;

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`anchor-htlc-${id}`))
		.digest();
}
function priv(seed: Buffer, i: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([i]))
		.digest();
}
function basepoints(seed: Buffer): IChannelBasepoints {
	return {
		fundingPubkey: getPublicKey(priv(seed, 0)),
		revocationBasepoint: getPublicKey(priv(seed, 1)),
		paymentBasepoint: getPublicKey(priv(seed, 2)),
		delayedPaymentBasepoint: getPublicKey(priv(seed, 3)),
		htlcBasepoint: getPublicKey(priv(seed, 4)),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}
function point(seed: Buffer, n: bigint): Buffer {
	return perCommitmentPointFromSecret(generateFromSeed(seed, MAX_INDEX - n));
}

function anchorChannelType(): Buffer {
	const f = FeatureFlags.empty();
	f.setCompulsory(Feature.STATIC_REMOTE_KEY);
	f.setCompulsory(Feature.ANCHOR_ZERO_FEE_HTLC);
	return f.toBuffer();
}

/**
 * Build a NORMAL opener+acceptor channel where the opener holds one inbound
 * (RECEIVED) HTLC, with the acceptor's real second-level HTLC signature over the
 * opener's commitment stored as opener.remoteHtlcSignatures. Returns everything
 * needed to run + verify the on-chain resolver on the opener's own commitment.
 */
function setup(anchor: boolean) {
	const openerSeed = makeSeed(1),
		acceptorSeed = makeSeed(2);
	const openerCommitSeed = makeSeed(3),
		acceptorCommitSeed = makeSeed(4);
	const ob = basepoints(openerSeed),
		ab = basepoints(acceptorSeed);
	ob.firstPerCommitmentPoint = point(openerCommitSeed, 0n);
	ab.firstPerCommitmentPoint = point(acceptorCommitSeed, 0n);

	const fundingTxid = crypto
		.createHash('sha256')
		.update(Buffer.from('fund'))
		.digest();
	const channelId = deriveChannelId(fundingTxid, 0);
	const channelType = anchor ? anchorChannelType() : null;

	const openerState = createOpenerState({
		temporaryChannelId: crypto.randomBytes(32),
		fundingSatoshis: 1_000_000n,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: ob,
		localPerCommitmentSeed: openerCommitSeed
	});
	openerState.remoteBasepoints = ab;
	openerState.remoteConfig = { ...DEFAULT_CHANNEL_CONFIG };
	openerState.fundingTxid = fundingTxid;
	openerState.fundingOutputIndex = 0;
	openerState.channelId = channelId;
	openerState.state = ChannelState.NORMAL;
	openerState.remoteCurrentPerCommitmentPoint = ab.firstPerCommitmentPoint;
	openerState.channelType = channelType;
	openerState.localBalanceMsat = 700_000_000n;
	openerState.remoteBalanceMsat = 300_000_000n;

	const acceptorState = createAcceptorState({
		temporaryChannelId: openerState.temporaryChannelId,
		fundingSatoshis: 1_000_000n,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: ab,
		localPerCommitmentSeed: acceptorCommitSeed,
		remoteBasepoints: ob,
		remoteConfig: { ...DEFAULT_CHANNEL_CONFIG }
	});
	acceptorState.fundingTxid = fundingTxid;
	acceptorState.fundingOutputIndex = 0;
	acceptorState.channelId = channelId;
	acceptorState.state = ChannelState.NORMAL;
	acceptorState.remoteCurrentPerCommitmentPoint = ob.firstPerCommitmentPoint;
	acceptorState.channelType = channelType;
	acceptorState.localBalanceMsat = 300_000_000n;
	acceptorState.remoteBalanceMsat = 700_000_000n;

	// One inbound HTLC for the opener (received); mirror as offered on acceptor.
	const preimage = crypto.randomBytes(32);
	const paymentHash = crypto.createHash('sha256').update(preimage).digest();
	const htlc = {
		id: 0n,
		amountMsat: 50_000_000n,
		paymentHash,
		cltvExpiry: 500000,
		onionRoutingPacket: Buffer.alloc(1366),
		state: HtlcState.COMMITTED
	};
	openerState.htlcs.set('h', { ...htlc, direction: HtlcDirection.RECEIVED });
	acceptorState.htlcs.set('h', { ...htlc, direction: HtlcDirection.OFFERED });

	// Acceptor signs the opener's commitment (opener is acceptor's "remote").
	const acceptorSigner = new ChannelSigner(
		priv(acceptorSeed, 0),
		priv(acceptorSeed, 4)
	);
	const openerLocalPoint = point(openerCommitSeed, 0n);
	const { htlcSignatures } = signRemoteCommitment(
		acceptorState,
		acceptorSigner,
		openerLocalPoint
	);
	openerState.remoteHtlcSignatures = htlcSignatures;

	// Build the opener's own commitment + classify its outputs (force-close on us).
	const built = buildLocalCommitment(openerState, openerLocalPoint);
	const tracked = classifyOutputs(
		built.result.tx,
		openerState,
		CommitmentType.OUR_COMMITMENT,
		0n
	);

	const resolved = resolveOurCommitmentOutputs(
		openerState,
		tracked,
		0n,
		Buffer.concat([Buffer.from([0x00, 0x14]), Buffer.alloc(20)]),
		10,
		new Map([[paymentHash.toString('hex'), preimage]]),
		priv(openerSeed, 3),
		priv(openerSeed, 4),
		htlcSignatures
	);

	const keys = deriveCommitmentKeys(
		openerState.localBasepoints,
		openerState.remoteBasepoints!,
		openerLocalPoint,
		true
	);
	return {
		resolved,
		htlcSignatures,
		remoteHtlcPubkey: keys.remoteHtlcPubkey,
		htlcAmount: 50_000n
	};
}

describe('On-chain HTLC second-level resolution (our commitment)', function () {
	for (const anchor of [false, true]) {
		const label = anchor ? 'anchor' : 'non-anchor';
		it(`builds a valid HTLC-success witness that matches the peer's signature (${label})`, function () {
			const { resolved, htlcSignatures, remoteHtlcPubkey, htlcAmount } =
				setup(anchor);

			const htlc = resolved.find(
				(r) => r.trackedOutput.outputType === OutputType.RECEIVED_HTLC
			);
			expect(htlc, 'received HTLC resolved').to.exist;
			expect(htlc!.spendTx, 'spendTx built').to.exist;
			expect(htlc!.witness, 'witness built').to.exist;

			const spendTx = htlc!.spendTx!;
			const ws = htlc!.trackedOutput.witnessScript!;
			const amount = Number(htlc!.trackedOutput.amount);
			const sighashType = anchor ? SIGHASH_ANCHOR : SIGHASH_ALL;

			// The decisive check: the peer's signature must validate against the tx
			// the resolver actually built (same variant + sighash). If the resolver
			// builds the wrong variant for anchors, this fails.
			const sigHash = spendTx.hashForWitnessV0(0, ws, amount, sighashType);
			expect(
				verify(sigHash, remoteHtlcPubkey, htlcSignatures[0]),
				'peer HTLC signature verifies against resolver tx'
			).to.equal(true);

			// Anchor second-level tx is zero-fee with a 1-block CSV.
			if (anchor) {
				expect(spendTx.ins[0].sequence).to.equal(1);
				expect(BigInt(spendTx.outs[0].value)).to.equal(htlcAmount); // full amount, no fee deducted
			}

			// Witness signatures must be DER-encoded with the correct trailing
			// sighash byte (not raw 64-byte compact).
			const witness = htlc!.witness!;
			const remoteSigEl = witness[1];
			const localSigEl = witness[2];
			expect(remoteSigEl[0]).to.equal(0x30); // DER sequence tag
			expect(remoteSigEl[remoteSigEl.length - 1]).to.equal(sighashType);
			expect(localSigEl[0]).to.equal(0x30);
			expect(localSigEl[localSigEl.length - 1]).to.equal(sighashType);
		});
	}
});
