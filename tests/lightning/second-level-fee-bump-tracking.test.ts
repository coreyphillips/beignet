/**
 * Regression: on anchor channels the pre-signed second-level HTLC tx is
 * zero-fee, so the broadcast variant has wallet fee inputs attached, which
 * CHANGES ITS TXID. ChainMonitor.handleOutputSpent used to recognize our own
 * second-level HTLC tx purely by txid, so the fee-bumped variant was treated
 * as a foreign spend: its CSV-delayed output was never tracked and never
 * swept, silently stranding the HTLC value after every fee-bumped
 * force-close claim.
 *
 * The fix matches on what fee attachment cannot change: input 0 spends the
 * same HTLC outpoint with the identical pre-signed witness
 * (SIGHASH_SINGLE|ANYONECANPAY preserves both).
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import {
	buildLocalCommitment,
	signRemoteCommitment
} from '../../src/lightning/channel/commitment-builder';
import {
	createOpenerState,
	createAcceptorState,
	IChannelState
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
import { ChainMonitor } from '../../src/lightning/chain/chain-monitor';
import {
	ChainActionType,
	OutputType,
	OutputStatus
} from '../../src/lightning/chain/types';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';

bitcoin.initEccLib(ecc);

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`sl-feebump-${id}`))
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

const DEST_SCRIPT = Buffer.concat([
	Buffer.from([0x00, 0x14]),
	Buffer.alloc(20, 0x0d)
]);

/**
 * An anchor channel where WE (the opener) hold one inbound HTLC with a known
 * preimage, our commitment is on-chain, and the monitor has produced the
 * pre-signed zero-fee HTLC-success tx for it.
 */
function setup(): {
	monitor: ChainMonitor;
	commitmentTx: bitcoin.Transaction;
	htlcOutputIndex: number;
	successTx: bitcoin.Transaction;
	openerState: IChannelState;
} {
	const openerSeed = makeSeed(1);
	const acceptorSeed = makeSeed(2);
	const openerCommitSeed = makeSeed(3);
	const acceptorCommitSeed = makeSeed(4);
	const ob = basepoints(openerSeed);
	const ab = basepoints(acceptorSeed);
	ob.firstPerCommitmentPoint = point(openerCommitSeed, 0n);
	ab.firstPerCommitmentPoint = point(acceptorCommitSeed, 0n);

	const fundingTxid = crypto.createHash('sha256').update('fund').digest();
	const channelId = deriveChannelId(fundingTxid, 0);
	const channelType = anchorChannelType();

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

	const preimage = crypto.randomBytes(32);
	const paymentHash = crypto.createHash('sha256').update(preimage).digest();
	const htlc = {
		id: 0n,
		amountMsat: 50_000_000n,
		paymentHash,
		cltvExpiry: 500_000,
		onionRoutingPacket: Buffer.alloc(1366),
		state: HtlcState.COMMITTED
	};
	openerState.htlcs.set('h', { ...htlc, direction: HtlcDirection.RECEIVED });
	acceptorState.htlcs.set('h', { ...htlc, direction: HtlcDirection.OFFERED });

	// The peer's real signature over our commitment's HTLC-success tx.
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

	const built = buildLocalCommitment(openerState, openerLocalPoint);
	const commitmentTx = built.result.tx;

	const monitor = new ChainMonitor(
		openerState,
		DEST_SCRIPT,
		10,
		priv(openerSeed, 1),
		priv(openerSeed, 2),
		undefined,
		priv(openerSeed, 3),
		priv(openerSeed, 4)
	);
	monitor.addPreimage(paymentHash, preimage);

	// Our commitment confirms; the 1-CSV anchor hold releases one block later,
	// producing the pre-signed zero-fee HTLC-success tx.
	monitor.handleFundingSpent(commitmentTx, 100);
	const actions = monitor.handleNewBlock(101);
	const feeBump = actions.find(
		(a) => a.type === ChainActionType.FEE_BUMP_AND_BROADCAST
	) as { tx: Buffer } | undefined;
	expect(feeBump, 'zero-fee HTLC-success routed to fee attach').to.not.equal(
		undefined
	);
	const successTx = bitcoin.Transaction.fromBuffer(feeBump!.tx);
	expect(successTx.ins[0].witness.length).to.equal(5);

	const htlcOutput = monitor
		.getTrackedOutputs()
		.find((o) => o.outputType === OutputType.RECEIVED_HTLC)!;
	expect(htlcOutput).to.not.equal(undefined);

	return {
		monitor,
		commitmentTx,
		htlcOutputIndex: htlcOutput.outputIndex,
		successTx,
		openerState
	};
}

/**
 * What the wallet's fee attachment produces: the same pre-signed tx with an
 * extra fee input (its own witness) and a change output appended. Input 0
 * (outpoint + witness) is untouched thanks to SIGHASH_SINGLE|ANYONECANPAY,
 * but the txid differs from the pre-signed template.
 */
function feeBumpedVariant(successTx: bitcoin.Transaction): bitcoin.Transaction {
	const bumped = successTx.clone();
	bumped.addInput(crypto.randomBytes(32), 0, 1);
	bumped.setWitness(1, [Buffer.alloc(72, 0x30), Buffer.alloc(33, 0x02)]);
	bumped.addOutput(
		Buffer.concat([Buffer.from([0x00, 0x14]), Buffer.alloc(20, 0x0c)]),
		30_000
	);
	expect(bumped.getId()).to.not.equal(successTx.getId());
	return bumped;
}

describe('Fee-bumped second-level HTLC tracking (anchor channels)', function () {
	it('tracks the CSV output of a FEE-BUMPED second-level HTLC tx and sweeps it at maturity', function () {
		const t = setup();
		const bumped = feeBumpedVariant(t.successTx);

		// The confirmed spend of our HTLC output is the fee-bumped variant.
		const spendHeight = 102;
		t.monitor.handleOutputSpent(
			t.commitmentTx.getId(),
			t.htlcOutputIndex,
			bumped,
			spendHeight
		);

		// The second-level CSV output (bumpedTxid:0) must now be tracked...
		const tracked = t.monitor
			.getTrackedOutputs()
			.find((o) => o.txid === bumped.getId() && o.outputIndex === 0);
		expect(
			tracked,
			'CSV output of the fee-bumped HTLC tx is tracked'
		).to.not.equal(undefined);

		// ...and swept once to_self_delay matures.
		const maturity = spendHeight + DEFAULT_CHANNEL_CONFIG.toSelfDelay;
		const actions = t.monitor.handleNewBlock(maturity);
		const sweeps = actions
			.filter((a) => a.type === ChainActionType.BROADCAST_TX)
			.map((a) => bitcoin.Transaction.fromBuffer((a as { tx: Buffer }).tx))
			.filter(
				(tx) =>
					Buffer.from(tx.ins[0].hash).equals(bumped.getHash()) &&
					tx.ins[0].index === 0
			);
		expect(sweeps.length, 'second-level sweep broadcast at maturity').to.equal(
			1
		);
		expect(Buffer.from(sweeps[0].outs[0].script).equals(DEST_SCRIPT)).to.equal(
			true
		);
		expect(tracked!.status).to.equal(OutputStatus.SPEND_BROADCAST);
	});

	it('still tracks the unbumped (same-txid) second-level HTLC tx', function () {
		const t = setup();
		const spendHeight = 102;
		t.monitor.handleOutputSpent(
			t.commitmentTx.getId(),
			t.htlcOutputIndex,
			t.successTx,
			spendHeight
		);
		const tracked = t.monitor
			.getTrackedOutputs()
			.find((o) => o.txid === t.successTx.getId() && o.outputIndex === 0);
		expect(tracked).to.not.equal(undefined);
	});

	it('does NOT track a foreign spend of the HTLC output (different tx, different witness)', function () {
		const t = setup();
		// Same outpoint, but not our pre-signed tx: e.g. the peer's competing
		// direct claim. Different outputs (so a different txid) AND a different
		// input-0 witness stack; it must not be adopted as our second-level tx.
		const foreign = new bitcoin.Transaction();
		foreign.version = 2;
		foreign.addInput(
			Buffer.from(t.successTx.ins[0].hash),
			t.successTx.ins[0].index,
			1
		);
		foreign.addOutput(
			Buffer.concat([Buffer.from([0x00, 0x14]), Buffer.alloc(20, 0x0e)]),
			45_000
		);
		foreign.setWitness(0, [
			Buffer.alloc(72, 0x31),
			Buffer.alloc(33, 0x03),
			Buffer.alloc(32, 0x04)
		]);
		expect(foreign.getId()).to.not.equal(t.successTx.getId());
		t.monitor.handleOutputSpent(
			t.commitmentTx.getId(),
			t.htlcOutputIndex,
			foreign,
			102
		);
		const tracked = t.monitor
			.getTrackedOutputs()
			.find((o) => o.txid === foreign.getId() && o.outputIndex === 0);
		expect(tracked).to.equal(undefined);
	});

	it('does NOT adopt a spend with a matching input-0 witness but tampered output 0 (value)', function () {
		const t = setup();
		// Same prevout, byte-identical pre-signed input-0 witness, wallet fee
		// input attached, but output 0 carries the wrong value: adoption must be
		// rejected by the explicit output-0 validation.
		const tampered = feeBumpedVariant(t.successTx);
		tampered.outs[0].value = t.successTx.outs[0].value - 1_000;
		t.monitor.handleOutputSpent(
			t.commitmentTx.getId(),
			t.htlcOutputIndex,
			tampered,
			102
		);
		const tracked = t.monitor
			.getTrackedOutputs()
			.find((o) => o.txid === tampered.getId() && o.outputIndex === 0);
		expect(tracked).to.equal(undefined);
	});

	it('does NOT adopt a spend with a matching input-0 witness but tampered output 0 (script)', function () {
		const t = setup();
		const tampered = feeBumpedVariant(t.successTx);
		tampered.outs[0].script = Buffer.concat([
			Buffer.from([0x00, 0x14]),
			Buffer.alloc(20, 0x0f)
		]);
		t.monitor.handleOutputSpent(
			t.commitmentTx.getId(),
			t.htlcOutputIndex,
			tampered,
			102
		);
		const tracked = t.monitor
			.getTrackedOutputs()
			.find((o) => o.txid === tampered.getId() && o.outputIndex === 0);
		expect(tracked).to.equal(undefined);
	});
});
