/**
 * Regression: the taproot penalty (justice) builder must not hand bitcoinjs a
 * negative output value when the fee exceeds what the batch is worth.
 *
 * buildAndSignPenalty summed its input values into a JavaScript `number`, the
 * only aggregate on-chain amount in the file not kept in bigint, and it was
 * also the only one with no `totalIn > fee` check. `addOutput` typeforces a
 * non-negative Satoshi, so an unaffordable batch threw.
 *
 * The deadline split makes that worse than a single lost sweep: an HTLC input
 * near its cltv_expiry gets its OWN penalty tx, so a small, expiring HTLC threw
 * before the batched penalty holding their to_local was ever built. The whole
 * breach remedy went with it.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	isTaprootChannel
} from '../../src/lightning/channel/types';
import {
	OutputType,
	OutputStatus,
	ITrackedOutput
} from '../../src/lightning/chain/types';
import {
	resolveRevokedCommitmentOutputs,
	IResolvedOutput
} from '../../src/lightning/chain/output-resolver';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { MAX_INDEX } from '../../src/lightning/keys/shachain';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { IChannelState } from '../../src/lightning/channel/channel-state';

bitcoin.initEccLib(ecc);
const NETWORK = bitcoin.networks.regtest;

function seedFor(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`taproot-penalty-guard-${id}`))
		.digest();
}

function privAt(seed: Buffer, i: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([i]))
		.digest();
}

function basepointsOf(seed: Buffer): IChannelBasepoints {
	return {
		fundingPubkey: getPublicKey(privAt(seed, 0)),
		revocationBasepoint: getPublicKey(privAt(seed, 1)),
		paymentBasepoint: getPublicKey(privAt(seed, 2)),
		delayedPaymentBasepoint: getPublicKey(privAt(seed, 3)),
		htlcBasepoint: getPublicKey(privAt(seed, 4)),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

function configOf(seed: Buffer, preferTaproot: boolean): IChannelManagerConfig {
	return {
		localConfig: { ...DEFAULT_CHANNEL_CONFIG, feeratePerKw: 2500 },
		localBasepoints: basepointsOf(seed),
		localPerCommitmentSeed: seedFor(1000 + seed[0]),
		localFundingPrivkey: privAt(seed, 0),
		htlcBasepointSecret: privAt(seed, 4),
		preferTaproot
	};
}

function connect(
	a: ChannelManager,
	aPub: string,
	b: ChannelManager,
	bPub: string
): void {
	a.on('message:outbound', (peer: string, type: number, payload: Buffer) => {
		if (peer === bPub) b.handleMessage(aPub, type, payload);
	});
	b.on('message:outbound', (peer: string, type: number, payload: Buffer) => {
		if (peer === aPub) a.handleMessage(bPub, type, payload);
	});
}

/**
 * A taproot channel advanced past commitment #1, so we hold the peer's revoked
 * #1 per-commitment secret and can drive the justice path against it.
 */
function revokedTaprootSetup(): {
	state: IChannelState;
	aliceSeed: Buffer;
	destScript: Buffer;
} {
	const aliceSeed = seedFor(1);
	const bobSeed = seedFor(2);
	const aliceCfg = configOf(aliceSeed, true);
	const bobCfg = configOf(bobSeed, false);
	const alice = new ChannelManager(aliceCfg);
	const bob = new ChannelManager(bobCfg);
	const aPub = aliceCfg.localBasepoints.fundingPubkey.toString('hex');
	const bPub = bobCfg.localBasepoints.fundingPubkey.toString('hex');
	connect(alice, aPub, bob, bPub);

	const aliceChannel = alice.openChannel(bPub, 3_000_000n);
	const channelId = alice.createFunding(
		aliceChannel,
		crypto.randomBytes(32),
		0,
		crypto.randomBytes(64)
	)!;
	alice.handleFundingConfirmed(channelId);
	bob.handleFundingConfirmed(channelId);
	expect(isTaprootChannel(aliceChannel.getFullState().channelType)).to.equal(
		true
	);
	expect(aliceChannel.getFullState().state).to.equal(ChannelState.NORMAL);

	// Advance past #1 so Bob's #1 per-commitment secret is revealed to us.
	expect(alice.updateChannelFee(channelId, 700).ok).to.equal(true);
	expect(alice.updateChannelFee(channelId, 800).ok).to.equal(true);

	const state = aliceChannel.getFullState();
	expect(Number(state.remoteCommitmentNumber)).to.be.greaterThan(1);
	expect(
		state.shaChainStore.getSecret(MAX_INDEX - 1n),
		"Bob's revoked #1 secret is held"
	).to.not.be.undefined;

	const destScript = bitcoin.payments.p2wpkh({
		pubkey: getPublicKey(privAt(aliceSeed, 9)),
		network: NETWORK
	}).output!;

	return { state, aliceSeed, destScript };
}

/**
 * A revoked commitment carrying their to_local plus one HTLC. cltvExpiry drives
 * the deadline split: near CURRENT_HEIGHT the HTLC gets its own penalty tx, far
 * from it both inputs share one batched tx.
 */
function trackedFor(
	toLocalSats: bigint,
	htlcSats: bigint,
	cltvExpiry = 705
): ITrackedOutput[] {
	const txid = crypto.randomBytes(32).toString('hex');
	return [
		{
			txid,
			outputIndex: 0,
			amount: toLocalSats,
			outputType: OutputType.TO_LOCAL,
			status: OutputStatus.CONFIRMED,
			confirmationHeight: 0
		},
		{
			txid,
			outputIndex: 1,
			amount: htlcSats,
			outputType: OutputType.OFFERED_HTLC,
			status: OutputStatus.CONFIRMED,
			confirmationHeight: 0,
			paymentHash: crypto.randomBytes(32),
			cltvExpiry
		}
	];
}

/** An empty stand-in: the taproot justice path reads amounts from tracked outputs. */
function emptyRevokedTx(): bitcoin.Transaction {
	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.addInput(crypto.randomBytes(32), 0);
	return tx;
}

const CURRENT_HEIGHT = 700;

function resolve(
	state: IChannelState,
	aliceSeed: Buffer,
	destScript: Buffer,
	tracked: ITrackedOutput[],
	feeRatePerVbyte: number
): IResolvedOutput[] {
	return resolveRevokedCommitmentOutputs(
		state,
		tracked,
		1n,
		emptyRevokedTx(),
		destScript,
		feeRatePerVbyte,
		privAt(aliceSeed, 1), // revocation basepoint secret
		privAt(aliceSeed, 2), // payment privkey
		NETWORK,
		CURRENT_HEIGHT
	);
}

describe('taproot penalty fee guard', function () {
	this.timeout(20_000);

	it('does not throw when the fee exceeds the whole batch', function () {
		const { state, aliceSeed, destScript } = revokedTaprootSetup();

		expect(() => {
			resolve(
				state,
				aliceSeed,
				destScript,
				trackedFor(50_000n, 20_000n),
				100_000 // ruinous feerate
			);
		}, 'an unaffordable penalty batch must not throw').to.not.throw();
	});

	it('builds the penalty at an affordable feerate', function () {
		const { state, aliceSeed, destScript } = revokedTaprootSetup();

		const resolved = resolve(
			state,
			aliceSeed,
			destScript,
			trackedFor(1_000_000n, 400_000n),
			5
		);

		expect(resolved.length, 'both penalty inputs resolved').to.equal(2);
		for (const r of resolved) {
			expect(r.spendTx, 'each input has a penalty spend').to.exist;
			expect(
				r.spendTx!.outs[0].value,
				'the penalty output is positive'
			).to.be.greaterThan(0);
		}
	});

	it('an unaffordable expiring HTLC no longer takes the to_local penalty with it', function () {
		const { state, aliceSeed, destScript } = revokedTaprootSetup();

		// The HTLC is near expiry so the deadline split gives it its own penalty
		// tx, and it is far too small to pay for one. Their to_local is large and
		// is what the batched penalty must still claim.
		const tracked = trackedFor(2_000_000n, 300n);

		const resolved = resolve(state, aliceSeed, destScript, tracked, 50);

		const toLocal = resolved.find(
			(r) => r.trackedOutput.outputType === OutputType.TO_LOCAL
		);
		expect(
			toLocal,
			'the batched to_local penalty was still built, which is what the throw prevented'
		).to.exist;
		expect(toLocal!.spendTx, 'and it carries a real spend').to.exist;

		const htlc = resolved.find(
			(r) => r.trackedOutput.outputType === OutputType.OFFERED_HTLC
		);
		expect(htlc, 'the unaffordable HTLC produced no penalty').to.equal(
			undefined
		);
	});

	it('skips an unaffordable batch entirely rather than building a dust penalty', function () {
		const { state, aliceSeed, destScript } = revokedTaprootSetup();

		// Both inputs together cannot cover the fee.
		const resolved = resolve(
			state,
			aliceSeed,
			destScript,
			trackedFor(400n, 300n, CURRENT_HEIGHT + 5000),
			50
		);

		expect(resolved, 'nothing unbroadcastable was produced').to.have.length(0);
	});

	it('accumulates every input of a batched penalty into one output', function () {
		const { state, aliceSeed, destScript } = revokedTaprootSetup();

		// A far-off expiry keeps the HTLC out of the urgent split, so both inputs
		// share one penalty tx and the accumulator is exercised across them.
		const resolved = resolve(
			state,
			aliceSeed,
			destScript,
			trackedFor(1_000_000n, 400_000n, CURRENT_HEIGHT + 5000),
			5
		);

		expect(resolved.length, 'both inputs resolved').to.equal(2);
		const tx = resolved[0].spendTx!;
		expect(
			resolved[1].spendTx,
			'both share the same batched penalty tx'
		).to.equal(tx);
		expect(tx.ins.length, 'the batch spends both outputs').to.equal(2);

		const totalIn = 1_000_000 + 400_000;
		expect(
			tx.outs[0].value,
			'the output is the SUM of both inputs minus the fee, not just one'
		).to.be.greaterThan(totalIn - 50_000);
		expect(tx.outs[0].value, 'and it does pay a fee').to.be.lessThan(totalIn);
	});
});
