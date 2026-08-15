/**
 * Regression: the taproot output resolvers must not hand bitcoinjs a negative
 * output value when the sweep fee exceeds what the output is worth.
 *
 * `addOutput` typeforces a non-negative Satoshi, so `Number(amount - fee)` threw
 * a TypeError. Three of the four unguarded sites sat inside a loop over one
 * commitment's outputs, so the throw abandoned the sweeps for every output
 * AFTER the offending one, not just that output's own. On a revoked commitment
 * it abandoned the penalty batch entirely, because the penalty is assembled
 * after that loop finishes.
 *
 * The witness-v0 builders in sweep.ts and two of the taproot revoked-path
 * resolvers already guarded; these four did not.
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
	buildLocalCommitment,
	buildRemoteCommitment
} from '../../src/lightning/channel/commitment-builder';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import { perCommitmentPointFromSecret } from '../../src/lightning/keys/derivation';
import {
	resolveTheirCurrentCommitmentOutputs,
	resolveOurCommitmentOutputs,
	classifyOutputs
} from '../../src/lightning/chain/output-resolver';
import { CommitmentType, OutputType } from '../../src/lightning/chain/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

bitcoin.initEccLib(ecc);

const NETWORK = bitcoin.networks.regtest;

function seedFor(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`taproot-underflow-${id}`))
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
 * A funded taproot channel carrying one HTLC, force-closed by Alice, plus the
 * material needed to drive the resolvers over its commitment.
 */
function taprootForceClose(): {
	state: ReturnType<ChannelManager['getChannel']> extends null
		? never
		: ReturnType<
				NonNullable<ReturnType<ChannelManager['getChannel']>>['getFullState']
		  >;
	ourCommitTx: bitcoin.Transaction;
	theirCommitTx: bitcoin.Transaction;
	destScript: Buffer;
	aliceSeed: Buffer;
	preimage: Buffer;
	paymentHash: Buffer;
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

	const aliceChannel = alice.openChannel(bPub, 3_000_000n, 1_500_000_000n);
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

	const preimage = crypto.randomBytes(32);
	const paymentHash = crypto.createHash('sha256').update(preimage).digest();
	expect(
		bob.addHtlc(channelId, 300_000_000n, paymentHash, 800, Buffer.alloc(1366))
			.ok
	).to.equal(true);

	const state = aliceChannel.getFullState();

	// Alice's own commitment (to_local + HTLC) and the peer's (our to_remote +
	// HTLC), both taproot.
	const localPoint = perCommitmentPointFromSecret(
		generateFromSeed(
			state.localPerCommitmentSeed,
			MAX_INDEX - state.localCommitmentNumber
		)
	);
	const ourCommitTx = buildLocalCommitment(state, localPoint).result.tx;
	const theirCommitTx = buildRemoteCommitment(
		state,
		state.remoteCurrentPerCommitmentPoint!
	).result.tx;

	const destScript = bitcoin.payments.p2wpkh({
		pubkey: getPublicKey(privAt(aliceSeed, 9)),
		network: NETWORK
	}).output!;

	return {
		state,
		ourCommitTx,
		theirCommitTx,
		destScript,
		aliceSeed,
		preimage,
		paymentHash
	};
}

/**
 * A sweep feerate high enough that the fee exceeds every output on the
 * commitment. This is what a fee spike during a force-close looks like, and it
 * is the condition the builders were not guarding.
 */
const RUINOUS_FEE_RATE = 100_000;

describe('taproot sweep fee underflow', function () {
	this.timeout(20_000);

	it('resolveTheirCurrentCommitmentOutputs does not throw when the fee exceeds every output', function () {
		const {
			state,
			theirCommitTx,
			destScript,
			aliceSeed,
			preimage,
			paymentHash
		} = taprootForceClose();

		const tracked = classifyOutputs(
			theirCommitTx,
			state,
			CommitmentType.THEIR_CURRENT_COMMITMENT,
			state.remoteCommitmentNumber
		);
		expect(
			tracked.length,
			'the commitment has outputs to resolve'
		).to.be.greaterThan(0);

		const knownPreimages = new Map<string, Buffer>([
			[paymentHash.toString('hex'), preimage]
		]);

		let resolved:
			| ReturnType<typeof resolveTheirCurrentCommitmentOutputs>
			| undefined;
		expect(() => {
			resolved = resolveTheirCurrentCommitmentOutputs(
				state,
				tracked,
				destScript,
				RUINOUS_FEE_RATE,
				knownPreimages,
				privAt(aliceSeed, 2),
				privAt(aliceSeed, 4),
				state.remoteCurrentPerCommitmentPoint ?? undefined
			);
		}, 'an unaffordable output must not throw out of the resolver').to.not.throw();

		// Every tracked output is still accounted for, just without a spend.
		expect(resolved!, 'all outputs are still reported').to.have.length(
			tracked.length
		);
		for (const r of resolved!) {
			expect(
				r.spendTx,
				`no unaffordable spend was built for ${r.trackedOutput.outputType}`
			).to.equal(undefined);
		}
	});

	it('resolveOurCommitmentOutputs does not throw when the fee exceeds every output', function () {
		const { state, ourCommitTx, destScript, preimage, paymentHash } =
			taprootForceClose();

		const tracked = classifyOutputs(
			ourCommitTx,
			state,
			CommitmentType.OUR_COMMITMENT,
			state.localCommitmentNumber
		);

		expect(() => {
			resolveOurCommitmentOutputs(
				state,
				tracked,
				state.localCommitmentNumber,
				destScript,
				RUINOUS_FEE_RATE,
				new Map<string, Buffer>([[paymentHash.toString('hex'), preimage]])
			);
		}, 'an unaffordable to_local must not throw out of the resolver').to.not.throw();
	});

	it('still builds the sweep at a feerate the output can afford', function () {
		const {
			state,
			theirCommitTx,
			destScript,
			aliceSeed,
			preimage,
			paymentHash
		} = taprootForceClose();

		const tracked = classifyOutputs(
			theirCommitTx,
			state,
			CommitmentType.THEIR_CURRENT_COMMITMENT,
			state.remoteCommitmentNumber
		);

		const resolved = resolveTheirCurrentCommitmentOutputs(
			state,
			tracked,
			destScript,
			5, // ordinary feerate
			new Map<string, Buffer>([[paymentHash.toString('hex'), preimage]]),
			privAt(aliceSeed, 2),
			privAt(aliceSeed, 4),
			state.remoteCurrentPerCommitmentPoint ?? undefined
		);

		const toRemote = resolved.find(
			(r) => r.trackedOutput.outputType === OutputType.TO_REMOTE
		);
		expect(toRemote, 'our to_remote is present').to.exist;
		expect(toRemote!.spendTx, 'and it is swept at an affordable feerate').to
			.exist;
		expect(
			toRemote!.spendTx!.outs[0].value,
			'the swept value is positive'
		).to.be.greaterThan(0);
	});

	it('skips only the unaffordable output and still sweeps the affordable one', function () {
		const {
			state,
			theirCommitTx,
			destScript,
			aliceSeed,
			preimage,
			paymentHash
		} = taprootForceClose();

		const tracked = classifyOutputs(
			theirCommitTx,
			state,
			CommitmentType.THEIR_CURRENT_COMMITMENT,
			state.remoteCommitmentNumber
		);
		const toRemote = tracked.find((o) => o.outputType === OutputType.TO_REMOTE);
		const htlc = tracked.find(
			(o) =>
				o.outputType === OutputType.OFFERED_HTLC ||
				o.outputType === OutputType.RECEIVED_HTLC
		);
		expect(toRemote, 'commitment carries a to_remote').to.exist;
		expect(htlc, 'commitment carries an HTLC output').to.exist;

		// Starve the HTLC output specifically: shrink it below any plausible fee
		// while leaving to_remote comfortably affordable. Ordering matters, the
		// starved output is resolved before the healthy one.
		const starved = { ...htlc!, amount: 1n };
		const reordered = [starved, toRemote!];

		const resolved = resolveTheirCurrentCommitmentOutputs(
			state,
			reordered,
			destScript,
			5,
			new Map<string, Buffer>([[paymentHash.toString('hex'), preimage]]),
			privAt(aliceSeed, 2),
			privAt(aliceSeed, 4),
			state.remoteCurrentPerCommitmentPoint ?? undefined
		);

		const starvedResult = resolved.find((r) => r.trackedOutput.amount === 1n);
		const healthyResult = resolved.find(
			(r) => r.trackedOutput.outputType === OutputType.TO_REMOTE
		);

		expect(starvedResult, 'the starved output is still reported').to.exist;
		expect(starvedResult!.spendTx, 'but carries no spend').to.equal(undefined);
		expect(healthyResult, 'the output AFTER the starved one still resolved').to
			.exist;
		expect(
			healthyResult!.spendTx,
			'and it was actually swept, which is what the throw used to prevent'
		).to.exist;
	});
});
