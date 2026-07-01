import { expect } from 'chai';
import crypto from 'crypto';
import * as ecc from '@bitcoinerlab/secp256k1';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	HtlcState,
	isTaprootChannel
} from '../../src/lightning/channel/types';
import {
	buildLocalCommitment,
	aggregateLocalCommitmentSig
} from '../../src/lightning/channel/commitment-builder';
import { taprootCommitmentSighash } from '../../src/lightning/channel/commitment-musig';
import { createTaprootFundingScript } from '../../src/lightning/script/funding-taproot';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { perCommitmentPointFromSecret } from '../../src/lightning/keys/derivation';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { Channel } from '../../src/lightning/channel/channel';

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`taproot-htlc-seed-${id}`))
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

function makeConfig(
	seedId: number,
	preferTaproot: boolean
): IChannelManagerConfig {
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
		htlcBasepointSecret,
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

function perCommitmentPoint(seed: Buffer, n: bigint): Buffer {
	return perCommitmentPointFromSecret(generateFromSeed(seed, MAX_INDEX - n));
}

function assertCommitmentAggregates(
	channel: Channel,
	commitmentNumber: bigint
): void {
	const state = channel.getFullState();
	const point = perCommitmentPoint(
		state.localPerCommitmentSeed,
		commitmentNumber
	);
	const finalSig = aggregateLocalCommitmentSig(
		state,
		channel.getSigner()!,
		state.localNonce!,
		state.remoteSigningNonce!,
		state.remoteCommitmentSignature!,
		point,
		commitmentNumber
	);
	const funding = createTaprootFundingScript(
		state.localBasepoints.fundingPubkey,
		state.remoteBasepoints!.fundingPubkey
	);
	const built = buildLocalCommitment(state, point, commitmentNumber);
	const sighash = taprootCommitmentSighash(
		built.result.tx,
		funding.p2trOutput,
		Number(state.fundingSatoshis)
	);
	expect(ecc.verifySchnorr(sighash, funding.outputKey, finalSig)).to.equal(
		true
	);
}

describe('option_taproot HTLC-bearing commitment round (Stage D)', function () {
	function readyChannel(
		seedA: number,
		seedB: number
	): {
		alice: ChannelManager;
		bob: ChannelManager;
		aliceChannel: Channel;
		bobChannel: Channel;
		channelId: Buffer;
		errors: string[];
	} {
		const alice = new ChannelManager(makeConfig(seedA, true));
		const bob = new ChannelManager(makeConfig(seedB, false));
		const aPub = alice['config'].localBasepoints.fundingPubkey.toString('hex');
		const bPub = bob['config'].localBasepoints.fundingPubkey.toString('hex');
		connect(alice, aPub, bob, bPub);

		const errors: string[] = [];
		alice.on('error', (_id: unknown, e: string) => errors.push(`alice:${e}`));
		bob.on('error', (_id: unknown, e: string) => errors.push(`bob:${e}`));

		const aliceChannel = alice.openChannel(bPub, 2_000_000n);
		const channelId = alice.createFunding(
			aliceChannel,
			crypto.randomBytes(32),
			0,
			crypto.randomBytes(64)
		)!;
		alice.handleFundingConfirmed(channelId);
		bob.handleFundingConfirmed(channelId);
		const bobChannel = bob.getChannel(channelId)!;
		expect(isTaprootChannel(aliceChannel.getFullState().channelType)).to.equal(
			true
		);
		expect(aliceChannel.getFullState().state).to.equal(ChannelState.NORMAL);
		return { alice, bob, aliceChannel, bobChannel, channelId, errors };
	}

	it('adds an HTLC, completes a full taproot round with HTLC signatures, and aggregates', function () {
		const { alice, aliceChannel, bobChannel, channelId, errors } = readyChannel(
			1,
			2
		);

		const paymentHash = crypto
			.createHash('sha256')
			.update(crypto.randomBytes(32))
			.digest();
		const res = alice.addHtlc(
			channelId,
			200_000_000n, // 200k sat
			paymentHash,
			600000,
			Buffer.alloc(1366)
		);
		expect(res.ok, res.error).to.equal(true);

		// No signature errors surfaced during the round.
		expect(errors, errors.join('; ')).to.have.length(0);

		// Both advanced to commitment #1 with the HTLC committed on both sides.
		for (const ch of [aliceChannel, bobChannel]) {
			const s = ch.getFullState();
			expect(s.localCommitmentNumber).to.equal(1n);
			expect(s.remoteCommitmentNumber).to.equal(1n);
			expect(s.htlcs.size).to.equal(1);
			const htlc = [...s.htlcs.values()][0];
			expect(htlc.state).to.equal(HtlcState.COMMITTED);
			expect(s.remoteHtlcSignatures.length).to.equal(1);
			expect(s.remoteHtlcSignatures[0].length).to.equal(64);
		}

		// The funding key-spend still aggregates over commitment #1 (which now
		// carries the HTLC output).
		assertCommitmentAggregates(aliceChannel, 1n);
		assertCommitmentAggregates(bobChannel, 1n);
	});
});
