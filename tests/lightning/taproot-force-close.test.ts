import { expect } from 'chai';
import crypto from 'crypto';
import * as ecc from '@bitcoinerlab/secp256k1';
import * as bitcoin from 'bitcoinjs-lib';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	isTaprootChannel
} from '../../src/lightning/channel/types';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { taprootCommitmentSighash } from '../../src/lightning/channel/commitment-musig';
import { createTaprootFundingScript } from '../../src/lightning/script/funding-taproot';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { Channel } from '../../src/lightning/channel/channel';

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`taproot-fc-seed-${id}`))
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

function connectManagers(
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
 * Force-close `channel` and assert the broadcast commitment transaction spends
 * the 2-of-2 MuSig2 funding output with a valid BIP340 key-spend witness — the
 * proof that force-close aggregated the stored partials into a broadcastable
 * signature an actual Bitcoin node would accept.
 */
function assertForceCloseWitnessValid(channel: Channel): void {
	const state = channel.getFullState();
	const signer = channel.getSigner();
	expect(signer, 'signer').to.not.be.null;

	const actions = channel.forceClose(signer!);
	const broadcast = actions.find(
		(a) => a.type === ChannelActionType.BROADCAST_TX
	) as { type: ChannelActionType; tx: Buffer } | undefined;
	expect(broadcast, 'a BROADCAST_TX action').to.not.be.undefined;
	expect(channel.getFullState().state).to.equal(ChannelState.FORCE_CLOSED);

	const tx = bitcoin.Transaction.fromBuffer(broadcast!.tx);

	// The funding input carries a single-element key-spend witness.
	const witness = tx.ins[0].witness;
	expect(witness.length, 'key-spend witness has one element').to.equal(1);
	const sig = witness[0];
	expect(sig.length === 64 || sig.length === 65, 'schnorr sig length').to.equal(
		true
	);

	// Recompute the BIP341 key-spend sighash over the 2-of-2 funding output and
	// verify the aggregated signature against the tweaked output key.
	const funding = createTaprootFundingScript(
		state.localBasepoints.fundingPubkey,
		state.remoteBasepoints!.fundingPubkey
	);
	const sighash = taprootCommitmentSighash(
		tx,
		funding.p2trOutput,
		Number(state.fundingSatoshis)
	);
	expect(
		ecc.verifySchnorr(sighash, funding.outputKey, sig.subarray(0, 64))
	).to.equal(true);
}

describe('option_taproot force-close key-spend aggregation (Stage C)', function () {
	function readyTaprootChannel(
		seedA: number,
		seedB: number
	): {
		alice: ChannelManager;
		bob: ChannelManager;
		aliceChannel: Channel;
		bobChannel: Channel;
		channelId: Buffer;
	} {
		const alice = new ChannelManager(makeConfig(seedA, true));
		const bob = new ChannelManager(makeConfig(seedB, false));
		const aPub = alice['config'].localBasepoints.fundingPubkey.toString('hex');
		const bPub = bob['config'].localBasepoints.fundingPubkey.toString('hex');
		connectManagers(alice, aPub, bob, bPub);

		const aliceChannel = alice.openChannel(bPub, 1_000_000n);
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
		return { alice, bob, aliceChannel, bobChannel, channelId };
	}

	it('force-closes at commitment #0 with a valid aggregated key-spend witness', function () {
		const { aliceChannel, bobChannel } = readyTaprootChannel(1, 2);
		// Both sides can unilaterally broadcast their initial commitment.
		assertForceCloseWitnessValid(aliceChannel);
		assertForceCloseWitnessValid(bobChannel);
	});

	it('force-closes after a commitment round at commitment #1', function () {
		const { alice, aliceChannel, bobChannel, channelId } = readyTaprootChannel(
			3,
			4
		);
		expect(alice.updateChannelFee(channelId, 1000).ok).to.equal(true);
		expect(aliceChannel.getFullState().localCommitmentNumber).to.equal(1n);
		expect(bobChannel.getFullState().localCommitmentNumber).to.equal(1n);

		// Each side force-closes on its latest (post-round) commitment #1.
		assertForceCloseWitnessValid(aliceChannel);
		assertForceCloseWitnessValid(bobChannel);
	});
});
