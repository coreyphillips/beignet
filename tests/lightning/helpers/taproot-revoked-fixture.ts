/**
 * A revoked TAPROOT commitment to drive justice-path tests with: a channel is
 * opened as option_taproot, advanced past commitment #1 so we hold the peer's
 * revoked per-commitment secret, and helpers hand back tracked outputs the
 * taproot resolver can claim. Shared by the penalty fee-guard suite and the
 * uneconomic-sweep-retry suite.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../../src/lightning/channel/channel-manager';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	isTaprootChannel
} from '../../../src/lightning/channel/types';
import {
	OutputType,
	OutputStatus,
	ITrackedOutput
} from '../../../src/lightning/chain/types';
import { IChannelBasepoints } from '../../../src/lightning/keys/derivation';
import { MAX_INDEX } from '../../../src/lightning/keys/shachain';
import { getPublicKey } from '../../../src/lightning/crypto/ecdh';
import { IChannelState } from '../../../src/lightning/channel/channel-state';

bitcoin.initEccLib(ecc);
export const NETWORK = bitcoin.networks.regtest;

export function seedFor(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`taproot-penalty-guard-${id}`))
		.digest();
}

export function privAt(seed: Buffer, i: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([i]))
		.digest();
}

export function basepointsOf(seed: Buffer): IChannelBasepoints {
	return {
		fundingPubkey: getPublicKey(privAt(seed, 0)),
		revocationBasepoint: getPublicKey(privAt(seed, 1)),
		paymentBasepoint: getPublicKey(privAt(seed, 2)),
		delayedPaymentBasepoint: getPublicKey(privAt(seed, 3)),
		htlcBasepoint: getPublicKey(privAt(seed, 4)),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

export function configOf(
	seed: Buffer,
	preferTaproot: boolean
): IChannelManagerConfig {
	return {
		localConfig: { ...DEFAULT_CHANNEL_CONFIG, feeratePerKw: 2500 },
		localBasepoints: basepointsOf(seed),
		localPerCommitmentSeed: seedFor(1000 + seed[0]),
		localFundingPrivkey: privAt(seed, 0),
		htlcBasepointSecret: privAt(seed, 4),
		preferTaproot
	};
}

export function connect(
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
export function revokedTaprootSetup(): {
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
export function trackedFor(
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
			outputType: OutputType.RECEIVED_HTLC,
			status: OutputStatus.CONFIRMED,
			confirmationHeight: 0,
			paymentHash: crypto.randomBytes(32),
			cltvExpiry
		}
	];
}

/** An empty stand-in: the taproot justice path reads amounts from tracked outputs. */
export function emptyRevokedTx(): bitcoin.Transaction {
	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.addInput(crypto.randomBytes(32), 0);
	return tx;
}
