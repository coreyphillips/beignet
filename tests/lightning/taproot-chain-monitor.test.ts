/**
 * P6e: the ChainMonitor end-to-end wiring for a taproot force-close. Feeds a
 * force-closed taproot commitment into ChainMonitor.handleFundingSpent and
 * asserts it classifies the commitment as OURS (the taproot-aware disambiguation),
 * classifies the P2TR outputs, and drives resolveOurCommitmentOutputs to build the
 * to_local CSV sweep and the HTLC-success sweep (the witnesses themselves are
 * already regtest-validated in the interop suite). No bitcoind required.
 */
import { expect } from 'chai';
import crypto from 'crypto';
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
import { ChainMonitor } from '../../src/lightning/chain/chain-monitor';
import { CommitmentType, OutputType } from '../../src/lightning/chain/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

const NETWORK = bitcoin.networks.regtest;

function seedFor(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`p6e-${id}`))
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

describe('option_taproot ChainMonitor force-close wiring (P6e)', function () {
	it('classifies a taproot force-close as OURS and builds to_local + HTLC sweeps', function () {
		const aliceSeed = seedFor(1);
		const bobSeed = seedFor(2);
		const aliceCfg = configOf(aliceSeed, true);
		const bobCfg = configOf(bobSeed, false);
		const alice = new ChannelManager(aliceCfg);
		const bob = new ChannelManager(bobCfg);
		const aPub = aliceCfg.localBasepoints.fundingPubkey.toString('hex');
		const bPub = bobCfg.localBasepoints.fundingPubkey.toString('hex');
		connect(alice, aPub, bob, bPub);

		// Open, push to acceptor, Bob offers an HTLC → Alice holds a received HTLC.
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
		expect(aliceChannel.getFullState().localCommitmentNumber).to.equal(1n);

		const state = aliceChannel.getFullState();
		const fc = aliceChannel.forceClose(aliceChannel.getSigner()!);
		const commitTx = bitcoin.Transaction.fromBuffer(
			(
				fc.find((a) => a.type === ChannelActionType.BROADCAST_TX) as {
					tx: Buffer;
				}
			).tx
		);

		// Drive the force-close through the ChainMonitor.
		const destScript = bitcoin.payments.p2wpkh({
			pubkey: getPublicKey(privAt(aliceSeed, 9)),
			network: NETWORK
		}).output!;
		const monitor = new ChainMonitor(
			state,
			destScript,
			5,
			privAt(aliceSeed, 1), // revocation basepoint secret
			privAt(aliceSeed, 2), // payment privkey
			NETWORK,
			privAt(aliceSeed, 3), // delayed payment basepoint secret
			privAt(aliceSeed, 4) // htlc basepoint secret
		);
		monitor.addPreimage(paymentHash, preimage);

		const actions = monitor.handleFundingSpent(commitTx, 500);

		// The monitor recognised our taproot commitment and tracked its P2TR outputs.
		const broadcast = monitor.getFullState().commitmentBroadcast!;
		expect(broadcast.commitmentType).to.equal(CommitmentType.OUR_COMMITMENT);

		const toLocal = broadcast.trackedOutputs.find(
			(o) => o.outputType === OutputType.TO_LOCAL
		);
		const htlc = broadcast.trackedOutputs.find(
			(o) => o.outputType === OutputType.RECEIVED_HTLC
		);
		expect(toLocal, 'to_local tracked').to.not.be.undefined;
		expect(htlc, 'received HTLC tracked').to.not.be.undefined;

		// Both sweeps were built (held for CSV/CLTV maturity) → sweepTxHex set.
		expect(toLocal!.sweepTxHex, 'to_local sweep built').to.be.a('string');
		expect(htlc!.sweepTxHex, 'HTLC-success sweep built').to.be.a('string');

		// The monitor emitted watch + sweep actions.
		expect(actions.length).to.be.greaterThan(0);
	});
});
