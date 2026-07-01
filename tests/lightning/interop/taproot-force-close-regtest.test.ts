/**
 * Interop (regtest bitcoind): drive a taproot channel through the full
 * ChannelManager state machine — open → fund (real outpoint) → channel_ready →
 * a commitment round — then forceClose() and assert bitcoind's testmempoolaccept
 * accepts the broadcast commitment, i.e. the MuSig2 key-spend witness aggregated
 * by force-close is valid against a real Bitcoin node. Auto-skips if regtest
 * bitcoind is unreachable.
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
import { ChannelActionType } from '../../../src/lightning/channel/channel-actions';
import { Channel } from '../../../src/lightning/channel/channel';
import { ChannelSigner } from '../../../src/lightning/keys/signer';
import {
	serializeChannelState,
	deserializeChannelState
} from '../../../src/lightning/storage/serialization';
import { createTaprootFundingScript } from '../../../src/lightning/script/funding-taproot';
import { IChannelBasepoints } from '../../../src/lightning/keys/derivation';
import { getPublicKey } from '../../../src/lightning/crypto/ecdh';
import { bitcoinRpc, mineBlocks, ensureBitcoindFunds } from './shared-helpers';

bitcoin.initEccLib(ecc);
const NETWORK = bitcoin.networks.regtest;

async function bitcoindUp(): Promise<boolean> {
	try {
		await bitcoinRpc('getblockchaininfo');
		return true;
	} catch {
		return false;
	}
}

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`taproot-fc-rt-seed-${id}`))
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

describe('Interop: option_taproot force-close (regtest)', function () {
	this.timeout(60_000);
	let skip = false;
	before(async function () {
		this.timeout(20_000);
		skip = !(await bitcoindUp());
		if (!skip) await ensureBitcoindFunds();
	});

	it('forceClose() broadcast is accepted by bitcoind after a commitment round', async function () {
		if (skip) this.skip();

		const alice = new ChannelManager(makeConfig(1, true));
		const bob = new ChannelManager(makeConfig(2, false));
		const aPub = alice['config'].localBasepoints.fundingPubkey.toString('hex');
		const bPub = bob['config'].localBasepoints.fundingPubkey.toString('hex');
		connect(alice, aPub, bob, bPub);

		const aliceFundingPub = alice['config'].localBasepoints.fundingPubkey;
		const bobFundingPub = bob['config'].localBasepoints.fundingPubkey;

		// Fund the real 2-of-2 MuSig2 key-spend P2TR output on regtest with exactly
		// the channel capacity (0.01 BTC = 1_000_000 sat).
		const capacitySat = 1_000_000n;
		const funding = createTaprootFundingScript(
			aliceFundingPub,
			bobFundingPub,
			NETWORK
		);
		const fundTxid = (await bitcoinRpc('sendtoaddress', [
			funding.address,
			0.01
		])) as string;
		await mineBlocks(1);
		const fundTx = (await bitcoinRpc('getrawtransaction', [
			fundTxid,
			true
		])) as {
			vout: { value: number; n: number; scriptPubKey: { address?: string } }[];
		};
		const fout = fundTx.vout.find(
			(v) => v.scriptPubKey.address === funding.address
		)!;
		expect(fout, 'funding output present on-chain').to.not.be.undefined;
		expect(Math.round(fout.value * 1e8)).to.equal(Number(capacitySat));

		// Drive the channel to NORMAL with the real funding outpoint. The commitment
		// builder takes fundingTxid in INTERNAL byte order (BOLT 2), so reverse the
		// display-order txid bitcoind returns.
		const aliceChannel = alice.openChannel(bPub, capacitySat);
		const channelId = alice.createFunding(
			aliceChannel,
			Buffer.from(fundTxid, 'hex').reverse(),
			fout.n,
			crypto.randomBytes(64)
		)!;
		alice.handleFundingConfirmed(channelId);
		bob.handleFundingConfirmed(channelId);
		expect(isTaprootChannel(aliceChannel.getFullState().channelType)).to.equal(
			true
		);
		expect(aliceChannel.getFullState().state).to.equal(ChannelState.NORMAL);

		// Run a commitment round at a feerate high enough to clear min-relay for the
		// broadcast commitment, then force-close on commitment #1.
		expect(alice.updateChannelFee(channelId, 2500).ok).to.equal(true);
		expect(aliceChannel.getFullState().localCommitmentNumber).to.equal(1n);

		const actions = aliceChannel.forceClose(aliceChannel.getSigner()!);
		const broadcast = actions.find(
			(a) => a.type === ChannelActionType.BROADCAST_TX
		) as { type: ChannelActionType; tx: Buffer } | undefined;
		expect(broadcast, 'a BROADCAST_TX action').to.not.be.undefined;

		const txHex = bitcoin.Transaction.fromBuffer(broadcast!.tx).toHex();

		// bitcoind accepts the aggregated key-spend commitment.
		const [res] = (await bitcoinRpc('testmempoolaccept', [[txHex]])) as {
			allowed: boolean;
			['reject-reason']?: string;
		}[];
		expect(res.allowed, res['reject-reason']).to.equal(true);

		// And it confirms when broadcast.
		await bitcoinRpc('sendrawtransaction', [txHex]);
		await mineBlocks(1);
		const mined = (await bitcoinRpc('getrawtransaction', [
			bitcoin.Transaction.fromBuffer(broadcast!.tx).getId(),
			true
		])) as { confirmations?: number };
		expect((mined.confirmations ?? 0) >= 1).to.equal(true);
	});

	it('force-closes the PRE-reconnect commitment after a reconnect (deterministic nonce, bitcoind-accepted)', async function () {
		if (skip) this.skip();

		const alice = new ChannelManager(makeConfig(3, true));
		const bob = new ChannelManager(makeConfig(4, false));
		const aPub = alice['config'].localBasepoints.fundingPubkey.toString('hex');
		const bPub = bob['config'].localBasepoints.fundingPubkey.toString('hex');
		connect(alice, aPub, bob, bPub);

		const capacitySat = 1_000_000n;
		const funding = createTaprootFundingScript(
			alice['config'].localBasepoints.fundingPubkey,
			bob['config'].localBasepoints.fundingPubkey,
			NETWORK
		);
		const fundTxid = (await bitcoinRpc('sendtoaddress', [
			funding.address,
			0.01
		])) as string;
		await mineBlocks(1);
		const fundTx = (await bitcoinRpc('getrawtransaction', [
			fundTxid,
			true
		])) as {
			vout: { value: number; n: number; scriptPubKey: { address?: string } }[];
		};
		const fout = fundTx.vout.find(
			(v) => v.scriptPubKey.address === funding.address
		)!;

		const aliceChannel = alice.openChannel(bPub, capacitySat);
		const channelId = alice.createFunding(
			aliceChannel,
			Buffer.from(fundTxid, 'hex').reverse(),
			fout.n,
			crypto.randomBytes(64)
		)!;
		alice.handleFundingConfirmed(channelId);
		bob.handleFundingConfirmed(channelId);

		// Advance to commitment #1: bob's partial over our commitment #1 + its
		// signing nonce are now stored, made against our verification nonce for
		// height 1.
		expect(alice.updateChannelFee(channelId, 2500).ok).to.equal(true);
		expect(aliceChannel.getFullState().localCommitmentNumber).to.equal(1n);

		// Simulate a reconnect that loses the in-memory verification nonces — the
		// scenario that previously made the pre-reconnect commitment
		// un-force-closeable. createReestablish re-derives them deterministically.
		const s = aliceChannel.getFullState();
		s.preReestablishState = s.state;
		s.state = ChannelState.AWAITING_REESTABLISH;
		s.localNonce = undefined;
		s.localNextNonce = undefined;
		aliceChannel.createReestablish();
		s.state = s.preReestablishState!;
		s.preReestablishState = null;

		// Force-close the pre-reconnect commitment and assert bitcoind accepts the
		// aggregated key-spend witness — i.e. the re-derived verification nonce +
		// the stored peer nonce/partial produce a consensus-valid signature.
		const actions = aliceChannel.forceClose(aliceChannel.getSigner()!);
		expect(
			actions.find((a) => a.type === ChannelActionType.ERROR),
			'force-close must not error'
		).to.be.undefined;
		const broadcast = actions.find(
			(a) => a.type === ChannelActionType.BROADCAST_TX
		) as { type: ChannelActionType; tx: Buffer } | undefined;
		expect(broadcast, 'a BROADCAST_TX action').to.not.be.undefined;

		const txHex = bitcoin.Transaction.fromBuffer(broadcast!.tx).toHex();
		const [res] = (await bitcoinRpc('testmempoolaccept', [[txHex]])) as {
			allowed: boolean;
			['reject-reason']?: string;
		}[];
		expect(res.allowed, res['reject-reason']).to.equal(true);

		await bitcoinRpc('sendrawtransaction', [txHex]);
		await mineBlocks(1);
		const mined = (await bitcoinRpc('getrawtransaction', [
			bitcoin.Transaction.fromBuffer(broadcast!.tx).getId(),
			true
		])) as { confirmations?: number };
		expect((mined.confirmations ?? 0) >= 1).to.equal(true);
	});

	it('force-closes after a RESTART (channel rebuilt purely from persisted bytes, bitcoind-accepted)', async function () {
		if (skip) this.skip();

		const alice = new ChannelManager(makeConfig(5, true));
		const bob = new ChannelManager(makeConfig(6, false));
		const aPub = alice['config'].localBasepoints.fundingPubkey.toString('hex');
		const bPub = bob['config'].localBasepoints.fundingPubkey.toString('hex');
		connect(alice, aPub, bob, bPub);

		const capacitySat = 1_000_000n;
		const funding = createTaprootFundingScript(
			alice['config'].localBasepoints.fundingPubkey,
			bob['config'].localBasepoints.fundingPubkey,
			NETWORK
		);
		const fundTxid = (await bitcoinRpc('sendtoaddress', [
			funding.address,
			0.01
		])) as string;
		await mineBlocks(1);
		const fundTx = (await bitcoinRpc('getrawtransaction', [
			fundTxid,
			true
		])) as {
			vout: { value: number; n: number; scriptPubKey: { address?: string } }[];
		};
		const fout = fundTx.vout.find(
			(v) => v.scriptPubKey.address === funding.address
		)!;

		const aliceChannel = alice.openChannel(bPub, capacitySat);
		const channelId = alice.createFunding(
			aliceChannel,
			Buffer.from(fundTxid, 'hex').reverse(),
			fout.n,
			crypto.randomBytes(64)
		)!;
		alice.handleFundingConfirmed(channelId);
		bob.handleFundingConfirmed(channelId);

		// Advance to commitment #1 so the peer's partial + signing nonce over our
		// current commitment are stored.
		expect(alice.updateChannelFee(channelId, 2500).ok).to.equal(true);
		expect(aliceChannel.getFullState().localCommitmentNumber).to.equal(1n);

		// ── SIMULATE A RESTART ──────────────────────────────────────
		// Persist alice's channel to bytes, then rebuild a brand-new Channel purely
		// from the serialized form + a fresh signer — exactly what crash recovery
		// does. The in-memory MuSig2 nonces are NOT serialized, so the restored
		// channel has neither localNonce nor localNextNonce; only the deterministic
		// seed + the persisted remoteSigningNonce/remoteCommitmentSignature survive.
		const serialized = serializeChannelState(aliceChannel.getFullState());
		const restoredState = deserializeChannelState(serialized);
		expect(restoredState.localNonce, 'verification nonce not persisted').to.be
			.undefined;
		expect(restoredState.localNextNonce, 'next nonce not persisted').to.be
			.undefined;
		expect(restoredState.remoteSigningNonce, 'peer signing nonce persisted').to
			.not.be.undefined;
		expect(restoredState.remoteCommitmentSignature, 'peer partial persisted').to
			.not.be.null;

		const restored = new Channel(
			restoredState,
			new ChannelSigner(
				alice['config'].localFundingPrivkey!,
				alice['config'].htlcBasepointSecret
			)
		);

		// Force-close the restored channel. forceClose re-derives the verification
		// nonce deterministically (from the persisted per-commitment seed) and
		// aggregates it with the persisted peer nonce/partial — bitcoind must accept
		// the resulting key-spend witness.
		const actions = restored.forceClose(restored.getSigner()!);
		expect(
			actions.find((a) => a.type === ChannelActionType.ERROR),
			'restored force-close must not error'
		).to.be.undefined;
		const broadcast = actions.find(
			(a) => a.type === ChannelActionType.BROADCAST_TX
		) as { type: ChannelActionType; tx: Buffer } | undefined;
		expect(broadcast, 'a BROADCAST_TX action').to.not.be.undefined;

		const txHex = bitcoin.Transaction.fromBuffer(broadcast!.tx).toHex();
		const [res] = (await bitcoinRpc('testmempoolaccept', [[txHex]])) as {
			allowed: boolean;
			['reject-reason']?: string;
		}[];
		expect(res.allowed, res['reject-reason']).to.equal(true);

		await bitcoinRpc('sendrawtransaction', [txHex]);
		await mineBlocks(1);
		const mined = (await bitcoinRpc('getrawtransaction', [
			bitcoin.Transaction.fromBuffer(broadcast!.tx).getId(),
			true
		])) as { confirmations?: number };
		expect((mined.confirmations ?? 0) >= 1).to.equal(true);
	});
});
