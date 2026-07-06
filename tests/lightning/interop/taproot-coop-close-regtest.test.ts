/**
 * Interop (regtest bitcoind): taproot cooperative close end-to-end — drive a
 * taproot channel through the full ChannelManager state machine with a REAL
 * on-chain MuSig2 P2TR funding output, cooperatively close it (shutdown nonce
 * TLV 8 + closing_signed partial-sig TLV 6, single-round fee), and assert
 * bitcoind accepts + confirms the aggregated key-spend closing tx. Auto-skips
 * if regtest bitcoind is unreachable.
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
		.update(Buffer.from(`taproot-coop-rt-seed-${id}`))
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

/** P2WPKH scripts owned by nobody — fine for regtest output checks. */
const SCRIPT_A = Buffer.from('0014' + 'aa'.repeat(20), 'hex');
const SCRIPT_B = Buffer.from('0014' + 'bb'.repeat(20), 'hex');

async function runCoopClose(
	seedA: number,
	seedB: number,
	initiator: 'opener' | 'acceptor'
): Promise<void> {
	const alice = new ChannelManager(makeConfig(seedA, true));
	const bob = new ChannelManager(makeConfig(seedB, false));
	alice.on('error', () => {});
	bob.on('error', () => {});
	const aPub = alice['config'].localBasepoints.fundingPubkey.toString('hex');
	const bPub = bob['config'].localBasepoints.fundingPubkey.toString('hex');
	connect(alice, aPub, bob, bPub);

	// Fund the real MuSig2 P2TR output with the channel capacity.
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
	const fundTx = (await bitcoinRpc('getrawtransaction', [fundTxid, true])) as {
		vout: { value: number; n: number; scriptPubKey: { address?: string } }[];
	};
	const fout = fundTx.vout.find(
		(v) => v.scriptPubKey.address === funding.address
	)!;
	expect(fout, 'funding output present on-chain').to.not.be.undefined;

	// Drive to NORMAL on the real outpoint (txid in INTERNAL byte order). Push
	// 300k sat to bob so both sides get a non-dust closing output.
	const aliceChannel = alice.openChannel(bPub, capacitySat, 300_000_000n);
	const channelId = alice.createFunding(
		aliceChannel,
		Buffer.from(fundTxid, 'hex').reverse(),
		fout.n,
		crypto.randomBytes(64)
	)!;
	alice.handleFundingConfirmed(channelId);
	bob.handleFundingConfirmed(channelId);
	const bobChannel = bob.getChannel(channelId)!;
	expect(isTaprootChannel(aliceChannel.getFullState().channelType)).to.equal(
		true
	);
	expect(aliceChannel.getFullState().state).to.equal(ChannelState.NORMAL);

	// Bump the channel feerate so the single-round closing fee clears
	// min-relay on the real node.
	expect(alice.updateChannelFee(channelId, 2500).ok).to.equal(true);

	const broadcasts: Buffer[] = [];
	alice.on('broadcast:tx', (tx: Buffer) => broadcasts.push(tx));
	bob.on('broadcast:tx', (tx: Buffer) => broadcasts.push(tx));

	const res =
		initiator === 'opener'
			? alice.initiateShutdown(channelId, SCRIPT_A)
			: bob.initiateShutdown(channelId, SCRIPT_B);
	expect(res.ok, res.error).to.equal(true);

	expect(aliceChannel.getState()).to.equal(ChannelState.CLOSED);
	expect(bobChannel.getState()).to.equal(ChannelState.CLOSED);
	expect(broadcasts.length).to.equal(2);
	expect(broadcasts[0].equals(broadcasts[1])).to.equal(true);

	const closeTx = bitcoin.Transaction.fromBuffer(broadcasts[0]);
	expect(closeTx.ins[0].witness.length).to.equal(1);
	expect(closeTx.ins[0].witness[0].length).to.equal(64);

	// bitcoind accepts the aggregated key-spend mutual close...
	const txHex = closeTx.toHex();
	const [accept] = (await bitcoinRpc('testmempoolaccept', [[txHex]])) as {
		allowed: boolean;
		['reject-reason']?: string;
	}[];
	expect(accept.allowed, accept['reject-reason']).to.equal(true);

	// ...and it confirms.
	await bitcoinRpc('sendrawtransaction', [txHex]);
	await mineBlocks(1);
	const mined = (await bitcoinRpc('getrawtransaction', [
		closeTx.getId(),
		true
	])) as { confirmations?: number };
	expect((mined.confirmations ?? 0) >= 1).to.equal(true);
}

describe('Interop: taproot cooperative close (regtest)', function () {
	this.timeout(60_000);
	let skip = false;
	before(async function () {
		this.timeout(20_000);
		skip = !(await bitcoindUp());
		if (!skip) await ensureBitcoindFunds();
	});

	it('opener-initiated coop close confirms on bitcoind', async function () {
		if (skip) this.skip();
		await runCoopClose(1, 2, 'opener');
	});

	it('acceptor-initiated coop close confirms on bitcoind', async function () {
		if (skip) this.skip();
		await runCoopClose(3, 4, 'acceptor');
	});
});
