/**
 * Interop (regtest) — P6c: the output-resolver claims OUR funds from the peer's
 * current (non-revoked) taproot commitment. Derives the keys for the peer's
 * current commitment, funds our to_remote output + an incoming (our received)
 * HTLC output on regtest, runs resolveTheirCurrentCommitmentOutputs, and asserts
 * bitcoind accepts the to_remote 1-CSV claim and the HTLC preimage-success claim.
 * Auto-skips if bitcoind is unreachable.
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
import { resolveTheirCurrentCommitmentOutputs } from '../../../src/lightning/chain/output-resolver';
import {
	buildTaprootToRemoteOutput,
	buildTaprootOfferedHtlcOutput
} from '../../../src/lightning/script/commitment-taproot';
import {
	IChannelBasepoints,
	deriveRevocationPubkey,
	derivePublicKey
} from '../../../src/lightning/keys/derivation';
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
function seedFor(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`p6-claim-${id}`))
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
		localConfig: {
			...DEFAULT_CHANNEL_CONFIG,
			feeratePerKw: 600,
			toSelfDelay: 10
		},
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
async function fund(
	address: string
): Promise<{ txid: string; vout: number; valueSat: number }> {
	const txid = (await bitcoinRpc('sendtoaddress', [address, 0.005])) as string;
	await mineBlocks(1);
	const tx = (await bitcoinRpc('getrawtransaction', [txid, true])) as {
		vout: { value: number; n: number; scriptPubKey: { address?: string } }[];
	};
	const o = tx.vout.find((v) => v.scriptPubKey.address === address)!;
	return { txid, vout: o.n, valueSat: Math.round(o.value * 1e8) };
}
async function accept(
	tx: bitcoin.Transaction
): Promise<{ ok: boolean; reason?: string }> {
	const [r] = (await bitcoinRpc('testmempoolaccept', [[tx.toHex()]])) as {
		allowed: boolean;
		['reject-reason']?: string;
	}[];
	return { ok: r.allowed, reason: r['reject-reason'] };
}

describe('Interop: option_taproot claim from peer current commitment (regtest, P6c)', function () {
	this.timeout(60_000);
	let skip = false;
	before(async function () {
		this.timeout(20_000);
		skip = !(await bitcoindUp());
		if (!skip) await ensureBitcoindFunds(2);
	});

	it('claims to_remote (1-CSV) and an incoming HTLC (preimage) that bitcoind accepts', async function () {
		if (skip) this.skip();

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

		const aliceState = aliceChannel.getFullState();
		const bobPoint = aliceState.remoteCurrentPerCommitmentPoint!;
		expect(bobPoint, "bob's current per-commitment point").to.not.be.undefined;

		// Reconstruct OUR claimable outputs on Bob's current commitment.
		const ourPayment = aliceCfg.localBasepoints.paymentBasepoint;
		const toRemote = buildTaprootToRemoteOutput(ourPayment, NETWORK);

		const revocationPubkey = deriveRevocationPubkey(
			aliceCfg.localBasepoints.revocationBasepoint,
			bobPoint
		);
		const theirHtlc = derivePublicKey(
			bobCfg.localBasepoints.htlcBasepoint,
			bobPoint
		);
		const ourHtlc = derivePublicKey(
			aliceCfg.localBasepoints.htlcBasepoint,
			bobPoint
		);
		// Our received = their offered output: claim with preimage via the success leaf.
		const preimage = crypto.randomBytes(32);
		const paymentHash = crypto.createHash('sha256').update(preimage).digest();
		const htlcOut = buildTaprootOfferedHtlcOutput(
			revocationPubkey,
			theirHtlc, // localHtlcPubkey on their commitment = theirs
			ourHtlc, // remoteHtlcPubkey on their commitment = ours
			paymentHash,
			NETWORK
		);

		const trFund = await fund(toRemote.address!);
		const htlcFund = await fund(htlcOut.address!);

		const tracked: ITrackedOutput[] = [
			{
				txid: trFund.txid,
				outputIndex: trFund.vout,
				amount: BigInt(trFund.valueSat),
				outputType: OutputType.TO_REMOTE,
				status: OutputStatus.CONFIRMED,
				confirmationHeight: 0
			},
			{
				txid: htlcFund.txid,
				outputIndex: htlcFund.vout,
				amount: BigInt(htlcFund.valueSat),
				outputType: OutputType.RECEIVED_HTLC,
				status: OutputStatus.CONFIRMED,
				confirmationHeight: 0,
				paymentHash
			}
		];

		const destScript = bitcoin.address.toOutputScript(
			(await bitcoinRpc('getnewaddress')) as string,
			NETWORK
		);
		const resolved = resolveTheirCurrentCommitmentOutputs(
			aliceState,
			tracked,
			destScript,
			2,
			new Map([[paymentHash.toString('hex'), preimage]]),
			privAt(aliceSeed, 2), // payment privkey
			privAt(aliceSeed, 4), // htlc basepoint secret
			bobPoint
		);

		const toRemoteClaim = resolved.find(
			(r) => r.trackedOutput.outputType === OutputType.TO_REMOTE
		)!;
		const htlcClaim = resolved.find(
			(r) => r.trackedOutput.outputType === OutputType.RECEIVED_HTLC
		)!;
		expect(toRemoteClaim.spendTx, 'to_remote claim').to.not.be.undefined;
		expect(htlcClaim.spendTx, 'HTLC claim').to.not.be.undefined;

		const trAccept = await accept(toRemoteClaim.spendTx!);
		expect(trAccept.ok, `to_remote: ${trAccept.reason}`).to.equal(true);
		const htlcAccept = await accept(htlcClaim.spendTx!);
		expect(htlcAccept.ok, `HTLC preimage claim: ${htlcAccept.reason}`).to.equal(
			true
		);
	});
});
