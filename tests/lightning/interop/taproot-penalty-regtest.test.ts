/**
 * Interop (regtest) — P6c: the output-resolver sweeps a peer's REVOKED taproot
 * commitment (justice). Drives a taproot channel to commitment #2 (so #1's
 * per-commitment secret is revealed to us), derives the keys for the peer's
 * revoked #1 commitment, funds its reconstructed to_local + HTLC outputs on
 * regtest, then runs resolveRevokedCommitmentOutputs and asserts bitcoind accepts
 * the penalty transaction (to_local revoke-tapleaf + HTLC revocation key-path).
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
	isTaprootChannel,
	HtlcDirection
} from '../../../src/lightning/channel/types';
import {
	OutputType,
	OutputStatus,
	ITrackedOutput
} from '../../../src/lightning/chain/types';
import { resolveRevokedCommitmentOutputs } from '../../../src/lightning/chain/output-resolver';
import {
	buildTaprootToLocalOutput,
	buildTaprootReceivedHtlcOutput
} from '../../../src/lightning/script/commitment-taproot';
import {
	IChannelBasepoints,
	perCommitmentPointFromSecret
} from '../../../src/lightning/keys/derivation';
import { MAX_INDEX } from '../../../src/lightning/keys/shachain';
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
		.update(Buffer.from(`p6-penalty-${id}`))
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

describe('Interop: option_taproot revoked-commitment penalty sweep (regtest, P6c)', function () {
	this.timeout(60_000);
	let skip = false;
	before(async function () {
		this.timeout(20_000);
		skip = !(await bitcoindUp());
		if (!skip) await ensureBitcoindFunds(2);
	});

	it('sweeps a revoked taproot commitment to_local + HTLC via the penalty resolver', async function () {
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

		// Advance to commitment #2 so Bob's #1 per-commitment secret is revealed.
		expect(alice.updateChannelFee(channelId, 700).ok).to.equal(true);
		expect(alice.updateChannelFee(channelId, 800).ok).to.equal(true);
		const aliceState = aliceChannel.getFullState();
		expect(Number(aliceState.remoteCommitmentNumber)).to.be.greaterThan(1);

		// Bob's revoked #1 per-commitment point, from the secret we now hold.
		const bobSecret1 = aliceState.shaChainStore.getSecret(MAX_INDEX - 1n);
		expect(bobSecret1, "Bob's revoked #1 secret").to.not.be.undefined;
		const bobPoint1 = perCommitmentPointFromSecret(bobSecret1!);

		// Reconstruct Bob's #1 to_local + an HTLC output (our perspective on their
		// commitment) and fund them on-chain so the penalty tx has real inputs.
		const { deriveRevocationPubkey, derivePublicKey } = await import(
			'../../../src/lightning/keys/derivation'
		);
		const revocationPubkey = deriveRevocationPubkey(
			aliceCfg.localBasepoints.revocationBasepoint,
			bobPoint1
		);
		const theirDelayed = derivePublicKey(
			bobCfg.localBasepoints.delayedPaymentBasepoint,
			bobPoint1
		);
		const ourHtlc = derivePublicKey(
			aliceCfg.localBasepoints.htlcBasepoint,
			bobPoint1
		);
		const theirHtlc = derivePublicKey(
			bobCfg.localBasepoints.htlcBasepoint,
			bobPoint1
		);

		const toLocal = buildTaprootToLocalOutput(
			revocationPubkey,
			theirDelayed,
			10, // toSelfDelay (matches configOf)
			NETWORK
		);
		// Our OFFERED htlc → their received output on their commitment.
		const paymentHash = crypto
			.createHash('sha256')
			.update(crypto.randomBytes(32))
			.digest();
		const cltvExpiry = 700;
		const htlcOut = buildTaprootReceivedHtlcOutput(
			revocationPubkey,
			theirHtlc, // localHtlcPubkey on their commitment = theirs
			ourHtlc, // remoteHtlcPubkey on their commitment = ours
			paymentHash,
			cltvExpiry,
			NETWORK
		);

		const tlFund = await fund(toLocal.address!);
		const htlcFund = await fund(htlcOut.address!);

		const tracked: ITrackedOutput[] = [
			{
				txid: tlFund.txid,
				outputIndex: tlFund.vout,
				amount: BigInt(tlFund.valueSat),
				outputType: OutputType.TO_LOCAL,
				status: OutputStatus.CONFIRMED,
				confirmationHeight: 0
			},
			{
				txid: htlcFund.txid,
				outputIndex: htlcFund.vout,
				amount: BigInt(htlcFund.valueSat),
				outputType: OutputType.OFFERED_HTLC,
				status: OutputStatus.CONFIRMED,
				confirmationHeight: 0,
				paymentHash,
				cltvExpiry
			}
		];

		const destScript = bitcoin.address.toOutputScript(
			(await bitcoinRpc('getnewaddress')) as string,
			NETWORK
		);
		const resolved = resolveRevokedCommitmentOutputs(
			aliceState,
			tracked,
			1n,
			new bitcoin.Transaction(), // revokedTx — ignored on the taproot path
			destScript,
			2,
			privAt(aliceSeed, 1), // revocation basepoint secret
			privAt(aliceSeed, 2), // payment privkey
			NETWORK
		);

		// One penalty tx sweeping both inputs.
		const penalty = resolved.find((r) => r.spendTx)!.spendTx!;
		expect(penalty.ins.length, 'penalty sweeps both outputs').to.equal(2);

		const [res] = (await bitcoinRpc('testmempoolaccept', [
			[penalty.toHex()]
		])) as {
			allowed: boolean;
			['reject-reason']?: string;
		}[];
		expect(res.allowed, res['reject-reason']).to.equal(true);

		await bitcoinRpc('sendrawtransaction', [penalty.toHex()]);
		await mineBlocks(1);
		const mined = (await bitcoinRpc('getrawtransaction', [
			penalty.getId(),
			true
		])) as {
			confirmations?: number;
		};
		expect((mined.confirmations ?? 0) >= 1).to.equal(true);
	});

	// H1 regression: a taproot HTLC output that was in the revoked commitment but
	// has since SETTLED (removed from live state.htlcs, so it is NOT in
	// trackedOutputs) must still be penalized via the revokedHtlcSnapshots
	// fallback. Before the fix the taproot resolver ignored the snapshot entirely
	// and the cheater reclaimed the output after its CLTV/CSV.
	it('penalizes a SETTLED taproot HTLC from the snapshot (not in trackedOutputs), bitcoind-accepted', async function () {
		if (skip) this.skip();

		const aliceSeed = seedFor(11);
		const bobSeed = seedFor(12);
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
		expect(alice.updateChannelFee(channelId, 700).ok).to.equal(true);
		expect(alice.updateChannelFee(channelId, 800).ok).to.equal(true);
		const aliceState = aliceChannel.getFullState();

		const bobSecret1 = aliceState.shaChainStore.getSecret(MAX_INDEX - 1n)!;
		const bobPoint1 = perCommitmentPointFromSecret(bobSecret1);
		const { deriveRevocationPubkey, derivePublicKey } = await import(
			'../../../src/lightning/keys/derivation'
		);
		const revocationPubkey = deriveRevocationPubkey(
			aliceCfg.localBasepoints.revocationBasepoint,
			bobPoint1
		);
		const ourHtlc = derivePublicKey(
			aliceCfg.localBasepoints.htlcBasepoint,
			bobPoint1
		);
		const theirHtlc = derivePublicKey(
			bobCfg.localBasepoints.htlcBasepoint,
			bobPoint1
		);

		// Our OFFERED HTLC → their received output on their commitment.
		const paymentHash = crypto
			.createHash('sha256')
			.update(crypto.randomBytes(32))
			.digest();
		const cltvExpiry = 700;
		const htlcOut = buildTaprootReceivedHtlcOutput(
			revocationPubkey,
			theirHtlc,
			ourHtlc,
			paymentHash,
			cltvExpiry,
			NETWORK
		);

		// Fund the HTLC output on-chain; that funding tx stands in for the broadcast
		// revoked commitment (its output[vout] is the HTLC output).
		const htlcFund = await fund(htlcOut.address!);
		const revokedHex = (await bitcoinRpc('getrawtransaction', [
			htlcFund.txid
		])) as string;
		const revokedTx = bitcoin.Transaction.fromHex(revokedHex);

		// The HTLC has SETTLED: it lives only in the snapshot, not in state.htlcs,
		// and trackedOutputs (from live classification) does NOT contain it.
		aliceState.revokedHtlcSnapshots = new Map([
			[
				'1',
				[
					{
						paymentHash,
						amountMsat: 100_000_000n,
						cltvExpiry,
						direction: HtlcDirection.OFFERED
					}
				]
			]
		]);

		const destScript = bitcoin.address.toOutputScript(
			(await bitcoinRpc('getnewaddress')) as string,
			NETWORK
		);
		const resolved = resolveRevokedCommitmentOutputs(
			aliceState,
			[], // trackedOutputs EMPTY — live classification missed the settled HTLC
			1n,
			revokedTx,
			destScript,
			2,
			privAt(aliceSeed, 1),
			privAt(aliceSeed, 2),
			NETWORK
		);

		// The snapshot fallback brought the settled HTLC output into the penalty.
		const penalty = resolved.find((r) => r.spendTx)?.spendTx;
		expect(penalty, 'a penalty tx must be produced from the snapshot').to.exist;
		const spendsHtlc = penalty!.ins.some(
			(vin) =>
				Buffer.from(vin.hash).reverse().toString('hex') === htlcFund.txid &&
				vin.index === htlcFund.vout
		);
		expect(spendsHtlc, 'penalty spends the settled HTLC output').to.equal(true);

		const [res] = (await bitcoinRpc('testmempoolaccept', [
			[penalty!.toHex()]
		])) as { allowed: boolean; ['reject-reason']?: string }[];
		expect(res.allowed, res['reject-reason']).to.equal(true);

		await bitcoinRpc('sendrawtransaction', [penalty!.toHex()]);
		await mineBlocks(1);
		const mined = (await bitcoinRpc('getrawtransaction', [
			penalty!.getId(),
			true
		])) as { confirmations?: number };
		expect((mined.confirmations ?? 0) >= 1).to.equal(true);
	});
});
