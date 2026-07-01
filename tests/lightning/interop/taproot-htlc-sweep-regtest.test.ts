/**
 * Interop (regtest bitcoind) — CAPSTONE: drive a taproot channel through the full
 * ChannelManager (open → real funding → channel_ready → add HTLC round →
 * force-close), confirm the commitment on-chain, then spend its HTLC output's
 * second-level HTLC-success transaction using the signatures the STATE MACHINE
 * exchanged (our own HTLC sig + the peer's stored remoteHtlcSignatures) plus the
 * preimage, with a wallet-funded fee input (SIGHASH_SINGLE|ANYONECANPAY). bitcoind
 * accepting this proves the taproot HTLC signatures the protocol produces are
 * valid against a real Bitcoin node end-to-end. Auto-skips if bitcoind is down.
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
import { deriveCommitmentKeys } from '../../../src/lightning/channel/commitment-builder';
import {
	buildTaprootReceivedHtlcOutput,
	buildTaprootSecondLevelOutput
} from '../../../src/lightning/script/commitment-taproot';
import { resolveSecondLevelHtlcOutput } from '../../../src/lightning/chain/output-resolver';
import {
	buildTaprootHtlcSuccessTx,
	taprootHtlcLeafSighash,
	signTaprootHtlcLeaf,
	verifyTaprootHtlcLeaf,
	TAPROOT_HTLC_SIGHASH_TYPE
} from '../../../src/lightning/script/htlc-taproot';
import { createTaprootFundingScript } from '../../../src/lightning/script/funding-taproot';
import {
	IChannelBasepoints,
	derivePrivateKey,
	derivePublicKey,
	deriveRevocationPubkey,
	perCommitmentPointFromSecret
} from '../../../src/lightning/keys/derivation';
import {
	generateFromSeed,
	MAX_INDEX
} from '../../../src/lightning/keys/shachain';
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
		.update(Buffer.from(`taproot-htlc-sweep-${id}`))
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
function perCommitmentPoint(seed: Buffer, n: bigint): Buffer {
	return perCommitmentPointFromSecret(generateFromSeed(seed, MAX_INDEX - n));
}

/** Fund `spk` as output index 0 of a fresh confirmed tx (stands in for a
 * broadcast second-level HTLC tx whose out[0] is the to_local-format output). */
async function fundScriptAtIndex0(
	spk: Buffer,
	amountSat: number
): Promise<bitcoin.Transaction> {
	const wPriv = crypto.randomBytes(32);
	const wPub = Buffer.from(ecc.pointFromScalar(wPriv, true)!);
	const wp = bitcoin.payments.p2wpkh({ pubkey: wPub, network: NETWORK });
	const ftxid = (await bitcoinRpc('sendtoaddress', [
		wp.address,
		(amountSat + 5000) / 1e8
	])) as string;
	await mineBlocks(1);
	const ftx = bitcoin.Transaction.fromHex(
		(await bitcoinRpc('getrawtransaction', [ftxid])) as string
	);
	const vout = ftx.outs.findIndex((o) => o.script.equals(wp.output!));
	const value = ftx.outs[vout].value;
	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.addInput(Buffer.from(ftxid, 'hex').reverse(), vout);
	tx.addOutput(spk, amountSat);
	const sh = tx.hashForWitnessV0(
		0,
		bitcoin.payments.p2pkh({ pubkey: wPub }).output!,
		value,
		bitcoin.Transaction.SIGHASH_ALL
	);
	const sig = bitcoin.script.signature.encode(
		Buffer.from(ecc.sign(sh, wPriv)),
		bitcoin.Transaction.SIGHASH_ALL
	);
	tx.ins[0].witness = [sig, wPub];
	await bitcoinRpc('sendrawtransaction', [tx.toHex()]);
	await mineBlocks(1);
	return tx;
}

describe('Interop: option_taproot HTLC sweep from a force-closed commitment (regtest)', function () {
	this.timeout(60_000);
	let skip = false;
	before(async function () {
		this.timeout(20_000);
		skip = !(await bitcoindUp());
		if (!skip) await ensureBitcoindFunds(2);
	});

	it('spends a force-closed commitment HTLC output with the state-machine sigs', async function () {
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

		// Fund the real MuSig2 P2TR funding output (0.03 BTC).
		const capacitySat = 3_000_000n;
		const funding = createTaprootFundingScript(
			aliceCfg.localBasepoints.fundingPubkey,
			bobCfg.localBasepoints.fundingPubkey,
			NETWORK
		);
		const fundTxid = (await bitcoinRpc('sendtoaddress', [
			funding.address,
			0.03
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

		// Open, push capacity to the acceptor so it can OFFER an HTLC (giving the
		// opener a RECEIVED HTLC → on-chain success spend with the preimage).
		const aliceChannel = alice.openChannel(bPub, capacitySat, 1_500_000_000n);
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

		// Bob offers an HTLC to Alice; capture the preimage.
		const preimage = crypto.randomBytes(32);
		const paymentHash = crypto.createHash('sha256').update(preimage).digest();
		const htlcAmountSat = 300_000n;
		const cltvExpiry = 800;
		const res = bob.addHtlc(
			channelId,
			htlcAmountSat * 1000n,
			paymentHash,
			cltvExpiry,
			Buffer.alloc(1366)
		);
		expect(res.ok, res.error).to.equal(true);
		expect(aliceChannel.getFullState().localCommitmentNumber).to.equal(1n);
		expect(aliceChannel.getFullState().remoteHtlcSignatures.length).to.equal(1);

		// Force-close Alice → commitment #1 (with the received HTLC output).
		const fcActions = aliceChannel.forceClose(aliceChannel.getSigner()!);
		const broadcast = fcActions.find(
			(a) => a.type === ChannelActionType.BROADCAST_TX
		) as { tx: Buffer } | undefined;
		expect(broadcast, 'force-close BROADCAST_TX').to.not.be.undefined;
		const commitTx = bitcoin.Transaction.fromBuffer(broadcast!.tx);
		const commitHex = commitTx.toHex();

		const [cAccept] = (await bitcoinRpc('testmempoolaccept', [
			[commitHex]
		])) as {
			allowed: boolean;
			['reject-reason']?: string;
		}[];
		expect(cAccept.allowed, cAccept['reject-reason']).to.equal(true);
		await bitcoinRpc('sendrawtransaction', [commitHex]);
		await mineBlocks(1); // confirm commitment (satisfies the 2nd-level 1-block CSV)

		// Reconstruct the HTLC output exactly as the commitment built it.
		const alicePoint1 = perCommitmentPoint(aliceCfg.localPerCommitmentSeed, 1n);
		const keys = deriveCommitmentKeys(
			aliceCfg.localBasepoints,
			bobCfg.localBasepoints,
			alicePoint1,
			true
		);
		const htlcOut = buildTaprootReceivedHtlcOutput(
			keys.revocationPubkey,
			keys.localHtlcPubkey,
			keys.remoteHtlcPubkey,
			paymentHash,
			cltvExpiry,
			NETWORK
		);
		const htlcVout = commitTx.outs.findIndex((o) =>
			o.script.equals(htlcOut.output)
		);
		expect(htlcVout, 'HTLC output present in the commitment').to.be.greaterThan(
			-1
		);

		// Rebuild the exact 1-in/1-out HTLC-success tx the state machine signed.
		const successTx = buildTaprootHtlcSuccessTx(
			commitTx.getId(),
			htlcVout,
			htlcAmountSat,
			keys.revocationPubkey,
			keys.localDelayedPubkey,
			aliceChannel.getFullState().remoteConfig.toSelfDelay,
			NETWORK
		);
		const sighash = taprootHtlcLeafSighash(
			successTx,
			htlcOut.output,
			Number(htlcAmountSat),
			htlcOut.success.script,
			htlcOut.success.leafVersion
		);
		const aliceHtlcPriv = derivePrivateKey(
			aliceCfg.htlcBasepointSecret!,
			alicePoint1,
			aliceCfg.localBasepoints.htlcBasepoint
		);
		const aliceSig = signTaprootHtlcLeaf(sighash, aliceHtlcPriv);
		const bobSig = aliceChannel.getFullState().remoteHtlcSignatures[0];

		// Both signatures validate against the reconstructed second-level tx.
		expect(
			verifyTaprootHtlcLeaf(sighash, keys.localHtlcPubkey, aliceSig)
		).to.equal(true);
		expect(
			verifyTaprootHtlcLeaf(sighash, keys.remoteHtlcPubkey, bobSig)
		).to.equal(true);

		// Attach a wallet-funded fee input (allowed by SIGHASH_SINGLE|ANYONECANPAY).
		const feePriv = crypto.randomBytes(32);
		const feePub = Buffer.from(ecc.pointFromScalar(feePriv, true)!);
		const feeP2wpkh = bitcoin.payments.p2wpkh({
			pubkey: feePub,
			network: NETWORK
		});
		const feeFundTxid = (await bitcoinRpc('sendtoaddress', [
			feeP2wpkh.address,
			0.001
		])) as string;
		await mineBlocks(1);
		const feeFundTx = (await bitcoinRpc('getrawtransaction', [
			feeFundTxid,
			true
		])) as {
			vout: { value: number; n: number; scriptPubKey: { address?: string } }[];
		};
		const feeOut = feeFundTx.vout.find(
			(v) => v.scriptPubKey.address === feeP2wpkh.address
		)!;
		const feeValueSat = Math.round(feeOut.value * 1e8);

		successTx.addInput(Buffer.from(feeFundTxid, 'hex').reverse(), feeOut.n);
		successTx.addOutput(feeP2wpkh.output!, feeValueSat - 500); // 500 sat fee

		// Input 0: the HTLC 2-of-2 success witness (sighash byte 0x83 appended).
		// Received-success leaf is ...<local=alice> CHECKSIGVERIFY <remote=bob>
		// CHECKSIG → alice consumed first (top): bottom→top = bob, alice, preimage.
		const sighashByte = Buffer.from([TAPROOT_HTLC_SIGHASH_TYPE]);
		successTx.ins[0].witness = [
			Buffer.concat([bobSig, sighashByte]),
			Buffer.concat([aliceSig, sighashByte]),
			preimage,
			htlcOut.success.script,
			htlcOut.success.controlBlock
		];
		// Input 1: P2WPKH wallet fee input.
		const feeSighash = successTx.hashForWitnessV0(
			1,
			bitcoin.payments.p2pkh({ pubkey: feePub }).output!,
			feeValueSat,
			bitcoin.Transaction.SIGHASH_ALL
		);
		const feeSig = bitcoin.script.signature.encode(
			Buffer.from(ecc.sign(feeSighash, feePriv)),
			bitcoin.Transaction.SIGHASH_ALL
		);
		successTx.ins[1].witness = [feeSig, feePub];

		const [sAccept] = (await bitcoinRpc('testmempoolaccept', [
			[successTx.toHex()]
		])) as { allowed: boolean; ['reject-reason']?: string }[];
		expect(sAccept.allowed, sAccept['reject-reason']).to.equal(true);

		// And it confirms.
		await bitcoinRpc('sendrawtransaction', [successTx.toHex()]);
		await mineBlocks(1);
		const mined = (await bitcoinRpc('getrawtransaction', [
			successTx.getId(),
			true
		])) as { confirmations?: number };
		expect((mined.confirmations ?? 0) >= 1).to.equal(true);
	});

	// M2 follow-up: sweep the CSV-delayed OUTPUT of our own second-level HTLC tx
	// (the TaprootSecondLevelScriptTree delay leaf) to our destination via
	// resolveSecondLevelHtlcOutput, and prove bitcoind accepts the delay-leaf
	// script-path spend after the CSV matures.
	it('sweeps OUR taproot second-level HTLC output (delay leaf), bitcoind-accepted', async function () {
		if (skip) this.skip();

		const delay = 6;
		const mkCfg = (seed: Buffer, pref: boolean): IChannelManagerConfig => ({
			...configOf(seed, pref),
			localConfig: {
				...DEFAULT_CHANNEL_CONFIG,
				feeratePerKw: 2500,
				toSelfDelay: delay
			}
		});
		const aliceSeed = seedFor(21);
		const bobSeed = seedFor(22);
		const aliceCfg = mkCfg(aliceSeed, true);
		const bobCfg = mkCfg(bobSeed, false);
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
		const state = aliceChannel.getFullState();

		// Reconstruct our commitment #0 second-level output the SAME way the resolver
		// does (revocation = remote's basepoint, delayed = ours, CSV = remoteConfig).
		const point = perCommitmentPointFromSecret(
			generateFromSeed(state.localPerCommitmentSeed, MAX_INDEX - 0n)
		);
		const revocationPubkey = deriveRevocationPubkey(
			bobCfg.localBasepoints.revocationBasepoint,
			point
		);
		const delayedPubkey = derivePublicKey(
			aliceCfg.localBasepoints.delayedPaymentBasepoint,
			point
		);
		const toSelfDelay = state.remoteConfig.toSelfDelay;
		expect(toSelfDelay).to.equal(delay);
		const sl = buildTaprootSecondLevelOutput(
			revocationPubkey,
			delayedPubkey,
			toSelfDelay,
			NETWORK
		);

		// Fund that second-level output as out[0] of a confirmed tx.
		const htlcTx = await fundScriptAtIndex0(sl.output, 100_000);
		const confHeight = (await bitcoinRpc('getblockcount')) as number;
		const dest = bitcoin.address.toOutputScript(
			(await bitcoinRpc('getnewaddress')) as string,
			NETWORK
		);

		const r = resolveSecondLevelHtlcOutput(
			state,
			htlcTx,
			confHeight,
			0n,
			dest,
			2,
			privAt(aliceSeed, 3), // delayed payment basepoint secret
			NETWORK
		);
		expect(r, 'a taproot second-level sweep is produced').to.not.be.null;
		expect(r!.trackedOutput.txid).to.equal(htlcTx.getId());
		expect(r!.csvDelay).to.equal(toSelfDelay);
		const sweep = r!.spendTx!;
		sweep.setWitness(0, r!.witness!);

		// Mature the CSV, then bitcoind must accept the delay-leaf script-path spend.
		await mineBlocks(toSelfDelay);
		const [acc] = (await bitcoinRpc('testmempoolaccept', [
			[sweep.toHex()]
		])) as { allowed: boolean; ['reject-reason']?: string }[];
		expect(acc.allowed, acc['reject-reason']).to.equal(true);

		await bitcoinRpc('sendrawtransaction', [sweep.toHex()]);
		await mineBlocks(1);
		const swept = (await bitcoinRpc('getrawtransaction', [
			sweep.getId(),
			true
		])) as { confirmations?: number };
		expect((swept.confirmations ?? 0) >= 1).to.equal(true);
	});
});
