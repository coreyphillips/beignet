/**
 * Interop (regtest) — P6: the output-resolver auto-classifies and auto-resolves a
 * force-closed TAPROOT commitment. Drives the full ChannelManager, force-closes,
 * then runs classifyOutputs + resolveOurCommitmentOutputs and asserts bitcoind
 * accepts the produced sweeps: the to_local CSV-delay spend and the second-level
 * HTLC-success spend (built from our sig + the peer's stored remoteHtlcSignatures).
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
import { ChannelActionType } from '../../../src/lightning/channel/channel-actions';
import { CommitmentType, OutputType } from '../../../src/lightning/chain/types';
import {
	classifyOutputs,
	resolveOurCommitmentOutputs
} from '../../../src/lightning/chain/output-resolver';
import { createTaprootFundingScript } from '../../../src/lightning/script/funding-taproot';
import { IChannelBasepoints } from '../../../src/lightning/keys/derivation';
import { getPublicKey } from '../../../src/lightning/crypto/ecdh';
import { bitcoinRpc, mineBlocks, ensureBitcoindFunds } from './shared-helpers';

bitcoin.initEccLib(ecc);
const NETWORK = bitcoin.networks.regtest;
const TO_SELF_DELAY = 10;

async function bitcoindUp(): Promise<boolean> {
	try {
		await bitcoinRpc('getblockchaininfo');
		return true;
	} catch {
		return false;
	}
}

function seedFor(id: number): Buffer {
	return crypto.createHash('sha256').update(Buffer.from(`p6-resolver-${id}`)).digest();
}
function privAt(seed: Buffer, i: number): Buffer {
	return crypto.createHash('sha256').update(seed).update(Buffer.from([i])).digest();
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
		localConfig: { ...DEFAULT_CHANNEL_CONFIG, feeratePerKw: 2500, toSelfDelay: TO_SELF_DELAY },
		localBasepoints: basepointsOf(seed),
		localPerCommitmentSeed: seedFor(1000 + seed[0]),
		localFundingPrivkey: privAt(seed, 0),
		htlcBasepointSecret: privAt(seed, 4),
		preferTaproot
	};
}
function connect(a: ChannelManager, aPub: string, b: ChannelManager, bPub: string): void {
	a.on('message:outbound', (peer: string, type: number, payload: Buffer) => {
		if (peer === bPub) b.handleMessage(aPub, type, payload);
	});
	b.on('message:outbound', (peer: string, type: number, payload: Buffer) => {
		if (peer === aPub) a.handleMessage(bPub, type, payload);
	});
}

async function accept(tx: bitcoin.Transaction): Promise<{ ok: boolean; reason?: string }> {
	const [r] = (await bitcoinRpc('testmempoolaccept', [[tx.toHex()]])) as {
		allowed: boolean;
		['reject-reason']?: string;
	}[];
	return { ok: r.allowed, reason: r['reject-reason'] };
}

describe('Interop: option_taproot output-resolver auto-sweep (regtest, P6)', function () {
	this.timeout(60_000);
	let skip = false;
	before(async function () {
		this.timeout(20_000);
		skip = !(await bitcoindUp());
		if (!skip) await ensureBitcoindFunds(2);
	});

	it('classifies + resolves to_local and HTLC-success sweeps that bitcoind accepts', async function () {
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

		const capacitySat = 3_000_000n;
		const funding = createTaprootFundingScript(
			aliceCfg.localBasepoints.fundingPubkey,
			bobCfg.localBasepoints.fundingPubkey,
			NETWORK
		);
		const fundTxid = (await bitcoinRpc('sendtoaddress', [funding.address, 0.03])) as string;
		await mineBlocks(1);
		const fundTx = (await bitcoinRpc('getrawtransaction', [fundTxid, true])) as {
			vout: { value: number; n: number; scriptPubKey: { address?: string } }[];
		};
		const fout = fundTx.vout.find((v) => v.scriptPubKey.address === funding.address)!;

		const aliceChannel = alice.openChannel(bPub, capacitySat, 1_500_000_000n);
		const channelId = alice.createFunding(
			aliceChannel,
			Buffer.from(fundTxid, 'hex').reverse(),
			fout.n,
			crypto.randomBytes(64)
		)!;
		alice.handleFundingConfirmed(channelId);
		bob.handleFundingConfirmed(channelId);
		expect(isTaprootChannel(aliceChannel.getFullState().channelType)).to.equal(true);
		expect(aliceChannel.getFullState().state).to.equal(ChannelState.NORMAL);

		const preimage = crypto.randomBytes(32);
		const paymentHash = crypto.createHash('sha256').update(preimage).digest();
		expect(
			bob.addHtlc(channelId, 300_000_000n, paymentHash, 800, Buffer.alloc(1366)).ok
		).to.equal(true);
		expect(aliceChannel.getFullState().localCommitmentNumber).to.equal(1n);

		// Force-close + confirm the commitment.
		const fc = aliceChannel.forceClose(aliceChannel.getSigner()!);
		const commitTx = bitcoin.Transaction.fromBuffer(
			(fc.find((a) => a.type === ChannelActionType.BROADCAST_TX) as { tx: Buffer }).tx
		);
		expect((await accept(commitTx)).ok).to.equal(true);
		await bitcoinRpc('sendrawtransaction', [commitTx.toHex()]);
		await mineBlocks(1);

		// P6a — classify the force-closed commitment's outputs.
		const tracked = classifyOutputs(
			commitTx,
			aliceChannel.getFullState(),
			CommitmentType.OUR_COMMITMENT,
			1n
		);
		const toLocal = tracked.find((o) => o.outputType === OutputType.TO_LOCAL);
		const htlcOut = tracked.find((o) => o.outputType === OutputType.RECEIVED_HTLC);
		expect(toLocal, 'to_local classified').to.not.be.undefined;
		expect(htlcOut, 'received HTLC classified').to.not.be.undefined;

		// P6b — resolve our outputs into spendable sweeps.
		const destScript = bitcoin.address.toOutputScript(
			(await bitcoinRpc('getnewaddress')) as string,
			NETWORK
		);
		const resolved = resolveOurCommitmentOutputs(
			aliceChannel.getFullState(),
			tracked,
			1n,
			destScript,
			2,
			new Map([[paymentHash.toString('hex'), preimage]]),
			privAt(aliceSeed, 3), // delayed payment basepoint secret
			privAt(aliceSeed, 4), // htlc basepoint secret
			aliceChannel.getFullState().remoteHtlcSignatures
		);

		// ── HTLC-success sweep (zero-fee → attach a wallet fee input) ──
		const htlcResolved = resolved.find(
			(r) => r.trackedOutput.outputType === OutputType.RECEIVED_HTLC
		)!;
		expect(htlcResolved.spendTx, 'HTLC sweep tx').to.not.be.undefined;
		expect(htlcResolved.witness, 'HTLC sweep witness').to.not.be.undefined;
		const htlcSweep = htlcResolved.spendTx!;
		htlcSweep.ins[0].witness = htlcResolved.witness!;

		const feePriv = crypto.randomBytes(32);
		const feePub = Buffer.from(ecc.pointFromScalar(feePriv, true)!);
		const feeP2wpkh = bitcoin.payments.p2wpkh({ pubkey: feePub, network: NETWORK });
		const feeTxid = (await bitcoinRpc('sendtoaddress', [feeP2wpkh.address, 0.001])) as string;
		await mineBlocks(1);
		const feeTx = (await bitcoinRpc('getrawtransaction', [feeTxid, true])) as {
			vout: { value: number; n: number; scriptPubKey: { address?: string } }[];
		};
		const feeO = feeTx.vout.find((v) => v.scriptPubKey.address === feeP2wpkh.address)!;
		const feeVal = Math.round(feeO.value * 1e8);
		htlcSweep.addInput(Buffer.from(feeTxid, 'hex').reverse(), feeO.n);
		htlcSweep.addOutput(feeP2wpkh.output!, feeVal - 500);
		const feeSh = htlcSweep.hashForWitnessV0(
			1,
			bitcoin.payments.p2pkh({ pubkey: feePub }).output!,
			feeVal,
			bitcoin.Transaction.SIGHASH_ALL
		);
		htlcSweep.ins[1].witness = [
			bitcoin.script.signature.encode(
				Buffer.from(ecc.sign(feeSh, feePriv)),
				bitcoin.Transaction.SIGHASH_ALL
			),
			feePub
		];
		const htlcAccept = await accept(htlcSweep);
		expect(htlcAccept.ok, `HTLC sweep: ${htlcAccept.reason}`).to.equal(true);

		// ── to_local sweep (CSV-delayed; mature it, then it carries its own fee) ──
		const toLocalResolved = resolved.find(
			(r) => r.trackedOutput.outputType === OutputType.TO_LOCAL
		)!;
		expect(toLocalResolved.spendTx, 'to_local sweep tx').to.not.be.undefined;
		const toLocalSweep = toLocalResolved.spendTx!;
		toLocalSweep.ins[0].witness = toLocalResolved.witness!;
		await mineBlocks(TO_SELF_DELAY); // mature the CSV delay
		const tlAccept = await accept(toLocalSweep);
		expect(tlAccept.ok, `to_local sweep: ${tlAccept.reason}`).to.equal(true);
	});
});
