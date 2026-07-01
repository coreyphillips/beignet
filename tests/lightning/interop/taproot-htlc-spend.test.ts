/**
 * option_taproot HTLC outputs — on-chain spendability (regtest, M4.4).
 *
 * Funds real offered/received taproot HTLC outputs and spends every path through
 * testmempoolaccept: the preimage-success leaf, the 2-of-2 timeout/success leaf,
 * the CLTV timeout leaf, and the revocation key-path (breach). This proves the
 * HTLC leaf scripts, control blocks, preimage/CLTV checks and the key-path tweak
 * are all valid Bitcoin. Auto-skips if regtest bitcoind is unreachable.
 */

import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import crypto from 'crypto';
import { bitcoinRpc, mineBlocks } from './shared-helpers';
import {
	buildTaprootOfferedHtlcOutput,
	buildTaprootReceivedHtlcOutput,
	buildTaprootAnchorOutput,
	ITaprootLeafSpend
} from '../../../src/lightning/script/commitment-taproot';

bitcoin.initEccLib(ecc);
const NETWORK = bitcoin.networks.regtest;

function taggedHash(tag: string, data: Buffer): Buffer {
	const t = sha256(Buffer.from(tag));
	const h = sha256.create();
	h.update(t);
	h.update(t);
	h.update(data);
	return Buffer.from(h.digest());
}

function tapleafHash(leafScript: Buffer, version = 0xc0): Buffer {
	const h = sha256.create();
	const t = sha256(Buffer.from('TapLeaf'));
	h.update(t);
	h.update(t);
	h.update(Buffer.from([version, leafScript.length]));
	h.update(leafScript);
	return Buffer.from(h.digest());
}

async function bitcoindUp(): Promise<boolean> {
	try {
		await bitcoinRpc('getblockchaininfo');
		return true;
	} catch {
		return false;
	}
}

type Utxo = { txid: string; vout: number; valueSat: number; scriptHex: string };

async function fundAndConfirm(address: string, confs = 1): Promise<Utxo> {
	const txid = (await bitcoinRpc('sendtoaddress', [address, 0.01])) as string;
	await mineBlocks(confs);
	const tx = (await bitcoinRpc('getrawtransaction', [txid, true])) as {
		vout: {
			value: number;
			n: number;
			scriptPubKey: { address?: string; hex: string };
		}[];
	};
	const o = tx.vout.find((v) => v.scriptPubKey.address === address)!;
	return {
		txid,
		vout: o.n,
		valueSat: Math.round(o.value * 1e8),
		scriptHex: o.scriptPubKey.hex
	};
}

async function spendTx(
	utxo: Utxo,
	sequence: number,
	nLockTime: number
): Promise<bitcoin.Transaction> {
	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.locktime = nLockTime;
	tx.addInput(Buffer.from(utxo.txid, 'hex').reverse(), utxo.vout, sequence);
	const dest = (await bitcoinRpc('getnewaddress')) as string;
	tx.addOutput(
		bitcoin.address.toOutputScript(dest, NETWORK),
		utxo.valueSat - 600
	);
	return tx;
}

function leafSighash(
	tx: bitcoin.Transaction,
	utxo: Utxo,
	leaf: ITaprootLeafSpend
): Buffer {
	return tx.hashForWitnessV1(
		0,
		[Buffer.from(utxo.scriptHex, 'hex')],
		[utxo.valueSat],
		bitcoin.Transaction.SIGHASH_DEFAULT,
		tapleafHash(leaf.script, leaf.leafVersion)
	);
}

function sign(sighash: Buffer, priv: Buffer): Buffer {
	return Buffer.from(ecc.signSchnorr(sighash, priv));
}

async function accepted(
	tx: bitcoin.Transaction
): Promise<{ ok: boolean; reason?: string }> {
	const [r] = (await bitcoinRpc('testmempoolaccept', [[tx.toHex()]])) as {
		allowed: boolean;
		['reject-reason']?: string;
	}[];
	return { ok: r.allowed, reason: r['reject-reason'] };
}

/** Sign + attach a taproot key-path spend (revocation/breach, or anchor owner). */
function keyPathWitness(
	tx: bitcoin.Transaction,
	utxo: Utxo,
	output: { internalKey: Buffer; merkleRoot: Buffer },
	internalPriv: Buffer
): void {
	const sighash = tx.hashForWitnessV1(
		0,
		[Buffer.from(utxo.scriptHex, 'hex')],
		[utxo.valueSat],
		bitcoin.Transaction.SIGHASH_DEFAULT
	);
	// BIP341 key-path tweak: t = H_TapTweak(internalKey || merkleRoot).
	const tweak = taggedHash(
		'TapTweak',
		Buffer.concat([output.internalKey, output.merkleRoot])
	);
	const internalPub = Buffer.from(ecc.pointFromScalar(internalPriv, true)!);
	const dPrime =
		internalPub[0] === 0x02 ? internalPriv : ecc.privateNegate(internalPriv);
	const tweakedPriv = Buffer.from(ecc.privateAdd(dPrime, tweak)!);
	tx.ins[0].witness = [sign(sighash, tweakedPriv)];
}

describe('Interop: option_taproot HTLC outputs spendable (regtest)', function () {
	this.timeout(60_000);
	let skip = false;
	before(async function () {
		this.timeout(20_000);
		skip = !(await bitcoindUp());
	});

	const kp = (): { priv: Buffer; pub: Buffer } => {
		const priv = crypto.randomBytes(32);
		return { priv, pub: Buffer.from(ecc.pointFromScalar(priv, true)!) };
	};
	const preimage = crypto.randomBytes(32);
	const paymentHash = Buffer.from(sha256(preimage));

	it('offered HTLC: remote sweeps via the preimage-success leaf', async function () {
		if (skip) this.skip();
		const revoke = kp(),
			local = kp(),
			remote = kp();
		const htlc = buildTaprootOfferedHtlcOutput(
			revoke.pub,
			local.pub,
			remote.pub,
			paymentHash,
			NETWORK
		);
		const utxo = await fundAndConfirm(htlc.address);
		// Offered-success leaf now ends in OP_1 OP_CSV OP_DROP → spend needs seq=1.
		const tx = await spendTx(utxo, 1, 0);
		const sig = sign(leafSighash(tx, utxo, htlc.success), remote.priv);
		tx.ins[0].witness = [
			sig,
			preimage,
			htlc.success.script,
			htlc.success.controlBlock
		];
		const r = await accepted(tx);
		expect(r.ok, r.reason).to.be.true;
	});

	it('offered HTLC: local reclaims via the 2-of-2 timeout leaf', async function () {
		if (skip) this.skip();
		const revoke = kp(),
			local = kp(),
			remote = kp();
		const htlc = buildTaprootOfferedHtlcOutput(
			revoke.pub,
			local.pub,
			remote.pub,
			paymentHash,
			NETWORK
		);
		const utxo = await fundAndConfirm(htlc.address);
		const tx = await spendTx(utxo, 0xffffffff, 0);
		const sh = leafSighash(tx, utxo, htlc.timeout);
		// Leaf is <local> CHECKSIGVERIFY <remote> CHECKSIG → local consumed first
		// (top). Witness (bottom→top): remoteSig, localSig.
		tx.ins[0].witness = [
			sign(sh, remote.priv),
			sign(sh, local.priv),
			htlc.timeout.script,
			htlc.timeout.controlBlock
		];
		const r = await accepted(tx);
		expect(r.ok, r.reason).to.be.true;
	});

	it('received HTLC: local sweeps via the 2-of-2 preimage-success leaf', async function () {
		if (skip) this.skip();
		const revoke = kp(),
			local = kp(),
			remote = kp();
		const htlc = buildTaprootReceivedHtlcOutput(
			revoke.pub,
			local.pub,
			remote.pub,
			paymentHash,
			100,
			NETWORK
		);
		const utxo = await fundAndConfirm(htlc.address);
		const tx = await spendTx(utxo, 0xffffffff, 0);
		const sh = leafSighash(tx, utxo, htlc.success);
		// Leaf is ...<local> CHECKSIGVERIFY <remote> CHECKSIG → consume preimage
		// (top), then localSig, then remoteSig. Witness (bottom→top):
		tx.ins[0].witness = [
			sign(sh, remote.priv),
			sign(sh, local.priv),
			preimage,
			htlc.success.script,
			htlc.success.controlBlock
		];
		const r = await accepted(tx);
		expect(r.ok, r.reason).to.be.true;
	});

	it('received HTLC: remote reclaims via the CLTV timeout leaf', async function () {
		if (skip) this.skip();
		const revoke = kp(),
			local = kp(),
			remote = kp();
		const cltv = 100; // well below the regtest tip → locktime satisfied
		const htlc = buildTaprootReceivedHtlcOutput(
			revoke.pub,
			local.pub,
			remote.pub,
			paymentHash,
			cltv,
			NETWORK
		);
		const utxo = await fundAndConfirm(htlc.address);
		// Leaf is <remote> CHECKSIG OP_1 OP_CSV OP_DROP <cltv> OP_CLTV OP_DROP →
		// seq=1 satisfies both the CSV-1 and keeps the input non-final for CLTV.
		const tx = await spendTx(utxo, 1, cltv);
		const sig = sign(leafSighash(tx, utxo, htlc.timeout), remote.priv);
		tx.ins[0].witness = [sig, htlc.timeout.script, htlc.timeout.controlBlock];
		const r = await accepted(tx);
		expect(r.ok, r.reason).to.be.true;
	});

	it('offered HTLC: breach is swept via the revocation key-path', async function () {
		if (skip) this.skip();
		const revoke = kp(),
			local = kp(),
			remote = kp();
		const htlc = buildTaprootOfferedHtlcOutput(
			revoke.pub,
			local.pub,
			remote.pub,
			paymentHash,
			NETWORK
		);
		const utxo = await fundAndConfirm(htlc.address);
		const tx = await spendTx(utxo, 0xffffffff, 0);
		keyPathWitness(tx, utxo, htlc, revoke.priv);
		const r = await accepted(tx);
		expect(r.ok, r.reason).to.be.true;
	});

	it('anchor: owner sweeps immediately via the funding key-path', async function () {
		if (skip) this.skip();
		const funding = kp();
		const anchor = buildTaprootAnchorOutput(funding.pub, NETWORK);
		const utxo = await fundAndConfirm(anchor.address);
		const tx = await spendTx(utxo, 0xffffffff, 0);
		keyPathWitness(tx, utxo, anchor, funding.priv);
		const r = await accepted(tx);
		expect(r.ok, r.reason).to.be.true;
	});

	it('anchor: anyone sweeps via the 16-block CSV leaf', async function () {
		if (skip) this.skip();
		const funding = kp();
		const anchor = buildTaprootAnchorOutput(funding.pub, NETWORK);
		const utxo = await fundAndConfirm(anchor.address, 16); // 16 confs for CSV
		const tx = await spendTx(utxo, 16, 0);
		tx.ins[0].witness = [anchor.anyone.script, anchor.anyone.controlBlock];
		const r = await accepted(tx);
		expect(r.ok, r.reason).to.be.true;
	});
});
