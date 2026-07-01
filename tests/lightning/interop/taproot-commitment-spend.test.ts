/**
 * option_taproot commitment outputs — on-chain spendability (regtest, M4.4).
 *
 * Funds real to_local (delay + revoke) and to_remote taproot outputs on regtest
 * bitcoind and spends each tapscript path, asserting the network accepts the
 * spend (testmempoolaccept). This proves the leaf scripts, control blocks, CSV
 * timelocks and script-path Schnorr signatures are all valid Bitcoin.
 *
 * Auto-skips if regtest bitcoind is not reachable.
 */

import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import crypto from 'crypto';
import { bitcoinRpc, mineBlocks } from './shared-helpers';
import {
	buildTaprootToLocalOutput,
	buildTaprootToRemoteOutput,
	ITaprootLeafSpend
} from '../../../src/lightning/script/commitment-taproot';

bitcoin.initEccLib(ecc);
const NETWORK = bitcoin.networks.regtest;

function tapleafHash(leafScript: Buffer, version = 0xc0): Buffer {
	const tag = sha256(Buffer.from('TapLeaf'));
	const h = sha256.create();
	h.update(tag);
	h.update(tag);
	h.update(Buffer.from([version]));
	// scripts here are < 253 bytes → single-byte compact size.
	h.update(Buffer.from([leafScript.length]));
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

/** Fund a taproot address, confirm it with `confirmations` blocks. */
async function fundAndConfirm(
	address: string,
	confirmations: number
): Promise<{ txid: string; vout: number; valueSat: number; scriptHex: string }> {
	const txid = (await bitcoinRpc('sendtoaddress', [address, 0.01])) as string;
	await mineBlocks(confirmations);
	const tx = (await bitcoinRpc('getrawtransaction', [txid, true])) as {
		vout: { value: number; n: number; scriptPubKey: { address?: string; hex: string } }[];
	};
	const out = tx.vout.find((o) => o.scriptPubKey.address === address)!;
	return {
		txid,
		vout: out.n,
		valueSat: Math.round(out.value * 1e8),
		scriptHex: out.scriptPubKey.hex
	};
}

/**
 * Build + sign a 1-in/1-out taproot script-path spend and return whether the
 * network accepts it.
 */
async function spendLeaf(
	utxo: { txid: string; vout: number; valueSat: number; scriptHex: string },
	leaf: ITaprootLeafSpend,
	signerPrivkey: Buffer,
	sequence: number
): Promise<{ allowed: boolean; reason?: string }> {
	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.addInput(
		Buffer.from(utxo.txid, 'hex').reverse(),
		utxo.vout,
		sequence
	);
	const dest = (await bitcoinRpc('getnewaddress')) as string;
	tx.addOutput(
		bitcoin.address.toOutputScript(dest, NETWORK),
		utxo.valueSat - 500
	);

	const prevScript = Buffer.from(utxo.scriptHex, 'hex');
	const sighash = tx.hashForWitnessV1(
		0,
		[prevScript],
		[utxo.valueSat],
		bitcoin.Transaction.SIGHASH_DEFAULT,
		tapleafHash(leaf.script, leaf.leafVersion)
	);
	const sig = Buffer.from(ecc.signSchnorr(sighash, signerPrivkey));
	tx.ins[0].witness = [sig, leaf.script, leaf.controlBlock];

	const [res] = (await bitcoinRpc('testmempoolaccept', [
		[tx.toHex()]
	])) as { allowed: boolean; ['reject-reason']?: string }[];
	return { allowed: res.allowed, reason: res['reject-reason'] };
}

describe('Interop: option_taproot commitment outputs spendable (regtest)', function () {
	this.timeout(60_000);

	let skip = false;
	before(async function () {
		this.timeout(20_000);
		skip = !(await bitcoindUp());
	});

	function keypair(): { priv: Buffer; pub: Buffer } {
		const priv = crypto.randomBytes(32);
		return { priv, pub: Buffer.from(ecc.pointFromScalar(priv, true)!) };
	}

	it('to_local revocation path spends', async function () {
		if (skip) this.skip();
		const revoke = keypair();
		const delayed = keypair();
		const out = buildTaprootToLocalOutput(revoke.pub, delayed.pub, 3, NETWORK);
		const utxo = await fundAndConfirm(out.address, 1);
		// Revocation leaf has no CSV → sequence final.
		const r = await spendLeaf(utxo, out.revoke, revoke.priv, 0xffffffff);
		expect(r.allowed, r.reason).to.be.true;
	});

	it('to_local delay path spends after the CSV matures', async function () {
		if (skip) this.skip();
		const revoke = keypair();
		const delayed = keypair();
		const toSelfDelay = 3;
		const out = buildTaprootToLocalOutput(
			revoke.pub,
			delayed.pub,
			toSelfDelay,
			NETWORK
		);
		// Give the funding output `toSelfDelay` confirmations so BIP68 is satisfied.
		const utxo = await fundAndConfirm(out.address, toSelfDelay);
		const r = await spendLeaf(utxo, out.delay, delayed.priv, toSelfDelay);
		expect(r.allowed, r.reason).to.be.true;
	});

	it('to_remote path spends after its 1-block CSV', async function () {
		if (skip) this.skip();
		const remote = keypair();
		const out = buildTaprootToRemoteOutput(remote.pub, NETWORK);
		const utxo = await fundAndConfirm(out.address, 1);
		const r = await spendLeaf(utxo, out.spend, remote.priv, 1);
		expect(r.allowed, r.reason).to.be.true;
	});

	it('to_local delay path is REJECTED before the CSV matures', async function () {
		if (skip) this.skip();
		const revoke = keypair();
		const delayed = keypair();
		const out = buildTaprootToLocalOutput(revoke.pub, delayed.pub, 5, NETWORK);
		const utxo = await fundAndConfirm(out.address, 1); // only 1 conf, need 5
		const r = await spendLeaf(utxo, out.delay, delayed.priv, 5);
		expect(r.allowed).to.be.false;
		expect(r.reason).to.match(/non-BIP68-final|csv/i);
	});
});
