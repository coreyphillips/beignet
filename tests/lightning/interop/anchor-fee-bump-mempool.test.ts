/**
 * Regtest mempool-acceptance validation for anchor fee bumping (bitcoind only).
 *
 * Proves, against a REAL bitcoind node, that the two fee-bump builders produce
 * transactions the network will actually relay:
 *
 *  1. attachFeeInputsToZeroFeeHtlcTx — a parent input pre-signed with
 *     SIGHASH_SINGLE|ANYONECANPAY (the zero-fee second-level HTLC case) stays
 *     valid when a wallet fee input + change are appended, and the combined tx
 *     is accepted by `testmempoolaccept`.
 *  2. buildAnchorCpfpTx — the anchor owner-path witness is spendable on a real
 *     node and the CPFP child is relay-acceptable.
 *
 * Needs only bitcoind (no LND/CLN). Skips cleanly when bitcoind is unreachable.
 * NOTE: authored without a local Docker daemon; run it in the regtest harness:
 *   npx mocha --exit --timeout 120000 -r ts-node/register \
 *     tests/lightning/interop/anchor-fee-bump-mempool.test.ts
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { ECPairFactory } from 'ecpair';
import { bitcoinRpc, ensureBitcoindFunds, mineBlocks } from './shared-helpers';
import {
	attachFeeInputsToZeroFeeHtlcTx,
	buildAnchorCpfpTx,
	signSweepInput
} from '../../../src/lightning/chain/sweep';
import { buildAnchorOutput } from '../../../src/lightning/script/anchor';
import type { ISpliceWalletInput } from '../../../src/lightning/channel/channel';

bitcoin.initEccLib(ecc);
const ECPair = ECPairFactory(ecc);
const network = bitcoin.networks.regtest;

const SIGHASH_ALL = bitcoin.Transaction.SIGHASH_ALL;
const SIGHASH_ANCHOR =
	bitcoin.Transaction.SIGHASH_SINGLE | bitcoin.Transaction.SIGHASH_ANYONECANPAY;

interface IFundedUtxo {
	priv: Buffer;
	pubkey: Buffer;
	prevTx: Buffer;
	vout: number;
	value: bigint;
}

/** Send to a fresh P2WPKH address we control, confirm it, and return the UTXO. */
async function fundP2wpkh(
	seed: string,
	amountSats: number
): Promise<IFundedUtxo> {
	const priv = crypto.createHash('sha256').update(`mempool-${seed}`).digest();
	const keyPair = ECPair.fromPrivateKey(priv, { network });
	const pubkey = Buffer.from(keyPair.publicKey);
	const address = bitcoin.payments.p2wpkh({ pubkey, network }).address!;

	const txid = (await bitcoinRpc('sendtoaddress', [
		address,
		amountSats / 1e8
	])) as string;
	await mineBlocks(1);
	const wtx = (await bitcoinRpc('gettransaction', [txid])) as { hex: string };
	const tx = bitcoin.Transaction.fromHex(wtx.hex);
	const script = bitcoin.payments.p2wpkh({ pubkey, network }).output!;
	const vout = tx.outs.findIndex((o) => o.script.equals(script));
	if (vout < 0) throw new Error('funded vout not found');
	return {
		priv,
		pubkey,
		prevTx: Buffer.from(tx.toBuffer()),
		vout,
		value: BigInt(tx.outs[vout].value)
	};
}

/** Wrap a funded P2WPKH UTXO as an ISpliceWalletInput with a real signWitness. */
function asWalletInput(u: IFundedUtxo): ISpliceWalletInput {
	const scriptCode = bitcoin.payments.p2pkh({ pubkey: u.pubkey, network })
		.output!;
	return {
		prevTx: u.prevTx,
		prevOutputIndex: u.vout,
		value: u.value,
		sequence: 0xfffffffd,
		confirmed: true,
		signWitness: (tx, inputIndex, value) => {
			const sighash = tx.hashForWitnessV0(
				inputIndex,
				scriptCode,
				Number(value),
				SIGHASH_ALL
			);
			const der = bitcoin.script.signature.encode(
				Buffer.from(ecc.sign(sighash, u.priv)),
				SIGHASH_ALL
			);
			return [der, u.pubkey];
		}
	};
}

async function testmempoolaccept(
	rawTxs: string[]
): Promise<Array<{ allowed: boolean; ['reject-reason']?: string }>> {
	return (await bitcoinRpc('testmempoolaccept', [rawTxs])) as Array<{
		allowed: boolean;
	}>;
}

async function changeScript(): Promise<Buffer> {
	const addr = (await bitcoinRpc('getnewaddress', [
		'fee-bump-change',
		'bech32'
	])) as string;
	return bitcoin.address.toOutputScript(addr, network);
}

describe('Interop: anchor fee bumping mempool acceptance (regtest)', function () {
	this.timeout(120_000);
	let skipAll = false;

	before(async function () {
		try {
			await bitcoinRpc('getblockchaininfo');
			await ensureBitcoindFunds(2);
		} catch {
			skipAll = true;
			console.log(
				'    ⚠ bitcoind not available — skipping anchor fee-bump mempool tests.'
			);
			this.skip();
		}
	});

	it('accepts a zero-fee HTLC tx after a wallet fee input is attached', async function () {
		if (skipAll) this.skip();

		// "Parent" input: pre-signed SIGHASH_SINGLE|ANYONECANPAY, zero fee (output
		// keeps the full input value) — exactly the second-level HTLC shape.
		const parentUtxo = await fundP2wpkh('htlc-parent', 60_000);
		const feeUtxo = await fundP2wpkh('htlc-fee', 60_000);

		const htlcTx = new bitcoin.Transaction();
		htlcTx.version = 2;
		htlcTx.addInput(
			bitcoin.Transaction.fromBuffer(parentUtxo.prevTx).getHash(),
			parentUtxo.vout,
			1
		);
		const sink = bitcoin.payments.p2wsh({
			redeem: { output: bitcoin.script.compile([bitcoin.opcodes.OP_TRUE]) },
			network
		}).output!;
		htlcTx.addOutput(sink, Number(parentUtxo.value)); // zero fee

		// Pre-sign the parent input as the counterparty would (P2WPKH scriptCode).
		const parentScriptCode = bitcoin.payments.p2pkh({
			pubkey: parentUtxo.pubkey,
			network
		}).output!;
		const parentSig = signSweepInput(
			htlcTx,
			0,
			parentScriptCode,
			Number(parentUtxo.value),
			parentUtxo.priv,
			SIGHASH_ANCHOR
		);
		const htlcWitness = [parentSig, parentUtxo.pubkey];

		const { tx } = attachFeeInputsToZeroFeeHtlcTx({
			htlcTx,
			htlcWitness,
			walletInputs: [asWalletInput(feeUtxo)],
			changeScript: await changeScript(),
			feeratePerVbyte: 5
		});

		const [res] = await testmempoolaccept([tx.toHex()]);
		expect(res.allowed, res['reject-reason']).to.be.true;
	});

	it('accepts an anchor CPFP child spending a confirmed anchor output', async function () {
		if (skipAll) this.skip();

		// Build a "commitment-like" parent carrying our anchor output, confirm it.
		const fundingUtxo = await fundP2wpkh('cpfp-funding', 80_000);
		const feeUtxo = await fundP2wpkh('cpfp-fee', 60_000);
		const anchor = buildAnchorOutput(fundingUtxo.pubkey);

		const parent = new bitcoin.Transaction();
		parent.version = 2;
		parent.addInput(
			bitcoin.Transaction.fromBuffer(fundingUtxo.prevTx).getHash(),
			fundingUtxo.vout,
			0xffffffff
		);
		parent.addOutput(anchor.script, 330);
		const parentFee = 300n;
		parent.addOutput(
			await changeScript(),
			Number(fundingUtxo.value - 330n - parentFee)
		);
		const fundingScriptCode = bitcoin.payments.p2pkh({
			pubkey: fundingUtxo.pubkey,
			network
		}).output!;
		const fundingSig = signSweepInput(
			parent,
			0,
			fundingScriptCode,
			Number(fundingUtxo.value),
			fundingUtxo.priv
		);
		parent.setWitness(0, [fundingSig, fundingUtxo.pubkey]);

		const [parentRes] = await testmempoolaccept([parent.toHex()]);
		expect(parentRes.allowed, parentRes['reject-reason']).to.be.true;
		await bitcoinRpc('sendrawtransaction', [parent.toHex()]);
		await mineBlocks(1);

		const { tx } = buildAnchorCpfpTx({
			commitmentTxid: parent.getId(),
			anchorOutputIndex: 0,
			anchorAmount: 330n,
			anchorWitnessScript: anchor.witnessScript,
			localFundingPrivkey: fundingUtxo.priv,
			parentVbytes: parent.virtualSize(),
			parentFeeSats: parentFee,
			walletInputs: [asWalletInput(feeUtxo)],
			changeScript: await changeScript(),
			feeratePerVbyte: 5
		});

		const [childRes] = await testmempoolaccept([tx.toHex()]);
		expect(childRes.allowed, childRes['reject-reason']).to.be.true;
	});
});
