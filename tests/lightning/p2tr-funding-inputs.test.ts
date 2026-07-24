/**
 * P2TR wallet inputs on the funding paths.
 *
 * The funding provider must select and sign taproot key-path UTXOs alongside
 * P2WPKH, and its P2TR closures must refuse to sign without the full prevout
 * set (BIP 341 sighashes commit to the scripts and values of ALL inputs).
 */
import { expect } from 'chai';
import * as crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { ECPairFactory } from 'ecpair';
import {
	WalletFundingProvider,
	scriptKind,
	taprootTweakPrivateKey
} from '../../src/lightning/wallet/wallet-funding-provider';

bitcoin.initEccLib(ecc);
const ECPair = ECPairFactory(ecc);
const network = bitcoin.networks.regtest;

function ok<T>(value: T) {
	return { isErr: () => false, value };
}

/**
 * One P2WPKH and one P2TR coin, each with a real funding transaction so the
 * provider can resolve prevouts, plus the minimal wallet surface
 * gatherWalletInputs touches.
 */
function makeWallet() {
	const wpkhKey = ECPair.makeRandom({ network });
	const trKey = ECPair.makeRandom({ network });
	const wpkhPub = Buffer.from(wpkhKey.publicKey);
	const trPub = Buffer.from(trKey.publicKey);

	const wpkh = bitcoin.payments.p2wpkh({ pubkey: wpkhPub, network });
	const tr = bitcoin.payments.p2tr({
		internalPubkey: trPub.subarray(1, 33),
		network
	});

	const fund = (script: Buffer, value: number): bitcoin.Transaction => {
		const tx = new bitcoin.Transaction();
		tx.version = 2;
		tx.addInput(crypto.randomBytes(32), 0);
		tx.addOutput(script, value);
		return tx;
	};
	const wpkhFundingTx = fund(wpkh.output!, 60_000);
	const trFundingTx = fund(tr.output!, 80_000);

	const keysByPath: Record<string, string> = {
		"m/84'/0/0": wpkhKey.toWIF(),
		"m/86'/0/0": trKey.toWIF()
	};
	const utxos = [
		{
			address: wpkh.address!,
			path: "m/84'/0/0",
			tx_hash: wpkhFundingTx.getId(),
			tx_pos: 0,
			value: 60_000,
			height: 100,
			publicKey: wpkhPub.toString('hex')
		},
		{
			address: tr.address!,
			path: "m/86'/0/0",
			tx_hash: trFundingTx.getId(),
			tx_pos: 0,
			value: 80_000,
			height: 100,
			publicKey: trPub.toString('hex')
		}
	];
	const hexByTxid: Record<string, string> = {
		[wpkhFundingTx.getId()]: wpkhFundingTx.toHex(),
		[trFundingTx.getId()]: trFundingTx.toHex()
	};

	const wallet = {
		network: 'regtest',
		send: async () => ok(''),
		listUtxos: () => utxos,
		getPrivateKey: (path: string) => keysByPath[path],
		getChangeAddress: async () => ok({ address: wpkh.address! }),
		electrum: {
			getTransactions: async (params: {
				txHashes: Array<{ tx_hash: string }>;
			}) =>
				ok({
					data: params.txHashes.map((t) => ({
						data: { tx_hash: t.tx_hash },
						result: { txid: t.tx_hash, hex: hexByTxid[t.tx_hash] }
					}))
				})
		}
	};
	return { wallet, wpkh, tr, trPub };
}

describe('P2TR funding inputs', function () {
	it('classifies script kinds', function () {
		const { wpkh, tr } = makeWallet();
		expect(scriptKind(wpkh.output!)).to.equal('p2wpkh');
		expect(scriptKind(tr.output!)).to.equal('p2tr');
		expect(scriptKind(Buffer.from('6a24aa21a9ed', 'hex'))).to.equal(null);
	});

	it('selects and signs P2TR alongside P2WPKH; taproot signature verifies', async function () {
		const { wallet, tr } = makeWallet();
		const provider = new WalletFundingProvider(wallet as never);

		// Both coins are needed to cover the target, so selection must accept
		// the taproot one rather than filter it out.
		const { inputs } = await provider.selectSpliceInputs!(100_000n, 1000);
		expect(inputs.length).to.equal(2);

		// Spend both into a dummy output and sign each input.
		const spend = new bitcoin.Transaction();
		spend.version = 2;
		const prevoutScripts: Buffer[] = [];
		const prevoutValues: bigint[] = [];
		for (const input of inputs) {
			const prev = bitcoin.Transaction.fromBuffer(input.prevTx);
			spend.addInput(prev.getHash(), input.prevOutputIndex, input.sequence);
			prevoutScripts.push(Buffer.from(prev.outs[input.prevOutputIndex].script));
			prevoutValues.push(BigInt(prev.outs[input.prevOutputIndex].value));
		}
		spend.addOutput(tr.output!, 139_000);
		const prevouts = { scripts: prevoutScripts, values: prevoutValues };

		for (let i = 0; i < inputs.length; i++) {
			const witness = inputs[i].signWitness(
				spend,
				i,
				inputs[i].value,
				prevouts
			);
			spend.setWitness(i, witness);
		}

		// The taproot input carries exactly one 64-byte Schnorr signature that
		// verifies against the output key of the funded address.
		const trIndex = prevoutScripts.findIndex((s) => scriptKind(s) === 'p2tr');
		const trWitness = spend.ins[trIndex].witness;
		expect(trWitness.length).to.equal(1);
		expect(trWitness[0].length).to.equal(64);
		const sighash = spend.hashForWitnessV1(
			trIndex,
			prevoutScripts,
			prevoutValues.map((v) => Number(v)),
			bitcoin.Transaction.SIGHASH_DEFAULT
		);
		const outputKey = prevoutScripts[trIndex].subarray(2);
		expect(ecc.verifySchnorr(sighash, outputKey, trWitness[0])).to.equal(true);

		// The P2WPKH witness keeps its [der, pubkey] shape.
		const wpkhIndex = trIndex === 0 ? 1 : 0;
		expect(spend.ins[wpkhIndex].witness.length).to.equal(2);
	});

	it('refuses to sign a P2TR input without the prevout set', async function () {
		const { wallet } = makeWallet();
		const provider = new WalletFundingProvider(wallet as never);
		const { inputs } = await provider.selectSpliceInputs!(100_000n, 1000);
		const trInput = inputs.find((i) => {
			const prev = bitcoin.Transaction.fromBuffer(i.prevTx);
			return (
				scriptKind(Buffer.from(prev.outs[i.prevOutputIndex].script)) === 'p2tr'
			);
		})!;
		const spend = new bitcoin.Transaction();
		spend.version = 2;
		const prev = bitcoin.Transaction.fromBuffer(trInput.prevTx);
		spend.addInput(prev.getHash(), trInput.prevOutputIndex, trInput.sequence);
		spend.addOutput(prev.outs[0].script, 79_000);
		expect(() => trInput.signWitness(spend, 0, trInput.value)).to.throw(
			'full prevout set'
		);
	});

	it('fee-bump selection never picks P2TR coins', async function () {
		// The fee-bump attach paths (sweep.ts) sign wallet inputs with
		// (tx, index, value) only and cannot supply the prevout set a BIP 341
		// sighash commits to, so selectFeeBumpInputs must stay P2WPKH-only.
		const { wallet } = makeWallet();
		const provider = new WalletFundingProvider(wallet as never);

		// A small target is covered by the P2WPKH coin alone.
		const { inputs } = await provider.selectFeeBumpInputs!(10_000n, 1000);
		for (const input of inputs) {
			const prev = bitcoin.Transaction.fromBuffer(input.prevTx);
			expect(
				scriptKind(Buffer.from(prev.outs[input.prevOutputIndex].script))
			).to.equal('p2wpkh');
		}

		// A target beyond the P2WPKH balance must fail honestly instead of
		// reaching for the taproot coin it cannot sign.
		try {
			await provider.selectFeeBumpInputs!(100_000n, 1000);
			expect.fail('expected insufficient-funds error');
		} catch (err) {
			expect((err as Error).message).to.contain('insufficient wallet funds');
		}
	});

	it('taproot key tweak matches the address output key', function () {
		const key = ECPair.makeRandom({ network });
		const pub = Buffer.from(key.publicKey);
		const payment = bitcoin.payments.p2tr({
			internalPubkey: pub.subarray(1, 33),
			network
		});
		const tweaked = taprootTweakPrivateKey(Buffer.from(key.privateKey!), pub);
		const msg = crypto.randomBytes(32);
		const sig = Buffer.from(ecc.signSchnorr(msg, tweaked));
		const outputKey = payment.output!.subarray(2);
		expect(ecc.verifySchnorr(msg, outputKey, sig)).to.equal(true);
	});
});
