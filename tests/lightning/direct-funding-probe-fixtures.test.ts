import { expect } from 'chai';
import fs from 'fs';
import path from 'path';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import {
	decodeDfOffer,
	deriveOfferId,
	encodeDfOffer,
	IDfOffer,
	ownershipProbeTransaction
} from '../../src/lightning/direct-funding/messages';
import {
	offerFieldProblem,
	ownershipProblem
} from '../../src/lightning/direct-funding/receiver/verify';

interface IProbeFixture {
	kind: 'p2wpkh' | 'p2tr';
	txid: string;
	vout: number;
	coinValueSat: string;
	coinScript: string;
	amountSat: string;
	sequence: number;
	offerId: string;
	unsignedTx: string;
	unsignedPsbt: string;
	signedPsbt: string;
	proof: { pubkey: string; signature: string };
}

const captured = JSON.parse(
	fs.readFileSync(
		path.join(__dirname, 'fixtures/cln-ownership-probes.json'),
		'utf8'
	)
) as { software: string; network: string; fixtures: IProbeFixture[] };

function offerFor(f: IProbeFixture): IDfOffer {
	const script = Buffer.from(f.coinScript, 'hex');
	return {
		offerId: Buffer.from(f.offerId, 'hex'),
		txid: Buffer.from(f.txid, 'hex'),
		vout: f.vout,
		amountSat: BigInt(f.amountSat),
		valueSat: BigInt(f.coinValueSat),
		sequence: f.sequence,
		changeScript: script,
		maxTotalFeeSat: 1000n,
		receiptHash: Buffer.alloc(32, 1),
		ownership: {
			pubkey:
				f.kind === 'p2tr'
					? script.subarray(2)
					: Buffer.from(f.proof.pubkey, 'hex'),
			signature: Buffer.alloc(64),
			probeProof: {
				pubkey: Buffer.from(f.proof.pubkey, 'hex'),
				signature: Buffer.from(f.proof.signature, 'hex')
			}
		}
	};
}

describe('Direct funding: captured CLN ownership probe signatures', () => {
	it('covers both coin kinds on regtest with an external signer', () => {
		expect(captured.network).to.equal('regtest');
		expect(captured.software).to.match(/^v26\.06/);
		expect(captured.fixtures.map((f) => f.kind)).to.deep.equal([
			'p2wpkh',
			'p2tr'
		]);
	});

	for (const f of captured.fixtures) {
		it(`${f.kind}: reconstructs the exact unsigned transaction signed by CLN`, () => {
			const offer = offerFor(f);
			expect(
				deriveOfferId(offer.txid, offer.vout, offer.amountSat).toString('hex')
			).to.equal(f.offerId);
			const { tx } = ownershipProbeTransaction(
				offer.offerId,
				offer.txid,
				offer.vout,
				offer.sequence,
				Buffer.from(f.coinScript, 'hex'),
				offer.valueSat
			);
			expect(tx.toHex()).to.equal(f.unsignedTx);
			for (const bytes of [f.unsignedPsbt, f.signedPsbt]) {
				const psbt = bitcoin.Psbt.fromBase64(bytes);
				expect(
					psbt.data.globalMap.unsignedTx.toBuffer().toString('hex')
				).to.equal(f.unsignedTx);
			}
			const signed = bitcoin.Psbt.fromBase64(f.signedPsbt).data.inputs[0];
			if (f.kind === 'p2tr') {
				expect(signed.tapKeySig!.toString('hex')).to.equal(f.proof.signature);
			} else {
				const decoded = bitcoin.script.signature.decode(
					signed.partialSig![0].signature
				);
				expect(decoded.hashType).to.equal(bitcoin.Transaction.SIGHASH_ALL);
				expect(decoded.signature.toString('hex')).to.equal(f.proof.signature);
			}
		});

		it(`${f.kind}: accepts the captured proof after a wire round trip`, () => {
			const offer = decodeDfOffer(encodeDfOffer(offerFor(f)));
			expect(
				ownershipProblem(offer, Buffer.from(f.coinScript, 'hex'))
			).to.equal(null);
		});

		it(`${f.kind}: rejects a changed amount with either the stale or recomputed offer ID`, () => {
			const offer = offerFor(f);
			offer.amountSat++;
			expect(offerFieldProblem(offer, {})).to.contain('offer id');
			offer.offerId = deriveOfferId(offer.txid, offer.vout, offer.amountSat);
			expect(offerFieldProblem(offer, {})).to.equal(null);
			expect(
				ownershipProblem(offer, Buffer.from(f.coinScript, 'hex'))
			).not.to.equal(null);
		});

		for (const field of [
			'sequence',
			'vout',
			'txid',
			'valueSat',
			'offerId'
		] as const) {
			it(`${f.kind}: rejects a captured signature after changing ${field}`, () => {
				const offer = offerFor(f);
				if (field === 'sequence') offer.sequence--;
				if (field === 'vout') offer.vout++;
				if (field === 'txid') offer.txid[0] ^= 1;
				if (field === 'valueSat') offer.valueSat++;
				if (field === 'offerId') offer.offerId[0] ^= 1;
				expect(
					ownershipProblem(offer, Buffer.from(f.coinScript, 'hex'))
				).not.to.equal(null);
			});
		}

		it(`${f.kind}: the signature cannot authorize a transaction without the poison input`, () => {
			const tx = bitcoin.Transaction.fromHex(f.unsignedTx);
			tx.ins.pop();
			const signature = Buffer.from(f.proof.signature, 'hex');
			const coinScript = Buffer.from(f.coinScript, 'hex');
			if (f.kind === 'p2tr') {
				const digest = tx.hashForWitnessV1(
					0,
					[coinScript],
					[Number(f.coinValueSat)],
					bitcoin.Transaction.SIGHASH_DEFAULT
				);
				expect(
					ecc.verifySchnorr(digest, coinScript.subarray(2), signature)
				).to.equal(false);
			} else {
				const pubkey = Buffer.from(f.proof.pubkey, 'hex');
				const code = bitcoin.payments.p2pkh({ pubkey }).output!;
				const digest = tx.hashForWitnessV0(
					0,
					code,
					Number(f.coinValueSat),
					bitcoin.Transaction.SIGHASH_ALL
				);
				expect(ecc.verify(digest, pubkey, signature)).to.equal(false);
			}
		});
	}
});
