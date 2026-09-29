import { expect } from 'chai';
import fs from 'fs';
import path from 'path';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import {
	decodeDfOffer,
	deriveOfferId,
	DF_PROBE_POISON_SCRIPT,
	encodeDfOffer,
	IDfOffer,
	ownershipProbeTransaction
} from '../../src/lightning/direct-funding/messages';
import {
	offerFieldProblem,
	ownershipProblem
} from '../../src/lightning/direct-funding/receiver/verify';
import {
	buildOffer,
	FakeDfNode,
	makeBip86Coin,
	makeCoin
} from './helpers/df-receiver';

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

const RECEIPT_HASH = Buffer.alloc(32, 1);

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
		receiptHash: RECEIPT_HASH,
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
		// Captured before the probe named the request (#1044): what CLN signed
		// is today's probe with only the offer id in its OP_RETURN.
		it(`${f.kind}: differs from the transaction CLN signed only by the receipt hash`, () => {
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
				offer.valueSat,
				offer.receiptHash
			);
			expect(tx.outs[0].script).to.deep.equal(
				Buffer.concat([Buffer.from([0x6a, 48]), offer.offerId, RECEIPT_HASH])
			);
			tx.outs[0].script = Buffer.concat([
				Buffer.from([0x6a, 16]),
				offer.offerId
			]);
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

		it(`${f.kind}: the captured signature is valid over the transaction CLN signed`, () => {
			expect(
				capturedSignatureSigns(f, bitcoin.Transaction.fromHex(f.unsignedTx))
			).to.equal(true);
		});

		it(`${f.kind}: refuses the captured proof, which does not name the request (#1044)`, () => {
			const offer = decodeDfOffer(encodeDfOffer(offerFor(f)));
			expect(
				ownershipProblem(offer, Buffer.from(f.coinScript, 'hex'))
			).to.equal(
				f.kind === 'p2tr'
					? 'invalid taproot ownership probe signature'
					: 'invalid ownership probe signature'
			);
		});

		it(`${f.kind}: the signature cannot authorize a transaction without the poison input`, () => {
			const tx = bitcoin.Transaction.fromHex(f.unsignedTx);
			tx.ins.pop();
			expect(capturedSignatureSigns(f, tx)).to.equal(false);
		});
	}
});

/** Whether the captured signature verifies for input 0 (the coin) of `tx`. */
function capturedSignatureSigns(
	f: IProbeFixture,
	tx: bitcoin.Transaction
): boolean {
	const signature = Buffer.from(f.proof.signature, 'hex');
	const coinScript = Buffer.from(f.coinScript, 'hex');
	if (f.kind === 'p2tr') {
		const digest = tx.hashForWitnessV1(
			0,
			[coinScript, DF_PROBE_POISON_SCRIPT].slice(0, tx.ins.length),
			[Number(f.coinValueSat), 0].slice(0, tx.ins.length),
			bitcoin.Transaction.SIGHASH_DEFAULT
		);
		return ecc.verifySchnorr(digest, coinScript.subarray(2), signature);
	}
	const pubkey = Buffer.from(f.proof.pubkey, 'hex');
	const digest = tx.hashForWitnessV0(
		0,
		bitcoin.payments.p2pkh({ pubkey }).output!,
		Number(f.coinValueSat),
		bitcoin.Transaction.SIGHASH_ALL
	);
	return ecc.verify(digest, pubkey, signature);
}

// Which fields a probe binds is checked on probes signed here: the captured
// ones predate the receipt hash, so they fail even with no field changed.
describe('Direct funding: ownership probe binding', () => {
	for (const kind of ['p2wpkh', 'p2tr'] as const) {
		const signed = (): { offer: IDfOffer; script: Buffer } => {
			const coin = kind === 'p2tr' ? makeBip86Coin() : makeCoin();
			return {
				offer: buildOffer(new FakeDfNode().mintRequest(), coin, {
					probeProof: true
				}),
				script: coin.script
			};
		};

		it(`${kind}: accepts a probe signed for this offer after a wire round trip`, () => {
			const { offer, script } = signed();
			expect(
				ownershipProblem(decodeDfOffer(encodeDfOffer(offer)), script)
			).to.equal(null);
		});

		it(`${kind}: rejects a changed amount with either the stale or recomputed offer ID`, () => {
			const { offer, script } = signed();
			offer.amountSat++;
			expect(offerFieldProblem(offer, {})).to.contain('offer id');
			offer.offerId = deriveOfferId(offer.txid, offer.vout, offer.amountSat);
			expect(offerFieldProblem(offer, {})).to.equal(null);
			expect(ownershipProblem(offer, script)).not.to.equal(null);
		});

		for (const field of [
			'sequence',
			'vout',
			'txid',
			'valueSat',
			'offerId',
			'receiptHash'
		] as const) {
			it(`${kind}: rejects the signature after changing ${field}`, () => {
				const { offer, script } = signed();
				if (field === 'sequence') offer.sequence--;
				if (field === 'vout') offer.vout++;
				if (field === 'txid') offer.txid[0] ^= 1;
				if (field === 'valueSat') offer.valueSat++;
				if (field === 'offerId') offer.offerId[0] ^= 1;
				if (field === 'receiptHash') offer.receiptHash[0] ^= 1;
				expect(ownershipProblem(offer, script)).not.to.equal(null);
			});
		}
	}
});
