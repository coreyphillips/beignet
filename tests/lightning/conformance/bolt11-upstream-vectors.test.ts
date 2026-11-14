/**
 * BOLT 11: upstream `bolt11/invoice-test.json`, vendored verbatim.
 *
 * Every vector must get the upstream verdict through the checks the payer
 * runs: decode(), then assertPayableInvoice(). Each invalid vector names the
 * layer that refuses it, so a rule that goes missing or moves fails here.
 */

import { expect } from 'chai';
import { bech32 } from 'bech32';
import { decode } from '../../../src/lightning/invoice/decode';
import { verifyInvoiceSignature } from '../../../src/lightning/invoice/signing';
import {
	BECH32_MAX_LIMIT,
	SIGNATURE_WORDS,
	TIMESTAMP_WORDS,
	TagType
} from '../../../src/lightning/invoice/types';
import { decodeTaggedField } from '../../../src/lightning/invoice/words';
import { assertPayableInvoice } from '../../../src/lightning/node/invoice-payability';
import {
	LightningErrorCode,
	LightningPaymentError
} from '../../../src/lightning/node/types';
import { loadVectors } from './helpers';

interface IUpstreamVector {
	description: string;
	valid: boolean;
	invoice: string;
}

interface IRefusal {
	layer: 'decode' | 'payer';
	error: string;
}

const vectors = loadVectors<IUpstreamVector[]>('bolt11/invoice-test.json');

const HIGH_S_WITH_N = "Non canonical signature (high-S) with 'n' field defined";

/** Where each invalid vector is refused, keyed by its upstream description. */
const REFUSED_BY: Record<string, IRefusal> = {
	'Same, but adding invalid unknown feature 100': {
		layer: 'payer',
		error: 'unknown feature bit 100'
	},
	'Same, but with an `n` field of invalid length': {
		layer: 'decode',
		error: 'field n has data_length 52, expected 53'
	},
	'Missing required `p` field': {
		layer: 'decode',
		error: 'missing required payment_hash'
	},
	'Two distinct p fields in an otherwise valid invoice': {
		layer: 'decode',
		error: 'more than one p field'
	},
	'The same p field twice in an otherwise valid invoice': {
		layer: 'decode',
		error: 'more than one p field'
	},
	'Two distinct s fields in an otherwise valid invoice': {
		layer: 'decode',
		error: 'more than one s field'
	},
	'Bech32 checksum is invalid': { layer: 'decode', error: 'Invalid checksum' },
	'Malformed bech32 string (no 1)': {
		layer: 'decode',
		error: 'No separator character'
	},
	'Malformed bech32 string (mixed case)': {
		layer: 'decode',
		error: 'Mixed-case string'
	},
	'Signature is not recoverable': {
		layer: 'decode',
		error: 'signature is not recoverable'
	},
	'String is too short': { layer: 'decode', error: 'Invoice too short' },
	'Invalid multiplier': { layer: 'decode', error: 'Invalid amount' },
	'Invalid sub-millisatoshi precision': {
		layer: 'decode',
		error: 'sub-millisatoshi'
	},
	// decode() stays a parser here: a secretless invoice can still be shown.
	'Missing required `s` field': {
		layer: 'payer',
		error: 'no payment secret'
	},
	// Upstream also gave this vector a second `s` field, which decode() meets
	// before the signature. Its high-S defect is checked on its own below.
	[HIGH_S_WITH_N]: { layer: 'decode', error: 'more than one s field' }
};

/** The payer's verdict on an invoice string: undefined when it would pay. */
function payerRefusal(invoice: string): IRefusal | undefined {
	let decoded;
	try {
		decoded = decode(invoice);
	} catch (e) {
		return { layer: 'decode', error: (e as Error).message };
	}
	try {
		assertPayableInvoice(decoded);
	} catch (e) {
		expect(e).to.be.instanceOf(LightningPaymentError);
		expect((e as LightningPaymentError).code).to.equal(
			LightningErrorCode.INVALID_INVOICE
		);
		return { layer: 'payer', error: (e as Error).message };
	}
	return undefined;
}

describe('BOLT 11: upstream invoice-test.json vectors', function () {
	for (const vector of vectors) {
		const verdict = vector.valid ? 'accepts' : 'refuses';
		it(`${verdict}: ${vector.description}`, function () {
			const refusal = payerRefusal(vector.invoice);
			if (vector.valid) {
				expect(refusal).to.equal(undefined);
				return;
			}
			const expected = REFUSED_BY[vector.description];
			expect(expected, 'no REFUSED_BY entry for this vector').to.not.equal(
				undefined
			);
			expect(refusal, 'the payer accepted it').to.not.equal(undefined);
			expect(refusal!.layer).to.equal(expected.layer);
			expect(refusal!.error).to.include(expected.error);
		});
	}

	it('lists a refusal for exactly the invalid vectors in the file', function () {
		const invalid = vectors.filter((v) => !v.valid).map((v) => v.description);
		expect(Object.keys(REFUSED_BY)).to.have.members(invalid);
	});

	it('refuses the high-S vector on S alone: the low-S copy verifies against n', function () {
		const vector = vectors.find((v) => v.description === HIGH_S_WITH_N);
		const { prefix, words } = bech32.decode(vector!.invoice, BECH32_MAX_LIMIT);
		const sigStart = words.length - SIGNATURE_WORDS;
		const dataWords = words.slice(0, sigStart);
		const signature = Buffer.from(bech32.fromWords(words.slice(sigStart)));

		let payee: Buffer | undefined;
		const tagged = dataWords.slice(TIMESTAMP_WORDS);
		for (let offset = 0; offset < tagged.length; ) {
			const field = decodeTaggedField(tagged, offset);
			if (field.type === TagType.PAYEE_PUBKEY) {
				payee = Buffer.from(bech32.fromWords(field.dataWords));
			}
			offset = field.nextOffset;
		}
		expect(payee, 'n field').to.not.equal(undefined);

		expect(
			verifyInvoiceSignature(prefix, dataWords, signature, payee!)
		).to.equal(false);
		const lowS = Buffer.from(signature);
		const n = BigInt(
			'0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'
		);
		const s = BigInt('0x' + signature.subarray(32, 64).toString('hex'));
		Buffer.from((n - s).toString(16).padStart(64, '0'), 'hex').copy(lowS, 32);
		expect(verifyInvoiceSignature(prefix, dataWords, lowS, payee!)).to.equal(
			true
		);
	});
});
