/**
 * Typed decode errors: user-supplied BOLT 11 / BOLT 12 strings that fail to
 * parse must surface as BeignetError INVALID_INVOICE / INVALID_OFFER (HTTP
 * 400 with the parser's message), not as unhandled throws the daemon scrubs
 * to a generic 500 "Internal server error" and logs as a server fault.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as secp from '@noble/secp256k1';
import {
	BeignetError,
	BeignetErrorCode,
	isRetryableError
} from '../../src/cli/errors';
import {
	decodeInvoiceInput,
	decodeOfferInput
} from '../../src/cli/beignet-node';
import { statusForErrorCode } from '../../src/cli/daemon';
import {
	encode,
	ensureHmac,
	Network,
	IInvoiceCreationOptions
} from '../../src/lightning/invoice';
import { encodeOffer, IOffer } from '../../src/lightning/offer';

ensureHmac();

/** Generate a random 32-byte private key and its compressed public key. */
function makeKeypair(): { privateKey: Buffer; publicKey: Buffer } {
	let privKey: Buffer;
	do {
		privKey = crypto.randomBytes(32);
	} while (!secp.utils.isValidPrivateKey(privKey));
	return {
		privateKey: privKey,
		publicKey: Buffer.from(secp.getPublicKey(privKey, true))
	};
}

function makeValidBolt11(): { bolt11: string; paymentHash: Buffer } {
	const { privateKey } = makeKeypair();
	const options: IInvoiceCreationOptions = {
		network: Network.MAINNET,
		paymentHash: crypto.randomBytes(32),
		description: 'typed decode test',
		privateKey,
		timestamp: 1700000000
	};
	return { bolt11: encode(options), paymentHash: options.paymentHash };
}

function makeValidOffer(): { encoded: string; description: string } {
	const { publicKey } = makeKeypair();
	const offer: IOffer = {
		offerId: Buffer.alloc(32),
		description: 'typed decode test offer',
		issuerId: publicKey
	};
	return { encoded: encodeOffer(offer), description: offer.description! };
}

/** Assert fn throws a BeignetError with the given code and return it. */
function expectBeignetCode(
	fn: () => unknown,
	code: BeignetErrorCode
): BeignetError {
	try {
		fn();
	} catch (err: unknown) {
		expect(err).to.be.instanceOf(BeignetError);
		const beignetErr = err as BeignetError;
		expect(beignetErr.code).to.equal(code);
		return beignetErr;
	}
	throw new Error('expected function to throw');
}

describe('decodeInvoiceInput', () => {
	it('decodes a valid invoice', () => {
		const { bolt11, paymentHash } = makeValidBolt11();
		const decoded = decodeInvoiceInput(bolt11);
		expect(decoded.paymentHash).to.deep.equal(paymentHash);
	});

	it('rejects garbage with INVALID_INVOICE and keeps the parser message', () => {
		const err = expectBeignetCode(
			() => decodeInvoiceInput('not an invoice'),
			BeignetErrorCode.INVALID_INVOICE
		);
		expect(err.message).to.include('Invalid invoice:');
		// The parser detail must survive; a bare prefix means it was lost.
		expect(err.message.length).to.be.greaterThan('Invalid invoice: '.length);
		expect(err.message).to.not.include('Internal server error');
	});

	it('rejects an offer string passed as an invoice', () => {
		const { encoded } = makeValidOffer();
		expectBeignetCode(
			() => decodeInvoiceInput(encoded),
			BeignetErrorCode.INVALID_INVOICE
		);
	});

	it('is a permanent (non-retryable) failure', () => {
		const err = new BeignetError(BeignetErrorCode.INVALID_INVOICE, 'x');
		expect(isRetryableError(err)).to.equal(false);
	});
});

describe('decodeOfferInput', () => {
	it('round-trips a valid offer', () => {
		const { encoded, description } = makeValidOffer();
		const decoded = decodeOfferInput(encoded);
		expect(decoded.description).to.equal(description);
	});

	it('rejects garbage with INVALID_OFFER and keeps the parser message', () => {
		const err = expectBeignetCode(
			() => decodeOfferInput('not an offer'),
			BeignetErrorCode.INVALID_OFFER
		);
		expect(err.message).to.include('Invalid offer:');
		expect(err.message.length).to.be.greaterThan('Invalid offer: '.length);
		expect(err.message).to.not.include('Internal server error');
	});

	it('rejects a bolt11 invoice passed as an offer', () => {
		const { bolt11 } = makeValidBolt11();
		expectBeignetCode(
			() => decodeOfferInput(bolt11),
			BeignetErrorCode.INVALID_OFFER
		);
	});

	it('is a permanent (non-retryable) failure', () => {
		const err = new BeignetError(BeignetErrorCode.INVALID_OFFER, 'x');
		expect(isRetryableError(err)).to.equal(false);
	});
});

describe('HTTP status mapping for decode failures', () => {
	it('maps INVALID_INVOICE and INVALID_OFFER to 400', () => {
		expect(statusForErrorCode('INVALID_INVOICE')).to.equal(400);
		expect(statusForErrorCode('INVALID_OFFER')).to.equal(400);
	});

	it('keeps unmapped codes as server faults (500)', () => {
		expect(statusForErrorCode('INTERNAL_ERROR')).to.equal(500);
	});
});
