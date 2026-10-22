/**
 * Issue #1689: an on-chain Result error carries a stable code and the error it
 * wraps, and keeps its message. Fully offline.
 */

import { expect } from 'chai';

import {
	CodedError,
	err,
	EWalletErrorCode,
	WatchOnlySigningError
} from '../src';

const errorOf = (res: ReturnType<typeof err>): CodedError => {
	if (!res.isErr()) throw new Error('expected an Err');
	return res.error;
};

describe('Result error codes', function () {
	it('carries UNSPECIFIED for a bare message', () => {
		const error = errorOf(err('no utxos'));
		expect(error).to.be.instanceOf(CodedError);
		expect(error.code).to.equal(EWalletErrorCode.UNSPECIFIED);
		expect(error.message).to.equal('no utxos');
		expect(error.cause).to.equal(undefined);
	});

	it('carries the code and cause it is given', () => {
		const cause = new Error('upstream');
		const error = errorOf(
			err(EWalletErrorCode.FEE_EXCEEDS_HALF_INPUTS, 'too high', cause)
		);
		expect(error.code).to.equal(EWalletErrorCode.FEE_EXCEEDS_HALF_INPUTS);
		expect(error.message).to.equal('too high');
		expect(error.cause).to.equal(cause);
	});

	it('passes a coded error through untouched', () => {
		const original = new WatchOnlySigningError();
		const error = errorOf(err(original));
		expect(error).to.equal(original);
		expect(error.code).to.equal('WATCH_ONLY_CANNOT_SIGN');
	});

	it('wraps an uncoded error, keeping its message and the error as the cause', () => {
		const original = new TypeError('bad input');
		const error = errorOf(err(original));
		expect(error.code).to.equal(EWalletErrorCode.UNSPECIFIED);
		expect(error.message).to.equal('bad input');
		expect(error.cause).to.equal(original);
	});

	it("keeps a foreign error's own string code", () => {
		const original = Object.assign(new Error('connect ECONNREFUSED'), {
			code: 'ECONNREFUSED'
		});
		const error = errorOf(err(original));
		expect(error.code).to.equal('ECONNREFUSED');
		expect(error.cause).to.equal(original);
	});

	it('keeps the message of a thrown plain object', () => {
		// Electrum rejects with JSON-RPC error objects, whose code is a number.
		const thrown = { code: -32600, message: 'invalid request' };
		const error = errorOf(err(thrown as unknown as Error));
		expect(error.code).to.equal(EWalletErrorCode.UNSPECIFIED);
		expect(error.message).to.equal('invalid request');
		expect(error.cause).to.equal(thrown);
	});
});
