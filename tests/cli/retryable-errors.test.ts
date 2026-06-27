/**
 * isRetryableError Tests
 *
 * Tests the isRetryableError() helper that AI agents use to decide
 * whether to retry a failed payment or surface the error.
 */

import { expect } from 'chai';
import {
	BeignetError,
	BeignetErrorCode,
	isRetryableError
} from '../../src/cli/errors';

describe('isRetryableError', () => {
	// ─────────────── Retryable Cases ───────────────

	it('PAYMENT_TIMEOUT is retryable', () => {
		const err = new BeignetError(BeignetErrorCode.PAYMENT_TIMEOUT, 'timed out');
		expect(isRetryableError(err)).to.be.true;
	});

	it('PEER_NOT_CONNECTED is retryable', () => {
		const err = new BeignetError(
			BeignetErrorCode.PEER_NOT_CONNECTED,
			'not connected'
		);
		expect(isRetryableError(err)).to.be.true;
	});

	it('NO_ROUTE is retryable', () => {
		const err = new BeignetError(BeignetErrorCode.NO_ROUTE, 'no route found');
		expect(isRetryableError(err)).to.be.true;
	});

	it('PAYMENT_FAILED without failureCode is retryable', () => {
		const err = new BeignetError(
			BeignetErrorCode.PAYMENT_FAILED,
			'payment failed'
		);
		expect(isRetryableError(err)).to.be.true;
	});

	it('PAYMENT_FAILED with temporary failureCode (0x1002 = temporary_node_failure) is retryable', () => {
		const err = new BeignetError(
			BeignetErrorCode.PAYMENT_FAILED,
			'temporary failure',
			0x2002
		);
		expect(isRetryableError(err)).to.be.true;
	});

	it('PAYMENT_FAILED with MPP_TIMEOUT (24) is retryable', () => {
		const err = new BeignetError(
			BeignetErrorCode.PAYMENT_FAILED,
			'mpp timeout',
			24
		);
		expect(isRetryableError(err)).to.be.true;
	});

	// ─────────────── Non-Retryable Cases ───────────────

	it('INVALID_PARAMS is not retryable', () => {
		const err = new BeignetError(BeignetErrorCode.INVALID_PARAMS, 'bad params');
		expect(isRetryableError(err)).to.be.false;
	});

	it('NODE_DESTROYED is not retryable', () => {
		const err = new BeignetError(BeignetErrorCode.NODE_DESTROYED, 'destroyed');
		expect(isRetryableError(err)).to.be.false;
	});

	it('INVOICE_EXPIRED is not retryable', () => {
		const err = new BeignetError(BeignetErrorCode.INVOICE_EXPIRED, 'expired');
		expect(isRetryableError(err)).to.be.false;
	});

	it('DUPLICATE_PAYMENT is not retryable', () => {
		const err = new BeignetError(
			BeignetErrorCode.DUPLICATE_PAYMENT,
			'duplicate'
		);
		expect(isRetryableError(err)).to.be.false;
	});

	it('UNAUTHORIZED is not retryable', () => {
		const err = new BeignetError(BeignetErrorCode.UNAUTHORIZED, 'unauthorized');
		expect(isRetryableError(err)).to.be.false;
	});

	it('BODY_TOO_LARGE is not retryable', () => {
		const err = new BeignetError(BeignetErrorCode.BODY_TOO_LARGE, 'too large');
		expect(isRetryableError(err)).to.be.false;
	});

	it('PAYMENT_FAILED with PERM flag (0x4000 | 16 = incorrect_or_unknown_payment_details) is not retryable', () => {
		const err = new BeignetError(
			BeignetErrorCode.PAYMENT_FAILED,
			'perm failure',
			0x4000 | 16
		);
		expect(isRetryableError(err)).to.be.false;
	});

	it('PAYMENT_FAILED with PERM flag (0x4000 | 9 = permanent_channel_failure) is not retryable', () => {
		const err = new BeignetError(
			BeignetErrorCode.PAYMENT_FAILED,
			'perm channel failure',
			0x4000 | 9
		);
		expect(isRetryableError(err)).to.be.false;
	});

	it('PAYMENT_FAILED with PERM flag (0x4000 | 3 = permanent_node_failure) is not retryable', () => {
		const err = new BeignetError(
			BeignetErrorCode.PAYMENT_FAILED,
			'perm node failure',
			0x4000 | 3
		);
		expect(isRetryableError(err)).to.be.false;
	});

	// ─────────────── Edge Cases ───────────────

	it('unknown error code is not retryable', () => {
		const err = new BeignetError('UNKNOWN_CODE', 'something weird');
		expect(isRetryableError(err)).to.be.false;
	});
});

describe('BeignetError — failureCode', () => {
	it('constructor stores failureCode', () => {
		const err = new BeignetError('PAYMENT_FAILED', 'test', 0x400f);
		expect(err.failureCode).to.equal(0x400f);
	});

	it('constructor defaults failureCode to undefined', () => {
		const err = new BeignetError('PAYMENT_FAILED', 'test');
		expect(err.failureCode).to.be.undefined;
	});

	it('toJSON includes failureCode when present', () => {
		const err = new BeignetError('PAYMENT_FAILED', 'test', 42);
		const json = err.toJSON();
		expect(json.failureCode).to.equal(42);
	});

	it('toJSON omits failureCode when absent', () => {
		const err = new BeignetError('PAYMENT_FAILED', 'test');
		const json = err.toJSON();
		expect(json).to.not.have.property('failureCode');
	});
});
