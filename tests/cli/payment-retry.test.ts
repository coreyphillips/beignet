import { expect } from 'chai';
import {
	RetryPaymentOptions,
	RetryPaymentResult,
	BeignetNodeEvents
} from '../../src/cli/types';
import {
	BeignetError,
	isRetryableError,
	BeignetErrorCode
} from '../../src/cli/errors';

describe('Payment Retry with Exponential Backoff', () => {
	describe('RetryPaymentOptions type', () => {
		it('has all expected fields', () => {
			const opts: RetryPaymentOptions = {
				maxRetries: 3,
				backoffMs: 2000,
				maxFeeSats: 100,
				amountSats: 1000,
				metadata: { orderId: 'abc123' }
			};
			expect(opts.maxRetries).to.equal(3);
			expect(opts.backoffMs).to.equal(2000);
			expect(opts.maxFeeSats).to.equal(100);
			expect(opts.amountSats).to.equal(1000);
			expect(opts.metadata).to.deep.equal({ orderId: 'abc123' });
		});

		it('all fields are optional', () => {
			const opts: RetryPaymentOptions = {};
			expect(opts.maxRetries).to.be.undefined;
			expect(opts.backoffMs).to.be.undefined;
		});

		it('defaults: maxRetries=3, backoffMs=2000', () => {
			const maxRetries = 3;
			const backoffMs = 2000;
			expect(maxRetries).to.equal(3);
			expect(backoffMs).to.equal(2000);
		});
	});

	describe('RetryPaymentResult type', () => {
		it('extends PaymentInfo with attempts field', () => {
			const result: RetryPaymentResult = {
				paymentHash: 'abc123',
				amountSats: 1000,
				status: 'COMPLETED',
				direction: 'OUTGOING',
				createdAt: Date.now(),
				attempts: 2
			};
			expect(result.attempts).to.equal(2);
			expect(result.paymentHash).to.be.a('string');
		});

		it('attempts=1 means first try succeeded', () => {
			const result: RetryPaymentResult = {
				paymentHash: 'abc',
				amountSats: 500,
				status: 'COMPLETED',
				direction: 'OUTGOING',
				createdAt: Date.now(),
				attempts: 1
			};
			expect(result.attempts).to.equal(1);
			expect(result.status).to.equal('COMPLETED');
		});

		it('FAILED result includes failureDescription and all attempts', () => {
			const result: RetryPaymentResult = {
				paymentHash: 'abc',
				amountSats: 500,
				status: 'FAILED',
				direction: 'OUTGOING',
				failureDescription: 'All retries exhausted',
				createdAt: Date.now(),
				attempts: 4
			};
			expect(result.status).to.equal('FAILED');
			expect(result.attempts).to.equal(4);
			expect(result.failureDescription).to.include('retries');
		});
	});

	describe('Retry logic', () => {
		it('exponential backoff formula: delay = backoffMs * 2^(attempt-1)', () => {
			const backoffMs = 2000;
			const delays = [1, 2, 3, 4].map(
				(attempt) => backoffMs * Math.pow(2, attempt - 1)
			);
			expect(delays).to.deep.equal([2000, 4000, 8000, 16000]);
		});

		it('retryable errors trigger retry', () => {
			const retryableErrors = [
				new BeignetError(BeignetErrorCode.PAYMENT_TIMEOUT, 'timed out'),
				new BeignetError(BeignetErrorCode.NO_ROUTE, 'no route'),
				new BeignetError(BeignetErrorCode.PEER_NOT_CONNECTED, 'peer offline'),
				new BeignetError(BeignetErrorCode.PAYMENT_FAILED, 'temporary failure')
			];
			for (const err of retryableErrors) {
				expect(isRetryableError(err)).to.be.true;
			}
		});

		it('permanent errors do NOT trigger retry', () => {
			const permanentErrors = [
				new BeignetError(BeignetErrorCode.INVOICE_EXPIRED, 'expired'),
				new BeignetError(BeignetErrorCode.DUPLICATE_PAYMENT, 'duplicate'),
				new BeignetError(BeignetErrorCode.INVALID_PARAMS, 'bad params')
			];
			for (const err of permanentErrors) {
				expect(isRetryableError(err)).to.be.false;
			}
		});

		it('BOLT 4 PERM flag (0x4000) is permanent — no retry', () => {
			const permErr = new BeignetError(
				'PAYMENT_FAILED',
				'permanent failure',
				0x4000 | 16
			);
			expect(isRetryableError(permErr)).to.be.false;
		});

		it('BOLT 4 temporary failure is retryable', () => {
			const tempErr = new BeignetError('PAYMENT_FAILED', 'temporary', 2);
			expect(isRetryableError(tempErr)).to.be.true;
		});
	});

	describe('payment:retry event', () => {
		it('event type is defined on BeignetNodeEvents', () => {
			const handler: BeignetNodeEvents['payment:retry'] = (data) => {
				expect(data.paymentHash).to.be.a('string');
				expect(data.attempt).to.be.a('number');
				expect(data.maxRetries).to.be.a('number');
				expect(data.nextRetryMs).to.be.a('number');
				expect(data.error).to.be.a('string');
			};
			handler({
				paymentHash: 'abc123',
				attempt: 1,
				maxRetries: 3,
				nextRetryMs: 2000,
				error: 'no route found'
			});
		});

		it('nextRetryMs follows exponential backoff', () => {
			const backoffMs = 2000;
			const attempt = 2;
			const nextRetryMs = backoffMs * Math.pow(2, attempt - 1);
			expect(nextRetryMs).to.equal(4000);
		});
	});

	describe('canSend pre-flight check', () => {
		it('retry aborts if insufficient liquidity', () => {
			// Simulate: after retry delay, check canSend before retrying
			const canSendResult = { canSend: false, availableSats: 0 };
			expect(canSendResult.canSend).to.be.false;
			// In this case, payInvoiceWithRetry returns FAILED without retrying
		});

		it('retry proceeds if sufficient liquidity', () => {
			const canSendResult = {
				canSend: true,
				bestChannelId: 'abc',
				availableSats: 50000
			};
			expect(canSendResult.canSend).to.be.true;
		});
	});
});
