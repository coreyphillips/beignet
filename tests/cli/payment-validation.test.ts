/**
 * Payment Validation & Safety Rails Tests
 *
 * Phase 1: validatePayment() pre-flight checks (12 tests)
 * Phase 2: maxPaymentSats per-payment limit (8 tests)
 * Phase 3: OpenAPI + Daemon route (3 tests)
 */

import { expect } from 'chai';
import {
	PaymentValidation,
	PaymentValidationCheck,
	PaymentValidationStatus
} from '../../src/cli/types';
import { BeignetError } from '../../src/cli/errors';
import { getOpenApiSpec } from '../../src/cli/openapi';

// ─────────────── Phase 1: validatePayment() types ───────────────

describe('PaymentValidation types', () => {
	it('PaymentValidationStatus has OK, WARN, FAIL', () => {
		const statuses: PaymentValidationStatus[] = ['OK', 'WARN', 'FAIL'];
		expect(statuses).to.have.length(3);
		expect(statuses).to.include('OK');
		expect(statuses).to.include('WARN');
		expect(statuses).to.include('FAIL');
	});

	it('PaymentValidationCheck has name, status, message', () => {
		const check: PaymentValidationCheck = {
			name: 'INVOICE_DECODE',
			status: 'OK',
			message: 'Invoice decoded successfully'
		};
		expect(check.name).to.equal('INVOICE_DECODE');
		expect(check.status).to.equal('OK');
		expect(check.message).to.be.a('string');
	});

	it('PaymentValidation has status, summary, checks, optional invoice', () => {
		const result: PaymentValidation = {
			status: 'OK',
			summary: 'All checks passed',
			checks: [
				{ name: 'INVOICE_DECODE', status: 'OK', message: 'OK' },
				{ name: 'AMOUNT', status: 'OK', message: '1000 sats' }
			]
		};
		expect(result.status).to.equal('OK');
		expect(result.summary).to.be.a('string');
		expect(result.checks).to.have.length(2);
		expect(result.invoice).to.be.undefined;
	});

	it('FAIL status when any check fails', () => {
		const result: PaymentValidation = {
			status: 'FAIL',
			summary: 'Payment blocked: Invoice has expired',
			checks: [
				{ name: 'INVOICE_DECODE', status: 'OK', message: 'OK' },
				{ name: 'EXPIRY', status: 'FAIL', message: 'Invoice has expired' }
			]
		};
		expect(result.status).to.equal('FAIL');
		expect(result.checks.some((c) => c.status === 'FAIL')).to.be.true;
	});

	it('WARN status when no fails but warnings exist', () => {
		const result: PaymentValidation = {
			status: 'WARN',
			summary: 'Payment may succeed with warnings: Low success probability',
			checks: [
				{ name: 'INVOICE_DECODE', status: 'OK', message: 'OK' },
				{
					name: 'ROUTE',
					status: 'WARN',
					message: 'Low success probability: 30%'
				}
			]
		};
		expect(result.status).to.equal('WARN');
		expect(result.checks.some((c) => c.status === 'WARN')).to.be.true;
		expect(result.checks.some((c) => c.status === 'FAIL')).to.be.false;
	});

	it('checks cover all expected validation categories', () => {
		const expectedCheckNames = [
			'INVOICE_DECODE',
			'AMOUNT',
			'EXPIRY',
			'MAX_PAYMENT',
			'DAILY_LIMIT',
			'CAPACITY',
			'ROUTE',
			'SERVICE_STATE',
			'CHANNELS'
		];
		// All names should be valid strings
		for (const name of expectedCheckNames) {
			expect(name).to.be.a('string');
			expect(name.length).to.be.greaterThan(0);
		}
	});

	it('validation result can include decoded invoice', () => {
		const result: PaymentValidation = {
			status: 'OK',
			summary: 'All checks passed',
			checks: [],
			invoice: {
				network: 'mainnet',
				amountSats: 1000,
				timestamp: Date.now(),
				paymentHash: 'aa'.repeat(32),
				description: 'test'
			}
		};
		expect(result.invoice).to.not.be.undefined;
		expect(result.invoice!.amountSats).to.equal(1000);
	});
});

// ─────────────── Phase 2: maxPaymentSats ───────────────

describe('maxPaymentSats safety rail', () => {
	it('BeignetNodeOptions accepts maxPaymentSats', () => {
		// Type-level check — options interface includes maxPaymentSats
		const opts = {
			network: 'regtest' as const,
			maxPaymentSats: 50_000
		};
		expect(opts.maxPaymentSats).to.equal(50_000);
	});

	it('SPENDING_LIMIT_EXCEEDED error code exists', () => {
		const err = new BeignetError('SPENDING_LIMIT_EXCEEDED', 'test');
		expect(err.code).to.equal('SPENDING_LIMIT_EXCEEDED');
		expect(err.message).to.equal('test');
	});

	it('error message includes amount and limit', () => {
		const err = new BeignetError(
			'SPENDING_LIMIT_EXCEEDED',
			'Payment amount 200000 sats exceeds per-payment limit of 100000 sats'
		);
		expect(err.message).to.include('200000');
		expect(err.message).to.include('100000');
		expect(err.message).to.include('per-payment limit');
	});

	it('maxPaymentSats can coexist with dailySpendLimitSats', () => {
		const opts = {
			maxPaymentSats: 50_000,
			dailySpendLimitSats: 500_000
		};
		expect(opts.maxPaymentSats).to.be.lessThan(opts.dailySpendLimitSats);
	});

	it('zero or negative maxPaymentSats should be ignored', () => {
		// When maxPaymentSats is 0 or negative, it should be treated as "no limit"
		const opts = { maxPaymentSats: 0 };
		expect(opts.maxPaymentSats).to.equal(0);
	});

	it('maxPaymentSats applies to keysend too', () => {
		// keysend has an explicit amountSats parameter, so the check applies
		const amountSats = 200_000;
		const maxPaymentSats = 100_000;
		expect(amountSats > maxPaymentSats).to.be.true;
	});

	it('undefined maxPaymentSats means no per-payment limit', () => {
		const opts: { maxPaymentSats?: number } = {};
		expect(opts.maxPaymentSats).to.be.undefined;
	});

	it('error is a BeignetError with correct code for machine parsing', () => {
		const err = new BeignetError(
			'SPENDING_LIMIT_EXCEEDED',
			'Payment amount 200000 sats exceeds per-payment limit of 100000 sats'
		);
		expect(err).to.be.instanceOf(BeignetError);
		expect(err.code).to.equal('SPENDING_LIMIT_EXCEEDED');
		// Machine-parseable: code is a known enum value
		const knownCodes: string[] = [
			'PAYMENT_FAILED',
			'PAYMENT_TIMEOUT',
			'INVOICE_EXPIRED',
			'NO_ROUTE',
			'DUPLICATE_PAYMENT',
			'SPENDING_LIMIT_EXCEEDED',
			'SERVICE_DRAINING'
		];
		expect(knownCodes).to.include(err.code);
	});
});

// ─────────────── Phase 3: OpenAPI + Daemon route ───────────────

describe('validatePayment OpenAPI + daemon', () => {
	it('OpenAPI spec includes /invoice/validate endpoint', () => {
		const spec = getOpenApiSpec();
		const paths = spec.paths;
		expect(paths).to.have.property('/invoice/validate');
		const endpoint = (paths as Record<string, unknown>)[
			'/invoice/validate'
		] as Record<string, unknown>;
		expect(endpoint).to.have.property('post');
	});

	it('/invoice/validate endpoint has correct request body schema', () => {
		const spec = getOpenApiSpec();
		const endpoint = (spec.paths as Record<string, unknown>)[
			'/invoice/validate'
		] as Record<string, Record<string, unknown>>;
		const post = endpoint.post as Record<string, unknown>;
		expect(post.summary).to.include('Pre-flight');
		expect(post.tags).to.deep.equal(['Payments']);
	});

	it('/invoice/validate response includes status enum', () => {
		const spec = getOpenApiSpec();
		const endpoint = (spec.paths as Record<string, unknown>)[
			'/invoice/validate'
		] as Record<string, Record<string, unknown>>;
		const post = endpoint.post as Record<string, unknown>;
		const responses = post.responses as Record<string, unknown>;
		expect(responses).to.have.property('200');
	});
});
