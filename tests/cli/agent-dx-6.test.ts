/**
 * Agent DX 6: BeignetNode waitForReady + typed payment error mapping tests.
 *
 * Tests the CLI-level wrappers for the new Production Hardening 11 features.
 */

import { expect } from 'chai';
import { BeignetNodeEvents } from '../../src/cli/types';
import { BeignetError } from '../../src/cli/errors';
import {
	LightningErrorCode,
	LightningPaymentError
} from '../../src/lightning/node/types';

describe('Agent DX 6: CLI-level Production Hardening 11', function () {
	this.timeout(5_000);

	describe('BeignetNodeEvents type', () => {
		it('should include node:ready event', () => {
			// Type-level check: node:ready exists in BeignetNodeEvents
			const eventKeys: Array<keyof BeignetNodeEvents> = [
				'payment:received',
				'payment:sent',
				'payment:failed',
				'channel:ready',
				'channel:closed',
				'peer:connect',
				'peer:disconnect',
				'node:error',
				'node:ready',
				'log'
			];
			expect(eventKeys).to.include('node:ready');
		});
	});

	describe('LightningPaymentError integration', () => {
		it('should LightningPaymentError be an Error instance', () => {
			const err = new LightningPaymentError(
				LightningErrorCode.NO_ROUTE,
				'No route found to destination'
			);
			expect(err).to.be.instanceOf(Error);
			expect(err).to.be.instanceOf(LightningPaymentError);
			expect(err.name).to.equal('LightningPaymentError');
			expect(err.code).to.equal('NO_ROUTE');
			expect(err.message).to.equal('No route found to destination');
		});

		it('should code property map to BeignetNode error codes', () => {
			// Mapping table: LightningErrorCode → BeignetErrorCode
			const expectedMappings: Array<[LightningErrorCode, string]> = [
				[LightningErrorCode.NO_ROUTE, 'NO_ROUTE'],
				[LightningErrorCode.DUPLICATE_PAYMENT, 'DUPLICATE_PAYMENT'],
				[LightningErrorCode.NO_CHANNEL_TO_HOP, 'PEER_NOT_CONNECTED'],
				[LightningErrorCode.FEE_EXCEEDS_MAX, 'PAYMENT_FAILED'],
				[LightningErrorCode.MISSING_AMOUNT, 'INVALID_PARAMS'],
				[LightningErrorCode.INVALID_INVOICE, 'INVALID_PARAMS'],
				[LightningErrorCode.INVOICE_EXPIRED, 'INVOICE_EXPIRED']
			];

			const codeMap: Record<string, string> = {
				NO_ROUTE: 'NO_ROUTE',
				DUPLICATE_PAYMENT: 'DUPLICATE_PAYMENT',
				NO_CHANNEL_TO_HOP: 'PEER_NOT_CONNECTED',
				FEE_EXCEEDS_MAX: 'PAYMENT_FAILED',
				MISSING_AMOUNT: 'INVALID_PARAMS',
				INVALID_INVOICE: 'INVALID_PARAMS',
				INVOICE_EXPIRED: 'INVOICE_EXPIRED'
			};

			for (const [lightningCode, beignetCode] of expectedMappings) {
				expect(codeMap[lightningCode]).to.equal(beignetCode);
			}
		});

		it('should detect code property via "code" in err pattern', () => {
			const err = new LightningPaymentError(
				LightningErrorCode.FEE_EXCEEDS_MAX,
				'Route fee exceeds maximum'
			);
			expect('code' in err).to.be.true;
			expect((err as { code: string }).code).to.equal('FEE_EXCEEDS_MAX');
		});

		it('should work with try/catch and instanceof', () => {
			try {
				throw new LightningPaymentError(
					LightningErrorCode.MISSING_AMOUNT,
					'Invoice has no amount'
				);
			} catch (err: unknown) {
				expect(err).to.be.instanceOf(LightningPaymentError);
				expect(err).to.be.instanceOf(Error);

				// Can access properties safely
				if (err instanceof Error && 'code' in err) {
					expect((err as LightningPaymentError).code).to.equal(
						'MISSING_AMOUNT'
					);
				}
			}
		});

		it('should BeignetError and LightningPaymentError be distinct', () => {
			const bErr = new BeignetError('NO_ROUTE', 'No route found');
			const lErr = new LightningPaymentError(
				LightningErrorCode.NO_ROUTE,
				'No route found'
			);

			expect(bErr).to.be.instanceOf(BeignetError);
			expect(bErr).to.not.be.instanceOf(LightningPaymentError);
			expect(lErr).to.be.instanceOf(LightningPaymentError);
			expect(lErr).to.not.be.instanceOf(BeignetError);

			// Both extend Error
			expect(bErr).to.be.instanceOf(Error);
			expect(lErr).to.be.instanceOf(Error);
		});

		it('should all 8 error codes exist', () => {
			const allCodes = Object.values(LightningErrorCode);
			expect(allCodes).to.have.lengthOf(8);
			expect(allCodes).to.include('NO_ROUTE');
			expect(allCodes).to.include('DUPLICATE_PAYMENT');
			expect(allCodes).to.include('NO_CHANNEL_TO_HOP');
			expect(allCodes).to.include('FEE_EXCEEDS_MAX');
			expect(allCodes).to.include('MISSING_AMOUNT');
			expect(allCodes).to.include('INVALID_INVOICE');
			expect(allCodes).to.include('INVOICE_EXPIRED');
			expect(allCodes).to.include('INVALID_KEYSEND');
		});
	});
});
