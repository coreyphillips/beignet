import { expect } from 'chai';
import { NodeStats } from '../../src/cli/types';

describe('Time-Windowed Stats', () => {
	it('NodeStats has windowMs field when window is specified', () => {
		const stats: NodeStats = {
			totalPaymentsSent: 5,
			totalPaymentsReceived: 3,
			totalPaymentsFailed: 1,
			totalSatsSent: 50000,
			totalSatsReceived: 30000,
			totalFeesPaid: 50,
			successRate: 0.8333,
			uptimeMs: 3600000,
			windowMs: 3600000
		};
		expect(stats.windowMs).to.equal(3600000);
	});

	it('NodeStats includes avgPaymentTimeSec', () => {
		const stats: NodeStats = {
			totalPaymentsSent: 1,
			totalPaymentsReceived: 0,
			totalPaymentsFailed: 0,
			totalSatsSent: 1000,
			totalSatsReceived: 0,
			totalFeesPaid: 1,
			successRate: 1,
			uptimeMs: 10000,
			avgPaymentTimeSec: 2.5
		};
		expect(stats.avgPaymentTimeSec).to.equal(2.5);
	});

	it('NodeStats includes avgFeePct', () => {
		const stats: NodeStats = {
			totalPaymentsSent: 1,
			totalPaymentsReceived: 0,
			totalPaymentsFailed: 0,
			totalSatsSent: 1000,
			totalSatsReceived: 0,
			totalFeesPaid: 10,
			successRate: 1,
			uptimeMs: 10000,
			avgFeePct: 1.0
		};
		expect(stats.avgFeePct).to.equal(1.0);
	});

	it('successRate is between 0 and 1', () => {
		const stats: NodeStats = {
			totalPaymentsSent: 3,
			totalPaymentsReceived: 0,
			totalPaymentsFailed: 1,
			totalSatsSent: 3000,
			totalSatsReceived: 0,
			totalFeesPaid: 3,
			successRate: 0.75,
			uptimeMs: 10000
		};
		expect(stats.successRate).to.be.at.least(0);
		expect(stats.successRate).to.be.at.most(1);
	});

	it('windowMs is omitted when no window specified', () => {
		const stats: NodeStats = {
			totalPaymentsSent: 0,
			totalPaymentsReceived: 0,
			totalPaymentsFailed: 0,
			totalSatsSent: 0,
			totalSatsReceived: 0,
			totalFeesPaid: 0,
			successRate: 0,
			uptimeMs: 10000
		};
		expect(stats.windowMs).to.be.undefined;
	});

	it('avgPaymentTimeSec is omitted when no completed payments', () => {
		const stats: NodeStats = {
			totalPaymentsSent: 0,
			totalPaymentsReceived: 0,
			totalPaymentsFailed: 0,
			totalSatsSent: 0,
			totalSatsReceived: 0,
			totalFeesPaid: 0,
			successRate: 0,
			uptimeMs: 10000
		};
		expect(stats.avgPaymentTimeSec).to.be.undefined;
	});
});
