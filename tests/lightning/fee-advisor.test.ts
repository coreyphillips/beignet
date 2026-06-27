import { expect } from 'chai';
import { FeeAdvisor } from '../../src/lightning/advisor/fee-advisor';

describe('FeeAdvisor', () => {
	let advisor: FeeAdvisor;

	beforeEach(() => {
		advisor = new FeeAdvisor();
	});

	it('recordSample() adds samples to the buffer', () => {
		expect(advisor.sampleCount).to.equal(0);
		advisor.recordSample(5);
		expect(advisor.sampleCount).to.equal(1);
		advisor.recordSample(10);
		expect(advisor.sampleCount).to.equal(2);
		// Non-positive samples are ignored
		advisor.recordSample(0);
		advisor.recordSample(-1);
		expect(advisor.sampleCount).to.equal(2);
	});

	it('getSnapshot() returns null when no samples', () => {
		expect(advisor.getSnapshot()).to.be.null;
	});

	it('getSnapshot() returns correct current rate', () => {
		advisor.recordSample(5);
		advisor.recordSample(10);
		advisor.recordSample(15);
		const snapshot = advisor.getSnapshot()!;
		expect(snapshot).to.not.be.null;
		expect(snapshot.currentSatPerVbyte).to.equal(15);
	});

	it('getSnapshot() calculates min/max/avg correctly', () => {
		advisor.recordSample(2);
		advisor.recordSample(4);
		advisor.recordSample(6);
		advisor.recordSample(8);
		advisor.recordSample(10);
		const snapshot = advisor.getSnapshot()!;
		expect(snapshot.minSatPerVbyte).to.equal(2);
		expect(snapshot.maxSatPerVbyte).to.equal(10);
		expect(snapshot.avgSatPerVbyte).to.equal(6);
	});

	it('getSnapshot() calculates percentile correctly', () => {
		// 10 samples: 1, 2, 3, 4, 5, 6, 7, 8, 9, 10
		for (let i = 1; i <= 10; i++) {
			advisor.recordSample(i);
		}
		// Current is 10 (highest), so 10/10 = 100%
		const snapshot = advisor.getSnapshot()!;
		expect(snapshot.percentile).to.equal(100);

		// Add a sample of 1 -- now current is 1 (lowest among 11 samples)
		const advisor2 = new FeeAdvisor();
		for (let i = 1; i <= 10; i++) {
			advisor2.recordSample(i);
		}
		advisor2.recordSample(1);
		const snapshot2 = advisor2.getSnapshot()!;
		// Current is 1, and 2 of 11 are <= 1
		expect(snapshot2.currentSatPerVbyte).to.equal(1);
		expect(snapshot2.percentile).to.equal(Math.round((2 / 11) * 100)); // 18
	});

	it('circular buffer wraps at 144 samples', () => {
		// Fill to capacity
		for (let i = 1; i <= 144; i++) {
			advisor.recordSample(i);
		}
		expect(advisor.sampleCount).to.equal(144);

		// getCurrentRate should be 144
		expect(advisor.getCurrentRate()).to.equal(144);

		// Add one more -- should overwrite the oldest
		advisor.recordSample(999);
		expect(advisor.sampleCount).to.equal(144); // Still 144
		expect(advisor.getCurrentRate()).to.equal(999);

		const snapshot = advisor.getSnapshot()!;
		// Min should now be 2 (since 1 was overwritten by 999)
		expect(snapshot.minSatPerVbyte).to.equal(2);
		expect(snapshot.maxSatPerVbyte).to.equal(999);
	});

	it('computeTrend returns RISING when recent fees are higher', () => {
		// 6 older samples at 10, then 6 recent samples at 20
		for (let i = 0; i < 6; i++) {
			advisor.recordSample(10);
		}
		for (let i = 0; i < 6; i++) {
			advisor.recordSample(20);
		}
		const snapshot = advisor.getSnapshot()!;
		expect(snapshot.trend).to.equal('RISING');
	});

	it('computeTrend returns FALLING when recent fees are lower', () => {
		// 6 older samples at 20, then 6 recent samples at 10
		for (let i = 0; i < 6; i++) {
			advisor.recordSample(20);
		}
		for (let i = 0; i < 6; i++) {
			advisor.recordSample(10);
		}
		const snapshot = advisor.getSnapshot()!;
		expect(snapshot.trend).to.equal('FALLING');
	});

	it('computeTrend returns STABLE when fees are consistent', () => {
		// 12 samples all at 10
		for (let i = 0; i < 12; i++) {
			advisor.recordSample(10);
		}
		const snapshot = advisor.getSnapshot()!;
		expect(snapshot.trend).to.equal('STABLE');
	});

	it('recommendation returns OPEN_NOW for low percentile and WAIT for high', () => {
		// Build a distribution: 1-100
		for (let i = 1; i <= 100; i++) {
			advisor.recordSample(i);
		}
		// Add stable low fee as current
		advisor.recordSample(5);
		const lowSnapshot = advisor.getSnapshot()!;
		// 5 is at the 5th percentile -- should be OPEN_NOW (percentile <= 20 even if RISING)
		expect(lowSnapshot.recommendation).to.equal('OPEN_NOW');

		// New advisor with high fees
		const advisor2 = new FeeAdvisor();
		for (let i = 1; i <= 100; i++) {
			advisor2.recordSample(i);
		}
		advisor2.recordSample(95);
		const highSnapshot = advisor2.getSnapshot()!;
		// 95 is at ~95th percentile -- should be WAIT
		expect(highSnapshot.recommendation).to.equal('WAIT');

		// New advisor with mid-range fees
		const advisor3 = new FeeAdvisor();
		for (let i = 1; i <= 100; i++) {
			advisor3.recordSample(i);
		}
		advisor3.recordSample(50);
		const midSnapshot = advisor3.getSnapshot()!;
		// 50 is at ~50th percentile -- should be NEUTRAL
		expect(midSnapshot.recommendation).to.equal('NEUTRAL');
	});

	it('estimatedOpenChannelCostSats uses 154 vbytes', () => {
		advisor.recordSample(10);
		const snapshot = advisor.getSnapshot()!;
		// 10 sat/vB * 154 vB = 1540
		expect(snapshot.estimatedOpenChannelCostSats).to.equal(1540);
	});
});
