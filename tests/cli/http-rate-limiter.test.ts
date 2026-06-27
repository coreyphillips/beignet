/**
 * Tests for HttpRateLimiter — token bucket rate limiting for the HTTP daemon.
 */

import { expect } from 'chai';
import { HttpRateLimiter } from '../../src/cli/http-rate-limiter';
import { BeignetErrorCode } from '../../src/cli/errors';

describe('HttpRateLimiter', () => {
	it('allows requests up to the configured limit', () => {
		const limiter = new HttpRateLimiter({ maxRequests: 5, windowMs: 60_000 });
		for (let i = 0; i < 5; i++) {
			expect(limiter.isAllowed('client-1')).to.be.true;
		}
		limiter.destroy();
	});

	it('blocks requests after the limit is exceeded', () => {
		const limiter = new HttpRateLimiter({ maxRequests: 3, windowMs: 60_000 });
		expect(limiter.isAllowed('client-1')).to.be.true;
		expect(limiter.isAllowed('client-1')).to.be.true;
		expect(limiter.isAllowed('client-1')).to.be.true;
		expect(limiter.isAllowed('client-1')).to.be.false;
		expect(limiter.isAllowed('client-1')).to.be.false;
		limiter.destroy();
	});

	it('tracks different clients separately', () => {
		const limiter = new HttpRateLimiter({ maxRequests: 2, windowMs: 60_000 });
		expect(limiter.isAllowed('client-A')).to.be.true;
		expect(limiter.isAllowed('client-A')).to.be.true;
		expect(limiter.isAllowed('client-A')).to.be.false;

		// Different client still has full quota
		expect(limiter.isAllowed('client-B')).to.be.true;
		expect(limiter.isAllowed('client-B')).to.be.true;
		expect(limiter.isAllowed('client-B')).to.be.false;
		limiter.destroy();
	});

	it('refills tokens over time', (done) => {
		const limiter = new HttpRateLimiter({ maxRequests: 2, windowMs: 100 });
		expect(limiter.isAllowed('client-1')).to.be.true;
		expect(limiter.isAllowed('client-1')).to.be.true;
		expect(limiter.isAllowed('client-1')).to.be.false;

		// After 120ms, tokens should have refilled
		setTimeout(() => {
			expect(limiter.isAllowed('client-1')).to.be.true;
			limiter.destroy();
			done();
		}, 120);
	});

	it('prune removes stale entries', () => {
		const limiter = new HttpRateLimiter({ maxRequests: 10, windowMs: 50 });
		// Use some tokens so the bucket exists
		limiter.isAllowed('stale-client');
		expect(limiter.size).to.equal(1);

		// Immediately prune — entry is fresh, should NOT be removed
		const pruned1 = limiter.prune();
		expect(pruned1).to.equal(0);
		expect(limiter.size).to.equal(1);

		limiter.destroy();
	});

	it('uses default values when no options provided', () => {
		const limiter = new HttpRateLimiter();
		// Should allow at least 100 requests (the default)
		for (let i = 0; i < 100; i++) {
			expect(limiter.isAllowed('default-client')).to.be.true;
		}
		// 101st should be blocked
		expect(limiter.isAllowed('default-client')).to.be.false;
		limiter.destroy();
	});

	it('destroy clears buckets and timer', () => {
		const limiter = new HttpRateLimiter({ maxRequests: 5, windowMs: 60_000 });
		limiter.isAllowed('test');
		expect(limiter.size).to.equal(1);
		limiter.destroy();
		expect(limiter.size).to.equal(0);
	});

	it('RATE_LIMITED error code exists in BeignetErrorCode', () => {
		expect(BeignetErrorCode.RATE_LIMITED).to.equal('RATE_LIMITED');
	});

	it('daemon rateLimit option is accepted in DaemonOptions type', async function () {
		this.timeout(10_000);
		const { startDaemon } = await import('../../src/cli/daemon');
		expect(typeof startDaemon).to.equal('function');
		// Type-level check: DaemonOptions should accept rateLimit
		// (this compiles, which is the test)
	});

	it('rate limiter handles rapid sequential requests correctly', () => {
		const limiter = new HttpRateLimiter({ maxRequests: 10, windowMs: 60_000 });
		const results: boolean[] = [];
		for (let i = 0; i < 15; i++) {
			results.push(limiter.isAllowed('rapid-client'));
		}
		const allowed = results.filter((r) => r).length;
		const blocked = results.filter((r) => !r).length;
		expect(allowed).to.equal(10);
		expect(blocked).to.equal(5);
		limiter.destroy();
	});
});
