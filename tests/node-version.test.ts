/**
 * Issue #1773: the daemon warns at startup when it runs on a Node.js release
 * without the October 21, 2026 security fixes. Pure version checks, offline.
 */

import { expect } from 'chai';

import {
	isPatchedNodeVersion,
	unpatchedNodeWarning
} from '../src/utils/node-version';

describe('Node.js security release check (#1773)', () => {
	it('accepts the first patched release on each line and anything later on it', () => {
		for (const version of [
			'22.23.4',
			'22.23.5',
			'22.24.0',
			'24.22.1',
			'24.23.0',
			'26.12.1',
			'26.13.0',
			'v24.22.1'
		]) {
			expect(isPatchedNodeVersion(version), version).to.equal(true);
		}
	});

	it('refuses releases before the fix on a patched line', () => {
		for (const version of [
			'22.23.3',
			'22.11.0',
			'24.22.0',
			'24.19.0',
			'26.12.0',
			'26.1.0'
		]) {
			expect(isPatchedNodeVersion(version), version).to.equal(false);
		}
	});

	it('refuses every release on an end-of-life line', () => {
		for (const version of [
			'18.20.8',
			'20.19.5',
			'21.7.3',
			'23.11.1',
			'25.9.0'
		]) {
			expect(isPatchedNodeVersion(version), version).to.equal(false);
		}
	});

	it('accepts a major line newer than the newest patched one', () => {
		expect(isPatchedNodeVersion('27.0.0')).to.equal(true);
	});

	it('refuses a version it cannot parse', () => {
		expect(isPatchedNodeVersion('')).to.equal(false);
		expect(isPatchedNodeVersion('next')).to.equal(false);
	});

	it('names the running version and the patched releases, and stays quiet when patched', () => {
		const warning = unpatchedNodeWarning('20.19.5');
		expect(warning).to.be.a('string');
		expect(warning).to.contain('Node.js v20.19.5');
		expect(warning).to.contain('October 21, 2026');
		expect(warning).to.contain('22.23.4, 24.22.1, 26.12.1');
		expect(unpatchedNodeWarning('24.22.1')).to.equal(undefined);
	});
});
