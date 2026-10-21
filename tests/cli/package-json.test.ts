/**
 * Package.json Tests
 *
 * Verifies package.json has required fields for production publishing.
 */

import { expect } from 'chai';
import { readFileSync } from 'fs';
import * as path from 'path';

const pkg = JSON.parse(
	readFileSync(path.resolve(__dirname, '../../package.json'), 'utf8')
);

describe('package.json', () => {
	it('should ask engines.node for a Node.js release with the October 21, 2026 security fixes (issue #1773)', () => {
		expect(pkg.engines).to.be.an('object');
		expect(pkg.engines.node).to.equal('^22.23.4 || ^24.22.1 || >=26.12.1');
	});

	it('should have files array to limit publish size', () => {
		expect(pkg.files).to.be.an('array');
		expect(pkg.files).to.include('dist/');
		expect(pkg.files).to.include('README.md');
	});

	it('should have exports for main, lightning, and cli', () => {
		expect(pkg.exports).to.be.an('object');
		expect(pkg.exports['.']).to.have.property('default');
		expect(pkg.exports['./lightning']).to.have.property('default');
		expect(pkg.exports['./cli']).to.have.property('default');
	});

	it('should have lightning-related keywords', () => {
		expect(pkg.keywords).to.be.an('array');
		expect(pkg.keywords).to.include('lightning');
		expect(pkg.keywords).to.include('Bitcoin');
	});

	it('should have bin entry for beignet CLI', () => {
		expect(pkg.bin).to.be.an('object');
		expect(pkg.bin.beignet).to.be.a('string');
	});
});
