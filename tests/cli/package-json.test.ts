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

	it('should export ./package.json (issue #1683)', () => {
		expect(pkg.exports['./package.json']).to.equal('./package.json');
	});

	// node10 resolution ignores `exports`, so each typed subpath needs a
	// typesVersions entry or a CommonJS TypeScript consumer gets no types.
	it('should map every typed subpath export in typesVersions (issue #1683)', () => {
		const mapped = pkg.typesVersions['*'];
		const subpaths = Object.keys(pkg.exports).filter(
			(key) => key !== '.' && typeof pkg.exports[key] === 'object'
		);
		expect(subpaths).to.include.members([
			'./lightning',
			'./cli',
			'./lightning/iroh-node',
			'./lightning/sqlite'
		]);
		expect(Object.keys(mapped)).to.have.members(
			subpaths.map((key) => key.slice(2))
		);
		for (const key of subpaths) {
			expect(mapped[key.slice(2)], key).to.deep.equal([
				pkg.exports[key].types.slice(2)
			]);
		}
	});

	it('should list better-sqlite3 as optional, not required (issue #1685)', () => {
		expect(pkg.dependencies).to.not.have.property('better-sqlite3');
		expect(pkg.optionalDependencies).to.have.property('better-sqlite3');
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
