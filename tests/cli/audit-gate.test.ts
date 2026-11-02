/**
 * The npm audit gate with named, expiring exceptions (scripts/audit-gate.js):
 * an excepted advisory covers the package it is on and every package whose
 * only problem is depending on it; anything else, and any exception past
 * its date, is left for the gate to fail on.
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as path from 'path';

// eslint-disable-next-line @typescript-eslint/no-var-requires
const gate = require('../../scripts/audit-gate.js') as {
	advisoryId(via: { url?: string; source?: number }): string;
	remaining(
		vulnerabilities: Record<string, unknown>,
		allowlist: unknown[],
		today: string
	): Record<string, unknown>;
	validateAllowlist(entries: unknown): void;
};

const MINIMATCH = 'GHSA-g3hv-75wg-m249';
const GLOB = 'GHSA-3g3m-2fjr-6pw4';
const REDIRECTS = 'GHSA-mrwp-f3q8-3g9p';

type Via =
	| string
	| {
			source: number;
			url: string;
			title: string;
			severity: string;
			range: string;
	  };

function record(
	name: string,
	severity: string,
	via: Via[]
): Record<string, unknown> {
	return {
		name,
		severity,
		isDirect: false,
		via,
		range: '*',
		nodes: [],
		effects: [],
		fixAvailable: false
	};
}

function advisory(
	id: string,
	severity: string,
	title: string,
	range: string
): Via {
	return {
		source: 1,
		url: `https://github.com/advisories/${id}`,
		title,
		severity,
		range
	};
}

/** A slice of the 2026-11-02 report: minimatch under glob, mocha and eslint, plus follow-redirects. */
function tree(): Record<string, unknown> {
	return {
		minimatch: record('minimatch', 'moderate', [
			advisory(
				MINIMATCH,
				'moderate',
				'minimatch has potential denial of service',
				'<11.0.1'
			)
		]),
		glob: record('glob', 'moderate', [
			advisory(
				GLOB,
				'moderate',
				'Glob: AbortSignal cancellation bypass',
				'>=9.0.0 <=14.0.1'
			),
			'minimatch'
		]),
		mocha: record('mocha', 'moderate', ['glob', 'minimatch']),
		eslint: record('eslint', 'moderate', ['minimatch']),
		'follow-redirects': record('follow-redirects', 'high', [
			advisory(
				REDIRECTS,
				'high',
				'follow-redirects discards sensitiveHeaders',
				'1.16.0 - 1.16.1'
			)
		])
	};
}

const allow = (
	advisoryIdValue: string,
	pkg: string,
	expires = '2026-12-31'
): Record<string, string> => ({
	advisory: advisoryIdValue,
	package: pkg,
	reason: 'a devDependency advisory no dependent has released a fix for',
	expires
});

describe('audit gate (scripts/audit-gate.js)', () => {
	const TODAY = '2026-11-02';

	it('excepts a listed advisory and everything that only depends on it', () => {
		const left = gate.remaining(
			tree(),
			[allow(MINIMATCH, 'minimatch'), allow(GLOB, 'glob')],
			TODAY
		);
		expect(Object.keys(left)).to.deep.equal(['follow-redirects']);
	});

	it('leaves everything with no allowlist', () => {
		expect(Object.keys(gate.remaining(tree(), [], TODAY)).sort()).to.deep.equal(
			['eslint', 'follow-redirects', 'glob', 'minimatch', 'mocha']
		);
	});

	it('an exception past its date covers nothing', () => {
		const left = gate.remaining(
			tree(),
			[allow(MINIMATCH, 'minimatch', '2026-11-01'), allow(GLOB, 'glob')],
			TODAY
		);
		expect(Object.keys(left).sort()).to.deep.equal([
			'eslint',
			'follow-redirects',
			'glob',
			'minimatch',
			'mocha'
		]);
		// On its last day it still holds.
		const onTheDay = gate.remaining(
			tree(),
			[allow(MINIMATCH, 'minimatch', TODAY), allow(GLOB, 'glob')],
			TODAY
		);
		expect(Object.keys(onTheDay)).to.deep.equal(['follow-redirects']);
	});

	it('an exception names the package the advisory is on, not a dependent', () => {
		const left = gate.remaining(
			tree(),
			[allow(MINIMATCH, 'eslint'), allow(GLOB, 'glob')],
			TODAY
		);
		expect(left).to.have.keys([
			'minimatch',
			'glob',
			'mocha',
			'eslint',
			'follow-redirects'
		]);
	});

	it('a package with one excepted and one open advisory stays open', () => {
		const vulns = tree();
		(vulns.glob as { via: Via[] }).via.push(
			advisory('GHSA-aaaa-bbbb-cccc', 'high', 'another glob problem', '*')
		);
		const left = gate.remaining(
			vulns,
			[allow(MINIMATCH, 'minimatch'), allow(GLOB, 'glob')],
			TODAY
		);
		expect(Object.keys(left).sort()).to.deep.equal([
			'follow-redirects',
			'glob',
			'mocha'
		]);
	});

	it('a cycle in via cannot cover itself', () => {
		const cyclic = {
			a: record('a', 'moderate', ['b']),
			b: record('b', 'moderate', [
				'a',
				advisory('GHSA-aaaa-bbbb-cccc', 'moderate', 'x', '*')
			])
		};
		expect(Object.keys(gate.remaining(cyclic, [], TODAY)).sort()).to.deep.equal(
			['a', 'b']
		);
		expect(
			gate.remaining(cyclic, [allow('GHSA-aaaa-bbbb-cccc', 'b')], TODAY)
		).to.deep.equal({});
	});

	it('a dependency the report does not list is not a problem', () => {
		const vulns = { eslint: record('eslint', 'moderate', ['not-in-report']) };
		expect(gate.remaining(vulns, [], TODAY)).to.deep.equal({});
	});

	it('reads the GHSA id off the advisory url, case-folded', () => {
		expect(
			gate.advisoryId({
				url: 'https://github.com/advisories/ghsa-g3hv-75wg-m249'
			})
		).to.equal(MINIMATCH);
		expect(gate.advisoryId({ source: 1097682 })).to.equal('1097682');
	});

	it('validates the allowlist shape and accepts the committed one', () => {
		const good = allow(MINIMATCH, 'minimatch');
		for (const bad of [
			{ ...good, advisory: 'CVE-2026-1' },
			{ ...good, package: '' },
			{ ...good, reason: 'because' },
			{ ...good, expires: '2026-13-40' },
			{ ...good, expires: 'soon' },
			'not an object'
		]) {
			expect(() => gate.validateAllowlist([bad]), JSON.stringify(bad)).to.throw(
				/audit-allowlist\.json entry 1/
			);
		}
		expect(() => gate.validateAllowlist({})).to.throw(/must be an array/);
		const committed = JSON.parse(
			fs.readFileSync(
				path.resolve(__dirname, '..', '..', 'audit-allowlist.json'),
				'utf8'
			)
		);
		expect(() => gate.validateAllowlist(committed)).to.not.throw();
		expect(
			committed.map((e: { advisory: string }) => e.advisory)
		).to.include.members([MINIMATCH, GLOB]);
	});
});
