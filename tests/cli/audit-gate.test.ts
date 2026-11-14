/**
 * The npm audit gate with named, expiring exceptions (scripts/audit-gate.js):
 * an excepted advisory covers the package it is on and every package whose
 * only problem is depending on it; anything else, and any exception past
 * its date, is left for the gate to fail on. Each exception names the issue
 * that removes it and runs a month at most, and the job summary shows the
 * days each one has left.
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as path from 'path';

// eslint-disable-next-line @typescript-eslint/no-var-requires
const gate = require('../../scripts/audit-gate.js') as {
	MAX_TERM_DAYS: number;
	WARN_WITHIN_DAYS: number;
	advisoryId(via: { url?: string; source?: number }): string;
	daysLeft(expires: string, today: string): number;
	remaining(
		vulnerabilities: Record<string, unknown>,
		allowlist: unknown[],
		today: string
	): Record<string, unknown>;
	summary(
		allowlist: unknown[] | null,
		today: string,
		outcome: string[]
	): string;
	validateAllowlist(entries: unknown, today?: string): void;
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
	expires = '2026-12-01'
): Record<string, string> => ({
	advisory: advisoryIdValue,
	package: pkg,
	reason: 'a devDependency advisory no dependent has released a fix for',
	issue: '#2022',
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
		expect(() => gate.validateAllowlist([good], TODAY)).to.not.throw();
		const { issue: _issue, ...noIssue } = good;
		for (const bad of [
			{ ...good, advisory: 'CVE-2026-1' },
			{ ...good, package: '' },
			{ ...good, reason: 'because' },
			{ ...good, expires: '2026-13-40' },
			{ ...good, expires: 'soon' },
			noIssue,
			{ ...good, issue: '' },
			{ ...good, issue: '2022' },
			{ ...good, issue: 'see the toolchain issue' },
			{ ...good, issue: 2022 },
			'not an object'
		]) {
			expect(
				() => gate.validateAllowlist([bad], TODAY),
				JSON.stringify(bad)
			).to.throw(/audit-allowlist\.json entry 1/);
		}
		expect(() => gate.validateAllowlist({})).to.throw(/must be an array/);
		const committed = JSON.parse(
			fs.readFileSync(
				path.resolve(__dirname, '..', '..', 'audit-allowlist.json'),
				'utf8'
			)
		);
		expect(() => gate.validateAllowlist(committed)).to.not.throw();
	});

	it('an exception without an issue names which rule it breaks', () => {
		const { issue: _issue, ...noIssue } = allow(MINIMATCH, 'minimatch');
		expect(() => gate.validateAllowlist([noIssue], TODAY)).to.throw(
			/entry 1: issue must name the open issue/
		);
	});

	it('an exception runs a month at most from the day the gate runs', () => {
		expect(gate.MAX_TERM_DAYS).to.equal(31);
		// 2026-11-02 + 31 days is 2026-12-03.
		expect(() =>
			gate.validateAllowlist(
				[allow(MINIMATCH, 'minimatch', '2026-12-03')],
				TODAY
			)
		).to.not.throw();
		expect(() =>
			gate.validateAllowlist(
				[allow(MINIMATCH, 'minimatch', '2026-12-04')],
				TODAY
			)
		).to.throw(/entry 1: expires is more than 31 days after 2026-11-02/);
		// The year-out date the first two exceptions carried is refused.
		expect(() =>
			gate.validateAllowlist(
				[allow(MINIMATCH, 'minimatch', '2026-12-31')],
				TODAY
			)
		).to.throw(/more than 31 days/);
		// A date already past is not a term problem; the gate fails it as expired.
		expect(() =>
			gate.validateAllowlist(
				[allow(MINIMATCH, 'minimatch', '2026-11-01')],
				TODAY
			)
		).to.not.throw();
	});

	it('counts days to expiry across a month end', () => {
		expect(gate.daysLeft('2026-12-01', TODAY)).to.equal(29);
		expect(gate.daysLeft(TODAY, TODAY)).to.equal(0);
		expect(gate.daysLeft('2026-11-01', TODAY)).to.equal(-1);
		expect(gate.daysLeft('2027-01-01', '2026-12-31')).to.equal(1);
	});

	it('the job summary shows every exception with its days left', () => {
		const md = gate.summary(
			[
				allow(MINIMATCH, 'minimatch', '2026-12-03'),
				allow(GLOB, 'glob', '2026-11-20'),
				allow(REDIRECTS, 'follow-redirects', TODAY),
				allow('GHSA-aaaa-bbbb-cccc', 'x', '2026-10-30')
			],
			TODAY,
			['audit gate: 4 advisories in the tree, 2 excepted, none failing.']
		);
		const row = (pkg: string): string =>
			md.split('\n').find((line) => line.includes(`| ${pkg} |`)) || '';
		expect(gate.WARN_WITHIN_DAYS).to.equal(30);
		// 31 days out is past the warning window.
		expect(row('minimatch')).to.equal(
			`| ${MINIMATCH} | minimatch | #2022 | 2026-12-03 | 31 days left |`
		);
		expect(row('glob')).to.equal(
			`| ${GLOB} | glob | #2022 | 2026-11-20 | :warning: 18 days left |`
		);
		expect(row('follow-redirects')).to.include(':warning: last day |');
		expect(row('x')).to.include(':x: EXPIRED 3 days ago |');
		expect(md).to.include(
			'    audit gate: 4 advisories in the tree, 2 excepted, none failing.'
		);
	});

	it('the job summary says when there are no exceptions, or the list was refused', () => {
		expect(gate.summary([], TODAY, [])).to.include(
			'None: audit-allowlist.json is empty.'
		);
		const refused = gate.summary(null, TODAY, [
			'audit-allowlist.json entry 1: issue must name the open issue'
		]);
		expect(refused).to.include('audit-allowlist.json was not accepted:');
		expect(refused).to.include(
			'    audit-allowlist.json entry 1: issue must name the open issue'
		);
	});
});
