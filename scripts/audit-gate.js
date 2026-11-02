#!/usr/bin/env node
/**
 * The npm audit gate, with named exceptions that expire.
 *
 *   node scripts/audit-gate.js   exit 1 on any advisory of moderate severity
 *                                or above that is not excepted, or on an
 *                                exception past its date; 2 when the audit
 *                                or the allowlist cannot be read
 *
 * `npm audit --audit-level=moderate` fails on an advisory in a test or lint
 * tool for which no dependent has released a fix (minimatch under eslint 8,
 * mocha, typedoc and c8 in November 2026), and a gate nobody can pass ends
 * up switched off. This gate reads audit-allowlist.json instead. An advisory
 * listed there, with the package it is on, the reason it is tolerated and
 * the date the exception lapses, does not fail the run, and neither does a
 * package whose only problem is depending on an excepted one. Everything
 * else fails the run, as before. An exception past its date fails the run
 * too, so each one is looked at again rather than forgotten.
 *
 * Exceptions are for devDependencies. The workflow runs
 * `npm audit --audit-level=moderate --omit=dev` beside this gate, with no
 * exceptions, so an advisory in what ships is never excepted.
 */
'use strict';

/* eslint-disable @typescript-eslint/no-var-requires */
const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const ALLOWLIST = path.join(__dirname, '..', 'audit-allowlist.json');
const SEVERITIES = ['info', 'low', 'moderate', 'high', 'critical'];
/** The level the plain gate failed at; low and info advisories still pass. */
const FAIL_AT = 'moderate';
const GHSA = /^GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}$/i;

/** A GHSA id in its published form: upper-case prefix, lower-case rest. */
function normalizeGhsa(id) {
	return `GHSA-${id.slice(5).toLowerCase()}`;
}

/** The GHSA id an advisory's url ends in, else its numeric source. */
function advisoryId(via) {
	const match = /GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}$/i.exec(
		via.url || ''
	);
	return match ? normalizeGhsa(match[0]) : String(via.source);
}

/** Check the allowlist's shape; the message names the entry at fault. */
function validateAllowlist(entries) {
	if (!Array.isArray(entries)) {
		throw new Error('audit-allowlist.json must be an array of exceptions');
	}
	entries.forEach((entry, i) => {
		const at = `audit-allowlist.json entry ${i + 1}`;
		if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
			throw new Error(`${at} must be an object`);
		}
		if (!GHSA.test(entry.advisory)) {
			throw new Error(`${at}: advisory must be a GHSA id`);
		}
		if (typeof entry.package !== 'string' || entry.package.length === 0) {
			throw new Error(
				`${at}: package must name the package the advisory is on`
			);
		}
		if (typeof entry.reason !== 'string' || entry.reason.length < 20) {
			throw new Error(`${at}: reason must say why the advisory is tolerated`);
		}
		if (
			typeof entry.expires !== 'string' ||
			!/^\d{4}-\d{2}-\d{2}$/.test(entry.expires) ||
			Number.isNaN(Date.parse(entry.expires))
		) {
			throw new Error(`${at}: expires must be a YYYY-MM-DD date`);
		}
	});
}

/**
 * The vulnerabilities (npm audit --json's `vulnerabilities` map) the
 * allowlist does not cover as of `today` (YYYY-MM-DD). A record is covered
 * when every advisory on it is listed, unexpired, for that package, and every
 * vulnerable dependency it reaches through (a string in `via`) is covered.
 * Computed as a fixpoint, so a cycle in `via` cannot cover itself.
 */
function remaining(vulnerabilities, allowlist, today) {
	const live = new Set(
		allowlist
			.filter((entry) => entry.expires >= today)
			.map((entry) => `${entry.package}@${normalizeGhsa(entry.advisory)}`)
	);
	const covered = new Set(Object.keys(vulnerabilities));
	let changed = true;
	while (changed) {
		changed = false;
		for (const name of covered) {
			const ok = (vulnerabilities[name].via || []).every((via) =>
				typeof via === 'string'
					? covered.has(via) || !(via in vulnerabilities)
					: live.has(`${name}@${advisoryId(via)}`)
			);
			if (!ok) {
				covered.delete(name);
				changed = true;
			}
		}
	}
	const out = {};
	for (const name of Object.keys(vulnerabilities)) {
		if (!covered.has(name)) out[name] = vulnerabilities[name];
	}
	return out;
}

function main() {
	let allowlist;
	try {
		allowlist = JSON.parse(fs.readFileSync(ALLOWLIST, 'utf8'));
		validateAllowlist(allowlist);
	} catch (err) {
		console.error(err.message);
		return 2;
	}
	const run = spawnSync(
		process.platform === 'win32' ? 'npm.cmd' : 'npm',
		['audit', '--json'],
		{ encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }
	);
	let report;
	try {
		report = JSON.parse(run.stdout);
	} catch {
		console.error(
			`npm audit gave no JSON (exit ${run.status}):\n${run.stderr}`
		);
		return 2;
	}
	if (report.error) {
		console.error(
			`npm audit failed: ${
				report.error.summary || JSON.stringify(report.error)
			}`
		);
		return 2;
	}
	const today = new Date().toISOString().slice(0, 10);
	const vulnerabilities = report.vulnerabilities || {};
	const left = remaining(vulnerabilities, allowlist, today);
	const failing = Object.values(left).filter(
		(v) => SEVERITIES.indexOf(v.severity) >= SEVERITIES.indexOf(FAIL_AT)
	);
	const expired = allowlist.filter((entry) => entry.expires < today);
	for (const entry of allowlist) {
		const state = entry.expires < today ? 'EXPIRED' : `until ${entry.expires}`;
		console.log(
			`exception ${entry.advisory} on ${entry.package} (${state}): ${entry.reason}`
		);
	}
	const excepted = Object.keys(vulnerabilities).filter(
		(name) => !(name in left)
	);
	if (excepted.length) console.log(`excepted: ${excepted.join(', ')}`);
	for (const v of failing) {
		const own = (v.via || [])
			.filter((via) => typeof via === 'object')
			.map((via) => `${advisoryId(via)} ${via.title}`);
		const through = (v.via || []).filter((via) => typeof via === 'string');
		console.log(
			`FAIL ${v.name} ${v.severity} ${v.range}` +
				(own.length ? `: ${own.join('; ')}` : '') +
				(through.length ? ` (via ${through.join(', ')})` : '')
		);
	}
	if (expired.length) {
		console.log(
			`${expired.length} exception(s) past their date: fix the advisory, or set a new date with the reason it still stands.`
		);
	}
	if (failing.length || expired.length) return 1;
	console.log(
		`audit gate: ${
			Object.keys(vulnerabilities).length
		} advisories in the tree, ${excepted.length} excepted, none failing.`
	);
	return 0;
}

module.exports = {
	FAIL_AT,
	SEVERITIES,
	advisoryId,
	remaining,
	validateAllowlist
};

if (require.main === module) process.exit(main());
