#!/usr/bin/env node
/**
 * The npm audit gate, with named exceptions that expire.
 *
 *   node scripts/audit-gate.js   exit 1 on any advisory of moderate severity
 *                                or above that is not excepted, or on an
 *                                exception past its date; 2 when the audit
 *                                cannot be read or the allowlist breaks the
 *                                rules below
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
 * Each exception also names the open issue whose work removes its cause
 * (`"issue": "#2022"`), and its date may be at most MAX_TERM_DAYS after the
 * day the gate runs. A date that can be pushed out a year at a time stops
 * being a deadline; one month at a time, with an owner, is still one. The
 * gate prints every exception with the days it has left, to the log and to
 * the GitHub job summary, and flags each one within WARN_WITHIN_DAYS of its
 * date, so the deadline shows before it fails every pull request.
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
/** The furthest out an exception's date may be: an extension is a month. */
const MAX_TERM_DAYS = 31;
/** An exception this many days or fewer from its date is flagged. */
const WARN_WITHIN_DAYS = 30;
const GHSA = /^GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}$/i;
const ISSUE = /^#[1-9]\d*$/;
const DAY_MS = 24 * 60 * 60 * 1000;

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

/** The UTC date as YYYY-MM-DD, the form `expires` is compared in. */
function isoToday() {
	return new Date().toISOString().slice(0, 10);
}

/** Days from `today` to `expires`: 0 on the last day it holds, negative after. */
function daysLeft(expires, today) {
	return Math.round((Date.parse(expires) - Date.parse(today)) / DAY_MS);
}

/** Check the allowlist's rules as of `today`; the message names the entry at fault. */
function validateAllowlist(entries, today = isoToday()) {
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
		if (typeof entry.issue !== 'string' || !ISSUE.test(entry.issue)) {
			throw new Error(
				`${at}: issue must name the open issue that removes the cause, as "#123"`
			);
		}
		if (
			typeof entry.expires !== 'string' ||
			!/^\d{4}-\d{2}-\d{2}$/.test(entry.expires) ||
			Number.isNaN(Date.parse(entry.expires))
		) {
			throw new Error(`${at}: expires must be a YYYY-MM-DD date`);
		}
		if (daysLeft(entry.expires, today) > MAX_TERM_DAYS) {
			throw new Error(
				`${at}: expires is more than ${MAX_TERM_DAYS} days after ${today}; extend an exception a month at a time`
			);
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

/** How long an exception has left, in words. */
function expiryState(entry, today) {
	const days = daysLeft(entry.expires, today);
	if (days < 0) return `EXPIRED ${-days} day${days === -1 ? '' : 's'} ago`;
	if (days === 0) return 'last day';
	return `${days} day${days === 1 ? '' : 's'} left`;
}

/** True when an unexpired exception is close enough to its date to flag. */
function expiresSoon(entry, today) {
	const days = daysLeft(entry.expires, today);
	return days >= 0 && days <= WARN_WITHIN_DAYS;
}

/**
 * The markdown for the GitHub job summary: each exception with its issue and
 * days left, flagged within WARN_WITHIN_DAYS of its date, then `outcome`
 * (lines of plain text). `allowlist` is null when it failed validation.
 */
function summary(allowlist, today, outcome) {
	const lines = ['### Audit exceptions', ''];
	if (allowlist === null) {
		lines.push('audit-allowlist.json was not accepted:');
	} else if (allowlist.length === 0) {
		lines.push('None: audit-allowlist.json is empty.');
	} else {
		lines.push(
			'| Advisory | Package | Removed by | Expires | Left |',
			'| --- | --- | --- | --- | --- |'
		);
		for (const entry of allowlist) {
			const flag =
				entry.expires < today
					? ':x: '
					: expiresSoon(entry, today)
					? ':warning: '
					: '';
			lines.push(
				`| ${entry.advisory} | ${entry.package} | ${entry.issue} | ${
					entry.expires
				} | ${flag}${expiryState(entry, today)} |`
			);
		}
	}
	const text = outcome.join('\n').split('\n');
	lines.push('', ...text.map((line) => `    ${line}`), '');
	return lines.join('\n');
}

function main() {
	const today = isoToday();
	// The outcome lines go to the job summary as well as the log.
	const outcome = [];
	const log = (line) => {
		console.log(line);
		outcome.push(line);
	};
	const error = (line) => {
		console.error(line);
		outcome.push(line);
	};
	let allowlist = null;
	const finish = (code) => {
		const file = process.env.GITHUB_STEP_SUMMARY;
		if (file) fs.appendFileSync(file, summary(allowlist, today, outcome));
		return code;
	};

	try {
		const read = JSON.parse(fs.readFileSync(ALLOWLIST, 'utf8'));
		validateAllowlist(read, today);
		allowlist = read;
	} catch (err) {
		error(err.message);
		return finish(2);
	}
	for (const entry of allowlist) {
		const state = expiryState(entry, today);
		console.log(
			`exception ${entry.advisory} on ${entry.package} (${entry.issue}, until ${entry.expires}, ${state}): ${entry.reason}`
		);
		// A workflow command: GitHub shows it as an annotation on the run.
		if (process.env.GITHUB_ACTIONS === 'true' && expiresSoon(entry, today)) {
			console.log(
				`::warning title=Audit exception lapses ${entry.expires}::${entry.advisory} on ${entry.package} (${state}). ${entry.issue} removes the cause.`
			);
		}
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
		error(`npm audit gave no JSON (exit ${run.status}):\n${run.stderr}`);
		return finish(2);
	}
	if (report.error) {
		error(
			`npm audit failed: ${
				report.error.summary || JSON.stringify(report.error)
			}`
		);
		return finish(2);
	}
	const vulnerabilities = report.vulnerabilities || {};
	const left = remaining(vulnerabilities, allowlist, today);
	const failing = Object.values(left).filter(
		(v) => SEVERITIES.indexOf(v.severity) >= SEVERITIES.indexOf(FAIL_AT)
	);
	const expired = allowlist.filter((entry) => entry.expires < today);
	const excepted = Object.keys(vulnerabilities).filter(
		(name) => !(name in left)
	);
	if (excepted.length) log(`excepted: ${excepted.join(', ')}`);
	for (const v of failing) {
		const own = (v.via || [])
			.filter((via) => typeof via === 'object')
			.map((via) => `${advisoryId(via)} ${via.title}`);
		const through = (v.via || []).filter((via) => typeof via === 'string');
		log(
			`FAIL ${v.name} ${v.severity} ${v.range}` +
				(own.length ? `: ${own.join('; ')}` : '') +
				(through.length ? ` (via ${through.join(', ')})` : '')
		);
	}
	if (expired.length) {
		log(
			`${expired.length} exception(s) past their date: fix the advisory, or set a new date at most ${MAX_TERM_DAYS} days out with the reason it still stands.`
		);
	}
	if (failing.length || expired.length) return finish(1);
	log(
		`audit gate: ${
			Object.keys(vulnerabilities).length
		} advisories in the tree, ${excepted.length} excepted, none failing.`
	);
	return finish(0);
}

module.exports = {
	FAIL_AT,
	MAX_TERM_DAYS,
	SEVERITIES,
	WARN_WITHIN_DAYS,
	advisoryId,
	daysLeft,
	remaining,
	summary,
	validateAllowlist
};

if (require.main === module) process.exit(main());
