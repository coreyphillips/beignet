/**
 * better-sqlite3 is optional (issue #1685): `beignet/lightning` and
 * `beignet/cli` must load without it, and only constructing a SQLite store
 * may ask for it.
 */

import { expect } from 'chai';
import { execFile } from 'child_process';
import * as path from 'path';
import { promisify } from 'util';

const run = promisify(execFile);
const repoRoot = path.resolve(__dirname, '..', '..');

const CHILD = `
const Module = require('module');
const path = require('path');
const load = Module._load;
const refused = [];
Module._load = function (request, parent) {
	if (request === 'better-sqlite3') {
		refused.push(parent ? path.relative(process.cwd(), parent.filename) : '');
		throw new Error('better-sqlite3 is unavailable');
	}
	return load.apply(this, arguments);
};
const report = { refused };
try {
	const lightning = require('./src/lightning');
	const cli = require('./src/cli');
	const sqlite = require('./src/lightning/sqlite');
	report.loaded =
		typeof lightning.node.LightningNode === 'function' &&
		typeof cli.BeignetNode === 'function';
	report.sameClasses =
		lightning.storage.SqliteStorage === sqlite.SqliteStorage &&
		lightning.recovery.GuardianStore === sqlite.GuardianStore;
	for (const [name, Store] of [
		['storage', lightning.storage.SqliteStorage],
		['guardian', sqlite.GuardianStore]
	]) {
		try {
			new Store(':memory:');
		} catch (e) {
			report[name + 'Error'] = e.message;
		}
	}
} catch (e) {
	report.loadError = e.message;
}
process.stdout.write(JSON.stringify(report));
`;

describe('better-sqlite3 as an optional dependency', function () {
	// ts-node compiles the whole lightning and cli load paths in the child.
	this.timeout(120_000);

	it('loads beignet/lightning and beignet/cli without it, and the stores ask for it when constructed (issue #1685)', async () => {
		const { stdout } = await run(
			process.execPath,
			['-r', 'ts-node/register', '-e', CHILD],
			{ cwd: repoRoot }
		);
		const report = JSON.parse(stdout);
		expect(report.loadError, JSON.stringify(report.refused)).to.equal(
			undefined
		);
		expect(report.loaded).to.equal(true);
		expect(report.sameClasses).to.equal(true);
		const expected =
			'SQLite storage requires the optional better-sqlite3 dependency: better-sqlite3 is unavailable';
		expect(report.storageError).to.equal(expected);
		expect(report.guardianError).to.equal(expected);
		const binding = path.join(
			'src',
			'lightning',
			'storage',
			'sqlite-binding.ts'
		);
		expect(report.refused).to.deep.equal([binding, binding]);
	});
});
