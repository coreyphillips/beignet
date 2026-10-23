/**
 * `beignet/node` must load without Node's fs, net and tls, without
 * better-sqlite3 and without the daemon (issue #1708). React Native has no
 * fs, and gets net and tls only from an alias the app sets up, so a
 * module-scope import of any of them on this load path fails the bundle.
 * `beignet/lightning`, where such an app takes MemoryStorage from, loads
 * under the same refusals. `beignet/cli` stays as `beignet/node` and
 * `beignet/daemon` together.
 */

import { expect } from 'chai';
import { execFile } from 'child_process';
import * as path from 'path';
import { promisify } from 'util';

const run = promisify(execFile);
const repoRoot = path.resolve(__dirname, '..', '..');

// Refused for every requester, dependencies included: socks, for one, loads
// net at module scope, so the lightning layer requires it on first use.
const CHILD = `
const Module = require('module');
const path = require('path');
const load = Module._load;
const REFUSED = new Set(['fs', 'net', 'tls', 'better-sqlite3']);
const refused = [];
let refusing = true;
Module._load = function (request, parent) {
	const name = request.startsWith('node:') ? request.slice(5) : request;
	if (refusing && REFUSED.has(name)) {
		refused.push(
			name + ' from ' + (parent ? path.relative(process.cwd(), parent.filename) : '')
		);
		throw new Error(name + ' is unavailable');
	}
	return load.apply(this, arguments);
};
const report = { refused };
try {
	const node = require('./src/node');
	report.loaded = typeof node.BeignetNode.create === 'function';
	const loadedFiles = Object.keys(require.cache).map((file) =>
		path.relative(process.cwd(), file)
	);
	report.daemonModules = loadedFiles.filter((file) =>
		/^src\\/cli\\/(daemon|openapi|auth|webhooks|http-rate-limiter)\\.ts$/.test(file)
	);
	report.sqliteModules = loadedFiles.filter((file) =>
		/sqlite-storage|better-sqlite3/.test(file)
	);
	report.memoryStorage =
		typeof require('./src/lightning').storage.MemoryStorage === 'function';
	refusing = false;
	const cli = require('./src/cli');
	const daemon = require('./src/daemon');
	report.sameNode = cli.BeignetNode === node.BeignetNode;
	report.sameDaemon = cli.startDaemon === daemon.startDaemon;
	report.cliExports = Object.keys(cli).sort();
	report.splitExports = [
		...new Set([...Object.keys(node), ...Object.keys(daemon)])
	].sort();
	report.nodeHasDaemon = 'startDaemon' in node;
} catch (e) {
	report.loadError = e.message;
}
process.stdout.write(JSON.stringify(report));
`;

describe('beignet/node entry', function () {
	// ts-node compiles the whole node load path in the child.
	this.timeout(120_000);

	it('loads without fs, net, tls, better-sqlite3 or the daemon, as beignet/lightning does, and beignet/cli is both entries together (issue #1708)', async () => {
		const { stdout } = await run(
			process.execPath,
			['-r', 'ts-node/register', '-e', CHILD],
			{ cwd: repoRoot }
		);
		const report = JSON.parse(stdout);
		expect(report.loadError, JSON.stringify(report.refused)).to.equal(
			undefined
		);
		expect(report.refused).to.deep.equal([]);
		expect(report.loaded).to.equal(true);
		expect(report.daemonModules).to.deep.equal([]);
		expect(report.sqliteModules).to.deep.equal([]);
		expect(report.nodeHasDaemon).to.equal(false);
		expect(report.memoryStorage).to.equal(true);
		expect(report.sameNode).to.equal(true);
		expect(report.sameDaemon).to.equal(true);
		expect(report.cliExports).to.deep.equal(report.splitExports);
	});
});
