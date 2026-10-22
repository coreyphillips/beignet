/**
 * The root entry must load without Node 'crypto' (issue #1686).
 *
 * A React Native host that injects only net and tls has no Node 'crypto', so a
 * module-scope import of it anywhere on the `beignet` load path breaks wallets
 * that never use the one feature needing it. Storage encryption is the only
 * root export that does: it asks the crypto provider, whose Node default loads
 * crypto on first use, and a host can install its own instead (issue #1696).
 */

import { expect } from 'chai';
import { execFile } from 'child_process';
import * as path from 'path';
import { promisify } from 'util';

const run = promisify(execFile);
const repoRoot = path.resolve(__dirname, '..', '..');

// Only beignet's own modules are refused crypto. Under Node resolution some
// dependencies (@noble/hashes, @noble/secp256k1, create-hash, randombytes) pick builds that
// require it, and their package.json `browser` field swaps those out on React
// Native, so refusing them here would fail on something the host never loads.
const CHILD = `
// Built before the refusal below, the way a host builds its own provider.
const { createCountingCryptoProvider } = require('./tests/lightning/helpers/counting-crypto-provider');
const hostProvider = createCountingCryptoProvider().provider;
const Module = require('module');
const path = require('path');
const load = Module._load;
const refused = [];
Module._load = function (request, parent) {
	const fromDependency =
		parent && parent.filename.includes(path.sep + 'node_modules' + path.sep);
	if ((request === 'crypto' || request === 'node:crypto') && !fromDependency) {
		refused.push(parent ? path.relative(process.cwd(), parent.filename) : '');
		throw new Error('crypto is unavailable');
	}
	return load.apply(this, arguments);
};
const report = { refused };
(async () => {
	try {
		const beignet = require('./src');
		report.loaded = typeof beignet.Wallet === 'function';
		try {
			beignet.createEncryptedStorage({}, Buffer.alloc(64));
		} catch (e) {
			report.encryptionError = e.message;
		}
		beignet.setCryptoProvider(hostProvider);
		const rows = new Map();
		const storage = beignet.createEncryptedStorage(
			{
				getData: async (key) => beignet.ok(rows.get(key)),
				setData: async (key, value) => {
					rows.set(key, value);
					return beignet.ok(true);
				}
			},
			Buffer.alloc(64)
		);
		await storage.setData('wallet', { balance: 1 });
		report.sealed = String(rows.get('wallet')).startsWith('encw1:');
		report.opened = (await storage.getData('wallet')).value;
	} catch (e) {
		report.loadError = e.message;
	}
	process.stdout.write(JSON.stringify(report));
})();
`;

describe('beignet root entry', function () {
	// ts-node compiles the whole root load path in the child.
	this.timeout(120_000);

	it('loads with Node crypto unavailable, and encryption asks for it on first use or takes a host provider (issues #1686, #1696)', async () => {
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
		// Proves the stub is live: the lazy require hits it once encryption runs.
		expect(report.encryptionError).to.include('crypto is unavailable');
		expect(report.encryptionError).to.include('setCryptoProvider');
		expect(report.refused).to.deep.equal([
			path.join('src', 'lightning', 'crypto', 'provider.ts')
		]);
		// With a host provider installed, encryption runs and nothing in
		// beignet asks for Node crypto again (issue #1696).
		expect(report.sealed).to.equal(true);
		expect(report.opened).to.deep.equal({ balance: 1 });
	});
});
