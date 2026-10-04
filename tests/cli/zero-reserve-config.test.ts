import { expect } from 'chai';
import fs from 'fs';
import sinon from 'sinon';
import { configPath, resolveConfig } from '../../src/cli/config';
import { daemonOptions } from '../../src/cli/daemon-options';

describe('Zero reserve operator configuration', () => {
	const original = process.env.BEIGNET_WAIVE_CLIENT_RESERVE;
	let stored: { waiveClientReserve?: boolean };
	beforeEach(() => {
		stored = {};
		delete process.env.BEIGNET_WAIVE_CLIENT_RESERVE;
		const read = fs.readFileSync;
		sinon.stub(fs, 'readFileSync').callsFake(((
			file: fs.PathOrFileDescriptor,
			...args: unknown[]
		) => {
			if (file === configPath()) return JSON.stringify(stored);
			return (read as Function)(file, ...args);
		}) as typeof fs.readFileSync);
	});
	afterEach(() => {
		sinon.restore();
		if (original === undefined) delete process.env.BEIGNET_WAIVE_CLIENT_RESERVE;
		else process.env.BEIGNET_WAIVE_CLIENT_RESERVE = original;
	});
	it('leaves the primary waiver disabled by default', () => {
		expect(resolveConfig({}).waiveClientReserve).to.equal(undefined);
	});
	it('carries the explicit environment setting into daemon options', () => {
		process.env.BEIGNET_WAIVE_CLIENT_RESERVE = 'true';
		expect(daemonOptions(resolveConfig({}), 0).waiveClientReserve).to.equal(
			true
		);
	});
	it('allows an explicit false to override an enabled configuration file', () => {
		stored = { waiveClientReserve: true };
		process.env.BEIGNET_WAIVE_CLIENT_RESERVE = 'false';
		expect(resolveConfig({}).waiveClientReserve).to.equal(false);
	});
	it('retains the file setting and gives explicit options precedence', () => {
		stored = { waiveClientReserve: true };
		expect(resolveConfig({}).waiveClientReserve).to.equal(true);
		process.env.BEIGNET_WAIVE_CLIENT_RESERVE = 'true';
		expect(
			resolveConfig({ waiveClientReserve: false }).waiveClientReserve
		).to.equal(false);
	});
	it('uses the existing exact-string boolean rule', () => {
		for (const value of ['TRUE', '1', 'yes', '']) {
			process.env.BEIGNET_WAIVE_CLIENT_RESERVE = value;
			expect(resolveConfig({}).waiveClientReserve).to.equal(undefined);
		}
	});
});
