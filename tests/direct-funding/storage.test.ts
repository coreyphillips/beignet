import { expect } from 'chai';
import fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import sinon from 'sinon';
import { FileDirectFundingStorage } from '../../src/direct-funding/node';

describe('Direct-funding file storage', () => {
	let directory: string;
	let storage: FileDirectFundingStorage;
	beforeEach(() => {
		directory = fs.mkdtempSync(
			path.join(os.tmpdir(), 'direct-funding-storage-')
		);
		storage = new FileDirectFundingStorage(directory);
	});
	afterEach(() => {
		sinon.restore();
		storage.close();
		fs.rmSync(directory, { recursive: true, force: true });
	});
	it('persists exact values across clean restarts with private permissions', () => {
		expect(storage.loadWalletData('df:payments')).to.equal(null);
		storage.saveWalletData('df:payments', '[{"value":"one"}]');
		const file = fs
			.readdirSync(directory)
			.find((name) => name.endsWith('.json'))!;
		expect(fs.statSync(path.join(directory, file)).mode & 0o777).to.equal(
			0o600
		);
		storage.close();
		storage = new FileDirectFundingStorage(directory);
		expect(storage.loadWalletData('df:payments')).to.equal('[{"value":"one"}]');
	});
	it('prevents a second writer and rejects use after close', () => {
		expect(() => new FileDirectFundingStorage(directory)).to.throw('locked');
		storage.close();
		expect(() => storage.saveWalletData('key', 'value')).to.throw('closed');
	});
	it('does not treat damaged data as an empty journal', () => {
		storage.saveWalletData('df:payments', '[]');
		const file = fs
			.readdirSync(directory)
			.find((name) => name.endsWith('.json'))!;
		fs.writeFileSync(path.join(directory, file), 'bad json');
		expect(() => storage.loadWalletData('df:payments')).to.throw();
	});
	it('keeps the old value and removes temporary files if fsync fails', () => {
		storage.saveWalletData('key', 'old');
		const stub = sinon.stub(fs, 'fsyncSync').throws(new Error('disk failed'));
		expect(() => storage.saveWalletData('key', 'new')).to.throw('disk failed');
		stub.restore();
		expect(storage.loadWalletData('key')).to.equal('old');
		expect(
			fs.readdirSync(directory).some((name) => name.endsWith('.tmp'))
		).to.equal(false);
	});
	it('skips the directory fsync on Windows, where Node cannot open a directory', () => {
		const platform = Object.getOwnPropertyDescriptor(process, 'platform')!;
		Object.defineProperty(process, 'platform', { ...platform, value: 'win32' });
		const open = sinon.spy(fs, 'openSync');
		try {
			storage.saveWalletData('key', 'value');
		} finally {
			Object.defineProperty(process, 'platform', platform);
		}
		expect(open.callCount).to.equal(1);
		expect(String(open.firstCall.args[0])).to.match(/\.tmp$/);
		expect(storage.loadWalletData('key')).to.equal('value');
	});
	it('hashes keys so storage identifiers cannot escape the directory', () => {
		storage.saveWalletData('../elsewhere', 'value');
		expect(storage.loadWalletData('../elsewhere')).to.equal('value');
		expect(
			fs.readdirSync(directory).filter((name) => name.endsWith('.json'))
		).to.have.length(1);
	});
});
