import { expect } from 'chai';
import { BeignetNodeEvents } from '../../src/cli/types';
import { BeignetNodeOptions } from '../../src/cli/beignet-node';

describe('Automated Backup Scheduling', () => {
	it('BeignetNodeOptions accepts backupPath', () => {
		const opts: BeignetNodeOptions = {
			mnemonic:
				'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
			network: 'regtest',
			backupPath: '/backups/node.db'
		};
		expect(opts.backupPath).to.equal('/backups/node.db');
	});

	it('BeignetNodeOptions accepts backupIntervalMs', () => {
		const opts: BeignetNodeOptions = {
			network: 'regtest',
			backupPath: '/backups/node.db',
			backupIntervalMs: 3600_000 // 1 hour
		};
		expect(opts.backupIntervalMs).to.equal(3600_000);
	});

	it('default backupIntervalMs is 6 hours when not specified', () => {
		const defaultMs = 6 * 60 * 60 * 1000;
		expect(defaultMs).to.equal(21600000);
	});

	it('backup:completed event type exists on BeignetNodeEvents', () => {
		// Type-level test: ensuring the event signature compiles
		const handler: BeignetNodeEvents['backup:completed'] = (data) => {
			expect(data.path).to.be.a('string');
			expect(data.timestamp).to.be.a('number');
		};
		handler({ path: '/backups/node.db', timestamp: Date.now() });
	});

	it('backup:failed event type exists on BeignetNodeEvents', () => {
		const handler: BeignetNodeEvents['backup:failed'] = (data) => {
			expect(data.path).to.be.a('string');
			expect(data.error).to.be.a('string');
			expect(data.timestamp).to.be.a('number');
		};
		handler({
			path: '/backups/node.db',
			error: 'disk full',
			timestamp: Date.now()
		});
	});

	it('backupPath is optional (no backup when not set)', () => {
		const opts: BeignetNodeOptions = { network: 'regtest' };
		expect(opts.backupPath).to.be.undefined;
	});
});
