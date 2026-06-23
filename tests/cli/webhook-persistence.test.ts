/**
 * Tests for webhook persistence — webhooks survive daemon restarts.
 */

import { expect } from 'chai';
import { WebhookManager } from '../../src/cli/webhooks';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';

describe('Webhook Persistence', () => {
	let storage: SqliteStorage;

	beforeEach(() => {
		storage = new SqliteStorage(':memory:');
		storage.open();
	});

	afterEach(() => {
		storage.close();
	});

	it('webhooks survive restart (register, recreate manager, verify list)', () => {
		const manager1 = new WebhookManager(storage);
		manager1.register('http://example.com/hook1', ['payment:received']);
		manager1.register('http://example.com/hook2', [
			'channel:ready',
			'channel:closed'
		]);
		expect(manager1.size).to.equal(2);

		// Simulate restart — create new manager with same storage
		const manager2 = new WebhookManager(storage);
		expect(manager2.size).to.equal(2);
		const list = manager2.list();
		expect(list.map((w) => w.url).sort()).to.deep.equal([
			'http://example.com/hook1',
			'http://example.com/hook2'
		]);
	});

	it('unregister removes from storage', () => {
		const manager1 = new WebhookManager(storage);
		const reg = manager1.register('http://example.com/hook', ['*']);
		manager1.unregister(reg.id);
		expect(manager1.size).to.equal(0);

		// After restart, still empty
		const manager2 = new WebhookManager(storage);
		expect(manager2.size).to.equal(0);
	});

	it('clear removes all from storage', () => {
		const manager1 = new WebhookManager(storage);
		manager1.register('http://example.com/hook1', ['payment:received']);
		manager1.register('http://example.com/hook2', ['payment:sent']);
		manager1.clear();
		expect(manager1.size).to.equal(0);

		const manager2 = new WebhookManager(storage);
		expect(manager2.size).to.equal(0);
	});

	it('backward compatible — no storage means ephemeral', () => {
		const manager = new WebhookManager();
		manager.register('http://example.com/hook', ['*']);
		expect(manager.size).to.equal(1);
		// No crash, works as before
	});

	it('secret is hashed in storage, not stored plaintext', () => {
		const manager = new WebhookManager(storage);
		manager.register('http://example.com/hook', ['*'], 'my-secret-key');

		const rows = storage.loadAllWebhooks();
		expect(rows).to.have.lengthOf(1);
		// secretHash should be a SHA-256 hex string, not the raw secret
		expect(rows[0].secretHash).to.not.equal('my-secret-key');
		expect(rows[0].secretHash).to.have.lengthOf(64); // SHA-256 hex = 64 chars
	});

	it('events array round-trips correctly', () => {
		const events = ['payment:received', 'payment:sent', 'channel:ready'];
		const manager1 = new WebhookManager(storage);
		manager1.register('http://example.com/hook', events);

		const manager2 = new WebhookManager(storage);
		const list = manager2.list();
		expect(list).to.have.lengthOf(1);
		expect(list[0].events).to.deep.equal(events);
	});

	it('restored webhooks show masked secret in list', () => {
		const manager1 = new WebhookManager(storage);
		manager1.register('http://example.com/hook', ['*'], 'secret123');

		const manager2 = new WebhookManager(storage);
		const list = manager2.list();
		expect(list).to.have.lengthOf(1);
		// Secret was registered, so it should show masked
		expect(list[0].secret).to.equal('***');
	});

	it('SqliteStorage schema version advances to 2', () => {
		expect(SqliteStorage.CURRENT_SCHEMA_VERSION).to.equal(2);
		const version = storage.getSchemaVersion();
		expect(version).to.be.at.least(1);
	});
});
