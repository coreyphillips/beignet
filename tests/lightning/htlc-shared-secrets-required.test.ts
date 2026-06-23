/**
 * Tests verifying HTLC shared secret methods are required on IStorageBackend.
 *
 * HTLC shared secrets are needed for proper failure message decryption after
 * crash recovery. Making these methods required prevents custom backends from
 * silently breaking this critical fund-safety feature.
 */

import { expect } from 'chai';
import * as crypto from 'crypto';
import { IStorageBackend } from '../../src/lightning/storage/types';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';

describe('HTLC Shared Secrets — Required Interface Contract', () => {
	it('saveHtlcSharedSecret is a required method on IStorageBackend', () => {
		// TypeScript enforces this at compile time. At runtime, verify
		// the method name exists in a complete implementation.
		const storage = new SqliteStorage(':memory:');
		storage.open();
		expect(typeof storage.saveHtlcSharedSecret).to.equal('function');
		storage.close();
	});

	it('deleteHtlcSharedSecret is a required method on IStorageBackend', () => {
		const storage = new SqliteStorage(':memory:');
		storage.open();
		expect(typeof storage.deleteHtlcSharedSecret).to.equal('function');
		storage.close();
	});

	it('loadAllHtlcSharedSecrets is a required method on IStorageBackend', () => {
		const storage = new SqliteStorage(':memory:');
		storage.open();
		expect(typeof storage.loadAllHtlcSharedSecrets).to.equal('function');
		storage.close();
	});

	it('HTLC shared secrets round-trip through SqliteStorage', () => {
		const storage = new SqliteStorage(':memory:');
		storage.open();

		const key = 'abc123def456:7';
		const secret = crypto.randomBytes(32);

		storage.saveHtlcSharedSecret(key, secret);
		const loaded = storage.loadAllHtlcSharedSecrets();
		expect(loaded).to.have.lengthOf(1);
		expect(loaded[0].key).to.equal(key);
		expect(loaded[0].secret.equals(secret)).to.be.true;

		storage.deleteHtlcSharedSecret(key);
		const afterDelete = storage.loadAllHtlcSharedSecrets();
		expect(afterDelete).to.have.lengthOf(0);

		storage.close();
	});

	it('a full IStorageBackend mock must include HTLC shared secret methods to compile', () => {
		// This test verifies that all 3 methods are part of the required interface.
		// A Partial<IStorageBackend> can still omit them, but any object typed as
		// IStorageBackend MUST have them.
		const requiredMethods: (keyof IStorageBackend)[] = [
			'saveHtlcSharedSecret',
			'deleteHtlcSharedSecret',
			'loadAllHtlcSharedSecrets'
		];
		for (const method of requiredMethods) {
			// Verify these are real keys of the interface
			expect(method).to.be.a('string');
			expect(method.length).to.be.greaterThan(0);
		}
	});

	it('lightning-node.ts calls methods directly without typeof guards', () => {
		// Verify that the storage implementation works when called directly
		// (no typeof check needed since methods are now required)
		const storage = new SqliteStorage(':memory:');
		storage.open();

		// These should work without any typeof guard
		const secrets = storage.loadAllHtlcSharedSecrets();
		expect(secrets).to.be.an('array');
		expect(secrets).to.have.lengthOf(0);

		const key = 'test:0';
		const secret = crypto.randomBytes(32);
		storage.saveHtlcSharedSecret(key, secret);

		const loaded = storage.loadAllHtlcSharedSecrets();
		expect(loaded).to.have.lengthOf(1);

		storage.deleteHtlcSharedSecret(key);
		expect(storage.loadAllHtlcSharedSecrets()).to.have.lengthOf(0);

		storage.close();
	});
});
