import { expect } from 'chai';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	IStorageBackend,
	IStorageConformanceCheck,
	MemoryStorage,
	STORAGE_CAPABILITIES,
	StorageCapability,
	hasRecoveryStorage,
	hasStorageCapability,
	partialStorageCapabilities,
	runStorageConformanceSuite,
	storageCapabilityMembers,
	storageConformanceChecks
} from '../../src/lightning/storage';

runStorageConformanceSuite(() => new SqliteStorage(':memory:'), {
	name: 'SqliteStorage conformance'
});

runStorageConformanceSuite(
	() =>
		new SqliteStorage(':memory:', undefined, {
			encryptionKey: Buffer.alloc(32, 7)
		}),
	{ name: 'SqliteStorage conformance, encrypted' }
);

runStorageConformanceSuite(() => new MemoryStorage(), {
	name: 'MemoryStorage conformance'
});

/** A MemoryStorage with the given capability groups' methods removed. */
function memoryWithout(...capabilities: StorageCapability[]): MemoryStorage {
	const storage = new MemoryStorage();
	for (const capability of capabilities) {
		for (const member of storageCapabilityMembers(capability)) {
			Object.defineProperty(storage, member, { value: undefined });
		}
	}
	return storage;
}

/** The names of the checks that throw against backends from `factory`. */
function failingChecks(factory: () => IStorageBackend): string[] {
	return storageConformanceChecks(factory)
		.filter((check: IStorageConformanceCheck) => {
			try {
				check.run();
				return false;
			} catch {
				return true;
			}
		})
		.map((check) => check.name);
}

describe('Storage conformance suite', function () {
	it('passes MemoryStorage on every check, skipping none', function () {
		const results = storageConformanceChecks(() => new MemoryStorage()).map(
			(check) => check.run()
		);
		expect(results.every((result) => result === 'passed')).to.equal(true);
	});

	it('fails a backend whose transaction does not roll back', function () {
		class NoRollback extends MemoryStorage {
			transaction<T>(fn: () => T): T {
				return fn();
			}
		}
		expect(failingChecks(() => new NoRollback())).to.include(
			'a throw rolls back every write of the transaction and rethrows'
		);
	});

	it('fails a backend that keeps the objects it is given', function () {
		class ByReference extends MemoryStorage {
			private readonly held = new Map<string, Buffer>();
			savePreimage(paymentHash: string, preimage: Buffer): void {
				this.held.set(paymentHash, preimage);
			}
			loadPreimage(paymentHash: string): Buffer | null {
				return this.held.get(paymentHash) ?? null;
			}
		}
		expect(failingChecks(() => new ByReference())).to.include(
			'stores copies, not the objects it is given'
		);
	});

	it('fails a backend whose deleteChannel drops the key index', function () {
		class ForgetsKeys extends MemoryStorage {
			private readonly forgotten = new Set<string>();
			deleteChannel(id: string): void {
				super.deleteChannel(id);
				this.forgotten.add(id);
			}
			loadChannelKeyIndex(channelId: string): number | null {
				return this.forgotten.has(channelId)
					? null
					: super.loadChannelKeyIndex(channelId);
			}
		}
		expect(failingChecks(() => new ForgetsKeys())).to.deep.equal([
			'channel key indices outlive their channel'
		]);
	});

	it('fails a backend whose save replaces the stored HTLC snapshots', function () {
		class ReplacesSnapshots extends MemoryStorage {
			saveChannel(
				id: string,
				state: Parameters<MemoryStorage['saveChannel']>[1],
				peerPubkey: string
			): void {
				super.deleteChannel(id);
				super.saveChannel(id, state, peerPubkey);
			}
		}
		expect(failingChecks(() => new ReplacesSnapshots())).to.include(
			'saveChannel adds revoked HTLC snapshots to the stored ones'
		);
	});

	it('fails a backend that implements part of a capability group', function () {
		const factory = (): MemoryStorage => {
			const storage = new MemoryStorage();
			Object.defineProperty(storage, 'loadRecoveryFrameHeader', {
				value: undefined
			});
			return storage;
		};
		expect(failingChecks(factory)).to.deep.equal([
			'implements each capability group whole or not at all'
		]);
	});

	it('skips the checks of a group the backend lacks', function () {
		const checks = storageConformanceChecks(() =>
			memoryWithout('watchtower', 'offers')
		);
		const skipped = checks
			.filter((check) => check.run() === 'skipped')
			.map((check) => check.capability);
		expect(skipped).to.deep.equal(['watchtower', 'offers']);
	});

	it('fails a backend missing a core method', function () {
		const factory = (): MemoryStorage => {
			const storage = new MemoryStorage();
			Object.defineProperty(storage, 'deletePreimage', { value: undefined });
			return storage;
		};
		expect(failingChecks(factory)).to.include(
			'implements every IStorageCore method'
		);
	});
});

describe('Storage capability groups', function () {
	it('SqliteStorage and MemoryStorage implement every group', function () {
		const sqlite = new SqliteStorage(':memory:');
		for (const storage of [sqlite, new MemoryStorage()]) {
			for (const capability of STORAGE_CAPABILITIES) {
				expect(hasStorageCapability(storage, capability), capability).to.equal(
					true
				);
			}
			expect(hasRecoveryStorage(storage)).to.equal(true);
			expect(partialStorageCapabilities(storage)).to.deep.equal([]);
		}
		sqlite.close();
	});

	it('a group is present only with every one of its methods', function () {
		const storage = new MemoryStorage();
		Object.defineProperty(storage, 'markWatchtowerUpdateAcked', {
			value: undefined
		});
		expect(hasStorageCapability(storage, 'watchtower')).to.equal(false);
		expect(partialStorageCapabilities(storage)).to.deep.equal(['watchtower']);
		expect(hasStorageCapability(storage, 'forwarding')).to.equal(true);
	});

	it('recovery storage needs the outbox and the journal', function () {
		expect(hasRecoveryStorage(memoryWithout('recoveryOutbox'))).to.equal(false);
		expect(hasRecoveryStorage(memoryWithout('recoveryJournal'))).to.equal(
			false
		);
		const bare = memoryWithout('recoveryOutbox', 'recoveryJournal');
		expect(hasRecoveryStorage(bare)).to.equal(false);
		expect(partialStorageCapabilities(bare)).to.deep.equal([]);
	});
});

describe('MemoryStorage', function () {
	it('rolls back only a nested transaction that throws', function () {
		const storage = new MemoryStorage();
		storage.transaction(() => {
			storage.saveMetadata('outer', '1');
			expect(() =>
				storage.transaction(() => {
					storage.saveMetadata('inner', '1');
					storage.saveMetadata('outer', '2');
					throw new Error('inner');
				})
			).to.throw('inner');
			expect(storage.loadMetadata('inner')).to.equal(null);
			expect(storage.loadMetadata('outer')).to.equal('1');
			expect(storage.inTransaction()).to.equal(true);
		});
		expect(storage.loadMetadata('outer')).to.equal('1');
		expect(storage.inTransaction()).to.equal(false);
	});

	it('refuses a transaction function that returns a promise', function () {
		const storage = new MemoryStorage();
		expect(() =>
			storage.transaction(() => {
				storage.saveMetadata('k', 'v');
				return Promise.resolve();
			})
		).to.throw(TypeError, 'cannot return a promise');
		expect(storage.loadMetadata('k')).to.equal(null);
		expect(storage.inTransaction()).to.equal(false);
	});

	it('keeps its contents across close and open', function () {
		const storage = new MemoryStorage();
		storage.open();
		storage.savePreimage('h', Buffer.alloc(32, 1));
		storage.close();
		storage.open();
		expect(storage.loadPreimage('h')).to.deep.equal(Buffer.alloc(32, 1));
	});

	it('reads rows in their original order after a rollback', function () {
		const storage = new MemoryStorage();
		const ids = [1, 2, 3].map((n) =>
			storage.saveOutboxMessage({
				peerId: 'peer',
				channelId: 'c',
				messageType: 132,
				wireMessage: Buffer.from([n]),
				disposition: 'pending_send'
			})
		);
		for (let n = 0; n < 5; n++) {
			storage.saveGossipChannel(`scid${n}`, {
				shortChannelId: Buffer.from([n]),
				nodeId1: Buffer.alloc(33, 2),
				nodeId2: Buffer.alloc(33, 3),
				features: Buffer.alloc(0)
			} as never);
		}
		const before = storage
			.loadAllGossipChannels()
			.map((c) => c.shortChannelId[0]);
		expect(() =>
			storage.transaction(() => {
				storage.deleteOutboxMessages('c');
				storage.deleteGossipChannel('scid0');
				storage.deleteGossipChannel('scid3');
				throw new Error('abort');
			})
		).to.throw('abort');
		expect(storage.loadOutboxMessages('c').map((row) => row.id)).to.deep.equal(
			ids
		);
		expect(
			storage.loadAllGossipChannels().map((c) => c.shortChannelId[0])
		).to.deep.equal(before);
		const page = storage.loadGossipChannelsAfter(0, 10);
		expect(page.rows.map((c) => c.shortChannelId[0])).to.deep.equal(before);
	});

	it('prunes the forwarding ledger to its cap, oldest first', function () {
		const storage = new MemoryStorage();
		storage.forwardingEventsMaxRows = 2;
		for (const settledAt of [1, 2, 3]) {
			storage.saveForwardingEvent({
				settledAt,
				inChannelId: 'a',
				outChannelId: 'b',
				amountInMsat: 2n,
				amountOutMsat: 1n,
				feeMsat: 1n
			});
		}
		expect(
			storage.listForwardingEvents().map((event) => event.settledAt)
		).to.deep.equal([3, 2]);
	});
});
