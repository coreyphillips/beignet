/**
 * The Lightning node's fenced view of BeignetNode's database (issue #958).
 *
 * BeignetNode hands the node a view of the SqliteStorage it shares with the
 * on-chain wallet. The node's destroy() closes the view, which fences it and
 * leaves the database open for the wallet; from then on every call through
 * the view fails the way a call on the closed database did.
 */

import { expect } from 'chai';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import Database from 'better-sqlite3';
import { BeignetNode } from '../../src/cli/beignet-node';
import { nodeStorageView } from '../../src/cli/node-storage-view';
import { decodeUpdateAddHtlcMessage } from '../../src/lightning/message/channel-update';
import { MessageType } from '../../src/lightning/message/types';
import {
	RecoveryCriticality,
	RecoveryManager
} from '../../src/lightning/recovery';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	exchangeCommitments,
	findSendAction,
	setupNormalChannels
} from '../lightning/helpers/revoked-commitment-fixture';

const CLOSED = 'The database connection is not open';

describe('nodeStorageView (issue #958)', () => {
	let tmpDir: string;
	let storage: SqliteStorage;

	const isOpen = (s: SqliteStorage): boolean =>
		(s as unknown as { db: { open: boolean } }).db.open;

	beforeEach(() => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-node-view-'));
		// Encrypted, so a call through the view has to reach the instance's
		// private key as well as its handle.
		storage = new SqliteStorage(path.join(tmpDir, 'view.db'), undefined, {
			encryptionKey: Buffer.alloc(32, 7)
		});
		storage.open();
	});

	afterEach(() => {
		try {
			storage.close();
		} catch {
			// already closed
		}
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it('passes calls through to the database before the fence', () => {
		const view = nodeStorageView(storage);
		view.saveMetadata('through-view', '1');
		expect(storage.loadMetadata('through-view')).to.equal('1');
		storage.saveWalletData('through-instance', '"secret"');
		expect(view.loadWalletData('through-instance')).to.equal('"secret"');
		expect(view.secretsEncryptedAtRest()).to.equal(true);

		// A transaction opened through the view is the database's own.
		expect(() =>
			view.transaction(() => {
				view.saveMetadata('rolled-back', '1');
				throw new Error('abort');
			})
		).to.throw('abort');
		expect(storage.loadMetadata('rolled-back')).to.equal(null);

		// Fields read and write through.
		expect(view.forwardingEventsMaxRows).to.equal(100_000);
		view.forwardingEventsMaxRows = 5;
		expect(storage.forwardingEventsMaxRows).to.equal(5);
	});

	it('is still a SqliteStorage, and a method read twice is one function', () => {
		const view = nodeStorageView(storage);
		expect(view).to.be.instanceOf(SqliteStorage);
		expect(view.constructor).to.equal(SqliteStorage);
		expect(view.saveMetadata).to.equal(view.saveMetadata);
	});

	it('close() fences the view and leaves the database open', () => {
		const view = nodeStorageView(storage);
		view.close();
		expect(isOpen(storage)).to.equal(true);
		storage.saveMetadata('owner-still-writes', '1');
		expect(storage.loadMetadata('owner-still-writes')).to.equal('1');
	});

	it('after the fence every call throws what a closed database throws, including a method read before it', async () => {
		// What the node's subsystems saw when its destroy() closed the
		// database itself.
		const closed = new SqliteStorage(path.join(tmpDir, 'closed.db'));
		closed.open();
		closed.close();
		expect(() => closed.saveMetadata('k', 'v')).to.throw(TypeError, CLOSED);

		const view = nodeStorageView(storage);
		const kept = view.saveMetadata;
		view.close();
		expect(() => view.saveMetadata('late', '1')).to.throw(TypeError, CLOSED);
		expect(() => view.loadMetadata('late')).to.throw(TypeError, CLOSED);
		expect(() => view.transaction(() => undefined)).to.throw(TypeError, CLOSED);
		expect(() => kept('kept', '1')).to.throw(TypeError, CLOSED);
		// The async method rejects rather than throwing, as on a closed
		// database.
		const backup = view.backup(path.join(tmpDir, 'backup.db'));
		let rejection: unknown;
		await backup.catch((error: unknown) => {
			rejection = error;
		});
		expect(rejection).to.be.instanceOf(TypeError);
		expect((rejection as Error).message).to.equal(CLOSED);

		expect(storage.loadMetadata('late')).to.equal(null);
		expect(storage.loadMetadata('kept')).to.equal(null);
		expect(isOpen(storage)).to.equal(true);
	});

	it('a second close() is a no-op', () => {
		const view = nodeStorageView(storage);
		view.close();
		expect(() => view.close()).to.not.throw();
		expect(isOpen(storage)).to.equal(true);
		expect(() => view.saveMetadata('k', 'v')).to.throw(TypeError, CLOSED);
	});

	it('names the instance as the store HTLC snapshots are saved to', () => {
		expect(nodeStorageView(storage).revokedHtlcSnapshotStore()).to.equal(
			storage
		);
	});
});

describe('HTLC snapshots saved by a BeignetNode (issue #1777)', function () {
	this.timeout(60_000);

	it('each channel save writes only the snapshot it adds', async () => {
		const dataDir = fs.mkdtempSync(
			path.join(os.tmpdir(), 'beignet-node-view-htlc-')
		);
		const node = await BeignetNode.create({
			network: 'regtest',
			dataDir,
			logLevel: 'silent',
			autoGossipSync: false,
			rapidGossipSync: false,
			electrumHost: '127.0.0.1',
			electrumPort: 65529,
			electrumTls: false
		});
		try {
			const recovery = (
				node.getNode() as unknown as { recovery: RecoveryManager }
			).recovery;
			const db = (node as unknown as { storage: { db: Database.Database } })
				.storage.db;
			db.exec(`
				CREATE TEMP TABLE snapshot_writes (n INTEGER);
				CREATE TEMP TRIGGER count_snapshot_writes
					AFTER INSERT ON main.revoked_htlc_snapshots
					BEGIN INSERT INTO snapshot_writes VALUES (1); END;
			`);
			const writes = (): number =>
				(
					db.prepare('SELECT COUNT(*) AS n FROM snapshot_writes').get() as {
						n: number;
					}
				).n;

			const { opener, acceptor } = setupNormalChannels();
			const channelId = opener.getChannelId()!.toString('hex');
			const add = findSendAction(
				opener.addHtlc(
					10_000_000n,
					crypto.randomBytes(32),
					500,
					Buffer.alloc(1366)
				),
				MessageType.UPDATE_ADD_HTLC
			);
			acceptor.handleUpdateAddHtlc(decodeUpdateAddHtlcMessage(add.payload));
			const save = (): void => {
				const result = recovery.commit({
					criticality: RecoveryCriticality.SafetyCritical,
					mutations: [
						{
							type: 'channel_state',
							channelId,
							state: opener.getFullState(),
							peerPubkey: '02'.padEnd(66, '1')
						}
					],
					outboundMessages: []
				});
				expect(result.committed).to.equal(true);
			};
			save();
			for (let i = 0; i < 5; i++) {
				exchangeCommitments(opener, acceptor);
				const before = writes();
				save();
				expect(writes() - before).to.equal(1);
			}
		} finally {
			await node.destroy();
			fs.rmSync(dataDir, { recursive: true, force: true });
		}
	});
});
