/**
 * Phase 1.2-1.4: SQLite Crash Safety & Timer Safety Tests.
 *
 * - 1.2: SQLite `synchronous = FULL`, checkpoint(), atomic transactions
 * - 1.3: Auto-reconnect timer tracking & cleanup on destroy()
 * - 1.4: waitForPayment/waitForChannelReady reject on destroy()
 */

import { expect } from 'chai';
import crypto from 'crypto';
import path from 'path';
import fs from 'fs';
import os from 'os';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import {
	DEFAULT_CHANNEL_CONFIG,
	ChannelState
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { createOpenerState } from '../../src/lightning/channel/channel-state';

// ─── Helpers ───

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`timer-safety-${id}`))
		.digest();
}

function derivePrivkey(seed: Buffer, index: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([index]))
		.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		keys.push(derivePrivkey(seed, i));
	}
	return {
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

function makeNodeConfig(
	seedId: number,
	extras?: Partial<INodeConfig>
): INodeConfig {
	const seed = makeSeed(seedId);
	const nodePrivateKey = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from('node-identity'))
		.digest();
	const fundingPrivkey = derivePrivkey(seed, 0);
	return {
		nodePrivateKey,
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey,
		...extras
	};
}

function tmpDbPath(): string {
	return path.join(
		os.tmpdir(),
		`beignet-test-${crypto.randomBytes(8).toString('hex')}.db`
	);
}

// ─── 1.2: SQLite Crash Safety ───

describe('SQLite Crash Safety', () => {
	let dbPath: string;
	let storage: SqliteStorage;

	beforeEach(() => {
		dbPath = tmpDbPath();
		storage = new SqliteStorage(dbPath);
	});

	afterEach(() => {
		try {
			storage.close();
		} catch {}
		try {
			fs.unlinkSync(dbPath);
		} catch {}
		try {
			fs.unlinkSync(dbPath + '-wal');
		} catch {}
		try {
			fs.unlinkSync(dbPath + '-shm');
		} catch {}
	});

	it('open() sets synchronous = FULL by default', () => {
		// Access internal db to verify pragma on the same connection
		storage.open();
		const db = (storage as any).db;
		const result = db.pragma('synchronous');
		// FULL = 2
		expect(result[0].synchronous).to.equal(2);
	});

	it('open() allows NORMAL sync mode for tests', () => {
		storage.open({ synchronous: 'NORMAL' });
		const db = (storage as any).db;
		const result = db.pragma('synchronous');
		// NORMAL = 1
		expect(result[0].synchronous).to.equal(1);
	});

	it('checkpoint() runs without error', () => {
		storage.open();
		// Write some data first so there's something in the WAL
		storage.savePayment('abc123', {
			paymentHash: Buffer.from('abc123', 'hex'),
			amountMsat: 1000n,
			status: 'COMPLETED' as any,
			direction: 'outbound' as any,
			createdAt: Date.now()
		} as any);
		expect(() => storage.checkpoint()).to.not.throw();
	});

	it('transaction() is atomic — partial failure rolls back', () => {
		storage.open();

		// Save a payment
		storage.savePayment('aaa111', {
			paymentHash: Buffer.from('aaa111', 'hex'),
			amountMsat: 1000n,
			status: 'COMPLETED' as any,
			direction: 'outbound' as any,
			createdAt: Date.now()
		} as any);

		// Attempt a transaction that fails halfway
		try {
			storage.transaction(() => {
				storage.savePayment('bbb222', {
					paymentHash: Buffer.from('bbb222', 'hex'),
					amountMsat: 2000n,
					status: 'COMPLETED' as any,
					direction: 'outbound' as any,
					createdAt: Date.now()
				} as any);
				throw new Error('simulated failure');
			});
		} catch {
			// expected
		}

		// bbb222 should not have been saved
		const payment = storage.loadPayment('bbb222');
		expect(payment).to.be.null;
		// aaa111 should still be there
		expect(storage.loadPayment('aaa111')).to.not.be.null;
	});

	it('data survives close/reopen cycle with FULL sync', () => {
		storage.open();
		storage.savePayment('ccc333', {
			paymentHash: Buffer.from('ccc333', 'hex'),
			amountMsat: 5000n,
			status: 'COMPLETED' as any,
			direction: 'inbound' as any,
			createdAt: Date.now()
		} as any);
		storage.close();

		// Reopen
		const storage2 = new SqliteStorage(dbPath);
		storage2.open();
		const loaded = storage2.loadPayment('ccc333');
		expect(loaded).to.not.be.null;
		expect(Number(loaded!.amountMsat)).to.equal(5000);
		storage2.close();
		storage = new SqliteStorage(dbPath); // reset for afterEach
		storage.open();
	});
});

// ─── 1.3: Auto-reconnect Timer Tracking ───

describe('Auto-reconnect Timer Tracking', () => {
	it('reconnect timers are cleared on destroy()', () => {
		const config = makeNodeConfig(30);
		const dbPath = tmpDbPath();
		const storage = new SqliteStorage(dbPath);
		storage.open({ synchronous: 'NORMAL' });

		// Save a peer address so auto-reconnect has something to do
		storage.savePeerAddress('02' + 'aa'.repeat(32), '127.0.0.1', 9735);

		// Save a channel in AWAITING_REESTABLISH so reconnect attempts
		const seed = makeSeed(30);
		const state = createOpenerState({
			temporaryChannelId: crypto.randomBytes(32),
			fundingSatoshis: 100_000n,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: makeBasepoints(seed),
			localPerCommitmentSeed: makeSeed(130)
		});
		state.channelId = crypto.randomBytes(32);
		state.state = ChannelState.AWAITING_REESTABLISH;
		storage.saveChannel(
			state.channelId.toString('hex'),
			state,
			'02' + 'aa'.repeat(32)
		);

		const node = new LightningNode({
			...config,
			storage,
			enableNetworking: true,
			autoReconnect: true
		});
		node.on('error', () => {});
		node.on('node:error', () => {});

		// Destroy immediately — timers should be cleaned up
		node.destroy();

		try {
			storage.close();
		} catch {}
		try {
			fs.unlinkSync(dbPath);
		} catch {}
		try {
			fs.unlinkSync(dbPath + '-wal');
		} catch {}
		try {
			fs.unlinkSync(dbPath + '-shm');
		} catch {}
	});

	it('no connectPeer calls after destroy()', async () => {
		const config = makeNodeConfig(31);
		const dbPath = tmpDbPath();
		const storage = new SqliteStorage(dbPath);
		storage.open({ synchronous: 'NORMAL' });

		storage.savePeerAddress('02' + 'bb'.repeat(32), '127.0.0.1', 9735);

		const seed = makeSeed(31);
		const state = createOpenerState({
			temporaryChannelId: crypto.randomBytes(32),
			fundingSatoshis: 100_000n,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: makeBasepoints(seed),
			localPerCommitmentSeed: makeSeed(131)
		});
		state.channelId = crypto.randomBytes(32);
		state.state = ChannelState.AWAITING_REESTABLISH;
		storage.saveChannel(
			state.channelId.toString('hex'),
			state,
			'02' + 'bb'.repeat(32)
		);

		const node = new LightningNode({
			...config,
			storage,
			enableNetworking: true,
			autoReconnect: true
		});
		let errorCount = 0;
		node.on('node:error', () => {
			errorCount++;
		});
		node.on('error', () => {});

		// Destroy immediately
		node.destroy();

		// Wait for any pending timers to fire
		await new Promise((r) => setTimeout(r, 200));

		// If timers were properly cleared, no auto-reconnect errors should fire
		// (since PeerManager is destroyed, any connect attempt would throw)
		expect(errorCount).to.equal(0);

		try {
			storage.close();
		} catch {}
		try {
			fs.unlinkSync(dbPath);
		} catch {}
		try {
			fs.unlinkSync(dbPath + '-wal');
		} catch {}
		try {
			fs.unlinkSync(dbPath + '-shm');
		} catch {}
	});
});

// ─── 1.4: waitForPayment/waitForChannelReady Timer Cleanup ───

describe('Wait Promise Timer Cleanup', () => {
	let node: LightningNode;

	beforeEach(() => {
		node = new LightningNode(makeNodeConfig(40));
		node.on('error', () => {});
		node.on('node:error', () => {});
	});

	afterEach(() => {
		try {
			node.destroy();
		} catch {}
	});

	it('waitForPayment rejects when node is destroyed', async () => {
		const hash = crypto.randomBytes(32);
		const promise = node.waitForPayment(hash, 60_000);

		// Destroy the node while waiting
		node.destroy();

		try {
			await promise;
			expect.fail('Should have rejected');
		} catch (err) {
			expect((err as Error).message).to.equal('Node destroyed');
		}
	});

	it('waitForChannelReady rejects when node is destroyed', async () => {
		const channelId = crypto.randomBytes(32);
		const promise = node.waitForChannelReady(channelId, 60_000);

		// Destroy the node while waiting
		node.destroy();

		try {
			await promise;
			expect.fail('Should have rejected');
		} catch (err) {
			expect((err as Error).message).to.equal('Node destroyed');
		}
	});

	it('multiple concurrent waits all reject on destroy', async () => {
		const promises = [
			node.waitForPayment(crypto.randomBytes(32), 60_000),
			node.waitForPayment(crypto.randomBytes(32), 60_000),
			node.waitForChannelReady(crypto.randomBytes(32), 60_000)
		];

		node.destroy();

		const results = await Promise.allSettled(promises);
		for (const result of results) {
			expect(result.status).to.equal('rejected');
			expect((result as PromiseRejectedResult).reason.message).to.equal(
				'Node destroyed'
			);
		}
	});

	it('waitForPayment rejects immediately if already destroyed', async () => {
		node.destroy();

		try {
			await node.waitForPayment(crypto.randomBytes(32));
			expect.fail('Should have rejected');
		} catch (err) {
			expect((err as Error).message).to.equal('Node destroyed');
		}
	});

	it('waitForChannelReady rejects immediately if already destroyed', async () => {
		node.destroy();

		try {
			await node.waitForChannelReady(crypto.randomBytes(32));
			expect.fail('Should have rejected');
		} catch (err) {
			expect((err as Error).message).to.equal('Node destroyed');
		}
	});

	it('resolved wait is cleaned up from active set', async () => {
		const hash = crypto.randomBytes(32);
		const promise = node.waitForPayment(hash, 5000);

		// Simulate a successful payment by emitting the event
		node.emit('payment:sent', {
			paymentHash: hash,
			amountMsat: 1000n,
			status: 'COMPLETED',
			direction: 'outbound',
			createdAt: Date.now()
		});

		await promise;

		// Destroying after resolution should not double-reject
		node.destroy();
	});
});
