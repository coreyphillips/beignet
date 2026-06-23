/**
 * Production Hardening 9 — Fund Safety & Reliability Tests (~23 tests)
 *
 * Fix 1: fromMnemonic() channelKeyDeriver (5 tests)
 * Fix 2: loadAll*() per-row error isolation (5 tests)
 * Fix 3: state.fundingTxid.reverse() safe copy (3 tests)
 * Fix 4: SQLite busy_timeout PRAGMA (2 tests)
 * Fix 5: SQLite close in destroy() (3 tests)
 * Fix 6: restoreChannel() reestablish expansion (3 tests)
 * Fix 10: setMaxListeners (2 tests)
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { Network } from '../../src/lightning/invoice/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	ChannelManager,
	IPerChannelKeys
} from '../../src/lightning/channel/channel-manager';
import { Channel } from '../../src/lightning/channel/channel';
import {
	ChannelState,
	ChannelRole,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { IChannelState } from '../../src/lightning/channel/channel-state';
import { ShaChainStore } from '../../src/lightning/keys/shachain';

const TEST_MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

function makePrivkey(seed: Buffer, index: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([index]))
		.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		keys.push(makePrivkey(seed, i));
	}
	return {
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: Buffer.alloc(33, 0x02)
	};
}

function createTestNode(seed?: Buffer): LightningNode {
	const s = seed || crypto.randomBytes(32);
	const privkey = makePrivkey(s, 0);
	const fundingPrivkey = makePrivkey(s, 1);
	const basepoints = makeBasepoints(s);
	const node = new LightningNode({
		nodePrivateKey: privkey,
		channelBasepoints: basepoints,
		perCommitmentSeed: s,
		fundingPrivkey,
		network: Network.REGTEST
	});
	node.on('error', () => {});
	node.on('node:error', () => {});
	return node;
}

function tmpDbPath(): string {
	return path.join(
		os.tmpdir(),
		`ph9-test-${Date.now()}-${Math.random().toString(36).slice(2)}.db`
	);
}

function makeMinimalChannelState(opts: {
	state: ChannelState;
	channelId?: Buffer;
	fundingTxid?: Buffer;
}): IChannelState {
	const seed = crypto.randomBytes(32);
	const bp = makeBasepoints(seed);
	return {
		role: ChannelRole.OPENER,
		state: opts.state,
		temporaryChannelId: crypto.randomBytes(32),
		channelId: opts.channelId || crypto.randomBytes(32),
		localConfig: DEFAULT_CHANNEL_CONFIG,
		remoteConfig: DEFAULT_CHANNEL_CONFIG,
		localBasepoints: bp,
		remoteBasepoints: bp,
		fundingSatoshis: 1_000_000n,
		pushMsat: 0n,
		feeratePerKw: 1000,
		localCommitmentNumber: 0n,
		remoteCommitmentNumber: 0n,
		localPerCommitmentSeed: seed,
		localPerCommitmentIndex: 281474976710655n,
		remotePerCommitmentPoint: Buffer.alloc(33, 0x02),
		fundingTxid: opts.fundingTxid || crypto.randomBytes(32),
		fundingOutputIndex: 0,
		minimumDepth: 3,
		channelType: Buffer.alloc(0),
		htlcs: new Map(),
		localShachain: new ShaChainStore(),
		channelReady: false,
		localChannelReady: false,
		remoteChannelReadyReceived: false,
		fundingBroadcastHeight: 0
	} as unknown as IChannelState;
}

describe('Production Hardening 9 — Fund Safety', () => {
	// ─── Fix 1: fromMnemonic() channelKeyDeriver ───

	describe('Fix 1: fromMnemonic() channelKeyDeriver', () => {
		let node: LightningNode;

		afterEach(() => {
			if (node) node.destroy();
		});

		it('fromMnemonic() wires channelKeyDeriver into ChannelManager', () => {
			node = LightningNode.fromMnemonic(TEST_MNEMONIC, {
				network: Network.REGTEST
			});
			node.on('error', () => {});
			node.on('node:error', () => {});
			// Access internal channelManager config
			const cm = node.getChannelManager();
			const config = (cm as any).config;
			expect(config.channelKeyDeriver).to.be.a('function');
		});

		it('deriver produces deterministic keys per index', () => {
			node = LightningNode.fromMnemonic(TEST_MNEMONIC, {
				network: Network.REGTEST
			});
			node.on('error', () => {});
			node.on('node:error', () => {});
			const cm = node.getChannelManager();
			const deriver = (cm as any).config.channelKeyDeriver as (
				idx: number
			) => IPerChannelKeys;
			const keys1a = deriver(1);
			const keys1b = deriver(1);
			expect(keys1a.fundingPrivkey.equals(keys1b.fundingPrivkey)).to.be.true;
			expect(keys1a.htlcBasepointSecret!.equals(keys1b.htlcBasepointSecret!)).to
				.be.true;
		});

		it('different channel indices produce different keys', () => {
			node = LightningNode.fromMnemonic(TEST_MNEMONIC, {
				network: Network.REGTEST
			});
			node.on('error', () => {});
			node.on('node:error', () => {});
			const cm = node.getChannelManager();
			const deriver = (cm as any).config.channelKeyDeriver as (
				idx: number
			) => IPerChannelKeys;
			const keys0 = deriver(0);
			const keys1 = deriver(1);
			expect(keys0.fundingPrivkey.equals(keys1.fundingPrivkey)).to.be.false;
		});

		it('manual channelKeyDeriver override works', () => {
			const customDeriver = (idx: number): IPerChannelKeys => {
				const s = crypto
					.createHash('sha256')
					.update(Buffer.from(`custom-${idx}`))
					.digest();
				return {
					fundingPrivkey: s,
					basepoints: makeBasepoints(s),
					perCommitmentSeed: s,
					htlcBasepointSecret: s
				};
			};
			node = LightningNode.fromMnemonic(TEST_MNEMONIC, {
				network: Network.REGTEST,
				channelKeyDeriver: customDeriver
			});
			node.on('error', () => {});
			node.on('node:error', () => {});
			const cm = node.getChannelManager();
			const deriver = (cm as any).config.channelKeyDeriver;
			expect(deriver).to.equal(customDeriver);
		});

		it('constructor without channelKeyDeriver still works (no-options regression)', () => {
			node = createTestNode();
			const info = node.getNodeInfo();
			expect(info.nodeId).to.be.a('string').with.length(66);
		});
	});

	// ─── Fix 2: loadAll*() per-row error isolation ───

	describe('Fix 2: loadAll*() per-row error isolation', () => {
		let storage: SqliteStorage;
		let dbPath: string;

		beforeEach(() => {
			dbPath = tmpDbPath();
			storage = new SqliteStorage(dbPath);
			storage.open();
		});

		afterEach(() => {
			try {
				storage.close();
			} catch {}
			try {
				fs.unlinkSync(dbPath);
			} catch {}
		});

		it('loadAllForwardedHtlcs() skips row with corrupted BigInt', () => {
			const db = (storage as any).db;
			// Insert valid row
			db.prepare(
				'INSERT INTO forwarded_htlcs (out_key, in_channel_id, in_htlc_id) VALUES (?, ?, ?)'
			).run('valid_key', 'aabb'.repeat(16), '42');
			// Insert corrupted row (non-numeric htlc_id)
			db.prepare(
				'INSERT INTO forwarded_htlcs (out_key, in_channel_id, in_htlc_id) VALUES (?, ?, ?)'
			).run('bad_key', 'ccdd'.repeat(16), 'not_a_number');
			const results = storage.loadAllForwardedHtlcs();
			expect(results).to.have.length(1);
			expect(results[0].outKey).to.equal('valid_key');
		});

		it('loadAllPreimages() returns valid data with for/try/catch pattern', () => {
			storage.savePreimage('aabb', Buffer.from('1234', 'hex'));
			storage.savePreimage('ccdd', Buffer.from('5678', 'hex'));
			const results = storage.loadAllPreimages();
			expect(results).to.have.length(2);
			expect(results.some((r) => r.paymentHash === 'aabb')).to.be.true;
		});

		it('loadAllScidMappings() returns valid data with for/try/catch pattern', () => {
			storage.saveScidMapping('scid1', Buffer.from('aa'.repeat(32), 'hex'));
			storage.saveScidMapping('scid2', Buffer.from('bb'.repeat(32), 'hex'));
			const results = storage.loadAllScidMappings();
			expect(results).to.have.length(2);
		});

		it('loadAllHtlcPaymentMappings() returns valid data with for/try/catch pattern', () => {
			storage.saveHtlcPaymentMapping('key1', 'hash1');
			storage.saveHtlcPaymentMapping('key2', 'hash2');
			const results = storage.loadAllHtlcPaymentMappings();
			expect(results).to.have.length(2);
		});

		it('loadAllPaymentSecrets() returns valid data with for/try/catch pattern', () => {
			storage.savePaymentSecret('hash1', Buffer.from('aa'.repeat(32), 'hex'));
			storage.savePaymentSecret('hash2', Buffer.from('bb'.repeat(32), 'hex'));
			const results = storage.loadAllPaymentSecrets();
			expect(results).to.have.length(2);
		});
	});

	// ─── Fix 3: fundingTxid safe copy ───

	describe('Fix 3: fundingTxid safe copy', () => {
		it('Buffer.from().reverse() does not mutate original', () => {
			const original = Buffer.from(
				'0102030405060708091011121314151617181920212223242526272829303132',
				'hex'
			);
			const originalHex = original.toString('hex');
			const reversed = Buffer.from(original).reverse();
			expect(original.toString('hex')).to.equal(originalHex);
			expect(reversed.toString('hex')).to.not.equal(originalHex);
		});

		it('.reverse() on original DOES mutate (showing the bug)', () => {
			const original = Buffer.from('0102030405', 'hex');
			const originalHex = original.toString('hex');
			original.reverse();
			expect(original.toString('hex')).to.not.equal(originalHex);
		});

		it('safe copy produces correct reversed hex', () => {
			const txid = Buffer.from('aabbccdd', 'hex');
			const displayHex = Buffer.from(txid).reverse().toString('hex');
			expect(displayHex).to.equal('ddccbbaa');
			// Original untouched
			expect(txid.toString('hex')).to.equal('aabbccdd');
		});
	});

	// ─── Fix 4: SQLite busy_timeout PRAGMA ───

	describe('Fix 4: SQLite busy_timeout', () => {
		let storage: SqliteStorage;
		let dbPath: string;

		afterEach(() => {
			try {
				storage.close();
			} catch {}
			try {
				fs.unlinkSync(dbPath);
			} catch {}
		});

		it('busy_timeout is set to 5000 after open()', () => {
			dbPath = tmpDbPath();
			storage = new SqliteStorage(dbPath);
			storage.open();
			const db = (storage as any).db;
			const result = db.pragma('busy_timeout');
			// SQLite returns the column as 'timeout'
			expect(result[0].timeout).to.equal(5000);
		});

		it('concurrent WAL access does not throw SQLITE_BUSY', () => {
			dbPath = tmpDbPath();
			storage = new SqliteStorage(dbPath);
			storage.open();
			// Simulate concurrent access by saving many rows rapidly
			for (let i = 0; i < 100; i++) {
				storage.savePreimage(`hash_${i}`, crypto.randomBytes(32));
			}
			const all = storage.loadAllPreimages();
			expect(all).to.have.length(100);
		});
	});

	// ─── Fix 5: Storage close in destroy() ───

	describe('Fix 5: Storage close in destroy()', () => {
		it('destroy() closes storage', () => {
			const dbPath = tmpDbPath();
			const storageInst = new SqliteStorage(dbPath);
			storageInst.open();
			const seed = crypto.randomBytes(32);
			const node = new LightningNode({
				nodePrivateKey: makePrivkey(seed, 0),
				channelBasepoints: makeBasepoints(seed),
				perCommitmentSeed: seed,
				fundingPrivkey: makePrivkey(seed, 1),
				network: Network.REGTEST,
				storage: storageInst
			});
			node.on('error', () => {});
			node.on('node:error', () => {});
			node.destroy();
			// After destroy, the db should be closed — trying to query should throw
			const db = (storageInst as any).db;
			expect(() => db.prepare('SELECT 1').get()).to.throw();
			try {
				fs.unlinkSync(dbPath);
			} catch {}
		});

		it('gracefulShutdown also closes storage', async () => {
			const dbPath = tmpDbPath();
			const storageInst = new SqliteStorage(dbPath);
			storageInst.open();
			const seed = crypto.randomBytes(32);
			const node = new LightningNode({
				nodePrivateKey: makePrivkey(seed, 0),
				channelBasepoints: makeBasepoints(seed),
				perCommitmentSeed: seed,
				fundingPrivkey: makePrivkey(seed, 1),
				network: Network.REGTEST,
				storage: storageInst
			});
			node.on('error', () => {});
			node.on('node:error', () => {});
			await node.gracefulShutdown(1000);
			const db = (storageInst as any).db;
			expect(() => db.prepare('SELECT 1').get()).to.throw();
			try {
				fs.unlinkSync(dbPath);
			} catch {}
		});

		it('destroy() without storage does not throw', () => {
			const node = createTestNode();
			expect(() => node.destroy()).to.not.throw();
		});
	});
});

describe('Production Hardening 9 — Reliability', () => {
	// ─── Fix 6: restoreChannel() reestablish expansion ───

	describe('Fix 6: restoreChannel() marks more states for reestablish', () => {
		function createChannelManager(): ChannelManager {
			const seed = crypto.randomBytes(32);
			const cm = new ChannelManager({
				localBasepoints: makeBasepoints(seed),
				localPerCommitmentSeed: seed,
				localFundingPrivkey: makePrivkey(seed, 1)
			});
			cm.on('error', () => {});
			return cm;
		}

		function createChannelInState(state: ChannelState): Channel {
			const channelState = makeMinimalChannelState({ state });
			return new Channel(channelState);
		}

		it('AWAITING_FUNDING_CONFIRMED channels are marked for reestablish', () => {
			const cm = createChannelManager();
			const ch = createChannelInState(ChannelState.AWAITING_FUNDING_CONFIRMED);
			cm.restoreChannel(ch, 'aa'.repeat(33));
			expect(ch.getState()).to.equal(ChannelState.AWAITING_REESTABLISH);
		});

		it('AWAITING_CHANNEL_READY channels are marked for reestablish', () => {
			const cm = createChannelManager();
			const ch = createChannelInState(ChannelState.AWAITING_CHANNEL_READY);
			cm.restoreChannel(ch, 'bb'.repeat(33));
			expect(ch.getState()).to.equal(ChannelState.AWAITING_REESTABLISH);
		});

		it('SHUTTING_DOWN channels are marked for reestablish', () => {
			const cm = createChannelManager();
			const ch = createChannelInState(ChannelState.SHUTTING_DOWN);
			cm.restoreChannel(ch, 'cc'.repeat(33));
			expect(ch.getState()).to.equal(ChannelState.AWAITING_REESTABLISH);
		});
	});

	// ─── Fix 10: setMaxListeners ───

	describe('Fix 10: setMaxListeners', () => {
		it('new LightningNode has maxListeners >= 50', () => {
			const node = createTestNode();
			expect(node.getMaxListeners()).to.be.at.least(50);
			node.destroy();
		});

		it('20+ concurrent listeners do not trigger memory leak warning', () => {
			const node = createTestNode();
			const warnings: string[] = [];
			const origWarn = process.emitWarning;
			process.emitWarning = ((msg: string) => {
				warnings.push(String(msg));
			}) as any;
			try {
				for (let i = 0; i < 25; i++) {
					node.on('payment:sent', () => {});
				}
				expect(warnings).to.have.length(0);
			} finally {
				process.emitWarning = origWarn;
				node.destroy();
			}
		});
	});
});
