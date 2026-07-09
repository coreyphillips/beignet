/**
 * Static channel backup (SCB) RESTORE tests.
 *
 * Covers the recovery-state classification rule (dataLossDetected + no remote
 * basepoints => any non-coop funding spend is the peer's commitment),
 * LightningNode.recoverFromStaticChannelBackup end-to-end against a fake
 * chain backend (channel reconstruction, funding watch, to_remote-only sweep
 * on the peer's force-close, duplicate skipping), the BeignetNode network /
 * seed checks, and the offline CLI db-restore helpers.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as bip39 from 'bip39';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { perCommitmentPointFromSecret } from '../../src/lightning/keys/derivation';
import { buildRemoteCommitment } from '../../src/lightning/channel/commitment-builder';
import { classifyCommitmentTx } from '../../src/lightning/chain/output-resolver';
import {
	CommitmentType,
	ChainActionType,
	OutputType
} from '../../src/lightning/chain/types';
import {
	IChainBackend,
	computeScriptHash
} from '../../src/lightning/chain/chain-watcher';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	encodeScb,
	IStaticChannelBackup
} from '../../src/lightning/backup/scb';
import { BeignetNode } from '../../src/cli/beignet-node';
import {
	SQLITE_HEADER,
	isSqliteFile,
	preRestoreBackupPath,
	restoreDbFile,
	performDbRestore
} from '../../src/cli/restore';
import { InstanceLockError } from '../../src/cli/instance-lock';

bitcoin.initEccLib(ecc);

// ─────────────── Harness (mirrors tests/lightning/scb.test.ts) ───────────────

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`scb-restore-seed-${id}`))
		.digest();
}

function makePrivkeys(seed: Buffer): Buffer[] {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		keys.push(
			crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from([i]))
				.digest()
		);
	}
	return keys;
}

function makeBasepoints(privkeys: Buffer[]): IChannelBasepoints {
	return {
		fundingPubkey: getPublicKey(privkeys[0]),
		revocationBasepoint: getPublicKey(privkeys[1]),
		paymentBasepoint: getPublicKey(privkeys[2]),
		delayedPaymentBasepoint: getPublicKey(privkeys[3]),
		htlcBasepoint: getPublicKey(privkeys[4]),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

function makeNodeConfig(seedId: number): INodeConfig {
	const seed = makeSeed(seedId);
	const privkeys = makePrivkeys(seed);
	const nodePrivateKey = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from('node-identity'))
		.digest();
	return {
		nodePrivateKey,
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(privkeys),
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey: privkeys[0],
		revocationBasepointSecret: privkeys[1],
		paymentBasepointSecret: privkeys[2],
		delayedPaymentBasepointSecret: privkeys[3],
		htlcBasepointSecret: privkeys[4],
		// Non-anchor (static_remotekey) so the to_remote claim is an immediate
		// P2WPKH sweep, mirroring the dlp-fell-behind monitor test.
		preferAnchors: false
	};
}

function connectNodes(nodeA: LightningNode, nodeB: LightningNode): void {
	nodeA.on(
		'message:outbound',
		(pubkey: string, type: number, payload: Buffer) => {
			if (pubkey === nodeB.getNodeId()) {
				nodeB.handlePeerMessage(nodeA.getNodeId(), type, payload);
			}
		}
	);
	nodeB.on(
		'message:outbound',
		(pubkey: string, type: number, payload: Buffer) => {
			if (pubkey === nodeA.getNodeId()) {
				nodeA.handlePeerMessage(nodeB.getNodeId(), type, payload);
			}
		}
	);
}

function openReadyChannel(
	alice: LightningNode,
	bob: LightningNode,
	fundingSatoshis = 1_000_000n
): { channelId: Buffer; fundingTxid: Buffer } {
	const channel = alice.openChannel(bob.getNodeId(), fundingSatoshis);
	const fundingTxid = crypto.randomBytes(32);
	const channelId = alice.createFunding(
		channel,
		fundingTxid,
		0,
		crypto.randomBytes(64)
	)!;
	alice.handleFundingConfirmed(channelId);
	bob.handleFundingConfirmed(channelId);
	return { channelId, fundingTxid };
}

/** A valid but unknown-to-us per-commitment point. */
function makeForeignPoint(tag: string): Buffer {
	return perCommitmentPointFromSecret(
		crypto.createHash('sha256').update(Buffer.from(tag)).digest()
	);
}

/**
 * Fake Electrum-style chain backend: the funding tx is "confirmed" at height
 * 100 and the current tip (delivered via the headers subscription) is 200.
 */
class FakeChainBackend implements IChainBackend {
	transactions = new Map<string, Buffer>(); // display txid -> raw tx
	history = new Map<string, Array<{ txid: string; height: number }>>();
	subscribedScriptHashes: string[] = [];
	broadcasts: string[] = [];
	getTransactionCalls: string[] = [];

	async subscribeToHeaders(
		onNewBlock: (height: number) => void
	): Promise<void> {
		onNewBlock(200);
	}

	async subscribeToScriptHash(scriptHash: string): Promise<void> {
		this.subscribedScriptHashes.push(scriptHash);
	}

	async getScriptHashHistory(
		scriptHash: string
	): Promise<Array<{ txid: string; height: number }>> {
		return this.history.get(scriptHash) ?? [];
	}

	async getTransaction(txid: string): Promise<Buffer> {
		this.getTransactionCalls.push(txid);
		const raw = this.transactions.get(txid);
		if (!raw) throw new Error(`Unknown tx ${txid}`);
		return raw;
	}

	async broadcastTransaction(rawTxHex: string): Promise<string> {
		this.broadcasts.push(rawTxHex);
		return bitcoin.Transaction.fromHex(rawTxHex).getId();
	}
}

describe('SCB restore', function () {
	// ───────── classifyCommitmentTx on a recovery state ─────────

	describe('classifyCommitmentTx - recovery state (no remoteBasepoints)', function () {
		function buildChannelAndCommitment(): {
			state: import('../../src/lightning/channel/channel-state').IChannelState;
			commitmentTx: bitcoin.Transaction;
		} {
			const alice = new LightningNode(makeNodeConfig(1));
			const bob = new LightningNode(makeNodeConfig(2));
			alice.on('node:error', () => {});
			bob.on('node:error', () => {});
			connectNodes(alice, bob);
			try {
				const { channelId } = openReadyChannel(alice, bob);
				const state = alice
					.getChannelManager()
					.getChannel(channelId)!
					.getFullState();
				// The peer's commitment at an index far beyond our recorded state.
				const built = buildRemoteCommitment(
					state,
					makeForeignPoint('recovery-classify-point'),
					5n
				);
				return { state, commitmentTx: built.result.tx };
			} finally {
				alice.destroy();
				bob.destroy();
			}
		}

		it('classifies any non-coop funding spend as THEIR_FUTURE_COMMITMENT when dataLossDetected is set', function () {
			const { state, commitmentTx } = buildChannelAndCommitment();
			state.remoteBasepoints = null;
			state.dataLossDetected = true;

			const result = classifyCommitmentTx(commitmentTx, state);
			expect(result.type).to.equal(CommitmentType.THEIR_FUTURE_COMMITMENT);
		});

		it('still classifies a cooperative close as COOPERATIVE_CLOSE', function () {
			const { state, commitmentTx } = buildChannelAndCommitment();
			state.remoteBasepoints = null;
			state.dataLossDetected = true;

			// A mutual close spends the funding output with locktime 0 and final
			// sequence - fabricate one on the same funding outpoint.
			const coopTx = new bitcoin.Transaction();
			coopTx.version = 2;
			coopTx.locktime = 0;
			coopTx.addInput(
				Buffer.from(commitmentTx.ins[0].hash),
				commitmentTx.ins[0].index,
				0xffffffff
			);
			coopTx.addOutput(Buffer.alloc(22), 900_000);

			const result = classifyCommitmentTx(coopTx, state);
			expect(result.type).to.equal(CommitmentType.COOPERATIVE_CLOSE);
		});

		it('stays UNKNOWN without dataLossDetected (no false sweeps on ordinary states)', function () {
			const { state, commitmentTx } = buildChannelAndCommitment();
			state.remoteBasepoints = null;

			const result = classifyCommitmentTx(commitmentTx, state);
			expect(result.type).to.equal(CommitmentType.UNKNOWN);
		});
	});

	// ───────── recoverFromStaticChannelBackup ─────────

	describe('LightningNode.recoverFromStaticChannelBackup', function () {
		it('reconstructs the channel, watches the funding, and sweeps only to_remote from the peer force-close', async function () {
			// 1. A real channel between alice and bob (loopback, no networking).
			const alice = new LightningNode(makeNodeConfig(1));
			const bob = new LightningNode(makeNodeConfig(2));
			alice.on('node:error', () => {});
			bob.on('node:error', () => {});
			connectNodes(alice, bob);

			let entries: import('../../src/lightning/backup/scb').IScbChannelEntry[];
			let channelId: Buffer;
			let commitmentTx: bitcoin.Transaction;
			try {
				const opened = openReadyChannel(alice, bob);
				channelId = opened.channelId;
				const originalState = alice
					.getChannelManager()
					.getChannel(channelId)!
					.getFullState();

				// 2. Export alice's SCB data, then fabricate the peer's (bob's)
				// future commitment spending the funding outpoint. Built from the
				// ORIGINAL state - the recovered node never has the material for it.
				entries = alice.buildStaticChannelBackupData().channels;
				expect(entries).to.have.length(1);
				commitmentTx = buildRemoteCommitment(
					originalState,
					makeForeignPoint('recovery-monitor-point'),
					4n
				).result.tx;
			} finally {
				alice.destroy();
				bob.destroy();
			}

			// 3. A FRESH node with the same seed/config and a fake chain backend.
			const backend = new FakeChainBackend();
			const fundingDisplayTxid = Buffer.from(entries[0].fundingTxid, 'hex')
				.reverse()
				.toString('hex');
			// Fabricated funding tx: only the watched output's script matters
			// (recovery takes it verbatim from the chain).
			const fundingTx = new bitcoin.Transaction();
			fundingTx.version = 2;
			fundingTx.addInput(crypto.randomBytes(32), 0);
			fundingTx.addOutput(
				bitcoin.payments.p2wsh({
					redeem: { output: bitcoin.script.compile([bitcoin.opcodes.OP_TRUE]) }
				}).output!,
				1_000_000
			);
			backend.transactions.set(fundingDisplayTxid, fundingTx.toBuffer());
			backend.transactions.set(commitmentTx.getId(), commitmentTx.toBuffer());
			const fundingScriptHash = computeScriptHash(fundingTx.outs[0].script);
			backend.history.set(fundingScriptHash, [
				{ txid: fundingDisplayTxid, height: 100 }
			]);

			const storage = new SqliteStorage(':memory:');
			storage.open();
			const restored = new LightningNode({
				...makeNodeConfig(1),
				storage,
				chainBackend: backend
			});
			restored.on('node:error', () => {});
			try {
				await restored.startChainWatcher();
				expect(restored.getChannelManager().getChannel(channelId)).to.equal(
					undefined
				);

				const result = await restored.recoverFromStaticChannelBackup(entries);
				expect(result.recovering).to.deep.equal([entries[0].channelId]);
				expect(result.skipped).to.deep.equal([]);

				// Channel reconstructed: broadcast-banned, ERRORED, no remote keys.
				const channel = restored.getChannelManager().getChannel(channelId);
				expect(channel).to.exist;
				const state = channel!.getFullState();
				expect(state.dataLossDetected).to.equal(true);
				expect(state.state).to.equal(ChannelState.ERRORED);
				expect(state.remoteBasepoints).to.equal(null);
				expect(state.fundingTxid!.toString('hex')).to.equal(
					entries[0].fundingTxid
				);
				expect(state.localCommitmentNumber).to.equal(0n);
				expect(state.remoteCommitmentNumber).to.equal(0n);

				// Persisted (survives a restart).
				const persisted = storage
					.loadAllChannels()
					.find((c) => c.channelId === entries[0].channelId);
				expect(persisted).to.exist;
				expect(persisted!.peerPubkey).to.equal(entries[0].peerNodeId);

				// Funding outpoint watched: the script was fetched from the chain
				// and its scripthash subscribed.
				expect(backend.getTransactionCalls).to.include(fundingDisplayTxid);
				expect(backend.subscribedScriptHashes).to.include(fundingScriptHash);

				// Duplicate restore is skipped with a reason.
				const again = await restored.recoverFromStaticChannelBackup(entries);
				expect(again.recovering).to.deep.equal([]);
				expect(again.skipped).to.have.length(1);
				expect(again.skipped[0].channelId).to.equal(entries[0].channelId);
				expect(again.skipped[0].reason).to.contain('already exists');

				// 4. The peer's commitment spends the funding outpoint: exactly one
				// to_remote sweep, nothing else (mirrors the dlp-fell-behind test).
				const destScript = bitcoin.payments.p2wpkh({
					pubkey: getPublicKey(makePrivkeys(makeSeed(1))[0]),
					network: bitcoin.networks.regtest
				}).output!;
				const actions = restored
					.getChannelManager()
					.handleFundingSpent(channelId, commitmentTx, 150, destScript, 10);

				const monitor = restored.getChannelManager().getMonitor(channelId)!;
				const tracked = monitor.getTrackedOutputs();
				expect(tracked.length).to.equal(1);
				expect(tracked[0].outputType).to.equal(OutputType.TO_REMOTE);

				const broadcasts = actions.filter(
					(a) => a.type === ChainActionType.BROADCAST_TX
				);
				expect(broadcasts.length).to.equal(1);
				expect(
					(broadcasts[0] as { description?: string }).description
				).to.contain('to_remote');

				// The sweep pays the destination script and spends the commitment.
				const sweep = bitcoin.Transaction.fromBuffer(
					(broadcasts[0] as { tx: Buffer }).tx
				);
				expect(
					Buffer.from(sweep.ins[0].hash).reverse().toString('hex')
				).to.equal(commitmentTx.getId());
				expect(sweep.outs[0].script.equals(destScript)).to.equal(true);
			} finally {
				restored.destroy();
				storage.close();
			}
		});
	});

	// ───────── BeignetNode.restoreFromScb guards ─────────

	describe('BeignetNode.restoreFromScb', function () {
		const MNEMONIC =
			'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
		let tmpDir: string;

		beforeEach(function () {
			tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-scb-restore-'));
		});

		afterEach(function () {
			fs.rmSync(tmpDir, { recursive: true, force: true });
		});

		it('refuses a wrong-network backup and a wrong-seed blob; accepts a matching empty one', async function () {
			this.timeout(60_000);
			const node = await BeignetNode.create({
				mnemonic: MNEMONIC,
				network: 'regtest',
				dataDir: tmpDir,
				logLevel: 'silent',
				rapidGossipSync: false,
				autoGossipSync: false
			});
			try {
				const seed = bip39.mnemonicToSeedSync(MNEMONIC);
				const base: IStaticChannelBackup = {
					version: 1,
					network: 'bc', // mainnet blob against a regtest node
					createdAt: Date.now(),
					channels: []
				};

				let networkError: Error | null = null;
				try {
					await node.restoreFromScb(encodeScb(base, seed));
				} catch (err) {
					networkError = err as Error;
				}
				expect(networkError).to.exist;
				expect(networkError!.message).to.match(/network/);

				let seedError: Error | null = null;
				try {
					await node.restoreFromScb(
						encodeScb(
							{ ...base, network: 'bcrt' },
							crypto.createHash('sha512').update('other-seed').digest()
						)
					);
				} catch (err) {
					seedError = err as Error;
				}
				expect(seedError).to.exist;
				expect(seedError!.message).to.match(/wrong seed|corrupted/);

				const ok = await node.restoreFromScb(
					encodeScb({ ...base, network: 'bcrt' }, seed)
				);
				expect(ok.channelCount).to.equal(0);
				expect(ok.recovering).to.deep.equal([]);
				expect(ok.skipped).to.deep.equal([]);
			} finally {
				await node.destroy();
			}
		});
	});

	// ───────── CLI offline db-restore helpers ─────────

	describe('CLI db-restore helpers', function () {
		let tmpDir: string;

		beforeEach(function () {
			tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-db-restore-'));
		});

		afterEach(function () {
			fs.rmSync(tmpDir, { recursive: true, force: true });
		});

		function writeSqliteLike(filePath: string, tag: string): void {
			fs.writeFileSync(
				filePath,
				Buffer.concat([SQLITE_HEADER, Buffer.from(tag)])
			);
		}

		it('isSqliteFile validates the 16-byte header', function () {
			const good = path.join(tmpDir, 'good.db');
			writeSqliteLike(good, 'payload');
			expect(isSqliteFile(good)).to.equal(true);

			const bad = path.join(tmpDir, 'bad.db');
			fs.writeFileSync(bad, 'beignet-scb-v1:AAAA');
			expect(isSqliteFile(bad)).to.equal(false);

			const short = path.join(tmpDir, 'short.db');
			fs.writeFileSync(short, SQLITE_HEADER.subarray(0, 8));
			expect(isSqliteFile(short)).to.equal(false);

			expect(isSqliteFile(path.join(tmpDir, 'missing.db'))).to.equal(false);
		});

		it('preRestoreBackupPath appends .pre-restore-<ts>', function () {
			expect(preRestoreBackupPath('/x/mainnet.db', 1234)).to.equal(
				'/x/mainnet.db.pre-restore-1234'
			);
		});

		it('restoreDbFile preserves the existing db and stale sidecars, then copies', function () {
			const backup = path.join(tmpDir, 'backup.db');
			const dbPath = path.join(tmpDir, 'mainnet.db');
			writeSqliteLike(backup, 'NEW');
			writeSqliteLike(dbPath, 'OLD');
			fs.writeFileSync(`${dbPath}-wal`, 'stale-wal');

			const result = restoreDbFile(backup, dbPath, 42);
			expect(result.preRestorePath).to.equal(`${dbPath}.pre-restore-42`);
			expect(fs.readFileSync(dbPath).includes('NEW')).to.equal(true);
			expect(fs.readFileSync(result.preRestorePath!).includes('OLD')).to.equal(
				true
			);
			// Old WAL moved aside so it cannot corrupt the restored file.
			expect(fs.existsSync(`${dbPath}-wal`)).to.equal(false);
			expect(fs.existsSync(`${result.preRestorePath}-wal`)).to.equal(true);
		});

		it('restoreDbFile refuses a non-SQLite file and leaves the db untouched', function () {
			const backup = path.join(tmpDir, 'not-a-db.bin');
			const dbPath = path.join(tmpDir, 'mainnet.db');
			fs.writeFileSync(backup, 'garbage');
			writeSqliteLike(dbPath, 'OLD');

			expect(() => restoreDbFile(backup, dbPath)).to.throw(/SQLite/);
			expect(fs.readFileSync(dbPath).includes('OLD')).to.equal(true);
			expect(fs.existsSync(preRestoreBackupPath(dbPath, 0))).to.equal(false);
		});

		it('performDbRestore refuses while another live process holds the instance lock', function () {
			const backup = path.join(tmpDir, 'backup.db');
			const dbPath = path.join(tmpDir, 'mainnet.db');
			const lockPath = path.join(tmpDir, 'mainnet.lock');
			writeSqliteLike(backup, 'NEW');
			writeSqliteLike(dbPath, 'OLD');
			// Simulate a running daemon: a live PID that is not ours (our parent).
			fs.writeFileSync(
				lockPath,
				JSON.stringify({
					pid: process.ppid,
					hostname: os.hostname(),
					createdAt: Date.now()
				})
			);

			expect(() => performDbRestore(backup, dbPath, lockPath)).to.throw(
				InstanceLockError
			);
			expect(fs.readFileSync(dbPath).includes('OLD')).to.equal(true);

			// With the lock free the restore proceeds and releases the lock after.
			fs.unlinkSync(lockPath);
			const result = performDbRestore(backup, dbPath, lockPath, 7);
			expect(fs.readFileSync(dbPath).includes('NEW')).to.equal(true);
			expect(result.preRestorePath).to.equal(`${dbPath}.pre-restore-7`);
			expect(fs.existsSync(lockPath)).to.equal(false);
		});
	});
});
