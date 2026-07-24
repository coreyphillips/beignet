/**
 * Funding broadcast retry (BOLT 2 obligation).
 *
 * Once funding_signed is received the funder MUST broadcast the funding tx.
 * The signed tx therefore lives until the funding CONFIRMS: a transient
 * broadcast failure is retried on every new block, the map is persisted so
 * a restart resumes the obligation, and a funding:missing alarm (mempool
 * eviction) is answered by a rebroadcast BEFORE the channel is voided.
 * Voiding is the last resort, reserved for a tx the network rejects.
 */
import { expect } from 'chai';
import crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	INodeConfig,
	IFundingProvider,
	ILightningError
} from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { IChainBackend } from '../../src/lightning/chain/chain-watcher';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';

bitcoin.initEccLib(ecc);

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`broadcast-retry-seed-${id}`))
		.digest();
}

function makeBasepoints(seed: Buffer): {
	basepoints: IChannelBasepoints;
	fundingPrivkey: Buffer;
	htlcSecret: Buffer;
} {
	const keys: Buffer[] = [];
	for (let i = 0; i < 6; i++) {
		keys.push(
			crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from([i]))
				.digest()
		);
	}
	return {
		basepoints: {
			fundingPubkey: getPublicKey(keys[0]),
			revocationBasepoint: getPublicKey(keys[1]),
			paymentBasepoint: getPublicKey(keys[2]),
			delayedPaymentBasepoint: getPublicKey(keys[3]),
			htlcBasepoint: getPublicKey(keys[4]),
			firstPerCommitmentPoint: Buffer.alloc(33)
		},
		fundingPrivkey: keys[0],
		htlcSecret: keys[4]
	};
}

/** A backend whose script-hash history is controllable per test. */
class ControlledBackend implements IChainBackend {
	history: Array<{ txid: string; height: number }> = [];
	async subscribeToHeaders(): Promise<void> {}
	async subscribeToScriptHash(): Promise<void> {}
	async getScriptHashHistory(): Promise<
		Array<{ txid: string; height: number }>
	> {
		return this.history;
	}
	async getTransaction(): Promise<Buffer> {
		throw new Error('not needed');
	}
	async broadcastTransaction(): Promise<string> {
		return '';
	}
}

function makeNodeConfig(
	seedId: number,
	opts: {
		fundingProvider?: IFundingProvider;
		chainBackend?: IChainBackend;
		storage?: SqliteStorage;
	} = {}
): INodeConfig {
	const seed = makeSeed(seedId);
	const nodePrivateKey = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from('node-identity'))
		.digest();
	const { basepoints, fundingPrivkey, htlcSecret } = makeBasepoints(seed);
	return {
		nodePrivateKey,
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: basepoints,
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey,
		htlcBasepointSecret: htlcSecret,
		...opts
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

function buildMockFundingTx(
	address: string,
	amountSats: number
): { txHex: string; txid: Buffer; outputIndex: number } {
	const tx = new bitcoin.Transaction();
	tx.addInput(crypto.randomBytes(32), 0);
	tx.addOutput(
		bitcoin.script.compile([bitcoin.opcodes.OP_0, crypto.randomBytes(20)]),
		50_000
	);
	tx.addOutput(
		bitcoin.address.toOutputScript(address, bitcoin.networks.regtest),
		amountSats
	);
	return { txHex: tx.toHex(), txid: Buffer.from(tx.getHash()), outputIndex: 1 };
}

const tick = (ms = 60): Promise<void> =>
	new Promise((resolve) => setTimeout(resolve, ms));

/** White-box read of the retained funding tx map. */
const pendingMap = (node: LightningNode): Map<string, string> =>
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	(node as any).pendingFundingTxs;

describe('Funding broadcast retry', function () {
	it('a failed broadcast retains the signed tx and the next block retries it', async function () {
		const broadcasts: string[] = [];
		let fail = true;
		let fundingTxidHex = '';
		const provider: IFundingProvider = {
			buildFundingTransaction: async (address, amountSats) => {
				const built = buildMockFundingTx(address, Number(amountSats));
				fundingTxidHex = built.txid.toString('hex');
				return built;
			},
			broadcastTransaction: async (txHex) => {
				broadcasts.push(txHex);
				if (fail) throw new Error('electrum hiccup');
				return bitcoin.Transaction.fromHex(txHex).getId();
			}
		};

		const alice = new LightningNode(
			makeNodeConfig(1, { fundingProvider: provider })
		);
		const bob = new LightningNode(makeNodeConfig(2));
		const errors: ILightningError[] = [];
		alice.on('node:error', (e: ILightningError) => errors.push(e));
		bob.on('node:error', () => {});
		connectNodes(alice, bob);

		alice.openChannel(bob.getNodeId(), 500_000n);
		await tick();

		// The broadcast failed, the error was surfaced, and the signed tx is
		// STILL retained (the old behavior deleted it before the attempt).
		expect(broadcasts.length).to.equal(1);
		expect(errors.some((e) => e.code === 'FUNDING_BROADCAST_FAILED')).to.equal(
			true
		);
		expect(pendingMap(alice).has(fundingTxidHex)).to.equal(true);

		// Next block: the obligation is retried with the SAME tx and succeeds.
		fail = false;
		alice.handleNewBlock(500);
		await tick();
		expect(broadcasts.length).to.equal(2);
		expect(broadcasts[1]).to.equal(broadcasts[0]);
		// Success does NOT retire the entry: it lives until the funding
		// confirms, so a later mempool eviction can be rebroadcast.
		expect(pendingMap(alice).has(fundingTxidHex)).to.equal(true);

		alice.destroy();
		bob.destroy();
	});

	it('funding:confirmed retires the obligation', async function () {
		let fundingTxidHex = '';
		const provider: IFundingProvider = {
			buildFundingTransaction: async (address, amountSats) => {
				const built = buildMockFundingTx(address, Number(amountSats));
				fundingTxidHex = built.txid.toString('hex');
				return built;
			},
			broadcastTransaction: async (txHex) =>
				bitcoin.Transaction.fromHex(txHex).getId()
		};
		const alice = new LightningNode(
			makeNodeConfig(3, {
				fundingProvider: provider,
				chainBackend: new ControlledBackend()
			})
		);
		const bob = new LightningNode(makeNodeConfig(4));
		alice.on('node:error', () => {});
		bob.on('node:error', () => {});
		connectNodes(alice, bob);

		const channel = alice.openChannel(bob.getNodeId(), 500_000n);
		await tick();
		expect(pendingMap(alice).has(fundingTxidHex)).to.equal(true);

		const channelId = channel.getChannelId()!;
		alice.getChainWatcher()!.emit('funding:confirmed', channelId);
		expect(
			pendingMap(alice).has(fundingTxidHex),
			'confirmation retires the retained tx'
		).to.equal(false);

		alice.destroy();
		bob.destroy();
	});

	it('an entry whose channel is gone is retired without broadcasting', async function () {
		const broadcasts: string[] = [];
		const provider: IFundingProvider = {
			buildFundingTransaction: async (address, amountSats) =>
				buildMockFundingTx(address, Number(amountSats)),
			broadcastTransaction: async (txHex) => {
				broadcasts.push(txHex);
				return 'txid';
			}
		};
		const alice = new LightningNode(
			makeNodeConfig(5, { fundingProvider: provider })
		);
		alice.on('node:error', () => {});

		// An orphaned obligation: no channel references this funding txid
		// (e.g. the open was aborted after the tx was built). Broadcasting it
		// would lock coins in a 2-of-2 nobody will use.
		pendingMap(alice).set('ab'.repeat(32), 'deadbeef');
		alice.handleNewBlock(500);
		await tick();

		expect(broadcasts.length).to.equal(0);
		expect(pendingMap(alice).size).to.equal(0);

		alice.destroy();
	});

	it('a restart restores the obligation and rebroadcasts', async function () {
		const dbPath = path.join(
			fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-retry-')),
			'node.db'
		);
		const broadcasts: string[] = [];
		let fundingTxidHex = '';
		const failingProvider: IFundingProvider = {
			buildFundingTransaction: async (address, amountSats) => {
				const built = buildMockFundingTx(address, Number(amountSats));
				fundingTxidHex = built.txid.toString('hex');
				return built;
			},
			broadcastTransaction: async () => {
				throw new Error('offline');
			}
		};

		const storage1 = new SqliteStorage(dbPath);
		storage1.open();
		const alice1 = new LightningNode(
			makeNodeConfig(6, { fundingProvider: failingProvider, storage: storage1 })
		);
		const bob = new LightningNode(makeNodeConfig(7));
		alice1.on('node:error', () => {});
		bob.on('node:error', () => {});
		connectNodes(alice1, bob);

		alice1.openChannel(bob.getNodeId(), 500_000n);
		await tick();
		expect(pendingMap(alice1).has(fundingTxidHex)).to.equal(true);
		alice1.destroy();
		bob.destroy();

		// Restart: the persisted obligation is restored and the startup retry
		// (chain watcher bring-up) rebroadcasts it.
		const workingProvider: IFundingProvider = {
			buildFundingTransaction: async (address, amountSats) =>
				buildMockFundingTx(address, Number(amountSats)),
			broadcastTransaction: async (txHex) => {
				broadcasts.push(txHex);
				return bitcoin.Transaction.fromHex(txHex).getId();
			}
		};
		const storage2 = new SqliteStorage(dbPath);
		storage2.open();
		const alice2 = new LightningNode(
			makeNodeConfig(6, {
				fundingProvider: workingProvider,
				storage: storage2,
				chainBackend: new ControlledBackend()
			})
		);
		alice2.on('node:error', () => {});
		await tick(120); // chain watcher auto-start runs the startup retry

		expect(
			pendingMap(alice2).has(fundingTxidHex),
			'obligation restored from storage'
		).to.equal(true);
		expect(broadcasts.length, 'startup retry rebroadcast').to.equal(1);

		alice2.destroy();
	});

	it('funding:missing rebroadcasts the held tx instead of voiding', async function () {
		const broadcasts: string[] = [];
		let fundingTxidHex = '';
		const provider: IFundingProvider = {
			buildFundingTransaction: async (address, amountSats) => {
				const built = buildMockFundingTx(address, Number(amountSats));
				fundingTxidHex = built.txid.toString('hex');
				return built;
			},
			broadcastTransaction: async (txHex) => {
				broadcasts.push(txHex);
				return bitcoin.Transaction.fromHex(txHex).getId();
			}
		};
		const alice = new LightningNode(
			makeNodeConfig(8, {
				fundingProvider: provider,
				chainBackend: new ControlledBackend()
			})
		);
		const bob = new LightningNode(makeNodeConfig(9));
		alice.on('node:error', () => {});
		bob.on('node:error', () => {});
		connectNodes(alice, bob);

		const channel = alice.openChannel(bob.getNodeId(), 500_000n);
		await tick();
		expect(broadcasts.length).to.equal(1);

		const voided: Buffer[] = [];
		alice.on('channel:voided', (d: { channelId: Buffer }) =>
			voided.push(d.channelId)
		);

		// The watcher reports the tx missing (display byte order, as the
		// watcher's history entries carry it).
		const displayTxid = Buffer.from(fundingTxidHex, 'hex')
			.reverse()
			.toString('hex');
		alice
			.getChainWatcher()!
			.emit('funding:missing', channel.getChannelId()!, displayTxid);
		await tick();

		expect(broadcasts.length, 'the held tx was rebroadcast').to.equal(2);
		expect(voided.length, 'the channel was NOT voided').to.equal(0);
		expect(alice.listChannels().length).to.equal(1);

		alice.destroy();
		bob.destroy();
	});

	it('funding:missing voids the channel when the rebroadcast is rejected', async function () {
		let fundingTxidHex = '';
		let acceptBroadcast = true;
		const provider: IFundingProvider = {
			buildFundingTransaction: async (address, amountSats) => {
				const built = buildMockFundingTx(address, Number(amountSats));
				fundingTxidHex = built.txid.toString('hex');
				return built;
			},
			broadcastTransaction: async (txHex) => {
				if (!acceptBroadcast) {
					throw new Error('bad-txns-inputs-missingorspent');
				}
				return bitcoin.Transaction.fromHex(txHex).getId();
			}
		};
		const alice = new LightningNode(
			makeNodeConfig(10, {
				fundingProvider: provider,
				chainBackend: new ControlledBackend()
			})
		);
		const bob = new LightningNode(makeNodeConfig(11));
		alice.on('node:error', () => {});
		bob.on('node:error', () => {});
		connectNodes(alice, bob);

		const channel = alice.openChannel(bob.getNodeId(), 500_000n);
		await tick();

		const voided: Buffer[] = [];
		alice.on('channel:voided', (d: { channelId: Buffer }) =>
			voided.push(d.channelId)
		);

		// An input was double-spent: the network rejects the rebroadcast, so
		// the channel is fiction and must be voided.
		acceptBroadcast = false;
		const displayTxid = Buffer.from(fundingTxidHex, 'hex')
			.reverse()
			.toString('hex');
		alice
			.getChainWatcher()!
			.emit('funding:missing', channel.getChannelId()!, displayTxid);
		await tick();

		expect(voided.length, 'rejected rebroadcast voids the channel').to.equal(1);
		expect(alice.listChannels().length).to.equal(0);
		expect(
			pendingMap(alice).has(fundingTxidHex),
			'the retained tx is retired with the channel'
		).to.equal(false);

		alice.destroy();
		bob.destroy();
	});
});
