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
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { IChainBackend } from '../../src/lightning/chain/chain-watcher';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	deserializeChannelState,
	serializeChannelState
} from '../../src/lightning/storage/serialization';
import { encodeErrorMessage } from '../../src/lightning/message/error';
import {
	CRASH_V1_PROFILE,
	GuardianClient,
	GuardianHttpServer,
	GuardianReplicator,
	IBoundGuardianClient,
	IWriterLeaseKeys,
	ReferenceGuardian,
	RestoreDriver,
	computeGuardianSetId,
	deriveRecoveryRoot,
	xOnlyFromSecret
} from '../../src/lightning/recovery';

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
		recovery?: INodeConfig['recovery'];
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

/** The node identity makeNodeConfig derives, as the recovery root needs it. */
function nodeSecretFor(seedId: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(makeSeed(seedId))
		.update(Buffer.from('node-identity'))
		.digest();
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

	it('a stranded obligation is re-adopted from the channel row on the next block', async function () {
		// A disconnect purges a channel's barrier-held batch, and for a v2
		// open that suffix can be the tx_signatures release plus the funding
		// broadcast: the fully signed tx is already durable on the row, but
		// the action that registers the runtime obligation never ran. The
		// per-block retry must adopt the row's payload (as 'restored', so it
		// re-asks authorization) instead of idling until a restart.
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
			makeNodeConfig(31, { fundingProvider: provider })
		);
		const bob = new LightningNode(makeNodeConfig(32));
		alice.on('node:error', () => {});
		bob.on('node:error', () => {});
		connectNodes(alice, bob);

		alice.openChannel(bob.getNodeId(), 500_000n);
		await tick();
		expect(broadcasts.length).to.equal(1);
		expect(pendingMap(alice).has(fundingTxidHex)).to.equal(true);

		// Strand it: the runtime entry vanishes the way a purged held batch
		// leaves things, while the channel row still owes the broadcast.
		pendingMap(alice).clear();
		expect(pendingMap(alice).size).to.equal(0);

		alice.handleNewBlock(501);
		await tick();
		expect(
			pendingMap(alice).has(fundingTxidHex),
			're-adopted from the channel row'
		).to.equal(true);
		expect(broadcasts.length, 'the obligation was re-broadcast').to.equal(2);
		expect(broadcasts[1]).to.equal(broadcasts[0]);

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

	it('a retained obligation renews its input pledges on every block', async function () {
		// The pledge that reserved the funding inputs is released on a timeout,
		// and again once the wallet stops listing the coin, while the obligation
		// runs until the funding CONFIRMS. Without a renewal on the retry cadence
		// the inputs return to the candidate set (or to an ordinary wallet send)
		// while the transaction we still owe the network is retrying.
		const renewed: string[] = [];
		let fundingTxidHex = '';
		let fundingTxHex = '';
		const provider: IFundingProvider = {
			buildFundingTransaction: async (address, amountSats) => {
				const built = buildMockFundingTx(address, Number(amountSats));
				fundingTxidHex = built.txid.toString('hex');
				fundingTxHex = built.txHex;
				return built;
			},
			broadcastTransaction: async (txHex) =>
				bitcoin.Transaction.fromHex(txHex).getId(),
			pledgeTransactionInputs: async (txHex) => {
				renewed.push(txHex);
			}
		};

		const alice = new LightningNode(
			makeNodeConfig(41, { fundingProvider: provider })
		);
		const bob = new LightningNode(makeNodeConfig(42));
		alice.on('node:error', () => {});
		bob.on('node:error', () => {});
		connectNodes(alice, bob);

		alice.openChannel(bob.getNodeId(), 500_000n);
		await tick();
		expect(pendingMap(alice).has(fundingTxidHex)).to.equal(true);

		alice.handleNewBlock(600);
		await tick();
		expect(renewed, 'the retained tx renewed its pledges').to.deep.equal([
			fundingTxHex
		]);

		// Still unconfirmed one block later: the reservation is renewed again
		// rather than left to time out under the obligation.
		alice.handleNewBlock(601);
		await tick();
		expect(renewed).to.deep.equal([fundingTxHex, fundingTxHex]);

		alice.destroy();
		bob.destroy();
	});

	it('a retired obligation stops renewing its pledges', async function () {
		const renewed: string[] = [];
		const provider: IFundingProvider = {
			buildFundingTransaction: async (address, amountSats) =>
				buildMockFundingTx(address, Number(amountSats)),
			broadcastTransaction: async () => 'txid',
			pledgeTransactionInputs: async (txHex) => {
				renewed.push(txHex);
			}
		};
		const alice = new LightningNode(
			makeNodeConfig(43, { fundingProvider: provider })
		);
		alice.on('node:error', () => {});

		// No channel references this funding txid, so the entry is retired. Its
		// coins are nobody's obligation now and must age out normally.
		pendingMap(alice).set('ab'.repeat(32), 'deadbeef');
		alice.handleNewBlock(600);
		await tick();

		expect(renewed).to.deep.equal([]);
		expect(pendingMap(alice).size).to.equal(0);

		alice.destroy();
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

	it('funding:missing does NOT void on a rejected rebroadcast', async function () {
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

		// The rebroadcast is rejected. That is NOT evidence the channel is
		// fiction: bad-txns-inputs-missingorspent covers an unconfirmed parent
		// this backend has not seen, a mempool conflict need not be confirmed,
		// and a timeout says nothing at all. BOLT 2 forgets an unconfirmed
		// funding only after 2016 blocks, so the channel and its retained
		// transaction are both kept.
		acceptBroadcast = false;
		const displayTxid = Buffer.from(fundingTxidHex, 'hex')
			.reverse()
			.toString('hex');
		alice
			.getChainWatcher()!
			.emit('funding:missing', channel.getChannelId()!, displayTxid);
		await tick();

		expect(voided.length, 'a rejection is not a verdict').to.equal(0);
		expect(alice.listChannels().length).to.equal(1);
		expect(
			pendingMap(alice).has(fundingTxidHex),
			'the retained tx survives a rejected rebroadcast'
		).to.equal(true);

		alice.destroy();
		bob.destroy();
	});
});

describe('Funding broadcast authorization (BOLT 2 ordering)', function () {
	/**
	 * Bridge the two nodes but WITHHOLD one message type from B to A, so the
	 * funder can be parked mid-handshake the way a real peer parks it.
	 */
	function connectWithheld(
		nodeA: LightningNode,
		nodeB: LightningNode,
		withheldType: number
	): { deliver: () => void } {
		const held: Array<{ type: number; payload: Buffer }> = [];
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
				if (pubkey !== nodeA.getNodeId()) return;
				if (type === withheldType) {
					held.push({ type, payload });
					return;
				}
				nodeA.handlePeerMessage(nodeB.getNodeId(), type, payload);
			}
		);
		return {
			deliver: (): void => {
				for (const m of held.splice(0)) {
					nodeA.handlePeerMessage(nodeB.getNodeId(), m.type, m.payload);
				}
			}
		};
	}

	const FUNDING_SIGNED = 35;

	it('a new block does NOT broadcast while funding_signed is outstanding', async function () {
		const broadcasts: string[] = [];
		const provider: IFundingProvider = {
			buildFundingTransaction: async (address, amountSats) =>
				buildMockFundingTx(address, Number(amountSats)),
			broadcastTransaction: async (txHex) => {
				broadcasts.push(txHex);
				return bitcoin.Transaction.fromHex(txHex).getId();
			}
		};
		const alice = new LightningNode(
			makeNodeConfig(41, { fundingProvider: provider })
		);
		const bob = new LightningNode(makeNodeConfig(42));
		alice.on('node:error', () => {});
		bob.on('node:error', () => {});
		connectWithheld(alice, bob, FUNDING_SIGNED);

		alice.openChannel(bob.getNodeId(), 500_000n);
		await tick();

		// Signed and retained, but NOT owed: without the acceptor's signature
		// over our commitment #0 the 2-of-2 has no unilateral exit for us.
		const channel = alice.getChannelManager().listChannels()[0];
		expect(channel.getFullState().state).to.equal(
			ChannelState.SENT_FUNDING_CREATED
		);
		expect(!!channel.getFullState().remoteCommitmentSignature).to.equal(false);
		expect(pendingMap(alice).size).to.equal(1);
		expect(broadcasts).to.have.length(0);

		// The block feed is the embedder's documented contract, and this is
		// where the obligation used to be assumed rather than checked.
		alice.handleNewBlock(500);
		await tick();
		expect(broadcasts).to.have.length(0);
		// And the retained transaction is NOT retired either: the open is still
		// live, so the obligation may still begin.
		expect(pendingMap(alice).size).to.equal(1);

		alice.destroy();
		bob.destroy();
	});

	it('a peer that never answers cannot be timed into a broadcast', async function () {
		const broadcasts: string[] = [];
		const provider: IFundingProvider = {
			buildFundingTransaction: async (address, amountSats) =>
				buildMockFundingTx(address, Number(amountSats)),
			broadcastTransaction: async (txHex) => {
				broadcasts.push(txHex);
				return bitcoin.Transaction.fromHex(txHex).getId();
			}
		};
		const alice = new LightningNode(
			makeNodeConfig(43, { fundingProvider: provider })
		);
		const bob = new LightningNode(makeNodeConfig(44));
		alice.on('node:error', () => {});
		bob.on('node:error', () => {});
		connectWithheld(alice, bob, FUNDING_SIGNED);

		alice.openChannel(bob.getNodeId(), 500_000n);
		await tick();

		// The window is not the round trip. Nothing in the node bounds a peer
		// that stays connected and simply never replies, so the timing is the
		// peer's to choose; every block must answer the same way.
		for (let height = 500; height < 510; height++) {
			alice.handleNewBlock(height);
		}
		await tick();
		expect(broadcasts).to.have.length(0);

		alice.destroy();
		bob.destroy();
	});

	it('an owed funding survives the channel dying, and its failed broadcast is never chain evidence', async function () {
		// Review of issue 413: 'authorized' only means we DECIDED to
		// broadcast. With the backend down the handoff failed, so an error
		// must not force-close on top of a parent that reached nobody, and
		// the obligation (BOLT 2: MUST broadcast after funding_signed) must
		// survive the channel dying rather than retire with it.
		const broadcasts: string[] = [];
		const released: Array<Array<{ txid: string; vout: number }>> = [];
		let fundingTxidHex = '';
		let fail = true;
		const provider: IFundingProvider = {
			buildFundingTransaction: async (address, amountSats) => {
				const built = buildMockFundingTx(address, Number(amountSats));
				fundingTxidHex = built.txid.toString('hex');
				return built;
			},
			broadcastTransaction: async (txHex) => {
				broadcasts.push(txHex);
				if (fail) throw new Error('backend down');
				return bitcoin.Transaction.fromHex(txHex).getId();
			},
			releaseInputPledges: async (outpoints) => {
				released.push(outpoints);
			}
		};
		const alice = new LightningNode(
			makeNodeConfig(51, { fundingProvider: provider })
		);
		const bob = new LightningNode(makeNodeConfig(52));
		const events: string[] = [];
		alice.on('node:error', (e: ILightningError) => events.push(e.code));
		bob.on('node:error', () => {});
		connectNodes(alice, bob);

		alice.openChannel(bob.getNodeId(), 500_000n);
		await tick();
		// funding_signed landed, authorization fired, the broadcast FAILED.
		expect(broadcasts).to.have.length(1);
		expect(pendingMap(alice).size).to.equal(1);

		const channelId = alice
			.getChannelManager()
			.listChannels()[0]
			.getChannelId()!;
		alice.handlePeerMessage(
			bob.getNodeId(),
			17, // ERROR
			encodeErrorMessage({ channelId, data: Buffer.from('nope') })
		);
		await tick();
		// No fictional close: the parent reached nobody.
		expect(events).to.not.include('CHANNEL_FAILED_FORCE_CLOSED');

		// The dead channel state does not retire the obligation: the entry
		// survives, rebroadcasts, and its pledges stay frozen.
		alice.handleNewBlock(500);
		await tick();
		expect(pendingMap(alice).has(fundingTxidHex)).to.equal(true);
		expect(broadcasts).to.have.length(2);
		expect(released).to.have.length(0);

		// Backend heals: the parent finally reaches the network.
		fail = false;
		alice.handleNewBlock(501);
		await tick();
		expect(broadcasts).to.have.length(3);

		// The confirmation stamps the proof and re-drives the owed close.
		alice.handleFundingConfirmed(channelId);
		await tick();
		expect(events).to.include('CHANNEL_FAILED_FORCE_CLOSED');

		// And the parent keeps rebroadcasting through the terminal state
		// until funding:confirmed retires the entry.
		alice.handleNewBlock(502);
		await tick();
		expect(pendingMap(alice).has(fundingTxidHex)).to.equal(true);
		expect(broadcasts).to.have.length(4);
		expect(released).to.have.length(0);

		alice.destroy();
		bob.destroy();
	});

	it('a parked candidate whose funding_signed landed keeps its entry and pledges (issue 412)', async function () {
		// The durability barrier can hold the authorization while
		// funding_signed has already landed: the obligation exists durably
		// (a restart re-adopts and re-asks), so an error racing the barrier
		// must not release the inputs a crash-recovered broadcast would
		// spend. awaitingFundingAuthorization is the guard.
		const released: Array<Array<{ txid: string; vout: number }>> = [];
		let fundingTxidHex = '';
		const provider: IFundingProvider = {
			buildFundingTransaction: async (address, amountSats) => {
				const built = buildMockFundingTx(address, Number(amountSats));
				fundingTxidHex = built.txid.toString('hex');
				return built;
			},
			broadcastTransaction: async (txHex) =>
				bitcoin.Transaction.fromHex(txHex).getId(),
			releaseInputPledges: async (outpoints) => {
				released.push(outpoints);
			}
		};
		const alice = new LightningNode(
			makeNodeConfig(53, { fundingProvider: provider })
		);
		const bob = new LightningNode(makeNodeConfig(54));
		alice.on('node:error', () => {});
		bob.on('node:error', () => {});
		connectNodes(alice, bob);

		alice.openChannel(bob.getNodeId(), 500_000n);
		await tick();
		// Model the parked barrier: funding_signed landed but the
		// authorization never fired in this process.
		const entry = pendingMap(alice).get(fundingTxidHex) as unknown as {
			phase: string;
			broadcastSucceeded?: boolean;
		};
		entry.phase = 'candidate';
		entry.broadcastSucceeded = undefined;

		const channelId = alice
			.getChannelManager()
			.listChannels()[0]
			.getChannelId()!;
		alice.handlePeerMessage(
			bob.getNodeId(),
			17, // ERROR
			encodeErrorMessage({ channelId, data: Buffer.from('nope') })
		);
		await tick();
		alice.handleNewBlock(500);
		await tick();

		expect(
			pendingMap(alice).has(fundingTxidHex),
			'the owed entry survives the dead channel'
		).to.equal(true);
		expect(released).to.have.length(0);

		alice.destroy();
		bob.destroy();
	});

	it('the retirement sweep runs on production headers too (issue 412)', async function () {
		// The live ChainWatcher block listener, not only the embedder-driven
		// handleNewBlock, must run the retry sweep: rebroadcasts, pledge
		// renewals and the dead-entry retirement all ride it.
		const released: Array<Array<{ txid: string; vout: number }>> = [];
		let builtTxHex = '';
		const provider: IFundingProvider = {
			buildFundingTransaction: async (address, amountSats) => {
				const built = buildMockFundingTx(address, Number(amountSats));
				builtTxHex = built.txHex;
				return built;
			},
			broadcastTransaction: async (txHex) =>
				bitcoin.Transaction.fromHex(txHex).getId(),
			releaseInputPledges: async (outpoints) => {
				released.push(outpoints);
			}
		};
		const alice = new LightningNode(
			makeNodeConfig(55, {
				fundingProvider: provider,
				chainBackend: new ControlledBackend()
			})
		);
		const bob = new LightningNode(makeNodeConfig(56));
		alice.on('node:error', () => {});
		bob.on('node:error', () => {});
		connectWithheld(alice, bob, FUNDING_SIGNED);

		alice.openChannel(bob.getNodeId(), 500_000n);
		await tick();
		expect(pendingMap(alice).size).to.equal(1);

		const channelId = alice
			.getChannelManager()
			.listChannels()[0]
			.getChannelId()!;
		alice.handlePeerMessage(
			bob.getNodeId(),
			17, // ERROR
			encodeErrorMessage({ channelId, data: Buffer.from('nope') })
		);
		await tick();

		// A production header, not handleNewBlock.
		alice.getChainWatcher()!.emit('block', 500);
		await tick();

		const expected = bitcoin.Transaction.fromHex(builtTxHex).ins.map(
			(input) => ({
				txid: Buffer.from(input.hash).reverse().toString('hex'),
				vout: input.index
			})
		);
		expect(released).to.deep.equal([expected]);
		expect(pendingMap(alice).size).to.equal(0);

		alice.destroy();
		bob.destroy();
	});

	it('a refused funding_signed frees the pledged inputs at once (issue 412)', async function () {
		const broadcasts: string[] = [];
		const released: Array<Array<{ txid: string; vout: number }>> = [];
		let builtTxHex = '';
		const provider: IFundingProvider = {
			buildFundingTransaction: async (address, amountSats) => {
				const built = buildMockFundingTx(address, Number(amountSats));
				builtTxHex = built.txHex;
				return built;
			},
			broadcastTransaction: async (txHex) => {
				broadcasts.push(txHex);
				return bitcoin.Transaction.fromHex(txHex).getId();
			},
			releaseInputPledges: async (outpoints) => {
				released.push(outpoints);
			}
		};
		const alice = new LightningNode(
			makeNodeConfig(47, { fundingProvider: provider })
		);
		const bob = new LightningNode(makeNodeConfig(48));
		alice.on('node:error', () => {});
		bob.on('node:error', () => {});

		// connectWithheld, except the held funding_signed is delivered with a
		// flipped signature byte, so the refusal lands after the promotion the
		// way a real socket orders it.
		const held: Array<{ type: number; payload: Buffer }> = [];
		alice.on(
			'message:outbound',
			(pubkey: string, type: number, payload: Buffer) => {
				if (pubkey === bob.getNodeId()) {
					bob.handlePeerMessage(alice.getNodeId(), type, payload);
				}
			}
		);
		bob.on(
			'message:outbound',
			(pubkey: string, type: number, payload: Buffer) => {
				if (pubkey !== alice.getNodeId()) return;
				if (type === FUNDING_SIGNED) {
					held.push({ type, payload });
					return;
				}
				alice.handlePeerMessage(bob.getNodeId(), type, payload);
			}
		);

		alice.openChannel(bob.getNodeId(), 500_000n);
		await tick();
		expect(pendingMap(alice).size).to.equal(1);
		expect(released).to.have.length(0);

		// [32 channel_id][64 signature]: flip a signature byte and deliver.
		const copy = Buffer.from(held[0].payload);
		copy[40] ^= 0xff;
		alice.handlePeerMessage(bob.getNodeId(), held[0].type, copy);
		await tick();

		const expected = bitcoin.Transaction.fromHex(builtTxHex).ins.map(
			(input) => ({
				txid: Buffer.from(input.hash).reverse().toString('hex'),
				vout: input.index
			})
		);
		expect(released, 'released immediately, before any block').to.have.length(
			1
		);
		expect(released[0]).to.deep.equal(expected);
		expect(alice.getChannelManager().listChannels()).to.have.length(0);

		// The next block retires the candidate entry without broadcasting.
		// The sweep's own release is a benign no-op at the provider.
		alice.handleNewBlock(500);
		await tick();
		expect(pendingMap(alice).size).to.equal(0);
		expect(broadcasts).to.have.length(0);
		for (const r of released) expect(r).to.deep.equal(expected);

		alice.destroy();
		bob.destroy();
	});

	it('a candidate entry retired for a dead channel frees the pledges at the next block (issue 412)', async function () {
		// A peer ERROR after funding_created runs failChannelByError: the
		// channel is ERRORED but stays registered, so the immediate release
		// above never fires. The entry-retirement sweep is the seam that
		// catches this shape, and every other path that drops a pre-broadcast
		// v1 channel.
		const broadcasts: string[] = [];
		const released: Array<Array<{ txid: string; vout: number }>> = [];
		let builtTxHex = '';
		const provider: IFundingProvider = {
			buildFundingTransaction: async (address, amountSats) => {
				const built = buildMockFundingTx(address, Number(amountSats));
				builtTxHex = built.txHex;
				return built;
			},
			broadcastTransaction: async (txHex) => {
				broadcasts.push(txHex);
				return bitcoin.Transaction.fromHex(txHex).getId();
			},
			releaseInputPledges: async (outpoints) => {
				released.push(outpoints);
			}
		};
		const alice = new LightningNode(
			makeNodeConfig(49, { fundingProvider: provider })
		);
		const bob = new LightningNode(makeNodeConfig(50));
		alice.on('node:error', () => {});
		bob.on('node:error', () => {});
		connectWithheld(alice, bob, FUNDING_SIGNED);

		alice.openChannel(bob.getNodeId(), 500_000n);
		await tick();
		expect(pendingMap(alice).size).to.equal(1);

		const channelId = alice
			.getChannelManager()
			.listChannels()[0]
			.getChannelId()!;
		alice.handlePeerMessage(
			bob.getNodeId(),
			17, // ERROR
			encodeErrorMessage({ channelId, data: Buffer.from('nope') })
		);
		await tick();
		expect(released, 'still registered: no immediate release').to.have.length(
			0
		);

		alice.handleNewBlock(500);
		await tick();
		const expected = bitcoin.Transaction.fromHex(builtTxHex).ins.map(
			(input) => ({
				txid: Buffer.from(input.hash).reverse().toString('hex'),
				vout: input.index
			})
		);
		expect(released, 'freed with the retired entry').to.deep.equal([expected]);
		expect(pendingMap(alice).size).to.equal(0);
		expect(broadcasts).to.have.length(0);

		alice.destroy();
		bob.destroy();
	});

	it('the obligation begins the moment funding_signed lands', async function () {
		const broadcasts: string[] = [];
		const released: Array<Array<{ txid: string; vout: number }>> = [];
		const provider: IFundingProvider = {
			buildFundingTransaction: async (address, amountSats) =>
				buildMockFundingTx(address, Number(amountSats)),
			broadcastTransaction: async (txHex) => {
				broadcasts.push(txHex);
				return bitcoin.Transaction.fromHex(txHex).getId();
			},
			releaseInputPledges: async (outpoints) => {
				released.push(outpoints);
			}
		};
		const alice = new LightningNode(
			makeNodeConfig(45, { fundingProvider: provider })
		);
		const bob = new LightningNode(makeNodeConfig(46));
		alice.on('node:error', () => {});
		bob.on('node:error', () => {});
		const bridge = connectWithheld(alice, bob, FUNDING_SIGNED);

		alice.openChannel(bob.getNodeId(), 500_000n);
		await tick();
		alice.handleNewBlock(500);
		await tick();
		expect(broadcasts).to.have.length(0);

		// Release the held funding_signed: the obligation starts here, and the
		// guard must not have turned a delay into a permanent refusal.
		bridge.deliver();
		await tick();
		expect(broadcasts).to.have.length(1);

		// And it stays an obligation until the funding confirms.
		alice.handleNewBlock(501);
		await tick();
		expect(broadcasts).to.have.length(2);
		expect(broadcasts[1]).to.equal(broadcasts[0]);
		// An authorized, broadcast funding never releases its pledges, on
		// either issue-412 seam: the coins are committed until it confirms.
		expect(released).to.have.length(0);

		alice.destroy();
		bob.destroy();
	});
});

describe('Funding authorization survives a restart', function () {
	it('a restart RE-ASKS for authorization instead of inferring it', async function () {
		// The obligation survives a restart, because the peer's signature over
		// our commitment #0 is on disk. The AUTHORIZATION does not. A channel
		// row proves only that THIS device wrote the frame, never that the
		// guardians accepted it, so a restart that read the row back would walk
		// straight around a barrier that was holding the broadcast when the
		// process died. It has to ask again, through a persist whose frame the
		// barrier can wait on.
		const dbPath = path.join(
			fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-reauth-')),
			'node.db'
		);
		let fundingTxidHex = '';
		const failing: IFundingProvider = {
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
			makeNodeConfig(51, { fundingProvider: failing, storage: storage1 })
		);
		const bob = new LightningNode(makeNodeConfig(52));
		alice1.on('node:error', () => {});
		bob.on('node:error', () => {});
		connectNodes(alice1, bob);
		alice1.openChannel(bob.getNodeId(), 500_000n);
		await tick();
		expect(pendingMap(alice1).has(fundingTxidHex)).to.equal(true);
		alice1.destroy();
		bob.destroy();

		const broadcasts: string[] = [];
		const working: IFundingProvider = {
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
			makeNodeConfig(51, {
				fundingProvider: working,
				storage: storage2,
				chainBackend: new ControlledBackend()
			})
		);
		alice2.on('node:error', () => {});

		// The restart's broadcast must be preceded by a PERSIST for the same
		// channel: that persist is the frame the authorization rides, and it is
		// the whole difference between asking again and inferring.
		const order: string[] = [];
		(
			alice2 as unknown as {
				channelManager: {
					on(e: string, l: (...a: unknown[]) => void): void;
				};
			}
		).channelManager.on('channel:persist', () => order.push('persist'));
		(
			alice2 as unknown as {
				channelManager: {
					on(e: string, l: (...a: unknown[]) => void): void;
				};
			}
		).channelManager.on('funding:authorized', () => order.push('authorized'));

		await tick(120);

		expect(broadcasts.length, 'the obligation still resumes').to.equal(1);
		expect(order[0], 'a fresh frame is minted first').to.equal('persist');
		expect(order).to.contain('authorized');

		alice2.destroy();
	});
});

describe('Funding payload and retry survive what the process does not', function () {
	it('the exact transaction rides the CHANNEL state, not just node metadata', async function () {
		// A guardian restore rebuilds channels from frames and has none of the
		// node's generic metadata. The frame that records funding_signed proves
		// the broadcast is owed; without the bytes beside it there is nothing to
		// broadcast, and the transaction cannot be rebuilt from the txid.
		let fundingTxidHex = '';
		let builtHex = '';
		const provider: IFundingProvider = {
			buildFundingTransaction: async (address, amountSats) => {
				const built = buildMockFundingTx(address, Number(amountSats));
				fundingTxidHex = built.txid.toString('hex');
				builtHex = built.txHex;
				return built;
			},
			broadcastTransaction: async (txHex) =>
				bitcoin.Transaction.fromHex(txHex).getId()
		};
		const alice = new LightningNode(
			makeNodeConfig(61, { fundingProvider: provider })
		);
		const bob = new LightningNode(makeNodeConfig(62));
		alice.on('node:error', () => {});
		bob.on('node:error', () => {});
		connectNodes(alice, bob);
		alice.openChannel(bob.getNodeId(), 500_000n);
		await tick();

		const state = alice.getChannelManager().listChannels()[0].getFullState();
		expect(state.fundingTxid?.toString('hex')).to.equal(fundingTxidHex);
		expect(state.pendingFundingTxHex).to.equal(builtHex);

		// And it survives the serialization the journal frame carries.
		const round = deserializeChannelState(serializeChannelState(state));
		expect(round.pendingFundingTxHex).to.equal(builtHex);

		alice.destroy();
		bob.destroy();
	});

	it('no rejection message ever voids a funder that still owes the broadcast', async function () {
		for (const message of [
			'connection reset by peer',
			'bad-txns-inputs-missingorspent'
		]) {
			let fundingTxidHex = '';
			const provider: IFundingProvider = {
				buildFundingTransaction: async (address, amountSats) => {
					const built = buildMockFundingTx(address, Number(amountSats));
					fundingTxidHex = built.txid.toString('hex');
					return built;
				},
				broadcastTransaction: async () => {
					throw new Error(message);
				}
			};
			const alice = new LightningNode(
				makeNodeConfig(63, {
					fundingProvider: provider,
					chainBackend: new ControlledBackend()
				})
			);
			const bob = new LightningNode(makeNodeConfig(64));
			alice.on('node:error', () => {});
			bob.on('node:error', () => {});
			connectNodes(alice, bob);
			const channel = alice.openChannel(bob.getNodeId(), 500_000n);
			await tick();
			const channelId = channel.getChannelId()!;
			const displayTxid = Buffer.from(fundingTxidHex, 'hex')
				.reverse()
				.toString('hex');

			// No message a backend can return proves the funding output can
			// never exist: a missing input can be an unconfirmed parent this
			// backend has not seen, a mempool conflict need not be confirmed,
			// and a timeout says nothing at all. The funder is OBLIGED to get
			// this confirmed, so it retries rather than ever forgetting.
			for (const height of [1_000, 1_000 + 2016, 1_000 + 5_000]) {
				alice.handleNewBlock(height);
				alice
					.getChainWatcher()!
					.emit('funding:missing', channelId, displayTxid);
				await tick(60);
				expect(
					alice.getChannelManager().getChannel(channelId),
					`voided for "${message}" at height ${height}`
				).to.not.equal(undefined);
			}
			expect(pendingMap(alice).has(fundingTxidHex)).to.equal(true);

			alice.destroy();
			bob.destroy();
		}
	});

	it('a node with no payload waits out the BOLT 2 timeout before forgetting', async function () {
		// The fundee never owns the funding transaction, so absence tells it
		// nothing it can act on. Forgetting after a handful of missing checks
		// would force a funder whose own quorum was merely slow to close and
		// reopen a channel that was never in trouble.
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
			makeNodeConfig(65, { fundingProvider: provider })
		);
		const bob = new LightningNode(
			makeNodeConfig(66, { chainBackend: new ControlledBackend() })
		);
		alice.on('node:error', () => {});
		bob.on('node:error', () => {});
		connectNodes(alice, bob);
		alice.openChannel(bob.getNodeId(), 500_000n);
		await tick();

		const bobChannel = bob.getChannelManager().listChannels()[0];
		const bobChannelId = bobChannel.getChannelId()!;
		expect(pendingMap(bob).size, 'the fundee owns no payload').to.equal(0);
		const displayTxid = Buffer.from(fundingTxidHex, 'hex')
			.reverse()
			.toString('hex');

		bob.handleNewBlock(1_000);
		bob.getChainWatcher()!.emit('funding:missing', bobChannelId, displayTxid);
		await tick(60);
		expect(
			bob.getChannelManager().getChannel(bobChannelId),
			'retained on the first absence'
		).to.not.equal(undefined);
		expect(bobChannel.getFullState().fundingMissingSinceHeight).to.equal(1_000);

		bob.handleNewBlock(1_000 + 2015);
		bob.getChainWatcher()!.emit('funding:missing', bobChannelId, displayTxid);
		await tick(60);
		expect(
			bob.getChannelManager().getChannel(bobChannelId),
			'2015 blocks is not 2016'
		).to.not.equal(undefined);

		bob.handleNewBlock(1_000 + 2016);
		bob.getChainWatcher()!.emit('funding:missing', bobChannelId, displayTxid);
		await tick(60);
		expect(
			bob.getChannelManager().getChannel(bobChannelId),
			'forgotten at the BOLT 2 timeout'
		).to.equal(undefined);

		alice.destroy();
		bob.destroy();
	});
});

/**
 * The clock counts down to DESTROYING a channel, so where it started has to
 * survive everything the channel survives. A start held only in memory is
 * lost on the next restart, the following absence starts it again at whatever
 * height the node is at by then, and a node that restarts often enough never
 * reaches the disposition at all. Adding the field to IChannelState makes it
 * persistABLE; only a commit makes a particular start persistED.
 */
describe('The funding forget clock outlives the process that starts it', function () {
	/** A fundee (owns no payload) with its own database, plus its funder. */
	async function fundeeWithStorage(
		seedId: number,
		storage: SqliteStorage
	): Promise<{
		funder: LightningNode;
		fundee: LightningNode;
		channelId: Buffer;
		displayTxid: string;
	}> {
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
		const funder = new LightningNode(
			makeNodeConfig(seedId, { fundingProvider: provider })
		);
		const fundee = new LightningNode(
			makeNodeConfig(seedId + 1, {
				storage,
				chainBackend: new ControlledBackend(),
				recovery: { enabled: true }
			})
		);
		funder.on('node:error', () => {});
		fundee.on('node:error', () => {});
		connectNodes(funder, fundee);
		funder.openChannel(fundee.getNodeId(), 500_000n);
		await tick();
		const channel = fundee.getChannelManager().listChannels()[0];
		return {
			funder,
			fundee,
			channelId: channel.getChannelId()!,
			displayTxid: Buffer.from(fundingTxidHex, 'hex').reverse().toString('hex')
		};
	}

	function reopen(seedId: number, storage: SqliteStorage): LightningNode {
		const node = new LightningNode(
			makeNodeConfig(seedId, {
				storage,
				chainBackend: new ControlledBackend(),
				recovery: { enabled: true }
			})
		);
		node.on('node:error', () => {});
		return node;
	}

	function tempDb(prefix: string): string {
		return path.join(
			fs.mkdtempSync(path.join(os.tmpdir(), `beignet-${prefix}-`)),
			'node.db'
		);
	}

	it('a restart reads the clock back instead of restarting it', async function () {
		this.timeout(20_000);
		const dbPath = tempDb('forget-clock');
		const storage1 = new SqliteStorage(dbPath);
		storage1.open();
		const first = await fundeeWithStorage(70, storage1);

		first.fundee.handleNewBlock(700_000);
		first.fundee
			.getChainWatcher()!
			.emit('funding:missing', first.channelId, first.displayTxid);
		await tick(60);
		expect(
			first.fundee
				.getChannelManager()
				.getChannel(first.channelId)!
				.fundingMissingSince(),
			'the clock started'
		).to.equal(700_000);

		first.funder.destroy();
		first.fundee.destroy();

		// A crash before any later transition: nothing else wrote this channel
		// between the start and the restart, so the start is durable or it is
		// nowhere.
		const storage2 = new SqliteStorage(dbPath);
		storage2.open();
		const restarted = reopen(71, storage2);
		await tick(150);

		const restored = restarted.getChannelManager().getChannel(first.channelId);
		expect(restored, 'channel restored').to.not.equal(undefined);
		expect(
			restored!.fundingMissingSince(),
			'the height the FIRST process observed, not this one'
		).to.equal(700_000);

		// 2015 blocks after the original start is still not 2016, however many
		// processes the wait was spread across.
		restarted.handleNewBlock(700_000 + 2015);
		restarted
			.getChainWatcher()!
			.emit('funding:missing', first.channelId, first.displayTxid);
		await tick(60);
		expect(
			restarted.getChannelManager().getChannel(first.channelId),
			'retained at 2015'
		).to.not.equal(undefined);

		restarted.handleNewBlock(700_000 + 2016);
		restarted
			.getChainWatcher()!
			.emit('funding:missing', first.channelId, first.displayTxid);
		await tick(60);
		expect(
			restarted.getChannelManager().getChannel(first.channelId),
			'forgotten at the boundary the FIRST process set'
		).to.equal(undefined);

		restarted.destroy();
	});

	it('a start that cannot be recorded does not begin', async function () {
		this.timeout(20_000);
		const storage = new SqliteStorage(':memory:');
		storage.open();
		const { funder, fundee, channelId, displayTxid } = await fundeeWithStorage(
			72,
			storage
		);

		// The disk refuses. A countdown toward destroying a channel must not
		// start from a height no restart can read back, so the fail-closed
		// direction is RETENTION: no clock, and ask again next time.
		const recovery = (
			fundee as unknown as {
				recovery: { commit: (...a: unknown[]) => unknown };
			}
		).recovery;
		const realCommit = recovery.commit.bind(recovery);
		recovery.commit = (): unknown => ({
			committed: false,
			released: [],
			frameSequence: null,
			error: new Error('disk full')
		});

		fundee.handleNewBlock(700_000);
		fundee.getChainWatcher()!.emit('funding:missing', channelId, displayTxid);
		await tick(60);
		const channel = fundee.getChannelManager().getChannel(channelId)!;
		expect(channel, 'retained').to.not.equal(undefined);
		expect(
			channel.fundingMissingSince(),
			'no clock was started from an unrecorded height'
		).to.equal(undefined);

		// The disk comes back and the next absence starts the clock for real,
		// at the height it is actually observed.
		recovery.commit = realCommit;
		fundee.handleNewBlock(700_050);
		fundee.getChainWatcher()!.emit('funding:missing', channelId, displayTxid);
		await tick(60);
		expect(channel.fundingMissingSince()).to.equal(700_050);

		funder.destroy();
		fundee.destroy();
	});

	it('a confirmed funding retires the clock durably', async function () {
		this.timeout(20_000);
		const dbPath = tempDb('forget-clock-confirmed');
		const storage1 = new SqliteStorage(dbPath);
		storage1.open();
		const first = await fundeeWithStorage(74, storage1);

		first.fundee.handleNewBlock(700_000);
		first.fundee
			.getChainWatcher()!
			.emit('funding:missing', first.channelId, first.displayTxid);
		await tick(60);
		expect(
			first.fundee
				.getChannelManager()
				.getChannel(first.channelId)!
				.fundingMissingSince()
		).to.equal(700_000);

		// Found after all. The clock stops, and stopping it is itself a state
		// change that has to reach disk: left there it keeps counting toward
		// voiding a channel whose funding is on the chain.
		first.fundee.getChainWatcher()!.emit('funding:confirmed', first.channelId);
		await tick(60);
		first.funder.destroy();
		first.fundee.destroy();

		const storage2 = new SqliteStorage(dbPath);
		storage2.open();
		const restarted = reopen(75, storage2);
		await tick(150);
		const restored = restarted.getChannelManager().getChannel(first.channelId);
		expect(
			restored!.fundingMissingSince(),
			'cleared clock stays cleared'
		).to.equal(undefined);

		// So an absence long after the original start begins a fresh clock
		// rather than landing past a boundary that was never running.
		restarted.handleNewBlock(700_000 + 2016);
		restarted
			.getChainWatcher()!
			.emit('funding:missing', first.channelId, first.displayTxid);
		await tick(60);
		expect(
			restarted.getChannelManager().getChannel(first.channelId),
			'not voided by a clock that had been retired'
		).to.not.equal(undefined);
		expect(restored!.fundingMissingSince()).to.equal(700_000 + 2016);

		restarted.destroy();
	});

	it('a guardian-only restore brings the clock back where it started', async function () {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(30_000);
		const secrets = [1, 2, 3].map((i) =>
			crypto.createHash('sha256').update(`forget-clock-guardian-${i}`).digest()
		);
		const ids = secrets.map((s) => xOnlyFromSecret(s));
		const setId = computeGuardianSetId({
			...CRASH_V1_PROFILE,
			guardianIds: ids
		});
		const context = { guardianSetId: setId, members: ids };
		let now = 2_000_000_000_000n;
		const clock = (): bigint => ++now;
		const served = await Promise.all(
			secrets.map(async (secret, index) => {
				const guardian = new ReferenceGuardian({
					path: ':memory:',
					guardianSecret: secret,
					members: ids,
					clock
				});
				const server = new GuardianHttpServer({ guardian });
				const port = await server.listen(0);
				return {
					guardian,
					server,
					bound: {
						client: new GuardianClient({
							url: `http://127.0.0.1:${port}`,
							guardianSetId: setId
						}),
						expectedGuardianId: ids[index]
					} as IBoundGuardianClient
				};
			})
		);
		const bound = served.map((s) => s.bound);
		const nodeSecret = nodeSecretFor(77);
		const recoveryRoot = deriveRecoveryRoot(nodeSecret);

		const storage1 = new SqliteStorage(':memory:');
		storage1.open();
		const first = await fundeeWithStorage(76, storage1);
		first.fundee.handleNewBlock(700_000);
		first.fundee
			.getChainWatcher()!
			.emit('funding:missing', first.channelId, first.displayTxid);
		await tick(60);

		// Everything this device journaled, including the frame the clock
		// started in, reaches the guardians.
		const replicator = new GuardianReplicator({
			storage: storage1,
			guardians: bound,
			context,
			required: CRASH_V1_PROFILE.required,
			recoveryRoot,
			clock
		});
		const decision = await replicator.ensureNamespace();
		await replicator.replicatePending(
			(decision as { lease: IWriterLeaseKeys }).lease
		);

		// The device is destroyed: process, database and all. Only the
		// guardians hold anything now.
		first.funder.destroy();
		first.fundee.destroy();
		storage1.close();

		const target = new SqliteStorage(':memory:');
		target.open();
		await new RestoreDriver({
			target,
			guardians: bound,
			context,
			required: CRASH_V1_PROFILE.required,
			recoveryRoot,
			nodeSecret,
			nodeId: getPublicKey(nodeSecret),
			clock
		}).restore();

		const revived = new LightningNode(
			makeNodeConfig(77, {
				storage: target,
				chainBackend: new ControlledBackend(),
				recovery: { enabled: true }
			})
		);
		revived.on('node:error', () => {});
		await tick(150);

		const restored = revived.getChannelManager().getChannel(first.channelId);
		expect(restored, 'the channel came back from the guardians').to.not.equal(
			undefined
		);
		expect(
			restored!.fundingMissingSince(),
			'and so did the height its clock started at'
		).to.equal(700_000);

		// The BOLT 2 boundary is the one the destroyed device set, not one
		// measured from the restore.
		revived.handleNewBlock(700_000 + 2015);
		revived
			.getChainWatcher()!
			.emit('funding:missing', first.channelId, first.displayTxid);
		await tick(60);
		expect(
			revived.getChannelManager().getChannel(first.channelId),
			'retained at 2015'
		).to.not.equal(undefined);

		revived.handleNewBlock(700_000 + 2016);
		revived
			.getChainWatcher()!
			.emit('funding:missing', first.channelId, first.displayTxid);
		await tick(60);
		expect(
			revived.getChannelManager().getChannel(first.channelId),
			'forgotten at the boundary the LOST device set'
		).to.equal(undefined);

		revived.destroy();
		target.close();
		for (const entry of served) {
			await entry.server.close();
			entry.guardian.close();
		}
	});
});
