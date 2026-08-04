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

	it('the obligation begins the moment funding_signed lands', async function () {
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
