/**
 * Durable funding transaction bytes on channel state (issue #1922, step 5a).
 *
 * A composite splice spends another channel's funding outpoint as an ordinary
 * interactive-tx input, and `tx_add_input` carries the whole previous
 * transaction, which a txid cannot reproduce. `IChannelState.fundingTxHex`
 * therefore keeps the transaction that created the current funding for the
 * channel's life: set when a v1 funder builds it or a v2 open is fully signed
 * (dual-funding-commitment.test.ts), replaced when a splice is adopted
 * (splice-lock-depth.test.ts), and filled from the chain by
 * `LightningNode.getFundingTxHex` for channels that never had it. These tests
 * pin the codec and the fill.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import {
	createOpenerState,
	IChannelState
} from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	serializeChannelState,
	deserializeChannelState
} from '../../src/lightning/storage/serialization';
import { IChainBackend } from '../../src/lightning/chain/chain-watcher';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import { MemoryStorage } from '../../src/lightning/storage/memory-storage';

const FUNDING_SATOSHIS = 1_000_000n;

function makeSeed(id: number): Buffer {
	return crypto.createHash('sha256').update(`funding-tx-hex-${id}`).digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const key = (i: number): Buffer =>
		crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([i]))
			.digest();
	return {
		fundingPubkey: getPublicKey(key(0)),
		revocationBasepoint: getPublicKey(key(1)),
		paymentBasepoint: getPublicKey(key(2)),
		delayedPaymentBasepoint: getPublicKey(key(3)),
		htlcBasepoint: getPublicKey(key(4)),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

function makeNodeConfig(
	seedId: number,
	extra: Partial<INodeConfig> = {}
): INodeConfig {
	const seed = makeSeed(seedId);
	return {
		nodePrivateKey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from('node-identity'))
			.digest(),
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([0]))
			.digest(),
		htlcBasepointSecret: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([4]))
			.digest(),
		...extra
	};
}

/** A backend that serves exactly the transactions it is given, counting asks. */
class ServingBackend implements IChainBackend {
	readonly asked: string[] = [];
	private readonly txs = new Map<string, Buffer>();
	constructor(private readonly down = false) {}
	/** Serve `tx` under `asId` (its own id unless the test lies on purpose). */
	serve(tx: bitcoin.Transaction, asId: string = tx.getId()): void {
		this.txs.set(asId, tx.toBuffer());
	}
	async subscribeToHeaders(): Promise<void> {}
	async subscribeToScriptHash(): Promise<void> {}
	async getScriptHashHistory(): Promise<
		Array<{ txid: string; height: number }>
	> {
		return [];
	}
	async getTransaction(txid: string): Promise<Buffer> {
		this.asked.push(txid);
		if (this.down) throw new Error('backend down');
		const tx = this.txs.get(txid);
		if (!tx) throw new Error(`unknown tx ${txid}`);
		return tx;
	}
	async broadcastTransaction(hex: string): Promise<string> {
		return bitcoin.Transaction.fromHex(hex).getId();
	}
}

function wire(a: LightningNode, b: LightningNode): void {
	a.on('message:outbound', (pubkey: string, type: number, payload: Buffer) => {
		if (pubkey === b.getNodeId())
			b.handlePeerMessage(a.getNodeId(), type, payload);
	});
	b.on('message:outbound', (pubkey: string, type: number, payload: Buffer) => {
		if (pubkey === a.getNodeId())
			a.handlePeerMessage(b.getNodeId(), type, payload);
	});
}

const tick = (ms = 30): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** A transaction with one P2WSH output, the shape a funding transaction has. */
function fundingTx(): bitcoin.Transaction {
	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.addInput(crypto.randomBytes(32), 0);
	tx.addOutput(
		Buffer.concat([Buffer.from([0x00, 0x20]), crypto.randomBytes(32)]),
		Number(FUNDING_SATOSHIS)
	);
	return tx;
}

describe('Durable funding transaction bytes (issue #1922 step 5a)', function () {
	this.timeout(10_000);

	describe('codec', function () {
		const state = (): ReturnType<typeof createOpenerState> =>
			createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: FUNDING_SATOSHIS,
				pushMsat: 0n,
				localConfig: DEFAULT_CHANNEL_CONFIG,
				localBasepoints: makeBasepoints(makeSeed(1)),
				localPerCommitmentSeed: makeSeed(2)
			});

		it('round-trips fundingTxHex and leaves it out when absent', () => {
			const tx = fundingTx();
			const row = serializeChannelState({
				...state(),
				fundingTxHex: tx.toHex()
			});
			expect(row.fundingTxHex).to.equal(tx.toHex());
			expect(deserializeChannelState(row).fundingTxHex).to.equal(tx.toHex());
			const bare = serializeChannelState(state());
			expect(bare.fundingTxHex).to.equal(undefined);
			expect(deserializeChannelState(bare).fundingTxHex).to.equal(undefined);
		});

		it('a row written before the field existed deserializes without it', () => {
			const row = serializeChannelState({
				...state(),
				fundingTxHex: fundingTx().toHex()
			});
			delete row.fundingTxHex;
			const legacy = JSON.parse(JSON.stringify(row));
			expect(deserializeChannelState(legacy).fundingTxHex).to.equal(undefined);
		});
	});

	describe('LightningNode.getFundingTxHex', function () {
		const nodes: LightningNode[] = [];
		afterEach(function () {
			for (const n of nodes.splice(0)) n.destroy();
		});

		function node(
			seedId: number,
			extra: Partial<INodeConfig> = {}
		): LightningNode {
			const n = new LightningNode(makeNodeConfig(seedId, extra));
			n.on('node:error', () => {});
			nodes.push(n);
			return n;
		}

		/**
		 * Alice funds a channel to Bob through createFunding, which carries the
		 * outpoint and no bytes, so neither side holds the transaction.
		 */
		function fund(
			alice: LightningNode,
			bob: LightningNode,
			tx: bitcoin.Transaction
		): Buffer {
			wire(alice, bob);
			const channelId = alice.createFunding(
				alice.openChannel(bob.getNodeId(), FUNDING_SATOSHIS),
				tx.getHash(),
				0,
				crypto.randomBytes(64)
			)!;
			alice.handleFundingConfirmed(channelId);
			bob.handleFundingConfirmed(channelId);
			return channelId;
		}

		const stateOf = (n: LightningNode, id: Buffer): Readonly<IChannelState> =>
			n.getRawChannel(id)!.getFullState();

		it('fetches the bytes once, checks them, persists them and serves them from state after', async function () {
			const tx = fundingTx();
			const storage = new MemoryStorage();
			const backend = new ServingBackend();
			backend.serve(tx);
			const alice = node(5001, { storage, chainBackend: backend });
			const bob = node(5002, { chainBackend: backend });
			const channelId = fund(alice, bob, tx);
			await tick();
			for (const n of [alice, bob]) {
				expect(stateOf(n, channelId).state).to.equal(ChannelState.NORMAL);
				expect(
					stateOf(n, channelId).fundingTxHex,
					'createFunding carries no bytes'
				).to.equal(undefined);
			}

			expect(await alice.getFundingTxHex(channelId)).to.equal(tx.toHex());
			expect(stateOf(alice, channelId).fundingTxHex).to.equal(tx.toHex());
			expect(backend.asked).to.deep.equal([tx.getId()]);
			expect(
				storage.loadChannel(channelId.toString('hex'))!.state.fundingTxHex,
				'the fill was persisted with the row'
			).to.equal(tx.toHex());

			expect(await alice.getFundingTxHex(channelId)).to.equal(tx.toHex());
			expect(backend.asked, 'served from state the second time').to.have.length(
				1
			);

			// The fundee, which only ever saw the outpoint, fills the same way.
			expect(await bob.getFundingTxHex(channelId)).to.equal(tx.toHex());
			expect(stateOf(bob, channelId).fundingTxHex).to.equal(tx.toHex());

			// A restart reads it back from the row.
			alice.removeAllListeners('message:outbound');
			const restarted = node(5001, { storage });
			expect(stateOf(restarted, channelId).fundingTxHex).to.equal(tx.toHex());
		});

		it('answers null and writes nothing when the backend serves another transaction, fails or is missing, and for an unknown channel', async function () {
			const tx = fundingTx();
			const lying = new ServingBackend();
			// Another transaction under the funding's id: the hash check refuses it.
			lying.serve(fundingTx(), tx.getId());
			const alice = node(5003, { chainBackend: lying });
			const bob = node(5004);
			const channelId = fund(alice, bob, tx);
			await tick();

			expect(await alice.getFundingTxHex(channelId)).to.equal(null);
			expect(lying.asked).to.deep.equal([tx.getId()]);
			expect(stateOf(alice, channelId).fundingTxHex).to.equal(undefined);
			expect(await bob.getFundingTxHex(channelId), 'no backend').to.equal(null);
			expect(
				await alice.getFundingTxHex(crypto.randomBytes(32)),
				'unknown channel'
			).to.equal(null);

			const down = node(5005, { chainBackend: new ServingBackend(true) });
			const carol = node(5006);
			const second = fund(down, carol, tx);
			await tick();
			expect(await down.getFundingTxHex(second), 'backend failure').to.equal(
				null
			);
			expect(stateOf(down, second).fundingTxHex).to.equal(undefined);

			let rejected: unknown = null;
			await alice.getFundingTxHex(Buffer.alloc(3)).catch((e) => {
				rejected = e;
			});
			expect(String(rejected)).to.match(/channelId/);
		});
	});
});
