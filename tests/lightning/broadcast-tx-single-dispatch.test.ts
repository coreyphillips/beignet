/**
 * Regression: a broadcast:tx emitted by ChannelManager must reach the chain
 * backend exactly ONCE.
 *
 * ChainWatcher's constructor subscribes to broadcast:tx and owns the broadcast,
 * including the non-Buffer guard, the txid dedup and the block-driven retry
 * queue. LightningNode.wireChannelManagerEvents also subscribed to the same
 * event and called chainWatcher.broadcastTransaction itself, so every closing
 * tx, force-close commitment, sweep and CPFP child was sent to the backend
 * twice. The loser of that race came back "already in mempool", was queued for
 * MAX_BROADCAST_RETRIES blocks and surfaced as a permanent false
 * BROADCAST_FAILED node:error on the most fund-critical path in the library.
 *
 * The node now only relays the event; genuine failures are wired from the
 * watcher's own broadcast:failure.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { IChainBackend } from '../../src/lightning/chain/chain-watcher';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { ILightningError, INodeConfig } from '../../src/lightning/node/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { Network } from '../../src/lightning/invoice/types';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';

bitcoin.initEccLib(ecc);

function makeSeed(label: string): Buffer {
	return crypto.createHash('sha256').update(Buffer.from(label)).digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 6; i++) {
		keys.push(
			getPublicKey(
				crypto
					.createHash('sha256')
					.update(seed)
					.update(Buffer.from([i]))
					.digest()
			)
		);
	}
	return {
		fundingPubkey: keys[0],
		revocationBasepoint: keys[1],
		paymentBasepoint: keys[2],
		delayedPaymentBasepoint: keys[3],
		htlcBasepoint: keys[4],
		firstPerCommitmentPoint: keys[5]
	};
}

function makeNodeConfig(label: string): INodeConfig {
	const seed = makeSeed(label);
	return {
		nodePrivateKey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from('node-identity'))
			.digest(),
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(`${label}-per-commitment`),
		fundingPrivkey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([0]))
			.digest()
	};
}

/**
 * Records every raw tx handed to the backend. Mirrors a real mempool: a txid
 * already accepted is rejected on a second submission, which is what turned the
 * duplicate dispatch into a spurious failure.
 */
class MempoolBackend implements IChainBackend {
	broadcasts: string[] = [];
	private accepted: Set<string> = new Set();

	async subscribeToHeaders(): Promise<void> {}
	async subscribeToScriptHash(): Promise<void> {}
	async getScriptHashHistory(): Promise<
		Array<{ txid: string; height: number }>
	> {
		return [];
	}
	async getTransaction(): Promise<Buffer> {
		throw new Error('not used');
	}
	async broadcastTransaction(rawTxHex: string): Promise<string> {
		this.broadcasts.push(rawTxHex);
		const txid = bitcoin.Transaction.fromHex(rawTxHex).getId();
		if (this.accepted.has(txid)) {
			throw new Error('txn-already-in-mempool');
		}
		this.accepted.add(txid);
		return txid;
	}
}

function makeSweepTx(): bitcoin.Transaction {
	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.addInput(crypto.randomBytes(32), 0, 0xffffffff);
	tx.setWitness(0, [crypto.randomBytes(64)]);
	tx.addOutput(
		bitcoin.payments.p2wpkh({
			pubkey: getPublicKey(crypto.randomBytes(32)),
			network: bitcoin.networks.regtest
		}).output!,
		9_000
	);
	return tx;
}

describe('broadcast:tx single dispatch', () => {
	let node: LightningNode;
	let backend: MempoolBackend;
	let errors: ILightningError[];

	beforeEach(async () => {
		backend = new MempoolBackend();
		const config = makeNodeConfig('broadcast-single-dispatch');
		config.chainBackend = backend;
		node = new LightningNode(config);
		errors = [];
		node.on('node:error', (err: ILightningError) => errors.push(err));
		// Let the constructor's fire-and-forget chain watcher start settle.
		await new Promise((resolve) => setTimeout(resolve, 50));
	});

	afterEach(() => {
		node.destroy();
	});

	it('hands each emitted transaction to the backend exactly once', async () => {
		const tx = makeSweepTx();

		node.getChannelManager().emit('broadcast:tx', tx.toBuffer());
		await new Promise((resolve) => setTimeout(resolve, 30));

		expect(backend.broadcasts.length, 'exactly one broadcast').to.equal(1);
		expect(backend.broadcasts[0], 'the emitted tx bytes').to.equal(tx.toHex());
	});

	it('does not raise BROADCAST_FAILED for a transaction that broadcast fine', async () => {
		node.getChannelManager().emit('broadcast:tx', makeSweepTx().toBuffer());
		await new Promise((resolve) => setTimeout(resolve, 30));

		expect(
			errors.filter((e) => e.code === 'BROADCAST_FAILED'),
			'no spurious broadcast failure'
		).to.have.length(0);
	});

	it('relays broadcast:tx to node consumers', async () => {
		const relayed: Buffer[] = [];
		node.on('broadcast:tx', (tx: Buffer) => relayed.push(tx));

		const tx = makeSweepTx();
		node.getChannelManager().emit('broadcast:tx', tx.toBuffer());
		await new Promise((resolve) => setTimeout(resolve, 30));

		expect(relayed.length, 'consumers still see the event').to.equal(1);
		expect(relayed[0].toString('hex')).to.equal(tx.toHex());
	});

	it('still surfaces BROADCAST_FAILED when the backend genuinely rejects', async () => {
		const tx = makeSweepTx();
		// Pre-accept the txid so the real dispatch is rejected.
		await backend.broadcastTransaction(tx.toHex());
		backend.broadcasts.length = 0;

		node.getChannelManager().emit('broadcast:tx', tx.toBuffer());
		await new Promise((resolve) => setTimeout(resolve, 30));

		expect(backend.broadcasts.length, 'one attempt was made').to.equal(1);
		expect(
			errors.filter((e) => e.code === 'BROADCAST_FAILED'),
			'the genuine failure is still reported'
		).to.have.length(1);
	});
});
