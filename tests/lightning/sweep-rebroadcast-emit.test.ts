/**
 * Regression: the REBUILD_SWEEP -> broadcast:tx -> ChainWatcher path must put a
 * real serialized transaction on the wire.
 *
 * rebuildSweep() returns a bitcoin.Transaction, but every broadcast:tx listener
 * (ChainWatcher) expects a raw Buffer and does rawTx.toString('hex'). Emitting
 * the Transaction directly (FS-3) serialized to "[object Object]", the backend
 * rejected it, and the failure path then called Transaction.fromBuffer on the
 * Transaction and threw inside the .catch - an unhandled rejection that
 * re-crashed every ~6 blocks while a breach penalty was still pending, so the
 * RBF re-bump never reached the network.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import {
	ChainWatcher,
	IChainBackend
} from '../../src/lightning/chain/chain-watcher';
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import { ChainActionType } from '../../src/lightning/chain/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';

bitcoin.initEccLib(ecc);

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

class RecordingBackend implements IChainBackend {
	broadcasts: string[] = [];
	async subscribeToHeaders(): Promise<void> {}
	async subscribeToScriptHash(): Promise<void> {}
	async getScriptHashHistory(): Promise<
		Array<{ txid: string; height: number }>
	> {
		return [];
	}
	async getTransaction(): Promise<Buffer> {
		return Buffer.alloc(0);
	}
	async broadcastTransaction(rawTxHex: string): Promise<string> {
		this.broadcasts.push(rawTxHex);
		return bitcoin.Transaction.fromHex(rawTxHex).getId();
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

describe('FS-3: REBUILD_SWEEP broadcast path', () => {
	let backend: RecordingBackend;
	let cm: ChannelManager;
	let watcher: ChainWatcher;

	beforeEach(async () => {
		backend = new RecordingBackend();
		cm = new ChannelManager({
			localBasepoints: makeBasepoints(crypto.randomBytes(32)),
			localPerCommitmentSeed: crypto.randomBytes(32),
			localFundingPrivkey: crypto.randomBytes(32)
		});
		cm.on('error', () => {});
		watcher = new ChainWatcher({ backend, channelManager: cm });
		await watcher.start();
	});

	afterEach(() => watcher.stop());

	it('broadcasts the actual rebuilt sweep tx bytes, not "[object Object]"', async () => {
		const channelId = crypto.randomBytes(32);
		const rebuilt = makeSweepTx();
		// Stub the monitor so REBUILD_SWEEP returns a bitcoin.Transaction, exactly
		// as the real rebuildSweep does.
		(cm as unknown as { monitors: Map<string, unknown> }).monitors.set(
			channelId.toString('hex'),
			{ rebuildSweep: () => rebuilt }
		);

		(
			cm as unknown as {
				processChainActions: (id: Buffer, actions: unknown[]) => void;
			}
		).processChainActions(channelId, [
			{
				type: ChainActionType.REBUILD_SWEEP,
				output: { txid: 'ab'.repeat(32), outputIndex: 0 },
				feeRatePerVbyte: 25
			}
		]);
		await new Promise((resolve) => setTimeout(resolve, 30));

		expect(
			backend.broadcasts.length,
			'the rebuilt sweep was broadcast'
		).to.equal(1);
		expect(
			backend.broadcasts[0],
			'the exact serialized tx reached the backend'
		).to.equal(rebuilt.toHex());
	});

	it('drops a non-Buffer broadcast:tx payload without crashing', async () => {
		let failure: Error | null = null;
		watcher.on('broadcast:failure', (err: Error) => (failure = err));

		// A stray Transaction (not a Buffer) must be dropped loudly, not throw an
		// unhandled rejection inside the failure path.
		cm.emit('broadcast:tx', makeSweepTx() as unknown as Buffer);
		await new Promise((resolve) => setTimeout(resolve, 20));

		expect(backend.broadcasts.length, 'nothing garbled was broadcast').to.equal(
			0
		);
		expect(failure, 'a broadcast:failure was surfaced').to.not.be.null;
	});
});
