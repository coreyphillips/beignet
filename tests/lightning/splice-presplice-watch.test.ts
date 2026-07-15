/**
 * Regression (FS-6): during an in-flight splice the OLD (pre-splice) funding
 * output must be watched for a hostile spend.
 *
 * restoreChainWatches used to watch ONLY the new splice outpoint on restart, and
 * its spend detection arms only once the splice tx confirms. So the old funding
 * output had no spend subscription: a peer that evicts our low-feerate splice
 * from the mempool and broadcasts a revoked pre-splice commitment spending the
 * old outpoint went undetected, and it could sweep the whole balance after its
 * to_self_delay. watchFundingSpendDuringSplice arms an immediate spend watch on
 * the old output, ignoring the splice tx itself.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import {
	ChainWatcher,
	IChainBackend,
	computeScriptHash
} from '../../src/lightning/chain/chain-watcher';
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';

bitcoin.initEccLib(ecc);

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const k: Buffer[] = [];
	for (let i = 0; i < 6; i++) {
		k.push(
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
		fundingPubkey: k[0],
		revocationBasepoint: k[1],
		paymentBasepoint: k[2],
		delayedPaymentBasepoint: k[3],
		htlcBasepoint: k[4],
		firstPerCommitmentPoint: k[5]
	};
}

class MockBackend implements IChainBackend {
	private cbs = new Map<string, Array<() => void>>();
	private history = new Map<string, Array<{ txid: string; height: number }>>();
	private txs = new Map<string, Buffer>();

	setHistory(sh: string, h: Array<{ txid: string; height: number }>): void {
		this.history.set(sh, h);
	}
	setTx(txid: string, raw: Buffer): void {
		this.txs.set(txid, raw);
	}
	fire(sh: string): void {
		for (const cb of this.cbs.get(sh) ?? []) cb();
	}
	async subscribeToHeaders(): Promise<void> {}
	async subscribeToScriptHash(sh: string, onChange: () => void): Promise<void> {
		const arr = this.cbs.get(sh) ?? [];
		arr.push(onChange);
		this.cbs.set(sh, arr);
	}
	async getScriptHashHistory(
		sh: string
	): Promise<Array<{ txid: string; height: number }>> {
		return this.history.get(sh) ?? [];
	}
	async getTransaction(txid: string): Promise<Buffer> {
		const t = this.txs.get(txid);
		if (!t) throw new Error(`no tx ${txid}`);
		return t;
	}
	async broadcastTransaction(): Promise<string> {
		return '';
	}
}

/** A tx spending (prevTxidDisplay:index). */
function spendOf(prevTxidDisplay: string, index: number): bitcoin.Transaction {
	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.addInput(Buffer.from(prevTxidDisplay, 'hex').reverse(), index);
	tx.addOutput(
		bitcoin.payments.p2wpkh({
			pubkey: getPublicKey(crypto.randomBytes(32)),
			network: bitcoin.networks.regtest
		}).output!,
		9_000
	);
	return tx;
}

describe('FS-6: pre-splice funding output spend watch', () => {
	let backend: MockBackend;
	let cm: ChannelManager;
	let watcher: ChainWatcher;

	beforeEach(async () => {
		backend = new MockBackend();
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

	it('ignores the splice tx but detects a revoked pre-splice commitment', async () => {
		const channelId = crypto.randomBytes(32);
		const oldFundingScript = bitcoin.payments.p2wsh({
			redeem: {
				output: bitcoin.script.compile([bitcoin.opcodes.OP_1])
			},
			network: bitcoin.networks.regtest
		}).output!;
		const scriptHash = computeScriptHash(oldFundingScript);
		const oldTxid = crypto.randomBytes(32).toString('hex');
		const oldIndex = 0;

		const spliceTx = spendOf(oldTxid, oldIndex);
		const spliceTxid = spliceTx.getId();
		backend.setTx(spliceTxid, spliceTx.toBuffer());

		const spent: bitcoin.Transaction[] = [];
		watcher.on('funding:spent', (_cid: Buffer, tx: bitcoin.Transaction) =>
			spent.push(tx)
		);

		await watcher.watchFundingSpendDuringSplice(
			channelId,
			oldTxid,
			oldIndex,
			oldFundingScript,
			spliceTxid
		);

		// The legitimate splice spends the old output: it must be IGNORED.
		backend.setHistory(scriptHash, [
			{ txid: oldTxid, height: 100 },
			{ txid: spliceTxid, height: 0 }
		]);
		backend.fire(scriptHash);
		await new Promise((r) => setTimeout(r, 30));
		expect(spent, 'splice tx is not treated as a breach').to.have.length(0);

		// The peer evicts the splice and broadcasts a revoked pre-splice commitment
		// spending the SAME old outpoint: it MUST be detected.
		const revokedTx = spendOf(oldTxid, oldIndex);
		const revokedTxid = revokedTx.getId();
		backend.setTx(revokedTxid, revokedTx.toBuffer());
		backend.setHistory(scriptHash, [
			{ txid: oldTxid, height: 100 },
			{ txid: revokedTxid, height: 0 }
		]);
		backend.fire(scriptHash);
		await new Promise((r) => setTimeout(r, 30));

		expect(spent, 'revoked pre-splice commitment detected').to.have.length(1);
		expect(spent[0].getId()).to.equal(revokedTxid);
	});
});
