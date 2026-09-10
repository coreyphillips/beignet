/**
 * Splice conflict recovery (issue #760).
 *
 * A depth-locked splice may carry an input this node does not vouch for (a
 * stranger's direct funding into a zero-conf channel). If the stranger spends
 * that input elsewhere and the spend confirms, the splice can never confirm,
 * BOLT 2 offers no abort past tx_signatures and beignet has no splice RBF, so
 * the channel would sit mid-splice forever. The recovery: the chain watcher
 * notices the competing spend at depth, the node puts it to the peer, each
 * side verifies against its own chain view, and both revert to the pre-splice
 * funding they still hold valid commitments for.
 *
 * Covered here: the watcher's verdict (at depth, not before, never for the
 * splice itself, never on mempool evidence, once), the independent verifier,
 * the channel's revert and its refusals, the durable conflict record, HTLC
 * traffic through a revert on a manager pair, the whole exchange between two
 * nodes over loopback (agreement, refusal and retry, restart mid-conflict),
 * and the direct-funding receiver failing the request behind the splice.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import * as bitcoin from 'bitcoinjs-lib';
import { createFundingScript } from '../../src/lightning/script/funding';
import * as ecc from '@bitcoinerlab/secp256k1';
import {
	ChainWatcher,
	IChainBackend,
	SPLICE_CONFLICT_DEPTH,
	computeScriptHash
} from '../../src/lightning/chain/chain-watcher';
import {
	Channel,
	REVERTED_SPLICES_KEPT
} from '../../src/lightning/channel/channel';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import {
	createOpenerState,
	ISpliceInFlight
} from '../../src/lightning/channel/channel-state';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	HtlcState
} from '../../src/lightning/channel/types';
import {
	deserializeChannelState,
	serializeChannelState
} from '../../src/lightning/storage/serialization';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	LightningNode,
	SPLICE_CONFLICT_REQUEST_BACKOFF_MS
} from '../../src/lightning/node/lightning-node';
import { MessageType } from '../../src/lightning/message/types';
import { QuiescenceState } from '../../src/lightning/channel/quiescence';
import { INodeConfig } from '../../src/lightning/node/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { Network } from '../../src/lightning/invoice/types';
import {
	BEIGNET_CUSTOM_MESSAGE_TYPE,
	BeignetCustomSubtype,
	decodeCustomMessage
} from '../../src/lightning/message/custom';
import {
	decodeSpliceConflictAck,
	encodeSpliceConflict
} from '../../src/lightning/message/splice-conflict';
import { encodeCustomMessage } from '../../src/lightning/message/custom';
import { DirectFundingReceiver } from '../../src/lightning/direct-funding/receiver/engine';
import {
	buildOffer,
	FakeDfNode,
	FakePayerLane,
	flush,
	LSP_PUBKEY,
	makeCoin
} from './helpers/df-receiver';

bitcoin.initEccLib(ecc);

const tick = (ms = 40): Promise<void> => new Promise((r) => setTimeout(r, ms));
const display = (b: Buffer): string => Buffer.from(b).reverse().toString('hex');

// ─────────────── Shared fixtures ───────────────

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`splice-input-conflict-${id}`))
		.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
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
	return {
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

/** A P2WPKH coin: the stranger's input. */
function makeCoinTx(valueSats: number): {
	tx: bitcoin.Transaction;
	script: Buffer;
	privkey: Buffer;
} {
	const privkey = crypto.randomBytes(32);
	const script = bitcoin.payments.p2wpkh({
		pubkey: Buffer.from(ecc.pointFromScalar(privkey, true)!),
		network: bitcoin.networks.regtest
	}).output!;
	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.addInput(crypto.randomBytes(32), 0);
	tx.addOutput(script, valueSats);
	return { tx, script, privkey };
}

/** A transaction spending the given outpoint (display txid) to a fresh key. */
function spendOf(prevTxidDisplay: string, vout: number): bitcoin.Transaction {
	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.addInput(Buffer.from(prevTxidDisplay, 'hex').reverse(), vout);
	tx.addOutput(
		bitcoin.payments.p2wpkh({
			pubkey: getPublicKey(crypto.randomBytes(32)),
			network: bitcoin.networks.regtest
		}).output!,
		9_000
	);
	tx.ins[0].witness = [Buffer.alloc(72, 1), Buffer.alloc(33, 2)];
	return tx;
}

/**
 * A signed-looking splice: input 0 spends the old funding (shared), input 1
 * the stranger's coin, output 0 the new funding.
 */
function spliceTxFor(
	oldFundingTxid: Buffer,
	oldFundingIndex: number,
	coin: bitcoin.Transaction
): bitcoin.Transaction {
	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.addInput(Buffer.from(oldFundingTxid), oldFundingIndex);
	tx.addInput(Buffer.from(coin.getHash()), 0);
	tx.addOutput(
		bitcoin.payments.p2wsh({
			redeem: { output: bitcoin.script.compile([bitcoin.opcodes.OP_TRUE]) }
		}).output!,
		1_040_000
	);
	tx.ins[0].witness = [
		Buffer.alloc(72, 1),
		Buffer.alloc(72, 2),
		Buffer.alloc(71, 3)
	];
	tx.ins[1].witness = [Buffer.alloc(72, 4), Buffer.alloc(33, 5)];
	return tx;
}

function inflightFor(
	spliceTx: bitcoin.Transaction,
	coinScript: Buffer,
	options: { lockAtDepth?: number; external?: boolean } = {}
): ISpliceInFlight {
	return {
		spliceTxid: Buffer.from(spliceTx.getHash()),
		newFundingOutputIndex: 0,
		newFundingSatoshis: 1_040_000n,
		spliceTxHex: spliceTx.toHex(),
		fullySigned: true,
		isInitiator: true,
		localRelativeSatoshis: 40_000n,
		remoteRelativeSatoshis: 0n,
		remoteFundingPubkey: makeBasepoints(Buffer.alloc(32, 9)).fundingPubkey,
		ourSharedInputSig: Buffer.alloc(64),
		ourWalletWitnesses: [[]],
		ourWalletInputIndices: [1],
		externalInputIndices: options.external === false ? undefined : [1],
		inputPrevouts: [
			{ script: Buffer.alloc(34, 0xaa), valueSats: 1_000_000n },
			{ script: coinScript, valueSats: 50_000n }
		],
		remoteCommitmentSig: crypto.randomBytes(64),
		sentTxSignatures: true,
		receivedTxSignatures: true,
		localSpliceLocked: false,
		remoteSpliceLocked: false,
		confirmed: false,
		lockAtDepth: options.lockAtDepth ?? 2
	};
}

// ─────────────── A. Chain watcher ───────────────

class MockBackend implements IChainBackend {
	private headerCbs: Array<(height: number) => void> = [];
	private history = new Map<string, Array<{ txid: string; height: number }>>();
	private txs = new Map<string, Buffer>();
	broadcasts: string[] = [];
	fetched: string[] = [];

	setHistory(sh: string, h: Array<{ txid: string; height: number }>): void {
		this.history.set(sh, h);
	}
	setTx(tx: bitcoin.Transaction): void {
		this.txs.set(tx.getId(), tx.toBuffer());
	}
	block(height: number): void {
		for (const cb of [...this.headerCbs]) cb(height);
	}
	async subscribeToHeaders(cb: (height: number) => void): Promise<void> {
		this.headerCbs.push(cb);
	}
	async subscribeToScriptHash(): Promise<void> {}
	async getScriptHashHistory(
		sh: string
	): Promise<Array<{ txid: string; height: number }>> {
		return this.history.get(sh) ?? [];
	}
	async getTransaction(txid: string): Promise<Buffer> {
		this.fetched.push(txid);
		const t = this.txs.get(txid);
		if (!t) throw new Error(`no tx ${txid}`);
		return t;
	}
	async broadcastTransaction(hex: string): Promise<string> {
		this.broadcasts.push(hex);
		return bitcoin.Transaction.fromHex(hex).getId();
	}
}

describe('Splice input conflict watch (issue #760)', function () {
	let backend: MockBackend;
	let cm: ChannelManager;
	let watcher: ChainWatcher;
	const channelId = crypto.randomBytes(32);

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

	function fixture(): {
		coin: bitcoin.Transaction;
		coinScript: Buffer;
		scriptHash: string;
		spliceTx: bitcoin.Transaction;
		conflict: bitcoin.Transaction;
		events: Array<{
			spliceTxid: string;
			conflictTxid: string;
			inputIndex: number;
			height: number;
		}>;
	} {
		const { tx: coin, script: coinScript } = makeCoinTx(50_000);
		const spliceTx = spliceTxFor(crypto.randomBytes(32), 0, coin);
		const conflict = spendOf(coin.getId(), 0);
		backend.setTx(coin);
		backend.setTx(spliceTx);
		backend.setTx(conflict);
		const events: Array<{
			spliceTxid: string;
			conflictTxid: string;
			inputIndex: number;
			height: number;
		}> = [];
		watcher.on(
			'splice:input-conflict',
			(
				cid: Buffer,
				spliceTxid: string,
				conflictTxid: string,
				inputIndex: number,
				height: number
			) => {
				expect(cid.equals(channelId)).to.equal(true);
				events.push({ spliceTxid, conflictTxid, inputIndex, height });
			}
		);
		watcher.watchSpliceInput(channelId, spliceTx.getId(), {
			txid: coin.getId(),
			vout: 0,
			script: coinScript,
			inputIndex: 1
		});
		return {
			coin,
			coinScript,
			scriptHash: computeScriptHash(coinScript),
			spliceTx,
			conflict,
			events
		};
	}

	it('reports a competing spend once it is SPLICE_CONFLICT_DEPTH deep, and not before', async () => {
		const f = fixture();
		expect(SPLICE_CONFLICT_DEPTH).to.equal(6);
		backend.setHistory(f.scriptHash, [
			{ txid: f.coin.getId(), height: 100 },
			{ txid: f.spliceTx.getId(), height: 0 },
			{ txid: f.conflict.getId(), height: 150 }
		]);
		for (let h = 150; h < 155; h++) {
			backend.block(h);
			await tick();
			expect(f.events, `depth ${h - 150 + 1} is not a verdict`).to.have.length(
				0
			);
		}
		backend.block(155);
		await tick();
		expect(f.events).to.deep.equal([
			{
				spliceTxid: f.spliceTx.getId(),
				conflictTxid: f.conflict.getId(),
				inputIndex: 1,
				height: 150
			}
		]);
		// Once per watch: later blocks say nothing new, and the transaction
		// was fetched a single time.
		backend.block(156);
		backend.block(157);
		await tick();
		expect(f.events).to.have.length(1);
		expect(
			backend.fetched.filter((t) => t === f.conflict.getId())
		).to.have.length(1);
		expect(watcher.spliceInputWatchesFor(channelId)).to.have.length(1);
	});

	it('is silent when the only other spender is in the mempool, and when the splice itself confirmed', async () => {
		const f = fixture();
		backend.setHistory(f.scriptHash, [
			{ txid: f.coin.getId(), height: 100 },
			{ txid: f.conflict.getId(), height: 0 }
		]);
		backend.block(160);
		await tick();
		expect(
			f.events,
			'mempool conflict is a warning, not a verdict'
		).to.have.length(0);
		expect(
			backend.fetched,
			'nothing fetched for a mempool entry'
		).to.deep.equal([]);

		// The splice won: it sits confirmed, the "conflict" entry is stale
		// evidence (a server showing both is a reorg in progress) and must not
		// produce a verdict against the transaction on chain.
		backend.setHistory(f.scriptHash, [
			{ txid: f.coin.getId(), height: 100 },
			{ txid: f.spliceTx.getId(), height: 140 },
			{ txid: f.conflict.getId(), height: 141 }
		]);
		backend.block(170);
		await tick();
		expect(f.events).to.have.length(0);
	});

	it('ignores a confirmed transaction on the script that does not spend the watched outpoint', async () => {
		const f = fixture();
		// Same script, different outpoint: the stranger reusing an address.
		const unrelated = spendOf(crypto.randomBytes(32).toString('hex'), 0);
		unrelated.addOutput(f.coinScript, 1_000);
		backend.setTx(unrelated);
		backend.setHistory(f.scriptHash, [
			{ txid: f.coin.getId(), height: 100 },
			{ txid: unrelated.getId(), height: 120 }
		]);
		backend.block(140);
		await tick();
		expect(f.events).to.have.length(0);
	});

	it('re-emits only when the chain names a different spender, and unwatch stops it', async () => {
		const f = fixture();
		backend.setHistory(f.scriptHash, [
			{ txid: f.coin.getId(), height: 100 },
			{ txid: f.conflict.getId(), height: 150 }
		]);
		backend.block(155);
		await tick();
		expect(f.events).to.have.length(1);
		const other = spendOf(f.coin.getId(), 0);
		backend.setTx(other);
		backend.setHistory(f.scriptHash, [
			{ txid: f.coin.getId(), height: 100 },
			{ txid: other.getId(), height: 151 }
		]);
		backend.block(156);
		await tick();
		expect(f.events).to.have.length(2);
		expect(f.events[1].conflictTxid).to.equal(other.getId());
		watcher.unwatchSpliceInputs(channelId, f.spliceTx.getId());
		expect(watcher.spliceInputWatchesFor(channelId)).to.have.length(0);
		backend.setHistory(f.scriptHash, [
			{ txid: f.coin.getId(), height: 100 },
			{ txid: f.conflict.getId(), height: 150 }
		]);
		backend.block(157);
		await tick();
		expect(f.events).to.have.length(2);
	});

	it('re-emits a verdict once the sighting that refused it is retracted (issue #776)', async () => {
		const f = fixture();
		// The splice is also the channel's funding watch, seen in a block
		// with its lock depth still ahead.
		const spliceFundingScript = Buffer.from('0020' + 'ab'.repeat(32), 'hex');
		const fundingHash = computeScriptHash(spliceFundingScript);
		backend.setHistory(fundingHash, [
			{ txid: f.spliceTx.getId(), height: 100 }
		]);
		const unseen: string[] = [];
		watcher.on('funding:unseen', (_id: Buffer, txid: string) =>
			unseen.push(txid)
		);
		await watcher.watchFundingOutput(
			channelId,
			f.spliceTx.getId(),
			0,
			100,
			spliceFundingScript
		);
		backend.setHistory(f.scriptHash, [
			{ txid: f.coin.getId(), height: 100 },
			{ txid: f.conflict.getId(), height: 150 }
		]);
		backend.block(155);
		await tick();
		expect(f.events).to.have.length(1);
		backend.block(156);
		await tick();
		expect(f.events, 'the same spender is not repeated').to.have.length(1);

		// A reorg takes the splice back to the mempool. The sighting that let
		// the listener refuse the verdict is retracted, and the verdict must
		// come again for it.
		backend.setHistory(fundingHash, [{ txid: f.spliceTx.getId(), height: 0 }]);
		backend.block(157);
		await tick();
		expect(unseen).to.deep.equal([f.spliceTx.getId()]);
		backend.block(158);
		await tick();
		expect(f.events, 're-emitted after the retraction').to.have.length(2);
		expect(f.events[1].conflictTxid).to.equal(f.conflict.getId());
		backend.block(159);
		await tick();
		expect(f.events, 'and latched again').to.have.length(2);
	});

	it('verifySpliceInputConflict checks the spender, the depth, the splice and never the shared input', async () => {
		const f = fixture();
		backend.setHistory(f.scriptHash, [
			{ txid: f.coin.getId(), height: 100 },
			{ txid: f.conflict.getId(), height: 150 }
		]);
		backend.block(155);
		await tick();
		const ok = await watcher.verifySpliceInputConflict(
			f.spliceTx.toHex(),
			f.conflict.getId(),
			0
		);
		expect(ok).to.deep.equal({ inputIndex: 1, height: 150, depth: 6 });

		// Too shallow.
		backend.block(154);
		expect(
			await watcher.verifySpliceInputConflict(
				f.spliceTx.toHex(),
				f.conflict.getId(),
				0
			)
		).to.equal(null);
		backend.block(155);

		// Spends the SHARED funding input only: a commitment, not a conflict.
		const oldFundingTxid = display(f.spliceTx.ins[0].hash);
		const commitment = spendOf(oldFundingTxid, 0);
		backend.setTx(commitment);
		expect(
			await watcher.verifySpliceInputConflict(
				f.spliceTx.toHex(),
				commitment.getId(),
				0
			)
		).to.equal(null);

		// The splice itself is never its own conflict.
		expect(
			await watcher.verifySpliceInputConflict(
				f.spliceTx.toHex(),
				f.spliceTx.getId(),
				0
			)
		).to.equal(null);

		// A spender the history does not confirm.
		backend.setHistory(f.scriptHash, [
			{ txid: f.coin.getId(), height: 100 },
			{ txid: f.conflict.getId(), height: 0 }
		]);
		expect(
			await watcher.verifySpliceInputConflict(
				f.spliceTx.toHex(),
				f.conflict.getId(),
				0
			)
		).to.equal(null);

		// The splice confirmed: the claim is refuted by the chain.
		backend.setHistory(f.scriptHash, [
			{ txid: f.coin.getId(), height: 100 },
			{ txid: f.spliceTx.getId(), height: 149 },
			{ txid: f.conflict.getId(), height: 150 }
		]);
		expect(
			await watcher.verifySpliceInputConflict(
				f.spliceTx.toHex(),
				f.conflict.getId(),
				0
			)
		).to.equal(null);

		// An unknown transaction is a transport failure, not a refutation.
		let threw = false;
		try {
			await watcher.verifySpliceInputConflict(
				f.spliceTx.toHex(),
				crypto.randomBytes(32).toString('hex'),
				0
			);
		} catch {
			threw = true;
		}
		expect(threw).to.equal(true);
	});
});

// ─────────────── B. Channel ───────────────

function splicingChannel(options: { conflict?: boolean } = {}): {
	channel: Channel;
	spliceTx: bitcoin.Transaction;
	oldFundingTxid: Buffer;
} {
	const state = createOpenerState({
		temporaryChannelId: crypto.randomBytes(32),
		fundingSatoshis: 1_000_000n,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(Buffer.alloc(32, 1)),
		localPerCommitmentSeed: Buffer.alloc(32, 3)
	});
	state.state = ChannelState.SPLICING;
	state.preSpliceState = ChannelState.NORMAL;
	state.channelId = crypto.randomBytes(32);
	state.fundingTxid = crypto.randomBytes(32);
	state.fundingOutputIndex = 1;
	state.minimumDepth = 3;
	state.remoteBasepoints = makeBasepoints(Buffer.alloc(32, 2));
	const { tx: coin, script } = makeCoinTx(50_000);
	const spliceTx = spliceTxFor(state.fundingTxid, 1, coin);
	state.spliceInFlight = inflightFor(spliceTx, script);
	state.spliceFundingTxid = Buffer.from(spliceTx.getHash());
	state.spliceFundingOutputIndex = 0;
	state.preSpliceSpendWatches = [
		{
			txid: display(state.fundingTxid),
			outputIndex: 1,
			script: Buffer.alloc(34, 0xaa).toString('hex'),
			spliceTxid: spliceTx.getId()
		}
	];
	state.unconfirmedSpliceTxs = [
		{ txid: Buffer.from(spliceTx.getHash()), txHex: spliceTx.toHex() }
	];
	const channel = new Channel(state);
	if (options.conflict !== false) {
		expect(
			channel.markSpliceConflicted({
				txid: spendOf(coin.getId(), 0).getId(),
				height: 150,
				inputIndex: 1
			})
		).to.equal(true);
	}
	return { channel, spliceTx, oldFundingTxid: state.fundingTxid };
}

describe('Channel splice revert (issue #760)', function () {
	it('revert restores the pre-splice channel and re-watches the old funding', () => {
		const { channel, spliceTx, oldFundingTxid } = splicingChannel();
		expect(channel.isSplicePendingLock()).to.equal(true);
		const conflictTxid = channel.getFullState().spliceInFlight!.conflict!.txid;
		const actions = channel.revertConflictedSplice();
		expect(actions.map((a) => a.type)).to.deep.equal([
			ChannelActionType.PERSIST_STATE,
			ChannelActionType.WATCH_FUNDING,
			ChannelActionType.SPLICE_REVERTED
		]);
		const watch = actions[1] as {
			fundingTxid: Buffer;
			fundingOutputIndex: number;
			minimumDepth: number;
			rearm?: boolean;
		};
		expect(watch.fundingTxid.equals(oldFundingTxid)).to.equal(true);
		expect(watch.fundingOutputIndex).to.equal(1);
		expect(watch.minimumDepth).to.equal(3);
		expect(watch.rearm).to.equal(true);
		const reverted = actions[2] as { spliceTxid: string; conflictTxid: string };
		expect(reverted.spliceTxid).to.equal(spliceTx.getId());
		expect(reverted.conflictTxid).to.equal(conflictTxid);

		const state = channel.getFullState();
		expect(state.state).to.equal(ChannelState.NORMAL);
		expect(state.preSpliceState).to.equal(null);
		expect(state.spliceInFlight).to.equal(null);
		expect(state.spliceFundingTxid).to.equal(null);
		expect(state.spliceFundingOutputIndex).to.equal(0);
		expect(state.fundingTxid!.equals(oldFundingTxid)).to.equal(true);
		expect(state.preSpliceSpendWatches).to.equal(undefined);
		expect(state.unconfirmedSpliceTxs).to.deep.equal([]);
		expect(channel.getSpliceSession()).to.equal(null);
		expect(channel.isQuiescent()).to.equal(false);
		expect(channel.isHtlcUsable()).to.equal(true);
		expect(channel.buildSpliceRebroadcastActions()).to.have.length(0);
		// The revert is remembered durably, with the material a too-deep
		// reorg would need to close the new funding.
		expect(state.revertedSplices).to.have.length(1);
		const kept = state.revertedSplices![0];
		expect(kept.spliceTxid).to.equal(spliceTx.getId());
		expect(kept.conflictTxid).to.equal(conflictTxid);
		expect(kept.spliceTxHex).to.equal(spliceTx.toHex());
		expect(kept.newFundingOutputIndex).to.equal(0);
		expect(kept.remoteFundingPubkey).to.equal(
			makeBasepoints(Buffer.alloc(32, 9)).fundingPubkey.toString('hex')
		);
		expect(kept.remoteCommitmentSig).to.be.a('string').with.length(128);
		expect(kept.revertedAt).to.be.a('number');
		expect(channel.hasRevertedSplice(spliceTx.getId())).to.equal(true);
		expect(channel.hasRevertedSplice('00'.repeat(32))).to.equal(false);
		// Nothing left to revert.
		expect(channel.revertConflictedSplice()[0].type).to.equal(
			ChannelActionType.ERROR
		);
	});

	it('the reverted-splice memory is bounded to the newest entries', () => {
		const { channel } = splicingChannel();
		const seen: string[] = [];
		for (let i = 0; i < REVERTED_SPLICES_KEPT + 3; i++) {
			const state = channel.getFullState();
			if (!state.spliceInFlight) {
				// Graft the next conflicted splice the way the previous one sat.
				const { tx: coin, script } = makeCoinTx(50_000 + i);
				const next = spliceTxFor(state.fundingTxid!, 1, coin);
				state.state = ChannelState.SPLICING;
				state.preSpliceState = ChannelState.NORMAL;
				state.spliceInFlight = inflightFor(next, script);
				channel.markSpliceConflicted({
					txid: spendOf(coin.getId(), 0).getId(),
					height: 150 + i,
					inputIndex: 1
				});
			}
			seen.push(display(channel.getFullState().spliceInFlight!.spliceTxid));
			expect(channel.revertConflictedSplice()[2].type).to.equal(
				ChannelActionType.SPLICE_REVERTED
			);
		}
		const kept = channel.getFullState().revertedSplices!;
		expect(kept).to.have.length(REVERTED_SPLICES_KEPT);
		expect(kept.map((r) => r.spliceTxid)).to.deep.equal(
			seen.slice(-REVERTED_SPLICES_KEPT)
		);
		expect(
			channel.hasRevertedSplice(seen[0]),
			'the oldest is forgotten'
		).to.equal(false);
	});

	it('the reverted-splice memory round-trips through the serialized state', () => {
		const { channel, spliceTx } = splicingChannel();
		channel.getFullState().spliceInFlight!.remoteHtlcSignatures = [
			crypto.randomBytes(64)
		];
		channel.getFullState().spliceInFlight!.remoteCommitmentSigFeeratePerKw = 1234;
		channel.revertConflictedSplice();
		const before = channel.getFullState().revertedSplices!;
		const restored = deserializeChannelState(
			JSON.parse(JSON.stringify(serializeChannelState(channel.getFullState())))
		);
		expect(restored.revertedSplices).to.deep.equal(before);
		expect(restored.revertedSplices![0].remoteHtlcSignatures).to.have.length(1);
		expect(
			restored.revertedSplices![0].remoteCommitmentSigFeeratePerKw
		).to.equal(1234);
		expect(new Channel(restored).hasRevertedSplice(spliceTx.getId())).to.equal(
			true
		);
		// Rows written before the field existed read as empty.
		const legacy = serializeChannelState(channel.getFullState());
		delete (legacy as { revertedSplices?: unknown }).revertedSplices;
		expect(deserializeChannelState(legacy).revertedSplices).to.deep.equal([]);
	});

	it('refuses without a conflict, once confirmed, once locked, and outside SPLICING', () => {
		const clean = splicingChannel({ conflict: false });
		expect(
			(clean.channel.revertConflictedSplice()[0] as { message: string }).message
		).to.match(/not conflicted/);

		const confirmed = splicingChannel();
		confirmed.channel.markSpliceConfirmed();
		expect(
			(confirmed.channel.revertConflictedSplice()[0] as { message: string })
				.message
		).to.match(/confirmed/);

		const locked = splicingChannel();
		locked.channel.getFullState().spliceInFlight!.localSpliceLocked = true;
		expect(
			(locked.channel.revertConflictedSplice()[0] as { message: string })
				.message
		).to.match(/splice_locked already sent/);

		const adopted = splicingChannel();
		adopted.channel.getFullState().state = ChannelState.NORMAL;
		expect(
			(adopted.channel.revertConflictedSplice()[0] as { message: string })
				.message
		).to.match(/not SPLICING/);
	});

	it('markSpliceConflicted refuses a confirmed or locked splice and dedupes by txid', () => {
		const { channel } = splicingChannel({ conflict: false });
		const conflict = { txid: 'ab'.repeat(32), height: 150, inputIndex: 1 };
		expect(channel.markSpliceConflicted(conflict)).to.equal(true);
		expect(channel.markSpliceConflicted(conflict), 'same txid').to.equal(false);
		expect(
			channel.markSpliceConflicted({ ...conflict, txid: 'cd'.repeat(32) }),
			'a different spender updates the record'
		).to.equal(true);
		channel.markSpliceConfirmed();
		expect(
			channel.markSpliceConflicted({ ...conflict, txid: 'ef'.repeat(32) })
		).to.equal(false);
		const locked = splicingChannel({ conflict: false });
		locked.channel.getFullState().spliceInFlight!.localSpliceLocked = true;
		expect(locked.channel.markSpliceConflicted(conflict)).to.equal(false);
	});

	it('the conflict record and its request stamp survive serialization', () => {
		const { channel } = splicingChannel();
		channel.noteSpliceConflictRequest(1_700_000_000_000);
		const before = channel.getFullState().spliceInFlight!.conflict!;
		const restored = deserializeChannelState(
			JSON.parse(JSON.stringify(serializeChannelState(channel.getFullState())))
		);
		expect(restored.spliceInFlight!.conflict).to.deep.equal({
			txid: before.txid,
			height: 150,
			inputIndex: 1,
			revertRequestedAt: 1_700_000_000_000
		});
		expect(restored.spliceInFlight!.lockAtDepth).to.equal(2);
		// A restored channel can still revert.
		const again = new Channel(restored);
		expect(again.revertConflictedSplice()[2].type).to.equal(
			ChannelActionType.SPLICE_REVERTED
		);
		// Older rows carry no conflict.
		const legacy = serializeChannelState(channel.getFullState());
		delete (legacy.spliceInFlight as { conflict?: unknown }).conflict;
		expect(deserializeChannelState(legacy).spliceInFlight!.conflict).to.equal(
			undefined
		);
	});

	it('a disconnected channel reverts through its wrapped state', () => {
		const { channel, oldFundingTxid } = splicingChannel();
		const state = channel.getFullState();
		state.preReestablishState = ChannelState.SPLICING;
		state.state = ChannelState.AWAITING_REESTABLISH;
		const actions = channel.revertConflictedSplice();
		expect(actions[2].type).to.equal(ChannelActionType.SPLICE_REVERTED);
		expect(state.state).to.equal(ChannelState.AWAITING_REESTABLISH);
		expect(state.preReestablishState).to.equal(ChannelState.NORMAL);
		expect(state.spliceInFlight).to.equal(null);
		expect(state.fundingTxid!.equals(oldFundingTxid)).to.equal(true);
	});

	it('getSpliceSharedInputIndex names the funding input of the in-flight splice', () => {
		const { channel } = splicingChannel();
		expect(channel.getSpliceSharedInputIndex()).to.equal(0);
		channel.revertConflictedSplice();
		expect(channel.getSpliceSharedInputIndex()).to.equal(null);
	});
});

// ─────────────── Manager pair: HTLCs through a revert ───────────────

function makeConfig(seedId: number): IChannelManagerConfig {
	const seed = makeSeed(seedId);
	return {
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(seed),
		localPerCommitmentSeed: makeSeed(seedId + 100),
		localFundingPrivkey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([0]))
			.digest(),
		htlcBasepointSecret: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([4]))
			.digest()
	};
}

function connectManagers(
	a: ChannelManager,
	aPubkey: string,
	b: ChannelManager,
	bPubkey: string
): void {
	a.on('message:outbound', (peer: string, type: number, payload: Buffer) => {
		if (peer === bPubkey) b.handleMessage(aPubkey, type, payload);
	});
	b.on('message:outbound', (peer: string, type: number, payload: Buffer) => {
		if (peer === aPubkey) a.handleMessage(bPubkey, type, payload);
	});
}

function makeSpliceInWallet(amountSats: bigint): {
	walletInput: {
		prevTx: Buffer;
		prevOutputIndex: number;
		value: bigint;
		sequence: number;
		signWitness: (
			tx: bitcoin.Transaction,
			inputIndex: number,
			value: bigint
		) => Buffer[];
	};
	changeScript: Buffer;
} {
	const walletPriv = crypto
		.createHash('sha256')
		.update('splice-input-conflict-wallet')
		.digest();
	const walletPub = Buffer.from(ecc.pointFromScalar(walletPriv, true)!);
	const walletScript = bitcoin.payments.p2wpkh({ pubkey: walletPub }).output!;
	const scriptCode = bitcoin.payments.p2pkh({ pubkey: walletPub }).output!;
	const value = amountSats + 100_000n;
	const prevTx = new bitcoin.Transaction();
	prevTx.version = 2;
	prevTx.addInput(crypto.randomBytes(32), 0);
	prevTx.addOutput(walletScript, Number(value));
	return {
		walletInput: {
			prevTx: prevTx.toBuffer(),
			prevOutputIndex: 0,
			value,
			sequence: 0xfffffffd,
			signWitness: (tx, inputIndex, inputValue): Buffer[] => {
				const sighash = tx.hashForWitnessV0(
					inputIndex,
					scriptCode,
					Number(inputValue),
					bitcoin.Transaction.SIGHASH_ALL
				);
				return [
					bitcoin.script.signature.encode(
						Buffer.from(ecc.sign(sighash, walletPriv)),
						bitcoin.Transaction.SIGHASH_ALL
					),
					walletPub
				];
			}
		},
		changeScript: walletScript
	};
}

describe('HTLC traffic through a splice revert on a manager pair (issue #760)', function () {
	it('an HTLC settled during the pending window stays settled, the revert lands both sides on the old funding, and a later HTLC settles too', () => {
		const openerConfig = makeConfig(401);
		const acceptorConfig = makeConfig(402);
		const openerPubkey =
			openerConfig.localBasepoints.fundingPubkey.toString('hex');
		const acceptorPubkey =
			acceptorConfig.localBasepoints.fundingPubkey.toString('hex');
		const openerManager = new ChannelManager(openerConfig);
		const acceptorManager = new ChannelManager(acceptorConfig);
		openerManager.on('error', () => {});
		acceptorManager.on('error', () => {});
		connectManagers(
			openerManager,
			openerPubkey,
			acceptorManager,
			acceptorPubkey
		);
		const openerChannel = openerManager.openChannel(acceptorPubkey, 1_000_000n);
		const fundingTxid = crypto.randomBytes(32);
		openerManager.createFunding(
			openerChannel,
			fundingTxid,
			0,
			crypto.randomBytes(64)
		);
		const channelId = openerChannel.getChannelId()!;
		openerManager.handleFundingConfirmed(channelId);
		acceptorManager.handleFundingConfirmed(channelId);
		const acceptorChannel = acceptorManager.getChannelsByPeer(openerPubkey)[0];
		expect(openerChannel.getState()).to.equal(ChannelState.NORMAL);

		// A depth-locked splice-in, driven to the pending-lock window.
		openerManager.initiateQuiescence(channelId);
		const wallet = makeSpliceInWallet(100_000n);
		openerChannel.setSpliceInInputs([wallet.walletInput], wallet.changeScript, {
			lockAtDepth: 2
		});
		expect(openerManager.initiateSplice(channelId, 100_000n, 253).ok).to.equal(
			true
		);
		expect(openerChannel.isSplicePendingLock()).to.equal(true);
		expect(acceptorChannel.isSplicePendingLock()).to.equal(true);
		const record = openerChannel.getFullState().spliceInFlight!;
		expect(record.lockAtDepth).to.equal(2);
		expect(acceptorChannel.getFullState().spliceInFlight!.lockAtDepth).to.equal(
			2
		);
		const openerBalanceBefore = openerChannel.getBalances().localMsat;

		// HTLC in the window: committed on both fundings, then settled.
		const preimage = crypto.randomBytes(32);
		const hash = crypto.createHash('sha256').update(preimage).digest();
		expect(
			openerManager.addHtlc(
				channelId,
				15_000_000n,
				hash,
				500_000,
				crypto.randomBytes(1366)
			).ok
		).to.equal(true);
		expect([...openerChannel.getFullState().htlcs.values()][0].state).to.equal(
			HtlcState.COMMITTED
		);
		acceptorManager.fulfillHtlc(channelId, 0n, preimage);
		expect(openerChannel.getFullState().htlcs.size).to.equal(0);
		expect(acceptorChannel.getFullState().htlcs.size).to.equal(0);
		const openerBalanceAfterHtlc = openerChannel.getBalances().localMsat;
		expect(openerBalanceAfterHtlc).to.equal(openerBalanceBefore - 15_000_000n);

		// The stranger's coin was spent elsewhere: both sides agree (the node
		// does the agreeing; here the outcome is applied on each) and revert.
		const conflict = { txid: 'cd'.repeat(32), height: 150, inputIndex: 1 };
		expect(openerChannel.markSpliceConflicted(conflict)).to.equal(true);
		expect(acceptorChannel.markSpliceConflicted(conflict)).to.equal(true);
		const watched: Buffer[] = [];
		openerManager.on('watch:funding', (txid: Buffer) => watched.push(txid));
		const opening: Buffer[] = [];
		openerManager.on('channel:opening', (_id: Buffer, txid: Buffer) =>
			opening.push(txid)
		);
		const reverted: Array<{ spliceTxid: string; conflictTxid: string }> = [];
		openerManager.on(
			'splice:reverted',
			(_id: Buffer, spliceTxid: string, conflictTxid: string) =>
				reverted.push({ spliceTxid, conflictTxid })
		);
		expect(openerManager.revertConflictedSplice(channelId).ok).to.equal(true);
		expect(acceptorManager.revertConflictedSplice(channelId).ok).to.equal(true);
		expect(reverted).to.deep.equal([
			{ spliceTxid: display(record.spliceTxid), conflictTxid: conflict.txid }
		]);
		expect(watched.map((t) => t.equals(fundingTxid))).to.deep.equal([true]);
		expect(opening, 'a re-arm is not an opening').to.deep.equal([]);
		for (const ch of [openerChannel, acceptorChannel]) {
			const st = ch.getFullState();
			expect(st.state).to.equal(ChannelState.NORMAL);
			expect(st.spliceInFlight).to.equal(null);
			expect(st.fundingTxid!.equals(fundingTxid)).to.equal(true);
			expect(st.fundingOutputIndex).to.equal(0);
			expect(ch.isHtlcUsable()).to.equal(true);
		}
		// The pre-splice commitment is the live one and it carried the settle.
		expect(openerChannel.getBalances().localMsat).to.equal(
			openerBalanceAfterHtlc
		);
		expect(openerChannel.getBalances().remoteMsat).to.equal(
			acceptorChannel.getBalances().localMsat
		);

		// Traffic continues on the old funding.
		const preimage2 = crypto.randomBytes(32);
		const hash2 = crypto.createHash('sha256').update(preimage2).digest();
		expect(
			openerManager.addHtlc(
				channelId,
				7_000_000n,
				hash2,
				500_000,
				crypto.randomBytes(1366)
			).ok
		).to.equal(true);
		let fulfilled = false;
		openerManager.on('htlc:fulfilled', () => {
			fulfilled = true;
		});
		acceptorManager.fulfillHtlc(channelId, 1n, preimage2);
		expect(fulfilled).to.equal(true);
		expect(openerChannel.getFullState().htlcs.size).to.equal(0);
		expect(openerChannel.getBalances().localMsat).to.equal(
			openerBalanceAfterHtlc - 7_000_000n
		);

		// And a fresh splice can start again where the pin used to be.
		expect(openerChannel.spliceBusyReason()).to.equal(null);
	});
});

// ─────────────── The adversarial races, under quiescence ───────────────

interface IRacePair {
	openerManager: ChannelManager;
	acceptorManager: ChannelManager;
	channelId: Buffer;
	openerChannel: Channel;
	acceptorChannel: Channel;
	fundingTxid: Buffer;
	errors: Array<{ node: string; msg: string }>;
	wireErrors: number;
	/** Hold acceptor-to-opener delivery (the ordered wire, paused). */
	holdAcceptorToOpener: (on: boolean) => void;
	flush: () => void;
	ready: Buffer[];
}

/**
 * A manager pair mid depth-locked splice (pending lock, both sides
 * conflicted), the shape the adversarial repro started from, with the
 * acceptor holding a balance so it can add HTLCs too.
 */
function racePair(seed: number): IRacePair {
	const openerConfig = makeConfig(seed);
	const acceptorConfig = makeConfig(seed + 1);
	const openerPubkey =
		openerConfig.localBasepoints.fundingPubkey.toString('hex');
	const acceptorPubkey =
		acceptorConfig.localBasepoints.fundingPubkey.toString('hex');
	const openerManager = new ChannelManager(openerConfig);
	const acceptorManager = new ChannelManager(acceptorConfig);
	const errors: Array<{ node: string; msg: string }> = [];
	const pair = {
		wireErrors: 0,
		ready: [] as Buffer[]
	};
	openerManager.on('error', (_id: Buffer, msg: string) =>
		errors.push({ node: 'opener', msg })
	);
	acceptorManager.on('error', (_id: Buffer, msg: string) =>
		errors.push({ node: 'acceptor', msg })
	);
	let holding = false;
	const held: Array<() => void> = [];
	openerManager.on(
		'message:outbound',
		(peer: string, type: number, payload: Buffer) => {
			if (type === MessageType.ERROR) pair.wireErrors++;
			if (peer === acceptorPubkey)
				acceptorManager.handleMessage(openerPubkey, type, payload);
		}
	);
	acceptorManager.on(
		'message:outbound',
		(peer: string, type: number, payload: Buffer) => {
			if (type === MessageType.ERROR) pair.wireErrors++;
			if (peer !== openerPubkey) return;
			const deliver = (): void =>
				openerManager.handleMessage(acceptorPubkey, type, payload);
			if (holding) held.push(deliver);
			else deliver();
		}
	);
	openerManager.on('splice:conflict-request-ready', (id: Buffer) =>
		pair.ready.push(id)
	);
	acceptorManager.on('splice:conflict-request-ready', (id: Buffer) =>
		pair.ready.push(id)
	);
	const openerChannel = openerManager.openChannel(acceptorPubkey, 1_000_000n);
	const fundingTxid = crypto.randomBytes(32);
	openerManager.createFunding(
		openerChannel,
		fundingTxid,
		0,
		crypto.randomBytes(64)
	);
	const channelId = openerChannel.getChannelId()!;
	openerManager.handleFundingConfirmed(channelId);
	acceptorManager.handleFundingConfirmed(channelId);
	const acceptorChannel = acceptorManager.getChannelsByPeer(openerPubkey)[0];
	openerManager.initiateQuiescence(channelId);
	const wallet = makeSpliceInWallet(100_000n);
	openerChannel.setSpliceInInputs([wallet.walletInput], wallet.changeScript, {
		lockAtDepth: 2
	});
	expect(openerManager.initiateSplice(channelId, 100_000n, 253).ok).to.equal(
		true
	);
	expect(openerChannel.isSplicePendingLock()).to.equal(true);
	expect(acceptorChannel.isSplicePendingLock()).to.equal(true);
	for (let i = 0; i < 2; i++) {
		const preimage = crypto.randomBytes(32);
		const hash = crypto.createHash('sha256').update(preimage).digest();
		expect(
			openerManager.addHtlc(
				channelId,
				150_000_000n,
				hash,
				500_000,
				crypto.randomBytes(1366)
			).ok
		).to.equal(true);
		acceptorManager.fulfillHtlc(channelId, BigInt(i), preimage);
	}
	expect(acceptorChannel.getFullState().htlcs.size).to.equal(0);
	const conflict = { txid: 'cd'.repeat(32), height: 150, inputIndex: 1 };
	expect(openerChannel.markSpliceConflicted(conflict)).to.equal(true);
	expect(acceptorChannel.markSpliceConflicted(conflict)).to.equal(true);
	errors.length = 0;
	return {
		openerManager,
		acceptorManager,
		channelId,
		openerChannel,
		acceptorChannel,
		fundingTxid,
		errors,
		get wireErrors(): number {
			return pair.wireErrors;
		},
		holdAcceptorToOpener: (on): void => {
			holding = on;
		},
		flush: (): void => {
			while (held.length) held.shift()!();
		},
		ready: pair.ready
	};
}

function addAndSettle(
	from: ChannelManager,
	to: ChannelManager,
	channelId: Buffer,
	htlcId: bigint
): void {
	const preimage = crypto.randomBytes(32);
	const hash = crypto.createHash('sha256').update(preimage).digest();
	expect(
		from.addHtlc(
			channelId,
			15_000_000n,
			hash,
			500_000,
			crypto.randomBytes(1366)
		).ok,
		'add after the revert'
	).to.equal(true);
	to.fulfillHtlc(channelId, htlcId, preimage);
}

function expectBothNormalOnOldFunding(p: IRacePair): void {
	for (const ch of [p.openerChannel, p.acceptorChannel]) {
		const st = ch.getFullState();
		expect(st.state).to.equal(ChannelState.NORMAL);
		expect(st.spliceInFlight).to.equal(null);
		expect(st.fundingTxid!.equals(p.fundingTxid)).to.equal(true);
		expect(st.htlcs.size).to.equal(0);
		expect(ch.isQuiescing()).to.equal(false);
	}
	expect(p.wireErrors, 'no wire error').to.equal(0);
	expect(p.openerChannel.getBalances().localMsat).to.equal(
		p.acceptorChannel.getBalances().remoteMsat
	);
}

/**
 * The exchange the node runs, at the manager level: the requester opens its
 * quiescence handshake; once QUIESCENT as initiator the request is ready
 * (the node would send SPLICE_CONFLICT here); the responder verifies (a
 * given here) and reverts, which exits its quiescence, and acks; the
 * requester reverts on the ack, which exits its own. `between` runs at the
 * point the ack is on the wire but not yet processed.
 */
function runExchange(
	p: IRacePair,
	requester: 'opener' | 'acceptor',
	between?: () => void
): void {
	const req = requester === 'opener' ? p.openerManager : p.acceptorManager;
	const res = requester === 'opener' ? p.acceptorManager : p.openerManager;
	const reqCh = requester === 'opener' ? p.openerChannel : p.acceptorChannel;
	const resCh = requester === 'opener' ? p.acceptorChannel : p.openerChannel;
	expect(req.requestSpliceConflictRevert(p.channelId).ok).to.equal(true);
	expect(p.ready).to.have.length(1);
	expect(reqCh.isQuiescent() && reqCh.isQuiescenceInitiator()).to.equal(true);
	expect(resCh.isQuiescent() && !resCh.isQuiescenceInitiator()).to.equal(true);
	// While both are quiescent neither side can put an update in flight.
	for (const m of [req, res]) {
		expect(
			m.addHtlc(
				p.channelId,
				1_000_000n,
				crypto.randomBytes(32),
				500_000,
				crypto.randomBytes(1366)
			).ok
		).to.equal(false);
	}
	// The two refusals above are the point; they are not defects.
	p.errors.length = 0;
	expect(res.revertConflictedSplice(p.channelId).ok).to.equal(true);
	expect(
		resCh.isQuiescing(),
		"the revert exits the responder's quiescence"
	).to.equal(false);
	if (between) between();
	expect(req.revertConflictedSplice(p.channelId).ok).to.equal(true);
	expect(reqCh.isQuiescing()).to.equal(false);
}

describe('Commitment rounds across a splice revert, under quiescence (issue #760)', function () {
	it('A: the acceptor reverts first; the opener cannot put a batch in flight until it has reverted too', () => {
		const p = racePair(500);
		runExchange(p, 'opener');
		expectBothNormalOnOldFunding(p);
		addAndSettle(p.openerManager, p.acceptorManager, p.channelId, 2n);
		addAndSettle(p.acceptorManager, p.openerManager, p.channelId, 0n);
		expectBothNormalOnOldFunding(p);
	});

	it('B: the opener reverts first (the acceptor asked); the acceptor cannot send a batch until it has reverted too', () => {
		const p = racePair(510);
		runExchange(p, 'acceptor');
		expectBothNormalOnOldFunding(p);
		addAndSettle(p.acceptorManager, p.openerManager, p.channelId, 0n);
		addAndSettle(p.openerManager, p.acceptorManager, p.channelId, 2n);
		expectBothNormalOnOldFunding(p);
	});

	it('C: an HTLC the reverted acceptor sends right after its ack lands after the opener has reverted, and settles', () => {
		const p = racePair(520);
		const preimage = crypto.randomBytes(32);
		const hash = crypto.createHash('sha256').update(preimage).digest();
		runExchange(p, 'opener', () => {
			// The acceptor's quiescence ended with its revert, so it may add at
			// once. On the ordered wire the add follows its ack, so the opener
			// processes the ack (and reverts) before the add arrives; the held
			// delivery stands in for that ordering.
			p.holdAcceptorToOpener(true);
			expect(
				p.acceptorManager.addHtlc(
					p.channelId,
					15_000_000n,
					hash,
					500_000,
					crypto.randomBytes(1366)
				).ok
			).to.equal(true);
		});
		p.holdAcceptorToOpener(false);
		p.flush();
		expect(p.errors, 'no refused update').to.deep.equal([]);
		expect(p.openerChannel.getFullState().htlcs.size).to.equal(1);
		p.openerManager.fulfillHtlc(p.channelId, 0n, preimage);
		expectBothNormalOnOldFunding(p);
		addAndSettle(p.openerManager, p.acceptorManager, p.channelId, 2n);
		expectBothNormalOnOldFunding(p);
	});

	it('the responder refusing (agreed=0) ends the session on both sides and HTLCs flow again', () => {
		const p = racePair(530);
		expect(
			p.openerManager.requestSpliceConflictRevert(p.channelId).ok
		).to.equal(true);
		expect(p.openerChannel.isQuiescent()).to.equal(true);
		expect(p.acceptorChannel.isQuiescent()).to.equal(true);
		// The responder answers agreed=0: it leaves the session as it acks,
		// the requester as it acts on the ack.
		expect(
			p.acceptorManager.abandonSpliceConflictRequest(p.channelId).ok
		).to.equal(true);
		expect(
			p.openerManager.abandonSpliceConflictRequest(p.channelId).ok
		).to.equal(true);
		for (const ch of [p.openerChannel, p.acceptorChannel]) {
			expect(ch.isQuiescing()).to.equal(false);
			expect(ch.getState()).to.equal(ChannelState.SPLICING);
			expect(ch.hasPendingSpliceConflictRequest()).to.equal(false);
		}
		const preimage = crypto.randomBytes(32);
		const hash = crypto.createHash('sha256').update(preimage).digest();
		expect(
			p.openerManager.addHtlc(
				p.channelId,
				15_000_000n,
				hash,
				500_000,
				crypto.randomBytes(1366)
			).ok
		).to.equal(true);
		p.acceptorManager.fulfillHtlc(p.channelId, 2n, preimage);
		expect(p.openerChannel.getFullState().htlcs.size).to.equal(0);
		expect(p.wireErrors).to.equal(0);
		// And the request can be made again.
		p.ready.length = 0;
		expect(
			p.openerManager.requestSpliceConflictRevert(p.channelId).ok
		).to.equal(true);
		expect(p.ready).to.have.length(1);
	});

	it('a request while the peer owns the session, or with an HTLC in flight, is refused transiently', () => {
		const p = racePair(540);
		expect(
			p.acceptorManager.requestSpliceConflictRevert(p.channelId).ok
		).to.equal(true);
		const refused = p.openerManager.requestSpliceConflictRevert(p.channelId);
		expect(refused.ok).to.equal(false);
		expect(refused.transient).to.equal(true);
		expect(p.openerChannel.hasPendingSpliceConflictRequest()).to.equal(false);
		p.acceptorManager.abandonSpliceConflictRequest(p.channelId);
		p.openerManager.abandonSpliceConflictRequest(p.channelId);
		// A COMMITTED HTLC does not block the handshake (BOLT 2 stfu waits
		// only for un-acked updates): the request goes out with one in place
		// and the HTLC settles once the session is over.
		const preimage = crypto.randomBytes(32);
		const hash = crypto.createHash('sha256').update(preimage).digest();
		expect(
			p.openerManager.addHtlc(
				p.channelId,
				15_000_000n,
				hash,
				500_000,
				crypto.randomBytes(1366)
			).ok
		).to.equal(true);
		p.ready.length = 0;
		expect(
			p.openerManager.requestSpliceConflictRevert(p.channelId).ok
		).to.equal(true);
		expect(p.ready).to.have.length(1);
		p.acceptorManager.abandonSpliceConflictRequest(p.channelId);
		p.openerManager.abandonSpliceConflictRequest(p.channelId);
		p.acceptorManager.fulfillHtlc(p.channelId, 2n, preimage);
		expect(p.openerChannel.getFullState().htlcs.size).to.equal(0);
		expect(p.wireErrors).to.equal(0);
	});
});

// ─────────────── Node level over loopback ───────────────

function makeNodeConfig(seedId: number): INodeConfig {
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
			.digest()
	};
}

interface INodeFixture {
	alice: LightningNode;
	bob: LightningNode;
	channelId: Buffer;
	oldFundingTxid: Buffer;
	spliceTx: bitcoin.Transaction;
	coin: bitcoin.Transaction;
	coinScriptHash: string;
	conflict: bitcoin.Transaction;
	backendA: MockBackend;
	backendB: MockBackend;
	frames: Array<{ from: string; subtype: number; payload: Buffer }>;
	/** Senders whose custom frames are recorded but not delivered. */
	muted: Set<string>;
	/** While set, deliveries queue here instead of landing (a reconnect). */
	hold: boolean;
	queue: Array<() => void>;
	reverted: Array<{ node: string; spliceTxid: string; conflictTxid: string }>;
	conflicted: string[];
	errors: Array<{ node: string; code: string }>;
	destroy: () => void;
}

/** Route one direction of the loopback wire, through the fixture's gate. */
function route(
	from: LightningNode,
	fromName: string,
	to: LightningNode,
	fx: INodeFixture
): void {
	from.on(
		'message:outbound',
		(pubkey: string, type: number, payload: Buffer) => {
			if (pubkey !== to.getNodeId()) return;
			if (type === BEIGNET_CUSTOM_MESSAGE_TYPE) {
				const env = decodeCustomMessage(payload);
				fx.frames.push({
					from: fromName,
					subtype: env.subtype,
					payload: env.payload
				});
				if (fx.muted.has(fromName)) return;
			}
			const deliver = (): void =>
				to.handlePeerMessage(from.getNodeId(), type, payload);
			if (fx.hold) fx.queue.push(deliver);
			else deliver();
		}
	);
}

function observe(name: string, n: LightningNode, fx: INodeFixture): void {
	n.on('error', () => {});
	n.on('node:error', (e: { code: string }) =>
		fx.errors.push({ node: name, code: e.code })
	);
	n.on('splice:reverted', (e: { spliceTxid: string; conflictTxid: string }) =>
		fx.reverted.push({ node: name, ...e })
	);
	n.on('splice:conflicted', () => fx.conflicted.push(name));
}

function wire(
	alice: LightningNode,
	bob: LightningNode,
	fx: INodeFixture
): void {
	route(alice, 'alice', bob, fx);
	route(bob, 'bob', alice, fx);
	observe('alice', alice, fx);
	observe('bob', bob, fx);
}

/** Graft the depth-locked splice at its point of no return on one node. */
function graft(
	node: LightningNode,
	channelId: Buffer,
	spliceTx: bitcoin.Transaction,
	coinScript: Buffer,
	role: 'initiator' | 'acceptor' = 'initiator'
): void {
	const ch = node.getChannelManager().getChannel(channelId)!;
	const raw = ch.getFullState();
	raw.state = ChannelState.SPLICING;
	raw.preSpliceState = ChannelState.NORMAL;
	raw.spliceInFlight = inflightFor(spliceTx, coinScript);
	if (role === 'acceptor') {
		// The other side of the same splice: no contribution of its own, so
		// every input but the shared one is somebody else's.
		raw.spliceInFlight.isInitiator = false;
		raw.spliceInFlight.ourWalletInputIndices = [];
		raw.spliceInFlight.ourWalletWitnesses = [];
		raw.spliceInFlight.externalInputIndices = undefined;
		raw.spliceInFlight.localRelativeSatoshis = 0n;
		raw.spliceInFlight.remoteRelativeSatoshis = 40_000n;
	}
	raw.spliceFundingTxid = Buffer.from(spliceTx.getHash());
	raw.spliceFundingOutputIndex = 0;
}

async function armSpliceWatch(
	node: LightningNode,
	spliceTx: bitcoin.Transaction
): Promise<void> {
	await (
		node as unknown as { registerFundingWatch(txid: Buffer): Promise<void> }
	).registerFundingWatch(Buffer.from(spliceTx.getHash()));
}

async function setupNodes(
	seedBase: number,
	options: {
		sharedBackend: boolean;
		storageA?: SqliteStorage;
		storageB?: SqliteStorage;
		bobRole?: 'initiator' | 'acceptor';
		armAlice?: boolean;
		armBob?: boolean;
	} = { sharedBackend: true }
): Promise<INodeFixture> {
	const backendA = new MockBackend();
	const backendB = options.sharedBackend ? backendA : new MockBackend();
	const configA = makeNodeConfig(seedBase);
	configA.chainBackend = backendA;
	if (options.storageA) configA.storage = options.storageA;
	const configB = makeNodeConfig(seedBase + 1);
	configB.chainBackend = backendB;
	if (options.storageB) configB.storage = options.storageB;
	const alice = new LightningNode(configA);
	const bob = new LightningNode(configB);
	const fx: INodeFixture = {
		alice,
		bob,
		channelId: Buffer.alloc(0),
		oldFundingTxid: Buffer.alloc(0),
		spliceTx: new bitcoin.Transaction(),
		coin: new bitcoin.Transaction(),
		coinScriptHash: '',
		conflict: new bitcoin.Transaction(),
		backendA,
		backendB,
		frames: [],
		muted: new Set(),
		hold: false,
		queue: [],
		reverted: [],
		conflicted: [],
		errors: [],
		destroy: (): void => {
			alice.destroy();
			bob.destroy();
		}
	};
	wire(alice, bob, fx);
	const channel = alice.openChannel(bob.getNodeId(), 1_000_000n);
	const channelId = alice.createFunding(
		channel,
		crypto.randomBytes(32),
		0,
		crypto.randomBytes(64)
	)!;
	alice.handleFundingConfirmed(channelId);
	bob.handleFundingConfirmed(channelId);
	await tick(80);
	const oldFundingTxid = alice
		.getChannelManager()
		.getChannel(channelId)!
		.getFullState().fundingTxid!;

	const { tx: coin, script: coinScript } = makeCoinTx(50_000);
	const spliceTx = spliceTxFor(oldFundingTxid, 0, coin);
	const conflict = spendOf(coin.getId(), 0);
	for (const b of new Set([backendA, backendB])) {
		b.setTx(coin);
		b.setTx(spliceTx);
		b.setTx(conflict);
	}
	graft(alice, channelId, spliceTx, coinScript);
	graft(bob, channelId, spliceTx, coinScript, options.bobRole ?? 'initiator');
	if (options.armAlice !== false) await armSpliceWatch(alice, spliceTx);
	if (options.armBob !== false) await armSpliceWatch(bob, spliceTx);
	Object.assign(fx, {
		channelId,
		oldFundingTxid,
		spliceTx,
		coin,
		coinScriptHash: computeScriptHash(coinScript),
		conflict
	});
	return fx;
}

function conflictHistory(
	fx: INodeFixture
): Array<{ txid: string; height: number }> {
	return [
		{ txid: fx.coin.getId(), height: 100 },
		{ txid: fx.spliceTx.getId(), height: 0 },
		{ txid: fx.conflict.getId(), height: 150 }
	];
}

function channelOf(node: LightningNode, channelId: Buffer): Channel {
	return node.getChannelManager().getChannel(channelId)!;
}

function watchedFundingTxid(
	node: LightningNode,
	channelId: Buffer
): string | undefined {
	const map = (
		node.getChainWatcher() as unknown as {
			watchedFundings: Map<string, { txid: string }>;
		}
	).watchedFundings;
	return map.get(channelId.toString('hex'))?.txid;
}

/** Shorten a node's wait for the peer's ack (the constant is 60 s). */
function shortenConflictTimeout(node: LightningNode, ms: number): void {
	(
		node as unknown as { spliceConflictRequestTimeoutMs: number }
	).spliceConflictRequestTimeoutMs = ms;
}

function clearConflictBackoff(node: LightningNode): void {
	(
		node as unknown as { spliceConflictBackoffUntil: Map<string, number> }
	).spliceConflictBackoffUntil.clear();
}

/**
 * Drive a loopback reconnect the way a socket pair delivers it: both sides
 * disconnected, then both channel_reestablish messages cross before any
 * reply lands.
 */
async function reconnect(
	a: LightningNode,
	b: LightningNode,
	fx: INodeFixture
): Promise<void> {
	for (const [x, y] of [
		[a, b],
		[b, a]
	] as const) {
		const ch = x.getChannelManager().getChannel(fx.channelId);
		if (ch && ch.getState() !== ChannelState.AWAITING_REESTABLISH) {
			x.getChannelManager().handlePeerDisconnected(y.getNodeId());
		}
	}
	await tick(20);
	fx.hold = true;
	a.getChannelManager().handlePeerReconnected(b.getNodeId());
	b.getChannelManager().handlePeerReconnected(a.getNodeId());
	while (fx.queue.length > 0) fx.queue.shift()!();
	fx.hold = false;
	await tick(20);
}

function acksFrom(
	fx: INodeFixture,
	from: string
): Array<{ agreed: boolean; reason: string }> {
	return fx.frames
		.filter(
			(f) =>
				f.from === from &&
				f.subtype === BeignetCustomSubtype.SPLICE_CONFLICT_ACK
		)
		.map((f) => {
			const ack = decodeSpliceConflictAck(f.payload);
			return { agreed: ack.agreed, reason: ack.reason };
		});
}

function requestsFrom(fx: INodeFixture, from: string): number {
	return fx.frames.filter(
		(f) => f.from === from && f.subtype === BeignetCustomSubtype.SPLICE_CONFLICT
	).length;
}

describe('Splice conflict recovery between two nodes (issue #760)', function () {
	this.timeout(15_000);

	it('arms one watch per input this node does not vouch for, from the live path, and none for an ordinary splice', async () => {
		const fx = await setupNodes(7601);
		for (const n of [fx.alice, fx.bob]) {
			expect(
				n.getChainWatcher()!.spliceInputWatchesFor(fx.channelId)
			).to.deep.equal([
				{
					spliceTxid: fx.spliceTx.getId(),
					inputIndex: 1,
					txid: fx.coin.getId(),
					vout: 0
				}
			]);
			// The splice's own funding watch replaced the old one, as always.
			expect(watchedFundingTxid(n, fx.channelId)).to.equal(fx.spliceTx.getId());
		}
		// A splice with no lock depth arms nothing, whatever it carries.
		const plain = channelOf(fx.alice, fx.channelId).getFullState();
		plain.spliceInFlight!.lockAtDepth = undefined;
		fx.alice.getChainWatcher()!.unwatchSpliceInputs(fx.channelId);
		await armSpliceWatch(fx.alice, fx.spliceTx);
		expect(
			fx.alice.getChainWatcher()!.spliceInputWatchesFor(fx.channelId)
		).to.have.length(0);
		fx.destroy();
	});

	it('takes a verdict refused under a stale sighting once the sighting is retracted (issue #776)', async () => {
		// Alice's chain view alone: bob's backend never shows the conflict,
		// so only alice's verdict is under test.
		const fx = await setupNodes(7699, { sharedBackend: false });
		const st = channelOf(fx.alice, fx.channelId).getFullState();
		const spliceFundingHash = computeScriptHash(
			createFundingScript(
				st.localBasepoints.fundingPubkey,
				st.spliceInFlight!.remoteFundingPubkey,
				bitcoin.networks.regtest
			).p2wshOutput
		);
		// The splice is seen at 154, two blocks short of its lock depth, and
		// the conflict is six deep at 155: the verdict lands while the record
		// says the chain has the splice, so the channel refuses it.
		fx.backendA.setHistory(spliceFundingHash, [
			{ txid: fx.spliceTx.getId(), height: 154 }
		]);
		fx.backendA.setHistory(fx.coinScriptHash, conflictHistory(fx));
		for (let h = 150; h <= 155; h++) fx.backendA.block(h);
		await tick(150);
		expect(
			channelOf(fx.alice, fx.channelId).getFullState().spliceInFlight!
				.confirmedHeight,
			'the sighting is stamped'
		).to.equal(154);
		expect(fx.conflicted, 'the verdict was refused').to.deep.equal([]);

		// The reorg takes the splice back. The next verdict is taken.
		fx.backendA.setHistory(spliceFundingHash, [
			{ txid: fx.spliceTx.getId(), height: 0 }
		]);
		fx.backendA.block(156);
		await tick(150);
		expect(
			channelOf(fx.alice, fx.channelId).getFullState().spliceInFlight
				?.confirmedHeight,
			'the sighting is retracted'
		).to.equal(undefined);
		fx.backendA.block(157);
		await tick(300);
		expect(fx.conflicted, 'the re-emitted verdict is taken').to.include(
			'alice'
		);
		fx.destroy();
	});

	it('both nodes detect the conflict at depth, agree it under one quiescence session and revert to the old funding', async () => {
		const fx = await setupNodes(7603);
		fx.backendA.setHistory(fx.coinScriptHash, conflictHistory(fx));
		for (let h = 150; h < 155; h++) fx.backendA.block(h);
		await tick(60);
		expect(fx.conflicted, 'nothing before depth').to.deep.equal([]);
		expect(channelOf(fx.alice, fx.channelId).getState()).to.equal(
			ChannelState.SPLICING
		);

		fx.backendA.block(155);
		await tick(150);

		// Both sides saw it and both opened a quiescence handshake; the funder
		// (alice) won the concurrent-stfu tie-break, so hers is the session:
		// only she asks, bob answers it after verifying on his own chain view,
		// and both revert. Nobody sends an update in between: both were
		// quiescent until their own revert.
		expect(fx.conflicted.sort()).to.deep.equal(['alice', 'bob']);
		expect(
			fx.errors
				.filter((e) => e.code === 'SPLICE_INPUT_CONFLICT')
				.map((e) => e.node)
				.sort()
		).to.deep.equal(['alice', 'bob']);
		expect(requestsFrom(fx, 'alice')).to.equal(1);
		expect(requestsFrom(fx, 'bob')).to.equal(0);
		expect(acksFrom(fx, 'bob')).to.deep.equal([{ agreed: true, reason: '' }]);
		expect(fx.reverted.map((r) => r.node).sort()).to.deep.equal([
			'alice',
			'bob'
		]);
		for (const r of fx.reverted) {
			expect(r.spliceTxid).to.equal(fx.spliceTx.getId());
			expect(r.conflictTxid).to.equal(fx.conflict.getId());
		}
		for (const n of [fx.alice, fx.bob]) {
			const ch = channelOf(n, fx.channelId);
			const st = ch.getFullState();
			expect(st.state).to.equal(ChannelState.NORMAL);
			expect(st.spliceInFlight).to.equal(null);
			expect(st.fundingTxid!.equals(fx.oldFundingTxid)).to.equal(true);
			expect(ch.isQuiescing(), 'session over').to.equal(false);
			// The old funding is watched again, and the dead splice's input
			// watches are gone.
			expect(watchedFundingTxid(n, fx.channelId)).to.equal(
				display(fx.oldFundingTxid)
			);
			expect(
				n.getChainWatcher()!.spliceInputWatchesFor(fx.channelId)
			).to.have.length(0);
		}
		// Nothing more is asked once both sides agree.
		const before = fx.frames.length;
		fx.backendA.block(156);
		await tick(60);
		expect(fx.frames.length).to.equal(before);
		fx.destroy();
	});

	it('a peer that cannot verify refuses (agreed=0), both leave quiescence, and the request is retried each block until it can', async () => {
		const fx = await setupNodes(7605, { sharedBackend: false });
		// Bob's server has not seen the conflict: only the coin's own history.
		fx.backendB.setHistory(fx.coinScriptHash, [
			{ txid: fx.coin.getId(), height: 100 }
		]);
		fx.backendA.setHistory(fx.coinScriptHash, conflictHistory(fx));
		for (let h = 150; h <= 155; h++) {
			fx.backendA.block(h);
			fx.backendB.block(h);
		}
		await tick(150);
		expect(fx.conflicted).to.deep.equal(['alice']);
		const refusals = acksFrom(fx, 'bob');
		expect(refusals).to.have.length(1);
		expect(refusals[0].agreed).to.equal(false);
		expect(refusals[0].reason).to.match(/not confirmed at depth/);
		expect(fx.reverted).to.deep.equal([]);
		const bobState = channelOf(fx.bob, fx.channelId).getFullState();
		expect(bobState.state).to.equal(ChannelState.SPLICING);
		expect(bobState.spliceInFlight!.conflict).to.equal(undefined);
		const aliceState = channelOf(fx.alice, fx.channelId).getFullState();
		expect(aliceState.state).to.equal(ChannelState.SPLICING);
		expect(aliceState.spliceInFlight!.conflict!.txid).to.equal(
			fx.conflict.getId()
		);
		expect(aliceState.spliceInFlight!.conflict!.revertRequestedAt).to.be.a(
			'number'
		);
		// agreed=0 ended the quiescence session on both sides: HTLCs flow
		// again until the next block re-asks.
		for (const n of [fx.alice, fx.bob]) {
			const ch = channelOf(n, fx.channelId);
			expect(ch.isQuiescing(), 'quiescence unwound').to.equal(false);
			expect(ch.getQuiescenceState()).to.equal(QuiescenceState.NORMAL);
			expect(ch.hasPendingSpliceConflictRequest()).to.equal(false);
		}

		// Next block: alice asks again (a fresh stfu handshake), bob still
		// cannot verify, and the session ends again.
		fx.backendA.block(156);
		await tick(100);
		expect(requestsFrom(fx, 'alice')).to.equal(2);
		expect(acksFrom(fx, 'bob')).to.have.length(2);
		expect(fx.reverted).to.deep.equal([]);
		expect(channelOf(fx.alice, fx.channelId).isQuiescing()).to.equal(false);

		// Bob's server catches up: whichever side asks next is answered, both
		// revert.
		fx.backendB.setHistory(fx.coinScriptHash, conflictHistory(fx));
		fx.backendB.block(156);
		fx.backendA.block(157);
		await tick(200);
		expect(fx.reverted.map((r) => r.node).sort()).to.deep.equal([
			'alice',
			'bob'
		]);
		for (const n of [fx.alice, fx.bob]) {
			const st = channelOf(n, fx.channelId).getFullState();
			expect(st.state).to.equal(ChannelState.NORMAL);
			expect(st.fundingTxid!.equals(fx.oldFundingTxid)).to.equal(true);
		}
		fx.destroy();
	});

	it("a request outside the sender's session, one naming the shared funding input, or one for a splice we do not hold is refused without moving the channel", async () => {
		const fx = await setupNodes(7607);
		fx.backendA.setHistory(fx.coinScriptHash, conflictHistory(fx));
		// One short of the verdict: the honest exchange has not started.
		for (let h = 150; h <= 154; h++) fx.backendA.block(h);
		await tick(20);
		const send = (spliceTxid: Buffer, inputIndex: number): void =>
			fx.alice.handlePeerMessage(
				fx.bob.getNodeId(),
				BEIGNET_CUSTOM_MESSAGE_TYPE,
				encodeCustomMessage(
					BeignetCustomSubtype.SPLICE_CONFLICT,
					encodeSpliceConflict({
						channelId: fx.channelId,
						spliceTxid,
						conflictTxid: Buffer.from(fx.conflict.getHash()),
						inputIndex
					})
				)
			);
		// Outside any quiescence session: refused before anything is checked.
		send(Buffer.from(fx.spliceTx.getHash()), 1);
		await tick(40);
		let acks = acksFrom(fx, 'alice');
		expect(acks).to.have.length(1);
		expect(acks[0].reason).to.match(/not quiescent/);
		expect(channelOf(fx.alice, fx.channelId).isQuiescing()).to.equal(false);

		// Bob opens his session the honest way (he holds a verdict of his
		// own); alice answers the stfu and is quiescent under it. A hand-built
		// request naming the shared input is refused, and the refusal ends
		// the session.
		fx.muted.add('bob');
		channelOf(fx.bob, fx.channelId).markSpliceConflicted({
			txid: fx.conflict.getId(),
			height: 150,
			inputIndex: 1
		});
		expect(
			fx.bob.getChannelManager().requestSpliceConflictRevert(fx.channelId).ok
		).to.equal(true);
		await tick(40);
		const alice = channelOf(fx.alice, fx.channelId);
		expect(alice.isQuiescent()).to.equal(true);
		expect(alice.isQuiescenceInitiator()).to.equal(false);
		send(Buffer.from(fx.spliceTx.getHash()), 0);
		await tick(60);
		acks = acksFrom(fx, 'alice');
		expect(acks).to.have.length(2);
		expect(acks[1].reason).to.match(/shared funding input/);
		expect(alice.isQuiescing(), 'the refusal ended the session').to.equal(
			false
		);
		// A splice we do not hold is refused whatever the session state.
		send(crypto.randomBytes(32), 1);
		await tick(40);
		acks = acksFrom(fx, 'alice');
		expect(acks).to.have.length(3);
		expect(acks[2].reason).to.match(/no such splice/);
		expect(acks.map((a) => a.agreed)).to.deep.equal([false, false, false]);
		expect(alice.getState()).to.equal(ChannelState.SPLICING);
		expect(alice.getFullState().spliceInFlight).to.not.equal(null);
		fx.destroy();
	});

	it('the requester that hears nothing within the window abandons the request, disconnects the peer and backs off', async () => {
		const fx = await setupNodes(7613, { sharedBackend: false });
		// Bob's server never sees the conflict, and his answers are lost.
		fx.backendB.setHistory(fx.coinScriptHash, [
			{ txid: fx.coin.getId(), height: 100 }
		]);
		fx.backendA.setHistory(fx.coinScriptHash, conflictHistory(fx));
		fx.muted.add('bob');
		shortenConflictTimeout(fx.alice, 150);
		const disconnects: string[] = [];
		fx.alice.on('peer:disconnect-requested', (pubkey: string) =>
			disconnects.push(pubkey)
		);
		for (let h = 150; h <= 155; h++) {
			fx.backendA.block(h);
			fx.backendB.block(h);
		}
		await tick(60);
		const alice = channelOf(fx.alice, fx.channelId);
		expect(requestsFrom(fx, 'alice')).to.equal(1);
		expect(alice.hasPendingSpliceConflictRequest()).to.equal(true);
		expect(alice.isQuiescent()).to.equal(true);
		await tick(250);
		// The window passed: the request is abandoned, quiescence unwound on
		// our side, the peer disconnected (the one reset quiescence has), and
		// the channel is left alone until the backoff passes.
		expect(alice.hasPendingSpliceConflictRequest()).to.equal(false);
		expect(alice.getQuiescenceState()).to.equal(QuiescenceState.NORMAL);
		expect(disconnects).to.deep.equal([fx.bob.getNodeId()]);
		expect(alice.getState()).to.equal(ChannelState.AWAITING_REESTABLISH);
		expect(alice.getFullState().spliceInFlight?.conflict?.txid).to.equal(
			fx.conflict.getId()
		);
		const backoff = (
			fx.alice as unknown as { spliceConflictBackoffUntil: Map<string, number> }
		).spliceConflictBackoffUntil.get(fx.channelId.toString('hex'))!;
		expect(backoff).to.be.greaterThan(
			Date.now() + SPLICE_CONFLICT_REQUEST_BACKOFF_MS - 5_000
		);
		// The reconnect re-asks only once the backoff has passed.
		await reconnect(fx.alice, fx.bob, fx);
		await tick(60);
		expect(requestsFrom(fx, 'alice'), 'inside the backoff').to.equal(1);
		clearConflictBackoff(fx.alice);
		fx.backendB.setHistory(fx.coinScriptHash, conflictHistory(fx));
		fx.muted.delete('bob');
		fx.backendA.block(156);
		fx.backendB.block(156);
		await tick(200);
		expect(requestsFrom(fx, 'alice')).to.be.greaterThan(1);
		expect(fx.reverted.map((r) => r.node).sort()).to.deep.equal([
			'alice',
			'bob'
		]);
		fx.destroy();
	});

	it('a conflict detected by the acceptor alone drives the revert', async () => {
		const fx = await setupNodes(7615, {
			sharedBackend: true,
			bobRole: 'acceptor',
			armAlice: false
		});
		// The acceptor contributed nothing, so it vouches for no input but the
		// shared one: it watches the initiator's coin.
		expect(
			fx.bob.getChainWatcher()!.spliceInputWatchesFor(fx.channelId)
		).to.deep.equal([
			{
				spliceTxid: fx.spliceTx.getId(),
				inputIndex: 1,
				txid: fx.coin.getId(),
				vout: 0
			}
		]);
		expect(
			fx.alice.getChainWatcher()!.spliceInputWatchesFor(fx.channelId)
		).to.have.length(0);
		fx.backendA.setHistory(fx.coinScriptHash, conflictHistory(fx));
		for (let h = 150; h <= 155; h++) fx.backendA.block(h);
		await tick(150);
		expect(fx.conflicted[0]).to.equal('bob');
		expect(requestsFrom(fx, 'bob')).to.equal(1);
		expect(requestsFrom(fx, 'alice')).to.equal(0);
		expect(acksFrom(fx, 'alice')).to.deep.equal([{ agreed: true, reason: '' }]);
		expect(fx.reverted.map((r) => r.node).sort()).to.deep.equal([
			'alice',
			'bob'
		]);
		for (const n of [fx.alice, fx.bob]) {
			const st = channelOf(n, fx.channelId).getFullState();
			expect(st.state).to.equal(ChannelState.NORMAL);
			expect(st.fundingTxid!.equals(fx.oldFundingTxid)).to.equal(true);
		}
		fx.destroy();
	});

	it('a record without prevout scripts still gets its watch, from the parent transaction', async () => {
		const fx = await setupNodes(7617, {
			sharedBackend: true,
			armAlice: false,
			armBob: false
		});
		const bob = channelOf(fx.bob, fx.channelId).getFullState();
		bob.spliceInFlight!.inputPrevouts = [];
		await armSpliceWatch(fx.bob, fx.spliceTx);
		expect(
			fx.bob.getChainWatcher()!.spliceInputWatchesFor(fx.channelId)
		).to.have.length(1);
		fx.backendA.setHistory(fx.coinScriptHash, conflictHistory(fx));
		for (let h = 150; h <= 155; h++) fx.backendA.block(h);
		await tick(150);
		expect(fx.conflicted).to.include('bob');
		expect(fx.reverted.map((r) => r.node).sort()).to.deep.equal([
			'alice',
			'bob'
		]);
		fx.destroy();
	});

	it('agreed=1 leaves only once the revert is on disk: a failed commit answers agreed=0 and the re-ask succeeds later', async () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'splice-commit-'));
		const real = new SqliteStorage(path.join(dir, 'bob.sqlite'));
		real.open();
		const failing = { value: false };
		const storageB = new Proxy(real, {
			get(target, prop, receiver) {
				if (prop === 'saveChannel' && failing.value) {
					return (): never => {
						throw new Error('disk full');
					};
				}
				const v = Reflect.get(target, prop, receiver);
				return typeof v === 'function' ? v.bind(target) : v;
			}
		});
		const fx = await setupNodes(7619, {
			sharedBackend: true,
			storageB,
			armBob: false
		});
		fx.backendA.setHistory(fx.coinScriptHash, conflictHistory(fx));
		failing.value = true;
		for (let h = 150; h <= 155; h++) fx.backendA.block(h);
		await tick(150);
		expect(acksFrom(fx, 'bob')).to.deep.equal([
			{
				agreed: false,
				reason: 'the revert could not be committed to disk; ask again'
			}
		]);
		// Alice kept her record and left the session; bob's revert stands in
		// memory until it can be written.
		const alice = channelOf(fx.alice, fx.channelId);
		expect(alice.getState()).to.equal(ChannelState.SPLICING);
		expect(alice.getFullState().spliceInFlight?.conflict).to.not.equal(
			undefined
		);
		expect(alice.isQuiescing()).to.equal(false);
		expect(fx.reverted.map((r) => r.node)).to.deep.equal(['bob']);
		// A failed persist severs the peer (the manager's fail-closed rule);
		// once the disk is back the reconnect's reestablish re-asks, and bob
		// answers from his durable memory, now written.
		failing.value = false;
		expect(channelOf(fx.bob, fx.channelId).getState()).to.equal(
			ChannelState.AWAITING_REESTABLISH
		);
		await reconnect(fx.alice, fx.bob, fx);
		await tick(150);
		expect(acksFrom(fx, 'bob').map((a) => a.agreed)).to.deep.equal([
			false,
			true
		]);
		expect(fx.reverted.map((r) => r.node)).to.deep.equal(['bob', 'alice']);
		expect(alice.getState()).to.equal(ChannelState.NORMAL);
		fx.destroy();
		real.close();
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it('verifies one claim per channel at a time and answers a repeated refuted claim from memory', async () => {
		const fx = await setupNodes(7621, { sharedBackend: false });
		fx.backendA.setHistory(fx.coinScriptHash, conflictHistory(fx));
		fx.backendB.setHistory(fx.coinScriptHash, [
			{ txid: fx.coin.getId(), height: 100 }
		]);
		// Alice's chain is one block short of the verdict: a claim naming the
		// real conflict fetches, then is refuted.
		for (let h = 150; h <= 154; h++) fx.backendA.block(h);
		await tick(20);
		fx.muted.add('bob');
		channelOf(fx.bob, fx.channelId).markSpliceConflicted({
			txid: fx.conflict.getId(),
			height: 150,
			inputIndex: 1
		});
		const frame = encodeCustomMessage(
			BeignetCustomSubtype.SPLICE_CONFLICT,
			encodeSpliceConflict({
				channelId: fx.channelId,
				spliceTxid: Buffer.from(fx.spliceTx.getHash()),
				conflictTxid: Buffer.from(fx.conflict.getHash()),
				inputIndex: 1
			})
		);
		const ask = (): void =>
			fx.alice.handlePeerMessage(
				fx.bob.getNodeId(),
				BEIGNET_CUSTOM_MESSAGE_TYPE,
				frame
			);
		const fetchesOfConflict = (): number =>
			fx.backendA.fetched.filter((t) => t === fx.conflict.getId()).length;
		// Under bob's session, three identical frames in a burst.
		expect(
			fx.bob.getChannelManager().requestSpliceConflictRevert(fx.channelId).ok
		).to.equal(true);
		await tick(30);
		const before = fetchesOfConflict();
		ask();
		ask();
		ask();
		await tick(80);
		expect(
			fetchesOfConflict() - before,
			'one verification for the burst'
		).to.equal(1);
		expect(acksFrom(fx, 'alice')).to.deep.equal([
			{
				agreed: false,
				reason: 'the conflict is not confirmed at depth on our chain view'
			}
		]);
		// The same claim again at the same height fetches nothing (the
		// session is over, so the refusal is the quiescence one).
		ask();
		await tick(40);
		expect(fetchesOfConflict() - before).to.equal(1);
		expect(acksFrom(fx, 'alice')).to.have.length(2);
		fx.destroy();
	});

	it('a restart mid-conflict keeps the verdict, re-arms the watches and resumes the request after the reestablish', async () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'splice-conflict-'));
		const dbPath = path.join(dir, 'alice.sqlite');
		const storage1 = new SqliteStorage(dbPath);
		storage1.open();
		const fx = await setupNodes(7609, {
			sharedBackend: false,
			storageA: storage1
		});
		fx.backendB.setHistory(fx.coinScriptHash, [
			{ txid: fx.coin.getId(), height: 100 }
		]);
		fx.backendA.setHistory(fx.coinScriptHash, conflictHistory(fx));
		for (let h = 150; h <= 155; h++) {
			fx.backendA.block(h);
			fx.backendB.block(h);
		}
		await tick(150);
		expect(fx.conflicted).to.deep.equal(['alice']);
		expect(fx.reverted).to.deep.equal([]);
		// Persist the grafted channel the way a live node would have.
		(
			fx.alice as unknown as { persistChannel(id: Buffer): void }
		).persistChannel(fx.channelId);
		fx.alice.destroy();
		storage1.close();

		// Alice comes back. The record on disk carries the conflict; the
		// restore re-arms the splice input watch; bob's server now has the
		// conflict. The request rides quiescence, which needs a live channel,
		// so the reconnect's reestablish is what re-asks: bob verifies and
		// agrees, both revert.
		const storage2 = new SqliteStorage(dbPath);
		storage2.open();
		const backendA2 = new MockBackend();
		backendA2.setTx(fx.coin);
		backendA2.setTx(fx.spliceTx);
		backendA2.setTx(fx.conflict);
		backendA2.setHistory(fx.coinScriptHash, conflictHistory(fx));
		const configA2 = makeNodeConfig(7609);
		configA2.chainBackend = backendA2;
		configA2.storage = storage2;
		const alice2 = new LightningNode(configA2);
		fx.bob.removeAllListeners('message:outbound');
		route(alice2, 'alice2', fx.bob, fx);
		route(fx.bob, 'bob', alice2, fx);
		observe('alice2', alice2, fx);
		await tick(150);
		const restored = channelOf(alice2, fx.channelId).getFullState();
		expect(
			restored.spliceInFlight?.conflict?.txid,
			'the verdict survived'
		).to.equal(fx.conflict.getId());
		expect(
			alice2.getChainWatcher()!.spliceInputWatchesFor(fx.channelId)
		).to.have.length(1);

		// Bob's server catches up, a block on: his earlier refutation of this
		// very claim was made at the old height and is not reused.
		fx.backendB.setHistory(fx.coinScriptHash, conflictHistory(fx));
		fx.backendB.block(156);
		await reconnect(alice2, fx.bob, fx);
		await tick(250);
		expect(requestsFrom(fx, 'alice2')).to.equal(1);
		expect(fx.reverted.map((r) => r.node).sort()).to.deep.equal([
			'alice2',
			'bob'
		]);
		const after = channelOf(alice2, fx.channelId).getFullState();
		expect(after.spliceInFlight).to.equal(null);
		expect(after.fundingTxid!.equals(fx.oldFundingTxid)).to.equal(true);
		expect(channelOf(fx.bob, fx.channelId).getState()).to.equal(
			ChannelState.NORMAL
		);
		alice2.destroy();
		fx.bob.destroy();
		storage2.close();
		fs.rmSync(dir, { recursive: true, force: true });
	});
});

describe('A reverted splice is remembered across a restart (issue #760)', function () {
	this.timeout(15_000);

	it('a peer whose ack was lost asks again after our restart and is told agreed=1, so it reverts too', async () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'splice-reverted-'));
		const dbPath = path.join(dir, 'alice.sqlite');
		const storage1 = new SqliteStorage(dbPath);
		storage1.open();
		const fx = await setupNodes(7611, {
			sharedBackend: true,
			storageA: storage1,
			armAlice: false
		});
		fx.backendA.setHistory(fx.coinScriptHash, conflictHistory(fx));
		// Only bob watches, so his is the session. The ack alice gives his
		// request is lost: she verifies it, reverts and answers into the
		// void; bob's wait runs out, he abandons the request and disconnects.
		fx.muted.add('alice');
		shortenConflictTimeout(fx.bob, 150);
		for (let h = 150; h <= 155; h++) fx.backendA.block(h);
		await tick(150);
		expect(fx.reverted.map((r) => r.node)).to.deep.equal(['alice']);
		const aliceBefore = channelOf(fx.alice, fx.channelId).getFullState();
		expect(aliceBefore.state).to.equal(ChannelState.NORMAL);
		expect(aliceBefore.revertedSplices!.map((r) => r.spliceTxid)).to.deep.equal(
			[fx.spliceTx.getId()]
		);
		await tick(250);
		const bobBefore = channelOf(fx.bob, fx.channelId);
		expect(bobBefore.hasPendingSpliceConflictRequest()).to.equal(false);
		expect(bobBefore.getState()).to.equal(ChannelState.AWAITING_REESTABLISH);
		expect(bobBefore.getFullState().spliceInFlight!.conflict!.txid).to.equal(
			fx.conflict.getId()
		);
		fx.alice.destroy();
		storage1.close();

		// Alice comes back from disk with the revert remembered and no splice
		// in flight. Past his backoff, bob's reconnect re-asks on a fresh stfu
		// that alice2 answers as an ordinary NORMAL channel would.
		const storage2 = new SqliteStorage(dbPath);
		storage2.open();
		const backendA2 = new MockBackend();
		const configA2 = makeNodeConfig(7611);
		configA2.chainBackend = backendA2;
		configA2.storage = storage2;
		const alice2 = new LightningNode(configA2);
		fx.bob.removeAllListeners('message:outbound');
		route(alice2, 'alice2', fx.bob, fx);
		route(fx.bob, 'bob', alice2, fx);
		observe('alice2', alice2, fx);
		await tick(150);
		const restored = channelOf(alice2, fx.channelId).getFullState();
		expect(restored.spliceInFlight).to.equal(null);
		expect(restored.revertedSplices!.map((r) => r.spliceTxid)).to.deep.equal([
			fx.spliceTx.getId()
		]);
		expect(
			alice2.getChainWatcher()!.spliceInputWatchesFor(fx.channelId)
		).to.have.length(0);

		clearConflictBackoff(fx.bob);
		await reconnect(alice2, fx.bob, fx);
		await tick(250);
		expect(acksFrom(fx, 'alice2')).to.deep.equal([
			{ agreed: true, reason: '' }
		]);
		expect(fx.reverted.map((r) => r.node)).to.deep.equal(['alice', 'bob']);
		const bobAfter = channelOf(fx.bob, fx.channelId).getFullState();
		expect(bobAfter.state).to.equal(ChannelState.NORMAL);
		expect(bobAfter.spliceInFlight).to.equal(null);
		expect(bobAfter.fundingTxid!.equals(fx.oldFundingTxid)).to.equal(true);
		// And bob asks no more.
		const before = fx.frames.filter((f) => f.from === 'bob').length;
		fx.backendA.block(157);
		await tick(80);
		expect(fx.frames.filter((f) => f.from === 'bob').length).to.equal(before);
		// The channel list names the revert for an operator.
		const listed = alice2
			.listChannels()
			.find((c) => c.channelId.equals(fx.channelId))!;
		expect(listed.revertedSplices?.map((r) => r.spliceTxid)).to.deep.equal([
			fx.spliceTx.getId()
		]);
		alice2.destroy();
		fx.bob.destroy();
		storage2.close();
		fs.rmSync(dir, { recursive: true, force: true });
	});
});

// ─────────────── Direct-funding receiver ───────────────

describe('Direct-funding receiver on a reverted splice (issue #760)', function () {
	it('fails the request attempt behind the splice and releases the coin', async () => {
		const node = new FakeDfNode();
		node.spliceChannel = crypto.randomBytes(32);
		node.trustedPayers.add(LSP_PUBKEY);
		const record = node.mintRequest();
		const coin = makeCoin();
		node.publish(coin);
		const offer = buildOffer(record, coin);
		const payer = new FakePayerLane(record, 'lane', LSP_PUBKEY);
		const engine = new DirectFundingReceiver(node, {
			allowSplice: true,
			negotiationTimeoutMs: 5_000,
			sweepIntervalMs: 60_000
		});
		const failed: Array<{ offerId: string; reason: string }> = [];
		engine.on('offer:failed', (e: { offerId: string; reason: string }) =>
			failed.push(e)
		);
		engine.start();
		engine.handleFrame(payer.offerFrame(offer));
		await flush();
		const { channelId, tx } = node.completeSpliceNegotiation(
			coin,
			offer,
			40_000n
		);
		await flush();
		const held = node.requests.attemptsFor(record.receiptHash);
		expect(held.funding?.splice).to.equal(true);
		expect(held.funding?.fundingTxid).to.equal(tx.getId());

		// An unrelated revert changes nothing.
		node.fireSpliceReverted({
			channelId,
			spliceTxid: crypto.randomBytes(32).toString('hex'),
			conflictTxid: 'ab'.repeat(32)
		});
		expect(failed).to.deep.equal([]);
		expect(node.requests.attemptsFor(record.receiptHash).activeOfferId).to.be.a(
			'string'
		);

		node.fireSpliceReverted({
			channelId,
			spliceTxid: tx.getId(),
			conflictTxid: 'ab'.repeat(32)
		});
		expect(failed).to.deep.equal([
			{
				offerId: offer.offerId.toString('hex'),
				reason: 'the payer spent the offered coin elsewhere'
			}
		]);
		const after = node.requests.attemptsFor(record.receiptHash);
		expect(after.activeOfferId, 'busy mark released').to.equal(undefined);
		expect(after.funding).to.equal(undefined);
		expect(node.requests.activeFundings()).to.deep.equal([]);
		// The request itself stays payable by a fresh offer.
		expect(node.requests.isTombstoned(record.receiptHash)).to.equal(false);
		engine.stop();
	});
});
