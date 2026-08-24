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

/**
 * Issue #479: the durable record the restart path re-arms from must be written
 * by the CHANNEL, in the batch that authorizes the splice broadcast, carrying
 * the superseded outpoint's OWN script.
 *
 * Two things went wrong when the node wrote it instead. It derived the script
 * from the channel's CURRENT funding keys, and a splice may rotate the peer's
 * funding pubkey (CLN does), so the watch subscribed to a script hash the old
 * output never paid. And it ran asynchronously off watch:funding, which on a
 * zero-conf channel fires after splice_locked has already adopted the new
 * funding, so the continuation read post-splice state.
 */
describe('Pre-splice spend watch record (issue #479)', () => {
	function makeSplicingChannel(): {
		channel: import('../../src/lightning/channel/channel').Channel;
		spliceTxid: Buffer;
		oldFundingTxid: Buffer;
		rotatedRemoteFundingPubkey: Buffer;
	} {
		const {
			createOpenerState
		} = require('../../src/lightning/channel/channel-state');
		const { Channel } = require('../../src/lightning/channel/channel');
		const {
			ChannelState,
			DEFAULT_CHANNEL_CONFIG
		} = require('../../src/lightning/channel/types');

		const local = makeBasepoints(Buffer.alloc(32, 1));
		const remote = makeBasepoints(Buffer.alloc(32, 2));
		const state = createOpenerState({
			temporaryChannelId: crypto.randomBytes(32),
			fundingSatoshis: 1_000_000n,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: local,
			localPerCommitmentSeed: Buffer.alloc(32, 3)
		});
		state.state = ChannelState.NORMAL;
		state.channelId = crypto.randomBytes(32);
		state.fundingTxid = crypto.randomBytes(32);
		state.fundingOutputIndex = 1;
		state.remoteBasepoints = remote;

		// The splice rotates the peer's funding pubkey, which is what makes the
		// channel's post-splice script the wrong one to watch the old output
		// with.
		const rotated = makeBasepoints(Buffer.alloc(32, 9)).fundingPubkey;
		const spliceTxid = crypto.randomBytes(32);
		state.spliceInFlight = {
			spliceTxid,
			newFundingOutputIndex: 0,
			newFundingSatoshis: 1_000_000n,
			spliceTxHex: '',
			fullySigned: true,
			isInitiator: true,
			localRelativeSatoshis: 0n,
			remoteRelativeSatoshis: 0n,
			remoteFundingPubkey: rotated,
			ourSharedInputSig: Buffer.alloc(64),
			ourWalletWitnesses: [],
			ourWalletInputIndices: [],
			inputPrevouts: [],
			remoteCommitmentSig: crypto.randomBytes(64),
			sentTxSignatures: true,
			receivedTxSignatures: true,
			localSpliceLocked: false,
			remoteSpliceLocked: false,
			confirmed: false
		};
		return {
			channel: new Channel(state),
			spliceTxid,
			oldFundingTxid: state.fundingTxid,
			rotatedRemoteFundingPubkey: rotated
		};
	}

	it('records the superseded outpoint with its own pre-splice script', () => {
		const { channel, spliceTxid, oldFundingTxid, rotatedRemoteFundingPubkey } =
			makeSplicingChannel();
		const state = channel.getFullState();
		const {
			createFundingScript
		} = require('../../src/lightning/script/funding');

		(
			channel as unknown as {
				_recordPreSpliceSpendWatch: (t: Buffer) => void;
			}
		)._recordPreSpliceSpendWatch(spliceTxid);

		const legs = state.preSpliceSpendWatches ?? [];
		expect(legs, 'one leg recorded').to.have.length(1);
		expect(legs[0].txid).to.equal(
			Buffer.from(oldFundingTxid).reverse().toString('hex')
		);
		expect(legs[0].outputIndex).to.equal(1);
		expect(legs[0].spliceTxid).to.equal(
			Buffer.from(spliceTxid).reverse().toString('hex')
		);

		// The PRE-splice script, built from the peer's pre-splice funding key.
		const preSplice = createFundingScript(
			state.localBasepoints.fundingPubkey,
			state.remoteBasepoints!.fundingPubkey
		).p2wshOutput as Buffer;
		const postSplice = createFundingScript(
			state.localBasepoints.fundingPubkey,
			rotatedRemoteFundingPubkey
		).p2wshOutput as Buffer;
		expect(legs[0].script).to.equal(preSplice.toString('hex'));
		expect(
			legs[0].script,
			'a rotated funding key makes the current script the wrong one'
		).to.not.equal(postSplice.toString('hex'));
		expect(computeScriptHash(preSplice)).to.not.equal(
			computeScriptHash(postSplice)
		);
	});

	it('captures pre-splice values even though splice_locked follows in the same batch', () => {
		const { channel, spliceTxid, oldFundingTxid } = makeSplicingChannel();
		const state = channel.getFullState();
		const priv = channel as unknown as {
			_recordPreSpliceSpendWatch: (t: Buffer) => void;
			completeSplice: () => void;
		};

		// The real ordering inside handleTxSignatures: the record is taken
		// where the WATCH_FUNDING is pushed, and completeSplice runs after, in
		// the same action array. Anything reading channel state afterwards
		// (the node's own watch:funding handler, for one) sees the adopted
		// funding.
		priv._recordPreSpliceSpendWatch(spliceTxid);
		priv.completeSplice();

		expect(state.fundingTxid!.equals(spliceTxid), 'the splice was adopted').to
			.be.true;
		expect(
			state.spliceInFlight,
			'and the record it was rebuilt from is gone'
		).to.equal(null);
		// The leg still names the outpoint the splice superseded, not the one
		// it created.
		expect(state.preSpliceSpendWatches![0].txid).to.equal(
			Buffer.from(oldFundingTxid).reverse().toString('hex')
		);
	});

	it('arms the leg in the same batch that reaches the point of no return', () => {
		// Once our tx_signatures leave, the peer can assemble and broadcast the
		// splice without us. No WATCH_FUNDING is in that batch, because the
		// transaction has not been broadcast and cannot be by us, so before
		// this the superseded outpoint had no live subscription at all between
		// our signature leaving and the peer's arriving: a node that did not
		// restart was blind to a revoked pre-splice commitment for the whole
		// window, and the channel's own watch would have read the legitimate
		// splice as a close.
		const { channel, spliceTxid } = makeSplicingChannel();
		const {
			ChannelActionType
		} = require('../../src/lightning/channel/channel-actions');
		const { SpliceState } = require('../../src/lightning/channel/splice');
		const { MessageType } = require('../../src/lightning/message/types');
		const priv = channel as unknown as Record<string, unknown>;

		// The state _maybeSendSpliceTxSigs runs in: the interactive tx is
		// complete, the commitment round is done, and we sign first.
		priv._spliceSession = {
			getState: () => SpliceState.AWAITING_TX_SIGNATURES
		};
		priv._spliceSentCommitment = true;
		priv._spliceReceivedCommitment = true;
		priv._spliceSentTxSigs = false;
		priv._signer = {};
		priv._spliceTx = { ourWalletWitnesses: [], newFundingOutputIndex: 0 };
		priv.buildAndSignSpliceTx = (): unknown => ({
			spliceTxid,
			newFundingOutputIndex: 0,
			signature: Buffer.alloc(64)
		});

		const actions = (
			priv._maybeSendSpliceTxSigs as () => Array<{
				type: string;
				messageType?: number;
			}>
		).call(channel);

		const types = actions.map((a) => a.type);
		expect(
			types.indexOf(ChannelActionType.PERSIST_STATE),
			'the records reach disk first'
		).to.equal(0);
		expect(
			types.indexOf(ChannelActionType.WATCH_PRESPLICE_SPEND),
			'then the superseded outpoint is covered'
		).to.equal(1);
		// BOTH outputs, not just the old one. Our signature completes the
		// shared 2-of-2 input, so from here the peer can publish the splice and
		// its own commitment on the spliced funding while withholding its
		// tx_signatures. Without this the new output was watched by nothing,
		// and once the leg retired at depth the channel's own watch, still on
		// the old outpoint, read the splice itself as a close.
		const watchNew = actions.find(
			(a) => a.type === ChannelActionType.WATCH_FUNDING
		) as unknown as { fundingTxid: Buffer; fundingOutputIndex: number };
		expect(watchNew, 'and so is the one the splice creates').to.not.equal(
			undefined
		);
		expect(watchNew.fundingTxid.equals(spliceTxid)).to.equal(true);
		expect(watchNew.fundingOutputIndex).to.equal(0);

		const send = actions.find(
			(a) =>
				a.type === ChannelActionType.SEND_MESSAGE &&
				a.messageType === MessageType.TX_SIGNATURES
		);
		expect(send, 'and only then does our signature leave').to.not.equal(
			undefined
		);
		expect(
			types.indexOf(ChannelActionType.SEND_MESSAGE),
			'in that order'
		).to.equal(types.length - 1);
		expect(channel.getFullState().preSpliceSpendWatches).to.have.length(1);
	});

	it('persists the leg a refused tx_signatures records', () => {
		// The refusal batch is the only thing that knows about the leg it just
		// recorded, and nothing downstream of a refusal is guaranteed to
		// persist the channel.
		const { channel, spliceTxid } = makeSplicingChannel();
		const {
			ChannelActionType
		} = require('../../src/lightning/channel/channel-actions');
		const priv = channel as unknown as Record<string, unknown>;
		priv._spliceSentTxSigs = true;
		channel.getFullState().spliceInFlight!.spliceTxid = spliceTxid;

		const actions = (
			priv._spliceTxSigsRefusal as (m: string) => Array<{ type: string }>
		).call(channel, 'nope');
		const types = actions.map((a) => a.type);
		expect(types[0], 'the persist leads the batch').to.equal(
			ChannelActionType.PERSIST_STATE
		);
		expect(types).to.include(ChannelActionType.WATCH_PRESPLICE_SPEND);
		expect(types).to.include(ChannelActionType.WATCH_FUNDING);
	});

	it('records no leg for a splice that has not reached the point of no return (issue #479)', () => {
		// Before our tx_signatures leave, nobody can broadcast that splice, so
		// the outpoint needs no leg - and recording one anyway makes it OUTLIVE
		// the negotiation, because such a splice can still be safely aborted.
		// Legs are keyed per outpoint, so the stale entry would then block a
		// later splice of the SAME outpoint from recording its real expected
		// spender, and the watcher would report that splice's own valid
		// transaction as a close.
		const { channel } = makeSplicingChannel();
		const state = channel.getFullState();
		state.preSpliceSpendWatches = undefined;
		state.spliceInFlight!.sentTxSignatures = false;

		expect(
			channel.recordInFlightPreSpliceSpendWatch(),
			'nothing is recorded before our signature leaves'
		).to.equal(false);
		expect(state.preSpliceSpendWatches).to.equal(undefined);

		// The splice is safely aborted and a NEW one takes its place on the
		// same outpoint. Its expected spender is the one that must be recorded.
		const secondSpliceTxid = crypto.randomBytes(32);
		state.spliceInFlight!.spliceTxid = secondSpliceTxid;
		state.spliceInFlight!.sentTxSignatures = true;

		expect(channel.recordInFlightPreSpliceSpendWatch()).to.equal(true);
		expect(state.preSpliceSpendWatches![0].spliceTxid).to.equal(
			Buffer.from(secondSpliceTxid).reverse().toString('hex')
		);
	});

	it('records one leg per superseded outpoint, never a duplicate', () => {
		const { channel, spliceTxid } = makeSplicingChannel();
		const priv = channel as unknown as {
			_recordPreSpliceSpendWatch: (t: Buffer) => void;
		};
		priv._recordPreSpliceSpendWatch(spliceTxid);
		priv._recordPreSpliceSpendWatch(spliceTxid);
		expect(channel.getFullState().preSpliceSpendWatches).to.have.length(1);
	});
});
