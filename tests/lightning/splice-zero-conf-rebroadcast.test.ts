/**
 * A zero-conf splice keeps its BOLT 2 broadcast obligation past splice_locked
 * (issue #756).
 *
 * A zero-conf channel locks a splice the moment tx_signatures complete, with
 * zero confirmations, and the adoption used to null `spliceInFlight`, the
 * only durable copy of the signed transaction and the sole key of both
 * rebroadcast drivers. A first broadcast the network refused (a splice-out of
 * a funding that is itself not relayed yet) then had nothing left to retry
 * it: the channel ran on the new funding while the chain never saw it, and
 * the payment silently never happened.
 *
 * The obligation now lives on the channel state until the funding watch
 * reports the transaction confirmed, and both drivers walk it.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { IChainBackend } from '../../src/lightning/chain/chain-watcher';
import { Channel } from '../../src/lightning/channel/channel';
import { createOpenerState } from '../../src/lightning/channel/channel-state';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';
import {
	deserializeChannelState,
	serializeChannelState
} from '../../src/lightning/storage/serialization';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { ILightningError, INodeConfig } from '../../src/lightning/node/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { Network } from '../../src/lightning/invoice/types';

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

function zeroConfType(): Buffer {
	const flags = new FeatureFlags();
	flags.setOptional(Feature.ZERO_CONF);
	return flags.toBuffer();
}

/** A signed-looking splice tx: one input spending the old funding, one output. */
function spliceTxFor(oldFundingTxid: Buffer): bitcoin.Transaction {
	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.addInput(Buffer.from(oldFundingTxid), 1);
	tx.addOutput(
		bitcoin.payments.p2wsh({
			redeem: { output: bitcoin.script.compile([bitcoin.opcodes.OP_TRUE]) }
		}).output!,
		999_000
	);
	tx.ins[0].witness = [
		Buffer.alloc(72, 1),
		Buffer.alloc(72, 2),
		Buffer.alloc(71, 3)
	];
	return tx;
}

function splicingChannel(options: { zeroConf: boolean }): {
	channel: Channel;
	spliceTx: bitcoin.Transaction;
	spliceTxid: Buffer;
} {
	const state = createOpenerState({
		temporaryChannelId: crypto.randomBytes(32),
		fundingSatoshis: 1_000_000n,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(Buffer.alloc(32, 1)),
		localPerCommitmentSeed: Buffer.alloc(32, 3)
	});
	state.state = ChannelState.NORMAL;
	state.channelId = crypto.randomBytes(32);
	state.fundingTxid = crypto.randomBytes(32);
	state.fundingOutputIndex = 1;
	state.remoteBasepoints = makeBasepoints(Buffer.alloc(32, 2));
	if (options.zeroConf) state.channelType = zeroConfType();
	const spliceTx = spliceTxFor(state.fundingTxid);
	const spliceTxid = Buffer.from(spliceTx.getHash());
	state.spliceInFlight = {
		spliceTxid,
		newFundingOutputIndex: 0,
		newFundingSatoshis: 999_000n,
		spliceTxHex: spliceTx.toHex(),
		fullySigned: true,
		isInitiator: true,
		localRelativeSatoshis: 0n,
		remoteRelativeSatoshis: 0n,
		remoteFundingPubkey: makeBasepoints(Buffer.alloc(32, 9)).fundingPubkey,
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
	return { channel: new Channel(state), spliceTx, spliceTxid };
}

const complete = (channel: Channel): void =>
	(channel as unknown as { completeSplice: () => void }).completeSplice();

const display = (b: Buffer): string => Buffer.from(b).reverse().toString('hex');

const hexOf = (list: Buffer[] | undefined): string[] | undefined =>
	list?.map((b) => b.toString('hex'));

/** A fully signed in-flight record at its point of no return for `spliceTx`. */
function inflightFor(
	spliceTx: bitcoin.Transaction
): NonNullable<ReturnType<Channel['getFullState']>['spliceInFlight']> {
	return {
		spliceTxid: Buffer.from(spliceTx.getHash()),
		newFundingOutputIndex: 0,
		newFundingSatoshis: 999_000n,
		spliceTxHex: spliceTx.toHex(),
		fullySigned: true,
		isInitiator: true,
		localRelativeSatoshis: 0n,
		remoteRelativeSatoshis: 0n,
		remoteFundingPubkey: makeBasepoints(Buffer.alloc(32, 9)).fundingPubkey,
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
}

describe('Zero-conf splice broadcast obligation (issue #756)', () => {
	it('adoption at zero confirmations keeps the signed tx, and the rebroadcast builder still finds it', () => {
		const { channel, spliceTx, spliceTxid } = splicingChannel({
			zeroConf: true
		});
		expect(channel.buildSpliceRebroadcastActions()).to.have.length(2);
		complete(channel);
		const state = channel.getFullState();
		expect(state.spliceInFlight, 'the record died with the adoption').to.equal(
			null
		);
		expect(state.fundingTxid!.equals(spliceTxid)).to.equal(true);
		expect(state.unconfirmedSpliceTxs).to.have.length(1);
		expect(state.unconfirmedSpliceTxs![0].txid.equals(spliceTxid)).to.equal(
			true
		);
		expect(state.unconfirmedSpliceTxs![0].txHex).to.equal(spliceTx.toHex());
		const actions = channel.buildSpliceRebroadcastActions();
		expect(actions.map((a) => a.type)).to.deep.equal([
			ChannelActionType.PERSIST_STATE,
			ChannelActionType.BROADCAST_TX
		]);
		const broadcast = actions[1] as { tx: Buffer; fundingCritical?: boolean };
		expect(broadcast.tx.toString('hex')).to.equal(spliceTx.toHex());
		expect(broadcast.fundingCritical).to.equal(true);
	});

	it('an ordinary channel locks at depth and owes nothing after adoption', () => {
		const { channel } = splicingChannel({ zeroConf: false });
		complete(channel);
		expect(channel.getFullState().unconfirmedSpliceTxs ?? []).to.have.length(0);
		expect(channel.buildSpliceRebroadcastActions()).to.have.length(0);
	});

	it('a record already marked confirmed owes nothing either', () => {
		const { channel } = splicingChannel({ zeroConf: true });
		channel.markSpliceConfirmed();
		complete(channel);
		expect(channel.getFullState().unconfirmedSpliceTxs ?? []).to.have.length(0);
	});

	it('only the chain retires it: a foreign txid is ignored, the funding confirming clears it', () => {
		const { channel, spliceTxid } = splicingChannel({ zeroConf: true });
		complete(channel);
		expect(
			channel.clearConfirmedSpliceBroadcasts(display(crypto.randomBytes(32)))
		).to.equal(false);
		expect(channel.getFullState().unconfirmedSpliceTxs).to.have.length(1);
		expect(
			channel.clearConfirmedSpliceBroadcasts(display(spliceTxid))
		).to.equal(true);
		expect(channel.getFullState().unconfirmedSpliceTxs).to.have.length(0);
		expect(channel.buildSpliceRebroadcastActions()).to.have.length(0);
		expect(
			channel.clearConfirmedSpliceBroadcasts(display(spliceTxid))
		).to.equal(false);
	});

	it('a confirmation of the current funding with no txid clears every entry', () => {
		const { channel } = splicingChannel({ zeroConf: true });
		complete(channel);
		expect(channel.clearConfirmedSpliceBroadcasts()).to.equal(true);
		expect(channel.getFullState().unconfirmedSpliceTxs).to.have.length(0);
	});

	it('survives a restart: the obligation round-trips through the serialized state', () => {
		const { channel, spliceTx, spliceTxid } = splicingChannel({
			zeroConf: true
		});
		complete(channel);
		const restored = deserializeChannelState(
			JSON.parse(JSON.stringify(serializeChannelState(channel.getFullState())))
		);
		expect(restored.unconfirmedSpliceTxs).to.have.length(1);
		expect(restored.unconfirmedSpliceTxs![0].txid.equals(spliceTxid)).to.equal(
			true
		);
		expect(restored.unconfirmedSpliceTxs![0].txHex).to.equal(spliceTx.toHex());
		expect(
			new Channel(restored).buildSpliceRebroadcastActions()
		).to.have.length(2);
		// A row written before the field existed reads as owing nothing.
		const legacy = serializeChannelState(channel.getFullState());
		delete (legacy as { unconfirmedSpliceTxs?: unknown }).unconfirmedSpliceTxs;
		expect(deserializeChannelState(legacy).unconfirmedSpliceTxs).to.deep.equal(
			[]
		);
	});

	// Issue #1060: the funding a splice retires stays on the channel, so a
	// wallet that sees that outpoint spent still knows whose it was.
	it('adoption records the retired funding, and a second splice appends to it', () => {
		const { channel, spliceTxid } = splicingChannel({ zeroConf: true });
		const original = channel.getFullState().fundingTxid!.toString('hex');
		expect(channel.getFullState().previousFundingTxids).to.equal(undefined);
		complete(channel);
		const once = channel.getFullState();
		expect(once.fundingTxid!.equals(spliceTxid)).to.equal(true);
		expect(hexOf(once.previousFundingTxids)).to.deep.equal([original]);

		// A second splice on the new funding: exactly one more entry, oldest
		// first, and the current funding is never in the list.
		const second = spliceTxFor(once.fundingTxid!);
		once.spliceInFlight = inflightFor(second);
		complete(channel);
		const twice = channel.getFullState();
		expect(twice.fundingTxid!.equals(second.getHash())).to.equal(true);
		expect(hexOf(twice.previousFundingTxids)).to.deep.equal([
			original,
			spliceTxid.toString('hex')
		]);
	});

	it('the retired fundings round-trip through the serialized state; an older row reads as none', () => {
		const { channel } = splicingChannel({ zeroConf: true });
		const original = channel.getFullState().fundingTxid!.toString('hex');
		complete(channel);
		const restored = deserializeChannelState(
			JSON.parse(JSON.stringify(serializeChannelState(channel.getFullState())))
		);
		expect(hexOf(restored.previousFundingTxids)).to.deep.equal([original]);
		expect(Buffer.isBuffer(restored.previousFundingTxids![0])).to.equal(true);
		// A row written before the field existed carries no list.
		const legacy = serializeChannelState(channel.getFullState());
		delete (legacy as { previousFundingTxids?: unknown }).previousFundingTxids;
		expect(deserializeChannelState(legacy).previousFundingTxids).to.equal(
			undefined
		);
		// A never-spliced channel writes no list either.
		const fresh = splicingChannel({ zeroConf: true }).channel;
		expect(
			JSON.parse(JSON.stringify(serializeChannelState(fresh.getFullState())))
		).to.not.have.property('previousFundingTxids');
	});
});

/** A backend that records broadcasts and can be told to refuse them. */
class ControlledBackend implements IChainBackend {
	broadcasts: string[] = [];
	failBroadcasts = false;
	failReason = 'bad-txns-inputs-missingorspent';
	async subscribeToHeaders(): Promise<void> {}
	async subscribeToScriptHash(): Promise<void> {}
	async getScriptHashHistory(): Promise<
		Array<{ txid: string; height: number }>
	> {
		return [];
	}
	async getTransaction(): Promise<Buffer> {
		throw new Error('not needed');
	}
	async broadcastTransaction(hex: string): Promise<string> {
		if (this.failBroadcasts) throw new Error(this.failReason);
		this.broadcasts.push(hex);
		return bitcoin.Transaction.fromHex(hex).getId();
	}
}

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`splice-zero-conf-rebroadcast-${id}`))
		.digest();
}

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

const tick = (ms = 30): Promise<void> => new Promise((r) => setTimeout(r, ms));

/**
 * A re-ask is spaced by LightningNode.REAUTH_RETRY_MS (ten minutes) so a
 * refused barrier is not hammered every block; the test stands in for the
 * clock by forgetting the last attempt.
 */
function elapse(node: LightningNode): void {
	(
		node as unknown as { reauthAttempts: Map<string, number> }
	).reauthAttempts.clear();
}

describe('Zero-conf splice rebroadcast on the node (issue #756)', function () {
	this.timeout(10_000);

	async function setup(seedBase: number): Promise<{
		alice: LightningNode;
		bob: LightningNode;
		channelId: Buffer;
		backend: ControlledBackend;
		spliceTx: bitcoin.Transaction;
		/** The funding the grafted splice retired, internal byte order. */
		originalFundingTxid: Buffer;
		destroy: () => void;
	}> {
		const backend = new ControlledBackend();
		const configA = makeNodeConfig(seedBase);
		configA.chainBackend = backend;
		const alice = new LightningNode(configA);
		const bob = new LightningNode(makeNodeConfig(seedBase + 1));
		for (const n of [alice, bob]) {
			n.on('error', () => {});
			n.on('node:error', () => {});
		}
		alice.on(
			'message:outbound',
			(pubkey: string, type: number, payload: Buffer) => {
				if (pubkey === bob.getNodeId())
					bob.handlePeerMessage(alice.getNodeId(), type, payload);
			}
		);
		bob.on(
			'message:outbound',
			(pubkey: string, type: number, payload: Buffer) => {
				if (pubkey === alice.getNodeId())
					alice.handlePeerMessage(bob.getNodeId(), type, payload);
			}
		);
		const channel = alice.openChannel(bob.getNodeId(), 1_000_000n);
		const channelId = alice.createFunding(
			channel,
			crypto.randomBytes(32),
			0,
			crypto.randomBytes(64)
		)!;
		alice.handleFundingConfirmed(channelId);
		bob.handleFundingConfirmed(channelId);
		await tick(60);

		// Graft the zero-conf splice at its point of no return, then let the
		// lock adopt it, the way tx_signatures + splice_locked do on a
		// zero-conf channel: the record is consumed with zero confirmations.
		const ch = alice.getChannelManager().getChannel(channelId)!;
		const raw = ch.getFullState();
		raw.channelType = zeroConfType();
		const spliceTx = spliceTxFor(raw.fundingTxid!);
		raw.spliceInFlight = {
			spliceTxid: Buffer.from(spliceTx.getHash()),
			newFundingOutputIndex: 0,
			newFundingSatoshis: 999_000n,
			spliceTxHex: spliceTx.toHex(),
			fullySigned: true,
			isInitiator: true,
			localRelativeSatoshis: 0n,
			remoteRelativeSatoshis: 0n,
			remoteFundingPubkey: makeBasepoints(Buffer.alloc(32, 9)).fundingPubkey,
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
		const originalFundingTxid = Buffer.from(raw.fundingTxid!);
		complete(ch);
		expect(ch.getFullState().spliceInFlight).to.equal(null);
		return {
			alice,
			bob,
			channelId,
			backend,
			spliceTx,
			originalFundingTxid,
			destroy: (): void => {
				alice.destroy();
				bob.destroy();
			}
		};
	}

	it('the per-block driver keeps broadcasting an adopted zero-conf splice until the chain confirms it', async () => {
		const fx = await setup(7561);
		const hex = fx.spliceTx.toHex();
		const count = (): number =>
			fx.backend.broadcasts.filter((b) => b === hex).length;
		expect(count(), 'nothing put out by the graft itself').to.equal(0);

		fx.alice.handleNewBlock(150);
		await tick();
		expect(count(), 'the first block after adoption re-asks').to.equal(1);
		elapse(fx.alice);
		fx.alice.handleNewBlock(151);
		await tick();
		expect(count(), 'and again once the re-ask spacing has passed').to.equal(2);

		// The chain takes it: the funding watch reports the new funding
		// confirmed, the obligation is met, the next block asks for nothing.
		fx.alice
			.getChainWatcher()!
			.emit('funding:confirmed', fx.channelId, fx.spliceTx.getId());
		await tick();
		expect(
			fx.alice.getChannelManager().getChannel(fx.channelId)!.getFullState()
				.unconfirmedSpliceTxs
		).to.have.length(0);
		elapse(fx.alice);
		fx.alice.handleNewBlock(152);
		await tick();
		expect(count()).to.equal(2);
		fx.destroy();
	});

	it('a refused first broadcast is retried on the next block instead of being forgotten', async () => {
		const fx = await setup(7563);
		const hex = fx.spliceTx.toHex();
		fx.backend.failBroadcasts = true;
		fx.alice.handleNewBlock(150);
		await tick();
		expect(fx.backend.broadcasts.filter((b) => b === hex)).to.have.length(0);
		fx.backend.failBroadcasts = false;
		elapse(fx.alice);
		fx.alice.handleNewBlock(151);
		await tick();
		expect(fx.backend.broadcasts.filter((b) => b === hex)).to.have.length(1);
		fx.destroy();
	});

	it('the watcher giving up is reported, not silent', async () => {
		const fx = await setup(7565);
		const errors: Array<{ code: string }> = [];
		fx.alice.on('node:error', (e: { code: string }) => errors.push(e));
		fx.alice
			.getChainWatcher()!
			.emit('broadcast:permanent_failure', new Error('retries exhausted'));
		expect(errors.map((e) => e.code)).to.include('BROADCAST_PERMANENT_FAILURE');
		fx.destroy();
	});

	// Issue #1060: the channel listing has to tell the wallet which
	// transactions are this channel's, before the lock (pendingSpliceTxid)
	// and after it (previousFundingTxids), display order like fundingTxid.
	it('listChannels reports the retired funding after adoption and the in-flight splice txid before it', async () => {
		const fx = await setup(7567);
		const listed = (): ReturnType<LightningNode['listChannels']>[number] =>
			fx.alice.listChannels().find((c) => c.channelId.equals(fx.channelId))!;
		const after = listed();
		expect(after.fundingTxid).to.equal(fx.spliceTx.getId());
		expect(after.previousFundingTxids).to.deep.equal([
			display(fx.originalFundingTxid)
		]);
		expect(after.pendingSpliceLocalBalanceMsat).to.equal(undefined);
		expect(after).to.not.have.property('pendingSpliceTxid');

		// A second splice at its point of no return: the txid is present
		// exactly when the pending balance is, and the list is untouched
		// until this one is adopted too.
		const raw = fx.alice
			.getChannelManager()
			.getChannel(fx.channelId)!
			.getFullState();
		const second = spliceTxFor(raw.fundingTxid!);
		raw.spliceInFlight = inflightFor(second);
		const mid = listed();
		expect(mid.pendingSpliceLocalBalanceMsat).to.not.equal(undefined);
		expect(mid.pendingSpliceTxid).to.equal(second.getId());
		expect(mid.previousFundingTxids).to.deep.equal([
			display(fx.originalFundingTxid)
		]);
		fx.destroy();
	});

	// Issue #1062: the watcher giving up on a splice the node still re-sends
	// every block is not the end of the attempt, and the report says which
	// transaction, whose channel, and that the node is still on it.
	it('a permanent failure for an adopted but unconfirmed splice names the txid and channel, retained', async () => {
		const fx = await setup(7569);
		const errors: ILightningError[] = [];
		fx.alice.on('node:error', (e: ILightningError) => errors.push(e));
		const txid = fx.spliceTx.getId();
		fx.alice
			.getChainWatcher()!
			.emit(
				'broadcast:permanent_failure',
				new Error(`Broadcast permanently failed after 12 retries: ${txid}`),
				txid
			);
		const err = errors.find((e) => e.code === 'BROADCAST_PERMANENT_FAILURE')!;
		expect(err.txid).to.equal(txid);
		expect(err.channelId!.equals(fx.channelId)).to.equal(true);
		expect(err.retained).to.equal(true);
		expect(err.message).to.match(/rebroadcasts it on every block/);
		fx.destroy();
	});

	it('a permanent failure for a fully signed in-flight splice is retained; an unsigned record names the channel only', async () => {
		const fx = await setup(7571);
		const errors: ILightningError[] = [];
		fx.alice.on('node:error', (e: ILightningError) => errors.push(e));
		const raw = fx.alice
			.getChannelManager()
			.getChannel(fx.channelId)!
			.getFullState();
		const second = spliceTxFor(raw.fundingTxid!);
		raw.spliceInFlight = inflightFor(second);
		const watcher = fx.alice.getChainWatcher()!;
		watcher.emit(
			'broadcast:permanent_failure',
			new Error('retries exhausted'),
			second.getId()
		);
		const signed = errors.find(
			(e) => e.code === 'BROADCAST_PERMANENT_FAILURE'
		)!;
		expect(signed.txid).to.equal(second.getId());
		expect(signed.channelId!.equals(fx.channelId)).to.equal(true);
		expect(signed.retained).to.equal(true);
		// Not fully signed: the per-block driver does not owe it, so nothing
		// re-sends it, but it is still this channel's transaction.
		raw.spliceInFlight.fullySigned = false;
		errors.length = 0;
		watcher.emit(
			'broadcast:permanent_failure',
			new Error('retries exhausted'),
			second.getId()
		);
		const unsigned = errors.find(
			(e) => e.code === 'BROADCAST_PERMANENT_FAILURE'
		)!;
		expect(unsigned.channelId!.equals(fx.channelId)).to.equal(true);
		expect(unsigned.retained).to.equal(false);
		expect(unsigned.message).to.not.match(/rebroadcasts it on every block/);
		fx.destroy();
	});

	it('a refused rebroadcast raises SPLICE_BROADCAST_REFUSED once per txid and reason, with the backend message', async () => {
		const fx = await setup(7573);
		const errors: ILightningError[] = [];
		fx.alice.on('node:error', (e: ILightningError) => errors.push(e));
		const logs: Array<{ action: string; data: Record<string, unknown> }> = [];
		fx.alice.on('log', (l: { action: string; data: Record<string, unknown> }) =>
			logs.push(l)
		);
		const refused = (): ILightningError[] =>
			errors.filter((e) => e.code === 'SPLICE_BROADCAST_REFUSED');
		// The barrier answered for this splice in this process, so the
		// per-block driver re-sends straight at the backend.
		(
			fx.alice as unknown as { authorizedSpliceBroadcasts: Set<string> }
		).authorizedSpliceBroadcasts.add(fx.channelId.toString('hex'));
		fx.backend.failBroadcasts = true;
		fx.alice.handleNewBlock(150);
		await tick();
		expect(refused()).to.have.length(1);
		const first = refused()[0];
		expect(first.txid).to.equal(fx.spliceTx.getId());
		expect(first.channelId!.equals(fx.channelId)).to.equal(true);
		expect(first.retained).to.equal(true);
		expect(first.message).to.include('bad-txns-inputs-missingorspent');
		expect(first.message).to.match(/rebroadcasts it on every block/);
		// The log line carries the backend's reason too, not just the channel.
		const logged = logs.find((l) => l.action === 'splice_rebroadcast_failed')!;
		expect(logged.data.error).to.equal('bad-txns-inputs-missingorspent');
		expect(logged.data.channelId).to.equal(fx.channelId.toString('hex'));
		// The same refusal on the next block: the log repeats, the error
		// does not.
		fx.alice.handleNewBlock(151);
		await tick();
		expect(refused()).to.have.length(1);
		expect(
			logs.filter((l) => l.action === 'splice_rebroadcast_failed')
		).to.have.length(2);
		// A different reason is a different report.
		fx.backend.failReason = 'min relay fee not met';
		fx.alice.handleNewBlock(152);
		await tick();
		expect(refused()).to.have.length(2);
		expect(refused()[1].message).to.include('min relay fee not met');
		// The network already having the transaction is the outcome wanted,
		// never a refusal.
		fx.backend.failReason = 'txn-already-in-mempool';
		fx.alice.handleNewBlock(153);
		await tick();
		expect(refused()).to.have.length(2);
		fx.destroy();
	});

	// Issue #921: Bitcoin Core 28 renamed "Transaction already in block
	// chain" to "Transaction outputs already in utxo set". Every block
	// between the splice's first confirmation and the lock re-sends it, and
	// each answer says the splice is mined, not refused.
	it('a mined splice answered in the Core 28+ wording is not reported as refused', async () => {
		const fx = await setup(7575);
		const errors: ILightningError[] = [];
		fx.alice.on('node:error', (e: ILightningError) => errors.push(e));
		(
			fx.alice as unknown as { authorizedSpliceBroadcasts: Set<string> }
		).authorizedSpliceBroadcasts.add(fx.channelId.toString('hex'));
		// Count the attempts, refused ones included, so the test cannot pass
		// on a driver that never re-sent anything.
		const attempts: string[] = [];
		const send = fx.backend.broadcastTransaction.bind(fx.backend);
		fx.backend.broadcastTransaction = async (hex: string): Promise<string> => {
			attempts.push(hex);
			return send(hex);
		};
		fx.backend.failBroadcasts = true;
		fx.backend.failReason =
			'Broadcast failed: Transaction outputs already in utxo set';
		fx.alice.handleNewBlock(150);
		await tick();
		fx.backend.failReason = 'Transaction already in block chain';
		fx.alice.handleNewBlock(151);
		await tick();
		expect(
			attempts.filter((hex) => hex === fx.spliceTx.toHex()),
			'the splice was re-sent on both blocks'
		).to.have.length(2);
		expect(
			errors.filter((e) => e.code === 'SPLICE_BROADCAST_REFUSED')
		).to.have.length(0);
		fx.destroy();
	});
});
