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
import { INodeConfig } from '../../src/lightning/node/types';
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
});

/** A backend that records broadcasts and can be told to refuse them. */
class ControlledBackend implements IChainBackend {
	broadcasts: string[] = [];
	failBroadcasts = false;
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
		if (this.failBroadcasts) throw new Error('bad-txns-inputs-missingorspent');
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
		complete(ch);
		expect(ch.getFullState().spliceInFlight).to.equal(null);
		return {
			alice,
			bob,
			channelId,
			backend,
			spliceTx,
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
});
