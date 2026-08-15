/**
 * Issue #357: a splice that confirms on a FORCE_CLOSED channel voids the
 * old-funding commitment the node broadcast (both spend the old funding
 * outpoint). The node must notice the confirmation via the funding watch,
 * durably mark the in-flight record confirmed (even when the splice session
 * died with the channel failure), and re-drive the close on the adopted new
 * funding automatically instead of waiting for an operator rebroadcast.
 */
import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { IChainBackend } from '../../src/lightning/chain/chain-watcher';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { Network } from '../../src/lightning/invoice/types';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { ISpliceInFlight } from '../../src/lightning/channel/channel-state';

bitcoin.initEccLib(ecc);

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`splice-close-redrive-seed-${id}`))
		.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 6; i++) {
		const priv = crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([i]))
			.digest();
		keys.push(getPublicKey(priv));
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
		if (this.failBroadcasts) throw new Error('connection refused');
		this.broadcasts.push(hex);
		return bitcoin.Transaction.fromHex(hex).getId();
	}
}

const tick = (ms = 25): Promise<void> => new Promise((r) => setTimeout(r, ms));

interface IFixture {
	alice: LightningNode;
	bob: LightningNode;
	channelId: Buffer;
	backend: ControlledBackend;
	destroy: () => void;
}

async function setup(seedBase: number): Promise<IFixture> {
	const backend = new ControlledBackend();
	const configA = makeNodeConfig(seedBase);
	configA.chainBackend = backend;
	const alice = new LightningNode(configA);
	const bob = new LightningNode(makeNodeConfig(seedBase + 1));
	alice.on('error', () => {});
	alice.on('node:error', () => {});
	bob.on('error', () => {});
	bob.on('node:error', () => {});
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
	await tick(60); // let the chain watcher auto-start

	return {
		alice,
		bob,
		channelId,
		backend,
		destroy: (): void => {
			alice.destroy();
			bob.destroy();
		}
	};
}

function destScript(node: LightningNode): Buffer {
	return bitcoin.payments.p2wpkh({
		pubkey: Buffer.from(node.getNodeId(), 'hex')
	}).output!;
}

/**
 * Graft a session-free point-of-no-return splice record onto the channel:
 * the markErrored / crash-restart shape where only the persisted record
 * survives. A real splice needs a full interactive negotiation; the
 * adoption path deliberately judges the record alone.
 */
function graftSpliceRecord(
	node: LightningNode,
	channelId: Buffer
): { spliceTxid: Buffer; displayHex: string } {
	const channel = node.getChannelManager().getChannel(channelId)!;
	const spliceTxid = crypto.randomBytes(32);
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	(channel.getFullState() as any).spliceInFlight = {
		spliceTxid,
		newFundingOutputIndex: 0,
		newFundingSatoshis: 1_000_000n,
		spliceTxHex: '',
		fullySigned: true,
		isInitiator: true,
		localRelativeSatoshis: 0n,
		remoteRelativeSatoshis: 0n,
		remoteFundingPubkey: getPublicKey(crypto.randomBytes(32)),
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
		spliceTxid,
		displayHex: Buffer.from(spliceTxid).reverse().toString('hex')
	};
}

function record(
	node: LightningNode,
	channelId: Buffer
): ISpliceInFlight | null {
	return (
		node.getChannelManager().getChannel(channelId)!.getFullState()
			.spliceInFlight ?? null
	);
}

describe('Issue #357: splice confirmation re-drives a FORCE_CLOSED close', function () {
	this.timeout(10_000);

	it('marks the record confirmed, adopts the new funding, and rebroadcasts the close', async () => {
		const fx = await setup(3571);
		const forced = fx.alice.forceCloseChannel(
			fx.channelId,
			destScript(fx.alice)
		);
		expect(forced.ok).to.equal(true);
		const { spliceTxid, displayHex } = graftSpliceRecord(
			fx.alice,
			fx.channelId
		);
		const broadcastsBefore = fx.backend.broadcasts.length;

		fx.alice
			.getChainWatcher()!
			.emit('funding:confirmed', fx.channelId, displayHex);
		await tick();

		const channel = fx.alice.getChannelManager().getChannel(fx.channelId)!;
		const state = channel.getFullState();
		// The adoption consumed the record and moved the channel onto the
		// confirmed new funding, still terminal.
		expect(state.spliceInFlight, 'record consumed by the adoption').to.equal(
			null
		);
		expect(
			state.fundingTxid!.equals(spliceTxid),
			'new funding adopted'
		).to.equal(true);
		expect(channel.getState()).to.equal(ChannelState.FORCE_CLOSED);
		// A close for the NEW funding reached the network without any operator call.
		expect(fx.backend.broadcasts.length).to.equal(broadcastsBefore + 1);
		const redriven = bitcoin.Transaction.fromHex(
			fx.backend.broadcasts[fx.backend.broadcasts.length - 1]
		);
		expect(
			Buffer.from(redriven.ins[0].hash).equals(spliceTxid),
			'redriven close spends the confirmed splice funding'
		).to.equal(true);
		expect(redriven.getId()).to.not.equal(forced.commitmentTxid);
		fx.destroy();
	});

	it('marks the record confirmed with no live session, so a manual rebroadcast can adopt too', async () => {
		const fx = await setup(3581);
		fx.alice.forceCloseChannel(fx.channelId, destScript(fx.alice));
		const { displayHex } = graftSpliceRecord(fx.alice, fx.channelId);
		// Suppress the automatic re-drive so this test isolates the durable
		// confirmation marking (the manual-recovery half of the fix).
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(fx.alice as any).redriveSpliceAdoptedClose = async (): Promise<void> => {};

		fx.alice
			.getChainWatcher()!
			.emit('funding:confirmed', fx.channelId, displayHex);
		await tick();

		expect(
			record(fx.alice, fx.channelId)!.confirmed,
			'confirmation recorded despite the dead session'
		).to.equal(true);

		const manual = await fx.alice.rebroadcastClose(fx.channelId);
		expect(manual.ok).to.equal(true);
		expect(manual.broadcastOk).to.equal(true);
		expect(
			record(fx.alice, fx.channelId),
			'manual rebroadcast consumed the confirmed record'
		).to.equal(null);
		fx.destroy();
	});

	it('a confirmation for a different txid neither marks nor re-drives', async () => {
		const fx = await setup(3591);
		fx.alice.forceCloseChannel(fx.channelId, destScript(fx.alice));
		graftSpliceRecord(fx.alice, fx.channelId);
		const broadcastsBefore = fx.backend.broadcasts.length;

		fx.alice
			.getChainWatcher()!
			.emit('funding:confirmed', fx.channelId, '99'.repeat(32));
		await tick();

		expect(record(fx.alice, fx.channelId)!.confirmed).to.equal(false);
		expect(fx.backend.broadcasts.length).to.equal(broadcastsBefore);
		fx.destroy();
	});

	it('a live channel records the confirmation but never re-drives a close', async () => {
		const fx = await setup(3601);
		const { displayHex } = graftSpliceRecord(fx.alice, fx.channelId);
		const broadcastsBefore = fx.backend.broadcasts.length;

		fx.alice
			.getChainWatcher()!
			.emit('funding:confirmed', fx.channelId, displayHex);
		await tick();

		expect(record(fx.alice, fx.channelId)!.confirmed).to.equal(true);
		expect(
			fx.alice.getChannelManager().getChannel(fx.channelId)!.getState()
		).to.equal(ChannelState.NORMAL);
		expect(fx.backend.broadcasts.length).to.equal(broadcastsBefore);
		fx.destroy();
	});

	it('retries a failed re-drive broadcast on the next block', async () => {
		const fx = await setup(3611);
		fx.alice.forceCloseChannel(fx.channelId, destScript(fx.alice));
		const { spliceTxid, displayHex } = graftSpliceRecord(
			fx.alice,
			fx.channelId
		);

		fx.backend.failBroadcasts = true;
		fx.alice
			.getChainWatcher()!
			.emit('funding:confirmed', fx.channelId, displayHex);
		await tick();

		// The adoption stuck (it is state, not a broadcast), the broadcast did
		// not, and the re-drive armed its per-block retry.
		const channel = fx.alice.getChannelManager().getChannel(fx.channelId)!;
		expect(channel.getFullState().fundingTxid!.equals(spliceTxid)).to.equal(
			true
		);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		expect((fx.alice as any)._pendingSpliceCloseRedrives.size).to.equal(1);

		fx.backend.failBroadcasts = false;
		const broadcastsBefore = fx.backend.broadcasts.length;
		fx.alice.handleNewBlock(800_000);
		await tick();

		expect(fx.backend.broadcasts.length).to.equal(broadcastsBefore + 1);
		const redriven = bitcoin.Transaction.fromHex(
			fx.backend.broadcasts[fx.backend.broadcasts.length - 1]
		);
		expect(Buffer.from(redriven.ins[0].hash).equals(spliceTxid)).to.equal(true);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		expect((fx.alice as any)._pendingSpliceCloseRedrives.size).to.equal(0);
		fx.destroy();
	});

	it('a repeat confirmation after the adoption is a no-op', async () => {
		const fx = await setup(3621);
		fx.alice.forceCloseChannel(fx.channelId, destScript(fx.alice));
		const { displayHex } = graftSpliceRecord(fx.alice, fx.channelId);

		fx.alice
			.getChainWatcher()!
			.emit('funding:confirmed', fx.channelId, displayHex);
		await tick();
		const broadcastsAfterFirst = fx.backend.broadcasts.length;

		// The restart re-arm latches and re-fires once per run; the record is
		// gone, so nothing may be marked or re-driven again.
		fx.alice
			.getChainWatcher()!
			.emit('funding:confirmed', fx.channelId, displayHex);
		await tick();

		expect(fx.backend.broadcasts.length).to.equal(broadcastsAfterFirst);
		fx.destroy();
	});
});
