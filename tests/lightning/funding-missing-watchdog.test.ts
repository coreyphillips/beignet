/**
 * Funding-missing watchdog and channel voiding.
 *
 * A zero-conf channel is NORMAL while its funding tx sits unconfirmed. If
 * that tx is evicted from the mempool or an input is double-spent, the
 * channel silently becomes fiction. The chain watcher must alarm after a
 * debounce ('funding:missing'), and the node must then VOID the channel:
 * drop it, delete its persisted state, and emit 'channel:voided'. A
 * vanished SPLICE tx is alarm-only, because the pre-splice channel is real.
 */
import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import {
	ChainWatcher,
	IChainBackend
} from '../../src/lightning/chain/chain-watcher';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { ILightningError, INodeConfig } from '../../src/lightning/node/types';
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { Network } from '../../src/lightning/invoice/types';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';

bitcoin.initEccLib(ecc);

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`funding-missing-seed-${id}`))
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
	const nodePrivateKey = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from('node-identity'))
		.digest();
	const fundingPrivkey = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([0]))
		.digest();
	return {
		nodePrivateKey,
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey
	};
}

/** A backend whose script-hash history is fully controllable per test. */
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

const tick = (ms = 25) => new Promise((r) => setTimeout(r, ms));

describe('Funding-missing watchdog', function () {
	let backend: ControlledBackend;
	let watcher: ChainWatcher;
	let missing: Array<{ channelId: string; txid: string }>;

	beforeEach(async () => {
		backend = new ControlledBackend();
		const channelManager = new ChannelManager({
			localBasepoints: makeBasepoints(makeSeed(1)),
			localPerCommitmentSeed: crypto.randomBytes(32),
			localFundingPrivkey: crypto.randomBytes(32)
		});
		channelManager.on('error', () => {});
		watcher = new ChainWatcher({ backend, channelManager });
		watcher.on('error', () => {});
		missing = [];
		watcher.on('funding:missing', (channelId: Buffer, txid: string) => {
			missing.push({ channelId: channelId.toString('hex'), txid });
		});
	});

	afterEach(() => watcher.stop());

	const channelId = Buffer.alloc(32, 7);
	const fundingTxid = '11'.repeat(32);
	const fundingScript = Buffer.from('0020' + '22'.repeat(32), 'hex');

	async function recheck(times: number): Promise<void> {
		for (let i = 0; i < times; i++) {
			watcher.recheckAllWatches();
			await tick();
		}
	}

	it('alarms once after three consecutive absences, not before', async function () {
		// Registration performs an immediate check; make it see the tx present
		// so the absence count afterwards is exact.
		backend.history = [{ txid: fundingTxid, height: 0 }];
		await watcher.watchFundingOutput(
			channelId,
			fundingTxid,
			0,
			1,
			fundingScript
		);
		await tick();
		backend.history = [];

		await recheck(2);
		expect(missing.length, 'debounce: no alarm before 3 checks').to.equal(0);
		await recheck(1);
		expect(missing.length, 'alarm after the 3rd absence').to.equal(1);
		expect(missing[0].txid).to.equal(fundingTxid);
		await recheck(3);
		expect(missing.length, 'debounced: no repeat alarms').to.equal(1);
	});

	it('a reappearing tx resets the counter and the alarm can fire again', async function () {
		backend.history = [{ txid: fundingTxid, height: 0 }];
		await watcher.watchFundingOutput(
			channelId,
			fundingTxid,
			0,
			1,
			fundingScript
		);
		await tick();
		backend.history = [];

		await recheck(2);
		// The tx bounces back into the mempool (e.g. a reorg or a re-broadcast).
		backend.history = [{ txid: fundingTxid, height: 0 }];
		await recheck(1);
		expect(missing.length, 'presence resets the counter').to.equal(0);

		// Gone again: the debounce starts over and the alarm fires anew.
		backend.history = [];
		await recheck(2);
		expect(missing.length).to.equal(0);
		await recheck(1);
		expect(missing.length).to.equal(1);
	});

	it('a merely unconfirmed (mempool) tx never alarms', async function () {
		backend.history = [{ txid: fundingTxid, height: 0 }];
		await watcher.watchFundingOutput(
			channelId,
			fundingTxid,
			0,
			1,
			fundingScript
		);
		await recheck(5);
		expect(missing.length).to.equal(0);
	});
});

describe('Channel voiding on funding:missing', function () {
	function setupPair(aSeed: number, bSeed: number) {
		const configA = makeNodeConfig(aSeed);
		configA.chainBackend = new ControlledBackend();
		const alice = new LightningNode(configA);
		const configB = makeNodeConfig(bSeed);
		const bob = new LightningNode(configB);
		alice.on('node:error', () => {});
		bob.on('node:error', () => {});

		alice.on('message:outbound', (pubkey, type, payload) => {
			if (pubkey === bob.getNodeId()) {
				bob.handlePeerMessage(alice.getNodeId(), type, payload);
			}
		});
		bob.on('message:outbound', (pubkey, type, payload) => {
			if (pubkey === alice.getNodeId()) {
				alice.handlePeerMessage(bob.getNodeId(), type, payload);
			}
		});

		const channel = alice.openChannel(bob.getNodeId(), 1_000_000n);
		const channelId = alice.createFunding(
			channel,
			crypto.randomBytes(32),
			0,
			crypto.randomBytes(64)
		)!;
		alice.handleFundingConfirmed(channelId);
		bob.handleFundingConfirmed(channelId);
		return { alice, bob, channelId };
	}

	it('voids the channel: dropped, watch retired, channel:voided emitted', async function () {
		const { alice, bob, channelId } = setupPair(900, 901);
		await tick(60); // let the chain watcher auto-start

		const voided: Buffer[] = [];
		const errors: ILightningError[] = [];
		alice.removeAllListeners('node:error');
		alice.on('node:error', (e: ILightningError) => errors.push(e));
		alice.on('channel:voided', (d: { channelId: Buffer }) =>
			voided.push(d.channelId)
		);

		expect(alice.listChannels().length).to.equal(1);
		alice
			.getChainWatcher()!
			.emit('funding:missing', channelId, '33'.repeat(32));

		expect(voided.length, 'channel:voided emitted').to.equal(1);
		expect(voided[0].equals(channelId)).to.equal(true);
		expect(
			alice.listChannels().length,
			'the channel is gone entirely (nothing to close)'
		).to.equal(0);
		expect(errors.some((e) => e.code === 'FUNDING_MISSING')).to.equal(true);

		alice.destroy();
		bob.destroy();
	});

	it('a vanished splice tx is alarm-only: the live channel survives', async function () {
		const { alice, bob, channelId } = setupPair(902, 903);
		await tick(60);

		const voided: Buffer[] = [];
		alice.on('channel:voided', (d: { channelId: Buffer }) =>
			voided.push(d.channelId)
		);

		// White-box: mark the channel as mid-splice; a real splice needs a full
		// interactive negotiation, but the guard only inspects spliceInFlight.
		const channel = alice.getChannelManager().getChannel(channelId)!;
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(channel.getFullState() as any).spliceInFlight = {
			spliceTxid: Buffer.from('44'.repeat(32), 'hex')
		};

		alice
			.getChainWatcher()!
			.emit('funding:missing', channelId, '44'.repeat(32));

		expect(voided.length, 'no voiding for a splice tx').to.equal(0);
		expect(
			alice.getChannelManager().getChannel(channelId),
			'the pre-splice channel is untouched'
		).to.not.equal(undefined);

		alice.destroy();
		bob.destroy();
	});
});
