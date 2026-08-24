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
		// The shape this suite is about, and the only one BOLT 2's forget clock
		// is for: NORMAL while the funding transaction has never reached the
		// chain. A channel whose funding our OWN watcher has seen is never
		// retired by absence (issue #481), so the zero-conf trust that let it
		// go NORMAL early has to be on the row for the clock to run at all.
		for (const node of [alice, bob]) {
			const st = (
				node as unknown as {
					channelManager: {
						getChannel: (id: Buffer) => {
							getFullState: () => Record<string, unknown>;
						};
					};
				}
			).channelManager
				.getChannel(channelId)
				.getFullState();
			st.zeroConfEnabled = true;
			st.trustedPeer = true;
		}
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
		// BOLT 2 forgets an unconfirmed funding only after 2016 blocks, and
		// this node holds no signed transaction of its own, so the first
		// absence starts a clock rather than reaching a verdict. Forgetting
		// sooner would force a funder whose broadcast is merely late to close
		// and reopen a channel that was never in trouble.
		alice.handleNewBlock(700_000);
		alice
			.getChainWatcher()!
			.emit('funding:missing', channelId, '33'.repeat(32));
		expect(voided.length, 'not voided on the first absence').to.equal(0);
		expect(alice.listChannels().length).to.equal(1);

		alice.handleNewBlock(700_000 + 2016);
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

	it('never voids a channel whose funding this node has seen on chain (issue #481)', async function () {
		// A splice that ends without its transaction confirming leaves the
		// channel's funding watch on an outpoint that may never exist, and both
		// the abort path and the zero-conf completeSplice null spliceInFlight
		// while it does. Three absent answers plus BOLT 2's 2016 blocks then
		// voided a live, funded channel, taking its monitor and its SCB entry
		// with it. Only the chain may retire a channel (issue #463), and the
		// chain has already spoken here.
		const { alice, bob, channelId } = setupPair(902, 903);
		await tick(60);

		const state = (
			alice as unknown as {
				channelManager: {
					getChannel: (id: Buffer) => {
						getFullState: () => Record<string, unknown>;
					};
				};
			}
		).channelManager
			.getChannel(channelId)
			.getFullState();
		// Our OWN watcher saw the funding reach depth; setupPair's zero-conf
		// trust is what would otherwise deny that.
		state.zeroConfEnabled = false;
		state.trustedPeer = false;
		// And the splice that superseded it has already been forgotten, which
		// is exactly what used to lift the old guard.
		state.spliceInFlight = null;

		const voided: Buffer[] = [];
		alice.removeAllListeners('node:error');
		alice.on('node:error', () => undefined);
		alice.on('channel:voided', (d: { channelId: Buffer }) =>
			voided.push(d.channelId)
		);

		alice.handleNewBlock(700_000);
		alice
			.getChainWatcher()!
			.emit('funding:missing', channelId, '44'.repeat(32));
		alice.handleNewBlock(700_000 + 2016 * 2);
		alice
			.getChainWatcher()!
			.emit('funding:missing', channelId, '44'.repeat(32));

		expect(voided.length, 'the forget clock never reaches a verdict').to.equal(
			0
		);
		expect(
			alice.listChannels().length,
			'and the channel is still here'
		).to.equal(1);

		alice.destroy();
		bob.destroy();
	});

	it('no chain tip: the absence starts no clock and the channel is retained', async function () {
		// Issue #463. currentBlockHeight is 0 until a header the backend
		// actually delivered replaces it, and a header subscription that
		// answers with the stored default never does. Stamping that as
		// "missing since" records the genesis block, and the next absence at a
		// real tip then measures a wait of the whole chain.
		const { alice, bob, channelId } = setupPair(904, 905);
		await tick(60);

		const voided: Buffer[] = [];
		alice.on('channel:voided', (d: { channelId: Buffer }) =>
			voided.push(d.channelId)
		);
		expect(alice.getCurrentBlockHeight(), 'no tip yet').to.equal(0);

		alice
			.getChainWatcher()!
			.emit('funding:missing', channelId, '55'.repeat(32));
		expect(voided, 'nothing is voided without a tip').to.have.length(0);
		expect(alice.listChannels().length).to.equal(1);
		const channel = alice.getChannelManager().getChannel(channelId)!;
		expect(channel.fundingMissingSince(), 'no clock was started').to.equal(
			undefined
		);

		// The tip arrives: the clock starts HERE, and the full BOLT 2 wait
		// still has to pass.
		alice.handleNewBlock(700_000);
		alice
			.getChainWatcher()!
			.emit('funding:missing', channelId, '55'.repeat(32));
		expect(channel.fundingMissingSince()).to.equal(700_000);
		expect(voided).to.have.length(0);
		expect(alice.listChannels().length).to.equal(1);

		alice.destroy();
		bob.destroy();
	});

	it('a start height stamped with no tip is not a countdown from genesis', async function () {
		// The same defect read back off disk: a row written by a build without
		// the guard carries a 0, which must not read as "missing since block
		// zero" and forget the channel on the first absence at a real tip.
		const { alice, bob, channelId } = setupPair(906, 907);
		await tick(60);

		const voided: Buffer[] = [];
		alice.on('channel:voided', (d: { channelId: Buffer }) =>
			voided.push(d.channelId)
		);
		const channel = alice.getChannelManager().getChannel(channelId)!;
		// White-box: exactly what such a row deserializes to.
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(channel.getFullState() as any).fundingMissingSinceHeight = 0;

		alice.handleNewBlock(700_000);
		alice
			.getChainWatcher()!
			.emit('funding:missing', channelId, '66'.repeat(32));
		expect(voided, 'the stale zero is repaired, not acted on').to.have.length(
			0
		);
		expect(channel.fundingMissingSince()).to.equal(700_000);
		expect(alice.listChannels().length).to.equal(1);

		// And the real wait still ends the way it always did.
		alice.handleNewBlock(700_000 + 2016);
		alice
			.getChainWatcher()!
			.emit('funding:missing', channelId, '66'.repeat(32));
		expect(voided).to.have.length(1);
		expect(alice.listChannels().length).to.equal(0);

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
