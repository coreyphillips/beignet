/**
 * Funding-missing watchdog: quarantine, the forget clock, and channel voiding.
 *
 * A zero-conf channel is NORMAL while its funding tx sits unconfirmed. If that
 * tx is evicted from the mempool or an input is double-spent, the channel
 * silently becomes a claim on an outpoint nobody has seen. The chain watcher
 * alarms after a debounce ('funding:missing'); the node then QUARANTINES the
 * channel against new HTLCs (issue #593) and runs BOLT 2's 2016-block forget
 * clock, at whose end it VOIDs: drop it, delete its persisted state, and emit
 * 'channel:voided'. A vanished SPLICE tx is alarm-only, because the pre-splice
 * channel is real.
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
import {
	IFundingProvider,
	ILightningError,
	INodeConfig
} from '../../src/lightning/node/types';
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import { Channel } from '../../src/lightning/channel/channel';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { Network } from '../../src/lightning/invoice/types';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { decodeUpdateAddHtlcMessage } from '../../src/lightning/message/channel-update';
import {
	deserializeChannelState,
	serializeChannelState
} from '../../src/lightning/storage/serialization';
import { settle } from './helpers/settle';

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

/**
 * A backend that can PARK history requests, so a test can choose the order two
 * overlapping scans finish in independently of the order they started in.
 * Each request captures the history that was queued when it was issued.
 */
class ParkingBackend implements IChainBackend {
	/** Served to the next request, and captured by it. */
	next: Array<{ txid: string; height: number }> = [];
	/** False makes every subsequent request park until released by index. */
	autoResolve = true;
	private parked: Array<() => void> = [];
	async subscribeToHeaders(): Promise<void> {}
	async subscribeToScriptHash(): Promise<void> {}
	getScriptHashHistory(): Promise<Array<{ txid: string; height: number }>> {
		const history = this.next;
		if (this.autoResolve) return Promise.resolve(history);
		return new Promise((resolve) => {
			this.parked.push(() => resolve(history));
		});
	}
	release(index: number): void {
		const [resolve] = this.parked.splice(index, 1);
		resolve();
	}
	get parkedCount(): number {
		return this.parked.length;
	}
	async getTransaction(): Promise<Buffer> {
		throw new Error('not needed');
	}
	async broadcastTransaction(): Promise<string> {
		return '';
	}
}

const tick = (ms = 25) => new Promise((r) => setTimeout(r, ms));

/** The white-box view of a channel's mutable state these suites poke at. */
type RawState = Record<string, unknown>;

function rawState(node: LightningNode, channelId: Buffer): RawState {
	return node
		.getChannelManager()
		.getChannel(channelId)!
		.getFullState() as unknown as RawState;
}

/**
 * Two loopbacked nodes sharing one zero-conf channel whose funding transaction
 * has never reached the chain: the one shape BOLT 2's forget clock, and the
 * quarantine layered over it, are actually for.
 */
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
	// Deterministic, so a test can name the same transaction the node holds:
	// fundingTxid is INTERNAL byte order, and every watcher-facing txid is the
	// display reverse of it.
	const fundingTxid = crypto
		.createHash('sha256')
		.update(`funding-missing-tx-${aSeed}`)
		.digest();
	const channelId = alice.createFunding(
		channel,
		fundingTxid,
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
		const st = rawState(node, channelId);
		st.zeroConfEnabled = true;
		st.trustedPeer = true;
	}
	return {
		alice,
		bob,
		channelId,
		fundingTxid,
		displayTxid: Buffer.from(fundingTxid).reverse().toString('hex')
	};
}

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
		watcher = new ChainWatcher({
			backend,
			channelManager,
			missingDebounceMs: 0
		});
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

	// Issue #672: scans come in bursts, and three absences landed within
	// 130 ms of a watch moving to a splice output whose transaction had not
	// been broadcast yet. Three checks are a debounce against a flaky answer;
	// the time floor is the debounce against a burst.
	it('three absences inside the time floor do not alarm; a later one does', async function () {
		const cm = new ChannelManager({
			localBasepoints: makeBasepoints(makeSeed(2)),
			localPerCommitmentSeed: crypto.randomBytes(32),
			localFundingPrivkey: crypto.randomBytes(32)
		});
		cm.on('error', () => {});
		// The floor is far longer than the burst below can take, and the run's
		// start is wound back by hand rather than slept through: a floor a
		// loaded machine's own scheduling can cross is a coin flip, not a test.
		const floorMs = 10_000;
		const w = new ChainWatcher({
			backend,
			channelManager: cm,
			missingDebounceMs: floorMs
		});
		w.on('error', () => {});
		const alarms: string[] = [];
		w.on('funding:missing', (_cid: Buffer, txid: string) => alarms.push(txid));
		/** Age the current run of absences past the floor. */
		const ageRunPastFloor = (): void => {
			const watched = (
				w as unknown as {
					watchedFundings: Map<string, { missingSince?: number }>;
				}
			).watchedFundings.get(channelId.toString('hex'))!;
			expect(watched.missingSince, 'a run is under way to age').to.be.a(
				'number'
			);
			watched.missingSince = watched.missingSince! - floorMs;
		};
		backend.history = [{ txid: fundingTxid, height: 0 }];
		await w.watchFundingOutput(channelId, fundingTxid, 0, 1, fundingScript);
		await tick();
		backend.history = [];
		for (let i = 0; i < 4; i++) {
			w.recheckAllWatches();
			await tick();
		}
		expect(alarms, 'a burst is not a verdict').to.deep.equal([]);
		ageRunPastFloor();
		w.recheckAllWatches();
		await tick();
		expect(alarms, 'an absence that persists past the floor is').to.deep.equal([
			fundingTxid
		]);
		// Presence resets the floor as it resets the count.
		backend.history = [{ txid: fundingTxid, height: 0 }];
		w.recheckAllWatches();
		await tick();
		backend.history = [];
		for (let i = 0; i < 3; i++) {
			w.recheckAllWatches();
			await tick();
		}
		expect(alarms, 'the floor starts over after a presence').to.have.length(1);
		w.stop();
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

	it('reports the recovery, edge-triggered, only when an absence was reported', async function () {
		// Issue #593: the counterpart of 'funding:missing'. A consumer holding a
		// restriction the alarm raised needs to be told when it is over, and
		// told only then: an ordinary present check on a channel that was never
		// reported missing announces nothing.
		const recovered: Array<{ channelId: string; txid: string }> = [];
		watcher.on('funding:recovered', (id: Buffer, txid: string) => {
			recovered.push({ channelId: id.toString('hex'), txid });
		});
		backend.history = [{ txid: fundingTxid, height: 0 }];
		await watcher.watchFundingOutput(
			channelId,
			fundingTxid,
			0,
			1,
			fundingScript
		);
		await tick();
		await recheck(3);
		expect(
			recovered,
			'nothing was reported missing, so nothing recovers'
		).to.have.length(0);

		backend.history = [];
		await recheck(3);
		expect(missing.length, 'reported missing').to.equal(1);

		backend.history = [{ txid: fundingTxid, height: 0 }];
		await recheck(1);
		expect(recovered, 'and reported back').to.have.length(1);
		expect(recovered[0].txid).to.equal(fundingTxid);
		expect(recovered[0].channelId).to.equal(channelId.toString('hex'));

		await recheck(3);
		expect(recovered, 'once, not once per check').to.have.length(1);
	});

	it('a stale presence answer cannot lift a newer absence verdict', async function () {
		// Scans of one watch overlap routinely, and each holds a history it
		// fetched before its awaits. Presence and absence are verdicts about
		// the same question, so an older scan resolving last must not overwrite
		// the newer one: it would clear a standing quarantine and cost three
		// fresh absences to raise again.
		const parking = new ParkingBackend();
		const channelManager = new ChannelManager({
			localBasepoints: makeBasepoints(makeSeed(2)),
			localPerCommitmentSeed: crypto.randomBytes(32),
			localFundingPrivkey: crypto.randomBytes(32)
		});
		channelManager.on('error', () => {});
		const w = new ChainWatcher({
			backend: parking,
			channelManager,
			missingDebounceMs: 0
		});
		w.on('error', () => {});
		const recovered: string[] = [];
		w.on('funding:recovered', (_id: Buffer, txid: string) =>
			recovered.push(txid)
		);

		parking.next = [{ txid: fundingTxid, height: 0 }];
		await w.watchFundingOutput(channelId, fundingTxid, 0, 1, fundingScript);
		await tick();
		parking.next = [];
		for (let i = 0; i < 3; i++) {
			w.recheckAllWatches();
			await tick();
		}
		expect(w.getFundingPresence(channelId), 'reported absent').to.equal(
			'absent'
		);

		// Scan A starts first and sees the funding present; scan B starts after
		// it and sees it gone. B answers first, then A.
		parking.autoResolve = false;
		parking.next = [{ txid: fundingTxid, height: 0 }];
		w.recheckAllWatches();
		await tick();
		parking.next = [];
		w.recheckAllWatches();
		await tick();
		expect(parking.parkedCount, 'two scans in flight').to.equal(2);
		parking.release(1);
		await tick();
		parking.release(0);
		await tick();

		expect(recovered, 'the older answer is discarded').to.have.length(0);
		expect(
			w.getFundingPresence(channelId),
			'and the newer verdict stands'
		).to.equal('absent');

		// A scan that genuinely starts after the absence still lifts it, so the
		// arbitration is an ordering rule and not a block.
		parking.autoResolve = true;
		parking.next = [{ txid: fundingTxid, height: 0 }];
		w.recheckAllWatches();
		await tick();
		expect(recovered, 'a fresh presence answer is honoured').to.have.length(1);
		expect(w.getFundingPresence(channelId)).to.equal('present');

		w.stop();
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

		const state = rawState(alice, channelId);
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

/**
 * Issue #593. The forget clock answers when a channel may be FORGOTTEN. It
 * says nothing about whether we may keep taking NEW HTLCs meanwhile, and for
 * the whole 2016 blocks the answer used to be yes: a channel whose funding
 * neither mempool nor chain could find stayed a router edge, an invoice hint
 * and a send candidate.
 *
 * The quarantine is that second answer, and only that one. It is reversible,
 * it never voids anything, and it never touches an existing HTLC.
 */
describe('Funding-missing quarantine (issue #593)', function () {
	/** A funding provider whose broadcast outcome the test chooses. */
	function stubProvider(outcome: 'ok' | 'reject'): {
		provider: IFundingProvider;
		sent: string[];
	} {
		const sent: string[] = [];
		const provider = {
			async buildFundingTransaction() {
				throw new Error('not needed');
			},
			async broadcastTransaction(txHex: string): Promise<string> {
				sent.push(txHex);
				if (outcome === 'reject') {
					throw new Error('bad-txns-inputs-missingorspent');
				}
				return 'txid';
			}
		} as unknown as IFundingProvider;
		return { provider, sent };
	}

	/**
	 * Put the node in the one state that reaches the rebroadcast arm: it holds
	 * the signed transaction AND the authorization to send it. Upstream gates
	 * the rebroadcast behind owesFundingBroadcast, which answers from the
	 * pending entry's phase and never from channel state.
	 */
	function armAuthorizedBroadcast(
		node: LightningNode,
		fundingTxid: Buffer,
		provider: IFundingProvider
	): void {
		const raw = node as unknown as {
			fundingProvider: IFundingProvider | null;
			pendingFundingTxs: Map<string, { txHex: string; phase: string }>;
		};
		raw.fundingProvider = provider;
		raw.pendingFundingTxs.set(fundingTxid.toString('hex'), {
			txHex: '02000000',
			phase: 'authorized'
		});
	}

	it('quarantines on the clock arm: no new HTLCs, nothing voided', async function () {
		const { alice, bob, channelId, displayTxid } = setupPair(910, 911);
		await tick(60);
		const voided: Buffer[] = [];
		alice.on('channel:voided', (d: { channelId: Buffer }) =>
			voided.push(d.channelId)
		);
		const channel = alice.getChannelManager().getChannel(channelId)!;
		expect(channel.acceptsNewHtlcs(), 'usable before the absence').to.equal(
			true
		);

		alice.handleNewBlock(700_000);
		alice.getChainWatcher()!.emit('funding:missing', channelId, displayTxid);

		expect(channel.isFundingUnaccounted(), 'quarantined').to.equal(true);
		expect(channel.acceptsNewHtlcs(), 'and takes no new HTLC').to.equal(false);
		// Everything else is deliberately untouched: this is a restriction, not
		// a disposition. The clock runs its full 2016 blocks alongside.
		expect(voided, 'nothing voided').to.have.length(0);
		expect(alice.listChannels(), 'the channel is still here').to.have.length(1);
		expect(channel.fundingMissingSince(), 'and the clock started').to.equal(
			700_000
		);
		expect(channel.canSettleHtlcs(), 'existing HTLCs still settle').to.equal(
			true
		);
		expect(
			channel.isHtlcUsable(),
			'and isHtlcUsable is untouched, so the deferred settle drains still run'
		).to.equal(true);

		const info = alice.getChannel(channelId)!;
		expect(info.htlcUsable, 'reported as unusable for new HTLCs').to.equal(
			false
		);
		expect(info.fundingUnaccounted, 'with the reason attached').to.equal(true);

		alice.destroy();
		bob.destroy();
	});

	it('a successful rebroadcast answers the absence, so nothing is quarantined', async function () {
		const { alice, bob, channelId, fundingTxid, displayTxid } = setupPair(
			912,
			913
		);
		await tick(60);
		// The tip lands BEFORE the obligation is armed: the per-block retry of a
		// pending broadcast is a separate driver, and one of its sends would be
		// indistinguishable from the one under test here.
		alice.handleNewBlock(700_000);
		const { provider, sent } = stubProvider('ok');
		armAuthorizedBroadcast(alice, fundingTxid, provider);
		const channel = alice.getChannelManager().getChannel(channelId)!;

		alice.getChainWatcher()!.emit('funding:missing', channelId, displayTxid);
		await settle(() => sent.length === 1, 2000);

		// A funder that answers absence by sending keeps its channel fully
		// usable: absence has been answered, not merely observed.
		expect(channel.isFundingUnaccounted(), 'not quarantined').to.equal(false);
		expect(channel.acceptsNewHtlcs(), 'and still fully usable').to.equal(true);
		expect(
			channel.fundingMissingSince(),
			'this side never starts the clock either'
		).to.equal(undefined);

		alice.destroy();
		bob.destroy();
	});

	it('a rejected rebroadcast quarantines, and disposes of nothing', async function () {
		const { alice, bob, channelId, fundingTxid, displayTxid } = setupPair(
			914,
			915
		);
		await tick(60);
		const voided: Buffer[] = [];
		alice.on('channel:voided', (d: { channelId: Buffer }) =>
			voided.push(d.channelId)
		);
		alice.handleNewBlock(700_000);
		const { provider, sent } = stubProvider('reject');
		armAuthorizedBroadcast(alice, fundingTxid, provider);
		const channel = alice.getChannelManager().getChannel(channelId)!;

		alice.getChainWatcher()!.emit('funding:missing', channelId, displayTxid);
		await settle(() => sent.length === 1, 2000);
		await settle(() => channel.isFundingUnaccounted(), 2000);

		// bad-txns-inputs-missingorspent covers an unconfirmed parent this
		// backend has not seen. It raises a restriction; it proves nothing that
		// could justify forgetting the channel.
		expect(channel.acceptsNewHtlcs(), 'no new HTLCs').to.equal(false);
		expect(voided, 'and nothing is voided').to.have.length(0);
		expect(alice.listChannels()).to.have.length(1);
		expect(
			channel.fundingMissingSince(),
			'the clock is the other arm; this one does not start it'
		).to.equal(undefined);

		alice.destroy();
		bob.destroy();
	});

	it('funding:recovered lifts the quarantine and stops the clock', async function () {
		const { alice, bob, channelId, displayTxid } = setupPair(916, 917);
		await tick(60);
		const channel = alice.getChannelManager().getChannel(channelId)!;

		alice.handleNewBlock(700_000);
		alice.getChainWatcher()!.emit('funding:missing', channelId, displayTxid);
		expect(channel.isFundingUnaccounted()).to.equal(true);
		expect(channel.fundingMissingSince()).to.equal(700_000);

		alice.getChainWatcher()!.emit('funding:recovered', channelId, displayTxid);

		expect(channel.isFundingUnaccounted(), 'quarantine lifted').to.equal(false);
		expect(channel.acceptsNewHtlcs(), 'fully usable again').to.equal(true);
		expect(
			channel.fundingMissingSince(),
			'and a countdown from one outage does not tick through the next'
		).to.equal(undefined);
		expect(alice.getChannel(channelId)!.fundingUnaccounted).to.equal(undefined);

		alice.destroy();
		bob.destroy();
	});

	it('the per-block presence poll lifts it too, so a dropped event is never permanent', async function () {
		const { alice, bob, channelId, displayTxid } = setupPair(918, 919);
		await tick(60);
		const channel = alice.getChannelManager().getChannel(channelId)!;

		alice.handleNewBlock(700_000);
		alice.getChainWatcher()!.emit('funding:missing', channelId, displayTxid);
		expect(channel.isFundingUnaccounted()).to.equal(true);

		// The event never arrives; the chain is asked directly instead.
		const watcher = alice.getChainWatcher()! as unknown as {
			getFundingPresence: (id: Buffer) => string;
		};
		watcher.getFundingPresence = () => 'present';
		alice.handleNewBlock(700_001);

		expect(channel.isFundingUnaccounted(), 'lifted by the poll').to.equal(
			false
		);
		expect(channel.fundingMissingSince()).to.equal(undefined);

		// And the poll re-raises it from the same answer the event would have
		// carried, so the two can never end up disagreeing.
		watcher.getFundingPresence = () => 'absent';
		alice.handleNewBlock(700_002);
		expect(channel.isFundingUnaccounted(), 're-raised by the poll').to.equal(
			true
		);

		alice.destroy();
		bob.destroy();
	});

	it('the quarantine survives a restart', async function () {
		const { alice, bob, channelId, displayTxid } = setupPair(920, 921);
		await tick(60);
		alice.handleNewBlock(700_000);
		alice.getChainWatcher()!.emit('funding:missing', channelId, displayTxid);
		const channel = alice.getChannelManager().getChannel(channelId)!;
		expect(channel.isFundingUnaccounted()).to.equal(true);

		// The row as a restart reads it back. Held only in memory the flag is
		// lost here, and the channel takes new HTLCs again until the next
		// absence: fail-closed is safe precisely because the presence poll
		// above is a lift path that cannot deadlock.
		const restored = new Channel(
			deserializeChannelState(
				JSON.parse(
					JSON.stringify(serializeChannelState(channel.getFullState()))
				)
			)
		);
		expect(restored.isFundingUnaccounted(), 'still quarantined').to.equal(true);
		expect(restored.acceptsNewHtlcs(), 'and still takes no new HTLC').to.equal(
			false
		);

		alice.destroy();
		bob.destroy();
	});

	it('an existing HTLC still settles while quarantined', async function () {
		const { alice, bob, channelId, displayTxid } = setupPair(922, 923);
		await tick(60);
		const aliceChannel = alice.getChannelManager().getChannel(channelId)!;
		const bobChannel = bob.getChannelManager().getChannel(channelId)!;

		// One HTLC in flight before anything goes wrong.
		const preimage = crypto.randomBytes(32);
		const paymentHash = crypto.createHash('sha256').update(preimage).digest();
		const addActions = aliceChannel.addHtlc(
			50_000_000n,
			paymentHash,
			500_000,
			crypto.randomBytes(1366)
		);
		const addMsg = addActions.find(
			(a) => a.type === ChannelActionType.SEND_MESSAGE
		) as { payload: Buffer } | undefined;
		expect(addMsg, 'the add went out').to.not.equal(undefined);
		bobChannel.handleUpdateAddHtlc(decodeUpdateAddHtlcMessage(addMsg!.payload));

		// Both ends lose sight of the funding. Only alice has a chain backend, so
		// bob's row is restricted directly: what is under test is the settle, not
		// how each side reached the same verdict about the chain.
		alice.handleNewBlock(700_000);
		alice.getChainWatcher()!.emit('funding:missing', channelId, displayTxid);
		bobChannel.markFundingUnaccounted();
		expect(aliceChannel.acceptsNewHtlcs(), 'no new HTLCs offered').to.equal(
			false
		);
		expect(bobChannel.acceptsNewHtlcs(), 'and none accepted').to.equal(false);

		// The preimage still gets released, which is the whole reason the
		// quarantine gates acceptsNewHtlcs and not isHtlcUsable: a held channel
		// with a queued fulfill that never releases it is a paid HTLC nobody
		// can claim.
		expect(bobChannel.canFulfillHtlc(0n), 'the settle is not gated').to.equal(
			true
		);
		const fulfill = bobChannel.fulfillHtlc(0n, preimage);
		expect(
			fulfill.some((a) => a.type === ChannelActionType.SEND_MESSAGE),
			'and the fulfill goes out'
		).to.equal(true);
		expect(
			fulfill.some((a) => a.type === ChannelActionType.ERROR),
			'with no refusal'
		).to.equal(false);

		alice.destroy();
		bob.destroy();
	});

	it('refuses a new outbound HTLC at the admission point, not just in selection', async function () {
		// acceptsNewHtlcs keeps the router, the forwarder, the hint builder and
		// the sender away from the channel, but selection is advice: anything
		// reaching ChannelManager.addHtlc directly arrives here instead. An add
		// admitted now is enforceable only by a commitment spending an outpoint
		// nobody has seen.
		const { alice, bob, channelId, displayTxid } = setupPair(930, 931);
		await tick(60);
		const channel = alice.getChannelManager().getChannel(channelId)!;
		alice.handleNewBlock(700_000);
		alice.getChainWatcher()!.emit('funding:missing', channelId, displayTxid);
		expect(channel.isFundingUnaccounted()).to.equal(true);

		const actions = channel.addHtlc(
			50_000_000n,
			crypto.randomBytes(32),
			500_000,
			crypto.randomBytes(1366)
		);
		expect(
			actions.filter((a) => a.type === ChannelActionType.SEND_MESSAGE),
			'no update_add_htlc goes out'
		).to.have.length(0);
		const err = actions.find((a) => a.type === ChannelActionType.ERROR) as
			| { message: string }
			| undefined;
		expect(err, 'refused with a reason').to.not.equal(undefined);
		expect(err!.message).to.contain('quarantined');
		expect(
			[...channel.getFullState().htlcs.keys()],
			'and nothing was written into the channel'
		).to.have.length(0);

		// The refusal is exactly as reversible as the quarantine.
		alice.getChainWatcher()!.emit('funding:recovered', channelId, displayTxid);
		const after = channel.addHtlc(
			50_000_000n,
			crypto.randomBytes(32),
			500_000,
			crypto.randomBytes(1366)
		);
		expect(
			after.some((a) => a.type === ChannelActionType.SEND_MESSAGE),
			'the add goes out once the funding is accounted for'
		).to.equal(true);

		alice.destroy();
		bob.destroy();
	});

	it('stamps an inbound add with admission-time provenance, and persists it', async function () {
		// BOLT 2 gives no way to refuse an add on the wire, so a quarantined
		// channel commits to it and the node fails it back afterwards. Which
		// adds those are is decided by WHEN each entered, not by the quarantine
		// alone: the restart redispatch replays committed HTLCs through the
		// same path, and one admitted before the quarantine still settles.
		const { alice, bob, channelId } = setupPair(932, 933);
		await tick(60);
		const aliceChannel = alice.getChannelManager().getChannel(channelId)!;
		const bobChannel = bob.getChannelManager().getChannel(channelId)!;

		const send = (): void => {
			const addMsg = aliceChannel
				.addHtlc(
					50_000_000n,
					crypto.randomBytes(32),
					500_000,
					crypto.randomBytes(1366)
				)
				.find((a) => a.type === ChannelActionType.SEND_MESSAGE) as
				| { payload: Buffer }
				| undefined;
			expect(addMsg, 'the add went out').to.not.equal(undefined);
			bobChannel.handleUpdateAddHtlc(
				decodeUpdateAddHtlcMessage(addMsg!.payload)
			);
		};

		send();
		// Only the receiving side loses sight of the funding, so alice still
		// offers: what is under test is the admission, not how each end reached
		// its own verdict about the chain.
		bobChannel.markFundingUnaccounted();
		send();

		const htlcs = bobChannel.getFullState().htlcs;
		expect(
			htlcs.get('received-0')!.addedWhileFundingUnaccounted,
			'the earlier add predates the quarantine'
		).to.equal(undefined);
		expect(
			htlcs.get('received-1')!.addedWhileFundingUnaccounted,
			'the later one carries the provenance'
		).to.equal(true);

		// It has to survive the crash between the commitment and the fail-back.
		const restored = new Channel(
			deserializeChannelState(
				JSON.parse(
					JSON.stringify(serializeChannelState(bobChannel.getFullState()))
				)
			)
		);
		const restoredHtlcs = restored.getFullState().htlcs;
		expect(
			restoredHtlcs.get('received-0')!.addedWhileFundingUnaccounted
		).to.equal(undefined);
		expect(
			restoredHtlcs.get('received-1')!.addedWhileFundingUnaccounted
		).to.equal(true);

		alice.destroy();
		bob.destroy();
	});

	describe('guard parity: quarantine refuses wherever disposal does', function () {
		const cases: Array<{
			name: string;
			seeds: [number, number];
			apply: (state: RawState) => void;
		}> = [
			{
				name: 'a splice in flight',
				seeds: [924, 925],
				apply: (state) => {
					state.spliceInFlight = {
						spliceTxid: Buffer.from('44'.repeat(32), 'hex')
					};
				}
			},
			{
				name: 'a live pre-splice spend watch (issue #479)',
				seeds: [926, 927],
				apply: (state) => {
					state.preSpliceSpendWatches = [
						{
							txid: '44'.repeat(32),
							outputIndex: 0,
							script: '0020' + '22'.repeat(32),
							spliceTxid: '55'.repeat(32)
						}
					];
				}
			},
			{
				name: 'funding this node has seen on chain (issue #481)',
				seeds: [928, 929],
				apply: (state) => {
					state.zeroConfEnabled = false;
					state.trustedPeer = false;
					state.spliceInFlight = null;
				}
			}
		];

		for (const testCase of cases) {
			it(`never quarantines with ${testCase.name}`, async function () {
				const { alice, bob, channelId, displayTxid } = setupPair(
					...testCase.seeds
				);
				await tick(60);
				testCase.apply(rawState(alice, channelId));
				const channel = alice.getChannelManager().getChannel(channelId)!;

				alice.handleNewBlock(700_000);
				alice
					.getChainWatcher()!
					.emit('funding:missing', channelId, displayTxid);

				expect(channel.isFundingUnaccounted(), 'not quarantined').to.equal(
					false
				);
				expect(channel.acceptsNewHtlcs(), 'and fully usable').to.equal(true);
				expect(
					channel.fundingMissingSince(),
					'the same guard stops the clock, as it always did'
				).to.equal(undefined);

				alice.destroy();
				bob.destroy();
			});
		}
	});
});
