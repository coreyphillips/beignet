/**
 * Regression: ChainWatcher.stop() tore down the wrong half of its wiring.
 *
 *  1. removeAllListeners() stripped the consumer's handlers, including the
 *     node's 'error' handler, while six in-flight paths still emit 'error'
 *     from a promise catch. EventEmitter THROWS on an 'error' emit with no
 *     listener, so an ordinary shutdown crashed the process whenever a chain
 *     request was in flight.
 *  2. The three ChannelManager subscriptions were never removed, so a stopped
 *     watcher still acted on channel events and still broadcast after
 *     node.destroy().
 *  3. LightningNode gated its wiring on a one-shot boolean that was never
 *     reset, so a stop() then start() cycle left the watcher with no listeners
 *     at all and the node silently stopped tracking the chain.
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
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';

bitcoin.initEccLib(ecc);

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

/** A backend whose calls can be resolved or rejected by the test, on demand. */
class ControllableBackend implements IChainBackend {
	headerCallback: ((height: number) => void) | null = null;
	broadcastCalls: string[] = [];
	/** Rejects every pending and future getScriptHashHistory call. */
	private historyRejecters: Array<(err: Error) => void> = [];
	private historyResolvers: Array<
		(entries: Array<{ txid: string; height: number }>) => void
	> = [];
	/** When set, history calls resolve immediately with this. */
	historyResponse: Array<{ txid: string; height: number }> | null = null;
	transactions: Map<string, Buffer> = new Map();
	broadcastShouldFail = false;

	async subscribeToHeaders(
		onNewBlock: (height: number) => void
	): Promise<void> {
		// ElectrumBackend replaces its single header callback rather than
		// accumulating, so a re-subscribe must not double-deliver here either.
		this.headerCallback = onNewBlock;
	}

	private scriptHashCallbacks: Array<() => void> = [];
	private subscribeSettlers: Array<{
		resolve: () => void;
		reject: (err: Error) => void;
	}> = [];
	/** When true, subscribeToScriptHash stays pending until settled by the test. */
	deferSubscribe = false;
	private txSettlers: Array<{
		resolve: (raw: Buffer) => void;
		reject: (err: Error) => void;
	}> = [];
	/** When true, getTransaction stays pending until settled by the test. */
	deferGetTransaction = false;

	subscribeToScriptHash(
		_scriptHash: string,
		onChange: () => void
	): Promise<void> {
		this.scriptHashCallbacks.push(onChange);
		if (!this.deferSubscribe) return Promise.resolve();
		return new Promise((resolve, reject) => {
			this.subscribeSettlers.push({ resolve, reject });
		});
	}

	pendingSubscribeCount(): number {
		return this.subscribeSettlers.length;
	}

	resolvePendingSubscribes(): void {
		const settlers = this.subscribeSettlers;
		this.subscribeSettlers = [];
		for (const s of settlers) s.resolve();
	}

	failPendingSubscribes(): void {
		const settlers = this.subscribeSettlers;
		this.subscribeSettlers = [];
		for (const s of settlers) s.reject(new Error('subscribe refused'));
	}

	pendingTxCount(): number {
		return this.txSettlers.length;
	}

	resolvePendingTx(raw: Buffer): void {
		const settlers = this.txSettlers;
		this.txSettlers = [];
		for (const s of settlers) s.resolve(raw);
	}

	/** Fire every scripthash subscription, as an Electrum status change would. */
	fireScriptHashes(): void {
		for (const cb of this.scriptHashCallbacks) cb();
	}

	getScriptHashHistory(): Promise<Array<{ txid: string; height: number }>> {
		if (this.historyResponse) return Promise.resolve(this.historyResponse);
		// Stays pending until the test settles it.
		return new Promise((resolve, reject) => {
			this.historyResolvers.push(resolve);
			this.historyRejecters.push(reject);
		});
	}

	getTransaction(txid: string): Promise<Buffer> {
		if (this.deferGetTransaction) {
			return new Promise((resolve, reject) => {
				this.txSettlers.push({ resolve, reject });
			});
		}
		const tx = this.transactions.get(txid);
		if (!tx) return Promise.reject(new Error(`no tx ${txid}`));
		return Promise.resolve(tx);
	}

	private broadcastSettlers: Array<{
		resolve: (txid: string) => void;
		reject: (err: Error) => void;
	}> = [];
	/** When true, broadcastTransaction stays pending until settled. */
	deferBroadcast = false;

	pendingBroadcastCount(): number {
		return this.broadcastSettlers.length;
	}

	failPendingBroadcasts(): void {
		const settlers = this.broadcastSettlers;
		this.broadcastSettlers = [];
		for (const s of settlers) s.reject(new Error('broadcast refused'));
	}

	async broadcastTransaction(rawTxHex: string): Promise<string> {
		this.broadcastCalls.push(rawTxHex);
		if (this.deferBroadcast) {
			return new Promise((resolve, reject) => {
				this.broadcastSettlers.push({ resolve, reject });
			});
		}
		if (this.broadcastShouldFail) throw new Error('broadcast refused');
		return crypto
			.createHash('sha256')
			.update(Buffer.from(rawTxHex, 'hex'))
			.digest()
			.reverse()
			.toString('hex');
	}

	/** Resolve everything in flight with the given history. */
	resolvePendingHistory(
		entries: Array<{ txid: string; height: number }>
	): void {
		const resolvers = this.historyResolvers;
		this.historyResolvers = [];
		this.historyRejecters = [];
		for (const resolve of resolvers) resolve(entries);
	}

	/** Reject everything the watcher has in flight against this backend. */
	failPendingHistory(): void {
		const rejecters = this.historyRejecters;
		this.historyRejecters = [];
		this.historyResolvers = [];
		for (const reject of rejecters) {
			reject(new Error('backend went away'));
		}
	}

	simulateNewBlock(height: number): void {
		this.headerCallback?.(height);
	}

	pendingHistoryCount(): number {
		return this.historyRejecters.length;
	}
}

function makeTx(): Buffer {
	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.addInput(crypto.randomBytes(32), 0);
	const pubkey = Buffer.from(ecc.pointFromScalar(crypto.randomBytes(32))!);
	tx.addOutput(bitcoin.payments.p2wpkh({ pubkey }).output!, 50_000);
	return tx.toBuffer();
}

const tick = (): Promise<void> =>
	new Promise((resolve) => setImmediate(resolve));

/**
 * Records unhandled rejections for the duration of a test. An 'error' emit with
 * no listener throws out of the promise catch it was emitted from, which
 * surfaces here rather than as a test assertion, and in production takes the
 * process down.
 */
const captureUnhandledRejections = (): {
	seen: unknown[];
	release: () => void;
} => {
	const seen: unknown[] = [];
	const onRejection = (reason: unknown): void => {
		seen.push(reason);
	};
	process.on('unhandledRejection', onRejection);
	return {
		seen,
		release: (): void => {
			process.off('unhandledRejection', onRejection);
		}
	};
};

function makeNodeConfig(seed: Buffer): INodeConfig {
	return {
		nodePrivateKey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from('node-identity'))
			.digest(),
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: crypto.createHash('sha256').update(seed).digest(),
		fundingPrivkey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([0]))
			.digest()
	};
}

describe('ChainWatcher teardown at node level', function () {
	this.timeout(20000);

	it('tracks block height again after the watcher is restarted', async function () {
		const backend = new ControllableBackend();
		const config = makeNodeConfig(crypto.randomBytes(32));
		config.chainBackend = backend;
		const node = new LightningNode(config);
		node.on('node:error', () => {});

		const watcher = node.getChainWatcher();
		if (!watcher) throw new Error('expected a chain watcher');

		await node.startChainWatcher();
		backend.simulateNewBlock(500);
		expect(
			(node as unknown as { currentBlockHeight: number }).currentBlockHeight,
			'height tracked while running'
		).to.equal(500);

		// A backend failover or a long outage stops and restarts the watcher.
		watcher.stop();
		await node.startChainWatcher();
		backend.simulateNewBlock(501);

		// The one-shot _chainWatcherEventsWired flag meant the node's listeners
		// were never re-registered after a stop(), so it stopped tracking the
		// chain with nothing surfaced.
		expect(
			(node as unknown as { currentBlockHeight: number }).currentBlockHeight,
			'height tracked again after restart'
		).to.equal(501);

		node.destroy();
	});
});

describe('ChainWatcher teardown', function () {
	this.timeout(20000);

	let backend: ControllableBackend;
	let channelManager: ChannelManager;
	let watcher: ChainWatcher;

	beforeEach(function () {
		const seed = crypto.randomBytes(32);
		backend = new ControllableBackend();
		channelManager = new ChannelManager({
			localBasepoints: makeBasepoints(seed),
			localPerCommitmentSeed: crypto.randomBytes(32),
			localFundingPrivkey: crypto.randomBytes(32)
		});
		channelManager.on('error', () => {});

		watcher = new ChainWatcher({ backend, channelManager });
	});

	afterEach(function () {
		watcher.stop();
	});

	it('keeps the consumer error handler through stop()', async function () {
		const rejections = captureUnhandledRejections();
		const errors: Error[] = [];
		watcher.on('error', (err: Error) => errors.push(err));

		// A funding watch leaves a getScriptHashHistory call in flight.
		const scriptPubkey = bitcoin.payments.p2wpkh({
			pubkey: Buffer.from(ecc.pointFromScalar(crypto.randomBytes(32))!)
		}).output as Buffer;
		const pending = watcher
			.watchFundingOutput(
				crypto.randomBytes(32),
				'ab'.repeat(32),
				0,
				1,
				scriptPubkey
			)
			.catch(() => {
				/* surfaced through 'error' below */
			});

		// Guard against a vacuous pass: there has to be something in flight for
		// the rejection to land after stop().
		await tick();
		expect(
			backend.pendingHistoryCount(),
			'a chain request is in flight'
		).to.be.greaterThan(0);

		watcher.stop();
		// The rejection lands after shutdown, which is the ordinary case on a
		// node with channels. Before the fix this threw out of the emit.
		backend.failPendingHistory();
		await pending;
		await tick();
		await tick();
		rejections.release();

		expect(watcher.listenerCount('error'), 'the handler survived').to.equal(1);
		expect(errors.length, 'the failure reached the consumer').to.equal(1);
		expect(
			rejections.seen,
			'nothing escaped as an unhandled rejection'
		).to.deep.equal([]);
	});

	it('does not throw when an error lands with no listener at all', async function () {
		// No 'error' listener is registered here. EventEmitter would throw out of
		// the catch that emitted, which lands as an unhandled rejection and, in
		// production, terminates the process.
		const rejections = captureUnhandledRejections();
		const scriptPubkey = bitcoin.payments.p2wpkh({
			pubkey: Buffer.from(ecc.pointFromScalar(crypto.randomBytes(32))!)
		}).output as Buffer;
		// Record the reason rather than swallowing it: the throw comes back out
		// of watchFundingOutput, and its production callers hand that to another
		// 'error' emit, which throws again inside a catch and takes the process
		// with it.
		let rejectedWith: unknown = null;
		const pending = watcher
			.watchFundingOutput(
				crypto.randomBytes(32),
				'cd'.repeat(32),
				0,
				1,
				scriptPubkey
			)
			.catch((e: unknown) => {
				rejectedWith = e;
			});

		await tick();
		expect(
			backend.pendingHistoryCount(),
			'a chain request is in flight'
		).to.be.greaterThan(0);
		expect(watcher.listenerCount('error'), 'nothing is listening').to.equal(0);

		backend.failPendingHistory();
		await pending;
		await tick();
		await tick();
		rejections.release();

		expect(
			rejectedWith === null ? 'none' : String(rejectedWith),
			'the emit did not throw back out of the watch'
		).to.equal('none');
		expect(
			rejections.seen.map(String),
			'nothing escaped as an unhandled rejection'
		).to.deep.equal([]);
	});

	it('stops broadcasting on behalf of the ChannelManager once stopped', async function () {
		const tx = makeTx();

		channelManager.emit('broadcast:tx', tx);
		await tick();
		expect(backend.broadcastCalls.length, 'broadcast while running').to.equal(
			1
		);

		watcher.stop();

		expect(
			channelManager.listenerCount('broadcast:tx'),
			'the watcher detached on stop()'
		).to.equal(0);

		channelManager.emit('broadcast:tx', tx);
		await tick();
		expect(backend.broadcastCalls.length, 'no broadcast after stop()').to.equal(
			1
		);
	});

	it('stops relaying watch:output once stopped', async function () {
		const requested: string[] = [];
		watcher.on('watch:output:requested', (txid: string) =>
			requested.push(txid)
		);

		channelManager.emit('watch:output', 'ab'.repeat(32), 0);
		expect(requested.length).to.equal(1);
		expect(
			channelManager.listenerCount('watch:output'),
			'the watcher is subscribed while running'
		).to.equal(1);

		watcher.stop();

		// Assert the subscription itself is gone, not just that nothing was
		// observed: removeAllListeners() used to delete this test's own listener,
		// which hid the fact that the handler was still attached and firing.
		expect(
			channelManager.listenerCount('watch:output'),
			'the watcher detached on stop()'
		).to.equal(0);

		channelManager.emit('watch:output', 'cd'.repeat(32), 0);
		expect(requested.length, 'no relay after stop()').to.equal(1);
	});

	it('can be restarted and still reaches its listeners', async function () {
		const blocks: number[] = [];
		watcher.on('block', (height: number) => blocks.push(height));

		await watcher.start();
		backend.simulateNewBlock(100);
		expect(blocks).to.deep.equal([100]);

		watcher.stop();
		await watcher.start();
		backend.simulateNewBlock(101);

		// Before the fix stop() removed the 'block' listener and the node's
		// one-shot wiring flag meant it was never re-registered, so the node
		// stopped tracking height with no error anywhere.
		expect(blocks, 'the restarted watcher still reports blocks').to.deep.equal([
			100, 101
		]);
	});

	describe('in-flight work after stop()', function () {
		// stop() detaching the wiring is not enough: a request that was already
		// on the wire resolves afterwards, and acting on it advances the
		// ChannelManager for a watcher that is no longer watching.

		it('does not process a funding check that resolves after stop', async function () {
			let confirmed = 0;
			(
				channelManager as unknown as {
					handleFundingConfirmed: (id: Buffer) => void;
				}
			).handleFundingConfirmed = (): void => {
				confirmed++;
			};
			const events: Buffer[] = [];
			watcher.on('funding:confirmed', (id: Buffer) => events.push(id));
			watcher.on('error', () => {});

			await watcher.start();
			backend.simulateNewBlock(200);

			const fundingTxid = 'ab'.repeat(32);
			const scriptPubkey = bitcoin.payments.p2wpkh({
				pubkey: Buffer.from(ecc.pointFromScalar(crypto.randomBytes(32))!)
			}).output as Buffer;
			const pending = watcher
				.watchFundingOutput(
					crypto.randomBytes(32),
					fundingTxid,
					0,
					1,
					scriptPubkey
				)
				.catch(() => {
					/* not the subject */
				});

			await tick();
			expect(
				backend.pendingHistoryCount(),
				'the confirmation check is in flight'
			).to.be.greaterThan(0);

			watcher.stop();
			// The funding confirmed, as far as the backend is concerned.
			backend.resolvePendingHistory([{ txid: fundingTxid, height: 190 }]);
			await pending;
			await tick();

			expect(confirmed, 'the ChannelManager was not advanced').to.equal(0);
			expect(events.length, 'no funding:confirmed after stop').to.equal(0);
		});

		it('does not process an output-spend check that resolves after stop', async function () {
			let spent = 0;
			(
				channelManager as unknown as {
					handleOutputSpent: () => void;
				}
			).handleOutputSpent = (): void => {
				spent++;
			};
			watcher.on('output:spent', () => spent++);
			watcher.on('error', () => {});

			await watcher.start();
			backend.simulateNewBlock(200);

			// A spend of the watched output, ready for the check to find.
			const watchedTxid = 'cd'.repeat(32);
			const spendTx = new bitcoin.Transaction();
			spendTx.version = 2;
			spendTx.addInput(Buffer.from(watchedTxid, 'hex').reverse(), 0);
			const pubkey = Buffer.from(ecc.pointFromScalar(crypto.randomBytes(32))!);
			const script = bitcoin.payments.p2wpkh({ pubkey }).output as Buffer;
			spendTx.addOutput(script, 10_000);
			backend.transactions.set(spendTx.getId(), spendTx.toBuffer());

			await watcher.watchOutput(watchedTxid, 0, script);
			// watchOutput only subscribes; the check runs when the scripthash
			// status changes.
			backend.fireScriptHashes();
			await tick();
			expect(
				backend.pendingHistoryCount(),
				'the spend check is in flight'
			).to.be.greaterThan(0);

			watcher.stop();
			backend.resolvePendingHistory([{ txid: spendTx.getId(), height: 195 }]);
			await tick();
			await tick();

			expect(spent, 'the spend was not reported after stop').to.equal(0);
		});

		it('does not advance the ChannelManager on a header received after stop', async function () {
			const heights: number[] = [];
			(
				channelManager as unknown as {
					handleNewBlock: (h: number) => unknown[];
				}
			).handleNewBlock = (h: number): unknown[] => {
				heights.push(h);
				return [];
			};
			const blocks: number[] = [];
			watcher.on('block', (h: number) => blocks.push(h));

			await watcher.start();
			backend.simulateNewBlock(300);
			expect(heights, 'delivered while running').to.deep.equal([300]);

			watcher.stop();
			// ElectrumBackend keeps its header callback across a watcher stop, so
			// the next header still arrives here.
			backend.simulateNewBlock(301);

			expect(heights, 'no advance after stop').to.deep.equal([300]);
			expect(blocks, 'no block event after stop').to.deep.equal([300]);
		});

		it('does not report a funding spend detected after stop', async function () {
			let spent = 0;
			(
				channelManager as unknown as {
					handleFundingConfirmed: (id: Buffer) => void;
					handleFundingSpent: () => void;
				}
			).handleFundingSpent = (): void => {
				spent++;
			};
			watcher.on('funding:spent', () => spent++);
			watcher.on('error', () => {});

			await watcher.start();
			backend.simulateNewBlock(200);

			const fundingTxid = 'ef'.repeat(32);
			const closeTx = new bitcoin.Transaction();
			closeTx.version = 2;
			closeTx.addInput(Buffer.from(fundingTxid, 'hex').reverse(), 0);
			const pubkey = Buffer.from(ecc.pointFromScalar(crypto.randomBytes(32))!);
			const script = bitcoin.payments.p2wpkh({ pubkey }).output as Buffer;
			closeTx.addOutput(script, 10_000);
			backend.transactions.set(closeTx.getId(), closeTx.toBuffer());

			const pending = watcher
				.watchFundingSpendDuringSplice(
					crypto.randomBytes(32),
					fundingTxid,
					0,
					script,
					// A splice txid to ignore; the close below is a different tx.
					'11'.repeat(32)
				)
				.catch(() => {
					/* not the subject */
				});
			await tick();
			expect(
				backend.pendingHistoryCount(),
				'the spend check is in flight'
			).to.be.greaterThan(0);

			watcher.stop();
			backend.resolvePendingHistory([{ txid: closeTx.getId(), height: 199 }]);
			await pending;
			await tick();
			await tick();

			expect(spent, 'the funding spend was not reported after stop').to.equal(
				0
			);
		});
	});

	describe('operations that start before stop() and finish after', function () {
		// The generation has to be captured at the START of the whole operation.
		// Capturing it inside a downstream method does not help when that method
		// is reached through an earlier, unguarded await: it captures the CURRENT
		// generation and every guard passes.

		it('does not install an output watch when getTransaction resolves after stop', async function () {
			let reported = 0;
			const manager = channelManager as unknown as {
				handleOutputSpent: () => void;
				handleOutputUnspent: () => void;
			};
			manager.handleOutputSpent = (): void => {
				reported++;
			};
			manager.handleOutputUnspent = (): void => {
				reported++;
			};
			watcher.on('output:spent', () => reported++);
			watcher.on('error', () => {});

			await watcher.start();
			backend.simulateNewBlock(400);

			// The tx whose output is being watched, and a later spend of it.
			const watchedTx = new bitcoin.Transaction();
			watchedTx.version = 2;
			watchedTx.addInput(crypto.randomBytes(32), 0);
			const pubkey = Buffer.from(ecc.pointFromScalar(crypto.randomBytes(32))!);
			const script = bitcoin.payments.p2wpkh({ pubkey }).output as Buffer;
			watchedTx.addOutput(script, 20_000);
			const watchedTxid = watchedTx.getId();

			const spendTx = new bitcoin.Transaction();
			spendTx.version = 2;
			spendTx.addInput(Buffer.from(watchedTxid, 'hex').reverse(), 0);
			spendTx.addOutput(script, 10_000);
			backend.transactions.set(spendTx.getId(), spendTx.toBuffer());

			backend.deferGetTransaction = true;
			const pending = watcher.watchOutputByTxid(watchedTxid, 0).catch(() => {
				/* not the subject */
			});
			await tick();
			expect(backend.pendingTxCount(), 'the fetch is in flight').to.equal(1);

			watcher.stop();
			backend.deferGetTransaction = false;
			backend.resolvePendingTx(watchedTx.toBuffer());
			await pending;
			await tick();

			expect(
				(watcher as unknown as { watchedOutputs: Map<string, unknown> })
					.watchedOutputs.size,
				'no watch was installed after stop'
			).to.equal(0);

			// The dangerous consequence, not just the internal map: a retained
			// scripthash callback firing must not drive the ChannelManager.
			backend.historyResponse = [{ txid: spendTx.getId(), height: 399 }];
			backend.fireScriptHashes();
			await tick();
			await tick();
			expect(reported, 'nothing was reported to the ChannelManager').to.equal(
				0
			);
		});

		it('does not begin a funding-spend check when the subscription resolves after stop', async function () {
			let spent = 0;
			(
				channelManager as unknown as { handleFundingSpent: () => void }
			).handleFundingSpent = (): void => {
				spent++;
			};
			watcher.on('funding:spent', () => spent++);
			watcher.on('error', () => {});

			await watcher.start();
			backend.simulateNewBlock(400);

			const fundingTxid = 'ab'.repeat(32);
			const closeTx = new bitcoin.Transaction();
			closeTx.version = 2;
			closeTx.addInput(Buffer.from(fundingTxid, 'hex').reverse(), 0);
			const pubkey = Buffer.from(ecc.pointFromScalar(crypto.randomBytes(32))!);
			const script = bitcoin.payments.p2wpkh({ pubkey }).output as Buffer;
			closeTx.addOutput(script, 10_000);
			backend.transactions.set(closeTx.getId(), closeTx.toBuffer());
			// The spend is already visible, so any check that runs will find it.
			backend.historyResponse = [{ txid: closeTx.getId(), height: 399 }];

			backend.deferSubscribe = true;
			const pending = watcher
				.watchFundingSpendDuringSplice(
					crypto.randomBytes(32),
					fundingTxid,
					0,
					script,
					'11'.repeat(32)
				)
				.catch(() => {
					/* not the subject */
				});
			await tick();
			expect(
				backend.pendingSubscribeCount(),
				'the subscription is in flight'
			).to.equal(1);

			watcher.stop();
			// checkFundingSpent runs only after this resolves, so it would capture
			// the post-stop generation and consider itself current.
			backend.resolvePendingSubscribes();
			await pending;
			await tick();
			await tick();

			expect(spent, 'the check did not run after stop').to.equal(0);
		});

		it('does not requeue a funding watch when its subscription rejects after stop', async function () {
			watcher.on('error', () => {});
			await watcher.start();

			const script = bitcoin.payments.p2wpkh({
				pubkey: Buffer.from(ecc.pointFromScalar(crypto.randomBytes(32))!)
			}).output as Buffer;

			backend.deferSubscribe = true;
			const pending = watcher
				.watchFundingOutput(
					crypto.randomBytes(32),
					'cd'.repeat(32),
					0,
					1,
					script
				)
				.catch(() => {
					/* not the subject */
				});
			await tick();
			expect(backend.pendingSubscribeCount()).to.equal(1);

			watcher.stop();
			backend.failPendingSubscribes();
			await pending;
			await tick();

			expect(
				(watcher as unknown as { failedFundingWatches: unknown[] })
					.failedFundingWatches.length,
				'the queue stop() cleared stayed clear'
			).to.equal(0);
		});

		it('does not requeue an output watch when its subscription rejects after stop', async function () {
			watcher.on('error', () => {});
			await watcher.start();

			const script = bitcoin.payments.p2wpkh({
				pubkey: Buffer.from(ecc.pointFromScalar(crypto.randomBytes(32))!)
			}).output as Buffer;

			backend.deferSubscribe = true;
			const pending = watcher
				.watchOutput('ef'.repeat(32), 0, script)
				.catch(() => {
					/* not the subject */
				});
			await tick();
			expect(backend.pendingSubscribeCount()).to.equal(1);

			watcher.stop();
			backend.failPendingSubscribes();
			await pending;
			await tick();

			expect(
				(watcher as unknown as { failedOutputWatches: unknown[] })
					.failedOutputWatches.length,
				'the queue stop() cleared stayed clear'
			).to.equal(0);
		});

		it('does not restore a failed broadcast when its retry rejects after stop', async function () {
			watcher.on('broadcast:failure', () => {});
			watcher.on('error', () => {});
			await watcher.start();

			// Seed the retry queue as a failed broadcast would.
			const tx = makeTx();
			const entry = {
				rawTx: tx,
				txidHex: bitcoin.Transaction.fromBuffer(tx).getId(),
				retryCount: 0
			};
			(
				watcher as unknown as { failedBroadcasts: unknown[] }
			).failedBroadcasts.push(entry);

			// The retry runs on the next block and fails.
			backend.broadcastShouldFail = true;
			backend.deferBroadcast = true;
			backend.simulateNewBlock(500);
			await tick();
			expect(
				backend.pendingBroadcastCount(),
				'the retry is in flight'
			).to.equal(1);

			watcher.stop();
			backend.failPendingBroadcasts();
			await tick();
			await tick();

			expect(
				(watcher as unknown as { failedBroadcasts: unknown[] }).failedBroadcasts
					.length,
				'the queue stop() cleared stayed clear'
			).to.equal(0);
		});
	});

	it('re-registers its ChannelManager handlers on restart, exactly once', async function () {
		await watcher.start();
		watcher.stop();
		await watcher.start();

		const tx = makeTx();
		channelManager.emit('broadcast:tx', tx);
		await tick();

		expect(
			backend.broadcastCalls.length,
			'one broadcast, not zero and not two'
		).to.equal(1);
	});
});
