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
	broadcastShouldFail = false;

	async subscribeToHeaders(
		onNewBlock: (height: number) => void
	): Promise<void> {
		// ElectrumBackend replaces its single header callback rather than
		// accumulating, so a re-subscribe must not double-deliver here either.
		this.headerCallback = onNewBlock;
	}

	async subscribeToScriptHash(): Promise<void> {
		// Accepted, never fires.
	}

	getScriptHashHistory(): Promise<Array<{ txid: string; height: number }>> {
		// Stays pending until the test settles it.
		return new Promise((_resolve, reject) => {
			this.historyRejecters.push(reject);
		});
	}

	async getTransaction(): Promise<Buffer> {
		throw new Error('not used');
	}

	async broadcastTransaction(rawTxHex: string): Promise<string> {
		this.broadcastCalls.push(rawTxHex);
		if (this.broadcastShouldFail) throw new Error('broadcast refused');
		return crypto
			.createHash('sha256')
			.update(Buffer.from(rawTxHex, 'hex'))
			.digest()
			.reverse()
			.toString('hex');
	}

	/** Reject everything the watcher has in flight against this backend. */
	failPendingHistory(): void {
		const rejecters = this.historyRejecters;
		this.historyRejecters = [];
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
