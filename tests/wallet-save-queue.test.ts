/**
 * Regression tests for issue #946: Wallet.saveWalletData.
 *
 * It checked for a storage adapter only on entry, then waited its turn in a
 * per-key queue and called the adapter without checking again. A stop()
 * landing while a write was queued cleared the adapter under it, and the
 * write rejected with a TypeError instead of answering Err. An adapter that
 * threw synchronously rejected the same way.
 *
 * The queue itself held back only one writer: every caller that arrived while
 * a write was in flight waited on that same write, then all of them wrote at
 * once, and an adapter that finished them out of order stored an older value
 * last. Each write also removed the queue entry when it finished, even when a
 * newer write had replaced it, so the next caller skipped the queue entirely.
 *
 * Fully OFFLINE: the wallet points at an unreachable Electrum port, never
 * refreshes, and writes to the balance key go to a storage double the test
 * finishes by hand.
 */

import { expect } from 'chai';
import net from 'net';
import sinon from 'sinon';
import tls from 'tls';

import {
	EAvailableNetworks,
	EProtocol,
	IWalletData,
	Result,
	TStorage,
	Wallet,
	ok
} from '../src';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

// Unreachable on purpose: these tests must work offline.
const electrumOptions = {
	net,
	tls,
	servers: {
		host: '127.0.0.1',
		ssl: 65526,
		tcp: 65526,
		protocol: EProtocol.tcp
	}
};

const NAME = 'savequeue';
const BALANCE_KEY = `${NAME}-regtest-balance`;

/** One write the storage double received and has not finished. */
type TPendingWrite = { value: unknown; land: () => void };

/**
 * Storage that writes every key at once except the balance, whose writes
 * wait for the test to land them, in whatever order it chooses: an adapter
 * that completes writes out of order. `throwSync` makes a balance write throw
 * before it returns a promise at all.
 */
const makeStorage = (): {
	store: Map<string, unknown>;
	storage: TStorage;
	writes: TPendingWrite[];
	landed: unknown[];
	control: { defer: boolean; throwSync: boolean };
} => {
	const store = new Map<string, unknown>();
	const writes: TPendingWrite[] = [];
	const landed: unknown[] = [];
	const control = { defer: false, throwSync: false };
	const storage: TStorage = {
		getData: async <K extends keyof IWalletData>(
			key: string
		): Promise<Result<IWalletData[K]>> => ok(store.get(key) as IWalletData[K]),
		setData: <K extends keyof IWalletData>(
			key: string,
			value: IWalletData[K]
		): Promise<Result<boolean>> => {
			const write = (): void => {
				store.set(key, value);
				if (key === BALANCE_KEY) landed.push(value);
			};
			if (key !== BALANCE_KEY || !control.defer) {
				if (key === BALANCE_KEY && control.throwSync) {
					throw new Error('storage is closed');
				}
				write();
				return Promise.resolve(ok(true));
			}
			return new Promise((resolve) => {
				let done = false;
				writes.push({
					value,
					land: (): void => {
						if (done) return;
						done = true;
						write();
						resolve(ok(true));
					}
				});
			});
		}
	};
	return { store, storage, writes, landed, control };
};

/** Lets every settled promise run its handlers. */
const flush = (): Promise<void> =>
	new Promise((resolve) => setImmediate(resolve));

/** Polls a condition and throws rather than returning quietly on timeout. */
const waitFor = async (
	predicate: () => boolean,
	ms: number,
	what: string
): Promise<void> => {
	const deadline = Date.now() + ms;
	while (!predicate()) {
		if (Date.now() > deadline) {
			throw new Error(`timed out after ${ms}ms waiting for ${what}`);
		}
		await new Promise((resolve) => setTimeout(resolve, 5));
	}
};

/** Rejects loudly rather than leaving the suite to hit mocha's own timeout. */
const withDeadline = async <T>(
	promise: Promise<T>,
	ms: number,
	what: string
): Promise<T> => {
	let timer: NodeJS.Timeout;
	const deadline = new Promise<never>((_, reject) => {
		timer = setTimeout(
			() => reject(new Error(`${what} did not settle within ${ms}ms`)),
			ms
		);
	});
	try {
		return await Promise.race([promise, deadline]);
	} finally {
		clearTimeout(timer!);
	}
};

/** Turns a rejection into a failure that says so, rather than a stack. */
const settle = (
	write: Promise<Result<string>>,
	what: string
): Promise<Result<string>> =>
	write.catch((e) => {
		throw new Error(`${what} rejected instead of answering: ${e}`);
	});

describe('Wallet storage writes (#946)', function () {
	this.timeout(60000);

	let wallet: Wallet;
	let store: Map<string, unknown>;
	let writes: TPendingWrite[];
	let landed: unknown[];
	let control: { defer: boolean; throwSync: boolean };

	beforeEach(async function () {
		let storage: TStorage;
		({ store, storage, writes, landed, control } = makeStorage());
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			name: NAME,
			network: EAvailableNetworks.regtest,
			storage,
			electrumOptions,
			disableRefreshOnCreate: true
		});
		if (res.isErr()) throw res.error;
		wallet = res.value;
		// Fired unawaited by create; let its write land before the cases start.
		await flush();
	});

	afterEach(async function () {
		// Land whatever a case left pending, so stop() has nothing to wait on.
		control.defer = false;
		for (let i = 0; i < writes.length; i++) {
			writes[i].land();
			await flush();
		}
		sinon.restore();
		wallet.isRefreshing = false;
		await wallet?.stop({ refreshTimeout: 1000 });
	});

	/** Lands the newest write the adapter holds, until none are left. */
	const landNewestFirst = async (
		all: Promise<Result<string>>[]
	): Promise<void> => {
		let settled = false;
		void Promise.all(all).then(() => {
			settled = true;
		});
		const done = new Set<TPendingWrite>();
		for (let i = 0; i < 100 && !settled; i++) {
			await flush();
			const open = writes.filter((write) => !done.has(write));
			const newest = open[open.length - 1];
			if (!newest) continue;
			done.add(newest);
			newest.land();
		}
		expect(settled, 'every write settled').to.equal(true);
	};

	it('lands writes to one key in the order they were issued, on an adapter that finishes out of order', async () => {
		control.defer = true;
		const issued = [1, 2, 3].map((value) =>
			settle(wallet.saveWalletData('balance', value), `write ${value}`)
		);

		await landNewestFirst(issued);

		for (const res of await Promise.all(issued)) {
			expect(res.isOk(), 'every write answered ok').to.equal(true);
		}
		expect(landed, 'the writes reached storage in call order').to.deep.equal([
			1, 2, 3
		]);
		expect(store.get(BALANCE_KEY), 'the last value issued is stored').to.equal(
			3
		);
	});

	it('holds a write issued while the one before it is in flight', async () => {
		control.defer = true;
		const issued = [1, 2, 3].map((value) =>
			settle(wallet.saveWalletData('balance', value), `write ${value}`)
		);
		await flush();
		expect(writes, 'only the first write reached storage').to.have.length(1);
		writes[0].land();
		await flush();
		expect(writes, 'the second followed the first').to.have.length(2);
		writes[1].land();
		await flush();
		expect(writes, 'the third followed the second').to.have.length(3);

		// The third is in flight. A fourth must still wait for it.
		issued.push(settle(wallet.saveWalletData('balance', 4), 'write 4'));
		await flush();
		expect(
			writes,
			'the fourth write did not overtake the third'
		).to.have.length(3);

		writes[2].land();
		await flush();
		expect(writes, 'the fourth followed the third').to.have.length(4);
		writes[3].land();

		for (const res of await Promise.all(issued)) {
			expect(res.isOk()).to.equal(true);
		}
		expect(landed).to.deep.equal([1, 2, 3, 4]);
		expect(store.get(BALANCE_KEY)).to.equal(4);
		expect(
			Object.keys(
				(wallet as unknown as { savingOperations: object }).savingOperations
			),
			'the queue is empty once every write landed'
		).to.have.length(0);
	});

	it('answers Err when the adapter throws before returning a promise', async () => {
		control.throwSync = true;
		const res = await settle(
			wallet.saveWalletData('balance', 1),
			'the throwing write'
		);
		expect(res.isErr()).to.equal(true);
		if (res.isErr()) {
			expect(res.error.message).to.include(BALANCE_KEY);
			expect(res.error.message).to.include('storage is closed');
		}

		// The key is not left wedged behind the failed write.
		control.throwSync = false;
		const next = await settle(wallet.saveWalletData('balance', 2), 'write 2');
		expect(next.isOk()).to.equal(true);
		expect(store.get(BALANCE_KEY)).to.equal(2);
	});

	it('answers Err naming the key for a queued write stop() dropped', async () => {
		control.defer = true;
		const first = settle(wallet.saveWalletData('balance', 1), 'write 1');
		const second = settle(wallet.saveWalletData('balance', 2), 'write 2');
		await flush();

		// The first write never lands inside the deadline, so stop() gives up
		// on both and turns storage off with the second still waiting its turn.
		const stopped = await withDeadline(
			wallet.stop({ refreshTimeout: 100 }),
			5000,
			'stop() behind a write that does not land'
		);
		expect(stopped.isOk(), 'the wallet stopped').to.equal(true);
		if (stopped.isOk()) {
			expect(stopped.value, 'the result names what was abandoned').to.include(
				'writes to balance'
			);
		}

		writes[0].land();
		expect((await first).isOk(), 'the write in flight landed').to.equal(true);
		const dropped = await second;
		expect(dropped.isErr(), 'the dropped write says so').to.equal(true);
		if (dropped.isErr()) {
			expect(dropped.error.message).to.include(BALANCE_KEY);
			expect(dropped.error.message).to.include('stopped');
		}
		expect(writes, 'the dropped write never reached storage').to.have.length(1);
		expect(store.get(BALANCE_KEY)).to.equal(1);
	});

	it('lets writes queued before stop() land when they do so inside the deadline', async () => {
		control.defer = true;
		const first = settle(wallet.saveWalletData('balance', 1), 'write 1');
		const second = settle(wallet.saveWalletData('balance', 2), 'write 2');
		await flush();

		let stopSettled = false;
		const stopping = wallet.stop({ refreshTimeout: 5000 }).then((res) => {
			stopSettled = true;
			return res;
		});
		// Long enough that a stop() ignoring the queue would have returned.
		await new Promise((resolve) => setTimeout(resolve, 100));
		expect(stopSettled, 'stop() is waiting on the queued writes').to.equal(
			false
		);

		writes[0].land();
		await waitFor(() => writes.length === 2, 5000, 'the second write');
		writes[1].land();
		const stopped = await withDeadline(stopping, 5000, 'stop()');

		expect(stopped.isOk()).to.equal(true);
		if (stopped.isOk()) {
			expect(stopped.value, 'nothing was abandoned').to.equal(
				'Wallet stopped.'
			);
		}
		expect((await first).isOk()).to.equal(true);
		expect((await second).isOk()).to.equal(true);
		expect(store.get(BALANCE_KEY)).to.equal(2);
		// Storage is off once stop() returns.
		expect(
			(await wallet.saveWalletData('balance', 3)).isOk(),
			'a write after stop() is a no-op, not a failure'
		).to.equal(true);
		expect(store.get(BALANCE_KEY)).to.equal(2);
	});

	// The storage wait shares the refresh's deadline instead of adding a
	// second one after it.
	it('waits for a refresh and queued writes within one deadline', async () => {
		sinon
			.stub(wallet, 'refreshWallet')
			.returns(new Promise<Result<IWalletData>>(() => undefined));
		wallet.isRefreshing = true;
		// Keeps the socket teardown out of the timing; afterEach does it.
		sinon.stub(wallet.electrum, 'disconnect').resolves();
		control.defer = true;
		const first = settle(wallet.saveWalletData('balance', 1), 'write 1');
		await flush();

		const started = Date.now();
		const stopped = await withDeadline(
			wallet.stop({ refreshTimeout: 400 }),
			5000,
			'stop() behind a refresh and a write that never settle'
		);
		// Two waits back to back would take 800ms.
		expect(Date.now() - started).to.be.below(700);
		expect(stopped.isOk()).to.equal(true);
		if (stopped.isOk()) {
			expect(stopped.value).to.include('abandoning a refresh');
			expect(stopped.value).to.include('writes to balance');
		}

		writes[0].land();
		expect((await first).isOk()).to.equal(true);
	});
});
