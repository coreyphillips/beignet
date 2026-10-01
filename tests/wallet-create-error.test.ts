/**
 * Regression for issue #966: Wallet.create returned an error and left the
 * Electrum connection poll of the wallet it had built running.
 *
 * The private constructor builds the wallet's Electrum instance, and the
 * Electrum constructor starts a poll every POLLING_INTERVAL. When
 * setWalletData then failed (a storage id mismatch here), create returned Err
 * and nothing ever stopped that poll: the discarded wallet went on connecting
 * to the configured servers, called the caller's onMessage with
 * connectedToElectrum for a wallet the caller was told does not exist, and
 * kept the process alive.
 *
 * The Electrum.abandon cases pin why the failed create does not simply call
 * disconnect(): that stops rn-electrum-client's client for the network, and
 * there is one per network for the whole process, so an instance that never
 * connected has to leave it to the sibling wallets still using it.
 *
 * Fully OFFLINE: the server is an unreachable local port, fake timers drive
 * the poll, and connectToElectrum or rn-electrum-client's stop are stubbed
 * wherever they would reach it.
 */

import { expect } from 'chai';
import net from 'net';
import tls from 'tls';
import sinon from 'sinon';

// The raw module.exports object: the compiled namespace import in src/electrum
// reads it live through getter bindings, while this file's own namespace copy
// would be non-writable and invisible to src.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const electrumHelpers = require('rn-electrum-client/helpers');

import {
	createConsoleLogger,
	EAddressType,
	EAvailableNetworks,
	EElectrumNetworks,
	Electrum,
	EProtocol,
	err,
	getWalletDataStorageKey,
	IWallet,
	IWalletData,
	ok,
	Result,
	TMessageDataMap,
	TStorage,
	Wallet
} from '../src';
import { POLLING_INTERVAL } from '../src/shapes/electrum';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const WALLET_NAME = 'createerrorwallet';
const NETWORK = EAvailableNetworks.regtest;

// Unreachable on purpose: this test must work offline.
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

/**
 * sinon's fake timers, reached through a cast: the sinon typing this repo
 * resolves for the default export does not declare them, and the test type
 * check is run over the whole tests tree.
 */
type TFakeClock = {
	tickAsync: (ms: number) => Promise<void>;
	countTimers: () => number;
	restore: () => void;
};
/** Timers only: promises and setImmediate stay real, so awaits still run. */
const useFakeClock = (): TFakeClock =>
	(
		sinon as unknown as {
			useFakeTimers: (opts: { toFake: string[] }) => TFakeClock;
		}
	).useFakeTimers({
		toFake: ['setInterval', 'clearInterval', 'setTimeout', 'clearTimeout']
	});

/** In-memory storage, optionally holding another wallet's id under this
 *  wallet's name, which is what makes storageIdCheck refuse the create. */
const memoryStorage = (foreignId?: string): TStorage => {
	const store: Record<string, unknown> = {};
	if (foreignId) {
		store[getWalletDataStorageKey(WALLET_NAME, NETWORK, 'id')] = foreignId;
	}
	return {
		getData: async <K extends keyof IWalletData>(
			key: string
		): Promise<Result<IWalletData[K]>> => ok(store[key] as IWalletData[K]),
		setData: async <K extends keyof IWalletData>(
			key: string,
			value: IWalletData[K]
		): Promise<Result<boolean>> => {
			store[key] = value;
			return ok(true);
		}
	};
};

const createGate = (): { promise: Promise<void>; release: () => void } => {
	let release = (): void => {};
	const promise = new Promise<void>((resolve) => {
		release = (): void => resolve();
	});
	return { promise, release };
};

describe('Wallet.create returning an error (issue #966)', function () {
	this.timeout(20000);

	let clock: TFakeClock;
	let connectStub: sinon.SinonStub;
	let messages: Array<{ key: keyof TMessageDataMap; data: unknown }>;
	/** A wallet a case did get back, stopped after it. */
	let created: Wallet | undefined;

	const params = (storage: TStorage): IWallet => ({
		mnemonic: MNEMONIC,
		network: NETWORK,
		name: WALLET_NAME,
		addressType: EAddressType.p2wpkh,
		electrumOptions,
		storage,
		// Only the poll may reach for a server in these cases.
		disableRefreshOnCreate: true,
		logger: createConsoleLogger('silent'),
		onMessage: (key, data): void => {
			messages.push({ key, data });
		}
	});

	/** Every connectedToElectrum message a caller was sent. */
	const connectionMessages = (): unknown[] =>
		messages.filter((m) => m.key === 'connectedToElectrum');

	beforeEach(function () {
		messages = [];
		created = undefined;
		// Installed before the create, so the poll the constructor starts is one
		// of these timers.
		clock = useFakeClock();
		// Nothing is dialled: the poll's reconnect is what is being counted.
		connectStub = sinon
			.stub(Electrum.prototype, 'connectToElectrum')
			.resolves(err('offline test: nothing is dialled'));
	});

	afterEach(async function () {
		// Uninstalls the clock too, and with it any interval a case left behind.
		sinon.restore();
		await created?.stop();
	});

	it('stops the connection poll of a wallet whose stored id does not match', async function () {
		const res = await Wallet.create(
			params(memoryStorage('the-id-of-another-wallet'))
		);
		if (res.isOk()) created = res.value;
		expect(res.isErr()).to.equal(true);
		if (res.isOk()) return;
		expect(res.error.message).to.contain('Mismatched id found in storage');

		// The constructor's interval was the only timer, and it is gone.
		expect(clock.countTimers()).to.equal(0);

		await clock.tickAsync(POLLING_INTERVAL);
		await clock.tickAsync(POLLING_INTERVAL);
		expect(connectStub.called).to.equal(false);
		expect(connectionMessages()).to.deep.equal([]);
	});

	it('stops the connection poll when the create throws after the constructor', async function () {
		// setWalletData catches everything it runs into, so the catch in create
		// is only reached by something outside it failing.
		sinon
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			.stub(Wallet.prototype as any, 'setWalletData')
			.rejects(new Error('storage exploded'));
		const res = await Wallet.create(params(memoryStorage()));
		if (res.isOk()) created = res.value;
		expect(res.isErr()).to.equal(true);
		if (res.isOk()) return;
		expect(res.error.message).to.equal('storage exploded');

		expect(clock.countTimers()).to.equal(0);
		await clock.tickAsync(POLLING_INTERVAL);
		await clock.tickAsync(POLLING_INTERVAL);
		expect(connectStub.called).to.equal(false);
		expect(connectionMessages()).to.deep.equal([]);
	});

	it('still starts the poll for a wallet it creates', async function () {
		const res = await Wallet.create(params(memoryStorage()));
		if (res.isErr()) throw res.error;
		created = res.value;

		expect(clock.countTimers()).to.be.at.least(1);
		await clock.tickAsync(POLLING_INTERVAL);
		expect(connectStub.calledOnce).to.equal(true);
		// The failed reconnect is reported, which is what a discarded wallet
		// must never do.
		expect(connectionMessages()).to.deep.equal([
			{ key: 'connectedToElectrum', data: false }
		]);
	});
});

describe('Electrum.abandon (issue #966)', function () {
	this.timeout(20000);

	let clock: TFakeClock;
	let stopStub: sinon.SinonStub;
	let messages: Array<{ key: keyof TMessageDataMap; data: unknown }>;
	let wallet: Wallet;

	beforeEach(async function () {
		messages = [];
		clock = useFakeClock();
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			network: NETWORK,
			name: WALLET_NAME,
			electrumOptions,
			storage: memoryStorage(),
			disableRefreshOnCreate: true,
			logger: createConsoleLogger('silent'),
			onMessage: (key, data): void => {
				messages.push({ key, data });
			}
		});
		if (res.isErr()) throw res.error;
		wallet = res.value;
		// The process-wide client for the network: what a sibling would lose.
		stopStub = sinon
			.stub(electrumHelpers, 'stop')
			.resolves({ error: false, data: 'Disconnected...' });
	});

	afterEach(async function () {
		sinon.restore();
		await wallet?.stop();
	});

	it('leaves the shared client alone for an instance that never connected', async function () {
		await wallet.electrum.abandon();

		expect(clock.countTimers()).to.equal(0);
		expect(stopStub.called).to.equal(false);
		expect(wallet.electrum.isDisconnected).to.equal(true);
	});

	it('disconnects an instance that is connected', async function () {
		wallet.electrum.connectedToElectrum = true;

		await wallet.electrum.abandon();

		expect(clock.countTimers()).to.equal(0);
		expect(stopStub.calledOnce).to.equal(true);
		expect(stopStub.firstCall.args[0]).to.deep.equal({
			network: EElectrumNetworks.bitcoinRegtest
		});
		expect(wallet.electrum.connectedToElectrum).to.equal(false);
	});

	it('waits for a connect in flight, then disconnects without announcing it', async function () {
		const gate = createGate();
		// attemptConnect is isolated for tests to fake the connection layer: this
		// one succeeds, but only once the gate opens.
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(wallet.electrum as any).attemptConnect = async (): Promise<{
			error: unknown;
		}> => {
			await gate.promise;
			return { error: undefined };
		};
		const connecting = wallet.electrum.connectToElectrum({
			servers: electrumOptions.servers
		});

		let abandoned = false;
		const abandoning = wallet.electrum.abandon().then(() => {
			abandoned = true;
		});
		await new Promise((resolve) => setImmediate(resolve));
		expect(abandoned).to.equal(false);
		expect(stopStub.called).to.equal(false);

		gate.release();
		await abandoning;

		expect((await connecting).isErr()).to.equal(true);
		expect(clock.countTimers()).to.equal(0);
		expect(stopStub.called).to.equal(true);
		expect(wallet.electrum.connectedToElectrum).to.equal(false);
		expect(wallet.electrum.isDisconnected).to.equal(true);
		expect(
			messages.filter((m) => m.key === 'connectedToElectrum')
		).to.deep.equal([]);
	});
});
