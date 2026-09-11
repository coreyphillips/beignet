/**
 * Regression: stop() must be bounded by the deadline it was given.
 *
 * stop() opened by awaiting refreshWallet() whenever isRefreshing was set, with
 * no deadline. The refresh queues that caller and resolves it only when the
 * in-flight refresh finishes, and a refresh waits on things that are not
 * bounded either (an Electrum client that falls into an untimed server_version
 * handshake when a network has no client, caller-supplied storage and address
 * callbacks). A server that accepted the socket and then stopped answering left
 * stop() pending forever: disableMessages unset, _setData still live,
 * electrum.disconnect() never reached.
 *
 * Fully OFFLINE: the wallet points at an unreachable port and every step of the
 * refresh is stubbed, so this asserts on the shutdown path alone.
 */

import { expect } from 'chai';
import net from 'net';
import tls from 'tls';
import sinon from 'sinon';

import {
	EAddressType,
	EAvailableNetworks,
	EProtocol,
	IGetUtxosResponse,
	ok,
	Result,
	Wallet
} from '../src';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

// Unreachable on purpose: this test must work offline.
const electrumOptions = {
	net,
	tls,
	servers: {
		host: '127.0.0.1',
		ssl: 65528,
		tcp: 65528,
		protocol: EProtocol.tcp
	}
};

/** The private members the cases below reach through a cast. */
type TWalletInternals = {
	setZeroIndexAddresses: () => Promise<Result<string>>;
	updateAddressIndexes: () => Promise<Result<string>>;
	_disableMessagesOnCreate: boolean;
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

describe('stop() refresh deadline', function () {
	this.timeout(60000);

	let wallet: Wallet;
	let getUtxosStub: sinon.SinonStub;
	let setZeroIndexStub: sinon.SinonStub;
	let updateAddressIndexesStub: sinon.SinonStub;
	let updateTransactionsStub: sinon.SinonStub;
	let subscribeStub: sinon.SinonStub;
	let disconnectStub: sinon.SinonStub;
	/** Releases whatever refresh is parked in getUtxos. */
	let releaseRefresh: () => void = () => undefined;
	let parkedRefresh: Promise<unknown> | null = null;
	let refreshSettled = false;

	beforeEach(async function () {
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			network: EAvailableNetworks.regtest,
			addressType: EAddressType.p2wpkh,
			electrumOptions
		});
		if (res.isErr()) throw res.error;
		wallet = res.value;

		// Wallet.create kicks off a refresh without awaiting it. Let that one
		// finish (it fails fast against the unreachable port) before stubbing, so
		// the cases below own the flag from a known-idle start.
		await waitFor(
			() => !wallet.isRefreshing,
			20000,
			'the refresh Wallet.create started to settle'
		);

		// Every step of the refresh succeeds: the shutdown path, not the sync, is
		// the subject.
		setZeroIndexStub = sinon
			.stub(wallet as unknown as TWalletInternals, 'setZeroIndexAddresses')
			.resolves(ok('stubbed'));
		updateAddressIndexesStub = sinon
			.stub(wallet as unknown as TWalletInternals, 'updateAddressIndexes')
			.resolves(ok('stubbed'));
		getUtxosStub = sinon.stub(wallet, 'getUtxos');
		updateTransactionsStub = sinon
			.stub(wallet, 'updateTransactions')
			.resolves(ok<string | undefined>(undefined));
		subscribeStub = sinon
			.stub(wallet.electrum, 'subscribeToAddresses')
			.resolves(ok('stubbed'));
		// Fired unawaited by every refresh; keep it off the network.
		sinon.stub(wallet, 'updateFeeEstimates').resolves(ok(wallet.feeEstimates));
		// Asserted on directly, and stubbed so the real socket teardown belongs to
		// afterEach alone.
		disconnectStub = sinon.stub(wallet.electrum, 'disconnect').resolves();

		parkedRefresh = null;
		refreshSettled = false;
		const parked = new Promise<void>((resolve) => {
			releaseRefresh = resolve;
		});
		getUtxosStub.callsFake(async () => {
			await parked;
			return ok<IGetUtxosResponse>({ utxos: [], balance: 0 });
		});
	});

	afterEach(async function () {
		// A case that stopped on the deadline left its refresh parked. Finish it
		// while the stubs are still installed, so the tail of it cannot reach the
		// unreachable server after the suite has moved on.
		releaseRefresh();
		if (parkedRefresh) await parkedRefresh;
		sinon.restore();
		wallet.isRefreshing = false;
		await wallet?.stop();
	});

	/** Starts a refresh and parks it in getUtxos with the flag up. */
	const parkARefresh = async (): Promise<void> => {
		parkedRefresh = wallet.refreshWallet().then(() => {
			refreshSettled = true;
		});
		await waitFor(
			() => getUtxosStub.callCount === 1,
			5000,
			'the refresh to reach getUtxos'
		);
		expect(wallet.isRefreshing, 'the refresh raised the flag').to.equal(true);
	};

	it('stops on the deadline when the refresh never settles', async function () {
		await parkARefresh();

		const stopped = await withDeadline(
			wallet.stop({ refreshTimeout: 100 }),
			5000,
			'stop() behind a refresh that never settles'
		);

		expect(stopped.isOk(), 'the wallet stopped').to.equal(true);
		if (stopped.isOk()) {
			expect(
				stopped.value,
				'the result says the refresh was abandoned'
			).to.contain('abandoning a refresh');
		}
		expect(refreshSettled, 'the refresh really is still in flight').to.equal(
			false
		);
		// The whole point of the deadline: the teardown happened anyway.
		expect(wallet.disableMessages, 'messages were disabled').to.equal(true);
		expect(
			disconnectStub.callCount,
			'the socket did not outlive the wallet'
		).to.equal(1);
	});

	it('does not let the abandoned refresh revive the wallet', async function () {
		// The deadline hands the refresh a life after stop(): it resumes with the
		// socket down and messages disabled, and must leave both that way.
		let releaseFirstStep: () => void = () => undefined;
		const parkedStep = new Promise<void>((resolve) => {
			releaseFirstStep = resolve;
		});
		setZeroIndexStub.callsFake(async () => {
			await parkedStep;
			return ok('stubbed');
		});
		// Stands in for the real updateAddressIndexes, which opens with exactly
		// this call: it is the refresh's first connection check after the park.
		updateAddressIndexesStub.callsFake(() => wallet.checkElectrumConnection());
		const connectStub = sinon
			.stub(wallet, 'connectToElectrum')
			.resolves(ok('connected'));
		// The daemon creates its wallet this way, so the refresh ends by putting
		// messages back.
		(wallet as unknown as TWalletInternals)._disableMessagesOnCreate = true;
		wallet.disableMessages = false;

		parkedRefresh = wallet.refreshWallet();
		await waitFor(
			() => setZeroIndexStub.callCount === 1,
			5000,
			'the refresh to park before its first connection check'
		);

		const stopped = await withDeadline(
			wallet.stop({ refreshTimeout: 50 }),
			5000,
			'stop() behind a parked refresh'
		);
		expect(stopped.isOk(), 'the wallet stopped').to.equal(true);

		releaseFirstStep();
		// The refused connection check ends the refresh there. A refresh that
		// reconnects instead carries on to the park in getUtxos, which only
		// afterEach releases.
		await withDeadline(
			parkedRefresh,
			5000,
			'the abandoned refresh at its connection check'
		);

		expect(
			connectStub.callCount,
			'the abandoned refresh did not dial a peer'
		).to.equal(0);
		expect(
			wallet.disableMessages,
			'the abandoned refresh did not re-enable messages'
		).to.equal(true);
	});

	it('ends a refresh abandoned past its connection check', async function () {
		// The park here is in getUtxos, downstream of the connection check the
		// refresh already passed, so the guard on that check cannot catch it. The
		// steps after it go to Electrum, which dials again when it finds itself
		// disconnected.
		await parkARefresh();

		const stopped = await withDeadline(
			wallet.stop({ refreshTimeout: 50 }),
			5000,
			'stop() behind a refresh parked in getUtxos'
		);
		expect(stopped.isOk(), 'the wallet stopped').to.equal(true);

		releaseRefresh();
		await withDeadline(parkedRefresh!, 5000, 'the abandoned refresh');

		expect(
			updateTransactionsStub.callCount,
			'the abandoned refresh did not go on to Electrum'
		).to.equal(0);
		expect(
			subscribeStub.callCount,
			'the abandoned refresh did not re-subscribe'
		).to.equal(0);
	});

	it('still waits for a refresh that settles inside the deadline', async function () {
		await parkARefresh();

		const stopping = wallet.stop({ refreshTimeout: 5000 });
		// Long enough that a stop() ignoring the refresh would have returned.
		await new Promise((resolve) => setTimeout(resolve, 100));
		expect(
			disconnectStub.callCount,
			'stop() is still waiting on the refresh'
		).to.equal(0);

		releaseRefresh();
		const stopped = await withDeadline(stopping, 5000, 'stop()');

		expect(stopped.isOk()).to.equal(true);
		if (stopped.isOk()) {
			expect(stopped.value, 'nothing was abandoned').to.equal(
				'Wallet stopped.'
			);
		}
		expect(refreshSettled, 'the refresh finished first').to.equal(true);
		expect(disconnectStub.callCount).to.equal(1);
	});

	it('tears down when the refresh rejects rather than resolving', async function () {
		// refreshWallet answers an Err rather than throwing today; this stands in
		// for any future path out of the wait that is not a clean resolve.
		sinon
			.stub(wallet, 'refreshWallet')
			.rejects(new Error('electrum went away'));
		wallet.isRefreshing = true;

		const stopped = await withDeadline(wallet.stop(), 5000, 'stop()');

		expect(
			stopped.isOk(),
			'the rejection did not become the caller problem'
		).to.equal(true);
		expect(wallet.disableMessages).to.equal(true);
		expect(disconnectStub.callCount, 'disconnect was reached').to.equal(1);
	});

	it('does not wait at all when no refresh is in flight', async function () {
		expect(wallet.isRefreshing).to.equal(false);

		const stopped = await withDeadline(
			wallet.stop({ refreshTimeout: 5000 }),
			1000,
			'stop() with an idle wallet'
		);

		expect(stopped.isOk()).to.equal(true);
		expect(getUtxosStub.callCount, 'no refresh was started').to.equal(0);
		expect(disconnectStub.callCount).to.equal(1);
	});
});
