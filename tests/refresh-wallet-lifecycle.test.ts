/**
 * Regression: refreshWallet must release isRefreshing on every path it owns.
 *
 * The flag was raised for every call but only lowered by the non-forced paths,
 * so a successful `force: true` refresh left it set for the life of the wallet.
 * rescanAddresses is the only forced caller and is public API, so after any
 * rescan every later refreshWallet() queued a resolver nothing would drain and
 * stop() waited on one of those promises forever.
 *
 * The release has to be ownership based rather than unconditional: a forced
 * refresh can be nested inside one already in flight (refreshWallet ->
 * updateTransactions -> checkUnconfirmedTransactions -> updateGhostTransactions
 * -> rescanAddresses -> refreshWallet), and lowering the flag there would hand a
 * second caller a concurrent refresh.
 *
 * Fully OFFLINE: the wallet points at an unreachable port and every step of the
 * refresh is stubbed, so this asserts on the flag lifecycle alone.
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
		ssl: 65529,
		tcp: 65529,
		protocol: EProtocol.tcp
	}
};

/** The private steps refreshWallet runs, stubbed through a cast. */
type TRefreshInternals = {
	setZeroIndexAddresses: () => Promise<Result<string>>;
	updateAddressIndexes: () => Promise<Result<string>>;
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

describe('refreshWallet flag lifecycle', function () {
	this.timeout(60000);

	let wallet: Wallet;
	let updateTransactionsStub: sinon.SinonStub;
	let getUtxosStub: sinon.SinonStub;

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
		// finish (it fails fast against the unreachable port) before stubbing,
		// so the cases below own the flag from a known-idle start.
		for (let i = 0; i < 400 && wallet.isRefreshing; i++) {
			await new Promise((resolve) => setTimeout(resolve, 25));
		}
		expect(
			wallet.isRefreshing,
			"the refresh Wallet.create started never settled, so these cases can't own the flag"
		).to.equal(false);

		// Every step of the refresh succeeds: the flag, not the sync, is the subject.
		sinon
			.stub(wallet as unknown as TRefreshInternals, 'setZeroIndexAddresses')
			.resolves(ok('stubbed'));
		sinon
			.stub(wallet as unknown as TRefreshInternals, 'updateAddressIndexes')
			.resolves(ok('stubbed'));
		getUtxosStub = sinon
			.stub(wallet, 'getUtxos')
			.resolves(ok<IGetUtxosResponse>({ utxos: [], balance: 0 }));
		updateTransactionsStub = sinon
			.stub(wallet, 'updateTransactions')
			.resolves(ok<string | undefined>(undefined));
		sinon.stub(wallet.electrum, 'subscribeToAddresses').resolves(ok('stubbed'));
		// Fired unawaited by every refresh; keep it off the network.
		sinon.stub(wallet, 'updateFeeEstimates').resolves(ok(wallet.feeEstimates));
	});

	afterEach(async function () {
		sinon.restore();
		// stop() waits on refreshWallet() while the flag is set, so a case that
		// fails on a leaked flag would hang teardown and take the rest of the
		// file with it. Every case asserts the flag itself before getting here.
		if (wallet) wallet.isRefreshing = false;
		await wallet?.stop();
	});

	it('releases the flag after a forced refresh it owns', async function () {
		const forced = await wallet.refreshWallet({ force: true });
		expect(forced.isOk(), 'the forced refresh succeeded').to.equal(true);
		expect(
			wallet.isRefreshing,
			'a forced refresh with no outer refresh releases the flag'
		).to.equal(false);

		const next = await withDeadline(
			wallet.refreshWallet({}),
			5000,
			'the refresh after a forced one'
		);
		expect(next.isOk()).to.equal(true);
	});

	it('releases the flag when a forced refresh it owns throws', async function () {
		getUtxosStub.rejects(new Error('electrum went away'));

		const forced = await wallet.refreshWallet({ force: true });
		expect(forced.isErr(), 'the throw is reported to the caller').to.equal(
			true
		);
		expect(
			wallet.isRefreshing,
			'a forced refresh that throws still releases the flag'
		).to.equal(false);
	});

	it('leaves the wallet usable and stoppable after rescanAddresses', async function () {
		const rescan = await wallet.rescanAddresses({
			shouldClearAddresses: false
		});
		expect(rescan.isOk(), 'the rescan succeeded').to.equal(true);
		expect(wallet.isRefreshing, 'the rescan released the flag').to.equal(false);

		// stop() waits on refreshWallet() when the flag is set, so a leaked flag
		// hangs it on a promise nothing will ever resolve.
		const stopped = await withDeadline(
			wallet.stop(),
			5000,
			'stop() after a rescan'
		);
		expect(stopped.isOk()).to.equal(true);
	});

	it('resolves a refresh queued while a forced refresh is in flight', async function () {
		let release: () => void = () => undefined;
		const gate = new Promise<void>((resolve) => {
			release = resolve;
		});
		getUtxosStub.callsFake(async () => {
			await gate;
			return ok<IGetUtxosResponse>({ utxos: [], balance: 0 });
		});

		const forced = wallet.refreshWallet({ force: true });
		expect(wallet.isRefreshing, 'the forced refresh raised the flag').to.equal(
			true
		);
		const queued = wallet.refreshWallet({});
		release();

		const [forcedRes, queuedRes] = await withDeadline(
			Promise.all([forced, queued]),
			5000,
			'the forced refresh and the call queued behind it'
		);
		expect(forcedRes.isOk()).to.equal(true);
		expect(queuedRes.isOk(), 'the queued caller was handed a result').to.equal(
			true
		);
		expect(wallet.isRefreshing).to.equal(false);
	});

	it('keeps the flag while a nested forced refresh runs inside another', async function () {
		let nested = 0;
		let flagAfterNestedRefresh: boolean | null = null;
		let queuedSettledDuringOuter = false;

		updateTransactionsStub.callsFake(
			async (): Promise<Result<string | undefined>> => {
				// Only the outer refresh nests, otherwise this recurses forever.
				if (nested++ === 0) {
					const inner = await wallet.refreshWallet({
						scanAllAddresses: true,
						force: true
					});
					expect(inner.isOk(), 'the nested forced refresh succeeded').to.equal(
						true
					);
					flagAfterNestedRefresh = wallet.isRefreshing;
				}
				return ok<string | undefined>(undefined);
			}
		);

		const outer = wallet.refreshWallet({});
		expect(wallet.isRefreshing).to.equal(true);
		const queued = wallet.refreshWallet({});
		void queued.then(() => {
			queuedSettledDuringOuter = flagAfterNestedRefresh === null;
		});

		const outerRes = await withDeadline(outer, 5000, 'the outer refresh');
		expect(outerRes.isOk()).to.equal(true);
		expect(
			nested,
			'the outer refresh reached updateTransactions'
		).to.be.greaterThan(0);
		expect(
			flagAfterNestedRefresh,
			'the nested forced refresh left the flag to its owner'
		).to.equal(true);
		expect(
			queuedSettledDuringOuter,
			'the queued caller was not resolved by the nested refresh'
		).to.equal(false);

		const queuedRes = await withDeadline(queued, 5000, 'the queued refresh');
		expect(queuedRes.isOk()).to.equal(true);
		expect(
			wallet.isRefreshing,
			'the outer refresh released the flag it owned'
		).to.equal(false);
	});
});
