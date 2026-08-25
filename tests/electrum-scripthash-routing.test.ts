/**
 * Regression tests for issue #478: Electrum script hash subscriptions were
 * aliased. rn-electrum-client installs ONE 'blockchain.scripthash.subscribe'
 * handler per network (the first onReceive it is handed) and answers a repeat
 * script hash with "Already Subscribed." without wiring the new callback, so
 * the first subscriber in the process received every notification and every
 * later callback was silently dead. The fix keeps a per-script-hash callback
 * registry inside Electrum and hands the client one stable dispatcher that
 * routes by the script hash in the notification payload.
 *
 * Fully OFFLINE: subscribeAddress is stubbed with a faithful model of the
 * client's global-handler contract, and notifications are fired by invoking
 * the captured handler exactly as the client's emitter would.
 */

import { expect } from 'chai';
import * as net from 'net';
import * as tls from 'tls';
import sinon from 'sinon';

// The raw module.exports object: the compiled namespace import in
// src/electrum reads it live through getter bindings, while the test file's
// own namespace copy would be non-writable and invisible to src.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const electrumHelpers = require('rn-electrum-client/helpers');

import {
	EAvailableNetworks,
	Electrum,
	EProtocol,
	EScanningStrategy,
	TServer,
	Wallet
} from '../src';
import { ElectrumBackend } from '../src/lightning/chain/electrum-backend';

type TNotification = [string, string];

const server: TServer = {
	host: 'offline.example.com',
	ssl: 50002,
	tcp: 50001,
	protocol: EProtocol.tcp
};

/**
 * The client keeps one handler per network: the first onReceive wins, and a
 * script hash already in the subscribed list resolves "Already Subscribed."
 * without wiring anything (rn-electrum-client/helpers/index.js:374-387).
 */
let globalHandler: ((data: TNotification) => void | Promise<void>) | null;
let subscribedHashes: string[];
/** Fail the next N protocol subscribes (after the handler install, matching
 *  where the real client's blockchainScripthash_subscribe request fails). */
let failNextSubscribes: number;
/** Hang the next N protocol subscribes, for the backend timeout path. */
let hangNextSubscribes: number;

const fireNotification = async (data: TNotification): Promise<void> => {
	if (!globalHandler) {
		throw new Error('No client-level handler was installed');
	}
	await globalHandler(data);
};

const createFakeWallet = (refreshSpy: sinon.SinonStub): Wallet => {
	return {
		sendMessage: (): void => {},
		isSwitchingNetworks: false,
		refreshWallet: refreshSpy,
		addressTypesToMonitor: [],
		data: { utxos: [] }
	} as unknown as Wallet;
};

/** Instances created this test, withdrawn from the shared per-network router
 *  in afterEach so no test leaks subscriptions into the next. */
const createdInstances: Electrum[] = [];

const createElectrum = (refreshSpy: sinon.SinonStub): Electrum => {
	const electrum = new Electrum({
		wallet: createFakeWallet(refreshSpy),
		network: EAvailableNetworks.testnet,
		net,
		tls,
		servers: [server]
	});
	// No background pings during tests.
	electrum.stopConnectionPolling();
	createdInstances.push(electrum);
	return electrum;
};

describe('Electrum script hash subscription routing (issue #478)', () => {
	let refreshSpy: sinon.SinonStub;
	let electrum: Electrum;

	beforeEach(() => {
		globalHandler = null;
		subscribedHashes = [];
		failNextSubscribes = 0;
		hangNextSubscribes = 0;
		sinon.stub(electrumHelpers, 'subscribeAddress').callsFake(
			async ({
				scriptHash = '',
				onReceive = undefined
			}: {
				scriptHash?: string;
				onReceive?: (data: TNotification) => void;
			} = {}) => {
				if (onReceive && !globalHandler) {
					globalHandler = onReceive;
				}
				if (hangNextSubscribes > 0) {
					hangNextSubscribes--;
					return new Promise(() => {});
				}
				if (failNextSubscribes > 0) {
					failNextSubscribes--;
					return {
						error: true,
						data: 'subscribe failed',
						id: 1,
						method: 'subscribeAddress'
					};
				}
				if (subscribedHashes.includes(scriptHash)) {
					return {
						error: false,
						data: 'Already Subscribed.',
						id: 1,
						method: 'subscribeAddress'
					};
				}
				subscribedHashes.push(scriptHash);
				return {
					error: false,
					data: { id: 1, jsonrpc: '2.0', result: null },
					id: 1,
					method: 'subscribeAddress'
				};
			}
		);
		refreshSpy = sinon.spy();
		electrum = createElectrum(refreshSpy);
	});

	afterEach(async () => {
		for (const instance of createdInstances) {
			await instance.disconnect();
		}
		createdInstances.length = 0;
		sinon.restore();
	});

	it('routes each notification to the callback registered for its hash', async () => {
		const cbA = sinon.spy();
		const cbB = sinon.spy();
		await electrum.subscribeToAddresses({
			scriptHashes: ['aaaa'],
			onReceive: cbA
		});
		await electrum.subscribeToAddresses({
			scriptHashes: ['bbbb'],
			onReceive: cbB
		});

		await fireNotification(['bbbb', 'status1']);

		expect(cbB.calledOnce, 'second subscriber must receive its own hash').to.be
			.true;
		expect(cbB.firstCall.args[0]).to.deep.equal(['bbbb', 'status1']);
		expect(cbA.notCalled, 'first subscriber must not see another hash').to.be
			.true;
	});

	it('honours a second callback for an already-subscribed hash', async () => {
		const cb1 = sinon.spy();
		const cb2 = sinon.spy();
		await electrum.subscribeToAddresses({
			scriptHashes: ['cccc'],
			onReceive: cb1
		});
		// The client answers this one "Already Subscribed." — the callback
		// must still be wired.
		await electrum.subscribeToAddresses({
			scriptHashes: ['cccc'],
			onReceive: cb2
		});

		await fireNotification(['cccc', 'status2']);

		expect(cb1.calledOnce).to.be.true;
		expect(cb2.calledOnce).to.be.true;
	});

	it('still refreshes the wallet on every notification', async () => {
		const cb = sinon.spy();
		await electrum.subscribeToAddresses({
			scriptHashes: ['dddd'],
			onReceive: cb
		});
		// Wallet-style subscription: no onReceive at all.
		await electrum.subscribeToAddresses({ scriptHashes: ['eeee'] });

		await fireNotification(['dddd', 's1']);
		await fireNotification(['eeee', 's2']);

		expect(cb.calledOnce).to.be.true;
		expect(refreshSpy.callCount).to.equal(2);
	});

	it('rescans a tracked UTXO index before refreshing on its notification', async () => {
		const getUtxosSpy = sinon.stub().resolves(undefined);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(electrum as any).getUtxos = getUtxosSpy;
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(electrum.wallet as any).data.utxos = [{ scriptHash: 'ffff', index: 3 }];

		// No script hashes provided: the wallet path subscribes its UTXOs.
		await electrum.subscribeToAddresses({});
		expect(subscribedHashes).to.include('ffff');

		await fireNotification(['ffff', 's']);

		expect(getUtxosSpy.calledOnce).to.be.true;
		expect(getUtxosSpy.firstCall.args[0]).to.deep.include({
			scanningStrategy: EScanningStrategy.singleIndex,
			addressIndex: 3,
			changeAddressIndex: 3
		});
		expect(getUtxosSpy.calledBefore(refreshSpy)).to.be.true;
	});

	it('removeScriptHashCallback detaches one callback and leaves siblings', async () => {
		const cb1 = sinon.spy();
		const cb2 = sinon.spy();
		await electrum.subscribeToAddresses({
			scriptHashes: ['abcd'],
			onReceive: cb1
		});
		await electrum.subscribeToAddresses({
			scriptHashes: ['abcd'],
			onReceive: cb2
		});

		const removed = electrum.removeScriptHashCallback({
			scriptHash: 'abcd',
			onReceive: cb1
		});
		expect(removed).to.be.true;

		await fireNotification(['abcd', 's']);

		expect(cb1.notCalled).to.be.true;
		expect(cb2.calledOnce).to.be.true;
		expect(refreshSpy.calledOnce).to.be.true;
	});

	it('routes across two instances on the same network', async () => {
		// The client keeps one handler per network for the whole PROCESS, so
		// the registry and dispatcher must be shared per network: an
		// instance-local router would strand every instance but the first.
		const refreshB = sinon.spy();
		const electrumB = createElectrum(refreshB);
		const cbA = sinon.spy();
		const cbB = sinon.spy();
		await electrum.subscribeToAddresses({
			scriptHashes: ['11aa'],
			onReceive: cbA
		});
		await electrumB.subscribeToAddresses({
			scriptHashes: ['22bb'],
			onReceive: cbB
		});

		await fireNotification(['22bb', 's1']);
		expect(cbB.calledOnce, "the second instance's callback fires").to.be.true;
		expect(refreshB.calledOnce, 'the second instance refreshes').to.be.true;
		expect(cbA.notCalled).to.be.true;
		expect(refreshSpy.notCalled, 'the first instance does not refresh').to.be
			.true;

		await fireNotification(['11aa', 's2']);
		expect(cbA.calledOnce).to.be.true;
		expect(refreshSpy.calledOnce).to.be.true;
		expect(cbB.calledOnce).to.be.true;
		expect(refreshB.calledOnce).to.be.true;
	});

	it('rolls back a callback whose subscription failed', async () => {
		// A caller that retries a failed subscription with a fresh closure
		// must not leave the failed attempt's callback receiving
		// notifications alongside its successor.
		const cb1 = sinon.spy();
		const cb2 = sinon.spy();
		failNextSubscribes = 1;
		const failed = await electrum.subscribeToAddresses({
			scriptHashes: ['33cc'],
			onReceive: cb1
		});
		expect(failed.isErr()).to.be.true;
		const retried = await electrum.subscribeToAddresses({
			scriptHashes: ['33cc'],
			onReceive: cb2
		});
		expect(retried.isErr()).to.be.false;

		await fireNotification(['33cc', 's']);
		expect(cb1.notCalled, 'the failed attempt left no callback').to.be.true;
		expect(cb2.calledOnce).to.be.true;
	});

	describe('ElectrumBackend fan-out over a shared funding script', () => {
		let backend: ElectrumBackend;

		beforeEach(() => {
			backend = new ElectrumBackend(electrum);
		});

		it('delivers one change to both the confirmation and the spend watcher', async () => {
			// watchFundingOutput and watchFundingSpend subscribe the same
			// funding script with different callbacks.
			const confirmationWatch = sinon.spy();
			const spendWatch = sinon.spy();
			await backend.subscribeToScriptHash('f00d', confirmationWatch);
			await backend.subscribeToScriptHash('f00d', spendWatch);

			await fireNotification(['f00d', 's1']);

			expect(confirmationWatch.calledOnce).to.be.true;
			expect(spendWatch.calledOnce).to.be.true;
		});

		it('does not duplicate deliveries after repeated resubscribeAll', async () => {
			const cb = sinon.spy();
			await backend.subscribeToScriptHash('beef', cb);

			// Reconnect: the client loses its per-network state.
			globalHandler = null;
			subscribedHashes = [];
			await backend.resubscribeAll();
			await backend.resubscribeAll();
			expect(subscribedHashes).to.deep.equal(['beef']);

			await fireNotification(['beef', 's1']);
			expect(cb.callCount).to.equal(1);
		});

		it('rolls back a backend callback whose subscribe attempt failed', async () => {
			// ChainWatcher retries a failed subscription with a fresh closure;
			// the failed attempt's callback must not fire alongside it.
			const stale = sinon.spy();
			const fresh = sinon.spy();
			failNextSubscribes = 1;
			let threw = false;
			try {
				await backend.subscribeToScriptHash('44dd', stale);
			} catch {
				threw = true;
			}
			expect(threw, 'the failed subscribe propagates').to.be.true;
			await backend.subscribeToScriptHash('44dd', fresh);

			await fireNotification(['44dd', 's']);
			expect(stale.notCalled, 'the failed attempt left no callback').to.be.true;
			expect(fresh.calledOnce).to.be.true;
		});

		it('rolls back a backend callback whose subscribe attempt timed out', async () => {
			const timedOut = sinon.spy();
			const fresh = sinon.spy();
			const impatient = new ElectrumBackend(electrum, 50);
			hangNextSubscribes = 1;
			let threw = false;
			try {
				await impatient.subscribeToScriptHash('55ee', timedOut);
			} catch {
				threw = true;
			}
			expect(threw, 'the timeout propagates').to.be.true;
			await impatient.subscribeToScriptHash('55ee', fresh);

			await fireNotification(['55ee', 's']);
			expect(timedOut.notCalled, 'the timed-out attempt left no callback').to.be
				.true;
			expect(fresh.calledOnce).to.be.true;
		});

		it('unsubscribeScriptHash stops delivery and future resubscription', async () => {
			const cb = sinon.spy();
			await backend.subscribeToScriptHash('dead', cb);
			expect(backend.unsubscribeScriptHash('dead')).to.be.true;

			await fireNotification(['dead', 's1']);
			expect(cb.notCalled).to.be.true;

			globalHandler = null;
			subscribedHashes = [];
			await backend.resubscribeAll();
			expect(subscribedHashes).to.not.include('dead');
		});
	});
});

/**
 * Issue #501 (and its duplicate #505): the script hash dispatcher iterated a
 * snapshot of the ENTRIES and never re-read the map, so an instance that
 * disconnected while an earlier entry was parked in getUtxos still had its
 * callbacks fired and its wallet refreshed. The header dispatcher already
 * re-read its handler at the moment of the call; this is its sibling.
 *
 * Issue #502: a stopped instance answers every subscribe with the disconnected
 * refusal by design, and ElectrumBackend's reconnect monitor could not tell
 * that apart from a server failure. It counted the refusal toward
 * onFailoverNeeded, whose handler calls connectToElectrum and puts the stopped
 * wallet fully back on the network.
 */
describe('Electrum dispatch and monitor against a stopped instance', () => {
	let refreshSpy: sinon.SinonStub;
	let electrum: Electrum;

	beforeEach(() => {
		globalHandler = null;
		subscribedHashes = [];
		failNextSubscribes = 0;
		hangNextSubscribes = 0;
		sinon.stub(electrumHelpers, 'subscribeAddress').callsFake(
			async ({
				scriptHash = '',
				onReceive = undefined
			}: {
				scriptHash?: string;
				onReceive?: (data: TNotification) => void;
			} = {}) => {
				if (onReceive && !globalHandler) globalHandler = onReceive;
				if (subscribedHashes.includes(scriptHash)) {
					return { error: false, data: 'Already Subscribed.' };
				}
				subscribedHashes.push(scriptHash);
				return { error: false, data: { id: 1, jsonrpc: '2.0', result: null } };
			}
		);
		refreshSpy = sinon.spy();
		electrum = createElectrum(refreshSpy);
	});

	afterEach(async () => {
		for (const instance of createdInstances) {
			await instance.disconnect();
		}
		createdInstances.length = 0;
		sinon.restore();
	});

	it('does not refresh a wallet that disconnects mid-dispatch (#501)', async () => {
		const refreshB = sinon.spy();
		const electrumB = createElectrum(refreshB);
		const cbB = sinon.spy();

		// Both instances subscribe the SAME hash, and the first tracks a UTXO
		// on it, so its entry parks the dispatch inside getUtxos.
		let release = (): void => {};
		const parked = new Promise<void>((resolve) => {
			release = (): void => resolve();
		});
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(electrum as any).getUtxos = async (): Promise<void> => parked;
		await electrum.subscribeToAddresses({
			scriptHashes: ['abab'],
			onReceive: sinon.spy()
		});
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(electrum as any)._scriptHashRecord('abab').utxoIndex = 0;
		await electrumB.subscribeToAddresses({
			scriptHashes: ['abab'],
			onReceive: cbB
		});

		const dispatched = fireNotification(['abab', 's1']);
		await new Promise((resolve) => setTimeout(resolve, 0));
		await electrumB.disconnect();
		release();
		await dispatched;

		expect(
			refreshB.called,
			'a wallet that shut down must not be refreshed'
		).to.equal(false);
		expect(cbB.called, 'and its callback must not be called either').to.equal(
			false
		);
	});

	it('lets the reconnect monitor tick past a stopped instance (#502)', async () => {
		const backend = new ElectrumBackend(electrum);
		let failovers = 0;
		backend.onFailoverNeeded = (): void => {
			failovers++;
		};
		await electrum.disconnect();

		// The monitor's tick pings with subscribeToHeader, which a stopped
		// instance refuses by design. Three of those used to reach the default
		// failover threshold and reconnect the wallet.
		const tick = async (): Promise<void> => {
			backend.startReconnectMonitor(10);
			await new Promise((resolve) => setTimeout(resolve, 40));
			backend.stopReconnectMonitor();
		};
		await tick();

		expect(
			backend.getConsecutiveFailures(),
			'a refusal by design is not a server failure'
		).to.equal(0);
		expect(failovers, 'and must not drive a failover').to.equal(0);
		expect(
			electrum.isDisconnected,
			'the stopped instance stays stopped'
		).to.equal(true);
	});
});
