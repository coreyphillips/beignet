/**
 * Regression tests for issue #482: reconnecting to a DIFFERENT Electrum server
 * kept the client's per-network subscription bookkeeping. rn-electrum-client
 * builds a fresh client whenever the target host/port/protocol differ, but only
 * its disconnect path clears subscribedAddresses/subscribedHeaders/
 * onAddressReceive, while the notification handlers live on the client object
 * that is thrown away. Every subscribe after a failover therefore answered
 * "Already Subscribed." although nothing was subscribed on the new connection,
 * so the process received no header and no script hash notifications. The fix
 * stops the current peer before connecting to a different one.
 *
 * Fully OFFLINE: the client helpers are stubbed with a faithful model of that
 * per-network state, including the upstream asymmetry (a server swap drops the
 * handlers but keeps the bookkeeping), and notifications are fired by invoking
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
	EAddressType,
	EAvailableNetworks,
	Electrum,
	EProtocol,
	err,
	IHeader,
	TServer,
	Wallet
} from '../src';

type TNotification = [string, string];
type TPeer = { host: string; port: number; protocol: string };

const serverA: TServer = {
	host: 'a.example.com',
	ssl: 50002,
	tcp: 50001,
	protocol: EProtocol.ssl
};
const serverB: TServer = {
	host: 'b.example.com',
	ssl: 50002,
	tcp: 50001,
	protocol: EProtocol.ssl
};

/** A parseable, deliberately meaningless 80 byte block header. */
const headerHex = '00'.repeat(80);
/** Script hash of the wallet's own receiving address. */
const walletScriptHash = 'ffff';

/** The state rn-electrum-client keeps per network. */
const client: {
	peer: TPeer | null;
	subscribedHeaders: boolean;
	subscribedHashes: string[];
	headerHandler: ((data: unknown[]) => void | Promise<void>) | null;
	addressHandler: ((data: TNotification) => void | Promise<void>) | null;
} = {
	peer: null,
	subscribedHeaders: false,
	subscribedHashes: [],
	headerHandler: null,
	addressHandler: null
};

/** Every subscription actually sent to a server ('headers' or a script hash). */
let protocolSubscribes: string[];
/** Connect/disconnect calls in order, to pin the disconnect-before-connect. */
let connectionEvents: string[];
/** Height the next header subscription reports, so the servers differ. */
let nextHeaderHeight: number;
/** Script hashes whose next subscription request should fail. */
let subscriptionFailures: Set<string>;
/** Held open to keep a subscription request in flight for as long as a test
 *  needs, so a disconnect can land in the middle of one. */
let subscriptionGate: { promise: Promise<void>; release: () => void } | null;
/** Hosts the fake connection layer accepts; anything else refuses to connect,
 *  including the hardcoded fallback peers the rotation falls through to. */
let reachableHosts: Set<string>;
/** Models a close() that throws: the client reports { error: true } and keeps
 *  every bit of its per-network state, peer included. */
let disconnectFails: boolean;

const createGate = (): { promise: Promise<void>; release: () => void } => {
	let release = (): void => {};
	const promise = new Promise<void>((resolve) => {
		release = (): void => resolve();
	});
	return { promise, release };
};

const resetClient = (): void => {
	client.peer = null;
	client.subscribedHeaders = false;
	client.subscribedHashes = [];
	client.headerHandler = null;
	client.addressHandler = null;
};

const stubHelpers = (): void => {
	sinon
		.stub(electrumHelpers, 'start')
		.callsFake(
			async ({
				network,
				customPeers
			}: {
				network: string;
				customPeers: TServer[];
			}) => {
				const server = customPeers[0];
				const protocol = server.protocol;
				const port = protocol === EProtocol.ssl ? server.ssl : server.tcp;
				if (!reachableHosts.has(server.host)) {
					connectionEvents.push(`refused:${server.host}`);
					return {
						error: true,
						data: 'Unable to connect to Electrum server.',
						network
					};
				}
				connectionEvents.push(`connect:${server.host}`);
				const sameServer =
					client.peer?.host === server.host &&
					client.peer?.port === port &&
					client.peer?.protocol === protocol;
				if (!sameServer) {
					// A brand new client object: the emitter carrying the subscription
					// handlers is gone, while the per-network bookkeeping survives.
					client.headerHandler = null;
					client.addressHandler = null;
					client.peer = { host: server.host, port, protocol };
				}
				return { error: false, data: client.peer, network };
			}
		);

	sinon
		.stub(electrumHelpers, 'stop')
		.callsFake(async ({ network }: { network?: string } = {}) => {
			if (disconnectFails) {
				// close() threw: the client returns before it clears any of the
				// per-network state, so the peer and the bookkeeping both survive.
				connectionEvents.push('disconnect-failed');
				return { error: true, data: 'socket hang up', network };
			}
			connectionEvents.push('disconnect');
			resetClient();
			return { error: false, data: 'Disconnected...', network };
		});

	sinon
		.stub(electrumHelpers, 'getConnectedPeer')
		.callsFake(() => client.peer ?? '');

	sinon.stub(electrumHelpers, 'subscribeHeader').callsFake(
		async ({
			onReceive
		}: {
			onReceive?: (data: unknown[]) => void;
		} = {}) => {
			if (client.subscribedHeaders) {
				return { error: false, data: 'Already Subscribed.' };
			}
			if (onReceive) client.headerHandler = onReceive;
			client.subscribedHeaders = true;
			protocolSubscribes.push('headers');
			return {
				error: false,
				data: { height: nextHeaderHeight, hex: headerHex }
			};
		}
	);

	sinon.stub(electrumHelpers, 'subscribeAddress').callsFake(
		async ({
			scriptHash = '',
			onReceive = undefined
		}: {
			scriptHash?: string;
			onReceive?: (data: TNotification) => void;
		} = {}) => {
			if (subscriptionGate) await subscriptionGate.promise;
			if (subscriptionFailures.delete(scriptHash)) {
				return { error: true, data: 'Subscription failed.' };
			}
			// One handler per network: the first onReceive it is handed wins.
			if (onReceive && !client.addressHandler) {
				client.addressHandler = onReceive;
			}
			if (client.subscribedHashes.includes(scriptHash)) {
				return { error: false, data: 'Already Subscribed.' };
			}
			client.subscribedHashes.push(scriptHash);
			protocolSubscribes.push(scriptHash);
			return { error: false, data: { id: 1, jsonrpc: '2.0', result: null } };
		}
	);
};

/** The wallet's stored header, updated by the header subscription. */
let storedHeader: IHeader;

const createFakeWallet = (
	refreshSpy: sinon.SinonStub,
	messageSpy: sinon.SinonStub,
	scriptHash: string = walletScriptHash
): Wallet => {
	return {
		sendMessage: messageSpy,
		isSwitchingNetworks: false,
		refreshWallet: refreshSpy,
		updateHeader: async (header: IHeader): Promise<void> => {
			storedHeader = header;
		},
		checkUnconfirmedTransactions: async (): Promise<void> => {},
		addressTypesToMonitor: [EAddressType.p2wpkh],
		gapLimitOptions: {
			lookAhead: 2,
			lookBehind: 2,
			lookAheadChange: 2,
			lookBehindChange: 2
		},
		get data() {
			return {
				utxos: [],
				header: storedHeader,
				addresses: {
					[EAddressType.p2wpkh]: {
						'0': { index: 0, scriptHash }
					}
				},
				addressIndex: { [EAddressType.p2wpkh]: { index: 0 } }
			};
		}
	} as unknown as Wallet;
};

/** Instances created this test, withdrawn from the shared per-network script
 *  hash router in afterEach so no test leaks subscriptions into the next. */
const createdInstances: Electrum[] = [];

const createElectrum = (
	refreshSpy: sinon.SinonStub,
	messageSpy: sinon.SinonStub,
	scriptHash: string = walletScriptHash
): Electrum => {
	const electrum = new Electrum({
		wallet: createFakeWallet(refreshSpy, messageSpy, scriptHash),
		network: EAvailableNetworks.testnet,
		net,
		tls,
		servers: [serverA]
	});
	// No background pings during tests.
	electrum.stopConnectionPolling();
	createdInstances.push(electrum);
	return electrum;
};

/** Lets the fire-and-forget post-connect subscriptions settle. */
const flush = async (): Promise<void> => {
	for (let i = 0; i < 5; i++) {
		await new Promise((resolve) => setTimeout(resolve, 0));
	}
};

describe('Electrum failover to a different server (issue #482)', () => {
	let electrum: Electrum;
	let refreshSpy: sinon.SinonStub;
	let messageSpy: sinon.SinonStub;

	beforeEach(() => {
		resetClient();
		protocolSubscribes = [];
		connectionEvents = [];
		nextHeaderHeight = 100;
		subscriptionFailures = new Set();
		subscriptionGate = null;
		reachableHosts = new Set([serverA.host, serverB.host]);
		disconnectFails = false;
		storedHeader = { height: 0, hash: '', hex: '' };
		stubHelpers();
		refreshSpy = sinon.spy();
		messageSpy = sinon.spy();
		electrum = createElectrum(refreshSpy, messageSpy);
	});

	afterEach(async () => {
		disconnectFails = false;
		subscriptionGate?.release();
		subscriptionGate = null;
		for (const instance of createdInstances) {
			await instance.disconnect();
		}
		createdInstances.length = 0;
		sinon.restore();
	});

	it('disconnects the old peer before connecting to a different server', async () => {
		const connected = await electrum.connectToElectrum({ servers: serverA });
		expect(connected.isOk()).to.equal(true);
		await flush();

		const swapped = await electrum.connectToElectrum({ servers: serverB });
		expect(swapped.isOk()).to.equal(true);
		await flush();

		expect(connectionEvents).to.deep.equal([
			`connect:${serverA.host}`,
			'disconnect',
			`connect:${serverB.host}`
		]);
	});

	it('re-issues the header subscription to the new server', async () => {
		await electrum.connectToElectrum({ servers: serverA });
		await flush();
		expect(protocolSubscribes).to.include('headers');

		protocolSubscribes = [];
		nextHeaderHeight = 250;
		await electrum.connectToElectrum({ servers: serverB });
		await flush();

		expect(
			protocolSubscribes,
			'blockchain.headers.subscribe must reach the new server'
		).to.include('headers');
		expect(
			client.headerHandler,
			'a header handler must be wired to the new client'
		).to.not.equal(null);
		expect(
			storedHeader.height,
			'the header must come from the new server, not local storage'
		).to.equal(250);
	});

	it('delivers header notifications from the new server', async () => {
		await electrum.connectToElectrum({ servers: serverA });
		await flush();
		await electrum.connectToElectrum({ servers: serverB });
		await flush();

		expect(client.headerHandler).to.not.equal(null);
		await client.headerHandler?.([{ height: 300, hex: headerHex }]);
		await flush();

		const newBlocks = messageSpy
			.getCalls()
			.filter(
				(call: { args: [string, { height: number }] }) =>
					call.args[0] === 'newBlock'
			);
		expect(newBlocks.length, 'the new block must reach the wallet').to.equal(1);
		expect(newBlocks[0].args[1].height).to.equal(300);
	});

	it('re-issues tracked script hash subscriptions to the new server', async () => {
		const onReceive = sinon.spy();
		await electrum.connectToElectrum({ servers: serverA });
		await flush();
		const subscribed = await electrum.subscribeToAddresses({
			scriptHashes: ['aaaa'],
			onReceive
		});
		expect(subscribed.isOk()).to.equal(true);
		expect(protocolSubscribes).to.include('aaaa');

		protocolSubscribes = [];
		await electrum.connectToElectrum({ servers: serverB });
		await flush();

		// Models the lightning backend's resubscribeAll() after a failover.
		await electrum.subscribeToAddresses({ scriptHashes: ['aaaa'], onReceive });
		expect(
			protocolSubscribes,
			'blockchain.scripthash.subscribe must reach the new server'
		).to.include('aaaa');

		expect(
			client.addressHandler,
			'the new client needs a script hash handler'
		).to.not.equal(null);
		await client.addressHandler?.(['aaaa', 'status-after-failover']);
		expect(onReceive.calledOnce, 'the callback must still be reached').to.equal(
			true
		);
	});

	it("re-subscribes the wallet's own addresses after a server change", async () => {
		await electrum.connectToElectrum({ servers: serverA });
		await flush();
		await electrum.subscribeToAddresses({});
		expect(protocolSubscribes).to.include(walletScriptHash);

		protocolSubscribes = [];
		await electrum.connectToElectrum({ servers: serverB });
		await flush();

		expect(
			protocolSubscribes,
			'wallet addresses must be re-subscribed on the new server'
		).to.include(walletScriptHash);
	});

	it('restores subscriptions when a failed switch lands back on the same server', async () => {
		const onReceive = sinon.spy();
		await electrum.connectToElectrum({ servers: serverA });
		await flush();
		await electrum.subscribeToAddresses({ scriptHashes: ['aaaa'], onReceive });
		await electrum.subscribeToAddresses({});
		expect(protocolSubscribes).to.include(walletScriptHash);

		// The switch stops A and then reaches no server at all, so the client
		// state is gone while the connected server never changed.
		reachableHosts = new Set();
		const failed = await electrum.connectToElectrum({ servers: serverB });
		expect(failed.isErr()).to.equal(true);
		expect(client.peer, 'the old peer was torn down').to.equal(null);

		protocolSubscribes = [];
		reachableHosts = new Set([serverA.host]);
		const recovered = await electrum.connectToElectrum({ servers: serverA });
		expect(recovered.isOk()).to.equal(true);
		await flush();

		expect(
			protocolSubscribes,
			'the wallet addresses must be re-subscribed, same server or not'
		).to.include(walletScriptHash);
		expect(
			protocolSubscribes,
			'tracked script hashes must be re-subscribed too'
		).to.include('aaaa');
		expect(client.addressHandler).to.not.equal(null);
		await client.addressHandler?.(['aaaa', 'status-after-recovery']);
		expect(onReceive.calledOnce, 'the callback must still be reached').to.equal(
			true
		);
	});

	it('retries a failed subscription restore on the next connect', async () => {
		const onReceive = sinon.spy();
		await electrum.connectToElectrum({ servers: serverA });
		await flush();
		await electrum.subscribeToAddresses({ scriptHashes: ['aaaa'], onReceive });

		protocolSubscribes = [];
		subscriptionFailures.add('aaaa');
		const swapped = await electrum.connectToElectrum({ servers: serverB });
		expect(swapped.isOk()).to.equal(true);
		await flush();
		expect(protocolSubscribes).to.not.include('aaaa');

		protocolSubscribes = [];
		const recovered = await electrum.connectToElectrum({ servers: serverB });
		expect(recovered.isOk()).to.equal(true);
		await flush();

		expect(protocolSubscribes).to.include('aaaa');
		expect(client.addressHandler).to.not.equal(null);
		await client.addressHandler?.(['aaaa', 'status-after-retry']);
		expect(onReceive.calledOnce).to.equal(true);
	});

	it('retries when restoring wallet subscriptions returns an error', async () => {
		await electrum.connectToElectrum({ servers: serverA });
		await flush();
		await electrum.subscribeToAddresses({ scriptHashes: ['aaaa'] });

		const walletSubscriptions = sinon
			.stub(electrum, 'subscribeToAddresses')
			.callThrough();
		walletSubscriptions
			.onFirstCall()
			.resolves(err<string>('Wallet subscription failed.'));
		const subscribeAddress =
			electrumHelpers.subscribeAddress as sinon.SinonStub;

		const swapped = await electrum.connectToElectrum({ servers: serverB });
		expect(swapped.isOk()).to.equal(true);
		await flush();
		const failedRestoreCalls = subscribeAddress
			.getCalls()
			.filter(
				(call: { args: [{ scriptHash: string }] }) =>
					call.args[0].scriptHash === 'aaaa'
			).length;

		const recovered = await electrum.connectToElectrum({ servers: serverB });
		expect(recovered.isOk()).to.equal(true);
		await flush();

		const recoveredRestoreCalls = subscribeAddress
			.getCalls()
			.filter(
				(call: { args: [{ scriptHash: string }] }) =>
					call.args[0].scriptHash === 'aaaa'
			).length;
		expect(recoveredRestoreCalls).to.equal(failedRestoreCalls + 1);
	});

	it("restores another instance's subscriptions after a server change", async () => {
		const otherWalletScriptHash = 'eeee';
		const other = createElectrum(
			sinon.spy(),
			sinon.spy(),
			otherWalletScriptHash
		);
		const onReceive = sinon.spy();
		await electrum.connectToElectrum({ servers: serverA });
		await flush();
		await other.connectToElectrum({ servers: serverA });
		await flush();
		await other.subscribeToAddresses({ scriptHashes: ['bbbb'], onReceive });
		await other.subscribeToAddresses({});
		expect(protocolSubscribes).to.include('bbbb');

		protocolSubscribes = [];
		await electrum.connectToElectrum({ servers: serverB });
		await flush();

		// One client per network for the whole process: the instance that
		// switched servers dropped these subscriptions, so it owes them back.
		expect(
			protocolSubscribes,
			"another instance's tracked hashes must reach the new server"
		).to.include('bbbb');
		expect(
			protocolSubscribes,
			"another instance's wallet addresses must reach the new server"
		).to.include(otherWalletScriptHash);
		expect(client.addressHandler).to.not.equal(null);
		await client.addressHandler?.(['bbbb', 'status-after-failover']);
		expect(
			onReceive.calledOnce,
			"the other instance's callback must still be reached"
		).to.equal(true);
	});

	it("keeps another instance's headers flowing after a server change", async () => {
		const otherMessageSpy = sinon.spy();
		const other = createElectrum(sinon.spy(), otherMessageSpy, 'eeee');
		// The first subscriber owns the client's single header handler; every
		// later one is answered with "Already Subscribed."
		await other.connectToElectrum({ servers: serverA });
		await flush();
		await electrum.connectToElectrum({ servers: serverA });
		await flush();

		await electrum.connectToElectrum({ servers: serverB });
		await flush();

		expect(client.headerHandler).to.not.equal(null);
		await client.headerHandler?.([{ height: 400, hex: headerHex }]);
		await flush();

		const otherBlocks = otherMessageSpy
			.getCalls()
			.filter(
				(call: { args: [string, { height: number }] }) =>
					call.args[0] === 'newBlock'
			);
		expect(
			otherBlocks.length,
			'the instance that did not switch must keep receiving blocks'
		).to.equal(1);
		expect(otherBlocks[0].args[1].height).to.equal(400);
		const ownBlocks = messageSpy
			.getCalls()
			.filter(
				(call: { args: [string, { height: number }] }) =>
					call.args[0] === 'newBlock'
			);
		expect(
			ownBlocks.length,
			'and the switching one must not double up'
		).to.equal(1);
	});

	it('lets another instance discharge a restore a failed switch left owed', async () => {
		const onReceive = sinon.spy();
		const other = createElectrum(sinon.spy(), sinon.spy(), 'eeee');
		await electrum.connectToElectrum({ servers: serverA });
		await flush();
		await other.connectToElectrum({ servers: serverA });
		await flush();
		await other.subscribeToAddresses({ scriptHashes: ['bbbb'], onReceive });

		// This instance stops the peer and then reaches nothing at all, so it
		// gives up still owing the restore.
		reachableHosts = new Set();
		const failed = await electrum.connectToElectrum({ servers: serverB });
		expect(failed.isErr()).to.equal(true);
		expect(client.peer, 'the old peer was torn down').to.equal(null);

		protocolSubscribes = [];
		reachableHosts = new Set([serverA.host]);
		const recovered = await other.connectToElectrum({ servers: serverA });
		expect(recovered.isOk()).to.equal(true);
		await flush();

		// The client is shared per network, so the debt is the network's: any
		// instance that gets back on it has to settle it.
		expect(
			protocolSubscribes,
			'the reconnecting instance must restore what the other one reset'
		).to.include('bbbb');
		expect(client.addressHandler).to.not.equal(null);
		await client.addressHandler?.(['bbbb', 'status-after-recovery']);
		expect(onReceive.calledOnce).to.equal(true);
	});

	it('does not re-register a wallet that disconnects mid-restore', async () => {
		const otherRefresh = sinon.stub();
		const other = createElectrum(otherRefresh, sinon.spy(), 'eeee');
		await other.connectToElectrum({ servers: serverA });
		await flush();
		await other.subscribeToAddresses({ scriptHashes: ['bbbb'] });

		// Hold the restore's subscriptions open so the disconnect lands while
		// they are still in flight.
		const gate = createGate();
		subscriptionGate = gate;
		void other.connectToElectrum({ servers: serverB });
		await flush();

		await other.disconnect();
		subscriptionGate = null;
		gate.release();
		await flush();

		otherRefresh.resetHistory();
		expect(client.addressHandler).to.not.equal(null);
		await client.addressHandler?.(['bbbb', 'status-after-disconnect']);
		await flush();

		expect(
			otherRefresh.called,
			'a stopped wallet must not be refreshed by the restore it outlived'
		).to.equal(false);
	});

	it('refuses to switch servers when the disconnect fails', async () => {
		const onReceive = sinon.spy();
		await electrum.connectToElectrum({ servers: serverA });
		await flush();
		await electrum.subscribeToAddresses({ scriptHashes: ['aaaa'], onReceive });
		const handler = client.addressHandler;

		disconnectFails = true;
		protocolSubscribes = [];
		connectionEvents = [];
		const swapped = await electrum.connectToElectrum({ servers: serverB });
		await flush();

		expect(
			swapped.isErr(),
			'a switch onto stale client state must not report success'
		).to.equal(true);
		expect(
			connectionEvents.some((event) => event.startsWith('connect:')),
			'no replacement client may be built on stale bookkeeping'
		).to.equal(false);
		expect(client.peer?.host, 'the live peer is kept').to.equal(serverA.host);
		expect(
			client.addressHandler,
			'the surviving handler still routes notifications'
		).to.equal(handler);
		await client.addressHandler?.(['aaaa', 'status-after-refusal']);
		expect(onReceive.calledOnce).to.equal(true);
	});

	it('keeps the connection when reconnecting to the same server', async () => {
		await electrum.connectToElectrum({ servers: serverA });
		await flush();
		await electrum.subscribeToAddresses({
			scriptHashes: ['cccc'],
			onReceive: sinon.spy()
		});
		const handler = client.addressHandler;
		protocolSubscribes = [];
		connectionEvents = [];

		await electrum.connectToElectrum({ servers: serverA });
		await flush();

		expect(connectionEvents, 'a live peer must not be torn down').to.deep.equal(
			[`connect:${serverA.host}`]
		);
		expect(protocolSubscribes, 'nothing needs re-subscribing').to.deep.equal(
			[]
		);
		expect(client.subscribedHeaders).to.equal(true);
		expect(client.addressHandler).to.equal(handler);
	});
});
