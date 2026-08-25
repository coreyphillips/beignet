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
 * And for issue #485: reconnecting to the SAME server after its socket died
 * loses every subscription too, because the client pings that peer inside
 * start() and, on failure, runs its own disconnect (clearing the same
 * bookkeeping) before building a replacement client. Nothing about that is
 * observable to the teardown above, so the restore after a successful connect
 * is unconditional.
 *
 * And for issue #494: the public subscribeToHeader/subscribeToAddresses did not
 * check the disconnected flag, so a caller that outlived disconnect() (an
 * ElectrumBackend reconnect monitor still ticking after wallet.stop()) put the
 * stopped instance straight back into the shared routers.
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
/** Per-call control over blockchain.headers.subscribe, keyed by call index, so
 *  a test can decide the order two concurrent subscribes resolve in and which
 *  of them fails. */
let headerSubscribeControls: Map<
	number,
	{ gate: { promise: Promise<void>; release: () => void }; fails: boolean }
>;
let headerSubscribeCalls: number;
/** Held open to keep a subscription request in flight for as long as a test
 *  needs, so a disconnect can land in the middle of one. */
let subscriptionGate: { promise: Promise<void>; release: () => void } | null;
/** Hosts the fake connection layer accepts; anything else refuses to connect,
 *  including the hardcoded fallback peers the rotation falls through to. */
let reachableHosts: Set<string>;
/** Models a close() that throws: the client reports { error: true } and keeps
 *  every bit of its per-network state, peer included. */
let disconnectFails: boolean;
/** Models a dead socket on the connected peer: the next connect to that same
 *  peer finds the client's own ping failing. Consumed on use, because the
 *  replacement client the reset leaves behind is alive. */
let socketIsDead: boolean;
/** Confirmed balance the stubbed script hash lookup answers with. */
const stubbedBalance = { confirmed: 4321, unconfirmed: 0 };

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
				let sameServer =
					client.peer?.host === server.host &&
					client.peer?.port === port &&
					client.peer?.protocol === protocol;
				if (sameServer && socketIsDead) {
					// The client pings the peer it believes it is connected to and,
					// when that fails, runs its own disconnect, which clears every
					// bit of the per-network state, before building a replacement
					// client for the very same server.
					socketIsDead = false;
					connectionEvents.push('self-disconnect');
					resetClient();
					sameServer = false;
				}
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
			const control = headerSubscribeControls.get(headerSubscribeCalls++);
			if (control) {
				await control.gate.promise;
				if (control.fails) {
					return { error: true, data: 'Subscription failed.' };
				}
			}
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

	sinon
		.stub(electrumHelpers, 'getAddressScriptHashBalance')
		.callsFake(async () => ({ error: false, data: stubbedBalance }));

	// The poll's health check: healthy for exactly as long as a peer is connected.
	sinon.stub(electrumHelpers, 'pingServer').callsFake(async () => ({
		error: !client.peer,
		data: client.peer ? 'pong' : 'Not connected.'
	}));
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

/** One pass of the connection poll, driven by hand so the tests keep their
 *  timing. */
const pollConnection = async (instance: Electrum): Promise<void> => {
	await (
		instance as unknown as { checkConnection: () => Promise<void> }
	).checkConnection();
};

/** Lets the fire-and-forget post-connect subscriptions settle. */
const flush = async (): Promise<void> => {
	for (let i = 0; i < 5; i++) {
		await new Promise((resolve) => setTimeout(resolve, 0));
	}
};

let electrum: Electrum;
let refreshSpy: sinon.SinonStub;
let messageSpy: sinon.SinonStub;

const startTest = (): void => {
	resetClient();
	protocolSubscribes = [];
	connectionEvents = [];
	nextHeaderHeight = 100;
	subscriptionFailures = new Set();
	subscriptionGate = null;
	headerSubscribeControls = new Map();
	headerSubscribeCalls = 0;
	reachableHosts = new Set([serverA.host, serverB.host]);
	disconnectFails = false;
	socketIsDead = false;
	storedHeader = { height: 0, hash: '', hex: '' };
	stubHelpers();
	refreshSpy = sinon.spy();
	messageSpy = sinon.spy();
	electrum = createElectrum(refreshSpy, messageSpy);
};

const endTest = async (): Promise<void> => {
	disconnectFails = false;
	socketIsDead = false;
	subscriptionGate?.release();
	subscriptionGate = null;
	for (const control of headerSubscribeControls.values()) {
		control.gate.release();
	}
	headerSubscribeControls.clear();
	for (const instance of createdInstances) {
		await instance.disconnect();
	}
	createdInstances.length = 0;
	sinon.restore();
};

describe('Electrum failover to a different server (issue #482)', () => {
	beforeEach(startTest);
	afterEach(endTest);

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

describe('Electrum reconnect to the same server after a dead socket (issue #485)', () => {
	beforeEach(startTest);
	afterEach(endTest);

	it('re-issues tracked script hash subscriptions the client reset', async () => {
		const onReceive = sinon.spy();
		await electrum.connectToElectrum({ servers: serverA });
		await flush();
		await electrum.subscribeToAddresses({ scriptHashes: ['aaaa'], onReceive });
		expect(protocolSubscribes).to.include('aaaa');

		socketIsDead = true;
		protocolSubscribes = [];
		connectionEvents = [];
		const reconnected = await electrum.connectToElectrum({ servers: serverA });
		expect(reconnected.isOk()).to.equal(true);
		await flush();

		expect(
			connectionEvents,
			'the client tore itself down without the server changing'
		).to.include('self-disconnect');
		expect(
			protocolSubscribes,
			'blockchain.scripthash.subscribe must reach the replacement client'
		).to.include('aaaa');
		expect(
			client.addressHandler,
			'the replacement client needs a script hash handler'
		).to.not.equal(null);
		await client.addressHandler?.(['aaaa', 'status-after-reconnect']);
		expect(onReceive.calledOnce, 'the callback must still be reached').to.equal(
			true
		);
	});

	it("re-subscribes the wallet's own addresses", async () => {
		await electrum.connectToElectrum({ servers: serverA });
		await flush();
		await electrum.subscribeToAddresses({});
		expect(protocolSubscribes).to.include(walletScriptHash);

		socketIsDead = true;
		protocolSubscribes = [];
		await electrum.connectToElectrum({ servers: serverA });
		await flush();

		expect(
			protocolSubscribes,
			'wallet addresses must be re-subscribed on the replacement client'
		).to.include(walletScriptHash);
	});

	it('restores through the reconnect guard on an Electrum call', async () => {
		const onReceive = sinon.spy();
		await electrum.connectToElectrum({ servers: serverA });
		await flush();
		await electrum.subscribeToAddresses({ scriptHashes: ['aaaa'], onReceive });

		// What the poll leaves behind when it notices the connection is gone:
		// the next Electrum call reconnects through its own guard, which is the
		// path that used to restore nothing at all.
		electrum.connectedToElectrum = false;
		socketIsDead = true;
		protocolSubscribes = [];
		const balance = await electrum.getAddressBalance(walletScriptHash);
		await flush();

		expect(balance.error, 'the call itself still answers').to.equal(false);
		expect(balance.confirmed).to.equal(stubbedBalance.confirmed);
		expect(
			protocolSubscribes,
			'the reconnect the call triggered must restore the subscriptions'
		).to.include('aaaa');
		expect(protocolSubscribes).to.include(walletScriptHash);
		expect(client.addressHandler).to.not.equal(null);
		await client.addressHandler?.(['aaaa', 'status-after-guard-reconnect']);
		expect(onReceive.calledOnce).to.equal(true);
	});

	it('retries a failed restore on a healthy connection poll', async () => {
		const onReceive = sinon.spy();
		await electrum.connectToElectrum({ servers: serverA });
		await flush();
		await electrum.subscribeToAddresses({ scriptHashes: ['aaaa'], onReceive });

		// The reconnect restores everything the dead socket cost, except that
		// one hash's re-subscribe errors. The replacement socket is healthy, so
		// no further connect is coming to try again.
		socketIsDead = true;
		subscriptionFailures.add('aaaa');
		protocolSubscribes = [];
		const reconnected = await electrum.connectToElectrum({ servers: serverA });
		expect(reconnected.isOk()).to.equal(true);
		await flush();
		expect(
			protocolSubscribes,
			'the restore of this hash failed'
		).to.not.include('aaaa');

		await pollConnection(electrum);
		await flush();

		expect(
			protocolSubscribes,
			'the poll must re-issue what the failed restore still owes'
		).to.include('aaaa');
		expect(client.addressHandler).to.not.equal(null);
		await client.addressHandler?.(['aaaa', 'status-after-poll-retry']);
		expect(onReceive.calledOnce, 'the callback must be reached again').to.equal(
			true
		);

		// And the debt is settled: a later healthy poll re-subscribes nothing.
		protocolSubscribes = [];
		await pollConnection(electrum);
		await flush();
		expect(protocolSubscribes).to.deep.equal([]);
	});

	it('keeps the header handler a concurrent subscribe installed', async () => {
		const otherMessageSpy = sinon.spy();
		const other = createElectrum(sinon.spy(), otherMessageSpy, 'cccc');
		const failing = { gate: createGate(), fails: true };
		const succeeding = { gate: createGate(), fails: false };
		headerSubscribeControls.set(0, failing);
		headerSubscribeControls.set(1, succeeding);

		// Two subscribes in flight at once, the second landing first.
		const first = other.subscribeToHeader();
		const second = other.subscribeToHeader();
		succeeding.gate.release();
		expect((await second).isOk()).to.equal(true);
		failing.gate.release();
		expect((await first).isErr()).to.equal(true);

		expect(
			client.headerHandler,
			'the successful subscribe wired a handler'
		).to.not.equal(null);
		await client.headerHandler?.([{ height: 512, hex: headerHex }]);
		await flush();

		const blocks = otherMessageSpy
			.getCalls()
			.filter(
				(call: { args: [string, { height: number }] }) =>
					call.args[0] === 'newBlock'
			);
		expect(
			blocks.length,
			'the failed attempt must not withdraw the live subscription'
		).to.equal(1);
		expect(blocks[0].args[1].height).to.equal(512);
	});

	it('withdraws the header handler when every subscribe fails', async () => {
		const otherMessageSpy = sinon.spy();
		const other = createElectrum(sinon.spy(), otherMessageSpy, 'cccc');
		const failing = { gate: createGate(), fails: true };
		failing.gate.release();
		headerSubscribeControls.set(0, failing);

		expect((await other.subscribeToHeader()).isErr()).to.equal(true);

		// Nothing is subscribed, so the handler this attempt installed has to go
		// with it rather than linger on the shared router.
		await electrum.connectToElectrum({ servers: serverA });
		await flush();
		await client.headerHandler?.([{ height: 640, hex: headerHex }]);
		await flush();

		const blocks = otherMessageSpy
			.getCalls()
			.filter(
				(call: { args: [string, { height: number }] }) =>
					call.args[0] === 'newBlock'
			);
		expect(blocks.length, 'the rolled back handler must stay gone').to.equal(0);
	});
});

describe('Electrum subscriptions after disconnect (issue #494)', () => {
	beforeEach(startTest);
	afterEach(endTest);

	it('refuses a header subscribe from a stopped instance', async () => {
		const otherMessageSpy = sinon.spy();
		const other = createElectrum(sinon.spy(), otherMessageSpy, 'eeee');
		await electrum.connectToElectrum({ servers: serverA });
		await flush();

		// The wallet stops, and a reconnect monitor that was mid-tick pings on
		// with the instance it still holds while another one keeps the network's
		// headers wired.
		await electrum.disconnect();
		await other.connectToElectrum({ servers: serverA });
		await flush();

		const late = await electrum.subscribeToHeader();

		expect(client.headerHandler).to.not.equal(null);
		await client.headerHandler?.([{ height: 700, hex: headerHex }]);
		await flush();

		const ownBlocks = messageSpy
			.getCalls()
			.filter(
				(call: { args: [string, { height: number }] }) =>
					call.args[0] === 'newBlock'
			);
		expect(
			ownBlocks.length,
			'a stopped wallet must not be refreshed by a new block'
		).to.equal(0);
		const otherBlocks = otherMessageSpy
			.getCalls()
			.filter(
				(call: { args: [string, { height: number }] }) =>
					call.args[0] === 'newBlock'
			);
		expect(
			otherBlocks.length,
			'the live instance still receives them'
		).to.equal(1);
		expect(late.isErr(), 'a stopped instance cannot subscribe').to.equal(true);
	});

	it('refuses a script hash subscribe from a stopped instance', async () => {
		const onReceive = sinon.spy();
		const other = createElectrum(sinon.spy(), sinon.spy(), 'eeee');
		await electrum.connectToElectrum({ servers: serverA });
		await flush();
		await electrum.subscribeToAddresses({ scriptHashes: ['aaaa'], onReceive });

		await electrum.disconnect();
		await other.connectToElectrum({ servers: serverA });
		await flush();

		refreshSpy.resetHistory();
		const late = await electrum.subscribeToAddresses({
			scriptHashes: ['aaaa'],
			onReceive
		});

		expect(client.addressHandler).to.not.equal(null);
		await client.addressHandler?.(['aaaa', 'status-after-stop']);
		await flush();

		expect(
			onReceive.called,
			'a stopped wallet must not be called back'
		).to.equal(false);
		expect(refreshSpy.called, 'nor refreshed by the notification').to.equal(
			false
		);
		expect(late.isErr(), 'a stopped instance cannot subscribe').to.equal(true);
	});

	it('leaves a header subscribe the disconnect outran unwired', async () => {
		const other = createElectrum(sinon.spy(), sinon.spy(), 'cccc');
		const gate = { gate: createGate(), fails: false };
		headerSubscribeControls.set(0, gate);

		const pending = other.subscribeToHeader();
		await other.disconnect();
		gate.gate.release();

		expect(
			(await pending).isErr(),
			'the subscribe the disconnect outran must not report success'
		).to.equal(true);
		expect(
			storedHeader.height,
			'nor write the header into a stopped wallet'
		).to.equal(0);
	});

	it('subscribes again once the instance reconnects', async () => {
		const onReceive = sinon.spy();
		await electrum.connectToElectrum({ servers: serverA });
		await flush();
		await electrum.disconnect();

		expect((await electrum.subscribeToHeader()).isErr()).to.equal(true);

		const reconnected = await electrum.connectToElectrum({ servers: serverA });
		expect(reconnected.isOk()).to.equal(true);
		await flush();

		expect((await electrum.subscribeToHeader()).isOk()).to.equal(true);
		const subscribed = await electrum.subscribeToAddresses({
			scriptHashes: ['aaaa'],
			onReceive
		});
		expect(subscribed.isOk()).to.equal(true);
		expect(client.addressHandler).to.not.equal(null);
		await client.addressHandler?.(['aaaa', 'status-after-revival']);
		expect(onReceive.calledOnce, 'the revived instance is wired').to.equal(
			true
		);
	});
});
