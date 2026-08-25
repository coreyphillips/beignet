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
 * And for issue #487: when that teardown refused every candidate, the connect
 * still reported the wallet disconnected and adopted the target it never
 * reached, so the peer it had deliberately kept went on serving calls while
 * every guarded call retried the same doomed switch.
 *
 * And for issue #494: the public subscribeToHeader/subscribeToAddresses did not
 * check the disconnected flag, so a caller that outlived disconnect() (an
 * ElectrumBackend reconnect monitor still ticking after wallet.stop()) put the
 * stopped instance straight back into the shared routers.
 *
 * And for issue #496: the header a (re)subscribe answers with was written
 * straight to storage without the reorg check the notification path runs, so a
 * rollback that happened while this process was away lowered the stored height
 * unreconciled, and every notification after it, higher than what was written,
 * read as ordinary growth. Only one instance is ever handed that header, a
 * reconciliation that failed had to be owed rather than reported as a restore,
 * and a notification that overtook the response had to keep its place.
 *
 * Fully OFFLINE: the client helpers are stubbed with a faithful model of that
 * per-network state, including the upstream asymmetry (a server swap drops the
 * handlers but keeps the bookkeeping), and notifications are fired by invoking
 * the captured handler exactly as the client's emitter would.
 */

import { Block } from 'bitcoinjs-lib';
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
	ok,
	Result,
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

/**
 * One canonical chain of parseable 80 byte headers, indexed by height, each
 * carrying the id of the header below it. A single constant hex would give
 * every height the same block id, which is not a chain any parent check can
 * read: adjacent headers would neither link nor conflict.
 */
const chainHex: string[] = [];
const chainHash: string[] = [];
const buildChainTo = (height: number, fork = 0): void => {
	while (chainHex.length <= height) {
		const at = chainHex.length;
		const header = Buffer.alloc(80);
		header.writeUInt32LE(1, 0);
		if (at > 0) {
			Buffer.from(chainHash[at - 1], 'hex')
				.reverse()
				.copy(header, 4);
		}
		header.writeUInt32LE(at + fork, 76);
		const hex = header.toString('hex');
		chainHex.push(hex);
		chainHash.push(Block.fromHex(hex).getId());
	}
};
/** The header this chain holds at `height`. */
const headerHexAt = (height: number): string => {
	buildChainTo(height);
	return chainHex[height];
};
/** Its block id, which is what the wallet stores and compares. */
const headerHashAt = (height: number): string => {
	buildChainTo(height);
	return chainHash[height];
};
/** A DIFFERENT block at the same height, on a chain that forked below it: the
 *  shape of a reorg that replaces the tip without shortening the chain. */
const siblingHeaderHexAt = (height: number): string => {
	const header = Buffer.alloc(80);
	header.writeUInt32LE(1, 0);
	if (height > 0) {
		Buffer.from(headerHashAt(height - 1), 'hex')
			.reverse()
			.copy(header, 4);
	}
	header.writeUInt32LE(0xffffffff - height, 76);
	return header.toString('hex');
};
/** Script hash of the wallet's own receiving address. */
const walletScriptHash = 'ffff';

/** The state rn-electrum-client keeps per network. */
const client: {
	peer: TPeer | null;
	subscribedHeaders: boolean;
	subscribedHashes: string[];
	/** EVERY listener registered on the client's shared emitter for this
	 *  network, in order. An array rather than one slot because .on() appends:
	 *  a second registration is exactly the defect #507 reports, and a single
	 *  slot would silently overwrite it instead of showing it. */
	headerHandlers: Array<(data: unknown[]) => void | Promise<void>>;
	addressHandler: ((data: TNotification) => void | Promise<void>) | null;
} = {
	peer: null,
	subscribedHeaders: false,
	subscribedHashes: [],
	headerHandlers: [],
	addressHandler: null
};

/** Emits one header notification exactly as the client's emitter would: to
 *  every registered listener, in registration order. */
const fireHeader = async (height: number, hex?: string): Promise<void> => {
	// One payload object for every listener, which is what the emitter does:
	// it hands each of them the same parsed params. And every listener is
	// invoked SYNCHRONOUSLY, back to back, because EventEmitter.emit does not
	// await the promise an async listener returns. That is the whole point of
	// the dispatcher's identity guard, which is assigned before its first
	// await: awaiting each listener in turn here would let dispatch #1 finish
	// before #2 begins and the guard would never be under test.
	const payload = [{ height, hex: hex ?? headerHexAt(height) }];
	const running = [...client.headerHandlers].map((handler) => handler(payload));
	await Promise.all(running);
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
 *  a test can decide the order two concurrent subscribes resolve in, which of
 *  them fails, and whether a notification overtakes the response. */
let headerSubscribeControls: Map<
	number,
	{
		gate: { promise: Promise<void>; release: () => void };
		fails: boolean;
		/** Height of a header notification delivered through the handler this
		 *  very call installs, before it answers with the current one. */
		deliverWhileInFlight?: number;
	}
>;
let headerSubscribeCalls: number;
/** Every call that reached the client's subscribeHeader, the ones it answers
 *  "Already Subscribed." included: reaching it at all is what dials a random
 *  peers.json server for a network with no client. */
let headerSubscribeRequests: number;
/** Held open to keep a subscription request in flight for as long as a test
 *  needs, so a disconnect can land in the middle of one. */
let subscriptionGate: { promise: Promise<void>; release: () => void } | null;
/** Held open to park a wallet inside updateHeader, so a disconnect can land
 *  while the shared header dispatch is part way through its queue. */
let headerHandlerGate: { promise: Promise<void>; release: () => void } | null;
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

/**
 * sinon's fake timers, reached through a cast: the sinon typing this repo
 * resolves for the default export does not declare them, and the test type
 * check is run over the whole tests tree.
 */
type TFakeClock = { tick: (ms: number) => void; restore: () => void };
const useFakeClock = (toFake: string[]): TFakeClock =>
	(
		sinon as unknown as {
			useFakeTimers: (opts: { now: number; toFake: string[] }) => TFakeClock;
		}
	).useFakeTimers({ now: Date.now(), toFake });

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
	client.headerHandlers = [];
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
					client.headerHandlers = [];
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
			headerSubscribeRequests++;
			// Answered before anything else, exactly as the client does: a
			// network it already holds a subscription for gets the bare string
			// and no listener.
			if (client.subscribedHeaders) {
				return { error: false, data: 'Already Subscribed.' };
			}
			// And the listener goes on the shared emitter BEFORE the awaited
			// request, with the network marked subscribed only after it comes
			// back. That window is what two overlapping subscribes both walk
			// through, leaving two listeners behind (issue #507).
			if (onReceive) client.headerHandlers.push(onReceive);
			const control = headerSubscribeControls.get(headerSubscribeCalls++);
			if (control) {
				await control.gate.promise;
				if (control.fails) {
					return { error: true, data: 'Subscription failed.' };
				}
			}
			client.subscribedHeaders = true;
			protocolSubscribes.push('headers');
			if (control?.deliverWhileInFlight !== undefined) {
				// The client installs the notification listener before it asks
				// for the current header, so a block found in between reaches
				// the wallet ahead of the response below.
				await onReceive?.([
					{
						height: control.deliverWhileInFlight,
						hex: headerHexAt(control.deliverWhileInFlight)
					}
				]);
			}
			return {
				error: false,
				data: {
					height: nextHeaderHeight,
					hex: headerHexAt(nextHeaderHeight)
				}
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

/** One wallet's header bookkeeping. Per wallet, because a header applies to
 *  every instance on the network and the tests have to tell them apart. */
type TWalletHeader = {
	/** The wallet's stored header, updated by the header subscription. */
	stored: IHeader;
	/** The reorg flag of every checkUnconfirmedTransactions call, in order. */
	reorgChecks: boolean[];
	/** Makes checkUnconfirmedTransactions answer an error, so a test can fail
	 *  the reconciliation without failing the header write before it. */
	reconcileFails: boolean;
	/** Parks THIS wallet inside updateHeader, so a test can wedge one instance
	 *  and watch what the others on the network do meanwhile. The global
	 *  headerHandlerGate parks every wallet at once and cannot show that. */
	writeGate: { promise: Promise<void>; release: () => void } | null;
	/** Makes updateHeader reject AFTER it has replaced the stored header, the
	 *  ordering Wallet.updateHeader has. */
	writeFails: boolean;
};

/** Every wallet header a test made, so afterEach can release a wedged one. */
const createdWalletHeaders: TWalletHeader[] = [];

const createWalletHeader = (): TWalletHeader => {
	const header: TWalletHeader = {
		stored: { height: 0, hash: '', hex: '' },
		reorgChecks: [],
		reconcileFails: false,
		writeGate: null,
		writeFails: false
	};
	createdWalletHeaders.push(header);
	return header;
};

/** The header bookkeeping of the wallet behind the default instance. */
let walletHeader: TWalletHeader;

const createFakeWallet = (
	refreshSpy: sinon.SinonStub,
	messageSpy: sinon.SinonStub,
	scriptHash: string = walletScriptHash,
	header: TWalletHeader = walletHeader
): Wallet => {
	return {
		sendMessage: messageSpy,
		isSwitchingNetworks: false,
		refreshWallet: refreshSpy,
		updateHeader: async (newHeader: IHeader): Promise<void> => {
			if (headerHandlerGate) await headerHandlerGate.promise;
			if (header.writeGate) await header.writeGate.promise;
			// Wallet.updateHeader replaces the in-memory header BEFORE it
			// awaits storage, so a write that rejects has already lowered the
			// height the rollback was read from. Modelled, because that
			// ordering is the whole of issue #516.
			header.stored = newHeader;
			if (header.writeFails) throw new Error('Storage is gone.');
		},
		checkUnconfirmedTransactions: async (
			reorgDetected = false
		): Promise<Result<string>> => {
			header.reorgChecks.push(reorgDetected);
			if (header.reconcileFails) return err('Unable to reconcile.');
			return ok('Reconciled.');
		},
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
				header: header.stored,
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
	scriptHash: string = walletScriptHash,
	header: TWalletHeader = walletHeader
): Electrum => {
	const electrum = new Electrum({
		wallet: createFakeWallet(refreshSpy, messageSpy, scriptHash, header),
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
	headerHandlerGate = null;
	headerSubscribeControls = new Map();
	headerSubscribeCalls = 0;
	headerSubscribeRequests = 0;
	reachableHosts = new Set([serverA.host, serverB.host]);
	disconnectFails = false;
	socketIsDead = false;
	walletHeader = createWalletHeader();
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
	headerHandlerGate?.release();
	headerHandlerGate = null;
	for (const control of headerSubscribeControls.values()) {
		control.gate.release();
	}
	headerSubscribeControls.clear();
	for (const header of createdWalletHeaders) {
		header.writeGate?.release();
		header.writeGate = null;
		header.writeFails = false;
	}
	createdWalletHeaders.length = 0;
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
			client.headerHandlers.length,
			'a header handler must be wired to the new client'
		).to.equal(1);
		expect(
			walletHeader.stored.height,
			'the header must come from the new server, not local storage'
		).to.equal(250);
	});

	it('delivers header notifications from the new server', async () => {
		await electrum.connectToElectrum({ servers: serverA });
		await flush();
		await electrum.connectToElectrum({ servers: serverB });
		await flush();

		expect(client.headerHandlers.length).to.be.greaterThan(0);
		await fireHeader(300);
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

		expect(client.headerHandlers.length).to.be.greaterThan(0);
		await fireHeader(400);
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

	it('stays connected when every candidate is refused (issue #487)', async () => {
		await electrum.connectToElectrum({ servers: serverA });
		await flush();
		messageSpy.resetHistory();

		disconnectFails = true;
		const swapped = await electrum.connectToElectrum({ servers: serverB });
		await flush();

		expect(swapped.isErr()).to.equal(true);
		expect(
			electrum.connectedToElectrum,
			'the peer the teardown kept is still serving every call'
		).to.equal(true);
		expect(
			messageSpy
				.getCalls()
				.filter(
					(call: { args: [string, boolean] }) =>
						call.args[0] === 'connectedToElectrum'
				).length,
			'no disconnect may be announced for a connection that never dropped'
		).to.equal(0);
		expect(
			electrum.servers,
			'the refused target must not become the reconnect target'
		).to.deep.equal([serverA]);
	});

	it('does not retry a refused switch on every later call (issue #487)', async () => {
		await electrum.connectToElectrum({ servers: serverA });
		await flush();

		disconnectFails = true;
		const swapped = await electrum.connectToElectrum({ servers: serverB });
		expect(swapped.isErr()).to.equal(true);
		await flush();
		connectionEvents = [];

		const balance = await electrum.getAddressBalance(walletScriptHash);

		expect(balance.error, 'the kept peer answers the call').to.equal(false);
		expect(balance.confirmed).to.equal(stubbedBalance.confirmed);
		expect(
			connectionEvents,
			'a guarded call must not retry the switch that was refused'
		).to.deep.equal([]);
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

	it('retries a failed header restore on a healthy connection poll', async () => {
		await electrum.connectToElectrum({ servers: serverA });
		await flush();

		// The reconnect restores everything the dead socket cost, except that
		// the header re-subscribe errors. The replacement socket is healthy, so
		// no further connect is coming to try again.
		socketIsDead = true;
		const failing = { gate: createGate(), fails: true };
		failing.gate.release();
		headerSubscribeControls.set(1, failing);
		protocolSubscribes = [];
		const reconnected = await electrum.connectToElectrum({ servers: serverA });
		expect(reconnected.isOk()).to.equal(true);
		await flush();
		expect(protocolSubscribes, 'the header restore failed').to.not.include(
			'headers'
		);
		// The client leaves the listener of a failed subscribe on its emitter
		// (it registers before the request and only marks the network
		// subscribed after it), so the count says nothing here. What matters is
		// that the network is not subscribed, so nothing is delivered.
		expect(
			protocolSubscribes,
			'nothing reached the replacement client'
		).to.not.include('headers');

		await pollConnection(electrum);
		await flush();

		expect(
			protocolSubscribes,
			'the poll must re-issue the header subscription the restore owes'
		).to.include('headers');
		expect(client.headerHandlers.length).to.be.greaterThan(0);
		await fireHeader(800);
		await flush();
		const blocks = messageSpy
			.getCalls()
			.filter(
				(call: { args: [string, { height: number }] }) =>
					call.args[0] === 'newBlock'
			);
		expect(blocks.length, 'and the wallet receives blocks again').to.equal(1);
		expect(blocks[0].args[1].height).to.equal(800);

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

		// Two subscribes in flight at once. The client call is serialised per
		// network (issue #507), so the second reaches the client only once the
		// first has settled, but both are registered in the router throughout.
		const first = other.subscribeToHeader();
		const second = other.subscribeToHeader();
		failing.gate.release();
		succeeding.gate.release();
		expect((await first).isErr()).to.equal(true);
		expect((await second).isOk()).to.equal(true);

		// The failed attempt left its own registration on the client's emitter,
		// so the emitter holds this dispatcher twice; the notification must
		// still reach the wallet exactly once.
		expect(client.headerHandlers.length).to.equal(2);
		await fireHeader(512);
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
		await fireHeader(640);
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

		expect(client.headerHandlers.length).to.be.greaterThan(0);
		await fireHeader(700);
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
			walletHeader.stored.height,
			'nor write the header into a stopped wallet'
		).to.equal(0);
	});

	it('drops a queued header dispatch for an instance that disconnects', async () => {
		const otherRefresh = sinon.stub();
		const otherMessageSpy = sinon.spy();
		const other = createElectrum(otherRefresh, otherMessageSpy, 'eeee');
		await electrum.connectToElectrum({ servers: serverA });
		await flush();
		await other.connectToElectrum({ servers: serverA });
		await flush();

		// The dispatch is sequential, so the second instance is still queued
		// behind the first while the first is inside updateHeader.
		const gate = createGate();
		headerHandlerGate = gate;
		const dispatched = fireHeader(700);
		await flush();
		await other.disconnect();
		gate.release();
		headerHandlerGate = null;
		await dispatched;
		await flush();

		const otherBlocks = otherMessageSpy
			.getCalls()
			.filter(
				(call: { args: [string, { height: number }] }) =>
					call.args[0] === 'newBlock'
			);
		expect(
			otherBlocks.length,
			'a wallet that stopped mid-dispatch must not be handed the header'
		).to.equal(0);
		expect(otherRefresh.called, 'nor refreshed by it').to.equal(false);
		const ownBlocks = messageSpy
			.getCalls()
			.filter(
				(call: { args: [string, { height: number }] }) =>
					call.args[0] === 'newBlock'
			);
		expect(
			ownBlocks.length,
			'while the instance that held the dispatch up still gets it'
		).to.equal(1);
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

describe('Electrum reconnect header reorg reconciliation (issue #496)', () => {
	beforeEach(startTest);
	afterEach(endTest);

	it('reconciles a rollback the reconnect header reports', async () => {
		await electrum.connectToElectrum({ servers: serverA });
		await flush();
		expect(walletHeader.stored.height).to.equal(100);
		walletHeader.reorgChecks = [];

		// The chain rolled back while the socket was dead, so the restore's
		// header subscription answers below the stored tip.
		nextHeaderHeight = 96;
		socketIsDead = true;
		const reconnected = await electrum.connectToElectrum({ servers: serverA });
		expect(reconnected.isOk()).to.equal(true);
		await flush();

		expect(walletHeader.stored.height, 'the shorter chain is stored').to.equal(
			96
		);
		expect(
			walletHeader.reorgChecks,
			'and the rollback it implies is reconciled'
		).to.deep.equal([true]);
	});

	it('reconciles a rollback a failover to a shorter chain reports', async () => {
		await electrum.connectToElectrum({ servers: serverA });
		await flush();
		walletHeader.reorgChecks = [];

		nextHeaderHeight = 90;
		const swapped = await electrum.connectToElectrum({ servers: serverB });
		expect(swapped.isOk()).to.equal(true);
		await flush();

		expect(walletHeader.stored.height).to.equal(90);
		expect(walletHeader.reorgChecks).to.deep.equal([true]);
	});

	it('leaves no rollback for a notification that could no longer see it', async () => {
		await electrum.connectToElectrum({ servers: serverA });
		await flush();
		walletHeader.reorgChecks = [];

		nextHeaderHeight = 96;
		socketIsDead = true;
		await electrum.connectToElectrum({ servers: serverA });
		await flush();

		// The shorter chain grows past the reconnect header but stays below the
		// tip that was stored before it, which is exactly the notification that
		// used to be the only chance to notice the rollback, and could not:
		// the unreconciled write had already lowered the stored height.
		expect(client.headerHandlers.length).to.be.greaterThan(0);
		await fireHeader(98);
		await flush();

		expect(walletHeader.stored.height).to.equal(98);
		expect(
			walletHeader.reorgChecks,
			'the reconnect reconciled it once, and the block on top is growth'
		).to.deep.equal([true]);
	});

	it('reconciles nothing when the reconnect header extends the stored chain', async () => {
		await electrum.connectToElectrum({ servers: serverA });
		await flush();
		walletHeader.reorgChecks = [];

		nextHeaderHeight = 140;
		socketIsDead = true;
		await electrum.connectToElectrum({ servers: serverA });
		await flush();

		expect(walletHeader.stored.height).to.equal(140);
		expect(
			walletHeader.reorgChecks,
			'a taller chain is not a rollback'
		).to.deep.equal([]);
	});

	it('still reconciles a rollback a notification reports', async () => {
		await electrum.connectToElectrum({ servers: serverA });
		await flush();
		walletHeader.reorgChecks = [];

		await fireHeader(95);
		await flush();

		expect(walletHeader.stored.height).to.equal(95);
		expect(walletHeader.reorgChecks).to.deep.equal([true]);
	});

	it('reconciles the rollback for every wallet on the network', async () => {
		const otherHeader = createWalletHeader();
		const other = createElectrum(sinon.spy(), sinon.spy(), 'eeee', otherHeader);
		await electrum.connectToElectrum({ servers: serverA });
		await flush();
		await other.connectToElectrum({ servers: serverA });
		await flush();
		expect(otherHeader.stored.height).to.equal(100);
		walletHeader.reorgChecks = [];
		otherHeader.reorgChecks = [];

		nextHeaderHeight = 96;
		socketIsDead = true;
		await electrum.connectToElectrum({ servers: serverA });
		await flush();

		// Only the reconnecting instance is handed the header the subscribe
		// answers with, and the notification that follows is too high to reveal
		// the rollback to anyone who missed it.
		expect(walletHeader.reorgChecks).to.deep.equal([true]);
		expect(
			otherHeader.stored.height,
			'a wallet that did not reconnect still sees the shorter chain'
		).to.equal(96);
		expect(
			otherHeader.reorgChecks,
			'and reconciles the rollback it implies'
		).to.deep.equal([true]);
	});

	it('reconciles the rollback for a wallet that subscribes after it', async () => {
		await electrum.connectToElectrum({ servers: serverA });
		await flush();
		nextHeaderHeight = 96;
		socketIsDead = true;
		await electrum.connectToElectrum({ servers: serverA });
		await flush();

		// Its own storage says 100, and the client answers the subscribe it
		// issues with a bare "Already Subscribed." carrying no header at all.
		const otherHeader = createWalletHeader();
		otherHeader.stored = {
			height: 100,
			hash: headerHashAt(100),
			hex: headerHexAt(100)
		};
		const other = createElectrum(sinon.spy(), sinon.spy(), 'eeee', otherHeader);
		await other.connectToElectrum({ servers: serverA });
		await flush();

		expect(otherHeader.stored.height).to.equal(96);
		expect(otherHeader.reorgChecks).to.deep.equal([true]);
	});

	it('keeps the restore owed when the reconciliation fails', async () => {
		await electrum.connectToElectrum({ servers: serverA });
		await flush();
		walletHeader.reorgChecks = [];
		walletHeader.reconcileFails = true;

		nextHeaderHeight = 96;
		socketIsDead = true;
		await electrum.connectToElectrum({ servers: serverA });
		await flush();
		expect(walletHeader.reorgChecks, 'the rollback was noticed').to.deep.equal([
			true
		]);

		// The header write already replaced the height the rollback was read
		// from, so nothing else would ever notice it again: the restore has to
		// still owe it, and the poll is what retries.
		walletHeader.reconcileFails = false;
		await pollConnection(electrum);
		await flush();

		expect(
			walletHeader.reorgChecks,
			'and is reconciled again until it succeeds'
		).to.deep.equal([true, true]);

		// Settled now: a later healthy poll reconciles nothing.
		await pollConnection(electrum);
		await flush();
		expect(walletHeader.reorgChecks).to.deep.equal([true, true]);
	});

	it('keeps a header notification that overtook the subscribe response', async () => {
		await electrum.connectToElectrum({ servers: serverA });
		await flush();
		walletHeader.reorgChecks = [];

		// The reconnect asks the server for the current header, and block 101 is
		// found before the answer comes back.
		socketIsDead = true;
		const overtaken = {
			gate: createGate(),
			fails: false,
			deliverWhileInFlight: 101
		};
		overtaken.gate.release();
		headerSubscribeControls.set(1, overtaken);
		await electrum.connectToElectrum({ servers: serverA });
		await flush();

		expect(walletHeader.stored.height, 'the newer header stands').to.equal(101);
		expect(
			walletHeader.reorgChecks,
			'and the block it reported is growth, not a rollback'
		).to.deep.equal([]);
	});
});

/**
 * Issue #507 (and its duplicate #488): rn-electrum-client registers the
 * notification listener on the client's shared emitter BEFORE the awaited
 * request and marks the network subscribed only after it, so two subscribes
 * that overlap that window both register the shared dispatcher, and a
 * subscribe that FAILS leaves its registration behind for the next one to
 * stack on. Every later header then ran the whole router queue once per
 * registration: two header writes, two wallet refreshes and two newBlock
 * messages per block, for the life of that client.
 *
 * The overlap is closed by serialising the client call per network, and the
 * registration a failed attempt leaves behind by dispatching one notification
 * payload once, whatever the emitter holds.
 */
describe('Electrum concurrent header subscribes (issue #507)', () => {
	beforeEach(startTest);
	afterEach(endTest);

	it('issues one subscription for two concurrent subscribes', async () => {
		// A real overlap: the first request is still in flight, inside the
		// window the client leaves open between registering its listener and
		// marking the network subscribed, when the second one is issued.
		const inFlight = createGate();
		headerSubscribeControls.set(0, { gate: inFlight, fails: false });
		const first = electrum.subscribeToHeader();
		const second = electrum.subscribeToHeader();
		await flush();
		inFlight.release();
		expect((await first).isOk()).to.equal(true);
		expect((await second).isOk()).to.equal(true);

		expect(
			protocolSubscribes.filter((entry) => entry === 'headers').length,
			'the second subscribe must find the network already subscribed'
		).to.equal(1);
		expect(
			client.headerHandlers.length,
			'and must not put a second listener on the shared emitter'
		).to.equal(1);
	});

	it('reports one block once when two subscribes overlap', async () => {
		// Both reach the client's registration window before either answers.
		const gateA = createGate();
		const gateB = createGate();
		headerSubscribeControls.set(0, { gate: gateA, fails: false });
		headerSubscribeControls.set(1, { gate: gateB, fails: false });
		const first = electrum.subscribeToHeader();
		const second = electrum.subscribeToHeader();
		gateA.release();
		gateB.release();
		await first;
		await second;
		messageSpy.resetHistory();
		refreshSpy.resetHistory();

		await fireHeader(101);
		await flush();

		const blocks = messageSpy
			.getCalls()
			.filter(
				(call: { args: [string, { height: number }] }) =>
					call.args[0] === 'newBlock'
			);
		expect(blocks.length, 'one block, one notification').to.equal(1);
		expect(walletHeader.stored.height).to.equal(101);
	});

	it('reports one block once after a failed subscribe left a listener', async () => {
		const failing = { gate: createGate(), fails: true };
		failing.gate.release();
		headerSubscribeControls.set(0, failing);
		expect((await electrum.subscribeToHeader()).isErr()).to.equal(true);
		expect((await electrum.subscribeToHeader()).isOk()).to.equal(true);

		// The client kept the failed attempt's listener, so it holds the shared
		// dispatcher twice.
		expect(client.headerHandlers.length).to.equal(2);
		messageSpy.resetHistory();

		await fireHeader(101);
		await flush();

		const blocks = messageSpy
			.getCalls()
			.filter(
				(call: { args: [string, { height: number }] }) =>
					call.args[0] === 'newBlock'
			);
		expect(blocks.length, 'the duplicate registration is swallowed').to.equal(
			1
		);
		expect(
			walletHeader.reorgChecks,
			'and the block is not reconciled twice either'
		).to.deep.equal([]);
	});

	it('does not let one unanswered subscribe wedge the network', async () => {
		const clock = useFakeClock(['setTimeout', 'clearTimeout']);
		try {
			// A server that accepts the connection and then says nothing. The
			// client's own handshake carries no timeout, so this attempt never
			// settles.
			const silent = createGate();
			headerSubscribeControls.set(0, { gate: silent, fails: false });
			const wedged = electrum.subscribeToHeader();
			await Promise.resolve();

			// A later caller must not queue behind it for the life of the
			// process: everything from the reconnect monitor to the restore
			// comes through here.
			const second = electrum.subscribeToHeader();
			clock.tick(60_000);
			const result = await second;
			expect(result.isOk()).to.equal(true);

			silent.release();
			await wedged;
		} finally {
			clock.restore();
		}
	});

	it('does not issue a queued subscribe from a stopped instance', async () => {
		await electrum.connectToElectrum({ servers: serverA });
		await flush();
		// The first subscribe holds the gate; the second queues behind it.
		const held = createGate();
		headerSubscribeControls.set(1, { gate: held, fails: false });
		client.subscribedHeaders = false;
		const first = electrum.subscribeToHeader();
		const queued = electrum.subscribeToHeader();
		await flush();

		await electrum.disconnect();
		const requestsBeforeRelease = headerSubscribeRequests;
		held.release();
		expect((await queued).isErr()).to.equal(true);
		await first;
		await flush();

		// The client dials a random peers.json server for any network it holds
		// no client for, and disconnect() is what leaves it with none, so a
		// request issued from the queue after that point connects a stopped
		// wallet to a server nobody chose.
		expect(
			headerSubscribeRequests,
			'the queued subscribe must not reach the client at all'
		).to.equal(requestsBeforeRelease);
	});

	it('still delivers two genuine blocks', async () => {
		await electrum.connectToElectrum({ servers: serverA });
		await flush();
		messageSpy.resetHistory();

		await fireHeader(101);
		await fireHeader(102);
		await flush();

		const blocks = messageSpy
			.getCalls()
			.filter(
				(call: { args: [string, { height: number }] }) =>
					call.args[0] === 'newBlock'
			);
		expect(
			blocks.map(
				(call: { args: [string, { height: number }] }) => call.args[1].height
			)
		).to.deep.equal([101, 102]);
	});
});

/**
 * Issue #508: the shared header dispatch awaited each instance in turn, so one
 * wallet whose updateHeader never settles parked every instance behind it in
 * the map, for that block and for every block after it. The catch around the
 * handler only ever covered a rejection, never a promise that does not settle.
 */
describe('Electrum header dispatch with a stalled wallet (issue #508)', () => {
	beforeEach(startTest);
	afterEach(endTest);

	it('reaches every other instance while one wallet is wedged', async () => {
		const otherHeader = createWalletHeader();
		const otherMessageSpy = sinon.spy();
		const other = createElectrum(
			sinon.spy(),
			otherMessageSpy,
			'cccc',
			otherHeader
		);
		await electrum.connectToElectrum({ servers: serverA });
		await flush();
		await other.connectToElectrum({ servers: serverA });
		await flush();
		otherMessageSpy.resetHistory();

		// The first instance's storage never answers.
		const wedged = createGate();
		walletHeader.writeGate = wedged;
		const dispatched = fireHeader(101);
		await flush();

		expect(
			otherHeader.stored.height,
			'the second wallet must not wait on the first'
		).to.equal(101);
		const blocks = otherMessageSpy
			.getCalls()
			.filter(
				(call: { args: [string, { height: number }] }) =>
					call.args[0] === 'newBlock'
			);
		expect(blocks.length).to.equal(1);

		wedged.release();
		walletHeader.writeGate = null;
		await dispatched;
	});

	it('keeps dropping a queued instance that withdraws mid-dispatch', async () => {
		const otherHeader = createWalletHeader();
		const otherRefresh = sinon.spy();
		const other = createElectrum(
			otherRefresh,
			sinon.spy(),
			'cccc',
			otherHeader
		);
		await electrum.connectToElectrum({ servers: serverA });
		await flush();
		await other.connectToElectrum({ servers: serverA });
		await flush();
		otherRefresh.resetHistory();

		// Both instances park in updateHeader; the second withdraws while it is
		// in there, so its refresh must never run.
		const gate = createGate();
		headerHandlerGate = gate;
		const dispatched = fireHeader(101);
		await flush();
		await other.disconnect();
		gate.release();
		headerHandlerGate = null;
		await dispatched;
		await flush();

		expect(
			otherRefresh.called,
			'a wallet that shut down must not be refreshed'
		).to.equal(false);
	});
});

/**
 * Issues #511 and #515: the rollback was decided by height alone although the
 * hash was in hand. A tip REPLACED at the same height was written as ordinary
 * growth, a chain that rolled back and rebuilt taller arrived above the stored
 * tip and read as growth too, and a server one block behind, which is what a
 * failover normally lands on, read as a rollback and fired a 'reorg' message
 * at every wallet on the network.
 */
describe('Electrum hash aware rollback detection (issues #511, #515)', () => {
	beforeEach(startTest);
	afterEach(endTest);

	const reorgMessages = (spy: {
		getCalls: () => Array<{ args: [string, unknown] }>;
	}): unknown[] =>
		spy
			.getCalls()
			.filter((call: { args: [string, unknown] }) => call.args[0] === 'reorg');

	it('reconciles a tip replaced at the same height', async () => {
		await electrum.connectToElectrum({ servers: serverA });
		await flush();
		expect(walletHeader.stored.height).to.equal(100);
		walletHeader.reorgChecks = [];

		// Same height, a different block: the chain never got shorter, but the
		// block this wallet's transactions were confirmed in is gone.
		await fireHeader(100, siblingHeaderHexAt(100));
		await flush();

		expect(walletHeader.stored.hash).to.equal(
			Block.fromHex(siblingHeaderHexAt(100)).getId()
		);
		expect(
			walletHeader.reorgChecks,
			'an equal height replacement is a rollback'
		).to.deep.equal([true]);
	});

	it('reconciles a rollback that rebuilt taller than the stored tip', async () => {
		await electrum.connectToElectrum({ servers: serverA });
		await flush();
		walletHeader.reorgChecks = [];

		// 101 that does not build on the stored 100: the chain rolled 100 back
		// and rebuilt, so the stored tip is gone although the height went up.
		const forked = Buffer.alloc(80);
		forked.writeUInt32LE(1, 0);
		Buffer.from(Block.fromHex(siblingHeaderHexAt(100)).getId(), 'hex')
			.reverse()
			.copy(forked, 4);
		forked.writeUInt32LE(7, 76);
		await fireHeader(101, forked.toString('hex'));
		await flush();

		expect(walletHeader.stored.height).to.equal(101);
		expect(
			walletHeader.reorgChecks,
			'a successor that does not link is a rollback'
		).to.deep.equal([true]);
	});

	it('treats a block that links onto the stored tip as growth', async () => {
		await electrum.connectToElectrum({ servers: serverA });
		await flush();
		walletHeader.reorgChecks = [];

		await fireHeader(101);
		await flush();

		expect(walletHeader.stored.height).to.equal(101);
		expect(walletHeader.reorgChecks).to.deep.equal([]);
	});

	it('ignores a server one block behind on the same chain', async () => {
		await electrum.connectToElectrum({ servers: serverA });
		await flush();
		walletHeader.reorgChecks = [];
		messageSpy.resetHistory();

		// The failover lands on a server that has not seen block 100 yet. It
		// holds this wallet's own block 99, so it says nothing about 100.
		nextHeaderHeight = 99;
		const swapped = await electrum.connectToElectrum({ servers: serverB });
		expect(swapped.isOk()).to.equal(true);
		await flush();

		expect(
			walletHeader.stored.height,
			'the stored tip is not lowered onto its own parent'
		).to.equal(100);
		expect(
			walletHeader.reorgChecks,
			'and no reconciliation is claimed'
		).to.deep.equal([]);
		expect(
			reorgMessages(messageSpy).length,
			"an ordinary failover must not fire a 'reorg' message"
		).to.equal(0);
	});

	it('still reconciles when that server then reports a different block 100', async () => {
		await electrum.connectToElectrum({ servers: serverA });
		await flush();
		nextHeaderHeight = 99;
		await electrum.connectToElectrum({ servers: serverB });
		await flush();
		walletHeader.reorgChecks = [];

		await fireHeader(100, siblingHeaderHexAt(100));
		await flush();

		expect(walletHeader.reorgChecks).to.deep.equal([true]);
	});

	it('reconciles a NOTIFICATION that reports the stored tip parent', async () => {
		await electrum.connectToElectrum({ servers: serverA });
		await flush();
		expect(walletHeader.stored.height).to.equal(100);
		walletHeader.reorgChecks = [];

		// The client only notifies when the server's tip CHANGES, so a server
		// announcing the parent of the block this wallet holds is saying that
		// block was undone. Ignoring it the way a subscribe answer is ignored
		// would lose the rollback for good once the rebuilt chain came back two
		// or more blocks up, where the height-only reading takes over.
		await fireHeader(99);
		await flush();

		expect(walletHeader.stored.height).to.equal(99);
		expect(walletHeader.reorgChecks).to.deep.equal([true]);
	});

	it('reconciles a rollback the ignored reconnect header preceded', async () => {
		await electrum.connectToElectrum({ servers: serverA });
		await flush();
		walletHeader.reorgChecks = [];

		// A failover lands on a server one block behind, which is ignored.
		nextHeaderHeight = 99;
		await electrum.connectToElectrum({ servers: serverB });
		await flush();
		expect(walletHeader.stored.height).to.equal(100);
		expect(walletHeader.reorgChecks).to.deep.equal([]);

		// That server then produces a DIFFERENT block 100, which is the
		// rollback showing itself.
		await fireHeader(100, siblingHeaderHexAt(100));
		await flush();

		expect(walletHeader.reorgChecks).to.deep.equal([true]);
	});

	it('keeps applying a header after one wallet storage throws', async () => {
		const brokenHeader = createWalletHeader();
		const broken = createElectrum(
			sinon.spy(),
			sinon.spy(),
			'dddd',
			brokenHeader
		);
		const otherHeader = createWalletHeader();
		const other = createElectrum(sinon.spy(), sinon.spy(), 'eeee', otherHeader);
		await broken.connectToElectrum({ servers: serverA });
		await flush();
		await other.connectToElectrum({ servers: serverA });
		await flush();

		// A stored hex too short to parse used to throw out of applyHeader,
		// which aborted the fan-out and left every wallet behind it unreached.
		brokenHeader.stored = { height: 100, hash: '', hex: '0x0100abcd' };
		otherHeader.stored = { height: 100, hash: '', hex: '0x0100abcd' };
		brokenHeader.writeFails = true;

		await fireHeader(101);
		await flush();

		expect(
			otherHeader.stored.height,
			'a wallet whose sibling threw must still get the header'
		).to.equal(101);
	});

	it('reconciles a rollback that surfaces two blocks above an ignored tip', async () => {
		await electrum.connectToElectrum({ servers: serverA });
		await flush();
		walletHeader.reorgChecks = [];

		// A failover lands on a server that answers with this tip's own parent,
		// which is ignored: it says nothing about block 100 either way.
		nextHeaderHeight = 99;
		await electrum.connectToElectrum({ servers: serverB });
		await flush();
		expect(walletHeader.stored.height).to.equal(100);
		expect(walletHeader.reorgChecks).to.deep.equal([]);

		// The wallet then misses a block (a disconnect, an app backgrounded)
		// and the next header it sees is two above the stored tip, too far away
		// to compare. Read as growth, the rollback that orphaned 100 would be
		// lost for good.
		const forkedAt100 = siblingHeaderHexAt(100);
		const forked101 = Buffer.alloc(80);
		forked101.writeUInt32LE(1, 0);
		Buffer.from(Block.fromHex(forkedAt100).getId(), 'hex')
			.reverse()
			.copy(forked101, 4);
		forked101.writeUInt32LE(11, 76);
		const forked102 = Buffer.alloc(80);
		forked102.writeUInt32LE(1, 0);
		Buffer.from(Block.fromHex(forked101.toString('hex')).getId(), 'hex')
			.reverse()
			.copy(forked102, 4);
		forked102.writeUInt32LE(12, 76);
		await fireHeader(102, forked102.toString('hex'));
		await flush();

		expect(walletHeader.stored.height).to.equal(102);
		expect(
			walletHeader.reorgChecks,
			'a tip no server would confirm must not be overwritten as growth'
		).to.deep.equal([true]);
	});

	it('leaves a fresh wallet with no stored hash alone', async () => {
		const freshHeader = createWalletHeader();
		const fresh = createElectrum(sinon.spy(), sinon.spy(), 'dddd', freshHeader);
		await fresh.connectToElectrum({ servers: serverA });
		await flush();

		expect(freshHeader.stored.height).to.equal(100);
		expect(
			freshHeader.reorgChecks,
			'the first header a wallet ever sees is not a rollback'
		).to.deep.equal([]);
	});
});

/**
 * Issue #516: the reorg debt was recorded AFTER the write it is meant to
 * outlive. Wallet.updateHeader replaces the in-memory header before it awaits
 * storage, so a write that rejects had already spent the height the rollback
 * was read from, and the next higher header read as ordinary growth.
 */
describe('Electrum reorg debt across a failed header write (issue #516)', () => {
	beforeEach(startTest);
	afterEach(endTest);

	it('still reconciles after a write that threw', async () => {
		await electrum.connectToElectrum({ servers: serverA });
		await flush();
		walletHeader.reorgChecks = [];

		// The rollback arrives and the write rejects, which used to leave the
		// debt unrecorded.
		walletHeader.writeFails = true;
		await fireHeader(95).catch(() => undefined);
		walletHeader.writeFails = false;
		await flush();
		expect(
			walletHeader.reorgChecks,
			'nothing was reconciled while the write was failing'
		).to.deep.equal([]);

		// The next header is above what is stored, so only the debt can still
		// reveal the rollback.
		await fireHeader(96);
		await flush();

		expect(walletHeader.reorgChecks).to.deep.equal([true]);
	});
});

/**
 * Issue #514: a failed reconciliation was reported as a subscription failure,
 * so ElectrumBackend's reconnect monitor counted it as a ping failure (three
 * of which fail the server over) and ChainWatcher.start read it as having no
 * header subscription and refused to accept work at all. It is another
 * wallet's debt as often as the caller's own.
 */
describe('Electrum reconcile debt is not a subscribe failure (issue #514)', () => {
	beforeEach(startTest);
	afterEach(endTest);

	it('answers ok when the subscription is live but the reconcile failed', async () => {
		await electrum.connectToElectrum({ servers: serverA });
		await flush();

		// A rollback the wallet cannot reconcile, reported by the subscribe.
		walletHeader.reconcileFails = true;
		nextHeaderHeight = 90;
		socketIsDead = true;
		await electrum.connectToElectrum({ servers: serverA });
		await flush();
		expect(walletHeader.reorgChecks).to.include(true);

		const subscribed = await electrum.subscribeToHeader();
		expect(
			subscribed.isOk(),
			'the subscription is registered, wired and answering'
		).to.equal(true);
	});

	it('still reports the debt to a caller asking about the server', async () => {
		await electrum.connectToElectrum({ servers: serverA });
		await flush();

		walletHeader.reconcileFails = true;
		nextHeaderHeight = 90;
		socketIsDead = true;
		await electrum.connectToElectrum({ servers: serverA });
		await flush();

		// The reconnect monitor's ping asks whether the SERVER is serving this
		// wallet, and the history batches behind the reconciliation are that
		// server's. Without this a server that answers headers and fails
		// history pinned the monitor at zero failures forever, and in the
		// daemon that monitor is the only path to a second server.
		const pinged = await electrum.pingHeaderSubscription();
		expect(pinged.isErr()).to.equal(true);
		expect(
			(await electrum.subscribeToHeader()).isOk(),
			'while the subscription itself is still live'
		).to.equal(true);
	});

	it('keeps the restore owed all the same', async () => {
		await electrum.connectToElectrum({ servers: serverA });
		await flush();

		walletHeader.reconcileFails = true;
		nextHeaderHeight = 90;
		socketIsDead = true;
		await electrum.connectToElectrum({ servers: serverA });
		await flush();
		protocolSubscribes.length = 0;

		// The poll is the restore's other retry hook, and it only fires on a
		// debt the restore recorded.
		walletHeader.reconcileFails = false;
		client.subscribedHeaders = false;
		await pollConnection(electrum);
		await flush();

		expect(protocolSubscribes, 'the owed restore must be retried').to.include(
			'headers'
		);
	});
});
