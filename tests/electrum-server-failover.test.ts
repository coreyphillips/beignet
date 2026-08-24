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
	messageSpy: sinon.SinonStub
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
						'0': { index: 0, scriptHash: walletScriptHash }
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
	messageSpy: sinon.SinonStub
): Electrum => {
	const electrum = new Electrum({
		wallet: createFakeWallet(refreshSpy, messageSpy),
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
		storedHeader = { height: 0, hash: '', hex: '' };
		stubHelpers();
		refreshSpy = sinon.spy();
		messageSpy = sinon.spy();
		electrum = createElectrum(refreshSpy, messageSpy);
	});

	afterEach(async () => {
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
