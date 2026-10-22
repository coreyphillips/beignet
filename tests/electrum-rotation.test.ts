import { expect } from 'chai';
import * as net from 'net';
import sinon from 'sinon';
import * as tls from 'tls';
import {
	EAvailableNetworks,
	Electrum,
	EProtocol,
	ok,
	Result,
	TServer,
	Wallet
} from '../src';
import { defaultElectrumPeers } from '../src/shapes';
import { EElectrumNetworks, IHeader } from '../src/types';

// The raw module.exports object, so stubs on it are seen by src/electrum.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const electrumHelpers = require('rn-electrum-client/helpers');

/**
 * These tests run fully offline: the single-server connect attempt is stubbed
 * with a fake connection layer, so rotation order, cooldown handling and the
 * peers.json fallback are exercised without any sockets.
 */

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

// An instance with fallback peers disabled bars them for every instance on its
// network until it disconnects, so none may outlive its test.
const refusingFallbacks: Electrum[] = [];

const createElectrum = (
	servers: TServer | TServer[],
	network = EAvailableNetworks.testnet,
	{ disableFallbackServers }: { disableFallbackServers?: boolean } = {}
): Electrum => {
	const fakeWallet = {
		sendMessage: (): void => {},
		isSwitchingNetworks: false
	} as unknown as Wallet;
	const electrum = new Electrum({
		wallet: fakeWallet,
		network,
		net,
		tls,
		servers,
		disableFallbackServers
	});
	if (disableFallbackServers) refusingFallbacks.push(electrum);
	// No background pings during tests.
	electrum.stopConnectionPolling();
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	(electrum as any).subscribeToHeader = async (): Promise<Result<IHeader>> =>
		ok({ height: 0, hash: '', hex: '' });
	return electrum;
};

const stubConnections = (
	electrum: Electrum,
	failHosts: Set<string>,
	attempts: string[]
): void => {
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	(electrum as any).attemptConnect = async (
		server: TServer
	): Promise<{ error: unknown }> => {
		attempts.push(server.host);
		return failHosts.has(server.host)
			? { error: 'connection refused' }
			: { error: false };
	};
};

describe('Electrum multi-server rotation', () => {
	afterEach(async () => {
		for (const electrum of refusingFallbacks.splice(0)) {
			await electrum.disconnect();
		}
	});

	it('starts with no current server and zero rotations', () => {
		const electrum = createElectrum([serverA, serverB]);
		expect(electrum.currentServer).to.equal(null);
		expect(electrum.rotationCount).to.equal(0);
	});

	it('rotates to the next server when the first fails to connect', async () => {
		const electrum = createElectrum([serverA, serverB]);
		const attempts: string[] = [];
		stubConnections(electrum, new Set([serverA.host]), attempts);

		const res = await electrum.connectToElectrum({});
		expect(res.isOk()).to.equal(true);
		expect(attempts).to.deep.equal([serverA.host, serverB.host]);
		expect(electrum.currentServer?.host).to.equal(serverB.host);
		// First successful connect establishes a baseline, not a rotation.
		expect(electrum.rotationCount).to.equal(0);
	});

	it('rotates off a failing current server and counts the rotation', async () => {
		const fallbackHosts = (
			defaultElectrumPeers[EElectrumNetworks.bitcoinTestnet] ?? []
		).map((s) => s.host);
		const electrum = createElectrum([serverA, serverB]);
		const attempts: string[] = [];
		stubConnections(electrum, new Set([serverA.host]), attempts);
		await electrum.connectToElectrum({});
		expect(electrum.currentServer?.host).to.equal(serverB.host);

		// B and the fallback peers die; A recovered but is still cooling down
		// from its earlier failure, so it is attempted last and still succeeds.
		attempts.length = 0;
		stubConnections(
			electrum,
			new Set([serverB.host, ...fallbackHosts]),
			attempts
		);
		const res = await electrum.connectToElectrum({});
		expect(res.isOk()).to.equal(true);
		expect(attempts).to.deep.equal([
			serverB.host,
			...fallbackHosts,
			serverA.host
		]);
		expect(electrum.currentServer?.host).to.equal(serverA.host);
		expect(electrum.rotationCount).to.equal(1);
	});

	it('does not touch a cooled-down server while the current one is healthy', async () => {
		const electrum = createElectrum([serverA, serverB]);
		const attempts: string[] = [];
		stubConnections(electrum, new Set([serverA.host]), attempts);
		await electrum.connectToElectrum({});

		// Reconnect with B healthy: A (cooling down) must not be attempted.
		attempts.length = 0;
		stubConnections(electrum, new Set(), attempts);
		const res = await electrum.connectToElectrum({});
		expect(res.isOk()).to.equal(true);
		expect(attempts).to.deep.equal([serverB.host]);
		expect(electrum.rotationCount).to.equal(0);
	});

	it('falls back to hardcoded peers when all provided servers fail', async () => {
		const fallbackHosts = (
			defaultElectrumPeers[EElectrumNetworks.bitcoinTestnet] ?? []
		).map((s) => s.host);
		expect(fallbackHosts.length).to.be.greaterThan(0);

		const electrum = createElectrum([serverA, serverB]);
		const attempts: string[] = [];
		stubConnections(electrum, new Set([serverA.host, serverB.host]), attempts);

		const res = await electrum.connectToElectrum({});
		expect(res.isOk()).to.equal(true);
		expect(attempts.slice(0, 2)).to.deep.equal([serverA.host, serverB.host]);
		expect(attempts[2]).to.equal(fallbackHosts[0]);
		expect(electrum.currentServer?.host).to.equal(fallbackHosts[0]);
	});

	it('uses the network fallback peers when no servers are provided', async () => {
		const fallbackHosts = (
			defaultElectrumPeers[EElectrumNetworks.bitcoinTestnet] ?? []
		).map((s) => s.host);
		const electrum = createElectrum([]);
		const attempts: string[] = [];
		stubConnections(electrum, new Set(), attempts);

		const res = await electrum.connectToElectrum({});
		expect(res.isOk()).to.equal(true);
		expect(attempts).to.deep.equal([fallbackHosts[0]]);
	});

	it('errs when every candidate fails', async () => {
		const electrum = createElectrum([serverA]);
		const attempts: string[] = [];
		const everything = new Set([
			serverA.host,
			...(defaultElectrumPeers[EElectrumNetworks.bitcoinTestnet] ?? []).map(
				(s) => s.host
			)
		]);
		stubConnections(electrum, everything, attempts);

		const res = await electrum.connectToElectrum({});
		expect(res.isErr()).to.equal(true);
		expect(attempts[0]).to.equal(serverA.host);
		expect(attempts.length).to.equal(everything.size);
		expect(electrum.currentServer).to.equal(null);
	});

	it('regtest requires a pre-specified server', async () => {
		const electrum = createElectrum([], EAvailableNetworks.regtest);
		const attempts: string[] = [];
		stubConnections(electrum, new Set(), attempts);

		const res = await electrum.connectToElectrum({});
		expect(res.isErr()).to.equal(true);
		expect(attempts).to.have.length(0);
	});

	it('regtest accepts a single server object when the connect omits servers (#980)', async () => {
		const electrum = createElectrum(serverA, EAvailableNetworks.regtest);
		const attempts: string[] = [];
		stubConnections(electrum, new Set(), attempts);

		const res = await electrum.connectToElectrum({});
		expect(res.isOk()).to.equal(true);
		expect(attempts).to.deep.equal([serverA.host]);
		expect(electrum.currentServer?.host).to.equal(serverA.host);
	});

	it('dials a single server object first when the connect omits servers (#980)', async () => {
		const electrum = createElectrum(serverA);
		const attempts: string[] = [];
		stubConnections(electrum, new Set(), attempts);

		const res = await electrum.connectToElectrum({});
		expect(res.isOk()).to.equal(true);
		expect(attempts).to.deep.equal([serverA.host]);
		expect(electrum.currentServer?.host).to.equal(serverA.host);
	});

	it('regtest never appends external fallback peers', async () => {
		const electrum = createElectrum([serverA], EAvailableNetworks.regtest);
		const attempts: string[] = [];
		stubConnections(electrum, new Set([serverA.host]), attempts);

		const res = await electrum.connectToElectrum({});
		expect(res.isErr()).to.equal(true);
		expect(attempts).to.deep.equal([serverA.host]);
	});

	it('never dials a fallback peer when they are disabled', async () => {
		const electrum = createElectrum([serverA, serverB], undefined, {
			disableFallbackServers: true
		});
		const attempts: string[] = [];
		stubConnections(electrum, new Set([serverA.host, serverB.host]), attempts);

		const res = await electrum.connectToElectrum({});
		expect(res.isErr()).to.equal(true);
		expect(attempts).to.deep.equal([serverA.host, serverB.host]);
		expect(electrum.currentServer).to.equal(null);
		expect(electrum.connectedToElectrum).to.equal(false);
	});

	it('still rotates through the given servers when fallback peers are disabled', async () => {
		const electrum = createElectrum([serverA, serverB], undefined, {
			disableFallbackServers: true
		});
		const attempts: string[] = [];
		stubConnections(electrum, new Set([serverA.host]), attempts);

		const res = await electrum.connectToElectrum({});
		expect(res.isOk()).to.equal(true);
		expect(attempts).to.deep.equal([serverA.host, serverB.host]);
		expect(electrum.currentServer?.host).to.equal(serverB.host);
	});

	it('errs without dialling when fallback peers are disabled and no server is given', async () => {
		const electrum = createElectrum([], undefined, {
			disableFallbackServers: true
		});
		const attempts: string[] = [];
		stubConnections(electrum, new Set(), attempts);

		const res = await electrum.connectToElectrum({});
		expect(res.isErr()).to.equal(true);
		if (res.isErr()) {
			expect(res.error.message).to.match(/fallback servers are disabled/);
		}
		expect(attempts).to.have.length(0);
	});

	it('keeps every instance on the network off fallback peers while one disables them', async () => {
		const fallbackHosts = (
			defaultElectrumPeers[EElectrumNetworks.bitcoinTestnet] ?? []
		).map((s) => s.host);
		const strict = createElectrum([serverA], undefined, {
			disableFallbackServers: true
		});
		stubConnections(strict, new Set(), []);
		expect((await strict.connectToElectrum({})).isOk()).to.equal(true);

		const permissive = createElectrum([]);
		const attempts: string[] = [];
		stubConnections(permissive, new Set(), attempts);
		expect((await permissive.connectToElectrum({})).isErr()).to.equal(true);
		expect(attempts).to.have.length(0);

		await strict.disconnect();
		expect((await permissive.connectToElectrum({})).isOk()).to.equal(true);
		expect(attempts).to.deep.equal([fallbackHosts[0]]);
	});

	it('skips fallback peers once an instance that disables them joins mid-rotation', async () => {
		const permissive = createElectrum([serverB]);
		const attempts: string[] = [];
		let failServerB = (): void => {};
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(permissive as any).attemptConnect = async (
			server: TServer
		): Promise<{ error: unknown }> => {
			attempts.push(server.host);
			if (server.host !== serverB.host) return { error: false };
			await new Promise<void>((resolve) => (failServerB = resolve));
			return { error: 'connection refused' };
		};
		const connecting = permissive.connectToElectrum({});

		const strict = createElectrum([serverA], undefined, {
			disableFallbackServers: true
		});
		stubConnections(strict, new Set(), []);
		expect((await strict.connectToElectrum({})).isOk()).to.equal(true);

		failServerB();
		expect((await connecting).isErr()).to.equal(true);
		expect(attempts).to.deep.equal([serverB.host]);
	});

	it('drops a fallback peer a sibling holds when an instance disables them', async () => {
		const [fallback] =
			defaultElectrumPeers[EElectrumNetworks.bitcoinTestnet] ?? [];
		sinon.stub(electrumHelpers, 'getConnectedPeer').returns({
			host: fallback.host,
			port: fallback.ssl,
			protocol: fallback.protocol
		});
		const stop = sinon.stub(electrumHelpers, 'stop').resolves({ error: false });
		try {
			const strict = createElectrum([], undefined, {
				disableFallbackServers: true
			});
			expect((await strict.connectToElectrum({})).isErr()).to.equal(true);
			expect(
				stop.calledWith({ network: EElectrumNetworks.bitcoinTestnet })
			).to.equal(true);
		} finally {
			sinon.restore();
		}
	});

	it('provides a signet fallback peer entry', () => {
		const signetPeers = defaultElectrumPeers[EElectrumNetworks.bitcoinSignet];
		expect(signetPeers).to.not.equal(undefined);
		expect(signetPeers![0].host).to.equal('mempool.space');
	});
});
