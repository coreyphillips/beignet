import { expect } from 'chai';
import * as net from 'net';
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

const createElectrum = (
	servers: TServer[],
	network = EAvailableNetworks.testnet
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
		servers
	});
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

	it('regtest never appends external fallback peers', async () => {
		const electrum = createElectrum([serverA], EAvailableNetworks.regtest);
		const attempts: string[] = [];
		stubConnections(electrum, new Set([serverA.host]), attempts);

		const res = await electrum.connectToElectrum({});
		expect(res.isErr()).to.equal(true);
		expect(attempts).to.deep.equal([serverA.host]);
	});

	it('provides a signet fallback peer entry', () => {
		const signetPeers = defaultElectrumPeers[EElectrumNetworks.bitcoinSignet];
		expect(signetPeers).to.not.equal(undefined);
		expect(signetPeers![0].host).to.equal('mempool.space');
	});
});
