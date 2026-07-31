/**
 * connectToElectrum failure reporting: runs offline against an unreachable
 * local port on purpose (like watch-only.test.ts), so it must not share a
 * process with the live-Electrum wallet suites (rn-electrum-client keeps
 * module-global client state).
 *
 * Regression for the network-switch exemption that returned success when
 * every candidate server had failed: with isSwitchingNetworks set, the old
 * code told every caller a connection existed, and each subsequent Electrum
 * call then failed confusingly or hung behind the connectedToElectrum guard.
 */

import { expect } from 'chai';
import net from 'net';
import tls from 'tls';
import {
	EAvailableNetworks,
	EElectrumNetworks,
	EProtocol,
	Wallet
} from '../src';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

// Unreachable on purpose: these tests must work offline.
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

// A second unreachable server, so field-update assertions can prove a change.
const otherServer = {
	host: '127.0.0.1',
	ssl: 65527,
	tcp: 65527,
	protocol: EProtocol.tcp
};

const network = EAvailableNetworks.regtest;

describe('connectToElectrum failure reporting', function () {
	this.timeout(60000);

	let wallet: Wallet;

	before(async function () {
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			network,
			electrumOptions
		});
		if (res.isErr()) throw res.error;
		wallet = res.value;
	});

	after(async function () {
		await wallet?.stop();
	});

	it('returns err when every server fails outside a network switch', async function () {
		const res = await wallet.electrum.connectToElectrum({
			network,
			servers: electrumOptions.servers
		});
		expect(res.isErr()).to.equal(true);
		expect(wallet.electrum.connectedToElectrum).to.equal(false);
	});

	it('returns err when every server fails DURING a network switch', async function () {
		wallet.isSwitchingNetworks = true;
		try {
			const res = await wallet.electrum.connectToElectrum({
				network,
				servers: electrumOptions.servers
			});
			// The old code returned ok('Connected to Electrum server.') here.
			expect(res.isErr()).to.equal(true);
			expect(wallet.electrum.connectedToElectrum).to.equal(false);
		} finally {
			wallet.isSwitchingNetworks = false;
		}
	});

	it('clears a stale connected state when every server fails during a switch', async function () {
		// publishConnectionChange used to suppress the internal state
		// assignment during a switch along with the event, so a previously
		// true connectedToElectrum survived the failed connect.
		wallet.electrum.connectedToElectrum = true;
		wallet.isSwitchingNetworks = true;
		try {
			const res = await wallet.electrum.connectToElectrum({
				network,
				servers: electrumOptions.servers
			});
			expect(res.isErr()).to.equal(true);
			expect(wallet.electrum.connectedToElectrum).to.equal(false);
		} finally {
			wallet.isSwitchingNetworks = false;
		}
	});

	// Last on purpose: it leaves the shared wallet pointed at testnet.
	it('still updates the network fields on a failed switch connect', async function () {
		// The switch exemption's legitimate purpose: the fields move to the
		// TARGET network even when it has no reachable server, so the wallet
		// is not left half-switched. Only the success report was the lie.
		// attemptConnect is stubbed (its declared purpose): a testnet target
		// would otherwise fall back to the bundled PUBLIC testnet servers and
		// really connect, making an offline test nondeterministic.
		expect(wallet.electrum.network).to.equal(EAvailableNetworks.regtest);
		expect(wallet.electrum.electrumNetwork).to.equal(
			EElectrumNetworks.bitcoinRegtest
		);

		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const electrumAny = wallet.electrum as any;
		const originalAttempt = electrumAny.attemptConnect.bind(wallet.electrum);
		electrumAny.attemptConnect = async (): Promise<{ error: unknown }> => ({
			error: new Error('unreachable (stubbed)')
		});
		wallet.isSwitchingNetworks = true;
		try {
			const connectRes = await wallet.electrum.connectToElectrum({
				network: EAvailableNetworks.testnet,
				servers: otherServer
			});
			expect(connectRes.isErr()).to.equal(true);

			// All three fields moved to the target values despite the failure.
			expect(wallet.electrum.network).to.equal(EAvailableNetworks.testnet);
			expect(wallet.electrum.electrumNetwork).to.equal(
				EElectrumNetworks.bitcoinTestnet
			);
			expect(wallet.electrum.servers).to.deep.equal([otherServer]);
		} finally {
			wallet.isSwitchingNetworks = false;
			electrumAny.attemptConnect = originalAttempt;
		}
	});
});
