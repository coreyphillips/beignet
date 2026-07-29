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
import { EAvailableNetworks, EProtocol, Wallet } from '../src';

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

	it('still updates the network fields on a failed switch connect', async function () {
		// The switch exemption's legitimate purpose: the fields move to the
		// target network even when it has no reachable server, so the wallet
		// is not left half-switched. Only the success report was the lie.
		wallet.isSwitchingNetworks = true;
		try {
			await wallet.electrum.connectToElectrum({
				network,
				servers: electrumOptions.servers
			});
			expect(wallet.electrum.network).to.equal(network);
		} finally {
			wallet.isSwitchingNetworks = false;
		}
	});
});
