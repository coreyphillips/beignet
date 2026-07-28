/**
 * Regression: Electrum.getUtxos must SKIP an address type with no generated
 * addresses, not abandon the rest of the scan.
 *
 * The loop's own comment said "If not, skip" but the code was `break`, so the
 * first monitored type with zero generated addresses dropped every LATER type
 * from the query. EAddressType orders p2tr last, so a wallet whose primary type
 * is p2tr but which has never generated p2sh addresses got back zero UTXOs for
 * its own addresses, which is indistinguishable from having no funds.
 *
 * Fully OFFLINE: the wallet points at an unreachable port and the final
 * listUnspentAddressScriptHashes call is stubbed, so this asserts on the set of
 * addresses the scan actually assembled.
 */

import { expect } from 'chai';
import net from 'net';
import tls from 'tls';
import sinon from 'sinon';

import { EAddressType, EAvailableNetworks, EProtocol, Wallet } from '../src';

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

describe('getUtxos address-type scan', function () {
	this.timeout(60000);

	const MONITORED = [EAddressType.p2wpkh, EAddressType.p2sh, EAddressType.p2tr];

	let wallet: Wallet;

	// Fresh wallet per test: the cases mutate the address book, and address
	// generation after Wallet.create is asynchronous, so each test populates
	// what it needs rather than racing the background fill.
	beforeEach(async function () {
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			network: EAvailableNetworks.regtest,
			addressType: EAddressType.p2tr,
			addressTypesToMonitor: MONITORED,
			electrumOptions
		});
		if (res.isErr()) throw res.error;
		wallet = res.value;

		for (const addressType of MONITORED) {
			const gen = await wallet.generateAddresses({
				addressAmount: 5,
				changeAddressAmount: 5,
				addressType
			});
			if (gen.isErr()) throw gen.error;
			wallet.data.addresses[addressType] = gen.value.addresses;
			wallet.data.changeAddresses[addressType] = gen.value.changeAddresses;
			expect(
				Object.keys(wallet.data.addresses[addressType]).length,
				`${addressType} addresses were generated`
			).to.be.greaterThan(0);
		}
	});

	afterEach(function () {
		sinon.restore();
	});

	it('still scans later address types when an earlier one has no addresses', async function () {
		const electrum = wallet.electrum;

		// p2sh sits between p2wpkh and p2tr in the monitor list. Empty it, as it
		// would be on a wallet that never generated addresses of that type.
		wallet.data.addresses[EAddressType.p2sh] = {};
		wallet.data.changeAddresses[EAddressType.p2sh] = {};

		const p2trAddresses = Object.values(
			wallet.data.addresses[EAddressType.p2tr]
		);
		expect(
			p2trAddresses.length,
			'the wallet has p2tr addresses to find'
		).to.be.greaterThan(0);

		// Capture the address set the scan assembles instead of hitting a server.
		const stub = sinon
			.stub(
				electrum as unknown as {
					listUnspentAddressScriptHashes: (a: unknown) => unknown;
				},
				'listUnspentAddressScriptHashes'
			)
			.resolves({
				isOk: (): boolean => true,
				value: { utxos: [], balance: 0 }
			});

		// Skip the connection attempt; this test is about the scan loop.
		(
			electrum as unknown as { connectedToElectrum: boolean }
		).connectedToElectrum = true;

		await electrum.getUtxos({});

		expect(stub.calledOnce, 'the scan reached the lookup').to.equal(true);
		const scanned = Object.values(
			(
				stub.firstCall.args[0] as {
					addresses: Record<string, { address: string }>;
				}
			).addresses
		).map((a) => a.address);

		const p2trScanned = p2trAddresses.filter((a) =>
			scanned.includes(a.address)
		);
		expect(
			p2trScanned.length,
			'p2tr addresses survived the empty p2sh type ahead of them'
		).to.be.greaterThan(0);
	});

	it('scans every monitored type when none are empty', async function () {
		const electrum = wallet.electrum;

		const stub = sinon
			.stub(
				electrum as unknown as {
					listUnspentAddressScriptHashes: (a: unknown) => unknown;
				},
				'listUnspentAddressScriptHashes'
			)
			.resolves({
				isOk: (): boolean => true,
				value: { utxos: [], balance: 0 }
			});
		(
			electrum as unknown as { connectedToElectrum: boolean }
		).connectedToElectrum = true;

		await electrum.getUtxos({});

		const scanned = Object.values(
			(
				stub.firstCall.args[0] as {
					addresses: Record<string, { address: string }>;
				}
			).addresses
		).map((a) => a.address);

		for (const type of [EAddressType.p2wpkh, EAddressType.p2tr]) {
			const some = Object.values(wallet.data.addresses[type]).some((a) =>
				scanned.includes(a.address)
			);
			expect(some, `${type} addresses were scanned`).to.equal(true);
		}
	});
});
