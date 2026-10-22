import { expect } from 'chai';
import { networks } from 'bitcoinjs-lib';

import {
	availableNetworks,
	EAvailableNetworks,
	EElectrumNetworks,
	getBitcoinJsNetwork,
	getElectrumNetwork,
	Network,
	TAvailableNetworks,
	toBitcoinJsNetwork,
	toElectrumNetwork
} from '../src';

describe('Network', () => {
	it('availableNetworks lists each network once', () => {
		expect(availableNetworks()).to.deep.equal([
			Network.bitcoin,
			Network.testnet,
			Network.regtest,
			Network.signet
		]);
	});

	it('keeps the values wallet storage keys are built from', () => {
		expect(Object.values(Network)).to.deep.equal([
			'bitcoin',
			'testnet',
			'regtest',
			'signet'
		]);
	});

	it('maps each network to its Electrum client key', () => {
		expect(availableNetworks().map(toElectrumNetwork)).to.deep.equal([
			EElectrumNetworks.bitcoin,
			EElectrumNetworks.bitcoinTestnet,
			EElectrumNetworks.bitcoinRegtest,
			EElectrumNetworks.bitcoinSignet
		]);
	});

	it('maps each network to bitcoinjs-lib parameters', () => {
		expect(toBitcoinJsNetwork(Network.bitcoin)).to.equal(networks.bitcoin);
		expect(toBitcoinJsNetwork(Network.testnet)).to.equal(networks.testnet);
		expect(toBitcoinJsNetwork(Network.regtest)).to.equal(networks.regtest);
		// Signet has no bitcoinjs-lib entry and shares testnet's parameters.
		expect(toBitcoinJsNetwork(Network.signet)).to.deep.equal(networks.testnet);
	});

	it('throws on a value that is not a Network instead of picking one', () => {
		const typo = 'mainnet' as Network;
		expect(() => toElectrumNetwork(typo)).to.throw('Unknown network: mainnet');
		expect(() => toBitcoinJsNetwork(typo)).to.throw('Unknown network: mainnet');
	});

	describe('deprecated aliases', () => {
		it('spell the same four values', () => {
			expect([
				EAvailableNetworks.bitcoin,
				EAvailableNetworks.mainnet,
				EAvailableNetworks.bitcoinMainnet
			]).to.deep.equal([Network.bitcoin, Network.bitcoin, Network.bitcoin]);
			expect([
				EAvailableNetworks.testnet,
				EAvailableNetworks.bitcoinTestnet
			]).to.deep.equal([Network.testnet, Network.testnet]);
			expect([
				EAvailableNetworks.regtest,
				EAvailableNetworks.bitcoinRegtest
			]).to.deep.equal([Network.regtest, Network.regtest]);
			expect([
				EAvailableNetworks.signet,
				EAvailableNetworks.bitcoinSignet
			]).to.deep.equal([Network.signet, Network.signet]);
		});

		// The assignments are the test: tsc:check:tests fails if the aliases
		// stop being interchangeable with Network the way the old enum was.
		it('type-check as Network in both directions', () => {
			const fromAlias: Network = EAvailableNetworks.bitcoinTestnet;
			const toAlias: EAvailableNetworks = Network.testnet;
			// Widens to Network like an enum member, so reassignment compiles.
			let widened = EAvailableNetworks.testnet;
			widened = Network.regtest;
			const memberAsType: EAvailableNetworks.mainnet = Network.bitcoin;
			const literal: TAvailableNetworks = Network.signet;
			expect([
				fromAlias,
				toAlias,
				widened,
				memberAsType,
				literal
			]).to.deep.equal(['testnet', 'testnet', 'regtest', 'bitcoin', 'signet']);
		});

		it('route the old adapters through the new ones', () => {
			expect(getElectrumNetwork(EAvailableNetworks.signet)).to.equal(
				EElectrumNetworks.bitcoinSignet
			);
			expect(getBitcoinJsNetwork('regtest')).to.equal(networks.regtest);
		});
	});
});
