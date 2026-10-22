import { Network as BitcoinJsNetwork, networks } from 'bitcoinjs-lib';
import { EElectrumNetworks } from './types/electrum';

/**
 * The Bitcoin network a wallet runs on. The values are part of the wallet's
 * storage keys (`${name}-${network}-${key}`), so they never change.
 */
export enum Network {
	bitcoin = 'bitcoin',
	testnet = 'testnet',
	regtest = 'regtest',
	signet = 'signet'
}

/** Typed `never` so a network missing from an adapter's switch fails to compile. */
const unknownNetwork = (network: never): never => {
	throw new Error(`Unknown network: ${String(network)}`);
};

/**
 * Signet shares testnet's address prefixes, bech32 hrp ('tb') and BIP32
 * versions; only the genesis block differs, so bitcoinjs-lib ships no
 * dedicated network entry for it.
 */
const signetNetwork: BitcoinJsNetwork = { ...networks.testnet };

/**
 * Returns the bitcoinjs-lib parameters for a network.
 * @param {Network} network
 * @returns {BitcoinJsNetwork}
 */
export const toBitcoinJsNetwork = (network: Network): BitcoinJsNetwork => {
	switch (network) {
		case Network.bitcoin:
			return networks.bitcoin;
		case Network.testnet:
			return networks.testnet;
		case Network.regtest:
			return networks.regtest;
		case Network.signet:
			return signetNetwork;
		default:
			return unknownNetwork(network);
	}
};

/**
 * Returns the key rn-electrum-client files a network's connection under.
 * @param {Network} network
 * @returns {EElectrumNetworks}
 */
export const toElectrumNetwork = (network: Network): EElectrumNetworks => {
	switch (network) {
		case Network.bitcoin:
			return EElectrumNetworks.bitcoin;
		case Network.testnet:
			return EElectrumNetworks.bitcoinTestnet;
		case Network.regtest:
			return EElectrumNetworks.bitcoinRegtest;
		case Network.signet:
			return EElectrumNetworks.bitcoinSignet;
		default:
			return unknownNetwork(network);
	}
};
