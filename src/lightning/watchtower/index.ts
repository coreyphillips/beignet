/**
 * Watchtower client: ships encrypted justice data to remote LND altruist towers
 * so a breach is punished even while this node is offline.
 */

export * from './types';
export * from './wtwire';
export * from './blob';
export * from './justice';
export { TowerConnection, parseTowerUri } from './tower-connection';
export {
	WatchtowerClient,
	IWatchtowerClientOptions,
	IWatchtowerStore
} from './watchtower-client';

import * as bitcoin from 'bitcoinjs-lib';

/**
 * Genesis block hashes in internal (chainhash) byte order, matching the value
 * LND puts in the wtwire Init chain_hash field.
 */
const GENESIS_HASHES: Record<string, string> = {
	bitcoin: '6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000',
	testnet: '43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000',
	// Internal order like the rest (the display-order form of this hash is
	// 0f9188f1...e206). A live LND tower rejects the reversed form with
	// "remote init has unknown chain hash".
	regtest: '06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f',
	signet: 'f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000'
};

/** Resolve the wtwire chain_hash for a bitcoinjs network. */
export function chainHashForNetwork(network: bitcoin.Network): Buffer {
	let name = 'bitcoin';
	if (network === bitcoin.networks.testnet) name = 'testnet';
	else if (network === bitcoin.networks.regtest) name = 'regtest';
	return Buffer.from(GENESIS_HASHES[name], 'hex');
}
