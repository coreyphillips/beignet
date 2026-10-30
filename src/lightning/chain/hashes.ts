/** Bitcoin genesis hashes in the internal byte order used by BOLT messages. */

/** Bitcoin mainnet chain hash */
export const BITCOIN_CHAIN_HASH = Buffer.from(
	'6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000',
	'hex'
);

/** Bitcoin regtest chain hash */
export const REGTEST_CHAIN_HASH = Buffer.from(
	'06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f',
	'hex'
);

/** Bitcoin signet chain hash (genesis hash, internal byte order) */
export const SIGNET_CHAIN_HASH = Buffer.from(
	'f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000',
	'hex'
);

/** Bitcoin testnet3 chain hash (genesis hash, internal byte order) */
export const TESTNET_CHAIN_HASH = Buffer.from(
	'43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000',
	'hex'
);
