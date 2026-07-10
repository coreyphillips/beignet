import { EElectrumNetworks, EProtocol, TMessageKeys, TServer } from '../types';

export const onMessageKeys: { [K in TMessageKeys]: K } = {
	newBlock: 'newBlock',
	transactionReceived: 'transactionReceived',
	transactionConfirmed: 'transactionConfirmed',
	transactionSent: 'transactionSent',
	rbf: 'rbf',
	reorg: 'reorg',
	connectedToElectrum: 'connectedToElectrum'
};

export const POLLING_INTERVAL = 1000 * 10;

/**
 * How long a failed Electrum server is skipped during rotation before it may
 * be retried, so reconnect attempts do not hammer a dead server.
 */
export const ELECTRUM_SERVER_COOLDOWN_MS = 1000 * 60;

/**
 * Fallback Electrum peers per network, tried after any user-provided servers.
 * Mirrors rn-electrum-client/helpers/peers.json plus networks the library
 * lacks (signet). Regtest is intentionally absent: a regtest wallet must
 * pre-specify its server, never silently reach an external host.
 */
export const defaultElectrumPeers: Partial<
	Record<EElectrumNetworks, TServer[]>
> = {
	[EElectrumNetworks.bitcoin]: [
		{ host: '35.187.18.233', ssl: 8900, tcp: 8911, protocol: EProtocol.ssl },
		{
			host: 'electrum.aantonop.com',
			ssl: 50002,
			tcp: 50001,
			protocol: EProtocol.ssl
		},
		{ host: 'bitcoin.lu.ke', ssl: 50002, tcp: 50001, protocol: EProtocol.ssl },
		{
			host: 'kirsche.emzy.de',
			ssl: 50002,
			tcp: 50001,
			protocol: EProtocol.ssl
		}
	],
	[EElectrumNetworks.bitcoinTestnet]: [
		{
			host: 'testnet.aranguren.org',
			ssl: 51002,
			tcp: 51001,
			protocol: EProtocol.ssl
		}
	],
	[EElectrumNetworks.bitcoinSignet]: [
		{ host: 'mempool.space', ssl: 60602, tcp: 60601, protocol: EProtocol.ssl }
	]
};
