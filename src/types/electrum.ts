import type { Network } from '../network';
import type {
	IAddress,
	IGetAddressBalanceRes,
	ITransaction,
	IUtxo
} from './wallet';

export type Net = typeof import('net');
export type Tls = typeof import('tls');

/**
 * The names rn-electrum-client keys its per-network state by, which is why
 * they differ from {@link Network}'s values. `toElectrumNetwork` maps one to
 * the other.
 */
export enum EElectrumNetworks {
	bitcoin = 'bitcoin',
	bitcoinTestnet = 'bitcoinTestnet',
	bitcoinRegtest = 'bitcoinRegtest',
	bitcoinSignet = 'bitcoinSignet'
}
export type TConnectToElectrumRes = string;

export interface IElectrumGetAddressBalanceRes extends IGetAddressBalanceRes {
	error: boolean;
}

export type TServer = {
	host: string;
	ssl: number;
	tcp: number;
	protocol: EProtocol;
};
export enum EProtocol {
	tcp = 'tcp',
	ssl = 'ssl'
}
/**
 * @deprecated Use {@link EProtocol}. Removed in the next major release.
 */
export type TProtocol = `${EProtocol}`;

/** How a wallet reaches Electrum: `electrumOptions` on `Wallet.create`. */
export interface IElectrumOptions {
	/** Node's `net` module, or `react-native-tcp-socket` on React Native. */
	net: Net;
	/**
	 * Node's `tls` module, or `react-native-tcp-socket` on React Native.
	 *
	 * With the plain module a TLS connection is encrypted but the server
	 * certificate is not checked, because rn-electrum-client dials with
	 * `rejectUnauthorized: false`, so an on-path attacker can stand in for the
	 * server. On Node, pass `withTlsVerification(tls)` to check it. React
	 * Native cannot verify yet.
	 */
	tls: Tls;
	/**
	 * Servers to connect to, tried in order. Required on regtest, and when
	 * `disableFallbackServers` is set.
	 */
	servers?: TServer | TServer[];
	/** Maximum number of requests sent in a single batch. Defaults to 20. */
	batchLimit?: number;
	/** Delay in milliseconds between batches. Defaults to 50. */
	batchDelay?: number;
	/**
	 * Never connect to the built-in public servers. By default, once every
	 * server in `servers` has failed (or when none is given), the wallet tries
	 * public servers for its network, and those learn every address the wallet
	 * watches. With this set the connect fails instead, and the connection
	 * poll keeps retrying `servers`. Regtest never uses public servers.
	 *
	 * Wallets on one network in a process share one connection, so while any
	 * of them sets this, none of them falls back to public servers.
	 */
	disableFallbackServers?: boolean;
}

export enum EScanningStrategy {
	all = 'all', // Scan all addresses/scripthashes
	gapLimit = 'gapLimit', // Adhere to the gap limit within range of the provided index when scanning addresses/scripthashes. If higher than the current index, it will be ignored
	startingIndex = 'startingIndex', // Scan all addresses/scripthashes starting from the provided index. If higher than the current index, it will be ignored
	singleIndex = 'singleIndex' // Scan the single provided address/scripthash
}

export interface IGetUtxosResponse {
	utxos: IUtxo[];
	balance: number;
}

export type TUnspentAddressScriptHashData = {
	[x: string]: IUtxo | IAddress;
};

export type TTxResult = {
	tx_hash: string;
	height: number;
};

export interface IGetAddressScriptHashesHistoryResponse {
	data: TTxResponse[];
	error: boolean;
	id: number;
	method: string;
	network: string;
}

export type TTxResponse = {
	data: IAddress;
	id: number;
	jsonrpc: string;
	param: string;
	result: TTxResult[];
};

export interface IGetAddressTxResponse {
	data: TAddressTxResponse[];
	error: boolean;
	id: number;
	method: string;
	network: string;
}
export type TAddressTxResponse = {
	data: string;
	id: number;
	jsonrpc: string;
	param: string;
	result: TTxResult[];
	error?: { code: number; message: string };
};

export interface IGetAddressScriptHashBalances {
	error: boolean;
	data:
		| Array<{
				id: number;
				jsonrpc: string;
				result: {
					confirmed: number;
					unconfirmed: number;
				};
				param: string;
				data: Record<string, unknown>;
		  }>
		| string;
	id: number;
	method: string;
	network: EElectrumNetworks;
}

export interface IGetAddressHistoryResponse extends TTxResult, IAddress {}

export interface IHeader {
	height: number;
	hash: string;
	hex: string;
}

export interface INewBlock {
	height: number;
	hex: string;
}

export interface IGetHeaderResponse {
	id: number;
	error: boolean;
	method: 'getHeader';
	data: string;
	network: Network;
}

export interface IGetTransactionsFromInputs {
	error: boolean;
	id: number;
	method: string;
	network: string;
	data: ITransaction<{
		tx_hash: string;
		vout: number;
	}>[];
}

export interface ISubscribeToHeader {
	data: {
		height: number;
		hex: string;
	};
	error: boolean;
	id: string;
	method: string;
}

export interface ISubscribeToAddress {
	data: {
		id: number;
		jsonrpc: string;
		result: null;
	};
	error: boolean;
	id: number;
	method: string;
}

export type TSubscribedReceive = [string, string];

export interface IFormattedPeerData {
	ip?: string;
	host: string;
	version?: string;
	ssl: string | number;
	tcp: string | number;
}

export interface IPeerData {
	host: string;
	port: string;
	protocol: `${EProtocol}`;
}

export type ElectrumConnectionPubSub = {
	publish: (isConnected: boolean) => void;
	subscribe: (
		callback: (isConnected: boolean) => void
	) => ElectrumConnectionSubscription;
};

export type ElectrumConnectionSubscription = {
	remove(): void;
};

export type TGetAddressHistory = { txid: string; height: number };

export type TUnspentAddressScriptHash = {
	height: number;
	tx_hash: string;
	tx_pos: number;
	value: number;
};

export type TUnspentAddressScriptHashResult = {
	id: number;
	jsonrpc: string;
	result: TUnspentAddressScriptHash[];
	param: string;
	data: IAddress;
};

export type TUnspentAddressScriptHashResponse = {
	id: number;
	error: boolean;
	method: string;
	data: TUnspentAddressScriptHashResult[];
	network: string;
};
