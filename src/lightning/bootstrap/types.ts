/**
 * BOLT 10: DNS-based peer discovery types.
 */

export interface IPeerAddress {
	/** 33-byte compressed public key */
	pubkey: Buffer;
	/** Hostname or IP address */
	host: string;
	/** Port number */
	port: number;
}

export interface IDnsSeedConfig {
	/** DNS seed hostname */
	hostname: string;
	/** Optional port override (default 9735) */
	defaultPort?: number;
}

export interface IBootstrapConfig {
	/** DNS seeds to query */
	seeds?: IDnsSeedConfig[];
	/** Maximum peers to return */
	maxPeers?: number;
	/** DNS lookup timeout in ms */
	timeoutMs?: number;
}
