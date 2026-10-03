/**
 * Peer connection URI parsing.
 *
 * Standard Lightning form:      pubkey@host:port         (TCP — unchanged)
 * WebSocket forms (additive):   pubkey@ws://host:port    (RFC 6455 client)
 *                               pubkey@wss://host:port
 * Iroh form:                    pubkey@iroh:<endpoint-id>?relay=<url>
 */

import { IPeerTransportOptions } from './duplex-transport';
import { parseWebSocketUrl } from './websocket';
import { parseIrohAddress } from './iroh';

export interface IParsedPeerUri {
	/** 33-byte compressed pubkey, lowercase hex. */
	pubkey: string;
	host: string;
	port: number;
	/** Present for WebSocket and Iroh URIs; absent means plain TCP. */
	transport?: IPeerTransportOptions;
}

/**
 * Parse a `pubkey@address` peer URI. The address part is either a plain
 * `host:port` (TCP), a ws:// / wss:// URL, or an iroh: endpoint address.
 */
export function parsePeerUri(uri: string): IParsedPeerUri {
	const at = uri.indexOf('@');
	if (at < 0) {
		throw new Error(`Invalid peer URI (missing @): ${uri}`);
	}
	const pubkey = uri.slice(0, at).toLowerCase();
	if (!/^[0-9a-f]{66}$/.test(pubkey)) {
		throw new Error(`Invalid peer pubkey in URI: ${uri}`);
	}
	const address = uri.slice(at + 1);

	if (/^iroh:/i.test(address)) {
		const parsed = parseIrohAddress(address);
		return {
			pubkey,
			host: parsed.endpointId,
			port: 0,
			transport: { type: 'iroh', ...parsed }
		};
	}

	if (/^wss?:\/\//i.test(address)) {
		const { host, port } = parseWebSocketUrl(address);
		return {
			pubkey,
			host,
			port,
			transport: { type: 'ws', url: address }
		};
	}

	const lastColon = address.lastIndexOf(':');
	if (lastColon < 0) {
		throw new Error(`Invalid peer URI (missing port): ${uri}`);
	}
	// Allow bracketed IPv6: pubkey@[::1]:9735
	const host = address.slice(0, lastColon).replace(/^\[|\]$/g, '');
	const port = parseInt(address.slice(lastColon + 1), 10);
	if (!host || !Number.isInteger(port) || port <= 0 || port > 65535) {
		throw new Error(`Invalid peer host/port in URI: ${uri}`);
	}
	return { pubkey, host, port };
}
