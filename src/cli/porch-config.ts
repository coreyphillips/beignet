/**
 * The daemon's Porch settings: the relays this node waits at and how it
 * reaches them. Which links it serves is state the daemon keeps
 * (porch-links.ts), not configuration.
 */
import {
	PORCH_MAX_TOKEN_BYTES,
	parsePorchRelayUrl
} from '../lightning/transport/porch';
import type {
	IPorchRelayConfig,
	PorchVia
} from '../lightning/transport/porch-host';
import { MAX_PORCH_STANDBYS } from '../lightning/transport/porch-host';

export interface PorchDaemonConfig {
	/**
	 * Porch relays to wait at, so the node can hand out `wss://` peer links
	 * that do not say where it runs. Each is a relay URL (`wss://host[:port]`),
	 * or `{ url, token }` for a relay that asks a node for a token. Unset or
	 * empty leaves Porch off.
	 */
	porchRelays?: (string | IPorchRelayConfig)[];
	/**
	 * How the relays are dialed. `tor` sends every relay connection through
	 * the SOCKS5 proxy (torProxy, else 127.0.0.1:9050), so the relay does not
	 * learn the node's address either. `direct` dials them directly whatever
	 * torProxy says. Unset dials a relay as any other peer at that host.
	 */
	porchVia?: PorchVia;
	/**
	 * Idle connections kept at each relay. Each one takes one visitor, and is
	 * replaced when it does. Default 2, at most 8.
	 */
	porchStandbys?: number;
	/**
	 * The token of a private relay, when exactly one relay is configured.
	 * With several, each relay's token goes in its own porchRelays entry.
	 */
	porchToken?: string;
}

/** `BEIGNET_PORCH_RELAYS`: comma-separated relay URLs. Empty turns Porch off. */
export function porchRelaysEnv(): string[] | undefined {
	return process.env.BEIGNET_PORCH_RELAYS?.split(',')
		.map((url) => url.trim())
		.filter(Boolean);
}

/** `BEIGNET_PORCH_VIA`: exactly `direct` or `tor`. */
export function porchViaEnv(): PorchVia | undefined {
	const value = process.env.BEIGNET_PORCH_VIA;
	if (value === undefined || value === '') return undefined;
	if (value === 'direct' || value === 'tor') return value;
	throw new Error('BEIGNET_PORCH_VIA must be exactly direct or tor');
}

/** `BEIGNET_PORCH_STANDBYS`: a whole number. */
export function porchStandbysEnv(): number | undefined {
	const value = process.env.BEIGNET_PORCH_STANDBYS;
	if (value === undefined || value === '') return undefined;
	if (!/^\d{1,4}$/.test(value)) {
		throw new Error('BEIGNET_PORCH_STANDBYS must be a whole number');
	}
	return parseInt(value, 10);
}

function checkToken(name: string, token: unknown): void {
	if (
		typeof token !== 'string' ||
		token.length === 0 ||
		Buffer.byteLength(token) > PORCH_MAX_TOKEN_BYTES
	) {
		throw new Error(
			`${name} must be a string of 1 to ${PORCH_MAX_TOKEN_BYTES} bytes`
		);
	}
}

/**
 * The relays as the node takes them, each with the token it is sent. Empty
 * when Porch is off. Throws on a relay that is not a relay URL, one listed
 * twice, or a token that would go to a relay it was not written for.
 */
export function porchRelayEntries(
	config: PorchDaemonConfig
): IPorchRelayConfig[] {
	const listed = config.porchRelays;
	if (listed === undefined) return [];
	if (!Array.isArray(listed)) {
		throw new Error(
			'porchRelays must be an array of relay URLs or { url, token } entries'
		);
	}
	const entries: IPorchRelayConfig[] = [];
	const seen = new Set<string>();
	for (const item of listed as unknown[]) {
		let url: unknown;
		let token: unknown;
		if (typeof item === 'string') url = item;
		else if (
			item !== null &&
			typeof item === 'object' &&
			!Array.isArray(item)
		) {
			({ url, token } = item as { url?: unknown; token?: unknown });
		}
		if (typeof url !== 'string') {
			throw new Error(
				'porchRelays must be an array of relay URLs or { url, token } entries'
			);
		}
		const relay = parsePorchRelayUrl(url);
		if (seen.has(relay.authority)) {
			throw new Error(`porchRelays lists ${relay.authority} twice`);
		}
		seen.add(relay.authority);
		if (token !== undefined)
			checkToken(`The token of ${relay.authority}`, token);
		entries.push({
			url,
			...(token !== undefined ? { token: token as string } : {})
		});
	}
	if (config.porchToken !== undefined && entries.length > 0) {
		// A token is a credential for one relay. Sent to every relay listed,
		// it would be disclosed to each of the others.
		if (entries.length > 1) {
			throw new Error(
				'porchToken is the token of a single relay. With several relays, ' +
					'give each its own as a { url, token } entry in porchRelays'
			);
		}
		if (entries[0].token !== undefined) {
			throw new Error(
				'The relay has a token in porchRelays and porchToken sets another; ' +
					'set one'
			);
		}
		entries[0] = { ...entries[0], token: config.porchToken };
	}
	return entries;
}

/** Everything about the Porch settings that can be checked without a node. */
export function validatePorchConfig(config: PorchDaemonConfig): void {
	if (config.porchToken !== undefined) {
		checkToken('porchToken', config.porchToken);
	}
	porchRelayEntries(config);
	if (
		config.porchVia !== undefined &&
		config.porchVia !== 'direct' &&
		config.porchVia !== 'tor'
	) {
		throw new Error("porchVia must be 'direct' or 'tor'");
	}
	const standbys = config.porchStandbys;
	if (
		standbys !== undefined &&
		(typeof standbys !== 'number' ||
			!Number.isInteger(standbys) ||
			standbys < 1 ||
			standbys > MAX_PORCH_STANDBYS)
	) {
		throw new Error(
			`porchStandbys must be a whole number from 1 to ${MAX_PORCH_STANDBYS}`
		);
	}
}
