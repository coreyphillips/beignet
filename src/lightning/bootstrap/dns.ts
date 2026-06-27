/**
 * BOLT 10: DNS-based peer discovery.
 *
 * Queries DNS SRV records for Lightning Network node discovery.
 * SRV record format: _lightning._tcp.<seed>
 *
 * Each SRV record's target hostname may encode a node pubkey
 * as a 66-character hex subdomain label.
 */

import dns from 'dns';
import { bech32 } from 'bech32';
import { IDnsSeedConfig, IPeerAddress } from './types';

/** Default Lightning Network port per BOLT 1. */
const DEFAULT_LIGHTNING_PORT = 9735;

/** Length of a hex-encoded compressed public key. */
const HEX_PUBKEY_LENGTH = 66;

/**
 * Parse an SRV record into a host and port.
 * Strips trailing dots from the hostname (DNS FQDN convention).
 */
export function parseSrvRecord(record: {
	name: string;
	port: number;
	priority: number;
	weight: number;
}): { host: string; port: number } {
	let host = record.name;
	// Strip trailing dot (DNS FQDN format)
	if (host.endsWith('.')) {
		host = host.slice(0, -1);
	}
	return { host, port: record.port };
}

/**
 * Resolve A records for a hostname.
 * Returns an array of IPv4 address strings.
 */
export function resolveARecords(hostname: string): Promise<string[]> {
	return new Promise((resolve, reject) => {
		dns.resolve4(hostname, (err, addresses) => {
			if (err) {
				reject(err);
			} else {
				resolve(addresses);
			}
		});
	});
}

/**
 * Resolve SRV records for a hostname.
 * Returns an array of SRV record objects.
 */
export function resolveSrvRecords(
	hostname: string
): Promise<
	Array<{ name: string; port: number; priority: number; weight: number }>
> {
	return new Promise((resolve, reject) => {
		dns.resolveSrv(hostname, (err, records) => {
			if (err) {
				reject(err);
			} else {
				resolve(records);
			}
		});
	});
}

/**
 * Try to extract a 33-byte compressed public key from an SRV target hostname.
 * Looks for a 66-char hex label in the hostname's subdomain parts.
 * Returns a zero-filled 33-byte Buffer if no pubkey is found.
 */
export function extractPubkeyFromHostname(hostname: string): Buffer {
	// Strip trailing dot
	const cleaned = hostname.endsWith('.') ? hostname.slice(0, -1) : hostname;
	const labels = cleaned.split('.');

	for (const label of labels) {
		// BOLT 10: Lightning DNS seeds encode the node id as a bech32 label with
		// the 'ln' human-readable prefix (e.g. ln1q...). Decode that to 33 bytes.
		if (label.toLowerCase().startsWith('ln1')) {
			try {
				const decoded = bech32.decode(label.toLowerCase(), 256);
				if (decoded.prefix === 'ln') {
					const bytes = Buffer.from(bech32.fromWords(decoded.words));
					if (bytes.length === 33 && (bytes[0] === 0x02 || bytes[0] === 0x03)) {
						return bytes;
					}
				}
			} catch {
				// Not a valid bech32 node id — fall through to other labels.
			}
		}

		// Legacy/alternate form: a 66-char hex label.
		if (label.length === HEX_PUBKEY_LENGTH && /^[0-9a-fA-F]+$/.test(label)) {
			const prefix = label.slice(0, 2);
			if (prefix === '02' || prefix === '03') {
				return Buffer.from(label, 'hex');
			}
		}
	}

	// No pubkey found — return placeholder
	return Buffer.alloc(33);
}

/**
 * Resolve a single DNS seed into peer addresses.
 *
 * 1. Queries SRV records for _lightning._tcp.<hostname>
 * 2. For each SRV record, extracts pubkey from hostname labels
 * 3. Resolves A records for each SRV target
 * 4. Combines pubkey + IP + port into IPeerAddress entries
 */
export async function resolveDnsSeed(
	seed: IDnsSeedConfig,
	timeoutMs?: number
): Promise<IPeerAddress[]> {
	const timeout = timeoutMs || 5000;
	const defaultPort = seed.defaultPort || DEFAULT_LIGHTNING_PORT;
	// BOLT 10: query SRV records on the seed domain directly (not under
	// _lightning._tcp). Targets are subdomains of the form ln1<bech32-nodeid>.<seed>.
	const srvDomain = seed.hostname;

	// Wrap the entire resolution in a timeout
	const result = await Promise.race([
		resolveSrvAndAddresses(srvDomain, defaultPort),
		new Promise<IPeerAddress[]>((_, reject) =>
			setTimeout(() => reject(new Error('DNS resolution timeout')), timeout)
		)
	]);

	return result;

	async function resolveSrvAndAddresses(
		domain: string,
		fallbackPort: number
	): Promise<IPeerAddress[]> {
		let srvRecords: Array<{
			name: string;
			port: number;
			priority: number;
			weight: number;
		}>;

		try {
			srvRecords = await resolveSrvRecords(domain);
		} catch {
			// SRV lookup failed — return empty
			return [];
		}

		if (!srvRecords || srvRecords.length === 0) {
			return [];
		}

		const resolvedPeers: IPeerAddress[] = [];

		// Resolve each SRV record in parallel
		const resolvePromises = srvRecords.map(async (record) => {
			const parsed = parseSrvRecord(record);
			const port = parsed.port || fallbackPort;
			const pubkey = extractPubkeyFromHostname(record.name);

			try {
				const addresses = await resolveARecords(parsed.host);
				for (const addr of addresses) {
					resolvedPeers.push({
						pubkey: Buffer.from(pubkey),
						host: addr,
						port
					});
				}
			} catch {
				// A record resolution failed for this SRV target — skip it
			}
		});

		await Promise.allSettled(resolvePromises);
		return resolvedPeers;
	}
}
