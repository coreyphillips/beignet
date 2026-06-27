/**
 * BOLT 10: Default DNS seeds and bootstrap aggregation.
 */
import { IDnsSeedConfig, IPeerAddress, IBootstrapConfig } from './types';
import { resolveDnsSeed } from './dns';

/** Well-known DNS seeds for Lightning mainnet. */
export const DEFAULT_DNS_SEEDS: IDnsSeedConfig[] = [
	{ hostname: 'nodes.lightning.directory' },
	{ hostname: 'lseed.bitcoinstats.com' },
	{ hostname: 'lseed.darosior.ninja' }
];

/**
 * Bootstrap peer discovery from multiple DNS seeds.
 * Queries all seeds in parallel, deduplicates by pubkey hex, returns up to maxPeers.
 */
export async function bootstrapPeers(
	config?: IBootstrapConfig
): Promise<IPeerAddress[]> {
	const seeds = config?.seeds || DEFAULT_DNS_SEEDS;
	const maxPeers = config?.maxPeers || 25;
	const timeoutMs = config?.timeoutMs || 5000;

	const results = await Promise.allSettled(
		seeds.map((seed) => resolveDnsSeed(seed, timeoutMs))
	);

	const seen = new Set<string>();
	const peers: IPeerAddress[] = [];

	for (const result of results) {
		if (result.status === 'fulfilled') {
			for (const peer of result.value) {
				const key = peer.pubkey.toString('hex');
				if (!seen.has(key)) {
					seen.add(key);
					peers.push(peer);
				}
			}
		}
	}

	// Shuffle for load distribution
	for (let i = peers.length - 1; i > 0; i--) {
		const j = Math.floor(Math.random() * (i + 1));
		[peers[i], peers[j]] = [peers[j], peers[i]];
	}

	return peers.slice(0, maxPeers);
}
