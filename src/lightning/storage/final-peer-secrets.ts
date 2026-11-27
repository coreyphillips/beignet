/**
 * The peer's revocation secrets, looked up per height over every ledger a
 * channel has had (#2151 step 2b): the records' shachains, the plain log and
 * the asset journal. This module holds the pure parts and the warning hook
 * through which a disagreement between sources reaches the chain watcher.
 */
import { sha256 } from '../crypto/provider';
import { MAX_INDEX } from '../keys/shachain';
import type { IFinalLedgerState } from './final-channel-updates';

/** One height's secret, matched to the commitment point, and whether the sources disagree. */
export interface IFinalPeerSecret {
	secret: Buffer | null;
	conflict: boolean;
}

/** The BOLT 3 derivation of the peer secret for `height` from shachain buckets, or null. */
export function shachainSecret(
	shachain: IFinalLedgerState['shachain'] | undefined,
	height: bigint
): Buffer | null {
	if (!shachain || height < 0n || height >= MAX_INDEX) return null;
	const index = MAX_INDEX - height;
	for (let bucket = 0; bucket < shachain.length; bucket++) {
		const entry = shachain[bucket];
		if (!entry) continue;
		const stored = MAX_INDEX - BigInt(entry.height);
		const bits = BigInt(bucket);
		if (index >> bits !== stored >> bits) continue;
		let derived = Buffer.from(entry.secret, 'hex');
		for (let bit = bucket - 1; bit >= 0; bit--)
			if ((index >> BigInt(bit)) & 1n) {
				derived = Buffer.from(derived);
				derived[bit >> 3] ^= 1 << bit % 8;
				derived = sha256(derived);
			}
		return derived;
	}
	return null;
}

/** Every height below `below` that the buckets derive. */
export function shachainSecrets(
	shachain: IFinalLedgerState['shachain'] | undefined,
	below: bigint
): Map<bigint, Buffer> {
	const out = new Map<bigint, Buffer>();
	for (let h = 0n; h < below; h++) {
		const secret = shachainSecret(shachain, h);
		if (secret) out.set(h, secret);
	}
	return out;
}

export interface IFinalPeerSecretConflict {
	channelId: string;
	height: bigint;
}
const sinks: ((c: IFinalPeerSecretConflict) => void)[] = [];

/**
 * The storage warning hook: a reader that sees two sources disagree for one
 * height notes it here, and never throws on the claim path.
 */
export function noteFinalPeerSecretConflict(
	channelId: string,
	height: bigint
): void {
	for (const sink of sinks) sink({ channelId, height });
}

/** Run a synchronous claim build and collect the conflicts its secret lookups noted. */
export function collectFinalPeerSecretConflicts<T>(run: () => T): {
	value: T;
	conflicts: IFinalPeerSecretConflict[];
} {
	const conflicts: IFinalPeerSecretConflict[] = [];
	const sink = (c: IFinalPeerSecretConflict): void => {
		if (
			!conflicts.some(
				(o) => o.channelId === c.channelId && o.height === c.height
			)
		)
			conflicts.push(c);
	};
	sinks.push(sink);
	try {
		return { value: run(), conflicts };
	} finally {
		sinks.splice(sinks.indexOf(sink), 1);
	}
}
