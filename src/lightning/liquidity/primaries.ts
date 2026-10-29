/**
 * Ranked receive primaries and the fill threshold (issue #1922, step 1).
 *
 * A wallet can hold channels with several primaries (LSPs) instead of
 * depending on one. The operator ranks them and sets one fill threshold in
 * sats. `selectReceiveTargets` is the rule that picks where a receive should
 * land:
 *
 *  1. The first primary, in rank order, whose balance is below the threshold.
 *  2. When every primary is at or above it, the one with the lowest balance,
 *     ties to the higher rank, so the channels stay level.
 *
 * "Balance" is our local balance summed over our usable channels with that
 * primary. A primary we have no channel with has a balance of zero, so it is
 * a valid target: receiving through it opens the channel.
 *
 * The function returns every primary in the order a receive should try them,
 * not only the first, so a caller whose target is down or declines has the
 * fallback order without asking again.
 *
 * `PrimariesStore` holds the list and the threshold and persists them through
 * the wallet-data slice of storage, the way the direct-funding records do, so
 * no new storage capability is needed.
 */

import { CodedError } from '../../utils/errors';
import { parsePeerUri } from '../transport/peer-uri';

/** Wallet-data key holding the ranked list and the threshold. */
export const PRIMARIES_STORAGE_KEY = 'liquidity:primaries';

/**
 * Entries held at once. The list is written whole on every change and walked
 * on every receive, so it needs a ceiling; no wallet needs more than this.
 */
export const MAX_PRIMARIES = 32;

export enum PrimariesErrorCode {
	INVALID_PRIMARY = 'INVALID_PRIMARY',
	DUPLICATE_PRIMARY = 'DUPLICATE_PRIMARY',
	UNKNOWN_PRIMARY = 'UNKNOWN_PRIMARY',
	INVALID_THRESHOLD = 'INVALID_THRESHOLD',
	INVALID_ORDER = 'INVALID_ORDER',
	TOO_MANY_PRIMARIES = 'TOO_MANY_PRIMARIES',
	PERSIST_FAILED = 'PERSIST_FAILED'
}

export class PrimariesError extends CodedError<PrimariesErrorCode> {
	constructor(code: PrimariesErrorCode, message: string) {
		super(code, message);
		this.name = 'PrimariesError';
	}
}

/** One primary. Rank is its position in the list, not a stored field. */
export interface IPrimary {
	/** 33-byte compressed node pubkey, lowercase hex. */
	pubkey: string;
	/** TCP address, when the primary is reached that way. */
	host?: string;
	port?: number;
	/**
	 * A full `pubkey@address` peer URI, for the transports a host and port
	 * cannot name (ws://, wss://, iroh:). Its pubkey must be this entry's.
	 */
	uri?: string;
}

export interface IPrimariesPolicy {
	/** Highest rank first. */
	primaries: IPrimary[];
	/**
	 * Sats of local balance a primary is filled to before receives move on to
	 * the next one. Null means no cap: the first-ranked primary always takes
	 * the receive.
	 */
	fillThresholdSat: number | null;
}

/** One primary as `selectReceiveTargets` ranks it. */
export interface IPrimaryCandidate {
	pubkey: string;
	/** 1-based position in the configured list. */
	rank: number;
	balanceSat: number;
	/** Whether this primary is below the threshold (always true with no cap). */
	belowThreshold: boolean;
}

/**
 * Every primary, in the order a receive should try them: those below the
 * threshold in rank order, then the rest by lowest balance, ties to the higher
 * rank. The first entry is the receive target. An empty list gives an empty
 * answer.
 *
 * `balances` maps a pubkey to its balance in sats; a primary missing from it
 * has no usable channel and counts as zero.
 */
export function selectReceiveTargets(
	policy: Readonly<IPrimariesPolicy>,
	balances: ReadonlyMap<string, number>
): IPrimaryCandidate[] {
	const threshold = policy.fillThresholdSat;
	const all = policy.primaries.map((p, i) => {
		const balanceSat = balances.get(p.pubkey) ?? 0;
		return {
			pubkey: p.pubkey,
			rank: i + 1,
			balanceSat,
			belowThreshold: threshold === null || balanceSat < threshold
		};
	});
	const below = all.filter((c) => c.belowThreshold);
	const full = all
		.filter((c) => !c.belowThreshold)
		.sort((a, b) => a.balanceSat - b.balanceSat || a.rank - b.rank);
	return [...below, ...full];
}

const PUBKEY_RE = /^0[23][0-9a-f]{64}$/;

function invalid(message: string): PrimariesError {
	return new PrimariesError(PrimariesErrorCode.INVALID_PRIMARY, message);
}

/**
 * Check one entry and return it normalized (lowercase pubkey, only the fields
 * it names). Throws `INVALID_PRIMARY` naming the field at fault.
 */
export function normalizePrimary(entry: unknown): IPrimary {
	if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
		throw invalid('a primary must be an object');
	}
	const { pubkey, host, port, uri } = entry as Record<string, unknown>;
	if (typeof pubkey !== 'string' || !PUBKEY_RE.test(pubkey.toLowerCase())) {
		throw invalid(
			'pubkey must be a 33-byte compressed public key (66 hex chars)'
		);
	}
	const out: IPrimary = { pubkey: pubkey.toLowerCase() };
	if (host !== undefined) {
		if (typeof host !== 'string' || host.length === 0) {
			throw invalid('host must be a non-empty string');
		}
		out.host = host;
	}
	if (port !== undefined) {
		if (
			typeof port !== 'number' ||
			!Number.isInteger(port) ||
			port < 1 ||
			port > 65535
		) {
			throw invalid('port must be a TCP port between 1 and 65535');
		}
		out.port = port;
	}
	if ((out.host === undefined) !== (out.port === undefined)) {
		throw invalid('host and port must be given together');
	}
	if (uri !== undefined) {
		if (typeof uri !== 'string') throw invalid('uri must be a string');
		let parsedPubkey: string;
		try {
			parsedPubkey = parsePeerUri(uri).pubkey;
		} catch (err) {
			throw invalid(
				`uri is not a peer URI: ${err instanceof Error ? err.message : err}`
			);
		}
		if (parsedPubkey !== out.pubkey) {
			throw invalid('uri names a different node than pubkey');
		}
		out.uri = uri;
	}
	return out;
}

/** Check a threshold: a non-negative safe integer, or null for no cap. */
export function normalizeFillThreshold(value: unknown): number | null {
	if (value === null) return null;
	if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
		throw new PrimariesError(
			PrimariesErrorCode.INVALID_THRESHOLD,
			'fillThresholdSat must be a non-negative integer, or null for no cap'
		);
	}
	return value;
}

export interface IPrimariesStoreDeps {
	storage?: {
		saveWalletData(key: string, value: string): void;
		loadWalletData(key: string): string | null;
	};
}

/**
 * The persisted list and threshold. Every write reaches storage before the
 * in-memory copy changes, so a write that fails leaves both as they were and
 * the caller gets `PERSIST_FAILED`, not a change that vanishes on restart.
 */
export class PrimariesStore {
	private policy: IPrimariesPolicy = { primaries: [], fillThresholdSat: null };

	constructor(private readonly deps: IPrimariesStoreDeps) {}

	/** Reload from storage. Returns how many primaries came back. */
	restore(): number {
		this.policy = { primaries: [], fillThresholdSat: null };
		const raw = this.deps.storage?.loadWalletData(PRIMARIES_STORAGE_KEY);
		if (!raw) return 0;
		let parsed: unknown;
		try {
			parsed = JSON.parse(raw);
		} catch {
			// What is lost is a preference, not money: receives fall back to
			// naming a peer, as they did before the list existed.
			return 0;
		}
		if (typeof parsed !== 'object' || parsed === null) return 0;
		const { primaries, fillThresholdSat } = parsed as Record<string, unknown>;
		const seen = new Set<string>();
		const kept: IPrimary[] = [];
		for (const entry of Array.isArray(primaries) ? primaries : []) {
			try {
				const p = normalizePrimary(entry);
				if (seen.has(p.pubkey) || kept.length >= MAX_PRIMARIES) continue;
				seen.add(p.pubkey);
				kept.push(p);
			} catch {
				continue;
			}
		}
		let threshold: number | null = null;
		try {
			threshold = normalizeFillThreshold(fillThresholdSat ?? null);
		} catch {
			threshold = null;
		}
		this.policy = { primaries: kept, fillThresholdSat: threshold };
		return kept.length;
	}

	/** A copy of the policy as it stands. */
	get(): IPrimariesPolicy {
		return {
			primaries: this.policy.primaries.map((p) => ({ ...p })),
			fillThresholdSat: this.policy.fillThresholdSat
		};
	}

	/**
	 * Add a primary at `rank` (1-based; default last). A pubkey already in the
	 * list is refused with `DUPLICATE_PRIMARY`; remove it first to change it.
	 */
	add(entry: unknown, rank?: number): IPrimariesPolicy {
		const primary = normalizePrimary(entry);
		const list = this.policy.primaries;
		if (list.some((p) => p.pubkey === primary.pubkey)) {
			throw new PrimariesError(
				PrimariesErrorCode.DUPLICATE_PRIMARY,
				`${primary.pubkey} is already a primary`
			);
		}
		if (list.length >= MAX_PRIMARIES) {
			throw new PrimariesError(
				PrimariesErrorCode.TOO_MANY_PRIMARIES,
				`at most ${MAX_PRIMARIES} primaries are kept`
			);
		}
		if (
			rank !== undefined &&
			(!Number.isInteger(rank) || rank < 1 || rank > list.length + 1)
		) {
			throw invalid(`rank must be an integer between 1 and ${list.length + 1}`);
		}
		const next = [...list];
		next.splice(rank === undefined ? next.length : rank - 1, 0, primary);
		return this.commit({ ...this.policy, primaries: next });
	}

	/** Drop a primary. An unknown pubkey is refused with `UNKNOWN_PRIMARY`. */
	remove(pubkey: unknown): IPrimariesPolicy {
		const key = typeof pubkey === 'string' ? pubkey.toLowerCase() : '';
		const next = this.policy.primaries.filter((p) => p.pubkey !== key);
		if (next.length === this.policy.primaries.length) {
			throw new PrimariesError(
				PrimariesErrorCode.UNKNOWN_PRIMARY,
				`${String(pubkey)} is not a primary`
			);
		}
		return this.commit({ ...this.policy, primaries: next });
	}

	/**
	 * Re-rank the list. `pubkeys` must name every primary exactly once,
	 * highest rank first, so a reorder can neither add nor drop one.
	 */
	reorder(pubkeys: unknown): IPrimariesPolicy {
		const list = this.policy.primaries;
		if (!Array.isArray(pubkeys) || pubkeys.length !== list.length) {
			throw new PrimariesError(
				PrimariesErrorCode.INVALID_ORDER,
				`order must list all ${list.length} primaries, each once`
			);
		}
		const byKey = new Map(list.map((p) => [p.pubkey, p]));
		const next: IPrimary[] = [];
		for (const raw of pubkeys) {
			const p =
				typeof raw === 'string' ? byKey.get(raw.toLowerCase()) : undefined;
			if (!p) {
				throw new PrimariesError(
					PrimariesErrorCode.INVALID_ORDER,
					`order must list all ${list.length} primaries, each once`
				);
			}
			byKey.delete(p.pubkey);
			next.push(p);
		}
		return this.commit({ ...this.policy, primaries: next });
	}

	setFillThreshold(value: unknown): IPrimariesPolicy {
		return this.commit({
			...this.policy,
			fillThresholdSat: normalizeFillThreshold(value)
		});
	}

	private commit(next: IPrimariesPolicy): IPrimariesPolicy {
		if (this.deps.storage) {
			try {
				this.deps.storage.saveWalletData(
					PRIMARIES_STORAGE_KEY,
					JSON.stringify(next)
				);
			} catch (err) {
				throw new PrimariesError(
					PrimariesErrorCode.PERSIST_FAILED,
					`primaries not saved: ${err instanceof Error ? err.message : err}`
				);
			}
		}
		this.policy = next;
		return this.get();
	}
}
