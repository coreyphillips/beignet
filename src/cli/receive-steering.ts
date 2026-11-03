/**
 * Receive steering through the ranked primaries (issue #1922, step 2a).
 *
 * A receive that names no peer walks the primaries in the order
 * `selectReceiveTargets` ranks them, and the first one that takes it wins.
 * `steerReceive` is that walk, with the pieces that touch the node injected
 * so the rule stays table-testable: whether a candidate is connected, how to
 * dial it, and the one attempt that registers the receive with it.
 *
 * Budget: one bound covers the whole list, so a list of 32 peers cannot turn
 * one peer's timeout into an unbounded wait. While more candidates remain, a
 * dial and an attempt are each capped short; the last candidate gets whatever
 * is left. That gives roughly two full candidates per call inside the default
 * budget, which is what a caller with its own 20 s timeout (the LFBW app on
 * `POST /jit/invoice`) can afford. A caller with more time raises the budget.
 *
 * Failing over is safe at the points this walker fails over: the JIT wallet
 * mints its invoice only after the LSP's ack, and the offline-receive quote
 * reserves nothing, so a candidate that is passed over leaves no payable
 * artifact behind. An intent that timed out at one LSP simply expires there.
 *
 * What counts as "try the next one" is the caller's list of codes. Anything
 * else (a malformed parameter, a fault) rethrows at once and ends the walk,
 * because it would fail the same way at every candidate.
 */

import { BeignetError, BeignetErrorCode } from './errors';
import type { IPeerTransportOptions } from '../lightning/transport/duplex-transport';
import { parsePeerUri } from '../lightning/transport/peer-uri';

/**
 * The whole walk, by default. Inside the 20 s the daemon's only JIT consumer
 * allows for one call, with room for the response.
 */
export const STEER_BUDGET_MS = 18_000;
/** A dial while more candidates remain. */
export const STEER_CONNECT_CAP_MS = 5_000;
/** An attempt while more candidates remain. */
export const STEER_ATTEMPT_CAP_MS = 8_000;
/** Below this much budget left, the remaining candidates are not tried. */
export const STEER_FLOOR_MS = 2_000;

/** Skip code for a candidate the budget did not reach. */
export const STEER_BUDGET_CODE = 'BUDGET_EXHAUSTED';

/** Attempt failures that mean the next primary may still take a JIT receive. */
export const JIT_STEER_CODES: ReadonlySet<string> = new Set([
	BeignetErrorCode.PEER_NOT_CONNECTED,
	BeignetErrorCode.CONNECT_FAILED,
	BeignetErrorCode.CONNECT_TIMEOUT,
	BeignetErrorCode.JIT_TIMEOUT,
	BeignetErrorCode.JIT_REFUSED,
	// Our own fence on brand-new channels: a primary we already hold a live
	// channel with is not fenced, so the walk goes on to it.
	BeignetErrorCode.NEW_CHANNELS_REFUSED
]);

/**
 * Attempt failures that mean the next primary may still take an automatic
 * offline receive. Both are per peer: whether it is connected, serves the
 * receive, or needs a minimum this amount does not meet on that route.
 */
export const OFFLINE_RECEIVE_STEER_CODES: ReadonlySet<string> = new Set([
	BeignetErrorCode.RECEIVE_UNAVAILABLE,
	BeignetErrorCode.AMOUNT_TOO_SMALL
]);

/** One primary as the walk sees it: its selection facts and its address. */
export interface ISteerCandidate {
	pubkey: string;
	/** 1-based configured rank. */
	rank: number;
	balanceSat: number;
	host?: string;
	port?: number;
	uri?: string;
}

/** Why one candidate did not take the receive. */
export interface ISteerSkip {
	pubkey: string;
	rank: number;
	/** `budget`: not tried, the budget ran out before it. */
	stage: 'connect' | 'attempt' | 'budget';
	code: string;
	message: string;
}

export interface ISteerDeps<T> {
	/** In the order to try them. */
	candidates: readonly ISteerCandidate[];
	isConnected(pubkey: string): boolean;
	/**
	 * Dial a candidate that is not connected. Absent: such a candidate is
	 * skipped as PEER_NOT_CONNECTED, for a caller that never dials.
	 */
	connect?(candidate: ISteerCandidate, timeoutMs: number): Promise<void>;
	/** Register the receive with a connected candidate. */
	attempt(candidate: ISteerCandidate, timeoutMs: number): Promise<T>;
	/** Attempt-stage codes that mean "try the next one". */
	candidateCodes: ReadonlySet<string>;
	budgetMs?: number;
	connectCapMs?: number;
	attemptCapMs?: number;
	/** Caps for the last candidate; default to what is left of the budget. */
	lastConnectCapMs?: number;
	lastAttemptCapMs?: number;
	floorMs?: number;
	now?(): number;
	onSkip?(skip: ISteerSkip): void;
}

export interface ISteerResult<T> {
	value: T;
	/** The primary that took the receive. */
	pubkey: string;
	/** The primaries passed over before it, in order. */
	skipped: ISteerSkip[];
}

/** The dial a stored primary address describes, as `connectPeer` takes it. */
export function dialTargetOf(candidate: ISteerCandidate): {
	host?: string;
	port?: number;
	transport?: IPeerTransportOptions;
} {
	if (candidate.uri !== undefined) {
		const parsed = parsePeerUri(candidate.uri);
		return {
			host: parsed.host,
			port: parsed.port,
			...(parsed.transport ? { transport: parsed.transport } : {})
		};
	}
	if (candidate.host !== undefined && candidate.port !== undefined) {
		return { host: candidate.host, port: candidate.port };
	}
	// Nothing stored: the library resolves the address (gossip, DNS).
	return {};
}

/**
 * The TCP address a payer can reach a primary's relay on, for a direct-funding
 * request bound to it (issue #1922): the host and port stored for the
 * primary, else its stored peer URI when that is a plain TCP one, else
 * `dialed`, the address this node last dialed the peer at, when that is TCP.
 * The address a peer is merely up on is never consulted: for a peer that
 * dialed us it is the far end of its socket, whose port is ephemeral, so a
 * payer sent there would reach nothing. A ws or iroh address is no use to a
 * payer dialing a Lightning relay either, so none of those count. Undefined
 * when nothing is known.
 */
export function relayAddressOf(
	stored: { host?: string; port?: number; uri?: string } | undefined,
	dialed:
		| { host?: string; port?: number; transport?: 'tcp' | 'ws' | 'iroh' }
		| undefined
): { host: string; port: number } | undefined {
	if (stored?.host !== undefined && stored.port !== undefined) {
		return { host: stored.host, port: stored.port };
	}
	if (stored?.uri !== undefined) {
		try {
			const parsed = parsePeerUri(stored.uri);
			if (parsed.transport === undefined && parsed.host && parsed.port) {
				return { host: parsed.host, port: parsed.port };
			}
		} catch {
			// A URI the store would not have taken: nothing to dial from it.
		}
	}
	if (
		dialed &&
		(dialed.transport === undefined || dialed.transport === 'tcp') &&
		dialed.host &&
		dialed.port
	) {
		return { host: dialed.host, port: dialed.port };
	}
	return undefined;
}

function short(pubkey: string): string {
	return pubkey.slice(0, 16);
}

/** The typed refusal when no primary took the receive. */
export function noPrimaryAvailable(
	skipped: readonly ISteerSkip[]
): BeignetError {
	const tried = skipped.filter((s) => s.stage !== 'budget').length;
	const detail = skipped
		.map((s) => `${short(s.pubkey)} (rank ${s.rank}): ${s.code} ${s.message}`)
		.join('; ');
	return new BeignetError(
		BeignetErrorCode.NO_PRIMARY_AVAILABLE,
		`No primary could take the receive (${tried} of ${skipped.length} tried): ${detail}`
	);
}

/**
 * Try the candidates in order under one budget and return the first
 * success. Throws NO_PRIMARY_AVAILABLE naming every candidate's reason when
 * none takes it, INVALID_PARAMS when there is no candidate at all, and
 * rethrows at once any failure that is not a candidate's own.
 */
export async function steerReceive<T>(
	deps: ISteerDeps<T>
): Promise<ISteerResult<T>> {
	const { candidates } = deps;
	if (candidates.length === 0) {
		throw new BeignetError(
			BeignetErrorCode.INVALID_PARAMS,
			'No primaries are configured: name the peer, or add primaries first.'
		);
	}
	const now = deps.now ?? Date.now;
	const budgetMs = deps.budgetMs ?? STEER_BUDGET_MS;
	const connectCapMs = deps.connectCapMs ?? STEER_CONNECT_CAP_MS;
	const attemptCapMs = deps.attemptCapMs ?? STEER_ATTEMPT_CAP_MS;
	const floorMs = deps.floorMs ?? STEER_FLOOR_MS;
	const start = now();
	const remaining = (): number => budgetMs - (now() - start);
	const skipped: ISteerSkip[] = [];
	const skip = (
		candidate: ISteerCandidate,
		stage: ISteerSkip['stage'],
		code: string,
		message: string
	): void => {
		const entry = {
			pubkey: candidate.pubkey,
			rank: candidate.rank,
			stage,
			code,
			message
		};
		skipped.push(entry);
		deps.onSkip?.(entry);
	};
	const outOfBudget = (from: number): void => {
		for (const c of candidates.slice(from)) {
			skip(
				c,
				'budget',
				STEER_BUDGET_CODE,
				`not tried: ${Math.max(
					0,
					remaining()
				)} ms of the ${budgetMs} ms budget left`
			);
		}
	};
	for (let i = 0; i < candidates.length; i++) {
		const candidate = candidates[i];
		const last = i === candidates.length - 1;
		if (remaining() < floorMs) {
			outOfBudget(i);
			break;
		}
		if (!deps.isConnected(candidate.pubkey)) {
			if (!deps.connect) {
				skip(
					candidate,
					'connect',
					BeignetErrorCode.PEER_NOT_CONNECTED,
					'not connected'
				);
				continue;
			}
			const cap = last
				? Math.min(remaining(), deps.lastConnectCapMs ?? remaining())
				: Math.min(remaining(), connectCapMs);
			try {
				await deps.connect(candidate, cap);
			} catch (err) {
				// Every typed dial failure is this peer's own; a plain throw is
				// a fault in the node, and the next candidate would hit it too.
				if (!(err instanceof BeignetError)) throw err;
				skip(candidate, 'connect', err.code, err.message);
				continue;
			}
			if (remaining() < floorMs) {
				outOfBudget(i);
				break;
			}
		}
		const cap = last
			? Math.min(remaining(), deps.lastAttemptCapMs ?? remaining())
			: Math.min(remaining(), attemptCapMs);
		try {
			const value = await deps.attempt(candidate, cap);
			return { value, pubkey: candidate.pubkey, skipped };
		} catch (err) {
			if (!(err instanceof BeignetError) || !deps.candidateCodes.has(err.code))
				throw err;
			skip(candidate, 'attempt', err.code, err.message);
		}
	}
	throw noPrimaryAvailable(skipped);
}
