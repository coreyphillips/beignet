/**
 * L402 client: fetch a paywalled resource, paying the challenge if needed.
 *
 * The flow, per github.com/lightninglabs/L402:
 *
 *   1. request with any credential already held for this scope
 *   2. on 402, parse the WWW-Authenticate challenge
 *   3. check the invoice against the payment hash the macaroon commits to
 *   4. check the price against the caller's cap
 *   5. pay, store the credential, retry once with Authorization
 *
 * Two rules shape everything here, because this is a code path where a REMOTE
 * response header causes an outbound payment:
 *
 *   Fail closed. A challenge whose commitment cannot be checked, or whose
 *   price cannot be bounded, is not paid.
 *
 *   Pay at most once per call. However the server answers the retry, no
 *   second payment happens inside one l402Fetch, so a misbehaving or hostile
 *   server cannot drive a payment loop.
 */

import * as crypto from 'crypto';
import { decode as decodeInvoice } from '../invoice/decode';
import {
	buildL402AuthorizationHeader,
	IL402Challenge,
	isHeaderSafeMacaroon,
	parseL402Challenge
} from './challenge';
import {
	credentialScope,
	IL402Credential,
	IL402CredentialStore,
	MemoryL402CredentialStore
} from './credentials';
import { macaroonPaymentHash } from './macaroon';

/** Minimal payer contract, so the protocol layer needs no node handle. */
export interface IL402Payer {
	/**
	 * Pay a BOLT 11 invoice and return its preimage. Implementations are
	 * expected to enforce their own spend controls as well; the cap here is
	 * about this call, not about the wallet's policy.
	 */
	payInvoice(
		bolt11: string,
		options: { maxFeeSats?: number; timeoutMs?: number }
	): Promise<{ preimage: Buffer }>;
}

/** Fetch signature, injected so tests and non-global runtimes both work. */
export type FetchLike = (
	input: string,
	init?: {
		method?: string;
		headers?: Record<string, string>;
		body?: string;
		signal?: AbortSignal;
	}
) => Promise<IL402Response>;

/** A web-stream body reader, structurally (no DOM lib dependency). */
export interface IL402BodyReader {
	read(): Promise<{ done: boolean; value?: Uint8Array }>;
	cancel(reason?: unknown): Promise<unknown> | void;
}

/** The parts of a Response this client uses. */
export interface IL402Response {
	status: number;
	headers: { get(name: string): string | null };
	text(): Promise<string>;
	/**
	 * Streaming body, when the fetch implementation provides one. Optional:
	 * consumers that need a size bound read this incrementally via
	 * {@link readCappedBody}; without it the only option is text(), which
	 * buffers whatever the server chooses to send.
	 */
	body?: { getReader(): IL402BodyReader } | null;
	/**
	 * Final URL after redirects, when the fetch implementation reports one.
	 * Load-bearing: a redirect can move the challenge to another origin, and
	 * paying it means paying someone the caller never named.
	 */
	url?: string;
}

export interface IL402RequestInit {
	method?: string;
	headers?: Record<string, string>;
	body?: string;
	signal?: AbortSignal;
}

export interface IL402FetchOptions {
	/** Who pays. Omit to refuse every challenge (useful for probing). */
	payer?: IL402Payer;
	/**
	 * Hard cap in satoshis on what ONE challenge may cost. Required: this is
	 * the only thing standing between an unattended agent and whatever price a
	 * remote server decides to put in its header.
	 */
	maxPriceSats: number;
	/**
	 * Routing fee cap in satoshis, passed to the payer. Omitted, it defaults
	 * to {@link defaultFeeCapSats} of the price rather than to "no cap": the
	 * invoice comes from a remote header, and its routing hints set the fee,
	 * so an uncapped fee is an uncapped payment no matter what the price says.
	 */
	maxFeeSats?: number;
	/** Payment timeout in ms. */
	timeoutMs?: number;
	/**
	 * Timeout in ms for each HTTP request. Defaults to
	 * {@link DEFAULT_FETCH_TIMEOUT_MS}; a server that accepts the connection
	 * and then stalls would otherwise hold the call open indefinitely.
	 */
	fetchTimeoutMs?: number;
	/** Where paid credentials live. Defaults to a process-lifetime store. */
	credentials?: IL402CredentialStore;
	/** Scope credentials per path rather than per origin. */
	scopePerPath?: boolean;
	/** fetch implementation. Defaults to the global one. */
	fetchImpl?: FetchLike;
	/**
	 * Pay a challenge whose macaroon could not be parsed, so the invoice's
	 * payment hash could NOT be checked against the server's commitment.
	 * Default false, and it should stay false: with this on, a server can
	 * bill for one hash and hand you a token bound to another.
	 */
	allowUnverifiedMacaroon?: boolean;
	/**
	 * Pay a challenge that arrived from a different origin than the one
	 * requested, after following redirects. Default false: a redirect chain
	 * otherwise lets any site the caller trusts hand the payment to one it
	 * does not.
	 */
	allowCrossOriginChallenge?: boolean;
}

/** Per-request HTTP timeout when the caller sets none. */
export const DEFAULT_FETCH_TIMEOUT_MS = 30_000;

/**
 * Routing fee ceiling for a challenge of `priceSats`, when the caller sets no
 * `maxFeeSats`.
 *
 * The percentage mirrors the 5% most Lightning wallets default to, and the
 * floor keeps sub-100-sat purchases (most of L402's traffic) routable, where a
 * pure percentage would round to nothing. The point is not to pick the perfect
 * number: it is that the fee a hostile invoice can demand is bounded by the
 * price the caller agreed to, instead of by the channel balance.
 */
export function defaultFeeCapSats(priceSats: number): number {
	return Math.max(5, Math.ceil(priceSats * 0.05));
}

/** What happened, alongside the final response. */
export interface IL402FetchResult {
	response: IL402Response;
	/** True when this call paid an invoice. */
	paid: boolean;
	/** The credential used or obtained, when there was one. */
	credential?: IL402Credential;
	/** Satoshis spent by this call. */
	amountPaidSats: number;
	/** Why a challenge was refused, when one was. */
	refusedReason?: string;
}

/** Errors this client raises before any payment leaves. */
export class L402Error extends Error {
	constructor(
		message: string,
		readonly code:
			| 'PRICE_ABOVE_CAP'
			| 'AMOUNTLESS_INVOICE'
			| 'HASH_COMMITMENT_MISMATCH'
			| 'UNVERIFIABLE_MACAROON'
			| 'UNUSABLE_MACAROON'
			| 'INVALID_INVOICE'
			| 'NO_PAYER'
			| 'CROSS_ORIGIN_CHALLENGE'
			| 'PREIMAGE_MISMATCH'
	) {
		super(message);
		this.name = 'L402Error';
	}
}

/**
 * Fetch a URL, satisfying an L402 challenge if the server issues one.
 *
 * Throws {@link L402Error} when a challenge is refused on safety grounds
 * (price above the cap, unbounded price, commitment mismatch), because those
 * are caller errors worth surfacing loudly rather than a 402 to interpret.
 * Anything else, including a server that keeps returning 402 after payment,
 * comes back as a normal response.
 */
export async function l402Fetch(
	url: string,
	init: IL402RequestInit = {},
	options: IL402FetchOptions
): Promise<IL402FetchResult> {
	const doFetch =
		options.fetchImpl ?? (globalThis.fetch as unknown as FetchLike);
	if (typeof doFetch !== 'function') {
		throw new Error('l402Fetch: no fetch implementation available');
	}
	if (!Number.isFinite(options.maxPriceSats) || options.maxPriceSats < 0) {
		throw new Error('l402Fetch: maxPriceSats must be a non-negative number');
	}

	const store = options.credentials ?? new MemoryL402CredentialStore();
	const scope = credentialScope(url, options.scopePerPath);
	const request = (credential?: IL402Credential): IL402RequestInit =>
		withTimeout(withAuthorization(init, credential), options);

	// First attempt, with a credential if we already hold one. A credential
	// that cannot be turned into a header is dropped rather than thrown over:
	// one poisoned entry would otherwise wedge the scope for good, since the
	// throw would land before the request that detects a dead credential.
	let usable = usableCredential(store.get(scope), store);
	let response = await doFetch(url, request(usable));

	// A held credential the server no longer accepts is dead weight: drop it
	// and fall through to the challenge path rather than failing the call.
	if (usable && (response.status === 401 || response.status === 402)) {
		store.delete(scope);
		usable = undefined;
		response = await doFetch(url, request(undefined));
	}

	if (response.status !== 402) {
		return {
			response,
			paid: false,
			credential: usable,
			amountPaidSats: 0
		};
	}

	const parsedChallenge = parseL402Challenge(
		response.headers.get('www-authenticate') ?? ''
	);
	if (!parsedChallenge) {
		// A 402 with no L402 challenge is the server's business, not ours.
		return { response, paid: false, amountPaidSats: 0 };
	}
	let challenge: IL402Challenge = parsedChallenge;

	// A redirect can move the challenge to an origin the caller never named,
	// and the response carries no hint of it beyond the final URL. Check
	// before validating, so a cross-origin challenge is refused for the right
	// reason rather than for whatever its invoice happens to look like.
	assertSameOrigin(url, response.url, options);

	// From here a payment can leave, so overlapping calls for one scope are
	// serialized: two calls that both saw a 402 would otherwise each pay their
	// own invoice for the same access. The lock only covers the challenge
	// path; the steady state above (credential held, server content) runs
	// concurrently. Callers who pass no store get no cross-call coalescing,
	// since without shared storage the second call could not reuse the first
	// call's credential anyway.
	return await withScopeLock(store, scope, async () => {
		// Another call may have paid while this one waited for the lock; its
		// credential satisfies this request without a second payment.
		const minted = usableCredential(store.get(scope), store);
		if (minted) {
			const reused = await doFetch(url, request(minted));
			if (reused.status !== 402) {
				return {
					response: reused,
					paid: false,
					credential: minted,
					amountPaidSats: 0
				};
			}
			// The minted credential no longer satisfies the server. Drop it,
			// and pay the freshest challenge visible: the invoice in the
			// original one may already be settled or expired.
			store.delete(minted.scope);
			const fresh = parseL402Challenge(
				reused.headers.get('www-authenticate') ?? ''
			);
			if (fresh) {
				assertSameOrigin(url, reused.url, options);
				challenge = fresh;
				response = reused;
			}
		}

		const priceSats = validateChallenge(challenge, options);
		if (!options.payer) {
			throw new L402Error(
				'l402Fetch: a challenge was issued but no payer was configured',
				'NO_PAYER'
			);
		}

		const paymentHash = decodeInvoice(challenge.invoice).paymentHash;
		const { preimage } = await options.payer.payInvoice(challenge.invoice, {
			maxFeeSats: options.maxFeeSats ?? defaultFeeCapSats(priceSats),
			timeoutMs: options.timeoutMs
		});

		// The preimage is what proves the payment to the server, so a payer
		// returning one that does not open the invoice's hash has handed us a
		// credential that cannot work. Say so instead of storing it and letting
		// every later request fail with an opaque 401.
		if (
			!crypto.createHash('sha256').update(preimage).digest().equals(paymentHash)
		) {
			throw new L402Error(
				'L402 payment returned a preimage that does not hash to the invoice payment hash',
				'PREIMAGE_MISMATCH'
			);
		}

		const credential: IL402Credential = {
			scope,
			macaroon: challenge.macaroon,
			preimage: preimage.toString('hex'),
			paymentHash: paymentHash.toString('hex'),
			amountSats: priceSats,
			createdAt: Date.now(),
			scheme: challenge.scheme
		};
		store.set(credential);

		// Exactly one retry. If it is another 402 the caller sees it and
		// decides; this function never pays twice.
		const retried = await doFetch(url, request(credential));
		return {
			response: retried,
			paid: true,
			credential,
			amountPaidSats: priceSats
		};
	});
}

/**
 * Serialize the paid path per (store, scope). Keyed by store so unrelated
 * stores never contend, and weakly so a discarded store takes its lock chain
 * with it. The synchronous section below runs to completion before any queued
 * function starts, which is what makes enqueueing race-free on one thread.
 */
const scopeLocks = new WeakMap<
	IL402CredentialStore,
	Map<string, Promise<unknown>>
>();

async function withScopeLock<T>(
	store: IL402CredentialStore,
	scope: string,
	fn: () => Promise<T>
): Promise<T> {
	let locks = scopeLocks.get(store);
	if (!locks) {
		locks = new Map();
		scopeLocks.set(store, locks);
	}
	const previous = locks.get(scope) ?? Promise.resolve();
	const run = previous.then(() => fn());
	// The stored tail never rejects, so one failed call cannot poison the
	// queue behind it; each caller still sees its own failure through `run`.
	const tail = run.then(
		() => undefined,
		() => undefined
	);
	locks.set(scope, tail);
	void tail.then(() => {
		if (locks?.get(scope) === tail) locks.delete(scope);
	});
	return run;
}

/**
 * Everything that must hold before a payment goes out. Returns the price in
 * satoshis; throws {@link L402Error} otherwise.
 */
export function validateChallenge(
	challenge: IL402Challenge,
	options: Pick<IL402FetchOptions, 'maxPriceSats' | 'allowUnverifiedMacaroon'>
): number {
	let invoice;
	try {
		invoice = decodeInvoice(challenge.invoice);
	} catch (err) {
		throw new L402Error(
			`L402 challenge carries an undecodable invoice: ${
				(err as Error).message
			}`,
			'INVALID_INVOICE'
		);
	}

	// A macaroon we cannot echo back is worthless once paid for, and base64
	// decoding ignores whitespace, so this has to be checked explicitly rather
	// than inferred from the token parsing cleanly.
	if (!isHeaderSafeMacaroon(challenge.macaroon)) {
		throw new L402Error(
			'L402 macaroon contains whitespace or a comma, so it cannot be sent back in an Authorization header',
			'UNUSABLE_MACAROON'
		);
	}

	// The commitment check, the reason a client parses macaroons at all: the
	// token must be bound to the hash of the invoice we are about to pay, or
	// the payment buys access to something else entirely.
	const committedHash = macaroonPaymentHash(challenge.macaroon);
	if (!committedHash) {
		if (!options.allowUnverifiedMacaroon) {
			throw new L402Error(
				'L402 macaroon could not be parsed, so the invoice payment hash cannot be checked against it',
				'UNVERIFIABLE_MACAROON'
			);
		}
	} else if (!committedHash.equals(invoice.paymentHash)) {
		throw new L402Error(
			'L402 macaroon commits to a different payment hash than the invoice',
			'HASH_COMMITMENT_MISMATCH'
		);
	}

	// An amountless invoice has no price to check against the cap, and paying
	// one means choosing the amount ourselves with no idea what the server
	// expects. Refuse rather than guess.
	if (invoice.amountMsat === undefined || invoice.amountMsat <= 0n) {
		throw new L402Error(
			'L402 challenge carries an amountless invoice, so its price cannot be capped',
			'AMOUNTLESS_INVOICE'
		);
	}

	// Round UP: a 1500 msat invoice costs more than 1 sat of value, and
	// rounding down would let sub-satoshi pricing slip past a 1 sat cap.
	const priceSats = Number((invoice.amountMsat + 999n) / 1000n);
	if (priceSats > options.maxPriceSats) {
		throw new L402Error(
			`L402 price ${priceSats} sat is above the ${options.maxPriceSats} sat cap`,
			'PRICE_ABOVE_CAP'
		);
	}
	return priceSats;
}

function withAuthorization(
	init: IL402RequestInit,
	credential?: IL402Credential
): IL402RequestInit {
	if (!credential) return init;
	return {
		...init,
		headers: {
			...(init.headers ?? {}),
			Authorization: buildL402AuthorizationHeader(
				credential.macaroon,
				credential.preimage,
				credential.scheme
			)
		}
	};
}

/**
 * Bound every HTTP request, unless the caller brought its own signal. Without
 * this a server that accepts the connection and then goes quiet holds the call
 * (and, through the daemon, a request handler) open forever.
 */
function withTimeout(
	init: IL402RequestInit,
	options: Pick<IL402FetchOptions, 'fetchTimeoutMs'>
): IL402RequestInit {
	if (init.signal) return init;
	const ms = options.fetchTimeoutMs ?? DEFAULT_FETCH_TIMEOUT_MS;
	if (!Number.isFinite(ms) || ms <= 0) return init;
	return { ...init, signal: AbortSignal.timeout(ms) };
}

/**
 * Drop a stored credential that cannot be turned into a header rather than
 * throwing out of the request. Nothing this client writes can be unusable, but
 * a caller-supplied store is not under our control.
 */
function usableCredential(
	credential: IL402Credential | undefined,
	store: IL402CredentialStore
): IL402Credential | undefined {
	if (!credential) return undefined;
	try {
		buildL402AuthorizationHeader(
			credential.macaroon,
			credential.preimage,
			credential.scheme
		);
		return credential;
	} catch {
		store.delete(credential.scope);
		return undefined;
	}
}

/**
 * Refuse a challenge that arrived from another origin after a redirect.
 *
 * `finalUrl` is absent for fetch implementations that do not report it (and
 * for a request that was never redirected), in which case there is nothing to
 * compare and the challenge stands on its own merits.
 */
function assertSameOrigin(
	requestedUrl: string,
	finalUrl: string | undefined,
	options: Pick<IL402FetchOptions, 'allowCrossOriginChallenge'>
): void {
	if (!finalUrl || options.allowCrossOriginChallenge) return;
	let requested: string;
	let final: string;
	try {
		requested = new URL(requestedUrl).origin;
		final = new URL(finalUrl).origin;
	} catch {
		return;
	}
	if (requested === final) return;
	throw new L402Error(
		`L402 challenge came from ${final} after a redirect from ${requested}, so it was not paid`,
		'CROSS_ORIGIN_CHALLENGE'
	);
}

/**
 * Read a response body under a byte cap without ever holding more than the
 * cap in memory. Streams when the implementation exposes a body reader and
 * cancels the stream once the cap is crossed; falls back to text() otherwise,
 * where the full buffer is unavoidable but the returned value is still capped.
 * Truncation is byte-exact, so a multibyte character split at the boundary
 * decodes as a replacement character; a cut body is marked, not exact.
 */
export async function readCappedBody(
	response: IL402Response,
	capBytes: number
): Promise<{ body: string; truncated: boolean }> {
	const stream = response.body;
	if (stream && typeof stream.getReader === 'function') {
		const reader = stream.getReader();
		const chunks: Buffer[] = [];
		let total = 0;
		let truncated = false;
		for (;;) {
			const { done, value } = await reader.read();
			if (done) break;
			if (!value || value.byteLength === 0) continue;
			chunks.push(
				Buffer.from(value.buffer, value.byteOffset, value.byteLength)
			);
			total += value.byteLength;
			if (total > capBytes) {
				truncated = true;
				try {
					await reader.cancel();
				} catch {
					// The bytes already read are the answer; a cancel failure
					// changes nothing about them.
				}
				break;
			}
		}
		let body = Buffer.concat(chunks);
		if (body.length > capBytes) body = body.subarray(0, capBytes);
		return { body: body.toString('utf8'), truncated };
	}

	const text = await response.text();
	const bytes = Buffer.from(text, 'utf8');
	if (bytes.length > capBytes) {
		return {
			body: bytes.subarray(0, capBytes).toString('utf8'),
			truncated: true
		};
	}
	return { body: text, truncated: false };
}

/**
 * Whether a URL names a private, loopback, or link-local host, judged from
 * the URL alone. Used by embedders whose l402Fetch is reachable over an API,
 * where "fetch this URL for me" would otherwise reach targets only the host
 * machine can see: localhost admin panels, RFC 1918 services, or the
 * 169.254.169.254 cloud metadata endpoint. Name-based only: a public DNS name
 * resolving to a private address (DNS rebinding) is out of scope here and
 * needs resolver-level enforcement.
 */
export function isPrivateNetworkUrl(url: string): boolean {
	let parsed: URL;
	try {
		parsed = new URL(url);
	} catch {
		return true;
	}
	// URL.hostname keeps the brackets on an IPv6 literal.
	const hostname = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase();
	if (!hostname) return true;
	if (hostname === 'localhost' || hostname.endsWith('.localhost')) return true;
	if (isIPv4(hostname)) return isPrivateIPv4(hostname);
	if (hostname.includes(':')) return isPrivateIPv6(hostname);
	return false;
}

function isIPv4(hostname: string): boolean {
	const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(hostname);
	if (!match) return false;
	return match.slice(1).every((octet) => Number(octet) <= 255);
}

function isPrivateIPv4(ip: string): boolean {
	const [a, b] = ip.split('.').map(Number);
	return (
		a === 0 || // "this network", including 0.0.0.0
		a === 10 || // RFC 1918
		a === 127 || // loopback
		(a === 100 && b >= 64 && b <= 127) || // CGNAT / overlay networks
		(a === 169 && b === 254) || // link-local, incl. cloud metadata
		(a === 172 && b >= 16 && b <= 31) || // RFC 1918
		(a === 192 && b === 168) // RFC 1918
	);
}

function isPrivateIPv6(ip: string): boolean {
	if (ip === '::' || ip === '::1') return true;
	if (ip.startsWith('::ffff:')) {
		// IPv4-mapped. The dotted form re-checks as IPv4; the pure-hex form is
		// refused outright rather than decoded, erring private.
		const mapped = ip.slice(7);
		return isIPv4(mapped) ? isPrivateIPv4(mapped) : true;
	}
	return (
		ip.startsWith('fc') || // fc00::/7 unique-local
		ip.startsWith('fd') ||
		ip.startsWith('fe8') || // fe80::/10 link-local
		ip.startsWith('fe9') ||
		ip.startsWith('fea') ||
		ip.startsWith('feb')
	);
}
