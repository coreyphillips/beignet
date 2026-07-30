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

import { decode as decodeInvoice } from '../invoice/decode';
import {
	buildL402AuthorizationHeader,
	IL402Challenge,
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
	}
) => Promise<IL402Response>;

/** The parts of a Response this client uses. */
export interface IL402Response {
	status: number;
	headers: { get(name: string): string | null };
	text(): Promise<string>;
}

export interface IL402RequestInit {
	method?: string;
	headers?: Record<string, string>;
	body?: string;
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
	/** Routing fee cap in satoshis, passed to the payer. */
	maxFeeSats?: number;
	/** Payment timeout in ms. */
	timeoutMs?: number;
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
			| 'INVALID_INVOICE'
			| 'NO_PAYER'
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
	const held = store.get(scope);

	// First attempt, with a credential if we already hold one.
	let response = await doFetch(url, withAuthorization(init, held));

	// A held credential the server no longer accepts is dead weight: drop it
	// and fall through to the challenge path rather than failing the call.
	if (held && (response.status === 401 || response.status === 402)) {
		store.delete(scope);
		response = await doFetch(url, withAuthorization(init, undefined));
	}

	if (response.status !== 402) {
		return {
			response,
			paid: false,
			credential: held,
			amountPaidSats: 0
		};
	}

	const challenge = parseL402Challenge(
		response.headers.get('www-authenticate') ?? ''
	);
	if (!challenge) {
		// A 402 with no L402 challenge is the server's business, not ours.
		return { response, paid: false, amountPaidSats: 0 };
	}

	const priceSats = validateChallenge(challenge, options);
	if (!options.payer) {
		throw new L402Error(
			'l402Fetch: a challenge was issued but no payer was configured',
			'NO_PAYER'
		);
	}

	const { preimage } = await options.payer.payInvoice(challenge.invoice, {
		maxFeeSats: options.maxFeeSats,
		timeoutMs: options.timeoutMs
	});

	const credential: IL402Credential = {
		scope,
		macaroon: challenge.macaroon,
		preimage: preimage.toString('hex'),
		paymentHash: decodeInvoice(challenge.invoice).paymentHash.toString('hex'),
		amountSats: priceSats,
		createdAt: Date.now(),
		scheme: challenge.scheme
	};
	store.set(credential);

	// Exactly one retry. If it is another 402 the caller sees it and decides;
	// this function never pays twice.
	const retried = await doFetch(url, withAuthorization(init, credential));
	return {
		response: retried,
		paid: true,
		credential,
		amountPaidSats: priceSats
	};
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
