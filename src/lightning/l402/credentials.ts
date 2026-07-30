/**
 * L402 credential store.
 *
 * A paid credential is (macaroon, preimage) for a scope. Reusing it is the
 * whole point of the protocol: without a store an agent pays again on every
 * request, which is both expensive and, for a metered API, indistinguishable
 * from an attack on the operator.
 *
 * The library ships an in-memory store. Anything durable is the embedder's
 * choice, because a credential is a bearer token: whoever holds it holds the
 * paid access, so where it lands (and whether that place is encrypted) is a
 * deployment decision, not a library one.
 */

/** One paid credential. */
export interface IL402Credential {
	/** Scope this credential was minted for (see credentialScope). */
	scope: string;
	/** Base64 macaroon, byte for byte as the server sent it. */
	macaroon: string;
	/** Payment preimage, lowercase hex. */
	preimage: string;
	/** Payment hash the macaroon committed to, lowercase hex. */
	paymentHash: string;
	/** What the credential cost, in satoshis. */
	amountSats: number;
	/** ms since epoch. */
	createdAt: number;
	/** Scheme the issuing server used, echoed back on retry. */
	scheme: 'L402' | 'LSAT';
}

export interface IL402CredentialStore {
	get(scope: string): IL402Credential | undefined;
	set(credential: IL402Credential): void;
	delete(scope: string): void;
	list(): IL402Credential[];
}

/**
 * The scope a credential is filed under.
 *
 * Origin by default, which is how Aperture-style servers issue them: one
 * token buys a service, not a single URL. `includePath` narrows it to
 * origin + path for servers that price per endpoint; over-narrowing only
 * costs an extra payment, while over-widening would send a token to an
 * endpoint that never minted it.
 */
export function credentialScope(url: string, includePath = false): string {
	const parsed = new URL(url);
	return includePath ? `${parsed.origin}${parsed.pathname}` : parsed.origin;
}

/** Process-lifetime store. Credentials do not survive a restart. */
export class MemoryL402CredentialStore implements IL402CredentialStore {
	private readonly entries = new Map<string, IL402Credential>();
	private readonly maxEntries: number;

	constructor(maxEntries = 1000) {
		this.maxEntries = maxEntries;
	}

	get(scope: string): IL402Credential | undefined {
		return this.entries.get(scope);
	}

	set(credential: IL402Credential): void {
		// Bounded: an agent crawling many hosts would otherwise grow this map
		// without limit. Oldest out first; losing one only costs a re-payment.
		if (
			this.entries.size >= this.maxEntries &&
			!this.entries.has(credential.scope)
		) {
			const oldest = this.entries.keys().next();
			if (!oldest.done) this.entries.delete(oldest.value);
		}
		this.entries.set(credential.scope, credential);
	}

	delete(scope: string): void {
		this.entries.delete(scope);
	}

	list(): IL402Credential[] {
		return [...this.entries.values()];
	}
}
