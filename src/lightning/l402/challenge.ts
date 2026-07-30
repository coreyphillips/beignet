/**
 * L402 challenge parsing and Authorization header construction.
 *
 * A server gates a resource by answering an unauthenticated request with
 * `402 Payment Required` and:
 *
 *   WWW-Authenticate: L402 macaroon="<base64>", invoice="<bolt11>"
 *
 * The client pays the invoice and retries with:
 *
 *   Authorization: L402 <base64 macaroon>:<hex preimage>
 *
 * `LSAT` is accepted as an alias everywhere `L402` is: it is the protocol's
 * former name and servers deployed before the rename still send it.
 */

/** The scheme names an L402 challenge may use. */
export const L402_SCHEMES = ['L402', 'LSAT'] as const;

/** A parsed `WWW-Authenticate` challenge. */
export interface IL402Challenge {
	/** The scheme as the server spelled it, for echoing back in kind. */
	scheme: 'L402' | 'LSAT';
	/** Base64 macaroon, exactly as received. */
	macaroon: string;
	/** BOLT 11 invoice string. */
	invoice: string;
}

/** Longest header we will scan, to bound work on a hostile response. */
const MAX_HEADER_LENGTH = 64 * 1024;

/**
 * Pull the L402 (or LSAT) challenge out of a `WWW-Authenticate` header.
 *
 * Returns null when the header carries no L402 challenge, which is not an
 * error: a server may legitimately answer 402 with a different scheme, and
 * the caller then simply surfaces the response.
 *
 * Tolerant of the shapes seen in the wild: either parameter order, optional
 * quoting, extra whitespace, and other schemes listed alongside. Deliberately
 * NOT tolerant of a challenge missing either parameter, since a challenge
 * without both halves cannot be acted on.
 */
export function parseL402Challenge(header: string): IL402Challenge | null {
	if (!header || header.length > MAX_HEADER_LENGTH) return null;

	for (const scheme of L402_SCHEMES) {
		// Match the scheme as a whole token so a value containing the word
		// (a macaroon happening to encode "L402") cannot be mistaken for one.
		const schemeMatch = new RegExp(`(?:^|[\\s,])${scheme}\\s+`, 'i').exec(
			header
		);
		if (!schemeMatch) continue;

		const rest = header.slice(schemeMatch.index + schemeMatch[0].length);
		const macaroon = extractParam(rest, 'macaroon');
		const invoice = extractParam(rest, 'invoice');
		if (!macaroon || !invoice) continue;

		return {
			scheme: scheme,
			macaroon,
			invoice
		};
	}
	return null;
}

/**
 * Read one `name="value"` or `name=value` parameter. Stops at a comma or
 * whitespace for unquoted values, which is what separates parameters and
 * successive challenges.
 */
function extractParam(source: string, name: string): string | null {
	const quoted = new RegExp(`(?:^|[\\s,])${name}\\s*=\\s*"([^"]*)"`, 'i').exec(
		source
	);
	if (quoted) return quoted[1].trim() || null;

	const bare = new RegExp(`(?:^|[\\s,])${name}\\s*=\\s*([^,\\s]+)`, 'i').exec(
		source
	);
	if (bare) return bare[1].trim() || null;

	return null;
}

/**
 * Build the `Authorization` value for a paid credential.
 *
 * The preimage is lowercase hex, per the reference implementation; the
 * macaroon is passed through byte for byte, because re-encoding it (padding,
 * alphabet) would change a value the server compares literally.
 */
export function buildL402AuthorizationHeader(
	macaroon: string,
	preimage: Buffer | string,
	scheme: 'L402' | 'LSAT' = 'L402'
): string {
	const preimageHex =
		typeof preimage === 'string'
			? preimage.trim().toLowerCase()
			: preimage.toString('hex');
	if (!/^[0-9a-f]{64}$/.test(preimageHex)) {
		throw new Error('L402: preimage must be 32 bytes of hex');
	}
	if (!macaroon || /[\s,]/.test(macaroon)) {
		throw new Error('L402: macaroon must be a non-empty header-safe token');
	}
	return `${scheme} ${macaroon}:${preimageHex}`;
}

/**
 * Parse an `Authorization: L402 <macaroon>:<preimage>` value back apart.
 * Used by tests and by the mock server; a client never needs it.
 */
export function parseL402AuthorizationHeader(
	header: string
): { macaroon: string; preimage: string } | null {
	if (!header) return null;
	const match = /^\s*(L402|LSAT)\s+([^\s:]+):([0-9a-fA-F]{64})\s*$/.exec(
		header
	);
	if (!match) return null;
	return { macaroon: match[2], preimage: match[3].toLowerCase() };
}
