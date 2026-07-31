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

/** RFC 7230 tchar: the characters a scheme or parameter name may use. */
const TOKEN_CHARS = "[!#$%&'*+.^_`|~0-9A-Za-z-]+";

/** One challenge as it appeared in the header, before L402 interpretation. */
interface IRawChallenge {
	scheme: string;
	params: Map<string, string>;
	/** A parameter given twice is ambiguous, so the challenge is unusable. */
	duplicated: boolean;
}

/**
 * Pull the L402 (or LSAT) challenge out of a `WWW-Authenticate` header.
 *
 * Returns null when the header carries no usable L402 challenge, which is not
 * an error: a server may legitimately answer 402 with a different scheme, and
 * the caller then simply surfaces the response.
 *
 * The header is split into whole challenges per RFC 7235 FIRST, and both
 * parameters must come from the SAME challenge. That is a payment-safety
 * property, not tidiness: reading `macaroon` from one challenge and `invoice`
 * from another produces a pair the server never issued together, and a header
 * that merely quotes attacker-controlled text (a reflected `realm`, say) could
 * otherwise smuggle in a challenge of its own and be paid.
 *
 * Still tolerant of the shapes seen in the wild: either parameter order,
 * optional quoting, extra whitespace, and other schemes listed alongside.
 * Deliberately NOT tolerant of a challenge missing either parameter, or of
 * one that gives either parameter twice.
 */
export function parseL402Challenge(header: string): IL402Challenge | null {
	if (!header || header.length > MAX_HEADER_LENGTH) return null;

	for (const raw of splitChallenges(header)) {
		const scheme = L402_SCHEMES.find(
			(s) => s.toLowerCase() === raw.scheme.toLowerCase()
		);
		if (!scheme || raw.duplicated) continue;

		const macaroon = raw.params.get('macaroon');
		const invoice = raw.params.get('invoice');
		if (!macaroon || !invoice) continue;

		return { scheme, macaroon, invoice };
	}
	return null;
}

/**
 * Split a `WWW-Authenticate` value into its challenges.
 *
 * A challenge starts at a token NOT followed by `=` (the scheme); every
 * `name=value` item after it belongs to that challenge until the next scheme
 * token. Commas inside a quoted value are data, not separators, which is what
 * stops a quoted parameter from being read as further challenges.
 */
function splitChallenges(header: string): IRawChallenge[] {
	const challenges: IRawChallenge[] = [];
	let current: IRawChallenge | null = null;

	for (const item of splitTopLevelCommas(header)) {
		// `scheme name=value`: opens a challenge and carries its first param.
		const withParam = new RegExp(
			`^(${TOKEN_CHARS})\\s+(${TOKEN_CHARS})\\s*=\\s*([\\s\\S]*)$`
		).exec(item);
		if (withParam) {
			current = { scheme: withParam[1], params: new Map(), duplicated: false };
			challenges.push(current);
			addParam(current, withParam[2], withParam[3]);
			continue;
		}

		// `name=value`: another parameter of the challenge already open.
		const param = new RegExp(`^(${TOKEN_CHARS})\\s*=\\s*([\\s\\S]*)$`).exec(
			item
		);
		if (param && current) {
			addParam(current, param[1], param[2]);
			continue;
		}

		// Anything else opens a challenge with no parameters of its own: a bare
		// scheme, or the token68 form (`Bearer <token>`).
		const bare = new RegExp(`^(${TOKEN_CHARS})(?:\\s+\\S+)?$`).exec(item);
		if (bare) {
			current = { scheme: bare[1], params: new Map(), duplicated: false };
			challenges.push(current);
			continue;
		}
		// Unparseable item: end the current challenge rather than letting a
		// later parameter attach to it across the gap.
		current = null;
	}
	return challenges;
}

/**
 * Record one parameter, flagging a repeat rather than picking a winner. An
 * empty value still claims its name: `macaroon="", macaroon="x"` is the same
 * ambiguity as two non-empty values, and skipping the empty one would let the
 * second quietly win. An empty macaroon or invoice never parses into a
 * challenge anyway, since both are required to be non-empty.
 */
function addParam(
	challenge: IRawChallenge,
	name: string,
	rawValue: string
): void {
	const key = name.toLowerCase();
	if (challenge.params.has(key)) {
		challenge.duplicated = true;
		return;
	}
	challenge.params.set(key, unquote(rawValue));
}

/** Strip surrounding quotes and resolve backslash escapes inside them. */
function unquote(value: string): string {
	const trimmed = value.trim();
	if (trimmed.length >= 2 && trimmed.startsWith('"') && trimmed.endsWith('"')) {
		return trimmed.slice(1, -1).replace(/\\(.)/g, '$1').trim();
	}
	return trimmed;
}

/** Split on commas that are not inside a quoted string. */
function splitTopLevelCommas(header: string): string[] {
	const items: string[] = [];
	let current = '';
	let inQuotes = false;

	for (let i = 0; i < header.length; i++) {
		const ch = header[i];
		if (inQuotes) {
			if (ch === '\\' && i + 1 < header.length) {
				current += ch + header[i + 1];
				i++;
				continue;
			}
			if (ch === '"') inQuotes = false;
			current += ch;
			continue;
		}
		if (ch === '"') {
			inQuotes = true;
			current += ch;
			continue;
		}
		if (ch === ',') {
			items.push(current);
			current = '';
			continue;
		}
		current += ch;
	}
	items.push(current);

	return items.map((s) => s.trim()).filter((s) => s.length > 0);
}

/**
 * Whether a macaroon can be sent back in an `Authorization` header byte for
 * byte. Checked BEFORE paying: base64 decoding ignores whitespace, so a
 * macaroon carrying a space (a server wrapping its base64, or one doing it
 * deliberately) parses fine and commits to the right hash, yet cannot be
 * echoed back. Discovering that after the payment would spend the sats and
 * throw away the purchase. A colon is rejected for the same reason: it is the
 * `macaroon:preimage` delimiter, so a macaroon containing one would mis-split
 * on the server. No base64 alphabet produces one, so nothing legitimate is
 * refused.
 */
export function isHeaderSafeMacaroon(macaroon: string): boolean {
	return Boolean(macaroon) && !/[\s,:]/.test(macaroon);
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
	if (!isHeaderSafeMacaroon(macaroon)) {
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
