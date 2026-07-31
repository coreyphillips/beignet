/**
 * L402 (Lightning HTTP 402) client, issue #266 phase 1.
 *
 * Tests cover:
 * 1. Challenge parsing: both schemes, both parameter orders, quoted and bare,
 *    other schemes alongside, and the malformed cases that must not parse
 * 2. Authorization header build and round trip
 * 3. Macaroon v2 binary reader and L402 identifier extraction
 * 4. Challenge validation: hash commitment, price cap, amountless invoices,
 *    unparseable macaroons (fail closed)
 * 5. l402Fetch end to end against an in-repo mock L402 server: pay, retry,
 *    credential reuse, rejection handling, and pay-at-most-once
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	buildL402AuthorizationHeader,
	parseL402AuthorizationHeader,
	parseL402Challenge
} from '../../src/lightning/l402/challenge';
import {
	macaroonPaymentHash,
	parseL402Identifier,
	parseMacaroon
} from '../../src/lightning/l402/macaroon';
import {
	defaultFeeCapSats,
	L402Error,
	l402Fetch,
	validateChallenge,
	IL402Response
} from '../../src/lightning/l402/client';
import {
	credentialScope,
	MemoryL402CredentialStore
} from '../../src/lightning/l402/credentials';
import { encode as encodeInvoice } from '../../src/lightning/invoice/encode';
import { decode as decodeInvoice } from '../../src/lightning/invoice/decode';
import { Network } from '../../src/lightning/invoice/types';

// ─────────────── Fixtures ───────────────

const NODE_PRIVKEY = crypto
	.createHash('sha256')
	.update('l402-test-node-key')
	.digest();

/** Encode a varint the way the macaroon v2 format does. */
function varint(value: number): Buffer {
	const bytes: number[] = [];
	let v = value;
	while (v > 0x7f) {
		bytes.push((v & 0x7f) | 0x80);
		v >>>= 7;
	}
	bytes.push(v);
	return Buffer.from(bytes);
}

function field(type: number, value: Buffer): Buffer {
	return Buffer.concat([varint(type), varint(value.length), value]);
}

/**
 * Build a macaroon in the v2 binary encoding lnd and Aperture emit, with an
 * L402 identifier committing to `paymentHash`.
 */
function makeMacaroon(
	paymentHash: Buffer,
	options: {
		location?: string;
		caveats?: string[];
		identifierOverride?: Buffer;
	} = {}
): string {
	const identifier =
		options.identifierOverride ??
		Buffer.concat([
			Buffer.from([0x00, 0x00]), // version 0
			paymentHash,
			crypto.randomBytes(32) // token id
		]);

	const parts: Buffer[] = [Buffer.from([0x02])];
	if (options.location) {
		parts.push(field(1, Buffer.from(options.location, 'utf8')));
	}
	parts.push(field(2, identifier));
	parts.push(Buffer.from([0x00])); // end of header section
	for (const caveat of options.caveats ?? []) {
		parts.push(field(2, Buffer.from(caveat, 'utf8')));
		parts.push(Buffer.from([0x00])); // end of this caveat
	}
	parts.push(Buffer.from([0x00])); // end of caveat section
	parts.push(field(6, crypto.randomBytes(32))); // signature
	return Buffer.concat(parts).toString('base64');
}

function makeInvoice(paymentHash: Buffer, amountMsat?: bigint): string {
	return encodeInvoice({
		network: Network.REGTEST,
		amountMsat,
		paymentHash,
		paymentSecret: crypto.randomBytes(32),
		description: 'l402 test',
		timestamp: Math.floor(Date.now() / 1000),
		expiry: 3600,
		privateKey: NODE_PRIVKEY
	});
}

/** A challenge pair whose macaroon and invoice agree on the payment hash. */
function makeChallengePair(amountMsat = 1_000n): {
	paymentHash: Buffer;
	preimage: Buffer;
	macaroon: string;
	invoice: string;
} {
	const preimage = crypto.randomBytes(32);
	const paymentHash = crypto.createHash('sha256').update(preimage).digest();
	return {
		paymentHash,
		preimage,
		macaroon: makeMacaroon(paymentHash, { location: 'test.example' }),
		invoice: makeInvoice(paymentHash, amountMsat)
	};
}

// ─────────────── Mock L402 server ───────────────

interface IMockServerOptions {
	/** Satoshis the server charges. */
	priceSats?: number;
	/** Serve a macaroon committing to a DIFFERENT hash than the invoice. */
	mismatchedCommitment?: boolean;
	/** Reject any Authorization header, forcing a re-challenge. */
	rejectCredentials?: boolean;
	/** Answer the paid retry with another 402. */
	alwaysChallenge?: boolean;
}

/**
 * An in-process L402 server: 402 with a challenge until a request arrives
 * carrying a valid Authorization, then 200.
 */
function createMockL402Server(options: IMockServerOptions = {}): {
	fetchImpl: (
		url: string,
		init?: { headers?: Record<string, string> }
	) => Promise<IL402Response>;
	payer: {
		payments: number;
		payInvoice: (b: string) => Promise<{ preimage: Buffer }>;
	};
	requests: Array<{ authorization?: string }>;
} {
	const priceMsat = BigInt(options.priceSats ?? 1) * 1000n;
	const issued = new Map<string, string>(); // macaroon -> preimage hex
	const requests: Array<{ authorization?: string }> = [];

	const fetchImpl = async (
		_url: string,
		init?: { headers?: Record<string, string> }
	): Promise<IL402Response> => {
		const authorization =
			init?.headers?.Authorization ?? init?.headers?.authorization;
		requests.push({ authorization });

		const parsed = authorization
			? parseL402AuthorizationHeader(authorization)
			: null;
		const accepted =
			parsed &&
			!options.rejectCredentials &&
			!options.alwaysChallenge &&
			issued.get(parsed.macaroon) === parsed.preimage;

		if (accepted) {
			return {
				status: 200,
				headers: { get: (): string | null => null },
				text: async (): Promise<string> => 'the paid content'
			};
		}

		const preimage = crypto.randomBytes(32);
		const paymentHash = crypto.createHash('sha256').update(preimage).digest();
		const committedHash = options.mismatchedCommitment
			? crypto.randomBytes(32)
			: paymentHash;
		const macaroon = makeMacaroon(committedHash, { location: 'mock.example' });
		issued.set(macaroon, preimage.toString('hex'));

		const header = `L402 macaroon="${macaroon}", invoice="${makeInvoice(
			paymentHash,
			priceMsat
		)}"`;
		return {
			status: 402,
			headers: {
				get: (name: string): string | null =>
					name.toLowerCase() === 'www-authenticate' ? header : null
			},
			text: async (): Promise<string> => 'payment required'
		};
	};

	/**
	 * Pays like a real payer would: settle the hash in the invoice it was
	 * handed, not whichever preimage happens to be lying around. Looking it up
	 * any other way would let a mismatched-commitment test pass by accident.
	 */
	const payer = {
		payments: 0,
		payInvoice: async (bolt11: string): Promise<{ preimage: Buffer }> => {
			payer.payments++;
			const invoiceHash = decodeInvoice(bolt11).paymentHash;
			for (const preimageHex of issued.values()) {
				const hash = crypto
					.createHash('sha256')
					.update(Buffer.from(preimageHex, 'hex'))
					.digest();
				if (hash.equals(invoiceHash)) {
					return { preimage: Buffer.from(preimageHex, 'hex') };
				}
			}
			throw new Error('mock: no preimage for that invoice');
		}
	};

	return { fetchImpl, payer, requests };
}

// ─────────────── 1-2. Challenge parsing and headers ───────────────

describe('L402 challenge parsing', () => {
	it('parses a standard L402 challenge', () => {
		const parsed = parseL402Challenge(
			'L402 macaroon="AGIAJEem", invoice="lnbc1500n1pchallenge"'
		);
		expect(parsed).to.not.equal(null);
		expect(parsed!.scheme).to.equal('L402');
		expect(parsed!.macaroon).to.equal('AGIAJEem');
		expect(parsed!.invoice).to.equal('lnbc1500n1pchallenge');
	});

	it('accepts the legacy LSAT scheme', () => {
		const parsed = parseL402Challenge(
			'LSAT macaroon="mac123", invoice="lnbc1invoice"'
		);
		expect(parsed!.scheme).to.equal('LSAT');
		expect(parsed!.macaroon).to.equal('mac123');
	});

	it('accepts either parameter order and unquoted values', () => {
		const parsed = parseL402Challenge('L402 invoice=lnbc1abc, macaroon=mac456');
		expect(parsed!.macaroon).to.equal('mac456');
		expect(parsed!.invoice).to.equal('lnbc1abc');
	});

	it('picks the L402 challenge out of a multi-scheme header', () => {
		const parsed = parseL402Challenge(
			'Basic realm="x", L402 macaroon="m1", invoice="lnbc1i"'
		);
		expect(parsed!.macaroon).to.equal('m1');
	});

	it('returns null when a parameter is missing', () => {
		expect(parseL402Challenge('L402 macaroon="onlymac"')).to.equal(null);
		expect(parseL402Challenge('L402 invoice="onlyinvoice"')).to.equal(null);
	});

	it('returns null for a non-L402 header or empty input', () => {
		expect(parseL402Challenge('Bearer realm="api"')).to.equal(null);
		expect(parseL402Challenge('')).to.equal(null);
	});

	it('does not mistake the scheme name inside a value for a challenge', () => {
		// A macaroon whose base64 happens to contain "L402" must not be read as
		// the start of a challenge.
		expect(parseL402Challenge('Bearer token="abcL402 macaroon=x"')).to.equal(
			null
		);
	});

	it('builds and re-parses an Authorization header', () => {
		const preimage = crypto.randomBytes(32);
		const header = buildL402AuthorizationHeader('macaroonvalue', preimage);
		expect(header).to.equal(`L402 macaroonvalue:${preimage.toString('hex')}`);
		const parsed = parseL402AuthorizationHeader(header);
		expect(parsed!.macaroon).to.equal('macaroonvalue');
		expect(parsed!.preimage).to.equal(preimage.toString('hex'));
	});

	it('echoes the legacy scheme back when the server used it', () => {
		const header = buildL402AuthorizationHeader(
			'mac',
			crypto.randomBytes(32),
			'LSAT'
		);
		expect(header.startsWith('LSAT ')).to.equal(true);
	});

	it('refuses a preimage that is not 32 bytes of hex', () => {
		expect(() => buildL402AuthorizationHeader('mac', 'nothex')).to.throw(
			'32 bytes of hex'
		);
	});

	it('refuses a macaroon that would break header framing', () => {
		expect(() =>
			buildL402AuthorizationHeader('has space', crypto.randomBytes(32))
		).to.throw('header-safe');
	});
});

// ─────────────── 3. Macaroon reader ───────────────

describe('L402 macaroon reader', () => {
	it('extracts the payment hash a macaroon commits to', () => {
		const paymentHash = crypto.randomBytes(32);
		const macaroon = makeMacaroon(paymentHash, { location: 'api.example' });

		const parsed = parseMacaroon(macaroon);
		expect(parsed.location).to.equal('api.example');
		expect(parsed.identifier).to.have.length(66);

		const identifier = parseL402Identifier(parsed.identifier);
		expect(identifier.version).to.equal(0);
		expect(identifier.paymentHash.equals(paymentHash)).to.equal(true);
		expect(identifier.tokenId).to.have.length(32);
	});

	it('reads a macaroon carrying caveats', () => {
		const paymentHash = crypto.randomBytes(32);
		const macaroon = makeMacaroon(paymentHash, {
			caveats: ['services=api:0', 'valid_until=2030-01-01']
		});
		const parsed = parseMacaroon(macaroon);
		expect(parsed.caveatCount).to.equal(2);
		expect(
			parseL402Identifier(parsed.identifier).paymentHash.equals(paymentHash)
		).to.equal(true);
	});

	it('accepts the url-safe base64 alphabet', () => {
		const paymentHash = crypto.randomBytes(32);
		const standard = makeMacaroon(paymentHash);
		const urlSafe = standard.replace(/\+/g, '-').replace(/\//g, '_');
		expect(macaroonPaymentHash(urlSafe)!.equals(paymentHash)).to.equal(true);
	});

	it('returns null rather than throwing for junk', () => {
		expect(macaroonPaymentHash('not-a-macaroon')).to.equal(null);
		expect(macaroonPaymentHash('')).to.equal(null);
	});

	it('rejects an unsupported macaroon version', () => {
		const v1 = Buffer.concat([Buffer.from([0x01]), crypto.randomBytes(20)]);
		expect(() => parseMacaroon(v1.toString('base64'))).to.throw(
			'unsupported version'
		);
	});

	it('rejects an identifier that is not an L402 identifier', () => {
		const macaroon = makeMacaroon(crypto.randomBytes(32), {
			identifierOverride: Buffer.from('some-other-scheme', 'utf8')
		});
		expect(() =>
			parseL402Identifier(parseMacaroon(macaroon).identifier)
		).to.throw('expected 66 bytes');
		expect(macaroonPaymentHash(macaroon)).to.equal(null);
	});

	it('rejects a truncated macaroon rather than reading past the end', () => {
		const full = Buffer.from(makeMacaroon(crypto.randomBytes(32)), 'base64');
		const truncated = full.subarray(0, 12).toString('base64');
		expect(() => parseMacaroon(truncated)).to.throw();
	});
});

// ─────────────── 4. Challenge validation ───────────────

describe('L402 challenge validation', () => {
	it('accepts a challenge whose macaroon and invoice agree', () => {
		const pair = makeChallengePair(2_000n);
		const price = validateChallenge(
			{ scheme: 'L402', macaroon: pair.macaroon, invoice: pair.invoice },
			{ maxPriceSats: 10 }
		);
		expect(price).to.equal(2);
	});

	it('refuses when the macaroon commits to a different payment hash', () => {
		const pair = makeChallengePair();
		const otherMacaroon = makeMacaroon(crypto.randomBytes(32));
		expect(() =>
			validateChallenge(
				{ scheme: 'L402', macaroon: otherMacaroon, invoice: pair.invoice },
				{ maxPriceSats: 100 }
			)
		)
			.to.throw(L402Error)
			.with.property('code', 'HASH_COMMITMENT_MISMATCH');
	});

	it('fails closed when the macaroon cannot be parsed', () => {
		const pair = makeChallengePair();
		expect(() =>
			validateChallenge(
				{ scheme: 'L402', macaroon: 'garbage', invoice: pair.invoice },
				{ maxPriceSats: 100 }
			)
		)
			.to.throw(L402Error)
			.with.property('code', 'UNVERIFIABLE_MACAROON');
	});

	it('pays an unverifiable macaroon only under an explicit opt-out', () => {
		const pair = makeChallengePair(1_000n);
		const price = validateChallenge(
			{ scheme: 'L402', macaroon: 'garbage', invoice: pair.invoice },
			{ maxPriceSats: 100, allowUnverifiedMacaroon: true }
		);
		expect(price).to.equal(1);
	});

	it('refuses a price above the cap', () => {
		const pair = makeChallengePair(50_000n);
		expect(() =>
			validateChallenge(
				{ scheme: 'L402', macaroon: pair.macaroon, invoice: pair.invoice },
				{ maxPriceSats: 10 }
			)
		)
			.to.throw(L402Error)
			.with.property('code', 'PRICE_ABOVE_CAP');
	});

	it('rounds a sub-satoshi price UP so it cannot slip past the cap', () => {
		// 1500 msat is more than 1 sat of value; rounding down would let it
		// through a 1 sat cap.
		const pair = makeChallengePair(1_500n);
		expect(() =>
			validateChallenge(
				{ scheme: 'L402', macaroon: pair.macaroon, invoice: pair.invoice },
				{ maxPriceSats: 1 }
			)
		)
			.to.throw(L402Error)
			.with.property('code', 'PRICE_ABOVE_CAP');
	});

	it('refuses an amountless invoice, whose price cannot be capped', () => {
		const pair = makeChallengePair();
		const amountless = makeInvoice(pair.paymentHash, undefined);
		expect(() =>
			validateChallenge(
				{ scheme: 'L402', macaroon: pair.macaroon, invoice: amountless },
				{ maxPriceSats: 1000 }
			)
		)
			.to.throw(L402Error)
			.with.property('code', 'AMOUNTLESS_INVOICE');
	});

	it('refuses an undecodable invoice', () => {
		const pair = makeChallengePair();
		expect(() =>
			validateChallenge(
				{ scheme: 'L402', macaroon: pair.macaroon, invoice: 'lnbcnonsense' },
				{ maxPriceSats: 1000 }
			)
		)
			.to.throw(L402Error)
			.with.property('code', 'INVALID_INVOICE');
	});
});

// ─────────────── 5. l402Fetch end to end ───────────────

describe('l402Fetch against a mock L402 server', () => {
	it('pays the challenge and returns the gated content', async () => {
		const server = createMockL402Server({ priceSats: 3 });
		const result = await l402Fetch(
			'https://mock.example/api/data',
			{},
			{
				payer: server.payer,
				maxPriceSats: 10,
				fetchImpl: server.fetchImpl,
				credentials: new MemoryL402CredentialStore()
			}
		);

		expect(result.response.status).to.equal(200);
		expect(await result.response.text()).to.equal('the paid content');
		expect(result.paid).to.equal(true);
		expect(result.amountPaidSats).to.equal(3);
		expect(server.payer.payments).to.equal(1);
		// One unauthenticated request, then one carrying the credential.
		expect(server.requests).to.have.length(2);
		expect(server.requests[0].authorization).to.equal(undefined);
		expect(server.requests[1].authorization).to.match(/^L402 /);
	});

	it('reuses a stored credential instead of paying again', async () => {
		const server = createMockL402Server({ priceSats: 1 });
		const store = new MemoryL402CredentialStore();
		const options = {
			payer: server.payer,
			maxPriceSats: 10,
			fetchImpl: server.fetchImpl,
			credentials: store
		};

		await l402Fetch('https://mock.example/a', {}, options);
		const second = await l402Fetch('https://mock.example/b', {}, options);

		expect(second.paid).to.equal(false);
		expect(second.amountPaidSats).to.equal(0);
		expect(second.response.status).to.equal(200);
		expect(server.payer.payments, 'paid once for the origin').to.equal(1);
		expect(store.list()).to.have.length(1);
	});

	it('drops a credential the server rejects and re-challenges', async () => {
		const server = createMockL402Server({ priceSats: 1 });
		const store = new MemoryL402CredentialStore();
		store.set({
			scope: credentialScope('https://mock.example/api'),
			macaroon: makeMacaroon(crypto.randomBytes(32)),
			preimage: crypto.randomBytes(32).toString('hex'),
			paymentHash: crypto.randomBytes(32).toString('hex'),
			amountSats: 1,
			createdAt: Date.now(),
			scheme: 'L402'
		});

		const result = await l402Fetch(
			'https://mock.example/api',
			{},
			{
				payer: server.payer,
				maxPriceSats: 10,
				fetchImpl: server.fetchImpl,
				credentials: store
			}
		);

		expect(result.response.status).to.equal(200);
		expect(result.paid).to.equal(true);
		expect(server.payer.payments).to.equal(1);
	});

	it('pays at most once even when the server keeps challenging', async () => {
		const server = createMockL402Server({ alwaysChallenge: true });
		const result = await l402Fetch(
			'https://mock.example/loop',
			{},
			{
				payer: server.payer,
				maxPriceSats: 10,
				fetchImpl: server.fetchImpl,
				credentials: new MemoryL402CredentialStore()
			}
		);

		expect(result.response.status).to.equal(402);
		expect(result.paid).to.equal(true);
		expect(server.payer.payments, 'no payment loop').to.equal(1);
	});

	it('pays nothing when the macaroon commits to a different hash', async () => {
		const server = createMockL402Server({ mismatchedCommitment: true });
		let error: unknown;
		try {
			await l402Fetch(
				'https://mock.example/api',
				{},
				{
					payer: server.payer,
					maxPriceSats: 10,
					fetchImpl: server.fetchImpl,
					credentials: new MemoryL402CredentialStore()
				}
			);
		} catch (err) {
			error = err;
		}
		expect(error).to.be.instanceOf(L402Error);
		expect((error as L402Error).code).to.equal('HASH_COMMITMENT_MISMATCH');
		expect(server.payer.payments, 'refused before paying').to.equal(0);
	});

	it('pays nothing when the price is above the cap', async () => {
		const server = createMockL402Server({ priceSats: 5000 });
		let error: unknown;
		try {
			await l402Fetch(
				'https://mock.example/expensive',
				{},
				{
					payer: server.payer,
					maxPriceSats: 10,
					fetchImpl: server.fetchImpl,
					credentials: new MemoryL402CredentialStore()
				}
			);
		} catch (err) {
			error = err;
		}
		expect((error as L402Error).code).to.equal('PRICE_ABOVE_CAP');
		expect(server.payer.payments).to.equal(0);
	});

	it('refuses a challenge when no payer is configured', async () => {
		const server = createMockL402Server({ priceSats: 1 });
		let error: unknown;
		try {
			await l402Fetch(
				'https://mock.example/api',
				{},
				{ maxPriceSats: 10, fetchImpl: server.fetchImpl }
			);
		} catch (err) {
			error = err;
		}
		expect((error as L402Error).code).to.equal('NO_PAYER');
	});

	it('passes a non-402 response straight through unpaid', async () => {
		const fetchImpl = async (): Promise<IL402Response> => ({
			status: 200,
			headers: { get: (): string | null => null },
			text: async (): Promise<string> => 'ungated'
		});
		const result = await l402Fetch(
			'https://open.example/free',
			{},
			{ maxPriceSats: 10, fetchImpl }
		);
		expect(result.paid).to.equal(false);
		expect(await result.response.text()).to.equal('ungated');
	});

	it('passes a 402 carrying no L402 challenge straight through', async () => {
		const fetchImpl = async (): Promise<IL402Response> => ({
			status: 402,
			headers: {
				get: (): string | null => 'Bearer realm="pay"'
			},
			text: async (): Promise<string> => 'some other 402'
		});
		const result = await l402Fetch(
			'https://other.example/x',
			{},
			{ maxPriceSats: 10, fetchImpl }
		);
		expect(result.response.status).to.equal(402);
		expect(result.paid).to.equal(false);
	});

	it('rejects a negative or non-numeric price cap up front', async () => {
		const server = createMockL402Server();
		let error: unknown;
		try {
			await l402Fetch(
				'https://mock.example/x',
				{},
				{ maxPriceSats: -1, fetchImpl: server.fetchImpl }
			);
		} catch (err) {
			error = err;
		}
		expect((error as Error).message).to.match(/non-negative/);
	});

	it('scopes credentials per origin by default and per path on request', () => {
		expect(credentialScope('https://api.example/v1/data')).to.equal(
			'https://api.example'
		);
		expect(credentialScope('https://api.example/v1/data', true)).to.equal(
			'https://api.example/v1/data'
		);
	});

	it('bounds the credential store rather than growing without limit', () => {
		const store = new MemoryL402CredentialStore(2);
		for (let i = 0; i < 5; i++) {
			store.set({
				scope: `https://host${i}.example`,
				macaroon: 'm',
				preimage: 'a'.repeat(64),
				paymentHash: 'b'.repeat(64),
				amountSats: 1,
				createdAt: Date.now(),
				scheme: 'L402'
			});
		}
		expect(store.list()).to.have.length(2);
		// Oldest evicted first, so the newest survive.
		expect(store.get('https://host4.example')).to.not.equal(undefined);
		expect(store.get('https://host0.example')).to.equal(undefined);
	});
});

// ─────────────── 6. Refusals that must happen BEFORE paying ───────────────
//
// Every case here is one where the old code paid first and discovered the
// problem afterwards, or never bounded the spend at all. The assertion that
// matters in each is `payments === 0`, or the cap the payer was handed.

describe('l402Fetch payment safety', () => {
	/** A payer that records what it was asked to do and settles honestly. */
	function recordingPayer(preimage: Buffer): {
		payments: number;
		lastOptions?: { maxFeeSats?: number; timeoutMs?: number };
		payInvoice: (
			bolt11: string,
			options: { maxFeeSats?: number; timeoutMs?: number }
		) => Promise<{ preimage: Buffer }>;
	} {
		const payer = {
			payments: 0,
			lastOptions: undefined as
				| { maxFeeSats?: number; timeoutMs?: number }
				| undefined,
			payInvoice: async (
				_bolt11: string,
				options: { maxFeeSats?: number; timeoutMs?: number }
			): Promise<{ preimage: Buffer }> => {
				payer.payments++;
				payer.lastOptions = options;
				return { preimage };
			}
		};
		return payer;
	}

	/** A server that answers every request with one fixed challenge header. */
	function fixedChallengeServer(
		header: string,
		finalUrl?: string
	): (url: string) => Promise<IL402Response> {
		return async (url: string): Promise<IL402Response> => ({
			status: 402,
			url: finalUrl ?? url,
			headers: {
				get: (name: string): string | null =>
					name.toLowerCase() === 'www-authenticate' ? header : null
			},
			text: async (): Promise<string> => 'payment required'
		});
	}

	it('caps the routing fee even when the caller sets none', async () => {
		const pair = makeChallengePair(100_000n); // 100 sat
		const payer = recordingPayer(pair.preimage);
		await l402Fetch(
			'https://mock.example/x',
			{},
			{
				payer,
				maxPriceSats: 200,
				fetchImpl: fixedChallengeServer(
					`L402 macaroon="${pair.macaroon}", invoice="${pair.invoice}"`
				)
			}
		);
		// Without a default the payer would receive undefined, which disables
		// the fee check outright and lets a hostile routing hint bill whatever
		// the channel can pay.
		expect(payer.lastOptions?.maxFeeSats).to.equal(defaultFeeCapSats(100));
		expect(payer.lastOptions?.maxFeeSats).to.equal(5);
	});

	it('keeps a floor under the fee cap for sub-satoshi prices', () => {
		expect(defaultFeeCapSats(1)).to.equal(5);
		expect(defaultFeeCapSats(1000)).to.equal(50);
	});

	it('lets the caller set a fee cap of their own', async () => {
		const pair = makeChallengePair(1_000n);
		const payer = recordingPayer(pair.preimage);
		await l402Fetch(
			'https://mock.example/x',
			{},
			{
				payer,
				maxPriceSats: 10,
				maxFeeSats: 3,
				fetchImpl: fixedChallengeServer(
					`L402 macaroon="${pair.macaroon}", invoice="${pair.invoice}"`
				)
			}
		);
		expect(payer.lastOptions?.maxFeeSats).to.equal(3);
	});

	it('refuses a macaroon it could not send back, without paying', async () => {
		// Base64 decoding ignores whitespace, so this macaroon parses and
		// commits to the right hash; only the header build would reject it.
		const pair = makeChallengePair(1_000n);
		const spaced = `${pair.macaroon.slice(0, 8)} ${pair.macaroon.slice(8)}`;
		expect(macaroonPaymentHash(spaced)?.toString('hex')).to.equal(
			pair.paymentHash.toString('hex')
		);

		const payer = recordingPayer(pair.preimage);
		const store = new MemoryL402CredentialStore();
		let error: unknown;
		try {
			await l402Fetch(
				'https://mock.example/x',
				{},
				{
					payer,
					maxPriceSats: 10,
					credentials: store,
					fetchImpl: fixedChallengeServer(
						`L402 macaroon="${spaced}", invoice="${pair.invoice}"`
					)
				}
			);
		} catch (err) {
			error = err;
		}
		expect((error as L402Error).code).to.equal('UNUSABLE_MACAROON');
		expect(payer.payments).to.equal(0);
		expect(store.list()).to.have.length(0);
	});

	it('refuses a challenge that arrived from another origin', async () => {
		const pair = makeChallengePair(1_000n);
		const payer = recordingPayer(pair.preimage);
		const fetchImpl = fixedChallengeServer(
			`L402 macaroon="${pair.macaroon}", invoice="${pair.invoice}"`,
			'https://evil.example/pay'
		);
		let error: unknown;
		try {
			await l402Fetch(
				'https://trusted.example/x',
				{},
				{ payer, maxPriceSats: 10, fetchImpl }
			);
		} catch (err) {
			error = err;
		}
		expect((error as L402Error).code).to.equal('CROSS_ORIGIN_CHALLENGE');
		expect(payer.payments).to.equal(0);

		// Opt in and the same challenge is paid, so the refusal is a policy and
		// not an inability.
		const allowed = await l402Fetch(
			'https://trusted.example/x',
			{},
			{
				payer,
				maxPriceSats: 10,
				fetchImpl,
				allowCrossOriginChallenge: true
			}
		);
		expect(allowed.paid).to.equal(true);
		expect(payer.payments).to.equal(1);
	});

	it('rejects a preimage that does not open the invoice hash', async () => {
		const pair = makeChallengePair(1_000n);
		const payer = recordingPayer(crypto.randomBytes(32)); // wrong preimage
		const store = new MemoryL402CredentialStore();
		let error: unknown;
		try {
			await l402Fetch(
				'https://mock.example/x',
				{},
				{
					payer,
					maxPriceSats: 10,
					credentials: store,
					fetchImpl: fixedChallengeServer(
						`L402 macaroon="${pair.macaroon}", invoice="${pair.invoice}"`
					)
				}
			);
		} catch (err) {
			error = err;
		}
		expect((error as L402Error).code).to.equal('PREIMAGE_MISMATCH');
		// A credential that cannot authenticate must not be stored: it would
		// fail every later request until someone forgot it by hand.
		expect(store.list()).to.have.length(0);
	});

	it('bounds each request with a timeout signal', async () => {
		const pair = makeChallengePair(1_000n);
		const signals: Array<AbortSignal | undefined> = [];
		const fetchImpl = async (
			url: string,
			init?: { signal?: AbortSignal }
		): Promise<IL402Response> => {
			signals.push(init?.signal);
			return {
				status: 402,
				url,
				headers: {
					get: (name: string): string | null =>
						name.toLowerCase() === 'www-authenticate'
							? `L402 macaroon="${pair.macaroon}", invoice="${pair.invoice}"`
							: null
				},
				text: async (): Promise<string> => 'payment required'
			};
		};
		await l402Fetch(
			'https://mock.example/x',
			{},
			{ payer: recordingPayer(pair.preimage), maxPriceSats: 10, fetchImpl }
		);
		expect(signals).to.have.length.greaterThan(0);
		for (const signal of signals) {
			expect(signal, 'every request carries an abort signal').to.not.equal(
				undefined
			);
		}
	});

	it('drops a stored credential that cannot be turned into a header', async () => {
		const pair = makeChallengePair(1_000n);
		const store = new MemoryL402CredentialStore();
		store.set({
			scope: 'https://mock.example',
			macaroon: 'not a header safe value',
			preimage: 'a'.repeat(64),
			paymentHash: 'b'.repeat(64),
			amountSats: 1,
			createdAt: Date.now(),
			scheme: 'L402'
		});
		// The request still goes out (and is answered), rather than throwing
		// before it and wedging the scope for the process lifetime.
		const result = await l402Fetch(
			'https://mock.example/x',
			{},
			{
				payer: recordingPayer(pair.preimage),
				maxPriceSats: 10,
				credentials: store,
				fetchImpl: fixedChallengeServer(
					`L402 macaroon="${pair.macaroon}", invoice="${pair.invoice}"`
				)
			}
		);
		expect(result.paid).to.equal(true);
	});
});

// ─────────────── 7. Parsing hardening ───────────────

describe('L402 parsing cannot be confused across challenges', () => {
	it('never pairs a macaroon and invoice from different challenges', () => {
		// The macaroon belongs to the LSAT challenge and the invoice to the
		// L402 one; pairing them produces something no server ever issued.
		const parsed = parseL402Challenge(
			'L402 invoice="i1", Bearer x, LSAT macaroon="m2", invoice="i2"'
		);
		expect(parsed!.scheme).to.equal('LSAT');
		expect(parsed!.macaroon).to.equal('m2');
		expect(parsed!.invoice).to.equal('i2');
	});

	it('does not read a challenge out of another scheme quoted value', () => {
		// A server (or CDN) reflecting caller-controlled text into a realm must
		// not be able to smuggle in a challenge of its own.
		const parsed = parseL402Challenge(
			'Bearer realm="foo, L402 macaroon=\\"INJECTED\\", invoice=\\"lnbcINJECT\\""'
		);
		expect(parsed).to.equal(null);
	});

	it('refuses a challenge that gives a parameter twice', () => {
		expect(
			parseL402Challenge(
				'L402 macaroon="m1", macaroon="m2", invoice="lnbc1abc"'
			)
		).to.equal(null);
	});

	it('still parses the ordinary shapes', () => {
		const spaced = parseL402Challenge(
			'  L402   macaroon = "mac" ,  invoice = "lnbc1xyz"  '
		);
		expect(spaced!.macaroon).to.equal('mac');
		expect(spaced!.invoice).to.equal('lnbc1xyz');
	});

	it('rejects a macaroon carrying a second identifier', () => {
		// Strict server-side parsers take the FIRST identifier, so honouring
		// the last one would check the commitment against a hash the server
		// never bound the token to.
		const first = crypto.randomBytes(32);
		const second = crypto.randomBytes(32);
		const macaroon = Buffer.concat([
			Buffer.from([0x02]),
			field(
				2,
				Buffer.concat([
					Buffer.from([0x00, 0x00]),
					first,
					crypto.randomBytes(32)
				])
			),
			field(
				2,
				Buffer.concat([
					Buffer.from([0x00, 0x00]),
					second,
					crypto.randomBytes(32)
				])
			),
			Buffer.from([0x00]),
			Buffer.from([0x00]),
			field(6, crypto.randomBytes(32))
		]).toString('base64');

		expect(() => parseMacaroon(macaroon)).to.throw(/duplicate identifier/);
		expect(macaroonPaymentHash(macaroon)).to.equal(null);

		// And a challenge carrying it is refused rather than paid.
		expect(() =>
			validateChallenge(
				{ scheme: 'L402', macaroon, invoice: makeInvoice(first, 1_000n) },
				{ maxPriceSats: 10 }
			)
		).to.throw(/could not be parsed/);
	});
});
