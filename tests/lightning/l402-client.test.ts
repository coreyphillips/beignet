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
import http from 'http';
import { AddressInfo } from 'net';
import {
	buildL402AuthorizationHeader,
	isHeaderSafeMacaroon,
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
	FetchLike,
	isPrivateNetworkUrl,
	L402Error,
	l402Fetch,
	readCappedBody,
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

	it('sends a cross-origin credential to its issuer, never the redirector', async () => {
		const pair = makeChallengePair(1_000n);
		const seen: Array<{ at: 'a' | 'b'; authorization?: string }> = [];
		const b = http.createServer((req, res) => {
			seen.push({ at: 'b', authorization: req.headers.authorization });
			const parsed = parseL402AuthorizationHeader(
				req.headers.authorization ?? ''
			);
			if (parsed?.preimage === pair.preimage.toString('hex')) {
				res.end('paid content');
				return;
			}
			res.writeHead(402, {
				'WWW-Authenticate': `L402 macaroon="${pair.macaroon}", invoice="${pair.invoice}"`
			});
			res.end('payment required');
		});
		const a = http.createServer((req, res) => {
			seen.push({ at: 'a', authorization: req.headers.authorization });
			res.writeHead(302, { Location: `${bOrigin}/pay` });
			res.end();
		});
		const listen = async (server: http.Server): Promise<string> => {
			await new Promise<void>((resolve) =>
				server.listen(0, '127.0.0.1', resolve)
			);
			return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
		};
		const bOrigin = await listen(b);
		const aOrigin = await listen(a);

		try {
			// Once with fetch following redirects itself, once hop by hop.
			for (const checkRedirect of [undefined, (): void => {}]) {
				seen.length = 0;
				const payer = recordingPayer(pair.preimage);
				const store = new MemoryL402CredentialStore();
				const options = {
					payer,
					maxPriceSats: 10,
					credentials: store,
					allowCrossOriginChallenge: true,
					checkRedirect
				};

				const paid = await l402Fetch(`${aOrigin}/start`, {}, options);
				expect(seen.map((r) => [r.at, Boolean(r.authorization)])).to.deep.equal(
					[
						['a', false],
						['b', false],
						['b', true]
					]
				);
				expect(paid.paid).to.equal(true);
				expect(await paid.response.text()).to.equal('paid content');
				expect(store.get(bOrigin)).to.not.equal(undefined);
				expect(store.get(aOrigin)).to.equal(undefined);

				// A later call finds the credential under B and reuses it there.
				seen.length = 0;
				const reused = await l402Fetch(`${aOrigin}/start`, {}, options);
				expect(reused.paid).to.equal(false);
				expect(await reused.response.text()).to.equal('paid content');
				expect(payer.payments).to.equal(1);
				expect(seen.map((r) => [r.at, Boolean(r.authorization)])).to.deep.equal(
					[
						['a', false],
						['b', false],
						['b', true]
					]
				);
			}
		} finally {
			for (const server of [a, b]) {
				server.closeAllConnections();
				server.close();
			}
		}
	});

	it('refuses a cross-origin challenge to a POST, whose body a redirect may have dropped', async () => {
		const pair = makeChallengePair(1_000n);
		const payer = recordingPayer(pair.preimage);
		let error: unknown;
		try {
			await l402Fetch(
				'https://trusted.example/x',
				{ method: 'POST', body: 'secret-body' },
				{
					payer,
					maxPriceSats: 10,
					allowCrossOriginChallenge: true,
					fetchImpl: fixedChallengeServer(
						`L402 macaroon="${pair.macaroon}", invoice="${pair.invoice}"`,
						'https://other.example/pay'
					)
				}
			);
		} catch (err) {
			error = err;
		}
		expect((error as L402Error).code).to.equal('CROSS_ORIGIN_CHALLENGE');
		expect(payer.payments).to.equal(0);
	});

	it('replaces a cross-origin credential its issuer rejects with 401', async () => {
		const pair = makeChallengePair(1_000n);
		const payer = recordingPayer(pair.preimage);
		const store = new MemoryL402CredentialStore();
		store.set({
			scope: 'https://issuer.example',
			macaroon: makeMacaroon(crypto.randomBytes(32)),
			preimage: crypto.randomBytes(32).toString('hex'),
			paymentHash: crypto.randomBytes(32).toString('hex'),
			amountSats: 1,
			createdAt: Date.now(),
			scheme: 'L402'
		});
		const challenge = `L402 macaroon="${pair.macaroon}", invoice="${pair.invoice}"`;
		// Every request ends at the issuer: unauthenticated ones are
		// challenged, and only the fresh credential is accepted.
		const fetchImpl: FetchLike = async (_url, init) => {
			const authorization = init?.headers?.Authorization;
			const status = !authorization
				? 402
				: authorization.includes(pair.preimage.toString('hex'))
				? 200
				: 401;
			return {
				status,
				url: 'https://issuer.example/pay',
				headers: {
					get: (name: string): string | null =>
						status === 402 && name.toLowerCase() === 'www-authenticate'
							? challenge
							: null
				},
				text: async (): Promise<string> => ''
			};
		};

		const result = await l402Fetch(
			'https://redirector.example/x',
			{},
			{
				payer,
				maxPriceSats: 10,
				credentials: store,
				allowCrossOriginChallenge: true,
				fetchImpl
			}
		);
		expect(result.response.status).to.equal(200);
		expect(result.paid).to.equal(true);
		expect(store.get('https://issuer.example')?.preimage).to.equal(
			pair.preimage.toString('hex')
		);
	});

	it('keeps a cross-origin credential when a redirect past its issuer ends in 401', async () => {
		const pair = makeChallengePair(1_000n);
		const payer = recordingPayer(pair.preimage);
		const store = new MemoryL402CredentialStore();
		const heldPreimage = crypto.randomBytes(32).toString('hex');
		store.set({
			scope: 'https://issuer.example',
			macaroon: makeMacaroon(crypto.randomBytes(32)),
			preimage: heldPreimage,
			paymentHash: crypto.randomBytes(32).toString('hex'),
			amountSats: 1,
			createdAt: Date.now(),
			scheme: 'L402'
		});
		const challenge = `L402 macaroon="${pair.macaroon}", invoice="${pair.invoice}"`;
		// Unauthenticated requests end at the issuer's challenge. The issuer
		// accepts the held credential and redirects to another origin, which
		// answers 401 because the hop stripped the credential.
		const fetchImpl: FetchLike = async (_url, init) => {
			const authenticated = Boolean(init?.headers?.Authorization);
			return {
				status: authenticated ? 401 : 402,
				url: authenticated
					? 'https://downstream.example/x'
					: 'https://issuer.example/pay',
				headers: {
					get: (name: string): string | null =>
						!authenticated && name.toLowerCase() === 'www-authenticate'
							? challenge
							: null
				},
				text: async (): Promise<string> => ''
			};
		};

		const result = await l402Fetch(
			'https://redirector.example/x',
			{},
			{
				payer,
				maxPriceSats: 10,
				credentials: store,
				allowCrossOriginChallenge: true,
				fetchImpl
			}
		);
		expect(result.response.status).to.equal(401);
		expect(result.paid).to.equal(false);
		expect(payer.payments).to.equal(0);
		expect(store.get('https://issuer.example')?.preimage).to.equal(
			heldPreimage
		);
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

// ─────────────── Review fixes: coalescing, capping, target hygiene ───────────────

describe('L402 concurrent calls and result hygiene', () => {
	it('pays once when two calls race on the same scope', async () => {
		const { fetchImpl, payer } = createMockL402Server({ priceSats: 3 });
		// Yield between request and response so the calls interleave: both see
		// their 402 before either has paid, the exact double-payment shape.
		const slowFetch: typeof fetchImpl = async (url, init) => {
			await new Promise((resolve) => setTimeout(resolve, 5));
			return fetchImpl(url, init);
		};
		const store = new MemoryL402CredentialStore();
		const opts = {
			payer,
			maxPriceSats: 10,
			credentials: store,
			fetchImpl: slowFetch
		};
		const [a, b] = await Promise.all([
			l402Fetch('https://api.example/data', {}, opts),
			l402Fetch('https://api.example/data', {}, opts)
		]);
		expect(payer.payments).to.equal(1);
		expect(a.response.status).to.equal(200);
		expect(b.response.status).to.equal(200);
		// Exactly one of the two calls carried the payment.
		expect(Number(a.paid) + Number(b.paid)).to.equal(1);
		expect(a.amountPaidSats + b.amountPaidSats).to.equal(3);
	});

	it('does not report a credential this call already dropped', async () => {
		const store = new MemoryL402CredentialStore();
		store.set({
			scope: 'https://api.example',
			macaroon: 'AAAA',
			preimage: '00'.repeat(32),
			paymentHash: '11'.repeat(32),
			amountSats: 1,
			createdAt: Date.now(),
			scheme: 'L402'
		});
		let calls = 0;
		const fetchImpl = async (): Promise<IL402Response> => {
			calls++;
			return calls === 1
				? {
						status: 401,
						headers: { get: (): string | null => null },
						text: async (): Promise<string> => 'no'
				  }
				: {
						status: 200,
						headers: { get: (): string | null => null },
						text: async (): Promise<string> => 'ok'
				  };
		};
		const result = await l402Fetch(
			'https://api.example/x',
			{},
			{ maxPriceSats: 10, credentials: store, fetchImpl }
		);
		expect(result.response.status).to.equal(200);
		expect(result.paid).to.equal(false);
		// The held credential was rejected by the server and deleted, so the
		// result must not present it as the one that worked.
		expect(result.credential).to.equal(undefined);
		expect(store.get('https://api.example')).to.equal(undefined);
	});

	it('refuses a macaroon containing the authorization delimiter', () => {
		expect(isHeaderSafeMacaroon('mac:aroon')).to.equal(false);
		expect(() =>
			buildL402AuthorizationHeader('mac:aroon', '00'.repeat(32))
		).to.throw(/header-safe/);
	});

	it('treats an empty then non-empty parameter as the same ambiguity', () => {
		expect(
			parseL402Challenge('L402 macaroon="", macaroon="m2", invoice="lnbc1abc"')
		).to.equal(null);
	});
});

describe('readCappedBody', () => {
	it('stops reading a streaming body at the cap and cancels the stream', async () => {
		const chunk = Buffer.alloc(1024, 0x61);
		let reads = 0;
		let cancelled = false;
		const response: IL402Response = {
			status: 200,
			headers: { get: (): string | null => null },
			text: async (): Promise<string> => {
				throw new Error('text() must not be used when a stream exists');
			},
			body: {
				getReader: () => ({
					// An endless body: only the cap can stop this read loop.
					read: async (): Promise<{ done: boolean; value?: Uint8Array }> => {
						reads++;
						return { done: false, value: chunk };
					},
					cancel: async (): Promise<void> => {
						cancelled = true;
					}
				})
			}
		};
		const { body, truncated } = await readCappedBody(response, 4000);
		expect(truncated).to.equal(true);
		expect(cancelled).to.equal(true);
		expect(Buffer.byteLength(body)).to.equal(4000);
		// Memory stays bounded by the cap plus one chunk, never the whole body.
		expect(reads).to.be.lessThan(6);
	});

	it('truncates a buffered body by bytes, not UTF-16 characters', async () => {
		const response: IL402Response = {
			status: 200,
			headers: { get: (): string | null => null },
			text: async (): Promise<string> => 'é'.repeat(10)
		};
		const capped = await readCappedBody(response, 8);
		expect(capped.truncated).to.equal(true);
		expect(Buffer.byteLength(capped.body)).to.be.at.most(8);
		const whole = await readCappedBody(response, 100);
		expect(whole.truncated).to.equal(false);
		expect(whole.body).to.equal('é'.repeat(10));
	});
});

describe('isPrivateNetworkUrl', () => {
	it('flags loopback, private, link-local, and mapped addresses', () => {
		for (const url of [
			'http://localhost:3000/x',
			'http://sub.localhost/x',
			'http://127.0.0.1/x',
			'http://127.8.9.10/x',
			'http://0.0.0.0/x',
			'http://10.1.2.3/x',
			'http://172.16.0.1/x',
			'http://172.31.255.255/x',
			'http://192.168.1.1/x',
			'http://169.254.169.254/latest/meta-data/',
			'http://100.100.1.1/x',
			'http://[::1]/x',
			'http://[::ffff:10.0.0.1]/x',
			'http://[fe80::1]/x',
			'http://[fd00::1]/x',
			'not a url'
		]) {
			expect(isPrivateNetworkUrl(url), url).to.equal(true);
		}
	});

	it('passes public targets through', () => {
		for (const url of [
			'https://api.example.com/data',
			'https://8.8.8.8/x',
			'http://172.15.0.1/x',
			'http://172.32.0.1/x',
			'http://11.0.0.1/x',
			'https://[2001:db8::1]/x'
		]) {
			expect(isPrivateNetworkUrl(url), url).to.equal(false);
		}
	});
});

// ─────────────── Redirects are vetted hop by hop ───────────────

describe('l402Fetch checkRedirect', () => {
	interface IRecordedRequest {
		url: string;
		method?: string;
		body?: string;
		headers: Record<string, string>;
		redirect?: string;
	}

	/**
	 * Answers each URL with the [status, Location] in `redirects`, a 402 with
	 * `challenge` when the request carries no Authorization and one is set, and
	 * 200 otherwise.
	 */
	function redirectServer(
		redirects: Record<string, [number, string]>,
		challenge?: string
	): { fetchImpl: FetchLike; requests: IRecordedRequest[] } {
		const requests: IRecordedRequest[] = [];
		const fetchImpl: FetchLike = async (url, init) => {
			const headers = init?.headers ?? {};
			requests.push({
				url,
				method: init?.method,
				body: init?.body,
				headers,
				redirect: init?.redirect
			});
			if (challenge && !headers.Authorization) {
				return {
					status: 402,
					url,
					headers: {
						get: (name: string): string | null =>
							name.toLowerCase() === 'www-authenticate' ? challenge : null
					},
					text: async (): Promise<string> => 'payment required'
				};
			}
			const hop = redirects[url];
			return {
				status: hop ? hop[0] : 200,
				url,
				headers: {
					get: (name: string): string | null =>
						hop && name.toLowerCase() === 'location' ? hop[1] : null
				},
				text: async (): Promise<string> => 'content'
			};
		};
		return { fetchImpl, requests };
	}

	const refusePrivate = (target: string): void => {
		if (isPrivateNetworkUrl(target)) throw new Error(`refused ${target}`);
	};

	async function rejection(promise: Promise<unknown>): Promise<Error> {
		try {
			await promise;
		} catch (err) {
			return err as Error;
		}
		throw new Error('expected a rejection');
	}

	it('refuses a redirect into a private target before requesting it', async () => {
		const { fetchImpl, requests } = redirectServer({
			'https://attacker.example/x': [
				307,
				'http://169.254.169.254/latest/api/token'
			]
		});
		const error = await rejection(
			l402Fetch(
				'https://attacker.example/x',
				{ method: 'POST', body: 'payload' },
				{ maxPriceSats: 10, fetchImpl, checkRedirect: refusePrivate }
			)
		);
		expect(error.message).to.contain('169.254.169.254');
		expect(requests.map((r) => r.url)).to.deep.equal([
			'https://attacker.example/x'
		]);
		expect(requests[0].redirect).to.equal('manual');
	});

	it('vets the redirect on the paid retry too', async () => {
		const pair = makeChallengePair(1_000n);
		const { fetchImpl, requests } = redirectServer(
			{ 'https://api.example/x': [307, 'http://127.0.0.1:2112/admin'] },
			`L402 macaroon="${pair.macaroon}", invoice="${pair.invoice}"`
		);
		let payments = 0;
		const error = await rejection(
			l402Fetch(
				'https://api.example/x',
				{},
				{
					maxPriceSats: 10,
					fetchImpl,
					checkRedirect: refusePrivate,
					payer: {
						payInvoice: async (): Promise<{ preimage: Buffer }> => {
							payments++;
							return { preimage: pair.preimage };
						}
					}
				}
			)
		);
		expect(error.message).to.contain('127.0.0.1');
		expect(payments).to.equal(1);
		expect(requests.map((r) => r.url)).to.deep.equal([
			'https://api.example/x',
			'https://api.example/x'
		]);
	});

	it('rewrites each hop the way fetch would', async () => {
		const { fetchImpl, requests } = redirectServer({
			'https://api.example/a': [307, '/b'],
			'https://api.example/b': [302, 'https://api.example/c']
		});
		const result = await l402Fetch(
			'https://api.example/a',
			{
				method: 'post',
				body: 'payload',
				headers: { 'Content-Type': 'application/json', 'X-Keep': '1' }
			},
			{ maxPriceSats: 10, fetchImpl, checkRedirect: refusePrivate }
		);
		expect(result.response.status).to.equal(200);
		expect(result.response.url).to.equal('https://api.example/c');
		// 307 keeps the method and body, against a relative Location.
		expect(requests[1]).to.include({
			url: 'https://api.example/b',
			method: 'post',
			body: 'payload'
		});
		expect(requests[1].headers).to.have.property('Content-Type');
		// 302 turns a POST into a GET and drops the body with its headers.
		expect(requests[2]).to.include({ method: 'GET', body: undefined });
		expect(requests[2].headers).to.deep.equal({ 'X-Keep': '1' });
	});

	it('keeps a credential off a hop to another origin', async () => {
		const pair = makeChallengePair(1_000n);
		const store = new MemoryL402CredentialStore();
		store.set({
			scope: 'https://api.example',
			macaroon: pair.macaroon,
			preimage: pair.preimage.toString('hex'),
			paymentHash: pair.paymentHash.toString('hex'),
			amountSats: 1,
			createdAt: Date.now(),
			scheme: 'L402'
		});
		const { fetchImpl, requests } = redirectServer({
			'https://api.example/a': [308, '/b'],
			'https://api.example/b': [308, 'https://cdn.example/c']
		});
		await l402Fetch(
			'https://api.example/a',
			{},
			{
				maxPriceSats: 10,
				fetchImpl,
				credentials: store,
				checkRedirect: refusePrivate
			}
		);
		expect(requests.map((r) => Boolean(r.headers.Authorization))).to.deep.equal(
			[true, true, false]
		);
	});

	it('sees a cross-origin challenge from a fetch that reports no final URL', async () => {
		const pair = makeChallengePair(1_000n);
		const challenge = `L402 macaroon="${pair.macaroon}", invoice="${pair.invoice}"`;
		const requests: Array<[string, boolean]> = [];
		// A redirects to B, which challenges. No response carries a url.
		const fetchImpl: FetchLike = async (url, init) => {
			const authorized = Boolean(init?.headers?.Authorization);
			requests.push([url, authorized]);
			const atA = url === 'https://a.example/x';
			const status = atA ? 302 : authorized ? 200 : 402;
			return {
				status,
				headers: {
					get: (name: string): string | null => {
						const lower = name.toLowerCase();
						if (atA && lower === 'location') return 'https://b.example/pay';
						if (status === 402 && lower === 'www-authenticate') {
							return challenge;
						}
						return null;
					}
				},
				text: async (): Promise<string> => ''
			};
		};
		let payments = 0;
		const options = {
			maxPriceSats: 10,
			fetchImpl,
			checkRedirect: refusePrivate,
			payer: {
				payInvoice: async (): Promise<{ preimage: Buffer }> => {
					payments++;
					return { preimage: pair.preimage };
				}
			}
		};

		const error = await rejection(
			l402Fetch('https://a.example/x', {}, options)
		);
		expect((error as L402Error).code).to.equal('CROSS_ORIGIN_CHALLENGE');
		expect(payments).to.equal(0);

		requests.length = 0;
		const result = await l402Fetch(
			'https://a.example/x',
			{},
			{ ...options, allowCrossOriginChallenge: true }
		);
		expect(result.paid).to.equal(true);
		expect(result.response.status).to.equal(200);
		expect(requests).to.deep.equal([
			['https://a.example/x', false],
			['https://b.example/pay', false],
			['https://b.example/pay', true]
		]);
	});

	it('gives up after 20 redirects', async () => {
		const { fetchImpl, requests } = redirectServer({
			'https://loop.example/a': [302, '/a']
		});
		const error = await rejection(
			l402Fetch(
				'https://loop.example/a',
				{},
				{ maxPriceSats: 10, fetchImpl, checkRedirect: refusePrivate }
			)
		);
		expect(error.message).to.contain('more than 20 redirects');
		expect(requests).to.have.length(21);
	});

	it('holds with the global fetch, which never reaches a refused hop', async () => {
		const hits: string[] = [];
		const server = http.createServer((req, res) => {
			hits.push(`${req.method} ${req.url}`);
			if (req.url === '/start') {
				res.writeHead(307, { Location: '/internal' });
				res.end('moved');
				return;
			}
			res.end('internal');
		});
		await new Promise<void>((resolve) =>
			server.listen(0, '127.0.0.1', resolve)
		);
		const start = `http://127.0.0.1:${
			(server.address() as AddressInfo).port
		}/start`;
		try {
			const error = await rejection(
				l402Fetch(
					start,
					{ method: 'POST', body: 'payload' },
					{
						maxPriceSats: 10,
						checkRedirect: (target) => {
							if (new URL(target).pathname === '/internal') {
								throw new Error('refused');
							}
						}
					}
				)
			);
			expect(error.message).to.equal('refused');
			expect(hits).to.deep.equal(['POST /start']);

			// A permitted hop is followed and its response returned.
			const result = await l402Fetch(
				start,
				{ method: 'POST', body: 'payload' },
				{ maxPriceSats: 10, checkRedirect: () => {} }
			);
			expect(await result.response.text()).to.equal('internal');
			expect(hits.slice(1)).to.deep.equal(['POST /start', 'POST /internal']);
		} finally {
			server.closeAllConnections();
			server.close();
		}
	});
});
