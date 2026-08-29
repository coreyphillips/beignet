/**
 * Direct-funding request envelope v3 (issue #610, LFBW port #532 4A).
 *
 * The envelope is the only artifact a payer sees before it does anything at
 * all, so the tests here are about two things: the byte layout the LFBW
 * dashboard decodes by hand, and the refusals that have to happen on the
 * payer's device before any network activity.
 */

import { expect } from 'chai';
import {
	DF_BIP21_PARAM,
	DF_ENVELOPE_MIN_BYTES,
	DfTransportType,
	DirectFundingError,
	DirectFundingErrorCode,
	IDfEnvelopeMintParams,
	IDfRequestEnvelope,
	IDfVerifyOptions,
	bip21WithRequest,
	canonicalRequestMessage,
	chainHashForNetwork,
	decodeAndVerifyRequestEnvelope,
	decodeRequestEnvelope,
	encodeRequestEnvelope,
	encodeUnsignedEnvelope,
	mintRequestEnvelope,
	requestFromBip21
} from '../../src/lightning/direct-funding';
import {
	signMessageWithKey,
	zbase32Decode
} from '../../src/lightning/crypto/message-signing';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { Network } from '../../src/lightning/invoice/types';

// ── Fixed inputs ───────────────────────────────────────────────────

const NODE_PRIVKEY = Buffer.alloc(32, 0x11);
const NODE_ID = getPublicKey(NODE_PRIVKEY);
const OTHER_PRIVKEY = Buffer.alloc(32, 0x22);
const ENCRYPTION_KEY = getPublicKey(Buffer.alloc(32, 0x33));
const REQUEST_ID = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
const RECEIPT_HASH = Buffer.alloc(32, 0xab);
const CHAIN_HASH = chainHashForNetwork(Network.REGTEST);
const NOW = 1_700_000_000_000;
const EXPIRES_AT = NOW + 3_600_000;

const sign =
	(key: Buffer) =>
	(message: string): string =>
		signMessageWithKey(message, key);

function params(
	over: Partial<IDfEnvelopeMintParams> = {}
): IDfEnvelopeMintParams {
	return {
		requestId: REQUEST_ID,
		chainHash: CHAIN_HASH,
		receiverNodeId: NODE_ID,
		expiresAt: EXPIRES_AT,
		receiptHash: RECEIPT_HASH,
		encryptionKey: ENCRYPTION_KEY,
		transports: [],
		...over
	};
}

function mint(over: Partial<IDfEnvelopeMintParams> = {}): IDfRequestEnvelope {
	return mintRequestEnvelope(params(over), sign(NODE_PRIVKEY), NOW);
}

function verifyOpts(over: Partial<IDfVerifyOptions> = {}): IDfVerifyOptions {
	return { expectedChainHash: CHAIN_HASH, now: NOW, ...over };
}

const errorCode = (fn: () => unknown): string | undefined => {
	try {
		fn();
	} catch (e) {
		return (e as DirectFundingError).code;
	}
	return undefined;
};

/** Sign arbitrary unsigned bytes, so a test can craft a layout mint refuses. */
function seal(unsigned: Buffer, key: Buffer = NODE_PRIVKEY): string {
	const sig = zbase32Decode(
		signMessageWithKey(canonicalRequestMessage(unsigned), key)
	);
	return Buffer.concat([unsigned, sig!]).toString('base64url');
}

/**
 * The LFBW dashboard's decoder, reproduced: it reads the node id at 49, the
 * expiry at 82 to 87, the flags bit at 88 and the amount at 89 to 96, hard
 * coded, and swallows every error. A field reordering does not fail there, it
 * shows a wrong node id, which is why the offsets are contract.
 */
function dashboardDecode(encoded: string): {
	nodeId: string;
	amountSats: number | null;
	expiresAt: number;
} | null {
	if (!/^[A-Za-z0-9_-]+$/.test(encoded)) return null;
	const bytes = Buffer.from(encoded, 'base64url');
	if (bytes[0] !== 3 || bytes.length <= 97) return null;
	let expiresAt = 0;
	for (let i = 82; i < 88; i++) expiresAt = expiresAt * 256 + bytes[i];
	let amountSats: number | null = null;
	if (bytes[88] & 1) {
		amountSats = 0;
		for (let i = 89; i < 97; i++) amountSats = amountSats * 256 + bytes[i];
	}
	return {
		nodeId: bytes.subarray(49, 82).toString('hex'),
		amountSats,
		expiresAt
	};
}

describe('Direct funding: request envelope v3', () => {
	describe('encoding', () => {
		it('lays the fields out at the offsets the dashboard reads', () => {
			const encoded = encodeRequestEnvelope(mint({ amountSat: 250_000n }));
			const bytes = Buffer.from(encoded, 'base64url');
			expect(bytes[0]).to.equal(3);
			expect(bytes.subarray(1, 17).toString('hex')).to.equal(
				REQUEST_ID.toString('hex')
			);
			expect(bytes.subarray(17, 49).toString('hex')).to.equal(
				CHAIN_HASH.toString('hex')
			);
			expect(bytes.subarray(49, 82).toString('hex')).to.equal(
				NODE_ID.toString('hex')
			);
			expect(bytes.readUIntBE(82, 6)).to.equal(EXPIRES_AT);
			expect(bytes[88] & 1).to.equal(1);
			expect(bytes.readBigUInt64BE(89)).to.equal(250_000n);
		});

		it('is unpadded base64url, which the dashboard gate requires', () => {
			// A single '=' (or a percent-encoded one) makes the dashboard drop
			// the whole bgnq parameter and show a plain on-chain address.
			for (const amount of [undefined, 1n, 250_000n]) {
				const encoded = encodeRequestEnvelope(mint({ amountSat: amount }));
				expect(encoded).to.match(/^[A-Za-z0-9_-]+$/);
			}
		});

		it('cross-checks against the dashboard decoder', () => {
			const encoded = encodeRequestEnvelope(mint({ amountSat: 250_000n }));
			expect(dashboardDecode(encoded)).to.deep.equal({
				nodeId: NODE_ID.toString('hex'),
				amountSats: 250_000,
				expiresAt: EXPIRES_AT
			});
			const noAmount = encodeRequestEnvelope(mint());
			expect(dashboardDecode(noAmount)?.amountSats).to.equal(null);
		});

		it('is 220 bytes without an amount and 228 with one', () => {
			expect(
				Buffer.from(encodeRequestEnvelope(mint()), 'base64url').length
			).to.equal(DF_ENVELOPE_MIN_BYTES);
			expect(
				Buffer.from(encodeRequestEnvelope(mint({ amountSat: 1n })), 'base64url')
					.length
			).to.equal(DF_ENVELOPE_MIN_BYTES + 8);
		});

		it('asserts every fixed-width field instead of mis-framing it', () => {
			// The fork wrote Buffer.from(hex,'hex') with no length check, so a
			// short field produced a mis-framed envelope that was then SIGNED.
			expect(() => mint({ requestId: Buffer.alloc(8) })).to.throw(
				/request id must be 16 bytes/
			);
			expect(() => mint({ chainHash: Buffer.alloc(31) })).to.throw(
				/chain hash must be 32 bytes/
			);
			expect(() => mint({ receiverNodeId: Buffer.alloc(33) })).to.throw(
				/valid compressed secp256k1/
			);
			expect(() => mint({ receiptHash: Buffer.alloc(0) })).to.throw(
				/receipt hash must be 32 bytes/
			);
		});

		it('refuses to mint an expiry beyond the maximum lifetime', () => {
			expect(
				errorCode(() => mint({ expiresAt: NOW + 30 * 24 * 3600 * 1000 }))
			).to.equal(DirectFundingErrorCode.EXPIRY_TOO_DISTANT);
			expect(errorCode(() => mint({ expiresAt: NOW }))).to.equal(
				DirectFundingErrorCode.EXPIRED
			);
		});

		it('never emits a reserved or unimplemented transport type', () => {
			expect(() =>
				mint({ transports: [{ type: 4, value: Buffer.alloc(4) }] })
			).to.throw(/refusing to mint unimplemented transport 4/);
			// The refusal is on the TYPE. A descriptor shaped like a known
			// transport but numbered 4 carries no `value` and so is not
			// "unknown"; a JS caller can build one, and signing it would claim
			// the type #533 is reserving.
			expect(() =>
				mint({
					transports: [
						{
							type: 4,
							relayNodeId: getPublicKey(Buffer.alloc(32, 0x55)),
							host: 'relay.example',
							port: 9735
						} as unknown as IDfEnvelopeMintParams['transports'][0]
					]
				})
			).to.throw(/refusing to mint unimplemented transport 4/);
		});
	});

	describe('round trip', () => {
		it('re-encodes byte for byte with every transport form', () => {
			const env = mint({
				amountSat: 12_345n,
				transports: [
					{
						type: DfTransportType.DIRECT_PEER,
						host: 'node.example',
						port: 9735
					},
					{
						type: DfTransportType.ONION_MESSAGE,
						host: 'lsp.example',
						port: 9736,
						introNodeId: getPublicKey(Buffer.alloc(32, 0x44)),
						pathKey: getPublicKey(Buffer.alloc(32, 0x55)),
						hops: [
							{
								blindedNodeId: getPublicKey(Buffer.alloc(32, 0x66)),
								encryptedData: Buffer.alloc(40, 0x77)
							},
							{
								blindedNodeId: getPublicKey(Buffer.alloc(32, 0x67)),
								encryptedData: Buffer.alloc(12, 0x78)
							}
						]
					},
					{
						type: DfTransportType.LSP_RELAY,
						relayNodeId: getPublicKey(Buffer.alloc(32, 0x44)),
						host: '10.0.0.1',
						port: 9735
					}
				]
			});
			const encoded = encodeRequestEnvelope(env);
			const decoded = decodeAndVerifyRequestEnvelope(encoded, verifyOpts());
			expect(encodeRequestEnvelope(decoded)).to.equal(encoded);
			expect(decoded.transports).to.deep.equal(env.transports);
			expect(decoded.amountSat).to.equal(12_345n);
			expect(decoded.expiresAt).to.equal(EXPIRES_AT);
		});

		it('omits amountSat entirely when the flag is clear', () => {
			const decoded = decodeRequestEnvelope(encodeRequestEnvelope(mint()));
			expect(decoded.amountSat).to.equal(undefined);
		});
	});

	describe('forward compatibility', () => {
		it('skips an unknown transport type and still verifies', () => {
			// The fork dropped unknown descriptors on decode and then RE-ENCODED
			// the parsed struct to check the signature, so any envelope carrying
			// a type it did not know failed verification outright.
			const known = encodeUnsignedEnvelope({
				version: 3,
				...params({
					transports: [
						{ type: DfTransportType.DIRECT_PEER, host: 'a.example', port: 1 }
					]
				})
			});
			const unknown = Buffer.concat([
				Buffer.from([9]),
				Buffer.from([0x00, 0x05]),
				Buffer.from('hello')
			]);
			// Bump num_transports (last byte before the descriptors is at
			// 220 - 65 - 1 - descriptor bytes) by rebuilding the prefix.
			const raw = Buffer.concat([known, unknown]);
			raw[88 + 1 + 32 + 33] = 2;
			const env = decodeAndVerifyRequestEnvelope(seal(raw), verifyOpts());
			expect(env.transports).to.have.length(2);
			expect(env.transports[1]).to.deep.equal({
				type: 9,
				value: Buffer.from('hello')
			});
			expect(encodeRequestEnvelope(env)).to.equal(seal(raw));
		});

		it('ignores unknown flags bits without breaking the signature', () => {
			const raw = encodeUnsignedEnvelope({ version: 3, ...params() });
			raw[88] |= 0b1000_0010;
			const env = decodeAndVerifyRequestEnvelope(seal(raw), verifyOpts());
			expect(env.amountSat).to.equal(undefined);
		});

		it('tolerates trailing bytes inside a known descriptor value', () => {
			const base = encodeUnsignedEnvelope({
				version: 3,
				...params({
					transports: [
						{ type: DfTransportType.DIRECT_PEER, host: 'a.example', port: 7 }
					]
				})
			});
			// Extend the descriptor value with two bytes a later revision might
			// define; the length prefix still frames it.
			const lenOffset = base.length - 2 - 12;
			const extended = Buffer.concat([base, Buffer.from([0xff, 0xff])]);
			extended.writeUInt16BE(extended.readUInt16BE(lenOffset) + 2, lenOffset);
			const env = decodeAndVerifyRequestEnvelope(seal(extended), verifyOpts());
			expect(env.transports[0]).to.deep.equal({
				type: DfTransportType.DIRECT_PEER,
				host: 'a.example',
				port: 7
			});
		});
	});

	describe('refusals', () => {
		const codeOf = errorCode;

		it('refuses a padded base64 request', () => {
			const encoded = encodeRequestEnvelope(mint());
			const padded = Buffer.from(encoded, 'base64url').toString('base64');
			expect(padded).to.contain('=');
			expect(codeOf(() => decodeRequestEnvelope(padded))).to.equal(
				DirectFundingErrorCode.MALFORMED
			);
			expect(codeOf(() => decodeRequestEnvelope(encoded + '='))).to.equal(
				DirectFundingErrorCode.MALFORMED
			);
		});

		it('refuses a non-canonical base64url encoding', () => {
			// Same bytes, different string: the trailing character of a 220-byte
			// payload has four unused bits, and Node's decoder ignores them. Two
			// decoders that disagree about which strings are requests is exactly
			// the failure the dashboard's regex gate exists to avoid.
			const alphabet =
				'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
			const encoded = encodeRequestEnvelope(mint());
			const v = alphabet.indexOf(encoded[encoded.length - 1]);
			const alt = alphabet[(v & 0x30) | ((v & 0x0f) === 0x0f ? 0x0 : 0xf)];
			const mutated = encoded.slice(0, -1) + alt;
			expect(mutated).to.not.equal(encoded);
			expect(Buffer.from(mutated, 'base64url')).to.deep.equal(
				Buffer.from(encoded, 'base64url')
			);
			expect(codeOf(() => decodeRequestEnvelope(mutated))).to.equal(
				DirectFundingErrorCode.MALFORMED
			);
		});

		it('refuses an unsupported version', () => {
			const raw = Buffer.from(encodeRequestEnvelope(mint()), 'base64url');
			raw[0] = 2;
			expect(
				codeOf(() => decodeRequestEnvelope(raw.toString('base64url')))
			).to.equal(DirectFundingErrorCode.UNSUPPORTED_VERSION);
		});

		it('refuses a truncated request', () => {
			const raw = Buffer.from(encodeRequestEnvelope(mint()), 'base64url');
			expect(
				codeOf(() =>
					decodeRequestEnvelope(raw.subarray(0, 200).toString('base64url'))
				)
			).to.equal(DirectFundingErrorCode.MALFORMED);
		});

		it('refuses trailing bytes after the signature', () => {
			const raw = Buffer.concat([
				Buffer.from(encodeRequestEnvelope(mint()), 'base64url'),
				Buffer.from([0])
			]);
			expect(
				codeOf(() => decodeRequestEnvelope(raw.toString('base64url')))
			).to.equal(DirectFundingErrorCode.MALFORMED);
		});

		it('refuses an expired request', () => {
			const encoded = encodeRequestEnvelope(mint());
			expect(
				codeOf(() =>
					decodeAndVerifyRequestEnvelope(
						encoded,
						verifyOpts({ now: EXPIRES_AT })
					)
				)
			).to.equal(DirectFundingErrorCode.EXPIRED);
		});

		it('refuses an absurd expiry', () => {
			// The fork only refused "already expired", so an unbounded u48 could
			// hold a store slot and a path-secret index effectively forever.
			const raw = encodeUnsignedEnvelope({
				version: 3,
				...params({ expiresAt: 0xffffffffffff })
			});
			expect(
				codeOf(() => decodeAndVerifyRequestEnvelope(seal(raw), verifyOpts()))
			).to.equal(DirectFundingErrorCode.EXPIRY_TOO_DISTANT);
		});

		it('refuses an invalid signature', () => {
			const raw = Buffer.from(encodeRequestEnvelope(mint()), 'base64url');
			raw[raw.length - 1] ^= 0xff;
			raw[raw.length - 2] ^= 0xff;
			const code = codeOf(() =>
				decodeAndVerifyRequestEnvelope(raw.toString('base64url'), verifyOpts())
			);
			expect([
				DirectFundingErrorCode.INVALID_SIGNATURE,
				DirectFundingErrorCode.WRONG_SIGNER
			]).to.include(code);
		});

		it('refuses a signature from anyone but the node it names', () => {
			// Recovery alone authenticates nothing: a signature by another key
			// still recovers SOME pubkey.
			const raw = encodeUnsignedEnvelope({ version: 3, ...params() });
			expect(
				codeOf(() =>
					decodeAndVerifyRequestEnvelope(seal(raw, OTHER_PRIVKEY), verifyOpts())
				)
			).to.equal(DirectFundingErrorCode.WRONG_SIGNER);
		});

		it('refuses a request bound to another chain', () => {
			// The fork's only chain check lived in one HTTP handler, so every
			// other caller of its decoder got a chain-unbound request.
			const encoded = encodeRequestEnvelope(
				mint({ chainHash: chainHashForNetwork(Network.MAINNET) })
			);
			expect(
				codeOf(() => decodeAndVerifyRequestEnvelope(encoded, verifyOpts()))
			).to.equal(DirectFundingErrorCode.WRONG_CHAIN);
		});

		it('refuses an encryption key that is not a curve point', () => {
			const raw = Buffer.from(encodeRequestEnvelope(mint()), 'base64url');
			// encryption_key sits right after the 32-byte receipt hash; 0x05 is
			// not a compressed-point prefix.
			raw[89 + 32] = 0x05;
			expect(
				codeOf(() => decodeRequestEnvelope(raw.toString('base64url')))
			).to.equal(DirectFundingErrorCode.MALFORMED);
		});
	});

	describe('BIP 21', () => {
		it('round trips through the URI parameter', () => {
			const encoded = encodeRequestEnvelope(mint());
			const uri = bip21WithRequest(
				'bitcoin:bcrt1qexampleaddress?amount=0.001',
				encoded
			);
			expect(uri).to.contain(`&${DF_BIP21_PARAM}=`);
			expect(requestFromBip21(uri)).to.equal(encoded);
		});

		it('adds the first query parameter when there is none', () => {
			const encoded = encodeRequestEnvelope(mint());
			expect(bip21WithRequest('bitcoin:addr', encoded)).to.equal(
				`bitcoin:addr?${DF_BIP21_PARAM}=${encoded}`
			);
		});

		it('drops a parameter the dashboard would drop', () => {
			expect(requestFromBip21('bitcoin:addr?bgnq=abc%3D')).to.equal(null);
			expect(requestFromBip21('bitcoin:addr?bgnq=abc=')).to.equal(null);
			expect(requestFromBip21('bitcoin:addr?amount=0.1')).to.equal(null);
			expect(requestFromBip21('bitcoin:addr')).to.equal(null);
		});
	});

	it('signs the exact string the draft specifies', () => {
		const env = mint();
		expect(canonicalRequestMessage(env.signedBytes)).to.equal(
			'beignet-df-req:v3:' + env.signedBytes.toString('base64url')
		);
		expect(env.signature).to.have.length(65);
		// Header byte is 27 + 4 + recovery id, the LND/CLN compact layout.
		expect(env.signature[0]).to.be.within(31, 34);
	});
});
