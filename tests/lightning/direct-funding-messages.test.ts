/**
 * Direct-funding protocol messages (issue #610, LFBW port #532 4A).
 *
 * All six bodies are TLV rather than the fork's JSON, so the tests here pin
 * the round trip, the fixed widths a peer cannot widen, and the two signed
 * strings both engines have to agree on byte for byte.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	DF_MAX_PREVOUTS,
	DirectFundingErrorCode,
	IDfOffer,
	IDfReceipt,
	IDfSignRequest,
	attestationMessage,
	decodeDfOffer,
	decodeDfOfferAck,
	decodeDfReceipt,
	decodeDfRelayFrame,
	decodeDfSignRequest,
	decodeDfWitness,
	deriveOfferId,
	encodeDfOffer,
	encodeDfOfferAck,
	encodeDfReceipt,
	encodeDfRelayFrame,
	encodeDfSignRequest,
	encodeDfWitness,
	bitcoinMessageHash,
	DF_PROBE_POISON_SCRIPT,
	ownershipDigest,
	ownershipMessage,
	ownershipProbePoisonTxid,
	ownershipProbeTransaction
} from '../../src/lightning/direct-funding';
import { BeignetCustomSubtype } from '../../src/lightning/message/custom';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	decodeTlvStream,
	encodeTlvStream
} from '../../src/lightning/message/tlv';
import { DirectFundingError } from '../../src/lightning/direct-funding/types';

const TXID = Buffer.alloc(32, 0xa1);
const OFFER_ID = deriveOfferId(TXID, 1, 250_000n);
const RECEIPT_HASH = Buffer.alloc(32, 0xb2);
const OWNER_PUBKEY = getPublicKey(Buffer.alloc(32, 0x21));
const LOCAL_FUNDING = getPublicKey(Buffer.alloc(32, 0x31));
const REMOTE_FUNDING = getPublicKey(Buffer.alloc(32, 0x41));

function offer(over: Partial<IDfOffer> = {}): IDfOffer {
	return {
		offerId: OFFER_ID,
		amountSat: 250_000n,
		txid: TXID,
		vout: 1,
		valueSat: 400_000n,
		sequence: 0xfffffffd,
		changeScript: Buffer.alloc(22, 0x00),
		maxTotalFeeSat: 1_000n,
		receiptHash: RECEIPT_HASH,
		ownership: { pubkey: OWNER_PUBKEY, signature: Buffer.alloc(64, 0x05) },
		...over
	};
}

function signRequest(over: Partial<IDfSignRequest> = {}): IDfSignRequest {
	return {
		offerId: OFFER_ID,
		rawTx: Buffer.alloc(300, 0x0c),
		prevouts: [
			{ valueSat: 400_000n, script: Buffer.alloc(22, 0x11) },
			{ valueSat: 900_000n, script: Buffer.alloc(34, 0x22) }
		],
		attestation: {
			fundingOutputIndex: 0,
			localFundingPubkey: LOCAL_FUNDING,
			remoteFundingPubkey: REMOTE_FUNDING,
			signature: Buffer.alloc(65, 0x07)
		},
		...over
	};
}

const codeOf = (fn: () => unknown): string | undefined => {
	try {
		fn();
	} catch (e) {
		return (e as DirectFundingError).code;
	}
	return undefined;
};

describe('Direct funding: protocol messages', () => {
	it('uses the subtypes already reserved upstream', () => {
		expect(BeignetCustomSubtype.DIRECT_FUNDING_OFFER).to.equal(16);
		expect(BeignetCustomSubtype.DIRECT_FUNDING_OFFER_ACK).to.equal(17);
		expect(BeignetCustomSubtype.DIRECT_FUNDING_SIGN_REQUEST).to.equal(18);
		expect(BeignetCustomSubtype.DIRECT_FUNDING_WITNESS).to.equal(19);
		expect(BeignetCustomSubtype.DIRECT_FUNDING_RECEIPT).to.equal(21);
		expect(BeignetCustomSubtype.DIRECT_FUNDING_RELAY).to.equal(22);
	});

	describe('funding_offer (16)', () => {
		it('round trips', () => {
			expect(decodeDfOffer(encodeDfOffer(offer()))).to.deep.equal(offer());
		});

		it('carries an x-only pubkey for a Taproot key-path input', () => {
			const taproot = offer({
				ownership: {
					pubkey: OWNER_PUBKEY.subarray(1),
					signature: Buffer.alloc(64, 0x06)
				}
			});
			expect(
				decodeDfOffer(encodeDfOffer(taproot)).ownership.pubkey
			).to.have.length(32);
		});

		it('carries the Bitcoin signed-message proof in an odd TLV an older decoder skips', () => {
			const withProof = offer({
				ownership: {
					pubkey: OWNER_PUBKEY,
					signature: Buffer.alloc(64),
					messageProof: {
						pubkey: OWNER_PUBKEY,
						signature: Buffer.alloc(65, 0x1f)
					}
				}
			});
			const bytes = encodeDfOffer(withProof);
			expect(decodeDfOffer(bytes)).to.deep.equal(withProof);
			expect(
				decodeDfOffer(encodeDfOffer(offer())).ownership.messageProof
			).to.equal(undefined);
			// Type 21 is odd: a decoder that knows only the rev 2 types walks past
			// it and reads the zeroed digest signature, which it then declines.
			const rev2Known = new Set([
				0n,
				2n,
				4n,
				6n,
				8n,
				10n,
				12n,
				14n,
				16n,
				18n,
				20n
			]);
			const asRev2 = decodeTlvStream(bytes, 0, rev2Known).records;
			expect(asRev2.some((r) => r.type === 21n)).to.equal(true);
			expect(asRev2.find((r) => r.type === 20n)!.value).to.deep.equal(
				Buffer.alloc(64)
			);
			// Present but the wrong width is refused, not ignored.
			const truncated = encodeTlvStream(
				decodeTlvStream(bytes).records.map((r) =>
					r.type === 21n ? { type: r.type, value: r.value.subarray(0, 97) } : r
				)
			);
			expect(codeOf(() => decodeDfOffer(truncated))).to.equal(
				DirectFundingErrorCode.MALFORMED
			);
			expect(() =>
				encodeDfOffer(
					offer({
						ownership: {
							pubkey: OWNER_PUBKEY,
							signature: Buffer.alloc(64),
							messageProof: {
								pubkey: OWNER_PUBKEY,
								signature: Buffer.alloc(64)
							}
						}
					})
				)
			).to.throw(/ownership message signature must be 65 bytes/);
		});

		it('carries the probe-transaction proof in odd TLV 23, and builds the probe deterministically', () => {
			const withProof = offer({
				ownership: {
					pubkey: OWNER_PUBKEY,
					signature: Buffer.alloc(64),
					probeProof: {
						pubkey: OWNER_PUBKEY,
						signature: Buffer.alloc(64, 0x07)
					}
				}
			});
			const bytes = encodeDfOffer(withProof);
			expect(decodeDfOffer(bytes)).to.deep.equal(withProof);
			const rev2Known = new Set([
				0n,
				2n,
				4n,
				6n,
				8n,
				10n,
				12n,
				14n,
				16n,
				18n,
				20n
			]);
			expect(
				decodeTlvStream(bytes, 0, rev2Known).records.some((r) => r.type === 23n)
			).to.equal(true);
			expect(() =>
				encodeDfOffer(
					offer({
						ownership: {
							pubkey: OWNER_PUBKEY,
							signature: Buffer.alloc(64),
							probeProof: { pubkey: OWNER_PUBKEY, signature: Buffer.alloc(65) }
						}
					})
				)
			).to.throw(/ownership probe signature must be 64 bytes/);

			const script = Buffer.alloc(22, 0x33);
			const a = ownershipProbeTransaction(
				OFFER_ID,
				TXID,
				1,
				0xfffffffd,
				script,
				400_000n
			);
			const b = ownershipProbeTransaction(
				OFFER_ID,
				TXID,
				1,
				0xfffffffd,
				script,
				400_000n
			);
			expect(a.tx.toBuffer()).to.deep.equal(b.tx.toBuffer());
			expect(a.tx.ins).to.have.length(2);
			expect(a.tx.ins[0].hash).to.deep.equal(Buffer.from(TXID).reverse());
			expect(a.tx.ins[0].index).to.equal(1);
			expect(a.tx.ins[0].sequence).to.equal(0xfffffffd);
			// The poison: a spend of an outpoint with no preimage.
			expect(a.tx.ins[1].hash).to.deep.equal(
				ownershipProbePoisonTxid(OFFER_ID)
			);
			expect(a.tx.ins[1].index).to.equal(0);
			expect(a.tx.outs).to.have.length(1);
			expect(a.tx.outs[0].value).to.equal(0);
			expect(a.tx.outs[0].script.subarray(0, 2)).to.deep.equal(
				Buffer.from([0x6a, 16])
			);
			expect(a.tx.outs[0].script.subarray(2)).to.deep.equal(OFFER_ID);
			expect(a.prevouts.scripts[1]).to.deep.equal(DF_PROBE_POISON_SCRIPT);
			expect(a.prevouts.values).to.deep.equal([400_000n, 0n]);
			// A different offer id is a different poison, so a probe signature
			// never carries across offers.
			expect(
				ownershipProbeTransaction(
					Buffer.alloc(16, 9),
					TXID,
					1,
					0xfffffffd,
					script,
					400_000n
				).tx.ins[1].hash
			).to.not.deep.equal(a.tx.ins[1].hash);
		});

		it('requires the receipt hash', () => {
			// Rev 2: sessions exist only for requests this receiver minted, and
			// the hash is what says which one.
			expect(decodeDfOffer(encodeDfOffer(offer())).receiptHash).to.deep.equal(
				RECEIPT_HASH
			);
			const withoutHash = encodeTlvStream(
				decodeTlvStream(encodeDfOffer(offer())).records.filter(
					(r) => r.type !== 16n
				)
			);
			expect(codeOf(() => decodeDfOffer(withoutHash))).to.equal(
				DirectFundingErrorCode.MALFORMED
			);
		});

		it('refuses a field that is not its fixed width', () => {
			expect(() => encodeDfOffer(offer({ txid: Buffer.alloc(16) }))).to.throw(
				/txid must be 32 bytes/
			);
			expect(() =>
				encodeDfOffer(
					offer({
						ownership: { pubkey: Buffer.alloc(20), signature: Buffer.alloc(64) }
					})
				)
			).to.throw(/ownership pubkey must be 33 bytes/);
			expect(() =>
				encodeDfOffer(offer({ changeScript: Buffer.alloc(600) }))
			).to.throw(/change script is 600 bytes/);
		});

		it('refuses an unknown even TLV type and tolerates an unknown odd one', () => {
			const body = encodeDfOffer(offer());
			const withOddExtra = Buffer.concat([
				body,
				encodeTlvStream([{ type: 41n, value: Buffer.from('later') }])
			]);
			expect(decodeDfOffer(withOddExtra)).to.deep.equal(offer());
			const withEvenExtra = Buffer.concat([
				body,
				encodeTlvStream([{ type: 42n, value: Buffer.from('required') }])
			]);
			expect(codeOf(() => decodeDfOffer(withEvenExtra))).to.equal(
				DirectFundingErrorCode.MALFORMED
			);
		});
	});

	describe('funding_offer_ack (17)', () => {
		it('round trips an acceptance and a decline with a reason', () => {
			expect(
				decodeDfOfferAck(
					encodeDfOfferAck({ offerId: OFFER_ID, accepted: true })
				)
			).to.deep.equal({ offerId: OFFER_ID, accepted: true });
			const declined = {
				offerId: OFFER_ID,
				accepted: false,
				reason: 'below the minimum amount'
			};
			expect(decodeDfOfferAck(encodeDfOfferAck(declined))).to.deep.equal(
				declined
			);
		});

		it('truncates our own over-long reason rather than refusing it', () => {
			const ack = decodeDfOfferAck(
				encodeDfOfferAck({
					offerId: OFFER_ID,
					accepted: false,
					reason: 'x'.repeat(500)
				})
			);
			expect(ack.reason).to.have.length(200);
		});
	});

	describe('funding_sign_request (18)', () => {
		it('round trips, splice field included', () => {
			expect(
				decodeDfSignRequest(encodeDfSignRequest(signRequest()))
			).to.deep.equal(signRequest());
			const spliced = signRequest({ sharedInputIndex: 3 });
			expect(decodeDfSignRequest(encodeDfSignRequest(spliced))).to.deep.equal(
				spliced
			);
		});

		it('round trips a body large enough to need the large onion form', () => {
			// Rev 2 bounds the transaction at 16 inputs and 8 outputs and the
			// message at the 32768-byte large onion form; 4B carries this one.
			const big = signRequest({
				rawTx: crypto.randomBytes(4_000),
				prevouts: [...Array(DF_MAX_PREVOUTS).keys()].map((i) => ({
					valueSat: BigInt(100_000 + i),
					script: Buffer.alloc(34, i)
				}))
			});
			const encoded = encodeDfSignRequest(big);
			expect(encoded.length).to.be.greaterThan(1300);
			expect(encoded.length).to.be.lessThan(32_768);
			expect(decodeDfSignRequest(encoded)).to.deep.equal(big);
		});

		it('refuses more prevouts than the transaction may hold', () => {
			expect(() =>
				encodeDfSignRequest(
					signRequest({
						prevouts: [...Array(17).keys()].map(() => ({
							valueSat: 1n,
							script: Buffer.alloc(22)
						}))
					})
				)
			).to.throw(/17 prevouts, max 16/);
		});

		it('refuses a prevout list that does not frame exactly', () => {
			const encoded = encodeDfSignRequest(signRequest());
			const decoded = decodeDfSignRequest(encoded);
			expect(decoded.prevouts).to.have.length(2);
			// A count that outruns the buffer must be a refusal, not a short list.
			const lying = encodeTlvStream([
				{ type: 0n, value: OFFER_ID },
				{ type: 2n, value: Buffer.alloc(10) },
				{ type: 4n, value: Buffer.from([0x00, 0x05]) },
				{ type: 6n, value: Buffer.alloc(4) },
				{ type: 8n, value: LOCAL_FUNDING },
				{ type: 10n, value: REMOTE_FUNDING },
				{ type: 12n, value: Buffer.alloc(65) }
			]);
			expect(codeOf(() => decodeDfSignRequest(lying))).to.equal(
				DirectFundingErrorCode.MALFORMED
			);
		});
	});

	describe('funding_witness (19)', () => {
		it('round trips a witness stack', () => {
			const w = {
				offerId: OFFER_ID,
				witness: [Buffer.alloc(72, 0x30), Buffer.alloc(33, 0x02)]
			};
			expect(decodeDfWitness(encodeDfWitness(w))).to.deep.equal(w);
		});

		it('round trips an empty stack and refuses an oversized one', () => {
			expect(
				decodeDfWitness(encodeDfWitness({ offerId: OFFER_ID, witness: [] }))
					.witness
			).to.deep.equal([]);
			expect(() =>
				encodeDfWitness({
					offerId: OFFER_ID,
					witness: [...Array(9).keys()].map(() => Buffer.alloc(1))
				})
			).to.throw(/9 items, max 8/);
		});
	});

	describe('funding_receipt (21)', () => {
		it('round trips with and without the complete transaction', () => {
			const bare: IDfReceipt = {
				offerId: OFFER_ID,
				preimage: Buffer.alloc(32, 0x09),
				fundingTxid: Buffer.alloc(32, 0x0a)
			};
			expect(decodeDfReceipt(encodeDfReceipt(bare))).to.deep.equal(bare);
			const full = { ...bare, rawTx: Buffer.alloc(500, 0x0b) };
			expect(decodeDfReceipt(encodeDfReceipt(full))).to.deep.equal(full);
		});
	});

	describe('relay frame (22)', () => {
		it('round trips an originator frame and a forwarded one', () => {
			const from = {
				subtype: 16,
				payload: Buffer.alloc(50, 1),
				from: LOCAL_FUNDING
			};
			const to = {
				subtype: 16,
				payload: Buffer.alloc(50, 1),
				to: REMOTE_FUNDING
			};
			expect(decodeDfRelayFrame(encodeDfRelayFrame(to))).to.deep.equal(to);
			expect(decodeDfRelayFrame(encodeDfRelayFrame(from))).to.deep.equal(from);
		});

		it('refuses a frame carrying both or neither endpoint', () => {
			// Both would let a payer pre-stamp its own origin; the relay stamps
			// `from` itself and never re-forwards a frame that has one.
			expect(() =>
				encodeDfRelayFrame({
					subtype: 16,
					payload: Buffer.alloc(1),
					to: REMOTE_FUNDING,
					from: LOCAL_FUNDING
				})
			).to.throw(/exactly one of to\/from/);
			const neither = encodeTlvStream([
				{ type: 0n, value: Buffer.from([0, 16]) },
				{ type: 2n, value: Buffer.alloc(4) }
			]);
			expect(codeOf(() => decodeDfRelayFrame(neither))).to.equal(
				DirectFundingErrorCode.MALFORMED
			);
			const both = encodeTlvStream([
				{ type: 0n, value: Buffer.from([0, 16]) },
				{ type: 2n, value: Buffer.alloc(4) },
				{ type: 4n, value: REMOTE_FUNDING },
				{ type: 6n, value: LOCAL_FUNDING }
			]);
			expect(codeOf(() => decodeDfRelayFrame(both))).to.equal(
				DirectFundingErrorCode.MALFORMED
			);
		});
	});

	describe('signed strings', () => {
		it('derives the offer id over the amount, not a prefix before it', () => {
			// An earlier draft revision truncated before the amount, so two
			// different amounts on one coin shared an id.
			expect(deriveOfferId(TXID, 1, 250_000n)).to.have.length(16);
			expect(deriveOfferId(TXID, 1, 250_000n)).to.deep.equal(OFFER_ID);
			expect(deriveOfferId(TXID, 1, 250_001n)).to.not.deep.equal(OFFER_ID);
			expect(deriveOfferId(TXID, 2, 250_000n)).to.not.deep.equal(OFFER_ID);
			expect(
				deriveOfferId(Buffer.alloc(32, 0xa2), 1, 250_000n)
			).to.not.deep.equal(OFFER_ID);
		});

		it('hashes a signed message the way Bitcoin Core does', () => {
			// bitcoin-cli signmessage / verifymessage envelope: varstr prefix,
			// varstr message, SHA256d. The same hash LND's SignMessageWithAddr
			// signs (checked against lnd 0.20 for both address kinds).
			const message = ownershipMessage(OFFER_ID, TXID, 1, 250_000n);
			expect(ownershipDigest(OFFER_ID, TXID, 1, 250_000n)).to.deep.equal(
				crypto.createHash('sha256').update(message, 'utf8').digest()
			);
			const prefix = Buffer.from('Bitcoin Signed Message:\n', 'utf8');
			const body = Buffer.from(message, 'utf8');
			const envelope = Buffer.concat([
				Buffer.from([prefix.length]),
				prefix,
				Buffer.from([body.length]),
				body
			]);
			const expected = crypto
				.createHash('sha256')
				.update(crypto.createHash('sha256').update(envelope).digest())
				.digest();
			expect(bitcoinMessageHash(message)).to.deep.equal(expected);
			// A message past 252 bytes takes the three-byte length form.
			const long = 'x'.repeat(300);
			const longEnvelope = Buffer.concat([
				Buffer.from([prefix.length]),
				prefix,
				Buffer.from([0xfd, 300 & 0xff, 300 >> 8]),
				Buffer.from(long, 'utf8')
			]);
			expect(bitcoinMessageHash(long)).to.deep.equal(
				crypto
					.createHash('sha256')
					.update(crypto.createHash('sha256').update(longEnvelope).digest())
					.digest()
			);
		});

		it('matches the draft ownership digest', () => {
			const expected = crypto
				.createHash('sha256')
				.update(
					`lfbw-direct-funding-offer:${OFFER_ID.toString('hex')}:` +
						`${TXID.toString('hex')}:1:250000`,
					'utf8'
				)
				.digest();
			expect(ownershipDigest(OFFER_ID, TXID, 1, 250_000n)).to.deep.equal(
				expected
			);
		});

		it('matches the draft attestation string', () => {
			const rawTx = Buffer.alloc(120, 0x0d);
			const txHash = crypto.createHash('sha256').update(rawTx).digest('hex');
			expect(attestationMessage(OFFER_ID, rawTx, 0, LOCAL_FUNDING)).to.equal(
				`lfbw-direct-funding-attest:${OFFER_ID.toString('hex')}:${txHash}:0:` +
					LOCAL_FUNDING.toString('hex')
			);
		});
	});
});
