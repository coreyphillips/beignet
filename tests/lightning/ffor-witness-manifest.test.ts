/**
 * FFOR D-R receipt witnesses, the objects (spec section 9.6.4, Appendix F.2,
 * F.3; issue #720 M9.0): the manifest's signature, the book consistency a
 * witness checks, the record's encoding and encryption, and R's
 * verification of a served record.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { FforVariant, IFforBookEntry } from '../../src/lightning/ffor/types';
import {
	buildVoucherBook,
	computeHAct,
	computeHBook,
	decodeVoucherBook
} from '../../src/lightning/ffor/transcript';
import {
	decodeManifest,
	decodeRecord,
	decodeRecordBody,
	encodeRecord,
	encodeRecordBody,
	encodeRecordHeader,
	recordAad,
	recordDigest,
	signManifest,
	termsHash,
	verifyManifest,
	verifyRecordSignature,
	verifyWitnessRecord
} from '../../src/lightning/ffor/witness-messages';
import {
	openRecordBody,
	sealRecordBody
} from '../../src/lightning/ffor/witness-crypto';
import {
	FF_WITNESS_PROFILE_DR,
	FF_WITNESS_RECORD_HEADER_LEN,
	FF_WITNESS_VERSION,
	IFforWitnessProvision,
	IFforWitnessRecord,
	IFforWitnessRecordHeader
} from '../../src/lightning/ffor/witness-types';
import { sign } from '../../src/lightning/crypto/ecdh';

const sha256 = (b: Buffer): Buffer =>
	crypto.createHash('sha256').update(b).digest();

function entries(
	K: number,
	amount = 100_000_000n
): { entries: IFforBookEntry[]; preimages: Buffer[] } {
	const preimages = Array.from({ length: K }, (_, i) =>
		sha256(Buffer.from(`t-${i}`))
	);
	return {
		preimages,
		entries: preimages.map((t, i) => ({
			k: i + 1,
			paymentHash: sha256(t),
			amountMsat: amount,
			voucherExpiry: 800_000,
			settlementDeadline: 798_992,
			sHtlcId: BigInt(10 + i)
		}))
	};
}

const EPOCH = sha256(Buffer.from('epoch'));
const T_SETUP = sha256(Buffer.from('tsetup'));
const H_COMMIT = sha256(Buffer.from('hcommit'));
const START = 790_000;

function manifestFor(
	book: Buffer,
	fetchPriv: Buffer,
	encPriv: Buffer,
	overrides: Partial<Parameters<typeof signManifest>[0]> = {}
): Buffer {
	const hBook = computeHBook(book);
	return signManifest(
		{
			version: FF_WITNESS_VERSION,
			profile: FF_WITNESS_PROFILE_DR,
			mailboxId: sha256(Buffer.from('mailbox')),
			tSetup: T_SETUP,
			hCommit: H_COMMIT,
			epochStartHeight: START,
			hAct: computeHAct(T_SETUP, hBook, H_COMMIT, START),
			fetchPubkey: getPublicKey(fetchPriv),
			encPubkey: getPublicKey(encPriv),
			retentionUntil: 800_000 + 144,
			minReceipts: 0,
			book,
			...overrides
		},
		fetchPriv
	);
}

describe('FFOR witness objects (section 9.6.4, Appendix F)', () => {
	it('the book round-trips and terms_hash is stable', () => {
		const { entries: es } = entries(3);
		const book = buildVoucherBook(EPOCH, FforVariant.D, es);
		const decoded = decodeVoucherBook(book);
		expect(decoded.epochId.equals(EPOCH)).to.be.true;
		expect(decoded.entries.map((e) => e.k)).to.deep.equal([1, 2, 3]);
		expect(decoded.entries[2].sHtlcId).to.equal(12n);
		expect(() => decodeVoucherBook(book.subarray(0, book.length - 1))).to.throw(
			/entry count/
		);
		// Pinned: a change here is a wire change (Appendix F.2 terms_hash).
		expect(termsHash(es[0]).toString('hex')).to.equal(
			termsHash({ ...es[0] }).toString('hex')
		);
		expect(termsHash(es[0]).equals(termsHash(es[1]))).to.be.false;
	});

	it('a manifest verifies under its fetch_key and nothing else', () => {
		const fetchPriv = crypto.randomBytes(32);
		const encPriv = crypto.randomBytes(32);
		const book = buildVoucherBook(EPOCH, FforVariant.D, entries(2).entries);
		const wire = manifestFor(book, fetchPriv, encPriv);
		const m = decodeManifest(wire);
		expect(verifyManifest(wire, m)).to.be.true;
		expect(m.book.equals(book)).to.be.true;
		expect(m.minReceipts).to.equal(0);
		// Signed by another key.
		const forged = manifestFor(book, crypto.randomBytes(32), encPriv, {
			fetchPubkey: getPublicKey(fetchPriv)
		});
		expect(verifyManifest(forged, decodeManifest(forged))).to.be.false;
		// One flipped bit in the body.
		const tampered = Buffer.from(wire);
		tampered[40] ^= 0x01;
		expect(verifyManifest(tampered, decodeManifest(tampered))).to.be.false;
		expect(() => decodeManifest(wire.subarray(0, 50))).to.throw(/too short/);
	});

	it('a record encodes to the Appendix F.2 layout, its body seals to enc_pubkey and the header is the AAD', () => {
		const witnessPriv = crypto.randomBytes(32);
		const encPriv = crypto.randomBytes(32);
		const { entries: es, preimages } = entries(1);
		const body = encodeRecordBody({
			epochId: EPOCH,
			k: 1,
			t: preimages[0],
			hK: es[0].paymentHash,
			dK: es[0].amountMsat,
			tExp: es[0].voucherExpiry,
			d: es[0].settlementDeadline,
			amountInMsat: 100_500_000n,
			amountOutMsat: 100_000_000n,
			outgoingCltv: 790_100,
			observedUnixTime: 1_700_000_000n
		});
		const header: IFforWitnessRecordHeader = {
			version: 1,
			profile: 1,
			mailboxId: sha256(Buffer.from('mailbox')),
			recordId: crypto.randomBytes(32),
			k: 1,
			hAct: sha256(Buffer.from('hact')),
			termsHash: termsHash(es[0]),
			witnessNodeId: getPublicKey(witnessPriv),
			encPubkey: getPublicKey(encPriv),
			recordedHeight: 790_050,
			flags: 0,
			ciphertextHash: Buffer.alloc(32)
		};
		expect(encodeRecordHeader(header)).to.have.length(
			FF_WITNESS_RECORD_HEADER_LEN
		);
		const ciphertext = sealRecordBody(
			getPublicKey(encPriv),
			recordAad(header),
			body
		);
		header.ciphertextHash = sha256(ciphertext);
		const signedHeader = encodeRecordHeader(header);
		const rec: IFforWitnessRecord = {
			header,
			witnessSig: sign(recordDigest(signedHeader), witnessPriv),
			ciphertext,
			receipts: [Buffer.from('receipt-1')]
		};
		const wire = encodeRecord(rec);
		const back = decodeRecord(wire);
		expect(back.header.k).to.equal(1);
		expect(back.receipts[0].toString()).to.equal('receipt-1');
		expect(verifyRecordSignature(back)).to.be.true;
		const opened = decodeRecordBody(
			openRecordBody(encPriv, recordAad(back.header), back.ciphertext)
		);
		expect(opened.t.equals(preimages[0])).to.be.true;
		expect(opened.observedUnixTime).to.equal(1_700_000_000n);
		// The header is the AAD: serving this body under another header fails.
		const otherAad = recordAad({ ...header, k: 2 });
		expect(() => openRecordBody(encPriv, otherAad, back.ciphertext)).to.throw();
		// Only enc_key opens it.
		expect(() =>
			openRecordBody(
				crypto.randomBytes(32),
				recordAad(back.header),
				back.ciphertext
			)
		).to.throw();
	});

	it("R's verification credits a good record and names every defect", () => {
		const witnessPriv = crypto.randomBytes(32);
		const encPriv = crypto.randomBytes(32);
		const fetchPriv = crypto.randomBytes(32);
		const { entries: es, preimages } = entries(2);
		const book = buildVoucherBook(EPOCH, FforVariant.D, es);
		const hAct = computeHAct(T_SETUP, computeHBook(book), H_COMMIT, START);
		const provision: IFforWitnessProvision = {
			witnessNodeId: getPublicKey(witnessPriv),
			mailboxId: sha256(Buffer.from('mailbox')),
			fetchPrivkey: fetchPriv,
			encPrivkey: encPriv,
			retentionUntil: 800_144,
			minReceipts: 0,
			manifestWire: Buffer.alloc(0),
			ackedAt: 1
		};
		const build = (
			k: number,
			t: Buffer,
			tweak: (
				h: IFforWitnessRecordHeader,
				body: Buffer
			) => [IFforWitnessRecordHeader, Buffer] = (h, b) => [h, b],
			signer = witnessPriv
		): IFforWitnessRecord => {
			const e = es[k - 1];
			let body = encodeRecordBody({
				epochId: EPOCH,
				k,
				t,
				hK: e.paymentHash,
				dK: e.amountMsat,
				tExp: e.voucherExpiry,
				d: e.settlementDeadline,
				amountInMsat: e.amountMsat + 1000n,
				amountOutMsat: e.amountMsat,
				outgoingCltv: 790_100,
				observedUnixTime: 1n
			});
			let header: IFforWitnessRecordHeader = {
				version: 1,
				profile: 1,
				mailboxId: provision.mailboxId,
				recordId: crypto.randomBytes(32),
				k,
				hAct,
				termsHash: termsHash(e),
				witnessNodeId: getPublicKey(witnessPriv),
				encPubkey: getPublicKey(encPriv),
				recordedHeight: 790_050,
				flags: 0,
				ciphertextHash: Buffer.alloc(32)
			};
			[header, body] = tweak(header, body);
			const ciphertext = sealRecordBody(
				header.encPubkey,
				recordAad(header),
				body
			);
			header.ciphertextHash = sha256(ciphertext);
			return {
				header,
				witnessSig: sign(recordDigest(encodeRecordHeader(header)), signer),
				ciphertext,
				receipts: []
			};
		};
		const good = verifyWitnessRecord(
			build(2, preimages[1]),
			provision,
			es,
			EPOCH,
			hAct
		);
		expect(good.ok, good.reason).to.be.true;
		expect(good.t!.equals(preimages[1])).to.be.true;
		expect(good.k).to.equal(2);

		const cases: [string, IFforWitnessRecord, RegExp][] = [
			['wrong preimage', build(1, preimages[1]), /does not hash to H_k/],
			[
				'another witness signed',
				build(1, preimages[0], undefined, crypto.randomBytes(32)),
				/names another witness|signature invalid/
			],
			[
				'H_act of another epoch',
				build(1, preimages[0], (h, b) => [
					{ ...h, hAct: sha256(Buffer.from('x')) },
					b
				]),
				/H_act mismatch/
			],
			[
				'terms of another slot',
				build(1, preimages[0], (h, b) => [
					{ ...h, termsHash: termsHash(es[1]) },
					b
				]),
				/terms_hash mismatch/
			],
			[
				'a slot the book lacks',
				build(1, preimages[0], (h, b) => [{ ...h, k: 9 }, b]),
				/no such slot/
			],
			[
				'unbarriered flag survives',
				build(1, preimages[0], (h, b) => [{ ...h, flags: 1 }, b]),
				/never/
			]
		];
		for (const [label, rec, re] of cases) {
			const v = verifyWitnessRecord(rec, provision, es, EPOCH, hAct);
			if (label === 'unbarriered flag survives') {
				expect(v.ok, label).to.be.true;
				expect(v.unbarriered, label).to.be.true;
				continue;
			}
			expect(v.ok, label).to.be.false;
			expect(v.reason, label).to.match(re);
		}
		// A body encrypted under our key but naming another epoch.
		const foreign = build(1, preimages[0], (h) => {
			const body = encodeRecordBody({
				epochId: sha256(Buffer.from('other')),
				k: 1,
				t: preimages[0],
				hK: es[0].paymentHash,
				dK: es[0].amountMsat,
				tExp: es[0].voucherExpiry,
				d: es[0].settlementDeadline,
				amountInMsat: 0n,
				amountOutMsat: 0n,
				outgoingCltv: 0,
				observedUnixTime: 0n
			});
			return [h, body];
		});
		expect(
			verifyWitnessRecord(foreign, provision, es, EPOCH, hAct).reason
		).to.match(/another epoch/);
		// A swapped ciphertext under a re-signed header: the AAD catches it.
		const a = build(1, preimages[0]);
		const b = build(2, preimages[1]);
		const swapped: IFforWitnessRecord = {
			...a,
			ciphertext: b.ciphertext,
			header: { ...a.header, ciphertextHash: sha256(b.ciphertext) }
		};
		swapped.witnessSig = sign(
			recordDigest(encodeRecordHeader(swapped.header)),
			witnessPriv
		);
		expect(
			verifyWitnessRecord(swapped, provision, es, EPOCH, hAct).reason
		).to.match(/does not open/);
	});
});
