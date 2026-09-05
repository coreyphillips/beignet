/**
 * Appendix F codecs: the manifest (section 9.6.4), the record (F.2), the six
 * witness messages (F.1), and the digests every signature covers. Integers
 * big-endian; every request carries a 16-byte request id first, echoed by
 * its response.
 */

import crypto from 'crypto';
import { sign, verify } from '../crypto/ecdh';
import { IFforBookEntry } from './types';
import { Reader, splitFixed, u16, u32, u64, u8 } from './messages';
import { decodeTlvStream, encodeTlvStream } from '../message/tlv';
import { encodeBookEntry } from './transcript';
import {
	FF_TERMS_TAG,
	FF_WITNESS_BODY_LEN,
	FF_WITNESS_CLOSE_TAG,
	FF_WITNESS_FETCH_TAG,
	FF_WITNESS_MANIFEST_TAG,
	FF_WITNESS_RECORD_HEADER_LEN,
	FF_WITNESS_RECORD_TAG,
	FF_WITNESS_REQUEST_ID_LEN,
	IFforWitnessAckMessage,
	IFforWitnessBody,
	IFforWitnessCloseAckMessage,
	IFforWitnessCloseMessage,
	IFforWitnessFetchMessage,
	IFforWitnessFetchRespMessage,
	IFforWitnessManifest,
	IFforWitnessProvisionMessage,
	IFforWitnessRecord,
	IFforWitnessRecordHeader,
	FF_WITNESS_FETCH_AFTER_K_TLV,
	FF_WITNESS_FETCH_NEXT_TLV
} from './witness-types';

function sha256(...parts: (Buffer | string)[]): Buffer {
	const h = crypto.createHash('sha256');
	for (const p of parts)
		h.update(typeof p === 'string' ? Buffer.from(p, 'ascii') : p);
	return h.digest();
}

function need32(b: Buffer, name: string): void {
	if (b.length !== 32) throw new Error(`${name} must be 32 bytes`);
}
function need33(b: Buffer, name: string): void {
	if (b.length !== 33) throw new Error(`${name} must be 33 bytes`);
}
function needId(b: Buffer): void {
	if (b.length !== FF_WITNESS_REQUEST_ID_LEN) {
		throw new Error('request_id must be 16 bytes');
	}
}

// ---------------------------------------------------------------------------
// terms_hash (Appendix F.2)
// ---------------------------------------------------------------------------

/** SHA256("ffor/terms" || entry_k): commits to (k, H_k, d_k, T_exp, D, s_htlc_id). */
export function termsHash(entry: IFforBookEntry): Buffer {
	return sha256(FF_TERMS_TAG, encodeBookEntry(entry));
}

// ---------------------------------------------------------------------------
// Manifest (section 9.6.4)
// ---------------------------------------------------------------------------

export function encodeManifestUnsigned(
	m: Omit<IFforWitnessManifest, 'signature'>
): Buffer {
	need32(m.mailboxId, 'mailbox_id');
	need32(m.tSetup, 'T_setup');
	need32(m.hCommit, 'H_commit');
	need32(m.hAct, 'H_act');
	need33(m.fetchPubkey, 'fetch_pubkey');
	need33(m.encPubkey, 'enc_pubkey');
	if (m.book.length > 0xffff) throw new Error('book too long');
	return Buffer.concat([
		u8(m.version),
		u8(m.profile),
		m.mailboxId,
		m.tSetup,
		m.hCommit,
		u32(m.epochStartHeight),
		m.hAct,
		m.fetchPubkey,
		m.encPubkey,
		u32(m.retentionUntil),
		u8(m.minReceipts),
		u16(m.book.length),
		m.book
	]);
}

export function manifestDigest(unsigned: Buffer): Buffer {
	return sha256(FF_WITNESS_MANIFEST_TAG, unsigned);
}

export function signManifest(
	m: Omit<IFforWitnessManifest, 'signature'>,
	fetchPrivkey: Buffer
): Buffer {
	const unsigned = encodeManifestUnsigned(m);
	return Buffer.concat([
		unsigned,
		sign(manifestDigest(unsigned), fetchPrivkey)
	]);
}

export function decodeManifest(bytes: Buffer): IFforWitnessManifest {
	const r = new Reader(bytes, 'manifest');
	const version = r.u8();
	const profile = r.u8();
	const mailboxId = r.bytes(32);
	const tSetup = r.bytes(32);
	const hCommit = r.bytes(32);
	const epochStartHeight = r.u32();
	const hAct = r.bytes(32);
	const fetchPubkey = r.bytes(33);
	const encPubkey = r.bytes(33);
	const retentionUntil = r.u32();
	const minReceipts = r.u8();
	const bookLen = r.u16();
	const book = r.bytes(bookLen);
	const signature = r.bytes(64);
	if (r.remaining() !== 0) throw new Error('manifest has trailing bytes');
	return {
		version,
		profile,
		mailboxId,
		tSetup,
		hCommit,
		epochStartHeight,
		hAct,
		fetchPubkey,
		encPubkey,
		retentionUntil,
		minReceipts,
		book,
		signature
	};
}

/** The manifest's own signature, under its fetch_pubkey. */
export function verifyManifest(
	bytes: Buffer,
	m: IFforWitnessManifest
): boolean {
	if (bytes.length < 64) return false;
	const unsigned = bytes.subarray(0, bytes.length - 64);
	return verify(manifestDigest(unsigned), m.fetchPubkey, m.signature, true);
}

// ---------------------------------------------------------------------------
// Record (Appendix F.2)
// ---------------------------------------------------------------------------

export function encodeRecordHeader(h: IFforWitnessRecordHeader): Buffer {
	need32(h.mailboxId, 'mailbox_id');
	need32(h.recordId, 'record_id');
	need32(h.hAct, 'H_act');
	need32(h.termsHash, 'terms_hash');
	need33(h.witnessNodeId, 'witness_node_id');
	need33(h.encPubkey, 'enc_pubkey');
	need32(h.ciphertextHash, 'ciphertext_hash');
	const out = Buffer.concat([
		u8(h.version),
		u8(h.profile),
		h.mailboxId,
		h.recordId,
		u16(h.k),
		h.hAct,
		h.termsHash,
		h.witnessNodeId,
		h.encPubkey,
		u32(h.recordedHeight),
		u8(h.flags),
		h.ciphertextHash
	]);
	if (out.length !== FF_WITNESS_RECORD_HEADER_LEN) {
		throw new Error('record header size mismatch');
	}
	return out;
}

export function recordDigest(headerBytes: Buffer): Buffer {
	return sha256(FF_WITNESS_RECORD_TAG, headerBytes);
}

/**
 * Appendix F.3's associated data: the header with `ciphertext_hash` zeroed.
 * The header commits to the ciphertext and the ciphertext is bound to the
 * header, so one of them has to be fixed first; the hash field is the one
 * that is left out of the AAD (spec erratum from the M9 implementation).
 */
export function recordAad(h: IFforWitnessRecordHeader): Buffer {
	return encodeRecordHeader({ ...h, ciphertextHash: Buffer.alloc(32) });
}

export function encodeRecord(rec: IFforWitnessRecord): Buffer {
	if (rec.ciphertext.length > 0xffff) throw new Error('ciphertext too long');
	if (rec.receipts.length > 0xff) throw new Error('too many receipts');
	return Buffer.concat([
		encodeRecordHeader(rec.header),
		rec.witnessSig,
		u16(rec.ciphertext.length),
		rec.ciphertext,
		u8(rec.receipts.length),
		...rec.receipts.map((x) => Buffer.concat([u16(x.length), x]))
	]);
}

export function decodeRecord(bytes: Buffer): IFforWitnessRecord {
	const r = new Reader(bytes, 'record');
	const header: IFforWitnessRecordHeader = {
		version: r.u8(),
		profile: r.u8(),
		mailboxId: r.bytes(32),
		recordId: r.bytes(32),
		k: r.u16(),
		hAct: r.bytes(32),
		termsHash: r.bytes(32),
		witnessNodeId: r.bytes(33),
		encPubkey: r.bytes(33),
		recordedHeight: r.u32(),
		flags: r.u8(),
		ciphertextHash: r.bytes(32)
	};
	const witnessSig = r.bytes(64);
	const ciphertext = r.bytes(r.u16());
	const n = r.u8();
	const receipts: Buffer[] = [];
	for (let i = 0; i < n; i++) receipts.push(r.bytes(r.u16()));
	if (r.remaining() !== 0) throw new Error('record has trailing bytes');
	return { header, witnessSig, ciphertext, receipts };
}

/** The witness's node-key signature over the header, strict low-S. */
export function verifyRecordSignature(rec: IFforWitnessRecord): boolean {
	return verify(
		recordDigest(encodeRecordHeader(rec.header)),
		rec.header.witnessNodeId,
		rec.witnessSig,
		true
	);
}

export function encodeRecordBody(b: IFforWitnessBody): Buffer {
	need32(b.epochId, 'epoch_id');
	need32(b.t, 't');
	need32(b.hK, 'H_k');
	const out = Buffer.concat([
		b.epochId,
		u16(b.k),
		b.t,
		b.hK,
		u64(b.dK),
		u32(b.tExp),
		u32(b.d),
		u64(b.amountInMsat),
		u64(b.amountOutMsat),
		u32(b.outgoingCltv),
		u64(b.observedUnixTime)
	]);
	if (out.length !== FF_WITNESS_BODY_LEN) throw new Error('body size mismatch');
	return out;
}

export function decodeRecordBody(bytes: Buffer): IFforWitnessBody {
	if (bytes.length !== FF_WITNESS_BODY_LEN) {
		throw new Error(`body must be ${FF_WITNESS_BODY_LEN} bytes`);
	}
	const r = new Reader(bytes, 'body');
	return {
		epochId: r.bytes(32),
		k: r.u16(),
		t: r.bytes(32),
		hK: r.bytes(32),
		dK: r.u64(),
		tExp: r.u32(),
		d: r.u32(),
		amountInMsat: r.u64(),
		amountOutMsat: r.u64(),
		outgoingCltv: r.u32(),
		observedUnixTime: r.u64()
	};
}

// ---------------------------------------------------------------------------
// Fetch and close digests (F.1)
// ---------------------------------------------------------------------------

/**
 * `SHA256("ffor/witness/fetch" || mailbox_id || nonce || tlv)`, where `tlv` is
 * the fetch's trailing TLV stream (empty on a first page, so a fetch without
 * paging digests exactly as before).
 */
export function fetchDigest(
	mailboxId: Buffer,
	nonce: Buffer,
	tlv: Buffer = Buffer.alloc(0)
): Buffer {
	return sha256(FF_WITNESS_FETCH_TAG, mailboxId, nonce, tlv);
}

/** F.1 paging: the trailing TLV stream of a fetch, empty without `after_k`. */
export function fetchTlv(afterK?: number): Buffer {
	if (afterK === undefined) return Buffer.alloc(0);
	if (!Number.isInteger(afterK) || afterK < 0 || afterK > 0xffff) {
		throw new Error('after_k out of range');
	}
	return encodeTlvStream([
		{ type: FF_WITNESS_FETCH_AFTER_K_TLV, value: u16(afterK) }
	]);
}

/** One u16 out of a trailing TLV stream; absent when the stream is empty. */
function readU16Tlv(
	tlv: Buffer,
	type: bigint,
	label: string
): number | undefined {
	if (tlv.length === 0) return undefined;
	const { records } = decodeTlvStream(tlv, 0, new Set([type]));
	const rec = records.find((x) => x.type === type);
	if (!rec) return undefined;
	if (rec.value.length !== 2) {
		throw new Error(`${label}: TLV ${type} is not a u16`);
	}
	return rec.value.readUInt16BE(0);
}

/** `SHA256("ffor/witness/close" || body without sig)`. */
export function closeDigest(bodyWithoutSig: Buffer): Buffer {
	return sha256(FF_WITNESS_CLOSE_TAG, bodyWithoutSig);
}

// ---------------------------------------------------------------------------
// Messages (F.1)
// ---------------------------------------------------------------------------

function errorBytes(error: string): Buffer {
	const e = Buffer.from(error, 'utf8');
	if (e.length > 0xffff) throw new Error('error too long');
	return Buffer.concat([u16(e.length), e]);
}

export function encodeWitnessProvision(
	requestId: Buffer,
	manifestWire: Buffer
): Buffer {
	needId(requestId);
	return Buffer.concat([requestId, manifestWire]);
}

export function decodeWitnessProvision(
	body: Buffer
): IFforWitnessProvisionMessage & { manifestWire: Buffer } {
	if (body.length < FF_WITNESS_REQUEST_ID_LEN + 1) {
		throw new Error('ff_witness_provision too short');
	}
	const requestId = Buffer.from(body.subarray(0, FF_WITNESS_REQUEST_ID_LEN));
	const manifestWire = Buffer.from(body.subarray(FF_WITNESS_REQUEST_ID_LEN));
	return { requestId, manifest: decodeManifest(manifestWire), manifestWire };
}

export function encodeWitnessAck(m: IFforWitnessAckMessage): Buffer {
	needId(m.requestId);
	if (m.ok) {
		need33(m.witnessNodeId!, 'witness_node_id');
		return Buffer.concat([
			m.requestId,
			u8(1),
			m.witnessNodeId!,
			u32(m.retentionUntil!)
		]);
	}
	return Buffer.concat([m.requestId, u8(0), errorBytes(m.error ?? '')]);
}

export function decodeWitnessAck(body: Buffer): IFforWitnessAckMessage {
	const r = new Reader(body, 'ff_witness_ack');
	const requestId = r.bytes(FF_WITNESS_REQUEST_ID_LEN);
	const ok = r.u8() === 1;
	if (ok) {
		return {
			requestId,
			ok,
			witnessNodeId: r.bytes(33),
			retentionUntil: r.u32()
		};
	}
	return { requestId, ok, error: r.bytes(r.u16()).toString('utf8') };
}

export function encodeWitnessFetch(
	requestId: Buffer,
	mailboxId: Buffer,
	nonce: Buffer,
	fetchPrivkey: Buffer,
	afterK?: number
): Buffer {
	needId(requestId);
	need32(mailboxId, 'mailbox_id');
	need32(nonce, 'nonce');
	const tlv = fetchTlv(afterK);
	return Buffer.concat([
		requestId,
		mailboxId,
		nonce,
		sign(fetchDigest(mailboxId, nonce, tlv), fetchPrivkey),
		tlv
	]);
}

export function decodeWitnessFetch(body: Buffer): IFforWitnessFetchMessage {
	const r = new Reader(body, 'ff_witness_fetch');
	const requestId = r.bytes(FF_WITNESS_REQUEST_ID_LEN);
	const mailboxId = r.bytes(32);
	const nonce = r.bytes(32);
	const signature = r.bytes(64);
	const tlv = r.bytes(r.remaining());
	const afterK = readU16Tlv(
		tlv,
		FF_WITNESS_FETCH_AFTER_K_TLV,
		'ff_witness_fetch'
	);
	return {
		requestId,
		mailboxId,
		nonce,
		signature,
		tlv,
		...(afterK !== undefined ? { afterK } : {})
	};
}

export function verifyWitnessFetch(
	m: IFforWitnessFetchMessage,
	fetchPubkey: Buffer
): boolean {
	return verify(
		fetchDigest(m.mailboxId, m.nonce, m.tlv),
		fetchPubkey,
		m.signature,
		true
	);
}

export function encodeWitnessFetchResp(
	m: IFforWitnessFetchRespMessage
): Buffer {
	needId(m.requestId);
	if (!m.ok) {
		return Buffer.concat([m.requestId, u8(0), errorBytes(m.error ?? '')]);
	}
	if (m.records.length > 0xffff) throw new Error('too many records');
	let tlv = Buffer.alloc(0);
	if (m.nextAfterK !== undefined) {
		if (
			!Number.isInteger(m.nextAfterK) ||
			m.nextAfterK < 0 ||
			m.nextAfterK > 0xffff
		) {
			throw new Error('next_after_k out of range');
		}
		tlv = encodeTlvStream([
			{ type: FF_WITNESS_FETCH_NEXT_TLV, value: u16(m.nextAfterK) }
		]);
	}
	return Buffer.concat([
		m.requestId,
		u8(1),
		u16(m.records.length),
		...m.records.map((rec) => {
			const bytes = encodeRecord(rec);
			if (bytes.length > 0xffff) throw new Error('record too long');
			return Buffer.concat([u16(bytes.length), bytes]);
		}),
		tlv
	]);
}

export function decodeWitnessFetchResp(
	body: Buffer
): IFforWitnessFetchRespMessage {
	const r = new Reader(body, 'ff_witness_fetch_resp');
	const requestId = r.bytes(FF_WITNESS_REQUEST_ID_LEN);
	const ok = r.u8() === 1;
	if (!ok) {
		return {
			requestId,
			ok,
			records: [],
			error: r.bytes(r.u16()).toString('utf8')
		};
	}
	const n = r.u16();
	const records: IFforWitnessRecord[] = [];
	for (let i = 0; i < n; i++) records.push(decodeRecord(r.bytes(r.u16())));
	const nextAfterK = readU16Tlv(
		r.bytes(r.remaining()),
		FF_WITNESS_FETCH_NEXT_TLV,
		'ff_witness_fetch_resp'
	);
	return {
		requestId,
		ok,
		records,
		...(nextAfterK !== undefined ? { nextAfterK } : {})
	};
}

/** The bytes the close signature covers: everything after the request id, before the sig. */
function closeUnsigned(
	mailboxId: Buffer,
	hAct: Buffer,
	numSlots: number,
	settled: Buffer,
	nonce: Buffer
): Buffer {
	need32(mailboxId, 'mailbox_id');
	need32(hAct, 'H_act');
	need32(nonce, 'nonce');
	if (settled.length !== Math.ceil(numSlots / 8)) {
		throw new Error('settled bitmap length does not match K');
	}
	return Buffer.concat([mailboxId, hAct, u16(numSlots), settled, nonce]);
}

export function encodeWitnessClose(
	requestId: Buffer,
	mailboxId: Buffer,
	hAct: Buffer,
	numSlots: number,
	settled: Buffer,
	nonce: Buffer,
	fetchPrivkey: Buffer
): Buffer {
	needId(requestId);
	const unsigned = closeUnsigned(mailboxId, hAct, numSlots, settled, nonce);
	return Buffer.concat([
		requestId,
		unsigned,
		sign(closeDigest(unsigned), fetchPrivkey)
	]);
}

export function decodeWitnessClose(body: Buffer): IFforWitnessCloseMessage {
	const r = new Reader(body, 'ff_witness_close');
	const requestId = r.bytes(FF_WITNESS_REQUEST_ID_LEN);
	const mailboxId = r.bytes(32);
	const hAct = r.bytes(32);
	const numSlots = r.u16();
	const settled = r.bytes(Math.ceil(numSlots / 8));
	const nonce = r.bytes(32);
	const signature = r.bytes(64);
	if (r.remaining() !== 0)
		throw new Error('ff_witness_close has trailing bytes');
	return { requestId, mailboxId, hAct, numSlots, settled, nonce, signature };
}

export function verifyWitnessClose(
	m: IFforWitnessCloseMessage,
	fetchPubkey: Buffer
): boolean {
	const unsigned = closeUnsigned(
		m.mailboxId,
		m.hAct,
		m.numSlots,
		m.settled,
		m.nonce
	);
	return verify(closeDigest(unsigned), fetchPubkey, m.signature, true);
}

export function encodeWitnessCloseAck(m: IFforWitnessCloseAckMessage): Buffer {
	needId(m.requestId);
	return Buffer.concat([m.requestId, u8(m.ok ? 1 : 0), u16(m.numRecordsHeld)]);
}

export function decodeWitnessCloseAck(
	body: Buffer
): IFforWitnessCloseAckMessage {
	const r = new Reader(body, 'ff_witness_close_ack');
	const requestId = r.bytes(FF_WITNESS_REQUEST_ID_LEN);
	const ok = r.u8() === 1;
	const numRecordsHeld = r.u16();
	if (r.remaining() !== 0) {
		throw new Error('ff_witness_close_ack has trailing bytes');
	}
	return { requestId, ok, numRecordsHeld };
}

/** The request id any witness-lane message starts with. */
export function witnessRequestId(body: Buffer): Buffer {
	if (body.length < FF_WITNESS_REQUEST_ID_LEN) {
		throw new Error('witness message too short for a request id');
	}
	return Buffer.from(body.subarray(0, FF_WITNESS_REQUEST_ID_LEN));
}

/** Utility: the set of hashes in a book, as hex. */
export function bookHashesHex(entries: IFforBookEntry[]): string[] {
	return entries.map((e) => e.paymentHash.toString('hex'));
}

export { splitFixed };

// ---------------------------------------------------------------------------
// R's verification of a served record (section 9.6.6)
// ---------------------------------------------------------------------------

import { getPublicKey } from '../crypto/ecdh';
import { openRecordBody } from './witness-crypto';
import { IFforWitnessProvision } from './witness-types';

export interface IFforWitnessVerification {
	ok: boolean;
	k: number;
	unbarriered: boolean;
	/** The preimage, when every check passed. */
	t?: Buffer;
	reason?: string;
}

/**
 * Section 9.6.6 steps 1 to 3 for one record: the witness's signature and
 * identity, H_act and terms_hash against R's own book, the body decrypted
 * under enc_key, SHA256(t) == H_k, and the body's (k, H_k, d_k) against the
 * header and the book. A record that fails is an audit fact, never credit.
 */
export function verifyWitnessRecord(
	rec: IFforWitnessRecord,
	provision: IFforWitnessProvision,
	entries: IFforBookEntry[],
	epochId: Buffer,
	hAct: Buffer
): IFforWitnessVerification {
	const h = rec.header;
	const out = (reason: string): IFforWitnessVerification => ({
		ok: false,
		k: h.k,
		unbarriered: (h.flags & 0x01) !== 0,
		reason
	});
	if (!h.witnessNodeId.equals(provision.witnessNodeId)) {
		return out('record names another witness');
	}
	if (!verifyRecordSignature(rec)) return out('witness signature invalid');
	if (!h.mailboxId.equals(provision.mailboxId)) return out('wrong mailbox');
	if (!h.hAct.equals(hAct)) return out('H_act mismatch');
	if (!h.encPubkey.equals(getPublicKey(provision.encPrivkey))) {
		return out('enc_pubkey is not ours');
	}
	const entry = entries[h.k - 1];
	if (!entry || entry.k !== h.k) return out('no such slot');
	if (!h.termsHash.equals(termsHash(entry))) return out('terms_hash mismatch');
	if (!sha256(rec.ciphertext).equals(h.ciphertextHash)) {
		return out('ciphertext_hash mismatch');
	}
	let body: IFforWitnessBody;
	try {
		body = decodeRecordBody(
			openRecordBody(provision.encPrivkey, recordAad(h), rec.ciphertext)
		);
	} catch (err) {
		return out(`body does not open: ${(err as Error).message}`);
	}
	if (!body.epochId.equals(epochId)) return out('body names another epoch');
	if (body.k !== h.k) return out('body slot disagrees with header');
	if (!body.hK.equals(entry.paymentHash))
		return out('body H_k disagrees with book');
	if (body.dK !== entry.amountMsat) return out('body d_k disagrees with book');
	if (
		body.tExp !== entry.voucherExpiry ||
		body.d !== entry.settlementDeadline
	) {
		return out('body T_exp or D disagrees with book');
	}
	if (!sha256(body.t).equals(entry.paymentHash)) {
		return out('preimage does not hash to H_k');
	}
	return { ok: true, k: h.k, unbarriered: (h.flags & 0x01) !== 0, t: body.t };
}
