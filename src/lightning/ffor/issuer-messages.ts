/**
 * The BOLT 12 issuer (spec section 9.7, Appendix F.6): the issuer manifest,
 * R's attestation, the four issuer messages and the invoice attestation
 * TLV. Same conventions as the witness lane: 16-byte request id first,
 * big-endian integers, authorization under the mailbox's fetch_key.
 */

import crypto from 'crypto';
import { sign, verify } from '../crypto/ecdh';
import { Reader, u16, u32, u64, u8 } from './messages';
import {
	FF_ISSUER_ATTEST_TAG,
	FF_ISSUER_STATUS_TAG,
	FF_WITNESS_REQUEST_ID_LEN
} from './witness-types';

/** Invoice TLV `ffor_issuer_attestation` (section 9.7.5), odd experimental. */
export const FF_ISSUER_ATTESTATION_TLV = 1_000_055_001n;
/** Section 9.7.3: the one refusal string, whatever the reason. */
export const FF_ISSUER_REFUSAL = 'no slot for this amount';
export const FF_ISSUER_MANIFEST_VERSION = 1;

/** One hop of the payment-path template (section 9.7.2). */
export interface IFforIssuerHop {
	nodeId: Buffer;
	shortChannelId: Buffer;
	feeBaseMsat: number;
	feeProportionalMillionths: number;
	cltvExpiryDelta: number;
	htlcMinimumMsat: bigint;
	htlcMaximumMsat: bigint;
}

export interface IFforIssuerManifest {
	version: number;
	mailboxId: Buffer;
	/** The BOLT 12 offer's TLV bytes. */
	offer: Buffer;
	hops: IFforIssuerHop[];
	issueUntil: number;
	rAttestation: Buffer;
}

function sha256(...parts: (Buffer | string)[]): Buffer {
	const h = crypto.createHash('sha256');
	for (const p of parts) {
		h.update(typeof p === 'string' ? Buffer.from(p, 'ascii') : p);
	}
	return h.digest();
}

function needId(b: Buffer): void {
	if (b.length !== FF_WITNESS_REQUEST_ID_LEN) {
		throw new Error('request_id must be 16 bytes');
	}
}

/** SHA256("ffor/issuer/attest" || offer_id || H_act || H_book). */
export function attestDigest(
	offerId: Buffer,
	hAct: Buffer,
	hBook: Buffer
): Buffer {
	return sha256(FF_ISSUER_ATTEST_TAG, offerId, hAct, hBook);
}

export function signAttestation(
	offerId: Buffer,
	hAct: Buffer,
	hBook: Buffer,
	nodePrivkey: Buffer
): Buffer {
	return sign(attestDigest(offerId, hAct, hBook), nodePrivkey);
}

export function verifyAttestation(
	offerId: Buffer,
	hAct: Buffer,
	hBook: Buffer,
	rNodeId: Buffer,
	attestation: Buffer
): boolean {
	return verify(attestDigest(offerId, hAct, hBook), rNodeId, attestation, true);
}

export function encodeIssuerHop(h: IFforIssuerHop): Buffer {
	if (h.nodeId.length !== 33) throw new Error('hop node id must be 33 bytes');
	if (h.shortChannelId.length !== 8)
		throw new Error('hop scid must be 8 bytes');
	return Buffer.concat([
		h.nodeId,
		h.shortChannelId,
		u32(h.feeBaseMsat),
		u32(h.feeProportionalMillionths),
		u16(h.cltvExpiryDelta),
		u64(h.htlcMinimumMsat),
		u64(h.htlcMaximumMsat)
	]);
}

export function encodeIssuerManifest(m: IFforIssuerManifest): Buffer {
	if (m.mailboxId.length !== 32) throw new Error('mailbox_id must be 32 bytes');
	if (m.offer.length > 0xffff) throw new Error('offer too long');
	if (m.hops.length > 0xffff) throw new Error('too many hops');
	if (m.rAttestation.length !== 64)
		throw new Error('attestation must be 64 bytes');
	return Buffer.concat([
		u8(m.version),
		m.mailboxId,
		u16(m.offer.length),
		m.offer,
		u16(m.hops.length),
		...m.hops.map(encodeIssuerHop),
		u32(m.issueUntil),
		m.rAttestation
	]);
}

export function decodeIssuerManifest(bytes: Buffer): IFforIssuerManifest {
	const r = new Reader(bytes, 'issuer_manifest');
	const version = r.u8();
	const mailboxId = r.bytes(32);
	const offer = r.bytes(r.u16());
	const n = r.u16();
	const hops: IFforIssuerHop[] = [];
	for (let i = 0; i < n; i++) {
		hops.push({
			nodeId: r.bytes(33),
			shortChannelId: r.bytes(8),
			feeBaseMsat: r.u32(),
			feeProportionalMillionths: r.u32(),
			cltvExpiryDelta: r.u16(),
			htlcMinimumMsat: r.u64(),
			htlcMaximumMsat: r.u64()
		});
	}
	const issueUntil = r.u32();
	const rAttestation = r.bytes(64);
	if (r.remaining() !== 0)
		throw new Error('issuer_manifest has trailing bytes');
	return { version, mailboxId, offer, hops, issueUntil, rAttestation };
}

// ── Messages (F.6) ────────────────────────────────────────────────────

function errorBytes(error: string): Buffer {
	const e = Buffer.from(error, 'utf8');
	return Buffer.concat([u16(e.length), e]);
}

export function encodeIssuerProvision(
	requestId: Buffer,
	manifest: Buffer
): Buffer {
	needId(requestId);
	return Buffer.concat([requestId, manifest]);
}

export function decodeIssuerProvision(body: Buffer): {
	requestId: Buffer;
	manifest: IFforIssuerManifest;
	manifestWire: Buffer;
} {
	if (body.length < FF_WITNESS_REQUEST_ID_LEN + 1) {
		throw new Error('ff_issuer_provision too short');
	}
	const requestId = Buffer.from(body.subarray(0, FF_WITNESS_REQUEST_ID_LEN));
	const manifestWire = Buffer.from(body.subarray(FF_WITNESS_REQUEST_ID_LEN));
	return {
		requestId,
		manifest: decodeIssuerManifest(manifestWire),
		manifestWire
	};
}

export interface IFforIssuerAck {
	requestId: Buffer;
	ok: boolean;
	blindedNodeIds: Buffer[];
	error?: string;
}

export function encodeIssuerAck(m: IFforIssuerAck): Buffer {
	needId(m.requestId);
	if (!m.ok)
		return Buffer.concat([m.requestId, u8(0), errorBytes(m.error ?? '')]);
	return Buffer.concat([
		m.requestId,
		u8(1),
		u16(m.blindedNodeIds.length),
		...m.blindedNodeIds
	]);
}

export function decodeIssuerAck(body: Buffer): IFforIssuerAck {
	const r = new Reader(body, 'ff_issuer_ack');
	const requestId = r.bytes(FF_WITNESS_REQUEST_ID_LEN);
	const ok = r.u8() === 1;
	if (!ok) {
		return {
			requestId,
			ok,
			blindedNodeIds: [],
			error: r.bytes(r.u16()).toString('utf8')
		};
	}
	const n = r.u16();
	const blindedNodeIds: Buffer[] = [];
	for (let i = 0; i < n; i++) blindedNodeIds.push(r.bytes(33));
	return { requestId, ok, blindedNodeIds };
}

export function statusDigest(mailboxId: Buffer, nonce: Buffer): Buffer {
	return sha256(FF_ISSUER_STATUS_TAG, mailboxId, nonce);
}

export function encodeIssuerStatus(
	requestId: Buffer,
	mailboxId: Buffer,
	nonce: Buffer,
	fetchPrivkey: Buffer
): Buffer {
	needId(requestId);
	return Buffer.concat([
		requestId,
		mailboxId,
		nonce,
		sign(statusDigest(mailboxId, nonce), fetchPrivkey)
	]);
}

export interface IFforIssuerStatusMessage {
	requestId: Buffer;
	mailboxId: Buffer;
	nonce: Buffer;
	signature: Buffer;
}

export function decodeIssuerStatus(body: Buffer): IFforIssuerStatusMessage {
	const r = new Reader(body, 'ff_issuer_status');
	const requestId = r.bytes(FF_WITNESS_REQUEST_ID_LEN);
	const mailboxId = r.bytes(32);
	const nonce = r.bytes(32);
	const signature = r.bytes(64);
	if (r.remaining() !== 0)
		throw new Error('ff_issuer_status has trailing bytes');
	return { requestId, mailboxId, nonce, signature };
}

export function verifyIssuerStatus(
	m: IFforIssuerStatusMessage,
	fetchPubkey: Buffer
): boolean {
	return verify(
		statusDigest(m.mailboxId, m.nonce),
		fetchPubkey,
		m.signature,
		true
	);
}

export interface IFforIssuedSlot {
	k: number;
	payerId: Buffer;
	metadataHash: Buffer;
	issuedUnixTime: bigint;
}

export interface IFforIssuerStatusResp {
	requestId: Buffer;
	ok: boolean;
	numSlots: number;
	issued: Buffer;
	slots: IFforIssuedSlot[];
	error?: string;
}

export function encodeIssuerStatusResp(m: IFforIssuerStatusResp): Buffer {
	needId(m.requestId);
	if (!m.ok)
		return Buffer.concat([m.requestId, u8(0), errorBytes(m.error ?? '')]);
	return Buffer.concat([
		m.requestId,
		u8(1),
		u16(m.numSlots),
		m.issued,
		...m.slots.map((s) =>
			Buffer.concat([
				u16(s.k),
				s.payerId,
				s.metadataHash,
				u64(s.issuedUnixTime)
			])
		)
	]);
}

export function decodeIssuerStatusResp(body: Buffer): IFforIssuerStatusResp {
	const r = new Reader(body, 'ff_issuer_status_resp');
	const requestId = r.bytes(FF_WITNESS_REQUEST_ID_LEN);
	const ok = r.u8() === 1;
	if (!ok) {
		return {
			requestId,
			ok,
			numSlots: 0,
			issued: Buffer.alloc(0),
			slots: [],
			error: r.bytes(r.u16()).toString('utf8')
		};
	}
	const numSlots = r.u16();
	const issued = r.bytes(Math.ceil(numSlots / 8));
	const slots: IFforIssuedSlot[] = [];
	while (r.remaining() > 0) {
		slots.push({
			k: r.u16(),
			payerId: r.bytes(33),
			metadataHash: r.bytes(32),
			issuedUnixTime: r.u64()
		});
	}
	return { requestId, ok, numSlots, issued, slots };
}

/** The value of TLV 1000055001: [32: H_act][32: H_book][64: r_attestation]. */
export function encodeAttestationTlvValue(
	hAct: Buffer,
	hBook: Buffer,
	rAttestation: Buffer
): Buffer {
	return Buffer.concat([hAct, hBook, rAttestation]);
}

export function decodeAttestationTlvValue(value: Buffer): {
	hAct: Buffer;
	hBook: Buffer;
	rAttestation: Buffer;
} {
	if (value.length !== 128)
		throw new Error('ffor_issuer_attestation must be 128 bytes');
	return {
		hAct: Buffer.from(value.subarray(0, 32)),
		hBook: Buffer.from(value.subarray(32, 64)),
		rAttestation: Buffer.from(value.subarray(64, 128))
	};
}
