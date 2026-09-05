/**
 * FFOR D-R receipt witnesses (spec section 9.6, Appendix F) and the BOLT 12
 * issuer (section 9.7, Appendix F.6): wire types, tags, sizes and the
 * objects the witness stores and R persists.
 *
 * A witness holds information, never money: the record it stores is R's
 * proof that a settlement happened, encrypted to a key only R holds and
 * signed by the witness's node key. Nothing here touches a channel.
 */

// ---------------------------------------------------------------------------
// Message types (Appendix F.1, F.6): odd, 16-byte request id first.
// ---------------------------------------------------------------------------

export const FF_WITNESS_PROVISION_TYPE = 55055;
export const FF_WITNESS_ACK_TYPE = 55057;
export const FF_WITNESS_FETCH_TYPE = 55059;
export const FF_WITNESS_FETCH_RESP_TYPE = 55061;
export const FF_WITNESS_CLOSE_TYPE = 55063;
export const FF_WITNESS_CLOSE_ACK_TYPE = 55065;
export const FF_ISSUER_PROVISION_TYPE = 55067;
export const FF_ISSUER_ACK_TYPE = 55069;
export const FF_ISSUER_STATUS_TYPE = 55071;
export const FF_ISSUER_STATUS_RESP_TYPE = 55073;

/** Every type the witness lane carries, requests and responses. */
export function isFforWitnessMessageType(type: number): boolean {
	return type >= FF_WITNESS_PROVISION_TYPE && type <= FF_ISSUER_STATUS_RESP_TYPE
		? type % 2 === 1
		: false;
}

/** The responses, which R (or I's client) correlates by request id. */
export function isFforWitnessResponseType(type: number): boolean {
	return (
		type === FF_WITNESS_ACK_TYPE ||
		type === FF_WITNESS_FETCH_RESP_TYPE ||
		type === FF_WITNESS_CLOSE_ACK_TYPE ||
		type === FF_ISSUER_ACK_TYPE ||
		type === FF_ISSUER_STATUS_RESP_TYPE
	);
}

export const FF_WITNESS_REQUEST_ID_LEN = 16;

// ---------------------------------------------------------------------------
// Tags and constants
// ---------------------------------------------------------------------------

export const FF_WITNESS_MANIFEST_TAG = 'ffor/witness/manifest';
export const FF_WITNESS_RECORD_TAG = 'ffor/witness/record';
export const FF_WITNESS_FETCH_TAG = 'ffor/witness/fetch';
export const FF_WITNESS_CLOSE_TAG = 'ffor/witness/close';
export const FF_WITNESS_BODY_INFO = 'ffor/witness/body';
export const FF_TERMS_TAG = 'ffor/terms';
export const FF_ISSUER_ATTEST_TAG = 'ffor/issuer/attest';
export const FF_ISSUER_STATUS_TAG = 'ffor/issuer/status';

export const FF_WITNESS_VERSION = 1;
/** Profile byte: 1 = D-R. */
export const FF_WITNESS_PROFILE_DR = 1;
/** Section 9.6.5: propagate within this wall-clock bound in normal operation. */
export const FF_WITNESS_BARRIER_MS = 30_000;

/**
 * Appendix F.1 paging. A mailbox with K near 483 holds more records than
 * one BOLT 8 frame carries, so `ff_witness_fetch` may carry an odd trailing
 * TLV naming `after_k`, and `ff_witness_fetch_resp` an odd trailing TLV
 * naming `next_after_k` while records remain. The witness serves records in
 * ascending k, at least one per page; each page is a fresh fetch under a
 * fresh nonce.
 */
export const FF_WITNESS_FETCH_AFTER_K_TLV = 1n;
export const FF_WITNESS_FETCH_NEXT_TLV = 1n;
/** Record bytes one fetch response carries at most (a frame is 65535). */
export const FF_WITNESS_FETCH_PAGE_BYTES = 60_000;
/** Section 9.6.4: retention_until MUST be at least T_exp + this. */
export const FF_WITNESS_RETENTION_MARGIN_BLOCKS = 144;
/** Appendix F.2: the fixed header, 235 bytes. */
export const FF_WITNESS_RECORD_HEADER_LEN =
	1 + 1 + 32 + 32 + 2 + 32 + 32 + 33 + 33 + 4 + 1 + 32;
/** Appendix F.2: the plaintext body, 142 bytes. */
export const FF_WITNESS_BODY_LEN = 32 + 2 + 32 + 32 + 8 + 4 + 4 + 8 + 8 + 4 + 8;
/** Record flags bit 0 (section 9.6.5). */
export const FF_WITNESS_FLAG_UNBARRIERED = 0x01;

// ---------------------------------------------------------------------------
// Objects
// ---------------------------------------------------------------------------

/** Section 9.6.4: what R gives a witness at provisioning. */
export interface IFforWitnessManifest {
	version: number;
	profile: number;
	mailboxId: Buffer;
	tSetup: Buffer;
	hCommit: Buffer;
	epochStartHeight: number;
	hAct: Buffer;
	fetchPubkey: Buffer;
	encPubkey: Buffer;
	retentionUntil: number;
	minReceipts: number;
	/** The whole section 7.5.3 book. */
	book: Buffer;
	/** Compact ECDSA under fetch_pubkey over the manifest digest. */
	signature: Buffer;
}

/** Appendix F.2: the signed, plaintext header of a record. */
export interface IFforWitnessRecordHeader {
	version: number;
	profile: number;
	mailboxId: Buffer;
	recordId: Buffer;
	k: number;
	hAct: Buffer;
	termsHash: Buffer;
	witnessNodeId: Buffer;
	encPubkey: Buffer;
	recordedHeight: number;
	flags: number;
	ciphertextHash: Buffer;
}

/** Appendix F.2: one record as stored and served. */
export interface IFforWitnessRecord {
	header: IFforWitnessRecordHeader;
	witnessSig: Buffer;
	ciphertext: Buffer;
	receipts: Buffer[];
}

/** Appendix F.2: the body, encrypted to enc_pubkey. */
export interface IFforWitnessBody {
	epochId: Buffer;
	k: number;
	t: Buffer;
	hK: Buffer;
	dK: bigint;
	tExp: number;
	d: number;
	amountInMsat: bigint;
	amountOutMsat: bigint;
	outgoingCltv: number;
	observedUnixTime: bigint;
}

/**
 * R's side of one witness (section 9.6.4 "R MUST persist, before going
 * offline"): the mailbox, the fetch and encryption keys, and whether the
 * witness acknowledged. Lives on the epoch record.
 */
export interface IFforWitnessProvision {
	witnessNodeId: Buffer;
	mailboxId: Buffer;
	fetchPrivkey: Buffer;
	encPrivkey: Buffer;
	retentionUntil: number;
	minReceipts: number;
	/** The manifest bytes as sent, signature included (re-provisioning). */
	manifestWire: Buffer;
	/** Unix ms of the ff_witness_ack, or null while owed. */
	ackedAt: number | null;
}

// Wire messages (Appendix F.1).

export interface IFforWitnessProvisionMessage {
	requestId: Buffer;
	manifest: IFforWitnessManifest;
}

export interface IFforWitnessAckMessage {
	requestId: Buffer;
	ok: boolean;
	witnessNodeId?: Buffer;
	retentionUntil?: number;
	error?: string;
}

export interface IFforWitnessFetchMessage {
	requestId: Buffer;
	mailboxId: Buffer;
	nonce: Buffer;
	signature: Buffer;
	/** The trailing TLV stream as it came off the wire; the signature covers it. */
	tlv: Buffer;
	/** F.1 paging: only records with k > after_k are wanted. */
	afterK?: number;
}

export interface IFforWitnessFetchRespMessage {
	requestId: Buffer;
	ok: boolean;
	records: IFforWitnessRecord[];
	error?: string;
	/** F.1 paging: present while records with k > next_after_k remain. */
	nextAfterK?: number;
}

export interface IFforWitnessCloseMessage {
	requestId: Buffer;
	mailboxId: Buffer;
	hAct: Buffer;
	numSlots: number;
	/** ceil(K/8) bytes, bit k-1 = slot k (LSB first within a byte). */
	settled: Buffer;
	nonce: Buffer;
	signature: Buffer;
}

export interface IFforWitnessCloseAckMessage {
	requestId: Buffer;
	ok: boolean;
	numRecordsHeld: number;
}
