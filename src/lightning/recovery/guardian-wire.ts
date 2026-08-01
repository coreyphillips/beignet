/**
 * Guardian wire crypto: canonical transcripts, domain-separated tagged
 * hashes, BIP340 signatures, the recovery root, guardian_set_id, and the
 * deterministic frame IV (docs/RECOVERY-GUARDIAN-WIRE.md sections 1, 3, 4).
 *
 * Everything signed in the guardian protocol is signed over a CANONICAL
 * fixed-width transcript hashed with a per-object BIP340 tag; protobuf or
 * JSON envelope bytes are never signed. All public keys here are 32-byte
 * x-only. Where this module and the wire specification disagree, the wire
 * specification wins and this module has a bug.
 */

import { createHash } from 'crypto';
import { hkdfSync } from 'crypto';
import { schnorrSign, schnorrVerify } from '../offer/schnorr';
import * as ecc from '@bitcoinerlab/secp256k1';

/** secp256k1 group order. */
const CURVE_ORDER = BigInt(
	'0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141'
);

export const GUARDIAN_PROTOCOL_VERSION = 1;

/** The only profile in protocol v1 (wire spec section 4). */
export const CRASH_V1_PROFILE = { profileId: 1, required: 2, total: 3 };

const ZERO32 = Buffer.alloc(32);

// ─────────────── tagged hashing ───────────────

/** BIP340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg). */
export function guardianTaggedHash(tag: string, message: Buffer): Buffer {
	const tagHash = createHash('sha256').update(tag, 'utf8').digest();
	return createHash('sha256')
		.update(tagHash)
		.update(tagHash)
		.update(message)
		.digest();
}

function u16(value: number): Buffer {
	const b = Buffer.alloc(2);
	b.writeUInt16BE(value);
	return b;
}

function u64(value: bigint): Buffer {
	const b = Buffer.alloc(8);
	b.writeBigUInt64BE(value);
	return b;
}

function expect32(name: string, buf: Buffer): Buffer {
	if (buf.length !== 32) {
		throw new Error(`${name} must be 32 bytes, got ${buf.length}`);
	}
	return buf;
}

// ─────────────── recovery root ───────────────

/**
 * The dedicated recovery root (wire spec 1.1): HKDF-SHA256 with empty salt
 * over the node secret, reduced to a valid nonzero scalar exactly as the
 * spec fixes it (interpret as big-endian, mod n-1, plus 1). Its x-only
 * public key IS the guardian namespace (recovery_id). The root authorizes
 * registration and epoch acquisition only; it never signs records.
 */
export function deriveRecoveryRoot(nodeSecret: Buffer): {
	rootSecret: Buffer;
	recoveryId: Buffer;
} {
	const okm = Buffer.from(
		hkdfSync(
			'sha256',
			nodeSecret,
			Buffer.alloc(0),
			'beignet-recovery-root-v1',
			32
		)
	);
	let scalar = 0n;
	for (const byte of okm) scalar = (scalar << 8n) | BigInt(byte);
	scalar = (scalar % (CURVE_ORDER - 1n)) + 1n;
	const rootSecret = Buffer.alloc(32);
	for (let i = 31; i >= 0; i--) {
		rootSecret[i] = Number(scalar & 0xffn);
		scalar >>= 8n;
	}
	const pub = ecc.pointFromScalar(rootSecret, true);
	if (!pub) throw new Error('recovery root scalar produced no point');
	return { rootSecret, recoveryId: Buffer.from(pub.subarray(1)) };
}

/** x-only public key for a fresh random writer or guardian secret. */
export function xOnlyFromSecret(secret: Buffer): Buffer {
	const pub = ecc.pointFromScalar(secret, true);
	if (!pub) throw new Error('invalid secp256k1 secret');
	return Buffer.from(pub.subarray(1));
}

// ─────────────── guardian_set_id ───────────────

export interface IGuardianSetProfile {
	profileId: number;
	required: number;
	total: number;
	/** 32-byte x-only guardian signing keys. */
	guardianIds: Buffer[];
}

/**
 * guardian_set_id (wire spec section 4): a tagged hash committing to the
 * profile, threshold, and the SORTED member set. crash-v1 is the only
 * profile protocol v1 accepts; any other tuple is rejected loudly.
 */
export function computeGuardianSetId(profile: IGuardianSetProfile): Buffer {
	if (
		profile.profileId !== CRASH_V1_PROFILE.profileId ||
		profile.required !== CRASH_V1_PROFILE.required ||
		profile.total !== CRASH_V1_PROFILE.total
	) {
		throw new Error(
			`unsupported guardian profile: only crash-v1 (1, 2-of-3) exists in protocol v1`
		);
	}
	if (profile.guardianIds.length !== profile.total) {
		throw new Error(
			`guardian set carries ${profile.guardianIds.length} members, profile requires ${profile.total}`
		);
	}
	const sorted = [...profile.guardianIds]
		.map((id) => expect32('guardianId', id))
		.sort(Buffer.compare);
	for (let i = 1; i < sorted.length; i++) {
		if (sorted[i - 1].equals(sorted[i])) {
			throw new Error('guardian set members must be distinct');
		}
	}
	return guardianTaggedHash(
		'beignet/recovery/guardian-set/v1',
		Buffer.concat([
			u16(profile.profileId),
			u16(profile.required),
			u16(profile.total),
			...sorted
		])
	);
}

// ─────────────── state shapes and canonical byte forms ───────────────

export interface WriterLease {
	epoch: bigint;
	/** 32-byte x-only, fresh random per epoch, never seed-derived. */
	writerPublicKey: Buffer;
}

export interface ChainOrigin {
	/** Fresh node: 1. Existing node: the retained journal base position. */
	firstSequence: bigint;
	/** 32 zero bytes for a fresh node. */
	previousHash: Buffer;
}

export interface LogHead {
	sequence: bigint;
	frameHash: Buffer;
	ciphertextHash: Buffer;
	recordEpoch: bigint;
}

export interface GuardianState {
	recoveryId: Buffer;
	lease: WriterLease;
	origin: ChainOrigin;
	logHead: LogHead;
}

/** Genesis log head: "no records stored yet" (wire spec 4.1). */
export function genesisLogHead(): LogHead {
	return {
		sequence: 0n,
		frameHash: Buffer.from(ZERO32),
		ciphertextHash: Buffer.from(ZERO32),
		recordEpoch: 0n
	};
}

export function isGenesisLogHead(head: LogHead): boolean {
	return (
		head.sequence === 0n &&
		head.recordEpoch === 0n &&
		head.frameHash.equals(ZERO32) &&
		head.ciphertextHash.equals(ZERO32)
	);
}

function leaseBytes(lease: WriterLease): Buffer {
	return Buffer.concat([
		u64(lease.epoch),
		expect32('writerPublicKey', lease.writerPublicKey)
	]);
}

function originBytes(origin: ChainOrigin): Buffer {
	return Buffer.concat([
		u64(origin.firstSequence),
		expect32('origin.previousHash', origin.previousHash)
	]);
}

function logHeadBytes(head: LogHead): Buffer {
	return Buffer.concat([
		u64(head.sequence),
		expect32('logHead.frameHash', head.frameHash),
		expect32('logHead.ciphertextHash', head.ciphertextHash),
		u64(head.recordEpoch)
	]);
}

/** STATE = recovery_id(32) || LEASE || ORIGIN || LOGHEAD (wire spec 4.1). */
export function stateBytes(state: GuardianState): Buffer {
	return Buffer.concat([
		expect32('recoveryId', state.recoveryId),
		leaseBytes(state.lease),
		originBytes(state.origin),
		logHeadBytes(state.logHead)
	]);
}

export function statesEqual(a: GuardianState, b: GuardianState): boolean {
	return stateBytes(a).equals(stateBytes(b));
}

function prefixBytes(guardianSetId: Buffer): Buffer {
	return Buffer.concat([
		u16(GUARDIAN_PROTOCOL_VERSION),
		expect32('guardianSetId', guardianSetId)
	]);
}

// ─────────────── transcripts (wire spec 4.2) ───────────────

/** REGISTER: PREFIX || STATE, signed by the recovery root. */
export function registerTranscriptHash(
	guardianSetId: Buffer,
	initialState: GuardianState
): Buffer {
	return guardianTaggedHash(
		'beignet/recovery/register/v1',
		Buffer.concat([prefixBytes(guardianSetId), stateBytes(initialState)])
	);
}

export interface RecordFields {
	recoveryId: Buffer;
	epoch: bigint;
	sequence: bigint;
	previousHash: Buffer;
	frameHash: Buffer;
	/** SHA-256 of the record ciphertext. */
	ciphertextHash: Buffer;
}

/** RECORD: signed by the writer key of lease.epoch. */
export function recordTranscriptHash(
	guardianSetId: Buffer,
	record: RecordFields
): Buffer {
	return guardianTaggedHash(
		'beignet/recovery/record/v1',
		Buffer.concat([
			prefixBytes(guardianSetId),
			expect32('recoveryId', record.recoveryId),
			u64(record.epoch),
			u64(record.sequence),
			expect32('previousHash', record.previousHash),
			expect32('frameHash', record.frameHash),
			expect32('ciphertextHash', record.ciphertextHash)
		])
	);
}

/** RECEIPT: PREFIX || guardianId || STATE || issuedAt, signed by the guardian. */
export function receiptTranscriptHash(
	guardianSetId: Buffer,
	guardianId: Buffer,
	state: GuardianState,
	issuedAt: bigint
): Buffer {
	return guardianTaggedHash(
		'beignet/recovery/receipt/v1',
		Buffer.concat([
			prefixBytes(guardianSetId),
			expect32('guardianId', guardianId),
			stateBytes(state),
			u64(issuedAt)
		])
	);
}

/**
 * ACQUIRE: PREFIX || STATE || newEpoch || newWriterPublicKey. Signed TWICE:
 * by the recovery root (authorizes the takeover) and by the NEW writer key
 * (proves possession).
 */
export function acquireTranscriptHash(
	guardianSetId: Buffer,
	expectedState: GuardianState,
	newEpoch: bigint,
	newWriterPublicKey: Buffer
): Buffer {
	return guardianTaggedHash(
		'beignet/recovery/epoch-request/v1',
		Buffer.concat([
			prefixBytes(guardianSetId),
			stateBytes(expectedState),
			u64(newEpoch),
			expect32('newWriterPublicKey', newWriterPublicKey)
		])
	);
}

/** TAKEOVER: signed by the guardian over the superseded final state. */
export function takeoverTranscriptHash(
	guardianSetId: Buffer,
	guardianId: Buffer,
	supersededState: GuardianState,
	newEpoch: bigint,
	newWriterPublicKey: Buffer,
	issuedAt: bigint
): Buffer {
	return guardianTaggedHash(
		'beignet/recovery/takeover/v1',
		Buffer.concat([
			prefixBytes(guardianSetId),
			expect32('guardianId', guardianId),
			stateBytes(supersededState),
			u64(newEpoch),
			expect32('newWriterPublicKey', newWriterPublicKey),
			u64(issuedAt)
		])
	);
}

// ─────────────── signing wrappers ───────────────

export function signTranscript(hash: Buffer, secret: Buffer): Buffer {
	return schnorrSign(hash, secret);
}

export function verifyTranscript(
	hash: Buffer,
	signature: Buffer,
	xOnlyPublicKey: Buffer
): boolean {
	return schnorrVerify(hash, expect32('publicKey', xOnlyPublicKey), signature);
}

// ─────────────── deterministic frame IV (wire spec 3.2) ───────────────

/**
 * The 96-bit AES-GCM IV for a journal frame, deterministic from revision 4
 * on: first 12 bytes of a tagged hash over (recovery_id, writerEpoch,
 * sequence, frameHash). recovery_id, NEVER the Lightning node id: every
 * other input plus the IV is visible in a stored record, so a node-id-keyed
 * IV would be an offline linkage oracle. A (key, IV) collision requires the
 * identical plaintext at the identical position, which re-encrypts to the
 * identical ciphertext: harmless. Robust against RNG-state rollback where
 * random IVs are not.
 */
export function deriveFrameIv(
	recoveryId: Buffer,
	writerEpoch: bigint,
	sequence: bigint,
	frameHash: Buffer
): Buffer {
	return guardianTaggedHash(
		'beignet/recovery/aes-gcm-iv/v1',
		Buffer.concat([
			expect32('recoveryId', recoveryId),
			u64(writerEpoch),
			u64(sequence),
			expect32('frameHash', frameHash)
		])
	).subarray(0, 12);
}
