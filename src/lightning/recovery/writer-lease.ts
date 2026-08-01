/**
 * Writer leases and split-brain fencing (docs/RECOVERY-PROTOCOL.md 5.6,
 * Phase 5).
 *
 * Every running instance writes under a lease: an epoch number, the fresh
 * random writer key that epoch is bound to, and the guardian certificates
 * proving the epoch was granted. The lease lives in recovery_meta beside
 * the journal's own state, because the journal stamps every frame with
 * `writerEpoch` and the two must never disagree.
 *
 * The rules this module exists to keep, in the order they matter:
 *
 * - Writer keys are FRESH RANDOM per epoch, never seed-derived (wire 1.2):
 *   a superseded device's writer key must die with it, and a stolen seed
 *   must not be able to forge records for old epochs.
 * - A lease is ONE atomic artifact. It is stored as a single versioned
 *   blob written in the same transaction as the journal's epoch key, so no
 *   crash can leave a new epoch beside an old key, or an epoch with no key
 *   material at all.
 * - Confirmation is identity-bound and never inherited. A confirmation
 *   records that a quorum acknowledged THIS (epoch, writerPublicKey);
 *   replacing the lease clears it, and confirming names the pair it
 *   expects, so a late callback cannot bless whatever lease is current.
 * - Loading FAILS CLOSED. A partial, malformed, or self-inconsistent lease
 *   throws rather than reading as "absent", because absent means "register
 *   fresh" and that is the one conclusion corruption must never produce.
 * - The private half is written only into storage that can protect it at
 *   rest, and never leaves the device.
 */

import { randomBytes } from 'crypto';
import * as ecc from '@bitcoinerlab/secp256k1';
import { IStorageBackend } from '../storage/types';
import {
	GuardianState,
	acquireTranscriptHash,
	signTranscript,
	xOnlyFromSecret
} from './guardian-wire';
import { IGuardianTakeoverCertificate } from './guardian';
import { JOURNAL_META_KEYS } from './journal';

/** The single lease blob; the journal owns the epoch key it rides with. */
const META_WRITER_LEASE = 'writer_lease_v1';

export const LEASE_META_KEYS = {
	writerEpoch: JOURNAL_META_KEYS.writerEpoch,
	lease: META_WRITER_LEASE
} as const;

const U64_MAX = 0xffffffffffffffffn;

/**
 * The stored lease is unreadable, incomplete, or self-inconsistent. Callers
 * must treat this as "ownership unprovable" and hold the node in quarantine
 * (spec 5.6, 5.7); it is NEVER equivalent to having no lease.
 */
export class CorruptWriterLeaseError extends Error {
	constructor(message: string) {
		super(`writer lease is corrupt: ${message}`);
		this.name = 'CorruptWriterLeaseError';
	}
}

export interface IWriterLease {
	epoch: bigint;
	/** 32-byte x-only public half; the epoch is bound to THIS key. */
	writerPublicKey: Buffer;
	/**
	 * Quorum attestation that this writer owns this epoch. Empty for the
	 * genesis lease established by REGISTER_NODE, which is authorized by the
	 * root-signed registration itself rather than by takeover certificates.
	 */
	guardianCertificates: IGuardianTakeoverCertificate[];
	/**
	 * Unix ms of the last quorum ownership confirmation OF THIS EXACT
	 * (epoch, writerPublicKey). Null means never confirmed under this lease.
	 */
	confirmedAt: bigint | null;
}

/** A lease plus the private half, for signing. Never leaves the device. */
export interface IWriterLeaseKeys extends IWriterLease {
	writerSecret: Buffer;
}

/** The identity a confirmation must name to be accepted. */
export interface IWriterLeaseIdentity {
	epoch: bigint;
	writerPublicKey: Buffer;
}

/** Absent is a fact; corruption throws rather than masquerading as absent. */
export type WriterLeaseLoad =
	| { state: 'absent' }
	| { state: 'present'; lease: IWriterLeaseKeys };

export interface IWriterLeasePersistOptions {
	/**
	 * Persist the signing secret into a backend that cannot guarantee
	 * encryption at rest. Off by default and meant only for deployments
	 * where the operator protects the database by other means (full-disk
	 * encryption, a hardware-backed volume); it is recorded here so the
	 * decision is explicit rather than accidental.
	 */
	allowUnencryptedSecrets?: boolean;
}

export function leaseStorageSupported(storage: IStorageBackend): boolean {
	return (
		typeof storage.getRecoveryMeta === 'function' &&
		typeof storage.setRecoveryMeta === 'function' &&
		typeof storage.transaction === 'function'
	);
}

function requireLeaseStorage(storage: IStorageBackend): void {
	if (!leaseStorageSupported(storage)) {
		throw new Error('Storage backend does not support writer leases');
	}
}

/** A fresh random writer keypair (wire 1.2). */
export function generateWriterKey(): { secret: Buffer; publicKey: Buffer } {
	for (;;) {
		const secret = randomBytes(32);
		if (!ecc.isPrivate(secret)) continue;
		return { secret, publicKey: xOnlyFromSecret(secret) };
	}
}

// ─────────────── encoding ───────────────

interface IEncodedState {
	recoveryId: string;
	lease: { epoch: string; writerPublicKey: string };
	origin: { firstSequence: string; previousHash: string };
	logHead: {
		sequence: string;
		frameHash: string;
		ciphertextHash: string;
		recordEpoch: string;
	};
}

interface IEncodedCertificate {
	protocolVersion: number;
	guardianSetId: string;
	guardianId: string;
	supersededState: IEncodedState;
	newEpoch: string;
	newWriterPublicKey: string;
	issuedAt: string;
	signature: string;
}

interface IPersistedWriterLeaseV1 {
	version: 1;
	epoch: string;
	writerSecret: string;
	writerPublicKey: string;
	guardianCertificates: IEncodedCertificate[];
	confirmedAt: string | null;
}

function encodeState(state: GuardianState): IEncodedState {
	return {
		recoveryId: state.recoveryId.toString('hex'),
		lease: {
			epoch: state.lease.epoch.toString(),
			writerPublicKey: state.lease.writerPublicKey.toString('hex')
		},
		origin: {
			firstSequence: state.origin.firstSequence.toString(),
			previousHash: state.origin.previousHash.toString('hex')
		},
		logHead: {
			sequence: state.logHead.sequence.toString(),
			frameHash: state.logHead.frameHash.toString('hex'),
			ciphertextHash: state.logHead.ciphertextHash.toString('hex'),
			recordEpoch: state.logHead.recordEpoch.toString()
		}
	};
}

function encodeWriterLease(lease: IWriterLeaseKeys): string {
	const payload: IPersistedWriterLeaseV1 = {
		version: 1,
		epoch: lease.epoch.toString(),
		writerSecret: lease.writerSecret.toString('hex'),
		writerPublicKey: lease.writerPublicKey.toString('hex'),
		guardianCertificates: lease.guardianCertificates.map((cert) => ({
			protocolVersion: cert.protocolVersion,
			guardianSetId: cert.guardianSetId.toString('hex'),
			guardianId: cert.guardianId.toString('hex'),
			supersededState: encodeState(cert.supersededState),
			newEpoch: cert.newEpoch.toString(),
			newWriterPublicKey: cert.newWriterPublicKey.toString('hex'),
			issuedAt: cert.issuedAt.toString(),
			signature: cert.signature.toString('hex')
		})),
		confirmedAt:
			lease.confirmedAt === null ? null : lease.confirmedAt.toString()
	};
	return JSON.stringify(payload);
}

// ─────────────── decoding, strictly ───────────────

function decodeHex(value: unknown, bytes: number, field: string): Buffer {
	if (typeof value !== 'string' || value.length !== bytes * 2) {
		throw new CorruptWriterLeaseError(`${field} is not ${bytes} hex bytes`);
	}
	if (!/^[0-9a-f]*$/i.test(value)) {
		throw new CorruptWriterLeaseError(`${field} is not hexadecimal`);
	}
	const buf = Buffer.from(value, 'hex');
	if (buf.length !== bytes) {
		throw new CorruptWriterLeaseError(`${field} is not ${bytes} hex bytes`);
	}
	return buf;
}

function decodeU64(value: unknown, field: string, min = 0n): bigint {
	if (typeof value !== 'string' || !/^\d+$/.test(value)) {
		throw new CorruptWriterLeaseError(`${field} is not a u64 string`);
	}
	const parsed = BigInt(value);
	if (parsed < min || parsed > U64_MAX) {
		throw new CorruptWriterLeaseError(`${field} is outside its allowed range`);
	}
	return parsed;
}

function decodeState(raw: unknown, field: string): GuardianState {
	if (typeof raw !== 'object' || raw === null) {
		throw new CorruptWriterLeaseError(`${field} is not an object`);
	}
	const state = raw as IEncodedState;
	if (
		typeof state.lease !== 'object' ||
		state.lease === null ||
		typeof state.origin !== 'object' ||
		state.origin === null ||
		typeof state.logHead !== 'object' ||
		state.logHead === null
	) {
		throw new CorruptWriterLeaseError(`${field} is missing its parts`);
	}
	return {
		recoveryId: decodeHex(state.recoveryId, 32, `${field}.recoveryId`),
		lease: {
			epoch: decodeU64(state.lease.epoch, `${field}.lease.epoch`, 1n),
			writerPublicKey: decodeHex(
				state.lease.writerPublicKey,
				32,
				`${field}.lease.writerPublicKey`
			)
		},
		origin: {
			firstSequence: decodeU64(
				state.origin.firstSequence,
				`${field}.origin.firstSequence`,
				1n
			),
			previousHash: decodeHex(
				state.origin.previousHash,
				32,
				`${field}.origin.previousHash`
			)
		},
		logHead: {
			sequence: decodeU64(state.logHead.sequence, `${field}.logHead.sequence`),
			frameHash: decodeHex(
				state.logHead.frameHash,
				32,
				`${field}.logHead.frameHash`
			),
			ciphertextHash: decodeHex(
				state.logHead.ciphertextHash,
				32,
				`${field}.logHead.ciphertextHash`
			),
			recordEpoch: decodeU64(
				state.logHead.recordEpoch,
				`${field}.logHead.recordEpoch`
			)
		}
	};
}

function decodeCertificate(
	raw: unknown,
	index: number
): IGuardianTakeoverCertificate {
	if (typeof raw !== 'object' || raw === null) {
		throw new CorruptWriterLeaseError(`certificate ${index} is not an object`);
	}
	const cert = raw as IEncodedCertificate;
	if (!Number.isInteger(cert.protocolVersion) || cert.protocolVersion < 1) {
		throw new CorruptWriterLeaseError(
			`certificate ${index} has no protocol version`
		);
	}
	return {
		protocolVersion: cert.protocolVersion,
		guardianSetId: decodeHex(
			cert.guardianSetId,
			32,
			`certificate ${index} guardianSetId`
		),
		guardianId: decodeHex(
			cert.guardianId,
			32,
			`certificate ${index} guardianId`
		),
		supersededState: decodeState(
			cert.supersededState,
			`certificate ${index} supersededState`
		),
		newEpoch: decodeU64(cert.newEpoch, `certificate ${index} newEpoch`, 1n),
		newWriterPublicKey: decodeHex(
			cert.newWriterPublicKey,
			32,
			`certificate ${index} newWriterPublicKey`
		),
		issuedAt: decodeU64(cert.issuedAt, `certificate ${index} issuedAt`),
		signature: decodeHex(cert.signature, 64, `certificate ${index} signature`)
	};
}

/**
 * Everything a lease must satisfy to be usable, checked on the way in AND
 * on the way out: the key pair agrees with itself, the epoch is a real
 * protocol epoch, and every certificate speaks about THIS lease. Quorum
 * sufficiency is not judged here (it needs the configured guardian set);
 * that belongs to the guardian integration layer.
 */
function assertConsistent(
	lease: IWriterLeaseKeys,
	fail: (m: string) => Error
): void {
	if (lease.epoch < 1n || lease.epoch > U64_MAX) {
		throw fail('epoch is outside its allowed range');
	}
	if (lease.writerSecret.length !== 32 || !ecc.isPrivate(lease.writerSecret)) {
		throw fail('writer secret is not a valid secp256k1 scalar');
	}
	if (lease.writerPublicKey.length !== 32) {
		throw fail('writer public key is not 32 bytes');
	}
	if (!xOnlyFromSecret(lease.writerSecret).equals(lease.writerPublicKey)) {
		throw fail('writer public key does not belong to the writer secret');
	}
	if (lease.confirmedAt !== null && lease.confirmedAt < 0n) {
		throw fail('confirmedAt is negative');
	}
	for (const [index, cert] of lease.guardianCertificates.entries()) {
		if (cert.newEpoch !== lease.epoch) {
			throw fail(`certificate ${index} grants a different epoch`);
		}
		if (!cert.newWriterPublicKey.equals(lease.writerPublicKey)) {
			throw fail(`certificate ${index} grants a different writer key`);
		}
	}
}

// ─────────────── persistence ───────────────

/**
 * Read the persisted lease. `absent` means this installation has never held
 * one (guardians disabled, or enabled but not yet registered). Anything
 * present but unreadable throws: absent authorizes a fresh registration,
 * and corruption must never be allowed to authorize that.
 */
export function loadWriterLease(storage: IStorageBackend): WriterLeaseLoad {
	if (!leaseStorageSupported(storage)) return { state: 'absent' };
	const raw = storage.getRecoveryMeta!(META_WRITER_LEASE);
	const epochRaw = storage.getRecoveryMeta!(JOURNAL_META_KEYS.writerEpoch);
	if (raw == null) {
		// The journal's default epoch (1, with no lease) is ordinary: the
		// journal may run without guardians. An epoch ABOVE the default with
		// no lease means key material was lost, which is not absence.
		if (epochRaw != null && BigInt(epochRaw) > 1n) {
			throw new CorruptWriterLeaseError(
				`journal epoch ${epochRaw} has no lease; writer key material is missing`
			);
		}
		return { state: 'absent' };
	}

	let parsed: IPersistedWriterLeaseV1;
	try {
		parsed = JSON.parse(raw) as IPersistedWriterLeaseV1;
	} catch {
		throw new CorruptWriterLeaseError('stored blob is not valid JSON');
	}
	if (typeof parsed !== 'object' || parsed === null) {
		throw new CorruptWriterLeaseError('stored blob is not an object');
	}
	if (parsed.version !== 1) {
		throw new CorruptWriterLeaseError(
			`unsupported stored lease version ${String(parsed.version)}`
		);
	}
	if (!Array.isArray(parsed.guardianCertificates)) {
		throw new CorruptWriterLeaseError('certificates are not an array');
	}
	const lease: IWriterLeaseKeys = {
		epoch: decodeU64(parsed.epoch, 'epoch', 1n),
		writerSecret: decodeHex(parsed.writerSecret, 32, 'writerSecret'),
		writerPublicKey: decodeHex(parsed.writerPublicKey, 32, 'writerPublicKey'),
		guardianCertificates: parsed.guardianCertificates.map((cert, index) =>
			decodeCertificate(cert, index)
		),
		confirmedAt:
			parsed.confirmedAt === null || parsed.confirmedAt === undefined
				? null
				: decodeU64(parsed.confirmedAt, 'confirmedAt')
	};
	assertConsistent(lease, (m) => new CorruptWriterLeaseError(m));
	// The journal stamps frames from ITS key; a disagreement means one of the
	// two writes was lost and the epoch a frame would carry is unprovable.
	if (epochRaw == null || BigInt(epochRaw) !== lease.epoch) {
		throw new CorruptWriterLeaseError(
			`journal epoch ${String(epochRaw)} disagrees with lease epoch ${
				lease.epoch
			}`
		);
	}
	return { state: 'present', lease };
}

/**
 * Replace the lease atomically. The blob and the journal's epoch key are
 * written in ONE transaction, so a crash leaves either the complete old
 * lease or the complete new one. Confirmation is part of the blob, so a
 * replacement never inherits the previous lease's confirmation.
 */
export function saveWriterLease(
	storage: IStorageBackend,
	lease: IWriterLeaseKeys,
	options: IWriterLeasePersistOptions = {}
): void {
	requireLeaseStorage(storage);
	assertConsistent(lease, (m) => new Error(`refusing to persist lease: ${m}`));
	if (
		!options.allowUnencryptedSecrets &&
		storage.secretsEncryptedAtRest?.() !== true
	) {
		throw new Error(
			'refusing to persist the writer signing key into storage that cannot ' +
				'guarantee encryption at rest; configure a storage encryption key, ' +
				'or set allowUnencryptedSecrets when the database is protected by ' +
				'other means'
		);
	}
	const encoded = encodeWriterLease(lease);
	storage.transaction(() => {
		storage.setRecoveryMeta!(META_WRITER_LEASE, encoded);
		storage.setRecoveryMeta!(
			JOURNAL_META_KEYS.writerEpoch,
			lease.epoch.toString()
		);
	});
}

/**
 * Record a quorum ownership confirmation (spec 5.6 startup rule), bound to
 * the identity it was obtained for. A confirmation that names a superseded
 * epoch or a different writer key is REJECTED rather than applied to
 * whatever lease happens to be current: a late callback must never bless a
 * lease nobody confirmed.
 */
export function markLeaseConfirmed(
	storage: IStorageBackend,
	expected: IWriterLeaseIdentity,
	confirmedAt: bigint
): void {
	requireLeaseStorage(storage);
	storage.transaction(() => {
		const loaded = loadWriterLease(storage);
		if (loaded.state !== 'present') {
			throw new Error('cannot confirm ownership: no writer lease is stored');
		}
		const current = loaded.lease;
		if (
			current.epoch !== expected.epoch ||
			!current.writerPublicKey.equals(expected.writerPublicKey)
		) {
			throw new Error(
				`ownership confirmation names epoch ${expected.epoch}, but the stored ` +
					`lease is epoch ${current.epoch}; refusing to confirm a lease that ` +
					'was not the one confirmed'
			);
		}
		storage.setRecoveryMeta!(
			META_WRITER_LEASE,
			encodeWriterLease({ ...current, confirmedAt })
		);
	});
}

/** The public view of a lease, safe to log or emit: a deep copy. */
export function publicLease(lease: IWriterLeaseKeys): IWriterLease {
	return {
		epoch: lease.epoch,
		writerPublicKey: Buffer.from(lease.writerPublicKey),
		guardianCertificates: lease.guardianCertificates.map((cert) => ({
			protocolVersion: cert.protocolVersion,
			guardianSetId: Buffer.from(cert.guardianSetId),
			guardianId: Buffer.from(cert.guardianId),
			supersededState: {
				recoveryId: Buffer.from(cert.supersededState.recoveryId),
				lease: {
					epoch: cert.supersededState.lease.epoch,
					writerPublicKey: Buffer.from(
						cert.supersededState.lease.writerPublicKey
					)
				},
				origin: {
					firstSequence: cert.supersededState.origin.firstSequence,
					previousHash: Buffer.from(cert.supersededState.origin.previousHash)
				},
				logHead: {
					sequence: cert.supersededState.logHead.sequence,
					frameHash: Buffer.from(cert.supersededState.logHead.frameHash),
					ciphertextHash: Buffer.from(
						cert.supersededState.logHead.ciphertextHash
					),
					recordEpoch: cert.supersededState.logHead.recordEpoch
				}
			},
			newEpoch: cert.newEpoch,
			newWriterPublicKey: Buffer.from(cert.newWriterPublicKey),
			issuedAt: cert.issuedAt,
			signature: Buffer.from(cert.signature)
		})),
		confirmedAt: lease.confirmedAt
	};
}

/**
 * The dual signature an ACQUIRE_EPOCH carries (wire 4.2): the recovery root
 * authorizes the takeover, the new writer key proves possession. Both sign
 * the same canonical transcript.
 */
export function signAcquisition(
	guardianSetId: Buffer,
	expectedState: GuardianState,
	newEpoch: bigint,
	newWriter: { secret: Buffer; publicKey: Buffer },
	rootSecret: Buffer
): { rootSignature: Buffer; newWriterSignature: Buffer } {
	// A mismatched pair is not an authorization bypass (the guardian rejects
	// the signature), but failing here names the real problem.
	if (
		newWriter.secret.length !== 32 ||
		!ecc.isPrivate(newWriter.secret) ||
		!xOnlyFromSecret(newWriter.secret).equals(newWriter.publicKey)
	) {
		throw new Error(
			'new writer public key does not belong to the new writer secret'
		);
	}
	const hash = acquireTranscriptHash(
		guardianSetId,
		expectedState,
		newEpoch,
		newWriter.publicKey
	);
	return {
		rootSignature: signTranscript(hash, rootSecret),
		newWriterSignature: signTranscript(hash, newWriter.secret)
	};
}
