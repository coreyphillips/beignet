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
 * Three rules this module exists to keep:
 *
 * - Writer keys are FRESH RANDOM per epoch, never seed-derived (wire 1.2):
 *   a superseded device's writer key must die with it, and a stolen seed
 *   must not be able to forge records for old epochs.
 * - The private half is stored ONLY under the storage backend's encryption,
 *   like every other secret the node persists, and never leaves the device.
 * - Authority comes from the recovery root, which co-signs every
 *   acquisition (wire 4.2): possession of a fresh key proves possession of
 *   itself, not ownership of the namespace.
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

/** recovery_meta keys owned by the lease (the journal owns the rest). */
const META_WRITER_SECRET = 'lease_writer_secret';
const META_WRITER_PUBLIC = 'lease_writer_public';
const META_LEASE_CERTIFICATES = 'lease_certificates';
const META_LEASE_CONFIRMED_AT = 'lease_confirmed_at';

export const LEASE_META_KEYS = {
	writerEpoch: JOURNAL_META_KEYS.writerEpoch,
	writerSecret: META_WRITER_SECRET,
	writerPublic: META_WRITER_PUBLIC,
	certificates: META_LEASE_CERTIFICATES,
	confirmedAt: META_LEASE_CONFIRMED_AT
} as const;

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
	/** Unix ms of the last successful quorum ownership confirmation. */
	confirmedAt: bigint | null;
}

/** A lease plus the private half, for signing. Never leaves the device. */
export interface IWriterLeaseKeys extends IWriterLease {
	writerSecret: Buffer;
}

export function leaseStorageSupported(storage: IStorageBackend): boolean {
	return (
		typeof storage.getRecoveryMeta === 'function' &&
		typeof storage.setRecoveryMeta === 'function'
	);
}

/** A fresh random writer keypair (wire 1.2). */
export function generateWriterKey(): { secret: Buffer; publicKey: Buffer } {
	for (;;) {
		const secret = randomBytes(32);
		if (!ecc.isPrivate(secret)) continue;
		return { secret, publicKey: xOnlyFromSecret(secret) };
	}
}

function encodeCertificates(
	certificates: IGuardianTakeoverCertificate[]
): string {
	return JSON.stringify(
		certificates.map((cert) => ({
			protocolVersion: cert.protocolVersion,
			guardianSetId: cert.guardianSetId.toString('hex'),
			guardianId: cert.guardianId.toString('hex'),
			supersededState: {
				recoveryId: cert.supersededState.recoveryId.toString('hex'),
				lease: {
					epoch: cert.supersededState.lease.epoch.toString(),
					writerPublicKey:
						cert.supersededState.lease.writerPublicKey.toString('hex')
				},
				origin: {
					firstSequence: cert.supersededState.origin.firstSequence.toString(),
					previousHash: cert.supersededState.origin.previousHash.toString('hex')
				},
				logHead: {
					sequence: cert.supersededState.logHead.sequence.toString(),
					frameHash: cert.supersededState.logHead.frameHash.toString('hex'),
					ciphertextHash:
						cert.supersededState.logHead.ciphertextHash.toString('hex'),
					recordEpoch: cert.supersededState.logHead.recordEpoch.toString()
				}
			},
			newEpoch: cert.newEpoch.toString(),
			newWriterPublicKey: cert.newWriterPublicKey.toString('hex'),
			issuedAt: cert.issuedAt.toString(),
			signature: cert.signature.toString('hex')
		}))
	);
}

interface IEncodedCertificate {
	protocolVersion: number;
	guardianSetId: string;
	guardianId: string;
	supersededState: {
		recoveryId: string;
		lease: { epoch: string; writerPublicKey: string };
		origin: { firstSequence: string; previousHash: string };
		logHead: {
			sequence: string;
			frameHash: string;
			ciphertextHash: string;
			recordEpoch: string;
		};
	};
	newEpoch: string;
	newWriterPublicKey: string;
	issuedAt: string;
	signature: string;
}

function decodeCertificates(raw: string): IGuardianTakeoverCertificate[] {
	const parsed = JSON.parse(raw) as IEncodedCertificate[];
	return parsed.map((cert) => ({
		protocolVersion: cert.protocolVersion,
		guardianSetId: Buffer.from(cert.guardianSetId, 'hex'),
		guardianId: Buffer.from(cert.guardianId, 'hex'),
		supersededState: {
			recoveryId: Buffer.from(cert.supersededState.recoveryId, 'hex'),
			lease: {
				epoch: BigInt(cert.supersededState.lease.epoch),
				writerPublicKey: Buffer.from(
					cert.supersededState.lease.writerPublicKey,
					'hex'
				)
			},
			origin: {
				firstSequence: BigInt(cert.supersededState.origin.firstSequence),
				previousHash: Buffer.from(
					cert.supersededState.origin.previousHash,
					'hex'
				)
			},
			logHead: {
				sequence: BigInt(cert.supersededState.logHead.sequence),
				frameHash: Buffer.from(cert.supersededState.logHead.frameHash, 'hex'),
				ciphertextHash: Buffer.from(
					cert.supersededState.logHead.ciphertextHash,
					'hex'
				),
				recordEpoch: BigInt(cert.supersededState.logHead.recordEpoch)
			}
		},
		newEpoch: BigInt(cert.newEpoch),
		newWriterPublicKey: Buffer.from(cert.newWriterPublicKey, 'hex'),
		issuedAt: BigInt(cert.issuedAt),
		signature: Buffer.from(cert.signature, 'hex')
	}));
}

/**
 * Read the persisted lease. Returns null when this installation has never
 * held one (guardians disabled, or enabled but not yet registered), which
 * is distinct from holding the genesis lease at epoch 1.
 */
export function loadWriterLease(
	storage: IStorageBackend
): IWriterLeaseKeys | null {
	if (!leaseStorageSupported(storage)) return null;
	const secretHex = storage.getRecoveryMeta!(META_WRITER_SECRET);
	const publicHex = storage.getRecoveryMeta!(META_WRITER_PUBLIC);
	const epochRaw = storage.getRecoveryMeta!(JOURNAL_META_KEYS.writerEpoch);
	if (!secretHex || !publicHex || epochRaw == null) return null;
	const certificatesRaw = storage.getRecoveryMeta!(META_LEASE_CERTIFICATES);
	const confirmedRaw = storage.getRecoveryMeta!(META_LEASE_CONFIRMED_AT);
	return {
		epoch: BigInt(epochRaw),
		writerSecret: Buffer.from(secretHex, 'hex'),
		writerPublicKey: Buffer.from(publicHex, 'hex'),
		guardianCertificates: certificatesRaw
			? decodeCertificates(certificatesRaw)
			: [],
		confirmedAt: confirmedRaw == null ? null : BigInt(confirmedRaw)
	};
}

/**
 * Persist a lease. The caller runs this inside a storage transaction when
 * it must commit with other state; the journal's writerEpoch key is written
 * here too, so a frame can never be stamped with an epoch the lease does
 * not claim.
 */
export function saveWriterLease(
	storage: IStorageBackend,
	lease: IWriterLeaseKeys
): void {
	if (!leaseStorageSupported(storage)) {
		throw new Error('Storage backend does not support writer leases');
	}
	storage.setRecoveryMeta!(
		JOURNAL_META_KEYS.writerEpoch,
		lease.epoch.toString()
	);
	storage.setRecoveryMeta!(
		META_WRITER_SECRET,
		lease.writerSecret.toString('hex')
	);
	storage.setRecoveryMeta!(
		META_WRITER_PUBLIC,
		lease.writerPublicKey.toString('hex')
	);
	storage.setRecoveryMeta!(
		META_LEASE_CERTIFICATES,
		encodeCertificates(lease.guardianCertificates)
	);
	if (lease.confirmedAt !== null) {
		storage.setRecoveryMeta!(
			META_LEASE_CONFIRMED_AT,
			lease.confirmedAt.toString()
		);
	}
}

/** Record a successful quorum ownership confirmation (spec 5.6 startup). */
export function markLeaseConfirmed(
	storage: IStorageBackend,
	confirmedAt: bigint
): void {
	if (!leaseStorageSupported(storage)) return;
	storage.setRecoveryMeta!(META_LEASE_CONFIRMED_AT, confirmedAt.toString());
}

/** The public view of a lease, safe to log or emit in events. */
export function publicLease(lease: IWriterLeaseKeys): IWriterLease {
	return {
		epoch: lease.epoch,
		writerPublicKey: Buffer.from(lease.writerPublicKey),
		guardianCertificates: lease.guardianCertificates,
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
