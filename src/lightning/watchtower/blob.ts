/**
 * LND watchtower justice blob (watchtower/blob).
 *
 * The client encrypts a JusticeKit under a key derived from the revoked
 * commitment txid and ships it with a 16-byte breach hint. When the tower sees
 * a transaction whose SHA256(txid)[:16] matches the hint, it derives the same
 * key from the on-chain txid, decrypts the kit, reassembles the penalty
 * transaction, and broadcasts it.
 *
 * Only the version-0 kit (legacy + anchor channels) is implemented here; the
 * to-local revocation branch is identical for both, and it is the fund-critical
 * breach punishment. The version-1 (taproot) kit is not yet produced.
 */

import { createHash, randomBytes } from 'crypto';
import {
	encrypt as xEncrypt,
	decrypt as xDecrypt
} from '../crypto/xchacha20poly1305';

/** blob.Flag / blob.Type values (watchtower/blob/type.go). */
export enum BlobFlag {
	REWARD = 1,
	COMMIT_OUTPUTS = 1 << 1,
	ANCHOR_CHANNEL = 1 << 2,
	TAPROOT_CHANNEL = 1 << 3
}

export enum BlobType {
	/** FlagCommitOutputs. */
	ALTRUIST_COMMIT = BlobFlag.COMMIT_OUTPUTS,
	/** FlagCommitOutputs | FlagAnchorChannel. */
	ALTRUIST_ANCHOR_COMMIT = BlobFlag.COMMIT_OUTPUTS | BlobFlag.ANCHOR_CHANNEL,
	/** FlagCommitOutputs | FlagTaprootChannel. */
	ALTRUIST_TAPROOT_COMMIT = BlobFlag.COMMIT_OUTPUTS | BlobFlag.TAPROOT_CHANNEL
}

/** SHA256(txid), first 16 bytes. */
export const BREACH_HINT_SIZE = 16;
/** chacha20poly1305 XNonce length. */
export const NONCE_SIZE = 24;
/** Poly1305 tag length. */
export const CIPHERTEXT_EXPANSION = 16;
/** Max sweep address (witness program) length the blob can carry. */
export const MAX_SWEEP_ADDR_SIZE = 42;
/** Fixed plaintext size of a version-0 kit. */
export const V0_PLAINTEXT_SIZE = 274;

/**
 * Breach hint = SHA256(txid)[:16]. `txid` MUST be in internal (little-endian,
 * wire/hash) byte order, matching lnd's chainhash.Hash bytes.
 */
export function breachHintFromTxid(txidInternal: Buffer): Buffer {
	if (txidInternal.length !== 32) {
		throw new Error('breach hint: txid must be 32 bytes');
	}
	return createHash('sha256')
		.update(txidInternal)
		.digest()
		.subarray(0, BREACH_HINT_SIZE);
}

/** Breach key = SHA256(txid || txid), used to encrypt/decrypt the blob. */
export function breachKeyFromTxid(txidInternal: Buffer): Buffer {
	if (txidInternal.length !== 32) {
		throw new Error('breach key: txid must be 32 bytes');
	}
	return createHash('sha256')
		.update(txidInternal)
		.update(txidInternal)
		.digest();
}

/** Version-0 justice kit fields (watchtower/blob/justice_kit_packet.go). */
export interface IJusticeKitV0 {
	/** Witness program of the client's sweep output (<= 42 bytes). */
	sweepAddress: Buffer;
	/** 33-byte compressed revocation pubkey. */
	revocationPubKey: Buffer;
	/** 33-byte compressed remote-party delayed pubkey. */
	localDelayPubKey: Buffer;
	/** to_self_delay of the revoked to_local output. */
	csvDelay: number;
	/** 64-byte raw (R||S) signature under revocationPubKey (SIGHASH_ALL). */
	commitToLocalSig: Buffer;
	/** 33-byte to-remote pubkey; blank (33 zero bytes) when absent. */
	commitToRemotePubKey?: Buffer;
	/** 64-byte raw (R||S) to-remote signature; only used when pubkey present. */
	commitToRemoteSig?: Buffer;
}

const EMPTY_33 = Buffer.alloc(33);
const EMPTY_64 = Buffer.alloc(64);

/** Encode a version-0 kit to its constant 274-byte plaintext. */
export function encodeJusticeKitV0(kit: IJusticeKitV0): Buffer {
	if (kit.sweepAddress.length > MAX_SWEEP_ADDR_SIZE) {
		throw new Error('justice kit: sweep address too long');
	}
	if (
		kit.revocationPubKey.length !== 33 ||
		kit.localDelayPubKey.length !== 33
	) {
		throw new Error('justice kit: pubkeys must be 33 bytes');
	}
	if (kit.commitToLocalSig.length !== 64) {
		throw new Error('justice kit: to-local sig must be 64 bytes');
	}
	const out = Buffer.alloc(V0_PLAINTEXT_SIZE);
	let o = 0;
	out.writeUInt8(kit.sweepAddress.length, o);
	o += 1;
	kit.sweepAddress.copy(out, o);
	o += MAX_SWEEP_ADDR_SIZE;
	kit.revocationPubKey.copy(out, o);
	o += 33;
	kit.localDelayPubKey.copy(out, o);
	o += 33;
	out.writeUInt32BE(kit.csvDelay >>> 0, o);
	o += 4;
	kit.commitToLocalSig.copy(out, o);
	o += 64;
	(kit.commitToRemotePubKey ?? EMPTY_33).copy(out, o);
	o += 33;
	(kit.commitToRemoteSig ?? EMPTY_64).copy(out, o);
	return out;
}

/** Decode a version-0 kit from its 274-byte plaintext. */
export function decodeJusticeKitV0(pt: Buffer): IJusticeKitV0 {
	if (pt.length !== V0_PLAINTEXT_SIZE) {
		throw new Error(
			`justice kit: plaintext must be ${V0_PLAINTEXT_SIZE} bytes, got ${pt.length}`
		);
	}
	let o = 0;
	const addrLen = pt.readUInt8(o);
	o += 1;
	if (addrLen > MAX_SWEEP_ADDR_SIZE) {
		throw new Error('justice kit: sweep address too long');
	}
	const sweepAddress = Buffer.from(pt.subarray(o, o + addrLen));
	o += MAX_SWEEP_ADDR_SIZE;
	const revocationPubKey = Buffer.from(pt.subarray(o, o + 33));
	o += 33;
	const localDelayPubKey = Buffer.from(pt.subarray(o, o + 33));
	o += 33;
	const csvDelay = pt.readUInt32BE(o);
	o += 4;
	const commitToLocalSig = Buffer.from(pt.subarray(o, o + 64));
	o += 64;
	const remotePub = Buffer.from(pt.subarray(o, o + 33));
	o += 33;
	const remoteSig = Buffer.from(pt.subarray(o, o + 64));
	const kit: IJusticeKitV0 = {
		sweepAddress,
		revocationPubKey,
		localDelayPubKey,
		csvDelay,
		commitToLocalSig
	};
	// A blank (all-zero / non-point) to-remote pubkey means no to-remote output.
	if (isCompressedPoint(remotePub)) {
		kit.commitToRemotePubKey = remotePub;
		kit.commitToRemoteSig = remoteSig;
	}
	return kit;
}

function isCompressedPoint(b: Buffer): boolean {
	return b.length === 33 && (b[0] === 0x02 || b[0] === 0x03);
}

/**
 * Encrypt a version-0 kit under the breach key. Layout: 24-byte nonce ||
 * ciphertext || 16-byte MAC (chacha20poly1305 XNonce), matching blob.Encrypt.
 */
export function encryptJusticeKitV0(kit: IJusticeKitV0, key: Buffer): Buffer {
	const nonce = randomNonce();
	const ct = xEncrypt(key, nonce, encodeJusticeKitV0(kit));
	return Buffer.concat([nonce, ct]);
}

/** Decrypt a version-0 blob produced by encryptJusticeKitV0 / blob.Encrypt. */
export function decryptJusticeKitV0(blob: Buffer, key: Buffer): IJusticeKitV0 {
	if (blob.length < NONCE_SIZE + CIPHERTEXT_EXPANSION) {
		throw new Error('justice blob: ciphertext too small');
	}
	const nonce = blob.subarray(0, NONCE_SIZE);
	const ct = blob.subarray(NONCE_SIZE);
	return decodeJusticeKitV0(xDecrypt(key, nonce, ct));
}

function randomNonce(): Buffer {
	return randomBytes(NONCE_SIZE);
}
