/**
 * Static channel backup (SCB): a portable, versioned, encrypted blob carrying
 * the minimum per-channel data needed to recover funds without the full
 * database. Recovery (follow-up work) uses the fell-behind DLP path: reconnect
 * to the peer with intentionally stale state, the peer force-closes, and the
 * chain monitor sweeps our to_remote output. Each entry therefore carries the
 * peer identity/addresses, the funding outpoint, and the key material locator
 * (channelKeyIndex) that flow needs.
 *
 * This covers every channel type we run, INCLUDING simple taproot channels:
 * the to_remote output always pays our STATIC payment basepoint
 * (static_remotekey P2WPKH, anchor CSV-1 P2WSH, taproot NUMS+1-CSV leaf), and
 * that basepoint's secret is re-derived from the seed via channelKeyIndex (or
 * the node-level paymentBasepointSecret for legacy null-index channels) - so
 * v1 entries carry everything a taproot recovery sweep needs and no format
 * bump is required. channelType (hex) tells the restored state which to_remote
 * variant to look for.
 *
 * Encoding: 'beignet-scb-v1:' + base64(iv || authTag || ciphertext) where the
 * ciphertext is the JSON backup encrypted with AES-256-GCM under
 * HKDF-SHA256(seed, salt empty, info 'beignet-scb-v1').
 */

import {
	hkdfKey,
	encryptWithPrefix,
	decryptWithPrefix
} from '../storage/encryption';

export const SCB_PREFIX = 'beignet-scb-v1:';
export const SCB_VERSION = 1;
const SCB_HKDF_INFO = 'beignet-scb-v1';

export interface IScbChannelEntry {
	/** Permanent channel id (hex). */
	channelId: string;
	/** Peer node pubkey (hex). */
	peerNodeId: string;
	/** Last-known peer network addresses as 'host:port'; may be empty. */
	peerAddresses: string[];
	/** Funding txid in INTERNAL byte order, exactly as stored in channel state. */
	fundingTxid: string;
	fundingOutputIndex: number;
	/** Channel capacity in satoshis (string for bigint-safe JSON). */
	fundingSatoshis: string;
	/** Per-channel key derivation index; null for legacy config-basepoint channels. */
	channelKeyIndex: number | null;
	/** Hex of the channel_type feature buffer; '' if unset. */
	channelType: string;
	role: 'OPENER' | 'ACCEPTOR';
	isTaproot: boolean;
	isAnchor: boolean;
}

export interface IStaticChannelBackup {
	version: 1;
	network: string;
	/** Caller-supplied creation timestamp (ms). */
	createdAt: number;
	channels: IScbChannelEntry[];
}

/**
 * Serialize and encrypt a static channel backup under the wallet seed.
 * Returns 'beignet-scb-v1:' + base64(iv || authTag || ciphertext).
 */
export function encodeScb(backup: IStaticChannelBackup, seed: Buffer): string {
	const key = hkdfKey(seed, SCB_HKDF_INFO);
	return encryptWithPrefix(key, JSON.stringify(backup), SCB_PREFIX);
}

/**
 * Decrypt and parse an encoded SCB blob. Throws on a missing/unknown prefix,
 * wrong seed or tampered ciphertext, and unsupported versions.
 */
export function decodeScb(encoded: string, seed: Buffer): IStaticChannelBackup {
	if (!encoded.startsWith(SCB_PREFIX)) {
		throw new Error(
			`Not a beignet static channel backup (missing ${SCB_PREFIX} prefix)`
		);
	}
	const key = hkdfKey(seed, SCB_HKDF_INFO);
	let json: string;
	try {
		json = decryptWithPrefix(key, encoded, SCB_PREFIX);
	} catch {
		throw new Error(
			'SCB decryption failed: wrong seed or corrupted/tampered backup'
		);
	}
	let parsed: unknown;
	try {
		parsed = JSON.parse(json);
	} catch {
		throw new Error('SCB payload is not valid JSON');
	}
	const backup = parsed as IStaticChannelBackup;
	if (backup.version !== SCB_VERSION) {
		throw new Error(`Unsupported SCB version: ${backup.version}`);
	}
	if (!Array.isArray(backup.channels)) {
		throw new Error('SCB payload is missing the channels array');
	}
	return backup;
}
