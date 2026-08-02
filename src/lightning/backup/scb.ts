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
 * variant to look for; leaseExpiry/isLessor (optional, liquidity ads) let it
 * reconstruct a lessor's lease-locked to_remote and set the sweep locktime.
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
import { isValidPublicKey } from '../crypto/ecdh';

export const SCB_PREFIX = 'beignet-scb-v1:';
export const SCB_VERSION = 1;
const SCB_HKDF_INFO = 'beignet-scb-v1';

/** No channel can hold more than the money that exists. */
const MAX_FUNDING_SATOSHIS = 21_000_000n * 100_000_000n;
/** Bitcoin's own limit on a transaction's output count bounds the index. */
const MAX_OUTPUT_INDEX = 0xffffffff;
/**
 * channelKeyIndex is a HARDENED BIP32 path component in the default deriver
 * (m/1017'/coinType'/channelIndex'), so anything above 2^31 - 1 is not a
 * derivable index at all: it throws inside the deriver instead of producing
 * key material.
 */
const MAX_BIP32_DERIVATION_INDEX = 0x7fffffff;

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
	/**
	 * Liquidity ads (bLIP-0051 lease). A LESSOR's to_remote is the
	 * lease-locked CSV variant, so recovery needs these to reconstruct the
	 * right script and set the sweep's input sequence. leaseCommitBlockheight
	 * is the blockheight agreed at open; the lease CSV =
	 * leaseExpiry - leaseCommitBlockheight (CLN model). Optional: absent on
	 * non-lease channels and on backups created before the fields existed
	 * (JSON tolerates both directions; no version bump).
	 */
	leaseExpiry?: number;
	isLessor?: boolean;
	leaseCommitBlockheight?: number;
}

export interface IStaticChannelBackup {
	version: 1;
	network: string;
	/** Caller-supplied creation timestamp (ms). */
	createdAt: number;
	channels: IScbChannelEntry[];
}

/**
 * Parse one backup address entry: 'host:port', with an optionally bracketed
 * IPv6 host, split on the LAST colon. THE parser for the SCB address format,
 * shared by entry validation, recovery address persistence and the recovery
 * dial loop, so none of them can drift on what counts as dialable.
 *
 * Strict on purpose: a permissive parseInt accepts '9735junk' and '0', and a
 * recovery flow that persists a garbage port has a dial candidate that can
 * never connect, which is worse than having none.
 */
export function parseScbAddress(
	address: unknown
): { host: string; port: number } | null {
	if (typeof address !== 'string') return null;
	const sep = address.lastIndexOf(':');
	if (sep <= 0 || sep === address.length - 1) return null;
	let host = address.slice(0, sep);
	// Only a MATCHED bracket pair is an IPv6 wrapper; a stray bracket on one
	// side is malformed, never something to strip and accept.
	if (host.startsWith('[') && host.endsWith(']')) {
		host = host.slice(1, -1);
	}
	if (host.length === 0) return null;
	// Whitespace, control characters and leftover brackets never appear in a
	// host we wrote ourselves.
	// eslint-disable-next-line no-control-regex
	if (/[\s[\]\u0000-\u001f\u007f]/.test(host)) return null;
	const portText = address.slice(sep + 1);
	if (!/^[0-9]{1,5}$/.test(portText)) return null;
	const port = Number(portText);
	if (port < 1 || port > 65535) return null;
	return { host, port };
}

const HEX_ONLY = /^[0-9a-fA-F]*$/;

function isHexOfBytes(value: unknown, bytes: number): boolean {
	return (
		typeof value === 'string' &&
		value.length === bytes * 2 &&
		HEX_ONLY.test(value)
	);
}

function isIndex(value: unknown, max: number): boolean {
	return (
		typeof value === 'number' &&
		Number.isInteger(value) &&
		value >= 0 &&
		value <= max
	);
}

/**
 * Validate one backup entry's shape. Returns the reason it is unusable, or
 * null when every field is what recovery will assume it is.
 *
 * Recovery reconstructs channel state from these fields and then watches an
 * on-chain outpoint for them, so a malformed entry must be rejected AT THE
 * BOUNDARY: reaching the reconstruction with a garbage funding txid installs
 * a channel whose funds can never be swept, and a garbage satoshi string
 * throws out of the recovery loop, taking the channels behind it down too.
 *
 * Absence is tolerated for exactly two reasons, and they are different:
 * `peerAddresses` and the taproot/anchor booleans are ADVISORY (recovery is
 * passive without addresses, and the channel type, not the booleans, picks
 * the output script), while an absent `channelKeyIndex` or `channelType` is
 * the LEGACY shape of a pre-per-channel-key, pre-typed channel. A modern
 * entry that CONTRADICTS itself, claiming taproot or anchors with no usable
 * channel type, is refused rather than reconstructed against the wrong
 * to_remote script.
 */
export function validateScbEntry(entry: unknown): string | null {
	if (!entry || typeof entry !== 'object') return 'entry is not an object';
	const e = entry as Record<string, unknown>;
	if (!isHexOfBytes(e.channelId, 32)) {
		return 'invalid channelId (expected 32-byte hex)';
	}
	if (!isHexOfBytes(e.peerNodeId, 33)) {
		return 'invalid peerNodeId (expected 33-byte hex)';
	}
	if (!isValidPublicKey(Buffer.from(e.peerNodeId as string, 'hex'))) {
		return 'peerNodeId is not a valid public key';
	}
	// Addresses are advisory (recovery is passive without them), so an absent
	// list is the empty list rather than a reason to forfeit the channel.
	if (
		e.peerAddresses !== undefined &&
		(!Array.isArray(e.peerAddresses) ||
			e.peerAddresses.some((a) => typeof a !== 'string'))
	) {
		return 'peerAddresses must be an array of strings';
	}
	if (!isHexOfBytes(e.fundingTxid, 32)) {
		return 'invalid fundingTxid (expected 32-byte hex)';
	}
	if (!isIndex(e.fundingOutputIndex, MAX_OUTPUT_INDEX)) {
		return 'invalid fundingOutputIndex';
	}
	if (
		typeof e.fundingSatoshis !== 'string' ||
		!/^[0-9]+$/.test(e.fundingSatoshis)
	) {
		return 'invalid fundingSatoshis (expected a decimal string)';
	}
	const funding = BigInt(e.fundingSatoshis);
	if (funding <= 0n || funding > MAX_FUNDING_SATOSHIS) {
		return 'fundingSatoshis out of range';
	}
	// null (or absent) is the LEGACY channel that derives from the node-level
	// basepoints, kept working for backups written before per-channel keys;
	// a present index must be one the deriver can actually derive.
	if (
		e.channelKeyIndex !== null &&
		e.channelKeyIndex !== undefined &&
		!isIndex(e.channelKeyIndex, MAX_BIP32_DERIVATION_INDEX)
	) {
		return 'invalid channelKeyIndex';
	}
	// channelType picks the to_remote variant the sweep looks for, so garbage
	// is fatal; absent is the untyped legacy channel, exactly as before.
	if (
		e.channelType !== undefined &&
		(typeof e.channelType !== 'string' ||
			e.channelType.length % 2 !== 0 ||
			!HEX_ONLY.test(e.channelType))
	) {
		return 'invalid channelType (expected hex)';
	}
	if (e.role !== 'OPENER' && e.role !== 'ACCEPTOR') {
		return 'invalid role';
	}
	// Recovery reads the channel type, not these two, so they only have to be
	// what they claim when present.
	if (
		(e.isTaproot !== undefined && typeof e.isTaproot !== 'boolean') ||
		(e.isAnchor !== undefined && typeof e.isAnchor !== 'boolean')
	) {
		return 'isTaproot and isAnchor must be booleans';
	}
	// A channel that says it is taproot or anchor cannot ALSO be the untyped
	// legacy shape: reconstructing it without its type would look for a
	// static_remotekey P2WPKH that its commitment never pays.
	if (
		(e.isTaproot === true || e.isAnchor === true) &&
		(typeof e.channelType !== 'string' || e.channelType.length === 0)
	) {
		return 'channelType is required for a taproot or anchor channel';
	}
	// Liquidity-ads fields are optional, but present means usable: the sweep
	// derives a lease CSV and an nLockTime from them.
	if (
		e.leaseExpiry !== undefined &&
		!isIndex(e.leaseExpiry, MAX_OUTPUT_INDEX)
	) {
		return 'invalid leaseExpiry';
	}
	if (
		e.leaseCommitBlockheight !== undefined &&
		!isIndex(e.leaseCommitBlockheight, MAX_OUTPUT_INDEX)
	) {
		return 'invalid leaseCommitBlockheight';
	}
	if (e.isLessor !== undefined && typeof e.isLessor !== 'boolean') {
		return 'invalid isLessor';
	}
	return null;
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
	if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
		throw new Error('SCB payload is not a backup object');
	}
	const backup = parsed as IStaticChannelBackup;
	if (backup.version !== SCB_VERSION) {
		throw new Error(`Unsupported SCB version: ${backup.version}`);
	}
	if (typeof backup.network !== 'string' || backup.network.length === 0) {
		throw new Error('SCB payload has no network');
	}
	if (
		typeof backup.createdAt !== 'number' ||
		!Number.isFinite(backup.createdAt)
	) {
		throw new Error('SCB payload has no createdAt timestamp');
	}
	if (!Array.isArray(backup.channels)) {
		throw new Error('SCB payload is missing the channels array');
	}
	return backup;
}

/**
 * Validate every entry of a decoded backup, returning one problem per
 * unusable entry.
 *
 * Deliberately NOT a throw out of `decodeScb`: the blob is AEAD-authenticated,
 * so a malformed entry inside a decryptable backup is a producer or version
 * bug rather than corruption, and refusing the whole backup for one bad entry
 * would forfeit the funds behind every good one. Recovery skips the invalid
 * entries with these reasons and restores the rest.
 */
export function validateScbEntries(
	backup: IStaticChannelBackup
): Array<{ index: number; channelId: string; reason: string }> {
	const problems: Array<{ index: number; channelId: string; reason: string }> =
		[];
	backup.channels.forEach((entry, index) => {
		const reason = validateScbEntry(entry);
		if (reason) {
			const id = (entry as { channelId?: unknown })?.channelId;
			problems.push({
				index,
				channelId: typeof id === 'string' ? id : '',
				reason
			});
		}
	});
	return problems;
}
