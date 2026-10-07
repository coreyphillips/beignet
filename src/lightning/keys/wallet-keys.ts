/**
 * Lightning wallet key derivation from HD seeds.
 *
 * Derives all Lightning-specific keys from a BIP32 root using the
 * key family path m/1017'/coinType'/0'/keyIndex.
 *
 * Key indices:
 *   0 - nodeKey (identity / signing)
 *   1 - fundingKey
 *   2 - revocationBase
 *   3 - paymentBase
 *   4 - delayedPaymentBase
 *   5 - htlcBase
 *   6 - perCommitmentSeed
 */

import * as bip39 from 'bip39';
import * as bip32 from 'bip32';
import { bip32 as sharedBip32 } from '../../utils/ecc-apis';
import { getPublicKey } from '../crypto/ecdh';
import { IChannelBasepoints } from './derivation';

const BIP32Factory = sharedBip32;

/** Lightning key family BIP32 purpose (BOLT-compliant LND uses 1017) */
const LN_PURPOSE = 1017;

/** Coin types */
export enum LnCoinType {
	BITCOIN = 0,
	TESTNET = 1,
	REGTEST = 1,
	SIGNET = 1
}

export interface ILightningKeysFromSeed {
	/** Node identity private key (32 bytes) */
	nodePrivateKey: Buffer;
	/** Node identity public key (33 bytes compressed) */
	nodePublicKey: Buffer;
	/** Funding private key (32 bytes) */
	fundingPrivkey: Buffer;
	/** Revocation basepoint secret (32 bytes) */
	revocationBasepointSecret: Buffer;
	/** Payment basepoint secret (32 bytes) */
	paymentBasepointSecret: Buffer;
	/** Delayed payment basepoint secret (32 bytes) */
	delayedPaymentBasepointSecret: Buffer;
	/** HTLC basepoint secret (32 bytes) */
	htlcBasepointSecret: Buffer;
	/** Per-commitment seed (32 bytes) */
	perCommitmentSeed: Buffer;
	/** Channel basepoints (all public keys) */
	channelBasepoints: IChannelBasepoints;
}

/**
 * Derive all Lightning keys from a BIP32 root key.
 *
 * Path: m/1017'/coinType'/0'/keyIndex
 *
 * @param root - BIP32 root key (from seed)
 * @param coinType - Coin type (0=mainnet, 1=testnet/regtest)
 * @returns All derived Lightning keys
 */
export function deriveLightningKeys(
	root: bip32.BIP32Interface,
	coinType: number = LnCoinType.BITCOIN
): ILightningKeysFromSeed {
	const basePath = `m/${LN_PURPOSE}'/${coinType}'/0'`;
	const base = root.derivePath(basePath);

	const deriveKey = (index: number): Buffer => {
		const child = base.derive(index);
		if (!child.privateKey) {
			throw new Error(`Failed to derive private key at ${basePath}/${index}`);
		}
		return Buffer.from(child.privateKey);
	};

	const nodePrivateKey = deriveKey(0);
	const fundingPrivkey = deriveKey(1);
	const revocationBasepointSecret = deriveKey(2);
	const paymentBasepointSecret = deriveKey(3);
	const delayedPaymentBasepointSecret = deriveKey(4);
	const htlcBasepointSecret = deriveKey(5);
	const perCommitmentSeed = deriveKey(6);

	const nodePublicKey = getPublicKey(nodePrivateKey);

	const channelBasepoints: IChannelBasepoints = {
		fundingPubkey: getPublicKey(fundingPrivkey),
		revocationBasepoint: getPublicKey(revocationBasepointSecret),
		paymentBasepoint: getPublicKey(paymentBasepointSecret),
		delayedPaymentBasepoint: getPublicKey(delayedPaymentBasepointSecret),
		htlcBasepoint: getPublicKey(htlcBasepointSecret),
		firstPerCommitmentPoint: Buffer.alloc(33) // populated during channel open
	};

	return {
		nodePrivateKey,
		nodePublicKey,
		fundingPrivkey,
		revocationBasepointSecret,
		paymentBasepointSecret,
		delayedPaymentBasepointSecret,
		htlcBasepointSecret,
		perCommitmentSeed,
		channelBasepoints
	};
}

/** Per-channel key set (excludes node identity key, which is shared). */
export interface IChannelKeys {
	/** Funding private key (32 bytes) */
	fundingPrivkey: Buffer;
	/** Revocation basepoint secret (32 bytes) */
	revocationBasepointSecret: Buffer;
	/** Payment basepoint secret (32 bytes) */
	paymentBasepointSecret: Buffer;
	/** Delayed payment basepoint secret (32 bytes) */
	delayedPaymentBasepointSecret: Buffer;
	/** HTLC basepoint secret (32 bytes) */
	htlcBasepointSecret: Buffer;
	/** Per-commitment seed (32 bytes) */
	perCommitmentSeed: Buffer;
	/** Channel basepoints (all public keys) */
	channelBasepoints: IChannelBasepoints;
}

/**
 * Derive per-channel keys from a BIP32 root key.
 *
 * Path: m/1017'/coinType'/channelIndex'/keyIndex
 *
 * The node identity key (keyIndex 0) is NOT included — it's shared across
 * all channels and derived at the node level. Only funding, revocation,
 * payment, delayed, htlc, and perCommitment keys are per-channel.
 *
 * @param root - BIP32 root key (from seed)
 * @param coinType - Coin type (0=mainnet, 1=testnet/regtest)
 * @param channelIndex - Per-channel index (0-based, incremented per channel)
 * @returns Per-channel keys
 */
export function deriveChannelKeys(
	root: bip32.BIP32Interface,
	coinType: number = LnCoinType.BITCOIN,
	channelIndex = 0
): IChannelKeys {
	const basePath = `m/${LN_PURPOSE}'/${coinType}'/${channelIndex}'`;
	// The hardened levels once, then each key from them. Deriving every key
	// from the root walked those levels again, computing each one's public
	// key for its fingerprint: about three point multiplications a key, and
	// on a phone, where they run in JavaScript, most of the time it took.
	const base = root.derivePath(basePath);

	const deriveKey = (index: number): Buffer => {
		const child = base.derive(index);
		if (!child.privateKey) {
			throw new Error(`Failed to derive private key at ${basePath}/${index}`);
		}
		return Buffer.from(child.privateKey);
	};

	const fundingPrivkey = deriveKey(1);
	const revocationBasepointSecret = deriveKey(2);
	const paymentBasepointSecret = deriveKey(3);
	const delayedPaymentBasepointSecret = deriveKey(4);
	const htlcBasepointSecret = deriveKey(5);
	const perCommitmentSeed = deriveKey(6);

	const channelBasepoints: IChannelBasepoints = {
		fundingPubkey: getPublicKey(fundingPrivkey),
		revocationBasepoint: getPublicKey(revocationBasepointSecret),
		paymentBasepoint: getPublicKey(paymentBasepointSecret),
		delayedPaymentBasepoint: getPublicKey(delayedPaymentBasepointSecret),
		htlcBasepoint: getPublicKey(htlcBasepointSecret),
		firstPerCommitmentPoint: Buffer.alloc(33) // populated during channel open
	};

	return {
		fundingPrivkey,
		revocationBasepointSecret,
		paymentBasepointSecret,
		delayedPaymentBasepointSecret,
		htlcBasepointSecret,
		perCommitmentSeed,
		channelBasepoints
	};
}

/**
 * A copy of `keys` that shares no buffer with it, for handing out keys that
 * are kept: whoever is handed them may change their bytes.
 */
export function copyChannelKeys(keys: IChannelKeys): IChannelKeys {
	const copy = (bytes: Buffer): Buffer => Buffer.from(bytes);
	const points = keys.channelBasepoints;
	return {
		fundingPrivkey: copy(keys.fundingPrivkey),
		revocationBasepointSecret: copy(keys.revocationBasepointSecret),
		paymentBasepointSecret: copy(keys.paymentBasepointSecret),
		delayedPaymentBasepointSecret: copy(keys.delayedPaymentBasepointSecret),
		htlcBasepointSecret: copy(keys.htlcBasepointSecret),
		perCommitmentSeed: copy(keys.perCommitmentSeed),
		channelBasepoints: {
			fundingPubkey: copy(points.fundingPubkey),
			revocationBasepoint: copy(points.revocationBasepoint),
			paymentBasepoint: copy(points.paymentBasepoint),
			delayedPaymentBasepoint: copy(points.delayedPaymentBasepoint),
			htlcBasepoint: copy(points.htlcBasepoint),
			firstPerCommitmentPoint: copy(points.firstPerCommitmentPoint)
		}
	};
}

/**
 * Build the BIP32 root of a BIP39 seed with this module's factory, so the
 * factory's ecc self-test runs once per process instead of once per caller.
 *
 * @param seed - BIP39 seed (mnemonicToSeed output)
 * @returns BIP32 root key
 */
export function bip32RootFromSeed(seed: Buffer): bip32.BIP32Interface {
	return BIP32Factory.fromSeed(seed);
}

/**
 * Derive all Lightning keys from a BIP39 seed. The same keys as
 * deriveLightningKeysFromMnemonic, without its PBKDF2 pass, for a caller
 * that already holds the seed.
 *
 * @param seed - BIP39 seed (mnemonicToSeed output)
 * @param coinType - Coin type (0=mainnet, 1=testnet/regtest)
 * @returns All derived Lightning keys
 */
export function deriveLightningKeysFromSeed(
	seed: Buffer,
	coinType: number = LnCoinType.BITCOIN
): ILightningKeysFromSeed {
	return deriveLightningKeys(bip32RootFromSeed(seed), coinType);
}

/**
 * Derive all Lightning keys from a BIP39 mnemonic.
 *
 * @param mnemonic - BIP39 mnemonic phrase
 * @param passphrase - Optional BIP39 passphrase
 * @param coinType - Coin type (0=mainnet, 1=testnet/regtest)
 * @returns All derived Lightning keys
 */
export function deriveLightningKeysFromMnemonic(
	mnemonic: string,
	passphrase?: string,
	coinType: number = LnCoinType.BITCOIN
): ILightningKeysFromSeed {
	if (!bip39.validateMnemonic(mnemonic)) {
		throw new Error('Invalid BIP39 mnemonic');
	}

	return deriveLightningKeysFromSeed(
		bip39.mnemonicToSeedSync(mnemonic, passphrase),
		coinType
	);
}
