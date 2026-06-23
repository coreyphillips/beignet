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

import * as bip32 from 'bip32';
import * as bip39 from 'bip39';
import * as ecc from '@bitcoinerlab/secp256k1';
import { getPublicKey } from '../crypto/ecdh';
import { IChannelBasepoints } from './derivation';

const BIP32Factory = bip32.BIP32Factory(ecc);

/** Lightning key family BIP32 purpose (BOLT-compliant LND uses 1017) */
const LN_PURPOSE = 1017;

/** Coin types */
export enum LnCoinType {
	BITCOIN = 0,
	TESTNET = 1,
	REGTEST = 1
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

	const deriveKey = (index: number): Buffer => {
		const child = root.derivePath(`${basePath}/${index}`);
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

	const deriveKey = (index: number): Buffer => {
		const child = root.derivePath(`${basePath}/${index}`);
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

	const seed = bip39.mnemonicToSeedSync(mnemonic, passphrase);
	const root = BIP32Factory.fromSeed(seed);

	return deriveLightningKeys(root, coinType);
}
