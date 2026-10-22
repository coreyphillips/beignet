import {
	EAddressType,
	IGetAddressesFromKeyPair,
	IGetAddressesFromPrivateKey,
	IKeyDerivationPath
} from '../types';
import { Network, toBitcoinJsNetwork } from '../network';
import {
	address as bitcoinJSAddress,
	Network as BitcoinJsNetwork
} from 'bitcoinjs-lib';
import * as bip39 from 'bip39';
import * as bitcoin from 'bitcoinjs-lib';
import { availableNetworks, isValidBech32mEncodedString } from './wallet';
import { err, ok, Result } from './result';
import { addressTypes, getAddressTypes } from '../shapes';
import { getKeyDerivationPathObject } from './derivation-path';
import { ECPairInterface } from 'ecpair';
import { ecc } from './ecc';
import { getECPair } from './ecc-apis';
import { BIP32Interface } from 'bip32';
import { toXOnly } from 'bitcoinjs-lib/src/psbt/bip371';

bitcoin.initEccLib(ecc);

/**
 * PSBT signature validator for Psbt.validateSignaturesOfInput. A 32-byte
 * pubkey means a taproot (x-only, schnorr) signature; 33 bytes means ECDSA.
 * @param {Buffer} pubkey
 * @param {Buffer} msghash
 * @param {Buffer} signature
 * @returns {boolean}
 */
export const validatePsbtSignature = (
	pubkey: Buffer,
	msghash: Buffer,
	signature: Buffer
): boolean => {
	if (pubkey.length === 32) {
		return Boolean(ecc.verifySchnorr(msghash, pubkey, signature));
	}
	return getECPair().fromPublicKey(pubkey).verify(msghash, signature);
};

/**
 * @deprecated Use `toBitcoinJsNetwork`. Removed in the next major release.
 * @param {Network} network
 * @returns {BitcoinJsNetwork}
 */
export const getBitcoinJsNetwork = (
	network: Network | `${Network}`
): BitcoinJsNetwork => toBitcoinJsNetwork(network as Network);

/**
 * Get address for a given scriptPubKey.
 * @param scriptPubKey
 * @param selectedNetwork
 * @returns {string}
 */
export const getAddressFromScriptPubKey = (
	scriptPubKey: string,
	selectedNetwork: Network
): string => {
	const network = toBitcoinJsNetwork(selectedNetwork);
	return bitcoin.address.fromOutputScript(
		Buffer.from(scriptPubKey, 'hex'),
		network
	);
};

/**
 * Get sha256 hash of a given string.
 * @param {string} str
 * @returns {string}
 */
export const getSha256 = (str: string): string => {
	const buffer = Buffer.from(str, 'utf8');
	const hash = bitcoin.crypto.sha256(buffer);
	return hash.toString('hex');
};

/**
 * Validate address for a given network.
 * If no address is provided, it will attempt to validate the address for all available networks.
 * @param {string} address
 * @param {Network} network
 * @returns {{isValid: boolean, network: Network}}
 */
export const validateAddress = ({
	address,
	network
}: {
	address: string;
	network?: Network;
}): {
	isValid: boolean;
	network: Network;
} => {
	try {
		//Validate address for all available networks
		let isValid = false;
		const availableNetworksList = availableNetworks();

		//Validate address for a specific network
		if (network !== undefined) {
			try {
				bitcoinJSAddress.toOutputScript(address, toBitcoinJsNetwork(network));
				return { isValid: true, network };
			} catch {
				// In the event the normal check fails, determine if this is a taproot address.
				const taprootRes = isValidBech32mEncodedString(address);
				if (taprootRes.isValid && taprootRes.network === network) {
					return { isValid: taprootRes.isValid, network: taprootRes.network };
				}
			}
			return { isValid: false, network };
		}

		for (let i = 0; i < availableNetworksList.length; i++) {
			const validateRes = validateAddress({
				address,
				network: availableNetworksList[i]
			});
			if (validateRes.isValid) {
				isValid = validateRes.isValid;
				network = validateRes.network;
				break;
			}
		}
		return { isValid, network: network ?? Network.bitcoin };
	} catch {
		return { isValid: false, network: Network.bitcoin };
	}
};

/**
 * Returns the derivation path object for the specified addressType and network.
 * @param {EAddressType} addressType
 * @param {Network} [selectedNetwork]
 * @returns Result<IKeyDerivationPath>
 */
export const getKeyDerivationPath = ({
	addressType,
	network
}: {
	addressType: EAddressType;
	network: Network;
}): Result<IKeyDerivationPath> => {
	try {
		const keyDerivationPathResponse = getKeyDerivationPathObject({
			network,
			path: addressTypes[addressType].path
		});
		if (keyDerivationPathResponse.isErr()) {
			return err(keyDerivationPathResponse.error);
		}
		return ok(keyDerivationPathResponse.value);
	} catch (e) {
		return err(e);
	}
};

/**
 * Get scriptHash for a given address
 * @param {string} address
 * @param {Network} network
 * @returns {string}
 */
export const getScriptHash = ({
	address,
	network
}: {
	address: string;
	network: Network;
}): string => {
	try {
		const _network = toBitcoinJsNetwork(network);
		const script = bitcoin.address.toOutputScript(address, _network);
		const hash = bitcoin.crypto.sha256(script);
		const reversedHash = Buffer.from(hash.reverse());
		return reversedHash.toString('hex');
	} catch {
		return '';
	}
};

/**
 * Extends bip39's generateMnemonic function.
 * @param {number} [strength]
 * @param {(size: number) => Buffer} [rng]
 * @param {string[]} [wordlist]
 * @returns {string}
 */
export const generateMnemonic = (
	strength?: number,
	rng?: (size: number) => Buffer,
	wordlist?: string[]
): string => {
	return bip39.generateMnemonic(strength, rng, wordlist);
};

/**
 * Attempts to validate the provided mnemonic.
 * @param {string} mnemonic
 * @returns {boolean}
 */
export const validateMnemonic = (mnemonic = ''): boolean => {
	try {
		return bip39.validateMnemonic(mnemonic);
	} catch {
		return false;
	}
};

/**
 * Determines if the two objects passed as params match.
 * @param obj1
 * @param obj2
 * @returns boolean
 */
export const objectsMatch = (obj1: unknown, obj2: unknown): boolean => {
	if (!obj1 || !obj2) {
		return false;
	}
	const a = obj1 as Record<string, unknown>;
	const b = obj2 as Record<string, unknown>;
	const obj1Length = Object.keys(a).length;
	const obj2Length = Object.keys(b).length;

	if (obj1Length === obj2Length) {
		return Object.keys(a).every((key) => key in b && b[key] === a[key]);
	} else {
		return false;
	}
};

/**
 * Get address from key pair.
 * @param {BIP32Interface | ECPairInterface} keyPair
 * @param {EAddressType} addressType
 * @param {BitcoinJsNetwork} network
 * @returns {IGetAddressesFromKeyPair}
 */
export const getAddressFromKeyPair = ({
	keyPair,
	addressType,
	network
}: {
	keyPair: BIP32Interface | ECPairInterface;
	addressType: EAddressType;
	network: BitcoinJsNetwork;
}): Result<IGetAddressesFromKeyPair> => {
	let address = '';
	switch (addressType) {
		case EAddressType.p2wpkh:
			//Get Bech32 (bc1) address
			address =
				bitcoin.payments.p2wpkh({
					pubkey: keyPair.publicKey,
					network
				}).address ?? '';
			break;
		case EAddressType.p2sh:
			//Get Segwit P2SH Address (3)
			address =
				bitcoin.payments.p2sh({
					redeem: bitcoin.payments.p2wpkh({
						pubkey: keyPair.publicKey,
						network
					}),
					network
				}).address ?? '';
			break;
		//Get Legacy Address (1)
		case EAddressType.p2pkh:
			address =
				bitcoin.payments.p2pkh({
					pubkey: keyPair.publicKey,
					network
				}).address ?? '';
			break;
		case EAddressType.p2tr:
			const res = getTapRootAddressFromPublicKey({
				publicKey: keyPair.publicKey,
				network
			});
			if (res.isErr()) return err(res.error);
			address = res.value.address;
			break;
		case EAddressType.p2wsh:
			// A sorted-multisig P2WSH address needs every cosigner's key, not a
			// single key pair; the Wallet multisig path builds it instead.
			break;
	}
	if (!address) return err('Unable to get address from key pair.');
	return ok({
		address,
		publicKey: keyPair.publicKey.toString('hex')
	});
};

/**
 * Returns taproot address information from the provided public key.
 * @param {Buffer} publicKey
 * @param {BitcoinJsNetwork} network
 * @returns {Result<{ address: string; output: Buffer; internalPubkey: Buffer; }>}
 */
export const getTapRootAddressFromPublicKey = ({
	publicKey,
	network
}: {
	publicKey: Buffer;
	network: BitcoinJsNetwork;
}): Result<{ address: string; output: Buffer; internalPubkey: Buffer }> => {
	try {
		const internalPubkey = toXOnly(publicKey);
		const { address, output } = bitcoin.payments.p2tr({
			internalPubkey,
			network
		});
		if (!address) return err('Unable to get address from key pair.');
		if (!output) return err('Unable to get output from key pair.');
		return ok({ address, output, internalPubkey });
	} catch (e) {
		return err(e);
	}
};

/**
 * Get addresses from a private key.
 * @param {string} privateKey
 * @param {EAddressType[]} [addrTypes]
 * @param {BitcoinJsNetwork} [network]
 */
export const getAddressesFromPrivateKey = ({
	privateKey,
	// p2wsh is excluded: a single private key cannot form a multisig script.
	addrTypes = getAddressTypes().filter((t) => t !== EAddressType.p2wsh),
	network = bitcoin.networks.bitcoin
}: {
	privateKey: string;
	addrTypes?: EAddressType[];
	network?: BitcoinJsNetwork;
}): Result<IGetAddressesFromPrivateKey> => {
	try {
		if (!privateKey) return err('No private key provided.');
		const keyPair = getECPair().fromWIF(privateKey, network);
		const response = addrTypes.map((addressType) => {
			const addressInfo = getAddressFromKeyPair({
				keyPair,
				addressType,
				network
			});
			if (addressInfo.isErr()) throw addressInfo.error;
			return addressInfo.value;
		});
		if (!response) return err('Unable to get addresses from private key.');
		return ok({
			keyPair,
			addresses: response
		});
	} catch (e) {
		return err(e);
	}
};

export const sleep = (ms: number): Promise<void> => {
	return new Promise((resolve) => {
		setTimeout(resolve, ms);
	});
};

/**
 * Returns the difference between two address indexes.
 * @param addrIndex1
 * @param addrIndex2
 * @returns number
 */
export const getAddressIndexDiff = (addrIndex1 = 0, addrIndex2 = 0): number => {
	if (addrIndex1 < 0) addrIndex1 = -1;
	if (addrIndex2 < 0) addrIndex2 = -1;
	return Math.abs(addrIndex1 - addrIndex2);
};

export const isPositive = (num: number): boolean => num > 0;
