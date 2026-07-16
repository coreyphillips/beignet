import * as bitcoin from 'bitcoinjs-lib';
import BIP32Factory, { BIP32Interface } from 'bip32';
import * as ecc from '@bitcoinerlab/secp256k1';

import { EAddressType, EAvailableNetworks } from '../types';
import { err, ok, Result } from './result';

const bip32 = BIP32Factory(ecc);

/**
 * Typed error thrown/returned whenever a watch-only wallet is asked to
 * perform an operation that requires private keys.
 */
export class WatchOnlySigningError extends Error {
	public readonly code = 'WATCH_ONLY_CANNOT_SIGN';
	constructor(message = 'watch-only wallet cannot sign') {
		super(message);
		this.name = 'WatchOnlySigningError';
	}
}

/** A key's true BIP 32 origin: master fingerprint + path to the known xpub. */
export interface IKeyOrigin {
	fingerprint: Buffer;
	// Path from the master to the xpub, "'"-hardened, no "m/" prefix
	// (e.g. "84'/0'/0'"). Undefined when only the fingerprint was supplied.
	path?: string;
}

/**
 * Validates and normalizes user-supplied key-origin metadata. The
 * fingerprint must be 8 hex chars; the path accepts "m/84'/0'/0'",
 * "84h/0h/0h" etc. and is normalized to "'"-hardened with no "m/" prefix.
 */
export const normalizeKeyOrigin = (
	masterFingerprint: string,
	originPath?: string
): Result<IKeyOrigin> => {
	if (!/^[0-9a-fA-F]{8}$/.test(masterFingerprint)) {
		return err(
			`masterFingerprint must be 8 hex characters, received "${masterFingerprint}".`
		);
	}
	const fingerprint = Buffer.from(masterFingerprint.toLowerCase(), 'hex');
	if (originPath === undefined) return ok({ fingerprint });
	const stripped = originPath.replace(/^m\//i, '').replace(/h/gi, "'");
	const segments = stripped.split('/');
	if (!segments.length || segments.some((s) => !/^\d+'?$/.test(s))) {
		return err(
			`originPath must be a derivation path like "m/84'/0'/0'", received "${originPath}".`
		);
	}
	return ok({ fingerprint, path: stripped });
};

// SLIP-132 extended public key version bytes. The version only encodes how
// the exporting wallet intended addresses to be derived; the key material is
// identical, so we re-parse under the target network after prefix checks.
const EXTENDED_KEY_VERSIONS: {
	[prefix: string]: {
		version: number;
		mainnet: boolean;
		addressType?: EAddressType;
	};
} = {
	xpub: { version: 0x0488b21e, mainnet: true },
	ypub: { version: 0x049d7cb2, mainnet: true, addressType: EAddressType.p2sh },
	zpub: {
		version: 0x04b24746,
		mainnet: true,
		addressType: EAddressType.p2wpkh
	},
	// SLIP-132 multisig P2WSH account keys (BIP 48 script type 2').
	Zpub: {
		version: 0x02aa7ed3,
		mainnet: true,
		addressType: EAddressType.p2wsh
	},
	tpub: { version: 0x043587cf, mainnet: false },
	upub: { version: 0x044a5262, mainnet: false, addressType: EAddressType.p2sh },
	vpub: {
		version: 0x045f1cf6,
		mainnet: false,
		addressType: EAddressType.p2wpkh
	},
	Vpub: {
		version: 0x02575483,
		mainnet: false,
		addressType: EAddressType.p2wsh
	}
};

export interface IParsedExtendedPublicKey {
	node: BIP32Interface;
	addressType?: EAddressType; // Inferred from a SLIP-132 prefix when present.
}

/**
 * Parses an account-level extended public key (xpub/ypub/zpub/tpub/upub/vpub)
 * and normalizes its version bytes to the provided network. The key is
 * assumed to be the ACCOUNT node (depth 3, m/purpose'/coin'/account').
 * @param {string} extendedKey
 * @param {EAvailableNetworks} network
 * @returns {Result<IParsedExtendedPublicKey>}
 */
export const parseExtendedPublicKey = (
	extendedKey: string,
	network: EAvailableNetworks
): Result<IParsedExtendedPublicKey> => {
	try {
		if (!extendedKey) return err('No extended public key provided.');
		const prefix = extendedKey.slice(0, 4);
		if (/^[xyztuv]prv$/i.test(prefix)) {
			return err(
				'An extended PRIVATE key was provided. Watch-only wallets accept public keys only.'
			);
		}
		const entry = EXTENDED_KEY_VERSIONS[prefix];
		if (!entry) {
			return err(
				`Unsupported extended public key prefix: ${prefix}. Supported prefixes: ${Object.keys(
					EXTENDED_KEY_VERSIONS
				).join(', ')}.`
			);
		}
		const isMainnet = network === EAvailableNetworks.bitcoin;
		if (entry.mainnet !== isMainnet) {
			return err(
				`Extended public key prefix ${prefix} does not match the ${network} network.`
			);
		}
		const targetNetwork = bitcoin.networks[network];
		// bip32.fromBase58 rejects any version bytes that differ from the
		// network passed in, so parse with the SLIP-132 version substituted.
		// The private version is set to a value no key can carry: fromBase58
		// checks the private version first, and public keys must never take
		// that branch.
		const parseNetwork = {
			...targetNetwork,
			bip32: { public: entry.version, private: 0 }
		};
		const node = bip32.fromBase58(extendedKey, parseNetwork);
		if (!node.isNeutered()) {
			return err(
				'An extended PRIVATE key was provided. Watch-only wallets accept public keys only.'
			);
		}
		return ok({ node, addressType: entry.addressType });
	} catch (e) {
		return err(e);
	}
};
