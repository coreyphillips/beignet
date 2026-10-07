/**
 * The ECPair and BIP32 APIs over the one curve library (ecc.ts), each made
 * once. ecpair and bip32 check the library against test vectors every time
 * a factory is made, and the engine made three of each.
 */
import { BIP32Factory } from 'bip32';
import { ECPairAPI, ECPairFactory } from 'ecpair';
import { ecc } from './ecc';

let ecpair: ECPairAPI | undefined;

/**
 * ECPair over `ecc`, made the first time it is asked for. Its check of the
 * library signs and verifies test vectors, about 0.3 s of pure-JS secp256k1
 * on a phone, and nothing at startup needs it: it signs and checks on-chain
 * spends. Made when the engine loaded, it held back the first paint of the
 * wallet that loaded it.
 */
export function getECPair(): ECPairAPI {
	if (!ecpair) ecpair = ECPairFactory(ecc);
	return ecpair;
}

/** BIP32 over `ecc`, made once: the wallet derives its keys as it opens. */
export const bip32 = BIP32Factory(ecc);
