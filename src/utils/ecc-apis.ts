/**
 * The ECPair and BIP32 APIs over the one curve library (ecc.ts), each made
 * once. ecpair and bip32 check the library against test vectors every time
 * a factory is made, and the engine made three of each.
 */
import { BIP32Factory } from 'bip32';
import { ECPairFactory } from 'ecpair';
import { ecc } from './ecc';

/** ECPair over `ecc`, made once. */
export const ECPair = ECPairFactory(ecc);

/** BIP32 over `ecc`, made once. */
export const bip32 = BIP32Factory(ecc);
