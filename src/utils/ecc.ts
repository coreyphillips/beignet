/**
 * The secp256k1 library every part of Beignet uses, and the ECPair and
 * BIP32 APIs built on it, each set up once.
 *
 * bitcoinjs-lib checks a curve library against test vectors the first time
 * it is handed one, and ecpair and bip32 check it each time a factory is
 * made. A bundled build gives every module that imports
 * `@bitcoinerlab/secp256k1` its own namespace object, so bitcoinjs-lib saw
 * a new library in each of the 20 modules that set it, and the checks ran
 * 26 times as the engine loaded: on a phone, most of a second of pure-JS
 * secp256k1 before its wallet could open. Every module takes the library
 * from here, one object, checked once.
 */
import * as secp256k1 from '@bitcoinerlab/secp256k1';
import * as bitcoin from 'bitcoinjs-lib';
import { BIP32Factory } from 'bip32';
import { ECPairFactory } from 'ecpair';

export const ecc = secp256k1;

bitcoin.initEccLib(ecc);

/** ECPair over `ecc`, made once. */
export const ECPair = ECPairFactory(ecc);

/** BIP32 over `ecc`, made once. */
export const bip32 = BIP32Factory(ecc);
