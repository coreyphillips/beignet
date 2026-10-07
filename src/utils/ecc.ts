/**
 * The secp256k1 library every part of Beignet uses, as one object.
 *
 * bitcoinjs-lib checks a curve library against test vectors the first time
 * it is handed one, and ecpair and bip32 check it each time a factory is
 * made (see ecc-apis.ts). A bundled build gives every module that imports
 * `@bitcoinerlab/secp256k1` its own namespace object, so bitcoinjs-lib saw
 * a new library in each of the 20 modules that set it, and the checks ran
 * 26 times as the engine loaded: on a phone, most of a second of pure-JS
 * secp256k1 before its wallet could open. Every module takes the library
 * from here, one object, so bitcoinjs-lib checks it once.
 *
 * This module imports nothing else, so a module that only needs the curve
 * pulls in nothing more than it did.
 */
import * as secp256k1 from '@bitcoinerlab/secp256k1';

export const ecc = secp256k1;
