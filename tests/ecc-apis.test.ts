import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import { EAddressType } from '../src/types';
import { getECPair } from '../src/utils/ecc-apis';
import {
	getAddressesFromPrivateKey,
	validatePsbtSignature
} from '../src/utils/helpers';

describe('The shared ECPair', () => {
	it('is made once, the first time it is asked for', () => {
		expect(getECPair()).to.equal(getECPair());
	});

	it('checks a signature over the hash it signed, and only that hash', () => {
		const pair = getECPair().makeRandom();
		const hash = Buffer.alloc(32, 7);
		const signature = pair.sign(hash);
		expect(validatePsbtSignature(pair.publicKey, hash, signature)).to.equal(
			true
		);
		expect(
			validatePsbtSignature(pair.publicKey, Buffer.alloc(32, 8), signature)
		).to.equal(false);
	});

	it('reads a WIF into the addresses of its key', () => {
		const network = bitcoin.networks.testnet;
		const pair = getECPair().makeRandom({ network });
		const read = getAddressesFromPrivateKey({
			privateKey: pair.toWIF(),
			addrTypes: [EAddressType.p2wpkh],
			network
		});
		if (read.isErr()) throw read.error;
		const p2wpkh = bitcoin.payments.p2wpkh({
			pubkey: pair.publicKey,
			network
		}).address;
		expect(JSON.stringify(read.value)).to.contain(p2wpkh);
	});
});
