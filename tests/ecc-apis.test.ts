import { expect } from 'chai';
import { execFileSync } from 'child_process';
import path from 'path';
import * as bitcoin from 'bitcoinjs-lib';
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
			network
		});
		if (read.isErr()) throw read.error;
		const p2wpkh = bitcoin.payments.p2wpkh({
			pubkey: pair.publicKey,
			network
		}).address;
		expect(JSON.stringify(read.value)).to.contain(p2wpkh);
	});

	it('reads all default addresses when helpers are imported alone', function () {
		this.timeout(15_000);
		// A fresh process prevents another suite's initEccLib call from hiding
		// the helper's missing initialization. The fixture is private key 1.
		const output = execFileSync(
			process.execPath,
			[
				'-r',
				require.resolve('ts-node/register'),
				'-e',
				`
				const helpers = require('./src/utils/helpers');
				const bitcoin = require('bitcoinjs-lib');
				const privateKey = 'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn';
				const read = helpers.getAddressesFromPrivateKey({ privateKey });
				if (read.isErr()) throw read.error;
				const taproot = helpers.getTapRootAddressFromPublicKey({
					publicKey: read.value.keyPair.publicKey,
					network: bitcoin.networks.bitcoin
				});
				if (taproot.isErr()) throw taproot.error;
				bitcoin.initEccLib(undefined);
				const failed = helpers.getAddressesFromPrivateKey({ privateKey });
				if (failed.isOk()) throw new Error('Expected missing ECC to fail');
				process.stdout.write(JSON.stringify({
					addresses: read.value.addresses.map(({ address }) => address),
					taprootAddress: taproot.value.address,
					taprootOutput: taproot.value.output.toString('hex'),
					error: failed.error.message
				}));
				`
			],
			{ cwd: path.resolve(__dirname, '..'), encoding: 'utf8', timeout: 10_000 }
		);
		const result = JSON.parse(output);
		expect(result.addresses).to.deep.equal([
			'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4',
			'3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN',
			'1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH',
			'bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sspknck9'
		]);
		expect(result.taprootAddress).to.equal(result.addresses[3]);
		expect(result.taprootOutput).to.equal(
			'5120da4710964f7852695de2da025290e24af6d8c281de5a0b902b7135fd9fd74d21'
		);
		expect(result.error).to.contain('No ECC Library provided');
	});
});
