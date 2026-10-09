/**
 * Regression tests for issue #1434: sweepPrivateKey staged every coin the key
 * held, and addInput refuses one below its script's dust threshold, so a
 * single 293 sat P2WPKH deposit aborted the sweep of the key's other coins.
 *
 * Fully OFFLINE: the wallet points at an unreachable Electrum port and the
 * key's UTXO lookup is stubbed.
 */

import { expect } from 'chai';
import net from 'net';
import sinon from 'sinon';
import tls from 'tls';
import ecc from '@bitcoinerlab/secp256k1';
import {
	Transaction as BitcoinTransaction,
	networks,
	payments
} from 'bitcoinjs-lib';
import { ECPairFactory } from 'ecpair';

import {
	EAddressType,
	EAvailableNetworks,
	EProtocol,
	IUtxo,
	Wallet,
	err,
	ok
} from '../src';

const ECPair = ECPairFactory(ecc);

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

// Unreachable on purpose: these tests must work offline.
const electrumOptions = {
	net,
	tls,
	servers: {
		host: '127.0.0.1',
		ssl: 65529,
		tcp: 65529,
		protocol: EProtocol.tcp
	}
};

const network = networks.regtest;
const RECIPIENT = 'bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk';

const keyPair = ECPair.fromPrivateKey(Buffer.alloc(32, 0x5a), { network });
const KEY_ADDRESS = payments.p2wpkh({ pubkey: keyPair.publicKey, network })
	.address as string;

/** A coin paying the swept key's P2WPKH address. */
const keyCoin = (txid: string, value: number): IUtxo => ({
	address: KEY_ADDRESS,
	index: 0,
	path: '',
	scriptHash: '00'.repeat(32),
	height: 1,
	tx_hash: txid,
	tx_pos: 0,
	value,
	publicKey: keyPair.publicKey.toString('hex')
});

describe('Sweeping a private key that holds dust (#1434)', function () {
	this.timeout(60000);

	let wallet: Wallet;

	/** Makes the key's UTXO lookup answer with the given coins. */
	const keyHolds = (utxos: IUtxo[]): void => {
		const balance = utxos.reduce((total, utxo) => total + utxo.value, 0);
		sinon
			.stub(wallet.electrum, 'listUnspentAddressScriptHashes')
			.resolves(ok({ utxos, balance }));
		// Segwit inputs build from witnessUtxo when the previous transaction
		// cannot be fetched.
		sinon.stub(wallet.electrum, 'getTransactions').resolves(err('offline'));
	};

	before(async function () {
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			name: 'sweepdust',
			network: EAvailableNetworks.regtest,
			addressType: EAddressType.p2wpkh,
			electrumOptions
		});
		if (res.isErr()) throw res.error;
		wallet = res.value;
		// The failed (offline) refresh still generates index-0 addresses.
		await wallet.refreshWallet({});
	});

	after(async function () {
		await wallet?.stop();
	});

	afterEach(function () {
		sinon.restore();
	});

	it('sweeps the coins above the threshold and leaves a 293 sat one behind', async () => {
		const funded = keyCoin('11'.repeat(32), 10_000);
		keyHolds([funded, keyCoin('22'.repeat(32), 293)]);

		const res = await wallet.sweepPrivateKey({
			privateKey: keyPair.toWIF(),
			toAddress: RECIPIENT,
			satsPerByte: 1,
			broadcast: false
		});
		if (res.isErr()) throw res.error;

		const tx = BitcoinTransaction.fromHex(res.value.hex);
		expect(
			tx.ins.map((input) => Buffer.from(input.hash).reverse().toString('hex'))
		).to.deep.equal([funded.tx_hash]);
		expect(tx.outs).to.have.length(1);
		expect(res.value.balance).to.equal(10_000);
		const fee = 10_000 - tx.outs[0].value;
		expect(fee).to.be.at.least(tx.virtualSize());
		expect(fee).to.be.below(10_000);
	});

	it('refuses a key whose every coin is below the threshold', async () => {
		// Together over the flat 546 getPrivateKeyInfo checks, each under 294.
		keyHolds([keyCoin('33'.repeat(32), 293), keyCoin('44'.repeat(32), 293)]);
		// A wallet coin, so an empty input set cannot fall back to the
		// wallet's own coins unnoticed.
		const source = wallet.data.addressIndex[EAddressType.p2wpkh];
		wallet.data.utxos.push({
			address: source.address,
			index: source.index,
			path: source.path,
			scriptHash: source.scriptHash,
			height: 1,
			tx_hash: '55'.repeat(32),
			tx_pos: 0,
			value: 50_000,
			publicKey: source.publicKey
		});

		const res = await wallet.sweepPrivateKey({
			privateKey: keyPair.toWIF(),
			toAddress: RECIPIENT,
			satsPerByte: 1,
			broadcast: false
		});

		expect(res.isErr(), 'the sweep was refused').to.equal(true);
		if (res.isOk()) return;
		expect(res.error.message).to.equal(
			'Every UTXO held by this key is below the dust limit.'
		);
		expect(wallet.transaction.data.inputs).to.have.length(0);
	});
});
