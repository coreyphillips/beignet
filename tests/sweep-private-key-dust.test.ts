/**
 * Regression tests for issue #1434: sweepPrivateKey staged every coin the key
 * held, and addInput refuses one below its script's dust threshold, so a
 * single 293 sat P2WPKH deposit aborted the sweep of the key's other coins.
 * Issue #1433: a key holding under 546 sats in total was refused before sweep
 * pricing, so its coins could not even join a sweep of the wallet's funds.
 * Issue #1466: a combined sweep also spent the wallet's frozen coins.
 * Issue #1467: a lone 500 sat coin could not pay for its own sweep at 1 sat/vB.
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
		wallet.data.utxos = [];
		wallet.data.blacklistedUtxos = [];
	});

	/** Adds a coin paying the wallet's own index-0 P2WPKH address. */
	const walletHolds = (txid: string, value: number): void => {
		const source = wallet.data.addressIndex[EAddressType.p2wpkh];
		wallet.data.utxos.push({
			address: source.address,
			index: source.index,
			path: source.path,
			scriptHash: source.scriptHash,
			height: 1,
			tx_hash: txid,
			tx_pos: 0,
			value,
			publicKey: source.publicKey
		});
	};

	/** The txids a signed transaction spends, in input order. */
	const spentTxids = (tx: BitcoinTransaction): string[] =>
		tx.ins.map((input) => Buffer.from(input.hash).reverse().toString('hex'));

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
		expect(spentTxids(tx)).to.deep.equal([funded.tx_hash]);
		expect(tx.outs).to.have.length(1);
		expect(res.value.balance).to.equal(10_000);
		const fee = 10_000 - tx.outs[0].value;
		expect(fee).to.be.at.least(tx.virtualSize());
		expect(fee).to.be.below(10_000);
	});

	it('refuses a key whose every coin is below the threshold', async () => {
		keyHolds([keyCoin('33'.repeat(32), 293), keyCoin('44'.repeat(32), 293)]);
		// A wallet coin, so an empty input set cannot fall back to the
		// wallet's own coins unnoticed.
		walletHolds('55'.repeat(32), 50_000);

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

	it('reports a key holding less than 546 sats', async () => {
		keyHolds([keyCoin('66'.repeat(32), 500)]);

		const res = await wallet.getPrivateKeyInfo(keyPair.toWIF());
		if (res.isErr()) throw res.error;

		expect(res.value.balance).to.equal(500);
		expect(res.value.utxos.map((utxo) => utxo.value)).to.deep.equal([500]);
	});

	it('sweeps a 500 sat coin together with the wallet coins', async () => {
		const coin = keyCoin('88'.repeat(32), 500);
		keyHolds([coin]);
		walletHolds('99'.repeat(32), 20_000);

		const res = await wallet.sweepPrivateKey({
			privateKey: keyPair.toWIF(),
			toAddress: RECIPIENT,
			satsPerByte: 1,
			broadcast: false,
			combineWithWalletUtxos: true
		});
		if (res.isErr()) throw res.error;

		const tx = BitcoinTransaction.fromHex(res.value.hex);
		expect(spentTxids(tx)).to.have.members(['99'.repeat(32), coin.tx_hash]);
		expect(tx.outs).to.have.length(1);
		expect(20_500 - tx.outs[0].value).to.be.at.least(tx.virtualSize());
	});

	it('leaves a frozen wallet coin out of a combined sweep (#1466)', async () => {
		const coin = keyCoin('bb'.repeat(32), 10_000);
		keyHolds([coin]);
		walletHolds('cc'.repeat(32), 50_000);
		walletHolds('dd'.repeat(32), 20_000);
		const frozen = await wallet.freezeUtxo({ txid: 'cc'.repeat(32), index: 0 });
		if (frozen.isErr()) throw frozen.error;

		const res = await wallet.sweepPrivateKey({
			privateKey: keyPair.toWIF(),
			toAddress: RECIPIENT,
			satsPerByte: 1,
			broadcast: false,
			combineWithWalletUtxos: true
		});
		if (res.isErr()) throw res.error;

		const tx = BitcoinTransaction.fromHex(res.value.hex);
		expect(spentTxids(tx)).to.have.members(['dd'.repeat(32), coin.tx_hash]);
		expect(tx.outs).to.have.length(1);
		const fee = 30_000 - tx.outs[0].value;
		expect(fee).to.be.at.least(tx.virtualSize());
		expect(fee).to.be.below(1_000);
	});

	it('sweeps a lone 500 sat coin at 1 sat/vB (#1467)', async () => {
		// Padded to 256 vB, the fee left 244 sats for a destination whose
		// threshold is 294.
		const coin = keyCoin('aa'.repeat(32), 500);
		keyHolds([coin]);

		const res = await wallet.sweepPrivateKey({
			privateKey: keyPair.toWIF(),
			toAddress: RECIPIENT,
			satsPerByte: 1,
			broadcast: false
		});
		if (res.isErr()) throw res.error;

		const tx = BitcoinTransaction.fromHex(res.value.hex);
		expect(spentTxids(tx)).to.deep.equal([coin.tx_hash]);
		expect(tx.outs).to.have.length(1);
		expect(tx.outs[0].value).to.be.at.least(294);
		expect(500 - tx.outs[0].value).to.be.at.least(tx.virtualSize());
	});

	it('refuses a key that holds no coins', async () => {
		keyHolds([]);

		const res = await wallet.sweepPrivateKey({
			privateKey: keyPair.toWIF(),
			toAddress: RECIPIENT,
			satsPerByte: 1,
			broadcast: false
		});

		expect(res.isErr(), 'the sweep was refused').to.equal(true);
		if (res.isOk()) return;
		expect(res.error.message).to.equal('No UTXOs found for this private key.');
	});
});
