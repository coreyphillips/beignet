/**
 * Regression tests for issue #1362: a refresh kept every coin below a flat 546
 * sats out of the UTXO set but still counted it in the balance, and the input
 * guards refused it too. Dust is a per-script threshold (294 sats for P2WPKH),
 * so a 400 sat P2WPKH coin was shown as funds that no send could ever spend.
 *
 * Fully OFFLINE: the wallet points at an unreachable Electrum port and the
 * scan is stubbed.
 */

import { expect } from 'chai';
import net from 'net';
import sinon from 'sinon';
import tls from 'tls';
import { payments, networks } from 'bitcoinjs-lib';
import { bech32m } from 'bech32';

import {
	EAddressType,
	EAvailableNetworks,
	EProtocol,
	IUtxo,
	Wallet,
	decodeRawTransaction,
	err,
	ok,
	removeDustUtxos
} from '../src';

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

const EXTERNAL_ADDRESS = 'bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk';

const network = networks.regtest;
const pubkey = Buffer.from(
	'0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
	'hex'
);

const sum = (utxos: IUtxo[]): number =>
	utxos.reduce((total, utxo) => total + utxo.value, 0);

describe('Dust thresholds for wallet coins (#1362)', function () {
	this.timeout(60000);

	describe('removeDustUtxos', function () {
		// Bitcoin Core's thresholds at the default dust relay fee, with the path
		// purpose removeDustUtxos also requires.
		const CASES = [
			{
				type: 'p2wpkh',
				address: payments.p2wpkh({ pubkey, network }).address as string,
				path: "m/84'/1'/0'/0/0",
				threshold: 294
			},
			{
				type: 'p2tr',
				address: bech32m.encode('bcrt', [
					1,
					...bech32m.toWords(pubkey.subarray(1, 33))
				]),
				path: "m/86'/1'/0'/0/0",
				threshold: 330
			},
			{
				type: 'p2sh',
				address: payments.p2sh({
					redeem: payments.p2wpkh({ pubkey, network }),
					network
				}).address as string,
				path: "m/49'/1'/0'/0/0",
				threshold: 540
			},
			{
				type: 'p2pkh',
				address: payments.p2pkh({ pubkey, network }).address as string,
				path: "m/44'/1'/0'/0/0",
				threshold: 546
			}
		];

		CASES.forEach(({ type, address, path, threshold }) => {
			it(`keeps a ${type} coin at ${threshold} and drops one at ${
				threshold - 1
			}`, function () {
				const coin = (value: number): IUtxo => ({
					address,
					index: 0,
					path,
					scriptHash: '00'.repeat(32),
					height: 1,
					tx_hash: value.toString(16).padStart(64, '0'),
					tx_pos: 0,
					value,
					publicKey: pubkey.toString('hex')
				});
				const kept = removeDustUtxos([coin(threshold - 1), coin(threshold)]);
				expect(kept.map((utxo) => utxo.value)).to.deep.equal([threshold]);
			});
		});
	});

	describe('wallet', function () {
		let wallet: Wallet;

		/** A coin paying the wallet's own index 0 P2WPKH address. */
		const coin = (txid: string, value: number): IUtxo => {
			const source = wallet.data.addressIndex[EAddressType.p2wpkh];
			return {
				address: source.address,
				index: source.index,
				path: source.path,
				scriptHash: source.scriptHash,
				height: 1,
				tx_hash: txid,
				tx_pos: 0,
				value,
				publicKey: source.publicKey
			};
		};

		/** Makes the next scan answer with the given coins. */
		const scanAnswers = (utxos: IUtxo[]): void => {
			sinon.stub(wallet, 'checkElectrumConnection').resolves(ok('connected'));
			sinon
				.stub(wallet.electrum, 'getUtxos')
				.resolves(ok({ utxos, balance: sum(utxos) }));
		};

		before(async function () {
			const res = await Wallet.create({
				mnemonic: MNEMONIC,
				name: 'dustutxos',
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

		it('leaves a sub-dust coin out of the balance as well as the set', async () => {
			const big = coin('11'.repeat(32), 60000);
			const small = coin('22'.repeat(32), 400);
			const dust = coin('33'.repeat(32), 293);
			scanAnswers([big, small, dust]);

			const scanRes = await wallet.getUtxos({});
			if (scanRes.isErr()) throw scanRes.error;
			expect(scanRes.value.utxos).to.deep.equal([big, small]);
			expect(scanRes.value.balance).to.equal(60400);
			expect(wallet.listUtxos()).to.deep.equal([big, small]);
			expect(wallet.getBalance()).to.equal(60400);
		});

		it('spends P2WPKH coins between 294 and 545 sats', async () => {
			const coins = ['44', '55', '66'].map((byte) =>
				coin(byte.repeat(32), 400)
			);
			scanAnswers(coins);
			const scanRes = await wallet.getUtxos({});
			if (scanRes.isErr()) throw scanRes.error;
			expect(wallet.getBalance()).to.equal(1200);

			// Segwit inputs build from witnessUtxo when the previous transaction
			// cannot be fetched.
			sinon.stub(wallet.electrum, 'getTransactions').resolves(err('offline'));
			const sendRes = await wallet.sendMax({
				address: EXTERNAL_ADDRESS,
				satsPerByte: 1,
				broadcast: false
			});
			if (sendRes.isErr()) throw sendRes.error;
			const decoded = decodeRawTransaction(sendRes.value, wallet.network);
			if (decoded.isErr()) throw decoded.error;
			expect(
				decoded.value.vin.map((vin) => `${vin.txid}:${vin.vout}`)
			).to.have.members(coins.map((c) => `${c.tx_hash}:${c.tx_pos}`));
		});

		it('addTxInput applies the P2WPKH threshold', async () => {
			await wallet.resetSendTransaction();
			const rejected = wallet.addTxInput({ input: coin('77'.repeat(32), 293) });
			expect(rejected.isErr(), '293 sats is dust for p2wpkh').to.equal(true);
			const accepted = wallet.addTxInput({ input: coin('88'.repeat(32), 294) });
			if (accepted.isErr()) throw accepted.error;
			expect(accepted.value.map((utxo) => utxo.value)).to.deep.equal([294]);
			await wallet.resetSendTransaction();
		});
	});
});
