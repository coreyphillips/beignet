/**
 * Issue #1808: getByteCount has no weight for a P2WSH input outside a
 * multisig wallet, so getTotalFeeObj sized such a send at 0 vB, took an
 * unbounded maximum rate and never returned from its rate search.
 *
 * Fully OFFLINE: the wallets never connect (remainOffline) and the UTXOs are
 * fabricated.
 */

import { expect } from 'chai';
import net from 'net';
import tls from 'tls';
import BIP32Factory from 'bip32';
import * as ecc from '@bitcoinerlab/secp256k1';
import * as bip39 from 'bip39';
import * as bitcoin from 'bitcoinjs-lib';

import {
	EAddressType,
	EAvailableNetworks,
	ECoinSelectPreference,
	getScriptHash,
	IUtxo,
	Wallet
} from '../src';

const bip32 = BIP32Factory(ecc);

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const COSIGNER_MNEMONICS = [
	'legal winner thank year wave sausage worth useful legal winner thank yellow',
	'letter advice cage absurd amount doctor acoustic avoid letter advice cage above'
];
const RECIPIENT = 'bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk';
const regtest = bitcoin.networks.regtest;
const network = EAvailableNetworks.regtest;
const MULTISIG_ACCOUNT_PATH = "m/48'/1'/0'/2'";
const INPUT_VALUE = 100_000;
const PAYMENT = 10_000;

const electrumOptions = { net, tls };

const utxoAt = (address: string, path: string, publicKey: string): IUtxo => ({
	address,
	index: 0,
	path,
	scriptHash: getScriptHash({ address, network }),
	height: 100,
	tx_hash: '11'.repeat(32),
	tx_pos: 0,
	value: INPUT_VALUE,
	publicKey
});

describe('Fee quote for a P2WSH input outside a multisig wallet (#1808)', function () {
	this.timeout(60000);

	const wallets: Wallet[] = [];

	after(async () => {
		await Promise.all(wallets.map((wallet) => wallet.stop()));
	});

	describe('single-key wallet', () => {
		let wallet: Wallet;
		let changeAddress: string;
		let p2wpkhInput: IUtxo;
		let p2wshInput: IUtxo;

		before(async () => {
			const res = await Wallet.create({
				mnemonic: MNEMONIC,
				network,
				addressType: EAddressType.p2wpkh,
				coinSelectPreference: ECoinSelectPreference.consolidate,
				electrumOptions,
				remainOffline: true,
				name: 'p2wshquotewithoutmultisig'
			});
			if (res.isErr()) throw res.error;
			wallet = res.value;
			wallets.push(wallet);
			// Populates the change address; the Electrum sync fails harmlessly
			// offline.
			await wallet.refreshWallet({});
			changeAddress =
				wallet.data.changeAddressIndex[EAddressType.p2wpkh].address;
			expect(changeAddress).to.match(/^bcrt1q/);

			const path = "m/84'/1'/0'/0/0";
			const node = wallet.derivePublicNode(path);
			if (node.isErr()) throw node.error;
			const publicKey = node.value.publicKey.toString('hex');
			const address = await wallet.getAddress({
				index: '0',
				addressType: EAddressType.p2wpkh
			});
			p2wpkhInput = utxoAt(address, path, publicKey);
			const p2wsh = bitcoin.payments.p2wsh({
				hash: Buffer.alloc(32, 1),
				network: regtest
			}).address;
			if (!p2wsh) throw new Error('expected a P2WSH address');
			p2wshInput = utxoAt(p2wsh, path, publicKey);
		});

		const quote = (
			input: IUtxo,
			satsPerByte: number,
			coinSelectPreference = ECoinSelectPreference.consolidate
		): ReturnType<Wallet['transaction']['getTotalFeeObj']> =>
			wallet.transaction.getTotalFeeObj({
				satsPerByte,
				coinSelectPreference,
				transaction: {
					inputs: [input],
					outputs: [{ address: RECIPIENT, value: PAYMENT, index: 0 }],
					changeAddress
				}
			});

		it('prices the same send from a P2WPKH input', () => {
			const res = quote(p2wpkhInput, 2);
			if (res.isErr()) throw res.error;
			expect(res.value.transactionByteCount).to.equal(141);
			expect(res.value.totalFee).to.equal(282);
		});

		const expectUnsized = (
			res: ReturnType<Wallet['transaction']['getTotalFeeObj']>
		): void => {
			expect(res.isErr()).to.equal(true);
			if (res.isOk()) return;
			expect(res.error.message).to.match(/Unable to size the transaction/);
		};

		// Under 2 sat/vB the size floor hid the missing weight. At 2 and up the
		// quote never returned.
		[1, 2, 25].forEach((satsPerByte) => {
			it(`refuses to quote it at ${satsPerByte} sat/vB`, () => {
				expectUnsized(quote(p2wshInput, satsPerByte));
			});
		});

		it('refuses to quote it when coin selection runs', () => {
			expectUnsized(quote(p2wshInput, 2, ECoinSelectPreference.small));
		});
	});

	describe('multisig wallet', () => {
		let wallet: Wallet;

		before(async () => {
			const cosigners = COSIGNER_MNEMONICS.map((mnemonic) =>
				bip32
					.fromSeed(bip39.mnemonicToSeedSync(mnemonic), regtest)
					.derivePath(MULTISIG_ACCOUNT_PATH)
					.neutered()
					.toBase58()
			);
			const res = await Wallet.createMultisig({
				threshold: 2,
				mnemonic: MNEMONIC,
				cosigners,
				network,
				electrumOptions,
				remainOffline: true
			});
			if (res.isErr()) throw res.error;
			wallet = res.value;
			wallets.push(wallet);
		});

		it('still prices a P2WSH input with its 2-of-3 script', async () => {
			const address = await wallet.getAddress({ index: '0' });
			const changeAddress = await wallet.getAddress({
				index: '0',
				changeAddress: true
			});
			const res = wallet.transaction.getTotalFeeObj({
				satsPerByte: 2,
				coinSelectPreference: ECoinSelectPreference.consolidate,
				transaction: {
					inputs: [
						utxoAt(address, `${MULTISIG_ACCOUNT_PATH}/0/0`, '02'.repeat(33))
					],
					outputs: [{ address: RECIPIENT, value: PAYMENT, index: 0 }],
					changeAddress
				}
			});
			if (res.isErr()) throw res.error;
			// Input: 8 + 41 * 4 + 73 * 2 + 34 * 3 = 420 WU. Outputs: P2WPKH 124 WU
			// and P2WSH change 172 WU. Marker and flag 2, version, locktime and
			// counts 40. 758 WU rounds up to 190 vB.
			expect(res.value.transactionByteCount).to.equal(190);
			expect(res.value.totalFee).to.equal(380);
			expect(res.value.satsPerByte).to.equal(2);
		});
	});
});
