/**
 * Issue #1527: the fee estimators priced a P2PKH input as if its key were
 * compressed. An uncompressed key is 32 bytes longer, so a payment signed
 * with one went out below the rate it was quoted at.
 *
 * Fully OFFLINE: the wallet never connects (remainOffline) and the
 * previous-transaction fetch is stubbed.
 */

import { expect } from 'chai';
import net from 'net';
import tls from 'tls';
import ecc from '@bitcoinerlab/secp256k1';
import * as bitcoin from 'bitcoinjs-lib';
import { ECPairFactory } from 'ecpair';

import {
	EAddressType,
	EAvailableNetworks,
	ECoinSelectPreference,
	IUtxo,
	ok,
	Result,
	Wallet
} from '../src';

const ECPair = ECPairFactory(ecc);

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const RECIPIENT = 'bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk';
const regtest = bitcoin.networks.regtest;
const RATE = 10;
const INPUT_VALUE = 10_000;

const electrumOptions = { net, tls };

const keyPair = ECPair.fromPrivateKey(Buffer.alloc(32, 0x5a), {
	network: regtest,
	compressed: false
});
const p2pkh = bitcoin.payments.p2pkh({
	pubkey: keyPair.publicKey,
	network: regtest
});
const segwitKeyPair = ECPair.fromPrivateKey(Buffer.alloc(32, 0x5b), {
	network: regtest
});
const p2wpkh = bitcoin.payments.p2wpkh({
	pubkey: segwitKeyPair.publicKey,
	network: regtest
});
const SEGWIT_VALUE = 20_000;
const prevTx = new bitcoin.Transaction();
prevTx.addInput(Buffer.alloc(32, 1), 0);
prevTx.addOutput(p2pkh.output as Buffer, INPUT_VALUE);
prevTx.addOutput(p2wpkh.output as Buffer, SEGWIT_VALUE);

const input: IUtxo = {
	address: p2pkh.address as string,
	index: 0,
	path: '',
	scriptHash: '00'.repeat(32),
	height: 1,
	tx_hash: prevTx.getId(),
	tx_pos: 0,
	value: INPUT_VALUE,
	publicKey: keyPair.publicKey.toString('hex'),
	keyPair
};

const segwitInput: IUtxo = {
	...input,
	address: p2wpkh.address as string,
	tx_pos: 1,
	value: SEGWIT_VALUE,
	publicKey: segwitKeyPair.publicKey.toString('hex'),
	keyPair: segwitKeyPair
};

describe('Fee estimation for an uncompressed P2PKH input (#1527)', function () {
	this.timeout(60000);

	let wallet: Wallet;
	let changeAddress: string;

	before(async () => {
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			network: EAvailableNetworks.regtest,
			addressType: EAddressType.p2wpkh,
			electrumOptions,
			remainOffline: true,
			name: 'uncompressedp2pkhfee'
		});
		if (res.isErr()) throw res.error;
		wallet = res.value;
		// Populates the change address; the Electrum sync fails harmlessly
		// offline.
		await wallet.refreshWallet({});
		changeAddress = wallet.data.changeAddressIndex[EAddressType.p2wpkh].address;
		expect(changeAddress).to.match(/^bcrt1q/);
		const electrum = wallet.electrum as unknown as {
			getTransactions: (args: {
				txHashes: { tx_hash: string }[];
			}) => Promise<unknown>;
		};
		electrum.getTransactions = async ({ txHashes }): Promise<unknown> =>
			ok({
				data: txHashes.map(({ tx_hash }) => ({
					data: { tx_hash },
					result: { hex: prevTx.toHex() }
				}))
			});
	});

	after(async () => {
		await wallet?.stop();
	});

	/** Stages the payment with P2WPKH change and prices it at RATE. */
	const stage = async (payment: number): Promise<Result<{ fee: number }>> => {
		await wallet.transaction.resetSendTransaction();
		const staged = wallet.transaction.updateSendTransaction({
			transaction: {
				inputs: [input],
				outputs: [{ address: RECIPIENT, value: payment, index: 0 }],
				changeAddress,
				satsPerByte: RATE
			}
		});
		if (staged.isErr()) throw staged.error;
		return wallet.transaction.updateFee({ satsPerByte: RATE });
	};

	[
		// 1,480 sats of change.
		{ payment: 6_000, outputCount: 2 },
		// The 80 sats left once the change output is paid for are under dust
		// and go to the fee.
		{ payment: 7_400, outputCount: 1 }
	].forEach(({ payment, outputCount }) => {
		const kind = outputCount === 2 ? 'with' : 'without';
		it(`pays ${RATE} sat/vB ${kind} change`, async () => {
			const fee = await stage(payment);
			if (fee.isErr()) throw fee.error;
			const quote = wallet.transaction.getTotalFeeObj({ satsPerByte: RATE });
			if (quote.isErr()) throw quote.error;
			expect(quote.value.totalFee).to.equal(fee.value.fee);

			const res = await wallet.transaction.createTransaction({});
			if (res.isErr()) throw res.error;
			const tx = bitcoin.Transaction.fromHex(res.value.hex);
			const paid =
				INPUT_VALUE - tx.outs.reduce((total, out) => total + out.value, 0);
			expect(paid).to.be.at.least(RATE * tx.virtualSize());
			expect(tx.outs).to.have.length(outputCount);
		});
	});

	it('refuses a leftover that pays the rate only for a compressed key', async () => {
		// 2,100 sats covers the 189 vB of a compressed spend without change, but
		// not the 221 vB of this one.
		const fee = await stage(7_900);
		expect(fee.isErr(), 'the fee update was refused').to.equal(true);
		if (fee.isOk()) return;
		expect(fee.error.message).to.equal(
			'New total amount exceeds the available balance. Unable to update the transaction fee.'
		);
	});

	it('selects another coin when an uncompressed spend needs one (#1550)', async () => {
		// The 10,000 sat coin covers 7,800 plus the 2,200 a compressed key
		// would cost, but not the 2,520 this one does.
		wallet.updateCoinSelectPreference(ECoinSelectPreference.small);
		try {
			await wallet.transaction.resetSendTransaction();
			const staged = wallet.transaction.updateSendTransaction({
				transaction: {
					inputs: [input, segwitInput],
					outputs: [{ address: RECIPIENT, value: 7_800, index: 0 }],
					changeAddress,
					satsPerByte: RATE
				}
			});
			if (staged.isErr()) throw staged.error;
			const fee = wallet.transaction.updateFee({ satsPerByte: RATE });
			if (fee.isErr()) throw fee.error;
			expect(fee.value.fee).to.equal(3_210);

			const res = await wallet.transaction.createTransaction({
				runCoinSelect: true
			});
			if (res.isErr()) throw res.error;
			const tx = bitcoin.Transaction.fromHex(res.value.hex);
			expect(tx.ins).to.have.length(2);
			const paid =
				INPUT_VALUE +
				SEGWIT_VALUE -
				tx.outs.reduce((total, out) => total + out.value, 0);
			expect(paid).to.equal(3_210);
			expect(paid).to.be.at.least(RATE * tx.virtualSize());
		} finally {
			wallet.updateCoinSelectPreference(ECoinSelectPreference.consolidate);
		}
	});

	it('prices Taproot inputs equally for compressed and uncompressed signing keys', async () => {
		const taproot = bitcoin.payments.p2tr({
			internalPubkey: keyPair.publicKey.subarray(1, 33),
			network: regtest
		});
		const funding = new bitcoin.Transaction();
		funding.addInput(Buffer.alloc(32, 2), 0);
		funding.addOutput(taproot.output!, INPUT_VALUE);
		funding.addOutput(taproot.output!, INPUT_VALUE);
		for (const compressed of [true, false]) {
			await wallet.transaction.resetSendTransaction();
			wallet.transaction.updateSendTransaction({
				transaction: {
					outputs: [{ address: RECIPIENT, value: 10_000, index: 0 }],
					changeAddress,
					satsPerByte: RATE
				}
			});
			const added = wallet.transaction.addExternalInputs({
				inputs: [0, 1].map((tx_pos) => ({
					...input,
					address: taproot.address!,
					tx_hash: funding.getId(),
					tx_pos
				})),
				keyPair: ECPair.fromPrivateKey(keyPair.privateKey!, {
					network: regtest,
					compressed
				})
			});
			if (added.isErr()) throw added.error;
			const quote = wallet.transaction.getTotalFeeObj({ satsPerByte: RATE });
			if (quote.isErr()) throw quote.error;
			expect(quote.value.totalFee).to.equal(1_880);
			expect(wallet.transaction.getTotalFee({ satsPerByte: RATE })).to.equal(
				1_880
			);
			const res = await wallet.transaction.createTransaction({});
			if (res.isErr()) throw res.error;
			const tx = bitcoin.Transaction.fromHex(res.value.hex);
			expect(tx.virtualSize()).to.equal(188);
			const paid =
				2 * INPUT_VALUE - tx.outs.reduce((total, out) => total + out.value, 0);
			expect(paid).to.equal(RATE * tx.virtualSize());
		}
	});
});
