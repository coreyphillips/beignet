/**
 * Issue #1465: with no change address staged, the fee estimate priced the
 * transaction without change, and the PSBT builder then fetched a change
 * address and added the output anyway. Four P2WPKH inputs and 600 sats of
 * change went out at 314 sats for 344 vB, under the 1 sat/vB asked for.
 *
 * Fully OFFLINE: the wallet points at an unreachable Electrum server, the UTXOs
 * are fabricated and the previous-transaction fetch is stubbed.
 */

import { expect } from 'chai';
import net from 'net';
import tls from 'tls';
import * as ecc from '@bitcoinerlab/secp256k1';
import * as bitcoin from 'bitcoinjs-lib';

import {
	EAddressType,
	EAvailableNetworks,
	ECoinSelectPreference,
	EProtocol,
	getScriptHash,
	IUtxo,
	ok,
	Wallet
} from '../src';
import { getByteCount } from '../src/utils/transaction';

bitcoin.initEccLib(ecc);

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const RECIPIENT = 'bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk';
const regtest = bitcoin.networks.regtest;
const network = EAvailableNetworks.regtest;
const PATH = "m/84'/1'/0'/0/0";
const INPUT_COUNT = 4;
const INPUT_VALUE = 10_000;
const INPUT_TOTAL = INPUT_COUNT * INPUT_VALUE;

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

describe('Fee estimation with generated change (#1465)', function () {
	this.timeout(120000);

	let wallet: Wallet;
	// Never refreshed, so its change index is unset and the builder derives
	// change through getChangeAddress.
	let freshWallet: Wallet;
	let inputs: IUtxo[];
	let changeAddress: string;

	before(async () => {
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			network,
			addressType: EAddressType.p2wpkh,
			electrumOptions,
			name: 'generatedchangefee'
		});
		if (res.isErr()) throw res.error;
		wallet = res.value;
		const fresh = await Wallet.create({
			mnemonic: MNEMONIC,
			network,
			addressType: EAddressType.p2wpkh,
			electrumOptions,
			name: 'generatedchangefeefresh',
			disableRefreshOnCreate: true
		});
		if (fresh.isErr()) throw fresh.error;
		freshWallet = fresh.value;
		expect(freshWallet.data.changeAddressIndex[EAddressType.p2wpkh].address).to
			.be.empty;
		// Populates the change address; the Electrum sync fails harmlessly
		// offline.
		await wallet.refreshWallet({});
		changeAddress = wallet.data.changeAddressIndex[EAddressType.p2wpkh].address;
		expect(changeAddress).to.match(/^bcrt1q/);

		const address = await wallet.getAddress({
			index: '0',
			addressType: EAddressType.p2wpkh
		});
		const node = wallet.derivePublicNode(PATH);
		if (node.isErr()) throw node.error;
		const prevTx = new bitcoin.Transaction();
		prevTx.addInput(Buffer.alloc(32, 1), 0);
		for (let i = 0; i < INPUT_COUNT; i++) {
			prevTx.addOutput(
				bitcoin.address.toOutputScript(address, regtest),
				INPUT_VALUE
			);
		}
		inputs = Array.from({ length: INPUT_COUNT }, (_, i) => ({
			address,
			index: 0,
			path: PATH,
			scriptHash: getScriptHash({ address, network }),
			height: 100,
			tx_hash: prevTx.getId(),
			tx_pos: i,
			value: INPUT_VALUE,
			publicKey: node.value.publicKey.toString('hex')
		}));
		for (const target of [wallet, freshWallet]) {
			const electrum = target.electrum as unknown as {
				getTransactions: () => Promise<unknown>;
			};
			electrum.getTransactions = async (): Promise<unknown> =>
				ok({ data: [{ result: { hex: prevTx.toHex() } }] });
		}
	});

	after(async () => {
		await wallet?.stop();
		await freshWallet?.stop();
	});

	/** The four inputs and the payment, plus one change output if asked. */
	const priceAt = (satsPerByte: number, withChange: boolean): number =>
		getByteCount({ P2WPKH: INPUT_COUNT }, { P2WPKH: withChange ? 2 : 1 }) *
		satsPerByte;

	[
		// The issue's reproduction: 39,086 sats paid, 600 sats left over.
		{ satsPerByte: 1, leftover: 600, pricedWithChange: true, change: true },
		{ satsPerByte: 5, leftover: 600, pricedWithChange: true, change: true },
		// Priced with change, the 269 sats left once the change output pays for
		// itself are under P2WPKH dust (294) and go to the fee. Priced without,
		// the builder would add 300 sats of change at the cheaper fee.
		{ satsPerByte: 1, leftover: 300, pricedWithChange: true, change: false },
		{ satsPerByte: 1, leftover: 200, pricedWithChange: false, change: false },
		{
			satsPerByte: 1,
			leftover: 600,
			pricedWithChange: true,
			change: true,
			fresh: true
		}
	].forEach(({ satsPerByte, leftover, pricedWithChange, change, fresh }) => {
		const title = `meets ${satsPerByte} sat/vB with ${leftover} sats left over`;
		it(fresh ? `${title} before the change index is set` : title, async () => {
			const target = fresh ? freshWallet : wallet;
			const payment = INPUT_TOTAL - priceAt(satsPerByte, false) - leftover;
			const transaction = {
				inputs,
				outputs: [{ address: RECIPIENT, value: payment, index: 0 }],
				changeAddress: '',
				satsPerByte
			};
			const fee = target.transaction.getTotalFee({
				satsPerByte,
				transaction,
				coinSelectPreference: ECoinSelectPreference.consolidate
			});
			const feeObj = target.transaction.getTotalFeeObj({
				satsPerByte,
				transaction,
				coinSelectPreference: ECoinSelectPreference.consolidate
			});
			if (feeObj.isErr()) throw feeObj.error;
			expect(fee).to.equal(priceAt(satsPerByte, pricedWithChange));
			expect(feeObj.value.totalFee).to.equal(fee);

			await target.transaction.resetSendTransaction();
			target.transaction.updateSendTransaction({
				transaction: { ...transaction, fee }
			});
			const res = await target.transaction.createTransaction({
				shuffleOutputs: false
			});
			if (res.isErr()) throw res.error;

			const tx = bitcoin.Transaction.fromHex(res.value.hex);
			const outputs = tx.outs.map((out) => ({
				address: bitcoin.address.fromOutputScript(out.script, regtest),
				value: out.value
			}));
			expect(outputs[0]).to.deep.equal({ address: RECIPIENT, value: payment });
			if (change) {
				expect(outputs).to.have.length(2);
				expect(outputs[1].address).to.equal(changeAddress);
			} else {
				expect(outputs).to.have.length(1);
			}
			const paid =
				INPUT_TOTAL - outputs.reduce((acc, { value }) => acc + value, 0);
			expect(paid).to.be.at.least(satsPerByte * tx.virtualSize());
		});
	});
});
