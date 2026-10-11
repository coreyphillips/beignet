/**
 * Issue #1562: the quote checked for generated change at its maximum rate
 * using the size at the requested rate. Three 366-sat inputs paying 550 sats
 * leave 302 sats at the 246 vB of 2 sat/vB, which counts change. At 1 sat/vB
 * the 256 vB floor leaves 292, under dust, so updateFee prices no change.
 * The quote priced change anyway and advertised 0 sat/vB.
 *
 * Fully OFFLINE: the wallet points at an unreachable Electrum server and the
 * UTXOs are fabricated.
 */

import { expect } from 'chai';
import net from 'net';
import tls from 'tls';

import {
	EAddressType,
	EAvailableNetworks,
	ECoinSelectPreference,
	EProtocol,
	getScriptHash,
	IUtxo,
	Wallet
} from '../src';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const RECIPIENT = 'bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk';
const network = EAvailableNetworks.regtest;
const PATH = "m/84'/1'/0'/0/0";
const INPUT_VALUE = 366;
const PAYMENT = 550;

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

describe('Generated change at the quoted maximum (#1562)', function () {
	this.timeout(60000);

	let wallet: Wallet;
	let inputs: IUtxo[];

	before(async () => {
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			network,
			addressType: EAddressType.p2wpkh,
			coinSelectPreference: ECoinSelectPreference.consolidate,
			electrumOptions,
			name: 'generatedchangequoterate'
		});
		if (res.isErr()) throw res.error;
		wallet = res.value;
		// Populates the change address; the Electrum sync fails harmlessly
		// offline.
		await wallet.refreshWallet({});

		const address = await wallet.getAddress({
			index: '0',
			addressType: EAddressType.p2wpkh
		});
		const node = wallet.derivePublicNode(PATH);
		if (node.isErr()) throw node.error;
		inputs = [0, 1, 2].map((tx_pos) => ({
			address,
			index: 0,
			path: PATH,
			scriptHash: getScriptHash({ address, network }),
			height: 100,
			tx_hash: '11'.repeat(32),
			tx_pos,
			value: INPUT_VALUE,
			publicKey: node.value.publicKey.toString('hex')
		}));
	});

	after(async () => {
		await wallet?.stop();
	});

	it('advertises the rate updateFee accepts without change', async () => {
		await wallet.transaction.resetSendTransaction();
		const staged = wallet.transaction.updateSendTransaction({
			transaction: {
				inputs,
				outputs: [{ address: RECIPIENT, value: PAYMENT, index: 0 }],
				changeAddress: ''
			}
		});
		if (staged.isErr()) throw staged.error;

		const quote = wallet.transaction.getTotalFeeObj({ satsPerByte: 2 });
		if (quote.isErr()) throw quote.error;
		expect(quote.value.maxSatPerByte).to.equal(1);
		expect(quote.value.satsPerByte).to.equal(1);
		expect(quote.value.totalFee).to.equal(256);

		const fee = wallet.transaction.updateFee({
			satsPerByte: quote.value.satsPerByte
		});
		if (fee.isErr()) throw new Error(fee.error.message);
		expect(fee.value.fee).to.equal(quote.value.totalFee);
	});
});
