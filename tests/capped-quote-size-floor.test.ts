/**
 * Issue #1543: a quote capped below 2 sat/vB left out the 256 vB size floor
 * updateFee prices at that rate. A 500-sat consolidate send quoted at 2 sat/vB
 * advertised 1 sat/vB for 166 sats, and updateFee then refused 256 sats
 * against the 250-sat half-output limit.
 *
 * Fully OFFLINE: the wallet never connects (remainOffline) and the UTXOs are
 * fabricated.
 */

import { expect } from 'chai';
import net from 'net';
import tls from 'tls';

import {
	EAddressType,
	EAvailableNetworks,
	ECoinSelectPreference,
	getScriptHash,
	IUtxo,
	Wallet
} from '../src';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const RECIPIENT = 'bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk';
const network = EAvailableNetworks.regtest;
const PATH = "m/84'/1'/0'/0/0";
const INPUT_VALUE = 1_000;
const PAYMENT = 500;
const RATE = 2;

const electrumOptions = { net, tls };

describe('Capped fee quote below 2 sat/vB (#1543)', function () {
	this.timeout(60000);

	let wallet: Wallet;
	let changeAddress: string;
	let inputs: IUtxo[];

	before(async () => {
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			network,
			addressType: EAddressType.p2wpkh,
			coinSelectPreference: ECoinSelectPreference.consolidate,
			electrumOptions,
			remainOffline: true,
			name: 'cappedquotesizefloor'
		});
		if (res.isErr()) throw res.error;
		wallet = res.value;
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
		inputs = [0, 1].map((tx_pos) => ({
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

	it('rechecks funds when capping below the requested rate', async () => {
		await wallet.transaction.resetSendTransaction();
		const staged = wallet.transaction.updateSendTransaction({
			transaction: {
				inputs: [{ ...inputs[0], value: 1_700 }],
				outputs: [{ address: RECIPIENT, value: 1_472, index: 0 }],
				changeAddress
			}
		});
		if (staged.isErr()) throw staged.error;

		const quote = wallet.transaction.getTotalFeeObj({ satsPerByte: 1.5 });
		if (quote.isErr()) throw quote.error;
		expect(quote.value.maxSatPerByte).to.equal(0);
		expect(quote.value.satsPerByte).to.equal(0);
		expect(quote.value.totalFee).to.equal(228);

		const fee = wallet.transaction.updateFee({
			satsPerByte: quote.value.satsPerByte
		});
		if (fee.isErr()) throw fee.error;
		expect(fee.value.fee).to.equal(quote.value.totalFee);
	});

	[1, 2].forEach((inputCount) => {
		it(`advertises a rate updateFee accepts for ${inputCount} input(s)`, async () => {
			await wallet.transaction.resetSendTransaction();
			const staged = wallet.transaction.updateSendTransaction({
				transaction: {
					inputs: inputs.slice(0, inputCount),
					outputs: [{ address: RECIPIENT, value: PAYMENT, index: 0 }],
					changeAddress,
					satsPerByte: RATE
				}
			});
			if (staged.isErr()) throw staged.error;

			const quote = wallet.transaction.getTotalFeeObj({ satsPerByte: RATE });
			if (quote.isErr()) throw quote.error;
			// At 1 sat/vB the floor prices 256 vB, which is over half the payment.
			expect(quote.value.maxSatPerByte).to.equal(0);
			expect(quote.value.satsPerByte).to.equal(0);

			const fee = wallet.transaction.updateFee({
				satsPerByte: quote.value.satsPerByte
			});
			if (fee.isErr()) throw new Error(fee.error.message);
			expect(fee.value.fee).to.equal(quote.value.totalFee);
		});
	});
});
