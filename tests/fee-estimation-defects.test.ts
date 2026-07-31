/**
 * Regression: four defects in the on-chain fee estimation path.
 *
 *  1. setupCpfp subtracted the parent's fee, denominated in BTC on
 *     IFormattedTransaction, from a sat/vB calculation, so the parent's fee was
 *     effectively ignored and the child overpaid.
 *  2. An OP_RETURN message was added to getByteCount as message.length * 2
 *     weight units, which is half the payload in vbytes once the total is
 *     divided by 4, so messaged transactions were under-priced.
 *  3. An input type with no entry in the weight table made totalWeight NaN, and
 *     NaN < minByteCount is false, so getByteCount returned NaN instead of the
 *     fallback its catch provides.
 *  4. autoCoinSelect topped up its selection with extra inputs and returned the
 *     fee it had calculated before they existed, leaving their weight unpaid.
 *
 * Fully OFFLINE: the arithmetic cases are pure, and the CPFP case stubs every
 * call that would touch a server.
 */

import { expect } from 'chai';
import net from 'net';
import tls from 'tls';
import sinon from 'sinon';
import { payments, networks } from 'bitcoinjs-lib';

import {
	EAddressType,
	EAvailableNetworks,
	ECoinSelectPreference,
	EProtocol,
	IUtxo,
	ok,
	Transaction,
	Wallet
} from '../src';
import { createOpReturnScript, getByteCount } from '../src/utils/transaction';
import { getDefaultSendTransaction } from '../src/shapes/wallet';
import {
	IFormattedTransaction,
	TGetByteCountInputs,
	TGetByteCountOutputs
} from '../src/types/wallet';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

// Unreachable on purpose: this test must work offline.
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
// Valid curve points (G, 2G, 3G, 4G), so bitcoinjs will encode them.
const PUBKEYS = [
	'0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
	'02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5',
	'02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9',
	'02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13'
];
const address = (index: number): string =>
	payments.p2wpkh({
		pubkey: Buffer.from(PUBKEYS[index % PUBKEYS.length], 'hex'),
		network
	}).address as string;

describe('fee estimation defects', function () {
	this.timeout(60000);

	describe('getByteCount: OP_RETURN message pricing', function () {
		const base = (message?: string): number =>
			getByteCount({ P2WPKH: 1 }, { P2WPKH: 1 }, message, 0);

		it('prices a message at its payload plus the output overhead', function () {
			// An OP_RETURN output costs (value:8) + (script_len:1) + (OP_RETURN:1)
			// + (pushdata:1) + payload. The old arithmetic charged half the payload
			// and nothing for the output itself: 40 bytes cost 5 vB rather than 51.
			const message = 'a'.repeat(40);
			expect(base(message) - base()).to.equal(40 + 11);
		});

		it('uses byte length, not character count', function () {
			// Four characters, twelve bytes in utf8.
			const message = 'éééé'.repeat(2);
			expect(base(message) - base()).to.equal(
				Buffer.byteLength(message, 'utf8') + 11
			);
		});

		it('prices the padding applied to a message below 5 bytes', function () {
			// createPsbtFromTransactionData pads a short message out to 5 bytes.
			expect(base('ab') - base()).to.equal(5 + 11);
		});

		it('accounts for the second pushdata byte above 75 bytes', function () {
			const message = 'a'.repeat(80);
			expect(base(message) - base()).to.equal(80 + 12);
		});

		// The estimator and the PSBT builder now go through createOpReturnScript,
		// so what is priced is the script that gets embedded. Pricing a second
		// copy of the serialization rules is what let them drift: the builder
		// padded on character count while the estimate clamped byte length, so a
		// short multibyte message was built at 6 or 7 bytes and priced at 5.
		[
			{ name: 'plain ascii', message: 'hello there' },
			{ name: 'short ascii, padded', message: 'ab' },
			{ name: 'short multibyte', message: 'é' },
			{ name: 'emoji', message: '😀' },
			{ name: 'multibyte above the pad', message: 'ééééééé' },
			{ name: 'at the pushdata boundary', message: 'a'.repeat(75) },
			{ name: 'over the pushdata boundary', message: 'a'.repeat(76) }
		].forEach(({ name, message }) => {
			it(`prices the exact script it embeds: ${name}`, function () {
				const script = createOpReturnScript(message);
				if (!script) throw new Error('expected a script');
				// The output is serialized as (value:8) + (script_len varint) + script.
				const outputSize = 8 + (script.length < 0xfd ? 1 : 3) + script.length;
				expect(base(message) - base()).to.equal(outputSize);
			});
		});

		it('pads to five bytes rather than five characters', function () {
			// 'é' is one character and two bytes; the emoji is two UTF-16 units and
			// four bytes. Padding on character count produced 6 and 7 byte payloads
			// against a 5 byte estimate.
			expect(createOpReturnScript('é')?.length).to.equal(2 + 5);
			expect(createOpReturnScript('😀')?.length).to.equal(2 + 5);
			expect(createOpReturnScript('abcde')?.length).to.equal(2 + 5);
		});

		it('charges nothing for a message that is never embedded', function () {
			// createPsbtFromTransactionData skips a whitespace-only message, so
			// pricing one was charging for an output that never appears.
			expect(createOpReturnScript('   ')).to.equal(undefined);
			expect(base('   ') - base()).to.equal(0);
			expect(base('') - base()).to.equal(0);
		});

		it('counts the OP_RETURN in the output count varint', function () {
			// 252 outputs fit a 1 byte CompactSize; the OP_RETURN makes 253, which
			// needs 3. The message block used to add its weight without ever
			// touching outputCount.
			const message = 'a'.repeat(40);
			const withMessage = getByteCount(
				{ P2WPKH: 1 },
				{ P2WPKH: 252 },
				message,
				0
			);
			const withoutMessage = getByteCount(
				{ P2WPKH: 1 },
				{ P2WPKH: 252 },
				'',
				0
			);
			const script = createOpReturnScript(message);
			if (!script) throw new Error('expected a script');
			const outputSize = 8 + 1 + script.length;
			expect(withMessage - withoutMessage).to.equal(outputSize + 2);
		});
	});

	describe('getByteCount: unknown types', function () {
		it('returns the fallback rather than NaN for an unpriced input type', function () {
			// The table has MULTISIG-P2WSH but no plain P2WSH, which autoCoinSelect
			// produces for a P2WSH utxo on a Transaction with no wallet attached.
			const result = getByteCount(
				{ P2WSH: 1 } as unknown as TGetByteCountInputs,
				{ P2WPKH: 1 }
			);
			expect(Number.isNaN(result), 'not NaN').to.equal(false);
			expect(result).to.equal(166);
		});

		it('honours an explicit minByteCount for an unpriced input type', function () {
			expect(
				getByteCount(
					{ P2WSH: 1 } as unknown as TGetByteCountInputs,
					{ P2WPKH: 1 },
					undefined,
					256
				)
			).to.equal(256);
		});

		it('returns the fallback rather than NaN for an unpriced output type', function () {
			const result = getByteCount(
				{ P2WPKH: 1 },
				{ NOPE: 1 } as unknown as TGetByteCountOutputs,
				undefined,
				0
			);
			expect(Number.isNaN(result), 'not NaN').to.equal(false);
			expect(result).to.equal(0);
		});

		it('still prices the types it does know', function () {
			expect(getByteCount({ P2WPKH: 1 }, { P2WPKH: 1 }, undefined, 0)).to.equal(
				Math.ceil((108 + 41 * 4 + 2 + 31 * 4 + 8 * 4 + 4 + 4) / 4)
			);
		});
	});

	describe('autoCoinSelect: repricing after a top-up', function () {
		// No wallet attached: autoCoinSelect is a pure function of its arguments.
		const transaction = new Transaction({
			wallet: undefined as unknown as Wallet
		});

		const utxo = (value: number, index: number): IUtxo => ({
			address: address(index),
			index,
			path: `m/84'/1'/0'/0/${index}`,
			scriptHash: '00'.repeat(32),
			height: 1,
			tx_hash: 'ab'.repeat(32),
			tx_pos: index,
			value,
			publicKey: '02'.repeat(33)
		});

		it('returns a fee that covers every input it selected', function () {
			const satsPerByte = 10;
			// Two 6000 sat inputs cover the 10000 sat payment but not the payment
			// plus its fee, so the third is pulled in by the top-up loop.
			const res = transaction.autoCoinSelect({
				inputs: [utxo(6000, 0), utxo(6000, 1), utxo(6000, 2)],
				outputs: [{ address: address(3), value: 10000, index: 0 }],
				changeAddress: address(4),
				satsPerByte,
				coinSelectPreference: ECoinSelectPreference.small
			});

			if (res.isErr()) throw res.error;
			expect(res.value.inputs.length, 'the top-up ran').to.equal(3);

			const expected =
				getByteCount({ P2WPKH: 3 }, { P2WPKH: 2 }, '', 0) * satsPerByte;
			// The old code returned the fee for the two inputs it had priced
			// before the loop, leaving the third input's ~68 vB unpaid.
			expect(res.value.fee).to.equal(expected);
		});

		it('keeps covering the total after repricing', function () {
			const satsPerByte = 10;
			const inputs = [utxo(6000, 0), utxo(6000, 1), utxo(6000, 2)];
			const res = transaction.autoCoinSelect({
				inputs,
				outputs: [{ address: address(3), value: 10000, index: 0 }],
				changeAddress: address(4),
				satsPerByte,
				coinSelectPreference: ECoinSelectPreference.small
			});

			if (res.isErr()) throw res.error;
			const selected = res.value.inputs.reduce((acc, i) => acc + i.value, 0);
			expect(selected).to.be.at.least(10000 + res.value.fee);
		});

		it('errs when repricing pushes the total out of reach', function () {
			// 10000 sats of payment against 10500 sats of inputs: the fee at 50
			// sat/vB cannot be covered no matter which inputs are added.
			const res = transaction.autoCoinSelect({
				inputs: [utxo(5000, 0), utxo(5500, 1)],
				outputs: [{ address: address(3), value: 10000, index: 0 }],
				changeAddress: address(4),
				satsPerByte: 50,
				coinSelectPreference: ECoinSelectPreference.small
			});

			expect(res.isErr()).to.equal(true);
		});

		it('still prices a single-input selection', function () {
			const satsPerByte = 5;
			const res = transaction.autoCoinSelect({
				inputs: [utxo(100000, 0)],
				outputs: [{ address: address(3), value: 10000, index: 0 }],
				changeAddress: address(4),
				satsPerByte,
				coinSelectPreference: ECoinSelectPreference.small
			});

			if (res.isErr()) throw res.error;
			expect(res.value.inputs.length).to.equal(1);
			// autoCoinSelect calls getByteCount without a minByteCount, so the
			// default 166 vB floor applies to a selection this small.
			expect(res.value.fee).to.equal(
				getByteCount({ P2WPKH: 1 }, { P2WPKH: 2 }, '') * satsPerByte
			);
		});
	});

	describe('setupCpfp: the parent fee is in BTC', function () {
		let wallet: Wallet;
		const PARENT_TXID = 'cd'.repeat(32);

		const stageParent = (feeBtc: number, vsize: number): void => {
			wallet.data.transactions[PARENT_TXID] = {
				fee: feeBtc,
				vsize
			} as IFormattedTransaction;
		};

		before(async function () {
			const res = await Wallet.create({
				mnemonic: MNEMONIC,
				network: EAvailableNetworks.regtest,
				addressType: EAddressType.p2wpkh,
				electrumOptions
			});
			if (res.isErr()) throw res.error;
			wallet = res.value;
		});

		after(async function () {
			await wallet?.electrum?.disconnect();
		});

		beforeEach(function () {
			wallet.feeEstimates = {
				...wallet.feeEstimates,
				fast: 10,
				normal: 5
			};
			sinon.stub(wallet.transaction, 'resetSendTransaction').resolves(ok(''));
			sinon
				.stub(wallet.transaction, 'setupTransaction')
				.resolves(ok(getDefaultSendTransaction()));
			sinon.stub(wallet, 'getReceiveAddress').resolves(ok(address(9)));
		});

		afterEach(function () {
			sinon.restore();
		});

		it('credits the parent fee at its value in sats', async function () {
			// Parent: 200 vB, 1000 sats of fee. Child: 141 vB assumed.
			// (10 * 341 - 1000) / 141 = 17.09 -> 18 sat/vB.
			// Reading the fee as 0.00001 instead of 1000 gave 25.
			stageParent(0.00001, 200);
			const sendMax = sinon
				.stub(wallet.transaction, 'sendMax')
				.resolves(ok(getDefaultSendTransaction()));

			const res = await wallet.transaction.setupCpfp({ txid: PARENT_TXID });

			if (res.isErr()) throw res.error;
			expect(sendMax.calledOnce, 'the child was set up').to.equal(true);
			expect(sendMax.firstCall.args[0].satsPerByte).to.equal(18);
			// (5 * 341 - 1000) / 141 = 5 sat/vB, against 13 before the fix.
			expect(wallet.transaction.data.minFee).to.equal(5);
		});

		it('never quotes below 1 sat/vB when the parent already overpaid', async function () {
			// 0.001 BTC of fee on a 200 vB parent is far above the target rate, so
			// the raw arithmetic goes negative.
			stageParent(0.001, 200);
			const sendMax = sinon
				.stub(wallet.transaction, 'sendMax')
				.resolves(ok(getDefaultSendTransaction()));

			const res = await wallet.transaction.setupCpfp({ txid: PARENT_TXID });

			if (res.isErr()) throw res.error;
			expect(sendMax.firstCall.args[0].satsPerByte).to.equal(1);
			expect(wallet.transaction.data.minFee).to.equal(1);
		});
	});
});
