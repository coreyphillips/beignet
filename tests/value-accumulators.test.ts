/**
 * Regression: the numeric accumulators under the on-chain wallet turned a NaN
 * or an error into a clean 0. Zero is a legitimate value for all of them, so
 * the failure was indistinguishable from an empty wallet or a zero-value
 * transaction.
 *
 *  1. reduceValue ended in `|| 0`, so one missing or non-numeric entry made the
 *     whole total 0. It backs the input and output totals, which feed the fee,
 *     the change calculation and the "fee is larger than the payment" guard.
 *  2. autoCoinSelect summed with `acc + Number(cur?.value) || 0`, which parses
 *     as `(acc + Number(cur?.value)) || 0`. One malformed output reset the
 *     running total, and a falsy amountToSend selects every UTXO in the wallet.
 *  3. Both value getters returned 0 for any Err without a word anywhere.
 *
 * Fully OFFLINE: the reducers are pure and the wallet points at an unreachable
 * port.
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
	IOutput,
	IUtxo,
	reduceValue,
	Transaction,
	Wallet
} from '../src';

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

const ADDRESS = payments.p2wpkh({
	pubkey: Buffer.from(
		'0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
		'hex'
	),
	network: networks.regtest
}).address as string;

const utxo = (value: number, index = 0): IUtxo => ({
	address: ADDRESS,
	index,
	path: `m/84'/1'/0'/0/${index}`,
	scriptHash: '00'.repeat(32),
	height: 1,
	tx_hash: 'ab'.repeat(32),
	tx_pos: index,
	value,
	publicKey: '02'.repeat(33)
});

describe('value accumulators', function () {
	this.timeout(60000);

	describe('reduceValue', function () {
		it('sums the requested key', function () {
			const res = reduceValue({
				arr: [utxo(1000), utxo(2500), utxo(4)],
				value: 'value'
			});
			if (res.isErr()) throw res.error;
			expect(res.value).to.equal(3504);
		});

		it('returns 0 for an empty array', function () {
			const res = reduceValue({ arr: [] as IUtxo[], value: 'value' });
			if (res.isErr()) throw res.error;
			expect(res.value).to.equal(0);
		});

		it('returns 0 when every entry is 0, rather than erring', function () {
			const res = reduceValue({ arr: [utxo(0), utxo(0)], value: 'value' });
			if (res.isErr()) throw res.error;
			expect(res.value).to.equal(0);
		});

		it('errs on a missing value instead of reporting 0', function () {
			// One entry without the key makes the total NaN. `|| 0` turned that
			// into a total of 0, which reads as "these inputs are worth nothing".
			const missing = { ...utxo(1000) } as Partial<IUtxo>;
			delete missing.value;
			const res = reduceValue({
				arr: [utxo(50_000), missing as IUtxo],
				value: 'value'
			});
			expect(res.isErr(), 'a NaN total is an error').to.equal(true);
		});

		it('errs on a non-numeric value', function () {
			const bad = { ...utxo(1000), value: 'not a number' as unknown as number };
			const res = reduceValue({ arr: [utxo(50_000), bad], value: 'value' });
			expect(res.isErr()).to.equal(true);
		});

		it('errs when no key is given', function () {
			const res = reduceValue({
				arr: [utxo(1000)],
				value: '' as unknown as keyof IUtxo
			});
			expect(res.isErr()).to.equal(true);
		});
	});

	describe('autoCoinSelect: a malformed output must not consolidate the wallet', function () {
		// No wallet attached: autoCoinSelect is a pure function of its arguments.
		const transaction = new Transaction({
			wallet: undefined as unknown as Wallet
		});

		// Five inputs, so "selected everything" is unmistakable.
		const inputs = [
			utxo(6000, 0),
			utxo(6000, 1),
			utxo(6000, 2),
			utxo(6000, 3),
			utxo(6000, 4)
		];

		const select = (
			outputs: IOutput[]
		): ReturnType<Transaction['autoCoinSelect']> =>
			transaction.autoCoinSelect({
				inputs: inputs.map((i) => ({ ...i })),
				outputs,
				changeAddress: ADDRESS,
				satsPerByte: 1,
				coinSelectPreference: ECoinSelectPreference.small
			});

		const malformed = {
			address: ADDRESS,
			value: undefined as unknown as number,
			index: 1
		};

		it('selects for the amount asked for when a later output is malformed', function () {
			const res = select([
				{ address: ADDRESS, value: 10_000, index: 0 },
				malformed
			]);

			if (res.isErr()) throw res.error;
			// `(acc + NaN) || 0` reset the total to 0, and a falsy amountToSend
			// takes the consolidate branch, which adds every UTXO in the wallet.
			expect(
				res.value.inputs.length,
				'did not fall through to a full consolidation'
			).to.be.lessThan(inputs.length);
			expect(res.value.inputs.length).to.be.greaterThan(0);
		});

		it('behaves the same when the malformed output comes first', function () {
			const res = select([
				{ ...malformed, index: 0 },
				{ address: ADDRESS, value: 10_000, index: 1 }
			]);

			if (res.isErr()) throw res.error;
			expect(res.value.inputs.length).to.be.lessThan(inputs.length);
		});

		it('still consolidates when there is genuinely no amount to send', function () {
			// A zero total is the documented signal for "spend everything", and
			// that behaviour is unchanged.
			const res = select([{ address: ADDRESS, value: 0, index: 0 }]);

			if (res.isErr()) throw res.error;
			expect(res.value.inputs.length).to.equal(inputs.length);
		});

		it('selects minimally for well-formed outputs', function () {
			const res = select([{ address: ADDRESS, value: 10_000, index: 0 }]);

			if (res.isErr()) throw res.error;
			expect(res.value.inputs.length).to.be.lessThan(inputs.length);
		});
	});

	describe('transaction value getters', function () {
		let wallet: Wallet;

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

		afterEach(function () {
			sinon.restore();
		});

		it('totals well-formed inputs and outputs', function () {
			expect(
				wallet.transaction.getTransactionInputValue({
					inputs: [utxo(1000), utxo(2000)]
				})
			).to.equal(3000);
			expect(
				wallet.transaction.getTransactionOutputValue({
					outputs: [{ address: ADDRESS, value: 700, index: 0 }]
				})
			).to.equal(700);
		});

		it('reports the failure it returns 0 for', function () {
			const logged = sinon.spy(wallet.logger, 'error');
			const bad = { ...utxo(1000), value: undefined as unknown as number };

			const total = wallet.transaction.getTransactionInputValue({
				inputs: [utxo(50_000), bad]
			});

			// The signature stays a number, so the caller still sees 0, but the
			// condition is no longer invisible.
			expect(total).to.equal(0);
			expect(logged.called, 'the failed total was logged').to.equal(true);
		});

		it('reports a failed output total too', function () {
			const logged = sinon.spy(wallet.logger, 'error');

			const total = wallet.transaction.getTransactionOutputValue({
				outputs: [
					{ address: ADDRESS, value: 5000, index: 0 },
					{
						address: ADDRESS,
						value: undefined as unknown as number,
						index: 1
					}
				]
			});

			expect(total).to.equal(0);
			expect(logged.called, 'the failed total was logged').to.equal(true);
		});

		it('says nothing for an empty set', function () {
			const logged = sinon.spy(wallet.logger, 'error');
			expect(
				wallet.transaction.getTransactionInputValue({ inputs: [] })
			).to.equal(0);
			expect(logged.called, 'an empty set is not a failure').to.equal(false);
		});
	});
});
