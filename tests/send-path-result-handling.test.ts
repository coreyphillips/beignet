/**
 * Regression: results returned by the on-chain send path must be acted on.
 *
 * The worst case was in sendMany, where a failed output update built an `err`
 * and dropped it on the floor, so the send continued to createTransaction and
 * broadcastTransaction with an output missing or stale. The fee-too-high branch
 * had the same shape: when the follow-up fee probe also failed, neither branch
 * returned and the un-updated fee was broadcast.
 *
 * Fully OFFLINE: the wallet points at an unreachable port and every call that
 * would touch a server is stubbed.
 */

import { expect } from 'chai';
import net from 'net';
import tls from 'tls';
import sinon from 'sinon';

import {
	EAddressType,
	EAvailableNetworks,
	EProtocol,
	getDataFallback,
	IUtxo,
	ok,
	err,
	Result,
	validateTransaction,
	Wallet
} from '../src';
import { getDefaultSendTransaction } from '../src/shapes/wallet';
import { TRANSACTION_DEFAULTS } from '../src/wallet/constants';

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

describe('send path result handling', function () {
	this.timeout(60000);

	let wallet: Wallet;
	let address: string;

	const utxo = (value: number): IUtxo => ({
		address,
		index: 0,
		path: "m/84'/1'/0'/0/0",
		scriptHash: '00'.repeat(32),
		height: 1,
		tx_hash: 'ab'.repeat(32),
		tx_pos: 0,
		value,
		publicKey: '02'.repeat(33)
	});

	beforeEach(async function () {
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			network: EAvailableNetworks.regtest,
			addressType: EAddressType.p2wpkh,
			electrumOptions
		});
		if (res.isErr()) throw res.error;
		wallet = res.value;

		const gen = await wallet.generateAddresses({
			addressAmount: 1,
			changeAddressAmount: 1,
			addressType: EAddressType.p2wpkh
		});
		if (gen.isErr()) throw gen.error;
		address = Object.values(gen.value.addresses)[0].address;

		// sendMany refuses to start without UTXOs.
		wallet.data.utxos = [utxo(100000)];
	});

	afterEach(function () {
		sinon.restore();
	});

	describe('sendMany', function () {
		// Stubs every step after the output loop so a send that should have
		// stopped is observable rather than merely slow.
		const stubDownstream = (): {
			create: sinon.SinonStub;
			broadcast: sinon.SinonStub;
		} => {
			sinon
				.stub(wallet.transaction, 'setupTransaction')
				.resolves(ok(getDefaultSendTransaction()));
			const create = sinon
				.stub(wallet.transaction, 'createTransaction')
				.resolves(ok({ id: 'id', hex: '00' }));
			const broadcast = sinon
				.stub(wallet.electrum, 'broadcastTransaction')
				.resolves(ok('txid'));
			return { create, broadcast };
		};

		it('stops instead of broadcasting when an output update fails', async function () {
			const { create, broadcast } = stubDownstream();

			// Fail the second of three outputs. Before the fix the loop kept going
			// and the transaction was built and broadcast without it.
			let calls = 0;
			sinon
				.stub(wallet.transaction, 'updateSendTransaction')
				.callsFake((): Result<string> => {
					calls++;
					return calls === 2 ? err('output rejected') : ok('updated');
				});

			const res = await wallet.sendMany({
				txs: [
					{ address, amount: 10000 },
					{ address, amount: 20000 },
					{ address, amount: 30000 }
				],
				satsPerByte: 2,
				shuffleOutputs: false
			});

			expect(res.isErr(), 'the send reported the failed output').to.equal(true);
			if (res.isErr()) {
				expect(res.error.message).to.equal('output rejected');
			}
			expect(calls, 'the loop stopped on the failed output').to.equal(2);
			expect(create.called, 'no transaction was built').to.equal(false);
			expect(broadcast.called, 'nothing was broadcast').to.equal(false);
		});

		it('stops when the fee update fails and the fee probe fails too', async function () {
			const { create, broadcast } = stubDownstream();
			sinon
				.stub(wallet.transaction, 'updateSendTransaction')
				.returns(ok('updated'));
			sinon
				.stub(wallet.transaction, 'updateFee')
				.returns(
					err(
						'Unable to increase the fee any further. Otherwise, it will exceed half the current input balance.'
					)
				);
			// The probe that would refine the message into "Fee is too high" is the
			// path that used to fall through to a broadcast at the old fee.
			sinon.stub(wallet, 'getFeeInfo').returns(err('no fee info'));

			const res = await wallet.sendMany({
				txs: [{ address, amount: 10000 }],
				satsPerByte: 2,
				shuffleOutputs: false
			});

			expect(res.isErr(), 'the send reported the failed fee update').to.equal(
				true
			);
			if (res.isErr()) {
				expect(res.error.message).to.contain('Unable to increase the fee');
			}
			expect(create.called, 'no transaction was built').to.equal(false);
			expect(broadcast.called, 'nothing was broadcast').to.equal(false);
		});
	});

	describe('dust outputs', function () {
		it('validateTransaction rejects an output below the dust limit', function () {
			const transaction = {
				...getDefaultSendTransaction(),
				inputs: [utxo(100000)],
				outputs: [
					{ address, value: TRANSACTION_DEFAULTS.dustLimit - 1, index: 0 }
				]
			};

			const res = validateTransaction(transaction);

			expect(res.isErr(), 'the sub-dust output was rejected').to.equal(true);
			if (res.isErr()) {
				expect(res.error.message).to.contain('dust limit');
			}
		});

		it('validateTransaction accepts an output at the dust limit', function () {
			const transaction = {
				...getDefaultSendTransaction(),
				inputs: [utxo(100000)],
				outputs: [{ address, value: TRANSACTION_DEFAULTS.dustLimit, index: 0 }]
			};

			expect(validateTransaction(transaction).isOk()).to.equal(true);
		});

		it('createTransaction refuses to build a sub-dust output', async function () {
			const res = await wallet.transaction.createTransaction({
				transactionData: {
					...getDefaultSendTransaction(),
					inputs: [utxo(100000)],
					outputs: [
						{ address, value: TRANSACTION_DEFAULTS.dustLimit - 1, index: 0 }
					]
				}
			});

			expect(res.isErr(), 'the build stopped at the sub-dust output').to.equal(
				true
			);
			if (res.isErr()) {
				expect(res.error.message).to.contain('dust limit');
			}
		});
	});

	describe('transaction input and tag helpers', function () {
		beforeEach(function () {
			sinon
				.stub(wallet.transaction, 'updateSendTransaction')
				.returns(err('storage unavailable'));
		});

		it('addTxInput propagates a failed update', function () {
			const res = wallet.addTxInput({ input: utxo(100000) });
			expect(res.isErr()).to.equal(true);
		});

		it('removeTxInput propagates a failed update', function () {
			const res = wallet.removeTxInput({ input: utxo(100000) });
			expect(res.isErr()).to.equal(true);
		});

		it('addTxTag propagates a failed update', function () {
			const res = wallet.addTxTag({ tag: 'tag' });
			expect(res.isErr()).to.equal(true);
		});

		it('removeTxTag propagates a failed update', function () {
			const res = wallet.removeTxTag({ tag: 'tag' });
			expect(res.isErr()).to.equal(true);
		});
	});

	describe('getDataFallback', function () {
		it('errs on a key with no default', async function () {
			const res = await getDataFallback('wallet0-regtest-notARealKey');
			expect(
				res.isErr(),
				'an unknown key is an error, not ok(undefined)'
			).to.equal(true);
		});

		it('still returns the default for a known key', async function () {
			const res = await getDataFallback('wallet0-regtest-utxos');
			expect(res.isOk()).to.equal(true);
			if (res.isOk()) expect(res.value).to.deep.equal([]);
		});
	});
});
