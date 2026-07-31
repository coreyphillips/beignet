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

import { payments, networks } from 'bitcoinjs-lib';
import { bech32m } from 'bech32';

import {
	EAddressType,
	EAvailableNetworks,
	EProtocol,
	getDataFallback,
	getDustThreshold,
	ISendTransaction,
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

// One regtest address per output script, so the dust cases can assert the
// threshold each script actually carries.
const network = networks.regtest;
const pubkey = Buffer.from(
	'0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
	'hex'
);
const addresses = {
	p2pkh: payments.p2pkh({ pubkey, network }).address as string,
	p2sh: payments.p2sh({
		redeem: payments.p2wpkh({ pubkey, network }),
		network
	}).address as string,
	p2wpkh: payments.p2wpkh({ pubkey, network }).address as string,
	p2wsh: payments.p2wsh({
		redeem: payments.p2pkh({ pubkey, network }),
		network
	}).address as string,
	// Encoded directly rather than via payments.p2tr, which would need the ecc
	// library initialised for a value this test never spends.
	p2tr: bech32m.encode('bcrt', [1, ...bech32m.toWords(pubkey.subarray(1, 33))])
};

describe('send path result handling', function () {
	this.timeout(60000);

	let wallet: Wallet;
	const address = addresses.p2wpkh;

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

	// One wallet for the file: every test that touches it stubs what it needs
	// and sinon.restore puts it back. Creating one per test left a reconnect
	// loop per wallet running into the suites that follow.
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
		// Bitcoin Core's thresholds at the default dust relay fee. A single 546
		// limit would reject the first four of these outright, all of which relay
		// today.
		const CASES = [
			{ type: 'p2wpkh', address: addresses.p2wpkh, threshold: 294 },
			{ type: 'p2tr', address: addresses.p2tr, threshold: 330 },
			{ type: 'p2wsh', address: addresses.p2wsh, threshold: 330 },
			{ type: 'p2sh', address: addresses.p2sh, threshold: 540 },
			{ type: 'p2pkh', address: addresses.p2pkh, threshold: 546 }
		];

		const withOutput = (
			outputAddress: string,
			value: number
		): ISendTransaction => ({
			...getDefaultSendTransaction(),
			inputs: [utxo(100000)],
			outputs: [{ address: outputAddress, value, index: 0 }]
		});

		CASES.forEach(({ type, address: outputAddress, threshold }) => {
			it(`getDustThreshold returns ${threshold} for ${type}`, function () {
				expect(getDustThreshold(outputAddress)).to.equal(threshold);
			});

			it(`validateTransaction rejects a ${type} output at ${
				threshold - 1
			}`, function () {
				const res = validateTransaction(
					withOutput(outputAddress, threshold - 1)
				);
				expect(res.isErr(), 'the sub-dust output was rejected').to.equal(true);
				if (res.isErr()) {
					expect(res.error.message).to.contain('dust threshold');
				}
			});

			it(`validateTransaction accepts a ${type} output at ${threshold}`, function () {
				expect(
					validateTransaction(withOutput(outputAddress, threshold)).isOk()
				).to.equal(true);
			});
		});

		it('falls back to the conservative limit for an unparsable address', function () {
			expect(getDustThreshold('not-an-address')).to.equal(
				TRANSACTION_DEFAULTS.dustLimit
			);
		});

		it('createTransaction refuses to build a sub-dust output', async function () {
			const res = await wallet.transaction.createTransaction({
				transactionData: withOutput(addresses.p2wpkh, 293)
			});

			expect(res.isErr(), 'the build stopped at the sub-dust output').to.equal(
				true
			);
			if (res.isErr()) {
				expect(res.error.message).to.contain('dust threshold');
			}
		});

		it('addOutput applies the same per-type threshold', async function () {
			const rejected = await wallet.transaction.addOutput({
				address: addresses.p2wpkh,
				value: 293,
				index: 0
			});
			expect(rejected.isErr(), '293 sats is dust for p2wpkh').to.equal(true);

			// 294 sats is relayable to a p2wpkh output and was rejected by the
			// blanket 546 guard this replaces.
			sinon
				.stub(wallet.transaction, 'setupTransaction')
				.resolves(ok(getDefaultSendTransaction()));
			sinon
				.stub(wallet.transaction, 'updateSendTransaction')
				.returns(ok('updated'));
			const accepted = await wallet.transaction.addOutput({
				address: addresses.p2wpkh,
				value: 294,
				index: 0
			});
			expect(accepted.isOk(), '294 sats is not dust for p2wpkh').to.equal(true);
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

		it('errs on an inherited Object property name', async function () {
			// `key in defaultWalletData` would answer true for these.
			for (const key of ['toString', 'constructor', 'hasOwnProperty']) {
				const res = await getDataFallback(`wallet0-regtest-${key}`);
				expect(res.isErr(), `${key} is not wallet data`).to.equal(true);
			}
		});

		it('still returns the default for a known key', async function () {
			const res = await getDataFallback('wallet0-regtest-utxos');
			expect(res.isOk()).to.equal(true);
			if (res.isOk()) expect(res.value).to.deep.equal([]);
		});
	});
});
