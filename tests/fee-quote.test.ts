/**
 * Quoting an on-chain transaction.
 *
 * A quote is only worth having if it is the number the transaction actually
 * pays, and only safe to serve from a `readonly` route if asking for it changes
 * nothing. Both are checked here against a real regtest wallet: the quote is
 * compared with the fee a broadcast transaction really paid, and the wallet's
 * staged transaction is compared with itself across the call.
 *
 * The pure size arithmetic underneath is checked first, because both bugs this
 * file exists to pin down lived there.
 */

import BitcoinJsonRpc from 'bitcoin-json-rpc';
import { expect } from 'chai';
import net from 'net';
import tls from 'tls';
import * as fs from 'fs';
import * as path from 'path';

import {
	EAddressType,
	EAvailableNetworks,
	EProtocol,
	generateMnemonic,
	Wallet
} from '../';
import { getByteCount } from '../src/utils/transaction';
import { getDefaultSendTransaction } from '../src/shapes/wallet';
import { ISendTransaction } from '../src/types/wallet';
import {
	bitcoinURL,
	electrumHost,
	electrumPort,
	initWaitForElectrumToSync,
	TWaitForElectrum
} from './utils';

const testTimeout = 90000;
const rpc = new BitcoinJsonRpc(bitcoinURL);

describe('On-chain fee quoting', function () {
	this.timeout(testTimeout);

	describe('getByteCount', () => {
		it('does not count a lower-case key twice', () => {
			// constructByteCountParam emits both spellings, one of them zero. Upper-
			// casing the key and then re-reading the object with it made the zero
			// entry pick up its twin's value and add it again.
			const plain = getByteCount({ P2WPKH: 1 }, { P2WPKH: 2 }, undefined, 0);
			const withZeroTwin = getByteCount(
				{ P2WPKH: 1 },
				{ P2WPKH: 2, p2wpkh: 0 },
				undefined,
				0
			);
			expect(withZeroTwin).to.equal(plain);
		});

		it('prices a taproot output like the 43 vB output it is', () => {
			// OP_1 <32-byte program> is 34 bytes, plus a length prefix and the 8-byte
			// value: the same size as a P2WSH output, not the 41 vB it was counted as.
			const p2tr = getByteCount({ P2WPKH: 1 }, { P2TR: 1 }, undefined, 0);
			const p2wsh = getByteCount({ P2WPKH: 1 }, { P2WSH: 1 }, undefined, 0);
			const p2wpkh = getByteCount({ P2WPKH: 1 }, { P2WPKH: 1 }, undefined, 0);
			expect(p2tr).to.equal(p2wsh);
			expect(p2tr - p2wpkh).to.equal(43 - 31);
		});
	});

	describe('quoteOnchain is pure', () => {
		it("never reaches for the wallet's staged transaction", () => {
			// The staging area is what a real send builds in. A quote that reset or
			// repopulated it could erase a send being prepared alongside it, and a
			// route classified readonly has no business writing to the wallet at all.
			const src = fs.readFileSync(
				path.join(__dirname, '../src/cli/beignet-node.ts'),
				'utf8'
			);
			const start = src.indexOf('async quoteOnchain(');
			expect(start, 'quoteOnchain not found').to.be.greaterThan(-1);
			const body = src.slice(start, src.indexOf('\n\t}', start));
			for (const mutator of [
				'setupTransaction',
				'resetSendTransaction',
				'updateSendTransaction',
				'saveWalletData'
			]) {
				expect(body, `quoteOnchain must not call ${mutator}`).to.not.include(
					mutator
				);
			}
		});
	});

	describe('against a real wallet', () => {
		let wallet: Wallet;
		let waitForElectrum: TWaitForElectrum;

		beforeEach(async function () {
			this.timeout(testTimeout);
			let balance = await rpc.getBalance();
			const address = await rpc.getNewAddress();
			await rpc.generateToAddress(1, address);
			while (balance < 10) {
				await rpc.generateToAddress(10, address);
				balance = await rpc.getBalance();
			}
			waitForElectrum = await initWaitForElectrumToSync(
				{ host: electrumHost, port: electrumPort },
				bitcoinURL
			);
			await waitForElectrum();

			const res = await Wallet.create({
				rbf: true,
				mnemonic: generateMnemonic(),
				network: EAvailableNetworks.regtest,
				addressType: EAddressType.p2wpkh,
				electrumOptions: {
					servers: [
						{
							host: '127.0.0.1',
							ssl: 60002,
							tcp: 60001,
							protocol: EProtocol.tcp
						}
					],
					net,
					tls
				},
				gapLimitOptions: {
					lookAhead: 2,
					lookBehind: 2,
					lookAheadChange: 2,
					lookBehindChange: 2
				}
			});
			if (res.isErr()) throw res.error;
			wallet = res.value;

			// Several UTXOs, so coin selection has something to actually do.
			for (let i = 0; i < 4; i++) {
				const addr = await wallet.getAddress();
				await rpc.sendToAddress(addr, '0.05');
			}
			await rpc.generateToAddress(1, address);
			await waitForElectrum();
			await wallet.refreshWallet({});
		});

		afterEach(async () => {
			await wallet?.electrum?.disconnect();
		});

		/** What the transaction really paid: inputs spent minus outputs created. */
		const feePaid = async (txid: string): Promise<number> => {
			const tx = await rpc.getRawTransactionAsObject(txid);
			let spent = 0;
			for (const vin of tx.vin) {
				const prev = await rpc.getRawTransactionAsObject(String(vin.txid));
				spent += Math.round(Number(prev.vout[Number(vin.vout)].value) * 1e8);
			}
			const created = tx.vout.reduce(
				(sum: number, out) => sum + Math.round(Number(out.value) * 1e8),
				0
			);
			return spent - created;
		};

		/** The transaction quoteOnchain prices: assembled in memory, never staged. */
		const quoteTransaction = (
			address: string,
			amountSats: number,
			satsPerByte: number,
			max = false
		): ISendTransaction => ({
			...getDefaultSendTransaction(),
			rbf: wallet.rbf,
			satsPerByte,
			max,
			changeAddress: wallet.data.changeAddressIndex[wallet.addressType].address,
			inputs: wallet.transaction.removeBlackListedUtxos(wallet.data.utxos),
			outputs: [{ address, value: amountSats, index: 0 }]
		});

		it('quotes the fee a send actually pays', async () => {
			const dest = await rpc.getNewAddress();
			const satsPerByte = 14;
			const amount = 2_000_000;

			const quote = wallet.getFeeInfo({
				satsPerByte,
				transaction: quoteTransaction(dest, amount, satsPerByte)
			});
			if (quote.isErr()) throw quote.error;

			const sent = await wallet.send({
				address: dest,
				amount,
				satsPerByte,
				rbf: true
			});
			if (sent.isErr()) throw new Error(sent.error.message);

			expect(await feePaid(sent.value)).to.equal(quote.value.totalFee);
		});

		it('quotes a sweep, and the sweep sends exactly that', async () => {
			const dest = await rpc.getNewAddress();
			const satsPerByte = 9;

			const quote = wallet.transaction.getMaxSendAmount({
				satsPerByte,
				transaction: quoteTransaction(dest, 0, satsPerByte, true)
			});
			if (quote.isErr()) throw quote.error;

			const sent = await wallet.sendMax({
				address: dest,
				satsPerByte,
				rbf: true
			});
			if (sent.isErr()) throw new Error(sent.error.message);

			const tx = await rpc.getRawTransactionAsObject(sent.value);
			expect(tx.vout, 'a sweep needs no change output').to.have.length(1);
			expect(Math.round(Number(tx.vout[0].value) * 1e8)).to.equal(
				quote.value.amount
			);
			expect(await feePaid(sent.value)).to.equal(quote.value.fee);
		});

		it('leaves the staged transaction byte-for-byte unchanged', async () => {
			// The invariant itself, rather than a proxy for it. This is the staging
			// area a real send builds in, and the one the old implementation reset,
			// repopulated and reset again to get its answer.
			const dest = 'bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080';
			const before = JSON.stringify(wallet.transaction.data);

			const quote = wallet.getFeeInfo({
				satsPerByte: 10,
				transaction: quoteTransaction(dest, 1_000_000, 10)
			});
			if (quote.isErr()) throw quote.error;

			const sweep = wallet.transaction.getMaxSendAmount({
				satsPerByte: 10,
				transaction: quoteTransaction(dest, 0, 10, true)
			});
			if (sweep.isErr()) throw sweep.error;

			expect(JSON.stringify(wallet.transaction.data)).to.equal(before);

			// And the check has teeth. Staging a transaction is the path a quote must
			// not take, and taking it does move this; without proving that, the
			// assertion above would pass just as happily against something that never
			// changes, and would not have caught the implementation it exists to
			// rule out.
			await wallet.transaction.setupTransaction({ rbf: wallet.rbf });
			expect(
				JSON.stringify(wallet.transaction.data),
				'staging a transaction should have moved it'
			).to.not.equal(before);
			await wallet.transaction.resetSendTransaction();
		});

		it('two quotes in flight together do not disturb each other', () => {
			const dest = 'bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080';
			const quotes = [1, 2, 3, 4].map(() =>
				wallet.getFeeInfo({
					satsPerByte: 11,
					transaction: quoteTransaction(dest, 1_500_000, 11)
				})
			);
			const fees = quotes.map((q) => {
				if (q.isErr()) throw q.error;
				return q.value.totalFee;
			});
			expect(new Set(fees).size, 'quotes disagreed').to.equal(1);
		});
	});
});
