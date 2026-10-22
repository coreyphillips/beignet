/**
 * sendMany and buildPsbt build from the coins they priced (#1360, #1431).
 * Fully OFFLINE: the wallet is created with remainOffline, UTXOs are
 * injected into wallet data, and nothing is broadcast.
 *
 * With any coinSelectPreference but consolidate, updateFee priced the subset
 * autoCoinSelect picks, while createTransaction and createUnsignedPsbt built
 * from every staged UTXO.
 * The change output absorbed the extra inputs and the transaction went out at
 * about half the requested rate.
 */

import { expect } from 'chai';
import net from 'net';
import tls from 'tls';
import {
	address as bitcoinAddress,
	networks,
	Transaction as BitcoinTransaction
} from 'bitcoinjs-lib';

import {
	EAddressType,
	EAvailableNetworks,
	ECoinSelectPreference,
	IUtxo,
	Wallet,
	createMemoryStorage
} from '../src';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

// The wallet is created with remainOffline: this test must work offline.
const electrumOptions = { net, tls };

const RECIPIENT = bitcoinAddress.toBech32(Buffer.alloc(20, 3), 0, 'bcrt');

describe('sendMany coin selection (#1360)', function () {
	this.timeout(60000);

	let wallet: Wallet;
	const injected = new Map<string, number>();

	/** Fabricates a UTXO paying to the wallet's own index-0 address. */
	const injectUtxo = async (
		txid: string,
		value: number,
		height = 0
	): Promise<IUtxo> => {
		const source = wallet.data.addressIndex[EAddressType.p2wpkh];
		if (!source?.address) throw new Error('No derived address available.');
		const utxo: IUtxo = {
			address: source.address,
			index: source.index,
			path: source.path,
			scriptHash: source.scriptHash,
			height,
			tx_hash: txid,
			tx_pos: 0,
			value,
			publicKey: source.publicKey
		};
		const res = await wallet.updateData({
			utxos: [...wallet.data.utxos, utxo],
			balance: wallet.data.balance + value
		});
		if (res.isErr()) throw res.error;
		injected.set(txid, value);
		return utxo;
	};

	/** Drops every UTXO, as if each had been spent. */
	const dropUtxos = async (): Promise<void> => {
		const { utxos, balance } = wallet.data;
		const res = await wallet.updateData({
			utxos: [],
			balance: utxos.reduce((sum, utxo) => sum - utxo.value, balance)
		});
		if (res.isErr()) throw res.error;
		for (const utxo of utxos) injected.delete(utxo.tx_hash);
	};

	/** Fee paid by a built transaction whose inputs are all injected UTXOs. */
	const feeOf = (tx: BitcoinTransaction): number => {
		const inputTotal = tx.ins.reduce((sum, input) => {
			const txid = Buffer.from(input.hash).reverse().toString('hex');
			const value = injected.get(txid);
			if (value === undefined) throw new Error(`Unknown input ${txid}.`);
			return sum + value;
		}, 0);
		const outputTotal = tx.outs.reduce((sum, output) => sum + output.value, 0);
		return inputTotal - outputTotal;
	};

	beforeEach(async function () {
		injected.clear();
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			name: 'sendcoinselect',
			network: EAvailableNetworks.regtest,
			addressType: EAddressType.p2wpkh,
			storage: createMemoryStorage(),
			electrumOptions,
			remainOffline: true
		});
		if (res.isErr()) throw res.error;
		wallet = res.value;
		// The failed (offline) refresh still generates index-0 addresses.
		await wallet.refreshWallet({});
		for (let i = 1; i <= 5; i++) {
			await injectUtxo(i.toString(16).padStart(2, '0').repeat(32), 10_000);
		}
	});

	afterEach(async function () {
		await wallet?.stop();
	});

	const send = async (): Promise<BitcoinTransaction> => {
		const res = await wallet.send({
			address: RECIPIENT,
			amount: 15_000,
			satsPerByte: 10,
			broadcast: false
		});
		if (res.isErr()) throw res.error;
		return BitcoinTransaction.fromHex(res.value);
	};

	it('spends only the selected coins and pays the requested rate', async function () {
		wallet.updateCoinSelectPreference(ECoinSelectPreference.small);

		const tx = await send();

		expect(tx.ins).to.have.length(2);
		expect(wallet.transaction.data.inputs).to.have.length(2);
		expect(feeOf(tx)).to.equal(wallet.transaction.data.fee);
		expect(feeOf(tx) / tx.virtualSize()).to.be.at.least(10);
	});

	it('still spends every coin under consolidate', async function () {
		wallet.updateCoinSelectPreference(ECoinSelectPreference.consolidate);

		const tx = await send();

		expect(tx.ins).to.have.length(5);
		expect(feeOf(tx)).to.equal(wallet.transaction.data.fee);
		expect(feeOf(tx) / tx.virtualSize()).to.be.at.least(10);
	});

	it('builds a PSBT from the selected coins at the requested rate (#1431)', async function () {
		wallet.updateCoinSelectPreference(ECoinSelectPreference.small);

		const built = await wallet.buildPsbt({
			address: RECIPIENT,
			amount: 15_000,
			satsPerByte: 10
		});
		if (built.isErr()) throw built.error;
		const signed = wallet.signPsbtWithOurKey(built.value.psbtBase64);
		if (signed.isErr()) throw signed.error;
		const imported = wallet.importSignedPsbt(signed.value);
		if (imported.isErr()) throw imported.error;
		const tx = BitcoinTransaction.fromHex(imported.value.txHex);

		expect(tx.ins).to.have.length(2);
		expect(built.value.inputs).to.have.length(2);
		expect(feeOf(tx)).to.equal(built.value.fee);
		expect(feeOf(tx) / tx.virtualSize()).to.be.at.least(10);
	});

	for (const twoRecipientsFirst of [false, true]) {
		it(`keeps each concurrent PSBT build on its own recipients (${
			twoRecipientsFirst ? 'two-recipient' : 'one-recipient'
		} build first, #1464)`, async function () {
			wallet.updateCoinSelectPreference(ECoinSelectPreference.small);
			const [a, b, c] = [4, 5, 6].map((fill) =>
				bitcoinAddress.toBech32(Buffer.alloc(20, fill), 0, 'bcrt')
			);
			const buildOne = (): ReturnType<Wallet['buildPsbt']> =>
				wallet.buildPsbt({ address: a, amount: 10_000, satsPerByte: 2 });
			const buildTwo = (): ReturnType<Wallet['buildPsbt']> =>
				wallet.buildPsbt({
					txs: [
						{ address: b, amount: 5_000 },
						{ address: c, amount: 6_000 }
					],
					satsPerByte: 2
				});

			const [one, two] = twoRecipientsFirst
				? (await Promise.all([buildTwo(), buildOne()])).reverse()
				: await Promise.all([buildOne(), buildTwo()]);
			if (one.isErr()) throw one.error;
			if (two.isErr()) throw two.error;
			// What the signed transaction pays, not just what the build reports.
			const paid = (psbtBase64: string): string[] => {
				const signed = wallet.signPsbtWithOurKey(psbtBase64);
				if (signed.isErr()) throw signed.error;
				const imported = wallet.importSignedPsbt(signed.value);
				if (imported.isErr()) throw imported.error;
				return BitcoinTransaction.fromHex(imported.value.txHex)
					.outs.map(({ script, value }) => ({
						address: bitcoinAddress.fromOutputScript(script, networks.regtest),
						value
					}))
					.filter(({ address }) => [a, b, c].includes(address))
					.map(({ address, value }) => `${address}:${value}`)
					.sort();
			};

			expect(paid(one.value.psbtBase64)).to.deep.equal([`${a}:10000`]);
			expect(paid(two.value.psbtBase64)).to.deep.equal(
				[`${b}:5000`, `${c}:6000`].sort()
			);
		});
	}

	it('leaves every coin to a concurrent PSBT build', async function () {
		wallet.updateCoinSelectPreference(ECoinSelectPreference.small);

		const [first, second] = await Promise.all([
			wallet.buildPsbt({ address: RECIPIENT, amount: 15_000, satsPerByte: 2 }),
			wallet.buildPsbt({ address: RECIPIENT, amount: 35_000, satsPerByte: 2 })
		]);
		if (first.isErr()) throw first.error;
		if (second.isErr()) throw second.error;

		expect(first.value.inputs).to.have.length(2);
		expect(second.value.inputs).to.have.length(4);
	});

	// Coin selection sorted the array it was given, and a quote gives it the
	// staged inputs (#1664).
	it('leaves the staged inputs in order when quoting', async function () {
		const values = [40_000, 10_000, 30_000, 20_000, 50_000];
		const heights = [105, 101, 103, 102, 104];
		const { utxos, balance } = wallet.data;
		const updated = await wallet.updateData({
			utxos: utxos.map((utxo, i) => ({
				...utxo,
				value: values[i],
				height: heights[i]
			})),
			balance: utxos.reduce(
				(sum, utxo, i) => sum + values[i] - utxo.value,
				balance
			)
		});
		if (updated.isErr()) throw updated.error;
		const staged = wallet.transaction.updateSendTransaction({
			transaction: {
				inputs: [...wallet.data.utxos],
				outputs: [{ address: RECIPIENT, value: 15_000, index: 0 }]
			}
		});
		if (staged.isErr()) throw staged.error;

		for (const coinSelectPreference of [
			ECoinSelectPreference.small,
			ECoinSelectPreference.large,
			ECoinSelectPreference.firstInFirstOut,
			ECoinSelectPreference.lastInFirstOut
		]) {
			const estimate = wallet.getFeeInfo({
				satsPerByte: 10,
				coinSelectPreference
			});
			if (estimate.isErr()) throw estimate.error;
			expect(
				wallet.transaction.data.inputs.map(({ value }) => value),
				coinSelectPreference
			).to.deep.equal(values);
		}
	});

	// Four coins pay 36,560 sats at 10 sat/vB and leave 3,440, exactly the fee
	// without change. Coin selection priced a change output as well and
	// refused the payment.
	describe('a payment with nothing left for change (#1526)', function () {
		const AMOUNT = 36_560;
		const FEE = 3_440;

		beforeEach(async function () {
			const utxos = [...wallet.data.utxos];
			const fifth = utxos.pop();
			if (!fifth) throw new Error('No UTXO to drop.');
			const res = await wallet.updateData({
				utxos,
				balance: wallet.data.balance - fifth.value
			});
			if (res.isErr()) throw res.error;
			injected.delete(fifth.tx_hash);
		});

		const expectNoChange = (tx: BitcoinTransaction): void => {
			expect(tx.ins).to.have.length(4);
			expect(tx.outs).to.have.length(1);
			expect(tx.outs[0].value).to.equal(AMOUNT);
			expect(feeOf(tx)).to.equal(FEE);
			expect(wallet.transaction.data.fee).to.equal(FEE);
			expect(feeOf(tx) / tx.virtualSize()).to.be.at.least(10);
		};

		const expectSends = async (): Promise<void> => {
			const res = await wallet.send({
				address: RECIPIENT,
				amount: AMOUNT,
				satsPerByte: 10,
				broadcast: false
			});
			if (res.isErr()) throw res.error;

			expectNoChange(BitcoinTransaction.fromHex(res.value));
			const estimate = wallet.getFeeInfo({ satsPerByte: 10 });
			if (estimate.isErr()) throw estimate.error;
			expect(estimate.value.totalFee).to.equal(FEE);
		};

		const expectBuilds = async (): Promise<void> => {
			const built = await wallet.buildPsbt({
				address: RECIPIENT,
				amount: AMOUNT,
				satsPerByte: 10
			});
			if (built.isErr()) throw built.error;
			const signed = wallet.signPsbtWithOurKey(built.value.psbtBase64);
			if (signed.isErr()) throw signed.error;
			const imported = wallet.importSignedPsbt(signed.value);
			if (imported.isErr()) throw imported.error;

			expectNoChange(BitcoinTransaction.fromHex(imported.value.txHex));
			expect(built.value.inputs).to.have.length(4);
			expect(built.value.fee).to.equal(FEE);
		};

		for (const preference of [
			ECoinSelectPreference.consolidate,
			ECoinSelectPreference.small,
			ECoinSelectPreference.large
		]) {
			it(`sends it under ${preference}`, async function () {
				wallet.updateCoinSelectPreference(preference);
				await expectSends();
			});

			it(`builds it under ${preference}`, async function () {
				wallet.updateCoinSelectPreference(preference);
				await expectBuilds();
			});
		}

		// A 300 sat coin selected after the four costs 680 to spend. Five inputs
		// leave 3,740 against a 3,820 fee without change, and coin selection
		// gave up on the four that already paid.
		describe('with an uneconomic coin selected last (#1549)', function () {
			const addTrailingCoin = async (
				preference: ECoinSelectPreference
			): Promise<void> => {
				const res = await wallet.updateData({
					utxos: wallet.data.utxos.map((utxo) => ({ ...utxo, height: 100 }))
				});
				if (res.isErr()) throw res.error;
				// FIFO spends the oldest coin first and LIFO the newest.
				await injectUtxo(
					'ff'.repeat(32),
					300,
					preference === ECoinSelectPreference.lastInFirstOut ? 99 : 101
				);
			};

			for (const preference of [
				ECoinSelectPreference.large,
				ECoinSelectPreference.firstInFirstOut,
				ECoinSelectPreference.lastInFirstOut
			]) {
				it(`sends it under ${preference}`, async function () {
					wallet.updateCoinSelectPreference(preference);
					await addTrailingCoin(preference);
					await expectSends();
				});

				it(`builds it under ${preference}`, async function () {
					wallet.updateCoinSelectPreference(preference);
					await addTrailingCoin(preference);
					await expectBuilds();
				});
			}
		});

		// The same coin picked before the payment is covered stayed in every
		// selection, so even the fallback to a shorter one kept it.
		describe('with an uneconomic coin selected first (#1566)', function () {
			const addLeadingCoin = async (): Promise<void> => {
				// FIFO and LIFO both reach the coin after two of the four.
				const res = await wallet.updateData({
					utxos: wallet.data.utxos.map((utxo, i) => ({
						...utxo,
						height: i < 2 ? 100 : 102
					}))
				});
				if (res.isErr()) throw res.error;
				await injectUtxo('ff'.repeat(32), 300, 101);
			};

			const expectQuotes = (): void => {
				const estimate = wallet.getFeeInfo({
					satsPerByte: 10,
					transaction: {
						outputs: [{ address: RECIPIENT, value: AMOUNT, index: 0 }]
					}
				});
				if (estimate.isErr()) throw estimate.error;
				expect(estimate.value.totalFee).to.equal(FEE);
			};

			for (const preference of [
				ECoinSelectPreference.small,
				ECoinSelectPreference.firstInFirstOut,
				ECoinSelectPreference.lastInFirstOut
			]) {
				it(`quotes it under ${preference}`, async function () {
					wallet.updateCoinSelectPreference(preference);
					await addLeadingCoin();
					expectQuotes();
				});

				it(`sends it under ${preference}`, async function () {
					wallet.updateCoinSelectPreference(preference);
					await addLeadingCoin();
					await expectSends();
				});

				it(`builds it under ${preference}`, async function () {
					wallet.updateCoinSelectPreference(preference);
					await addLeadingCoin();
					await expectBuilds();
				});
			}
		});
	});

	// Both small coins cost 680 sats each to spend, so neither comes back once
	// dropped. The 10,000 sat coin pays alone, with its 1,400 sat leftover as
	// the fee (#1579).
	describe('with coins dropped down to the size floor (#1575)', function () {
		const AMOUNT = 8_600;
		const FEE = 1_400;

		beforeEach(async function () {
			await dropUtxos();
			await injectUtxo('fd'.repeat(32), 300);
			await injectUtxo('fe'.repeat(32), 500);
			await injectUtxo('ff'.repeat(32), 10_000);
			wallet.updateCoinSelectPreference(ECoinSelectPreference.small);
		});

		const expectPaid = (tx: BitcoinTransaction): void => {
			expect(tx.ins).to.have.length(1);
			expect(tx.outs).to.have.length(1);
			expect(tx.outs[0].value).to.equal(AMOUNT);
			expect(feeOf(tx)).to.equal(FEE);
			expect(feeOf(tx) / tx.virtualSize()).to.be.at.least(10);
		};

		it('quotes it', function () {
			const estimate = wallet.getFeeInfo({
				satsPerByte: 10,
				transaction: {
					outputs: [{ address: RECIPIENT, value: AMOUNT, index: 0 }]
				}
			});
			if (estimate.isErr()) throw estimate.error;
			expect(estimate.value.totalFee).to.equal(FEE);
		});

		it('sends it', async function () {
			const res = await wallet.send({
				address: RECIPIENT,
				amount: AMOUNT,
				satsPerByte: 10,
				broadcast: false
			});
			if (res.isErr()) throw res.error;

			expectPaid(BitcoinTransaction.fromHex(res.value));
			expect(wallet.transaction.data.fee).to.equal(FEE);
		});

		it('builds it', async function () {
			const built = await wallet.buildPsbt({
				address: RECIPIENT,
				amount: AMOUNT,
				satsPerByte: 10
			});
			if (built.isErr()) throw built.error;
			const signed = wallet.signPsbtWithOurKey(built.value.psbtBase64);
			if (signed.isErr()) throw signed.error;
			const imported = wallet.importSignedPsbt(signed.value);
			if (imported.isErr()) throw imported.error;

			expectPaid(BitcoinTransaction.fromHex(imported.value.txHex));
			expect(built.value.fee).to.equal(FEE);
		});
	});

	// One input and one output come to 110 vB, so the 10,000 sat coin pays
	// 8,400 at 10 sat/vB and leaves 1,600. The small coins cost 680 sats each
	// to spend. Priced at 166 vB, nothing paid. With a 141 vB change output,
	// 8,300 leaves 290 and 8,400 leaves 190, both under P2WPKH dust, so the
	// whole leftover is the fee and the quote has to say so (#1584).
	describe('a payment under 166 vB (#1579)', function () {
		for (const [AMOUNT, FEE, coins] of [
			[8_300, 1_700, [100, 300, 10_000]],
			[8_300, 1_700, [10_000]],
			[8_400, 1_600, [100, 300, 10_000]],
			[8_400, 1_600, [10_000]]
		] as const) {
			describe(`of ${AMOUNT} from ${coins.join(', ')} sat coins`, function () {
				beforeEach(async function () {
					await dropUtxos();
					for (const [i, value] of coins.entries()) {
						await injectUtxo((0xfd + i).toString(16).repeat(32), value);
					}
					wallet.updateCoinSelectPreference(ECoinSelectPreference.small);
				});

				const expectPaid = (tx: BitcoinTransaction): void => {
					expect(tx.ins).to.have.length(1);
					expect(tx.outs).to.have.length(1);
					expect(tx.outs[0].value).to.equal(AMOUNT);
					expect(feeOf(tx)).to.equal(FEE);
					expect(feeOf(tx) / tx.virtualSize()).to.be.at.least(10);
				};

				it('quotes it', function () {
					const estimate = wallet.getFeeInfo({
						satsPerByte: 10,
						transaction: {
							outputs: [{ address: RECIPIENT, value: AMOUNT, index: 0 }]
						}
					});
					if (estimate.isErr()) throw estimate.error;
					expect(estimate.value.totalFee).to.equal(FEE);
					expect(estimate.value.transactionByteCount).to.equal(110);
					expect(estimate.value.satsPerByte).to.equal(10);
				});

				it('sends it', async function () {
					const res = await wallet.send({
						address: RECIPIENT,
						amount: AMOUNT,
						satsPerByte: 10,
						broadcast: false
					});
					if (res.isErr()) throw res.error;

					expectPaid(BitcoinTransaction.fromHex(res.value));
					expect(wallet.transaction.data.fee).to.equal(FEE);
				});

				it('builds it', async function () {
					const built = await wallet.buildPsbt({
						address: RECIPIENT,
						amount: AMOUNT,
						satsPerByte: 10
					});
					if (built.isErr()) throw built.error;
					const signed = wallet.signPsbtWithOurKey(built.value.psbtBase64);
					if (signed.isErr()) throw signed.error;
					const imported = wallet.importSignedPsbt(signed.value);
					if (imported.isErr()) throw imported.error;

					expectPaid(BitcoinTransaction.fromHex(imported.value.txHex));
					expect(built.value.fee).to.equal(FEE);
				});
			});
		}
	});

	// 3,000 from a 4,500 sat coin at 10 sat/vB leaves 90 sats of change, so
	// the fee is the whole 1,500 leftover, half the payment, which updateFee
	// refuses. 8 sat/vB is the highest rate that keeps the change (#1584).
	describe('a payment whose dust change is half its fee (#1584)', function () {
		const AMOUNT = 3_000;

		beforeEach(async function () {
			await dropUtxos();
			await injectUtxo('ff'.repeat(32), 4_500);
			wallet.updateCoinSelectPreference(ECoinSelectPreference.small);
		});

		it('quotes the highest rate that keeps the change', async function () {
			const estimate = wallet.getFeeInfo({
				satsPerByte: 10,
				transaction: {
					outputs: [{ address: RECIPIENT, value: AMOUNT, index: 0 }]
				}
			});
			if (estimate.isErr()) throw estimate.error;
			expect(estimate.value.satsPerByte).to.equal(8);
			expect(estimate.value.totalFee).to.equal(1_128);

			const refused = await wallet.send({
				address: RECIPIENT,
				amount: AMOUNT,
				satsPerByte: 10,
				broadcast: false
			});
			expect(refused.isErr()).to.equal(true);

			const res = await wallet.send({
				address: RECIPIENT,
				amount: AMOUNT,
				satsPerByte: 8,
				broadcast: false
			});
			if (res.isErr()) throw res.error;
			const tx = BitcoinTransaction.fromHex(res.value);
			expect(tx.outs).to.have.length(2);
			expect(feeOf(tx)).to.equal(estimate.value.totalFee);
		});
	});

	// At 1.5 sat/vB all five coins leave 147 sats of change, so the fee is
	// the 767 leftover, over half the payment. 1 sat/vB selects only four,
	// whose 122 sats of change is dust, so the capped quote is their 467
	// leftover, not the 413 the five coins would pay at that rate.
	describe('a capped quote that selects fewer coins (#1584)', function () {
		const AMOUNT = 1_533;

		beforeEach(async function () {
			await dropUtxos();
			for (const [i, value] of [300, 300, 300, 500, 900].entries()) {
				await injectUtxo((0xe0 + i).toString(16).repeat(32), value);
			}
			wallet.updateCoinSelectPreference(ECoinSelectPreference.large);
		});

		it('quotes what the capped send pays', async function () {
			const estimate = wallet.getFeeInfo({
				satsPerByte: 1.5,
				transaction: {
					outputs: [{ address: RECIPIENT, value: AMOUNT, index: 0 }]
				}
			});
			if (estimate.isErr()) throw estimate.error;
			expect(estimate.value.satsPerByte).to.equal(1);

			const res = await wallet.send({
				address: RECIPIENT,
				amount: AMOUNT,
				satsPerByte: estimate.value.satsPerByte,
				broadcast: false
			});
			if (res.isErr()) throw res.error;
			const tx = BitcoinTransaction.fromHex(res.value);
			expect(tx.ins).to.have.length(4);
			expect(tx.outs).to.have.length(1);
			expect(feeOf(tx)).to.equal(estimate.value.totalFee);
			expect(estimate.value.totalFee).to.equal(467);
			expect(estimate.value.transactionByteCount).to.equal(314);
		});
	});

	// At 1.5 sat/vB the 256 vB size floor leaves 1,100 from a 1,700 sat coin
	// with 216 sats of change, so the fee is the 600 leftover, over half the
	// payment. 2 sat/vB has no floor and keeps the change, so the maximum is
	// above the request, but only 1 sat/vB fits below it.
	describe('a requested rate below a higher maximum that fits (#1584)', function () {
		const AMOUNT = 1_100;

		beforeEach(async function () {
			await dropUtxos();
			await injectUtxo('ff'.repeat(32), 1_700);
			wallet.updateCoinSelectPreference(ECoinSelectPreference.small);
		});

		it('quotes a rate below the request that sends', async function () {
			const estimate = wallet.getFeeInfo({
				satsPerByte: 1.5,
				transaction: {
					outputs: [{ address: RECIPIENT, value: AMOUNT, index: 0 }]
				}
			});
			if (estimate.isErr()) throw estimate.error;
			expect(estimate.value.satsPerByte).to.equal(1);
			expect(estimate.value.totalFee).to.equal(256);

			const refused = await wallet.send({
				address: RECIPIENT,
				amount: AMOUNT,
				satsPerByte: 1.5,
				broadcast: false
			});
			expect(refused.isErr()).to.equal(true);

			const res = await wallet.send({
				address: RECIPIENT,
				amount: AMOUNT,
				satsPerByte: estimate.value.satsPerByte,
				broadcast: false
			});
			if (res.isErr()) throw res.error;
			const tx = BitcoinTransaction.fromHex(res.value);
			expect(tx.outs).to.have.length(2);
			expect(feeOf(tx)).to.equal(estimate.value.totalFee);
		});
	});

	// About 420 coins cover the payment and 70 more its fee at 20 sat/vB. A
	// quote selects coins at every rate its searches try, and repricing the
	// whole selection for each coin added made every quote quadratic in the
	// number of coins (#1664).
	describe('with 500 coins (#1664)', function () {
		const AMOUNT = 4_200_000;

		beforeEach(async function () {
			await dropUtxos();
			for (let i = 0; i < 500; i++) {
				await injectUtxo(
					i.toString(16).padStart(64, '0'),
					10_000 + (i % 7) * 13
				);
			}
			wallet.updateCoinSelectPreference(ECoinSelectPreference.small);
		});

		it('quotes a range of rates in well under a second', function () {
			const started = Date.now();
			for (const satsPerByte of [1, 2, 5, 10, 20]) {
				const estimate = wallet.getFeeInfo({
					satsPerByte,
					transaction: {
						outputs: [{ address: RECIPIENT, value: AMOUNT, index: 0 }]
					}
				});
				if (estimate.isErr()) throw estimate.error;
				expect(estimate.value.satsPerByte).to.equal(satsPerByte);
			}
			expect(Date.now() - started).to.be.below(1_000);
		});
	});
});
