/**
 * Two on-chain wallet defects (#1038). Fully OFFLINE: the wallet is created
 * with remainOffline, UTXOs are injected into wallet data, and the
 * transaction lookups a boost makes are stubbed.
 *
 *  1. sendMax priced its single output as the wallet's own address type, so a
 *     p2wpkh wallet sweeping to a p2tr or p2wsh address paid for 31 vB of
 *     output and built 43 (visible once the sweep is above the 166 vB floor).
 *  2. getRbfData's "already confirmed" guard read the request echo Electrum
 *     tags each result with, so it never fired, and setupCpfp had no fresh
 *     check at all. Both relied on the height stored at the last refresh.
 */

import { expect } from 'chai';
import net from 'net';
import tls from 'tls';
import sinon from 'sinon';
import {
	address as bitcoinAddress,
	networks,
	payments,
	script as bitcoinScript,
	Transaction as BitcoinTransaction
} from 'bitcoinjs-lib';

import {
	EAddressType,
	EAvailableNetworks,
	EBoostType,
	ECoinSelectPreference,
	IUtxo,
	Wallet,
	createMemoryStorage,
	ok
} from '../src';
import {
	IFormattedTransaction,
	ITxHash,
	TTxDetails
} from '../src/types/wallet';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

// The wallet is created with remainOffline: this test must work offline.
const electrumOptions = { net, tls };

const P2TR = bitcoinAddress.toBech32(Buffer.alloc(32, 1), 1, 'bcrt');
const P2WSH = bitcoinAddress.toBech32(Buffer.alloc(32, 2), 0, 'bcrt');
const P2WPKH = bitcoinAddress.toBech32(Buffer.alloc(20, 3), 0, 'bcrt');
const FOREIGN = bitcoinAddress.toBech32(Buffer.alloc(20, 4), 0, 'bcrt');

/** A verbose scriptPubKey for an OP_RETURN pushing each message. */
const nulldata = (
	...messages: string[]
): { asm: string; hex: string; type: string } => {
	const script = payments.embed({
		data: messages.map((message) => Buffer.from(message))
	}).output as Buffer;
	return {
		asm: bitcoinScript.toASM(script),
		hex: script.toString('hex'),
		type: 'nulldata'
	};
};

const BOOSTED_TXID = 'bb'.repeat(32);
const FUNDING_TXID = 'aa'.repeat(32);
const FOREIGN_TXID = 'cc'.repeat(32);

describe('sweep output pricing and boost confirmation guard (#1038)', function () {
	this.timeout(60000);

	let wallet: Wallet;

	const receiveAddress = (): string =>
		wallet.data.addressIndex[EAddressType.p2wpkh].address;
	const changeAddress = (): string =>
		wallet.data.changeAddressIndex[EAddressType.p2wpkh].address;

	/** Fabricates a UTXO paying to the wallet's own index-0 address. */
	const injectUtxo = async (
		txid: string,
		value: number,
		txPos = 0
	): Promise<IUtxo> => {
		const source = wallet.data.addressIndex[EAddressType.p2wpkh];
		if (!source?.address) throw new Error('No derived address available.');
		const utxo: IUtxo = {
			address: source.address,
			index: source.index,
			path: source.path,
			scriptHash: source.scriptHash,
			height: 0,
			tx_hash: txid,
			tx_pos: txPos,
			value,
			publicKey: source.publicKey
		};
		const res = await wallet.updateData({
			utxos: [...wallet.data.utxos, utxo],
			balance: wallet.data.balance + value
		});
		if (res.isErr()) throw res.error;
		return utxo;
	};

	/**
	 * Answers getTransactions from a fixed set of verbose results, each tagged
	 * with the request it answers, the way rn-electrum-client tags them.
	 */
	const stubLookups = (results: Record<string, Partial<TTxDetails>>): void => {
		sinon
			.stub(wallet.electrum, 'getTransactions')
			.callsFake(async ({ txHashes }: { txHashes: ITxHash[] }) =>
				ok({
					error: false,
					id: 0,
					method: 'getTransactions',
					network: 'regtest',
					data: txHashes.map(({ tx_hash }) => ({
						id: 0,
						jsonrpc: '2.0',
						param: tx_hash,
						data: { tx_hash } as unknown as IUtxo,
						result: { txid: tx_hash, ...results[tx_hash] } as TTxDetails
					}))
				})
			);
	};

	/**
	 * The boosted transaction spends a confirmed 100k output of ours, pays 40k
	 * sats away and 50k back to change, leaving a 10k fee.
	 */
	const stubBoostedTransaction = (
		confirmations?: number,
		{ recipient = 40_000, change = 50_000 } = {}
	): void => {
		stubLookups({
			[BOOSTED_TXID]: {
				confirmations,
				vin: [{ txid: FUNDING_TXID, vout: 0 }] as TTxDetails['vin'],
				vout: [
					{ value: recipient / 1e8, n: 0, scriptPubKey: { address: P2WPKH } },
					{
						value: change / 1e8,
						n: 1,
						scriptPubKey: { address: changeAddress() }
					}
				] as unknown as TTxDetails['vout']
			},
			[FUNDING_TXID]: {
				confirmations: 10,
				vout: [
					{ value: 0.001, n: 0, scriptPubKey: { address: receiveAddress() } }
				] as unknown as TTxDetails['vout']
			}
		});
	};

	beforeEach(async function () {
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			name: 'sweeppricing',
			network: EAvailableNetworks.regtest,
			addressType: EAddressType.p2wpkh,
			rbf: true,
			storage: createMemoryStorage(),
			electrumOptions,
			remainOffline: true
		});
		if (res.isErr()) throw res.error;
		wallet = res.value;
		// The failed (offline) refresh still generates index-0 addresses.
		await wallet.refreshWallet({});
		wallet.feeEstimates = { ...wallet.feeEstimates, fast: 10, normal: 5 };
	});

	afterEach(async function () {
		sinon.restore();
		await wallet?.stop();
	});

	describe('sendMax', function () {
		[
			{ name: 'p2tr', to: P2TR },
			{ name: 'p2wsh', to: P2WSH },
			{ name: 'p2wpkh', to: P2WPKH }
		].forEach(({ name, to }) => {
			it(`pays the requested rate on a sweep to ${name}`, async function () {
				const satsPerByte = 10;
				await injectUtxo(FUNDING_TXID, 100_000);
				await injectUtxo(BOOSTED_TXID, 100_000);

				const res = await wallet.sendMax({
					address: to,
					satsPerByte,
					broadcast: false
				});
				if (res.isErr()) throw res.error;

				const tx = BitcoinTransaction.fromHex(res.value);
				expect(tx.ins).to.have.length(2);
				expect(tx.outs, 'a sweep needs no change output').to.have.length(1);
				const fee = 200_000 - tx.outs[0].value;
				// A 2-in-1-out p2wpkh-to-p2tr sweep is about 190 vB. Priced as p2wpkh
				// it paid for 178.
				expect(fee).to.be.at.least(tx.virtualSize() * satsPerByte);
				expect(fee).to.equal(wallet.transaction.data.fee);
			});
		});

		// A sweep has no change output to CPFP from, so RBF is the sender's only
		// way to bump it (#1359).
		[true, false].forEach((rbf) => {
			it(`stages rbf: ${rbf} in the input sequences`, async function () {
				await injectUtxo(FUNDING_TXID, 100_000);
				await injectUtxo(BOOSTED_TXID, 100_000);

				const res = await wallet.sendMax({
					address: P2WPKH,
					satsPerByte: 10,
					rbf,
					broadcast: false
				});
				if (res.isErr()) throw res.error;

				const tx = BitcoinTransaction.fromHex(res.value);
				expect(tx.ins).to.have.length(2);
				for (const input of tx.ins) {
					expect(input.sequence < 0xfffffffe, 'signals RBF').to.equal(rbf);
				}
			});
		});
	});

	describe('getFeeInfo', function () {
		// #1492: at 7 sat/vB the send selects the second coin, so the one coin
		// selected at 2 sat/vB must not cap the maximum.
		[ECoinSelectPreference.small, ECoinSelectPreference.large].forEach(
			(preference) => {
				it(`quotes a maximum rate that selects another coin with preference ${preference}`, async function () {
					wallet.updateCoinSelectPreference(preference);
					await injectUtxo(FUNDING_TXID, 100_000);
					await injectUtxo(BOOSTED_TXID, 100_000);
					const setup = await wallet.transaction.setupTransaction();
					if (setup.isErr()) throw setup.error;
					const staged = wallet.transaction.updateSendTransaction({
						transaction: {
							outputs: [{ address: P2WPKH, value: 99_000, index: 0 }]
						}
					});
					if (staged.isErr()) throw staged.error;

					const quote = wallet.getFeeInfo({ satsPerByte: 2 });
					if (quote.isErr()) throw quote.error;
					expect(quote.value.maxSatPerByte).to.be.at.least(7);
					const updated = wallet.transaction.updateFee({ satsPerByte: 7 });
					if (updated.isErr()) throw updated.error;
				});

				// #1545: one coin pays 5 sat/vB, so the size-based maximum is 540.
				// Coin selection at 540 adds the second coin, and with it the fee is
				// over half the payment down to 365.
				it(`quotes a maximum rate whose own coin selection fits under half with preference ${preference}`, async function () {
					wallet.updateCoinSelectPreference(preference);
					await injectUtxo(FUNDING_TXID, 185_744);
					await injectUtxo(BOOSTED_TXID, 176_152);
					const setup = await wallet.transaction.setupTransaction();
					if (setup.isErr()) throw setup.error;
					const staged = wallet.transaction.updateSendTransaction({
						transaction: {
							outputs: [{ address: P2WPKH, value: 152_312, index: 0 }]
						}
					});
					if (staged.isErr()) throw staged.error;

					const quote = wallet.getFeeInfo({ satsPerByte: 5 });
					if (quote.isErr()) throw quote.error;
					expect(quote.value.transactionByteCount).to.equal(141);
					expect(quote.value.maxSatPerByte).to.equal(364);
					const atMax = wallet.transaction.updateFee({
						satsPerByte: quote.value.maxSatPerByte
					});
					if (atMax.isErr()) throw atMax.error;
					expect(atMax.value.fee).to.equal(209 * 364);
					const aboveMax = wallet.transaction.updateFee({
						satsPerByte: quote.value.maxSatPerByte + 1
					});
					expect(aboveMax.isErr(), '365 sat/vB is refused').to.equal(true);
				});

				// From 95 sat/vB both coins pay the whole 20,000 left over, more than
				// half the payment: up to 110 as change the leftover cannot pay for,
				// from 111 as dust the builder adds to the fee (#1586). Preference
				// large pays 95 sat/vB with the 50,322 coin alone.
				[
					[29_936, 29_936],
					[50_322, 9_550]
				].forEach(([first, second]) => {
					const oneCoin =
						preference === ECoinSelectPreference.large && first === 50_322;
					const [maximum, size] = oneCoin ? [95, 110] : [94, 209];
					it(`quotes a maximum rate below a whole-leftover fee with preference ${preference} and coins of ${first} and ${second}`, async function () {
						wallet.updateCoinSelectPreference(preference);
						await injectUtxo(FUNDING_TXID, first);
						await injectUtxo(BOOSTED_TXID, second);
						const setup = await wallet.transaction.setupTransaction();
						if (setup.isErr()) throw setup.error;
						const staged = wallet.transaction.updateSendTransaction({
							transaction: {
								changeAddress: '',
								outputs: [{ address: P2WPKH, value: 39_872, index: 0 }]
							}
						});
						if (staged.isErr()) throw staged.error;

						const quote = wallet.getFeeInfo({ satsPerByte: 112 });
						if (quote.isErr()) throw quote.error;
						expect(quote.value.maxSatPerByte).to.equal(maximum);
						expect(quote.value.totalFee).to.equal(size * maximum);
						const atMax = wallet.transaction.updateFee({
							satsPerByte: quote.value.maxSatPerByte
						});
						if (atMax.isErr()) throw atMax.error;
						expect(atMax.value.fee).to.equal(quote.value.totalFee);
						const aboveMax = wallet.transaction.updateFee({
							satsPerByte: quote.value.maxSatPerByte + 1
						});
						expect(aboveMax.isErr()).to.equal(true);
					});
				});
			}
		);

		// #1565: half the 190,000 payment allows 454 sat/vB, but only 10,000 is
		// left over. At 56 the change drops and the 178 vB fee fits it.
		[
			ECoinSelectPreference.small,
			ECoinSelectPreference.large,
			ECoinSelectPreference.consolidate
		].forEach((preference) => {
			it(`quotes a maximum rate the inputs can pay with preference ${preference}`, async function () {
				wallet.updateCoinSelectPreference(preference);
				await injectUtxo(FUNDING_TXID, 100_000);
				await injectUtxo(BOOSTED_TXID, 100_000);
				const setup = await wallet.transaction.setupTransaction();
				if (setup.isErr()) throw setup.error;
				const staged = wallet.transaction.updateSendTransaction({
					transaction: {
						outputs: [{ address: P2WPKH, value: 190_000, index: 0 }]
					}
				});
				if (staged.isErr()) throw staged.error;

				const quote = wallet.getFeeInfo({ satsPerByte: 5 });
				if (quote.isErr()) throw quote.error;
				expect(quote.value.totalFee).to.equal(209 * 5);
				expect(quote.value.maxSatPerByte).to.equal(56);
				const atMax = wallet.transaction.updateFee({
					satsPerByte: quote.value.maxSatPerByte
				});
				if (atMax.isErr()) throw atMax.error;
				expect(atMax.value.fee).to.equal(10_000);
				const aboveMax = wallet.transaction.updateFee({
					satsPerByte: quote.value.maxSatPerByte + 1
				});
				expect(aboveMax.isErr(), '57 sat/vB is refused').to.equal(true);
			});
		});

		// #1518: 1 sat/vB with change is exactly half the 602 payment, but the
		// change drops and the fee is the 270 sats left over.
		it('quotes a maximum rate that drops the change output', async function () {
			wallet.updateCoinSelectPreference(ECoinSelectPreference.consolidate);
			await injectUtxo(FUNDING_TXID, 436);
			await injectUtxo(BOOSTED_TXID, 436);
			const setup = await wallet.transaction.setupTransaction();
			if (setup.isErr()) throw setup.error;
			const message = 'm'.repeat(80);
			const staged = wallet.transaction.updateSendTransaction({
				transaction: {
					message,
					outputs: [{ address: P2WPKH, value: 602, index: 0 }]
				}
			});
			if (staged.isErr()) throw staged.error;

			const quote = wallet.getFeeInfo({ satsPerByte: 2, message });
			if (quote.isErr()) throw quote.error;
			expect(quote.value.maxSatPerByte).to.equal(1);
			const atMax = wallet.transaction.updateFee({
				satsPerByte: quote.value.maxSatPerByte
			});
			if (atMax.isErr()) throw atMax.error;
			expect(atMax.value.fee).to.equal(270);
			stubLookups({});
			const created = await wallet.transaction.createTransaction();
			if (created.isErr()) throw created.error;
			const tx = BitcoinTransaction.fromHex(created.value.hex);
			expect(tx.outs.map((out) => out.value)).to.have.members([0, 602]);
		});

		// #1518: six coins at 1 sat/vB are exactly half the 962 payment, but that
		// rate selects five and pays 413. Without a staged change address the
		// quote prices the change the builder generates.
		[
			{ name: 'staged', stagedChange: {} },
			{ name: 'generated', stagedChange: { changeAddress: '' } }
		].forEach(({ name, stagedChange }) => {
			it(`quotes a maximum rate that selects fewer coins with ${name} change`, async function () {
				wallet.updateCoinSelectPreference(ECoinSelectPreference.small);
				for (const [txPos, value] of [300, 300, 300, 300, 500, 600].entries()) {
					await injectUtxo(FUNDING_TXID, value, txPos);
				}
				const setup = await wallet.transaction.setupTransaction();
				if (setup.isErr()) throw setup.error;
				const staged = wallet.transaction.updateSendTransaction({
					transaction: {
						...stagedChange,
						outputs: [{ address: P2WPKH, value: 962, index: 0 }]
					}
				});
				if (staged.isErr()) throw staged.error;

				const quote = wallet.getFeeInfo({ satsPerByte: 2 });
				if (quote.isErr()) throw quote.error;
				expect(quote.value.maxSatPerByte).to.equal(1);
				const atMax = wallet.transaction.updateFee({
					satsPerByte: quote.value.maxSatPerByte
				});
				if (atMax.isErr()) throw atMax.error;
				expect(atMax.value.fee).to.equal(413);
				stubLookups({});
				const created = await wallet.transaction.createTransaction({
					runCoinSelect: true
				});
				if (created.isErr()) throw created.error;
				const tx = BitcoinTransaction.fromHex(created.value.hex);
				expect(tx.ins).to.have.length(5);
				expect(tx.outs.map((out) => out.value)).to.have.members([962, 325]);
			});
		});

		// #1519: 1,000 sat/vB leaves nothing for change, but the builder adds it
		// at the maximum, so the maximum has to pay for its 31 vB.
		it('quotes a maximum rate that pays for the change it generates', async function () {
			wallet.updateCoinSelectPreference(ECoinSelectPreference.consolidate);
			await injectUtxo(FUNDING_TXID, 100_000);
			await injectUtxo(BOOSTED_TXID, 100_000);
			const setup = await wallet.transaction.setupTransaction();
			if (setup.isErr()) throw setup.error;
			const staged = wallet.transaction.updateSendTransaction({
				transaction: {
					changeAddress: '',
					outputs: [{ address: P2WPKH, value: 40_000, index: 0 }]
				}
			});
			if (staged.isErr()) throw staged.error;

			const quote = wallet.getFeeInfo({ satsPerByte: 1000 });
			if (quote.isErr()) throw quote.error;
			expect(quote.value.maxSatPerByte).to.equal(95);
			expect(quote.value.transactionByteCount).to.equal(209);
			expect(quote.value.totalFee).to.equal(209 * 95);
			const atMax = wallet.transaction.updateFee({
				satsPerByte: quote.value.maxSatPerByte
			});
			if (atMax.isErr()) throw atMax.error;
			expect(atMax.value.fee).to.equal(quote.value.totalFee);
			stubLookups({});
			const created = await wallet.transaction.createTransaction();
			if (created.isErr()) throw created.error;
			const tx = BitcoinTransaction.fromHex(created.value.hex);
			expect(tx.outs.map((out) => out.value)).to.have.members([
				40_000,
				160_000 - atMax.value.fee
			]);
		});

		// #1584: at 95 sat/vB the 39,872 payment leaves 281 sats of change,
		// under dust, so the fee is the whole 20,136 leftover, over half.
		[
			{ input: 30_004, payment: 39_872, maximum: 94 },
			{ input: 55_903, payment: 74_404, maximum: 177 }
		].forEach(({ input, payment, maximum }) => {
			it(`prices generated change below half a ${payment}-sat payment`, async function () {
				wallet.updateCoinSelectPreference(ECoinSelectPreference.consolidate);
				await injectUtxo(FUNDING_TXID, input);
				await injectUtxo(BOOSTED_TXID, input);
				const setup = await wallet.transaction.setupTransaction();
				if (setup.isErr()) throw setup.error;
				const staged = wallet.transaction.updateSendTransaction({
					transaction: {
						changeAddress: '',
						outputs: [{ address: P2WPKH, value: payment, index: 0 }]
					}
				});
				if (staged.isErr()) throw staged.error;

				const quote = wallet.getFeeInfo({ satsPerByte: 1000 });
				if (quote.isErr()) throw quote.error;
				expect(quote.value.maxSatPerByte).to.equal(maximum);
				expect(quote.value.transactionByteCount).to.equal(209);
				expect(quote.value.totalFee).to.equal(209 * maximum);
				const atMax = wallet.transaction.updateFee({
					satsPerByte: quote.value.maxSatPerByte
				});
				if (atMax.isErr()) throw atMax.error;
				expect(atMax.value.fee).to.equal(quote.value.totalFee);
				stubLookups({});
				const created = await wallet.transaction.createTransaction();
				if (created.isErr()) throw created.error;
				const tx = BitcoinTransaction.fromHex(created.value.hex);
				expect(tx.outs.map((out) => out.value)).to.have.members([
					payment,
					2 * input - payment - quote.value.totalFee
				]);
			});
		});

		// #1520: half the 166,239 payment over 141 vB is 589.5 sat/vB. 589.1 is
		// affordable, but the quote rounded it down to 589.
		it('quotes a fractional rate above the integer maximum that it can pay', async function () {
			wallet.updateCoinSelectPreference(ECoinSelectPreference.consolidate);
			await injectUtxo(FUNDING_TXID, 1_000_000);
			const setup = await wallet.transaction.setupTransaction();
			if (setup.isErr()) throw setup.error;
			const staged = wallet.transaction.updateSendTransaction({
				transaction: {
					outputs: [{ address: P2WPKH, value: 166_239, index: 0 }]
				}
			});
			if (staged.isErr()) throw staged.error;

			const quote = wallet.getFeeInfo({ satsPerByte: 589.1 });
			if (quote.isErr()) throw quote.error;
			expect(quote.value.maxSatPerByte).to.equal(589);
			expect(quote.value.satsPerByte).to.equal(589.1);
			const updated = wallet.transaction.updateFee({ satsPerByte: 589.1 });
			if (updated.isErr()) throw updated.error;
			expect(updated.value.fee).to.equal(83_064);
			expect(quote.value.totalFee).to.equal(updated.value.fee);

			const capped = wallet.getFeeInfo({ satsPerByte: 589.6 });
			if (capped.isErr()) throw capped.error;
			expect(capped.value.satsPerByte).to.equal(589);
			const refused = wallet.transaction.updateFee({ satsPerByte: 589.6 });
			expect(refused.isErr(), '589.6 sat/vB is refused').to.equal(true);
		});
	});

	describe('setupRbf', function () {
		beforeEach(async function () {
			await injectUtxo(FUNDING_TXID, 100_000);
		});

		it('refuses a transaction that has confirmed since the last refresh', async function () {
			stubBoostedTransaction(1);

			const res = await wallet.transaction.setupRbf({ txid: BOOSTED_TXID });

			expect(res.isErr(), 'setupRbf refused').to.equal(true);
			if (res.isOk()) return;
			expect(res.error.message).to.include('already confirmed');
		});

		it('replaces an unconfirmed transaction that spends a confirmed coin', async function () {
			// The old guard sat in the input loop, where the transaction looked up
			// is the one funding the input. That one is normally confirmed, so the
			// check belongs on the transaction being replaced.
			stubBoostedTransaction(undefined);

			const res = await wallet.transaction.setupRbf({ txid: BOOSTED_TXID });

			if (res.isErr()) throw res.error;
			expect(res.value.inputs.map((input) => input.tx_hash)).to.deep.equal([
				FUNDING_TXID
			]);
			expect(res.value.changeAddress).to.equal(changeAddress());
		});

		/**
		 * The boosted transaction spends two 100k coins, so a replacement must
		 * too. Its 1k fee is outbid at the rates these tests ask for.
		 */
		const stubTwoInputBoostedTransaction = (recipient = 40_000): void => {
			stubLookups({
				[BOOSTED_TXID]: {
					vin: [
						{ txid: FUNDING_TXID, vout: 0 },
						{ txid: FUNDING_TXID, vout: 1 }
					] as TTxDetails['vin'],
					vout: [
						{ value: recipient / 1e8, n: 0, scriptPubKey: { address: P2WPKH } },
						{
							value: (199_000 - recipient) / 1e8,
							n: 1,
							scriptPubKey: { address: changeAddress() }
						}
					] as unknown as TTxDetails['vout']
				},
				[FUNDING_TXID]: {
					confirmations: 10,
					vout: [
						{ value: 0.001, n: 0, scriptPubKey: { address: receiveAddress() } },
						{ value: 0.001, n: 1, scriptPubKey: { address: receiveAddress() } }
					] as unknown as TTxDetails['vout']
				}
			});
		};

		// #1364: the change output was priced twice, once from the outputs and
		// once from changeAddress.
		it('prices the replacement it builds', async function () {
			// Smallest-first selection covers the 40k payment with one input, so
			// it would price the two-input replacement an input short.
			wallet.updateCoinSelectPreference(ECoinSelectPreference.small);
			stubTwoInputBoostedTransaction();

			const res = await wallet.transaction.setupRbf({ txid: BOOSTED_TXID });
			if (res.isErr()) throw res.error;
			const created = await wallet.transaction.createTransaction();
			if (created.isErr()) throw created.error;

			const tx = BitcoinTransaction.fromHex(created.value.hex);
			expect(tx.ins).to.have.length(2);
			expect(tx.outs).to.have.length(2);
			const fee = 200_000 - tx.outs.reduce((sum, out) => sum + out.value, 0);
			expect(res.value.satsPerByte).to.equal(10);
			expect(fee).to.equal(res.value.fee);
			// At the fast rate of 10 sat/vB. A third, phantom output adds 31 vB.
			expect(fee).to.be.at.least(tx.virtualSize() * 10);
			expect(fee).to.be.below((tx.virtualSize() + 31) * 10);
		});

		// #1428: either preference covers the 40k payment with one input.
		[ECoinSelectPreference.small, ECoinSelectPreference.large].forEach(
			(preference) => {
				it(`pays a custom rate on every input with preference ${preference}`, async function () {
					wallet.updateCoinSelectPreference(preference);
					stubTwoInputBoostedTransaction();

					const res = await wallet.transaction.setupRbf({ txid: BOOSTED_TXID });
					if (res.isErr()) throw res.error;
					const updated = wallet.transaction.updateFee({ satsPerByte: 20 });
					if (updated.isErr()) throw updated.error;
					const created = await wallet.transaction.createTransaction();
					if (created.isErr()) throw created.error;

					const tx = BitcoinTransaction.fromHex(created.value.hex);
					expect(tx.ins).to.have.length(2);
					expect(tx.outs.map((out) => out.value)).to.include(40_000);
					const fee =
						200_000 - tx.outs.reduce((sum, out) => sum + out.value, 0);
					expect(fee).to.equal(updated.value.fee);
					expect(fee).to.be.at.least(tx.virtualSize() * 20);
					expect(wallet.coinSelectPreference).to.equal(preference);
				});
			}
		);

		// #1462: the quote coin-selected the same single input.
		[ECoinSelectPreference.small, ECoinSelectPreference.large].forEach(
			(preference) => {
				it(`quotes every input of a replacement with preference ${preference}`, async function () {
					wallet.updateCoinSelectPreference(preference);
					stubTwoInputBoostedTransaction();

					const res = await wallet.transaction.setupRbf({ txid: BOOSTED_TXID });
					if (res.isErr()) throw res.error;
					const updated = wallet.transaction.updateFee({ satsPerByte: 20 });
					if (updated.isErr()) throw updated.error;
					const quote = wallet.getFeeInfo({ satsPerByte: 20 });
					if (quote.isErr()) throw quote.error;
					const created = await wallet.transaction.createTransaction();
					if (created.isErr()) throw created.error;

					const tx = BitcoinTransaction.fromHex(created.value.hex);
					expect(tx.ins).to.have.length(2);
					const fee =
						200_000 - tx.outs.reduce((sum, out) => sum + out.value, 0);
					expect(quote.value.totalFee).to.equal(fee);
					const atMax = wallet.transaction.updateFee({
						satsPerByte: quote.value.maxSatPerByte
					});
					expect(atMax.isOk(), 'the quoted maximum rate is accepted').to.equal(
						true
					);
					expect(wallet.coinSelectPreference).to.equal(preference);
				});
			}
		);

		// #1492: half the 180k payment allowed 430 sat/vB, a fee the 20k left
		// after it cannot pay. #1496: a rate the change cannot pay sends without
		// it, so the maximum is priced without the 31 vB P2WPKH change output.
		[ECoinSelectPreference.small, ECoinSelectPreference.large].forEach(
			(preference) => {
				it(`quotes a maximum rate the leftover can pay with preference ${preference}`, async function () {
					wallet.updateCoinSelectPreference(preference);
					stubTwoInputBoostedTransaction(180_000);

					const res = await wallet.transaction.setupRbf({ txid: BOOSTED_TXID });
					if (res.isErr()) throw res.error;
					const updated = wallet.transaction.updateFee({ satsPerByte: 20 });
					if (updated.isErr()) throw updated.error;
					const quote = wallet.getFeeInfo({ satsPerByte: 20 });
					if (quote.isErr()) throw quote.error;
					expect(quote.value.totalFee).to.equal(updated.value.fee);

					const { maxSatPerByte, transactionByteCount } = quote.value;
					expect(maxSatPerByte).to.equal(
						Math.floor(20_000 / (transactionByteCount - 31))
					);
					const atMax = wallet.transaction.updateFee({
						satsPerByte: maxSatPerByte
					});
					if (atMax.isErr()) throw atMax.error;
					const capped = wallet.getFeeInfo({ satsPerByte: maxSatPerByte + 1 });
					if (capped.isErr()) throw capped.error;
					expect(capped.value.satsPerByte).to.equal(maxSatPerByte);
					expect(capped.value.totalFee).to.equal(atMax.value.fee);
					const created = await wallet.transaction.createTransaction();
					if (created.isErr()) throw created.error;
					const tx = BitcoinTransaction.fromHex(created.value.hex);
					expect(tx.outs.map((out) => out.value)).to.deep.equal([180_000]);
					expect(20_000).to.be.at.least(maxSatPerByte * tx.virtualSize());
					const overMax = wallet.transaction.updateFee({
						satsPerByte: maxSatPerByte + 1
					});
					expect(overMax.isErr(), 'one more sat/vB is refused').to.equal(true);
				});
			}
		);

		// #1518: half the 41,800 payment is exactly 100 sat/vB over 209 vB, a fee
		// updateFee refuses.
		[ECoinSelectPreference.small, ECoinSelectPreference.large].forEach(
			(preference) => {
				it(`quotes a maximum rate under half the payment with preference ${preference}`, async function () {
					wallet.updateCoinSelectPreference(preference);
					stubTwoInputBoostedTransaction(41_800);

					const res = await wallet.transaction.setupRbf({ txid: BOOSTED_TXID });
					if (res.isErr()) throw res.error;
					const quote = wallet.getFeeInfo({ satsPerByte: 20 });
					if (quote.isErr()) throw quote.error;

					const { maxSatPerByte, transactionByteCount } = quote.value;
					const atMax = wallet.transaction.updateFee({
						satsPerByte: maxSatPerByte
					});
					if (atMax.isErr()) throw atMax.error;
					expect(atMax.value.fee).to.equal(
						maxSatPerByte * transactionByteCount
					);
					expect((maxSatPerByte + 1) * transactionByteCount).to.equal(
						41_800 / 2
					);
					const overMax = wallet.transaction.updateFee({
						satsPerByte: maxSatPerByte + 1
					});
					expect(overMax.isErr(), 'one more sat/vB is refused').to.equal(true);
				});
			}
		);

		// #1520: the 4,285 sats the 195,715 payment leaves pay 24.05 sat/vB on
		// the 178 vB without change, but the quote rounded the rate down to 24.
		it('quotes a fractional rate above the integer maximum that the leftover can pay', async function () {
			stubTwoInputBoostedTransaction(195_715);

			const res = await wallet.transaction.setupRbf({ txid: BOOSTED_TXID });
			if (res.isErr()) throw res.error;
			const quote = wallet.getFeeInfo({ satsPerByte: 24.05 });
			if (quote.isErr()) throw quote.error;
			expect(quote.value.maxSatPerByte).to.equal(24);
			expect(quote.value.satsPerByte).to.equal(24.05);
			const updated = wallet.transaction.updateFee({ satsPerByte: 24.05 });
			if (updated.isErr()) throw updated.error;
			expect(updated.value.fee).to.equal(4_285);
			expect(quote.value.totalFee).to.equal(updated.value.fee);

			const capped = wallet.getFeeInfo({ satsPerByte: 24.1 });
			if (capped.isErr()) throw capped.error;
			expect(capped.value.satsPerByte).to.equal(24);
			const refused = wallet.transaction.updateFee({ satsPerByte: 24.1 });
			expect(refused.isErr(), '24.1 sat/vB is refused').to.equal(true);
		});

		// #1430: at these estimates the quote was 1,660 sats and minFee 2, both
		// under the original's 10k fee.
		it('outbids the original fee when estimates have fallen', async function () {
			wallet.feeEstimates = { ...wallet.feeEstimates, fast: 10, slow: 2 };
			stubBoostedTransaction();

			const res = await wallet.transaction.setupRbf({ txid: BOOSTED_TXID });
			if (res.isErr()) throw res.error;
			const { minFee, fee: quotedFee, satsPerByte } = res.value;
			expect(satsPerByte, 'quoted at the floor').to.equal(minFee);

			const below = wallet.transaction.updateFee({ satsPerByte: minFee - 1 });
			expect(below.isErr(), 'a rate under the floor is refused').to.equal(true);
			const updated = wallet.transaction.updateFee({ satsPerByte: minFee });
			if (updated.isErr()) throw updated.error;
			expect(updated.value.fee).to.equal(quotedFee);
			const created = await wallet.transaction.createTransaction();
			if (created.isErr()) throw created.error;

			const tx = BitcoinTransaction.fromHex(created.value.hex);
			const fee = 100_000 - tx.outs.reduce((sum, out) => sum + out.value, 0);
			expect(fee).to.equal(quotedFee);
			// More than the original, by its own size at 1 sat/vB (BIP 125).
			expect(fee - 10_000).to.be.at.least(tx.virtualSize());
		});

		it('covers the incremental relay fee for a signed nested SegWit replacement', async function () {
			const source = wallet.data.addressIndex[EAddressType.p2sh];
			const change = wallet.data.changeAddressIndex[EAddressType.p2sh].address;
			const previous = new BitcoinTransaction();
			previous.addInput(Buffer.alloc(32, 1), 0);
			const script = bitcoinAddress.toOutputScript(
				source.address,
				networks.regtest
			);
			previous.addOutput(script, 100_000);
			previous.addOutput(script, 100_000);
			const originalFee = 2_550;
			wallet.feeEstimates = { ...wallet.feeEstimates, fast: 2, slow: 1 };
			sinon.stub(wallet, 'fetchRbfData').resolves(
				ok({
					inputs: [0, 1].map((index) => ({
						...source,
						index,
						height: 0,
						tx_hash: previous.getId(),
						tx_pos: index,
						value: 100_000
					})),
					outputs: [
						{ address: P2WPKH, value: 10_000, index: 0 },
						{ address: change, value: 187_450, index: 1 }
					],
					changeAddress: change,
					fee: originalFee,
					balance: 200_000,
					addressType: EAddressType.p2sh,
					message: ''
				})
			);
			stubLookups({ [previous.getId()]: { hex: previous.toHex() } });

			const res = await wallet.transaction.setupRbf({ txid: BOOSTED_TXID });
			if (res.isErr()) throw res.error;
			expect(res.value.minFee).to.equal(11);
			const updated = wallet.transaction.updateFee({
				satsPerByte: res.value.minFee
			});
			if (updated.isErr()) throw updated.error;
			expect(updated.value.fee).to.equal(res.value.fee);
			const created = await wallet.transaction.createTransaction({
				shuffleOutputs: false
			});
			if (created.isErr()) throw created.error;

			const tx = BitcoinTransaction.fromHex(created.value.hex);
			expect(tx.virtualSize()).to.equal(256);
			const fee = 200_000 - tx.outs.reduce((sum, out) => sum + out.value, 0);
			expect(fee).to.equal(res.value.fee);
			expect(fee - originalFee).to.be.at.least(tx.virtualSize());
		});

		// #1489: the foreign input was skipped, so the original's 20k fee read as
		// 10k and a 10,292 sat replacement was signed.
		[
			{ name: 'a foreign address', scriptPubKey: { address: FOREIGN } },
			{
				name: 'no address',
				scriptPubKey: { asm: `${'02'.repeat(33)} OP_CHECKSIG`, type: 'pubkey' }
			}
		].forEach(({ name, scriptPubKey }) => {
			it(`refuses a transaction with an input paid to ${name}`, async function () {
				wallet.feeEstimates = { ...wallet.feeEstimates, fast: 10, slow: 2 };
				stubLookups({
					[BOOSTED_TXID]: {
						vin: [
							{ txid: FUNDING_TXID, vout: 0 },
							{ txid: FOREIGN_TXID, vout: 0 }
						] as TTxDetails['vin'],
						vout: [
							{ value: 0.0004, n: 0, scriptPubKey: { address: P2WPKH } },
							{
								value: 0.0005,
								n: 1,
								scriptPubKey: { address: changeAddress() }
							}
						] as unknown as TTxDetails['vout']
					},
					[FUNDING_TXID]: {
						confirmations: 10,
						vout: [
							{
								value: 0.001,
								n: 0,
								scriptPubKey: { address: receiveAddress() }
							}
						] as unknown as TTxDetails['vout']
					},
					[FOREIGN_TXID]: {
						confirmations: 10,
						vout: [
							{ value: 0.0001, n: 0, scriptPubKey }
						] as unknown as TTxDetails['vout']
					}
				});

				const rbfData = await wallet.getRbfData({
					txHash: { tx_hash: BOOSTED_TXID }
				});
				expect(rbfData.isErr(), 'getRbfData refused').to.equal(true);
				const res = await wallet.transaction.setupRbf({ txid: BOOSTED_TXID });

				expect(res.isErr(), 'setupRbf refused').to.equal(true);
				if (res.isOk()) return;
				expect(res.error.message).to.include('Unable to RBF');
				expect(wallet.transaction.data.outputs).to.have.length(0);
				expect(wallet.transaction.data.boostType).to.not.equal(EBoostType.rbf);
			});
		});

		// #1517: an OP_RETURN before the change was staged as a zero-value
		// payment to the address read before it, which failed to sign.
		[0, 1, 2].forEach((position) => {
			it(`signs a replacement with an OP_RETURN at output ${position}`, async function () {
				const message = 'hello beignet';
				const vout: Record<string, unknown>[] = [
					{ value: 0.0004, scriptPubKey: { address: P2WPKH } },
					{ value: 0.0005, scriptPubKey: { address: changeAddress() } }
				];
				vout.splice(position, 0, {
					value: 0,
					scriptPubKey: nulldata(message)
				});
				stubLookups({
					[BOOSTED_TXID]: {
						vin: [{ txid: FUNDING_TXID, vout: 0 }] as TTxDetails['vin'],
						vout: vout.map((output, n) => ({
							...output,
							n
						})) as unknown as TTxDetails['vout']
					},
					[FUNDING_TXID]: {
						confirmations: 10,
						vout: [
							{
								value: 0.001,
								n: 0,
								scriptPubKey: { address: receiveAddress() }
							}
						] as unknown as TTxDetails['vout']
					}
				});

				const rbfData = await wallet.getRbfData({
					txHash: { tx_hash: BOOSTED_TXID }
				});
				if (rbfData.isErr()) throw rbfData.error;
				expect(rbfData.value.fee).to.equal(10_000);
				const res = await wallet.transaction.setupRbf({ txid: BOOSTED_TXID });
				if (res.isErr()) throw res.error;
				expect(res.value.outputs).to.deep.equal([
					{ address: P2WPKH, value: 40_000, index: 0 }
				]);
				expect(res.value.message).to.equal(message);
				const created = await wallet.transaction.createTransaction();
				if (created.isErr()) throw created.error;

				const tx = BitcoinTransaction.fromHex(created.value.hex);
				expect(tx.outs).to.have.length(3);
				const embedded = tx.outs.filter((out) => out.script[0] === 0x6a);
				expect(embedded).to.have.length(1);
				expect(embedded[0].value).to.equal(0);
				expect(embedded[0].script.toString()).to.include(message);
				const fee = 100_000 - tx.outs.reduce((sum, out) => sum + out.value, 0);
				expect(fee).to.equal(res.value.fee);
				expect(fee - 10_000).to.be.at.least(tx.virtualSize());
			});
		});

		/** The boosted transaction with these OP_RETURNs after its change. */
		const stubWithNulldata = (
			...scriptPubKeys: Record<string, unknown>[]
		): void =>
			stubLookups({
				[BOOSTED_TXID]: {
					vin: [{ txid: FUNDING_TXID, vout: 0 }] as TTxDetails['vin'],
					vout: [
						{ value: 0.0004, scriptPubKey: { address: P2WPKH } },
						{ value: 0.0005, scriptPubKey: { address: changeAddress() } },
						...scriptPubKeys.map((scriptPubKey) => ({ value: 0, scriptPubKey }))
					].map((output, n) => ({
						...output,
						n
					})) as unknown as TTxDetails['vout']
				},
				[FUNDING_TXID]: {
					confirmations: 10,
					vout: [
						{
							value: 0.001,
							n: 0,
							scriptPubKey: { address: receiveAddress() }
						}
					] as unknown as TTxDetails['vout']
				}
			});

		// #1542: bitcoind's asm shows a push of up to 4 bytes as a number, so
		// "hi" was read as no message and left out of the replacement.
		it('signs a replacement that keeps a two byte message', async function () {
			stubWithNulldata({
				asm: 'OP_RETURN 26984',
				hex: '6a026869',
				type: 'nulldata'
			});

			const res = await wallet.transaction.setupRbf({ txid: BOOSTED_TXID });
			if (res.isErr()) throw res.error;
			expect(res.value.message).to.equal('hi');
			const created = await wallet.transaction.createTransaction();
			if (created.isErr()) throw created.error;

			const tx = BitcoinTransaction.fromHex(created.value.hex);
			const embedded = tx.outs.filter((out) => out.script[0] === 0x6a);
			expect(embedded).to.have.length(1);
			const [, payload] = bitcoinScript.decompile(embedded[0].script) ?? [];
			expect(Buffer.isBuffer(payload)).to.equal(true);
			expect((payload as Buffer).toString().trimEnd()).to.equal('hi');
			const fee = 100_000 - tx.outs.reduce((sum, out) => sum + out.value, 0);
			expect(fee).to.equal(res.value.fee);
		});

		// #1542: the replacement carries one message, and every message but the
		// last was dropped from it.
		[
			{
				name: 'two OP_RETURN outputs',
				scriptPubKeys: [nulldata('first message'), nulldata('second message')]
			},
			{
				name: 'an OP_RETURN with two pushes',
				scriptPubKeys: [nulldata('first message', 'second message')]
			}
		].forEach(({ name, scriptPubKeys }) => {
			it(`refuses a transaction with ${name}`, async function () {
				stubWithNulldata(...scriptPubKeys);

				const rbfData = await wallet.getRbfData({
					txHash: { tx_hash: BOOSTED_TXID }
				});
				expect(rbfData.isErr(), 'getRbfData refused').to.equal(true);
				const res = await wallet.transaction.setupRbf({ txid: BOOSTED_TXID });

				expect(res.isErr(), 'setupRbf refused').to.equal(true);
				if (res.isOk()) return;
				expect(res.error.message).to.include('more than one OP_RETURN message');
				expect(wallet.transaction.data.outputs).to.have.length(0);
				expect(wallet.transaction.data.boostType).to.not.equal(EBoostType.rbf);
				const created = await wallet.transaction.createTransaction();
				expect(created.isErr(), 'nothing is signed').to.equal(true);
			});
		});

		// #1561: the replacement rebuilt the message from UTF-8 text, so 0xff was
		// signed as U+FFFD and five spaces were left out.
		[
			{ name: 'is not valid UTF-8', hex: '6a05ff74657374' },
			{ name: 'is only spaces', hex: '6a052020202020' }
		].forEach(({ name, hex }) => {
			it(`refuses a transaction whose OP_RETURN message ${name}`, async function () {
				stubWithNulldata({
					asm: bitcoinScript.toASM(Buffer.from(hex, 'hex')),
					hex,
					type: 'nulldata'
				});

				const rbfData = await wallet.getRbfData({
					txHash: { tx_hash: BOOSTED_TXID }
				});
				expect(rbfData.isErr(), 'getRbfData refused').to.equal(true);
				const res = await wallet.transaction.setupRbf({ txid: BOOSTED_TXID });

				expect(res.isErr(), 'setupRbf refused').to.equal(true);
				if (res.isOk()) return;
				expect(res.error.message).to.include('cannot rebuild');
				expect(wallet.transaction.data.outputs).to.have.length(0);
				expect(wallet.transaction.data.boostType).to.not.equal(EBoostType.rbf);
				const created = await wallet.transaction.createTransaction();
				expect(created.isErr(), 'nothing is signed').to.equal(true);
			});
		});

		// #1541: a bare pubkey output inherited the address read before it. Its
		// 10k was paid to the input's address, to the recipient, or into change.
		[0, 1, 2].forEach((position) => {
			it(`refuses a transaction that pays a bare pubkey at output ${position}`, async function () {
				const vout: Record<string, unknown>[] = [
					{ value: 0.0004, scriptPubKey: { address: P2WPKH } },
					{ value: 0.0004, scriptPubKey: { address: changeAddress() } }
				];
				vout.splice(position, 0, {
					value: 0.0001,
					scriptPubKey: {
						asm: `${'02'.repeat(33)} OP_CHECKSIG`,
						type: 'pubkey'
					}
				});
				stubLookups({
					[BOOSTED_TXID]: {
						vin: [{ txid: FUNDING_TXID, vout: 0 }] as TTxDetails['vin'],
						vout: vout.map((output, n) => ({
							...output,
							n
						})) as unknown as TTxDetails['vout']
					},
					[FUNDING_TXID]: {
						confirmations: 10,
						vout: [
							{
								value: 0.001,
								n: 0,
								scriptPubKey: { address: receiveAddress() }
							}
						] as unknown as TTxDetails['vout']
					}
				});

				const rbfData = await wallet.getRbfData({
					txHash: { tx_hash: BOOSTED_TXID }
				});
				expect(rbfData.isErr(), 'getRbfData refused').to.equal(true);
				const res = await wallet.transaction.setupRbf({ txid: BOOSTED_TXID });

				expect(res.isErr(), 'setupRbf refused').to.equal(true);
				if (res.isOk()) return;
				expect(res.error.message).to.include('without an address');
				expect(wallet.transaction.data.outputs).to.have.length(0);
				expect(wallet.transaction.data.boostType).to.not.equal(EBoostType.rbf);
				const created = await wallet.transaction.createTransaction();
				expect(created.isErr(), 'nothing is signed').to.equal(true);
			});
		});

		// #1521: the quote left out the staged message, so it offered 60 sat/vB
		// on 166 vB. With the message that is 10,860 sats even without change,
		// more than the 10k left. 55 is 10k over the 181 vB without change.
		[ECoinSelectPreference.small, ECoinSelectPreference.large].forEach(
			(preference) => {
				it(`quotes a maximum rate that pays for the message with preference ${preference}`, async function () {
					wallet.updateCoinSelectPreference(preference);
					const message = 'm'.repeat(60);
					stubLookups({
						[BOOSTED_TXID]: {
							vin: [{ txid: FUNDING_TXID, vout: 0 }] as TTxDetails['vin'],
							vout: [
								{ value: 0.0009, n: 0, scriptPubKey: { address: P2WPKH } },
								{ value: 0, n: 1, scriptPubKey: nulldata(message) },
								{
									value: 0.00009,
									n: 2,
									scriptPubKey: { address: changeAddress() }
								}
							] as unknown as TTxDetails['vout']
						},
						[FUNDING_TXID]: {
							confirmations: 10,
							vout: [
								{
									value: 0.001,
									n: 0,
									scriptPubKey: { address: receiveAddress() }
								}
							] as unknown as TTxDetails['vout']
						}
					});

					const res = await wallet.transaction.setupRbf({ txid: BOOSTED_TXID });
					if (res.isErr()) throw res.error;
					expect(res.value.message).to.equal(message);
					const quote = wallet.getFeeInfo({ satsPerByte: 20 });
					if (quote.isErr()) throw quote.error;
					const explicit = wallet.getFeeInfo({ satsPerByte: 20, message });
					if (explicit.isErr()) throw explicit.error;
					expect(quote.value).to.deep.equal(explicit.value);
					const withoutMessage = wallet.getFeeInfo({
						satsPerByte: 20,
						message: ''
					});
					if (withoutMessage.isErr()) throw withoutMessage.error;
					expect(withoutMessage.value.transactionByteCount).to.be.below(
						quote.value.transactionByteCount
					);

					const { maxSatPerByte } = quote.value;
					expect(maxSatPerByte).to.equal(55);
					const atMax = wallet.transaction.updateFee({
						satsPerByte: maxSatPerByte
					});
					if (atMax.isErr()) throw atMax.error;
					const created = await wallet.transaction.createTransaction();
					if (created.isErr()) throw created.error;
					const tx = BitcoinTransaction.fromHex(created.value.hex);
					expect(
						tx.outs.filter((out) => out.script[0] === 0x6a)
					).to.have.length(1);
					const fee =
						100_000 - tx.outs.reduce((sum, out) => sum + out.value, 0);
					expect(fee).to.equal(atMax.value.fee);
					expect(fee).to.be.at.least(maxSatPerByte * tx.virtualSize());
					const overMax = wallet.transaction.updateFee({
						satsPerByte: maxSatPerByte + 1
					});
					expect(overMax.isErr(), 'one more sat/vB is refused').to.equal(true);
				});
			}
		);

		it('refuses when the change cannot pay the replacement floor', async function () {
			wallet.feeEstimates = { ...wallet.feeEstimates, fast: 10, slow: 2 };
			// Outbidding a 9,961 sat fee on 141 vB takes 72 sat/vB, which is 191
			// sats more. The change holds 100, and dropping it pays 100 more than
			// the original, short of the 110 vB the replacement then needs.
			stubBoostedTransaction(undefined, { recipient: 89_939, change: 100 });

			const res = await wallet.transaction.setupRbf({ txid: BOOSTED_TXID });

			expect(res.isErr(), 'setupRbf refused').to.equal(true);
			if (res.isOk()) return;
			expect(res.error.message).to.include('Not enough sats');
		});

		// #1544: outbidding the 9,700 sat fee takes 43 sat/vB, which the 300 sat
		// change cannot pay. Without it the 10k left pays 49.5 sat/vB on 202 vB,
		// but outputs plus fee equal the inputs, and that read as too little.
		[ECoinSelectPreference.small, ECoinSelectPreference.large].forEach(
			(preference) => {
				it(`drops change the replacement exhausts with preference ${preference}`, async function () {
					wallet.updateCoinSelectPreference(preference);
					wallet.feeEstimates = { ...wallet.feeEstimates, fast: 10, slow: 2 };
					const message = 'm'.repeat(80);
					stubLookups({
						[BOOSTED_TXID]: {
							vin: [{ txid: FUNDING_TXID, vout: 0 }] as TTxDetails['vin'],
							vout: [
								{ value: 0.0009, n: 0, scriptPubKey: { address: P2WPKH } },
								{
									value: 0.000003,
									n: 1,
									scriptPubKey: { address: changeAddress() }
								},
								{ value: 0, n: 2, scriptPubKey: nulldata(message) }
							] as unknown as TTxDetails['vout']
						},
						[FUNDING_TXID]: {
							confirmations: 10,
							vout: [
								{
									value: 0.001,
									n: 0,
									scriptPubKey: { address: receiveAddress() }
								}
							] as unknown as TTxDetails['vout']
						}
					});

					const res = await wallet.transaction.setupRbf({ txid: BOOSTED_TXID });
					if (res.isErr()) throw res.error;
					expect(res.value.minFee).to.equal(43);
					expect(res.value.satsPerByte).to.equal(43);
					expect(res.value.fee).to.equal(10_000);
					expect(res.value.outputs).to.deep.equal([
						{ address: P2WPKH, value: 90_000, index: 0 }
					]);
					expect(res.value.message).to.equal(message);
					const updated = wallet.transaction.updateFee({
						satsPerByte: res.value.minFee
					});
					if (updated.isErr()) throw updated.error;
					expect(updated.value.fee).to.equal(res.value.fee);
					const created = await wallet.transaction.createTransaction();
					if (created.isErr()) throw created.error;

					const tx = BitcoinTransaction.fromHex(created.value.hex);
					expect(tx.outs).to.have.length(2);
					expect(tx.outs.map((out) => out.value)).to.include(90_000);
					const embedded = tx.outs.filter((out) => out.script[0] === 0x6a);
					expect(embedded).to.have.length(1);
					expect(embedded[0].script.toString()).to.include(message);
					const fee =
						100_000 - tx.outs.reduce((sum, out) => sum + out.value, 0);
					expect(fee).to.equal(10_000);
					expect(fee).to.be.at.least(43 * tx.virtualSize());
					// More than the original, by its own size at 1 sat/vB (BIP 125).
					expect(fee - 9_700).to.be.at.least(tx.virtualSize());
					expect(wallet.coinSelectPreference).to.equal(preference);
				});
			}
		);

		// #1563: outbidding the 1,000 sat fee on 344 vB takes 4 sat/vB, which the
		// 300 sat change cannot pay. Without it the 1,300 left pays the rate on
		// 313 vB, but only 300 more than the original (BIP 125 wants 313).
		[ECoinSelectPreference.small, ECoinSelectPreference.large].forEach(
			(preference) => {
				it(`refuses a dropped-change replacement under the relay floor with preference ${preference}`, async function () {
					wallet.updateCoinSelectPreference(preference);
					wallet.feeEstimates = { ...wallet.feeEstimates, fast: 2, slow: 1 };
					const vouts = [0, 1, 2, 3];
					stubLookups({
						[BOOSTED_TXID]: {
							vin: vouts.map((vout) => ({
								txid: FUNDING_TXID,
								vout
							})) as TTxDetails['vin'],
							vout: [
								{ value: 0.003987, n: 0, scriptPubKey: { address: P2WPKH } },
								{
									value: 0.000003,
									n: 1,
									scriptPubKey: { address: changeAddress() }
								}
							] as unknown as TTxDetails['vout']
						},
						[FUNDING_TXID]: {
							confirmations: 10,
							vout: vouts.map((n) => ({
								value: 0.001,
								n,
								scriptPubKey: { address: receiveAddress() }
							})) as unknown as TTxDetails['vout']
						}
					});

					const res = await wallet.transaction.setupRbf({ txid: BOOSTED_TXID });

					expect(res.isErr(), 'setupRbf refused').to.equal(true);
					if (res.isOk()) return;
					expect(res.error.message).to.include('Not enough sats');
				});
			}
		);
	});

	describe('setupCpfp', function () {
		beforeEach(async function () {
			// The unconfirmed parent as stored at the last refresh: 200 vB, 1000
			// sats of fee, and an output of ours the child can spend.
			const parent = await wallet.updateData({
				transactions: {
					...wallet.data.transactions,
					[BOOSTED_TXID]: { fee: 0.00001, vsize: 200 } as IFormattedTransaction
				}
			});
			if (parent.isErr()) throw parent.error;
			await injectUtxo(BOOSTED_TXID, 50_000);
		});

		it('refuses a parent that has confirmed since the last refresh', async function () {
			stubLookups({ [BOOSTED_TXID]: { confirmations: 1 } });
			const sendMax = sinon.spy(wallet.transaction, 'sendMax');

			const res = await wallet.transaction.setupCpfp({ txid: BOOSTED_TXID });

			expect(res.isErr(), 'setupCpfp refused').to.equal(true);
			if (res.isOk()) return;
			expect(res.error.message).to.include('already confirmed');
			expect(sendMax.called, 'no child was set up').to.equal(false);
			expect(wallet.transaction.data.outputs).to.have.length(0);
		});

		it('sets up a child for a parent that is still unconfirmed', async function () {
			stubLookups({ [BOOSTED_TXID]: {} });

			const res = await wallet.transaction.setupCpfp({ txid: BOOSTED_TXID });

			if (res.isErr()) throw res.error;
			expect(
				res.value.inputs.map((input) => input.tx_hash),
				'only the parent is spent'
			).to.deep.equal([BOOSTED_TXID]);
		});

		// #1497: the child was sized at 141 vB. Spending both of the parent's
		// outputs to us makes it about 177, so the first three packages came
		// out below fast and the last below normal at minFee.
		[
			{ fast: 1.5, normal: 1, parentFee: 282 },
			{ fast: 2, normal: 1, parentFee: 423 },
			{ fast: 4, normal: 1, parentFee: 705 },
			{ fast: 10, normal: 2, parentFee: 423 }
		].forEach(({ fast, normal, parentFee }) => {
			it(`brings a two-input child's package to fast ${fast} and normal ${normal}`, async function () {
				const parentVsize = 141;
				const parent = await wallet.updateData({
					transactions: {
						...wallet.data.transactions,
						[BOOSTED_TXID]: {
							fee: parentFee / 1e8,
							vsize: parentVsize
						} as IFormattedTransaction
					}
				});
				if (parent.isErr()) throw parent.error;
				await injectUtxo(BOOSTED_TXID, 50_000, 1);
				wallet.feeEstimates = { ...wallet.feeEstimates, fast, normal };
				stubLookups({ [BOOSTED_TXID]: {} });

				/** Signs a child at the rate given, or the one setupCpfp picks. */
				const signChild = async (
					satsPerByte?: number
				): Promise<{ packageRate: number; minFee: number }> => {
					const res = await wallet.transaction.setupCpfp({
						txid: BOOSTED_TXID,
						satsPerByte
					});
					if (res.isErr()) throw res.error;
					const { minFee } = res.value;
					const created = await wallet.transaction.createTransaction();
					if (created.isErr()) throw created.error;
					const tx = BitcoinTransaction.fromHex(created.value.hex);
					expect(tx.ins).to.have.length(2);
					const childFee = 100_000 - tx.outs[0].value;
					return {
						packageRate:
							(parentFee + childFee) / (parentVsize + tx.virtualSize()),
						minFee
					};
				};

				const atFast = await signChild();
				expect(atFast.packageRate).to.be.at.least(fast);
				const atMinFee = await signChild(atFast.minFee);
				expect(atMinFee.packageRate).to.be.at.least(normal);
			});
		});
	});
});
