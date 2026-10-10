/**
 * Two on-chain wallet defects (#1038). Fully OFFLINE: the wallet points at an
 * unreachable Electrum port, UTXOs are injected into wallet data, and the
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
	Transaction as BitcoinTransaction
} from 'bitcoinjs-lib';

import {
	EAddressType,
	EAvailableNetworks,
	EBoostType,
	ECoinSelectPreference,
	EProtocol,
	IUtxo,
	IWalletData,
	Result,
	TStorage,
	Wallet,
	ok
} from '../src';
import {
	IFormattedTransaction,
	ITxHash,
	TTxDetails
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

const P2TR = bitcoinAddress.toBech32(Buffer.alloc(32, 1), 1, 'bcrt');
const P2WSH = bitcoinAddress.toBech32(Buffer.alloc(32, 2), 0, 'bcrt');
const P2WPKH = bitcoinAddress.toBech32(Buffer.alloc(20, 3), 0, 'bcrt');
const FOREIGN = bitcoinAddress.toBech32(Buffer.alloc(20, 4), 0, 'bcrt');

const BOOSTED_TXID = 'bb'.repeat(32);
const FUNDING_TXID = 'aa'.repeat(32);
const FOREIGN_TXID = 'cc'.repeat(32);

/** An in-memory TStorage, so the wallet has somewhere to persist. */
const memoryStorage = (): TStorage => {
	const store = new Map<string, unknown>();
	return {
		getData: async <K extends keyof IWalletData>(
			key: string
		): Promise<Result<IWalletData[K]>> => ok(store.get(key) as IWalletData[K]),
		setData: async <K extends keyof IWalletData>(
			key: string,
			value: IWalletData[K]
		): Promise<Result<boolean>> => {
			store.set(key, value);
			return ok(true);
		}
	};
};

describe('sweep output pricing and boost confirmation guard (#1038)', function () {
	this.timeout(60000);

	let wallet: Wallet;

	const receiveAddress = (): string =>
		wallet.data.addressIndex[EAddressType.p2wpkh].address;
	const changeAddress = (): string =>
		wallet.data.changeAddressIndex[EAddressType.p2wpkh].address;

	/** Fabricates a UTXO paying to the wallet's own index-0 address. */
	const injectUtxo = (txid: string, value: number, txPos = 0): IUtxo => {
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
		wallet.data.utxos.push(utxo);
		wallet.data.balance += value;
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
			storage: memoryStorage(),
			electrumOptions
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
				// Two inputs, because getByteCount floors every estimate at 166 vB and
				// a 1-in-1-out sweep sits under that floor whatever its output type.
				injectUtxo(FUNDING_TXID, 100_000);
				injectUtxo(BOOSTED_TXID, 100_000);

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
				injectUtxo(FUNDING_TXID, 100_000);
				injectUtxo(BOOSTED_TXID, 100_000);

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
					injectUtxo(FUNDING_TXID, 100_000);
					injectUtxo(BOOSTED_TXID, 100_000);
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
			}
		);

		// #1518: 1 sat/vB with change is exactly half the 602 payment, but the
		// change drops and the fee is the 270 sats left over.
		it('quotes a maximum rate that drops the change output', async function () {
			wallet.updateCoinSelectPreference(ECoinSelectPreference.consolidate);
			injectUtxo(FUNDING_TXID, 436);
			injectUtxo(BOOSTED_TXID, 436);
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
				[300, 300, 300, 300, 500, 600].forEach((value, txPos) =>
					injectUtxo(FUNDING_TXID, value, txPos)
				);
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
	});

	describe('setupRbf', function () {
		beforeEach(function () {
			injectUtxo(FUNDING_TXID, 100_000);
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
			sinon.stub(wallet, 'getRbfData').resolves(
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
					scriptPubKey: {
						asm: `OP_RETURN ${Buffer.from(message).toString('hex')}`,
						type: 'nulldata'
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

		it('refuses when the change cannot pay the replacement floor', async function () {
			wallet.feeEstimates = { ...wallet.feeEstimates, fast: 10, slow: 2 };
			// Outbidding a 9,961 sat fee on 166 vB takes 62 sat/vB, which is 331
			// sats more. The change holds 300.
			stubBoostedTransaction(undefined, { recipient: 89_739, change: 300 });

			const res = await wallet.transaction.setupRbf({ txid: BOOSTED_TXID });

			expect(res.isErr(), 'setupRbf refused').to.equal(true);
			if (res.isOk()) return;
			expect(res.error.message).to.include('Not enough sats');
		});
	});

	describe('setupCpfp', function () {
		beforeEach(function () {
			// The unconfirmed parent as stored at the last refresh: 200 vB, 1000
			// sats of fee, and an output of ours the child can spend.
			wallet.data.transactions[BOOSTED_TXID] = {
				fee: 0.00001,
				vsize: 200
			} as IFormattedTransaction;
			injectUtxo(BOOSTED_TXID, 50_000);
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
				wallet.data.transactions[BOOSTED_TXID] = {
					fee: parentFee / 1e8,
					vsize: parentVsize
				} as IFormattedTransaction;
				injectUtxo(BOOSTED_TXID, 50_000, 1);
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
