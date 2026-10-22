/**
 * Golden values for coin selection and fee pricing (#1704). Every scenario in
 * fee-pricing-scenarios.ts goes through autoCoinSelect, getTotalFee with and
 * without generated change, and getTotalFeeObj, and the results must match
 * fee-pricing-golden.json exactly. The file was recorded before selection and
 * pricing moved into pure functions, so a refactor that changes any number
 * fails here.
 *
 * A deliberate pricing change rewrites the file with
 *   UPDATE_GOLDEN=1 npx mocha --exit -r ts-node/register tests/fee-pricing-golden.test.ts
 * and the diff shows every quote it moves.
 *
 * Fully OFFLINE: the wallets never connect (remainOffline).
 */

import { expect } from 'chai';
import fs from 'fs';
import net from 'net';
import tls from 'tls';
import BIP32Factory from 'bip32';
import * as ecc from '@bitcoinerlab/secp256k1';
import * as bip39 from 'bip39';
import { networks } from 'bitcoinjs-lib';

import type { IUtxo, Transaction } from '../src';
import {
	EAddressType,
	EAvailableNetworks,
	ECoinSelectPreference,
	Wallet,
	createMemoryStorage
} from '../src';
import {
	GOLDEN_FILE,
	IPricingScenario,
	RANDOM_COUNT,
	RANDOM_SEED,
	STAGED_CHANGE,
	TPricingRecord,
	TWalletKey,
	WALLETS,
	addressOf,
	coin,
	fixtureScenarios,
	randomScenarios,
	recordOf
} from './fee-pricing-scenarios';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const COSIGNER_MNEMONICS = [
	'legal winner thank year wave sausage worth useful legal winner thank yellow',
	'letter advice cage absurd amount doctor acoustic avoid letter advice cage above'
];
const network = EAvailableNetworks.regtest;
const electrumOptions = { net, tls };

const run = (
	transaction: Transaction,
	{
		coinSelectPreference,
		satsPerByte,
		transaction: staged,
		message,
		fundingLightning
	}: IPricingScenario
): TPricingRecord => {
	const { inputs } = staged;
	const order = [...inputs];
	const feeWith = (generatesChange: boolean): number =>
		transaction.getTotalFee({
			satsPerByte,
			message,
			transaction: staged,
			fundingLightning,
			coinSelectPreference,
			generatesChange
		});
	const record = recordOf({
		inputs,
		selected: transaction.autoCoinSelect({
			inputs,
			outputs: staged.outputs ?? [],
			changeAddress: staged.changeAddress,
			satsPerByte,
			message,
			coinSelectPreference
		}),
		fee: feeWith(true),
		feeWithoutChange: feeWith(false),
		quote: transaction.getTotalFeeObj({
			satsPerByte,
			message,
			transaction: staged,
			fundingLightning,
			coinSelectPreference
		})
	});
	// A quote is a read: the caller's coins keep their order.
	expect(inputs).to.have.length(order.length);
	inputs.forEach((input, i) => expect(input).to.equal(order[i]));
	return record;
};

const readGolden = (): Record<string, unknown> =>
	fs.existsSync(GOLDEN_FILE)
		? (JSON.parse(fs.readFileSync(GOLDEN_FILE, 'utf8')) as Record<
				string,
				unknown
		  >)
		: {};

/** One scenario per line, so a changed quote is a one-line diff. */
const writeGolden = (records: Record<string, unknown>): void => {
	const lines = Object.entries(records).map(
		([name, record]) => `\t${JSON.stringify(name)}: ${JSON.stringify(record)}`
	);
	fs.writeFileSync(GOLDEN_FILE, `{\n${lines.join(',\n')}\n}\n`);
};

describe('Fee pricing golden values (#1704)', function () {
	this.timeout(120_000);

	const wallets = {} as Record<TWalletKey, Wallet>;
	const golden = readGolden();
	const recorded: Record<string, unknown> = {};

	before(async () => {
		const single = async (
			name: string,
			addressType: EAddressType,
			refresh: boolean
		): Promise<Wallet> => {
			const res = await Wallet.create({
				mnemonic: MNEMONIC,
				network,
				addressType,
				electrumOptions,
				storage: createMemoryStorage(),
				remainOffline: true,
				disableRefreshOnCreate: !refresh,
				name
			});
			if (res.isErr()) throw res.error;
			// Sets the change index; the Electrum sync fails harmlessly offline.
			if (refresh) await res.value.refreshWallet({});
			return res.value;
		};
		const cosigners = COSIGNER_MNEMONICS.map((mnemonic) =>
			BIP32Factory(ecc)
				.fromSeed(bip39.mnemonicToSeedSync(mnemonic), networks.regtest)
				.derivePath("m/48'/1'/0'/2'")
				.neutered()
				.toBase58()
		);
		const multisig = await Wallet.createMultisig({
			threshold: 2,
			mnemonic: MNEMONIC,
			cosigners,
			network,
			electrumOptions,
			storage: createMemoryStorage(),
			remainOffline: true
		});
		if (multisig.isErr()) throw multisig.error;
		await multisig.value.refreshWallet({});

		Object.assign(wallets, {
			p2wpkh: await single('goldenp2wpkh', EAddressType.p2wpkh, true),
			'p2wpkh-fresh': await single(
				'goldenp2wpkhfresh',
				EAddressType.p2wpkh,
				false
			),
			p2tr: await single('goldenp2tr', EAddressType.p2tr, true),
			'p2sh-fresh': await single('goldenp2shfresh', EAddressType.p2sh, false),
			'p2pkh-fresh': await single(
				'goldenp2pkhfresh',
				EAddressType.p2pkh,
				false
			),
			multisig: multisig.value
		});
		expect(Object.keys(wallets)).to.have.members([...WALLETS]);
		expect(
			wallets.p2wpkh.data.changeAddressIndex[EAddressType.p2wpkh].address
		).to.match(/^bcrt1q/);
		expect(
			wallets['p2wpkh-fresh'].data.changeAddressIndex[EAddressType.p2wpkh]
				.address
		).to.equal('');
	});

	after(async () => {
		await Promise.all(Object.values(wallets).map((wallet) => wallet.stop()));
		if (process.env.UPDATE_GOLDEN) writeGolden(recorded);
	});

	/** Records `name` and checks it against the golden file. */
	const expectGolden = (name: string, record: unknown): void => {
		recorded[name] = record;
		if (process.env.UPDATE_GOLDEN) return;
		expect(record, name).to.deep.equal(golden[name]);
	};

	const expectScenarios = (scenarios: IPricingScenario[]): void => {
		const changed: string[] = [];
		for (const scenario of scenarios) {
			const record = run(wallets[scenario.wallet].transaction, scenario);
			recorded[scenario.name] = record;
			if (JSON.stringify(record) !== JSON.stringify(golden[scenario.name])) {
				changed.push(
					`${scenario.name}: ${JSON.stringify(
						record
					)}, recorded ${JSON.stringify(golden[scenario.name])}`
				);
			}
		}
		if (process.env.UPDATE_GOLDEN) return;
		expect(changed.slice(0, 20), `${changed.length} changed`).to.deep.equal([]);
	};

	it('prices the fixtures of the fee issues as recorded', () => {
		expectScenarios(fixtureScenarios());
	});

	it(`prices ${RANDOM_COUNT} random scenarios as recorded`, () => {
		expectScenarios(randomScenarios(RANDOM_COUNT, RANDOM_SEED));
	});

	describe('defaults', () => {
		const {
			consolidate,
			small,
			large,
			firstInFirstOut: fifo,
			lastInFirstOut: lifo
		} = ECoinSelectPreference;
		const coins: IUtxo[] = [
			coin(1, 10_000, { height: 103 }),
			coin(2, 4_000, { height: 101 }),
			coin(3, 10_000, { height: 0 }),
			coin(4, 300, { height: 102 }),
			coin(5, 10_000, { height: 104 })
		];
		const outputs = [
			{ address: addressOf('p2tr', 0xa0), value: 20_000, index: 0 }
		];

		let wallet: Wallet;
		before(() => {
			wallet = wallets.p2wpkh;
		});
		afterEach(async () => {
			await wallet.transaction.resetSendTransaction();
			wallet.updateCoinSelectPreference(consolidate);
			const res = await wallet.updateData({ utxos: [], balance: 0 });
			if (res.isErr()) throw res.error;
		});

		const quote = (
			res: ReturnType<Transaction['getTotalFeeObj']>
		): TPricingRecord[3] =>
			res.isOk()
				? [
						res.value.totalFee,
						res.value.transactionByteCount,
						res.value.satsPerByte,
						res.value.maxSatPerByte
				  ]
				: res.error.message;

		for (const preference of [consolidate, small, large, fifo, lifo]) {
			for (const change of ['staged', 'generated'] as const) {
				it(`prices the staged send under ${preference} with ${change} change`, async () => {
					wallet.updateCoinSelectPreference(preference);
					const staged = wallet.transaction.updateSendTransaction({
						transaction: {
							inputs: coins,
							outputs,
							changeAddress: change === 'staged' ? STAGED_CHANGE.p2wpkh : '',
							message: 'golden'
						}
					});
					if (staged.isErr()) throw staged.error;
					for (const satsPerByte of [2, 10]) {
						expectGolden(
							`defaults staged ${preference} ${change} ${satsPerByte}`,
							[
								quote(wallet.transaction.getTotalFeeObj({ satsPerByte })),
								wallet.transaction.getTotalFee({ satsPerByte }),
								wallet.transaction.getTotalFee({
									satsPerByte,
									generatesChange: false
								}),
								quote(wallet.transaction.getTotalFeeObj())
							]
						);
					}
				});
			}

			it(`prices the wallet's coins under ${preference} when none are staged`, async () => {
				const res = await wallet.updateData({
					utxos: coins,
					balance: coins.reduce((sum, { value }) => sum + value, 0)
				});
				if (res.isErr()) throw res.error;
				for (const satsPerByte of [2, 10, 40]) {
					const fee = wallet.getFeeInfo({
						satsPerByte,
						coinSelectPreference: preference,
						transaction: { outputs }
					});
					expectGolden(
						`defaults wallet coins ${preference} ${satsPerByte}`,
						quote(fee)
					);
				}
			});
		}
	});
});
