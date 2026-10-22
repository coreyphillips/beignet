/**
 * selectCoins, priceTransaction and quoteTransaction price every golden
 * scenario from their arguments alone (#1704): no wallet, no staged send,
 * and each argument frozen, so a function that wrote to one would fail.
 */

import { expect } from 'chai';
import fs from 'fs';

import { EAddressType } from '../src';
import type { IPricingWallet } from '../src/transaction/pricing';
import {
	estimateFee,
	quoteTransaction,
	selectCoins
} from '../src/transaction/pricing';
import {
	GOLDEN_FILE,
	IPricingScenario,
	RANDOM_COUNT,
	RANDOM_SEED,
	TPricingRecord,
	TWalletKey,
	addressOf,
	fixtureScenarios,
	randomScenarios,
	recordOf
} from './fee-pricing-scenarios';

/** Pricing reads only the change address's script type. */
const WALLETS: Record<TWalletKey, IPricingWallet> = {
	p2wpkh: {
		addressType: EAddressType.p2wpkh,
		changeAddress: addressOf('p2wpkh', 0xd0)
	},
	'p2wpkh-fresh': {
		addressType: EAddressType.p2wpkh,
		changeAddress: addressOf('p2wpkh', 0xd1)
	},
	p2tr: {
		addressType: EAddressType.p2tr,
		changeAddress: addressOf('p2tr', 0xd2)
	},
	'p2sh-fresh': {
		addressType: EAddressType.p2sh,
		changeAddress: addressOf('p2sh', 0xd3)
	},
	'p2pkh-fresh': {
		addressType: EAddressType.p2pkh,
		changeAddress: addressOf('p2pkh', 0xd4)
	},
	multisig: {
		addressType: EAddressType.p2wsh,
		multisig: { threshold: 2, totalCosigners: 3 },
		changeAddress: addressOf('p2wsh', 0xd5)
	}
};

/** Freezes `value` and everything it holds, except Buffers, which cannot be. */
const deepFreeze = <T>(value: T): T => {
	if (value && typeof value === 'object' && !Buffer.isBuffer(value)) {
		Object.values(value).forEach(deepFreeze);
		Object.freeze(value);
	}
	return value;
};

const price = ({
	wallet: key,
	coinSelectPreference,
	satsPerByte,
	transaction,
	message,
	fundingLightning
}: IPricingScenario): TPricingRecord => {
	const wallet = WALLETS[key];
	const feeWith = (generatesChange: boolean): number =>
		estimateFee({
			satsPerByte,
			message: message ?? '',
			transaction,
			fundingLightning,
			coinSelectPreference,
			generatesChange,
			wallet
		});
	return recordOf({
		inputs: transaction.inputs,
		selected: selectCoins({
			inputs: transaction.inputs,
			outputs: transaction.outputs ?? [],
			changeAddress: transaction.changeAddress,
			satsPerByte,
			message,
			coinSelectPreference,
			multisig: wallet.multisig
		}),
		fee: feeWith(true),
		feeWithoutChange: feeWith(false),
		quote: quoteTransaction({
			satsPerByte,
			message: message ?? transaction.message ?? '',
			transaction,
			fundingLightning,
			coinSelectPreference,
			wallet
		})
	});
};

describe('Pure fee pricing (#1704)', function () {
	this.timeout(60_000);

	const golden = JSON.parse(fs.readFileSync(GOLDEN_FILE, 'utf8')) as Record<
		string,
		TPricingRecord
	>;

	const expectGolden = (scenarios: IPricingScenario[]): void => {
		const changed = deepFreeze(scenarios)
			.map((scenario) => ({ scenario, record: price(scenario) }))
			.filter(
				({ scenario, record }) =>
					JSON.stringify(record) !== JSON.stringify(golden[scenario.name])
			)
			.map(
				({ scenario, record }) =>
					`${scenario.name}: ${JSON.stringify(
						record
					)}, recorded ${JSON.stringify(golden[scenario.name])}`
			);
		expect(changed.slice(0, 20), `${changed.length} changed`).to.deep.equal([]);
	};

	it('prices the fixtures of the fee issues as recorded', () => {
		expectGolden(fixtureScenarios());
	});

	it(`prices ${RANDOM_COUNT} random scenarios as recorded`, () => {
		expectGolden(randomScenarios(RANDOM_COUNT, RANDOM_SEED));
	});
});
