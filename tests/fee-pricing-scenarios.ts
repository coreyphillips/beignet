/**
 * Coin selection and fee pricing scenarios for the golden test (#1704): the
 * fixtures of the fee issues fixed since #1492, plus a seeded random sweep.
 * Every scenario is plain data. Addresses are synthetic, since pricing only
 * reads an address's script type.
 */

import { address as bitcoinAddress, networks, payments } from 'bitcoinjs-lib';
import type { ECPairInterface } from 'ecpair';

import path from 'path';

import type {
	ICoinSelectResponse,
	IOutput,
	ISendTransaction,
	IUtxo,
	Result,
	TGetTotalFeeObj
} from '../src';
import { EBoostType, ECoinSelectPreference } from '../src';

export const GOLDEN_FILE = path.join(__dirname, 'fee-pricing-golden.json');
export const RANDOM_SEED = 1704;
export const RANDOM_COUNT = 1_200;

/**
 * What one scenario prices to: the coin selection (an error message, or its
 * fee and the positions of the coins it picked), the fee with and without
 * generated change, and the quote (an error message, or its totalFee,
 * transactionByteCount, satsPerByte and maxSatPerByte).
 */
export type TPricingRecord = [
	string | number[],
	number,
	number,
	string | number[]
];

export const recordOf = ({
	inputs,
	selected,
	fee,
	feeWithoutChange,
	quote
}: {
	inputs: IUtxo[];
	selected: Result<ICoinSelectResponse>;
	fee: number;
	feeWithoutChange: number;
	quote: Result<TGetTotalFeeObj>;
}): TPricingRecord => {
	const position = new Map(inputs.map((input, i) => [input, i]));
	return [
		selected.isOk()
			? [
					selected.value.fee,
					...selected.value.inputs.map((input) => position.get(input) ?? -1)
			  ]
			: selected.error.message,
		fee,
		feeWithoutChange,
		quote.isOk()
			? [
					quote.value.totalFee,
					quote.value.transactionByteCount,
					quote.value.satsPerByte,
					quote.value.maxSatPerByte
			  ]
			: quote.error.message
	];
};

/** The wallets the golden test creates, by the state pricing reads. */
export const WALLETS = [
	// Refreshed, so its change index is set.
	'p2wpkh',
	// Never refreshed: no change index, so pricing stands in a change address.
	'p2wpkh-fresh',
	'p2tr',
	'p2sh-fresh',
	'p2pkh-fresh',
	// 2-of-3, which prices P2WSH inputs at their multisig weight.
	'multisig'
] as const;
export type TWalletKey = (typeof WALLETS)[number];

export type TScriptType = 'p2wpkh' | 'p2tr' | 'p2sh' | 'p2pkh' | 'p2wsh';

export interface IPricingScenario {
	name: string;
	wallet: TWalletKey;
	coinSelectPreference: ECoinSelectPreference;
	satsPerByte: number;
	transaction: Partial<ISendTransaction> & { inputs: IUtxo[] };
	/** Passed to every call when set. Left out, each call uses its default. */
	message?: string;
	fundingLightning: boolean;
}

const hash = (bytes: number, seed: number): Buffer => {
	const out = Buffer.alloc(bytes);
	out.writeUInt32BE(seed >>> 0, 0);
	return out;
};

/** A regtest address of `type`, distinct for each seed. */
export const addressOf = (type: TScriptType, seed: number): string => {
	const network = networks.regtest;
	switch (type) {
		case 'p2wpkh':
			return bitcoinAddress.toBech32(hash(20, seed), 0, network.bech32);
		case 'p2wsh':
			return bitcoinAddress.toBech32(hash(32, seed), 0, network.bech32);
		case 'p2tr':
			return bitcoinAddress.toBech32(hash(32, seed), 1, network.bech32);
		case 'p2sh':
			return payments.p2sh({ hash: hash(20, seed), network }).address ?? '';
		case 'p2pkh':
			return payments.p2pkh({ hash: hash(20, seed), network }).address ?? '';
	}
};

/** A staged change address of the wallet's own type. */
export const STAGED_CHANGE: Record<TWalletKey, string> = {
	p2wpkh: addressOf('p2wpkh', 0xc0),
	'p2wpkh-fresh': addressOf('p2wpkh', 0xc1),
	p2tr: addressOf('p2tr', 0xc2),
	'p2sh-fresh': addressOf('p2sh', 0xc3),
	'p2pkh-fresh': addressOf('p2pkh', 0xc4),
	multisig: addressOf('p2wsh', 0xc5)
};

const RECIPIENT = addressOf('p2wpkh', 0xa0);

/** Only the key's length is read: 65 bytes is an uncompressed P2PKH key. */
const keyPairOf = (length: 33 | 65): ECPairInterface =>
	({
		publicKey: Buffer.alloc(length, length === 65 ? 4 : 2)
	}) as ECPairInterface;

export const coin = (
	id: number,
	value: number,
	{
		type = 'p2wpkh',
		height = 100,
		keyLength
	}: { type?: TScriptType; height?: number; keyLength?: 33 | 65 } = {}
): IUtxo => ({
	address: addressOf(type, id),
	index: 0,
	path: "m/84'/1'/0'/0/0",
	scriptHash: '00'.repeat(32),
	height,
	tx_hash: id.toString(16).padStart(64, '0'),
	tx_pos: id % 3,
	value,
	publicKey: '02'.repeat(33),
	...(keyLength ? { keyPair: keyPairOf(keyLength) } : {})
});

const coins = (values: number[], first = 1): IUtxo[] =>
	values.map((value, i) => coin(first + i, value));

const payTo = (...values: number[]): IOutput[] =>
	values.map((value, index) => ({
		address: index ? addressOf('p2wpkh', 0xa0 + index) : RECIPIENT,
		value,
		index
	}));

type TChange = 'staged' | 'generated' | 'none';

const changeFor = (wallet: TWalletKey, change: TChange): string | undefined =>
	change === 'staged'
		? STAGED_CHANGE[wallet]
		: change === 'generated'
		? ''
		: undefined;

interface IFixture {
	issue: string;
	wallet?: TWalletKey;
	inputs: IUtxo[];
	outputs: IOutput[];
	change: TChange;
	preferences: ECoinSelectPreference[];
	rates: number[];
	extra?: Partial<ISendTransaction>;
}

const {
	consolidate,
	small,
	large,
	firstInFirstOut: fifo,
	lastInFirstOut: lifo
} = ECoinSelectPreference;
const ALL_PREFERENCES = [consolidate, small, large, fifo, lifo];

// Built on each call, so a test that freezes its scenarios freezes its own.
const fixtures = (): IFixture[] => [
	// A higher rate selects another coin, so the maximum is past the rate
	// that one coin pays.
	{
		issue: '#1492',
		inputs: coins([100_000, 100_000]),
		outputs: payTo(99_000),
		change: 'staged',
		preferences: [small, large],
		rates: [2, 7, 8]
	},
	// One coin pays 5 sat/vB, the size-based maximum is 540, and coin
	// selection at that rate adds the second coin: 364 is the highest rate
	// under half.
	{
		issue: '#1545',
		inputs: coins([185_744, 176_152]),
		outputs: payTo(152_312),
		change: 'staged',
		preferences: [small, large],
		rates: [5, 364, 365, 540]
	},
	// Three 366 sat coins paying 550: the 1 sat/vB size floor leaves dust,
	// so no whole rate fits.
	{
		issue: '#1562',
		inputs: coins([366, 366, 366]),
		outputs: payTo(550),
		change: 'generated',
		preferences: [consolidate],
		rates: [1, 2, 3]
	},
	// Change the leftover cannot pay for at 95 sat/vB and up.
	{
		issue: '#1584 sweep',
		inputs: coins([30_004, 30_004]),
		outputs: payTo(39_872),
		change: 'generated',
		preferences: [consolidate],
		rates: [94, 95, 1000]
	},
	{
		issue: '#1584 sweep',
		inputs: coins([55_903, 55_903]),
		outputs: payTo(74_404),
		change: 'generated',
		preferences: [consolidate],
		rates: [177, 178, 1000]
	},
	{
		issue: '#1586',
		inputs: coins([29_936, 29_936]),
		outputs: payTo(39_872),
		change: 'generated',
		preferences: [small, large],
		rates: [94, 95, 110, 111, 112]
	},
	{
		issue: '#1586',
		inputs: coins([50_322, 9_550]),
		outputs: payTo(39_872),
		change: 'generated',
		preferences: [small, large],
		rates: [94, 95, 110, 111, 112]
	},
	// Dust change half the fee: 8 sat/vB is the highest rate keeping change.
	{
		issue: '#1584 half',
		inputs: coins([4_500]),
		outputs: payTo(3_000),
		change: 'staged',
		preferences: [small],
		rates: [8, 9, 10]
	},
	// The capped rate selects fewer coins than the requested one.
	{
		issue: '#1584 capped',
		inputs: coins([300, 300, 300, 500, 900]),
		outputs: payTo(1_533),
		change: 'staged',
		preferences: [large, small],
		rates: [1, 1.5, 2]
	},
	// The size floor at 1.5 sat/vB leaves change a 2 sat/vB send keeps.
	{
		issue: '#1584 floor',
		inputs: coins([1_700]),
		outputs: payTo(1_100),
		change: 'staged',
		preferences: [small],
		rates: [1, 1.5, 2]
	},
	// Under 166 vB, with change under dust.
	...[8_300, 8_400].flatMap((amount) =>
		[[100, 300, 10_000], [10_000]].map(
			(values): IFixture => ({
				issue: '#1579',
				inputs: coins(values),
				outputs: payTo(amount),
				change: 'staged',
				preferences: [small],
				rates: [9, 10, 11]
			})
		)
	),
	// Coins dropped down to the size floor.
	{
		issue: '#1575',
		inputs: coins([300, 500, 10_000]),
		outputs: payTo(8_600),
		change: 'staged',
		preferences: [small, large],
		rates: [1, 10]
	},
	// Nothing left for change, with and without an uneconomic coin first or
	// last in the order each preference selects.
	{
		issue: '#1526',
		inputs: coins([10_000, 10_000, 10_000, 10_000]),
		outputs: payTo(36_560),
		change: 'staged',
		preferences: ALL_PREFERENCES,
		rates: [10, 11]
	},
	{
		issue: '#1549',
		inputs: [
			...coins([10_000, 10_000, 10_000, 10_000]),
			coin(9, 300, { height: 101 })
		],
		outputs: payTo(36_560),
		change: 'staged',
		preferences: ALL_PREFERENCES,
		rates: [10]
	},
	{
		issue: '#1566',
		inputs: [
			coin(1, 10_000, { height: 100 }),
			coin(2, 10_000, { height: 100 }),
			coin(3, 10_000, { height: 102 }),
			coin(4, 10_000, { height: 102 }),
			coin(9, 300, { height: 101 })
		],
		outputs: payTo(36_560),
		change: 'staged',
		preferences: ALL_PREFERENCES,
		rates: [10]
	},
	// Generated change: 600 and 300 sats left over at the fee without change,
	// and 200, which is dust before change is priced (#1587).
	...[
		{ payment: 39_086, rates: [1] },
		{ payment: 37_830, rates: [5] },
		{ payment: 39_386, rates: [1] },
		{ payment: 39_486, rates: [1] },
		{ payment: 36_560, rates: [10] }
	].flatMap(({ payment, rates }) =>
		(['p2wpkh', 'p2wpkh-fresh'] as const).map(
			(wallet): IFixture => ({
				issue: '#1587',
				wallet,
				inputs: coins([10_000, 10_000, 10_000, 10_000]),
				outputs: payTo(payment),
				change: 'generated',
				preferences: [consolidate, small],
				rates
			})
		)
	),
	// Staged change the leftover cannot pay for.
	{
		issue: '#1496',
		inputs: coins([10_000, 10_000, 10_000, 10_000]),
		outputs: payTo(36_560),
		change: 'staged',
		preferences: [consolidate],
		rates: [10]
	},
	// A quote capped below 2 sat/vB takes the size floor.
	{
		issue: '#1543',
		inputs: coins([1_000, 1_000]),
		outputs: payTo(500),
		change: 'staged',
		preferences: [consolidate],
		rates: [1, 2]
	},
	{
		issue: '#1543',
		inputs: coins([1_700]),
		outputs: payTo(1_472),
		change: 'staged',
		preferences: [consolidate],
		rates: [1, 2]
	},
	// A fractional rate above the whole-number maximum.
	{
		issue: '#1520',
		inputs: coins([1_000_000]),
		outputs: payTo(166_239),
		change: 'staged',
		preferences: [consolidate],
		rates: [589.1, 589.6]
	},
	// A P2WSH input is sized only in a multisig wallet.
	{
		issue: '#1808',
		inputs: [coin(1, 100_000, { type: 'p2wsh' })],
		outputs: payTo(10_000),
		change: 'staged',
		preferences: [consolidate, small],
		rates: [1, 2, 25]
	},
	{
		issue: '#1808',
		wallet: 'multisig',
		inputs: [coin(1, 100_000, { type: 'p2wsh' })],
		outputs: payTo(10_000),
		change: 'staged',
		preferences: [consolidate, small],
		rates: [1, 2, 25]
	},
	// Uncompressed P2PKH keys are 32 vB over what getByteCount counts.
	{
		issue: '#1527',
		inputs: [
			coin(1, 3_000, { type: 'p2pkh', keyLength: 65 }),
			coin(2, 3_000, { type: 'p2pkh', keyLength: 65 })
		],
		outputs: payTo(2_000),
		change: 'staged',
		preferences: [consolidate, small],
		rates: [1, 2, 5]
	},
	// A replacement prices every input it spends.
	{
		issue: '#1472',
		inputs: coins([20_000, 20_000, 20_000]),
		outputs: payTo(15_000),
		change: 'staged',
		preferences: [small],
		rates: [2, 10],
		extra: { boostType: EBoostType.rbf }
	},
	// A max send pays its fee from its one output.
	{
		issue: '#1467',
		inputs: coins([500]),
		outputs: payTo(0),
		change: 'staged',
		preferences: [consolidate],
		rates: [1, 1.5],
		extra: { max: true }
	},
	// Leftovers of exactly P2WPKH dust (294) and one under: at the fee
	// without change for generated change, and at the fee with change for
	// staged change.
	...[39_392, 39_393].map(
		(payment): IFixture => ({
			issue: `dust boundary ${payment}`,
			inputs: coins([10_000, 10_000, 10_000, 10_000]),
			outputs: payTo(payment),
			change: 'generated',
			preferences: [consolidate, small],
			rates: [1]
		})
	),
	...[36_256, 36_257].map(
		(payment): IFixture => ({
			issue: `dust boundary ${payment}`,
			inputs: coins([10_000, 10_000, 10_000, 10_000]),
			outputs: payTo(payment),
			change: 'staged',
			preferences: [consolidate, small],
			rates: [10]
		})
	),
	// Nothing left once the change output is paid for, on a fee over half
	// the payment.
	{
		issue: 'zero leftover',
		inputs: coins([600]),
		outputs: payTo(318),
		change: 'staged',
		preferences: [consolidate, small],
		rates: [2]
	}
];

/** Every fixture at every preference and rate it lists. */
export const fixtureScenarios = (): IPricingScenario[] => {
	const seen = new Map<string, number>();
	return fixtures().flatMap((fixture) =>
		fixture.preferences.flatMap((coinSelectPreference) =>
			fixture.rates.map((satsPerByte): IPricingScenario => {
				const wallet = fixture.wallet ?? 'p2wpkh';
				const base = `${fixture.issue} ${wallet} ${coinSelectPreference} ${satsPerByte}`;
				const count = (seen.get(base) ?? 0) + 1;
				seen.set(base, count);
				return {
					name: count > 1 ? `${base} (${count})` : base,
					wallet,
					coinSelectPreference,
					satsPerByte,
					transaction: {
						inputs: fixture.inputs,
						outputs: fixture.outputs,
						changeAddress: changeFor(wallet, fixture.change),
						...fixture.extra
					},
					fundingLightning: false
				};
			})
		)
	);
};

/** mulberry32: a small seeded generator, so the sweep is the same everywhere. */
const generator = (seed: number): (() => number) => {
	let state = seed >>> 0;
	return (): number => {
		state = (state + 0x6d2b79f5) >>> 0;
		let t = state;
		t = Math.imul(t ^ (t >>> 15), t | 1);
		t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
		return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
	};
};

const RATES = [1, 1.5, 2, 3, 5, 7.3, 10, 25, 60, 150, 400];
const INPUT_TYPES: TScriptType[] = [
	'p2wpkh',
	'p2wpkh',
	'p2wpkh',
	'p2tr',
	'p2sh',
	'p2pkh'
];
const OUTPUT_TYPES: TScriptType[] = [
	'p2wpkh',
	'p2wpkh',
	'p2tr',
	'p2wsh',
	'p2sh',
	'p2pkh'
];

/**
 * `count` random scenarios from `seed`. Payments are often set just under
 * what the coins can pay, where change turns to dust or stops paying for
 * itself.
 */
export const randomScenarios = (
	count: number,
	seed: number
): IPricingScenario[] => {
	const random = generator(seed);
	const pick = <T>(items: readonly T[]): T =>
		items[Math.floor(random() * items.length)];
	const between = (low: number, high: number): number =>
		low + Math.floor(random() * (high - low + 1));
	const chance = (p: number): boolean => random() < p;

	let nextId = 1;
	return Array.from({ length: count }, (_, i): IPricingScenario => {
		const wallet = pick(WALLETS);
		const coinSelectPreference = pick(ALL_PREFERENCES);
		const satsPerByte = chance(0.6) ? pick(RATES) : between(1, 400);

		const inputCount = chance(0.85) ? between(1, 8) : between(9, 30);
		const inputs = Array.from({ length: inputCount }, () => {
			const type: TScriptType =
				wallet === 'multisig'
					? chance(0.8)
						? 'p2wsh'
						: pick(INPUT_TYPES)
					: chance(0.005)
					? 'p2wsh'
					: pick(INPUT_TYPES);
			const size = random();
			const value =
				size < 0.25
					? between(100, 1_500)
					: size < 0.6
					? between(1_500, 30_000)
					: size < 0.9
					? between(30_000, 300_000)
					: between(300_000, 3_000_000);
			const keyLength =
				type === 'p2pkh' && chance(0.5) ? 65 : chance(0.15) ? 33 : undefined;
			return coin(nextId++, value, {
				type,
				height: chance(0.2) ? 0 : between(100, 200),
				keyLength
			});
		});
		const total = inputs.reduce((sum, { value }) => sum + value, 0);

		const max = chance(0.12);
		const outputCount = max ? 1 : chance(0.08) ? 0 : between(1, 3);
		let paying: number;
		if (max) {
			paying = chance(0.5) ? 0 : total;
		} else {
			// About what the coins pay at this rate without change.
			const roughFee = Math.ceil(
				(11 + inputCount * 68 + outputCount * 31) * satsPerByte
			);
			const tight = total - roughFee - between(0, 1_000);
			paying =
				chance(0.4) && tight > 0
					? tight
					: Math.floor(
							total * (chance(0.15) ? 0.9 + random() * 0.3 : random())
					  );
		}
		const outputs: IOutput[] = Array.from(
			{ length: outputCount },
			(_output, index) => {
				const share =
					index === outputCount - 1
						? paying
						: Math.floor(paying * random() * 0.6);
				paying -= share;
				return {
					address: addressOf(pick(OUTPUT_TYPES), 0x1000 + i * 4 + index),
					value: share,
					index
				};
			}
		);

		const message = chance(0.15)
			? 'm'.repeat(between(1, 80))
			: chance(0.05)
			? '   '
			: '';
		const boostType = chance(0.1)
			? EBoostType.rbf
			: chance(0.3)
			? EBoostType.cpfp
			: undefined;
		return {
			name: `random ${i}`,
			wallet,
			coinSelectPreference,
			satsPerByte,
			transaction: {
				inputs,
				outputs,
				changeAddress: changeFor(
					wallet,
					pick(['staged', 'staged', 'generated', 'none'] as const)
				),
				message,
				max,
				boostType
			},
			message: chance(0.5) ? message : undefined,
			fundingLightning: chance(0.1)
		};
	});
};
