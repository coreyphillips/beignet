/**
 * Sample conversion terms for the #2151 Step 3a tests (contract section 3 and
 * amendment v3.1 items 3 and 4). Every value here is in the canonical form
 * (the interface's key order, no other keys, each value of its JSON type) and
 * meets the value grammar the numbered checks apply. The direction picks the
 * variant: to an asset (the seller adds units, the first commitment splits
 * them) or to plain (the buyer takes every unit, no first commitment units, a
 * withdrawal payer).
 *
 * GRAMMAR_CASES lists one violation of the value grammar per entry, with the
 * numbered check's text that refuses it.
 */
import type { IAssetConversionTerms } from '../../../src/lightning/channel/asset-conversion-terms';
import { MAX_SPLICE_FEERATE_PERKW } from '../../../src/lightning/channel/splice-weight';
import { ASSET_SPLICE_RECOVERY_TYPE_HEX } from '../../../src/lightning/features/asset-opening';
import { MAX_MONEY_SATS } from '../../../src/lightning/interactive-tx/validation';

/** The plain target type of section 2: the form without the alias bit. */
export const PLAIN_TARGET_TYPE_HEX = '0100000000000000000000';
/** Two issuances in ascending order. */
export const SAMPLE_ASSET_A = '4c'.repeat(32);
export const SAMPLE_ASSET_B = '5d'.repeat(32);
/** 2100-01-01 in unix seconds (amendment v3.1 item 4). */
export const SAMPLE_EXPIRES_AT = 4_102_444_800;
/** A display-order txid with letters and no byte symmetry, so every parent case changes it. */
export const SAMPLE_PARENT_TXID = 'a2b3'.repeat(16);

type Direction = IAssetConversionTerms['direction'];

function toAsset(): IAssetConversionTerms {
	return {
		version: 1,
		channelId: '11'.repeat(32),
		parent: { txid: SAMPLE_PARENT_TXID, outputIndex: 0, stateNumber: '0' },
		direction: 'to-asset',
		targetType: ASSET_SPLICE_RECOVERY_TYPE_HEX,
		giver: 'acceptor',
		candidate: {
			dustLimitSats: { opener: '354', acceptor: '354' },
			maxAcceptedHtlcs: { opener: 83, acceptor: 83 }
		},
		contributions: { opener: '-1000', acceptor: '25000' },
		units: {
			holder: 'acceptor',
			issuances: [
				{ assetId: SAMPLE_ASSET_A, amount: '1000' },
				{ assetId: SAMPLE_ASSET_B, amount: '7' }
			]
		},
		firstCommitment: {
			commitmentFeeratePerKw: 253,
			balanceMsat: { opener: '500000000', acceptor: '20000000' },
			units: [
				{ assetId: SAMPLE_ASSET_A, opener: '0', acceptor: '1000' },
				{ assetId: SAMPLE_ASSET_B, opener: '0', acceptor: '7' }
			]
		},
		fees: {
			fundingPayer: 'opener',
			budgets: { opener: '2000', acceptor: '0' },
			feeratePerKw: 1000
		},
		agreement: { reference: 'a1b2c3d4', expiresAt: SAMPLE_EXPIRES_AT },
		lockDepth: 3
	};
}

function toPlain(): IAssetConversionTerms {
	return {
		version: 1,
		channelId: '11'.repeat(32),
		parent: { txid: SAMPLE_PARENT_TXID, outputIndex: 1, stateNumber: '4' },
		direction: 'to-plain',
		targetType: PLAIN_TARGET_TYPE_HEX,
		giver: 'opener',
		candidate: {
			dustLimitSats: { opener: '354', acceptor: '354' },
			maxAcceptedHtlcs: { opener: 83, acceptor: 83 }
		},
		contributions: { opener: '0', acceptor: '-3000' },
		units: {
			holder: 'acceptor',
			issuances: [{ assetId: SAMPLE_ASSET_A, amount: '1000' }]
		},
		firstCommitment: {
			commitmentFeeratePerKw: 253,
			balanceMsat: { opener: '400000000', acceptor: '96000000' }
		},
		fees: {
			fundingPayer: 'acceptor',
			budgets: { opener: '0', acceptor: '2500' },
			feeratePerKw: 1000,
			withdrawalPayer: 'acceptor'
		},
		agreement: { reference: 'ff00', expiresAt: SAMPLE_EXPIRES_AT },
		lockDepth: 6
	};
}

/**
 * Canonical terms of the variant `overrides.direction` names (to an asset by
 * default), with the top-level fields of `overrides` put in place. Overrides
 * keep the key order, so the result stays canonical when each value does.
 */
export function sampleTerms(
	overrides: Partial<IAssetConversionTerms> = {}
): IAssetConversionTerms {
	const direction: Direction = overrides.direction ?? 'to-asset';
	const base = direction === 'to-plain' ? toPlain() : toAsset();
	const out = { ...base };
	for (const [key, value] of Object.entries(overrides))
		(out as Record<string, unknown>)[key] = value;
	return out;
}

/** A deep copy, so a test can change one nested field at a time. */
export function copyTerms<T>(terms: T): T {
	return JSON.parse(JSON.stringify(terms)) as T;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Loose = Record<string, any>;
/** The terms as a plain object, so a case can write a value outside its type. */
const loose = (t: IAssetConversionTerms): Loose => t as unknown as Loose;

export const CHECK_TEXTS = {
	version: 'Unsupported asset conversion terms version',
	parent: 'Asset conversion terms name a different parent',
	target: 'Asset conversion names a different target type',
	parameters: "Asset conversion channel parameters differ from the channel's",
	units: 'Invalid asset conversion units',
	amounts: 'Invalid asset conversion amounts or fees',
	feerate: "Asset conversion commitment feerate differs from the channel's",
	reference: 'Invalid asset conversion agreement reference',
	expired: 'Asset conversion agreement has expired',
	lockDepth: 'Asset conversion lock depth must be 3 to 6'
} as const;

export interface IGrammarCase {
	what: string;
	applies: 'to-asset' | 'to-plain' | 'both';
	/** Breaks one rule in one field of any canonical terms of that direction. */
	change(t: IAssetConversionTerms): void;
	/** The numbered check's text (amendment v3.1 item 3). */
	text: string;
}

const U64_MAX = 18446744073709551615n;
const MAX_PLUS_ONE = (MAX_MONEY_SATS + 1n).toString();
/** n distinct asset ids in ascending order. */
const ascendingIds = (n: number): string[] =>
	Array.from({ length: n }, (_, i) =>
		(i + 1).toString(16).padStart(2, '0').repeat(32)
	);
/** The issuances with one more of an asset id above every other, out of order first. */
const reversedPair = (first: {
	assetId: string;
	amount: string;
}): { assetId: string; amount: string }[] => [
	{ assetId: 'ff'.repeat(32), amount: first.amount },
	first
];

/**
 * One violation of the value grammar per entry, one field at a time. Each
 * change reads the terms it is given (asset ids, amounts, heights), so it
 * applies to terms built from any channel, not only to sampleTerms.
 * channelId is left out: terms naming another channel are dropped silently.
 */
export const GRAMMAR_CASES: IGrammarCase[] = [
	// Check 1.
	{
		what: 'version 2',
		applies: 'both',
		change: (t): void => void (loose(t).version = 2),
		text: CHECK_TEXTS.version
	},
	{
		what: 'version 0',
		applies: 'both',
		change: (t): void => void (loose(t).version = 0),
		text: CHECK_TEXTS.version
	},
	// Check 2: a malformed parent can only show up as a mismatch.
	{
		what: 'parent txid in uppercase',
		applies: 'both',
		change: (t): void => void (t.parent.txid = t.parent.txid.toUpperCase()),
		text: CHECK_TEXTS.parent
	},
	{
		what: 'parent txid in internal byte order',
		applies: 'both',
		change: (t): void =>
			void (t.parent.txid = Buffer.from(t.parent.txid, 'hex')
				.reverse()
				.toString('hex')),
		text: CHECK_TEXTS.parent
	},
	{
		what: 'parent txid of 63 characters',
		applies: 'both',
		change: (t): void => void (t.parent.txid = t.parent.txid.slice(1)),
		text: CHECK_TEXTS.parent
	},
	{
		what: 'parent output index above the safe range',
		applies: 'both',
		change: (t): void => void (t.parent.outputIndex = 2 ** 53),
		text: CHECK_TEXTS.parent
	},
	{
		what: 'fractional parent output index',
		applies: 'both',
		change: (t): void =>
			void (t.parent.outputIndex = t.parent.outputIndex + 0.5),
		text: CHECK_TEXTS.parent
	},
	{
		what: 'state number with a leading zero',
		applies: 'both',
		change: (t): void =>
			void (t.parent.stateNumber = '0' + t.parent.stateNumber),
		text: CHECK_TEXTS.parent
	},
	{
		what: 'state number above 2^48 - 1',
		applies: 'both',
		change: (t): void => void (t.parent.stateNumber = (2n ** 48n).toString()),
		text: CHECK_TEXTS.parent
	},
	{
		what: 'negative state number',
		applies: 'both',
		change: (t): void =>
			void (t.parent.stateNumber = '-' + t.parent.stateNumber),
		text: CHECK_TEXTS.parent
	},
	// Check 3.
	{
		what: 'target type with an uppercase byte added',
		applies: 'both',
		change: (t): void => void (t.targetType = t.targetType + 'AB'),
		text: CHECK_TEXTS.target
	},
	{
		what: 'target type that is not hex',
		applies: 'both',
		change: (t): void => void (t.targetType = t.targetType.slice(0, -2) + 'zz'),
		text: CHECK_TEXTS.target
	},
	// Check 4.
	{
		what: 'opener dust limit with a leading zero',
		applies: 'both',
		change: (t): void =>
			void (t.candidate.dustLimitSats.opener =
				'0' + t.candidate.dustLimitSats.opener),
		text: CHECK_TEXTS.parameters
	},
	{
		what: 'acceptor dust limit with a plus sign',
		applies: 'both',
		change: (t): void =>
			void (t.candidate.dustLimitSats.acceptor =
				'+' + t.candidate.dustLimitSats.acceptor),
		text: CHECK_TEXTS.parameters
	},
	{
		what: 'dust limit above MAX_MONEY_SATS',
		applies: 'both',
		change: (t): void => void (t.candidate.dustLimitSats.opener = MAX_PLUS_ONE),
		text: CHECK_TEXTS.parameters
	},
	{
		what: 'fractional HTLC limit',
		applies: 'both',
		change: (t): void =>
			void (t.candidate.maxAcceptedHtlcs.acceptor =
				t.candidate.maxAcceptedHtlcs.acceptor + 0.5),
		text: CHECK_TEXTS.parameters
	},
	{
		what: 'HTLC limit above the safe range',
		applies: 'both',
		change: (t): void => void (t.candidate.maxAcceptedHtlcs.opener = 2 ** 53),
		text: CHECK_TEXTS.parameters
	},
	// Check 5.
	{
		what: 'issuance amount with a leading zero',
		applies: 'both',
		change: (t): void =>
			void (t.units.issuances[0].amount = '0' + t.units.issuances[0].amount),
		text: CHECK_TEXTS.units
	},
	{
		what: 'issuance amount above a u64',
		applies: 'both',
		change: (t): void =>
			void (t.units.issuances[0].amount = (U64_MAX + 1n).toString()),
		text: CHECK_TEXTS.units
	},
	{
		what: 'negative issuance amount',
		applies: 'both',
		change: (t): void =>
			void (t.units.issuances[0].amount = '-' + t.units.issuances[0].amount),
		text: CHECK_TEXTS.units
	},
	{
		what: 'issuance asset id in uppercase',
		applies: 'both',
		change: (t): void =>
			void (t.units.issuances[0].assetId =
				t.units.issuances[0].assetId.toUpperCase()),
		text: CHECK_TEXTS.units
	},
	{
		what: 'issuance asset id of 62 characters',
		applies: 'both',
		change: (t): void =>
			void (t.units.issuances[0].assetId =
				t.units.issuances[0].assetId.slice(2)),
		text: CHECK_TEXTS.units
	},
	{
		what: '17 issuances',
		applies: 'both',
		change: (t): void =>
			void (t.units.issuances = ascendingIds(17).map((assetId) => ({
				assetId,
				amount: '1'
			}))),
		text: CHECK_TEXTS.units
	},
	{
		what: 'issuances out of order',
		applies: 'both',
		change: (t): void =>
			void (t.units.issuances = reversedPair(t.units.issuances[0])),
		text: CHECK_TEXTS.units
	},
	{
		what: 'a repeated issuance',
		applies: 'both',
		change: (t): void =>
			void (t.units.issuances = [
				t.units.issuances[0],
				{ ...t.units.issuances[0] }
			]),
		text: CHECK_TEXTS.units
	},
	{
		what: 'first commitment unit with a leading zero',
		applies: 'to-asset',
		change: (t): void => {
			const u = t.firstCommitment.units![0];
			u.acceptor = '0' + u.acceptor;
		},
		text: CHECK_TEXTS.units
	},
	{
		what: 'first commitment unit above a u64',
		applies: 'to-asset',
		change: (t): void =>
			void (t.firstCommitment.units![0].opener = (U64_MAX + 1n).toString()),
		text: CHECK_TEXTS.units
	},
	{
		what: 'first commitment unit asset id in uppercase',
		applies: 'to-asset',
		change: (t): void => {
			const u = t.firstCommitment.units![0];
			u.assetId = u.assetId.toUpperCase();
		},
		text: CHECK_TEXTS.units
	},
	{
		what: 'first commitment units out of order',
		applies: 'to-asset',
		change: (t): void => {
			const [first] = t.firstCommitment.units!;
			t.firstCommitment.units = [
				{ assetId: 'ff'.repeat(32), opener: '0', acceptor: '0' },
				first
			];
		},
		text: CHECK_TEXTS.units
	},
	{
		what: 'a repeated first commitment unit',
		applies: 'to-asset',
		change: (t): void => {
			const [first] = t.firstCommitment.units!;
			t.firstCommitment.units = [first, { ...first }];
		},
		text: CHECK_TEXTS.units
	},
	{
		what: 'first commitment units to plain',
		applies: 'to-plain',
		change: (t): void =>
			void (t.firstCommitment.units = t.units.issuances.map(
				(i: { assetId: string; amount: string }) => ({
					assetId: i.assetId,
					opener: '0',
					acceptor: i.amount
				})
			)),
		text: CHECK_TEXTS.units
	},
	// Check 6.
	{
		what: 'contribution of -0',
		applies: 'both',
		change: (t): void => void (t.contributions.opener = '-0'),
		text: CHECK_TEXTS.amounts
	},
	{
		what: 'contribution with a plus sign',
		applies: 'both',
		change: (t): void =>
			void (t.contributions.acceptor = '+' + t.contributions.acceptor),
		text: CHECK_TEXTS.amounts
	},
	{
		what: 'contribution with a leading zero',
		applies: 'both',
		change: (t): void =>
			void (t.contributions.acceptor = '0' + t.contributions.acceptor),
		text: CHECK_TEXTS.amounts
	},
	{
		what: 'contribution above MAX_MONEY_SATS',
		applies: 'both',
		change: (t): void => void (t.contributions.acceptor = MAX_PLUS_ONE),
		text: CHECK_TEXTS.amounts
	},
	{
		what: 'contribution below -MAX_MONEY_SATS',
		applies: 'both',
		change: (t): void => void (t.contributions.opener = '-' + MAX_PLUS_ONE),
		text: CHECK_TEXTS.amounts
	},
	{
		what: 'balance with a leading zero',
		applies: 'both',
		change: (t): void =>
			void (t.firstCommitment.balanceMsat.opener =
				'0' + t.firstCommitment.balanceMsat.opener),
		text: CHECK_TEXTS.amounts
	},
	{
		what: 'balance above MAX_MONEY_SATS * 1000',
		applies: 'both',
		change: (t): void =>
			void (t.firstCommitment.balanceMsat.acceptor = (
				MAX_MONEY_SATS * 1000n +
				1n
			).toString()),
		text: CHECK_TEXTS.amounts
	},
	{
		what: 'fee budget with a leading zero',
		applies: 'both',
		change: (t): void =>
			void (t.fees.budgets.opener = '0' + t.fees.budgets.opener),
		text: CHECK_TEXTS.amounts
	},
	{
		what: 'fee budget above MAX_MONEY_SATS',
		applies: 'both',
		change: (t): void => void (t.fees.budgets.acceptor = MAX_PLUS_ONE),
		text: CHECK_TEXTS.amounts
	},
	{
		what: 'funding feerate of 0',
		applies: 'both',
		change: (t): void => void (t.fees.feeratePerKw = 0),
		text: CHECK_TEXTS.amounts
	},
	{
		what: 'funding feerate above MAX_SPLICE_FEERATE_PERKW',
		applies: 'both',
		change: (t): void =>
			void (t.fees.feeratePerKw = MAX_SPLICE_FEERATE_PERKW + 1),
		text: CHECK_TEXTS.amounts
	},
	{
		what: 'fractional funding feerate',
		applies: 'both',
		change: (t): void => void (t.fees.feeratePerKw = t.fees.feeratePerKw + 0.5),
		text: CHECK_TEXTS.amounts
	},
	{
		what: 'a withdrawal payer to an asset',
		applies: 'to-asset',
		change: (t): void => void (t.fees.withdrawalPayer = t.fees.fundingPayer),
		text: CHECK_TEXTS.amounts
	},
	// Check 7.
	{
		what: 'fractional commitment feerate',
		applies: 'both',
		change: (t): void =>
			void (t.firstCommitment.commitmentFeeratePerKw =
				t.firstCommitment.commitmentFeeratePerKw + 0.5),
		text: CHECK_TEXTS.feerate
	},
	{
		what: 'commitment feerate above the safe range',
		applies: 'both',
		change: (t): void =>
			void (t.firstCommitment.commitmentFeeratePerKw = 2 ** 53),
		text: CHECK_TEXTS.feerate
	},
	// Check 8.
	{
		what: 'empty reference',
		applies: 'both',
		change: (t): void => void (t.agreement.reference = ''),
		text: CHECK_TEXTS.reference
	},
	{
		what: 'reference of one character',
		applies: 'both',
		change: (t): void =>
			void (t.agreement.reference = t.agreement.reference.slice(0, 1)),
		text: CHECK_TEXTS.reference
	},
	{
		what: 'reference of odd length',
		applies: 'both',
		change: (t): void =>
			void (t.agreement.reference = t.agreement.reference + 'a'),
		text: CHECK_TEXTS.reference
	},
	{
		what: 'reference of 130 characters',
		applies: 'both',
		change: (t): void => void (t.agreement.reference = 'ab'.repeat(65)),
		text: CHECK_TEXTS.reference
	},
	{
		what: 'reference in uppercase',
		applies: 'both',
		change: (t): void =>
			void (t.agreement.reference = 'AB' + t.agreement.reference),
		text: CHECK_TEXTS.reference
	},
	{
		what: 'reference that is not hex',
		applies: 'both',
		change: (t): void =>
			void (t.agreement.reference = 'zz' + t.agreement.reference),
		text: CHECK_TEXTS.reference
	},
	// Check 9.
	{
		what: 'fractional expiry',
		applies: 'both',
		change: (t): void =>
			void (t.agreement.expiresAt = t.agreement.expiresAt + 0.5),
		text: CHECK_TEXTS.expired
	},
	{
		what: 'expiry above the safe range',
		applies: 'both',
		change: (t): void => void (t.agreement.expiresAt = 2 ** 53),
		text: CHECK_TEXTS.expired
	},
	// Check 10.
	{
		what: 'fractional lock depth',
		applies: 'both',
		change: (t): void => void (t.lockDepth = t.lockDepth + 0.5),
		text: CHECK_TEXTS.lockDepth
	},
	{
		what: 'lock depth above the safe range',
		applies: 'both',
		change: (t): void => void (t.lockDepth = 2 ** 53),
		text: CHECK_TEXTS.lockDepth
	}
];
