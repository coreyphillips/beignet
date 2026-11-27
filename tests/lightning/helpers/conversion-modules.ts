/**
 * Lazy access to the modules and members that #2151 Steps 3a and 3b add, so that on
 * a tree without them each test fails on its own with "not implemented:
 * <name>" instead of the whole file failing at load time. The types come from
 * the modules themselves, so the tests compile once the code exists.
 */
import path from 'path';
import type { Transaction } from 'bitcoinjs-lib';
import type { IInteractiveTxInput } from '../../../src/lightning/interactive-tx/types';
import type {
	IAssetConversionContext,
	IAssetConversionTerms
} from '../../../src/lightning/channel';

type TermsModule =
	typeof import('../../../src/lightning/channel/asset-conversion-terms');
type TransportModule =
	typeof import('../../../src/lightning/channel/asset-conversion-transport');
type FeaturesModule =
	typeof import('../../../src/lightning/features/asset-conversion');

const SRC = path.join(__dirname, '..', '..', '..', 'src', 'lightning');

function load<T>(rel: string): T {
	const file = path.join(SRC, rel);
	try {
		return require(file) as T;
	} catch (error) {
		const e = error as NodeJS.ErrnoException;
		if (e?.code === 'MODULE_NOT_FOUND' && String(e.message).includes(file))
			throw new Error('not implemented: src/lightning/' + rel);
		throw error;
	}
}

/** `src/lightning/channel/asset-conversion-terms.ts` (section 3). */
export const conversionTerms = (): TermsModule =>
	load<TermsModule>('channel/asset-conversion-terms');
/** `src/lightning/channel/asset-conversion-transport.ts` (section 6). */
export const conversionTransport = (): TransportModule =>
	load<TransportModule>('channel/asset-conversion-transport');
/** `src/lightning/features/asset-conversion.ts` (section 1). */
export const conversionFeatures = (): FeaturesModule =>
	load<FeaturesModule>('features/asset-conversion');

/**
 * A member that Step 3a adds to an existing module or object, read when the
 * test runs. Throws "not implemented: <where>.<key>" while it is missing.
 */
export function member<T extends object, K extends keyof T>(
	owner: T,
	key: K,
	where: string
): NonNullable<T[K]> {
	const value = owner[key];
	if (value === undefined || value === null)
		throw new Error('not implemented: ' + where + '.' + String(key));
	return value as NonNullable<T[K]>;
}

/** A method on an instance that Step 3a adds, bound to it. */
export function method<A extends unknown[], R>(
	owner: object,
	key: string,
	where: string
): (...args: A) => R {
	const fn = (owner as Record<string, unknown>)[key];
	if (typeof fn !== 'function')
		throw new Error('not implemented: ' + where + '.' + key);
	return (fn as (...args: A) => R).bind(owner);
}

// ---------------------------------------------------------------------------
// #2151 Step 3b: the layout. The module and the new members do not exist on
// the base, so their types are mirrored here from the contract (sections 1
// and 4) and the module is loaded when a test runs.
// ---------------------------------------------------------------------------

/** Initiator first, as `AssetOpenPair`. */
export type ConversionPair<T> = readonly [initiator: T, acceptor: T];

/** `IAssetSpliceWireRecordLimit`. */
export interface IConversionRecordLimit {
	type: bigint;
	maxBytes: number;
}

/** `IAssetConversionMovement` (section 1). */
export interface IConversionMovement {
	assetId: string;
	from: 'initiator' | 'acceptor';
	outputSerial: bigint;
	units: bigint;
}

/** A per-issuance row in initiator order. */
export interface IConversionUnitsRow {
	assetId: string;
	initiator: bigint;
	acceptor: bigint;
}

/** `IAssetConversionBitcoin` (section 1). */
export interface IConversionBitcoin {
	fundingKeys: ConversionPair<Buffer>;
	lockTime: number;
	minimumDepth: number;
	feeratePerKw: number;
	parent: {
		type: 'plain' | 'asset';
		channelType: string;
		valueSats: bigint;
		fundingKeys: ConversionPair<Buffer>;
		root?: Buffer;
	};
	candidate: {
		type: 'plain' | 'asset';
		channelType: string;
		maxAcceptedHtlcs: ConversionPair<number>;
		dustLimitSats: ConversionPair<bigint>;
	};
}

/** `IAssetConversionDescription` (section 1). */
export interface IConversionDescription {
	inputs: readonly {
		serialId: bigint;
		txid: Buffer;
		vout: number;
		sequence: number;
		isShared: boolean;
		prevTx?: Buffer;
	}[];
	outputs: readonly {
		serialId: bigint;
		kind: 'funding' | 'withdrawal' | 'change';
		valueSats: bigint;
		descriptorHash: Buffer;
	}[];
	movements: readonly IConversionMovement[];
	parentUnits: readonly IConversionUnitsRow[];
	feeBudgets: readonly bigint[];
	relativeSatoshis: readonly bigint[];
	commitmentRecordLimits?: readonly (readonly IConversionRecordLimit[])[];
}

/** `IAssetConversionPlan` (section 1). */
export interface IConversionPlan {
	digest: Buffer;
}

/** The three planner members of `IAssetConversionHost` (section 1). */
export interface IConversionPlanner {
	proposeConversion(
		ctx: IAssetConversionContext,
		terms: IAssetConversionTerms
	): Promise<Buffer>;
	describeConversion(
		ctx: IAssetConversionContext,
		proposals: ConversionPair<Buffer>,
		bitcoin: IConversionBitcoin
	): Promise<IConversionDescription>;
	prepareConversion(
		ctx: IAssetConversionContext,
		proposals: ConversionPair<Buffer>,
		bitcoin: IConversionBitcoin,
		layoutDigest: Buffer
	): Promise<IConversionPlan>;
}

/** The internal `IAssetConversionLayout` (section 4). */
export interface IConversionLayout {
	attempt: Buffer;
	chainHash: Buffer;
	channelId: Buffer;
	init: Buffer;
	ack: Buffer;
	termsDigest: Buffer;
	targetType: Buffer;
	direction: 'to-plain' | 'to-asset';
	parent: Transaction;
	parentIndex: number;
	parentKeys: ConversionPair<Buffer>;
	parentType: 'plain' | 'asset';
	parentRoot?: Buffer;
	priorDigest?: Buffer;
	stateNumber: bigint;
	parentBalancesMsat: ConversionPair<bigint>;
	feeratePerKw: number;
	feeBudgets: ConversionPair<bigint>;
	candidateMaxAcceptedHtlcs: ConversionPair<number>;
	candidateDustSats: ConversionPair<bigint>;
	commitmentRecordLimits: ConversionPair<
		readonly IConversionRecordLimit[]
	> | null;
	parentUnits: readonly IConversionUnitsRow[];
	movements: readonly IConversionMovement[];
	firstCommitment: {
		balanceMsat: ConversionPair<bigint>;
		units: readonly IConversionUnitsRow[];
	};
	proposalDigests: ConversionPair<Buffer>;
	inputs: readonly IInteractiveTxInput[];
	outputs: readonly {
		serialId: bigint;
		role: 'funding' | 'change' | 'withdrawal';
		amountSats: bigint;
		descriptorHash: Buffer;
	}[];
}

/** The internal `IAssetConversionLayoutExpectation` (section 4, v2.1 item 8). */
export interface IConversionLayoutExpectation {
	terms: IAssetConversionTerms;
	isInitiator: boolean;
	isOpener: boolean;
	parentValueSats: bigint;
	relativeSatoshis: ConversionPair<bigint>;
}

interface LayoutModule {
	checkConversionLayout(
		layout: IConversionLayout,
		expectation: IConversionLayoutExpectation
	): unknown;
	assetConversionLayoutDigest(layout: IConversionLayout): Buffer;
	/**
	 * The layout of a host's description over the engine's own fields
	 * (section 4, "From the description to the layout"): it throws the
	 * describe text for a description of the wrong shape (section 3, S15).
	 */
	describedConversionLayout(
		base: IConversionLayoutBase,
		relativeSatoshis: ConversionPair<bigint>,
		description: unknown
	): IConversionLayout;
}

/** The layout fields the engine fills itself, before the description's. */
export type IConversionLayoutBase = Omit<
	IConversionLayout,
	'commitmentRecordLimits' | 'parentUnits' | 'movements' | 'inputs' | 'outputs'
>;

/** `src/lightning/channel/asset-conversion-layout.ts` (section 4). */
export const conversionLayout = (): LayoutModule =>
	load<LayoutModule>('channel/asset-conversion-layout');

/**
 * `completeAssetConversionHost` of the conversion transport (section 1),
 * read when the test runs.
 */
export function completeAssetConversionHost(): (host: unknown) => boolean {
	return member(
		conversionTransport() as unknown as {
			completeAssetConversionHost?: (host: unknown) => boolean;
		},
		'completeAssetConversionHost',
		'src/lightning/channel/asset-conversion-transport'
	);
}
