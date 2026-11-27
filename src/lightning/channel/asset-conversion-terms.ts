/**
 * The terms of an asset conversion (#2151): what both hosts confirm by
 * digest before quiescence. Every side is named by its role in the
 * channel's opening, so both peers build the same bytes.
 *
 * The canonical form checks structure only. The value grammar belongs to
 * the numbered checks, each with its own text, which the conversion
 * transport runs against the live channel.
 */
import { sha256 } from '../crypto/provider';
import { MAX_MONEY_SATS } from '../interactive-tx/validation';
import { MAX_SPLICE_FEERATE_PERKW } from './splice-weight';

export interface IAssetConversionTerms {
	version: 1;
	/** The channel id, 64 lowercase hex characters. */
	channelId: string;
	/** The live funding outpoint (display-order txid) and the state number N. */
	parent: { txid: string; outputIndex: number; stateNumber: string };
	direction: 'to-plain' | 'to-asset';
	/** The target channel type, lowercase hex. */
	targetType: string;
	giver: 'opener' | 'acceptor';
	candidate: {
		dustLimitSats: { opener: string; acceptor: string };
		maxAcceptedHtlcs: { opener: number; acceptor: number };
	};
	/** Each role's signed splice contribution in satoshis. */
	contributions: { opener: string; acceptor: string };
	units: {
		holder: 'opener' | 'acceptor';
		/** At most 16, ascending by asset id. */
		issuances: { assetId: string; amount: string }[];
	};
	/**
	 * The candidate's first commitment. `balanceMsat` is the two channel
	 * balances before the commitment fee and the anchors, adding up to the
	 * capacity times 1000; the opener's fee and anchors come out of the
	 * opener's balance when the commitments are built.
	 */
	firstCommitment: {
		commitmentFeeratePerKw: number;
		balanceMsat: { opener: string; acceptor: string };
		/** To an asset only, in the order of the issuances. */
		units?: { assetId: string; opener: string; acceptor: string }[];
	};
	fees: {
		fundingPayer: 'opener' | 'acceptor';
		budgets: { opener: string; acceptor: string };
		feeratePerKw: number;
		/** To plain only. */
		withdrawalPayer?: 'opener' | 'acceptor';
	};
	/** The host's agreement: 1 to 64 bytes in lowercase hex, and an expiry in unix seconds. */
	agreement: { reference: string; expiresAt: number };
	lockDepth: number;
}

const DOMAIN = Buffer.from('beignet/asset-conversion/terms/v1\0', 'ascii');

export const ASSET_CONVERSION_TEXTS = {
	invalid: 'Invalid asset conversion terms',
	version: 'Unsupported asset conversion terms version',
	parent: 'Asset conversion terms name a different parent',
	target: 'Asset conversion names a different target type',
	parameters: "Asset conversion channel parameters differ from the channel's",
	units: 'Invalid asset conversion units',
	amounts: 'Invalid asset conversion amounts or fees',
	feerate: "Asset conversion commitment feerate differs from the channel's",
	reference: 'Invalid asset conversion agreement reference',
	agreement: 'Asset conversion terms name a different agreement',
	expired: 'Asset conversion agreement has expired',
	lockDepth: 'Asset conversion lock depth must be 3 to 6',
	held: 'A conversion of this channel is in progress'
} as const;

type Shape =
	| 'string'
	| 'number'
	| 'role'
	| 'direction'
	| { [key: string]: Shape }
	| { list: Shape };
const pair = (shape: Shape): Shape => ({ opener: shape, acceptor: shape });
const SHAPE: { [key: string]: Shape } = {
	version: 'number',
	channelId: 'string',
	parent: { txid: 'string', outputIndex: 'number', stateNumber: 'string' },
	direction: 'direction',
	targetType: 'string',
	giver: 'role',
	candidate: {
		dustLimitSats: pair('string'),
		maxAcceptedHtlcs: pair('number')
	},
	contributions: pair('string'),
	units: {
		holder: 'role',
		issuances: { list: { assetId: 'string', amount: 'string' } }
	},
	firstCommitment: {
		commitmentFeeratePerKw: 'number',
		balanceMsat: pair('string'),
		units: { list: { assetId: 'string', opener: 'string', acceptor: 'string' } }
	},
	fees: {
		fundingPayer: 'role',
		budgets: pair('string'),
		feeratePerKw: 'number',
		withdrawalPayer: 'role'
	},
	agreement: { reference: 'string', expiresAt: 'number' },
	lockDepth: 'number'
};
/** The keys a canonical form may leave out. */
const OPTIONAL = new Set(['firstCommitment.units', 'fees.withdrawalPayer']);

function invalid(): never {
	throw new Error(ASSET_CONVERSION_TEXTS.invalid);
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return (
		typeof value === 'object' &&
		value !== null &&
		!Array.isArray(value) &&
		Object.getPrototypeOf(value) === Object.prototype
	);
}

/** A copy of `value` in the key order of `shape`, or a throw. */
function shaped(value: unknown, shape: Shape, path: string): unknown {
	if (shape === 'string' || shape === 'number') {
		if (typeof value !== shape) invalid();
		return value;
	}
	if (shape === 'role') {
		if (value !== 'opener' && value !== 'acceptor') invalid();
		return value;
	}
	if (shape === 'direction') {
		if (value !== 'to-plain' && value !== 'to-asset') invalid();
		return value;
	}
	if ('list' in shape && Object.keys(shape).length === 1) {
		if (!Array.isArray(value)) invalid();
		return value.map((item) => shaped(item, shape.list as Shape, path));
	}
	if (!isRecord(value)) invalid();
	const fields = shape as { [key: string]: Shape };
	const present = Object.keys(value).filter((k) => value[k] !== undefined);
	if (present.some((k) => !Object.prototype.hasOwnProperty.call(fields, k)))
		invalid();
	const out: Record<string, unknown> = {};
	for (const [key, inner] of Object.entries(fields)) {
		const name = path ? path + '.' + key : key;
		if (value[key] === undefined) {
			if (!OPTIONAL.has(name)) invalid();
			continue;
		}
		out[key] = shaped(value[key], inner, name);
	}
	return out;
}

/**
 * The canonical form of `terms`: the interface's key order, no other keys,
 * and each value of its JSON type. Throws "Invalid asset conversion terms"
 * otherwise. The value grammar is left to the numbered checks.
 */
export function canonicalAssetConversionTerms(
	terms: IAssetConversionTerms
): IAssetConversionTerms {
	return shaped(terms, SHAPE, '') as IAssetConversionTerms;
}

/** The canonical bytes: JSON with no whitespace, in the canonical key order. */
export function assetConversionTermsBytes(
	terms: IAssetConversionTerms
): Buffer {
	return Buffer.from(
		JSON.stringify(canonicalAssetConversionTerms(terms)),
		'utf8'
	);
}

/** sha256 of the terms domain and the canonical bytes. */
export function assetConversionTermsDigest(
	terms: IAssetConversionTerms
): Buffer {
	return assetConversionBytesDigest(assetConversionTermsBytes(terms));
}

/** The digest of canonical bytes already in hand. */
export function assetConversionBytesDigest(bytes: Buffer): Buffer {
	return sha256(Buffer.concat([DOMAIN, bytes]));
}

/** What the live channel decides about the terms, from one side's own store. */
export interface IAssetConversionExpectation {
	channelId: string;
	parent: { txid: string; outputIndex: number; stateNumber: string };
	direction: IAssetConversionTerms['direction'];
	targetType: string;
	dustLimitSats: { opener: string; acceptor: string };
	maxAcceptedHtlcs: { opener: number; acceptor: number };
	commitmentFeeratePerKw: number;
	/** The start's reference in hex, at the initiator only. */
	reference?: string;
}

const UNSIGNED = /^(0|[1-9][0-9]*)$/;
const SIGNED = /^(0|-?[1-9][0-9]*)$/;
const ASSET_ID = /^[0-9a-f]{64}$/;
const REFERENCE = /^([0-9a-f]{2}){1,64}$/;
const U64_MAX = 0xffffffffffffffffn;
const MAX_ISSUANCES = 16;

const unsigned = (v: string, max: bigint): boolean =>
	UNSIGNED.test(v) && BigInt(v) <= max;
const signed = (v: string, max: bigint): boolean => {
	if (!SIGNED.test(v)) return false;
	const n = BigInt(v);
	return n <= max && -n <= max;
};
const both = <T>(
	p: { opener: T; acceptor: T },
	ok: (v: T) => boolean
): boolean => ok(p.opener) && ok(p.acceptor);

function unitsValid(t: IAssetConversionTerms): boolean {
	const { issuances } = t.units;
	if (!issuances.length || issuances.length > MAX_ISSUANCES) return false;
	for (const [i, issuance] of issuances.entries())
		if (
			!ASSET_ID.test(issuance.assetId) ||
			!unsigned(issuance.amount, U64_MAX) ||
			(i > 0 && issuances[i - 1].assetId >= issuance.assetId)
		)
			return false;
	const split = t.firstCommitment.units;
	if (t.direction === 'to-plain') return split === undefined;
	return (
		split !== undefined &&
		split.length === issuances.length &&
		split.every(
			(u, i) =>
				u.assetId === issuances[i].assetId &&
				unsigned(u.opener, U64_MAX) &&
				unsigned(u.acceptor, U64_MAX) &&
				BigInt(u.opener) + BigInt(u.acceptor) === BigInt(issuances[i].amount)
		)
	);
}

function amountsValid(t: IAssetConversionTerms): boolean {
	const { feeratePerKw } = t.fees;
	return (
		both(t.contributions, (v) => signed(v, MAX_MONEY_SATS)) &&
		both(t.firstCommitment.balanceMsat, (v) =>
			unsigned(v, MAX_MONEY_SATS * 1000n)
		) &&
		both(t.fees.budgets, (v) => unsigned(v, MAX_MONEY_SATS)) &&
		Number.isSafeInteger(feeratePerKw) &&
		feeratePerKw >= 1 &&
		feeratePerKw <= MAX_SPLICE_FEERATE_PERKW &&
		(t.direction === 'to-plain' || t.fees.withdrawalPayer === undefined)
	);
}

/**
 * The engine's checks of canonical terms, in their order. Returns the
 * first failure's text, or undefined when the terms fit the channel.
 */
export function assetConversionTermsFailure(
	t: IAssetConversionTerms,
	expected: IAssetConversionExpectation,
	nowMs: number
): string | undefined {
	const x = ASSET_CONVERSION_TEXTS;
	if (t.version !== 1) return x.version;
	if (
		t.channelId !== expected.channelId ||
		t.parent.txid !== expected.parent.txid ||
		t.parent.outputIndex !== expected.parent.outputIndex ||
		t.parent.stateNumber !== expected.parent.stateNumber
	)
		return x.parent;
	if (
		t.direction !== expected.direction ||
		t.targetType !== expected.targetType
	)
		return x.target;
	const c = t.candidate;
	if (
		c.dustLimitSats.opener !== expected.dustLimitSats.opener ||
		c.dustLimitSats.acceptor !== expected.dustLimitSats.acceptor ||
		c.maxAcceptedHtlcs.opener !== expected.maxAcceptedHtlcs.opener ||
		c.maxAcceptedHtlcs.acceptor !== expected.maxAcceptedHtlcs.acceptor
	)
		return x.parameters;
	if (!unitsValid(t)) return x.units;
	if (!amountsValid(t)) return x.amounts;
	if (
		t.firstCommitment.commitmentFeeratePerKw !== expected.commitmentFeeratePerKw
	)
		return x.feerate;
	if (!REFERENCE.test(t.agreement.reference)) return x.reference;
	if (
		expected.reference !== undefined &&
		t.agreement.reference !== expected.reference
	)
		return x.agreement;
	const { expiresAt } = t.agreement;
	if (!Number.isSafeInteger(expiresAt) || expiresAt * 1000 <= nowMs)
		return x.expired;
	if (!Number.isSafeInteger(t.lockDepth) || t.lockDepth < 3 || t.lockDepth > 6)
		return x.lockDepth;
	return undefined;
}
