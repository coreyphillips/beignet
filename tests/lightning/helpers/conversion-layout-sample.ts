/**
 * Layouts for the pure checks of #2151 Step 3b (contract section 4), built
 * from a spec in channel roles, and the layout digest computed here from
 * the contract's formula, not by the code under test.
 *
 * A spec names each side by its role in the channel's opening ('opener' or
 * 'acceptor'). The builder maps it to initiator order through
 * `openerInitiates`, so one spec gives the same layout seen from either
 * side, and the variant where the channel's acceptor initiates. Serials in
 * a spec are those for `openerInitiates`; when the acceptor initiates,
 * every serial a side owns flips its low bit (the shared input and the
 * funding output stay the initiator's).
 */
import { createHash } from 'crypto';
import { Transaction } from 'bitcoinjs-lib';
import type { IAssetConversionTerms } from '../../../src/lightning/channel';
import { REGTEST_CHAIN_HASH } from '../../../src/lightning/chain/hashes';
import { getPublicKey } from '../../../src/lightning/crypto/ecdh';
import { ASSET_SPLICE_RECOVERY_TYPE_HEX } from '../../../src/lightning/features/asset-opening';
import type { IInteractiveTxInput } from '../../../src/lightning/interactive-tx/types';
import { createTaprootFundingScript } from '../../../src/lightning/script/funding-taproot';
import {
	attemptIdOf,
	encodeSpliceAck,
	encodeSpliceInit,
	FAR_EXPIRY,
	PLAIN_TARGET_TYPE_HEX
} from './conversion-managers';
import type {
	ConversionPair,
	IConversionUnitsRow,
	IConversionLayout,
	IConversionLayoutExpectation,
	IConversionRecordLimit
} from './conversion-modules';

export type Role = 'opener' | 'acceptor';
export interface IByRole<T> {
	opener: T;
	acceptor: T;
}

export interface ISpecInput {
	key: string;
	/** 'shared' for the parent's funding output. */
	owner: Role | 'shared';
	serial: bigint;
	/** An external input's coin value (one P2TR output at vout 0). */
	value?: bigint;
}
export interface ISpecOutput {
	key: string;
	/** 'funding' for the candidate's funding output (the initiator's). */
	owner: Role | 'funding';
	role: 'funding' | 'change' | 'withdrawal';
	serial: bigint;
	amount: bigint;
}
export interface ISpecMovement {
	assetId: string;
	from: Role;
	/** The key of the output it credits. */
	output: string;
	units: bigint;
}

export interface ILayoutSpec {
	direction: 'to-asset' | 'to-plain';
	openerInitiates: boolean;
	parentValue: bigint;
	/** The parent snapshot's balances, msat. */
	parentBalances: IByRole<bigint>;
	/** The unit holder (seller to an asset, buyer to bitcoin), also the giver. */
	holder: Role;
	issuances: { assetId: string; amount: bigint }[];
	contributions: IByRole<bigint>;
	budgets: IByRole<bigint>;
	fundingPayer: Role;
	/** The first commitment's balances, msat. */
	firstBalances: IByRole<bigint>;
	/** To an asset: the first commitment's units. */
	firstUnits: { assetId: string; opener: bigint; acceptor: bigint }[];
	dust: IByRole<bigint>;
	htlcs: IByRole<number>;
	inputs: ISpecInput[];
	outputs: ISpecOutput[];
	movements: ISpecMovement[];
	/** To bitcoin: the parent's funded issuances by holder. */
	parentUnits: { assetId: string; opener: bigint; acceptor: bigint }[];
	recordLimits: IByRole<IConversionRecordLimit[]> | null;
	stateNumber: bigint;
	priorDigest?: Buffer;
	feeratePerKw: number;
	commitmentFeeratePerKw: number;
	lockDepth: number;
	/** The root the parent's funding script commits to, when not the layout's own. */
	scriptRoot?: Buffer;
}

export interface ISample {
	spec: ILayoutSpec;
	terms: IAssetConversionTerms;
	layout: IConversionLayout;
	/** The same layout seen by the initiator and by the acceptor. */
	expectations: [IConversionLayoutExpectation, IConversionLayoutExpectation];
	/** The serial a spec output key got. */
	serialOf(key: string): bigint;
}

export const ASSET_A = '1a'.repeat(32);
export const ASSET_B = '2b'.repeat(32);
export const SAMPLE_CHANNEL_ID = Buffer.alloc(32, 0x3c);
export const SAMPLE_PARENT_INDEX = 1;
export const SAMPLE_LOCKTIME = 600_000;
export const SAMPLE_PROPOSALS: ConversionPair<Buffer> = [
	Buffer.from('sample conversion proposal of the initiator', 'ascii'),
	Buffer.from('sample conversion proposal of the acceptor', 'ascii')
];

export const sha256 = (data: Buffer | string): Buffer =>
	createHash('sha256').update(data).digest();

/** Four distinct valid keys: the parent's (initiator, acceptor), then init's and ack's. */
export const SAMPLE_KEYS: [Buffer, Buffer, Buffer, Buffer] = [1, 2, 3, 4].map(
	(n) => getPublicKey(sha256('sample conversion key ' + n))
) as [Buffer, Buffer, Buffer, Buffer];
export const SAMPLE_ROOT = sha256('sample conversion parent root');
export const SAMPLE_PRIOR = sha256('sample conversion prior round');

/** A wallet coin of `value` sats: one P2TR output at vout 0. */
export function sampleCoin(value: bigint, tag = 'coin'): Transaction {
	const tx = new Transaction();
	tx.version = 2;
	tx.addInput(sha256('sample conversion ' + tag + ' input'), 0, 0xfffffffd);
	tx.addOutput(
		Buffer.concat([
			Buffer.from([0x51, 0x20]),
			sha256('sample ' + tag + ' key')
		]),
		Number(value)
	);
	return tx;
}

/**
 * The parent funding transaction: a P2WPKH output at 0, then the funding
 * output at SAMPLE_PARENT_INDEX for the two parent keys (and the root of an
 * asset parent).
 */
export function sampleParent(
	value: bigint,
	keys: ConversionPair<Buffer>,
	root?: Buffer,
	tag = 'parent'
): Transaction {
	const tx = new Transaction();
	tx.version = 2;
	tx.addInput(sha256('sample conversion ' + tag + ' input'), 0, 0xfffffffd);
	tx.addOutput(
		Buffer.concat([Buffer.from([0x00, 0x14]), sha256(tag).subarray(0, 20)]),
		50_000
	);
	tx.addOutput(
		createTaprootFundingScript(keys[0], keys[1], undefined, root).p2trOutput,
		Number(value)
	);
	return tx;
}

/** sha256 of the terms domain and canonical JSON, as 3a's termsIdentity. */
export function termsDigestOf(terms: IAssetConversionTerms): Buffer {
	return sha256(
		Buffer.concat([
			Buffer.from('beignet/asset-conversion/terms/v1\0', 'ascii'),
			Buffer.from(JSON.stringify(terms), 'ascii')
		])
	);
}

/** The spec of an asset parent's conversion to bitcoin: the buyer is the opener. */
export function toPlainSpec(): ILayoutSpec {
	return {
		direction: 'to-plain',
		openerInitiates: true,
		parentValue: 200_000n,
		parentBalances: { opener: 120_000_000n, acceptor: 80_000_000n },
		holder: 'opener',
		issuances: [
			{ assetId: ASSET_A, amount: 1000n },
			{ assetId: ASSET_B, amount: 500n }
		],
		contributions: { opener: -4200n, acceptor: 0n },
		budgets: { opener: 1200n, acceptor: 0n },
		fundingPayer: 'opener',
		firstBalances: { opener: 115_800_000n, acceptor: 80_000_000n },
		firstUnits: [],
		dust: { opener: 354n, acceptor: 1000n },
		htlcs: { opener: 30, acceptor: 20 },
		inputs: [{ key: 'shared', owner: 'shared', serial: 0n }],
		outputs: [
			{
				key: 'funding',
				owner: 'funding',
				role: 'funding',
				serial: 2n,
				amount: 195_800n
			},
			{
				key: 'w1',
				owner: 'opener',
				role: 'withdrawal',
				serial: 4n,
				amount: 1000n
			},
			{
				key: 'w2',
				owner: 'opener',
				role: 'withdrawal',
				serial: 6n,
				amount: 2000n
			}
		],
		movements: [
			{ assetId: ASSET_A, from: 'opener', output: 'w1', units: 300n },
			{ assetId: ASSET_A, from: 'acceptor', output: 'w1', units: 400n },
			{ assetId: ASSET_A, from: 'acceptor', output: 'w2', units: 300n },
			{ assetId: ASSET_B, from: 'acceptor', output: 'w2', units: 500n }
		],
		parentUnits: [
			{ assetId: ASSET_A, opener: 300n, acceptor: 700n },
			{ assetId: ASSET_B, opener: 0n, acceptor: 500n }
		],
		recordLimits: null,
		stateNumber: 1n,
		priorDigest: SAMPLE_PRIOR,
		feeratePerKw: 1000,
		commitmentFeeratePerKw: 253,
		lockDepth: 3
	};
}

/** The spec of a plain parent's conversion to an asset: the seller is the acceptor. */
export function toAssetSpec(): ILayoutSpec {
	return {
		direction: 'to-asset',
		openerInitiates: true,
		parentValue: 200_000n,
		parentBalances: { opener: 150_000_000n, acceptor: 50_000_000n },
		holder: 'acceptor',
		issuances: [
			{ assetId: ASSET_A, amount: 1000n },
			{ assetId: ASSET_B, amount: 500n }
		],
		contributions: { opener: 0n, acceptor: 0n },
		budgets: { opener: 0n, acceptor: 1500n },
		fundingPayer: 'acceptor',
		firstBalances: { opener: 140_000_000n, acceptor: 60_000_000n },
		firstUnits: [
			{ assetId: ASSET_A, opener: 400n, acceptor: 600n },
			{ assetId: ASSET_B, opener: 500n, acceptor: 0n }
		],
		dust: { opener: 354n, acceptor: 354n },
		htlcs: { opener: 83, acceptor: 83 },
		inputs: [
			{ key: 'shared', owner: 'shared', serial: 0n },
			{ key: 'coin', owner: 'acceptor', serial: 5n, value: 20_000n }
		],
		outputs: [
			{
				key: 'funding',
				owner: 'funding',
				role: 'funding',
				serial: 2n,
				amount: 200_000n
			},
			{
				key: 'change',
				owner: 'acceptor',
				role: 'change',
				serial: 7n,
				amount: 18_500n
			}
		],
		movements: [
			{ assetId: ASSET_A, from: 'acceptor', output: 'funding', units: 1000n },
			{ assetId: ASSET_A, from: 'acceptor', output: 'change', units: 250n },
			{ assetId: ASSET_B, from: 'acceptor', output: 'funding', units: 500n }
		],
		parentUnits: [],
		recordLimits: {
			opener: [
				{ type: 65539n, maxBytes: 10 },
				{ type: 65537n, maxBytes: 2000 }
			],
			acceptor: [{ type: 65537n, maxBytes: 2000 }]
		},
		stateNumber: 2n,
		feeratePerKw: 1000,
		commitmentFeeratePerKw: 253,
		lockDepth: 3
	};
}

export function specOf(direction: ILayoutSpec['direction']): ILayoutSpec {
	return direction === 'to-asset' ? toAssetSpec() : toPlainSpec();
}

/** Build the terms, the layout and both expectations of a spec. */
export function buildSample(spec: ILayoutSpec): ISample {
	const oi = spec.openerInitiates;
	const order = <T>(p: IByRole<T>): [T, T] =>
		oi ? [p.opener, p.acceptor] : [p.acceptor, p.opener];
	const splice = (role: Role): 'initiator' | 'acceptor' =>
		(role === 'opener') === oi ? 'initiator' : 'acceptor';
	const serial = (owner: string, base: bigint): bigint =>
		owner === 'shared' || owner === 'funding' || oi ? base : base ^ 1n;
	const toAsset = spec.direction === 'to-asset';
	const parentKeys: ConversionPair<Buffer> = [SAMPLE_KEYS[0], SAMPLE_KEYS[1]];
	const root = toAsset ? undefined : SAMPLE_ROOT;
	const parent = sampleParent(
		spec.parentValue,
		parentKeys,
		'scriptRoot' in spec ? spec.scriptRoot : root
	);
	const str = (p: IByRole<bigint>): IByRole<string> => ({
		opener: p.opener.toString(),
		acceptor: p.acceptor.toString()
	});
	const terms: IAssetConversionTerms = {
		version: 1,
		channelId: SAMPLE_CHANNEL_ID.toString('hex'),
		parent: {
			txid: parent.getId(),
			outputIndex: SAMPLE_PARENT_INDEX,
			stateNumber: spec.stateNumber.toString()
		},
		direction: spec.direction,
		targetType: toAsset
			? ASSET_SPLICE_RECOVERY_TYPE_HEX
			: PLAIN_TARGET_TYPE_HEX,
		giver: spec.holder,
		candidate: {
			dustLimitSats: str(spec.dust),
			maxAcceptedHtlcs: {
				opener: spec.htlcs.opener,
				acceptor: spec.htlcs.acceptor
			}
		},
		contributions: str(spec.contributions),
		units: {
			holder: spec.holder,
			issuances: spec.issuances.map((i) => ({
				assetId: i.assetId,
				amount: i.amount.toString()
			}))
		},
		firstCommitment: {
			commitmentFeeratePerKw: spec.commitmentFeeratePerKw,
			balanceMsat: str(spec.firstBalances),
			...(toAsset && {
				units: spec.firstUnits.map((u) => ({
					assetId: u.assetId,
					opener: u.opener.toString(),
					acceptor: u.acceptor.toString()
				}))
			})
		},
		fees: {
			fundingPayer: spec.fundingPayer,
			budgets: str(spec.budgets),
			feeratePerKw: spec.feeratePerKw,
			...(!toAsset && { withdrawalPayer: spec.holder })
		},
		agreement: { reference: '5e'.repeat(16), expiresAt: FAR_EXPIRY },
		lockDepth: spec.lockDepth
	};
	const D = termsDigestOf(terms);
	const targetType = Buffer.from(terms.targetType, 'hex');
	const conversion = { termsDigest: D, targetType };
	const rel = order(spec.contributions);
	const init = encodeSpliceInit({
		channelId: SAMPLE_CHANNEL_ID,
		relativeSatoshis: rel[0],
		fundingFeeratePerkw: spec.feeratePerKw,
		locktime: SAMPLE_LOCKTIME,
		fundingPubkey: SAMPLE_KEYS[2],
		lockDepth: spec.lockDepth,
		conversion
	});
	const ack = encodeSpliceAck({
		channelId: SAMPLE_CHANNEL_ID,
		relativeSatoshis: rel[1],
		fundingPubkey: SAMPLE_KEYS[3],
		lockDepth: spec.lockDepth,
		conversion
	});
	const serials = new Map<string, bigint>();
	const inputs: IInteractiveTxInput[] = spec.inputs.map((i) => {
		const serialId = serial(i.owner, i.serial);
		serials.set(i.key, serialId);
		if (i.owner === 'shared')
			return {
				serialId,
				prevTxid: parent.getHash(),
				prevOutputIndex: SAMPLE_PARENT_INDEX,
				sequence: 0xfffffffd,
				isShared: true
			};
		const coin = sampleCoin(i.value ?? 0n, i.key);
		return {
			serialId,
			prevTxid: coin.getHash(),
			prevOutputIndex: 0,
			sequence: 0xfffffffd,
			prevTx: coin.toBuffer(),
			isShared: false
		};
	});
	const outputs = spec.outputs.map((o) => {
		const serialId = serial(o.owner, o.serial);
		serials.set(o.key, serialId);
		return {
			serialId,
			role: o.role,
			amountSats: o.amount,
			descriptorHash: sha256('sample conversion output ' + o.key)
		};
	});
	const serialOf = (key: string): bigint => {
		const n = serials.get(key);
		if (n === undefined) throw new Error('No sample item ' + key);
		return n;
	};
	const row = (u: {
		assetId: string;
		opener: bigint;
		acceptor: bigint;
	}): IConversionUnitsRow => {
		const [initiator, acceptor] = order(u);
		return { assetId: u.assetId, initiator, acceptor };
	};
	const layout: IConversionLayout = {
		attempt: attemptIdOf(
			terms.channelId,
			terms.parent.txid,
			SAMPLE_PARENT_INDEX,
			D,
			oi ? 'opener' : 'acceptor'
		),
		chainHash: Buffer.from(REGTEST_CHAIN_HASH),
		channelId: Buffer.from(SAMPLE_CHANNEL_ID),
		init,
		ack,
		termsDigest: D,
		targetType,
		direction: spec.direction,
		parent,
		parentIndex: SAMPLE_PARENT_INDEX,
		parentKeys,
		parentType: toAsset ? 'plain' : 'asset',
		...(root && { parentRoot: root }),
		...(spec.priorDigest && { priorDigest: spec.priorDigest }),
		stateNumber: spec.stateNumber,
		parentBalancesMsat: order(spec.parentBalances),
		feeratePerKw: spec.feeratePerKw,
		feeBudgets: order(spec.budgets),
		candidateMaxAcceptedHtlcs: order(spec.htlcs),
		candidateDustSats: order(spec.dust),
		commitmentRecordLimits: spec.recordLimits
			? (order(spec.recordLimits).map((r) => r.map((x) => ({ ...x }))) as [
					IConversionRecordLimit[],
					IConversionRecordLimit[]
			  ])
			: null,
		parentUnits: spec.parentUnits.map(row),
		movements: spec.movements.map((m) => ({
			assetId: m.assetId,
			from: splice(m.from),
			outputSerial: serialOf(m.output),
			units: m.units
		})),
		firstCommitment: {
			balanceMsat: order(spec.firstBalances),
			units: spec.firstUnits.map(row)
		},
		proposalDigests: [sha256(SAMPLE_PROPOSALS[0]), sha256(SAMPLE_PROPOSALS[1])],
		inputs: [...inputs].sort(bySerial),
		outputs: [...outputs].sort(bySerial)
	};
	const expectation = (isInitiator: boolean): IConversionLayoutExpectation => ({
		terms: JSON.parse(JSON.stringify(terms)) as IAssetConversionTerms,
		isInitiator,
		isOpener: isInitiator === oi,
		parentValueSats: spec.parentValue,
		relativeSatoshis: rel
	});
	return {
		spec,
		terms,
		layout,
		expectations: [expectation(true), expectation(false)],
		serialOf
	};
}

function bySerial<T extends { serialId: bigint }>(a: T, b: T): number {
	return a.serialId < b.serialId ? -1 : a.serialId > b.serialId ? 1 : 0;
}

const hex = (b: Buffer): string => b.toString('hex');
const dec = (n: bigint): string => n.toString();

/** The 27 entries the layout digest hashes, in the contract's order (section 4, v2.1 item 7). */
export function layoutFields(l: IConversionLayout): unknown[] {
	const movements = [...l.movements].sort((a, b) =>
		a.assetId !== b.assetId
			? a.assetId < b.assetId
				? -1
				: 1
			: a.from !== b.from
			? a.from === 'initiator'
				? -1
				: 1
			: a.outputSerial < b.outputSerial
			? -1
			: a.outputSerial > b.outputSerial
			? 1
			: 0
	);
	const rows = (
		units: readonly { assetId: string; initiator: bigint; acceptor: bigint }[]
	): string[][] =>
		units.map((u) => [u.assetId, dec(u.initiator), dec(u.acceptor)]);
	return [
		hex(l.attempt),
		hex(l.chainHash),
		hex(l.channelId),
		hex(l.init),
		hex(l.ack),
		hex(l.termsDigest),
		hex(l.targetType),
		l.direction,
		hex(l.parent.getHash()),
		l.parentIndex,
		l.parentKeys.map(hex),
		l.parentType,
		l.parentRoot ? hex(l.parentRoot) : '',
		l.priorDigest ? hex(l.priorDigest) : '',
		dec(l.stateNumber),
		l.parentBalancesMsat.map(dec),
		l.feeratePerKw,
		l.feeBudgets.map(dec),
		[...l.candidateMaxAcceptedHtlcs],
		l.candidateDustSats.map(dec),
		l.commitmentRecordLimits === null
			? null
			: l.commitmentRecordLimits.map((records) =>
					[...records]
						.sort((a, b) => (a.type < b.type ? -1 : 1))
						.map((r) => [dec(r.type), r.maxBytes])
			  ),
		rows(l.parentUnits),
		movements.map((m) => [
			m.assetId,
			m.from,
			dec(m.outputSerial),
			dec(m.units)
		]),
		[l.firstCommitment.balanceMsat.map(dec), rows(l.firstCommitment.units)],
		l.proposalDigests.map(hex),
		l.inputs.map((i) => [
			dec(i.serialId),
			hex(i.prevTxid),
			i.prevOutputIndex,
			i.sequence,
			i.isShared === true,
			i.prevTx?.length ? hex(sha256(i.prevTx)) : null
		]),
		l.outputs.map((o) => [
			dec(o.serialId),
			o.role,
			dec(o.amountSats),
			hex(o.descriptorHash)
		])
	];
}

/** sha256('beignet/asset-conversion/layout/v1\0' || JSON.stringify(fields)). */
export function layoutDigestOf(l: IConversionLayout): Buffer {
	return sha256(
		Buffer.from(
			'beignet/asset-conversion/layout/v1\0' + JSON.stringify(layoutFields(l)),
			'utf8'
		)
	);
}
