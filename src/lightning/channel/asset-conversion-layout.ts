/**
 * The layout of an asset conversion (#2151 step 3b): what both engines
 * build from the hosts' description of a conversion splice, in initiator
 * order, check without relying on either host, and hash. Internal: not in
 * the barrel.
 */
import { Transaction } from 'bitcoinjs-lib';
import { REGTEST_CHAIN_HASH } from '../chain/hashes';
import { isValidPublicKey } from '../crypto/ecdh';
import { sha256 } from '../crypto/provider';
import {
	assetSpliceCommitmentBytes,
	type IAssetSpliceWireRecordLimit
} from '../features/asset-splice';
import type { IInteractiveTxInput } from '../interactive-tx/types';
import {
	DUST_LIMIT_SATS,
	MAX_INTERACTIVE_TX_INPUTS,
	MAX_INTERACTIVE_TX_OUTPUTS,
	MAX_INTERACTIVE_TX_SEQUENCE,
	MAX_MONEY_SATS,
	MAX_PEER_PREVTX_BYTES_PER_SESSION,
	validatePeerInputPrevTx
} from '../interactive-tx/validation';
import {
	decodeSpliceAckMessage,
	decodeSpliceMessage,
	encodeSpliceAckMessage,
	encodeSpliceMessage
} from '../message/splice';
import { createTaprootFundingScript } from '../script/funding-taproot';
import {
	assetConversionTermsDigest,
	type IAssetConversionTerms
} from './asset-conversion-terms';
import type {
	AssetOpenPair,
	IAssetConversionMovement
} from './asset-opening-provider';
import { checkSerials } from './asset-splice-manifest';
import { auxiliaryCarrierError } from './auxiliary-funding';
import { validateFinalSpliceReserves } from './final-commitment-reserve';
import {
	buildFinalSpliceCandidate,
	type IFinalSpliceCandidate,
	type IFinalSpliceTerms
} from './final-splice-candidate';
import { ASSET_OPEN_OBJECT_LIMIT } from '../message/asset-open';

type Pair<T> = AssetOpenPair<T>;
type UnitsRow = { assetId: string; initiator: bigint; acceptor: bigint };

export interface IAssetConversionLayout {
	attempt: Buffer;
	chainHash: Buffer;
	channelId: Buffer;
	/** The encoded `splice_init` and `splice_ack`. */
	init: Buffer;
	ack: Buffer;
	termsDigest: Buffer;
	targetType: Buffer;
	direction: 'to-plain' | 'to-asset';
	/** The live funding transaction and output index. */
	parent: Transaction;
	parentIndex: number;
	/** Initiator first. */
	parentKeys: Pair<Buffer>;
	parentType: 'plain' | 'asset';
	parentRoot?: Buffer;
	/** An asset parent at N > 0: the committed round's digest. */
	priorDigest?: Buffer;
	stateNumber: bigint;
	/** The parent snapshot, initiator first. */
	parentBalancesMsat: Pair<bigint>;
	feeratePerKw: number;
	feeBudgets: Pair<bigint>;
	candidateMaxAcceptedHtlcs: Pair<number>;
	candidateDustSats: Pair<bigint>;
	/** Null to bitcoin. */
	commitmentRecordLimits: Pair<readonly IAssetSpliceWireRecordLimit[]> | null;
	parentUnits: readonly UnitsRow[];
	movements: readonly IAssetConversionMovement[];
	firstCommitment: { balanceMsat: Pair<bigint>; units: readonly UnitsRow[] };
	/** sha256 of each proposal. */
	proposalDigests: Pair<Buffer>;
	inputs: readonly IInteractiveTxInput[];
	outputs: readonly {
		serialId: bigint;
		role: 'funding' | 'change' | 'withdrawal';
		amountSats: bigint;
		descriptorHash: Buffer;
	}[];
}

export interface IAssetConversionLayoutExpectation {
	/** Canonical. */
	terms: IAssetConversionTerms;
	isInitiator: boolean;
	isOpener: boolean;
	parentValueSats: bigint;
	/** The terms' contributions, initiator first. */
	relativeSatoshis: Pair<bigint>;
}

export const ASSET_CONVERSION_LAYOUT_TEXTS = {
	layout: 'Invalid asset conversion layout',
	keys: 'Invalid asset conversion parent or funding keys',
	count: 'Invalid asset conversion item count',
	order: 'Invalid asset conversion serial order or reuse',
	shared: 'Incorrect shared asset conversion input',
	external: 'Invalid external asset conversion input',
	mismatch: 'External asset conversion transaction mismatch',
	input: 'Invalid asset conversion input',
	amount: 'Invalid asset conversion output amount',
	funding: 'Incorrect asset conversion funding output',
	role: 'Unknown asset conversion output role',
	fees: 'Asset conversion exceeds its fee budgets',
	first: 'Asset conversion first commitment does not add up',
	units: 'Asset conversion units differ from its terms',
	credit: 'Asset conversion credits an output its owner did not add',
	describe: 'Asset conversion host could not describe the layout'
} as const;
const T = ASSET_CONVERSION_LAYOUT_TEXTS;

const U64_MAX = 0xffffffffffffffffn;
const ASSET_ID = /^[0-9a-f]{64}$/;

const fail = (text: string): never => {
	throw new Error(text);
};
const inRange = (v: unknown, min: bigint, max: bigint): v is bigint =>
	typeof v === 'bigint' && v >= min && v <= max;
const samePair = <V>(a: Pair<V>, b: Pair<V>): boolean =>
	Array.isArray(a) && a.length === 2 && a[0] === b[0] && a[1] === b[1];
const byInitiator = (
	openerInitiates: boolean
): (<V>(p: { opener: V; acceptor: V }) => [V, V]) =>
	function order<V>(p: { opener: V; acceptor: V }): [V, V] {
		return openerInitiates ? [p.opener, p.acceptor] : [p.acceptor, p.opener];
	};
const owner = (serialId: bigint): 0 | 1 => (serialId & 1n ? 1 : 0);

/**
 * The engine's checks of a conversion layout (contract section 4, checks 1
 * to 8 and 10 to 13), in their order. Throws the first failure's text.
 */
export function checkConversionLayout(
	layout: IAssetConversionLayout,
	expectation: IAssetConversionLayoutExpectation
): void {
	const l = layout,
		x = expectation,
		t = x.terms;
	const order = byInitiator(x.isInitiator === x.isOpener);
	const toAsset = t.direction === 'to-asset';

	// 1. The negotiation, and every field the engine fills from the terms.
	let init!: ReturnType<typeof decodeSpliceMessage>;
	let ack!: ReturnType<typeof decodeSpliceAckMessage>;
	let fresh: boolean;
	try {
		init = decodeSpliceMessage(l.init);
		ack = decodeSpliceAckMessage(l.ack);
		const digest = assetConversionTermsDigest(t);
		const target = Buffer.from(t.targetType, 'hex');
		const tlv = (c?: { termsDigest: Buffer; targetType: Buffer }): boolean =>
			!!c && c.termsDigest.equals(digest) && c.targetType.equals(target);
		const units = (t.firstCommitment.units ?? []).map((u) => {
			const [i, a] = order(u).map(BigInt);
			return { assetId: u.assetId, initiator: i, acceptor: a };
		});
		const first = l.firstCommitment;
		fresh =
			encodeSpliceMessage(init).equals(l.init) &&
			encodeSpliceAckMessage(ack).equals(l.ack) &&
			tlv(init.conversion) &&
			tlv(ack.conversion) &&
			l.chainHash.equals(REGTEST_CHAIN_HASH) &&
			l.channelId.toString('hex') === t.channelId &&
			init.channelId.equals(l.channelId) &&
			ack.channelId.equals(l.channelId) &&
			!init.requireConfirmedInputs &&
			!ack.requireConfirmedInputs &&
			init.lockDepth === t.lockDepth &&
			ack.lockDepth === t.lockDepth &&
			init.fundingFeeratePerkw === t.fees.feeratePerKw &&
			init.relativeSatoshis === x.relativeSatoshis[0] &&
			ack.relativeSatoshis === x.relativeSatoshis[1] &&
			l.parentKeys.length === 2 &&
			l.stateNumber === BigInt(t.parent.stateNumber) &&
			l.parent.getId() === t.parent.txid &&
			l.parentIndex === t.parent.outputIndex &&
			l.termsDigest.equals(digest) &&
			l.targetType.equals(target) &&
			l.direction === t.direction &&
			l.feeratePerKw === t.fees.feeratePerKw &&
			samePair(
				l.feeBudgets,
				order(t.fees.budgets).map(BigInt) as [bigint, bigint]
			) &&
			samePair(
				l.candidateMaxAcceptedHtlcs,
				order(t.candidate.maxAcceptedHtlcs)
			) &&
			samePair(
				l.candidateDustSats,
				order(t.candidate.dustLimitSats).map(BigInt) as [bigint, bigint]
			) &&
			samePair(
				first.balanceMsat,
				order(t.firstCommitment.balanceMsat).map(BigInt) as [bigint, bigint]
			) &&
			first.units.length === units.length &&
			first.units.every(
				(u, i) =>
					u.assetId === units[i].assetId &&
					u.initiator === units[i].initiator &&
					u.acceptor === units[i].acceptor
			);
	} catch {
		fresh = false;
	}
	if (!fresh) fail(T.layout);

	// 2. The parent and the funding keys.
	const keys = [...l.parentKeys, init.fundingPubkey, ack.fundingPubkey];
	const parentOut = Number.isInteger(l.parentIndex)
		? l.parent.outs[l.parentIndex]
		: undefined;
	let script: Buffer | undefined;
	if (keys.every((k) => Buffer.isBuffer(k) && isValidPublicKey(k)))
		try {
			script = createTaprootFundingScript(
				l.parentKeys[0],
				l.parentKeys[1],
				undefined,
				l.parentType === 'asset' ? l.parentRoot : undefined
			).p2trOutput;
		} catch {
			script = undefined;
		}
	if (
		!script ||
		new Set(keys.map((k) => k.subarray(1).toString('hex'))).size !== 4 ||
		!parentOut ||
		!parentOut.script.equals(script) ||
		BigInt(parentOut.value) !== x.parentValueSats
	)
		fail(T.keys);

	// 3. The serials.
	const serials = new Set<bigint>();
	const texts = { count: T.count, order: T.order };
	checkSerials(l.inputs, MAX_INTERACTIVE_TX_INPUTS, serials, texts);
	checkSerials(l.outputs, MAX_INTERACTIVE_TX_OUTPUTS, serials, texts);

	// 4. The inputs: one shared input on the parent, and external coins.
	const parentHash = l.parent.getHash();
	const prevouts = new Set<string>();
	const fees = [-init.relativeSatoshis, -ack.relativeSatoshis];
	const prevTxBytes = [0, 0];
	let shared = 0;
	for (const input of l.inputs) {
		const { serialId, prevTxid, prevOutputIndex, sequence, prevTx } = input;
		const outpoint =
			(Buffer.isBuffer(prevTxid) ? prevTxid.toString('hex') : '') +
			':' +
			prevOutputIndex;
		if (
			!Buffer.isBuffer(prevTxid) ||
			prevTxid.length !== 32 ||
			!Number.isInteger(prevOutputIndex) ||
			prevOutputIndex < 0 ||
			prevOutputIndex > 0xffffffff ||
			!Number.isInteger(sequence) ||
			sequence < 0 ||
			sequence > MAX_INTERACTIVE_TX_SEQUENCE ||
			prevouts.has(outpoint) ||
			(input.prevTxVout !== undefined && input.prevTxVout !== prevOutputIndex)
		)
			fail(T.input);
		prevouts.add(outpoint);
		const side = owner(serialId);
		if (input.isShared === true) {
			if (
				++shared !== 1 ||
				side !== 0 ||
				!parentHash.equals(prevTxid) ||
				l.parentIndex !== prevOutputIndex ||
				prevTx?.length
			)
				fail(T.shared);
			continue;
		}
		if (
			(input.isShared !== undefined && input.isShared !== false) ||
			!Buffer.isBuffer(prevTx) ||
			prevTx.length > 65535 ||
			(prevTxBytes[side] += prevTx.length) >
				MAX_PEER_PREVTX_BYTES_PER_SESSION ||
			validatePeerInputPrevTx(prevTx, prevOutputIndex)
		)
			fail(T.external);
		const previous = Transaction.fromBuffer(prevTx!);
		if (
			!previous.getHash().equals(prevTxid) ||
			!previous.toBuffer().equals(prevTx!)
		)
			fail(T.mismatch);
		fees[side] += BigInt(previous.outs[prevOutputIndex].value);
	}
	if (shared !== 1) fail(T.shared);

	// 5. The output amounts.
	const [dust0, dust1] = l.candidateDustSats;
	let floor = dust0 > dust1 ? dust0 : dust1;
	if (floor < DUST_LIMIT_SATS) floor = DUST_LIMIT_SATS;
	let total = 0n;
	for (const o of l.outputs)
		if (
			!inRange(o.amountSats, floor, MAX_MONEY_SATS) ||
			(total += o.amountSats) > MAX_MONEY_SATS
		)
			fail(T.amount);

	// 6. One funding output of the capacity; the rest withdrawals or change.
	const capacity =
		x.parentValueSats + x.relativeSatoshis[0] + x.relativeSatoshis[1];
	let funding: IAssetConversionLayout['outputs'][number] | undefined;
	for (const o of l.outputs) {
		if (o.role === 'funding') {
			if (funding || owner(o.serialId) !== 0 || o.amountSats !== capacity)
				fail(T.funding);
			funding = o;
		} else if (
			(o.role !== 'withdrawal' && o.role !== 'change') ||
			(o.role === 'withdrawal' && toAsset)
		)
			fail(T.role);
		else fees[owner(o.serialId)] -= o.amountSats;
	}
	if (!funding) fail(T.funding);
	const fundingSerial = funding!.serialId;

	// 7. Each owner's fee within its budget.
	if (fees.some((fee, i) => !inRange(fee, 0n, l.feeBudgets[i]))) fail(T.fees);

	// 8. The first commitment adds up to the capacity.
	const balances = l.firstCommitment.balanceMsat;
	if (balances[0] + balances[1] !== capacity * 1000n) fail(T.first);

	// 10. The units against the terms.
	const amounts = new Map(
		t.units.issuances.map((i) => [i.assetId, BigInt(i.amount)])
	);
	const holder: 'initiator' | 'acceptor' =
		order({ opener: 'opener', acceptor: 'acceptor' })[0] === t.units.holder
			? 'initiator'
			: 'acceptor';
	const roles = new Map(l.outputs.map((o) => [o.serialId, o.role]));
	const moved = new Map<string, bigint>();
	const add = (key: string, units: bigint): void => {
		moved.set(key, (moved.get(key) ?? 0n) + units);
	};
	const seen = new Set<string>();
	for (const m of l.movements) {
		const key = m.assetId + ':' + m.from + ':' + String(m.outputSerial);
		if (
			typeof m.assetId !== 'string' ||
			!ASSET_ID.test(m.assetId) ||
			!amounts.has(m.assetId) ||
			(m.from !== 'initiator' && m.from !== 'acceptor') ||
			typeof m.outputSerial !== 'bigint' ||
			!inRange(m.units, 1n, U64_MAX) ||
			seen.has(key)
		)
			fail(T.units);
		seen.add(key);
		add(m.assetId, m.units);
		add(m.assetId + ':' + m.from, m.units);
		if (m.outputSerial === fundingSerial) add(m.assetId + ':funding', m.units);
	}
	let previous = '';
	for (const u of l.parentUnits) {
		if (
			typeof u.assetId !== 'string' ||
			!ASSET_ID.test(u.assetId) ||
			u.assetId <= previous ||
			!inRange(u.initiator, 0n, U64_MAX) ||
			!inRange(u.acceptor, 0n, U64_MAX) ||
			u.initiator + u.acceptor < 1n
		)
			fail(T.units);
		previous = u.assetId;
	}
	if (toAsset) {
		if (
			l.parentUnits.length ||
			l.movements.some(
				(m) =>
					m.from !== holder ||
					(m.outputSerial !== fundingSerial &&
						roles.get(m.outputSerial) !== 'change')
			) ||
			[...amounts].some(
				([assetId, amount]) =>
					(moved.get(assetId + ':funding') ?? 0n) !== amount
			) ||
			!Array.isArray(l.commitmentRecordLimits) ||
			l.commitmentRecordLimits.length !== 2
		)
			fail(T.units);
		for (const records of l.commitmentRecordLimits!)
			assetSpliceCommitmentBytes(l.candidateMaxAcceptedHtlcs, records);
	} else if (
		l.parentUnits.length !== amounts.size ||
		l.parentUnits.some(
			(u) =>
				amounts.get(u.assetId) !== u.initiator + u.acceptor ||
				(moved.get(u.assetId) ?? 0n) !== amounts.get(u.assetId) ||
				(moved.get(u.assetId + ':initiator') ?? 0n) !== u.initiator ||
				(moved.get(u.assetId + ':acceptor') ?? 0n) !== u.acceptor
		) ||
		l.movements.some((m) => roles.get(m.outputSerial) !== 'withdrawal') ||
		l.commitmentRecordLimits !== null
	)
		fail(T.units);

	// 11. Units credit only the holder's own outputs, besides the funding output.
	const credited = holder === 'initiator' ? 0 : 1;
	if (
		l.movements.some(
			(m) =>
				m.outputSerial !== fundingSerial && owner(m.outputSerial) !== credited
		)
	)
		fail(T.credit);

	// 12. The reserves, with the trade rule for a side without an output.
	const local = x.isInitiator ? 0 : 1,
		remote = x.isInitiator ? 1 : 0;
	const dust = t.candidate.dustLimitSats;
	const owns = (side: 0 | 1): boolean =>
		l.outputs.some((o) => o.role !== 'funding' && owner(o.serialId) === side) ||
		balances[side] < l.parentBalancesMsat[side];
	validateFinalSpliceReserves(
		capacity,
		{
			localDustLimitSatoshis: Number(x.isOpener ? dust.opener : dust.acceptor),
			remoteDustLimitSatoshis: Number(x.isOpener ? dust.acceptor : dust.opener),
			commitmentFeeratePerKw: t.firstCommitment.commitmentFeeratePerKw
		},
		{ localBalanceMsat: balances[local], remoteBalanceMsat: balances[remote] },
		[],
		x.isOpener,
		[owns(local), owns(remote)]
	);

	// 13. To an asset, each side holding units can carry them.
	if (toAsset) {
		const sum = (role: 'opener' | 'acceptor'): bigint =>
			(t.firstCommitment.units ?? []).reduce((s, u) => s + BigInt(u[role]), 0n);
		const carrier = auxiliaryCarrierError({
			fundingSatoshis: capacity,
			pushMsat: BigInt(t.firstCommitment.balanceMsat.acceptor),
			feeratePerKw: t.firstCommitment.commitmentFeeratePerKw,
			openerAssetBalance: sum('opener'),
			acceptorAssetBalance: sum('acceptor'),
			dustLimitSatoshis: dust0 > dust1 ? dust0 : dust1
		});
		if (carrier) fail(carrier);
	}
}

/**
 * sha256('beignet/asset-conversion/layout/v1\0' || JSON of the fields),
 * every bigint a decimal string and every Buffer lowercase hex. It checks
 * nothing.
 */
export function assetConversionLayoutDigest(
	layout: IAssetConversionLayout
): Buffer {
	const l = layout;
	const hex = (b: Buffer): string => b.toString('hex');
	const dec = (n: bigint): string => n.toString();
	const rows = (units: readonly UnitsRow[]): string[][] =>
		units.map((u) => [u.assetId, dec(u.initiator), dec(u.acceptor)]);
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
	const fields = [
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
	return sha256(
		Buffer.from(
			'beignet/asset-conversion/layout/v1\0' + JSON.stringify(fields),
			'utf8'
		)
	);
}

/** sha256('asset-conversion-agreement/v1\0' || layoutDigest || planDigest): the `layout_ack` value. */
export function assetConversionAgreementDigest(
	layoutDigest: Buffer,
	planDigest: Buffer
): Buffer {
	return sha256(
		Buffer.concat([
			Buffer.from('asset-conversion-agreement/v1\0', 'ascii'),
			layoutDigest,
			planDigest
		])
	);
}

/** The layout fields the engine fills itself, before the description's. */
export type IAssetConversionLayoutBase = Omit<
	IAssetConversionLayout,
	'commitmentRecordLimits' | 'parentUnits' | 'movements' | 'inputs' | 'outputs'
>;

const isBuffer = (v: unknown, length?: number): v is Buffer =>
	Buffer.isBuffer(v) && (length === undefined || v.length === length);
const isSafe = (v: unknown): v is number => Number.isSafeInteger(v);
const isRecord = (v: unknown): v is Record<string, unknown> =>
	typeof v === 'object' && v !== null;
const listOf = (
	v: unknown,
	item: (x: Record<string, unknown>) => boolean
): boolean => Array.isArray(v) && v.every((x) => isRecord(x) && item(x));

/** Whether a host's description has the JavaScript shape its type names (section 3, S15). */
function describedShape(d: unknown): d is {
	inputs: Record<string, unknown>[];
	outputs: Record<string, unknown>[];
	movements: Record<string, unknown>[];
	parentUnits: Record<string, unknown>[];
	feeBudgets: bigint[];
	relativeSatoshis: bigint[];
	commitmentRecordLimits?: Record<string, unknown>[][];
} {
	if (!isRecord(d)) return false;
	const pair = (v: unknown): boolean =>
		Array.isArray(v) && v.length === 2 && v.every((n) => typeof n === 'bigint');
	return (
		listOf(
			d.inputs,
			(i) =>
				typeof i.serialId === 'bigint' &&
				isBuffer(i.txid, 32) &&
				isSafe(i.vout) &&
				isSafe(i.sequence) &&
				typeof i.isShared === 'boolean' &&
				(i.prevTx === undefined || isBuffer(i.prevTx))
		) &&
		listOf(
			d.outputs,
			(o) =>
				typeof o.serialId === 'bigint' &&
				(o.kind === 'funding' ||
					o.kind === 'withdrawal' ||
					o.kind === 'change') &&
				typeof o.valueSats === 'bigint' &&
				isBuffer(o.descriptorHash, 32)
		) &&
		listOf(
			d.movements,
			(m) =>
				typeof m.assetId === 'string' &&
				(m.from === 'initiator' || m.from === 'acceptor') &&
				typeof m.outputSerial === 'bigint' &&
				typeof m.units === 'bigint'
		) &&
		listOf(
			d.parentUnits,
			(u) =>
				typeof u.assetId === 'string' &&
				typeof u.initiator === 'bigint' &&
				typeof u.acceptor === 'bigint'
		) &&
		pair(d.feeBudgets) &&
		pair(d.relativeSatoshis) &&
		(d.commitmentRecordLimits === undefined ||
			(Array.isArray(d.commitmentRecordLimits) &&
				d.commitmentRecordLimits.every((records) =>
					listOf(
						records,
						(r) => typeof r.type === 'bigint' && isSafe(r.maxBytes)
					)
				)))
	);
}

/** More entries than any list of a layout can hold. */
const DESCRIPTION_LIST_LIMIT = 65_536;

/**
 * A plain copy of a host's description, read once per field before any
 * check (amendment v2.4 item 2): arrays become dense arrays (a hole is
 * `undefined`), records become plain objects of the named fields, and
 * Buffers are copied. Anything else is kept as read, for the shape check.
 */
function copyDescription(d: unknown): unknown {
	if (!isRecord(d)) return d;
	// The length is read once, and a list longer than any layout holds is
	// not read at all: its shape check then fails (amendment v2.5 item 2).
	const list = (v: unknown, item: (x: unknown) => unknown): unknown => {
		if (!Array.isArray(v)) return v;
		const items = v as unknown[];
		const length = items.length;
		if (length > DESCRIPTION_LIST_LIMIT) return undefined;
		return Array.from({ length }, (_, i) => item(items[i]));
	};
	const fields =
		(...names: string[]) =>
		(x: unknown): unknown => {
			if (!isRecord(x)) return x;
			const out: Record<string, unknown> = {};
			for (const name of names) {
				const v = x[name];
				out[name] = Buffer.isBuffer(v) ? Buffer.from(v) : v;
			}
			return out;
		};
	const same = (x: unknown): unknown => x;
	const records = d.commitmentRecordLimits;
	return {
		inputs: list(
			d.inputs,
			fields('serialId', 'txid', 'vout', 'sequence', 'isShared', 'prevTx')
		),
		outputs: list(
			d.outputs,
			fields('serialId', 'kind', 'valueSats', 'descriptorHash')
		),
		movements: list(
			d.movements,
			fields('assetId', 'from', 'outputSerial', 'units')
		),
		parentUnits: list(
			d.parentUnits,
			fields('assetId', 'initiator', 'acceptor')
		),
		feeBudgets: list(d.feeBudgets, same),
		relativeSatoshis: list(d.relativeSatoshis, same),
		commitmentRecordLimits: list(records, (r) =>
			list(r, fields('type', 'maxBytes'))
		)
	};
}

/**
 * The layout of a host's description over the engine's own fields, as the
 * asset splice maps one. The description is copied first and only the copy
 * is read. A description of the wrong shape is the host's failure; pairs
 * that differ from the terms' budgets and contributions are "Invalid asset
 * conversion layout".
 */
export function describedConversionLayout(
	base: IAssetConversionLayoutBase,
	relativeSatoshis: Pair<bigint>,
	description: unknown
): IAssetConversionLayout {
	let d: unknown;
	try {
		d = copyDescription(description);
	} catch {
		// A getter or proxy that throws is the host's failure too.
		return fail(T.describe);
	}
	if (!describedShape(d)) return fail(T.describe);
	if (
		!samePair(base.feeBudgets, d.feeBudgets as unknown as Pair<bigint>) ||
		!samePair(relativeSatoshis, d.relativeSatoshis as unknown as Pair<bigint>)
	)
		fail(T.layout);
	return {
		...base,
		commitmentRecordLimits:
			d.commitmentRecordLimits === undefined
				? null
				: (d.commitmentRecordLimits.map((records) =>
						records.map((r) => ({
							type: r.type as bigint,
							maxBytes: r.maxBytes as number
						}))
				  ) as unknown as Pair<IAssetSpliceWireRecordLimit[]>),
		parentUnits: d.parentUnits.map((u) => ({
			assetId: u.assetId as string,
			initiator: u.initiator as bigint,
			acceptor: u.acceptor as bigint
		})),
		movements: d.movements.map((m) => ({
			assetId: m.assetId as string,
			from: m.from as 'initiator' | 'acceptor',
			outputSerial: m.outputSerial as bigint,
			units: m.units as bigint
		})),
		inputs: d.inputs.map((i) => ({
			serialId: i.serialId as bigint,
			prevTxid: Buffer.from(i.txid as Buffer),
			prevOutputIndex: i.vout as number,
			sequence: i.sequence as number,
			isShared: i.isShared as boolean,
			...(i.prevTx !== undefined && { prevTx: Buffer.from(i.prevTx as Buffer) })
		})),
		outputs: d.outputs.map((o) => ({
			serialId: o.serialId as bigint,
			role: o.kind as 'funding' | 'change' | 'withdrawal',
			amountSats: o.valueSats as bigint,
			descriptorHash: Buffer.from(o.descriptorHash as Buffer)
		}))
	};
}

// ---- The frozen candidate (#2151 Step 4b) ----

/** The text of every frozen candidate that the acknowledged layout does not describe. */
export const FROZEN_CONVERSION_TEXT =
	'Frozen asset conversion disagrees with the acknowledged layout';

/** What the plan's finalize answered: the unsigned funding and its proofs' digests. */
export interface IConversionFundingFacts {
	layoutDigest: Buffer;
	transaction: Buffer;
	proofDigest: Buffer;
	fundingRoot?: Buffer;
	fundingProofs?: Buffer;
}

/** The frozen candidate both engines sign over, with its final digest. */
export interface IVerifiedConversionCandidate {
	terms: IFinalSpliceTerms;
	candidate: IFinalSpliceCandidate;
	layoutDigest: Buffer;
	finalDigest: Buffer;
	/** To an asset: the candidate's root and its funding proofs. */
	fundingRoot?: Buffer;
	fundingProofs?: Buffer;
	proofDigest: Buffer;
}

/**
 * sha256('beignet/asset-conversion/final/v1\0' || layoutDigest ||
 * sha256(targetType) || candidate tx.getHash() || (fundingRoot or 32 zero
 * bytes) || sha256(authorization[0]) || sha256(authorization[1]) ||
 * proofDigest), the authorizations in initiator order.
 */
export function assetConversionFinalDigest(
	layoutDigest: Buffer,
	targetType: Buffer,
	candidateHash: Buffer,
	fundingRoot: Buffer | undefined,
	authorizations: Pair<Buffer>,
	proofDigest: Buffer
): Buffer {
	return sha256(
		Buffer.concat([
			Buffer.from('beignet/asset-conversion/final/v1\0', 'ascii'),
			layoutDigest,
			sha256(targetType),
			candidateHash,
			fundingRoot ?? Buffer.alloc(32),
			sha256(authorizations[0]),
			sha256(authorizations[1]),
			proofDigest
		])
	);
}

/**
 * sha256('beignet/asset-conversion/construction/v1\0' || finalDigest ||
 * tx.getHash() || sha256(nonces[0]) || sha256(nonces[1])), the two last
 * `tx_complete` payloads in initiator order.
 */
export function assetConversionCheckpointDigest(
	finalDigest: Buffer,
	txHash: Buffer,
	nonces: Pair<Buffer>
): Buffer {
	return sha256(
		Buffer.concat([
			Buffer.from('beignet/asset-conversion/construction/v1\0', 'ascii'),
			finalDigest,
			txHash,
			sha256(nonces[0]),
			sha256(nonces[1])
		])
	);
}

const isBytes = (v: unknown, min: number, max: number): v is Buffer =>
	Buffer.isBuffer(v) && v.length >= min && v.length <= max;

/**
 * The plan's frozen funding against the acknowledged layout (#2151 Step
 * 4b, section 3.1): the layout and agreement digests, the transaction the
 * splice builder gives from the layout's terms with the conversion's one
 * root, its funding index and output amounts, and the proofs' shapes by
 * direction. Any difference throws `FROZEN_CONVERSION_TEXT`.
 */
export function verifyConversionCandidate(
	layout: IAssetConversionLayout,
	acknowledged: { layoutDigest: Buffer; agreement: Buffer; planDigest: Buffer },
	isInitiator: boolean,
	frozen: Transaction,
	funding: IConversionFundingFacts,
	authorizations: Pair<Buffer>
): IVerifiedConversionCandidate {
	try {
		const layoutDigest = assetConversionLayoutDigest(layout);
		const toAsset = layout.direction === 'to-asset';
		if (
			!layoutDigest.equals(acknowledged.layoutDigest) ||
			!assetConversionAgreementDigest(
				layoutDigest,
				acknowledged.planDigest
			).equals(acknowledged.agreement) ||
			!Buffer.isBuffer(funding.layoutDigest) ||
			!layoutDigest.equals(funding.layoutDigest) ||
			!Buffer.isBuffer(funding.transaction) ||
			!frozen.toBuffer().equals(funding.transaction) ||
			frozen.outs.length !== layout.outputs.length ||
			!isBytes(funding.proofDigest, 32, 32) ||
			(toAsset
				? !isBytes(funding.fundingRoot, 32, 32) ||
				  !isBytes(funding.fundingProofs, 1, ASSET_OPEN_OBJECT_LIMIT)
				: funding.fundingRoot !== undefined ||
				  funding.fundingProofs !== undefined ||
				  !layout.parentRoot)
		)
			throw new Error(FROZEN_CONVERSION_TEXT);
		const init = decodeSpliceMessage(layout.init);
		const ack = decodeSpliceAckMessage(layout.ack);
		const local = isInitiator ? init : ack;
		const peer = isInitiator ? ack : init;
		const [dust0, dust1] = layout.candidateDustSats;
		let dust = dust0 > dust1 ? dust0 : dust1;
		if (dust < DUST_LIMIT_SATS) dust = DUST_LIMIT_SATS;
		const terms: IFinalSpliceTerms = {
			parent: Transaction.fromBuffer(layout.parent.toBuffer()),
			parentIndex: layout.parentIndex,
			oldLocalKey: Buffer.from(layout.parentKeys[isInitiator ? 0 : 1]),
			oldPeerKey: Buffer.from(layout.parentKeys[isInitiator ? 1 : 0]),
			newLocalKey: Buffer.from(local.fundingPubkey),
			newPeerKey: Buffer.from(peer.fundingPubkey),
			localIsSpliceInitiator: isInitiator,
			localDelta: local.relativeSatoshis,
			peerDelta: peer.relativeSatoshis,
			localFeeBudget: layout.feeBudgets[isInitiator ? 0 : 1],
			feerate: layout.feeratePerKw,
			dust,
			locktime: init.locktime,
			conversionRoots: toAsset
				? { candidate: Buffer.from(funding.fundingRoot!) }
				: { parent: Buffer.from(layout.parentRoot!) }
		};
		const candidate = buildFinalSpliceCandidate(
			terms,
			layout.inputs.map((i) => ({
				...i,
				prevTxid: Buffer.from(i.prevTxid),
				prevTx: i.prevTx && Buffer.from(i.prevTx)
			})),
			layout.outputs.map((o, i) => ({
				serialId: o.serialId,
				amountSats: o.amountSats,
				scriptPubkey: Buffer.from(frozen.outs[i].script)
			}))
		);
		const fundingIndex = layout.outputs.findIndex((o) => o.role === 'funding');
		if (
			candidate.fundingIndex !== fundingIndex ||
			layout.outputs.some(
				(o, i) => BigInt(candidate.tx.outs[i].value) !== o.amountSats
			) ||
			!candidate.tx.toBuffer().equals(funding.transaction)
		)
			throw new Error(FROZEN_CONVERSION_TEXT);
		return {
			terms,
			candidate,
			layoutDigest,
			finalDigest: assetConversionFinalDigest(
				layoutDigest,
				layout.targetType,
				candidate.tx.getHash(),
				toAsset ? funding.fundingRoot : undefined,
				authorizations,
				funding.proofDigest
			),
			...(toAsset && {
				fundingRoot: Buffer.from(funding.fundingRoot!),
				fundingProofs: Buffer.from(funding.fundingProofs!)
			}),
			proofDigest: Buffer.from(funding.proofDigest)
		};
	} catch {
		throw new Error(FROZEN_CONVERSION_TEXT);
	}
}
