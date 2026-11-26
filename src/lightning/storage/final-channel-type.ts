/**
 * #2151 step 2a: the `channel-type` record of a generation 6 channel. A
 * record names the channel's new type, the funding output it lives on from
 * then, the state number it starts at and the seed its new ledger starts
 * from. Step 5 appends it at adoption; nothing on the wire changes.
 */
import { Transaction } from 'bitcoinjs-lib';
import { ecc } from '../../utils/ecc';
import { isFinalTaprootTypeHex } from '../channel/commitment-profile';
import { finalFundingReserveSats } from '../channel/final-commitment-reserve';
import {
	buildAssetSpliceCommitment,
	buildFinalCommitmentView,
	type IFinalOpeningTerms
} from '../channel/final-opening-commitment';
import type { IFinalFundingReference } from '../channel/final-splice-candidate';
import { taggedHash } from '../crypto/hash';
import { ASSET_SPLICE_RECOVERY_TYPE_HEX } from '../features/asset-opening';
import { MAX_INDEX } from '../keys/shachain';
import type { IAssetSpliceExitBranch } from './asset-splice-exit-proofs';
import {
	canonicalSpliceFunding,
	canonicalSpliceHolder
} from './asset-splice-recovery';
import type { IFinalLedgerState } from './final-channel-updates';
import type { IFinalOpeningCandidate } from './final-opening-candidate';
import {
	checkUpdateNonce,
	type IFinalUpdateNonce
} from './final-update-signing';

export type FinalChannelKind = 'plain' | 'asset';
export type IFinalPeerShachain = IFinalLedgerState['shachain'];
type Funds = IFinalLedgerState['locked'];

/** The first plain commitments at the record's state number, on its funding. */
export interface IFinalPlainSeed {
	local: { tx: string; signed: string; nextNonce: IFinalUpdateNonce };
	remote: { tx: string; nextNonce: IFinalUpdateNonce };
	localRevoke?: string;
	peerRevoke?: string;
	funds: Funds;
	nextLocalId: string;
	nextPeerId: string;
	/** This device's points at N and N + 1, computed by the writer. */
	localPoints: [string, string];
	shachain: IFinalPeerShachain;
}
/** The first asset state at the record's state number, shaped as a secured round. */
export interface IFinalAssetSeed {
	members: IAssetSpliceExitBranch[];
	feerate: number;
	nextLocalId: string;
	nextPeerId: string;
	htlcs: [];
	peerNextPoint: string;
	peerNonces: string[];
	localNonces: string[];
	localRevoke?: string;
	peerRevoke?: string;
	digest: string;
	/** This device's points at N and N + 1, computed by the writer. */
	localPoints: [string, string];
	shachain: IFinalPeerShachain;
}
export interface IFinalChannelTypeRecord {
	kind: 'channel-type';
	type: FinalChannelKind;
	channelType: string;
	stateNumber: string;
	funding: IFinalFundingReference;
	parent: { txid: string; outputIndex: number };
	seed: IFinalPlainSeed | IFinalAssetSeed;
}
type Unseeded<T> = Omit<T, 'shachain' | 'localPoints'>;
/** The writer's input: the record without the peer shachain and the local points, which the writer computes. */
export type IFinalChannelTypeInput = Omit<IFinalChannelTypeRecord, 'seed'> & {
	seed: Unseeded<IFinalPlainSeed> | Unseeded<IFinalAssetSeed>;
};
/** A channel's current type: the latest record, else the opening. */
export interface IFinalChannelType {
	type: FinalChannelKind;
	channelType: string;
	source: 'opening' | 'record';
	stateNumber: bigint;
	funding: { txid: string; outputIndex: number };
	record?: IFinalChannelTypeRecord;
}

function invalid(): never {
	throw new Error('Invalid channel type record');
}
function check(condition: unknown): asserts condition {
	if (!condition) invalid();
}
function keys(v: unknown, required: string[], optional: string[] = []): void {
	check(v !== null && typeof v === 'object' && !Array.isArray(v));
	const present = Object.keys(v as object);
	check(required.every((k) => present.includes(k)));
	check(present.every((k) => required.includes(k) || optional.includes(k)));
}
function hex(v: unknown, bytes?: number): string {
	check(
		typeof v === 'string' &&
			v.length > 0 &&
			v.length % 2 === 0 &&
			/^[0-9a-f]+$/.test(v) &&
			(bytes === undefined || v.length === bytes * 2)
	);
	return v;
}
function decimal(v: unknown): string {
	check(
		typeof v === 'string' &&
			v.length <= 20 &&
			/^(0|[1-9][0-9]*)$/.test(v) &&
			BigInt(v) <= 0xffffffffffffffffn
	);
	return v;
}
function index(v: unknown, max = 0xffffffff): number {
	check(Number.isSafeInteger(v) && (v as number) >= 0 && (v as number) <= max);
	return v as number;
}
function nonce(v: unknown, local: boolean): IFinalUpdateNonce {
	keys(v, ['pub'], local ? ['source'] : []);
	const n = v as IFinalUpdateNonce;
	if (local) check(n.source === 'splice');
	return { pub: hex(n.pub, 66), ...(local && { source: 'splice' as const }) };
}
function revokes(seed: { localRevoke?: unknown; peerRevoke?: unknown }): {
	peerRevoke?: string | undefined;
	localRevoke?: string | undefined;
} {
	return {
		...(seed.localRevoke !== undefined && {
			localRevoke: hex(seed.localRevoke)
		}),
		...(seed.peerRevoke !== undefined && { peerRevoke: hex(seed.peerRevoke) })
	};
}
function funding(v: unknown): IFinalFundingReference {
	keys(v, [
		'fundingTxHex',
		'fundingOutputIndex',
		'localFundingPubkey',
		'remoteFundingPubkey',
		'localFundingKeyIndex'
	]);
	try {
		const ref = canonicalSpliceFunding(v as IFinalFundingReference);
		const tx = Transaction.fromHex(ref.fundingTxHex);
		check(tx.toHex() === ref.fundingTxHex && tx.outs[ref.fundingOutputIndex]);
		return ref;
	} catch {
		return invalid();
	}
}
function holderRecovery(
	v: IAssetSpliceExitBranch['localRecovery']
): IAssetSpliceExitBranch['localRecovery'] {
	keys(v, [
		'point',
		'localBalanceMsat',
		'remoteBalanceMsat',
		'toLocal',
		'toRemote',
		'ownedOutputIndex',
		'htlcs'
	]);
	let c: typeof v;
	try {
		c = canonicalSpliceHolder(v);
	} catch {
		return invalid();
	}
	check(c.htlcs.length === 0);
	return {
		point: c.point,
		localBalanceMsat: c.localBalanceMsat,
		remoteBalanceMsat: c.remoteBalanceMsat,
		toLocal: c.toLocal,
		toRemote: c.toRemote,
		ownedOutputIndex: c.ownedOutputIndex,
		htlcs: []
	};
}
function member(v: IAssetSpliceExitBranch): IAssetSpliceExitBranch {
	keys(v, [
		'minimumDepth',
		'funding',
		'localRecovery',
		'remoteRecovery',
		'fundingTxid',
		'outputIndex',
		'fundingRoot',
		'fundingProofs',
		'localCommitment',
		'localProofs',
		'remoteCommitment',
		'remoteProofs'
	]);
	return {
		minimumDepth: index(v.minimumDepth),
		funding: funding(v.funding),
		localRecovery: holderRecovery(v.localRecovery),
		remoteRecovery: holderRecovery(v.remoteRecovery),
		fundingTxid: hex(v.fundingTxid, 32),
		outputIndex: index(v.outputIndex),
		fundingRoot: hex(v.fundingRoot, 32),
		fundingProofs: hex(v.fundingProofs),
		localCommitment: hex(v.localCommitment),
		localProofs: hex(v.localProofs),
		remoteCommitment: hex(v.remoteCommitment),
		remoteProofs: hex(v.remoteProofs)
	};
}
function shachain(v: unknown): IFinalPeerShachain {
	check(Array.isArray(v) && v.length <= 49);
	return (v as IFinalPeerShachain).map((e) => {
		if (e === null) return null;
		keys(e, ['height', 'secret']);
		return {
			height: index(e.height, Number.MAX_SAFE_INTEGER),
			secret: hex(e.secret, 32)
		};
	});
}
function localPoints(v: unknown): [string, string] {
	check(Array.isArray(v) && v.length === 2);
	const [a, b] = v as unknown[];
	return [hex(a, 33), hex(b, 33)];
}
function plainSeed(
	v: Unseeded<IFinalPlainSeed>,
	withChain: boolean
): {
	funds: { feeratePerKw: number; local: string; peer: string; htlcs: never[] };
	nextLocalId: string;
	nextPeerId: string;
	peerRevoke?: string | undefined;
	localRevoke?: string | undefined;
	local: { tx: string; signed: string; nextNonce: IFinalUpdateNonce };
	remote: { tx: string; nextNonce: IFinalUpdateNonce };
} {
	const optional = ['localRevoke', 'peerRevoke'];
	keys(
		v,
		['local', 'remote', 'funds', 'nextLocalId', 'nextPeerId'].concat(
			withChain ? ['localPoints', 'shachain'] : []
		),
		optional
	);
	keys(v.local, ['tx', 'signed', 'nextNonce']);
	keys(v.remote, ['tx', 'nextNonce']);
	keys(v.funds, ['feeratePerKw', 'local', 'peer', 'htlcs']);
	check(Array.isArray(v.funds.htlcs) && v.funds.htlcs.length === 0);
	return {
		local: {
			tx: hex(v.local.tx),
			signed: hex(v.local.signed),
			nextNonce: nonce(v.local.nextNonce, true)
		},
		remote: {
			tx: hex(v.remote.tx),
			nextNonce: nonce(v.remote.nextNonce, false)
		},
		...revokes(v),
		funds: {
			feeratePerKw: index(v.funds.feeratePerKw),
			local: decimal(v.funds.local),
			peer: decimal(v.funds.peer),
			htlcs: []
		},
		nextLocalId: decimal(v.nextLocalId),
		nextPeerId: decimal(v.nextPeerId)
	};
}
function assetSeed(
	v: Unseeded<IFinalAssetSeed>,
	withChain: boolean
): {
	digest: string;
	peerRevoke?: string | undefined;
	localRevoke?: string | undefined;
	members: IAssetSpliceExitBranch[];
	feerate: number;
	nextLocalId: string;
	nextPeerId: string;
	htlcs: [];
	peerNextPoint: string;
	peerNonces: string[];
	localNonces: string[];
} {
	keys(
		v,
		[
			'members',
			'feerate',
			'nextLocalId',
			'nextPeerId',
			'htlcs',
			'peerNextPoint',
			'peerNonces',
			'localNonces',
			'digest'
		].concat(withChain ? ['localPoints', 'shachain'] : []),
		['localRevoke', 'peerRevoke']
	);
	check(Array.isArray(v.members) && v.members.length === 1);
	check(Array.isArray(v.htlcs) && v.htlcs.length === 0);
	const list = (n: unknown): string[] => {
		check(Array.isArray(n) && n.length === v.members.length);
		return (n as unknown[]).map((x) => hex(x, 66));
	};
	return {
		members: v.members.map(member),
		feerate: index(v.feerate),
		nextLocalId: decimal(v.nextLocalId),
		nextPeerId: decimal(v.nextPeerId),
		htlcs: [] as [],
		peerNextPoint: hex(v.peerNextPoint, 33),
		peerNonces: list(v.peerNonces),
		localNonces: list(v.localNonces),
		...revokes(v),
		digest: hex(v.digest, 32)
	};
}
function canonical(
	r: IFinalChannelTypeRecord | IFinalChannelTypeInput,
	withChain: boolean
): IFinalChannelTypeRecord | IFinalChannelTypeInput {
	keys(r, [
		'kind',
		'type',
		'channelType',
		'stateNumber',
		'funding',
		'parent',
		'seed'
	]);
	check(r.kind === 'channel-type');
	check(r.type === 'plain' || r.type === 'asset');
	check(
		r.type === 'plain'
			? isFinalTaprootTypeHex(r.channelType)
			: r.channelType === ASSET_SPLICE_RECOVERY_TYPE_HEX
	);
	const n = decimal(r.stateNumber);
	check(BigInt(n) < MAX_INDEX - 1n);
	keys(r.parent, ['txid', 'outputIndex']);
	const parent = {
		txid: hex(r.parent.txid, 32),
		outputIndex: index(r.parent.outputIndex)
	};
	const seed =
		r.type === 'plain'
			? plainSeed(r.seed as Unseeded<IFinalPlainSeed>, withChain)
			: assetSeed(r.seed as Unseeded<IFinalAssetSeed>, withChain);
	return {
		kind: 'channel-type',
		type: r.type,
		channelType: r.channelType,
		stateNumber: n,
		funding: funding(r.funding),
		parent,
		seed: withChain
			? {
					...seed,
					localPoints: localPoints(
						(r.seed as { localPoints?: unknown }).localPoints
					),
					shachain: shachain((r.seed as { shachain?: unknown }).shachain)
			  }
			: seed
	} as IFinalChannelTypeRecord;
}

/** Validate every field of a stored record and return it in canonical field order. */
export function canonicalFinalChannelTypeRecord(
	r: IFinalChannelTypeRecord
): IFinalChannelTypeRecord {
	return canonical(r, true) as IFinalChannelTypeRecord;
}
/** The writer's form: the record without `seed.shachain`. */
export function canonicalFinalChannelTypeInput(
	r: IFinalChannelTypeInput
): IFinalChannelTypeInput {
	return canonical(r, false) as IFinalChannelTypeInput;
}

/** The outpoint a funding reference names. */
export function fundingOutpoint(ref: {
	fundingTxHex: string;
	fundingOutputIndex: number;
}): { txid: string; outputIndex: number } {
	return {
		txid: Transaction.fromHex(ref.fundingTxHex).getId(),
		outputIndex: ref.fundingOutputIndex
	};
}

/**
 * The asset seed's round digest, which the round at N + 1 hashes as its
 * prior. Both peers compute it from opener-ordered fields, since each side's
 * own record names local and remote the other way round.
 */
export function finalAssetSeedDigest(
	channelId: string,
	isInitiator: boolean,
	input: Pick<IFinalChannelTypeInput, 'stateNumber' | 'funding' | 'seed'>
): string {
	const seed = input.seed as Unseeded<IFinalAssetSeed>;
	const m = seed.members[0];
	const opener = <T>(local: T, peer: T): [T, T] =>
		isInitiator ? [local, peer] : [peer, local];
	const txid = (hexTx: string): string => Transaction.fromHex(hexTx).getId();
	const raw = JSON.stringify([
		channelId,
		input.stateNumber,
		Transaction.fromHex(input.funding.fundingTxHex).getId(),
		input.funding.fundingOutputIndex,
		m.fundingRoot,
		opener(m.localRecovery.localBalanceMsat, m.localRecovery.remoteBalanceMsat),
		opener([], []),
		seed.feerate,
		opener(seed.nextLocalId, seed.nextPeerId),
		[],
		opener(txid(m.localCommitment), txid(m.remoteCommitment))
	]);
	return taggedHash('beignet/channel-type-seed/v1', Buffer.from(raw)).toString(
		'hex'
	);
}

/** What the old ledger says at the record's state number N, for seed verification. */
export interface IFinalSeedContext {
	candidate: IFinalOpeningCandidate;
	terms: IFinalOpeningTerms;
	/** The opening's own asset root, absent for a plain opening. */
	openingRoot?: Buffer;
	/** This device's point at N, from the old ledger. */
	localPoint: Buffer;
	/** The peer's points at N and N + 1, from the old ledger. */
	peerPoints: [Buffer, Buffer];
	nextLocalId: string;
	nextPeerId: string;
}
function unsigned(hexTx: string): string {
	const tx = Transaction.fromHex(hexTx);
	tx.ins.forEach((_, i) => tx.setWitness(i, []));
	return tx.toHex();
}
function seedRefused(what: string): never {
	throw new Error('Channel type seed ' + what + ' does not verify');
}
/** The key path signature of a commitment against the funding output it spends. */
function verifyFundingSignature(
	signedHex: string,
	ref: IFinalFundingReference
): void {
	const tx = Transaction.fromHex(signedHex);
	const out = Transaction.fromHex(ref.fundingTxHex).outs[
		ref.fundingOutputIndex
	];
	const sig = tx.ins[0]?.witness[0];
	if (!out || !sig || sig.length !== 64 || tx.ins.length !== 1)
		seedRefused('signature');
	const digest = tx.hashForWitnessV1(
		0,
		[out.script],
		[out.value],
		Transaction.SIGHASH_DEFAULT
	);
	if (!ecc.verifySchnorr(digest, out.script.subarray(2), sig))
		seedRefused('signature');
}
function verifyReserves(
	ctx: IFinalSeedContext,
	ref: IFinalFundingReference,
	localMsat: bigint,
	remoteMsat: bigint
): void {
	const capacity = BigInt(
		Transaction.fromHex(ref.fundingTxHex).outs[ref.fundingOutputIndex].value
	);
	if (
		localMsat / 1000n < finalFundingReserveSats(capacity, ctx.terms, true) ||
		remoteMsat / 1000n < finalFundingReserveSats(capacity, ctx.terms, false)
	)
		seedRefused('reserve');
}
function verifyIds(
	seed: { nextLocalId: string; nextPeerId: string },
	ctx: IFinalSeedContext
): void {
	if (
		seed.nextLocalId !== ctx.nextLocalId ||
		seed.nextPeerId !== ctx.nextPeerId
	)
		seedRefused('HTLC IDs');
}
function validNonce(pub: string, what: string): void {
	try {
		checkUpdateNonce(Buffer.from(pub, 'hex'));
	} catch {
		seedRefused(what);
	}
}
function rebuilt(
	build: () => Transaction,
	expected: string,
	what: string
): void {
	let built: string | undefined;
	try {
		built = build().toHex();
	} catch {
		built = undefined;
	}
	if (built !== expected) seedRefused(what);
}

/**
 * Seed verification (the writer's rule 13): the new type's builder at N on
 * the record's funding rebuilds the seed's commitments, the local one is
 * signed for that funding, the peer's points and the next HTLC IDs are the
 * old ledger's, the nonces are well formed and both reserves hold. The
 * balances need not be the old ledger's, since a conversion moves balances
 * by agreement. The local nonces are the device's derivation, which needs
 * the funding key: they are checked where the root is present.
 */
export function verifyFinalChannelTypeSeed(
	channelId: string,
	input: IFinalChannelTypeInput,
	ctx: IFinalSeedContext
): void {
	const n = BigInt(input.stateNumber);
	const ref = input.funding;
	const as = {
		channelType: input.channelType,
		...(ctx.openingRoot && { openingRoot: ctx.openingRoot })
	};
	if (input.type === 'plain') {
		const seed = input.seed as Unseeded<IFinalPlainSeed>;
		const terms = {
			...ctx.terms,
			commitmentFeeratePerKw: seed.funds.feeratePerKw!
		};
		const balances = {
			localBalanceMsat: BigInt(seed.funds.local),
			remoteBalanceMsat: BigInt(seed.funds.peer)
		};
		const view =
			(holder: 'local' | 'remote', point: Buffer) => (): Transaction =>
				buildFinalCommitmentView(
					ctx.candidate,
					terms,
					holder,
					point,
					n,
					balances,
					[],
					ref,
					as
				).tx;
		rebuilt(view('remote', ctx.peerPoints[0]), seed.remote.tx, 'rebuilt bytes');
		rebuilt(
			view('local', ctx.localPoint),
			unsigned(seed.local.tx),
			'rebuilt bytes'
		);
		verifyFundingSignature(seed.local.tx, ref);
		validNonce(seed.local.nextNonce.pub, 'local nonce');
		validNonce(seed.remote.nextNonce.pub, 'remote nonce');
		if (seed.local.nextNonce.pub === seed.remote.nextNonce.pub)
			seedRefused('nonces');
		verifyIds(seed, ctx);
		verifyReserves(
			ctx,
			ref,
			balances.localBalanceMsat,
			balances.remoteBalanceMsat
		);
		return;
	}
	const seed = input.seed as Unseeded<IFinalAssetSeed>;
	const m = seed.members[0];
	const { txid, outputIndex } = fundingOutpoint(ref);
	if (
		JSON.stringify(m.funding) !== JSON.stringify(ref) ||
		m.fundingTxid !== txid ||
		m.outputIndex !== outputIndex
	)
		seedRefused('member funding');
	if (
		m.localRecovery.point !== ctx.localPoint.toString('hex') ||
		m.remoteRecovery.point !== ctx.peerPoints[0].toString('hex') ||
		seed.peerNextPoint !== ctx.peerPoints[1].toString('hex')
	)
		seedRefused('points');
	const terms = { ...ctx.terms, commitmentFeeratePerKw: seed.feerate };
	const leaf = (
		v: { script: string; leafVersion?: number } | null
	): { leafVersion?: number | undefined; script: Buffer } | undefined =>
		v
			? {
					script: Buffer.from(v.script, 'hex'),
					...(v.leafVersion !== undefined && { leafVersion: v.leafVersion })
			  }
			: undefined;
	const view =
		(holder: 'local' | 'remote', r: IAssetSpliceExitBranch['localRecovery']) =>
		(): Transaction =>
			buildAssetSpliceCommitment(
				ctx.candidate,
				terms,
				holder,
				Buffer.from(r.point, 'hex'),
				n,
				{
					localBalanceMsat: BigInt(r.localBalanceMsat),
					remoteBalanceMsat: BigInt(r.remoteBalanceMsat)
				},
				[],
				ref,
				ctx.openingRoot as Buffer,
				{
					fundingRoot: Buffer.from(m.fundingRoot, 'hex'),
					toLocal: leaf(r.toLocal),
					toRemote: leaf(r.toRemote)
				},
				as
			).tx;
	rebuilt(
		view('remote', m.remoteRecovery),
		m.remoteCommitment,
		'rebuilt bytes'
	);
	rebuilt(
		view('local', m.localRecovery),
		unsigned(m.localCommitment),
		'rebuilt bytes'
	);
	verifyFundingSignature(m.localCommitment, ref);
	for (const pub of [...seed.peerNonces, ...seed.localNonces])
		validNonce(pub, 'nonce');
	if (new Set([...seed.peerNonces, ...seed.localNonces]).size !== 2)
		seedRefused('nonces');
	if (
		seed.digest !==
		finalAssetSeedDigest(channelId, ctx.candidate.isInitiator, input)
	)
		seedRefused('digest');
	verifyIds(seed, ctx);
	verifyReserves(
		ctx,
		ref,
		BigInt(m.localRecovery.localBalanceMsat),
		BigInt(m.localRecovery.remoteBalanceMsat)
	);
}

/** The `channel-type` records a storage holds; a storage double without the reader holds none. */
export function channelTypeRecordsOf(
	storage: object,
	id: string
): readonly IFinalChannelTypeRecord[] {
	const read = (
		storage as {
			loadFinalChannelTypeRecords?: (c: string) => IFinalChannelTypeRecord[];
		}
	).loadFinalChannelTypeRecords;
	return typeof read === 'function' ? read.call(storage, id) : [];
}
/** A channel's current kind, or the opening's when a storage double has no reader. */
export function currentKindOf(
	storage: object,
	id: string,
	opening: FinalChannelKind
): FinalChannelKind | null {
	const read = (
		storage as { loadFinalChannelKind?: (c: string) => FinalChannelKind | null }
	).loadFinalChannelKind;
	return typeof read === 'function' ? read.call(storage, id) : opening;
}
