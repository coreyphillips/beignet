/**
 * #2151 Step 4b (contract sections 1 to 13, V1 to V13, W1 to W7): the
 * readers, digests and phase drivers of the signing tests. The members the
 * step adds (the `conversion-dropped` event, `refuseRecordedRepair`'s new
 * arguments, the round's states) do not exist on the base, so each is
 * reached when a test runs, and a missing one fails that test with what the
 * contract expects instead of failing the file at load time.
 */
import { createHash, randomBytes } from 'crypto';
import { readdirSync, readFileSync, statSync } from 'fs';
import path from 'path';
import { expect } from 'chai';
import { Transaction } from 'bitcoinjs-lib';
import type Database from 'better-sqlite3';
import { encodeCommitmentSignedMessage } from '../../../src/lightning/message/channel-commitment';
import { MessageType } from '../../../src/lightning/message/types';
import { finalBranchReaders } from '../../../src/lightning/storage/final-branch-readers';
import type { SqliteStorage } from '../../../src/lightning/storage/sqlite-storage';
import type { FinalOpeningAuthority } from '../../../src/lightning/storage/final-opening-authority';
import {
	attemptEvents,
	attemptRowCount,
	conversionQuiet
} from './conversion-attempts';
import {
	abandoned,
	abortText,
	agreeOnTerms,
	attemptOf,
	customPayload,
	FENCE,
	frameOf,
	never,
	parseFrame,
	rawFrame,
	assetSpliceCustom,
	startConversion,
	stubAuthorization,
	stubConsent,
	stubExitEvidence,
	stubExitReceipt,
	stubExitShare,
	stubFinalize,
	track,
	updateRound,
	type IConversionPair,
	type IWireMessage
} from './conversion-managers';
import type {
	IConversionExitReceipt,
	IConversionFunding,
	IConversionHostExitViews
} from './conversion-modules';
import { method } from './conversion-modules';

const sha256 = (b: Buffer): Buffer => createHash('sha256').update(b).digest();

// ---------------------------------------------------------------------------
// Texts (section 11)
// ---------------------------------------------------------------------------

/** The fence before Step 4b, retired from src, docs and the tests (10.1). */
export const OLD_FENCE =
	'Asset conversion stops before its layout is signed in this build';

export const SIGNING_TEXTS = {
	consent: 'Asset conversion host could not consent',
	authorize: 'Asset conversion host could not authorize the assets',
	finalize: 'Asset conversion host could not finalize the funding',
	sign: 'Asset conversion host could not sign the exits',
	verify: 'Asset conversion host could not verify the exits',
	retain: 'Asset conversion host could not retain the exits',
	invalidConsent: 'Invalid asset conversion consent',
	premature: 'Premature asset conversion signing object',
	conflicting: 'Conflicting asset conversion signing object',
	frozen: 'Frozen asset conversion disagrees with the acknowledged layout',
	finalAck: 'Peers disagree on the final asset conversion funding',
	interactive:
		'Asset conversion interactive transaction differs from the agreed candidate',
	checkpoint:
		'Asset conversion peers disagree on the frozen transaction or signing nonces',
	evidence: 'Asset conversion exit evidence differs from the signed views',
	parentProofs:
		'Conversion parent holder proofs differ from the enrolled receipt',
	receipt: 'Host receipt differs from the signed asset conversion commitments',
	withdrawal: 'Conversion withdrawal receipt differs from the layout',
	dropped: 'Conversion exits were dropped',
	releasedDrop: 'Released conversion exits cannot be dropped'
} as const;

/** The reused texts (section 11). */
export const REUSED_TEXTS = {
	unexpected: 'Unexpected message during asset conversion',
	peerUpdated: 'Peer updated the channel during conversion quiescence',
	timedOut: 'Asset conversion timed out',
	prepare: 'Asset conversion host could not prepare the layout',
	frame: 'Invalid asset conversion layout frame',
	held: 'A conversion of this channel is in progress',
	otherAttempt: 'Another conversion of this channel is in progress',
	parameters: "Asset conversion channel parameters differ from the channel's",
	invalidExits: 'Invalid conversion exits',
	notRetained: 'Conversion exits were not retained',
	restore:
		'Restore of a channel with a pending type conversion is not supported yet',
	disconnected: 'Peer disconnected',
	closed: 'Asset conversion ended by a close',
	restart: 'Asset conversion ended by a restart',
	withdrawalFailed: 'Asset conversion withdrawal could not be recorded: '
} as const;

/** The envelope phases of subtype 98 the conversion signs with (section 5.4). */
export const SIGNING_PHASES = {
	authorization: 1,
	final: 2,
	exit: 3,
	finalAck: 5,
	checkpoint: 6
} as const;

/** The construction messages (section 5.2). */
export const CONSTRUCTION_NAMES = [
	'TX_ADD_INPUT',
	'TX_ADD_OUTPUT',
	'TX_REMOVE_INPUT',
	'TX_REMOVE_OUTPUT',
	'TX_COMPLETE'
] as const;
export const isConstruction = (m: IWireMessage): boolean =>
	(CONSTRUCTION_NAMES as readonly string[]).includes(m.name);

// ---------------------------------------------------------------------------
// The conversion scope (sections 7.2 to 7.5)
// ---------------------------------------------------------------------------

export const CONVERSION_SCOPE = 'conversion';

export type ConversionScopeEvent = { kind: string; digest: string } & Record<
	string,
	unknown
>;

function rawDb(store: SqliteStorage): Database.Database {
	return (store as unknown as { db: Database.Database }).db;
}

interface IJournal {
	read<T>(scope: string, id: string): { records: T[] };
	append(scope: string, id: string, head: unknown, event: unknown): void;
}
/** The store's own device journal (it decrypts and pulls in a device-ahead row). */
export function journalOf(store: SqliteStorage): IJournal {
	return (store as unknown as { finalJournal(): IJournal }).finalJournal();
}

/** The `conversion` scope's events for a channel, oldest first. */
export function conversionEvents(
	store: SqliteStorage,
	id: string
): ConversionScopeEvent[] {
	return journalOf(store).read<ConversionScopeEvent>(CONVERSION_SCOPE, id)
		.records;
}
export const conversionKinds = (store: SqliteStorage, id: string): string[] =>
	conversionEvents(store, id).map((e) => e.kind);

/** The wallet's rows of the scope, by plain SQL. */
export function conversionRowCount(store: SqliteStorage, id: string): number {
	return (
		rawDb(store)
			.prepare(
				'SELECT COUNT(*) AS n FROM final_lifecycle_log WHERE scope = ? AND channel_id = ?'
			)
			.get(CONVERSION_SCOPE, id) as { n: number }
	).n;
}

/** The scopes of a channel's lifecycle rows after rowid `since`, in insertion order. */
export function lifecycleScopes(
	store: SqliteStorage,
	id: string,
	since = 0
): string[] {
	return (
		rawDb(store)
			.prepare(
				'SELECT scope FROM final_lifecycle_log WHERE channel_id = ? AND rowid > ? ORDER BY rowid'
			)
			.all(id, since) as { scope: string }[]
	).map((r) => r.scope);
}
export function lastRowid(store: SqliteStorage): number {
	return (
		(
			rawDb(store)
				.prepare('SELECT MAX(rowid) AS n FROM final_lifecycle_log')
				.get() as { n: number | null }
		).n ?? 0
	);
}
/** Row counts by scope for a channel, every scope. */
export function scopeCounts(
	store: SqliteStorage,
	id: string
): Record<string, number> {
	const out: Record<string, number> = {};
	for (const r of rawDb(store)
		.prepare(
			'SELECT scope, COUNT(*) AS n FROM final_lifecycle_log WHERE channel_id = ? GROUP BY scope'
		)
		.all(id) as { scope: string; n: number }[])
		out[r.scope] = r.n;
	return out;
}

export type RetainedConversion = {
	digest: string;
	stateNumber: string;
	released: boolean;
	dropped?: boolean;
} & Record<string, unknown>;

/** The private `finalConversions(id)` (7.5: with `dropped` beside `released`). */
export function finalConversionsOf(
	store: SqliteStorage,
	id: string
): RetainedConversion[] {
	return method<[string], RetainedConversion[]>(
		store,
		'finalConversions',
		'SqliteStorage'
	)(id);
}
/** The private `pendingFinalConversions(id)`, the strict read (W6). */
export function pendingConversionsOf(
	store: SqliteStorage,
	id: string
): RetainedConversion[] {
	return method<[string], RetainedConversion[]>(
		store,
		'pendingFinalConversions',
		'SqliteStorage'
	)(id);
}
/** finalBranchReaders' `finalChannelFundings`, as the claim builders read it. */
export function fundingsOf(
	store: SqliteStorage,
	id: string
): { fundingTxid?: string; txid?: string; kind?: string }[] {
	return finalBranchReaders(store)!.finalChannelFundings(id) as unknown as {
		fundingTxid?: string;
		txid?: string;
	}[];
}
export const branchRowsOf = (store: SqliteStorage, id: string): number =>
	finalBranchReaders(store)!.finalBranchRows(id);

/**
 * `SqliteStorage.refuseRecordedRepair` with 7.4's arguments. The contract
 * names the two new ones (the wallet's journal key and identity) but not
 * their place; the tests take them after the channel id (tests-notes.md).
 */
export function refuseRepair(
	db: Database.Database,
	authority: FinalOpeningAuthority | null,
	id: string,
	store: SqliteStorage
): void {
	const s = store as unknown as {
		encryptionKey?: Buffer;
		walletIdentity?: string;
	};
	(
		store.constructor as unknown as {
			refuseRecordedRepair(
				db: Database.Database,
				authority: FinalOpeningAuthority | null,
				id: string,
				key?: Buffer,
				identity?: string
			): void;
		}
	).refuseRecordedRepair(db, authority, id, s.encryptionKey, s.walletIdentity);
}
export const walletDb = rawDb;

/** Append a planted event to the scope through the store's own journal. */
export function plantConversionEvent(
	store: SqliteStorage,
	id: string,
	event: Record<string, unknown>
): void {
	const journal = journalOf(store);
	journal.append(
		CONVERSION_SCOPE,
		id,
		journal.read(CONVERSION_SCOPE, id),
		event
	);
}

// ---------------------------------------------------------------------------
// Digests (sections 3.2 and 3.3), from the contract's formulas
// ---------------------------------------------------------------------------

export function finalDigestOf(f: {
	layoutDigest: Buffer;
	targetType: string;
	candidateHash: Buffer;
	fundingRoot?: Buffer;
	authorizations: readonly [Buffer, Buffer];
	proofDigest: Buffer;
}): Buffer {
	return sha256(
		Buffer.concat([
			Buffer.from('beignet/asset-conversion/final/v1\0', 'ascii'),
			f.layoutDigest,
			sha256(Buffer.from(f.targetType, 'hex')),
			f.candidateHash,
			f.fundingRoot ?? Buffer.alloc(32),
			sha256(f.authorizations[0]),
			sha256(f.authorizations[1]),
			f.proofDigest
		])
	);
}

export function checkpointDigestOf(
	finalDigest: Buffer,
	txHash: Buffer,
	nonces: readonly [Buffer, Buffer]
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

// ---------------------------------------------------------------------------
// What the hosts saw and returned
// ---------------------------------------------------------------------------

export interface ICapture {
	/** Each side's finalize answer. */
	fundings: [IConversionFunding?, IConversionFunding?];
	/** Each side's views at signConversionExits. */
	views: [IConversionHostExitViews?, IConversionHostExitViews?];
	/** Each side's retain answer. */
	receipts: [IConversionExitReceipt?, IConversionExitReceipt?];
	/** Each side's finalize arguments: both consents and both authorizations. */
	finalizeArgs: [
		{ consents: readonly Buffer[]; authorizations: readonly Buffer[] }?,
		{ consents: readonly Buffer[]; authorizations: readonly Buffer[] }?
	];
}

/** Wrap both hosts' finalize, sign and retain defaults to record what they saw. */
export function capture(p: IConversionPair): ICapture {
	const c: ICapture = {
		fundings: [],
		views: [],
		receipts: [],
		finalizeArgs: []
	} as unknown as ICapture;
	for (const i of [0, 1] as const) {
		const h = p.hosts[i];
		const finalize = h.finalize;
		h.finalize = (facts, consents, authorizations): unknown => {
			c.finalizeArgs[i] = { consents, authorizations };
			const out = finalize(facts, consents, authorizations);
			c.fundings[i] = out as IConversionFunding;
			return out;
		};
		const sign = h.signExits;
		h.signExits = (ctx, views): unknown => {
			c.views[i] = views;
			return sign(ctx, views);
		};
		const retain = h.retainExits;
		h.retainExits = (ctx, views, exact): unknown => {
			const out = retain(ctx, views, exact);
			c.receipts[i] = out as IConversionExitReceipt;
			return out;
		};
	}
	return c;
}

/** Reset every 4b answer of both hosts to the stub defaults. */
export function defaultSigning(p: IConversionPair): void {
	for (const i of [0, 1] as const) {
		const h = p.hosts[i];
		h.prepare = (ctx, proposals, bitcoin, layoutDigest): unknown =>
			h.planFor(ctx, proposals, bitcoin, layoutDigest);
		h.consent = (ctx): unknown => stubConsent(ctx);
		h.authorize = (ctx, consents): unknown => stubAuthorization(ctx, consents);
		h.finalize = (facts): unknown => stubFinalize(facts);
		h.signExits = (ctx, views): unknown => stubExitShare(ctx, views);
		h.verifyExits = (ctx, views): unknown => stubExitEvidence(h, ctx, views);
		h.retainExits = (ctx, views, exact): unknown =>
			stubExitReceipt(h, ctx, views, exact);
	}
}

// ---------------------------------------------------------------------------
// Gates and phases (section 13)
// ---------------------------------------------------------------------------

/** A host answer held until `open()`; `never` keeps it pending for good. */
export interface IGate {
	wait: Promise<void>;
	open(): void;
	opened: boolean;
}
export function gate(): IGate {
	let open!: () => void;
	const g: IGate = {
		wait: new Promise<void>((done) => (open = done)),
		open: () => {
			g.opened = true;
			open();
		},
		opened: false
	};
	return g;
}

export type Phase = 'P1' | 'P2' | 'P3' | 'P4' | 'P5' | 'P6' | 'P7a' | 'P7b';
export const PHASES: readonly Phase[] = [
	'P1',
	'P2',
	'P3',
	'P4',
	'P5',
	'P6',
	'P7a',
	'P7b'
];
/** The states each phase leaves side I and side A in (sections 5.1 and 13). */
export const PHASE_STATES: Record<Phase, [string, string]> = {
	P1: ['agreed', 'agreed'],
	P2: ['agreed', 'agreed'],
	P3: ['agreed', 'agreed'],
	P4: ['constructing', 'constructing'],
	P5: ['securing', 'securing'],
	P6: ['securing', 'securing'],
	P7a: ['securing', 'securing'],
	P7b: ['aborting', 'secured']
};

export interface IAtPhase {
	I: 0 | 1;
	A: 0 | 1;
	phase: Phase;
	start: ReturnType<typeof track>;
	/** Open the gates and release what the link holds, then settle. */
	release(): Promise<void>;
	/** The gates the phase holds a host call on (P1, P2, P7a). */
	gates: IGate[];
}

/**
 * Side `I` starts a conversion and both sides stop at `phase`:
 * - P1: both hosts' consent waits on a gate;
 * - P2: both consents are exchanged and both authorize calls wait;
 * - P3: both final_ack frames wait on the link;
 * - P4: the acceptor's construction messages wait on the link;
 * - P5: both exit share frames wait on the link;
 * - P6: both candidate commitment_signed messages wait on the link;
 * - P7a: both retainConversionExits calls wait;
 * - P7b: the initiator's fence waits on the link (the acceptor is secured).
 * Then the test checks that both attempts are in the phase's states.
 */
export async function toPhase(
	p: IConversionPair,
	phase: Phase,
	I: 0 | 1 = 0,
	reference = Buffer.alloc(8, 0x4c)
): Promise<IAtPhase> {
	const A = (1 - I) as 0 | 1;
	const gates: IGate[] = [];
	const hang = <T>(run: () => T): (() => Promise<T>) => {
		const g = gate();
		gates.push(g);
		return () => g.wait.then(run);
	};
	if (phase === 'P1')
		for (const h of p.hosts) {
			const later = hang(() => undefined);
			const consent = h.consent;
			h.consent = (ctx): unknown => later().then(() => consent(ctx));
		}
	if (phase === 'P2')
		for (const h of p.hosts) {
			const later = hang(() => undefined);
			const authorize = h.authorize;
			h.authorize = (ctx, consents): unknown =>
				later().then(() => authorize(ctx, consents));
		}
	if (phase === 'P7a')
		for (const h of p.hosts) {
			const later = hang(() => undefined);
			const retain = h.retainExits;
			h.retainExits = (ctx, views, exact): unknown =>
				later().then(() => retain(ctx, views, exact));
		}
	if (phase === 'P3') p.link.hold('asset_splice:5');
	if (phase === 'P4') p.link.hold((m) => m.from === A && isConstruction(m));
	if (phase === 'P5') p.link.hold('asset_splice:3');
	if (phase === 'P6') p.link.hold('COMMITMENT_SIGNED');
	if (phase === 'P7b') p.link.hold({ from: I, name: 'TX_ABORT' });
	agreeOnTerms(p);
	const start = track(
		startConversion(p.managers[I], p.channelId, { reference })
	);
	await p.settle();
	expect(
		[I, A].map((i) => {
			const a = attemptOf(p.managers[i], p.id);
			return a && !a.ended ? a.state : 'ended';
		}),
		'reached ' + phase + ' (initiator, acceptor)'
	).to.deep.equal(PHASE_STATES[phase]);
	return {
		I,
		A,
		phase,
		start,
		gates,
		async release(): Promise<void> {
			for (const g of gates) g.open();
			p.link.clearRules();
			p.link.release();
			await p.settle();
		}
	};
}

/** Every 4b host gate of a phase answers now (a late answer after the end). */
export async function lateAnswers(
	p: IConversionPair,
	at: IAtPhase
): Promise<void> {
	for (const g of at.gates) g.open();
	await p.settle();
}

/** The sides that hold `conversion-exits` at a phase: only at P7b, both. */
export const retainedAt = (phase: Phase): boolean => phase === 'P7b';

/**
 * Side i ended its attempt through 4a's paths, which drop first (7.3): since
 * `base` its attempt scope reads a record and its withdrawal, its conversion
 * scope reads `conversion-exits` then `conversion-dropped` when it retained
 * and nothing otherwise, the drop is on disk before the withdrawal, quiet
 * reads false and the host was told once.
 */
export function expectEnded(
	p: IConversionPair,
	i: 0 | 1,
	base: { attempts: number[]; conversions: number[]; rowid: number[] },
	retained: boolean,
	reason?: string
): void {
	const store = p.stores[i];
	const kinds = attemptEvents(store, p.id)
		.slice(base.attempts[i])
		.map((e) => e.kind);
	expect(kinds, 'side ' + i + ' attempt scope').to.deep.equal([
		'conversion-attempt',
		'conversion-withdrawn'
	]);
	expect(
		conversionKinds(store, p.id).slice(base.conversions[i]),
		'side ' + i + ' conversion scope'
	).to.deep.equal(retained ? ['conversion-exits', 'conversion-dropped'] : []);
	const scopes = lifecycleScopes(store, p.id, base.rowid[i]).filter(
		(s) => s === 'conversion' || s === 'conversion-attempt'
	);
	expect(scopes, 'side ' + i + ' row order').to.deep.equal(
		retained
			? ['conversion-attempt', 'conversion', 'conversion', 'conversion-attempt']
			: ['conversion-attempt', 'conversion-attempt']
	);
	expect(conversionQuiet(p.managers[i], p.id), 'side ' + i + ' quiet').to.equal(
		false
	);
	const told = abandoned(p, i);
	expect(told, 'side ' + i + ' abandon once').to.have.length(1);
	if (reason !== undefined)
		expect(told[0], 'side ' + i + ' reason').to.equal(reason);
}

/** Row marks before an attempt. */
export function marks(p: IConversionPair): {
	attempts: number[];
	conversions: number[];
	rowid: number[];
} {
	return {
		attempts: p.stores.map((st) => attemptEvents(st, p.id).length),
		conversions: p.stores.map((st) => conversionEvents(st, p.id).length),
		rowid: p.stores.map(lastRowid)
	};
}

/** Rows of every scope of both sides, for "a late answer writes nothing". */
export const allRows = (p: IConversionPair): number[][] =>
	p.stores.map((st) => [
		attemptRowCount(st, p.id),
		conversionRowCount(st, p.id),
		lastRowid(st)
	]);

/**
 * After a reconnect the channel is at its parent, unchanged, and a payment
 * works. A payment here is an update round on the parent (a fee update on a
 * plain parent, an asset fee round on an asset parent), as 4a's tests run.
 */
export async function expectParentWorks(
	p: IConversionPair,
	parent: unknown[]
): Promise<void> {
	await p.reconnect();
	for (const i of [0, 1] as const)
		expect(p.stores[i].loadFinalChannelType(p.id), 'parent ' + i).to.deep.equal(
			parent[i]
		);
	await updateRound(p);
}

// ---------------------------------------------------------------------------
// Wire
// ---------------------------------------------------------------------------

/** The fence and echo texts side `from` sent since `mark`. */
export const abortsFrom = (
	p: IConversionPair,
	from: 0 | 1,
	mark = 0
): string[] =>
	p.link.sent
		.slice(mark)
		.filter((m) => m.from === from && m.name === 'TX_ABORT')
		.map(abortText);

/** The candidate's txid in internal byte order, from a side's finalize answer. */
export function candidateHash(funding: IConversionFunding): Buffer {
	return Transaction.fromBuffer(funding.transaction).getHash();
}

/** A candidate commitment_signed naming `fundingTxid` (internal order), signed by nobody. */
export function forgedCommitmentSigned(
	channelId: Buffer,
	fundingTxid: Buffer
): Buffer {
	return encodeCommitmentSignedMessage({
		channelId,
		signature: Buffer.alloc(64),
		htlcSignatures: [],
		fundingTxid,
		partialSignatureWithNonce: randomBytes(98)
	} as never);
}

/** A subtype 98 frame with one bit of its digest flipped. */
export function flipFrameDigest(m: IWireMessage): Buffer {
	const f = parseFrame(customPayload(m.payload).frame);
	const digest = Buffer.from(f.digest);
	digest[0] ^= 1;
	return assetSpliceCustom(rawFrame({ ...f, digest }));
}

/** The digest field of the frames of a phase that side `from` sent. */
export function frameDigests(
	p: IConversionPair,
	from: 0 | 1,
	name: string,
	mark = 0
): Buffer[] {
	return p.link.sent
		.slice(mark)
		.filter((m) => m.from === from && m.name === name)
		.map((m) => frameOf(m).digest);
}

/** Every file under `dir` whose text contains `needle`. */
export function filesContaining(dir: string, needle: string): string[] {
	const out: string[] = [];
	const walk = (d: string): void => {
		for (const name of readdirSync(d)) {
			const f = path.join(d, name);
			if (statSync(f).isDirectory()) walk(f);
			else if (readFileSync(f, 'utf8').includes(needle)) out.push(f);
		}
	};
	walk(dir);
	return out;
}

export const SRC_DIR = path.join(__dirname, '..', '..', '..', 'src');
export const REPO_DIR = path.join(__dirname, '..', '..', '..');

/** A host call that never answers (the 15 s host bound ends it). */
export const neverAnswers = (): Promise<never> => never<never>();

/** The fence both sides send since Step 4b. */
export const NEW_FENCE = FENCE;

/** The ids of the wire's TX messages, for A24. */
export const FUNDING_SIGNATURE_NAMES = ['TX_SIGNATURES', 'SPLICE_LOCKED'];

export { MessageType, sha256 };
