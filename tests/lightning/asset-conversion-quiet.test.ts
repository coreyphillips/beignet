/**
 * #2151 Step 4a, contract section 8, the quiet file: from its `layout_ack`,
 * a side's conversion attempt is on disk in the device-journal scope
 * `conversion-attempt` and the channel is quiet, until the side withdraws
 * the attempt (sections 2 to 4 and amendments A1 and A3 to A9).
 *
 * Most tests hold both `layout_ack` frames on the link, so both sides stay
 * past their own `layout_ack` and quiet lasts until the test releases them
 * (the fence) or ends the attempt another way. Messages whose order matters
 * are handed to the managers' frame handlers directly.
 */
import { expect } from 'chai';
import { createHash } from 'crypto';
import path from 'path';
import sinon from 'sinon';
import type Database from 'better-sqlite3';
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import { encodeUpdateAddHtlcMessage } from '../../src/lightning/message/channel-update';
import { BeignetCustomSubtype } from '../../src/lightning/message/custom';
import { encodeTxAbortMessage } from '../../src/lightning/message/interactive-tx';
import { MessageType } from '../../src/lightning/message/types';
import { finalBranchReaders } from '../../src/lightning/storage/final-branch-readers';
import { FinalDeviceJournal } from '../../src/lightning/storage/final-device-journal';
import { FinalOpeningAuthority } from '../../src/lightning/storage/final-opening-authority';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { plainTypePair, scratch } from './helpers/channel-type-pairs';
import { deviceAuthority } from './helpers/channel-type-record';
import { generateFinalGeneration } from './helpers/final-generation';
import {
	ATTEMPT_SCOPE,
	ATTEMPT_TEXTS,
	attemptEvents,
	attemptRowCount,
	attemptStorage,
	canonicalConversionReason,
	conversionQuiet,
	expectedReason,
	type ConversionAttemptEvent,
	type IConversionAttemptFields
} from './helpers/conversion-attempts';
import {
	abandoned,
	abortText,
	agreementDigestOf,
	allocatedKeyIndex,
	conversionPair,
	conversionTransportOf,
	FENCE,
	held,
	PAIR_HEIGHT,
	parentHeight,
	readReply,
	roleOf,
	settleOnce,
	sharedPair,
	startConversion,
	storeTerms,
	stubConversionDescription,
	stubProposal,
	termsIdentity,
	track,
	updateRound,
	type ICrashOptions,
	type IConversionPair,
	type IWireMessage
} from './helpers/conversion-managers';

const REF = Buffer.alloc(8, 0x4b);
/** ASSET_CONVERSION_TEXTS.held. */
const HELD = 'A conversion of this channel is in progress';
const OTHER_ATTEMPT = 'Another conversion of this channel is in progress';
const PEER_UPDATED = 'Peer updated the channel during conversion quiescence';
const DISCONNECTED = 'Peer disconnected';
const CLOSED = 'Asset conversion ended by a close';
const {
	topLevel: TOP_LEVEL,
	wallet: WALLET,
	notRecorded: NOT_RECORDED,
	withdrawalFailed: WITHDRAWAL_FAILED,
	restart: RESTART,
	invalid: INVALID
} = ATTEMPT_TEXTS;
const SCRIPT = Buffer.from('0014' + '22'.repeat(20), 'hex');

const sha256 = (b: Buffer): Buffer => createHash('sha256').update(b).digest();
const hex = (b: Buffer): string => b.toString('hex');
type AttemptRecord = ConversionAttemptEvent & { kind: 'conversion-attempt' };

/** Both hosts take terms from their own store for whichever channel they are asked about. */
function agree(p: IConversionPair): void {
	for (const i of [0, 1] as const)
		p.hosts[i].terms = (ctx, request): ReturnType<typeof storeTerms> =>
			storeTerms(p.stores[i], ctx.channelId, { reference: request.reference });
}

/** Undo what a test changed on a shared pair's hosts and records. */
function clean(p: IConversionPair): void {
	p.link.clearRules();
	p.link.held.splice(0);
	p.link.taps.splice(0);
	p.hostLog.splice(0);
	for (const i of [0, 1] as const) {
		p.errors[i].splice(0);
		p.recycled[i].splice(0);
		const h = p.hosts[i];
		h.verify = (): unknown => true;
		h.abandon = (): unknown => undefined;
		h.propose = (): unknown => stubProposal(i);
		h.describe = (ctx, _proposals, bitcoin): unknown =>
			stubConversionDescription(ctx, h.termsFor(ctx), bitcoin);
		h.prepare = (_ctx, _proposals, _bitcoin, layoutDigest): unknown => ({
			digest: sha256(layoutDigest)
		});
		p.feerateEstimates[i] = async (): Promise<number> => 1000;
	}
	agree(p);
}

/** End whatever a test left live: both sides disconnect and reconnect. */
async function reset(p: IConversionPair): Promise<void> {
	p.link.clearRules();
	p.link.held.splice(0);
	p.link.taps.splice(0);
	p.disconnect();
	await p.reconnect();
}

/** Side `I` starts a conversion of `channelId` and the link runs until idle. */
async function run(
	p: IConversionPair,
	I: 0 | 1 = 0,
	channelId = p.channelId
): Promise<ReturnType<typeof track>> {
	agree(p);
	const start = track(
		startConversion(p.managers[I], channelId, { reference: REF })
	);
	await p.settle();
	await start.done;
	return start;
}

/**
 * Side `I` starts and both sides pass their own layout_ack, which wait on
 * the link: from here both are quiet until `fence` releases the frames.
 */
async function toQuiet(
	p: IConversionPair,
	I: 0 | 1 = 0,
	channelId = p.channelId
): Promise<void> {
	const before = p.link.held.length;
	p.link.hold('asset_splice:4');
	const start = await run(p, I, channelId);
	expect(start.error, 'start').to.equal(undefined);
	expect(
		p.link.held
			.slice(before)
			.map((m) => m.from + ':' + m.name)
			.sort(),
		'both layout_acks wait on the link'
	).to.deep.equal(['0:asset_splice:4', '1:asset_splice:4']);
}

/** Release the layout_acks: I compares them and sends the fence's tx_abort. */
async function fence(p: IConversionPair): Promise<void> {
	p.link.clearRules();
	p.link.release();
	await p.settle();
}

/** Each side's quiet flag. */
const quiet = (p: IConversionPair, id = p.id): boolean[] =>
	p.managers.map((m) => conversionQuiet(m, id));
/** The texts of the tx_abort messages side `from` put on the link since `mark`. */
const abortsFrom = (p: IConversionPair, from: 0 | 1, mark = 0): string[] =>
	p.link.sent
		.slice(mark)
		.filter((m) => m.from === from && m.name === 'TX_ABORT')
		.map(abortText);
const sentNames = (p: IConversionPair, from: 0 | 1, mark = 0): string[] =>
	p.link.sent
		.slice(mark)
		.filter((m) => m.from === from)
		.map((m) => m.name);
/** The scope's events of side i's store since row `from`. */
const eventsSince = (
	p: IConversionPair,
	i: 0 | 1,
	from: number,
	id = p.id
): ConversionAttemptEvent[] => attemptEvents(p.stores[i], id).slice(from);
const rowsOf = (p: IConversionPair, id = p.id): number[] =>
	p.stores.map((st) => attemptRowCount(st, id));

/** The parent as the snapshot names it (IAssetConversionContext.parent). */
function parentOf(
	store: SqliteStorage,
	id: string
): IConversionAttemptFields['parent'] {
	const current = store.loadFinalChannelType(id)!;
	return {
		txid: current.funding.txid,
		outputIndex: current.funding.outputIndex,
		stateNumber: parentHeight(store, id, current.type).toString(),
		type: current.type,
		channelType: current.channelType
	};
}

/** A valid attempt record for direct writes on `store`'s channel `id`. */
function sampleRecord(
	store: SqliteStorage,
	id: string,
	peer: string,
	attempt = 'a1'.repeat(32)
): IConversionAttemptFields {
	const parent = parentOf(store, id);
	return {
		attempt,
		peer,
		isInitiator: true,
		isOpener: roleOf(store, id) === 'opener',
		giver: 'opener',
		direction: parent.type === 'plain' ? 'to-asset' : 'to-plain',
		parent,
		termsDigest: 'b2'.repeat(32),
		layoutDigest: 'c3'.repeat(32),
		planDigest: 'd4'.repeat(32),
		agreement: 'e5'.repeat(32),
		keyIndex: 7
	};
}

/** Make side i's device commits of the scope throw, `times` times (Infinity: always). */
function failCommits(
	p: IConversionPair,
	i: 0 | 1,
	how: 'before-commit' | 'after-commit',
	times = 1
): { failures: () => number } {
	const authority = deviceAuthority(p.stores[i]);
	const commit = authority.commitLifecycleEntry.bind(authority);
	let failed = 0;
	sinon
		.stub(authority, 'commitLifecycleEntry')
		.callsFake((slot: string, value: string) => {
			const fail = slot.startsWith('conversion-attempt/') && failed < times;
			if (fail && how === 'before-commit') {
				failed++;
				throw new Error('device commit failed');
			}
			commit(slot, value);
			if (fail) {
				failed++;
				throw new Error('wallet insert failed');
			}
		});
	return { failures: () => failed };
}

/** Side i's transport no longer reports the in-memory hold, so only quiet can refuse. */
function maskHeld(p: IConversionPair): void {
	for (const m of p.managers)
		(
			conversionTransportOf(m) as unknown as { held(id: string): boolean }
		).held = (): boolean => false;
}

/** The refusal text of a local start, 'accepted', or a note that it never answered. */
async function refusal(start: () => unknown): Promise<string> {
	let timer: ReturnType<typeof setTimeout> | undefined;
	try {
		const out = await Promise.race([
			Promise.resolve().then(start),
			new Promise((done) => {
				timer = setTimeout(
					() => done({ ok: false, error: 'no answer within 2 s' }),
					2000
				);
			})
		]);
		const r = out as { ok?: boolean; error?: string } | undefined;
		return r && r.ok === false ? String(r.error) : 'accepted';
	} catch (e) {
		return (e as Error).message;
	} finally {
		if (timer) clearTimeout(timer);
	}
}

const addHtlc = (p: IConversionPair, id = 0n): Buffer =>
	encodeUpdateAddHtlcMessage({
		channelId: p.channelId,
		id,
		amountMsat: 1_000_000n,
		paymentHash: sha256(Buffer.alloc(32, 0x45)),
		cltvExpiry: PAIR_HEIGHT + 100,
		onionRoutingPacket: Buffer.alloc(1366)
	});
const SPLICE_PLAN = {
	localDelta: '-10000',
	feeBudget: '2000',
	feerate: 1000,
	locktime: PAIR_HEIGHT,
	inputs: [],
	outputs: []
};
type FinalSplicePlan = Parameters<ChannelManager['startFinalSplice']>[1];

/**
 * Hand a peer update of the pair's kind to side 0's frame handler and
 * record side 0's scope rows at the moment it is delivered on (the final
 * transport's queue, or the asset update transport). The update is taken
 * there and not applied, so the shared channel stays as it was.
 */
function deliverPeerUpdate(p: IConversionPair): number[] {
	const seen: number[] = [];
	const m = p.managers[0] as unknown as {
		finalTransport: { queue(peer: string, id: string, msg: unknown): void };
		assetUpdates: { custom(peer: string, raw: Buffer): void };
	};
	if (p.kind === 'plain') {
		sinon
			.stub(m.finalTransport, 'queue')
			.callsFake((_peer: string, _id: string, msg: unknown) => {
				if ((msg as { type: number }).type === MessageType.UPDATE_ADD_HTLC)
					seen.push(attemptRowCount(p.stores[0], p.id));
			});
		p.managers[0].handleMessage(
			p.nodeIds[1],
			MessageType.UPDATE_ADD_HTLC,
			addHtlc(p)
		);
	} else {
		sinon.stub(m.assetUpdates, 'custom').callsFake(() => {
			seen.push(attemptRowCount(p.stores[0], p.id));
		});
		p.managers[0].handleAssetOpenFrame(
			p.nodeIds[1],
			BeignetCustomSubtype.ASSET_UPDATE,
			Buffer.concat([p.channelId, Buffer.alloc(8), Buffer.from([1, 0])])
		);
	}
	return seen;
}

describe('Asset conversion quiet from layout_ack (#2151 step 4a, section 8 quiet file)', function () {
	this.timeout(180000);
	const s = scratch('conversion-quiet-');
	const used = new Set<'plain' | 'asset'>();
	const sharedPairs = {
		plain: sharedPair(s, 'plain'),
		asset: sharedPair(s, 'asset')
	};
	/** A shared pair, reset after the test that took it. */
	const shared = (kind: 'plain' | 'asset'): Promise<IConversionPair> => {
		used.add(kind);
		return sharedPairs[kind]().then((p) => {
			clean(p);
			return p;
		});
	};
	/** A pair of its own, for a test that leaves its channel changed. */
	const fresh = async (
		kind: 'plain' | 'asset' = 'plain',
		options?: Parameters<typeof conversionPair>[2]
	): Promise<IConversionPair> => {
		const p = await conversionPair(s, kind, options);
		clean(p);
		return p;
	};
	afterEach(async () => {
		sinon.restore();
		for (const kind of [...used]) await reset(await sharedPairs[kind]());
		used.clear();
	});
	after(() => s.release());

	describe('Records (test 1)', () => {
		for (const [kind, I] of [
			['plain', 0],
			['asset', 1]
		] as const)
			it(`writes one attempt record before each layout_ack and one withdrawal before each tx_abort at the fence (${kind}, side ${I} initiating)`, async () => {
				const p = await shared(kind);
				const A = (1 - I) as 0 | 1;
				const base = rowsOf(p);
				const parent = p.stores.map((st) => parentOf(st, p.id));
				// The sender's new rows at the moment each frame goes on the link.
				const at: Record<string, number[]> = {};
				p.link.taps.push((m: IWireMessage) => {
					if (m.name === 'asset_splice:4' || m.name === 'TX_ABORT')
						(at[m.from + ':' + m.name] ??= []).push(
							attemptRowCount(p.stores[m.from], p.id) - base[m.from]
						);
				});
				const start = await run(p, I);
				expect(start.error, 'start').to.equal(undefined);
				expect(abandoned(p, 0), 'the fence').to.deep.equal([FENCE]);
				expect(at, 'rows when each frame left').to.deep.equal({
					[`${I}:asset_splice:4`]: [1],
					[`${A}:asset_splice:4`]: [1],
					[`${I}:TX_ABORT`]: [2],
					[`${A}:TX_ABORT`]: [2]
				});
				const terms = storeTerms(p.stores[I], p.id, { reference: REF });
				const id = termsIdentity(terms, undefined, roleOf(p.stores[I], p.id));
				for (const i of [0, 1] as const) {
					const prepare = p.hostLog.find(
						(c) => c.side === i && c.name === 'prepareConversion'
					)!;
					const layoutDigest = prepare.args[3] as Buffer;
					const planDigest = sha256(layoutDigest);
					expect(eventsSince(p, i, base[i]), 'side ' + i).to.deep.equal([
						{
							kind: 'conversion-attempt',
							attempt: hex(id.attempt),
							peer: p.nodeIds[1 - i],
							isInitiator: i === I,
							isOpener: roleOf(p.stores[i], p.id) === 'opener',
							giver: 'opener',
							direction: kind === 'plain' ? 'to-asset' : 'to-plain',
							parent: parent[i],
							termsDigest: hex(id.digest),
							layoutDigest: hex(layoutDigest),
							planDigest: hex(planDigest),
							agreement: hex(agreementDigestOf(layoutDigest, planDigest)),
							keyIndex: allocatedKeyIndex(p.stores[i])
						},
						{
							kind: 'conversion-withdrawn',
							attempt: hex(id.attempt),
							reason: FENCE
						}
					]);
					const storage = attemptStorage(p.stores[i]);
					expect(storage.conversionAttemptOpen(p.id), 'open').to.equal(false);
					expect(storage.openConversionAttempt(p.id), 'open record').to.equal(
						null
					);
				}
			});

		it('reads the open record while both layout_acks wait (plain)', async () => {
			const p = await shared('plain');
			const base = rowsOf(p);
			await toQuiet(p, 0);
			for (const i of [0, 1] as const) {
				const [record] = eventsSince(p, i, base[i]) as AttemptRecord[];
				const storage = attemptStorage(p.stores[i]);
				expect(storage.conversionAttemptOpen(p.id), 'open ' + i).to.equal(true);
				expect(storage.openConversionAttempt(p.id)?.attempt).to.equal(
					record.attempt
				);
			}
			await fence(p);
		});
	});

	describe('Quiet, local (test 2, A7 and A9)', () => {
		it('refuses every plain local update and a plain splice start from the quiet check, before staging', async () => {
			const p = await fresh('plain');
			await toQuiet(p, 0);
			maskHeld(p);
			expect(quiet(p), 'quiet').to.deep.equal([true, true]);
			const out: Record<string, string> = {};
			const staged: string[] = [];
			for (const i of [0, 1] as const) {
				const m = p.managers[i];
				const store = p.stores[i];
				const stage = store.stageFinalHtlcUpdate.bind(store);
				sinon
					.stub(store, 'stageFinalHtlcUpdate')
					.callsFake((...args: Parameters<typeof stage>) => {
						if (args[1] === 'local') staged.push(i + ':' + args[2]);
						return stage(...args);
					});
				out[i + ' add'] = await refusal(() =>
					m.addHtlc(
						p.channelId,
						1_000_000n,
						sha256(Buffer.alloc(32, 8)),
						PAIR_HEIGHT + 100,
						Buffer.alloc(1366)
					)
				);
				if (i === p.opener)
					out[i + ' fee'] = await refusal(() =>
						m.updateChannelFee(p.channelId, 555)
					);
				// No HTLC exists during quiet: an unknown id reaches the check.
				out[i + ' fulfil'] = await refusal(() =>
					m.fulfillHtlc(p.channelId, 99n, Buffer.alloc(32, 9))
				);
				out[i + ' fail'] = await refusal(() =>
					m.failHtlc(p.channelId, 99n, Buffer.alloc(32))
				);
				out[i + ' splice'] = await refusal(() =>
					m.startFinalSplice(
						p.channelId,
						SPLICE_PLAN as unknown as FinalSplicePlan
					)
				);
			}
			expect(out).to.deep.equal(
				Object.fromEntries(Object.keys(out).map((k) => [k, HELD]))
			);
			expect(staged, 'nothing staged').to.deep.equal([]);
		});

		it('refuses every asset change kind and an asset splice start from the quiet check, and the refused splice start never enters the splice queue (S7)', async () => {
			const p = await fresh('asset');
			await toQuiet(p, 0);
			maskHeld(p);
			expect(quiet(p), 'quiet').to.deep.equal([true, true]);
			const out: Record<string, string> = {};
			const queue: Record<string, unknown> = {};
			for (const i of [0, 1] as const) {
				const m = p.managers[i];
				const mark = p.link.sent.length;
				out[i + ' add'] = await refusal(() =>
					m.startAssetSpliceUpdate(p.channelId, [
						{
							kind: 'add',
							htlc: {
								id: 0n,
								offeredBy: 'local',
								amountMsat: 1_000_000n,
								paymentHash: sha256(Buffer.alloc(32, 8)),
								cltvExpiry: PAIR_HEIGHT + 100,
								allocations: []
							}
						}
					])
				);
				if (i === p.opener)
					out[i + ' fee'] = await refusal(() =>
						m.startAssetSpliceUpdate(p.channelId, [
							{ kind: 'fee', feeratePerKw: 1555 }
						])
					);
				out[i + ' fulfill'] = await refusal(() =>
					m.startAssetSpliceUpdate(p.channelId, [
						{
							kind: 'fulfill',
							offeredBy: 'peer',
							id: 99n,
							preimage: Buffer.alloc(32, 9)
						}
					])
				);
				out[i + ' fail'] = await refusal(() =>
					m.startAssetSpliceUpdate(p.channelId, [
						{
							kind: 'fail',
							offeredBy: 'peer',
							id: 99n,
							reason: Buffer.alloc(32)
						}
					])
				);
				const splice = (
					m as unknown as {
						assetSplice: {
							negotiating(id: string): boolean;
							enqueue(...args: unknown[]): unknown;
						};
					}
				).assetSplice;
				const enqueue = sinon.spy(splice, 'enqueue');
				const started = m.startAssetSplice(p.channelId, {
					fundingFeeratePerkw: 1000,
					minimumDepth: 3
				});
				queue[i + ' negotiating at once'] = splice.negotiating(p.id);
				out[i + ' splice'] = await refusal(() => started);
				queue[i + ' enqueued'] = enqueue.callCount;
				queue[i + ' asset updates sent'] = sentNames(p, i, mark).filter(
					(n) => n === 'asset_update'
				).length;
			}
			expect(out).to.deep.equal(
				Object.fromEntries(Object.keys(out).map((k) => [k, HELD]))
			);
			expect(queue).to.deep.equal({
				'0 negotiating at once': false,
				'0 enqueued': 0,
				'0 asset updates sent': 0,
				'1 negotiating at once': false,
				'1 enqueued': 0,
				'1 asset updates sent': 0
			});
		});

		it(`refuses a second conversion start during a live attempt with "${HELD}" on both sides (control, green on the base)`, async () => {
			const p = await shared('plain');
			await toQuiet(p, 0);
			for (const i of [0, 1] as const) {
				const again = track(
					startConversion(p.managers[i], p.channelId, { reference: REF })
				);
				await again.done;
				expect(again.error, 'side ' + i).to.equal(HELD);
			}
			await fence(p);
			expect(abandoned(p, 0)).to.deep.equal([FENCE]);
		});

		it(`refuses a new conversion with "${OTHER_ATTEMPT}" while a record stays open after a crash, both its own start and the peer's terms (A7)`, async () => {
			const p = await fresh('plain');
			const base = rowsOf(p);
			await toQuiet(p, 0);
			expect(rowsOf(p)[0] - base[0], 'recorded').to.equal(1);
			// Every write of the scope on side 0 fails: the sweep cannot withdraw.
			failCommits(p, 0, 'before-commit', Infinity);
			p.crash(0);
			await settleOnce();
			expect(rowsOf(p)[0] - base[0], 'still open after the sweep').to.equal(1);
			await p.reconnect();
			const own = track(
				startConversion(p.managers[0], p.channelId, { reference: REF })
			);
			await p.settle();
			await own.done;
			expect(own.error, 'its own start').to.equal(OTHER_ATTEMPT);
			const mark = p.link.sent.length;
			const peer = await run(p, 1);
			expect(peer.error, "the peer's start sent its terms").to.equal(undefined);
			const reply = p.link.sent
				.slice(mark)
				.find((m) => m.from === 0 && m.name === 'conversion_reply');
			expect(reply && readReply(reply), "the peer's terms").to.deep.include({
				accept: false,
				reason: OTHER_ATTEMPT
			});
			expect(abandoned(p, 1).slice(-1)).to.deep.equal([OTHER_ATTEMPT]);
		});
	});

	describe('Quiet ends at the withdrawal (test 3)', () => {
		it('ends quiet on both sides at the fence, after which a payment and a plain splice go through (plain)', async () => {
			const p = await fresh('plain');
			await toQuiet(p, 0);
			expect(quiet(p), 'quiet').to.deep.equal([true, true]);
			await fence(p);
			expect(abandoned(p, 0)).to.deep.equal([FENCE]);
			expect(quiet(p), 'after the withdrawal').to.deep.equal([false, false]);
			const preimage = Buffer.alloc(32, 0x71);
			const add = p.managers[0].addHtlc(
				p.channelId,
				1_000_000n,
				sha256(preimage),
				PAIR_HEIGHT + 100,
				Buffer.alloc(1366)
			);
			expect(add.ok, add.error).to.equal(true);
			await p.settle();
			// Booleans, not the HTLC: a parallel worker cannot send its BigInts.
			const received = (): boolean =>
				p.managers[1].finalReceivedHtlc(p.channelId, 0n) !== undefined;
			expect(received(), 'the payment arrived').to.equal(true);
			const fulfil = p.managers[1].fulfillHtlc(p.channelId, 0n, preimage);
			expect(fulfil.ok, fulfil.error).to.equal(true);
			await p.settle();
			expect(received(), 'the payment settled').to.equal(false);
			const mark = p.link.sent.length;
			p.managers[0].startFinalSplice(
				p.channelId,
				SPLICE_PLAN as unknown as FinalSplicePlan
			);
			await p.settle();
			expect(sentNames(p, 0, mark), 'the splice started').to.include('STFU');
		});

		it('ends quiet on both sides at the fence, after which an update round goes through (asset)', async () => {
			const p = await shared('asset');
			await toQuiet(p, 1);
			expect(quiet(p), 'quiet').to.deep.equal([true, true]);
			await fence(p);
			expect(quiet(p), 'after the withdrawal').to.deep.equal([false, false]);
			await updateRound(p);
		});
	});

	describe('Two consecutive attempts with identical terms (test 4, M4 and A1)', () => {
		it('records both in order, attempt, withdrawal, attempt, withdrawal, and quiet ends after each', async () => {
			const p = await shared('plain');
			const base = rowsOf(p);
			for (const round of [1, 2]) {
				await toQuiet(p, 0);
				expect(quiet(p), 'quiet in attempt ' + round).to.deep.equal([
					true,
					true
				]);
				await fence(p);
				expect(abandoned(p, 0).slice(-1), 'fence ' + round).to.deep.equal([
					FENCE
				]);
				expect(quiet(p), 'after attempt ' + round).to.deep.equal([
					false,
					false
				]);
			}
			for (const i of [0, 1] as const) {
				const events = eventsSince(p, i, base[i]);
				expect(events.map((e) => e.kind)).to.deep.equal([
					'conversion-attempt',
					'conversion-withdrawn',
					'conversion-attempt',
					'conversion-withdrawn'
				]);
				expect(
					new Set(events.map((e) => e.attempt)).size,
					'identical terms give one attempt id'
				).to.equal(1);
				const [first, , second] = events as AttemptRecord[];
				expect(second.keyIndex, 'a new key').to.not.equal(first.keyIndex);
			}
		});
	});

	describe('A peer update during quiet (test 5)', () => {
		for (const kind of ['plain', 'asset'] as const)
			it(`aborts, has the withdrawal on disk before the update is delivered, and delivers it (${kind})`, async () => {
				const p = await shared(kind);
				const base = rowsOf(p)[0];
				await toQuiet(p, 0);
				const mark = p.link.sent.length;
				const seen = deliverPeerUpdate(p);
				expect(seen, 'the update was delivered').to.have.length(1);
				expect(abortsFrom(p, 0, mark)).to.deep.equal([PEER_UPDATED]);
				expect(
					seen.map((n) => n - base),
					'rows when the update was delivered'
				).to.deep.equal([2]);
				const [, withdrawal] = eventsSince(p, 0, base);
				expect(withdrawal).to.deep.include({
					kind: 'conversion-withdrawn',
					reason: PEER_UPDATED
				});
			});
	});

	describe("A peer's tx_abort during quiet (test 6, M3 and A4)", () => {
		// 10 kept, then 0xff and a backslash (8 escaped), 180 kept: 198 bytes.
		// The next 0xff would cross 200, so the cut falls before it.
		const LONG = Buffer.concat([
			Buffer.from('a'.repeat(10)),
			Buffer.from([0xff, 0x5c]),
			Buffer.from('b'.repeat(180)),
			Buffer.from([0xff]),
			Buffer.from('c'.repeat(107))
		]);
		const cases: [string, Buffer, string][] = [
			[
				'300 bytes with 0xff and a backslash',
				LONG,
				'a'.repeat(10) + '\\xff\\x5c' + 'b'.repeat(180)
			],
			[
				'an e with an acute accent',
				Buffer.from('\u{e9}', 'utf8'),
				'\\xc3\\xa9'
			],
			['a, a backslash and b', Buffer.from('a\\b'), 'a\\x5cb']
		];

		for (const [what, data, text] of cases)
			it(`writes the withdrawal with the canonical text of ${what}, and quiet ends`, async () => {
				const p = await shared('plain');
				const base = rowsOf(p);
				await toQuiet(p, 0);
				p.managers[0].handleMessage(
					p.nodeIds[1],
					MessageType.TX_ABORT,
					encodeTxAbortMessage({ channelId: p.channelId, data })
				);
				p.link.clearRules();
				p.link.held.splice(0);
				await p.settle();
				for (const i of [0, 1] as const) {
					const [record, withdrawal] = eventsSince(p, i, base[i]);
					expect(withdrawal, 'side ' + i).to.deep.equal({
						kind: 'conversion-withdrawn',
						attempt: record.attempt,
						reason: text
					});
				}
				expect(quiet(p), 'quiet ends').to.deep.equal([false, false]);
			});

		it('gives the canonical form from canonicalConversionReason', () => {
			// The expected texts above follow A4's rule (a check of this file).
			expect(LONG).to.have.length(300);
			for (const [, data, text] of cases)
				expect(expectedReason(data)).to.equal(text);
			const long = 'x'.repeat(198) + '\\' + 'y'.repeat(50);
			expect(canonicalConversionReason('\u{e9}')).to.equal('\\xc3\\xa9');
			expect(canonicalConversionReason('a\\b')).to.equal('a\\x5cb');
			expect(canonicalConversionReason(FENCE)).to.equal(FENCE);
			expect(canonicalConversionReason(long)).to.equal(expectedReason(long));
			expect(expectedReason(long)).to.have.length(198);
		});
	});

	describe('A crash restart during quiet (test 7 and A5, A6)', () => {
		/**
		 * Both sides quiet, then side 0 crashes and is built again. Pins the
		 * record surviving, the withdrawal written by the constructor before
		 * the first block and before any reconnect, and side 0's host calls
		 * after the crash.
		 */
		async function crashDuringQuiet(
			options: ICrashOptions,
			hostCalled: boolean
		): Promise<IConversionPair> {
			const p = await fresh('plain');
			const base = rowsOf(p)[0];
			await toQuiet(p, 0);
			const ctx = p.hosts[0].calls('verifyConversionTerms')[0].args[0] as {
				attempt: Buffer;
			};
			const calls = p.hostLog.length;
			let survived = -1;
			const atFirstBlock: number[] = [];
			const block = sinon
				.stub(ChannelManager.prototype, 'handleNewBlock')
				.callsFake(function (this: ChannelManager, height: number) {
					atFirstBlock.push(attemptRowCount(p.stores[0], p.id) - base);
					return block.wrappedMethod.call(this, height);
				});
			const reconnected = sinon.spy(
				ChannelManager.prototype,
				'handlePeerReconnected'
			);
			try {
				p.crash(0, {
					...options,
					afterCrash: () =>
						(survived = attemptRowCount(p.stores[0], p.id) - base)
				});
			} finally {
				block.restore();
			}
			expect(survived, 'the record survives the crash').to.equal(1);
			expect(
				atFirstBlock,
				'withdrawn when the first block arrives'
			).to.deep.equal([2]);
			expect(reconnected.callCount, 'before any reconnect').to.equal(0);
			reconnected.restore();
			await settleOnce();
			expect(eventsSince(p, 0, base + 1)).to.deep.equal([
				{
					kind: 'conversion-withdrawn',
					attempt: hex(ctx.attempt),
					reason: RESTART
				}
			]);
			const after = p.hostLog.slice(calls).filter((c) => c.side === 0);
			if (hostCalled) {
				expect(
					after.map((c) => c.name),
					'one abandon'
				).to.deep.equal(['abandonConversion']);
				expect(after[0].args, 'the rebuilt context').to.deep.equal([
					ctx,
					RESTART
				]);
			} else
				expect(
					after.map((c) => c.name),
					'no host call'
				).to.deep.equal([]);
			return p;
		}

		it('withdraws in the constructor of the rebuilt manager and calls abandon once with the rebuilt context', async () => {
			const p = await crashDuringQuiet({}, true);
			await p.reconnect();
			expect(quiet(p), 'not quiet').to.deep.equal([false, false]);
			await updateRound(p);
		});

		it('withdraws the same way over a store opened again from its file, after its reconcile at open', async () => {
			const p = await crashDuringQuiet({ reopen: true }, true);
			await p.reconnect();
			await updateRound(p);
		});

		it('still withdraws, with no host call, when the rebuilt manager has no conversion host', async () => {
			await crashDuringQuiet({ conversion: false }, false);
		});

		it('still withdraws, with no host call, when the rebuilt manager has no verifyRemoteFundingInput (no final transport, no conversion offered)', async () => {
			await crashDuringQuiet({ verify: false }, false);
		});
	});

	describe('Disconnect and destroy (test 8)', () => {
		it('writes the withdrawal on both sides at a disconnect and calls abandon once each', async () => {
			const p = await shared('plain');
			const base = rowsOf(p);
			await toQuiet(p, 0);
			p.disconnect();
			await settleOnce();
			for (const i of [0, 1] as const) {
				expect(eventsSince(p, i, base[i]).map((e) => e.kind)).to.deep.equal([
					'conversion-attempt',
					'conversion-withdrawn'
				]);
				expect(eventsSince(p, i, base[i])[1]).to.deep.include({
					reason: DISCONNECTED
				});
				expect(abandoned(p, i), 'side ' + i).to.deep.equal([DISCONNECTED]);
			}
			expect(quiet(p)).to.deep.equal([false, false]);
		});

		it('writes the withdrawal and calls abandon once at a destroy through stopAssetOpenings', async () => {
			const p = await fresh('plain');
			const base = rowsOf(p)[0];
			await toQuiet(p, 0);
			p.managers[0].stopAssetOpenings();
			await settleOnce();
			const [, withdrawal] = eventsSince(p, 0, base);
			expect(withdrawal).to.deep.include({
				kind: 'conversion-withdrawn',
				reason: DISCONNECTED
			});
			expect(abandoned(p, 0)).to.deep.equal([DISCONNECTED]);
			expect(conversionQuiet(p.managers[0], p.id)).to.equal(false);
			p.disconnect();
		});

		it('writes two withdrawals for two quiet channels of one peer at one disconnect', async () => {
			const p = await fresh('plain', { extraChannel: true });
			const extra = p.extra!;
			await toQuiet(p, 0);
			await toQuiet(p, 0, extra.channelId);
			for (const id of [p.id, extra.id])
				expect(quiet(p, id), 'quiet ' + id).to.deep.equal([true, true]);
			p.disconnect();
			await settleOnce();
			for (const id of [p.id, extra.id])
				for (const i of [0, 1] as const)
					expect(
						attemptEvents(p.stores[i], id).map((e) =>
							e.kind === 'conversion-withdrawn' ? e.reason : e.kind
						),
						`side ${i}, channel ${id === p.id ? 1 : 2}`
					).to.deep.equal(['conversion-attempt', DISCONNECTED]);
		});
	});

	describe('Close during quiet (test 9)', () => {
		it('writes the withdrawal at initiateShutdown and the close goes on', async () => {
			const p = await fresh('plain');
			await toQuiet(p, 0);
			// The pair's config has no local basepoints: give the close a wallet script.
			p.managers[0].setMonitorDestinationScript(SCRIPT);
			const mark = p.link.sent.length;
			const r = p.managers[0].initiateShutdown(p.channelId, SCRIPT);
			expect(r.ok, r.error).to.equal(true);
			await p.settle();
			expect(sentNames(p, 0, mark), 'the close goes on').to.include('SHUTDOWN');
			expect(
				eventsSince(p, 0, 0).map((e) =>
					e.kind === 'conversion-withdrawn' ? e.reason : e.kind
				)
			).to.deep.equal(['conversion-attempt', CLOSED]);
		});

		it('writes the withdrawal at forceClose and the close goes on', async () => {
			const p = await fresh('plain');
			await toQuiet(p, 0);
			const broadcast: Buffer[] = [];
			p.managers[0].on('broadcast:tx', (tx: Buffer) => broadcast.push(tx));
			const r = p.managers[0].forceClose(p.channelId, SCRIPT);
			expect(r.ok, r.error).to.equal(true);
			expect(broadcast, 'the close goes on').to.have.length.at.least(1);
			expect(
				eventsSince(p, 0, 0).map((e) =>
					e.kind === 'conversion-withdrawn' ? e.reason : e.kind
				)
			).to.deep.equal(['conversion-attempt', CLOSED]);
		});
	});

	describe('A failed record append (test 10, S4 and A3)', () => {
		it(`fails with "${NOT_RECORDED}", sends no layout_ack, and withdraws the record its reconcile pulled in`, async () => {
			const p = await shared('plain');
			const base = rowsOf(p)[0];
			// The device slot commits; the wallet insert then throws, once.
			failCommits(p, 0, 'after-commit', 1);
			const mark = p.link.sent.length;
			await run(p, 0);
			expect(abortsFrom(p, 0, mark), 'the failure').to.deep.equal([
				NOT_RECORDED
			]);
			expect(sentNames(p, 0, mark), 'no layout_ack').to.not.include(
				'asset_splice:4'
			);
			expect(abandoned(p, 0)).to.deep.equal([NOT_RECORDED]);
			expect(
				p.errors[0].some((e) => e.includes('wallet insert failed')),
				'the storage error is reported'
			).to.equal(true);
			const events = eventsSince(p, 0, base);
			expect(events.map((e) => e.kind)).to.deep.equal([
				'conversion-attempt',
				'conversion-withdrawn'
			]);
			expect(events[1]).to.deep.equal({
				kind: 'conversion-withdrawn',
				attempt: events[0].attempt,
				reason: NOT_RECORDED
			});
		});
	});

	describe('A failed withdrawal append (test 11, S5 and A1, A9)', () => {
		it('reports it, reads not quiet at once, and writes the withdrawal on a later quiet read that succeeds', async () => {
			const p = await shared('plain');
			const base = rowsOf(p)[0];
			await toQuiet(p, 0);
			// Before the device commit: the original append, then the first retry.
			const commits = failCommits(p, 0, 'before-commit', 2);
			await fence(p);
			expect(abortsFrom(p, 0), 'the fence still goes out').to.include(FENCE);
			expect(abandoned(p, 0), 'one end').to.deep.equal([FENCE]);
			const reports = (): string[] =>
				p.errors[0].filter(
					(e) =>
						e.startsWith(WITHDRAWAL_FAILED) &&
						e.includes('device commit failed')
				);
			expect(reports(), 'reported').to.have.length(1);
			expect(rowsOf(p)[0] - base, 'still odd').to.equal(1);
			expect(conversionQuiet(p.managers[0], p.id), 'fail open').to.equal(false);
			expect(commits.failures(), 'the retry ran and failed').to.equal(2);
			expect(rowsOf(p)[0] - base, 'masked, still odd').to.equal(1);
			expect(conversionQuiet(p.managers[0], p.id), 'retried').to.equal(false);
			expect(rowsOf(p)[0] - base, 'the retry wrote it').to.equal(2);
			expect(eventsSince(p, 0, base)[1]).to.deep.include({
				kind: 'conversion-withdrawn',
				reason: FENCE
			});
			expect(reports(), 'the retry never reports').to.have.length(1);
			expect(abandoned(p, 0), 'and never calls abandon').to.deep.equal([FENCE]);
		});

		it('takes a withdrawal whose wallet insert failed after its device commit, so a second attempt with identical terms is quiet until its own withdrawal', async () => {
			const p = await shared('plain');
			const base = rowsOf(p)[0];
			await toQuiet(p, 0);
			failCommits(p, 0, 'after-commit', 1);
			await fence(p);
			expect(abandoned(p, 0)).to.deep.equal([FENCE]);
			// No quiet read before the second attempt.
			await toQuiet(p, 0);
			expect(quiet(p), 'quiet in the second attempt').to.deep.equal([
				true,
				true
			]);
			await fence(p);
			expect(quiet(p), 'after its withdrawal').to.deep.equal([false, false]);
			expect(
				eventsSince(p, 0, base).map((e) =>
					e.kind === 'conversion-withdrawn' ? e.reason : e.kind
				)
			).to.deep.equal([
				'conversion-attempt',
				FENCE,
				'conversion-attempt',
				FENCE
			]);
		});

		it("lets the peer's update through when the withdrawal inside observe fails", async () => {
			const p = await shared('plain');
			const base = rowsOf(p)[0];
			await toQuiet(p, 0);
			failCommits(p, 0, 'before-commit', 1);
			const mark = p.link.sent.length;
			const seen = deliverPeerUpdate(p);
			expect(seen, 'the update was delivered').to.have.length(1);
			expect(abortsFrom(p, 0, mark)).to.deep.equal([PEER_UPDATED]);
			expect(
				p.errors[0].filter((e) => e.startsWith(WITHDRAWAL_FAILED)),
				'reported'
			).to.have.length(1);
			expect(
				seen.map((n) => n - base),
				'not written'
			).to.deep.equal([1]);
			// The next quiet read retries and writes it.
			expect(conversionQuiet(p.managers[0], p.id)).to.equal(false);
			expect(rowsOf(p)[0] - base).to.equal(2);
		});

		it('keeps the record open across a crash whose sweep also fails, and the sweep of the following start withdraws it', async () => {
			const p = await fresh('plain');
			const base = rowsOf(p)[0];
			await toQuiet(p, 0);
			const commits = failCommits(p, 0, 'before-commit', Infinity);
			p.crash(0);
			await settleOnce();
			expect(commits.failures(), "the sweep's append failed").to.be.at.least(1);
			expect(rowsOf(p)[0] - base, 'still open').to.equal(1);
			expect(attemptStorage(p.stores[0]).conversionAttemptOpen(p.id)).to.equal(
				true
			);
			expect(conversionQuiet(p.managers[0], p.id), 'fail open').to.equal(false);
			expect(
				p.errors[0].some((e) => e.includes('device commit failed')),
				"the sweep's failure is reported"
			).to.equal(true);
			sinon.restore();
			p.crash(0);
			await settleOnce();
			expect(eventsSince(p, 0, base).map((e) => e.kind)).to.deep.equal([
				'conversion-attempt',
				'conversion-withdrawn'
			]);
			expect(eventsSince(p, 0, base)[1]).to.deep.include({ reason: RESTART });
			expect(
				abandoned(p, 0).filter((t) => t === RESTART),
				'abandon at each start, the second a repeat'
			).to.have.length(2);
		});
	});

	describe('Writer gates (test 12, sections 2.4 to 2.6 and A1)', () => {
		/** A generation 6 plain channel's two stores, with no managers. */
		const stores = (
			generation: 2 | 6 = 6
		): {
			store: SqliteStorage;
			id: string;
			peer: string;
			storage: ReturnType<typeof attemptStorage>;
		} => {
			const pair = plainTypePair(s, 0, generation);
			const store = pair.stores[0];
			return {
				store,
				id: pair.id,
				peer: pair.sides[1].binding.nodeId,
				storage: attemptStorage(store)
			};
		};
		const db = (store: SqliteStorage): Database.Database =>
			(store as unknown as { db: Database.Database }).db;

		it(`refuses both writers without an original conversion wallet: "${WALLET}"`, () => {
			const { store, id, peer, storage } = stores(2);
			expect(() =>
				storage.recordConversionAttempt(id, sampleRecord(store, id, peer))
			).to.throw(WALLET);
			expect(() =>
				storage.withdrawConversionAttempt(id, 1, 'a1'.repeat(32), FENCE)
			).to.throw(WALLET);
		});

		it(`refuses both writers inside a transaction: "${TOP_LEVEL}"`, () => {
			const { store, id, peer, storage } = stores();
			const record = sampleRecord(store, id, peer);
			expect(() =>
				db(store).transaction(() =>
					storage.recordConversionAttempt(id, record)
				)()
			).to.throw(TOP_LEVEL);
			const n = storage.recordConversionAttempt(id, record);
			expect(() =>
				db(store).transaction(() =>
					storage.withdrawConversionAttempt(id, n, record.attempt, FENCE)
				)()
			).to.throw(TOP_LEVEL);
			expect(attemptRowCount(store, id)).to.equal(1);
		});

		it(`refuses a record while one is open: "${OTHER_ATTEMPT}"`, () => {
			const { store, id, peer, storage } = stores();
			const record = sampleRecord(store, id, peer);
			expect(storage.recordConversionAttempt(id, record), 'n').to.equal(1);
			expect(() => storage.recordConversionAttempt(id, record)).to.throw(
				OTHER_ATTEMPT
			);
			expect(attemptRowCount(store, id)).to.equal(1);
		});

		it(`withdraws by sequence: appends after its own record, is a no-op once withdrawn, and otherwise refuses with "${NOT_RECORDED}"`, () => {
			const { store, id, peer, storage } = stores();
			const record = sampleRecord(store, id, peer);
			const other = 'f6'.repeat(32);
			expect(
				() => storage.withdrawConversionAttempt(id, 1, record.attempt, FENCE),
				'no record'
			).to.throw(NOT_RECORDED);
			const n = storage.recordConversionAttempt(id, record);
			expect(n).to.equal(1);
			expect(
				() => storage.withdrawConversionAttempt(id, n, other, FENCE),
				'another attempt'
			).to.throw(NOT_RECORDED);
			expect(
				() =>
					storage.withdrawConversionAttempt(id, n + 1, record.attempt, FENCE),
				'another sequence'
			).to.throw(NOT_RECORDED);
			expect(attemptStorage(store).conversionAttemptOpen(id)).to.equal(true);
			storage.withdrawConversionAttempt(id, n, record.attempt, FENCE);
			expect(attemptRowCount(store, id)).to.equal(2);
			storage.withdrawConversionAttempt(id, n, record.attempt, FENCE);
			expect(attemptRowCount(store, id), 'a no-op').to.equal(2);
			expect(
				() => storage.withdrawConversionAttempt(id, n, other, FENCE),
				'a withdrawn record under another id'
			).to.throw(NOT_RECORDED);
			expect(
				() => storage.withdrawConversionAttempt(id, 2, record.attempt, FENCE),
				'the withdrawal row'
			).to.throw(NOT_RECORDED);
			// The same attempt id again, at sequence 3 (M4).
			expect(storage.recordConversionAttempt(id, record), 'n again').to.equal(
				3
			);
			storage.withdrawConversionAttempt(id, 1, record.attempt, FENCE);
			expect(attemptRowCount(store, id), 'the old record: a no-op').to.equal(3);
			storage.withdrawConversionAttempt(id, 3, record.attempt, FENCE);
			expect(attemptEvents(store, id).map((e) => e.kind)).to.deep.equal([
				'conversion-attempt',
				'conversion-withdrawn',
				'conversion-attempt',
				'conversion-withdrawn'
			]);
			expect(
				() => storage.withdrawConversionAttempt(id, 5, record.attempt, FENCE),
				'past the scope'
			).to.throw(NOT_RECORDED);
		});

		it(`refuses a reason that is not canonical, and a malformed record: "${INVALID}"`, () => {
			const { store, id, peer, storage } = stores();
			const record = sampleRecord(store, id, peer);
			const malformed: [string, unknown][] = [
				['an unknown field', { ...record, extra: true }],
				['a 31 byte attempt', { ...record, attempt: 'a1'.repeat(31) }],
				['a 32 byte peer', { ...record, peer: '02' + 'aa'.repeat(31) }],
				['a 31 byte agreement', { ...record, agreement: 'e5'.repeat(31) }]
			];
			for (const [what, event] of malformed)
				expect(
					() =>
						storage.recordConversionAttempt(
							id,
							event as IConversionAttemptFields
						),
					what
				).to.throw(INVALID);
			expect(attemptRowCount(store, id), 'nothing written').to.equal(0);
			const n = storage.recordConversionAttempt(id, record);
			for (const [what, reason] of [
				['a raw non-ASCII byte', '\u{e9}'],
				['a control byte', 'line\nbreak'],
				['201 bytes', 'r'.repeat(201)]
			] as const)
				expect(
					() =>
						storage.withdrawConversionAttempt(id, n, record.attempt, reason),
					what
				).to.throw(INVALID);
			expect(attemptRowCount(store, id), 'still open').to.equal(1);
			storage.withdrawConversionAttempt(
				id,
				n,
				record.attempt,
				expectedReason('\u{e9}' + 'r'.repeat(300))
			);
			expect(attemptRowCount(store, id)).to.equal(2);
		});

		it('reads the open record and the odd count', () => {
			const { store, id, peer, storage } = stores();
			const record = sampleRecord(store, id, peer);
			expect(storage.conversionAttemptOpen(id)).to.equal(false);
			expect(storage.openConversionAttempt(id)).to.equal(null);
			const n = storage.recordConversionAttempt(id, record);
			expect(storage.conversionAttemptOpen(id)).to.equal(true);
			expect(storage.openConversionAttempt(id)?.attempt).to.equal(
				record.attempt
			);
			storage.withdrawConversionAttempt(id, n, record.attempt, FENCE);
			expect(storage.conversionAttemptOpen(id)).to.equal(false);
			expect(storage.openConversionAttempt(id)).to.equal(null);
		});

		it('sweeps every open record of the wallet once and never throws', () => {
			const { store, id, peer, storage } = stores();
			const record = sampleRecord(store, id, peer);
			storage.recordConversionAttempt(id, record);
			const authority = deviceAuthority(store);
			const stub = sinon
				.stub(authority, 'commitLifecycleEntry')
				.throws(new Error('device commit failed'));
			expect(() =>
				storage.withdrawOpenConversionAttempts(RESTART)
			).to.not.throw();
			expect(storage.conversionAttemptOpen(id), 'still open').to.equal(true);
			stub.restore();
			storage.withdrawOpenConversionAttempts(RESTART);
			expect(attemptEvents(store, id)).to.deep.equal([
				{ kind: 'conversion-attempt', ...record },
				{
					kind: 'conversion-withdrawn',
					attempt: record.attempt,
					reason: RESTART
				}
			]);
			storage.withdrawOpenConversionAttempts(RESTART);
			expect(attemptRowCount(store, id), 'nothing more').to.equal(2);
		});
	});

	describe('Not counted elsewhere (test 13, section 2.7)', () => {
		for (const kind of ['plain', 'asset'] as const)
			it(`counts no branch row, refuses no restore and sees no splice after a record and a withdrawal (${kind})`, async () => {
				const p = await shared(kind);
				const base = rowsOf(p);
				const start = await run(p, 0);
				expect(start.error).to.equal(undefined);
				expect(abandoned(p, 0), 'the fence').to.deep.equal([FENCE]);
				for (const i of [0, 1] as const) {
					const store = p.stores[i];
					expect(attemptRowCount(store, p.id) - base[i], 'side ' + i).to.equal(
						2
					);
					expect(finalBranchReaders(store)!.finalBranchRows(p.id)).to.equal(0);
					expect(() =>
						(
							SqliteStorage as unknown as {
								refuseRecordedRepair(
									db: Database.Database,
									authority: FinalOpeningAuthority | null,
									id: string
								): void;
							}
						).refuseRecordedRepair(
							(store as unknown as { db: Database.Database }).db,
							deviceAuthority(store),
							p.id
						)
					).to.not.throw();
					const st = store as unknown as {
						channelTypeState(id: string): { current: unknown } | null;
						channelSpliceInProgress(id: string, current: unknown): boolean;
					};
					expect(
						st.channelSpliceInProgress(p.id, st.channelTypeState(p.id)!.current)
					).to.equal(false);
				}
			});
	});

	describe('No query outside generation 6 (test 14)', () => {
		const freshStore = (g: 5 | 6): SqliteStorage => {
			const store = SqliteStorage.createFinalWallet(
				path.join(s.dir(), 'g' + g),
				generateFinalGeneration(g).binding
			);
			s.closing(() => store.close());
			return store;
		};
		const attemptQueries = (prepare: { args: unknown[][] }): string[] =>
			prepare.args
				.map((a) => String(a[0]))
				.filter((sql) => sql.includes(ATTEMPT_SCOPE));

		it('runs no conversion-attempt query on a generation 5 store, and one on a generation 6 store', () => {
			const id = 'ab'.repeat(32);
			const g5 = freshStore(5);
			const spy5 = sinon.spy(
				(g5 as unknown as { db: Database.Database }).db,
				'prepare'
			);
			expect(attemptStorage(g5).conversionAttemptOpen(id)).to.equal(false);
			expect(attemptQueries(spy5), 'generation 5').to.deep.equal([]);
			const g6 = freshStore(6);
			const spy6 = sinon.spy(
				(g6 as unknown as { db: Database.Database }).db,
				'prepare'
			);
			expect(attemptStorage(g6).conversionAttemptOpen('not an id')).to.equal(
				false
			);
			expect(attemptQueries(spy6), 'a malformed id').to.deep.equal([]);
			expect(attemptStorage(g6).conversionAttemptOpen(id)).to.equal(false);
			expect(attemptQueries(spy6), 'generation 6').to.have.length(1);
		});
	});

	describe('A quiet read is one COUNT (test 15, S6 and A9)', () => {
		it('runs one prepared COUNT and no journal read after ten attempts', async () => {
			const p = await shared('plain');
			const store = p.stores[0];
			const storage = attemptStorage(store);
			for (let k = 0; k < 10; k++) {
				const record = sampleRecord(
					store,
					p.id,
					p.nodeIds[1],
					(k + 16).toString(16).repeat(32)
				);
				const n = storage.recordConversionAttempt(p.id, record);
				storage.withdrawConversionAttempt(p.id, n, record.attempt, FENCE);
			}
			const read = (): {
				quiet: boolean;
				statements: string[];
				reads: number;
			} => {
				// A first read may prepare the statement; the read measured is the next.
				conversionQuiet(p.managers[0], p.id);
				const db = (store as unknown as { db: Database.Database }).db;
				const stmt = sinon.spy(
					store as unknown as { _stmt(sql: string): unknown },
					'_stmt'
				);
				const prepare = sinon.spy(db, 'prepare');
				const journal = [
					sinon.spy(FinalDeviceJournal.prototype, 'read'),
					sinon.spy(
						FinalDeviceJournal.prototype as unknown as {
							readPrefix(): unknown;
						},
						'readPrefix'
					),
					sinon.spy(FinalOpeningAuthority.prototype, 'lifecycleEntry')
				];
				try {
					const q = conversionQuiet(p.managers[0], p.id);
					return {
						quiet: q,
						statements: [...stmt.args, ...prepare.args]
							.map((a: unknown[]) => String(a[0]))
							.filter((sql) => sql.includes('final_lifecycle_log')),
						reads: journal.reduce((n, spy) => n + spy.callCount, 0)
					};
				} finally {
					for (const spy of [stmt, prepare, ...journal]) spy.restore();
				}
			};
			const closed = read();
			expect(closed.quiet).to.equal(false);
			expect(closed.statements, 'statements').to.have.length(1);
			expect(closed.statements[0]).to.match(/COUNT/i);
			expect(closed.reads, 'no journal or device read').to.equal(0);
			// The open record is a live attempt's (amendment B1: a record that
			// no live attempt holds is an orphan, withdrawn when it is met).
			await toQuiet(p, 0);
			const open = read();
			expect(open.quiet).to.equal(true);
			expect(open.statements).to.have.length(1);
			expect(open.statements[0]).to.match(/COUNT/i);
			expect(open.reads).to.equal(0);
			await fence(p);
			expect(held(p.managers[0], p.id)).to.equal(false);
		});
	});
});
