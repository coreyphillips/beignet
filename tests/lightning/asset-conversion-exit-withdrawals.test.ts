/**
 * #2151 Step 4b, contract section 13, the exit withdrawals file: every end of
 * an attempt between the agreement and the fence goes through 4a's paths,
 * which since Step 4b drop a retained candidate before the withdrawal
 * (sections 7.3 and 8, V1, V2, V4, W1, W2). Numbers in titles are the
 * contract's (B1 to B18).
 *
 * The phases are section 13's (P1 to P7b), reached by `toPhase`. In each
 * case the withdrawal is written, and where a side retained (P7b) the drop
 * before it; quiet ends; the host is told once; a late host answer writes
 * nothing; and, where the peer stays, a reconnect gives the parent and an
 * update round on it works.
 */
import { expect } from 'chai';
import sinon from 'sinon';
import type Database from 'better-sqlite3';
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import { encodeUpdateAddHtlcMessage } from '../../src/lightning/message/channel-update';
import {
	encodeTxAddInputMessage,
	encodeTxAddOutputMessage,
	encodeTxCompleteMessage
} from '../../src/lightning/message/interactive-tx';
import { MessageType } from '../../src/lightning/message/types';
import { FinalDeviceJournal } from '../../src/lightning/storage/final-device-journal';
import { scratch } from './helpers/channel-type-pairs';
import { deviceAuthority } from './helpers/channel-type-record';
import {
	attemptEvents,
	attemptRowCount,
	canonicalConversionReason,
	conversionQuiet
} from './helpers/conversion-attempts';
import {
	abandoned,
	agreeOnTerms,
	attemptOf,
	conversionPair,
	FENCE,
	never,
	PAIR_HEIGHT,
	settleOnce,
	sharedPair,
	silenceConversion,
	startConversion,
	stubConversionDescription,
	stubExitEvidence,
	stubProposal,
	tick,
	track,
	txAbort,
	updateRound,
	type IConversionPair,
	type IWireMessage
} from './helpers/conversion-managers';
import {
	abortsFrom,
	allRows,
	candidateHash,
	capture,
	CONSTRUCTION_NAMES,
	conversionKinds,
	conversionRowCount,
	defaultSigning,
	expectEnded,
	expectParentWorks,
	forgedCommitmentSigned,
	gate,
	lateAnswers,
	marks,
	pendingConversionsOf,
	PHASES,
	refuseRepair,
	retainedAt,
	REUSED_TEXTS,
	SIGNING_TEXTS,
	toPhase,
	walletDb
} from './helpers/conversion-signing';

const R = REUSED_TEXTS;
const T = SIGNING_TEXTS;
const REF = Buffer.alloc(8, 0x4e);
const DEADLINE_MS = 5_000;
const SCRIPT = Buffer.from('0014' + '22'.repeat(20), 'hex');

const fakeClock = (): sinon.SinonFakeTimers =>
	sinon.useFakeTimers({
		now: Date.now(),
		toFake: ['Date', 'setTimeout', 'clearTimeout']
	});

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
		h.verifyExits = (ctx, views): unknown => stubExitEvidence(h, ctx, views);
		p.feerateEstimates[i] = async (): Promise<number> => 1000;
	}
	defaultSigning(p);
	agreeOnTerms(p);
}

async function reset(p: IConversionPair): Promise<void> {
	p.link.clearRules();
	p.link.held.splice(0);
	p.link.taps.splice(0);
	p.disconnect();
	await p.reconnect();
}

const sentNames = (p: IConversionPair, from: 0 | 1, mark = 0): string[] =>
	p.link.sent
		.slice(mark)
		.filter((m) => m.from === from)
		.map((m) => m.name);
const parentsOf = (p: IConversionPair): unknown[] =>
	p.stores.map((st) => st.loadFinalChannelType(p.id));

describe('Every end of a signing attempt drops, then withdraws (#2151 step 4b, section 13, the exit withdrawals file)', function () {
	this.timeout(240000);
	const s = scratch('conversion-exit-withdrawals-');
	const used = new Set<string>();
	const pairs: Record<string, () => Promise<IConversionPair>> = {
		plain: sharedPair(s, 'plain'),
		asset1: sharedPair(s, 'asset', { rounds: 1 }),
		deadline: sharedPair(s, 'plain', {
			config: [{ quiescenceTimeoutMs: DEADLINE_MS }, undefined]
		})
	};
	const shared = (key: string): Promise<IConversionPair> => {
		used.add(key);
		return pairs[key]().then((p) => {
			clean(p);
			return p;
		});
	};
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
		for (const key of [...used]) await reset(await pairs[key]());
		used.clear();
	});
	after(() => s.release());

	describe('A disconnect (B1)', () => {
		for (const phase of PHASES)
			for (const [key, I] of [
				['plain', 0],
				['asset1', 1]
			] as const)
				it(`B1. withdraws on both sides at a disconnect at ${phase} (${key}, side ${I} initiating)`, async () => {
					const p = await shared(key);
					const base = marks(p);
					const parent = parentsOf(p);
					const at = await toPhase(p, phase, I);
					p.disconnect();
					await p.settle();
					// The initiator is aborting at P7b, not ended: the disconnect
					// ends both sides.
					const told: [string, string] = [R.disconnected, R.disconnected];
					for (const i of [0, 1] as const)
						expectEnded(p, i, base, retainedAt(phase), told[i]);
					const rows = allRows(p);
					await lateAnswers(p, at);
					expect(allRows(p), 'a late answer writes nothing').to.deep.equal(
						rows
					);
					await expectParentWorks(p, parent);
				});
	});

	describe('A crash restart (B2)', () => {
		for (const phase of PHASES)
			for (const i of [0, 1] as const)
				it(`B2. withdraws side ${i} in its rebuilt manager's sweep before any reconnect at ${phase}, dropping first where it retained`, async () => {
					const p = await fresh('plain');
					const base = marks(p);
					const parent = parentsOf(p);
					const at = await toPhase(p, phase, 0);
					const reconnected = sinon.spy(
						ChannelManager.prototype,
						'handlePeerReconnected'
					);
					p.crash(i);
					expect(reconnected.callCount, 'before any reconnect').to.equal(0);
					reconnected.restore();
					await settleOnce();
					// The initiator at P7b withdrew at its fence and was aborting,
					// waiting for the echo, when it crashed: no end ran, and its
					// rebuilt manager finds no open record to tell the host of.
					const untold = phase === 'P7b' && i === 0;
					const crashedReason = untold ? undefined : R.restart;
					expect(
						attemptEvents(p.stores[i], p.id)
							.slice(base.attempts[i])
							.map((e) => e.kind),
						'side ' + i + ' withdrawn by the sweep'
					).to.deep.equal(['conversion-attempt', 'conversion-withdrawn']);
					expect(
						conversionKinds(p.stores[i], p.id).slice(base.conversions[i]),
						'side ' + i + ' dropped first where it retained'
					).to.deep.equal(
						retainedAt(phase) ? ['conversion-exits', 'conversion-dropped'] : []
					);
					await p.settle();
					expectEnded(
						p,
						i,
						base,
						retainedAt(phase),
						crashedReason,
						untold ? 0 : 1
					);
					const rows = allRows(p);
					await lateAnswers(p, at);
					expect(
						allRows(p),
						"the old manager's late answer writes nothing"
					).to.deep.equal(rows);
					await expectParentWorks(p, parent);
				});
	});

	describe('The deadline (B3, B4)', () => {
		const hostWaits: [string, (p: IConversionPair) => void][] = [
			[
				'consent',
				(p): unknown => (p.hosts[0].consent = (): unknown => never())
			],
			[
				'authorize',
				(p): unknown => (p.hosts[0].authorize = (): unknown => never())
			],
			[
				'finalize',
				(p): unknown => (p.hosts[0].finalize = (): unknown => never())
			],
			[
				'signConversionExits',
				(p): unknown => (p.hosts[0].signExits = (): unknown => never())
			],
			[
				'verifyConversionExits',
				(p): unknown => (p.hosts[0].verifyExits = (): unknown => never())
			],
			[
				'retainConversionExits',
				(p): unknown => (p.hosts[0].retainExits = (): unknown => never())
			]
		];
		const peerWaits: [string, (m: IWireMessage) => boolean][] = [
			[
				'consent',
				(m): boolean => m.from === 1 && m.name === 'asset_splice_consent'
			],
			[
				'authorization',
				(m): boolean => m.from === 1 && m.name === 'asset_splice:1'
			],
			[
				'final_ack',
				(m): boolean => m.from === 1 && m.name === 'asset_splice:5'
			],
			[
				'a construction turn',
				(m): boolean =>
					m.from === 1 &&
					(CONSTRUCTION_NAMES as readonly string[]).includes(m.name)
			],
			[
				'checkpoint',
				(m): boolean => m.from === 1 && m.name === 'asset_splice:6'
			],
			[
				'exit share',
				// Side 1's commitment_signed follows its exit share on an
				// ordered connection, so it is held too.
				(m): boolean =>
					m.from === 1 &&
					(m.name === 'asset_splice:3' || m.name === 'COMMITMENT_SIGNED')
			],
			[
				'commitment_signed',
				(m): boolean => m.from === 1 && m.name === 'COMMITMENT_SIGNED'
			]
		];
		const cases: [string, (p: IConversionPair) => void][] = [
			...hostWaits.map(
				([name, set]) =>
					['the host ' + name, set] as [string, (p: IConversionPair) => void]
			),
			...peerWaits.map(
				([name, match]) =>
					[
						'the peer ' + name,
						(p: IConversionPair): void => p.link.hold(match)
					] as [string, (p: IConversionPair) => void]
			)
		];
		for (const [what, setup] of cases)
			it(`B3. times out 5 s after the agreement while side 0 waits for ${what}, with one tx_abort and no conversion-exits after it`, async () => {
				const p = await shared('deadline');
				const base = marks(p);
				setup(p);
				let agreedAt = -1;
				p.link.taps.push((m) => {
					if (m.name === 'asset_splice:4') agreedAt = Date.now();
				});
				const clock = fakeClock();
				try {
					agreeOnTerms(p);
					const start = track(
						startConversion(p.managers[0], p.channelId, { reference: REF })
					);
					await p.settle();
					expect(agreedAt, 'both layout_acks left').to.be.greaterThan(0);
					expect(
						attemptOf(p.managers[0], p.id)?.state,
						'past the agreement'
					).to.be.oneOf(['agreed', 'constructing', 'securing']);
					const mark = p.link.delivered.length;
					await tick(p, clock, agreedAt + DEADLINE_MS - 100 - Date.now());
					expect(abandoned(p, 0), 'alive 100 ms before').to.deep.equal([]);
					await tick(p, clock, 200);
					expect(abandoned(p, 0), 'ended within 100 ms after').to.deep.equal([
						R.timedOut
					]);
					expect(
						p.link.delivered
							.slice(mark)
							.filter((m) => m.from === 0 && m.name === 'TX_ABORT'),
						'the peer sees one tx_abort'
					).to.have.length(1);
					const exits = conversionKinds(p.stores[0], p.id).slice(
						base.conversions[0]
					);
					await tick(p, clock, 20_000);
					expect(
						conversionKinds(p.stores[0], p.id).slice(base.conversions[0])
					).to.deep.equal(exits);
					expect(exits).to.not.include('conversion-exits');
					await start.done;
				} finally {
					clock.restore();
				}
			});

		it('B4. arms the deadline again at the agreement, so a negotiation of 4.9 s still gets a full 5 s signing window', async () => {
			const p = await shared('deadline');
			const h = p.hosts[0];
			const describe = h.describe;
			h.describe = (ctx, proposals, bitcoin): unknown =>
				new Promise((done) =>
					setTimeout(() => done(describe(ctx, proposals, bitcoin)), 4_900)
				);
			h.consent = (): unknown => never();
			let agreedAt = -1;
			p.link.taps.push((m) => {
				if (m.name === 'asset_splice:4') agreedAt = Date.now();
			});
			const clock = fakeClock();
			try {
				const started = Date.now();
				agreeOnTerms(p);
				const start = track(
					startConversion(p.managers[0], p.channelId, { reference: REF })
				);
				await p.settle();
				await tick(p, clock, 4_900);
				expect(agreedAt - started, 'the negotiation took 4.9 s').to.be.at.least(
					4_900
				);
				await tick(p, clock, 300);
				expect(abandoned(p, 0), 'alive past the start plus 5 s').to.deep.equal(
					[]
				);
				await tick(p, clock, agreedAt + DEADLINE_MS - 100 - Date.now());
				expect(
					abandoned(p, 0),
					'alive 100 ms before the agreement plus 5 s'
				).to.deep.equal([]);
				await tick(p, clock, 200);
				expect(abandoned(p, 0)).to.deep.equal([R.timedOut]);
				await start.done;
			} finally {
				clock.restore();
			}
		});
	});

	describe('A peer update (B5)', () => {
		for (const phase of PHASES)
			it(`B5. withdraws${
				phase === 'P7b' ? ' and drops' : ''
			} before a peer update at ${phase} is applied, and delivers it (plain)`, async () => {
				const p = await shared('plain');
				const base = marks(p);
				const at = await toPhase(p, phase, 0);
				const A = at.A;
				const seen: number[][] = [];
				const m = p.managers[A] as unknown as {
					finalTransport: {
						queue(peer: string, id: string, msg: unknown): void;
					};
				};
				sinon
					.stub(m.finalTransport, 'queue')
					.callsFake((_peer: string, _id: string, msg: unknown) => {
						if ((msg as { type: number }).type === MessageType.UPDATE_ADD_HTLC)
							seen.push([
								attemptRowCount(p.stores[A], p.id) - base.attempts[A],
								conversionRowCount(p.stores[A], p.id) - base.conversions[A]
							]);
					});
				p.managers[A].handleMessage(
					p.nodeIds[at.I],
					MessageType.UPDATE_ADD_HTLC,
					encodeUpdateAddHtlcMessage({
						channelId: p.channelId,
						id: 0n,
						amountMsat: 1_000_000n,
						paymentHash: Buffer.alloc(32, 0x45),
						cltvExpiry: PAIR_HEIGHT + 100,
						onionRoutingPacket: Buffer.alloc(1366)
					})
				);
				await p.settle();
				expect(seen, 'rows when the update was delivered').to.deep.equal([
					[2, retainedAt(phase) ? 2 : 0]
				]);
				// At P7a and P7b the side's tx_abort is answered only once the
				// initiator's retain answers or its held fence arrives (W2).
				if (phase === 'P7a' || phase === 'P7b') await at.release();
				expectEnded(p, A, base, retainedAt(phase), R.peerUpdated);
			});
	});

	describe("A peer's tx_abort (B6)", () => {
		for (const phase of PHASES)
			it(`B6. ends at a peer tx_abort at ${phase}, ${
				phase === 'P7a' ? 'queued behind the pending retain' : 'taken at once'
			}, with the canonical reason`, async () => {
				const p = await shared('plain');
				const base = marks(p);
				const at = await toPhase(p, phase, 0);
				// The receiver: the initiator, except at P7b where only the
				// acceptor is live, and at P7a, where the initiator fences right
				// after its retain (W2) and only the acceptor echoes.
				const to = (phase === 'P7b' || phase === 'P7a' ? at.A : at.I) as 0 | 1;
				const from = (1 - to) as 0 | 1;
				if (phase === 'P7b') {
					p.link.clearRules();
					p.link.held.splice(0);
				}
				const text = 'peer stops\u{1}';
				const mark = p.link.sent.length;
				p.managers[to].handleMessage(
					p.nodeIds[from],
					MessageType.TX_ABORT,
					txAbort(p.channelId, text)
				);
				await settleOnce();
				const canonical = canonicalConversionReason(text);
				if (phase !== 'P7a')
					expect(abandoned(p, to), 'ended at once').to.deep.equal([canonical]);
				else
					expect(abandoned(p, to), 'queued behind the retain').to.deep.equal(
						[]
					);
				await lateAnswers(p, at);
				await p.settle();
				expect(abandoned(p, to)).to.deep.equal([canonical]);
				if (
					phase === 'P5' ||
					phase === 'P6' ||
					phase === 'P1' ||
					phase === 'P2' ||
					phase === 'P3' ||
					phase === 'P4'
				)
					expect(
						sentNames(p, to, mark).filter(
							(n) => n === 'asset_splice:3' || n === 'COMMITMENT_SIGNED'
						),
						'nothing signed leaves after the abort'
					).to.deep.equal([]);
				expectEnded(p, to, base, phase === 'P7a' || phase === 'P7b', canonical);
			});
	});

	describe('A local close and a destroy (B7, B8)', () => {
		for (const phase of ['P2', 'P5', 'P7b'] as const)
			for (const close of ['initiateShutdown', 'forceClose'] as const)
				it(`B7. withdraws${
					phase === 'P7b' ? ' and drops' : ''
				} at ${close} at ${phase}, and the close goes on`, async () => {
					const p = await fresh('plain');
					const base = marks(p);
					const at = await toPhase(p, phase, 0);
					const side = (phase === 'P7b' ? at.A : at.I) as 0 | 1;
					const broadcast: unknown[] = [];
					p.managers[side].on('broadcast:tx', (tx: unknown) =>
						broadcast.push(tx)
					);
					// The pair's config has no local basepoints: give the close a
					// wallet script, as 4a's close test does.
					p.managers[side].setMonitorDestinationScript(SCRIPT);
					const mark = p.link.sent.length;
					const r =
						close === 'initiateShutdown'
							? p.managers[side].initiateShutdown(p.channelId, SCRIPT)
							: p.managers[side].forceClose(p.channelId, SCRIPT);
					expect(r.ok, r.error).to.equal(true);
					await p.settle();
					if (close === 'initiateShutdown')
						expect(sentNames(p, side, mark), 'the close goes on').to.include(
							'SHUTDOWN'
						);
					else
						expect(broadcast, 'the close goes on').to.have.length.at.least(1);
					// At P7b the acceptor's tx_abort ends at the initiator's held fence.
					if (phase === 'P7b') {
						p.link.clearRules();
						p.link.release();
						await p.settle();
					}
					expectEnded(p, side, base, retainedAt(phase), R.closed);
				});

		it('B8. drops, withdraws and tells the host once at a destroy at P7b', async () => {
			const p = await fresh('plain');
			const base = marks(p);
			const at = await toPhase(p, 'P7b', 0);
			p.managers[at.A].stopAssetOpenings();
			await p.settle();
			expectEnded(p, at.A, base, true);
		});
	});

	describe('A failed drop and an orphan (B9 to B12)', () => {
		/** Make side i's device commit of its next conversion row fail, once: before the commit, or after it (the wallet insert). */
		function failDrop(
			p: IConversionPair,
			i: 0 | 1,
			how: 'before-commit' | 'after-commit'
		): { failed: () => boolean } {
			const authority = deviceAuthority(p.stores[i]);
			const commit = authority.commitLifecycleEntry.bind(authority);
			let failed = false;
			sinon
				.stub(authority, 'commitLifecycleEntry')
				.callsFake((slot: string, value: string) => {
					const fail = !failed && slot.startsWith('conversion/');
					if (fail && how === 'before-commit') {
						failed = true;
						throw new Error('device commit failed');
					}
					commit(slot, value);
					if (fail) {
						failed = true;
						throw new Error('wallet insert failed');
					}
				});
			return { failed: () => failed };
		}

		it('B9. writes no withdrawal when the drop fails, reports once, reads not quiet, and drops and withdraws on the next quiet read', async () => {
			const p = await fresh('plain');
			const base = marks(p);
			const at = await toPhase(p, 'P7b', 0);
			const A = at.A;
			const fail = failDrop(p, A, 'before-commit');
			await at.release();
			expect(fail.failed(), 'the drop failed').to.equal(true);
			expect(
				attemptEvents(p.stores[A], p.id)
					.slice(base.attempts[A])
					.map((e) => e.kind),
				'no withdrawal'
			).to.deep.equal(['conversion-attempt']);
			const reports = p.errors[A].filter((e) =>
				e.startsWith(R.withdrawalFailed)
			);
			expect(reports, 'one report').to.have.length(1);
			expect(conversionQuiet(p.managers[A], p.id), 'not quiet').to.equal(false);
			sinon.restore();
			expect(conversionQuiet(p.managers[A], p.id)).to.equal(false);
			expectEnded(p, A, base, true);
			expect(
				p.errors[A].filter((e) => e.startsWith(R.withdrawalFailed)),
				'no second report'
			).to.have.length(1);
		});

		it('B10. drops, then withdraws, an orphan whose channel holds a retained candidate at the next quiet read, and tells the host', async () => {
			const p = await fresh('plain');
			const base = marks(p);
			const at = await toPhase(p, 'P7b', 0);
			silenceConversion(p.managers[at.A]);
			expect(
				conversionQuiet(p.managers[at.A], p.id),
				'quiet reads false'
			).to.equal(false);
			await p.settle();
			// 4a's D1: the host hears of an orphan only for a record from before
			// this process; this process's attempt is told by its end, which a
			// silenced attempt never ran.
			expectEnded(p, at.A, base, true, undefined, 0);
		});

		it('B11. takes a drop that landed only on the device through the reconcile and does not repeat it', async () => {
			const p = await fresh('plain');
			const base = marks(p);
			const at = await toPhase(p, 'P7b', 0);
			const A = at.A;
			const fail = failDrop(p, A, 'after-commit');
			await at.release();
			expect(fail.failed(), 'the wallet insert failed').to.equal(true);
			sinon.restore();
			conversionQuiet(p.managers[A], p.id);
			await p.settle();
			expectEnded(p, A, base, true);
		});

		it('B12. drops, then withdraws, through the orphan path when the sweep cannot list the scope', async () => {
			const p = await fresh('plain');
			const base = marks(p);
			const at = await toPhase(p, 'P7b', 0);
			const A = at.A;
			p.crash(A, {
				afterCrash: () => {
					const db = walletDb(p.stores[A]);
					const prepare = db.prepare.bind(db);
					let listings = 0;
					sinon.stub(db, 'prepare').callsFake(((sql: string) => {
						if (sql.includes('GROUP BY channel_id') && listings++ === 0)
							throw new Error('database is locked');
						return prepare(sql);
					}) as typeof db.prepare);
				}
			});
			expect(
				attemptEvents(p.stores[A], p.id)
					.slice(base.attempts[A])
					.map((e) => e.kind),
				'unswept'
			).to.deep.equal(['conversion-attempt']);
			sinon.restore();
			expect(conversionQuiet(p.managers[A], p.id)).to.equal(false);
			await p.settle();
			expect(
				conversionKinds(p.stores[A], p.id).slice(base.conversions[A])
			).to.deep.equal(['conversion-exits', 'conversion-dropped']);
			expect(
				attemptEvents(p.stores[A], p.id)
					.slice(base.attempts[A])
					.map((e) => e.kind)
			).to.deep.equal(['conversion-attempt', 'conversion-withdrawn']);
		});
	});

	describe('The fence meets a pending retain (B13)', () => {
		it("B13. queues the fence behind the acceptor's pending retain; a retain that never answers fails at the host bound and the initiator ends at the echo", async () => {
			const p = await shared('plain');
			const base = marks(p);
			p.hosts[1].retainExits = (): unknown => never();
			const clock = fakeClock();
			try {
				agreeOnTerms(p);
				const start = track(
					startConversion(p.managers[0], p.channelId, { reference: REF })
				);
				await p.settle();
				expect(abandoned(p, 1), 'the fence waits in the queue').to.deep.equal(
					[]
				);
				expect(p.hosts[0].calls('retainConversionExits')).to.have.length(1);
				await tick(p, clock, 16_000);
				await tick(p, clock, 16_000);
				expect(abandoned(p, 1)).to.deep.equal([T.retain]);
				expect(abandoned(p, 0)).to.deep.equal([FENCE]);
				expect(
					conversionKinds(p.stores[1], p.id).slice(base.conversions[1])
				).to.deep.equal([]);
				expect(
					conversionKinds(p.stores[0], p.id).slice(base.conversions[0])
				).to.deep.equal(['conversion-exits', 'conversion-dropped']);
				await start.done;
			} finally {
				clock.restore();
			}
		});
	});

	describe('No resume and stale messages (B14 to B16)', () => {
		const stale = (p: IConversionPair): [string, number, Buffer][] => {
			const nonce = (): Buffer =>
				Buffer.concat([
					Buffer.from([2]),
					Buffer.alloc(32, 7),
					Buffer.from([3]),
					Buffer.alloc(32, 9)
				]);
			return [
				[
					'tx_add_input',
					MessageType.TX_ADD_INPUT,
					encodeTxAddInputMessage({
						channelId: p.channelId,
						serialId: 1n,
						prevTx: Buffer.alloc(0),
						prevTxVout: 0,
						sequence: 0xfffffffd,
						sharedInputTxid: Buffer.alloc(32, 1)
					} as never)
				],
				[
					'tx_add_output',
					MessageType.TX_ADD_OUTPUT,
					encodeTxAddOutputMessage({
						channelId: p.channelId,
						serialId: 3n,
						amountSats: 100000n,
						scriptPubkey: Buffer.concat([
							Buffer.from([0x51, 0x20]),
							Buffer.alloc(32, 5)
						])
					})
				],
				[
					'tx_complete',
					MessageType.TX_COMPLETE,
					encodeTxCompleteMessage({
						channelId: p.channelId,
						commitNonces: { current: nonce(), next: nonce() },
						fundingInputNonce: nonce()
					})
				]
			];
		};
		const quietWire = (p: IConversionPair, mark: number): string[] =>
			p.link.sent
				.slice(mark)
				.filter((m) => m.name === 'ERROR' || m.name === 'WARNING')
				.map((m) => m.from + ':' + m.name);

		for (const key of ['plain', 'asset1'] as const)
			it(`B14. resends nothing after a reconnect, drops construction messages in aborting and a stale candidate commitment_signed after the end, with no row from them (${key})`, async () => {
				const p = await shared(key);
				const c = capture(p);
				const broadcasts: unknown[] = [];
				for (const m of p.managers)
					m.on('broadcast:tx', (tx: unknown) => broadcasts.push(tx));
				const at = await toPhase(p, 'P7b', 0);
				// In aborting: the initiator drops each construction message and the candidate commitment_signed.
				const before = allRows(p);
				for (const [, type, payload] of stale(p))
					p.managers[at.I].handleMessage(p.nodeIds[at.A], type, payload);
				p.managers[at.I].handleMessage(
					p.nodeIds[at.A],
					MessageType.COMMITMENT_SIGNED,
					forgedCommitmentSigned(p.channelId, candidateHash(c.fundings[at.I]!))
				);
				await p.settle();
				expect(
					allRows(p)[at.I],
					'no row from the stale messages in aborting'
				).to.deep.equal(before[at.I]);
				await at.release();
				expect(abandoned(p, 0)).to.deep.equal([FENCE]);
				expect(abandoned(p, 1)).to.deep.equal([FENCE]);
				// After the end: the candidate commitment_signed only.
				const ended = allRows(p);
				const mark = p.link.sent.length;
				p.managers[0].handleMessage(
					p.nodeIds[1],
					MessageType.COMMITMENT_SIGNED,
					forgedCommitmentSigned(p.channelId, candidateHash(c.fundings[0]!))
				);
				await p.settle();
				expect(allRows(p), 'no row after the end').to.deep.equal(ended);
				expect(quietWire(p, mark), 'no error or warning').to.deep.equal([]);
				expect(p.errors, 'no contained error').to.deep.equal([[], []]);
				expect(broadcasts, 'no broadcast').to.deep.equal([]);
				expect(
					p.stores[0].loadFinalDaemonOpening(p.id)?.exitToBroadcast,
					'no exit request'
				).to.equal(undefined);
				const reconnect = p.link.sent.length;
				p.disconnect();
				await p.reconnect();
				expect(
					p.link.sent
						.slice(reconnect)
						.map((m) => m.name)
						.filter(
							(n) =>
								n.startsWith('asset_splice') ||
								(CONSTRUCTION_NAMES as readonly string[]).includes(n) ||
								n === 'COMMITMENT_SIGNED'
						),
					'nothing resent'
				).to.deep.equal([]);
			});

		for (const key of ['plain', 'asset1'] as const)
			it(`B15. drops the peer's candidate commitment_signed that crosses a failed verify, with no error, and a payment works after a reconnect (${key})`, async () => {
				const p = await shared(key);
				const parent = parentsOf(p);
				p.hosts[0].verifyExits = (): unknown => {
					throw new Error('host refused');
				};
				const mark = p.link.sent.length;
				agreeOnTerms(p);
				const start = track(
					startConversion(p.managers[0], p.channelId, { reference: REF })
				);
				await p.settle();
				await start.done;
				expect(abandoned(p, 0)).to.deep.equal([T.verify]);
				expect(
					sentNames(p, 1, mark),
					"side 1's commitment_signed crossed"
				).to.include('COMMITMENT_SIGNED');
				expect(quietWire(p, mark)).to.deep.equal([]);
				expect(p.errors).to.deep.equal([[], []]);
				await expectParentWorks(p, parent);
			});

		it('B16. takes at once a peer tx_abort that follows its commitment_signed while our verify is pending, echoes it and sends no commitment_signed', async () => {
			const p = await shared('plain');
			const g = gate();
			const h = p.hosts[0];
			const verify = h.verifyExits;
			h.verifyExits = (ctx, views, shares): unknown =>
				g.wait.then(() => verify(ctx, views, shares));
			p.link.hold({ from: 1, name: 'COMMITMENT_SIGNED' });
			agreeOnTerms(p);
			const mark = p.link.sent.length;
			const start = track(
				startConversion(p.managers[0], p.channelId, { reference: REF })
			);
			await p.settle();
			expect(p.link.held, "the peer's commitment_signed waits").to.have.length(
				1
			);
			p.link.clearRules();
			p.link.release();
			p.link.inject(1, MessageType.TX_ABORT, txAbort(p.channelId, 'stop'));
			await p.settle();
			expect(abandoned(p, 0), 'taken at once').to.deep.equal([
				canonicalConversionReason('stop')
			]);
			g.open();
			await p.settle();
			await start.done;
			expect(
				sentNames(p, 0, mark).filter((n) => n === 'COMMITMENT_SIGNED'),
				'no commitment_signed'
			).to.deep.equal([]);
			expect(abortsFrom(p, 0, mark), 'the echo').to.have.length(1);
			expect(p.recycled, 'no disconnect').to.deep.equal([[], []]);
		});
	});

	describe('Device-only exits (B17) and the same connection after the fence (B18)', () => {
		it('B17. drops a device-only conversion-exits whose reconcile failed at the withdrawal, and a new conversion and a restore proceed', async () => {
			const p = await fresh('plain');
			const base = marks(p);
			const A = 1 as const;
			const store = p.stores[A];
			const authority = deviceAuthority(store);
			const commit = authority.commitLifecycleEntry.bind(authority);
			let armed = false;
			let reconcileFailed = false;
			sinon
				.stub(authority, 'commitLifecycleEntry')
				.callsFake((slot: string, value: string) => {
					commit(slot, value);
					if (!armed && slot.startsWith('conversion/')) {
						armed = true;
						throw new Error('wallet insert failed');
					}
				});
			const read = FinalDeviceJournal.prototype.read;
			sinon.stub(FinalDeviceJournal.prototype, 'read').callsFake(function (
				this: FinalDeviceJournal,
				...args: unknown[]
			) {
				if (armed && !reconcileFailed && args[0] === 'conversion') {
					reconcileFailed = true;
					throw new Error('reconcile failed');
				}
				return (read as (...a: unknown[]) => unknown).apply(this, args);
			} as never);
			agreeOnTerms(p);
			await track(
				startConversion(p.managers[0], p.channelId, { reference: REF })
			).done;
			await p.settle();
			expect(
				armed && reconcileFailed,
				'the exits are on the device only'
			).to.equal(true);
			sinon.restore();
			expect(
				conversionKinds(store, p.id).slice(base.conversions[A]),
				'dropped'
			).to.deep.equal(['conversion-exits', 'conversion-dropped']);
			expect(
				pendingConversionsOf(store, p.id),
				'nothing pending'
			).to.deep.equal([]);
			p.crash(A, { reopen: true });
			await p.reconnect();
			clean(p);
			agreeOnTerms(p);
			await track(
				startConversion(p.managers[0], p.channelId, { reference: REF })
			).done;
			await p.settle();
			expect(abandoned(p, 0).slice(-1), 'a new conversion').to.deep.equal([
				FENCE
			]);
			expect(() =>
				refuseRepair(
					walletDb(p.stores[A]) as Database.Database,
					deviceAuthority(p.stores[A]),
					p.id,
					p.stores[A]
				)
			).to.not.throw();
		});

		it('B18. runs a plain splice construction to completion and a second identical attempt to the fence on the same connection after the fence (plain)', async () => {
			const p = await shared('plain');
			agreeOnTerms(p);
			await track(
				startConversion(p.managers[0], p.channelId, { reference: REF })
			).done;
			await p.settle();
			expect(abandoned(p, 0), 'the first fence').to.deep.equal([FENCE]);
			const mark = p.link.sent.length;
			p.managers[0].startFinalSplice(p.channelId, {
				// Within the fee budget: with no output, the whole delta is fee.
				localDelta: '-1000',
				feeBudget: '2000',
				feerate: 1000,
				locktime: PAIR_HEIGHT,
				inputs: [],
				outputs: []
			} as unknown as Parameters<ChannelManager['startFinalSplice']>[1]);
			await p.settle();
			const construction = p.link.sent
				.slice(mark)
				.filter((m) =>
					(CONSTRUCTION_NAMES as readonly string[]).includes(m.name)
				);
			expect(
				construction.slice(-2).map((m) => m.name),
				'the construction completes'
			).to.deep.equal(['TX_COMPLETE', 'TX_COMPLETE']);
			expect(
				abortsFrom(p, 0, mark)
					.concat(abortsFrom(p, 1, mark))
					.filter((t) => /conversion/i.test(t)),
				'the conversion took none of it'
			).to.deep.equal([]);
			p.disconnect();
			await p.reconnect();
			clean(p);
			agreeOnTerms(p);
			await track(
				startConversion(p.managers[0], p.channelId, { reference: REF })
			).done;
			await p.settle();
			expect(abandoned(p, 0), 'the second fence').to.deep.equal([FENCE]);
		});

		it('B18. runs a second attempt with identical terms to the fence on the same connection after the fence (asset)', async () => {
			const p = await shared('asset1');
			for (const round of [1, 2]) {
				agreeOnTerms(p);
				await track(
					startConversion(p.managers[0], p.channelId, { reference: REF })
				).done;
				await p.settle();
				expect(abandoned(p, 0).slice(-1), 'fence ' + round).to.deep.equal([
					FENCE
				]);
			}
			await updateRound(p);
		});
	});
});
