/**
 * #2151 Step 3a, contract tests 5, 2 (the engine's checks of the terms), 8
 * and the last item of 9: two generation 6 ChannelManagers agree on a
 * conversion and stop at the fence.
 */
import { expect } from 'chai';
import { randomBytes } from 'crypto';
import { isValidPublicKey } from '../../src/lightning/crypto/ecdh';
import { MessageType } from '../../src/lightning/message/types';
import type { IAssetConversionTerms } from '../../src/lightning/channel';
import { scratch } from './helpers/channel-type-pairs';
import { conversionTerms } from './helpers/conversion-modules';
import { GRAMMAR_CASES } from './helpers/conversion-terms-sample';
import {
	abandoned,
	abortText,
	agreeOnTerms,
	allocatedKeyIndex,
	changedRows,
	conversionPair,
	decodeSpliceAck,
	decodeSpliceInit,
	encodeSpliceAck,
	encodeSpliceInit,
	held,
	PAIR_HEIGHT,
	readReply,
	readTerms,
	replyMessage,
	roleOf,
	startConversion,
	stfu,
	storeTerms,
	tableRows,
	termsFrames,
	termsIdentity,
	track,
	type IConversionPair,
	type IWireMessage,
	FENCE,
	parentHeight,
	updateRound,
	sharedPair
} from './helpers/conversion-managers';
import { BEIGNET_CUSTOM_MESSAGE_TYPE } from '../../src/lightning/message/custom';

function conversionMessages(p: IConversionPair, from: number): IWireMessage[] {
	return p.link.delivered
		.slice(from)
		.filter(
			(m) =>
				m.type !== BEIGNET_CUSTOM_MESSAGE_TYPE ||
				m.name.startsWith('conversion_')
		);
}

describe('Asset conversion agreement to the fence (#2151 step 3a, test 5)', function () {
	this.timeout(60000);
	const s = scratch('conversion-agreement-');
	const pairs = {
		plain: sharedPair(s, 'plain'),
		asset: sharedPair(s, 'asset')
	};
	after(() => s.release());

	for (const kind of ['plain', 'asset'] as const)
		for (const [initiator, giver] of [
			[0, 'opener'],
			[1, 'opener'],
			[0, 'acceptor'],
			[1, 'acceptor']
		] as const)
			it(`agrees on a ${kind} parent with side ${initiator} initiating and the ${giver} giving, then stops at the fence`, async () => {
				const p = await pairs[kind]();
				const I = initiator,
					A = (1 - initiator) as 0 | 1;
				const reference = randomBytes(16);
				agreeOnTerms(p, { giver });
				const rows = p.stores.map(tableRows);
				const keys = p.stores.map(allocatedKeyIndex);
				const parent = p.stores.map((st) => st.loadFinalChannelType(p.id));
				const info = p.managers.map((m) => m.finalOpeningInfo(p.channelId)[0]);
				const mark = p.link.delivered.length,
					log = p.hostLog.length;
				const start = track(
					startConversion(p.managers[I], p.channelId, { reference })
				);
				await p.settle();
				await start.done;
				expect(start.error, 'start').to.equal(undefined);

				// The message order of section 6.
				const wire = conversionMessages(p, mark);
				expect(wire.map((m) => m.from + ':' + m.name)).to.deep.equal([
					`${I}:conversion_terms`,
					`${A}:conversion_reply`,
					`${I}:STFU`,
					`${A}:STFU`,
					`${I}:SPLICE`,
					`${A}:SPLICE_ACK`,
					`${I}:TX_ABORT`,
					`${A}:TX_ABORT`
				]);
				const terms = storeTerms(p.stores[I], p.id, { giver, reference });
				const { digest, attempt, bytes } = termsIdentity(terms);
				const sent = readTerms([wire[0]]);
				expect(sent.attempt).to.equal(attempt.toString('hex'));
				expect(sent.bytes.toString()).to.equal(bytes.toString());
				expect(readReply(wire[1])).to.deep.equal({
					attempt: attempt.toString('hex'),
					digest: digest.toString('hex'),
					accept: true
				});
				expect(wire[2].payload).to.deep.equal(stfu(p.channelId, true));
				expect(wire[3].payload).to.deep.equal(stfu(p.channelId, false));
				const init = decodeSpliceInit(wire[4].payload);
				expect(encodeSpliceInit(init)).to.deep.equal(wire[4].payload);
				expect(init.channelId).to.deep.equal(p.channelId);
				expect(isValidPublicKey(init.fundingPubkey)).to.equal(true);
				expect(init.relativeSatoshis).to.equal(
					BigInt(terms.contributions[roleOf(p.stores[I], p.id)])
				);
				expect(init.fundingFeeratePerkw).to.equal(terms.fees.feeratePerKw);
				expect(init.locktime).to.be.at.most(PAIR_HEIGHT + 1);
				expect(init.lockDepth).to.equal(3);
				expect(init.requireConfirmedInputs).to.not.equal(true);
				expect(init.conversion).to.deep.equal({
					termsDigest: digest,
					targetType: Buffer.from(terms.targetType, 'hex')
				});
				const ack = decodeSpliceAck(wire[5].payload);
				expect(encodeSpliceAck(ack)).to.deep.equal(wire[5].payload);
				expect(isValidPublicKey(ack.fundingPubkey)).to.equal(true);
				expect(ack.fundingPubkey).to.not.deep.equal(init.fundingPubkey);
				expect(ack.relativeSatoshis).to.equal(
					BigInt(terms.contributions[roleOf(p.stores[A], p.id)])
				);
				expect(ack.lockDepth).to.equal(3);
				expect(ack.conversion).to.deep.equal(init.conversion);
				expect(abortText(wire[6])).to.equal(FENCE);
				// The echo repeats the data it received (v3.1 item 5).
				expect(wire[7].payload).to.deep.equal(wire[6].payload);

				// Both hosts, in order, with the same canonical terms and digest.
				const calls = p.hostLog.slice(log);
				expect(calls.map((c) => c.side + ':' + c.name)).to.deep.equal([
					`${I}:conversionTerms`,
					`${I}:verifyConversionTerms`,
					`${A}:verifyConversionTerms`,
					`${A}:abandonConversion`,
					`${I}:abandonConversion`
				]);
				const request = calls[0].args[1] as { reference: Buffer };
				expect(request.reference).to.deep.equal(reference);
				expect(calls[0].args[0]).to.not.have.property('attempt');
				const verifies = calls.filter(
					(c) => c.name === 'verifyConversionTerms'
				);
				for (const v of verifies) {
					expect(v.args[1]).to.deep.equal(JSON.parse(bytes.toString()));
					expect(v.args[2]).to.deep.equal(digest);
				}
				expect(
					conversionTerms().assetConversionTermsDigest(
						verifies[1].args[1] as IAssetConversionTerms
					)
				).to.deep.equal(digest);
				for (const [side, v] of [
					[I, verifies[0]],
					[A, verifies[1]]
				] as const) {
					const store = p.stores[side];
					const current = store.loadFinalChannelType(p.id)!;
					expect(v.args[0]).to.deep.equal({
						channelId: p.id,
						peer: p.nodeIds[1 - side],
						attempt,
						isInitiator: side === I,
						isOpener: roleOf(store, p.id) === 'opener',
						parent: {
							txid: current.funding.txid,
							outputIndex: current.funding.outputIndex,
							stateNumber: parentHeight(store, p.id, kind).toString(),
							type: kind,
							channelType: current.channelType
						},
						direction: kind === 'plain' ? 'to-asset' : 'to-plain'
					});
				}
				expect(abandoned(p, 0)).to.deep.equal([FENCE]);
				expect(abandoned(p, 1)).to.deep.equal([FENCE]);
				p.hostLog.splice(0);

				// The parent is unchanged, except each side's one key allocation.
				for (const i of [0, 1] as const) {
					expect(held(p.managers[i], p.id)).to.equal(false);
					expect(p.stores[i].loadFinalChannelType(p.id)).to.deep.equal(
						parent[i]
					);
					const now = p.managers[i].finalOpeningInfo(p.channelId)[0];
					expect(now.localBalanceMsat).to.equal(info[i].localBalanceMsat);
					expect(now.remoteBalanceMsat).to.equal(info[i].remoteBalanceMsat);
					expect(allocatedKeyIndex(p.stores[i])).to.equal(keys[i] + 1);
					const changed = changedRows(rows[i], tableRows(p.stores[i]));
					expect(changed).to.have.length(2);
					expect(
						changed.every((r) =>
							/^[+-] metadata \{"key":"channel_key_index_allocated"/.test(r)
						),
						changed.join('\n')
					).to.equal(true);
				}
				expect(p.errors).to.deep.equal([[], []]);
				await updateRound(p);
			});
});

describe("The engine's checks of the terms (#2151 step 3a, test 2)", function () {
	this.timeout(60000);
	const s = scratch('conversion-checks-');
	const pairs = {
		plain: sharedPair(s, 'plain', undefined, (p) => p.link.script(0)),
		asset: sharedPair(s, 'asset', undefined, (p) => p.link.script(0))
	};
	after(() => s.release());

	/** Side 0 sends `terms` (or `bytes`) and side 1's answer is returned. */
	async function answer(
		p: IConversionPair,
		terms: IAssetConversionTerms,
		bytes?: Buffer,
		attemptOverride?: Buffer
	): Promise<ReturnType<typeof readReply> | undefined> {
		const id = termsIdentity(terms, bytes);
		const mark = p.link.inbox[0].length;
		for (const raw of termsFrames(attemptOverride ?? id.attempt, id.bytes))
			p.link.send(0, BEIGNET_CUSTOM_MESSAGE_TYPE, raw);
		await p.settle();
		const replies = p.link.inbox[0]
			.slice(mark)
			.filter((m) => m.name === 'conversion_reply');
		const reply = replies[0] && readReply(replies[0]);
		// Withdraw an accepted attempt, so the next case starts clean.
		if (reply?.accept) {
			p.link.send(
				0,
				BEIGNET_CUSTOM_MESSAGE_TYPE,
				replyMessage(id.attempt, id.digest, 'Asset conversion withdrawn')
			);
			await p.settle();
		}
		return reply;
	}
	const base = (p: IConversionPair): IAssetConversionTerms =>
		storeTerms(p.stores[0], p.id);
	type Case = [
		string,
		(t: IAssetConversionTerms, p: IConversionPair) => void,
		string
	];
	const cases: Case[] = [
		[
			'version 2',
			(t): unknown => ((t as { version: number }).version = 2),
			'Unsupported asset conversion terms version'
		],
		[
			'another parent txid',
			(t): unknown => (t.parent.txid = 'ab'.repeat(32)),
			'Asset conversion terms name a different parent'
		],
		[
			'another output index',
			(t): unknown => (t.parent.outputIndex += 1),
			'Asset conversion terms name a different parent'
		],
		[
			'another state number',
			(t): unknown =>
				(t.parent.stateNumber = String(BigInt(t.parent.stateNumber) + 1n)),
			'Asset conversion terms name a different parent'
		],
		[
			'the other direction',
			(t): unknown =>
				(t.direction = t.direction === 'to-asset' ? 'to-plain' : 'to-asset'),
			'Asset conversion names a different target type'
		],
		[
			'the plain type with the alias bit',
			(t, p): unknown =>
				(t.targetType =
					p.kind === 'plain'
						? '0100000000000000000000'
						: '0100000000000000008000'),
			'Asset conversion names a different target type'
		],
		[
			"the opener's dust limit",
			(t): unknown => (t.candidate.dustLimitSatoshis.opener = '355'),
			"Asset conversion channel parameters differ from the channel's"
		],
		[
			"the acceptor's dust limit",
			(t): unknown => (t.candidate.dustLimitSatoshis.acceptor = '353'),
			"Asset conversion channel parameters differ from the channel's"
		],
		[
			"the opener's HTLC limit",
			(t): unknown => (t.candidate.maxAcceptedHtlcs.opener -= 1),
			"Asset conversion channel parameters differ from the channel's"
		],
		[
			"the acceptor's HTLC limit",
			(t): unknown => (t.candidate.maxAcceptedHtlcs.acceptor -= 1),
			"Asset conversion channel parameters differ from the channel's"
		],
		[
			'no issuance',
			(t): void => {
				t.units.issuances = [];
				if (t.firstCommitment.units) t.firstCommitment.units = [];
			},
			'Invalid asset conversion units'
		],
		[
			'a first commitment split that misses one unit',
			(t, p): void => {
				if (p.kind === 'plain') t.firstCommitment.units![0].acceptor = '1';
				else
					t.firstCommitment.units = [
						{
							assetId: t.units.issuances[0].assetId,
							opener: '1000',
							acceptor: '0'
						}
					];
			},
			'Invalid asset conversion units'
		],
		[
			'a funding feerate of 0',
			(t): unknown => (t.fees.feeratePerKw = 0),
			'Invalid asset conversion amounts or fees'
		],
		[
			'a withdrawal payer to an asset',
			(t): unknown => (t.fees.withdrawalPayer = 'opener'),
			'Invalid asset conversion amounts or fees'
		],
		[
			'another commitment feerate',
			(t): unknown => (t.firstCommitment.commitmentFeeratePerKw += 1),
			"Asset conversion commitment feerate differs from the channel's"
		],
		[
			'an expired agreement',
			(t): unknown => (t.agreement.expiresAt = 1000),
			'Asset conversion agreement has expired'
		],
		[
			'lock depth 2',
			(t): unknown => (t.lockDepth = 2),
			'Asset conversion lock depth must be 3 to 6'
		],
		[
			'lock depth 7',
			(t): unknown => (t.lockDepth = 7),
			'Asset conversion lock depth must be 3 to 6'
		]
	];

	for (const kind of ['plain', 'asset'] as const) {
		it(`accepts the store-derived terms on a ${kind} parent at the acceptor`, async () => {
			const p = await pairs[kind]();
			expect(await answer(p, base(p))).to.include({ accept: true });
		});
		for (const [what, change, text] of cases.filter(
			// To plain a withdrawal payer is allowed either way: nothing to refuse.
			([name]) => kind === 'plain' || !name.startsWith('a withdrawal payer')
		))
			it(`declines ${what} on a ${kind} parent with "${text}"`, async () => {
				const p = await pairs[kind]();
				const t = base(p);
				change(t, p);
				expect(await answer(p, t)).to.deep.include({
					accept: false,
					reason: text
				});
			});
		const direction = kind === 'plain' ? 'to-asset' : 'to-plain';
		for (const g of GRAMMAR_CASES.filter(
			(c) => c.applies === 'both' || c.applies === direction
		))
			it(`declines ${g.what} on a ${kind} parent with "${g.text}" (grammar)`, async () => {
				const p = await pairs[kind]();
				const t = base(p);
				g.change(t);
				expect(await answer(p, t)).to.deep.include({
					accept: false,
					reason: g.text
				});
			});
		it(`declines terms whose bytes are not canonical on a ${kind} parent`, async () => {
			const p = await pairs[kind]();
			const t = base(p);
			const spaced = Buffer.from(JSON.stringify(t, null, 1));
			const { lockDepth, version, ...rest } = t;
			const reordered = Buffer.from(
				JSON.stringify({ lockDepth, version, ...rest })
			);
			const extra = Buffer.from(JSON.stringify({ ...t, note: 'x' }));
			for (const bytes of [spaced, reordered, extra])
				expect(await answer(p, t, bytes)).to.deep.include({
					accept: false,
					reason: 'Invalid asset conversion terms'
				});
		});
		it(`declines terms whose attempt id does not match their bytes on a ${kind} parent`, async () => {
			const p = await pairs[kind]();
			expect(
				await answer(p, base(p), undefined, Buffer.alloc(32, 7))
			).to.deep.include({
				accept: false,
				reason: 'Invalid asset conversion terms'
			});
		});
		it(`drops terms naming a channel that is not the sender's on a ${kind} parent`, async () => {
			const p = await pairs[kind]();
			const t = base(p);
			t.channelId = 'cd'.repeat(32);
			expect(await answer(p, t)).to.equal(undefined);
			// The channel still answers terms of its own afterwards.
			expect(await answer(p, base(p))).to.include({ accept: true });
		});
	}
});

describe("The initiator's checks of its host's terms (#2151 step 3a, test 2)", function () {
	this.timeout(60000);
	const s = scratch('conversion-initiator-checks-');
	const shared = sharedPair(s, 'plain');
	let p: IConversionPair;
	after(() => s.release());

	async function startWith(
		change: (t: IAssetConversionTerms, reference: Buffer) => unknown
	): Promise<{ error?: string; wire: string[]; calls: string[] }> {
		const mark = p.link.delivered.length,
			log = p.hostLog.length;
		p.hosts[0].terms = (_ctx, request): IAssetConversionTerms => {
			const t = storeTerms(p.stores[0], p.id, { reference: request.reference });
			const out = change(t, request.reference);
			return (out ?? t) as IAssetConversionTerms;
		};
		p.hosts[1].terms = (): IAssetConversionTerms =>
			storeTerms(p.stores[1], p.id);
		const start = track(
			startConversion(p.managers[0], p.channelId, {
				reference: Buffer.alloc(8, 1)
			})
		);
		await p.settle();
		await start.done;
		return {
			error: start.error,
			wire: p.link.delivered.slice(mark).map((m) => m.from + ':' + m.name),
			calls: p.hostLog.slice(log).map((c) => c.side + ':' + c.name)
		};
	}

	for (const [what, change, text] of [
		[
			'version 2',
			(t: IAssetConversionTerms): unknown =>
				((t as { version: number }).version = 2),
			'Unsupported asset conversion terms version'
		],
		[
			'another channel id',
			(t: IAssetConversionTerms): unknown => (t.channelId = 'cd'.repeat(32)),
			'Asset conversion terms name a different parent'
		],
		[
			'another target type',
			(t: IAssetConversionTerms): unknown =>
				(t.targetType = '0100000000000000000000'),
			'Asset conversion names a different target type'
		],
		[
			'another agreement reference',
			(t: IAssetConversionTerms): unknown => (t.agreement.reference = 'beef'),
			'Asset conversion terms name a different agreement'
		],
		[
			'an odd-length reference',
			(t: IAssetConversionTerms): unknown => (t.agreement.reference = 'abc'),
			'Invalid asset conversion agreement reference'
		],
		[
			'lock depth 7',
			(t: IAssetConversionTerms): unknown => (t.lockDepth = 7),
			'Asset conversion lock depth must be 3 to 6'
		],
		[
			'an extra key',
			(t: IAssetConversionTerms): unknown => ({ ...t, note: 1 }),
			'Invalid asset conversion terms'
		]
	] as const)
		it(`ends its own start on ${what} before any wire, with "${text}"`, async () => {
			p = await shared();
			const r = await startWith(change);
			expect(r.error).to.equal(text);
			expect(r.wire).to.deep.equal([]);
			// No attempt reached verifyConversionTerms, so nothing is abandoned.
			expect(r.calls).to.deep.equal(['0:conversionTerms']);
			expect(held(p.managers[0], p.id)).to.equal(false);
		});

	it("accepts a host's terms in any key order and sends the canonical bytes", async () => {
		p = await shared();
		const reorder = (v: unknown): unknown =>
			Array.isArray(v)
				? v.map(reorder)
				: v && typeof v === 'object'
				? Object.fromEntries(
						Object.entries(v as object)
							.reverse()
							.map(([k, x]) => [k, reorder(x)])
				  )
				: v;
		const mark = p.link.delivered.length;
		const r = await startWith((t) => reorder(t));
		expect(r.error).to.equal(undefined);
		const terms = p.link.delivered
			.slice(mark)
			.filter((m) => m.name === 'conversion_terms');
		const t = storeTerms(p.stores[0], p.id, { reference: Buffer.alloc(8, 1) });
		expect(readTerms(terms).bytes.toString()).to.equal(JSON.stringify(t));
		expect(abandoned(p, 0)).to.include(FENCE);
	});
});

describe('Final channels are not announced (#2151 step 3a, test 8)', function () {
	this.timeout(60000);
	const s = scratch('conversion-unannounced-');
	after(() => s.release());
	for (const kind of ['plain', 'asset'] as const)
		it(`never announces a ready ${kind} final channel, even past six confirmations`, async () => {
			// A plain pair does not reconnect on the base (v3.1 item 1), so the
			// plain case stays off the wire and pins the managers alone.
			const p = await conversionPair(s, kind, {
				connect: kind === 'asset'
			});
			const events: string[] = [];
			for (const m of p.managers) {
				const e = m as unknown as {
					emit(name: string | symbol, ...args: unknown[]): boolean;
				};
				const emit = e.emit.bind(m);
				e.emit = (name, ...args): boolean => {
					events.push(String(name));
					return emit(name, ...args);
				};
			}
			for (let h = PAIR_HEIGHT + 1; h <= PAIR_HEIGHT + 12; h++)
				for (const m of p.managers) m.handleNewBlock(h);
			await p.settle();
			const gossip = [
				MessageType.ANNOUNCEMENT_SIGNATURES,
				MessageType.CHANNEL_ANNOUNCEMENT,
				MessageType.CHANNEL_UPDATE
			];
			expect(p.link.sent.filter((m) => gossip.includes(m.type))).to.deep.equal(
				[]
			);
			expect(events.filter((e) => /announce/i.test(e))).to.deep.equal([]);
			for (const store of p.stores) {
				const session = store.loadFinalOpeningSession(p.id)!;
				expect(JSON.stringify(session)).to.not.match(/announce/i);
			}
		});
});

describe('A reply naming another attempt (#2151 step 3a, test 9)', function () {
	this.timeout(60000);
	const s = scratch('conversion-other-reply-');
	after(() => s.release());
	it('is ignored by the initiator, whose attempt goes on to the fence', async () => {
		const p = await conversionPair(s, 'plain');
		agreeOnTerms(p);
		// Hold side 1's real reply, inject one for another attempt and another digest first.
		p.link.hold({ from: 1, name: 'conversion_reply' });
		const start = track(
			startConversion(p.managers[0], p.channelId, {
				reference: Buffer.alloc(4, 2)
			})
		);
		await p.settle();
		await start.done;
		expect(p.link.held.map((m) => m.name)).to.deep.equal(['conversion_reply']);
		// The start resolves once the terms are sent, before any reply (v3.1 item 2).
		expect(start).to.include({ settled: true, error: undefined });
		const real = readReply(p.link.held[0]);
		p.link.inject(
			1,
			BEIGNET_CUSTOM_MESSAGE_TYPE,
			replyMessage(
				Buffer.alloc(32, 9),
				Buffer.from(real.digest, 'hex'),
				'Other'
			)
		);
		// An accept must carry D (v3.1 item 7).
		p.link.inject(
			1,
			BEIGNET_CUSTOM_MESSAGE_TYPE,
			replyMessage(Buffer.from(real.attempt, 'hex'), Buffer.alloc(32, 9))
		);
		await p.settle();
		expect(abandoned(p, 0)).to.deep.equal([]);
		expect(held(p.managers[0], p.id)).to.equal(true);
		p.link.clearRules();
		p.link.release();
		await p.settle();
		expect(abandoned(p, 0)).to.deep.equal([FENCE]);
		expect(abandoned(p, 1)).to.deep.equal([FENCE]);
	});

	it('takes a decline by attempt id whatever its digest field', async () => {
		const p = await conversionPair(s, 'asset');
		agreeOnTerms(p);
		p.link.hold({ from: 1, name: 'conversion_reply' });
		const start = track(
			startConversion(p.managers[0], p.channelId, {
				reference: Buffer.alloc(4, 3)
			})
		);
		await p.settle();
		await start.done;
		const real = readReply(p.link.held[0]);
		p.link.held.splice(0);
		p.link.inject(
			1,
			BEIGNET_CUSTOM_MESSAGE_TYPE,
			replyMessage(
				Buffer.from(real.attempt, 'hex'),
				Buffer.alloc(32, 9),
				'Declined elsewhere'
			)
		);
		await p.settle();
		expect(abandoned(p, 0)).to.deep.equal(['Declined elsewhere']);
		expect(held(p.managers[0], p.id)).to.equal(false);
	});
});

describe('A plain channel of a generation 6 wallet reconnects (#2151 step 3a, v3.1 item 1)', function () {
	this.timeout(60000);
	const s = scratch('conversion-reconnect-');
	after(() => s.release());
	it('sends channel_reestablish from both sides with a complete recovery host, then takes an update round', async () => {
		// The pair's setup is the reconnect: it calls handlePeerReconnected on both sides.
		const p = await conversionPair(s, 'plain');
		expect(
			p.link.sent
				.filter((m) => m.name === 'CHANNEL_REESTABLISH')
				.map((m) => m.from)
				.sort()
		).to.deep.equal([0, 1]);
		expect([p.ready(0), p.ready(1)]).to.deep.equal([true, true]);
		await updateRound(p);
		p.disconnect();
		await p.reconnect();
		expect(
			p.link.sent.filter((m) => m.name === 'CHANNEL_REESTABLISH')
		).to.have.length(4);
		await updateRound(p);
	});
});
