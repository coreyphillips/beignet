/**
 * #2151 Step 3a, contract test 4: eligibility and preconditions (sections 1
 * and 4), on the initiator before any wire and on the acceptor in its reply.
 */
import { expect } from 'chai';
import { createHash } from 'crypto';
import {
	encodeUpdateAddHtlcMessage,
	encodeUpdateFeeMessage
} from '../../src/lightning/message/channel-update';
import { BEIGNET_CUSTOM_MESSAGE_TYPE } from '../../src/lightning/message/custom';
import { MessageType } from '../../src/lightning/message/types';
import type { IAssetConversionTerms } from '../../src/lightning/channel';
import { scratch, type Scratch } from './helpers/channel-type-pairs';
import {
	assetParentBranch,
	buildConversion,
	conversionExits,
	openingParent,
	retainBoth,
	toPlain
} from './helpers/channel-type-record';
import {
	abandoned,
	agreeOnTerms,
	conversionPair,
	held,
	never,
	PAIR_HEIGHT,
	readReply,
	replyMessage,
	startConversion,
	stfu,
	storeTerms,
	termsFrames,
	termsIdentity,
	track,
	type IConversionPair,
	type IPairOptions,
	FENCE,
	updateRound,
	sharedPair
} from './helpers/conversion-managers';

const NOT_OFFERED = 'Asset conversion is not offered by this node';
const NOT_NEGOTIATED = 'Asset conversion is not negotiated with this peer';
const IN_PROGRESS = 'A conversion of this channel is in progress';

/** Side 0 starts; returns its rejection, what reached the wire and the host calls. */
async function initiate(
	p: IConversionPair,
	side: 0 | 1 = 0
): Promise<{ error?: string; wire: string[]; calls: string[] }> {
	const mark = p.link.sent.length,
		log = p.hostLog.length;
	agreeOnTerms(p);
	const start = track(
		startConversion(p.managers[side], p.channelId, {
			reference: Buffer.alloc(8, 3)
		})
	);
	await p.settle();
	await start.done;
	return {
		error: start.error,
		wire: p.link.sent
			.slice(mark)
			.filter((m) => m.from === side)
			.map((m) => m.name),
		calls: p.hostLog.slice(log).map((c) => c.side + ':' + c.name)
	};
}

/** Expect side `side`'s start to end with `text` before any host call or wire. */
async function refusedAtStart(
	p: IConversionPair,
	text: string,
	side: 0 | 1 = 0
): Promise<void> {
	const r = await initiate(p, side);
	expect(r.error).to.equal(text);
	expect(r.wire.filter((n) => n.startsWith('conversion_'))).to.deep.equal([]);
	expect(r.calls).to.deep.equal([]);
	expect(held(p.managers[side], p.id)).to.equal(false);
}

/** Side 0, scripted, sends store-derived terms; side 1's reply is returned. */
async function acceptorAnswer(
	p: IConversionPair
): Promise<ReturnType<typeof readReply> | undefined> {
	p.link.script(0);
	const t = storeTerms(p.stores[0], p.id);
	const id = termsIdentity(t);
	const mark = p.link.inbox[0].length;
	for (const raw of termsFrames(id.attempt, id.bytes))
		p.link.send(0, BEIGNET_CUSTOM_MESSAGE_TYPE, raw);
	await p.settle();
	const reply = p.link.inbox[0]
		.slice(mark)
		.find((m) => m.name === 'conversion_reply');
	return reply && readReply(reply);
}

async function pair(
	s: Scratch,
	kind: 'plain' | 'asset',
	options?: IPairOptions
): Promise<IConversionPair> {
	return conversionPair(s, kind, options);
}

describe('Asset conversion eligibility (#2151 step 3a, test 4, section 1)', function () {
	this.timeout(60000);
	const s = scratch('conversion-eligibility-');
	after(() => s.release());

	it('refuses at the initiator with no transport: a generation 5 wallet, and a host without the three members', async () => {
		await refusedAtStart(
			await pair(s, 'plain', { generations: [5, 5] }),
			NOT_OFFERED
		);
		await refusedAtStart(
			await pair(s, 'plain', { withoutHostMembers: [true, false] }),
			NOT_OFFERED
		);
	});

	it('answers terms from a generation 5 acceptor with a decline', async () => {
		const p = await pair(s, 'plain', { generations: [5, 5] });
		expect(await acceptorAnswer(p)).to.deep.include({
			accept: false,
			reason: NOT_OFFERED
		});
	});

	it('ends with the peer reason when the peer sets 463 without the host members', async () => {
		const p = await pair(s, 'plain', { withoutHostMembers: [false, true] });
		const r = await initiate(p);
		expect(r.wire.filter((n) => n.startsWith('conversion_'))).to.deep.equal([
			'conversion_terms'
		]);
		expect(abandoned(p, 0)).to.deep.equal([NOT_OFFERED]);
		expect(held(p.managers[0], p.id)).to.equal(false);
		expect(p.link.sent.some((m) => m.name === 'STFU')).to.equal(false);
		await updateRound(p);
	});

	it('refuses a peer without 463 on either side', async () => {
		await refusedAtStart(
			await pair(s, 'plain', { without463: [false, true] }),
			NOT_NEGOTIATED
		);
		const p = await pair(s, 'asset', { without463: [true, false] });
		expect(await acceptorAnswer(p)).to.deep.include({
			accept: false,
			reason: NOT_NEGOTIATED
		});
	});

	it('refuses a disconnected peer, then converts once reconnected', async () => {
		const p = await pair(s, 'asset');
		p.disconnect();
		await refusedAtStart(p, 'Asset conversion requires a connected peer');
		await p.reconnect();
		await initiate(p);
		expect(abandoned(p, 0)).to.deep.equal([FENCE]);
	});
});

describe('Asset conversion preconditions (#2151 step 3a, test 4, section 4)', function () {
	this.timeout(60000);
	const s = scratch('conversion-preconditions-');
	after(() => s.release());

	it('refuses a channel with a type record', async () => {
		const t = await toPlain(s, 0);
		const devices = t.pair.p.f.devices;
		const p = await pair(s, 'plain', {
			existing: {
				id: t.id,
				stores: t.stores(),
				roots: devices.map((d) => d.party.root),
				nodeIds: [
					devices[0].party.binding.nodeId,
					devices[1].party.binding.nodeId
				]
			}
		});
		await refusedAtStart(
			p,
			'Asset conversion of a channel with a recorded type change is not supported yet'
		);
	});

	it('refuses a plain parent opened at 483 HTLCs or with dust limits that are not 354', async () => {
		for (const terms of [
			{ remoteDustLimitSatoshis: 354, maxAcceptedHtlcs: 483 },
			{ remoteDustLimitSatoshis: 546, maxAcceptedHtlcs: 83 }
		]) {
			const p = await pair(s, 'plain', { terms });
			await refusedAtStart(
				p,
				'Asset conversion requires channel parameters that fit the asset type'
			);
		}
	});

	it('refuses an unconfirmed funding', async () => {
		await refusedAtStart(
			await pair(s, 'plain', { skipDepth: true }),
			'Asset conversion requires a confirmed live funding'
		);
	});

	it('refuses a channel whose exit was requested', async () => {
		const p = await pair(s, 'plain');
		p.stores[0].requestFinalOpeningExit(p.id);
		await refusedAtStart(p, 'Asset conversion requires an open channel');
	});

	for (const kind of ['plain', 'asset'] as const)
		it(`refuses a ${kind} channel with an HTLC, at each side and in the reply`, async () => {
			const p = await pair(s, kind);
			const hash = createHash('sha256').update(Buffer.alloc(32, 4)).digest();
			if (kind === 'plain') {
				const r = p.managers[0].addHtlc(
					p.channelId,
					5_000_000n,
					hash,
					PAIR_HEIGHT + 100,
					Buffer.alloc(1366)
				);
				expect(r.ok, r.error).to.equal(true);
			} else
				await p.managers[0].startAssetSpliceUpdate(p.channelId, [
					{
						kind: 'add',
						htlc: {
							id: 0n,
							offeredBy: 'local',
							amountMsat: 5_000_000n,
							paymentHash: hash,
							cltvExpiry: PAIR_HEIGHT + 100,
							allocations: []
						}
					}
				]);
			await p.settle();
			const text = 'Asset conversion requires a channel with no HTLC';
			await refusedAtStart(p, text, 0);
			await refusedAtStart(p, text, 1);
			expect(await acceptorAnswer(p)).to.deep.include({
				accept: false,
				reason: text
			});
		});

	it('refuses while a plain round is in flight at the initiator and at the acceptor', async () => {
		const p = await pair(s, 'plain');
		const quiet = 'Asset conversion requires a quiescent channel';
		// Hold the non-opener's revocation so the opener's round stays open.
		const other = (1 - p.opener) as 0 | 1;
		p.link.hold({ from: other, name: 'REVOKE_AND_ACK' });
		const r = p.managers[p.opener].updateChannelFee(p.channelId, 777);
		expect(r.ok, r.error).to.equal(true);
		await p.settle();
		await refusedAtStart(p, quiet, p.opener);
		await refusedAtStart(p, quiet, other);
	});

	it('declines at the acceptor while a peer update is in flight when the terms arrive', async () => {
		const p = await pair(s, 'plain');
		// Side 0 opened the fixture channel, so it may send update_fee.
		expect(p.opener).to.equal(0);
		// Side 0 (scripted) sends an update_fee, then terms before the round settles.
		p.link.script(0);
		p.link.send(
			0,
			MessageType.UPDATE_FEE,
			encodeUpdateFeeMessage({ channelId: p.channelId, feeratePerKw: 777 })
		);
		await p.settle();
		expect(await acceptorAnswer(p)).to.deep.include({
			accept: false,
			reason: 'Asset conversion requires a quiescent channel'
		});
	});

	it('ends by the failure rule when the peer updates after its own accept, before stfu', async () => {
		const p = await pair(s, 'plain');
		// The scripted acceptor adds an HTLC, which either side may offer.
		agreeOnTerms(p);
		p.link.script(1);
		const start = track(
			startConversion(p.managers[0], p.channelId, {
				reference: Buffer.alloc(8, 3)
			})
		);
		await p.settle();
		await start.done;
		const terms = p.link.inbox[1].filter((m) => m.name === 'conversion_terms');
		expect(terms).to.have.length(1);
		const t = storeTerms(p.stores[0], p.id, { reference: Buffer.alloc(8, 3) });
		const id = termsIdentity(t);
		p.link.send(
			1,
			MessageType.UPDATE_ADD_HTLC,
			encodeUpdateAddHtlcMessage({
				channelId: p.channelId,
				id: 0n,
				amountMsat: 1_000_000n,
				paymentHash: createHash('sha256').update(Buffer.alloc(32, 3)).digest(),
				cltvExpiry: PAIR_HEIGHT + 100,
				onionRoutingPacket: Buffer.alloc(1366)
			})
		);
		p.link.send(
			1,
			BEIGNET_CUSTOM_MESSAGE_TYPE,
			replyMessage(id.attempt, id.digest)
		);
		await p.settle();
		// Before its own stfu, I withdraws with a decline naming the failed check.
		const replies = p.link.inbox[1].filter(
			(m) => m.name === 'conversion_reply'
		);
		expect(replies.map(readReply)).to.deep.include({
			attempt: id.attempt.toString('hex'),
			digest: id.digest.toString('hex'),
			accept: false,
			reason: 'Asset conversion requires a quiescent channel'
		});
		expect(p.link.inbox[1].some((m) => m.name === 'STFU')).to.equal(false);
		expect(abandoned(p, 0)).to.deep.equal([
			'Asset conversion requires a quiescent channel'
		]);
	});

	it('refuses a channel with a pending conversion exit (2b)', async () => {
		const p = await pair(s, 'asset', { rounds: 1 });
		const devices = p.stores.map((store, i) => ({ store, root: p.roots[i] }));
		const c = buildConversion(devices, p.id, {
			type: 'plain',
			stateNumber: 1,
			parent: openingParent(devices[0].store, p.id)
		});
		const parents = devices.map((d) => assetParentBranch(d.store, p.id, 1));
		retainBoth(devices, p.id, conversionExits(devices, c, parents));
		await refusedAtStart(p, 'Another conversion of this channel is pending');
		await refusedAtStart(p, 'Another conversion of this channel is pending', 1);
	});

	it('refuses while an inbound asset splice request is open', async () => {
		const p = await pair(s, 'asset');
		// Side 1, scripted, asks for quiescence for an asset splice.
		p.link.script(1);
		p.link.send(1, MessageType.STFU, stfu(p.channelId, true));
		await p.settle();
		expect(p.link.inbox[1].map((m) => m.name)).to.include('STFU');
		await refusedAtStart(p, 'Asset conversion requires no pending splice');
	});

	it('refuses a queued asset splice start, and a pending plain splice', async () => {
		const a = await pair(s, 'asset');
		(
			a.dualFunding[0] as unknown as { proposeSplice: () => Promise<Buffer> }
		).proposeSplice = (): Promise<Buffer> => never<Buffer>();
		void a.managers[0]
			.startAssetSplice(a.channelId, {
				fundingFeeratePerkw: 1000,
				minimumDepth: 3
			})
			.catch(() => undefined);
		await a.settle();
		await refusedAtStart(a, 'Asset conversion requires no pending splice');
		const p = await pair(s, 'plain');
		p.link.hold({ from: 1, name: 'STFU' });
		p.managers[0].startFinalSplice(p.channelId, {
			localDelta: -10_000n,
			feeBudget: 2_000n,
			feerate: 1000,
			locktime: PAIR_HEIGHT,
			inputs: [],
			outputs: []
		} as unknown as Parameters<(typeof p.managers)[0]['startFinalSplice']>[1]);
		await p.settle();
		await refusedAtStart(p, 'Asset conversion requires no pending splice');
	});

	for (const kind of ['plain', 'asset'] as const)
		it(`reads the current commitment feerate after an update_fee round on a ${kind} parent (check 7)`, async () => {
			const p = await pair(s, kind);
			await updateRound(p);
			// Terms built from the opening's feerate are declined; the current one converts.
			const stale = storeTerms(p.stores[1], p.id);
			stale.firstCommitment.commitmentFeeratePerKw =
				p.stores[1].loadFinalOpeningSession(p.id)!.terms.commitmentFeeratePerKw;
			p.hosts[1].terms = (): IAssetConversionTerms => stale;
			const r = await initiate(p, 1);
			expect(r.error).to.equal(
				"Asset conversion commitment feerate differs from the channel's"
			);
			await initiate(p, 1);
			expect(abandoned(p, 1)).to.deep.equal([FENCE]);
		});
});

describe('A second conversion start while an attempt exists (#2151 step 3a, test 4, V2-M4)', function () {
	this.timeout(60000);
	const s = scratch('conversion-second-start-');
	const shared = sharedPair(s, 'plain');
	let p: IConversionPair;
	after(() => s.release());

	for (const [state, side, hold] of [
		['I announced', 0, { from: 1, name: 'conversion_reply' }],
		['I quiescing', 0, { from: 1, name: 'STFU' }],
		['I init-sent', 0, { from: 1, name: 'SPLICE_ACK' }],
		['I aborting', 0, { from: 1, name: 'TX_ABORT' }],
		['A accepted', 1, { from: 0, name: 'STFU' }],
		['A quiesced', 1, { from: 0, name: 'SPLICE' }],
		['A acked', 1, { from: 0, name: 'TX_ABORT' }]
	] as const)
		it(`refuses a second start in ${state}`, async () => {
			p = await shared();
			agreeOnTerms(p);
			p.hostLog.splice(0);
			p.link.hold(hold);
			const first = track(
				startConversion(p.managers[0], p.channelId, {
					reference: Buffer.alloc(8, 5)
				})
			);
			await p.settle();
			await first.done;
			const second = track(
				startConversion(p.managers[side], p.channelId, {
					reference: Buffer.alloc(8, 6)
				})
			);
			await second.done;
			expect(second.error).to.equal(IN_PROGRESS);
			p.link.clearRules();
			p.link.release();
			await p.settle();
			expect(abandoned(p, 0)).to.deep.equal([FENCE]);
			expect(held(p.managers[0], p.id) || held(p.managers[1], p.id)).to.equal(
				false
			);
		});

	it('refuses a second start at A in draining', async () => {
		p = await shared();
		agreeOnTerms(p);
		p.hostLog.splice(0);
		p.link.script(0);
		const t = storeTerms(p.stores[0], p.id);
		const id = termsIdentity(t);
		for (const raw of termsFrames(id.attempt, id.bytes))
			p.link.send(0, BEIGNET_CUSTOM_MESSAGE_TYPE, raw);
		await p.settle();
		// stfu(0) from I while A is accepted: A declines and drains.
		p.link.send(0, MessageType.STFU, stfu(p.channelId, false));
		await p.settle();
		const second = track(
			startConversion(p.managers[1], p.channelId, {
				reference: Buffer.alloc(8, 6)
			})
		);
		await second.done;
		expect(second.error).to.equal(IN_PROGRESS);
	});
});
