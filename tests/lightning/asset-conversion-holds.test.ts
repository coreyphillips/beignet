/**
 * #2151 Step 3a, contract tests 7 (holds) and 10 (crossings): two
 * ChannelManagers with a live conversion attempt between them.
 */
import { expect } from 'chai';
import { createHash } from 'crypto';
import sinon from 'sinon';
import { encodeUpdateAddHtlcMessage } from '../../src/lightning/message/channel-update';
import {
	BEIGNET_CUSTOM_MESSAGE_TYPE,
	BeignetCustomSubtype,
	encodeCustomMessage
} from '../../src/lightning/message/custom';
import { MessageType } from '../../src/lightning/message/types';
import { scratch } from './helpers/channel-type-pairs';
import {
	abandoned,
	abortText,
	agreeOnTerms,
	conversionPair,
	FENCE,
	held,
	PAIR_HEIGHT,
	readReply,
	startConversion,
	stfu,
	storeTerms,
	termsFrames,
	termsIdentity,
	tick,
	track,
	txAbort,
	updateRound,
	type IConversionPair
} from './helpers/conversion-managers';
import { encodeUpdateFeeMessage } from '../../src/lightning/message/channel-update';

const IN_PROGRESS = 'A conversion of this channel is in progress';
const REF = Buffer.alloc(8, 0x31);
const hashOf = (b: Buffer): Buffer => createHash('sha256').update(b).digest();

async function start(
	p: IConversionPair,
	side: 0 | 1 = 0
): Promise<ReturnType<typeof track>> {
	agreeOnTerms(p);
	const t = track(
		startConversion(p.managers[side], p.channelId, { reference: REF })
	);
	await p.settle();
	return t;
}

/** Every local start the hold covers, on side i. Each returns its refusal text or undefined. */
async function localStarts(
	p: IConversionPair,
	i: 0 | 1
): Promise<Record<string, string | undefined>> {
	const out: Record<string, string | undefined> = {};
	const text = async (f: () => unknown): Promise<string | undefined> => {
		try {
			const r = (await f()) as { ok?: boolean; error?: string } | undefined;
			return r && r.ok === false ? r.error : undefined;
		} catch (e) {
			return (e as Error).message;
		}
	};
	const m = p.managers[i];
	if (p.kind === 'plain') {
		out.add = await text(() =>
			m.addHtlc(
				p.channelId,
				1_000_000n,
				hashOf(Buffer.alloc(32, 8)),
				PAIR_HEIGHT + 100,
				Buffer.alloc(1366)
			)
		);
		if (i === p.opener)
			out.fee = await text(() => m.updateChannelFee(p.channelId, 555));
		out.splice = await text(() =>
			m.startFinalSplice(p.channelId, {
				localDelta: '-10000',
				feeBudget: '2000',
				feerate: 1000,
				locktime: PAIR_HEIGHT,
				inputs: [],
				outputs: []
			} as unknown as Parameters<typeof m.startFinalSplice>[1])
		);
	} else {
		out.add = await text(() =>
			m.startAssetSpliceUpdate(p.channelId, [
				{
					kind: 'add',
					htlc: {
						id: 0n,
						offeredBy: 'local',
						amountMsat: 1_000_000n,
						paymentHash: hashOf(Buffer.alloc(32, 8)),
						cltvExpiry: PAIR_HEIGHT + 100,
						allocations: []
					}
				}
			])
		);
		// Only the opener may change the fee, on either type.
		if (i === p.opener)
			out.fee = await text(() =>
				m.startAssetSpliceUpdate(p.channelId, [
					{ kind: 'fee', feeratePerKw: 1555 }
				])
			);
		out.splice = await text(() =>
			m.startAssetSplice(p.channelId, {
				fundingFeeratePerkw: 1000,
				minimumDepth: 3
			})
		);
	}
	return out;
}

describe('Holds while an attempt is live (#2151 step 3a, test 7)', function () {
	this.timeout(60000);
	const s = scratch('conversion-holds-');
	after(() => s.release());

	for (const kind of ['plain', 'asset'] as const)
		it(`refuses every local start on a ${kind} channel at both sides while held, and each works after the end`, async () => {
			const p = await conversionPair(s, kind);
			// I announced and A accepted: hold I's stfu(1).
			p.link.hold({ from: 0, name: 'STFU' });
			await start(p);
			for (const i of [0, 1] as const) {
				expect(held(p.managers[i], p.id), 'held ' + i).to.equal(true);
				const refused = await localStarts(p, i);
				for (const [what, error] of Object.entries(refused))
					expect(error, `${what} at side ${i}`).to.equal(IN_PROGRESS);
			}
			p.link.clearRules();
			p.link.release();
			await p.settle();
			expect(abandoned(p, 0)).to.deep.equal([FENCE]);
			expect([
				held(p.managers[0], p.id),
				held(p.managers[1], p.id)
			]).to.deep.equal([false, false]);
			await updateRound(p);
		});

	it('refuses an asset update start and an asset splice start queued before the conversion start', async () => {
		const p = await conversionPair(s, 'asset');
		agreeOnTerms(p);
		p.link.hold({ from: 0, name: 'STFU' });
		const update = track(
			p.managers[0].startAssetSpliceUpdate(p.channelId, [
				{ kind: 'fee', feeratePerKw: 1444 }
			])
		);
		const splice = track(
			p.managers[0].startAssetSplice(p.channelId, {
				fundingFeeratePerkw: 1000,
				minimumDepth: 3
			})
		);
		const conversion = track(
			startConversion(p.managers[0], p.channelId, { reference: REF })
		);
		await p.settle();
		await Promise.all([update.done, splice.done, conversion.done]);
		expect(update.error).to.equal(IN_PROGRESS);
		expect(splice.error).to.equal(IN_PROGRESS);
		expect(p.link.sent.some((m) => m.name === 'asset_update')).to.equal(false);
	});

	it("lets a local fail and an inbound plain update go as today before the side's own stfu", async () => {
		const p = await conversionPair(s, 'plain');
		agreeOnTerms(p);
		// I's terms wait on the link while A adds an HTLC to I and I fails it.
		p.link.hold({ from: 0, name: 'conversion_terms' });
		await start(p);
		expect(held(p.managers[0], p.id)).to.equal(true);
		const add = p.managers[1].addHtlc(
			p.channelId,
			1_000_000n,
			hashOf(Buffer.alloc(32, 7)),
			PAIR_HEIGHT + 100,
			Buffer.alloc(1366)
		);
		expect(add.ok, add.error).to.equal(true);
		await p.settle();
		expect(
			p.managers[0].finalReceivedHtlc(p.channelId, 0n),
			'inbound add delivered'
		).to.not.equal(undefined);
		const fail = p.managers[0].failHtlc(p.channelId, 0n, Buffer.alloc(32));
		expect(fail.ok, fail.error).to.equal(true);
		await p.settle();
		expect(
			p.managers[0].finalReceivedHtlc(p.channelId, 0n),
			'fail committed'
		).to.equal(undefined);
		p.link.clearRules();
		p.link.release();
		await p.settle();
		// The two rounds moved the state number past the held terms' (check 2).
		expect(abandoned(p, 0)).to.deep.equal([
			'Asset conversion terms name a different parent'
		]);
		await updateRound(p);
	});

	it('handles an inbound asset update before the stfu as today, and the next check refuses its HTLC', async () => {
		const p = await conversionPair(s, 'asset');
		agreeOnTerms(p);
		p.link.hold({ from: 0, name: 'conversion_terms' });
		await start(p);
		const before = p.stores[0].assetSpliceUpdateHead(p.id).nextNumber;
		await p.managers[1].startAssetSpliceUpdate(p.channelId, [
			{
				kind: 'add',
				htlc: {
					id: 0n,
					offeredBy: 'local',
					amountMsat: 1_000_000n,
					paymentHash: hashOf(Buffer.alloc(32, 6)),
					cltvExpiry: PAIR_HEIGHT + 100,
					allocations: []
				}
			}
		]);
		await p.settle();
		expect(p.stores[0].assetSpliceUpdateHead(p.id).nextNumber).to.equal(
			before + 1n
		);
		p.link.clearRules();
		p.link.release();
		await p.settle();
		const ends = [...abandoned(p, 0), ...abandoned(p, 1)];
		expect(ends).to.include('Asset conversion requires a channel with no HTLC');
	});
});

describe('Crossings (#2151 step 3a, test 10)', function () {
	this.timeout(60000);
	const s = scratch('conversion-crossings-');
	let clock: sinon.SinonFakeTimers | undefined;
	afterEach(() => {
		clock?.restore();
		clock = undefined;
	});
	after(() => s.release());

	it("refuses a new local splice until the fence's echo arrives, then starts it", async () => {
		const p = await conversionPair(s, 'plain');
		p.link.hold({ from: 1, name: 'TX_ABORT' });
		await start(p);
		const plan = {
			localDelta: '-10000',
			feeBudget: '2000',
			feerate: 1000,
			locktime: PAIR_HEIGHT,
			inputs: [],
			outputs: []
		} as unknown as Parameters<(typeof p.managers)[0]['startFinalSplice']>[1];
		expect(() => p.managers[0].startFinalSplice(p.channelId, plan)).to.throw(
			IN_PROGRESS
		);
		p.link.clearRules();
		p.link.release();
		await p.settle();
		expect(abandoned(p, 0)).to.deep.equal([FENCE]);
		const mark = p.link.sent.length;
		p.managers[0].startFinalSplice(p.channelId, plan);
		await p.settle();
		expect(
			p.link.sent.slice(mark).map((m) => m.from + ':' + m.name)
		).to.include('0:STFU');
	});

	it('answers a stfu that crosses its decline with tx_abort from draining, opening no plain acceptor attempt', async () => {
		const p = await conversionPair(s, 'plain');
		p.link.hold({ from: 0, name: 'STFU' });
		await start(p);
		// A declines after its accept (a local close), goes draining.
		p.managers[1].initiateShutdown(
			p.channelId,
			Buffer.from('0014' + '22'.repeat(20), 'hex')
		);
		p.link.clearRules();
		p.link.release();
		await p.settle();
		const fromA = p.link.delivered.filter((m) => m.from === 1);
		expect(
			fromA.filter((m) => m.name === 'TX_ABORT').map(abortText)
		).to.deep.equal(['Asset conversion withdrawn']);
		expect(fromA.some((m) => m.name === 'STFU')).to.equal(false);
		expect(abandoned(p, 1)).to.deep.equal([
			'Asset conversion ended by a close'
		]);
	});

	/** The texts of the tx_abort messages side `from` put on the link since `mark`. */
	const abortsFrom = (p: IConversionPair, from: 0 | 1, mark = 0): string[] =>
		p.link.sent
			.slice(mark)
			.filter((m) => m.from === from && m.name === 'TX_ABORT')
			.map(abortText);
	const WITHDRAWN = 'Asset conversion withdrawn';
	const CLOSED = 'Asset conversion ended by a close';
	const TIMED_OUT = 'Asset conversion timed out';
	const closeA = (p: IConversionPair): void => {
		p.managers[1].initiateShutdown(
			p.channelId,
			Buffer.from('0014' + '22'.repeat(20), 'hex')
		);
	};

	it('answers once from draining when stfu(1) and tx_abort reach it in one turn, and I ends on that answer (v2.4 item 1)', async () => {
		const p = await conversionPair(s, 'plain', { quiescenceTimeoutMs: 5_000 });
		clock = sinon.useFakeTimers({
			now: Date.now(),
			toFake: ['Date', 'setTimeout', 'clearTimeout']
		});
		p.link.hold({ from: 0, name: 'STFU' });
		p.link.hold({ from: 0, name: 'TX_ABORT' });
		await start(p);
		// A declines after its accept (a local close), goes draining.
		closeA(p);
		await p.settle();
		// I's deadline fails it in quiescing, right after its stfu(1).
		await tick(p, clock, 5_000);
		expect(p.link.held.map((m) => m.from + ':' + m.name)).to.deep.equal([
			'0:STFU',
			'0:TX_ABORT'
		]);
		const mark = p.link.sent.length;
		p.link.clearRules();
		p.link.burst(
			(m) => m.from === 0 && (m.name === 'STFU' || m.name === 'TX_ABORT')
		);
		p.link.release();
		await p.settle();
		expect(abortsFrom(p, 1, mark), "A's answer").to.deep.equal([WITHDRAWN]);
		expect(abandoned(p, 0), 'I ends on it as its echo').to.deep.equal([
			TIMED_OUT
		]);
		expect(abandoned(p, 1)).to.deep.equal([CLOSED]);
		// Past both phase bounds: nobody waited for an echo.
		await tick(p, clock, 20_000);
		expect(p.recycled).to.deep.equal([[], []]);
		expect(abortsFrom(p, 0)).to.deep.equal([TIMED_OUT]);
		expect(abortsFrom(p, 1)).to.deep.equal([WITHDRAWN]);
		expect(abandoned(p, 0)).to.deep.equal([TIMED_OUT]);
		expect(abandoned(p, 1)).to.deep.equal([CLOSED]);
		expect([
			held(p.managers[0], p.id),
			held(p.managers[1], p.id)
		]).to.deep.equal([false, false]);
	});

	it('answers once from draining a tx_abort with no stfu(1) before it (v2.4 item 1)', async () => {
		const p = await conversionPair(s, 'plain');
		p.link.hold({ from: 0, name: 'STFU' });
		await start(p);
		closeA(p);
		await p.settle();
		const mark = p.link.sent.length;
		p.link.inject(0, MessageType.TX_ABORT, txAbort(p.channelId, CLOSED));
		const injected = p.link.sent.length;
		await p.settle();
		expect(abortsFrom(p, 1, mark), "A's answer").to.deep.equal([WITHDRAWN]);
		expect(abandoned(p, 1)).to.deep.equal([CLOSED]);
		// I, still quiescing, takes the answer as a peer tx_abort: it echoes and ends.
		expect(abortsFrom(p, 0, injected)).to.deep.equal([WITHDRAWN]);
		expect(abandoned(p, 0)).to.deep.equal([WITHDRAWN]);
		p.link.held.splice(0);
		expect(abortsFrom(p, 1, mark), 'A answers once').to.deep.equal([WITHDRAWN]);
		expect(p.recycled).to.deep.equal([[], []]);
	});

	it('sends nothing more from aborting when the tx_abort messages of both sides cross (v2.4 item 1)', async () => {
		const p = await conversionPair(s, 'plain');
		const DESCRIBE = 'Asset conversion host could not describe the layout';
		const PREPARE = 'Asset conversion host could not prepare the layout';
		p.hosts[0].describe = (): unknown => {
			throw new Error('no description');
		};
		p.hosts[1].prepare = (): unknown => {
			throw new Error('no plan');
		};
		p.link.hold('TX_ABORT');
		await start(p);
		expect(p.link.held.map((m) => m.from + ':' + abortText(m))).to.have.members(
			['0:' + DESCRIBE, '1:' + PREPARE]
		);
		p.link.clearRules();
		p.link.release();
		await p.settle();
		expect(abortsFrom(p, 0)).to.deep.equal([DESCRIBE]);
		expect(abortsFrom(p, 1)).to.deep.equal([PREPARE]);
		expect(abandoned(p, 0)).to.deep.equal([DESCRIBE]);
		expect(abandoned(p, 1)).to.deep.equal([PREPARE]);
		expect(p.recycled).to.deep.equal([[], []]);
	});

	it('passes a stale asset splice echo to the asset splice transport while the conversion owns no wire', async () => {
		const p = await conversionPair(s, 'asset');
		p.link.hold({ from: 1, name: 'conversion_reply' });
		await start(p);
		p.link.inject(
			1,
			MessageType.TX_ABORT,
			txAbort(p.channelId, 'Splice abandoned')
		);
		await p.settle();
		expect(abandoned(p, 0)).to.deep.equal([]);
		expect(held(p.managers[0], p.id)).to.equal(true);
		p.link.clearRules();
		p.link.release();
		await p.settle();
		expect(abandoned(p, 0)).to.deep.equal([FENCE]);
	});

	for (const kind of ['plain', 'asset'] as const)
		it(`aborts on a peer update in the quiet window of a ${kind} channel, then delivers it`, async () => {
			const p = await conversionPair(s, kind);
			p.link.hold({ from: 1, name: 'SPLICE_ACK' });
			await start(p);
			const update =
				kind === 'plain'
					? {
							type: MessageType.UPDATE_ADD_HTLC,
							payload: encodeUpdateAddHtlcMessage({
								channelId: p.channelId,
								id: 0n,
								amountMsat: 1_000_000n,
								paymentHash: hashOf(Buffer.alloc(32, 5)),
								cltvExpiry: PAIR_HEIGHT + 100,
								onionRoutingPacket: Buffer.alloc(1366)
							})
					  }
					: {
							type: BEIGNET_CUSTOM_MESSAGE_TYPE,
							payload: encodeCustomMessage(
								BeignetCustomSubtype.ASSET_UPDATE,
								Buffer.concat([
									p.channelId,
									Buffer.alloc(8),
									Buffer.from([1, 0])
								])
							)
					  };
			const errorsBefore = p.errors[0].length;
			p.link.inject(1, update.type, update.payload);
			await p.settle();
			const aborts = p.link.delivered.filter(
				(m) => m.from === 0 && m.name === 'TX_ABORT'
			);
			expect(aborts.map(abortText)).to.deep.equal([
				'Peer updated the channel during conversion quiescence'
			]);
			// Delivered as today: the plain add is recorded, the asset frame reaches its transport.
			if (kind === 'plain')
				expect(p.managers[0].finalUpdateStatus(p.id)?.pending).to.deep.include({
					direction: 'peer',
					type: MessageType.UPDATE_ADD_HTLC
				});
			else expect(p.errors[0].length).to.be.at.least(errorsBefore);
		});

	for (const kind of ['plain', 'asset'] as const)
		it(`disconnects the peer when aborting has no echo for 15 seconds on a ${kind} channel`, async () => {
			const p = await conversionPair(s, kind);
			clock = sinon.useFakeTimers({
				now: Date.now(),
				toFake: ['Date', 'setTimeout', 'clearTimeout']
			});
			p.link.drop({ from: 1, name: 'TX_ABORT' });
			await start(p);
			// I sent the fence's tx_abort and waits for the echo.
			expect(
				p.link.delivered
					.filter((m) => m.from === 0 && m.name === 'TX_ABORT')
					.map(abortText)
			).to.deep.equal([FENCE]);
			await tick(p, clock, 14_000);
			expect(p.recycled[0]).to.deep.equal([]);
			await tick(p, clock, 1_500);
			expect(p.recycled[0]).to.deep.equal([p.nodeIds[1]]);
			expect(held(p.managers[0], p.id)).to.equal(false);
		});

	it('applies a peer update still queued in the final transport before the acceptor checks the terms', async () => {
		const p = await conversionPair(s, 'plain');
		expect(p.opener).to.equal(0);
		p.link.script(0);
		const t = storeTerms(p.stores[0], p.id);
		const id = termsIdentity(t);
		// No settle between the two: the update is still queued when the terms arrive.
		p.link.send(
			0,
			MessageType.UPDATE_FEE,
			encodeUpdateFeeMessage({ channelId: p.channelId, feeratePerKw: 888 })
		);
		for (const raw of termsFrames(id.attempt, id.bytes))
			p.link.send(0, BEIGNET_CUSTOM_MESSAGE_TYPE, raw);
		await p.settle();
		const reply = p.link.inbox[0].find((m) => m.name === 'conversion_reply');
		expect(reply && readReply(reply)).to.deep.include({
			accept: false,
			reason: 'Asset conversion requires a quiescent channel'
		});
	});

	it('releases the hold before awaiting abandonConversion', async () => {
		const p = await conversionPair(s, 'plain');
		clock = sinon.useFakeTimers({
			now: Date.now(),
			toFake: ['Date', 'setTimeout', 'clearTimeout']
		});
		p.hosts[0].abandon = (): Promise<void> =>
			new Promise<void>((done) => setTimeout(done, 10_000));
		await start(p);
		expect(p.hosts[0].calls('abandonConversion')).to.have.length(1);
		expect(p.hosts[0].calls('abandonConversion')[0].settled).to.not.equal(true);
		expect(held(p.managers[0], p.id)).to.equal(false);
		const r = p.managers[0].addHtlc(
			p.channelId,
			1_000_000n,
			hashOf(Buffer.alloc(32, 4)),
			PAIR_HEIGHT + 100,
			Buffer.alloc(1366)
		);
		expect(r.ok, r.error).to.equal(true);
		await tick(p, clock, 10_500);
	});

	it('withdraws when the peer sends stfu(0) to an accepted attempt, and drains', async () => {
		const p = await conversionPair(s, 'plain');
		agreeOnTerms(p);
		p.link.script(0);
		const t = storeTerms(p.stores[0], p.id);
		const id = termsIdentity(t);
		for (const raw of termsFrames(id.attempt, id.bytes))
			p.link.send(0, BEIGNET_CUSTOM_MESSAGE_TYPE, raw);
		await p.settle();
		p.link.send(0, MessageType.STFU, stfu(p.channelId, false));
		await p.settle();
		const replies = p.link.inbox[0]
			.filter((m) => m.name === 'conversion_reply')
			.map(readReply);
		expect(replies.map((r) => r.reason)).to.deep.equal([
			undefined,
			'Unexpected message during asset conversion'
		]);
		p.link.send(0, MessageType.STFU, stfu(p.channelId, true));
		await p.settle();
		expect(
			p.link.inbox[0].filter((m) => m.name === 'TX_ABORT').map(abortText)
		).to.deep.equal(['Asset conversion withdrawn']);
		p.link.send(
			0,
			MessageType.TX_ABORT,
			txAbort(p.channelId, 'Asset conversion withdrawn')
		);
		await p.settle();
		expect(held(p.managers[1], p.id)).to.equal(false);
		expect(abandoned(p, 1)).to.deep.equal([
			'Unexpected message during asset conversion'
		]);
	});
});

describe('A draining acceptor answers once (#2151 step 3b, v2.5 item 1)', function () {
	this.timeout(90000);
	const s = scratch('conversion-draining-once-');
	after(() => s.release());

	/** A scripted I takes the real A to draining: terms, then stfu(0) before A's own. */
	async function draining(): Promise<IConversionPair> {
		const p = await conversionPair(s, 'plain');
		agreeOnTerms(p);
		p.link.script(0);
		const t = storeTerms(p.stores[0], p.id);
		const id = termsIdentity(t);
		for (const raw of termsFrames(id.attempt, id.bytes))
			p.link.send(0, BEIGNET_CUSTOM_MESSAGE_TYPE, raw);
		await p.settle();
		p.link.send(0, MessageType.STFU, stfu(p.channelId, false));
		await p.settle();
		return p;
	}
	const abortsToI = (p: IConversionPair): string[] =>
		p.link.inbox[0].filter((m) => m.name === 'TX_ABORT').map(abortText);

	it('answers a repeated stfu(1) once', async () => {
		const p = await draining();
		p.link.send(0, MessageType.STFU, stfu(p.channelId, true));
		await p.settle();
		p.link.send(0, MessageType.STFU, stfu(p.channelId, true));
		await p.settle();
		expect(abortsToI(p)).to.deep.equal(['Asset conversion withdrawn']);
	});

	it('answers stfu(1) and then a tx_abort once, and ends', async () => {
		const p = await draining();
		p.link.send(0, MessageType.STFU, stfu(p.channelId, true));
		await p.settle();
		p.link.send(0, MessageType.TX_ABORT, txAbort(p.channelId, 'x'));
		await p.settle();
		expect(abortsToI(p)).to.deep.equal(['Asset conversion withdrawn']);
		expect(held(p.managers[1], p.id)).to.equal(false);
		expect(abandoned(p, 1)).to.deep.equal([
			'Unexpected message during asset conversion'
		]);
	});
});
