/**
 * #2151 Step 3a, contract test 6: refusals in the agreement. Each ends both
 * sides with the right text and abandonConversion once where section 5 says.
 */
import { expect } from 'chai';
import sinon from 'sinon';
import {
	BEIGNET_CUSTOM_MESSAGE_TYPE,
	decodeCustomMessage
} from '../../src/lightning/message/custom';
import { encodeUpdateAddHtlcMessage } from '../../src/lightning/message/channel-update';
import { MessageType } from '../../src/lightning/message/types';
import type { IAssetConversionTerms } from '../../src/lightning/channel';
import { scratch } from './helpers/channel-type-pairs';
import {
	abandoned,
	abortText,
	agreeOnTerms,
	allocatedKeyIndex,
	conversionPair,
	conversionTransportOf,
	decodeSpliceInit,
	encodeSpliceAck,
	encodeSpliceInit,
	FENCE,
	held,
	never,
	readReply,
	readTerms,
	replyMessage,
	startConversion,
	stfu,
	storeTerms,
	termsFrames,
	termsIdentity,
	tick,
	track,
	txAbort,
	updateRound,
	type IConversionPair,
	type WireMatch,
	sharedPair
} from './helpers/conversion-managers';

const DECLINED = 'Asset conversion host declined the terms';
const WITHDRAWN = 'Asset conversion withdrawn';
const DISCONNECTED = 'Peer disconnected';
const SPLICE_INIT_MISMATCH =
	'Asset conversion splice_init does not match its terms';
const SPLICE_ACK_MISMATCH =
	'Asset conversion splice_ack does not match its terms';
const EXPIRED = 'Asset conversion agreement has expired';
const CLOSE = 'Asset conversion ended by a close';
const QUIET = 'Asset conversion requires a quiescent channel';
const fakeClock = (): sinon.SinonFakeTimers =>
	sinon.useFakeTimers({
		now: Date.now(),
		toFake: ['Date', 'setTimeout', 'clearTimeout']
	});
const REF = Buffer.alloc(8, 0x21);

async function run(
	p: IConversionPair,
	side: 0 | 1 = 0
): Promise<ReturnType<typeof track>> {
	const start = track(
		startConversion(p.managers[side], p.channelId, { reference: REF })
	);
	await p.settle();
	return start;
}

function clean(p: IConversionPair): void {
	p.link.clearRules();
	p.link.held.splice(0);
	p.hostLog.splice(0);
	agreeOnTerms(p);
	for (const h of p.hosts) {
		h.verify = (): unknown => true;
		h.abandon = (): unknown => undefined;
	}
}

describe('Host refusals in the agreement (#2151 step 3a, test 6)', function () {
	this.timeout(60000);
	const s = scratch('conversion-host-refusals-');
	const shared = sharedPair(s, 'plain');
	let p: IConversionPair;
	let clock: sinon.SinonFakeTimers | undefined;
	afterEach(() => {
		clock?.restore();
		clock = undefined;
	});
	after(() => s.release());

	for (const [what, answer] of [
		['false', (): unknown => false],
		[
			'a throw',
			(): void => {
				throw new Error('host failure');
			}
		],
		['another value', (): unknown => 'yes'],
		['a rejection', (): unknown => Promise.reject(new Error('host failure'))]
	] as const) {
		it(`ends both sides when the acceptor's host answers ${what}`, async () => {
			p = await shared();
			clean(p);
			p.hosts[1].verify = answer;
			await run(p);
			const replies = p.link.delivered.filter(
				(m) => m.name === 'conversion_reply'
			);
			expect(readReply(replies[replies.length - 1])).to.deep.include({
				accept: false,
				reason: DECLINED
			});
			expect(abandoned(p, 1)).to.deep.equal([DECLINED]);
			expect(abandoned(p, 0)).to.deep.equal([DECLINED]);
			expect([
				held(p.managers[0], p.id),
				held(p.managers[1], p.id)
			]).to.deep.equal([false, false]);
		});
		it(`ends the initiator before any wire when its own host answers ${what}`, async () => {
			p = await shared();
			clean(p);
			p.hosts[0].verify = answer;
			const mark = p.link.sent.length;
			const start = await run(p);
			await start.done;
			expect(start.error).to.equal(DECLINED);
			expect(p.link.sent.slice(mark).map((m) => m.name)).to.deep.equal([]);
			expect(abandoned(p, 0)).to.deep.equal([DECLINED]);
			expect(p.hosts[1].calls()).to.deep.equal([]);
		});
	}

	it("declines when the hosts' terms differ by one sat or one unit", async () => {
		p = await shared();
		clean(p);
		for (const change of [
			(t: ReturnType<typeof storeTerms>): unknown =>
				(t.fees.budgets.opener = String(BigInt(t.fees.budgets.opener) + 1n)),
			(t: ReturnType<typeof storeTerms>): unknown =>
				(t.units.issuances[0].amount = String(
					BigInt(t.units.issuances[0].amount) + 1n
				))
		]) {
			clean(p);
			// The acceptor's host confirms only the digest of the terms it expects.
			p.hosts[1].verify = (_ctx, _terms, digest): boolean => {
				const own = storeTerms(p.stores[1], p.id, { reference: REF });
				change(own);
				return termsIdentity(own).digest.equals(digest);
			};
			await run(p);
			expect(abandoned(p, 1)).to.deep.equal([DECLINED]);
			expect(abandoned(p, 0)).to.deep.equal([DECLINED]);
		}
	});

	it('declines at 15 seconds when the acceptor host never answers', async () => {
		p = await shared();
		clean(p);
		clock = sinon.useFakeTimers({
			now: Date.now(),
			toFake: ['Date', 'setTimeout', 'clearTimeout']
		});
		p.hosts[1].verify = (): unknown => never();
		await run(p);
		expect(abandoned(p, 0)).to.deep.equal([]);
		await tick(p, clock, 14_000);
		expect(abandoned(p, 0)).to.deep.equal([]);
		await tick(p, clock, 1_500);
		expect(abandoned(p, 0)).to.deep.equal([DECLINED]);
		expect(abandoned(p, 1)).to.deep.equal([DECLINED]);
	});

	it('ends at the 30 second reply bound when the peer drops conversion frames', async () => {
		p = await shared();
		clean(p);
		clock = sinon.useFakeTimers({
			now: Date.now(),
			toFake: ['Date', 'setTimeout', 'clearTimeout']
		});
		p.link.drop('conversion_terms');
		await run(p);
		await tick(p, clock, 29_000);
		expect(abandoned(p, 0)).to.deep.equal([]);
		expect(held(p.managers[0], p.id)).to.equal(true);
		await tick(p, clock, 1_500);
		expect(abandoned(p, 0)).to.deep.equal([WITHDRAWN]);
		expect(held(p.managers[0], p.id)).to.equal(false);
		await updateRound(p);
	});

	it('times out at the deadline after quiescence began, on both sides', async () => {
		p = await shared();
		clean(p);
		clock = sinon.useFakeTimers({
			now: Date.now(),
			toFake: ['Date', 'setTimeout', 'clearTimeout']
		});
		// I sent stfu(1); A's stfu(0) never arrives.
		p.link.hold({ from: 1, name: 'STFU' });
		await run(p);
		await tick(p, clock, 59_000);
		expect(abandoned(p, 0)).to.deep.equal([]);
		await tick(p, clock, 1_500);
		const aborts = p.link.delivered.filter((m) => m.name === 'TX_ABORT');
		expect(abortText(aborts[0])).to.equal('Asset conversion timed out');
		expect(abandoned(p, 0)).to.deep.equal(['Asset conversion timed out']);
		expect(abandoned(p, 1)).to.deep.equal(['Asset conversion timed out']);
	});

	it('ends when the peer starts quiescence first, and the stfu goes on to the splice transport', async () => {
		p = await shared();
		clean(p);
		p.link.script(1);
		await run(p);
		p.link.send(1, MessageType.STFU, stfu(p.channelId, true));
		await p.settle();
		expect(abandoned(p, 0)).to.deep.equal(['Peer started quiescence first']);
		// Today's transport answers the peer's stfu(1) with its own stfu(0).
		expect(
			p.link.inbox[1].filter((m) => m.name === 'STFU').map((m) => m.payload)
		).to.deep.equal([stfu(p.channelId, false)]);
		p.link.scripted[1] = false;
	});
});

describe('Refusals by a scripted peer (#2151 step 3a, test 6)', function () {
	this.timeout(60000);
	const s = scratch('conversion-scripted-');
	after(() => s.release());

	/** Side 0 real initiator, side 1 scripted: accept, stfu(0), then `ack` of the splice_init. */
	async function toSpliceInit(p: IConversionPair): Promise<{
		t: IAssetConversionTerms;
		id: ReturnType<typeof termsIdentity>;
		init: ReturnType<typeof decodeSpliceInit>;
	}> {
		agreeOnTerms(p);
		p.link.script(1);
		await run(p);
		const t = storeTerms(p.stores[0], p.id, { reference: REF });
		const id = termsIdentity(t);
		p.link.send(
			1,
			BEIGNET_CUSTOM_MESSAGE_TYPE,
			replyMessage(id.attempt, id.digest)
		);
		await p.settle();
		p.link.send(1, MessageType.STFU, stfu(p.channelId, false));
		await p.settle();
		const init = p.link.inbox[1].find((m) => m.name === 'SPLICE')!;
		return { t, id, init: decodeSpliceInit(init.payload) };
	}

	it('aborts on a splice_ack that omits the TLV', async () => {
		const p = await conversionPair(s, 'plain');
		const { init } = await toSpliceInit(p);
		p.link.send(
			1,
			MessageType.SPLICE_ACK,
			encodeSpliceAck({
				channelId: p.channelId,
				fundingPubkey: init.fundingPubkey,
				relativeSatoshis: 0n,
				lockDepth: 3
			})
		);
		await p.settle();
		const abort = p.link.inbox[1].find((m) => m.name === 'TX_ABORT');
		expect(abort, 'tx_abort').to.not.equal(undefined);
		expect(abortText(abort!)).to.equal(SPLICE_ACK_MISMATCH);
		p.link.send(1, MessageType.TX_ABORT, abort!.payload);
		await p.settle();
		expect(abandoned(p, 0)).to.deep.equal([SPLICE_ACK_MISMATCH]);
		expect(held(p.managers[0], p.id)).to.equal(false);
	});

	/** Side 0 scripted initiator, side 1 real acceptor, up to its stfu(0). */
	async function toAcceptorQuiesced(p: IConversionPair): Promise<{
		t: IAssetConversionTerms;
		id: ReturnType<typeof termsIdentity>;
	}> {
		agreeOnTerms(p);
		p.link.script(0);
		const t = storeTerms(p.stores[0], p.id);
		const id = termsIdentity(t);
		for (const raw of termsFrames(id.attempt, id.bytes))
			p.link.send(0, BEIGNET_CUSTOM_MESSAGE_TYPE, raw);
		await p.settle();
		p.link.send(0, MessageType.STFU, stfu(p.channelId, true));
		await p.settle();
		// The acceptor accepted and answered stfu(1) with its own stfu(0).
		expect(
			p.link.inbox[0]
				.filter((m) => m.name === 'conversion_reply')
				.map((m) => readReply(m).accept)
		).to.deep.equal([true]);
		expect(held(p.managers[1], p.id)).to.equal(true);
		return { t, id };
	}

	interface GoodInit {
		channelId: Buffer;
		fundingPubkey: Buffer;
		relativeSatoshis: bigint;
		fundingFeeratePerkw: number;
		locktime: number;
		lockDepth: number;
		conversion: { termsDigest: Buffer; targetType: Buffer };
	}
	const good = (
		p: IConversionPair,
		t: ReturnType<typeof storeTerms>,
		digest: Buffer
	): GoodInit => ({
		channelId: p.channelId,
		fundingPubkey: Buffer.from(
			'02' + '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
			'hex'
		),
		relativeSatoshis: BigInt(t.contributions.opener),
		fundingFeeratePerkw: t.fees.feeratePerKw,
		locktime: 600_000,
		lockDepth: 3,
		conversion: {
			termsDigest: digest,
			targetType: Buffer.from(t.targetType, 'hex')
		}
	});
	for (const [what, change] of [
		[
			'a TLV digest that differs',
			(m: ReturnType<typeof good>): unknown =>
				(m.conversion.termsDigest = Buffer.alloc(32, 1))
		],
		[
			'a TLV type that differs',
			(m: ReturnType<typeof good>): unknown =>
				(m.conversion.targetType = Buffer.from('0100000000000000000000', 'hex'))
		],
		[
			'a contribution that differs',
			(m: ReturnType<typeof good>): unknown => (m.relativeSatoshis += 1n)
		],
		[
			'a feerate that differs',
			(m: ReturnType<typeof good>): unknown => (m.fundingFeeratePerkw += 1)
		],
		[
			'a lock depth that differs',
			(m: ReturnType<typeof good>): unknown => (m.lockDepth = 4)
		],
		[
			'a locktime past the height plus one',
			(m: ReturnType<typeof good>): unknown => (m.locktime = 600_002)
		],
		[
			'an invalid key',
			(m: ReturnType<typeof good>): unknown =>
				(m.fundingPubkey = Buffer.alloc(33, 5))
		]
	] as const)
		it(`aborts at the acceptor on a splice_init with ${what}`, async () => {
			const p = await conversionPair(s, 'plain');
			const { t, id } = await toAcceptorQuiesced(p);
			expect(p.link.inbox[0].map((m) => m.name)).to.include('STFU');
			const m = good(p, t, id.digest);
			if (p.opener === 1) m.relativeSatoshis = BigInt(t.contributions.acceptor);
			change(m);
			p.link.send(0, MessageType.SPLICE, encodeSpliceInit(m));
			await p.settle();
			const abort = p.link.inbox[0].find((x) => x.name === 'TX_ABORT');
			expect(abort, 'tx_abort').to.not.equal(undefined);
			expect(abortText(abort!)).to.equal(
				what === 'a TLV type that differs'
					? 'Asset conversion names a different target type'
					: SPLICE_INIT_MISMATCH
			);
			expect(p.link.inbox[0].some((x) => x.name === 'SPLICE_ACK')).to.equal(
				false
			);
			p.link.send(0, MessageType.TX_ABORT, txAbort(p.channelId, 'echo'));
			await p.settle();
			expect(abandoned(p, 1)).to.deep.equal([abortText(abort!)]);
		});

	it('aborts at the acceptor on a splice_init that does not re-encode byte for byte', async () => {
		const p = await conversionPair(s, 'plain');
		const { t, id } = await toAcceptorQuiesced(p);
		const m = good(p, t, id.digest);
		if (p.opener === 1) m.relativeSatoshis = BigInt(t.contributions.acceptor);
		// An unknown odd TLV after the conversion record does not re-encode.
		const raw = Buffer.concat([
			encodeSpliceInit(m),
			Buffer.from('fe0001000701ff', 'hex')
		]);
		p.link.send(0, MessageType.SPLICE, raw);
		await p.settle();
		expect(
			p.link.inbox[0].filter((x) => x.name === 'TX_ABORT').map(abortText)
		).to.deep.equal([SPLICE_INIT_MISMATCH]);
		expect(p.link.inbox[0].some((x) => x.name === 'SPLICE_ACK')).to.equal(
			false
		);
	});
});

describe('Crossing terms (#2151 step 3a, test 6, V2-S7)', function () {
	this.timeout(60000);
	const s = scratch('conversion-crossing-');
	after(() => s.release());
	it("continues the opener's attempt, whichever side is the opener", async () => {
		const p = await conversionPair(s, 'plain');
		for (const first of [0, 1] as const) {
			clean(p);
			const starts = [first, 1 - first].map((i) =>
				track(
					startConversion(p.managers[i], p.channelId, {
						reference: Buffer.alloc(8, 9 + i)
					})
				)
			);
			await p.settle();
			await Promise.all(starts.map((x) => x.done));
			const opener = p.opener,
				other = (1 - opener) as 0 | 1;
			expect(abandoned(p, opener)).to.deep.equal([FENCE]);
			const ends = abandoned(p, other);
			expect(ends).to.deep.equal([
				"Peer's conversion of this channel goes first",
				FENCE
			]);
			expect(
				p.link.delivered.filter((m) => m.name === 'SPLICE').map((m) => m.from)
			).to.include(opener);
		}
	});
});

describe('Disconnects and restarts in each state (#2151 step 3a, test 6)', function () {
	this.timeout(60000);
	const s = scratch('conversion-disconnect-');
	const shared = sharedPair(s, 'asset');
	let p: IConversionPair;
	after(() => s.release());

	// In I aborting, A has already ended at I's tx_abort with the fence text
	// (row "A acked | tx_abort"); only its echo is held.
	const states: [string, WireMatch, string][] = [
		['I announced', { from: 1, name: 'conversion_reply' }, DISCONNECTED],
		['A accepted', { from: 0, name: 'STFU' }, DISCONNECTED],
		['I quiescing', { from: 1, name: 'STFU' }, DISCONNECTED],
		['A quiesced', { from: 0, name: 'SPLICE' }, DISCONNECTED],
		['I init-sent', { from: 1, name: 'SPLICE_ACK' }, DISCONNECTED],
		['A acked', { from: 0, name: 'TX_ABORT' }, DISCONNECTED],
		['I aborting', { from: 1, name: 'TX_ABORT' }, FENCE]
	];
	for (const [state, at, peerEnd] of states) {
		it(`ends I with "${DISCONNECTED}" at ${state}, A with "${peerEnd}", and replays nothing after reconnect`, async () => {
			p = await shared();
			clean(p);
			p.link.hold(at);
			await run(p);
			p.link.held.splice(0);
			p.disconnect();
			expect(abandoned(p, 0)).to.deep.equal([DISCONNECTED]);
			expect(abandoned(p, 1)).to.deep.equal([peerEnd]);
			p.link.clearRules();
			const mark = p.link.sent.length;
			await p.reconnect();
			expect(
				p.link.sent
					.slice(mark)
					.filter(
						(m) =>
							m.name.startsWith('conversion_') ||
							['STFU', 'SPLICE', 'SPLICE_ACK', 'TX_ABORT'].includes(m.name)
					)
			).to.deep.equal([]);
			expect(p.errors).to.deep.equal([[], []]);
		});
		it(`calls nothing on the restarted side at ${state}`, async () => {
			p = await shared();
			clean(p);
			p.link.hold(at);
			await run(p);
			p.link.held.splice(0);
			p.link.clearRules();
			// The old manager's teardown ends the attempt as a disconnect does;
			// count only what the new manager calls.
			let before = -1;
			await p.restart(0, () => {
				before = p.hosts[0].calls('abandonConversion').length;
			});
			expect(p.hosts[0].calls('abandonConversion').length).to.equal(before);
			expect(abandoned(p, 1)).to.deep.equal([peerEnd]);
			expect(held(p.managers[0], p.id)).to.equal(false);
			await updateRound(p);
		});
	}
});

describe('Restarts on a plain pair (#2151 step 3a, test 6)', function () {
	this.timeout(90000);
	const s = scratch('conversion-plain-restart-');
	const shared = sharedPair(s, 'plain');
	let p: IConversionPair;
	after(() => s.release());
	for (const [state, at] of [
		['I announced', { from: 1, name: 'conversion_reply' }],
		['I quiescing', { from: 1, name: 'STFU' }],
		['A acked', { from: 0, name: 'TX_ABORT' }]
	] as const)
		it(`calls nothing on the restarted side at ${state}, and the peer ends`, async () => {
			p = await shared();
			clean(p);
			p.link.hold(at);
			await run(p);
			p.link.held.splice(0);
			p.link.clearRules();
			// Count only what the new manager calls (see above).
			let before = -1;
			await p.restart(0, () => {
				before = p.hosts[0].calls('abandonConversion').length;
			});
			expect(p.hosts[0].calls('abandonConversion').length).to.equal(before);
			expect(abandoned(p, 1)).to.deep.equal([DISCONNECTED]);
			expect(held(p.managers[0], p.id)).to.equal(false);
			expect(p.ready(0)).to.equal(true);
		});
});

describe('Check 9 at each stfu point (#2151 step 3a, test 6, v3.1 item 6)', function () {
	this.timeout(60000);
	const s = scratch('conversion-expiry-');
	const shared = sharedPair(s, 'asset');
	let p: IConversionPair;
	let clock: sinon.SinonFakeTimers | undefined;
	afterEach(() => {
		clock?.restore();
		clock = undefined;
	});
	after(() => s.release());

	for (const [point, at, ends] of [
		[
			"I's accept reply, before its stfu(1)",
			{ from: 1, name: 'conversion_reply' },
			[EXPIRED, WITHDRAWN]
		],
		[
			"I's stfu(0), before its splice_init",
			{ from: 1, name: 'STFU' },
			[EXPIRED, EXPIRED]
		],
		[
			"A's stfu(1), before its stfu(0)",
			{ from: 0, name: 'STFU' },
			[EXPIRED, EXPIRED]
		],
		[
			"A's splice_init, before its splice_ack",
			{ from: 0, name: 'SPLICE' },
			[EXPIRED, EXPIRED]
		]
	] as const)
		it(`ends both sides when the agreement expires at ${point}`, async () => {
			p = await shared();
			clean(p);
			clock = fakeClock();
			agreeOnTerms(p, { expiresAt: Math.floor(Date.now() / 1000) + 20 });
			p.link.hold(at);
			await run(p);
			expect(abandoned(p, 0)).to.deep.equal([]);
			// Past expiresAt, inside the 30 second reply bound and the deadline.
			await tick(p, clock, 25_000);
			p.link.clearRules();
			p.link.release();
			await p.settle();
			expect([abandoned(p, 0), abandoned(p, 1)]).to.deep.equal([
				[ends[0]],
				[ends[1]]
			]);
			expect(p.link.delivered.some((m) => m.name === 'SPLICE_ACK')).to.equal(
				false
			);
		});
});

describe('A key failure and an exit in each state (#2151 step 3a, test 6, V2-M2)', function () {
	this.timeout(60000);
	const s = scratch('conversion-key-exit-');
	afterEach(() => sinon.restore());
	after(() => s.release());

	for (const [side, at, missing] of [
		[0, { from: 1, name: 'STFU' }, 'SPLICE'],
		[1, { from: 0, name: 'SPLICE' }, 'SPLICE_ACK']
	] as const)
		it(`aborts when side ${side} cannot allocate its candidate funding key`, async () => {
			const p = await conversionPair(s, 'asset');
			agreeOnTerms(p);
			p.link.hold(at);
			await run(p);
			sinon
				.stub(p.stores[side], 'allocateFinalChannelKeyIndex')
				.throws(new Error('Key store unavailable'));
			p.link.clearRules();
			p.link.release();
			await p.settle();
			expect(p.link.delivered.some((m) => m.name === missing)).to.equal(false);
			const aborts = p.link.delivered.filter(
				(m) => m.from === side && m.name === 'TX_ABORT'
			);
			expect(aborts, 'tx_abort from the failing side').to.have.length(1);
			const text = abortText(aborts[0]);
			expect([abandoned(p, 0), abandoned(p, 1)]).to.deep.equal([
				[text],
				[text]
			]);
			expect([
				held(p.managers[0], p.id),
				held(p.managers[1], p.id)
			]).to.deep.equal([false, false]);
		});

	for (const [who, when, at, ends] of [
		[
			'I',
			'before its own stfu',
			{ from: 1, name: 'conversion_reply' },
			[CLOSE, WITHDRAWN]
		],
		['I', 'after its own stfu', { from: 1, name: 'STFU' }, [CLOSE, CLOSE]],
		['A', 'before its own stfu', { from: 0, name: 'STFU' }, [WITHDRAWN, CLOSE]],
		['A', 'after its own stfu', { from: 0, name: 'SPLICE' }, [CLOSE, CLOSE]]
	] as const)
		it(`ends both sides when ${who} requests an exit ${when}`, async () => {
			const p = await conversionPair(s, 'asset');
			agreeOnTerms(p);
			p.link.hold(at);
			await run(p);
			const side = who === 'I' ? 0 : 1;
			p.managers[side].forceClose(p.channelId, Buffer.alloc(1));
			p.link.clearRules();
			p.link.release();
			await p.settle();
			expect([abandoned(p, 0), abandoned(p, 1)]).to.deep.equal([
				[ends[0]],
				[ends[1]]
			]);
			// Nothing reached another transport: no splice message left either side.
			expect(
				p.link.delivered.some(
					(m) => m.name === 'SPLICE_ACK' || m.name.startsWith('asset_splice')
				)
			).to.equal(false);
		});
});

describe('An update in flight at a stfu point, from a scripted peer (#2151 step 3a, test 4, V2-S1)', function () {
	this.timeout(60000);
	const s = scratch('conversion-stfu-update-');
	after(() => s.release());
	const add = (p: IConversionPair): Buffer =>
		encodeUpdateAddHtlcMessage({
			channelId: p.channelId,
			id: 0n,
			amountMsat: 1_000_000n,
			paymentHash: Buffer.alloc(32, 0x44),
			cltvExpiry: 600_100,
			onionRoutingPacket: Buffer.alloc(1366)
		});

	it("aborts at A's stfu point when the initiator updated after the accept", async () => {
		const p = await conversionPair(s, 'plain');
		agreeOnTerms(p);
		p.link.script(0);
		const t = storeTerms(p.stores[0], p.id);
		const id = termsIdentity(t);
		for (const raw of termsFrames(id.attempt, id.bytes))
			p.link.send(0, BEIGNET_CUSTOM_MESSAGE_TYPE, raw);
		await p.settle();
		expect(
			p.link.inbox[0]
				.filter((m) => m.name === 'conversion_reply')
				.map((m) => readReply(m).accept)
		).to.deep.equal([true]);
		p.link.send(0, MessageType.UPDATE_ADD_HTLC, add(p));
		p.link.send(0, MessageType.STFU, stfu(p.channelId, true));
		await p.settle();
		expect(
			p.link.inbox[0].filter((m) => m.name === 'TX_ABORT').map(abortText)
		).to.deep.equal([QUIET]);
		expect(p.link.inbox[0].some((m) => m.name === 'STFU')).to.equal(false);
	});

	it("aborts at I's stfu(0) point when the acceptor updated before its stfu", async () => {
		const p = await conversionPair(s, 'plain');
		agreeOnTerms(p);
		p.link.script(1);
		await run(p);
		const t = storeTerms(p.stores[0], p.id, { reference: REF });
		const id = termsIdentity(t);
		p.link.send(
			1,
			BEIGNET_CUSTOM_MESSAGE_TYPE,
			replyMessage(id.attempt, id.digest)
		);
		await p.settle();
		expect(p.link.inbox[1].some((m) => m.name === 'STFU')).to.equal(true);
		p.link.send(1, MessageType.UPDATE_ADD_HTLC, add(p));
		p.link.send(1, MessageType.STFU, stfu(p.channelId, false));
		await p.settle();
		expect(
			p.link.inbox[1].filter((m) => m.name === 'TX_ABORT').map(abortText)
		).to.deep.equal([QUIET]);
		expect(p.link.inbox[1].some((m) => m.name === 'SPLICE')).to.equal(false);
	});
});

describe('The failure rule for a close (#2151 step 3a, test 6, V2-M2)', function () {
	this.timeout(60000);
	const s = scratch('conversion-close-');
	after(() => s.release());
	for (const [when, hold] of [
		['before its own stfu', { from: 1, name: 'conversion_reply' }],
		['after its own stfu', { from: 1, name: 'STFU' }]
	] as const)
		it(`ends the initiator's attempt on a local close ${when}`, async () => {
			const p = await conversionPair(s, 'plain');
			agreeOnTerms(p);
			p.link.hold(hold);
			await run(p);
			p.managers[0].initiateShutdown(
				p.channelId,
				Buffer.from('0014' + '11'.repeat(20), 'hex')
			);
			p.link.clearRules();
			p.link.release();
			await p.settle();
			expect(abandoned(p, 0)).to.deep.equal([CLOSE]);
			const sentByI = p.link.delivered.filter((m) => m.from === 0);
			if (when === 'before its own stfu') {
				const decline = sentByI
					.filter((m) => m.name === 'conversion_reply')
					.map(readReply);
				expect(decline).to.deep.include.members([
					{ ...decline[0], accept: false, reason: CLOSE }
				]);
				expect(abandoned(p, 1)).to.deep.equal([WITHDRAWN]);
			} else {
				expect(
					sentByI.filter((m) => m.name === 'TX_ABORT').map(abortText)
				).to.deep.equal([CLOSE]);
				expect(abandoned(p, 1)).to.deep.equal([CLOSE]);
			}
			// Nothing reached another transport: no splice was opened on either side.
			expect(p.errors.flat().filter((e) => /splice/i.test(e))).to.deep.equal(
				[]
			);
		});
});

describe('Crossing identical terms (#2151 step 3a, diff review 1)', function () {
	this.timeout(60000);
	const s = scratch('conversion-crossing-identical-');
	after(() => s.release());
	const PEER_GOES_FIRST = "Peer's conversion of this channel goes first";

	for (const kind of ['plain', 'asset'] as const)
		it(`continues the opener's attempt to the fence when both sides start the same agreement (${kind})`, async () => {
			const p = await conversionPair(s, kind);
			agreeOnTerms(p);
			// One agreement on both sides: identical terms, one attempt id.
			const reference = Buffer.alloc(8, 0x77);
			const starts = [0, 1].map((i) =>
				track(startConversion(p.managers[i], p.channelId, { reference }))
			);
			await p.settle();
			await Promise.all(starts.map((x) => x.done));
			const opener = p.opener,
				other = (1 - opener) as 0 | 1;
			const terms = p.link.sent.filter((m) => m.name === 'conversion_terms');
			expect(terms.map((m) => m.from).sort()).to.deep.equal([0, 1]);
			// Identical terms, but each side's attempt id names its own role
			// (amendment v3.5), so the opener's decline names only the peer's.
			const sent = terms.map((m) => readTerms([m]));
			expect(sent[0].bytes.equals(sent[1].bytes)).to.equal(true);
			expect(sent[0].attempt).to.not.equal(sent[1].attempt);
			const declines = p.link.sent
				.filter((m) => m.from === opener && m.name === 'conversion_reply')
				.map(readReply);
			expect(declines.map((r) => [r.attempt, r.accept])).to.deep.equal([
				[sent[terms[0].from === other ? 0 : 1].attempt, false]
			]);
			expect(abandoned(p, other)).to.deep.equal([PEER_GOES_FIRST, FENCE]);
			expect(abandoned(p, opener)).to.deep.equal([FENCE]);
			expect([
				held(p.managers[0], p.id),
				held(p.managers[1], p.id)
			]).to.deep.equal([false, false]);
			// The opener's decline of the non-opener's terms has arrived, so it
			// may start the same terms (same state number, same id) again at
			// once (amendment v3.4 item 3).
			const again = track(
				startConversion(p.managers[other], p.channelId, { reference })
			);
			await p.settle();
			await again.done;
			expect(again.error).to.equal(undefined);
			expect(abandoned(p, other)).to.deep.equal([
				PEER_GOES_FIRST,
				FENCE,
				FENCE
			]);
			await updateRound(p);
		});
});

describe('An attempt that ends while it waits for the barrier (#2151 step 3a, diff review 2)', function () {
	this.timeout(60000);
	const s = scratch('conversion-barrier-end-');
	after(() => s.release());

	/** Make side i's barrier wait until the returned function is called. */
	function gateBarrier(p: IConversionPair, i: 0 | 1): () => void {
		const m = p.managers[i] as unknown as {
			finalTransport?: { settled(id: string): Promise<void> };
			assetUpdates?: { settled(id: string): Promise<void> };
		};
		let open!: () => void;
		const gate = new Promise<void>((done) => (open = done));
		const restore: (() => void)[] = [];
		for (const t of [m.finalTransport, m.assetUpdates]) {
			if (!t) continue;
			const original = t.settled.bind(t);
			t.settled = (id: string): Promise<void> => gate.then(() => original(id));
			restore.push(() => (t.settled = original));
		}
		return () => {
			for (const r of restore) r();
			open();
		};
	}

	const WIRE = ['STFU', 'SPLICE', 'SPLICE_ACK', 'TX_ABORT'];
	// [handler, the message held to reach it, the side whose handler waits]
	const cases: [string, WireMatch, 0 | 1][] = [
		["I's accept (before stfu(1))", { from: 1, name: 'conversion_reply' }, 0],
		["I's stfu(0) (before splice_init)", { from: 1, name: 'STFU' }, 0],
		["A's stfu(1) (before stfu(0))", { from: 0, name: 'STFU' }, 1],
		["A's splice_init (before splice_ack)", { from: 0, name: 'SPLICE' }, 1]
	];
	for (const [what, at, side] of cases)
		it(`sends nothing and allocates no key once a disconnect ended it, at ${what}`, async () => {
			const p = await conversionPair(s, 'plain');
			agreeOnTerms(p);
			p.link.hold(at, true);
			const start = track(
				startConversion(p.managers[0], p.channelId, { reference: REF })
			);
			await p.settle();
			await start.done;
			expect(p.link.held.length, 'the message is held').to.equal(1);
			const open = gateBarrier(p, side);
			p.link.release();
			await p.settle();
			p.disconnect();
			expect(abandoned(p, side)).to.deep.equal([DISCONNECTED]);
			const keys = allocatedKeyIndex(p.stores[side]);
			const mark = p.link.sent.length;
			await p.reconnect();
			open();
			await p.settle();
			expect(
				p.link.sent
					.slice(mark)
					.filter((m) => m.from === side && WIRE.includes(m.name))
					.map((m) => m.name),
				'sent after the attempt ended'
			).to.deep.equal([]);
			expect(allocatedKeyIndex(p.stores[side]), 'key index').to.equal(keys);
			await updateRound(p);
		});
});

describe('A retry of withdrawn terms (#2151 step 3a, amendment v3.4)', function () {
	this.timeout(60000);
	const s = scratch('conversion-retry-');
	let clock: sinon.SinonFakeTimers | undefined;
	afterEach(() => {
		clock?.restore();
		clock = undefined;
	});
	after(() => s.release());
	const TOO_SOON = 'Asset conversion repeats a withdrawn attempt too soon';

	it('refuses identical terms for the reply bound after a withdrawal with no reply, and ignores the stale accept', async () => {
		const p = await conversionPair(s, 'plain');
		agreeOnTerms(p);
		clock = fakeClock();
		// A accepts, but its reply stays on the wire past I's reply bound.
		p.link.hold({ from: 1, name: 'conversion_reply' });
		await run(p);
		await tick(p, clock, 30_500);
		expect(abandoned(p, 0)).to.deep.equal([WITHDRAWN]);
		expect(abandoned(p, 1)).to.deep.equal([WITHDRAWN]);
		// The same agreement again: identical terms, the same attempt id.
		const mark = p.link.sent.length,
			log = p.hostLog.length;
		const retry = await run(p);
		await retry.done;
		expect(retry.error).to.equal(TOO_SOON);
		expect(
			p.link.sent
				.slice(mark)
				.filter((m) => m.from === 0)
				.map((m) => m.name)
		).to.deep.equal([]);
		expect(
			p.hostLog.slice(log).map((c) => c.side + ':' + c.name)
		).to.deep.equal(['0:conversionTerms']);
		expect(held(p.managers[0], p.id)).to.equal(false);
		// The stale accept arrives and matches nothing.
		p.link.clearRules();
		p.link.release();
		await p.settle();
		expect(p.link.sent.slice(mark).some((m) => m.name === 'STFU')).to.equal(
			false
		);
		// After the bound, the same terms convert to the fence.
		await tick(p, clock, 30_000);
		const again = await run(p);
		await again.done;
		expect(again.error).to.equal(undefined);
		await p.settle();
		expect(abandoned(p, 0)).to.deep.equal([WITHDRAWN, FENCE]);
		expect(abandoned(p, 1)).to.deep.equal([WITHDRAWN, FENCE]);
	});

	it('lets identical terms start again at once after a decline', async () => {
		const p = await conversionPair(s, 'plain');
		agreeOnTerms(p);
		p.hosts[1].verify = (): unknown => false;
		const first = await run(p);
		await first.done;
		expect(abandoned(p, 0)).to.deep.equal([DECLINED]);
		p.hosts[1].verify = (): unknown => true;
		const again = await run(p);
		await again.done;
		expect(again.error).to.equal(undefined);
		await p.settle();
		expect(abandoned(p, 0)).to.deep.equal([DECLINED, FENCE]);
	});
});

describe('Withdrawals and attempt ids (#2151 step 3a, amendment v3.5)', function () {
	this.timeout(120000);
	const s = scratch('conversion-withdrawals-');
	let clock: sinon.SinonFakeTimers | undefined;
	afterEach(() => {
		clock?.restore();
		clock = undefined;
	});
	after(() => s.release());
	const TOO_SOON = 'Asset conversion repeats a withdrawn attempt too soon';
	const shortDeadline = (p: IConversionPair, side: 0 | 1): void => {
		(
			conversionTransportOf(p.managers[side]) as unknown as {
				deps: { timeoutMs?: number };
			}
		).deps.timeoutMs = 2000;
	};
	const startAt = async (
		p: IConversionPair,
		side: 0 | 1,
		reference: Buffer
	): Promise<ReturnType<typeof track>> => {
		const t = track(
			startConversion(p.managers[side], p.channelId, { reference })
		);
		await p.settle();
		await t.done;
		return t;
	};

	it('still refuses the first withdrawn terms after other terms were withdrawn inside its bound', async () => {
		const p = await conversionPair(s, 'plain');
		agreeOnTerms(p);
		shortDeadline(p, 0);
		clock = fakeClock();
		// Side 1's accepts stay on the wire past two withdrawals.
		p.link.hold({ from: 1, name: 'conversion_reply' });
		const X = Buffer.alloc(8, 0x21),
			Y = Buffer.alloc(8, 0x42);
		expect((await startAt(p, 0, X)).error).to.equal(undefined);
		await tick(p, clock, 2000);
		expect((await startAt(p, 0, Y)).error).to.equal(undefined);
		await tick(p, clock, 2000);
		expect(abandoned(p, 0)).to.deep.equal([WITHDRAWN, WITHDRAWN]);
		expect(p.link.held.map((m) => m.name)).to.deep.equal([
			'conversion_reply',
			'conversion_reply'
		]);
		const mark = p.link.sent.length;
		const retry = await startAt(p, 0, X);
		expect(retry.error).to.equal(TOO_SOON);
		p.link.clearRules();
		p.link.release();
		await p.settle();
		// Both stale accepts match nothing.
		expect(
			p.link.sent.slice(mark).map((m) => m.from + ':' + m.name)
		).to.deep.equal([]);
		expect(abandoned(p, 0)).to.deep.equal([WITHDRAWN, WITHDRAWN]);
		expect([
			held(p.managers[0], p.id),
			held(p.managers[1], p.id)
		]).to.deep.equal([false, false]);
	});

	it("keeps the opener's attempt when the non-opener withdraws its own identical terms first", async () => {
		const p = await conversionPair(s, 'plain');
		agreeOnTerms(p);
		const opener = p.opener,
			other = (1 - opener) as 0 | 1;
		const reference = Buffer.alloc(8, 0x77);
		shortDeadline(p, other);
		clock = fakeClock();
		// The opener's terms and its decline of the peer's are delayed.
		p.link.hold(
			(m) =>
				m.from === opener &&
				(m.name === 'conversion_terms' || m.name === 'conversion_reply')
		);
		expect((await startAt(p, opener, reference)).error).to.equal(undefined);
		expect((await startAt(p, other, reference)).error).to.equal(undefined);
		// The non-opener withdraws its own attempt. Its decline names its own
		// id, not the opener's, so the opener's attempt goes on.
		await tick(p, clock, 2000);
		expect(abandoned(p, other)).to.deep.equal([WITHDRAWN]);
		expect(abandoned(p, opener)).to.deep.equal([]);
		expect(held(p.managers[opener], p.id)).to.equal(true);
		p.link.clearRules();
		p.link.release();
		await p.settle();
		expect(abandoned(p, opener)).to.deep.equal([FENCE]);
		expect(abandoned(p, other)).to.deep.equal([WITHDRAWN, FENCE]);
		expect([
			held(p.managers[0], p.id),
			held(p.managers[1], p.id)
		]).to.deep.equal([false, false]);
	});

	it('takes a withdrawal and the retry of the same terms in one burst as two attempts', async () => {
		const p = await conversionPair(s, 'plain');
		expect(p.opener).to.equal(0);
		p.link.script(0);
		const t = storeTerms(p.stores[0], p.id, { reference: REF });
		const id = termsIdentity(t);
		const deliver = (raw: Buffer): void => {
			const { subtype, payload } = decodeCustomMessage(raw);
			p.managers[1].handleAssetOpenFrame(p.nodeIds[0], subtype, payload);
		};
		for (const raw of termsFrames(id.attempt, id.bytes))
			p.link.send(0, BEIGNET_CUSTOM_MESSAGE_TYPE, raw);
		await p.settle();
		const replies = (): ReturnType<typeof readReply>[] =>
			p.link.inbox[0]
				.filter((m) => m.name === 'conversion_reply')
				.map(readReply);
		expect(replies().map((r) => r.accept)).to.deep.equal([true]);
		// The withdrawal, then the same terms again, with no turn between.
		deliver(replyMessage(id.attempt, id.digest, WITHDRAWN));
		for (const raw of termsFrames(id.attempt, id.bytes)) deliver(raw);
		await p.settle();
		expect(abandoned(p, 1)).to.deep.equal([WITHDRAWN]);
		expect(replies().map((r) => r.accept)).to.deep.equal([true, true]);
		expect(held(p.managers[1], p.id)).to.equal(true);
		p.link.send(
			0,
			BEIGNET_CUSTOM_MESSAGE_TYPE,
			replyMessage(id.attempt, id.digest, WITHDRAWN)
		);
		await p.settle();
		expect(abandoned(p, 1)).to.deep.equal([WITHDRAWN, WITHDRAWN]);
		expect(held(p.managers[1], p.id)).to.equal(false);
	});
});
