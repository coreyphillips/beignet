/**
 * #2151 Step 3a: withdrawals around a crossing, and the acceptor's end on a
 * withdrawal while its assessment waits (amendment v3.6, from the second
 * recheck).
 */
import { expect } from 'chai';
import sinon from 'sinon';
import {
	BEIGNET_CUSTOM_MESSAGE_TYPE,
	decodeCustomMessage
} from '../../src/lightning/message/custom';
import { scratch } from './helpers/channel-type-pairs';
import {
	abandoned,
	agreeOnTerms,
	allocatedKeyIndex,
	conversionPair,
	gateBarrier,
	held,
	readReply,
	readTerms,
	replyMessage,
	startConversion,
	storeTerms,
	termsFrames,
	termsIdentity,
	tick,
	track,
	updateRound,
	type IConversionPair
} from './helpers/conversion-managers';

const WITHDRAWN = 'Asset conversion withdrawn';
const PEER_GOES_FIRST = "Peer's conversion of this channel goes first";
const OTHER_ATTEMPT = 'Another conversion of this channel is in progress';

/** Deliver a custom message to side 1 at once, as side 0, with no turn between. */
function deliverTo1(p: IConversionPair, raw: Buffer): void {
	const { subtype, payload } = decodeCustomMessage(raw);
	p.managers[1].handleAssetOpenFrame(p.nodeIds[0], subtype, payload);
}

describe('A crossing end withdraws its own terms (#2151 step 3a, amendment v3.6)', function () {
	this.timeout(120000);
	const s = scratch('conversion-crossing-withdraw-');
	let clock: sinon.SinonFakeTimers | undefined;
	afterEach(() => {
		clock?.restore();
		clock = undefined;
	});
	after(() => s.release());

	it('leaves the opener holding nothing when its own withdrawal crossed the non-opener terms', async () => {
		const p = await conversionPair(s, 'plain');
		agreeOnTerms(p);
		const opener = p.opener,
			other = (1 - opener) as 0 | 1;
		clock = sinon.useFakeTimers({
			now: Date.now(),
			toFake: ['Date', 'setTimeout', 'clearTimeout']
		});
		// Every conversion frame of the non-opener stays on the wire.
		p.link.hold(
			(m) =>
				m.from === other &&
				(m.name === 'conversion_terms' || m.name === 'conversion_reply')
		);
		const startAt = async (
			side: 0 | 1,
			fill: number
		): Promise<ReturnType<typeof track>> => {
			const t = track(
				startConversion(p.managers[side], p.channelId, {
					reference: Buffer.alloc(8, fill)
				})
			);
			await p.settle();
			await t.done;
			return t;
		};
		// The non-opener announces first; its terms are held.
		expect((await startAt(other, 0x31)).error).to.equal(undefined);
		// The opener's terms reach the non-opener, which ends its own attempt,
		// withdraws its terms, and accepts the opener's.
		expect((await startAt(opener, 0x32)).error).to.equal(undefined);
		expect(abandoned(p, other)).to.deep.equal([PEER_GOES_FIRST]);
		// The accept stays on the wire past the opener's reply bound, so the
		// opener withdraws, and the non-opener's acceptor ends on it.
		await tick(p, clock, 30_500);
		expect(abandoned(p, opener)).to.deep.equal([WITHDRAWN]);
		expect(abandoned(p, other)).to.deep.equal([PEER_GOES_FIRST, WITHDRAWN]);
		// The non-opener's frames arrive: its terms, its withdrawal of them,
		// then its accept of the opener's.
		p.link.clearRules();
		p.link.release();
		await p.settle();
		expect(
			held(p.managers[opener], p.id),
			'opener holds the channel for an attempt its peer already ended'
		).to.equal(false);
		expect(held(p.managers[other], p.id)).to.equal(false);
		await updateRound(p);
	});
});

describe('A decline and the opener terms in one burst (#2151 step 3a, amendment v3.6)', function () {
	this.timeout(120000);
	const s = scratch('conversion-decline-burst-');
	after(() => s.release());

	it('lets the non-opener start the same terms again at once, since its decline arrived', async () => {
		const p = await conversionPair(s, 'plain');
		expect(p.opener).to.equal(0);
		agreeOnTerms(p);
		// Side 0, the opener, is scripted; side 1 is a real non-opener.
		p.link.script(0);
		const reference = Buffer.alloc(8, 0x55);
		const start = track(
			startConversion(p.managers[1], p.channelId, { reference })
		);
		await p.settle();
		await start.done;
		expect(start.error).to.equal(undefined);
		const own = readTerms(
			p.link.inbox[0].filter((m) => m.name === 'conversion_terms')
		);
		// The opener, still starting, declines the peer's terms, then sends
		// its own. Both arrive with no turn between.
		const t = storeTerms(p.stores[0], p.id, {
			reference: Buffer.alloc(8, 0x66)
		});
		const id = termsIdentity(t);
		deliverTo1(
			p,
			replyMessage(
				Buffer.from(own.attempt, 'hex'),
				Buffer.from(own.digest, 'hex'),
				OTHER_ATTEMPT
			)
		);
		for (const raw of termsFrames(id.attempt, id.bytes)) deliverTo1(p, raw);
		await p.settle();
		expect(
			p.link.inbox[0]
				.filter((m) => m.name === 'conversion_reply')
				.map(readReply)
				.filter((r) => r.attempt === id.attempt.toString('hex'))
				.map((r) => r.accept)
		).to.deep.equal([true]);
		// The opener withdraws its attempt; the non-opener's acceptor ends.
		p.link.send(
			0,
			BEIGNET_CUSTOM_MESSAGE_TYPE,
			replyMessage(id.attempt, id.digest, WITHDRAWN)
		);
		await p.settle();
		expect(abandoned(p, 1).slice(-1)).to.deep.equal([WITHDRAWN]);
		// The decline of the non-opener's first attempt has arrived, so the
		// same terms may start again at once, as after any decline.
		const again = track(
			startConversion(p.managers[1], p.channelId, { reference })
		);
		await p.settle();
		await again.done;
		expect(again.error, 'retry of terms whose decline arrived').to.equal(
			undefined
		);
	});
});

describe('The acceptor ends at once on a withdrawal while it assesses (#2151 step 3a, amendment v3.5 item 4)', function () {
	this.timeout(120000);
	const s = scratch('conversion-withdraw-assess-');
	after(() => s.release());

	for (const at of ['first barrier', 'verify', 'second barrier'] as const)
		it(`sends nothing and calls the host once at most when the withdrawal arrives during the ${at}`, async () => {
			const p = await conversionPair(s, 'plain');
			expect(p.opener).to.equal(0);
			p.link.script(0);
			const t = storeTerms(p.stores[0], p.id, {
				reference: Buffer.alloc(8, 0x21)
			});
			const id = termsIdentity(t);
			let release: () => void = () => undefined;
			let answer: ((v: boolean) => void) | undefined;
			if (at === 'first barrier') release = gateBarrier(p, 1);
			if (at === 'verify')
				p.hosts[1].verify = (): unknown =>
					new Promise<boolean>((done) => (answer = done));
			if (at === 'second barrier')
				p.hosts[1].verify = (): unknown => {
					release = gateBarrier(p, 1);
					return true;
				};
			const keys = allocatedKeyIndex(p.stores[1]);
			for (const raw of termsFrames(id.attempt, id.bytes)) deliverTo1(p, raw);
			await p.settle();
			const calls = (): string[] =>
				p.hostLog.filter((c) => c.side === 1).map((c) => c.name);
			expect(calls()).to.deep.equal(
				at === 'first barrier' ? [] : ['verifyConversionTerms']
			);
			expect(held(p.managers[1], p.id)).to.equal(false);
			deliverTo1(p, replyMessage(id.attempt, id.digest, WITHDRAWN));
			const ends = at === 'first barrier' ? [] : [WITHDRAWN];
			expect(abandoned(p, 1)).to.deep.equal(ends);
			release();
			answer?.(true);
			await p.settle();
			expect(
				p.link.inbox[0]
					.map((m) => m.name)
					.filter((n) =>
						['conversion_reply', 'STFU', 'SPLICE', 'TX_ABORT'].includes(n)
					),
				'sent to the initiator'
			).to.deep.equal([]);
			expect(calls()).to.deep.equal(
				at === 'first barrier'
					? []
					: ['verifyConversionTerms', 'abandonConversion']
			);
			expect(abandoned(p, 1)).to.deep.equal(ends);
			expect(held(p.managers[1], p.id)).to.equal(false);
			expect(allocatedKeyIndex(p.stores[1])).to.equal(keys);
		});
});
