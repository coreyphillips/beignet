/**
 * Issue #2098, step 7: a forward with an asset leg in the forwarding
 * history and its events.
 *
 * Where an ordinary forward gets a row (at the upstream fulfil, its
 * outgoing leg fulfilled in its channel), a forward with an asset leg gets
 * one too, marked `auxiliary`. Its amounts are what each leg was worth,
 * never a carrier: the host's value of an incoming asset leg (or the amount
 * of an incoming bitcoin leg) in, the amount the onion asked the node to
 * forward out, and the fee their difference. Beside them the row keeps each
 * asset leg's units and carrier and the next hop the onion named. The
 * node's htlc:forwarded event and its structured log carry the same. The
 * summary's bitcoin totals count ordinary forwards only, and a total of the
 * marked ones stands beside them. An ordinary forward's row, event and log
 * are as they were.
 */

import { expect } from 'chai';
import { HtlcState } from '../../src/lightning/channel/types';
import type { IForwardingEvent } from '../../src/lightning/storage/types';
import {
	FORWARD_CARRIER_MSAT,
	forwardChainWorld
} from './helpers/auxiliary-forward-world';
import { withAssetForwards, withAssetOpens } from './helpers/auxiliary-nodes';
import { amountRecord } from './helpers/auxiliary-pair';
import {
	FORWARD_MSAT,
	INCOMING_MSAT,
	INCOMING_UNITS,
	MSAT_PER_UNIT,
	OUTGOING_UNITS,
	cancelAtCarol,
	incomingWorth,
	listenBob,
	openScene,
	rounds,
	settleAtCarol,
	shapeName,
	type IScene,
	type Shape
} from './helpers/auxiliary-forward-scene';

/** The keys of an ordinary forward's row, event and log, as before this step. */
const ROW_KEYS = [
	'amountInMsat',
	'amountOutMsat',
	'feeMsat',
	'id',
	'inChannelId',
	'inScid',
	'outChannelId',
	'outScid',
	'settledAt'
];
const EVENT_KEYS = [
	'amountInMsat',
	'amountOutMsat',
	'feeMsat',
	'inChannelId',
	'outChannelId'
];
const LOG_KEYS = [
	'amountInMsat',
	'amountOutMsat',
	'feeMsat',
	'inChannelId',
	'outChannelId',
	'paymentHash'
];

describe('a forward with an asset leg in the forwarding history and its events (issue #2098, step 7)', function () {
	this.timeout(240_000);
	withAssetOpens();
	withAssetForwards();
	const world = forwardChainWorld();
	afterEach(() => world.dispose());

	const rowsOf = (s: IScene): IForwardingEvent[] =>
		s.w.hosts.bob.node.listForwards();

	const CASES: Array<{ shape: Shape; quote: boolean }> = [
		{ shape: ['ordinary', 'asset'], quote: false },
		{ shape: ['ordinary', 'asset'], quote: true },
		{ shape: ['asset', 'ordinary'], quote: false },
		{ shape: ['asset', 'asset'], quote: false },
		{ shape: ['asset', 'asset'], quote: true }
	];

	for (const { shape, quote } of CASES) {
		it(`${shapeName(shape)}${
			quote ? ', by a quote' : ''
		}: one row marked auxiliary at what each leg was worth, with each asset leg's units and carrier and the next hop, and one htlc:forwarded and log saying the same`, async () => {
			const s = await openScene(
				world,
				`fwd-hist-${shape.join('-')}${quote ? '-q' : ''}`,
				shape,
				{ quote }
			);
			expect(rowsOf(s)).to.have.length(0);
			await settleAtCarol(s);
			const [inKind, outKind] = shape;
			const worth = incomingWorth(shape);
			const rows = rowsOf(s);
			expect(rows).to.have.length(1);
			const row = rows[0];
			expect(row).to.deep.include({
				auxiliary: true,
				inChannelId: s.w.inChannel.toString('hex'),
				outChannelId: s.w.outChannel.toString('hex'),
				amountInMsat: worth,
				amountOutMsat: FORWARD_MSAT,
				feeMsat: worth - FORWARD_MSAT,
				nextHopScid: s.next.toString('hex')
			});
			expect(row.inAuxiliaryAmount).to.equal(
				inKind === 'asset' ? INCOMING_UNITS : undefined
			);
			expect(row.inWireAmountMsat).to.equal(
				inKind === 'asset' ? FORWARD_CARRIER_MSAT : undefined
			);
			expect(row.outAuxiliaryAmount).to.equal(
				outKind === 'asset' ? OUTGOING_UNITS : undefined
			);
			expect(row.outWireAmountMsat).to.equal(
				outKind === 'asset' ? FORWARD_CARRIER_MSAT : undefined
			);

			// The event, once, with the same.
			expect(s.forwarded).to.have.length(1);
			const event = s.forwarded[0] as Record<string, unknown> & {
				inChannelId: Buffer;
				outChannelId: Buffer;
				nextHopScid?: Buffer;
			};
			expect(event.inChannelId.equals(s.w.inChannel)).to.equal(true);
			expect(event.outChannelId.equals(s.w.outChannel)).to.equal(true);
			expect(event).to.deep.include({
				auxiliary: true,
				amountInMsat: worth,
				amountOutMsat: FORWARD_MSAT,
				feeMsat: worth - FORWARD_MSAT
			});
			expect(event.nextHopScid?.equals(s.next)).to.equal(true);
			expect(event.inAuxiliaryAmount).to.equal(row.inAuxiliaryAmount);
			expect(event.inWireAmountMsat).to.equal(row.inWireAmountMsat);
			expect(event.outAuxiliaryAmount).to.equal(row.outAuxiliaryAmount);
			expect(event.outWireAmountMsat).to.equal(row.outWireAmountMsat);

			// The structured log, with units as decimal strings.
			const logs = s.logs.filter(
				(log) => log.category === 'htlc' && log.action === 'forwarded'
			);
			expect(logs).to.have.length(1);
			expect(logs[0].data).to.deep.include({
				auxiliary: true,
				paymentHash: s.held.paymentHash.toString('hex'),
				amountInMsat: Number(worth),
				amountOutMsat: Number(FORWARD_MSAT),
				feeMsat: Number(worth - FORWARD_MSAT),
				nextHopScid: s.next.toString('hex')
			});
			expect(logs[0].data.inAuxiliaryAmount).to.equal(
				inKind === 'asset' ? INCOMING_UNITS.toString() : undefined
			);
			expect(logs[0].data.outAuxiliaryAmount).to.equal(
				outKind === 'asset' ? OUTGOING_UNITS.toString() : undefined
			);
		});
	}

	it("the summary's bitcoin totals count ordinary forwards only, and the marked ones have a total of their own", async () => {
		const s = await openScene(world, 'fwd-hist-summary', ['asset', 'asset']);
		expect(s.w.hosts.bob.node.getForwardingSummary()).to.deep.equal({
			count: 0,
			volumeOutMsat: 0n,
			feesEarnedMsat: 0n
		});
		await settleAtCarol(s);
		const fee = INCOMING_UNITS * MSAT_PER_UNIT - FORWARD_MSAT;
		expect(s.w.hosts.bob.node.getForwardingSummary()).to.deep.equal({
			count: 0,
			volumeOutMsat: 0n,
			feesEarnedMsat: 0n,
			auxiliary: { count: 1, volumeOutMsat: FORWARD_MSAT, feesEarnedMsat: fee }
		});
		expect(
			s.w.hosts.bob.node.getForwardingSummary({ since: Date.now() + 60_000 })
		).to.deep.equal({ count: 0, volumeOutMsat: 0n, feesEarnedMsat: 0n });
	});

	it("an ordinary forward on the same node writes its row, event and log as before, with no key of this step's", async () => {
		const s = await openScene(world, 'fwd-hist-ordinary', [
			'ordinary',
			'ordinary'
		]);
		await settleAtCarol(s);
		expect(s.asked).to.have.length(0);
		const rows = rowsOf(s);
		expect(rows).to.have.length(1);
		expect(Object.keys(rows[0]).sort()).to.deep.equal(ROW_KEYS);
		expect(rows[0]).to.deep.include({
			amountInMsat: INCOMING_MSAT,
			amountOutMsat: FORWARD_MSAT,
			feeMsat: INCOMING_MSAT - FORWARD_MSAT
		});
		expect(s.forwarded).to.have.length(1);
		expect(Object.keys(s.forwarded[0]).sort()).to.deep.equal(EVENT_KEYS);
		const log = s.logs.find(
			(entry) => entry.category === 'htlc' && entry.action === 'forwarded'
		)!;
		expect(Object.keys(log.data).sort()).to.deep.equal(LOG_KEYS);
		const summary = s.w.hosts.bob.node.getForwardingSummary();
		expect(summary).to.deep.equal({
			count: 1,
			volumeOutMsat: FORWARD_MSAT,
			feesEarnedMsat: INCOMING_MSAT - FORWARD_MSAT
		});
		expect(Object.keys(summary)).to.not.include('auxiliary');
	});

	it('a forward with an asset leg failed downstream writes no row and raises no event', async () => {
		const s = await openScene(world, 'fwd-hist-failed', ['asset', 'asset']);
		await cancelAtCarol(s);
		expect(rowsOf(s)).to.have.length(0);
		expect(s.forwarded).to.have.length(0);
	});

	it('the worth survives a restart between the add and the settle', async () => {
		const s = await openScene(world, 'fwd-hist-restart', ['asset', 'asset']);
		await world.restartBob(s.w, 'fwd-hist-restart');
		listenBob(s);
		await settleAtCarol(s);
		const rows = rowsOf(s);
		expect(rows).to.have.length(1);
		expect(rows[0]).to.deep.include({
			auxiliary: true,
			amountInMsat: INCOMING_UNITS * MSAT_PER_UNIT,
			amountOutMsat: FORWARD_MSAT,
			nextHopScid: s.next.toString('hex')
		});
	});

	it('a host told nothing of the ends still has its forwards in the history', async () => {
		const s = await openScene(
			world,
			'fwd-hist-no-ends',
			['asset', 'ordinary'],
			{
				ends: false
			}
		);
		await settleAtCarol(s);
		const rows = rowsOf(s);
		expect(rows).to.have.length(1);
		expect(rows[0]).to.deep.include({
			auxiliary: true,
			amountInMsat: INCOMING_UNITS * MSAT_PER_UNIT,
			amountOutMsat: FORWARD_MSAT
		});
		expect(s.told).to.have.length(0);
	});

	it('writes a row only for an outgoing leg fulfilled in its channel', async () => {
		const s = await openScene(world, 'fwd-hist-fulfilled', ['asset', 'asset']);
		const node = s.w.hosts.bob.node as unknown as {
			buildForwardingEvent: (
				outChannelId: Buffer,
				outHtlcId: bigint,
				forward: { inChannelId: Buffer; inHtlcId: bigint }
			) => { mutation: { event: Record<string, unknown> } | null } | null;
		};
		const state = s.w.hosts.bob.node
			.getChannelManager()
			.getChannel(s.w.outChannel)!
			.getFullState();
		const [, offered] = [...state.htlcs].find(([key]) =>
			key.startsWith('offered-')
		)!;
		const forward = { inChannelId: s.w.inChannel, inHtlcId: 0n };
		const was = offered.state;
		try {
			// Failed downstream, or claimed on the chain while the entry is
			// still committed: nothing paid out in the channel, no row.
			for (const at of [HtlcState.FAILED, HtlcState.COMMITTED]) {
				offered.state = at;
				expect(
					node.buildForwardingEvent(s.w.outChannel, offered.id, forward),
					`with the outgoing entry ${at}`
				).to.equal(null);
			}
			offered.state = HtlcState.FULFILLED;
			const built = node.buildForwardingEvent(
				s.w.outChannel,
				offered.id,
				forward
			);
			expect(built?.mutation?.event.auxiliary).to.equal(true);
		} finally {
			offered.state = was;
		}
	});

	it('htlc:forward-refused of a forward with an asset leg is marked auxiliary', async () => {
		const s = await openScene(world, 'fwd-hist-refused', ['asset', 'asset'], {
			// More units than Bob holds on his channel with Carol: the add is refused.
			answer: (_request, terms) => ({
				...terms,
				outgoingHtlc: {
					customRecords: amountRecord(99_999n),
					wireAmountMsat: FORWARD_CARRIER_MSAT
				}
			}),
			held: false
		});
		await rounds('the refusal', () => s.refused.length >= 1);
		expect(s.refused).to.have.length(1);
		expect(s.refused[0].auxiliary).to.equal(true);
		// And its log, as the review of this step found missing.
		const log = s.logs.find((entry) => entry.action === 'forward_refused')!;
		expect(log.data.auxiliary).to.equal(true);
		expect(rowsOf(s)).to.have.length(0);
	});
});
