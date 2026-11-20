/**
 * Issue #2098, step 7: each leg's end tells the host the quote the forward
 * was taken under. The host of a forward with an asset leg is told how each
 * leg ends (onForwardLegResolved, step 5); from this step each end also
 * carries the next hop the onion named (for a forward by a quote, the short
 * channel id the host claimed for it) and what the leg was worth as the node
 * counted it: the host's value of an incoming asset leg, the amount of an
 * incoming bitcoin leg, and the amount to forward of an outgoing leg.
 *
 * The node keeps both on the HTLC entries from the ask on: the next hop and
 * the amount to forward with the mark that it asks, the worth with the mark
 * that its host took the forward on, and all three on the outgoing HTLC as
 * it is added. Nothing here adds a write of its own.
 */

import { expect } from 'chai';
import type { IAuxiliaryForwardLegResolution } from '../../src/lightning/channel/auxiliary-forward';
import type { IHtlcEntry } from '../../src/lightning/channel/types';
import { forwardChainWorld } from './helpers/auxiliary-forward-world';
import { withAssetForwards, withAssetOpens } from './helpers/auxiliary-nodes';
import { settle } from './helpers/auxiliary-on-chain';
import {
	FORWARD_MSAT,
	INCOMING_MSAT,
	INCOMING_UNITS,
	MSAT_PER_UNIT,
	cancelAtCarol,
	incomingWorth,
	legEnds,
	listenBob,
	openScene,
	rounds,
	settleAtCarol,
	shapeName,
	type IScene,
	type Shape
} from './helpers/auxiliary-forward-scene';

/** What the forward's HTLC entries keep of its terms (IHtlcEntry.forwardTerms). */
type Kept = {
	shortChannelId: Buffer;
	amountToForwardMsat: bigint;
	incomingValueMsat?: bigint;
};

const keptOf = (entry: IHtlcEntry | undefined): Kept | undefined =>
	(entry as (IHtlcEntry & { forwardTerms?: Kept }) | undefined)?.forwardTerms;

/** The next hop and the worth an end tells, as one string to compare. */
const quoteOf = (end: IAuxiliaryForwardLegResolution): string => {
	const told = end as IAuxiliaryForwardLegResolution & {
		shortChannelId?: Buffer;
		valueMsat?: bigint;
	};
	return `${told.shortChannelId?.toString('hex') ?? '-'}@${
		told.valueMsat?.toString() ?? '-'
	}`;
};

describe("each leg's end tells the host the quote it was taken under (issue #2098, step 7)", function () {
	this.timeout(240_000);
	withAssetOpens();
	withAssetForwards();
	const world = forwardChainWorld();
	afterEach(() => world.dispose());

	/** Bob's stored row of a channel: the received or offered entry of the forward. */
	const storedEntry = (
		s: IScene,
		channelId: Buffer,
		side: 'received' | 'offered'
	): IHtlcEntry | undefined =>
		[
			...(s.w.hosts.bob.storage!.loadChannel(channelId.toString('hex'))?.state
				.htlcs ?? new Map<string, IHtlcEntry>())
		].find(
			([key, entry]) =>
				key.startsWith(`${side}-`) &&
				entry.paymentHash.equals(s.held.paymentHash)
		)?.[1];

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
		}: each leg's end tells the next hop the onion named and what the leg was worth, kept on the entries from the ask`, async () => {
			const kept: { atAsk?: Kept } = {};
			const scene: { s?: IScene } = {};
			const s = await openScene(
				world,
				`fwd-quote-${shape.join('-')}${quote ? '-q' : ''}`,
				shape,
				{
					quote,
					beforeSend: (opened) => {
						scene.s = opened;
					},
					answer: (request, terms) => {
						// The row of the incoming channel says what the node asks
						// about before the host is asked.
						const row = scene
							.s!.w.hosts.bob.storage!.loadChannel(
								request.incoming.channelId.toString('hex')
							)
							?.state.htlcs.get(`received-${request.incoming.htlcId}`);
						kept.atAsk = keptOf(row);
						return terms;
					}
				}
			);
			expect(s.asked).to.have.length(1);
			expect(
				kept.atAsk?.shortChannelId.toString('hex'),
				'the next hop, written with the ask'
			).to.equal(s.next.toString('hex'));
			expect(kept.atAsk?.amountToForwardMsat).to.equal(FORWARD_MSAT);
			// The outgoing HTLC carries all three in its channel's row.
			const offered = keptOf(storedEntry(s, s.w.outChannel, 'offered'));
			expect(offered?.shortChannelId.toString('hex')).to.equal(
				s.next.toString('hex')
			);
			expect(offered?.amountToForwardMsat).to.equal(FORWARD_MSAT);
			expect(offered?.incomingValueMsat).to.equal(incomingWorth(shape));

			await settleAtCarol(s);
			await rounds('both ends told', () => s.told.length >= 2);
			expect(legEnds(s)).to.deep.equal([
				'incoming:fulfilled',
				'outgoing:fulfilled'
			]);
			const next = s.next.toString('hex');
			expect(s.told.map(quoteOf).sort()).to.deep.equal(
				[`${next}@${incomingWorth(shape)}`, `${next}@${FORWARD_MSAT}`].sort()
			);
			const incoming = s.told.find((end) => end.leg === 'incoming')!;
			expect(quoteOf(incoming)).to.equal(`${next}@${incomingWorth(shape)}`);
		});
	}

	it('a forward failed downstream tells both ends the next hop and the worth', async () => {
		const s = await openScene(world, 'fwd-quote-failed', ['asset', 'asset']);
		await cancelAtCarol(s);
		await rounds('both ends told', () => s.told.length >= 2);
		expect(legEnds(s)).to.deep.equal(['incoming:failed', 'outgoing:failed']);
		const next = s.next.toString('hex');
		expect(quoteOf(s.told.find((end) => end.leg === 'incoming')!)).to.equal(
			`${next}@${INCOMING_UNITS * MSAT_PER_UNIT}`
		);
		expect(quoteOf(s.told.find((end) => end.leg === 'outgoing')!)).to.equal(
			`${next}@${FORWARD_MSAT}`
		);
	});

	it('terms refused as malformed: the outgoing leg never offered tells the next hop and the amount to forward, and an incoming asset leg tells no worth', async () => {
		const s = await openScene(
			world,
			'fwd-quote-malformed',
			['asset', 'ordinary'],
			{
				// The incoming leg is an asset leg: the terms must value it.
				answer: () => ({}),
				held: false
			}
		);
		await rounds('both ends told', () => s.told.length >= 2);
		expect(legEnds(s)).to.deep.equal([
			'incoming:failed',
			'outgoing:never-offered'
		]);
		const next = s.next.toString('hex');
		expect(quoteOf(s.told.find((end) => end.leg === 'outgoing')!)).to.equal(
			`${next}@${FORWARD_MSAT}`
		);
		expect(quoteOf(s.told.find((end) => end.leg === 'incoming')!)).to.equal(
			`${next}@-`
		);
	});

	it('terms refused as malformed on an incoming bitcoin leg: its end tells what it carried', async () => {
		const s = await openScene(
			world,
			'fwd-quote-malformed-btc',
			['ordinary', 'asset'],
			{
				// The outgoing leg is an asset leg: the terms must carry its HTLC.
				answer: () => ({}),
				held: false
			}
		);
		await rounds('both ends told', () => s.told.length >= 2);
		const next = s.next.toString('hex');
		expect(quoteOf(s.told.find((end) => end.leg === 'incoming')!)).to.equal(
			`${next}@${INCOMING_MSAT}`
		);
		expect(quoteOf(s.told.find((end) => end.leg === 'outgoing')!)).to.equal(
			`${next}@${FORWARD_MSAT}`
		);
	});

	it("a refusal after the terms keeps the host's value of the incoming asset leg, which its end tells", async () => {
		// Short of the amount to forward and the fee: refused after the terms.
		const low = FORWARD_MSAT - 1n;
		const s = await openScene(world, 'fwd-quote-low', ['asset', 'ordinary'], {
			answer: () => ({ incomingValueMsat: low }),
			held: false
		});
		await rounds('both ends told', () => s.told.length >= 2);
		expect(legEnds(s)).to.deep.equal([
			'incoming:failed',
			'outgoing:never-offered'
		]);
		const next = s.next.toString('hex');
		expect(quoteOf(s.told.find((end) => end.leg === 'incoming')!)).to.equal(
			`${next}@${low}`
		);
	});

	it('a check before the onion is read, after a stop, tells the next hop and the amount to forward the ask kept', async () => {
		const s = await openScene(world, 'fwd-quote-cap', ['asset', 'asset'], {
			beforeSend: (opened) => {
				const node = opened.w.hosts.bob.node as unknown as {
					handleIncomingHtlc: (
						channelId: Buffer,
						htlcId: bigint,
						...rest: unknown[]
					) => unknown;
					maxTotalInFlightHtlcs: number;
				};
				const next = opened.w.hosts.bob.node
					.getChannelManager()
					.getChannel(opened.w.outChannel)!
					.getFullState().scidAlias!;
				// As after a stop: the node wrote that it asks, with the next
				// hop and the amount to forward, and the bound on HTLCs in
				// flight now refuses the HTLC before its onion is read.
				const dispatch = node.handleIncomingHtlc.bind(opened.w.hosts.bob.node);
				node.handleIncomingHtlc = (channelId, htlcId, ...rest): unknown => {
					expect(
						(
							opened.w.hosts.bob.node.getChannelManager() as unknown as {
								recordForwardAsk: (
									channelId: Buffer,
									htlcId: bigint,
									terms?: Kept
								) => boolean;
							}
						).recordForwardAsk(channelId, htlcId, {
							shortChannelId: Buffer.from(next),
							amountToForwardMsat: FORWARD_MSAT
						})
					).to.equal(true);
					node.maxTotalInFlightHtlcs = -1;
					return dispatch(channelId, htlcId, ...rest);
				};
			},
			held: false
		});
		await rounds('both ends told', () => s.told.length >= 2);
		expect(s.asked).to.have.length(0);
		expect(legEnds(s)).to.deep.equal([
			'incoming:failed',
			'outgoing:never-offered'
		]);
		const next = s.next.toString('hex');
		expect(quoteOf(s.told.find((end) => end.leg === 'outgoing')!)).to.equal(
			`${next}@${FORWARD_MSAT}`
		);
	});

	it("a second ask after a stop that values the incoming leg otherwise: the incoming leg's end tells the second value", async () => {
		const first = INCOMING_UNITS * MSAT_PER_UNIT + 7n;
		const s = await openScene(world, 'fwd-quote-reask', ['asset', 'ordinary'], {
			beforeSend: (opened) => {
				const node = opened.w.hosts.bob.node as unknown as {
					handleIncomingHtlc: (
						channelId: Buffer,
						htlcId: bigint,
						...rest: unknown[]
					) => unknown;
				};
				const next = opened.w.hosts.bob.node
					.getChannelManager()
					.getChannel(opened.w.outChannel)!
					.getFullState().scidAlias!;
				// As after a stop: the node asked, and wrote the first answer's
				// value with the mark that its host took the forward on, but
				// offered nothing; it asks again on the way back.
				const manager =
					opened.w.hosts.bob.node.getChannelManager() as unknown as {
						recordForwardAsk: (
							channelId: Buffer,
							htlcId: bigint,
							terms?: Kept
						) => boolean;
						recordForwardTaken: (
							channelId: Buffer,
							htlcId: bigint,
							terms?: Kept
						) => boolean;
					};
				const dispatch = node.handleIncomingHtlc.bind(opened.w.hosts.bob.node);
				node.handleIncomingHtlc = (channelId, htlcId, ...rest): unknown => {
					const terms = {
						shortChannelId: Buffer.from(next),
						amountToForwardMsat: FORWARD_MSAT
					};
					expect(manager.recordForwardAsk(channelId, htlcId, terms)).to.equal(
						true
					);
					expect(
						manager.recordForwardTaken(channelId, htlcId, {
							...terms,
							incomingValueMsat: first
						})
					).to.equal(true);
					return dispatch(channelId, htlcId, ...rest);
				};
			}
		});
		expect(s.asked).to.have.length(1);
		await settleAtCarol(s);
		await rounds('both ends told', () => s.told.length >= 2);
		const next = s.next.toString('hex');
		expect(quoteOf(s.told.find((end) => end.leg === 'incoming')!)).to.equal(
			`${next}@${INCOMING_UNITS * MSAT_PER_UNIT}`
		);
	});

	it('an end the host has not taken keeps the next hop and the worth across a restart, and the host is handed its own copy', async () => {
		let refuse = true;
		const s = await openScene(
			world,
			'fwd-quote-restart',
			['ordinary', 'asset'],
			{
				onEnd: (end) => {
					if (refuse) {
						// The host spoils what it was handed, and does not take it.
						(end as { shortChannelId?: Buffer }).shortChannelId?.fill(0xee);
						throw new Error('host busy');
					}
				}
			}
		);
		await settleAtCarol(s);
		for (let i = 0; i < 10; i++) await settle();
		expect(s.told).to.have.length(0);
		await world.restartBob(s.w, 'fwd-quote-restart');
		listenBob(s);
		refuse = false;
		await world.mine(s.w, 1);
		await rounds('both ends told after the restart', () => s.told.length >= 2);
		expect(legEnds(s)).to.deep.equal([
			'incoming:fulfilled',
			'outgoing:fulfilled'
		]);
		const next = s.next.toString('hex');
		expect(s.told.map(quoteOf).sort()).to.deep.equal(
			[`${next}@${INCOMING_MSAT}`, `${next}@${FORWARD_MSAT}`].sort()
		);
	});
});
