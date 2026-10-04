/**
 * Issue #1303: one failed durable write withholds an update, and the next
 * write lands. The peer must receive the withheld update before any
 * commitment_signed that covers it, and the channel must stay NORMAL.
 *
 * A plain channel, no FFOR epoch: two ChannelManagers in loopback
 * (helpers/ffor-concurrent-pair.ts). Nothing here runs the node's
 * transition:blocked listener, so each case disconnects and reconnects the
 * way that listener would.
 */

import { expect } from 'chai';
import { ChannelState } from '../../src/lightning/channel/types';
import { MessageType } from '../../src/lightning/message/types';
import {
	createPair,
	IPair,
	offer,
	ordinaryHtlcs,
	Side,
	why
} from './helpers/ffor-concurrent-pair';

function sentBy(pair: IPair, side: Side): number[] {
	return pair.link.log.filter((e) => e.from === side).map((e) => e.type);
}

/** Fail the next durable write on one side, once. Returns the block count. */
function failNextWrite(pair: IPair, side: Side): { blocked: number } {
	const mgr = side === 'S' ? pair.sManager : pair.rManager;
	const seen = { blocked: 0 };
	let failed = false;
	mgr.on('channel:persist', (ev: { request?: { committed: boolean } }) => {
		if (!failed && ev.request) {
			ev.request.committed = false;
			failed = true;
		}
	});
	mgr.on('transition:blocked', () => seen.blocked++);
	return seen;
}

function expectAlive(pair: IPair, label: string): void {
	expect(pair.sErrors, `${label} S errors ${why(pair)}`).to.deep.equal([]);
	expect(pair.rErrors, `${label} R errors ${why(pair)}`).to.deep.equal([]);
	expect(pair.link.types(), `${label} ${why(pair)}`).to.not.include(
		MessageType.ERROR
	);
	expect(pair.sChannel.getState(), `${label} S`).to.equal(ChannelState.NORMAL);
	expect(pair.rChannel.getState(), `${label} R`).to.equal(ChannelState.NORMAL);
}

/** `update` leaves `side` before its first commitment_signed. */
function expectUpdateBeforeSignature(
	pair: IPair,
	side: Side,
	update: MessageType
): void {
	const sent = sentBy(pair, side);
	const at = sent.indexOf(update);
	expect(at, `${update} sent ${why(pair)}`).to.be.at.least(0);
	expect(sent.indexOf(MessageType.COMMITMENT_SIGNED), why(pair)).to.be.above(
		at
	);
}

function reconnect(pair: IPair): void {
	pair.link.disconnect();
	pair.link.log.length = 0;
	pair.link.reconnect();
}

describe('A commitment_signed after a failed write (issue #1303)', () => {
	it('a withheld fulfil is not signed over by the auto-sign or by a later write that lands', () => {
		const pair = createPair({ pushSat: 200_000n });
		const first = offer(pair, 'S', 2_000_000n);
		const second = offer(pair, 'S', 3_000_000n);
		expect(first.result.ok, first.result.error).to.equal(true);
		expect(second.result.ok, second.result.error).to.equal(true);
		const seen = failNextWrite(pair, 'R');
		pair.link.log.length = 0;

		const res = pair.rManager.fulfillHtlc(
			pair.channelId,
			first.id,
			first.preimage
		);
		expect(res.sendsWithheld).to.equal(true);
		expect(seen.blocked).to.equal(1);
		// This write lands and its fulfil leaves; the signature still waits.
		const later = pair.rManager.fulfillHtlc(
			pair.channelId,
			second.id,
			second.preimage
		);
		expect(later.ok, later.error).to.equal(true);
		expect(later.sendsWithheld).to.equal(undefined);
		expect(sentBy(pair, 'R')).to.deep.equal([MessageType.UPDATE_FULFILL_HTLC]);
		expectAlive(pair, 'before the reconnect');

		reconnect(pair);
		expectUpdateBeforeSignature(pair, 'R', MessageType.UPDATE_FULFILL_HTLC);
		expectAlive(pair, 'after the reconnect');
		expect(pair.events.S.fulfilled).to.include.members([first.id, second.id]);
		expect(ordinaryHtlcs(pair.sChannel)).to.deep.equal([]);
		expect(ordinaryHtlcs(pair.rChannel)).to.deep.equal([]);
	});

	it('a withheld fail is not signed over', () => {
		const pair = createPair({ pushSat: 200_000n });
		const add = offer(pair, 'S', 2_000_000n);
		expect(add.result.ok, add.result.error).to.equal(true);
		const seen = failNextWrite(pair, 'R');
		pair.link.log.length = 0;

		const res = pair.rManager.failHtlc(
			pair.channelId,
			add.id,
			Buffer.alloc(256, 7)
		);
		expect(res.ok, res.error).to.equal(true);
		expect(seen.blocked).to.equal(1);
		expect(sentBy(pair, 'R')).to.deep.equal([]);
		expectAlive(pair, 'before the reconnect');

		reconnect(pair);
		expectUpdateBeforeSignature(pair, 'R', MessageType.UPDATE_FAIL_HTLC);
		expectAlive(pair, 'after the reconnect');
		expect(pair.events.S.failed).to.include(add.id);
		expect(ordinaryHtlcs(pair.sChannel)).to.deep.equal([]);
		expect(ordinaryHtlcs(pair.rChannel)).to.deep.equal([]);
	});

	it('a withheld add is not signed over, and completes after the reconnect', () => {
		const pair = createPair({ pushSat: 200_000n });
		const seen = failNextWrite(pair, 'S');
		pair.link.log.length = 0;

		const add = offer(pair, 'S', 2_000_000n);
		expect(add.result.ok, add.result.error).to.equal(true);
		expect(seen.blocked).to.equal(1);
		expect(sentBy(pair, 'S')).to.deep.equal([]);
		expectAlive(pair, 'before the reconnect');

		reconnect(pair);
		expectUpdateBeforeSignature(pair, 'S', MessageType.UPDATE_ADD_HTLC);
		expectAlive(pair, 'after the reconnect');
		expect(pair.events.R.forwarded).to.include(add.id);
		const res = pair.rManager.fulfillHtlc(pair.channelId, add.id, add.preimage);
		expect(res.ok, res.error).to.equal(true);
		expectAlive(pair, 'settled');
		expect(pair.events.S.fulfilled).to.include(add.id);
		expect(ordinaryHtlcs(pair.sChannel)).to.deep.equal([]);
		expect(ordinaryHtlcs(pair.rChannel)).to.deep.equal([]);
	});
});
