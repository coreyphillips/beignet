/**
 * FFOR concurrent receive (issue #1283): the drain hold, through the node.
 *
 * R is DRAINING with a voucher fail queued and S reestablishes short of
 * DRAINING (it came back from a row that predates ff_close), so R holds its
 * retransmission chain until S's ff_close_ack returns. The manager reports
 * channel:reestablished in the same turn, and the node answers that event
 * by settling what the channel is owed: a forward whose downstream leg
 * settled while the channel was down. Nobody calls anything: the fulfil is
 * produced by the node itself while the chain is held.
 *
 * Review round 1 of PR #1301 found that such a fulfil left ahead of the held
 * commitment_signed and S failed the channel. This is that trigger with
 * real nodes: S pays X through R, X settles while the S-R link is down, and
 * the reconnect does the rest.
 */

import { expect } from 'chai';
import { Channel } from '../../src/lightning/channel/channel';
import { ChannelState, HtlcState } from '../../src/lightning/channel/types';
import { FforSlotState, FforState } from '../../src/lightning/ffor/types';
import { encodeShortChannelId } from '../../src/lightning/gossip/types';
import { MessageType } from '../../src/lightning/message/types';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { PaymentStatus } from '../../src/lightning/node/types';
import {
	deserializeChannelState,
	serializeChannelState
} from '../../src/lightning/storage/serialization';
import {
	activateWorld,
	createConcurrentWorld
} from './helpers/ffor-concurrent-world';
import {
	IWorld,
	makeNodeConfig,
	NodeLink,
	openReadyChannel,
	publishChannel,
	record,
	TIP
} from './helpers/ffor-world';

/** Let every deferred dispatch (setImmediate) run. */
async function flush(turns = 5): Promise<void> {
	for (let i = 0; i < turns; i++) {
		await new Promise<void>((resolve) => setImmediate(resolve));
	}
}

async function waitFor(what: string, done: () => boolean): Promise<void> {
	for (let i = 0; i < 200; i++) {
		if (done()) return;
		await flush(1);
	}
	throw new Error(`timed out waiting for ${what}`);
}

let seed = 0;

/** A node X beyond R, with a channel R opened to it that S can route over. */
function addDownstream(w: IWorld): {
	x: LightningNode;
	rx: NodeLink;
	errors: string[];
} {
	seed += 1;
	const x = new LightningNode(makeNodeConfig(9_700 + seed));
	const errors: string[] = [];
	x.on('node:error', (e: { message: string }) => errors.push(e.message));
	const rx = new NodeLink(w.r, x);
	const channelId = openReadyChannel(w.r, x, 1_000_000n);
	const scid = encodeShortChannelId({ block: 500, txIndex: 7, outputIndex: 0 });
	for (const viewer of [w.s, w.r, x]) {
		publishChannel(viewer, w.r, x, channelId, scid);
	}
	x.handleNewBlock(TIP);
	return { x, rx, errors };
}

function srChannel(node: LightningNode, w: IWorld): Channel {
	return node.getChannelManager().getChannel(w.srChannelId)!;
}

function ordinary(ch: Channel): string[] {
	const out: string[] = [];
	for (const [key, e] of ch.getFullState().htlcs) {
		if (e.fforVoucher !== true) out.push(`${key}:${HtlcState[e.state]}`);
	}
	return out;
}

describe('FFOR concurrent receive: the drain hold through the node', function () {
	this.timeout(60_000);

	it('a forward owed upstream is settled by the node on channel:reestablished while the chain is held: the fulfil waits behind the chain, nothing fails, and the payer is paid out', async () => {
		const w = createConcurrentWorld();
		activateWorld(w, true);
		const { x, errors: xErrors } = addDownstream(w);

		// S pays X through R. The hold invoice parks the HTLC at X with both
		// adds irrevocably committed.
		const invoice = x.createInvoice({
			amountMsat: 3_000_000n,
			description: 'through R',
			hold: true
		});
		const payment = w.s.sendPayment(invoice.bolt11);
		await waitFor('the HTLC to park at X', () =>
			x.listHoldInvoices().some((h) => h.state === 'ACCEPTED')
		);
		expect(payment.status).to.equal(PaymentStatus.PENDING);
		expect(ordinary(srChannel(w.r, w)).length, 'inbound at R').to.equal(1);

		// S's row from before the close.
		const backup = JSON.stringify(
			serializeChannelState(srChannel(w.s, w).getFullState())
		);

		// R retires the book. S acknowledges; R's drain (three voucher fails
		// and their commitment_signed) is lost on the wire.
		const rId = w.r.getNodeId();
		w.sr.drop = (from, type): boolean =>
			from === rId && type !== MessageType.FF_CLOSE;
		const closed = w.r.closeFforEpoch(w.srHex);
		expect(closed.ok, closed.error).to.equal(true);
		await flush();
		expect(record(w.r, w.srHex).state).to.equal(FforState.DRAINING);
		w.sr.drop = null;

		// The link goes down, and S comes back from the row that predates
		// ff_close: ACTIVE, with no close on record.
		w.sr.disconnect();
		w.s
			.getChannelManager()
			.restoreChannel(
				new Channel(deserializeChannelState(JSON.parse(backup))),
				rId
			);
		await flush();
		expect(record(w.s, w.srHex).state).to.equal(FforState.ACTIVE);

		// X settles while the inbound channel cannot carry the fulfil: R
		// holds the preimage and owes it upstream.
		x.settleHeldHtlc(invoice.paymentHash);
		await flush();
		const owed = ordinary(srChannel(w.r, w));
		expect(owed.length, 'the inbound HTLC is still on R').to.equal(1);
		expect(owed[0]).to.match(/^received-\d+:COMMITTED$/);

		// The reconnect. Nothing is called on R: its node hears
		// channel:reestablished and settles the forward upstream on its own,
		// while the chain is held.
		w.sr.log.length = 0;
		w.errors.s.length = 0;
		w.errors.r.length = 0;
		w.sr.reconnect();
		await flush();
		await waitFor('the payer to be paid out', () => {
			return payment.status !== PaymentStatus.PENDING;
		});
		await flush();

		const wire = w.sr.log.map((e) => `${e.from === rId ? 'R' : 'S'}:${e.type}`);
		expect(wire, `no wire error ${JSON.stringify(w.errors)}`).to.not.include(
			`S:${MessageType.ERROR}`
		);
		expect(wire).to.not.include(`R:${MessageType.ERROR}`);
		// The fulfil of the forward joined the held chain, and the held
		// commitment_signed was made again over it: the three voucher fails,
		// the fulfil, then one signature that covers all four.
		const fromR = w.sr.log.filter((e) => e.from === rId).map((e) => e.type);
		expect(fromR.slice(0, 7)).to.deep.equal([
			MessageType.CHANNEL_REESTABLISH,
			MessageType.FF_CLOSE,
			MessageType.UPDATE_FAIL_HTLC,
			MessageType.UPDATE_FAIL_HTLC,
			MessageType.UPDATE_FAIL_HTLC,
			MessageType.UPDATE_FULFILL_HTLC,
			MessageType.COMMITMENT_SIGNED
		]);
		expect(srChannel(w.s, w).getState()).to.equal(ChannelState.NORMAL);
		expect(srChannel(w.r, w).getState()).to.equal(ChannelState.NORMAL);
		expect(payment.status).to.equal(PaymentStatus.COMPLETED);
		expect(record(w.r, w.srHex).state).to.equal(FforState.CLOSED);
		expect(record(w.s, w.srHex).state).to.equal(FforState.CLOSED);
		expect(ordinary(srChannel(w.r, w))).to.deep.equal([]);
		expect(ordinary(srChannel(w.s, w))).to.deep.equal([]);
		expect(xErrors).to.deep.equal([]);

		for (const node of [w.p, w.s, w.r, x]) node.destroy();
	});

	it("S's second acknowledgement differs while the chain is held: R's node asks its host to drop the connection, once, and the reconnect settles the forward the dispute held back", async () => {
		// The same forward owed upstream, but S's row also predates a
		// settlement, so the acknowledgement it signs again differs from the
		// one R processed. R records the dispute and keeps its chain held;
		// its own settles are refused until the channel reestablishes. The
		// manager asks for that reestablish (transition:blocked), the node
		// applies the disconnect and tells its host
		// (peer:disconnect-requested), and the reconnect drains: without the
		// request the forward would wait for its on-chain deadline on a
		// healthy connection.
		const w = createConcurrentWorld();
		activateWorld(w, true);
		const { x, errors: xErrors } = addDownstream(w);
		const invoice = x.createInvoice({
			amountMsat: 3_000_000n,
			description: 'through R',
			hold: true
		});
		const payment = w.s.sendPayment(invoice.bolt11);
		await waitFor('the HTLC to park at X', () =>
			x.listHoldInvoices().some((h) => h.state === 'ACCEPTED')
		);
		const rId = w.r.getNodeId();
		const sId = w.s.getNodeId();
		const backup = JSON.stringify(
			serializeChannelState(srChannel(w.s, w).getFullState())
		);
		// S settles slot 2 after that row was written.
		const settled = w.s
			.getChannelManager()
			.fforSetSlot(
				w.srChannelId,
				2,
				FforSlotState.SETTLED,
				`${'ab'.repeat(32)}:2`
			);
		expect(settled.ok, settled.error).to.equal(true);
		w.sr.drop = (from, type): boolean =>
			from === rId && type !== MessageType.FF_CLOSE;
		const closed = w.r.closeFforEpoch(w.srHex);
		expect(closed.ok, closed.error).to.equal(true);
		await flush();
		expect(record(w.r, w.srHex).state).to.equal(FforState.DRAINING);
		w.sr.drop = null;
		w.sr.disconnect();
		w.s
			.getChannelManager()
			.restoreChannel(
				new Channel(deserializeChannelState(JSON.parse(backup))),
				rId
			);
		await flush();
		x.settleHeldHtlc(invoice.paymentHash);
		await flush();

		const requested: string[] = [];
		const enforce: string[] = [];
		w.r.on('peer:disconnect-requested', (pubkey: string) =>
			requested.push(pubkey)
		);
		w.r.on('ffor:enforce', (e: { channelId: Buffer }) =>
			enforce.push(e.channelId.toString('hex'))
		);
		w.sr.log.length = 0;
		w.sr.reconnect();
		// In the dispute, before the node's deferred disconnect. The node
		// settled the forward on channel:reestablished, ahead of S's
		// acknowledgement, so its fulfil waits in the held chain; nothing of
		// R's stream has left, and the payer is still waiting.
		expect(record(w.r, w.srHex).activationMismatch).to.equal(true);
		expect(payment.status).to.equal(PaymentStatus.PENDING);
		expect(ordinary(srChannel(w.r, w))[0]).to.match(/^received-\d+:FULFILLED$/);
		expect(
			w.sr.log.filter((e) => e.from === rId).map((e) => e.type)
		).to.deep.equal([MessageType.CHANNEL_REESTABLISH, MessageType.FF_CLOSE]);
		await waitFor('the node to ask its host for the disconnect', () => {
			return requested.length > 0;
		});
		expect(requested).to.deep.equal([sId]);
		expect(enforce).to.deep.equal([w.srHex]);
		expect(srChannel(w.r, w).getState()).to.equal(
			ChannelState.AWAITING_REESTABLISH
		);
		// The host severs the transport and the peers reconnect.
		w.sr.disconnect();
		w.sr.reconnect();
		await waitFor('the payer to be paid out', () => {
			return payment.status !== PaymentStatus.PENDING;
		});
		await flush();
		const wire = w.sr.log.map((e) => `${e.from === rId ? 'R' : 'S'}:${e.type}`);
		expect(wire, JSON.stringify(w.errors)).to.not.include(
			`S:${MessageType.ERROR}`
		);
		expect(wire).to.not.include(`R:${MessageType.ERROR}`);
		expect(payment.status).to.equal(PaymentStatus.COMPLETED);
		expect(record(w.r, w.srHex).state).to.equal(FforState.CLOSED);
		expect(record(w.s, w.srHex).state).to.equal(FforState.CLOSED);
		expect(ordinary(srChannel(w.r, w))).to.deep.equal([]);
		expect(requested.length, 'asked once').to.equal(1);
		expect(xErrors).to.deep.equal([]);

		for (const node of [w.p, w.s, w.r, x]) node.destroy();
	});
});
