/**
 * The expiry auto-fail and a received add that is not irrevocably committed
 * (issue #1297).
 *
 * scanExpiringHtlcs fails back a received HTLC that nears its cltv_expiry.
 * BOLT 2 allows update_fail_htlc only once the add is irrevocably committed
 * on both sides, and the scan did not ask. For an update_add_htlc the peer
 * had sent but not yet signed in, the fail went out one block later, a stock
 * peer answered "update_fail_htlc for an HTLC not yet committed" with a wire
 * error, and the channel was lost over an HTLC nobody owed anything on.
 *
 * Nothing is owed on such an add. Unsigned, it is in no commitment at all,
 * and a disconnect rolls it back. Signed in but not yet revoked for by the
 * peer, it is the peer's to time out on chain. Either way it becomes failable
 * the moment the round completes, and the scan (or the node's own dispatch)
 * takes it from there.
 *
 * Every case drives real messages between two nodes and stops chosen ones.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { IChannelState } from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	HtlcDirection,
	HtlcState,
	IHtlcEntry,
	receivedAddIrrevocablyCommitted
} from '../../src/lightning/channel/types';
import { MessageType } from '../../src/lightning/message/types';
import {
	buildGraph,
	createNode,
	openReadyChannel
} from './helpers/loopback-nodes';

const TAG = 'expiry-autofail-unsigned-add';
const HEIGHT = 800_000;
/** LightningNode's default htlcSafetyMargin. */
const MARGIN = 6;
const HTLC_MSAT = 50_000_000n;

type Side = 'alice' | 'bob';

interface IRig {
	alice: LightningNode;
	bob: LightningNode;
	channelId: Buffer;
	/** Message types from each side that are stopped, and what was stopped. */
	drop: Record<Side, Set<number>>;
	dropped: Record<Side, Array<{ type: number; payload: Buffer }>>;
	/** Every message type each side put on the wire, stopped or not. */
	sent: Record<Side, number[]>;
	errors: Record<Side, string[]>;
	destroy: () => void;
}

function rig(seedBase: number): IRig {
	const alice = createNode(TAG, seedBase);
	const bob = createNode(TAG, seedBase + 1);
	const r: IRig = {
		alice,
		bob,
		channelId: Buffer.alloc(0),
		drop: { alice: new Set(), bob: new Set() },
		dropped: { alice: [], bob: [] },
		sent: { alice: [], bob: [] },
		errors: { alice: [], bob: [] },
		destroy: (): void => {
			alice.destroy();
			bob.destroy();
		}
	};
	const route = (from: LightningNode, to: LightningNode, side: Side): void => {
		from.on('message:outbound', (pk: string, t: number, p: Buffer) => {
			if (pk !== to.getNodeId()) return;
			r.sent[side].push(t);
			if (r.drop[side].has(t)) {
				r.dropped[side].push({ type: t, payload: p });
				return;
			}
			to.handlePeerMessage(from.getNodeId(), t, p);
		});
	};
	route(alice, bob, 'alice');
	route(bob, alice, 'bob');
	r.channelId = openReadyChannel(alice, bob);
	buildGraph(alice, bob, [r.channelId]);
	alice.on('node:error', (e: { code: string }) => r.errors.alice.push(e.code));
	bob.on('node:error', (e: { code: string }) => r.errors.bob.push(e.code));
	alice.handleNewBlock(HEIGHT);
	bob.handleNewBlock(HEIGHT);
	r.sent.alice.length = 0;
	r.sent.bob.length = 0;
	return r;
}

function fullState(node: LightningNode, channelId: Buffer): IChannelState {
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	return (node.getChannelManager().getChannel(channelId) as any).getFullState();
}

function received(st: IChannelState): IHtlcEntry[] {
	return [...st.htlcs.values()].filter(
		(e) => e.direction === HtlcDirection.RECEIVED
	);
}

function fails(types: number[]): number[] {
	return types.filter(
		(t) =>
			t === MessageType.UPDATE_FAIL_HTLC ||
			t === MessageType.UPDATE_FAIL_MALFORMED_HTLC
	);
}

/** Alice offers an HTLC Bob has no use for, expiring at `expiry`. */
function offer(r: IRig, expiry: number): void {
	const res = r.alice
		.getChannelManager()
		.addHtlc(
			r.channelId,
			HTLC_MSAT,
			crypto.randomBytes(32),
			expiry,
			Buffer.alloc(1366)
		);
	expect(res.ok, res.error).to.equal(true);
}

/** Releases every message of `type` that was stopped on `side`, in order. */
function release(r: IRig, side: Side, type: number): void {
	r.drop[side].delete(type);
	const from = r[side];
	const to = side === 'alice' ? r.bob : r.alice;
	const held = r.dropped[side].filter((m) => m.type === type);
	r.dropped[side] = r.dropped[side].filter((m) => m.type !== type);
	for (const m of held)
		to.handlePeerMessage(from.getNodeId(), m.type, m.payload);
}

describe('Expiry auto-fail and an add that is not irrevocably committed (issue #1297)', function () {
	this.timeout(20_000);

	it('sends no update_fail_htlc for an add the peer has not signed in, and the channel survives', function () {
		const r = rig(10);
		r.drop.alice.add(MessageType.COMMITMENT_SIGNED);
		offer(r, HEIGHT + MARGIN - 2);
		const entry = received(fullState(r.bob, r.channelId))[0];
		expect(entry.state).to.equal(HtlcState.PENDING);
		expect(entry.addLocallyRevoked, 'unsigned').to.equal(false);
		expect(r.dropped.alice, 'her signature was stopped').to.have.length(1);

		// One block, with the expiry already inside the fail margin.
		r.bob.handleNewBlock(HEIGHT + 1);

		expect(fails(r.sent.bob), 'no early fail on the wire').to.have.length(0);
		expect(
			r.sent.alice,
			'and nothing for the peer to object to'
		).to.not.include(MessageType.ERROR);
		expect(fullState(r.bob, r.channelId).state).to.equal(ChannelState.NORMAL);
		expect(fullState(r.alice, r.channelId).state).to.equal(ChannelState.NORMAL);
		expect(
			received(fullState(r.bob, r.channelId))[0].state,
			'the add is untouched'
		).to.equal(HtlcState.PENDING);
		r.destroy();
	});

	it('nothing is owed if the peer never signs: blocks past the expiry change nothing, and a disconnect drops the add', function () {
		const r = rig(20);
		r.drop.alice.add(MessageType.COMMITMENT_SIGNED);
		const expiry = HEIGHT + MARGIN - 2;
		offer(r, expiry);
		const before = fullState(r.bob, r.channelId).remoteBalanceMsat;

		for (let height = HEIGHT + 1; height <= expiry + 3; height++) {
			r.bob.handleNewBlock(height);
		}

		expect(fails(r.sent.bob)).to.have.length(0);
		expect(r.errors.bob, 'no backstop fired either').to.have.length(0);
		expect(fullState(r.bob, r.channelId).state).to.equal(ChannelState.NORMAL);
		expect(fullState(r.alice, r.channelId).state).to.equal(ChannelState.NORMAL);

		r.bob.getChannelManager().handlePeerDisconnected(r.alice.getNodeId());
		const st = fullState(r.bob, r.channelId);
		expect(received(st), 'rolled back').to.have.length(0);
		expect(st.remoteBalanceMsat, 'with the amount back on the peer').to.equal(
			before + HTLC_MSAT
		);
		r.destroy();
	});

	it('the add is failed back once the peer signs it in and the round completes', function () {
		const r = rig(30);
		r.drop.alice.add(MessageType.COMMITMENT_SIGNED);
		offer(r, HEIGHT + MARGIN - 2);
		r.bob.handleNewBlock(HEIGHT + 1);
		expect(fails(r.sent.bob)).to.have.length(0);

		// Her signature arrives after all. The round completes, the add is
		// irrevocably committed, and it is failed back the ordinary way.
		release(r, 'alice', MessageType.COMMITMENT_SIGNED);

		expect(fails(r.sent.bob), 'failed back now').to.have.length(1);
		expect(r.sent.alice).to.not.include(MessageType.ERROR);
		expect(fullState(r.bob, r.channelId).htlcs.size).to.equal(0);
		expect(fullState(r.alice, r.channelId).htlcs.size).to.equal(0);
		expect(fullState(r.bob, r.channelId).state).to.equal(ChannelState.NORMAL);
		expect(fullState(r.alice, r.channelId).state).to.equal(ChannelState.NORMAL);
		r.destroy();
	});

	it('sends none for an add the peer signed in but has not revoked for, and fails it once it has', function () {
		// One step further along: her commitment_signed is accepted and ours
		// is out, but her revoke_and_ack for it is stopped. The add is in our
		// commitment and still not irrevocably committed.
		const r = rig(40);
		r.drop.alice.add(MessageType.REVOKE_AND_ACK);
		offer(r, HEIGHT + MARGIN - 2);
		const entry = received(fullState(r.bob, r.channelId))[0];
		expect(entry.state).to.equal(HtlcState.COMMITTED);
		expect(entry.addLocallyRevoked, 'signed in').to.equal(true);
		expect(receivedAddIrrevocablyCommitted(entry)).to.equal(false);

		r.bob.handleNewBlock(HEIGHT + 1);

		expect(fails(r.sent.bob), 'no early fail on the wire').to.have.length(0);
		expect(fullState(r.bob, r.channelId).state).to.equal(ChannelState.NORMAL);

		release(r, 'alice', MessageType.REVOKE_AND_ACK);

		expect(fails(r.sent.bob), 'failed back now').to.have.length(1);
		expect(r.sent.alice).to.not.include(MessageType.ERROR);
		expect(fullState(r.bob, r.channelId).htlcs.size).to.equal(0);
		expect(fullState(r.alice, r.channelId).htlcs.size).to.equal(0);
		r.destroy();
	});

	it('still fails an irrevocably committed add, at the same height as before', function () {
		// The arm's ordinary work. The node normally resolves an add the
		// moment it is irrevocably committed, so its dispatch is unhooked
		// here to leave one for the scan: committed on both sides, unresolved,
		// and running out of time.
		const r = rig(50);
		r.bob.getChannelManager().removeAllListeners('htlc:forwarded');
		const expiry = HEIGHT + 40;
		offer(r, expiry);
		const entry = received(fullState(r.bob, r.channelId))[0];
		expect(receivedAddIrrevocablyCommitted(entry)).to.equal(true);
		expect(fails(r.sent.bob), 'left unresolved').to.have.length(0);

		let failedAt: number | undefined;
		for (let height = HEIGHT + 1; height <= expiry; height++) {
			r.bob.handleNewBlock(height);
			if (failedAt === undefined && fails(r.sent.bob).length > 0) {
				failedAt = height;
			}
		}

		expect(failedAt, 'failed at the safety margin').to.equal(expiry - MARGIN);
		expect(fails(r.sent.bob), 'once').to.have.length(1);
		expect(r.sent.alice).to.not.include(MessageType.ERROR);
		expect(fullState(r.bob, r.channelId).htlcs.size).to.equal(0);
		expect(fullState(r.alice, r.channelId).htlcs.size).to.equal(0);
		expect(fullState(r.bob, r.channelId).state).to.equal(ChannelState.NORMAL);
		r.destroy();
	});
});
