/**
 * Reestablish cluster regressions (S-2.H5 + S-2.M1, 2026-07-15 review).
 *
 * S-2.H5: uncommitted REMOTE updates must not survive a disconnect. The peer
 * forgets updates it never committed via commitment_signed and retransmits
 * (possibly different) updates after reestablish. Keeping them (a) stranded a
 * phantom received-HTLC that permanently debited remoteBalanceMsat and leaked
 * an HTLC slot, and (b) combined with the id-only add dedup, silently
 * swallowed a legitimately REUSED id carrying a different HTLC (CLN drops
 * uncommitted adds on reconnect and reuses the id), desyncing the commitment
 * into a force close. The dedup is now content-aware: identical replays stay
 * no-ops, an id collision with different contents fails the channel.
 *
 * S-2.M1: when the peer missed BOTH our last revoke_and_ack and our last
 * commitment_signed, BOLT 2 requires retransmission in the ORIGINAL relative
 * order. The handler always replayed revoke_and_ack first, desyncing a
 * crossed commitment round; the order is now recorded (lastSentWasRevoke)
 * and honored.
 *
 * Wire harness modeled on reestablish-update-retransmission.test.ts.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import { Channel } from '../../src/lightning/channel/channel';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	HtlcState
} from '../../src/lightning/channel/types';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { MessageType } from '../../src/lightning/message/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	serializeChannelState,
	deserializeChannelState
} from '../../src/lightning/storage/serialization';

const sha256 = (b: Buffer): Buffer =>
	crypto.createHash('sha256').update(b).digest();

function makeConfig(name: string): IChannelManagerConfig {
	const seed = sha256(Buffer.from(`reest-cluster-${name}`));
	const k = (i: number): Buffer =>
		sha256(Buffer.concat([seed, Buffer.from([i])]));
	const basepoints: IChannelBasepoints = {
		fundingPubkey: getPublicKey(k(0)),
		revocationBasepoint: getPublicKey(k(1)),
		paymentBasepoint: getPublicKey(k(2)),
		delayedPaymentBasepoint: getPublicKey(k(3)),
		htlcBasepoint: getPublicKey(k(4)),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
	return {
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: basepoints,
		localPerCommitmentSeed: sha256(Buffer.from(`${name}-commit`)),
		localFundingPrivkey: k(0),
		htlcBasepointSecret: k(4),
		nodePrivateKey: sha256(Buffer.from(`${name}-node`)),
		preferAnchors: true
	};
}

const FUNDING_SATOSHIS = 1_000_000n;
const CAPACITY_MSAT = FUNDING_SATOSHIS * 1000n;

interface IWire {
	cutBefore: (type: MessageType, fromB?: boolean) => void;
	cut: () => void;
	log: string[];
	reconnect: () => void;
	restartA: (snapshot?: string) => void;
}

interface IPair {
	A: () => ChannelManager;
	B: () => ChannelManager;
	channelId: Buffer;
	aChannel: () => Channel;
	bChannel: () => Channel;
	errors: string[];
	fulfilled: Buffer[];
	wire: IWire;
	snapshotA: () => string;
	disconnectBoth: () => void;
}

function makePair(tag: string): IPair {
	const aConfig = makeConfig(`${tag}-A`);
	const bConfig = makeConfig(`${tag}-B`);
	const aPub = getPublicKey(aConfig.nodePrivateKey!).toString('hex');
	const bPub = getPublicKey(bConfig.nodePrivateKey!).toString('hex');
	const managers = new Map<string, ChannelManager>();
	managers.set(aPub, new ChannelManager(aConfig));
	managers.set(bPub, new ChannelManager(bConfig));
	const errors: string[] = [];
	const fulfilled: Buffer[] = [];
	const log: string[] = [];

	let alive = true;
	let cutType: MessageType | null = null;
	let cutFromB = false;
	let paused = false;
	const queue: Array<{ from: string; to: string; type: number; p: Buffer }> =
		[];

	const dispatch = (
		from: string,
		to: string,
		type: number,
		p: Buffer
	): void => {
		if (!alive) return;
		if (cutType !== null && type === cutType && (from === bPub) === cutFromB) {
			alive = false;
			cutType = null;
			return;
		}
		log.push(`${from === aPub ? 'A->B' : 'B->A'} ${MessageType[type]}`);
		managers.get(to)!.handleMessage(from, type, p);
	};
	const attach = (pub: string, peer: string): void => {
		const m = managers.get(pub)!;
		m.on('error', (_id, msg: string) =>
			errors.push(`${pub === aPub ? 'A' : 'B'}: ${msg}`)
		);
		m.on('message:outbound', (to: string, type: number, p: Buffer) => {
			if (managers.get(pub) !== m) return;
			if (to !== peer) return;
			if (paused) {
				queue.push({ from: pub, to, type, p });
				return;
			}
			dispatch(pub, to, type, p);
		});
	};
	attach(aPub, bPub);
	attach(bPub, aPub);
	managers
		.get(bPub)!
		.on('htlc:fulfilled', (_c, _id, preimage: Buffer) =>
			fulfilled.push(preimage)
		);

	const aChan = managers.get(aPub)!.openChannel(bPub, FUNDING_SATOSHIS);
	managers
		.get(aPub)!
		.createFunding(aChan, crypto.randomBytes(32), 0, crypto.randomBytes(64));
	const channelId = aChan.getChannelId()!;
	managers.get(aPub)!.handleFundingConfirmed(channelId);
	managers.get(bPub)!.handleFundingConfirmed(channelId);

	const chan = (pub: string, peer: string): Channel =>
		managers.get(pub)!.getChannelsByPeer(peer)[0];
	expect(chan(aPub, bPub).getState()).to.equal(ChannelState.NORMAL);

	const reestPayload = (c: Channel): Buffer =>
		(
			c
				.createReestablish()
				.find((x) => x.type === ChannelActionType.SEND_MESSAGE) as {
				payload: Buffer;
			}
		).payload;

	const wire: IWire = {
		cutBefore: (type: MessageType, fromB = false): void => {
			cutType = type;
			cutFromB = fromB;
		},
		cut: (): void => {
			alive = false;
		},
		log,
		reconnect: (): void => {
			const a = managers.get(aPub)!;
			const b = managers.get(bPub)!;
			const aC = chan(aPub, bPub);
			const bC = chan(bPub, aPub);
			if (aC.getState() === ChannelState.NORMAL) a.handlePeerDisconnected(bPub);
			if (bC.getState() === ChannelState.NORMAL) b.handlePeerDisconnected(aPub);
			alive = true;
			cutType = null;
			paused = true;
			const aRe = reestPayload(aC);
			const bRe = reestPayload(bC);
			b.handleMessage(aPub, MessageType.CHANNEL_REESTABLISH, aRe);
			a.handleMessage(bPub, MessageType.CHANNEL_REESTABLISH, bRe);
			paused = false;
			while (queue.length > 0) {
				const m = queue.shift()!;
				dispatch(m.from, m.to, m.type, m.p);
			}
		},
		restartA: (snapshot?: string): void => {
			alive = false;
			const state = snapshot
				? deserializeChannelState(JSON.parse(snapshot))
				: deserializeChannelState(
						JSON.parse(
							JSON.stringify(
								serializeChannelState(chan(aPub, bPub).getFullState())
							)
						)
				  );
			const a2 = new ChannelManager(aConfig);
			a2.restoreChannel(new Channel(state), bPub);
			managers.set(aPub, a2);
			attach(aPub, bPub);
			managers.get(bPub)!.handlePeerDisconnected(aPub);
		}
	};

	return {
		A: (): ChannelManager => managers.get(aPub)!,
		B: (): ChannelManager => managers.get(bPub)!,
		channelId,
		aChannel: (): Channel => chan(aPub, bPub),
		bChannel: (): Channel => chan(bPub, aPub),
		errors,
		fulfilled,
		wire,
		snapshotA: (): string =>
			JSON.stringify(serializeChannelState(chan(aPub, bPub).getFullState())),
		disconnectBoth: (): void => {
			alive = false;
			managers.get(aPub)!.handlePeerDisconnected(bPub);
			managers.get(bPub)!.handlePeerDisconnected(aPub);
		}
	};
}

describe('S-2.H5: uncommitted remote updates reversed on disconnect', function () {
	it('reverses an uncommitted add: balance and slot restored, replay re-applies cleanly', function () {
		const t = makePair('reverse-add');
		const preimage = crypto.randomBytes(32);
		const hash = sha256(preimage);
		// The wire dies before A's commitment_signed: B holds an UNCOMMITTED add.
		t.wire.cutBefore(MessageType.COMMITMENT_SIGNED);
		t.A().addHtlc(t.channelId, 1_000_000n, hash, 900, Buffer.alloc(1366));
		const bState = t.bChannel().getFullState();
		expect(bState.htlcs.size, 'B holds the uncommitted add').to.equal(1);
		expect(bState.remoteBalanceMsat).to.equal(CAPACITY_MSAT - 1_000_000n);

		// Disconnect observed: the uncommitted remote add must be REVERSED —
		// entry gone, provisional remote-balance debit restored.
		t.disconnectBoth();
		expect(bState.htlcs.size, 'phantom entry removed').to.equal(0);
		expect(bState.remoteBalanceMsat, 'provisional debit restored').to.equal(
			CAPACITY_MSAT
		);

		// A retransmits the add after reestablish; the round completes once.
		t.wire.reconnect();
		expect(t.errors, t.errors.join('; ')).to.have.length(0);
		const bEntry = [...t.bChannel().getFullState().htlcs.values()].find((h) =>
			h.paymentHash.equals(hash)
		);
		expect(bEntry, 'replayed add re-applied').to.not.equal(undefined);
		t.B().fulfillHtlc(t.channelId, bEntry!.id, preimage);
		expect(t.errors, t.errors.join('; ')).to.have.length(0);
		expect(t.bChannel().getBalances().localMsat).to.equal(1_000_000n);
	});

	it('a restarted sender reusing the id for a DIFFERENT HTLC completes instead of desyncing', function () {
		const t = makePair('id-reuse');
		// Snapshot A before any payment: a real node whose disk lags the wire.
		const preAddSnapshot = t.snapshotA();

		// A adds HTLC id 0; B receives it but never a commitment_signed.
		t.wire.cutBefore(MessageType.COMMITMENT_SIGNED);
		t.A().addHtlc(
			t.channelId,
			1_000_000n,
			sha256(Buffer.from('first-payment')),
			900,
			Buffer.alloc(1366)
		);

		// A restarts from the pre-add snapshot: its htlc counter is back at 0,
		// and per BOLT 2 it may reuse id 0 for a completely different HTLC.
		t.wire.restartA(preAddSnapshot);
		t.wire.reconnect();
		expect(t.errors, t.errors.join('; ')).to.have.length(0);

		const preimage = crypto.randomBytes(32);
		const hash2 = sha256(preimage);
		t.A().addHtlc(t.channelId, 2_000_000n, hash2, 900, Buffer.alloc(1366));
		expect(t.errors, t.errors.join('; ')).to.have.length(0);

		// B holds exactly the NEW HTLC (the stale uncommitted one was reversed;
		// before the fix the id-only dedup swallowed this add and the following
		// commitment_signed desynced the channel).
		const bHtlcs = [...t.bChannel().getFullState().htlcs.values()];
		expect(bHtlcs).to.have.length(1);
		expect(bHtlcs[0].paymentHash.equals(hash2)).to.equal(true);
		expect(bHtlcs[0].amountMsat).to.equal(2_000_000n);
		t.B().fulfillHtlc(t.channelId, bHtlcs[0].id, preimage);
		expect(t.errors, t.errors.join('; ')).to.have.length(0);
		expect(t.bChannel().getBalances().localMsat).to.equal(2_000_000n);
	});

	it('fails the channel on an id collision with different contents (no silent desync)', function () {
		const t = makePair('id-collision');
		const preimage = crypto.randomBytes(32);
		const hash = sha256(preimage);
		// Fully commit a payment so B's received-0 is COMMITTED (survives
		// disconnects) and its id can never be legitimately reused.
		t.A().addHtlc(t.channelId, 1_000_000n, hash, 900, Buffer.alloc(1366));
		expect(t.errors, t.errors.join('; ')).to.have.length(0);

		const actions = t.bChannel().handleUpdateAddHtlc({
			channelId: t.channelId,
			id: 0n,
			amountMsat: 3_000_000n,
			paymentHash: sha256(Buffer.from('other')),
			cltvExpiry: 950,
			onionRoutingPacket: Buffer.alloc(1366)
		});
		const err = actions.find((a) => a.type === ChannelActionType.ERROR) as
			| { message: string }
			| undefined;
		expect(err, 'channel failed on the collision').to.not.equal(undefined);
		expect(err!.message).to.match(/reuses id/);

		// A byte-identical replay stays a no-op.
		const committed = t.bChannel().getFullState().htlcs.get('received-0')!;
		const replay = t.bChannel().handleUpdateAddHtlc({
			channelId: t.channelId,
			id: 0n,
			amountMsat: committed.amountMsat,
			paymentHash: committed.paymentHash,
			cltvExpiry: committed.cltvExpiry,
			onionRoutingPacket: committed.onionRoutingPacket
		});
		expect(replay).to.have.length(0);
	});

	it('reverses an uncommitted remote fulfill: HTLC restored, replay settles once', function () {
		const t = makePair('reverse-fulfill');
		const preimage = crypto.randomBytes(32);
		const hash = sha256(preimage);
		// Payment fully committed first.
		t.A().addHtlc(t.channelId, 2_000_000n, hash, 900, Buffer.alloc(1366));
		expect(t.errors, t.errors.join('; ')).to.have.length(0);
		const bEntry = [...t.bChannel().getFullState().htlcs.values()][0];

		// B fulfills; A receives the update_fulfill but never B's covering
		// commitment_signed (the wire dies before it).
		t.wire.cutBefore(MessageType.COMMITMENT_SIGNED, true);
		t.B().fulfillHtlc(t.channelId, bEntry.id, preimage);
		const aEntry = t.aChannel().getFullState().htlcs.get(`offered-0`)!;
		expect(aEntry.state).to.equal(HtlcState.FULFILLED);

		// Disconnect: the uncommitted remote removal is reversed.
		t.disconnectBoth();
		expect(aEntry.state, 'removal reversed to COMMITTED').to.equal(
			HtlcState.COMMITTED
		);
		expect(aEntry.removalLocallyRevoked).to.equal(undefined);
		expect(aEntry.removalRemoteCommitted).to.equal(undefined);

		// B replays the fulfill after reestablish; balances settle exactly once.
		t.wire.reconnect();
		expect(t.errors, t.errors.join('; ')).to.have.length(0);
		expect(t.aChannel().getFullState().htlcs.size).to.equal(0);
		expect(t.bChannel().getBalances().localMsat).to.equal(2_000_000n);
		expect(t.aChannel().getBalances().localMsat).to.equal(
			CAPACITY_MSAT - 2_000_000n
		);
	});
});

describe('S-2.M1: retransmission preserves the original send order', function () {
	/**
	 * Build a channel with both retransmission caches populated (one full
	 * commitment round), force it into AWAITING_REESTABLISH, and hand it a
	 * reestablish message claiming the peer missed BOTH our last
	 * revoke_and_ack and our last commitment_signed.
	 */
	function dualRetransmitSetup(
		tag: string,
		lastSentWasRevoke: boolean
	): MessageType[] {
		const t = makePair(tag);
		const preimage = crypto.randomBytes(32);
		const hash = sha256(preimage);
		// One committed round in each direction populates both caches
		// (lastSentCommitmentSigned + lastSentRevokeSecret) on A.
		t.A().addHtlc(t.channelId, 1_000_000n, hash, 900, Buffer.alloc(1366));
		const bEntry = [...t.bChannel().getFullState().htlcs.values()][0];
		t.B().fulfillHtlc(t.channelId, bEntry.id, preimage);
		expect(t.errors, t.errors.join('; ')).to.have.length(0);

		const aC = t.aChannel();
		const st = aC.getFullState();
		expect(
			st.lastSentCommitmentSigned,
			'commitment cache present'
		).to.not.equal(null);
		expect(st.lastSentRevokeSecret, 'revoke cache present').to.not.equal(null);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(st as any).lastSentWasRevoke = lastSentWasRevoke;

		t.disconnectBoth();
		// The peer claims it missed our last commitment_signed AND our last
		// revoke_and_ack: nextCommitmentNumber <= remoteCommitmentNumber and
		// nextRevocationNumber + 1 == localCommitmentNumber.
		const actions = aC.handleReestablish({
			channelId: t.channelId,
			nextCommitmentNumber: st.remoteCommitmentNumber,
			nextRevocationNumber: st.localCommitmentNumber - 1n,
			yourLastPerCommitmentSecret: Buffer.alloc(32),
			myCurrentPerCommitmentPoint: Buffer.alloc(33)
		});
		return actions
			.filter(
				(a) =>
					a.type === ChannelActionType.SEND_MESSAGE &&
					((a as { messageType: MessageType }).messageType ===
						MessageType.COMMITMENT_SIGNED ||
						(a as { messageType: MessageType }).messageType ===
							MessageType.REVOKE_AND_ACK)
			)
			.map((a) => (a as { messageType: MessageType }).messageType);
	}

	it('commitment_signed sent first originally: it is retransmitted first', function () {
		// lastSentWasRevoke=true: the revoke was the LAST thing sent, so the
		// original order was commitment_signed -> revoke_and_ack.
		const order = dualRetransmitSetup('order-commit-first', true);
		expect(order.length).to.be.greaterThan(1);
		expect(order.indexOf(MessageType.COMMITMENT_SIGNED)).to.be.lessThan(
			order.indexOf(MessageType.REVOKE_AND_ACK)
		);
	});

	it('revoke_and_ack sent first originally: it is retransmitted first', function () {
		const order = dualRetransmitSetup('order-revoke-first', false);
		expect(order.length).to.be.greaterThan(1);
		expect(order.indexOf(MessageType.REVOKE_AND_ACK)).to.be.lessThan(
			order.indexOf(MessageType.COMMITMENT_SIGNED)
		);
	});

	it('the recorded order survives serialization round-trip', function () {
		const t = makePair('order-persist');
		const preimage = crypto.randomBytes(32);
		t.A().addHtlc(
			t.channelId,
			1_000_000n,
			sha256(preimage),
			900,
			Buffer.alloc(1366)
		);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const st = t.aChannel().getFullState() as any;
		// The last message of a settled round we initiated is our
		// revoke_and_ack for the peer's crossing commitment.
		expect(st.lastSentWasRevoke).to.not.equal(null);
		expect(st.lastSentWasRevoke).to.not.equal(undefined);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const restored = deserializeChannelState(
			JSON.parse(JSON.stringify(serializeChannelState(st)))
		) as any;
		expect(restored.lastSentWasRevoke).to.equal(st.lastSentWasRevoke);
	});
});
