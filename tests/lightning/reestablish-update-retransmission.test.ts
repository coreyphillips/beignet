/**
 * BOLT 2 reestablish: un-acked update_add_htlc / update_fulfill_htlc /
 * update_fail_htlc messages MUST be retransmitted on reconnection, BEFORE any
 * retransmitted commitment_signed.
 *
 * Previously only commitment_signed / revoke_and_ack were retransmitted: any
 * connection cut landing between an update and its signature either stranded
 * the HTLC forever (receiver never saw the update, sender never re-sent it)
 * or desynced the channel (the peer received a signature covering updates it
 * never got). The update_fulfill flavor is fund-affecting: the preimage-
 * bearing message is lost while the fulfiller's HTLC stays unresolved.
 *
 * Cases:
 *  (a) cut between update_add and commitment_signed -> reconnect -> payment
 *      completes exactly once;
 *  (b) update_fulfill lost with the connection -> reconnect -> the fulfill
 *      is replayed, the payer learns the preimage, balances settle;
 *  (c) receiver restarts from storage predating the update -> reconnect ->
 *      the replayed update drives a fresh round to completion;
 *  (d) update_fail lost -> reconnect -> the refund lands;
 *  plus a both-sides-kept control (peer holding the update treats the replay
 *  idempotently: no duplicate settlement).
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
	DEFAULT_CHANNEL_CONFIG
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
	const seed = sha256(Buffer.from(`reest-retx-${name}`));
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

/**
 * Loopback wire with a one-shot cut and reestablish-time FIFO queueing (a
 * real connection delivers both reestablish messages before any responses
 * they trigger).
 */
interface IWire {
	/** From the next message of `type` sent by `fromB?` B : A, drop it and
	 *  everything after (the connection died mid-flight). */
	cutBefore: (type: MessageType, fromB?: boolean) => void;
	cut: () => void;
	log: string[];
	reconnect: () => void;
	restartB: (snapshot?: string) => void;
	restartA: () => void;
}

interface IPair {
	/** LIVE manager accessors (survive wire.restart*). */
	A: () => ChannelManager;
	B: () => ChannelManager;
	channelId: Buffer;
	aChannel: () => Channel;
	bChannel: () => Channel;
	errors: string[];
	fulfilled: Buffer[];
	failed: bigint[];
	wire: IWire;
	snapshotB: () => string;
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
	const failed: bigint[] = [];
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
			alive = false; // the connection died before this message arrived
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
			if (managers.get(pub) !== m) return; // stale (restarted) manager
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
		.get(aPub)!
		.on('htlc:fulfilled', (_c, _id, preimage: Buffer) =>
			fulfilled.push(preimage)
		);
	managers.get(aPub)!.on('htlc:failed', (_c, id: bigint) => failed.push(id));

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
			// Both sides observe the disconnect, then exchange reestablish with
			// real-connection FIFO (responses queue behind both reestablishes).
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
		restartB: (snapshot?: string): void => {
			alive = false;
			const state = snapshot
				? deserializeChannelState(JSON.parse(snapshot))
				: deserializeChannelState(
						JSON.parse(
							JSON.stringify(
								serializeChannelState(chan(bPub, aPub).getFullState())
							)
						)
				  );
			const b2 = new ChannelManager(bConfig);
			b2.restoreChannel(new Channel(state), aPub);
			managers.set(bPub, b2);
			attach(bPub, aPub);
			managers.get(aPub)!.handlePeerDisconnected(bPub);
		},
		restartA: (): void => {
			alive = false;
			const state = deserializeChannelState(
				JSON.parse(
					JSON.stringify(serializeChannelState(chan(aPub, bPub).getFullState()))
				)
			);
			const a2 = new ChannelManager(aConfig);
			a2.restoreChannel(new Channel(state), bPub);
			a2.on('htlc:fulfilled', (_c, _id, preimage: Buffer) =>
				fulfilled.push(preimage)
			);
			a2.on('htlc:failed', (_c, id: bigint) => failed.push(id));
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
		failed,
		wire,
		snapshotB: (): string =>
			JSON.stringify(serializeChannelState(chan(bPub, aPub).getFullState()))
	};
}

describe('reestablish: un-acked update retransmission (BOLT 2)', function () {
	it('(a) cut between update_add and commitment_signed: payment completes after reconnect', function () {
		const t = makePair('cut-add-sig');
		const preimage = crypto.randomBytes(32);
		const hash = sha256(preimage);
		// The wire dies right before A's commitment_signed is delivered: B has
		// the update_add but no signature for it.
		t.wire.cutBefore(MessageType.COMMITMENT_SIGNED);
		t.A().addHtlc(t.channelId, 1_000_000n, hash, 900, Buffer.alloc(1366));
		expect(t.errors, t.errors.join('; ')).to.have.length(0);

		t.wire.reconnect();
		expect(t.errors, t.errors.join('; ')).to.have.length(0);
		expect(t.aChannel().getState()).to.equal(ChannelState.NORMAL);
		// B holds the committed HTLC; fulfilling completes the payment ONCE.
		const bEntry = [...t.bChannel().getFullState().htlcs.values()].find((h) =>
			h.paymentHash.equals(hash)
		);
		expect(bEntry, 'B holds the HTLC after reconnect').to.not.equal(undefined);
		t.B().fulfillHtlc(t.channelId, bEntry!.id, preimage);
		expect(t.errors, t.errors.join('; ')).to.have.length(0);
		expect(t.fulfilled).to.have.length(1);
		expect(t.bChannel().getBalances().localMsat).to.equal(1_000_000n);
		expect(t.aChannel().getBalances().localMsat).to.equal(
			CAPACITY_MSAT - 1_000_000n
		);
	});

	it('(a2) update_add itself lost with the connection: retransmitted on reconnect', function () {
		const t = makePair('lost-add');
		const preimage = crypto.randomBytes(32);
		const hash = sha256(preimage);
		// The wire dies right before the update_add is delivered: B never saw
		// the HTLC at all; A must retransmit the update, not just a signature.
		t.wire.cutBefore(MessageType.UPDATE_ADD_HTLC);
		t.A().addHtlc(t.channelId, 1_000_000n, hash, 900, Buffer.alloc(1366));
		expect(
			[...t.bChannel().getFullState().htlcs.values()],
			'B never saw the add'
		).to.have.length(0);

		t.wire.reconnect();
		expect(t.errors, t.errors.join('; ')).to.have.length(0);
		const bEntry = [...t.bChannel().getFullState().htlcs.values()].find((h) =>
			h.paymentHash.equals(hash)
		);
		expect(bEntry, 'the add was retransmitted').to.not.equal(undefined);
		t.B().fulfillHtlc(t.channelId, bEntry!.id, preimage);
		expect(t.errors, t.errors.join('; ')).to.have.length(0);
		expect(t.fulfilled).to.have.length(1);
		expect(t.bChannel().getBalances().localMsat).to.equal(1_000_000n);
	});

	it('(b) update_fulfill lost with the connection: the preimage-bearing update is replayed', function () {
		const t = makePair('lost-fulfill');
		const preimage = crypto.randomBytes(32);
		const hash = sha256(preimage);
		// Payment fully committed first.
		t.A().addHtlc(t.channelId, 2_000_000n, hash, 900, Buffer.alloc(1366));
		expect(t.errors, t.errors.join('; ')).to.have.length(0);
		const bEntry = [...t.bChannel().getFullState().htlcs.values()][0];

		// B fulfills, but the wire dies before the update_fulfill arrives: the
		// preimage never reaches A, and without retransmission the HTLC would
		// stay stranded until expiry (fund-affecting for B).
		t.wire.cutBefore(MessageType.UPDATE_FULFILL_HTLC, true);
		t.B().fulfillHtlc(t.channelId, bEntry.id, preimage);
		expect(t.fulfilled, 'the fulfill was lost').to.have.length(0);

		t.wire.reconnect();
		expect(t.errors, t.errors.join('; ')).to.have.length(0);
		expect(t.fulfilled, 'the fulfill was replayed').to.have.length(1);
		expect(sha256(t.fulfilled[0]).equals(hash)).to.equal(true);
		expect(t.bChannel().getBalances().localMsat).to.equal(2_000_000n);
		expect(t.aChannel().getBalances().localMsat).to.equal(
			CAPACITY_MSAT - 2_000_000n
		);
		expect(t.aChannel().getFullState().htlcs.size).to.equal(0);
		expect(t.bChannel().getFullState().htlcs.size).to.equal(0);
	});

	it('(c) receiver restarts from storage predating the update: fresh round completes', function () {
		const t = makePair('restart-b');
		// Persist B BEFORE the payment: a real node whose disk lags the wire.
		const preUpdateSnapshot = t.snapshotB();
		const preimage = crypto.randomBytes(32);
		const hash = sha256(preimage);
		t.wire.cutBefore(MessageType.UPDATE_ADD_HTLC); // B never processes it live
		t.A().addHtlc(t.channelId, 1_500_000n, hash, 900, Buffer.alloc(1366));

		// B restarts from the pre-update snapshot.
		t.wire.restartB(preUpdateSnapshot);
		t.wire.reconnect();
		expect(t.errors, t.errors.join('; ')).to.have.length(0);
		const bChan = t.bChannel();
		const bEntry = [...bChan.getFullState().htlcs.values()].find((h) =>
			h.paymentHash.equals(hash)
		);
		expect(bEntry, 'restored B received the replayed add').to.not.equal(
			undefined
		);
		t.B().fulfillHtlc(t.channelId, bEntry!.id, preimage);
		expect(t.errors, t.errors.join('; ')).to.have.length(0);
		expect(t.fulfilled).to.have.length(1);
		expect(bChan.getBalances().localMsat).to.equal(1_500_000n);
	});

	it('(d) update_fail lost with the connection: the refund lands after reconnect', function () {
		const t = makePair('lost-fail');
		const hash = sha256(crypto.randomBytes(32));
		t.A().addHtlc(t.channelId, 1_200_000n, hash, 900, Buffer.alloc(1366));
		const bEntry = [...t.bChannel().getFullState().htlcs.values()][0];
		t.wire.cutBefore(MessageType.UPDATE_FAIL_HTLC, true);
		t.B().failHtlc(t.channelId, bEntry.id, Buffer.from('no route'));
		expect(t.failed).to.have.length(0);

		t.wire.reconnect();
		expect(t.errors, t.errors.join('; ')).to.have.length(0);
		expect(t.failed, 'the fail was replayed').to.have.length(1);
		expect(t.aChannel().getBalances().localMsat).to.equal(CAPACITY_MSAT);
		expect(t.aChannel().getFullState().htlcs.size).to.equal(0);
		expect(t.bChannel().getFullState().htlcs.size).to.equal(0);
	});

	it('control: a peer that DID keep the update treats the replay idempotently (no duplicate settlement)', function () {
		const t = makePair('idempotent');
		const preimage = crypto.randomBytes(32);
		const hash = sha256(preimage);
		// Deliver the add but cut before the signature: B keeps the PENDING
		// HTLC in memory across the reconnect (beignet keeps uncommitted
		// updates), so A's replayed update_add must be deduplicated.
		t.wire.cutBefore(MessageType.COMMITMENT_SIGNED);
		t.A().addHtlc(t.channelId, 1_000_000n, hash, 900, Buffer.alloc(1366));
		t.wire.reconnect();
		expect(t.errors, t.errors.join('; ')).to.have.length(0);
		// Exactly ONE HTLC on B despite the replay.
		expect(
			[...t.bChannel().getFullState().htlcs.values()].filter((h) =>
				h.paymentHash.equals(hash)
			)
		).to.have.length(1);
		const bEntry = [...t.bChannel().getFullState().htlcs.values()][0];
		t.B().fulfillHtlc(t.channelId, bEntry.id, preimage);
		expect(t.fulfilled).to.have.length(1);
		expect(t.bChannel().getBalances().localMsat).to.equal(1_000_000n);
	});
});
