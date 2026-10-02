/**
 * BOLT 2 reestablish: a retransmitted commitment_signed follows exactly the
 * updates it covers. Updates queued AFTER that signature was made (while its
 * revoke_and_ack is outstanding) are retransmitted after it, and after any
 * revoke_and_ack retransmitted behind it, so they wait for our NEXT
 * signature on the peer exactly as they did on the original connection
 * (issue #1300).
 *
 * Before the fix handleReestablish replayed the whole pendingLocalUpdates
 * queue ahead of the stored commitment_signed. A peer that missed the
 * signature then held updates the signature never covered, and failed the
 * channel with "Invalid commitment signature".
 *
 * Variants:
 *  (a) add, commitment_signed, add: all lost;
 *  (b) the peer received the first add but not the signature or the second;
 *  (c) the peer received the add and the signature, its revoke_and_ack was
 *      lost, the second add was lost (no signature retransmission: pinned);
 *  (d) the update queued after the signature is a fulfil or a fail;
 *  (e) update_fee beside the signature, on either side of it;
 *  (f) crossing traffic, including both orders of our own revoke_and_ack
 *      relative to the signature;
 *  (g) the same across a restart (serialize / deserialize) of either side;
 *  (h) the receiver accepts the correct order from a conformant peer,
 *      whatever order this implementation's sender produced;
 *  the same boundary for a start_batch commitment batch while a splice
 *  awaits its lock, for option_taproot, and for an FFOR drain held back
 *  under section 7.5.5 (the held set keeps its order);
 *  plus the cases with NO signature to retransmit, which must stay as they
 *  were: every queued update goes out ahead of a fresh signature.
 *
 * The boundary is pendingLocalUpdatesSignedCount, which signCommitment has
 * always written and the channel row has always carried beside the queue.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import { Channel } from '../../src/lightning/channel/channel';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	isTaprootChannel
} from '../../src/lightning/channel/types';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { MessageType } from '../../src/lightning/message/types';
import { FforState, IFforEpochRecord } from '../../src/lightning/ffor/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	serializeChannelState,
	deserializeChannelState
} from '../../src/lightning/storage/serialization';

const sha256 = (b: Buffer): Buffer =>
	crypto.createHash('sha256').update(b).digest();

function makeConfig(name: string, taproot = false): IChannelManagerConfig {
	const seed = sha256(Buffer.from(`reest-order-${name}`));
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
		preferAnchors: true,
		...(taproot ? { preferTaproot: true } : {})
	};
}

const FUNDING_SATOSHIS = 1_000_000n;
const CAPACITY_MSAT = FUNDING_SATOSHIS * 1000n;
/** What the setup payment moves to B so B can offer HTLCs of its own. */
const B_FLOAT_MSAT = 300_000_000n;

type Side = 'A' | 'B';
interface IQueued {
	from: string;
	to: string;
	type: number;
	p: Buffer;
}

/**
 * Loopback wire. Beyond the one-shot cut of the retransmission tests it can
 * lose ONE direction (a dying connection still delivers what the other side
 * already put on it), records what each side retransmits on reconnect, and
 * lets a test reorder that retransmission to stand in for another
 * implementation's sender.
 */
interface IWire {
	/** From the next message of `type` sent by `fromB ? B : A`, drop it and
	 *  everything after, in both directions. */
	cutBefore: (type: MessageType, fromB?: boolean) => void;
	/** Drop everything from here on, in both directions. */
	cut: () => void;
	/** Drop everything this side sends from here on; the other direction
	 *  keeps delivering until the wire is cut. */
	dropFrom: (side: Side) => void;
	/** Drop every message the filter matches, until the next reconnect. */
	dropWhen: (filter: ((from: Side, type: number) => boolean) | null) => void;
	reconnect: (opts?: {
		reorder?: (side: Side, types: IQueued[]) => IQueued[];
		/** The new connection dies after delivering this many messages. */
		deliverOnly?: number;
	}) => void;
	restartA: () => void;
	restartB: () => void;
	/** What each side queued in answer to the peer's channel_reestablish. */
	replay: Record<Side, string[]>;
	/** Every message delivered since the last reconnect, in order. */
	delivered: string[];
}

interface IPair {
	A: () => ChannelManager;
	B: () => ChannelManager;
	channelId: Buffer;
	aChannel: () => Channel;
	bChannel: () => Channel;
	errors: string[];
	fulfilled: Record<Side, Buffer[]>;
	failed: Record<Side, bigint[]>;
	wire: IWire;
}

function makePair(tag: string, taproot = false): IPair {
	const aConfig = makeConfig(`${tag}-A`, taproot);
	const bConfig = makeConfig(`${tag}-B`, taproot);
	const aPub = getPublicKey(aConfig.nodePrivateKey!).toString('hex');
	const bPub = getPublicKey(bConfig.nodePrivateKey!).toString('hex');
	const managers = new Map<string, ChannelManager>();
	managers.set(aPub, new ChannelManager(aConfig));
	managers.set(bPub, new ChannelManager(bConfig));
	const errors: string[] = [];
	const fulfilled: Record<Side, Buffer[]> = { A: [], B: [] };
	const failed: Record<Side, bigint[]> = { A: [], B: [] };
	const replay: Record<Side, string[]> = { A: [], B: [] };
	const delivered: string[] = [];
	const sideOf = (pub: string): Side => (pub === aPub ? 'A' : 'B');

	let alive = true;
	let cutType: MessageType | null = null;
	let cutFromB = false;
	let dropped: Side | null = null;
	let deliverBudget: number | null = null;
	let dropFilter: ((from: Side, type: number) => boolean) | null = null;
	let paused = false;
	let pumping = false;
	let queue: IQueued[] = [];

	const dispatch = (m: IQueued): void => {
		if (!alive) return;
		if (dropped === sideOf(m.from)) return;
		if (dropFilter && dropFilter(sideOf(m.from), m.type)) return;
		if (
			cutType !== null &&
			m.type === cutType &&
			(m.from === bPub) === cutFromB
		) {
			alive = false; // the connection died before this message arrived
			cutType = null;
			return;
		}
		if (deliverBudget !== null) {
			if (deliverBudget === 0) {
				alive = false;
				deliverBudget = null;
				return;
			}
			deliverBudget--;
		}
		delivered.push(`${sideOf(m.from)}:${MessageType[m.type]}`);
		managers.get(m.to)!.handleMessage(m.from, m.type, m.p);
	};
	// One FIFO for the connection: a message sent while another is being
	// handled is delivered after everything already on the wire, as on a real
	// connection. Delivering it at once would let a signature made in answer
	// to the peer's revoke_and_ack overtake the updates retransmitted ahead of
	// it.
	const pump = (): void => {
		if (paused || pumping) return;
		pumping = true;
		try {
			while (queue.length > 0) dispatch(queue.shift()!);
		} finally {
			pumping = false;
		}
	};
	const attach = (pub: string, peer: string): void => {
		const m = managers.get(pub)!;
		const side = sideOf(pub);
		m.on('error', (_id, msg: string) => errors.push(`${side}: ${msg}`));
		m.on('htlc:fulfilled', (_c, _id, preimage: Buffer) =>
			fulfilled[side].push(preimage)
		);
		m.on('htlc:failed', (_c, id: bigint) => failed[side].push(id));
		m.on('message:outbound', (to: string, type: number, p: Buffer) => {
			if (managers.get(pub) !== m) return; // stale (restarted) manager
			if (to !== peer) return;
			queue.push({ from: pub, to, type, p });
			pump();
		});
	};
	attach(aPub, bPub);
	attach(bPub, aPub);

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

	const restart = (pub: string, peer: string): void => {
		alive = false;
		const config = pub === aPub ? aConfig : bConfig;
		const state = deserializeChannelState(
			JSON.parse(
				JSON.stringify(serializeChannelState(chan(pub, peer).getFullState()))
			)
		);
		const fresh = new ChannelManager(config);
		fresh.restoreChannel(new Channel(state), peer);
		managers.set(pub, fresh);
		attach(pub, peer);
		managers.get(peer)!.handlePeerDisconnected(pub);
	};

	const wire: IWire = {
		cutBefore: (type: MessageType, fromB = false): void => {
			cutType = type;
			cutFromB = fromB;
		},
		cut: (): void => {
			alive = false;
		},
		dropFrom: (side: Side): void => {
			dropped = side;
		},
		dropWhen: (filter): void => {
			dropFilter = filter;
		},
		replay,
		delivered,
		reconnect: (opts): void => {
			// Both sides observe the disconnect, then exchange reestablish with
			// real-connection FIFO (responses queue behind both reestablishes).
			const a = managers.get(aPub)!;
			const b = managers.get(bPub)!;
			const aC = chan(aPub, bPub);
			const bC = chan(bPub, aPub);
			if (aC.getState() !== ChannelState.AWAITING_REESTABLISH) {
				a.handlePeerDisconnected(bPub);
			}
			if (bC.getState() !== ChannelState.AWAITING_REESTABLISH) {
				b.handlePeerDisconnected(aPub);
			}
			alive = true;
			cutType = null;
			dropped = null;
			dropFilter = null;
			deliverBudget = opts?.deliverOnly ?? null;
			delivered.length = 0;
			paused = true;
			const aRe = reestPayload(aC);
			const bRe = reestPayload(bC);
			b.handleMessage(aPub, MessageType.CHANNEL_REESTABLISH, aRe);
			a.handleMessage(bPub, MessageType.CHANNEL_REESTABLISH, bRe);
			paused = false;
			replay.A = queue
				.filter((m) => m.from === aPub)
				.map((m) => MessageType[m.type]);
			replay.B = queue
				.filter((m) => m.from === bPub)
				.map((m) => MessageType[m.type]);
			if (opts?.reorder) {
				const fromB = opts.reorder(
					'B',
					queue.filter((m) => m.from === bPub)
				);
				const fromA = opts.reorder(
					'A',
					queue.filter((m) => m.from === aPub)
				);
				queue = [...fromB, ...fromA];
			}
			pump();
		},
		restartA: (): void => restart(aPub, bPub),
		restartB: (): void => restart(bPub, aPub)
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
		wire
	};
}

const ONION = Buffer.alloc(1366);
const ADD = 'UPDATE_ADD_HTLC';
const FULFILL = 'UPDATE_FULFILL_HTLC';
const FAIL = 'UPDATE_FAIL_HTLC';
const FEE = 'UPDATE_FEE';
const SIG = 'COMMITMENT_SIGNED';
const RAA = 'REVOKE_AND_ACK';

interface IPayment {
	preimage: Buffer;
	hash: Buffer;
	amountMsat: bigint;
}

function offer(t: IPair, from: Side, amountMsat: bigint): IPayment {
	const preimage = crypto.randomBytes(32);
	const hash = sha256(preimage);
	const manager = from === 'A' ? t.A() : t.B();
	manager.addHtlc(t.channelId, amountMsat, hash, 900, ONION);
	return { preimage, hash, amountMsat };
}

/** The id the RECEIVING side holds the payment under. */
function receivedId(t: IPair, receiver: Side, p: IPayment): bigint {
	const channel = receiver === 'A' ? t.aChannel() : t.bChannel();
	const entry = [...channel.getFullState().htlcs.entries()].find(
		([key, h]) => key.startsWith('received-') && h.paymentHash.equals(p.hash)
	);
	expect(entry, `${receiver} holds the HTLC`).to.not.equal(undefined);
	return entry![1].id;
}

function settle(t: IPair, receiver: Side, p: IPayment): void {
	const manager = receiver === 'A' ? t.A() : t.B();
	manager.fulfillHtlc(t.channelId, receivedId(t, receiver, p), p.preimage);
}

/** A funded pair where B holds a balance, so both sides can offer. */
function makeFundedPair(tag: string, taproot = false): IPair {
	const t = makePair(tag, taproot);
	const float = offer(t, 'A', B_FLOAT_MSAT);
	settle(t, 'B', float);
	expect(t.errors, t.errors.join('; ')).to.have.length(0);
	expect(t.bChannel().getBalances().localMsat).to.equal(B_FLOAT_MSAT);
	t.fulfilled.A.length = 0;
	return t;
}

/**
 * A parseable wallet UTXO (plus change script) funding a splice-in, as the
 * splice tests build it: the tx_complete audit wants real inputs.
 */
function makeSpliceInWallet(amountSats: bigint): {
	walletInput: {
		prevTx: Buffer;
		prevOutputIndex: number;
		value: bigint;
		sequence: number;
		signWitness: (
			tx: bitcoin.Transaction,
			inputIndex: number,
			value: bigint
		) => Buffer[];
	};
	changeScript: Buffer;
} {
	bitcoin.initEccLib(ecc);
	const walletPriv = sha256(Buffer.from('reest-order-splice-wallet'));
	const walletPub = Buffer.from(ecc.pointFromScalar(walletPriv, true)!);
	const walletScript = bitcoin.payments.p2wpkh({ pubkey: walletPub }).output!;
	const scriptCode = bitcoin.payments.p2pkh({ pubkey: walletPub }).output!;
	const value = amountSats + 100_000n;
	const prevTx = new bitcoin.Transaction();
	prevTx.version = 2;
	prevTx.addInput(crypto.randomBytes(32), 0);
	prevTx.addOutput(walletScript, Number(value));
	return {
		walletInput: {
			prevTx: prevTx.toBuffer(),
			prevOutputIndex: 0,
			value,
			sequence: 0xfffffffd,
			signWitness: (
				tx: bitcoin.Transaction,
				inputIndex: number,
				inputValue: bigint
			): Buffer[] => {
				const sighash = tx.hashForWitnessV0(
					inputIndex,
					scriptCode,
					Number(inputValue),
					bitcoin.Transaction.SIGHASH_ALL
				);
				const sig64 = Buffer.from(ecc.sign(sighash, walletPriv));
				const der = bitcoin.script.signature.encode(
					sig64,
					bitcoin.Transaction.SIGHASH_ALL
				);
				return [der, walletPub];
			}
		},
		changeScript: walletScript
	};
}

/**
 * A funded pair driven to the pending-lock window of a splice-in: fully
 * signed, splice_locked never sent, so every commitment round is a
 * start_batch batch of two commitment_signed.
 */
function makePendingLockPair(tag: string): IPair {
	const t = makeFundedPair(tag);
	t.A().initiateQuiescence(t.channelId);
	const wallet = makeSpliceInWallet(100_000n);
	t.aChannel().setSpliceInInputs([wallet.walletInput], wallet.changeScript);
	expect(t.A().initiateSplice(t.channelId, 100_000n, 253).ok).to.equal(true);
	expect(t.errors, t.errors.join('; ')).to.have.length(0);
	expect(t.aChannel().isSplicePendingLock()).to.equal(true);
	expect(t.bChannel().isSplicePendingLock()).to.equal(true);
	return t;
}

function queueOf(c: Channel): { types: string[]; signed: number } {
	const s = c.getFullState();
	return {
		types: s.pendingLocalUpdates.map((u) => MessageType[u.type]),
		signed: s.pendingLocalUpdatesSignedCount
	};
}

/**
 * Both sides alive and level: nothing queued, nothing owed, no signature in
 * flight, and each side's count of the other's commitments agrees.
 */
function expectLevel(t: IPair): void {
	expect(t.errors, t.errors.join('; ')).to.have.length(0);
	const a = t.aChannel();
	const b = t.bChannel();
	expect(a.getState(), 'A state').to.equal(ChannelState.NORMAL);
	expect(b.getState(), 'B state').to.equal(ChannelState.NORMAL);
	for (const [name, c] of [
		['A', a],
		['B', b]
	] as Array<[string, Channel]>) {
		expect(queueOf(c).types, `${name} queue`).to.deep.equal([]);
		expect(queueOf(c).signed, `${name} signed count`).to.equal(0);
		expect(c.needsCommitment(), `${name} owes a signature`).to.equal(false);
		expect(
			c.isAwaitingRemoteRevocation(),
			`${name} awaits a revocation`
		).to.equal(false);
	}
	const as = a.getFullState();
	const bs = b.getFullState();
	expect(as.remoteCommitmentNumber, 'A signed == B revoked up to').to.equal(
		bs.localCommitmentNumber
	);
	expect(bs.remoteCommitmentNumber, 'B signed == A revoked up to').to.equal(
		as.localCommitmentNumber
	);
	expect(a.getBalances().localMsat).to.equal(b.getBalances().remoteMsat);
	expect(b.getBalances().localMsat).to.equal(a.getBalances().remoteMsat);
}

/** One more full payment in each direction: the channel still works. */
function expectStillUsable(t: IPair): void {
	const aBefore = t.aChannel().getBalances().localMsat;
	const bBefore = t.bChannel().getBalances().localMsat;
	const ab = offer(t, 'A', 3_000_000n);
	settle(t, 'B', ab);
	const ba = offer(t, 'B', 2_000_000n);
	settle(t, 'A', ba);
	expectLevel(t);
	expect(t.aChannel().getBalances().localMsat).to.equal(aBefore - 1_000_000n);
	expect(t.bChannel().getBalances().localMsat).to.equal(bBefore + 1_000_000n);
	expect(t.aChannel().getFullState().htlcs.size).to.equal(0);
	expect(t.bChannel().getFullState().htlcs.size).to.equal(0);
}

describe('reestablish: replay order around a retransmitted commitment_signed (issue #1300)', function () {
	// Real signatures on every round; generous under a loaded parallel run.
	this.timeout(60_000);

	describe('(a) add, commitment_signed, add: all lost', function () {
		it('replays the covered add, the signature, then the later add', function () {
			const t = makeFundedPair('a-all-lost');
			t.wire.cut();
			const first = offer(t, 'A', 1_000_000n);
			const second = offer(t, 'A', 2_000_000n);
			expect(queueOf(t.aChannel())).to.deep.equal({
				types: [ADD, ADD],
				signed: 1
			});
			expect(t.aChannel().isAwaitingRemoteRevocation()).to.equal(true);
			expect(t.aChannel().needsCommitment()).to.equal(true);

			t.wire.reconnect();
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(t.wire.replay.A).to.deep.equal([ADD, SIG, ADD]);
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			// The later add was committed by our NEXT signature, sent only
			// after the peer's revoke_and_ack for the retransmitted one.
			const sigs = t.wire.delivered
				.map((m, i) => ({ m, i }))
				.filter((x) => x.m === `A:${SIG}`);
			expect(sigs).to.have.length(2);
			const firstRaa = t.wire.delivered.indexOf(`B:${RAA}`);
			expect(firstRaa).to.be.greaterThan(sigs[0].i);
			expect(sigs[1].i).to.be.greaterThan(firstRaa);
			expectLevel(t);

			settle(t, 'B', first);
			settle(t, 'B', second);
			expectLevel(t);
			expect(t.fulfilled.A).to.have.length(2);
			expect(t.bChannel().getBalances().localMsat).to.equal(
				B_FLOAT_MSAT + 3_000_000n
			);
			expect(t.aChannel().getBalances().localMsat).to.equal(
				CAPACITY_MSAT - B_FLOAT_MSAT - 3_000_000n
			);
			expectStillUsable(t);
		});

		it('several adds after the signature keep their order behind it', function () {
			const t = makeFundedPair('a-three-later');
			t.wire.cut();
			const payments = [
				offer(t, 'A', 1_000_000n),
				offer(t, 'A', 2_000_000n),
				offer(t, 'A', 3_000_000n),
				offer(t, 'A', 4_000_000n)
			];
			expect(queueOf(t.aChannel()).signed).to.equal(1);

			t.wire.reconnect();
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(t.wire.replay.A).to.deep.equal([ADD, SIG, ADD, ADD, ADD]);
			expectLevel(t);
			// Ids arrived in order: B holds 1..4 under consecutive ids.
			const ids = payments.map((p) => receivedId(t, 'B', p));
			expect(ids).to.deep.equal([
				ids[0],
				ids[0] + 1n,
				ids[0] + 2n,
				ids[0] + 3n
			]);
			for (const p of payments) settle(t, 'B', p);
			expectLevel(t);
			expect(t.bChannel().getBalances().localMsat).to.equal(
				B_FLOAT_MSAT + 10_000_000n
			);
			expectStillUsable(t);
		});

		it('two adds under the signature and one after it', function () {
			const t = makeFundedPair('a-two-covered');
			// The manager signs after every add, so the two covered adds are
			// queued on the channel itself and signed for together.
			t.wire.cut();
			const p1 = crypto.randomBytes(32);
			const p2 = crypto.randomBytes(32);
			t.aChannel().addHtlc(1_000_000n, sha256(p1), 900, ONION);
			t.aChannel().addHtlc(2_000_000n, sha256(p2), 900, ONION);
			t.A().autoSignAndSendCommitment(t.channelId);
			const third = offer(t, 'A', 3_000_000n);
			expect(queueOf(t.aChannel())).to.deep.equal({
				types: [ADD, ADD, ADD],
				signed: 2
			});

			t.wire.reconnect();
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(t.wire.replay.A).to.deep.equal([ADD, ADD, SIG, ADD]);
			expectLevel(t);
			settle(t, 'B', {
				preimage: p1,
				hash: sha256(p1),
				amountMsat: 1_000_000n
			});
			settle(t, 'B', {
				preimage: p2,
				hash: sha256(p2),
				amountMsat: 2_000_000n
			});
			settle(t, 'B', third);
			expectLevel(t);
			expect(t.bChannel().getBalances().localMsat).to.equal(
				B_FLOAT_MSAT + 6_000_000n
			);
			expectStillUsable(t);
		});
	});

	describe('(b) the peer received the first add, not the signature or the second add', function () {
		it('replays add, signature, add; the peer ends with both committed', function () {
			const t = makeFundedPair('b-add-kept');
			t.wire.cutBefore(MessageType.COMMITMENT_SIGNED);
			const first = offer(t, 'A', 1_000_000n);
			// B saw the add (uncommitted) and nothing else.
			expect(
				[...t.bChannel().getFullState().htlcs.values()].some((h) =>
					h.paymentHash.equals(first.hash)
				)
			).to.equal(true);
			const second = offer(t, 'A', 2_000_000n);

			t.wire.reconnect();
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(t.wire.replay.A).to.deep.equal([ADD, SIG, ADD]);
			expectLevel(t);
			settle(t, 'B', first);
			settle(t, 'B', second);
			expectLevel(t);
			expect(t.fulfilled.A).to.have.length(2);
			expectStillUsable(t);
		});
	});

	describe('(c) the peer received add and signature; its revoke_and_ack and our second add were lost', function () {
		it('no signature is retransmitted; the later add rides the next signature', function () {
			const t = makeFundedPair('c-raa-lost');
			t.wire.cutBefore(MessageType.REVOKE_AND_ACK, true);
			const first = offer(t, 'A', 1_000_000n);
			const second = offer(t, 'A', 2_000_000n);
			expect(queueOf(t.aChannel())).to.deep.equal({
				types: [ADD, ADD],
				signed: 1
			});

			t.wire.reconnect();
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			// Unchanged behaviour: with no signature to retransmit the whole
			// queue is replayed (the peer ignores the add it committed).
			expect(t.wire.replay.A).to.deep.equal([ADD, ADD]);
			expect(t.wire.replay.B).to.deep.equal([RAA, SIG]);
			expectLevel(t);
			settle(t, 'B', first);
			settle(t, 'B', second);
			expectLevel(t);
			expect(t.fulfilled.A).to.have.length(2);
			expectStillUsable(t);
		});
	});

	describe('(d) a fulfil or fail queued after the signature', function () {
		const twoCommitted = (
			tag: string
		): { t: IPair; h1: IPayment; h2: IPayment } => {
			const t = makeFundedPair(tag);
			const h1 = offer(t, 'A', 4_000_000n);
			const h2 = offer(t, 'A', 5_000_000n);
			expectLevel(t);
			return { t, h1, h2 };
		};

		it('fulfil, signature, fulfil: all lost', function () {
			const { t, h1, h2 } = twoCommitted('d-fulfil-fulfil');
			t.wire.cut();
			settle(t, 'B', h1);
			settle(t, 'B', h2);
			expect(queueOf(t.bChannel())).to.deep.equal({
				types: [FULFILL, FULFILL],
				signed: 1
			});

			t.wire.reconnect();
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(t.wire.replay.B).to.deep.equal([FULFILL, SIG, FULFILL]);
			expectLevel(t);
			expect(t.fulfilled.A).to.have.length(2);
			expect(t.bChannel().getBalances().localMsat).to.equal(
				B_FLOAT_MSAT + 9_000_000n
			);
			expect(t.aChannel().getFullState().htlcs.size).to.equal(0);
			expect(t.bChannel().getFullState().htlcs.size).to.equal(0);
			expectStillUsable(t);
		});

		it('fulfil, signature, fail: all lost', function () {
			const { t, h1, h2 } = twoCommitted('d-fulfil-fail');
			t.wire.cut();
			settle(t, 'B', h1);
			t.B().failHtlc(t.channelId, receivedId(t, 'B', h2), Buffer.from('no'));
			expect(queueOf(t.bChannel())).to.deep.equal({
				types: [FULFILL, FAIL],
				signed: 1
			});

			t.wire.reconnect();
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(t.wire.replay.B).to.deep.equal([FULFILL, SIG, FAIL]);
			expectLevel(t);
			expect(t.fulfilled.A).to.have.length(1);
			expect(t.failed.A).to.have.length(1);
			expect(t.bChannel().getBalances().localMsat).to.equal(
				B_FLOAT_MSAT + 4_000_000n
			);
			expect(t.aChannel().getFullState().htlcs.size).to.equal(0);
			expectStillUsable(t);
		});

		it('fail, signature, fulfil: all lost', function () {
			const { t, h1, h2 } = twoCommitted('d-fail-fulfil');
			t.wire.cut();
			t.B().failHtlc(t.channelId, receivedId(t, 'B', h1), Buffer.from('no'));
			settle(t, 'B', h2);

			t.wire.reconnect();
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(t.wire.replay.B).to.deep.equal([FAIL, SIG, FULFILL]);
			expectLevel(t);
			expect(t.fulfilled.A).to.have.length(1);
			expect(t.failed.A).to.have.length(1);
			expect(t.bChannel().getBalances().localMsat).to.equal(
				B_FLOAT_MSAT + 5_000_000n
			);
			expectStillUsable(t);
		});

		it('add, signature, fulfil: the later update is a removal of another HTLC', function () {
			const { t, h1, h2 } = twoCommitted('d-add-fulfil');
			t.wire.cut();
			const own = offer(t, 'B', 1_000_000n);
			settle(t, 'B', h1);

			t.wire.reconnect();
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(t.wire.replay.B).to.deep.equal([ADD, SIG, FULFILL]);
			expectLevel(t);
			expect(t.fulfilled.A).to.have.length(1);
			settle(t, 'A', own);
			settle(t, 'B', h2);
			expectLevel(t);
			expect(t.bChannel().getBalances().localMsat).to.equal(
				B_FLOAT_MSAT + 9_000_000n - 1_000_000n
			);
			expectStillUsable(t);
		});

		it('the peer received the first fulfil but not the signature', function () {
			const { t, h1, h2 } = twoCommitted('d-fulfil-kept');
			t.wire.cutBefore(MessageType.COMMITMENT_SIGNED, true);
			settle(t, 'B', h1);
			expect(t.fulfilled.A, 'A learned the first preimage').to.have.length(1);
			settle(t, 'B', h2);

			t.wire.reconnect();
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(t.wire.replay.B).to.deep.equal([FULFILL, SIG, FULFILL]);
			expectLevel(t);
			expect(t.bChannel().getBalances().localMsat).to.equal(
				B_FLOAT_MSAT + 9_000_000n
			);
			expectStillUsable(t);
		});
	});

	describe('a signature that covers none of our own updates', function () {
		it('signature (acking the peer add), then our add: the signature goes first', function () {
			const t = makeFundedPair('zero-covered');
			// A offers; B revokes and signs back. B's signature covers no update
			// of B's own, and it is lost; B then offers an HTLC of its own.
			t.wire.cutBefore(MessageType.COMMITMENT_SIGNED, true);
			const inbound = offer(t, 'A', 1_000_000n);
			expect(t.bChannel().isAwaitingRemoteRevocation()).to.equal(true);
			const own = offer(t, 'B', 2_000_000n);
			expect(queueOf(t.bChannel())).to.deep.equal({ types: [ADD], signed: 0 });

			t.wire.reconnect();
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(t.wire.replay.B).to.deep.equal([SIG, ADD]);
			expectLevel(t);
			settle(t, 'B', inbound);
			settle(t, 'A', own);
			expectLevel(t);
			expectStillUsable(t);
		});
	});

	describe('(e) update_fee beside the signature', function () {
		it('update_fee, signature, add: the fee is covered, the add is not', function () {
			const t = makeFundedPair('e-fee-covered');
			t.wire.cut();
			expect(t.A().updateChannelFee(t.channelId, 1000).ok).to.equal(true);
			const later = offer(t, 'A', 1_000_000n);
			expect(queueOf(t.aChannel())).to.deep.equal({
				types: [FEE, ADD],
				signed: 1
			});

			t.wire.reconnect();
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(t.wire.replay.A).to.deep.equal([FEE, SIG, ADD]);
			expectLevel(t);
			expect(t.aChannel().getFullState().localConfig.feeratePerKw).to.equal(
				1000
			);
			expect(t.bChannel().getFullState().remoteConfig.feeratePerKw).to.equal(
				1000
			);
			settle(t, 'B', later);
			expectLevel(t);
			expectStillUsable(t);
		});

		it('add, signature, update_fee: the unsigned fee is rolled back, not replayed', function () {
			const t = makeFundedPair('e-fee-later');
			const rateBefore = t.aChannel().getFullState().localConfig.feeratePerKw;
			t.wire.cut();
			const first = offer(t, 'A', 1_000_000n);
			expect(t.A().updateChannelFee(t.channelId, 1000).ok).to.equal(true);
			expect(queueOf(t.aChannel())).to.deep.equal({
				types: [ADD, FEE],
				signed: 1
			});

			t.wire.reconnect();
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			// markForReestablish drops an update_fee no signature covers; the
			// boundary below it does not move.
			expect(t.wire.replay.A).to.deep.equal([ADD, SIG]);
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(t.aChannel().getState()).to.equal(ChannelState.NORMAL);
			expect(t.bChannel().getState()).to.equal(ChannelState.NORMAL);
			expect(t.aChannel().getFullState().localConfig.feeratePerKw).to.equal(
				rateBefore
			);
			expect(t.bChannel().getFullState().remoteConfig.feeratePerKw).to.equal(
				rateBefore
			);
			settle(t, 'B', first);
			expectLevel(t);
			expectStillUsable(t);
		});

		it('add, signature, update_fee, add: the later add survives the fee rollback behind the signature', function () {
			const t = makeFundedPair('e-fee-between');
			t.wire.cut();
			const first = offer(t, 'A', 1_000_000n);
			expect(t.A().updateChannelFee(t.channelId, 1000).ok).to.equal(true);
			const second = offer(t, 'A', 2_000_000n);
			expect(queueOf(t.aChannel())).to.deep.equal({
				types: [ADD, FEE, ADD],
				signed: 1
			});

			t.wire.reconnect();
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(t.wire.replay.A).to.deep.equal([ADD, SIG, ADD]);
			expectLevel(t);
			settle(t, 'B', first);
			settle(t, 'B', second);
			expectLevel(t);
			expectStillUsable(t);
		});
	});

	describe('(f) crossing traffic', function () {
		it('both sides lost add, signature, add', function () {
			const t = makeFundedPair('f-both');
			t.wire.cut();
			const a1 = offer(t, 'A', 1_000_000n);
			const a2 = offer(t, 'A', 2_000_000n);
			const b1 = offer(t, 'B', 3_000_000n);
			const b2 = offer(t, 'B', 4_000_000n);

			t.wire.reconnect();
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(t.wire.replay.A).to.deep.equal([ADD, SIG, ADD]);
			expect(t.wire.replay.B).to.deep.equal([ADD, SIG, ADD]);
			expectLevel(t);
			settle(t, 'B', a1);
			settle(t, 'B', a2);
			settle(t, 'A', b1);
			settle(t, 'A', b2);
			expectLevel(t);
			expect(t.bChannel().getBalances().localMsat).to.equal(
				B_FLOAT_MSAT + 3_000_000n - 7_000_000n
			);
			expectStillUsable(t);
		});

		it('our revoke_and_ack was sent last: add, signature, revoke_and_ack, then the later add', function () {
			const t = makeFundedPair('f-revoke-last');
			// A's side of the connection is already dead; B's still delivers.
			t.wire.dropFrom('A');
			const a1 = offer(t, 'A', 1_000_000n); // add + signature, lost
			const b1 = offer(t, 'B', 3_000_000n); // add + signature reach A
			// A revoked for B's signature (lost) and cannot sign yet.
			expect(t.aChannel().getFullState().lastSentWasRevoke).to.equal(true);
			const a2 = offer(t, 'A', 2_000_000n); // queued behind the signature
			t.wire.cut();
			expect(queueOf(t.aChannel())).to.deep.equal({
				types: [ADD, ADD],
				signed: 1
			});

			t.wire.reconnect();
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(t.wire.replay.A).to.deep.equal([ADD, SIG, RAA, ADD]);
			expectLevel(t);
			settle(t, 'B', a1);
			settle(t, 'B', a2);
			settle(t, 'A', b1);
			expectLevel(t);
			expectStillUsable(t);
		});

		it('our revoke_and_ack was sent first: revoke_and_ack, signature, then the later add', function () {
			const t = makeFundedPair('f-revoke-first');
			t.wire.dropFrom('A');
			// B's add and signature reach A; A's revoke_and_ack and the
			// signature it owes in answer are both lost.
			const b1 = offer(t, 'B', 3_000_000n);
			expect(t.aChannel().getFullState().lastSentWasRevoke).to.equal(false);
			expect(t.aChannel().isAwaitingRemoteRevocation()).to.equal(true);
			const a1 = offer(t, 'A', 1_000_000n); // queued behind the signature
			t.wire.cut();
			expect(queueOf(t.aChannel())).to.deep.equal({ types: [ADD], signed: 0 });

			t.wire.reconnect();
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(t.wire.replay.A).to.deep.equal([RAA, SIG, ADD]);
			expectLevel(t);
			settle(t, 'B', a1);
			settle(t, 'A', b1);
			expectLevel(t);
			expectStillUsable(t);
		});

		it('a fulfil on one side crosses add, signature, add on the other', function () {
			const t = makeFundedPair('f-fulfil-cross');
			const h1 = offer(t, 'A', 4_000_000n);
			const h2 = offer(t, 'A', 5_000_000n);
			expectLevel(t);
			t.wire.cut();
			const a1 = offer(t, 'A', 1_000_000n);
			const a2 = offer(t, 'A', 2_000_000n);
			settle(t, 'B', h1);
			settle(t, 'B', h2);

			t.wire.reconnect();
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(t.wire.replay.A).to.deep.equal([ADD, SIG, ADD]);
			expect(t.wire.replay.B).to.deep.equal([FULFILL, SIG, FULFILL]);
			expectLevel(t);
			expect(t.fulfilled.A).to.have.length(2);
			settle(t, 'B', a1);
			settle(t, 'B', a2);
			expectLevel(t);
			expect(t.bChannel().getBalances().localMsat).to.equal(
				B_FLOAT_MSAT + 12_000_000n
			);
			expectStillUsable(t);
		});
	});

	describe('(g) across a restart', function () {
		it('the sender restarts: the boundary survives serialization', function () {
			const t = makeFundedPair('g-restart-sender');
			t.wire.cut();
			const first = offer(t, 'A', 1_000_000n);
			const second = offer(t, 'A', 2_000_000n);
			t.wire.restartA();
			expect(queueOf(t.aChannel())).to.deep.equal({
				types: [ADD, ADD],
				signed: 1
			});

			t.wire.reconnect();
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(t.wire.replay.A).to.deep.equal([ADD, SIG, ADD]);
			expectLevel(t);
			settle(t, 'B', first);
			settle(t, 'B', second);
			expectLevel(t);
			expect(t.fulfilled.A).to.have.length(2);
			expectStillUsable(t);
		});

		it('the receiver restarts', function () {
			const t = makeFundedPair('g-restart-receiver');
			t.wire.cutBefore(MessageType.COMMITMENT_SIGNED);
			const first = offer(t, 'A', 1_000_000n);
			const second = offer(t, 'A', 2_000_000n);
			t.wire.restartB();

			t.wire.reconnect();
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(t.wire.replay.A).to.deep.equal([ADD, SIG, ADD]);
			expectLevel(t);
			settle(t, 'B', first);
			settle(t, 'B', second);
			expectLevel(t);
			expectStillUsable(t);
		});

		it('both restart, with a fulfil behind the signature', function () {
			const t = makeFundedPair('g-restart-both');
			const h1 = offer(t, 'A', 4_000_000n);
			const h2 = offer(t, 'A', 5_000_000n);
			expectLevel(t);
			t.wire.cut();
			settle(t, 'B', h1);
			settle(t, 'B', h2);
			t.wire.restartB();
			t.wire.restartA();

			t.wire.reconnect();
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(t.wire.replay.B).to.deep.equal([FULFILL, SIG, FULFILL]);
			expectLevel(t);
			expect(t.fulfilled.A).to.have.length(2);
			expect(t.bChannel().getBalances().localMsat).to.equal(
				B_FLOAT_MSAT + 9_000_000n
			);
			expectStillUsable(t);
		});

		it('the sender restarts with its revoke_and_ack sent last', function () {
			const t = makeFundedPair('g-restart-revoke-last');
			t.wire.dropFrom('A');
			const a1 = offer(t, 'A', 1_000_000n);
			const b1 = offer(t, 'B', 3_000_000n);
			const a2 = offer(t, 'A', 2_000_000n);
			t.wire.cut();
			t.wire.restartA();

			t.wire.reconnect();
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(t.wire.replay.A).to.deep.equal([ADD, SIG, RAA, ADD]);
			expectLevel(t);
			settle(t, 'B', a1);
			settle(t, 'B', a2);
			settle(t, 'A', b1);
			expectLevel(t);
			expectStillUsable(t);
		});

		it('the sender restarts with an update_fee under the signature', function () {
			const t = makeFundedPair('g-restart-fee');
			t.wire.cut();
			expect(t.A().updateChannelFee(t.channelId, 1000).ok).to.equal(true);
			const later = offer(t, 'A', 1_000_000n);
			t.wire.restartA();
			expect(queueOf(t.aChannel())).to.deep.equal({
				types: [FEE, ADD],
				signed: 1
			});

			t.wire.reconnect();
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(t.wire.replay.A).to.deep.equal([FEE, SIG, ADD]);
			expectLevel(t);
			expect(t.bChannel().getFullState().remoteConfig.feeratePerKw).to.equal(
				1000
			);
			settle(t, 'B', later);
			expectLevel(t);
			expectStillUsable(t);
		});

		it('a second disconnect before the round completes replays the same order again', function () {
			const t = makeFundedPair('g-twice');
			t.wire.cut();
			const first = offer(t, 'A', 1_000_000n);
			const second = offer(t, 'A', 2_000_000n);
			// The first reconnect dies before anything A retransmits arrives.
			t.wire.reconnect({ deliverOnly: 0 });
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(t.wire.replay.A).to.deep.equal([ADD, SIG, ADD]);
			expect(queueOf(t.aChannel())).to.deep.equal({
				types: [ADD, ADD],
				signed: 1
			});

			t.wire.reconnect();
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(t.wire.replay.A).to.deep.equal([ADD, SIG, ADD]);
			expectLevel(t);
			settle(t, 'B', first);
			settle(t, 'B', second);
			expectLevel(t);
			expectStillUsable(t);
		});

		it('a second disconnect after the signature arrived, before the later add did', function () {
			const t = makeFundedPair('g-twice-partial');
			t.wire.cut();
			const first = offer(t, 'A', 1_000_000n);
			const second = offer(t, 'A', 2_000_000n);
			// The covered add and the signature arrive; the later add and the
			// peer's revoke_and_ack die with the connection.
			t.wire.reconnect({ deliverOnly: 2 });
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(t.wire.delivered).to.deep.equal([`A:${ADD}`, `A:${SIG}`]);
			expect(queueOf(t.aChannel())).to.deep.equal({
				types: [ADD, ADD],
				signed: 1
			});

			// The peer holds the signature now: none is retransmitted, and its
			// revoke_and_ack releases our next signature for the later add.
			t.wire.reconnect();
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(t.wire.replay.A).to.deep.equal([ADD, ADD]);
			expect(t.wire.replay.B).to.deep.equal([RAA, SIG]);
			expectLevel(t);
			settle(t, 'B', first);
			settle(t, 'B', second);
			expectLevel(t);
			expectStillUsable(t);
		});
	});

	describe('(h) receiving the correct order from a conformant peer', function () {
		// The retransmission is rearranged ON THE WIRE into the BOLT 2 order
		// (covered updates, commitment_signed, later updates), so these hold
		// whatever order the sending side of this implementation produced.
		const conformant = (side: Side, covered: number) => {
			return (from: Side, msgs: IQueued[]): IQueued[] => {
				if (from !== side) return msgs;
				const updates = msgs.filter(
					(m) =>
						m.type === MessageType.UPDATE_ADD_HTLC ||
						m.type === MessageType.UPDATE_FULFILL_HTLC ||
						m.type === MessageType.UPDATE_FAIL_HTLC
				);
				const sig = msgs.filter(
					(m) => m.type === MessageType.COMMITMENT_SIGNED
				);
				const rest = msgs.filter(
					(m) => !updates.includes(m) && !sig.includes(m)
				);
				return [
					...rest,
					...updates.slice(0, covered),
					...sig,
					...updates.slice(covered)
				];
			};
		};

		it('add, commitment_signed, add', function () {
			const t = makeFundedPair('h-adds');
			t.wire.cut();
			const first = offer(t, 'A', 1_000_000n);
			const second = offer(t, 'A', 2_000_000n);

			t.wire.reconnect({ reorder: conformant('A', 1) });
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(t.wire.delivered.slice(0, 3)).to.deep.equal([
				`A:${ADD}`,
				`A:${SIG}`,
				`A:${ADD}`
			]);
			expectLevel(t);
			settle(t, 'B', first);
			settle(t, 'B', second);
			expectLevel(t);
			expectStillUsable(t);
		});

		it('fulfil, commitment_signed, fail', function () {
			const t = makeFundedPair('h-removals');
			const h1 = offer(t, 'A', 4_000_000n);
			const h2 = offer(t, 'A', 5_000_000n);
			t.wire.cut();
			settle(t, 'B', h1);
			t.B().failHtlc(t.channelId, receivedId(t, 'B', h2), Buffer.from('no'));

			t.wire.reconnect({ reorder: conformant('B', 1) });
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(t.wire.delivered.slice(0, 3)).to.deep.equal([
				`B:${FULFILL}`,
				`B:${SIG}`,
				`B:${FAIL}`
			]);
			expectLevel(t);
			expect(t.fulfilled.A).to.have.length(1);
			expect(t.failed.A).to.have.length(1);
			expectStillUsable(t);
		});

		it('commitment_signed then add, when the signature covers none of the peer updates', function () {
			const t = makeFundedPair('h-zero');
			t.wire.cutBefore(MessageType.COMMITMENT_SIGNED, true);
			const inbound = offer(t, 'A', 1_000_000n);
			const own = offer(t, 'B', 2_000_000n);

			t.wire.reconnect({ reorder: conformant('B', 0) });
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(t.wire.delivered.slice(0, 2)).to.deep.equal([
				`B:${SIG}`,
				`B:${ADD}`
			]);
			expectLevel(t);
			settle(t, 'B', inbound);
			settle(t, 'A', own);
			expectLevel(t);
			expectStillUsable(t);
		});
	});

	describe('a commitment batch while a splice awaits its lock', function () {
		const BATCH = 'START_BATCH';
		// The splice resumption retransmits tx_signatures beside the
		// commitment traffic; it is not part of the order under test.
		const commitmentTraffic = (replay: string[]): string[] =>
			replay.filter((m) => m !== 'TX_SIGNATURES');
		const lockAndCheck = (t: IPair): void => {
			t.A().sendSpliceLocked(t.channelId);
			t.B().sendSpliceLocked(t.channelId);
			expectLevel(t);
			expectStillUsable(t);
		};

		it('add, batch, add: the later add follows the retransmitted batch', function () {
			const t = makePendingLockPair('batch-cached');
			t.wire.cut();
			const first = offer(t, 'A', 1_000_000n);
			const second = offer(t, 'A', 2_000_000n);
			expect(queueOf(t.aChannel())).to.deep.equal({
				types: [ADD, ADD],
				signed: 1
			});

			t.wire.reconnect();
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(commitmentTraffic(t.wire.replay.A)).to.deep.equal([
				ADD,
				BATCH,
				SIG,
				SIG,
				ADD
			]);
			expect(t.aChannel().isSplicePendingLock()).to.equal(true);
			expect(t.bChannel().isSplicePendingLock()).to.equal(true);
			settle(t, 'B', first);
			settle(t, 'B', second);
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(t.fulfilled.A).to.have.length(2);
			lockAndCheck(t);
		});

		it('no batch to retransmit: the whole queue goes out, as before', function () {
			const t = makePendingLockPair('batch-none');
			// The batch arrives; the peer's revoke_and_ack and our later add
			// are lost.
			t.wire.cutBefore(MessageType.REVOKE_AND_ACK, true);
			const first = offer(t, 'A', 1_000_000n);
			const second = offer(t, 'A', 2_000_000n);

			t.wire.reconnect();
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(commitmentTraffic(t.wire.replay.A)).to.deep.equal([ADD, ADD]);
			settle(t, 'B', first);
			settle(t, 'B', second);
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(t.fulfilled.A).to.have.length(2);
			lockAndCheck(t);
		});
	});

	describe('option_taproot (the signature is a cached partial_signature_with_nonce)', function () {
		// MuSig2 on every round.
		this.timeout(120_000);

		const taprootPair = (tag: string): IPair => {
			const t = makeFundedPair(tag, true);
			expect(
				isTaprootChannel(t.aChannel().getFullState().channelType)
			).to.equal(true);
			return t;
		};

		it('add, signature, add: all lost', function () {
			const t = taprootPair('taproot-adds');
			t.wire.cut();
			const first = offer(t, 'A', 1_000_000n);
			const second = offer(t, 'A', 2_000_000n);

			t.wire.reconnect();
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(t.wire.replay.A).to.deep.equal([ADD, SIG, ADD]);
			expectLevel(t);
			settle(t, 'B', first);
			settle(t, 'B', second);
			expectLevel(t);
			expectStillUsable(t);
		});

		it('fulfil, signature, fulfil: all lost, and the sender restarts', function () {
			const t = taprootPair('taproot-fulfils');
			const h1 = offer(t, 'A', 4_000_000n);
			const h2 = offer(t, 'A', 5_000_000n);
			expectLevel(t);
			t.wire.cut();
			settle(t, 'B', h1);
			settle(t, 'B', h2);
			t.wire.restartB();

			t.wire.reconnect();
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(t.wire.replay.B).to.deep.equal([FULFILL, SIG, FULFILL]);
			expectLevel(t);
			expect(t.fulfilled.A).to.have.length(2);
			expectStillUsable(t);
		});

		it('our revoke_and_ack was sent last: add, signature, revoke_and_ack, add', function () {
			const t = taprootPair('taproot-revoke-last');
			t.wire.dropFrom('A');
			const a1 = offer(t, 'A', 1_000_000n);
			const b1 = offer(t, 'B', 3_000_000n);
			const a2 = offer(t, 'A', 2_000_000n);
			t.wire.cut();

			t.wire.reconnect();
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(t.wire.replay.A).to.deep.equal([ADD, SIG, RAA, ADD]);
			expectLevel(t);
			settle(t, 'B', a1);
			settle(t, 'B', a2);
			settle(t, 'A', b1);
			expectLevel(t);
			expectStillUsable(t);
		});
	});

	describe('FFOR drain (section 7.5.5 hold)', function () {
		const TIP = 795_000;
		const AMOUNTS = [994_000n, 546_250n, 49_749_000n];
		const record = (c: Channel): IFforEpochRecord => {
			const f = c.getFforEpoch();
			expect(f, 'epoch record').to.not.equal(null);
			return f!;
		};

		/**
		 * A is S, B is R, epoch ACTIVE, then closed with R's drain cut in two
		 * and none of it delivered: fails for vouchers 1 and 2 under R's
		 * commitment_signed, and a fulfil for voucher 3 queued behind that
		 * signature. An honest drain leaves in one burst, so the second half
		 * is contrived: the first pass is kept off voucher 3, whose preimage R
		 * then learns the way a payer's receipt delivers it.
		 */
		const drainInTwoHalves = (tag: string): IPair => {
			const t = makePair(tag);
			t.A().handleNewBlock(TIP);
			t.B().handleNewBlock(TIP);
			const started = t.B().initiateFforEpoch(t.channelId, {
				voucherAmountsMsat: AMOUNTS,
				minPaymentMsat: 400_000n,
				settlementDeadline: 798_992,
				voucherExpiry: 800_000,
				feeBaseMsat: 1000,
				feeProportionalMillionths: 5000
			});
			expect(started.ok, started.error).to.equal(true);
			expect(record(t.aChannel()).state).to.equal(FforState.ACTIVE);
			expect(record(t.bChannel()).state).to.equal(FforState.ACTIVE);

			const r = t.bChannel();
			const vouchers = [...r.getFullState().htlcs.values()]
				.filter((h) => h.fforVoucher === true)
				.sort((x, y) => Number(x.id - y.id));
			expect(vouchers).to.have.length(AMOUNTS.length);
			const last = vouchers[vouchers.length - 1];
			const failHtlc = r.failHtlc.bind(r);
			let holdBack = true;
			r.failHtlc = ((id: bigint, ...rest: unknown[]) =>
				holdBack && id === last.id
					? [
							{
								type: ChannelActionType.ERROR,
								message: 'held back by the test'
							}
					  ]
					: (failHtlc as (...a: unknown[]) => unknown)(
							id,
							...rest
					  )) as typeof r.failHtlc;

			// R's drain never arrives; ff_close and its ack do.
			t.wire.dropWhen(
				(from, type) =>
					from === 'B' &&
					(type === MessageType.UPDATE_FULFILL_HTLC ||
						type === MessageType.UPDATE_FAIL_HTLC ||
						type === MessageType.COMMITMENT_SIGNED)
			);
			expect(t.B().closeFforEpoch(t.channelId).ok).to.equal(true);
			expect(record(t.aChannel()).state).to.equal(FforState.DRAINING);
			expect(record(r).state).to.equal(FforState.DRAINING);
			expect(queueOf(r)).to.deep.equal({ types: [FAIL, FAIL], signed: 2 });
			expect(r.isAwaitingRemoteRevocation()).to.equal(true);

			holdBack = false;
			const preimage = record(t.aChannel()).preimages[AMOUNTS.length - 1];
			expect(t.B().fforAddPreimage(t.channelId, preimage).ok).to.equal(true);
			expect(queueOf(r)).to.deep.equal({
				types: [FAIL, FAIL, FULFILL],
				signed: 2
			});
			t.wire.cut();
			return t;
		};

		const expectDrained = (t: IPair): void => {
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(record(t.aChannel()).state).to.equal(FforState.CLOSED);
			expect(record(t.bChannel()).state).to.equal(FforState.CLOSED);
			expect(t.aChannel().getFullState().htlcs.size).to.equal(0);
			expect(t.bChannel().getFullState().htlcs.size).to.equal(0);
			expect(t.bChannel().getBalances().localMsat).to.equal(
				AMOUNTS[AMOUNTS.length - 1]
			);
			expectLevel(t);
		};

		it('no hold: fails, signature, then the later fulfil', function () {
			const t = drainInTwoHalves('ffor-no-hold');
			t.wire.reconnect();
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(
				t.wire.replay.B.filter((m) => [FAIL, FULFILL, SIG, RAA].includes(m))
			).to.deep.equal([FAIL, FAIL, SIG, FULFILL]);
			expectDrained(t);
		});

		it('held for an S that does not hold ff_close: the release keeps that order', function () {
			const t = drainInTwoHalves('ffor-hold');
			// S comes back from a backup that predates ff_close.
			const s = record(t.aChannel());
			s.state = FforState.ACTIVE;
			s.closeWire = null;
			s.closeAckWire = null;
			s.settledBitmap = null;
			s.closeProcessed = false;

			t.wire.reconnect();
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			// Nothing of the drain left with the reestablish answer...
			expect(
				t.wire.replay.B.filter((m) => [FAIL, FULFILL, SIG, RAA].includes(m))
			).to.deep.equal([]);
			expect(t.wire.replay.B).to.include('FF_CLOSE');
			// ...and S's ff_close_ack released it in the BOLT 2 order.
			const drain = t.wire.delivered.filter((m) => m.startsWith('B:'));
			const ack = t.wire.delivered.indexOf('A:FF_CLOSE_ACK');
			expect(ack).to.be.greaterThan(-1);
			expect(
				t.wire.delivered.indexOf(`B:${FAIL}`),
				'the drain waited for the ack'
			).to.be.greaterThan(ack);
			expect(drain.filter((m) => m !== 'B:FF_CLOSE').slice(0, 4)).to.deep.equal(
				[`B:${FAIL}`, `B:${FAIL}`, `B:${SIG}`, `B:${FULFILL}`]
			);
			expectDrained(t);
		});
	});

	describe('no signature to retransmit: the whole queue goes out ahead of a fresh signature', function () {
		it('two adds queued and never signed', function () {
			const t = makeFundedPair('none-unsigned');
			t.wire.cut();
			const p1 = crypto.randomBytes(32);
			const p2 = crypto.randomBytes(32);
			// Through the channel: queued and owed, with no signature made.
			t.aChannel().addHtlc(1_000_000n, sha256(p1), 900, ONION);
			t.aChannel().addHtlc(2_000_000n, sha256(p2), 900, ONION);
			expect(queueOf(t.aChannel())).to.deep.equal({
				types: [ADD, ADD],
				signed: 0
			});
			expect(t.aChannel().isAwaitingRemoteRevocation()).to.equal(false);

			t.wire.reconnect();
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			// Both adds, then the fresh signature the reestablish tail makes
			// for them.
			expect(t.wire.replay.A).to.deep.equal([ADD, ADD, SIG]);
			expectLevel(t);
			settle(t, 'B', {
				preimage: p1,
				hash: sha256(p1),
				amountMsat: 1_000_000n
			});
			settle(t, 'B', {
				preimage: p2,
				hash: sha256(p2),
				amountMsat: 2_000_000n
			});
			expectLevel(t);
			expectStillUsable(t);
		});

		it('an add queued after a signature the peer has already revoked', function () {
			const t = makeFundedPair('none-revoked');
			const first = offer(t, 'A', 1_000_000n);
			expectLevel(t);
			t.wire.cut();
			const p2 = crypto.randomBytes(32);
			t.aChannel().addHtlc(2_000_000n, sha256(p2), 900, ONION);
			expect(queueOf(t.aChannel())).to.deep.equal({ types: [ADD], signed: 0 });

			t.wire.reconnect();
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(t.wire.replay.A).to.deep.equal([ADD, SIG]);
			expectLevel(t);
			settle(t, 'B', first);
			settle(t, 'B', {
				preimage: p2,
				hash: sha256(p2),
				amountMsat: 2_000_000n
			});
			expectLevel(t);
			expectStillUsable(t);
		});

		it('a signature that covers the whole queue is retransmitted behind all of it', function () {
			const t = makeFundedPair('none-later');
			t.wire.cut();
			const first = offer(t, 'A', 1_000_000n);
			expect(queueOf(t.aChannel())).to.deep.equal({ types: [ADD], signed: 1 });

			t.wire.reconnect();
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(t.wire.replay.A).to.deep.equal([ADD, SIG]);
			expectLevel(t);
			settle(t, 'B', first);
			expectLevel(t);
			expectStillUsable(t);
		});

		it('a level channel replays nothing', function () {
			const t = makeFundedPair('none-level');
			t.wire.cut();
			t.wire.reconnect();
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(t.wire.replay.A).to.deep.equal([]);
			expect(t.wire.replay.B).to.deep.equal([]);
			expectLevel(t);
			expectStillUsable(t);
		});
	});

	describe('stored rows', function () {
		it('the boundary is a plain optional count: a row without it loads as zero', function () {
			const t = makeFundedPair('row-old');
			const row = JSON.parse(
				JSON.stringify(serializeChannelState(t.aChannel().getFullState()))
			);
			expect(row.pendingLocalUpdatesSignedCount).to.equal(0);
			delete row.pendingLocalUpdatesSignedCount;
			delete row.pendingLocalUpdates;
			const loaded = deserializeChannelState(row);
			expect(loaded.pendingLocalUpdates).to.deep.equal([]);
			expect(loaded.pendingLocalUpdatesSignedCount).to.equal(0);
		});

		it('a state whose count is not a number names no boundary: the whole queue stays ahead of the signature', function () {
			const t = makeFundedPair('row-no-count');
			t.wire.cut();
			offer(t, 'A', 1_000_000n);
			offer(t, 'A', 2_000_000n);
			// No writer produces this (the count is written with the queue);
			// the read is defensive, and falls back to the order used before
			// the boundary was read.
			(
				t.aChannel().getFullState() as unknown as {
					pendingLocalUpdatesSignedCount: unknown;
				}
			).pendingLocalUpdatesSignedCount = undefined;

			t.wire.reconnect({ deliverOnly: 0 });
			expect(t.wire.replay.A).to.deep.equal([ADD, ADD, SIG]);
		});

		it('a row saved mid-round carries the queue and the count', function () {
			const t = makeFundedPair('row-mid');
			t.wire.cut();
			offer(t, 'A', 1_000_000n);
			offer(t, 'A', 2_000_000n);
			const row = JSON.parse(
				JSON.stringify(serializeChannelState(t.aChannel().getFullState()))
			);
			expect(row.pendingLocalUpdatesSignedCount).to.equal(1);
			expect(row.pendingLocalUpdates).to.have.length(2);
			const loaded = deserializeChannelState(row);
			expect(loaded.pendingLocalUpdatesSignedCount).to.equal(1);
			expect(
				loaded.pendingLocalUpdates.map((u) => MessageType[u.type])
			).to.deep.equal([ADD, ADD]);
		});
	});
});
