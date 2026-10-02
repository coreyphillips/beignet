/**
 * Adversarial review, round 2: the received-removal window after its review
 * fixes (PR #1292) and the received-add window stacked on it (PR #1296,
 * issue #1295).
 *
 * Every case drives real messages between two nodes and stops chosen ones, so
 * the states are the ones the wire produces. The oracle is never the builder
 * under test alone: a close counts only when the peer's STORED signature
 * verifies over the planned transaction, and an HTLC claim counts only when
 * the peer's STORED second-level signature verifies over the transaction the
 * resolver built for that output.
 */

import { expect } from 'chai';
import fs from 'fs';
import os from 'os';
import path from 'path';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import { IChannelState } from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	HtlcDirection,
	HtlcState,
	IHtlcEntry,
	isAnchorChannel
} from '../../src/lightning/channel/types';
import {
	buildLocalCommitment,
	deriveCommitmentKeys
} from '../../src/lightning/channel/commitment-builder';
import {
	classifyOutputs,
	resolveOurCommitmentOutputs
} from '../../src/lightning/chain/output-resolver';
import {
	CommitmentType,
	ITrackedOutput,
	OutputType
} from '../../src/lightning/chain/types';
import { createFundingScript } from '../../src/lightning/script/funding';
import { perCommitmentPointFromSecret } from '../../src/lightning/keys/derivation';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import { verify } from '../../src/lightning/crypto/ecdh';
import { MessageType } from '../../src/lightning/message/types';
import { serializeChannelState } from '../../src/lightning/storage/serialization';
import {
	buildGraph,
	createNode,
	makeExternalHash,
	makeSeed,
	openReadyChannel
} from './helpers/loopback-nodes';
import { seedKey } from './helpers/real-signing';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';

const TAG = 'received-window-adversarial-round2';
const DESTINATION = Buffer.from('0014' + '22'.repeat(20), 'hex');

type Side = 'alice' | 'bob';

interface IGate {
	/** Message types from this side that are dropped (and recorded). */
	drop: Record<Side, Set<number>>;
	dropped: Record<Side, Array<{ type: number; payload: Buffer }>>;
	/** While set, every delivery from this side waits here, in order. */
	queue: Record<Side, Array<() => void> | null>;
	seen: Record<Side, number[]>;
}

interface IRig {
	alice: LightningNode;
	bob: LightningNode;
	aliceSeedId: number;
	bobSeedId: number;
	channelId: Buffer;
	gate: IGate;
	destroy: () => void;
}

function rig(
	seedBase: number,
	extra: Partial<INodeConfig> = {},
	fundingSatoshis = 1_000_000n,
	bobStorage?: SqliteStorage
): IRig {
	const alice = createNode(TAG, seedBase, undefined, extra);
	const bob = createNode(TAG, seedBase + 1, bobStorage, extra);
	const gate: IGate = {
		drop: { alice: new Set(), bob: new Set() },
		dropped: { alice: [], bob: [] },
		queue: { alice: null, bob: null },
		seen: { alice: [], bob: [] }
	};
	const route = (from: LightningNode, to: LightningNode, side: Side): void => {
		from.on('message:outbound', (pk: string, t: number, p: Buffer) => {
			if (pk !== to.getNodeId()) return;
			if (gate.drop[side].has(t)) {
				gate.dropped[side].push({ type: t, payload: p });
				return;
			}
			const deliver = (): void => {
				gate.seen[side].push(t);
				to.handlePeerMessage(from.getNodeId(), t, p);
			};
			const q = gate.queue[side];
			if (q) q.push(deliver);
			else deliver();
		});
	};
	route(alice, bob, 'alice');
	route(bob, alice, 'bob');
	const channelId = openReadyChannel(alice, bob, fundingSatoshis);
	buildGraph(alice, bob, [channelId]);
	buildGraph(bob, alice, [channelId]);
	return {
		alice,
		bob,
		aliceSeedId: seedBase,
		bobSeedId: seedBase + 1,
		channelId,
		gate,
		destroy: (): void => {
			alice.destroy();
			bob.destroy();
		}
	};
}

function fullState(node: LightningNode, channelId: Buffer): IChannelState {
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	return (node.getChannelManager().getChannel(channelId) as any).getFullState();
}

function planClose(
	node: LightningNode,
	channelId: Buffer
): { ok: boolean; error?: string; commitmentTx?: Buffer } {
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const manager = node.getChannelManager() as any;
	const channel = manager.getChannel(channelId);
	return channel.prepareForceClose(manager.signerFor(channel, true));
}

/** Whether the stored remote signature covers the given commitment (ECDSA). */
function peerSigned(
	node: LightningNode,
	channelId: Buffer,
	tx: bitcoin.Transaction
): boolean {
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const manager = node.getChannelManager() as any;
	const channel = manager.getChannel(channelId);
	const st = channel.getFullState();
	const funding = createFundingScript(
		st.localBasepoints.fundingPubkey,
		st.remoteBasepoints.fundingPubkey
	);
	return manager
		.signerFor(channel, true)
		.verifyCommitmentSig(
			tx,
			st.remoteCommitmentSignature,
			st.remoteBasepoints.fundingPubkey,
			funding.witnessScript,
			Number(st.fundingSatoshis)
		);
}

function localPoint(st: IChannelState): Buffer {
	return perCommitmentPointFromSecret(
		generateFromSeed(
			st.localPerCommitmentSeed,
			MAX_INDEX - st.localCommitmentNumber
		)
	);
}

function rebuild(st: IChannelState): ReturnType<typeof buildLocalCommitment> {
	return buildLocalCommitment(st, localPoint(st), undefined, true);
}

function htlcOutputs(tracked: ITrackedOutput[]): ITrackedOutput[] {
	return tracked.filter(
		(o) =>
			o.outputType === OutputType.RECEIVED_HTLC ||
			o.outputType === OutputType.OFFERED_HTLC
	);
}

/** Hold invoice on `payee`, paid by `payer`, parked. */
function park(
	payer: LightningNode,
	payee: LightningNode,
	amountMsat: bigint,
	label: string
): { preimage: Buffer; hash: Buffer } {
	const { preimage, hash } = makeExternalHash();
	const invoice = payee.createInvoice({
		amountMsat,
		description: label,
		hold: true,
		paymentHash: hash
	});
	payer.sendPayment(invoice.bolt11);
	return { preimage, hash };
}

/** A settled payment, to move balance to the payee before the test proper. */
function pay(
	payer: LightningNode,
	payee: LightningNode,
	amountMsat: bigint
): void {
	const invoice = payee.createInvoice({
		amountMsat,
		description: 'prefund'
	});
	payer.sendPayment(invoice.bolt11);
}

interface IVerdict {
	tx: bitcoin.Transaction;
	tracked: ITrackedOutput[];
	htlcs: ITrackedOutput[];
}

/**
 * The full unilateral-exit check for `side` at this instant:
 *  - prepareForceClose answers ok,
 *  - the stored peer signature verifies over the planned transaction,
 *  - every stored second-level signature is paired with one tracked HTLC
 *    output, and verifies over the second-level transaction the resolver
 *    builds for that output.
 */
function assertExit(
	r: IRig,
	side: Side,
	preimages: Array<{ preimage: Buffer; hash: Buffer }>,
	label: string
): IVerdict {
	const node = side === 'alice' ? r.alice : r.bob;
	const seedId = side === 'alice' ? r.aliceSeedId : r.bobSeedId;
	const plan = planClose(node, r.channelId);
	expect(plan.ok, `${label}: ${plan.error}`).to.equal(true);
	const tx = bitcoin.Transaction.fromBuffer(plan.commitmentTx!);
	const st = fullState(node, r.channelId);
	expect(
		peerSigned(node, r.channelId, tx),
		`${label}: stored signature covers the planned commitment`
	).to.equal(true);

	const tracked = classifyOutputs(
		tx,
		st,
		CommitmentType.OUR_COMMITMENT,
		st.localCommitmentNumber
	);
	const htlcs = htlcOutputs(tracked);
	expect(
		htlcs.length,
		`${label}: one tracked HTLC output per stored HTLC signature`
	).to.equal(st.remoteHtlcSignatures.length);

	const seed = makeSeed(TAG, seedId);
	const known = new Map(
		preimages.map((p) => [p.hash.toString('hex'), p.preimage])
	);
	// Give every received output a preimage-shaped value so the HTLC-success
	// is built and its stored signature can be checked. Signature validity
	// does not depend on the preimage bytes.
	for (const o of htlcs) {
		const k = o.paymentHash!.toString('hex');
		if (!known.has(k)) known.set(k, Buffer.alloc(32, 7));
	}
	const resolved = resolveOurCommitmentOutputs(
		st,
		tracked,
		st.localCommitmentNumber,
		DESTINATION,
		10,
		known,
		seedKey(seed, 3),
		seedKey(seed, 4),
		st.remoteHtlcSignatures
	);
	const keys = deriveCommitmentKeys(
		st.localBasepoints,
		st.remoteBasepoints!,
		localPoint(st),
		true
	);
	const sighashType = isAnchorChannel(st.channelType)
		? bitcoin.Transaction.SIGHASH_SINGLE |
		  bitcoin.Transaction.SIGHASH_ANYONECANPAY
		: bitcoin.Transaction.SIGHASH_ALL;
	const usedSigs = new Set<number>();
	for (const res of resolved) {
		const o = res.trackedOutput;
		if (
			o.outputType !== OutputType.RECEIVED_HTLC &&
			o.outputType !== OutputType.OFFERED_HTLC
		) {
			continue;
		}
		expect(res.spendTx, `${label}: second-level tx built`).to.not.equal(
			undefined
		);
		expect(
			usedSigs.has(o.htlcSigIndex!),
			`${label}: sig index reused`
		).to.equal(false);
		usedSigs.add(o.htlcSigIndex!);
		const sigHash = res.spendTx!.hashForWitnessV0(
			0,
			o.witnessScript!,
			Number(o.amount),
			sighashType
		);
		expect(
			verify(
				sigHash,
				keys.remoteHtlcPubkey,
				st.remoteHtlcSignatures[o.htlcSigIndex!]
			),
			`${label}: stored HTLC signature ${o.htlcSigIndex} verifies for output ${o.outputIndex} (${o.outputType}, ${o.amount} sat)`
		).to.equal(true);
	}
	return { tx, tracked, htlcs };
}

function stopAliceCommitmentSigned(r: IRig): void {
	r.gate.drop.alice.add(MessageType.COMMITMENT_SIGNED);
}

function stopCommitmentSigned(r: IRig, side: Side): void {
	r.gate.drop[side].add(MessageType.COMMITMENT_SIGNED);
}

function tempDb(prefix: string): string {
	return path.join(
		fs.mkdtempSync(path.join(os.tmpdir(), `beignet-${prefix}-`)),
		'node.db'
	);
}

function monitorHtlcs(
	node: LightningNode,
	channelId: Buffer
): ITrackedOutput[] {
	return htlcOutputs(
		node.getChannelManager().getMonitor(channelId)!.getTrackedOutputs()
	);
}

/** Bob parks one HTLC from Alice and removes it with her signature stopped. */
function simpleWindow(
	seedBase: number,
	removal: 'fulfill' | 'fail',
	extra: Partial<INodeConfig> = {},
	bobStorage?: SqliteStorage
): IRig & {
	h: { preimage: Buffer; hash: Buffer };
	signed: bitcoin.Transaction;
} {
	const r = rig(seedBase, extra, 1_000_000n, bobStorage);
	const h = park(r.alice, r.bob, 50_000_000n, 'window');
	expect(r.bob.listHeldHtlcs()).to.have.length(1);
	const signed = rebuild(fullState(r.bob, r.channelId)).result.tx;
	stopAliceCommitmentSigned(r);
	if (removal === 'fulfill') {
		expect(r.bob.settleHeldHtlc(h.hash, h.preimage)).to.equal(true);
	} else {
		expect(r.bob.cancelHoldInvoice(h.hash)).to.deep.equal({ htlcsFailed: 1 });
	}
	const st = fullState(r.bob, r.channelId);
	expect(st.htlcs.size, 'the entry left the map').to.equal(0);
	expect(st.signedLocalRemovals, 'and is kept').to.have.length(1);
	return { ...r, h, signed };
}

function received(st: IChannelState): IHtlcEntry[] {
	return [...st.htlcs.values()].filter(
		(e) => e.direction === HtlcDirection.RECEIVED
	);
}

/** A snapshot of everything a channel row holds, for purity checks. */
function snapshot(node: LightningNode, channelId: Buffer): string {
	return JSON.stringify(serializeChannelState(fullState(node, channelId)));
}

/** Counts the signature checks one prepareForceClose makes. */
function planCost(
	node: LightningNode,
	channelId: Buffer
): { ok: boolean; error?: string; checks: number; ms: number } {
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const manager = node.getChannelManager() as any;
	const channel = manager.getChannel(channelId);
	const signer = manager.signerFor(channel, true);
	let checks = 0;
	const counting = new Proxy(signer, {
		get(target, prop, receiver): unknown {
			if (prop === 'verifyCommitmentSig') {
				return (...args: unknown[]): unknown => {
					checks++;
					return target.verifyCommitmentSig(...args);
				};
			}
			const value = Reflect.get(target, prop, receiver);
			return typeof value === 'function' ? value.bind(target) : value;
		}
	});
	const started = Date.now();
	const plan = channel.prepareForceClose(counting);
	return { ok: plan.ok, error: plan.error, checks, ms: Date.now() - started };
}

function staleEntry(
	id: bigint,
	state: HtlcState,
	amountMsat: bigint
): IHtlcEntry {
	return {
		id,
		amountMsat,
		paymentHash: crypto.randomBytes(32),
		cltvExpiry: 800_100,
		onionRoutingPacket: Buffer.alloc(0),
		direction: HtlcDirection.RECEIVED,
		state
	};
}

/**
 * Drop and restore the connection. One FIFO for both directions, so both
 * channel_reestablish messages are processed before any reply, as on a real
 * socket pair.
 */
function reconnect(r: IRig): void {
	const am = r.alice.getChannelManager();
	const bm = r.bob.getChannelManager();
	am.handlePeerDisconnected(r.bob.getNodeId());
	bm.handlePeerDisconnected(r.alice.getNodeId());
	const fifo: Array<() => void> = [];
	r.gate.queue.alice = fifo;
	r.gate.queue.bob = fifo;
	am.handlePeerReconnected(r.bob.getNodeId());
	bm.handlePeerReconnected(r.alice.getNodeId());
	while (fifo.length > 0) fifo.shift()!();
	r.gate.queue.alice = null;
	r.gate.queue.bob = null;
}

/** Wire a restored node to its peer and reestablish, FIFO. */
function rewireAndReconnect(
	peer: LightningNode,
	restored: LightningNode
): void {
	const fifo: Array<() => void> = [];
	let hold = true;
	const rewire = (from: LightningNode, to: LightningNode): void => {
		from.on('message:outbound', (pk: string, t: number, p: Buffer) => {
			if (pk !== to.getNodeId()) return;
			const deliver = (): void => to.handlePeerMessage(from.getNodeId(), t, p);
			if (hold) fifo.push(deliver);
			else deliver();
		});
	};
	rewire(peer, restored);
	rewire(restored, peer);
	peer.getChannelManager().handlePeerReconnected(restored.getNodeId());
	restored.getChannelManager().handlePeerReconnected(peer.getNodeId());
	while (fifo.length > 0) fifo.shift()!();
	hold = false;
}

async function settleLoop(rounds = 6): Promise<void> {
	for (let i = 0; i < rounds; i++) {
		await new Promise<void>((resolve) => setImmediate(resolve));
	}
}

describe('Received windows, adversarial round 2', function () {
	this.timeout(60_000);

	describe('the received-add rebuild (PR #1296)', function () {
		it('an unsigned add our own commitment_signed turned COMMITTED is left out, survives a disconnect, and the channel converges on reconnect', function () {
			// signCommitment flips every PENDING entry to COMMITTED, the
			// peer's unsigned add included, and the disconnect rollback only
			// drops PENDING ones. The entry therefore outlives the
			// connection with addLocallyRevoked still false. Everything Alice
			// sends after her add is lost, as a dropped connection loses it.
			const r = rig(3000);
			pay(r.alice, r.bob, 300_000_000n);
			const before = rebuild(fullState(r.bob, r.channelId)).result.tx;
			expect(peerSigned(r.bob, r.channelId, before)).to.equal(true);
			stopAliceCommitmentSigned(r);
			r.gate.drop.alice.add(MessageType.REVOKE_AND_ACK);
			const theirs = park(r.alice, r.bob, 40_000_000n, 'unsigned');
			const mine = park(r.bob, r.alice, 20_000_000n, 'bob-offers');
			let st = fullState(r.bob, r.channelId);
			expect(received(st)[0].state).to.equal(HtlcState.COMMITTED);
			expect(received(st)[0].addLocallyRevoked).to.equal(false);
			let v = assertExit(r, 'bob', [mine], 'COMMITTED, unsigned');
			expect(v.tx.getId()).to.equal(before.getId());

			r.bob.getChannelManager().handlePeerDisconnected(r.alice.getNodeId());
			st = fullState(r.bob, r.channelId);
			expect(received(st), 'not rolled back').to.have.length(1);
			v = assertExit(r, 'bob', [mine], 'after disconnect');
			expect(v.tx.getId()).to.equal(before.getId());

			r.gate.drop.alice.clear();
			reconnect(r);
			st = fullState(r.bob, r.channelId);
			expect(st.state, 'reestablished').to.equal(ChannelState.NORMAL);
			expect(received(st)[0].addLocallyRevoked, 'signed in now').to.not.equal(
				false
			);
			expect(r.bob.listHeldHtlcs(), 'and parked').to.have.length(1);
			v = assertExit(r, 'bob', [mine, theirs], 'after reconnect');
			expect(v.htlcs, 'both HTLCs on the commitment').to.have.length(2);
			expect(r.bob.settleHeldHtlc(theirs.hash, theirs.preimage)).to.equal(true);
			expect(r.alice.settleHeldHtlc(mine.hash, mine.preimage)).to.equal(true);
			expect(fullState(r.bob, r.channelId).htlcs.size).to.equal(0);
			expect(fullState(r.alice, r.channelId).htlcs.size).to.equal(0);
			assertExit(r, 'bob', [], 'idle again');
			assertExit(r, 'alice', [], 'idle again');
			r.destroy();
		});

		it('the same, with the peer revoking for our commitment while still withholding its own: closes connected and disconnected', function () {
			// Only a peer that skips its commitment_signed produces this
			// order (revoke_and_ack delivered, the signature before it not).
			// On master this state refuses the close for good, disconnect
			// or not, since the COMMITTED entry is never rolled back.
			const r = rig(3010);
			pay(r.alice, r.bob, 300_000_000n);
			const before = rebuild(fullState(r.bob, r.channelId)).result.tx;
			stopAliceCommitmentSigned(r);
			park(r.alice, r.bob, 40_000_000n, 'unsigned');
			const mine = park(r.bob, r.alice, 20_000_000n, 'bob-offers');
			const st = fullState(r.bob, r.channelId);
			expect(received(st)[0].state).to.equal(HtlcState.COMMITTED);
			expect(received(st)[0].addLocallyRevoked).to.equal(false);
			let v = assertExit(r, 'bob', [mine], 'connected');
			expect(v.tx.getId()).to.equal(before.getId());
			r.bob.getChannelManager().handlePeerDisconnected(r.alice.getNodeId());
			v = assertExit(r, 'bob', [mine], 'disconnected');
			expect(v.tx.getId()).to.equal(before.getId());
			r.destroy();
		});

		it('the same entry in the row at a restart: closes on the signed commitment, then converges', async function () {
			const dbPath = tempDb('r2-phantom');
			const disk = new SqliteStorage(dbPath);
			disk.open();
			const r = rig(3020, {}, 1_000_000n, disk);
			pay(r.alice, r.bob, 300_000_000n);
			const before = rebuild(fullState(r.bob, r.channelId)).result.tx;
			stopAliceCommitmentSigned(r);
			r.gate.drop.alice.add(MessageType.REVOKE_AND_ACK);
			const theirs = park(r.alice, r.bob, 40_000_000n, 'unsigned');
			const mine = park(r.bob, r.alice, 20_000_000n, 'bob-offers');
			const idHex = r.channelId.toString('hex');
			const row = disk.loadChannel(idHex)!.state;
			expect(
				received(row).map((e) => e.addLocallyRevoked),
				'the unsigned add is in the row'
			).to.deep.equal([false]);

			r.bob.destroy();
			r.alice.getChannelManager().handlePeerDisconnected(r.bob.getNodeId());
			r.alice.removeAllListeners('message:outbound');
			const disk2 = new SqliteStorage(dbPath);
			disk2.open();
			const restored = createNode(TAG, r.bobSeedId, disk2);
			buildGraph(restored, r.alice, [r.channelId]);
			const r2: IRig = { ...r, bob: restored };
			const v = assertExit(r2, 'bob', [mine], 'restored');
			expect(v.tx.getId()).to.equal(before.getId());

			rewireAndReconnect(r.alice, restored);
			await settleLoop();

			const st = fullState(restored, r.channelId);
			expect(st.state).to.equal(ChannelState.NORMAL);
			const after = assertExit(r2, 'bob', [mine, theirs], 'reestablished');
			expect(after.htlcs).to.have.length(2);
			expect(restored.settleHeldHtlc(theirs.hash, theirs.preimage)).to.equal(
				true
			);
			await settleLoop();
			expect(received(fullState(restored, r.channelId))).to.have.length(0);
			restored.destroy();
			r.alice.destroy();
		});

		it('planning is pure: the row is byte-identical after a plan, a second plan is the same transaction, and an abandoned plan does not disturb the signature that then arrives', function () {
			const r = rig(3040);
			const committed = park(r.alice, r.bob, 50_000_000n, 'committed');
			stopAliceCommitmentSigned(r);
			const added = park(r.alice, r.bob, 40_000_000n, 'unsigned');
			expect(r.gate.dropped.alice, 'her covering signature').to.have.length(1);

			const row = snapshot(r.bob, r.channelId);
			const first = planClose(r.bob, r.channelId);
			expect(first.ok, first.error).to.equal(true);
			expect(snapshot(r.bob, r.channelId), 'untouched by the plan').to.equal(
				row
			);
			const second = planClose(r.bob, r.channelId);
			expect(second.commitmentTx!.equals(first.commitmentTx!)).to.equal(true);
			expect(snapshot(r.bob, r.channelId)).to.equal(row);

			// The plan is dropped, and the signature it did not wait for lands.
			r.gate.drop.alice.clear();
			r.bob.handlePeerMessage(
				r.alice.getNodeId(),
				MessageType.COMMITMENT_SIGNED,
				r.gate.dropped.alice[0].payload
			);
			const st = fullState(r.bob, r.channelId);
			expect(st.state).to.equal(ChannelState.NORMAL);
			expect(r.bob.listHeldHtlcs(), 'the add is parked').to.have.length(2);
			const v = assertExit(r, 'bob', [committed, added], 'after the signature');
			expect(v.htlcs).to.have.length(2);
			expect(v.tx.getId()).to.not.equal(
				bitcoin.Transaction.fromBuffer(first.commitmentTx!).getId()
			);
			expect(r.bob.settleHeldHtlc(added.hash, added.preimage)).to.equal(true);
			expect(r.bob.settleHeldHtlc(committed.hash, committed.preimage)).to.equal(
				true
			);
			expect(fullState(r.bob, r.channelId).htlcs.size).to.equal(0);
			r.destroy();
		});

		it('planning is pure on the fallback paths too (subset of the kept list, and the carried reading)', function () {
			const r = rig(3060);
			const a = park(r.alice, r.bob, 50_000_000n, 'a');
			const b = park(r.alice, r.bob, 60_000_000n, 'b');
			stopAliceCommitmentSigned(r);
			expect(r.bob.settleHeldHtlc(a.hash, a.preimage)).to.equal(true);
			const st = fullState(r.bob, r.channelId);
			const signed = rebuild(st).result.tx;
			// A leftover beside the genuine entry, and the live add wrongly
			// read as unsigned: the plan has to go through both fallbacks.
			st.signedLocalRemovals = [
				staleEntry(77n, HtlcState.FAILED, 45_000_000n),
				...st.signedLocalRemovals!
			];
			received(st)[0].addLocallyRevoked = false;
			const row = snapshot(r.bob, r.channelId);
			const plan = planClose(r.bob, r.channelId);
			expect(plan.ok, plan.error).to.equal(true);
			expect(
				bitcoin.Transaction.fromBuffer(plan.commitmentTx!).getId()
			).to.equal(signed.getId());
			expect(snapshot(r.bob, r.channelId), 'untouched').to.equal(row);
			expect(
				st.signedLocalRemovals,
				'the live list is not narrowed by a plan'
			).to.have.length(2);
			expect(received(st)[0].addLocallyRevoked).to.equal(false);
			void b;
			r.destroy();
		});

		it('fourteen unsigned adds on a legacy channel with our own update_fee staged: the signed commitment has none of them (the funder-fee test reading, on the wire)', function () {
			// tests/lightning/funder-fee-inbound-add.test.ts now expects 0 HTLC
			// outputs for 14 received adds with addLocallyRevoked false. Here
			// the same shape is produced by real messages and judged by the
			// real stored signature.
			const r = rig(3080, { preferAnchors: false });
			pay(r.alice, r.bob, 400_000_000n);
			// Bob pays so that ALICE, the opener and fee payer, receives.
			const signed = rebuild(fullState(r.alice, r.channelId)).result.tx;
			expect(peerSigned(r.alice, r.channelId, signed)).to.equal(true);
			stopCommitmentSigned(r, 'bob');
			for (let i = 0; i < 14; i++) {
				park(r.bob, r.alice, 20_000_000n, `stack-${i}`);
			}
			let st = fullState(r.alice, r.channelId);
			expect(
				received(st).filter((e) => e.addLocallyRevoked === false)
			).to.have.length(14);
			let v = assertExit(r, 'alice', [], '14 unsigned adds');
			expect(v.tx.getId()).to.equal(signed.getId());
			expect(v.htlcs).to.have.length(0);

			const rate = st.localConfig.feeratePerKw;
			const res = r.alice.updateChannelFee(r.channelId, rate * 3);
			expect(res.ok, res.error).to.equal(true);
			st = fullState(r.alice, r.channelId);
			v = assertExit(r, 'alice', [], '14 unsigned adds, own fee staged');
			expect(v.tx.getId()).to.equal(signed.getId());
			r.destroy();
		});

		it('adds sent before and after the peer last signed: the first is carried, the second is not', function () {
			const r = rig(3100);
			const first = park(r.alice, r.bob, 50_000_000n, 'before-signature');
			const signed = rebuild(fullState(r.bob, r.channelId)).result.tx;
			stopAliceCommitmentSigned(r);
			park(r.alice, r.bob, 40_000_000n, 'after-signature');
			park(r.alice, r.bob, 200_000n, 'after-signature-dust');
			const v = assertExit(r, 'bob', [first], 'one signed, two not');
			expect(v.tx.getId()).to.equal(signed.getId());
			expect(v.htlcs).to.have.length(1);
			expect(v.htlcs[0].paymentHash!.equals(first.hash)).to.equal(true);
			r.destroy();
		});

		it('the peer (opener) stages update_fee and an add, both unsigned, on a legacy channel', function () {
			const r = rig(3120, { preferAnchors: false });
			const first = park(r.alice, r.bob, 50_000_000n, 'committed');
			const signed = rebuild(fullState(r.bob, r.channelId)).result.tx;
			stopAliceCommitmentSigned(r);
			const rate = fullState(r.bob, r.channelId).remoteConfig.feeratePerKw;
			expect(r.alice.updateChannelFee(r.channelId, rate * 3).ok).to.equal(true);
			park(r.alice, r.bob, 40_000_000n, 'unsigned');
			const st = fullState(r.bob, r.channelId);
			expect(st.pendingFeeratePerKw).to.equal(rate * 3);
			const v = assertExit(r, 'bob', [first], 'fee and add unsigned');
			expect(v.tx.getId()).to.equal(signed.getId());
			r.destroy();
		});

		it('converges after an add failed before its covering signature (the round 1 flag flip): nothing owed for it, the payer retry is a fresh add, next payment settles', function () {
			const r = rig(3140);
			stopAliceCommitmentSigned(r);
			const h = park(r.alice, r.bob, 50_000_000n, 'early-fail');
			const entry = received(fullState(r.bob, r.channelId))[0];
			const covering = r.gate.dropped.alice[0].payload;
			r.gate.drop.alice.clear();

			r.gate.queue.bob = [];
			expect(
				r.bob
					.getChannelManager()
					.failHtlc(r.channelId, entry.id, Buffer.alloc(292)).ok
			).to.equal(true);
			r.bob.handlePeerMessage(
				r.alice.getNodeId(),
				MessageType.COMMITMENT_SIGNED,
				covering
			);
			let st = fullState(r.bob, r.channelId);
			expect(received(st)[0].state).to.equal(HtlcState.FAILED);
			expect(received(st)[0].addLocallyRevoked, 'flipped').to.equal(true);
			expect(st.needsCommitment, 'nothing owed for it').to.not.equal(true);
			expect(r.bob.listHeldHtlcs(), 'not parked or forwarded').to.have.length(
				0
			);
			const held = r.gate.queue.bob!;
			r.gate.queue.bob = null;
			expect(held).to.have.length(3);
			held[2]();
			held[0]();
			held[1]();

			// The round completed. Alice's payment retried over the same
			// channel, so the one entry left is a NEW add, signed in and
			// parked.
			st = fullState(r.bob, r.channelId);
			expect(st.state).to.equal(ChannelState.NORMAL);
			expect(st.signedLocalRemovals, 'the window closed').to.equal(undefined);
			expect(
				received(st).filter((e) => e.id === entry.id),
				'the failed add is gone'
			).to.have.length(0);
			for (const e of received(st)) {
				expect(e.state).to.equal(HtlcState.COMMITTED);
				expect(e.addLocallyRevoked).to.not.equal(false);
			}
			assertExit(r, 'bob', [h], 'bob settled');
			assertExit(r, 'alice', [h], 'alice settled');
			if (r.bob.listHeldHtlcs().length > 0) {
				expect(r.bob.settleHeldHtlc(h.hash, h.preimage)).to.equal(true);
			}
			expect(fullState(r.bob, r.channelId).htlcs.size).to.equal(0);
			expect(fullState(r.alice, r.channelId).htlcs.size).to.equal(0);
			const balance = r.bob.getBalance().localBalanceMsat;
			pay(r.alice, r.bob, 30_000_000n);
			expect(r.bob.getBalance().localBalanceMsat).to.equal(
				balance + 30_000_000n
			);
			assertExit(r, 'bob', [], 'bob after a payment');
			r.destroy();
		});

		it('an add FULFILLED before its covering signature: kept once the signature carries it, and the round converges', function () {
			const r = rig(3160);
			stopAliceCommitmentSigned(r);
			const h = park(r.alice, r.bob, 50_000_000n, 'early-fulfill');
			const entry = received(fullState(r.bob, r.channelId))[0];
			const covering = r.gate.dropped.alice[0].payload;
			const balance = fullState(r.bob, r.channelId).localBalanceMsat;

			r.gate.queue.bob = [];
			const done = r.bob
				.getChannelManager()
				.fulfillHtlc(r.channelId, entry.id, h.preimage);
			expect(done.ok, done.error).to.equal(true);
			r.bob.handlePeerMessage(
				r.alice.getNodeId(),
				MessageType.COMMITMENT_SIGNED,
				covering
			);
			let st = fullState(r.bob, r.channelId);
			const carried = rebuild(st).result;
			expect(carried.outputMap.htlcs).to.have.length(1);
			expect(peerSigned(r.bob, r.channelId, carried.tx)).to.equal(true);
			const held = r.gate.queue.bob!;
			r.gate.queue.bob = null;
			expect(held).to.have.length(3);
			held[2]();
			held[0]();
			held[1]();

			// Alice revoked for the removal; her next signature is stopped.
			st = fullState(r.bob, r.channelId);
			expect(st.htlcs.size).to.equal(0);
			expect(st.signedLocalRemovals, 'kept').to.have.length(1);
			expect(st.localBalanceMsat).to.equal(balance + 50_000_000n);
			const v = assertExit(r, 'bob', [h], 'early fulfill window');
			expect(v.tx.getId()).to.equal(carried.tx.getId());
			expect(v.htlcs).to.have.length(1);

			// And the window closes when she signs.
			r.gate.drop.alice.clear();
			const last = r.gate.dropped.alice[r.gate.dropped.alice.length - 1];
			r.bob.handlePeerMessage(r.alice.getNodeId(), last.type, last.payload);
			st = fullState(r.bob, r.channelId);
			expect(st.signedLocalRemovals).to.equal(undefined);
			assertExit(r, 'bob', [], 'closed');
			assertExit(r, 'alice', [], 'closed');
			r.destroy();
		});

		it('pins the limit of the carried reading: all unsigned-flagged adds are carried together, so one wrongly flagged beside one truly unsigned refuses', function () {
			// No path is known that leaves a signed-in add flagged unsigned
			// since the round 1 flag flip; this is the shape the "all
			// together" fallback cannot answer if one ever does.
			const r = rig(3190);
			const signedIn = park(r.alice, r.bob, 50_000_000n, 'signed-in');
			stopAliceCommitmentSigned(r);
			park(r.alice, r.bob, 40_000_000n, 'unsigned');
			const st = fullState(r.bob, r.channelId);
			const entry = received(st).find((e) => e.addLocallyRevoked !== false)!;
			expect(planClose(r.bob, r.channelId).ok, 'flags right').to.equal(true);
			entry.addLocallyRevoked = false;
			expect(
				planClose(r.bob, r.channelId).ok,
				'one flag wrong beside one right'
			).to.equal(false);
			// A disconnect drops the truly unsigned add; the wrong flag alone
			// is then overruled by the signature.
			r.bob.getChannelManager().handlePeerDisconnected(r.alice.getNodeId());
			const v = assertExit(r, 'bob', [signedIn], 'wrong flag alone');
			expect(v.htlcs).to.have.length(1);
			r.destroy();
		});

		it('pins issue #1299 item 3 (manager API only): an add fulfilled early and revoked for with no covering signature ever arriving refuses the close', function () {
			// An accepted residual, tracked in issue #1299. The node never
			// settles an add before it is irrevocably committed;
			// ChannelManager.fulfillHtlc does not check. The peer
			// revokes for the removal without ever signing the add in. The
			// entry is dropped unkept (rightly: the signature never carried
			// it), but its amount has moved to our balance, and nothing is
			// left to tell the rebuild that the signed commitment predates
			// the credit. A failed add in the same position closes fine (it
			// refunds the peer, which is where the signed commitment has it).
			const r = rig(3180);
			const before = rebuild(fullState(r.bob, r.channelId)).result.tx;
			expect(peerSigned(r.bob, r.channelId, before)).to.equal(true);
			stopAliceCommitmentSigned(r);
			const h = park(r.alice, r.bob, 50_000_000n, 'never-signed');
			const entry = received(fullState(r.bob, r.channelId))[0];
			r.gate.queue.bob = [];
			expect(
				r.bob.getChannelManager().fulfillHtlc(r.channelId, entry.id, h.preimage)
					.ok
			).to.equal(true);
			const held = r.gate.queue.bob!;
			r.gate.queue.bob = null;
			// A lenient peer, made by hand as in round 1.
			const offered = [...fullState(r.alice, r.channelId).htlcs.values()].find(
				(e) => e.direction === HtlcDirection.OFFERED
			)!;
			offered.state = HtlcState.COMMITTED;
			offered.addRemoteCommitted = true;
			for (const deliver of held) deliver();
			const st = fullState(r.bob, r.channelId);
			if (st.htlcs.size !== 0) this.skip();
			expect(st.signedLocalRemovals, 'nothing kept').to.equal(undefined);
			expect(
				peerSigned(r.bob, r.channelId, before),
				'the stored signature is still the one from before the add'
			).to.equal(true);

			const plan = planClose(r.bob, r.channelId);

			expect(plan.ok, 'refused until issue #1299 item 3 is fixed').to.equal(
				false
			);
			r.destroy();
		});

		describe('with a splice pending its lock', function () {
			/** A wallet UTXO funding a splice-in (copied from splice.test.ts). */
			function spliceInWallet(amountSats: bigint): {
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
				const walletPriv = crypto
					.createHash('sha256')
					.update('received-window-round2-wallet')
					.digest();
				const walletPub = Buffer.from(ecc.pointFromScalar(walletPriv, true)!);
				const walletScript = bitcoin.payments.p2wpkh({ pubkey: walletPub })
					.output!;
				const scriptCode = bitcoin.payments.p2pkh({ pubkey: walletPub })
					.output!;
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

			/** Alice splices in 100k sat; both sides stop short of splice_locked. */
			function toPendingLock(r: IRig): void {
				const am = r.alice.getChannelManager();
				// eslint-disable-next-line @typescript-eslint/no-explicit-any
				const ac = am.getChannel(r.channelId) as any;
				am.initiateQuiescence(r.channelId);
				const wallet = spliceInWallet(100_000n);
				ac.setSpliceInInputs([wallet.walletInput], wallet.changeScript);
				const res = am.initiateSplice(r.channelId, 100_000n, 253);
				expect(res.ok, res.error).to.equal(true);
				expect(ac.isSplicePendingLock(), 'Alice pending lock').to.equal(true);
				// eslint-disable-next-line @typescript-eslint/no-explicit-any
				const bc = r.bob.getChannelManager().getChannel(r.channelId) as any;
				expect(bc.isSplicePendingLock(), 'Bob pending lock').to.equal(true);
			}

			it('an unsigned add during pending-lock: exit on the old funding, and on the new one after the lock', function () {
				const r = rig(3200);
				const live = park(r.alice, r.bob, 60_000_000n, 'live');
				toPendingLock(r);
				const before = rebuild(fullState(r.bob, r.channelId)).result.tx;
				expect(peerSigned(r.bob, r.channelId, before)).to.equal(true);
				r.gate.drop.alice.add(MessageType.COMMITMENT_SIGNED);
				r.gate.drop.alice.add(MessageType.START_BATCH);
				park(r.alice, r.bob, 40_000_000n, 'unsigned');
				let st = fullState(r.bob, r.channelId);
				expect(
					received(st).filter((e) => e.addLocallyRevoked === false)
				).to.have.length(1);
				const v = assertExit(r, 'bob', [live], 'pending-lock, old funding');
				expect(v.tx.getId()).to.equal(before.getId());
				expect(v.htlcs).to.have.length(1);

				r.alice.getChannelManager().sendSpliceLocked(r.channelId);
				r.bob.getChannelManager().sendSpliceLocked(r.channelId);
				st = fullState(r.bob, r.channelId);
				expect(st.spliceInFlight ?? null, 'adopted').to.equal(null);
				const after = assertExit(r, 'bob', [live], 'after adoption');
				expect(after.htlcs, 'only the signed HTLC').to.have.length(1);
				expect(
					Buffer.from(after.tx.ins[0].hash).equals(st.fundingTxid!),
					'spends the new funding'
				).to.equal(true);
				r.destroy();
			});
		});
	});

	describe('chain side in the received-add window (PR #1296)', function () {
		it('our close through the monitor: the signed HTLC is claimed, the unsigned add tracks nothing', function () {
			const r = rig(3300);
			const signedIn = park(r.alice, r.bob, 50_000_000n, 'signed-in');
			const signed = rebuild(fullState(r.bob, r.channelId)).result.tx;
			stopAliceCommitmentSigned(r);
			const unsigned = park(r.alice, r.bob, 40_000_000n, 'unsigned');
			const manager = r.bob.getChannelManager();
			// The preimage of both is known to the node from here on.
			manager.recordPreimage(signedIn.hash, signedIn.preimage);
			manager.recordPreimage(unsigned.hash, unsigned.preimage);
			const broadcasts: string[] = [];
			manager.on('broadcast:tx', (tx: Buffer) =>
				broadcasts.push(bitcoin.Transaction.fromBuffer(tx).getId())
			);
			expect(manager.forceClose(r.channelId, DESTINATION).ok).to.equal(true);
			expect(broadcasts).to.include(signed.getId());
			manager.handleFundingSpent(r.channelId, signed, 800_000, DESTINATION);
			const tracked = monitorHtlcs(r.bob, r.channelId);
			expect(tracked, 'one HTLC output, one tracked').to.have.length(1);
			expect(tracked[0].paymentHash!.equals(signedIn.hash)).to.equal(true);
			expect(tracked[0].sweepTxHex, 'HTLC-success built').to.not.equal(
				undefined
			);
			r.destroy();
		});

		it('an unsigned twin of a KEPT removal: the output goes to the kept entry and is claimed', function () {
			const r = rig(3320);
			const { preimage, hash } = makeExternalHash();
			r.alice.sendPayment(
				r.bob.createInvoice({
					amountMsat: 50_000_000n,
					description: 'twin',
					hold: true,
					paymentHash: hash
				}).bolt11
			);
			const signed = rebuild(fullState(r.bob, r.channelId)).result.tx;
			stopAliceCommitmentSigned(r);
			expect(r.bob.settleHeldHtlc(hash, preimage)).to.equal(true);
			const st = fullState(r.bob, r.channelId);
			const kept = st.signedLocalRemovals![0];
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			const channel = r.bob.getChannelManager().getChannel(r.channelId) as any;
			const actions = channel.handleUpdateAddHtlc({
				channelId: r.channelId,
				id: kept.id + 1n,
				amountMsat: kept.amountMsat,
				paymentHash: kept.paymentHash,
				cltvExpiry: kept.cltvExpiry,
				onionRoutingPacket: kept.onionRoutingPacket
			});
			expect(
				actions.filter((x: { type: string }) => /ERROR/.test(x.type))
			).to.have.length(0);
			expect(received(st)[0].addLocallyRevoked).to.equal(false);

			const v = assertExit(r, 'bob', [{ preimage, hash }], 'kept and twin');
			expect(v.tx.getId()).to.equal(signed.getId());
			expect(v.htlcs).to.have.length(1);
			expect(v.htlcs[0].htlcId, 'attributed to the kept entry').to.equal(
				kept.id
			);
			r.destroy();
		});

		it('the peer broadcasts its commitment in the window: it does not carry its unsigned add, ours is whole, and the signed HTLC is still claimable', function () {
			const r = rig(3340);
			pay(r.alice, r.bob, 100_000_000n);
			const signedIn = park(r.alice, r.bob, 50_000_000n, 'signed-in');
			stopAliceCommitmentSigned(r);
			park(r.alice, r.bob, 40_000_000n, 'unsigned');
			const alicePlan = planClose(r.alice, r.channelId);
			expect(alicePlan.ok, alicePlan.error).to.equal(true);
			const aliceTx = bitcoin.Transaction.fromBuffer(alicePlan.commitmentTx!);
			expect(
				aliceTx.outs.filter((o) => BigInt(o.value) === 40_000n),
				'her own commitment has no output for the add we never signed in'
			).to.have.length(0);
			const st = fullState(r.bob, r.channelId);
			const manager = r.bob.getChannelManager();
			manager.recordPreimage(signedIn.hash, signedIn.preimage);
			manager.handleFundingSpent(r.channelId, aliceTx, 800_000, DESTINATION);
			const monitor = manager.getMonitor(r.channelId)!;
			const htlcs = monitorHtlcs(r.bob, r.channelId);
			expect(htlcs, 'only the signed HTLC').to.have.length(1);
			expect(htlcs[0].paymentHash!.equals(signedIn.hash)).to.equal(true);
			expect(htlcs[0].sweepTxHex, 'claimed with the preimage').to.not.equal(
				undefined
			);
			const ours = monitor
				.getTrackedOutputs()
				.filter((o) => o.outputType === OutputType.TO_REMOTE);
			expect(ours).to.have.length(1);
			expect(ours[0].amount).to.equal(st.localBalanceMsat / 1000n);
			r.destroy();
		});

		it('a revoked peer commitment while an unsigned add sits in the map: every output is punished, the add attributes nothing', function () {
			const r = rig(3360);
			const h = park(r.alice, r.bob, 50_000_000n, 'in-revoked');
			const old = planClose(r.alice, r.channelId);
			expect(old.ok, old.error).to.equal(true);
			const revokedTx = bitcoin.Transaction.fromBuffer(old.commitmentTx!);
			expect(r.bob.settleHeldHtlc(h.hash, h.preimage)).to.equal(true);
			expect(fullState(r.bob, r.channelId).htlcs.size).to.equal(0);
			stopAliceCommitmentSigned(r);
			park(r.alice, r.bob, 50_000_000n, 'unsigned-same-amount');
			const manager = r.bob.getChannelManager();
			const seed = makeSeed(TAG, r.bobSeedId);
			manager.handleFundingSpent(
				r.channelId,
				revokedTx,
				800_000,
				DESTINATION,
				10,
				seedKey(seed, 1),
				seedKey(seed, 2)
			);
			const tracked = manager.getMonitor(r.channelId)!.getTrackedOutputs();
			const htlc = tracked.filter((o) => BigInt(o.amount) === 50_000n);
			expect(htlc, 'the revoked HTLC output, once').to.have.length(1);
			expect(htlc[0].sweepTxHex, 'with a penalty spend').to.not.equal(
				undefined
			);
			expect(
				htlc[0].paymentHash?.equals(h.hash) ?? true,
				'not attributed to the unsigned add'
			).to.equal(true);
			r.destroy();
		});
	});

	describe('the kept-list search (PR #1292 round 1, c)', function () {
		for (const order of ['stale twin first', 'stale twin last'] as const) {
			it(`byte-identical twins, one genuine (${order}): the close and the claim hold whichever entry the search lands on`, function () {
				const w = simpleWindow(
					order === 'stale twin first' ? 3400 : 3410,
					'fulfill'
				);
				const st = fullState(w.bob, w.channelId);
				const genuine = st.signedLocalRemovals![0];
				const twin: IHtlcEntry = { ...genuine, id: genuine.id + 50n };
				st.signedLocalRemovals =
					order === 'stale twin first' ? [twin, genuine] : [genuine, twin];
				const manager = w.bob.getChannelManager();
				const broadcasts: string[] = [];
				manager.on('broadcast:tx', (tx: Buffer) =>
					broadcasts.push(bitcoin.Transaction.fromBuffer(tx).getId())
				);
				const v = assertExit(w, 'bob', [w.h], 'twins');
				expect(v.tx.getId()).to.equal(w.signed.getId());
				expect(v.htlcs, 'one output, one tracked').to.have.length(1);

				expect(manager.forceClose(w.channelId, DESTINATION).ok).to.equal(true);
				expect(broadcasts).to.include(w.signed.getId());
				const after = fullState(w.bob, w.channelId);
				expect(
					after.signedLocalRemovals,
					'narrowed to the one entry the signature covers'
				).to.have.length(1);
				manager.handleFundingSpent(w.channelId, w.signed, 800_000, DESTINATION);
				const tracked = monitorHtlcs(w.bob, w.channelId);
				expect(tracked).to.have.length(1);
				expect(tracked[0].sweepTxHex, 'HTLC-success built').to.not.equal(
					undefined
				);
				// eslint-disable-next-line no-console
				console.log(
					`        ${order}: kept id ${
						after.signedLocalRemovals![0].id
					} (genuine is ${genuine.id}), tracked htlcId ${tracked[0].htlcId}`
				);
				w.destroy();
			});
		}

		/** Bob removes `genuine` HTLCs in the window, then `stale` leftovers are put in front. */
		function mixedList(
			seedBase: number,
			genuine: number,
			stale: number
		): { r: IRig; signed: bitcoin.Transaction } {
			const r = rig(seedBase);
			const parked = [];
			for (let i = 0; i < genuine; i++) {
				parked.push(
					park(r.alice, r.bob, BigInt(20_000_000 + i * 1_000_000), `g${i}`)
				);
			}
			park(r.alice, r.bob, 60_000_000n, 'live');
			const signed = rebuild(fullState(r.bob, r.channelId)).result.tx;
			stopAliceCommitmentSigned(r);
			for (const h of parked) {
				expect(r.bob.settleHeldHtlc(h.hash, h.preimage)).to.equal(true);
			}
			const st = fullState(r.bob, r.channelId);
			expect(st.signedLocalRemovals).to.have.length(genuine);
			const leftovers: IHtlcEntry[] = [];
			for (let i = 0; i < stale; i++) {
				leftovers.push(
					staleEntry(
						BigInt(900 + i),
						HtlcState.FULFILLED,
						BigInt(11_000_000 + i)
					)
				);
			}
			st.signedLocalRemovals = [...leftovers, ...st.signedLocalRemovals!];
			return { r, signed };
		}

		it('six entries, two of them leftovers: found by the full search', function () {
			const { r, signed } = mixedList(3420, 4, 2);
			const cost = planCost(r.bob, r.channelId);
			expect(cost.ok, cost.error).to.equal(true);
			expect(cost.checks, 'bounded by 2^6').to.be.at.most(64);
			const plan = planClose(r.bob, r.channelId);
			expect(
				bitcoin.Transaction.fromBuffer(plan.commitmentTx!).getId()
			).to.equal(signed.getId());
			r.destroy();
		});

		it('seven entries, one leftover: found among the all-but-one selections', function () {
			const { r, signed } = mixedList(3440, 6, 1);
			const cost = planCost(r.bob, r.channelId);
			expect(cost.ok, cost.error).to.equal(true);
			expect(cost.checks).to.be.at.most(9);
			const plan = planClose(r.bob, r.channelId);
			expect(
				bitcoin.Transaction.fromBuffer(plan.commitmentTx!).getId()
			).to.equal(signed.getId());
			r.destroy();
		});

		it('pins issue #1299 item 1: seven entries, two of them leftovers, refuses the close (past six the search only drops one entry or all)', function () {
			// An accepted residual, tracked in issue #1299: the bound of the
			// kept-list search. The leftovers here are injected, not produced
			// on the wire.
			// What a splice negotiated inside one window and a second
			// window after its lock leave behind: the first window's
			// entries are leftovers for the adopted signature, the second
			// window's are genuine. Five genuine and two leftovers is
			// neither all-but-one nor none.
			const { r, signed } = mixedList(3460, 5, 2);
			expect(
				peerSigned(r.bob, r.channelId, signed),
				'the stored signature covers the commitment with the five'
			).to.equal(true);

			const plan = planClose(r.bob, r.channelId);

			expect(plan.ok, 'refused until issue #1299 item 1 is fixed').to.equal(
				false
			);
			r.destroy();
		});

		it('cost of a refused plan: six kept entries and an unsigned add', function () {
			const { r } = mixedList(3480, 4, 2);
			park(r.alice, r.bob, 40_000_000n, 'unsigned');
			const st = fullState(r.bob, r.channelId);
			const good = st.remoteCommitmentSignature!;
			const bad = Buffer.from(good);
			bad[10] ^= 0xff;
			st.remoteCommitmentSignature = bad;
			const cost = planCost(r.bob, r.channelId);
			st.remoteCommitmentSignature = good;
			expect(cost.ok).to.equal(false);
			// eslint-disable-next-line no-console
			console.log(
				`        refused, K=6, one unsigned add: ${cost.checks} checks, ${cost.ms} ms`
			);
			// The full list, its 63 smaller selections, and both once more
			// with the unsigned add carried.
			expect(cost.checks).to.equal(128);
			r.destroy();
		});

		it('cost of a refused plan multiplies with unstamped offered adds (rows from before addRemoteSigned)', function () {
			const { r } = mixedList(3490, 4, 2);
			park(r.alice, r.bob, 40_000_000n, 'unsigned');
			const st = fullState(r.bob, r.channelId);
			// Five offered adds as a pre-stamp row would hold them.
			for (let i = 0; i < 5; i++) {
				st.htlcs.set(`offered-${700 + i}`, {
					id: BigInt(700 + i),
					amountMsat: BigInt(5_000_000 + i),
					paymentHash: crypto.randomBytes(32),
					cltvExpiry: 800_200,
					onionRoutingPacket: Buffer.alloc(0),
					direction: HtlcDirection.OFFERED,
					state: HtlcState.COMMITTED
				});
			}
			const good = st.remoteCommitmentSignature!;
			const bad = Buffer.from(good);
			bad[10] ^= 0xff;
			st.remoteCommitmentSignature = bad;
			const cost = planCost(r.bob, r.channelId);
			st.remoteCommitmentSignature = good;
			expect(cost.ok).to.equal(false);
			// eslint-disable-next-line no-console
			console.log(
				`        refused, K=6, U=5, one unsigned add: ${cost.checks} checks, ${cost.ms} ms`
			);
			// 2 readings of the received adds x 64 selections x (1 + U).
			expect(cost.checks).to.equal(2 * 64 * 6);
			r.destroy();
		});

		it('cost of a refused plan: a kept list at max_accepted_htlcs and an unsigned add', function () {
			this.timeout(600_000);
			const w = simpleWindow(3500, 'fulfill');
			park(w.alice, w.bob, 40_000_000n, 'unsigned');
			const st = fullState(w.bob, w.channelId);
			const max = st.localConfig.maxAcceptedHtlcs;
			const list: IHtlcEntry[] = [...st.signedLocalRemovals!];
			for (let i = 0; list.length < max; i++) {
				list.push(staleEntry(BigInt(1000 + i), HtlcState.FAILED, 1_000_000n));
			}
			st.signedLocalRemovals = list;
			const good = st.remoteCommitmentSignature!;
			const bad = Buffer.from(good);
			bad[10] ^= 0xff;
			st.remoteCommitmentSignature = bad;
			const cost = planCost(w.bob, w.channelId);
			st.remoteCommitmentSignature = good;
			expect(cost.ok).to.equal(false);
			// eslint-disable-next-line no-console
			console.log(
				`        refused, K=${max}, one unsigned add: ${cost.checks} checks, ${cost.ms} ms`
			);
			// Linear, not exponential: the list, each all-but-one, none, and
			// all of that once more with the add carried.
			expect(cost.checks).to.equal(2 * (max + 2));
			w.destroy();
		});
	});

	describe('the claim backstop for a kept fulfilled HTLC (PR #1292 round 1, a)', function () {
		interface IWatch {
			attempts: Array<{ height: number; ok: boolean; error?: string }>;
			broadcasts: string[];
			codes: string[];
			height: { now: number };
		}

		/** Records every force-close attempt, broadcast and node error on Bob. */
		function watch(r: IRig): IWatch {
			const w: IWatch = {
				attempts: [],
				broadcasts: [],
				codes: [],
				height: { now: 0 }
			};
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			const manager = r.bob.getChannelManager() as any;
			const original = manager.forceClose.bind(manager);
			manager.forceClose = (
				...args: unknown[]
			): { ok: boolean; error?: string } => {
				const res = original(...args);
				w.attempts.push({ height: w.height.now, ok: res.ok, error: res.error });
				return res;
			};
			manager.on('broadcast:tx', (tx: Buffer) =>
				w.broadcasts.push(bitcoin.Transaction.fromBuffer(tx).getId())
			);
			r.bob.on('node:error', (e: { code: string }) => w.codes.push(e.code));
			return w;
		}

		function blocks(r: IRig, w: IWatch, from: number, to: number): void {
			const step = from <= to ? 1 : -1;
			for (let h = from; h !== to + step; h += step) {
				w.height.now = h;
				r.bob.handleNewBlock(h);
			}
		}

		function expiryOf(r: IRig): number {
			const st = fullState(r.bob, r.channelId);
			return [...received(st), ...(st.signedLocalRemovals ?? [])][0].cltvExpiry;
		}

		it('fires once, at the margin a live fulfilled HTLC gets, and a reorg afterwards changes nothing', function () {
			const w = simpleWindow(3600, 'fulfill');
			const expiry = expiryOf(w);
			const seen = watch(w);
			blocks(w, seen, expiry - 30, expiry + 3);
			expect(fullState(w.bob, w.channelId).state).to.equal(
				ChannelState.FORCE_CLOSED
			);
			const closes = seen.attempts.filter((a) => a.ok);
			expect(closes, 'one successful close').to.have.length(1);
			expect(closes[0].height, 'the 18-block claim buffer').to.equal(
				expiry - 18
			);
			expect(
				seen.codes.filter((c) => c === 'HTLC_CLAIM_FORCE_CLOSE')
			).to.have.length(1);
			expect(
				seen.broadcasts.filter((id) => id === w.signed.getId()).length,
				'the signed commitment went out'
			).to.be.greaterThan(0);
			const attempts = seen.attempts.length;
			// The tip moves back below the trigger height and forward again.
			blocks(w, seen, expiry - 25, expiry - 10);
			expect(seen.attempts.length, 'no further close attempt').to.equal(
				attempts
			);
			expect(fullState(w.bob, w.channelId).state).to.equal(
				ChannelState.FORCE_CLOSED
			);
			w.destroy();
		});

		it('a kept FAILED entry never closes the channel', function () {
			const w = simpleWindow(3620, 'fail');
			const expiry = expiryOf(w);
			const seen = watch(w);
			blocks(w, seen, expiry - 30, expiry + 3);
			expect(seen.attempts).to.have.length(0);
			expect(fullState(w.bob, w.channelId).state).to.equal(ChannelState.NORMAL);
			w.destroy();
		});

		it('still fires when the node has pruned the preimage from its own map, and the claim is built', function () {
			const w = simpleWindow(3640, 'fulfill');
			const expiry = expiryOf(w);
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			const preimages = (w.bob as any).preimages as Map<string, Buffer>;
			preimages.delete(w.h.hash.toString('hex'));
			const seen = watch(w);
			blocks(w, seen, expiry - 20, expiry - 17);
			expect(seen.attempts.filter((a) => a.ok)).to.have.length(1);
			w.bob
				.getChannelManager()
				.handleFundingSpent(w.channelId, w.signed, expiry - 16, DESTINATION);
			const tracked = monitorHtlcs(w.bob, w.channelId);
			expect(tracked).to.have.length(1);
			expect(
				tracked[0].sweepTxHex,
				'the monitor still has the preimage'
			).to.not.equal(undefined);
			w.destroy();
		});

		it('a kept fulfilled entry beside a live fulfilled one the peer never acked: one close for both', function () {
			const r = rig(3660);
			const a = park(r.alice, r.bob, 50_000_000n, 'kept');
			const b = park(r.alice, r.bob, 60_000_000n, 'unacked');
			const signed = rebuild(fullState(r.bob, r.channelId)).result.tx;
			stopAliceCommitmentSigned(r);
			expect(r.bob.settleHeldHtlc(a.hash, a.preimage)).to.equal(true);
			r.gate.drop.alice.add(MessageType.REVOKE_AND_ACK);
			expect(r.bob.settleHeldHtlc(b.hash, b.preimage)).to.equal(true);
			const st = fullState(r.bob, r.channelId);
			expect(st.signedLocalRemovals).to.have.length(1);
			expect(received(st).map((e) => e.state)).to.deep.equal([
				HtlcState.FULFILLED
			]);
			const expiry = Math.min(
				received(st)[0].cltvExpiry,
				st.signedLocalRemovals![0].cltvExpiry
			);
			const seen = watch(r);
			blocks(r, seen, expiry - 30, expiry + 3);
			expect(seen.attempts.filter((x) => x.ok)).to.have.length(1);
			expect(
				seen.attempts.filter((x) => !x.ok),
				'no refused retries'
			).to.have.length(0);
			expect(seen.broadcasts).to.include(signed.getId());
			const manager = r.bob.getChannelManager();
			manager.handleFundingSpent(r.channelId, signed, expiry, DESTINATION);
			const tracked = monitorHtlcs(r.bob, r.channelId);
			expect(tracked).to.have.length(2);
			for (const o of tracked) {
				expect(o.sweepTxHex, 'both claimed').to.not.equal(undefined);
			}
			r.destroy();
		});

		it('with the offered-side stalled removal (issue #634) on the same channel: one close, one broadcast, one reason', function () {
			const r = rig(3680);
			pay(r.alice, r.bob, 300_000_000n);
			const h = park(r.alice, r.bob, 50_000_000n, 'kept');
			const o = park(r.bob, r.alice, 30_000_000n, 'offered');
			const signed = rebuild(fullState(r.bob, r.channelId)).result.tx;
			stopAliceCommitmentSigned(r);
			expect(r.bob.settleHeldHtlc(h.hash, h.preimage)).to.equal(true);
			expect(r.alice.settleHeldHtlc(o.hash, o.preimage)).to.equal(true);
			const st = fullState(r.bob, r.channelId);
			const offered = [...st.htlcs.values()].find(
				(e) => e.direction === HtlcDirection.OFFERED
			)!;
			expect(offered.state, 'the peer fulfilled and left it unsigned').to.equal(
				HtlcState.FULFILLED
			);
			const keptExpiry = st.signedLocalRemovals![0].cltvExpiry;
			const seen = watch(r);
			const low = Math.min(keptExpiry, offered.cltvExpiry) - 30;
			const high = Math.max(keptExpiry, offered.cltvExpiry) + 30;
			blocks(r, seen, low, high);
			expect(seen.attempts, 'one attempt in all').to.have.length(1);
			expect(seen.attempts[0].ok).to.equal(true);
			expect(
				seen.broadcasts.filter((id) => id === signed.getId())
			).to.have.length(1);
			const after = fullState(r.bob, r.channelId);
			expect(after.state).to.equal(ChannelState.FORCE_CLOSED);
			expect(after.closeReason).to.equal('HTLC_CLAIM_FORCE_CLOSE');
			r.destroy();
		});

		it('fires through an unsigned peer add while the peer stays connected (refused, and the channel left ERRORED for good, on PR #1292 alone)', function () {
			const w = simpleWindow(3690, 'fulfill');
			park(w.alice, w.bob, 40_000_000n, 'unsigned');
			const expiry = fullState(w.bob, w.channelId).signedLocalRemovals![0]
				.cltvExpiry;
			const seen = watch(w);
			blocks(w, seen, expiry - 30, expiry + 3);
			expect(seen.attempts).to.have.length(1);
			expect(seen.attempts[0]).to.deep.include({
				height: expiry - 18,
				ok: true
			});
			expect(seen.broadcasts).to.include(w.signed.getId());
			expect(fullState(w.bob, w.channelId).state).to.equal(
				ChannelState.FORCE_CLOSED
			);
			w.destroy();
		});

		it('one unsigned update_add_htlc on a hash whose preimage we hold, inside the claim buffer, does not close the channel: there is nothing to claim', function () {
			// The claim arm reads PENDING entries and used to ask only whether
			// the preimage is in hand, never whether the add is in the
			// commitment we hold. Before the received-add rebuild that close
			// was refused (the rebuild carried the add and the signature did
			// not cover it); with the add left out of the rebuild it would go
			// through, on a commitment that has no output for the HTLC it is
			// closing to claim. The arm now skips an add the peer has not
			// signed in.
			const r = rig(3720);
			pay(r.alice, r.bob, 100_000_000n);
			const invoice = r.bob.createInvoice({
				amountMsat: 50_000_000n,
				description: 'an invoice of ours, so its preimage is in the store'
			});
			r.bob.handleNewBlock(1000);
			const before = rebuild(fullState(r.bob, r.channelId)).result.tx;
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			const channel = r.bob.getChannelManager().getChannel(r.channelId) as any;
			const nextId = fullState(r.alice, r.channelId).localHtlcCounter;
			const actions = channel.handleUpdateAddHtlc({
				channelId: r.channelId,
				id: nextId,
				amountMsat: 50_000_000n,
				paymentHash: invoice.paymentHash,
				cltvExpiry: 1012,
				onionRoutingPacket: Buffer.alloc(1366)
			});
			expect(
				actions.filter((x: { type: string }) => /ERROR/.test(x.type))
			).to.have.length(0);
			const st = fullState(r.bob, r.channelId);
			expect(received(st).map((e) => e.addLocallyRevoked)).to.deep.equal([
				false
			]);
			expect(
				peerSigned(r.bob, r.channelId, before),
				'the stored signature is still over the commitment from before the add'
			).to.equal(true);
			expect(
				before.outs.filter((o) => BigInt(o.value) === 50_000n),
				'which has no output for it'
			).to.have.length(0);

			const seen = watch(r);
			blocks(r, seen, 1001, 1001);

			expect(
				seen.broadcasts,
				'no close for an HTLC that is not in our commitment'
			).to.have.length(0);
			expect(seen.attempts, 'none attempted either').to.have.length(0);
			expect(seen.codes).to.not.include('HTLC_CLAIM_FORCE_CLOSE');
			expect(fullState(r.bob, r.channelId).state).to.equal(ChannelState.NORMAL);
			r.destroy();
		});

		it('the same HTLC once the peer has signed it in closes at the claim buffer as before', function () {
			// The other side of that gate, on the wire: an invoice of ours is
			// paid, the peer's signature covering the add is accepted, and its
			// revoke_and_ack for our own commitment never comes. The add is in
			// the commitment we hold, it is not irrevocably committed so the
			// node has not fulfilled it, and its preimage is in the store.
			const r = rig(3740);
			const invoice = r.bob.createInvoice({
				amountMsat: 50_000_000n,
				description: 'an invoice of ours, signed in and never revoked for'
			});
			r.gate.drop.alice.add(MessageType.REVOKE_AND_ACK);
			r.alice.sendPayment(invoice.bolt11);
			const st = fullState(r.bob, r.channelId);
			const entry = received(st)[0];
			expect(entry.state).to.equal(HtlcState.COMMITTED);
			expect(entry.addLocallyRevoked, 'signed in').to.equal(true);
			expect(entry.addRemotelyRevoked, 'not irrevocable').to.equal(false);
			const signed = rebuild(st).result.tx;
			expect(peerSigned(r.bob, r.channelId, signed)).to.equal(true);
			expect(
				signed.outs.filter((o) => BigInt(o.value) === 50_000n),
				'the commitment we hold has the output'
			).to.have.length(1);

			const seen = watch(r);
			blocks(r, seen, entry.cltvExpiry - 25, entry.cltvExpiry - 10);

			expect(seen.attempts).to.have.length(1);
			expect(seen.attempts[0]).to.deep.include({
				height: entry.cltvExpiry - 18,
				ok: true
			});
			expect(seen.codes).to.include('HTLC_CLAIM_FORCE_CLOSE');
			expect(seen.broadcasts).to.include(signed.getId());
			r.destroy();
		});

		it('pins the SHUTTING_DOWN gap (issue #1298): the claim arm does not scan it, and the stuck-channel timer closes 7 blocks before expiry instead of 18', function () {
			// Tracked in issue #1298, and present on master before any of
			// this: a live fulfilled HTLC in SHUTTING_DOWN is
			// skipped the same way. The only close left is the stuck-channel
			// timer, which starts at the first block seen in the state, lives
			// in memory, and fires 11 blocks later.
			const w = simpleWindow(3700, 'fulfill');
			const expiry = expiryOf(w);
			const seen = watch(w);
			blocks(w, seen, expiry - 25, expiry - 19);
			expect(seen.attempts).to.have.length(0);
			// The peer goes silent from here on.
			w.gate.queue.alice = [];
			const res = w.bob
				.getChannelManager()
				.initiateShutdown(w.channelId, DESTINATION);
			expect(res.ok, res.error).to.equal(true);
			blocks(w, seen, expiry - 18, expiry + 5);
			expect(seen.attempts).to.have.length(1);
			expect(seen.attempts[0]).to.deep.include({
				height: expiry - 7,
				ok: true
			});
			expect(seen.codes).to.deep.equal(['STUCK_CHANNEL_FORCE_CLOSED']);
			expect(seen.broadcasts).to.include(w.signed.getId());
			w.destroy();
		});
	});
});
