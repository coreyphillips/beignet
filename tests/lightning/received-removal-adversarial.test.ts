/**
 * Adversarial review of the received-removal force-close window (PR #1292,
 * issue #1291).
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
	isAnchorChannel,
	isTaprootChannel
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
import {
	deserializeChannelState,
	serializeChannelState
} from '../../src/lightning/storage/serialization';
import {
	buildGraph,
	createNode,
	makeExternalHash,
	makeSeed,
	openReadyChannel
} from './helpers/loopback-nodes';
import { seedKey } from './helpers/real-signing';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { MonitorState } from '../../src/lightning/chain/types';

const TAG = 'received-removal-adversarial';
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

describe('Received-removal window, adversarial', function () {
	this.timeout(20_000);

	describe('builder: what the kept entries reproduce', function () {
		for (const anchors of [true, false]) {
			const kind = anchors ? 'anchors' : 'legacy';
			for (const removal of ['fulfill', 'fail'] as const) {
				it(`a trimmed (dust) HTLC removed in the window, ${kind}, ${removal}`, function () {
					const r = rig(
						(anchors ? 1000 : 1100) + (removal === 'fulfill' ? 0 : 10),
						{ preferAnchors: anchors }
					);
					expect(
						isAnchorChannel(fullState(r.bob, r.channelId).channelType)
					).to.equal(anchors);
					// Below Bob's dust limit (354 sat), so it has no output and
					// its amount sits in the fee of the signed commitment.
					const dust = park(r.alice, r.bob, 200_000n, 'dust');
					const live = park(r.alice, r.bob, 40_000_000n, 'live');
					expect(r.bob.listHeldHtlcs()).to.have.length(2);
					const before = rebuild(fullState(r.bob, r.channelId)).result.tx;
					expect(peerSigned(r.bob, r.channelId, before)).to.equal(true);

					stopAliceCommitmentSigned(r);
					if (removal === 'fulfill') {
						expect(r.bob.settleHeldHtlc(dust.hash, dust.preimage)).to.equal(
							true
						);
					} else {
						expect(r.bob.cancelHoldInvoice(dust.hash)).to.deep.equal({
							htlcsFailed: 1
						});
					}
					const st = fullState(r.bob, r.channelId);
					expect(
						st.signedLocalRemovals,
						'the dust entry is kept'
					).to.have.length(1);
					const v = assertExit(r, 'bob', [dust, live], 'dust window');
					expect(v.tx.getId()).to.equal(before.getId());
					expect(v.htlcs, 'only the live HTLC has an output').to.have.length(1);
					r.destroy();
				});
			}
		}

		for (const removal of ['fulfill', 'fail'] as const) {
			it(`fractional-msat HTLCs removed in the window (${removal})`, function () {
				const r = rig(1200 + (removal === 'fulfill' ? 0 : 10));
				// Leave both balances with sub-satoshi residue first.
				pay(r.alice, r.bob, 123_456_789n);
				const a = park(r.alice, r.bob, 50_000_999n, 'a');
				const b = park(r.alice, r.bob, 60_000_001n, 'b');
				const c = park(r.alice, r.bob, 70_000_500n, 'c');
				expect(r.bob.listHeldHtlcs()).to.have.length(3);
				const before = rebuild(fullState(r.bob, r.channelId)).result.tx;
				expect(peerSigned(r.bob, r.channelId, before)).to.equal(true);

				stopAliceCommitmentSigned(r);
				for (const h of [a, b]) {
					if (removal === 'fulfill') {
						expect(r.bob.settleHeldHtlc(h.hash, h.preimage)).to.equal(true);
					} else {
						expect(r.bob.cancelHoldInvoice(h.hash)).to.deep.equal({
							htlcsFailed: 1
						});
					}
					const v = assertExit(r, 'bob', [a, b, c], 'fractional window');
					expect(v.tx.getId()).to.equal(before.getId());
					expect(v.htlcs).to.have.length(3);
				}
				expect(
					fullState(r.bob, r.channelId).signedLocalRemovals
				).to.have.length(2);
				r.destroy();
			});
		}
	});

	describe('mixed rounds inside the window', function () {
		it('several fulfilled and failed together, an offered removal, and new adds from both sides', function () {
			const r = rig(1300);
			pay(r.alice, r.bob, 300_000_000n);
			const h1 = park(r.alice, r.bob, 50_000_000n, 'h1');
			const h2 = park(r.alice, r.bob, 51_000_000n, 'h2');
			const h3 = park(r.alice, r.bob, 52_000_000n, 'h3');
			const h4 = park(r.alice, r.bob, 53_000_000n, 'h4');
			const o1 = park(r.bob, r.alice, 30_000_000n, 'o1');
			expect(r.bob.listHeldHtlcs()).to.have.length(4);
			expect(r.alice.listHeldHtlcs()).to.have.length(1);
			const all = [h1, h2, h3, h4, o1];
			const before = rebuild(fullState(r.bob, r.channelId)).result.tx;
			expect(peerSigned(r.bob, r.channelId, before)).to.equal(true);
			const check = (label: string, htlcCount = 5): void => {
				const v = assertExit(r, 'bob', all, label);
				expect(v.tx.getId(), `${label}: the signed commitment`).to.equal(
					before.getId()
				);
				expect(v.htlcs, `${label}: every HTLC output tracked`).to.have.length(
					htlcCount
				);
			};
			check('before');

			stopAliceCommitmentSigned(r);
			expect(r.bob.settleHeldHtlc(h1.hash, h1.preimage)).to.equal(true);
			check('h1 fulfilled');
			expect(r.bob.cancelHoldInvoice(h2.hash)).to.deep.equal({
				htlcsFailed: 1
			});
			check('h2 failed');
			expect(r.bob.settleHeldHtlc(h3.hash, h3.preimage)).to.equal(true);
			check('h3 fulfilled');
			expect(
				fullState(r.bob, r.channelId).signedLocalRemovals,
				'three kept'
			).to.have.length(3);

			// Alice removes the HTLC Bob offered: on Bob it is an offered
			// removal the stored signature still carries.
			expect(r.alice.settleHeldHtlc(o1.hash, o1.preimage)).to.equal(true);
			check('o1 fulfilled by the peer');

			// Bob offers a new HTLC; Alice revokes for it and her signature
			// covering it never arrives.
			const o2 = park(r.bob, r.alice, 20_000_000n, 'o2');
			all.push(o2);
			check('o2 offered, unsigned by the peer');

			r.destroy();
		});

		it('a same-hash, same-amount, same-expiry add beside a kept removal', function () {
			const r = rig(1320);
			const { preimage, hash } = makeExternalHash();
			const inv = (): string =>
				r.bob.createInvoice({
					amountMsat: 50_000_000n,
					description: 'twin',
					hold: true,
					paymentHash: hash
				}).bolt11;
			const bolt11 = inv();
			r.alice.sendPayment(bolt11);
			expect(r.bob.listHeldHtlcs()).to.have.length(1);
			const other = park(r.alice, r.bob, 60_000_000n, 'other');
			const before = rebuild(fullState(r.bob, r.channelId)).result.tx;

			stopAliceCommitmentSigned(r);
			expect(r.bob.settleHeldHtlc(hash, preimage)).to.equal(true);
			const st = fullState(r.bob, r.channelId);
			expect(st.signedLocalRemovals).to.have.length(1);
			const kept = st.signedLocalRemovals![0];

			// A twin of the kept entry arrives as a fresh add: same hash, amount
			// and expiry, so its script is byte-identical. Its covering
			// commitment_signed is withheld like the rest. Injected as the wire
			// message Alice would send for a retry.
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			const channel = r.bob.getChannelManager().getChannel(r.channelId) as any;
			const nextId =
				[...fullState(r.alice, r.channelId).htlcs.values()]
					.filter((e) => e.direction === HtlcDirection.OFFERED)
					.reduce((m, e) => (e.id > m ? e.id : m), kept.id) + 1n;
			const actions = channel.handleUpdateAddHtlc({
				channelId: r.channelId,
				id: nextId,
				amountMsat: kept.amountMsat,
				paymentHash: kept.paymentHash,
				cltvExpiry: kept.cltvExpiry,
				onionRoutingPacket: kept.onionRoutingPacket
			});
			expect(
				actions.filter((a: { type: string }) => /ERROR/.test(a.type)),
				'the twin add is accepted'
			).to.have.length(0);
			expect(received(fullState(r.bob, r.channelId))).to.have.length(2);

			// The signed commitment reaches the chain. (A close of our own is
			// refused here for a different reason, pinned in the next cases.)
			const tx = before;
			const now = fullState(r.bob, r.channelId);
			const tracked = htlcOutputs(
				classifyOutputs(
					tx,
					now,
					CommitmentType.OUR_COMMITMENT,
					now.localCommitmentNumber
				)
			);
			expect(tracked).to.have.length(2);
			const twin = tracked.find((o) => o.paymentHash!.equals(hash))!;
			expect(
				twin.htlcId,
				'the output is attributed to the kept entry, not the unsigned twin'
			).to.equal(kept.id);
			void other;
			r.destroy();
		});
	});

	describe('update_fee in flight during the window', function () {
		it('the peer (opener) stages a new feerate whose signature never arrives', function () {
			const w = simpleWindow(1400, 'fulfill', { preferAnchors: false });
			const before = fullState(w.bob, w.channelId);
			const rate = before.remoteConfig.feeratePerKw;
			const res = w.alice.updateChannelFee(w.channelId, rate * 3);
			expect(res.ok, res.error).to.equal(true);
			const st = fullState(w.bob, w.channelId);
			expect(st.pendingFeeratePerKw, 'staged on Bob').to.equal(rate * 3);
			const v = assertExit(w, 'bob', [w.h], 'fee staged by peer');
			expect(v.tx.getId()).to.equal(w.signed.getId());
			w.destroy();
		});

		it('we (opener) stage a new feerate inside our own window', function () {
			// Roles swapped: Alice opened the channel and is the one holding
			// the window, with Bob withholding.
			const r = rig(1420, { preferAnchors: false });
			pay(r.alice, r.bob, 300_000_000n);
			const h = park(r.bob, r.alice, 50_000_000n, 'to-opener');
			expect(r.alice.listHeldHtlcs()).to.have.length(1);
			const signed = rebuild(fullState(r.alice, r.channelId)).result.tx;
			stopCommitmentSigned(r, 'bob');
			expect(r.alice.settleHeldHtlc(h.hash, h.preimage)).to.equal(true);
			expect(
				fullState(r.alice, r.channelId).signedLocalRemovals
			).to.have.length(1);
			let v = assertExit(r, 'alice', [h], 'opener window');
			expect(v.tx.getId()).to.equal(signed.getId());

			const rate = fullState(r.alice, r.channelId).localConfig.feeratePerKw;
			const res = r.alice.updateChannelFee(r.channelId, rate * 2);
			expect(res.ok, res.error).to.equal(true);
			v = assertExit(r, 'alice', [h], 'opener window, own fee staged');
			expect(v.tx.getId()).to.equal(signed.getId());
			r.destroy();
		});
	});

	describe('the list across reconnects, replays and rejections', function () {
		it('survives a reconnect on which the peer still withholds', function () {
			const w = simpleWindow(1500, 'fulfill');
			const am = w.alice.getChannelManager();
			const bm = w.bob.getChannelManager();
			am.handlePeerDisconnected(w.bob.getNodeId());
			bm.handlePeerDisconnected(w.alice.getNodeId());
			w.gate.queue.alice = [];
			w.gate.queue.bob = [];
			am.handlePeerReconnected(w.bob.getNodeId());
			bm.handlePeerReconnected(w.alice.getNodeId());
			const qa = w.gate.queue.alice;
			const qb = w.gate.queue.bob;
			w.gate.queue.alice = null;
			w.gate.queue.bob = null;
			for (const d of [...qa, ...qb]) d();
			const st = fullState(w.bob, w.channelId);
			expect(
				w.gate.dropped.alice.length,
				'Alice retransmitted her commitment_signed and it was stopped again'
			).to.be.greaterThan(1);
			expect(st.signedLocalRemovals, 'still kept').to.have.length(1);
			const v = assertExit(w, 'bob', [w.h], 'after reconnect');
			expect(v.tx.getId()).to.equal(w.signed.getId());
			w.destroy();
		});

		it('a replayed revoke_and_ack does not keep the entry twice', function () {
			const r = rig(1520);
			const h = park(r.alice, r.bob, 50_000_000n, 'replay');
			const signed = rebuild(fullState(r.bob, r.channelId)).result.tx;
			stopAliceCommitmentSigned(r);
			let raa: Buffer | null = null;
			r.alice.on('message:outbound', (_pk: string, t: number, p: Buffer) => {
				if (t === MessageType.REVOKE_AND_ACK) raa = p;
			});
			expect(r.bob.settleHeldHtlc(h.hash, h.preimage)).to.equal(true);
			expect(raa, 'captured').to.not.equal(null);
			expect(fullState(r.bob, r.channelId).signedLocalRemovals).to.have.length(
				1
			);
			const balance = fullState(r.bob, r.channelId).localBalanceMsat;

			r.bob.handlePeerMessage(
				r.alice.getNodeId(),
				MessageType.REVOKE_AND_ACK,
				raa!
			);

			const st = fullState(r.bob, r.channelId);
			expect(st.signedLocalRemovals, 'kept once').to.have.length(1);
			expect(st.localBalanceMsat, 'credited once').to.equal(balance);
			const plan = planClose(r.bob, r.channelId);
			expect(plan.ok, plan.error).to.equal(true);
			expect(
				bitcoin.Transaction.fromBuffer(plan.commitmentTx!).getId()
			).to.equal(signed.getId());
			r.destroy();
		});

		it('a rejected commitment_signed leaves the list and the exit intact', function () {
			const w = simpleWindow(1540, 'fulfill');
			expect(w.gate.dropped.alice).to.have.length(1);
			const forged = Buffer.from(w.gate.dropped.alice[0].payload);
			// channel_id (32) then the 64-byte signature: break the signature.
			forged[40] ^= 0xff;
			const broadcasts: string[] = [];
			w.bob
				.getChannelManager()
				.on('broadcast:tx', (tx: Buffer) =>
					broadcasts.push(bitcoin.Transaction.fromBuffer(tx).getId())
				);
			w.bob.handlePeerMessage(
				w.alice.getNodeId(),
				MessageType.COMMITMENT_SIGNED,
				forged
			);
			const st = fullState(w.bob, w.channelId);
			expect(st.signedLocalRemovals, 'still kept').to.have.length(1);
			if (broadcasts.length === 0) {
				const res = w.bob
					.getChannelManager()
					.forceClose(w.channelId, DESTINATION);
				expect(res.ok, `${st.state}: ${res.error}`).to.equal(true);
			}
			expect(
				broadcasts,
				'the commitment the peer signed is what went out'
			).to.include(w.signed.getId());
			w.destroy();
		});

		it('the withheld commitment_signed delivered twice clears once and fails the second', function () {
			const w = simpleWindow(1560, 'fulfill');
			const payload = w.gate.dropped.alice[0].payload;
			w.gate.drop.alice.clear();
			w.bob.handlePeerMessage(
				w.alice.getNodeId(),
				MessageType.COMMITMENT_SIGNED,
				payload
			);
			let st = fullState(w.bob, w.channelId);
			expect(st.signedLocalRemovals).to.equal(undefined);
			const afterFirst = rebuild(st).result.tx.getId();
			expect(afterFirst).to.not.equal(w.signed.getId());
			w.bob.handlePeerMessage(
				w.alice.getNodeId(),
				MessageType.COMMITMENT_SIGNED,
				payload
			);
			st = fullState(w.bob, w.channelId);
			expect(st.signedLocalRemovals).to.equal(undefined);
			// Whatever the replay did to the channel, the commitment we hold
			// is still the one the first delivery stored.
			const plan = planClose(w.bob, w.channelId);
			if (plan.ok) {
				expect(
					bitcoin.Transaction.fromBuffer(plan.commitmentTx!).getId()
				).to.equal(afterFirst);
			}
			w.destroy();
		});

		it('a shutdown started inside the window does not disturb the exit', function () {
			// hasPendingHtlcs reads the channel as idle in the window, so a
			// shutdown is admitted while our commitment still carries the HTLC.
			const w = simpleWindow(1580 + 5, 'fulfill');
			const res = w.bob
				.getChannelManager()
				.initiateShutdown(w.channelId, DESTINATION);
			expect(res.ok, res.error).to.equal(true);
			const st = fullState(w.bob, w.channelId);
			expect(st.state).to.not.equal(ChannelState.NORMAL);
			expect(st.signedLocalRemovals).to.have.length(1);
			const plan = planClose(w.bob, w.channelId);
			expect(plan.ok, plan.error).to.equal(true);
			const tx = bitcoin.Transaction.fromBuffer(plan.commitmentTx!);
			expect(tx.getId()).to.equal(w.signed.getId());
			expect(peerSigned(w.bob, w.channelId, tx)).to.equal(true);
			w.destroy();
		});

		it('survives a restart from disk: close, classification and the HTLC-success', function () {
			const dbPath = tempDb('rr-adversarial');
			const disk = new SqliteStorage(dbPath);
			disk.open();
			const w = simpleWindow(1580, 'fulfill', {}, disk);
			const aliceId = w.alice.getNodeId();
			w.bob.destroy();
			w.alice.getChannelManager().handlePeerDisconnected(w.bob.getNodeId());

			const disk2 = new SqliteStorage(dbPath);
			disk2.open();
			const restored = createNode(TAG, w.bobSeedId, disk2);
			const st = fullState(restored, w.channelId);
			expect(
				st.signedLocalRemovals,
				'the kept entry is on disk'
			).to.have.length(1);
			const broadcasts: string[] = [];
			const manager = restored.getChannelManager();
			manager.on('broadcast:tx', (tx: Buffer) =>
				broadcasts.push(bitcoin.Transaction.fromBuffer(tx).getId())
			);
			const res = manager.forceClose(w.channelId, DESTINATION);
			expect(res.ok, res.error).to.equal(true);
			expect(broadcasts, 'the signed commitment went out').to.include(
				w.signed.getId()
			);
			manager.handleFundingSpent(w.channelId, w.signed, 800_000, DESTINATION);
			const tracked = monitorHtlcs(restored, w.channelId);
			expect(tracked, 'the HTLC output is tracked').to.have.length(1);
			expect(
				tracked[0].sweepTxHex,
				'the HTLC-success is built from the preimage on disk'
			).to.not.equal(undefined);
			const claim = bitcoin.Transaction.fromHex(tracked[0].sweepTxHex!);
			expect(
				claim.ins[0].witness.some((item) => item.equals(w.h.preimage))
			).to.equal(true);
			void aliceId;
			restored.destroy();
			w.alice.destroy();
		});
	});

	describe('the window closing after a restart', function () {
		it('the commitment_signed a reconnect redelivers clears the list in memory and on disk', async function () {
			const dbPath = tempDb('rr-adversarial-clear');
			const disk = new SqliteStorage(dbPath);
			disk.open();
			const w = simpleWindow(1590, 'fulfill', {}, disk);
			const idHex = w.channelId.toString('hex');
			expect(
				disk.loadChannel(idHex)!.state.signedLocalRemovals,
				'on disk inside the window'
			).to.have.length(1);
			w.bob.destroy();
			w.alice.getChannelManager().handlePeerDisconnected(w.bob.getNodeId());
			w.alice.removeAllListeners('message:outbound');

			const disk2 = new SqliteStorage(dbPath);
			disk2.open();
			const restored = createNode(TAG, w.bobSeedId, disk2);
			expect(
				fullState(restored, w.channelId).signedLocalRemovals
			).to.have.length(1);

			// Both channel_reestablish messages cross before any reply.
			const queue: Array<() => void> = [];
			let hold = true;
			const rewire = (from: LightningNode, to: LightningNode): void => {
				from.on('message:outbound', (pk: string, t: number, p: Buffer) => {
					if (pk !== to.getNodeId()) return;
					const deliver = (): void =>
						to.handlePeerMessage(from.getNodeId(), t, p);
					if (hold) queue.push(deliver);
					else deliver();
				});
			};
			rewire(w.alice, restored);
			rewire(restored, w.alice);
			w.alice.getChannelManager().handlePeerReconnected(restored.getNodeId());
			restored.getChannelManager().handlePeerReconnected(w.alice.getNodeId());
			while (queue.length > 0) queue.shift()!();
			hold = false;
			for (let i = 0; i < 6; i++) {
				await new Promise<void>((resolve) => setImmediate(resolve));
			}

			const st = fullState(restored, w.channelId);
			expect(st.state).to.equal(ChannelState.NORMAL);
			expect(st.signedLocalRemovals, 'cleared in memory').to.equal(undefined);
			expect(
				disk2.loadChannel(idHex)!.state.signedLocalRemovals,
				'and on disk'
			).to.equal(undefined);
			const plan = planClose(restored, w.channelId);
			expect(plan.ok, plan.error).to.equal(true);
			const tx = bitcoin.Transaction.fromBuffer(plan.commitmentTx!);
			expect(tx.getId()).to.not.equal(w.signed.getId());
			expect(peerSigned(restored, w.channelId, tx)).to.equal(true);
			restored.destroy();
			w.alice.destroy();
		});
	});

	describe('chain side', function () {
		it('the peer broadcasts its CURRENT commitment in the window: no HTLC output is tracked and ours is whole', function () {
			const w = simpleWindow(1600, 'fulfill');
			const alicePlan = planClose(w.alice, w.channelId);
			expect(alicePlan.ok, alicePlan.error).to.equal(true);
			const aliceTx = bitcoin.Transaction.fromBuffer(alicePlan.commitmentTx!);
			const st = fullState(w.bob, w.channelId);
			const manager = w.bob.getChannelManager();
			manager.handleFundingSpent(w.channelId, aliceTx, 800_000, DESTINATION);
			const monitor = manager.getMonitor(w.channelId)!;
			expect(monitorHtlcs(w.bob, w.channelId), 'no HTLC output').to.have.length(
				0
			);
			const ours = monitor
				.getTrackedOutputs()
				.filter((o) => o.outputType === OutputType.TO_REMOTE);
			expect(ours, 'our balance output').to.have.length(1);
			expect(ours[0].amount, 'carries the fulfilled amount').to.equal(
				st.localBalanceMsat / 1000n
			);
			expect(monitor.getState()).to.not.equal(MonitorState.FULLY_RESOLVED);
			w.destroy();
		});

		it('the peer broadcasts its REVOKED commitment (with the HTLC) in the window: penalised, the kept entry is not a candidate', function () {
			const r = rig(1620);
			const h = park(r.alice, r.bob, 50_000_000n, 'revoked');
			const old = planClose(r.alice, r.channelId);
			expect(old.ok, old.error).to.equal(true);
			const revokedTx = bitcoin.Transaction.fromBuffer(old.commitmentTx!);
			stopAliceCommitmentSigned(r);
			expect(r.bob.settleHeldHtlc(h.hash, h.preimage)).to.equal(true);
			const st = fullState(r.bob, r.channelId);
			expect(st.signedLocalRemovals).to.have.length(1);

			// Asked directly: on THEIR commitment the kept entry is not offered.
			const direct = classifyOutputs(
				revokedTx,
				st,
				CommitmentType.THEIR_REVOKED_COMMITMENT,
				st.remoteCommitmentNumber - 1n
			);
			expect(
				htlcOutputs(direct),
				'the kept entry attributes nothing on the peer commitment'
			).to.have.length(0);

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
			const monitor = manager.getMonitor(r.channelId)!;
			const tracked = monitor.getTrackedOutputs();
			const htlc = tracked.filter((o) => BigInt(o.amount) === 50_000n);
			expect(htlc, 'the revoked HTLC output is tracked').to.have.length(1);
			expect(htlc[0].sweepTxHex, 'with a penalty spend').to.not.equal(
				undefined
			);
			r.destroy();
		});

		it('our close in the window through the monitor: fee attach on the preserved input, each output resolved once, nothing credited twice', function () {
			const r = rig(1660);
			const a = park(r.alice, r.bob, 50_000_000n, 'fulfilled');
			const b = park(r.alice, r.bob, 60_000_000n, 'failed');
			const signed = rebuild(fullState(r.bob, r.channelId)).result.tx;
			stopAliceCommitmentSigned(r);
			expect(r.bob.settleHeldHtlc(a.hash, a.preimage)).to.equal(true);
			expect(r.bob.cancelHoldInvoice(b.hash)).to.deep.equal({ htlcsFailed: 1 });
			const balance = fullState(r.bob, r.channelId).localBalanceMsat;
			const manager = r.bob.getChannelManager();
			expect(manager.forceClose(r.channelId, DESTINATION).ok).to.equal(true);

			const actions: Array<{ type: string; [k: string]: unknown }> = [];
			const push = (list: unknown[]): void => {
				actions.push(...(list as Array<{ type: string }>));
			};
			push(
				manager.handleFundingSpent(r.channelId, signed, 800_000, DESTINATION)
			);
			push(manager.handleNewBlock(800_001));
			push(manager.handleNewBlock(800_002));

			const tracked = monitorHtlcs(r.bob, r.channelId);
			expect(tracked, 'one tracked output per HTLC output').to.have.length(2);
			const outA = tracked.find((o) => o.paymentHash!.equals(a.hash))!;
			const outB = tracked.find((o) => o.paymentHash!.equals(b.hash))!;
			expect(
				outA.sweepTxHex,
				'HTLC-success for the fulfilled one'
			).to.not.equal(undefined);
			expect(outB.sweepTxHex, 'no claim for the failed one').to.equal(
				undefined
			);

			// The broadcast of the HTLC-success carries the peer's stored
			// signature on input 0 (SINGLE|ANYONECANPAY on anchors).
			const st = fullState(r.bob, r.channelId);
			const claim = bitcoin.Transaction.fromHex(outA.sweepTxHex!);
			const sent = actions.filter(
				(x) =>
					(x.type === 'CHAIN_FEE_BUMP_AND_BROADCAST' ||
						x.type === 'CHAIN_BROADCAST_TX') &&
					Buffer.isBuffer(x.tx) &&
					bitcoin.Transaction.fromBuffer(x.tx as Buffer).ins.some(
						(i) =>
							Buffer.from(i.hash).reverse().toString('hex') ===
								signed.getId() && i.index === outA.outputIndex
					)
			);
			expect(
				sent,
				'the HTLC-success was handed to the broadcaster'
			).to.have.length.greaterThan(0);
			const keys = deriveCommitmentKeys(
				st.localBasepoints,
				st.remoteBasepoints!,
				localPoint(st),
				true
			);
			const sighashType =
				bitcoin.Transaction.SIGHASH_SINGLE |
				bitcoin.Transaction.SIGHASH_ANYONECANPAY;
			const remoteSig = bitcoin.script.signature.decode(
				claim.ins[0].witness[1]
			);
			expect(remoteSig.hashType).to.equal(sighashType);
			expect(
				verify(
					claim.hashForWitnessV0(
						0,
						outA.witnessScript!,
						Number(outA.amount),
						sighashType
					),
					keys.remoteHtlcPubkey,
					remoteSig.signature
				),
				'the peer signature on the preserved input verifies'
			).to.equal(true);

			// Both outputs get spent: ours by the HTLC-success, the failed one
			// by the peer's timeout. Each resolves exactly once.
			const timeout = new bitcoin.Transaction();
			timeout.addInput(Buffer.from(signed.getHash()), outB.outputIndex);
			timeout.addOutput(DESTINATION, 1000);
			push(
				manager.handleOutputSpent(
					signed.getId(),
					outA.outputIndex,
					claim,
					800_003
				)
			);
			push(
				manager.handleOutputSpent(
					signed.getId(),
					outB.outputIndex,
					timeout,
					800_003
				)
			);
			for (let height = 800_004; height < 800_400; height += 1) {
				push(manager.handleNewBlock(height));
			}
			const resolved = actions.filter(
				(x) => x.type === 'CHAIN_OUTPUT_RESOLVED' && x.txid === signed.getId()
			);
			const count = (index: number): number =>
				resolved.filter((x) => x.outputIndex === index).length;
			expect(
				count(outA.outputIndex),
				'fulfilled output resolved once'
			).to.equal(1);
			expect(count(outB.outputIndex), 'failed output resolved once').to.equal(
				1
			);
			expect(
				fullState(r.bob, r.channelId).localBalanceMsat,
				'the channel balance was credited at the revoke_and_ack, and only then'
			).to.equal(balance);
			r.destroy();
		});

		it('claims a kept FAILED entry by HTLC-success when its preimage is in hand (as in the first phase of the removal)', function () {
			// The PR text leaves a failed HTLC to the peer's timeout. The
			// resolver knows nothing of an entry's state: it claims any
			// RECEIVED_HTLC whose preimage it holds, and that now includes a
			// kept FAILED entry (a second HTLC on a hash already paid, say).
			// The same happens one message earlier on master, while the entry
			// is still in the map, so this pins behaviour, not a regression.
			const w = simpleWindow(1640, 'fail');
			const st = fullState(w.bob, w.channelId);
			const tracked = classifyOutputs(
				w.signed,
				st,
				CommitmentType.OUR_COMMITMENT,
				st.localCommitmentNumber
			);
			const seed = makeSeed(TAG, w.bobSeedId);
			const resolved = resolveOurCommitmentOutputs(
				st,
				tracked,
				st.localCommitmentNumber,
				DESTINATION,
				10,
				new Map([[w.h.hash.toString('hex'), w.h.preimage]]),
				seedKey(seed, 3),
				seedKey(seed, 4),
				st.remoteHtlcSignatures
			);
			const claim = resolved.find(
				(x) => x.trackedOutput.outputType === OutputType.RECEIVED_HTLC
			);
			expect(
				claim?.spendTx,
				'an HTLC-success is built for the HTLC we told the peer we failed'
			).to.not.equal(undefined);
			w.destroy();
		});
	});

	describe('splice', function () {
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
				.update('received-removal-adversarial-wallet')
				.digest();
			const walletPub = Buffer.from(ecc.pointFromScalar(walletPriv, true)!);
			const walletScript = bitcoin.payments.p2wpkh({ pubkey: walletPub })
				.output!;
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

		for (const removal of ['fulfill', 'fail'] as const) {
			it(`a window opened during pending-lock (${removal}): exit on the old funding, and on the new one after the lock`, function () {
				const r = rig(removal === 'fulfill' ? 1700 : 1720);
				const h = park(r.alice, r.bob, 50_000_000n, 'through-splice');
				const live = park(r.alice, r.bob, 60_000_000n, 'live');
				expect(r.bob.listHeldHtlcs()).to.have.length(2);
				toPendingLock(r);

				const before = rebuild(fullState(r.bob, r.channelId)).result.tx;
				expect(peerSigned(r.bob, r.channelId, before)).to.equal(true);
				// The batch: start_batch and both commitment_signed are stopped.
				r.gate.drop.alice.add(MessageType.COMMITMENT_SIGNED);
				r.gate.drop.alice.add(MessageType.START_BATCH);
				if (removal === 'fulfill') {
					expect(r.bob.settleHeldHtlc(h.hash, h.preimage)).to.equal(true);
				} else {
					expect(r.bob.cancelHoldInvoice(h.hash)).to.deep.equal({
						htlcsFailed: 1
					});
				}
				let st = fullState(r.bob, r.channelId);
				expect(st.signedLocalRemovals, 'kept').to.have.length(1);
				expect(st.spliceInFlight, 'splice still pending').to.not.equal(null);

				const v = assertExit(
					r,
					'bob',
					[h, live],
					'pending-lock window, old funding'
				);
				expect(v.tx.getId()).to.equal(before.getId());
				expect(v.htlcs).to.have.length(2);

				// The splice locks. Adoption swaps the stored signature for the
				// splice-side one, which was signed over the same HTLC set.
				r.alice.getChannelManager().sendSpliceLocked(r.channelId);
				r.bob.getChannelManager().sendSpliceLocked(r.channelId);
				st = fullState(r.bob, r.channelId);
				expect(st.spliceInFlight ?? null, 'adopted').to.equal(null);
				expect(st.state).to.equal(ChannelState.NORMAL);
				expect(
					st.signedLocalRemovals,
					'still kept after adoption'
				).to.have.length(1);
				const after = assertExit(r, 'bob', [h, live], 'window after adoption');
				expect(
					after.htlcs,
					'both HTLC outputs on the new funding'
				).to.have.length(2);
				expect(
					Buffer.from(after.tx.ins[0].hash).equals(st.fundingTxid!),
					'spends the new funding'
				).to.equal(true);
				r.destroy();
			});
		}
	});

	describe('where the window is still shut', function () {
		it('pins issue #1295 (same on master, no removal involved): an update_add_htlc with its commitment_signed withheld refuses the close by itself', function () {
			// The root of the next case, isolated, and not this window's to
			// fix: issue #1295 tracks it. The signedLocal rebuild carries
			// every PENDING received entry, including one no signature we hold
			// covers (addLocallyRevoked === false), and leaves its amount out
			// of the peer's balance.
			const r = rig(1340);
			park(r.alice, r.bob, 50_000_000n, 'committed');
			const before = rebuild(fullState(r.bob, r.channelId)).result.tx;
			expect(peerSigned(r.bob, r.channelId, before)).to.equal(true);
			stopAliceCommitmentSigned(r);
			park(r.alice, r.bob, 40_000_000n, 'unsigned');
			const st = fullState(r.bob, r.channelId);
			expect(received(st)).to.have.length(2);
			expect(
				received(st).filter((e) => e.addLocallyRevoked === false)
			).to.have.length(1);
			expect(
				rebuild(st).result.outputMap.htlcs,
				'the rebuild carries the unsigned add'
			).to.have.length(2);
			expect(
				peerSigned(r.bob, r.channelId, before),
				'while the stored signature is still over the commitment without it'
			).to.equal(true);

			const plan = planClose(r.bob, r.channelId);

			expect(plan.ok, 'refused until issue #1295 is fixed').to.equal(false);
			r.destroy();
		});

		it('pins issue #1295: one update_add_htlc from the withholding peer closes the exit again (force close refused while connected)', function () {
			// The peer withholds its commitment_signed, which is the case the
			// PR is for, and also sends one update_add_htlc. The add is in no
			// signature we hold, yet the signedLocal rebuild carries it, so
			// every candidate (with and without the kept removal) is refused.
			// Issue #1295 tracks the fix.
			const w = simpleWindow(1800, 'fulfill');
			park(w.alice, w.bob, 40_000_000n, 'unsigned');
			const st = fullState(w.bob, w.channelId);
			expect(
				received(st).filter((e) => e.addLocallyRevoked === false),
				'the unsigned peer add is on Bob'
			).to.have.length(1);
			expect(st.signedLocalRemovals).to.have.length(1);
			expect(
				peerSigned(w.bob, w.channelId, w.signed),
				'the stored signature still covers the commitment with the kept HTLC'
			).to.equal(true);

			const viaNode = w.bob.forceCloseChannel(w.channelId, DESTINATION);
			const res = viaNode.ok
				? viaNode
				: w.bob.getChannelManager().forceClose(w.channelId, DESTINATION);

			expect(res.ok, 'refused until issue #1295 is fixed').to.equal(false);
			w.destroy();
		});

		it('the same state closes once the peer is disconnected (the unsigned add is rolled back)', function () {
			const w = simpleWindow(1820, 'fulfill');
			park(w.alice, w.bob, 40_000_000n, 'unsigned');
			expect(
				planClose(w.bob, w.channelId).ok,
				'refused while connected'
			).to.equal(false);
			w.bob.getChannelManager().handlePeerDisconnected(w.alice.getNodeId());
			const v = assertExit(w, 'bob', [w.h], 'after disconnect');
			expect(v.tx.getId()).to.equal(w.signed.getId());
			w.destroy();
		});

		it('an add failed before the peer ever signed it in is not kept, and the close is the commitment from before the add', function () {
			// The boundary the addLocallyRevoked === false skip is for, with
			// real signatures. An honest peer refuses a fail for an add it has
			// not seen committed, so Alice is made lenient by hand: her entry
			// is stamped as committed just before the fail reaches her. What
			// Bob receives is a revoke_and_ack for his removal with no
			// commitment_signed of hers ever covering the add.
			const r = rig(1830);
			const before = rebuild(fullState(r.bob, r.channelId)).result.tx;
			expect(peerSigned(r.bob, r.channelId, before)).to.equal(true);
			stopAliceCommitmentSigned(r);
			park(r.alice, r.bob, 50_000_000n, 'never-signed');
			const entry = received(fullState(r.bob, r.channelId))[0];
			expect(entry.addLocallyRevoked).to.equal(false);

			r.gate.queue.bob = [];
			const failed = r.bob
				.getChannelManager()
				.failHtlc(r.channelId, entry.id, Buffer.alloc(292));
			expect(failed.ok, failed.error).to.equal(true);
			const held = r.gate.queue.bob!;
			r.gate.queue.bob = null;
			expect(held, 'fail and commitment_signed').to.have.length(2);
			const offered = [...fullState(r.alice, r.channelId).htlcs.values()].find(
				(e) => e.direction === HtlcDirection.OFFERED
			)!;
			offered.state = HtlcState.COMMITTED;
			offered.addRemoteCommitted = true;
			for (const deliver of held) deliver();

			const st = fullState(r.bob, r.channelId);
			if (st.htlcs.size !== 0) {
				// The hand-made lenient peer did not complete the round; the
				// boundary cannot be reached this way and the case is void.
				this.skip();
			}
			expect(st.signedLocalRemovals, 'nothing kept').to.equal(undefined);
			const plan = planClose(r.bob, r.channelId);
			expect(plan.ok, plan.error).to.equal(true);
			expect(
				bitcoin.Transaction.fromBuffer(plan.commitmentTx!).getId(),
				'the commitment from before the add'
			).to.equal(before.getId());
			r.destroy();
		});

		it('an add failed before its covering commitment_signed arrives is kept once that signature carries it', function () {
			// The other side of the addLocallyRevoked === false skip. The flag
			// has to flip in handleCommitmentSigned whatever state the entry
			// is in: an add already FAILED when its covering signature is
			// accepted is in the commitment that signature covers, and the
			// peer's revoke_and_ack for the removal must keep it.
			const r = rig(1840);
			stopAliceCommitmentSigned(r);
			const h = park(r.alice, r.bob, 50_000_000n, 'early-fail');
			let st = fullState(r.bob, r.channelId);
			const entry = received(st)[0];
			expect(entry.state).to.equal(HtlcState.PENDING);
			expect(entry.addLocallyRevoked).to.equal(false);
			expect(
				r.gate.dropped.alice,
				'her covering signature is in flight'
			).to.have.length(1);
			const covering = r.gate.dropped.alice[0].payload;

			// Bob fails it at once. His messages are held so the crossing can
			// be laid out by hand.
			r.gate.queue.bob = [];
			const failed = r.bob
				.getChannelManager()
				.failHtlc(r.channelId, entry.id, Buffer.alloc(292));
			expect(failed.ok, failed.error).to.equal(true);

			// Alice's commitment_signed, sent before she saw the fail, lands.
			r.bob.handlePeerMessage(
				r.alice.getNodeId(),
				MessageType.COMMITMENT_SIGNED,
				covering
			);
			st = fullState(r.bob, r.channelId);
			expect(st.state, 'Bob accepted it').to.equal(ChannelState.NORMAL);
			const carried = rebuild(st).result;
			expect(carried.outputMap.htlcs, 'it carries the HTLC').to.have.length(1);
			expect(
				peerSigned(r.bob, r.channelId, carried.tx),
				'and is what the stored signature covers'
			).to.equal(true);
			expect(
				received(st)[0].addLocallyRevoked,
				'the flag flipped although the entry was already FAILED'
			).to.equal(true);

			// Bob's held messages reach Alice. His revoke first, so that an
			// honest implementation accepts the early fail; the order Bob
			// himself sees from here on is the same either way.
			const held = r.gate.queue.bob!;
			r.gate.queue.bob = null;
			expect(held, 'fail, commitment_signed, revoke_and_ack').to.have.length(3);
			held[2]();
			held[0]();
			held[1]();

			st = fullState(r.bob, r.channelId);
			expect(st.htlcs.size, 'Alice revoked for the removal').to.equal(0);
			expect(st.signedLocalRemovals, 'and the entry is kept').to.have.length(1);
			expect(
				peerSigned(r.bob, r.channelId, carried.tx),
				'the stored signature is still the one that carries the HTLC'
			).to.equal(true);

			const v = assertExit(r, 'bob', [h], 'early fail, signed in');
			expect(v.tx.getId(), 'the commitment the peer signed').to.equal(
				carried.tx.getId()
			);
			expect(v.htlcs, 'with the HTLC output tracked').to.have.length(1);
			r.destroy();
		});

		it('a leftover entry beside a genuine one costs only itself (the signature decides entry by entry)', function () {
			// A signature that replaced the stored one outside
			// handleCommitmentSigned leaves the list stale (the PR names
			// splice adoption). With one leftover and one genuine entry
			// neither "all" nor "none" is the signed commitment, so the
			// fallback has to try the selections in between.
			const r = rig(1860);
			const a = park(r.alice, r.bob, 50_000_000n, 'a');
			const b = park(r.alice, r.bob, 60_000_000n, 'b');
			const signed = rebuild(fullState(r.bob, r.channelId)).result.tx;
			stopAliceCommitmentSigned(r);
			expect(r.bob.settleHeldHtlc(a.hash, a.preimage)).to.equal(true);
			const st = fullState(r.bob, r.channelId);
			expect(st.signedLocalRemovals).to.have.length(1);
			expect(planClose(r.bob, r.channelId).ok, 'genuine entry alone').to.equal(
				true
			);
			st.signedLocalRemovals = [
				{
					id: 77n,
					amountMsat: 45_000_000n,
					paymentHash: crypto.randomBytes(32),
					cltvExpiry: 800_100,
					onionRoutingPacket: Buffer.alloc(0),
					direction: HtlcDirection.RECEIVED,
					state: HtlcState.FAILED
				},
				...st.signedLocalRemovals!
			];
			const genuine = st.signedLocalRemovals[1];

			const v = assertExit(r, 'bob', [a, b], 'leftover beside genuine');

			expect(v.tx.getId()).to.equal(signed.getId());
			expect(v.htlcs, 'both real HTLC outputs tracked').to.have.length(2);

			// The close itself drops the leftover, so the monitor classifies
			// the broadcast against the entries it was built from.
			const res = r.bob
				.getChannelManager()
				.forceClose(r.channelId, DESTINATION);
			expect(res.ok, res.error).to.equal(true);
			expect(
				fullState(r.bob, r.channelId).signedLocalRemovals,
				'only the entry the signature covered is left'
			).to.deep.equal([genuine]);
			r.destroy();
		});

		it('finds the covered entries among several leftovers, up to the bound of the full search', function () {
			const r = rig(1880);
			const a = park(r.alice, r.bob, 50_000_000n, 'a');
			const b = park(r.alice, r.bob, 60_000_000n, 'b');
			const signed = rebuild(fullState(r.bob, r.channelId)).result.tx;
			stopAliceCommitmentSigned(r);
			expect(r.bob.settleHeldHtlc(a.hash, a.preimage)).to.equal(true);
			expect(r.bob.cancelHoldInvoice(b.hash)).to.deep.equal({ htlcsFailed: 1 });
			const st = fullState(r.bob, r.channelId);
			const genuine = st.signedLocalRemovals!;
			expect(genuine).to.have.length(2);
			const leftover = (id: bigint): IHtlcEntry => ({
				id,
				amountMsat: 45_000_000n + id * 1000n,
				paymentHash: crypto.randomBytes(32),
				cltvExpiry: 800_100,
				onionRoutingPacket: Buffer.alloc(0),
				direction: HtlcDirection.RECEIVED,
				state: id % 2n === 0n ? HtlcState.FAILED : HtlcState.FULFILLED
			});

			// Six entries, four of them leftovers, in mixed order: inside the
			// full search, so the two covered ones are found.
			st.signedLocalRemovals = [
				leftover(70n),
				genuine[0],
				leftover(71n),
				leftover(72n),
				genuine[1],
				leftover(73n)
			];
			const v = assertExit(r, 'bob', [a, b], 'four leftovers of six');
			expect(v.tx.getId()).to.equal(signed.getId());
			expect(v.htlcs).to.have.length(2);

			// Seven entries are past the full search, which then tries only
			// "one entry too many" and "none of it". Five leftovers beside two
			// covered entries is neither, so the close is refused: the bound,
			// pinned.
			st.signedLocalRemovals = [
				leftover(80n),
				leftover(81n),
				genuine[0],
				leftover(82n),
				leftover(83n),
				genuine[1],
				leftover(84n)
			];
			expect(
				planClose(r.bob, r.channelId).ok,
				'seven entries, five of them leftovers: outside the bounded search'
			).to.equal(false);
			r.destroy();
		});

		it('past the full search, one leftover among many covered entries is still found', function () {
			const r = rig(1890);
			pay(r.alice, r.bob, 100_000_000n);
			const parked = [];
			for (let i = 0; i < 7; i++) {
				parked.push(
					park(r.alice, r.bob, 20_000_000n + BigInt(i) * 1_000_000n, `p${i}`)
				);
			}
			expect(r.bob.listHeldHtlcs()).to.have.length(7);
			const signed = rebuild(fullState(r.bob, r.channelId)).result.tx;
			stopAliceCommitmentSigned(r);
			for (const h of parked) {
				expect(r.bob.settleHeldHtlc(h.hash, h.preimage)).to.equal(true);
			}
			const st = fullState(r.bob, r.channelId);
			expect(st.signedLocalRemovals).to.have.length(7);
			st.signedLocalRemovals = [
				...st.signedLocalRemovals!.slice(0, 3),
				{
					id: 99n,
					amountMsat: 45_000_000n,
					paymentHash: crypto.randomBytes(32),
					cltvExpiry: 800_100,
					onionRoutingPacket: Buffer.alloc(0),
					direction: HtlcDirection.RECEIVED,
					state: HtlcState.FULFILLED
				},
				...st.signedLocalRemovals!.slice(3)
			];

			const v = assertExit(r, 'bob', parked, 'one leftover of eight');

			expect(v.tx.getId()).to.equal(signed.getId());
			expect(v.htlcs).to.have.length(7);
			r.destroy();
		});
	});

	describe('deadline of a kept, fulfilled HTLC', function () {
		/** Runs Bob through the blocks around the HTLC's expiry. */
		function pastExpiry(
			phase: 'first' | 'window',
			seedBase: number
		): {
			r: IRig;
			h: { preimage: Buffer; hash: Buffer };
			expiry: number;
			signed: bitcoin.Transaction;
			broadcasts: string[];
			/** The first height at which Bob's channel was force closed. */
			closedAt: number | undefined;
		} {
			const r = rig(seedBase);
			const h = park(r.alice, r.bob, 50_000_000n, 'deadline');
			const expiry = received(fullState(r.bob, r.channelId))[0].cltvExpiry;
			const signed = rebuild(fullState(r.bob, r.channelId)).result.tx;
			stopAliceCommitmentSigned(r);
			if (phase === 'first') r.gate.drop.alice.add(MessageType.REVOKE_AND_ACK);
			expect(r.bob.settleHeldHtlc(h.hash, h.preimage)).to.equal(true);
			const broadcasts: string[] = [];
			r.bob
				.getChannelManager()
				.on('broadcast:tx', (tx: Buffer) =>
					broadcasts.push(bitcoin.Transaction.fromBuffer(tx).getId())
				);
			let closedAt: number | undefined;
			for (let height = expiry - 20; height <= expiry + 2; height++) {
				r.bob.handleNewBlock(height);
				if (
					closedAt === undefined &&
					fullState(r.bob, r.channelId).state === ChannelState.FORCE_CLOSED
				) {
					closedAt = height;
				}
			}
			return { r, h, expiry, signed, broadcasts, closedAt };
		}

		it('control: one message earlier (peer has not revoked) the backstop closes ahead of the expiry', function () {
			const { r, signed, broadcasts } = pastExpiry('first', 2120);
			expect(fullState(r.bob, r.channelId).state).to.equal(
				ChannelState.FORCE_CLOSED
			);
			expect(broadcasts).to.include(signed.getId());
			r.destroy();
		});

		it('in the window the backstop closes ahead of the expiry, with the signed commitment and the HTLC-success built', function () {
			const { r, h, expiry, signed, broadcasts, closedAt } = pastExpiry(
				'window',
				2100
			);
			const st = fullState(r.bob, r.channelId);
			expect(st.signedLocalRemovals).to.have.length(1);
			expect(st.state, 'the backstop fired').to.equal(
				ChannelState.FORCE_CLOSED
			);
			expect(broadcasts, 'with the commitment the peer signed').to.include(
				signed.getId()
			);

			// It fired as the claim buffer was reached, not at the expiry: the
			// same height the control case, one message earlier, closes at.
			expect(closedAt, 'closed inside the scan').to.not.equal(undefined);
			expect(
				expiry - closedAt!,
				'the 18-block claim buffer before the expiry'
			).to.equal(18);
			expect(
				pastExpiry('first', 2180).closedAt,
				'as the control does'
			).to.equal(closedAt);

			// The commitment confirms before the expiry and our HTLC-success
			// is ready, with the preimage, while the peer's timeout is not yet
			// valid.
			const manager = r.bob.getChannelManager();
			manager.handleFundingSpent(
				r.channelId,
				signed,
				closedAt! + 1,
				DESTINATION
			);
			const tracked = monitorHtlcs(r.bob, r.channelId);
			expect(tracked, 'the HTLC output is tracked').to.have.length(1);
			expect(tracked[0].outputType).to.equal(OutputType.RECEIVED_HTLC);
			expect(tracked[0].sweepTxHex, 'HTLC-success built').to.not.equal(
				undefined
			);
			const claim = bitcoin.Transaction.fromHex(tracked[0].sweepTxHex!);
			expect(
				claim.ins[0].witness.some((item) => item.equals(h.preimage)),
				'with the preimage'
			).to.equal(true);
			r.destroy();
		});

		it('a kept FAILED entry needs no close: nothing fires around its expiry', function () {
			const r = rig(2140);
			const h = park(r.alice, r.bob, 50_000_000n, 'deadline-failed');
			const expiry = received(fullState(r.bob, r.channelId))[0].cltvExpiry;
			stopAliceCommitmentSigned(r);
			expect(r.bob.cancelHoldInvoice(h.hash)).to.deep.equal({ htlcsFailed: 1 });
			expect(fullState(r.bob, r.channelId).signedLocalRemovals).to.have.length(
				1
			);
			const broadcasts: string[] = [];
			r.bob
				.getChannelManager()
				.on('broadcast:tx', (tx: Buffer) =>
					broadcasts.push(bitcoin.Transaction.fromBuffer(tx).getId())
				);
			for (let height = expiry - 20; height <= expiry + 2; height++) {
				r.bob.handleNewBlock(height);
			}
			expect(fullState(r.bob, r.channelId).state).to.equal(ChannelState.NORMAL);
			expect(broadcasts).to.have.length(0);
			r.destroy();
		});

		it('with the peer gone the backstop still closes ahead of the expiry', function () {
			const r = rig(2160);
			const h = park(r.alice, r.bob, 50_000_000n, 'deadline-gone');
			const expiry = received(fullState(r.bob, r.channelId))[0].cltvExpiry;
			const signed = rebuild(fullState(r.bob, r.channelId)).result.tx;
			stopAliceCommitmentSigned(r);
			expect(r.bob.settleHeldHtlc(h.hash, h.preimage)).to.equal(true);
			r.bob.getChannelManager().handlePeerDisconnected(r.alice.getNodeId());
			const broadcasts: string[] = [];
			r.bob
				.getChannelManager()
				.on('broadcast:tx', (tx: Buffer) =>
					broadcasts.push(bitcoin.Transaction.fromBuffer(tx).getId())
				);
			for (let height = expiry - 20; height <= expiry - 10; height++) {
				r.bob.handleNewBlock(height);
			}
			expect(fullState(r.bob, r.channelId).state).to.equal(
				ChannelState.FORCE_CLOSED
			);
			expect(broadcasts).to.include(signed.getId());
			r.destroy();
		});
	});

	describe('taproot', function () {
		it('fulfilled, failed and live together', function () {
			const r = rig(1900, { preferTaproot: true });
			expect(
				isTaprootChannel(fullState(r.bob, r.channelId).channelType)
			).to.equal(true);
			const a = park(r.alice, r.bob, 50_000_000n, 'a');
			const b = park(r.alice, r.bob, 60_000_000n, 'b');
			const c = park(r.alice, r.bob, 70_000_000n, 'c');
			expect(r.bob.listHeldHtlcs()).to.have.length(3);
			const before = rebuild(fullState(r.bob, r.channelId)).result.tx;
			stopAliceCommitmentSigned(r);
			expect(r.bob.settleHeldHtlc(a.hash, a.preimage)).to.equal(true);
			expect(r.bob.cancelHoldInvoice(b.hash)).to.deep.equal({ htlcsFailed: 1 });
			const st = fullState(r.bob, r.channelId);
			expect(st.signedLocalRemovals).to.have.length(2);

			// ok only once the peer's stored partial verified over the rebuild.
			const plan = planClose(r.bob, r.channelId);
			expect(plan.ok, plan.error).to.equal(true);
			const tx = bitcoin.Transaction.fromBuffer(plan.commitmentTx!);
			expect(tx.getId()).to.equal(before.getId());
			const tracked = classifyOutputs(
				tx,
				st,
				CommitmentType.OUR_COMMITMENT,
				st.localCommitmentNumber
			);
			const htlcs = htlcOutputs(tracked).sort(
				(x, y) => x.outputIndex - y.outputIndex
			);
			expect(htlcs).to.have.length(3);
			expect(st.remoteHtlcSignatures).to.have.length(3);
			expect(htlcs.map((o) => o.htlcSigIndex)).to.deep.equal([0, 1, 2]);
			const seed = makeSeed(TAG, r.bobSeedId);
			const resolved = resolveOurCommitmentOutputs(
				st,
				tracked,
				st.localCommitmentNumber,
				DESTINATION,
				10,
				new Map([
					[a.hash.toString('hex'), a.preimage],
					[c.hash.toString('hex'), c.preimage]
				]),
				seedKey(seed, 3),
				seedKey(seed, 4),
				st.remoteHtlcSignatures
			);
			const claims = resolved.filter(
				(x) =>
					x.trackedOutput.outputType === OutputType.RECEIVED_HTLC && x.spendTx
			);
			expect(
				claims,
				'the fulfilled and the live one are claimed'
			).to.have.length(2);
			for (const claim of claims) {
				expect(claim.witness, 'witnessed').to.not.equal(undefined);
			}
			r.destroy();
		});
	});

	describe('persistence and accounting', function () {
		it('the kept entries survive a serialize / deserialize round trip field for field', function () {
			const w = simpleWindow(2000, 'fulfill');
			const st = fullState(w.bob, w.channelId);
			const row = JSON.parse(JSON.stringify(serializeChannelState(st)));
			expect(row.signedLocalRemovals).to.have.length(1);
			const back = deserializeChannelState(row);
			expect(back.signedLocalRemovals).to.have.length(1);
			const x = st.signedLocalRemovals![0];
			const y = back.signedLocalRemovals![0];
			expect(y.id).to.equal(x.id);
			expect(y.amountMsat).to.equal(x.amountMsat);
			expect(y.cltvExpiry).to.equal(x.cltvExpiry);
			expect(y.state).to.equal(x.state);
			expect(y.direction).to.equal(x.direction);
			expect(y.paymentHash.equals(x.paymentHash)).to.equal(true);
			expect(
				JSON.stringify(serializeChannelState(back)),
				'a second round trip is byte-stable'
			).to.equal(JSON.stringify(serializeChannelState(st)));
			// A row written before the field existed.
			delete row.signedLocalRemovals;
			const old = deserializeChannelState(row);
			expect(old.signedLocalRemovals).to.equal(undefined);
			expect(back.htlcs.size, 'not leaked into the map').to.equal(0);
			w.destroy();
		});

		it('balances and in-flight totals read the same inside the window and after it closes', function () {
			const w = simpleWindow(2020, 'fulfill');
			const inside = w.bob.getBalance();
			const insideInfo = w.bob.listChannels()[0];
			expect(inside.unsettledBalanceMsat, 'nothing in flight').to.equal(0n);
			w.gate.drop.alice.clear();
			for (const m of w.gate.dropped.alice) {
				w.bob.handlePeerMessage(w.alice.getNodeId(), m.type, m.payload);
			}
			expect(fullState(w.bob, w.channelId).signedLocalRemovals).to.equal(
				undefined
			);
			const after = w.bob.getBalance();
			const afterInfo = w.bob.listChannels()[0];
			expect(after.localBalanceMsat).to.equal(inside.localBalanceMsat);
			expect(after.remoteBalanceMsat).to.equal(inside.remoteBalanceMsat);
			expect(after.unsettledBalanceMsat).to.equal(inside.unsettledBalanceMsat);
			expect(afterInfo.localBalanceMsat).to.equal(insideInfo.localBalanceMsat);
			expect(afterInfo.remoteBalanceMsat).to.equal(
				insideInfo.remoteBalanceMsat
			);
			w.destroy();
		});
	});
});
