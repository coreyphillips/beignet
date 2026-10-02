/**
 * A received update_add_htlc whose covering commitment_signed has not arrived
 * (issue #1295).
 *
 * The peer adds an HTLC and, until its commitment_signed lands, the signature
 * we hold is still over the commitment from before the add: no output for it,
 * and its amount still on the peer's side. The force-close rebuild used to
 * carry every received entry in the map, the unsigned one included, so what
 * it built was not what the peer had signed and the close was refused for as
 * long as the connection stayed up and the peer withheld its signature.
 *
 * This is the fourth corner of one family. An offered add the peer has not
 * signed in (#643), an offered removal it has not signed away (#634) and a
 * received removal it has not signed away (#1291) were handled; a received
 * add it has not signed in was not.
 *
 * Every case drives real messages between two nodes and stops chosen ones.
 * A close counts only when the peer's STORED signature verifies over the
 * planned transaction, and an HTLC output counts only when the peer's STORED
 * second-level signature verifies over the transaction the resolver builds
 * for it.
 */

import { expect } from 'chai';
import fs from 'fs';
import os from 'os';
import path from 'path';
import * as bitcoin from 'bitcoinjs-lib';
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
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	buildGraph,
	createNode,
	makeExternalHash,
	makeSeed,
	openReadyChannel
} from './helpers/loopback-nodes';
import { seedKey } from './helpers/real-signing';

const TAG = 'received-add-window';
const DESTINATION = Buffer.from('0014' + '33'.repeat(20), 'hex');

type Side = 'alice' | 'bob';

interface IRig {
	alice: LightningNode;
	bob: LightningNode;
	seedIds: Record<Side, number>;
	channelId: Buffer;
	/** Message types from each side that are stopped, and what was stopped. */
	drop: Record<Side, Set<number>>;
	dropped: Record<Side, Array<{ type: number; payload: Buffer }>>;
	/** While set, every delivery from this side waits here, in order. */
	queue: Record<Side, Array<() => void> | null>;
	destroy: () => void;
}

function rig(
	seedBase: number,
	extra: Partial<INodeConfig> = {},
	bobStorage?: SqliteStorage
): IRig {
	const alice = createNode(TAG, seedBase, undefined, extra);
	const bob = createNode(TAG, seedBase + 1, bobStorage, extra);
	const r: IRig = {
		alice,
		bob,
		seedIds: { alice: seedBase, bob: seedBase + 1 },
		channelId: Buffer.alloc(0),
		drop: { alice: new Set(), bob: new Set() },
		dropped: { alice: [], bob: [] },
		queue: { alice: null, bob: null },
		destroy: (): void => {
			alice.destroy();
			bob.destroy();
		}
	};
	const route = (from: LightningNode, to: LightningNode, side: Side): void => {
		from.on('message:outbound', (pk: string, t: number, p: Buffer) => {
			if (pk !== to.getNodeId()) return;
			if (r.drop[side].has(t)) {
				r.dropped[side].push({ type: t, payload: p });
				return;
			}
			const deliver = (): void => to.handlePeerMessage(from.getNodeId(), t, p);
			const q = r.queue[side];
			if (q) q.push(deliver);
			else deliver();
		});
	};
	route(alice, bob, 'alice');
	route(bob, alice, 'bob');
	r.channelId = openReadyChannel(alice, bob);
	buildGraph(alice, bob, [r.channelId]);
	buildGraph(bob, alice, [r.channelId]);
	return r;
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

/** The commitment this state rebuilds for the stored signature. */
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

function received(st: IChannelState): IHtlcEntry[] {
	return [...st.htlcs.values()].filter(
		(e) => e.direction === HtlcDirection.RECEIVED
	);
}

function unsignedAdds(st: IChannelState): IHtlcEntry[] {
	return received(st).filter((e) => e.addLocallyRevoked === false);
}

/** Hold invoice on `payee`, paid by `payer`: the HTLC stays parked. */
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
	payer.sendPayment(
		payee.createInvoice({ amountMsat, description: 'prefund' }).bolt11
	);
}

function tempDb(prefix: string): string {
	return path.join(
		fs.mkdtempSync(path.join(os.tmpdir(), `beignet-${prefix}-`)),
		'node.db'
	);
}

interface IVerdict {
	tx: bitcoin.Transaction;
	htlcs: ITrackedOutput[];
}

/**
 * The full unilateral-exit check for `side` at this instant:
 *  - prepareForceClose answers ok,
 *  - the stored peer signature verifies over the planned transaction,
 *  - every stored second-level signature is paired with one tracked HTLC
 *    output and verifies over the second-level transaction the resolver
 *    builds for that output.
 */
function assertExit(r: IRig, side: Side, label: string): IVerdict {
	const node = r[side];
	const plan = planClose(node, r.channelId);
	expect(plan.ok, `${label}: ${plan.error}`).to.equal(true);
	const tx = bitcoin.Transaction.fromBuffer(plan.commitmentTx!);
	expect(
		peerSigned(node, r.channelId, tx),
		`${label}: stored signature covers the planned commitment`
	).to.equal(true);
	return { tx, htlcs: assertClassified(r, side, tx, label) };
}

/** The resolver half of assertExit, for a commitment already in hand. */
function assertClassified(
	r: IRig,
	side: Side,
	tx: bitcoin.Transaction,
	label: string
): ITrackedOutput[] {
	const st = fullState(r[side], r.channelId);
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

	const seed = makeSeed(TAG, r.seedIds[side]);
	// A preimage-shaped value for every received output, so the HTLC-success
	// is built and its stored signature can be checked. Signature validity
	// does not depend on the preimage bytes.
	const known = new Map(
		htlcs.map((o) => [o.paymentHash!.toString('hex'), Buffer.alloc(32, 7)])
	);
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
	const used = new Set<number>();
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
		expect(used.has(o.htlcSigIndex!), `${label}: sig index reused`).to.equal(
			false
		);
		used.add(o.htlcSigIndex!);
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
			`${label}: stored HTLC signature ${o.htlcSigIndex} verifies for output ${o.outputIndex}`
		).to.equal(true);
	}
	return htlcs;
}

interface IUnsigned extends IRig {
	/** The commitment Alice last signed for Bob, from before the unsigned add. */
	signed: bitcoin.Transaction;
	/** The HTLC that was fully committed first, when asked for. */
	committed?: { preimage: Buffer; hash: Buffer };
}

/**
 * Alice sends update_add_htlc and her commitment_signed is stopped: Bob holds
 * a PENDING received entry no signature of hers covers.
 */
function unsignedAdd(
	seedBase: number,
	opts: {
		extra?: Partial<INodeConfig>;
		committedFirst?: boolean;
		amountMsat?: bigint;
		bobStorage?: SqliteStorage;
	} = {}
): IUnsigned {
	const r = rig(seedBase, opts.extra, opts.bobStorage);
	const committed = opts.committedFirst
		? park(r.alice, r.bob, 50_000_000n, 'committed')
		: undefined;
	const before = fullState(r.bob, r.channelId);
	const signed = rebuild(before).result.tx;
	if (!isTaprootChannel(before.channelType)) {
		expect(
			peerSigned(r.bob, r.channelId, signed),
			'Alice signed the commitment from before the add'
		).to.equal(true);
	}
	const signature = Buffer.from(before.remoteCommitmentSignature!);
	const number = before.localCommitmentNumber;

	r.drop.alice.add(MessageType.COMMITMENT_SIGNED);
	park(r.alice, r.bob, opts.amountMsat ?? 40_000_000n, 'unsigned');

	// The window, pinned: the add is on Bob, flagged as covered by no
	// signature, and the commitment he holds has not moved.
	const st = fullState(r.bob, r.channelId);
	expect(unsignedAdds(st), 'the unsigned add is on Bob').to.have.length(1);
	expect(unsignedAdds(st)[0].state).to.equal(HtlcState.PENDING);
	expect(r.dropped.alice, 'her covering signature was stopped').to.have.length(
		1
	);
	expect(st.localCommitmentNumber).to.equal(number);
	expect(st.remoteCommitmentSignature!.equals(signature)).to.equal(true);
	expect(st.state).to.equal(ChannelState.NORMAL);
	return { ...r, signed, committed };
}

describe('A received add the peer has not signed into our commitment (issue #1295)', function () {
	this.timeout(20_000);

	it('force closes on the commitment from before the add, while connected', function () {
		const w = unsignedAdd(10);

		const v = assertExit(w, 'bob', 'unsigned add');

		expect(v.tx.getId(), 'the commitment the peer signed').to.equal(
			w.signed.getId()
		);
		expect(v.htlcs, 'which has no HTLC output').to.have.length(0);
		w.destroy();
	});

	it('the rebuild leaves the add out and its amount with the peer', function () {
		const w = unsignedAdd(20, { committedFirst: true });
		const st = fullState(w.bob, w.channelId);

		const built = rebuild(st).result;

		expect(built.outputMap.htlcs, 'only the signed-in HTLC').to.have.length(1);
		expect(built.tx.getId()).to.equal(w.signed.getId());
		// The commitment being VERIFIED is the next one, which does carry it.
		const next = buildLocalCommitment(
			st,
			perCommitmentPointFromSecret(
				generateFromSeed(
					st.localPerCommitmentSeed,
					MAX_INDEX - (st.localCommitmentNumber + 1n)
				)
			),
			st.localCommitmentNumber + 1n
		).result;
		expect(next.outputMap.htlcs, 'the next commitment has both').to.have.length(
			2
		);
		w.destroy();
	});

	it('closes through the manager and through the node, and broadcasts it', function () {
		for (const via of ['manager', 'node'] as const) {
			const w = unsignedAdd(via === 'manager' ? 30 : 40);
			const broadcasts: string[] = [];
			w.bob
				.getChannelManager()
				.on('broadcast:tx', (tx: Buffer) =>
					broadcasts.push(bitcoin.Transaction.fromBuffer(tx).getId())
				);

			const res =
				via === 'manager'
					? w.bob.getChannelManager().forceClose(w.channelId, DESTINATION)
					: w.bob.forceCloseChannel(w.channelId, DESTINATION);

			expect(res.ok, `${via}: ${res.error}`).to.equal(true);
			expect(fullState(w.bob, w.channelId).state).to.equal(
				ChannelState.FORCE_CLOSED
			);
			expect(broadcasts, `${via}: the signed commitment went out`).to.include(
				w.signed.getId()
			);
			w.destroy();
		}
	});

	it('still carries a received add that IS signed in, beside the one that is not', function () {
		const w = unsignedAdd(50, { committedFirst: true });

		const v = assertExit(w, 'bob', 'signed add beside unsigned add');

		expect(v.tx.getId()).to.equal(w.signed.getId());
		expect(v.htlcs, 'the signed-in HTLC keeps its output').to.have.length(1);
		expect(v.htlcs[0].paymentHash!.equals(w.committed!.hash)).to.equal(true);
		expect(v.htlcs[0].outputType).to.equal(OutputType.RECEIVED_HTLC);
		w.destroy();
	});

	it('carries the add from the moment its commitment_signed is accepted', function () {
		// Alice's signature lands, and Bob's own commitment_signed is the one
		// stopped: the round is half done, and the commitment Bob holds now
		// has the output.
		const r = rig(60);
		r.drop.bob.add(MessageType.COMMITMENT_SIGNED);
		const h = park(r.alice, r.bob, 40_000_000n, 'signed-in');
		const st = fullState(r.bob, r.channelId);
		expect(received(st)).to.have.length(1);
		expect(received(st)[0].addLocallyRevoked, 'signed in').to.equal(true);
		expect(r.dropped.bob, 'his own signature was stopped').to.have.length(1);

		const v = assertExit(r, 'bob', 'add signed in');

		expect(v.htlcs).to.have.length(1);
		expect(v.htlcs[0].paymentHash!.equals(h.hash)).to.equal(true);
		r.destroy();
	});

	it('an unsigned add below the dust limit changes nothing either', function () {
		const w = unsignedAdd(70, { committedFirst: true, amountMsat: 200_000n });

		const v = assertExit(w, 'bob', 'unsigned dust add');

		expect(v.tx.getId()).to.equal(w.signed.getId());
		expect(v.htlcs).to.have.length(1);
		w.destroy();
	});

	it('several unsigned adds, with fractional amounts, beside a signed one', function () {
		const w = unsignedAdd(80, {
			committedFirst: true,
			amountMsat: 40_000_999n
		});
		park(w.alice, w.bob, 30_000_001n, 'unsigned-2');
		park(w.alice, w.bob, 20_000_500n, 'unsigned-3');
		expect(unsignedAdds(fullState(w.bob, w.channelId))).to.have.length(3);

		const v = assertExit(w, 'bob', 'three unsigned adds');

		expect(v.tx.getId()).to.equal(w.signed.getId());
		expect(v.htlcs).to.have.length(1);
		w.destroy();
	});

	it('an unsigned add we already failed is absent as well', function () {
		// Nothing on the wire stops us failing an add before its covering
		// signature arrives. The entry is FAILED with its removal unacked,
		// which reads as "output still present" for a signed-in HTLC, and the
		// stored signature has never seen this one.
		const w = unsignedAdd(90, { committedFirst: true });
		const entry = unsignedAdds(fullState(w.bob, w.channelId))[0];
		w.queue.bob = [];
		const failed = w.bob
			.getChannelManager()
			.failHtlc(w.channelId, entry.id, Buffer.alloc(292));
		expect(failed.ok, failed.error).to.equal(true);
		const st = fullState(w.bob, w.channelId);
		expect(unsignedAdds(st)[0].state).to.equal(HtlcState.FAILED);

		const v = assertExit(w, 'bob', 'unsigned add, failed');

		expect(v.tx.getId()).to.equal(w.signed.getId());
		expect(v.htlcs).to.have.length(1);
		w.destroy();
	});

	it('mixed with a kept removal: the peer withholds its signature and adds an HTLC', function () {
		// The received-removal window (issue #1291) with one update_add_htlc
		// on top: the stored signature covers the removed HTLC and not the
		// new one.
		const r = rig(100);
		const kept = park(r.alice, r.bob, 50_000_000n, 'kept');
		const signed = rebuild(fullState(r.bob, r.channelId)).result.tx;
		r.drop.alice.add(MessageType.COMMITMENT_SIGNED);
		expect(r.bob.settleHeldHtlc(kept.hash, kept.preimage)).to.equal(true);
		park(r.alice, r.bob, 40_000_000n, 'unsigned');
		const st = fullState(r.bob, r.channelId);
		expect(st.signedLocalRemovals, 'the removal is kept').to.have.length(1);
		expect(unsignedAdds(st), 'the add is unsigned').to.have.length(1);

		const v = assertExit(r, 'bob', 'kept removal and unsigned add');

		expect(v.tx.getId()).to.equal(signed.getId());
		expect(v.htlcs, 'the kept HTLC output only').to.have.length(1);
		expect(v.htlcs[0].paymentHash!.equals(kept.hash)).to.equal(true);

		const res = r.bob.forceCloseChannel(r.channelId, DESTINATION);
		expect(res.ok, res.error).to.equal(true);
		r.destroy();
	});

	it('the opener receiving the unsigned add closes the same way', function () {
		// Roles swapped: Alice opened the channel and pays the fee, and Bob is
		// the one who adds and withholds.
		const r = rig(110);
		pay(r.alice, r.bob, 300_000_000n);
		park(r.bob, r.alice, 50_000_000n, 'committed');
		const signed = rebuild(fullState(r.alice, r.channelId)).result.tx;
		expect(peerSigned(r.alice, r.channelId, signed)).to.equal(true);
		r.drop.bob.add(MessageType.COMMITMENT_SIGNED);
		park(r.bob, r.alice, 40_000_000n, 'unsigned');
		expect(unsignedAdds(fullState(r.alice, r.channelId))).to.have.length(1);

		const v = assertExit(r, 'alice', 'opener, unsigned add');

		expect(v.tx.getId()).to.equal(signed.getId());
		expect(v.htlcs).to.have.length(1);
		r.destroy();
	});

	it('on a taproot channel', function () {
		const w = unsignedAdd(120, {
			extra: { preferTaproot: true },
			committedFirst: true
		});
		const st = fullState(w.bob, w.channelId);
		expect(isTaprootChannel(st.channelType)).to.equal(true);

		// ok only once the peer's stored partial verified over the rebuild.
		const plan = planClose(w.bob, w.channelId);

		expect(plan.ok, plan.error).to.equal(true);
		const tx = bitcoin.Transaction.fromBuffer(plan.commitmentTx!);
		expect(tx.getId()).to.equal(w.signed.getId());
		const htlcs = htlcOutputs(
			classifyOutputs(
				tx,
				st,
				CommitmentType.OUR_COMMITMENT,
				st.localCommitmentNumber
			)
		);
		expect(htlcs, 'the signed-in HTLC only').to.have.length(1);
		expect(st.remoteHtlcSignatures).to.have.length(1);
		expect(htlcs[0].htlcSigIndex).to.equal(0);
		w.destroy();
	});

	it('the stored row rebuilds the same commitment', function () {
		const w = unsignedAdd(130, { committedFirst: true });

		const restored = deserializeChannelState(
			JSON.parse(
				JSON.stringify(serializeChannelState(fullState(w.bob, w.channelId)))
			)
		);

		expect(unsignedAdds(restored), 'the flag is on disk').to.have.length(1);
		expect(rebuild(restored).result.tx.getId()).to.equal(w.signed.getId());
		w.destroy();
	});

	it('after a restart from disk the close is still the signed commitment', function () {
		// An update_add_htlc alone is not written to disk; the next persist
		// carries it. Here that is Bob settling the committed HTLC with the
		// peer's signature still withheld, which leaves a stored row holding
		// both the unsigned add and a kept removal.
		const dbPath = tempDb('received-add');
		const disk = new SqliteStorage(dbPath);
		disk.open();
		const w = unsignedAdd(140, { committedFirst: true, bobStorage: disk });
		expect(
			w.bob.settleHeldHtlc(w.committed!.hash, w.committed!.preimage)
		).to.equal(true);
		const row = disk.loadChannel(w.channelId.toString('hex'))!.state;
		expect(unsignedAdds(row), 'the unsigned add is on disk').to.have.length(1);
		expect(row.signedLocalRemovals, 'beside the kept removal').to.have.length(
			1
		);
		expect(
			rebuild(row).result.tx.getId(),
			'and the stored row rebuilds the signed commitment'
		).to.equal(w.signed.getId());
		w.bob.destroy();

		const disk2 = new SqliteStorage(dbPath);
		disk2.open();
		const restored = createNode(TAG, w.seedIds.bob, disk2);
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
		restored.destroy();
		w.alice.destroy();
	});

	it('classifies our own commitment: the signed HTLC is tracked, the unsigned one attributes nothing', function () {
		const w = unsignedAdd(150, { committedFirst: true });
		const st = fullState(w.bob, w.channelId);
		const unsigned = unsignedAdds(st)[0];

		const htlcs = assertClassified(w, 'bob', w.signed, 'signed commitment');

		expect(htlcs).to.have.length(1);
		expect(htlcs[0].htlcSigIndex).to.equal(0);
		expect(htlcs[0].paymentHash!.equals(w.committed!.hash)).to.equal(true);
		expect(
			htlcs.some((o) => o.htlcId === unsigned.id),
			'nothing is attributed to the unsigned add'
		).to.equal(false);
		w.destroy();
	});

	it('an unsigned twin of a signed HTLC does not take its output', function () {
		// A retry on the same hash, amount and expiry has a byte-identical
		// script. The one output in the signed commitment belongs to the
		// signed-in entry, whatever order the entries are met in.
		const w = unsignedAdd(160, { committedFirst: true });
		const st = fullState(w.bob, w.channelId);
		const signedIn = received(st).find((e) => e.addLocallyRevoked !== false)!;
		const unsigned = unsignedAdds(st)[0];
		// Make the unsigned entry the twin, and move it ahead of the signed one
		// in the map so that insertion order cannot be what decides.
		const twin: IHtlcEntry = {
			...unsigned,
			amountMsat: signedIn.amountMsat,
			paymentHash: signedIn.paymentHash,
			cltvExpiry: signedIn.cltvExpiry
		};
		const reordered = new Map<string, IHtlcEntry>();
		reordered.set(`received-${twin.id}`, twin);
		for (const [key, entry] of st.htlcs) {
			if (entry !== unsigned) reordered.set(key, entry);
		}
		const view = { ...st, htlcs: reordered } as IChannelState;

		const htlcs = htlcOutputs(
			classifyOutputs(
				w.signed,
				view,
				CommitmentType.OUR_COMMITMENT,
				view.localCommitmentNumber
			)
		);

		expect(htlcs).to.have.length(1);
		expect(
			htlcs[0].htlcId,
			'attributed to the signed-in entry, not the unsigned twin'
		).to.equal(signedIn.id);
		w.destroy();
	});

	it('lets the signature overrule the flag: an add wrongly read as unsigned is still carried', function () {
		// The flag is a reading of our own records and the stored signature is
		// the fact. A signed-in add whose flag says otherwise must not cost
		// the exit: the close falls back to the rebuild that carries it.
		const r = rig(170);
		const h = park(r.alice, r.bob, 50_000_000n, 'signed-in');
		const st = fullState(r.bob, r.channelId);
		const signed = rebuild(st).result.tx;
		expect(peerSigned(r.bob, r.channelId, signed)).to.equal(true);
		received(st)[0].addLocallyRevoked = false;
		expect(
			rebuild(st).result.tx.getId(),
			'the first rebuild now leaves it out'
		).to.not.equal(signed.getId());

		const plan = planClose(r.bob, r.channelId);

		expect(plan.ok, plan.error).to.equal(true);
		const tx = bitcoin.Transaction.fromBuffer(plan.commitmentTx!);
		expect(tx.getId()).to.equal(signed.getId());
		expect(peerSigned(r.bob, r.channelId, tx)).to.equal(true);
		const htlcs = assertClassified(r, 'bob', tx, 'flag overruled');
		expect(htlcs).to.have.length(1);
		expect(htlcs[0].paymentHash!.equals(h.hash)).to.equal(true);
		r.destroy();
	});

	it('the window closing: the withheld signature arrives and the add is carried', function () {
		const w = unsignedAdd(180);
		w.drop.alice.clear();
		for (const m of w.dropped.alice) {
			w.bob.handlePeerMessage(w.alice.getNodeId(), m.type, m.payload);
		}
		const st = fullState(w.bob, w.channelId);
		expect(unsignedAdds(st), 'signed in now').to.have.length(0);

		const v = assertExit(w, 'bob', 'after the signature');

		expect(v.tx.getId()).to.not.equal(w.signed.getId());
		expect(v.htlcs).to.have.length(1);
		w.destroy();
	});

	it('a disconnect rolls the unsigned add back and the close is unchanged', function () {
		const w = unsignedAdd(190, { committedFirst: true });
		w.bob.getChannelManager().handlePeerDisconnected(w.alice.getNodeId());
		expect(
			unsignedAdds(fullState(w.bob, w.channelId)),
			'rolled back'
		).to.have.length(0);

		const v = assertExit(w, 'bob', 'after disconnect');

		expect(v.tx.getId()).to.equal(w.signed.getId());
		expect(v.htlcs).to.have.length(1);
		w.destroy();
	});
});
