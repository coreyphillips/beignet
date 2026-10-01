/**
 * A received HTLC we removed, between the peer's revoke_and_ack and its next
 * commitment_signed.
 *
 * We fulfill (or fail) an HTLC the peer offered and sign the peer's
 * commitment without it. The peer's revoke_and_ack makes that removal
 * irrevocable on ITS commitment, and the balance moves. The commitment WE
 * hold is a different matter: the peer's stored signature is still over the
 * one that carries the HTLC output, and stays so until its next
 * commitment_signed arrives. A peer that goes quiet at that point leaves us
 * holding exactly that commitment, and it is the only transaction we can put
 * on chain.
 *
 * So inside the window three things have to hold:
 *  - a force close is possible at all,
 *  - what it broadcasts is the commitment the peer signed, HTLC output and
 *    all, and
 *  - the output is recognised on chain: claimed by HTLC-success with the
 *    preimage and the peer's stored HTLC signature when we fulfilled, and left
 *    to the peer's timeout when we failed.
 *
 * The fixture drives real messages between two nodes and stops the peer's
 * commitment_signed, so the window is the one the wire produces.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import { LightningNode } from '../../src/lightning/node/lightning-node';
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

const TAG = 'received-removal-window';
const HTLC_MSAT = 50_000_000n;
const HTLC_SATS = HTLC_MSAT / 1000n;
/** A second HTLC left live, larger so the removed one's output sorts first. */
const LIVE_MSAT = 60_000_000n;
const DESTINATION = Buffer.from('0014' + '11'.repeat(20), 'hex');

interface IFilter {
	allow: (from: string, type: number) => boolean;
	/** While set, deliveries wait here: a reconnect holds its replies back. */
	held?: Array<() => void>;
}

/** connectNodes with a gate, so a message can be withheld mid-round. */
function wire(a: LightningNode, b: LightningNode, filter: IFilter): void {
	const route = (from: LightningNode, to: LightningNode): void => {
		from.on('message:outbound', (pk: string, t: number, p: Buffer) => {
			if (pk !== to.getNodeId()) return;
			if (!filter.allow(from.getNodeId(), t)) return;
			const deliver = (): void => to.handlePeerMessage(from.getNodeId(), t, p);
			if (filter.held) filter.held.push(deliver);
			else deliver();
		});
	};
	route(a, b);
	route(b, a);
}

function fullState(node: LightningNode, channelId: Buffer): IChannelState {
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	return (node.getChannelManager().getChannel(channelId) as any).getFullState();
}

/** prepareForceClose, which plans the close without moving the channel. */
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

function outputsOf(tx: bitcoin.Transaction): string[] {
	return tx.outs.map((o) => `${o.value}:${o.script.toString('hex')}`);
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

interface IWindow {
	/** S: offered the HTLC, revoked for our removal, and went quiet. */
	alice: LightningNode;
	/** R: received the HTLC and removed it. */
	bob: LightningNode;
	bobSeedId: number;
	channelId: Buffer;
	preimage: Buffer;
	hash: Buffer;
	/** The HTLC left parked beside the removed one, when asked for. */
	live?: { preimage: Buffer; hash: Buffer };
	/**
	 * The commitment Alice last signed for Bob, as Bob would have broadcast it
	 * while the HTLC was simply committed. Nothing Alice signs reaches Bob
	 * after this, so in the window it is still the one her signature covers.
	 */
	signed: bitcoin.Transaction;
	/** Alice's commitment_signed messages the gate held back, in order. */
	withheld: Buffer[];
	/** Lets Alice's commitment_signed through again and delivers the held ones. */
	release: () => void;
	/**
	 * Drops the connection and brings it back with nothing withheld. Both
	 * channel_reestablish messages land before any reply, as on a real socket.
	 */
	reconnect: () => void;
	destroy: () => void;
}

/**
 * Bob parks Alice's HTLC on a hold invoice, then settles or cancels it with
 * Alice's commitment_signed stopped: his removal round runs up to and
 * including her revoke_and_ack, and no further.
 */
function removalWindow(
	seedBase: number,
	removal: 'fulfill' | 'fail',
	opts: { taproot?: boolean; liveBeside?: boolean } = {}
): IWindow {
	const extra = opts.taproot ? { preferTaproot: true } : {};
	const alice = createNode(TAG, seedBase, undefined, extra);
	const bob = createNode(TAG, seedBase + 1, undefined, extra);
	const filter: IFilter = { allow: () => true };
	wire(alice, bob, filter);
	const channelId = openReadyChannel(alice, bob);
	buildGraph(alice, bob, [channelId]);
	expect(
		isTaprootChannel(fullState(bob, channelId).channelType),
		'the channel type the test asked for'
	).to.equal(opts.taproot === true);

	const { preimage, hash } = makeExternalHash();
	const invoice = bob.createInvoice({
		amountMsat: HTLC_MSAT,
		description: 'received-removal-window',
		hold: true,
		paymentHash: hash
	});
	alice.sendPayment(invoice.bolt11);
	expect(bob.listHeldHtlcs(), 'the HTLC is parked on Bob').to.have.length(1);

	let live: { preimage: Buffer; hash: Buffer } | undefined;
	if (opts.liveBeside) {
		live = makeExternalHash();
		const second = bob.createInvoice({
			amountMsat: LIVE_MSAT,
			description: 'received-removal-window-live',
			hold: true,
			paymentHash: live.hash
		});
		alice.sendPayment(second.bolt11);
		expect(bob.listHeldHtlcs(), 'and so is the second').to.have.length(2);
	}

	// The add round is complete: Alice's signature covers a commitment of
	// Bob's that carries the HTLC. Built before any removal and checked
	// against her signature, so it does not lean on the window handling
	// under test.
	const before = fullState(bob, channelId);
	const builtBefore = rebuild(before);
	const signed = builtBefore.result.tx;
	expect(
		builtBefore.result.outputMap.htlcs,
		'the signed commitment carries every parked HTLC'
	).to.have.length(opts.liveBeside ? 2 : 1);
	expect(
		signed.outs.some((o) => BigInt(o.value) === HTLC_SATS),
		'the one about to be removed among them'
	).to.equal(true);
	if (!opts.taproot) {
		expect(
			peerSigned(bob, channelId, signed),
			'Alice signed the commitment that carries the HTLC'
		).to.equal(true);
	}
	const numberBefore = before.localCommitmentNumber;
	const signatureBefore = Buffer.from(before.remoteCommitmentSignature!);
	const revokedBefore = before.remoteRevocationNumber ?? 0n;

	const aliceId = alice.getNodeId();
	const withheld: Buffer[] = [];
	let stalled = true;
	const seen: number[] = [];
	alice.on('message:outbound', (pk: string, t: number, p: Buffer) => {
		if (pk !== bob.getNodeId()) return;
		if (stalled && t === MessageType.COMMITMENT_SIGNED) withheld.push(p);
	});
	filter.allow = (from: string, type: number): boolean => {
		if (from !== aliceId) return true;
		if (stalled && type === MessageType.COMMITMENT_SIGNED) return false;
		seen.push(type);
		return true;
	};

	if (removal === 'fulfill') {
		expect(bob.settleHeldHtlc(hash, preimage), 'Bob fulfills').to.equal(true);
	} else {
		expect(bob.cancelHoldInvoice(hash), 'Bob fails').to.deep.equal({
			htlcsFailed: 1
		});
	}

	// The window, pinned from both ends. Alice's revoke_and_ack for Bob's
	// removal commitment reached Bob...
	const st = fullState(bob, channelId);
	expect(seen, 'Alice revoked for the removal').to.include(
		MessageType.REVOKE_AND_ACK
	);
	expect(st.remoteRevocationNumber, 'Bob processed that revoke').to.equal(
		revokedBefore + 1n
	);
	// ...and the commitment_signed she owes him for it did not.
	expect(withheld, 'Alice signed and the gate held it').to.have.length(1);
	expect(st.localCommitmentNumber, 'Bob holds the same commitment').to.equal(
		numberBefore
	);
	expect(
		st.remoteCommitmentSignature!.equals(signatureBefore),
		'under the same signature'
	).to.equal(true);
	expect(st.state).to.equal(ChannelState.NORMAL);

	return {
		alice,
		bob,
		bobSeedId: seedBase + 1,
		channelId,
		preimage,
		hash,
		live,
		signed,
		withheld,
		release: (): void => {
			stalled = false;
			for (const payload of withheld) {
				bob.handlePeerMessage(aliceId, MessageType.COMMITMENT_SIGNED, payload);
			}
		},
		reconnect: (): void => {
			stalled = false;
			const aliceManager = alice.getChannelManager();
			const bobManager = bob.getChannelManager();
			aliceManager.handlePeerDisconnected(bob.getNodeId());
			bobManager.handlePeerDisconnected(aliceId);
			const held: Array<() => void> = [];
			filter.held = held;
			aliceManager.handlePeerReconnected(bob.getNodeId());
			bobManager.handlePeerReconnected(aliceId);
			filter.held = undefined;
			for (const deliver of held) deliver();
		},
		destroy: (): void => {
			alice.destroy();
			bob.destroy();
		}
	};
}

/** The planned force-close commitment, which must exist. */
function plannedCommitment(w: IWindow): bitcoin.Transaction {
	const plan = planClose(w.bob, w.channelId);
	expect(plan.ok, plan.error).to.equal(true);
	return bitcoin.Transaction.fromBuffer(plan.commitmentTx!);
}

/** Bob's own classification and claims for his commitment once it confirms. */
function resolveOnBob(
	w: IWindow,
	tx: bitcoin.Transaction,
	preimages: Map<string, Buffer>
): {
	tracked: ITrackedOutput[];
	resolved: ReturnType<typeof resolveOurCommitmentOutputs>;
} {
	const st = fullState(w.bob, w.channelId);
	const tracked = classifyOutputs(
		tx,
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
		preimages,
		seedKey(seed, 3),
		seedKey(seed, 4),
		st.remoteHtlcSignatures
	);
	return { tracked, resolved };
}

describe('A received HTLC removed, before the peer signs our commitment without it', function () {
	this.timeout(20_000);

	for (const removal of ['fulfill', 'fail'] as const) {
		const seedOffset = removal === 'fulfill' ? 0 : 100;

		it(`force closes on the commitment the peer signed (${removal})`, function () {
			const w = removalWindow(10 + seedOffset, removal);

			const tx = plannedCommitment(w);

			expect(
				outputsOf(tx),
				'the same outputs as the commitment the peer signed'
			).to.deep.equal(outputsOf(w.signed));
			expect(tx.getId(), 'and the same transaction').to.equal(w.signed.getId());
			expect(
				tx.outs.some((o) => BigInt(o.value) === HTLC_SATS),
				'the HTLC output is still in it'
			).to.equal(true);
			expect(
				peerSigned(w.bob, w.channelId, tx),
				'the stored remote signature covers what we broadcast'
			).to.equal(true);
			w.destroy();
		});

		it(`force closes through the manager and broadcasts it (${removal})`, function () {
			const w = removalWindow(20 + seedOffset, removal);
			const broadcasts: Buffer[] = [];
			w.bob
				.getChannelManager()
				.on('broadcast:tx', (tx: Buffer) => broadcasts.push(tx));

			const result = w.bob
				.getChannelManager()
				.forceClose(w.channelId, DESTINATION);

			expect(result.ok, result.error).to.equal(true);
			expect(fullState(w.bob, w.channelId).state).to.equal(
				ChannelState.FORCE_CLOSED
			);
			const ids = broadcasts.map((b) =>
				bitcoin.Transaction.fromBuffer(b).getId()
			);
			expect(ids, 'the signed commitment went out').to.include(
				w.signed.getId()
			);
			w.destroy();
		});

		it(`rebuilds the same commitment after a restart (${removal})`, function () {
			const w = removalWindow(30 + seedOffset, removal);

			const restored = deserializeChannelState(
				JSON.parse(
					JSON.stringify(serializeChannelState(fullState(w.bob, w.channelId)))
				)
			);

			expect(
				rebuild(restored).result.tx.getId(),
				'the stored row rebuilds it too'
			).to.equal(w.signed.getId());

			// Outside the window the row carries nothing new.
			w.release();
			expect(
				JSON.parse(
					JSON.stringify(serializeChannelState(fullState(w.bob, w.channelId)))
				)
			).to.not.have.property('signedLocalRemovals');
			w.destroy();
		});

		it(`drops the output once the peer signs it away (${removal})`, function () {
			const w = removalWindow(40 + seedOffset, removal);

			w.release();

			const st = fullState(w.bob, w.channelId);
			expect(st.htlcs.size, 'nothing is left of the HTLC').to.equal(0);
			expect(st.signedLocalRemovals, 'nor kept for the rebuild').to.equal(
				undefined
			);
			const tx = plannedCommitment(w);
			const rebuilt = rebuild(st).result;
			expect(tx.getId(), 'the close is the plain rebuild').to.equal(
				rebuilt.tx.getId()
			);
			expect(
				rebuilt.outputMap.htlcs,
				'which has no HTLC output'
			).to.have.length(0);
			expect(tx.getId()).to.not.equal(w.signed.getId());
			expect(
				peerSigned(w.bob, w.channelId, tx),
				'the new signature covers it'
			).to.equal(true);
			// The old commitment is revoked now. Classified under its own
			// number, so the keys are the ones its outputs were built with,
			// nothing in our records attributes the HTLC output any more.
			const stale = classifyOutputs(
				w.signed,
				st,
				CommitmentType.OUR_COMMITMENT,
				st.localCommitmentNumber - 1n
			);
			expect(
				stale.length,
				'the old commitment is still recognised as ours'
			).to.be.greaterThan(0);
			expect(
				htlcOutputs(stale),
				'with no HTLC of ours on it to claim'
			).to.have.length(0);
			w.destroy();
		});
	}

	it('claims the fulfilled HTLC by HTLC-success with the stored signature', function () {
		const w = removalWindow(50, 'fulfill');
		const st = fullState(w.bob, w.channelId);

		// The commitment the peer signed is on chain, however it got there.
		const { tracked, resolved } = resolveOnBob(
			w,
			w.signed,
			new Map([[w.hash.toString('hex'), w.preimage]])
		);

		const htlcs = htlcOutputs(tracked);
		expect(htlcs, 'the HTLC output is tracked').to.have.length(1);
		expect(htlcs[0].outputType).to.equal(OutputType.RECEIVED_HTLC);
		expect(htlcs[0].amount).to.equal(HTLC_SATS);
		expect(htlcs[0].paymentHash!.equals(w.hash)).to.equal(true);
		// Index into remoteHtlcSignatures: the only HTLC output is the first.
		expect(htlcs[0].htlcSigIndex).to.equal(0);

		const claim = resolved.find(
			(r) => r.trackedOutput.outputType === OutputType.RECEIVED_HTLC
		);
		expect(claim?.spendTx, 'HTLC-success built').to.not.equal(undefined);
		expect(claim?.witness, 'HTLC-success witnessed').to.not.equal(undefined);
		expect(
			claim!.witness!.some((item) => item.equals(w.preimage)),
			'the witness reveals the preimage'
		).to.equal(true);
		expect(
			Buffer.from(claim!.spendTx!.ins[0].hash).reverse().toString('hex'),
			'it spends the commitment'
		).to.equal(w.signed.getId());

		// Decisive: the peer's stored signature verifies against the exact
		// second-level transaction the resolver built.
		expect(st.remoteHtlcSignatures, 'one stored HTLC signature').to.have.length(
			1
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
		const sigHash = claim!.spendTx!.hashForWitnessV0(
			0,
			claim!.trackedOutput.witnessScript!,
			Number(claim!.trackedOutput.amount),
			sighashType
		);
		expect(
			verify(sigHash, keys.remoteHtlcPubkey, st.remoteHtlcSignatures[0]),
			'peer HTLC signature verifies against the HTLC-success'
		).to.equal(true);
		w.destroy();
	});

	it('has the HTLC-success ready on the monitor after our own close', function () {
		const w = removalWindow(60, 'fulfill');
		const manager = w.bob.getChannelManager();
		expect(manager.forceClose(w.channelId, DESTINATION).ok).to.equal(true);

		manager.handleFundingSpent(w.channelId, w.signed, 800_000, DESTINATION);

		const tracked = htlcOutputs(
			manager.getMonitor(w.channelId)!.getTrackedOutputs()
		);
		expect(tracked, 'the HTLC output is tracked').to.have.length(1);
		expect(tracked[0].outputType).to.equal(OutputType.RECEIVED_HTLC);
		expect(tracked[0].htlcSigIndex).to.equal(0);
		// The monitor was seeded with the preimage at the fulfill, so the
		// witnessed HTLC-success is ready (broadcast, or held for the anchor
		// output's one-block delay).
		expect(tracked[0].sweepTxHex, 'the HTLC-success is built').to.not.equal(
			undefined
		);
		const claim = bitcoin.Transaction.fromHex(tracked[0].sweepTxHex!);
		expect(
			Buffer.from(claim.ins[0].hash).reverse().toString('hex'),
			'it spends the commitment'
		).to.equal(w.signed.getId());
		expect(claim.ins[0].index).to.equal(tracked[0].outputIndex);
		expect(
			claim.ins[0].witness.some((item) => item.equals(w.preimage)),
			'with the preimage'
		).to.equal(true);
		w.destroy();
	});

	it('leaves the failed HTLC to the peer: tracked, no claim of ours, and its timeout armed', function () {
		const w = removalWindow(70, 'fail');

		// Bob: the output is his received HTLC, and he holds no preimage.
		const { tracked, resolved } = resolveOnBob(w, w.signed, new Map());
		const htlcs = htlcOutputs(tracked);
		expect(htlcs, 'the HTLC output is tracked').to.have.length(1);
		expect(htlcs[0].outputType).to.equal(OutputType.RECEIVED_HTLC);
		expect(htlcs[0].htlcSigIndex).to.equal(0);
		const claim = resolved.find(
			(r) => r.trackedOutput.outputType === OutputType.RECEIVED_HTLC
		);
		expect(claim?.spendTx, 'nothing for Bob to claim it with').to.equal(
			undefined
		);

		// Alice: Bob's commitment is on chain with her offered HTLC in it, and
		// it comes back to her by timeout.
		const expiry = [...fullState(w.alice, w.channelId).htlcs.values()].find(
			(e) => e.direction === HtlcDirection.OFFERED
		)!.cltvExpiry;
		const aliceManager = w.alice.getChannelManager();
		aliceManager.handleFundingSpent(w.channelId, w.signed, expiry, DESTINATION);
		const aliceTracked = htlcOutputs(
			aliceManager.getMonitor(w.channelId)!.getTrackedOutputs()
		);
		expect(aliceTracked, 'Alice tracks her offered HTLC').to.have.length(1);
		expect(aliceTracked[0].amount).to.equal(HTLC_SATS);
		expect(aliceTracked[0].cltvExpiry).to.equal(expiry);
		w.destroy();
	});

	it('keeps signature indices aligned for a live HTLC beside the removed one', function () {
		// The removed HTLC is the smaller of the two, so its output comes
		// first: leaving it out would pair the live one with the wrong
		// stored signature (the shape of issue #556).
		const w = removalWindow(80, 'fulfill', { liveBeside: true });
		const st = fullState(w.bob, w.channelId);

		const tx = plannedCommitment(w);
		expect(tx.getId(), 'the commitment the peer signed').to.equal(
			w.signed.getId()
		);

		const { tracked, resolved } = resolveOnBob(
			w,
			tx,
			new Map([
				[w.hash.toString('hex'), w.preimage],
				[w.live!.hash.toString('hex'), w.live!.preimage]
			])
		);
		const htlcs = htlcOutputs(tracked).sort(
			(a, b) => a.outputIndex - b.outputIndex
		);
		expect(htlcs, 'both HTLC outputs are tracked').to.have.length(2);
		expect(
			htlcs[0].paymentHash!.equals(w.hash),
			'the removed one first'
		).to.equal(true);
		expect(htlcs.map((o) => o.htlcSigIndex)).to.deep.equal([0, 1]);

		expect(st.remoteHtlcSignatures).to.have.length(2);
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
		let verified = 0;
		for (const r of resolved) {
			if (r.trackedOutput.outputType !== OutputType.RECEIVED_HTLC) continue;
			expect(r.spendTx, 'HTLC-success built').to.not.equal(undefined);
			const sigHash = r.spendTx!.hashForWitnessV0(
				0,
				r.trackedOutput.witnessScript!,
				Number(r.trackedOutput.amount),
				sighashType
			);
			expect(
				verify(
					sigHash,
					keys.remoteHtlcPubkey,
					st.remoteHtlcSignatures[r.trackedOutput.htlcSigIndex!]
				),
				`signature ${r.trackedOutput.htlcSigIndex} verifies`
			).to.equal(true);
			verified++;
		}
		expect(verified, 'both claims carry verifying signatures').to.equal(2);
		w.destroy();
	});

	it('force closes on it with the peer gone', function () {
		// The case the window matters for: the peer disconnects owing its
		// commitment_signed and does not come back.
		const w = removalWindow(110, 'fulfill');
		w.bob.getChannelManager().handlePeerDisconnected(w.alice.getNodeId());
		expect(fullState(w.bob, w.channelId).state).to.equal(
			ChannelState.AWAITING_REESTABLISH
		);

		const tx = plannedCommitment(w);

		expect(tx.getId()).to.equal(w.signed.getId());
		expect(peerSigned(w.bob, w.channelId, tx)).to.equal(true);
		w.destroy();
	});

	it('does not keep a removal whose add the peer never signed in', function () {
		// Nothing on the wire stops us failing an add before the peer's
		// commitment_signed has covered it, and the commitment we hold then
		// never had the output. The entry says so itself: addLocallyRevoked
		// is still false. Set by hand, since an honest peer never revokes for
		// such a removal.
		const alice = createNode(TAG, 120);
		const bob = createNode(TAG, 121);
		wire(alice, bob, { allow: () => true });
		const channelId = openReadyChannel(alice, bob);
		buildGraph(alice, bob, [channelId]);
		const { hash } = makeExternalHash();
		const invoice = bob.createInvoice({
			amountMsat: HTLC_MSAT,
			description: 'received-removal-window-unsigned',
			hold: true,
			paymentHash: hash
		});
		alice.sendPayment(invoice.bolt11);
		const entry = [...fullState(bob, channelId).htlcs.values()].find(
			(e) => e.direction === HtlcDirection.RECEIVED
		)!;
		entry.addLocallyRevoked = false;
		let kept: IHtlcEntry[] | undefined;
		let revoked = false;
		alice.on('message:outbound', (_pk: string, t: number) => {
			// Listeners run in order, so Bob has handled the revoke by now.
			if (t !== MessageType.REVOKE_AND_ACK || revoked) return;
			revoked = true;
			kept = fullState(bob, channelId).signedLocalRemovals;
		});

		expect(bob.cancelHoldInvoice(hash)).to.deep.equal({ htlcsFailed: 1 });

		expect(revoked, 'Alice revoked for the removal').to.equal(true);
		expect(kept, 'nothing was kept for the rebuild').to.equal(undefined);
		alice.destroy();
		bob.destroy();
	});

	it('lets the signature overrule a kept removal it does not cover', function () {
		// The kept removals are a reading of our own records, and the stored
		// signature is the fact. A leftover the signature does not cover must
		// cost nothing: the close falls back to the rebuild without it.
		const w = removalWindow(130, 'fulfill');
		w.release();
		const st = fullState(w.bob, w.channelId);
		const current = rebuild(st).result.tx;
		st.signedLocalRemovals = [
			{
				id: 99n,
				amountMsat: HTLC_MSAT,
				paymentHash: crypto.randomBytes(32),
				cltvExpiry: 800_100,
				onionRoutingPacket: Buffer.alloc(0),
				direction: HtlcDirection.RECEIVED,
				state: HtlcState.FULFILLED
			}
		];
		expect(
			rebuild(st).result.tx.getId(),
			'the leftover changes the first rebuild'
		).to.not.equal(current.getId());

		const tx = plannedCommitment(w);

		expect(tx.getId(), 'the close is the one the peer signed').to.equal(
			current.getId()
		);
		expect(peerSigned(w.bob, w.channelId, tx)).to.equal(true);
		const { tracked } = resolveOnBob(w, tx, new Map());
		expect(
			htlcOutputs(tracked),
			'and the leftover matches no output'
		).to.have.length(0);
		w.destroy();
	});

	it('ends with the signature a reconnect redelivers', function () {
		const w = removalWindow(140, 'fulfill');

		// Reestablish asks Alice for the commitment_signed Bob never saw.
		w.reconnect();

		const st = fullState(w.bob, w.channelId);
		expect(st.state).to.equal(ChannelState.NORMAL);
		expect(st.signedLocalRemovals, 'the window is over').to.equal(undefined);
		const tx = plannedCommitment(w);
		expect(rebuild(st).result.outputMap.htlcs).to.have.length(0);
		expect(tx.getId()).to.not.equal(w.signed.getId());
		expect(peerSigned(w.bob, w.channelId, tx)).to.equal(true);
		w.destroy();
	});

	it('force closes a taproot channel on the commitment the peer signed', function () {
		const w = removalWindow(90, 'fulfill', { taproot: true });

		// The plan only comes back ok once the peer's stored partial signature
		// has verified over this rebuild and the aggregate over its sighash.
		const tx = plannedCommitment(w);

		expect(outputsOf(tx)).to.deep.equal(outputsOf(w.signed));
		expect(tx.getId()).to.equal(w.signed.getId());
		const { tracked, resolved } = resolveOnBob(
			w,
			tx,
			new Map([[w.hash.toString('hex'), w.preimage]])
		);
		const htlcs = htlcOutputs(tracked);
		expect(htlcs, 'the HTLC output is tracked').to.have.length(1);
		expect(htlcs[0].outputType).to.equal(OutputType.RECEIVED_HTLC);
		expect(htlcs[0].htlcSigIndex).to.equal(0);
		const claim = resolved.find(
			(r) => r.trackedOutput.outputType === OutputType.RECEIVED_HTLC
		);
		expect(claim?.spendTx, 'HTLC-success built').to.not.equal(undefined);
		expect(claim?.witness, 'and witnessed').to.not.equal(undefined);
		w.destroy();
	});
});
