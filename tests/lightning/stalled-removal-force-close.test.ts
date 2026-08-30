/**
 * A removal round the peer starts and never finishes (issue #634).
 *
 * The peer sends update_fail_htlc for an HTLC we offered and then withholds
 * its commitment_signed. The entry sits FAILED with both phases outstanding,
 * which is not a resolution: a disconnect rolls it back to COMMITTED and the
 * peer may retransmit a fulfill, and the commitment we would broadcast is the
 * one it signed BEFORE the fail, which still carries the offered output. A
 * payee that stalls there past the expiry keeps the downstream leg claimable
 * while our inbound leg times out on chain.
 *
 * Two things have to hold for the expiry backstop to be worth taking: the
 * scanner must reach a stalled leg at all, and the commitment it broadcasts
 * must be the one the stored remote signature covers.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	HtlcDirection,
	HtlcState,
	IHtlcEntry
} from '../../src/lightning/channel/types';
import { OutputType } from '../../src/lightning/chain/types';
import { createFundingScript } from '../../src/lightning/script/funding';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { MessageType } from '../../src/lightning/message/types';

// ─── Node plumbing (model: errored-channel-backstops.test.ts) ───

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`stalled-removal-${id}`))
		.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		keys.push(
			crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from([i]))
				.digest()
		);
	}
	return {
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

function makeNodeConfig(seedId: number): INodeConfig {
	const seed = makeSeed(seedId);
	return {
		nodePrivateKey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from('node-identity'))
			.digest(),
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([0]))
			.digest(),
		htlcBasepointSecret: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([4]))
			.digest()
	};
}

function createNode(seedId: number): LightningNode {
	const node = new LightningNode(makeNodeConfig(seedId));
	node.on('error', () => {});
	return node;
}

interface IFilter {
	allow: (from: string, type: number) => boolean;
}

function wire(a: LightningNode, b: LightningNode, filter: IFilter): void {
	const route = (from: LightningNode, to: LightningNode): void => {
		from.on('message:outbound', (pk: string, t: number, p: Buffer) => {
			if (pk !== to.getNodeId()) return;
			if (!filter.allow(from.getNodeId(), t)) return;
			to.handlePeerMessage(from.getNodeId(), t, p);
		});
	};
	route(a, b);
	route(b, a);
}

function openReadyChannel(a: LightningNode, b: LightningNode): Buffer {
	const channel = a.openChannel(b.getNodeId(), 1_000_000n);
	const channelId = a.createFunding(
		channel,
		crypto.randomBytes(32),
		0,
		crypto.randomBytes(64)
	)!;
	a.handleFundingConfirmed(channelId);
	b.handleFundingConfirmed(channelId);
	return channelId;
}

const HEIGHT = 800_000;
const EXPIRY = HEIGHT + 100;
const HTLC_MSAT = 50_000_000n;
/** LightningNode.OFFERED_HTLC_FORCE_CLOSE_GRACE_BLOCKS. */
const GRACE = 6;

interface IStall {
	alice: LightningNode;
	bob: LightningNode;
	channelId: Buffer;
	entry: IHtlcEntry;
	events: string[];
	destroy: () => void;
}

/**
 * Alice offers an HTLC Bob cannot make sense of; Bob fails it back and his
 * commitment_signed is dropped from that moment on, so the removal round
 * stops half-done exactly as a withholding payee's would.
 *
 * `signsTheAdd: false` drops Bob's commitment_signed from the start instead,
 * so the fail arrives for an add no local commitment of ours ever carried.
 */
function stalledRemoval(
	seedBase: number,
	opts: { signsTheAdd?: boolean } = {}
): IStall {
	const signsTheAdd = opts.signsTheAdd !== false;
	const alice = createNode(seedBase);
	const bob = createNode(seedBase + 1);
	const filter: IFilter = { allow: () => true };
	wire(alice, bob, filter);
	const channelId = openReadyChannel(alice, bob);
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const a = alice as any;
	a.currentBlockHeight = HEIGHT;
	const events: string[] = [];
	alice.on('node:error', (err: { code: string }) => events.push(err.code));

	const bobId = bob.getNodeId();
	let failSeen = !signsTheAdd;
	filter.allow = (from: string, type: number): boolean => {
		if (from !== bobId) return true;
		if (type === MessageType.UPDATE_FAIL_HTLC) {
			failSeen = true;
			return true;
		}
		return !(failSeen && type === MessageType.COMMITMENT_SIGNED);
	};

	alice
		.getChannelManager()
		.addHtlc(
			channelId,
			HTLC_MSAT,
			crypto.randomBytes(32),
			EXPIRY,
			Buffer.alloc(1366)
		);

	if (!signsTheAdd) {
		// Bob never got our revoke_and_ack (his commitment_signed never
		// arrived), so his own dispatch cannot reach the fail. A peer that
		// fails ahead of the round is exactly what this covers, so send it.
		bob.getChannelManager().failHtlc(channelId, 0n, Buffer.alloc(32));
	}

	const entry = alice
		.getChannelManager()
		.getChannel(channelId)!
		.getFullState()
		.htlcs.get('offered-0')!;
	expect(entry, 'the offered entry survives the fail').to.not.equal(undefined);
	expect(entry.state, 'the peer failed it').to.equal(HtlcState.FAILED);
	expect(
		entry.removalLocallyRevoked,
		'no signature covers the removal'
	).to.equal(false);

	return {
		alice,
		bob,
		channelId,
		entry,
		events,
		destroy: (): void => {
			alice.destroy();
			bob.destroy();
		}
	};
}

/** The commitment the channel would broadcast, as force-close bytes. */
function plannedCommitment(
	node: LightningNode,
	channelId: Buffer
): bitcoin.Transaction {
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const manager = node.getChannelManager() as any;
	const channel = manager.getChannel(channelId);
	const plan = channel.prepareForceClose(manager.signerFor(channel, true));
	expect(plan.ok, plan.error).to.equal(true);
	return bitcoin.Transaction.fromBuffer(plan.commitmentTx);
}

/** Whether the stored remote signature covers the given commitment. */
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

/** The per-commitment point of the channel's current local commitment. */
function plannedCommitmentPoint(
	node: LightningNode,
	channelId: Buffer
): Buffer {
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const st = (
		node.getChannelManager().getChannel(channelId) as any
	).getFullState();
	const {
		perCommitmentPointFromSecret
	} = require('../../src/lightning/keys/derivation');
	const {
		generateFromSeed,
		MAX_INDEX
	} = require('../../src/lightning/keys/shachain');
	return perCommitmentPointFromSecret(
		generateFromSeed(
			st.localPerCommitmentSeed,
			MAX_INDEX - st.localCommitmentNumber
		)
	);
}

describe('The commitment a stalled removal round leaves us (issue #634)', function () {
	this.timeout(20_000);

	it('broadcasts the commitment the peer actually signed', function () {
		const f = stalledRemoval(300);

		const tx = plannedCommitment(f.alice, f.channelId);

		expect(
			tx.outs.some((o) => BigInt(o.value) === HTLC_MSAT / 1000n),
			'the offered HTLC output is still in the commitment'
		).to.equal(true);
		// The peer's signature is over the commitment it signed before the
		// fail; rebuilding without the output makes the funding witness
		// invalid, so nothing we broadcast can confirm.
		expect(
			peerSigned(f.alice, f.channelId, tx),
			'the stored remote signature covers what we broadcast'
		).to.equal(true);
		f.destroy();
	});

	it('does the same for a fulfill the peer leaves unsigned', function () {
		// handleUpdateFulfillHtlc leaves the identical entry shape, and the
		// commitment we hold is just as much the pre-removal one, so the
		// rebuild may not key on FAILED.
		const f = stalledRemoval(305);
		f.entry.state = HtlcState.FULFILLED;

		const tx = plannedCommitment(f.alice, f.channelId);

		expect(
			tx.outs.some((o) => BigInt(o.value) === HTLC_MSAT / 1000n),
			'the offered HTLC output is still in the commitment'
		).to.equal(true);
		expect(
			peerSigned(f.alice, f.channelId, tx),
			'the stored remote signature covers what we broadcast'
		).to.equal(true);
		f.destroy();
	});

	it('tracks the retained output so the timeout claim is armed', function () {
		const f = stalledRemoval(310);
		const tx = plannedCommitment(f.alice, f.channelId);

		f.alice
			.getChannelManager()
			.handleFundingSpent(
				f.channelId,
				tx,
				EXPIRY,
				Buffer.from('0014' + '11'.repeat(20), 'hex')
			);

		const tracked = f.alice
			.getChannelManager()
			.getMonitor(f.channelId)!
			.getTrackedOutputs()
			.filter((o) => o.outputType === OutputType.OFFERED_HTLC);
		expect(tracked, 'the offered HTLC output is tracked').to.have.length(1);
		expect(tracked[0].htlcId).to.equal(0n);
		expect(tracked[0].cltvExpiry).to.equal(EXPIRY);
		// Index into remoteHtlcSignatures: an untracked output ahead of this
		// one would pair every later claim with the wrong signature.
		expect(tracked[0].htlcSigIndex).to.equal(0);
		f.destroy();
	});

	it('drops an output no commitment of ours was ever signed with', function () {
		// The peer revoked for our add (so it may not be rolled back) but never
		// signed a commitment carrying it, then failed it anyway. Retaining the
		// output here would put it in a commitment the stored signature was
		// made without.
		const f = stalledRemoval(345, { signsTheAdd: false });
		expect(f.entry.addRemoteCommitted, 'the peer revoked for the add').to.equal(
			true
		);

		const tx = plannedCommitment(f.alice, f.channelId);

		expect(
			tx.outs.some((o) => BigInt(o.value) === HTLC_MSAT / 1000n),
			'no offered HTLC output'
		).to.equal(false);
		expect(
			peerSigned(f.alice, f.channelId, tx),
			'the stored remote signature covers what we broadcast'
		).to.equal(true);
		f.destroy();
	});

	it('still holds an offered HTLC out of the commitment it verifies', function () {
		// The gate is the signedLocal rebuild alone: the commitment the peer
		// signs NEXT drops the removal, and admitting it there would reject
		// every valid commitment_signed that completes the round.
		const f = stalledRemoval(350);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const st = (
			f.alice.getChannelManager().getChannel(f.channelId) as any
		).getFullState();
		const {
			buildLocalCommitment
		} = require('../../src/lightning/channel/commitment-builder');
		const point = plannedCommitmentPoint(f.alice, f.channelId);

		const next = buildLocalCommitment(st, point, st.localCommitmentNumber + 1n);

		expect(
			next.htlcOutputs.some(
				(o: { direction: HtlcDirection }) =>
					o.direction === HtlcDirection.OFFERED
			),
			'the verified commitment has no offered output'
		).to.equal(false);
		f.destroy();
	});
});

describe('The expiry backstop on a stalled removal round (issue #634)', function () {
	this.timeout(20_000);

	it('force-closes once the stall outlasts the grace period', function () {
		const f = stalledRemoval(320);

		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(f.alice as any).scanExpiringOfferedHtlcs(EXPIRY + GRACE);

		expect(f.events).to.include('HTLC_EXPIRY_FORCE_CLOSE');
		expect(
			f.alice.getChannelManager().getChannel(f.channelId)!.getState()
		).to.equal(ChannelState.FORCE_CLOSED);
		f.destroy();
	});

	it('gives the off-chain removal its grace period first', function () {
		const f = stalledRemoval(330);

		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(f.alice as any).scanExpiringOfferedHtlcs(EXPIRY + GRACE - 1);

		expect(f.events).to.not.include('HTLC_EXPIRY_FORCE_CLOSE');
		expect(
			f.alice.getChannelManager().getChannel(f.channelId)!.getState()
		).to.equal(ChannelState.NORMAL);
		f.destroy();
	});

	it('leaves a completed removal alone', function () {
		// Both phases done (here in the legacy flagless encoding): the leg is
		// gone from every commitment either side can put on chain, so there is
		// nothing on it to close for.
		const f = stalledRemoval(340);
		delete f.entry.removalLocallyRevoked;
		delete f.entry.removalRemoteCommitted;

		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(f.alice as any).scanExpiringOfferedHtlcs(EXPIRY + GRACE + 100);

		expect(f.events).to.not.include('HTLC_EXPIRY_FORCE_CLOSE');
		expect(
			f.alice.getChannelManager().getChannel(f.channelId)!.getState()
		).to.equal(ChannelState.NORMAL);
		f.destroy();
	});
});
