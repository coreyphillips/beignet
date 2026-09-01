/**
 * An offered add the peer has not signed into a local commitment of ours
 * (issue #643).
 *
 * The peer's revoke_and_ack for our commitment_signed sets addRemoteCommitted
 * one message BEFORE its own commitment_signed reaches us. Inside that gap the
 * peer holds the add on its commitment while the signature we store still
 * covers a commitment without it. A force close rebuilds what the STORED
 * signature covers, so admitting the add on addRemoteCommitted alone broadcasts
 * a transaction that signature does not verify: the funding witness is invalid,
 * nothing confirms, and the expiry backstop takes that close by itself.
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
	HtlcState,
	IHtlcEntry
} from '../../src/lightning/channel/types';
import { createFundingScript } from '../../src/lightning/script/funding';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { MessageType } from '../../src/lightning/message/types';

// ─── Node plumbing (model: errored-channel-backstops.test.ts) ───

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`unsigned-add-${id}`))
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
const HTLC_SATS = HTLC_MSAT / 1000n;
/** LightningNode.OFFERED_HTLC_FORCE_CLOSE_GRACE_BLOCKS. */
const GRACE = 6;

interface IStall {
	alice: LightningNode;
	bob: LightningNode;
	channelId: Buffer;
	entry: IHtlcEntry;
	events: string[];
	broadcasts: Buffer[];
	destroy: () => void;
}

/**
 * Alice offers an HTLC and Bob stops answering.
 *
 * `signsTheAdd: false` drops Bob's commitment_signed from the start, so his
 * revoke_and_ack lands (the add may no longer be rolled back) while no local
 * commitment of Alice's was ever signed carrying it. Otherwise the round
 * completes normally and the HTLC simply sits there unresolved.
 */
function stalledAdd(
	seedBase: number,
	opts: { signsTheAdd?: boolean; preimage?: Buffer } = {}
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
	const broadcasts: Buffer[] = [];
	alice
		.getChannelManager()
		.on('broadcast:tx', (tx: Buffer) => broadcasts.push(tx));

	const bobId = bob.getNodeId();
	let failSeen = false;
	filter.allow = (from: string, type: number): boolean => {
		if (from !== bobId) return true;
		if (!signsTheAdd) return type !== MessageType.COMMITMENT_SIGNED;
		// The add round completes, and Bob then fails an HTLC he has no invoice
		// for. Drop that removal and everything after it, so the add is left
		// signed in and unresolved: an ordinary stall.
		if (type === MessageType.UPDATE_FAIL_HTLC) failSeen = true;
		return !failSeen;
	};

	const paymentHash = opts.preimage
		? crypto.createHash('sha256').update(opts.preimage).digest()
		: crypto.randomBytes(32);
	alice
		.getChannelManager()
		.addHtlc(channelId, HTLC_MSAT, paymentHash, EXPIRY, Buffer.alloc(1366));

	const entry = alice
		.getChannelManager()
		.getChannel(channelId)!
		.getFullState()
		.htlcs.get('offered-0')!;
	expect(entry, 'the offered entry exists').to.not.equal(undefined);
	expect(entry.addRemoteCommitted, 'the peer revoked for the add').to.equal(
		true
	);
	expect(entry.addRemoteSigned, 'whether the peer signed it in').to.equal(
		signsTheAdd
	);

	return {
		alice,
		bob,
		channelId,
		entry,
		events,
		broadcasts,
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

function hasHtlcOutput(tx: bitcoin.Transaction): boolean {
	return tx.outs.some((o) => BigInt(o.value) === HTLC_SATS);
}

describe('The force-close rebuild and an unsigned add (issue #643)', function () {
	this.timeout(20_000);

	it('drops the add the expiry backstop would otherwise broadcast', function () {
		// The issue's reproduction: the peer fails the add it never signed in,
		// then disconnects, and markForReestablish rolls the entry back to
		// COMMITTED with addRemoteSigned still false.
		const f = stalledAdd(600, { signsTheAdd: false });
		f.bob.getChannelManager().failHtlc(f.channelId, 0n, Buffer.alloc(32));
		expect(f.entry.state, 'the peer failed it').to.equal(HtlcState.FAILED);
		f.alice.getChannelManager().handlePeerDisconnected(f.bob.getNodeId());
		expect(f.entry.state, 'the disconnect rolled the fail back').to.equal(
			HtlcState.COMMITTED
		);

		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(f.alice as any).scanExpiringOfferedHtlcs(EXPIRY + GRACE);

		expect(f.events, 'the backstop took the close').to.include(
			'HTLC_EXPIRY_FORCE_CLOSE'
		);
		expect(
			f.alice.getChannelManager().getChannel(f.channelId)!.getFullState().state
		).to.equal(ChannelState.FORCE_CLOSED);
		expect(f.broadcasts, 'one commitment broadcast').to.have.length(1);
		const tx = bitcoin.Transaction.fromBuffer(f.broadcasts[0]);
		expect(hasHtlcOutput(tx), 'no HTLC output the signature predates').to.equal(
			false
		);
		expect(
			peerSigned(f.alice, f.channelId, tx),
			'the stored remote signature covers what we broadcast'
		).to.equal(true);
		f.destroy();
	});

	it('drops it with no removal in the picture at all', function () {
		// The add alone is enough: the inclusion comes from the live-entry arm,
		// not from anything the fail or the rollback did.
		const f = stalledAdd(610, { signsTheAdd: false });

		const tx = plannedCommitment(f.alice, f.channelId);

		expect(hasHtlcOutput(tx), 'no HTLC output').to.equal(false);
		expect(
			peerSigned(f.alice, f.channelId, tx),
			'the stored remote signature covers what we broadcast'
		).to.equal(true);
		f.destroy();
	});

	it('keeps an add the peer did sign into our commitment', function () {
		// The ordinary stall, and the case the fix must not touch: the peer
		// signed the add in and simply never resolved it, so the output belongs
		// in the commitment and the timeout path is what reclaims it.
		const f = stalledAdd(620);

		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(f.alice as any).scanExpiringOfferedHtlcs(EXPIRY + GRACE);

		expect(f.events).to.include('HTLC_EXPIRY_FORCE_CLOSE');
		expect(f.broadcasts, 'one commitment broadcast').to.have.length(1);
		const tx = bitcoin.Transaction.fromBuffer(f.broadcasts[0]);
		expect(hasHtlcOutput(tx), 'the HTLC output is in the commitment').to.equal(
			true
		);
		expect(
			peerSigned(f.alice, f.channelId, tx),
			'the stored remote signature covers what we broadcast'
		).to.equal(true);
		f.destroy();
	});

	it('returns the deduction when the peer fulfills an add it never signed', function () {
		// The peer can reveal the preimage inside the same gap. The stored
		// signature covers the pre-add balances, so the ordinary fulfill
		// accounting (credit the peer, keep our deduction) rebuilds a
		// commitment that signature does not verify.
		const preimage = crypto.randomBytes(32);
		const f = stalledAdd(640, { signsTheAdd: false, preimage });
		f.bob.getChannelManager().fulfillHtlc(f.channelId, 0n, preimage);
		expect(f.entry.state, 'the peer fulfilled it').to.equal(
			HtlcState.FULFILLED
		);

		const tx = plannedCommitment(f.alice, f.channelId);

		expect(
			peerSigned(f.alice, f.channelId, tx),
			'the stored remote signature covers what we broadcast'
		).to.equal(true);
		f.destroy();
	});

	it('keeps the output for a row persisted before the flag existed', function () {
		// Absent means "already signed": a row written before addRemoteSigned
		// must keep reading as one the signature covers, or the rebuild drops an
		// output that is genuinely in the commitment.
		const f = stalledAdd(630);
		delete f.entry.addRemoteSigned;

		const tx = plannedCommitment(f.alice, f.channelId);

		expect(hasHtlcOutput(tx), 'the HTLC output is in the commitment').to.equal(
			true
		);
		expect(
			peerSigned(f.alice, f.channelId, tx),
			'the stored remote signature covers what we broadcast'
		).to.equal(true);
		f.destroy();
	});
});
