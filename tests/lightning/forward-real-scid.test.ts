/**
 * Forwarding by a channel's REAL (announced) short_channel_id.
 *
 * Senders build routes from the public gossip graph, which carries real SCIDs, so
 * a forwarding node must accept HTLCs addressed by the SCID it published. beignet
 * previously registered only SCID *aliases* in its forwarding lookup table, so
 * every forward through it failed with unknown_next_peer (0x400A) while direct
 * payments, whose final hop payload carries no short_channel_id at all, kept
 * working. These tests lock down both halves of the rule:
 *
 *   announced channel   -> real SCID is forwardable
 *   unannounced channel -> real SCID is NOT forwardable (BOLT 2 option_scid_alias:
 *                          honouring it would leak the funding outpoint)
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { Channel } from '../../src/lightning/channel/channel';
import { createOpenerState } from '../../src/lightning/channel/channel-state';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { encodeShortChannelId } from '../../src/lightning/gossip/types';
import {
	UNKNOWN_NEXT_PEER,
	TEMPORARY_CHANNEL_FAILURE,
	TEMPORARY_NODE_FAILURE,
	INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS
} from '../../src/lightning/onion/types';

// ── Helpers ────────────────────────────────────────────────────────

function makeBasepoints(): IChannelBasepoints {
	return {
		fundingPubkey: crypto.randomBytes(33),
		revocationBasepoint: crypto.randomBytes(33),
		paymentBasepoint: crypto.randomBytes(33),
		delayedPaymentBasepoint: crypto.randomBytes(33),
		htlcBasepoint: crypto.randomBytes(33),
		firstPerCommitmentPoint: crypto.randomBytes(33)
	};
}

function makeNode(): LightningNode {
	return new LightningNode({
		nodePrivateKey: crypto.randomBytes(32),
		perCommitmentSeed: crypto.randomBytes(32),
		channelBasepoints: makeBasepoints(),
		fundingPrivkey: crypto.randomBytes(32)
	});
}

/**
 * A confirmed channel with both an alias and a real SCID, installed on the node.
 * Block 900_000 is deliberate: 900000 << 40 is far beyond Number.MAX_SAFE_INTEGER,
 * so this also exercises the SCID staying a Buffer rather than a JS number.
 */
function installChannel(
	node: LightningNode,
	opts: { announced: boolean; outputIndex?: number }
): { channelId: Buffer; realScid: Buffer; alias: Buffer } {
	const state = createOpenerState({
		temporaryChannelId: crypto.randomBytes(32),
		fundingSatoshis: 100_000n,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(),
		localPerCommitmentSeed: crypto.randomBytes(32)
	});

	const channelId = crypto.randomBytes(32);
	const realScid = encodeShortChannelId({
		block: 900_000,
		txIndex: 42,
		outputIndex: opts.outputIndex ?? 0
	});
	const alias = crypto.randomBytes(8);

	state.channelId = channelId;
	state.shortChannelId = realScid;
	state.scidAlias = alias;
	state.announceChannel = opts.announced;

	const channel = new Channel(state);
	(node as any).channelManager.restoreChannel(
		channel,
		crypto.randomBytes(33).toString('hex')
	);

	return { channelId, realScid, alias };
}

function registeredScids(node: LightningNode): Set<string> {
	return new Set((node as any).scidToChannelId.keys());
}

// ── Tests ──────────────────────────────────────────────────────────

describe('Forwarding by real SCID', function () {
	let node: LightningNode;

	beforeEach(function () {
		node = makeNode();
	});

	afterEach(function () {
		node.destroy();
	});

	describe('registerChannelScids', function () {
		it('registers the real SCID for an announced channel', function () {
			const { channelId, realScid, alias } = installChannel(node, {
				announced: true
			});

			(node as any).registerChannelScids(channelId);

			const scids = registeredScids(node);
			expect(
				scids.has(realScid.toString('hex')),
				'real SCID must be forwardable on an announced channel'
			).to.be.true;
			expect(scids.has(alias.toString('hex'))).to.be.true;
		});

		it('maps the real SCID to the correct channel id', function () {
			const { channelId, realScid } = installChannel(node, {
				announced: true
			});

			(node as any).registerChannelScids(channelId);

			const mapped = (node as any).scidToChannelId.get(
				realScid.toString('hex')
			);
			expect(mapped).to.not.be.undefined;
			expect(Buffer.from(mapped).equals(channelId)).to.be.true;
		});

		it('does NOT register the real SCID for an unannounced channel', function () {
			const { channelId, realScid, alias } = installChannel(node, {
				announced: false
			});

			(node as any).registerChannelScids(channelId);

			const scids = registeredScids(node);
			expect(
				scids.has(realScid.toString('hex')),
				'a private channel addressed by its real SCID would leak the funding outpoint'
			).to.be.false;
			expect(
				scids.has(alias.toString('hex')),
				'the alias remains the way to address a private channel'
			).to.be.true;
		});

		it('is idempotent', function () {
			const { channelId, realScid } = installChannel(node, {
				announced: true
			});

			(node as any).registerChannelScids(channelId);
			const afterFirst = registeredScids(node).size;
			(node as any).registerChannelScids(channelId);

			expect(registeredScids(node).size).to.equal(afterFirst);
			expect(registeredScids(node).has(realScid.toString('hex'))).to.be.true;
		});
	});

	describe('channel:scid-assigned', function () {
		it('registers the real SCID when the funding reaches announcement depth', function () {
			// The real SCID does not exist at channel:ready, only later, so the
			// assignment itself has to drive registration.
			const { channelId, realScid } = installChannel(node, {
				announced: true
			});
			expect(registeredScids(node).has(realScid.toString('hex'))).to.be.false;

			(node as any).channelManager.emit(
				'channel:scid-assigned',
				channelId,
				realScid
			);

			expect(registeredScids(node).has(realScid.toString('hex'))).to.be.true;
		});

		it('ignores the assignment for an unannounced channel', function () {
			const { channelId, realScid } = installChannel(node, {
				announced: false
			});

			(node as any).channelManager.emit(
				'channel:scid-assigned',
				channelId,
				realScid
			);

			expect(registeredScids(node).has(realScid.toString('hex'))).to.be.false;
		});

		it('ignores the assignment for an unknown channel', function () {
			(node as any).channelManager.emit(
				'channel:scid-assigned',
				crypto.randomBytes(32),
				encodeShortChannelId({ block: 900_001, txIndex: 1, outputIndex: 0 })
			);

			expect(registeredScids(node).size).to.equal(0);
		});
	});
});

describe('Payment failure attribution', function () {
	let node: LightningNode;

	afterEach(function () {
		node.destroy();
	});

	/**
	 * A 2-hop route: us -> partner -> destination. A route hop's shortChannelId is
	 * the channel used to REACH that hop, so hops[0].scid is our own channel and
	 * hops[1].scid is the partner's channel onward to the destination.
	 */
	function twoHopPayment(failureCode: number, failureSourceIndex: number): any {
		const ourChannel = encodeShortChannelId({
			block: 900_000,
			txIndex: 1,
			outputIndex: 0
		});
		const partnerChannel = encodeShortChannelId({
			block: 900_100,
			txIndex: 7,
			outputIndex: 1
		});
		return {
			failureCode,
			failureSourceIndex,
			amountMsat: 1_000_000n,
			route: {
				hops: [
					{ pubkey: crypto.randomBytes(33), shortChannelId: ourChannel },
					{ pubkey: crypto.randomBytes(33), shortChannelId: partnerChannel }
				]
			},
			_ourChannel: ourChannel,
			_partnerChannel: partnerChannel
		};
	}

	beforeEach(function () {
		node = makeNode();
	});

	it('blames the erring hop OUTGOING channel, not our own channel', function () {
		// The partner returns unknown_next_peer at index 0. The channel at fault is
		// the partner's link onward, not the channel we used to reach the partner.
		// Blaming hops[0] penalises our own only channel, which MissionControl then
		// scores down and retries exclude, eventually leaving no route at all.
		const payment = twoHopPayment(UNKNOWN_NEXT_PEER, 0);

		const scid = (node as any).getCulpableHopScid(payment);

		expect(scid).to.equal(payment._partnerChannel.toString('hex'));
		expect(scid).to.not.equal(payment._ourChannel.toString('hex'));
	});

	it('blames the outgoing channel for temporary_channel_failure', function () {
		const payment = twoHopPayment(TEMPORARY_CHANNEL_FAILURE, 0);

		expect((node as any).getCulpableHopScid(payment)).to.equal(
			payment._partnerChannel.toString('hex')
		);
	});

	it('blames no channel for a node-level failure', function () {
		const payment = twoHopPayment(TEMPORARY_NODE_FAILURE, 0);

		expect((node as any).getCulpableHopScid(payment)).to.be.undefined;
	});

	it('blames no channel for a failure from the final hop', function () {
		// The destination has no outgoing channel, so there is nothing to penalise.
		const payment = twoHopPayment(INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS, 1);

		expect((node as any).getCulpableHopScid(payment)).to.be.undefined;
	});

	it('blames no channel when the failure could not be decrypted', function () {
		const payment = twoHopPayment(UNKNOWN_NEXT_PEER, 0);
		payment.failureSourceIndex = undefined;

		expect((node as any).getCulpableHopScid(payment)).to.be.undefined;
	});
});
