/**
 * Forwarding by a channel's REAL (announced) short_channel_id.
 *
 * Senders build routes from the public gossip graph, and invoice route hints
 * likewise prefer the real SCID, so a forwarding node must accept HTLCs
 * addressed by the real short_channel_id. beignet previously registered only
 * SCID *aliases* in its forwarding lookup table, so every forward through it
 * failed with unknown_next_peer (0x400A) while direct payments, whose final hop
 * payload carries no short_channel_id at all, kept working.
 *
 * The eligibility rule is BOLT 2's, which keys off the negotiated CHANNEL TYPE
 * and not off announce_channel: only a channel whose channel_type includes
 * option_scid_alias must refuse its real SCID.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { Channel } from '../../src/lightning/channel/channel';
import { createOpenerState } from '../../src/lightning/channel/channel-state';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { encodeShortChannelId } from '../../src/lightning/gossip/types';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';
import { decryptFailureMessage } from '../../src/lightning/onion/failures';
import {
	UNKNOWN_NEXT_PEER,
	TEMPORARY_CHANNEL_FAILURE,
	TEMPORARY_NODE_FAILURE,
	PERMANENT_CHANNEL_FAILURE,
	REQUIRED_CHANNEL_FEATURE_MISSING,
	REQUIRED_NODE_FEATURE_MISSING,
	INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS,
	ROUTING_INFO_LENGTH
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

/** channel_type = static_remotekey, what beignet actually negotiates today. */
function plainChannelType(): Buffer {
	const flags = FeatureFlags.empty();
	flags.setCompulsory(Feature.STATIC_REMOTE_KEY);
	return flags.toBuffer();
}

/** channel_type = static_remotekey + option_scid_alias. */
function scidAliasChannelType(): Buffer {
	const flags = FeatureFlags.empty();
	flags.setCompulsory(Feature.STATIC_REMOTE_KEY);
	flags.setOptional(Feature.SCID_ALIAS);
	return flags.toBuffer();
}

/**
 * A confirmed channel with both an alias and a real SCID, installed on the node.
 * Block 900_000 is deliberate: 900000 << 40 is far beyond Number.MAX_SAFE_INTEGER,
 * so this also exercises the SCID staying a Buffer rather than a JS number.
 */
function installChannel(
	node: LightningNode,
	opts: {
		announced?: boolean;
		channelType?: Buffer;
		txIndex?: number;
	} = {}
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
		txIndex: opts.txIndex ?? 42,
		outputIndex: 0
	});
	const alias = crypto.randomBytes(8);

	state.channelId = channelId;
	state.shortChannelId = realScid;
	state.scidAlias = alias;
	state.announceChannel = opts.announced ?? true;
	state.channelType = opts.channelType ?? plainChannelType();

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

// ── SCID registration ──────────────────────────────────────────────

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

		it('registers the real SCID for a PRIVATE channel that did not negotiate option_scid_alias', function () {
			// BOLT 2 conditions the prohibition on the channel type, not on
			// announce_channel. Rejecting every private channel would break invoice
			// route hints, which prefer the real SCID over the alias.
			const { channelId, realScid } = installChannel(node, {
				announced: false,
				channelType: plainChannelType()
			});

			(node as any).registerChannelScids(channelId);

			expect(registeredScids(node).has(realScid.toString('hex'))).to.be.true;
		});

		it('does NOT register the real SCID when channel_type includes option_scid_alias', function () {
			const { channelId, realScid, alias } = installChannel(node, {
				announced: false,
				channelType: scidAliasChannelType()
			});

			(node as any).registerChannelScids(channelId);

			const scids = registeredScids(node);
			expect(
				scids.has(realScid.toString('hex')),
				'option_scid_alias means the real SCID must not be accepted'
			).to.be.false;
			expect(
				scids.has(alias.toString('hex')),
				'the alias remains the way to address the channel'
			).to.be.true;
		});

		it('maps the real SCID to the correct channel id', function () {
			const { channelId, realScid } = installChannel(node);

			(node as any).registerChannelScids(channelId);

			const mapped = (node as any).scidToChannelId.get(
				realScid.toString('hex')
			);
			expect(mapped).to.not.be.undefined;
			expect(Buffer.from(mapped).equals(channelId)).to.be.true;
		});

		it('is idempotent', function () {
			const { channelId, realScid } = installChannel(node);

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
			const { channelId, realScid } = installChannel(node);
			expect(registeredScids(node).has(realScid.toString('hex'))).to.be.false;

			(node as any).channelManager.emit(
				'channel:scid-assigned',
				channelId,
				realScid
			);

			expect(registeredScids(node).has(realScid.toString('hex'))).to.be.true;
		});

		it('ignores the assignment when channel_type includes option_scid_alias', function () {
			const { channelId, realScid } = installChannel(node, {
				channelType: scidAliasChannelType()
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

// ── The actual forwarding path ─────────────────────────────────────

/**
 * Drives handleForwardHtlc, the production path that failed in the wild:
 *
 *   A --- channel AB ---> B --- channel BC ---> C
 *                              real SCID = X
 *
 * An onion arriving at B names X as the outgoing channel. This proves the
 * lookup resolves and B forwards, rather than merely proving a map entry exists.
 */
describe('Forwarding by real SCID: handleForwardHtlc', function () {
	let node: LightningNode;
	let addHtlcCalls: Array<{ channelId: Buffer; amountMsat: bigint }>;
	let failHtlcCalls: Array<{ reason: Buffer }>;
	let sharedSecret: Buffer;

	beforeEach(function () {
		node = makeNode();
		addHtlcCalls = [];
		failHtlcCalls = [];
		sharedSecret = crypto.randomBytes(32);

		const cm = (node as any).channelManager;
		cm.addHtlc = (channelId: Buffer, amountMsat: bigint) => {
			addHtlcCalls.push({ channelId, amountMsat });
			return { ok: true };
		};
		cm.failHtlc = (_inChannelId: Buffer, _htlcId: bigint, reason: Buffer) => {
			failHtlcCalls.push({ reason });
		};
	});

	afterEach(function () {
		node.destroy();
	});

	function forwardWithScid(outgoingScid: Buffer): void {
		(node as any).handleForwardHtlc(
			crypto.randomBytes(32), // incoming channel id
			0n, // incoming htlc id
			crypto.randomBytes(32), // payment hash
			{
				hopPayload: {
					// Generous amount and CLTV so the fee and CLTV policy checks pass
					// and the SCID lookup is what decides the outcome.
					amountToForwardMsat: 1_000_000n,
					outgoingCltvValue: 700_000,
					shortChannelId: outgoingScid
				},
				nextPacket: {
					version: 0,
					ephemeralKey: crypto.randomBytes(33),
					routingInfo: Buffer.alloc(ROUTING_INFO_LENGTH),
					hmac: crypto.randomBytes(32)
				},
				sharedSecret
			},
			1_100_000n, // incoming amount, covers forward + fee
			700_500 // incoming CLTV, covers outgoing + our delta
		);
	}

	/** Recover the failure code B sent back on the incoming HTLC. */
	function failureCode(): number | undefined {
		if (failHtlcCalls.length === 0) return undefined;
		const result = decryptFailureMessage(
			[sharedSecret],
			failHtlcCalls[0].reason
		);
		return result?.failure.failureCode;
	}

	it('forwards an HTLC addressed by the real SCID', function () {
		const { channelId, realScid } = installChannel(node, { announced: true });
		(node as any).registerChannelScids(channelId);

		forwardWithScid(realScid);

		expect(
			failureCode(),
			'must not fail back: this is the exact unknown_next_peer regression'
		).to.be.undefined;
		expect(addHtlcCalls).to.have.lengthOf(1);
		expect(addHtlcCalls[0].channelId.equals(channelId)).to.be.true;
	});

	it('forwards an HTLC addressed by the SCID alias', function () {
		const { channelId, alias } = installChannel(node, { announced: true });
		(node as any).registerChannelScids(channelId);

		forwardWithScid(alias);

		expect(failureCode()).to.be.undefined;
		expect(addHtlcCalls).to.have.lengthOf(1);
		expect(addHtlcCalls[0].channelId.equals(channelId)).to.be.true;
	});

	it('fails with unknown_next_peer for an SCID we do not have', function () {
		const { channelId } = installChannel(node, { announced: true });
		(node as any).registerChannelScids(channelId);

		forwardWithScid(
			encodeShortChannelId({ block: 800_000, txIndex: 9, outputIndex: 3 })
		);

		expect(failureCode()).to.equal(UNKNOWN_NEXT_PEER);
		expect(addHtlcCalls).to.be.empty;
	});

	it('fails with unknown_next_peer for the real SCID of an option_scid_alias channel', function () {
		const { channelId, realScid } = installChannel(node, {
			announced: false,
			channelType: scidAliasChannelType()
		});
		(node as any).registerChannelScids(channelId);

		forwardWithScid(realScid);

		expect(failureCode()).to.equal(UNKNOWN_NEXT_PEER);
		expect(addHtlcCalls).to.be.empty;
	});
});

// ── Failure attribution ────────────────────────────────────────────

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

	// Every BOLT 4 failure that describes the erring node's OUTGOING channel.
	// permanent_channel_failure and required_channel_feature_missing are easy to
	// miss: the first carries UPDATE, the second does not.
	const channelScoped = [
		['temporary_channel_failure', TEMPORARY_CHANNEL_FAILURE],
		['permanent_channel_failure', PERMANENT_CHANNEL_FAILURE],
		['required_channel_feature_missing', REQUIRED_CHANNEL_FEATURE_MISSING]
	] as const;

	channelScoped.forEach(([name, code]) => {
		it(`blames the outgoing channel for ${name}`, function () {
			const payment = twoHopPayment(code, 0);

			expect((node as any).getCulpableHopScid(payment)).to.equal(
				payment._partnerChannel.toString('hex')
			);
		});
	});

	const nodeScoped = [
		['temporary_node_failure', TEMPORARY_NODE_FAILURE],
		['required_node_feature_missing', REQUIRED_NODE_FEATURE_MISSING]
	] as const;

	nodeScoped.forEach(([name, code]) => {
		it(`blames no channel for ${name}`, function () {
			const payment = twoHopPayment(code, 0);

			expect((node as any).getCulpableHopScid(payment)).to.be.undefined;
		});
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
