/**
 * Issue #1009: a forwarder never applied expiry_too_soon.
 *
 * handleForwardHtlc checked the onion's outgoing_cltv_value only against the
 * INCOMING expiry (our cltv_expiry_delta), never against our chain tip. An
 * upstream could therefore offer B an HTLC that cleared B's delta while its
 * onion told B to forward with an outgoing_cltv_value a thousand blocks in
 * the past, and B relayed it as it was. A downstream beignet then answered
 * the expired add by failing the channel, force-closing B's OUTGOING channel
 * over a payment B had no part in.
 *
 * Alice -> Bob -> Carol over loopback transports, with Alice's onion built by
 * hand (her own payer would never produce one): Bob fails the inbound HTLC
 * with expiry_too_soon, Carol never sees an update_add_htlc, and no channel
 * leaves NORMAL. The control forwards the same shape with a sane expiry.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	HtlcDirection,
	HtlcState,
	IHtlcEntry
} from '../../src/lightning/channel/types';
import { Channel } from '../../src/lightning/channel/channel';
import { createOpenerState } from '../../src/lightning/channel/channel-state';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { encodeShortChannelId } from '../../src/lightning/gossip/types';
import { MessageType } from '../../src/lightning/message/types';
import {
	EXPIRY_TOO_SOON,
	INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS
} from '../../src/lightning/onion/types';
import {
	constructOnionPacket,
	encodeOnionPacket
} from '../../src/lightning/onion/construct';
import { computeSharedSecrets } from '../../src/lightning/onion/sphinx-crypto';
import { decryptFailureMessage } from '../../src/lightning/onion/failures';
import {
	serializeHtlcEntry,
	deserializeHtlcEntry
} from '../../src/lightning/storage/serialization';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	createNode,
	connectNodes,
	openReadyChannel
} from './helpers/loopback-nodes';

const HEIGHT = 800_000;

interface IChain {
	alice: LightningNode;
	bob: LightningNode;
	carol: LightningNode;
	abChannelId: Buffer;
	bcChannelId: Buffer;
	scidBC: Buffer;
}

function buildChain(): IChain {
	const alice = createNode('e2e-1009', 1);
	const bob = createNode('e2e-1009', 2);
	const carol = createNode('e2e-1009', 3);
	connectNodes(alice, bob);
	connectNodes(bob, carol);
	const abChannelId = openReadyChannel(alice, bob);
	const bcChannelId = openReadyChannel(bob, carol);
	const scidBC = encodeShortChannelId({
		block: 900,
		txIndex: 2,
		outputIndex: 0
	});
	bob.registerChannelScid(bcChannelId, scidBC);
	carol.registerChannelScid(bcChannelId, scidBC);
	for (const n of [alice, bob, carol]) n.handleNewBlock(HEIGHT);
	return { alice, bob, carol, abChannelId, bcChannelId, scidBC };
}

/**
 * Alice offers Bob an HTLC expiring at `incomingCltv` whose onion tells Bob
 * to forward to Carol with `outgoingCltv`. Returns what Bob failed upstream
 * (decrypted with the onion's own secrets) and the adds Bob sent Carol.
 */
function relayThroughBob(
	chain: IChain,
	incomingCltv: number,
	outgoingCltv: number
): { failureCodes: number[]; addsToCarol: number } {
	const { alice, bob, carol, abChannelId, scidBC } = chain;
	const paymentHash = crypto.randomBytes(32);
	const sessionKey = crypto.randomBytes(32);
	const bobPub = Buffer.from(bob.getNodeId(), 'hex');
	const carolPub = Buffer.from(carol.getNodeId(), 'hex');
	const hops = [
		{
			pubkey: bobPub,
			payload: {
				amountToForwardMsat: 1_000_000n,
				outgoingCltvValue: outgoingCltv,
				shortChannelId: scidBC
			}
		},
		{
			pubkey: carolPub,
			payload: {
				amountToForwardMsat: 1_000_000n,
				outgoingCltvValue: outgoingCltv
			}
		}
	];
	const packet = constructOnionPacket(sessionKey, hops, paymentHash);
	const { sharedSecrets } = computeSharedSecrets(sessionKey, [
		bobPub,
		carolPub
	]);

	const reasons: Buffer[] = [];
	const cm = bob.getChannelManager();
	const failHtlc = cm.failHtlc.bind(cm);
	(cm as unknown as { failHtlc: unknown }).failHtlc = (
		c: Buffer,
		id: bigint,
		reason: Buffer
	): unknown => {
		reasons.push(reason);
		return failHtlc(c, id, reason);
	};
	let addsToCarol = 0;
	bob.on('message:outbound', (pk: string, type: number) => {
		if (pk === carol.getNodeId() && type === MessageType.UPDATE_ADD_HTLC) {
			addsToCarol++;
		}
	});

	// Generous fee, so only the expiry decides the outcome.
	const result = alice
		.getChannelManager()
		.addHtlc(
			abChannelId,
			1_100_000n,
			paymentHash,
			incomingCltv,
			encodeOnionPacket(packet)
		);
	expect(result.ok, 'Alice offered the HTLC').to.equal(true);

	const failureCodes = reasons.map((reason) => {
		const decrypted = decryptFailureMessage(sharedSecrets, reason);
		expect(decrypted, 'failure decrypts').to.not.be.null;
		return decrypted!.failure.failureCode;
	});
	return { failureCodes, addsToCarol };
}

function expectAllNormal(chain: IChain): void {
	const { alice, bob, carol, abChannelId, bcChannelId } = chain;
	const views: Array<[string, LightningNode, Buffer]> = [
		['alice ab', alice, abChannelId],
		['bob ab', bob, abChannelId],
		['bob bc', bob, bcChannelId],
		['carol bc', carol, bcChannelId]
	];
	for (const [name, node, channelId] of views) {
		expect(
			node.getChannelManager().getChannel(channelId)!.getState(),
			`${name} stays NORMAL`
		).to.equal(ChannelState.NORMAL);
	}
}

describe('Forward with an outgoing cltv_expiry already past the tip (issue #1009)', function () {
	this.timeout(20_000);

	it('B fails the inbound HTLC with expiry_too_soon; C never sees an add; no channel leaves NORMAL', function () {
		const chain = buildChain();
		// Clears Bob's 40-block delta with one block to spare; the onion's
		// outgoing_cltv_value is a thousand blocks stale.
		const { failureCodes, addsToCarol } = relayThroughBob(
			chain,
			HEIGHT + 41,
			HEIGHT - 1000
		);

		expect(failureCodes).to.deep.equal([EXPIRY_TOO_SOON]);
		expect(addsToCarol, 'Carol never received an add').to.equal(0);
		expect(
			chain.carol
				.getChannelManager()
				.getChannel(chain.bcChannelId)!
				.getFullState().htlcs.size,
			'nothing entered the B-C channel'
		).to.equal(0);
		expectAllNormal(chain);
	});

	it('control: the same shape with a live outgoing expiry is forwarded to C', function () {
		const chain = buildChain();
		const { addsToCarol } = relayThroughBob(chain, HEIGHT + 100, HEIGHT + 60);

		expect(addsToCarol, 'Carol received the add').to.equal(1);
		expectAllNormal(chain);
	});
});

function makeBasepoints(): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) keys.push(crypto.randomBytes(32));
	return {
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

describe('Receiver side: an inbound add admitted past its expiry (issue #1009)', function () {
	this.timeout(20_000);

	it('a block landing before the peer acks the fail-back does not force-close the channel', function () {
		// The claim backstop (scanExpiringHtlcs) treats any inbound HTLC whose
		// preimage we hold as claimable, and every invoice we issue puts its
		// preimage there. A stamped add to one of our own hashes is inside the
		// claim buffer by definition, and the peer decides how long the entry
		// lingers after our fail-back by withholding its ack. That window must
		// not close the channel the fail-back was meant to keep open.
		const alice = createNode('rx-1009', 4);
		const bob = createNode('rx-1009', 5);
		const queue: Array<{ type: number; payload: Buffer }> = [];
		let hold = false;
		alice.on('message:outbound', (pk: string, t: number, p: Buffer) => {
			if (pk !== bob.getNodeId()) return;
			if (hold) {
				queue.push({ type: t, payload: p });
				return;
			}
			bob.handlePeerMessage(alice.getNodeId(), t, p);
		});
		bob.on('message:outbound', (pk: string, t: number, p: Buffer) => {
			if (pk !== alice.getNodeId()) return;
			// From Bob's fail-back on, Alice's replies stay on the wire.
			if (t === MessageType.UPDATE_FAIL_HTLC) hold = true;
			alice.handlePeerMessage(bob.getNodeId(), t, p);
		});
		const channelId = openReadyChannel(alice, bob);
		alice.handleNewBlock(500);
		bob.handleNewBlock(6_000);

		const inv = bob.createInvoice({
			amountMsat: 1_000_000n,
			description: 'expired-on-arrival'
		});
		expect(
			(bob as unknown as { preimages: Map<string, Buffer> }).preimages.has(
				inv.paymentHash.toString('hex')
			),
			'Bob holds the preimage of every invoice he issued'
		).to.equal(true);

		// Alice's onion, a single final hop for Bob, built from HER tip.
		const sessionKey = crypto.randomBytes(32);
		const bobPub = Buffer.from(bob.getNodeId(), 'hex');
		const packet = constructOnionPacket(
			sessionKey,
			[
				{
					pubkey: bobPub,
					payload: {
						amountToForwardMsat: 1_000_000n,
						outgoingCltvValue: 540,
						paymentSecret: inv.paymentSecret,
						totalMsat: 1_000_000n
					}
				}
			],
			inv.paymentHash
		);
		const { sharedSecrets } = computeSharedSecrets(sessionKey, [bobPub]);

		const reasons: Buffer[] = [];
		const cm = bob.getChannelManager();
		const failHtlc = cm.failHtlc.bind(cm);
		(cm as unknown as { failHtlc: unknown }).failHtlc = (
			c: Buffer,
			id: bigint,
			reason: Buffer
		): unknown => {
			reasons.push(reason);
			return failHtlc(c, id, reason);
		};
		// The loopback funding never touched a chain: give Bob's channel the
		// depth the issue #413 gate wants, so the claim arm is really reachable
		// and would really close the channel rather than being skipped.
		bob
			.getChannelManager()
			.getChannel(channelId)!
			.getFullState().fundingConfirmationHeight = 100;
		const errorCodes: string[] = [];
		bob.on('node:error', (e: { code: string }) => errorCodes.push(e.code));
		const logs: unknown[] = [];
		bob.on('log', (l: unknown) => logs.push(l));

		const result = alice
			.getChannelManager()
			.addHtlc(
				channelId,
				1_000_000n,
				inv.paymentHash,
				540,
				encodeOnionPacket(packet)
			);
		expect(result.ok, 'Alice offered the HTLC').to.equal(true);

		// Bob admitted it, stamped it and failed it back; Alice's ack of the
		// removal is still on the wire, so the entry lingers.
		const bobChannel = bob.getChannelManager().getChannel(channelId)!;
		const entry = bobChannel.getFullState().htlcs.get('received-0')!;
		expect(entry, 'admitted').to.not.equal(undefined);
		expect(entry.expiredOnArrival, 'stamped').to.equal(true);
		expect(entry.state, 'failed back, removal pending').to.equal(
			HtlcState.FAILED
		);
		expect(reasons, 'one fail-back').to.have.length(1);
		expect(queue.length, 'the ack is withheld').to.be.greaterThan(0);
		expect(JSON.stringify(logs)).to.include('refused_expired_on_arrival');

		// A block lands in the window the peer controls.
		bob.handleNewBlock(6_001);
		expect(errorCodes, 'no claim force-close').to.not.include(
			'HTLC_CLAIM_FORCE_CLOSE'
		);
		// Nor a skipped one: the arm was never entered for this entry.
		expect(JSON.stringify(logs)).to.not.include('HTLC_CLAIM_FORCE_CLOSE');
		expect(bobChannel.getState(), 'channel stays open').to.equal(
			ChannelState.NORMAL
		);

		// The peer acks: the fail-back completes and both sides are clean.
		hold = false;
		while (queue.length > 0) {
			const m = queue.shift()!;
			bob.handlePeerMessage(alice.getNodeId(), m.type, m.payload);
		}
		expect(
			bobChannel.getFullState().htlcs.has('received-0'),
			'removal irrevocable on Bob'
		).to.equal(false);
		expect(
			alice
				.getChannelManager()
				.getChannel(channelId)!
				.getFullState()
				.htlcs.has('offered-0'),
			'removal irrevocable on Alice'
		).to.equal(false);
		expect(bobChannel.getState()).to.equal(ChannelState.NORMAL);
		const decrypted = decryptFailureMessage(sharedSecrets, reasons[0]);
		expect(decrypted, 'failure decrypts').to.not.be.null;
		expect(decrypted!.failure.failureCode).to.equal(
			INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS
		);
		alice.destroy();
		bob.destroy();
	});

	it('the stamp survives serialisation, alongside the dust flag', function () {
		const base: IHtlcEntry = {
			id: 3n,
			amountMsat: 1_000n,
			paymentHash: crypto.randomBytes(32),
			cltvExpiry: 400,
			onionRoutingPacket: Buffer.alloc(1366),
			direction: HtlcDirection.RECEIVED,
			state: HtlcState.COMMITTED
		};
		const stamped = deserializeHtlcEntry(
			serializeHtlcEntry('received-3', {
				...base,
				expiredOnArrival: true,
				dustExposureFailback: true
			})
		);
		expect(stamped.key).to.equal('received-3');
		expect(stamped.entry.expiredOnArrival).to.equal(true);
		expect(stamped.entry.dustExposureFailback).to.equal(true);

		// Absent stays absent, on the row and after the round trip.
		const row = serializeHtlcEntry('received-3', base);
		expect(Object.keys(row)).to.not.include('expiredOnArrival');
		expect(Object.keys(row)).to.not.include('dustExposureFailback');
		const plain = deserializeHtlcEntry(row);
		expect(plain.entry.expiredOnArrival).to.equal(undefined);
		expect(plain.entry.dustExposureFailback).to.equal(undefined);
	});

	it('a restart honours the stamp: the redispatch fails the HTLC back, never settles it', function () {
		const storage = new SqliteStorage(':memory:');
		storage.open();
		const before = createNode('rs-1009', 6, storage);
		const peerHex = getPublicKey(crypto.randomBytes(32)).toString('hex');
		const state = createOpenerState({
			temporaryChannelId: crypto.randomBytes(32),
			fundingSatoshis: 1_000_000n,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: makeBasepoints(),
			localPerCommitmentSeed: crypto.randomBytes(32)
		});
		const channelId = crypto.randomBytes(32);
		state.channelId = channelId;
		state.state = ChannelState.NORMAL;

		// A two-hop onion, so the restarted node is a forwarder for it.
		const paymentHash = crypto.randomBytes(32);
		const sessionKey = crypto.randomBytes(32);
		const hops = [
			{
				pubkey: Buffer.from(before.getNodeId(), 'hex'),
				payload: {
					amountToForwardMsat: 1_000_000n,
					outgoingCltvValue: 360,
					shortChannelId: Buffer.alloc(8, 7)
				}
			},
			{
				pubkey: getPublicKey(crypto.randomBytes(32)),
				payload: { amountToForwardMsat: 1_000_000n, outgoingCltvValue: 360 }
			}
		];
		const packet = constructOnionPacket(sessionKey, hops, paymentHash);
		const { sharedSecrets } = computeSharedSecrets(
			sessionKey,
			hops.map((h) => h.pubkey)
		);
		// Committed and dispatched once before the crash, stamped at admission.
		state.htlcs.set('received-0', {
			id: 0n,
			amountMsat: 1_000_000n,
			paymentHash,
			cltvExpiry: 400,
			onionRoutingPacket: encodeOnionPacket(packet),
			direction: HtlcDirection.RECEIVED,
			state: HtlcState.COMMITTED,
			forwardEmitted: true,
			expiredOnArrival: true
		});
		before.getChannelManager().restoreChannel(new Channel(state), peerHex);
		(
			before as unknown as { persistChannel: (id: Buffer) => void }
		).persistChannel(channelId);
		expect(storage.loadAllChannels(), 'row persisted').to.have.length(1);

		// The restart reads the row back with the stamp on it.
		const after = createNode('rs-1009', 6, storage);
		const restored = after.getChannelManager().getChannel(channelId)!;
		expect(restored, 'channel restored').to.not.equal(undefined);
		expect(
			restored.getFullState().htlcs.get('received-0')!.expiredOnArrival,
			'stamp restored'
		).to.equal(true);
		(
			after as unknown as { currentBlockHeight: number }
		).currentBlockHeight = 500;

		const reasons: Buffer[] = [];
		const cm = after.getChannelManager();
		(cm as unknown as { failHtlc: unknown }).failHtlc = (
			_c: Buffer,
			_id: bigint,
			reason: Buffer
		): { ok: boolean } => {
			reasons.push(reason);
			return { ok: true };
		};
		let fulfilled = 0;
		(cm as unknown as { fulfillHtlc: unknown }).fulfillHtlc = (): {
			ok: boolean;
		} => {
			fulfilled++;
			return { ok: true };
		};
		(
			after as unknown as {
				redispatchUnresolvedReceivedHtlcs: (id: Buffer) => void;
			}
		).redispatchUnresolvedReceivedHtlcs(channelId);

		expect(fulfilled, 'never settled').to.equal(0);
		expect(reasons, 'failed back on redispatch').to.have.length(1);
		const decrypted = decryptFailureMessage([sharedSecrets[0]], reasons[0]);
		expect(decrypted, 'failure decrypts').to.not.be.null;
		expect(decrypted!.failure.failureCode).to.equal(EXPIRY_TOO_SOON);
		expect(restored.getState()).to.not.equal(ChannelState.ERRORED);
		before.destroy();
		after.destroy();
		storage.close?.();
	});
});
