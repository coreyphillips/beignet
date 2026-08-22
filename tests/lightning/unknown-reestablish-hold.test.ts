/**
 * Issue #462: a peer-storage node must not fail a peer's channel_reestablish
 * for a channel its (deliberately empty) database has no record of.
 *
 * A node restoring over peer_storage receives the Recovery Capsule and the
 * peer's channel_reestablish in the same instant. Answering with the BOLT 1
 * unknown-channel error force-closes exactly the channel the Tier 2 restore is
 * about to resume, so with a hold window configured the reply is parked
 * instead. The error is DEFERRED, never dropped: one window per peer and
 * channel, after which the peer gets the same answer it gets today.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { MessageType } from '../../src/lightning/message/types';
import { encodeChannelReestablishMessage } from '../../src/lightning/message/channel-reestablish';

// ─── Harness (model: channel-manager.test.ts) ───

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`seed-${id}`))
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

function makeConfig(seedId: number): IChannelManagerConfig {
	const seed = makeSeed(seedId);
	return {
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(seed),
		localPerCommitmentSeed: makeSeed(seedId + 100),
		localFundingPrivkey: crypto
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

const aliceConfig = makeConfig(1);
const bobConfig = makeConfig(2);
const alicePubkey = aliceConfig.localBasepoints.fundingPubkey.toString('hex');
const bobPubkey = bobConfig.localBasepoints.fundingPubkey.toString('hex');

function reestablishPayload(channelId: Buffer): Buffer {
	return encodeChannelReestablishMessage({
		channelId,
		nextCommitmentNumber: 1n,
		nextRevocationNumber: 0n,
		yourLastPerCommitmentSecret: Buffer.alloc(32),
		myCurrentPerCommitmentPoint: getPublicKey(makeSeed(99))
	});
}

/** A manager plus the outbound messages it produced, with 'error' absorbed. */
function makeRestoreTarget(holdMs?: number): {
	manager: ChannelManager;
	sent: Array<{ peer: string; type: number; payload: Buffer }>;
	unknownChannelErrors: () => Array<{ peer: string; payload: Buffer }>;
} {
	const manager = new ChannelManager(
		holdMs === undefined
			? makeConfig(1)
			: { ...makeConfig(1), unknownChannelReestablishHoldMs: holdMs }
	);
	const sent: Array<{ peer: string; type: number; payload: Buffer }> = [];
	manager.on(
		'message:outbound',
		(peer: string, type: number, payload: Buffer) => {
			sent.push({ peer, type, payload });
		}
	);
	manager.on('error', () => {
		/* observed through the messages */
	});
	return {
		manager,
		sent,
		unknownChannelErrors: (): Array<{ peer: string; payload: Buffer }> =>
			sent
				.filter(
					(m) =>
						m.type === MessageType.ERROR &&
						m.payload.toString('utf8').includes('unknown or closed channel')
				)
				.map((m) => ({ peer: m.peer, payload: m.payload }))
	};
}

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

describe('Unknown-channel reestablish hold (issue #462)', function () {
	describe('without a hold window (every mode but peer-storage)', function () {
		it('answers an unknown channel immediately, exactly as before', function () {
			const { manager, sent, unknownChannelErrors } = makeRestoreTarget();

			manager.handleMessage(
				bobPubkey,
				MessageType.CHANNEL_REESTABLISH,
				reestablishPayload(crypto.randomBytes(32))
			);

			expect(sent).to.have.length(1);
			expect(unknownChannelErrors()).to.have.length(1);
		});

		it('declines to hold for a window past the timer ceiling', function () {
			// setTimeout turns anything past 2^31-1 ms into a 1 ms delay, so a
			// hold configured beyond it must fail closed rather than pretend.
			const { manager, unknownChannelErrors } =
				makeRestoreTarget(2_147_483_648);

			manager.handleMessage(
				bobPubkey,
				MessageType.CHANNEL_REESTABLISH,
				reestablishPayload(crypto.randomBytes(32))
			);

			expect(unknownChannelErrors()).to.have.length(1);
		});
	});

	describe('with a hold window (peer-storage restore target)', function () {
		it('parks the reply and reports the peer that is waiting', function () {
			const { manager, sent } = makeRestoreTarget(5_000);
			const channelId = crypto.randomBytes(32);
			const held: Array<{
				peer: string;
				channelId: string;
				expiresAt: number;
			}> = [];
			manager.on(
				'reestablish:held',
				(peer: string, id: Buffer, expiresAt: number) => {
					held.push({ peer, channelId: id.toString('hex'), expiresAt });
				}
			);

			manager.handleMessage(
				bobPubkey,
				MessageType.CHANNEL_REESTABLISH,
				reestablishPayload(channelId)
			);

			// Nothing on the wire: not the error, and not a reestablish of our
			// own for a channel we do not have (spec 5.7).
			expect(sent, 'nothing sent while held').to.have.length(0);
			expect(held).to.have.length(1);
			expect(held[0].peer).to.equal(bobPubkey);
			expect(held[0].channelId).to.equal(channelId.toString('hex'));
			expect(held[0].expiresAt).to.be.greaterThan(Date.now());

			const status = manager.heldUnknownChannelReestablish();
			expect(status).to.have.length(1);
			expect(status[0].peer).to.equal(bobPubkey);
			expect(status[0].channelId).to.equal(channelId.toString('hex'));
			expect(status[0].expiresAt).to.equal(held[0].expiresAt);

			manager.detachFromPeerManager();
		});

		it('sends the error once the window elapses', async function () {
			const { manager, unknownChannelErrors } = makeRestoreTarget(50);
			const channelId = crypto.randomBytes(32);

			manager.handleMessage(
				bobPubkey,
				MessageType.CHANNEL_REESTABLISH,
				reestablishPayload(channelId)
			);
			expect(unknownChannelErrors()).to.have.length(0);

			await sleep(300);

			const errors = unknownChannelErrors();
			expect(errors, 'deferred, not dropped').to.have.length(1);
			expect(errors[0].peer).to.equal(bobPubkey);
			// The error quotes the channel the peer asked about, which is what
			// makes it actionable at their end.
			expect(errors[0].payload.subarray(0, 32).toString('hex')).to.equal(
				channelId.toString('hex')
			);
			// The window is spent: nothing is still parked.
			expect(manager.heldUnknownChannelReestablish()).to.have.length(0);
		});

		it('grants the window once per peer and channel', async function () {
			const { manager, unknownChannelErrors } = makeRestoreTarget(50);
			const channelId = crypto.randomBytes(32);

			manager.handleMessage(
				bobPubkey,
				MessageType.CHANNEL_REESTABLISH,
				reestablishPayload(channelId)
			);
			await sleep(300);
			expect(unknownChannelErrors()).to.have.length(1);

			// A peer that reconnects and asks again is answered at once: without
			// this a flapping peer would renew the hold forever.
			manager.handleMessage(
				bobPubkey,
				MessageType.CHANNEL_REESTABLISH,
				reestablishPayload(channelId)
			);
			expect(unknownChannelErrors()).to.have.length(2);
		});

		it('stays silent when the peer retransmits inside the window', function () {
			const { manager, sent } = makeRestoreTarget(5_000);
			const channelId = crypto.randomBytes(32);
			const payload = reestablishPayload(channelId);

			manager.handleMessage(
				bobPubkey,
				MessageType.CHANNEL_REESTABLISH,
				payload
			);
			manager.handleMessage(
				bobPubkey,
				MessageType.CHANNEL_REESTABLISH,
				payload
			);

			expect(sent).to.have.length(0);
			expect(manager.heldUnknownChannelReestablish()).to.have.length(1);

			manager.detachFromPeerManager();
		});

		it('keeps the original deadline across a disconnect', async function () {
			const { manager } = makeRestoreTarget(5_000);
			const channelId = crypto.randomBytes(32);

			manager.handleMessage(
				bobPubkey,
				MessageType.CHANNEL_REESTABLISH,
				reestablishPayload(channelId)
			);
			const deadline = manager.heldUnknownChannelReestablish()[0].expiresAt;

			manager.handlePeerDisconnected(bobPubkey);
			// Nobody is holding a dead connection open, so nothing is reported
			// as waiting until the peer comes back and asks again.
			expect(manager.heldUnknownChannelReestablish()).to.have.length(0);

			await sleep(30);
			manager.handleMessage(
				bobPubkey,
				MessageType.CHANNEL_REESTABLISH,
				reestablishPayload(channelId)
			);

			const held = manager.heldUnknownChannelReestablish();
			expect(held, 'still parked after the reconnect').to.have.length(1);
			expect(held[0].expiresAt, 'window not renewed').to.equal(deadline);

			manager.detachFromPeerManager();
		});

		it('still answers after a disconnect re-armed the hold', async function () {
			const { manager, unknownChannelErrors } = makeRestoreTarget(120);
			const channelId = crypto.randomBytes(32);

			manager.handleMessage(
				bobPubkey,
				MessageType.CHANNEL_REESTABLISH,
				reestablishPayload(channelId)
			);
			// The disconnect retires the timer; without a re-arm on the next
			// reestablish the peer would never hear back at all.
			manager.handlePeerDisconnected(bobPubkey);
			await sleep(20);
			manager.handleMessage(
				bobPubkey,
				MessageType.CHANNEL_REESTABLISH,
				reestablishPayload(channelId)
			);

			await sleep(400);
			expect(unknownChannelErrors()).to.have.length(1);
		});

		it('spends the quota per peer, so one peer cannot expose another', function () {
			const { manager, sent, unknownChannelErrors } = makeRestoreTarget(5_000);
			const flooder = crypto.randomBytes(33).toString('hex');

			// 64 is MAX_HELD_UNKNOWN_REESTABLISH_PER_PEER: far past any real
			// topology, and the point at which a peer fabricating channel ids
			// stops buying timers.
			for (let i = 0; i < 64; i++) {
				manager.handleMessage(
					flooder,
					MessageType.CHANNEL_REESTABLISH,
					reestablishPayload(crypto.randomBytes(32))
				);
			}
			expect(sent, 'all parked').to.have.length(0);
			expect(manager.heldUnknownChannelReestablish()).to.have.length(64);

			// Spending it is self-inflicted: only the flooder falls through.
			manager.handleMessage(
				flooder,
				MessageType.CHANNEL_REESTABLISH,
				reestablishPayload(crypto.randomBytes(32))
			);
			const errors = unknownChannelErrors();
			expect(errors, 'the flooder fails closed').to.have.length(1);
			expect(errors[0].peer).to.equal(flooder);

			// An honest peer arriving after the flood still gets its window: a
			// global budget would have handed this one the permanent error and
			// force-closed a channel a restore was about to resume.
			const channelId = crypto.randomBytes(32);
			manager.handleMessage(
				bobPubkey,
				MessageType.CHANNEL_REESTABLISH,
				reestablishPayload(channelId)
			);
			expect(
				unknownChannelErrors(),
				'the honest peer is untouched by the flood'
			).to.have.length(1);
			expect(
				manager
					.heldUnknownChannelReestablish()
					.filter((h) => h.peer === bobPubkey)
			).to.have.length(1);

			manager.detachFromPeerManager();
		});

		it('detaching drops every parked message and its timer', async function () {
			const { manager, sent } = makeRestoreTarget(50);

			manager.handleMessage(
				bobPubkey,
				MessageType.CHANNEL_REESTABLISH,
				reestablishPayload(crypto.randomBytes(32))
			);
			manager.detachFromPeerManager();
			expect(manager.heldUnknownChannelReestablish()).to.have.length(0);

			await sleep(200);
			expect(sent, 'no reply from a detached manager').to.have.length(0);
		});
	});

	describe('channels this node does know about are never held', function () {
		function openAndReadyChannel(holdMs: number): {
			alice: ChannelManager;
			bob: ChannelManager;
			channelId: Buffer;
		} {
			const alice = new ChannelManager({
				...aliceConfig,
				unknownChannelReestablishHoldMs: holdMs
			});
			const bob = new ChannelManager(bobConfig);
			alice.on(
				'message:outbound',
				(peer: string, type: number, payload: Buffer) => {
					if (peer === bobPubkey) bob.handleMessage(alicePubkey, type, payload);
				}
			);
			bob.on(
				'message:outbound',
				(peer: string, type: number, payload: Buffer) => {
					if (peer === alicePubkey)
						alice.handleMessage(bobPubkey, type, payload);
				}
			);
			alice.on('error', () => {
				/* absorbed */
			});
			bob.on('error', () => {
				/* absorbed */
			});

			const channel = alice.openChannel(bobPubkey, 1_000_000n);
			const channelId = alice.createFunding(
				channel,
				crypto.randomBytes(32),
				0,
				crypto.randomBytes(64)
			)!;
			alice.handleFundingConfirmed(channelId);
			bob.handleFundingConfirmed(channelId);
			return { alice, bob, channelId };
		}

		it('answers a force-closed channel at once even with a window set', function () {
			const { alice, channelId } = openAndReadyChannel(5_000);
			alice.getChannel(channelId)!.getFullState().state =
				ChannelState.FORCE_CLOSED;

			const sent: Array<{ type: number }> = [];
			alice.on('message:outbound', (_peer: string, type: number) => {
				sent.push({ type });
			});

			alice.handleMessage(
				bobPubkey,
				MessageType.CHANNEL_REESTABLISH,
				reestablishPayload(channelId)
			);

			// A channel we HAVE a record of is not a restore-window question:
			// the hold covers the unknown case only.
			expect(sent.some((m) => m.type === MessageType.ERROR)).to.be.true;
			expect(alice.heldUnknownChannelReestablish()).to.have.length(0);
		});

		it('replays a held message against the restored channel instead of failing it', async function () {
			// The point of the hold: state that arrives during the window must
			// answer the peer, not be overtaken by the error.
			const { alice, channelId } = openAndReadyChannel(0);
			const restored = new ChannelManager({
				...aliceConfig,
				unknownChannelReestablishHoldMs: 80
			});
			const sent: Array<{ type: number; payload: Buffer }> = [];
			restored.on(
				'message:outbound',
				(_peer: string, type: number, payload: Buffer) => {
					sent.push({ type, payload });
				}
			);
			restored.on('error', () => {
				/* absorbed */
			});

			restored.handleMessage(
				bobPubkey,
				MessageType.CHANNEL_REESTABLISH,
				reestablishPayload(channelId)
			);
			expect(sent, 'parked while the database is still empty').to.have.length(
				0
			);

			// Stand in for the capsule restore: the channel now exists.
			restored.restoreChannel(alice.getChannel(channelId)!, bobPubkey);
			await sleep(400);

			expect(
				sent.filter(
					(m) =>
						m.type === MessageType.ERROR &&
						m.payload.toString('utf8').includes('unknown or closed channel')
				),
				'the restored channel is never failed as unknown'
			).to.have.length(0);
			// BOLT 2: both sides transmit channel_reestablish, and wait, before
			// any other message for the channel. Bring-up ran while the database
			// was still empty, so this replay is the only chance to send ours.
			expect(sent.length, 'the peer is answered').to.be.greaterThan(0);
			expect(
				sent[0].type,
				'our channel_reestablish precedes any other channel traffic'
			).to.equal(MessageType.CHANNEL_REESTABLISH);
			expect(sent[0].payload.subarray(0, 32).toString('hex')).to.equal(
				channelId.toString('hex')
			);
			expect(restored.heldUnknownChannelReestablish()).to.have.length(0);
		});

		it('never replays a parked message against another peer channel', async function () {
			// The window is exactly when a channel id can change hands: a peer
			// parks an id while the database is empty, and the restore installs
			// it as SOMEONE ELSE'S channel. Replaying through the private handler
			// would run the sender's counters against that channel and could
			// mark it ERRORED.
			const { alice, channelId } = openAndReadyChannel(0);
			const restored = new ChannelManager({
				...aliceConfig,
				unknownChannelReestablishHoldMs: 80
			});
			const impostor = crypto.randomBytes(33).toString('hex');
			const sent: Array<{ peer: string; type: number }> = [];
			restored.on('message:outbound', (peer: string, type: number) => {
				sent.push({ peer, type });
			});
			restored.on('error', () => {
				/* absorbed */
			});

			restored.handleMessage(
				impostor,
				MessageType.CHANNEL_REESTABLISH,
				reestablishPayload(channelId)
			);
			// The restore hands the id to bob, not to the peer that parked it.
			const channel = alice.getChannel(channelId)!;
			restored.restoreChannel(channel, bobPubkey);
			await sleep(400);

			expect(
				sent.filter((m) => m.peer === impostor),
				'nothing is sent to a peer that does not own the channel'
			).to.have.length(0);
			expect(channel.getState(), "the owner's channel is untouched").to.equal(
				ChannelState.AWAITING_REESTABLISH
			);
		});
	});
});
