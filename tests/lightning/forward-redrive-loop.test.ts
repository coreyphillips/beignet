/**
 * Regression tests for the stuck-forward re-drive loop.
 *
 * A received HTLC stays COMMITTED for the whole time its forward is in flight
 * downstream. handleRevokeAndAck used to re-scan the HTLC map on every
 * commitment round and re-emit HTLC_FORWARDED for every COMMITTED received
 * entry, so one inbound payment was handed to the forwarding layer again and
 * again, each time producing another outgoing HTLC and another provisional
 * balance deduction. ChannelManager then reported every one of those adds as a
 * success even when the Channel had refused it, so the incoming HTLC was never
 * failed back and the loop could not clear itself. Observed live against an LND
 * peer: hours of "Insufficient balance for HTLC" on one channel, an
 * "HTLC <n> not found" on another, and finally a peer-side "invalid update"
 * that killed the channel.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	createOpenerState,
	createAcceptorState
} from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	HtlcState
} from '../../src/lightning/channel/types';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { Channel as ChannelClass } from '../../src/lightning/channel/channel';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { MessageType } from '../../src/lightning/message/types';
import {
	decodeOpenChannelMessage,
	decodeAcceptChannelMessage
} from '../../src/lightning/message/channel-open';
import {
	decodeFundingCreatedMessage,
	decodeFundingSignedMessage,
	decodeChannelReadyMessage
} from '../../src/lightning/message/channel-funding';
import { decodeUpdateAddHtlcMessage } from '../../src/lightning/message/channel-update';
import {
	decodeCommitmentSignedMessage,
	decodeRevokeAndAckMessage
} from '../../src/lightning/message/channel-commitment';
import { serializeHtlcEntry } from '../../src/lightning/storage/serialization';

const FUNDING_SATOSHIS = 1_000_000n;
const PUSH_MSAT = 0n;

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

/* eslint-disable @typescript-eslint/no-explicit-any */
function findAction(actions: any[], type: ChannelActionType): any {
	return actions.find((a) => a.type === type);
}

function findActions(actions: any[], type: ChannelActionType): any[] {
	return actions.filter((a) => a.type === type);
}

function findSendAction(actions: any[], msgType: MessageType): any {
	return actions.find(
		(a: any) =>
			a.type === ChannelActionType.SEND_MESSAGE && a.messageType === msgType
	);
}
/* eslint-enable @typescript-eslint/no-explicit-any */

describe('Stuck forward re-drive loop', function () {
	const openerSeed = crypto.createHash('sha256').update('redrive-a').digest();
	const acceptorSeed = crypto.createHash('sha256').update('redrive-b').digest();
	const openerCommitmentSeed = crypto
		.createHash('sha256')
		.update('redrive-a-commit')
		.digest();
	const acceptorCommitmentSeed = crypto
		.createHash('sha256')
		.update('redrive-b-commit')
		.digest();

	function getToNormal(): { opener: ChannelClass; acceptor: ChannelClass } {
		const openerBasepoints = makeBasepoints(openerSeed);
		const acceptorBasepoints = makeBasepoints(acceptorSeed);

		const opener = new ChannelClass(
			createOpenerState({
				temporaryChannelId: Buffer.alloc(32, 0xaa),
				fundingSatoshis: FUNDING_SATOSHIS,
				pushMsat: PUSH_MSAT,
				localConfig: { ...DEFAULT_CHANNEL_CONFIG },
				localBasepoints: openerBasepoints,
				localPerCommitmentSeed: openerCommitmentSeed
			})
		);
		const acceptor = new ChannelClass(
			createAcceptorState({
				temporaryChannelId: Buffer.alloc(32, 0xaa),
				fundingSatoshis: 0n,
				pushMsat: 0n,
				localConfig: { ...DEFAULT_CHANNEL_CONFIG },
				localBasepoints: acceptorBasepoints,
				localPerCommitmentSeed: acceptorCommitmentSeed,
				remoteBasepoints: openerBasepoints,
				remoteConfig: { ...DEFAULT_CHANNEL_CONFIG }
			})
		);

		const openMsg = findSendAction(
			opener.initiateOpen(),
			MessageType.OPEN_CHANNEL
		);
		const acceptMsg = findSendAction(
			acceptor.handleOpenChannel(decodeOpenChannelMessage(openMsg.payload)),
			MessageType.ACCEPT_CHANNEL
		);
		opener.handleAcceptChannel(decodeAcceptChannelMessage(acceptMsg.payload));

		const fcMsg = findSendAction(
			opener.createFundingCreated(
				crypto.randomBytes(32),
				0,
				crypto.randomBytes(64)
			),
			MessageType.FUNDING_CREATED
		);
		const fsMsg = findSendAction(
			acceptor.handleFundingCreated(
				decodeFundingCreatedMessage(fcMsg.payload),
				crypto.randomBytes(64)
			),
			MessageType.FUNDING_SIGNED
		);
		opener.handleFundingSigned(decodeFundingSignedMessage(fsMsg.payload));

		const orMsg = findSendAction(
			opener.fundingConfirmed(),
			MessageType.CHANNEL_READY
		);
		const arMsg = findSendAction(
			acceptor.fundingConfirmed(),
			MessageType.CHANNEL_READY
		);
		opener.handleChannelReady(decodeChannelReadyMessage(arMsg.payload));
		acceptor.handleChannelReady(decodeChannelReadyMessage(orMsg.payload));

		expect(opener.getState()).to.equal(ChannelState.NORMAL);
		expect(acceptor.getState()).to.equal(ChannelState.NORMAL);
		return { opener, acceptor };
	}

	// One full BOLT 2 commitment round-trip initiated by `a`. Returns the actions
	// `b` produced from its closing handleRevokeAndAck, which is where
	// HTLC_FORWARDED is dispatched.
	/* eslint-disable @typescript-eslint/no-explicit-any */
	function commitmentRoundTrip(a: ChannelClass, b: ChannelClass): any[] {
		const s1 = findSendAction(
			a.signCommitment(crypto.randomBytes(64), []),
			MessageType.COMMITMENT_SIGNED
		);
		const r1 = findSendAction(
			b.handleCommitmentSigned(decodeCommitmentSignedMessage(s1.payload)),
			MessageType.REVOKE_AND_ACK
		);
		a.handleRevokeAndAck(decodeRevokeAndAckMessage(r1.payload));
		const s2 = findSendAction(
			b.signCommitment(crypto.randomBytes(64), []),
			MessageType.COMMITMENT_SIGNED
		);
		const r2 = findSendAction(
			a.handleCommitmentSigned(decodeCommitmentSignedMessage(s2.payload)),
			MessageType.REVOKE_AND_ACK
		);
		return b.handleRevokeAndAck(decodeRevokeAndAckMessage(r2.payload));
	}
	/* eslint-enable @typescript-eslint/no-explicit-any */

	// Push one HTLC from `opener` to `acceptor` and run the round-trip that
	// irrevocably commits it. Returns the acceptor's closing revoke_and_ack
	// actions.
	/* eslint-disable @typescript-eslint/no-explicit-any */
	function deliverHtlc(
		opener: ChannelClass,
		acceptor: ChannelClass,
		amountMsat: bigint
	): { paymentHash: Buffer; preimage: Buffer; actions: any[] } {
		const preimage = crypto.randomBytes(32);
		const paymentHash = crypto.createHash('sha256').update(preimage).digest();
		const addMsg = findSendAction(
			opener.addHtlc(amountMsat, paymentHash, 500000, crypto.randomBytes(1366)),
			MessageType.UPDATE_ADD_HTLC
		);
		acceptor.handleUpdateAddHtlc(decodeUpdateAddHtlcMessage(addMsg.payload));
		const actions = commitmentRoundTrip(opener, acceptor);
		return { paymentHash, preimage, actions };
	}
	/* eslint-enable @typescript-eslint/no-explicit-any */

	describe('HTLC_FORWARDED dispatch is edge-triggered', function () {
		it('dispatches a received HTLC exactly once, not on every later round', function () {
			const { opener, acceptor } = getToNormal();

			const first = deliverHtlc(opener, acceptor, 50_000_000n);
			const firstForwards = findActions(
				first.actions,
				ChannelActionType.HTLC_FORWARDED
			);
			expect(firstForwards).to.have.length(1);
			expect(firstForwards[0].paymentHash.toString('hex')).to.equal(
				first.paymentHash.toString('hex')
			);

			// The forward is now "in flight downstream": we neither fulfill nor fail
			// it, so the entry stays COMMITTED. Drive several more commitment rounds
			// by sending unrelated HTLCs. Each round must dispatch only the HTLC it
			// newly committed, never the earlier still-unsettled one.
			for (let i = 0; i < 3; i++) {
				const next = deliverHtlc(opener, acceptor, 10_000_000n);
				const forwards = findActions(
					next.actions,
					ChannelActionType.HTLC_FORWARDED
				);
				expect(
					forwards,
					`round ${i + 2} dispatched more than the new HTLC`
				).to.have.length(1);
				expect(forwards[0].paymentHash.toString('hex')).to.equal(
					next.paymentHash.toString('hex')
				);
			}
		});

		it('re-dispatches nothing on a round that carries no new inbound HTLC', function () {
			const { opener, acceptor } = getToNormal();
			deliverHtlc(opener, acceptor, 50_000_000n);

			// Another opener-initiated round, this time with no new update. The
			// acceptor still holds the first HTLC in COMMITTED (its forward is in
			// flight downstream), so this is exactly the round that used to
			// re-dispatch it.
			const actions = commitmentRoundTrip(opener, acceptor);
			expect(findAction(actions, ChannelActionType.HTLC_FORWARDED)).to.be
				.undefined;
		});

		it('persists the marker so a restart does not re-dispatch', function () {
			const { opener, acceptor } = getToNormal();
			deliverHtlc(opener, acceptor, 50_000_000n);

			const entries = [...acceptor.getFullState().htlcs.entries()];
			const received = entries.find(([key]) => key.startsWith('received-'));
			expect(received, 'expected a received HTLC entry').to.exist;
			expect(received![1].forwardEmitted).to.equal(true);
			expect(
				serializeHtlcEntry(received![0], received![1]).forwardEmitted
			).to.equal(true);
		});
	});

	describe('send-side repeat-settle guard', function () {
		it('treats a repeated fulfill as a no-op rather than a second wire message', function () {
			const { opener, acceptor } = getToNormal();
			const { preimage, actions } = deliverHtlc(opener, acceptor, 50_000_000n);
			const htlcId = findActions(actions, ChannelActionType.HTLC_FORWARDED)[0]
				.htlcId;

			const firstFulfill = acceptor.fulfillHtlc(htlcId, preimage);
			expect(findSendAction(firstFulfill, MessageType.UPDATE_FULFILL_HTLC)).to
				.exist;

			// A second fulfill for the same id must not put another
			// update_fulfill_htlc on the wire: the peer has already removed that id
			// from its update log and answers a repeat by failing the channel.
			const secondFulfill = acceptor.fulfillHtlc(htlcId, preimage);
			expect(secondFulfill).to.have.length(0);
		});

		it('refuses to fail an HTLC it already fulfilled', function () {
			const { opener, acceptor } = getToNormal();
			const { preimage, actions } = deliverHtlc(opener, acceptor, 50_000_000n);
			const htlcId = findActions(actions, ChannelActionType.HTLC_FORWARDED)[0]
				.htlcId;

			acceptor.fulfillHtlc(htlcId, preimage);

			// Failing after fulfilling would send the value to the remote balance on
			// the next revoke_and_ack, giving away money whose preimage we already
			// revealed. It must be refused, not silently applied.
			const failActions = acceptor.failHtlc(htlcId, Buffer.alloc(32));
			const error = findAction(failActions, ChannelActionType.ERROR);
			expect(error).to.exist;
			expect(error.message).to.contain('already fulfilled');
			expect(findSendAction(failActions, MessageType.UPDATE_FAIL_HTLC)).to.be
				.undefined;

			const entry = acceptor.getFullState().htlcs.get(`received-${htlcId}`);
			expect(entry!.state).to.equal(HtlcState.FULFILLED);
		});

		it('treats a repeated fail as a no-op', function () {
			const { opener, acceptor } = getToNormal();
			const { actions } = deliverHtlc(opener, acceptor, 50_000_000n);
			const htlcId = findActions(actions, ChannelActionType.HTLC_FORWARDED)[0]
				.htlcId;

			const firstFail = acceptor.failHtlc(htlcId, Buffer.alloc(32));
			expect(findSendAction(firstFail, MessageType.UPDATE_FAIL_HTLC)).to.exist;

			const secondFail = acceptor.failHtlc(htlcId, Buffer.alloc(32));
			expect(secondFail).to.have.length(0);
		});
	});

	describe('ChannelManager reports a refused update', function () {
		function makeConfig(seedId: number): IChannelManagerConfig {
			const seed = crypto
				.createHash('sha256')
				.update(Buffer.from(`redrive-mgr-${seedId}`))
				.digest();
			return {
				localConfig: { ...DEFAULT_CHANNEL_CONFIG },
				localBasepoints: makeBasepoints(seed),
				localPerCommitmentSeed: crypto
					.createHash('sha256')
					.update(seed)
					.update(Buffer.from('commit'))
					.digest(),
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

		it('returns ok:false with the reason when the channel refuses the add', function () {
			const aliceConfig = makeConfig(1);
			const bobConfig = makeConfig(2);
			const alicePubkey =
				aliceConfig.localBasepoints.fundingPubkey.toString('hex');
			const bobPubkey = bobConfig.localBasepoints.fundingPubkey.toString('hex');

			const alice = new ChannelManager(aliceConfig);
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
			// Errors are emitted as well as returned; swallow them so the emitter
			// does not throw on an unhandled 'error' event.
			alice.on('error', () => undefined);
			bob.on('error', () => undefined);

			const channel = alice.openChannel(bobPubkey, 1_000_000n);
			const channelId = alice.createFunding(
				channel,
				crypto.randomBytes(32),
				0,
				crypto.randomBytes(64)
			)!;
			alice.handleFundingConfirmed(channelId);
			bob.handleFundingConfirmed(channelId);
			expect(alice.getChannel(channelId)!.getState()).to.equal(
				ChannelState.NORMAL
			);

			// Ask for far more than the channel holds. The Channel refuses with an
			// ERROR action; the manager must surface that as ok:false so a caller
			// that branches on `ok` (the forwarding path does) fails the incoming
			// HTLC back instead of treating the refusal as a delivered forward.
			const result = alice.addHtlc(
				channelId,
				10_000_000_000n,
				crypto.randomBytes(32),
				500000,
				crypto.randomBytes(1366)
			);

			expect(result.ok).to.equal(false);
			expect(result.error).to.contain('Insufficient balance for HTLC');
		});
	});
});
