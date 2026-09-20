/**
 * Issues #905 and #915: a channel whose peer reports
 * next_revocation_number at exactly localCommitmentNumber + 1 has had its
 * CURRENT local commitment revoked in the peer's view. localCommitmentNumber
 * advances when WE send revoke_and_ack, so the peer counting one more than
 * this row recorded sending means the secret for commitment
 * localCommitmentNumber, the one this row would broadcast, is already in the
 * peer's hands. That is the only stale shape handleReestablish lets RESUME,
 * and before this fix nothing recorded it: mustNotBroadcastCommitment did not
 * cover it, the operator's force close was ungated by design (5.6's labelled
 * escape hatch), and the daemon accepted acceptStaleStateRisk: true and
 * published a revoked commitment. The hatch is for a RISK; this is a
 * certainty, so the row now carries restoreRevokedRisk, persisted, and every
 * broadcast path, the operator's included, refuses through the one predicate.
 *
 * The four rows below are the capsule at head (L0, R0) meeting the peer's
 * live head, in the issue's table: (L0, R0) nothing lost, (L0 + 1, R0 + 1)
 * one completed round, (L0, R0 + 1) our commitment_signed unrecorded, and
 * (L0 + 1, R0) our revoke_and_ack unrecorded, which is the bug. The real
 * per-commitment secret is sent at index L0, not zeros, so the cells stay
 * valid once an all-zero secret stops passing validation (issue #907).
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	createOpenerState,
	createAcceptorState,
	mustNotBroadcastCommitment
} from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { Channel } from '../../src/lightning/channel/channel';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
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
import {
	decodeCommitmentSignedMessage,
	decodeRevokeAndAckMessage
} from '../../src/lightning/message/channel-commitment';
import { IChannelReestablishMessage } from '../../src/lightning/message/channel-reestablish';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import { perCommitmentPointFromSecret } from '../../src/lightning/keys/derivation';
import {
	serializeChannelState,
	deserializeChannelState
} from '../../src/lightning/storage/serialization';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { Network } from '../../src/lightning/invoice/types';
import { ILightningError } from '../../src/lightning/node/types';
import { ChannelRecoveryStatus } from '../../src/lightning/recovery/channel-status';
import {
	signerFromSeed,
	realInitialCommitmentSig,
	realCommitmentSigs
} from './helpers/real-signing';

bitcoin.initEccLib(ecc);

const REVOKED_REFUSAL =
	'Refusing to broadcast: the peer already holds the revocation for this commitment';

// ── Channel-pair harness (pattern shared with recovery-phase5-status.test.ts) ──

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const privkeys: Buffer[] = [];
	for (let i = 0; i < 6; i++) {
		privkeys.push(
			crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from([i]))
				.digest()
		);
	}
	return {
		fundingPubkey: getPublicKey(privkeys[0]),
		revocationBasepoint: getPublicKey(privkeys[1]),
		paymentBasepoint: getPublicKey(privkeys[2]),
		delayedPaymentBasepoint: getPublicKey(privkeys[3]),
		htlcBasepoint: getPublicKey(privkeys[4]),
		firstPerCommitmentPoint: getPublicKey(privkeys[5])
	};
}

function findSendAction(
	actions: Array<{ type: ChannelActionType }>,
	msgType: MessageType
): { payload: Buffer } | undefined {
	return actions.find(
		(a) =>
			a.type === ChannelActionType.SEND_MESSAGE &&
			(a as unknown as { messageType: MessageType }).messageType === msgType
	) as { payload: Buffer } | undefined;
}

function setupNormalChannels(): {
	opener: Channel;
	acceptor: Channel;
	openerCommitmentSeed: Buffer;
} {
	const openerSeed = Buffer.alloc(32, 0x71);
	const acceptorSeed = Buffer.alloc(32, 0x72);
	const openerCommitmentSeed = crypto
		.createHash('sha256')
		.update(Buffer.from('revoked-risk-opener'))
		.digest();
	const acceptorCommitmentSeed = crypto
		.createHash('sha256')
		.update(Buffer.from('revoked-risk-acceptor'))
		.digest();
	const openerBasepoints = makeBasepoints(openerSeed);
	const acceptorBasepoints = makeBasepoints(acceptorSeed);

	const opener = new Channel(
		createOpenerState({
			temporaryChannelId: Buffer.alloc(32, 0xe5),
			fundingSatoshis: 1_000_000n,
			pushMsat: 200_000_000n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: openerBasepoints,
			localPerCommitmentSeed: openerCommitmentSeed
		})
	);
	const acceptor = new Channel(
		createAcceptorState({
			temporaryChannelId: Buffer.alloc(32, 0xe5),
			fundingSatoshis: 0n,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: acceptorBasepoints,
			localPerCommitmentSeed: acceptorCommitmentSeed,
			remoteBasepoints: openerBasepoints,
			remoteConfig: { ...DEFAULT_CHANNEL_CONFIG }
		})
	);
	opener.setSigner(signerFromSeed(openerSeed));
	acceptor.setSigner(signerFromSeed(acceptorSeed));

	const openActions = opener.initiateOpen();
	const openMsg = findSendAction(openActions, MessageType.OPEN_CHANNEL)!;
	const acceptActions = acceptor.handleOpenChannel(
		decodeOpenChannelMessage(openMsg.payload)
	);
	const acceptMsg = findSendAction(acceptActions, MessageType.ACCEPT_CHANNEL)!;
	opener.handleAcceptChannel(decodeAcceptChannelMessage(acceptMsg.payload));

	const fundingTxid = crypto.randomBytes(32);
	const fcActions = opener.createFundingCreated(
		fundingTxid,
		0,
		realInitialCommitmentSig(opener, fundingTxid, 0)
	);
	const fcMsg = findSendAction(fcActions, MessageType.FUNDING_CREATED)!;
	const fc = decodeFundingCreatedMessage(fcMsg.payload);
	const fsActions = acceptor.handleFundingCreated(
		fc,
		realInitialCommitmentSig(acceptor, fc.fundingTxid, fc.fundingOutputIndex)
	);
	const fsMsg = findSendAction(fsActions, MessageType.FUNDING_SIGNED)!;
	opener.handleFundingSigned(decodeFundingSignedMessage(fsMsg.payload));

	const openerReady = findSendAction(
		opener.fundingConfirmed(),
		MessageType.CHANNEL_READY
	)!;
	acceptor.handleChannelReady(decodeChannelReadyMessage(openerReady.payload));
	const acceptorReady = findSendAction(
		acceptor.fundingConfirmed(),
		MessageType.CHANNEL_READY
	)!;
	opener.handleChannelReady(decodeChannelReadyMessage(acceptorReady.payload));

	expect(opener.getState()).to.equal(ChannelState.NORMAL);
	expect(acceptor.getState()).to.equal(ChannelState.NORMAL);
	return { opener, acceptor, openerCommitmentSeed };
}

function signRealCommitment(
	channel: Channel
): Array<{ type: ChannelActionType }> {
	const sigs = realCommitmentSigs(channel);
	return channel.signCommitment(sigs.signature, sigs.htlcSignatures);
}

/** One full commitment round in each direction (advances both numbers to 1). */
function exchangeCommitments(opener: Channel, acceptor: Channel): void {
	const commitMsg1 = findSendAction(
		signRealCommitment(opener),
		MessageType.COMMITMENT_SIGNED
	)!;
	const raaMsg1 = findSendAction(
		acceptor.handleCommitmentSigned(
			decodeCommitmentSignedMessage(commitMsg1.payload)
		),
		MessageType.REVOKE_AND_ACK
	)!;
	opener.handleRevokeAndAck(decodeRevokeAndAckMessage(raaMsg1.payload));

	const commitMsg2 = findSendAction(
		signRealCommitment(acceptor),
		MessageType.COMMITMENT_SIGNED
	)!;
	const raaMsg2 = findSendAction(
		opener.handleCommitmentSigned(
			decodeCommitmentSignedMessage(commitMsg2.payload)
		),
		MessageType.REVOKE_AND_ACK
	)!;
	acceptor.handleRevokeAndAck(decodeRevokeAndAckMessage(raaMsg2.payload));
}

/** OUR per-commitment secret at `index`, as the peer would echo it back. */
function secretAt(seed: Buffer, index: bigint): Buffer {
	return generateFromSeed(seed, MAX_INDEX - index);
}

function peerPoint(): Buffer {
	return perCommitmentPointFromSecret(
		crypto.createHash('sha256').update(Buffer.from('peer-point')).digest()
	);
}

/**
 * The capsule's opener at head (L0, R0): one completed round each way, the
 * restore hold stamped as markCapsuleRestoredChannels does, wrapped for the
 * reestablish the peer is about to answer.
 */
function heldOpener(hold = true): {
	opener: Channel;
	seed: Buffer;
	L0: bigint;
	R0: bigint;
} {
	const { opener, acceptor, openerCommitmentSeed } = setupNormalChannels();
	exchangeCommitments(opener, acceptor);
	const state = opener.getFullState();
	if (hold) state.restoreRecencyUnproven = true;
	opener.markForReestablish();
	return {
		opener,
		seed: openerCommitmentSeed,
		L0: state.localCommitmentNumber,
		R0: state.remoteCommitmentNumber
	};
}

/**
 * The peer's channel_reestablish from live head (L, R), in the counters it
 * reports: next_commitment_number R + 1, next_revocation_number L, and
 * your_last_per_commitment_secret at index L - 1.
 */
function peerReestablish(
	opener: Channel,
	seed: Buffer,
	liveL: bigint,
	liveR: bigint,
	secret?: Buffer
): IChannelReestablishMessage {
	return {
		channelId: opener.getChannelId()!,
		nextCommitmentNumber: liveR + 1n,
		nextRevocationNumber: liveL,
		yourLastPerCommitmentSecret:
			secret ?? (liveL > 0n ? secretAt(seed, liveL - 1n) : Buffer.alloc(32)),
		myCurrentPerCommitmentPoint: peerPoint()
	};
}

function hasAction(
	actions: Array<{ type: ChannelActionType }>,
	type: ChannelActionType
): boolean {
	return actions.some((a) => a.type === type);
}

describe('Proven revoked commitment (issues #905 and #915)', function () {
	describe('the capsule at head (L0, R0) meets the peer', function () {
		it('(L0, R0), nothing lost: resumes, the flag stays off, the operator force close stands', function () {
			const { opener, seed, L0, R0 } = heldOpener();

			const actions = opener.handleReestablish(
				peerReestablish(opener, seed, L0, R0)
			);

			const state = opener.getFullState();
			expect(opener.getState()).to.equal(ChannelState.NORMAL);
			expect(hasAction(actions, ChannelActionType.ERROR)).to.equal(false);
			expect(state.restoreRevokedRisk, 'the clean case never sets it').to.equal(
				undefined
			);
			expect(state.restoreRecencyUnproven, 'the hold stands').to.equal(true);
			expect(mustNotBroadcastCommitment(state)).to.equal(false);
			// Revision 13's design: the hold is a RISK and the operator's own
			// close is its labelled exit, so the engine lets it through.
			const plan = opener.prepareForceClose(opener.getSigner()!);
			expect(plan.ok, plan.ok ? '' : plan.error).to.equal(true);
		});

		it('(L0 + 1, R0 + 1), one completed round: the DLP arm, ERRORED and dataLossDetected', function () {
			const { opener, seed, L0, R0 } = heldOpener();

			const actions = opener.handleReestablish(
				peerReestablish(opener, seed, L0 + 1n, R0 + 1n)
			);

			const state = opener.getFullState();
			expect(opener.getState()).to.equal(ChannelState.ERRORED);
			expect(state.dataLossDetected).to.equal(true);
			expect(state.restoreRevokedRisk, 'the DLP arm owns this row').to.equal(
				undefined
			);
			expect(hasAction(actions, ChannelActionType.ERROR)).to.equal(true);
			expect(findSendAction(actions, MessageType.ERROR)).to.not.equal(
				undefined
			);
			const plan = opener.prepareForceClose(opener.getSigner()!);
			expect(plan.ok).to.equal(false);
			expect((plan as { error: string }).error).to.equal(
				'Refusing to broadcast stale commitment after data loss'
			);
		});

		it('(L0, R0 + 1), our commitment_signed unrecorded: the gap arm, ERRORED asking the peer to close', function () {
			const { opener, seed, L0, R0 } = heldOpener();

			const actions = opener.handleReestablish(
				peerReestablish(opener, seed, L0, R0 + 1n)
			);

			const state = opener.getFullState();
			expect(opener.getState()).to.equal(ChannelState.ERRORED);
			expect(opener.getRecoveryCloseReason()).to.equal('restore-unproven');
			expect(state.dataLossDetected).to.not.equal(true);
			expect(state.restoreRevokedRisk, 'the gap arm owns this row').to.equal(
				undefined
			);
			expect(hasAction(actions, ChannelActionType.ERROR)).to.equal(true);
			expect(findSendAction(actions, MessageType.ERROR)).to.not.equal(
				undefined
			);
			// Unchanged: a risk, as designed, so the hatch is still the
			// operator's.
			expect(mustNotBroadcastCommitment(state)).to.equal(false);
		});

		it('(L0 + 1, R0), our revoke_and_ack unrecorded: resumes, persists restoreRevokedRisk and refuses every broadcast', function () {
			const { opener, seed, L0, R0 } = heldOpener();

			// The peer counts one revoke_and_ack more than this row sent, and
			// echoes OUR secret for index L0: the commitment this row would
			// broadcast is revoked in its view.
			const msg = peerReestablish(opener, seed, L0 + 1n, R0);
			expect(msg.nextRevocationNumber).to.equal(L0 + 1n);
			expect(msg.yourLastPerCommitmentSecret.equals(secretAt(seed, L0))).to.be
				.true;
			const actions = opener.handleReestablish(msg);

			const state = opener.getFullState();
			// The levelling retransmission is wanted, so the row resumes.
			expect(opener.getState()).to.equal(ChannelState.NORMAL);
			expect(
				hasAction(actions, ChannelActionType.ERROR),
				'no error: this is not a gap'
			).to.equal(false);
			expect(findSendAction(actions, MessageType.ERROR)).to.equal(undefined);
			expect(hasAction(actions, ChannelActionType.BROADCAST_TX)).to.equal(
				false
			);
			// The shape retransmits nothing, so the trailing persist never
			// fires; the setter carries its own.
			expect(hasAction(actions, ChannelActionType.SEND_MESSAGE)).to.equal(
				false
			);
			expect(
				hasAction(actions, ChannelActionType.PERSIST_STATE),
				'the flag is persisted by the reestablish batch'
			).to.equal(true);
			expect(state.restoreRevokedRisk).to.equal(true);
			expect(state.restoreRecencyUnproven, 'the hold stands too').to.equal(
				true
			);
			expect(mustNotBroadcastCommitment(state)).to.equal(true);
			const plan = opener.prepareForceClose(opener.getSigner()!);
			expect(plan.ok).to.equal(false);
			expect((plan as { error: string }).error).to.equal(REVOKED_REFUSAL);
		});
	});

	it('an all-zero secret at + 1 does not set the flag: the proof is the secret, not the counter', function () {
		const { opener, seed, L0, R0 } = heldOpener();

		const actions = opener.handleReestablish(
			peerReestablish(opener, seed, L0 + 1n, R0, Buffer.alloc(32))
		);

		// Any peer can send this shape: the counter is read off our own
		// channel_reestablish, and only the secret at index L0 proves the
		// revocation. While zeroes pass validation the row resumes with the
		// hatch open, as before this fix; once an all-zero secret above
		// revocation 0 fails the channel (issue #907) the same message ends
		// ERRORED on the invalid secret. Neither world may set the flag, or a
		// peer without the secret could remove the held row's only exit.
		const state = opener.getFullState();
		expect(state.restoreRevokedRisk).to.equal(undefined);
		expect(
			state.state === ChannelState.NORMAL ||
				state.state === ChannelState.ERRORED,
			'resumed (zeroes exempt) or failed on the invalid secret (#907)'
		).to.equal(true);
		if (state.state === ChannelState.NORMAL) {
			expect(hasAction(actions, ChannelActionType.ERROR)).to.equal(false);
			expect(mustNotBroadcastCommitment(state)).to.equal(false);
		}
		const plan = opener.prepareForceClose(opener.getSigner()!);
		expect((plan as { error?: string }).error).to.not.equal(REVOKED_REFUSAL);
	});

	it('protects an ordinary row with the same valid proof and refuses new HTLCs (issue #915)', function () {
		const { opener, seed, L0, R0 } = heldOpener(false);
		const actions = opener.handleReestablish(
			peerReestablish(opener, seed, L0 + 1n, R0)
		);

		expect(opener.getState()).to.equal(ChannelState.NORMAL);
		expect(hasAction(actions, ChannelActionType.ERROR)).to.equal(false);
		expect(hasAction(actions, ChannelActionType.PERSIST_STATE)).to.equal(true);
		expect(opener.getFullState().restoreRecencyUnproven).to.equal(undefined);
		expect(opener.getFullState().restoreRevokedRisk).to.equal(true);
		expect(opener.getRecoveryStatus()).to.equal(
			ChannelRecoveryStatus.LocalDataLoss
		);
		expect(mustNotBroadcastCommitment(opener.getFullState())).to.equal(true);
		const plan = opener.prepareForceClose(opener.getSigner()!);
		expect(plan.ok).to.equal(false);
		expect((plan as { error: string }).error).to.equal(REVOKED_REFUSAL);

		expect(opener.acceptsNewHtlcs()).to.equal(false);
		expect(opener.canOfferHtlcSet([1_000_000n])).to.equal(false);
		const added = opener.addHtlc(
			1_000_000n,
			Buffer.alloc(32, 0x31),
			500,
			Buffer.alloc(1366)
		);
		expect(hasAction(added, ChannelActionType.ERROR)).to.equal(true);
		expect(hasAction(added, ChannelActionType.SEND_MESSAGE)).to.equal(false);

		// Inbound adds follow the existing fail-back path once committed.
		// Their admission stamp keeps pre-existing obligations settleable.
		const received = opener.handleUpdateAddHtlc({
			channelId: opener.getChannelId()!,
			id: 0n,
			amountMsat: 1_000_000n,
			paymentHash: Buffer.alloc(32, 0x32),
			cltvExpiry: 500,
			onionRoutingPacket: Buffer.alloc(1366)
		});
		expect(hasAction(received, ChannelActionType.ERROR)).to.equal(false);
		expect(
			opener.getFullState().htlcs.get('received-0')?.addedWhileRestoreUnproven
		).to.equal(true);
	});

	for (const hold of [false, true]) {
		for (const secret of [Buffer.alloc(32), Buffer.alloc(32, 0x81)]) {
			it(`does not hard-latch a forged proof (capsule=${hold}, zero=${secret.equals(
				Buffer.alloc(32)
			)})`, function () {
				const { opener, seed, L0, R0 } = heldOpener(hold);
				opener.handleReestablish(
					peerReestablish(opener, seed, L0 + 1n, R0, secret)
				);
				expect(opener.getFullState().restoreRevokedRisk).to.equal(undefined);
				expect(mustNotBroadcastCommitment(opener.getFullState())).to.equal(
					false
				);
			});
		}
	}

	it('the flag survives a serialization round trip and a rebuilt Channel still refuses', function () {
		const { opener, seed, L0, R0 } = heldOpener();
		opener.handleReestablish(peerReestablish(opener, seed, L0 + 1n, R0));
		const state = opener.getFullState();
		expect(state.restoreRevokedRisk).to.equal(true);

		const restored = deserializeChannelState(serializeChannelState(state));
		expect(
			restored.restoreRevokedRisk,
			'a restart must not forget it'
		).to.equal(true);
		expect(restored.restoreRecencyUnproven).to.equal(true);
		expect(mustNotBroadcastCommitment(restored)).to.equal(true);
		const rebuilt = new Channel(restored);
		const plan = rebuilt.prepareForceClose(opener.getSigner()!);
		expect(plan.ok).to.equal(false);
		expect((plan as { error: string }).error).to.equal(REVOKED_REFUSAL);

		// And an unflagged row round-trips to no flag: nothing invents it.
		const clean = heldOpener();
		clean.opener.handleReestablish(
			peerReestablish(clean.opener, clean.seed, clean.L0, clean.R0)
		);
		expect(
			deserializeChannelState(
				serializeChannelState(clean.opener.getFullState())
			).restoreRevokedRisk
		).to.equal(undefined);
	});

	for (const hold of [false, true]) {
		it(`refuses operator and timeout closes after restart (capsule=${hold})`, function () {
			const { opener, seed, L0, R0 } = heldOpener(hold);
			opener.handleReestablish(peerReestablish(opener, seed, L0 + 1n, R0));
			const state = deserializeChannelState(
				serializeChannelState(opener.getFullState())
			);
			expect(state.restoreRevokedRisk).to.equal(true);

			const storage = new SqliteStorage(':memory:');
			storage.open();
			const peer = getPublicKey(Buffer.alloc(32, 0x75)).toString('hex');
			const idHex = state.channelId!.toString('hex');
			storage.saveChannel(idHex, state, peer);

			const node = new LightningNode({
				nodePrivateKey: crypto
					.createHash('sha256')
					.update(Buffer.from('revoked-risk-node'))
					.digest(),
				network: Network.REGTEST as Network,
				channelBasepoints: makeBasepoints(Buffer.alloc(32, 0x76)),
				perCommitmentSeed: crypto
					.createHash('sha256')
					.update(Buffer.from('revoked-risk-pcs'))
					.digest(),
				fundingPrivkey: crypto
					.createHash('sha256')
					.update(Buffer.from('revoked-risk-funding'))
					.digest(),
				htlcBasepointSecret: crypto
					.createHash('sha256')
					.update(Buffer.from('revoked-risk-htlc'))
					.digest(),
				storage,
				enableNetworking: false
			});
			node.on('error', () => {});
			const errors: ILightningError[] = [];
			node.on('node:error', (e: ILightningError) => errors.push(e));
			try {
				const row = node
					.getRecoveryStatus()
					.channels.find((c) => c.channelId === idHex);
				expect(row, 'the channel is on the recovery status').to.not.equal(
					undefined
				);
				expect(row!.restoreRecencyUnproven).to.equal(hold ? true : undefined);
				expect(row!.status).to.equal(ChannelRecoveryStatus.LocalDataLoss);
				expect(row!.restoreRevokedRisk, 'reported beside the hold').to.equal(
					true
				);

				const channel = node.getChannelManager().getChannel(state.channelId!)!;
				channel.markForReestablish();
				expect(channel.isFundingKnownOnChain()).to.equal(true);
				const scanner = node as unknown as {
					scanStuckChannels(height: number): void;
					reestablishTimeoutBlocks: number;
				};
				scanner.scanStuckChannels(100);
				scanner.scanStuckChannels(101 + scanner.reestablishTimeoutBlocks);
				expect(channel.getState()).to.equal(ChannelState.AWAITING_REESTABLISH);
				expect(errors).to.have.length(0);
				channel.markErrored();
				expect(channel.getRecoveryCloseReason()).to.equal('local-data-loss');
				scanner.scanStuckChannels(200);
				scanner.scanStuckChannels(201 + scanner.reestablishTimeoutBlocks);
				expect(channel.getState()).to.equal(ChannelState.ERRORED);
				expect(errors).to.have.length(0);

				// Reason 'user', the hatch revision 13 left open: refused, under
				// its own code, before the engine is even asked.
				const script = Buffer.concat([
					Buffer.from([0x00, 0x14]),
					crypto
						.createHash('sha256')
						.update(Buffer.from('sweep'))
						.digest()
						.subarray(0, 20)
				]);
				const result = node.forceCloseChannel(state.channelId!, script);
				expect(result.ok).to.equal(false);
				expect(result.error).to.match(/already holds the revocation/);
				expect(result.error).to.match(/no risk to accept/);
				expect(errors.map((e) => e.code)).to.deep.equal([
					'FORCE_CLOSE_REVOKED'
				]);
				expect(
					node.getChannelManager().getChannel(state.channelId!)!.getState(),
					'nothing moved'
				).to.not.equal(ChannelState.FORCE_CLOSED);
			} finally {
				node.destroy();
				storage.close();
			}
		});
	}
});
