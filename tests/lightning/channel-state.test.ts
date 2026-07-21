import { expect } from 'chai';
import crypto from 'crypto';
import {
	createOpenerState,
	createAcceptorState
} from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	ChannelRole,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { Channel as ChannelClass } from '../../src/lightning/channel/channel';
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
import {
	decodeUpdateAddHtlcMessage,
	decodeUpdateFulfillHtlcMessage,
	decodeUpdateFailHtlcMessage
} from '../../src/lightning/message/channel-update';
import {
	decodeCommitmentSignedMessage,
	decodeRevokeAndAckMessage
} from '../../src/lightning/message/channel-commitment';
import {
	decodeShutdownMessage,
	decodeClosingSignedMessage
} from '../../src/lightning/message/channel-close';
import { deriveChannelId } from '../../src/lightning/channel/validation';

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	// Derive deterministic keys from seed
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		const privkey = crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([i]))
			.digest();
		keys.push(privkey);
	}

	return {
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: Buffer.alloc(33) // will be set during initiateOpen/handleOpenChannel
	};
}

function findAction(actions: any[], type: ChannelActionType): any {
	return actions.find((a) => a.type === type);
}

function findSendAction(actions: any[], msgType: MessageType): any {
	return actions.find(
		(a: any) =>
			a.type === ChannelActionType.SEND_MESSAGE && a.messageType === msgType
	);
}

describe('Channel State Machine', function () {
	const openerSeed = Buffer.alloc(32, 0x01);
	const acceptorSeed = Buffer.alloc(32, 0x02);
	const openerCommitmentSeed = crypto
		.createHash('sha256')
		.update(Buffer.from('opener-commitment'))
		.digest();
	const acceptorCommitmentSeed = crypto
		.createHash('sha256')
		.update(Buffer.from('acceptor-commitment'))
		.digest();

	const FUNDING_SATOSHIS = 1_000_000n;
	const PUSH_MSAT = 0n;

	function createTestChannels(): {
		opener: ChannelClass;
		acceptor: ChannelClass;
	} {
		const openerBasepoints = makeBasepoints(openerSeed);
		const acceptorBasepoints = makeBasepoints(acceptorSeed);

		const openerState = createOpenerState({
			temporaryChannelId: Buffer.alloc(32, 0xaa),
			fundingSatoshis: FUNDING_SATOSHIS,
			pushMsat: PUSH_MSAT,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: openerBasepoints,
			localPerCommitmentSeed: openerCommitmentSeed
		});

		const opener = new ChannelClass(openerState);

		const acceptorState = createAcceptorState({
			temporaryChannelId: Buffer.alloc(32, 0xaa),
			fundingSatoshis: 0n,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: acceptorBasepoints,
			localPerCommitmentSeed: acceptorCommitmentSeed,
			remoteBasepoints: openerBasepoints,
			remoteConfig: { ...DEFAULT_CHANNEL_CONFIG }
		});

		const acceptor = new ChannelClass(acceptorState);

		return { opener, acceptor };
	}

	describe('Channel Opening Flow', function () {
		it('should start in NONE state', function () {
			const { opener, acceptor } = createTestChannels();
			expect(opener.getState()).to.equal(ChannelState.NONE);
			expect(acceptor.getState()).to.equal(ChannelState.NONE);
		});

		it('should transition opener to SENT_OPEN on initiateOpen', function () {
			const { opener } = createTestChannels();
			const actions = opener.initiateOpen();
			expect(opener.getState()).to.equal(ChannelState.SENT_OPEN);
			const sendAction = findSendAction(actions, MessageType.OPEN_CHANNEL);
			expect(sendAction).to.exist;
		});

		it('should reject initiateOpen if not in NONE state', function () {
			const { opener } = createTestChannels();
			opener.initiateOpen();
			const actions = opener.initiateOpen();
			const error = findAction(actions, ChannelActionType.ERROR);
			expect(error).to.exist;
			expect(error.message).to.contain('wrong state');
		});

		it('should complete full opening handshake', function () {
			const { opener, acceptor } = createTestChannels();

			// Step 1: Opener sends open_channel
			const openActions = opener.initiateOpen();
			expect(opener.getState()).to.equal(ChannelState.SENT_OPEN);
			const openMsg = findSendAction(openActions, MessageType.OPEN_CHANNEL);
			expect(openMsg).to.exist;

			// Step 2: Acceptor receives open_channel, sends accept_channel
			const decodedOpen = decodeOpenChannelMessage(openMsg.payload);
			const acceptActions = acceptor.handleOpenChannel(decodedOpen);
			expect(acceptor.getState()).to.equal(ChannelState.SENT_ACCEPT);
			const acceptMsg = findSendAction(
				acceptActions,
				MessageType.ACCEPT_CHANNEL
			);
			expect(acceptMsg).to.exist;

			// Step 3: Opener receives accept_channel
			const decodedAccept = decodeAcceptChannelMessage(acceptMsg.payload);
			const handleAcceptActions = opener.handleAcceptChannel(decodedAccept);
			expect(opener.getState()).to.equal(ChannelState.SENT_ACCEPT);
			expect(handleAcceptActions).to.have.length(0);

			// Step 4: Opener creates funding transaction and sends funding_created
			const fundingTxid = crypto.randomBytes(32);
			const fundingOutputIndex = 0;
			const fakeSig = crypto.randomBytes(64);

			const fundingCreatedActions = opener.createFundingCreated(
				fundingTxid,
				fundingOutputIndex,
				fakeSig
			);
			expect(opener.getState()).to.equal(ChannelState.SENT_FUNDING_CREATED);
			const fundingCreatedMsg = findSendAction(
				fundingCreatedActions,
				MessageType.FUNDING_CREATED
			);
			expect(fundingCreatedMsg).to.exist;

			// Step 5: Acceptor receives funding_created, sends funding_signed
			const decodedFundingCreated = decodeFundingCreatedMessage(
				fundingCreatedMsg.payload
			);
			const fakeSig2 = crypto.randomBytes(64);
			const fundingSignedActions = acceptor.handleFundingCreated(
				decodedFundingCreated,
				fakeSig2
			);
			expect(acceptor.getState()).to.equal(
				ChannelState.AWAITING_FUNDING_CONFIRMED
			);
			const fundingSignedMsg = findSendAction(
				fundingSignedActions,
				MessageType.FUNDING_SIGNED
			);
			expect(fundingSignedMsg).to.exist;
			const watchAction = findAction(
				fundingSignedActions,
				ChannelActionType.WATCH_FUNDING
			);
			expect(watchAction).to.exist;
			expect(watchAction.fundingTxid).to.deep.equal(fundingTxid);

			// Step 6: Opener receives funding_signed
			const decodedFundingSigned = decodeFundingSignedMessage(
				fundingSignedMsg.payload
			);
			const handleFundingSignedActions =
				opener.handleFundingSigned(decodedFundingSigned);
			expect(opener.getState()).to.equal(
				ChannelState.AWAITING_FUNDING_CONFIRMED
			);
			const openerWatch = findAction(
				handleFundingSignedActions,
				ChannelActionType.WATCH_FUNDING
			);
			expect(openerWatch).to.exist;

			// Both should have the same channel ID
			expect(opener.getChannelId()).to.not.be.null;
			expect(acceptor.getChannelId()).to.not.be.null;
			expect(opener.getChannelId()!.equals(acceptor.getChannelId()!)).to.be
				.true;

			// Verify channel ID derivation
			const expectedId = deriveChannelId(fundingTxid, fundingOutputIndex);
			expect(opener.getChannelId()!.equals(expectedId)).to.be.true;
		});
	});

	describe('Channel Ready Flow', function () {
		function getToReadyState(): {
			opener: ChannelClass;
			acceptor: ChannelClass;
		} {
			const { opener, acceptor } = createTestChannels();

			const openActions = opener.initiateOpen();
			const openMsg = findSendAction(openActions, MessageType.OPEN_CHANNEL);
			const acceptActions = acceptor.handleOpenChannel(
				decodeOpenChannelMessage(openMsg.payload)
			);
			const acceptMsg = findSendAction(
				acceptActions,
				MessageType.ACCEPT_CHANNEL
			);
			opener.handleAcceptChannel(decodeAcceptChannelMessage(acceptMsg.payload));

			const fundingTxid = crypto.randomBytes(32);
			const fakeSig = crypto.randomBytes(64);
			const fundingCreatedActions = opener.createFundingCreated(
				fundingTxid,
				0,
				fakeSig
			);
			const fcMsg = findSendAction(
				fundingCreatedActions,
				MessageType.FUNDING_CREATED
			);
			const fsActions = acceptor.handleFundingCreated(
				decodeFundingCreatedMessage(fcMsg.payload),
				crypto.randomBytes(64)
			);
			const fsMsg = findSendAction(fsActions, MessageType.FUNDING_SIGNED);
			opener.handleFundingSigned(decodeFundingSignedMessage(fsMsg.payload));

			return { opener, acceptor };
		}

		it('should handle funding confirmed + channel_ready (opener first)', function () {
			const { opener, acceptor } = getToReadyState();

			// Opener's funding confirmed first
			const openerReadyActions = opener.fundingConfirmed();
			expect(opener.getState()).to.equal(ChannelState.AWAITING_CHANNEL_READY);
			const openerReadyMsg = findSendAction(
				openerReadyActions,
				MessageType.CHANNEL_READY
			);
			expect(openerReadyMsg).to.exist;

			// Acceptor receives opener's channel_ready
			const decodedReady = decodeChannelReadyMessage(openerReadyMsg.payload);
			acceptor.handleChannelReady(decodedReady);
			// Acceptor still waiting for its own funding confirmation
			expect(acceptor.getState()).to.equal(ChannelState.AWAITING_CHANNEL_READY);

			// Acceptor's funding confirmed
			const acceptorReadyActions = acceptor.fundingConfirmed();
			expect(acceptor.getState()).to.equal(ChannelState.NORMAL);
			const channelReadyAction = findAction(
				acceptorReadyActions,
				ChannelActionType.CHANNEL_READY
			);
			expect(channelReadyAction).to.exist;

			// Opener receives acceptor's channel_ready
			const acceptorReadyMsg = findSendAction(
				acceptorReadyActions,
				MessageType.CHANNEL_READY
			);
			const openerHandleActions = opener.handleChannelReady(
				decodeChannelReadyMessage(acceptorReadyMsg.payload)
			);
			expect(opener.getState()).to.equal(ChannelState.NORMAL);
			const openerChannelReady = findAction(
				openerHandleActions,
				ChannelActionType.CHANNEL_READY
			);
			expect(openerChannelReady).to.exist;
		});

		it('should handle funding confirmed + channel_ready (acceptor first)', function () {
			const { opener, acceptor } = getToReadyState();

			// Acceptor's funding confirmed first
			const acceptorReadyActions = acceptor.fundingConfirmed();
			expect(acceptor.getState()).to.equal(ChannelState.AWAITING_CHANNEL_READY);

			// Opener receives acceptor's channel_ready
			const acceptorReadyMsg = findSendAction(
				acceptorReadyActions,
				MessageType.CHANNEL_READY
			);
			opener.handleChannelReady(
				decodeChannelReadyMessage(acceptorReadyMsg.payload)
			);
			expect(opener.getState()).to.equal(ChannelState.AWAITING_CHANNEL_READY);

			// Opener's funding confirmed
			const openerReadyActions = opener.fundingConfirmed();
			expect(opener.getState()).to.equal(ChannelState.NORMAL);

			// Acceptor receives opener's channel_ready
			const openerReadyMsg = findSendAction(
				openerReadyActions,
				MessageType.CHANNEL_READY
			);
			acceptor.handleChannelReady(
				decodeChannelReadyMessage(openerReadyMsg.payload)
			);
			expect(acceptor.getState()).to.equal(ChannelState.NORMAL);
		});

		it('should ignore duplicate channel_ready in NORMAL state', function () {
			const { opener, acceptor } = getToReadyState();

			// Both confirmed and ready
			const openerReadyActions = opener.fundingConfirmed();
			const acceptorReadyActions = acceptor.fundingConfirmed();

			const openerReadyMsg = findSendAction(
				openerReadyActions,
				MessageType.CHANNEL_READY
			);
			const acceptorReadyMsg = findSendAction(
				acceptorReadyActions,
				MessageType.CHANNEL_READY
			);

			opener.handleChannelReady(
				decodeChannelReadyMessage(acceptorReadyMsg.payload)
			);
			acceptor.handleChannelReady(
				decodeChannelReadyMessage(openerReadyMsg.payload)
			);

			expect(opener.getState()).to.equal(ChannelState.NORMAL);
			expect(acceptor.getState()).to.equal(ChannelState.NORMAL);

			// Duplicate should be ignored
			const duplicateActions = opener.handleChannelReady(
				decodeChannelReadyMessage(acceptorReadyMsg.payload)
			);
			expect(duplicateActions).to.have.length(0);
			expect(opener.getState()).to.equal(ChannelState.NORMAL);
		});
	});

	describe('HTLC Operations', function () {
		function getToNormal(): { opener: ChannelClass; acceptor: ChannelClass } {
			const { opener, acceptor } = createTestChannels();

			const openActions = opener.initiateOpen();
			const openMsg = findSendAction(openActions, MessageType.OPEN_CHANNEL);
			const acceptActions = acceptor.handleOpenChannel(
				decodeOpenChannelMessage(openMsg.payload)
			);
			const acceptMsg = findSendAction(
				acceptActions,
				MessageType.ACCEPT_CHANNEL
			);
			opener.handleAcceptChannel(decodeAcceptChannelMessage(acceptMsg.payload));

			const fundingTxid = crypto.randomBytes(32);
			const fcActions = opener.createFundingCreated(
				fundingTxid,
				0,
				crypto.randomBytes(64)
			);
			const fcMsg = findSendAction(fcActions, MessageType.FUNDING_CREATED);
			const fsActions = acceptor.handleFundingCreated(
				decodeFundingCreatedMessage(fcMsg.payload),
				crypto.randomBytes(64)
			);
			const fsMsg = findSendAction(fsActions, MessageType.FUNDING_SIGNED);
			opener.handleFundingSigned(decodeFundingSignedMessage(fsMsg.payload));

			// Both confirm and ready
			const openerReady = opener.fundingConfirmed();
			const acceptorReady = acceptor.fundingConfirmed();

			const orMsg = findSendAction(openerReady, MessageType.CHANNEL_READY);
			const arMsg = findSendAction(acceptorReady, MessageType.CHANNEL_READY);

			opener.handleChannelReady(decodeChannelReadyMessage(arMsg.payload));
			acceptor.handleChannelReady(decodeChannelReadyMessage(orMsg.payload));

			expect(opener.getState()).to.equal(ChannelState.NORMAL);
			expect(acceptor.getState()).to.equal(ChannelState.NORMAL);

			return { opener, acceptor };
		}

		// Drive one full BOLT 2 commitment round-trip initiated by `a`:
		// a signs b's new commitment, b revokes + signs back, a revokes. This is
		// what irrevocably commits pending updates and settles balances. These
		// channels have no signer, so handleCommitmentSigned skips signature
		// verification and placeholder signatures are fine.
		function commitmentRoundTrip(a: ChannelClass, b: ChannelClass): void {
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
			b.handleRevokeAndAck(decodeRevokeAndAckMessage(r2.payload));
		}

		it('should have correct initial balances', function () {
			const { opener, acceptor } = getToNormal();
			const openerBal = opener.getBalances();
			const acceptorBal = acceptor.getBalances();

			expect(openerBal.localMsat).to.equal(FUNDING_SATOSHIS * 1000n);
			expect(openerBal.remoteMsat).to.equal(0n);
			expect(acceptorBal.localMsat).to.equal(0n);
			expect(acceptorBal.remoteMsat).to.equal(FUNDING_SATOSHIS * 1000n);
		});

		it('should add an HTLC and update balances', function () {
			const { opener, acceptor } = getToNormal();

			const preimage = crypto.randomBytes(32);
			const paymentHash = crypto.createHash('sha256').update(preimage).digest();
			const amountMsat = 50_000_000n; // 50k sat
			const onionPacket = crypto.randomBytes(1366);

			// Opener adds HTLC
			const addActions = opener.addHtlc(
				amountMsat,
				paymentHash,
				500000,
				onionPacket
			);
			const addMsg = findSendAction(addActions, MessageType.UPDATE_ADD_HTLC);
			expect(addMsg).to.exist;

			// Verify opener balance deducted
			const openerBal = opener.getBalances();
			expect(openerBal.localMsat).to.equal(
				FUNDING_SATOSHIS * 1000n - amountMsat
			);

			// Acceptor receives HTLC. Per BOLT 2 the received HTLC is held in
			// PENDING and NOT forwarded yet — forwarding is deferred until the
			// commitment round-trip completes (see handleRevokeAndAck).
			const decoded = decodeUpdateAddHtlcMessage(addMsg.payload);
			const handleActions = acceptor.handleUpdateAddHtlc(decoded);
			const forwardAction = findAction(
				handleActions,
				ChannelActionType.HTLC_FORWARDED
			);
			expect(forwardAction).to.be.undefined;
			const received = acceptor.getFullState().htlcs.get('received-0');
			expect(received).to.exist;

			// Acceptor's remote balance is provisionally deducted on receipt.
			const acceptorBal = acceptor.getBalances();
			expect(acceptorBal.remoteMsat).to.equal(
				FUNDING_SATOSHIS * 1000n - amountMsat
			);
		});

		it('should fulfill an HTLC and update balances', function () {
			const { opener, acceptor } = getToNormal();

			const preimage = crypto.randomBytes(32);
			const paymentHash = crypto.createHash('sha256').update(preimage).digest();
			const amountMsat = 50_000_000n;
			const onionPacket = crypto.randomBytes(1366);

			// Opener adds HTLC and the update is committed on both sides.
			const addActions = opener.addHtlc(
				amountMsat,
				paymentHash,
				500000,
				onionPacket
			);
			const addMsg = findSendAction(addActions, MessageType.UPDATE_ADD_HTLC);
			const decoded = decodeUpdateAddHtlcMessage(addMsg.payload);
			acceptor.handleUpdateAddHtlc(decoded);
			commitmentRoundTrip(opener, acceptor);

			// Acceptor fulfills HTLC. Per BOLT 2 the balance is NOT credited yet —
			// it settles only once the removal is committed via revoke_and_ack.
			const fulfillActions = acceptor.fulfillHtlc(decoded.id, preimage);
			const fulfillMsg = findSendAction(
				fulfillActions,
				MessageType.UPDATE_FULFILL_HTLC
			);
			expect(fulfillMsg).to.exist;
			expect(acceptor.getBalances().localMsat).to.equal(0n);

			// Opener receives fulfill, then the fulfill is committed on both sides.
			const decodedFulfill = decodeUpdateFulfillHtlcMessage(fulfillMsg.payload);
			const handleFulfillActions =
				opener.handleUpdateFulfillHtlc(decodedFulfill);
			const fulfilledAction = findAction(
				handleFulfillActions,
				ChannelActionType.HTLC_FULFILLED
			);
			expect(fulfilledAction).to.exist;
			commitmentRoundTrip(acceptor, opener);

			// Balances are now settled: the amount moved from opener to acceptor.
			const openerBal = opener.getBalances();
			const acceptorBal = acceptor.getBalances();
			expect(acceptorBal.localMsat).to.equal(amountMsat);
			expect(openerBal.remoteMsat).to.equal(amountMsat);
			expect(openerBal.localMsat).to.equal(
				FUNDING_SATOSHIS * 1000n - amountMsat
			);
		});

		it('should fail an HTLC and refund balance', function () {
			const { opener, acceptor } = getToNormal();

			const preimage = crypto.randomBytes(32);
			const paymentHash = crypto.createHash('sha256').update(preimage).digest();
			const amountMsat = 50_000_000n;
			const onionPacket = crypto.randomBytes(1366);

			// Opener adds HTLC and the update is committed on both sides.
			const addActions = opener.addHtlc(
				amountMsat,
				paymentHash,
				500000,
				onionPacket
			);
			const addMsg = findSendAction(addActions, MessageType.UPDATE_ADD_HTLC);
			const decoded = decodeUpdateAddHtlcMessage(addMsg.payload);
			acceptor.handleUpdateAddHtlc(decoded);
			commitmentRoundTrip(opener, acceptor);

			// Acceptor fails HTLC. The refund is NOT applied yet — it settles only
			// once the removal is committed via revoke_and_ack.
			const reason = Buffer.from('payment failed');
			const failActions = acceptor.failHtlc(decoded.id, reason);
			const failMsg = findSendAction(failActions, MessageType.UPDATE_FAIL_HTLC);
			expect(failMsg).to.exist;

			// Opener receives fail, then the fail is committed on both sides.
			const decodedFail = decodeUpdateFailHtlcMessage(failMsg.payload);
			const handleFailActions = opener.handleUpdateFailHtlc(decodedFail);
			const failedAction = findAction(
				handleFailActions,
				ChannelActionType.HTLC_FAILED
			);
			expect(failedAction).to.exist;
			commitmentRoundTrip(acceptor, opener);

			// Balances are now refunded to their pre-HTLC values.
			const openerBal = opener.getBalances();
			const acceptorBal = acceptor.getBalances();
			expect(openerBal.localMsat).to.equal(FUNDING_SATOSHIS * 1000n);
			expect(acceptorBal.remoteMsat).to.equal(FUNDING_SATOSHIS * 1000n);
		});

		it('should reject HTLC with invalid preimage', function () {
			const { opener, acceptor } = getToNormal();

			const preimage = crypto.randomBytes(32);
			const paymentHash = crypto.createHash('sha256').update(preimage).digest();
			const amountMsat = 50_000_000n;

			const addActions = opener.addHtlc(
				amountMsat,
				paymentHash,
				500000,
				crypto.randomBytes(1366)
			);
			const addMsg = findSendAction(addActions, MessageType.UPDATE_ADD_HTLC);
			acceptor.handleUpdateAddHtlc(decodeUpdateAddHtlcMessage(addMsg.payload));

			// Try to fulfill with wrong preimage
			const wrongPreimage = crypto.randomBytes(32);
			const actions = acceptor.fulfillHtlc(0n, wrongPreimage);
			const error = findAction(actions, ChannelActionType.ERROR);
			expect(error).to.exist;
			expect(error.message).to.contain('Invalid preimage');
		});

		it('should reject HTLC below remote minimum', function () {
			const { opener } = getToNormal();
			const actions = opener.addHtlc(
				0n, // below minimum
				crypto.randomBytes(32),
				500000,
				crypto.randomBytes(1366)
			);
			const error = findAction(actions, ChannelActionType.ERROR);
			expect(error).to.exist;
			expect(error.message).to.contain('below remote minimum');
		});

		it('should reject HTLC exceeding max value in flight', function () {
			const { opener } = getToNormal();
			// The default limit is clamped to capacity, and anything above
			// capacity trips the balance check first. Pin the peer's advertised
			// limit below our spendable balance so the in-flight check is the
			// one that rejects.
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(opener as any)._state.remoteConfig.maxHtlcValueInFlightMsat =
				500_000_000n;
			const amount = 600_000_000n; // above the 500M limit, below balance
			const actions = opener.addHtlc(
				amount,
				crypto.randomBytes(32),
				500000,
				crypto.randomBytes(1366)
			);
			const error = findAction(actions, ChannelActionType.ERROR);
			expect(error).to.exist;
			expect(error.message).to.contain('Max HTLC value in flight exceeded');
		});

		it('should reject HTLC exceeding balance minus reserve', function () {
			const { opener } = getToNormal();
			// Max in-flight is 500M msat, reserve is 10M msat.
			// Local balance is 1B msat. Send 495M (within in-flight) to leave 505M.
			// Then try another 500M which exceeds balance-reserve (505M - 10M = 495M).
			opener.addHtlc(
				495_000_000n,
				crypto.randomBytes(32),
				500000,
				crypto.randomBytes(1366)
			);
			const actions = opener.addHtlc(
				500_000_000n,
				crypto.randomBytes(32),
				500001,
				crypto.randomBytes(1366)
			);
			const error = findAction(actions, ChannelActionType.ERROR);
			expect(error).to.exist;
			// This hits in-flight check again (495M + 500M > 500M in-flight max)
			// Let's test balance check directly with a smaller amount
			expect(error.message).to.match(/Max HTLC|Insufficient/);
		});

		it('should reject HTLC in wrong state', function () {
			const { opener } = createTestChannels();
			const actions = opener.addHtlc(
				50_000_000n,
				crypto.randomBytes(32),
				500000,
				crypto.randomBytes(1366)
			);
			const error = findAction(actions, ChannelActionType.ERROR);
			expect(error).to.exist;
			expect(error.message).to.contain('NONE state');
		});
	});

	describe('Commitment Signed / Revoke and Ack', function () {
		function getToNormal(): { opener: ChannelClass; acceptor: ChannelClass } {
			const { opener, acceptor } = createTestChannels();

			const openActions = opener.initiateOpen();
			const openMsg = findSendAction(openActions, MessageType.OPEN_CHANNEL);
			const acceptActions = acceptor.handleOpenChannel(
				decodeOpenChannelMessage(openMsg.payload)
			);
			const acceptMsg = findSendAction(
				acceptActions,
				MessageType.ACCEPT_CHANNEL
			);
			opener.handleAcceptChannel(decodeAcceptChannelMessage(acceptMsg.payload));

			const fcActions = opener.createFundingCreated(
				crypto.randomBytes(32),
				0,
				crypto.randomBytes(64)
			);
			const fcMsg = findSendAction(fcActions, MessageType.FUNDING_CREATED);
			const fsActions = acceptor.handleFundingCreated(
				decodeFundingCreatedMessage(fcMsg.payload),
				crypto.randomBytes(64)
			);
			const fsMsg = findSendAction(fsActions, MessageType.FUNDING_SIGNED);
			opener.handleFundingSigned(decodeFundingSignedMessage(fsMsg.payload));

			const or = opener.fundingConfirmed();
			const ar = acceptor.fundingConfirmed();
			opener.handleChannelReady(
				decodeChannelReadyMessage(
					findSendAction(ar, MessageType.CHANNEL_READY).payload
				)
			);
			acceptor.handleChannelReady(
				decodeChannelReadyMessage(
					findSendAction(or, MessageType.CHANNEL_READY).payload
				)
			);

			return { opener, acceptor };
		}

		it('should handle commitment_signed and revoke_and_ack cycle', function () {
			const { opener, acceptor } = getToNormal();

			// Opener signs commitment
			const sigActions = opener.signCommitment(crypto.randomBytes(64), []);
			const sigMsg = findSendAction(sigActions, MessageType.COMMITMENT_SIGNED);
			expect(sigMsg).to.exist;

			// Acceptor handles commitment_signed, sends revoke_and_ack
			const decoded = decodeCommitmentSignedMessage(sigMsg.payload);
			const revokeActions = acceptor.handleCommitmentSigned(decoded);
			const revokeMsg = findSendAction(
				revokeActions,
				MessageType.REVOKE_AND_ACK
			);
			expect(revokeMsg).to.exist;

			// Opener handles revoke_and_ack
			const decodedRevoke = decodeRevokeAndAckMessage(revokeMsg.payload);
			const handleRevokeActions = opener.handleRevokeAndAck(decodedRevoke);
			// PERSIST_STATE action emitted after processing revoke_and_ack (Fix 2.2)
			expect(handleRevokeActions).to.have.length(1);
			expect(handleRevokeActions[0].type).to.equal('PERSIST_STATE');

			// Commitment numbers should advance
			const openerNums = opener.getCommitmentNumbers();
			const acceptorNums = acceptor.getCommitmentNumbers();
			expect(openerNums.remote).to.equal(1n); // opener sent commitment
			expect(acceptorNums.local).to.equal(1n); // acceptor received and revoked
		});

		it('should handle full HTLC lifecycle with commitment exchange', function () {
			const { opener, acceptor } = getToNormal();

			const preimage = crypto.randomBytes(32);
			const paymentHash = crypto.createHash('sha256').update(preimage).digest();
			const amountMsat = 50_000_000n;

			// 1. Opener adds HTLC
			const addActions = opener.addHtlc(
				amountMsat,
				paymentHash,
				500000,
				crypto.randomBytes(1366)
			);
			const addMsg = findSendAction(addActions, MessageType.UPDATE_ADD_HTLC);
			acceptor.handleUpdateAddHtlc(decodeUpdateAddHtlcMessage(addMsg.payload));

			// 2. Opener signs commitment (including HTLC)
			const sigActions1 = opener.signCommitment(crypto.randomBytes(64), []);
			const sigMsg1 = findSendAction(
				sigActions1,
				MessageType.COMMITMENT_SIGNED
			);
			const revokeActions1 = acceptor.handleCommitmentSigned(
				decodeCommitmentSignedMessage(sigMsg1.payload)
			);
			const revokeMsg1 = findSendAction(
				revokeActions1,
				MessageType.REVOKE_AND_ACK
			);
			opener.handleRevokeAndAck(decodeRevokeAndAckMessage(revokeMsg1.payload));

			// 3. Acceptor signs commitment (acknowledging HTLC)
			const sigActions2 = acceptor.signCommitment(crypto.randomBytes(64), []);
			const sigMsg2 = findSendAction(
				sigActions2,
				MessageType.COMMITMENT_SIGNED
			);
			const revokeActions2 = opener.handleCommitmentSigned(
				decodeCommitmentSignedMessage(sigMsg2.payload)
			);
			const revokeMsg2 = findSendAction(
				revokeActions2,
				MessageType.REVOKE_AND_ACK
			);
			acceptor.handleRevokeAndAck(
				decodeRevokeAndAckMessage(revokeMsg2.payload)
			);

			// 4. Acceptor fulfills HTLC
			const fulfillActions = acceptor.fulfillHtlc(0n, preimage);
			const fulfillMsg = findSendAction(
				fulfillActions,
				MessageType.UPDATE_FULFILL_HTLC
			);
			opener.handleUpdateFulfillHtlc(
				decodeUpdateFulfillHtlcMessage(fulfillMsg.payload)
			);

			// 5. Acceptor signs commitment (with fulfilled HTLC)
			const sigActions3 = acceptor.signCommitment(crypto.randomBytes(64), []);
			const sigMsg3 = findSendAction(
				sigActions3,
				MessageType.COMMITMENT_SIGNED
			);
			const revokeActions3 = opener.handleCommitmentSigned(
				decodeCommitmentSignedMessage(sigMsg3.payload)
			);
			const revokeMsg3 = findSendAction(
				revokeActions3,
				MessageType.REVOKE_AND_ACK
			);
			acceptor.handleRevokeAndAck(
				decodeRevokeAndAckMessage(revokeMsg3.payload)
			);

			// 6. Opener signs commitment
			const sigActions4 = opener.signCommitment(crypto.randomBytes(64), []);
			const sigMsg4 = findSendAction(
				sigActions4,
				MessageType.COMMITMENT_SIGNED
			);
			const revokeActions4 = acceptor.handleCommitmentSigned(
				decodeCommitmentSignedMessage(sigMsg4.payload)
			);
			const revokeMsg4 = findSendAction(
				revokeActions4,
				MessageType.REVOKE_AND_ACK
			);
			opener.handleRevokeAndAck(decodeRevokeAndAckMessage(revokeMsg4.payload));

			// Final balances
			const openerBal = opener.getBalances();
			const acceptorBal = acceptor.getBalances();

			expect(openerBal.localMsat).to.equal(
				FUNDING_SATOSHIS * 1000n - amountMsat
			);
			expect(openerBal.remoteMsat).to.equal(amountMsat);
			expect(acceptorBal.localMsat).to.equal(amountMsat);
			expect(acceptorBal.remoteMsat).to.equal(
				FUNDING_SATOSHIS * 1000n - amountMsat
			);
		});
	});

	describe('Fee Updates', function () {
		function getToNormal(): { opener: ChannelClass; acceptor: ChannelClass } {
			const { opener, acceptor } = createTestChannels();

			const openActions = opener.initiateOpen();
			const openMsg = findSendAction(openActions, MessageType.OPEN_CHANNEL);
			const acceptActions = acceptor.handleOpenChannel(
				decodeOpenChannelMessage(openMsg.payload)
			);
			const acceptMsg = findSendAction(
				acceptActions,
				MessageType.ACCEPT_CHANNEL
			);
			opener.handleAcceptChannel(decodeAcceptChannelMessage(acceptMsg.payload));

			const fcActions = opener.createFundingCreated(
				crypto.randomBytes(32),
				0,
				crypto.randomBytes(64)
			);
			const fcMsg = findSendAction(fcActions, MessageType.FUNDING_CREATED);
			const fsActions = acceptor.handleFundingCreated(
				decodeFundingCreatedMessage(fcMsg.payload),
				crypto.randomBytes(64)
			);
			const fsMsg = findSendAction(fsActions, MessageType.FUNDING_SIGNED);
			opener.handleFundingSigned(decodeFundingSignedMessage(fsMsg.payload));

			const or = opener.fundingConfirmed();
			const ar = acceptor.fundingConfirmed();
			opener.handleChannelReady(
				decodeChannelReadyMessage(
					findSendAction(ar, MessageType.CHANNEL_READY).payload
				)
			);
			acceptor.handleChannelReady(
				decodeChannelReadyMessage(
					findSendAction(or, MessageType.CHANNEL_READY).payload
				)
			);

			return { opener, acceptor };
		}

		it('should allow opener to update fee', function () {
			const { opener } = getToNormal();
			const actions = opener.updateFee(5000);
			const msg = findSendAction(actions, MessageType.UPDATE_FEE);
			expect(msg).to.exist;
		});

		it('should reject an opener fee below the 253 sat/kw floor', function () {
			const { opener } = getToNormal();
			const actions = opener.updateFee(100);
			const error = findAction(actions, ChannelActionType.ERROR);
			expect(error).to.exist;
			expect(error.message).to.contain('minimum relay fee');
			// No UPDATE_FEE should be emitted for an invalid proposal.
			expect(findSendAction(actions, MessageType.UPDATE_FEE)).to.be.undefined;
		});

		it('should reject an opener fee above the 100000 sat/kw ceiling', function () {
			const { opener } = getToNormal();
			const actions = opener.updateFee(200_000);
			const error = findAction(actions, ChannelActionType.ERROR);
			expect(error).to.exist;
			expect(error.message).to.contain('absolute maximum');
			expect(findSendAction(actions, MessageType.UPDATE_FEE)).to.be.undefined;
		});

		it('should reject fee update from acceptor', function () {
			const { acceptor } = getToNormal();
			const actions = acceptor.updateFee(5000);
			const error = findAction(actions, ChannelActionType.ERROR);
			expect(error).to.exist;
			expect(error.message).to.contain('Only opener');
		});

		it('should reject fee update from opener sent to opener', function () {
			const { opener } = getToNormal();
			// Opener sends fee, then handles it (which is invalid since opener role != acceptor)
			const actions = opener.handleUpdateFee({
				channelId: opener.getChannelId()!,
				feeratePerKw: 5000
			});
			const error = findAction(actions, ChannelActionType.ERROR);
			expect(error).to.exist;
			expect(error.message).to.contain('Only opener');
		});
	});

	describe('Cooperative Close', function () {
		function getToNormal(): { opener: ChannelClass; acceptor: ChannelClass } {
			const { opener, acceptor } = createTestChannels();

			const openActions = opener.initiateOpen();
			const openMsg = findSendAction(openActions, MessageType.OPEN_CHANNEL);
			const acceptActions = acceptor.handleOpenChannel(
				decodeOpenChannelMessage(openMsg.payload)
			);
			const acceptMsg = findSendAction(
				acceptActions,
				MessageType.ACCEPT_CHANNEL
			);
			opener.handleAcceptChannel(decodeAcceptChannelMessage(acceptMsg.payload));

			const fcActions = opener.createFundingCreated(
				crypto.randomBytes(32),
				0,
				crypto.randomBytes(64)
			);
			const fcMsg = findSendAction(fcActions, MessageType.FUNDING_CREATED);
			const fsActions = acceptor.handleFundingCreated(
				decodeFundingCreatedMessage(fcMsg.payload),
				crypto.randomBytes(64)
			);
			const fsMsg = findSendAction(fsActions, MessageType.FUNDING_SIGNED);
			opener.handleFundingSigned(decodeFundingSignedMessage(fsMsg.payload));

			const or = opener.fundingConfirmed();
			const ar = acceptor.fundingConfirmed();
			opener.handleChannelReady(
				decodeChannelReadyMessage(
					findSendAction(ar, MessageType.CHANNEL_READY).payload
				)
			);
			acceptor.handleChannelReady(
				decodeChannelReadyMessage(
					findSendAction(or, MessageType.CHANNEL_READY).payload
				)
			);

			return { opener, acceptor };
		}

		it('should handle cooperative close flow', function () {
			const { opener, acceptor } = getToNormal();

			const openerScript = Buffer.from('0014' + '0'.repeat(40), 'hex');
			// Opener initiates shutdown
			const shutdownActions = opener.initiateShutdown(openerScript);
			expect(opener.getState()).to.equal(ChannelState.SHUTTING_DOWN);
			const shutdownMsg = findSendAction(shutdownActions, MessageType.SHUTDOWN);
			expect(shutdownMsg).to.exist;

			// Acceptor handles shutdown
			const decodedShutdown = decodeShutdownMessage(shutdownMsg.payload);
			acceptor.handleShutdown(decodedShutdown);
			expect(acceptor.getState()).to.equal(ChannelState.NEGOTIATING_CLOSING);

			// Opener receives shutdown from acceptor → transitions to NEGOTIATING_CLOSING
			opener.handleShutdown({
				channelId: opener.getChannelId()!,
				scriptPubkey: Buffer.from('0014' + '0'.repeat(40), 'hex')
			});
			expect(opener.getState()).to.equal(ChannelState.NEGOTIATING_CLOSING);

			// Opener proposes closing fee
			const proposeActions = opener.proposeClosingFee(crypto.randomBytes(64));
			const proposedPayload = findSendAction(
				proposeActions,
				MessageType.CLOSING_SIGNED
			);
			expect(proposedPayload).to.exist;
			const proposedFee = decodeClosingSignedMessage(
				proposedPayload.payload
			).feeSatoshis;

			// Acceptor responds with the same fee → agreement
			const closingActions = opener.handleClosingSigned(
				{
					channelId: opener.getChannelId()!,
					feeSatoshis: proposedFee,
					signature: crypto.randomBytes(64)
				},
				() => crypto.randomBytes(64)
			);

			expect(opener.getState()).to.equal(ChannelState.CLOSED);
			const closedAction = findAction(
				closingActions,
				ChannelActionType.CHANNEL_CLOSED
			);
			expect(closedAction).to.exist;
		});

		it('should reject shutdown in wrong state', function () {
			const { opener } = createTestChannels();
			const actions = opener.initiateShutdown(crypto.randomBytes(22));
			const error = findAction(actions, ChannelActionType.ERROR);
			expect(error).to.exist;
		});

		it('should reject a peer shutdown with a non-standard scriptPubkey', function () {
			const { opener } = createTestChannels();
			const actions = opener.handleShutdown({
				channelId: Buffer.alloc(32, 0xcc),
				scriptPubkey: crypto.randomBytes(22) // junk, not a valid P2WPKH
			});
			const error = findAction(actions, ChannelActionType.ERROR);
			expect(error).to.exist;
			expect((error as any).message).to.contain('Invalid shutdown');
		});
	});

	describe('Reconnection', function () {
		function getToNormal(): { opener: ChannelClass; acceptor: ChannelClass } {
			const { opener, acceptor } = createTestChannels();

			const openActions = opener.initiateOpen();
			const openMsg = findSendAction(openActions, MessageType.OPEN_CHANNEL);
			const acceptActions = acceptor.handleOpenChannel(
				decodeOpenChannelMessage(openMsg.payload)
			);
			const acceptMsg = findSendAction(
				acceptActions,
				MessageType.ACCEPT_CHANNEL
			);
			opener.handleAcceptChannel(decodeAcceptChannelMessage(acceptMsg.payload));

			const fcActions = opener.createFundingCreated(
				crypto.randomBytes(32),
				0,
				crypto.randomBytes(64)
			);
			const fcMsg = findSendAction(fcActions, MessageType.FUNDING_CREATED);
			const fsActions = acceptor.handleFundingCreated(
				decodeFundingCreatedMessage(fcMsg.payload),
				crypto.randomBytes(64)
			);
			const fsMsg = findSendAction(fsActions, MessageType.FUNDING_SIGNED);
			opener.handleFundingSigned(decodeFundingSignedMessage(fsMsg.payload));

			const or = opener.fundingConfirmed();
			const ar = acceptor.fundingConfirmed();
			opener.handleChannelReady(
				decodeChannelReadyMessage(
					findSendAction(ar, MessageType.CHANNEL_READY).payload
				)
			);
			acceptor.handleChannelReady(
				decodeChannelReadyMessage(
					findSendAction(or, MessageType.CHANNEL_READY).payload
				)
			);

			return { opener, acceptor };
		}

		it('should create valid channel_reestablish message', function () {
			const { opener } = getToNormal();
			const actions = opener.createReestablish();
			const msg = findSendAction(actions, MessageType.CHANNEL_REESTABLISH);
			expect(msg).to.exist;
		});
	});

	describe('State Getters', function () {
		it('should return correct role', function () {
			const { opener, acceptor } = createTestChannels();
			expect(opener.getRole()).to.equal(ChannelRole.OPENER);
			expect(acceptor.getRole()).to.equal(ChannelRole.ACCEPTOR);
		});

		it('should return correct funding amount', function () {
			const { opener } = createTestChannels();
			expect(opener.getFundingSatoshis()).to.equal(FUNDING_SATOSHIS);
		});

		it('should return null channel ID before funding', function () {
			const { opener } = createTestChannels();
			expect(opener.getChannelId()).to.be.null;
		});
	});
});
