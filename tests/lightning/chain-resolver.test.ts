import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	createOpenerState,
	createAcceptorState
} from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	ChannelRole,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { Channel } from '../../src/lightning/channel/channel';
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
import {
	buildLocalCommitment,
	buildRemoteCommitment
} from '../../src/lightning/channel/commitment-builder';
import {
	calculateObscuredCommitmentNumber,
	buildToLocalScript
} from '../../src/lightning/script/commitment';
import { buildPenaltyTx } from '../../src/lightning/script/revocation';
import { buildClosingTx } from '../../src/lightning/chain/closing';
import {
	extractCommitmentNumber,
	classifyCommitmentTx,
	classifyOutputs,
	resolveOurCommitmentOutputs,
	resolveTheirCurrentCommitmentOutputs,
	resolveRevokedCommitmentOutputs,
	resolveSecondLevelHtlcOutput,
	extractPreimageFromWitness
} from '../../src/lightning/chain/output-resolver';
import {
	CommitmentType,
	OutputType,
	OutputStatus
} from '../../src/lightning/chain/types';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import { perCommitmentPointFromSecret } from '../../src/lightning/keys/derivation';

bitcoin.initEccLib(ecc);

const network = bitcoin.networks.regtest;

function makeBasepoints(seed: Buffer): {
	basepoints: IChannelBasepoints;
	privkeys: Buffer[];
} {
	const privkeys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		const privkey = crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([i]))
			.digest();
		privkeys.push(privkey);
	}
	return {
		basepoints: {
			fundingPubkey: getPublicKey(privkeys[0]),
			revocationBasepoint: getPublicKey(privkeys[1]),
			paymentBasepoint: getPublicKey(privkeys[2]),
			delayedPaymentBasepoint: getPublicKey(privkeys[3]),
			htlcBasepoint: getPublicKey(privkeys[4]),
			firstPerCommitmentPoint: Buffer.alloc(33)
		},
		privkeys
	};
}

function findSendAction(actions: any[], msgType: MessageType): any {
	return actions.find(
		(a: any) =>
			a.type === ChannelActionType.SEND_MESSAGE && a.messageType === msgType
	);
}

/**
 * Set up two channels through the full opening handshake and into NORMAL state.
 */
function setupNormalChannels(): {
	opener: Channel;
	acceptor: Channel;
	openerPrivkeys: Buffer[];
	acceptorPrivkeys: Buffer[];
	openerCommitmentSeed: Buffer;
	acceptorCommitmentSeed: Buffer;
} {
	const openerSeed = Buffer.alloc(32, 0x11);
	const acceptorSeed = Buffer.alloc(32, 0x22);
	const openerCommitmentSeed = crypto
		.createHash('sha256')
		.update(Buffer.from('resolver-opener'))
		.digest();
	const acceptorCommitmentSeed = crypto
		.createHash('sha256')
		.update(Buffer.from('resolver-acceptor'))
		.digest();

	const { basepoints: openerBasepoints, privkeys: openerPrivkeys } =
		makeBasepoints(openerSeed);
	const { basepoints: acceptorBasepoints, privkeys: acceptorPrivkeys } =
		makeBasepoints(acceptorSeed);

	const openerState = createOpenerState({
		temporaryChannelId: Buffer.alloc(32, 0xbb),
		fundingSatoshis: 1_000_000n,
		pushMsat: 200_000_000n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: openerBasepoints,
		localPerCommitmentSeed: openerCommitmentSeed
	});

	const opener = new Channel(openerState);

	const acceptorState = createAcceptorState({
		temporaryChannelId: Buffer.alloc(32, 0xbb),
		fundingSatoshis: 0n,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: acceptorBasepoints,
		localPerCommitmentSeed: acceptorCommitmentSeed,
		remoteBasepoints: openerBasepoints,
		remoteConfig: { ...DEFAULT_CHANNEL_CONFIG }
	});

	const acceptor = new Channel(acceptorState);

	// Opening handshake
	const openActions = opener.initiateOpen();
	const openMsg = findSendAction(openActions, MessageType.OPEN_CHANNEL);
	const acceptActions = acceptor.handleOpenChannel(
		decodeOpenChannelMessage(openMsg.payload)
	);
	const acceptMsg = findSendAction(acceptActions, MessageType.ACCEPT_CHANNEL);
	opener.handleAcceptChannel(decodeAcceptChannelMessage(acceptMsg.payload));

	const fundingTxid = crypto.randomBytes(32);
	const fakeSig = crypto.randomBytes(64);
	const fcActions = opener.createFundingCreated(fundingTxid, 0, fakeSig);
	const fcMsg = findSendAction(fcActions, MessageType.FUNDING_CREATED);
	const fsActions = acceptor.handleFundingCreated(
		decodeFundingCreatedMessage(fcMsg.payload),
		crypto.randomBytes(64)
	);
	const fsMsg = findSendAction(fsActions, MessageType.FUNDING_SIGNED);
	opener.handleFundingSigned(decodeFundingSignedMessage(fsMsg.payload));

	// Funding confirmed + channel ready
	const openerReadyActions = opener.fundingConfirmed();
	const openerReadyMsg = findSendAction(
		openerReadyActions,
		MessageType.CHANNEL_READY
	);
	acceptor.handleChannelReady(
		decodeChannelReadyMessage(openerReadyMsg.payload)
	);

	const acceptorReadyActions = acceptor.fundingConfirmed();
	const acceptorReadyMsg = findSendAction(
		acceptorReadyActions,
		MessageType.CHANNEL_READY
	);
	opener.handleChannelReady(
		decodeChannelReadyMessage(acceptorReadyMsg.payload)
	);

	expect(opener.getState()).to.equal(ChannelState.NORMAL);
	expect(acceptor.getState()).to.equal(ChannelState.NORMAL);

	return {
		opener,
		acceptor,
		openerPrivkeys,
		acceptorPrivkeys,
		openerCommitmentSeed,
		acceptorCommitmentSeed
	};
}

/**
 * Exchange commitment signatures between two channels.
 */
function exchangeCommitments(opener: Channel, acceptor: Channel): void {
	const sig1 = crypto.randomBytes(64);
	const commitActions1 = opener.signCommitment(sig1, []);
	const commitMsg1 = findSendAction(
		commitActions1,
		MessageType.COMMITMENT_SIGNED
	);
	const csMsg1 = decodeCommitmentSignedMessage(commitMsg1.payload);
	const raaActions1 = acceptor.handleCommitmentSigned(csMsg1);
	const raaMsg1 = findSendAction(raaActions1, MessageType.REVOKE_AND_ACK);
	opener.handleRevokeAndAck(decodeRevokeAndAckMessage(raaMsg1.payload));

	const sig2 = crypto.randomBytes(64);
	const commitActions2 = acceptor.signCommitment(sig2, []);
	const commitMsg2 = findSendAction(
		commitActions2,
		MessageType.COMMITMENT_SIGNED
	);
	const csMsg2 = decodeCommitmentSignedMessage(commitMsg2.payload);
	const raaActions2 = opener.handleCommitmentSigned(csMsg2);
	const raaMsg2 = findSendAction(raaActions2, MessageType.REVOKE_AND_ACK);
	acceptor.handleRevokeAndAck(decodeRevokeAndAckMessage(raaMsg2.payload));
}

describe('Output Resolver (Phase 4B)', function () {
	describe('extractCommitmentNumber', function () {
		it('should extract commitment number 0 from a fresh commitment', function () {
			const { opener } = setupNormalChannels();
			const state = opener.getFullState();

			const perCommitmentSecret = generateFromSeed(
				state.localPerCommitmentSeed,
				MAX_INDEX - 0n
			);
			const perCommitmentPoint =
				perCommitmentPointFromSecret(perCommitmentSecret);
			const built = buildLocalCommitment(state, perCommitmentPoint);

			const isOpener = state.role === ChannelRole.OPENER;
			const openPBP = isOpener
				? state.localBasepoints.paymentBasepoint
				: state.remoteBasepoints!.paymentBasepoint;
			const acceptPBP = isOpener
				? state.remoteBasepoints!.paymentBasepoint
				: state.localBasepoints.paymentBasepoint;

			const extracted = extractCommitmentNumber(
				built.result.tx,
				openPBP,
				acceptPBP
			);

			expect(extracted).to.equal(0n);
		});

		it('should round-trip an arbitrary commitment number', function () {
			const openPBP = getPublicKey(crypto.randomBytes(32));
			const acceptPBP = getPublicKey(crypto.randomBytes(32));
			const commitmentNumber = 42n;

			const obscured = calculateObscuredCommitmentNumber(
				openPBP,
				acceptPBP,
				commitmentNumber
			);

			// Build a mock tx with the obscured values
			const tx = new bitcoin.Transaction();
			tx.version = 2;
			tx.locktime = 0x20000000 | Number(obscured & 0xffffffn);
			const sequence =
				(0x80000000 | Number((obscured >> 24n) & 0xffffffn)) >>> 0;
			tx.addInput(Buffer.alloc(32), 0, sequence);

			const extracted = extractCommitmentNumber(tx, openPBP, acceptPBP);
			expect(extracted).to.equal(commitmentNumber);
		});

		it('should round-trip commitment number after updates', function () {
			const openPBP = getPublicKey(crypto.randomBytes(32));
			const acceptPBP = getPublicKey(crypto.randomBytes(32));

			for (const num of [0n, 1n, 100n, 65535n, 16777215n]) {
				const obscured = calculateObscuredCommitmentNumber(
					openPBP,
					acceptPBP,
					num
				);
				const tx = new bitcoin.Transaction();
				tx.version = 2;
				tx.locktime = 0x20000000 | Number(obscured & 0xffffffn);
				const seq = (0x80000000 | Number((obscured >> 24n) & 0xffffffn)) >>> 0;
				tx.addInput(Buffer.alloc(32), 0, seq);

				const extracted = extractCommitmentNumber(tx, openPBP, acceptPBP);
				expect(extracted).to.equal(num);
			}
		});
	});

	describe('classifyCommitmentTx', function () {
		it('should classify a cooperative close', function () {
			const { opener } = setupNormalChannels();
			const state = opener.getFullState();

			// Build a cooperative closing tx (locktime 0, sequence 0xFFFFFFFF)
			const closingResult = buildClosingTx({
				fundingTxid: state.fundingTxid!.toString('hex'),
				fundingOutputIndex: state.fundingOutputIndex,
				fundingAmount: state.fundingSatoshis,
				localScriptPubkey: Buffer.alloc(22, 0x01),
				remoteScriptPubkey: Buffer.alloc(22, 0x02),
				localAmount: 500_000n,
				remoteAmount: 499_000n,
				feeAmount: 1_000n
			});

			const result = classifyCommitmentTx(closingResult.tx, state);
			expect(result.type).to.equal(CommitmentType.COOPERATIVE_CLOSE);
		});

		it('should classify our commitment', function () {
			const { opener } = setupNormalChannels();
			const state = opener.getFullState();

			const perCommitmentSecret = generateFromSeed(
				state.localPerCommitmentSeed,
				MAX_INDEX - state.localCommitmentNumber
			);
			const perCommitmentPoint =
				perCommitmentPointFromSecret(perCommitmentSecret);
			const built = buildLocalCommitment(state, perCommitmentPoint);

			const result = classifyCommitmentTx(built.result.tx, state);
			expect(result.type).to.equal(CommitmentType.OUR_COMMITMENT);
			expect(result.commitmentNumber).to.equal(state.localCommitmentNumber);
		});

		it('should classify their current commitment', function () {
			const { opener } = setupNormalChannels();
			const state = opener.getFullState();

			const remotePerCommitmentPoint = state.remoteCurrentPerCommitmentPoint!;
			const built = buildRemoteCommitment(state, remotePerCommitmentPoint);

			const result = classifyCommitmentTx(built.result.tx, state);
			expect(result.type).to.equal(CommitmentType.THEIR_CURRENT_COMMITMENT);
			expect(result.commitmentNumber).to.equal(state.remoteCommitmentNumber);
		});

		it('should classify a revoked commitment', function () {
			const { opener, acceptor } = setupNormalChannels();

			// Exchange commitments to advance and store secrets
			exchangeCommitments(opener, acceptor);

			const state = opener.getFullState();

			// Build what would have been remote's commitment at number 0
			// After one exchange, remote is at number 1, so 0 is revoked
			const secretIndex = MAX_INDEX - 0n;
			const secret = state.shaChainStore.getSecret(secretIndex);
			expect(secret).to.not.be.null;

			// Build the old remote commitment
			// We need a state snapshot at commitment 0, but let's just verify
			// the classification by checking if the number < remoteCommitmentNumber
			// and we have the secret
			const obscured = calculateObscuredCommitmentNumber(
				state.localBasepoints.paymentBasepoint,
				state.remoteBasepoints!.paymentBasepoint,
				0n
			);

			const tx = new bitcoin.Transaction();
			tx.version = 2;
			tx.locktime = 0x20000000 | Number(obscured & 0xffffffn);
			const seq = (0x80000000 | Number((obscured >> 24n) & 0xffffffn)) >>> 0;
			const fundingTxidBuf = Buffer.from(
				state.fundingTxid!.toString('hex'),
				'hex'
			).reverse();
			tx.addInput(fundingTxidBuf, state.fundingOutputIndex, seq);
			tx.addOutput(Buffer.alloc(34), 500_000);

			const result = classifyCommitmentTx(tx, state);
			expect(result.type).to.equal(CommitmentType.THEIR_REVOKED_COMMITMENT);
			expect(result.commitmentNumber).to.equal(0n);
		});

		it('classifies a revoked commitment whose index equals localCommitmentNumber as a breach, not ours (C1)', function () {
			// C1 fund-safety regression: mid-round where WE are the initiator, our
			// localCommitmentNumber lags remoteCommitmentNumber by one, so the peer's
			// REVOKED commitment shares the index of our current local commitment. It
			// must be classified THEIR_REVOKED (→ penalty), never OUR_COMMITMENT.
			const { opener, acceptor } = setupNormalChannels();

			// Capture the peer's per-commitment point #0 and build their commitment #0
			// BEFORE the half-round (balances are unchanged, only the index/keys matter).
			const preState = opener.getFullState();
			const peerPoint0 = preState.remoteCurrentPerCommitmentPoint!;
			const peerRevokedTx = buildRemoteCommitment(preState, peerPoint0, 0n)
				.result.tx;

			// Half a commitment round: opener signs (remoteCommitmentNumber 0→1) and
			// consumes the peer's revoke_and_ack (stores secret #0), but never receives
			// the peer's commitment_signed, so localCommitmentNumber stays 0.
			const sig = crypto.randomBytes(64);
			const commitActions = opener.signCommitment(sig, []);
			const commitMsg = findSendAction(
				commitActions,
				MessageType.COMMITMENT_SIGNED
			);
			const raaActions = acceptor.handleCommitmentSigned(
				decodeCommitmentSignedMessage(commitMsg.payload)
			);
			const raaMsg = findSendAction(raaActions, MessageType.REVOKE_AND_ACK);
			opener.handleRevokeAndAck(decodeRevokeAndAckMessage(raaMsg.payload));

			const c1State = opener.getFullState();
			// Precondition: the exact ambiguous configuration.
			expect(c1State.localCommitmentNumber).to.equal(0n);
			expect(c1State.remoteCommitmentNumber).to.equal(1n);
			expect(c1State.shaChainStore.getSecret(MAX_INDEX - 0n)).to.not.be.null;

			// The peer's revoked commitment #0 must be recognized as a breach.
			const breach = classifyCommitmentTx(peerRevokedTx, c1State);
			expect(breach.type).to.equal(CommitmentType.THEIR_REVOKED_COMMITMENT);
			expect(breach.commitmentNumber).to.equal(0n);

			// Sanity: OUR OWN commitment #0 broadcast in the same state is still ours.
			const ourPoint0 = perCommitmentPointFromSecret(
				generateFromSeed(c1State.localPerCommitmentSeed, MAX_INDEX - 0n)
			);
			const ourTx = buildLocalCommitment(c1State, ourPoint0, 0n).result.tx;
			const ours = classifyCommitmentTx(ourTx, c1State);
			expect(ours.type).to.equal(CommitmentType.OUR_COMMITMENT);
		});

		it('should return UNKNOWN for unrecognized commitment', function () {
			const { opener } = setupNormalChannels();
			const state = opener.getFullState();

			// Build a tx with a commitment number we don't recognize
			const obscured = calculateObscuredCommitmentNumber(
				state.localBasepoints.paymentBasepoint,
				state.remoteBasepoints!.paymentBasepoint,
				999n // neither local nor remote
			);

			const tx = new bitcoin.Transaction();
			tx.version = 2;
			tx.locktime = 0x20000000 | Number(obscured & 0xffffffn);
			const seq = (0x80000000 | Number((obscured >> 24n) & 0xffffffn)) >>> 0;
			const fundingTxidBuf = Buffer.from(
				state.fundingTxid!.toString('hex'),
				'hex'
			).reverse();
			tx.addInput(fundingTxidBuf, state.fundingOutputIndex, seq);
			tx.addOutput(Buffer.alloc(34), 500_000);

			const result = classifyCommitmentTx(tx, state);
			expect(result.type).to.equal(CommitmentType.UNKNOWN);
		});
	});

	describe('classifyOutputs', function () {
		it('should classify to_local and to_remote on our commitment', function () {
			const { opener } = setupNormalChannels();
			const state = opener.getFullState();

			const perCommitmentSecret = generateFromSeed(
				state.localPerCommitmentSeed,
				MAX_INDEX - state.localCommitmentNumber
			);
			const perCommitmentPoint =
				perCommitmentPointFromSecret(perCommitmentSecret);
			const built = buildLocalCommitment(state, perCommitmentPoint);

			const outputs = classifyOutputs(
				built.result.tx,
				state,
				CommitmentType.OUR_COMMITMENT,
				state.localCommitmentNumber
			);

			// Should have both to_local and to_remote
			const toLocal = outputs.find((o) => o.outputType === OutputType.TO_LOCAL);
			const toRemote = outputs.find(
				(o) => o.outputType === OutputType.TO_REMOTE
			);

			expect(toLocal).to.exist;
			expect(toRemote).to.exist;
			expect(toLocal!.witnessScript).to.not.be.undefined;
		});

		it('should classify to_local and to_remote on their commitment', function () {
			const { opener } = setupNormalChannels();
			const state = opener.getFullState();

			const remotePerCommitmentPoint = state.remoteCurrentPerCommitmentPoint!;
			const built = buildRemoteCommitment(state, remotePerCommitmentPoint);

			const outputs = classifyOutputs(
				built.result.tx,
				state,
				CommitmentType.THEIR_CURRENT_COMMITMENT,
				state.remoteCommitmentNumber
			);

			const toLocal = outputs.find((o) => o.outputType === OutputType.TO_LOCAL);
			const toRemote = outputs.find(
				(o) => o.outputType === OutputType.TO_REMOTE
			);

			expect(toLocal).to.exist;
			expect(toRemote).to.exist;
		});

		it('should classify HTLC outputs on our commitment', function () {
			const { opener } = setupNormalChannels();

			// Add an HTLC
			const preimage = crypto.randomBytes(32);
			const paymentHash = crypto.createHash('sha256').update(preimage).digest();
			opener.addHtlc(10_000_000n, paymentHash, 500, Buffer.alloc(1366));

			const state = opener.getFullState();
			const perCommitmentSecret = generateFromSeed(
				state.localPerCommitmentSeed,
				MAX_INDEX - state.localCommitmentNumber
			);
			const perCommitmentPoint =
				perCommitmentPointFromSecret(perCommitmentSecret);
			const built = buildLocalCommitment(state, perCommitmentPoint);

			const outputs = classifyOutputs(
				built.result.tx,
				state,
				CommitmentType.OUR_COMMITMENT,
				state.localCommitmentNumber
			);

			const htlcOutputs = outputs.filter(
				(o) =>
					o.outputType === OutputType.OFFERED_HTLC ||
					o.outputType === OutputType.RECEIVED_HTLC
			);
			expect(htlcOutputs.length).to.be.greaterThan(0);
			expect(htlcOutputs[0].paymentHash).to.deep.equal(paymentHash);
		});
	});

	describe('resolveOurCommitmentOutputs', function () {
		it('should produce a to_local sweep with CSV delay', function () {
			const { opener } = setupNormalChannels();
			const state = opener.getFullState();

			const perCommitmentSecret = generateFromSeed(
				state.localPerCommitmentSeed,
				MAX_INDEX - state.localCommitmentNumber
			);
			const perCommitmentPoint =
				perCommitmentPointFromSecret(perCommitmentSecret);
			const built = buildLocalCommitment(state, perCommitmentPoint);

			const trackedOutputs = classifyOutputs(
				built.result.tx,
				state,
				CommitmentType.OUR_COMMITMENT,
				state.localCommitmentNumber
			);

			const destScript = Buffer.alloc(22);
			destScript[0] = 0x00;
			destScript[1] = 0x14;

			const resolved = resolveOurCommitmentOutputs(
				state,
				trackedOutputs,
				state.localCommitmentNumber,
				destScript,
				4,
				new Map()
			);

			const toLocalResolution = resolved.find(
				(r) => r.trackedOutput.outputType === OutputType.TO_LOCAL
			);
			expect(toLocalResolution).to.exist;
			expect(toLocalResolution!.spendTx).to.exist;
			expect(toLocalResolution!.csvDelay).to.equal(
				state.remoteConfig.toSelfDelay
			);
			expect(toLocalResolution!.witness).to.exist;
			expect(toLocalResolution!.witness).to.have.length(3);
		});

		it('should produce HTLC-timeout for offered HTLCs', function () {
			const { opener } = setupNormalChannels();

			const preimage = crypto.randomBytes(32);
			const paymentHash = crypto.createHash('sha256').update(preimage).digest();
			opener.addHtlc(10_000_000n, paymentHash, 500, Buffer.alloc(1366));

			const state = opener.getFullState();
			const perCommitmentSecret = generateFromSeed(
				state.localPerCommitmentSeed,
				MAX_INDEX - state.localCommitmentNumber
			);
			const perCommitmentPoint =
				perCommitmentPointFromSecret(perCommitmentSecret);
			const built = buildLocalCommitment(state, perCommitmentPoint);

			const trackedOutputs = classifyOutputs(
				built.result.tx,
				state,
				CommitmentType.OUR_COMMITMENT,
				state.localCommitmentNumber
			);

			const destScript = Buffer.alloc(22);
			destScript[0] = 0x00;
			destScript[1] = 0x14;

			const resolved = resolveOurCommitmentOutputs(
				state,
				trackedOutputs,
				state.localCommitmentNumber,
				destScript,
				4,
				new Map()
			);

			const htlcResolution = resolved.find(
				(r) => r.trackedOutput.outputType === OutputType.OFFERED_HTLC
			);
			expect(htlcResolution).to.exist;
			expect(htlcResolution!.spendTx).to.exist;
			expect(htlcResolution!.cltvExpiry).to.equal(500);
		});
	});

	describe('resolveTheirCurrentCommitmentOutputs', function () {
		it('should produce immediate to_remote claim', function () {
			const { opener, openerPrivkeys } = setupNormalChannels();
			const state = opener.getFullState();

			const remotePerCommitmentPoint = state.remoteCurrentPerCommitmentPoint!;
			const built = buildRemoteCommitment(state, remotePerCommitmentPoint);

			const trackedOutputs = classifyOutputs(
				built.result.tx,
				state,
				CommitmentType.THEIR_CURRENT_COMMITMENT,
				state.remoteCommitmentNumber
			);

			const destScript = Buffer.alloc(22);
			destScript[0] = 0x00;
			destScript[1] = 0x14;

			// Payment privkey is privkeys[2] (index 2 = payment basepoint)
			const paymentPrivkey = openerPrivkeys[2];

			const resolved = resolveTheirCurrentCommitmentOutputs(
				state,
				trackedOutputs,
				destScript,
				4,
				new Map(),
				paymentPrivkey
			);

			const toRemoteResolution = resolved.find(
				(r) => r.trackedOutput.outputType === OutputType.TO_REMOTE
			);
			expect(toRemoteResolution).to.exist;
			expect(toRemoteResolution!.spendTx).to.exist;
			// No CSV delay for to_remote
			expect(toRemoteResolution!.csvDelay).to.be.undefined;
			expect(toRemoteResolution!.witness).to.exist;
			expect(toRemoteResolution!.witness).to.have.length(2); // sig + pubkey
		});
	});

	describe('resolveRevokedCommitmentOutputs', function () {
		it('should produce penalty sweep for revoked to_local', function () {
			const { opener, acceptor, openerPrivkeys } = setupNormalChannels();

			// Exchange commitments to get a revocable state
			exchangeCommitments(opener, acceptor);

			const state = opener.getFullState();

			// The revoked commitment is at number 0
			const secretIndex = MAX_INDEX - 0n;
			const secret = state.shaChainStore.getSecret(secretIndex);
			expect(secret).to.not.be.null;

			const revokedPoint = perCommitmentPointFromSecret(secret!);

			// Rebuild the remote commitment at number 0
			// Use calculateObscuredCommitmentNumber for the old commitment
			const isOpener = state.role === ChannelRole.OPENER;
			const openPBP = isOpener
				? state.localBasepoints.paymentBasepoint
				: state.remoteBasepoints!.paymentBasepoint;
			const acceptPBP = isOpener
				? state.remoteBasepoints!.paymentBasepoint
				: state.localBasepoints.paymentBasepoint;

			// Build a simplified revoked commitment tx for testing
			const obscured = calculateObscuredCommitmentNumber(
				openPBP,
				acceptPBP,
				0n
			);
			const revokedTx = new bitcoin.Transaction();
			revokedTx.version = 2;
			revokedTx.locktime = 0x20000000 | Number(obscured & 0xffffffn);
			const seq = (0x80000000 | Number((obscured >> 24n) & 0xffffffn)) >>> 0;

			const fundingTxidBuf = Buffer.from(
				state.fundingTxid!.toString('hex'),
				'hex'
			).reverse();
			revokedTx.addInput(fundingTxidBuf, state.fundingOutputIndex, seq);

			// Add a to_local output (their delayed key, our revocation)
			const {
				deriveRevocationPubkey,
				derivePublicKey
			} = require('../../src/lightning/keys/derivation');
			const revocationPubkey = deriveRevocationPubkey(
				state.localBasepoints.revocationBasepoint,
				revokedPoint
			);
			const theirDelayedPubkey = derivePublicKey(
				state.remoteBasepoints!.delayedPaymentBasepoint,
				revokedPoint
			);
			const toLocalScript = buildToLocalScript(
				revocationPubkey,
				theirDelayedPubkey,
				state.localConfig.toSelfDelay
			);
			const p2wsh = bitcoin.payments.p2wsh({
				redeem: { output: toLocalScript }
			});
			revokedTx.addOutput(p2wsh.output!, 800_000);

			// Track outputs
			const trackedOutputs = [
				{
					txid: revokedTx.getId(),
					outputIndex: 0,
					amount: 800_000n,
					outputType: OutputType.TO_LOCAL as OutputType.TO_LOCAL,
					status: OutputStatus.CONFIRMED as OutputStatus.CONFIRMED,
					confirmationHeight: 100,
					witnessScript: toLocalScript
				}
			];

			const destScript = Buffer.alloc(22);
			destScript[0] = 0x00;
			destScript[1] = 0x14;
			crypto.randomBytes(20).copy(destScript, 2);

			// privkeys[1] is revocation basepoint secret
			const revocationBasepointSecret = openerPrivkeys[1];

			const resolved = resolveRevokedCommitmentOutputs(
				state,
				trackedOutputs,
				0n,
				revokedTx,
				destScript,
				10,
				revocationBasepointSecret,
				openerPrivkeys[0], // paymentPrivkey (unused: no to_remote output here)
				network
			);

			const penaltyResolution = resolved.find(
				(r) => r.trackedOutput.outputType === OutputType.TO_LOCAL
			);
			expect(penaltyResolution).to.exist;
			expect(penaltyResolution!.spendTx).to.exist;
			expect(penaltyResolution!.witness).to.exist;
		});

		it('H2: penalizes a revoked HTLC output reconstructed from the snapshot (HTLC gone from live state)', function () {
			const { opener, acceptor, openerPrivkeys } = setupNormalChannels();
			exchangeCommitments(opener, acceptor);
			const state = opener.getFullState();

			const secret = state.shaChainStore.getSecret(MAX_INDEX - 0n)!;
			const revokedPoint = perCommitmentPointFromSecret(secret);
			const {
				deriveRevocationPubkey,
				derivePublicKey
			} = require('../../src/lightning/keys/derivation');
			const {
				buildReceivedHtlcScript
			} = require('../../src/lightning/script/htlc');
			const { HtlcDirection } = require('../../src/lightning/channel/types');

			// An HTLC we offered that was present in revoked commitment #0 but has
			// since settled and been removed from live state.htlcs.
			const paymentHash = crypto.randomBytes(32);
			const cltvExpiry = 700_000;
			state.revokedHtlcSnapshots = new Map([
				[
					'0',
					[
						{
							paymentHash,
							amountMsat: 1_000_000n,
							cltvExpiry,
							direction: HtlcDirection.OFFERED
						}
					]
				]
			]);
			state.htlcs.clear(); // settled & forgotten

			// Reconstruct the exact HTLC output the cheater's commitment carries.
			const revocationPubkey = deriveRevocationPubkey(
				state.localBasepoints.revocationBasepoint,
				revokedPoint
			);
			const theirHtlc = derivePublicKey(
				state.remoteBasepoints!.htlcBasepoint,
				revokedPoint
			);
			const ourHtlc = derivePublicKey(
				state.localBasepoints.htlcBasepoint,
				revokedPoint
			);
			const htlcScript = buildReceivedHtlcScript(
				revocationPubkey,
				theirHtlc,
				ourHtlc,
				paymentHash,
				cltvExpiry,
				false
			);
			const htlcP2wsh = bitcoin.payments.p2wsh({
				redeem: { output: htlcScript }
			});

			const isOpener = state.role === ChannelRole.OPENER;
			const openPBP = isOpener
				? state.localBasepoints.paymentBasepoint
				: state.remoteBasepoints!.paymentBasepoint;
			const acceptPBP = isOpener
				? state.remoteBasepoints!.paymentBasepoint
				: state.localBasepoints.paymentBasepoint;
			const obscured = calculateObscuredCommitmentNumber(
				openPBP,
				acceptPBP,
				0n
			);
			const revokedTx = new bitcoin.Transaction();
			revokedTx.version = 2;
			revokedTx.locktime = 0x20000000 | Number(obscured & 0xffffffn);
			const seq = (0x80000000 | Number((obscured >> 24n) & 0xffffffn)) >>> 0;
			revokedTx.addInput(
				Buffer.from(state.fundingTxid!.toString('hex'), 'hex').reverse(),
				state.fundingOutputIndex,
				seq
			);
			revokedTx.addOutput(htlcP2wsh.output!, 100_000); // the revoked HTLC output

			const destScript = Buffer.alloc(22);
			destScript[0] = 0x00;
			destScript[1] = 0x14;
			crypto.randomBytes(20).copy(destScript, 2);

			// trackedOutputs is EMPTY — live classification missed the settled HTLC.
			const resolved = resolveRevokedCommitmentOutputs(
				state,
				[],
				0n,
				revokedTx,
				destScript,
				10,
				openerPrivkeys[1],
				openerPrivkeys[0],
				network
			);

			// The snapshot reconstruction must have brought the HTLC output into the
			// penalty: a spendTx exists for output index 0.
			const htlcPenalty = resolved.find(
				(r) => r.trackedOutput.outputIndex === 0 && r.spendTx
			);
			expect(htlcPenalty, 'revoked HTLC output must be penalized').to.exist;
			expect(htlcPenalty!.witness).to.exist;
		});
	});

	describe('resolveSecondLevelHtlcOutput (M2)', function () {
		it('builds a CSV sweep of our second-level HTLC output to the destination', function () {
			const { opener, openerPrivkeys } = setupNormalChannels();
			const state = opener.getFullState();
			const commitmentNumber = 0n;

			const {
				deriveRevocationPubkey,
				derivePublicKey
			} = require('../../src/lightning/keys/derivation');
			const {
				buildToLocalScript
			} = require('../../src/lightning/script/commitment');

			const point = perCommitmentPointFromSecret(
				generateFromSeed(
					state.localPerCommitmentSeed,
					MAX_INDEX - commitmentNumber
				)
			);
			const revocationPubkey = deriveRevocationPubkey(
				state.remoteBasepoints!.revocationBasepoint,
				point
			);
			const delayedPubkey = derivePublicKey(
				state.localBasepoints.delayedPaymentBasepoint,
				point
			);
			const toSelfDelay = state.remoteConfig.toSelfDelay;
			// A stand-in for our broadcast HTLC-timeout/success tx: out[0] is the
			// to_local-format second-level output.
			const script = buildToLocalScript(
				revocationPubkey,
				delayedPubkey,
				toSelfDelay
			);
			const p2wsh = bitcoin.payments.p2wsh({ redeem: { output: script } });
			const htlcTx = new bitcoin.Transaction();
			htlcTx.version = 2;
			htlcTx.addInput(crypto.randomBytes(32), 0);
			htlcTx.addOutput(p2wsh.output!, 90_000);

			const dest = Buffer.concat([
				Buffer.from([0x00, 0x14]),
				crypto.randomBytes(20)
			]);
			const r = resolveSecondLevelHtlcOutput(
				state,
				htlcTx,
				150,
				commitmentNumber,
				dest,
				10,
				openerPrivkeys[3], // delayed payment basepoint secret
				network
			);

			expect(r, 'a second-level sweep is produced').to.not.be.null;
			expect(r!.trackedOutput.outputType).to.equal(OutputType.TO_LOCAL);
			expect(r!.trackedOutput.txid).to.equal(htlcTx.getId());
			expect(r!.trackedOutput.outputIndex).to.equal(0);
			expect(r!.trackedOutput.confirmationHeight).to.equal(150);
			expect(r!.csvDelay).to.equal(toSelfDelay);
			expect(r!.witness, 'signed to_local delayed witness').to.exist;
			// The sweep spends htlcTx:0 (with the CSV sequence) and pays our destination.
			expect(
				Buffer.from(r!.spendTx!.ins[0].hash).reverse().toString('hex')
			).to.equal(htlcTx.getId());
			expect(r!.spendTx!.ins[0].sequence).to.equal(toSelfDelay);
			expect(r!.spendTx!.outs[0].script.equals(dest)).to.be.true;
		});

		it('returns null when out[0] is not our second-level to_local output', function () {
			const { opener, openerPrivkeys } = setupNormalChannels();
			const state = opener.getFullState();
			const htlcTx = new bitcoin.Transaction();
			htlcTx.version = 2;
			htlcTx.addInput(crypto.randomBytes(32), 0);
			// A random P2WPKH — not our reconstructed to_local script.
			htlcTx.addOutput(
				Buffer.concat([Buffer.from([0x00, 0x14]), crypto.randomBytes(20)]),
				90_000
			);
			const r = resolveSecondLevelHtlcOutput(
				state,
				htlcTx,
				150,
				0n,
				Buffer.concat([Buffer.from([0x00, 0x14]), crypto.randomBytes(20)]),
				10,
				openerPrivkeys[3],
				network
			);
			expect(r).to.be.null;
		});
	});

	describe('extractPreimageFromWitness', function () {
		it('should extract 32-byte preimage from HTLC-success witness', function () {
			const preimage = crypto.randomBytes(32);
			const witness = [
				Buffer.alloc(0), // OP_0
				Buffer.alloc(72), // remoteSig
				Buffer.alloc(72), // localSig
				preimage,
				Buffer.alloc(100) // witnessScript
			];

			const extracted = extractPreimageFromWitness(witness);
			expect(extracted).to.not.be.null;
			expect(extracted).to.deep.equal(preimage);
		});

		it('should return null for HTLC-timeout witness (no preimage)', function () {
			const witness = [
				Buffer.alloc(0), // OP_0
				Buffer.alloc(72), // remoteSig
				Buffer.alloc(72), // localSig
				Buffer.alloc(0), // OP_0 (timeout path)
				Buffer.alloc(100) // witnessScript
			];

			const extracted = extractPreimageFromWitness(witness);
			expect(extracted).to.be.null;
		});

		it('should return null for insufficient witness length', function () {
			const witness = [Buffer.alloc(0), Buffer.alloc(72)];
			const extracted = extractPreimageFromWitness(witness);
			expect(extracted).to.be.null;
		});

		it('should return null for empty witness', function () {
			const extracted = extractPreimageFromWitness([]);
			expect(extracted).to.be.null;
		});
	});

	// Regression guard for the HTLC remote-signature indexing (review item V1).
	// The resolver picks remoteHtlcSignatures[htlcSigIndex] for each HTLC output,
	// where htlcSigIndex is assigned by classifyOutputs in commitment-output order.
	// The signer (signRemoteCommitment) produces those signatures in
	// outputMap.htlcs order — also commitment-output order. This test pins the
	// invariant that the two orderings agree, so a mismatch (wrong peer signature
	// applied to an HTLC sweep → stuck funds) can never silently regress.
	describe('HTLC signature index ordering (V1)', function () {
		it('classifyOutputs htlcSigIndex matches signer outputMap.htlcs order for multiple HTLCs', function () {
			const { opener } = setupNormalChannels();

			// Two offered HTLCs with distinct amounts + expiries so they occupy
			// distinct, deterministically-ordered commitment outputs.
			const preimageA = crypto.randomBytes(32);
			const preimageB = crypto.randomBytes(32);
			const hashA = crypto.createHash('sha256').update(preimageA).digest();
			const hashB = crypto.createHash('sha256').update(preimageB).digest();
			opener.addHtlc(10_000_000n, hashA, 500, Buffer.alloc(1366));
			opener.addHtlc(50_000_000n, hashB, 600, Buffer.alloc(1366));

			const state = opener.getFullState();
			const perCommitmentSecret = generateFromSeed(
				state.localPerCommitmentSeed,
				MAX_INDEX - state.localCommitmentNumber
			);
			const perCommitmentPoint =
				perCommitmentPointFromSecret(perCommitmentSecret);
			const built = buildLocalCommitment(state, perCommitmentPoint);

			const trackedOutputs = classifyOutputs(
				built.result.tx,
				state,
				CommitmentType.OUR_COMMITMENT,
				state.localCommitmentNumber
			);

			const htlcOutputs = trackedOutputs.filter(
				(o) =>
					o.outputType === OutputType.OFFERED_HTLC ||
					o.outputType === OutputType.RECEIVED_HTLC
			);
			expect(htlcOutputs.length).to.equal(2);

			// Every HTLC output must carry a sig index, and that index must point
			// back to this exact output in the signer's output map.
			for (const o of htlcOutputs) {
				expect(o.htlcSigIndex, 'htlcSigIndex must be assigned').to.be.a(
					'number'
				);
				expect(built.result.outputMap.htlcs[o.htlcSigIndex!]).to.equal(
					o.outputIndex
				);
			}

			// Sig indices must be a contiguous 0..n-1 set (no gaps/dupes).
			const indices = htlcOutputs
				.map((o) => o.htlcSigIndex!)
				.sort((a, b) => a - b);
			expect(indices).to.deep.equal([0, 1]);
		});
	});

	// Review item V3: penalty (justice) tx fee estimation. The previous flat
	// "160 vbytes per input" figure roughly doubled the true per-input cost and
	// over-paid when sweeping many revoked outputs. The refined estimate must
	// stay strictly below the old one while still leaving a positive output.
	describe('Penalty tx fee estimation (V3)', function () {
		const destAddress = bitcoin.payments.p2wpkh({
			hash: Buffer.alloc(20, 0x07),
			network
		}).address!;
		const revocationPrivkey = crypto.randomBytes(32);

		function makeRevokedTx(
			outputCount: number,
			value: number
		): bitcoin.Transaction {
			const tx = new bitcoin.Transaction();
			tx.version = 2;
			const p2wsh = bitcoin.payments.p2wsh({
				redeem: {
					output: bitcoin.script.compile([bitcoin.opcodes.OP_TRUE]),
					network
				},
				network
			});
			for (let i = 0; i < outputCount; i++) {
				tx.addOutput(p2wsh.output!, value);
			}
			return tx;
		}

		function impliedFee(n: number, value: number, feeRate: number): number {
			const revokedTx = makeRevokedTx(n, value);
			const outputIndices = Array.from({ length: n }, (_, i) => i);
			const witnessScripts = new Map<number, Buffer>();
			// to_local-style witness script length (~83 bytes) for each output.
			outputIndices.forEach((i) => witnessScripts.set(i, Buffer.alloc(83)));
			const penalty = buildPenaltyTx({
				revokedTx,
				revocationPrivkey,
				destinationAddress: destAddress,
				feeRatePerVbyte: feeRate,
				outputIndices,
				witnessScripts,
				network
			} as any);
			const totalIn = n * value;
			return totalIn - penalty.outs[0].value;
		}

		it('charges less than the old flat 160-vbyte/input estimate', function () {
			const feeRate = 10;
			for (const n of [1, 3, 10]) {
				const oldFee = (10 + n * 160 + 31) * feeRate;
				const newFee = impliedFee(n, 1_000_000, feeRate);
				expect(newFee, `n=${n}`).to.be.lessThan(oldFee);
				expect(newFee, `n=${n} positive`).to.be.greaterThan(0);
			}
		});

		it('scales the fee with the number of swept outputs', function () {
			const feeRate = 10;
			const fee1 = impliedFee(1, 1_000_000, feeRate);
			const fee5 = impliedFee(5, 1_000_000, feeRate);
			expect(fee5).to.be.greaterThan(fee1);
		});
	});
});
