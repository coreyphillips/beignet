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
	DEFAULT_CHANNEL_CONFIG,
	HtlcDirection,
	HtlcState
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
import { ChainMonitor } from '../../src/lightning/chain/chain-monitor';
import {
	MonitorState,
	ChainActionType,
	OutputStatus,
	OutputType
} from '../../src/lightning/chain/types';
import { resolveRevokedSecondLevelOutput } from '../../src/lightning/chain/output-resolver';
import { estimateSweepVbytes } from '../../src/lightning/chain/sweep';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { MAX_INDEX } from '../../src/lightning/keys/shachain';
import {
	perCommitmentPointFromSecret,
	deriveRevocationPubkey,
	derivePublicKey
} from '../../src/lightning/keys/derivation';
import {
	buildToLocalScript,
	calculateObscuredCommitmentNumber
} from '../../src/lightning/script/commitment';
import { buildReceivedHtlcScript } from '../../src/lightning/script/htlc';

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

function setupNormalChannels(): {
	opener: Channel;
	acceptor: Channel;
	openerPrivkeys: Buffer[];
	acceptorPrivkeys: Buffer[];
} {
	const openerSeed = Buffer.alloc(32, 0x51);
	const acceptorSeed = Buffer.alloc(32, 0x52);
	const openerCommitmentSeed = crypto
		.createHash('sha256')
		.update(Buffer.from('second-level-justice-opener'))
		.digest();
	const acceptorCommitmentSeed = crypto
		.createHash('sha256')
		.update(Buffer.from('second-level-justice-acceptor'))
		.digest();

	const { basepoints: openerBasepoints, privkeys: openerPrivkeys } =
		makeBasepoints(openerSeed);
	const { basepoints: acceptorBasepoints, privkeys: acceptorPrivkeys } =
		makeBasepoints(acceptorSeed);

	const openerState = createOpenerState({
		temporaryChannelId: Buffer.alloc(32, 0xdd),
		fundingSatoshis: 1_000_000n,
		pushMsat: 200_000_000n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: openerBasepoints,
		localPerCommitmentSeed: openerCommitmentSeed
	});

	const opener = new Channel(openerState);

	const acceptorState = createAcceptorState({
		temporaryChannelId: Buffer.alloc(32, 0xdd),
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

	return { opener, acceptor, openerPrivkeys, acceptorPrivkeys };
}

function exchangeCommitments(opener: Channel, acceptor: Channel): void {
	const sig1 = crypto.randomBytes(64);
	const commitActions1 = opener.signCommitment(sig1, []);
	const commitMsg1 = findSendAction(
		commitActions1,
		MessageType.COMMITMENT_SIGNED
	);
	const raaActions1 = acceptor.handleCommitmentSigned(
		decodeCommitmentSignedMessage(commitMsg1.payload)
	);
	const raaMsg1 = findSendAction(raaActions1, MessageType.REVOKE_AND_ACK);
	opener.handleRevokeAndAck(decodeRevokeAndAckMessage(raaMsg1.payload));

	const sig2 = crypto.randomBytes(64);
	const commitActions2 = acceptor.signCommitment(sig2, []);
	const commitMsg2 = findSendAction(
		commitActions2,
		MessageType.COMMITMENT_SIGNED
	);
	const raaActions2 = opener.handleCommitmentSigned(
		decodeCommitmentSignedMessage(commitMsg2.payload)
	);
	const raaMsg2 = findSendAction(raaActions2, MessageType.REVOKE_AND_ACK);
	acceptor.handleRevokeAndAck(decodeRevokeAndAckMessage(raaMsg2.payload));
}

function makeP2wpkhScript(pubkey: Buffer): Buffer {
	return bitcoin.payments.p2wpkh({ pubkey, network }).output!;
}

/**
 * Build the exact to_local-format output the PEER's pre-signed second-level
 * HTLC tx creates on their revoked commitment #0: their delayed key, our
 * revocation key, the to_self_delay we demanded of them.
 */
function buildPeerSecondLevelScript(state: any, revokedPoint: Buffer): Buffer {
	const revocationPubkey = deriveRevocationPubkey(
		state.localBasepoints.revocationBasepoint,
		revokedPoint
	);
	const theirDelayedPubkey = derivePublicKey(
		state.remoteBasepoints!.delayedPaymentBasepoint,
		revokedPoint
	);
	return buildToLocalScript(
		revocationPubkey,
		theirDelayedPubkey,
		state.localConfig.toSelfDelay
	);
}

/** Revoked commitment #0 skeleton with the correct obscured-number encoding. */
function buildRevokedTxShell(state: any): bitcoin.Transaction {
	const isOpener = state.role === ChannelRole.OPENER;
	const openPBP = isOpener
		? state.localBasepoints.paymentBasepoint
		: state.remoteBasepoints!.paymentBasepoint;
	const acceptPBP = isOpener
		? state.remoteBasepoints!.paymentBasepoint
		: state.localBasepoints.paymentBasepoint;
	const obscured = calculateObscuredCommitmentNumber(openPBP, acceptPBP, 0n);
	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.locktime = 0x20000000 | Number(obscured & 0xffffffn);
	const seq = (0x80000000 | Number((obscured >> 24n) & 0xffffffn)) >>> 0;
	tx.addInput(
		Buffer.from(state.fundingTxid!.toString('hex'), 'hex').reverse(),
		state.fundingOutputIndex,
		seq
	);
	return tx;
}

describe('Revoked second-level HTLC justice (#8)', function () {
	describe('resolveRevokedSecondLevelOutput', function () {
		it('claims the peer second-level output via the revocation path (no timelock)', function () {
			const { opener, acceptor, openerPrivkeys } = setupNormalChannels();
			exchangeCommitments(opener, acceptor);
			const state = opener.getFullState();

			const secret = state.shaChainStore.getSecret(MAX_INDEX - 0n);
			expect(secret, 'revoked per-commitment secret available').to.not.be.null;
			const revokedPoint = perCommitmentPointFromSecret(secret!);
			const witnessScript = buildPeerSecondLevelScript(state, revokedPoint);
			const p2wsh = bitcoin.payments.p2wsh({
				redeem: { output: witnessScript }
			});

			// The cheater's HTLC-success/timeout tx. The claimable output sits at
			// index 1 behind a decoy — matching must scan every output, not just [0].
			const htlcTx = new bitcoin.Transaction();
			htlcTx.version = 2;
			htlcTx.addInput(crypto.randomBytes(32), 0);
			htlcTx.addOutput(
				Buffer.concat([Buffer.from([0x00, 0x14]), crypto.randomBytes(20)]),
				5_000
			);
			htlcTx.addOutput(p2wsh.output!, 90_000);

			const dest = Buffer.concat([
				Buffer.from([0x00, 0x14]),
				crypto.randomBytes(20)
			]);
			const resolved = resolveRevokedSecondLevelOutput(
				state,
				htlcTx,
				150,
				0n,
				dest,
				10,
				openerPrivkeys[1],
				network
			);

			expect(resolved).to.have.length(1);
			const r = resolved[0];
			expect(r.trackedOutput.txid).to.equal(htlcTx.getId());
			expect(r.trackedOutput.outputIndex).to.equal(1);
			expect(r.trackedOutput.outputType).to.equal(OutputType.TO_LOCAL);
			expect(r.trackedOutput.confirmationHeight).to.equal(150);
			expect(r.trackedOutput.amount).to.equal(90_000n);
			expect(r.csvDelay, 'revocation path has no CSV delay').to.be.undefined;

			// The claim spends htlcTx:1 with the revocation-branch witness.
			expect(r.spendTx).to.exist;
			expect(
				Buffer.from(r.spendTx!.ins[0].hash).reverse().toString('hex')
			).to.equal(htlcTx.getId());
			expect(r.spendTx!.ins[0].index).to.equal(1);
			expect(r.witness).to.have.length(3);
			expect(r.witness![1].equals(Buffer.from([0x01]))).to.be.true;
			expect(r.witness![2].equals(witnessScript)).to.be.true;

			// Pays our destination with the sweep fee deducted.
			const fee = Math.ceil(10 * estimateSweepVbytes(OutputType.TO_LOCAL));
			expect(r.spendTx!.outs[0].script.equals(dest)).to.be.true;
			expect(r.spendTx!.outs[0].value).to.equal(90_000 - fee);
		});

		it('returns an empty array when no output matches', function () {
			const { opener, acceptor, openerPrivkeys } = setupNormalChannels();
			exchangeCommitments(opener, acceptor);
			const state = opener.getFullState();

			const tx = new bitcoin.Transaction();
			tx.version = 2;
			tx.addInput(crypto.randomBytes(32), 0);
			tx.addOutput(
				Buffer.concat([Buffer.from([0x00, 0x14]), crypto.randomBytes(20)]),
				90_000
			);

			const resolved = resolveRevokedSecondLevelOutput(
				state,
				tx,
				150,
				0n,
				Buffer.concat([Buffer.from([0x00, 0x14]), crypto.randomBytes(20)]),
				10,
				openerPrivkeys[1],
				network
			);
			expect(resolved).to.have.length(0);
		});
	});

	describe('ChainMonitor.handleOutputSpent', function () {
		function setupRevokedBreach(): {
			monitor: ChainMonitor;
			state: any;
			revokedTx: bitcoin.Transaction;
			htlcIndex: number;
			secondLevelScript: Buffer;
			paymentHash: Buffer;
			preimage: Buffer;
		} {
			const { opener, acceptor, openerPrivkeys } = setupNormalChannels();
			exchangeCommitments(opener, acceptor);
			const state = opener.getFullState();

			// A live HTLC we offered — on the peer's commitment it is their
			// received-HTLC output, claimable by them via HTLC-success + preimage.
			const preimage = crypto.randomBytes(32);
			const paymentHash = crypto.createHash('sha256').update(preimage).digest();
			const cltvExpiry = 700_000;
			state.htlcs.set('OFFERED-0', {
				id: 0n,
				amountMsat: 100_000_000n,
				paymentHash,
				cltvExpiry,
				onionRoutingPacket: Buffer.alloc(0),
				direction: HtlcDirection.OFFERED,
				state: HtlcState.COMMITTED
			});

			const destScript = makeP2wpkhScript(getPublicKey(openerPrivkeys[0]));
			const monitor = new ChainMonitor(
				state,
				destScript,
				10,
				openerPrivkeys[1],
				openerPrivkeys[2],
				network
			);

			const secret = state.shaChainStore.getSecret(MAX_INDEX - 0n)!;
			const revokedPoint = perCommitmentPointFromSecret(secret);
			const revocationPubkey = deriveRevocationPubkey(
				state.localBasepoints.revocationBasepoint,
				revokedPoint
			);
			const theirDelayedPubkey = derivePublicKey(
				state.remoteBasepoints!.delayedPaymentBasepoint,
				revokedPoint
			);
			const theirHtlcPubkey = derivePublicKey(
				state.remoteBasepoints!.htlcBasepoint,
				revokedPoint
			);
			const ourHtlcPubkey = derivePublicKey(
				state.localBasepoints.htlcBasepoint,
				revokedPoint
			);

			// Their revoked commitment #0: their to_local at 0, the HTLC at 1.
			const revokedTx = buildRevokedTxShell(state);
			const toLocalScript = buildToLocalScript(
				revocationPubkey,
				theirDelayedPubkey,
				state.localConfig.toSelfDelay
			);
			revokedTx.addOutput(
				bitcoin.payments.p2wsh({ redeem: { output: toLocalScript } }).output!,
				700_000
			);
			const htlcScript = buildReceivedHtlcScript(
				revocationPubkey,
				theirHtlcPubkey,
				ourHtlcPubkey,
				paymentHash,
				cltvExpiry,
				false
			);
			revokedTx.addOutput(
				bitcoin.payments.p2wsh({ redeem: { output: htlcScript } }).output!,
				100_000
			);

			const actions = monitor.handleFundingSpent(revokedTx, 100);
			expect(monitor.getState()).to.equal(MonitorState.RESOLVING);
			expect(
				actions.some((a: any) => a.type === ChainActionType.BROADCAST_TX),
				'penalty broadcast on breach detection'
			).to.be.true;
			const htlcOutput = monitor
				.getTrackedOutputs()
				.find((o) => o.outputType === OutputType.OFFERED_HTLC);
			expect(htlcOutput, 'the revoked HTLC output is tracked').to.exist;

			return {
				monitor,
				state,
				revokedTx,
				htlcIndex: htlcOutput!.outputIndex,
				secondLevelScript: buildPeerSecondLevelScript(state, revokedPoint),
				paymentHash,
				preimage
			};
		}

		it('claims the cheater second-level HTLC tx output immediately', function () {
			const { monitor, revokedTx, htlcIndex, secondLevelScript, preimage } =
				setupRevokedBreach();

			// The cheater wins the race: their pre-signed HTLC-success confirms.
			const secondLevelTx = new bitcoin.Transaction();
			secondLevelTx.version = 2;
			secondLevelTx.addInput(
				Buffer.from(revokedTx.getId(), 'hex').reverse(),
				htlcIndex,
				0
			);
			secondLevelTx.ins[0].witness = [
				Buffer.alloc(0),
				crypto.randomBytes(72),
				crypto.randomBytes(72),
				preimage,
				crypto.randomBytes(80)
			];
			secondLevelTx.addOutput(
				bitcoin.payments.p2wsh({ redeem: { output: secondLevelScript } })
					.output!,
				95_000
			);

			const actions = monitor.handleOutputSpent(
				revokedTx.getId(),
				htlcIndex,
				secondLevelTx,
				105
			);

			const broadcast = actions.find(
				(a: any) =>
					a.type === ChainActionType.BROADCAST_TX &&
					a.description.includes('second-level')
			) as any;
			expect(broadcast, 'second-level justice claim broadcast').to.exist;
			const claimTx = bitcoin.Transaction.fromBuffer(broadcast.tx);
			expect(
				Buffer.from(claimTx.ins[0].hash).reverse().toString('hex')
			).to.equal(secondLevelTx.getId());
			expect(claimTx.ins[0].index).to.equal(0);
			// Revocation-branch witness: [sig, OP_TRUE flag, witnessScript].
			expect(claimTx.ins[0].witness).to.have.length(3);
			expect(claimTx.ins[0].witness[1].equals(Buffer.from([0x01]))).to.be.true;
			expect(claimTx.ins[0].witness[2].equals(secondLevelScript)).to.be.true;

			const watch = actions.find(
				(a: any) =>
					a.type === ChainActionType.WATCH_OUTPUT &&
					a.txid === secondLevelTx.getId()
			);
			expect(watch, 'the second-level output is watched').to.exist;

			const tracked = monitor
				.getTrackedOutputs()
				.find((o) => o.txid === secondLevelTx.getId());
			expect(tracked).to.exist;
			expect(tracked!.status).to.equal(OutputStatus.SPEND_BROADCAST);
			expect(tracked!.sweepTxHex).to.exist;
		});

		it('does not build a claim when our own penalty spends the HTLC output', function () {
			const { monitor, revokedTx, htlcIndex } = setupRevokedBreach();

			const htlcOutput = monitor
				.getTrackedOutputs()
				.find(
					(o) => o.txid === revokedTx.getId() && o.outputIndex === htlcIndex
				)!;
			expect(htlcOutput.sweepTxHex, 'penalty stored on the HTLC output').to
				.exist;
			const penaltyTx = bitcoin.Transaction.fromHex(htlcOutput.sweepTxHex!);

			const before = monitor.getTrackedOutputs().length;
			const actions = monitor.handleOutputSpent(
				revokedTx.getId(),
				htlcIndex,
				penaltyTx,
				105
			);

			expect(
				actions.some((a: any) => a.type === ChainActionType.BROADCAST_TX),
				'no second-level claim for our own penalty'
			).to.be.false;
			expect(monitor.getTrackedOutputs().length).to.equal(before);
			expect(htlcOutput.status).to.equal(OutputStatus.SPEND_CONFIRMED);
			expect(htlcOutput.resolutionTxid).to.equal(penaltyTx.getId());
		});
	});
});
