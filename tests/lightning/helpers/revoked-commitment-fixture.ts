/**
 * A funded, revoked witness-v0 commitment to drive breach-remedy tests with.
 *
 * Two channels are opened and driven to NORMAL, one commitment exchange is
 * revoked, and commitment #0 is reconstructed as a real transaction whose
 * outputs the resolver can classify and claim. Shared by the deadline-split
 * suite and the uneconomic-sweep-retry suite so both work against exactly the
 * same breach.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import { getPublicKey } from '../../../src/lightning/crypto/ecdh';
import {
	createOpenerState,
	createAcceptorState
} from '../../../src/lightning/channel/channel-state';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	ChannelRole
} from '../../../src/lightning/channel/types';
import { Channel } from '../../../src/lightning/channel/channel';
import { IChannelBasepoints } from '../../../src/lightning/keys/derivation';
import { MessageType } from '../../../src/lightning/message/types';
import {
	decodeOpenChannelMessage,
	decodeAcceptChannelMessage
} from '../../../src/lightning/message/channel-open';
import {
	decodeFundingCreatedMessage,
	decodeFundingSignedMessage,
	decodeChannelReadyMessage
} from '../../../src/lightning/message/channel-funding';
import {
	decodeCommitmentSignedMessage,
	decodeRevokeAndAckMessage
} from '../../../src/lightning/message/channel-commitment';
import {
	OutputStatus,
	OutputType,
	ITrackedOutput
} from '../../../src/lightning/chain/types';
import { ChannelActionType } from '../../../src/lightning/channel/channel-actions';
import { MAX_INDEX } from '../../../src/lightning/keys/shachain';
import {
	perCommitmentPointFromSecret,
	deriveRevocationPubkey,
	derivePublicKey
} from '../../../src/lightning/keys/derivation';
import {
	buildToLocalScript,
	calculateObscuredCommitmentNumber
} from '../../../src/lightning/script/commitment';
import { buildReceivedHtlcScript } from '../../../src/lightning/script/htlc';
import { PENALTY_SPLIT_DEADLINE_BLOCKS } from '../../../src/lightning/chain/output-resolver';

export function makeBasepoints(seed: Buffer): {
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

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function findSendAction(actions: any[], msgType: MessageType): any {
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	return actions.find(
		(a: any) =>
			a.type === ChannelActionType.SEND_MESSAGE && a.messageType === msgType
	);
}

export function setupNormalChannels(): {
	opener: Channel;
	acceptor: Channel;
	openerPrivkeys: Buffer[];
} {
	const openerSeed = Buffer.alloc(32, 0x51);
	const acceptorSeed = Buffer.alloc(32, 0x52);
	const openerCommitmentSeed = crypto
		.createHash('sha256')
		.update(Buffer.from('penalty-split-opener'))
		.digest();
	const acceptorCommitmentSeed = crypto
		.createHash('sha256')
		.update(Buffer.from('penalty-split-acceptor'))
		.digest();

	const { basepoints: openerBasepoints, privkeys: openerPrivkeys } =
		makeBasepoints(openerSeed);
	const { basepoints: acceptorBasepoints } = makeBasepoints(acceptorSeed);

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

	const openActions = opener.initiateOpen();
	const openMsg = findSendAction(openActions, MessageType.OPEN_CHANNEL);
	const acceptActions = acceptor.handleOpenChannel(
		decodeOpenChannelMessage(openMsg.payload)
	);
	const acceptMsg = findSendAction(acceptActions, MessageType.ACCEPT_CHANNEL);
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

	return { opener, acceptor, openerPrivkeys };
}

export function exchangeCommitments(opener: Channel, acceptor: Channel): void {
	const commitActions1 = opener.signCommitment(crypto.randomBytes(64), []);
	const commitMsg1 = findSendAction(
		commitActions1,
		MessageType.COMMITMENT_SIGNED
	);
	const raaActions1 = acceptor.handleCommitmentSigned(
		decodeCommitmentSignedMessage(commitMsg1.payload)
	);
	const raaMsg1 = findSendAction(raaActions1, MessageType.REVOKE_AND_ACK);
	opener.handleRevokeAndAck(decodeRevokeAndAckMessage(raaMsg1.payload));

	const commitActions2 = acceptor.signCommitment(crypto.randomBytes(64), []);
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

export interface IRevokedSetup {
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	state: any;
	revokedTx: bitcoin.Transaction;
	trackedOutputs: ITrackedOutput[];
	openerPrivkeys: Buffer[];
	destScript: Buffer;
	nearCltv: number;
	farCltv: number;
	/** Index of the appended to_remote output, when one was requested. */
	toRemoteIndex?: number;
}

export interface IRevokedSetupOptions {
	/**
	 * Append OUR balance on their revoked commitment (plain P2WPKH, the
	 * non-anchor static_remotekey shape) at this value in satoshis.
	 */
	toRemoteSats?: number;
}

/**
 * Revoked commitment #0 with three penalty outputs:
 *   0: to_local
 *   1: HTLC with a NEAR cltv_expiry (within the split margin of `height`)
 *   2: HTLC with a FAR cltv_expiry
 * plus an optional index 3 carrying our to_remote balance.
 */
export function setupRevokedWithHtlcs(
	height: number,
	options: IRevokedSetupOptions = {}
): IRevokedSetup {
	const { opener, acceptor, openerPrivkeys } = setupNormalChannels();
	exchangeCommitments(opener, acceptor);
	const state = opener.getFullState();

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
	const theirHtlc = derivePublicKey(
		state.remoteBasepoints!.htlcBasepoint,
		revokedPoint
	);
	const ourHtlc = derivePublicKey(
		state.localBasepoints.htlcBasepoint,
		revokedPoint
	);

	const isOpener = state.role === ChannelRole.OPENER;
	const openPBP = isOpener
		? state.localBasepoints.paymentBasepoint
		: state.remoteBasepoints!.paymentBasepoint;
	const acceptPBP = isOpener
		? state.remoteBasepoints!.paymentBasepoint
		: state.localBasepoints.paymentBasepoint;
	const obscured = calculateObscuredCommitmentNumber(openPBP, acceptPBP, 0n);

	const revokedTx = new bitcoin.Transaction();
	revokedTx.version = 2;
	revokedTx.locktime = 0x20000000 | Number(obscured & 0xffffffn);
	const seq = (0x80000000 | Number((obscured >> 24n) & 0xffffffn)) >>> 0;
	revokedTx.addInput(
		Buffer.from(state.fundingTxid!.toString('hex'), 'hex').reverse(),
		state.fundingOutputIndex,
		seq
	);

	const toLocalScript = buildToLocalScript(
		revocationPubkey,
		theirDelayedPubkey,
		state.localConfig.toSelfDelay
	);
	revokedTx.addOutput(
		bitcoin.payments.p2wsh({ redeem: { output: toLocalScript } }).output!,
		600_000
	);

	// One HTLC just inside the split margin, one far outside it.
	const nearCltv = height + PENALTY_SPLIT_DEADLINE_BLOCKS - 2;
	const farCltv = height + PENALTY_SPLIT_DEADLINE_BLOCKS + 500;
	const nearScript = buildReceivedHtlcScript(
		revocationPubkey,
		theirHtlc,
		ourHtlc,
		crypto.randomBytes(32),
		nearCltv,
		false
	);
	const farScript = buildReceivedHtlcScript(
		revocationPubkey,
		theirHtlc,
		ourHtlc,
		crypto.randomBytes(32),
		farCltv,
		false
	);
	revokedTx.addOutput(
		bitcoin.payments.p2wsh({ redeem: { output: nearScript } }).output!,
		120_000
	);
	revokedTx.addOutput(
		bitcoin.payments.p2wsh({ redeem: { output: farScript } }).output!,
		130_000
	);

	const base = {
		txid: revokedTx.getId(),
		status: OutputStatus.CONFIRMED as OutputStatus.CONFIRMED,
		confirmationHeight: height
	};
	const trackedOutputs: ITrackedOutput[] = [
		{
			...base,
			outputIndex: 0,
			amount: 600_000n,
			outputType: OutputType.TO_LOCAL,
			witnessScript: toLocalScript
		},
		{
			...base,
			outputIndex: 1,
			amount: 120_000n,
			outputType: OutputType.RECEIVED_HTLC,
			witnessScript: nearScript,
			cltvExpiry: nearCltv
		},
		{
			...base,
			outputIndex: 2,
			amount: 130_000n,
			outputType: OutputType.RECEIVED_HTLC,
			witnessScript: farScript,
			cltvExpiry: farCltv
		}
	];

	let toRemoteIndex: number | undefined;
	if (options.toRemoteSats !== undefined) {
		// static_remotekey: our balance pays our payment basepoint directly.
		const ourP2wpkh = bitcoin.payments.p2wpkh({
			pubkey: state.localBasepoints.paymentBasepoint
		});
		toRemoteIndex = revokedTx.outs.length;
		revokedTx.addOutput(ourP2wpkh.output!, options.toRemoteSats);
		trackedOutputs.push({
			...base,
			outputIndex: toRemoteIndex,
			amount: BigInt(options.toRemoteSats),
			outputType: OutputType.TO_REMOTE
		});
	}
	// Adding outputs changes the txid, so stamp the final one on every tracked
	// output rather than the value `base` captured mid-build.
	const txid = revokedTx.getId();
	for (const output of trackedOutputs) output.txid = txid;

	const destScript = Buffer.concat([
		Buffer.from([0x00, 0x14]),
		crypto.randomBytes(20)
	]);

	return {
		state,
		revokedTx,
		trackedOutputs,
		openerPrivkeys,
		destScript,
		nearCltv,
		farCltv,
		toRemoteIndex
	};
}
