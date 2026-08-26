/**
 * The lessor's lease-locked to_remote on the BUYER's commitment is held
 * until its CSV matures and then released by handleNewBlock, with the CSV
 * as the sweep's input sequence and no nLockTime (CLN pure-CSV lease).
 *
 * Unit twin of the cln-lease-seller interop test's sweep phase (issue
 * #537). The interop failure that motivated it was NOT a sweep bug: CLN's
 * close RPC negotiates a mutual close before its unilateraltimeout, and
 * the cooperative close had gotten fast enough to beat the timeout, so no
 * lease-locked output ever reached the chain. This test pins the actual
 * hold/release machinery at the monitor level, where no peer can turn the
 * close cooperative.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	createOpenerState,
	createAcceptorState
} from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
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
import { buildRemoteCommitment } from '../../src/lightning/channel/commitment-builder';
import { ChainMonitor } from '../../src/lightning/chain/chain-monitor';
import { ChainActionType, OutputType } from '../../src/lightning/chain/types';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import {
	signerFromSeed,
	realInitialCommitmentSig
} from './helpers/real-signing';

const network = bitcoin.networks.regtest;

const ANCHOR_CHANNEL_TYPE = Buffer.from('401000', 'hex');
const LEASE_EXPIRY = 804_032;
const LEASE_COMMIT_BH = 800_013; // advanced past open by update_blockheight
const LEASE_CSV = LEASE_EXPIRY - LEASE_COMMIT_BH; // 4019

function makeBasepoints(seed: Buffer): {
	basepoints: IChannelBasepoints;
	privkeys: Buffer[];
} {
	const privkeys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		privkeys.push(
			crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from([i]))
				.digest()
		);
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

function findSendAction(
	actions: Array<{ type: ChannelActionType; messageType?: MessageType }>,
	msgType: MessageType
): { payload: Buffer } {
	return actions.find(
		(a) =>
			a.type === ChannelActionType.SEND_MESSAGE && a.messageType === msgType
	) as unknown as { payload: Buffer };
}

function setupNormalChannel(): { opener: Channel; openerPrivkeys: Buffer[] } {
	const openerSeed = Buffer.alloc(32, 0x51);
	const acceptorSeed = Buffer.alloc(32, 0x52);
	const openerCommitmentSeed = crypto
		.createHash('sha256')
		.update(Buffer.from('lease-sweep-opener'))
		.digest();
	const acceptorCommitmentSeed = crypto
		.createHash('sha256')
		.update(Buffer.from('lease-sweep-acceptor'))
		.digest();

	const { basepoints: openerBasepoints, privkeys: openerPrivkeys } =
		makeBasepoints(openerSeed);
	const { basepoints: acceptorBasepoints } = makeBasepoints(acceptorSeed);

	const openerState = createOpenerState({
		temporaryChannelId: Buffer.alloc(32, 0xcd),
		fundingSatoshis: 1_000_000n,
		pushMsat: 200_000_000n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: openerBasepoints,
		localPerCommitmentSeed: openerCommitmentSeed
	});
	const opener = new Channel(openerState);

	const acceptorState = createAcceptorState({
		temporaryChannelId: Buffer.alloc(32, 0xcd),
		fundingSatoshis: 0n,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: acceptorBasepoints,
		localPerCommitmentSeed: acceptorCommitmentSeed,
		remoteBasepoints: openerBasepoints,
		remoteConfig: { ...DEFAULT_CHANNEL_CONFIG }
	});
	const acceptor = new Channel(acceptorState);

	opener.setSigner(signerFromSeed(openerSeed));
	acceptor.setSigner(signerFromSeed(acceptorSeed));

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
		realInitialCommitmentSig(opener, fundingTxid, 0)
	);
	const fcMsg = findSendAction(fcActions, MessageType.FUNDING_CREATED);
	const decodedFc = decodeFundingCreatedMessage(fcMsg.payload);
	const fsActions = acceptor.handleFundingCreated(
		decodedFc,
		realInitialCommitmentSig(
			acceptor,
			decodedFc.fundingTxid,
			decodedFc.fundingOutputIndex
		)
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
	return { opener, openerPrivkeys };
}

describe('Lease-locked to_remote sweep release (issue #537)', function () {
	it('holds the lessor to_remote until the lease CSV matures, then releases it', function () {
		const { opener, openerPrivkeys } = setupNormalChannel();
		const state = opener.getFullState();
		state.channelType = ANCHOR_CHANNEL_TYPE;
		state.isLessor = true;
		state.leaseExpiry = LEASE_EXPIRY;
		state.leaseCommitBlockheight = LEASE_COMMIT_BH;

		const destScript = bitcoin.payments.p2wpkh({
			pubkey: getPublicKey(openerPrivkeys[0]),
			network
		}).output!;
		const monitor = new ChainMonitor(
			state,
			destScript,
			10,
			openerPrivkeys[1],
			openerPrivkeys[2],
			network
		);

		// The buyer (remote) force-closes: their commitment carries OUR balance
		// as the lease-locked to_remote.
		const built = buildRemoteCommitment(
			state,
			state.remoteCurrentPerCommitmentPoint!
		);
		const closingTx = built.result.tx;

		const confHeight = 100;
		const actions = monitor.handleFundingSpent(closingTx, confHeight);
		const isToRemoteBroadcast = (a: {
			type: ChainActionType;
			description?: string;
		}): boolean =>
			a.type === ChainActionType.BROADCAST_TX &&
			(a.description ?? '').includes('to_remote');
		expect(
			actions.filter(isToRemoteBroadcast).length,
			'held at detection (CSV not matured)'
		).to.equal(0);

		// The lease-locked output was tracked at all (classification worked).
		const tracked = monitor
			.getTrackedOutputs()
			.filter((o) => o.outputType === OutputType.TO_REMOTE);
		expect(tracked.length, 'to_remote tracked').to.equal(1);

		// One block before maturity: still held.
		const before = monitor.handleNewBlock(confHeight + LEASE_CSV - 1);
		expect(
			before.filter(isToRemoteBroadcast).length,
			'still held one block early'
		).to.equal(0);

		// At maturity: released, with the CSV as the input sequence.
		const atMaturity = monitor.handleNewBlock(confHeight + LEASE_CSV);
		const releases = atMaturity.filter(isToRemoteBroadcast);
		expect(releases.length, 'released at maturity').to.equal(1);
		const sweep = bitcoin.Transaction.fromBuffer(
			(releases[0] as unknown as { tx: Buffer }).tx
		);
		expect(sweep.ins[0].sequence, 'input sequence = lease CSV').to.equal(
			LEASE_CSV
		);
		expect(sweep.locktime).to.equal(0);
		expect(Buffer.from(sweep.outs[0].script).equals(destScript)).to.equal(true);
	});
});
