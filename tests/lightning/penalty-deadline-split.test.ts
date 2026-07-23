/**
 * Per-output penalty tx fallback near expiry.
 *
 * A batched penalty tx spends every claimable output of a revoked commitment
 * in one transaction. If the cheater's pre-signed HTLC-timeout wins the race
 * for ONE of those inputs (possible as soon as its cltv_expiry passes), the
 * whole batch becomes invalid and every other claim stalls until the
 * rebroadcast interval rebuilds them. The fallback: any HTLC input within
 * PENALTY_SPLIT_DEADLINE_BLOCKS of its cltv_expiry is claimed in its OWN
 * single-input penalty tx; the rest stay batched. Far from any deadline (or
 * when no height is known) the previous single-batch behavior is preserved.
 */

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
	DEFAULT_CHANNEL_CONFIG,
	ChannelRole,
	HtlcDirection
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
	ChainActionType,
	OutputStatus,
	OutputType,
	ITrackedOutput
} from '../../src/lightning/chain/types';
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
import {
	resolveRevokedCommitmentOutputs,
	PENALTY_SPLIT_DEADLINE_BLOCKS
} from '../../src/lightning/chain/output-resolver';

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

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function findSendAction(actions: any[], msgType: MessageType): any {
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	return actions.find(
		(a: any) =>
			a.type === ChannelActionType.SEND_MESSAGE && a.messageType === msgType
	);
}

function setupNormalChannels(): {
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

function exchangeCommitments(opener: Channel, acceptor: Channel): void {
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

interface IRevokedSetup {
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	state: any;
	revokedTx: bitcoin.Transaction;
	trackedOutputs: ITrackedOutput[];
	openerPrivkeys: Buffer[];
	destScript: Buffer;
	nearCltv: number;
	farCltv: number;
}

/**
 * Revoked commitment #0 with three penalty outputs:
 *   0: to_local
 *   1: HTLC with a NEAR cltv_expiry (within the split margin of `height`)
 *   2: HTLC with a FAR cltv_expiry
 */
function setupRevokedWithHtlcs(height: number): IRevokedSetup {
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
		farCltv
	};
}

describe('Per-output penalty fallback near expiry', function () {
	const HEIGHT = 750_000;

	it('isolates a near-deadline HTLC input into its own penalty tx', function () {
		const s = setupRevokedWithHtlcs(HEIGHT);

		const resolved = resolveRevokedCommitmentOutputs(
			s.state,
			s.trackedOutputs,
			0n,
			s.revokedTx,
			s.destScript,
			10,
			s.openerPrivkeys[1],
			s.openerPrivkeys[2],
			network,
			HEIGHT
		);

		const byIndex = new Map(
			resolved.map((r) => [r.trackedOutput.outputIndex, r])
		);
		expect(byIndex.size).to.equal(3);

		// The near-deadline HTLC (index 1) gets a single-input tx of its own.
		const near = byIndex.get(1)!;
		expect(near.spendTx!.ins.length).to.equal(1);
		expect(near.spendTx!.ins[0].index).to.equal(1);
		expect(
			Buffer.from(near.spendTx!.ins[0].hash).reverse().toString('hex')
		).to.equal(s.revokedTx.getId());

		// to_local + far HTLC stay batched in ONE shared tx.
		const toLocal = byIndex.get(0)!;
		const far = byIndex.get(2)!;
		expect(toLocal.spendTx).to.equal(far.spendTx);
		expect(toLocal.spendTx!.ins.length).to.equal(2);
		expect(toLocal.spendTx!.getId()).to.not.equal(near.spendTx!.getId());

		// Every input carries its witness (the batch signs per-input).
		for (const r of resolved) {
			expect(r.witness).to.exist;
			expect(r.witness![r.witness!.length - 1].length).to.be.greaterThan(0);
		}
	});

	it('keeps the single batched penalty when no height is known (previous behavior)', function () {
		const s = setupRevokedWithHtlcs(HEIGHT);

		const resolved = resolveRevokedCommitmentOutputs(
			s.state,
			s.trackedOutputs,
			0n,
			s.revokedTx,
			s.destScript,
			10,
			s.openerPrivkeys[1],
			s.openerPrivkeys[2],
			network
		);

		expect(resolved.length).to.equal(3);
		const txids = new Set(resolved.map((r) => r.spendTx!.getId()));
		expect(txids.size).to.equal(1);
		expect(resolved[0].spendTx!.ins.length).to.equal(3);
	});

	it('keeps the single batched penalty when every deadline is far', function () {
		const s = setupRevokedWithHtlcs(HEIGHT);

		// Far below both cltv_expiry values: nothing is urgent.
		const resolved = resolveRevokedCommitmentOutputs(
			s.state,
			s.trackedOutputs,
			0n,
			s.revokedTx,
			s.destScript,
			10,
			s.openerPrivkeys[1],
			s.openerPrivkeys[2],
			network,
			HEIGHT - 10_000
		);

		const txids = new Set(resolved.map((r) => r.spendTx!.getId()));
		expect(txids.size).to.equal(1);
		expect(resolved[0].spendTx!.ins.length).to.equal(3);
	});

	it('splits a snapshot-reconstructed HTLC near its deadline (H2 path)', function () {
		const s = setupRevokedWithHtlcs(HEIGHT);

		// Move the near HTLC out of live tracking and into the revoked snapshot
		// (settled since the revoked commitment; direction OFFERED from our
		// perspective maps to the received-HTLC script on their commitment).
		const remaining = [s.trackedOutputs[0], s.trackedOutputs[2]];
		s.state.revokedHtlcSnapshots = new Map([
			[
				'0',
				[
					{
						paymentHash: crypto.randomBytes(32),
						amountMsat: 120_000_000n,
						cltvExpiry: s.nearCltv,
						direction: HtlcDirection.OFFERED
					}
				]
			]
		]);
		// Rebuild the snapshot entry's script so it matches revokedTx output 1.
		const secret = s.state.shaChainStore.getSecret(MAX_INDEX - 0n)!;
		const revokedPoint = perCommitmentPointFromSecret(secret);
		const snapshotEntry = s.state.revokedHtlcSnapshots.get('0')![0];
		const script = buildReceivedHtlcScript(
			deriveRevocationPubkey(
				s.state.localBasepoints.revocationBasepoint,
				revokedPoint
			),
			derivePublicKey(s.state.remoteBasepoints!.htlcBasepoint, revokedPoint),
			derivePublicKey(s.state.localBasepoints.htlcBasepoint, revokedPoint),
			snapshotEntry.paymentHash,
			s.nearCltv,
			false
		);
		s.revokedTx.outs[1].script = bitcoin.payments.p2wsh({
			redeem: { output: script }
		}).output!;

		const resolved = resolveRevokedCommitmentOutputs(
			s.state,
			remaining,
			0n,
			s.revokedTx,
			s.destScript,
			10,
			s.openerPrivkeys[1],
			s.openerPrivkeys[2],
			network,
			HEIGHT
		);

		expect(resolved.length).to.equal(3);
		const near = resolved.find((r) => r.trackedOutput.outputIndex === 1)!;
		expect(near).to.exist;
		expect(near.spendTx!.ins.length).to.equal(1);
		expect(near.trackedOutput.cltvExpiry).to.equal(s.nearCltv);
		// The other two share the batch.
		const others = resolved.filter((r) => r.trackedOutput.outputIndex !== 1);
		expect(others[0].spendTx).to.equal(others[1].spendTx);
		expect(others[0].spendTx!.getId()).to.not.equal(near.spendTx!.getId());
	});

	it('monitor broadcasts each distinct penalty tx exactly once (dedupe + split)', function () {
		const s = setupRevokedWithHtlcs(HEIGHT);

		// Route both HTLCs through the snapshot (classification only matches
		// live HTLCs): the resolver's H2 fallback picks them up with their
		// deadlines, so the monitor's height plumbing drives the split.
		const secret = s.state.shaChainStore.getSecret(MAX_INDEX - 0n)!;
		const revokedPoint = perCommitmentPointFromSecret(secret);
		const revocationPubkey = deriveRevocationPubkey(
			s.state.localBasepoints.revocationBasepoint,
			revokedPoint
		);
		const theirHtlc = derivePublicKey(
			s.state.remoteBasepoints!.htlcBasepoint,
			revokedPoint
		);
		const ourHtlc = derivePublicKey(
			s.state.localBasepoints.htlcBasepoint,
			revokedPoint
		);
		const nearHash = crypto.randomBytes(32);
		const farHash = crypto.randomBytes(32);
		s.state.revokedHtlcSnapshots = new Map([
			[
				'0',
				[
					{
						paymentHash: nearHash,
						amountMsat: 120_000_000n,
						cltvExpiry: s.nearCltv,
						direction: HtlcDirection.OFFERED
					},
					{
						paymentHash: farHash,
						amountMsat: 130_000_000n,
						cltvExpiry: s.farCltv,
						direction: HtlcDirection.OFFERED
					}
				]
			]
		]);
		s.revokedTx.outs[1].script = bitcoin.payments.p2wsh({
			redeem: {
				output: buildReceivedHtlcScript(
					revocationPubkey,
					theirHtlc,
					ourHtlc,
					nearHash,
					s.nearCltv,
					false
				)
			}
		}).output!;
		s.revokedTx.outs[2].script = bitcoin.payments.p2wsh({
			redeem: {
				output: buildReceivedHtlcScript(
					revocationPubkey,
					theirHtlc,
					ourHtlc,
					farHash,
					s.farCltv,
					false
				)
			}
		}).output!;

		const monitor = new ChainMonitor(
			s.state,
			s.destScript,
			10,
			s.openerPrivkeys[1],
			s.openerPrivkeys[2],
			network
		);
		const actions = monitor.handleFundingSpent(s.revokedTx, HEIGHT);

		const penaltyBroadcasts = actions.filter(
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(a: any) =>
				a.type === ChainActionType.BROADCAST_TX &&
				a.description?.includes('penalty')
		);
		// Two distinct penalty txs (near-deadline single + batch), each once.
		const txs = penaltyBroadcasts.map(
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(a: any) => bitcoin.Transaction.fromBuffer(a.tx)
		);
		expect(txs.length).to.equal(2);
		expect(new Set(txs.map((t) => t.getId())).size).to.equal(2);

		// The single-input tx claims the near HTLC outpoint; the batch claims
		// the other two.
		const single = txs.find((t) => t.ins.length === 1)!;
		const batch = txs.find((t) => t.ins.length === 2)!;
		expect(single).to.exist;
		expect(batch).to.exist;
		expect(single.ins[0].index).to.equal(1);
		expect(batch.ins.map((i) => i.index).sort()).to.deep.equal([0, 2]);
	});
});
