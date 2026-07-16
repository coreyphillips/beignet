/**
 * BOLT 2 v2 (dual-funding) channel_id derivation.
 *
 *   channel_id           = SHA256(lesser-revocation-basepoint || greater-revocation-basepoint)
 *   temporary_channel_id = channel_id with the non-initiator's basepoint zeroed
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as secp from '@noble/secp256k1';
import {
	deriveV2ChannelId,
	deriveV2TemporaryChannelId
} from '../../src/lightning/channel/validation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { IDualFundingParams } from '../../src/lightning/channel/dual-funding';
import { MessageType } from '../../src/lightning/message/types';
import { encodeTxAddInputMessage } from '../../src/lightning/message/interactive-tx';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';

function validPriv(): Buffer {
	let k: Buffer;
	do {
		k = crypto.randomBytes(32);
	} while (!secp.utils.isValidPrivateKey(k));
	return k;
}

function makeBasepoints(): IChannelBasepoints {
	return {
		fundingPubkey: getPublicKey(validPriv()),
		revocationBasepoint: getPublicKey(validPriv()),
		paymentBasepoint: getPublicKey(validPriv()),
		delayedPaymentBasepoint: getPublicKey(validPriv()),
		htlcBasepoint: getPublicKey(validPriv()),
		firstPerCommitmentPoint: getPublicKey(validPriv())
	};
}

function makeParams(): IDualFundingParams {
	return {
		fundingSatoshis: 100_000n,
		fundingFeeratePerkw: 1000,
		commitmentFeeratePerkw: 253,
		dustLimitSatoshis: 546n,
		maxHtlcValueInFlightMsat: 500_000_000n,
		htlcMinimumMsat: 1000n,
		toSelfDelay: 144,
		maxAcceptedHtlcs: 483,
		locktime: 0,
		localBasepoints: makeBasepoints(),
		localPerCommitmentSeed: crypto.randomBytes(32),
		secondPerCommitmentPoint: getPublicKey(validPriv())
	};
}

function makeManager(nodePrivateKey: Buffer): ChannelManager {
	const mgr = new ChannelManager({
		localBasepoints: makeBasepoints(),
		localPerCommitmentSeed: crypto.randomBytes(32),
		localFundingPrivkey: validPriv(),
		nodePrivateKey
	});
	mgr.on('error', () => {});
	return mgr;
}

function wire(
	a: ChannelManager,
	aId: string,
	b: ChannelManager,
	bId: string
): void {
	a.on('message:outbound', (peer: string, type: number, payload: Buffer) => {
		if (peer === bId) b.handleMessage(aId, type, payload);
	});
	b.on('message:outbound', (peer: string, type: number, payload: Buffer) => {
		if (peer === aId) a.handleMessage(bId, type, payload);
	});
}

function sha256(...parts: Buffer[]): Buffer {
	return crypto.createHash('sha256').update(Buffer.concat(parts)).digest();
}

describe('v2 channel_id derivation (BOLT 2)', () => {
	const revA = getPublicKey(crypto.randomBytes(32));
	const revB = getPublicKey(crypto.randomBytes(32));

	it('is SHA256(lesser || greater) of the two revocation basepoints', () => {
		const [lesser, greater] =
			Buffer.compare(revA, revB) <= 0 ? [revA, revB] : [revB, revA];
		expect(deriveV2ChannelId(revA, revB)).to.deep.equal(
			sha256(lesser, greater)
		);
	});

	it('is order-independent (both peers derive the same id)', () => {
		expect(deriveV2ChannelId(revA, revB)).to.deep.equal(
			deriveV2ChannelId(revB, revA)
		);
	});

	it('produces a 32-byte id', () => {
		expect(deriveV2ChannelId(revA, revB).length).to.equal(32);
	});

	it('temporary_channel_id zeroes the peer basepoint (opener basepoint is greater)', () => {
		// A zeroed 33-byte basepoint sorts below any compressed point (0x02/0x03),
		// so it is always the lesser half.
		const zeros = Buffer.alloc(33);
		expect(deriveV2TemporaryChannelId(revA)).to.deep.equal(sha256(zeros, revA));
		expect(deriveV2TemporaryChannelId(revA)).to.deep.equal(
			deriveV2ChannelId(zeros, revA)
		);
	});

	it('temporary_channel_id differs from the final channel_id', () => {
		expect(deriveV2TemporaryChannelId(revA)).to.not.deep.equal(
			deriveV2ChannelId(revA, revB)
		);
	});

	it('distinct basepoint pairs yield distinct channel ids', () => {
		const revC = getPublicKey(crypto.randomBytes(32));
		expect(deriveV2ChannelId(revA, revB)).to.not.deep.equal(
			deriveV2ChannelId(revA, revC)
		);
	});
});

describe('v2 channel_id: two-manager open + interactive-tx routing', () => {
	it('both peers derive the same spec channel_id and route tx messages by it', () => {
		const openerPriv = validPriv();
		const acceptorPriv = validPriv();
		const openerId = getPublicKey(openerPriv).toString('hex');
		const acceptorId = getPublicKey(acceptorPriv).toString('hex');

		const opener = makeManager(openerPriv);
		const acceptor = makeManager(acceptorPriv);
		wire(opener, openerId, acceptor, acceptorId);

		const params = makeParams();
		const openerChannel = opener.createDualFundedChannel(acceptorId, params);

		// open_channel2 / accept_channel2 flowed over the wire. The acceptor's
		// channel exists (routing of accept_channel2 back to the opener already
		// proved the derived temporary_channel_id round-trips).
		const acceptorChannel = acceptor
			.listChannels()
			.find((c) => c.getFullState().fundingVersion === 2);
		expect(acceptorChannel, 'acceptor created a v2 channel').to.not.be
			.undefined;

		const finalId = openerChannel.getChannelId();
		expect(finalId, 'opener has a derived channel_id').to.not.be.null;
		// Both sides derived the SAME channel_id from the two revocation basepoints.
		expect(acceptorChannel!.getChannelId()).to.deep.equal(finalId);
		// It is the spec derivation over the two revocation basepoints (the
		// channel's OWN keys, which the manager advertises on the wire), not the
		// temporary id and not a funding-outpoint XOR.
		const expected = deriveV2ChannelId(
			openerChannel.getFullState().localBasepoints.revocationBasepoint,
			acceptorChannel!.getFullState().localBasepoints.revocationBasepoint
		);
		expect(finalId).to.deep.equal(expected);
		expect(finalId).to.not.deep.equal(openerChannel.getTemporaryChannelId());

		// An interactive-tx message now carries the final channel_id; feeding it to
		// the acceptor manager must route to the acceptor channel (via the
		// derived-id temp lookup) and land in its session, not be dropped.
		// A valid native-segwit prev_tx: the receive side now enforces prevtx
		// validity + segwit-only spends (S-2.H3).
		const prevTx = new bitcoin.Transaction();
		prevTx.version = 2;
		prevTx.addInput(crypto.randomBytes(32), 0);
		prevTx.addOutput(
			Buffer.concat([Buffer.from([0x00, 0x14]), crypto.randomBytes(20)]),
			100_000
		);
		const inputActions = openerChannel.addTxInput({
			serialId: 0n,
			prevTxid: Buffer.from(prevTx.getHash()),
			prevOutputIndex: 0,
			sequence: 0xfffffffd,
			prevTx: prevTx.toBuffer(),
			prevTxVout: 0
		});
		const sendAction = inputActions.find(
			(a) => a.type === ChannelActionType.SEND_MESSAGE
		) as { messageType: MessageType; payload: Buffer } | undefined;
		expect(sendAction, 'tx_add_input emitted').to.not.be.undefined;
		// The message is stamped with the final channel_id.
		const {
			decodeTxAddInputMessage
		} = require('../../src/lightning/message/interactive-tx');
		expect(
			decodeTxAddInputMessage(sendAction!.payload).channelId
		).to.deep.equal(finalId);

		const before =
			acceptorChannel!.getDualFundingSession()?.getTxBuilder()?.getInputs()
				.length ?? 0;
		acceptor.handleMessage(
			openerId,
			MessageType.TX_ADD_INPUT,
			encodeTxAddInputMessage(decodeTxAddInputMessage(sendAction!.payload))
		);
		const after =
			acceptorChannel!.getDualFundingSession()?.getTxBuilder()?.getInputs()
				.length ?? 0;
		expect(after, 'tx_add_input routed into the acceptor session').to.equal(
			before + 1
		);
	});
});
