/**
 * Issue #469 review, finding 8: a channel restored from a Recovery Capsule
 * whose recency cannot be proven must not REPLAY an update_add_htlc no
 * commitment_signed of ours ever covered.
 *
 * addHtlc refuses to offer one on such a channel, permanently, because the
 * on-chain deadline backstops that would enforce it are disarmed for as long
 * as the hold stands. But handleReestablish replays pendingLocalUpdates as raw
 * bytes with no inspection, so a persisted unsigned add walked straight past
 * that guard on the next reconnect - and the entry still carried
 * needsCommitment, so the reestablish tail's auto-sign would have committed it.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { Channel } from '../../src/lightning/channel/channel';
import { createOpenerState } from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	HtlcState
} from '../../src/lightning/channel/types';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { MessageType } from '../../src/lightning/message/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';

bitcoin.initEccLib(ecc);

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 6; i++) {
		keys.push(
			getPublicKey(
				crypto
					.createHash('sha256')
					.update(seed)
					.update(Buffer.from([i]))
					.digest()
			)
		);
	}
	return {
		fundingPubkey: keys[0],
		revocationBasepoint: keys[1],
		paymentBasepoint: keys[2],
		delayedPaymentBasepoint: keys[3],
		htlcBasepoint: keys[4],
		firstPerCommitmentPoint: keys[5]
	};
}

/** A NORMAL channel with one offered HTLC queued and never signed for. */
function channelWithUnsignedAdd(): {
	channel: Channel;
	htlcId: bigint;
	amountMsat: bigint;
	balanceBefore: bigint;
} {
	const state = createOpenerState({
		temporaryChannelId: crypto.randomBytes(32),
		fundingSatoshis: 1_000_000n,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(Buffer.alloc(32, 1)),
		localPerCommitmentSeed: Buffer.alloc(32, 3)
	});
	state.state = ChannelState.NORMAL;
	state.channelId = crypto.randomBytes(32);
	state.fundingTxid = crypto.randomBytes(32);
	state.fundingOutputIndex = 0;
	state.remoteBasepoints = makeBasepoints(Buffer.alloc(32, 2));
	state.remoteCurrentPerCommitmentPoint = state.remoteBasepoints.fundingPubkey;
	const channel = new Channel(state);

	const balanceBefore = state.localBalanceMsat;
	const amountMsat = 50_000_000n;
	const actions = channel.addHtlc(
		amountMsat,
		crypto.randomBytes(32),
		800_000,
		Buffer.alloc(1366)
	);
	expect(
		actions.find((a) => a.type === ChannelActionType.ERROR),
		'the add is accepted while the channel is not yet held'
	).to.equal(undefined);
	expect(state.pendingLocalUpdates).to.have.length(1);
	expect(state.pendingLocalUpdatesSignedCount).to.equal(0);
	return {
		channel,
		htlcId: state.localHtlcCounter - 1n,
		amountMsat,
		balanceBefore
	};
}

describe('Issue #469: a held restore forgets its unsigned adds', function () {
	it('drops the queued add, refunds the balance and reports it', () => {
		const { channel, htlcId, amountMsat, balanceBefore } =
			channelWithUnsignedAdd();
		const state = channel.getFullState();
		state.restoreRecencyUnproven = true;

		const abandoned = channel.markForReestablish();

		expect(abandoned, 'the drop is reported, not silent').to.have.length(1);
		expect(abandoned[0].htlcId).to.equal(htlcId);
		expect(abandoned[0].amountMsat).to.equal(amountMsat);
		expect(state.pendingLocalUpdates, 'nothing left to replay').to.have.length(
			0
		);
		expect(
			state.htlcs.has(`offered-${htlcId}`),
			'and no phantom offered HTLC survives'
		).to.equal(false);
		expect(state.localBalanceMsat, 'the provisional debit came back').to.equal(
			balanceBefore
		);
	});

	it('never touches an add our commitment_signed covers', () => {
		const { channel, htlcId } = channelWithUnsignedAdd();
		const state = channel.getFullState();
		// The shape signCommitment leaves behind: the queued update is covered
		// by our outstanding signature and MUST be retransmitted (BOLT 2).
		state.pendingLocalUpdatesSignedCount = state.pendingLocalUpdates.length;
		const entry = state.htlcs.get(`offered-${htlcId}`)!;
		entry.state = HtlcState.COMMITTED;
		entry.commitCoverPending = true;
		state.restoreRecencyUnproven = true;

		expect(channel.markForReestablish(), 'nothing is dropped').to.have.length(
			0
		);
		expect(state.pendingLocalUpdates).to.have.length(1);
		expect(
			state.pendingLocalUpdatesSignedCount,
			'and the signed boundary still indexes the same entry'
		).to.equal(1);
		expect(state.htlcs.has(`offered-${htlcId}`)).to.equal(true);
	});

	it('leaves an ordinary channel alone, because BOLT 2 says replay it', () => {
		const { channel, htlcId } = channelWithUnsignedAdd();
		const state = channel.getFullState();

		expect(channel.markForReestablish()).to.have.length(0);
		expect(state.pendingLocalUpdates, 'the replay survives').to.have.length(1);
		expect(state.htlcs.has(`offered-${htlcId}`)).to.equal(true);
	});

	it('does not rewind localHtlcCounter', () => {
		// Rewinding is the dangerous option: it lets a later add reuse an id a
		// peer that kept the original still holds, which this implementation
		// treats as channel-fatal. The gap can never be observed, because
		// addHtlc refuses every subsequent add while the hold stands.
		const { channel } = channelWithUnsignedAdd();
		const state = channel.getFullState();
		const counterBefore = state.localHtlcCounter;
		state.restoreRecencyUnproven = true;

		channel.markForReestablish();

		expect(state.localHtlcCounter).to.equal(counterBefore);
	});

	it('clears the commitment debt the dropped add created, and only that', () => {
		// autoSignAndSendCommitment gates on needsCommitment alone, with no
		// "would this commitment differ" test. Left set, the reestablish tail
		// would send a commitment_signed covering no updates: a BOLT 2 MUST
		// NOT, which CLN answers with an error - force-closing the one channel
		// that must not be force-closed.
		const { channel } = channelWithUnsignedAdd();
		const state = channel.getFullState();
		expect(state.needsCommitment, 'the add set the debt').to.equal(true);
		state.restoreRecencyUnproven = true;

		channel.markForReestablish();
		expect(
			state.needsCommitment,
			'and dropping the only reason clears it'
		).to.equal(false);
	});

	it('keeps the commitment debt when something else still owes one', () => {
		const { channel } = channelWithUnsignedAdd();
		const state = channel.getFullState();
		// A peer update we have revoked for but not yet covered by a signature
		// of ours: still owed, whatever happens to our own add.
		state.htlcs.set('received-9', {
			id: 9n,
			amountMsat: 10_000n,
			paymentHash: crypto.randomBytes(32),
			onionRoutingPacket: Buffer.alloc(1366),
			cltvExpiry: 800_000,
			direction: 1,
			state: HtlcState.PENDING,
			addLocallyRevoked: true
		} as never);
		state.restoreRecencyUnproven = true;

		channel.markForReestablish();
		expect(state.needsCommitment).to.equal(true);
	});

	it('drops the add on a row the capsule already wrapped in AWAITING_REESTABLISH', () => {
		// A capsule can hold a channel persisted mid-reestablish.
		// markForReestablish refuses that state on purpose - re-wrapping would
		// overwrite preReestablishState and lose the state the channel returns
		// to - so the rollback has to reach it another way, or the add is
		// replayed the moment the peer reconnects.
		const { channel, htlcId } = channelWithUnsignedAdd();
		const state = channel.getFullState();
		state.preReestablishState = ChannelState.NORMAL;
		state.state = ChannelState.AWAITING_REESTABLISH;
		state.restoreRecencyUnproven = true;

		expect(
			channel.markForReestablish(),
			'the wrapping path correctly declines this state'
		).to.have.length(0);

		const abandoned = channel.dropUnsignedHeldAdds();
		expect(abandoned, 'but the rollback still runs').to.have.length(1);
		expect(abandoned[0].htlcId).to.equal(htlcId);
		expect(state.pendingLocalUpdates).to.have.length(0);
		expect(
			state.preReestablishState,
			'and the state it returns to is untouched'
		).to.equal(ChannelState.NORMAL);
	});

	it('the reestablish replay carries no dropped add', () => {
		const { channel, htlcId } = channelWithUnsignedAdd();
		const state = channel.getFullState();
		state.restoreRecencyUnproven = true;
		channel.markForReestablish();

		const actions = channel.handleReestablish({
			channelId: state.channelId!,
			nextCommitmentNumber: state.remoteCommitmentNumber + 1n,
			nextRevocationNumber: state.localCommitmentNumber,
			yourLastPerCommitmentSecret: Buffer.alloc(32),
			myCurrentPerCommitmentPoint: state.remoteBasepoints!.fundingPubkey
		} as never);

		const replayedAdd = actions.find(
			(a) =>
				a.type === ChannelActionType.SEND_MESSAGE &&
				(a as { messageType: number }).messageType ===
					MessageType.UPDATE_ADD_HTLC
		);
		expect(replayedAdd, `add ${htlcId} is not re-offered`).to.equal(undefined);
	});
});
