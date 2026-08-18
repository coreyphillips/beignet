import { expect } from 'chai';
import crypto from 'crypto';
import { Channel } from '../../src/lightning/channel/channel';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import {
	createAcceptorState,
	IChannelState
} from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	HtlcDirection,
	HtlcState
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { buildLocalCommitment } from '../../src/lightning/channel/commitment-builder';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { IUpdateAddHtlcMessage } from '../../src/lightning/message/channel-update';
import { IUpdateFeeMessage } from '../../src/lightning/message/channel-update';

/**
 * Issue 386: the reserve we ENFORCE on the peer floors at the LOWER of the two
 * dust limits (v2ReserveWeEnforce; computeChannelReserve's capacity/5 cap can
 * land under our own dust limit on a small v1 channel too). So on an
 * asymmetric-dust channel a peer balance that clears its reserve can still be
 * dust in the commitment WE hold, and if our own balance is already under our
 * dust limit an ordinary inbound update_add_htlc or update_fee leaves that
 * commitment with every output trimmed. A transaction with no outputs cannot be
 * broadcast, so we would hold no unilateral exit while the peer keeps one.
 */

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
		firstPerCommitmentPoint: getPublicKey(keys[1])
	};
}

interface IFixtureOpts {
	/** Our own dust limit, which is what OUR commitment trims at. */
	ourDust?: bigint;
	/** The peer's dust limit, which is what THEIR commitment trims at. */
	peerDust?: bigint;
	/** localConfig.channelReserveSatoshis: what we require of the peer. */
	enforceReserve?: bigint;
	/** remoteConfig.channelReserveSatoshis: what the peer requires of us. */
	keepReserve?: bigint;
	capacitySats?: bigint;
	ourMsat?: bigint;
	theirMsat?: bigint;
	feeratePerKw?: number;
	fundingVersion?: 1 | 2;
}

/**
 * A NORMAL non-anchor channel where WE are the acceptor and the peer is the
 * funder. Defaults reproduce issue 386's own worked example: a 2,500-sat v2
 * channel with our dust at the maximum and the peer's at the minimum, which the
 * real open path admits (only ONE side starts under its reserve, and the
 * opener's 1,817 clears both dust limits).
 */
function makeChannel(opts: IFixtureOpts = {}): Channel {
	const ourDust = opts.ourDust ?? 1_062n;
	const peerDust = opts.peerDust ?? 354n;
	const capacity = opts.capacitySats ?? 2_500n;
	const feeratePerKw = opts.feeratePerKw ?? 253;
	const ourSeed = crypto.createHash('sha256').update('acceptor').digest();
	const peerSeed = crypto.createHash('sha256').update('opener').digest();
	const commitSeed = crypto.createHash('sha256').update('commit').digest();

	const state: IChannelState = createAcceptorState({
		temporaryChannelId: crypto.randomBytes(32),
		fundingSatoshis: capacity,
		pushMsat: 0n,
		localConfig: {
			...DEFAULT_CHANNEL_CONFIG,
			dustLimitSatoshis: ourDust,
			channelReserveSatoshis: opts.enforceReserve ?? 354n
		},
		localBasepoints: makeBasepoints(ourSeed),
		localPerCommitmentSeed: commitSeed,
		remoteBasepoints: makeBasepoints(peerSeed),
		remoteConfig: {
			...DEFAULT_CHANNEL_CONFIG,
			dustLimitSatoshis: peerDust,
			channelReserveSatoshis: opts.keepReserve ?? 1_062n,
			feeratePerKw
		}
	});

	state.channelId = crypto.randomBytes(32);
	state.fundingTxid = crypto.randomBytes(32);
	state.fundingOutputIndex = 0;
	state.state = ChannelState.NORMAL;
	state.fundingVersion = opts.fundingVersion ?? 2;
	state.commitmentFeeratePerkw = feeratePerKw;
	state.localBalanceMsat = opts.ourMsat ?? 500_000n;
	state.remoteBalanceMsat = opts.theirMsat ?? 2_000_000n;
	state.remoteCurrentPerCommitmentPoint =
		state.remoteBasepoints!.firstPerCommitmentPoint;
	state.remoteNextPerCommitmentPoint =
		state.remoteBasepoints!.firstPerCommitmentPoint;

	return new Channel(state);
}

function addHtlcMsg(
	channel: Channel,
	amountMsat: bigint
): IUpdateAddHtlcMessage {
	return {
		channelId: channel.getChannelId()!,
		id: 0n,
		amountMsat,
		paymentHash: crypto.randomBytes(32),
		cltvExpiry: 500,
		onionRoutingPacket: Buffer.alloc(1366)
	};
}

function feeMsg(channel: Channel, feeratePerKw: number): IUpdateFeeMessage {
	return { channelId: channel.getChannelId()!, feeratePerKw };
}

const errorOf = (
	actions: ReturnType<Channel['handleUpdateFee']>
): string | null => {
	for (const a of actions) {
		if (a.type === ChannelActionType.ERROR) {
			return (a as unknown as { message: string }).message;
		}
	}
	return null;
};

/** Outputs of the commitment WE hold, as the builder would produce it now. */
function localOutputCount(channel: Channel): number {
	const state = channel.getFullState();
	return buildLocalCommitment(
		state,
		state.remoteBasepoints!.firstPerCommitmentPoint,
		state.localCommitmentNumber
	).result.tx.outs.length;
}

describe('Asymmetric dust limits vs peer-driven updates (issue 386)', function () {
	it('refuses an inbound update_add_htlc that would leave our commitment with no outputs', function () {
		const channel = makeChannel();
		// 800 sats is dust on OUR side (1,062 + the 177-sat success fee at 253
		// sat/kw = a 1,239-sat threshold) and not on theirs, so it becomes no
		// output in the commitment we hold. That leaves the opener on
		// 2,000 - 800 - 183 = 1,017 and us on 500, both under our 1,062 limit.
		const actions = channel.handleUpdateAddHtlc(addHtlcMsg(channel, 800_000n));
		expect(errorOf(actions)).to.match(/trim every output of the commitment/);

		// The message identifies WHICH arm refused, and the reserve arm could not
		// have: the opener needs 354 + 226 = 580 sats here and keeps 1,200.
		expect(
			Number(channel.getFullState().localConfig.channelReserveSatoshis)
		).to.equal(354);

		// And nothing was written: a refusal has to leave live state alone.
		expect(channel.getFullState().htlcs.size).to.equal(0);
		expect(Number(channel.getFullState().remoteBalanceMsat)).to.equal(
			2_000_000
		);
	});

	it('refuses an inbound update_fee that would leave our commitment with no outputs', function () {
		const channel = makeChannel();
		// 1,400 sat/kw charges 1,013 sats, taking the opener to 987.
		const actions = channel.handleUpdateFee(feeMsg(channel, 1_400));
		expect(errorOf(actions)).to.match(/trim every output of the commitment/);

		// No fee round was staged or promoted by the refusal.
		expect(channel.getFullState().pendingFeeratePerKw).to.equal(undefined);
		expect(Number(channel.getFullState().remoteConfig.feeratePerKw)).to.equal(
			253
		);
	});

	it('admits an update_fee that leaves the opener above our dust limit', function () {
		const channel = makeChannel();
		// 1,000 sat/kw charges 724, leaving the opener on 1,276.
		expect(errorOf(channel.handleUpdateFee(feeMsg(channel, 1_000)))).to.equal(
			null
		);
		expect(channel.getFullState().pendingFeeratePerKw).to.equal(1_000);
		expect(localOutputCount(channel)).to.equal(1);
	});

	it('admits an inbound HTLC that survives our dust limit as its own output', function () {
		const channel = makeChannel();
		// 1,300 sats clears the 1,239-sat threshold, so the HTLC IS an output in
		// our commitment even though both main balances are dust afterwards
		// (500 for us, 700 - 226 = 474 for the opener). A guard that only looked
		// at the two main balances would refuse this.
		expect(
			errorOf(channel.handleUpdateAddHtlc(addHtlcMsg(channel, 1_300_000n)))
		).to.equal(null);
		expect(channel.getFullState().htlcs.size).to.equal(1);
		expect(localOutputCount(channel)).to.equal(1);
	});

	it('does not refuse a commitment kept alive by a deferred settlement credit', function () {
		// The builder credits a settled HTLC back into a main balance a full
		// commitment round before the live balance field moves, so a guard that
		// read localBalanceMsat directly would understate to_local here and
		// force close a healthy channel.
		const channel = makeChannel({
			capacitySats: 3_000n,
			theirMsat: 2_500_000n
		});
		const state = channel.getFullState();
		state.remoteBalanceMsat = 1_200_000n;
		state.htlcs.set('received-7', {
			id: 7n,
			direction: HtlcDirection.RECEIVED,
			amountMsat: 1_300_000n,
			paymentHash: crypto.randomBytes(32),
			cltvExpiry: 500,
			onionRoutingPacket: Buffer.alloc(1366),
			state: HtlcState.FULFILLED,
			removalRemoteCommitted: true
		});

		// to_local is 500 + 1,300 = 1,800, above our 1,062 limit, so the
		// commitment has an output and the update is legal.
		expect(errorOf(channel.handleUpdateFee(feeMsg(channel, 1_000)))).to.equal(
			null
		);
		expect(localOutputCount(channel)).to.equal(1);
	});

	it('leaves a symmetric-dust channel entirely untouched', function () {
		// Both limits at 354 puts the reserve we enforce at or above our own dust
		// limit, which is the gate: the peer can never drop below our trim
		// threshold, so there is nothing to check and nothing to refuse.
		const channel = makeChannel({
			ourDust: 354n,
			peerDust: 354n,
			keepReserve: 546n
		});
		expect(errorOf(channel.handleUpdateFee(feeMsg(channel, 1_400)))).to.equal(
			null
		);
		const other = makeChannel({
			ourDust: 354n,
			peerDust: 354n,
			keepReserve: 546n
		});
		expect(
			errorOf(other.handleUpdateAddHtlc(addHtlcMsg(other, 800_000n)))
		).to.equal(null);
	});

	it('protects a v1 channel too, where the 20% cap puts the reserve under our dust limit', function () {
		// computeChannelReserve caps at capacity/5, so a 2,500-sat v1 channel
		// advertises 500 even though our own dust limit is 1,062. Same hole, and
		// the guard is version-agnostic because it lives in the update handlers.
		const channel = makeChannel({ fundingVersion: 1, enforceReserve: 500n });
		expect(errorOf(channel.handleUpdateFee(feeMsg(channel, 1_400)))).to.match(
			/trim every output of the commitment/
		);
	});

	it('refuses to plan a force close whose commitment has no outputs', function () {
		const channel = makeChannel();
		const state = channel.getFullState();
		// Reach the state the guards above prevent, by writing it directly.
		state.remoteBalanceMsat = 1_017_000n;
		state.remoteCommitmentSignature = crypto.randomBytes(64);
		expect(localOutputCount(channel)).to.equal(0);

		const plan = channel.prepareForceClose(channel.getSigner()!);
		expect(plan.ok).to.equal(false);
		expect((plan as { error: string }).error).to.match(
			/every commitment output is below the dust limit/
		);
	});
});
