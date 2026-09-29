/**
 * Issue #1047: receive-side state-machine checks that disagreed with BOLT 2/3.
 *
 * The funder-affordability arms of handleUpdateAddHtlc and handleUpdateFee
 * counted trimmed HTLCs toward the funder's commitment fee, so a funder
 * holding dust HTLCs was failed at a boundary the spec formula admits. And a
 * settle for an offered HTLC the peer had not yet committed was accepted,
 * where BOLT 2 says the receiver MUST fail the channel.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { Channel } from '../../src/lightning/channel/channel';
import {
	ChannelAction,
	ChannelActionType
} from '../../src/lightning/channel/channel-actions';
import {
	createAcceptorState,
	IChannelState
} from '../../src/lightning/channel/channel-state';
import {
	ChannelRole,
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	HtlcDirection,
	HtlcState,
	IHtlcEntry
} from '../../src/lightning/channel/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { IUpdateAddHtlcMessage } from '../../src/lightning/message/channel-update';
import { MessageType } from '../../src/lightning/message/types';

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

function anchorType(): Buffer {
	const flags = FeatureFlags.empty();
	flags.setOptional(Feature.ANCHOR_ZERO_FEE_HTLC);
	return flags.toBuffer();
}

/**
 * A NORMAL channel where the PEER funds, with default dust limits (354 sat)
 * and a 10,000-sat reserve both ways, so _localCommitmentEmptyRefusal
 * short-circuits and no guard reaches the builder or a signer.
 */
function makeChannel(opts: {
	channelType: Buffer | null;
	remoteFeeratePerKw: number;
	remoteMsat: bigint;
	htlcs?: Partial<IHtlcEntry>[];
}): Channel {
	const state: IChannelState = createAcceptorState({
		temporaryChannelId: crypto.randomBytes(32),
		fundingSatoshis: 1_000_000n,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG, channelReserveSatoshis: 10_000n },
		localBasepoints: makeBasepoints(Buffer.from('local')),
		localPerCommitmentSeed: crypto.createHash('sha256').update('c').digest(),
		remoteBasepoints: makeBasepoints(Buffer.from('remote')),
		remoteConfig: {
			...DEFAULT_CHANNEL_CONFIG,
			channelReserveSatoshis: 10_000n,
			feeratePerKw: opts.remoteFeeratePerKw
		}
	});
	state.channelId = crypto.randomBytes(32);
	state.fundingTxid = crypto.randomBytes(32);
	state.fundingOutputIndex = 0;
	state.state = ChannelState.NORMAL;
	state.role = ChannelRole.ACCEPTOR;
	state.channelType = opts.channelType;
	state.localBalanceMsat = 500_000_000n;
	state.remoteBalanceMsat = opts.remoteMsat;
	state.remoteCurrentPerCommitmentPoint =
		state.remoteBasepoints!.firstPerCommitmentPoint;
	state.remoteNextPerCommitmentPoint =
		state.remoteBasepoints!.firstPerCommitmentPoint;
	(opts.htlcs ?? []).forEach((h, i) => {
		const direction = h.direction ?? HtlcDirection.OFFERED;
		const key = `${
			direction === HtlcDirection.OFFERED ? 'offered' : 'received'
		}-${i}`;
		state.htlcs.set(key, {
			id: BigInt(i),
			amountMsat: 1_000_000n,
			paymentHash: crypto.randomBytes(32),
			cltvExpiry: 600,
			onionRoutingPacket: Buffer.alloc(1366),
			state: HtlcState.COMMITTED,
			...h,
			direction
		});
	});
	return new Channel(state);
}

const errorOf = (actions: ChannelAction[]): string | null => {
	for (const a of actions) {
		if (a.type === ChannelActionType.ERROR) {
			return (a as unknown as { message: string }).message;
		}
	}
	return null;
};

const sentWireError = (actions: ChannelAction[]): boolean =>
	actions.some(
		(a) =>
			a.type === ChannelActionType.SEND_MESSAGE &&
			(a as unknown as { messageType: MessageType }).messageType ===
				MessageType.ERROR
	);

const addMsg = (
	channel: Channel,
	amountMsat: bigint
): IUpdateAddHtlcMessage => ({
	channelId: channel.getChannelId()!,
	id: 99n,
	amountMsat,
	paymentHash: crypto.randomBytes(32),
	cltvExpiry: 500,
	onionRoutingPacket: Buffer.alloc(1366)
});

/** Three offered HTLCs of 100 sat: under the 354-sat dust limit on any channel. */
const dust = (): Partial<IHtlcEntry>[] =>
	[0, 1, 2].map(() => ({ amountMsat: 100_000n }));

describe('Channel state-machine leniencies (issue #1047)', function () {
	describe('handleUpdateAddHtlc: the funder pays for untrimmed HTLCs only', function () {
		// Anchor channel at 5,000 sat/kw: with only the new HTLC untrimmed the
		// funder owes (1124 + 172) * 5 = 6,480 sat plus 660 in anchors above its
		// 10,000-sat reserve. Counting the three dust HTLCs as well priced it at
		// (1124 + 688) * 5 + 660 = 9,720 and failed this add.
		it('admits an add the spec formula affords beside dust HTLCs', function () {
			const channel = makeChannel({
				channelType: anchorType(),
				remoteFeeratePerKw: 5_000,
				remoteMsat: 20_000_000n,
				htlcs: dust()
			});
			const actions = channel.handleUpdateAddHtlc(addMsg(channel, 2_860_000n));
			expect(errorOf(actions)).to.equal(null);
			expect(channel.getFullState().remoteBalanceMsat).to.equal(17_140_000n);
		});

		it('still fails one msat past that boundary', function () {
			const channel = makeChannel({
				channelType: anchorType(),
				remoteFeeratePerKw: 5_000,
				remoteMsat: 20_000_000n,
				htlcs: dust()
			});
			const actions = channel.handleUpdateAddHtlc(addMsg(channel, 2_860_001n));
			expect(errorOf(actions)).to.equal(
				'Remote cannot afford HTLC above channel reserve'
			);
			expect(sentWireError(actions)).to.equal(true);
		});

		it('trims at the second-level fee on a legacy channel', function () {
			// 1,000-sat HTLCs clear the 354-sat dust limit but not the 3,669-sat
			// offered threshold at 5,000 sat/kw (354 + 663 * 5), so only the new
			// add is paid for: (724 + 172) * 5 = 4,480 sat, no anchors.
			const htlcs = [0, 1, 2].map(() => ({ amountMsat: 1_000_000n }));
			const admitted = makeChannel({
				channelType: null,
				remoteFeeratePerKw: 5_000,
				remoteMsat: 20_000_000n,
				htlcs
			});
			expect(
				errorOf(admitted.handleUpdateAddHtlc(addMsg(admitted, 5_520_000n)))
			).to.equal(null);
			const refused = makeChannel({
				channelType: null,
				remoteFeeratePerKw: 5_000,
				remoteMsat: 20_000_000n,
				htlcs
			});
			expect(
				errorOf(refused.handleUpdateAddHtlc(addMsg(refused, 5_520_001n)))
			).to.equal('Remote cannot afford HTLC above channel reserve');
		});

		it('still counts untrimmed HTLCs already in flight', function () {
			// Two 5,000-sat HTLCs stay untrimmed: (1124 + 516) * 5 + 660 = 8,860.
			const fixture = (): Channel =>
				makeChannel({
					channelType: anchorType(),
					remoteFeeratePerKw: 5_000,
					remoteMsat: 20_000_000n,
					htlcs: [
						...dust(),
						{ amountMsat: 5_000_000n },
						{ amountMsat: 5_000_000n }
					]
				});
			const admitted = fixture();
			expect(
				errorOf(admitted.handleUpdateAddHtlc(addMsg(admitted, 1_140_000n)))
			).to.equal(null);
			const refused = fixture();
			expect(
				errorOf(refused.handleUpdateAddHtlc(addMsg(refused, 1_140_001n)))
			).to.equal('Remote cannot afford HTLC above channel reserve');
		});
	});

	describe('handleUpdateFee: the funder pays for untrimmed HTLCs only', function () {
		// 10,000 sat/kw with no untrimmed HTLC: 1124 * 10 + 660 = 11,900 sat.
		// The three dust HTLCs used to add 516 * 10 on top.
		it('accepts a rate the spec formula affords beside dust HTLCs', function () {
			const channel = makeChannel({
				channelType: anchorType(),
				remoteFeeratePerKw: 2_000,
				remoteMsat: 21_900_000n,
				htlcs: dust()
			});
			const actions = channel.handleUpdateFee({
				channelId: channel.getChannelId()!,
				feeratePerKw: 10_000
			});
			expect(errorOf(actions)).to.equal(null);
			expect(channel.getFullState().pendingFeeratePerKw).to.equal(10_000);
		});

		it('still fails one msat under that boundary', function () {
			const channel = makeChannel({
				channelType: anchorType(),
				remoteFeeratePerKw: 2_000,
				remoteMsat: 21_899_999n,
				htlcs: dust()
			});
			const actions = channel.handleUpdateFee({
				channelId: channel.getChannelId()!,
				feeratePerKw: 10_000
			});
			expect(errorOf(actions)).to.equal(
				'Fee rate would drain opener below channel reserve'
			);
			expect(sentWireError(actions)).to.equal(true);
		});
	});

	describe('peer settles for an offered HTLC it has not committed', function () {
		const preimage = Buffer.alloc(32, 7);
		const paymentHash = crypto.createHash('sha256').update(preimage).digest();

		const settles: {
			name: string;
			wire: string;
			send: (channel: Channel) => ChannelAction[];
			settled: HtlcState;
		}[] = [
			{
				name: 'update_fulfill_htlc',
				wire: 'update_fulfill_htlc for an HTLC not yet committed',
				send: (channel) =>
					channel.handleUpdateFulfillHtlc({
						channelId: channel.getChannelId()!,
						id: 0n,
						paymentPreimage: preimage
					}),
				settled: HtlcState.FULFILLED
			},
			{
				name: 'update_fail_htlc',
				wire: 'update_fail_htlc for an HTLC not yet committed',
				send: (channel) =>
					channel.handleUpdateFailHtlc({
						channelId: channel.getChannelId()!,
						id: 0n,
						reason: Buffer.alloc(32)
					}),
				settled: HtlcState.FAILED
			},
			{
				name: 'update_fail_malformed_htlc',
				wire: 'update_fail_malformed_htlc for an HTLC not yet committed',
				send: (channel) =>
					channel.handleUpdateFailMalformedHtlc({
						channelId: channel.getChannelId()!,
						id: 0n,
						sha256OfOnion: Buffer.alloc(32),
						failureCode: 0xc005
					}),
				settled: HtlcState.FAILED
			}
		];

		const withOffered = (entry: Partial<IHtlcEntry>): Channel =>
			makeChannel({
				channelType: anchorType(),
				remoteFeeratePerKw: 2_000,
				remoteMsat: 400_000_000n,
				htlcs: [{ paymentHash, ...entry }]
			});

		for (const s of settles) {
			it(`fails the channel on ${s.name} for an add still PENDING`, function () {
				const channel = withOffered({
					state: HtlcState.PENDING,
					addRemoteCommitted: false
				});
				const actions = s.send(channel);
				expect(errorOf(actions)).to.equal(s.wire);
				expect(sentWireError(actions)).to.equal(true);
				expect(channel.getState()).to.equal(ChannelState.ERRORED);
				expect(channel.getFullState().htlcs.get('offered-0')!.state).to.equal(
					HtlcState.PENDING
				);
			});

			it(`fails the channel on ${s.name} before the peer revoked for the add`, function () {
				const channel = withOffered({
					state: HtlcState.COMMITTED,
					addRemoteCommitted: false
				});
				expect(errorOf(s.send(channel))).to.equal(s.wire);
				expect(channel.getState()).to.equal(ChannelState.ERRORED);
			});

			it(`accepts ${s.name} once the add is committed`, function () {
				const channel = withOffered({
					state: HtlcState.COMMITTED,
					addRemoteCommitted: true
				});
				expect(errorOf(s.send(channel))).to.equal(null);
				expect(channel.getState()).to.equal(ChannelState.NORMAL);
				expect(channel.getFullState().htlcs.get('offered-0')!.state).to.equal(
					s.settled
				);
			});
		}
	});
});
