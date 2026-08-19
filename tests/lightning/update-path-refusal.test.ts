/**
 * Issue #404: update-path refusals return a bare ERROR the peer never sees.
 *
 * `ChannelActionType.ERROR` is never put on the wire, so a refused
 * `update_add_htlc` or `update_fee` left the peer holding an entry our own
 * commitment would never hold. Its next `commitment_signed` then covered state
 * we do not have, `verifyRemoteCommitmentSig` failed, and the channel force
 * closed a round later blamed on "Invalid commitment signature" rather than on
 * the refusal that actually happened.
 *
 * The rule these tests pin: an arm is wire-visible iff the refusal is
 * unconditional and permanent AND no legal in-flight crossing can produce it.
 * The second clause is what keeps the lifecycle guards and the SENT_STFU half
 * of the quiescence guard local, and the control tests below are the ones that
 * fail if a later change "unifies" them with the rest.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { Channel } from '../../src/lightning/channel/channel';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import {
	createAcceptorState,
	IChannelState
} from '../../src/lightning/channel/channel-state';
import {
	ChannelRole,
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	HtlcDirection,
	HtlcState
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	IUpdateAddHtlcMessage,
	IUpdateFeeMessage
} from '../../src/lightning/message/channel-update';
import { QuiescenceState } from '../../src/lightning/channel/quiescence';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';
import { expectWireFailure, wireRefusalOf } from './helpers/open-refusal';

function makeBasepoints(seed: string): IChannelBasepoints {
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

/**
 * A NORMAL non-anchor channel where WE are the acceptor and the peer is the
 * funder, so every inbound arm of both handlers is reachable. A FRESH one per
 * assertion, because a wire-visible refusal now marks the channel ERRORED.
 */
function makeChannel(
	overrides: Partial<IChannelState> = {},
	config: Partial<typeof DEFAULT_CHANNEL_CONFIG> = {}
): Channel {
	const state = createAcceptorState({
		temporaryChannelId: crypto.randomBytes(32),
		fundingSatoshis: 1_000_000n,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG, ...config },
		localBasepoints: makeBasepoints('acceptor'),
		localPerCommitmentSeed: crypto.createHash('sha256').update('c').digest(),
		remoteBasepoints: makeBasepoints('opener'),
		remoteConfig: { ...DEFAULT_CHANNEL_CONFIG, feeratePerKw: 253 }
	});
	state.channelId = crypto.randomBytes(32);
	state.fundingTxid = crypto.randomBytes(32);
	state.fundingOutputIndex = 0;
	state.state = ChannelState.NORMAL;
	state.commitmentFeeratePerkw = 253;
	state.localBalanceMsat = 400_000_000n;
	state.remoteBalanceMsat = 500_000_000n;
	state.remoteCurrentPerCommitmentPoint =
		state.remoteBasepoints!.firstPerCommitmentPoint;
	state.remoteNextPerCommitmentPoint =
		state.remoteBasepoints!.firstPerCommitmentPoint;
	Object.assign(state, overrides);
	return new Channel(state);
}

function add(
	channel: Channel,
	over: Partial<IUpdateAddHtlcMessage> = {}
): IUpdateAddHtlcMessage {
	return {
		channelId: channel.getChannelId()!,
		id: 0n,
		amountMsat: 1_000_000n,
		paymentHash: crypto.randomBytes(32),
		cltvExpiry: 500,
		onionRoutingPacket: Buffer.alloc(1366),
		...over
	};
}

function fee(channel: Channel, feeratePerKw: number): IUpdateFeeMessage {
	return { channelId: channel.getChannelId()!, feeratePerKw };
}

/** A committed inbound HTLC, so dust-exposure and in-flight arms are reachable. */
function seedHtlc(channel: Channel, amountMsat: bigint, id: bigint): void {
	channel.getFullState().htlcs.set(`received-${id}`, {
		id,
		direction: HtlcDirection.RECEIVED,
		amountMsat,
		paymentHash: crypto.randomBytes(32),
		cltvExpiry: 500,
		onionRoutingPacket: Buffer.alloc(1366),
		state: HtlcState.COMMITTED
	});
}

describe('Update-path refusals reach the peer (issue 404)', function () {
	describe('handleUpdateAddHtlc', function () {
		const cases: Array<{
			name: string;
			reason: RegExp;
			run: () => {
				channel: Channel;
				actions: ReturnType<Channel['handleUpdateAddHtlc']>;
			};
		}> = [
			{
				name: 'an id collision with different contents',
				reason: /reuses id/,
				run: () => {
					const channel = makeChannel();
					seedHtlc(channel, 1_000_000n, 0n);
					return {
						channel,
						actions: channel.handleUpdateAddHtlc(
							add(channel, { id: 0n, amountMsat: 3_000_000n })
						)
					};
				}
			},
			{
				name: 'a zero amount',
				reason: /greater than 0/,
				run: () => {
					const channel = makeChannel();
					return {
						channel,
						actions: channel.handleUpdateAddHtlc(
							add(channel, { amountMsat: 0n })
						)
					};
				}
			},
			{
				name: 'an amount below the htlc_minimum_msat we advertised',
				reason: /below our minimum/,
				run: () => {
					const channel = makeChannel({}, { htlcMinimumMsat: 10_000n });
					return {
						channel,
						actions: channel.handleUpdateAddHtlc(
							add(channel, { amountMsat: 5_000n })
						)
					};
				}
			},
			{
				name: 'more adds than the max_accepted_htlcs we advertised',
				reason: /Max inbound pending/,
				run: () => {
					const channel = makeChannel({}, { maxAcceptedHtlcs: 1 });
					channel.getFullState().htlcs.set('received-9', {
						id: 9n,
						direction: HtlcDirection.RECEIVED,
						amountMsat: 1_000n,
						paymentHash: crypto.randomBytes(32),
						cltvExpiry: 500,
						onionRoutingPacket: Buffer.alloc(1366),
						state: HtlcState.PENDING
					});
					return {
						channel,
						actions: channel.handleUpdateAddHtlc(add(channel))
					};
				}
			},
			{
				name: 'more value than the max_htlc_value_in_flight_msat we advertised',
				reason: /Max inbound HTLC value/,
				run: () => {
					const channel = makeChannel(
						{},
						{ maxHtlcValueInFlightMsat: 50_000n }
					);
					return {
						channel,
						actions: channel.handleUpdateAddHtlc(
							add(channel, { amountMsat: 60_000n })
						)
					};
				}
			},
			{
				name: 'an amount the sender cannot afford above its reserve',
				reason: /cannot afford HTLC above channel reserve/,
				run: () => {
					const channel = makeChannel();
					return {
						channel,
						actions: channel.handleUpdateAddHtlc(
							add(channel, { amountMsat: 499_000_000n })
						)
					};
				}
			},
			{
				name: 'a cltv_expiry that is a unix timestamp',
				reason: /not a block height/,
				run: () => {
					const channel = makeChannel();
					return {
						channel,
						actions: channel.handleUpdateAddHtlc(
							add(channel, { cltvExpiry: 500_000_001 })
						)
					};
				}
			},
			{
				name: 'a cltv_expiry that has already expired',
				reason: /CLTV already expired/,
				run: () => {
					const channel = makeChannel();
					channel.setBlockHeight(1_000);
					return {
						channel,
						actions: channel.handleUpdateAddHtlc(
							add(channel, { cltvExpiry: 999 })
						)
					};
				}
			},
			{
				name: 'a cltv_expiry past our horizon',
				reason: /CLTV too far in future/,
				run: () => {
					const channel = makeChannel();
					channel.setBlockHeight(1_000);
					return {
						channel,
						actions: channel.handleUpdateAddHtlc(
							add(channel, { cltvExpiry: 1_000 + 5_041 })
						)
					};
				}
			}
		];

		for (const c of cases) {
			it(`fails the channel on the wire for ${c.name}`, function () {
				const { channel, actions } = c.run();
				expectWireFailure(actions, channel.getChannelId()!, c.reason);
				expect(channel.getState()).to.equal(ChannelState.ERRORED);
			});
		}

		it('fails the channel on the wire for dust exposure over our ceiling', function () {
			// Our own ceiling, not a BOLT 2 MUST, and told anyway: the peer could not
			// have predicted the policy but the divergence is identical.
			const channel = makeChannel({}, { dustLimitSatoshis: 100_000n });
			seedHtlc(channel, 50_000_000n, 5n);
			const actions = channel.handleUpdateAddHtlc(
				add(channel, { id: 1n, amountMsat: 50_000_000n })
			);
			expectWireFailure(
				actions,
				channel.getChannelId()!,
				/Dust HTLC exposure limit exceeded/
			);
			expect(channel.getState()).to.equal(ChannelState.ERRORED);
		});

		it('control: a byte-identical replay is still a no-op', function () {
			const channel = makeChannel();
			const msg = add(channel);
			channel.getFullState().htlcs.set('received-0', {
				id: 0n,
				direction: HtlcDirection.RECEIVED,
				amountMsat: msg.amountMsat,
				paymentHash: msg.paymentHash,
				cltvExpiry: msg.cltvExpiry,
				onionRoutingPacket: msg.onionRoutingPacket,
				state: HtlcState.COMMITTED
			});
			expect(channel.handleUpdateAddHtlc(msg)).to.have.length(0);
			expect(channel.getState()).to.equal(ChannelState.NORMAL);
		});

		it('ACCEPTS an add that crossed our own shutdown', function () {
			// BOLT 2 forbids an add only AFTER the peer has received our shutdown,
			// and until it sends its own we have no evidence it has. Dropping such an
			// add does not spare the channel: the peer's covering commitment_signed
			// is then verified against a commitment that lacks the HTLC and the
			// channel dies on an "invalid signature" that was never invalid.
			const channel = makeChannel({
				state: ChannelState.SHUTTING_DOWN,
				localShutdownScript: Buffer.alloc(22),
				remoteShutdownScript: null
			});
			const actions = channel.handleUpdateAddHtlc(add(channel));
			expect(actions, 'admitted, not refused').to.have.length(0);
			expect(
				channel.getFullState().htlcs.get('received-0'),
				'recorded'
			).to.not.equal(undefined);
			expect(channel.getState()).to.equal(ChannelState.SHUTTING_DOWN);
		});

		// The end-to-end half of this, where the peer's covering commitment_signed
		// is verified against the commitment the admitted add produced, needs a real
		// signing pair and lives in bolt2-low-hardening.test.ts beside normalPair.

		it('control: an add after the PEER shut down still refuses LOCALLY', function () {
			// The peer IS bound here, and it is still not condemned. Two reasons,
			// both at the guard: nothing cascades (handleCommitmentSigned refuses a
			// covering commitment outside NORMAL/SHUTTING_DOWN, so the add stalls
			// rather than force-closing), and handleReestablish REPLAYS every queued
			// update_add_htlc after a reconnect, so a peer retransmitting an
			// unrevoked add into a shutting-down channel is doing exactly what BOLT 2
			// requires. Wire-failing here would force close a conformant peer.
			const channel = makeChannel({
				state: ChannelState.NEGOTIATING_CLOSING,
				localShutdownScript: Buffer.alloc(22),
				remoteShutdownScript: Buffer.alloc(22)
			});
			const actions = channel.handleUpdateAddHtlc(add(channel));
			expect(wireRefusalOf(actions), 'nothing on the wire').to.equal(null);
			expect(actions).to.have.length(1);
			expect(channel.getState()).to.equal(ChannelState.NEGOTIATING_CLOSING);
		});

		it('control: a CLOSED channel refuses LOCALLY and is preserved', function () {
			// The peer may simply not have seen our transition, and destroying a
			// close that is going fine would be worse than refusing.
			const channel = makeChannel({ state: ChannelState.CLOSED });
			const actions = channel.handleUpdateAddHtlc(add(channel));
			expect(wireRefusalOf(actions), 'nothing on the wire').to.equal(null);
			expect(actions).to.have.length(1);
			const local = actions[0] as { type: ChannelActionType; cleanup?: string };
			expect(local.type).to.equal(ChannelActionType.ERROR);
			expect(local.cleanup, 'the manager must not drop the lifecycle').to.equal(
				'none'
			);
			expect(channel.getState()).to.equal(ChannelState.CLOSED);
		});
	});

	describe('the quiescence guard splits on WHO sent stfu', function () {
		it('fails the channel once the PEER has sent stfu', function () {
			const channel = makeChannel();
			channel.handleStfuMessage({
				channelId: channel.getChannelId()!,
				initiator: true
			});
			// Answering it lands in QUIESCENT; RECEIVED_STFU takes the same arm,
			// since peerHasSentStfu() covers both and only the PEER's stfu matters.
			expect(channel.getQuiescenceState()).to.equal(QuiescenceState.QUIESCENT);
			const actions = channel.handleUpdateAddHtlc(add(channel));
			expectWireFailure(
				actions,
				channel.getChannelId()!,
				/update_add_htlc after your stfu/
			);
			expect(channel.getState()).to.equal(ChannelState.ERRORED);
		});

		it('control: an add that merely crossed OUR stfu stays local', function () {
			// The peer owes nothing until it has received our stfu, a moment we
			// cannot observe, and BOLT 2 requires that window to exist.
			const channel = makeChannel();
			channel.initiateQuiescence();
			expect(channel.getQuiescenceState()).to.equal(QuiescenceState.SENT_STFU);
			const actions = channel.handleUpdateAddHtlc(add(channel));
			expect(wireRefusalOf(actions), 'nothing on the wire').to.equal(null);
			expect(actions).to.have.length(1);
			expect(channel.getState()).to.equal(ChannelState.NORMAL);
		});
	});

	describe('handleUpdateFee', function () {
		it('fails the channel on the wire when we are not the acceptor', function () {
			const channel = makeChannel({ role: ChannelRole.OPENER });
			const actions = channel.handleUpdateFee(fee(channel, 1_000));
			expectWireFailure(
				actions,
				channel.getChannelId()!,
				/Only opener can send update_fee/
			);
			expect(channel.getState()).to.equal(ChannelState.ERRORED);
		});

		it('fails the channel on the wire below the relay floor', function () {
			const channel = makeChannel();
			const actions = channel.handleUpdateFee(fee(channel, 252));
			expectWireFailure(
				actions,
				channel.getChannelId()!,
				/below minimum relay fee/
			);
			expect(channel.getState()).to.equal(ChannelState.ERRORED);
		});

		it('fails the channel on the wire above the absolute ceiling', function () {
			const channel = makeChannel();
			const actions = channel.handleUpdateFee(fee(channel, 100_001));
			expectWireFailure(
				actions,
				channel.getChannelId()!,
				/above absolute maximum/
			);
			expect(channel.getState()).to.equal(ChannelState.ERRORED);
		});

		it('fails the channel on the wire past the 10x relative bound', function () {
			const channel = makeChannel();
			const actions = channel.handleUpdateFee(fee(channel, 2_531));
			expectWireFailure(actions, channel.getChannelId()!, /unreasonably high/);
			expect(channel.getState()).to.equal(ChannelState.ERRORED);
		});

		it('but measures 10x against the rate already STAGED in this round', function () {
			// BOLT 2 lets the opener send several update_fee inside one round and
			// counts the last. pendingFeeratePerKw is promoted into remoteConfig only
			// at the signable phase or round completion, so measuring against the
			// committed rate refused a legal escalation. Now that this arm fails the
			// channel, that false positive would be fatal.
			const channel = makeChannel();
			expect(channel.handleUpdateFee(fee(channel, 2_530))).to.have.length(0);
			expect(channel.getFullState().pendingFeeratePerKw).to.equal(2_530);
			expect(channel.handleUpdateFee(fee(channel, 25_300))).to.have.length(0);
			expect(channel.getState()).to.equal(ChannelState.NORMAL);
		});

		it('fails the channel on the wire when the rate drains the opener', function () {
			const channel = makeChannel({ remoteBalanceMsat: 3_000_000n });
			const actions = channel.handleUpdateFee(fee(channel, 2_500));
			expectWireFailure(
				actions,
				channel.getChannelId()!,
				/drain opener below channel reserve/
			);
			expect(channel.getState()).to.equal(ChannelState.ERRORED);
		});

		it('control: the lifecycle guard stays LOCAL on a closed channel', function () {
			const channel = makeChannel({ state: ChannelState.CLOSED });
			const actions = channel.handleUpdateFee(fee(channel, 1_000));
			expect(wireRefusalOf(actions), 'nothing on the wire').to.equal(null);
			expect(actions).to.have.length(1);
			const local = actions[0] as { type: ChannelActionType; cleanup?: string };
			expect(local.cleanup, 'the manager must not drop the lifecycle').to.equal(
				'none'
			);
			expect(channel.getState()).to.equal(ChannelState.CLOSED);
		});
	});

	describe('no refusal arm mutates before it refuses', function () {
		it('leaves the HTLC map and both balances untouched', function () {
			const channel = makeChannel();
			const before = {
				htlcs: channel.getFullState().htlcs.size,
				local: channel.getFullState().localBalanceMsat,
				remote: channel.getFullState().remoteBalanceMsat
			};
			channel.handleUpdateAddHtlc(add(channel, { amountMsat: 499_000_000n }));
			expect(channel.getFullState().htlcs.size).to.equal(before.htlcs);
			expect(channel.getFullState().localBalanceMsat).to.equal(before.local);
			expect(channel.getFullState().remoteBalanceMsat).to.equal(before.remote);
		});

		it('leaves the staged and committed feerates untouched', function () {
			const channel = makeChannel({ remoteBalanceMsat: 3_000_000n });
			const before = {
				pending: channel.getFullState().pendingFeeratePerKw,
				committed: channel.getFullState().remoteConfig.feeratePerKw
			};
			channel.handleUpdateFee(fee(channel, 2_500));
			expect(channel.getFullState().pendingFeeratePerKw).to.equal(
				before.pending
			);
			expect(channel.getFullState().remoteConfig.feeratePerKw).to.equal(
				before.committed
			);
		});
	});

	describe('a failure the id cannot carry stays off the wire', function () {
		// _failChannelWithWireError shares refuseWithWireError's scope rule. Without
		// that, an all-zero channel_id would tell the peer to fail EVERY channel it
		// has with us, and a malformed-length one would throw out of the helper
		// AFTER the channel had already been marked ERRORED, so the caller got no
		// actions at all for a channel that was now failed.

		it('suppresses the wire half under the reserved all-zero id', function () {
			const channel = makeChannel({ channelId: Buffer.alloc(32) });
			const actions = channel.handleUpdateAddHtlc(
				add(channel, { amountMsat: 0n })
			);
			expect(wireRefusalOf(actions), 'never connection-wide').to.equal(null);
			// The channel is still failed and still persisted; only the peer's
			// notification is lost.
			expect(channel.getState()).to.equal(ChannelState.ERRORED);
			expect(actions[0].type).to.equal(ChannelActionType.PERSIST_STATE);
			expect(
				actions.some((a) => a.type === ChannelActionType.ERROR),
				'the local failure still stands'
			).to.equal(true);
		});

		it('and does not throw on a malformed-length id', function () {
			const channel = makeChannel({ channelId: Buffer.alloc(16) });
			let actions: ReturnType<Channel['handleUpdateAddHtlc']> = [];
			expect(() => {
				actions = channel.handleUpdateAddHtlc(add(channel, { amountMsat: 0n }));
			}, 'a throw would strand an ERRORED channel with no actions').to.not.throw();
			expect(wireRefusalOf(actions)).to.equal(null);
			expect(channel.getState()).to.equal(ChannelState.ERRORED);
			expect(actions.some((a) => a.type === ChannelActionType.ERROR)).to.equal(
				true
			);
		});
	});
});

/** An OFFERED htlc with a known preimage, for the resolution handlers. */
function seedOfferedHtlc(channel: Channel, id: bigint, preimage: Buffer): void {
	channel.getFullState().htlcs.set(`offered-${id}`, {
		id,
		direction: HtlcDirection.OFFERED,
		amountMsat: 1_000_000n,
		paymentHash: crypto.createHash('sha256').update(preimage).digest(),
		cltvExpiry: 500,
		onionRoutingPacket: Buffer.alloc(1366),
		state: HtlcState.COMMITTED
	});
}

function makeTaprootChannelType(): Buffer {
	const flags = FeatureFlags.empty();
	flags.setCompulsory(Feature.OPTION_TAPROOT);
	return flags.toBuffer();
}

describe('Resolution and closing refusals reach the peer (issue 409)', function () {
	describe('handleUpdateFulfillHtlc', function () {
		it('fails the channel on the wire on an invalid preimage (attempted theft)', function () {
			const channel = makeChannel();
			seedOfferedHtlc(channel, 0n, Buffer.alloc(32, 1));
			const actions = channel.handleUpdateFulfillHtlc({
				channelId: channel.getChannelId()!,
				id: 0n,
				paymentPreimage: Buffer.alloc(32, 2)
			});
			expectWireFailure(
				actions,
				channel.getChannelId()!,
				/Invalid preimage for offered HTLC/
			);
			expect(channel.getState()).to.equal(ChannelState.ERRORED);
		});

		it('control: an unknown id refuses LOCALLY (crash-replay carve-out)', function () {
			// A peer restored from a legally lagging snapshot replays its whole
			// pending-update queue, and the replayed fulfill can land on an entry
			// the completed round already deleted. Never wire-fail it.
			const channel = makeChannel();
			const actions = channel.handleUpdateFulfillHtlc({
				channelId: channel.getChannelId()!,
				id: 99n,
				paymentPreimage: Buffer.alloc(32, 2)
			});
			expect(wireRefusalOf(actions), 'nothing on the wire').to.equal(null);
			expect(actions).to.have.length(1);
			expect(actions[0].type).to.equal(ChannelActionType.ERROR);
			expect(channel.getState()).to.equal(ChannelState.NORMAL);
		});
	});

	describe('handleUpdateFailHtlc / handleUpdateFailMalformedHtlc', function () {
		it('control: an unknown id on update_fail_htlc refuses LOCALLY', function () {
			const channel = makeChannel();
			const actions = channel.handleUpdateFailHtlc({
				channelId: channel.getChannelId()!,
				id: 99n,
				reason: Buffer.alloc(32)
			});
			expect(wireRefusalOf(actions), 'nothing on the wire').to.equal(null);
			expect(actions).to.have.length(1);
			expect(channel.getState()).to.equal(ChannelState.NORMAL);
		});

		it('fails the channel on the wire when failure_code lacks BADONION', function () {
			// The bit check precedes the entry lookup, so no seeding needed: a
			// missing BADONION bit is nonconformant whatever the id refers to.
			const channel = makeChannel();
			const actions = channel.handleUpdateFailMalformedHtlc({
				channelId: channel.getChannelId()!,
				id: 0n,
				sha256OfOnion: Buffer.alloc(32),
				failureCode: 0x4001 // BADONION (0x8000) not set
			});
			expectWireFailure(actions, channel.getChannelId()!, /BADONION/);
			expect(channel.getState()).to.equal(ChannelState.ERRORED);
		});

		it('control: an unknown id with a proper BADONION code refuses LOCALLY', function () {
			const channel = makeChannel();
			const actions = channel.handleUpdateFailMalformedHtlc({
				channelId: channel.getChannelId()!,
				id: 99n,
				sha256OfOnion: Buffer.alloc(32),
				failureCode: 0x8000 | 1
			});
			expect(wireRefusalOf(actions), 'nothing on the wire').to.equal(null);
			expect(actions).to.have.length(1);
			expect(channel.getState()).to.equal(ChannelState.NORMAL);
		});
	});

	describe('handleRevokeAndAck, taproot nonce arm', function () {
		it('fails the channel on the wire when next_local_nonce is missing', function () {
			const secret = crypto.createHash('sha256').update('raa-s').digest();
			const channel = makeChannel({
				channelType: makeTaprootChannelType(),
				remoteCommitmentNumber: 1n,
				remoteCurrentPerCommitmentPoint: getPublicKey(secret)
			});
			const actions = channel.handleRevokeAndAck({
				channelId: channel.getChannelId()!,
				perCommitmentSecret: secret,
				nextPerCommitmentPoint: getPublicKey(Buffer.alloc(32, 7))
				// no nextLocalNonce
			});
			expectWireFailure(actions, channel.getChannelId()!, /next_local_nonce/);
			expect(channel.getState()).to.equal(ChannelState.ERRORED);
		});
	});
});
