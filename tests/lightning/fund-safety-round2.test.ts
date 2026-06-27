import { expect } from 'chai';
import crypto from 'crypto';
import { Channel } from '../../src/lightning/channel/channel';
import {
	createOpenerState,
	createAcceptorState
} from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { buildLocalCommitment } from '../../src/lightning/channel/commitment-builder';
import {
	IChannelBasepoints,
	perCommitmentPointFromSecret
} from '../../src/lightning/keys/derivation';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

function getPerCommitmentPoint(seed: Buffer, commitmentNumber: bigint): Buffer {
	return perCommitmentPointFromSecret(
		generateFromSeed(seed, MAX_INDEX - commitmentNumber)
	);
}

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
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

const localSeed = crypto
	.createHash('sha256')
	.update('fund-safety-local')
	.digest();
const remoteSeed = crypto
	.createHash('sha256')
	.update('fund-safety-remote')
	.digest();

function makeNormalOpenerChannel(): Channel {
	const state = createOpenerState({
		temporaryChannelId: crypto.randomBytes(32),
		fundingSatoshis: 1_000_000n,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(localSeed),
		localPerCommitmentSeed: localSeed
	});
	state.channelId = crypto.randomBytes(32);
	state.state = ChannelState.NORMAL;
	state.fundingTxid = crypto.randomBytes(32);
	state.remoteBasepoints = makeBasepoints(remoteSeed);
	state.remoteConfig = { ...DEFAULT_CHANNEL_CONFIG };
	state.localBalanceMsat = 1_000_000_000n;
	state.remoteBalanceMsat = 0n;
	return new Channel(state);
}

function makeNormalAcceptorChannel(): Channel {
	const state = createAcceptorState({
		temporaryChannelId: crypto.randomBytes(32),
		fundingSatoshis: 1_000_000n,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(localSeed),
		localPerCommitmentSeed: localSeed,
		remoteBasepoints: makeBasepoints(remoteSeed),
		remoteConfig: { ...DEFAULT_CHANNEL_CONFIG }
	});
	state.channelId = crypto.randomBytes(32);
	state.state = ChannelState.NORMAL;
	state.fundingTxid = crypto.randomBytes(32);
	state.fundingSatoshis = 1_000_000n;
	state.localBalanceMsat = 100_000_000n;
	state.remoteBalanceMsat = 900_000_000n;
	return new Channel(state);
}

describe('Fund safety round 2', function () {
	describe('Dust HTLC exposure cap', function () {
		it('rejects an outbound dust HTLC once total dust exposure would exceed the cap', function () {
			const channel = makeNormalOpenerChannel();
			const dustAmount = 350_000n; // 350 sats < 354-sat default dust limit

			// 14 dust HTLCs = 4_900_000 msat — under the 5_000_000 msat cap.
			for (let i = 0; i < 14; i++) {
				const actions = channel.addHtlc(
					dustAmount,
					crypto.randomBytes(32),
					1000,
					Buffer.alloc(1366)
				);
				expect(
					actions.find((a) => a.type === ChannelActionType.ERROR),
					`dust HTLC ${i} accepted`
				).to.not.exist;
			}

			// The 15th would push exposure to 5_250_000 msat — rejected.
			const rejected = channel.addHtlc(
				dustAmount,
				crypto.randomBytes(32),
				1000,
				Buffer.alloc(1366)
			);
			const err: any = rejected.find((a) => a.type === ChannelActionType.ERROR);
			expect(err).to.exist;
			expect(err.message).to.include('Dust HTLC exposure');

			// A non-dust HTLC is still fine.
			const ok = channel.addHtlc(
				50_000_000n,
				crypto.randomBytes(32),
				1000,
				Buffer.alloc(1366)
			);
			expect(ok.find((a) => a.type === ChannelActionType.ERROR)).to.not.exist;
		});

		it('rejects an inbound dust HTLC over the cap', function () {
			const channel = makeNormalAcceptorChannel();
			const dustAmount = 350_000n;
			for (let i = 0; i < 14; i++) {
				const actions = channel.handleUpdateAddHtlc({
					channelId: channel.getChannelId()!,
					id: BigInt(i),
					amountMsat: dustAmount,
					paymentHash: crypto.randomBytes(32),
					cltvExpiry: 1000,
					onionRoutingPacket: Buffer.alloc(1366)
				});
				expect(
					actions.find((a) => a.type === ChannelActionType.ERROR),
					`inbound dust HTLC ${i} accepted`
				).to.not.exist;
			}
			const rejected = channel.handleUpdateAddHtlc({
				channelId: channel.getChannelId()!,
				id: 14n,
				amountMsat: dustAmount,
				paymentHash: crypto.randomBytes(32),
				cltvExpiry: 1000,
				onionRoutingPacket: Buffer.alloc(1366)
			});
			const err: any = rejected.find((a) => a.type === ChannelActionType.ERROR);
			expect(err).to.exist;
			expect(err.message).to.include('Dust HTLC exposure');
		});
	});

	describe('update_fee absolute cap', function () {
		it('rejects an update_fee above 100000 sat/kw even within the 10x relative bound', function () {
			const channel = makeNormalAcceptorChannel();
			channel.getFullState().remoteConfig.feeratePerKw = 50_000;

			const actions = channel.handleUpdateFee({
				channelId: channel.getChannelId()!,
				feeratePerKw: 150_000 // 3x current — passes the relative bound
			});
			const err: any = actions.find((a) => a.type === ChannelActionType.ERROR);
			expect(err).to.exist;
			expect(err.message).to.include('absolute maximum');
		});
	});

	describe('Commitment fee saturation', function () {
		it('never produces a negative opener balance when the fee exceeds it', function () {
			const channel = makeNormalOpenerChannel();
			const state = channel.getFullState();
			// Opener holds 100 sats; at 5000 sat/kw the commitment fee (~3620 sats)
			// vastly exceeds it.
			state.localBalanceMsat = 100_000n;
			state.remoteBalanceMsat = 999_900_000n;
			state.localConfig.feeratePerKw = 5000;
			state.remoteConfig.feeratePerKw = 5000;

			const point = getPerCommitmentPoint(state.localPerCommitmentSeed, 0n);
			const built = buildLocalCommitment(state, point);
			// The opener's to_local output is removed (trimmed), never negative.
			for (const out of built.result.tx.outs) {
				expect(out.value).to.be.at.least(0);
			}
			// Total outputs never exceed the funding amount.
			const total = built.result.tx.outs.reduce((s, o) => s + o.value, 0);
			expect(total).to.be.at.most(1_000_000);
		});
	});
});
