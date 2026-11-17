/**
 * Fixed channel states for the asset channel storage tests (issue #2093).
 *
 * `ordinaryChannelState` builds a channel with no asset state from constants
 * only, so what it serializes to is the same on every run and in every
 * release. The digests of it were taken with the code as it stood before
 * asset channels touched the storage codec; the tests hold the codec to them.
 */

import crypto from 'crypto';
import { createOpenerState } from '../../../src/lightning/channel/channel-state';
import type { IChannelState } from '../../../src/lightning/channel/channel-state';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	HtlcDirection,
	HtlcState
} from '../../../src/lightning/channel/types';
import { FeatureFlags, Feature } from '../../../src/lightning/features/flags';
import { getPublicKey } from '../../../src/lightning/crypto/ecdh';
import { serializeChannelState } from '../../../src/lightning/storage/serialization';
import {
	encodeFrame,
	hashFrame
} from '../../../src/lightning/recovery/frame-codec';
import type { RecoveryFrame } from '../../../src/lightning/recovery/types';

export const FIXTURE_PEER = getPublicKey(Buffer.alloc(32, 0x77)).toString(
	'hex'
);

const key = (n: number): Buffer => getPublicKey(Buffer.alloc(32, n));

function channelType(...features: number[]): Buffer {
	const flags = FeatureFlags.empty();
	for (const feature of features) flags.setCompulsory(feature);
	return flags.toBuffer();
}

/** A NORMAL channel with two HTLCs in flight and no asset state. */
export function ordinaryChannelState(
	kind: 'taproot' | 'anchors'
): IChannelState {
	const fill = kind === 'taproot' ? 0x10 : 0x20;
	const state = createOpenerState({
		temporaryChannelId: Buffer.alloc(32, fill + 1),
		fundingSatoshis: 1_000_000n,
		pushMsat: 250_000_000n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: {
			fundingPubkey: key(fill + 2),
			revocationBasepoint: key(fill + 3),
			paymentBasepoint: key(fill + 4),
			delayedPaymentBasepoint: key(fill + 5),
			htlcBasepoint: key(fill + 6),
			firstPerCommitmentPoint: key(fill + 7)
		},
		localPerCommitmentSeed: Buffer.alloc(32, fill + 8)
	});
	state.channelId = Buffer.alloc(32, fill + 9);
	state.state = ChannelState.NORMAL;
	state.fundingTxid = Buffer.alloc(32, fill + 10);
	state.fundingOutputIndex = 1;
	state.minimumDepth = 3;
	state.remoteBasepoints = {
		fundingPubkey: key(fill + 11),
		revocationBasepoint: key(fill + 12),
		paymentBasepoint: key(fill + 13),
		delayedPaymentBasepoint: key(fill + 14),
		htlcBasepoint: key(fill + 15),
		firstPerCommitmentPoint: key(fill + 16)
	};
	state.remoteCurrentPerCommitmentPoint = key(fill + 17);
	state.remoteNextPerCommitmentPoint = key(fill + 18);
	state.localCommitmentNumber = 5n;
	state.remoteCommitmentNumber = 5n;
	state.remoteRevocationNumber = 4n;
	state.localBalanceMsat = 700_000_000n;
	state.remoteBalanceMsat = 240_000_000n;
	state.localHtlcCounter = 1n;
	state.channelType =
		kind === 'taproot'
			? channelType(Feature.OPTION_TAPROOT)
			: channelType(Feature.STATIC_REMOTE_KEY, Feature.ANCHOR_ZERO_FEE_HTLC);
	if (kind === 'taproot') {
		state.remoteNonce = Buffer.concat([key(fill + 19), key(fill + 20)]);
		state.remoteSigningNonce = Buffer.concat([key(fill + 21), key(fill + 22)]);
	}
	state.htlcs.set('offered-0', {
		id: 0n,
		amountMsat: 40_000_000n,
		paymentHash: Buffer.alloc(32, fill + 23),
		cltvExpiry: 800_100,
		onionRoutingPacket: Buffer.alloc(1366, fill + 24),
		direction: HtlcDirection.OFFERED,
		state: HtlcState.COMMITTED,
		addRemoteCommitted: true
	});
	state.htlcs.set('received-3', {
		id: 3n,
		amountMsat: 20_000_000n,
		paymentHash: Buffer.alloc(32, fill + 25),
		cltvExpiry: 800_200,
		onionRoutingPacket: Buffer.alloc(1366, fill + 26),
		direction: HtlcDirection.RECEIVED,
		state: HtlcState.COMMITTED,
		forwardEmitted: true
	});
	return state;
}

/** The recovery frame that journals `state` as its one mutation. */
export function channelStateFrame(
	state: IChannelState,
	version: RecoveryFrame['version']
): RecoveryFrame {
	return {
		version,
		writerEpoch: 1n,
		sequence: 7n,
		previousFrameHash: Buffer.alloc(32, 0x55),
		timestamp: 1_700_000_000_000,
		mutations: [
			{
				type: 'channel_state',
				channelId: state.channelId!.toString('hex'),
				state,
				peerPubkey: FIXTURE_PEER
			}
		],
		outboundMessages: []
	};
}

export interface IStorageDigests {
	/** Top-level keys of the stored row, in the order they are written. */
	keys: string[];
	/** Keys of the first stored HTLC, in the order they are written. */
	htlcKeys: string[];
	rowLength: number;
	rowSha256: string;
	frame3Hash: string;
	frame4Hash: string;
}

const sha256 = (data: string): string =>
	crypto.createHash('sha256').update(data, 'utf8').digest('hex');

/** What `state` is stored as, reduced to values a test can pin. */
export function storageDigests(state: IChannelState): IStorageDigests {
	const row = serializeChannelState(state);
	const json = JSON.stringify(row);
	return {
		keys: Object.keys(row),
		htlcKeys: Object.keys(row.htlcs[0]),
		rowLength: json.length,
		rowSha256: sha256(json),
		frame3Hash: hashFrame(encodeFrame(channelStateFrame(state, 3))).toString(
			'hex'
		),
		frame4Hash: hashFrame(encodeFrame(channelStateFrame(state, 4))).toString(
			'hex'
		)
	};
}
