/**
 * A reference auxiliary channel provider and a pair of asset channels for
 * the asset channel tests (issue #2093).
 *
 * The provider is deterministic, as a real one has to be: both peers build
 * the same commitment on their own and must arrive at the same leaves. Its
 * leaves are OP_RETURN scripts over a description of what they commit to,
 * so a test can tell which commitment, output and balance a leaf is for.
 */

import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import { ChannelManager } from '../../../src/lightning/channel/channel-manager';
import type { Channel } from '../../../src/lightning/channel/channel';
import type { IChannelState } from '../../../src/lightning/channel/channel-state';
import type {
	IChannelAuxiliaryProvider,
	ITaprootAuxLeaf
} from '../../../src/lightning/channel/auxiliary';
import { ChannelState } from '../../../src/lightning/channel/types';
import { FeatureFlags, Feature } from '../../../src/lightning/features/flags';
import { configOf, connect, seedFor } from './taproot-revoked-fixture';
import { writableState } from './writable-state';

export const hash = (value: Buffer | string): Buffer =>
	crypto.createHash('sha256').update(value).digest();

/** Custom record 65536: the asset amount of an HTLC, as the provider reads it. */
export const amountRecord = (amount: bigint): Map<bigint, Buffer> => {
	const value = Buffer.alloc(8);
	value.writeBigUInt64BE(amount);
	return new Map([[65536n, value]]);
};

export const leafFor = (value: string): ITaprootAuxLeaf => ({
	script: bitcoin.script.compile([bitcoin.opcodes.OP_RETURN, hash(value)])
});

/** The type of an asset channel: the overlay bit and nothing else. */
export function overlayChannelType(...extra: number[]): Buffer {
	const flags = FeatureFlags.empty();
	flags.setCompulsory(Feature.OPTION_TAPROOT_OVERLAY);
	for (const feature of extra) flags.setCompulsory(feature);
	return flags.toBuffer();
}

export function referenceProvider(): IChannelAuxiliaryProvider {
	return {
		buildCommitment(context) {
			const outputLeaves = new Map<number, ITaprootAuxLeaf>();
			const secondLevelLeaves = new Map<string, ITaprootAuxLeaf>();
			for (const output of context.outputs) {
				if (output.role.startsWith('anchor_')) continue;
				const balance =
					output.role === 'to_local'
						? context.side === 'local'
							? context.localAssetBalance
							: context.remoteAssetBalance
						: output.role === 'to_remote'
						? context.side === 'local'
							? context.remoteAssetBalance
							: context.localAssetBalance
						: context.htlcs.find(
								(item) =>
									item.htlcId === output.htlcId &&
									item.direction === output.direction
						  )!.auxiliaryAmount;
				if (!balance) continue;
				outputLeaves.set(
					output.outputIndex,
					leafFor(`${context.commitmentNumber}:${output.role}:${balance}`)
				);
				if (output.htlcId !== undefined) {
					secondLevelLeaves.set(
						`${output.direction}:${output.htlcId}`,
						leafFor(`second:${context.commitmentNumber}:${balance}`)
					);
				}
			}
			return {
				customData: Buffer.from(`view:${context.commitmentNumber}`),
				outputLeaves,
				secondLevelLeaves
			};
		},
		signHtlcs(context) {
			return new Map([[65538n, hash(context.commitment.result.tx.toBuffer())]]);
		},
		verifyHtlcs(context, records) {
			return (
				records
					.get(65538n)
					?.equals(hash(context.commitment.result.tx.toBuffer())) ?? false
			);
		},
		validateHtlc(_state, entry) {
			if (entry.customRecords?.get(65536n)?.length !== 8) {
				throw new Error('Missing asset amount');
			}
		},
		getHtlcAmount(_state, entry) {
			return entry.customRecords!.get(65536n)!.readBigUInt64BE();
		},
		prepareShutdown(state) {
			const key = state.localBasepoints.fundingPubkey;
			return {
				scriptPubkey: bitcoin.payments.p2tr({ internalPubkey: key.subarray(1) })
					.output!,
				customRecords: new Map([[65539n, key]])
			};
		},
		verifyShutdown(_state, shutdown) {
			const key = shutdown.customRecords.get(65539n);
			return (
				!!key &&
				shutdown.scriptPubkey.equals(
					bitcoin.payments.p2tr({ internalPubkey: key.subarray(1) }).output!
				)
			);
		},
		buildClose(context) {
			const auxiliary = context.state.auxiliaryState!;
			const scripts = new Map<number, Buffer>();
			for (const [index, balance, records] of [
				[
					context.localOutputIndex,
					auxiliary.localBalance,
					auxiliary.localShutdownRecords
				],
				[
					context.remoteOutputIndex,
					auxiliary.remoteBalance,
					auxiliary.remoteShutdownRecords
				]
			] as const) {
				if (index !== undefined && balance > 0n) {
					scripts.set(
						index,
						bitcoin.payments.p2tr({
							internalPubkey: records!.get(65539n)!.subarray(1),
							scriptTree: { output: leafFor(`close:${balance}`).script }
						}).output!
					);
				}
			}
			return {
				outputScripts: scripts,
				customData: Buffer.from('signed close assets')
			};
		}
	};
}

export const ASSET_FUNDING_ROOT = hash('asset funding root');

/**
 * Turn an open simple taproot channel into an asset channel in place, the
 * way an asset opening leaves it: the overlay type, the root its funding
 * key commits to, the asset balances and the provider.
 */
export function makeAssetChannel(
	channel: Channel,
	provider: IChannelAuxiliaryProvider,
	localBalance: bigint,
	remoteBalance: bigint,
	channelType: Buffer = overlayChannelType()
): IChannelState {
	const state = writableState(channel);
	state.channelType = channelType;
	state.fundingTaprootMerkleRoot = Buffer.from(ASSET_FUNDING_ROOT);
	state.auxiliaryState = {
		channelData: Buffer.from('asset funding blob'),
		localBalance,
		remoteBalance,
		localCommitments: new Map(),
		remoteCommitments: new Map()
	};
	state.auxiliaryProvider = provider;
	return state;
}

export interface IAssetPair {
	alice: ChannelManager;
	bob: ChannelManager;
	aliceChannel: Channel;
	bobChannel: Channel;
	aliceProvider: IChannelAuxiliaryProvider;
	bobProvider: IChannelAuxiliaryProvider;
	/** The channel id. */
	id: Buffer;
	alicePubkey: string;
	bobPubkey: string;
	/** Every 'error' either manager raised, as text. */
	errors: string[];
	/** Every message that crossed the wire, in order. */
	wire: Array<{ from: 'alice' | 'bob'; type: number; payload: Buffer }>;
	/** Rewrite or drop a message before it is delivered; return null to drop. */
	intercept: {
		fn?: (
			from: 'alice' | 'bob',
			type: number,
			payload: Buffer
		) => Buffer | null;
	};
}

/**
 * Two managers with one open channel between them, Alice the opener holding
 * 1000 asset units and Bob none. With `asset: false` the channel stays the
 * ordinary simple taproot channel it was opened as.
 */
export function taprootPair(
	seed: number,
	options: { asset?: boolean; channelType?: Buffer } = {}
): IAssetPair {
	const aliceCfg = configOf(seedFor(seed), true);
	const bobCfg = configOf(seedFor(seed + 1), false);
	const alice = new ChannelManager(aliceCfg);
	const bob = new ChannelManager(bobCfg);
	const alicePubkey = aliceCfg.localBasepoints.fundingPubkey.toString('hex');
	const bobPubkey = bobCfg.localBasepoints.fundingPubkey.toString('hex');
	const wire: IAssetPair['wire'] = [];
	const errors: string[] = [];
	for (const [name, manager] of [
		['alice', alice],
		['bob', bob]
	] as const) {
		manager.on('error', (...args: unknown[]) => {
			errors.push(
				`${name}: ${args
					.map((arg) =>
						arg instanceof Error
							? arg.message
							: Buffer.isBuffer(arg)
							? arg.toString('hex')
							: String(arg)
					)
					.join(' ')}`
			);
		});
	}
	const intercept: IAssetPair['intercept'] = {};
	const link = (
		from: 'alice' | 'bob',
		source: ChannelManager,
		sourcePubkey: string,
		target: ChannelManager,
		targetPubkey: string
	): void => {
		source.on(
			'message:outbound',
			(peer: string, type: number, payload: Buffer) => {
				if (peer !== targetPubkey) return;
				const delivered = intercept.fn
					? intercept.fn(from, type, payload)
					: payload;
				if (!delivered) return;
				wire.push({ from, type, payload: delivered });
				target.handleMessage(sourcePubkey, type, delivered);
			}
		);
	};
	link('alice', alice, alicePubkey, bob, bobPubkey);
	link('bob', bob, bobPubkey, alice, alicePubkey);

	const aliceChannel = alice.openChannel(bobPubkey, 3_000_000n);
	const id = alice.createFunding(
		aliceChannel,
		hash(`asset pair funding ${seed}`),
		0,
		Buffer.alloc(64, 1)
	)!;
	alice.handleFundingConfirmed(id);
	bob.handleFundingConfirmed(id);
	const bobChannel = bob.getChannel(id)!;
	for (const channel of [aliceChannel, bobChannel]) {
		if (channel.getFullState().state !== ChannelState.NORMAL) {
			throw new Error('taproot pair did not reach NORMAL');
		}
	}
	const aliceProvider = referenceProvider();
	const bobProvider = referenceProvider();
	if (options.asset !== false) {
		makeAssetChannel(
			aliceChannel,
			aliceProvider,
			1000n,
			0n,
			options.channelType
		);
		makeAssetChannel(bobChannel, bobProvider, 0n, 1000n, options.channelType);
	}
	wire.length = 0;
	return {
		alice,
		bob,
		aliceChannel,
		bobChannel,
		aliceProvider,
		bobProvider,
		id,
		alicePubkey,
		bobPubkey,
		errors,
		wire,
		intercept
	};
}

// `connect` is re-exported for tests that link managers themselves.
export { connect };
