/**
 * LightningNode configuration defaults. The constructor reads the config
 * `resolveNodeConfig` returns, so a default added anywhere else is one the
 * snapshot in tests/lightning/resolve-node-config.test.ts cannot see.
 */

import { Network } from '../invoice/types';
import { noopLogger } from '../../logger';
import { DF_DEFAULT_REQUEST_TTL_MS } from '../direct-funding/types';
import {
	REVERSE_SWAP_DEFAULTS,
	REVERSE_SWAP_DEFAULT_EXPOSURE
} from '../swaps/reverse-engine';
import { DEFAULT_MIN_IMBALANCE_PCT } from '../advisor/rebalance-planner';
import {
	DEFAULT_FEE_TUNE_FLOOR_PPM,
	DEFAULT_FEE_TUNE_CEIL_PPM
} from '../advisor/fee-tuner';
import type { ILogger } from '../../logger';
import type { INodeAddress } from '../gossip/types';
import type { IZeroReserveConfig } from '../channel/zero-reserve';
import type { IJitReceiveConfig } from '../liquidity/jit-receive';
import type { IFforWitnessConfig } from '../ffor/witness-service';
import type { ISwapConfirmationPolicy, ISwapExposurePolicy } from '../swaps';
import type { Socks5ProxyScope } from '../transport/peer-manager';
import type { RecoveryDurability } from '../recovery/types';
import type { GuardianDescriptor } from '../recovery/capsule';
import type {
	IAutoRebalanceConfig,
	IAutoTuneFeesConfig,
	IDirectFundingNodeConfig,
	INodeConfig,
	IResourceConfig,
	ISwapNodeConfig
} from './types';

/**
 * Blocks of headroom before a parked hold-invoice HTLC's CLTV expiry at which we
 * auto-fail it off-chain, rather than letting it force an on-chain timeout (which
 * would close the channel). Mirrors the safety margin used for forwarded HTLCs.
 */
export const HELD_HTLC_EXPIRY_MARGIN = 18;

/**
 * Wallet-role refusal ceilings on an LSP's opening-fee quote. Blunt guards,
 * not a price: they exist so a peer cannot answer an intent with a quote the
 * operator never agreed to and have the wallet register an allowance for it.
 * Both are configurable through `jitReceiveClient`.
 */
export const JIT_CLIENT_MAX_FLAT_FEE_SAT = 10_000n;
export const JIT_CLIENT_MAX_FEE_PPM = 50_000;

/** Ten minutes: the grace LND gives a superseded channel_update. */
export const DEFAULT_FORWARDING_POLICY_GRACE_MS = 10 * 60 * 1000;

/**
 * Blocks before an inbound HTLC's cltv_expiry at which, if we hold its
 * preimage but the off-chain fulfill has not been acked, we force-close the
 * inbound channel to claim on-chain. Must leave enough room for our
 * HTLC-success to confirm before the peer's HTLC-timeout becomes spendable at
 * cltv_expiry (LDK-style CLTV_CLAIM_BUFFER).
 */
export const INBOUND_HTLC_CLAIM_FORCE_CLOSE_BUFFER = 18;

/** The flat options `resolveNodeConfig` folds into a nested group. */
type DeprecatedNodeConfigKey =
	| 'forwardingEnabled'
	| 'forwardingCltvDelta'
	| 'forwardingFeeBaseMsat'
	| 'forwardingFeePropMillionths'
	| 'forwardingPolicyGraceMs'
	| 'fforSettle'
	| 'fforConcurrent'
	| 'fforWitness'
	| 'fforIssuer';

/** The INodeConfig fields `resolveNodeConfig` fills in, as it fills them. */
interface IResolvedNodeDefaults {
	network: Network;
	enableNetworking: boolean;
	autoReconnect: boolean;
	autoReleaseHeldForwards: boolean;
	resourceConfig: Readonly<Required<IResourceConfig>>;
	recovery: Readonly<
		NonNullable<INodeConfig['recovery']> & {
			enabled: boolean;
			durability: RecoveryDurability;
			guardians: GuardianDescriptor[];
		}
	>;
	htlcSafetyMargin: number;
	forwarding: Readonly<Required<NonNullable<INodeConfig['forwarding']>>>;
	ffor: Readonly<{
		settle?: NonNullable<INodeConfig['ffor']>['settle'];
		concurrent?: NonNullable<INodeConfig['ffor']>['concurrent'];
		witness?: Readonly<IFforWitnessConfig & { safetyDelta: number }>;
		issuer?: NonNullable<INodeConfig['ffor']>['issuer'];
	}>;
	eagerGossipVerify: boolean;
	cooperativeGraphRestore: boolean;
	jitReceive?: Readonly<IJitReceiveConfig & { holdExpiryMarginBlocks: number }>;
	jitReceiveClient: Readonly<
		Required<NonNullable<INodeConfig['jitReceiveClient']>>
	>;
	directFunding?: Readonly<IDirectFundingNodeConfig & { requestTtlMs: number }>;
	swaps?: Readonly<
		ISwapNodeConfig & {
			exposure: ISwapExposurePolicy;
			confirmations: ISwapConfirmationPolicy;
		}
	>;
	mppTimeoutMs: number;
	announcedAddresses: INodeAddress[];
	socks5ProxyScope: Socks5ProxyScope;
	watchtowers: string[];
	preferAnchors: boolean;
	largeChannels: boolean;
	peerStorageEnabled: boolean;
	logger: ILogger;
	maxPaymentRetries: number;
	maxTotalInFlightHtlcs: number;
	reestablishTimeoutBlocks: number;
	autoUpdateChannelFees: boolean;
	zeroReserve: Readonly<
		IZeroReserveConfig &
			Required<Pick<IZeroReserveConfig, 'role' | 'advertise'>>
	>;
	autoRebalance: Readonly<Required<IAutoRebalanceConfig>>;
	autoTuneFees: Readonly<Required<IAutoTuneFeesConfig>>;
}

/**
 * An `INodeConfig` with every default LightningNode applies filled in, and
 * the deprecated flat options folded into their groups.
 */
export type ResolvedNodeConfig = Omit<
	INodeConfig,
	DeprecatedNodeConfigKey | keyof IResolvedNodeDefaults
> &
	IResolvedNodeDefaults;

/**
 * Apply every default LightningNode uses to `input`. Pure: `input` is neither
 * changed nor frozen. The result and each option group it builds are frozen.
 *
 * A flat option and its nested form may both be given; the nested one wins.
 *
 * Options the node hands unchanged to the component that reads them keep
 * that component's default and are left as given: `channelConfig`,
 * `maxReconnectDelay`, `maxInboundPeers`, `quiescenceTimeoutMs`,
 * `rateLimitConfig`, the journal tuning in `recovery`, and every field of the
 * subsystem configs not named in `ResolvedNodeConfig`. So are the injected
 * objects (`storage`, `chainBackend`, `fundingProvider`, `feeEstimator`,
 * `localFeatures`, the key material) and `chainHashes`, whose absence means
 * "advertise none, accept any".
 */
export function resolveNodeConfig(
	input: INodeConfig
): Readonly<ResolvedNodeConfig> {
	const {
		forwardingEnabled,
		forwardingCltvDelta,
		forwardingFeeBaseMsat,
		forwardingFeePropMillionths,
		forwardingPolicyGraceMs,
		fforSettle,
		fforConcurrent,
		fforWitness,
		fforIssuer,
		...rest
	} = input;

	const htlcSafetyMargin = input.htlcSafetyMargin ?? 6;
	const enableNetworking = input.enableNetworking ?? false;

	const witness = input.ffor?.witness ?? fforWitness;
	const ffor = Object.freeze({
		settle: input.ffor?.settle ?? fforSettle,
		concurrent: input.ffor?.concurrent ?? fforConcurrent,
		// The witness barrier's CLTV arm must fire before the expiring-HTLC
		// scan would force-close the inbound channel to claim an HTLC we now
		// hold the preimage for: one block earlier than that buffer.
		witness: witness
			? Object.freeze({
					...witness,
					safetyDelta:
						witness.safetyDelta ??
						Math.max(INBOUND_HTLC_CLAIM_FORCE_CLOSE_BUFFER, htlcSafetyMargin) +
							1
			  })
			: undefined,
		issuer: input.ffor?.issuer ?? fforIssuer
	});

	// Wallets accept zero-reserve waivers by default. Primaries still need the
	// operator setting, and an explicit advertisement opt-out wins.
	const zeroReserveRole =
		input.zeroReserve?.role ??
		(input.jitReceive?.enabled || input.zeroReserve?.waiveClientReserve
			? 'primary'
			: 'wallet');
	const zeroReserve = Object.freeze({
		...input.zeroReserve,
		role: zeroReserveRole,
		advertise:
			input.zeroReserve?.advertise ??
			(zeroReserveRole === 'wallet' ||
				input.zeroReserve?.waiveClientReserve === true)
	});

	return Object.freeze({
		...rest,
		network: input.network || Network.REGTEST,
		enableNetworking,
		// The PeerManager's disconnect-time redials and the startup reconnect
		// both answer to this one switch.
		autoReconnect: input.autoReconnect ?? enableNetworking,
		autoReleaseHeldForwards: input.autoReleaseHeldForwards ?? true,
		resourceConfig: Object.freeze({
			maxCompletedPayments:
				input.resourceConfig?.maxCompletedPayments ?? 10_000,
			completedPaymentTtlMs:
				input.resourceConfig?.completedPaymentTtlMs ?? 86_400_000,
			cleanupIntervalMs: input.resourceConfig?.cleanupIntervalMs ?? 60_000
		}),
		recovery: Object.freeze({
			...input.recovery,
			enabled: input.recovery?.enabled === true,
			// async-remote is exactly the node's conduct before durability
			// modes existed.
			durability: input.recovery?.durability ?? 'async-remote',
			guardians: input.recovery?.guardians ?? []
		}),
		htlcSafetyMargin,
		forwarding: Object.freeze({
			enabled: input.forwarding?.enabled ?? forwardingEnabled ?? true,
			cltvDelta: input.forwarding?.cltvDelta ?? forwardingCltvDelta ?? 40,
			feeBaseMsat:
				input.forwarding?.feeBaseMsat ?? forwardingFeeBaseMsat ?? 1000,
			feePropMillionths:
				input.forwarding?.feePropMillionths ?? forwardingFeePropMillionths ?? 1,
			policyGraceMs:
				input.forwarding?.policyGraceMs ??
				forwardingPolicyGraceMs ??
				DEFAULT_FORWARDING_POLICY_GRACE_MS
		}),
		ffor,
		eagerGossipVerify: input.eagerGossipVerify ?? false,
		cooperativeGraphRestore: input.cooperativeGraphRestore ?? false,
		// A JIT hold must be revoked no later than the node's own expiring-HTLC
		// scan would fail the same leg, or that scan refunds upstream while the
		// engine still believes it may forward.
		jitReceive: input.jitReceive
			? Object.freeze({
					...input.jitReceive,
					holdExpiryMarginBlocks:
						input.jitReceive.holdExpiryMarginBlocks ??
						Math.max(HELD_HTLC_EXPIRY_MARGIN, htlcSafetyMargin)
			  })
			: undefined,
		jitReceiveClient: Object.freeze({
			maxFlatFeeSat:
				input.jitReceiveClient?.maxFlatFeeSat ?? JIT_CLIENT_MAX_FLAT_FEE_SAT,
			maxFeePpm: input.jitReceiveClient?.maxFeePpm ?? JIT_CLIENT_MAX_FEE_PPM
		}),
		directFunding: input.directFunding
			? Object.freeze({
					...input.directFunding,
					requestTtlMs:
						input.directFunding.requestTtlMs ?? DF_DEFAULT_REQUEST_TTL_MS
			  })
			: undefined,
		swaps: input.swaps
			? Object.freeze({
					...input.swaps,
					exposure: {
						...REVERSE_SWAP_DEFAULT_EXPOSURE,
						...input.swaps.exposure
					},
					confirmations: {
						fundingConfirmations:
							input.swaps.confirmations?.fundingConfirmations ??
							REVERSE_SWAP_DEFAULTS.fundingConfirmations,
						resolutionConfirmations:
							input.swaps.confirmations?.resolutionConfirmations ??
							REVERSE_SWAP_DEFAULTS.resolutionConfirmations
					}
			  })
			: undefined,
		mppTimeoutMs: input.mppTimeoutMs ?? 60_000,
		// BOLT 7 requires address descriptors in ascending order by type.
		announcedAddresses: [...(input.announcedAddresses ?? [])].sort(
			(a, b) => a.type - b.type
		),
		socks5ProxyScope: input.socks5ProxyScope ?? 'all',
		watchtowers: input.watchtowers ?? [],
		// Anchors are the default channel type now that wallet-funded fee
		// bumping makes their force-close safe.
		preferAnchors: input.preferAnchors ?? true,
		// option_wumbo, matching LND, CLN and Eclair. The cap is lifted for a
		// peer only when both sides advertise it.
		largeChannels: input.largeChannels ?? true,
		peerStorageEnabled: input.peerStorageEnabled ?? true,
		logger: input.logger ?? noopLogger,
		maxPaymentRetries: input.maxPaymentRetries ?? 3,
		maxTotalInFlightHtlcs: input.maxTotalInFlightHtlcs ?? 1000,
		reestablishTimeoutBlocks: input.reestablishTimeoutBlocks ?? 2016,
		// Off: a stale or uncommitted update_fee bump desyncs the commitments
		// and breaks every later HTLC.
		autoUpdateChannelFees: input.autoUpdateChannelFees ?? false,
		zeroReserve,
		autoRebalance: Object.freeze({
			enabled: input.autoRebalance?.enabled === true,
			budgetSatsPerDay: input.autoRebalance?.budgetSatsPerDay ?? 1_000,
			minImbalancePct:
				input.autoRebalance?.minImbalancePct ?? DEFAULT_MIN_IMBALANCE_PCT,
			intervalMs: input.autoRebalance?.intervalMs ?? 3_600_000
		}),
		autoTuneFees: Object.freeze({
			enabled: input.autoTuneFees?.enabled === true,
			intervalMs: input.autoTuneFees?.intervalMs ?? 21_600_000,
			floorPpm: input.autoTuneFees?.floorPpm ?? DEFAULT_FEE_TUNE_FLOOR_PPM,
			ceilPpm: input.autoTuneFees?.ceilPpm ?? DEFAULT_FEE_TUNE_CEIL_PPM
		})
	});
}
