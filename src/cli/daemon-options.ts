/**
 * The daemon options a resolved config asks for.
 *
 * Its own module because cli.ts runs main() the moment it is imported, so a
 * test could not reach this mapping while it lived there, and the mapping is
 * exactly the kind that needs one: a field it forgets fails silently. The env
 * is accepted, the config validates it, the daemon starts, and the role is
 * simply off. BEIGNET_SWAPS did that from issue #737 (0.15.0) and
 * BEIGNET_GUARDIAN_SERVE from issue #699, both parsed and bounds-checked and
 * then never handed to the node, so an operator who had configured a swap
 * provider got GET /swaps/status answering enabled:false with no reason why.
 */
import { DaemonOptions } from './daemon';
import { BeignetConfig } from './types';

export function daemonOptions(
	config: BeignetConfig,
	daemonPort: number
): DaemonOptions {
	return {
		mnemonic: config.mnemonic,
		network: config.network,
		alias: config.alias,
		dataDir: config.dataDir,
		electrumHost: config.electrumHost,
		electrumPort: config.electrumPort,
		electrumTls: config.electrumTls,
		electrumServers: config.electrumServers,
		feeEstimationSource: config.feeEstimationSource,
		listenPort: config.listenPort,
		websocketPort: config.websocketPort,
		daemonPort,
		daemonHost: config.daemonHost,
		preferAnchors: config.preferAnchors,
		largeChannels: config.largeChannels,
		apiToken: config.apiToken,
		apiKeys: config.apiKeys,
		backupPath: config.backupPath,
		backupIntervalMs: config.backupIntervalMs,
		dailySpendLimitSats: config.dailySpendLimitSats,
		tlsCert: config.tlsCert,
		tlsKey: config.tlsKey,
		torProxy: config.torProxy,
		announceAddresses: config.announceAddresses,
		watchtowers: config.watchtowers,
		htlcEvents: config.htlcEvents,
		metricsPublic: config.metricsPublic,
		insecure: config.insecure,
		forwardingEnabled: config.forwardingEnabled,
		eagerGossipVerify: config.eagerGossipVerify,
		autoReconnect: config.autoReconnect,
		logLevel: config.logLevel,
		recoveryMode: config.recoveryMode,
		recoveryGuardians: config.recoveryGuardians,
		recoveryProfile: config.recoveryProfile,
		recoveryLeaseCheckIntervalMs: config.recoveryLeaseCheckIntervalMs,
		recoveryReestablishHoldMs: config.recoveryReestablishHoldMs,
		recoveryAutoApply: config.recoveryAutoApply,
		recoveryAutoApplySettleMs: config.recoveryAutoApplySettleMs,
		recoveryAutoApplyMaxWaitMs: config.recoveryAutoApplyMaxWaitMs,
		routingFeeBaseMsat: config.routingFeeBaseMsat,
		routingFeePpm: config.routingFeePpm,
		routingCltvDelta: config.routingCltvDelta,
		leaseRates: config.leaseRates,
		jitReceive: config.jitReceive,
		swaps: config.swaps,
		dfRelay: config.dfRelay,
		dfMinAmountSat: config.dfMinAmountSat,
		// Guardian hosting (issue #699). guardianServe needs a listenPort and
		// the daemon says so by name, so a misconfigured set refuses startup
		// rather than serving nothing.
		guardianServe: config.guardianServe,
		guardianToken: config.guardianToken,
		guardianMaxBytesPerSet: config.guardianMaxBytesPerSet,
		guardianMaxSets: config.guardianMaxSets,
		guardianMaxCiphertextBytes: config.guardianMaxCiphertextBytes,
		autoBootstrap: config.autoBootstrap,
		connectTimeoutMs: config.connectTimeoutMs
	};
}
