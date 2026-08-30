/**
 * CLI config file management.
 * Reads/writes ~/.beignet/config.json and manages daemon PID files.
 */

import * as fs from 'fs';
import * as path from 'path';
import { BeignetConfig } from './types';
import { TLogLevel } from '../logger';

const LOG_LEVELS: TLogLevel[] = ['debug', 'info', 'warn', 'error', 'silent'];

function parseLogLevel(value?: string): TLogLevel | undefined {
	return LOG_LEVELS.includes(value as TLogLevel)
		? (value as TLogLevel)
		: undefined;
}

/**
 * Resolved on every call, never frozen at module load. These paths follow HOME,
 * and HOME is not a constant: the CLI tests redirect it per-test to keep their
 * writes inside a temp dir. A module-level `const` captured the value at import
 * time, so those redirects were silently ignored and saveConfig() wrote the
 * developer's real ~/.beignet/config.json instead (issue #604). It also made
 * every test that touches config contend on one file outside the repo, which is
 * a cross-process race the moment test:cli runs with --parallel.
 */
function beignetDir(): string {
	return path.join(
		process.env.HOME || process.env.USERPROFILE || '.',
		'.beignet'
	);
}

function configPath(): string {
	return path.join(beignetDir(), 'config.json');
}

function pidPath(): string {
	return path.join(beignetDir(), 'daemon.pid');
}

export function loadConfig(): BeignetConfig {
	try {
		const raw = fs.readFileSync(configPath(), 'utf-8');
		return JSON.parse(raw) as BeignetConfig;
	} catch {
		return {};
	}
}

export function saveConfig(config: BeignetConfig): void {
	fs.mkdirSync(beignetDir(), { recursive: true });
	fs.writeFileSync(configPath(), JSON.stringify(config, null, 2) + '\n');
}

/**
 * BEIGNET_API_KEYS: JSON array of { name, key, scopes } for scoped API keys.
 * Malformed JSON is ignored here (treated as unset); scope/name validation
 * happens in the daemon's ApiKeyAuthenticator at startup.
 */
function parseApiKeysEnv(): BeignetConfig['apiKeys'] {
	const raw = process.env.BEIGNET_API_KEYS;
	if (!raw) return undefined;
	try {
		const parsed = JSON.parse(raw);
		return Array.isArray(parsed)
			? (parsed as BeignetConfig['apiKeys'])
			: undefined;
	} catch {
		return undefined;
	}
}

/**
 * An env value that must be a COMPLETE base-10 integer.
 *
 * parseInt stops at the first character it cannot use, so it reads '0.5' as 0
 * and '10m' as 10: for a timer that silently disables a protection whose 0
 * means off or turns ten minutes into ten milliseconds, and for a fee it
 * advertises a policy the operator never wrote. Anything that is not wholly an
 * integer becomes NaN here instead, which the daemon's range check refuses at
 * startup with a message naming the variable, matching what the docs promise.
 * Absent or empty stays undefined so the config file still gets its turn.
 */
function integerEnv(raw: string | undefined): number | undefined {
	const trimmed = raw?.trim();
	if (!trimmed) return undefined;
	return /^[+-]?\d+$/.test(trimmed) ? Number(trimmed) : Number.NaN;
}

/**
 * BEIGNET_LEASE_RATES: a JSON object with the five option_will_fund
 * lease_rates fields (issue #532 workstream 1B). Same fail-closed contract as
 * integerEnv, extended to an object: absent or empty stays undefined (config
 * file's turn), while malformed JSON, a non-object, or a missing/non-numeric
 * field surfaces as NaN in that field so the daemon's leaseRatesRefusal check
 * refuses startup naming the variable. Never the parseApiKeysEnv treat-as-
 * unset direction: a seller policy that is set but unreadable must not
 * silently become "never sell". Field ranges are enforced by
 * leaseRatesRefusal in beignet-node.ts, which owns the field-to-width table.
 */
function leaseRatesEnv(raw: string | undefined): BeignetConfig['leaseRates'] {
	const trimmed = raw?.trim();
	if (!trimmed) return undefined;
	let parsed: unknown;
	try {
		parsed = JSON.parse(trimmed);
	} catch {
		parsed = undefined;
	}
	const obj = (
		typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)
			? parsed
			: {}
	) as Record<string, unknown>;
	const field = (name: string): number => {
		const v = obj[name];
		return typeof v === 'number' ? v : Number.NaN;
	};
	return {
		fundingWeightWitness: field('fundingWeightWitness'),
		leaseFeeBasis: field('leaseFeeBasis'),
		leaseFeeBaseSat: field('leaseFeeBaseSat'),
		channelFeeMaxBaseMsat: field('channelFeeMaxBaseMsat'),
		channelFeeMaxProportionalThousandths: field(
			'channelFeeMaxProportionalThousandths'
		)
	};
}

/**
 * BEIGNET_JIT_RECEIVE / _FLAT_FEE_SAT / _FEE_PPM / _MAX_FLAT_FEE_SAT /
 * _MAX_FEE_PPM, assembled into one config block. Returns undefined when none
 * of them is set, so the config file still gets its turn.
 *
 * `enabled` is the autoReconnect rule (exact 'true'/'false', anything else
 * ignored): the safe direction for this switch is OFF, because it decides
 * whether this node fronts channel funding with its own coins for peers. The
 * fork's `=== 'true'` made BEIGNET_JIT_RECEIVE=1 read as an explicit false,
 * which is the same result by accident rather than by rule. The fee fields go
 * through integerEnv, so a partly numeric one surfaces as NaN and refuses
 * startup naming the variable instead of advertising a price nobody wrote.
 */
function jitReceiveEnv(): BeignetConfig['jitReceive'] {
	const enabledRaw = process.env.BEIGNET_JIT_RECEIVE?.trim();
	const enabled =
		enabledRaw === 'true' ? true : enabledRaw === 'false' ? false : undefined;
	const flatFeeSat = integerEnv(process.env.BEIGNET_JIT_FLAT_FEE_SAT);
	const feePpm = integerEnv(process.env.BEIGNET_JIT_FEE_PPM);
	const maxFlatFeeSat = integerEnv(process.env.BEIGNET_JIT_MAX_FLAT_FEE_SAT);
	const maxFeePpm = integerEnv(process.env.BEIGNET_JIT_MAX_FEE_PPM);
	if (
		enabled === undefined &&
		flatFeeSat === undefined &&
		feePpm === undefined &&
		maxFlatFeeSat === undefined &&
		maxFeePpm === undefined
	) {
		return undefined;
	}
	return {
		...(enabled !== undefined ? { enabled } : {}),
		...(flatFeeSat !== undefined ? { flatFeeSat } : {}),
		...(feePpm !== undefined ? { feePpm } : {}),
		...(maxFlatFeeSat !== undefined ? { maxFlatFeeSat } : {}),
		...(maxFeePpm !== undefined ? { maxFeePpm } : {})
	};
}

/**
 * Merge CLI flags > env vars > config file, returning final config.
 */
export function resolveConfig(cliFlags: Partial<BeignetConfig>): BeignetConfig {
	const file = loadConfig();

	return {
		mnemonic:
			cliFlags.mnemonic || process.env.BEIGNET_MNEMONIC || file.mnemonic,
		network: (cliFlags.network ||
			process.env.BEIGNET_NETWORK ||
			file.network ||
			'mainnet') as BeignetConfig['network'],
		alias: cliFlags.alias || process.env.BEIGNET_ALIAS || file.alias,
		dataDir: cliFlags.dataDir || process.env.BEIGNET_DATA_DIR || file.dataDir,
		electrumHost:
			cliFlags.electrumHost ||
			process.env.BEIGNET_ELECTRUM_HOST ||
			file.electrumHost,
		electrumPort:
			cliFlags.electrumPort ||
			(process.env.BEIGNET_ELECTRUM_PORT
				? parseInt(process.env.BEIGNET_ELECTRUM_PORT, 10)
				: undefined) ||
			file.electrumPort,
		electrumTls:
			cliFlags.electrumTls ??
			(process.env.BEIGNET_ELECTRUM_TLS !== undefined
				? process.env.BEIGNET_ELECTRUM_TLS === 'true'
				: undefined) ??
			file.electrumTls,
		listenPort:
			cliFlags.listenPort ||
			(process.env.BEIGNET_LISTEN_PORT
				? parseInt(process.env.BEIGNET_LISTEN_PORT, 10)
				: undefined) ||
			file.listenPort,
		websocketPort:
			cliFlags.websocketPort ||
			(process.env.BEIGNET_WEBSOCKET_PORT
				? parseInt(process.env.BEIGNET_WEBSOCKET_PORT, 10)
				: undefined) ||
			file.websocketPort,
		daemonHost:
			cliFlags.daemonHost || process.env.BEIGNET_DAEMON_HOST || file.daemonHost,
		daemonPort:
			cliFlags.daemonPort ||
			(process.env.BEIGNET_DAEMON_PORT
				? parseInt(process.env.BEIGNET_DAEMON_PORT, 10)
				: undefined) ||
			file.daemonPort,
		preferAnchors:
			cliFlags.preferAnchors ??
			(process.env.BEIGNET_PREFER_ANCHORS !== undefined
				? process.env.BEIGNET_PREFER_ANCHORS === 'true'
				: undefined) ??
			file.preferAnchors,
		largeChannels:
			cliFlags.largeChannels ??
			(process.env.BEIGNET_LARGE_CHANNELS !== undefined
				? process.env.BEIGNET_LARGE_CHANNELS === 'true'
				: undefined) ??
			file.largeChannels,
		apiToken:
			cliFlags.apiToken || process.env.BEIGNET_API_TOKEN || file.apiToken,
		apiKeys: cliFlags.apiKeys || parseApiKeysEnv() || file.apiKeys,
		autoBootstrap:
			cliFlags.autoBootstrap ??
			(process.env.BEIGNET_AUTO_BOOTSTRAP !== undefined
				? process.env.BEIGNET_AUTO_BOOTSTRAP === 'true'
				: undefined) ??
			file.autoBootstrap,
		backupPath:
			cliFlags.backupPath || process.env.BEIGNET_BACKUP_PATH || file.backupPath,
		backupIntervalMs:
			cliFlags.backupIntervalMs ||
			(process.env.BEIGNET_BACKUP_INTERVAL_MS
				? parseInt(process.env.BEIGNET_BACKUP_INTERVAL_MS, 10)
				: undefined) ||
			file.backupIntervalMs,
		electrumServers: cliFlags.electrumServers || file.electrumServers,
		feeEstimationSource: (cliFlags.feeEstimationSource ||
			process.env.BEIGNET_FEE_SOURCE ||
			file.feeEstimationSource) as BeignetConfig['feeEstimationSource'],
		dailySpendLimitSats:
			cliFlags.dailySpendLimitSats ||
			(process.env.BEIGNET_DAILY_SPEND_LIMIT_SATS
				? parseInt(process.env.BEIGNET_DAILY_SPEND_LIMIT_SATS, 10)
				: undefined) ||
			file.dailySpendLimitSats,
		connectTimeoutMs:
			cliFlags.connectTimeoutMs ||
			(process.env.BEIGNET_CONNECT_TIMEOUT_MS
				? parseInt(process.env.BEIGNET_CONNECT_TIMEOUT_MS, 10)
				: undefined) ||
			file.connectTimeoutMs,
		tlsCert: cliFlags.tlsCert || process.env.BEIGNET_TLS_CERT || file.tlsCert,
		tlsKey: cliFlags.tlsKey || process.env.BEIGNET_TLS_KEY || file.tlsKey,
		torProxy:
			cliFlags.torProxy || process.env.BEIGNET_TOR_PROXY || file.torProxy,
		announceAddresses:
			cliFlags.announceAddresses ||
			(process.env.BEIGNET_ANNOUNCE_ADDRESSES
				? process.env.BEIGNET_ANNOUNCE_ADDRESSES.split(',')
						.map((a) => a.trim())
						.filter((a) => a.length > 0)
				: undefined) ||
			file.announceAddresses,
		watchtowers:
			cliFlags.watchtowers ||
			(process.env.BEIGNET_WATCHTOWERS
				? process.env.BEIGNET_WATCHTOWERS.split(',')
						.map((a) => a.trim())
						.filter((a) => a.length > 0)
				: undefined) ||
			file.watchtowers,
		htlcEvents:
			cliFlags.htlcEvents ??
			(process.env.BEIGNET_HTLC_EVENTS !== undefined
				? process.env.BEIGNET_HTLC_EVENTS === 'true'
				: undefined) ??
			file.htlcEvents,
		metricsPublic:
			cliFlags.metricsPublic ??
			(process.env.BEIGNET_METRICS_PUBLIC !== undefined
				? process.env.BEIGNET_METRICS_PUBLIC === 'true'
				: undefined) ??
			file.metricsPublic,
		insecure:
			cliFlags.insecure ??
			(process.env.BEIGNET_INSECURE !== undefined
				? process.env.BEIGNET_INSECURE === 'true'
				: undefined) ??
			file.insecure,
		forwardingEnabled:
			cliFlags.forwardingEnabled ??
			(process.env.BEIGNET_FORWARDING_ENABLED !== undefined
				? process.env.BEIGNET_FORWARDING_ENABLED === 'true'
				: undefined) ??
			file.forwardingEnabled,
		// Exact 'true'/'false' only (the autoReconnect rule): a typo falls back
		// to the default, lazy verification, which is the safe direction — the
		// node still never serves anything unverified, it just verifies later
		// and cheaper.
		eagerGossipVerify:
			cliFlags.eagerGossipVerify ??
			(process.env.BEIGNET_EAGER_GOSSIP_VERIFY === 'true'
				? true
				: process.env.BEIGNET_EAGER_GOSSIP_VERIFY === 'false'
				? false
				: undefined) ??
			file.eagerGossipVerify,
		// Exact 'true'/'false' only; anything else is ignored rather than
		// guessed at, per the standing rule that a typo never crashes the
		// daemon. Ignored falls back to the node default (reconnect ON), which
		// is the safe direction for this switch: a malformed value must not
		// silently park a node whose unreachable channels the reestablish
		// watchdog would eventually force-close.
		autoReconnect:
			cliFlags.autoReconnect ??
			(process.env.BEIGNET_AUTO_RECONNECT === 'true'
				? true
				: process.env.BEIGNET_AUTO_RECONNECT === 'false'
				? false
				: undefined) ??
			file.autoReconnect,
		logLevel:
			parseLogLevel(cliFlags.logLevel) ||
			parseLogLevel(process.env.BEIGNET_LOG_LEVEL) ||
			parseLogLevel(file.logLevel),
		// Passed through raw: the daemon validates before booting a node, so a
		// malformed guardian set or profile refuses startup with a precise
		// message instead of silently changing the quorum arithmetic. Only the
		// MODE follows the ignore-typos rule, because its fallback (off) is the
		// safe direction and an existing quorum-marked database still refuses
		// to start unbarriered at the library level.
		recoveryMode:
			cliFlags.recoveryMode ||
			process.env.BEIGNET_RECOVERY_MODE ||
			file.recoveryMode,
		recoveryGuardians:
			cliFlags.recoveryGuardians ||
			(process.env.BEIGNET_RECOVERY_GUARDIANS
				? process.env.BEIGNET_RECOVERY_GUARDIANS.split(',')
						.map((g) => g.trim())
						.filter((g) => g.length > 0)
				: undefined) ||
			file.recoveryGuardians,
		recoveryProfile:
			cliFlags.recoveryProfile ||
			process.env.BEIGNET_RECOVERY_PROFILE ||
			file.recoveryProfile,
		recoveryLeaseCheckIntervalMs:
			cliFlags.recoveryLeaseCheckIntervalMs ??
			integerEnv(process.env.BEIGNET_RECOVERY_LEASE_CHECK_MS) ??
			file.recoveryLeaseCheckIntervalMs,
		recoveryReestablishHoldMs:
			cliFlags.recoveryReestablishHoldMs ??
			integerEnv(process.env.BEIGNET_RECOVERY_REESTABLISH_HOLD_MS) ??
			file.recoveryReestablishHoldMs,
		// Routing fee defaults and the lease seller policy use ?? throughout:
		// a configured 0 (free base fee, zero ppm) is a real policy and must
		// survive the merge.
		routingFeeBaseMsat:
			cliFlags.routingFeeBaseMsat ??
			integerEnv(process.env.BEIGNET_FEE_BASE_MSAT) ??
			file.routingFeeBaseMsat,
		routingFeePpm:
			cliFlags.routingFeePpm ??
			integerEnv(process.env.BEIGNET_FEE_PPM) ??
			file.routingFeePpm,
		routingCltvDelta:
			cliFlags.routingCltvDelta ??
			integerEnv(process.env.BEIGNET_CLTV_DELTA) ??
			file.routingCltvDelta,
		leaseRates:
			cliFlags.leaseRates ??
			leaseRatesEnv(process.env.BEIGNET_LEASE_RATES) ??
			file.leaseRates,
		jitReceive: cliFlags.jitReceive ?? jitReceiveEnv() ?? file.jitReceive,
		// Same exact-string rule as the JIT trio, and the same reasoning: the
		// safe direction for this switch is OFF, because it decides whether this
		// node forwards frames on behalf of strangers. `=== 'true'` alone would
		// make BEIGNET_DF_RELAY=1 read as an explicit false, which is the right
		// answer by accident rather than by rule, and it would also mask a typo
		// in the config file it is supposed to defer to.
		dfRelay:
			cliFlags.dfRelay ??
			(process.env.BEIGNET_DF_RELAY === 'true'
				? true
				: process.env.BEIGNET_DF_RELAY === 'false'
				? false
				: undefined) ??
			file.dfRelay,
		// integerEnv, so '10m' or '0.5' surfaces as NaN and refuses startup
		// naming the variable rather than silently becoming 10 or 0. ?? rather
		// than ||, so a configured 0 survives the merge and clamps to the floor.
		dfMinAmountSat:
			cliFlags.dfMinAmountSat ??
			integerEnv(process.env.BEIGNET_DF_MIN_AMOUNT) ??
			file.dfMinAmountSat
	};
}

export function writePidFile(pid: number, port: number): void {
	fs.mkdirSync(beignetDir(), { recursive: true });
	fs.writeFileSync(pidPath(), JSON.stringify({ pid, port }));
}

export function readPidFile(): { pid: number; port: number } | null {
	try {
		const raw = fs.readFileSync(pidPath(), 'utf-8');
		return JSON.parse(raw);
	} catch {
		return null;
	}
}

export function removePidFile(): void {
	try {
		fs.unlinkSync(pidPath());
	} catch {
		// ignore
	}
}

export function getDaemonPort(): number {
	const pidInfo = readPidFile();
	return pidInfo?.port || 2112;
}

export { beignetDir, configPath, pidPath };
