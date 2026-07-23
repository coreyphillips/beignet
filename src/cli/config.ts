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

const BEIGNET_DIR = path.join(
	process.env.HOME || process.env.USERPROFILE || '.',
	'.beignet'
);

const CONFIG_PATH = path.join(BEIGNET_DIR, 'config.json');
const PID_PATH = path.join(BEIGNET_DIR, 'daemon.pid');

export function loadConfig(): BeignetConfig {
	try {
		const raw = fs.readFileSync(CONFIG_PATH, 'utf-8');
		return JSON.parse(raw) as BeignetConfig;
	} catch {
		return {};
	}
}

export function saveConfig(config: BeignetConfig): void {
	fs.mkdirSync(BEIGNET_DIR, { recursive: true });
	fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2) + '\n');
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
		forwardingEnabled:
			cliFlags.forwardingEnabled ??
			(process.env.BEIGNET_FORWARDING_ENABLED !== undefined
				? process.env.BEIGNET_FORWARDING_ENABLED === 'true'
				: undefined) ??
			file.forwardingEnabled,
		logLevel:
			parseLogLevel(cliFlags.logLevel) ||
			parseLogLevel(process.env.BEIGNET_LOG_LEVEL) ||
			parseLogLevel(file.logLevel)
	};
}

export function writePidFile(pid: number, port: number): void {
	fs.mkdirSync(BEIGNET_DIR, { recursive: true });
	fs.writeFileSync(PID_PATH, JSON.stringify({ pid, port }));
}

export function readPidFile(): { pid: number; port: number } | null {
	try {
		const raw = fs.readFileSync(PID_PATH, 'utf-8');
		return JSON.parse(raw);
	} catch {
		return null;
	}
}

export function removePidFile(): void {
	try {
		fs.unlinkSync(PID_PATH);
	} catch {
		// ignore
	}
}

export function getDaemonPort(): number {
	const pidInfo = readPidFile();
	return pidInfo?.port || 2112;
}

export { BEIGNET_DIR, CONFIG_PATH };
