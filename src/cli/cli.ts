#!/usr/bin/env node

/**
 * Beignet CLI: AI-friendly Bitcoin + Lightning interface.
 *
 * Commands are thin HTTP clients that send requests to the daemon,
 * except `init` and `start` which are handled locally.
 */

import * as http from 'http';
import * as fs from 'fs';
import * as nodePath from 'path';
import { generateMnemonic } from '../utils/helpers';
import {
	loadConfig,
	saveConfig,
	resolveConfig,
	writePidFile,
	readPidFile,
	removePidFile,
	getDaemonPort
} from './config';
import { startDaemon } from './daemon';
import { defaultDataDirForMnemonic } from './beignet-node';
import { performDbRestore } from './restore';
import { InstanceLockError } from './instance-lock';
import { ApiResponse, BeignetConfig } from './types';

const args = process.argv.slice(2);
const pretty = args.includes('--pretty');
const filteredArgs = args.filter((a) => a !== '--pretty');

function output(data: unknown): void {
	const str = pretty ? JSON.stringify(data, null, 2) : JSON.stringify(data);
	process.stdout.write(str + '\n');
}

function parseFlag(name: string): string | undefined {
	const idx = filteredArgs.indexOf(name);
	if (idx === -1 || idx + 1 >= filteredArgs.length) return undefined;
	return filteredArgs[idx + 1];
}

function hasFlag(name: string): boolean {
	return filteredArgs.includes(name);
}

/** Collect every value of a repeatable flag (e.g. --watchtower a --watchtower b). */
function parseRepeatedFlag(name: string): string[] {
	const out: string[] = [];
	for (let i = 0; i < filteredArgs.length - 1; i++) {
		if (filteredArgs[i] === name) out.push(filteredArgs[i + 1]);
	}
	return out;
}

// Resolve apiToken from CLI flag, env, or config file for HTTP requests
function getApiToken(): string | undefined {
	const flagToken = parseFlag('--api-token');
	if (flagToken) return flagToken;
	if (process.env.BEIGNET_API_TOKEN) return process.env.BEIGNET_API_TOKEN;
	const config = loadConfig();
	return config.apiToken;
}

async function httpRequest(
	method: string,
	path: string,
	body?: Record<string, unknown>
): Promise<ApiResponse<unknown>> {
	const port = getDaemonPort();
	const token = getApiToken();
	return new Promise((resolve, reject) => {
		const payload = body ? JSON.stringify(body) : undefined;
		const headers: Record<string, string | number> = {};
		if (payload) {
			headers['Content-Type'] = 'application/json';
			headers['Content-Length'] = Buffer.byteLength(payload);
		}
		if (token) {
			headers['Authorization'] = `Bearer ${token}`;
		}
		const req = http.request(
			{
				hostname: '127.0.0.1',
				port,
				path,
				method,
				headers
			},
			(res) => {
				const chunks: Buffer[] = [];
				res.on('data', (chunk: Buffer) => chunks.push(chunk));
				res.on('end', () => {
					try {
						resolve(JSON.parse(Buffer.concat(chunks).toString()));
					} catch {
						resolve({
							ok: false,
							error: { code: 'PARSE_ERROR', message: 'Invalid JSON response' }
						});
					}
				});
			}
		);
		req.on('error', (err) => {
			reject(
				new Error(
					`Cannot connect to daemon on port ${port}: ${err.message}. Is it running? Use 'beignet start' first.`
				)
			);
		});
		if (payload) req.write(payload);
		req.end();
	});
}

async function main(): Promise<void> {
	const cmd = filteredArgs[0];

	if (!cmd || cmd === 'help' || cmd === '--help' || cmd === '-h') {
		printHelp();
		return;
	}

	switch (cmd) {
		case 'init':
			return handleInit();
		case 'start':
			return handleStart();
		case 'stop':
			return handleStop();
		case 'info':
			return outputResult(await httpRequest('GET', '/info'));
		case 'balance':
			return outputResult(await httpRequest('GET', '/balance'));
		case 'transactions':
			return outputResult(
				await httpRequest(
					'GET',
					filteredArgs[1]
						? `/transactions?limit=${encodeURIComponent(filteredArgs[1])}`
						: '/transactions'
				)
			);
		case 'utxos':
			return outputResult(await httpRequest('GET', '/utxos'));
		case 'fee-estimates':
			return outputResult(await httpRequest('GET', '/fees/estimates'));
		case 'address':
			if (filteredArgs[1] === 'validate') {
				return outputResult(
					await httpRequest('POST', '/address/validate', {
						address: filteredArgs[2]
					})
				);
			}
			return outputResult(await httpRequest('POST', '/address/new'));
		case 'mnemonic':
			return outputResult(await httpRequest('GET', '/mnemonic'));
		case 'send':
			return outputResult(
				await httpRequest('POST', '/send', {
					address: filteredArgs[1],
					amountSats: parseInt(filteredArgs[2], 10)
				})
			);
		case 'send-max':
			return outputResult(
				await httpRequest('POST', '/send-max', {
					address: filteredArgs[1],
					satsPerVbyte: filteredArgs[2]
						? parseInt(filteredArgs[2], 10)
						: undefined
				})
			);
		case 'tx':
			return handleTx();
		case 'consolidate':
			return outputResult(
				await httpRequest('POST', '/consolidate', {
					satsPerVbyte: filteredArgs[1]
						? parseInt(filteredArgs[1], 10)
						: undefined
				})
			);
		case 'peer':
			return handlePeer();
		case 'channel':
			return handleChannel();
		case 'invoice':
			return handleInvoice();
		case 'payment':
			return handlePayment();
		case 'keysend':
			return handleKeysend();
		case 'forwards':
			return handleForwards();
		case 'graph':
			return handleGraph();
		case 'gossip':
			return handleGossip();
		case 'message':
			return handleMessage();
		case 'recover-fallback-funds':
			return outputResult(
				await httpRequest('POST', '/recover-fallback-funds', {
					feeRatePerVbyte: parseFlag('--fee-rate')
						? parseInt(parseFlag('--fee-rate')!, 10)
						: undefined
				})
			);
		case 'watchtower':
			return handleWatchtower();
		case 'route':
			return handleRoute();
		case 'rebalance':
			return handleRebalance();
		case 'advisor':
			return handleAdvisor();
		case 'bootstrap':
			return handleBootstrap();
		case 'trusted-peer':
			return handleTrustedPeer();
		case 'offer':
			return handleOffer();
		case 'health':
			return outputResult(await httpRequest('GET', '/health'));
		case 'ready':
			return outputResult(await httpRequest('GET', '/ready'));
		case 'readiness':
			return outputResult(await httpRequest('GET', '/readiness'));
		case 'metrics':
			return handleMetrics();
		case 'stats':
			return outputResult(
				await httpRequest(
					'GET',
					filteredArgs[1] ? `/stats?window=${filteredArgs[1]}` : '/stats'
				)
			);
		case 'liquidity':
			return outputResult(await httpRequest('GET', '/liquidity'));
		case 'fees':
			return outputResult(await httpRequest('GET', '/fees'));
		case 'spend-limit':
			return outputResult(await httpRequest('GET', '/spend-limit'));
		case 'logs':
			return handleLogs();
		case 'can-send':
			return outputResult(
				await httpRequest(
					'GET',
					`/can-send?amountSats=${encodeURIComponent(filteredArgs[1] || '0')}`
				)
			);
		case 'can-receive':
			return outputResult(
				await httpRequest(
					'GET',
					`/can-receive?amountSats=${encodeURIComponent(
						filteredArgs[1] || '0'
					)}`
				)
			);
		case 'wallet':
			return handleWallet();
		case 'node':
			return handleNode();
		case 'webhooks':
			return handleWebhooks();
		case 'queue':
			return handleQueue();
		case 'backup':
			return handleBackup();
		case 'restore':
			return handleRestore();
		default:
			output({
				ok: false,
				error: { code: 'UNKNOWN_COMMAND', message: `Unknown command: ${cmd}` }
			});
			process.exitCode = 1;
	}
}

function handleInit(): void {
	const config = loadConfig();
	const network = parseFlag('--network') || config.network || 'mainnet';
	const alias = parseFlag('--alias') || config.alias;

	if (config.mnemonic) {
		output({
			ok: true,
			result: {
				message: 'Config already exists',
				mnemonic: config.mnemonic,
				network: config.network
			}
		});
		return;
	}

	const mnemonic = generateMnemonic();
	const newConfig: BeignetConfig = {
		...config,
		mnemonic,
		network: network as BeignetConfig['network']
	};
	if (alias) newConfig.alias = alias;
	saveConfig(newConfig);

	output({ ok: true, result: { message: 'Initialized', mnemonic, network } });
}

async function handleStart(): Promise<void> {
	const existing = readPidFile();
	if (existing) {
		// Check if process is still alive
		try {
			process.kill(existing.pid, 0);
			output({
				ok: false,
				error: {
					code: 'ALREADY_RUNNING',
					message: `Daemon already running (PID ${existing.pid}, port ${existing.port})`
				}
			});
			return;
		} catch {
			removePidFile();
		}
	}

	const cliFlags: Partial<BeignetConfig> = {};
	const networkFlag = parseFlag('--network');
	if (networkFlag) cliFlags.network = networkFlag as BeignetConfig['network'];
	const portFlag = parseFlag('--port');
	if (portFlag) cliFlags.daemonPort = parseInt(portFlag, 10);
	const aliasFlag = parseFlag('--alias');
	if (aliasFlag) cliFlags.alias = aliasFlag;
	const hostFlag = parseFlag('--host');
	if (hostFlag) cliFlags.daemonHost = hostFlag;
	if (hasFlag('--anchors')) cliFlags.preferAnchors = true;
	if (hasFlag('--large-channels')) cliFlags.largeChannels = true;
	if (hasFlag('--htlc-events')) cliFlags.htlcEvents = true;
	const apiTokenFlag = parseFlag('--api-token');
	if (apiTokenFlag) cliFlags.apiToken = apiTokenFlag;
	const backupPathFlag = parseFlag('--backup-path');
	if (backupPathFlag) cliFlags.backupPath = backupPathFlag;
	const backupIntervalFlag = parseFlag('--backup-interval');
	if (backupIntervalFlag)
		cliFlags.backupIntervalMs = parseInt(backupIntervalFlag, 10);
	const spendLimitFlag = parseFlag('--daily-spend-limit');
	if (spendLimitFlag)
		cliFlags.dailySpendLimitSats = parseInt(spendLimitFlag, 10);
	const tlsCertFlag = parseFlag('--tls-cert');
	if (tlsCertFlag) cliFlags.tlsCert = tlsCertFlag;
	const tlsKeyFlag = parseFlag('--tls-key');
	if (tlsKeyFlag) cliFlags.tlsKey = tlsKeyFlag;
	const torProxyFlag = parseFlag('--tor-proxy');
	if (torProxyFlag) cliFlags.torProxy = torProxyFlag;
	const announceAddrFlag = parseFlag('--announce-addr');
	if (announceAddrFlag)
		cliFlags.announceAddresses = announceAddrFlag
			.split(',')
			.map((a) => a.trim())
			.filter((a) => a.length > 0);
	const watchtowerFlags = parseRepeatedFlag('--watchtower');
	if (watchtowerFlags.length > 0) cliFlags.watchtowers = watchtowerFlags;

	const config = resolveConfig(cliFlags);

	if (!config.mnemonic) {
		output({
			ok: false,
			error: {
				code: 'NO_MNEMONIC',
				message:
					'No mnemonic found. Run "beignet init" first or set BEIGNET_MNEMONIC.'
			}
		});
		process.exitCode = 1;
		return;
	}

	const daemonPort = config.daemonPort || 2112;
	const isDaemon = hasFlag('--daemon');

	try {
		const { server } = await startDaemon({
			mnemonic: config.mnemonic,
			network: config.network,
			alias: config.alias,
			dataDir: config.dataDir,
			electrumHost: config.electrumHost,
			electrumPort: config.electrumPort,
			electrumTls: config.electrumTls,
			electrumServers: config.electrumServers,
			listenPort: config.listenPort,
			daemonPort,
			daemonHost: config.daemonHost,
			preferAnchors: config.preferAnchors,
			largeChannels: config.largeChannels,
			apiToken: config.apiToken,
			backupPath: config.backupPath,
			backupIntervalMs: config.backupIntervalMs,
			dailySpendLimitSats: config.dailySpendLimitSats,
			tlsCert: config.tlsCert,
			tlsKey: config.tlsKey,
			torProxy: config.torProxy,
			announceAddresses: config.announceAddresses,
			watchtowers: config.watchtowers,
			htlcEvents: config.htlcEvents
		});

		writePidFile(process.pid, daemonPort);
		output({
			ok: true,
			result: { message: 'Node started', port: daemonPort, pid: process.pid }
		});

		// Clean shutdown on signals
		const shutdown = (): void => {
			removePidFile();
			server.close();
			process.exit(0);
		};
		process.on('SIGINT', shutdown);
		process.on('SIGTERM', shutdown);

		if (isDaemon) {
			// Keep running
		} else {
			// Keep running in foreground
		}
	} catch (err: unknown) {
		const msg = err instanceof Error ? err.message : String(err);
		output({ ok: false, error: { code: 'START_FAILED', message: msg } });
		process.exitCode = 1;
	}
}

async function handleStop(): Promise<void> {
	try {
		const result = await httpRequest('POST', '/stop');
		removePidFile();
		outputResult(result);
	} catch (err: unknown) {
		removePidFile();
		const msg = err instanceof Error ? err.message : String(err);
		output({ ok: false, error: { code: 'STOP_FAILED', message: msg } });
	}
}

async function handleTx(): Promise<void> {
	const sub = filteredArgs[1];
	switch (sub) {
		case 'bump-fee':
			return outputResult(
				await httpRequest('POST', '/tx/bump-fee', {
					txid: filteredArgs[2],
					satsPerVbyte: filteredArgs[3]
						? parseInt(filteredArgs[3], 10)
						: undefined
				})
			);
		case 'boost':
			return outputResult(
				await httpRequest('POST', '/tx/boost', {
					txid: filteredArgs[2],
					satsPerVbyte: filteredArgs[3]
						? parseInt(filteredArgs[3], 10)
						: undefined
				})
			);
		case 'boostable':
			return outputResult(await httpRequest('GET', '/transactions/boostable'));
		default:
			output({
				ok: false,
				error: {
					code: 'UNKNOWN_COMMAND',
					message:
						'Usage: beignet tx [bump-fee <txid> <satsPerVbyte>|boost <txid> [satsPerVbyte]|boostable]'
				}
			});
			process.exitCode = 1;
	}
}

async function handlePeer(): Promise<void> {
	const sub = filteredArgs[1];
	switch (sub) {
		case 'connect':
			// host/port are optional: "beignet peer connect <pubkey>" resolves the
			// address from the gossip graph / DNS bootstrap.
			return outputResult(
				await httpRequest(
					'POST',
					'/peer/connect',
					filteredArgs[3] !== undefined
						? {
								pubkey: filteredArgs[2],
								host: filteredArgs[3],
								port: parseInt(filteredArgs[4], 10)
						  }
						: { pubkey: filteredArgs[2] }
				)
			);
		case 'disconnect':
			return outputResult(
				await httpRequest('POST', '/peer/disconnect', {
					pubkey: filteredArgs[2]
				})
			);
		case 'list':
			return outputResult(await httpRequest('GET', '/peers'));
		default:
			output({
				ok: false,
				error: {
					code: 'UNKNOWN_COMMAND',
					message: 'Usage: beignet peer [connect|disconnect|list]'
				}
			});
			process.exitCode = 1;
	}
}

async function handleChannel(): Promise<void> {
	const sub = filteredArgs[1];
	switch (sub) {
		case 'open':
			return outputResult(
				await httpRequest('POST', '/channel/open', {
					pubkey: filteredArgs[2],
					amountSats: parseInt(filteredArgs[3], 10),
					pushSats: filteredArgs[4] ? parseInt(filteredArgs[4], 10) : undefined
				})
			);
		case 'close':
			return outputResult(
				await httpRequest('POST', '/channel/close', {
					channelId: filteredArgs[2]
				})
			);
		case 'forceclose':
			return outputResult(
				await httpRequest('POST', '/channel/forceclose', {
					channelId: filteredArgs[2]
				})
			);
		case 'list':
			return outputResult(await httpRequest('GET', '/channels'));
		case 'get':
			return outputResult(
				await httpRequest(
					'GET',
					`/channel?channelId=${encodeURIComponent(filteredArgs[2] || '')}`
				)
			);
		case 'open-zeroconf':
			return outputResult(
				await httpRequest('POST', '/channel/open-zeroconf', {
					pubkey: filteredArgs[2],
					amountSats: parseInt(filteredArgs[3], 10),
					pushSats: filteredArgs[4] ? parseInt(filteredArgs[4], 10) : undefined
				})
			);
		case 'open-v2':
			return outputResult(
				await httpRequest('POST', '/channel/open-v2', {
					pubkey: filteredArgs[2],
					amountSats: parseInt(filteredArgs[3], 10),
					fundingFeeratePerkw: filteredArgs[4]
						? parseInt(filteredArgs[4], 10)
						: undefined
				})
			);
		case 'splice-in':
			return outputResult(
				await httpRequest('POST', '/channel/splice-in', {
					channelId: filteredArgs[2],
					amountSats: parseInt(filteredArgs[3], 10),
					feeratePerkw: parseInt(filteredArgs[4], 10)
				})
			);
		case 'splice-out':
			return outputResult(
				await httpRequest('POST', '/channel/splice-out', {
					channelId: filteredArgs[2],
					amountSats: parseInt(filteredArgs[3], 10),
					feeratePerkw: parseInt(filteredArgs[4], 10)
				})
			);
		case 'ensure-minimum':
			return outputResult(
				await httpRequest('POST', '/channels/ensure-minimum', {
					count: parseInt(filteredArgs[2], 10),
					satsPerChannel: parseInt(filteredArgs[3], 10)
				})
			);
		case 'diagnostics':
			return outputResult(
				await httpRequest(
					'GET',
					`/channel/diagnostics?channelId=${encodeURIComponent(
						filteredArgs[2] || ''
					)}`
				)
			);
		case 'health':
			return outputResult(
				await httpRequest(
					'GET',
					`/channel/health?channelId=${encodeURIComponent(
						filteredArgs[2] || ''
					)}`
				)
			);
		case 'policy':
			return outputResult(
				await httpRequest(
					'GET',
					`/channel/policy?channelId=${encodeURIComponent(
						filteredArgs[2] || ''
					)}`
				)
			);
		case 'suggestions':
			return outputResult(
				await httpRequest(
					'GET',
					filteredArgs[2]
						? `/channel/suggestions?count=${encodeURIComponent(
								filteredArgs[2]
						  )}`
						: '/channel/suggestions'
				)
			);
		case 'ready':
			return outputResult(await httpRequest('GET', '/channels/ready'));
		case 'connect-and-open':
			return outputResult(
				await httpRequest('POST', '/channel/connect-and-open', {
					pubkey: filteredArgs[2],
					host: filteredArgs[3],
					port: filteredArgs[4] ? parseInt(filteredArgs[4], 10) : undefined,
					amountSats: filteredArgs[5]
						? parseInt(filteredArgs[5], 10)
						: undefined,
					pushSats: filteredArgs[6] ? parseInt(filteredArgs[6], 10) : undefined
				})
			);
		case 'open-and-wait': {
			const timeout = parseFlag('--timeout');
			return outputResult(
				await httpRequest('POST', '/channel/open-and-wait', {
					pubkey: filteredArgs[2],
					amountSats: filteredArgs[3]
						? parseInt(filteredArgs[3], 10)
						: undefined,
					pushSats: filteredArgs[4] ? parseInt(filteredArgs[4], 10) : undefined,
					timeoutMs: timeout !== undefined ? parseInt(timeout, 10) : undefined
				})
			);
		}
		case 'wait-ready': {
			const timeout = parseFlag('--timeout');
			return outputResult(
				await httpRequest('POST', '/channel/wait-ready', {
					channelId: filteredArgs[2],
					timeoutMs: timeout !== undefined ? parseInt(timeout, 10) : undefined
				})
			);
		}
		// COMMITMENT feerate (BOLT 2 update_fee), not the routing fee policy.
		case 'update-commitment-feerate':
			return outputResult(
				await httpRequest('POST', '/channel/update-commitment-feerate', {
					channelId: filteredArgs[2],
					feeratePerKw: filteredArgs[3]
						? parseInt(filteredArgs[3], 10)
						: undefined
				})
			);
		case 'update-policy': {
			const target = filteredArgs[2];
			if (!target) {
				output({
					ok: false,
					error: {
						code: 'INVALID_PARAMS',
						message:
							'Usage: beignet channel update-policy <channelId|all> [--base-fee-msat N] [--ppm N] [--cltv-delta N] [--htlc-min-msat N] [--htlc-max-msat N]'
					}
				});
				process.exitCode = 1;
				return;
			}
			const body: Record<string, unknown> =
				target === 'all' ? { all: true } : { channelId: target };
			const baseFee = parseFlag('--base-fee-msat');
			if (baseFee !== undefined) body.feeBaseMsat = parseInt(baseFee, 10);
			const ppm = parseFlag('--ppm');
			if (ppm !== undefined) body.feeProportionalMillionths = parseInt(ppm, 10);
			const cltvDelta = parseFlag('--cltv-delta');
			if (cltvDelta !== undefined)
				body.cltvExpiryDelta = parseInt(cltvDelta, 10);
			// Msat bounds travel as strings so values above 2^53 survive JSON
			const htlcMin = parseFlag('--htlc-min-msat');
			if (htlcMin !== undefined) body.htlcMinimumMsat = htlcMin;
			const htlcMax = parseFlag('--htlc-max-msat');
			if (htlcMax !== undefined) body.htlcMaximumMsat = htlcMax;
			return outputResult(
				await httpRequest('POST', '/channel/update-policy', body)
			);
		}
		default:
			output({
				ok: false,
				error: {
					code: 'UNKNOWN_COMMAND',
					message:
						'Usage: beignet channel [open|open-zeroconf|open-v2|open-and-wait|connect-and-open|close|forceclose|splice-in|splice-out|ensure-minimum|update-policy|update-commitment-feerate|policy|diagnostics|health|suggestions|wait-ready|ready|list|get]'
				}
			});
			process.exitCode = 1;
	}
}

async function handleInvoice(): Promise<void> {
	const sub = filteredArgs[1];
	switch (sub) {
		case 'create':
			return outputResult(
				await httpRequest('POST', '/invoice/create', {
					amountSats: parseInt(filteredArgs[2], 10),
					description: filteredArgs[3] || ''
				})
			);
		case 'create-hold': {
			// The caller supplies sha256(preimage) and keeps the preimage until
			// `invoice settle-hold`. The incoming HTLC parks instead of settling.
			const paymentHash = filteredArgs[2];
			if (!paymentHash) {
				output({
					ok: false,
					error: {
						code: 'INVALID_PARAMS',
						message:
							'Usage: beignet invoice create-hold <paymentHash> [amountSats] [description] [--expiry secs]'
					}
				});
				process.exitCode = 1;
				return;
			}
			const expiryFlag = parseFlag('--expiry');
			return outputResult(
				await httpRequest('POST', '/invoice/create-hold', {
					paymentHash,
					amountSats: filteredArgs[3]
						? parseInt(filteredArgs[3], 10)
						: undefined,
					description: filteredArgs[4] || '',
					expiry: expiryFlag ? parseInt(expiryFlag, 10) : undefined
				})
			);
		}
		case 'settle-hold':
			return outputResult(
				await httpRequest('POST', '/invoice/settle-hold', {
					preimage: filteredArgs[2]
				})
			);
		case 'cancel-hold':
			return outputResult(
				await httpRequest('POST', '/invoice/cancel-hold', {
					paymentHash: filteredArgs[2]
				})
			);
		case 'held':
			return outputResult(await httpRequest('GET', '/invoices/held'));
		case 'decode':
			return outputResult(
				await httpRequest('POST', '/invoice/decode', {
					bolt11: filteredArgs[2]
				})
			);
		case 'validate':
			return outputResult(
				await httpRequest('POST', '/invoice/validate', {
					bolt11: filteredArgs[2],
					amountSats: filteredArgs[3]
						? parseInt(filteredArgs[3], 10)
						: undefined
				})
			);
		case 'get':
			return outputResult(
				await httpRequest(
					'GET',
					`/invoice?paymentHash=${encodeURIComponent(filteredArgs[2] || '')}`
				)
			);
		case 'pay':
			return outputResult(
				await httpRequest('POST', '/invoice/pay', {
					bolt11: filteredArgs[2]
				})
			);
		case 'pay-safe':
			return outputResult(
				await httpRequest('POST', '/invoice/pay-safe', {
					bolt11: filteredArgs[2],
					maxFeeSats: parseFlag('--max-fee')
						? parseInt(parseFlag('--max-fee')!, 10)
						: undefined,
					amountSats: parseFlag('--amount')
						? parseInt(parseFlag('--amount')!, 10)
						: undefined,
					timeoutMs: parseFlag('--timeout')
						? parseInt(parseFlag('--timeout')!, 10)
						: undefined
				})
			);
		case 'pay-async':
			return outputResult(
				await httpRequest('POST', '/invoice/pay-async', {
					bolt11: filteredArgs[2],
					maxFeeSats: parseFlag('--max-fee')
						? parseInt(parseFlag('--max-fee')!, 10)
						: undefined,
					amountSats: parseFlag('--amount')
						? parseInt(parseFlag('--amount')!, 10)
						: undefined
				})
			);
		case 'pay-retry':
			return outputResult(
				await httpRequest('POST', '/invoice/pay-retry', {
					bolt11: filteredArgs[2],
					maxRetries: parseFlag('--max-retries')
						? parseInt(parseFlag('--max-retries')!, 10)
						: undefined,
					backoffMs: parseFlag('--backoff-ms')
						? parseInt(parseFlag('--backoff-ms')!, 10)
						: undefined,
					maxFeeSats: parseFlag('--max-fee')
						? parseInt(parseFlag('--max-fee')!, 10)
						: undefined
				})
			);
		case 'list':
			return outputResult(await httpRequest('GET', '/invoices'));
		default:
			output({
				ok: false,
				error: {
					code: 'UNKNOWN_COMMAND',
					message:
						'Usage: beignet invoice [create|create-hold|settle-hold|cancel-hold|held|decode|validate|get|pay|pay-safe|pay-async|pay-retry|list]'
				}
			});
			process.exitCode = 1;
	}
}

async function handlePayment(): Promise<void> {
	const sub = filteredArgs[1];
	switch (sub) {
		case 'list':
			return outputResult(await httpRequest('GET', '/payments'));
		case 'get':
			return outputResult(
				await httpRequest(
					'GET',
					`/payment?paymentHash=${encodeURIComponent(filteredArgs[2] || '')}`
				)
			);
		case 'send-to-route': {
			// Route comes from `beignet route query`: inline JSON or a file path.
			const paymentHash = filteredArgs[2];
			const routeArg = filteredArgs[3];
			if (!paymentHash || !routeArg) {
				output({
					ok: false,
					error: {
						code: 'INVALID_PARAMS',
						message:
							'Usage: beignet payment send-to-route <paymentHash> <routeJson|routeFile> [--payment-secret <hex>]'
					}
				});
				process.exitCode = 1;
				return;
			}
			let routeStr = routeArg;
			if (!routeArg.trimStart().startsWith('{')) {
				try {
					routeStr = fs.readFileSync(routeArg, 'utf8');
				} catch (err: unknown) {
					output({
						ok: false,
						error: {
							code: 'INVALID_PARAMS',
							message: `Cannot read route file: ${(err as Error).message}`
						}
					});
					process.exitCode = 1;
					return;
				}
			}
			let route: { hops?: unknown };
			try {
				route = JSON.parse(routeStr);
			} catch {
				output({
					ok: false,
					error: {
						code: 'INVALID_PARAMS',
						message: 'Route is not valid JSON'
					}
				});
				process.exitCode = 1;
				return;
			}
			// Accept the full `route query` result (it has hops) or { hops: [...] }
			const result =
				route && typeof route === 'object' && 'result' in route
					? (route as { result: { hops?: unknown } }).result
					: route;
			return outputResult(
				await httpRequest('POST', '/payment/send-to-route', {
					paymentHash,
					route: { hops: result.hops },
					paymentSecret: parseFlag('--payment-secret')
				})
			);
		}
		case 'cancel':
			return outputResult(
				await httpRequest('POST', '/payment/cancel', {
					paymentHash: filteredArgs[2]
				})
			);
		case 'wait': {
			const timeout = parseFlag('--timeout');
			return outputResult(
				await httpRequest('POST', '/payment/wait', {
					paymentHash: filteredArgs[2],
					timeoutMs: timeout !== undefined ? parseInt(timeout, 10) : undefined
				})
			);
		}
		case 'proof':
			return outputResult(
				await httpRequest(
					'GET',
					`/payment/proof?paymentHash=${encodeURIComponent(
						filteredArgs[2] || ''
					)}`
				)
			);
		case 'verify-proof':
			return outputResult(
				await httpRequest(
					'GET',
					`/payment/verify-proof?paymentHash=${encodeURIComponent(
						filteredArgs[2] || ''
					)}`
				)
			);
		case 'estimate':
			return outputResult(
				await httpRequest('POST', '/payment/estimate', {
					bolt11: filteredArgs[2],
					amountSats: filteredArgs[3]
						? parseInt(filteredArgs[3], 10)
						: undefined
				})
			);
		case 'metadata': {
			// Metadata is passed as inline JSON: '{"key":"value"}'
			const paymentHash = filteredArgs[2];
			const metadataArg = filteredArgs[3];
			if (!paymentHash || !metadataArg) {
				output({
					ok: false,
					error: {
						code: 'INVALID_PARAMS',
						message:
							'Usage: beignet payment metadata <paymentHash> \'{"key":"value"}\''
					}
				});
				process.exitCode = 1;
				return;
			}
			let metadata: Record<string, string>;
			try {
				metadata = JSON.parse(metadataArg);
			} catch {
				output({
					ok: false,
					error: {
						code: 'INVALID_PARAMS',
						message: 'Metadata is not valid JSON'
					}
				});
				process.exitCode = 1;
				return;
			}
			return outputResult(
				await httpRequest('POST', '/payment/metadata', {
					paymentHash,
					metadata
				})
			);
		}
		default:
			output({
				ok: false,
				error: {
					code: 'UNKNOWN_COMMAND',
					message:
						'Usage: beignet payment [list|get|cancel|wait|proof|verify-proof|estimate|metadata|send-to-route]'
				}
			});
			process.exitCode = 1;
	}
}

async function handleKeysend(): Promise<void> {
	// "keysend safe <pubkey> <sats>" maps to POST /keysend/safe (never throws;
	// resolves with status FAILED instead).
	const safe = filteredArgs[1] === 'safe';
	const base = safe ? 2 : 1;
	const pubkey = filteredArgs[base];
	const sats = filteredArgs[base + 1];
	if (!pubkey || !sats) {
		output({
			ok: false,
			error: {
				code: 'INVALID_PARAMS',
				message:
					'Usage: beignet keysend [safe] <pubkey> <sats> [--max-fee <sats>] [--timeout <ms>]'
			}
		});
		process.exitCode = 1;
		return;
	}
	const maxFee = parseFlag('--max-fee');
	const timeout = parseFlag('--timeout');
	return outputResult(
		await httpRequest('POST', safe ? '/keysend/safe' : '/keysend', {
			pubkey,
			amountSats: parseInt(sats, 10),
			maxFeeSats: maxFee !== undefined ? parseInt(maxFee, 10) : undefined,
			timeoutMs: timeout !== undefined ? parseInt(timeout, 10) : undefined
		})
	);
}

async function handleLogs(): Promise<void> {
	const params = new URLSearchParams();
	const category = parseFlag('--category');
	if (category !== undefined) params.set('category', category);
	const since = parseFlag('--since');
	if (since !== undefined) params.set('since', since);
	const limit = parseFlag('--limit');
	if (limit !== undefined) params.set('limit', limit);
	const qs = params.toString();
	return outputResult(await httpRequest('GET', qs ? `/logs?${qs}` : '/logs'));
}

async function handleWallet(): Promise<void> {
	const sub = filteredArgs[1];
	switch (sub) {
		case 'refresh':
			return outputResult(await httpRequest('POST', '/wallet/refresh'));
		default:
			output({
				ok: false,
				error: {
					code: 'UNKNOWN_COMMAND',
					message: 'Usage: beignet wallet refresh'
				}
			});
			process.exitCode = 1;
	}
}

async function handleNode(): Promise<void> {
	const sub = filteredArgs[1];
	switch (sub) {
		case 'uri': {
			const host = parseFlag('--host');
			return outputResult(
				await httpRequest(
					'GET',
					host !== undefined
						? `/node/uri?host=${encodeURIComponent(host)}`
						: '/node/uri'
				)
			);
		}
		case 'wait-ready': {
			const timeout = parseFlag('--timeout');
			return outputResult(
				await httpRequest('POST', '/node/wait-ready', {
					timeoutMs: timeout !== undefined ? parseInt(timeout, 10) : undefined
				})
			);
		}
		default:
			output({
				ok: false,
				error: {
					code: 'UNKNOWN_COMMAND',
					message:
						'Usage: beignet node [uri [--host <addr>]|wait-ready [--timeout <ms>]]'
				}
			});
			process.exitCode = 1;
	}
}

async function handleWebhooks(): Promise<void> {
	const sub = filteredArgs[1];
	switch (sub) {
		case 'register': {
			// Events are comma-separated, e.g. "payment:received,channel:ready" or "*"
			const url = filteredArgs[2];
			const events = filteredArgs[3];
			if (!url || !events) {
				output({
					ok: false,
					error: {
						code: 'INVALID_PARAMS',
						message:
							'Usage: beignet webhooks register <url> <event,event,...|*> [--secret <secret>]'
					}
				});
				process.exitCode = 1;
				return;
			}
			return outputResult(
				await httpRequest('POST', '/webhooks/register', {
					url,
					events: events
						.split(',')
						.map((e) => e.trim())
						.filter((e) => e.length > 0),
					secret: parseFlag('--secret')
				})
			);
		}
		case 'unregister':
			return outputResult(
				await httpRequest('DELETE', '/webhooks/unregister', {
					id: filteredArgs[2]
				})
			);
		case 'list':
			return outputResult(await httpRequest('GET', '/webhooks'));
		default:
			output({
				ok: false,
				error: {
					code: 'UNKNOWN_COMMAND',
					message:
						'Usage: beignet webhooks [register <url> <events>|unregister <id>|list]'
				}
			});
			process.exitCode = 1;
	}
}

async function handleQueue(): Promise<void> {
	const sub = filteredArgs[1];
	switch (sub) {
		case 'add': {
			const bolt11 = filteredArgs[2];
			if (!bolt11) {
				output({
					ok: false,
					error: {
						code: 'INVALID_PARAMS',
						message:
							'Usage: beignet queue add <bolt11> [--priority <1-10>] [--amount <sats>] [--max-fee <sats>]'
					}
				});
				process.exitCode = 1;
				return;
			}
			const priority = parseFlag('--priority');
			const amount = parseFlag('--amount');
			const maxFee = parseFlag('--max-fee');
			return outputResult(
				await httpRequest('POST', '/queue/add', {
					bolt11,
					priority: priority !== undefined ? parseInt(priority, 10) : undefined,
					amountSats: amount !== undefined ? parseInt(amount, 10) : undefined,
					maxFeeSats: maxFee !== undefined ? parseInt(maxFee, 10) : undefined
				})
			);
		}
		case 'cancel':
			return outputResult(
				await httpRequest('POST', '/queue/cancel', { id: filteredArgs[2] })
			);
		case 'list':
			return outputResult(await httpRequest('GET', '/queue'));
		default:
			output({
				ok: false,
				error: {
					code: 'UNKNOWN_COMMAND',
					message: 'Usage: beignet queue [add <bolt11>|cancel <id>|list]'
				}
			});
			process.exitCode = 1;
	}
}

async function handleGraph(): Promise<void> {
	const sub = filteredArgs[1];
	switch (sub) {
		case 'info':
			return outputResult(await httpRequest('GET', '/graph/info'));
		case 'node':
			return outputResult(
				await httpRequest(
					'GET',
					`/graph/node?pubkey=${encodeURIComponent(filteredArgs[2] || '')}`
				)
			);
		case 'channel':
			return outputResult(
				await httpRequest(
					'GET',
					`/graph/channel?scid=${encodeURIComponent(filteredArgs[2] || '')}`
				)
			);
		case 'describe': {
			const params = new URLSearchParams();
			const limit = parseFlag('--limit');
			if (limit !== undefined) params.set('limit', limit);
			const offset = parseFlag('--offset');
			if (offset !== undefined) params.set('offset', offset);
			const qs = params.toString();
			return outputResult(
				await httpRequest(
					'GET',
					qs ? `/graph/describe?${qs}` : '/graph/describe'
				)
			);
		}
		default:
			output({
				ok: false,
				error: {
					code: 'UNKNOWN_COMMAND',
					message:
						'Usage: beignet graph [info|node <pubkey>|channel <scid>|describe [--limit N] [--offset N]]'
				}
			});
			process.exitCode = 1;
	}
}

async function handleWatchtower(): Promise<void> {
	const sub = filteredArgs[1];
	switch (sub) {
		case 'list':
			return outputResult(await httpRequest('GET', '/watchtowers'));
		case 'add': {
			const uri = filteredArgs[2];
			if (!uri) {
				output({
					ok: false,
					error: {
						code: 'INVALID_PARAMS',
						message: 'Usage: beignet watchtower add <pubkey@host:port>'
					}
				});
				process.exitCode = 1;
				return;
			}
			return outputResult(
				await httpRequest('POST', '/watchtower/add', { uri })
			);
		}
		case 'remove': {
			const uri = filteredArgs[2];
			if (!uri) {
				output({
					ok: false,
					error: {
						code: 'INVALID_PARAMS',
						message: 'Usage: beignet watchtower remove <pubkey@host:port>'
					}
				});
				process.exitCode = 1;
				return;
			}
			return outputResult(
				await httpRequest('DELETE', '/watchtower/remove', { uri })
			);
		}
		default:
			output({
				ok: false,
				error: {
					code: 'UNKNOWN_COMMAND',
					message: 'Usage: beignet watchtower [list|add <uri>|remove <uri>]'
				}
			});
			process.exitCode = 1;
	}
}

async function handleRoute(): Promise<void> {
	const sub = filteredArgs[1];
	switch (sub) {
		case 'query': {
			const destination = filteredArgs[2];
			const sats = filteredArgs[3];
			if (!destination || !sats) {
				output({
					ok: false,
					error: {
						code: 'INVALID_PARAMS',
						message:
							'Usage: beignet route query <destination> <sats> [--max-fee <sats>]'
					}
				});
				process.exitCode = 1;
				return;
			}
			const maxFee = parseFlag('--max-fee');
			return outputResult(
				await httpRequest('POST', '/route/query', {
					destination,
					amountSats: parseInt(sats, 10),
					maxFeeSats: maxFee !== undefined ? parseInt(maxFee, 10) : undefined
				})
			);
		}
		case 'estimate':
			return outputResult(
				await httpRequest('POST', '/route/estimate', {
					bolt11: filteredArgs[2],
					amountSats: filteredArgs[3]
						? parseInt(filteredArgs[3], 10)
						: undefined
				})
			);
		case 'probe': {
			const destination = filteredArgs[2];
			const sats = filteredArgs[3];
			if (!destination || !sats) {
				output({
					ok: false,
					error: {
						code: 'INVALID_PARAMS',
						message: 'Usage: beignet route probe <destination> <sats>'
					}
				});
				process.exitCode = 1;
				return;
			}
			return outputResult(
				await httpRequest('POST', '/route/probe', {
					destination,
					amountSats: parseInt(sats, 10)
				})
			);
		}
		default:
			output({
				ok: false,
				error: {
					code: 'UNKNOWN_COMMAND',
					message:
						'Usage: beignet route [query <destination> <sats>|estimate <bolt11> [sats]|probe <destination> <sats>]'
				}
			});
			process.exitCode = 1;
	}
}

async function handleForwards(): Promise<void> {
	const params = new URLSearchParams();
	const since = parseFlag('--since');
	if (since !== undefined) params.set('since', since);
	if (filteredArgs[1] === 'summary') {
		const qs = params.toString();
		return outputResult(
			await httpRequest('GET', `/forwards/summary${qs ? `?${qs}` : ''}`)
		);
	}
	const limit = parseFlag('--limit');
	if (limit !== undefined) params.set('limit', limit);
	const qs = params.toString();
	return outputResult(
		await httpRequest('GET', `/forwards${qs ? `?${qs}` : ''}`)
	);
}

async function handleRebalance(): Promise<void> {
	const fromChannelId = filteredArgs[1];
	const toChannelId = filteredArgs[2];
	const amountSats = filteredArgs[3];
	const maxFee = parseFlag('--max-fee');
	// --max-fee is mandatory: the CLI never invents a routing-fee cap.
	if (!fromChannelId || !toChannelId || !amountSats || maxFee === undefined) {
		output({
			ok: false,
			error: {
				code: 'INVALID_PARAMS',
				message:
					'Usage: beignet rebalance <fromChannelId> <toChannelId> <amountSats> --max-fee <sats>'
			}
		});
		process.exitCode = 1;
		return;
	}
	return outputResult(
		await httpRequest('POST', '/rebalance', {
			fromChannelId,
			toChannelId,
			amountSats: parseInt(amountSats, 10),
			maxFeeSats: parseInt(maxFee, 10)
		})
	);
}

async function handleAdvisor(): Promise<void> {
	const sub = filteredArgs[1];
	switch (sub) {
		case 'recommendations':
			return outputResult(await httpRequest('GET', '/advisor/recommendations'));
		case 'execute-rebalances': {
			const budget = parseFlag('--budget');
			return outputResult(
				await httpRequest('POST', '/advisor/execute-rebalances', {
					budgetSatsPerDay:
						budget !== undefined ? parseInt(budget, 10) : undefined
				})
			);
		}
		default:
			output({
				ok: false,
				error: {
					code: 'UNKNOWN_COMMAND',
					message:
						'Usage: beignet advisor [recommendations|execute-rebalances [--budget <sats>]]'
				}
			});
			process.exitCode = 1;
	}
}

async function handleBootstrap(): Promise<void> {
	const sub = filteredArgs[1];
	switch (sub) {
		case 'discover':
			return outputResult(await httpRequest('POST', '/peers/bootstrap'));
		case 'connect':
			return outputResult(
				await httpRequest('POST', '/peers/connect-seeds', {
					maxPeers: filteredArgs[2] ? parseInt(filteredArgs[2], 10) : undefined
				})
			);
		default:
			output({
				ok: false,
				error: {
					code: 'UNKNOWN_COMMAND',
					message: 'Usage: beignet bootstrap [discover|connect [maxPeers]]'
				}
			});
			process.exitCode = 1;
	}
}

async function handleTrustedPeer(): Promise<void> {
	const sub = filteredArgs[1];
	switch (sub) {
		case 'add':
			return outputResult(
				await httpRequest('POST', '/trusted-peer/add', {
					pubkey: filteredArgs[2]
				})
			);
		case 'remove':
			return outputResult(
				await httpRequest('POST', '/trusted-peer/remove', {
					pubkey: filteredArgs[2]
				})
			);
		case 'list':
			return outputResult(await httpRequest('GET', '/trusted-peers'));
		default:
			output({
				ok: false,
				error: {
					code: 'UNKNOWN_COMMAND',
					message: 'Usage: beignet trusted-peer [add|remove|list]'
				}
			});
			process.exitCode = 1;
	}
}

async function handleOffer(): Promise<void> {
	const sub = filteredArgs[1];
	switch (sub) {
		case 'create':
			return outputResult(
				await httpRequest('POST', '/offer/create', {
					description: filteredArgs[2] || '',
					amountSats: filteredArgs[3]
						? parseInt(filteredArgs[3], 10)
						: undefined
				})
			);
		case 'list':
			return outputResult(await httpRequest('GET', '/offers'));
		case 'decode':
			return outputResult(
				await httpRequest('POST', '/offer/decode', {
					offer: filteredArgs[2]
				})
			);
		case 'pay':
			return outputResult(
				await httpRequest('POST', '/offer/pay', {
					offer: filteredArgs[2],
					amountSats: filteredArgs[3]
						? parseInt(filteredArgs[3], 10)
						: undefined
				})
			);
		default:
			output({
				ok: false,
				error: {
					code: 'UNKNOWN_COMMAND',
					message: 'Usage: beignet offer [create|list|decode|pay]'
				}
			});
			process.exitCode = 1;
	}
}

async function handleGossip(): Promise<void> {
	const sub = filteredArgs[1];
	switch (sub) {
		case 'sync':
			return outputResult(
				await httpRequest('POST', '/gossip/sync', {
					pubkey: filteredArgs[2] || undefined
				})
			);
		case 'sync-rapid':
			return outputResult(await httpRequest('POST', '/gossip/sync-rapid'));
		default:
			output({
				ok: false,
				error: {
					code: 'UNKNOWN_COMMAND',
					message: 'Usage: beignet gossip [sync [pubkey]|sync-rapid]'
				}
			});
			process.exitCode = 1;
	}
}

async function handleMessage(): Promise<void> {
	const sub = filteredArgs[1];
	switch (sub) {
		case 'sign':
			return outputResult(
				await httpRequest('POST', '/message/sign', {
					message: filteredArgs[2]
				})
			);
		case 'verify':
			return outputResult(
				await httpRequest('POST', '/message/verify', {
					message: filteredArgs[2],
					signature: filteredArgs[3]
				})
			);
		default:
			output({
				ok: false,
				error: {
					code: 'UNKNOWN_COMMAND',
					message:
						'Usage: beignet message [sign <message>|verify <message> <signature>]'
				}
			});
			process.exitCode = 1;
	}
}

async function handleBackup(): Promise<void> {
	const sub = filteredArgs[1];
	if (sub === 'trigger') {
		// On-demand encrypted database backup to the configured backupPath.
		return outputResult(await httpRequest('POST', '/backup/trigger'));
	}
	if (sub === 'peer-retrieved') {
		// `beignet backup peer-retrieved`: newest valid SCB a peer returned via
		// BOLT 1 peer storage. Restore explicitly with `beignet restore scb`.
		return outputResult(await httpRequest('GET', '/backup/peer-retrieved'));
	}
	if (sub === 'scb') {
		// `beignet backup scb [destPath]`: fetch the encrypted static channel
		// backup; with destPath, write the encoded blob there instead of printing.
		const result = await httpRequest('GET', '/backup/scb');
		const destPath = filteredArgs[2];
		if (!result.ok || !destPath) return outputResult(result);
		const { encoded, channelCount } = result.result as {
			encoded: string;
			channelCount: number;
		};
		fs.writeFileSync(destPath, encoded);
		return output({
			ok: true,
			result: { written: true, path: destPath, channelCount }
		});
	}
	// `beignet backup <destPath>`: legacy full-database copy.
	if (!sub) {
		output({
			ok: false,
			error: {
				code: 'INVALID_PARAMS',
				message:
					'Usage: beignet backup <destPath> | beignet backup scb [destPath] | beignet backup trigger'
			}
		});
		process.exitCode = 1;
		return;
	}
	return outputResult(await httpRequest('POST', '/backup', { destPath: sub }));
}

async function handleRestore(): Promise<void> {
	const sub = filteredArgs[1];
	const file = filteredArgs[2];

	if (sub === 'scb') {
		// On-chain recovery only: channels are reconstructed in a broadcast-banned
		// state and funds arrive when each peer force-closes. Requires the daemon.
		if (!file) {
			output({
				ok: false,
				error: {
					code: 'INVALID_PARAMS',
					message: 'Usage: beignet restore scb <file>'
				}
			});
			process.exitCode = 1;
			return;
		}
		let encoded: string;
		try {
			encoded = fs.readFileSync(file, 'utf8').trim();
		} catch (err: unknown) {
			output({
				ok: false,
				error: {
					code: 'INVALID_PARAMS',
					message: `Cannot read SCB file: ${(err as Error).message}`
				}
			});
			process.exitCode = 1;
			return;
		}
		return outputResult(await httpRequest('POST', '/restore/scb', { encoded }));
	}

	if (sub === 'db') {
		// OFFLINE full-state restore: copies a database backup into place. The
		// daemon must be stopped - the restore holds the same single-instance
		// lock the daemon takes, so a live node is never overwritten.
		if (!file) {
			output({
				ok: false,
				error: {
					code: 'INVALID_PARAMS',
					message: 'Usage: beignet restore db <backupFile>'
				}
			});
			process.exitCode = 1;
			return;
		}
		const config = resolveConfig({});
		if (!config.mnemonic) {
			output({
				ok: false,
				error: {
					code: 'NO_MNEMONIC',
					message:
						'No mnemonic found. Run "beignet init" first or set BEIGNET_MNEMONIC (the restored DB is seed-encrypted and needs the same mnemonic).'
				}
			});
			process.exitCode = 1;
			return;
		}
		// Belt and braces: the PID file catches a daemon started via this CLI
		// even when it runs on a different data dir than the one resolved here.
		const pidInfo = readPidFile();
		if (pidInfo) {
			try {
				process.kill(pidInfo.pid, 0);
				output({
					ok: false,
					error: {
						code: 'DAEMON_RUNNING',
						message: `Daemon is running (PID ${pidInfo.pid}). Stop it with 'beignet stop' before restoring the database.`
					}
				});
				process.exitCode = 1;
				return;
			} catch {
				// Stale PID file - the instance lock below is the real gate.
			}
		}
		const network = config.network || 'mainnet';
		const dataDir =
			config.dataDir || defaultDataDirForMnemonic(config.mnemonic);
		const dbPath = nodePath.join(dataDir, `${network}.db`);
		const lockPath = nodePath.join(dataDir, `${network}.lock`);
		try {
			fs.mkdirSync(dataDir, { recursive: true });
			const result = performDbRestore(file, dbPath, lockPath);
			output({
				ok: true,
				result: {
					restored: true,
					dbPath: result.dbPath,
					preRestorePath: result.preRestorePath,
					network,
					note: 'DB is encrypted under the wallet seed; start the node with the same mnemonic.'
				}
			});
		} catch (err: unknown) {
			const code =
				err instanceof InstanceLockError ? 'DAEMON_RUNNING' : 'RESTORE_FAILED';
			output({
				ok: false,
				error: { code, message: (err as Error).message }
			});
			process.exitCode = 1;
		}
		return;
	}

	output({
		ok: false,
		error: {
			code: 'UNKNOWN_COMMAND',
			message:
				'Usage: beignet restore scb <file> | beignet restore db <backupFile>'
		}
	});
	process.exitCode = 1;
}

async function handleMetrics(): Promise<void> {
	const port = getDaemonPort();
	const token = getApiToken();
	return new Promise((resolve, reject) => {
		const headers: Record<string, string> = {};
		if (token) headers['Authorization'] = `Bearer ${token}`;
		const req = http.request(
			{ hostname: '127.0.0.1', port, path: '/metrics', method: 'GET', headers },
			(res) => {
				const chunks: Buffer[] = [];
				res.on('data', (chunk: Buffer) => chunks.push(chunk));
				res.on('end', () => {
					process.stdout.write(Buffer.concat(chunks).toString());
					resolve();
				});
			}
		);
		req.on('error', (err) => {
			reject(
				new Error(
					`Cannot connect to daemon on port ${port}: ${err.message}. Is it running?`
				)
			);
		});
		req.end();
	});
}

function outputResult(result: ApiResponse<unknown>): void {
	output(result);
	if (!result.ok) process.exitCode = 1;
}

function printHelp(): void {
	const help = `beignet - AI-friendly Bitcoin + Lightning CLI

Usage: beignet <command> [options]

Setup:
  init [--network N] [--alias A]         Generate mnemonic + config
  start [flags]                          Start node daemon
  stop                                   Stop daemon

Info:
  info                                   Node info
  balance                                On-chain + Lightning balance
  address                                New receive address
  address validate <address>             Validate a Bitcoin address
  mnemonic                               Show mnemonic
  health                                 Node health status
  ready                                  Whether the node is operational
  readiness                              Mainnet readiness checklist
  metrics                                Prometheus-format metrics (text/plain)
  stats [windowMs]                       Node statistics (optional time window)
  liquidity                              Liquidity snapshot + recommendations
  fees                                   On-chain fee trend analysis
  spend-limit                            Daily spending limit status
  logs [--category C] [--since ts] [--limit n]
                                         Query the persistent action log
  can-send [sats]                        Check Lightning send capacity
  can-receive [sats]                     Check Lightning receive capacity
  node uri [--host <addr>]               Node connection URI (pubkey@host:port)
  node wait-ready [--timeout ms]         Block until the node is operational

On-chain:
  send <address> <sats>                  Send on-chain
  send-max <address> [satsPerVbyte]      Sweep the whole on-chain balance
  tx bump-fee <txid> <satsPerVbyte>      RBF an unconfirmed tx at a higher fee
  tx boost <txid> [satsPerVbyte]         Fee-bump a tx (RBF when possible,
                                         else CPFP)
  tx boostable                           List unconfirmed txs eligible for
                                         RBF/CPFP
  consolidate [satsPerVbyte]             Merge all UTXOs into one output at a
                                         fresh wallet address
  transactions [limit]                   List on-chain transactions (newest first)
  utxos                                  List wallet UTXOs
  fee-estimates                          Current fee estimates (sats/vbyte)
  wallet refresh                         Re-sync the on-chain wallet
  recover-fallback-funds [--fee-rate N]  Sweep funding-key fallback UTXOs into
                                         the wallet
  backup <destPath>                      Create database backup
  backup trigger                         Run the configured scheduled backup now
  backup scb [destPath]                  Export encrypted static channel backup
  backup peer-retrieved                  Show newest SCB returned by a peer
                                         (BOLT 1 peer storage)
  restore scb <file>                     Restore channels from an SCB (on-chain
                                         recovery only: peers force-close and
                                         funds are swept to the wallet)
  restore db <backupFile>                Restore a database backup (full state;
                                         OFFLINE - stop the daemon first; needs
                                         the same mnemonic, DB is seed-encrypted)

Peers:
  peer connect <pubkey> <host> <port>    Connect to peer
  peer disconnect <pubkey>               Disconnect peer
  peer list                              List peers

DNS Bootstrap (BOLT 10):
  bootstrap discover                     Discover peers via DNS seeds
  bootstrap connect [maxPeers]           Connect to discovered peers

Trusted Peers (Zero-Conf):
  trusted-peer add <pubkey>              Trust peer for zero-conf channels
  trusted-peer remove <pubkey>           Remove peer from trusted set
  trusted-peer list                      List trusted peers

Channels:
  channel open <pubkey> <sats> [push]    Open channel (auto-funded)
  channel open-zeroconf <pk> <sats> [push]  Open zero-conf channel
  channel open-v2 <pubkey> <sats> [feerate]  Open dual-funded v2 channel
  channel open-and-wait <pubkey> <sats> [push] [--timeout ms]
                                         Open channel + block until NORMAL
  channel connect-and-open <pubkey> <host> <port> <sats> [push]
                                         Connect to peer + open in one call
  channel close <id>                     Cooperative close
  channel forceclose <id>                Force close
  channel splice-in <id> <sats> <feerate>   Add funds to channel
  channel splice-out <id> <sats> <feerate>  Withdraw funds from channel
  channel ensure-minimum <count> <sats>  Auto-open channels to minimum count
  channel update-policy <id|all> [--base-fee-msat N] [--ppm N] [--cltv-delta N]
                        [--htlc-min-msat N] [--htlc-max-msat N]
                                         Set routing fee policy (channel_update)
  channel update-commitment-feerate <id> <feeratePerKw>
                                         Set COMMITMENT feerate (BOLT 2
                                         update_fee), not the routing policy
  channel policy <id>                    Effective routing policy for a channel
  channel list                           List channels
  channel ready                          List channels in NORMAL state
  channel get <id>                       Channel details (includes routing policy)
  channel health <id>                    Channel health + liquidity warnings
  channel diagnostics <id>               Routing-readiness diagnostics for a channel
  channel suggestions [count]            Graph-based channel open suggestions
  channel wait-ready <id> [--timeout ms] Block until a channel reaches NORMAL

Invoices & Payments:
  invoice create <sats> [description]    Create BOLT 11 invoice
  invoice create-hold <hash> [sats] [description] [--expiry secs]
                                         Create hold invoice for a payment hash
                                         you supply (keep the preimage; HTLCs
                                         park until settle-hold/cancel-hold)
  invoice settle-hold <preimage>         Settle a parked hold invoice
  invoice cancel-hold <hash>             Cancel a hold invoice (fails HTLCs back)
  invoice held                           List hold invoices + their state
  invoice decode <bolt11>                Decode invoice
  invoice validate <bolt11> [sats]       Pre-flight checks: should this be paid?
  invoice get <hash>                     Details of an invoice we created
  invoice pay <bolt11>                   Pay invoice (blocks until settled)
  invoice pay-safe <bolt11> [--max-fee N] [--amount N] [--timeout ms]
                                         Pay; resolves with status FAILED
                                         instead of erroring
  invoice pay-async <bolt11> [--max-fee N] [--amount N]
                                         Fire-and-forget pay; poll 'payment get'
  invoice pay-retry <bolt11> [flags]     Pay with exponential backoff retry
  invoice list                           List created invoices
  keysend [safe] <pubkey> <sats> [--max-fee N] [--timeout ms]
                                         Spontaneous payment, no invoice needed
                                         ('safe' resolves FAILED, never errors)
  payment list                           List payments
  payment get <hash>                     Payment details
  payment cancel <hash>                  Cancel a pending outbound payment
  payment wait <hash> [--timeout ms]     Block until a payment settles
  payment proof <hash>                   Cryptographic payment proof
  payment verify-proof <hash>            Verify a stored payment proof
  payment estimate <bolt11> [sats]       Success probability + fee estimate
  payment metadata <hash> <json>         Attach key-value metadata to a payment
  payment send-to-route <hash> <route>   Pay along an explicit route (inline
                                         JSON or a file with 'route query'
                                         output) [--payment-secret <hex>]
  queue add <bolt11> [--priority N] [--amount N] [--max-fee N]
                                         Enqueue a payment for ordered dispatch
  queue cancel <id>                      Cancel a queued payment
  queue list                             List the payment queue

Graph Queries:
  graph info                             Graph summary (node/channel counts)
  graph node <pubkey>                    Node announcement info + its channels
  graph channel <scid>                   Channel endpoints + both fee policies
                                         (scid: <block>x<tx>x<out> or hex)
  graph describe [--limit N] [--offset N]  Paged channel dump (default 500)
  gossip sync [pubkey]                   Sync gossip from peers (or one peer)
  gossip sync-rapid                      Rapid Gossip Sync snapshot (mainnet)
  route query <destination> <sats>       Compute a route without paying
                                         [--max-fee <sats>]
  route estimate <bolt11> [sats]         Estimate route fee for an invoice
  route probe <destination> <sats>       Probe route viability (no payment)

Routing:
  forwards [--since ts] [--limit n]      List settled forwards (fees earned)
  forwards summary [--since ts]          Forwarding totals (count, volume, fees)
  rebalance <fromId> <toId> <sats> --max-fee <sats>
                                         Circular rebalance between two of our
                                         channels (aborts if fee exceeds cap)
  advisor recommendations                Liquidity analysis + rebalance plan
  advisor execute-rebalances [--budget <sats>]
                                         Run the advisor's rebalance plan under
                                         a per-day fee budget

Messages:
  message sign <message>                 Sign with the node key (LND-compatible)
  message verify <message> <signature>   Recover + check the signer pubkey
Watchtowers:
  watchtower list                        Per-tower session + backlog health
  watchtower add <pubkey@host:port>      Add an LND altruist watchtower
  watchtower remove <pubkey@host:port>   Remove a watchtower

BOLT 12 Offers:
  offer create <description> [amountSats]  Create reusable offer
  offer list                             List local offers
  offer decode <offer>                   Decode a BOLT 12 offer string
  offer pay <offer> [amountSats]         Pay a BOLT 12 offer

Webhooks (event push; see also GET /events SSE):
  webhooks register <url> <events> [--secret S]
                                         Register a callback URL; <events> is
                                         comma-separated (or '*' for all)
  webhooks unregister <id>               Remove a webhook
  webhooks list                          List registered webhooks

Start flags:
  --port <N>                             HTTP daemon port (default: 2112)
  --host <addr>                          HTTP daemon bind address (default: 127.0.0.1)
  --daemon                               Run in background
  --anchors                              Prefer anchor channels (zero-fee HTLC)
  --api-token <token>                    API authentication token
  --backup-path <path>                   Enable automated backups to path
  --backup-interval <ms>                 Backup interval (default: 21600000 = 6h)
  --daily-spend-limit <sats>             Daily spending limit in satoshis
  --tls-cert <path>                      TLS certificate file (enables HTTPS)
  --tls-key <path>                       TLS private key file (requires --tls-cert)
  --tor-proxy <host:port>                SOCKS5 proxy for outbound Lightning peer
                                         connections (e.g. Tor at 127.0.0.1:9050)
  --announce-addr <addr[,addr...]>       Addresses to advertise in node_announcement
                                         (IPv4, [ipv6]:port, .onion v3, or hostname;
                                         port defaults to 9735)
  --htlc-events                          Relay per-HTLC events (htlc:forwarded/
                                         fulfilled/failed) over SSE + webhooks
                                         (off by default: high volume on routers)

Pay-retry flags:
  --max-retries <N>                      Max retry attempts (default: 3)
  --backoff-ms <N>                       Base backoff delay (default: 2000)
  --max-fee <sats>                       Max routing fee cap

Global options:
  --pretty                               Pretty-print JSON output

All output is JSON (except 'metrics'). The CLI sends HTTP requests to the daemon on 127.0.0.1:2112.`;

	process.stdout.write(help + '\n');
}

main().catch((err) => {
	output({
		ok: false,
		error: { code: 'FATAL', message: err.message || String(err) }
	});
	process.exitCode = 1;
});
