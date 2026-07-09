#!/usr/bin/env node

/**
 * Beignet CLI: AI-friendly Bitcoin + Lightning interface.
 *
 * Commands are thin HTTP clients that send requests to the daemon,
 * except `init` and `start` which are handled locally.
 */

import * as http from 'http';
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
		case 'peer':
			return handlePeer();
		case 'channel':
			return handleChannel();
		case 'invoice':
			return handleInvoice();
		case 'payment':
			return handlePayment();
		case 'bootstrap':
			return handleBootstrap();
		case 'trusted-peer':
			return handleTrustedPeer();
		case 'offer':
			return handleOffer();
		case 'health':
			return outputResult(await httpRequest('GET', '/health'));
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
		case 'backup':
			return outputResult(
				await httpRequest('POST', '/backup', {
					destPath: filteredArgs[1]
				})
			);
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
			apiToken: config.apiToken,
			backupPath: config.backupPath,
			backupIntervalMs: config.backupIntervalMs,
			dailySpendLimitSats: config.dailySpendLimitSats,
			tlsCert: config.tlsCert,
			tlsKey: config.tlsKey,
			torProxy: config.torProxy,
			announceAddresses: config.announceAddresses
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

async function handlePeer(): Promise<void> {
	const sub = filteredArgs[1];
	switch (sub) {
		case 'connect':
			return outputResult(
				await httpRequest('POST', '/peer/connect', {
					pubkey: filteredArgs[2],
					host: filteredArgs[3],
					port: parseInt(filteredArgs[4], 10)
				})
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
		default:
			output({
				ok: false,
				error: {
					code: 'UNKNOWN_COMMAND',
					message:
						'Usage: beignet channel [open|open-zeroconf|open-v2|close|forceclose|splice-in|splice-out|ensure-minimum|list|get]'
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
		case 'decode':
			return outputResult(
				await httpRequest('POST', '/invoice/decode', {
					bolt11: filteredArgs[2]
				})
			);
		case 'pay':
			return outputResult(
				await httpRequest('POST', '/invoice/pay', {
					bolt11: filteredArgs[2]
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
					message: 'Usage: beignet invoice [create|decode|pay|pay-retry|list]'
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
		default:
			output({
				ok: false,
				error: {
					code: 'UNKNOWN_COMMAND',
					message: 'Usage: beignet payment [list|get]'
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
					message: 'Usage: beignet offer [create|list|pay]'
				}
			});
			process.exitCode = 1;
	}
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
  mnemonic                               Show mnemonic
  health                                 Node health status
  readiness                              Mainnet readiness checklist
  metrics                                Prometheus-format metrics (text/plain)
  stats [windowMs]                       Node statistics (optional time window)

On-chain:
  send <address> <sats>                  Send on-chain
  transactions [limit]                   List on-chain transactions (newest first)
  utxos                                  List wallet UTXOs
  fee-estimates                          Current fee estimates (sats/vbyte)
  backup <destPath>                      Create database backup

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
  channel close <id>                     Cooperative close
  channel forceclose <id>                Force close
  channel splice-in <id> <sats> <feerate>   Add funds to channel
  channel splice-out <id> <sats> <feerate>  Withdraw funds from channel
  channel ensure-minimum <count> <sats>  Auto-open channels to minimum count
  channel list                           List channels
  channel get <id>                       Channel details

Invoices & Payments:
  invoice create <sats> [description]    Create BOLT 11 invoice
  invoice decode <bolt11>                Decode invoice
  invoice pay <bolt11>                   Pay invoice (blocks until settled)
  invoice pay-retry <bolt11> [flags]     Pay with exponential backoff retry
  invoice list                           List created invoices
  payment list                           List payments
  payment get <hash>                     Payment details

BOLT 12 Offers:
  offer create <description> [amountSats]  Create reusable offer
  offer list                             List local offers
  offer pay <offer> [amountSats]         Pay a BOLT 12 offer

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
