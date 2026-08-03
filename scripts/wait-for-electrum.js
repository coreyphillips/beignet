#!/usr/bin/env node
/**
 * Wait until the Electrum server is genuinely SERVING, not merely listening.
 *
 * CI used `wait-for-it -p 60001`, which a published Docker port satisfies
 * the instant the container starts: the proxy accepts the connection while
 * electrs is still starting up and syncing. The wait therefore returned
 * "available after 0 seconds" and the wallet suite opened its first real
 * connection into a server that was not answering yet, which failed the
 * connect test and then cascaded into "No UTXOs available" across every
 * wallet test that needed a synced index.
 *
 * This probe speaks the protocol instead: it requires a `server.version`
 * answer AND a `blockchain.headers.subscribe` tip that has caught up with
 * bitcoind's block count, so "ready" means what the tests need it to mean.
 *
 * Usage: node scripts/wait-for-electrum.js [host] [port] [timeoutSeconds]
 * Env:   BITCOIN_RPC_URL to compare tips (skipped when unset/unreachable).
 */

// Plain CommonJS on purpose: CI runs this with bare `node`, before the
// project's dependencies (and its TypeScript loader) are installed.
/* eslint-disable @typescript-eslint/no-var-requires */
const net = require('net');
const http = require('http');
const https = require('https');

const host = process.argv[2] || '127.0.0.1';
const port = Number(process.argv[3] || 60001);
const timeoutSeconds = Number(process.argv[4] || 180);
const bitcoinRpcUrl =
	process.env.BITCOIN_RPC_URL || 'http://polaruser:polarpass@127.0.0.1:43782';

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** One request/response round trip over a fresh socket. */
function electrumCall(method, params, socketTimeoutMs = 5000) {
	return new Promise((resolve, reject) => {
		const socket = net.connect({ host, port });
		let buffer = '';
		const done = (err, value) => {
			socket.removeAllListeners();
			socket.destroy();
			err ? reject(err) : resolve(value);
		};
		socket.setTimeout(socketTimeoutMs);
		socket.on('timeout', () => done(new Error('socket timeout')));
		socket.on('error', (err) => done(err));
		socket.on('connect', () => {
			socket.write(`${JSON.stringify({ id: 1, method, params })}\n`);
		});
		socket.on('data', (chunk) => {
			buffer += chunk.toString('utf8');
			const newline = buffer.indexOf('\n');
			if (newline === -1) return;
			try {
				const message = JSON.parse(buffer.slice(0, newline));
				if (message.error) {
					done(new Error(JSON.stringify(message.error)));
					return;
				}
				done(null, message.result);
			} catch (err) {
				done(err);
			}
		});
	});
}

/** bitcoind's block count, or null when it cannot be read. */
function bitcoinBlockCount() {
	return new Promise((resolve) => {
		let url;
		try {
			url = new URL(bitcoinRpcUrl);
		} catch {
			resolve(null);
			return;
		}
		const body = JSON.stringify({
			jsonrpc: '1.0',
			id: 'wait-for-electrum',
			method: 'getblockcount',
			params: []
		});
		const transport = url.protocol === 'https:' ? https : http;
		const request = transport.request(
			{
				hostname: url.hostname,
				port: url.port,
				path: url.pathname || '/',
				method: 'POST',
				timeout: 5000,
				auth: `${decodeURIComponent(url.username)}:${decodeURIComponent(
					url.password
				)}`,
				headers: { 'Content-Type': 'application/json' }
			},
			(response) => {
				let data = '';
				response.on('data', (chunk) => (data += chunk));
				response.on('end', () => {
					try {
						resolve(JSON.parse(data).result ?? null);
					} catch {
						resolve(null);
					}
				});
			}
		);
		request.on('timeout', () => {
			request.destroy();
			resolve(null);
		});
		request.on('error', () => resolve(null));
		request.write(body);
		request.end();
	});
}

async function main() {
	const deadline = Date.now() + timeoutSeconds * 1000;
	let lastFailure = 'no attempt made';
	let attempts = 0;

	while (Date.now() < deadline) {
		attempts += 1;
		try {
			await electrumCall('server.version', ['beignet-ci', '1.4']);
			const tip = await electrumCall('blockchain.headers.subscribe', []);
			const electrumHeight =
				tip && typeof tip.height === 'number' ? tip.height : -1;
			if (electrumHeight < 0) {
				throw new Error('no tip height in headers subscription');
			}
			const chainHeight = await bitcoinBlockCount();
			if (chainHeight !== null && electrumHeight < chainHeight) {
				throw new Error(
					`indexing: electrum at ${electrumHeight}, bitcoind at ${chainHeight}`
				);
			}
			console.log(
				`electrum ${host}:${port} is serving at height ${electrumHeight} ` +
					`after ${attempts} attempt(s)`
			);
			return;
		} catch (err) {
			lastFailure = err instanceof Error ? err.message : String(err);
		}
		await sleep(1000);
	}

	console.error(
		`electrum ${host}:${port} was not serving within ${timeoutSeconds}s ` +
			`(${attempts} attempts, last failure: ${lastFailure})`
	);
	process.exit(1);
}

main().catch((err) => {
	console.error(err);
	process.exit(1);
});
