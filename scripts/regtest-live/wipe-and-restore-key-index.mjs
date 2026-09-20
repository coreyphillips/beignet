#!/usr/bin/env node
/**
 * Live regtest check for issue #918 (the interop half of issue #906): a node
 * that opens a channel against a real LSP, loses its data directory, and
 * boots again from the mnemonic alone must NOT hand its next channel the keys
 * of the channel the previous device held. PR #914 floors the channel key
 * index at the birth tip times 128 and fences new channels until the tip is
 * known; this script proves it end to end against a live beignet LSP, with
 * the LSP OPENING the channel (inbound on our side) through beignet direct
 * funding, so the inbound acceptor path is the one exercised.
 *
 * What it does, with three daemons built from this checkout (`npm run build`
 * first):
 *   1. Device A boots from a fresh mnemonic, connects to the LSP, configures
 *      it as the direct-funding liquidity peer and mints a request.
 *   2. A payer P boots from its own mnemonic, is funded by the regtest
 *      faucet, and pays A's request: the LSP opens a channel to A.
 *   3. A stops. Its data directory is copied aside and deleted.
 *   4. Device B boots from A's mnemonic against an EMPTY directory, at a
 *      later chain tip, and the same flow gives it a second channel.
 *   5. Both databases are read back with the seed-derived storage key, and
 *      the script asserts: each index is at or above its boot's floor, B's
 *      index is above A's, the funding pubkeys, revocation basepoints and
 *      per-commitment seeds differ, and neither channel used key index 1.
 *
 * Environment (defaults match the maintainer's regtest set-up):
 *   BEIGNET_LSP_URI    pubkey@host:port of a beignet LSP with direct funding
 *   REGTEST_API        the regtest dashboard base URL (faucet + mining)
 *   BEIGNET_ELECTRUM_HOST / BEIGNET_ELECTRUM_PORT / BEIGNET_ELECTRUM_TLS
 *   BEIGNET_TOR_PROXY  SOCKS5 host:port when the LSP is an onion address
 *   WORK_DIR           where the daemons' HOME and data directories go
 *   CHANNEL_SATS       channel size (default 200000)
 *
 * Run: node scripts/regtest-live/wipe-and-restore-key-index.mjs
 * Exit code 0 means every assertion held; the daemons are stopped on exit.
 */
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const bip39 = require('bip39');
const { BIP32Factory } = require('bip32');
const ecc = require('@bitcoinerlab/secp256k1');
const { SqliteStorage } = require(path.join(repo, 'dist/lightning/storage/sqlite-storage.js'));
const { deriveStorageKey } = require(path.join(repo, 'dist/lightning/storage/encryption.js'));
const { deriveChannelKeys, LnCoinType } = require(path.join(repo, 'dist/lightning/keys/wallet-keys.js'));

const LSP_URI = process.env.BEIGNET_LSP_URI ||
	'0324d19e88c07c43d474d8695932d499df2db5f8c24ed82f247cd7cea54c9bbaf9@ulyeemszaigzrvpjcjcby4ehibrvsuqi5sq4dmmew2urk2nse5f7spid.onion:9103';
const REGTEST_API = process.env.REGTEST_API || 'http://mint.local:3022';
const ELECTRUM_HOST = process.env.BEIGNET_ELECTRUM_HOST || 'mint.local';
const ELECTRUM_PORT = process.env.BEIGNET_ELECTRUM_PORT || '60401';
const ELECTRUM_TLS = process.env.BEIGNET_ELECTRUM_TLS || 'false';
const TOR_PROXY = process.env.BEIGNET_TOR_PROXY || '127.0.0.1:9050';
const CHANNEL_SATS = Number(process.env.CHANNEL_SATS || 200000);
const WORK_DIR = process.env.WORK_DIR || fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-918-'));
const CLI = path.join(repo, 'dist/cli/cli.js');
const STRIDE = 128;

const [lspPubkey, lspAddr] = LSP_URI.split('@');
const lspHost = lspAddr.slice(0, lspAddr.lastIndexOf(':'));
const lspPort = Number(lspAddr.slice(lspAddr.lastIndexOf(':') + 1));

const daemons = [];
const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function boot(tag, mnemonic, daemonPort, listenPort) {
	const home = path.join(WORK_DIR, `home-${tag}`);
	const dataDir = path.join(WORK_DIR, `data-${tag}`);
	fs.mkdirSync(home, { recursive: true });
	fs.mkdirSync(dataDir, { recursive: true });
	const out = fs.openSync(path.join(WORK_DIR, `${tag}.log`), 'a');
	const child = spawn(process.execPath, [CLI, 'start', '--log-level', 'info'], {
		env: {
			...process.env,
			HOME: home,
			BEIGNET_MNEMONIC: mnemonic,
			BEIGNET_NETWORK: 'regtest',
			BEIGNET_DATA_DIR: dataDir,
			BEIGNET_ELECTRUM_HOST: ELECTRUM_HOST,
			BEIGNET_ELECTRUM_PORT: ELECTRUM_PORT,
			BEIGNET_ELECTRUM_TLS: ELECTRUM_TLS,
			BEIGNET_LISTEN_PORT: String(listenPort),
			BEIGNET_DAEMON_PORT: String(daemonPort),
			BEIGNET_API_TOKEN: 't',
			BEIGNET_TOR_PROXY: TOR_PROXY
		},
		stdio: ['ignore', out, out]
	});
	const d = { tag, child, daemonPort, dataDir, mnemonic };
	daemons.push(d);
	return d;
}

async function api(d, method, route, body, timeoutMs = 120000) {
	const res = await fetch(`http://127.0.0.1:${d.daemonPort}${route}`, {
		method,
		headers: { Authorization: 'Bearer t', 'Content-Type': 'application/json' },
		body: body === undefined ? undefined : JSON.stringify(body),
		signal: AbortSignal.timeout(timeoutMs)
	});
	const json = await res.json();
	if (!json.ok) throw new Error(`${method} ${route}: ${JSON.stringify(json.error)}`);
	return json.result;
}

async function regtest(method, route, body) {
	const res = await fetch(`${REGTEST_API}${route}`, {
		method,
		headers: { 'Content-Type': 'application/json' },
		body: body === undefined ? undefined : JSON.stringify(body),
		signal: AbortSignal.timeout(120000)
	});
	return res.json();
}

async function waitReady(d) {
	for (let i = 0; i < 60; i++) {
		try {
			const info = await api(d, 'GET', '/info', undefined, 5000);
			if (info.blockHeight > 0) return info;
		} catch {
			/* not up yet */
		}
		await sleep(2000);
	}
	throw new Error(`${d.tag} never became ready`);
}

async function stop(d) {
	if (d.child.exitCode !== null) return;
	d.child.kill('SIGTERM');
	await new Promise((r) => {
		const t = setTimeout(() => {
			d.child.kill('SIGKILL');
			r();
		}, 15000);
		d.child.once('exit', () => {
			clearTimeout(t);
			r();
		});
	});
}

async function inboundChannelFromLsp(receiver, payer) {
	await api(receiver, 'POST', '/peer/connect', { pubkey: lspPubkey, host: lspHost, port: lspPort });
	await api(receiver, 'POST', '/direct-funding/configure', { lspPubkey, lspHost, lspPort });
	const req = await api(receiver, 'POST', '/direct-funding/request', { amountSats: CHANNEL_SATS });
	log(`${receiver.tag}: direct-funding request minted, payer sends ${CHANNEL_SATS} sats`);
	const sent = await api(payer, 'POST', '/direct-funding/send', { request: req.request, amountSats: CHANNEL_SATS }, 600000);
	log(`${receiver.tag}: funding tx ${sent.fundingTxid}`);
	await regtest('POST', '/api/mine', { blocks: 3 });
	for (let i = 0; i < 60; i++) {
		const channels = await api(receiver, 'GET', '/channels');
		const ch = channels.find((c) => c.fundingTxid === sent.fundingTxid && c.state === 'NORMAL');
		if (ch) return ch;
		await sleep(2000);
	}
	throw new Error(`${receiver.tag}: channel ${sent.fundingTxid} never reached NORMAL`);
}

function readKeys(dataDir, mnemonic) {
	const key = deriveStorageKey(bip39.mnemonicToSeedSync(mnemonic));
	const s = new SqliteStorage(path.join(dataDir, 'regtest.db'), (e) => log('corrupt row', e), { encryptionKey: key });
	s.open();
	const channels = s.loadAllChannels().map(({ state }) => ({
		channelId: state.channelId.toString('hex'),
		keyIndex: s.loadChannelKeyIndex(state.channelId.toString('hex')),
		fundingPubkey: state.localBasepoints.fundingPubkey.toString('hex'),
		revocationBasepoint: state.localBasepoints.revocationBasepoint.toString('hex'),
		perCommitmentSeed: state.localPerCommitmentSeed.toString('hex')
	}));
	s.close?.();
	return { channels };
}

function snapshotForRead(dataDir) {
	// The daemon keeps the database in WAL mode; the -wal and -shm files carry
	// the rows the main file does not yet, so copy the set.
	const dst = fs.mkdtempSync(path.join(WORK_DIR, 'snap-'));
	for (const f of fs.readdirSync(dataDir)) {
		if (f.startsWith('regtest.db')) fs.copyFileSync(path.join(dataDir, f), path.join(dst, f));
	}
	return dst;
}

const checks = [];
function check(name, ok, detail) {
	checks.push({ name, ok });
	log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? `  (${detail})` : ''}`);
}

async function main() {
	log(`work dir ${WORK_DIR}`);
	const mnemonic = bip39.generateMnemonic();
	const payerMnemonic = bip39.generateMnemonic();

	const A = boot('A', mnemonic, 2311, 9811);
	const P = boot('P', payerMnemonic, 2313, 9813);
	const infoA = await waitReady(A);
	await waitReady(P);
	log(`A node id ${infoA.nodeId} at height ${infoA.blockHeight}`);

	const addr = (await api(P, 'POST', '/address/new', {})).address;
	await regtest('POST', '/api/faucet', { address: addr, amount: 1, confirmations: 1 });
	for (let i = 0; i < 60; i++) {
		if ((await api(P, 'GET', '/balance')).onchain > 0) break;
		await sleep(2000);
	}
	await api(P, 'POST', '/peer/connect', { pubkey: lspPubkey, host: lspHost, port: lspPort });

	const birthA = infoA.blockHeight;
	const chA = await inboundChannelFromLsp(A, P);
	log(`A: channel ${chA.channelId} NORMAL`);
	await stop(A);
	const keptA = path.join(WORK_DIR, 'data-A-kept');
	fs.cpSync(A.dataDir, keptA, { recursive: true });
	fs.rmSync(A.dataDir, { recursive: true, force: true });
	log('A stopped, data directory copied aside and deleted');

	// At least one block has passed (the funding confirmations), so B's birth
	// tip is above A's and its floor lands above A's index.
	const B = boot('B', mnemonic, 2312, 9812);
	const infoB = await waitReady(B);
	check('B boots with the same node id from the mnemonic alone', infoB.nodeId === infoA.nodeId);
	const birthB = infoB.blockHeight;
	const chB = await inboundChannelFromLsp(B, P);
	log(`B: channel ${chB.channelId} NORMAL`);
	await stop(B);
	await stop(P);

	const a = readKeys(keptA, mnemonic).channels.find((c) => c.channelId === chA.channelId);
	const b = readKeys(snapshotForRead(B.dataDir), mnemonic).channels.find((c) => c.channelId === chB.channelId);
	if (!a || !b) throw new Error('could not read both channel rows back');
	const root = BIP32Factory(ecc).fromSeed(bip39.mnemonicToSeedSync(mnemonic));
	const idx1 = deriveChannelKeys(root, LnCoinType.REGTEST, 1);
	const idx1Funding = Buffer.from(ecc.pointFromScalar(idx1.fundingPrivkey, true)).toString('hex');
	const idx1Seed = idx1.perCommitmentSeed.toString('hex');

	check(`A's index is at or above its birth floor (${birthA} * ${STRIDE})`, a.keyIndex >= birthA * STRIDE, `index ${a.keyIndex}`);
	check(`B's index is at or above its birth floor (${birthB} * ${STRIDE})`, b.keyIndex >= birthB * STRIDE, `index ${b.keyIndex}`);
	check("B's index is above A's", b.keyIndex > a.keyIndex);
	check('funding pubkeys differ', a.fundingPubkey !== b.fundingPubkey);
	check('revocation basepoints differ', a.revocationBasepoint !== b.revocationBasepoint);
	check('per-commitment seeds differ', a.perCommitmentSeed !== b.perCommitmentSeed);
	check('neither channel used key index 1', a.keyIndex !== 1 && b.keyIndex !== 1);
	check('neither funding pubkey is the index-1 key', a.fundingPubkey !== idx1Funding && b.fundingPubkey !== idx1Funding);
	check('neither per-commitment seed is the index-1 seed', a.perCommitmentSeed !== idx1Seed && b.perCommitmentSeed !== idx1Seed);

	const failed = checks.filter((c) => !c.ok);
	log(`${checks.length - failed.length}/${checks.length} checks passed`);
	if (failed.length) process.exit(1);
}

process.on('SIGINT', () => Promise.all(daemons.map(stop)).then(() => process.exit(130)));
main()
	.catch((e) => {
		console.error(e);
		process.exitCode = 1;
	})
	.finally(() => Promise.all(daemons.map(stop)));
