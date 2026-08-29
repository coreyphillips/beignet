/**
 * BEIGNET_DF_* resolution and the direct-funding daemon surface (issue #613,
 * LFBW port #532 workstream 4D).
 *
 * `dfRelay` decides whether this node forwards opaque frames on behalf of
 * strangers, so it follows the exact-string rule: only 'true' and 'false'
 * count, anything else falls back to the safe direction. The fork's `=== 'true'`
 * read BEIGNET_DF_RELAY=1 as an explicit FALSE, which is the right answer by
 * accident rather than by rule.
 *
 * `dfMinAmountSat` goes through integerEnv, so '10m' resolves to NaN rather
 * than 10 and startup refuses it by name.
 *
 * The route tests below are the app's binding contract: configure MERGES, the
 * config readback keeps lspPubkey, and send accepts feeHeadroomSats as an alias
 * for maxTotalFeeSat because that is what the LFBW app posts today.
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import { resolveConfig } from '../../src/cli/config';
import { startDaemon, statusForErrorCode } from '../../src/cli/daemon';
import { BeignetError } from '../../src/cli/errors';
import {
	decodeRequestEnvelope,
	requestFromBip21,
	bip21WithRequest
} from '../../src/lightning/direct-funding/envelope';
import { DirectFundingErrorCode } from '../../src/lightning/direct-funding/types';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const OFFLINE = {
	electrumHost: '127.0.0.1',
	electrumPort: 65529,
	electrumTls: false,
	rapidGossipSync: false,
	autoGossipSync: false,
	logLevel: 'silent' as const,
	network: 'regtest' as const,
	mnemonic: MNEMONIC,
	daemonPort: 0
};

const VARS = ['BEIGNET_DF_RELAY', 'BEIGNET_DF_MIN_AMOUNT'];

/** One daemon call, JSON in and out. */
function httpCall(
	port: number,
	method: 'GET' | 'POST',
	route: string,
	body?: unknown
): Promise<{ status: number; json: Record<string, unknown> }> {
	return new Promise((resolve, reject) => {
		const req = http.request(
			{
				host: '127.0.0.1',
				port,
				path: route,
				method,
				headers: { 'content-type': 'application/json' }
			},
			(res) => {
				let raw = '';
				res.on('data', (c) => (raw += c));
				res.on('end', () =>
					resolve({ status: res.statusCode ?? 0, json: JSON.parse(raw) })
				);
			}
		);
		req.on('error', reject);
		req.end(body === undefined ? undefined : JSON.stringify(body));
	});
}

const errorOf = (json: Record<string, unknown>): { code: string } =>
	json.error as { code: string };

describe('resolveConfig direct funding', () => {
	afterEach(() => {
		for (const v of VARS) delete process.env[v];
	});

	it('is undefined when nothing sets it', () => {
		const config = resolveConfig({});
		expect(config.dfRelay).to.equal(undefined);
		expect(config.dfMinAmountSat).to.equal(undefined);
	});

	it('resolves both from the environment', () => {
		process.env.BEIGNET_DF_RELAY = 'true';
		process.env.BEIGNET_DF_MIN_AMOUNT = '25000';
		const config = resolveConfig({});
		expect(config.dfRelay).to.equal(true);
		expect(config.dfMinAmountSat).to.equal(25_000);
	});

	it('honours an explicit false', () => {
		process.env.BEIGNET_DF_RELAY = 'false';
		expect(resolveConfig({}).dfRelay).to.equal(false);
	});

	it('ignores anything that is not exactly true or false', () => {
		// '1' is the case the fork got right by accident: its `=== 'true'` made
		// this an explicit FALSE, which happens to match the safe direction here
		// and would have been the wrong answer for a switch whose default is on.
		for (const junk of ['1', 'TRUE', 'yes', 'on', '']) {
			process.env.BEIGNET_DF_RELAY = junk;
			expect(resolveConfig({}).dfRelay, junk).to.equal(undefined);
		}
	});

	it('surfaces a partly numeric minimum as NaN, not as a truncated number', () => {
		for (const raw of ['10m', '0.5', ' 12 000']) {
			process.env.BEIGNET_DF_MIN_AMOUNT = raw;
			expect(Number.isNaN(resolveConfig({}).dfMinAmountSat), raw).to.equal(
				true
			);
		}
	});

	it('keeps a configured zero, which clamps to the floor rather than vanishing', () => {
		process.env.BEIGNET_DF_MIN_AMOUNT = '0';
		// ?? not ||: a zero here is a real value the clamp then raises, and || would
		// drop it back to the config file.
		expect(resolveConfig({}).dfMinAmountSat).to.equal(0);
	});

	it('prefers the CLI flag over the environment', () => {
		process.env.BEIGNET_DF_RELAY = 'true';
		process.env.BEIGNET_DF_MIN_AMOUNT = '25000';
		const config = resolveConfig({ dfRelay: false, dfMinAmountSat: 7_000 });
		expect(config.dfRelay).to.equal(false);
		expect(config.dfMinAmountSat).to.equal(7_000);
	});
});

describe('daemon startup direct funding config', function () {
	this.timeout(30_000);

	it('refuses the NaN a partly numeric minimum resolves to', async () => {
		let error: unknown = null;
		try {
			const daemon = await startDaemon({
				...OFFLINE,
				dfMinAmountSat: Number.NaN
			});
			await daemon.stop();
		} catch (e) {
			error = e;
		}
		expect(error, 'expected startDaemon to refuse').to.be.instanceOf(
			BeignetError
		);
		expect((error as BeignetError).message).to.match(/BEIGNET_DF_MIN_AMOUNT/);
	});
});

describe('direct funding daemon surface', function () {
	this.timeout(30_000);
	let dataDir: string;
	let daemon: Awaited<ReturnType<typeof startDaemon>>;
	let port: number;

	const LSP = '02' + 'ab'.repeat(32);

	const call = (
		method: 'GET' | 'POST',
		route: string,
		body?: unknown
	): ReturnType<typeof httpCall> => httpCall(port, method, route, body);

	const resultOf = (json: Record<string, unknown>): Record<string, unknown> =>
		json.result as Record<string, unknown>;

	before(async () => {
		dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-df-4d-'));
		daemon = await startDaemon({ ...OFFLINE, dataDir, dfMinAmountSat: 20_000 });
		port = (daemon.server.address() as AddressInfo).port;
	});

	after(async () => {
		await daemon.stop();
		fs.rmSync(dataDir, { recursive: true, force: true });
	});

	it('reports the configured minimum, with no liquidity peer yet', async () => {
		const { json } = await call('GET', '/direct-funding/config');
		expect(resultOf(json)).to.deep.equal({
			lspPubkey: null,
			lspHost: null,
			lspPort: null,
			targetInboundSat: 0,
			trusted: false,
			minAmountSat: 20_000
		});
	});

	it('configure MERGES: a later partial post keeps what it did not name', async () => {
		const first = await call('POST', '/direct-funding/configure', {
			lspPubkey: LSP,
			lspHost: 'lsp.example',
			lspPort: 9735,
			targetInboundSat: 500_000,
			trusted: true
		});
		expect(resultOf(first.json).lspPubkey).to.equal(LSP);
		// Exactly what the dashboard does: post the minimum alone, then require
		// lspPubkey to still be there in the readback.
		const second = await call('POST', '/direct-funding/configure', {
			minAmountSat: 30_000
		});
		expect(resultOf(second.json)).to.deep.equal({
			lspPubkey: LSP,
			lspHost: 'lsp.example',
			lspPort: 9735,
			targetInboundSat: 500_000,
			trusted: true,
			minAmountSat: 30_000
		});
		const readback = await call('GET', '/direct-funding/config');
		expect(resultOf(readback.json).lspPubkey).to.equal(LSP);
	});

	it('clamps a minimum under the floor and reports the clamped value', async () => {
		// The dashboard compares what it reads back against what it asked for, so
		// the clamp has to be visible rather than applied later at the engine.
		const { json } = await call('POST', '/direct-funding/configure', {
			minAmountSat: 100
		});
		expect(resultOf(json).minAmountSat).to.equal(5_000);
		await call('POST', '/direct-funding/configure', { minAmountSat: 30_000 });
	});

	it('refuses a malformed liquidity peer before it reaches the policy', async () => {
		const { json, status } = await call('POST', '/direct-funding/configure', {
			lspPubkey: 'nothex'
		});
		expect((json.error as { code: string }).code).to.equal('INVALID_PARAMS');
		expect(status).to.equal(400);
		const readback = await call('GET', '/direct-funding/config');
		expect(resultOf(readback.json).lspPubkey).to.equal(LSP);
	});

	it('mints a request whose envelope decodes to this node', async () => {
		const info = daemon.node.getInfo();
		const { json } = await call('POST', '/direct-funding/request', {
			host: '10.0.0.5',
			port: 9736,
			amountSats: 120_000
		});
		const result = resultOf(json);
		expect(result.paymentHash).to.be.a('string');
		expect(result.expiresAt).to.be.a('number');
		const env = decodeRequestEnvelope(result.request as string);
		expect(env.receiverNodeId.toString('hex')).to.equal(info.nodeId);
		expect(env.amountSat).to.equal(120_000n);
		expect(env.receiptHash.toString('hex')).to.equal(result.paymentHash);
		// The host and port the CALLER gave, untouched.
		const direct = env.transports.find((t) => t.type === 1) as {
			host: string;
			port: number;
		};
		expect(direct.host).to.equal('10.0.0.5');
		expect(direct.port).to.equal(9736);
		// And it round-trips through a BIP 21 URI, which is how it is handed out.
		const uri = bip21WithRequest(
			'bitcoin:bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080?amount=0.0012',
			result.request as string
		);
		expect(requestFromBip21(uri)).to.equal(result.request);
	});

	it('emits no direct-peer descriptor when the caller names no address', async () => {
		const { json } = await call('POST', '/direct-funding/request', {});
		const env = decodeRequestEnvelope(resultOf(json).request as string);
		expect(env.transports.some((t) => t.type === 1)).to.equal(false);
		expect(env.amountSat).to.equal(undefined);
	});

	it('refuses a port that is not a port', async () => {
		const { json } = await call('POST', '/direct-funding/request', {
			host: 'h',
			port: 70_000
		});
		expect((json.error as { code: string }).code).to.equal('INVALID_PARAMS');
	});

	it('needs a request on send, and says so in words the app can show', async () => {
		const { json, status } = await call('POST', '/direct-funding/send', {});
		expect((json.error as { code: string }).code).to.equal('INVALID_PARAMS');
		expect((json.error as { message: string }).message).to.contain('request');
		expect(status).to.equal(400);
	});

	it('refuses a request for a different chain, by code', async () => {
		const minted = await call('POST', '/direct-funding/request', {});
		const request = resultOf(minted.json).request as string;
		// Flip the chain hash's first byte: still a well-formed envelope, still
		// signed by us, and for a chain this wallet does not pay on.
		const raw = Buffer.from(request, 'base64url');
		raw[1 + 16] ^= 0xff;
		const { json, status } = await call('POST', '/direct-funding/send', {
			request: raw.toString('base64url'),
			amountSats: 50_000
		});
		const code = (json.error as { code: string }).code;
		// The signature covers the chain hash, so a flipped byte is caught as a
		// wrong signer before the chain check; both are pre-witness refusals with
		// a status of their own rather than a 500.
		expect([
			DirectFundingErrorCode.WRONG_CHAIN,
			DirectFundingErrorCode.WRONG_SIGNER,
			DirectFundingErrorCode.INVALID_SIGNATURE
		]).to.include(code);
		expect(status).to.equal(400);
	});

	it('needs an amount when the request fixes none', async () => {
		const minted = await call('POST', '/direct-funding/request', {});
		const { json, status } = await call('POST', '/direct-funding/send', {
			request: resultOf(minted.json).request
		});
		expect((json.error as { code: string }).code).to.equal(
			DirectFundingErrorCode.AMOUNT_REQUIRED
		);
		expect(status).to.equal(400);
	});

	it('refuses an amount that contradicts a fixed-amount request', async () => {
		const minted = await call('POST', '/direct-funding/request', {
			amountSats: 60_000
		});
		const { json } = await call('POST', '/direct-funding/send', {
			request: resultOf(minted.json).request,
			amountSats: 70_000
		});
		expect((json.error as { code: string }).code).to.equal(
			DirectFundingErrorCode.AMOUNT_MISMATCH
		);
	});

	it('accepts feeHeadroomSats as an alias, which is what the app posts', async () => {
		const minted = await call('POST', '/direct-funding/request', {});
		// This wallet is offline and empty, so the send gets as far as coin
		// selection and no further: what is under test is that the alias reaches
		// the fee ceiling rather than being dropped as an unknown field.
		const { json } = await call('POST', '/direct-funding/send', {
			request: resultOf(minted.json).request,
			amountSats: 50_000,
			feeHeadroomSats: 1_000
		});
		const error = json.error as { code: string; message: string };
		expect(error.code).to.equal(DirectFundingErrorCode.NO_SUITABLE_UTXO);
		expect(error.message).to.contain('51000');
	});

	it('answers a fund refusal and a transport failure with different codes', () => {
		// The app falls back to a plain on-chain send on either, so this is the
		// distinction it reads. Both are pre-witness, and neither is a 500.
		expect(
			statusForErrorCode(DirectFundingErrorCode.NO_SUITABLE_UTXO)
		).to.equal(409);
		expect(statusForErrorCode(DirectFundingErrorCode.UNREACHABLE)).to.equal(
			502
		);
		for (const code of Object.values(DirectFundingErrorCode)) {
			expect(statusForErrorCode(code), code).to.not.equal(500);
		}
	});

	it('keeps the policy across a restart', async () => {
		await daemon.stop();
		daemon = await startDaemon({ ...OFFLINE, dataDir, dfMinAmountSat: 20_000 });
		port = (daemon.server.address() as AddressInfo).port;
		const { json } = await call('GET', '/direct-funding/config');
		expect(resultOf(json).lspPubkey).to.equal(LSP);
		expect(resultOf(json).minAmountSat).to.equal(30_000);
		expect(resultOf(json).trusted).to.equal(true);
	});
});

/**
 * A direct-funding send pays a stranger out of our own coin and holds the
 * request open for the whole exchange, so it answers to the same two node-wide
 * gates every other outgoing payment does. Both refuse before the engine is
 * entered, which keeps them on the pre-witness side of the never-reject rule.
 */
describe('direct funding under the node-wide payment gates', function () {
	this.timeout(30_000);
	let dataDir: string;
	let daemon: Awaited<ReturnType<typeof startDaemon>>;
	let port: number;

	const call = (
		method: 'GET' | 'POST',
		route: string,
		body?: unknown
	): ReturnType<typeof httpCall> => httpCall(port, method, route, body);

	/** A request minted by this node, which is payable and cheap to make. */
	async function mintedRequest(): Promise<string> {
		const { json } = await call('POST', '/direct-funding/request', {});
		return (json.result as { request: string }).request;
	}

	before(async () => {
		dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-df-gates-'));
		daemon = await startDaemon({
			...OFFLINE,
			dataDir,
			dailySpendLimitSats: 1
		});
		port = (daemon.server.address() as AddressInfo).port;
	});

	after(async () => {
		await daemon.stop();
		fs.rmSync(dataDir, { recursive: true, force: true });
	});

	it('refuses a send while the node is draining', async () => {
		const request = await mintedRequest();
		daemon.node.setDraining(true);
		try {
			const { json } = await call('POST', '/direct-funding/send', {
				request,
				amountSats: 50_000
			});
			// /stop closes storage and networking once the drain poll comes back
			// empty, and this exchange would still have been running inside it.
			expect(errorOf(json).code).to.equal('SERVICE_DRAINING');
		} finally {
			daemon.node.setDraining(false);
		}
	});

	it('counts a direct-funding send against the daily spend limit', async () => {
		const request = await mintedRequest();
		const { json } = await call('POST', '/direct-funding/send', {
			request,
			amountSats: 50_000
		});
		// The receiver is a stranger's channel: the money leaves, exactly as it
		// does on an address-targeted splice-out.
		expect(errorOf(json).code).to.equal('SPENDING_LIMIT_EXCEEDED');
	});

	it('is quiet about the amount a fixed-amount request names', async () => {
		// The app posts no amount for a request that fixes one, so the limit has
		// to read it off the envelope rather than off the body.
		const minted = await call('POST', '/direct-funding/request', {
			amountSats: 60_000
		});
		const { json } = await call('POST', '/direct-funding/send', {
			request: (minted.json.result as { request: string }).request
		});
		expect(errorOf(json).code).to.equal('SPENDING_LIMIT_EXCEEDED');
	});

	it('has no pending payment when nothing is running', () => {
		expect(daemon.node.hasPendingPayments()).to.equal(false);
	});
});
