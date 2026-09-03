/**
 * Daemon startup and the JIT receive surface (issue #532 workstream 3B).
 *
 * A malformed BEIGNET_JIT_* value refuses startup naming the variable rather
 * than booting with a fee policy the operator never wrote: integerEnv turns
 * '5.5' into NaN, and this is the check that turns NaN into an error instead
 * of into an LSP charging NaN sat.
 *
 * The rest is the surface the LFBW app calls: minFinalCltvExpiry on
 * POST /invoice/create, which is bounded here because the fork put it
 * straight into the BOLT 11 `c` tag unvalidated, and POST /jit/invoice, whose
 * own parameter checks run before the LSP is ever contacted.
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import { startDaemon, statusForErrorCode } from '../../src/cli/daemon';
import { jitInvoiceError } from '../../src/cli/beignet-node';
import { BeignetError } from '../../src/cli/errors';
import { decode } from '../../src/lightning/invoice/decode';
import { LightningNode } from '../../src/lightning/node/lightning-node';

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

async function expectStartRefused(
	jitReceive: unknown,
	message: RegExp
): Promise<void> {
	let error: unknown = null;
	try {
		const daemon = await startDaemon({
			...OFFLINE,
			jitReceive
		} as Parameters<typeof startDaemon>[0]);
		await daemon.stop();
	} catch (e) {
		error = e;
	}
	expect(error, 'expected startDaemon to refuse').to.be.instanceOf(
		BeignetError
	);
	expect((error as BeignetError).code).to.equal('INVALID_PARAMS');
	expect((error as BeignetError).message).to.match(message);
}

describe('daemon startup JIT receive config', function () {
	this.timeout(30_000);

	it('refuses the NaN a partly numeric env value resolves to', async () => {
		await expectStartRefused(
			{ enabled: true, flatFeeSat: Number.NaN },
			/BEIGNET_JIT_\* flatFeeSat must be an integer between 0 and 4294967295/
		);
	});

	it('refuses a proportional fee larger than the payment it comes from', async () => {
		await expectStartRefused(
			{ enabled: true, feePpm: 1_000_001 },
			/feePpm must be an integer between 0 and 1000000/
		);
	});

	it('refuses a fractional client ceiling', async () => {
		await expectStartRefused(
			{ maxFlatFeeSat: 0.5 },
			/maxFlatFeeSat must be an integer/
		);
	});

	// Issue #665: a cap that is not a whole number is a budget nobody wrote.
	it('refuses a fractional or negative exposure cap', async () => {
		await expectStartRefused(
			{ enabled: true, maxConcurrentFundings: 0.5 },
			/maxConcurrentFundings must be an integer/
		);
		await expectStartRefused(
			{ enabled: true, maxTotalFundingSats: -1 },
			/maxTotalFundingSats must be an integer/
		);
	});

	it('refuses a non-boolean enabled', async () => {
		await expectStartRefused({ enabled: 'true' }, /enabled must be a boolean/);
	});
});

describe('JIT receive daemon surface', function () {
	this.timeout(30_000);
	let dataDir: string;
	let daemon: Awaited<ReturnType<typeof startDaemon>>;

	before(async () => {
		dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-jit-3b-'));
		daemon = await startDaemon({
			...OFFLINE,
			dataDir,
			jitReceive: {
				enabled: true,
				flatFeeSat: 100,
				feePpm: 2_000,
				maxFlatFeeSat: 250,
				maxFeePpm: 3_000,
				maxClientFundingSats: 400_000,
				maxConcurrentFundings: 2,
				maxTotalFundingSats: 5_000_000
			}
		});
	});

	after(async () => {
		await daemon.stop();
		fs.rmSync(dataDir, { recursive: true, force: true });
	});

	it('threads both roles into the library node', () => {
		const inner = (daemon.node as unknown as { node: LightningNode }).node;
		const manager = inner.getJitReceiveManager();
		expect(manager, 'the LSP engine is running').to.not.equal(undefined);
		const cast = inner as unknown as {
			jitClientMaxFlatFeeSat: bigint;
			jitClientMaxFeePpm: number;
		};
		expect(cast.jitClientMaxFlatFeeSat).to.equal(250n);
		expect(cast.jitClientMaxFeePpm).to.equal(3_000);
	});

	// Issue #665: the exposure caps reach the LSP engine as the bigint and
	// count the library keeps, so what the operator wrote is what bounds
	// the coins this node fronts.
	it('threads the exposure caps into the LSP engine', () => {
		const inner = (daemon.node as unknown as { node: LightningNode }).node;
		const manager = inner.getJitReceiveManager() as unknown as {
			cfg: {
				maxClientFundingSats: bigint;
				maxConcurrentFundings: number;
				maxTotalFundingSats?: bigint;
			};
		};
		expect(manager.cfg.maxClientFundingSats).to.equal(400_000n);
		expect(manager.cfg.maxConcurrentFundings).to.equal(2);
		expect(manager.cfg.maxTotalFundingSats).to.equal(5_000_000n);
	});

	it('puts minFinalCltvExpiry into the invoice c tag', () => {
		// The LFBW app's splice-hold fallback sends 72; without it the receive
		// silently loses the headroom an on-the-fly funding needs.
		const invoice = daemon.node.createInvoice(
			1_000,
			'headroom',
			3600,
			undefined,
			72
		);
		expect(decode(invoice.bolt11).minFinalCltvExpiry).to.equal(72);
	});

	it('refuses a minFinalCltvExpiry no sender would ever pay', () => {
		for (const value of [0, -1, 2017, 1.5]) {
			expect(
				() => daemon.node.createInvoice(1_000, 'bad', 3600, undefined, value),
				String(value)
			).to.throw(/minFinalCltvExpiry must be an integer between 1 and 2016/);
		}
	});

	it('leaves an invoice without the field on the node default', () => {
		const invoice = daemon.node.createInvoice(1_000, 'plain');
		expect(decode(invoice.bolt11).minFinalCltvExpiry).to.equal(40);
	});

	it('checks the JIT invoice parameters before contacting any LSP', async () => {
		for (const [opts, message] of [
			[{ lspPubkey: 'nothex' }, /lspPubkey must be a 33-byte/],
			[
				{ lspPubkey: '02'.padEnd(66, 'a'), amountSats: 1.5 },
				/amountSats must be a whole number/
			],
			[
				{ lspPubkey: '02'.padEnd(66, 'a'), targetRemainingInboundSat: -1 },
				/targetRemainingInboundSat must be a whole number/
			]
		] as const) {
			let error: unknown = null;
			try {
				await daemon.node.createJitInvoice(opts);
			} catch (e) {
				error = e;
			}
			expect((error as Error | null)?.message, JSON.stringify(opts)).to.match(
				message
			);
		}
	});

	it('fails a JIT invoice for a peer that is not connected', async () => {
		let error: unknown = null;
		try {
			await daemon.node.createJitInvoice({
				lspPubkey: '02'.padEnd(66, 'a'),
				amountSats: 1_000,
				description: 'no peer'
			});
		} catch (e) {
			error = e;
		}
		expect(
			error,
			'an unreachable LSP is an error, never an invoice'
		).to.not.equal(null);
		// Typed (issue #671): the daemon answers 409 PEER_NOT_CONNECTED with
		// the reason rather than scrubbing it to INTERNAL_ERROR.
		expect((error as BeignetError).code).to.equal('PEER_NOT_CONNECTED');
	});

	// Issue #671: every refusal the wallet side throws as a plain Error has a
	// typed code and a status the app can act on; a genuine fault stays
	// untyped and scrubbed.
	it('types the LSP decline, the ceiling refusal and the ack timeout', () => {
		const typed = (message: string): BeignetError =>
			jitInvoiceError(new Error(message)) as BeignetError;
		expect(
			typed(
				'LSP declined the JIT receive intent: at most 2 live intents per peer'
			).code
		).to.equal('JIT_REFUSED');
		expect(
			typed(
				'LSP quoted 500 sat + 0 ppm, above the accepted maximum of 250 sat + 3000 ppm'
			).code
		).to.equal('JIT_REFUSED');
		expect(
			typed('LSP accepted the intent without an intercept scid').code
		).to.equal('JIT_REFUSED');
		expect(
			typed('timed out waiting for the LSP JIT receive ack').code
		).to.equal('JIT_TIMEOUT');
		expect(typed('Not connected to peer 02ab').code).to.equal(
			'PEER_NOT_CONNECTED'
		);
		expect(typed('LSP declined the JIT receive intent: x').message).to.match(
			/at most|declined/
		);
		const fault = new Error('database is locked');
		expect(jitInvoiceError(fault)).to.equal(fault);
		expect(statusForErrorCode('JIT_REFUSED')).to.equal(400);
		expect(statusForErrorCode('JIT_TIMEOUT')).to.equal(504);
	});

	it('dispatches POST /jit/invoice and requires the LSP pubkey', async () => {
		const { port } = daemon.server.address() as AddressInfo;
		const response = await new Promise<{ status: number; body: string }>(
			(resolve, reject) => {
				const req = http.request(
					{
						host: '127.0.0.1',
						port,
						path: '/jit/invoice',
						method: 'POST',
						headers: { 'content-type': 'application/json' }
					},
					(res) => {
						let body = '';
						res.on('data', (c) => (body += c));
						res.on('end', () => resolve({ status: res.statusCode ?? 0, body }));
					}
				);
				req.on('error', reject);
				req.end(JSON.stringify({ amountSats: 1_000 }));
			}
		);
		// The route exists (a missing one answers NOT_FOUND) and refuses the
		// call before any peer work.
		expect(JSON.parse(response.body).error.code).to.equal('INVALID_PARAMS');
	});
});
