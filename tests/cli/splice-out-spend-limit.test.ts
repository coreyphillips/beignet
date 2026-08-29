/**
 * Address-targeted splice-outs consume the daily spend budget (issue #534
 * review, LFBW port #532 workstream 1A).
 *
 * A splice-out to an external address is an external send: the destination
 * receives the full amount and the channel additionally pays the on-chain fee
 * (the engine declares relative = -(amount + fee)). Before this guard the
 * path performed no spend-limit check or accounting, because the existing
 * contract excluded splices as internal moves, so `dailySpendLimitSats` could
 * be bypassed entirely by splicing out to a third party. Wallet-credited
 * splice-outs (no address) stay outside the limit: those funds return to our
 * own wallet.
 *
 * Route-level cases boot the daemon offline (unreachable Electrum); the limit
 * check runs before the channel lookup, so no channel is needed. Unit-level
 * cases drive BeignetNode.spliceOut over a stubbed engine to pin the
 * record-only-on-acceptance accounting.
 */

import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import { IStartedDaemon, startDaemon } from '../../src/cli/daemon';
import { BeignetNode } from '../../src/cli/beignet-node';
import {
	estimateSpliceTxWeight,
	spliceFeeSats
} from '../../src/lightning/channel/splice-weight';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const UNKNOWN_CHANNEL_ID = 'ab'.repeat(32);

// secp256k1 generator point, compressed: a valid pubkey for address fixtures.
const PUBKEY = Buffer.from(
	'0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
	'hex'
);
const REGTEST_ADDRESS = bitcoin.payments.p2wpkh({
	pubkey: PUBKEY,
	network: bitcoin.networks.regtest
}).address!;
const REGTEST_SCRIPT = bitcoin.address.toOutputScript(
	REGTEST_ADDRESS,
	bitcoin.networks.regtest
);

/** The exact fee BeignetNode.spliceOut charges against the budget. */
function expectedFeeSats(feeratePerkw: number): number {
	return Number(
		spliceFeeSats(
			estimateSpliceTxWeight({
				walletInputCount: 0,
				destinationScriptLen: REGTEST_SCRIPT.length
			}),
			feeratePerkw
		)
	);
}

function request(
	port: number,
	body: Record<string, unknown>
): Promise<{ status: number; body: Record<string, unknown> }> {
	return new Promise((resolve, reject) => {
		const payload = JSON.stringify(body);
		const req = http.request(
			{
				hostname: '127.0.0.1',
				port,
				path: '/channel/splice-out',
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'Content-Length': Buffer.byteLength(payload)
				}
			},
			(res) => {
				const chunks: Buffer[] = [];
				res.on('data', (chunk: Buffer) => chunks.push(chunk));
				res.on('end', () => {
					try {
						resolve({
							status: res.statusCode!,
							body: JSON.parse(Buffer.concat(chunks).toString())
						});
					} catch {
						resolve({ status: res.statusCode!, body: {} });
					}
				});
			}
		);
		req.on('error', reject);
		req.write(payload);
		req.end();
	});
}

const DAILY_LIMIT_SATS = 10_000;

describe('Splice-out daily spend limit: daemon route', function () {
	this.timeout(30_000);

	const dir = fs.mkdtempSync(
		path.join(os.tmpdir(), 'beignet-splice-out-limit-')
	);
	let daemon: IStartedDaemon;
	let port: number;

	before(async () => {
		daemon = await startDaemon({
			electrumHost: '127.0.0.1',
			electrumPort: 65529,
			electrumTls: false,
			rapidGossipSync: false,
			autoGossipSync: false,
			logLevel: 'silent',
			network: 'regtest',
			mnemonic: MNEMONIC,
			daemonPort: 0,
			dataDir: dir,
			dailySpendLimitSats: DAILY_LIMIT_SATS
		});
		port = (daemon.server.address() as AddressInfo).port;
	});

	after(async () => {
		await daemon.stop();
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it('refuses an address-targeted splice-out over the daily limit', async () => {
		const res = await request(port, {
			channelId: UNKNOWN_CHANNEL_ID,
			amountSats: DAILY_LIMIT_SATS * 5,
			feeratePerkw: 2500,
			address: REGTEST_ADDRESS
		});
		expect(res.status).to.equal(403);
		expect(res.body.ok).to.equal(false);
		const error = res.body.error as { code: string; message: string };
		expect(error.code).to.equal('SPENDING_LIMIT_EXCEEDED');
		expect(error.message).to.include('Daily spend limit exceeded');
	});

	it('counts the on-chain fee, not just the amount', async () => {
		// The amount alone fits the budget; only amount + fee exceeds it, so a
		// refusal proves the fee is part of the admitted spend.
		const amountSats = DAILY_LIMIT_SATS - 1;
		expect(expectedFeeSats(2500)).to.be.greaterThan(1);
		const res = await request(port, {
			channelId: UNKNOWN_CHANNEL_ID,
			amountSats,
			feeratePerkw: 2500,
			address: REGTEST_ADDRESS
		});
		expect(res.status).to.equal(403);
		const error = res.body.error as { code: string };
		expect(error.code).to.equal('SPENDING_LIMIT_EXCEEDED');
	});

	it('leaves wallet-credited splice-outs outside the limit', async () => {
		// Same over-limit amount, no address: the funds would return to our
		// own wallet, so the request passes admission and proceeds to the
		// channel lookup, which on this fresh node answers CHANNEL_NOT_FOUND
		// rather than the budget refusal.
		const res = await request(port, {
			channelId: UNKNOWN_CHANNEL_ID,
			amountSats: DAILY_LIMIT_SATS * 5,
			feeratePerkw: 2500
		});
		expect(res.status).to.equal(404);
		expect(res.body.ok).to.equal(false);
		const error = res.body.error as { code: string; message: string };
		expect(error.code).to.equal('CHANNEL_NOT_FOUND');
		expect(error.message).to.include('Channel not found');
	});
});

describe('Splice-out daily spend limit: accounting', () => {
	interface FakeBeignetNode {
		_dailySpendLimitSats?: number;
		_dailySpentSats: number;
		_dailySpentLightningSats: number;
		_dailySpentOnchainSats: number;
		_pendingSpendSats: number;
		_dailySpendResetTime: number;
		_asyncSpendClaims: Map<string, unknown>;
		getBitcoinNetwork: () => unknown;
		node: { spliceOut: () => { ok: boolean; error?: string } };
		engineCalls: number;
		spliceOut: BeignetNode['spliceOut'];
	}

	function fakeNode(
		limitSats: number | undefined,
		engineResult: { ok: boolean; error?: string }
	): FakeBeignetNode {
		// Object.create keeps the real prototype methods (_checkSpendLimit,
		// _recordSpend, ...) while the engine below it is a stub, so the test
		// exercises the actual admission code with none of the node boot.
		const fake = Object.create(
			BeignetNode.prototype
		) as unknown as FakeBeignetNode;
		fake._dailySpendLimitSats = limitSats;
		fake._dailySpentSats = 0;
		fake._dailySpentLightningSats = 0;
		fake._dailySpentOnchainSats = 0;
		fake._pendingSpendSats = 0;
		fake._dailySpendResetTime = Date.now() + 24 * 60 * 60 * 1000;
		fake._asyncSpendClaims = new Map();
		fake.getBitcoinNetwork = (): unknown => bitcoin.networks.regtest;
		fake.engineCalls = 0;
		fake.node = {
			spliceOut: (): { ok: boolean; error?: string } => {
				fake.engineCalls++;
				return engineResult;
			}
		};
		return fake;
	}

	it('records amount + fee as an on-chain spend when the engine accepts', () => {
		const fake = fakeNode(1_000_000, { ok: true });
		const result = fake.spliceOut(
			UNKNOWN_CHANNEL_ID,
			5_000,
			2500,
			REGTEST_ADDRESS
		);
		expect(result.ok).to.equal(true);
		const total = 5_000 + expectedFeeSats(2500);
		expect(fake._dailySpentSats).to.equal(total);
		expect(fake._dailySpentOnchainSats).to.equal(total);
		expect(fake._dailySpentLightningSats).to.equal(0);
	});

	it('refuses over the limit before the engine is called', () => {
		const fake = fakeNode(1_000, { ok: true });
		expect(() =>
			fake.spliceOut(UNKNOWN_CHANNEL_ID, 5_000, 2500, REGTEST_ADDRESS)
		).to.throw(/Daily spend limit exceeded/);
		expect(fake.engineCalls).to.equal(0);
		expect(fake._dailySpentSats).to.equal(0);
	});

	it('records nothing when the engine refuses in-band', () => {
		const fake = fakeNode(1_000_000, {
			ok: false,
			error: `Channel not found: ${UNKNOWN_CHANNEL_ID}`
		});
		const result = fake.spliceOut(
			UNKNOWN_CHANNEL_ID,
			5_000,
			2500,
			REGTEST_ADDRESS
		);
		expect(result.ok).to.equal(false);
		expect(fake.engineCalls).to.equal(1);
		expect(fake._dailySpentSats).to.equal(0);
	});

	it('neither checks nor records a wallet-credited splice-out', () => {
		const fake = fakeNode(100, { ok: true });
		const result = fake.spliceOut(UNKNOWN_CHANNEL_ID, 5_000, 2500);
		expect(result.ok).to.equal(true);
		expect(fake.engineCalls).to.equal(1);
		expect(fake._dailySpentSats).to.equal(0);
	});
});
