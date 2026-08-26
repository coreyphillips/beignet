/**
 * Startup and wallet ergonomics (issue #548, LFBW port #532 workstream 1F),
 * offline.
 *
 * - waitForInitialSync settles even when Electrum is unreachable: it means
 *   "the startup refresh attempt finished", and the kick behind it is what
 *   makes the wallet subscribe to its addresses at all.
 * - addressType 'p2tr' yields taproot (bech32m) deposit addresses; the
 *   default stays p2wpkh.
 * - onchain:rbf surfaces the wallet's replaced-txid list; the transaction:*
 *   relays are unchanged beside it.
 * - The lightningNode/onchainWallet escape hatches expose the real
 *   underlying instances for features BeignetNode does not proxy.
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as net from 'net';
import { BeignetNode } from '../../src/cli/beignet-node';
import { BeignetError } from '../../src/cli/errors';
import { Wallet } from '../../src/wallet';
import { EPaymentType } from '../../src/types/wallet';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

function offlineOpts(dataDir: string): Record<string, unknown> {
	return {
		electrumHost: '127.0.0.1',
		electrumPort: 65529,
		electrumTls: false,
		rapidGossipSync: false,
		autoGossipSync: false,
		logLevel: 'silent' as const,
		network: 'regtest' as const,
		mnemonic: MNEMONIC,
		dataDir
	};
}

describe('Startup and wallet ergonomics (issue #548)', function () {
	this.timeout(60_000);

	const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-ergo-'));
	let bn: BeignetNode;

	before(async () => {
		bn = await BeignetNode.create(offlineOpts(dataDir));
	});

	after(async () => {
		await bn.destroy();
		fs.rmSync(dataDir, { recursive: true, force: true });
	});

	it('waitForInitialSync settles offline instead of hanging', async () => {
		let settled = false;
		await Promise.race([
			bn.waitForInitialSync().then(() => {
				settled = true;
			}),
			new Promise((resolve) => setTimeout(resolve, 20_000))
		]);
		expect(settled, 'initial sync settled').to.equal(true);
	});

	it('exposes the real underlying instances through the escape hatches', () => {
		expect(bn.lightningNode).to.equal(
			(bn as unknown as { node: unknown }).node
		);
		expect(bn.onchainWallet).to.equal(
			(bn as unknown as { wallet: unknown }).wallet
		);
		// The hatch is live, not a copy: the same channel manager the node
		// APIs use is reachable through it.
		expect(bn.lightningNode.getChannelManager()).to.equal(
			bn.lightningNode.getChannelManager()
		);
	});

	it('relays a wallet rbf report as onchain:rbf, transaction:* untouched', () => {
		const rbf: Array<{ txids: string[] }> = [];
		const received: unknown[] = [];
		// Typed straight off BeignetNodeEvents (issue #548 review): the
		// payload arrives as { txids: string[] }, no cast.
		bn.on('onchain:rbf', (data) => rbf.push(data));
		bn.on('transaction:received', (e: unknown) => received.push(e));
		const internals = bn as unknown as {
			onWalletMessage: (key: string, data: unknown) => void;
		};
		internals.onWalletMessage('rbf', ['aa'.repeat(32), 'bb'.repeat(32)]);
		internals.onWalletMessage('transactionReceived', {
			transaction: {
				txid: 'cc'.repeat(32),
				type: EPaymentType.received,
				value: 0.001,
				fee: 0.00001,
				satsPerByte: 2,
				address: 'bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080',
				height: 0,
				timestamp: 1_700_000_000
			}
		});
		expect(rbf).to.have.length(1);
		expect(rbf[0].txids).to.deep.equal(['aa'.repeat(32), 'bb'.repeat(32)]);
		expect(received, 'transaction:received still relays').to.have.length(1);
	});

	it('settles at the startup bound against a silent Electrum server', async function () {
		// A server that accepts the socket but never answers server_version
		// has no timeout of its own; unbounded, waitForInitialSync would hang
		// for the life of the process (issue #548 review). Budget: the header
		// subscribe path carries its own 30s gate (HEADER_SUBSCRIBE_GATE_MS)
		// that this scenario also rides through, so the proof here is
		// "settles within a bounded budget", not "settles fast".
		this.timeout(120_000);
		const socks: net.Socket[] = [];
		const silent = net.createServer((sock) => {
			// Accept and say nothing; keep the socket so teardown can sever
			// it (server.close() alone leaves live sockets, and the wallet's
			// reconnect loop would wedge destroy() on them).
			socks.push(sock);
		});
		await new Promise<void>((resolve) => silent.listen(0, resolve));
		const port = (silent.address() as net.AddressInfo).port;
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-ergo-silent-'));
		const statics = BeignetNode as unknown as {
			INITIAL_SYNC_TIMEOUT_MS: number;
			STARTUP_ADDRESS_LOOKUP_TIMEOUT_MS: number;
		};
		const originalBound = statics.INITIAL_SYNC_TIMEOUT_MS;
		const originalLookup = statics.STARTUP_ADDRESS_LOOKUP_TIMEOUT_MS;
		statics.INITIAL_SYNC_TIMEOUT_MS = 1500;
		// init's own sweep-address resolution hits the silent server first and
		// is bounded separately; shorten it too or create() eats the timeout.
		statics.STARTUP_ADDRESS_LOOKUP_TIMEOUT_MS = 1500;
		let silentNode: BeignetNode | undefined;
		try {
			silentNode = await BeignetNode.create({
				...offlineOpts(dir),
				electrumPort: port
			});
			let settled = false;
			await Promise.race([
				silentNode.waitForInitialSync().then(() => {
					settled = true;
				}),
				new Promise((resolve) => setTimeout(resolve, 90_000))
			]);
			expect(settled, 'settled at the bound, not hanging').to.equal(true);
		} finally {
			statics.INITIAL_SYNC_TIMEOUT_MS = originalBound;
			statics.STARTUP_ADDRESS_LOOKUP_TIMEOUT_MS = originalLookup;
			// Sever the silent sockets FIRST: reconnect attempts then fail
			// fast (ECONNREFUSED) instead of re-entering the untimed
			// handshake under destroy().
			for (const sock of socks) sock.destroy();
			silent.close();
			if (silentNode) await silentNode.destroy();
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	it('runs exactly ONE startup refresh (create no longer double-scans)', async function () {
		// Wallet.create used to fire its own refreshWallet beside init step
		// 15's tracked one; if the first finished during init, boot scanned
		// the whole wallet twice (issue #548 review).
		this.timeout(30_000);
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-ergo-once-'));
		const original = Wallet.prototype.refreshWallet;
		let calls = 0;
		Wallet.prototype.refreshWallet = function (
			...args: Parameters<typeof original>
		): ReturnType<typeof original> {
			calls++;
			return original.apply(this, args);
		};
		let counted: BeignetNode | undefined;
		try {
			counted = await BeignetNode.create(offlineOpts(dir));
			await counted.waitForInitialSync();
			expect(calls, 'one startup refresh, one owner').to.equal(1);
		} finally {
			Wallet.prototype.refreshWallet = original;
			if (counted) await counted.destroy();
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	it('names the restore-pending hold instead of returning undefined', async () => {
		// Guardian restore-pending startup returns before node/wallet exist;
		// the getters and the waiter must say so rather than hand back
		// undefined behind non-optional types (issue #548 review).
		const held = Object.create(BeignetNode.prototype) as BeignetNode;
		for (const call of [
			(): unknown => held.lightningNode,
			(): unknown => held.onchainWallet
		]) {
			try {
				call();
				expect.fail('expected NODE_RESTORE_PENDING');
			} catch (err) {
				expect(err).to.be.instanceOf(BeignetError);
				expect((err as BeignetError).code).to.equal('NODE_RESTORE_PENDING');
			}
		}
		try {
			await held.waitForInitialSync();
			expect.fail('expected NODE_RESTORE_PENDING');
		} catch (err) {
			expect(err).to.be.instanceOf(BeignetError);
			expect((err as BeignetError).code).to.equal('NODE_RESTORE_PENDING');
		}
	});

	it('addressType p2tr yields taproot deposit addresses (default p2wpkh)', async () => {
		// The default node derives segwit v0 (bech32, bcrt1q...).
		const v0 = await bn.onchainWallet.getAddress({ index: '0' });
		expect(v0.startsWith('bcrt1q'), v0).to.equal(true);

		const trDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-ergo-tr-'));
		const tr = await BeignetNode.create({
			...offlineOpts(trDir),
			addressType: 'p2tr'
		});
		try {
			// Taproot is segwit v1: bech32m, bcrt1p....
			const v1 = await tr.onchainWallet.getAddress({ index: '0' });
			expect(v1.startsWith('bcrt1p'), v1).to.equal(true);
		} finally {
			await tr.destroy();
			fs.rmSync(trDir, { recursive: true, force: true });
		}
	});
});
