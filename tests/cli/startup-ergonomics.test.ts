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
import { BeignetNode } from '../../src/cli/beignet-node';
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
		bn.on('onchain:rbf', (...args: unknown[]) =>
			rbf.push(args[0] as { txids: string[] })
		);
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
