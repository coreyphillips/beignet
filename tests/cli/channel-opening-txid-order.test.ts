/**
 * The funding txid a channel:opening carries names the transaction the way
 * bitcoind and GET /channels do (issue #681).
 *
 * The engine emits the funding HASH (internal byte order). Relayed as-is,
 * the daemon's "Channel opening" log line and its SSE frame named a
 * transaction nobody else could find: an operator grepping for the id on
 * their dashboard, or in bitcoin-cli, got nothing.
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { IStartedDaemon, startDaemon } from '../../src/cli/daemon';
import { LightningNode } from '../../src/lightning/node/lightning-node';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

describe('channel:opening funding txid order (issue #681)', function () {
	this.timeout(30_000);
	let daemon: IStartedDaemon;
	let dataDir: string;

	before(async () => {
		dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-txid-order-'));
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
			dataDir
		});
	});

	after(async () => {
		await daemon.stop();
		fs.rmSync(dataDir, { recursive: true, force: true });
	});

	it('relays the txid in display order, reversed from the hash the engine emits', async () => {
		const inner = (daemon.node as unknown as { node: LightningNode }).node;
		const hash = Buffer.from(
			'a54b98c12ac9a432ea53d58a44f8570907b52bfd7b10a7c05b08a09639352975',
			'hex'
		);
		const seen = new Promise<{ channelId: string; fundingTxid: string }>(
			(resolve) => daemon.node.once('channel:opening', resolve)
		);
		inner.emit('channel:opening', {
			channelId: Buffer.alloc(32, 7),
			fundingTxid: hash
		});
		const event = await seen;
		expect(event.fundingTxid).to.equal(
			'7529353996a0085bc0a7107bfd2bb5070957f8448ad553ea32a4c92ac1984ba5'
		);
		expect(event.channelId).to.equal('07'.repeat(32));
	});
});
