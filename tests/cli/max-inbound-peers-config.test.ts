/**
 * BEIGNET_MAX_INBOUND_PEERS (issue #1021): resolution, startup validation,
 * and the value reaching the node's peer manager.
 *
 * Offline tests: config resolution needs no node, and the boot cases use an
 * unreachable Electrum (the recovery-surface pattern).
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { BeignetNode } from '../../src/cli/beignet-node';
import { resolveConfig, saveConfig } from '../../src/cli/config';
import { daemonOptions } from '../../src/cli/daemon-options';
import { startDaemon } from '../../src/cli/daemon';
import { BeignetError } from '../../src/cli/errors';

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
	daemonPort: 0
};

describe('resolveConfig maxInboundPeers', () => {
	const origHome = process.env.HOME;
	let tmpHome: string;

	beforeEach(() => {
		tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-max-inbound-'));
		process.env.HOME = tmpHome;
	});

	afterEach(() => {
		process.env.HOME = origHome;
		delete process.env.BEIGNET_MAX_INBOUND_PEERS;
		fs.rmSync(tmpHome, { recursive: true, force: true });
	});

	it('is undefined when nothing sets it', () => {
		expect(resolveConfig({}).maxInboundPeers).to.equal(undefined);
	});

	it('resolves from BEIGNET_MAX_INBOUND_PEERS, zero included, and reaches the daemon options', () => {
		process.env.BEIGNET_MAX_INBOUND_PEERS = '0';
		const config = resolveConfig({});
		expect(config.maxInboundPeers).to.equal(0);
		expect(daemonOptions(config, 0).maxInboundPeers).to.equal(0);
	});

	it('turns a partly numeric value into NaN for startup to refuse', () => {
		process.env.BEIGNET_MAX_INBOUND_PEERS = '40x';
		expect(resolveConfig({}).maxInboundPeers).to.be.NaN;
	});

	it('reads the config file key, with the env var taking precedence', () => {
		saveConfig({ maxInboundPeers: 40 });
		expect(resolveConfig({}).maxInboundPeers).to.equal(40);
		process.env.BEIGNET_MAX_INBOUND_PEERS = '60';
		expect(resolveConfig({}).maxInboundPeers).to.equal(60);
	});
});

describe('maxInboundPeers at startup', function () {
	this.timeout(60_000);

	let dir: string;

	beforeEach(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-max-inbound-boot-'));
	});

	afterEach(() => {
		fs.rmSync(dir, { recursive: true, force: true });
	});

	for (const bad of [-1, 1.5, Number.NaN]) {
		it(`refuses maxInboundPeers ${bad}`, async () => {
			let error: unknown;
			try {
				const daemon = await startDaemon({
					...OFFLINE,
					mnemonic: MNEMONIC,
					dataDir: dir,
					maxInboundPeers: bad
				});
				await daemon.stop();
			} catch (e) {
				error = e;
			}
			expect(error, 'expected startDaemon to refuse').to.be.instanceOf(
				BeignetError
			);
			expect((error as Error).message).to.match(
				/maxInboundPeers must be a non-negative integer/
			);
		});
	}

	it('hands the value to the peer manager', async () => {
		const node = await BeignetNode.create({
			...OFFLINE,
			mnemonic: MNEMONIC,
			dataDir: dir,
			maxInboundPeers: 7
		});
		try {
			const inner = (
				node as unknown as {
					node: { peerManager: { maxInboundPeers: number } | null };
				}
			).node;
			expect(inner.peerManager, 'networking is on').to.not.equal(null);
			expect(inner.peerManager!.maxInboundPeers).to.equal(7);
		} finally {
			await node.destroy();
		}
	});
});
