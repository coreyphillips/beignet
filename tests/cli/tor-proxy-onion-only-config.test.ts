/**
 * BEIGNET_TOR_PROXY_ONION_ONLY resolution and startup validation (issue #963):
 * the Tor proxy for .onion peers only, with public clearnet dialed directly
 * (LND's tor.skip-proxy-for-clearnet-targets, "hybrid mode").
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

describe('resolveConfig torProxyOnionOnly', () => {
	const origHome = process.env.HOME;
	let tmpHome: string;

	beforeEach(() => {
		// The config file lives under $HOME/.beignet, so a fresh HOME starts
		// from no file at all and the file-key case writes there.
		tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-tor-onion-'));
		process.env.HOME = tmpHome;
	});

	afterEach(() => {
		process.env.HOME = origHome;
		delete process.env.BEIGNET_TOR_PROXY_ONION_ONLY;
		fs.rmSync(tmpHome, { recursive: true, force: true });
	});

	it('is undefined when nothing sets it, so every public peer rides the proxy', () => {
		const resolved = resolveConfig({});
		expect(resolved.torProxyOnionOnly).to.equal(undefined);
	});

	it('resolves true from BEIGNET_TOR_PROXY_ONION_ONLY=true', () => {
		process.env.BEIGNET_TOR_PROXY_ONION_ONLY = 'true';
		const resolved = resolveConfig({});
		expect(resolved.torProxyOnionOnly).to.equal(true);
	});

	it('resolves false from BEIGNET_TOR_PROXY_ONION_ONLY=false', () => {
		process.env.BEIGNET_TOR_PROXY_ONION_ONLY = 'false';
		const resolved = resolveConfig({});
		expect(resolved.torProxyOnionOnly).to.equal(false);
	});

	it('ignores anything but exact true/false, so a typo means proxy everything', () => {
		// Ignored leaves the switch unset: the private direction, since the
		// mistake then costs latency rather than revealing the clearnet
		// address to a public peer.
		for (const junk of ['TRUE', 'FALSE', '1', '0', 'yes', 'onion', '']) {
			process.env.BEIGNET_TOR_PROXY_ONION_ONLY = junk;
			const resolved = resolveConfig({});
			expect(resolved.torProxyOnionOnly, JSON.stringify(junk)).to.equal(
				undefined
			);
		}
	});

	it('prefers the CLI flag over the env var', () => {
		process.env.BEIGNET_TOR_PROXY_ONION_ONLY = 'false';
		const resolved = resolveConfig({ torProxyOnionOnly: true });
		expect(resolved.torProxyOnionOnly).to.equal(true);
	});

	it('reads the config file key, below the env var', () => {
		saveConfig({ torProxyOnionOnly: true, torProxy: '10.21.21.11:9050' });
		expect(resolveConfig({}).torProxyOnionOnly).to.equal(true);
		expect(resolveConfig({}).torProxy).to.equal('10.21.21.11:9050');

		process.env.BEIGNET_TOR_PROXY_ONION_ONLY = 'false';
		expect(resolveConfig({}).torProxyOnionOnly).to.equal(false);
	});
});

describe('torProxyOnionOnly at startup', function () {
	this.timeout(60_000);

	let dir: string;

	beforeEach(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-tor-onion-boot-'));
	});

	afterEach(() => {
		fs.rmSync(dir, { recursive: true, force: true });
	});

	const refused = async (
		opts: Record<string, unknown>,
		pattern: RegExp
	): Promise<void> => {
		let error: unknown;
		try {
			const daemon = await startDaemon({
				...OFFLINE,
				mnemonic: MNEMONIC,
				dataDir: dir,
				...opts
			});
			await daemon.stop();
		} catch (e) {
			error = e;
		}
		expect(error, 'expected startDaemon to refuse').to.be.instanceOf(
			BeignetError
		);
		expect((error as Error).message).to.match(pattern);
	};

	it('refuses torProxyOnionOnly without torProxy', async () => {
		// The switch only narrows which hosts use the proxy; with none
		// configured it has nothing to act on, and silently accepting it would
		// leave the operator believing onion peers are reachable.
		await refused({ torProxyOnionOnly: true }, /needs torProxy/);
	});

	it('refuses a torProxyOnionOnly that is not a boolean', async () => {
		await refused(
			{ torProxy: '127.0.0.1:9050', torProxyOnionOnly: 'yes' },
			/torProxyOnionOnly must be a boolean/
		);
	});

	it('boots with torProxy and hands the peer manager scope onion', async () => {
		// The proxy is never dialed at boot: no peers are known and bootstrap
		// is off, so a dead 127.0.0.1:9050 is fine here.
		const node = await BeignetNode.create({
			...OFFLINE,
			mnemonic: MNEMONIC,
			dataDir: dir,
			torProxy: '127.0.0.1:9050',
			torProxyOnionOnly: true
		});
		try {
			const inner = (
				node as unknown as {
					node: {
						socks5ProxyScope: string;
						peerManager: {
							socks5Proxy?: { host: string; port: number };
							socks5ProxyScope: string;
						} | null;
					};
				}
			).node;
			expect(inner.socks5ProxyScope).to.equal('onion');
			expect(inner.peerManager, 'networking is on').to.not.equal(null);
			expect(inner.peerManager!.socks5ProxyScope).to.equal('onion');
			expect(inner.peerManager!.socks5Proxy).to.deep.equal({
				host: '127.0.0.1',
				port: 9050
			});
		} finally {
			await node.destroy();
		}
	});

	it('defaults the scope to all when the switch is off', async () => {
		const node = await BeignetNode.create({
			...OFFLINE,
			mnemonic: MNEMONIC,
			dataDir: dir,
			torProxy: '127.0.0.1:9050'
		});
		try {
			const inner = (
				node as unknown as {
					node: { peerManager: { socks5ProxyScope: string } | null };
				}
			).node;
			expect(inner.peerManager!.socks5ProxyScope).to.equal('all');
		} finally {
			await node.destroy();
		}
	});
});
